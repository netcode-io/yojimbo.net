/*
    yojimbo TypeScript port: WebRTC transport extension.

    This folder is an EXTENSION of the TypeScript port, not a mirror of an upstream file: upstream yojimbo has no
    WebRTC transport. It is distributed under the same BSD 3-Clause license as the rest of this package.

    webrtc_server.ts: the Node server side. NODE ONLY. It needs the optional peer dependency node-datachannel
    (libdatachannel bindings), which is loaded lazily by open() so merely importing this file pulls in nothing
    native; node:http and node:dgram are reached through process.getBuiltinModule, never a static import.

    WebRTCServerAdapter is a yojimbo Adapter with custom packet I/O that serves BOTH kinds of client on one
    yojimbo Server:

      - native UDP clients (Node, C++, C#): the adapter owns a UDP socket bound to the server address (netcode's
        own socket layer), so they connect exactly as to a plain yojimbo server;
      - WebRTC peers (browsers, webrtc_client.ts): each peer gets one pre-negotiated, unordered, maxRetransmits 0
        data channel ('netcode', id 0) and a unique synthetic address that netcode sees as the peer's source.

    Synthetic addresses. Each adapter picks a random RFC 4193 unique-local /64,
        fdXX:XXXX:XXXX:5754::/64      (fd + 40 random bits global id, subnet 0x5754 "WT")
    and gives peer n the address [prefix::0:n_hi:n_mid:n_lo]:1 from a monotonically increasing 48-bit counter.
    Addresses are never reused while the adapter lives, so netcode's address-keyed state (encryption mappings,
    the connect token history, client slots) can never confuse a new peer with an old one, even while a stale
    mapping is still timing out. A UDP datagram whose source falls inside the prefix is dropped, so a real UDP
    source can never collide with (or impersonate) a peer either.

    Queues. WebRTC messages are queued in one bounded FIFO shared by all peers (maxQueuedPackets) with a per-peer
    cap (maxQueuedPacketsPerPeer) so one peer cannot starve the rest; UDP datagrams queue in netcode's socket
    receive buffer (bounded in bytes, as the kernel's). ReceivePacket alternates between the two sources so
    neither starves the other. Overflow is dropped, as a full socket buffer drops.

    Signaling: handleSignal( req, res ) (node:http shaped; works from express / fastify raw req/res too) or
    listenSignaling( port, { path } ). One POST of { sdp, connectToken } (JSON; connectToken = base64 of the
    2048 byte connect token) answered with { sdp } after ICE gathering completes (non-trickle). The connect token
    is validated BEFORE any peer connection is allocated: decrypted with the server's private key (so only your
    token issuer can open a peer), protocol id, expiry, and this server's address in the token's encrypted
    server list -- the same checks netcode makes on a connection request. That is the DoS gate. On top:
    per-IP and global caps on pending and total peers, a per-token signal count, body size / content type /
    method checks, and timeouts that reap peers which never open, never send, never complete the netcode
    handshake, or go idle. A peer is released when netcode disconnects its client (after a short linger so the
    disconnect packets get out) or when its channel / peer connection closes or fails.

    Usage:

        class GameServerAdapter extends WebRTCServerAdapter { override CreateMessageFactory( ... ) { ... } }
        const adapter = new GameServerAdapter( { address: '203.0.113.7:40000', privateKey, protocolId } );
        await adapter.open();                                         // binds UDP, loads node-datachannel
        const server = new Server( allocator, privateKey, adapter.address, config, adapter, time );
        server.Start( maxClients );
        adapter.attachServer( server );                               // lets it map client slots to peers
        await adapter.listenSignaling( 8080, { path: '/signal' } );   // or route POSTs to adapter.handleSignal
        ...drive the server as usual; at shutdown: server.Stop(); adapter.close();

    If you override OnServerClientConnected / OnServerClientDisconnected, call super.
*/

import type { IncomingMessage, ServerResponse, Server as HttpServer } from 'node:http';
import {
    Adapter, Address, Server, MaxAdapterPacketBytes, AddressFromNetcode, AddressToNetcode, yojimbo_random_bytes,
    ADDRESS_IPV6,
} from '../source/yojimbo.ts';
import {
    netcode_socket_t, netcode_socket_create, netcode_socket_destroy, netcode_socket_send_packet, netcode_socket_receive_packet,
    netcode_address_t, NETCODE_SOCKET_ERROR_NONE, NETCODE_ADDRESS_IPV6, NETCODE_SERVER_SOCKET_SNDBUF_SIZE, NETCODE_SERVER_SOCKET_RCVBUF_SIZE,
} from '../netcode/netcode.ts';
import { DecodeBase64, GenerateConnectToken, ValidateConnectToken } from './webrtc_token.ts';
import type { GenerateConnectTokenOptions } from './webrtc_token.ts';
import { WebRTCChannelLabel, WebRTCChannelId } from './webrtc_client.ts';

export { GenerateConnectToken, ValidateConnectToken, EncodeBase64, DecodeBase64 } from './webrtc_token.ts';
export type { GenerateConnectTokenOptions, ConnectTokenInfo, ValidateConnectTokenResult } from './webrtc_token.ts';

// ----------------------------------------------------------------------------------------------------------
// the parts of node-datachannel used here, typed structurally so this file compiles without it installed

interface NdcDataChannel
{
    sendMessageBinary( buffer: Uint8Array ): boolean;
    isOpen(): boolean;
    bufferedAmount(): number;
    close(): void;
    onOpen( cb: () => void ): void;
    onClosed( cb: () => void ): void;
    onError( cb: ( err: string ) => void ): void;
    onMessage( cb: ( msg: string | Uint8Array | ArrayBuffer ) => void ): void;
}

interface NdcPeerConnection
{
    close(): void;
    setLocalDescription( type?: string ): void;
    setRemoteDescription( sdp: string, type: string ): void;
    localDescription(): { type: string, sdp: string } | null;
    createDataChannel( label: string, config?: { negotiated?: boolean, id?: number, unordered?: boolean, maxRetransmits?: number } ): NdcDataChannel;
    gatheringState(): string;
    onStateChange( cb: ( state: string ) => void ): void;
    onGatheringStateChange( cb: ( state: string ) => void ): void;
}

interface NdcModule
{
    PeerConnection: new ( peerName: string, config: Record<string, unknown> ) => NdcPeerConnection;
}

/** node-datachannel ICE server: 'stun:host:port' / 'turn:user:pass@host:port' strings or objects. */
export type WebRTCServerIceServer = string | { hostname: string, port: number, username?: string, password?: string, relayType?: 'TurnUdp' | 'TurnTcp' | 'TurnTls' };

export interface WebRTCServerOptions
{
    /** The server address: the UDP socket binds to it and it is the address in connect tokens. Port 0 picks a free port (UDP only; read adapter.address after open()). */
    address: Address | string;
    /** The server private key (same as passed to Server). */
    privateKey: Uint8Array;
    /** ClientServerConfig.protocolId. */
    protocolId: bigint;
    /** Serve native UDP clients too. Default true. */
    udp?: boolean;
    /** STUN / TURN servers for the server's own candidates. Default none (fine when the server has a public IP or on a LAN). */
    iceServers?: WebRTCServerIceServer[];
    /** Extra node-datachannel RtcConfig: e.g. { portRangeBegin, portRangeEnd } or { enableIceUdpMux: true } for firewalls, bindAddress. */
    rtcConfig?: Record<string, unknown>;
    /** Max peers (pending + open). Default 256. */
    maxPeers?: number;
    /** Max peers per client IP. Default 16. */
    maxPeersPerIp?: number;
    /** Max peers still connecting (signaled, channel not open yet). Default 32. */
    maxPendingPeers?: number;
    /** Max connecting peers per client IP. Default 4. */
    maxPendingPeersPerIp?: number;
    /** How many times one connect token may be used to signal. Default 2 (one retry). */
    maxSignalsPerToken?: number;
    /** Signal accepted → data channel open, else reaped. Default 10000 ms. */
    pendingTimeoutMs?: number;
    /** Channel open → first packet, else reaped. Default 5000 ms. */
    firstPacketTimeoutMs?: number;
    /** Channel open → netcode client connected (needs attachServer), else reaped. Default 15000 ms. */
    handshakeTimeoutMs?: number;
    /** No packet received for this long → reaped. Default 30000 ms. */
    idleTimeoutMs?: number;
    /** After netcode disconnects a peer's client, keep the channel this long so the disconnect packets get out. Default 250 ms. */
    lingerMs?: number;
    /** Max wait for the server's ICE gathering before answering with what it has. Default 5000 ms. */
    iceGatheringTimeoutMs?: number;
    /** Max signaling request body. Default 16384 bytes (an offer is ~1 KB, the token ~2.7 KB of base64). */
    maxBodyBytes?: number;
    /** Max time to receive the request body. Default 5000 ms. */
    bodyTimeoutMs?: number;
    /** Merged WebRTC receive queue size in packets. Default 4096. */
    maxQueuedPackets?: number;
    /** Per-peer share of the receive queue in packets. Default 256. */
    maxQueuedPacketsPerPeer?: number;
    /** Sends to a peer are dropped while its channel buffers more than this. Default 1 MiB. */
    maxBufferedBytes?: number;
    /** CORS for the signaling endpoint. Default none (same origin only). '*' or a list of allowed origins. */
    cors?: { origins: '*' | string[], allowHeaders?: string[] } | null;
    /** How to get the client IP for the per-IP limits (e.g. from X-Forwarded-For behind your own proxy). Default req.socket.remoteAddress. */
    clientIp?: ( req: IncomingMessage ) => string;
    /** Called with every signaling decision (logging / metrics). */
    onSignal?: ( event: { ip: string, status: number, reason: string } ) => void;
    /** Called when a peer's channel opens and when a peer is released, with why (logging / metrics). */
    onPeerEvent?: ( event: { address: string, ip: string, event: 'open' | 'released', reason: string } ) => void;
}

export interface WebRTCServerStats
{
    pendingPeers: number;
    openPeers: number;
    closingPeers: number;
    peersCreated: number;
    peersReaped: number;
    signalsAccepted: number;
    signalsRejected: number;
    packetsDropped: number;
    spoofedUdpDropped: number;
    queuedPackets: number;
}

type PeerState = 'pending' | 'open' | 'closing' | 'closed';

class WebRTCPeer
{
    id: number;
    address: Address;
    ip: string;
    pc: NdcPeerConnection | null = null;
    channel: NdcDataChannel | null = null;
    state: PeerState = 'pending';
    created: number;
    opened = 0;
    lastReceive = 0;
    receivedAny = false;
    connected = false;
    closeAt = 0;
    queued = 0;
    clientIndex = -1;

    constructor( id: number, address: Address, ip: string, now: number )
    {
        this.id = id;
        this.address = address;
        this.ip = ip;
        this.created = now;
    }
}

class QueuedPacket
{
    peer: WebRTCPeer;
    data: Uint8Array;

    constructor( peer: WebRTCPeer, data: Uint8Array )
    {
        this.peer = peer;
        this.data = data;
    }
}

const SyntheticSubnet = 0x5754;                 // "WT"
const SyntheticPort = 1;
const SweepIntervalMs = 100;

function now(): number
{
    return performance.now();
}

class SignalError extends Error
{
    status: number;

    constructor( status: number, message: string )
    {
        super( message );
        this.status = status;
    }
}

/**
    yojimbo server Adapter that multiplexes native UDP clients and WebRTC peers. Node only. Dedicated to one Server.
 */

export class WebRTCServerAdapter extends Adapter
{
    private m_options: WebRTCServerOptions;
    private m_address: Address;
    private m_ndc: NdcModule | null = null;
    private m_opened = false;
    private m_server: Server | null = null;

    private m_socket: netcode_socket_t | null = null;
    private m_udpFrom = new netcode_address_t();
    private m_udpTo = new netcode_address_t();

    private m_prefix = new Uint16Array( 4 );
    private m_nextPeerId = 1;
    private m_peers = new Map<number, WebRTCPeer>();
    private m_pendingCount = 0;
    private m_pendingPerIp = new Map<string, number>();
    private m_peersPerIp = new Map<string, number>();
    private m_tokenUses = new Map<string, { uses: number, expire: bigint }>();
    private m_lastTokenPrune = 0;

    private m_queue: QueuedPacket[] = [];
    private m_queueStart = 0;
    private m_nextSource = 0;

    private m_sweepTimer: ReturnType<typeof setInterval> | null = null;
    private m_httpServers = new Set<HttpServer>();

    private m_stats = { peersCreated: 0, peersReaped: 0, signalsAccepted: 0, signalsRejected: 0, packetsDropped: 0, spoofedUdpDropped: 0 };

    constructor( options: WebRTCServerOptions )
    {
        super();
        this.m_options = options;
        this.m_address = typeof options.address === 'string' ? new Address( options.address ) : options.address.Clone();

        const random = new Uint8Array( 5 );
        yojimbo_random_bytes( random, 5 );
        this.m_prefix[0] = 0xFD00 | random[0];
        this.m_prefix[1] = ( random[1] << 8 ) | random[2];
        this.m_prefix[2] = ( random[3] << 8 ) | random[4];
        this.m_prefix[3] = SyntheticSubnet;
    }

    /** The server address (with the actual port once open() bound port 0). Pass this to the Server constructor and into connect tokens. */
    get address(): Address { return this.m_address.Clone(); }

    /** True between open() and close(). */
    get isOpen(): boolean { return this.m_opened; }

    get stats(): WebRTCServerStats
    {
        let open = 0, closing = 0;
        for ( const peer of this.m_peers.values() )
        {
            if ( peer.state === 'open' ) open++;
            else if ( peer.state === 'closing' ) closing++;
        }
        return { ...this.m_stats, pendingPeers: this.m_pendingCount, openPeers: open, closingPeers: closing, queuedPackets: this.m_queue.length - this.m_queueStart };
    }

    /**
        Load node-datachannel and bind the UDP socket (unless options.udp is false). Throws on failure.
        Call before constructing the Server, and construct it with adapter.address.
     */

    async open(): Promise<void>
    {
        if ( this.m_opened )
            return;

        if ( !this.m_address.IsValid() )
            throw new Error( 'WebRTCServerAdapter: invalid server address' );

        if ( typeof process === 'undefined' || !process.versions?.node )
            throw new Error( 'WebRTCServerAdapter is Node only' );

        // the specifier is a variable on purpose: bundlers and tsc leave the optional native dependency alone
        const specifier = 'node-datachannel';
        let module: { default?: NdcModule } & Partial<NdcModule>;
        try
        {
            module = await import( specifier );
        }
        catch ( error )
        {
            throw new Error( `WebRTCServerAdapter: node-datachannel is required (npm install node-datachannel): ${error instanceof Error ? error.message : String( error )}` );
        }
        const ndc = ( module.PeerConnection ? module : module.default ) as NdcModule | undefined;
        if ( !ndc?.PeerConnection )
            throw new Error( 'WebRTCServerAdapter: node-datachannel has no PeerConnection' );
        this.m_ndc = ndc;

        if ( this.m_options.udp ?? true )
        {
            const socket = new netcode_socket_t();
            const bindAddress = new netcode_address_t();
            AddressToNetcode( this.m_address, bindAddress );
            const result = netcode_socket_create( socket, bindAddress, NETCODE_SERVER_SOCKET_SNDBUF_SIZE, NETCODE_SERVER_SOCKET_RCVBUF_SIZE );
            if ( result !== NETCODE_SOCKET_ERROR_NONE )
                throw new Error( `WebRTCServerAdapter: failed to bind UDP socket on ${this.m_address.ToString()} (netcode socket error ${result})` );
            this.m_socket = socket;
            this.m_address.SetPort( socket.address.port );
        }
        else if ( this.m_address.GetPort() === 0 )
        {
            throw new Error( 'WebRTCServerAdapter: without UDP the server address needs an explicit port' );
        }

        this.m_sweepTimer = setInterval( () => this.Sweep(), SweepIntervalMs );
        this.m_sweepTimer.unref?.();
        this.m_opened = true;
    }

    /** Let the adapter map netcode client slots to peers (release on disconnect, handshake timeout). Call after Server.Start. */

    attachServer( server: Server | null ): void
    {
        this.m_server = server;
    }

    /** Close every peer, the UDP socket and the signaling servers started by listenSignaling. Stop the Server first. */

    close(): void
    {
        for ( const peer of [ ...this.m_peers.values() ] )
            this.ReleasePeer( peer, false, 'adapter closed' );
        this.m_queue = [];
        this.m_queueStart = 0;
        if ( this.m_socket )
        {
            netcode_socket_destroy( this.m_socket );
            this.m_socket = null;
        }
        if ( this.m_sweepTimer )
        {
            clearInterval( this.m_sweepTimer );
            this.m_sweepTimer = null;
        }
        for ( const server of this.m_httpServers )
        {
            server.close();
            server.closeAllConnections?.();
        }
        this.m_httpServers.clear();
        this.m_server = null;
        this.m_opened = false;
    }

    override Dispose(): void
    {
        this.close();
        super.Dispose();
    }

    /** A connect token for this server (dev / tests: in production your backend issues tokens). */

    generateConnectToken( clientId: bigint, options: Partial<GenerateConnectTokenOptions> = {} ): Uint8Array | null
    {
        return GenerateConnectToken( {
            privateKey: this.m_options.privateKey,
            protocolId: this.m_options.protocolId,
            serverAddresses: [ this.m_address ],
            ...options,
            clientId,
        } );
    }

    /** True if the address is one of this adapter's synthetic peer addresses. */

    IsPeerAddress( address: Address ): boolean
    {
        if ( address.GetType() !== ADDRESS_IPV6 )
            return false;
        const fields = address.GetAddress6();
        return fields[0] === this.m_prefix[0] && fields[1] === this.m_prefix[1] && fields[2] === this.m_prefix[2] && fields[3] === this.m_prefix[3];
    }

    // ------------------------------------------------------------------------------------------------------
    // custom packet I/O

    override UseCustomPacketIO(): boolean
    {
        return true;
    }

    override SendPacket( to: Address, packetData: Uint8Array, packetBytes: number ): void
    {
        if ( packetBytes <= 0 || packetBytes > MaxAdapterPacketBytes )
            return;

        if ( this.IsPeerAddress( to ) )
        {
            const peer = this.FindPeer( to );
            const channel = peer?.channel;
            if ( !peer || !channel || ( peer.state !== 'open' && peer.state !== 'closing' ) || channel.bufferedAmount() > ( this.m_options.maxBufferedBytes ?? 1024 * 1024 ) )
            {
                this.m_stats.packetsDropped++;
                return;
            }
            try
            {
                // packetData is only valid during the call: send a copy
                if ( !channel.sendMessageBinary( packetData.slice( 0, packetBytes ) ) )
                    this.m_stats.packetsDropped++;
            }
            catch
            {
                this.m_stats.packetsDropped++;
            }
            return;
        }

        const socket = this.m_socket;
        if ( !socket || socket.handle === null )
            return;
        if ( !AddressToNetcode( to, this.m_udpTo ) || this.m_udpTo.type !== socket.address.type )
            return;
        netcode_socket_send_packet( socket, this.m_udpTo, packetData, packetBytes );
    }

    override ReceivePacket( from: Address, packetData: Uint8Array, maxPacketBytes: number ): number
    {
        // alternate between the WebRTC queue and the UDP socket so neither starves the other
        for ( let i = 0; i < 2; ++i )
        {
            const source = this.m_nextSource;
            this.m_nextSource ^= 1;
            const bytes = source === 0 ? this.ReceiveWebRTCPacket( from, packetData, maxPacketBytes ) : this.ReceiveUDPPacket( from, packetData, maxPacketBytes );
            if ( bytes > 0 )
                return bytes;
        }
        return 0;
    }

    override OnServerClientConnected( clientIndex: number ): void
    {
        const address = this.m_server?.GetClientAddress( clientIndex );
        if ( !address || address.type !== NETCODE_ADDRESS_IPV6 )
            return;
        const peer = this.FindPeer( AddressFromNetcode( address ) );
        if ( peer && peer.state === 'open' )
        {
            peer.connected = true;
            peer.clientIndex = clientIndex;
        }
    }

    override OnServerClientDisconnected( clientIndex: number ): void
    {
        for ( const peer of this.m_peers.values() )
        {
            if ( peer.clientIndex === clientIndex )
            {
                // netcode sends the disconnect packets right after this callback: let them out, then release
                peer.clientIndex = -1;
                if ( peer.state === 'open' )
                {
                    peer.state = 'closing';
                    peer.closeAt = now() + ( this.m_options.lingerMs ?? 250 );
                }
            }
        }
    }

    // ------------------------------------------------------------------------------------------------------
    // signaling

    /**
        Handle one signaling request: POST application/json { sdp, connectToken } → 200 { sdp }.
        Errors: 400 malformed, 403 bad / expired / foreign / overused token, 405 method, 408 slow body, 413 body too
        large, 415 content type, 429 per-IP limit, 503 server full or closed. Never throws.
     */

    async handleSignal( req: IncomingMessage, res: ServerResponse ): Promise<void>
    {
        const ip = this.ClientIp( req );
        try
        {
            this.ApplyCors( req, res );

            if ( req.method === 'OPTIONS' && this.m_options.cors )
            {
                res.statusCode = 204;
                res.end();
                return;
            }

            if ( req.method !== 'POST' )
            {
                res.setHeader( 'Allow', this.m_options.cors ? 'POST, OPTIONS' : 'POST' );
                throw new SignalError( 405, 'method not allowed' );
            }

            if ( !this.m_opened || !this.m_ndc )
                throw new SignalError( 503, 'server not open' );

            const contentType = String( req.headers['content-type'] ?? '' ).split( ';' )[0].trim().toLowerCase();
            if ( contentType !== 'application/json' )
                throw new SignalError( 415, 'content type must be application/json' );

            const maxBodyBytes = this.m_options.maxBodyBytes ?? 16384;
            const declaredLength = Number( req.headers['content-length'] );
            if ( Number.isFinite( declaredLength ) && declaredLength > maxBodyBytes )
                throw new SignalError( 413, 'body too large' );

            // cheap limits before reading or decrypting anything
            this.CheckLimits( ip );

            const body = await ReadBody( req, maxBodyBytes, this.m_options.bodyTimeoutMs ?? 5000 );

            let request: { sdp?: unknown, connectToken?: unknown };
            try
            {
                request = JSON.parse( body );
            }
            catch
            {
                throw new SignalError( 400, 'body is not JSON' );
            }
            if ( typeof request !== 'object' || request === null || typeof request.sdp !== 'string' || typeof request.connectToken !== 'string' )
                throw new SignalError( 400, 'expected { sdp: string, connectToken: string }' );
            if ( !request.sdp.startsWith( 'v=0' ) )
                throw new SignalError( 400, 'sdp is not an SDP offer' );

            // the DoS gate: a valid connect token for this server, before any peer connection exists

            const token = DecodeBase64( request.connectToken );
            if ( !token )
                throw new SignalError( 403, 'connect token is not base64' );
            const validation = ValidateConnectToken( token, this.m_options.privateKey, this.m_options.protocolId, this.m_address );
            if ( !validation.ok )
                throw new SignalError( 403, `invalid connect token (${validation.reason})` );

            this.PruneTokenUses();
            const uses = this.m_tokenUses.get( validation.info.tokenId );
            if ( uses && uses.uses >= ( this.m_options.maxSignalsPerToken ?? 2 ) )
                throw new SignalError( 403, 'connect token already used' );

            this.CheckLimits( ip );           // again: the body read was async

            if ( uses )
                uses.uses++;
            else
            {
                if ( this.m_tokenUses.size >= 65536 )
                    this.m_tokenUses.delete( this.m_tokenUses.keys().next().value! );
                this.m_tokenUses.set( validation.info.tokenId, { uses: 1, expire: validation.info.expireTimestamp } );
            }

            const peer = this.CreatePeer( ip );
            let answer: string;
            try
            {
                answer = await this.Answer( peer, request.sdp );
            }
            catch ( error )
            {
                this.ReleasePeer( peer, false, 'answer failed' );
                throw error;
            }

            if ( peer.state === 'closed' )
                throw new SignalError( 503, 'peer closed while answering' );

            // the client went away while we gathered (req.destroyed is no use: a fully read request is destroyed)
            if ( res.destroyed || res.socket?.destroyed )
            {
                this.ReleasePeer( peer, false, 'signaling client went away' );
                return;
            }

            this.m_stats.signalsAccepted++;
            try { this.m_options.onSignal?.( { ip, status: 200, reason: 'ok' } ); } catch { /* listener errors are not ours */ }
            res.statusCode = 200;
            res.setHeader( 'Content-Type', 'application/json' );
            res.setHeader( 'Cache-Control', 'no-store' );
            res.end( JSON.stringify( { sdp: answer } ) );
        }
        catch ( error )
        {
            const status = error instanceof SignalError ? error.status : 500;
            const reason = error instanceof Error ? error.message : String( error );
            this.m_stats.signalsRejected++;
            try { this.m_options.onSignal?.( { ip, status, reason } ); } catch { /* listener errors are not ours */ }
            if ( !res.headersSent && !res.destroyed )
            {
                res.statusCode = status;
                res.setHeader( 'Content-Type', 'text/plain; charset=utf-8' );
                res.setHeader( 'Cache-Control', 'no-store' );
                if ( status === 413 || status === 408 )
                {
                    // the body may still be arriving. answer, then discard what's left (bounded) before closing: closing
                    // with unread data sends a TCP RST, and Windows clients drop the response they haven't read yet
                    res.setHeader( 'Connection', 'close' );
                    res.on( 'finish', () => DrainThenClose( req ) );
                }
                res.end( status === 500 ? 'internal error' : reason );
            }
        }
    }

    /**
        Start a node:http server that routes POST (and OPTIONS, with cors) on options.path (default '/signal') to
        handleSignal and answers 404 elsewhere. Closed by close(). Resolves once listening.
     */

    async listenSignaling( port: number, options: { path?: string, host?: string } = {} ): Promise<HttpServer>
    {
        const http = process.getBuiltinModule( 'node:http' );
        const path = options.path ?? '/signal';
        const server = http.createServer( ( req, res ) =>
        {
            const url = new URL( req.url ?? '/', 'http://localhost' );
            if ( url.pathname === path )
            {
                void this.handleSignal( req, res );
                return;
            }
            res.statusCode = 404;
            res.end( 'not found' );
        } );
        server.headersTimeout = 10000;
        server.requestTimeout = 15000;
        await new Promise<void>( ( resolve, reject ) =>
        {
            server.once( 'error', reject );
            server.listen( port, options.host, () => { server.off( 'error', reject ); resolve(); } );
        } );
        this.m_httpServers.add( server );
        server.on( 'close', () => this.m_httpServers.delete( server ) );
        return server;
    }

    // ------------------------------------------------------------------------------------------------------

    private ReceiveWebRTCPacket( from: Address, packetData: Uint8Array, maxPacketBytes: number ): number
    {
        while ( this.m_queueStart < this.m_queue.length )
        {
            const packet = this.m_queue[this.m_queueStart];
            this.m_queue[this.m_queueStart++] = undefined as unknown as QueuedPacket;
            if ( this.m_queueStart === this.m_queue.length )
            {
                this.m_queue = [];
                this.m_queueStart = 0;
            }
            else if ( this.m_queueStart >= 1024 )
            {
                this.m_queue = this.m_queue.slice( this.m_queueStart );
                this.m_queueStart = 0;
            }

            const peer = packet.peer;
            peer.queued--;
            if ( peer.state !== 'open' || packet.data.length > maxPacketBytes || packet.data.length > packetData.length )
                continue;

            packetData.set( packet.data );
            from.Assign( peer.address );
            return packet.data.length;
        }
        return 0;
    }

    private ReceiveUDPPacket( from: Address, packetData: Uint8Array, maxPacketBytes: number ): number
    {
        const socket = this.m_socket;
        if ( !socket || socket.handle === null )
            return 0;
        while ( true )
        {
            const bytes = netcode_socket_receive_packet( socket, this.m_udpFrom, packetData, maxPacketBytes );
            if ( bytes <= 0 )
                return 0;
            const address = AddressFromNetcode( this.m_udpFrom );
            if ( this.IsPeerAddress( address ) )
            {
                // a UDP source inside our synthetic prefix would alias a WebRTC peer: never deliver it
                this.m_stats.spoofedUdpDropped++;
                continue;
            }
            from.Assign( address );
            return bytes;
        }
    }

    private FindPeer( address: Address ): WebRTCPeer | null
    {
        if ( !this.IsPeerAddress( address ) )
            return null;
        const fields = address.GetAddress6();
        const id = fields[5] * 0x100000000 + fields[6] * 0x10000 + fields[7];
        const peer = this.m_peers.get( id );
        return peer && peer.address.Equals( address ) ? peer : null;
    }

    private ClientIp( req: IncomingMessage ): string
    {
        try
        {
            return this.m_options.clientIp?.( req ) ?? req.socket?.remoteAddress ?? 'unknown';
        }
        catch
        {
            return 'unknown';
        }
    }

    private ApplyCors( req: IncomingMessage, res: ServerResponse ): void
    {
        const cors = this.m_options.cors;
        if ( !cors )
            return;
        const origin = req.headers.origin;
        if ( cors.origins === '*' )
            res.setHeader( 'Access-Control-Allow-Origin', '*' );
        else if ( origin && cors.origins.includes( origin ) )
        {
            res.setHeader( 'Access-Control-Allow-Origin', origin );
            res.setHeader( 'Vary', 'Origin' );
        }
        else
            return;
        if ( req.method === 'OPTIONS' )
        {
            res.setHeader( 'Access-Control-Allow-Methods', 'POST, OPTIONS' );
            res.setHeader( 'Access-Control-Allow-Headers', [ 'Content-Type', ...( cors.allowHeaders ?? [] ) ].join( ', ' ) );
            res.setHeader( 'Access-Control-Max-Age', '600' );
        }
    }

    private CheckLimits( ip: string ): void
    {
        if ( ( this.m_pendingPerIp.get( ip ) ?? 0 ) >= ( this.m_options.maxPendingPeersPerIp ?? 4 ) )
            throw new SignalError( 429, 'too many connecting peers from this address' );
        if ( ( this.m_peersPerIp.get( ip ) ?? 0 ) >= ( this.m_options.maxPeersPerIp ?? 16 ) )
            throw new SignalError( 429, 'too many peers from this address' );
        if ( this.m_pendingCount >= ( this.m_options.maxPendingPeers ?? 32 ) )
            throw new SignalError( 503, 'too many connecting peers' );
        if ( this.m_peers.size >= ( this.m_options.maxPeers ?? 256 ) )
            throw new SignalError( 503, 'server full' );
    }

    private PruneTokenUses(): void
    {
        const time = now();
        if ( time - this.m_lastTokenPrune < 1000 || this.m_tokenUses.size === 0 )
            return;
        this.m_lastTokenPrune = time;
        const unixTime = BigInt( Math.floor( Date.now() / 1000 ) );
        for ( const [ tokenId, entry ] of this.m_tokenUses )
        {
            if ( entry.expire <= unixTime )
                this.m_tokenUses.delete( tokenId );
        }
    }

    private CreatePeer( ip: string ): WebRTCPeer
    {
        const id = this.m_nextPeerId++;
        const address = new Address( [ this.m_prefix[0], this.m_prefix[1], this.m_prefix[2], this.m_prefix[3],
                                       0, Math.floor( id / 0x100000000 ) & 0xFFFF, Math.floor( id / 0x10000 ) & 0xFFFF, id & 0xFFFF ], SyntheticPort );
        const peer = new WebRTCPeer( id, address, ip, now() );
        this.m_peers.set( id, peer );
        this.m_pendingCount++;
        this.m_pendingPerIp.set( ip, ( this.m_pendingPerIp.get( ip ) ?? 0 ) + 1 );
        this.m_peersPerIp.set( ip, ( this.m_peersPerIp.get( ip ) ?? 0 ) + 1 );
        this.m_stats.peersCreated++;
        return peer;
    }

    private async Answer( peer: WebRTCPeer, offer: string ): Promise<string>
    {
        const ndc = this.m_ndc!;
        const pc = new ndc.PeerConnection( `yojimbo-${peer.id}`, {
            ...this.m_options.rtcConfig,
            iceServers: this.m_options.iceServers ?? [],
            disableAutoNegotiation: true,
        } );
        peer.pc = pc;

        pc.onStateChange( state =>
        {
            if ( state === 'failed' || state === 'closed' )
                this.ReleasePeer( peer, false, `peer connection ${state}` );
        } );

        try
        {
            pc.setRemoteDescription( offer, 'offer' );
        }
        catch ( error )
        {
            throw new SignalError( 400, `bad offer: ${error instanceof Error ? error.message : String( error )}` );
        }

        // pre-negotiated, as the client creates it: unordered, no retransmits (UDP semantics)
        const channel = pc.createDataChannel( WebRTCChannelLabel, { negotiated: true, id: WebRTCChannelId, unordered: true, maxRetransmits: 0 } );
        peer.channel = channel;
        channel.onOpen( () => this.OnPeerOpen( peer ) );
        channel.onClosed( () => this.ReleasePeer( peer, false, 'data channel closed' ) );
        channel.onError( error => this.ReleasePeer( peer, false, `data channel error: ${error}` ) );
        channel.onMessage( message => this.OnPeerMessage( peer, message ) );

        const gathered = new Promise<void>( resolve =>
        {
            const timer = setTimeout( resolve, this.m_options.iceGatheringTimeoutMs ?? 5000 );
            pc.onGatheringStateChange( state => { if ( state === 'complete' ) { clearTimeout( timer ); resolve(); } } );
        } );

        try
        {
            pc.setLocalDescription( 'answer' );
        }
        catch ( error )
        {
            throw new SignalError( 400, `cannot answer the offer: ${error instanceof Error ? error.message : String( error )}` );
        }

        if ( pc.gatheringState() !== 'complete' )
            await gathered;

        if ( peer.state === 'closed' )
            throw new SignalError( 503, 'peer closed while gathering' );

        const description = pc.localDescription();
        if ( !description || !description.sdp )
            throw new SignalError( 500, 'no local description' );
        return description.sdp;
    }

    private OnPeerOpen( peer: WebRTCPeer ): void
    {
        if ( peer.state !== 'pending' )
            return;
        peer.state = 'open';
        peer.opened = now();
        this.DecrementPending( peer );
        this.EmitPeerEvent( peer, 'open', 'data channel open' );
    }

    private EmitPeerEvent( peer: WebRTCPeer, event: 'open' | 'released', reason: string ): void
    {
        try
        {
            this.m_options.onPeerEvent?.( { address: peer.address.ToString(), ip: peer.ip, event, reason } );
        }
        catch
        {
            // listener errors are not ours
        }
    }

    private OnPeerMessage( peer: WebRTCPeer, message: string | Uint8Array | ArrayBuffer ): void
    {
        if ( peer.state !== 'open' )
            return;
        peer.lastReceive = now();
        peer.receivedAny = true;
        if ( typeof message === 'string' )
        {
            this.m_stats.packetsDropped++;
            return;
        }
        const data = message instanceof ArrayBuffer ? new Uint8Array( message ) : message;
        if ( data.length === 0 || data.length > MaxAdapterPacketBytes
             || this.m_queue.length - this.m_queueStart >= ( this.m_options.maxQueuedPackets ?? 4096 )
             || peer.queued >= ( this.m_options.maxQueuedPacketsPerPeer ?? 256 ) )
        {
            this.m_stats.packetsDropped++;
            return;
        }
        peer.queued++;
        this.m_queue.push( new QueuedPacket( peer, data ) );
    }

    private DecrementPending( peer: WebRTCPeer ): void
    {
        this.m_pendingCount--;
        const count = ( this.m_pendingPerIp.get( peer.ip ) ?? 1 ) - 1;
        if ( count > 0 )
            this.m_pendingPerIp.set( peer.ip, count );
        else
            this.m_pendingPerIp.delete( peer.ip );
    }

    private ReleasePeer( peer: WebRTCPeer, reaped: boolean, reason: string ): void
    {
        if ( peer.state === 'closed' )
            return;
        if ( peer.state === 'pending' )
            this.DecrementPending( peer );
        peer.state = 'closed';
        this.m_peers.delete( peer.id );
        const count = ( this.m_peersPerIp.get( peer.ip ) ?? 1 ) - 1;
        if ( count > 0 )
            this.m_peersPerIp.set( peer.ip, count );
        else
            this.m_peersPerIp.delete( peer.ip );
        if ( reaped )
            this.m_stats.peersReaped++;
        this.EmitPeerEvent( peer, 'released', reason );

        // its netcode client (if any) cannot hear us any more: free the slot now rather than after the timeout
        const server = this.m_server;
        const clientIndex = peer.clientIndex;
        peer.clientIndex = -1;
        if ( server && clientIndex >= 0 && server.IsRunning() && server.IsClientConnected( clientIndex ) )
        {
            const address = server.GetClientAddress( clientIndex );
            if ( address && AddressFromNetcode( address ).Equals( peer.address ) )
                server.DisconnectClient( clientIndex );
        }

        // close outside of any node-datachannel callback we may be in
        const channel = peer.channel;
        const pc = peer.pc;
        peer.channel = null;
        peer.pc = null;
        setImmediate( () =>
        {
            try { channel?.close(); } catch { /* already closed */ }
            try { pc?.close(); } catch { /* already closed */ }
        } );
    }

    private Sweep(): void
    {
        const time = now();
        const pendingTimeout = this.m_options.pendingTimeoutMs ?? 10000;
        const firstPacketTimeout = this.m_options.firstPacketTimeoutMs ?? 5000;
        const handshakeTimeout = this.m_options.handshakeTimeoutMs ?? 15000;
        const idleTimeout = this.m_options.idleTimeoutMs ?? 30000;
        for ( const peer of [ ...this.m_peers.values() ] )
        {
            switch ( peer.state )
            {
                case 'pending':
                    if ( time - peer.created > pendingTimeout )
                        this.ReleasePeer( peer, true, 'never opened (pendingTimeoutMs)' );
                    break;
                case 'open':
                    if ( !peer.receivedAny && time - peer.opened > firstPacketTimeout )
                        this.ReleasePeer( peer, true, 'no packet (firstPacketTimeoutMs)' );
                    else if ( peer.receivedAny && time - peer.lastReceive > idleTimeout )
                        this.ReleasePeer( peer, true, 'idle (idleTimeoutMs)' );
                    else if ( this.m_server && !peer.connected && time - peer.opened > handshakeTimeout )
                        this.ReleasePeer( peer, true, 'no netcode connection (handshakeTimeoutMs)' );
                    break;
                case 'closing':
                    if ( time >= peer.closeAt )
                        this.ReleasePeer( peer, false, 'netcode client disconnected' );
                    break;
            }
        }
    }
}

/**
    Release node-datachannel's native threads (its global cleanup) so the process can exit. Call once at process
    shutdown, after closing every adapter and every node-datachannel peer connection (including polyfill ones).
 */

export async function ShutdownWebRTC(): Promise<void>
{
    const specifier = 'node-datachannel';
    try
    {
        const module = await import( specifier ) as { cleanup?: () => void, default?: { cleanup?: () => void } };
        ( module.cleanup ?? module.default?.cleanup )?.();
    }
    catch
    {
        // not installed: nothing to clean up
    }
}

/** Read a request body as UTF-8 with a size cap and a deadline. */

/** Discard the rest of a refused request body, at most 1 MB or 1 s, then close the connection. */

function DrainThenClose( req: IncomingMessage ): void
{
    const DrainMaxBytes = 1024 * 1024;
    const DrainMaxMs = 1000;
    let drained = 0;
    const close = () => { clearTimeout( timer ); req.off( 'data', onData ); req.destroy(); };
    const onData = ( chunk: Uint8Array ) => { drained += chunk.length; if ( drained > DrainMaxBytes ) close(); };
    const timer = setTimeout( close, DrainMaxMs );
    req.on( 'data', onData );
    req.once( 'end', close );
    req.once( 'error', close );
    req.resume();
}

function ReadBody( req: IncomingMessage, maxBytes: number, timeoutMs: number ): Promise<string>
{
    return new Promise<string>( ( resolve, reject ) =>
    {
        const chunks: Uint8Array[] = [];
        let total = 0;
        let done = false;
        const finish = ( error: SignalError | null ) =>
        {
            if ( done )
                return;
            done = true;
            clearTimeout( timer );
            req.off( 'data', onData );
            req.off( 'end', onEnd );
            req.off( 'error', onError );
            if ( error )
            {
                req.pause();
                reject( error );
            }
            else
                resolve( new TextDecoder().decode( Buffer.concat( chunks ) ) );
        };
        const onData = ( chunk: Uint8Array ) =>
        {
            total += chunk.length;
            if ( total > maxBytes )
                finish( new SignalError( 413, 'body too large' ) );
            else
                chunks.push( chunk );
        };
        const onEnd = () => finish( null );
        const onError = () => finish( new SignalError( 400, 'request error' ) );
        const timer = setTimeout( () => finish( new SignalError( 408, 'body timeout' ) ), timeoutMs );
        req.on( 'data', onData );
        req.on( 'end', onEnd );
        req.on( 'error', onError );
    } );
}
