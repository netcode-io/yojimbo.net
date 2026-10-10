/*
    yojimbo TypeScript port: WebRTC transport extension.

    This folder is an EXTENSION of the TypeScript port, not a mirror of an upstream file: upstream yojimbo has no
    WebRTC transport. It is distributed under the same BSD 3-Clause license as the rest of this package.

    webrtc_server.ts: the server side, for Node and for browsers. It uses the standard RTCPeerConnection /
    RTCDataChannel API: options.RTCPeerConnection if given, else the browser's own (globalThis.RTCPeerConnection),
    else, on Node, node-datachannel's polyfill (the optional peer dependency node-datachannel, loaded lazily by
    open(), so merely importing this file pulls in nothing native). This file has no node:* import: native UDP goes
    through netcode's socket layer (node:dgram via process.getBuiltinModule), and the Node HTTP signaling lives in
    webrtc_server_http.ts.

    WebRTCServerAdapter is a yojimbo Adapter with custom packet I/O that serves BOTH kinds of client on one
    yojimbo Server:

      - native UDP clients (Node, C++, C#), on Node only: the adapter owns a UDP socket bound to the server address
        (netcode's own socket layer), so they connect exactly as to a plain yojimbo server. In a browser there is
        no UDP and the server is WebRTC only;
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

    Signaling: accept( { sdp, connectToken, ip } ) takes one client offer (non-trickle) and resolves with the
    answer { sdp } after the server's ICE gathering completes, or throws SignalError( status, reason ). It is the
    one gate every signaling transport goes through: HTTP (HandleSignal / ListenSignaling in webrtc_server_http.ts,
    Node), a WebSocket, a BroadcastChannel to another tab, or a client in the same page calling it directly. The
    connect token is validated BEFORE any peer connection is created: decrypted with the server's private key (so
    only your token issuer can open a peer), protocol id, expiry, and this server's address in the token's
    encrypted server list -- the same checks netcode makes on a connection request. That is the DoS gate. On top:
    per-IP and global caps on pending and total peers, a per-token signal count, and timeouts that reap peers which
    never open, never send, never complete the netcode handshake, or go idle. A peer is released when netcode
    disconnects its client (after a short linger so the disconnect packets get out) or when its channel / peer
    connection closes or fails.

    Per-IP caps key on request.ip: the client's IP for HTTP, or any stable per-caller identity your transport has
    (a session or user id). Without one only the global caps apply, so a transport that cannot tell callers apart
    should authenticate them before calling accept().

    Usage:

        class GameServerAdapter extends WebRTCServerAdapter { override CreateMessageFactory( ... ) { ... } }
        const adapter = new GameServerAdapter( { address: '203.0.113.7:40000', privateKey, protocolId } );
        await adapter.open();                                         // finds RTCPeerConnection, binds UDP (Node)
        const server = new Server( allocator, privateKey, adapter.address, config, adapter, time );
        server.Start( maxClients );
        adapter.attachServer( server );                               // lets it map client slots to peers
        await ListenSignaling( adapter, 8080, { path: '/signal' } );  // Node HTTP (webrtc_server_http.ts), and/or
        const answer = await adapter.accept( { sdp, connectToken, ip } );    // from your own signaling
        ...drive the server as usual; at shutdown: server.Stop(); adapter.close();

    In a browser it is the same, WebRTC only, with an explicit port in the address (there it is only the identity
    connect tokens name). The page then holds the server private key: mint a fresh key per session on your backend.

    If you override OnServerClientConnected / OnServerClientDisconnected, call super.
*/

import {
    Adapter, Address, Server, MaxAdapterPacketBytes, AddressFromNetcode, AddressToNetcode, yojimbo_random_bytes,
    ADDRESS_IPV6,
} from '../source/yojimbo.ts';
import {
    netcode_socket_t, netcode_socket_create, netcode_socket_destroy, netcode_socket_send_packet, netcode_socket_receive_packet,
    netcode_address_t, NETCODE_SOCKET_ERROR_NONE, NETCODE_ADDRESS_IPV6, NETCODE_SERVER_SOCKET_SNDBUF_SIZE, NETCODE_SERVER_SOCKET_RCVBUF_SIZE,
} from '../netcode/netcode.ts';
import { GenerateConnectToken, ValidateConnectToken } from './webrtc_token.ts';
import type { GenerateConnectTokenOptions } from './webrtc_token.ts';
import { CreateNetcodeChannel, WaitForIceGathering, NetcodeChannelPacket, DescribeError } from './webrtc_client.ts';
import type { RTCPeerConnectionConstructor } from './webrtc_client.ts';

export { GenerateConnectToken, ValidateConnectToken, EncodeBase64, DecodeBase64 } from './webrtc_token.ts';
export type { GenerateConnectTokenOptions, ConnectTokenInfo, ValidateConnectTokenResult } from './webrtc_token.ts';

// The public types below are structural on purpose: a Node server project need not include the DOM lib to use
// this file's declarations (webrtc_client.ts's do need it).

/**
    An RTCPeerConnection constructor: globalThis.RTCPeerConnection in browsers, node-datachannel/polyfill's in Node.
    (webrtc_client.ts's RTCPeerConnectionConstructor, typed loosely so these declarations need no DOM lib.)
 */
export type WebRTCPeerConnectionConstructor = new ( configuration?: any ) => object;

/**
    A STUN / TURN server: a standard RTCIceServer ({ urls, username, credential }), or, as before, a node-datachannel
    string 'stun:host:port' / 'turn:user:pass@host:port' or object { hostname, port, username, password, relayType }.
 */
export type WebRTCServerIceServer = { urls: string | string[], username?: string, credential?: string } | string | { hostname: string, port: number, username?: string, password?: string, relayType?: 'TurnUdp' | 'TurnTcp' | 'TurnTls' };

/**
    One signaling request for WebRTCServerAdapter.accept: the client's offer (webrtc_client.ts's WebRTCSignalOffer),
    plus who is asking.
 */
export interface WebRTCSignalRequest
{
    /** The client's SDP offer (non-trickle). */
    sdp: string;
    /** The client's ConnectTokenBytes connect token. */
    connectToken: Uint8Array;
    /** The client IP, or any stable per-caller identity, for the per-IP caps. Omitted: only the global caps apply. */
    ip?: string;
    /** Fires if the caller goes away: the peer is released and accept() rejects with 499. */
    signal?: AbortSignal;
}

export interface WebRTCServerOptions
{
    /** The server address: the UDP socket binds to it and it is the address in connect tokens. Port 0 picks a free port (UDP only; read adapter.address after open()). */
    address: Address | string;
    /** The server private key (same as passed to Server). */
    privateKey: Uint8Array;
    /** ClientServerConfig.protocolId. */
    protocolId: bigint;
    /** Serve native UDP clients too (Node only). Default: true where node:dgram exists (Node), else false. true without UDP throws. */
    udp?: boolean;
    /** RTCPeerConnection constructor. Default globalThis.RTCPeerConnection, else on Node node-datachannel/polyfill's. */
    RTCPeerConnection?: WebRTCPeerConnectionConstructor;
    /** STUN / TURN servers for the server's own candidates. Default none (fine when the server has a public IP or on a LAN). */
    iceServers?: WebRTCServerIceServer[];
    /**
        Extra RTCConfiguration fields. Through node-datachannel's polyfill its RtcConfig fields pass too: e.g.
        { portRangeBegin, portRangeEnd } or { enableIceUdpMux: true } for firewalls, bindAddress.
     */
    rtcConfig?: Record<string, unknown>;
    /** Max peers (pending + open). Default 256. */
    maxPeers?: number;
    /** Max peers per client IP (request.ip). Default 16. */
    maxPeersPerIp?: number;
    /** Max peers still connecting (signaled, channel not open yet). Default 32. */
    maxPendingPeers?: number;
    /** Max connecting peers per client IP (request.ip). Default 4. */
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
    /** Merged WebRTC receive queue size in packets. Default 4096. */
    maxQueuedPackets?: number;
    /** Per-peer share of the receive queue in packets. Default 256. */
    maxQueuedPacketsPerPeer?: number;
    /** Sends to a peer are dropped while its channel buffers more than this. Default 1 MiB. */
    maxBufferedBytes?: number;
    /** Called with every signaling decision (logging / metrics). ip is '' when the request had none. */
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
    ip: string | null;
    pc: RTCPeerConnection | null = null;
    channel: RTCDataChannel | null = null;
    state: PeerState = 'pending';
    created: number;
    opened = 0;
    lastReceive = 0;
    receivedAny = false;
    connected = false;
    closeAt = 0;
    queued = 0;
    clientIndex = -1;

    constructor( id: number, address: Address, ip: string | null, now: number )
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

/**
    A refused signaling request. status is what the HTTP signaling answers with: 400 malformed offer, 403 bad /
    expired / foreign / overused token, 429 per-IP limit, 499 caller went away, 503 server full or closed, 500 other.
 */

export class SignalError extends Error
{
    status: number;

    constructor( status: number, message: string )
    {
        super( message );
        this.name = 'SignalError';
        this.status = status;
    }
}

/**
    yojimbo server Adapter that multiplexes native UDP clients (Node) and WebRTC peers. Dedicated to one Server.
 */

export class WebRTCServerAdapter extends Adapter
{
    private m_options: WebRTCServerOptions;
    private m_address: Address;
    private m_PeerConnection: RTCPeerConnectionConstructor | null = null;
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
    private m_closeListeners = new Set<() => void>();

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

    /** True if open() bound a UDP socket for native clients. */
    get servesUdp(): boolean { return this.m_socket !== null; }

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
        Find the RTCPeerConnection constructor (on Node without one: load node-datachannel's polyfill) and bind the
        UDP socket (Node, unless options.udp is false). Throws on failure.
        Call before constructing the Server, and construct it with adapter.address.
     */

    async open(): Promise<void>
    {
        if ( this.m_opened )
            return;

        if ( !this.m_address.IsValid() )
            throw new Error( 'WebRTCServerAdapter: invalid server address' );

        const PeerConnection = this.m_options.RTCPeerConnection as RTCPeerConnectionConstructor | undefined
            ?? ( globalThis as { RTCPeerConnection?: RTCPeerConnectionConstructor } ).RTCPeerConnection
            ?? await LoadNodePolyfill();
        if ( !PeerConnection )
            throw new Error( 'WebRTCServerAdapter: no RTCPeerConnection on this platform (pass options.RTCPeerConnection)' );

        const udpAvailable = HasNodeDgram();
        if ( this.m_options.udp === true && !udpAvailable )
            throw new Error( 'WebRTCServerAdapter: native UDP needs Node (pass udp: false)' );

        if ( ( this.m_options.udp ?? true ) && udpAvailable )
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

        this.m_PeerConnection = PeerConnection;
        this.m_sweepTimer = setInterval( () => this.Sweep(), SweepIntervalMs );
        ( this.m_sweepTimer as { unref?: () => void } ).unref?.();
        this.m_opened = true;
    }

    /** Let the adapter map netcode client slots to peers (release on disconnect, handshake timeout). Call after Server.Start. */

    attachServer( server: Server | null ): void
    {
        this.m_server = server;
    }

    /** Close every peer and the UDP socket, then run the onClose listeners (ListenSignaling's HTTP server closes). Stop the Server first. */

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
        this.m_server = null;
        this.m_opened = false;
        const listeners = [ ...this.m_closeListeners ];
        this.m_closeListeners.clear();
        for ( const listener of listeners )
        {
            try { listener(); } catch { /* listener errors are not ours */ }
        }
    }

    /** Run listener once when close() is called (e.g. to stop a signaling transport). Returns a function that removes it. */

    onClose( listener: () => void ): () => void
    {
        this.m_closeListeners.add( listener );
        return () => { this.m_closeListeners.delete( listener ); };
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
            if ( !peer || !channel || ( peer.state !== 'open' && peer.state !== 'closing' ) || channel.readyState !== 'open' || channel.bufferedAmount > ( this.m_options.maxBufferedBytes ?? 1024 * 1024 ) )
            {
                this.m_stats.packetsDropped++;
                return;
            }
            try
            {
                // packetData is only valid during the call: send a copy
                channel.send( packetData.slice( 0, packetBytes ) );
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
        Accept one client offer: check the limits and the connect token, then create the peer and answer. Every
        signaling transport goes through here (see the file comment). Resolves with { sdp } once the server's ICE
        gathering completes; throws SignalError( status, reason ) on refusal (400 malformed offer, 403 bad /
        expired / foreign / overused token, 429 per-IP limit, 499 aborted, 503 server full or closed).
        Every outcome is counted in stats and reported to options.onSignal.
     */

    async accept( request: WebRTCSignalRequest ): Promise<{ sdp: string }>
    {
        const ip = typeof request?.ip === 'string' ? request.ip : null;
        try
        {
            const sdp = await this.Accept( request, ip );
            this.reportSignal( ip, 200, 'ok' );
            return { sdp };
        }
        catch ( error )
        {
            const status = error instanceof SignalError ? error.status : 500;
            const reason = error instanceof Error ? error.message : String( error );
            this.reportSignal( ip, status, reason );
            throw error instanceof SignalError ? error : new SignalError( 500, reason );
        }
    }

    /**
        The cheap checks accept() starts with (server open, per-IP and global caps), for a transport to run before it
        reads a request, as HandleSignal does. Throws SignalError and reports nothing: report it with reportSignal.
     */

    precheck( ip?: string | null ): void
    {
        if ( !this.m_opened || !this.m_PeerConnection )
            throw new SignalError( 503, 'server not open' );
        this.CheckLimits( ip ?? null );
    }

    /**
        Count and report (options.onSignal) a signaling refusal made outside accept(), e.g. by a transport before it
        got to accept() (bad method, body too large). accept() reports its own outcomes.
     */

    reportSignal( ip: string | null | undefined, status: number, reason: string ): void
    {
        if ( status === 200 )
            this.m_stats.signalsAccepted++;
        else
            this.m_stats.signalsRejected++;
        try { this.m_options.onSignal?.( { ip: ip ?? '', status, reason } ); } catch { /* listener errors are not ours */ }
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

    private async Accept( request: WebRTCSignalRequest, ip: string | null ): Promise<string>
    {
        if ( !this.m_opened || !this.m_PeerConnection )
            throw new SignalError( 503, 'server not open' );

        // cheap limits before looking at (or decrypting) anything
        this.CheckLimits( ip );

        if ( typeof request !== 'object' || request === null || typeof request.sdp !== 'string' )
            throw new SignalError( 400, 'expected { sdp: string, connectToken: Uint8Array }' );
        if ( !request.sdp.startsWith( 'v=0' ) )
            throw new SignalError( 400, 'sdp is not an SDP offer' );
        if ( !( request.connectToken instanceof Uint8Array ) )
            throw new SignalError( 403, 'connect token is not bytes' );
        if ( request.signal?.aborted )
            throw new SignalError( 499, 'signaling client went away' );

        // the DoS gate: a valid connect token for this server, before any peer connection exists

        const validation = ValidateConnectToken( request.connectToken, this.m_options.privateKey, this.m_options.protocolId, this.m_address );
        if ( !validation.ok )
            throw new SignalError( 403, `invalid connect token (${validation.reason})` );

        this.PruneTokenUses();
        const uses = this.m_tokenUses.get( validation.info.tokenId );
        if ( uses && uses.uses >= ( this.m_options.maxSignalsPerToken ?? 2 ) )
            throw new SignalError( 403, 'connect token already used' );

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

        // the client went away while we gathered
        if ( request.signal?.aborted )
        {
            this.ReleasePeer( peer, false, 'signaling client went away' );
            throw new SignalError( 499, 'signaling client went away' );
        }

        return answer;
    }

    private CheckLimits( ip: string | null ): void
    {
        if ( ip !== null && ( this.m_pendingPerIp.get( ip ) ?? 0 ) >= ( this.m_options.maxPendingPeersPerIp ?? 4 ) )
            throw new SignalError( 429, 'too many connecting peers from this address' );
        if ( ip !== null && ( this.m_peersPerIp.get( ip ) ?? 0 ) >= ( this.m_options.maxPeersPerIp ?? 16 ) )
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

    private CreatePeer( ip: string | null ): WebRTCPeer
    {
        const id = this.m_nextPeerId++;
        const address = new Address( [ this.m_prefix[0], this.m_prefix[1], this.m_prefix[2], this.m_prefix[3],
                                       0, Math.floor( id / 0x100000000 ) & 0xFFFF, Math.floor( id / 0x10000 ) & 0xFFFF, id & 0xFFFF ], SyntheticPort );
        const peer = new WebRTCPeer( id, address, ip, now() );
        this.m_peers.set( id, peer );
        this.m_pendingCount++;
        if ( ip !== null )
        {
            this.m_pendingPerIp.set( ip, ( this.m_pendingPerIp.get( ip ) ?? 0 ) + 1 );
            this.m_peersPerIp.set( ip, ( this.m_peersPerIp.get( ip ) ?? 0 ) + 1 );
        }
        this.m_stats.peersCreated++;
        return peer;
    }

    private async Answer( peer: WebRTCPeer, offer: string ): Promise<string>
    {
        const PeerConnection = this.m_PeerConnection!;
        const iceServers = ( this.m_options.iceServers ?? [] ).map( ToRTCIceServer );
        let pc: RTCPeerConnection;
        try
        {
            pc = new PeerConnection( { ...this.m_options.rtcConfig, iceServers } as RTCConfiguration );
        }
        catch ( error )
        {
            throw new SignalError( 500, `cannot create a peer connection: ${error instanceof Error ? error.message : String( error )}` );
        }
        peer.pc = pc;

        pc.onconnectionstatechange = () =>
        {
            if ( pc.connectionState === 'failed' || pc.connectionState === 'closed' )
                this.ReleasePeer( peer, false, `peer connection ${pc.connectionState}` );
        };

        try
        {
            await pc.setRemoteDescription( { type: 'offer', sdp: offer } );
        }
        catch ( error )
        {
            throw new SignalError( 400, `bad offer: ${error instanceof Error ? error.message : String( error )}` );
        }

        if ( peer.state === 'closed' )
            throw new SignalError( 503, 'peer closed while answering' );

        // pre-negotiated, as the client creates it: unordered, no retransmits (UDP semantics). Created after the
        // remote offer is applied: node-datachannel would otherwise start an offer of its own
        const channel = CreateNetcodeChannel( pc );
        peer.channel = channel;
        channel.onopen = () => this.OnPeerOpen( peer );
        channel.onclose = () => this.ReleasePeer( peer, false, 'data channel closed' );
        channel.onerror = ( event ) => this.ReleasePeer( peer, false, `data channel error: ${DescribeError( event )}` );
        channel.onmessage = ( event: MessageEvent ) => this.OnPeerMessage( peer, event.data );

        try
        {
            await pc.setLocalDescription( await pc.createAnswer() );
        }
        catch ( error )
        {
            throw new SignalError( 400, `cannot answer the offer: ${error instanceof Error ? error.message : String( error )}` );
        }

        await WaitForIceGathering( pc, this.m_options.iceGatheringTimeoutMs ?? 5000 );

        if ( ( peer.state as PeerState ) === 'closed' )           // released by a callback while we waited
            throw new SignalError( 503, 'peer closed while gathering' );

        const description = pc.localDescription;
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
            this.m_options.onPeerEvent?.( { address: peer.address.ToString(), ip: peer.ip ?? '', event, reason } );
        }
        catch
        {
            // listener errors are not ours
        }
    }

    private OnPeerMessage( peer: WebRTCPeer, message: unknown ): void
    {
        if ( peer.state !== 'open' )
            return;
        peer.lastReceive = now();
        peer.receivedAny = true;
        const data = NetcodeChannelPacket( message );
        if ( !data )
        {
            this.m_stats.packetsDropped++;          // text messages are not netcode packets
            return;
        }
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
        if ( peer.ip === null )
            return;
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
        if ( peer.ip !== null )
        {
            const count = ( this.m_peersPerIp.get( peer.ip ) ?? 1 ) - 1;
            if ( count > 0 )
                this.m_peersPerIp.set( peer.ip, count );
            else
                this.m_peersPerIp.delete( peer.ip );
        }
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

        // close outside of any WebRTC callback we may be in
        const channel = peer.channel;
        const pc = peer.pc;
        peer.channel = null;
        peer.pc = null;
        if ( channel )
        {
            channel.onopen = null;
            channel.onclose = null;
            channel.onerror = null;
            channel.onmessage = null;
        }
        if ( pc )
            pc.onconnectionstatechange = null;
        setTimeout( () =>
        {
            try { channel?.close(); } catch { /* already closed */ }
            try { pc?.close(); } catch { /* already closed */ }
        }, 0 );
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
    Release node-datachannel's native threads (its global cleanup) so the process can exit. Node only: a no-op
    elsewhere. Call once at process shutdown, after closing every adapter and every node-datachannel peer connection
    (including polyfill ones).
 */

export async function ShutdownWebRTC(): Promise<void>
{
    if ( !IsNode() )
        return;
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

function IsNode(): boolean
{
    return !!( globalThis as { process?: { versions?: { node?: string } } } ).process?.versions?.node;
}

function HasNodeDgram(): boolean
{
    try
    {
        return !!( globalThis as { process?: { getBuiltinModule?: ( id: string ) => unknown } } ).process?.getBuiltinModule?.( 'node:dgram' );
    }
    catch
    {
        return false;
    }
}

/** On Node, node-datachannel's polyfill RTCPeerConnection; null elsewhere. Throws if node-datachannel is missing. */

async function LoadNodePolyfill(): Promise<RTCPeerConnectionConstructor | null>
{
    if ( !IsNode() )
        return null;
    // the specifier is a variable on purpose: bundlers and tsc leave the optional native dependency alone
    const specifier = 'node-datachannel/polyfill';
    let module: { RTCPeerConnection?: RTCPeerConnectionConstructor, default?: { RTCPeerConnection?: RTCPeerConnectionConstructor } };
    try
    {
        module = await import( specifier );
    }
    catch ( error )
    {
        throw new Error( `WebRTCServerAdapter: node-datachannel is required on Node (npm install node-datachannel): ${error instanceof Error ? error.message : String( error )}` );
    }
    const PeerConnection = module.RTCPeerConnection ?? module.default?.RTCPeerConnection;
    if ( !PeerConnection )
        throw new Error( 'WebRTCServerAdapter: node-datachannel/polyfill has no RTCPeerConnection' );
    return PeerConnection;
}

/** WebRTCServerIceServer → RTCIceServer (node-datachannel's string and object forms are still accepted). */

function ToRTCIceServer( server: WebRTCServerIceServer ): RTCIceServer
{
    if ( typeof server === 'string' )
    {
        // 'turn:user:pass@host:port' carries its credentials in the URL
        const match = /^(turns?):([^:@]*):([^@]*)@(.+)$/.exec( server );
        return match ? { urls: `${match[1]}:${match[4]}`, username: decodeURIComponent( match[2] ), credential: decodeURIComponent( match[3] ) } : { urls: server };
    }
    if ( 'hostname' in server )
    {
        const turn = server.username !== undefined || server.relayType !== undefined;
        const scheme = !turn ? 'stun' : server.relayType === 'TurnTls' ? 'turns' : 'turn';
        const transport = server.relayType === 'TurnTcp' ? '?transport=tcp' : '';
        return { urls: `${scheme}:${server.hostname}:${server.port}${transport}`, username: server.username, credential: server.password };
    }
    return server as RTCIceServer;
}
