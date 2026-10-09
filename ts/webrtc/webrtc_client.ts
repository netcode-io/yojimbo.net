/*
    yojimbo TypeScript port: WebRTC transport extension.

    This folder is an EXTENSION of the TypeScript port, not a mirror of an upstream file: upstream yojimbo has no
    WebRTC transport. It is distributed under the same BSD 3-Clause license as the rest of this package.

    webrtc_client.ts: the browser side. A yojimbo Adapter that carries netcode packets over one WebRTC data channel
    to a Node server running WebRTCServerAdapter (webrtc_server.ts). Platform neutral: in a browser it uses the
    native RTCPeerConnection; in Node (tests) pass node-datachannel's polyfill RTCPeerConnection in the options.

    Usage (subclass it instead of Adapter, exactly as you would subclass Adapter):

        class GameAdapter extends WebRTCClientAdapter
        {
            override CreateMessageFactory( allocator: Allocator ) { return YOJIMBO_NEW( allocator, () => new GameMessageFactory( allocator ) ); }
        }

        const adapter = new GameAdapter( { iceServers: [ { urls: 'stun:stun.example.com:3478' } ] } );
        const client = new Client( GetDefaultAllocator(), new Address( '0.0.0.0' ), config, adapter, yojimbo_time() );
        const connectToken = ...;                                 // ConnectTokenBytes, from your backend
        await adapter.connect( 'https://game.example.com/signal', connectToken );
        client.Connect( clientId, connectToken );                 // then drive the client as usual

    connect() does the WebRTC part (non-trickle ICE, one HTTP POST of { sdp, connectToken } answered with { sdp }) and
    resolves once the data channel is open. client.Connect then runs the normal netcode handshake through the channel:
    the netcode packets are the same encrypted packets UDP carries, so the channel adds no trust of its own. For dev,
    client.InsecureConnect( privateKey, clientId, serverAddress ) works too; the signaling endpoint still wants a
    valid token, so mint one with GenerateConnectToken (webrtc_token.ts) from the same private key.

    Channel: pre-negotiated (negotiated: true, id 0) on both ends, unordered with maxRetransmits 0, i.e. UDP
    semantics. (With an in-band DCEP channel the answering side was observed to report ordered / reliable.)

    Failure: if the channel or peer connection closes or fails, the adapter enters the 'closed' / 'failed' state
    and drops every packet from then on. The yojimbo client then times out on its own as it would on a dead UDP
    path; check adapter.state (or onStateChange) to react sooner.

    ICE: no ICE servers by default, which works on localhost and a LAN. Across NATs add STUN (and TURN for
    symmetric NATs / strict firewalls) in options.iceServers, e.g.
        [ { urls: 'stun:stun.l.google.com:19302' }, { urls: 'turn:turn.example.com:3478', username, credential } ]
*/

import { Adapter, Address, MaxAdapterPacketBytes, ConnectTokenBytes } from '../source/yojimbo.ts';
import { EncodeBase64, ConnectTokenServerAddresses } from './webrtc_token.ts';

/** The data channel both ends create (pre-negotiated). */
export const WebRTCChannelLabel = 'netcode';
export const WebRTCChannelId = 0;

export type WebRTCClientState = 'idle' | 'connecting' | 'open' | 'closed' | 'failed';

/** An RTCPeerConnection constructor: globalThis.RTCPeerConnection in browsers, node-datachannel/polyfill's in Node. */
export type RTCPeerConnectionConstructor = new ( configuration?: RTCConfiguration ) => RTCPeerConnection;

export interface WebRTCClientOptions
{
    /** Default globalThis.RTCPeerConnection. */
    RTCPeerConnection?: RTCPeerConnectionConstructor;
    /** ICE servers (STUN / TURN). Default none: fine for localhost and LAN. */
    iceServers?: RTCIceServer[];
    /** Extra RTCConfiguration fields (e.g. iceTransportPolicy: 'relay'). */
    rtcConfiguration?: RTCConfiguration;
    /** fetch implementation for the signaling POST. Default globalThis.fetch. */
    fetch?: typeof fetch;
    /** Extra headers on the signaling POST (e.g. an auth header for your own gateway). */
    headers?: Record<string, string>;
    /** Max wait for ICE gathering before sending the offer with the candidates found so far. Default 5000 ms. */
    iceGatheringTimeoutMs?: number;
    /** Max time for the whole connect() (gathering + signaling + channel open). Default 15000 ms. */
    connectTimeoutMs?: number;
    /** Received packets waiting for ReceivePacket; beyond this they are dropped (as a full socket buffer drops). Default 1024. */
    maxQueuedPackets?: number;
    /** Sends are dropped while the channel has more than this many bytes buffered (UDP semantics, no unbounded buffering). Default 1 MiB. */
    maxBufferedBytes?: number;
    /** Called on every state change. */
    onStateChange?: ( state: WebRTCClientState, error: string | null ) => void;
}

/**
    yojimbo Adapter whose custom packet I/O runs over a WebRTC data channel. Dedicated to one Client.
    Subclass it and override CreateMessageFactory (and anything else) as you would Adapter.
 */

export class WebRTCClientAdapter extends Adapter
{
    private m_options: WebRTCClientOptions;
    private m_state: WebRTCClientState = 'idle';
    private m_error: string | null = null;
    private m_peer: RTCPeerConnection | null = null;
    private m_channel: RTCDataChannel | null = null;
    private m_serverAddress = new Address();
    private m_queue: Uint8Array[] = [];
    private m_queueStart = 0;
    private m_maxQueuedPackets: number;
    private m_maxBufferedBytes: number;
    private m_packetsSent = 0;
    private m_packetsReceived = 0;
    private m_packetsDropped = 0;

    constructor( options: WebRTCClientOptions = {} )
    {
        super();
        this.m_options = options;
        this.m_maxQueuedPackets = options.maxQueuedPackets ?? 1024;
        this.m_maxBufferedBytes = options.maxBufferedBytes ?? 1024 * 1024;
    }

    /** idle → connecting → open, then closed (close()) or failed (error, channel or peer connection loss). */
    get state(): WebRTCClientState { return this.m_state; }

    /** Why the adapter failed, or null. */
    get error(): string | null { return this.m_error; }

    /** Packet counters (dropped = queue full, oversized, channel congested or not open). */
    get stats(): { sent: number, received: number, dropped: number, queued: number }
    {
        return { sent: this.m_packetsSent, received: this.m_packetsReceived, dropped: this.m_packetsDropped, queued: this.m_queue.length - this.m_queueStart };
    }

    /**
        Open the WebRTC data channel to a game server.
        @param url The server's signaling endpoint (WebRTCServerAdapter.handleSignal / listenSignaling).
        @param connectToken The connect token (ConnectTokenBytes) the client will connect with. The server validates
                            it before it allocates anything for this peer.
        @returns Resolves when the channel is open; rejects (state 'failed') on any error or timeout.
     */

    async connect( url: string, connectToken: Uint8Array ): Promise<void>
    {
        if ( this.m_state !== 'idle' && this.m_state !== 'closed' && this.m_state !== 'failed' )
            throw new Error( `WebRTCClientAdapter.connect: already ${this.m_state}` );
        if ( !( connectToken instanceof Uint8Array ) || connectToken.length !== ConnectTokenBytes )
            throw new Error( 'WebRTCClientAdapter.connect: connect token must be ConnectTokenBytes bytes' );

        this.Teardown();
        this.m_error = null;
        this.m_queue = [];
        this.m_queueStart = 0;

        // netcode checks that packets come from the server address it is talking to. SendPacket tracks that
        // address; until the first send, report the token's first server address

        const addresses = ConnectTokenServerAddresses( connectToken );
        this.m_serverAddress = addresses.length > 0 ? addresses[0] : new Address();

        const PeerConnection = this.m_options.RTCPeerConnection ?? ( globalThis as { RTCPeerConnection?: RTCPeerConnectionConstructor } ).RTCPeerConnection;
        const fetchFunction = this.m_options.fetch ?? globalThis.fetch;
        if ( !PeerConnection )
            return this.Fail( 'no RTCPeerConnection on this platform (pass options.RTCPeerConnection)' );
        if ( !fetchFunction )
            return this.Fail( 'no fetch on this platform (pass options.fetch)' );

        this.SetState( 'connecting' );

        const connectTimeoutMs = this.m_options.connectTimeoutMs ?? 15000;
        const abort = new AbortController();
        let timer: ReturnType<typeof setTimeout> | undefined;
        const timeout = new Promise<never>( ( _resolve, reject ) =>
        {
            timer = setTimeout( () => { abort.abort(); reject( new Error( `connect timed out after ${connectTimeoutMs} ms` ) ); }, connectTimeoutMs );
        } );

        try
        {
            await Promise.race( [ this.Establish( PeerConnection, fetchFunction.bind( globalThis ), url, connectToken, abort.signal ), timeout ] );
        }
        catch ( error )
        {
            abort.abort();
            return this.Fail( error instanceof Error ? error.message : String( error ) );
        }
        finally
        {
            clearTimeout( timer );
        }
    }

    /** Close the channel and peer connection (state 'closed'). The yojimbo client, if still connected, will time out. */

    close(): void
    {
        this.Teardown();
        if ( this.m_state === 'open' || this.m_state === 'connecting' )
        {
            this.m_error = null;
            this.SetState( 'closed' );
        }
    }

    override Dispose(): void
    {
        this.close();
        super.Dispose();
    }

    override UseCustomPacketIO(): boolean
    {
        return true;
    }

    override SendPacket( to: Address, packetData: Uint8Array, packetBytes: number ): void
    {
        this.m_serverAddress.Assign( to );

        const channel = this.m_channel;
        if ( this.m_state !== 'open' || !channel || channel.readyState !== 'open' || packetBytes <= 0 || packetBytes > MaxAdapterPacketBytes || channel.bufferedAmount > this.m_maxBufferedBytes )
        {
            this.m_packetsDropped++;
            return;
        }

        try
        {
            // packetData is only valid during the call: send a copy
            channel.send( packetData.slice( 0, packetBytes ) );
            this.m_packetsSent++;
        }
        catch
        {
            this.m_packetsDropped++;
        }
    }

    override ReceivePacket( from: Address, packetData: Uint8Array, maxPacketBytes: number ): number
    {
        while ( this.m_queueStart < this.m_queue.length )
        {
            const packet = this.m_queue[this.m_queueStart++];
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

            if ( packet.length > maxPacketBytes || packet.length > packetData.length )
            {
                this.m_packetsDropped++;
                continue;
            }

            packetData.set( packet );
            from.Assign( this.m_serverAddress );
            this.m_packetsReceived++;
            return packet.length;
        }
        return 0;
    }

    // ------------------------------------------------------------------------------------------------------

    private async Establish( PeerConnection: RTCPeerConnectionConstructor, fetchFunction: typeof fetch, url: string, connectToken: Uint8Array, signal: AbortSignal ): Promise<void>
    {
        const configuration: RTCConfiguration = { ...this.m_options.rtcConfiguration, iceServers: this.m_options.iceServers ?? this.m_options.rtcConfiguration?.iceServers ?? [] };
        const peer = new PeerConnection( configuration );
        this.m_peer = peer;

        const channel = peer.createDataChannel( WebRTCChannelLabel, { negotiated: true, id: WebRTCChannelId, ordered: false, maxRetransmits: 0 } );
        channel.binaryType = 'arraybuffer';
        this.m_channel = channel;

        const opened = new Promise<void>( ( resolve, reject ) =>
        {
            channel.onopen = () => resolve();
            channel.onclose = () => { reject( new Error( 'data channel closed' ) ); this.OnTransportLost( channel, 'closed', 'data channel closed' ); };
            channel.onerror = ( event ) => { const message = DescribeError( event ); reject( new Error( `data channel error: ${message}` ) ); this.OnTransportLost( channel, 'failed', `data channel error: ${message}` ); };
            peer.onconnectionstatechange = () =>
            {
                if ( peer.connectionState === 'failed' || peer.connectionState === 'closed' )
                {
                    reject( new Error( `peer connection ${peer.connectionState}` ) );
                    this.OnTransportLost( channel, 'failed', `peer connection ${peer.connectionState}` );
                }
            };
        } );
        opened.catch( () => {} );         // observed via the race below; avoid an unhandled rejection after timeouts

        channel.onmessage = ( event: MessageEvent ) => this.OnMessage( channel, event.data );

        // non-trickle: gather every candidate first, then send one offer

        await peer.setLocalDescription( await peer.createOffer() );
        await WaitForIceGathering( peer, this.m_options.iceGatheringTimeoutMs ?? 5000 );
        const offer = peer.localDescription;
        if ( !offer || !offer.sdp )
            throw new Error( 'no local description' );

        const response = await fetchFunction( url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', ...this.m_options.headers },
            body: JSON.stringify( { sdp: offer.sdp, connectToken: EncodeBase64( connectToken ) } ),
            signal,
        } );
        if ( !response.ok )
        {
            let detail = '';
            try { detail = ( await response.text() ).slice( 0, 200 ); } catch { detail = ''; }
            throw new Error( `signaling failed: HTTP ${response.status}${detail ? ` (${detail})` : ''}` );
        }
        const answer = await response.json() as { sdp?: unknown };
        if ( typeof answer?.sdp !== 'string' )
            throw new Error( 'signaling failed: no sdp in the answer' );

        if ( this.m_peer !== peer )
            throw new Error( 'closed while connecting' );

        await peer.setRemoteDescription( { type: 'answer', sdp: answer.sdp } );
        await opened;

        if ( this.m_peer !== peer )
            throw new Error( 'closed while connecting' );

        this.SetState( 'open' );
    }

    private OnMessage( channel: RTCDataChannel, data: unknown ): void
    {
        if ( channel !== this.m_channel )
            return;
        let packet: Uint8Array;
        if ( data instanceof ArrayBuffer )
            packet = new Uint8Array( data );
        else if ( ArrayBuffer.isView( data ) )
            packet = new Uint8Array( data.buffer, data.byteOffset, data.byteLength );
        else
        {
            this.m_packetsDropped++;          // text messages are not netcode packets
            return;
        }
        if ( packet.length === 0 || packet.length > MaxAdapterPacketBytes || this.m_queue.length - this.m_queueStart >= this.m_maxQueuedPackets )
        {
            this.m_packetsDropped++;
            return;
        }
        this.m_queue.push( packet );
    }

    private OnTransportLost( channel: RTCDataChannel, state: 'closed' | 'failed', error: string ): void
    {
        if ( channel !== this.m_channel )
            return;
        // while connecting, connect() reports the failure (its pending promise rejects)
        if ( this.m_state === 'open' )
        {
            this.Teardown();
            this.m_error = error;
            this.SetState( state );
        }
    }

    private Fail( message: string ): never
    {
        this.Teardown();
        this.m_error = message;
        this.SetState( 'failed' );
        throw new Error( `WebRTCClientAdapter: ${message}` );
    }

    private Teardown(): void
    {
        const channel = this.m_channel;
        const peer = this.m_peer;
        this.m_channel = null;
        this.m_peer = null;
        if ( channel )
        {
            channel.onopen = null;
            channel.onclose = null;
            channel.onerror = null;
            channel.onmessage = null;
            try { channel.close(); } catch { /* already closed */ }
        }
        if ( peer )
        {
            peer.onconnectionstatechange = null;
            try { peer.close(); } catch { /* already closed */ }
        }
    }

    private SetState( state: WebRTCClientState ): void
    {
        if ( this.m_state === state )
            return;
        this.m_state = state;
        try
        {
            this.m_options.onStateChange?.( state, this.m_error );
        }
        catch
        {
            // a throwing listener must not break the transport
        }
    }
}

function WaitForIceGathering( peer: RTCPeerConnection, timeoutMs: number ): Promise<void>
{
    if ( peer.iceGatheringState === 'complete' )
        return Promise.resolve();
    return new Promise<void>( resolve =>
    {
        const done = () =>
        {
            clearTimeout( timer );
            peer.removeEventListener( 'icegatheringstatechange', check );
            resolve();
        };
        const check = () => { if ( peer.iceGatheringState === 'complete' ) done(); };
        const timer = setTimeout( done, timeoutMs );          // send what we have: host candidates come first
        peer.addEventListener( 'icegatheringstatechange', check );
    } );
}

function DescribeError( event: unknown ): string
{
    const error = ( event as { error?: { message?: string } } )?.error;
    return error?.message ?? 'unknown';
}
