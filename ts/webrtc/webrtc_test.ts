/*
    yojimbo TypeScript port: WebRTC transport extension.

    This folder is an EXTENSION of the TypeScript port, not a mirror of an upstream file: upstream yojimbo has no
    WebRTC transport. It is distributed under the same BSD 3-Clause license as the rest of this package.

    webrtc_test.ts: end to end test of the WebRTC transport, in Node.

        node webrtc/webrtc_test.ts          (npm run test:webrtc)

    One yojimbo Server on 127.0.0.1:<free port> with WebRTCServerAdapter, signaling on another free port. Then:

      1. signaling refusals: bad / foreign / wrong protocol / expired tokens → 403 with no peer created, oversized
         bodies → 413, wrong content type → 415, wrong method → 405, malformed JSON → 400;
      2. at the same time, a "browser" yojimbo Client (WebRTCClientAdapter on node-datachannel's polyfill
         RTCPeerConnection, secure connect token) and a plain UDP yojimbo Client run the interop echo protocol
         (1000 reliable messages, every 8th a block of up to 5000 bytes, plus unreliable) against the server;
      3. the WebRTC peer is released once its client disconnects;
      4. a peer that signals but never opens its channel is reaped, and a token cannot signal more than
         maxSignalsPerToken times;
      5. dev path: a client mints its own token for signaling and connects with InsecureConnect.
*/

import { RTCPeerConnection as PolyfillRTCPeerConnection } from 'node-datachannel/polyfill';
import {
    InitializeYojimbo, ShutdownYojimbo, GetDefaultAllocator, yojimbo_log_level, yojimbo_time, yojimbo_sleep,
    YOJIMBO_LOG_LEVEL_ERROR, Address, Client, Server, MaxClients, KeyBytes, Allocator, MessageFactory, YOJIMBO_NEW,
    GetClientDisconnectReasonString,
} from '../source/yojimbo.ts';
import { TestAdapter, TestMessageFactory, ProtocolId } from '../shared.ts';
import { WebRTCClientAdapter, type RTCPeerConnectionConstructor } from './webrtc_client.ts';
import { WebRTCServerAdapter, GenerateConnectToken, EncodeBase64, ShutdownWebRTC } from './webrtc_server.ts';
import { CreateEchoConfig, EchoServerUpdate, EchoClient } from './webrtc_echo.ts';

const RTCPeerConnection = PolyfillRTCPeerConnection as unknown as RTCPeerConnectionConstructor;

class EchoServerAdapter extends WebRTCServerAdapter
{
    override CreateMessageFactory( allocator: Allocator ): MessageFactory | null
    {
        return YOJIMBO_NEW( allocator, () => new TestMessageFactory( allocator ) );
    }
}

class EchoClientAdapter extends WebRTCClientAdapter
{
    override CreateMessageFactory( allocator: Allocator ): MessageFactory | null
    {
        return YOJIMBO_NEW( allocator, () => new TestMessageFactory( allocator ) );
    }
}

let failures = 0;

function check( condition: unknown, message: string ): void
{
    if ( condition )
        console.log( `  ok: ${message}` );
    else
    {
        console.log( `FAIL: ${message}` );
        failures++;
    }
}

function RandomKey(): Uint8Array
{
    const key = new Uint8Array( KeyBytes );
    crypto.getRandomValues( key );
    return key;
}

async function WaitFor( condition: () => boolean, timeoutSeconds: number ): Promise<boolean>
{
    const start = yojimbo_time();
    while ( !condition() )
    {
        if ( yojimbo_time() - start > timeoutSeconds )
            return false;
        await yojimbo_sleep( 0.02 );
    }
    return true;
}

/** Raw POST with node:http (fetch cannot send a lying Content-Length or survive an early 413 reliably). */

function RawPost( url: string, body: Uint8Array, headers: Record<string, string>, chunked = false ): Promise<number>
{
    const http = process.getBuiltinModule( 'node:http' );
    return new Promise<number>( ( resolve ) =>
    {
        let settled = false;
        const settle = ( status: number ) => { if ( !settled ) { settled = true; resolve( status ); } };
        const req = http.request( url, { method: 'POST', headers: chunked ? headers : { ...headers, 'Content-Length': String( body.length ) } }, res =>
        {
            settle( res.statusCode ?? 0 );
            res.resume();
        } );
        req.on( 'error', () => settle( -1 ) );
        if ( chunked )
        {
            // stream it in pieces so the server must count while reading
            let offset = 0;
            const pump = () =>
            {
                while ( offset < body.length )
                {
                    const piece = body.subarray( offset, offset + 4096 );
                    offset += piece.length;
                    if ( !req.write( piece ) )
                    {
                        req.once( 'drain', pump );
                        return;
                    }
                }
                req.end();
            };
            pump();
        }
        else
        {
            req.end( body );
        }
    } );
}

async function PostJson( url: string, value: unknown, contentType = 'application/json', method = 'POST' ): Promise<{ status: number, body: string }>
{
    const response = await fetch( url, { method, headers: { 'Content-Type': contentType }, body: method === 'GET' ? undefined : JSON.stringify( value ) } );
    return { status: response.status, body: await response.text() };
}

/** A real offer from a polyfill peer connection (non-trickle), plus the peer so the caller can close it. */

async function MakeOffer(): Promise<{ peer: RTCPeerConnection, sdp: string }>
{
    const peer = new RTCPeerConnection( { iceServers: [] } );
    peer.createDataChannel( 'netcode', { negotiated: true, id: 0, ordered: false, maxRetransmits: 0 } );
    await peer.setLocalDescription( await peer.createOffer() );
    await WaitFor( () => peer.iceGatheringState === 'complete', 5 );
    return { peer, sdp: peer.localDescription!.sdp };
}

async function RunClient( name: string, client: Client, echo: EchoClient | null, timeoutSeconds: number ): Promise<boolean>
{
    const start = yojimbo_time();
    let ok = false;
    while ( true )
    {
        client.SendPackets();
        client.ReceivePackets();
        client.AdvanceTime( yojimbo_time() );

        if ( client.ConnectionFailed() )
        {
            console.log( `  ${name}: connection failed (${GetClientDisconnectReasonString( client.GetDisconnectReason() )})` );
            break;
        }

        if ( echo )
        {
            const status = echo.Update();
            if ( status !== 'running' )
            {
                console.log( `  ${name}: ${echo.detail}` );
                ok = status === 'pass';
                break;
            }
        }
        else if ( client.IsConnected() )
        {
            ok = true;
            break;
        }

        if ( yojimbo_time() - start > timeoutSeconds )
        {
            console.log( `  ${name}: timed out${echo ? ` with ${echo.numReceived}/${echo.numMessages} echoes` : ''}` );
            break;
        }

        await yojimbo_sleep( 0.01 );
    }
    client.Disconnect();
    return ok;
}

async function main(): Promise<number>
{
    if ( !InitializeYojimbo() )
    {
        console.log( 'error: failed to initialize yojimbo' );
        return 1;
    }
    yojimbo_log_level( YOJIMBO_LOG_LEVEL_ERROR );

    const privateKey = RandomKey();
    const config = CreateEchoConfig();

    const adapter = new EchoServerAdapter( {
        address: '127.0.0.1:0',
        privateKey,
        protocolId: ProtocolId,
        pendingTimeoutMs: 1500,
        maxSignalsPerToken: 2,
        maxBodyBytes: 16384,
    } );
    await adapter.open();
    const serverAddress = adapter.address;
    check( serverAddress.GetPort() > 0, `server bound UDP on ${serverAddress.ToString()}` );

    const server = new Server( GetDefaultAllocator(), privateKey, serverAddress, config, adapter, yojimbo_time() );
    server.Start( MaxClients );
    adapter.attachServer( server );

    const httpServer = await adapter.listenSignaling( 0, { host: '127.0.0.1', path: '/signal' } );
    const signalPort = ( httpServer.address() as { port: number } ).port;
    const signalUrl = `http://127.0.0.1:${signalPort}/signal`;
    console.log( `server: ${serverAddress.ToString()}, signaling ${signalUrl}` );

    let maxConnected = 0;
    const serverPump = setInterval( () =>
    {
        server.SendPackets();
        server.ReceivePackets();
        server.AdvanceTime( yojimbo_time() );
        EchoServerUpdate( server, config );
        maxConnected = Math.max( maxConnected, server.GetNumConnectedClients() );
    }, 10 );

    try
    {
        // ------------------------------------------------------------------------------------------------
        console.log( '1. signaling refusals' );
        {
            const { peer, sdp } = await MakeOffer();

            const garbage = new Uint8Array( 2048 );
            crypto.getRandomValues( garbage );
            const badToken = await PostJson( signalUrl, { sdp, connectToken: EncodeBase64( garbage ) } );
            check( badToken.status === 403, `random token → ${badToken.status} (${badToken.body})` );

            const foreign = GenerateConnectToken( { privateKey, protocolId: ProtocolId, clientId: 9n, serverAddresses: [ new Address( '127.0.0.1', serverAddress.GetPort() === 1 ? 2 : 1 ) ] } )!;
            const foreignToken = await PostJson( signalUrl, { sdp, connectToken: EncodeBase64( foreign ) } );
            check( foreignToken.status === 403, `token for another server → ${foreignToken.status} (${foreignToken.body})` );

            const otherKey = GenerateConnectToken( { privateKey: RandomKey(), protocolId: ProtocolId, clientId: 9n, serverAddresses: [ serverAddress ] } )!;
            const otherKeyToken = await PostJson( signalUrl, { sdp, connectToken: EncodeBase64( otherKey ) } );
            check( otherKeyToken.status === 403, `token signed with another key → ${otherKeyToken.status} (${otherKeyToken.body})` );

            const otherProtocol = GenerateConnectToken( { privateKey, protocolId: ProtocolId + 1n, clientId: 9n, serverAddresses: [ serverAddress ] } )!;
            const otherProtocolToken = await PostJson( signalUrl, { sdp, connectToken: EncodeBase64( otherProtocol ) } );
            check( otherProtocolToken.status === 403, `token for another protocol → ${otherProtocolToken.status} (${otherProtocolToken.body})` );

            const expired = GenerateConnectToken( { privateKey, protocolId: ProtocolId, clientId: 9n, serverAddresses: [ serverAddress ], expireSeconds: 0 } )!;
            const expiredToken = await PostJson( signalUrl, { sdp, connectToken: EncodeBase64( expired ) } );
            check( expiredToken.status === 403, `expired token → ${expiredToken.status} (${expiredToken.body})` );

            const notBase64 = await PostJson( signalUrl, { sdp, connectToken: '!!!!' } );
            check( notBase64.status === 403, `non-base64 token → ${notBase64.status}` );

            const malformed = await RawPost( signalUrl, new TextEncoder().encode( '{ not json' ), { 'Content-Type': 'application/json' } );
            check( malformed === 400, `malformed JSON → ${malformed}` );

            const missing = await PostJson( signalUrl, { sdp } );
            check( missing.status === 400, `missing token → ${missing.status}` );

            const wrongType = await PostJson( signalUrl, { sdp, connectToken: '' }, 'text/plain' );
            check( wrongType.status === 415, `text/plain → ${wrongType.status}` );

            const wrongMethod = await fetch( signalUrl );
            check( wrongMethod.status === 405, `GET → ${wrongMethod.status}` );

            const notFound = await fetch( `http://127.0.0.1:${signalPort}/elsewhere`, { method: 'POST' } );
            check( notFound.status === 404, `other path → ${notFound.status}` );

            const big = new Uint8Array( 100000 ).fill( 0x20 );
            const declaredTooLarge = await RawPost( signalUrl, big, { 'Content-Type': 'application/json' } );
            check( declaredTooLarge === 413, `oversized body (Content-Length) → ${declaredTooLarge}` );

            const streamedTooLarge = await RawPost( signalUrl, big, { 'Content-Type': 'application/json' }, true );
            check( streamedTooLarge === 413, `oversized body (chunked) → ${streamedTooLarge}` );

            check( adapter.stats.peersCreated === 0, `no peer created by refused signals (created ${adapter.stats.peersCreated})` );
            peer.close();
        }

        // ------------------------------------------------------------------------------------------------
        console.log( '2. WebRTC client and UDP client echo at the same time' );
        let webrtcClientAdapter: EchoClientAdapter;
        {
            webrtcClientAdapter = new EchoClientAdapter( { RTCPeerConnection } );
            const webrtcToken = adapter.generateConnectToken( 1n )!;
            const connectStart = yojimbo_time();
            await webrtcClientAdapter.connect( signalUrl, webrtcToken );
            check( webrtcClientAdapter.state === 'open', `data channel open in ${( ( yojimbo_time() - connectStart ) * 1000 ).toFixed( 0 )} ms` );
            // the server side sees the channel open independently (and possibly a little later) than the client
            const serverOpen = await WaitFor( () => adapter.stats.openPeers === 1 && adapter.stats.pendingPeers === 0, 3 );
            check( serverOpen, `server has one open peer (${JSON.stringify( adapter.stats )})` );

            const webrtcClient = new Client( GetDefaultAllocator(), new Address( '0.0.0.0' ), config, webrtcClientAdapter, yojimbo_time() );
            webrtcClient.Connect( 1n, webrtcToken );

            const udpAdapter = new TestAdapter();
            const udpClient = new Client( GetDefaultAllocator(), new Address( '0.0.0.0' ), config, udpAdapter, yojimbo_time() );
            udpClient.Connect( 2n, adapter.generateConnectToken( 2n )! );

            const start = yojimbo_time();
            const [ webrtcOk, udpOk ] = await Promise.all( [
                RunClient( 'webrtc client', webrtcClient, new EchoClient( webrtcClient ), 60 ),
                RunClient( 'udp client', udpClient, new EchoClient( udpClient ), 60 ),
            ] );
            console.log( `  echo took ${( yojimbo_time() - start ).toFixed( 2 )} s` );
            check( webrtcOk, 'WebRTC client echo protocol passed' );
            check( udpOk, 'UDP client echo protocol passed' );
            check( maxConnected === 2, `both clients were connected at once (max ${maxConnected})` );
            check( webrtcClientAdapter.stats.sent > 0 && webrtcClientAdapter.stats.received > 0, `WebRTC client adapter moved packets (${JSON.stringify( webrtcClientAdapter.stats )})` );

            webrtcClient.Dispose();
            udpClient.Dispose();

            // ----------------------------------------------------------------------------------------------
            console.log( '3. peer released after its client disconnects' );
            const released = await WaitFor( () => adapter.stats.openPeers === 0 && adapter.stats.closingPeers === 0, 3 );
            check( released, `WebRTC peer released (${JSON.stringify( adapter.stats )})` );
            check( await WaitFor( () => server.GetNumConnectedClients() === 0, 3 ), 'server has no clients left' );
            webrtcClientAdapter.close();
        }

        // ------------------------------------------------------------------------------------------------
        console.log( '4. never-opened peers are reaped; token signal limit' );
        {
            const token = adapter.generateConnectToken( 7n )!;
            const reapedBefore = adapter.stats.peersReaped;
            const first = await MakeOffer();
            const second = await MakeOffer();
            const third = await MakeOffer();
            const r1 = await PostJson( signalUrl, { sdp: first.sdp, connectToken: EncodeBase64( token ) } );
            const r2 = await PostJson( signalUrl, { sdp: second.sdp, connectToken: EncodeBase64( token ) } );
            const r3 = await PostJson( signalUrl, { sdp: third.sdp, connectToken: EncodeBase64( token ) } );
            check( r1.status === 200 && JSON.parse( r1.body ).sdp?.startsWith( 'v=0' ), `valid token, answer never applied → ${r1.status} with an SDP answer` );
            check( r2.status === 200, `same token again (maxSignalsPerToken 2) → ${r2.status}` );
            check( r3.status === 403, `same token a third time → ${r3.status} (${r3.body})` );
            check( adapter.stats.pendingPeers === 2, `two pending peers (${adapter.stats.pendingPeers})` );
            const reaped = await WaitFor( () => adapter.stats.pendingPeers === 0, 4 );
            check( reaped && adapter.stats.peersReaped - reapedBefore === 2, `pending peers reaped after pendingTimeoutMs (${JSON.stringify( adapter.stats )})` );
            first.peer.close();
            second.peer.close();
            third.peer.close();
        }

        // ------------------------------------------------------------------------------------------------
        console.log( '5. dev path: self-minted token for signaling + InsecureConnect' );
        {
            const clientAdapter = new EchoClientAdapter( { RTCPeerConnection } );
            const token = GenerateConnectToken( { privateKey, protocolId: ProtocolId, clientId: 3n, serverAddresses: [ serverAddress ] } )!;
            await clientAdapter.connect( signalUrl, token );
            const client = new Client( GetDefaultAllocator(), new Address( '0.0.0.0' ), config, clientAdapter, yojimbo_time() );
            client.InsecureConnect( privateKey, 3n, serverAddress );
            const connected = await RunClient( 'insecure webrtc client', client, null, 10 );
            check( connected, 'InsecureConnect over WebRTC connected' );
            client.Dispose();
            clientAdapter.close();
            check( await WaitFor( () => adapter.stats.openPeers === 0 && adapter.stats.closingPeers === 0, 3 ), 'its peer was released' );
        }

        // ------------------------------------------------------------------------------------------------
        console.log( '6. client adapter surfaces signaling failure' );
        {
            const clientAdapter = new EchoClientAdapter( { RTCPeerConnection } );
            const bad = new Uint8Array( 2048 );
            let error = '';
            try
            {
                await clientAdapter.connect( signalUrl, bad );
            }
            catch ( e )
            {
                error = e instanceof Error ? e.message : String( e );
            }
            check( clientAdapter.state === 'failed' && /403/.test( error ), `connect() with a bad token rejects with 403, state failed (${error})` );
        }
    }
    finally
    {
        clearInterval( serverPump );
        server.Stop();
        server.Dispose();
        adapter.close();
        await yojimbo_sleep( 0.1 );
        await ShutdownWebRTC();
        ShutdownYojimbo();
    }

    console.log( failures === 0 ? 'PASS' : `FAIL (${failures} failures)` );
    return failures === 0 ? 0 : 1;
}

try
{
    process.exitCode = await main();
}
catch ( error )
{
    console.log( error instanceof Error ? ( error.stack ?? error.message ) : String( error ) );
    process.exitCode = 1;
}
