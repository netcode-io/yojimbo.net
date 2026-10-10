/*
    yojimbo TypeScript port: WebRTC transport extension.

    This folder is an EXTENSION of the TypeScript port, not a mirror of an upstream file: upstream yojimbo has no
    WebRTC transport. It is distributed under the same BSD 3-Clause license as the rest of this package.

    webrtc_browser_page.ts: the page script of webrtc_browser_test.ts, bundled for the browser by esbuild. One page
    hosts a yojimbo Server on WebRTCServerAdapter (the browser's own RTCPeerConnection, WebRTC only); other pages of
    the same origin connect to it, signaling in-page over a BroadcastChannel into adapter.accept() -- no HTTP and no
    Node anywhere. The test drives it through globalThis.yojimboTest.
*/

import {
    InitializeYojimbo, yojimbo_log_level, YOJIMBO_LOG_LEVEL_ERROR, GetDefaultAllocator, yojimbo_time, yojimbo_sleep,
    Address, Client, Server, MaxClients, Allocator, MessageFactory, YOJIMBO_NEW, GetClientDisconnectReasonString,
} from '../source/yojimbo.ts';
import { TestMessageFactory, ProtocolId } from '../shared.ts';
import { WebRTCClientAdapter, type WebRTCSignal } from './webrtc_client.ts';
import { WebRTCServerAdapter, SignalError } from './webrtc_server.ts';
import { CreateEchoConfig, EchoServerUpdate, EchoClient } from './webrtc_echo.ts';

class PageServerAdapter extends WebRTCServerAdapter
{
    override CreateMessageFactory( allocator: Allocator ): MessageFactory | null
    {
        return YOJIMBO_NEW( allocator, () => new TestMessageFactory( allocator ) );
    }
}

class PageClientAdapter extends WebRTCClientAdapter
{
    override CreateMessageFactory( allocator: Allocator ): MessageFactory | null
    {
        return YOJIMBO_NEW( allocator, () => new TestMessageFactory( allocator ) );
    }
}

const SignalChannelName = 'yojimbo-signal';

interface SignalMessage { kind: 'offer', id: string, from: string, sdp: string, connectToken: Uint8Array }
interface ReplyMessage { kind: 'answer', id: string, sdp?: string, status?: number, error?: string }

let initialized = false;

function Initialize(): void
{
    if ( initialized )
        return;
    if ( !InitializeYojimbo() )
        throw new Error( 'InitializeYojimbo failed' );
    yojimbo_log_level( YOJIMBO_LOG_LEVEL_ERROR );
    initialized = true;
}

let hostAdapter: PageServerAdapter | null = null;
let hostServer: Server | null = null;
let hostMaxConnected = 0;

/** Host a server in this page: WebRTC only, signaling answered on the BroadcastChannel. */

async function startHost( privateKey: number[], address: string ): Promise<{ address: string, udp: boolean }>
{
    Initialize();
    const key = new Uint8Array( privateKey );
    const config = CreateEchoConfig();
    const adapter = new PageServerAdapter( { address, privateKey: key, protocolId: ProtocolId } );
    await adapter.open();
    const server = new Server( GetDefaultAllocator(), key, adapter.address, config, adapter, yojimbo_time() );
    if ( !server.Start( MaxClients ) )
        throw new Error( 'server failed to start' );
    adapter.attachServer( server );

    setInterval( () =>
    {
        server.SendPackets();
        server.ReceivePackets();
        server.AdvanceTime( yojimbo_time() );
        EchoServerUpdate( server, config );
        hostMaxConnected = Math.max( hostMaxConnected, server.GetNumConnectedClients() );
    }, 10 );

    const channel = new BroadcastChannel( SignalChannelName );
    channel.onmessage = async ( event: MessageEvent<SignalMessage> ) =>
    {
        const message = event.data;
        if ( message?.kind !== 'offer' )
            return;
        let reply: ReplyMessage;
        try
        {
            // the sending tab's id stands in for a client IP in the per-IP caps
            const answer = await adapter.accept( { sdp: message.sdp, connectToken: message.connectToken, ip: message.from } );
            reply = { kind: 'answer', id: message.id, sdp: answer.sdp };
        }
        catch ( error )
        {
            reply = { kind: 'answer', id: message.id, status: error instanceof SignalError ? error.status : 500, error: error instanceof Error ? error.message : String( error ) };
        }
        channel.postMessage( reply );
    };

    hostAdapter = adapter;
    hostServer = server;
    return { address: adapter.address.ToString(), udp: adapter.servesUdp };
}

function hostStats(): object
{
    return { ...hostAdapter?.stats, connectedClients: hostServer?.GetNumConnectedClients() ?? -1, maxConnected: hostMaxConnected };
}

/** The client side of the in-page signaling: post the offer on the BroadcastChannel, wait for the host's reply. */

function BroadcastSignal(): WebRTCSignal
{
    const from = crypto.randomUUID();
    return ( offer, abort ) => new Promise( ( resolve, reject ) =>
    {
        const channel = new BroadcastChannel( SignalChannelName );
        const id = crypto.randomUUID();
        const done = () => { channel.close(); abort.removeEventListener( 'abort', onAbort ); };
        const onAbort = () => { done(); reject( new Error( 'aborted' ) ); };
        abort.addEventListener( 'abort', onAbort );
        channel.onmessage = ( event: MessageEvent<ReplyMessage> ) =>
        {
            const reply = event.data;
            if ( reply?.kind !== 'answer' || reply.id !== id )
                return;
            done();
            if ( typeof reply.sdp === 'string' )
                resolve( { sdp: reply.sdp } );
            else
                reject( Object.assign( new Error( reply.error ?? 'refused' ), { status: reply.status } ) );
        };
        channel.postMessage( { kind: 'offer', id, from, sdp: offer.sdp, connectToken: offer.connectToken } satisfies SignalMessage );
    } );
}

/** Connect a yojimbo client through the host page and run the echo protocol. */

async function runClient( connectToken: number[], clientId: string, numMessages: number ): Promise<{ ok: boolean, state: string, detail: string }>
{
    Initialize();
    const adapter = new PageClientAdapter();
    const token = new Uint8Array( connectToken );
    try
    {
        await adapter.connect( token, BroadcastSignal() );
    }
    catch ( error )
    {
        return { ok: false, state: adapter.state, detail: error instanceof Error ? error.message : String( error ) };
    }

    const config = CreateEchoConfig();
    const client = new Client( GetDefaultAllocator(), new Address( '0.0.0.0' ), config, adapter, yojimbo_time() );
    client.Connect( BigInt( clientId ), token );
    const echo = new EchoClient( client, numMessages );
    const start = yojimbo_time();
    let ok = false;
    let detail = '';
    while ( true )
    {
        client.SendPackets();
        client.ReceivePackets();
        client.AdvanceTime( yojimbo_time() );
        if ( client.ConnectionFailed() )
        {
            detail = `connection failed (${GetClientDisconnectReasonString( client.GetDisconnectReason() )})`;
            break;
        }
        const status = echo.Update();
        if ( status !== 'running' )
        {
            ok = status === 'pass';
            detail = echo.detail;
            break;
        }
        if ( yojimbo_time() - start > 60 )
        {
            detail = `timed out with ${echo.numReceived}/${echo.numMessages} echoes`;
            break;
        }
        await yojimbo_sleep( 0.01 );
    }
    client.Disconnect();
    client.Dispose();
    adapter.close();
    return { ok, state: adapter.state, detail };
}

( globalThis as { yojimboTest?: object } ).yojimboTest = { startHost, hostStats, runClient };
