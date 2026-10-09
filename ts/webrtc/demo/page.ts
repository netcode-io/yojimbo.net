/*
    yojimbo TypeScript port: WebRTC transport extension.

    This folder is an EXTENSION of the TypeScript port, not a mirror of an upstream file: upstream yojimbo has no
    WebRTC transport. It is distributed under the same BSD 3-Clause license as the rest of this package.

    demo/page.ts: the browser side of the WebRTC demo. `npm run build` compiles it to dist/webrtc/demo/page.js, which
    index.html loads as an ES module; it imports only the built library (dist/), never anything from Node.

    It fetches a connect token from the demo server's /token (DEV ONLY endpoint), opens the WebRTC data channel via
    /signal, connects a yojimbo Client with that token and runs the interop echo protocol (1000 reliable messages,
    every 8th a multi-fragment block, plus unreliable), writing progress and a final PASS / FAIL line into #result.
*/

import {
    InitializeYojimbo, GetDefaultAllocator, yojimbo_time, yojimbo_sleep, yojimbo_log_level, YOJIMBO_LOG_LEVEL_ERROR,
    Address, Client, Allocator, MessageFactory, YOJIMBO_NEW, GetClientDisconnectReasonString,
} from '../../source/yojimbo.ts';
import { TestMessageFactory } from '../../shared.ts';
import { WebRTCClientAdapter } from '../webrtc_client.ts';
import { DecodeBase64 } from '../webrtc_token.ts';
import { CreateEchoConfig, EchoClient, EchoNumMessages } from '../webrtc_echo.ts';

class DemoClientAdapter extends WebRTCClientAdapter
{
    override CreateMessageFactory( allocator: Allocator ): MessageFactory | null
    {
        return YOJIMBO_NEW( allocator, () => new TestMessageFactory( allocator ) );
    }
}

const TimeoutSeconds = 60;

/** ?messages=N runs a shorter (or longer) echo; default EchoNumMessages (1000). */
const NumMessages = Math.max( 1, Number( new URLSearchParams( location.search ).get( 'messages' ) ) || EchoNumMessages );

function Element( id: string ): HTMLElement
{
    const element = document.getElementById( id );
    if ( !element )
        throw new Error( `#${id} missing` );
    return element;
}

function Log( text: string ): void
{
    const line = document.createElement( 'div' );
    line.textContent = `${( performance.now() / 1000 ).toFixed( 2 ).padStart( 7 )}  ${text}`;
    Element( 'log' ).appendChild( line );
}

function SetResult( text: string, status: 'running' | 'pass' | 'fail' ): void
{
    const result = Element( 'result' );
    result.textContent = text;
    result.dataset.status = status;
}

let initialized = false;

async function Run(): Promise<boolean>
{
    const button = Element( 'run' ) as HTMLButtonElement;
    button.disabled = true;
    SetResult( 'running…', 'running' );
    Element( 'log' ).textContent = '';

    if ( !initialized )
    {
        if ( !InitializeYojimbo() )
        {
            SetResult( 'FAIL: could not initialize yojimbo', 'fail' );
            button.disabled = false;
            return false;
        }
        yojimbo_log_level( YOJIMBO_LOG_LEVEL_ERROR );
        initialized = true;
    }

    const adapter = new DemoClientAdapter( { onStateChange: ( state, error ) => Log( `transport ${state}${error ? `: ${error}` : ''}` ) } );
    let client: Client | null = null;
    let ok = false;

    try
    {
        // 1. a connect token. DEV ONLY: the demo server hands them out; a game gets one from its backend
        const tokenResponse = await fetch( '/token', { cache: 'no-store' } );
        if ( !tokenResponse.ok )
            throw new Error( `/token: HTTP ${tokenResponse.status}` );
        const tokenJson = await tokenResponse.json() as { clientId: string, connectToken: string, serverAddress: string };
        const connectToken = DecodeBase64( tokenJson.connectToken );
        if ( !connectToken )
            throw new Error( '/token: bad token' );
        const clientId = BigInt( tokenJson.clientId );
        Log( `got a connect token for client ${clientId.toString( 16 )} → server ${tokenJson.serverAddress}` );

        // 2. the WebRTC data channel (one POST to /signal)
        const start = performance.now();
        await adapter.connect( '/signal', connectToken );
        Log( `data channel open in ${( performance.now() - start ).toFixed( 0 )} ms` );

        // 3. the usual yojimbo secure connect, through the channel
        const config = CreateEchoConfig();
        client = new Client( GetDefaultAllocator(), new Address( '0.0.0.0' ), config, adapter, yojimbo_time() );
        client.Connect( clientId, connectToken );

        const echo = new EchoClient( client, NumMessages );
        const startTime = yojimbo_time();
        let connectedLogged = false;
        let lastProgress = -1;
        while ( true )
        {
            client.SendPackets();
            client.ReceivePackets();
            client.AdvanceTime( yojimbo_time() );

            if ( client.ConnectionFailed() )
                throw new Error( `connection failed (${GetClientDisconnectReasonString( client.GetDisconnectReason() )})` );

            if ( client.IsConnected() && !connectedLogged )
            {
                connectedLogged = true;
                Log( `yojimbo client connected (client index ${client.GetClientIndex()})` );
            }

            const status = echo.Update();
            if ( echo.numReceived !== lastProgress && ( echo.numReceived % 50 === 0 || status !== 'running' ) )
            {
                lastProgress = echo.numReceived;
                SetResult( `running… ${echo.numReceived}/${echo.numMessages} reliable echoes, ${echo.numUnreliableEchoes} unreliable`, 'running' );
            }
            if ( status === 'pass' )
            {
                ok = true;
                Log( echo.detail );
                SetResult( `PASS: ${echo.detail} in ${( yojimbo_time() - startTime ).toFixed( 1 )} s`, 'pass' );
                break;
            }
            if ( status === 'fail' )
                throw new Error( echo.detail );

            if ( yojimbo_time() - startTime > TimeoutSeconds )
                throw new Error( `timed out with ${echo.numReceived}/${echo.numMessages} echoes` );

            await yojimbo_sleep( 0.01 );
        }
    }
    catch ( error )
    {
        const message = error instanceof Error ? error.message : String( error );
        Log( `error: ${message}` );
        SetResult( `FAIL: ${message}`, 'fail' );
    }
    finally
    {
        if ( client )
        {
            client.Disconnect();
            client.Dispose();
        }
        // let the disconnect packets leave before the channel closes
        await yojimbo_sleep( 0.1 );
        adapter.close();
        button.disabled = false;
    }
    return ok;
}

Element( 'run' ).addEventListener( 'click', () => { void Run(); } );
void Run();
