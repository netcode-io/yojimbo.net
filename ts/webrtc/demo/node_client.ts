/*
    yojimbo TypeScript port: WebRTC transport extension.

    This folder is an EXTENSION of the TypeScript port, not a mirror of an upstream file: upstream yojimbo has no
    WebRTC transport. It is distributed under the same BSD 3-Clause license as the rest of this package.

    demo/node_client.ts: the demo page's client, headless, in Node (node-datachannel's polyfill RTCPeerConnection).
    Runs the same flow against a running demo server: GET /token, POST /signal, yojimbo Connect, echo protocol.

        node webrtc/demo/node_client.ts [http://localhost:8080]
*/

import { RTCPeerConnection } from 'node-datachannel/polyfill';
import {
    InitializeYojimbo, ShutdownYojimbo, GetDefaultAllocator, yojimbo_time, yojimbo_sleep, yojimbo_log_level, YOJIMBO_LOG_LEVEL_ERROR,
    Address, Client, Allocator, MessageFactory, YOJIMBO_NEW, GetClientDisconnectReasonString,
} from '../../source/yojimbo.ts';
import { TestMessageFactory } from '../../shared.ts';
import { WebRTCClientAdapter, type RTCPeerConnectionConstructor } from '../webrtc_client.ts';
import { DecodeBase64 } from '../webrtc_token.ts';
import { ShutdownWebRTC } from '../webrtc_server.ts';
import { CreateEchoConfig, EchoClient } from '../webrtc_echo.ts';

class DemoClientAdapter extends WebRTCClientAdapter
{
    override CreateMessageFactory( allocator: Allocator ): MessageFactory | null
    {
        return YOJIMBO_NEW( allocator, () => new TestMessageFactory( allocator ) );
    }
}

async function main( base: string ): Promise<number>
{
    if ( !InitializeYojimbo() )
        return 1;
    yojimbo_log_level( YOJIMBO_LOG_LEVEL_ERROR );

    const adapter = new DemoClientAdapter( { RTCPeerConnection: RTCPeerConnection as unknown as RTCPeerConnectionConstructor } );
    let client: Client | null = null;
    let result = 1;
    try
    {
        const tokenJson = await ( await fetch( new URL( '/token', base ) ) ).json() as { clientId: string, connectToken: string };
        const connectToken = DecodeBase64( tokenJson.connectToken )!;
        const clientId = BigInt( tokenJson.clientId );

        await adapter.connect( new URL( '/signal', base ).toString(), connectToken );
        console.log( 'client: data channel open' );

        client = new Client( GetDefaultAllocator(), new Address( '0.0.0.0' ), CreateEchoConfig(), adapter, yojimbo_time() );
        client.Connect( clientId, connectToken );

        const echo = new EchoClient( client );
        const start = yojimbo_time();
        while ( true )
        {
            client.SendPackets();
            client.ReceivePackets();
            client.AdvanceTime( yojimbo_time() );
            if ( client.ConnectionFailed() )
            {
                console.log( `client: connection failed (${GetClientDisconnectReasonString( client.GetDisconnectReason() )})` );
                break;
            }
            const status = echo.Update();
            if ( status !== 'running' )
            {
                console.log( `client: ${echo.detail}` );
                result = status === 'pass' ? 0 : 1;
                break;
            }
            if ( yojimbo_time() - start > 60 )
            {
                console.log( `client: timed out with ${echo.numReceived}/${echo.numMessages} echoes` );
                break;
            }
            await yojimbo_sleep( 0.01 );
        }
    }
    catch ( error )
    {
        console.log( `client: ${error instanceof Error ? error.message : String( error )}` );
    }
    finally
    {
        if ( client )
        {
            client.Disconnect();
            client.Dispose();
        }
        await yojimbo_sleep( 0.1 );
        adapter.close();
        await yojimbo_sleep( 0.1 );
        await ShutdownWebRTC();
        ShutdownYojimbo();
    }
    console.log( result === 0 ? 'PASS' : 'FAIL' );
    return result;
}

process.exitCode = await main( process.argv[2] ?? 'http://localhost:8080' );
