/*
    yojimbo TypeScript port: WebRTC transport extension.

    This folder is an EXTENSION of the TypeScript port, not a mirror of an upstream file: upstream yojimbo has no
    WebRTC transport. It is distributed under the same BSD 3-Clause license as the rest of this package.

    demo/server.ts: WebRTC demo server (Node only, DEV ONLY).

        npm run build                          # the page loads the built ES modules from dist/
        node webrtc/demo/server.ts             # then open http://localhost:8080/

    Options (environment): HTTP_PORT (default 8080), HTTP_HOST (default 127.0.0.1; 0.0.0.0 to reach it from the LAN),
    UDP_ADDRESS (default 127.0.0.1:40000, the yojimbo server address), WEBRTC_LOG (libdatachannel log level, e.g. Info).

    One yojimbo Server (WebRTCServerAdapter) running the interop echo protocol for any number of clients, and one
    HTTP server for:

        GET  /                 the demo page (demo/index.html)
        GET  /dist/...         the built library (ts/dist)
        POST /signal           WebRTC signaling (HandleSignal, webrtc_server_http.ts)
        GET  /token            DEV ONLY: issues a connect token to anyone who asks. A real deployment issues tokens
                               from its backend after authenticating the player.

    The private key is all zeros -- DEV ONLY, the same key interop/ uses -- so native UDP interop clients can join
    the same server at the same time:  node interop/ts/interop.ts client 40000  (or the C++ / C# interop clients).
*/

import type { IncomingMessage, ServerResponse } from 'node:http';
import {
    InitializeYojimbo, ShutdownYojimbo, GetDefaultAllocator, yojimbo_log_level, yojimbo_time, yojimbo_random_bytes,
    YOJIMBO_LOG_LEVEL_ERROR, Server, MaxClients, KeyBytes, Allocator, MessageFactory, YOJIMBO_NEW, AddressFromNetcode,
} from '../../source/yojimbo.ts';
import { TestMessageFactory, ProtocolId } from '../../shared.ts';
import { WebRTCServerAdapter, EncodeBase64, ShutdownWebRTC, HandleSignal } from '../webrtc_server_http.ts';
import { CreateEchoConfig, EchoServerUpdate } from '../webrtc_echo.ts';

const fs = process.getBuiltinModule( 'node:fs' );
const path = process.getBuiltinModule( 'node:path' );
const http = process.getBuiltinModule( 'node:http' );
const url = process.getBuiltinModule( 'node:url' );

const demoDirectory = path.dirname( url.fileURLToPath( import.meta.url ) );
const distDirectory = path.resolve( demoDirectory, '../../dist' );

const httpPort = Number( process.env.HTTP_PORT ?? 8080 );
const httpHost = process.env.HTTP_HOST ?? '127.0.0.1';
const udpAddress = process.env.UDP_ADDRESS ?? '127.0.0.1:40000';

const ContentTypes: Record<string, string> = {
    '.html': 'text/html; charset=utf-8',
    '.js': 'text/javascript; charset=utf-8',
    '.map': 'application/json; charset=utf-8',
    '.css': 'text/css; charset=utf-8',
    '.ts': 'text/plain; charset=utf-8',
};

class DemoServerAdapter extends WebRTCServerAdapter
{
    server: Server | null = null;

    override CreateMessageFactory( allocator: Allocator ): MessageFactory | null
    {
        return YOJIMBO_NEW( allocator, () => new TestMessageFactory( allocator ) );
    }

    override OnServerClientConnected( clientIndex: number ): void
    {
        super.OnServerClientConnected( clientIndex );
        const address = this.server?.GetClientAddress( clientIndex );
        console.log( `client ${clientIndex} connected from ${address ? AddressFromNetcode( address ).ToString() : '?'}${address && this.IsPeerAddress( AddressFromNetcode( address ) ) ? ' (WebRTC)' : ' (UDP)'}` );
    }

    override OnServerClientDisconnected( clientIndex: number ): void
    {
        super.OnServerClientDisconnected( clientIndex );
        console.log( `client ${clientIndex} disconnected` );
    }
}

function SendFile( res: ServerResponse, file: string ): void
{
    fs.readFile( file, ( error, data ) =>
    {
        if ( error )
        {
            res.statusCode = 404;
            res.end( 'not found' );
            return;
        }
        res.statusCode = 200;
        res.setHeader( 'Content-Type', ContentTypes[path.extname( file )] ?? 'application/octet-stream' );
        res.setHeader( 'Cache-Control', 'no-cache' );
        res.end( data );
    } );
}

async function main(): Promise<number>
{
    if ( !fs.existsSync( path.join( distDirectory, 'webrtc/demo/page.js' ) ) )
    {
        console.log( `error: ${distDirectory}/webrtc/demo/page.js is missing. Run "npm run build" in ts/ first.` );
        return 1;
    }

    if ( !InitializeYojimbo() )
    {
        console.log( 'error: failed to initialize yojimbo' );
        return 1;
    }
    yojimbo_log_level( YOJIMBO_LOG_LEVEL_ERROR );

    const privateKey = new Uint8Array( KeyBytes );         // DEV ONLY: all zeros, as interop/
    const config = CreateEchoConfig();

    const adapter = new DemoServerAdapter( {
        address: udpAddress,
        privateKey,
        protocolId: ProtocolId,
        onSignal: ( { ip, status, reason } ) => console.log( `signal from ${ip}: ${status} ${reason}` ),
        onPeerEvent: ( { address, ip, event, reason } ) => console.log( `peer ${address} (${ip}) ${event}: ${reason}` ),
    } );

    if ( process.env.WEBRTC_LOG )
    {
        // libdatachannel's own log (Verbose, Debug, Info, Warning, Error, Fatal)
        const specifier = 'node-datachannel';
        const ndc = await import( specifier ) as { initLogger( level: string, cb: ( level: string, message: string ) => void ): void };
        ndc.initLogger( process.env.WEBRTC_LOG, ( level, message ) => console.log( `[libdatachannel] ${level} ${message}` ) );
    }
    await adapter.open();
    const server = new Server( GetDefaultAllocator(), privateKey, adapter.address, config, adapter, yojimbo_time() );
    if ( !server.Start( MaxClients ) )
    {
        console.log( 'error: server failed to start' );
        adapter.close();
        return 1;
    }
    adapter.server = server;
    adapter.attachServer( server );

    const httpServer = http.createServer( ( req: IncomingMessage, res: ServerResponse ) =>
    {
        const pathname = decodeURIComponent( new URL( req.url ?? '/', 'http://localhost' ).pathname );

        if ( pathname === '/signal' )
        {
            void HandleSignal( adapter, req, res );
            return;
        }

        if ( req.method !== 'GET' && req.method !== 'HEAD' )
        {
            res.statusCode = 405;
            res.end( 'method not allowed' );
            return;
        }

        if ( pathname === '/token' )
        {
            // DEV ONLY: hands a connect token to anyone. Issue tokens from your authenticated backend instead.
            const clientIdBytes = new Uint8Array( 8 );
            yojimbo_random_bytes( clientIdBytes, 8 );
            const clientId = new DataView( clientIdBytes.buffer ).getBigUint64( 0, true );
            const token = adapter.generateConnectToken( clientId );
            res.setHeader( 'Content-Type', 'application/json' );
            res.setHeader( 'Cache-Control', 'no-store' );
            res.end( JSON.stringify( { clientId: clientId.toString(), connectToken: token ? EncodeBase64( token ) : null, serverAddress: adapter.address.ToString() } ) );
            return;
        }

        if ( pathname === '/' || pathname === '/index.html' )
        {
            SendFile( res, path.join( demoDirectory, 'index.html' ) );
            return;
        }

        if ( pathname.startsWith( '/dist/' ) )
        {
            const file = path.resolve( distDirectory, '.' + pathname.slice( '/dist'.length ) );
            if ( !file.startsWith( distDirectory + path.sep ) )
            {
                res.statusCode = 403;
                res.end( 'forbidden' );
                return;
            }
            SendFile( res, file );
            return;
        }

        res.statusCode = 404;
        res.end( 'not found' );
    } );

    await new Promise<void>( ( resolve, reject ) =>
    {
        httpServer.once( 'error', reject );
        httpServer.listen( httpPort, httpHost, () => resolve() );
    } );

    const shownHost = httpHost === '0.0.0.0' || httpHost === '127.0.0.1' ? 'localhost' : httpHost;
    console.log( `yojimbo WebRTC demo (DEV ONLY: zero private key, open /token endpoint)` );
    console.log( `  page:       http://${shownHost}:${httpPort}/` );
    console.log( `  signaling:  POST http://${shownHost}:${httpPort}/signal` );
    console.log( `  UDP:        ${adapter.address.ToString()}  (node interop/ts/interop.ts client ${adapter.address.GetPort()})` );

    const timer = setInterval( () =>
    {
        server.SendPackets();
        server.ReceivePackets();
        server.AdvanceTime( yojimbo_time() );
        EchoServerUpdate( server, config );
    }, 10 );

    await new Promise<void>( resolve =>
    {
        process.once( 'SIGINT', resolve );
        process.once( 'SIGTERM', resolve );
    } );

    console.log( 'shutting down' );
    clearInterval( timer );
    server.Stop();
    server.Dispose();
    adapter.close();
    httpServer.close();
    httpServer.closeAllConnections();
    ShutdownYojimbo();
    await ShutdownWebRTC();
    return 0;
}

process.exitCode = await main();
