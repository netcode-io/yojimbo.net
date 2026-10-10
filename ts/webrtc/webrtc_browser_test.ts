/*
    yojimbo TypeScript port: WebRTC transport extension.

    This folder is an EXTENSION of the TypeScript port, not a mirror of an upstream file: upstream yojimbo has no
    WebRTC transport. It is distributed under the same BSD 3-Clause license as the rest of this package.

    webrtc_browser_test.ts: a yojimbo server hosted in a browser page, in headless Chromium.

        npx playwright-core install --only-shell chromium      # once
        node webrtc/webrtc_browser_test.ts                     (npm run test:browser)

    esbuild bundles webrtc_browser_page.ts for the browser; a local HTTP server serves it to two pages of one
    origin. The host page runs a yojimbo Server on WebRTCServerAdapter with the browser's own RTCPeerConnection
    (WebRTC only); the client page connects with WebRTCClientAdapter, signaling over a BroadcastChannel straight
    into the host's adapter.accept(), and runs the echo protocol. A client with a bad token must be refused. Node
    only mints the key and the tokens (as a backend would).
*/

import * as esbuild from 'esbuild';
import { chromium } from 'playwright-core';
import { KeyBytes } from '../source/yojimbo.ts';
import { ProtocolId } from '../shared.ts';
import { GenerateConnectToken } from './webrtc_token.ts';

const http = process.getBuiltinModule( 'node:http' );
const path = process.getBuiltinModule( 'node:path' );
const url = process.getBuiltinModule( 'node:url' );

const webrtcDirectory = path.dirname( url.fileURLToPath( import.meta.url ) );

const NumMessages = 200;
const HostAddress = '127.0.0.1:40000';          // only the identity connect tokens name: nothing binds it

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

interface PageApi
{
    startHost( privateKey: number[], address: string ): Promise<{ address: string, udp: boolean }>;
    hostStats(): { peersCreated?: number, signalsAccepted?: number, signalsRejected?: number, openPeers?: number, maxConnected: number };
    runClient( connectToken: number[], clientId: string, numMessages: number ): Promise<{ ok: boolean, state: string, detail: string }>;
}

declare const yojimboTest: PageApi;

async function main(): Promise<number>
{
    const bundle = await esbuild.build( {
        entryPoints: [ path.join( webrtcDirectory, 'webrtc_browser_page.ts' ) ],
        bundle: true,
        platform: 'browser',
        format: 'esm',
        target: 'es2023',
        write: false,
        logLevel: 'warning',
        outfile: 'page.js',
    } );
    await esbuild.stop();
    const pageScript = bundle.outputFiles[0].text;

    const httpServer = http.createServer( ( req, res ) =>
    {
        if ( req.url === '/page.js' )
        {
            res.setHeader( 'Content-Type', 'text/javascript; charset=utf-8' );
            res.end( pageScript );
            return;
        }
        res.setHeader( 'Content-Type', 'text/html; charset=utf-8' );
        res.end( '<!doctype html><meta charset="utf-8"><title>yojimbo</title><script type="module" src="/page.js"></script>' );
    } );
    await new Promise<void>( resolve => httpServer.listen( 0, '127.0.0.1', resolve ) );
    const origin = `http://127.0.0.1:${( httpServer.address() as { port: number } ).port}/`;

    // background pages must keep their timers running: the host pumps its server on setInterval
    const browser = await chromium.launch( { args: [ '--disable-background-timer-throttling', '--disable-renderer-backgrounding', '--disable-backgrounding-occluded-windows' ] } );
    try
    {
        const context = await browser.newContext();
        const hostPage = await context.newPage();
        const clientPage = await context.newPage();
        for ( const page of [ hostPage, clientPage ] )
        {
            page.on( 'pageerror', error => console.log( `  page error: ${error.message}` ) );
            await page.goto( origin );
            await page.waitForFunction( () => typeof ( globalThis as { yojimboTest?: unknown } ).yojimboTest === 'object' );
        }

        const privateKey = new Uint8Array( KeyBytes );
        crypto.getRandomValues( privateKey );
        const serverAddress = HostAddress;

        console.log( 'host page: yojimbo server on the browser\'s RTCPeerConnection' );
        const host = await hostPage.evaluate( ( [ key, address ] ) => yojimboTest.startHost( key, address ), [ Array.from( privateKey ), serverAddress ] as const );
        check( host.address === serverAddress && !host.udp, `server open on ${host.address}, WebRTC only (no UDP in a browser)` );

        console.log( 'client page: BroadcastChannel signaling → adapter.accept(), echo protocol' );
        const mint = ( clientId: bigint, key = privateKey ) => Array.from( GenerateConnectToken( { privateKey: key, protocolId: ProtocolId, clientId, serverAddresses: [ serverAddress ] } )! );

        const badKey = new Uint8Array( KeyBytes );
        crypto.getRandomValues( badKey );
        const refused = await clientPage.evaluate( ( [ token ] ) => yojimboTest.runClient( token, '99', 1 ), [ mint( 99n, badKey ) ] as const );
        check( !refused.ok && refused.state === 'failed' && /signaling failed: 403/.test( refused.detail ), `token from another key refused (${refused.detail})` );

        const start = performance.now();
        const result = await clientPage.evaluate( ( [ token, count ] ) => yojimboTest.runClient( token, '1', count ), [ mint( 1n ), NumMessages ] as const );
        check( result.ok, `echo through the browser-hosted server: ${result.detail} in ${( ( performance.now() - start ) / 1000 ).toFixed( 1 )} s` );

        const stats = await hostPage.evaluate( () => yojimboTest.hostStats() );
        check( stats.peersCreated === 1 && stats.signalsAccepted === 1 && stats.signalsRejected === 1 && stats.maxConnected === 1,
               `host stats: one peer, one signal accepted, one rejected, one client connected (${JSON.stringify( stats )})` );
    }
    finally
    {
        await browser.close();
        httpServer.close();
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
