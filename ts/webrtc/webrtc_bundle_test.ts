/*
    yojimbo TypeScript port: WebRTC transport extension.

    This folder is an EXTENSION of the TypeScript port, not a mirror of an upstream file: upstream yojimbo has no
    WebRTC transport. It is distributed under the same BSD 3-Clause license as the rest of this package.

    webrtc_bundle_test.ts: the browser bundle check. Needs the built package (npm run build).

        node webrtc/webrtc_bundle_test.ts          (npm run test:bundle)

    Bundles a page that imports yojimbo2, yojimbo2/webrtc/client and yojimbo2/webrtc/server -- through the
    package's exports map, as a consumer would -- with esbuild for platform=browser, and checks that the bundle
    pulls in no node:* module and nothing from node-datachannel, and that yojimbo2/webrtc/server-http, by
    contrast, is the part that needs Node.
*/

import * as esbuild from 'esbuild';

const fs = process.getBuiltinModule( 'node:fs' );
const os = process.getBuiltinModule( 'node:os' );
const path = process.getBuiltinModule( 'node:path' );
const url = process.getBuiltinModule( 'node:url' );

const packageDirectory = path.resolve( path.dirname( url.fileURLToPath( import.meta.url ) ), '..' );

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

async function Bundle( consumer: string, source: string ): Promise<{ ok: boolean, inputs: string[], text: string, errors: string[] }>
{
    try
    {
        const result = await esbuild.build( {
            stdin: { contents: source, resolveDir: consumer, sourcefile: 'page.js', loader: 'js' },
            bundle: true,
            platform: 'browser',
            format: 'esm',
            target: 'es2023',
            write: false,
            metafile: true,
            logLevel: 'silent',
            outfile: path.join( consumer, 'out.js' ),
        } );
        return { ok: true, inputs: Object.keys( result.metafile.inputs ), text: result.outputFiles[0].text, errors: [] };
    }
    catch ( error )
    {
        const errors = ( error as { errors?: { text: string }[] } ).errors?.map( e => e.text ) ?? [ String( error ) ];
        return { ok: false, inputs: [], text: '', errors };
    }
}

async function main(): Promise<number>
{
    for ( const file of [ 'source/yojimbo.js', 'webrtc/webrtc_client.js', 'webrtc/webrtc_server.js', 'webrtc/webrtc_server_http.js' ] )
    {
        if ( !fs.existsSync( path.join( packageDirectory, 'dist', file ) ) )
        {
            console.log( `error: dist/${file} is missing. Run "npm run build" in ts/ first.` );
            return 1;
        }
    }

    // a consumer project with yojimbo2 installed (a link to this package), so imports resolve through "exports"
    const consumer = fs.mkdtempSync( path.join( os.tmpdir(), 'yojimbo2-bundle-' ) );
    try
    {
        fs.mkdirSync( path.join( consumer, 'node_modules' ) );
        fs.symlinkSync( packageDirectory, path.join( consumer, 'node_modules', 'yojimbo2' ), 'junction' );

        console.log( 'browser bundle of yojimbo2 + yojimbo2/webrtc/client + yojimbo2/webrtc/server' );
        const page = await Bundle( consumer, [
            `import { Server, Client, InitializeYojimbo } from 'yojimbo2';`,
            `import { WebRTCClientAdapter, HttpSignal } from 'yojimbo2/webrtc/client';`,
            `import { WebRTCServerAdapter, SignalError, ShutdownWebRTC } from 'yojimbo2/webrtc/server';`,
            `globalThis.used = [ Server, Client, InitializeYojimbo, WebRTCClientAdapter, HttpSignal, WebRTCServerAdapter, SignalError, ShutdownWebRTC ];`,
        ].join( '\n' ) );
        check( page.ok, `esbuild platform=browser succeeded${page.ok ? '' : `: ${page.errors.join( '; ' )}`}` );
        check( page.inputs.some( input => input.includes( 'webrtc_server.js' ) ) && page.inputs.some( input => input.includes( 'webrtc_client.js' ) ), `the bundle holds the client and the server (${page.inputs.length} modules)` );
        const nodeInputs = page.inputs.filter( input => input.startsWith( 'node:' ) || input.includes( 'node-datachannel' ) || input.includes( 'webrtc_server_http' ) );
        check( nodeInputs.length === 0, `no node:*, node-datachannel or HTTP signaling module in the bundle${nodeInputs.length ? `: ${nodeInputs.join( ', ' )}` : ''}` );
        const nodeImports = page.text.match( /(?:from\s*|import\s*\(\s*|require\s*\(\s*)["']node:[^"']*["']/g ) ?? [];
        check( nodeImports.length === 0, `no import of a node:* module in the output${nodeImports.length ? `: ${nodeImports.join( ', ' )}` : ''}` );
        const ndcImports = page.text.match( /(?:from\s*|import\s*\(\s*|require\s*\(\s*)["']node-datachannel[^"']*["']/g ) ?? [];
        check( ndcImports.length === 0, `no static import of node-datachannel in the output${ndcImports.length ? `: ${ndcImports.join( ', ' )}` : ''}` );
        console.log( `  bundle: ${( page.text.length / 1024 ).toFixed( 0 )} KiB unminified` );

        console.log( 'yojimbo2/webrtc/server-http is the Node part' );
        const http = await Bundle( consumer, `import { ListenSignaling } from 'yojimbo2/webrtc/server-http';\nglobalThis.used = ListenSignaling;` );
        check( http.ok && http.inputs.some( input => input.includes( 'webrtc_server_http.js' ) ), 'it bundles (node:http is reached at run time, never imported)' );
    }
    finally
    {
        fs.rmSync( consumer, { recursive: true, force: true } );
        await esbuild.stop();
    }

    console.log( failures === 0 ? 'PASS' : `FAIL (${failures} failures)` );
    return failures === 0 ? 0 : 1;
}

process.exitCode = await main();
