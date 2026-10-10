// Packs yojimbo2, installs it into a scratch project and type-checks consumer.ts against the declarations with
// skipLibCheck off, on the oldest supported TypeScript and the latest, under nodenext and bundler resolution.
// The declarations must not need a newer TypeScript than the floor (e.g. inferred Uint8Array<ArrayBuffer> needs 5.7).
//
//     node consumer_test/run.mjs            (from ts/; needs network for npx and npm install)

import child_process from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import url from 'node:url';

const MinimumTypeScript = '5.0';
const here = path.dirname( url.fileURLToPath( import.meta.url ) );
const ts = path.resolve( here, '..' );
const scratch = fs.mkdtempSync( path.join( os.tmpdir(), 'yojimbo2-consumer-' ) );
const run = ( command, cwd ) => child_process.execSync( command, { cwd, stdio: [ 'ignore', 'pipe', 'pipe' ], encoding: 'utf8', shell: true } );

run( `npm pack --pack-destination "${scratch}"`, ts );
const tarball = fs.readdirSync( scratch ).find( name => name.endsWith( '.tgz' ) );
fs.writeFileSync( path.join( scratch, 'package.json' ), JSON.stringify( { name: 'consumer', private: true, type: 'module' } ) );
run( `npm install --no-audit --no-fund ./${tarball}`, scratch );
fs.copyFileSync( path.join( here, 'consumer.ts' ), path.join( scratch, 'consumer.ts' ) );

let failed = 0;
for ( const version of [ MinimumTypeScript, 'latest' ] )
{
    for ( const resolution of [ 'nodenext', 'bundler' ] )
    {
        const compilerOptions = {
            target: 'es2022', module: resolution === 'bundler' ? 'esnext' : 'nodenext', moduleResolution: resolution,
            strict: true, noEmit: true, skipLibCheck: false, lib: [ 'es2022', 'dom' ], types: [],
        };
        fs.writeFileSync( path.join( scratch, 'tsconfig.json' ), JSON.stringify( { compilerOptions, files: [ 'consumer.ts' ] } ) );
        try
        {
            run( `npx -y -p typescript@${version} tsc -p .`, scratch );
            console.log( `ok: typescript@${version} (${resolution})` );
        }
        catch ( error )
        {
            failed++;
            console.log( `FAIL: typescript@${version} (${resolution})\n${error.stdout}${error.stderr}` );
        }
    }
}
fs.rmSync( scratch, { recursive: true, force: true } );
console.log( failed ? `FAIL (${failed})` : 'PASS' );
process.exitCode = failed ? 1 : 0;
