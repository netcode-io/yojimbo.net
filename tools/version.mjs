#!/usr/bin/env node
/*
    Package versions for the ports.

    The ports mirror the upstream yojimbo version they implement (cpp/include/yojimbo_config.h), plus a port
    revision for fixes made here between upstream releases. VERSION at the repo root holds it in NuGet form:

        1.13.5      the port of upstream 1.13.5
        1.13.5.1    the first port-only fix on top of it

    npm has no fourth part, so the npm version folds the revision into the patch: PATCH * 100 + REVISION
    (1.13.5 -> 1.13.500, 1.13.5.1 -> 1.13.501, upstream 1.13.6 -> 1.13.600). This keeps npm ordering correct.

        node tools/version.mjs                 print the versions
        node tools/version.mjs check [tag]     verify VERSION, cs/yojimbo.csproj, ts/package.json (and a vX.Y.Z[.R] tag)
        node tools/version.mjs set 1.13.5.1    write VERSION, cs/yojimbo.csproj, ts/package.json and its lockfile
*/

import fs from 'node:fs';
import path from 'node:path';
import url from 'node:url';

const root = path.resolve( path.dirname( url.fileURLToPath( import.meta.url ) ), '..' );
const file = ( relative ) => path.join( root, relative );

function parse( version )
{
    const match = /^(\d+)\.(\d+)\.(\d+)(?:\.(\d+))?$/.exec( version.trim() );
    if ( !match )
        throw new Error( `bad version "${version}": expected MAJOR.MINOR.PATCH or MAJOR.MINOR.PATCH.REVISION` );
    const [ , major, minor, patch, revision = '0' ] = match;
    const v = { major: +major, minor: +minor, patch: +patch, revision: +revision };
    if ( v.revision > 99 )
        throw new Error( `port revision ${v.revision} is over 99, which the npm encoding can't hold` );
    return v;
}

const upstreamOf = ( v ) => `${v.major}.${v.minor}.${v.patch}`;
const nugetOf = ( v ) => v.revision ? `${upstreamOf( v )}.${v.revision}` : upstreamOf( v );
const npmOf = ( v ) => `${v.major}.${v.minor}.${v.patch * 100 + v.revision}`;

function readUpstream()
{
    const header = fs.readFileSync( file( 'cpp/include/yojimbo_config.h' ), 'utf8' );
    const get = ( name ) =>
    {
        const match = new RegExp( `#define\\s+YOJIMBO_${name}_VERSION\\s+(\\d+)` ).exec( header );
        if ( !match )
            throw new Error( `YOJIMBO_${name}_VERSION not found in cpp/include/yojimbo_config.h (is the cpp submodule checked out?)` );
        return match[1];
    };
    return `${get( 'MAJOR' )}.${get( 'MINOR' )}.${get( 'PATCH' )}`;
}

const readVersion = () => fs.readFileSync( file( 'VERSION' ), 'utf8' ).trim();

function readCsproj()
{
    const match = /<Version>([^<]+)<\/Version>/.exec( fs.readFileSync( file( 'cs/yojimbo.csproj' ), 'utf8' ) );
    if ( !match )
        throw new Error( 'no <Version> in cs/yojimbo.csproj' );
    return match[1];
}

const readPackageJson = () => JSON.parse( fs.readFileSync( file( 'ts/package.json' ), 'utf8' ) ).version;

function check( tag )
{
    const v = parse( readVersion() );
    const problems = [];
    const upstream = readUpstream();
    if ( upstreamOf( v ) !== upstream )
        problems.push( `VERSION ${readVersion()} ports upstream ${upstreamOf( v )}, but cpp/ is upstream ${upstream}` );
    if ( readCsproj() !== nugetOf( v ) )
        problems.push( `cs/yojimbo.csproj has ${readCsproj()}, expected ${nugetOf( v )}` );
    if ( readPackageJson() !== npmOf( v ) )
        problems.push( `ts/package.json has ${readPackageJson()}, expected ${npmOf( v )}` );
    if ( tag !== undefined && tag.replace( /^refs\/tags\//, '' ) !== `v${nugetOf( v )}` )
        problems.push( `tag ${tag} does not match VERSION (expected v${nugetOf( v )})` );
    for ( const problem of problems )
        console.error( `error: ${problem}` );
    if ( problems.length === 0 )
        console.log( `ok: upstream ${upstream}, nuget ${nugetOf( v )}, npm ${npmOf( v )}` );
    return problems.length === 0;
}

function set( version )
{
    const v = parse( version );
    fs.writeFileSync( file( 'VERSION' ), nugetOf( v ) + '\n' );

    const csproj = fs.readFileSync( file( 'cs/yojimbo.csproj' ), 'utf8' );
    fs.writeFileSync( file( 'cs/yojimbo.csproj' ), csproj.replace( /<Version>[^<]+<\/Version>/, `<Version>${nugetOf( v )}</Version>` ) );

    for ( const name of [ 'ts/package.json', 'ts/package-lock.json' ] )
    {
        if ( !fs.existsSync( file( name ) ) )
            continue;
        const json = JSON.parse( fs.readFileSync( file( name ), 'utf8' ) );
        json.version = npmOf( v );
        if ( json.packages?.[''] )
            json.packages[''].version = npmOf( v );
        fs.writeFileSync( file( name ), JSON.stringify( json, null, 2 ) + '\n' );
    }
    console.log( `set: nuget ${nugetOf( v )}, npm ${npmOf( v )}` );
}

const [ command, argument ] = process.argv.slice( 2 );
if ( command === 'set' && argument )
    set( argument );
else if ( command === 'check' )
    process.exitCode = check( argument ) ? 0 : 1;
else if ( command === undefined )
{
    const v = parse( readVersion() );
    console.log( `upstream ${upstreamOf( v )} (cpp/ is ${readUpstream()}), nuget ${nugetOf( v )}, npm ${npmOf( v )}` );
}
else
{
    console.error( 'usage: node tools/version.mjs [check [tag] | set <MAJOR.MINOR.PATCH[.REVISION]>]' );
    process.exitCode = 1;
}
