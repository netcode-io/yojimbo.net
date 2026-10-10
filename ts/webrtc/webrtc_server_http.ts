/*
    yojimbo TypeScript port: WebRTC transport extension.

    This folder is an EXTENSION of the TypeScript port, not a mirror of an upstream file: upstream yojimbo has no
    WebRTC transport. It is distributed under the same BSD 3-Clause license as the rest of this package.

    webrtc_server_http.ts: HTTP signaling for WebRTCServerAdapter (webrtc_server.ts). NODE ONLY: node:http shaped
    request / response (works from express / fastify raw req / res too); node:http itself is reached through
    process.getBuiltinModule, never a static import. Kept apart from webrtc_server.ts so a browser bundle of the
    server carries no Node code. It re-exports webrtc_server.ts, so a Node server can import everything from here.

    One POST of application/json { sdp, connectToken } (connectToken = base64 of the 2048 byte connect token),
    answered with 200 { sdp } -- the client side is HttpSignal / connect( url, token ) in webrtc_client.ts. This
    layer owns only what is HTTP: method, CORS, content type, body size and deadline, JSON, base64, and the client
    IP. Everything else (token validation before any peer exists, caps, the per-token signal count, timeouts and
    reaping, onSignal) is WebRTCServerAdapter.accept(), in the same order as before:

        method / CORS → content type → declared length → caps (adapter.precheck) → body → JSON → base64 → accept()

    Usage:

        await ListenSignaling( adapter, 8080, { path: '/signal', cors: { origins: [ 'https://game.example.com' ] } } );
        // or route POST /signal yourself:  HandleSignal( adapter, req, res, { clientIp } )
*/

import type { IncomingMessage, ServerResponse, Server as HttpServer } from 'node:http';
import { WebRTCServerAdapter, SignalError } from './webrtc_server.ts';
import { DecodeBase64 } from './webrtc_token.ts';

export * from './webrtc_server.ts';

export interface WebRTCHttpSignalOptions
{
    /** Max signaling request body. Default 16384 bytes (an offer is ~1 KB, the token ~2.7 KB of base64). */
    maxBodyBytes?: number;
    /** Max time to receive the request body. Default 5000 ms. */
    bodyTimeoutMs?: number;
    /** CORS for the signaling endpoint. Default none (same origin only). '*' or a list of allowed origins. */
    cors?: { origins: '*' | string[], allowHeaders?: string[] } | null;
    /** How to get the client IP for the per-IP limits (e.g. from X-Forwarded-For behind your own proxy). Default req.socket.remoteAddress. */
    clientIp?: ( req: IncomingMessage ) => string;
}

/**
    Handle one signaling request: POST application/json { sdp, connectToken } → 200 { sdp }.
    Errors: 400 malformed, 403 bad / expired / foreign / overused token, 405 method, 408 slow body, 413 body too
    large, 415 content type, 429 per-IP limit, 503 server full or closed. Never throws.
 */

export async function HandleSignal( adapter: WebRTCServerAdapter, req: IncomingMessage, res: ServerResponse, options: WebRTCHttpSignalOptions = {} ): Promise<void>
{
    const ip = ClientIp( req, options );
    let accepting = false;
    try
    {
        ApplyCors( req, res, options );

        if ( req.method === 'OPTIONS' && options.cors )
        {
            res.statusCode = 204;
            res.end();
            return;
        }

        if ( req.method !== 'POST' )
        {
            res.setHeader( 'Allow', options.cors ? 'POST, OPTIONS' : 'POST' );
            throw new SignalError( 405, 'method not allowed' );
        }

        if ( !adapter.isOpen )
            throw new SignalError( 503, 'server not open' );

        const contentType = String( req.headers['content-type'] ?? '' ).split( ';' )[0].trim().toLowerCase();
        if ( contentType !== 'application/json' )
            throw new SignalError( 415, 'content type must be application/json' );

        const maxBodyBytes = options.maxBodyBytes ?? 16384;
        const declaredLength = Number( req.headers['content-length'] );
        if ( Number.isFinite( declaredLength ) && declaredLength > maxBodyBytes )
            throw new SignalError( 413, 'body too large' );

        // cheap limits before reading or decrypting anything (accept() checks them again)
        adapter.precheck( ip );

        const body = await ReadBody( req, maxBodyBytes, options.bodyTimeoutMs ?? 5000 );

        let request: { sdp?: unknown, connectToken?: unknown };
        try
        {
            request = JSON.parse( body );
        }
        catch
        {
            throw new SignalError( 400, 'body is not JSON' );
        }
        if ( typeof request !== 'object' || request === null || typeof request.sdp !== 'string' || typeof request.connectToken !== 'string' )
            throw new SignalError( 400, 'expected { sdp: string, connectToken: string }' );

        const connectToken = DecodeBase64( request.connectToken );
        if ( !connectToken )
            throw new SignalError( 403, 'connect token is not base64' );

        // the client going away while the server gathers releases its peer (req.destroyed is no use: a fully read
        // request is destroyed; the response closes before it ends instead)
        const abort = new AbortController();
        const onClose = () => { if ( !res.writableEnded ) abort.abort(); };
        res.once( 'close', onClose );
        if ( res.destroyed || res.socket?.destroyed )
            abort.abort();

        accepting = true;             // from here accept() reports the outcome itself
        let answer: { sdp: string };
        try
        {
            answer = await adapter.accept( { sdp: request.sdp, connectToken, ip, signal: abort.signal } );
        }
        finally
        {
            res.off( 'close', onClose );
        }

        res.statusCode = 200;
        res.setHeader( 'Content-Type', 'application/json' );
        res.setHeader( 'Cache-Control', 'no-store' );
        res.end( JSON.stringify( { sdp: answer.sdp } ) );
    }
    catch ( error )
    {
        const status = error instanceof SignalError ? error.status : 500;
        const reason = error instanceof Error ? error.message : String( error );
        if ( !accepting )
            adapter.reportSignal( ip, status, reason );
        if ( !res.headersSent && !res.destroyed )
        {
            res.statusCode = status;
            res.setHeader( 'Content-Type', 'text/plain; charset=utf-8' );
            res.setHeader( 'Cache-Control', 'no-store' );
            if ( status === 413 || status === 408 )
            {
                // the body may still be arriving. answer, then discard what's left (bounded) before closing: closing
                // with unread data sends a TCP RST, and Windows clients drop the response they haven't read yet
                res.setHeader( 'Connection', 'close' );
                res.on( 'finish', () => DrainThenClose( req ) );
            }
            res.end( status === 500 ? 'internal error' : reason );
        }
    }
}

/**
    Start a node:http server that routes POST (and OPTIONS, with cors) on options.path (default '/signal') to
    HandleSignal and answers 404 elsewhere. Closed by adapter.close(). Resolves once listening.
 */

export async function ListenSignaling( adapter: WebRTCServerAdapter, port: number, options: WebRTCHttpSignalOptions & { path?: string, host?: string } = {} ): Promise<HttpServer>
{
    const http = process.getBuiltinModule( 'node:http' );
    const path = options.path ?? '/signal';
    const server = http.createServer( ( req, res ) =>
    {
        const url = new URL( req.url ?? '/', 'http://localhost' );
        if ( url.pathname === path )
        {
            void HandleSignal( adapter, req, res, options );
            return;
        }
        res.statusCode = 404;
        res.end( 'not found' );
    } );
    server.headersTimeout = 10000;
    server.requestTimeout = 15000;
    await new Promise<void>( ( resolve, reject ) =>
    {
        server.once( 'error', reject );
        server.listen( port, options.host, () => { server.off( 'error', reject ); resolve(); } );
    } );
    const removeListener = adapter.onClose( () =>
    {
        server.close();
        server.closeAllConnections?.();
    } );
    server.on( 'close', removeListener );
    return server;
}

function ClientIp( req: IncomingMessage, options: WebRTCHttpSignalOptions ): string
{
    try
    {
        return options.clientIp?.( req ) ?? req.socket?.remoteAddress ?? 'unknown';
    }
    catch
    {
        return 'unknown';
    }
}

function ApplyCors( req: IncomingMessage, res: ServerResponse, options: WebRTCHttpSignalOptions ): void
{
    const cors = options.cors;
    if ( !cors )
        return;
    const origin = req.headers.origin;
    if ( cors.origins === '*' )
        res.setHeader( 'Access-Control-Allow-Origin', '*' );
    else if ( origin && cors.origins.includes( origin ) )
    {
        res.setHeader( 'Access-Control-Allow-Origin', origin );
        res.setHeader( 'Vary', 'Origin' );
    }
    else
        return;
    if ( req.method === 'OPTIONS' )
    {
        res.setHeader( 'Access-Control-Allow-Methods', 'POST, OPTIONS' );
        res.setHeader( 'Access-Control-Allow-Headers', [ 'Content-Type', ...( cors.allowHeaders ?? [] ) ].join( ', ' ) );
        res.setHeader( 'Access-Control-Max-Age', '600' );
    }
}

/** Discard the rest of a refused request body, at most 1 MB or 1 s, then close the connection. */

function DrainThenClose( req: IncomingMessage ): void
{
    const DrainMaxBytes = 1024 * 1024;
    const DrainMaxMs = 1000;
    let drained = 0;
    const close = () => { clearTimeout( timer ); req.off( 'data', onData ); req.destroy(); };
    const onData = ( chunk: Uint8Array ) => { drained += chunk.length; if ( drained > DrainMaxBytes ) close(); };
    const timer = setTimeout( close, DrainMaxMs );
    req.on( 'data', onData );
    req.once( 'end', close );
    req.once( 'error', close );
    req.resume();
}

/** Read a request body as UTF-8 with a size cap and a deadline. */

function ReadBody( req: IncomingMessage, maxBytes: number, timeoutMs: number ): Promise<string>
{
    return new Promise<string>( ( resolve, reject ) =>
    {
        const chunks: Uint8Array[] = [];
        let total = 0;
        let done = false;
        const finish = ( error: SignalError | null ) =>
        {
            if ( done )
                return;
            done = true;
            clearTimeout( timer );
            req.off( 'data', onData );
            req.off( 'end', onEnd );
            req.off( 'error', onError );
            if ( error )
            {
                req.pause();
                reject( error );
            }
            else
                resolve( new TextDecoder().decode( Buffer.concat( chunks ) ) );
        };
        const onData = ( chunk: Uint8Array ) =>
        {
            total += chunk.length;
            if ( total > maxBytes )
                finish( new SignalError( 413, 'body too large' ) );
            else
                chunks.push( chunk );
        };
        const onEnd = () => finish( null );
        const onError = () => finish( new SignalError( 400, 'request error' ) );
        const timer = setTimeout( () => finish( new SignalError( 408, 'body timeout' ) ), timeoutMs );
        req.on( 'data', onData );
        req.on( 'end', onEnd );
        req.on( 'error', onError );
    } );
}
