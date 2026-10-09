/*
    yojimbo TypeScript port: WebRTC transport extension.

    This folder is an EXTENSION of the TypeScript port, not a mirror of an upstream file: upstream yojimbo has no
    WebRTC transport. It is distributed under the same BSD 3-Clause license as the rest of this package.

    webrtc_token.ts: connect token helpers shared by the WebRTC client and server. Platform neutral (no Node APIs),
    so a browser can import it too.

      - GenerateConnectToken: issue a connect token (what a matchmaker / backend does). For dev and tests; in
        production tokens come from your backend, which holds the private key.
      - ValidateConnectToken: the WebRTC signaling gate. Checks a connect token the way netcode's server does when
        a connection request arrives (version, protocol id, expiry, authenticity by decrypting the private part
        with the server's private key, and this server's address in the token's server address whitelist), so the
        signaling endpoint can refuse to allocate a peer connection for anyone without a valid token.
      - EncodeBase64 / DecodeBase64: the connect token travels as base64 in the signaling JSON.
*/

import {
    netcode_generate_connect_token, netcode_decrypt_connect_token_private, netcode_read_connect_token_private,
    netcode_connect_token_private_t, netcode_address_equal, netcode_address_t,
    NETCODE_OK, NETCODE_CONNECT_TOKEN_BYTES, NETCODE_CONNECT_TOKEN_PRIVATE_BYTES, NETCODE_CONNECT_TOKEN_NONCE_BYTES,
    NETCODE_VERSION_INFO_BYTES, NETCODE_KEY_BYTES, NETCODE_MAC_BYTES, NETCODE_MAX_SERVERS_PER_CONNECT,
} from '../netcode/netcode.ts';
import { Address, AddressToNetcode, DefaultMaxConnectTokenLifetime, YOJIMBO_DEFAULT_TIMEOUT } from '../source/yojimbo.ts';

/** "NETCODE 1.02\0", the version info at the start of every connect token (netcode.c NETCODE_VERSION_INFO). */
const ConnectTokenVersionInfo = new Uint8Array( [ 0x4E, 0x45, 0x54, 0x43, 0x4F, 0x44, 0x45, 0x20, 0x31, 0x2E, 0x30, 0x32, 0x00 ] );

// public connect token layout (netcode_write_connect_token)
const ConnectTokenProtocolIdOffset = NETCODE_VERSION_INFO_BYTES;
const ConnectTokenCreateTimestampOffset = ConnectTokenProtocolIdOffset + 8;
const ConnectTokenExpireTimestampOffset = ConnectTokenCreateTimestampOffset + 8;
const ConnectTokenNonceOffset = ConnectTokenExpireTimestampOffset + 8;
const ConnectTokenPrivateOffset = ConnectTokenNonceOffset + NETCODE_CONNECT_TOKEN_NONCE_BYTES;

/** Base64 of a byte array (standard alphabet, padded). */

export function EncodeBase64( data: Uint8Array ): string
{
    let binary = '';
    for ( let i = 0; i < data.length; i += 0x8000 )
        binary += String.fromCharCode( ...data.subarray( i, i + 0x8000 ) );
    return btoa( binary );
}

/** Strict base64 decode (standard alphabet, padded). Returns null for anything malformed. */

export function DecodeBase64( text: string ): Uint8Array | null
{
    if ( typeof text !== 'string' || text.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test( text ) )
        return null;
    let binary: string;
    try
    {
        binary = atob( text );
    }
    catch
    {
        return null;
    }
    const data = new Uint8Array( binary.length );
    for ( let i = 0; i < binary.length; ++i )
        data[i] = binary.charCodeAt( i );
    return data;
}

export interface GenerateConnectTokenOptions
{
    /** The private key shared by the token issuer and the game servers (KeyBytes). */
    privateKey: Uint8Array;
    /** Must match ClientServerConfig.protocolId on the server. */
    protocolId: bigint;
    /** Unique id of the client (uint64). */
    clientId: bigint;
    /** Server addresses the client may connect to, in order (1..32). For a WebRTC server: the address its adapter was opened on. */
    serverAddresses: ReadonlyArray<Address | string>;
    /** Token lifetime in seconds. Default DefaultMaxConnectTokenLifetime (30), which must match the server's ClientServerConfig.maxConnectTokenLifetime. */
    expireSeconds?: number;
    /** Connection timeout in seconds carried in the token. Default YOJIMBO_DEFAULT_TIMEOUT (10). */
    timeoutSeconds?: number;
    /** Up to 256 bytes of user data, delivered to the server (encrypted). */
    userData?: Uint8Array;
}

/**
    Issue a connect token (ConnectTokenBytes), or null on bad arguments.
    This is what a matchmaker does. Dev / tests only: anyone holding the private key can mint tokens, so in production
    tokens are issued by your backend after it authenticates the player, never by a public endpoint.
 */

export function GenerateConnectToken( options: GenerateConnectTokenOptions ): Uint8Array | null
{
    const addresses = options.serverAddresses.map( address => typeof address === 'string' ? address : address.ToString() );
    if ( addresses.length < 1 || addresses.length > NETCODE_MAX_SERVERS_PER_CONNECT || options.privateKey.length < NETCODE_KEY_BYTES )
        return null;
    const userData = new Uint8Array( 256 );
    if ( options.userData )
        userData.set( options.userData.subarray( 0, 256 ) );
    const token = new Uint8Array( NETCODE_CONNECT_TOKEN_BYTES );
    if ( netcode_generate_connect_token( addresses.length, addresses, addresses,
                                         options.expireSeconds ?? DefaultMaxConnectTokenLifetime,
                                         options.timeoutSeconds ?? YOJIMBO_DEFAULT_TIMEOUT,
                                         options.clientId, options.protocolId, options.privateKey, userData, token ) !== NETCODE_OK )
        return null;
    return token;
}

export interface ConnectTokenInfo
{
    clientId: bigint;
    expireTimestamp: bigint;
    timeoutSeconds: number;
    /** Hex of the private part's MAC: identifies the token (netcode keys its token history on the same bytes). */
    tokenId: string;
}

export type ValidateConnectTokenResult = { ok: true, info: ConnectTokenInfo } | { ok: false, reason: string };

/**
    Validate a connect token as netcode's server would on a connection request, without touching any server state.
    @param token The full public connect token (ConnectTokenBytes).
    @param privateKey The server's private key.
    @param protocolId The server's protocol id.
    @param serverAddress The address the netcode server runs on: it must be in the token's (encrypted) server address list.
    @param now Current unix time in seconds (default: the clock).
 */

export function ValidateConnectToken( token: Uint8Array, privateKey: Uint8Array, protocolId: bigint, serverAddress: Address, now?: bigint ): ValidateConnectTokenResult
{
    if ( !( token instanceof Uint8Array ) || token.length !== NETCODE_CONNECT_TOKEN_BYTES )
        return { ok: false, reason: 'bad token length' };

    for ( let i = 0; i < NETCODE_VERSION_INFO_BYTES; ++i )
    {
        if ( token[i] !== ConnectTokenVersionInfo[i] )
            return { ok: false, reason: 'bad version info' };
    }

    const view = new DataView( token.buffer, token.byteOffset, token.byteLength );
    const tokenProtocolId = view.getBigUint64( ConnectTokenProtocolIdOffset, true );
    const createTimestamp = view.getBigUint64( ConnectTokenCreateTimestampOffset, true );
    const expireTimestamp = view.getBigUint64( ConnectTokenExpireTimestampOffset, true );

    if ( tokenProtocolId !== BigInt.asUintN( 64, protocolId ) )
        return { ok: false, reason: 'wrong protocol id' };

    if ( createTimestamp > expireTimestamp )
        return { ok: false, reason: 'bad timestamps' };

    const currentTimestamp = now ?? BigInt( Math.floor( Date.now() / 1000 ) );
    if ( expireTimestamp <= currentTimestamp )
        return { ok: false, reason: 'expired' };

    // decrypt a copy of the private part (decryption is in place). this authenticates the whole token header
    // too: version info, protocol id and expire timestamp are the additional data

    const nonce = token.slice( ConnectTokenNonceOffset, ConnectTokenNonceOffset + NETCODE_CONNECT_TOKEN_NONCE_BYTES );
    const privateData = token.slice( ConnectTokenPrivateOffset, ConnectTokenPrivateOffset + NETCODE_CONNECT_TOKEN_PRIVATE_BYTES );
    const mac = privateData.slice( NETCODE_CONNECT_TOKEN_PRIVATE_BYTES - NETCODE_MAC_BYTES );
    if ( netcode_decrypt_connect_token_private( privateData, NETCODE_CONNECT_TOKEN_PRIVATE_BYTES, ConnectTokenVersionInfo,
                                                tokenProtocolId, expireTimestamp, nonce, privateKey ) !== NETCODE_OK )
        return { ok: false, reason: 'decrypt failed' };

    const tokenPrivate = new netcode_connect_token_private_t();
    if ( netcode_read_connect_token_private( privateData, NETCODE_CONNECT_TOKEN_PRIVATE_BYTES, tokenPrivate ) !== NETCODE_OK )
        return { ok: false, reason: 'bad private data' };

    const address = new netcode_address_t();
    if ( !AddressToNetcode( serverAddress, address ) )
        return { ok: false, reason: 'bad server address' };

    let found = false;
    for ( let i = 0; i < tokenPrivate.num_server_addresses; ++i )
    {
        if ( netcode_address_equal( address, tokenPrivate.server_addresses[i] ) )
            found = true;
    }

    // wipe the keys we just decrypted
    privateData.fill( 0 );
    tokenPrivate.client_to_server_key.fill( 0 );
    tokenPrivate.server_to_client_key.fill( 0 );

    if ( !found )
        return { ok: false, reason: 'server address not in token' };

    let tokenId = '';
    for ( const byte of mac )
        tokenId += byte.toString( 16 ).padStart( 2, '0' );

    return { ok: true, info: { clientId: tokenPrivate.client_id, expireTimestamp, timeoutSeconds: tokenPrivate.timeout_seconds, tokenId } };
}

/** The public server addresses listed in a connect token (unauthenticated: the client side's view), or [] if malformed. */

export function ConnectTokenServerAddresses( token: Uint8Array ): Address[]
{
    const addresses: Address[] = [];
    if ( !( token instanceof Uint8Array ) || token.length !== NETCODE_CONNECT_TOKEN_BYTES )
        return addresses;
    const view = new DataView( token.buffer, token.byteOffset, token.byteLength );
    let offset = ConnectTokenPrivateOffset + NETCODE_CONNECT_TOKEN_PRIVATE_BYTES + 4;     // skip timeout_seconds
    const count = view.getUint32( offset, true );
    offset += 4;
    if ( count < 1 || count > NETCODE_MAX_SERVERS_PER_CONNECT )
        return addresses;
    for ( let i = 0; i < count; ++i )
    {
        const type = token[offset++];
        if ( type === 1 )
        {
            addresses.push( new Address( token[offset], token[offset + 1], token[offset + 2], token[offset + 3], view.getUint16( offset + 4, true ) ) );
            offset += 6;
        }
        else if ( type === 2 )
        {
            const fields: number[] = [];
            for ( let j = 0; j < 8; ++j )
                fields.push( view.getUint16( offset + j * 2, true ) );
            addresses.push( new Address( fields, view.getUint16( offset + 16, true ) ) );
            offset += 18;
        }
        else
        {
            return [];
        }
    }
    return addresses;
}
