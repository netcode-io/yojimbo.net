/*
    netcode

    Copyright © 2017 - 2026, Más Bandwidth LLC

    Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

        1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

        2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer
           in the documentation and/or other materials provided with the distribution.

        3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived
           from this software without specific prior written permission.

    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
    INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
    DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
    SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
    SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
    WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
    USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

/*
    If you use this library in a product, please credit
    "netcode - Glenn Fiedler and Rowan Claude" in your product credits. The
    license doesn't require this credit. It's an official request, and honoring
    it is appreciated.
*/

/*
    netcode.ts

    TypeScript port of netcode 1.4.8 (cpp/netcode/netcode.h + netcode.c). The wire format is byte for byte
    the C one ("NETCODE 1.02": same packet layouts, associated data, nonces and sizes), so a TypeScript client
    talks to a C server and the other way around. Functions keep their upstream names and order; C structs
    are classes with the same field names. The tests of netcode.c are ported at the end of this file, and
    netcode_test() runs them.

    Porting notes (what differs from C, and why):

    - Types. Bytes are Uint8Array. Values that are 64 bit (packet sequences, client ids, protocol ids,
      timestamps) are bigint; everything else is number. Functions that return int in C return number here
      (NETCODE_OK / NETCODE_ERROR, 0 / 1), so code ports one to one. C out-params are `{ value }` objects.

    - netcode_address_t is a class. C copies addresses by value, so netcode stores its own copy whenever it
      keeps an address (netcode_address_copy); callers may reuse their address objects freely. `data.ipv4`
      and `data.ipv6` are views of the same 16 bytes, like the C union.

    - Configs. client and server create copy the config (including the private key) as C copies the struct,
      so changing the caller's config afterwards has no effect, and server destroy wipes only its own copy.

    - Allocation. allocate_function( context, bytes ) is called wherever C allocates. A falsy return is an
      allocation failure and is handled exactly as C handles NULL; any other value just means success (the
      JS objects themselves are allocated by netcode). free_function( context, object ) is called wherever
      C frees, with the object being released. The defaults succeed and do nothing.

    - Packets handed to the user. netcode_client_receive_packet / netcode_server_receive_packet return a
      Uint8Array view of exactly the payload (with 8 bytes of slack behind it in the underlying buffer, as C
      leaves for serialize's 8 byte reads). Pass that same view to netcode_*_free_packet. packet_data passed
      to send_packet_override and send_loopback_packet_callback is only valid during the call, as in C.

    - Asserts are always compiled in (there is no NDEBUG). They call netcode_assert_function, whose default
      prints and throws instead of exiting. As upstream, no assert is on the untrusted network read path.

    - Time. netcode_time() is performance.now() in seconds since the first call. netcode_sleep() cannot block
      in JavaScript: it returns a Promise. A loop over real sockets must yield to the event loop (await
      netcode_sleep, or a timer between updates) or no packet is ever received.

    - Sockets. UDP is the Node dgram module, loaded with process.getBuiltinModule( 'node:dgram' ) so the same
      file loads in a browser, where there is no UDP: creating a socket there fails cleanly with the
      CREATE_SOCKET create error, and netcode is driven through override_send_and_receive or loopback
      instead. dgram is event based, so each socket queues incoming datagrams from its 'message' events into
      a receive queue bounded by the receive buffer size (the overflow is dropped, as the kernel drops it),
      and netcode_socket_receive_packet drains that queue synchronously. Sends are fire and forget.

      Bind is reported synchronously, keeping the upstream API: the socket is created with a lookup function
      that resolves the numeric address synchronously, which makes dgram's bind() complete (or emit its
      error) before it returns, so a port in use is a BIND_SOCKET create error right away, as in C. Should a
      runtime ever complete bind asynchronously anyway, the socket is kept and a late bind error is recorded
      on it (netcode_socket_t.error) and logged; its sends and receives then do nothing.

      Socket options: IPV6_V6ONLY via ipv6Only, SO_SNDBUF / SO_RCVBUF via set*BufferSize after bind (with
      the same halving back off as C), the bound port via address(). Packet tagging uses setTOS( 46 ) when
      the runtime has it; Node has no setTOS, so there it is a no-op (as on platforms without QoS in C).
      IPv4 and IPv6 are separate sockets, as in C, and dual-stack clients and servers get one of each.

    - Address parsing follows inet_pton as glibc implements it (strict: no leading zeros in IPv4 octets,
      at most four hex digits in an IPv6 group, no zone ids); address_to_string follows inet_ntop.

    - Logging. netcode_printf takes a printf style format with %d %s %x %f and %.16" + PRIx64 + " style
      64 bit hex, formatted only when the log level lets the message through. The printf function receives
      the formatted string.

    - The nonce audit test instrumentation (NETCODE_ENABLE_NONCE_AUDIT) is switched on while netcode_test()
      runs, so the whole suite checks that no key and nonce pair is ever used twice.
*/

import
{
    crypto_aead_chacha20poly1305_ietf_decrypt,
    crypto_aead_chacha20poly1305_ietf_encrypt,
    crypto_aead_xchacha20poly1305_ietf_decrypt,
    crypto_aead_xchacha20poly1305_ietf_encrypt,
    crypto_verify_16,
    crypto_verify_32,
    crypto_verify_64,
    randombytes_buf,
    sodium_init,
    sodium_memzero,
    type sodium_length_out,
} from '../sodium/sodium.ts';

// ---------------------------------------------------------------------------------------------
// netcode.h

export const NETCODE_VERSION_FULL = '1.4.8';
export const NETCODE_VERSION_MAJOR = 1;
export const NETCODE_VERSION_MINOR = 4;
export const NETCODE_VERSION_PATCH = 8;

/** 1 on little endian hosts (all supported ones), 0 otherwise */
export const NETCODE_LITTLE_ENDIAN = new Uint8Array( new Uint32Array( [ 0x11223344 ] ).buffer )[0] == 0x44 ? 1 : 0;

export const NETCODE_CONNECT_TOKEN_BYTES = 2048;
export const NETCODE_KEY_BYTES = 32;
export const NETCODE_MAC_BYTES = 16;
export const NETCODE_USER_DATA_BYTES = 256;
export const NETCODE_MAX_SERVERS_PER_CONNECT = 32;
export const NETCODE_DEFAULT_MAX_CONNECT_TOKEN_LIFETIME = 30;

export const NETCODE_CLIENT_STATE_CONNECT_TOKEN_EXPIRED = -6;
export const NETCODE_CLIENT_STATE_INVALID_CONNECT_TOKEN = -5;
export const NETCODE_CLIENT_STATE_CONNECTION_TIMED_OUT = -4;
export const NETCODE_CLIENT_STATE_CONNECTION_RESPONSE_TIMED_OUT = -3;
export const NETCODE_CLIENT_STATE_CONNECTION_REQUEST_TIMED_OUT = -2;
export const NETCODE_CLIENT_STATE_CONNECTION_DENIED = -1;
export const NETCODE_CLIENT_STATE_DISCONNECTED = 0;
export const NETCODE_CLIENT_STATE_SENDING_CONNECTION_REQUEST = 1;
export const NETCODE_CLIENT_STATE_SENDING_CONNECTION_RESPONSE = 2;
export const NETCODE_CLIENT_STATE_CONNECTED = 3;

// The reason the client in a server slot was last disconnected. Tracked per-client slot:
// reset to NONE when the server starts and when a new client connects to the slot, and
// recorded before the connect_disconnect_callback fires, so it can be queried from inside
// that callback via netcode_server_client_disconnect_reason.
export const NETCODE_SERVER_CLIENT_DISCONNECT_REASON_NONE = 0;
export const NETCODE_SERVER_CLIENT_DISCONNECT_REASON_TIMED_OUT = 1;
export const NETCODE_SERVER_CLIENT_DISCONNECT_REASON_CLIENT_DISCONNECT = 2;
export const NETCODE_SERVER_CLIENT_DISCONNECT_REASON_SERVER_DISCONNECT = 3;

export const NETCODE_CLIENT_CREATE_ERROR_NONE = 0;
export const NETCODE_CLIENT_CREATE_ERROR_PARSE_ADDRESS_FAILED = 1;
export const NETCODE_CLIENT_CREATE_ERROR_PARSE_ADDRESS2_FAILED = 2;
export const NETCODE_CLIENT_CREATE_ERROR_SIMULATOR_REQUIRES_PORT = 3;
export const NETCODE_CLIENT_CREATE_ERROR_CREATE_SOCKET_IPV4_FAILED = 4;
export const NETCODE_CLIENT_CREATE_ERROR_CREATE_SOCKET_IPV6_FAILED = 5;
export const NETCODE_CLIENT_CREATE_ERROR_ALLOCATE_CLIENT_FAILED = 6;
export const NETCODE_CLIENT_CREATE_ERROR_MISSING_OVERRIDE_CALLBACK = 7;

export const NETCODE_SERVER_CREATE_ERROR_NONE = 0;
export const NETCODE_SERVER_CREATE_ERROR_PARSE_ADDRESS_FAILED = 1;
export const NETCODE_SERVER_CREATE_ERROR_PARSE_ADDRESS2_FAILED = 2;
export const NETCODE_SERVER_CREATE_ERROR_CREATE_SOCKET_IPV4_FAILED = 3;
export const NETCODE_SERVER_CREATE_ERROR_CREATE_SOCKET_IPV6_FAILED = 4;
export const NETCODE_SERVER_CREATE_ERROR_BIND_SOCKET_IPV4_FAILED = 5;
export const NETCODE_SERVER_CREATE_ERROR_BIND_SOCKET_IPV6_FAILED = 6;
export const NETCODE_SERVER_CREATE_ERROR_ALLOCATE_SERVER_FAILED = 7;
export const NETCODE_SERVER_CREATE_ERROR_MISSING_OVERRIDE_CALLBACK = 8;

export const NETCODE_MAX_CLIENTS = 256;
export const NETCODE_MAX_PACKET_SIZE = 1200;

export const NETCODE_MAX_ADDRESS_STRING_LENGTH = 256;

export const NETCODE_LOG_LEVEL_NONE = 0;
export const NETCODE_LOG_LEVEL_ERROR = 1;
export const NETCODE_LOG_LEVEL_INFO = 2;
export const NETCODE_LOG_LEVEL_DEBUG = 3;

export const NETCODE_OK = 1;
export const NETCODE_ERROR = 0;

export const NETCODE_ADDRESS_NONE = 0;
export const NETCODE_ADDRESS_IPV4 = 1;
export const NETCODE_ADDRESS_IPV6 = 2;

export const NETCODE_PACKET_TAGGING = 1;

/** allocate_function( context, bytes ): a falsy return is an allocation failure, anything else success */
export type netcode_allocate_function_t = ( context: unknown, bytes: number ) => unknown;

/** free_function( context, object ): called with the object netcode releases */
export type netcode_free_function_t = ( context: unknown, pointer: unknown ) => void;

/** packet_data is only valid during the call */
export type netcode_send_packet_override_t = ( context: unknown, to: netcode_address_t, packet_data: Uint8Array, packet_bytes: number ) => void;

/** write a received packet into packet_data (at most max_packet_bytes) and its sender into from. return its size, or 0 for none */
export type netcode_receive_packet_override_t = ( context: unknown, from: netcode_address_t, packet_data: Uint8Array, max_packet_bytes: number ) => number;

/** packet_data is only valid during the call */
export type netcode_send_loopback_packet_callback_t = ( context: unknown, client_index: number, packet_data: Uint8Array, packet_bytes: number, packet_sequence: bigint ) => void;

export class netcode_client_config_t
{
    allocator_context: unknown = null;
    allocate_function: netcode_allocate_function_t | null = null;
    free_function: netcode_free_function_t | null = null;
    network_simulator: netcode_network_simulator_t | null = null;
    callback_context: unknown = null;
    state_change_callback: ( ( context: unknown, previous_state: number, current_state: number ) => void ) | null = null;
    send_loopback_packet_callback: netcode_send_loopback_packet_callback_t | null = null;
    override_send_and_receive = 0;
    send_packet_override: netcode_send_packet_override_t | null = null;
    receive_packet_override: netcode_receive_packet_override_t | null = null;
}

export class netcode_server_config_t
{
    protocol_id = 0n;
    private_key = new Uint8Array( NETCODE_KEY_BYTES );
    allocator_context: unknown = null;
    allocate_function: netcode_allocate_function_t | null = null;
    free_function: netcode_free_function_t | null = null;
    network_simulator: netcode_network_simulator_t | null = null;
    callback_context: unknown = null;
    connect_disconnect_callback: ( ( context: unknown, client_index: number, connected: number ) => void ) | null = null;
    send_loopback_packet_callback: netcode_send_loopback_packet_callback_t | null = null;
    override_send_and_receive = 0;
    send_packet_override: netcode_send_packet_override_t | null = null;
    receive_packet_override: netcode_receive_packet_override_t | null = null;

    /*
        max_connect_token_lifetime is the longest lifetime in seconds that the backend issues
        connect tokens with, as passed to netcode_generate_connect_token. The server ignores any
        connection request whose connect token expire timestamp minus this lifetime is earlier
        than the time the server started, so a connect token that could have been issued before
        the server started cannot be presented after it. Set it to the lifetime your backend
        issues: a larger value rejects legitimate connect tokens until the difference has elapsed,
        and a smaller value lets connect tokens issued shortly before the server started through.
        A value of zero or less takes NETCODE_DEFAULT_MAX_CONNECT_TOKEN_LIFETIME instead.
    */

    max_connect_token_lifetime = 0;
}

// ---------------------------------------------------------------------------------------------
// netcode.c

export const NETCODE_SOCKET_IPV6 = 1;
export const NETCODE_SOCKET_IPV4 = 2;

export const NETCODE_CONNECT_TOKEN_NONCE_BYTES = 24;
export const NETCODE_CONNECT_TOKEN_PRIVATE_BYTES = 1024;
export const NETCODE_CHALLENGE_TOKEN_BYTES = 300;
export const NETCODE_VERSION_INFO_BYTES = 13;
export const NETCODE_MAX_PACKET_BYTES = 1300;
export const NETCODE_MAX_PAYLOAD_BYTES = 1200;
export const NETCODE_PACKET_QUEUE_SIZE = 256;
export const NETCODE_REPLAY_PROTECTION_BUFFER_SIZE = 256;
export const NETCODE_CLIENT_MAX_RECEIVE_PACKETS = 64;
export const NETCODE_SERVER_MAX_RECEIVE_PACKETS = 64 * NETCODE_MAX_CLIENTS;
export const NETCODE_CLIENT_SOCKET_SNDBUF_SIZE = 4 * 1024 * 1024;
export const NETCODE_CLIENT_SOCKET_RCVBUF_SIZE = 4 * 1024 * 1024;
export const NETCODE_SERVER_SOCKET_SNDBUF_SIZE = 4 * 1024 * 1024;
export const NETCODE_SERVER_SOCKET_RCVBUF_SIZE = 4 * 1024 * 1024;

// "NETCODE 1.02" and its terminating zero
const NETCODE_VERSION_INFO = new Uint8Array( [ 0x4E, 0x45, 0x54, 0x43, 0x4F, 0x44, 0x45, 0x20, 0x31, 0x2E, 0x30, 0x32, 0x00 ] );
const NETCODE_PACKET_SEND_RATE = 10.0;
const NETCODE_NUM_DISCONNECT_PACKETS = 10;

const NETCODE_ENABLE_LOGGING = true;

// ------------------------------------------------------------------

let netcode_packet_tagging_enabled = 0;

export function netcode_enable_packet_tagging(): void
{
    netcode_packet_tagging_enabled = 1;
}

// ------------------------------------------------------------------

type netcode_process_t = { stdout?: { write( text: string ): unknown }, getBuiltinModule?: ( id: string ) => unknown };

function netcode_process(): netcode_process_t | undefined
{
    return ( globalThis as { process?: netcode_process_t } ).process;
}

/** writes text as is to stdout on Node, or to the console elsewhere */
function netcode_default_printf_function( text: string ): void
{
    const stdout = netcode_process()?.stdout;
    if ( stdout )
        stdout.write( text );
    else
        console.log( text.endsWith( '\n' ) ? text.slice( 0, -1 ) : text );
}

export function netcode_default_assert_handler( condition: string, func: string, file: string, line: number ): void
{
    const message = 'assert failed: ( ' + condition + ' ), function ' + func + ', file ' + file + ', line ' + line;
    netcode_default_printf_function( message + '\n' );
    // C breaks into the debugger and exits. throwing is the JavaScript equivalent that also works in a browser.
    throw new Error( 'netcode ' + message );
}

let log_level = 0;
let printf_function: ( text: string ) => void = netcode_default_printf_function;
export let netcode_assert_function: ( condition: string, func: string, file: string, line: number ) => void = netcode_default_assert_handler;

export function netcode_log_level( level: number ): void
{
    log_level = level;
}

export function netcode_set_printf_function( func: ( text: string ) => void ): void
{
    netcode_assert( func );
    printf_function = func;
}

/*
    The default assert handler prints the failed condition and throws. A custom assert handler may
    return instead, in which case execution continues past the failed assert -- that is the caller's
    choice and their responsibility.
*/

export function netcode_set_assert_function( func: ( condition: string, func: string, file: string, line: number ) => void ): void
{
    netcode_assert_function = func;
}

/** asserts are always compiled in. the failing location is recovered from the stack, so a passing assert costs one call */
export function netcode_assert( condition: unknown ): void
{
    if ( !condition )
        netcode_assert_failed();
}

function netcode_assert_failed(): void
{
    // frames: Error, netcode_assert_failed, netcode_assert, caller
    const frame = ( new Error().stack ?? '' ).split( '\n' )[3] ?? '';
    const match = /at (?:(.+?) \()?(.*):(\d+):\d+\)?\s*$/.exec( frame );
    // JavaScript has no #condition: the location identifies the assert
    netcode_assert_function( 'netcode_assert',
                             ( match?.[1] ?? '?' ).replace( /^Module\./, '' ),
                             match?.[2] ?? 'netcode.ts',
                             match ? parseInt( match[3], 10 ) : 0 );
}

export const PRIx64 = 'llx';

/** the subset of printf netcode uses: %% %d %s %x %f, optional .precision, ll/l length modifiers */
function netcode_format( format: string, args: unknown[] ): string
{
    let arg = 0;
    return format.replace( /%%|%(?:\.(\d+))?(?:ll|l)?([dsxuf])/g, ( match: string, precision: string | undefined, conversion: string | undefined ) =>
    {
        if ( match == '%%' )
            return '%';
        const value = args[arg++];
        switch ( conversion )
        {
            case 'd':
            case 'u':
                return typeof value == 'number' ? String( Math.trunc( value ) ) : String( value );
            case 'x':
            {
                const v = typeof value == 'bigint' ? BigInt.asUintN( 64, value ) : BigInt.asUintN( 32, BigInt( Math.trunc( Number( value ) ) ) );
                return v.toString( 16 ).padStart( precision ? parseInt( precision, 10 ) : 0, '0' );
            }
            case 'f':
                return Number( value ).toFixed( precision ? parseInt( precision, 10 ) : 6 );
            default:
                return String( value );
        }
    } );
}

export function netcode_printf( level: number, format: string, ...args: unknown[] ): void
{
    if ( !NETCODE_ENABLE_LOGGING )
        return;
    if ( level > log_level )
        return;
    printf_function( netcode_format( format, args ) );
}

export function netcode_default_allocate_function( context: unknown, bytes: number ): unknown
{
    void context;
    void bytes;
    return true;
}

export function netcode_default_free_function( context: unknown, pointer: unknown ): void
{
    void context;
    void pointer;
}

// ------------------------------------------------------------------

export class netcode_address_data_t
{
    /** ipv4 and ipv6 are views of the same 16 bytes, like the C union */
    readonly ipv4: Uint8Array;
    readonly ipv6: Uint16Array;

    constructor()
    {
        const buffer = new ArrayBuffer( 16 );
        this.ipv4 = new Uint8Array( buffer, 0, 4 );
        this.ipv6 = new Uint16Array( buffer );
    }
}

export class netcode_address_t
{
    data = new netcode_address_data_t();
    port = 0;
    type = 0;
}

/** dst = src, like C's struct assignment. netcode keeps its own copy of every address it stores */
export function netcode_address_copy( dst: netcode_address_t, src: netcode_address_t ): void
{
    dst.data.ipv6.set( src.data.ipv6 );
    dst.port = src.port;
    dst.type = src.type;
}

/** memset( address, 0, sizeof( netcode_address_t ) ) */
export function netcode_address_zero( address: netcode_address_t ): void
{
    address.data.ipv6.fill( 0 );
    address.port = 0;
    address.type = NETCODE_ADDRESS_NONE;
}

export function netcode_address_clone( address: netcode_address_t ): netcode_address_t
{
    const copy = new netcode_address_t();
    netcode_address_copy( copy, address );
    return copy;
}

function netcode_address_array( count: number ): netcode_address_t[]
{
    const array = new Array<netcode_address_t>( count );
    for ( let i = 0; i < count; i++ )
        array[i] = new netcode_address_t();
    return array;
}

function netcode_parse_port( string: string, port: { value: number } ): number
{
    // the port must be all digits and fit in [0,65535]. anything else is an error,
    // rather than whatever atoi truncation used to produce.

    if ( string.length == 0 )
        return NETCODE_ERROR;

    let value = 0;
    for ( let i = 0; i < string.length; i++ )
    {
        const c = string.charCodeAt( i );
        if ( c < 0x30 || c > 0x39 )
            return NETCODE_ERROR;
        value = value * 10 + ( c - 0x30 );
        if ( value > 65535 )
            return NETCODE_ERROR;
    }

    port.value = value;

    return NETCODE_OK;
}

function netcode_hex_digit( c: number ): number
{
    if ( c >= 0x30 && c <= 0x39 ) return c - 0x30;
    if ( c >= 0x61 && c <= 0x66 ) return c - 0x61 + 10;
    if ( c >= 0x41 && c <= 0x46 ) return c - 0x41 + 10;
    return -1;
}

/** inet_pton( AF_INET ) as glibc implements it: exactly four dotted decimal octets, no leading zeros */
function netcode_inet_pton4( src: string, dst: Uint8Array ): boolean
{
    const tmp = [ 0, 0, 0, 0 ];
    let saw_digit = false;
    let octets = 0;
    let current = 0;
    for ( let i = 0; i < src.length; i++ )
    {
        const c = src.charCodeAt( i );
        if ( c >= 0x30 && c <= 0x39 )
        {
            if ( saw_digit && tmp[current] == 0 )
                return false;
            const value = tmp[current] * 10 + ( c - 0x30 );
            if ( value > 255 )
                return false;
            tmp[current] = value;
            if ( !saw_digit )
            {
                if ( ++octets > 4 )
                    return false;
                saw_digit = true;
            }
        }
        else if ( c == 0x2E && saw_digit )
        {
            if ( octets == 4 )
                return false;
            current++;
            saw_digit = false;
        }
        else
        {
            return false;
        }
    }
    if ( octets < 4 )
        return false;
    for ( let i = 0; i < 4; i++ )
        dst[i] = tmp[i];
    return true;
}

/** inet_pton( AF_INET6 ) as glibc implements it. dst receives the eight 16 bit groups in host order */
function netcode_inet_pton6( src: string, dst: Uint16Array ): boolean
{
    const tmp = [ 0, 0, 0, 0, 0, 0, 0, 0 ];
    let tp = 0;
    let colonp = -1;
    let i = 0;
    const n = src.length;

    // leading :: requires some special handling

    if ( n > 0 && src.charCodeAt( 0 ) == 0x3A )
    {
        if ( n < 2 || src.charCodeAt( 1 ) != 0x3A )
            return false;
        i = 1;
    }

    let curtok = i;
    let saw_xdigit = false;
    let xdigits = 0;
    let value = 0;

    while ( i < n )
    {
        const c = src.charCodeAt( i++ );
        const digit = netcode_hex_digit( c );
        if ( digit >= 0 )
        {
            if ( ++xdigits > 4 )
                return false;
            value = ( value << 4 ) | digit;
            saw_xdigit = true;
            continue;
        }
        if ( c == 0x3A )
        {
            curtok = i;
            if ( !saw_xdigit )
            {
                if ( colonp != -1 )
                    return false;
                colonp = tp;
                continue;
            }
            else if ( i == n )
            {
                return false;
            }
            if ( tp + 1 > 8 )
                return false;
            tmp[tp++] = value;
            saw_xdigit = false;
            xdigits = 0;
            value = 0;
            continue;
        }
        if ( c == 0x2E && tp + 2 <= 8 )
        {
            const ipv4 = new Uint8Array( 4 );
            if ( !netcode_inet_pton4( src.substring( curtok ), ipv4 ) )
                return false;
            tmp[tp++] = ( ipv4[0] << 8 ) | ipv4[1];
            tmp[tp++] = ( ipv4[2] << 8 ) | ipv4[3];
            saw_xdigit = false;
            break;
        }
        return false;
    }

    if ( saw_xdigit )
    {
        if ( tp + 1 > 8 )
            return false;
        tmp[tp++] = value;
    }

    if ( colonp != -1 )
    {
        // shift the groups after the :: to the end. a :: that stands for no group at all is an error

        if ( tp == 8 )
            return false;
        const nmove = tp - colonp;
        for ( let j = 1; j <= nmove; j++ )
        {
            tmp[8 - j] = tmp[colonp + nmove - j];
            tmp[colonp + nmove - j] = 0;
        }
        tp = 8;
    }

    if ( tp != 8 )
        return false;

    for ( let j = 0; j < 8; j++ )
        dst[j] = tmp[j];

    return true;
}

/** inet_ntop( AF_INET6 ): the longest run of two or more zero groups becomes ::, embedded ipv4 where inet_ntop prints it */
function netcode_inet_ntop6( words: Uint16Array ): string
{
    let best_base = -1, best_len = 0;
    let cur_base = -1, cur_len = 0;
    for ( let i = 0; i < 8; i++ )
    {
        if ( words[i] == 0 )
        {
            if ( cur_base == -1 )
            {
                cur_base = i;
                cur_len = 1;
            }
            else
            {
                cur_len++;
            }
        }
        else if ( cur_base != -1 )
        {
            if ( best_base == -1 || cur_len > best_len )
            {
                best_base = cur_base;
                best_len = cur_len;
            }
            cur_base = -1;
        }
    }
    if ( cur_base != -1 && ( best_base == -1 || cur_len > best_len ) )
    {
        best_base = cur_base;
        best_len = cur_len;
    }
    if ( best_base != -1 && best_len < 2 )
        best_base = -1;

    let result = '';
    for ( let i = 0; i < 8; i++ )
    {
        if ( best_base != -1 && i >= best_base && i < best_base + best_len )
        {
            if ( i == best_base )
                result += ':';
            continue;
        }
        if ( i != 0 )
            result += ':';
        if ( i == 6 && best_base == 0 && ( best_len == 6 || ( best_len == 5 && words[5] == 0xFFFF ) ) )
        {
            result += ( words[6] >>> 8 ) + '.' + ( words[6] & 0xFF ) + '.' + ( words[7] >>> 8 ) + '.' + ( words[7] & 0xFF );
            return result;
        }
        result += words[i].toString( 16 );
    }
    if ( best_base != -1 && best_base + best_len == 8 )
        result += ':';
    return result;
}

export function netcode_parse_address( address_string_in: string, address: netcode_address_t ): number
{
    netcode_assert( address_string_in != null );
    netcode_assert( address );

    netcode_address_zero( address );

    if ( address_string_in == null )
        return NETCODE_ERROR;

    // first try to parse the string as an IPv6 address:
    // 1. if the first character is '[' then it's probably an ipv6 in form "[addr6]:portnum"
    // 2. otherwise try to parse as a raw IPv6 address using inet_pton

    let address_string = address_string_in;
    const terminator = address_string.indexOf( '\0' );
    if ( terminator >= 0 )
        address_string = address_string.substring( 0, terminator );
    if ( address_string.length > NETCODE_MAX_ADDRESS_STRING_LENGTH - 1 )
        address_string = address_string.substring( 0, NETCODE_MAX_ADDRESS_STRING_LENGTH - 1 );

    let address_string_length = address_string.length;

    const port = { value: 0 };

    if ( address_string_length > 0 && address_string[0] == '[' )
    {
        const base_index = address_string_length - 1;

        let end = address_string_length;

        for ( let i = 0; i < 6; i++ )         // note: no need to search past 6 characters as ":65535" is longest possible port value
        {
            const index = base_index - i;
            if ( index < 3 )
                break;
            if ( address_string[index] == ':' && address_string[index - 1] == ']' )
            {
                if ( netcode_parse_port( address_string.substring( index + 1 ), port ) != NETCODE_OK )
                    return NETCODE_ERROR;
                address.port = port.value;
                end = index - 1;
                break;
            }
        }

        // if a port is omitted, it is assumed to be zero. strip the trailing ']' so "[addr]" parses as just the address

        if ( end == address_string_length && address_string[base_index] == ']' )
            end = base_index;

        address_string = address_string.substring( 1, Math.max( 1, end ) );
    }

    if ( netcode_inet_pton6( address_string, address.data.ipv6 ) )
    {
        address.type = NETCODE_ADDRESS_IPV6;
        return NETCODE_OK;
    }

    // otherwise it's probably an IPv4 address:
    // 1. look for ":portnum", if found save the portnum and strip it out
    // 2. parse remaining ipv4 address via inet_pton

    address.data.ipv6.fill( 0 );

    address_string_length = address_string.length;
    const base_index = address_string_length - 1;
    for ( let i = 0; i < 6; i++ )
    {
        const index = base_index - i;
        if ( index < 0 )
            break;
        if ( address_string[index] == ':' )
        {
            if ( netcode_parse_port( address_string.substring( index + 1 ), port ) != NETCODE_OK )
                return NETCODE_ERROR;
            address.port = port.value;
            address_string = address_string.substring( 0, index );
            break;
        }
    }

    if ( netcode_inet_pton4( address_string, address.data.ipv4 ) )
    {
        address.type = NETCODE_ADDRESS_IPV4;
        return NETCODE_OK;
    }

    return NETCODE_ERROR;
}

/**
    Returns the address in its printable form, at most NETCODE_MAX_ADDRESS_STRING_LENGTH-1 characters.
    (C writes it into a caller supplied buffer and returns the buffer.)
*/
export function netcode_address_to_string( address: netcode_address_t ): string
{
    netcode_assert( address );

    let result: string;

    if ( address.type == NETCODE_ADDRESS_IPV6 )
    {
        const address_string = netcode_inet_ntop6( address.data.ipv6 );
        result = address.port == 0 ? address_string : '[' + address_string + ']:' + address.port;
    }
    else if ( address.type == NETCODE_ADDRESS_IPV4 )
    {
        const ipv4 = address.data.ipv4;
        result = ipv4[0] + '.' + ipv4[1] + '.' + ipv4[2] + '.' + ipv4[3];
        if ( address.port != 0 )
            result += ':' + address.port;
    }
    else
    {
        result = 'NONE';
    }

    return result.length < NETCODE_MAX_ADDRESS_STRING_LENGTH ? result : result.substring( 0, NETCODE_MAX_ADDRESS_STRING_LENGTH - 1 );
}

export function netcode_address_equal( a: netcode_address_t, b: netcode_address_t ): number
{
    netcode_assert( a );
    netcode_assert( b );

    if ( a.type != b.type )
        return 0;

    if ( a.port != b.port )
        return 0;

    if ( a.type == NETCODE_ADDRESS_IPV4 )
    {
        for ( let i = 0; i < 4; i++ )
        {
            if ( a.data.ipv4[i] != b.data.ipv4[i] )
                return 0;
        }
    }
    else if ( a.type == NETCODE_ADDRESS_IPV6 )
    {
        for ( let i = 0; i < 8; i++ )
        {
            if ( a.data.ipv6[i] != b.data.ipv6[i] )
                return 0;
        }
    }
    else
    {
        return 0;
    }

    return 1;
}

// ----------------------------------------------------------------

class netcode_t
{
    initialized = 0;
}

const netcode = new netcode_t();

export function netcode_init(): number
{
    // reference counted so multiple subsystems in the same application can call
    // netcode_init and netcode_term independently

    if ( netcode.initialized )
    {
        netcode.initialized++;
        return NETCODE_OK;
    }

    if ( sodium_init() == -1 )
        return NETCODE_ERROR;

    netcode.initialized = 1;

    return NETCODE_OK;
}

export function netcode_term(): void
{
    netcode_assert( netcode.initialized );

    if ( !netcode.initialized )
        return;

    netcode.initialized--;
}

// ----------------------------------------------------------------

/*
    Platform seam: UDP sockets. Only the members of Node's dgram module that netcode uses, typed
    structurally so this file needs no Node types and loads unchanged in a browser.
*/

interface netcode_udp_remote_info_t
{
    address: string;
    family: string | number;
    port: number;
}

interface netcode_udp_handle_t
{
    bind( options: { address: string, port: number, exclusive: boolean } ): unknown;
    send( msg: Uint8Array, port: number, address: string, callback: ( error: Error | null ) => void ): void;
    close(): unknown;
    on( event: string, listener: ( ...args: never[] ) => void ): unknown;
    address(): { address: string, family: string, port: number };
    setRecvBufferSize( size: number ): void;
    setSendBufferSize( size: number ): void;
    setTOS?: ( tos: number ) => void;
}

interface netcode_dgram_t
{
    createSocket( options: { type: 'udp4' | 'udp6', ipv6Only?: boolean, lookup?: unknown } ): netcode_udp_handle_t;
}

let netcode_dgram: netcode_dgram_t | null | undefined = undefined;

function netcode_get_dgram(): netcode_dgram_t | null
{
    if ( netcode_dgram === undefined )
    {
        let dgram: unknown = undefined;
        try
        {
            dgram = netcode_process()?.getBuiltinModule?.( 'node:dgram' );
        }
        catch
        {
            dgram = undefined;
        }
        netcode_dgram = dgram ? dgram as netcode_dgram_t : null;
    }
    return netcode_dgram;
}

class netcode_socket_datagram_t
{
    data: Uint8Array;
    from: netcode_address_t;

    constructor( data: Uint8Array, from: netcode_address_t )
    {
        this.data = data;
        this.from = from;
    }
}

export class netcode_socket_t
{
    address = new netcode_address_t();
    /** the dgram socket, or null. C: the socket handle, 0 when there is none */
    handle: netcode_udp_handle_t | null = null;
    /** last asynchronous socket error, if any (see the porting notes on bind) */
    error: string | null = null;
    // datagrams received from 'message' events, waiting for netcode_socket_receive_packet
    receive_queue: netcode_socket_datagram_t[] = [];
    receive_queue_start = 0;
    receive_queue_bytes = 0;
    receive_queue_max_bytes = 0;
    num_receive_packets_dropped = 0;
    // destination string cache for sends
    send_address = new netcode_address_t();
    send_address_string = '';
    // bind progress, from the 'listening' and 'error' events
    bound = false;
    bind_pending = false;
    bind_error: Error | null = null;
}

export class netcode_socket_holder_t
{
    ipv4 = new netcode_socket_t();
    ipv6 = new netcode_socket_t();
}

export const NETCODE_SOCKET_ERROR_NONE = 0;
export const NETCODE_SOCKET_ERROR_CREATE_FAILED = 1;
export const NETCODE_SOCKET_ERROR_SET_NON_BLOCKING_FAILED = 2;
export const NETCODE_SOCKET_ERROR_SOCKOPT_IPV6_ONLY_FAILED = 3;
export const NETCODE_SOCKET_ERROR_SOCKOPT_RCVBUF_FAILED = 4;
export const NETCODE_SOCKET_ERROR_SOCKOPT_SNDBUF_FAILED = 5;
export const NETCODE_SOCKET_ERROR_BIND_IPV4_FAILED = 6;
export const NETCODE_SOCKET_ERROR_BIND_IPV6_FAILED = 7;
export const NETCODE_SOCKET_ERROR_GET_SOCKNAME_IPV4_FAILED = 8;
export const NETCODE_SOCKET_ERROR_GET_SOCKNAME_IPV6_FAILED = 9;
export const NETCODE_SOCKET_ERROR_DISABLE_UDP_PORT_CONNRESET_FAILED = 10;
export const NETCODE_SOCKET_ERROR_ENABLE_PACKET_TAGGING_FAILED = 11;

function netcode_socket_clear_receive_queue( socket: netcode_socket_t ): void
{
    socket.receive_queue = [];
    socket.receive_queue_start = 0;
    socket.receive_queue_bytes = 0;
}

export function netcode_socket_destroy( socket: netcode_socket_t ): void
{
    netcode_assert( socket );
    netcode_assert( netcode.initialized );

    if ( socket.handle !== null )
    {
        const handle = socket.handle;
        socket.handle = null;
        try
        {
            handle.close();
        }
        catch
        {
            // already closed
        }
    }

    netcode_socket_clear_receive_queue( socket );
}

/** the numeric host of an address without port or brackets, as dgram takes it */
function netcode_address_to_host_string( address: netcode_address_t ): string
{
    if ( address.type == NETCODE_ADDRESS_IPV6 )
        return netcode_inet_ntop6( address.data.ipv6 );
    const ipv4 = address.data.ipv4;
    return ipv4[0] + '.' + ipv4[1] + '.' + ipv4[2] + '.' + ipv4[3];
}

/** fills address from a dgram host string and port. returns NETCODE_OK or NETCODE_ERROR */
function netcode_host_string_to_address( host: string, port: number, address: netcode_address_t ): number
{
    netcode_address_zero( address );
    if ( host.indexOf( ':' ) >= 0 )
    {
        const zone = host.indexOf( '%' );
        if ( !netcode_inet_pton6( zone >= 0 ? host.substring( 0, zone ) : host, address.data.ipv6 ) )
            return NETCODE_ERROR;
        address.type = NETCODE_ADDRESS_IPV6;
    }
    else
    {
        if ( !netcode_inet_pton4( host, address.data.ipv4 ) )
            return NETCODE_ERROR;
        address.type = NETCODE_ADDRESS_IPV4;
    }
    address.port = port;
    return NETCODE_OK;
}

/*
    dgram resolves the bind address through this lookup function. netcode only binds numeric addresses,
    and answering synchronously makes bind() complete -- or emit its error -- before it returns, which is
    what lets netcode_socket_create report a bind failure synchronously, like C.
*/

function netcode_socket_lookup( address: string, family: unknown, callback: ( error: Error | null, address: string, family: number ) => void ): void
{
    callback( null, address, typeof family == 'number' ? family : ( address.indexOf( ':' ) >= 0 ? 6 : 4 ) );
}

function netcode_socket_send_callback( error: Error | null ): void
{
    if ( error )
        netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "socket send failed: %s\n", error.message );
}

function netcode_socket_on_message( socket: netcode_socket_t, handle: netcode_udp_handle_t, data: Uint8Array, remote: netcode_udp_remote_info_t ): void
{
    if ( socket.handle !== handle )
        return;

    if ( data.length == 0 )
        return;

    if ( socket.receive_queue_bytes + data.length > socket.receive_queue_max_bytes )
    {
        // the receive buffer is full: drop the datagram, as the kernel does

        socket.num_receive_packets_dropped++;
        return;
    }

    const from = new netcode_address_t();
    if ( netcode_host_string_to_address( remote.address, remote.port, from ) != NETCODE_OK )
        return;

    socket.receive_queue.push( new netcode_socket_datagram_t( data, from ) );
    socket.receive_queue_bytes += data.length;
}

function netcode_socket_on_error( socket: netcode_socket_t, handle: netcode_udp_handle_t, error: Error ): void
{
    if ( socket.handle !== handle )
        return;

    if ( !socket.bound )
    {
        // bind failed. synchronously inside netcode_socket_create, or (fallback) later

        socket.bind_error = error;
        if ( socket.bind_pending )
        {
            socket.error = error.message;
            netcode_printf( NETCODE_LOG_LEVEL_ERROR, "error: failed to bind socket (%s): %s\n", socket.address.type == NETCODE_ADDRESS_IPV6 ? "ipv6" : "ipv4", error.message );
        }
        return;
    }

    socket.error = error.message;
    netcode_printf( NETCODE_LOG_LEVEL_ERROR, "error: socket error: %s\n", error.message );
}

function netcode_socket_on_listening( socket: netcode_socket_t, handle: netcode_udp_handle_t ): void
{
    if ( socket.handle !== handle )
        return;

    socket.bound = true;
    socket.bind_pending = false;

    if ( socket.address.port == 0 )
    {
        try
        {
            socket.address.port = handle.address().port;
        }
        catch
        {
            // keep zero
        }
    }
}

function netcode_socket_set_buffer_size( handle: netcode_udp_handle_t, send: boolean, requested_size: number ): number
{
    // increase socket send and receive buffer sizes. linux and windows clamp requests that
    // exceed the OS limit, but the BSDs reject them instead, so back off until accepted.

    let size = requested_size;
    while ( true )
    {
        try
        {
            if ( send )
                handle.setSendBufferSize( size );
            else
                handle.setRecvBufferSize( size );
            return size;
        }
        catch
        {
            size = Math.floor( size / 2 );
            if ( size < 256 * 1024 )
                return -1;
        }
    }
}

export function netcode_socket_create( s: netcode_socket_t, address: netcode_address_t, send_buffer_size: number, receive_buffer_size: number ): number
{
    netcode_assert( s );
    netcode_assert( address );
    netcode_assert( netcode.initialized );

    netcode_assert( address.type != NETCODE_ADDRESS_NONE );

    netcode_address_copy( s.address, address );

    netcode_socket_clear_receive_queue( s );
    s.receive_queue_max_bytes = 0;
    s.num_receive_packets_dropped = 0;
    s.error = null;
    s.bound = false;
    s.bind_pending = false;
    s.bind_error = null;
    netcode_address_zero( s.send_address );
    s.send_address_string = '';

    const ipv6 = address.type == NETCODE_ADDRESS_IPV6;

    // create socket. IPV6_V6ONLY is a socket option of dgram's, applied when it binds

    const dgram = netcode_get_dgram();

    let handle: netcode_udp_handle_t | null = null;

    if ( dgram )
    {
        try
        {
            handle = dgram.createSocket( { type: ipv6 ? 'udp6' : 'udp4', ipv6Only: ipv6, lookup: netcode_socket_lookup } );
        }
        catch
        {
            handle = null;
        }
    }

    if ( !handle )
    {
        netcode_printf( NETCODE_LOG_LEVEL_ERROR, dgram ? "error: failed to create socket\n" : "error: failed to create socket (no udp sockets on this platform)\n" );
        s.handle = null;
        return NETCODE_SOCKET_ERROR_CREATE_FAILED;
    }

    const created_handle = handle;

    s.handle = created_handle;

    created_handle.on( 'error', ( error: Error ) => netcode_socket_on_error( s, created_handle, error ) );
    created_handle.on( 'listening', () => netcode_socket_on_listening( s, created_handle ) );
    created_handle.on( 'message', ( data: Uint8Array, remote: netcode_udp_remote_info_t ) => netcode_socket_on_message( s, created_handle, data, remote ) );

    // bind to port. this completes synchronously (see netcode_socket_lookup)

    try
    {
        created_handle.bind( { address: netcode_address_to_host_string( address ), port: address.port, exclusive: true } );
    }
    catch ( error )
    {
        s.bind_error = error instanceof Error ? error : new Error( String( error ) );
    }

    if ( s.bind_error !== null )
    {
        netcode_printf( NETCODE_LOG_LEVEL_ERROR, "error: failed to bind socket (%s)\n", ipv6 ? "ipv6" : "ipv4" );
        netcode_socket_destroy( s );
        return ipv6 ? NETCODE_SOCKET_ERROR_BIND_IPV6_FAILED : NETCODE_SOCKET_ERROR_BIND_IPV4_FAILED;
    }

    if ( !s.bound )
    {
        // fallback for a runtime that binds asynchronously: keep the socket. 'listening' fills in the
        // port, and a late bind error is recorded in s.error and logged

        netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "socket bind is pending (%s)\n", ipv6 ? "ipv6" : "ipv4" );
        s.receive_queue_max_bytes = receive_buffer_size;
        s.bind_pending = true;
        return NETCODE_SOCKET_ERROR_NONE;
    }

    // increase socket send and receive buffer sizes (after bind: dgram sets them on a bound socket)

    {
        const size = netcode_socket_set_buffer_size( created_handle, true, send_buffer_size );
        if ( size < 0 )
        {
            netcode_printf( NETCODE_LOG_LEVEL_ERROR, "error: failed to set socket send buffer size\n" );
            netcode_socket_destroy( s );
            return NETCODE_SOCKET_ERROR_SOCKOPT_SNDBUF_FAILED;
        }
        if ( size != send_buffer_size )
        {
            netcode_printf( NETCODE_LOG_LEVEL_INFO, "socket send buffer size reduced from %d to %d\n", send_buffer_size, size );
        }
    }

    {
        const size = netcode_socket_set_buffer_size( created_handle, false, receive_buffer_size );
        if ( size < 0 )
        {
            netcode_printf( NETCODE_LOG_LEVEL_ERROR, "error: failed to set socket receive buffer size\n" );
            netcode_socket_destroy( s );
            return NETCODE_SOCKET_ERROR_SOCKOPT_RCVBUF_FAILED;
        }
        if ( size != receive_buffer_size )
        {
            netcode_printf( NETCODE_LOG_LEVEL_INFO, "socket receive buffer size reduced from %d to %d\n", receive_buffer_size, size );
        }
        s.receive_queue_max_bytes = size;
    }

    // if bound to port 0 find the actual port we got

    if ( address.port == 0 )
    {
        let port = -1;
        try
        {
            port = created_handle.address().port;
        }
        catch
        {
            port = -1;
        }

        if ( port <= 0 )
        {
            netcode_printf( NETCODE_LOG_LEVEL_ERROR, "error: failed to get socket port (%s)\n", ipv6 ? "ipv6" : "ipv4" );
            netcode_socket_destroy( s );
            return ipv6 ? NETCODE_SOCKET_ERROR_GET_SOCKNAME_IPV6_FAILED : NETCODE_SOCKET_ERROR_GET_SOCKNAME_IPV4_FAILED;
        }

        s.address.port = port;
    }

    // dgram sockets never block, so there is no non-blocking mode to set

    // tag packets as low latency. dgram has no IP_TOS / IPV6_TCLASS; use setTOS where the runtime has one

    if ( NETCODE_PACKET_TAGGING && netcode_packet_tagging_enabled && typeof created_handle.setTOS == 'function' )
    {
        try
        {
            created_handle.setTOS( 46 );
        }
        catch
        {
            netcode_printf( NETCODE_LOG_LEVEL_ERROR, "error: failed to enable packet tagging (%s)\n", ipv6 ? "ipv6" : "ipv4" );
            netcode_socket_destroy( s );
            return NETCODE_SOCKET_ERROR_ENABLE_PACKET_TAGGING_FAILED;
        }
    }

    return NETCODE_SOCKET_ERROR_NONE;
}

export function netcode_socket_send_packet( socket: netcode_socket_t, to: netcode_address_t, packet_data: Uint8Array, packet_bytes: number ): void
{
    netcode_assert( socket );
    netcode_assert( socket.handle !== null );
    netcode_assert( to );
    netcode_assert( to.type == NETCODE_ADDRESS_IPV6 || to.type == NETCODE_ADDRESS_IPV4 );
    netcode_assert( packet_data );
    netcode_assert( packet_bytes > 0 );

    const handle = socket.handle;

    if ( handle === null || socket.bind_error !== null )
        return;

    if ( !netcode_address_equal( socket.send_address, to ) )
    {
        netcode_address_copy( socket.send_address, to );
        socket.send_address_string = netcode_address_to_host_string( to );
    }

    // fire and forget, like sendto with its result ignored. the copy is because dgram may send after
    // returning, and the caller reuses packet_data

    try
    {
        handle.send( packet_data.slice( 0, packet_bytes ), to.port, socket.send_address_string, netcode_socket_send_callback );
    }
    catch ( error )
    {
        netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "socket send failed: %s\n", String( error ) );
    }
}

export function netcode_socket_receive_packet( socket: netcode_socket_t, from: netcode_address_t, packet_data: Uint8Array, max_packet_size: number ): number
{
    netcode_assert( socket );
    netcode_assert( socket.handle !== null );
    netcode_assert( from );
    netcode_assert( packet_data );
    netcode_assert( max_packet_size > 0 );

    if ( socket.receive_queue_start >= socket.receive_queue.length )
        return 0;

    const datagram = socket.receive_queue[socket.receive_queue_start++];

    socket.receive_queue_bytes -= datagram.data.length;

    if ( socket.receive_queue_start == socket.receive_queue.length )
    {
        socket.receive_queue = [];
        socket.receive_queue_start = 0;
    }
    else if ( socket.receive_queue_start >= 1024 )
    {
        socket.receive_queue = socket.receive_queue.slice( socket.receive_queue_start );
        socket.receive_queue_start = 0;
    }

    // a datagram longer than the buffer is truncated, as recvfrom truncates it

    const bytes_read = Math.min( datagram.data.length, max_packet_size, packet_data.length );

    packet_data.set( datagram.data.subarray( 0, bytes_read ) );

    netcode_address_copy( from, datagram.from );

    return bytes_read;
}

// ----------------------------------------------------------------

/** a position in a byte buffer, like the C uint8_t ** the read and write functions take */
export class netcode_pointer_t
{
    buffer: Uint8Array;
    offset: number;

    constructor( buffer: Uint8Array, offset = 0 )
    {
        this.buffer = buffer;
        this.offset = offset;
    }
}

export function netcode_write_uint8( p: netcode_pointer_t, value: number ): void
{
    p.buffer[p.offset] = value & 0xFF;
    p.offset += 1;
}

export function netcode_write_uint16( p: netcode_pointer_t, value: number ): void
{
    const b = p.buffer, o = p.offset;
    b[o] = value & 0xFF;
    b[o + 1] = ( value >>> 8 ) & 0xFF;
    p.offset += 2;
}

export function netcode_write_uint32( p: netcode_pointer_t, value: number ): void
{
    const b = p.buffer, o = p.offset;
    b[o] = value & 0xFF;
    b[o + 1] = ( value >>> 8 ) & 0xFF;
    b[o + 2] = ( value >>> 16 ) & 0xFF;
    b[o + 3] = ( value >>> 24 ) & 0xFF;
    p.offset += 4;
}

export function netcode_write_uint64( p: netcode_pointer_t, value: bigint ): void
{
    const v = BigInt.asUintN( 64, value );
    netcode_write_uint32( p, Number( v & 0xFFFFFFFFn ) );
    netcode_write_uint32( p, Number( v >> 32n ) );
}

export function netcode_write_bytes( p: netcode_pointer_t, byte_array: Uint8Array, num_bytes: number ): void
{
    p.buffer.set( byte_array.subarray( 0, num_bytes ), p.offset );
    p.offset += num_bytes;
}

export function netcode_read_uint8( p: netcode_pointer_t ): number
{
    const value = p.buffer[p.offset];
    p.offset += 1;
    return value;
}

export function netcode_read_uint16( p: netcode_pointer_t ): number
{
    const b = p.buffer, o = p.offset;
    const value = b[o] | ( b[o + 1] << 8 );
    p.offset += 2;
    return value;
}

export function netcode_read_uint32( p: netcode_pointer_t ): number
{
    const b = p.buffer, o = p.offset;
    const value = ( b[o] | ( b[o + 1] << 8 ) | ( b[o + 2] << 16 ) | ( b[o + 3] << 24 ) ) >>> 0;
    p.offset += 4;
    return value;
}

export function netcode_read_uint64( p: netcode_pointer_t ): bigint
{
    const low = netcode_read_uint32( p );
    const high = netcode_read_uint32( p );
    return ( BigInt( high ) << 32n ) | BigInt( low );
}

export function netcode_read_bytes( p: netcode_pointer_t, byte_array: Uint8Array, num_bytes: number ): void
{
    byte_array.set( p.buffer.subarray( p.offset, p.offset + num_bytes ) );
    p.offset += num_bytes;
}

// ----------------------------------------------------------------

export function netcode_generate_key( key: Uint8Array ): void
{
    netcode_assert( key );
    randombytes_buf( key, NETCODE_KEY_BYTES );
}

export function netcode_generate_nonce( nonce: Uint8Array ): void
{
    netcode_assert( nonce );
    randombytes_buf( nonce, NETCODE_CONNECT_TOKEN_NONCE_BYTES );
}

export function netcode_random_bytes( data: Uint8Array, bytes: number ): void
{
    netcode_assert( data );
    netcode_assert( bytes > 0 );
    randombytes_buf( data, bytes );
}

const netcode_aead_length: sodium_length_out = { value: 0 };

/** message is encrypted in place: it starts at message[0] and needs NETCODE_MAC_BYTES of room after it for the tag */
export function netcode_encrypt_aead_bignonce( message: Uint8Array, message_length: number,
                                               additional: Uint8Array | null, additional_length: number,
                                               nonce: Uint8Array,
                                               key: Uint8Array ): number
{
    const result = crypto_aead_xchacha20poly1305_ietf_encrypt( message, netcode_aead_length,
                                                               message, message_length,
                                                               additional, additional_length,
                                                               null, nonce, key );

    if ( result != 0 )
        return NETCODE_ERROR;

    netcode_assert( netcode_aead_length.value == message_length + NETCODE_MAC_BYTES );

    return NETCODE_OK;
}

export function netcode_decrypt_aead_bignonce( message: Uint8Array, message_length: number,
                                               additional: Uint8Array | null, additional_length: number,
                                               nonce: Uint8Array,
                                               key: Uint8Array ): number
{
    const result = crypto_aead_xchacha20poly1305_ietf_decrypt( message, netcode_aead_length,
                                                               null,
                                                               message, message_length,
                                                               additional, additional_length,
                                                               nonce, key );

    if ( result != 0 )
        return NETCODE_ERROR;

    netcode_assert( netcode_aead_length.value == message_length - NETCODE_MAC_BYTES );

    return NETCODE_OK;
}

export function netcode_encrypt_aead( message: Uint8Array, message_length: number,
                                      additional: Uint8Array | null, additional_length: number,
                                      nonce: Uint8Array,
                                      key: Uint8Array ): number
{
    const result = crypto_aead_chacha20poly1305_ietf_encrypt( message, netcode_aead_length,
                                                              message, message_length,
                                                              additional, additional_length,
                                                              null, nonce, key );

    if ( result != 0 )
        return NETCODE_ERROR;

    netcode_assert( netcode_aead_length.value == message_length + NETCODE_MAC_BYTES );

    return NETCODE_OK;
}

export function netcode_decrypt_aead( message: Uint8Array, message_length: number,
                                      additional: Uint8Array | null, additional_length: number,
                                      nonce: Uint8Array,
                                      key: Uint8Array ): number
{
    const result = crypto_aead_chacha20poly1305_ietf_decrypt( message, netcode_aead_length,
                                                              null,
                                                              message, message_length,
                                                              additional, additional_length,
                                                              nonce, key );

    if ( result != 0 )
        return NETCODE_ERROR;

    netcode_assert( netcode_aead_length.value == message_length - NETCODE_MAC_BYTES );

    return NETCODE_OK;
}

// ----------------------------------------------------------------

export class netcode_connect_token_private_t
{
    client_id = 0n;
    timeout_seconds = 0;
    num_server_addresses = 0;
    server_addresses: netcode_address_t[] = netcode_address_array( NETCODE_MAX_SERVERS_PER_CONNECT );
    client_to_server_key = new Uint8Array( NETCODE_KEY_BYTES );
    server_to_client_key = new Uint8Array( NETCODE_KEY_BYTES );
    user_data = new Uint8Array( NETCODE_USER_DATA_BYTES );
}

export function netcode_generate_connect_token_private( connect_token: netcode_connect_token_private_t,
                                                        client_id: bigint,
                                                        timeout_seconds: number,
                                                        num_server_addresses: number,
                                                        server_addresses: netcode_address_t[],
                                                        user_data: Uint8Array | null ): void
{
    netcode_assert( connect_token );
    netcode_assert( num_server_addresses > 0 );
    netcode_assert( num_server_addresses <= NETCODE_MAX_SERVERS_PER_CONNECT );
    netcode_assert( server_addresses );
    netcode_assert( user_data );

    connect_token.client_id = BigInt.asUintN( 64, client_id );
    connect_token.timeout_seconds = timeout_seconds | 0;
    connect_token.num_server_addresses = num_server_addresses;

    for ( let i = 0; i < num_server_addresses; i++ )
    {
        netcode_address_copy( connect_token.server_addresses[i], server_addresses[i] );
    }

    netcode_generate_key( connect_token.client_to_server_key );
    netcode_generate_key( connect_token.server_to_client_key );

    if ( user_data != null )
    {
        connect_token.user_data.set( user_data.subarray( 0, NETCODE_USER_DATA_BYTES ) );
    }
    else
    {
        connect_token.user_data.fill( 0 );
    }
}

export function netcode_write_connect_token_private( connect_token: netcode_connect_token_private_t, buffer: Uint8Array, buffer_length: number ): void
{
    netcode_assert( connect_token );
    netcode_assert( connect_token.num_server_addresses > 0 );
    netcode_assert( connect_token.num_server_addresses <= NETCODE_MAX_SERVERS_PER_CONNECT );
    netcode_assert( buffer );
    netcode_assert( buffer_length >= NETCODE_CONNECT_TOKEN_PRIVATE_BYTES );

    const p = new netcode_pointer_t( buffer );

    netcode_write_uint64( p, connect_token.client_id );

    netcode_write_uint32( p, connect_token.timeout_seconds );

    netcode_write_uint32( p, connect_token.num_server_addresses );

    for ( let i = 0; i < connect_token.num_server_addresses; i++ )
    {
        const server_address = connect_token.server_addresses[i];

        if ( server_address.type == NETCODE_ADDRESS_IPV4 )
        {
            netcode_write_uint8( p, NETCODE_ADDRESS_IPV4 );
            for ( let j = 0; j < 4; j++ )
            {
                netcode_write_uint8( p, server_address.data.ipv4[j] );
            }
            netcode_write_uint16( p, server_address.port );
        }
        else if ( server_address.type == NETCODE_ADDRESS_IPV6 )
        {
            netcode_write_uint8( p, NETCODE_ADDRESS_IPV6 );
            for ( let j = 0; j < 8; j++ )
            {
                netcode_write_uint16( p, server_address.data.ipv6[j] );
            }
            netcode_write_uint16( p, server_address.port );
        }
        else
        {
            netcode_assert( 0 );
        }
    }

    netcode_write_bytes( p, connect_token.client_to_server_key, NETCODE_KEY_BYTES );

    netcode_write_bytes( p, connect_token.server_to_client_key, NETCODE_KEY_BYTES );

    netcode_write_bytes( p, connect_token.user_data, NETCODE_USER_DATA_BYTES );

    netcode_assert( p.offset <= NETCODE_CONNECT_TOKEN_PRIVATE_BYTES - NETCODE_MAC_BYTES );

    buffer.fill( 0, p.offset, NETCODE_CONNECT_TOKEN_PRIVATE_BYTES );
}

export function netcode_encrypt_connect_token_private( buffer: Uint8Array,
                                                       buffer_length: number,
                                                       version_info: Uint8Array,
                                                       protocol_id: bigint,
                                                       expire_timestamp: bigint,
                                                       nonce: Uint8Array,
                                                       key: Uint8Array ): number
{
    netcode_assert( buffer );
    netcode_assert( buffer_length == NETCODE_CONNECT_TOKEN_PRIVATE_BYTES );
    netcode_assert( key );

    const additional_data = new Uint8Array( NETCODE_VERSION_INFO_BYTES + 8 + 8 );
    {
        const p = new netcode_pointer_t( additional_data );
        netcode_write_bytes( p, version_info, NETCODE_VERSION_INFO_BYTES );
        netcode_write_uint64( p, protocol_id );
        netcode_write_uint64( p, expire_timestamp );
    }

    return netcode_encrypt_aead_bignonce( buffer, NETCODE_CONNECT_TOKEN_PRIVATE_BYTES - NETCODE_MAC_BYTES, additional_data, additional_data.length, nonce, key );
}

export function netcode_decrypt_connect_token_private( buffer: Uint8Array,
                                                       buffer_length: number,
                                                       version_info: Uint8Array,
                                                       protocol_id: bigint,
                                                       expire_timestamp: bigint,
                                                       nonce: Uint8Array,
                                                       key: Uint8Array ): number
{
    netcode_assert( buffer );
    netcode_assert( buffer_length == NETCODE_CONNECT_TOKEN_PRIVATE_BYTES );
    netcode_assert( key );

    const additional_data = new Uint8Array( NETCODE_VERSION_INFO_BYTES + 8 + 8 );
    {
        const p = new netcode_pointer_t( additional_data );
        netcode_write_bytes( p, version_info, NETCODE_VERSION_INFO_BYTES );
        netcode_write_uint64( p, protocol_id );
        netcode_write_uint64( p, expire_timestamp );
    }

    return netcode_decrypt_aead_bignonce( buffer, NETCODE_CONNECT_TOKEN_PRIVATE_BYTES, additional_data, additional_data.length, nonce, key );
}

export function netcode_read_connect_token_private( buffer: Uint8Array, buffer_length: number, connect_token: netcode_connect_token_private_t ): number
{
    netcode_assert( buffer );
    netcode_assert( connect_token );

    if ( buffer_length < NETCODE_CONNECT_TOKEN_PRIVATE_BYTES || buffer.length < NETCODE_CONNECT_TOKEN_PRIVATE_BYTES )
        return NETCODE_ERROR;

    const p = new netcode_pointer_t( buffer );

    connect_token.client_id = netcode_read_uint64( p );

    connect_token.timeout_seconds = netcode_read_uint32( p ) | 0;

    connect_token.num_server_addresses = netcode_read_uint32( p ) | 0;

    if ( connect_token.num_server_addresses <= 0 )
        return NETCODE_ERROR;

    if ( connect_token.num_server_addresses > NETCODE_MAX_SERVERS_PER_CONNECT )
        return NETCODE_ERROR;

    for ( let i = 0; i < connect_token.num_server_addresses; i++ )
    {
        const server_address = connect_token.server_addresses[i];

        server_address.type = netcode_read_uint8( p );

        if ( server_address.type == NETCODE_ADDRESS_IPV4 )
        {
            for ( let j = 0; j < 4; j++ )
            {
                server_address.data.ipv4[j] = netcode_read_uint8( p );
            }
            server_address.port = netcode_read_uint16( p );
        }
        else if ( server_address.type == NETCODE_ADDRESS_IPV6 )
        {
            for ( let j = 0; j < 8; j++ )
            {
                server_address.data.ipv6[j] = netcode_read_uint16( p );
            }
            server_address.port = netcode_read_uint16( p );
        }
        else
        {
            return NETCODE_ERROR;
        }
    }

    netcode_read_bytes( p, connect_token.client_to_server_key, NETCODE_KEY_BYTES );

    netcode_read_bytes( p, connect_token.server_to_client_key, NETCODE_KEY_BYTES );

    netcode_read_bytes( p, connect_token.user_data, NETCODE_USER_DATA_BYTES );

    return NETCODE_OK;
}

// -----------------------------------------------

export class netcode_challenge_token_t
{
    client_id = 0n;
    user_data = new Uint8Array( NETCODE_USER_DATA_BYTES );
}

export function netcode_write_challenge_token( challenge_token: netcode_challenge_token_t, buffer: Uint8Array, buffer_length: number ): void
{
    netcode_assert( challenge_token );
    netcode_assert( buffer );
    netcode_assert( buffer_length >= NETCODE_CHALLENGE_TOKEN_BYTES );

    buffer.fill( 0, 0, NETCODE_CHALLENGE_TOKEN_BYTES );

    const p = new netcode_pointer_t( buffer );

    netcode_write_uint64( p, challenge_token.client_id );

    netcode_write_bytes( p, challenge_token.user_data, NETCODE_USER_DATA_BYTES );

    netcode_assert( p.offset <= NETCODE_CHALLENGE_TOKEN_BYTES - NETCODE_MAC_BYTES );
}

function netcode_write_sequence_nonce( nonce: Uint8Array, sequence: bigint ): void
{
    const p = new netcode_pointer_t( nonce );
    netcode_write_uint32( p, 0 );
    netcode_write_uint64( p, sequence );
}

export function netcode_encrypt_challenge_token( buffer: Uint8Array, buffer_length: number, sequence: bigint, key: Uint8Array ): number
{
    netcode_assert( buffer );
    netcode_assert( buffer_length >= NETCODE_CHALLENGE_TOKEN_BYTES );
    netcode_assert( key );

    const nonce = new Uint8Array( 12 );
    netcode_write_sequence_nonce( nonce, sequence );

    return netcode_encrypt_aead( buffer, NETCODE_CHALLENGE_TOKEN_BYTES - NETCODE_MAC_BYTES, null, 0, nonce, key );
}

export function netcode_decrypt_challenge_token( buffer: Uint8Array, buffer_length: number, sequence: bigint, key: Uint8Array ): number
{
    netcode_assert( buffer );
    netcode_assert( buffer_length >= NETCODE_CHALLENGE_TOKEN_BYTES );
    netcode_assert( key );

    const nonce = new Uint8Array( 12 );
    netcode_write_sequence_nonce( nonce, sequence );

    return netcode_decrypt_aead( buffer, NETCODE_CHALLENGE_TOKEN_BYTES, null, 0, nonce, key );
}

export function netcode_read_challenge_token( buffer: Uint8Array, buffer_length: number, challenge_token: netcode_challenge_token_t ): number
{
    netcode_assert( buffer );
    netcode_assert( challenge_token );

    if ( buffer_length < NETCODE_CHALLENGE_TOKEN_BYTES || buffer.length < NETCODE_CHALLENGE_TOKEN_BYTES )
        return NETCODE_ERROR;

    const p = new netcode_pointer_t( buffer );

    challenge_token.client_id = netcode_read_uint64( p );

    netcode_read_bytes( p, challenge_token.user_data, NETCODE_USER_DATA_BYTES );

    netcode_assert( p.offset == 8 + NETCODE_USER_DATA_BYTES );

    return NETCODE_OK;
}

// ----------------------------------------------------------------

export const NETCODE_CONNECTION_REQUEST_PACKET = 0;
export const NETCODE_CONNECTION_DENIED_PACKET = 1;
export const NETCODE_CONNECTION_CHALLENGE_PACKET = 2;
export const NETCODE_CONNECTION_RESPONSE_PACKET = 3;
export const NETCODE_CONNECTION_KEEP_ALIVE_PACKET = 4;
export const NETCODE_CONNECTION_PAYLOAD_PACKET = 5;
export const NETCODE_CONNECTION_DISCONNECT_PACKET = 6;
export const NETCODE_CONNECTION_NUM_PACKETS = 7;

export class netcode_connection_request_packet_t
{
    packet_type = NETCODE_CONNECTION_REQUEST_PACKET;
    version_info = new Uint8Array( NETCODE_VERSION_INFO_BYTES );
    protocol_id = 0n;
    connect_token_expire_timestamp = 0n;
    connect_token_nonce = new Uint8Array( NETCODE_CONNECT_TOKEN_NONCE_BYTES );
    connect_token_data = new Uint8Array( NETCODE_CONNECT_TOKEN_PRIVATE_BYTES );
}

export class netcode_connection_denied_packet_t
{
    packet_type = NETCODE_CONNECTION_DENIED_PACKET;
}

export class netcode_connection_challenge_packet_t
{
    packet_type = NETCODE_CONNECTION_CHALLENGE_PACKET;
    challenge_token_sequence = 0n;
    challenge_token_data = new Uint8Array( NETCODE_CHALLENGE_TOKEN_BYTES );
}

export class netcode_connection_response_packet_t
{
    packet_type = NETCODE_CONNECTION_RESPONSE_PACKET;
    challenge_token_sequence = 0n;
    challenge_token_data = new Uint8Array( NETCODE_CHALLENGE_TOKEN_BYTES );
}

export class netcode_connection_keep_alive_packet_t
{
    packet_type = NETCODE_CONNECTION_KEEP_ALIVE_PACKET;
    client_index = 0;
    max_clients = 0;
}

export class netcode_connection_payload_packet_t
{
    packet_type = NETCODE_CONNECTION_PAYLOAD_PACKET;
    payload_bytes = 0;
    payload_data: Uint8Array;

    constructor( payload_data: Uint8Array = new Uint8Array( 0 ), payload_bytes = 0 )
    {
        this.payload_data = payload_data;
        this.payload_bytes = payload_bytes;
    }
}

export class netcode_connection_disconnect_packet_t
{
    packet_type = NETCODE_CONNECTION_DISCONNECT_PACKET;
}

export type netcode_packet_t = netcode_connection_request_packet_t
                             | netcode_connection_denied_packet_t
                             | netcode_connection_challenge_packet_t
                             | netcode_connection_response_packet_t
                             | netcode_connection_keep_alive_packet_t
                             | netcode_connection_payload_packet_t
                             | netcode_connection_disconnect_packet_t;

// receive_packet hands the user the payload view; free_packet maps it back to its packet
const netcode_payload_packets = new WeakMap<Uint8Array, netcode_connection_payload_packet_t>();

// sizes of the C packet structs, passed to allocate_function as the bytes it would allocate
const NETCODE_PAYLOAD_PACKET_HEADER_BYTES = 8;
const NETCODE_PAYLOAD_PACKET_SLACK_BYTES = 8;

export function netcode_create_payload_packet( payload_bytes: number, allocator_context: unknown, allocate_function: netcode_allocate_function_t | null ): netcode_connection_payload_packet_t | null
{
    netcode_assert( payload_bytes >= 0 );
    netcode_assert( payload_bytes <= NETCODE_MAX_PAYLOAD_BYTES );

    if ( allocate_function == null )
    {
        allocate_function = netcode_default_allocate_function;
    }

    if ( !allocate_function( allocator_context, NETCODE_PAYLOAD_PACKET_HEADER_BYTES + NETCODE_PAYLOAD_PACKET_SLACK_BYTES + payload_bytes ) )
        return null;

    /* serialize's BitReader loads an 8-byte window from the current byte, so a
       read in the last payload byte reaches 7 past it. The payload view has 8
       bytes of slack behind it in its buffer, as C allocates them. */

    const payload_data = new Uint8Array( new ArrayBuffer( payload_bytes + NETCODE_PAYLOAD_PACKET_SLACK_BYTES ), 0, payload_bytes );

    const packet = new netcode_connection_payload_packet_t( payload_data, payload_bytes );

    netcode_payload_packets.set( payload_data, packet );

    return packet;
}

export class netcode_context_t
{
    write_packet_key = new Uint8Array( NETCODE_KEY_BYTES );
    read_packet_key = new Uint8Array( NETCODE_KEY_BYTES );
}

export function netcode_sequence_number_bytes_required( sequence: bigint ): number
{
    let i: number;
    let mask = 0xFF00000000000000n;
    for ( i = 0; i < 7; i++ )
    {
        if ( sequence & mask )
            break;
        mask >>= 8n;
    }
    return 8 - i;
}

/*
    Test-only instrumentation (NETCODE_ENABLE_NONCE_AUDIT in C), switched on while netcode_test() runs.

    Records the key and nonce of every packet netcode_write_packet encrypts and counts how
    many times a pair repeats. A repeated key and nonce pair under AEAD is what a connect
    token used for two sessions produces, so the whole test suite running with zero repeats
    is the property worth pinning.
*/

const NETCODE_NONCE_AUDIT_MAX_RECORDS = 1 << 18;

let netcode_nonce_audit_enabled = false;
let netcode_nonce_audit_records = new Set<string>();
let netcode_nonce_audit_num_repeats = 0;
let netcode_nonce_audit_overflowed = 0;

function netcode_nonce_audit_write_packet( key: Uint8Array, nonce: Uint8Array ): void
{
    let record = '';
    for ( let i = 0; i < NETCODE_KEY_BYTES; i++ )
        record += String.fromCharCode( key[i] );
    for ( let i = 0; i < 12; i++ )
        record += String.fromCharCode( nonce[i] );

    if ( netcode_nonce_audit_records.has( record ) )
    {
        netcode_nonce_audit_num_repeats++;
        netcode_printf( NETCODE_LOG_LEVEL_NONE, "NONCE AUDIT: repeated key and nonce pair: key %x.. sequence %d\n", ( ( key[0] << 24 ) | ( key[1] << 16 ) | ( key[2] << 8 ) | key[3] ) >>> 0, nonce[4] );
        return;
    }

    if ( netcode_nonce_audit_records.size == NETCODE_NONCE_AUDIT_MAX_RECORDS )
    {
        netcode_nonce_audit_overflowed = 1;
        return;
    }

    netcode_nonce_audit_records.add( record );
}

function netcode_nonce_audit_num_pairs(): number
{
    return netcode_nonce_audit_records.size;
}

function netcode_nonce_audit_repeats(): number
{
    return netcode_nonce_audit_num_repeats;
}

function netcode_nonce_audit_overflow(): number
{
    return netcode_nonce_audit_overflowed;
}

// scratch for the associated data and nonce of packet encryption. netcode is single threaded
const netcode_packet_additional_data = new Uint8Array( NETCODE_VERSION_INFO_BYTES + 8 + 1 );
const netcode_packet_nonce = new Uint8Array( 12 );

function netcode_write_packet_additional_data( protocol_id: bigint, prefix_byte: number ): void
{
    const p = new netcode_pointer_t( netcode_packet_additional_data );
    netcode_write_bytes( p, NETCODE_VERSION_INFO, NETCODE_VERSION_INFO_BYTES );
    netcode_write_uint64( p, protocol_id );
    netcode_write_uint8( p, prefix_byte );
}

export function netcode_write_packet( packet: netcode_packet_t, buffer: Uint8Array, buffer_length: number, sequence: bigint, write_packet_key: Uint8Array, protocol_id: bigint ): number
{
    netcode_assert( packet );
    netcode_assert( buffer );
    netcode_assert( write_packet_key );

    const packet_type = packet.packet_type;

    if ( packet_type == NETCODE_CONNECTION_REQUEST_PACKET )
    {
        // connection request packet: first byte is zero

        netcode_assert( buffer_length >= 1 + 13 + 8 + 8 + NETCODE_CONNECT_TOKEN_NONCE_BYTES + NETCODE_CONNECT_TOKEN_PRIVATE_BYTES );

        const p = packet as netcode_connection_request_packet_t;

        const b = new netcode_pointer_t( buffer );

        netcode_write_uint8( b, NETCODE_CONNECTION_REQUEST_PACKET );
        netcode_write_bytes( b, p.version_info, NETCODE_VERSION_INFO_BYTES );
        netcode_write_uint64( b, p.protocol_id );
        netcode_write_uint64( b, p.connect_token_expire_timestamp );
        netcode_write_bytes( b, p.connect_token_nonce, NETCODE_CONNECT_TOKEN_NONCE_BYTES );
        netcode_write_bytes( b, p.connect_token_data, NETCODE_CONNECT_TOKEN_PRIVATE_BYTES );

        netcode_assert( b.offset == 1 + 13 + 8 + 8 + NETCODE_CONNECT_TOKEN_NONCE_BYTES + NETCODE_CONNECT_TOKEN_PRIVATE_BYTES );

        return b.offset;
    }
    else
    {
        // *** encrypted packets ***

        // write the prefix byte (this is a combination of the packet type and number of sequence bytes)

        const b = new netcode_pointer_t( buffer );

        sequence = BigInt.asUintN( 64, sequence );

        const sequence_bytes = netcode_sequence_number_bytes_required( sequence );

        netcode_assert( sequence_bytes >= 1 );
        netcode_assert( sequence_bytes <= 8 );

        netcode_assert( packet_type <= 0xF );

        const prefix_byte = ( packet_type | ( sequence_bytes << 4 ) ) & 0xFF;

        netcode_write_uint8( b, prefix_byte );

        // write the variable length sequence number [1,8] bytes.

        let sequence_temp = sequence;

        for ( let i = 0; i < sequence_bytes; i++ )
        {
            netcode_write_uint8( b, Number( sequence_temp & 0xFFn ) );
            sequence_temp >>= 8n;
        }

        // write packet data according to type. this data will be encrypted.

        const encrypted_start = b.offset;

        switch ( packet_type )
        {
            case NETCODE_CONNECTION_DENIED_PACKET:
            {
                // ...
            }
            break;

            case NETCODE_CONNECTION_CHALLENGE_PACKET:
            {
                const p = packet as netcode_connection_challenge_packet_t;
                netcode_write_uint64( b, p.challenge_token_sequence );
                netcode_write_bytes( b, p.challenge_token_data, NETCODE_CHALLENGE_TOKEN_BYTES );
            }
            break;

            case NETCODE_CONNECTION_RESPONSE_PACKET:
            {
                const p = packet as netcode_connection_response_packet_t;
                netcode_write_uint64( b, p.challenge_token_sequence );
                netcode_write_bytes( b, p.challenge_token_data, NETCODE_CHALLENGE_TOKEN_BYTES );
            }
            break;

            case NETCODE_CONNECTION_KEEP_ALIVE_PACKET:
            {
                const p = packet as netcode_connection_keep_alive_packet_t;
                netcode_write_uint32( b, p.client_index );
                netcode_write_uint32( b, p.max_clients );
            }
            break;

            case NETCODE_CONNECTION_PAYLOAD_PACKET:
            {
                const p = packet as netcode_connection_payload_packet_t;

                netcode_assert( p.payload_bytes <= NETCODE_MAX_PAYLOAD_BYTES );

                netcode_write_bytes( b, p.payload_data, p.payload_bytes );
            }
            break;

            case NETCODE_CONNECTION_DISCONNECT_PACKET:
            {
                // ...
            }
            break;

            default:
                netcode_assert( 0 );
        }

        netcode_assert( b.offset <= buffer_length - NETCODE_MAC_BYTES );

        const encrypted_finish = b.offset;

        // encrypt the per-packet packet written with the prefix byte, protocol id and version as the associated data. this must match to decrypt.

        netcode_write_packet_additional_data( protocol_id, prefix_byte );

        netcode_write_sequence_nonce( netcode_packet_nonce, sequence );

        if ( netcode_nonce_audit_enabled )
        {
            netcode_nonce_audit_write_packet( write_packet_key, netcode_packet_nonce );
        }

        if ( netcode_encrypt_aead( buffer.subarray( encrypted_start ),
                                   encrypted_finish - encrypted_start,
                                   netcode_packet_additional_data, netcode_packet_additional_data.length,
                                   netcode_packet_nonce, write_packet_key ) != NETCODE_OK )
        {
            return NETCODE_ERROR;
        }

        b.offset += NETCODE_MAC_BYTES;

        netcode_assert( b.offset <= buffer_length );

        return b.offset;
    }
}

export class netcode_replay_protection_t
{
    most_recent_sequence = 0n;
    received_packet = new BigUint64Array( NETCODE_REPLAY_PROTECTION_BUFFER_SIZE );
}

const NETCODE_UINT64_MAX = 0xFFFFFFFFFFFFFFFFn;
const NETCODE_REPLAY_PROTECTION_BUFFER_SIZE_N = BigInt( NETCODE_REPLAY_PROTECTION_BUFFER_SIZE );

export function netcode_replay_protection_reset( replay_protection: netcode_replay_protection_t ): void
{
    netcode_assert( replay_protection );
    replay_protection.most_recent_sequence = 0n;
    replay_protection.received_packet.fill( NETCODE_UINT64_MAX );
}

export function netcode_replay_protection_already_received( replay_protection: netcode_replay_protection_t, sequence: bigint ): number
{
    netcode_assert( replay_protection );

    // written so it cannot overflow: "sequence + BUFFER_SIZE <= most_recent" wraps for
    // sequence values near UINT64_MAX and falsely rejects them as replays

    if ( replay_protection.most_recent_sequence >= NETCODE_REPLAY_PROTECTION_BUFFER_SIZE_N &&
         sequence <= replay_protection.most_recent_sequence - NETCODE_REPLAY_PROTECTION_BUFFER_SIZE_N )
        return 1;

    const index = Number( sequence % NETCODE_REPLAY_PROTECTION_BUFFER_SIZE_N );

    if ( replay_protection.received_packet[index] == NETCODE_UINT64_MAX )
        return 0;

    if ( replay_protection.received_packet[index] >= sequence )
        return 1;

    return 0;
}

export function netcode_replay_protection_advance_sequence( replay_protection: netcode_replay_protection_t, sequence: bigint ): void
{
    netcode_assert( replay_protection );

    if ( sequence > replay_protection.most_recent_sequence )
        replay_protection.most_recent_sequence = sequence;

    const index = Number( sequence % NETCODE_REPLAY_PROTECTION_BUFFER_SIZE_N );

    replay_protection.received_packet[index] = sequence;
}

function netcode_version_info_valid( version_info: Uint8Array ): boolean
{
    for ( let i = 0; i < NETCODE_VERSION_INFO_BYTES; i++ )
    {
        if ( version_info[i] != NETCODE_VERSION_INFO[i] )
            return false;
    }
    return true;
}

// sizes of the C packet structs, passed to allocate_function
const NETCODE_CONNECTION_REQUEST_PACKET_BYTES = 1 + NETCODE_VERSION_INFO_BYTES + 2 + 8 + 8 + NETCODE_CONNECT_TOKEN_NONCE_BYTES + NETCODE_CONNECT_TOKEN_PRIVATE_BYTES;
const NETCODE_CONNECTION_CHALLENGE_PACKET_BYTES = 8 + 8 + NETCODE_CHALLENGE_TOKEN_BYTES;
const NETCODE_CONNECTION_KEEP_ALIVE_PACKET_BYTES = 12;
const NETCODE_CONNECTION_EMPTY_PACKET_BYTES = 1;

/**
    Reads and validates a packet. Encrypted packets are decrypted in place in buffer. sequence.value
    receives the packet sequence. Returns the packet, or null when it is ignored.
*/
export function netcode_read_packet( buffer: Uint8Array,
                                     buffer_length: number,
                                     sequence: { value: bigint },
                                     read_packet_key: Uint8Array | null,
                                     protocol_id: bigint,
                                     current_timestamp: bigint,
                                     min_connect_token_expire_timestamp: bigint,
                                     private_key: Uint8Array | null,
                                     allowed_packets: Uint8Array,
                                     replay_protection: netcode_replay_protection_t | null,
                                     allocator_context: unknown,
                                     allocate_function: netcode_allocate_function_t | null ): netcode_packet_t | null
{
    netcode_assert( sequence );
    netcode_assert( allowed_packets );

    sequence.value = 0n;

    if ( allocate_function == null )
    {
        allocate_function = netcode_default_allocate_function;
    }

    if ( buffer_length < 1 )
    {
        netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "ignored packet. buffer length is less than 1\n" );
        return null;
    }

    if ( buffer_length > buffer.length )
    {
        netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "ignored packet. buffer length is larger than the buffer\n" );
        return null;
    }

    const p = new netcode_pointer_t( buffer );

    const prefix_byte = netcode_read_uint8( p );

    if ( prefix_byte == NETCODE_CONNECTION_REQUEST_PACKET )
    {
        // connection request packet: first byte is zero

        if ( !allowed_packets[NETCODE_CONNECTION_REQUEST_PACKET] )
        {
            netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "ignored connection request packet. packet type is not allowed\n" );
            return null;
        }

        if ( buffer_length != 1 + NETCODE_VERSION_INFO_BYTES + 8 + 8 + NETCODE_CONNECT_TOKEN_NONCE_BYTES + NETCODE_CONNECT_TOKEN_PRIVATE_BYTES )
        {
            netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "ignored connection request packet. bad packet length (expected %d, got %d)\n", 1 + NETCODE_VERSION_INFO_BYTES + 8 + 8 + NETCODE_CONNECT_TOKEN_NONCE_BYTES + NETCODE_CONNECT_TOKEN_PRIVATE_BYTES, buffer_length );
            return null;
        }

        if ( !private_key )
        {
            netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "ignored connection request packet. no private key\n" );
            return null;
        }

        const version_info = new Uint8Array( NETCODE_VERSION_INFO_BYTES );
        netcode_read_bytes( p, version_info, NETCODE_VERSION_INFO_BYTES );
        if ( !netcode_version_info_valid( version_info ) )
        {
            netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "ignored connection request packet. bad version info\n" );
            return null;
        }

        const packet_protocol_id = netcode_read_uint64( p );
        if ( packet_protocol_id != protocol_id )
        {
            netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "ignored connection request packet. wrong protocol id. expected %.16" + PRIx64 + ", got %.16" + PRIx64 + "\n",
                protocol_id, packet_protocol_id );
            return null;
        }

        const packet_connect_token_expire_timestamp = netcode_read_uint64( p );
        if ( packet_connect_token_expire_timestamp <= current_timestamp )
        {
            netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "ignored connection request packet. connect token expired\n" );
            return null;
        }

        // a connect token that could have been issued before the server started is refused: its keys
        // were already used to encrypt packets under sequence numbers that start again from zero.

        if ( packet_connect_token_expire_timestamp < min_connect_token_expire_timestamp )
        {
            netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "ignored connection request packet. connect token predates the server start\n" );
            return null;
        }

        const packet_connect_token_nonce = new Uint8Array( NETCODE_CONNECT_TOKEN_NONCE_BYTES );
        netcode_read_bytes( p, packet_connect_token_nonce, packet_connect_token_nonce.length );

        netcode_assert( p.offset == 1 + NETCODE_VERSION_INFO_BYTES + 8 + 8 + NETCODE_CONNECT_TOKEN_NONCE_BYTES );

        if ( netcode_decrypt_connect_token_private( buffer.subarray( p.offset ),
                                                    NETCODE_CONNECT_TOKEN_PRIVATE_BYTES,
                                                    version_info,
                                                    protocol_id,
                                                    packet_connect_token_expire_timestamp,
                                                    packet_connect_token_nonce,
                                                    private_key ) != NETCODE_OK )
        {
            netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "ignored connection request packet. connect token failed to decrypt\n" );
            return null;
        }

        if ( !allocate_function( allocator_context, NETCODE_CONNECTION_REQUEST_PACKET_BYTES ) )
        {
            netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "ignored connection request packet. failed to allocate packet\n" );
            return null;
        }

        const packet = new netcode_connection_request_packet_t();

        packet.packet_type = NETCODE_CONNECTION_REQUEST_PACKET;
        packet.version_info.set( version_info );
        packet.protocol_id = packet_protocol_id;
        packet.connect_token_expire_timestamp = packet_connect_token_expire_timestamp;
        packet.connect_token_nonce.set( packet_connect_token_nonce );
        netcode_read_bytes( p, packet.connect_token_data, NETCODE_CONNECT_TOKEN_PRIVATE_BYTES );

        netcode_assert( p.offset == 1 + NETCODE_VERSION_INFO_BYTES + 8 + 8 + NETCODE_CONNECT_TOKEN_NONCE_BYTES + NETCODE_CONNECT_TOKEN_PRIVATE_BYTES );

        return packet;
    }
    else
    {
        // *** encrypted packets ***

        if ( !read_packet_key )
        {
            netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "ignored encrypted packet. no read packet key for this address\n" );
            return null;
        }

        if ( buffer_length < 1 + 1 + NETCODE_MAC_BYTES )
        {
            netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "ignored encrypted packet. packet is too small to be valid (%d bytes)\n", buffer_length );
            return null;
        }

        // extract the packet type and number of sequence bytes from the prefix byte

        const packet_type = prefix_byte & 0xF;

        if ( packet_type >= NETCODE_CONNECTION_NUM_PACKETS )
        {
            netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "ignored encrypted packet. packet type %d is invalid\n", packet_type );
            return null;
        }

        if ( !allowed_packets[packet_type] )
        {
            netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "ignored encrypted packet. packet type %d is not allowed\n", packet_type );
            return null;
        }

        const sequence_bytes = prefix_byte >> 4;

        if ( sequence_bytes < 1 || sequence_bytes > 8 )
        {
            netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "ignored encrypted packet. sequence bytes %d is out of range [1,8]\n", sequence_bytes );
            return null;
        }

        if ( buffer_length < 1 + sequence_bytes + NETCODE_MAC_BYTES )
        {
            netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "ignored encrypted packet. buffer is too small for sequence bytes + encryption mac\n" );
            return null;
        }

        // read variable length sequence number [1,8]

        let packet_sequence = 0n;
        for ( let i = 0; i < sequence_bytes; i++ )
        {
            const value = netcode_read_uint8( p );
            packet_sequence |= BigInt( value ) << BigInt( 8 * i );
        }
        sequence.value = packet_sequence;

        // ignore the packet if it has already been received

        if ( replay_protection && packet_type >= NETCODE_CONNECTION_KEEP_ALIVE_PACKET )
        {
            if ( netcode_replay_protection_already_received( replay_protection, packet_sequence ) )
            {
                netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "ignored packet. sequence %.16" + PRIx64 + " already received (replay protection)\n", packet_sequence );
                return null;
            }
        }

        // decrypt the per-packet type data

        netcode_write_packet_additional_data( protocol_id, prefix_byte );

        netcode_write_sequence_nonce( netcode_packet_nonce, packet_sequence );

        const encrypted_bytes = buffer_length - p.offset;

        if ( encrypted_bytes < NETCODE_MAC_BYTES )
        {
            netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "ignored encrypted packet. encrypted payload is too small\n" );
            return null;
        }

        if ( netcode_decrypt_aead( buffer.subarray( p.offset, buffer_length ), encrypted_bytes, netcode_packet_additional_data, netcode_packet_additional_data.length, netcode_packet_nonce, read_packet_key ) != NETCODE_OK )
        {
            netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "ignored encrypted packet. failed to decrypt\n" );
            return null;
        }

        const decrypted_bytes = encrypted_bytes - NETCODE_MAC_BYTES;

        // update the latest replay protection sequence #

        if ( replay_protection && packet_type >= NETCODE_CONNECTION_KEEP_ALIVE_PACKET )
        {
            netcode_replay_protection_advance_sequence( replay_protection, packet_sequence );
        }

        // process the per-packet type data that was just decrypted

        switch ( packet_type )
        {
            case NETCODE_CONNECTION_DENIED_PACKET:
            {
                if ( decrypted_bytes != 0 )
                {
                    netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "ignored connection denied packet. decrypted packet data is wrong size\n" );
                    return null;
                }

                if ( !allocate_function( allocator_context, NETCODE_CONNECTION_EMPTY_PACKET_BYTES ) )
                {
                    netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "ignored connection denied packet. could not allocate packet struct\n" );
                    return null;
                }

                return new netcode_connection_denied_packet_t();
            }

            case NETCODE_CONNECTION_CHALLENGE_PACKET:
            {
                if ( decrypted_bytes != 8 + NETCODE_CHALLENGE_TOKEN_BYTES )
                {
                    netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "ignored connection challenge packet. decrypted packet data is wrong size\n" );
                    return null;
                }

                if ( !allocate_function( allocator_context, NETCODE_CONNECTION_CHALLENGE_PACKET_BYTES ) )
                {
                    netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "ignored connection challenge packet. could not allocate packet struct\n" );
                    return null;
                }

                const packet = new netcode_connection_challenge_packet_t();
                packet.challenge_token_sequence = netcode_read_uint64( p );
                netcode_read_bytes( p, packet.challenge_token_data, NETCODE_CHALLENGE_TOKEN_BYTES );

                return packet;
            }

            case NETCODE_CONNECTION_RESPONSE_PACKET:
            {
                if ( decrypted_bytes != 8 + NETCODE_CHALLENGE_TOKEN_BYTES )
                {
                    netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "ignored connection response packet. decrypted packet data is wrong size\n" );
                    return null;
                }

                if ( !allocate_function( allocator_context, NETCODE_CONNECTION_CHALLENGE_PACKET_BYTES ) )
                {
                    netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "ignored connection response packet. could not allocate packet struct\n" );
                    return null;
                }

                const packet = new netcode_connection_response_packet_t();
                packet.challenge_token_sequence = netcode_read_uint64( p );
                netcode_read_bytes( p, packet.challenge_token_data, NETCODE_CHALLENGE_TOKEN_BYTES );

                return packet;
            }

            case NETCODE_CONNECTION_KEEP_ALIVE_PACKET:
            {
                if ( decrypted_bytes != 8 )
                {
                    netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "ignored connection keep alive packet. decrypted packet data is wrong size\n" );
                    return null;
                }

                if ( !allocate_function( allocator_context, NETCODE_CONNECTION_KEEP_ALIVE_PACKET_BYTES ) )
                {
                    netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "ignored connection keep alive packet. could not allocate packet struct\n" );
                    return null;
                }

                const packet = new netcode_connection_keep_alive_packet_t();
                packet.client_index = netcode_read_uint32( p ) | 0;
                packet.max_clients = netcode_read_uint32( p ) | 0;

                return packet;
            }

            case NETCODE_CONNECTION_PAYLOAD_PACKET:
            {
                if ( decrypted_bytes < 1 )
                {
                    netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "ignored connection payload packet. payload is too small\n" );
                    return null;
                }

                if ( decrypted_bytes > NETCODE_MAX_PAYLOAD_BYTES )
                {
                    netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "ignored connection payload packet. payload is too large\n" );
                    return null;
                }

                const packet = netcode_create_payload_packet( decrypted_bytes, allocator_context, allocate_function );

                if ( !packet )
                {
                    netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "ignored connection payload packet. could not allocate packet struct\n" );
                    return null;
                }

                packet.payload_data.set( buffer.subarray( p.offset, p.offset + decrypted_bytes ) );

                return packet;
            }

            case NETCODE_CONNECTION_DISCONNECT_PACKET:
            {
                if ( decrypted_bytes != 0 )
                {
                    netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "ignored connection disconnect packet. decrypted packet data is wrong size\n" );
                    return null;
                }

                if ( !allocate_function( allocator_context, NETCODE_CONNECTION_EMPTY_PACKET_BYTES ) )
                {
                    netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "ignored connection disconnect packet. could not allocate packet struct\n" );
                    return null;
                }

                return new netcode_connection_disconnect_packet_t();
            }

            default:
                return null;
        }
    }
}

// ----------------------------------------------------------------

export class netcode_connect_token_t
{
    version_info = new Uint8Array( NETCODE_VERSION_INFO_BYTES );
    protocol_id = 0n;
    create_timestamp = 0n;
    expire_timestamp = 0n;
    nonce = new Uint8Array( NETCODE_CONNECT_TOKEN_NONCE_BYTES );
    private_data = new Uint8Array( NETCODE_CONNECT_TOKEN_PRIVATE_BYTES );
    timeout_seconds = 0;
    num_server_addresses = 0;
    server_addresses: netcode_address_t[] = netcode_address_array( NETCODE_MAX_SERVERS_PER_CONNECT );
    client_to_server_key = new Uint8Array( NETCODE_KEY_BYTES );
    server_to_client_key = new Uint8Array( NETCODE_KEY_BYTES );
}

/** sodium_memzero( connect_token, sizeof( struct netcode_connect_token_t ) ) */
function netcode_connect_token_zero( connect_token: netcode_connect_token_t ): void
{
    sodium_memzero( connect_token.version_info );
    connect_token.protocol_id = 0n;
    connect_token.create_timestamp = 0n;
    connect_token.expire_timestamp = 0n;
    sodium_memzero( connect_token.nonce );
    sodium_memzero( connect_token.private_data );
    connect_token.timeout_seconds = 0;
    connect_token.num_server_addresses = 0;
    for ( let i = 0; i < NETCODE_MAX_SERVERS_PER_CONNECT; i++ )
        netcode_address_zero( connect_token.server_addresses[i] );
    sodium_memzero( connect_token.client_to_server_key );
    sodium_memzero( connect_token.server_to_client_key );
}

export function netcode_write_connect_token( connect_token: netcode_connect_token_t, buffer: Uint8Array, buffer_length: number ): void
{
    netcode_assert( connect_token );
    netcode_assert( buffer );
    netcode_assert( buffer_length >= NETCODE_CONNECT_TOKEN_BYTES );

    const p = new netcode_pointer_t( buffer );

    netcode_write_bytes( p, connect_token.version_info, NETCODE_VERSION_INFO_BYTES );

    netcode_write_uint64( p, connect_token.protocol_id );

    netcode_write_uint64( p, connect_token.create_timestamp );

    netcode_write_uint64( p, connect_token.expire_timestamp );

    netcode_write_bytes( p, connect_token.nonce, NETCODE_CONNECT_TOKEN_NONCE_BYTES );

    netcode_write_bytes( p, connect_token.private_data, NETCODE_CONNECT_TOKEN_PRIVATE_BYTES );

    netcode_write_uint32( p, connect_token.timeout_seconds );

    netcode_write_uint32( p, connect_token.num_server_addresses );

    for ( let i = 0; i < connect_token.num_server_addresses; i++ )
    {
        const server_address = connect_token.server_addresses[i];

        if ( server_address.type == NETCODE_ADDRESS_IPV4 )
        {
            netcode_write_uint8( p, NETCODE_ADDRESS_IPV4 );
            for ( let j = 0; j < 4; j++ )
            {
                netcode_write_uint8( p, server_address.data.ipv4[j] );
            }
            netcode_write_uint16( p, server_address.port );
        }
        else if ( server_address.type == NETCODE_ADDRESS_IPV6 )
        {
            netcode_write_uint8( p, NETCODE_ADDRESS_IPV6 );
            for ( let j = 0; j < 8; j++ )
            {
                netcode_write_uint16( p, server_address.data.ipv6[j] );
            }
            netcode_write_uint16( p, server_address.port );
        }
        else
        {
            netcode_assert( 0 );
        }
    }

    netcode_write_bytes( p, connect_token.client_to_server_key, NETCODE_KEY_BYTES );

    netcode_write_bytes( p, connect_token.server_to_client_key, NETCODE_KEY_BYTES );

    netcode_assert( p.offset <= NETCODE_CONNECT_TOKEN_BYTES );

    buffer.fill( 0, p.offset, NETCODE_CONNECT_TOKEN_BYTES );
}

export function netcode_read_connect_token( buffer: Uint8Array, buffer_length: number, connect_token: netcode_connect_token_t ): number
{
    netcode_assert( buffer );
    netcode_assert( connect_token );

    if ( buffer_length != NETCODE_CONNECT_TOKEN_BYTES || buffer.length < NETCODE_CONNECT_TOKEN_BYTES )
    {
        netcode_printf( NETCODE_LOG_LEVEL_ERROR, "error: read connect data has bad buffer length (%d)\n", buffer_length );
        return NETCODE_ERROR;
    }

    const p = new netcode_pointer_t( buffer );

    netcode_read_bytes( p, connect_token.version_info, NETCODE_VERSION_INFO_BYTES );
    if ( !netcode_version_info_valid( connect_token.version_info ) )
    {
        connect_token.version_info[12] = 0;
        let got = '';
        for ( let i = 0; i < NETCODE_VERSION_INFO_BYTES && connect_token.version_info[i] != 0; i++ )
            got += String.fromCharCode( connect_token.version_info[i] );
        netcode_printf( NETCODE_LOG_LEVEL_ERROR, "error: read connect data has bad version info (got %s, expected %s)\n", got, "NETCODE 1.02" );
        return NETCODE_ERROR;
    }

    connect_token.protocol_id = netcode_read_uint64( p );

    connect_token.create_timestamp = netcode_read_uint64( p );

    connect_token.expire_timestamp = netcode_read_uint64( p );

    if ( connect_token.create_timestamp > connect_token.expire_timestamp )
        return NETCODE_ERROR;

    netcode_read_bytes( p, connect_token.nonce, NETCODE_CONNECT_TOKEN_NONCE_BYTES );

    netcode_read_bytes( p, connect_token.private_data, NETCODE_CONNECT_TOKEN_PRIVATE_BYTES );

    connect_token.timeout_seconds = netcode_read_uint32( p ) | 0;

    connect_token.num_server_addresses = netcode_read_uint32( p ) | 0;

    if ( connect_token.num_server_addresses <= 0 || connect_token.num_server_addresses > NETCODE_MAX_SERVERS_PER_CONNECT )
    {
        netcode_printf( NETCODE_LOG_LEVEL_ERROR, "error: read connect data has bad number of server addresses (%d)\n", connect_token.num_server_addresses );
        return NETCODE_ERROR;
    }

    for ( let i = 0; i < connect_token.num_server_addresses; i++ )
    {
        const server_address = connect_token.server_addresses[i];

        server_address.type = netcode_read_uint8( p );

        if ( server_address.type == NETCODE_ADDRESS_IPV4 )
        {
            for ( let j = 0; j < 4; j++ )
            {
                server_address.data.ipv4[j] = netcode_read_uint8( p );
            }
            server_address.port = netcode_read_uint16( p );
        }
        else if ( server_address.type == NETCODE_ADDRESS_IPV6 )
        {
            for ( let j = 0; j < 8; j++ )
            {
                server_address.data.ipv6[j] = netcode_read_uint16( p );
            }
            server_address.port = netcode_read_uint16( p );
        }
        else
        {
            netcode_printf( NETCODE_LOG_LEVEL_ERROR, "error: read connect data has bad address type (%d)\n", server_address.type );
            return NETCODE_ERROR;
        }
    }

    netcode_read_bytes( p, connect_token.client_to_server_key, NETCODE_KEY_BYTES );

    netcode_read_bytes( p, connect_token.server_to_client_key, NETCODE_KEY_BYTES );

    return NETCODE_OK;
}

// ----------------------------------------------------------------

export class netcode_packet_queue_t
{
    allocator_context: unknown = null;
    allocate_function: netcode_allocate_function_t = netcode_default_allocate_function;
    free_function: netcode_free_function_t = netcode_default_free_function;
    num_packets = 0;
    start_index = 0;
    packet_data: unknown[] = new Array<unknown>( NETCODE_PACKET_QUEUE_SIZE ).fill( null );
    packet_sequence = new BigUint64Array( NETCODE_PACKET_QUEUE_SIZE );
}

export function netcode_packet_queue_init( queue: netcode_packet_queue_t,
                                           allocator_context: unknown,
                                           allocate_function: netcode_allocate_function_t | null,
                                           free_function: netcode_free_function_t | null ): void
{
    if ( allocate_function == null )
    {
        allocate_function = netcode_default_allocate_function;
    }

    if ( free_function == null )
    {
        free_function = netcode_default_free_function;
    }

    netcode_assert( queue );

    queue.allocator_context = allocator_context;
    queue.allocate_function = allocate_function;
    queue.free_function = free_function;
    queue.num_packets = 0;
    queue.start_index = 0;
    queue.packet_data.fill( null );
    queue.packet_sequence.fill( 0n );
}

export function netcode_packet_queue_push( queue: netcode_packet_queue_t, packet_data: unknown, packet_sequence: bigint ): number
{
    netcode_assert( queue );
    netcode_assert( packet_data );
    if ( queue.num_packets == NETCODE_PACKET_QUEUE_SIZE )
    {
        queue.free_function( queue.allocator_context, packet_data );
        return 0;
    }
    const index = ( queue.start_index + queue.num_packets ) % NETCODE_PACKET_QUEUE_SIZE;
    queue.packet_data[index] = packet_data;
    queue.packet_sequence[index] = BigInt.asUintN( 64, packet_sequence );
    queue.num_packets++;
    return 1;
}

export function netcode_packet_queue_pop( queue: netcode_packet_queue_t, packet_sequence: { value: bigint } | null ): unknown
{
    if ( queue.num_packets == 0 )
        return null;
    const packet = queue.packet_data[queue.start_index];
    queue.packet_data[queue.start_index] = null;
    if ( packet_sequence )
        packet_sequence.value = queue.packet_sequence[queue.start_index];
    queue.start_index = ( queue.start_index + 1 ) % NETCODE_PACKET_QUEUE_SIZE;
    queue.num_packets--;
    return packet;
}

export function netcode_packet_queue_clear( queue: netcode_packet_queue_t ): void
{
    netcode_assert( queue );
    while ( queue.num_packets > 0 )
    {
        queue.free_function( queue.allocator_context, netcode_packet_queue_pop( queue, null ) );
    }
    queue.start_index = 0;
    queue.packet_data.fill( null );
    queue.packet_sequence.fill( 0n );
}

// ----------------------------------------------------------------

export const NETCODE_NETWORK_SIMULATOR_NUM_PACKET_ENTRIES = NETCODE_MAX_CLIENTS * 256;
export const NETCODE_NETWORK_SIMULATOR_NUM_PENDING_RECEIVE_PACKETS = NETCODE_MAX_CLIENTS * 64;
const NETCODE_NETWORK_SIMULATOR_RNG_SEED = 0x9E3779B97F4A7C15n;

export class netcode_network_simulator_packet_entry_t
{
    from = new netcode_address_t();
    to = new netcode_address_t();
    delivery_time = 0.0;
    packet_data: Uint8Array | null = null;
    packet_bytes = 0;
}

export class netcode_network_simulator_t
{
    allocator_context: unknown = null;
    allocate_function: netcode_allocate_function_t = netcode_default_allocate_function;
    free_function: netcode_free_function_t = netcode_default_free_function;
    // C declares these as float. they are rounded to float where the simulator uses them
    latency_milliseconds = 0.0;
    jitter_milliseconds = 0.0;
    packet_loss_percent = 0.0;
    duplicate_packet_percent = 0.0;
    rng_state = 0n;
    time = 0.0;
    current_index = 0;
    num_pending_receive_packets = 0;
    // slots are created on first use: an empty slot is null, or an entry whose packet_data is null
    packet_entries: ( netcode_network_simulator_packet_entry_t | null )[] = new Array<netcode_network_simulator_packet_entry_t | null>( NETCODE_NETWORK_SIMULATOR_NUM_PACKET_ENTRIES ).fill( null );
    pending_receive_packets: ( netcode_network_simulator_packet_entry_t | null )[] = new Array<netcode_network_simulator_packet_entry_t | null>( NETCODE_NETWORK_SIMULATOR_NUM_PENDING_RECEIVE_PACKETS ).fill( null );
}

const NETCODE_NETWORK_SIMULATOR_BYTES = 64 + ( NETCODE_NETWORK_SIMULATOR_NUM_PACKET_ENTRIES + NETCODE_NETWORK_SIMULATOR_NUM_PENDING_RECEIVE_PACKETS ) * 64;

export function netcode_network_simulator_create( allocator_context: unknown,
                                                  allocate_function: netcode_allocate_function_t | null,
                                                  free_function: netcode_free_function_t | null ): netcode_network_simulator_t
{
    if ( allocate_function == null )
    {
        allocate_function = netcode_default_allocate_function;
    }

    if ( free_function == null )
    {
        free_function = netcode_default_free_function;
    }

    netcode_assert( allocate_function( allocator_context, NETCODE_NETWORK_SIMULATOR_BYTES ) );

    const network_simulator = new netcode_network_simulator_t();

    network_simulator.allocator_context = allocator_context;
    network_simulator.allocate_function = allocate_function;
    network_simulator.free_function = free_function;
    network_simulator.rng_state = NETCODE_NETWORK_SIMULATOR_RNG_SEED;

    return network_simulator;
}

export function netcode_network_simulator_reset( network_simulator: netcode_network_simulator_t ): void
{
    netcode_assert( network_simulator );

    netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "network simulator reset\n" );

    for ( let i = 0; i < NETCODE_NETWORK_SIMULATOR_NUM_PACKET_ENTRIES; i++ )
    {
        const entry = network_simulator.packet_entries[i];
        if ( entry && entry.packet_data )
            network_simulator.free_function( network_simulator.allocator_context, entry.packet_data );
        network_simulator.packet_entries[i] = null;
    }

    for ( let i = 0; i < network_simulator.num_pending_receive_packets; i++ )
    {
        const entry = network_simulator.pending_receive_packets[i];
        if ( entry && entry.packet_data )
            network_simulator.free_function( network_simulator.allocator_context, entry.packet_data );
        network_simulator.pending_receive_packets[i] = null;
    }

    network_simulator.current_index = 0;
    network_simulator.num_pending_receive_packets = 0;
    network_simulator.rng_state = NETCODE_NETWORK_SIMULATOR_RNG_SEED;
}

export function netcode_network_simulator_destroy( network_simulator: netcode_network_simulator_t ): void
{
    netcode_assert( network_simulator );
    netcode_network_simulator_reset( network_simulator );
    network_simulator.free_function( network_simulator.allocator_context, network_simulator );
}

function netcode_network_simulator_random_uint64( network_simulator: netcode_network_simulator_t ): bigint
{
    // xorshift64*. self-contained and deterministic, unlike rand(): the simulator
    // produces the same loss, jitter and duplication sequence on every run, and
    // shares no state with the application or other simulator instances.

    let x = network_simulator.rng_state;
    x ^= x >> 12n;
    x = BigInt.asUintN( 64, x ^ ( x << 25n ) );
    x ^= x >> 27n;
    network_simulator.rng_state = x;
    return BigInt.asUintN( 64, x * 0x2545F4914F6CDD1Dn );
}

function netcode_network_simulator_random_float( network_simulator: netcode_network_simulator_t, a: number, b: number ): number
{
    netcode_assert( a < b );
    const fround = Math.fround;
    const random = fround( Number( netcode_network_simulator_random_uint64( network_simulator ) >> 40n ) / ( 1 << 24 ) );
    return fround( fround( a ) + fround( random * fround( fround( b ) - fround( a ) ) ) );
}

export function netcode_network_simulator_queue_packet( network_simulator: netcode_network_simulator_t,
                                                        from: netcode_address_t,
                                                        to: netcode_address_t,
                                                        packet_data: Uint8Array,
                                                        packet_bytes: number,
                                                        delay: number ): void
{
    // allocate before touching the slot. if the allocator fails, drop this packet and leave
    // the entry already queued in that slot alone, rather than copying into null.

    if ( !network_simulator.allocate_function( network_simulator.allocator_context, packet_bytes ) )
    {
        netcode_printf( NETCODE_LOG_LEVEL_ERROR, "error: network simulator could not allocate packet data\n" );
        return;
    }

    const entry_packet_data = packet_data.slice( 0, packet_bytes );

    let entry = network_simulator.packet_entries[network_simulator.current_index];

    if ( entry === null )
    {
        entry = new netcode_network_simulator_packet_entry_t();
        network_simulator.packet_entries[network_simulator.current_index] = entry;
    }
    else if ( entry.packet_data )
    {
        network_simulator.free_function( network_simulator.allocator_context, entry.packet_data );
        entry.packet_data = null;
    }

    netcode_address_copy( entry.from, from );
    netcode_address_copy( entry.to, to );
    entry.packet_data = entry_packet_data;
    entry.packet_bytes = packet_bytes;
    entry.delivery_time = network_simulator.time + delay;
    network_simulator.current_index++;
    network_simulator.current_index %= NETCODE_NETWORK_SIMULATOR_NUM_PACKET_ENTRIES;
}

export function netcode_network_simulator_send_packet( network_simulator: netcode_network_simulator_t,
                                                       from: netcode_address_t,
                                                       to: netcode_address_t,
                                                       packet_data: Uint8Array,
                                                       packet_bytes: number ): void
{
    netcode_assert( network_simulator );
    netcode_assert( from );
    netcode_assert( from.type != 0 );
    netcode_assert( to );
    netcode_assert( to.type != 0 );
    netcode_assert( packet_data );
    netcode_assert( packet_bytes > 0 );
    netcode_assert( packet_bytes <= NETCODE_MAX_PACKET_BYTES );

    const fround = Math.fround;

    if ( netcode_network_simulator_random_float( network_simulator, 0.0, 100.0 ) <= fround( network_simulator.packet_loss_percent ) )
        return;

    let delay = fround( fround( network_simulator.latency_milliseconds ) / 1000.0 );

    if ( fround( network_simulator.jitter_milliseconds ) > 0.0 )
        delay = fround( delay + fround( netcode_network_simulator_random_float( network_simulator, -fround( network_simulator.jitter_milliseconds ), +fround( network_simulator.jitter_milliseconds ) ) / 1000.0 ) );

    netcode_network_simulator_queue_packet( network_simulator, from, to, packet_data, packet_bytes, delay );

    if ( netcode_network_simulator_random_float( network_simulator, 0.0, 100.0 ) <= fround( network_simulator.duplicate_packet_percent ) )
    {
        netcode_network_simulator_queue_packet( network_simulator, from, to, packet_data, packet_bytes, fround( delay + netcode_network_simulator_random_float( network_simulator, 0, 1.0 ) ) );
    }
}

/**
    Moves the packets for `to` that are ready into packet_data[], packet_bytes[] and from[], at most
    max_packets of them, and returns how many. The packet data is the caller's to release with the
    simulator's free_function (or just drop).
*/
export function netcode_network_simulator_receive_packets( network_simulator: netcode_network_simulator_t,
                                                           to: netcode_address_t,
                                                           max_packets: number,
                                                           packet_data: ( Uint8Array | null )[],
                                                           packet_bytes: Int32Array | number[],
                                                           from: netcode_address_t[] ): number
{
    netcode_assert( network_simulator );
    netcode_assert( max_packets >= 0 );
    netcode_assert( packet_data );
    netcode_assert( packet_bytes );
    netcode_assert( from );
    netcode_assert( to );

    let num_packets = 0;

    for ( let i = 0; i < network_simulator.num_pending_receive_packets; i++ )
    {
        if ( num_packets == max_packets )
            break;

        const entry = network_simulator.pending_receive_packets[i];

        if ( !entry || !entry.packet_data )
            continue;

        if ( !netcode_address_equal( entry.to, to ) )
            continue;

        packet_data[num_packets] = entry.packet_data;
        packet_bytes[num_packets] = entry.packet_bytes;
        from[num_packets] = entry.from;

        entry.packet_data = null;

        num_packets++;
    }

    netcode_assert( num_packets <= max_packets );

    return num_packets;
}

export function netcode_network_simulator_update( network_simulator: netcode_network_simulator_t, time: number ): void
{
    netcode_assert( network_simulator );

    network_simulator.time = time;

    // discard any pending receive packets that are still in the buffer

    for ( let i = 0; i < network_simulator.num_pending_receive_packets; i++ )
    {
        const entry = network_simulator.pending_receive_packets[i];
        if ( entry && entry.packet_data )
        {
            network_simulator.free_function( network_simulator.allocator_context, entry.packet_data );
            entry.packet_data = null;
        }
        network_simulator.pending_receive_packets[i] = null;
    }

    network_simulator.num_pending_receive_packets = 0;

    // walk across packet entries and move any that are ready to be received into the pending receive buffer

    for ( let i = 0; i < NETCODE_NETWORK_SIMULATOR_NUM_PACKET_ENTRIES; i++ )
    {
        const entry = network_simulator.packet_entries[i];

        if ( !entry || !entry.packet_data )
            continue;

        if ( network_simulator.num_pending_receive_packets == NETCODE_NETWORK_SIMULATOR_NUM_PENDING_RECEIVE_PACKETS )
            break;

        if ( entry.delivery_time <= time )
        {
            // the entry moves to the pending buffer, and its slot is empty again
            network_simulator.pending_receive_packets[network_simulator.num_pending_receive_packets] = entry;
            network_simulator.num_pending_receive_packets++;
            network_simulator.packet_entries[i] = null;
        }
    }
}

// ----------------------------------------------------------------

// runtime guards of the public entry points. C ints cannot be fractional or NaN; JavaScript numbers can,
// so the range checks C does also reject those

function netcode_payload_bytes_valid( packet_data: Uint8Array, packet_bytes: number ): boolean
{
    return Number.isInteger( packet_bytes ) && packet_bytes > 0 && packet_bytes <= NETCODE_MAX_PACKET_SIZE && packet_bytes <= packet_data.length;
}

function netcode_server_client_index_valid( server: netcode_server_t, client_index: number ): boolean
{
    return Number.isInteger( client_index ) && client_index >= 0 && client_index < server.max_clients;
}

const netcode_empty_bytes = new Uint8Array( 0 );

// shared by the client and server send paths: dispatch a written packet to the network
// simulator, the send override, or the socket matching the destination address family

function netcode_send_packet_to_address( network_simulator: netcode_network_simulator_t | null,
                                         override_context: unknown,
                                         send_packet_override: netcode_send_packet_override_t | null,
                                         socket_holder: netcode_socket_holder_t,
                                         from: netcode_address_t,
                                         to: netcode_address_t,
                                         packet_data: Uint8Array,
                                         packet_bytes: number ): void
{
    if ( network_simulator )
    {
        netcode_network_simulator_send_packet( network_simulator, from, to, packet_data, packet_bytes );
    }
    else if ( send_packet_override )
    {
        send_packet_override( override_context, to, packet_data, packet_bytes );
    }
    else if ( to.type == NETCODE_ADDRESS_IPV4 )
    {
        netcode_socket_send_packet( socket_holder.ipv4, to, packet_data, packet_bytes );
    }
    else if ( to.type == NETCODE_ADDRESS_IPV6 )
    {
        netcode_socket_send_packet( socket_holder.ipv6, to, packet_data, packet_bytes );
    }
}

/** the current unix time in seconds, as C's (uint64_t) time( NULL ) */
function netcode_unix_time(): bigint
{
    return BigInt( Math.floor( Date.now() / 1000 ) );
}

// ----------------------------------------------------------------

export function netcode_client_state_name( client_state: number ): string
{
    switch ( client_state )
    {
        case NETCODE_CLIENT_STATE_CONNECT_TOKEN_EXPIRED:                return "connect token expired";
        case NETCODE_CLIENT_STATE_INVALID_CONNECT_TOKEN:                return "invalid connect token";
        case NETCODE_CLIENT_STATE_CONNECTION_TIMED_OUT:                 return "connection timed out";
        case NETCODE_CLIENT_STATE_CONNECTION_REQUEST_TIMED_OUT:         return "connection request timed out";
        case NETCODE_CLIENT_STATE_CONNECTION_RESPONSE_TIMED_OUT:        return "connection response timed out";
        case NETCODE_CLIENT_STATE_CONNECTION_DENIED:                    return "connection denied";
        case NETCODE_CLIENT_STATE_DISCONNECTED:                         return "disconnected";
        case NETCODE_CLIENT_STATE_SENDING_CONNECTION_REQUEST:           return "sending connection request";
        case NETCODE_CLIENT_STATE_SENDING_CONNECTION_RESPONSE:          return "sending connection response";
        case NETCODE_CLIENT_STATE_CONNECTED:                            return "connected";
        default:
            netcode_assert( 0 );
            return "???";
    }
}

export function netcode_default_client_config( config: netcode_client_config_t ): void
{
    netcode_assert( config );
    config.allocator_context = null;
    config.allocate_function = netcode_default_allocate_function;
    config.free_function = netcode_default_free_function;
    config.network_simulator = null;
    config.callback_context = null;
    config.state_change_callback = null;
    config.send_loopback_packet_callback = null;
    config.override_send_and_receive = 0;
    config.send_packet_override = null;
    config.receive_packet_override = null;
}

/** C copies the config struct. the client keeps its own copy */
function netcode_client_config_copy( config: netcode_client_config_t ): netcode_client_config_t
{
    const copy = new netcode_client_config_t();
    copy.allocator_context = config.allocator_context;
    copy.allocate_function = config.allocate_function;
    copy.free_function = config.free_function;
    copy.network_simulator = config.network_simulator;
    copy.callback_context = config.callback_context;
    copy.state_change_callback = config.state_change_callback;
    copy.send_loopback_packet_callback = config.send_loopback_packet_callback;
    copy.override_send_and_receive = config.override_send_and_receive;
    copy.send_packet_override = config.send_packet_override;
    copy.receive_packet_override = config.receive_packet_override;
    return copy;
}

export class netcode_client_t
{
    config = new netcode_client_config_t();
    state = 0;
    time = 0.0;
    connect_start_time = 0.0;
    last_packet_send_time = 0.0;
    last_packet_receive_time = 0.0;
    should_disconnect = 0;
    should_disconnect_state = 0;
    sequence = 0n;
    client_index = 0;
    max_clients = 0;
    server_address_index = 0;
    address = new netcode_address_t();
    server_address = new netcode_address_t();
    connect_token = new netcode_connect_token_t();
    socket_holder = new netcode_socket_holder_t();
    context = new netcode_context_t();
    replay_protection = new netcode_replay_protection_t();
    packet_receive_queue = new netcode_packet_queue_t();
    challenge_token_sequence = 0n;
    challenge_token_data = new Uint8Array( NETCODE_CHALLENGE_TOKEN_BYTES );
    receive_packet_data: ( Uint8Array | null )[] = new Array<Uint8Array | null>( NETCODE_CLIENT_MAX_RECEIVE_PACKETS ).fill( null );
    receive_packet_bytes = new Int32Array( NETCODE_CLIENT_MAX_RECEIVE_PACKETS );
    receive_from: netcode_address_t[] = new Array<netcode_address_t>( NETCODE_CLIENT_MAX_RECEIVE_PACKETS );
    loopback = 0;
    // scratch buffers (C keeps these on the stack)
    packet_buffer = new Uint8Array( NETCODE_MAX_PACKET_BYTES );
    receive_buffer = new Uint8Array( NETCODE_MAX_PACKET_BYTES );
    receive_address = new netcode_address_t();
    payload_packet = new netcode_connection_payload_packet_t();
}

const NETCODE_CLIENT_BYTES = 8192;

let client_create_error = 0;

export function netcode_client_create_error(): number
{
    return client_create_error;
}

export function netcode_client_socket_create( socket: netcode_socket_t,
                                              address: netcode_address_t,
                                              send_buffer_size: number,
                                              receive_buffer_size: number,
                                              config: netcode_client_config_t ): number
{
    netcode_assert( socket );
    netcode_assert( address );
    netcode_assert( config );

    if ( !config.network_simulator )
    {
        if ( !config.override_send_and_receive )
        {
            if ( netcode_socket_create( socket, address, send_buffer_size, receive_buffer_size ) != NETCODE_SOCKET_ERROR_NONE )
            {
                client_create_error = ( address.type == NETCODE_ADDRESS_IPV6 ) ? NETCODE_CLIENT_CREATE_ERROR_CREATE_SOCKET_IPV6_FAILED
                                                                               : NETCODE_CLIENT_CREATE_ERROR_CREATE_SOCKET_IPV4_FAILED;
                return 0;
            }
        }
    }
    else
    {
        if ( address.port == 0 )
        {
            netcode_printf( NETCODE_LOG_LEVEL_ERROR, "error: must bind to a specific port when using network simulator\n" );
            client_create_error = NETCODE_CLIENT_CREATE_ERROR_SIMULATOR_REQUIRES_PORT;
            return 0;
        }
    }

    return 1;
}

export function netcode_client_create_dual( address1_string: string,
                                            address2_string: string | null,
                                            config: netcode_client_config_t,
                                            time: number ): netcode_client_t | null
{
    netcode_assert( config );
    netcode_assert( netcode.initialized );

    client_create_error = NETCODE_CLIENT_CREATE_ERROR_NONE;

    // tolerate a zeroed config: default the allocator functions so a forgotten
    // netcode_default_client_config is an inconvenience, not a crash. the client keeps its own copy

    const config_copy = netcode_client_config_copy( config );
    if ( !config_copy.allocate_function )
        config_copy.allocate_function = netcode_default_allocate_function;
    if ( !config_copy.free_function )
        config_copy.free_function = netcode_default_free_function;
    config = config_copy;

    // the overrides are called on the update path with no null check. a missing one is a
    // configuration error, refused here rather than dereferenced on the first update.

    if ( config.override_send_and_receive && ( !config.send_packet_override || !config.receive_packet_override ) )
    {
        netcode_printf( NETCODE_LOG_LEVEL_ERROR, "error: override_send_and_receive requires both send_packet_override and receive_packet_override\n" );
        client_create_error = NETCODE_CLIENT_CREATE_ERROR_MISSING_OVERRIDE_CALLBACK;
        return null;
    }

    const address1 = new netcode_address_t();
    const address2 = new netcode_address_t();

    if ( netcode_parse_address( address1_string, address1 ) != NETCODE_OK )
    {
        netcode_printf( NETCODE_LOG_LEVEL_ERROR, "error: failed to parse client address\n" );
        client_create_error = NETCODE_CLIENT_CREATE_ERROR_PARSE_ADDRESS_FAILED;
        return null;
    }

    if ( address2_string != null && netcode_parse_address( address2_string, address2 ) != NETCODE_OK )
    {
        netcode_printf( NETCODE_LOG_LEVEL_ERROR, "error: failed to parse client address2\n" );
        client_create_error = NETCODE_CLIENT_CREATE_ERROR_PARSE_ADDRESS2_FAILED;
        return null;
    }

    const socket_ipv4 = new netcode_socket_t();
    const socket_ipv6 = new netcode_socket_t();

    if ( address1.type == NETCODE_ADDRESS_IPV4 || address2.type == NETCODE_ADDRESS_IPV4 )
    {
        if ( !netcode_client_socket_create( socket_ipv4, address1.type == NETCODE_ADDRESS_IPV4 ? address1 : address2, NETCODE_CLIENT_SOCKET_SNDBUF_SIZE, NETCODE_CLIENT_SOCKET_RCVBUF_SIZE, config ) )
        {
            return null;
        }
    }

    if ( address1.type == NETCODE_ADDRESS_IPV6 || address2.type == NETCODE_ADDRESS_IPV6 )
    {
        if ( !netcode_client_socket_create( socket_ipv6, address1.type == NETCODE_ADDRESS_IPV6 ? address1 : address2, NETCODE_CLIENT_SOCKET_SNDBUF_SIZE, NETCODE_CLIENT_SOCKET_RCVBUF_SIZE, config ) )
        {
            netcode_socket_destroy( socket_ipv4 );
            return null;
        }
    }

    if ( !config.allocate_function!( config.allocator_context, NETCODE_CLIENT_BYTES ) )
    {
        netcode_socket_destroy( socket_ipv4 );
        netcode_socket_destroy( socket_ipv6 );
        client_create_error = NETCODE_CLIENT_CREATE_ERROR_ALLOCATE_CLIENT_FAILED;
        return null;
    }

    const client = new netcode_client_t();

    const socket_address = address1.type == NETCODE_ADDRESS_IPV4 ? socket_ipv4.address : socket_ipv6.address;

    if ( !config.network_simulator )
    {
        netcode_printf( NETCODE_LOG_LEVEL_INFO, "client started on port %d\n", socket_address.port );
    }
    else
    {
        netcode_printf( NETCODE_LOG_LEVEL_INFO, "client started on port %d (network simulator)\n", socket_address.port );
    }

    client.config = config;
    client.socket_holder.ipv4 = socket_ipv4;
    client.socket_holder.ipv6 = socket_ipv6;
    netcode_address_copy( client.address, config.network_simulator ? address1 : socket_address );
    client.state = NETCODE_CLIENT_STATE_DISCONNECTED;
    client.time = time;
    client.connect_start_time = 0.0;
    client.last_packet_send_time = -1000.0;
    client.last_packet_receive_time = -1000.0;
    client.should_disconnect = 0;
    client.should_disconnect_state = NETCODE_CLIENT_STATE_DISCONNECTED;
    client.sequence = 0n;
    client.client_index = 0;
    client.max_clients = 0;
    client.server_address_index = 0;
    client.challenge_token_sequence = 0n;
    client.loopback = 0;
    netcode_address_zero( client.server_address );
    netcode_connect_token_zero( client.connect_token );
    sodium_memzero( client.context.write_packet_key );
    sodium_memzero( client.context.read_packet_key );
    client.challenge_token_data.fill( 0 );

    netcode_packet_queue_init( client.packet_receive_queue, config.allocator_context, config.allocate_function, config.free_function );

    netcode_replay_protection_reset( client.replay_protection );

    return client;
}

export function netcode_client_create( address: string, config: netcode_client_config_t, time: number ): netcode_client_t | null
{
    return netcode_client_create_dual( address, null, config, time );
}

export function netcode_client_destroy( client: netcode_client_t ): void
{
    netcode_assert( client );
    if ( !client.loopback )
        netcode_client_disconnect( client );
    else
        netcode_client_disconnect_loopback( client );
    netcode_socket_destroy( client.socket_holder.ipv4 );
    netcode_socket_destroy( client.socket_holder.ipv6 );
    netcode_packet_queue_clear( client.packet_receive_queue );
    client.config.free_function!( client.config.allocator_context, client );
}

export function netcode_client_set_state( client: netcode_client_t, client_state: number ): void
{
    netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "client changed state from '%s' to '%s'\n",
        netcode_client_state_name( client.state ), netcode_client_state_name( client_state ) );

    if ( client.config.state_change_callback )
    {
        client.config.state_change_callback( client.config.callback_context, client.state, client_state );
    }

    client.state = client_state;
}

export function netcode_client_reset_before_next_connect( client: netcode_client_t ): void
{
    client.connect_start_time = client.time;
    client.last_packet_send_time = client.time - 1.0;
    client.last_packet_receive_time = client.time;
    client.should_disconnect = 0;
    client.should_disconnect_state = NETCODE_CLIENT_STATE_DISCONNECTED;
    client.challenge_token_sequence = 0n;

    client.challenge_token_data.fill( 0 );

    netcode_replay_protection_reset( client.replay_protection );
}

export function netcode_client_reset_connection_data( client: netcode_client_t, client_state: number ): void
{
    netcode_assert( client );

    client.sequence = 0n;
    client.loopback = 0;
    client.client_index = 0;
    client.max_clients = 0;
    client.connect_start_time = 0.0;
    client.server_address_index = 0;
    netcode_address_zero( client.server_address );
    netcode_connect_token_zero( client.connect_token );
    sodium_memzero( client.context.write_packet_key );
    sodium_memzero( client.context.read_packet_key );

    netcode_client_set_state( client, client_state );

    netcode_client_reset_before_next_connect( client );

    netcode_packet_queue_clear( client.packet_receive_queue );
}

export function netcode_client_connect( client: netcode_client_t, connect_token: Uint8Array ): void
{
    netcode_assert( client );
    netcode_assert( connect_token );

    netcode_client_disconnect( client );

    if ( netcode_read_connect_token( connect_token, NETCODE_CONNECT_TOKEN_BYTES, client.connect_token ) != NETCODE_OK )
    {
        netcode_client_set_state( client, NETCODE_CLIENT_STATE_INVALID_CONNECT_TOKEN );
        return;
    }

    client.server_address_index = 0;
    netcode_address_copy( client.server_address, client.connect_token.server_addresses[0] );

    if ( client.connect_token.num_server_addresses == 1 )
    {
        netcode_printf( NETCODE_LOG_LEVEL_INFO, "client connecting to server %s\n",
            netcode_address_to_string( client.server_address ) );
    }
    else
    {
        netcode_printf( NETCODE_LOG_LEVEL_INFO, "client connecting to server %s [%d/%d]\n",
            netcode_address_to_string( client.server_address ), client.server_address_index + 1, client.connect_token.num_server_addresses );
    }

    client.context.read_packet_key.set( client.connect_token.server_to_client_key );
    client.context.write_packet_key.set( client.connect_token.client_to_server_key );

    netcode_client_reset_before_next_connect( client );

    netcode_client_set_state( client, NETCODE_CLIENT_STATE_SENDING_CONNECTION_REQUEST );
}

export function netcode_client_process_packet_internal( client: netcode_client_t, from: netcode_address_t, packet: netcode_packet_t, sequence: bigint ): void
{
    netcode_assert( client );
    netcode_assert( packet );

    const packet_type = packet.packet_type;

    switch ( packet_type )
    {
        case NETCODE_CONNECTION_DENIED_PACKET:
        {
            if ( ( client.state == NETCODE_CLIENT_STATE_SENDING_CONNECTION_REQUEST ||
                   client.state == NETCODE_CLIENT_STATE_SENDING_CONNECTION_RESPONSE )
                                                &&
                      netcode_address_equal( from, client.server_address ) )
            {
                client.should_disconnect = 1;
                client.should_disconnect_state = NETCODE_CLIENT_STATE_CONNECTION_DENIED;
                client.last_packet_receive_time = client.time;
            }
        }
        break;

        case NETCODE_CONNECTION_CHALLENGE_PACKET:
        {
            if ( client.state == NETCODE_CLIENT_STATE_SENDING_CONNECTION_REQUEST && netcode_address_equal( from, client.server_address ) )
            {
                netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "client received connection challenge packet from server\n" );

                const p = packet as netcode_connection_challenge_packet_t;
                client.challenge_token_sequence = p.challenge_token_sequence;
                client.challenge_token_data.set( p.challenge_token_data );
                client.last_packet_receive_time = client.time;

                netcode_client_set_state( client, NETCODE_CLIENT_STATE_SENDING_CONNECTION_RESPONSE );
            }
        }
        break;

        case NETCODE_CONNECTION_KEEP_ALIVE_PACKET:
        {
            if ( netcode_address_equal( from, client.server_address ) )
            {
                const p = packet as netcode_connection_keep_alive_packet_t;

                if ( client.state == NETCODE_CLIENT_STATE_CONNECTED )
                {
                    netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "client received connection keep alive packet from server\n" );

                    client.last_packet_receive_time = client.time;
                }
                else if ( client.state == NETCODE_CLIENT_STATE_SENDING_CONNECTION_RESPONSE )
                {
                    netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "client received connection keep alive packet from server\n" );

                    client.last_packet_receive_time = client.time;
                    client.client_index = p.client_index;
                    client.max_clients = p.max_clients;

                    netcode_client_set_state( client, NETCODE_CLIENT_STATE_CONNECTED );

                    netcode_printf( NETCODE_LOG_LEVEL_INFO, "client connected to server\n" );
                }
            }
        }
        break;

        case NETCODE_CONNECTION_PAYLOAD_PACKET:
        {
            if ( client.state == NETCODE_CLIENT_STATE_CONNECTED && netcode_address_equal( from, client.server_address ) )
            {
                netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "client received connection payload packet from server\n" );

                netcode_packet_queue_push( client.packet_receive_queue, packet, sequence );

                client.last_packet_receive_time = client.time;

                return;
            }
        }
        break;

        case NETCODE_CONNECTION_DISCONNECT_PACKET:
        {
            if ( client.state == NETCODE_CLIENT_STATE_CONNECTED && netcode_address_equal( from, client.server_address ) )
            {
                netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "client received disconnect packet from server\n" );

                client.should_disconnect = 1;
                client.should_disconnect_state = NETCODE_CLIENT_STATE_DISCONNECTED;
                client.last_packet_receive_time = client.time;
            }
        }
        break;

        default:
            break;
    }

    client.config.free_function!( client.config.allocator_context, packet );
}

const netcode_client_allowed_packets = ( () =>
{
    const allowed_packets = new Uint8Array( NETCODE_CONNECTION_NUM_PACKETS );
    allowed_packets[NETCODE_CONNECTION_DENIED_PACKET] = 1;
    allowed_packets[NETCODE_CONNECTION_CHALLENGE_PACKET] = 1;
    allowed_packets[NETCODE_CONNECTION_KEEP_ALIVE_PACKET] = 1;
    allowed_packets[NETCODE_CONNECTION_PAYLOAD_PACKET] = 1;
    allowed_packets[NETCODE_CONNECTION_DISCONNECT_PACKET] = 1;
    return allowed_packets;
} )();

/** processes a packet received through some other channel. packet_data is decrypted in place */
export function netcode_client_process_packet( client: netcode_client_t, from: netcode_address_t, packet_data: Uint8Array, packet_bytes: number ): void
{
    const current_timestamp = netcode_unix_time();

    const sequence = { value: 0n };

    const packet = netcode_read_packet( packet_data,
                                        packet_bytes,
                                        sequence,
                                        client.context.read_packet_key,
                                        client.connect_token.protocol_id,
                                        current_timestamp,
                                        0n,
                                        null,
                                        netcode_client_allowed_packets,
                                        client.replay_protection,
                                        client.config.allocator_context,
                                        client.config.allocate_function );

    if ( !packet )
        return;

    netcode_client_process_packet_internal( client, from, packet, sequence.value );
}

export function netcode_client_receive_packets( client: netcode_client_t ): void
{
    netcode_assert( client );
    netcode_assert( !client.loopback );

    if ( !client.config.network_simulator )
    {
        // process packets received from socket

        const from = client.receive_address;
        const packet_data = client.receive_buffer;

        while ( true )
        {
            netcode_address_zero( from );

            let packet_bytes = 0;

            if ( client.config.override_send_and_receive )
            {
                packet_bytes = client.config.receive_packet_override!( client.config.callback_context, from, packet_data, NETCODE_MAX_PACKET_BYTES );
            }
            else if ( client.server_address.type == NETCODE_ADDRESS_IPV4 )
            {
                packet_bytes = netcode_socket_receive_packet( client.socket_holder.ipv4, from, packet_data, NETCODE_MAX_PACKET_BYTES );
            }
            else if ( client.server_address.type == NETCODE_ADDRESS_IPV6 )
            {
                packet_bytes = netcode_socket_receive_packet( client.socket_holder.ipv6, from, packet_data, NETCODE_MAX_PACKET_BYTES );
            }

            if ( packet_bytes <= 0 )
                break;

            netcode_client_process_packet( client, from, packet_data, Math.min( packet_bytes, NETCODE_MAX_PACKET_BYTES ) );
        }
    }
    else
    {
        // process packets received from network simulator

        const num_packets_received = netcode_network_simulator_receive_packets( client.config.network_simulator,
                                                                                client.address,
                                                                                NETCODE_CLIENT_MAX_RECEIVE_PACKETS,
                                                                                client.receive_packet_data,
                                                                                client.receive_packet_bytes,
                                                                                client.receive_from );

        for ( let i = 0; i < num_packets_received; i++ )
        {
            const packet_data = client.receive_packet_data[i]!;

            netcode_client_process_packet( client, client.receive_from[i], packet_data, client.receive_packet_bytes[i] );

            client.config.free_function!( client.config.allocator_context, packet_data );

            client.receive_packet_data[i] = null;
        }
    }
}

export function netcode_client_send_packet_to_server_internal( client: netcode_client_t, packet: netcode_packet_t ): void
{
    netcode_assert( client );
    netcode_assert( !client.loopback );

    const packet_data = client.packet_buffer;

    const packet_bytes = netcode_write_packet( packet,
                                               packet_data,
                                               NETCODE_MAX_PACKET_BYTES,
                                               client.sequence,
                                               client.context.write_packet_key,
                                               client.connect_token.protocol_id );

    client.sequence = BigInt.asUintN( 64, client.sequence + 1n );

    netcode_assert( packet_bytes <= NETCODE_MAX_PACKET_BYTES );

    netcode_send_packet_to_address( client.config.network_simulator,
                                    client.config.callback_context,
                                    client.config.override_send_and_receive ? client.config.send_packet_override : null,
                                    client.socket_holder,
                                    client.address,
                                    client.server_address,
                                    packet_data,
                                    packet_bytes );

    client.last_packet_send_time = client.time;
}

export function netcode_client_send_packets( client: netcode_client_t ): void
{
    netcode_assert( client );
    netcode_assert( !client.loopback );

    switch ( client.state )
    {
        case NETCODE_CLIENT_STATE_SENDING_CONNECTION_REQUEST:
        {
            if ( client.last_packet_send_time + ( 1.0 / NETCODE_PACKET_SEND_RATE ) >= client.time )
                return;

            netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "client sent connection request packet to server\n" );

            const packet = new netcode_connection_request_packet_t();
            packet.packet_type = NETCODE_CONNECTION_REQUEST_PACKET;
            packet.version_info.set( NETCODE_VERSION_INFO );
            packet.protocol_id = client.connect_token.protocol_id;
            packet.connect_token_expire_timestamp = client.connect_token.expire_timestamp;
            packet.connect_token_nonce.set( client.connect_token.nonce );
            packet.connect_token_data.set( client.connect_token.private_data );

            netcode_client_send_packet_to_server_internal( client, packet );
        }
        break;

        case NETCODE_CLIENT_STATE_SENDING_CONNECTION_RESPONSE:
        {
            if ( client.last_packet_send_time + ( 1.0 / NETCODE_PACKET_SEND_RATE ) >= client.time )
                return;

            netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "client sent connection response packet to server\n" );

            const packet = new netcode_connection_response_packet_t();
            packet.packet_type = NETCODE_CONNECTION_RESPONSE_PACKET;
            packet.challenge_token_sequence = client.challenge_token_sequence;
            packet.challenge_token_data.set( client.challenge_token_data );

            netcode_client_send_packet_to_server_internal( client, packet );
        }
        break;

        case NETCODE_CLIENT_STATE_CONNECTED:
        {
            if ( client.last_packet_send_time + ( 1.0 / NETCODE_PACKET_SEND_RATE ) >= client.time )
                return;

            netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "client sent connection keep alive packet to server\n" );

            const packet = new netcode_connection_keep_alive_packet_t();
            packet.packet_type = NETCODE_CONNECTION_KEEP_ALIVE_PACKET;
            packet.client_index = 0;
            packet.max_clients = 0;

            netcode_client_send_packet_to_server_internal( client, packet );
        }
        break;

        default:
            break;
    }
}

export function netcode_client_connect_to_next_server( client: netcode_client_t ): number
{
    netcode_assert( client );

    if ( client.server_address_index + 1 >= client.connect_token.num_server_addresses )
    {
        netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "client has no more servers to connect to\n" );
        return 0;
    }

    client.server_address_index++;
    netcode_address_copy( client.server_address, client.connect_token.server_addresses[client.server_address_index] );

    netcode_client_reset_before_next_connect( client );

    netcode_printf( NETCODE_LOG_LEVEL_INFO, "client connecting to next server %s [%d/%d]\n",
        netcode_address_to_string( client.server_address ),
        client.server_address_index + 1,
        client.connect_token.num_server_addresses );

    netcode_client_set_state( client, NETCODE_CLIENT_STATE_SENDING_CONNECTION_REQUEST );

    return 1;
}

export function netcode_client_update( client: netcode_client_t, time: number ): void
{
    netcode_assert( client );

    client.time = time;

    if ( client.loopback )
        return;

    netcode_client_receive_packets( client );

    netcode_client_send_packets( client );

    if ( client.state > NETCODE_CLIENT_STATE_DISCONNECTED && client.state < NETCODE_CLIENT_STATE_CONNECTED )
    {
        const connect_token_expire_seconds = BigInt.asUintN( 64, client.connect_token.expire_timestamp - client.connect_token.create_timestamp );
        if ( client.time - client.connect_start_time >= Number( connect_token_expire_seconds ) )
        {
            netcode_printf( NETCODE_LOG_LEVEL_INFO, "client connect failed. connect token expired\n" );
            netcode_client_disconnect_internal( client, NETCODE_CLIENT_STATE_CONNECT_TOKEN_EXPIRED, 0 );
            return;
        }
    }

    if ( client.should_disconnect )
    {
        netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "client should disconnect -> %s\n", netcode_client_state_name( client.should_disconnect_state ) );
        if ( netcode_client_connect_to_next_server( client ) )
            return;
        netcode_client_disconnect_internal( client, client.should_disconnect_state, 0 );
        return;
    }

    switch ( client.state )
    {
        case NETCODE_CLIENT_STATE_SENDING_CONNECTION_REQUEST:
        {
            if ( client.connect_token.timeout_seconds > 0 && client.last_packet_receive_time + client.connect_token.timeout_seconds < time )
            {
                netcode_printf( NETCODE_LOG_LEVEL_INFO, "client connect failed. connection request timed out\n" );
                if ( netcode_client_connect_to_next_server( client ) )
                    return;
                netcode_client_disconnect_internal( client, NETCODE_CLIENT_STATE_CONNECTION_REQUEST_TIMED_OUT, 0 );
                return;
            }
        }
        break;

        case NETCODE_CLIENT_STATE_SENDING_CONNECTION_RESPONSE:
        {
            if ( client.connect_token.timeout_seconds > 0 && client.last_packet_receive_time + client.connect_token.timeout_seconds < time )
            {
                netcode_printf( NETCODE_LOG_LEVEL_INFO, "client connect failed. connection response timed out\n" );
                if ( netcode_client_connect_to_next_server( client ) )
                    return;
                netcode_client_disconnect_internal( client, NETCODE_CLIENT_STATE_CONNECTION_RESPONSE_TIMED_OUT, 0 );
                return;
            }
        }
        break;

        case NETCODE_CLIENT_STATE_CONNECTED:
        {
            if ( client.connect_token.timeout_seconds > 0 && client.last_packet_receive_time + client.connect_token.timeout_seconds < time )
            {
                netcode_printf( NETCODE_LOG_LEVEL_INFO, "client connection timed out\n" );
                netcode_client_disconnect_internal( client, NETCODE_CLIENT_STATE_CONNECTION_TIMED_OUT, 0 );
                return;
            }
        }
        break;

        default:
            break;
    }
}

export function netcode_client_next_packet_sequence( client: netcode_client_t ): bigint
{
    netcode_assert( client );
    return client.sequence;
}

export function netcode_client_send_packet( client: netcode_client_t, packet_data: Uint8Array, packet_bytes: number ): void
{
    netcode_assert( client );
    netcode_assert( packet_data );
    netcode_assert( packet_bytes > 0 );
    netcode_assert( packet_bytes <= NETCODE_MAX_PACKET_SIZE );

    // zero byte payloads are not valid on the wire and would silently vanish at the receiver

    if ( !netcode_payload_bytes_valid( packet_data, packet_bytes ) )
    {
        netcode_printf( NETCODE_LOG_LEVEL_ERROR, "error: payload packet size is out of range (%d)\n", packet_bytes );
        return;
    }

    if ( client.state != NETCODE_CLIENT_STATE_CONNECTED )
        return;

    if ( !client.loopback )
    {
        const packet = client.payload_packet;

        packet.packet_type = NETCODE_CONNECTION_PAYLOAD_PACKET;
        packet.payload_bytes = packet_bytes;
        packet.payload_data = packet_data;

        netcode_client_send_packet_to_server_internal( client, packet );

        packet.payload_data = netcode_empty_bytes;
    }
    else
    {
        const sequence = client.sequence;
        client.sequence = BigInt.asUintN( 64, sequence + 1n );

        client.config.send_loopback_packet_callback!( client.config.callback_context,
                                                      client.client_index,
                                                      packet_data,
                                                      packet_bytes,
                                                      sequence );
    }
}

/** returns a view of exactly the payload, or null. pass the view to netcode_client_free_packet */
export function netcode_client_receive_packet( client: netcode_client_t, packet_bytes: { value: number }, packet_sequence: { value: bigint } | null ): Uint8Array | null
{
    netcode_assert( client );
    netcode_assert( packet_bytes );

    const packet = netcode_packet_queue_pop( client.packet_receive_queue, packet_sequence ) as netcode_connection_payload_packet_t | null;

    if ( packet )
    {
        netcode_assert( packet.packet_type == NETCODE_CONNECTION_PAYLOAD_PACKET );
        packet_bytes.value = packet.payload_bytes;
        netcode_assert( packet_bytes.value >= 0 );
        netcode_assert( packet_bytes.value <= NETCODE_MAX_PAYLOAD_BYTES );
        return packet.payload_data;
    }
    else
    {
        return null;
    }
}

export function netcode_client_free_packet( client: netcode_client_t, packet: Uint8Array ): void
{
    netcode_assert( client );
    netcode_assert( packet );
    const payload_packet = netcode_payload_packets.get( packet );
    netcode_assert( payload_packet );
    netcode_payload_packets.delete( packet );
    client.config.free_function!( client.config.allocator_context, payload_packet ?? packet );
}

export function netcode_client_disconnect( client: netcode_client_t ): void
{
    netcode_assert( client );
    netcode_assert( !client.loopback );
    netcode_client_disconnect_internal( client, NETCODE_CLIENT_STATE_DISCONNECTED, 1 );
}

export function netcode_client_disconnect_internal( client: netcode_client_t, destination_state: number, send_disconnect_packets: number ): void
{
    netcode_assert( !client.loopback );
    netcode_assert( destination_state <= NETCODE_CLIENT_STATE_DISCONNECTED );

    if ( client.state <= NETCODE_CLIENT_STATE_DISCONNECTED || client.state == destination_state )
        return;

    netcode_printf( NETCODE_LOG_LEVEL_INFO, "client disconnected\n" );

    if ( !client.loopback && send_disconnect_packets && client.state > NETCODE_CLIENT_STATE_DISCONNECTED )
    {
        netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "client sent disconnect packets to server\n" );

        for ( let i = 0; i < NETCODE_NUM_DISCONNECT_PACKETS; i++ )
        {
            netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "client sent disconnect packet %d\n", i );

            const packet = new netcode_connection_disconnect_packet_t();
            packet.packet_type = NETCODE_CONNECTION_DISCONNECT_PACKET;

            netcode_client_send_packet_to_server_internal( client, packet );
        }
    }

    netcode_client_reset_connection_data( client, destination_state );
}

export function netcode_client_state( client: netcode_client_t ): number
{
    netcode_assert( client );
    return client.state;
}

export function netcode_client_index( client: netcode_client_t ): number
{
    netcode_assert( client );
    return client.client_index;
}

export function netcode_client_max_clients( client: netcode_client_t ): number
{
    netcode_assert( client );
    return client.max_clients;
}

export function netcode_client_connect_loopback( client: netcode_client_t, client_index: number, max_clients: number ): void
{
    netcode_assert( client );
    netcode_assert( client.state <= NETCODE_CLIENT_STATE_DISCONNECTED );

    // a loopback client sends only through this callback. without it the first send would
    // call a null pointer, so refuse to enter loopback at all, in every build.

    netcode_assert( client.config.send_loopback_packet_callback );

    if ( !client.config.send_loopback_packet_callback )
    {
        netcode_printf( NETCODE_LOG_LEVEL_ERROR, "error: a loopback client requires send_loopback_packet_callback\n" );
        return;
    }

    netcode_printf( NETCODE_LOG_LEVEL_INFO, "client connected to server via loopback as client %d\n", client_index );
    client.state = NETCODE_CLIENT_STATE_CONNECTED;
    client.client_index = client_index;
    client.max_clients = max_clients;
    client.loopback = 1;
}

export function netcode_client_disconnect_loopback( client: netcode_client_t ): void
{
    netcode_assert( client );
    netcode_assert( client.loopback );
    netcode_client_reset_connection_data( client, NETCODE_CLIENT_STATE_DISCONNECTED );
}

export function netcode_client_loopback( client: netcode_client_t ): number
{
    netcode_assert( client );
    return client.loopback;
}

export function netcode_client_process_loopback_packet( client: netcode_client_t, packet_data: Uint8Array, packet_bytes: number, packet_sequence: bigint ): void
{
    netcode_assert( client );
    netcode_assert( client.loopback );
    netcode_assert( packet_data );
    netcode_assert( packet_bytes > 0 );
    netcode_assert( packet_bytes <= NETCODE_MAX_PACKET_SIZE );

    if ( !client.loopback )
        return;

    if ( !netcode_payload_bytes_valid( packet_data, packet_bytes ) )
        return;

    const packet = netcode_create_payload_packet( packet_bytes, client.config.allocator_context, client.config.allocate_function );
    if ( !packet )
        return;
    packet.payload_data.set( packet_data.subarray( 0, packet_bytes ) );
    netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "client processing loopback packet from server\n" );
    netcode_packet_queue_push( client.packet_receive_queue, packet, packet_sequence );
}

export function netcode_client_get_port( client: netcode_client_t ): number
{
    netcode_assert( client );
    return client.address.type == NETCODE_ADDRESS_IPV4 ? client.socket_holder.ipv4.address.port : client.socket_holder.ipv6.address.port;
}

/** the client's own server address (live, like the C pointer) */
export function netcode_client_server_address( client: netcode_client_t ): netcode_address_t
{
    netcode_assert( client );
    return client.server_address;
}

// ----------------------------------------------------------------

export const NETCODE_MAX_ENCRYPTION_MAPPINGS = NETCODE_MAX_CLIENTS * 4;

export class netcode_encryption_manager_t
{
    num_encryption_mappings = 0;
    timeout = new Int32Array( NETCODE_MAX_ENCRYPTION_MAPPINGS );
    expire_time = new Float64Array( NETCODE_MAX_ENCRYPTION_MAPPINGS );
    last_access_time = new Float64Array( NETCODE_MAX_ENCRYPTION_MAPPINGS );
    address: netcode_address_t[] = netcode_address_array( NETCODE_MAX_ENCRYPTION_MAPPINGS );
    client_index = new Int32Array( NETCODE_MAX_ENCRYPTION_MAPPINGS );
    connect_token_entry_index = new Int32Array( NETCODE_MAX_ENCRYPTION_MAPPINGS );
    send_key = new Uint8Array( NETCODE_KEY_BYTES * NETCODE_MAX_ENCRYPTION_MAPPINGS );
    receive_key = new Uint8Array( NETCODE_KEY_BYTES * NETCODE_MAX_ENCRYPTION_MAPPINGS );
}

export function netcode_encryption_manager_reset( encryption_manager: netcode_encryption_manager_t ): void
{
    netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "reset encryption manager\n" );

    netcode_assert( encryption_manager );

    encryption_manager.num_encryption_mappings = 0;

    for ( let i = 0; i < NETCODE_MAX_ENCRYPTION_MAPPINGS; i++ )
    {
        encryption_manager.client_index[i] = -1;
        encryption_manager.connect_token_entry_index[i] = -1;
        encryption_manager.expire_time[i] = -1.0;
        encryption_manager.last_access_time[i] = -1000.0;
        netcode_address_zero( encryption_manager.address[i] );
    }

    encryption_manager.timeout.fill( 0 );
    sodium_memzero( encryption_manager.send_key );
    sodium_memzero( encryption_manager.receive_key );
}

export function netcode_encryption_manager_entry_expired( encryption_manager: netcode_encryption_manager_t, index: number, time: number ): number
{
    return ( ( encryption_manager.timeout[index] > 0 && ( encryption_manager.last_access_time[index] + encryption_manager.timeout[index] ) < time ) ||
             ( encryption_manager.expire_time[index] >= 0.0 && encryption_manager.expire_time[index] < time ) ) ? 1 : 0;
}

export function netcode_encryption_manager_add_encryption_mapping( encryption_manager: netcode_encryption_manager_t,
                                                                   address: netcode_address_t,
                                                                   send_key: Uint8Array,
                                                                   receive_key: Uint8Array,
                                                                   time: number,
                                                                   expire_time: number,
                                                                   timeout: number,
                                                                   connect_token_entry_index: number ): number
{
    for ( let i = 0; i < encryption_manager.num_encryption_mappings; i++ )
    {
        if ( netcode_address_equal( encryption_manager.address[i], address ) && !netcode_encryption_manager_entry_expired( encryption_manager, i, time ) )
        {
            encryption_manager.timeout[i] = timeout;
            encryption_manager.expire_time[i] = expire_time;
            encryption_manager.last_access_time[i] = time;
            encryption_manager.connect_token_entry_index[i] = connect_token_entry_index;
            encryption_manager.send_key.set( send_key.subarray( 0, NETCODE_KEY_BYTES ), i * NETCODE_KEY_BYTES );
            encryption_manager.receive_key.set( receive_key.subarray( 0, NETCODE_KEY_BYTES ), i * NETCODE_KEY_BYTES );
            return 1;
        }
    }

    for ( let i = 0; i < NETCODE_MAX_ENCRYPTION_MAPPINGS; i++ )
    {
        if ( encryption_manager.address[i].type == NETCODE_ADDRESS_NONE ||
            ( netcode_encryption_manager_entry_expired( encryption_manager, i, time ) && encryption_manager.client_index[i] == -1 ) )
        {
            encryption_manager.timeout[i] = timeout;
            netcode_address_copy( encryption_manager.address[i], address );
            encryption_manager.expire_time[i] = expire_time;
            encryption_manager.last_access_time[i] = time;
            encryption_manager.connect_token_entry_index[i] = connect_token_entry_index;
            encryption_manager.send_key.set( send_key.subarray( 0, NETCODE_KEY_BYTES ), i * NETCODE_KEY_BYTES );
            encryption_manager.receive_key.set( receive_key.subarray( 0, NETCODE_KEY_BYTES ), i * NETCODE_KEY_BYTES );
            if ( i + 1 > encryption_manager.num_encryption_mappings )
                encryption_manager.num_encryption_mappings = i + 1;
            return 1;
        }
    }

    return 0;
}

export function netcode_encryption_manager_remove_encryption_mapping( encryption_manager: netcode_encryption_manager_t, address: netcode_address_t, time: number ): number
{
    netcode_assert( encryption_manager );
    netcode_assert( address );

    for ( let i = 0; i < encryption_manager.num_encryption_mappings; i++ )
    {
        if ( netcode_address_equal( encryption_manager.address[i], address ) )
        {
            encryption_manager.expire_time[i] = -1.0;
            encryption_manager.last_access_time[i] = -1000.0;
            encryption_manager.connect_token_entry_index[i] = -1;
            netcode_address_zero( encryption_manager.address[i] );
            encryption_manager.send_key.fill( 0, i * NETCODE_KEY_BYTES, ( i + 1 ) * NETCODE_KEY_BYTES );
            encryption_manager.receive_key.fill( 0, i * NETCODE_KEY_BYTES, ( i + 1 ) * NETCODE_KEY_BYTES );

            if ( i + 1 == encryption_manager.num_encryption_mappings )
            {
                let index = i - 1;
                while ( index >= 0 )
                {
                    if ( !netcode_encryption_manager_entry_expired( encryption_manager, index, time ) || encryption_manager.client_index[index] != -1 )
                    {
                        break;
                    }
                    encryption_manager.address[index].type = NETCODE_ADDRESS_NONE;
                    index--;
                }
                encryption_manager.num_encryption_mappings = index + 1;
            }

            return 1;
        }
    }

    return 0;
}

export function netcode_encryption_manager_find_encryption_mapping( encryption_manager: netcode_encryption_manager_t, address: netcode_address_t, time: number ): number
{
    for ( let i = 0; i < encryption_manager.num_encryption_mappings; i++ )
    {
        if ( netcode_address_equal( encryption_manager.address[i], address ) && !netcode_encryption_manager_entry_expired( encryption_manager, i, time ) )
        {
            encryption_manager.last_access_time[i] = time;
            return i;
        }
    }
    return -1;
}

export function netcode_encryption_manager_touch( encryption_manager: netcode_encryption_manager_t, index: number, address: netcode_address_t, time: number ): number
{
    netcode_assert( index >= 0 );
    netcode_assert( index < encryption_manager.num_encryption_mappings );
    if ( index < 0 || index >= NETCODE_MAX_ENCRYPTION_MAPPINGS )
        return 0;
    if ( !netcode_address_equal( encryption_manager.address[index], address ) )
        return 0;
    encryption_manager.last_access_time[index] = time;
    return 1;
}

export function netcode_encryption_manager_set_expire_time( encryption_manager: netcode_encryption_manager_t, index: number, expire_time: number ): void
{
    netcode_assert( index >= 0 );
    netcode_assert( index < encryption_manager.num_encryption_mappings );
    encryption_manager.expire_time[index] = expire_time;
}

/** a view of the key in the manager, or null */
export function netcode_encryption_manager_get_send_key( encryption_manager: netcode_encryption_manager_t, index: number ): Uint8Array | null
{
    netcode_assert( encryption_manager );
    if ( index == -1 )
        return null;
    netcode_assert( index >= 0 );
    netcode_assert( index < encryption_manager.num_encryption_mappings );
    return encryption_manager.send_key.subarray( index * NETCODE_KEY_BYTES, ( index + 1 ) * NETCODE_KEY_BYTES );
}

/** a view of the key in the manager, or null */
export function netcode_encryption_manager_get_receive_key( encryption_manager: netcode_encryption_manager_t, index: number ): Uint8Array | null
{
    netcode_assert( encryption_manager );
    if ( index == -1 )
        return null;
    netcode_assert( index >= 0 );
    netcode_assert( index < encryption_manager.num_encryption_mappings );
    return encryption_manager.receive_key.subarray( index * NETCODE_KEY_BYTES, ( index + 1 ) * NETCODE_KEY_BYTES );
}

export function netcode_encryption_manager_get_timeout( encryption_manager: netcode_encryption_manager_t, index: number ): number
{
    netcode_assert( encryption_manager );
    if ( index == -1 )
        return 0;
    netcode_assert( index >= 0 );
    netcode_assert( index < encryption_manager.num_encryption_mappings );
    return encryption_manager.timeout[index];
}

export function netcode_encryption_manager_get_connect_token_entry_index( encryption_manager: netcode_encryption_manager_t, index: number ): number
{
    netcode_assert( encryption_manager );
    if ( index == -1 )
        return -1;
    netcode_assert( index >= 0 );
    netcode_assert( index < encryption_manager.num_encryption_mappings );
    return encryption_manager.connect_token_entry_index[index];
}

// ----------------------------------------------------------------

export const NETCODE_MAX_CONNECT_TOKEN_ENTRIES = NETCODE_MAX_CLIENTS * 8;

export const NETCODE_CONNECT_TOKEN_ENTRY_FREE = 0;
export const NETCODE_CONNECT_TOKEN_ENTRY_PENDING = 1;
export const NETCODE_CONNECT_TOKEN_ENTRY_CONSUMED = 2;

export const NETCODE_CONNECT_TOKEN_ENTRY_REFUSED = -1;
export const NETCODE_CONNECT_TOKEN_HISTORY_FULL = -2;

export class netcode_connect_token_entry_t
{
    state = NETCODE_CONNECT_TOKEN_ENTRY_FREE;
    time = 0.0;                    // server time the entry was created. never refreshed afterwards
    expire_timestamp = 0n;         // when the connect token expires, and with it this entry
    mac = new Uint8Array( NETCODE_MAC_BYTES );
    address = new netcode_address_t();
}

export function netcode_connect_token_entries_create(): netcode_connect_token_entry_t[]
{
    const connect_token_entries = new Array<netcode_connect_token_entry_t>( NETCODE_MAX_CONNECT_TOKEN_ENTRIES );
    for ( let i = 0; i < NETCODE_MAX_CONNECT_TOKEN_ENTRIES; i++ )
        connect_token_entries[i] = new netcode_connect_token_entry_t();
    netcode_connect_token_entries_reset( connect_token_entries );
    return connect_token_entries;
}

export function netcode_connect_token_entries_reset( connect_token_entries: netcode_connect_token_entry_t[] ): void
{
    for ( let i = 0; i < NETCODE_MAX_CONNECT_TOKEN_ENTRIES; i++ )
    {
        const entry = connect_token_entries[i];
        entry.state = NETCODE_CONNECT_TOKEN_ENTRY_FREE;
        entry.time = -1000.0;
        entry.expire_timestamp = 0n;
        entry.mac.fill( 0 );
        netcode_address_zero( entry.address );
    }
}

function netcode_mac_equal( a: Uint8Array, b: Uint8Array ): boolean
{
    for ( let i = 0; i < NETCODE_MAC_BYTES; i++ )
    {
        if ( a[i] != b[i] )
            return false;
    }
    return true;
}

/*
    Returns the index of the entry that admits this connection request, or one of
    NETCODE_CONNECT_TOKEN_ENTRY_REFUSED and NETCODE_CONNECT_TOKEN_HISTORY_FULL.

    An entry is created pending the first time a connect token is seen, and becomes consumed
    when the client that presented it is installed in a client slot. A pending entry admits
    a retransmitted connection request from the address that created it, so a handshake that
    loses a packet still completes. A consumed entry admits nothing, whatever the address, so
    the keys inside a connect token encrypt exactly one session.

    An entry lives until its connect token expires. A history whose entries all hold unexpired
    connect tokens refuses a new connect token instead of evicting one, because evicting is
    how a flood of connect tokens would reopen a token that has already been used.
*/

export function netcode_connect_token_entries_find_or_add( connect_token_entries: netcode_connect_token_entry_t[],
                                                           address: netcode_address_t,
                                                           mac: Uint8Array,
                                                           expire_timestamp: bigint,
                                                           current_timestamp: bigint,
                                                           time: number ): number
{
    netcode_assert( connect_token_entries );
    netcode_assert( address );
    netcode_assert( mac );

    // find the matching entry for the token mac and the first entry free to take a new token.
    // constant time worst case. This is intentional!

    let matching_token_index = -1;
    let free_token_index = -1;

    for ( let i = 0; i < NETCODE_MAX_CONNECT_TOKEN_ENTRIES; i++ )
    {
        const entry = connect_token_entries[i];

        if ( entry.state != NETCODE_CONNECT_TOKEN_ENTRY_FREE &&
             netcode_mac_equal( mac, entry.mac ) )
        {
            matching_token_index = i;
        }

        if ( free_token_index == -1 &&
             ( entry.state == NETCODE_CONNECT_TOKEN_ENTRY_FREE ||
               entry.expire_timestamp <= current_timestamp ) )
        {
            free_token_index = i;
        }
    }

    // if no entry is found with the mac, this is a new connect token

    if ( matching_token_index == -1 )
    {
        if ( free_token_index == -1 )
            return NETCODE_CONNECT_TOKEN_HISTORY_FULL;

        const entry = connect_token_entries[free_token_index];
        entry.state = NETCODE_CONNECT_TOKEN_ENTRY_PENDING;
        entry.time = time;
        entry.expire_timestamp = expire_timestamp;
        netcode_address_copy( entry.address, address );
        entry.mac.set( mac.subarray( 0, NETCODE_MAC_BYTES ) );
        return free_token_index;
    }

    // a pending entry admits the address that created it, and nothing else. a consumed entry admits nothing.
    // the entry time is set when the entry is created and is never refreshed.

    netcode_assert( matching_token_index >= 0 );
    netcode_assert( matching_token_index < NETCODE_MAX_CONNECT_TOKEN_ENTRIES );

    if ( connect_token_entries[matching_token_index].state == NETCODE_CONNECT_TOKEN_ENTRY_PENDING &&
         netcode_address_equal( connect_token_entries[matching_token_index].address, address ) )
    {
        return matching_token_index;
    }

    return NETCODE_CONNECT_TOKEN_ENTRY_REFUSED;
}

export function netcode_connect_token_entries_consume( connect_token_entries: netcode_connect_token_entry_t[], index: number ): void
{
    netcode_assert( connect_token_entries );
    netcode_assert( index >= 0 );
    netcode_assert( index < NETCODE_MAX_CONNECT_TOKEN_ENTRIES );

    connect_token_entries[index].state = NETCODE_CONNECT_TOKEN_ENTRY_CONSUMED;
}

/** FNV-1a 64. C: typedef uint64_t netcode_fnv_t, passed by pointer */
export class netcode_fnv_t
{
    value = 0n;
}

export function netcode_fnv_init( fnv: netcode_fnv_t ): void
{
    fnv.value = 0xCBF29CE484222325n;
}

export function netcode_fnv_write( fnv: netcode_fnv_t, data: Uint8Array, size: number ): void
{
    let value = fnv.value;
    for ( let i = 0; i < size; i++ )
    {
        value ^= BigInt( data[i] );
        value = BigInt.asUintN( 64, value * 0x00000100000001B3n );
    }
    fnv.value = value;
}

export function netcode_fnv_finalize( fnv: netcode_fnv_t ): bigint
{
    return fnv.value;
}

/** hashes the UTF-8 bytes of the string (C hashes its char bytes) */
export function netcode_hash_string( string: string ): bigint
{
    const fnv = new netcode_fnv_t();
    netcode_fnv_init( fnv );
    const data = new TextEncoder().encode( string );
    netcode_fnv_write( fnv, data, data.length );
    return netcode_fnv_finalize( fnv );
}

export function netcode_hash_data( data: Uint8Array, size: number ): bigint
{
    const fnv = new netcode_fnv_t();
    netcode_fnv_init( fnv );
    netcode_fnv_write( fnv, data, size );
    return netcode_fnv_finalize( fnv );
}

// ----------------------------------------------------------------

export const NETCODE_SERVER_FLAG_IGNORE_CONNECTION_REQUEST_PACKETS = 1;
export const NETCODE_SERVER_FLAG_IGNORE_CONNECTION_RESPONSE_PACKETS = 1 << 1;

export function netcode_default_server_config( config: netcode_server_config_t ): void
{
    netcode_assert( config );
    config.max_connect_token_lifetime = NETCODE_DEFAULT_MAX_CONNECT_TOKEN_LIFETIME;
    config.allocator_context = null;
    config.allocate_function = netcode_default_allocate_function;
    config.free_function = netcode_default_free_function;
    config.network_simulator = null;
    config.callback_context = null;
    config.connect_disconnect_callback = null;
    config.send_loopback_packet_callback = null;
    config.override_send_and_receive = 0;
    config.send_packet_override = null;
    config.receive_packet_override = null;
}

/** C copies the config struct, private key included. the server keeps its own copy */
function netcode_server_config_copy( config: netcode_server_config_t ): netcode_server_config_t
{
    const copy = new netcode_server_config_t();
    copy.protocol_id = BigInt.asUintN( 64, config.protocol_id );
    if ( config.private_key )
        copy.private_key.set( config.private_key.subarray( 0, NETCODE_KEY_BYTES ) );
    copy.allocator_context = config.allocator_context;
    copy.allocate_function = config.allocate_function;
    copy.free_function = config.free_function;
    copy.network_simulator = config.network_simulator;
    copy.callback_context = config.callback_context;
    copy.connect_disconnect_callback = config.connect_disconnect_callback;
    copy.send_loopback_packet_callback = config.send_loopback_packet_callback;
    copy.override_send_and_receive = config.override_send_and_receive;
    copy.send_packet_override = config.send_packet_override;
    copy.receive_packet_override = config.receive_packet_override;
    copy.max_connect_token_lifetime = config.max_connect_token_lifetime;
    return copy;
}

export class netcode_server_t
{
    config = new netcode_server_config_t();
    socket_holder = new netcode_socket_holder_t();
    address = new netcode_address_t();
    address2 = new netcode_address_t();
    flags = 0;
    time = 0.0;
    running = 0;
    max_clients = 0;
    num_connected_clients = 0;
    global_sequence = 0n;
    challenge_sequence = 0n;
    min_connect_token_expire_timestamp = 0n;
    challenge_key = new Uint8Array( NETCODE_KEY_BYTES );
    client_connected = new Int32Array( NETCODE_MAX_CLIENTS );
    client_timeout = new Int32Array( NETCODE_MAX_CLIENTS );
    client_loopback = new Int32Array( NETCODE_MAX_CLIENTS );
    client_confirmed = new Int32Array( NETCODE_MAX_CLIENTS );
    client_disconnect_reason = new Int32Array( NETCODE_MAX_CLIENTS );
    client_encryption_index = new Int32Array( NETCODE_MAX_CLIENTS );
    client_id = new BigUint64Array( NETCODE_MAX_CLIENTS );
    client_sequence = new BigUint64Array( NETCODE_MAX_CLIENTS );
    client_last_packet_send_time = new Float64Array( NETCODE_MAX_CLIENTS );
    client_last_packet_receive_time = new Float64Array( NETCODE_MAX_CLIENTS );
    client_user_data: Uint8Array[];
    client_replay_protection: netcode_replay_protection_t[];
    client_packet_queue: netcode_packet_queue_t[];
    client_address: netcode_address_t[] = netcode_address_array( NETCODE_MAX_CLIENTS );
    connect_token_entries: netcode_connect_token_entry_t[] = netcode_connect_token_entries_create();
    encryption_manager = new netcode_encryption_manager_t();
    receive_packet_data: ( Uint8Array | null )[] = new Array<Uint8Array | null>( NETCODE_SERVER_MAX_RECEIVE_PACKETS ).fill( null );
    receive_packet_bytes = new Int32Array( NETCODE_SERVER_MAX_RECEIVE_PACKETS );
    receive_from: netcode_address_t[] = new Array<netcode_address_t>( NETCODE_SERVER_MAX_RECEIVE_PACKETS );
    // scratch buffers (C keeps these on the stack)
    packet_buffer = new Uint8Array( NETCODE_MAX_PACKET_BYTES );
    receive_buffer = new Uint8Array( NETCODE_MAX_PACKET_BYTES );
    receive_address = new netcode_address_t();
    payload_packet = new netcode_connection_payload_packet_t();

    constructor()
    {
        const user_data = new Uint8Array( NETCODE_MAX_CLIENTS * NETCODE_USER_DATA_BYTES );
        this.client_user_data = new Array<Uint8Array>( NETCODE_MAX_CLIENTS );
        this.client_replay_protection = new Array<netcode_replay_protection_t>( NETCODE_MAX_CLIENTS );
        this.client_packet_queue = new Array<netcode_packet_queue_t>( NETCODE_MAX_CLIENTS );
        for ( let i = 0; i < NETCODE_MAX_CLIENTS; i++ )
        {
            this.client_user_data[i] = user_data.subarray( i * NETCODE_USER_DATA_BYTES, ( i + 1 ) * NETCODE_USER_DATA_BYTES );
            this.client_replay_protection[i] = new netcode_replay_protection_t();
            this.client_packet_queue[i] = new netcode_packet_queue_t();
        }
    }
}

const NETCODE_SERVER_BYTES = 1 << 20;

let server_create_error = 0;

export function netcode_server_create_error(): number
{
    return server_create_error;
}

export function netcode_server_socket_create( socket: netcode_socket_t,
                                              address: netcode_address_t,
                                              send_buffer_size: number,
                                              receive_buffer_size: number,
                                              config: netcode_server_config_t ): number
{
    netcode_assert( socket );
    netcode_assert( address );
    netcode_assert( config );

    if ( !config.network_simulator )
    {
        if ( !config.override_send_and_receive )
        {
            const socket_error = netcode_socket_create( socket, address, send_buffer_size, receive_buffer_size );

            if ( socket_error != NETCODE_SOCKET_ERROR_NONE )
            {
                // report bind failures separately: a port already in use is the common
                // operational failure for dedicated servers, and callers want to react
                // to it differently than to a socket that could not be created at all

                if ( socket_error == NETCODE_SOCKET_ERROR_BIND_IPV4_FAILED || socket_error == NETCODE_SOCKET_ERROR_BIND_IPV6_FAILED )
                {
                    server_create_error = ( address.type == NETCODE_ADDRESS_IPV6 ) ? NETCODE_SERVER_CREATE_ERROR_BIND_SOCKET_IPV6_FAILED
                                                                                   : NETCODE_SERVER_CREATE_ERROR_BIND_SOCKET_IPV4_FAILED;
                }
                else
                {
                    server_create_error = ( address.type == NETCODE_ADDRESS_IPV6 ) ? NETCODE_SERVER_CREATE_ERROR_CREATE_SOCKET_IPV6_FAILED
                                                                                   : NETCODE_SERVER_CREATE_ERROR_CREATE_SOCKET_IPV4_FAILED;
                }
                return 0;
            }
        }
    }

    return 1;
}

export function netcode_server_create_dual( server_address1_string: string, server_address2_string: string | null, config: netcode_server_config_t, time: number ): netcode_server_t | null
{
    netcode_assert( config );
    netcode_assert( netcode.initialized );

    server_create_error = NETCODE_SERVER_CREATE_ERROR_NONE;

    // tolerate a zeroed config: default the allocator functions so a forgotten
    // netcode_default_server_config is an inconvenience, not a crash. the server keeps its own copy

    const config_copy = netcode_server_config_copy( config );
    if ( !config_copy.allocate_function )
        config_copy.allocate_function = netcode_default_allocate_function;
    if ( !config_copy.free_function )
        config_copy.free_function = netcode_default_free_function;
    if ( config_copy.max_connect_token_lifetime <= 0 )
        config_copy.max_connect_token_lifetime = NETCODE_DEFAULT_MAX_CONNECT_TOKEN_LIFETIME;
    config = config_copy;

    // the overrides are called on the update path with no null check. a missing one is a
    // configuration error, refused here rather than dereferenced on the first update.

    if ( config.override_send_and_receive && ( !config.send_packet_override || !config.receive_packet_override ) )
    {
        netcode_printf( NETCODE_LOG_LEVEL_ERROR, "error: override_send_and_receive requires both send_packet_override and receive_packet_override\n" );
        server_create_error = NETCODE_SERVER_CREATE_ERROR_MISSING_OVERRIDE_CALLBACK;
        return null;
    }

    const server_address1 = new netcode_address_t();
    const server_address2 = new netcode_address_t();

    if ( netcode_parse_address( server_address1_string, server_address1 ) != NETCODE_OK )
    {
        netcode_printf( NETCODE_LOG_LEVEL_ERROR, "error: failed to parse server public address\n" );
        server_create_error = NETCODE_SERVER_CREATE_ERROR_PARSE_ADDRESS_FAILED;
        return null;
    }

    if ( server_address2_string != null && netcode_parse_address( server_address2_string, server_address2 ) != NETCODE_OK )
    {
        netcode_printf( NETCODE_LOG_LEVEL_ERROR, "error: failed to parse server public address2\n" );
        server_create_error = NETCODE_SERVER_CREATE_ERROR_PARSE_ADDRESS2_FAILED;
        return null;
    }

    const bind_address_ipv4 = new netcode_address_t();
    const bind_address_ipv6 = new netcode_address_t();

    const socket_ipv4 = new netcode_socket_t();
    const socket_ipv6 = new netcode_socket_t();

    if ( server_address1.type == NETCODE_ADDRESS_IPV4 || server_address2.type == NETCODE_ADDRESS_IPV4 )
    {
        bind_address_ipv4.type = NETCODE_ADDRESS_IPV4;
        bind_address_ipv4.port = server_address1.type == NETCODE_ADDRESS_IPV4 ? server_address1.port : server_address2.port;

        if ( !netcode_server_socket_create( socket_ipv4, bind_address_ipv4, NETCODE_SERVER_SOCKET_SNDBUF_SIZE, NETCODE_SERVER_SOCKET_RCVBUF_SIZE, config ) )
        {
            return null;
        }
    }

    if ( server_address1.type == NETCODE_ADDRESS_IPV6 || server_address2.type == NETCODE_ADDRESS_IPV6 )
    {
        bind_address_ipv6.type = NETCODE_ADDRESS_IPV6;
        bind_address_ipv6.port = server_address1.type == NETCODE_ADDRESS_IPV6 ? server_address1.port : server_address2.port;

        if ( !netcode_server_socket_create( socket_ipv6, bind_address_ipv6, NETCODE_SERVER_SOCKET_SNDBUF_SIZE, NETCODE_SERVER_SOCKET_RCVBUF_SIZE, config ) )
        {
            netcode_socket_destroy( socket_ipv4 );
            return null;
        }
    }

    if ( !config.allocate_function!( config.allocator_context, NETCODE_SERVER_BYTES ) )
    {
        netcode_socket_destroy( socket_ipv4 );
        netcode_socket_destroy( socket_ipv6 );
        server_create_error = NETCODE_SERVER_CREATE_ERROR_ALLOCATE_SERVER_FAILED;
        return null;
    }

    const server = new netcode_server_t();

    if ( !config.network_simulator )
    {
        netcode_printf( NETCODE_LOG_LEVEL_INFO, "server listening on %s\n", server_address1_string );
    }
    else
    {
        netcode_printf( NETCODE_LOG_LEVEL_INFO, "server listening on %s (network simulator)\n", server_address1_string );
    }

    server.config = config;
    server.socket_holder.ipv4 = socket_ipv4;
    server.socket_holder.ipv6 = socket_ipv6;
    netcode_address_copy( server.address, server_address1 );
    netcode_address_copy( server.address2, server_address2 );
    server.time = time;
    server.global_sequence = 1n << 63n;

    for ( let i = 0; i < NETCODE_MAX_CLIENTS; i++ )
    {
        server.client_encryption_index[i] = -1;
    }

    netcode_connect_token_entries_reset( server.connect_token_entries );

    netcode_encryption_manager_reset( server.encryption_manager );

    for ( let i = 0; i < NETCODE_MAX_CLIENTS; i++ )
    {
        netcode_replay_protection_reset( server.client_replay_protection[i] );
    }

    return server;
}

export function netcode_server_create( server_address_string: string, config: netcode_server_config_t, time: number ): netcode_server_t | null
{
    return netcode_server_create_dual( server_address_string, null, config, time );
}

export function netcode_server_destroy( server: netcode_server_t ): void
{
    netcode_assert( server );

    netcode_server_stop( server );

    netcode_socket_destroy( server.socket_holder.ipv4 );
    netcode_socket_destroy( server.socket_holder.ipv6 );

    sodium_memzero( server.config.private_key, NETCODE_KEY_BYTES );

    server.config.free_function!( server.config.allocator_context, server );
}

export function netcode_server_start( server: netcode_server_t, max_clients: number ): void
{
    netcode_assert( server );
    netcode_assert( max_clients > 0 );
    netcode_assert( max_clients <= NETCODE_MAX_CLIENTS );

    // the per-client arrays are sized NETCODE_MAX_CLIENTS. an out of range value here
    // must not get through in release builds where asserts compile out

    if ( !( Number.isInteger( max_clients ) && max_clients > 0 && max_clients <= NETCODE_MAX_CLIENTS ) )
    {
        netcode_printf( NETCODE_LOG_LEVEL_ERROR, "error: max clients must be in [1,%d], got %d\n", NETCODE_MAX_CLIENTS, max_clients );
        return;
    }

    if ( server.running )
    {
        netcode_server_stop( server );
    }

    netcode_printf( NETCODE_LOG_LEVEL_INFO, "server started with %d client slots\n", max_clients );

    server.running = 1;
    server.max_clients = max_clients;
    server.num_connected_clients = 0;
    server.challenge_sequence = 0n;
    netcode_generate_key( server.challenge_key );

    // a connect token issued before this server started carries keys that already encrypted
    // packets at sequence numbers this run starts again from. the earliest expire timestamp a
    // connect token issued after the start can carry is the start time plus the maximum
    // lifetime the backend issues, so anything earlier than that is refused.

    server.min_connect_token_expire_timestamp = netcode_unix_time() + BigInt( server.config.max_connect_token_lifetime );

    // global packets (challenge, denied) encrypt with the same per-token server to client
    // keys as per-client packets, whose sequences start at zero, so the global sequence
    // lives in the top half of the sequence space to keep AEAD nonces disjoint under a
    // shared key. netcode_server_stop zeroes it, so it must be re-seeded on every start,
    // not just in netcode_server_create -- otherwise a stopped and restarted server would
    // reuse nonces between global and per-client packets.

    server.global_sequence = 1n << 63n;

    for ( let i = 0; i < server.max_clients; i++ )
    {
        netcode_packet_queue_init( server.client_packet_queue[i], server.config.allocator_context, server.config.allocate_function, server.config.free_function );
    }

    for ( let i = 0; i < NETCODE_MAX_CLIENTS; i++ )
    {
        server.client_disconnect_reason[i] = NETCODE_SERVER_CLIENT_DISCONNECT_REASON_NONE;
    }
}

export function netcode_server_send_global_packet( server: netcode_server_t, packet: netcode_packet_t, to: netcode_address_t, packet_key: Uint8Array ): void
{
    netcode_assert( server );
    netcode_assert( packet );
    netcode_assert( to );
    netcode_assert( packet_key );

    const packet_data = server.packet_buffer;

    const packet_bytes = netcode_write_packet( packet, packet_data, NETCODE_MAX_PACKET_BYTES, server.global_sequence, packet_key, server.config.protocol_id );

    netcode_assert( packet_bytes <= NETCODE_MAX_PACKET_BYTES );

    netcode_send_packet_to_address( server.config.network_simulator,
                                    server.config.callback_context,
                                    server.config.override_send_and_receive ? server.config.send_packet_override : null,
                                    server.socket_holder,
                                    server.address,
                                    to,
                                    packet_data,
                                    packet_bytes );

    server.global_sequence = BigInt.asUintN( 64, server.global_sequence + 1n );
}

export function netcode_server_send_client_packet( server: netcode_server_t, packet: netcode_packet_t, client_index: number ): void
{
    netcode_assert( server );
    netcode_assert( packet );
    netcode_assert( client_index >= 0 );
    netcode_assert( client_index < server.max_clients );
    netcode_assert( server.client_connected[client_index] );
    netcode_assert( !server.client_loopback[client_index] );

    const packet_data = server.packet_buffer;

    if ( !netcode_encryption_manager_touch( server.encryption_manager,
                                            server.client_encryption_index[client_index],
                                            server.client_address[client_index],
                                            server.time ) )
    {
        netcode_printf( NETCODE_LOG_LEVEL_ERROR, "error: encryption mapping is out of date for client %d\n", client_index );
        return;
    }

    const packet_key = netcode_encryption_manager_get_send_key( server.encryption_manager, server.client_encryption_index[client_index] )!;

    const packet_bytes = netcode_write_packet( packet, packet_data, NETCODE_MAX_PACKET_BYTES, server.client_sequence[client_index], packet_key, server.config.protocol_id );

    netcode_assert( packet_bytes <= NETCODE_MAX_PACKET_BYTES );

    netcode_send_packet_to_address( server.config.network_simulator,
                                    server.config.callback_context,
                                    server.config.override_send_and_receive ? server.config.send_packet_override : null,
                                    server.socket_holder,
                                    server.address,
                                    server.client_address[client_index],
                                    packet_data,
                                    packet_bytes );

    server.client_sequence[client_index]++;

    server.client_last_packet_send_time[client_index] = server.time;
}

function netcode_server_reset_client_slot( server: netcode_server_t, client_index: number ): void
{
    netcode_packet_queue_clear( server.client_packet_queue[client_index] );

    server.client_connected[client_index] = 0;
    server.client_loopback[client_index] = 0;
    server.client_confirmed[client_index] = 0;
    server.client_id[client_index] = 0n;
    server.client_sequence[client_index] = 0n;
    server.client_last_packet_send_time[client_index] = 0.0;
    server.client_last_packet_receive_time[client_index] = 0.0;
    netcode_address_zero( server.client_address[client_index] );
    server.client_encryption_index[client_index] = -1;
    server.client_user_data[client_index].fill( 0 );

    server.num_connected_clients--;

    netcode_assert( server.num_connected_clients >= 0 );
}

export function netcode_server_disconnect_client_internal( server: netcode_server_t, client_index: number, send_disconnect_packets: number, disconnect_reason: number ): void
{
    netcode_assert( server );
    netcode_assert( server.running );
    netcode_assert( client_index >= 0 );
    netcode_assert( client_index < server.max_clients );
    netcode_assert( server.client_connected[client_index] );
    netcode_assert( !server.client_loopback[client_index] );
    netcode_assert( server.encryption_manager.client_index[server.client_encryption_index[client_index]] == client_index );

    netcode_printf( NETCODE_LOG_LEVEL_INFO, "server disconnected client %d\n", client_index );

    // record why before the callback fires, so the reason can be queried from inside the callback

    server.client_disconnect_reason[client_index] = disconnect_reason;

    if ( server.config.connect_disconnect_callback )
    {
        server.config.connect_disconnect_callback( server.config.callback_context, client_index, 0 );
    }

    if ( send_disconnect_packets )
    {
        netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "server sent disconnect packets to client %d\n", client_index );

        for ( let i = 0; i < NETCODE_NUM_DISCONNECT_PACKETS; i++ )
        {
            netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "server sent disconnect packet %d\n", i );

            const packet = new netcode_connection_disconnect_packet_t();
            packet.packet_type = NETCODE_CONNECTION_DISCONNECT_PACKET;

            netcode_server_send_client_packet( server, packet, client_index );
        }
    }

    netcode_replay_protection_reset( server.client_replay_protection[client_index] );

    server.encryption_manager.client_index[server.client_encryption_index[client_index]] = -1;

    netcode_encryption_manager_remove_encryption_mapping( server.encryption_manager, server.client_address[client_index], server.time );

    netcode_server_reset_client_slot( server, client_index );
}

export function netcode_server_disconnect_client( server: netcode_server_t, client_index: number ): void
{
    netcode_assert( server );

    if ( !server.running )
        return;

    netcode_assert( client_index >= 0 );
    netcode_assert( client_index < server.max_clients );

    if ( !netcode_server_client_index_valid( server, client_index ) )
        return;

    netcode_assert( server.client_loopback[client_index] == 0 );

    if ( !server.client_connected[client_index] )
        return;

    if ( server.client_loopback[client_index] )
        return;

    netcode_server_disconnect_client_internal( server, client_index, 1, NETCODE_SERVER_CLIENT_DISCONNECT_REASON_SERVER_DISCONNECT );
}

export function netcode_server_disconnect_all_clients( server: netcode_server_t ): void
{
    netcode_assert( server );

    if ( !server.running )
        return;

    for ( let i = 0; i < server.max_clients; i++ )
    {
        if ( server.client_connected[i] && !server.client_loopback[i] )
        {
            netcode_server_disconnect_client_internal( server, i, 1, NETCODE_SERVER_CLIENT_DISCONNECT_REASON_SERVER_DISCONNECT );
        }
    }
}

export function netcode_server_stop( server: netcode_server_t ): void
{
    netcode_assert( server );

    if ( !server.running )
        return;

    netcode_server_disconnect_all_clients( server );

    // loopback clients are not disconnected above, but they must not survive a server stop

    for ( let i = 0; i < server.max_clients; i++ )
    {
        if ( server.client_connected[i] && server.client_loopback[i] )
        {
            netcode_server_disconnect_loopback_client( server, i );
        }
    }

    server.running = 0;
    server.max_clients = 0;
    server.num_connected_clients = 0;

    server.global_sequence = 0n;
    server.challenge_sequence = 0n;
    sodium_memzero( server.challenge_key, NETCODE_KEY_BYTES );

    netcode_connect_token_entries_reset( server.connect_token_entries );

    netcode_encryption_manager_reset( server.encryption_manager );

    netcode_printf( NETCODE_LOG_LEVEL_INFO, "server stopped\n" );
}

export function netcode_server_find_client_index_by_id( server: netcode_server_t, client_id: bigint ): number
{
    netcode_assert( server );

    for ( let i = 0; i < server.max_clients; i++ )
    {
        if ( server.client_connected[i] && server.client_id[i] == client_id )
            return i;
    }

    return -1;
}

export function netcode_server_find_client_index_by_address( server: netcode_server_t, address: netcode_address_t ): number
{
    netcode_assert( server );
    netcode_assert( address );

    for ( let i = 0; i < server.max_clients; i++ )
    {
        if ( server.client_connected[i] && netcode_address_equal( server.client_address[i], address ) )
            return i;
    }

    return -1;
}

export function netcode_server_process_connection_request_packet( server: netcode_server_t,
                                                                  from: netcode_address_t,
                                                                  packet: netcode_connection_request_packet_t,
                                                                  current_timestamp: bigint ): void
{
    netcode_assert( server );

    const connect_token_private = new netcode_connect_token_private_t();
    if ( netcode_read_connect_token_private( packet.connect_token_data, NETCODE_CONNECT_TOKEN_PRIVATE_BYTES, connect_token_private ) != NETCODE_OK )
    {
        netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "server ignored connection request. failed to read connect token\n" );
        return;
    }

    let found_server_address = 0;
    for ( let i = 0; i < connect_token_private.num_server_addresses; i++ )
    {
        if ( netcode_address_equal( server.address, connect_token_private.server_addresses[i] ) )
        {
            found_server_address = 1;
        }
        if ( server.address2.type != NETCODE_ADDRESS_NONE && netcode_address_equal( server.address2, connect_token_private.server_addresses[i] ) )
        {
            found_server_address = 1;
        }
    }
    if ( !found_server_address )
    {
        netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "server ignored connection request. server address not in connect token whitelist\n" );
        return;
    }

    if ( netcode_server_find_client_index_by_address( server, from ) != -1 )
    {
        netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "server ignored connection request. a client with this address is already connected\n" );
        return;
    }

    if ( netcode_server_find_client_index_by_id( server, connect_token_private.client_id ) != -1 )
    {
        netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "server ignored connection request. a client with this id is already connected\n" );
        return;
    }

    const connect_token_entry_index = netcode_connect_token_entries_find_or_add( server.connect_token_entries,
                                                                                 from,
                                                                                 packet.connect_token_data.subarray( NETCODE_CONNECT_TOKEN_PRIVATE_BYTES - NETCODE_MAC_BYTES, NETCODE_CONNECT_TOKEN_PRIVATE_BYTES ),
                                                                                 packet.connect_token_expire_timestamp,
                                                                                 current_timestamp,
                                                                                 server.time );

    if ( connect_token_entry_index == NETCODE_CONNECT_TOKEN_HISTORY_FULL )
    {
        netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "server ignored connection request. connect token history is full\n" );
        return;
    }

    if ( connect_token_entry_index == NETCODE_CONNECT_TOKEN_ENTRY_REFUSED )
    {
        netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "server ignored connection request. connect token has already been used\n" );
        return;
    }

    if ( server.num_connected_clients == server.max_clients )
    {
        netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "server denied connection request. server is full\n" );

        const p = new netcode_connection_denied_packet_t();
        p.packet_type = NETCODE_CONNECTION_DENIED_PACKET;

        netcode_server_send_global_packet( server, p, from, connect_token_private.server_to_client_key );

        return;
    }

    const expire_time = ( connect_token_private.timeout_seconds >= 0 ) ? server.time + connect_token_private.timeout_seconds : -1.0;

    if ( !netcode_encryption_manager_add_encryption_mapping( server.encryption_manager,
                                                             from,
                                                             connect_token_private.server_to_client_key,
                                                             connect_token_private.client_to_server_key,
                                                             server.time,
                                                             expire_time,
                                                             connect_token_private.timeout_seconds,
                                                             connect_token_entry_index ) )
    {
        netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "server ignored connection request. failed to add encryption mapping\n" );
        return;
    }

    const challenge_token = new netcode_challenge_token_t();
    challenge_token.client_id = connect_token_private.client_id;
    challenge_token.user_data.set( connect_token_private.user_data );

    const challenge_packet = new netcode_connection_challenge_packet_t();
    challenge_packet.packet_type = NETCODE_CONNECTION_CHALLENGE_PACKET;
    challenge_packet.challenge_token_sequence = server.challenge_sequence;
    netcode_write_challenge_token( challenge_token, challenge_packet.challenge_token_data, NETCODE_CHALLENGE_TOKEN_BYTES );
    if ( netcode_encrypt_challenge_token( challenge_packet.challenge_token_data,
                                          NETCODE_CHALLENGE_TOKEN_BYTES,
                                          server.challenge_sequence,
                                          server.challenge_key ) != NETCODE_OK )
    {
        netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "server ignored connection request. failed to encrypt challenge token\n" );
        return;
    }

    server.challenge_sequence = BigInt.asUintN( 64, server.challenge_sequence + 1n );

    netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "server sent connection challenge packet\n" );

    netcode_server_send_global_packet( server, challenge_packet, from, connect_token_private.server_to_client_key );
}

export function netcode_server_find_free_client_index( server: netcode_server_t ): number
{
    netcode_assert( server );

    for ( let i = 0; i < server.max_clients; i++ )
    {
        if ( !server.client_connected[i] )
            return i;
    }

    return -1;
}

export function netcode_server_connect_client( server: netcode_server_t,
                                               client_index: number,
                                               address: netcode_address_t,
                                               client_id: bigint,
                                               encryption_index: number,
                                               timeout_seconds: number,
                                               user_data: Uint8Array ): void
{
    netcode_assert( server );
    netcode_assert( server.running );
    netcode_assert( client_index >= 0 );
    netcode_assert( client_index < server.max_clients );
    netcode_assert( address );
    netcode_assert( encryption_index != -1 );
    netcode_assert( user_data );
    netcode_assert( server.encryption_manager.client_index[encryption_index] == -1 );

    server.num_connected_clients++;

    netcode_assert( server.num_connected_clients <= server.max_clients );

    netcode_assert( server.client_connected[client_index] == 0 );

    netcode_encryption_manager_set_expire_time( server.encryption_manager, encryption_index, -1.0 );

    server.encryption_manager.client_index[encryption_index] = client_index;

    server.client_connected[client_index] = 1;
    server.client_timeout[client_index] = timeout_seconds;
    server.client_encryption_index[client_index] = encryption_index;
    server.client_id[client_index] = client_id;
    server.client_sequence[client_index] = 0n;
    netcode_address_copy( server.client_address[client_index], address );
    server.client_disconnect_reason[client_index] = NETCODE_SERVER_CLIENT_DISCONNECT_REASON_NONE;

    netcode_assert( netcode_server_find_client_index_by_id( server, client_id ) == client_index );
    netcode_assert( netcode_server_find_client_index_by_address( server, address ) == client_index );

    server.client_last_packet_send_time[client_index] = server.time;
    server.client_last_packet_receive_time[client_index] = server.time;
    server.client_user_data[client_index].set( user_data.subarray( 0, NETCODE_USER_DATA_BYTES ) );

    // the connect token that got this client here is spent: its history entry admits nothing from now on

    const connect_token_entry_index = netcode_encryption_manager_get_connect_token_entry_index( server.encryption_manager, encryption_index );
    if ( connect_token_entry_index >= 0 )
    {
        netcode_connect_token_entries_consume( server.connect_token_entries, connect_token_entry_index );
    }

    netcode_printf( NETCODE_LOG_LEVEL_INFO, "server accepted client %s %.16" + PRIx64 + " in slot %d\n",
        netcode_address_to_string( address ), client_id, client_index );

    const packet = new netcode_connection_keep_alive_packet_t();
    packet.packet_type = NETCODE_CONNECTION_KEEP_ALIVE_PACKET;
    packet.client_index = client_index;
    packet.max_clients = server.max_clients;

    netcode_server_send_client_packet( server, packet, client_index );

    if ( server.config.connect_disconnect_callback )
    {
        server.config.connect_disconnect_callback( server.config.callback_context, client_index, 1 );
    }
}

export function netcode_server_process_connection_response_packet( server: netcode_server_t,
                                                                   from: netcode_address_t,
                                                                   packet: netcode_connection_response_packet_t,
                                                                   encryption_index: number ): void
{
    netcode_assert( server );

    if ( netcode_decrypt_challenge_token( packet.challenge_token_data,
                                          NETCODE_CHALLENGE_TOKEN_BYTES,
                                          packet.challenge_token_sequence,
                                          server.challenge_key ) != NETCODE_OK )
    {
        netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "server ignored connection response. failed to decrypt challenge token\n" );
        return;
    }

    const challenge_token = new netcode_challenge_token_t();
    if ( netcode_read_challenge_token( packet.challenge_token_data, NETCODE_CHALLENGE_TOKEN_BYTES, challenge_token ) != NETCODE_OK )
    {
        netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "server ignored connection response. failed to read challenge token\n" );
        return;
    }

    const packet_send_key = netcode_encryption_manager_get_send_key( server.encryption_manager, encryption_index );

    if ( !packet_send_key )
    {
        netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "server ignored connection response. no packet send key\n" );
        return;
    }

    if ( netcode_server_find_client_index_by_address( server, from ) != -1 )
    {
        netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "server ignored connection response. a client with this address is already connected\n" );
        return;
    }

    if ( netcode_server_find_client_index_by_id( server, challenge_token.client_id ) != -1 )
    {
        netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "server ignored connection response. a client with this id is already connected\n" );
        return;
    }

    if ( server.num_connected_clients == server.max_clients )
    {
        netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "server denied connection response. server is full\n" );

        const p = new netcode_connection_denied_packet_t();
        p.packet_type = NETCODE_CONNECTION_DENIED_PACKET;

        netcode_server_send_global_packet( server, p, from, packet_send_key );

        return;
    }

    const client_index = netcode_server_find_free_client_index( server );

    netcode_assert( client_index != -1 );

    const timeout_seconds = netcode_encryption_manager_get_timeout( server.encryption_manager, encryption_index );

    netcode_server_connect_client( server, client_index, from, challenge_token.client_id, encryption_index, timeout_seconds, challenge_token.user_data );
}

export function netcode_server_process_packet_internal( server: netcode_server_t,
                                                        from: netcode_address_t,
                                                        packet: netcode_packet_t,
                                                        sequence: bigint,
                                                        current_timestamp: bigint,
                                                        encryption_index: number,
                                                        client_index: number ): void
{
    netcode_assert( server );
    netcode_assert( packet );

    const packet_type = packet.packet_type;

    switch ( packet_type )
    {
        case NETCODE_CONNECTION_REQUEST_PACKET:
        {
            if ( ( server.flags & NETCODE_SERVER_FLAG_IGNORE_CONNECTION_REQUEST_PACKETS ) == 0 )
            {
                netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "server received connection request from %s\n", netcode_address_to_string( from ) );
                netcode_server_process_connection_request_packet( server, from, packet as netcode_connection_request_packet_t, current_timestamp );
            }
        }
        break;

        case NETCODE_CONNECTION_RESPONSE_PACKET:
        {
            if ( ( server.flags & NETCODE_SERVER_FLAG_IGNORE_CONNECTION_RESPONSE_PACKETS ) == 0 )
            {
                netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "server received connection response from %s\n", netcode_address_to_string( from ) );
                netcode_server_process_connection_response_packet( server, from, packet as netcode_connection_response_packet_t, encryption_index );
            }
        }
        break;

        case NETCODE_CONNECTION_KEEP_ALIVE_PACKET:
        {
            if ( client_index != -1 )
            {
                netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "server received connection keep alive packet from client %d\n", client_index );
                server.client_last_packet_receive_time[client_index] = server.time;
                if ( !server.client_confirmed[client_index] )
                {
                    netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "server confirmed connection with client %d\n", client_index );
                    server.client_confirmed[client_index] = 1;
                }
            }
        }
        break;

        case NETCODE_CONNECTION_PAYLOAD_PACKET:
        {
            if ( client_index != -1 )
            {
                netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "server received connection payload packet from client %d\n", client_index );
                server.client_last_packet_receive_time[client_index] = server.time;
                if ( !server.client_confirmed[client_index] )
                {
                    netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "server confirmed connection with client %d\n", client_index );
                    server.client_confirmed[client_index] = 1;
                }
                netcode_packet_queue_push( server.client_packet_queue[client_index], packet, sequence );
                return;
            }
        }
        break;

        case NETCODE_CONNECTION_DISCONNECT_PACKET:
        {
            if ( client_index != -1 )
            {
                netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "server received disconnect packet from client %d\n", client_index );
                netcode_server_disconnect_client_internal( server, client_index, 0, NETCODE_SERVER_CLIENT_DISCONNECT_REASON_CLIENT_DISCONNECT );
            }
        }
        break;

        default:
            break;
    }

    server.config.free_function!( server.config.allocator_context, packet );
}

const netcode_server_allowed_packets = ( () =>
{
    const allowed_packets = new Uint8Array( NETCODE_CONNECTION_NUM_PACKETS );
    allowed_packets[NETCODE_CONNECTION_REQUEST_PACKET] = 1;
    allowed_packets[NETCODE_CONNECTION_RESPONSE_PACKET] = 1;
    allowed_packets[NETCODE_CONNECTION_KEEP_ALIVE_PACKET] = 1;
    allowed_packets[NETCODE_CONNECTION_PAYLOAD_PACKET] = 1;
    allowed_packets[NETCODE_CONNECTION_DISCONNECT_PACKET] = 1;
    return allowed_packets;
} )();

/** processes a packet received through some other channel. packet_data is decrypted in place */
export function netcode_server_process_packet( server: netcode_server_t, from: netcode_address_t, packet_data: Uint8Array, packet_bytes: number ): void
{
    const current_timestamp = netcode_unix_time();

    netcode_server_read_and_process_packet( server, from, packet_data, packet_bytes, current_timestamp, netcode_server_allowed_packets );
}

export function netcode_server_read_and_process_packet( server: netcode_server_t,
                                                        from: netcode_address_t,
                                                        packet_data: Uint8Array,
                                                        packet_bytes: number,
                                                        current_timestamp: bigint,
                                                        allowed_packets: Uint8Array ): void
{
    if ( !server.running )
        return;

    if ( packet_bytes <= 1 )
        return;

    const sequence = { value: 0n };

    let encryption_index = -1;
    const client_index = netcode_server_find_client_index_by_address( server, from );
    if ( client_index != -1 )
    {
        netcode_assert( client_index >= 0 );
        netcode_assert( client_index < server.max_clients );
        encryption_index = server.client_encryption_index[client_index];
    }
    else
    {
        encryption_index = netcode_encryption_manager_find_encryption_mapping( server.encryption_manager, from, server.time );
    }

    const read_packet_key = netcode_encryption_manager_get_receive_key( server.encryption_manager, encryption_index );

    if ( !read_packet_key && packet_data[0] != 0 )
    {
        netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "server could not process packet because no encryption mapping exists for %s\n", netcode_address_to_string( from ) );
        return;
    }

    const packet = netcode_read_packet( packet_data,
                                        packet_bytes,
                                        sequence,
                                        read_packet_key,
                                        server.config.protocol_id,
                                        current_timestamp,
                                        server.min_connect_token_expire_timestamp,
                                        server.config.private_key,
                                        allowed_packets,
                                        ( client_index != -1 ) ? server.client_replay_protection[client_index] : null,
                                        server.config.allocator_context,
                                        server.config.allocate_function );

    if ( !packet )
        return;

    netcode_server_process_packet_internal( server, from, packet, sequence.value, current_timestamp, encryption_index, client_index );
}

export function netcode_server_receive_packets( server: netcode_server_t ): void
{
    netcode_assert( server );

    const allowed_packets = netcode_server_allowed_packets;

    const current_timestamp = netcode_unix_time();

    if ( !server.config.network_simulator )
    {
        // process packets received from socket

        const from = server.receive_address;
        const packet_data = server.receive_buffer;

        while ( true )
        {
            netcode_address_zero( from );

            let packet_bytes = 0;

            if ( server.config.override_send_and_receive )
            {
                packet_bytes = server.config.receive_packet_override!( server.config.callback_context, from, packet_data, NETCODE_MAX_PACKET_BYTES );
            }
            else
            {
                if ( server.socket_holder.ipv4.handle !== null )
                    packet_bytes = netcode_socket_receive_packet( server.socket_holder.ipv4, from, packet_data, NETCODE_MAX_PACKET_BYTES );

                if ( packet_bytes == 0 && server.socket_holder.ipv6.handle !== null )
                    packet_bytes = netcode_socket_receive_packet( server.socket_holder.ipv6, from, packet_data, NETCODE_MAX_PACKET_BYTES );
            }

            if ( packet_bytes <= 0 )
                break;

            netcode_server_read_and_process_packet( server, from, packet_data, Math.min( packet_bytes, NETCODE_MAX_PACKET_BYTES ), current_timestamp, allowed_packets );
        }
    }
    else
    {
        // process packets received from network simulator

        const num_packets_received = netcode_network_simulator_receive_packets( server.config.network_simulator,
                                                                                server.address,
                                                                                NETCODE_SERVER_MAX_RECEIVE_PACKETS,
                                                                                server.receive_packet_data,
                                                                                server.receive_packet_bytes,
                                                                                server.receive_from );

        for ( let i = 0; i < num_packets_received; i++ )
        {
            const packet_data = server.receive_packet_data[i]!;

            netcode_server_read_and_process_packet( server,
                                                    server.receive_from[i],
                                                    packet_data,
                                                    server.receive_packet_bytes[i],
                                                    current_timestamp,
                                                    allowed_packets );

            server.config.free_function!( server.config.allocator_context, packet_data );

            server.receive_packet_data[i] = null;
        }
    }
}

export function netcode_server_send_packets( server: netcode_server_t ): void
{
    netcode_assert( server );

    if ( !server.running )
        return;

    for ( let i = 0; i < server.max_clients; i++ )
    {
        if ( server.client_connected[i] && !server.client_loopback[i] &&
             ( server.client_last_packet_send_time[i] + ( 1.0 / NETCODE_PACKET_SEND_RATE ) <= server.time ) )
        {
            netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "server sent connection keep alive packet to client %d\n", i );
            const packet = new netcode_connection_keep_alive_packet_t();
            packet.packet_type = NETCODE_CONNECTION_KEEP_ALIVE_PACKET;
            packet.client_index = i;
            packet.max_clients = server.max_clients;
            netcode_server_send_client_packet( server, packet, i );
        }
    }
}

export function netcode_server_check_for_timeouts( server: netcode_server_t ): void
{
    netcode_assert( server );

    if ( !server.running )
        return;

    for ( let i = 0; i < server.max_clients; i++ )
    {
        if ( !server.client_connected[i] )
            continue;

        if ( server.client_timeout[i] <= 0 )
            continue;

        if ( server.client_loopback[i] )
            continue;

        if ( ( server.time - server.client_last_packet_receive_time[i] ) >= 1.0 )
        {
            netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "server has not received a packet from client %d for %.2f seconds\n", i, server.time - server.client_last_packet_receive_time[i] );
        }

        if ( server.client_last_packet_receive_time[i] + server.client_timeout[i] <= server.time )
        {
            netcode_printf( NETCODE_LOG_LEVEL_INFO, "server timed out client %d\n", i );
            netcode_server_disconnect_client_internal( server, i, 0, NETCODE_SERVER_CLIENT_DISCONNECT_REASON_TIMED_OUT );
        }
    }
}

export function netcode_server_client_connected( server: netcode_server_t, client_index: number ): number
{
    netcode_assert( server );

    if ( !server.running )
        return 0;

    if ( !netcode_server_client_index_valid( server, client_index ) )
        return 0;

    return server.client_connected[client_index];
}

export function netcode_server_client_disconnect_reason( server: netcode_server_t, client_index: number ): number
{
    netcode_assert( server );

    if ( !server.running )
        return NETCODE_SERVER_CLIENT_DISCONNECT_REASON_NONE;

    if ( !netcode_server_client_index_valid( server, client_index ) )
        return NETCODE_SERVER_CLIENT_DISCONNECT_REASON_NONE;

    return server.client_disconnect_reason[client_index];
}

export function netcode_server_client_id( server: netcode_server_t, client_index: number ): bigint
{
    netcode_assert( server );

    if ( !server.running )
        return 0n;

    if ( !netcode_server_client_index_valid( server, client_index ) )
        return 0n;

    return server.client_id[client_index];
}

/** the server's own copy of the client address (live, like the C pointer), or null */
export function netcode_server_client_address( server: netcode_server_t, client_index: number ): netcode_address_t | null
{
    netcode_assert( server );

    if ( !server.running )
        return null;

    if ( !netcode_server_client_index_valid( server, client_index ) )
        return null;

    return server.client_address[client_index];
}

export function netcode_server_next_packet_sequence( server: netcode_server_t, client_index: number ): bigint
{
    netcode_assert( server );
    netcode_assert( client_index >= 0 );
    netcode_assert( client_index < server.max_clients );
    if ( !server.running )
        return 0n;
    if ( !netcode_server_client_index_valid( server, client_index ) )
        return 0n;
    if ( !server.client_connected[client_index] )
        return 0n;
    return server.client_sequence[client_index];
}

export function netcode_server_send_packet( server: netcode_server_t, client_index: number, packet_data: Uint8Array, packet_bytes: number ): void
{
    netcode_assert( server );
    netcode_assert( packet_data );
    netcode_assert( packet_bytes > 0 );
    netcode_assert( packet_bytes <= NETCODE_MAX_PACKET_SIZE );

    // zero byte payloads are not valid on the wire and would silently vanish at the receiver

    if ( !netcode_payload_bytes_valid( packet_data, packet_bytes ) )
    {
        netcode_printf( NETCODE_LOG_LEVEL_ERROR, "error: payload packet size is out of range (%d)\n", packet_bytes );
        return;
    }

    if ( !server.running )
        return;

    netcode_assert( client_index >= 0 );
    netcode_assert( client_index < server.max_clients );

    if ( !netcode_server_client_index_valid( server, client_index ) )
        return;

    if ( !server.client_connected[client_index] )
        return;

    if ( !server.client_loopback[client_index] )
    {
        const packet = server.payload_packet;

        packet.packet_type = NETCODE_CONNECTION_PAYLOAD_PACKET;
        packet.payload_bytes = packet_bytes;
        packet.payload_data = packet_data;

        if ( !server.client_confirmed[client_index] )
        {
            const keep_alive_packet = new netcode_connection_keep_alive_packet_t();
            keep_alive_packet.packet_type = NETCODE_CONNECTION_KEEP_ALIVE_PACKET;
            keep_alive_packet.client_index = client_index;
            keep_alive_packet.max_clients = server.max_clients;
            netcode_server_send_client_packet( server, keep_alive_packet, client_index );
        }

        netcode_server_send_client_packet( server, packet, client_index );

        packet.payload_data = netcode_empty_bytes;
    }
    else
    {
        netcode_assert( server.config.send_loopback_packet_callback );

        const sequence = server.client_sequence[client_index]++;

        server.config.send_loopback_packet_callback!( server.config.callback_context,
                                                      client_index,
                                                      packet_data,
                                                      packet_bytes,
                                                      sequence );

        server.client_last_packet_send_time[client_index] = server.time;
    }
}

/** returns a view of exactly the payload, or null. pass the view to netcode_server_free_packet */
export function netcode_server_receive_packet( server: netcode_server_t, client_index: number, packet_bytes: { value: number }, packet_sequence: { value: bigint } | null ): Uint8Array | null
{
    netcode_assert( server );
    netcode_assert( packet_bytes );

    netcode_assert( client_index >= 0 );

    if ( !server.running )
        return null;

    netcode_assert( client_index < server.max_clients );

    if ( !netcode_server_client_index_valid( server, client_index ) )
        return null;

    if ( !server.client_connected[client_index] )
        return null;

    const packet = netcode_packet_queue_pop( server.client_packet_queue[client_index], packet_sequence ) as netcode_connection_payload_packet_t | null;

    if ( packet )
    {
        netcode_assert( packet.packet_type == NETCODE_CONNECTION_PAYLOAD_PACKET );
        packet_bytes.value = packet.payload_bytes;
        netcode_assert( packet_bytes.value >= 0 );
        netcode_assert( packet_bytes.value <= NETCODE_MAX_PAYLOAD_BYTES );
        return packet.payload_data;
    }
    else
    {
        return null;
    }
}

export function netcode_server_free_packet( server: netcode_server_t, packet: Uint8Array ): void
{
    netcode_assert( server );
    netcode_assert( packet );
    const payload_packet = netcode_payload_packets.get( packet );
    netcode_assert( payload_packet );
    netcode_payload_packets.delete( packet );
    server.config.free_function!( server.config.allocator_context, payload_packet ?? packet );
}

export function netcode_server_num_connected_clients( server: netcode_server_t ): number
{
    netcode_assert( server );
    return server.num_connected_clients;
}

/** a live view of the client's NETCODE_USER_DATA_BYTES of user data, or null */
export function netcode_server_client_user_data( server: netcode_server_t, client_index: number ): Uint8Array | null
{
    netcode_assert( server );
    netcode_assert( client_index >= 0 );
    netcode_assert( client_index < server.max_clients );
    if ( !server.running )
        return null;
    if ( !netcode_server_client_index_valid( server, client_index ) )
        return null;
    return server.client_user_data[client_index];
}

export function netcode_server_running( server: netcode_server_t ): number
{
    netcode_assert( server );
    return server.running;
}

export function netcode_server_max_clients( server: netcode_server_t ): number
{
    return server.max_clients;
}

export function netcode_server_update( server: netcode_server_t, time: number ): void
{
    netcode_assert( server );
    server.time = time;
    netcode_server_receive_packets( server );
    netcode_server_send_packets( server );
    netcode_server_check_for_timeouts( server );
}

export function netcode_server_connect_loopback_client( server: netcode_server_t, client_index: number, client_id: bigint, user_data: Uint8Array | null ): void
{
    netcode_assert( server );
    netcode_assert( client_index >= 0 );
    netcode_assert( client_index < server.max_clients );
    netcode_assert( server.running );

    // the server sends to a loopback client only through this callback. without it the
    // first send would call a null pointer, so refuse the slot at all, in every build.

    netcode_assert( server.config.send_loopback_packet_callback );

    if ( !server.config.send_loopback_packet_callback )
    {
        netcode_printf( NETCODE_LOG_LEVEL_ERROR, "error: a loopback client requires send_loopback_packet_callback\n" );
        return;
    }

    if ( !server.running )
        return;

    if ( !netcode_server_client_index_valid( server, client_index ) )
        return;

    netcode_assert( !server.client_connected[client_index] );

    if ( server.client_connected[client_index] )
        return;

    server.num_connected_clients++;

    netcode_assert( server.num_connected_clients <= server.max_clients );

    server.client_loopback[client_index] = 1;
    server.client_connected[client_index] = 1;
    server.client_confirmed[client_index] = 1;
    server.client_encryption_index[client_index] = -1;
    server.client_id[client_index] = BigInt.asUintN( 64, client_id );
    server.client_sequence[client_index] = 0n;
    server.client_disconnect_reason[client_index] = NETCODE_SERVER_CLIENT_DISCONNECT_REASON_NONE;
    netcode_address_zero( server.client_address[client_index] );
    server.client_last_packet_send_time[client_index] = server.time;
    server.client_last_packet_receive_time[client_index] = server.time;

    if ( user_data )
    {
        server.client_user_data[client_index].set( user_data.subarray( 0, NETCODE_USER_DATA_BYTES ) );
    }
    else
    {
        server.client_user_data[client_index].fill( 0 );
    }

    netcode_printf( NETCODE_LOG_LEVEL_INFO, "server connected loopback client %.16" + PRIx64 + " in slot %d\n", client_id, client_index );

    if ( server.config.connect_disconnect_callback )
    {
        server.config.connect_disconnect_callback( server.config.callback_context, client_index, 1 );
    }
}

export function netcode_server_disconnect_loopback_client( server: netcode_server_t, client_index: number ): void
{
    netcode_assert( server );
    netcode_assert( client_index >= 0 );
    netcode_assert( client_index < server.max_clients );
    netcode_assert( server.running );

    if ( !server.running )
        return;

    if ( !netcode_server_client_index_valid( server, client_index ) )
        return;

    netcode_assert( server.client_connected[client_index] );
    netcode_assert( server.client_loopback[client_index] );

    if ( !server.client_connected[client_index] || !server.client_loopback[client_index] )
        return;

    netcode_printf( NETCODE_LOG_LEVEL_INFO, "server disconnected loopback client %d\n", client_index );

    server.client_disconnect_reason[client_index] = NETCODE_SERVER_CLIENT_DISCONNECT_REASON_SERVER_DISCONNECT;

    if ( server.config.connect_disconnect_callback )
    {
        server.config.connect_disconnect_callback( server.config.callback_context, client_index, 0 );
    }

    netcode_server_reset_client_slot( server, client_index );
}

export function netcode_server_client_loopback( server: netcode_server_t, client_index: number ): number
{
    netcode_assert( server );
    netcode_assert( server.running );
    netcode_assert( client_index >= 0 );
    netcode_assert( client_index < server.max_clients );
    if ( !server.running )
        return 0;
    if ( !netcode_server_client_index_valid( server, client_index ) )
        return 0;
    return server.client_loopback[client_index];
}

export function netcode_server_process_loopback_packet( server: netcode_server_t, client_index: number, packet_data: Uint8Array, packet_bytes: number, packet_sequence: bigint ): void
{
    netcode_assert( server );
    netcode_assert( client_index >= 0 );
    netcode_assert( client_index < server.max_clients );
    netcode_assert( packet_data );
    netcode_assert( packet_bytes > 0 );
    netcode_assert( packet_bytes <= NETCODE_MAX_PACKET_SIZE );
    netcode_assert( server.running );

    if ( !server.running )
        return;

    if ( !netcode_server_client_index_valid( server, client_index ) )
        return;

    netcode_assert( server.client_connected[client_index] );
    netcode_assert( server.client_loopback[client_index] );

    if ( !server.client_connected[client_index] || !server.client_loopback[client_index] )
        return;

    if ( !netcode_payload_bytes_valid( packet_data, packet_bytes ) )
        return;

    const packet = netcode_create_payload_packet( packet_bytes, server.config.allocator_context, server.config.allocate_function );
    if ( !packet )
        return;

    packet.payload_data.set( packet_data.subarray( 0, packet_bytes ) );

    netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "server processing loopback packet from client %d\n", client_index );

    server.client_last_packet_receive_time[client_index] = server.time;

    netcode_packet_queue_push( server.client_packet_queue[client_index], packet, packet_sequence );
}

export function netcode_server_get_port( server: netcode_server_t ): number
{
    netcode_assert( server );
    return server.address.type == NETCODE_ADDRESS_IPV4 ? server.socket_holder.ipv4.address.port : server.socket_holder.ipv6.address.port;
}

// ----------------------------------------------------------------

export function netcode_generate_connect_token( num_server_addresses: number,
                                                public_server_addresses: readonly string[],
                                                internal_server_addresses: readonly string[],
                                                expire_seconds: number,
                                                timeout_seconds: number,
                                                client_id: bigint,
                                                protocol_id: bigint,
                                                private_key: Uint8Array,
                                                user_data: Uint8Array | null,
                                                output_buffer: Uint8Array ): number
{
    netcode_assert( num_server_addresses > 0 );
    netcode_assert( num_server_addresses <= NETCODE_MAX_SERVERS_PER_CONNECT );
    netcode_assert( public_server_addresses );
    netcode_assert( internal_server_addresses );

    // the parsed address arrays below are sized NETCODE_MAX_SERVERS_PER_CONNECT. an out of
    // range value here must not get through in release builds where asserts compile out.
    // every other public entry point already does this; this one was missed

    if ( !( Number.isInteger( num_server_addresses ) && num_server_addresses > 0 && num_server_addresses <= NETCODE_MAX_SERVERS_PER_CONNECT ) )
    {
        netcode_printf( NETCODE_LOG_LEVEL_ERROR, "error: number of server addresses must be in [1,%d], got %d\n", NETCODE_MAX_SERVERS_PER_CONNECT, num_server_addresses );
        return NETCODE_ERROR;
    }
    netcode_assert( private_key );
    netcode_assert( user_data );
    netcode_assert( output_buffer );

    // parse public server addresses

    const parsed_public_server_addresses = netcode_address_array( num_server_addresses );
    for ( let i = 0; i < num_server_addresses; i++ )
    {
        if ( i >= public_server_addresses.length || netcode_parse_address( public_server_addresses[i], parsed_public_server_addresses[i] ) != NETCODE_OK )
        {
            return NETCODE_ERROR;
        }
    }

    // parse internal server addresses

    const parsed_internal_server_addresses = netcode_address_array( num_server_addresses );
    for ( let i = 0; i < num_server_addresses; i++ )
    {
        if ( i >= internal_server_addresses.length || netcode_parse_address( internal_server_addresses[i], parsed_internal_server_addresses[i] ) != NETCODE_OK )
        {
            return NETCODE_ERROR;
        }
    }

    // generate a connect token

    const nonce = new Uint8Array( NETCODE_CONNECT_TOKEN_NONCE_BYTES );
    netcode_generate_nonce( nonce );

    const connect_token_private = new netcode_connect_token_private_t();
    netcode_generate_connect_token_private( connect_token_private, client_id, timeout_seconds, num_server_addresses, parsed_internal_server_addresses, user_data );

    // write it to a buffer

    const connect_token_data = new Uint8Array( NETCODE_CONNECT_TOKEN_PRIVATE_BYTES );
    netcode_write_connect_token_private( connect_token_private, connect_token_data, NETCODE_CONNECT_TOKEN_PRIVATE_BYTES );

    // encrypt the buffer

    const create_timestamp = netcode_unix_time();
    const expire_timestamp = ( expire_seconds >= 0 ) ? BigInt.asUintN( 64, create_timestamp + BigInt( Math.trunc( expire_seconds ) ) ) : 0xFFFFFFFFFFFFFFFFn;
    if ( netcode_encrypt_connect_token_private( connect_token_data, NETCODE_CONNECT_TOKEN_PRIVATE_BYTES, NETCODE_VERSION_INFO, protocol_id, expire_timestamp, nonce, private_key ) != NETCODE_OK )
        return NETCODE_ERROR;

    // wrap a connect token around the private connect token data

    const connect_token = new netcode_connect_token_t();
    connect_token.version_info.set( NETCODE_VERSION_INFO );
    connect_token.protocol_id = BigInt.asUintN( 64, protocol_id );
    connect_token.create_timestamp = create_timestamp;
    connect_token.expire_timestamp = expire_timestamp;
    connect_token.nonce.set( nonce );
    connect_token.private_data.set( connect_token_data );
    connect_token.num_server_addresses = num_server_addresses;
    for ( let i = 0; i < num_server_addresses; i++ )
        netcode_address_copy( connect_token.server_addresses[i], parsed_public_server_addresses[i] );
    connect_token.client_to_server_key.set( connect_token_private.client_to_server_key );
    connect_token.server_to_client_key.set( connect_token_private.server_to_client_key );
    connect_token.timeout_seconds = timeout_seconds | 0;

    // write the connect token to the output buffer

    netcode_write_connect_token( connect_token, output_buffer, NETCODE_CONNECT_TOKEN_BYTES );

    return NETCODE_OK;
}

// ---------------------------------------------------------------

let netcode_time_start = -1;

/** seconds since the first call (which returns 0), from the monotonic performance.now() */
export function netcode_time(): number
{
    const now = performance.now() / 1000.0;
    if ( netcode_time_start < 0 )
    {
        netcode_time_start = now;
        return 0.0;
    }
    return now - netcode_time_start;
}

/** JavaScript cannot block: this resolves after the given time. await it in loops so packets can arrive */
export function netcode_sleep( seconds: number ): Promise<void>
{
    return new Promise<void>( ( resolve ) => setTimeout( resolve, Math.max( 0, seconds * 1000.0 ) ) );
}

// ---------------------------------------------------------------

// ---------------------------------------------------------------
// tests (NETCODE_ENABLE_TESTS)

function check_handler( condition: string, func: string, file: string, line: number ): never
{
    const message = 'check failed: ( ' + condition + ' ), function ' + func + ', file ' + file + ', line ' + line;
    netcode_default_printf_function( message + '\n' );
    throw new Error( message );
}

function check( condition: unknown ): void
{
    if ( !condition )
    {
        const frame = ( new Error().stack ?? '' ).split( '\n' )[2] ?? '';
        const match = /at (?:(.+?) \()?(.*):(\d+):\d+\)?\s*$/.exec( frame );
        check_handler( 'check', ( match?.[1] ?? '?' ).replace( /^Module\./, '' ), match?.[2] ?? 'netcode.ts', match ? parseInt( match[3], 10 ) : 0 );
    }
}

function bytes_equal( a: Uint8Array, b: Uint8Array, length: number ): boolean
{
    if ( a.length < length || b.length < length )
        return false;
    for ( let i = 0; i < length; i++ )
    {
        if ( a[i] != b[i] )
            return false;
    }
    return true;
}

function random_uint64(): bigint
{
    const data = new Uint8Array( 8 );
    netcode_random_bytes( data, 8 );
    return new DataView( data.buffer ).getBigUint64( 0, true );
}

function test_crypto_aead_vectors(): void
{
    // Known-answer test for the two AEAD primitives netcode relies on. Expected ciphertext was
    // generated from libsodium reference output. Do not edit these arrays by hand: a golden failure
    // here means the crypto no longer agrees with upstream, which would break every other netcode
    // implementation on the wire.

    const kat_key = new Uint8Array( [
        0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,0x49,0x4a,0x4b,
        0x4c,0x4d,0x4e,0x4f,0x50,0x51,0x52,0x53,0x54,0x55,0x56,0x57,
        0x58,0x59,0x5a,0x5b,0x5c,0x5d,0x5e,0x5f,
    ] );
    const kat_ad = new Uint8Array( [
        0xc0,0xc1,0xc2,0xc3,0xc4,0xc5,0xc6,0xc7,0xc8,0xc9,0xca,0xcb,
    ] );
    const kat_msg = new Uint8Array( [
        0x79,0x6f,0x6a,0x69,0x6d,0x62,0x6f,0x20,0x76,0x65,0x6e,0x64,0x6f,0x72,0x65,0x64,0x20,0x6c,0x69,0x62,
        0x73,0x6f,0x64,0x69,0x75,0x6d,0x20,0x41,0x45,0x41,0x44,0x20,0x6b,0x6e,0x6f,0x77,0x6e,0x2d,0x61,0x6e,
        0x73,0x77,0x65,0x72,0x20,0x74,0x65,0x73,0x74,0x20,0x76,0x65,0x63,0x74,0x6f,0x72,0x21,0x21,
    ] );
    const kat_npub_ietf = new Uint8Array( [
        0xa0,0xa1,0xa2,0xa3,0xa4,0xa5,0xa6,0xa7,0xa8,0xa9,0xaa,0xab,
    ] );
    const kat_ct_ietf = new Uint8Array( [
        0xd5,0xae,0xb1,0x85,0x15,0x8b,0x07,0xb3,0x01,0x15,0xf0,0x59,
        0xb4,0x4e,0x9d,0x45,0x91,0x58,0xab,0xff,0xaf,0xbd,0x81,0x4f,
        0xbf,0x52,0xc2,0x4c,0xa1,0x5e,0x60,0x5f,0x58,0x63,0x31,0x96,
        0xda,0x90,0x07,0x63,0xb9,0x0c,0x21,0x46,0xf2,0xe4,0x65,0x96,
        0x7a,0x81,0x7f,0xa2,0x5d,0xd1,0x79,0xf6,0x9b,0x18,0x5d,0xe0,
        0xb6,0x57,0x93,0xbe,0x8c,0xb5,0xa9,0x75,0x98,0xa4,0x6f,0xd5,
        0xbe,0x9d,
    ] );
    const kat_npub_xchacha = new Uint8Array( [
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,
        0x1c,0x1d,0x1e,0x1f,0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,
    ] );
    const kat_ct_xchacha = new Uint8Array( [
        0x2b,0x24,0x83,0x2a,0x6c,0x9e,0x21,0x02,0x2a,0x14,0x32,0x56,
        0x4b,0x27,0x37,0x92,0x24,0x40,0xa9,0x92,0xd3,0x53,0xa7,0xa5,
        0x64,0xd3,0x8e,0x0c,0x75,0x79,0x75,0x3f,0xca,0x82,0xfa,0x85,
        0xf0,0xa6,0xac,0x08,0x9a,0x25,0xf1,0x8f,0x42,0x20,0x70,0x8e,
        0x38,0x25,0xd1,0x08,0x45,0x81,0x75,0x18,0xe4,0xd1,0x88,0xbd,
        0x92,0xfa,0x84,0xdc,0xd6,0xa3,0x9a,0x67,0x52,0x91,0x62,0xf4,
        0x86,0x7b,
    ] );

    const c = new Uint8Array( 128 );
    const m = new Uint8Array( 128 );
    const clen = { value: 0 };
    const mlen = { value: 0 };

    // ChaCha20-Poly1305 (IETF) -- the construction netcode uses on the wire

    check( crypto_aead_chacha20poly1305_ietf_encrypt( c, clen, kat_msg, kat_msg.length, kat_ad, kat_ad.length, null, kat_npub_ietf, kat_key ) == 0 );
    check( clen.value == kat_ct_ietf.length );
    check( bytes_equal( c, kat_ct_ietf, clen.value ) );
    check( crypto_aead_chacha20poly1305_ietf_decrypt( m, mlen, null, c, clen.value, kat_ad, kat_ad.length, kat_npub_ietf, kat_key ) == 0 );
    check( mlen.value == kat_msg.length );
    check( bytes_equal( m, kat_msg, mlen.value ) );

    // a tampered tag must be rejected

    c[0] ^= 0x01;
    check( crypto_aead_chacha20poly1305_ietf_decrypt( m, mlen, null, c, clen.value, kat_ad, kat_ad.length, kat_npub_ietf, kat_key ) != 0 );

    // XChaCha20-Poly1305

    check( crypto_aead_xchacha20poly1305_ietf_encrypt( c, clen, kat_msg, kat_msg.length, kat_ad, kat_ad.length, null, kat_npub_xchacha, kat_key ) == 0 );
    check( clen.value == kat_ct_xchacha.length );
    check( bytes_equal( c, kat_ct_xchacha, clen.value ) );
    check( crypto_aead_xchacha20poly1305_ietf_decrypt( m, mlen, null, c, clen.value, kat_ad, kat_ad.length, kat_npub_xchacha, kat_key ) == 0 );
    check( mlen.value == kat_msg.length );
    check( bytes_equal( m, kat_msg, mlen.value ) );
    c[0] ^= 0x01;
    check( crypto_aead_xchacha20poly1305_ietf_decrypt( m, mlen, null, c, clen.value, kat_ad, kat_ad.length, kat_npub_xchacha, kat_key ) != 0 );

    // the constant-time comparison that checks the Poly1305 tag

    const a = new Uint8Array( 64 ), b = new Uint8Array( 64 );
    for ( let i = 0; i < 64; i++ ) { a[i] = i; b[i] = i; }
    check( crypto_verify_16( a, b ) == 0 );
    check( crypto_verify_32( a, b ) == 0 );
    check( crypto_verify_64( a, b ) == 0 );
    for ( let i = 0; i < 8; i++ )
    {
        b[0] = a[0] ^ ( 1 << i );
        check( crypto_verify_16( a, b ) == -1 );
        check( crypto_verify_32( a, b ) == -1 );
        check( crypto_verify_64( a, b ) == -1 );
    }
    b[0] = a[0];
    b[63] = a[63] ^ 0x80;
    check( crypto_verify_64( a, b ) == -1 );
}

function test_queue(): void
{
    const queue = new netcode_packet_queue_t();

    netcode_packet_queue_init( queue, null, null, null );

    check( queue.num_packets == 0 );
    check( queue.start_index == 0 );

    // attempting to pop a packet off an empty queue should return NULL

    check( netcode_packet_queue_pop( queue, null ) == null );

    // add some packets to the queue and make sure they pop off in the correct order
    {
        const NUM_PACKETS = 100;

        const packets: Uint8Array[] = [];

        for ( let i = 0; i < NUM_PACKETS; i++ )
        {
            packets[i] = new Uint8Array( ( i + 1 ) * 256 );
            check( netcode_packet_queue_push( queue, packets[i], BigInt( i ) ) == 1 );
        }

        check( queue.num_packets == NUM_PACKETS );

        for ( let i = 0; i < NUM_PACKETS; i++ )
        {
            const sequence = { value: 0n };
            const packet = netcode_packet_queue_pop( queue, sequence );
            check( sequence.value == BigInt( i ) );
            check( packet === packets[i] );
        }
    }

    // after all entries are popped off, the queue is empty, so calls to pop should return NULL

    check( queue.num_packets == 0 );

    check( netcode_packet_queue_pop( queue, null ) == null );

    // test that the packet queue can be filled to max capacity

    const packets: Uint8Array[] = [];

    for ( let i = 0; i < NETCODE_PACKET_QUEUE_SIZE; i++ )
    {
        packets[i] = new Uint8Array( i * 256 );
        check( netcode_packet_queue_push( queue, packets[i], BigInt( i ) ) == 1 );
    }

    check( queue.num_packets == NETCODE_PACKET_QUEUE_SIZE );

    // when the queue is full, attempting to push a packet should fail and return 0

    check( netcode_packet_queue_push( queue, new Uint8Array( 100 ), 0n ) == 0 );

    // make sure all packets pop off in the correct order

    for ( let i = 0; i < NETCODE_PACKET_QUEUE_SIZE; i++ )
    {
        const sequence = { value: 0n };
        const packet = netcode_packet_queue_pop( queue, sequence );
        check( sequence.value == BigInt( i ) );
        check( packet === packets[i] );
    }

    // add some packets again

    for ( let i = 0; i < NETCODE_PACKET_QUEUE_SIZE; i++ )
    {
        packets[i] = new Uint8Array( i * 256 );
        check( netcode_packet_queue_push( queue, packets[i], BigInt( i ) ) == 1 );
    }

    // clear the queue and make sure that all packets are freed

    netcode_packet_queue_clear( queue );

    check( queue.start_index == 0 );
    check( queue.num_packets == 0 );
    for ( let i = 0; i < NETCODE_PACKET_QUEUE_SIZE; i++ )
        check( queue.packet_data[i] == null );
}

function test_endian(): void
{
    const value = 0x11223344;

    const bytes = new Uint8Array( new Uint32Array( [ value ] ).buffer );

    if ( NETCODE_LITTLE_ENDIAN )
    {
        check( bytes[0] == 0x44 );
        check( bytes[1] == 0x33 );
        check( bytes[2] == 0x22 );
        check( bytes[3] == 0x11 );
    }
    else
    {
        check( bytes[3] == 0x44 );
        check( bytes[2] == 0x33 );
        check( bytes[1] == 0x22 );
        check( bytes[0] == 0x11 );
    }
}

function test_sequence(): void
{
    check( netcode_sequence_number_bytes_required( 0n ) == 1 );
    check( netcode_sequence_number_bytes_required( 0x11n ) == 1 );
    check( netcode_sequence_number_bytes_required( 0x1122n ) == 2 );
    check( netcode_sequence_number_bytes_required( 0x112233n ) == 3 );
    check( netcode_sequence_number_bytes_required( 0x11223344n ) == 4 );
    check( netcode_sequence_number_bytes_required( 0x1122334455n ) == 5 );
    check( netcode_sequence_number_bytes_required( 0x112233445566n ) == 6 );
    check( netcode_sequence_number_bytes_required( 0x11223344556677n ) == 7 );
    check( netcode_sequence_number_bytes_required( 0x1122334455667788n ) == 8 );
}

function check_ipv4_address( address: netcode_address_t, port: number, ipv4: number[] ): void
{
    check( address.type == NETCODE_ADDRESS_IPV4 );
    check( address.port == port );
    for ( let i = 0; i < 4; i++ )
        check( address.data.ipv4[i] == ipv4[i] );
}

function check_ipv6_address( address: netcode_address_t, port: number, ipv6: number[] ): void
{
    check( address.type == NETCODE_ADDRESS_IPV6 );
    check( address.port == port );
    for ( let i = 0; i < 8; i++ )
        check( address.data.ipv6[i] == ipv6[i] );
}

function test_address(): void
{
    {
        const address = new netcode_address_t();
        check( netcode_parse_address( "", address ) == NETCODE_ERROR );
        check( netcode_parse_address( "[", address ) == NETCODE_ERROR );
        check( netcode_parse_address( "[]", address ) == NETCODE_ERROR );
        check( netcode_parse_address( "[]:", address ) == NETCODE_ERROR );
        check( netcode_parse_address( ":", address ) == NETCODE_ERROR );
        check( netcode_parse_address( "1", address ) == NETCODE_ERROR );
        check( netcode_parse_address( "12", address ) == NETCODE_ERROR );
        check( netcode_parse_address( "123", address ) == NETCODE_ERROR );
        check( netcode_parse_address( "1234", address ) == NETCODE_ERROR );
        check( netcode_parse_address( "1234.0.12313.0000", address ) == NETCODE_ERROR );
        check( netcode_parse_address( "1234.0.12313.0000.0.0.0.0.0", address ) == NETCODE_ERROR );
        check( netcode_parse_address( "1312313:123131:1312313:123131:1312313:123131:1312313:123131:1312313:123131:1312313:123131", address ) == NETCODE_ERROR );
        check( netcode_parse_address( ".", address ) == NETCODE_ERROR );
        check( netcode_parse_address( "..", address ) == NETCODE_ERROR );
        check( netcode_parse_address( "...", address ) == NETCODE_ERROR );
        check( netcode_parse_address( "....", address ) == NETCODE_ERROR );
        check( netcode_parse_address( ".....", address ) == NETCODE_ERROR );
    }

    // ports must be all digits in [0,65535]. out of range and non-numeric ports must not silently truncate

    {
        const address = new netcode_address_t();
        check( netcode_parse_address( "127.0.0.1:65535", address ) == NETCODE_OK );
        check( address.type == NETCODE_ADDRESS_IPV4 );
        check( address.port == 65535 );
        check( netcode_parse_address( "[::1]:65535", address ) == NETCODE_OK );
        check( address.type == NETCODE_ADDRESS_IPV6 );
        check( address.port == 65535 );
        check( netcode_parse_address( "127.0.0.1:65536", address ) == NETCODE_ERROR );
        check( netcode_parse_address( "127.0.0.1:99999", address ) == NETCODE_ERROR );
        check( netcode_parse_address( "127.0.0.1:", address ) == NETCODE_ERROR );
        check( netcode_parse_address( "127.0.0.1:40k", address ) == NETCODE_ERROR );
        check( netcode_parse_address( "[::1]:65536", address ) == NETCODE_ERROR );
        check( netcode_parse_address( "[::1]:", address ) == NETCODE_ERROR );
        check( netcode_parse_address( "[::1]:40k", address ) == NETCODE_ERROR );
    }

    {
        const address = new netcode_address_t();
        check( netcode_parse_address( "107.77.207.77", address ) == NETCODE_OK );
        check_ipv4_address( address, 0, [ 107, 77, 207, 77 ] );
    }

    {
        const address = new netcode_address_t();
        check( netcode_parse_address( "127.0.0.1", address ) == NETCODE_OK );
        check_ipv4_address( address, 0, [ 127, 0, 0, 1 ] );
    }

    {
        const address = new netcode_address_t();
        check( netcode_parse_address( "107.77.207.77:40000", address ) == NETCODE_OK );
        check_ipv4_address( address, 40000, [ 107, 77, 207, 77 ] );
    }

    {
        const address = new netcode_address_t();
        check( netcode_parse_address( "127.0.0.1:40000", address ) == NETCODE_OK );
        check_ipv4_address( address, 40000, [ 127, 0, 0, 1 ] );
    }

    {
        const address = new netcode_address_t();
        check( netcode_parse_address( "fe80::202:b3ff:fe1e:8329", address ) == NETCODE_OK );
        check_ipv6_address( address, 0, [ 0xfe80, 0x0000, 0x0000, 0x0000, 0x0202, 0xb3ff, 0xfe1e, 0x8329 ] );
    }

    {
        const address = new netcode_address_t();
        check( netcode_parse_address( "::", address ) == NETCODE_OK );
        check_ipv6_address( address, 0, [ 0, 0, 0, 0, 0, 0, 0, 0 ] );
    }

    {
        const address = new netcode_address_t();
        check( netcode_parse_address( "::1", address ) == NETCODE_OK );
        check_ipv6_address( address, 0, [ 0, 0, 0, 0, 0, 0, 0, 1 ] );
    }

    {
        const address = new netcode_address_t();
        check( netcode_parse_address( "::0", address ) == NETCODE_OK );
        check_ipv6_address( address, 0, [ 0, 0, 0, 0, 0, 0, 0, 0 ] );
    }

    {
        const address = new netcode_address_t();
        check( netcode_parse_address( "[::1]", address ) == NETCODE_OK );
        check_ipv6_address( address, 0, [ 0, 0, 0, 0, 0, 0, 0, 1 ] );
    }

    {
        const address = new netcode_address_t();
        check( netcode_parse_address( "[::0]", address ) == NETCODE_OK );
        check_ipv6_address( address, 0, [ 0, 0, 0, 0, 0, 0, 0, 0 ] );
    }

    {
        const address = new netcode_address_t();
        check( netcode_parse_address( "[fe80::1]", address ) == NETCODE_OK );
        check_ipv6_address( address, 0, [ 0xfe80, 0, 0, 0, 0, 0, 0, 1 ] );
    }

    {
        const address = new netcode_address_t();
        check( netcode_parse_address( "[fe80::202:b3ff:fe1e:8329]:40000", address ) == NETCODE_OK );
        check_ipv6_address( address, 40000, [ 0xfe80, 0x0000, 0x0000, 0x0000, 0x0202, 0xb3ff, 0xfe1e, 0x8329 ] );
    }

    {
        const address = new netcode_address_t();
        check( netcode_parse_address( "[::]:40000", address ) == NETCODE_OK );
        check_ipv6_address( address, 40000, [ 0, 0, 0, 0, 0, 0, 0, 0 ] );
    }

    {
        const address = new netcode_address_t();
        check( netcode_parse_address( "[::1]:5", address ) == NETCODE_OK );
        check_ipv6_address( address, 5, [ 0, 0, 0, 0, 0, 0, 0, 1 ] );
    }

    {
        const address = new netcode_address_t();
        check( netcode_parse_address( "[fe80::1]:5", address ) == NETCODE_OK );
        check_ipv6_address( address, 5, [ 0xfe80, 0, 0, 0, 0, 0, 0, 1 ] );
    }

    {
        const address = new netcode_address_t();
        check( netcode_parse_address( "[::1]:40000", address ) == NETCODE_OK );
        check_ipv6_address( address, 40000, [ 0, 0, 0, 0, 0, 0, 0, 1 ] );
    }

    // TypeScript port: the inet_pton / inet_ntop reimplementations, checked against glibc's behaviour,
    // and address_to_string round trips

    {
        const address = new netcode_address_t();
        check( netcode_parse_address( "01.2.3.4", address ) == NETCODE_ERROR );
        check( netcode_parse_address( "1.2.3.256", address ) == NETCODE_ERROR );
        check( netcode_parse_address( "00001::1", address ) == NETCODE_ERROR );
        check( netcode_parse_address( "1::2::3", address ) == NETCODE_ERROR );
        check( netcode_parse_address( "::1:", address ) == NETCODE_ERROR );
        check( netcode_parse_address( "1:2:3:4:5:6:7:8::", address ) == NETCODE_ERROR );
        check( netcode_parse_address( ":1::2", address ) == NETCODE_ERROR );
        check( netcode_parse_address( "fe80::1%lo0", address ) == NETCODE_ERROR );
        check( netcode_parse_address( "::ffff:1.2.3.4", address ) == NETCODE_OK );
        check_ipv6_address( address, 0, [ 0, 0, 0, 0, 0, 0xffff, 0x0102, 0x0304 ] );
        check( netcode_parse_address( "1:2:3:4:5:6:7::", address ) == NETCODE_OK );
        check_ipv6_address( address, 0, [ 1, 2, 3, 4, 5, 6, 7, 0 ] );
        check( netcode_parse_address( "127.0.0.1:0", address ) == NETCODE_OK );
        check_ipv4_address( address, 0, [ 127, 0, 0, 1 ] );

        const round_trip = [ "127.0.0.1", "127.0.0.1:40000", "::", "::1", "[::1]:40000", "fe80::202:b3ff:fe1e:8329",
                             "[fe80::202:b3ff:fe1e:8329]:40000", "1:0:0:1::1", "1:0:1:0:1:0:1:0", "2001:db8::1:0:0:1",
                             "::ffff:1.2.3.4", "::1.2.3.4", "::2", "1:2:3:4:5:6:7:0" ];
        for ( const string of round_trip )
        {
            check( netcode_parse_address( string, address ) == NETCODE_OK );
            check( netcode_address_to_string( address ) == string );
        }

        netcode_address_zero( address );
        check( netcode_address_to_string( address ) == "NONE" );
    }
}

const TEST_PROTOCOL_ID = 0x1122334455667788n;
const TEST_CLIENT_ID = 0x1n;
const TEST_SERVER_PORT = 40000;
const TEST_CONNECT_TOKEN_EXPIRY = 30;
const TEST_TIMEOUT_SECONDS = 15;

let test_oor_asserts_fired = 0;

function test_oor_assert_handler( condition: string, func: string, file: string, line: number ): void
{
    void condition; void func; void file; void line;
    test_oor_asserts_fired++;
    // deliberately RETURNS. a custom handler may do this and execution continues past the failed
    // assert, which is the only way to reach the code path behind it.
}

function test_generate_connect_token_out_of_range(): void
{
    // netcode_generate_connect_token parses into arrays sized NETCODE_MAX_SERVERS_PER_CONNECT.
    // The asserts fire first by design, so this installs a handler that returns in order to
    // reach the runtime check underneath them.

    const private_key = new Uint8Array( NETCODE_KEY_BYTES );
    const user_data = new Uint8Array( NETCODE_USER_DATA_BYTES );
    const connect_token = new Uint8Array( NETCODE_CONNECT_TOKEN_BYTES );

    const server_address = [ "127.0.0.1:40000" ];

    test_oor_asserts_fired = 0;
    netcode_set_assert_function( test_oor_assert_handler );

    check( netcode_generate_connect_token( 0, server_address, server_address, 30, 5, 1000n, TEST_PROTOCOL_ID, private_key, user_data, connect_token ) == NETCODE_ERROR );
    check( netcode_generate_connect_token( -1, server_address, server_address, 30, 5, 1000n, TEST_PROTOCOL_ID, private_key, user_data, connect_token ) == NETCODE_ERROR );
    check( netcode_generate_connect_token( NETCODE_MAX_SERVERS_PER_CONNECT + 1, server_address, server_address, 30, 5, 1000n, TEST_PROTOCOL_ID, private_key, user_data, connect_token ) == NETCODE_ERROR );

    // asserts are always compiled in here (a debug build), so they must have fired

    check( test_oor_asserts_fired > 0 );

    // restore the DEFAULT handler

    netcode_set_assert_function( netcode_default_assert_handler );

    // and an in-range call still succeeds, so the guard cannot pass by rejecting everything

    check( netcode_generate_connect_token( 1, server_address, server_address, 30, 5, 1000n, TEST_PROTOCOL_ID, private_key, user_data, connect_token ) == NETCODE_OK );
}

function test_server_address_127_0_0_1(): netcode_address_t
{
    const server_address = new netcode_address_t();
    server_address.type = NETCODE_ADDRESS_IPV4;
    server_address.data.ipv4[0] = 127;
    server_address.data.ipv4[1] = 0;
    server_address.data.ipv4[2] = 0;
    server_address.data.ipv4[3] = 1;
    server_address.port = TEST_SERVER_PORT;
    return server_address;
}

function test_connect_token(): void
{
    // generate a connect token

    const server_address = test_server_address_127_0_0_1();

    const user_data = new Uint8Array( NETCODE_USER_DATA_BYTES );
    netcode_random_bytes( user_data, NETCODE_USER_DATA_BYTES );

    const input_token = new netcode_connect_token_private_t();

    netcode_generate_connect_token_private( input_token, TEST_CLIENT_ID, TEST_TIMEOUT_SECONDS, 1, [ server_address ], user_data );

    check( input_token.client_id == TEST_CLIENT_ID );
    check( input_token.num_server_addresses == 1 );
    check( bytes_equal( input_token.user_data, user_data, NETCODE_USER_DATA_BYTES ) );
    check( netcode_address_equal( input_token.server_addresses[0], server_address ) );

    // write it to a buffer

    const buffer = new Uint8Array( NETCODE_CONNECT_TOKEN_PRIVATE_BYTES );

    netcode_write_connect_token_private( input_token, buffer, NETCODE_CONNECT_TOKEN_PRIVATE_BYTES );

    // encrypt the buffer

    const expire_timestamp = netcode_unix_time() + 30n;
    const nonce = new Uint8Array( NETCODE_CONNECT_TOKEN_NONCE_BYTES );
    netcode_generate_nonce( nonce );
    const key = new Uint8Array( NETCODE_KEY_BYTES );
    netcode_generate_key( key );

    check( netcode_encrypt_connect_token_private( buffer,
                                                  NETCODE_CONNECT_TOKEN_PRIVATE_BYTES,
                                                  NETCODE_VERSION_INFO,
                                                  TEST_PROTOCOL_ID,
                                                  expire_timestamp,
                                                  nonce,
                                                  key ) == NETCODE_OK );

    // decrypt the buffer

    check( netcode_decrypt_connect_token_private( buffer,
                                                  NETCODE_CONNECT_TOKEN_PRIVATE_BYTES,
                                                  NETCODE_VERSION_INFO,
                                                  TEST_PROTOCOL_ID,
                                                  expire_timestamp,
                                                  nonce,
                                                  key ) == NETCODE_OK );

    // read the connect token back in

    const output_token = new netcode_connect_token_private_t();

    check( netcode_read_connect_token_private( buffer, NETCODE_CONNECT_TOKEN_PRIVATE_BYTES, output_token ) == NETCODE_OK );

    // make sure that everything matches the original connect token

    check( output_token.client_id == input_token.client_id );
    check( output_token.timeout_seconds == input_token.timeout_seconds );
    check( output_token.num_server_addresses == input_token.num_server_addresses );
    check( netcode_address_equal( output_token.server_addresses[0], input_token.server_addresses[0] ) );
    check( bytes_equal( output_token.client_to_server_key, input_token.client_to_server_key, NETCODE_KEY_BYTES ) );
    check( bytes_equal( output_token.server_to_client_key, input_token.server_to_client_key, NETCODE_KEY_BYTES ) );
    check( bytes_equal( output_token.user_data, input_token.user_data, NETCODE_USER_DATA_BYTES ) );
}

function test_challenge_token(): void
{
    // additional data is NULL, 0.

    const input_token = new netcode_challenge_token_t();

    input_token.client_id = TEST_CLIENT_ID;
    netcode_random_bytes( input_token.user_data, NETCODE_USER_DATA_BYTES );

    // write it to a buffer

    const buffer = new Uint8Array( NETCODE_CHALLENGE_TOKEN_BYTES );

    netcode_write_challenge_token( input_token, buffer, NETCODE_CHALLENGE_TOKEN_BYTES );

    // encrypt the buffer

    const sequence = 1000n;
    const key = new Uint8Array( NETCODE_KEY_BYTES );
    netcode_generate_key( key );

    check( netcode_encrypt_challenge_token( buffer, NETCODE_CHALLENGE_TOKEN_BYTES, sequence, key ) == NETCODE_OK );

    // decrypt the buffer

    check( netcode_decrypt_challenge_token( buffer, NETCODE_CHALLENGE_TOKEN_BYTES, sequence, key ) == NETCODE_OK );

    // read the challenge token back in

    const output_token = new netcode_challenge_token_t();

    check( netcode_read_challenge_token( buffer, NETCODE_CHALLENGE_TOKEN_BYTES, output_token ) == NETCODE_OK );

    // make sure that everything matches the original challenge token

    check( output_token.client_id == input_token.client_id );
    check( bytes_equal( output_token.user_data, input_token.user_data, NETCODE_USER_DATA_BYTES ) );
}

function test_allowed_packets_all(): Uint8Array
{
    const allowed_packets = new Uint8Array( NETCODE_CONNECTION_NUM_PACKETS );
    allowed_packets.fill( 1 );
    return allowed_packets;
}

function test_connection_request_packet(): void
{
    // generate a connect token

    const server_address = test_server_address_127_0_0_1();

    const user_data = new Uint8Array( NETCODE_USER_DATA_BYTES );
    netcode_random_bytes( user_data, NETCODE_USER_DATA_BYTES );

    const input_token = new netcode_connect_token_private_t();

    netcode_generate_connect_token_private( input_token, TEST_CLIENT_ID, TEST_TIMEOUT_SECONDS, 1, [ server_address ], user_data );

    check( input_token.client_id == TEST_CLIENT_ID );
    check( input_token.num_server_addresses == 1 );
    check( bytes_equal( input_token.user_data, user_data, NETCODE_USER_DATA_BYTES ) );
    check( netcode_address_equal( input_token.server_addresses[0], server_address ) );

    // write the conect token to a buffer (non-encrypted)

    const connect_token_data = new Uint8Array( NETCODE_CONNECT_TOKEN_PRIVATE_BYTES );

    netcode_write_connect_token_private( input_token, connect_token_data, NETCODE_CONNECT_TOKEN_PRIVATE_BYTES );

    // copy to a second buffer then encrypt it in place (we need the unencrypted token for verification later on)

    const encrypted_connect_token_data = connect_token_data.slice();

    const connect_token_expire_timestamp = netcode_unix_time() + 30n;
    const connect_token_nonce = new Uint8Array( NETCODE_CONNECT_TOKEN_NONCE_BYTES );
    netcode_generate_nonce( connect_token_nonce );
    const connect_token_key = new Uint8Array( NETCODE_KEY_BYTES );
    netcode_generate_key( connect_token_key );

    check( netcode_encrypt_connect_token_private( encrypted_connect_token_data,
                                                  NETCODE_CONNECT_TOKEN_PRIVATE_BYTES,
                                                  NETCODE_VERSION_INFO,
                                                  TEST_PROTOCOL_ID,
                                                  connect_token_expire_timestamp,
                                                  connect_token_nonce,
                                                  connect_token_key ) == NETCODE_OK );

    // setup a connection request packet wrapping the encrypted connect token

    const input_packet = new netcode_connection_request_packet_t();

    input_packet.packet_type = NETCODE_CONNECTION_REQUEST_PACKET;
    input_packet.version_info.set( NETCODE_VERSION_INFO );
    input_packet.protocol_id = TEST_PROTOCOL_ID;
    input_packet.connect_token_expire_timestamp = connect_token_expire_timestamp;
    input_packet.connect_token_nonce.set( connect_token_nonce );
    input_packet.connect_token_data.set( encrypted_connect_token_data );

    // write the connection request packet to a buffer

    const buffer = new Uint8Array( 2048 );

    const packet_key = new Uint8Array( NETCODE_KEY_BYTES );

    netcode_generate_key( packet_key );

    const bytes_written = netcode_write_packet( input_packet, buffer, buffer.length, 1000n, packet_key, TEST_PROTOCOL_ID );

    check( bytes_written > 0 );

    // read the connection request packet back in from the buffer (the connect token data is decrypted as part of the read packet validation)

    const sequence = { value: 1000n };

    const allowed_packets = test_allowed_packets_all();

    const output_packet = netcode_read_packet( buffer, bytes_written, sequence, packet_key, TEST_PROTOCOL_ID, netcode_unix_time(), 0n, connect_token_key, allowed_packets, null, null, null ) as netcode_connection_request_packet_t;

    check( output_packet );

    // make sure the read packet matches what was written

    check( output_packet.packet_type == NETCODE_CONNECTION_REQUEST_PACKET );
    check( bytes_equal( output_packet.version_info, input_packet.version_info, NETCODE_VERSION_INFO_BYTES ) );
    check( output_packet.protocol_id == input_packet.protocol_id );
    check( output_packet.connect_token_expire_timestamp == input_packet.connect_token_expire_timestamp );
    check( bytes_equal( output_packet.connect_token_nonce, input_packet.connect_token_nonce, NETCODE_CONNECT_TOKEN_NONCE_BYTES ) );
    check( bytes_equal( output_packet.connect_token_data, connect_token_data, NETCODE_CONNECT_TOKEN_PRIVATE_BYTES - NETCODE_MAC_BYTES ) );
}

function test_connection_denied_packet(): void
{
    // setup a connection denied packet

    const input_packet = new netcode_connection_denied_packet_t();

    input_packet.packet_type = NETCODE_CONNECTION_DENIED_PACKET;

    // write the packet to a buffer

    const buffer = new Uint8Array( NETCODE_MAX_PACKET_BYTES );

    const packet_key = new Uint8Array( NETCODE_KEY_BYTES );

    netcode_generate_key( packet_key );

    const bytes_written = netcode_write_packet( input_packet, buffer, buffer.length, 1000n, packet_key, TEST_PROTOCOL_ID );

    check( bytes_written > 0 );

    // read the packet back in from the buffer

    const sequence = { value: 0n };

    const allowed_packet_types = test_allowed_packets_all();

    const output_packet = netcode_read_packet( buffer, bytes_written, sequence, packet_key, TEST_PROTOCOL_ID, netcode_unix_time(), 0n, null, allowed_packet_types, null, null, null ) as netcode_connection_denied_packet_t;

    check( output_packet );

    // make sure the read packet matches what was written

    check( output_packet.packet_type == NETCODE_CONNECTION_DENIED_PACKET );
}

function test_connection_challenge_packet(): void
{
    // setup a connection challenge packet

    const input_packet = new netcode_connection_challenge_packet_t();

    input_packet.packet_type = NETCODE_CONNECTION_CHALLENGE_PACKET;
    input_packet.challenge_token_sequence = 0n;
    netcode_random_bytes( input_packet.challenge_token_data, NETCODE_CHALLENGE_TOKEN_BYTES );

    // write the packet to a buffer

    const buffer = new Uint8Array( NETCODE_MAX_PACKET_BYTES );

    const packet_key = new Uint8Array( NETCODE_KEY_BYTES );

    netcode_generate_key( packet_key );

    const bytes_written = netcode_write_packet( input_packet, buffer, buffer.length, 1000n, packet_key, TEST_PROTOCOL_ID );

    check( bytes_written > 0 );

    // read the packet back in from the buffer

    const sequence = { value: 0n };

    const allowed_packet_types = test_allowed_packets_all();

    const output_packet = netcode_read_packet( buffer, bytes_written, sequence, packet_key, TEST_PROTOCOL_ID, netcode_unix_time(), 0n, null, allowed_packet_types, null, null, null ) as netcode_connection_challenge_packet_t;

    check( output_packet );

    // make sure the read packet packet matches what was written

    check( output_packet.packet_type == NETCODE_CONNECTION_CHALLENGE_PACKET );
    check( output_packet.challenge_token_sequence == input_packet.challenge_token_sequence );
    check( bytes_equal( output_packet.challenge_token_data, input_packet.challenge_token_data, NETCODE_CHALLENGE_TOKEN_BYTES ) );
}

function test_connection_response_packet(): void
{
    // setup a connection response packet

    const input_packet = new netcode_connection_response_packet_t();

    input_packet.packet_type = NETCODE_CONNECTION_RESPONSE_PACKET;
    input_packet.challenge_token_sequence = 0n;
    netcode_random_bytes( input_packet.challenge_token_data, NETCODE_CHALLENGE_TOKEN_BYTES );

    // write the packet to a buffer

    const buffer = new Uint8Array( NETCODE_MAX_PACKET_BYTES );

    const packet_key = new Uint8Array( NETCODE_KEY_BYTES );

    netcode_generate_key( packet_key );

    const bytes_written = netcode_write_packet( input_packet, buffer, buffer.length, 1000n, packet_key, TEST_PROTOCOL_ID );

    check( bytes_written > 0 );

    // read the packet back in from the buffer

    const sequence = { value: 0n };

    const allowed_packet_types = test_allowed_packets_all();

    const output_packet = netcode_read_packet( buffer, bytes_written, sequence, packet_key, TEST_PROTOCOL_ID, netcode_unix_time(), 0n, null, allowed_packet_types, null, null, null ) as netcode_connection_response_packet_t;

    check( output_packet );

    // make sure the read packet matches what was written

    check( output_packet.packet_type == NETCODE_CONNECTION_RESPONSE_PACKET );
    check( output_packet.challenge_token_sequence == input_packet.challenge_token_sequence );
    check( bytes_equal( output_packet.challenge_token_data, input_packet.challenge_token_data, NETCODE_CHALLENGE_TOKEN_BYTES ) );
}

function test_connection_keep_alive_packet(): void
{
    // setup a connection keep alive packet

    const input_packet = new netcode_connection_keep_alive_packet_t();

    input_packet.packet_type = NETCODE_CONNECTION_KEEP_ALIVE_PACKET;
    input_packet.client_index = 10;
    input_packet.max_clients = 16;

    // write the packet to a buffer

    const buffer = new Uint8Array( NETCODE_MAX_PACKET_BYTES );

    const packet_key = new Uint8Array( NETCODE_KEY_BYTES );

    netcode_generate_key( packet_key );

    const bytes_written = netcode_write_packet( input_packet, buffer, buffer.length, 1000n, packet_key, TEST_PROTOCOL_ID );

    check( bytes_written > 0 );

    // read the packet back in from the buffer

    const sequence = { value: 0n };

    const allowed_packet_types = test_allowed_packets_all();

    const output_packet = netcode_read_packet( buffer, bytes_written, sequence, packet_key, TEST_PROTOCOL_ID, netcode_unix_time(), 0n, null, allowed_packet_types, null, null, null ) as netcode_connection_keep_alive_packet_t;

    check( output_packet );

    // make sure the read packet matches what was written

    check( output_packet.packet_type == NETCODE_CONNECTION_KEEP_ALIVE_PACKET );
    check( output_packet.client_index == input_packet.client_index );
    check( output_packet.max_clients == input_packet.max_clients );
}

function test_connection_payload_packet(): void
{
    // setup a connection payload packet

    const input_packet = netcode_create_payload_packet( NETCODE_MAX_PAYLOAD_BYTES, null, null )!;

    check( input_packet.packet_type == NETCODE_CONNECTION_PAYLOAD_PACKET );
    check( input_packet.payload_bytes == NETCODE_MAX_PAYLOAD_BYTES );

    netcode_random_bytes( input_packet.payload_data, NETCODE_MAX_PAYLOAD_BYTES );

    // write the packet to a buffer

    const buffer = new Uint8Array( NETCODE_MAX_PACKET_BYTES );

    const packet_key = new Uint8Array( NETCODE_KEY_BYTES );

    netcode_generate_key( packet_key );

    const bytes_written = netcode_write_packet( input_packet, buffer, buffer.length, 1000n, packet_key, TEST_PROTOCOL_ID );

    check( bytes_written > 0 );

    // read the packet back in from the buffer

    const sequence = { value: 0n };

    const allowed_packet_types = test_allowed_packets_all();

    const output_packet = netcode_read_packet( buffer, bytes_written, sequence, packet_key, TEST_PROTOCOL_ID, netcode_unix_time(), 0n, null, allowed_packet_types, null, null, null ) as netcode_connection_payload_packet_t;

    check( output_packet );

    // make sure the read packet matches what was written

    check( output_packet.packet_type == NETCODE_CONNECTION_PAYLOAD_PACKET );
    check( output_packet.payload_bytes == input_packet.payload_bytes );
    check( bytes_equal( output_packet.payload_data, input_packet.payload_data, NETCODE_MAX_PAYLOAD_BYTES ) );

    // TypeScript port: the payload view has the 8 bytes of reader slack behind it

    check( output_packet.payload_data.buffer.byteLength >= output_packet.payload_bytes + 8 );
}

function test_connection_disconnect_packet(): void
{
    // setup a connection disconnect packet

    const input_packet = new netcode_connection_disconnect_packet_t();

    input_packet.packet_type = NETCODE_CONNECTION_DISCONNECT_PACKET;

    // write the packet to a buffer

    const buffer = new Uint8Array( NETCODE_MAX_PACKET_BYTES );

    const packet_key = new Uint8Array( NETCODE_KEY_BYTES );

    netcode_generate_key( packet_key );

    const bytes_written = netcode_write_packet( input_packet, buffer, buffer.length, 1000n, packet_key, TEST_PROTOCOL_ID );

    check( bytes_written > 0 );

    // read the packet back in from the buffer

    const sequence = { value: 0n };

    const allowed_packet_types = test_allowed_packets_all();

    const output_packet = netcode_read_packet( buffer, bytes_written, sequence, packet_key, TEST_PROTOCOL_ID, netcode_unix_time(), 0n, null, allowed_packet_types, null, null, null ) as netcode_connection_disconnect_packet_t;

    check( output_packet );

    // make sure the read packet matches what was written

    check( output_packet.packet_type == NETCODE_CONNECTION_DISCONNECT_PACKET );
}

function test_connect_token_public(): void
{
    // generate a private connect token

    const server_address = test_server_address_127_0_0_1();

    const user_data = new Uint8Array( NETCODE_USER_DATA_BYTES );
    netcode_random_bytes( user_data, NETCODE_USER_DATA_BYTES );

    const connect_token_private = new netcode_connect_token_private_t();

    netcode_generate_connect_token_private( connect_token_private, TEST_CLIENT_ID, TEST_TIMEOUT_SECONDS, 1, [ server_address ], user_data );

    check( connect_token_private.client_id == TEST_CLIENT_ID );
    check( connect_token_private.num_server_addresses == 1 );
    check( bytes_equal( connect_token_private.user_data, user_data, NETCODE_USER_DATA_BYTES ) );
    check( netcode_address_equal( connect_token_private.server_addresses[0], server_address ) );

    // write it to a buffer

    const connect_token_private_data = new Uint8Array( NETCODE_CONNECT_TOKEN_PRIVATE_BYTES );
    netcode_write_connect_token_private( connect_token_private, connect_token_private_data, NETCODE_CONNECT_TOKEN_PRIVATE_BYTES );

    // encrypt the buffer

    const create_timestamp = netcode_unix_time();
    const expire_timestamp = create_timestamp + 30n;
    const connect_token_nonce = new Uint8Array( NETCODE_CONNECT_TOKEN_NONCE_BYTES );
    netcode_generate_nonce( connect_token_nonce );
    const key = new Uint8Array( NETCODE_KEY_BYTES );
    netcode_generate_key( key );
    check( netcode_encrypt_connect_token_private( connect_token_private_data,
                                                  NETCODE_CONNECT_TOKEN_PRIVATE_BYTES,
                                                  NETCODE_VERSION_INFO,
                                                  TEST_PROTOCOL_ID,
                                                  expire_timestamp,
                                                  connect_token_nonce,
                                                  key ) == 1 );

    // wrap a public connect token around the private connect token data

    const input_connect_token = new netcode_connect_token_t();
    input_connect_token.version_info.set( NETCODE_VERSION_INFO );
    input_connect_token.protocol_id = TEST_PROTOCOL_ID;
    input_connect_token.create_timestamp = create_timestamp;
    input_connect_token.expire_timestamp = expire_timestamp;
    input_connect_token.nonce.set( connect_token_nonce );
    input_connect_token.private_data.set( connect_token_private_data );
    input_connect_token.num_server_addresses = 1;
    netcode_address_copy( input_connect_token.server_addresses[0], server_address );
    input_connect_token.client_to_server_key.set( connect_token_private.client_to_server_key );
    input_connect_token.server_to_client_key.set( connect_token_private.server_to_client_key );
    input_connect_token.timeout_seconds = TEST_TIMEOUT_SECONDS;

    // write the connect token to a buffer

    const buffer = new Uint8Array( NETCODE_CONNECT_TOKEN_BYTES );
    netcode_write_connect_token( input_connect_token, buffer, NETCODE_CONNECT_TOKEN_BYTES );

    // read the buffer back in

    const output_connect_token = new netcode_connect_token_t();
    check( netcode_read_connect_token( buffer, NETCODE_CONNECT_TOKEN_BYTES, output_connect_token ) == 1 );

    // make sure the public connect token matches what was written

    check( bytes_equal( output_connect_token.version_info, input_connect_token.version_info, NETCODE_VERSION_INFO_BYTES ) );
    check( output_connect_token.protocol_id == input_connect_token.protocol_id );
    check( output_connect_token.create_timestamp == input_connect_token.create_timestamp );
    check( output_connect_token.expire_timestamp == input_connect_token.expire_timestamp );
    check( bytes_equal( output_connect_token.nonce, input_connect_token.nonce, NETCODE_CONNECT_TOKEN_NONCE_BYTES ) );
    check( bytes_equal( output_connect_token.private_data, input_connect_token.private_data, NETCODE_CONNECT_TOKEN_PRIVATE_BYTES ) );
    check( output_connect_token.num_server_addresses == input_connect_token.num_server_addresses );
    check( netcode_address_equal( output_connect_token.server_addresses[0], input_connect_token.server_addresses[0] ) );
    check( bytes_equal( output_connect_token.client_to_server_key, input_connect_token.client_to_server_key, NETCODE_KEY_BYTES ) );
    check( bytes_equal( output_connect_token.server_to_client_key, input_connect_token.server_to_client_key, NETCODE_KEY_BYTES ) );
    check( output_connect_token.timeout_seconds == input_connect_token.timeout_seconds );
}

function test_encryption_manager(): void
{
    const encryption_manager = new netcode_encryption_manager_t();

    netcode_encryption_manager_reset( encryption_manager );

    let time = 100.0;

    // generate some test encryption mappings

    class encryption_mapping_t
    {
        address = new netcode_address_t();
        send_key = new Uint8Array( NETCODE_KEY_BYTES );
        receive_key = new Uint8Array( NETCODE_KEY_BYTES );
    }

    const NUM_ENCRYPTION_MAPPINGS = 5;

    const encryption_mapping: encryption_mapping_t[] = [];
    for ( let i = 0; i < NUM_ENCRYPTION_MAPPINGS; i++ )
    {
        encryption_mapping[i] = new encryption_mapping_t();
        encryption_mapping[i].address.type = NETCODE_ADDRESS_IPV6;
        encryption_mapping[i].address.data.ipv6[7] = 1;
        encryption_mapping[i].address.port = 20000 + i;
        netcode_generate_key( encryption_mapping[i].send_key );
        netcode_generate_key( encryption_mapping[i].receive_key );
    }

    // add the encryption mappings to the manager and make sure they can be looked up by address

    for ( let i = 0; i < NUM_ENCRYPTION_MAPPINGS; i++ )
    {
        let encryption_index = netcode_encryption_manager_find_encryption_mapping( encryption_manager, encryption_mapping[i].address, time );

        check( encryption_index == -1 );

        check( netcode_encryption_manager_get_send_key( encryption_manager, encryption_index ) == null );
        check( netcode_encryption_manager_get_receive_key( encryption_manager, encryption_index ) == null );

        check( netcode_encryption_manager_add_encryption_mapping( encryption_manager,
                                                                  encryption_mapping[i].address,
                                                                  encryption_mapping[i].send_key,
                                                                  encryption_mapping[i].receive_key,
                                                                  time,
                                                                  -1.0,
                                                                  TEST_TIMEOUT_SECONDS,
                                                                  -1 ) );

        encryption_index = netcode_encryption_manager_find_encryption_mapping( encryption_manager, encryption_mapping[i].address, time );

        const send_key = netcode_encryption_manager_get_send_key( encryption_manager, encryption_index );
        const receive_key = netcode_encryption_manager_get_receive_key( encryption_manager, encryption_index );

        check( send_key );
        check( receive_key );

        check( bytes_equal( send_key!, encryption_mapping[i].send_key, NETCODE_KEY_BYTES ) );
        check( bytes_equal( receive_key!, encryption_mapping[i].receive_key, NETCODE_KEY_BYTES ) );
    }

    // removing an encryption mapping that doesn't exist should return 0
    {
        const address = new netcode_address_t();
        address.type = NETCODE_ADDRESS_IPV6;
        address.data.ipv6[7] = 1;
        address.port = 50000;

        check( netcode_encryption_manager_remove_encryption_mapping( encryption_manager, address, time ) == 0 );
    }

    // remove the first and last encryption mappings

    check( netcode_encryption_manager_remove_encryption_mapping( encryption_manager, encryption_mapping[0].address, time ) == 1 );

    check( netcode_encryption_manager_remove_encryption_mapping( encryption_manager, encryption_mapping[NUM_ENCRYPTION_MAPPINGS - 1].address, time ) == 1 );

    // make sure the encryption mappings that were removed can no longer be looked up by address

    for ( let i = 0; i < NUM_ENCRYPTION_MAPPINGS; i++ )
    {
        const encryption_index = netcode_encryption_manager_find_encryption_mapping( encryption_manager, encryption_mapping[i].address, time );

        const send_key = netcode_encryption_manager_get_send_key( encryption_manager, encryption_index );
        const receive_key = netcode_encryption_manager_get_receive_key( encryption_manager, encryption_index );

        if ( i != 0 && i != NUM_ENCRYPTION_MAPPINGS - 1 )
        {
            check( send_key );
            check( receive_key );

            check( bytes_equal( send_key!, encryption_mapping[i].send_key, NETCODE_KEY_BYTES ) );
            check( bytes_equal( receive_key!, encryption_mapping[i].receive_key, NETCODE_KEY_BYTES ) );
        }
        else
        {
            check( !send_key );
            check( !receive_key );
        }
    }

    // add the encryption mappings back in

    check( netcode_encryption_manager_add_encryption_mapping( encryption_manager,
                                                              encryption_mapping[0].address,
                                                              encryption_mapping[0].send_key,
                                                              encryption_mapping[0].receive_key,
                                                              time,
                                                              -1.0,
                                                              TEST_TIMEOUT_SECONDS,
                                                              -1 ) );

    check( netcode_encryption_manager_add_encryption_mapping( encryption_manager,
                                                              encryption_mapping[NUM_ENCRYPTION_MAPPINGS - 1].address,
                                                              encryption_mapping[NUM_ENCRYPTION_MAPPINGS - 1].send_key,
                                                              encryption_mapping[NUM_ENCRYPTION_MAPPINGS - 1].receive_key,
                                                              time,
                                                              -1.0,
                                                              TEST_TIMEOUT_SECONDS,
                                                              -1 ) );

    // all encryption mappings should be able to be looked up by address again

    for ( let i = 0; i < NUM_ENCRYPTION_MAPPINGS; i++ )
    {
        const encryption_index = netcode_encryption_manager_find_encryption_mapping( encryption_manager, encryption_mapping[i].address, time );

        const send_key = netcode_encryption_manager_get_send_key( encryption_manager, encryption_index );
        const receive_key = netcode_encryption_manager_get_receive_key( encryption_manager, encryption_index );

        check( send_key );
        check( receive_key );

        check( bytes_equal( send_key!, encryption_mapping[i].send_key, NETCODE_KEY_BYTES ) );
        check( bytes_equal( receive_key!, encryption_mapping[i].receive_key, NETCODE_KEY_BYTES ) );
    }

    // check that encryption mappings time out properly

    time += TEST_TIMEOUT_SECONDS * 2;

    for ( let i = 0; i < NUM_ENCRYPTION_MAPPINGS; i++ )
    {
        const encryption_index = netcode_encryption_manager_find_encryption_mapping( encryption_manager, encryption_mapping[i].address, time );

        const send_key = netcode_encryption_manager_get_send_key( encryption_manager, encryption_index );
        const receive_key = netcode_encryption_manager_get_receive_key( encryption_manager, encryption_index );

        check( !send_key );
        check( !receive_key );
    }

    // add the same encryption mappings after timeout

    for ( let i = 0; i < NUM_ENCRYPTION_MAPPINGS; i++ )
    {
        let encryption_index = netcode_encryption_manager_find_encryption_mapping( encryption_manager, encryption_mapping[i].address, time );

        check( encryption_index == -1 );

        check( netcode_encryption_manager_get_send_key( encryption_manager, encryption_index ) == null );
        check( netcode_encryption_manager_get_receive_key( encryption_manager, encryption_index ) == null );

        check( netcode_encryption_manager_add_encryption_mapping( encryption_manager,
                                                                  encryption_mapping[i].address,
                                                                  encryption_mapping[i].send_key,
                                                                  encryption_mapping[i].receive_key,
                                                                  time,
                                                                  -1.0,
                                                                  TEST_TIMEOUT_SECONDS,
                                                                  -1 ) );

        encryption_index = netcode_encryption_manager_find_encryption_mapping( encryption_manager, encryption_mapping[i].address, time );

        const send_key = netcode_encryption_manager_get_send_key( encryption_manager, encryption_index );
        const receive_key = netcode_encryption_manager_get_receive_key( encryption_manager, encryption_index );

        check( send_key );
        check( receive_key );

        check( bytes_equal( send_key!, encryption_mapping[i].send_key, NETCODE_KEY_BYTES ) );
        check( bytes_equal( receive_key!, encryption_mapping[i].receive_key, NETCODE_KEY_BYTES ) );
    }

    // reset the encryption mapping and verify that all encryption mappings have been removed

    netcode_encryption_manager_reset( encryption_manager );

    for ( let i = 0; i < NUM_ENCRYPTION_MAPPINGS; i++ )
    {
        const encryption_index = netcode_encryption_manager_find_encryption_mapping( encryption_manager, encryption_mapping[i].address, time );

        const send_key = netcode_encryption_manager_get_send_key( encryption_manager, encryption_index );
        const receive_key = netcode_encryption_manager_get_receive_key( encryption_manager, encryption_index );

        check( !send_key );
        check( !receive_key );
    }

    // test the expire time for encryption mapping works as expected

    check( netcode_encryption_manager_add_encryption_mapping( encryption_manager,
                                                              encryption_mapping[0].address,
                                                              encryption_mapping[0].send_key,
                                                              encryption_mapping[0].receive_key,
                                                              time,
                                                              time + 1.0,
                                                              TEST_TIMEOUT_SECONDS,
                                                              -1 ) );

    const encryption_index = netcode_encryption_manager_find_encryption_mapping( encryption_manager, encryption_mapping[0].address, time );

    check( encryption_index != -1 );

    check( netcode_encryption_manager_find_encryption_mapping( encryption_manager, encryption_mapping[0].address, time + Math.fround( 1.1 ) ) == -1 );

    netcode_encryption_manager_set_expire_time( encryption_manager, encryption_index, -1.0 );

    check( netcode_encryption_manager_find_encryption_mapping( encryption_manager, encryption_mapping[0].address, time ) == encryption_index );
}

function test_replay_protection(): void
{
    const replay_protection = new netcode_replay_protection_t();

    for ( let i = 0; i < 2; i++ )
    {
        netcode_replay_protection_reset( replay_protection );

        check( replay_protection.most_recent_sequence == 0n );

        // the first time we receive packets, they should not be already received

        const MAX_SEQUENCE = BigInt( NETCODE_REPLAY_PROTECTION_BUFFER_SIZE * 4 );

        for ( let sequence = 0n; sequence < MAX_SEQUENCE; ++sequence )
        {
            check( netcode_replay_protection_already_received( replay_protection, sequence ) == 0 );
            netcode_replay_protection_advance_sequence( replay_protection, sequence );
        }

        // old packets outside buffer should be considered already received

        check( netcode_replay_protection_already_received( replay_protection, 0n ) == 1 );

        // packets received a second time should be flagged already received

        for ( let sequence = MAX_SEQUENCE - 10n; sequence < MAX_SEQUENCE; ++sequence )
        {
            check( netcode_replay_protection_already_received( replay_protection, sequence ) == 1 );
        }

        // jumping ahead to a much higher sequence should be considered not already received

        check( netcode_replay_protection_already_received( replay_protection, MAX_SEQUENCE + BigInt( NETCODE_REPLAY_PROTECTION_BUFFER_SIZE ) ) == 0 );

        // old packets should be considered already received

        for ( let sequence = 0n; sequence < MAX_SEQUENCE; ++sequence )
        {
            check( netcode_replay_protection_already_received( replay_protection, sequence ) == 1 );
        }
    }

    // sequence numbers near UINT64_MAX must not be falsely rejected as replays.

    const UINT64_MAX = 0xFFFFFFFFFFFFFFFFn;
    const BUFFER_SIZE = BigInt( NETCODE_REPLAY_PROTECTION_BUFFER_SIZE );

    netcode_replay_protection_reset( replay_protection );

    check( netcode_replay_protection_already_received( replay_protection, UINT64_MAX - BUFFER_SIZE ) == 0 );
    netcode_replay_protection_advance_sequence( replay_protection, UINT64_MAX - BUFFER_SIZE );

    check( netcode_replay_protection_already_received( replay_protection, UINT64_MAX - 1n ) == 0 );
    netcode_replay_protection_advance_sequence( replay_protection, UINT64_MAX - 1n );

    // and a replayed packet up there is still caught

    check( netcode_replay_protection_already_received( replay_protection, UINT64_MAX - 1n ) == 1 );

    // while packets that fell out of the window are rejected as before

    check( netcode_replay_protection_already_received( replay_protection, UINT64_MAX - 1n - BUFFER_SIZE ) == 1 );
}

let num_ignored_asserts = 0;

function test_runtime_guards_assert_handler( condition: string, func: string, file: string, line: number ): void
{
    void condition; void func; void file; void line;
    num_ignored_asserts++;
}

function test_runtime_guards(): void
{
    // out of range arguments to public entry points must not crash or corrupt memory.
    // install an assert handler that continues instead of throwing so this test runs.

    netcode_set_assert_function( test_runtime_guards_assert_handler );

    // no private key needed: nothing in this test decrypts anything

    const server_config = new netcode_server_config_t();
    netcode_default_server_config( server_config );
    server_config.protocol_id = TEST_PROTOCOL_ID;

    const server = netcode_server_create( "127.0.0.1:40000", server_config, 0.0 )!;

    check( server );

    // starting with an out of range number of clients must not start the server

    netcode_server_start( server, 0 );
    check( !netcode_server_running( server ) );

    netcode_server_start( server, -1 );
    check( !netcode_server_running( server ) );

    netcode_server_start( server, NETCODE_MAX_CLIENTS + 1 );
    check( !netcode_server_running( server ) );

    netcode_server_start( server, 1 );
    check( netcode_server_running( server ) );
    check( netcode_server_max_clients( server ) == 1 );

    // out of range client indices must return cleanly. max clients is 1, so 1 is out of range

    check( netcode_server_client_user_data( server, -1 ) == null );
    check( netcode_server_client_user_data( server, 1 ) == null );
    check( netcode_server_client_user_data( server, NETCODE_MAX_CLIENTS ) == null );

    check( netcode_server_next_packet_sequence( server, -1 ) == 0n );
    check( netcode_server_next_packet_sequence( server, 1 ) == 0n );

    check( netcode_server_client_loopback( server, -1 ) == 0 );
    check( netcode_server_client_loopback( server, 1 ) == 0 );

    const packet_bytes = { value: 0 };
    const packet_sequence = { value: 0n };
    check( netcode_server_receive_packet( server, -1, packet_bytes, packet_sequence ) == null );
    check( netcode_server_receive_packet( server, 1, packet_bytes, packet_sequence ) == null );

    const payload = new Uint8Array( NETCODE_MAX_PACKET_SIZE );

    netcode_server_send_packet( server, -1, payload, NETCODE_MAX_PACKET_SIZE );
    netcode_server_send_packet( server, 1, payload, NETCODE_MAX_PACKET_SIZE );

    netcode_server_disconnect_client( server, -1 );
    netcode_server_disconnect_client( server, 1 );

    netcode_server_connect_loopback_client( server, -1, 1n, null );
    netcode_server_connect_loopback_client( server, 1, 1n, null );

    netcode_server_disconnect_loopback_client( server, -1 );
    netcode_server_disconnect_loopback_client( server, 1 );

    netcode_server_process_loopback_packet( server, -1, payload, NETCODE_MAX_PACKET_SIZE, 0n );
    netcode_server_process_loopback_packet( server, 1, payload, NETCODE_MAX_PACKET_SIZE, 0n );

    // TypeScript port: non integer and NaN arguments are out of range too

    netcode_server_send_packet( server, 0.5, payload, NETCODE_MAX_PACKET_SIZE );
    netcode_server_send_packet( server, NaN, payload, NETCODE_MAX_PACKET_SIZE );
    netcode_server_send_packet( server, 0, payload, NaN );
    check( netcode_server_client_connected( server, NaN ) == 0 );

    // none of the above may have connected anybody or torn anything down

    check( netcode_server_running( server ) );
    check( netcode_server_num_connected_clients( server ) == 0 );

    netcode_server_destroy( server );

    netcode_set_assert_function( netcode_default_assert_handler );
}

function test_init_and_defaults(): void
{
    // netcode_init is reference counted, so multiple subsystems in the same
    // application can call netcode_init and netcode_term independently.
    // the test runner has already called netcode_init (at least) once.

    const initialized = netcode.initialized;
    check( initialized >= 1 );
    check( netcode_init() == NETCODE_OK );
    check( netcode.initialized == initialized + 1 );
    netcode_term();
    check( netcode.initialized == initialized );

    // a zeroed config must give working defaults instead of crashing on a NULL allocator

    {
        const client_config = new netcode_client_config_t();

        // port 0 asks the OS for an ephemeral port: nothing connects here.
        const client = netcode_client_create( "127.0.0.1:0", client_config, 0.0 );

        check( client );

        check( netcode_client_get_port( client! ) != 0 );

        netcode_client_destroy( client! );
    }

    {
        const server_config = new netcode_server_config_t();

        // ephemeral here too, and for the same reason: nothing connects to this server.
        const server = netcode_server_create( "127.0.0.1:0", server_config, 0.0 );

        check( server );
        check( server!.config.max_connect_token_lifetime == NETCODE_DEFAULT_MAX_CONNECT_TOKEN_LIFETIME );

        netcode_server_destroy( server! );
    }

    // TypeScript port: the server and client keep their own copy of the config, as C copies the struct

    {
        const server_config = new netcode_server_config_t();
        netcode_default_server_config( server_config );
        server_config.protocol_id = TEST_PROTOCOL_ID;
        server_config.private_key[0] = 1;

        const server = netcode_server_create( "127.0.0.1:0", server_config, 0.0 )!;

        check( server );

        server_config.protocol_id = 0n;
        server_config.private_key[0] = 2;

        check( server.config.protocol_id == TEST_PROTOCOL_ID );
        check( server.config.private_key[0] == 1 );

        netcode_server_destroy( server );

        // and destroying the server erases its copy of the private key, not the caller's

        check( server.config.private_key[0] == 0 );
        check( server_config.private_key[0] == 2 );
    }
}

function test_failing_allocate_function( context: unknown, bytes: number ): unknown
{
    void context;
    void bytes;
    return null;
}

let test_simulator_allocations_fail = 0;

function test_toggle_allocate_function( context: unknown, bytes: number ): unknown
{
    void context;
    if ( test_simulator_allocations_fail )
        return null;
    return new Uint8Array( bytes );
}

function test_toggle_free_function( context: unknown, pointer: unknown ): void
{
    void context;
    void pointer;
}

function test_override_send_packet( context: unknown, to: netcode_address_t, packet_data: Uint8Array, packet_bytes: number ): void
{
    void context;
    void to;
    void packet_data;
    void packet_bytes;
}

function test_override_receive_packet( context: unknown, from: netcode_address_t, packet_data: Uint8Array, max_packet_bytes: number ): number
{
    void context;
    void from;
    void packet_data;
    void max_packet_bytes;
    return 0;
}

let test_ipv6_available = true;

function test_check_ipv6_available(): boolean
{
    // the ipv6 socket tests need ::1. hosts without ipv6 skip them
    const address = new netcode_address_t();
    netcode_parse_address( "[::1]:0", address );
    const socket = new netcode_socket_t();
    const error = netcode_socket_create( socket, address, 256 * 1024, 256 * 1024 );
    netcode_socket_destroy( socket );
    return error == NETCODE_SOCKET_ERROR_NONE;
}

function test_client_create_error(): void
{
    const client_config = new netcode_client_config_t();
    netcode_default_client_config( client_config );

    // successful create leaves the create error as NONE

    {
        const client = netcode_client_create( "0.0.0.0:50000", client_config, 0.0 );

        check( client );
        check( netcode_client_create_error() == NETCODE_CLIENT_CREATE_ERROR_NONE );

        netcode_client_destroy( client! );
    }

    // bad first address

    check( netcode_client_create( "not an address", client_config, 0.0 ) == null );
    check( netcode_client_create_error() == NETCODE_CLIENT_CREATE_ERROR_PARSE_ADDRESS_FAILED );

    // bad second address

    check( netcode_client_create_dual( "0.0.0.0:50000", "not an address", client_config, 0.0 ) == null );
    check( netcode_client_create_error() == NETCODE_CLIENT_CREATE_ERROR_PARSE_ADDRESS2_FAILED );

    // the network simulator requires binding to a specific port

    {
        const network_simulator = netcode_network_simulator_create( null, null, null );

        const simulator_config = new netcode_client_config_t();
        netcode_default_client_config( simulator_config );
        simulator_config.network_simulator = network_simulator;

        check( netcode_client_create( "0.0.0.0", simulator_config, 0.0 ) == null );
        check( netcode_client_create_error() == NETCODE_CLIENT_CREATE_ERROR_SIMULATOR_REQUIRES_PORT );

        netcode_network_simulator_destroy( network_simulator );
    }

    // binding a second client to a port already in use fails at socket creation (ipv4)

    {
        const first_client = netcode_client_create( "127.0.0.1:50000", client_config, 0.0 );

        check( first_client );

        check( netcode_client_create( "127.0.0.1:50000", client_config, 0.0 ) == null );
        check( netcode_client_create_error() == NETCODE_CLIENT_CREATE_ERROR_CREATE_SOCKET_IPV4_FAILED );

        netcode_client_destroy( first_client! );
    }

    // and the same over ipv6 reports the ipv6 error

    if ( test_ipv6_available )
    {
        const first_client = netcode_client_create( "[::1]:50000", client_config, 0.0 );

        check( first_client );

        check( netcode_client_create( "[::1]:50000", client_config, 0.0 ) == null );
        check( netcode_client_create_error() == NETCODE_CLIENT_CREATE_ERROR_CREATE_SOCKET_IPV6_FAILED );

        netcode_client_destroy( first_client! );
    }

    // client struct allocation failure

    {
        const failing_config = new netcode_client_config_t();
        netcode_default_client_config( failing_config );
        failing_config.allocate_function = test_failing_allocate_function;

        check( netcode_client_create( "0.0.0.0:50000", failing_config, 0.0 ) == null );
        check( netcode_client_create_error() == NETCODE_CLIENT_CREATE_ERROR_ALLOCATE_CLIENT_FAILED );
    }

    // override_send_and_receive with either override callback missing is refused at create time,
    // rather than calling a null pointer on the first update

    {
        const override_config = new netcode_client_config_t();
        netcode_default_client_config( override_config );
        override_config.override_send_and_receive = 1;
        override_config.send_packet_override = test_override_send_packet;

        check( netcode_client_create( "0.0.0.0:50000", override_config, 0.0 ) == null );
        check( netcode_client_create_error() == NETCODE_CLIENT_CREATE_ERROR_MISSING_OVERRIDE_CALLBACK );

        override_config.send_packet_override = null;
        override_config.receive_packet_override = test_override_receive_packet;

        check( netcode_client_create( "0.0.0.0:50000", override_config, 0.0 ) == null );
        check( netcode_client_create_error() == NETCODE_CLIENT_CREATE_ERROR_MISSING_OVERRIDE_CALLBACK );
    }
}

function test_server_create_error(): void
{
    const server_config = new netcode_server_config_t();
    netcode_default_server_config( server_config );

    // successful create leaves the create error as NONE

    {
        const server = netcode_server_create( "127.0.0.1:40000", server_config, 0.0 );

        check( server );
        check( netcode_server_create_error() == NETCODE_SERVER_CREATE_ERROR_NONE );

        netcode_server_destroy( server! );
    }

    // bad first address

    check( netcode_server_create( "not an address", server_config, 0.0 ) == null );
    check( netcode_server_create_error() == NETCODE_SERVER_CREATE_ERROR_PARSE_ADDRESS_FAILED );

    // bad second address

    check( netcode_server_create_dual( "127.0.0.1:40000", "not an address", server_config, 0.0 ) == null );
    check( netcode_server_create_error() == NETCODE_SERVER_CREATE_ERROR_PARSE_ADDRESS2_FAILED );

    // a port already in use is reported as a bind failure, distinct from other socket errors (ipv4)

    {
        const first_server = netcode_server_create( "127.0.0.1:40000", server_config, 0.0 );

        check( first_server );

        check( netcode_server_create( "127.0.0.1:40000", server_config, 0.0 ) == null );
        check( netcode_server_create_error() == NETCODE_SERVER_CREATE_ERROR_BIND_SOCKET_IPV4_FAILED );

        netcode_server_destroy( first_server! );
    }

    // and the same over ipv6 reports the ipv6 bind error

    if ( test_ipv6_available )
    {
        const first_server = netcode_server_create( "[::1]:40000", server_config, 0.0 );

        check( first_server );

        check( netcode_server_create( "[::1]:40000", server_config, 0.0 ) == null );
        check( netcode_server_create_error() == NETCODE_SERVER_CREATE_ERROR_BIND_SOCKET_IPV6_FAILED );

        netcode_server_destroy( first_server! );
    }

    // server struct allocation failure

    {
        const failing_config = new netcode_server_config_t();
        netcode_default_server_config( failing_config );
        failing_config.allocate_function = test_failing_allocate_function;

        check( netcode_server_create( "127.0.0.1:40000", failing_config, 0.0 ) == null );
        check( netcode_server_create_error() == NETCODE_SERVER_CREATE_ERROR_ALLOCATE_SERVER_FAILED );
    }

    // override_send_and_receive with either override callback missing is refused at create time,
    // rather than calling a null pointer on the first update

    {
        const override_config = new netcode_server_config_t();
        netcode_default_server_config( override_config );
        override_config.override_send_and_receive = 1;
        override_config.send_packet_override = test_override_send_packet;

        check( netcode_server_create( "127.0.0.1:40000", override_config, 0.0 ) == null );
        check( netcode_server_create_error() == NETCODE_SERVER_CREATE_ERROR_MISSING_OVERRIDE_CALLBACK );

        override_config.send_packet_override = null;
        override_config.receive_packet_override = test_override_receive_packet;

        check( netcode_server_create( "127.0.0.1:40000", override_config, 0.0 ) == null );
        check( netcode_server_create_error() == NETCODE_SERVER_CREATE_ERROR_MISSING_OVERRIDE_CALLBACK );
    }
}

function test_network_simulator_allocation_failure(): void
{
    // a failed allocation in the simulator must drop the packet, not memcpy into null

    const network_simulator = netcode_network_simulator_create( null, test_toggle_allocate_function, test_toggle_free_function );

    check( network_simulator );

    const from = new netcode_address_t();
    const to = new netcode_address_t();

    check( netcode_parse_address( "127.0.0.1:50000", from ) == NETCODE_OK );
    check( netcode_parse_address( "127.0.0.1:50001", to ) == NETCODE_OK );

    const packet_data = new Uint8Array( 256 );
    for ( let i = 0; i < 256; i++ )
    {
        packet_data[i] = i;
    }

    test_simulator_allocations_fail = 1;

    netcode_network_simulator_send_packet( network_simulator, from, to, packet_data, packet_data.length );

    test_simulator_allocations_fail = 0;

    netcode_network_simulator_update( network_simulator, 0.0 );

    const receive_packet_data: ( Uint8Array | null )[] = new Array( 16 ).fill( null );
    const receive_packet_bytes = new Int32Array( 16 );
    const receive_from: netcode_address_t[] = new Array( 16 );

    check( netcode_network_simulator_receive_packets( network_simulator, to, 16, receive_packet_data, receive_packet_bytes, receive_from ) == 0 );

    // and the simulator still works once the allocator recovers

    netcode_network_simulator_send_packet( network_simulator, from, to, packet_data, packet_data.length );

    netcode_network_simulator_update( network_simulator, 0.0 );

    check( netcode_network_simulator_receive_packets( network_simulator, to, 16, receive_packet_data, receive_packet_bytes, receive_from ) == 1 );

    check( receive_packet_bytes[0] == 256 );
    check( bytes_equal( receive_packet_data[0]!, packet_data, 256 ) );
    check( netcode_address_equal( receive_from[0], from ) );

    // a received packet buffer belongs to the caller, so free it before the simulator goes

    test_toggle_free_function( null, receive_packet_data[0] );

    netcode_network_simulator_destroy( network_simulator );
}

function test_network_simulator_determinism(): void
{
    // the network simulator has its own seeded rng, so two simulators given
    // identical inputs must drop, delay and duplicate identically

    const DETERMINISM_NUM_PACKETS = 100;
    const DETERMINISM_MAX_RECEIVE = 256;

    const simulator_a = netcode_network_simulator_create( null, null, null );
    const simulator_b = netcode_network_simulator_create( null, null, null );

    check( simulator_a );
    check( simulator_b );

    simulator_a.latency_milliseconds = 100.0;
    simulator_a.jitter_milliseconds = 50.0;
    simulator_a.packet_loss_percent = 25.0;
    simulator_a.duplicate_packet_percent = 25.0;

    simulator_b.latency_milliseconds = 100.0;
    simulator_b.jitter_milliseconds = 50.0;
    simulator_b.packet_loss_percent = 25.0;
    simulator_b.duplicate_packet_percent = 25.0;

    const from = new netcode_address_t();
    const to = new netcode_address_t();
    check( netcode_parse_address( "127.0.0.1:40000", from ) == NETCODE_OK );
    check( netcode_parse_address( "127.0.0.1:50000", to ) == NETCODE_OK );

    const packet_data = new Uint8Array( 256 );
    for ( let i = 0; i < DETERMINISM_NUM_PACKETS; i++ )
    {
        for ( let j = 0; j < packet_data.length; j++ )
        {
            packet_data[j] = ( i + j ) & 0xFF;
        }
        netcode_network_simulator_send_packet( simulator_a, from, to, packet_data, packet_data.length );
        netcode_network_simulator_send_packet( simulator_b, from, to, packet_data, packet_data.length );
    }

    let total_received = 0;

    const packet_data_a: ( Uint8Array | null )[] = new Array( DETERMINISM_MAX_RECEIVE ).fill( null );
    const packet_data_b: ( Uint8Array | null )[] = new Array( DETERMINISM_MAX_RECEIVE ).fill( null );
    const packet_bytes_a = new Int32Array( DETERMINISM_MAX_RECEIVE );
    const packet_bytes_b = new Int32Array( DETERMINISM_MAX_RECEIVE );
    const from_a: netcode_address_t[] = new Array( DETERMINISM_MAX_RECEIVE );
    const from_b: netcode_address_t[] = new Array( DETERMINISM_MAX_RECEIVE );

    for ( let time = 0.0; time < 2.0; time += 0.01 )
    {
        netcode_network_simulator_update( simulator_a, time );
        netcode_network_simulator_update( simulator_b, time );

        const num_packets_a = netcode_network_simulator_receive_packets( simulator_a, to, DETERMINISM_MAX_RECEIVE, packet_data_a, packet_bytes_a, from_a );
        const num_packets_b = netcode_network_simulator_receive_packets( simulator_b, to, DETERMINISM_MAX_RECEIVE, packet_data_b, packet_bytes_b, from_b );

        check( num_packets_a == num_packets_b );

        for ( let i = 0; i < num_packets_a; i++ )
        {
            check( packet_bytes_a[i] == packet_bytes_b[i] );
            check( bytes_equal( packet_data_a[i]!, packet_data_b[i]!, packet_bytes_a[i] ) );
        }

        total_received += num_packets_a;
    }

    check( total_received > 0 );

    // TypeScript port: the rng is xorshift64* seeded with 0x9E3779B97F4A7C15, as in C. its first
    // outputs (computed independently with 64 bit unsigned arithmetic) pin it to the C sequence

    {
        const simulator = netcode_network_simulator_create( null, null, null );
        check( netcode_network_simulator_random_uint64( simulator ) == 0x0D83B3E29A21487An );
        check( netcode_network_simulator_random_uint64( simulator ) == 0x54C44C79F1FE9D67n );
        netcode_network_simulator_destroy( simulator );
    }

    netcode_network_simulator_destroy( simulator_a );
    netcode_network_simulator_destroy( simulator_b );
}

function test_client_create(): void
{
    {
        const client_config = new netcode_client_config_t();
        netcode_default_client_config( client_config );

        const client = netcode_client_create( "127.0.0.1:40000", client_config, 0.0 )!;

        const test_address = new netcode_address_t();
        netcode_parse_address( "127.0.0.1:40000", test_address );

        check( client );
        check( client.socket_holder.ipv4.handle !== null );
        check( client.socket_holder.ipv6.handle === null );
        check( netcode_address_equal( client.address, test_address ) );

        netcode_client_destroy( client );
    }

    if ( test_ipv6_available )
    {
        const client_config = new netcode_client_config_t();
        netcode_default_client_config( client_config );

        const client = netcode_client_create( "[::]:50000", client_config, 0.0 )!;

        const test_address = new netcode_address_t();
        netcode_parse_address( "[::]:50000", test_address );

        check( client );
        check( client.socket_holder.ipv4.handle === null );
        check( client.socket_holder.ipv6.handle !== null );
        check( netcode_address_equal( client.address, test_address ) );

        netcode_client_destroy( client );
    }

    if ( test_ipv6_available )
    {
        const client_config = new netcode_client_config_t();
        netcode_default_client_config( client_config );

        const client = netcode_client_create_dual( "127.0.0.1:40000", "[::]:50000", client_config, 0.0 )!;

        const test_address = new netcode_address_t();
        netcode_parse_address( "127.0.0.1:40000", test_address );

        check( client );
        check( client.socket_holder.ipv4.handle !== null );
        check( client.socket_holder.ipv6.handle !== null );
        check( netcode_address_equal( client.address, test_address ) );

        netcode_client_destroy( client );
    }

    if ( test_ipv6_available )
    {
        const client_config = new netcode_client_config_t();
        netcode_default_client_config( client_config );

        const client = netcode_client_create_dual( "[::]:50000", "127.0.0.1:40000", client_config, 0.0 )!;

        const test_address = new netcode_address_t();
        netcode_parse_address( "[::]:50000", test_address );

        check( client );
        check( client.socket_holder.ipv4.handle !== null );
        check( client.socket_holder.ipv6.handle !== null );
        check( netcode_address_equal( client.address, test_address ) );

        netcode_client_destroy( client );
    }
}

function test_server_create(): void
{
    {
        const server_config = new netcode_server_config_t();
        netcode_default_server_config( server_config );

        const server = netcode_server_create( "127.0.0.1:40000", server_config, 0.0 )!;

        const test_address = new netcode_address_t();
        netcode_parse_address( "127.0.0.1:40000", test_address );

        check( server );
        check( server.socket_holder.ipv4.handle !== null );
        check( server.socket_holder.ipv6.handle === null );
        check( netcode_address_equal( server.address, test_address ) );

        netcode_server_destroy( server );
    }

    if ( test_ipv6_available )
    {
        const server_config = new netcode_server_config_t();
        netcode_default_server_config( server_config );

        const server = netcode_server_create( "[::1]:50000", server_config, 0.0 )!;

        const test_address = new netcode_address_t();
        netcode_parse_address( "[::1]:50000", test_address );

        check( server );
        check( server.socket_holder.ipv4.handle === null );
        check( server.socket_holder.ipv6.handle !== null );
        check( netcode_address_equal( server.address, test_address ) );

        netcode_server_destroy( server );
    }

    if ( test_ipv6_available )
    {
        const server_config = new netcode_server_config_t();
        netcode_default_server_config( server_config );

        const server = netcode_server_create_dual( "127.0.0.1:40000", "[::1]:50000", server_config, 0.0 )!;

        const test_address = new netcode_address_t();
        netcode_parse_address( "127.0.0.1:40000", test_address );

        check( server );
        check( server.socket_holder.ipv4.handle !== null );
        check( server.socket_holder.ipv6.handle !== null );
        check( netcode_address_equal( server.address, test_address ) );

        netcode_server_destroy( server );
    }

    if ( test_ipv6_available )
    {
        const server_config = new netcode_server_config_t();
        netcode_default_server_config( server_config );

        const server = netcode_server_create_dual( "[::1]:50000", "127.0.0.1:40000", server_config, 0.0 )!;

        const test_address = new netcode_address_t();
        netcode_parse_address( "[::1]:50000", test_address );

        check( server );
        check( server.socket_holder.ipv4.handle !== null );
        check( server.socket_holder.ipv6.handle !== null );
        check( netcode_address_equal( server.address, test_address ) );

        netcode_server_destroy( server );
    }
}

function test_server_restart_global_sequence(): void
{
    // global packets (challenge, denied) share per-token server to client keys with
    // per-client packets, so the global sequence must stay in the top half of the
    // sequence space or a stopped and restarted server reuses AEAD nonces. regression
    // test: netcode_server_stop zeroes the global sequence, start must re-seed it.

    const server_config = new netcode_server_config_t();
    netcode_default_server_config( server_config );

    const server = netcode_server_create( "127.0.0.1:40000", server_config, 0.0 )!;

    check( server );
    check( server.global_sequence == 1n << 63n );

    netcode_server_start( server, 1 );

    check( server.global_sequence == 1n << 63n );

    server.global_sequence += 1000n;        // as if the server had sent some global packets

    netcode_server_stop( server );

    netcode_server_start( server, 1 );

    check( server.global_sequence == 1n << 63n );

    netcode_server_destroy( server );
}

const private_key = new Uint8Array( [ 0x60, 0x6a, 0xbe, 0x6e, 0xc9, 0x19, 0x10, 0xea,
                                      0x9a, 0x65, 0x62, 0xf6, 0x6f, 0x2b, 0x30, 0xe4,
                                      0x43, 0x71, 0xd6, 0x2c, 0xd1, 0x99, 0x27, 0x26,
                                      0x6b, 0x3c, 0x60, 0xf4, 0xb7, 0x15, 0xab, 0xa1 ] );

function test_network_simulator_create_lossy(): netcode_network_simulator_t
{
    const network_simulator = netcode_network_simulator_create( null, null, null );

    network_simulator.latency_milliseconds = 250;
    network_simulator.jitter_milliseconds = 250;
    network_simulator.packet_loss_percent = 5;
    network_simulator.duplicate_packet_percent = 10;

    return network_simulator;
}

function test_create_simulator_client( address: string, network_simulator: netcode_network_simulator_t, time: number ): netcode_client_t
{
    const client_config = new netcode_client_config_t();
    netcode_default_client_config( client_config );
    client_config.network_simulator = network_simulator;

    const client = netcode_client_create( address, client_config, time );

    check( client );

    return client!;
}

function test_create_simulator_server( address: string, network_simulator: netcode_network_simulator_t, time: number ): netcode_server_t
{
    const server_config = new netcode_server_config_t();
    netcode_default_server_config( server_config );
    server_config.protocol_id = TEST_PROTOCOL_ID;
    server_config.network_simulator = network_simulator;
    server_config.private_key.set( private_key );

    const server = netcode_server_create( address, server_config, time );

    check( server );

    return server!;
}

function test_generate_connect_token( server_address: string, client_id: bigint, timeout_seconds = TEST_TIMEOUT_SECONDS ): Uint8Array
{
    const connect_token = new Uint8Array( NETCODE_CONNECT_TOKEN_BYTES );

    const user_data = new Uint8Array( NETCODE_USER_DATA_BYTES );
    netcode_random_bytes( user_data, NETCODE_USER_DATA_BYTES );

    check( netcode_generate_connect_token( 1, [ server_address ], [ server_address ], TEST_CONNECT_TOKEN_EXPIRY, timeout_seconds, client_id, TEST_PROTOCOL_ID, private_key, user_data, connect_token ) );

    return connect_token;
}

/** pumps the simulator, client and server until the client connects or fails. returns the new time */
function test_connect_simulator_client( network_simulator: netcode_network_simulator_t, client: netcode_client_t, server: netcode_server_t, time: number, delta_time: number ): number
{
    while ( true )
    {
        netcode_network_simulator_update( network_simulator, time );

        netcode_client_update( client, time );

        netcode_server_update( server, time );

        if ( netcode_client_state( client ) <= NETCODE_CLIENT_STATE_DISCONNECTED )
            break;

        if ( netcode_client_state( client ) == NETCODE_CLIENT_STATE_CONNECTED )
            break;

        time += delta_time;
    }

    return time;
}

function test_packet_data(): Uint8Array
{
    const packet_data = new Uint8Array( NETCODE_MAX_PACKET_SIZE );
    for ( let i = 0; i < NETCODE_MAX_PACKET_SIZE; i++ )
        packet_data[i] = i & 0xFF;
    return packet_data;
}

function test_drain_client_packets( client: netcode_client_t, packet_data: Uint8Array ): number
{
    let num_packets_received = 0;
    while ( true )
    {
        const packet_bytes = { value: 0 };
        const packet_sequence = { value: 0n };
        const packet = netcode_client_receive_packet( client, packet_bytes, packet_sequence );
        if ( !packet )
            break;
        check( packet_bytes.value == NETCODE_MAX_PACKET_SIZE );
        check( bytes_equal( packet, packet_data, NETCODE_MAX_PACKET_SIZE ) );
        num_packets_received++;
        netcode_client_free_packet( client, packet );
    }
    return num_packets_received;
}

function test_drain_server_packets( server: netcode_server_t, client_index: number, packet_data: Uint8Array ): number
{
    let num_packets_received = 0;
    while ( true )
    {
        const packet_bytes = { value: 0 };
        const packet_sequence = { value: 0n };
        const packet = netcode_server_receive_packet( server, client_index, packet_bytes, packet_sequence );
        if ( !packet )
            break;
        check( packet_bytes.value == NETCODE_MAX_PACKET_SIZE );
        check( bytes_equal( packet, packet_data, NETCODE_MAX_PACKET_SIZE ) );
        num_packets_received++;
        netcode_server_free_packet( server, packet );
    }
    return num_packets_received;
}

/** exchanges payload packets until both sides have 10, then disconnects the client server side and runs until the client sees it */
function test_exchange_packets_then_disconnect( network_simulator: netcode_network_simulator_t, client: netcode_client_t, server: netcode_server_t, time: number, time_step: number ): void
{
    let server_num_packets_received = 0;
    let client_num_packets_received = 0;

    const packet_data = test_packet_data();

    while ( true )
    {
        netcode_network_simulator_update( network_simulator, time );

        netcode_client_update( client, time );

        netcode_server_update( server, time );

        netcode_client_send_packet( client, packet_data, NETCODE_MAX_PACKET_SIZE );

        netcode_server_send_packet( server, 0, packet_data, NETCODE_MAX_PACKET_SIZE );

        client_num_packets_received += test_drain_client_packets( client, packet_data );

        server_num_packets_received += test_drain_server_packets( server, 0, packet_data );

        if ( client_num_packets_received >= 10 && server_num_packets_received >= 10 )
        {
            if ( netcode_server_client_connected( server, 0 ) )
            {
                netcode_server_disconnect_client( server, 0 );
            }
        }

        if ( netcode_client_state( client ) <= NETCODE_CLIENT_STATE_DISCONNECTED )
            break;

        time += time_step;
    }

    check( client_num_packets_received >= 10 && server_num_packets_received >= 10 );
}

function test_client_server_connect(): void
{
    const network_simulator = test_network_simulator_create_lossy();

    let time = 0.0;
    const delta_time = 1.0 / 10.0;

    const client = test_create_simulator_client( "[::]:50000", network_simulator, time );

    const server = test_create_simulator_server( "[::1]:40000", network_simulator, time );

    netcode_server_start( server, 1 );

    const connect_token = test_generate_connect_token( "[::1]:40000", random_uint64() );

    netcode_client_connect( client, connect_token );

    time = test_connect_simulator_client( network_simulator, client, server, time, delta_time );

    check( netcode_client_state( client ) == NETCODE_CLIENT_STATE_CONNECTED );
    check( netcode_client_index( client ) == 0 );
    check( netcode_server_client_connected( server, 0 ) == 1 );
    check( netcode_server_num_connected_clients( server ) == 1 );

    test_exchange_packets_then_disconnect( network_simulator, client, server, time, delta_time );

    netcode_server_destroy( server );

    netcode_client_destroy( client );

    netcode_network_simulator_destroy( network_simulator );
}

async function client_server_socket_connect_to( client_address: string, client_address2: string | null, server_address: string, server_address2: string | null, connect_address: string ): Promise<void>
{
    let time = 0.0;
    const delta_time = 1.0 / 10.0;

    const client_config = new netcode_client_config_t();
    netcode_default_client_config( client_config );

    const client = netcode_client_create_dual( client_address, client_address2, client_config, time )!;

    check( client );

    const server_config = new netcode_server_config_t();
    netcode_default_server_config( server_config );
    server_config.protocol_id = TEST_PROTOCOL_ID;
    server_config.private_key.set( private_key );

    const server = netcode_server_create_dual( server_address, server_address2, server_config, time )!;

    check( server );

    netcode_server_start( server, 1 );

    const connect_token = test_generate_connect_token( connect_address, random_uint64() );

    netcode_client_connect( client, connect_token );

    while ( true )
    {
        netcode_client_update( client, time );

        netcode_server_update( server, time );

        if ( netcode_client_state( client ) <= NETCODE_CLIENT_STATE_DISCONNECTED )
            break;

        if ( netcode_client_state( client ) == NETCODE_CLIENT_STATE_CONNECTED )
            break;

        // this test runs over real sockets while advancing virtual time, so it must yield
        // real time each iteration or the virtual timeouts can expire before the OS delivers
        // a single loopback packet. in JavaScript this await is also what lets packets arrive at all.

        await netcode_sleep( 0.01 );

        time += delta_time;
    }

    check( netcode_client_state( client ) == NETCODE_CLIENT_STATE_CONNECTED );
    check( netcode_server_num_connected_clients( server ) == 1 );

    netcode_server_destroy( server );

    netcode_client_destroy( client );
}

async function client_server_socket_connect( client_address: string, client_address2: string | null, server_address: string, server_address2: string | null ): Promise<void>
{
    await client_server_socket_connect_to( client_address, client_address2, server_address, server_address2, server_address );
}

async function test_client_server_ipv4_socket_connect(): Promise<void>
{
    await client_server_socket_connect( "0.0.0.0:50000", null        , "127.0.0.1:40000", null          );
    if ( !test_ipv6_available )
        return;
    await client_server_socket_connect( "0.0.0.0:50000", null        , "127.0.0.1:40000", "[::1]:40000" );
    await client_server_socket_connect( "0.0.0.0:50000", "[::]:50000", "127.0.0.1:40000", null          );
    await client_server_socket_connect( "0.0.0.0:50000", "[::]:50000", "127.0.0.1:40000", "[::1]:40000" );
}

async function test_client_server_ipv6_socket_connect(): Promise<void>
{
    if ( !test_ipv6_available )
        return;
    await client_server_socket_connect( "[::]:50000"   , null        , "[::1]:40000", null              );
    await client_server_socket_connect( "[::]:50000"   , null        , "[::1]:40000", "127.0.0.1:40000" );
    await client_server_socket_connect( "0.0.0.0:50000", "[::]:50000", "[::1]:40000", null              );
    await client_server_socket_connect( "0.0.0.0:50000", "[::]:50000", "[::1]:40000", "127.0.0.1:40000" );
}

async function test_client_server_dual_socket_connect(): Promise<void>
{
    if ( !test_ipv6_available )
        return;

    // dual stack client connects to dual stack server over ipv4

    await client_server_socket_connect( "0.0.0.0:50000", "[::]:50000", "127.0.0.1:40000", "[::1]:40000" );

    // dual stack client connects to dual stack server over ipv6

    await client_server_socket_connect( "0.0.0.0:50000", "[::]:50000", "[::1]:40000", "127.0.0.1:40000" );

    // dual stack client connects to the second address of a dual stack server (ipv6, then ipv4)

    await client_server_socket_connect_to( "0.0.0.0:50000", "[::]:50000", "127.0.0.1:40000", "[::1]:40000", "[::1]:40000" );

    await client_server_socket_connect_to( "0.0.0.0:50000", "[::]:50000", "[::1]:40000", "127.0.0.1:40000", "127.0.0.1:40000" );
}

function test_client_server_keep_alive(): void
{
    const network_simulator = test_network_simulator_create_lossy();

    let time = 0.0;
    const delta_time = 1.0 / 10.0;

    // connect client to server

    const client = test_create_simulator_client( "[::]:50000", network_simulator, time );

    const server = test_create_simulator_server( "[::1]:40000", network_simulator, time );

    netcode_server_start( server, 1 );

    const connect_token = test_generate_connect_token( "[::1]:40000", random_uint64() );

    netcode_client_connect( client, connect_token );

    time = test_connect_simulator_client( network_simulator, client, server, time, delta_time );

    check( netcode_client_state( client ) == NETCODE_CLIENT_STATE_CONNECTED );
    check( netcode_client_index( client ) == 0 );
    check( netcode_server_client_connected( server, 0 ) == 1 );
    check( netcode_server_num_connected_clients( server ) == 1 );

    // pump the client and server long enough that they would timeout without keep alive packets

    const num_iterations = Math.trunc( Math.fround( Math.fround( 1.25 ) * TEST_TIMEOUT_SECONDS ) / delta_time ) + 1;

    for ( let i = 0; i < num_iterations; i++ )
    {
        netcode_network_simulator_update( network_simulator, time );

        netcode_client_update( client, time );

        netcode_server_update( server, time );

        if ( netcode_client_state( client ) <= NETCODE_CLIENT_STATE_DISCONNECTED )
            break;

        time += delta_time;
    }

    check( netcode_client_state( client ) == NETCODE_CLIENT_STATE_CONNECTED );
    check( netcode_client_index( client ) == 0 );
    check( netcode_server_client_connected( server, 0 ) == 1 );
    check( netcode_server_num_connected_clients( server ) == 1 );

    netcode_server_destroy( server );

    netcode_client_destroy( client );

    netcode_network_simulator_destroy( network_simulator );
}

function test_client_server_multiple_clients(): void
{
    const NUM_START_STOP_ITERATIONS = 3;

    const max_clients = [ 2, 32, 5 ];

    const network_simulator = test_network_simulator_create_lossy();

    let time = 0.0;
    const delta_time = 1.0 / 10.0;

    const server = test_create_simulator_server( "[::1]:40000", network_simulator, time );

    for ( let i = 0; i < NUM_START_STOP_ITERATIONS; i++ )
    {
        // start the server with max # of clients for this iteration

        netcode_server_start( server, max_clients[i] );

        // create # of client objects for this iteration and connect to server

        const client: netcode_client_t[] = [];

        for ( let j = 0; j < max_clients[i]; j++ )
        {
            const client_address = "[::]:" + ( 50000 + j );

            client[j] = test_create_simulator_client( client_address, network_simulator, time );

            const connect_token = test_generate_connect_token( "[::1]:40000", random_uint64() );

            netcode_client_connect( client[j], connect_token );
        }

        // make sure all clients can connect

        while ( true )
        {
            netcode_network_simulator_update( network_simulator, time );

            for ( let j = 0; j < max_clients[i]; j++ )
            {
                netcode_client_update( client[j], time );
            }

            netcode_server_update( server, time );

            let num_connected_clients = 0;

            for ( let j = 0; j < max_clients[i]; j++ )
            {
                if ( netcode_client_state( client[j] ) <= NETCODE_CLIENT_STATE_DISCONNECTED )
                    break;

                if ( netcode_client_state( client[j] ) == NETCODE_CLIENT_STATE_CONNECTED )
                    num_connected_clients++;
            }

            if ( num_connected_clients == max_clients[i] )
                break;

            time += delta_time;
        }

        check( netcode_server_num_connected_clients( server ) == max_clients[i] );

        for ( let j = 0; j < max_clients[i]; j++ )
        {
            check( netcode_client_state( client[j] ) == NETCODE_CLIENT_STATE_CONNECTED );
            check( netcode_server_client_connected( server, j ) == 1 );
        }

        // make sure all clients can exchange packets with the server

        const server_num_packets_received = new Int32Array( max_clients[i] );
        const client_num_packets_received = new Int32Array( max_clients[i] );

        const packet_data = test_packet_data();

        while ( true )
        {
            netcode_network_simulator_update( network_simulator, time );

            for ( let j = 0; j < max_clients[i]; j++ )
            {
                netcode_client_update( client[j], time );
            }

            netcode_server_update( server, time );

            for ( let j = 0; j < max_clients[i]; j++ )
            {
                netcode_client_send_packet( client[j], packet_data, NETCODE_MAX_PACKET_SIZE );
            }

            for ( let j = 0; j < max_clients[i]; j++ )
            {
                netcode_server_send_packet( server, j, packet_data, NETCODE_MAX_PACKET_SIZE );
            }

            for ( let j = 0; j < max_clients[i]; j++ )
            {
                client_num_packets_received[j] += test_drain_client_packets( client[j], packet_data );
            }

            for ( let j = 0; j < max_clients[i]; j++ )
            {
                server_num_packets_received[j] += test_drain_server_packets( server, j, packet_data );
            }

            let num_clients_ready = 0;

            for ( let j = 0; j < max_clients[i]; j++ )
            {
                if ( client_num_packets_received[j] >= 1 && server_num_packets_received[j] >= 1 )
                {
                    num_clients_ready++;
                }
            }

            if ( num_clients_ready == max_clients[i] )
                break;

            for ( let j = 0; j < max_clients[i]; j++ )
            {
                if ( netcode_client_state( client[j] ) <= NETCODE_CLIENT_STATE_DISCONNECTED )
                    break;
            }

            time += delta_time;
        }

        let num_clients_ready = 0;

        for ( let j = 0; j < max_clients[i]; j++ )
        {
            if ( client_num_packets_received[j] >= 1 && server_num_packets_received[j] >= 1 )
            {
                num_clients_ready++;
            }
        }

        check( num_clients_ready == max_clients[i] );

        netcode_network_simulator_reset( network_simulator );

        for ( let j = 0; j < max_clients[i]; j++ )
        {
            netcode_client_destroy( client[j] );
        }

        netcode_server_stop( server );
    }

    netcode_server_destroy( server );

    netcode_network_simulator_destroy( network_simulator );
}

function test_client_server_multiple_servers(): void
{
    const network_simulator = test_network_simulator_create_lossy();

    let time = 0.0;
    const delta_time = 1.0 / 10.0;

    const client = test_create_simulator_client( "[::]:50000", network_simulator, time );

    const server = test_create_simulator_server( "[::1]:40000", network_simulator, time );

    netcode_server_start( server, 1 );

    const server_address = [ "10.10.10.10:1000", "100.100.100.100:50000", "[::1]:40000" ];

    const connect_token = new Uint8Array( NETCODE_CONNECT_TOKEN_BYTES );

    const client_id = random_uint64();

    const user_data = new Uint8Array( NETCODE_USER_DATA_BYTES );
    netcode_random_bytes( user_data, NETCODE_USER_DATA_BYTES );

    check( netcode_generate_connect_token( 3, server_address, server_address, TEST_CONNECT_TOKEN_EXPIRY, TEST_TIMEOUT_SECONDS, client_id, TEST_PROTOCOL_ID, private_key, user_data, connect_token ) );

    netcode_client_connect( client, connect_token );

    time = test_connect_simulator_client( network_simulator, client, server, time, delta_time );

    check( netcode_client_state( client ) == NETCODE_CLIENT_STATE_CONNECTED );
    check( netcode_client_index( client ) == 0 );
    check( netcode_server_client_connected( server, 0 ) == 1 );
    check( netcode_server_num_connected_clients( server ) == 1 );

    test_exchange_packets_then_disconnect( network_simulator, client, server, time, delta_time );

    netcode_server_destroy( server );

    netcode_client_destroy( client );

    netcode_network_simulator_destroy( network_simulator );
}

function test_client_error_connect_token_expired(): void
{
    const network_simulator = test_network_simulator_create_lossy();

    const time = 0.0;

    const client = test_create_simulator_client( "[::]:50000", network_simulator, time );

    const server_address = [ "[::1]:40000" ];

    const connect_token = new Uint8Array( NETCODE_CONNECT_TOKEN_BYTES );

    const client_id = random_uint64();

    const user_data = new Uint8Array( NETCODE_USER_DATA_BYTES );
    netcode_random_bytes( user_data, NETCODE_USER_DATA_BYTES );

    check( netcode_generate_connect_token( 1, server_address, server_address, 0, TEST_TIMEOUT_SECONDS, client_id, TEST_PROTOCOL_ID, private_key, user_data, connect_token ) );

    netcode_client_connect( client, connect_token );

    netcode_client_update( client, time );

    check( netcode_client_state( client ) == NETCODE_CLIENT_STATE_CONNECT_TOKEN_EXPIRED );

    netcode_client_destroy( client );

    netcode_network_simulator_destroy( network_simulator );
}

function test_client_error_invalid_connect_token(): void
{
    const network_simulator = test_network_simulator_create_lossy();

    const time = 0.0;

    const client = test_create_simulator_client( "[::]:50000", network_simulator, time );

    const connect_token = new Uint8Array( NETCODE_CONNECT_TOKEN_BYTES );
    netcode_random_bytes( connect_token, NETCODE_CONNECT_TOKEN_BYTES );

    netcode_client_connect( client, connect_token );

    check( netcode_client_state( client ) == NETCODE_CLIENT_STATE_INVALID_CONNECT_TOKEN );

    netcode_client_destroy( client );

    netcode_network_simulator_destroy( network_simulator );
}

function test_client_error_connection_timed_out(): void
{
    const network_simulator = test_network_simulator_create_lossy();

    let time = 0.0;
    const delta_time = 1.0 / 10.0;

    // connect a client to the server

    const client = test_create_simulator_client( "[::]:50000", network_simulator, time );

    const server = test_create_simulator_server( "[::1]:40000", network_simulator, time );

    netcode_server_start( server, 1 );

    const connect_token = test_generate_connect_token( "[::1]:40000", random_uint64() );

    netcode_client_connect( client, connect_token );

    time = test_connect_simulator_client( network_simulator, client, server, time, delta_time );

    check( netcode_client_state( client ) == NETCODE_CLIENT_STATE_CONNECTED );
    check( netcode_client_index( client ) == 0 );
    check( netcode_server_client_connected( server, 0 ) == 1 );
    check( netcode_server_num_connected_clients( server ) == 1 );

    // now disable updating the server and verify that the client times out

    while ( true )
    {
        netcode_network_simulator_update( network_simulator, time );

        netcode_client_update( client, time );

        if ( netcode_client_state( client ) <= NETCODE_CLIENT_STATE_DISCONNECTED )
            break;

        time += delta_time;
    }

    check( netcode_client_state( client ) == NETCODE_CLIENT_STATE_CONNECTION_TIMED_OUT );

    netcode_server_destroy( server );

    netcode_client_destroy( client );

    netcode_network_simulator_destroy( network_simulator );
}

function test_client_error_connection_response_timeout(): void
{
    const network_simulator = test_network_simulator_create_lossy();

    let time = 0.0;
    const delta_time = 1.0 / 10.0;

    const client = test_create_simulator_client( "[::]:50000", network_simulator, time );

    const server = test_create_simulator_server( "[::1]:40000", network_simulator, time );

    server.flags = NETCODE_SERVER_FLAG_IGNORE_CONNECTION_RESPONSE_PACKETS;

    netcode_server_start( server, 1 );

    const connect_token = test_generate_connect_token( "[::1]:40000", random_uint64() );

    netcode_client_connect( client, connect_token );

    time = test_connect_simulator_client( network_simulator, client, server, time, delta_time );

    check( netcode_client_state( client ) == NETCODE_CLIENT_STATE_CONNECTION_RESPONSE_TIMED_OUT );

    netcode_server_destroy( server );

    netcode_client_destroy( client );

    netcode_network_simulator_destroy( network_simulator );
}

function test_client_error_connection_request_timeout(): void
{
    const network_simulator = test_network_simulator_create_lossy();

    let time = 0.0;
    const delta_time = 1.0 / 60.0;

    const client = test_create_simulator_client( "[::]:50000", network_simulator, time );

    const server = test_create_simulator_server( "[::1]:40000", network_simulator, time );

    server.flags = NETCODE_SERVER_FLAG_IGNORE_CONNECTION_REQUEST_PACKETS;

    netcode_server_start( server, 1 );

    const connect_token = test_generate_connect_token( "[::1]:40000", random_uint64() );

    netcode_client_connect( client, connect_token );

    time = test_connect_simulator_client( network_simulator, client, server, time, delta_time );

    check( netcode_client_state( client ) == NETCODE_CLIENT_STATE_CONNECTION_REQUEST_TIMED_OUT );

    netcode_server_destroy( server );

    netcode_client_destroy( client );

    netcode_network_simulator_destroy( network_simulator );
}

function test_client_error_connection_denied(): void
{
    const network_simulator = test_network_simulator_create_lossy();

    // start a server and connect one client

    let time = 0.0;
    const delta_time = 1.0 / 10.0;

    const client = test_create_simulator_client( "[::]:50000", network_simulator, time );

    const server = test_create_simulator_server( "[::1]:40000", network_simulator, time );

    netcode_server_start( server, 1 );

    const connect_token = test_generate_connect_token( "[::1]:40000", random_uint64() );

    netcode_client_connect( client, connect_token );

    time = test_connect_simulator_client( network_simulator, client, server, time, delta_time );

    check( netcode_client_state( client ) == NETCODE_CLIENT_STATE_CONNECTED );
    check( netcode_client_index( client ) == 0 );
    check( netcode_server_client_connected( server, 0 ) == 1 );
    check( netcode_server_num_connected_clients( server ) == 1 );

    // now attempt to connect a second client. the connection should be denied.

    const client2 = test_create_simulator_client( "[::]:50001", network_simulator, time );

    const connect_token2 = test_generate_connect_token( "[::1]:40000", random_uint64() );

    netcode_client_connect( client2, connect_token2 );

    while ( true )
    {
        netcode_network_simulator_update( network_simulator, time );

        netcode_client_update( client, time );

        netcode_client_update( client2, time );

        netcode_server_update( server, time );

        if ( netcode_client_state( client ) <= NETCODE_CLIENT_STATE_DISCONNECTED )
            break;

        if ( netcode_client_state( client2 ) <= NETCODE_CLIENT_STATE_DISCONNECTED )
            break;

        time += delta_time;
    }

    check( netcode_client_state( client ) == NETCODE_CLIENT_STATE_CONNECTED );
    check( netcode_client_state( client2 ) == NETCODE_CLIENT_STATE_CONNECTION_DENIED );
    check( netcode_server_client_connected( server, 0 ) == 1 );
    check( netcode_server_num_connected_clients( server ) == 1 );

    netcode_server_destroy( server );

    netcode_client_destroy( client );

    netcode_client_destroy( client2 );

    netcode_network_simulator_destroy( network_simulator );
}

function test_client_side_disconnect(): void
{
    const network_simulator = netcode_network_simulator_create( null, null, null );

    // start a server and connect one client

    let time = 0.0;
    const delta_time = 1.0 / 10.0;

    const client = test_create_simulator_client( "[::]:50000", network_simulator, time );

    const server = test_create_simulator_server( "[::1]:40000", network_simulator, time );

    netcode_server_start( server, 1 );

    const connect_token = test_generate_connect_token( "[::1]:40000", random_uint64() );

    netcode_client_connect( client, connect_token );

    time = test_connect_simulator_client( network_simulator, client, server, time, delta_time );

    check( netcode_client_state( client ) == NETCODE_CLIENT_STATE_CONNECTED );
    check( netcode_client_index( client ) == 0 );
    check( netcode_server_client_connected( server, 0 ) == 1 );
    check( netcode_server_num_connected_clients( server ) == 1 );

    // disconnect client side and verify that the server sees that client disconnect cleanly, rather than timing out.

    netcode_client_disconnect( client );

    for ( let i = 0; i < 10; i++ )
    {
        netcode_network_simulator_update( network_simulator, time );

        netcode_client_update( client, time );

        netcode_server_update( server, time );

        if ( netcode_server_client_connected( server, 0 ) == 0 )
            break;

        time += delta_time;
    }

    check( netcode_server_client_connected( server, 0 ) == 0 );
    check( netcode_server_num_connected_clients( server ) == 0 );
    check( netcode_server_client_disconnect_reason( server, 0 ) == NETCODE_SERVER_CLIENT_DISCONNECT_REASON_CLIENT_DISCONNECT );

    netcode_server_destroy( server );

    netcode_client_destroy( client );

    netcode_network_simulator_destroy( network_simulator );
}

function test_server_side_disconnect(): void
{
    const network_simulator = netcode_network_simulator_create( null, null, null );

    // start a server and connect one client

    let time = 0.0;
    const delta_time = 1.0 / 10.0;

    const client = test_create_simulator_client( "[::]:50000", network_simulator, time );

    const server = test_create_simulator_server( "[::1]:40000", network_simulator, time );

    netcode_server_start( server, 1 );

    const connect_token = test_generate_connect_token( "[::1]:40000", random_uint64() );

    netcode_client_connect( client, connect_token );

    time = test_connect_simulator_client( network_simulator, client, server, time, delta_time );

    check( netcode_client_state( client ) == NETCODE_CLIENT_STATE_CONNECTED );
    check( netcode_client_index( client ) == 0 );
    check( netcode_server_client_connected( server, 0 ) == 1 );
    check( netcode_server_num_connected_clients( server ) == 1 );

    // disconnect server side and verify that the client disconnects cleanly, rather than timing out.

    netcode_server_disconnect_client( server, 0 );

    for ( let i = 0; i < 10; i++ )
    {
        netcode_network_simulator_update( network_simulator, time );

        netcode_client_update( client, time );

        netcode_server_update( server, time );

        if ( netcode_client_state( client ) == NETCODE_CLIENT_STATE_DISCONNECTED )
            break;

        time += delta_time;
    }

    check( netcode_client_state( client ) == NETCODE_CLIENT_STATE_DISCONNECTED );
    check( netcode_server_client_connected( server, 0 ) == 0 );
    check( netcode_server_num_connected_clients( server ) == 0 );
    check( netcode_server_client_disconnect_reason( server, 0 ) == NETCODE_SERVER_CLIENT_DISCONNECT_REASON_SERVER_DISCONNECT );

    netcode_server_destroy( server );

    netcode_client_destroy( client );

    netcode_network_simulator_destroy( network_simulator );
}

function test_server_client_disconnect_reason(): void
{
    const network_simulator = netcode_network_simulator_create( null, null, null );

    // start a server and connect one client

    let time = 0.0;
    const delta_time = 1.0 / 10.0;

    const client = test_create_simulator_client( "[::]:50000", network_simulator, time );

    const server = test_create_simulator_server( "[::1]:40000", network_simulator, time );

    netcode_server_start( server, 1 );

    // no disconnect has happened yet, so the client slot reason is none

    check( netcode_server_client_disconnect_reason( server, 0 ) == NETCODE_SERVER_CLIENT_DISCONNECT_REASON_NONE );

    const server_address = [ "[::1]:40000" ];

    const connect_token = new Uint8Array( NETCODE_CONNECT_TOKEN_BYTES );

    const client_id = random_uint64();

    const user_data = new Uint8Array( NETCODE_USER_DATA_BYTES );
    netcode_random_bytes( user_data, NETCODE_USER_DATA_BYTES );

    check( netcode_generate_connect_token( 1, server_address, server_address, TEST_CONNECT_TOKEN_EXPIRY, TEST_TIMEOUT_SECONDS, client_id, TEST_PROTOCOL_ID, private_key, user_data, connect_token ) );

    netcode_client_connect( client, connect_token );

    time = test_connect_simulator_client( network_simulator, client, server, time, delta_time );

    check( netcode_client_state( client ) == NETCODE_CLIENT_STATE_CONNECTED );
    check( netcode_server_client_connected( server, 0 ) == 1 );
    check( netcode_server_client_disconnect_reason( server, 0 ) == NETCODE_SERVER_CLIENT_DISCONNECT_REASON_NONE );

    // stop updating the client so it goes silent. the server should time it out
    // and record that as the disconnect reason, distinct from a clean disconnect

    for ( let i = 0; i < 200; i++ )
    {
        netcode_network_simulator_update( network_simulator, time );

        netcode_server_update( server, time );

        if ( !netcode_server_client_connected( server, 0 ) )
            break;

        time += delta_time;
    }

    check( netcode_server_client_connected( server, 0 ) == 0 );
    check( netcode_server_num_connected_clients( server ) == 0 );
    check( netcode_server_client_disconnect_reason( server, 0 ) == NETCODE_SERVER_CLIENT_DISCONNECT_REASON_TIMED_OUT );

    // reconnect. a new client connecting to the slot clears the reason back to none

    netcode_client_disconnect( client );

    // catch the client's internal clock up to the current time before reconnecting, since it
    // was deliberately not updated above. otherwise the first update after connect sees the
    // whole timeout leg as elapsed time and immediately times out the connection request.
    netcode_client_update( client, time );

    netcode_network_simulator_reset( network_simulator );

    check( netcode_generate_connect_token( 1, server_address, server_address, TEST_CONNECT_TOKEN_EXPIRY, TEST_TIMEOUT_SECONDS, client_id, TEST_PROTOCOL_ID, private_key, user_data, connect_token ) );

    netcode_client_connect( client, connect_token );

    time = test_connect_simulator_client( network_simulator, client, server, time, delta_time );

    check( netcode_client_state( client ) == NETCODE_CLIENT_STATE_CONNECTED );
    check( netcode_server_client_connected( server, 0 ) == 1 );
    check( netcode_server_client_disconnect_reason( server, 0 ) == NETCODE_SERVER_CLIENT_DISCONNECT_REASON_NONE );

    netcode_server_destroy( server );

    netcode_client_destroy( client );

    netcode_network_simulator_destroy( network_simulator );
}

function test_client_reconnect(): void
{
    const network_simulator = test_network_simulator_create_lossy();

    // start a server and connect one client

    let time = 0.0;
    const delta_time = 1.0 / 10.0;

    const client = test_create_simulator_client( "[::]:50000", network_simulator, time );

    const server = test_create_simulator_server( "[::1]:40000", network_simulator, time );

    netcode_server_start( server, 1 );

    const server_address = [ "[::1]:40000" ];

    const connect_token = new Uint8Array( NETCODE_CONNECT_TOKEN_BYTES );

    const client_id = random_uint64();

    const user_data = new Uint8Array( NETCODE_USER_DATA_BYTES );
    netcode_random_bytes( user_data, NETCODE_USER_DATA_BYTES );

    check( netcode_generate_connect_token( 1, server_address, server_address, TEST_CONNECT_TOKEN_EXPIRY, TEST_TIMEOUT_SECONDS, client_id, TEST_PROTOCOL_ID, private_key, user_data, connect_token ) );

    netcode_client_connect( client, connect_token );

    time = test_connect_simulator_client( network_simulator, client, server, time, delta_time );

    check( netcode_client_state( client ) == NETCODE_CLIENT_STATE_CONNECTED );
    check( netcode_client_index( client ) == 0 );
    check( netcode_server_client_connected( server, 0 ) == 1 );
    check( netcode_server_num_connected_clients( server ) == 1 );

    // disconnect client on the server-side and wait until client sees the disconnect

    netcode_network_simulator_reset( network_simulator );

    netcode_server_disconnect_client( server, 0 );

    while ( true )
    {
        netcode_network_simulator_update( network_simulator, time );

        netcode_client_update( client, time );

        netcode_server_update( server, time );

        if ( netcode_client_state( client ) <= NETCODE_CLIENT_STATE_DISCONNECTED )
            break;

        time += delta_time;
    }

    check( netcode_client_state( client ) == NETCODE_CLIENT_STATE_DISCONNECTED );
    check( netcode_server_client_connected( server, 0 ) == 0 );
    check( netcode_server_num_connected_clients( server ) == 0 );

    // now reconnect the client and verify they connect

    netcode_network_simulator_reset( network_simulator );

    check( netcode_generate_connect_token( 1, server_address, server_address, TEST_CONNECT_TOKEN_EXPIRY, TEST_TIMEOUT_SECONDS, client_id, TEST_PROTOCOL_ID, private_key, user_data, connect_token ) );

    netcode_client_connect( client, connect_token );

    time = test_connect_simulator_client( network_simulator, client, server, time, delta_time );

    check( netcode_client_state( client ) == NETCODE_CLIENT_STATE_CONNECTED );
    check( netcode_client_index( client ) == 0 );
    check( netcode_server_client_connected( server, 0 ) == 1 );
    check( netcode_server_num_connected_clients( server ) == 1 );

    netcode_server_destroy( server );

    netcode_client_destroy( client );

    netcode_network_simulator_destroy( network_simulator );
}

function test_connect_token_entries(): void
{
    const connect_token_entries = netcode_connect_token_entries_create();

    netcode_connect_token_entries_reset( connect_token_entries );

    const address_a = new netcode_address_t();
    const address_b = new netcode_address_t();

    check( netcode_parse_address( "[::1]:50000", address_a ) == NETCODE_OK );
    check( netcode_parse_address( "[::1]:50001", address_b ) == NETCODE_OK );

    const current_timestamp = 1000n;
    const expire_timestamp = current_timestamp + 30n;

    const mac = new Uint8Array( NETCODE_MAC_BYTES );

    // a connect token the history has not seen creates a pending entry

    mac[0] = 1;

    const index = netcode_connect_token_entries_find_or_add( connect_token_entries, address_a, mac, expire_timestamp, current_timestamp, 100.0 );

    check( index >= 0 );
    check( connect_token_entries[index].state == NETCODE_CONNECT_TOKEN_ENTRY_PENDING );
    check( connect_token_entries[index].time == 100.0 );

    // a pending entry admits a retransmitted connection request from the address that created it,
    // and the entry time is not refreshed

    check( netcode_connect_token_entries_find_or_add( connect_token_entries, address_a, mac, expire_timestamp, current_timestamp, 200.0 ) == index );
    check( connect_token_entries[index].time == 100.0 );

    // a pending entry refuses every other address

    check( netcode_connect_token_entries_find_or_add( connect_token_entries, address_b, mac, expire_timestamp, current_timestamp, 200.0 ) == NETCODE_CONNECT_TOKEN_ENTRY_REFUSED );

    // a consumed entry admits nothing, including the address that used the connect token

    netcode_connect_token_entries_consume( connect_token_entries, index );

    check( connect_token_entries[index].state == NETCODE_CONNECT_TOKEN_ENTRY_CONSUMED );
    check( netcode_connect_token_entries_find_or_add( connect_token_entries, address_a, mac, expire_timestamp, current_timestamp, 300.0 ) == NETCODE_CONNECT_TOKEN_ENTRY_REFUSED );
    check( netcode_connect_token_entries_find_or_add( connect_token_entries, address_b, mac, expire_timestamp, current_timestamp, 300.0 ) == NETCODE_CONNECT_TOKEN_ENTRY_REFUSED );

    // a history whose entries all hold unexpired connect tokens refuses a new connect token
    // instead of evicting one

    for ( let i = 1; i < NETCODE_MAX_CONNECT_TOKEN_ENTRIES; i++ )
    {
        mac.fill( 0 );
        mac[0] = ( i + 1 ) & 0xFF;
        mac[1] = ( ( i + 1 ) >> 8 ) & 0xFF;
        check( netcode_connect_token_entries_find_or_add( connect_token_entries, address_a, mac, expire_timestamp, current_timestamp, 400.0 ) >= 0 );
    }

    mac.fill( 0 );
    mac[0] = 0xFF;
    mac[1] = 0xFF;

    check( netcode_connect_token_entries_find_or_add( connect_token_entries, address_a, mac, expire_timestamp, current_timestamp, 500.0 ) == NETCODE_CONNECT_TOKEN_HISTORY_FULL );

    // the consumed entry is still refusing its connect token, and was not evicted by the flood

    mac.fill( 0 );
    mac[0] = 1;

    check( netcode_connect_token_entries_find_or_add( connect_token_entries, address_a, mac, expire_timestamp, current_timestamp, 500.0 ) == NETCODE_CONNECT_TOKEN_ENTRY_REFUSED );

    // entries live until their connect token expires. once they have, the history takes new connect tokens again

    mac.fill( 0 );
    mac[0] = 0xFF;
    mac[1] = 0xFF;

    check( netcode_connect_token_entries_find_or_add( connect_token_entries, address_a, mac, expire_timestamp, expire_timestamp, 600.0 ) >= 0 );
}

/*
    A client and a server wired directly to each other through the send and receive overrides.
    Packets are handed straight to the other side, so the handshake is exercised with no sockets,
    no network simulator and no randomness at all. The wire can drop the first packets the server
    sends, which is what makes the client retransmit its connection request, and it keeps a copy
    of the first payload packet the client sends so it can be replayed later.
*/

class test_wire_t
{
    client: netcode_client_t | null = null;
    server: netcode_server_t | null = null;
    client_address = new netcode_address_t();
    server_address = new netcode_address_t();
    shutting_down = 0;
    drop_server_packets = 0;
    num_connection_requests = 0;
    payload_packet = new Uint8Array( NETCODE_MAX_PACKET_BYTES );
    payload_packet_bytes = 0;
}

let test_wire = new test_wire_t();

function test_wire_client_send_packet( context: unknown, to: netcode_address_t, packet_data: Uint8Array, packet_bytes: number ): void
{
    void context;
    void to;

    // the wire is down once either end is being destroyed. the disconnect packets they send
    // on the way out have nowhere to go, exactly as an application shutting down would find

    if ( test_wire.shutting_down )
        return;

    if ( packet_data[0] == NETCODE_CONNECTION_REQUEST_PACKET )
    {
        test_wire.num_connection_requests++;
    }

    if ( ( packet_data[0] & 0xF ) == NETCODE_CONNECTION_PAYLOAD_PACKET && test_wire.payload_packet_bytes == 0 )
    {
        test_wire.payload_packet.set( packet_data.subarray( 0, packet_bytes ) );
        test_wire.payload_packet_bytes = packet_bytes;
    }

    netcode_server_process_packet( test_wire.server!, test_wire.client_address, packet_data, packet_bytes );
}

function test_wire_server_send_packet( context: unknown, to: netcode_address_t, packet_data: Uint8Array, packet_bytes: number ): void
{
    void context;
    void to;

    if ( test_wire.shutting_down )
        return;

    if ( test_wire.drop_server_packets > 0 )
    {
        test_wire.drop_server_packets--;
        return;
    }

    netcode_client_process_packet( test_wire.client!, test_wire.server_address, packet_data, packet_bytes );
}

function test_wire_receive_packet( context: unknown, from: netcode_address_t, packet_data: Uint8Array, max_packet_bytes: number ): number
{
    void context;
    void from;
    void packet_data;
    void max_packet_bytes;
    return 0;
}

function test_wire_create( drop_server_packets: number ): void
{
    test_wire = new test_wire_t();

    test_wire.drop_server_packets = drop_server_packets;

    check( netcode_parse_address( "[::1]:50000", test_wire.client_address ) == NETCODE_OK );
    check( netcode_parse_address( "[::1]:40000", test_wire.server_address ) == NETCODE_OK );

    const client_config = new netcode_client_config_t();
    netcode_default_client_config( client_config );
    client_config.override_send_and_receive = 1;
    client_config.send_packet_override = test_wire_client_send_packet;
    client_config.receive_packet_override = test_wire_receive_packet;

    test_wire.client = netcode_client_create( "[::1]:50000", client_config, 0.0 );

    check( test_wire.client );

    const server_config = new netcode_server_config_t();
    netcode_default_server_config( server_config );
    server_config.protocol_id = TEST_PROTOCOL_ID;
    server_config.override_send_and_receive = 1;
    server_config.send_packet_override = test_wire_server_send_packet;
    server_config.receive_packet_override = test_wire_receive_packet;
    server_config.private_key.set( private_key );

    test_wire.server = netcode_server_create( "[::1]:40000", server_config, 0.0 );

    check( test_wire.server );

    netcode_server_start( test_wire.server!, 1 );
}

function test_wire_destroy(): void
{
    test_wire.shutting_down = 1;
    netcode_server_destroy( test_wire.server! );
    netcode_client_destroy( test_wire.client! );
    test_wire = new test_wire_t();
}

/** returns the new time */
function test_wire_connect_client( connect_token: Uint8Array, time: number, delta_time: number ): number
{
    netcode_client_connect( test_wire.client!, connect_token );

    while ( true )
    {
        netcode_client_update( test_wire.client!, time );

        netcode_server_update( test_wire.server!, time );

        if ( netcode_client_state( test_wire.client! ) <= NETCODE_CLIENT_STATE_DISCONNECTED )
            break;

        if ( netcode_client_state( test_wire.client! ) == NETCODE_CLIENT_STATE_CONNECTED )
            break;

        time += delta_time;
    }

    return time;
}

function test_wire_generate_connect_token( connect_token: Uint8Array, client_id: bigint, expire_seconds: number ): void
{
    const server_address = [ "[::1]:40000" ];

    const user_data = new Uint8Array( NETCODE_USER_DATA_BYTES );
    netcode_random_bytes( user_data, NETCODE_USER_DATA_BYTES );

    check( netcode_generate_connect_token( 1, server_address, server_address, expire_seconds, TEST_TIMEOUT_SECONDS, client_id, TEST_PROTOCOL_ID, private_key, user_data, connect_token ) );
}

function test_client_server_connection_request_retransmission(): void
{
    // the first three packets the server sends are dropped, so the client retransmits its
    // connection request into a handshake the server already has a pending history entry for

    test_wire_create( 3 );

    let time = 0.0;
    const delta_time = 1.0 / 10.0;

    const connect_token = new Uint8Array( NETCODE_CONNECT_TOKEN_BYTES );
    test_wire_generate_connect_token( connect_token, TEST_CLIENT_ID, TEST_CONNECT_TOKEN_EXPIRY );

    time = test_wire_connect_client( connect_token, time, delta_time );

    check( netcode_client_state( test_wire.client! ) == NETCODE_CLIENT_STATE_CONNECTED );
    check( netcode_server_client_connected( test_wire.server!, 0 ) == 1 );
    check( netcode_server_num_connected_clients( test_wire.server! ) == 1 );
    check( test_wire.num_connection_requests >= 4 );

    test_wire_destroy();
}

function test_client_server_replay_across_sessions(): void
{
    test_wire_create( 0 );

    let time = 0.0;
    const delta_time = 1.0 / 10.0;

    // connect a first session and keep a copy of a payload packet the client sends in it

    const connect_token = new Uint8Array( NETCODE_CONNECT_TOKEN_BYTES );
    test_wire_generate_connect_token( connect_token, TEST_CLIENT_ID, TEST_CONNECT_TOKEN_EXPIRY );

    time = test_wire_connect_client( connect_token, time, delta_time );

    check( netcode_client_state( test_wire.client! ) == NETCODE_CLIENT_STATE_CONNECTED );

    const payload = new Uint8Array( NETCODE_MAX_PACKET_SIZE );
    for ( let i = 0; i < NETCODE_MAX_PACKET_SIZE; i++ )
    {
        payload[i] = i & 0xFF;
    }

    netcode_client_send_packet( test_wire.client!, payload, NETCODE_MAX_PACKET_SIZE );

    check( test_wire.payload_packet_bytes > 0 );

    // disconnect, then connect a second session with a new connect token

    netcode_server_disconnect_client( test_wire.server!, 0 );

    while ( netcode_client_state( test_wire.client! ) > NETCODE_CLIENT_STATE_DISCONNECTED )
    {
        netcode_client_update( test_wire.client!, time );
        netcode_server_update( test_wire.server!, time );
        time += delta_time;
    }

    const second_connect_token = new Uint8Array( NETCODE_CONNECT_TOKEN_BYTES );
    test_wire_generate_connect_token( second_connect_token, TEST_CLIENT_ID, TEST_CONNECT_TOKEN_EXPIRY );

    time = test_wire_connect_client( second_connect_token, time, delta_time );

    check( netcode_client_state( test_wire.client! ) == NETCODE_CLIENT_STATE_CONNECTED );

    // drain anything the second session has delivered so far

    while ( true )
    {
        const packet_bytes = { value: 0 };
        const packet_sequence = { value: 0n };
        const packet = netcode_server_receive_packet( test_wire.server!, 0, packet_bytes, packet_sequence );
        if ( !packet )
            break;
        netcode_server_free_packet( test_wire.server!, packet );
    }

    // the datagram from the first session is refused by the second

    netcode_server_process_packet( test_wire.server!, test_wire.client_address, test_wire.payload_packet, test_wire.payload_packet_bytes );

    const packet_bytes = { value: 0 };
    const packet_sequence = { value: 0n };

    check( netcode_server_receive_packet( test_wire.server!, 0, packet_bytes, packet_sequence ) == null );

    test_wire_destroy();
}

function test_client_reconnect_with_used_connect_token(): void
{
    test_wire_create( 0 );

    let time = 0.0;
    const delta_time = 1.0 / 10.0;

    const connect_token = new Uint8Array( NETCODE_CONNECT_TOKEN_BYTES );
    test_wire_generate_connect_token( connect_token, TEST_CLIENT_ID, TEST_CONNECT_TOKEN_EXPIRY );

    time = test_wire_connect_client( connect_token, time, delta_time );

    check( netcode_client_state( test_wire.client! ) == NETCODE_CLIENT_STATE_CONNECTED );
    check( netcode_server_num_connected_clients( test_wire.server! ) == 1 );

    // disconnect the client server side and wait until the client sees it

    netcode_server_disconnect_client( test_wire.server!, 0 );

    while ( netcode_client_state( test_wire.client! ) > NETCODE_CLIENT_STATE_DISCONNECTED )
    {
        netcode_client_update( test_wire.client!, time );
        netcode_server_update( test_wire.server!, time );
        time += delta_time;
    }

    check( netcode_server_num_connected_clients( test_wire.server! ) == 0 );

    // the connect token is spent. presenting it again, from the same address that used it,
    // connects nothing: the client runs out of connection request retries instead

    time = test_wire_connect_client( connect_token, time, delta_time );

    check( netcode_client_state( test_wire.client! ) == NETCODE_CLIENT_STATE_CONNECTION_REQUEST_TIMED_OUT );
    check( netcode_server_num_connected_clients( test_wire.server! ) == 0 );

    test_wire_destroy();
}

function test_client_error_connect_token_predates_server_start(): void
{
    test_wire_create( 0 );

    let time = 0.0;
    const delta_time = 1.0 / 10.0;

    // a connect token with a shorter lifetime than the server's configured maximum expires
    // earlier than any connect token the backend could have issued after the server started,
    // which is exactly the shape of a connect token issued before it started

    const connect_token = new Uint8Array( NETCODE_CONNECT_TOKEN_BYTES );
    test_wire_generate_connect_token( connect_token, TEST_CLIENT_ID, NETCODE_DEFAULT_MAX_CONNECT_TOKEN_LIFETIME - 10 );

    time = test_wire_connect_client( connect_token, time, delta_time );

    check( netcode_client_state( test_wire.client! ) == NETCODE_CLIENT_STATE_CONNECTION_REQUEST_TIMED_OUT );
    check( netcode_server_num_connected_clients( test_wire.server! ) == 0 );

    // a connect token with the full lifetime connects

    test_wire_generate_connect_token( connect_token, TEST_CLIENT_ID, TEST_CONNECT_TOKEN_EXPIRY );

    time = test_wire_connect_client( connect_token, time, delta_time );

    check( netcode_client_state( test_wire.client! ) == NETCODE_CLIENT_STATE_CONNECTED );
    check( netcode_server_num_connected_clients( test_wire.server! ) == 1 );

    test_wire_destroy();
}

function test_nonce_audit(): void
{
    // every packet every test above encrypted was recorded by key and nonce. a repeat is a
    // connect token encrypting two sessions, which is what the connect token lifecycle prevents

    netcode_printf( NETCODE_LOG_LEVEL_NONE, "    %d key and nonce pairs recorded\n", netcode_nonce_audit_num_pairs() );

    check( netcode_nonce_audit_num_pairs() > 0 );
    check( netcode_nonce_audit_overflow() == 0 );
    check( netcode_nonce_audit_repeats() == 0 );
}

class test_loopback_context_t
{
    client: netcode_client_t | null = null;
    server: netcode_server_t | null = null;
    num_loopback_packets_sent_to_client = 0;
    num_loopback_packets_sent_to_server = 0;
}

function client_send_loopback_packet_callback( _context: unknown, client_index: number, packet_data: Uint8Array, packet_bytes: number, packet_sequence: bigint ): void
{
    check( _context );
    check( client_index == 0 );
    check( packet_data );
    check( packet_bytes == NETCODE_MAX_PACKET_SIZE );
    for ( let i = 0; i < packet_bytes; i++ )
    {
        check( packet_data[i] == ( i & 0xFF ) );
    }
    const context = _context as test_loopback_context_t;
    context.num_loopback_packets_sent_to_server++;
    netcode_server_process_loopback_packet( context.server!, client_index, packet_data, packet_bytes, packet_sequence );
}

function server_send_loopback_packet_callback( _context: unknown, client_index: number, packet_data: Uint8Array, packet_bytes: number, packet_sequence: bigint ): void
{
    check( _context );
    check( client_index == 0 );
    check( packet_data );
    check( packet_bytes == NETCODE_MAX_PACKET_SIZE );
    for ( let i = 0; i < packet_bytes; i++ )
    {
        check( packet_data[i] == ( i & 0xFF ) );
    }
    const context = _context as test_loopback_context_t;
    context.num_loopback_packets_sent_to_client++;
    netcode_client_process_loopback_packet( context.client!, packet_data, packet_bytes, packet_sequence );
}

function test_disable_timeout(): void
{
    const network_simulator = test_network_simulator_create_lossy();

    let time = 0.0;
    const delta_time = 1.0 / 10.0;

    const client = test_create_simulator_client( "[::]:50000", network_simulator, time );

    const server = test_create_simulator_server( "[::1]:40000", network_simulator, time );

    netcode_server_start( server, 1 );

    const connect_token = test_generate_connect_token( "[::1]:40000", random_uint64(), -1 );

    netcode_client_connect( client, connect_token );

    time = test_connect_simulator_client( network_simulator, client, server, time, delta_time );

    check( netcode_client_state( client ) == NETCODE_CLIENT_STATE_CONNECTED );
    check( netcode_client_index( client ) == 0 );
    check( netcode_server_client_connected( server, 0 ) == 1 );
    check( netcode_server_num_connected_clients( server ) == 1 );

    test_exchange_packets_then_disconnect( network_simulator, client, server, time, 1000.0 );        // normally this would timeout the client

    netcode_server_destroy( server );

    netcode_client_destroy( client );

    netcode_network_simulator_destroy( network_simulator );
}

function test_loopback(): void
{
    const context = new test_loopback_context_t();

    const network_simulator = test_network_simulator_create_lossy();

    let time = 0.0;
    const delta_time = 1.0 / 10.0;

    // start the server

    const server_config = new netcode_server_config_t();
    netcode_default_server_config( server_config );
    server_config.protocol_id = TEST_PROTOCOL_ID;
    server_config.network_simulator = network_simulator;
    server_config.callback_context = context;
    server_config.send_loopback_packet_callback = server_send_loopback_packet_callback;
    server_config.private_key.set( private_key );

    const server = netcode_server_create( "[::1]:40000", server_config, time )!;

    check( server );

    const max_clients = 2;

    netcode_server_start( server, max_clients );

    context.server = server;

    // connect a loopback client in slot 0

    const client_config = new netcode_client_config_t();
    netcode_default_client_config( client_config );
    client_config.callback_context = context;
    client_config.send_loopback_packet_callback = client_send_loopback_packet_callback;
    client_config.network_simulator = network_simulator;

    const loopback_client = netcode_client_create( "[::]:50000", client_config, time )!;
    check( loopback_client );
    netcode_client_connect_loopback( loopback_client, 0, max_clients );
    context.client = loopback_client;

    check( netcode_client_index( loopback_client ) == 0 );
    check( netcode_client_loopback( loopback_client ) == 1 );
    check( netcode_client_max_clients( loopback_client ) == max_clients );
    check( netcode_client_state( loopback_client ) == NETCODE_CLIENT_STATE_CONNECTED );

    netcode_server_connect_loopback_client( server, 0, random_uint64(), null );

    check( netcode_server_client_loopback( server, 0 ) == 1 );
    check( netcode_server_client_connected( server, 0 ) == 1 );
    check( netcode_server_num_connected_clients( server ) == 1 );

    // connect a regular client in the other slot

    const regular_client = netcode_client_create( "[::]:50001", client_config, time )!;

    check( regular_client );

    const connect_token = test_generate_connect_token( "[::1]:40000", random_uint64() );

    netcode_client_connect( regular_client, connect_token );

    time = test_connect_simulator_client( network_simulator, regular_client, server, time, delta_time );

    check( netcode_client_state( regular_client ) == NETCODE_CLIENT_STATE_CONNECTED );
    check( netcode_client_index( regular_client ) == 1 );
    check( netcode_server_client_connected( server, 0 ) == 1 );
    check( netcode_server_client_connected( server, 1 ) == 1 );
    check( netcode_server_client_loopback( server, 0 ) == 1 );
    check( netcode_server_client_loopback( server, 1 ) == 0 );
    check( netcode_server_num_connected_clients( server ) == 2 );

    // test that we can exchange packets for the regular client and the loopback client

    const packet_data = test_packet_data();

    const exchange_packets = (): void =>
    {
        let loopback_client_num_packets_received = 0;
        let loopback_server_num_packets_received = 0;
        let regular_server_num_packets_received = 0;
        let regular_client_num_packets_received = 0;

        while ( true )
        {
            netcode_network_simulator_update( network_simulator, time );

            netcode_client_update( regular_client, time );

            netcode_server_update( server, time );

            netcode_client_send_packet( loopback_client, packet_data, NETCODE_MAX_PACKET_SIZE );

            netcode_client_send_packet( regular_client, packet_data, NETCODE_MAX_PACKET_SIZE );

            netcode_server_send_packet( server, 0, packet_data, NETCODE_MAX_PACKET_SIZE );

            netcode_server_send_packet( server, 1, packet_data, NETCODE_MAX_PACKET_SIZE );

            loopback_client_num_packets_received += test_drain_client_packets( loopback_client, packet_data );

            regular_client_num_packets_received += test_drain_client_packets( regular_client, packet_data );

            loopback_server_num_packets_received += test_drain_server_packets( server, 0, packet_data );

            regular_server_num_packets_received += test_drain_server_packets( server, 1, packet_data );

            if ( loopback_client_num_packets_received >= 10 && loopback_server_num_packets_received >= 10 &&
                 regular_client_num_packets_received >= 10 && regular_server_num_packets_received >= 10 )
                break;

            if ( netcode_client_state( regular_client ) <= NETCODE_CLIENT_STATE_DISCONNECTED )
                break;

            time += delta_time;
        }

        check( loopback_client_num_packets_received >= 10 );
        check( loopback_server_num_packets_received >= 10 );
        check( regular_client_num_packets_received >= 10 );
        check( regular_server_num_packets_received >= 10 );
        check( context.num_loopback_packets_sent_to_client >= 10 );
        check( context.num_loopback_packets_sent_to_server >= 10 );
    };

    exchange_packets();

    // verify that we can disconnect the loopback client

    check( netcode_server_client_loopback( server, 0 ) == 1 );
    check( netcode_server_client_connected( server, 0 ) == 1 );
    check( netcode_server_num_connected_clients( server ) == 2 );

    netcode_server_disconnect_loopback_client( server, 0 );

    check( netcode_server_client_loopback( server, 0 ) == 0 );
    check( netcode_server_client_connected( server, 0 ) == 0 );
    check( netcode_server_num_connected_clients( server ) == 1 );

    netcode_client_disconnect_loopback( loopback_client );

    check( netcode_client_state( loopback_client ) == NETCODE_CLIENT_STATE_DISCONNECTED );

    // verify that we can reconnect the loopback client

    netcode_server_connect_loopback_client( server, 0, random_uint64(), null );

    check( netcode_server_client_loopback( server, 0 ) == 1 );
    check( netcode_server_client_loopback( server, 1 ) == 0 );
    check( netcode_server_client_connected( server, 0 ) == 1 );
    check( netcode_server_client_connected( server, 1 ) == 1 );
    check( netcode_server_num_connected_clients( server ) == 2 );

    netcode_client_connect_loopback( loopback_client, 0, max_clients );

    check( netcode_client_index( loopback_client ) == 0 );
    check( netcode_client_loopback( loopback_client ) == 1 );
    check( netcode_client_max_clients( loopback_client ) == max_clients );
    check( netcode_client_state( loopback_client ) == NETCODE_CLIENT_STATE_CONNECTED );

    // verify that we can exchange packets for both regular and loopback client post reconnect

    context.num_loopback_packets_sent_to_client = 0;
    context.num_loopback_packets_sent_to_server = 0;

    exchange_packets();

    // verify the regular client times out but loopback client doesn't

    time += 100000.0;

    netcode_server_update( server, time );

    check( netcode_server_client_connected( server, 0 ) == 1 );
    check( netcode_server_client_connected( server, 1 ) == 0 );

    netcode_client_update( loopback_client, time );

    check( netcode_client_state( loopback_client ) == NETCODE_CLIENT_STATE_CONNECTED );

    // verify that disconnect all clients leaves loopback clients alone

    netcode_server_disconnect_all_clients( server );

    check( netcode_server_client_connected( server, 0 ) == 1 );
    check( netcode_server_client_connected( server, 1 ) == 0 );
    check( netcode_server_client_loopback( server, 0 ) == 1 );

    // clean up

    netcode_client_destroy( regular_client );

    netcode_client_destroy( loopback_client );

    netcode_server_destroy( server );

    netcode_network_simulator_destroy( network_simulator );
}

function test_packet_tagging(): void
{
    // IMPORTANT: Packet tagging is off by default because it doesn't play well with some older home routers.
    // However, providing players with a way to turn it on is recommended, since it can significantly reduce
    // jitter playing over Wi-Fi. (Node's dgram has no setTOS, so there sockets are created untagged.)

    netcode_enable_packet_tagging();

    const pairs: [ string, string ][] = [ [ "127.0.0.1:40000", "127.0.0.1:50000" ] ];
    if ( test_ipv6_available )
        pairs.push( [ "[::1]:40000", "[::1]:50000" ] );

    for ( const [ server_address, client_address ] of pairs )
    {
        const server_config = new netcode_server_config_t();
        netcode_default_server_config( server_config );

        const server = netcode_server_create( server_address, server_config, 0.0 );

        check( server );

        const client_config = new netcode_client_config_t();
        netcode_default_client_config( client_config );

        const client = netcode_client_create( client_address, client_config, 0.0 );

        check( client );

        const connect_token = test_generate_connect_token( server_address, random_uint64() );

        netcode_client_connect( client!, connect_token );

        netcode_client_destroy( client! );

        netcode_server_destroy( server! );
    }

    // tagging is process wide. turn it back off so the tests that follow run with the default
    netcode_packet_tagging_enabled = 0;
}

function test_loopback_callback_required(): void
{
    // entering loopback with send_loopback_packet_callback unset would call a null function
    // on the next send. both sides must refuse to enter loopback instead. the guard asserts
    // as well as returning, so install the handler that continues.

    netcode_set_assert_function( test_runtime_guards_assert_handler );

    const client_config = new netcode_client_config_t();
    netcode_default_client_config( client_config );

    const client = netcode_client_create( "0.0.0.0:50000", client_config, 0.0 )!;

    check( client );

    netcode_client_connect_loopback( client, 0, 1 );

    check( netcode_client_loopback( client ) == 0 );
    check( netcode_client_state( client ) == NETCODE_CLIENT_STATE_DISCONNECTED );

    const payload = new Uint8Array( NETCODE_MAX_PACKET_SIZE );

    netcode_client_send_packet( client, payload, NETCODE_MAX_PACKET_SIZE );

    netcode_client_destroy( client );

    const server_config = new netcode_server_config_t();
    netcode_default_server_config( server_config );

    const server = netcode_server_create( "127.0.0.1:40000", server_config, 0.0 )!;

    check( server );

    netcode_server_start( server, 1 );

    netcode_server_connect_loopback_client( server, 0, 1n, null );

    check( netcode_server_client_loopback( server, 0 ) == 0 );
    check( netcode_server_client_connected( server, 0 ) == 0 );
    check( netcode_server_num_connected_clients( server ) == 0 );

    netcode_server_send_packet( server, 0, payload, NETCODE_MAX_PACKET_SIZE );

    netcode_server_destroy( server );

    netcode_set_assert_function( netcode_default_assert_handler );
}

/*
    Runs every test of netcode.c. Tests over real sockets (40000, 50000 and nearby ports on 127.0.0.1
    and ::1) await between updates so packets can arrive; tests over the network simulator, loopback
    or the override wire are synchronous. ::1 tests are skipped on hosts without IPv6. Throws on the
    first failed check.
*/
export async function netcode_test(): Promise<void>
{
    const self_initialized = !netcode.initialized;
    if ( self_initialized )
        check( netcode_init() == NETCODE_OK );

    test_ipv6_available = test_check_ipv6_available();
    if ( !test_ipv6_available )
        netcode_printf( NETCODE_LOG_LEVEL_NONE, "netcode_test: ::1 is not available, skipping the ipv6 socket tests\n" );

    // NETCODE_ENABLE_NONCE_AUDIT: record every encrypted key and nonce pair while the suite runs
    netcode_nonce_audit_enabled = true;
    netcode_nonce_audit_records = new Set<string>();
    netcode_nonce_audit_num_repeats = 0;
    netcode_nonce_audit_overflowed = 0;

    const run_test = async ( name: string, test_function: () => void | Promise<void> ): Promise<void> =>
    {
        netcode_printf( NETCODE_LOG_LEVEL_NONE, name + '\n' );
        await test_function();
    };

    try
    {
        //while ( 1 )
        {
            await run_test( 'test_crypto_aead_vectors', test_crypto_aead_vectors );
            await run_test( 'test_queue', test_queue );
            await run_test( 'test_endian', test_endian );
            await run_test( 'test_address', test_address );
            await run_test( 'test_sequence', test_sequence );
            await run_test( 'test_connect_token', test_connect_token );
            await run_test( 'test_generate_connect_token_out_of_range', test_generate_connect_token_out_of_range );
            await run_test( 'test_challenge_token', test_challenge_token );
            await run_test( 'test_connection_request_packet', test_connection_request_packet );
            await run_test( 'test_connection_denied_packet', test_connection_denied_packet );
            await run_test( 'test_connection_challenge_packet', test_connection_challenge_packet );
            await run_test( 'test_connection_response_packet', test_connection_response_packet );
            await run_test( 'test_connection_keep_alive_packet', test_connection_keep_alive_packet );
            await run_test( 'test_connection_payload_packet', test_connection_payload_packet );
            await run_test( 'test_connection_disconnect_packet', test_connection_disconnect_packet );
            await run_test( 'test_connect_token_public', test_connect_token_public );
            await run_test( 'test_encryption_manager', test_encryption_manager );
            await run_test( 'test_replay_protection', test_replay_protection );
            await run_test( 'test_runtime_guards', test_runtime_guards );
            await run_test( 'test_init_and_defaults', test_init_and_defaults );
            await run_test( 'test_client_create_error', test_client_create_error );
            await run_test( 'test_server_create_error', test_server_create_error );
            await run_test( 'test_network_simulator_determinism', test_network_simulator_determinism );
            await run_test( 'test_network_simulator_allocation_failure', test_network_simulator_allocation_failure );
            await run_test( 'test_client_create', test_client_create );
            await run_test( 'test_server_create', test_server_create );
            await run_test( 'test_server_restart_global_sequence', test_server_restart_global_sequence );
            await run_test( 'test_client_server_connect', test_client_server_connect );
            await run_test( 'test_client_server_ipv4_socket_connect', test_client_server_ipv4_socket_connect );
            await run_test( 'test_client_server_ipv6_socket_connect', test_client_server_ipv6_socket_connect );
            await run_test( 'test_client_server_dual_socket_connect', test_client_server_dual_socket_connect );
            await run_test( 'test_client_server_keep_alive', test_client_server_keep_alive );
            await run_test( 'test_client_server_multiple_clients', test_client_server_multiple_clients );
            await run_test( 'test_client_server_multiple_servers', test_client_server_multiple_servers );
            await run_test( 'test_client_error_connect_token_expired', test_client_error_connect_token_expired );
            await run_test( 'test_client_error_invalid_connect_token', test_client_error_invalid_connect_token );
            await run_test( 'test_client_error_connection_timed_out', test_client_error_connection_timed_out );
            await run_test( 'test_client_error_connection_response_timeout', test_client_error_connection_response_timeout );
            await run_test( 'test_client_error_connection_request_timeout', test_client_error_connection_request_timeout );
            await run_test( 'test_client_error_connection_denied', test_client_error_connection_denied );
            await run_test( 'test_client_side_disconnect', test_client_side_disconnect );
            await run_test( 'test_server_side_disconnect', test_server_side_disconnect );
            await run_test( 'test_server_client_disconnect_reason', test_server_client_disconnect_reason );
            await run_test( 'test_client_reconnect', test_client_reconnect );
            await run_test( 'test_connect_token_entries', test_connect_token_entries );
            await run_test( 'test_client_server_connection_request_retransmission', test_client_server_connection_request_retransmission );
            await run_test( 'test_client_server_replay_across_sessions', test_client_server_replay_across_sessions );
            await run_test( 'test_client_reconnect_with_used_connect_token', test_client_reconnect_with_used_connect_token );
            await run_test( 'test_client_error_connect_token_predates_server_start', test_client_error_connect_token_predates_server_start );
            await run_test( 'test_disable_timeout', test_disable_timeout );
            await run_test( 'test_loopback', test_loopback );
            await run_test( 'test_loopback_callback_required', test_loopback_callback_required );
            if ( NETCODE_PACKET_TAGGING )
                await run_test( 'test_packet_tagging', test_packet_tagging );
            await run_test( 'test_nonce_audit', test_nonce_audit );
        }
    }
    finally
    {
        netcode_nonce_audit_enabled = false;
        netcode_nonce_audit_records = new Set<string>();
        netcode_set_assert_function( netcode_default_assert_handler );
        if ( self_initialized )
            netcode_term();
    }
}
