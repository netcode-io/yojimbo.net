/*
    reliable

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
    "reliable - Glenn Fiedler and Rowan Claude" in your product credits. The
    license doesn't require this credit. It's an official request, and honoring
    it is appreciated.
*/

/*
    TypeScript port of reliable 1.4.5 (upstream cpp/reliable/reliable.h + reliable.c). Function order follows reliable.c so
    upstream diffs map cleanly. Platform neutral: no Node-only APIs, time is passed in by the caller (seconds, as a double).

    Port notes (see also cs/reliable/reliable.cs, the C# port of the same version):

      - sequence numbers are uint16 held in a number (& 0xFFFF), ack_bits is a uint32 held in a number (>>> 0). config.id is a
        bigint (uint64 in C) and is handed back unchanged to the callbacks.
      - the endpoint keeps its own copy of the config (reliable.c: endpoint->config = *config).
      - float statistics are rounded to float32 (Math.fround) where reliable.c stores or computes them as float.
      - counters are numbers (uint64 in C). they are exact to 2^53, which no counter can reach in practice.
      - endpoint storage (acks, rtt history, transmit buffer, sequence buffers) is managed typed arrays. allocate_function and
        free_function are used for what reliable.c allocates at run time: the fragment reassembly buffers (the receive path),
        plus reliable_endpoint_free_packet. allocate_function may return null, or throw, and the fragment is dropped and counted
        invalid exactly as in reliable.c.
      - receive hardening (as in the C# port): a packet_bytes that is not an integer in [1, packet_data.length] is dropped and
        counted invalid instead of asserted, because a typed array read past its end returns undefined rather than faulting.
      - asserts are always on (there is no separate release build): a failed reliable_assert calls the assert function and
        throws. per upstream they guard programmer contracts only, never wire data.
*/

// ---------------------------------------------------------------
// reliable.h
// ---------------------------------------------------------------

export const RELIABLE_VERSION_FULL = "1.4.5";
export const RELIABLE_VERSION_MAJOR = 1;
export const RELIABLE_VERSION_MINOR = 4;
export const RELIABLE_VERSION_PATCH = 5;

export const RELIABLE_ENDPOINT_COUNTER_NUM_PACKETS_SENT = 0;
export const RELIABLE_ENDPOINT_COUNTER_NUM_PACKETS_RECEIVED = 1;
export const RELIABLE_ENDPOINT_COUNTER_NUM_PACKETS_ACKED = 2;
export const RELIABLE_ENDPOINT_COUNTER_NUM_PACKETS_STALE = 3;
export const RELIABLE_ENDPOINT_COUNTER_NUM_PACKETS_INVALID = 4;
export const RELIABLE_ENDPOINT_COUNTER_NUM_PACKETS_TOO_LARGE_TO_SEND = 5;
export const RELIABLE_ENDPOINT_COUNTER_NUM_PACKETS_TOO_LARGE_TO_RECEIVE = 6;
export const RELIABLE_ENDPOINT_COUNTER_NUM_FRAGMENTS_SENT = 7;
export const RELIABLE_ENDPOINT_COUNTER_NUM_FRAGMENTS_RECEIVED = 8;
export const RELIABLE_ENDPOINT_COUNTER_NUM_FRAGMENTS_INVALID = 9;
export const RELIABLE_ENDPOINT_COUNTER_NUM_PACKETS_DUPLICATE = 10;
export const RELIABLE_ENDPOINT_NUM_COUNTERS = 11;

export const RELIABLE_MAX_PACKET_HEADER_BYTES = 9;
export const RELIABLE_FRAGMENT_HEADER_BYTES = 5;

export const RELIABLE_LOG_LEVEL_NONE = 0;
export const RELIABLE_LOG_LEVEL_ERROR = 1;
export const RELIABLE_LOG_LEVEL_INFO = 2;
export const RELIABLE_LOG_LEVEL_DEBUG = 3;

export const RELIABLE_OK = 1;
export const RELIABLE_ERROR = 0;

// called to send a packet: (context, id, sequence, packet_data, packet_bytes). must not send packets on the same endpoint.
// packet_data is the endpoint's own transmit scratch buffer: only the first packet_bytes bytes are the packet
// (packet_data.length may be larger), and it is valid only for the duration of the call. copy the bytes if you need them later

export type reliable_transmit_packet_function_t = ( context: unknown, id: bigint, sequence: number, packet_data: Uint8Array, packet_bytes: number ) => void;

// called when a packet is received: (context, id, sequence, packet_data, packet_bytes). return true to accept and ack the
// packet, false to reject it (rejected packets are not acked and may be processed again if they arrive again). packet_data is
// a view of exactly the payload (packet_data.length == packet_bytes) and is valid only for the duration of the call: for a
// reassembled packet it is a view of an internal buffer the endpoint frees as soon as you return

export type reliable_process_packet_function_t = ( context: unknown, id: bigint, sequence: number, packet_data: Uint8Array, packet_bytes: number ) => boolean;

// custom allocator for the run time buffers (fragment reassembly). returning null is a supported outcome: the fragment is
// dropped and counted invalid. the returned array must hold at least the requested number of bytes

export type reliable_allocate_function_t = ( context: unknown, bytes: number ) => Uint8Array | null;

export type reliable_free_function_t = ( context: unknown, pointer: unknown ) => void;

export type reliable_assert_function_t = ( condition: string, function_name: string, file: string, line: number ) => void;

export type reliable_printf_function_t = ( text: string ) => void;

export class reliable_config_t
{
    name: string = "";                                                              // name of the endpoint. used in log output
    context: unknown = null;                                                        // passed to the transmit and process packet callbacks
    id: bigint = 0n;                                                                // id of the endpoint. passed to callbacks so shared callbacks can tell endpoints apart
    max_packet_size: number = 0;                                                    // maximum packet size that can be sent or received (bytes)
    fragment_above: number = 0;                                                     // packets larger than this many bytes are sent as fragments
    max_fragments: number = 0;                                                      // maximum number of fragments per-packet. 256 max. must cover max_packet_size / fragment_size
    fragment_size: number = 0;                                                      // size of each fragment (bytes)
    ack_buffer_size: number = 0;                                                    // maximum number of acks buffered between calls to reliable_endpoint_clear_acks
    sent_packets_buffer_size: number = 0;                                           // number of sent packets tracked for acks, packet loss and bandwidth stats
    received_packets_buffer_size: number = 0;                                       // number of received packets tracked. also the window for stale and duplicate packet rejection
    fragment_reassembly_buffer_size: number = 0;                                    // number of packets that can be under reassembly from fragments at the same time
    rtt_smoothing_factor: number = 0;                                               // exponential smoothing factor for the rtt moving average
    rtt_history_size: number = 0;                                                   // number of rtt samples kept for min/max/avg rtt and jitter
    packet_loss_smoothing_factor: number = 0;                                       // exponential smoothing factor for packet loss
    bandwidth_smoothing_factor: number = 0;                                         // exponential smoothing factor for bandwidth
    packet_header_size: number = 0;                                                 // assumed network header overhead per-packet, used only for bandwidth stats. 28 = IPv4 + UDP
    transmit_packet_function: reliable_transmit_packet_function_t | null = null;    // called to send a packet. see reliable_transmit_packet_function_t
    process_packet_function: reliable_process_packet_function_t | null = null;      // called when a packet is received. see reliable_process_packet_function_t
    allocator_context: unknown = null;                                              // passed to the allocate and free functions
    allocate_function: reliable_allocate_function_t | null = null;                  // custom allocator. null = new Uint8Array
    free_function: reliable_free_function_t | null = null;                          // custom free. null = nothing (garbage collected)
}

// ---------------------------------------------------------------
// reliable.c
// ---------------------------------------------------------------

const INT_MAX = 2147483647;
const FLT_MAX = 3.4028234663852886e+38;

function default_assert_handler( condition: string, function_name: string, file: string, line: number ): void
{
    console.log( `assert failed: ( ${condition} ), function ${function_name}, file ${file}, line ${line}` );
}

function default_printf_function( text: string ): void
{
    console.log( text.endsWith( "\n" ) ? text.slice( 0, -1 ) : text );
}

let log_level = 0;
let printf_function: reliable_printf_function_t = default_printf_function;
export let reliable_assert_function: reliable_assert_function_t = default_assert_handler;

export function reliable_log_level( level: number ): void
{
    log_level = level;
}

export function reliable_set_printf_function( fn: reliable_printf_function_t ): void
{
    reliable_assert( fn != null, "function", "reliable_set_printf_function" );
    printf_function = fn;
}

export function reliable_set_assert_function( fn: reliable_assert_function_t ): void
{
    reliable_assert_function = fn;
}

// reliable_assert. upstream compiles it out of release builds and exits on failure; here it is always on and throws after
// calling the assert function, so a broken programmer contract never continues

export function reliable_assert( condition: boolean, condition_text: string, function_name: string = "" ): asserts condition
{
    if ( !condition )
    {
        reliable_assert_function( condition_text, function_name, "reliable.ts", 0 );
        throw new Error( `reliable assert failed: ( ${condition_text} ), function ${function_name}` );
    }
}

// reliable_printf. the format string follows the upstream one (%s, %d, %zu) and is only formatted when the level is enabled, so
// a debug log on the packet path costs a comparison at the default log level. arguments are fixed parameters rather than a rest
// array so a filtered call allocates nothing

function reliable_printf( level: number, format: string, a?: unknown, b?: unknown, c?: unknown, d?: unknown, e?: unknown ): void
{
    if ( level > log_level )
        return;
    let index = 0;
    const text = format.replace( /%(%|s|d|zu)/g, ( _match: string, spec: string ): string =>
    {
        if ( spec === "%" )
            return "%";
        const value = index === 0 ? a : index === 1 ? b : index === 2 ? c : index === 3 ? d : e;
        index++;
        return String( value );
    } );
    printf_function( text );
}

function reliable_default_allocate_function( _context: unknown, bytes: number ): Uint8Array | null
{
    return new Uint8Array( bytes );
}

function reliable_default_free_function( _context: unknown, _pointer: unknown ): void
{
}

// ------------------------------------------------------------------

export function reliable_init(): number
{
    return RELIABLE_OK;
}

export function reliable_term(): void
{
}

// ---------------------------------------------------------------

function reliable_sequence_greater_than( s1: number, s2: number ): boolean
{
    return ( ( s1 > s2 ) && ( s1 - s2 <= 32768 ) ) ||
           ( ( s1 < s2 ) && ( s2 - s1  > 32768 ) );
}

function reliable_sequence_less_than( s1: number, s2: number ): boolean
{
    return reliable_sequence_greater_than( s2, s1 );
}

// ---------------------------------------------------------------

export type reliable_cleanup_function_t<T> = ( data: T, allocator_context: unknown, free_function: reliable_free_function_t ) => void;

// internal. exported only as a type, so the declaration of reliable_endpoint_t can name it

export class reliable_sequence_buffer_t<T>
{
    allocator_context: unknown = null;
    allocate_function: reliable_allocate_function_t = reliable_default_allocate_function;
    free_function: reliable_free_function_t = reliable_default_free_function;
    sequence: number = 0;
    num_entries: number = 0;
    entry_sequence: Uint32Array = new Uint32Array( 0 );
    entry_data: T[] = [];
}

function reliable_sequence_buffer_create<T>( num_entries: number,
                                             create_entry: () => T,
                                             allocator_context: unknown,
                                             allocate_function: reliable_allocate_function_t | null,
                                             free_function: reliable_free_function_t | null ): reliable_sequence_buffer_t<T> | null
{
    reliable_assert( num_entries > 0, "num_entries > 0", "reliable_sequence_buffer_create" );

    if ( allocate_function == null )
    {
        allocate_function = reliable_default_allocate_function;
    }

    if ( free_function == null )
    {
        free_function = reliable_default_free_function;
    }

    if ( !Number.isInteger( num_entries ) || num_entries <= 0 )
    {
        return null;
    }

    const sequence_buffer = new reliable_sequence_buffer_t<T>();

    sequence_buffer.allocator_context = allocator_context;
    sequence_buffer.allocate_function = allocate_function;
    sequence_buffer.free_function = free_function;
    sequence_buffer.sequence = 0;
    sequence_buffer.num_entries = num_entries;

    try
    {
        sequence_buffer.entry_sequence = new Uint32Array( num_entries );
        sequence_buffer.entry_data = new Array<T>( num_entries );
        for ( let i = 0; i < num_entries; ++i )
        {
            sequence_buffer.entry_data[i] = create_entry();
        }
    }
    catch
    {
        return null;
    }

    sequence_buffer.entry_sequence.fill( 0xFFFFFFFF );

    return sequence_buffer;
}

function reliable_sequence_buffer_destroy<T>( sequence_buffer: reliable_sequence_buffer_t<T> ): void
{
    reliable_assert( sequence_buffer != null, "sequence_buffer", "reliable_sequence_buffer_destroy" );
    sequence_buffer.entry_sequence = new Uint32Array( 0 );
    sequence_buffer.entry_data = [];
    sequence_buffer.num_entries = 0;
}

function reliable_sequence_buffer_reset<T>( sequence_buffer: reliable_sequence_buffer_t<T> ): void
{
    reliable_assert( sequence_buffer != null, "sequence_buffer", "reliable_sequence_buffer_reset" );
    sequence_buffer.sequence = 0;
    sequence_buffer.entry_sequence.fill( 0xFFFFFFFF );
}

function reliable_sequence_buffer_remove_entries<T>( sequence_buffer: reliable_sequence_buffer_t<T>,
                                                     start_sequence: number,
                                                     finish_sequence: number,
                                                     cleanup_function: reliable_cleanup_function_t<T> | null ): void
{
    reliable_assert( sequence_buffer != null, "sequence_buffer", "reliable_sequence_buffer_remove_entries" );
    if ( finish_sequence < start_sequence )
    {
        finish_sequence += 65536;
    }
    if ( finish_sequence - start_sequence < sequence_buffer.num_entries )
    {
        for ( let sequence = start_sequence; sequence <= finish_sequence; ++sequence )
        {
            if ( cleanup_function )
            {
                cleanup_function( sequence_buffer.entry_data[ sequence % sequence_buffer.num_entries ],
                                  sequence_buffer.allocator_context,
                                  sequence_buffer.free_function );
            }
            sequence_buffer.entry_sequence[ sequence % sequence_buffer.num_entries ] = 0xFFFFFFFF;
        }
    }
    else
    {
        for ( let i = 0; i < sequence_buffer.num_entries; ++i )
        {
            if ( cleanup_function )
            {
                cleanup_function( sequence_buffer.entry_data[i],
                                  sequence_buffer.allocator_context,
                                  sequence_buffer.free_function );
            }
            sequence_buffer.entry_sequence[i] = 0xFFFFFFFF;
        }
    }
}

function reliable_sequence_buffer_test_insert<T>( sequence_buffer: reliable_sequence_buffer_t<T>, sequence: number ): boolean
{
    return reliable_sequence_less_than( sequence, ( sequence_buffer.sequence - sequence_buffer.num_entries ) & 0xFFFF ) ? false : true;
}

function reliable_sequence_buffer_insert<T>( sequence_buffer: reliable_sequence_buffer_t<T>, sequence: number ): T | null
{
    reliable_assert( sequence_buffer != null, "sequence_buffer", "reliable_sequence_buffer_insert" );
    if ( reliable_sequence_less_than( sequence, ( sequence_buffer.sequence - sequence_buffer.num_entries ) & 0xFFFF ) )
    {
        return null;
    }
    if ( reliable_sequence_greater_than( ( sequence + 1 ) & 0xFFFF, sequence_buffer.sequence ) )
    {
        reliable_sequence_buffer_remove_entries( sequence_buffer, sequence_buffer.sequence, sequence, null );
        sequence_buffer.sequence = ( sequence + 1 ) & 0xFFFF;
    }
    const index = sequence % sequence_buffer.num_entries;
    sequence_buffer.entry_sequence[index] = sequence;
    return sequence_buffer.entry_data[index];
}

function reliable_sequence_buffer_advance<T>( sequence_buffer: reliable_sequence_buffer_t<T>, sequence: number ): void
{
    reliable_assert( sequence_buffer != null, "sequence_buffer", "reliable_sequence_buffer_advance" );
    if ( reliable_sequence_greater_than( ( sequence + 1 ) & 0xFFFF, sequence_buffer.sequence ) )
    {
        reliable_sequence_buffer_remove_entries( sequence_buffer, sequence_buffer.sequence, sequence, null );
        sequence_buffer.sequence = ( sequence + 1 ) & 0xFFFF;
    }
}

function reliable_sequence_buffer_insert_with_cleanup<T>( sequence_buffer: reliable_sequence_buffer_t<T>,
                                                          sequence: number,
                                                          cleanup_function: reliable_cleanup_function_t<T> ): T | null
{
    reliable_assert( sequence_buffer != null, "sequence_buffer", "reliable_sequence_buffer_insert_with_cleanup" );
    if ( reliable_sequence_greater_than( ( sequence + 1 ) & 0xFFFF, sequence_buffer.sequence ) )
    {
        reliable_sequence_buffer_remove_entries( sequence_buffer, sequence_buffer.sequence, sequence, cleanup_function );
        sequence_buffer.sequence = ( sequence + 1 ) & 0xFFFF;
    }
    else if ( reliable_sequence_less_than( sequence, ( sequence_buffer.sequence - sequence_buffer.num_entries ) & 0xFFFF ) )
    {
        return null;
    }
    const index = sequence % sequence_buffer.num_entries;
    if ( sequence_buffer.entry_sequence[index] !== 0xFFFFFFFF )
    {
        cleanup_function( sequence_buffer.entry_data[ sequence % sequence_buffer.num_entries ],
                          sequence_buffer.allocator_context,
                          sequence_buffer.free_function );
    }
    sequence_buffer.entry_sequence[index] = sequence;
    return sequence_buffer.entry_data[index];
}

function reliable_sequence_buffer_advance_with_cleanup<T>( sequence_buffer: reliable_sequence_buffer_t<T>,
                                                           sequence: number,
                                                           cleanup_function: reliable_cleanup_function_t<T> ): void
{
    reliable_assert( sequence_buffer != null, "sequence_buffer", "reliable_sequence_buffer_advance_with_cleanup" );
    if ( reliable_sequence_greater_than( ( sequence + 1 ) & 0xFFFF, sequence_buffer.sequence ) )
    {
        reliable_sequence_buffer_remove_entries( sequence_buffer, sequence_buffer.sequence, sequence, cleanup_function );
        sequence_buffer.sequence = ( sequence + 1 ) & 0xFFFF;
    }
}

function reliable_sequence_buffer_remove_with_cleanup<T>( sequence_buffer: reliable_sequence_buffer_t<T>,
                                                          sequence: number,
                                                          cleanup_function: reliable_cleanup_function_t<T> ): void
{
    reliable_assert( sequence_buffer != null, "sequence_buffer", "reliable_sequence_buffer_remove_with_cleanup" );
    const index = sequence % sequence_buffer.num_entries;
    if ( sequence_buffer.entry_sequence[index] !== 0xFFFFFFFF )
    {
        sequence_buffer.entry_sequence[index] = 0xFFFFFFFF;
        cleanup_function( sequence_buffer.entry_data[index], sequence_buffer.allocator_context, sequence_buffer.free_function );
    }
}

function reliable_sequence_buffer_exists<T>( sequence_buffer: reliable_sequence_buffer_t<T>, sequence: number ): boolean
{
    reliable_assert( sequence_buffer != null, "sequence_buffer", "reliable_sequence_buffer_exists" );
    return sequence_buffer.entry_sequence[ sequence % sequence_buffer.num_entries ] === sequence;
}

function reliable_sequence_buffer_find<T>( sequence_buffer: reliable_sequence_buffer_t<T>, sequence: number ): T | null
{
    reliable_assert( sequence_buffer != null, "sequence_buffer", "reliable_sequence_buffer_find" );
    const index = sequence % sequence_buffer.num_entries;
    return ( sequence_buffer.entry_sequence[index] === sequence ) ? sequence_buffer.entry_data[index] : null;
}

function reliable_sequence_buffer_at_index<T>( sequence_buffer: reliable_sequence_buffer_t<T>, index: number ): T | null
{
    reliable_assert( sequence_buffer != null, "sequence_buffer", "reliable_sequence_buffer_at_index" );
    reliable_assert( index >= 0, "index >= 0", "reliable_sequence_buffer_at_index" );
    reliable_assert( index < sequence_buffer.num_entries, "index < sequence_buffer->num_entries", "reliable_sequence_buffer_at_index" );
    return sequence_buffer.entry_sequence[index] !== 0xFFFFFFFF ? sequence_buffer.entry_data[index] : null;
}

// out parameters of reliable_sequence_buffer_generate_ack_bits (uint16_t * ack, uint32_t * ack_bits)

export class reliable_ack_bits_t
{
    ack: number = 0;
    ack_bits: number = 0;
}

function reliable_sequence_buffer_generate_ack_bits<T>( sequence_buffer: reliable_sequence_buffer_t<T>, out: reliable_ack_bits_t ): void
{
    reliable_assert( sequence_buffer != null, "sequence_buffer", "reliable_sequence_buffer_generate_ack_bits" );
    reliable_assert( out != null, "ack && ack_bits", "reliable_sequence_buffer_generate_ack_bits" );
    const ack = ( sequence_buffer.sequence - 1 ) & 0xFFFF;
    let ack_bits = 0;
    let mask = 1;
    for ( let i = 0; i < 32; ++i )
    {
        const sequence = ( ack - i ) & 0xFFFF;
        if ( reliable_sequence_buffer_exists( sequence_buffer, sequence ) )
            ack_bits |= mask;
        mask <<= 1;
    }
    out.ack = ack;
    out.ack_bits = ack_bits >>> 0;
}

// ---------------------------------------------------------------

// reliable.c advances a uint8_t ** cursor. here the cursor is an offset: writes return the advanced offset, and reads take the
// offset and leave advancing it to the caller

function reliable_write_uint8( buffer: Uint8Array, p: number, value: number ): number
{
    buffer[p] = value & 0xFF;
    return p + 1;
}

function reliable_write_uint16( buffer: Uint8Array, p: number, value: number ): number
{
    buffer[p] = value & 0xFF;
    buffer[p + 1] = ( value >>> 8 ) & 0xFF;
    return p + 2;
}

function reliable_read_uint8( buffer: Uint8Array, p: number ): number
{
    return buffer[p];
}

function reliable_read_uint16( buffer: Uint8Array, p: number ): number
{
    return buffer[p] | ( buffer[p + 1] << 8 );
}

// ---------------------------------------------------------------

export class reliable_fragment_reassembly_data_t
{
    sequence: number = 0;
    ack: number = 0;
    ack_bits: number = 0;
    num_fragments_received: number = 0;
    num_fragments_total: number = 0;
    packet_data: Uint8Array | null = null;
    packet_bytes: number = 0;
    packet_header_bytes: number = 0;
    fragment_received: Uint8Array = new Uint8Array( 256 );
}

function reliable_fragment_reassembly_data_cleanup( reassembly_data: reliable_fragment_reassembly_data_t, allocator_context: unknown, free_function: reliable_free_function_t ): void
{
    reliable_assert( free_function != null, "free_function", "reliable_fragment_reassembly_data_cleanup" );
    if ( reassembly_data.packet_data )
    {
        free_function( allocator_context, reassembly_data.packet_data );
        reassembly_data.packet_data = null;
    }
}

// ---------------------------------------------------------------

export class reliable_sent_packet_data_t
{
    time: number = 0.0;
    acked: boolean = false;
    packet_bytes: number = 0;
}

export class reliable_received_packet_data_t
{
    time: number = 0.0;
    packet_bytes: number = 0;
}

export class reliable_endpoint_t
{
    allocator_context: unknown = null;
    allocate_function: reliable_allocate_function_t = reliable_default_allocate_function;
    free_function: reliable_free_function_t = reliable_default_free_function;
    config: reliable_config_t = new reliable_config_t();
    time: number = 0.0;
    rtt: number = 0.0;
    rtt_min: number = 0.0;
    rtt_max: number = 0.0;
    rtt_avg: number = 0.0;
    jitter_avg_vs_min_rtt: number = 0.0;
    jitter_max_vs_min_rtt: number = 0.0;
    jitter_stddev_vs_avg_rtt: number = 0.0;
    packet_loss: number = 0.0;
    sent_bandwidth_kbps: number = 0.0;
    received_bandwidth_kbps: number = 0.0;
    acked_bandwidth_kbps: number = 0.0;
    num_acks: number = 0;
    acks: Uint16Array = new Uint16Array( 0 );
    sequence: number = 0;
    rtt_history_buffer: Float32Array = new Float32Array( 0 );
    transmit_buffer: Uint8Array = new Uint8Array( 0 );
    sent_packets!: reliable_sequence_buffer_t<reliable_sent_packet_data_t>;
    received_packets!: reliable_sequence_buffer_t<reliable_received_packet_data_t>;
    fragment_reassembly!: reliable_sequence_buffer_t<reliable_fragment_reassembly_data_t>;
    counters: number[] = new Array<number>( RELIABLE_ENDPOINT_NUM_COUNTERS ).fill( 0 );
}

// fills a config with sensible defaults for a client/server game exchanging packets at 60HZ. returns the config for convenience

export function reliable_default_config( config: reliable_config_t ): reliable_config_t
{
    reliable_assert( config != null, "config", "reliable_default_config" );
    Object.assign( config, new reliable_config_t() );
    config.name = "endpoint";
    config.max_packet_size = 16 * 1024;
    config.fragment_above = 1024;
    config.max_fragments = 16;
    config.fragment_size = 1024;
    config.ack_buffer_size = 256;
    config.sent_packets_buffer_size = 256;
    config.received_packets_buffer_size = 256;
    config.fragment_reassembly_buffer_size = 64;
    config.rtt_smoothing_factor = Math.fround( 0.0025 );
    config.rtt_history_size = 512;
    config.packet_loss_smoothing_factor = Math.fround( 0.1 );
    config.bandwidth_smoothing_factor = Math.fround( 0.1 );
    config.packet_header_size = 28;                    // note: UDP over IPv4 = 20 + 8 bytes, UDP over IPv6 = 40 + 8 bytes
    return config;
}

// the endpoint keeps its own copy of the config, as reliable.c does with endpoint->config = *config

function reliable_config_copy( config: reliable_config_t ): reliable_config_t
{
    return Object.assign( new reliable_config_t(), config );
}

// a C int: the config's size fields are int in reliable.c, so anything that is not a 32 bit integer has no C equivalent

function reliable_is_int( value: number ): boolean
{
    return Number.isInteger( value ) && value >= -2147483648 && value <= INT_MAX;
}

// checks the config a caller hands to reliable_endpoint_create. every field is range checked and the two relationships between
// fields are checked: a fragment threshold above the maximum packet size can never fire, and a fragment count that does not
// cover the maximum packet size means a large packet has nowhere to go. logs what is wrong and returns false to refuse the config

function reliable_config_valid( config: reliable_config_t | null | undefined ): config is reliable_config_t
{
    if ( config == null )
    {
        reliable_printf( RELIABLE_LOG_LEVEL_ERROR, "[reliable] config is NULL\n" );
        return false;
    }

    // TS port: the size fields must be C ints, or every range check below could be passed by a NaN or a fraction

    if ( !reliable_is_int( config.max_packet_size ) || !reliable_is_int( config.fragment_above ) ||
         !reliable_is_int( config.max_fragments ) || !reliable_is_int( config.fragment_size ) ||
         !reliable_is_int( config.ack_buffer_size ) || !reliable_is_int( config.sent_packets_buffer_size ) ||
         !reliable_is_int( config.received_packets_buffer_size ) || !reliable_is_int( config.fragment_reassembly_buffer_size ) ||
         !reliable_is_int( config.rtt_history_size ) || !reliable_is_int( config.packet_header_size ) )
    {
        reliable_printf( RELIABLE_LOG_LEVEL_ERROR, "[%s] config sizes must be 32 bit integers\n", config.name );
        return false;
    }

    if ( config.max_packet_size <= 0 )
    {
        reliable_printf( RELIABLE_LOG_LEVEL_ERROR, "[%s] max_packet_size must be positive\n", config.name );
        return false;
    }

    if ( config.fragment_above <= 0 )
    {
        reliable_printf( RELIABLE_LOG_LEVEL_ERROR, "[%s] fragment_above must be positive\n", config.name );
        return false;
    }

    if ( config.fragment_size <= 0 )
    {
        reliable_printf( RELIABLE_LOG_LEVEL_ERROR, "[%s] fragment_size must be positive\n", config.name );
        return false;
    }

    if ( config.max_fragments <= 0 || config.max_fragments > 256 )
    {
        reliable_printf( RELIABLE_LOG_LEVEL_ERROR, "[%s] max_fragments must be between 1 and 256\n", config.name );
        return false;
    }

    if ( config.ack_buffer_size <= 0 || config.sent_packets_buffer_size <= 0 ||
         config.received_packets_buffer_size <= 0 || config.fragment_reassembly_buffer_size <= 0 ||
         config.rtt_history_size <= 0 )
    {
        reliable_printf( RELIABLE_LOG_LEVEL_ERROR, "[%s] buffer sizes must be positive\n", config.name );
        return false;
    }

    if ( config.transmit_packet_function == null || config.process_packet_function == null )
    {
        reliable_printf( RELIABLE_LOG_LEVEL_ERROR, "[%s] transmit and process packet functions are required\n", config.name );
        return false;
    }

    if ( config.fragment_above > config.max_packet_size )
    {
        reliable_printf( RELIABLE_LOG_LEVEL_ERROR, "[%s] fragment_above (%d) is above max_packet_size (%d)\n",
                         config.name, config.fragment_above, config.max_packet_size );
        return false;
    }

    // max_fragments * fragment_size must cover max_packet_size. written as a division of the
    // two values already known to be positive, so neither side can overflow

    if ( config.max_fragments <= Math.trunc( ( config.max_packet_size - 1 ) / config.fragment_size ) )
    {
        reliable_printf( RELIABLE_LOG_LEVEL_ERROR, "[%s] max_fragments (%d) times fragment_size (%d) does not cover max_packet_size (%d)\n",
                         config.name, config.max_fragments, config.fragment_size, config.max_packet_size );
        return false;
    }

    if ( config.max_fragments * config.fragment_size > INT_MAX - RELIABLE_MAX_PACKET_HEADER_BYTES )
    {
        reliable_printf( RELIABLE_LOG_LEVEL_ERROR, "[%s] max_fragments (%d) times fragment_size (%d) does not fit in a packet length\n",
                         config.name, config.max_fragments, config.fragment_size );
        return false;
    }

    if ( config.max_packet_size > INT_MAX - RELIABLE_MAX_PACKET_HEADER_BYTES - RELIABLE_FRAGMENT_HEADER_BYTES )
    {
        reliable_printf( RELIABLE_LOG_LEVEL_ERROR, "[%s] max_packet_size (%d) is too large for the receive length check\n",
                         config.name, config.max_packet_size );
        return false;
    }

    if ( config.packet_header_size < 0 )
    {
        reliable_printf( RELIABLE_LOG_LEVEL_ERROR, "[%s] packet_header_size must not be negative\n", config.name );
        return false;
    }

    if ( config.packet_header_size + config.max_packet_size > INT_MAX )
    {
        reliable_printf( RELIABLE_LOG_LEVEL_ERROR, "[%s] packet_header_size (%d) plus max_packet_size (%d) does not fit a packet length\n",
                         config.name, config.packet_header_size, config.max_packet_size );
        return false;
    }

    return true;
}

// creates an endpoint. one endpoint per connection: a client has one, a server has one per client slot. returns null if the
// config is not valid or if an allocation fails

export function reliable_endpoint_create( config: reliable_config_t | null, time: number ): reliable_endpoint_t | null
{
    if ( !reliable_config_valid( config ) )
    {
        return null;
    }

    const allocator_context = config.allocator_context;
    let allocate_function = config.allocate_function;
    let free_function = config.free_function;

    if ( allocate_function == null )
    {
        allocate_function = reliable_default_allocate_function;
    }

    if ( free_function == null )
    {
        free_function = reliable_default_free_function;
    }

    // scratch buffer for outgoing packets, so the send path doesn't allocate. sized for whichever is larger: a regular packet or a fragment

    if ( config.max_packet_size > INT_MAX - RELIABLE_MAX_PACKET_HEADER_BYTES ||
         config.fragment_size > INT_MAX - RELIABLE_FRAGMENT_HEADER_BYTES - RELIABLE_MAX_PACKET_HEADER_BYTES )
    {
        return null;
    }

    let transmit_buffer_size = config.max_packet_size + RELIABLE_MAX_PACKET_HEADER_BYTES;
    const fragment_transmit_buffer_size = RELIABLE_FRAGMENT_HEADER_BYTES + RELIABLE_MAX_PACKET_HEADER_BYTES + config.fragment_size;
    if ( fragment_transmit_buffer_size > transmit_buffer_size )
    {
        transmit_buffer_size = fragment_transmit_buffer_size;
    }

    const endpoint = new reliable_endpoint_t();

    endpoint.allocator_context = allocator_context;
    endpoint.allocate_function = allocate_function;
    endpoint.free_function = free_function;
    endpoint.config = reliable_config_copy( config );
    endpoint.time = time;

    // the runtime allocates the endpoint's storage. an allocation it cannot make throws a RangeError, which is the equivalent
    // of allocate_function returning NULL in reliable.c: nothing is retained and create returns null

    let sent_packets: reliable_sequence_buffer_t<reliable_sent_packet_data_t> | null = null;
    let received_packets: reliable_sequence_buffer_t<reliable_received_packet_data_t> | null = null;
    let fragment_reassembly: reliable_sequence_buffer_t<reliable_fragment_reassembly_data_t> | null = null;

    try
    {
        endpoint.acks = new Uint16Array( config.ack_buffer_size );

        sent_packets = reliable_sequence_buffer_create( config.sent_packets_buffer_size,
                                                        () => new reliable_sent_packet_data_t(),
                                                        allocator_context,
                                                        allocate_function,
                                                        free_function );

        received_packets = reliable_sequence_buffer_create( config.received_packets_buffer_size,
                                                            () => new reliable_received_packet_data_t(),
                                                            allocator_context,
                                                            allocate_function,
                                                            free_function );

        fragment_reassembly = reliable_sequence_buffer_create( config.fragment_reassembly_buffer_size,
                                                               () => new reliable_fragment_reassembly_data_t(),
                                                               allocator_context,
                                                               allocate_function,
                                                               free_function );

        endpoint.rtt_history_buffer = new Float32Array( config.rtt_history_size );

        endpoint.transmit_buffer = new Uint8Array( transmit_buffer_size );
    }
    catch
    {
        sent_packets = received_packets = null;
        fragment_reassembly = null;
    }

    if ( sent_packets == null ||
         received_packets == null ||
         fragment_reassembly == null )
    {
        reliable_printf( RELIABLE_LOG_LEVEL_ERROR, "[%s] failed to allocate endpoint\n", endpoint.config.name );
        return null;
    }

    endpoint.sent_packets = sent_packets;
    endpoint.received_packets = received_packets;
    endpoint.fragment_reassembly = fragment_reassembly;

    endpoint.rtt_history_buffer.fill( -1.0 );

    return endpoint;
}

// destroys an endpoint, handing every reassembly buffer it still holds back to free_function. the endpoint must not be used after

export function reliable_endpoint_destroy( endpoint: reliable_endpoint_t ): void
{
    reliable_assert( endpoint != null, "endpoint", "reliable_endpoint_destroy" );

    if ( endpoint.fragment_reassembly )
    {
        for ( let i = 0; i < endpoint.config.fragment_reassembly_buffer_size && i < endpoint.fragment_reassembly.num_entries; ++i )
        {
            const reassembly_data = reliable_sequence_buffer_at_index( endpoint.fragment_reassembly, i );

            if ( reassembly_data && reassembly_data.packet_data )
            {
                endpoint.free_function( endpoint.allocator_context, reassembly_data.packet_data );
                reassembly_data.packet_data = null;
            }
        }
    }

    endpoint.acks = new Uint16Array( 0 );
    endpoint.num_acks = 0;

    if ( endpoint.sent_packets )
    {
        reliable_sequence_buffer_destroy( endpoint.sent_packets );
    }

    if ( endpoint.received_packets )
    {
        reliable_sequence_buffer_destroy( endpoint.received_packets );
    }

    if ( endpoint.fragment_reassembly )
    {
        reliable_sequence_buffer_destroy( endpoint.fragment_reassembly );
    }

    endpoint.rtt_history_buffer = new Float32Array( 0 );

    endpoint.transmit_buffer = new Uint8Array( 0 );
}

// returns the sequence number the next sent packet will have. use it to map acked sequence numbers back to the contents of packets you sent

export function reliable_endpoint_next_packet_sequence( endpoint: reliable_endpoint_t ): number
{
    reliable_assert( endpoint != null, "endpoint", "reliable_endpoint_next_packet_sequence" );
    return endpoint.sequence;
}

// writes a packet header at the start of packet_data (which must hold RELIABLE_MAX_PACKET_HEADER_BYTES). returns the bytes written

function reliable_write_packet_header( packet_data: Uint8Array, sequence: number, ack: number, ack_bits: number ): number
{
    let p = 0;

    let prefix_byte = 0;

    if ( ( ack_bits & 0x000000FF ) !== 0x000000FF )
    {
        prefix_byte |= ( 1 << 1 );
    }

    if ( ( ack_bits & 0x0000FF00 ) !== 0x0000FF00 )
    {
        prefix_byte |= ( 1 << 2 );
    }

    if ( ( ack_bits & 0x00FF0000 ) !== 0x00FF0000 )
    {
        prefix_byte |= ( 1 << 3 );
    }

    if ( ( ( ack_bits & 0xFF000000 ) >>> 0 ) !== 0xFF000000 )
    {
        prefix_byte |= ( 1 << 4 );
    }

    let sequence_difference = sequence - ack;
    if ( sequence_difference < 0 )
        sequence_difference += 65536;
    if ( sequence_difference <= 255 )
        prefix_byte |= ( 1 << 5 );

    p = reliable_write_uint8( packet_data, p, prefix_byte );

    p = reliable_write_uint16( packet_data, p, sequence );

    if ( sequence_difference <= 255 )
    {
        p = reliable_write_uint8( packet_data, p, sequence_difference );
    }
    else
    {
        p = reliable_write_uint16( packet_data, p, ack );
    }

    if ( ( ack_bits & 0x000000FF ) !== 0x000000FF )
    {
        p = reliable_write_uint8( packet_data, p, ack_bits & 0x000000FF );
    }

    if ( ( ack_bits & 0x0000FF00 ) !== 0x0000FF00 )
    {
        p = reliable_write_uint8( packet_data, p, ( ack_bits & 0x0000FF00 ) >>> 8 );
    }

    if ( ( ack_bits & 0x00FF0000 ) !== 0x00FF0000 )
    {
        p = reliable_write_uint8( packet_data, p, ( ack_bits & 0x00FF0000 ) >>> 16 );
    }

    if ( ( ( ack_bits & 0xFF000000 ) >>> 0 ) !== 0xFF000000 )
    {
        p = reliable_write_uint8( packet_data, p, ( ack_bits & 0xFF000000 ) >>> 24 );
    }

    reliable_assert( p <= RELIABLE_MAX_PACKET_HEADER_BYTES, "p - packet_data <= RELIABLE_MAX_PACKET_HEADER_BYTES", "reliable_write_packet_header" );

    return p;
}

const send_ack_bits = new reliable_ack_bits_t();

// sends a packet. the packet is handed to the transmit packet callback, split into fragments first if larger than config.fragment_above.
// packet_bytes is the number of bytes of packet_data to send (packet_data.length may be larger)

export function reliable_endpoint_send_packet( endpoint: reliable_endpoint_t, packet_data: Uint8Array, packet_bytes: number ): void
{
    reliable_assert( endpoint != null, "endpoint", "reliable_endpoint_send_packet" );
    reliable_assert( packet_data != null, "packet_data", "reliable_endpoint_send_packet" );
    reliable_assert( packet_bytes > 0, "packet_bytes > 0", "reliable_endpoint_send_packet" );

    // TS port: a typed array copy stops at the end of the source, so sending more bytes than the array holds would put the
    // previous packet's bytes from the scratch buffer on the wire. the caller's contract, asserted like the line above

    reliable_assert( Number.isInteger( packet_bytes ) && packet_bytes <= packet_data.length, "packet_bytes <= packet_data.length", "reliable_endpoint_send_packet" );

    if ( packet_bytes > endpoint.config.max_packet_size )
    {
        reliable_printf( RELIABLE_LOG_LEVEL_ERROR, "[%s] packet too large to send. packet is %d bytes, maximum is %d\n",
            endpoint.config.name, packet_bytes, endpoint.config.max_packet_size );
        endpoint.counters[RELIABLE_ENDPOINT_COUNTER_NUM_PACKETS_TOO_LARGE_TO_SEND]++;
        return;
    }

    const sequence = endpoint.sequence;
    endpoint.sequence = ( endpoint.sequence + 1 ) & 0xFFFF;

    reliable_sequence_buffer_generate_ack_bits( endpoint.received_packets, send_ack_bits );

    const ack = send_ack_bits.ack;
    const ack_bits = send_ack_bits.ack_bits;

    reliable_printf( RELIABLE_LOG_LEVEL_DEBUG, "[%s] sending packet %d\n", endpoint.config.name, sequence );

    const sent_packet_data = reliable_sequence_buffer_insert( endpoint.sent_packets, sequence );

    reliable_assert( sent_packet_data != null, "sent_packet_data", "reliable_endpoint_send_packet" );

    sent_packet_data.time = endpoint.time;
    sent_packet_data.packet_bytes = endpoint.config.packet_header_size + packet_bytes;
    sent_packet_data.acked = false;

    const transmit_packet_function = endpoint.config.transmit_packet_function!;

    if ( packet_bytes <= endpoint.config.fragment_above )
    {
        // regular packet

        reliable_printf( RELIABLE_LOG_LEVEL_DEBUG, "[%s] sending packet %d without fragmentation\n", endpoint.config.name, sequence );

        const transmit_packet_data = endpoint.transmit_buffer;

        const packet_header_bytes = reliable_write_packet_header( transmit_packet_data, sequence, ack, ack_bits );

        transmit_packet_data.set( packet_data.subarray( 0, packet_bytes ), packet_header_bytes );

        transmit_packet_function( endpoint.config.context, endpoint.config.id, sequence, transmit_packet_data, packet_header_bytes + packet_bytes );
    }
    else
    {
        // fragmented packet

        const packet_header = new Uint8Array( RELIABLE_MAX_PACKET_HEADER_BYTES );

        const packet_header_bytes = reliable_write_packet_header( packet_header, sequence, ack, ack_bits );

        const num_fragments = Math.trunc( packet_bytes / endpoint.config.fragment_size ) + ( ( packet_bytes % endpoint.config.fragment_size ) !== 0 ? 1 : 0 );

        reliable_printf( RELIABLE_LOG_LEVEL_DEBUG, "[%s] sending packet %d as %d fragments\n", endpoint.config.name, sequence, num_fragments );

        reliable_assert( num_fragments >= 1, "num_fragments >= 1", "reliable_endpoint_send_packet" );
        reliable_assert( num_fragments <= endpoint.config.max_fragments, "num_fragments <= endpoint->config.max_fragments", "reliable_endpoint_send_packet" );

        const fragment_packet_data = endpoint.transmit_buffer;

        let q = 0;

        const end = q + packet_bytes;

        for ( let fragment_id = 0; fragment_id < num_fragments; ++fragment_id )
        {
            let p = 0;

            p = reliable_write_uint8( fragment_packet_data, p, 1 );
            p = reliable_write_uint16( fragment_packet_data, p, sequence );
            p = reliable_write_uint8( fragment_packet_data, p, fragment_id );
            p = reliable_write_uint8( fragment_packet_data, p, num_fragments - 1 );

            if ( fragment_id === 0 )
            {
                fragment_packet_data.set( packet_header.subarray( 0, packet_header_bytes ), p );
                p += packet_header_bytes;
            }

            let bytes_to_copy = endpoint.config.fragment_size;
            if ( q + bytes_to_copy > end )
            {
                bytes_to_copy = end - q;
            }

            fragment_packet_data.set( packet_data.subarray( q, q + bytes_to_copy ), p );

            p += bytes_to_copy;
            q += bytes_to_copy;

            const fragment_packet_bytes = p;

            transmit_packet_function( endpoint.config.context, endpoint.config.id, sequence, fragment_packet_data, fragment_packet_bytes );

            endpoint.counters[RELIABLE_ENDPOINT_COUNTER_NUM_FRAGMENTS_SENT]++;
        }
    }

    endpoint.counters[RELIABLE_ENDPOINT_COUNTER_NUM_PACKETS_SENT]++;
}

// out parameters of reliable_read_packet_header (uint16_t * sequence, uint16_t * ack, uint32_t * ack_bits)

export class reliable_packet_header_t
{
    sequence: number = 0;
    ack: number = 0;
    ack_bits: number = 0;
}

// reads a packet header from packet_data[offset .. offset + packet_bytes). packet_bytes is the number of bytes available from
// offset. returns the header bytes read, or -1 if the header is invalid. the values are written to out

function reliable_read_packet_header( name: string, packet_data: Uint8Array, offset: number, packet_bytes: number, out: reliable_packet_header_t ): number
{
    if ( packet_bytes < 3 )
    {
        reliable_printf( RELIABLE_LOG_LEVEL_DEBUG, "[%s] packet too small for packet header (1)\n", name );
        return -1;
    }

    let p = offset;

    const prefix_byte = reliable_read_uint8( packet_data, p );
    p += 1;

    if ( ( prefix_byte & 1 ) !== 0 )
    {
        reliable_printf( RELIABLE_LOG_LEVEL_DEBUG, "[%s] prefix byte does not indicate a regular packet\n", name );
        return -1;
    }

    const sequence = reliable_read_uint16( packet_data, p );
    p += 2;

    let ack: number;

    if ( prefix_byte & ( 1 << 5 ) )
    {
        if ( packet_bytes < 3 + 1 )
        {
            reliable_printf( RELIABLE_LOG_LEVEL_DEBUG, "[%s] packet too small for packet header (2)\n", name );
            return -1;
        }
        const sequence_difference = reliable_read_uint8( packet_data, p );
        p += 1;
        ack = ( sequence - sequence_difference ) & 0xFFFF;
    }
    else
    {
        if ( packet_bytes < 3 + 2 )
        {
            reliable_printf( RELIABLE_LOG_LEVEL_DEBUG, "[%s] packet too small for packet header (3)\n", name );
            return -1;
        }
        ack = reliable_read_uint16( packet_data, p );
        p += 2;
    }

    let expected_bytes = 0;
    for ( let i = 1; i <= 4; ++i )
    {
        if ( prefix_byte & ( 1 << i ) )
        {
            expected_bytes++;
        }
    }
    if ( packet_bytes < ( p - offset ) + expected_bytes )
    {
        reliable_printf( RELIABLE_LOG_LEVEL_DEBUG, "[%s] packet too small for packet header (4)\n", name );
        return -1;
    }

    let ack_bits = 0xFFFFFFFF;

    if ( prefix_byte & ( 1 << 1 ) )
    {
        ack_bits &= 0xFFFFFF00;
        ack_bits |= reliable_read_uint8( packet_data, p );
        p += 1;
    }

    if ( prefix_byte & ( 1 << 2 ) )
    {
        ack_bits &= 0xFFFF00FF;
        ack_bits |= reliable_read_uint8( packet_data, p ) << 8;
        p += 1;
    }

    if ( prefix_byte & ( 1 << 3 ) )
    {
        ack_bits &= 0xFF00FFFF;
        ack_bits |= reliable_read_uint8( packet_data, p ) << 16;
        p += 1;
    }

    if ( prefix_byte & ( 1 << 4 ) )
    {
        ack_bits &= 0x00FFFFFF;
        ack_bits |= reliable_read_uint8( packet_data, p ) << 24;
        p += 1;
    }

    out.sequence = sequence;
    out.ack = ack;
    out.ack_bits = ack_bits >>> 0;

    return p - offset;
}

// out parameters of reliable_read_fragment_header

export class reliable_fragment_header_t
{
    fragment_id: number = 0;
    num_fragments: number = 0;
    fragment_bytes: number = 0;
    sequence: number = 0;
    ack: number = 0;
    ack_bits: number = 0;
}

// scratch for the read path. each is written and consumed with no callback in between, so reentrant receives cannot clobber them

const fragment_packet_header_scratch = new reliable_packet_header_t();
const canonical_header_scratch = new Uint8Array( RELIABLE_MAX_PACKET_HEADER_BYTES );
const store_packet_header_scratch = new Uint8Array( RELIABLE_MAX_PACKET_HEADER_BYTES );

function reliable_read_fragment_header( name: string,
                                        packet_data: Uint8Array,
                                        offset: number,
                                        packet_bytes: number,
                                        max_fragments: number,
                                        fragment_size: number,
                                        out: reliable_fragment_header_t ): number
{
    if ( packet_bytes < RELIABLE_FRAGMENT_HEADER_BYTES )
    {
        reliable_printf( RELIABLE_LOG_LEVEL_DEBUG, "[%s] packet is too small to read fragment header\n", name );
        return -1;
    }

    let p = offset;

    const prefix_byte = reliable_read_uint8( packet_data, p );
    p += 1;
    if ( prefix_byte !== 1 )
    {
        reliable_printf( RELIABLE_LOG_LEVEL_DEBUG, "[%s] prefix byte is not a fragment\n", name );
        return -1;
    }

    const sequence = reliable_read_uint16( packet_data, p );
    p += 2;
    const fragment_id = reliable_read_uint8( packet_data, p );
    p += 1;
    const num_fragments = reliable_read_uint8( packet_data, p ) + 1;
    p += 1;

    if ( num_fragments > max_fragments )
    {
        reliable_printf( RELIABLE_LOG_LEVEL_DEBUG, "[%s] num fragments %d outside of range of max fragments %d\n", name, num_fragments, max_fragments );
        return -1;
    }

    if ( fragment_id >= num_fragments )
    {
        reliable_printf( RELIABLE_LOG_LEVEL_DEBUG, "[%s] fragment id %d outside of range of num fragments %d\n", name, fragment_id, num_fragments );
        return -1;
    }

    let fragment_bytes = packet_bytes - RELIABLE_FRAGMENT_HEADER_BYTES;

    let packet_sequence = 0;
    let packet_ack = 0;
    let packet_ack_bits = 0;

    if ( fragment_id === 0 )
    {
        const packet_header_bytes = reliable_read_packet_header( name,
                                                                 packet_data,
                                                                 offset + RELIABLE_FRAGMENT_HEADER_BYTES,
                                                                 packet_bytes - RELIABLE_FRAGMENT_HEADER_BYTES,
                                                                 fragment_packet_header_scratch );

        if ( packet_header_bytes < 0 )
        {
            reliable_printf( RELIABLE_LOG_LEVEL_DEBUG, "[%s] bad packet header in fragment\n", name );
            return -1;
        }

        packet_sequence = fragment_packet_header_scratch.sequence;
        packet_ack = fragment_packet_header_scratch.ack;
        packet_ack_bits = fragment_packet_header_scratch.ack_bits;

        if ( packet_sequence !== sequence )
        {
            reliable_printf( RELIABLE_LOG_LEVEL_DEBUG, "[%s] bad packet sequence in fragment. expected %d, got %d\n", name, sequence, packet_sequence );
            return -1;
        }

        // the packet header is re-encoded canonically during reassembly, so a non-canonical
        // header would shift where the fragment payload lands. reject it here instead.

        const canonical_header_bytes = reliable_write_packet_header( canonical_header_scratch, packet_sequence, packet_ack, packet_ack_bits );
        let canonical = canonical_header_bytes === packet_header_bytes;
        for ( let i = 0; canonical && i < canonical_header_bytes; ++i )
        {
            if ( canonical_header_scratch[i] !== packet_data[ offset + RELIABLE_FRAGMENT_HEADER_BYTES + i ] )
            {
                canonical = false;
            }
        }
        if ( !canonical )
        {
            reliable_printf( RELIABLE_LOG_LEVEL_DEBUG, "[%s] non-canonical packet header in fragment\n", name );
            return -1;
        }

        fragment_bytes = packet_bytes - packet_header_bytes - RELIABLE_FRAGMENT_HEADER_BYTES;
    }

    if ( fragment_bytes > fragment_size )
    {
        reliable_printf( RELIABLE_LOG_LEVEL_DEBUG, "[%s] fragment bytes %d > fragment size %d\n", name, fragment_bytes, fragment_size );
        return - 1;
    }

    if ( fragment_id !== num_fragments - 1 && fragment_bytes !== fragment_size )
    {
        reliable_printf( RELIABLE_LOG_LEVEL_DEBUG, "[%s] fragment %d is %d bytes, which is not the expected fragment size %d\n",
            name, fragment_id, fragment_bytes, fragment_size );
        return -1;
    }

    out.fragment_id = fragment_id;
    out.num_fragments = num_fragments;
    out.fragment_bytes = fragment_bytes;
    out.sequence = sequence;
    out.ack = packet_ack;
    out.ack_bits = packet_ack_bits;

    return p - offset;
}

// stores fragment_data[offset .. offset + fragment_bytes) into the reassembly buffer, bounds checked against the buffer

function reliable_store_fragment_data( reassembly_data: reliable_fragment_reassembly_data_t,
                                       sequence: number,
                                       ack: number,
                                       ack_bits: number,
                                       fragment_id: number,
                                       fragment_size: number,
                                       fragment_data: Uint8Array,
                                       offset: number,
                                       fragment_bytes: number ): void
{
    const packet_data = reassembly_data.packet_data;
    if ( packet_data == null )
        return;

    let p = offset;

    if ( fragment_id === 0 )
    {
        reassembly_data.packet_header_bytes = reliable_write_packet_header( store_packet_header_scratch, sequence, ack, ack_bits );

        packet_data.set( store_packet_header_scratch.subarray( 0, reassembly_data.packet_header_bytes ),
                         RELIABLE_MAX_PACKET_HEADER_BYTES - reassembly_data.packet_header_bytes );

        p += reassembly_data.packet_header_bytes;
        fragment_bytes -= reassembly_data.packet_header_bytes;
    }

    if ( fragment_id === reassembly_data.num_fragments_total - 1 )
    {
        const packet_bytes = ( reassembly_data.num_fragments_total - 1 ) * fragment_size + fragment_bytes;
        if ( packet_bytes < 0 || packet_bytes > INT_MAX )
            return;
        reassembly_data.packet_bytes = packet_bytes;
    }

    const store_offset = RELIABLE_MAX_PACKET_HEADER_BYTES + fragment_id * fragment_size;
    const end_offset = store_offset + fragment_bytes;
    const max_size = RELIABLE_MAX_PACKET_HEADER_BYTES + reassembly_data.num_fragments_total * fragment_size;

    if ( fragment_bytes < 0 || end_offset > max_size || p + fragment_bytes > fragment_data.length )
    {
        reliable_printf( RELIABLE_LOG_LEVEL_DEBUG,
            "[reliable] invalid fragment size %d (would write past %zu/%zu)\n",
            fragment_bytes, end_offset, max_size );
        return;
    }

    packet_data.set( fragment_data.subarray( p, p + fragment_bytes ), store_offset );
}

const receive_packet_header = new reliable_packet_header_t();
const receive_fragment_header = new reliable_fragment_header_t();

// call this for each packet received from your socket. valid packets are passed to the process packet callback. stale and
// duplicate packets are dropped. packet_bytes is the number of bytes of packet_data that hold the packet

export function reliable_endpoint_receive_packet( endpoint: reliable_endpoint_t, packet_data: Uint8Array, packet_bytes: number ): void
{
    reliable_assert( endpoint != null, "endpoint", "reliable_endpoint_receive_packet" );

    // TS hardening (as in the C# port): reliable.c only asserts packet_bytes > 0. here a length that does not describe bytes
    // the array actually holds is dropped and counted, since reading past the end of a typed array yields undefined, not a fault

    if ( packet_data == null || !Number.isInteger( packet_bytes ) || packet_bytes <= 0 || packet_bytes > packet_data.length )
    {
        reliable_printf( RELIABLE_LOG_LEVEL_DEBUG, "[%s] ignoring invalid packet. packet bytes %d out of range\n", endpoint.config.name, packet_bytes );
        endpoint.counters[RELIABLE_ENDPOINT_COUNTER_NUM_PACKETS_INVALID]++;
        return;
    }

    if ( packet_bytes > endpoint.config.max_packet_size + RELIABLE_MAX_PACKET_HEADER_BYTES + RELIABLE_FRAGMENT_HEADER_BYTES )
    {
        reliable_printf( RELIABLE_LOG_LEVEL_DEBUG, "[%s] packet too large to receive. packet is at least %d bytes, maximum is %d\n",
            endpoint.config.name, packet_bytes - ( RELIABLE_MAX_PACKET_HEADER_BYTES + RELIABLE_FRAGMENT_HEADER_BYTES ), endpoint.config.max_packet_size );
        endpoint.counters[RELIABLE_ENDPOINT_COUNTER_NUM_PACKETS_TOO_LARGE_TO_RECEIVE]++;
        return;
    }

    const prefix_byte = packet_data[0];

    if ( ( prefix_byte & 1 ) === 0 )
    {
        // regular packet

        endpoint.counters[RELIABLE_ENDPOINT_COUNTER_NUM_PACKETS_RECEIVED]++;

        const packet_header_bytes = reliable_read_packet_header( endpoint.config.name, packet_data, 0, packet_bytes, receive_packet_header );
        if ( packet_header_bytes < 0 )
        {
            reliable_printf( RELIABLE_LOG_LEVEL_DEBUG, "[%s] ignoring invalid packet. could not read packet header\n", endpoint.config.name );
            endpoint.counters[RELIABLE_ENDPOINT_COUNTER_NUM_PACKETS_INVALID]++;
            return;
        }

        // copied out of the scratch before any callback can reenter receive

        const sequence = receive_packet_header.sequence;
        const ack = receive_packet_header.ack;
        let ack_bits = receive_packet_header.ack_bits;

        reliable_assert( packet_header_bytes <= packet_bytes, "packet_header_bytes <= packet_bytes", "reliable_endpoint_receive_packet" );

        const packet_payload_bytes = packet_bytes - packet_header_bytes;

        if ( packet_payload_bytes > endpoint.config.max_packet_size )
        {
            reliable_printf( RELIABLE_LOG_LEVEL_ERROR, "[%s] packet too large to receive. packet is at %d bytes, maximum is %d\n",
                endpoint.config.name, packet_payload_bytes, endpoint.config.max_packet_size );
            endpoint.counters[RELIABLE_ENDPOINT_COUNTER_NUM_PACKETS_TOO_LARGE_TO_RECEIVE]++;
            return;
        }

        if ( !reliable_sequence_buffer_test_insert( endpoint.received_packets, sequence ) )
        {
            reliable_printf( RELIABLE_LOG_LEVEL_DEBUG, "[%s] ignoring stale packet %d\n", endpoint.config.name, sequence );
            endpoint.counters[RELIABLE_ENDPOINT_COUNTER_NUM_PACKETS_STALE]++;
            return;
        }

        if ( reliable_sequence_buffer_exists( endpoint.received_packets, sequence ) )
        {
            reliable_printf( RELIABLE_LOG_LEVEL_DEBUG, "[%s] ignoring duplicate packet %d\n", endpoint.config.name, sequence );
            endpoint.counters[RELIABLE_ENDPOINT_COUNTER_NUM_PACKETS_DUPLICATE]++;
            return;
        }

        reliable_printf( RELIABLE_LOG_LEVEL_DEBUG, "[%s] processing packet %d\n", endpoint.config.name, sequence );

        if ( endpoint.config.process_packet_function!( endpoint.config.context,
                                                       endpoint.config.id,
                                                       sequence,
                                                       packet_data.subarray( packet_header_bytes, packet_bytes ),
                                                       packet_bytes - packet_header_bytes ) )
        {
            reliable_printf( RELIABLE_LOG_LEVEL_DEBUG, "[%s] process packet %d successful\n", endpoint.config.name, sequence );

            const received_packet_data = reliable_sequence_buffer_insert( endpoint.received_packets, sequence );

            reliable_sequence_buffer_advance_with_cleanup( endpoint.fragment_reassembly, sequence, reliable_fragment_reassembly_data_cleanup );

            reliable_assert( received_packet_data != null, "received_packet_data", "reliable_endpoint_receive_packet" );

            received_packet_data.time = endpoint.time;
            received_packet_data.packet_bytes = endpoint.config.packet_header_size + packet_bytes;

            for ( let i = 0; i < 32; ++i )
            {
                if ( ack_bits & 1 )
                {
                    const ack_sequence = ( ack - i ) & 0xFFFF;

                    const sent_packet_data = reliable_sequence_buffer_find( endpoint.sent_packets, ack_sequence );

                    if ( sent_packet_data && !sent_packet_data.acked )
                    {
                        if ( endpoint.num_acks < endpoint.config.ack_buffer_size )
                        {
                            reliable_printf( RELIABLE_LOG_LEVEL_DEBUG, "[%s] acked packet %d\n", endpoint.config.name, ack_sequence );
                            endpoint.acks[endpoint.num_acks++] = ack_sequence;
                            endpoint.counters[RELIABLE_ENDPOINT_COUNTER_NUM_PACKETS_ACKED]++;
                            sent_packet_data.acked = true;

                            const rtt = Math.fround( Math.fround( endpoint.time - sent_packet_data.time ) * 1000.0 );

                            reliable_assert( rtt >= 0.0, "rtt >= 0.0", "reliable_endpoint_receive_packet" );

                            const index = ack_sequence % endpoint.config.rtt_history_size;

                            endpoint.rtt_history_buffer[index] = rtt;

                            if ( ( endpoint.rtt === 0.0 && rtt > 0.0 ) || Math.abs( Math.fround( endpoint.rtt - rtt ) ) < 0.00001 )
                            {
                                endpoint.rtt = rtt;
                            }
                            else
                            {
                                endpoint.rtt = Math.fround( endpoint.rtt + Math.fround( Math.fround( rtt - endpoint.rtt ) * Math.fround( endpoint.config.rtt_smoothing_factor ) ) );
                            }
                        }
                        else
                        {
                            reliable_printf( RELIABLE_LOG_LEVEL_ERROR, "[%s] ack buffer is full. dropped ack for packet %d. make sure you call reliable_endpoint_clear_acks\n",
                                endpoint.config.name, ack_sequence );
                        }
                    }
                }
                ack_bits >>>= 1;
            }
        }
        else
        {
            reliable_printf( RELIABLE_LOG_LEVEL_ERROR, "[%s] process packet failed\n", endpoint.config.name );
        }
    }
    else
    {
        // fragment packet

        const fragment_header_bytes = reliable_read_fragment_header( endpoint.config.name,
                                                                     packet_data,
                                                                     0,
                                                                     packet_bytes,
                                                                     endpoint.config.max_fragments,
                                                                     endpoint.config.fragment_size,
                                                                     receive_fragment_header );

        if ( fragment_header_bytes < 0 )
        {
            reliable_printf( RELIABLE_LOG_LEVEL_DEBUG, "[%s] ignoring invalid fragment. could not read fragment header\n", endpoint.config.name );
            endpoint.counters[RELIABLE_ENDPOINT_COUNTER_NUM_FRAGMENTS_INVALID]++;
            return;
        }

        // copied out of the scratch before the reassembled packet reenters receive

        const fragment_id = receive_fragment_header.fragment_id;
        const num_fragments = receive_fragment_header.num_fragments;
        const sequence = receive_fragment_header.sequence;
        const ack = receive_fragment_header.ack;
        const ack_bits = receive_fragment_header.ack_bits;

        if ( reliable_sequence_buffer_exists( endpoint.received_packets, sequence ) )
        {
            reliable_printf( RELIABLE_LOG_LEVEL_DEBUG, "[%s] ignoring fragment %d of packet %d. packet already received\n",
                endpoint.config.name, fragment_id, sequence );
            return;
        }

        let reassembly_data = reliable_sequence_buffer_find( endpoint.fragment_reassembly, sequence );

        if ( !reassembly_data )
        {
            reassembly_data = reliable_sequence_buffer_insert_with_cleanup( endpoint.fragment_reassembly, sequence, reliable_fragment_reassembly_data_cleanup );

            if ( !reassembly_data )
            {
                reliable_printf( RELIABLE_LOG_LEVEL_ERROR, "[%s] ignoring invalid fragment. could not insert in reassembly buffer (stale)\n", endpoint.config.name );
                endpoint.counters[RELIABLE_ENDPOINT_COUNTER_NUM_FRAGMENTS_INVALID]++;
                return;
            }

            reliable_sequence_buffer_advance( endpoint.received_packets, sequence );

            const packet_buffer_size = RELIABLE_MAX_PACKET_HEADER_BYTES + num_fragments * endpoint.config.fragment_size + 8;

            reassembly_data.sequence = sequence;
            reassembly_data.ack = 0;
            reassembly_data.ack_bits = 0;
            reassembly_data.num_fragments_received = 0;
            reassembly_data.num_fragments_total = num_fragments;

            // a null return (or a throw, or an array too small to hold the packet) from the caller-supplied allocator is a
            // supported outcome; honor it on the receive path so memory pressure fails the fragment instead of the endpoint

            let packet_data_buffer: Uint8Array | null = null;
            try
            {
                packet_data_buffer = endpoint.allocate_function( endpoint.allocator_context, packet_buffer_size );
            }
            catch
            {
                packet_data_buffer = null;
            }

            if ( packet_data_buffer != null && !( packet_data_buffer.length >= packet_buffer_size ) )
            {
                endpoint.free_function( endpoint.allocator_context, packet_data_buffer );
                packet_data_buffer = null;
            }

            if ( !packet_data_buffer )
            {
                reliable_printf( RELIABLE_LOG_LEVEL_ERROR, "[%s] ignoring fragment %d of packet %d. reassembly allocation failed\n",
                    endpoint.config.name, fragment_id, sequence );
                reliable_sequence_buffer_remove_with_cleanup( endpoint.fragment_reassembly, sequence, reliable_fragment_reassembly_data_cleanup );
                endpoint.counters[RELIABLE_ENDPOINT_COUNTER_NUM_FRAGMENTS_INVALID]++;
                return;
            }

            reassembly_data.packet_data = packet_data_buffer;

            // allocate_function may hand back memory that is not zeroed. completeness is guaranteed by the fragment bitmap plus
            // validated offsets today, but zeroing means any future logic error that skips storing a fragment leaks zeros into
            // the delivered packet instead of stale contents.
            packet_data_buffer.fill( 0, 0, packet_buffer_size );

            reassembly_data.packet_bytes = 0;
            reassembly_data.packet_header_bytes = 0;
            reassembly_data.fragment_received.fill( 0 );
        }

        if ( num_fragments !== reassembly_data.num_fragments_total )
        {
            reliable_printf( RELIABLE_LOG_LEVEL_ERROR, "[%s] ignoring invalid fragment. fragment count mismatch. expected %d, got %d\n",
                endpoint.config.name, reassembly_data.num_fragments_total, num_fragments );
            endpoint.counters[RELIABLE_ENDPOINT_COUNTER_NUM_FRAGMENTS_INVALID]++;
            return;
        }

        if ( reassembly_data.fragment_received[fragment_id] )
        {
            reliable_printf( RELIABLE_LOG_LEVEL_ERROR, "[%s] ignoring fragment %d of packet %d. fragment already received\n",
                endpoint.config.name, fragment_id, sequence );
            return;
        }

        reliable_printf( RELIABLE_LOG_LEVEL_DEBUG, "[%s] received fragment %d of packet %d (%d/%d)\n",
            endpoint.config.name, fragment_id, sequence, reassembly_data.num_fragments_received + 1, num_fragments );

        reassembly_data.num_fragments_received++;
        reassembly_data.fragment_received[fragment_id] = 1;

        reliable_store_fragment_data( reassembly_data,
                                      sequence,
                                      ack,
                                      ack_bits,
                                      fragment_id,
                                      endpoint.config.fragment_size,
                                      packet_data,
                                      fragment_header_bytes,
                                      packet_bytes - fragment_header_bytes );

        if ( reassembly_data.num_fragments_received === reassembly_data.num_fragments_total )
        {
            reliable_printf( RELIABLE_LOG_LEVEL_DEBUG, "[%s] completed reassembly of packet %d\n", endpoint.config.name, sequence );

            const reassembled = reassembly_data.packet_data!;
            const reassembled_offset = RELIABLE_MAX_PACKET_HEADER_BYTES - reassembly_data.packet_header_bytes;
            const reassembled_bytes = reassembly_data.packet_header_bytes + reassembly_data.packet_bytes;

            reliable_endpoint_receive_packet( endpoint,
                                              reassembled.subarray( reassembled_offset, reassembled_offset + reassembled_bytes ),
                                              reassembled_bytes );

            reliable_sequence_buffer_remove_with_cleanup( endpoint.fragment_reassembly, sequence, reliable_fragment_reassembly_data_cleanup );
        }

        endpoint.counters[RELIABLE_ENDPOINT_COUNTER_NUM_FRAGMENTS_RECEIVED]++;
    }
}

// frees a packet using the endpoint's free function

export function reliable_endpoint_free_packet( endpoint: reliable_endpoint_t, packet: unknown ): void
{
    reliable_assert( endpoint != null, "endpoint", "reliable_endpoint_free_packet" );
    reliable_assert( packet != null, "packet", "reliable_endpoint_free_packet" );
    endpoint.free_function( endpoint.allocator_context, packet );
}

// returns a read only view of the sequence numbers of sent packets acked since the last clear (its length is the number of
// acks). the view belongs to the endpoint. it stays valid until the next call to reliable_endpoint_receive_packet,
// reliable_endpoint_clear_acks, reliable_endpoint_reset or reliable_endpoint_destroy on that endpoint. copy what you need first

export function reliable_endpoint_get_acks( endpoint: reliable_endpoint_t ): Uint16Array
{
    reliable_assert( endpoint != null, "endpoint", "reliable_endpoint_get_acks" );
    return endpoint.acks.subarray( 0, endpoint.num_acks );
}

// clears the ack array. call this once per-frame after processing acks. if you don't, the ack buffer fills up and new acks are dropped

export function reliable_endpoint_clear_acks( endpoint: reliable_endpoint_t ): void
{
    reliable_assert( endpoint != null, "endpoint", "reliable_endpoint_clear_acks" );
    endpoint.num_acks = 0;
}

// resets the endpoint to its initial state: acks, counters, sequence number, all tracking buffers, the rtt history and every
// rtt, jitter, packet loss and bandwidth statistic are cleared. the config and the allocator are kept, so the endpoint is
// immediately usable again

export function reliable_endpoint_reset( endpoint: reliable_endpoint_t ): void
{
    reliable_assert( endpoint != null, "endpoint", "reliable_endpoint_reset" );

    endpoint.num_acks = 0;
    endpoint.sequence = 0;

    // every value a getter can return goes back to what it was at create, so the header's
    // promise holds for the statistics as well as for the buffers

    endpoint.rtt = 0.0;
    endpoint.rtt_min = 0.0;
    endpoint.rtt_max = 0.0;
    endpoint.rtt_avg = 0.0;
    endpoint.jitter_avg_vs_min_rtt = 0.0;
    endpoint.jitter_max_vs_min_rtt = 0.0;
    endpoint.jitter_stddev_vs_avg_rtt = 0.0;
    endpoint.packet_loss = 0.0;
    endpoint.sent_bandwidth_kbps = 0.0;
    endpoint.received_bandwidth_kbps = 0.0;
    endpoint.acked_bandwidth_kbps = 0.0;

    endpoint.acks.fill( 0 );
    endpoint.counters.fill( 0 );

    endpoint.rtt_history_buffer.fill( -1.0 );

    for ( let i = 0; i < endpoint.config.fragment_reassembly_buffer_size; ++i )
    {
        const reassembly_data = reliable_sequence_buffer_at_index( endpoint.fragment_reassembly, i );

        if ( reassembly_data && reassembly_data.packet_data )
        {
            endpoint.free_function( endpoint.allocator_context, reassembly_data.packet_data );
            reassembly_data.packet_data = null;
        }
    }

    reliable_sequence_buffer_reset( endpoint.sent_packets );
    reliable_sequence_buffer_reset( endpoint.received_packets );
    reliable_sequence_buffer_reset( endpoint.fragment_reassembly );
}

// updates rtt, jitter, packet loss and bandwidth stats. call once per-frame with the current time (seconds)

export function reliable_endpoint_update( endpoint: reliable_endpoint_t, time: number ): void
{
    reliable_assert( endpoint != null, "endpoint", "reliable_endpoint_update" );

    endpoint.time = time;

    const rtt_history_buffer = endpoint.rtt_history_buffer;

    // calculate min and max rtt
    {
        let min_rtt = FLT_MAX;
        let max_rtt = 0.0;
        let sum_rtt = 0.0;
        let count = 0;
        for ( let i = 0; i < endpoint.config.rtt_history_size; i++ )
        {
            const rtt = rtt_history_buffer[i];
            if ( rtt >= 0.0 )
            {
                if ( rtt < min_rtt )
                {
                    min_rtt = rtt;
                }
                if ( rtt > max_rtt )
                {
                    max_rtt = rtt;
                }
                sum_rtt = Math.fround( sum_rtt + rtt );
                count++;
            }
        }
        // the sample count, not the value of min_rtt, says whether the history is empty. a
        // sentinel compared against a real rtt reports 0 for a link slow enough to reach it

        if ( count > 0 )
        {
            endpoint.rtt_min = min_rtt;
            endpoint.rtt_max = max_rtt;
            endpoint.rtt_avg = Math.fround( sum_rtt / count );
        }
        else
        {
            endpoint.rtt_min = 0.0;
            endpoint.rtt_max = 0.0;
            endpoint.rtt_avg = 0.0;
        }
    }

    // calculate average jitter vs. min rtt
    {
        let sum = 0.0;
        let count = 0;
        for ( let i = 0; i < endpoint.config.rtt_history_size; i++ )
        {
            if ( rtt_history_buffer[i] >= 0.0 )
            {
                sum = Math.fround( sum + Math.fround( rtt_history_buffer[i] - endpoint.rtt_min ) );
                count++;
            }
        }
        if ( count > 0 )
        {
            endpoint.jitter_avg_vs_min_rtt = Math.fround( sum / count );
        }
        else
        {
            endpoint.jitter_avg_vs_min_rtt = 0.0;
        }
    }

    // calculate max jitter vs. min rtt
    {
        let max = 0.0;
        for ( let i = 0; i < endpoint.config.rtt_history_size; i++ )
        {
            if ( rtt_history_buffer[i] >= 0.0 )
            {
                const difference = Math.fround( rtt_history_buffer[i] - endpoint.rtt_min );
                if ( difference > max )
                {
                    max = difference;
                }
            }
        }
        endpoint.jitter_max_vs_min_rtt = max;
    }

    // calculate stddev jitter vs. avg rtt
    {
        let sum = 0.0;
        let count = 0;
        for ( let i = 0; i < endpoint.config.rtt_history_size; i++ )
        {
            if ( rtt_history_buffer[i] >= 0.0 )
            {
                const deviation = Math.fround( rtt_history_buffer[i] - endpoint.rtt_avg );
                sum = Math.fround( sum + Math.fround( deviation * deviation ) );
                count++;
            }
        }
        if ( count > 0 )
        {
            endpoint.jitter_stddev_vs_avg_rtt = Math.fround( Math.pow( Math.fround( sum / count ), 0.5 ) );
        }
        else
        {
            endpoint.jitter_stddev_vs_avg_rtt = 0.0;
        }
    }

    // calculate packet loss
    {
        const base_sequence = endpoint.sent_packets.sequence - endpoint.config.sent_packets_buffer_size + 1 + 0xFFFF;
        let num_sent = 0;
        let num_dropped = 0;
        const num_samples = Math.trunc( endpoint.config.sent_packets_buffer_size / 2 );
        for ( let i = 0; i < num_samples; ++i )
        {
            const sequence = ( base_sequence + i ) & 0xFFFF;
            const sent_packet_data = reliable_sequence_buffer_find( endpoint.sent_packets, sequence );
            if ( sent_packet_data )
            {
                num_sent++;
                if ( !sent_packet_data.acked )
                {
                    num_dropped++;
                }
            }
        }
        if ( num_sent > 0 )
        {
            const packet_loss = Math.fround( Math.fround( num_dropped / num_sent ) * 100.0 );
            if ( Math.abs( Math.fround( endpoint.packet_loss - packet_loss ) ) > 0.00001 )
            {
                endpoint.packet_loss = Math.fround( endpoint.packet_loss + Math.fround( Math.fround( packet_loss - endpoint.packet_loss ) * Math.fround( endpoint.config.packet_loss_smoothing_factor ) ) );
            }
            else
            {
                endpoint.packet_loss = packet_loss;
            }
        }
        else
        {
            endpoint.packet_loss = 0.0;
        }
    }

    // calculate sent bandwidth
    {
        const base_sequence = endpoint.sent_packets.sequence - endpoint.config.sent_packets_buffer_size + 1 + 0xFFFF;
        let bytes_sent = 0;
        let start_time = FLT_MAX;
        let finish_time = 0.0;
        const num_samples = Math.trunc( endpoint.config.sent_packets_buffer_size / 2 );
        for ( let i = 0; i < num_samples; ++i )
        {
            const sequence = ( base_sequence + i ) & 0xFFFF;
            const sent_packet_data = reliable_sequence_buffer_find( endpoint.sent_packets, sequence );
            if ( !sent_packet_data )
            {
                continue;
            }
            bytes_sent += sent_packet_data.packet_bytes;
            if ( sent_packet_data.time < start_time )
            {
                start_time = sent_packet_data.time;
            }
            if ( sent_packet_data.time > finish_time )
            {
                finish_time = sent_packet_data.time;
            }
        }
        if ( start_time !== FLT_MAX && finish_time > start_time )
        {
            const sent_bandwidth_kbps = Math.fround( bytes_sent / ( finish_time - start_time ) * 8.0 / 1000.0 );
            if ( Math.abs( Math.fround( endpoint.sent_bandwidth_kbps - sent_bandwidth_kbps ) ) > 0.00001 )
            {
                endpoint.sent_bandwidth_kbps = Math.fround( endpoint.sent_bandwidth_kbps + Math.fround( Math.fround( sent_bandwidth_kbps - endpoint.sent_bandwidth_kbps ) * Math.fround( endpoint.config.bandwidth_smoothing_factor ) ) );
            }
            else
            {
                endpoint.sent_bandwidth_kbps = sent_bandwidth_kbps;
            }
        }
    }

    // calculate received bandwidth
    {
        const base_sequence = endpoint.received_packets.sequence - endpoint.config.received_packets_buffer_size + 1 + 0xFFFF;
        let bytes_sent = 0;
        let start_time = FLT_MAX;
        let finish_time = 0.0;
        const num_samples = Math.trunc( endpoint.config.received_packets_buffer_size / 2 );
        for ( let i = 0; i < num_samples; ++i )
        {
            const sequence = ( base_sequence + i ) & 0xFFFF;
            const received_packet_data = reliable_sequence_buffer_find( endpoint.received_packets, sequence );
            if ( !received_packet_data )
            {
                continue;
            }
            bytes_sent += received_packet_data.packet_bytes;
            if ( received_packet_data.time < start_time )
            {
                start_time = received_packet_data.time;
            }
            if ( received_packet_data.time > finish_time )
            {
                finish_time = received_packet_data.time;
            }
        }
        if ( start_time !== FLT_MAX && finish_time > start_time )
        {
            const received_bandwidth_kbps = Math.fround( bytes_sent / ( finish_time - start_time ) * 8.0 / 1000.0 );
            if ( Math.abs( Math.fround( endpoint.received_bandwidth_kbps - received_bandwidth_kbps ) ) > 0.00001 )
            {
                endpoint.received_bandwidth_kbps = Math.fround( endpoint.received_bandwidth_kbps + Math.fround( Math.fround( received_bandwidth_kbps - endpoint.received_bandwidth_kbps ) * Math.fround( endpoint.config.bandwidth_smoothing_factor ) ) );
            }
            else
            {
                endpoint.received_bandwidth_kbps = received_bandwidth_kbps;
            }
        }
    }

    // calculate acked bandwidth
    {
        const base_sequence = endpoint.sent_packets.sequence - endpoint.config.sent_packets_buffer_size + 1 + 0xFFFF;
        let bytes_sent = 0;
        let start_time = FLT_MAX;
        let finish_time = 0.0;
        const num_samples = Math.trunc( endpoint.config.sent_packets_buffer_size / 2 );
        for ( let i = 0; i < num_samples; ++i )
        {
            const sequence = ( base_sequence + i ) & 0xFFFF;
            const sent_packet_data = reliable_sequence_buffer_find( endpoint.sent_packets, sequence );
            if ( !sent_packet_data || !sent_packet_data.acked )
            {
                continue;
            }
            bytes_sent += sent_packet_data.packet_bytes;
            if ( sent_packet_data.time < start_time )
            {
                start_time = sent_packet_data.time;
            }
            if ( sent_packet_data.time > finish_time )
            {
                finish_time = sent_packet_data.time;
            }
        }
        if ( start_time !== FLT_MAX && finish_time > start_time )
        {
            const acked_bandwidth_kbps = Math.fround( bytes_sent / ( finish_time - start_time ) * 8.0 / 1000.0 );
            if ( Math.abs( Math.fround( endpoint.acked_bandwidth_kbps - acked_bandwidth_kbps ) ) > 0.00001 )
            {
                endpoint.acked_bandwidth_kbps = Math.fround( endpoint.acked_bandwidth_kbps + Math.fround( Math.fround( acked_bandwidth_kbps - endpoint.acked_bandwidth_kbps ) * Math.fround( endpoint.config.bandwidth_smoothing_factor ) ) );
            }
            else
            {
                endpoint.acked_bandwidth_kbps = acked_bandwidth_kbps;
            }
        }
    }
}

// rtt and jitter are in milliseconds, packet loss is a percentage, bandwidth is in kilobits per-second

export function reliable_endpoint_rtt( endpoint: reliable_endpoint_t ): number       // exponentially smoothed moving average
{
    reliable_assert( endpoint != null, "endpoint", "reliable_endpoint_rtt" );
    return endpoint.rtt;
}

export function reliable_endpoint_rtt_min( endpoint: reliable_endpoint_t ): number
{
    reliable_assert( endpoint != null, "endpoint", "reliable_endpoint_rtt_min" );
    return endpoint.rtt_min;
}

export function reliable_endpoint_rtt_max( endpoint: reliable_endpoint_t ): number
{
    reliable_assert( endpoint != null, "endpoint", "reliable_endpoint_rtt_max" );
    return endpoint.rtt_max;
}

export function reliable_endpoint_rtt_avg( endpoint: reliable_endpoint_t ): number
{
    reliable_assert( endpoint != null, "endpoint", "reliable_endpoint_rtt_avg" );
    return endpoint.rtt_avg;
}

export function reliable_endpoint_jitter_avg_vs_min_rtt( endpoint: reliable_endpoint_t ): number
{
    reliable_assert( endpoint != null, "endpoint", "reliable_endpoint_jitter_avg_vs_min_rtt" );
    return endpoint.jitter_avg_vs_min_rtt;
}

export function reliable_endpoint_jitter_max_vs_min_rtt( endpoint: reliable_endpoint_t ): number
{
    reliable_assert( endpoint != null, "endpoint", "reliable_endpoint_jitter_max_vs_min_rtt" );
    return endpoint.jitter_max_vs_min_rtt;
}

export function reliable_endpoint_jitter_stddev_vs_avg_rtt( endpoint: reliable_endpoint_t ): number
{
    reliable_assert( endpoint != null, "endpoint", "reliable_endpoint_jitter_stddev_vs_avg_rtt" );
    return endpoint.jitter_stddev_vs_avg_rtt;
}

export function reliable_endpoint_packet_loss( endpoint: reliable_endpoint_t ): number
{
    reliable_assert( endpoint != null, "endpoint", "reliable_endpoint_packet_loss" );
    return endpoint.packet_loss;
}

// out parameters of reliable_endpoint_bandwidth (float * sent_bandwidth_kbps, float * received_bandwidth_kbps, float * acked_bandwidth_kbps)

export interface reliable_bandwidth_t
{
    sent_bandwidth_kbps: number;
    received_bandwidth_kbps: number;
    acked_bandwidth_kbps: number;
}

export function reliable_endpoint_bandwidth( endpoint: reliable_endpoint_t ): reliable_bandwidth_t
{
    reliable_assert( endpoint != null, "endpoint", "reliable_endpoint_bandwidth" );
    return {
        sent_bandwidth_kbps: endpoint.sent_bandwidth_kbps,
        received_bandwidth_kbps: endpoint.received_bandwidth_kbps,
        acked_bandwidth_kbps: endpoint.acked_bandwidth_kbps,
    };
}

// returns a read only view of the RELIABLE_ENDPOINT_NUM_COUNTERS counters, indexed with RELIABLE_ENDPOINT_COUNTER_*. the array
// belongs to the endpoint and stays valid until it is reset or destroyed

export function reliable_endpoint_counters( endpoint: reliable_endpoint_t ): readonly number[]
{
    reliable_assert( endpoint != null, "endpoint", "reliable_endpoint_counters" );
    return endpoint.counters;
}

// (reliable_copy_string is not ported: it copies into a fixed size char array, and a TS string is immutable and unbounded)

// ---------------------------------------------------------------
// tests (reliable.c: RELIABLE_ENABLE_TESTS)
// ---------------------------------------------------------------

function check( condition: boolean ): asserts condition
{
    if ( !condition )
    {
        throw new Error( "check failed" );
    }
}

function test_endian(): void
{
    const value = new Uint32Array( [ 0x11223344 ] );

    const bytes = new Uint8Array( value.buffer );

    // the library itself never depends on host byte order (every field is written a byte at a time). this checks the
    // host is little endian, as upstream does under RELIABLE_LITTLE_ENDIAN

    check( bytes[0] === 0x44 );
    check( bytes[1] === 0x33 );
    check( bytes[2] === 0x22 );
    check( bytes[3] === 0x11 );
}

class test_sequence_data_t
{
    sequence: number = 0;
}

const TEST_SEQUENCE_BUFFER_SIZE = 256;

function test_sequence_buffer(): void
{
    const sequence_buffer = reliable_sequence_buffer_create( TEST_SEQUENCE_BUFFER_SIZE,
                                                             () => new test_sequence_data_t(),
                                                             null,
                                                             null,
                                                             null );

    check( sequence_buffer != null );
    check( sequence_buffer.sequence === 0 );
    check( sequence_buffer.num_entries === TEST_SEQUENCE_BUFFER_SIZE );
    // (entry_stride == sizeof( struct test_sequence_data_t ) has no equivalent: entries are objects)

    let i: number;
    for ( i = 0; i < TEST_SEQUENCE_BUFFER_SIZE; ++i )
    {
        check( reliable_sequence_buffer_find( sequence_buffer, i ) === null );
    }

    for ( i = 0; i <= TEST_SEQUENCE_BUFFER_SIZE * 4; ++i )
    {
        const entry = reliable_sequence_buffer_insert( sequence_buffer, i );
        check( entry != null );
        entry.sequence = i;
        check( sequence_buffer.sequence === i + 1 );
    }

    for ( i = 0; i <= TEST_SEQUENCE_BUFFER_SIZE; ++i )
    {
        const entry = reliable_sequence_buffer_insert( sequence_buffer, i );
        check( entry === null );
    }

    let index = TEST_SEQUENCE_BUFFER_SIZE * 4;
    for ( i = 0; i < TEST_SEQUENCE_BUFFER_SIZE; ++i )
    {
        const entry = reliable_sequence_buffer_find( sequence_buffer, index );
        check( entry != null );
        check( entry.sequence === index );
        index--;
    }

    reliable_sequence_buffer_reset( sequence_buffer );

    check( sequence_buffer != null );
    check( sequence_buffer.sequence === 0 );
    check( sequence_buffer.num_entries === TEST_SEQUENCE_BUFFER_SIZE );

    for ( i = 0; i < TEST_SEQUENCE_BUFFER_SIZE; ++i )
    {
        check( reliable_sequence_buffer_find( sequence_buffer, i ) === null );
    }

    reliable_sequence_buffer_destroy( sequence_buffer );
}

function test_generate_ack_bits(): void
{
    const sequence_buffer = reliable_sequence_buffer_create( TEST_SEQUENCE_BUFFER_SIZE,
                                                             () => new test_sequence_data_t(),
                                                             null,
                                                             null,
                                                             null );
    check( sequence_buffer != null );

    const out = new reliable_ack_bits_t();
    out.ack = 0;
    out.ack_bits = 0xFFFFFFFF;

    reliable_sequence_buffer_generate_ack_bits( sequence_buffer, out );
    check( out.ack === 0xFFFF );
    check( out.ack_bits === 0 );

    let i: number;
    for ( i = 0; i <= TEST_SEQUENCE_BUFFER_SIZE; ++i )
    {
        reliable_sequence_buffer_insert( sequence_buffer, i );
    }

    reliable_sequence_buffer_generate_ack_bits( sequence_buffer, out );
    check( ( out.ack as number ) === TEST_SEQUENCE_BUFFER_SIZE );
    check( ( out.ack_bits as number ) === 0xFFFFFFFF );

    reliable_sequence_buffer_reset( sequence_buffer );

    const input_acks = [ 1, 5, 9, 11 ];
    const input_num_acks = input_acks.length;
    for ( i = 0; i < input_num_acks; ++i )
    {
        reliable_sequence_buffer_insert( sequence_buffer, input_acks[i] );
    }

    reliable_sequence_buffer_generate_ack_bits( sequence_buffer, out );

    check( ( out.ack as number ) === 11 );
    check( ( out.ack_bits as number ) === ( 1 | ( 1 << ( 11 - 9 ) ) | ( 1 << ( 11 - 5 ) ) | ( 1 << ( 11 - 1 ) ) ) );

    reliable_sequence_buffer_destroy( sequence_buffer );
}

function test_packet_header(): void
{
    let write_sequence: number;
    let write_ack: number;
    let write_ack_bits: number;

    const read = new reliable_packet_header_t();

    const packet_data = new Uint8Array( RELIABLE_MAX_PACKET_HEADER_BYTES );

    // worst case, sequence and ack are far apart, no packets acked.

    write_sequence = 10000;
    write_ack = 100;
    write_ack_bits = 0;

    let bytes_written = reliable_write_packet_header( packet_data, write_sequence, write_ack, write_ack_bits );

    check( bytes_written === RELIABLE_MAX_PACKET_HEADER_BYTES );

    let bytes_read = reliable_read_packet_header( "test_packet_header", packet_data, 0, bytes_written, read );

    check( bytes_read === bytes_written );

    check( read.sequence === write_sequence );
    check( read.ack === write_ack );
    check( read.ack_bits === write_ack_bits );

    // rare case. sequence and ack are far apart, significant # of acks are missing

    write_sequence = 10000;
    write_ack = 100;
    write_ack_bits = 0xFEFEFFFE;

    bytes_written = reliable_write_packet_header( packet_data, write_sequence, write_ack, write_ack_bits );

    check( bytes_written === 1 + 2 + 2 + 3 );

    bytes_read = reliable_read_packet_header( "test_packet_header", packet_data, 0, bytes_written, read );

    check( bytes_read === bytes_written );

    check( read.sequence === write_sequence );
    check( read.ack === write_ack );
    check( read.ack_bits === write_ack_bits );

    // common case under packet loss. sequence and ack are close together, some acks are missing

    write_sequence = 200;
    write_ack = 100;
    write_ack_bits = 0xFFFEFFFF;

    bytes_written = reliable_write_packet_header( packet_data, write_sequence, write_ack, write_ack_bits );

    check( bytes_written === 1 + 2 + 1 + 1 );

    bytes_read = reliable_read_packet_header( "test_packet_header", packet_data, 0, bytes_written, read );

    check( bytes_read === bytes_written );

    check( read.sequence === write_sequence );
    check( read.ack === write_ack );
    check( read.ack_bits === write_ack_bits );

    // ideal case. no packet loss.

    write_sequence = 200;
    write_ack = 100;
    write_ack_bits = 0xFFFFFFFF;

    bytes_written = reliable_write_packet_header( packet_data, write_sequence, write_ack, write_ack_bits );

    check( bytes_written === 1 + 2 + 1 );

    bytes_read = reliable_read_packet_header( "test_packet_header", packet_data, 0, bytes_written, read );

    check( bytes_read === bytes_written );

    check( read.sequence === write_sequence );
    check( read.ack === write_ack );
    check( read.ack_bits === write_ack_bits );
}

class test_context_t
{
    drop: boolean = false;
    allow_packets: number = -1;
    sender: reliable_endpoint_t | null = null;
    receiver: reliable_endpoint_t | null = null;
}

function test_default_context( context: test_context_t ): void
{
    context.drop = false;
    context.allow_packets = -1;
    context.sender = null;
    context.receiver = null;
}

function test_transmit_packet_function( _context: unknown, id: bigint, _sequence: number, packet_data: Uint8Array, packet_bytes: number ): void
{
    const context = _context as test_context_t;

    if ( context.drop )
    {
        return;
    }

    if ( context.allow_packets >= 0 )
    {
        if ( context.allow_packets === 0 )
        {
            return;
        }

        context.allow_packets--;
    }

    if ( id === 0n )
    {
        reliable_endpoint_receive_packet( context.receiver!, packet_data, packet_bytes );
    }
    else if ( id === 1n )
    {
        reliable_endpoint_receive_packet( context.sender!, packet_data, packet_bytes );
    }
}

function test_process_packet_function( _context: unknown, _id: bigint, _sequence: number, _packet_data: Uint8Array, _packet_bytes: number ): boolean
{
    return true;
}

function test_new_config(): reliable_config_t
{
    return reliable_default_config( new reliable_config_t() );
}

const TEST_ACKS_NUM_ITERATIONS = 256;

function test_acks(): void
{
    let time = 100.0;

    const context = new test_context_t();
    test_default_context( context );

    const sender_config = test_new_config();
    const receiver_config = test_new_config();

    sender_config.context = context;
    sender_config.id = 0n;
    sender_config.transmit_packet_function = test_transmit_packet_function;
    sender_config.process_packet_function = test_process_packet_function;

    receiver_config.context = context;
    receiver_config.id = 1n;
    receiver_config.transmit_packet_function = test_transmit_packet_function;
    receiver_config.process_packet_function = test_process_packet_function;

    context.sender = reliable_endpoint_create( sender_config, time );
    context.receiver = reliable_endpoint_create( receiver_config, time );
    check( context.sender != null && context.receiver != null );

    const delta_time = 0.01;

    let i: number;
    for ( i = 0; i < TEST_ACKS_NUM_ITERATIONS; ++i )
    {
        const dummy_packet = new Uint8Array( 8 );

        reliable_endpoint_send_packet( context.sender, dummy_packet, dummy_packet.length );
        reliable_endpoint_send_packet( context.receiver, dummy_packet, dummy_packet.length );

        reliable_endpoint_update( context.sender, time );
        reliable_endpoint_update( context.receiver, time );

        time += delta_time;
    }

    const sender_acked_packet = new Uint8Array( TEST_ACKS_NUM_ITERATIONS );
    const sender_acks = reliable_endpoint_get_acks( context.sender );
    for ( i = 0; i < sender_acks.length; ++i )
    {
        if ( sender_acks[i] < TEST_ACKS_NUM_ITERATIONS )
        {
            sender_acked_packet[sender_acks[i]] = 1;
        }
    }
    for ( i = 0; i < TEST_ACKS_NUM_ITERATIONS / 2; ++i )
    {
        check( sender_acked_packet[i] === 1 );
    }

    const receiver_acked_packet = new Uint8Array( TEST_ACKS_NUM_ITERATIONS );
    const receiver_acks = reliable_endpoint_get_acks( context.receiver );
    for ( i = 0; i < receiver_acks.length; ++i )
    {
        if ( receiver_acks[i] < TEST_ACKS_NUM_ITERATIONS )
            receiver_acked_packet[receiver_acks[i]] = 1;
    }
    for ( i = 0; i < TEST_ACKS_NUM_ITERATIONS / 2; ++i )
    {
        check( receiver_acked_packet[i] === 1 );
    }

    reliable_endpoint_destroy( context.sender );
    reliable_endpoint_destroy( context.receiver );
}

function test_acks_packet_loss(): void
{
    let time = 100.0;

    const context = new test_context_t();
    test_default_context( context );

    const sender_config = test_new_config();
    const receiver_config = test_new_config();

    sender_config.context = context;
    sender_config.id = 0n;
    sender_config.transmit_packet_function = test_transmit_packet_function;
    sender_config.process_packet_function = test_process_packet_function;

    receiver_config.context = context;
    receiver_config.id = 1n;
    receiver_config.transmit_packet_function = test_transmit_packet_function;
    receiver_config.process_packet_function = test_process_packet_function;

    context.sender = reliable_endpoint_create( sender_config, time );
    context.receiver = reliable_endpoint_create( receiver_config, time );
    check( context.sender != null && context.receiver != null );

    const delta_time = Math.fround( 0.1 );

    let i: number;
    for ( i = 0; i < TEST_ACKS_NUM_ITERATIONS; ++i )
    {
        const dummy_packet = new Uint8Array( 8 );

        context.drop = ( i % 2 ) !== 0;

        reliable_endpoint_send_packet( context.sender, dummy_packet, dummy_packet.length );
        reliable_endpoint_send_packet( context.receiver, dummy_packet, dummy_packet.length );

        reliable_endpoint_update( context.sender, time );
        reliable_endpoint_update( context.receiver, time );

        time += delta_time;
    }

    const sender_acked_packet = new Uint8Array( TEST_ACKS_NUM_ITERATIONS );
    const sender_acks = reliable_endpoint_get_acks( context.sender );
    for ( i = 0; i < sender_acks.length; ++i )
    {
        if ( sender_acks[i] < TEST_ACKS_NUM_ITERATIONS )
        {
            sender_acked_packet[sender_acks[i]] = 1;
        }
    }
    for ( i = 0; i < TEST_ACKS_NUM_ITERATIONS / 2; ++i )
    {
        check( sender_acked_packet[i] === ( i + 1 ) % 2 );
    }

    const receiver_acked_packet = new Uint8Array( TEST_ACKS_NUM_ITERATIONS );
    const receiver_acks = reliable_endpoint_get_acks( context.receiver );
    for ( i = 0; i < receiver_acks.length; ++i )
    {
        if ( receiver_acks[i] < TEST_ACKS_NUM_ITERATIONS )
        {
            receiver_acked_packet[receiver_acks[i]] = 1;
        }
    }
    for ( i = 0; i < TEST_ACKS_NUM_ITERATIONS / 2; ++i )
    {
        check( receiver_acked_packet[i] === ( i + 1 ) % 2 );
    }

    reliable_endpoint_destroy( context.sender );
    reliable_endpoint_destroy( context.receiver );
}

let test_duplicate_packets_num_processed = 0;

function test_duplicate_packets_transmit_packet_function( _context: unknown, id: bigint, _sequence: number, packet_data: Uint8Array, packet_bytes: number ): void
{
    const context = _context as test_context_t;

    if ( id === 0n )
    {
        // deliver each packet to the receiver twice, simulating duplication on the network
        reliable_endpoint_receive_packet( context.receiver!, packet_data, packet_bytes );
        reliable_endpoint_receive_packet( context.receiver!, packet_data, packet_bytes );
    }
}

function test_duplicate_packets_process_packet_function( _context: unknown, _id: bigint, _sequence: number, _packet_data: Uint8Array, _packet_bytes: number ): boolean
{
    test_duplicate_packets_num_processed++;

    return true;
}

const TEST_DUPLICATE_PACKETS_NUM_ITERATIONS = 16;

function test_duplicate_packets(): void
{
    const time = 100.0;

    const context = new test_context_t();
    test_default_context( context );

    const sender_config = test_new_config();
    const receiver_config = test_new_config();

    sender_config.name = "sender";
    sender_config.context = context;
    sender_config.id = 0n;
    sender_config.transmit_packet_function = test_duplicate_packets_transmit_packet_function;
    sender_config.process_packet_function = test_process_packet_function;

    receiver_config.name = "receiver";
    receiver_config.context = context;
    receiver_config.id = 1n;
    receiver_config.transmit_packet_function = test_duplicate_packets_transmit_packet_function;
    receiver_config.process_packet_function = test_duplicate_packets_process_packet_function;

    context.sender = reliable_endpoint_create( sender_config, time );
    context.receiver = reliable_endpoint_create( receiver_config, time );
    check( context.sender != null && context.receiver != null );

    test_duplicate_packets_num_processed = 0;

    let i: number;
    for ( i = 0; i < TEST_DUPLICATE_PACKETS_NUM_ITERATIONS; ++i )
    {
        const dummy_packet = new Uint8Array( 8 );
        reliable_endpoint_send_packet( context.sender, dummy_packet, dummy_packet.length );
    }

    check( test_duplicate_packets_num_processed === TEST_DUPLICATE_PACKETS_NUM_ITERATIONS );

    const receiver_counters = reliable_endpoint_counters( context.receiver );

    check( receiver_counters[RELIABLE_ENDPOINT_COUNTER_NUM_PACKETS_RECEIVED] === 2 * TEST_DUPLICATE_PACKETS_NUM_ITERATIONS );
    check( receiver_counters[RELIABLE_ENDPOINT_COUNTER_NUM_PACKETS_DUPLICATE] === TEST_DUPLICATE_PACKETS_NUM_ITERATIONS );

    // duplicate fragments arriving after their packet was delivered must not restart reassembly

    const fragmented_sequence = reliable_endpoint_next_packet_sequence( context.sender );

    const large_packet = new Uint8Array( 2048 );
    reliable_endpoint_send_packet( context.sender, large_packet, large_packet.length );

    check( test_duplicate_packets_num_processed === TEST_DUPLICATE_PACKETS_NUM_ITERATIONS + 1 );
    check( !reliable_sequence_buffer_exists( context.receiver.fragment_reassembly, fragmented_sequence ) );

    reliable_endpoint_destroy( context.sender );
    reliable_endpoint_destroy( context.receiver );
}

const test_stale_packets_first_packet = new Uint8Array( 64 );
let test_stale_packets_first_packet_bytes = 0;
let test_stale_packets_num_processed = 0;

function test_stale_packets_transmit_packet_function( _context: unknown, id: bigint, sequence: number, packet_data: Uint8Array, packet_bytes: number ): void
{
    const context = _context as test_context_t;

    if ( id === 0n )
    {
        if ( sequence === 0 && test_stale_packets_first_packet_bytes === 0 )
        {
            reliable_assert( packet_bytes <= test_stale_packets_first_packet.length, "packet_bytes <= sizeof( test_stale_packets_first_packet )" );
            test_stale_packets_first_packet.set( packet_data.subarray( 0, packet_bytes ) );
            test_stale_packets_first_packet_bytes = packet_bytes;
        }

        reliable_endpoint_receive_packet( context.receiver!, packet_data, packet_bytes );
    }
}

function test_stale_packets_process_packet_function( _context: unknown, _id: bigint, _sequence: number, _packet_data: Uint8Array, _packet_bytes: number ): boolean
{
    test_stale_packets_num_processed++;

    return true;
}

const TEST_STALE_PACKETS_NUM_ITERATIONS = 300;

function test_stale_packets(): void
{
    const time = 100.0;

    const context = new test_context_t();
    test_default_context( context );

    const sender_config = test_new_config();
    const receiver_config = test_new_config();

    sender_config.name = "sender";
    sender_config.context = context;
    sender_config.id = 0n;
    sender_config.transmit_packet_function = test_stale_packets_transmit_packet_function;
    sender_config.process_packet_function = test_process_packet_function;

    receiver_config.name = "receiver";
    receiver_config.context = context;
    receiver_config.id = 1n;
    receiver_config.transmit_packet_function = test_stale_packets_transmit_packet_function;
    receiver_config.process_packet_function = test_stale_packets_process_packet_function;

    context.sender = reliable_endpoint_create( sender_config, time );
    context.receiver = reliable_endpoint_create( receiver_config, time );
    check( context.sender != null && context.receiver != null );

    test_stale_packets_first_packet_bytes = 0;
    test_stale_packets_num_processed = 0;

    // send enough packets that sequence 0 falls out of the receive window (256 entries)

    let i: number;
    for ( i = 0; i < TEST_STALE_PACKETS_NUM_ITERATIONS; ++i )
    {
        const dummy_packet = new Uint8Array( 8 );
        reliable_endpoint_send_packet( context.sender, dummy_packet, dummy_packet.length );
    }

    check( test_stale_packets_num_processed === TEST_STALE_PACKETS_NUM_ITERATIONS );
    check( test_stale_packets_first_packet_bytes > 0 );

    // replaying the first packet must be rejected as stale, not processed

    reliable_endpoint_receive_packet( context.receiver, test_stale_packets_first_packet, test_stale_packets_first_packet_bytes );

    check( test_stale_packets_num_processed === TEST_STALE_PACKETS_NUM_ITERATIONS );

    const receiver_counters = reliable_endpoint_counters( context.receiver );

    check( receiver_counters[RELIABLE_ENDPOINT_COUNTER_NUM_PACKETS_STALE] === 1 );

    reliable_endpoint_destroy( context.sender );
    reliable_endpoint_destroy( context.receiver );
}

const TEST_ACK_BUFFER_OVERFLOW_NUM_PACKETS = 32;
const TEST_ACK_BUFFER_OVERFLOW_BUFFER_SIZE = 16;

function test_ack_buffer_overflow(): void
{
    const time = 100.0;

    const context = new test_context_t();
    test_default_context( context );

    const sender_config = test_new_config();
    const receiver_config = test_new_config();

    // undersized ack buffer on the sender, so a single received packet acking 32 sent packets overflows it

    sender_config.ack_buffer_size = TEST_ACK_BUFFER_OVERFLOW_BUFFER_SIZE;

    sender_config.name = "sender";
    sender_config.context = context;
    sender_config.id = 0n;
    sender_config.transmit_packet_function = test_transmit_packet_function;
    sender_config.process_packet_function = test_process_packet_function;

    receiver_config.name = "receiver";
    receiver_config.context = context;
    receiver_config.id = 1n;
    receiver_config.transmit_packet_function = test_transmit_packet_function;
    receiver_config.process_packet_function = test_process_packet_function;

    context.sender = reliable_endpoint_create( sender_config, time );
    context.receiver = reliable_endpoint_create( receiver_config, time );
    check( context.sender != null && context.receiver != null );

    let i: number;
    for ( i = 0; i < TEST_ACK_BUFFER_OVERFLOW_NUM_PACKETS; ++i )
    {
        const dummy_packet = new Uint8Array( 8 );
        reliable_endpoint_send_packet( context.sender, dummy_packet, dummy_packet.length );
    }

    // one packet back from the receiver acks all 32, but only 16 fit in the ack buffer. the rest are dropped

    {
        const dummy_packet = new Uint8Array( 8 );
        reliable_endpoint_send_packet( context.receiver, dummy_packet, dummy_packet.length );
    }

    let num_acks = reliable_endpoint_get_acks( context.sender ).length;
    check( num_acks === TEST_ACK_BUFFER_OVERFLOW_BUFFER_SIZE );

    const sender_counters = reliable_endpoint_counters( context.sender );
    check( sender_counters[RELIABLE_ENDPOINT_COUNTER_NUM_PACKETS_ACKED] === TEST_ACK_BUFFER_OVERFLOW_BUFFER_SIZE );

    // once the caller clears acks, the dropped acks are reported on the next packet that covers them

    reliable_endpoint_clear_acks( context.sender );

    {
        const dummy_packet = new Uint8Array( 8 );
        reliable_endpoint_send_packet( context.receiver, dummy_packet, dummy_packet.length );
    }

    num_acks = reliable_endpoint_get_acks( context.sender ).length;
    check( num_acks === TEST_ACK_BUFFER_OVERFLOW_NUM_PACKETS - TEST_ACK_BUFFER_OVERFLOW_BUFFER_SIZE );
    check( ( sender_counters[RELIABLE_ENDPOINT_COUNTER_NUM_PACKETS_ACKED] as number ) === TEST_ACK_BUFFER_OVERFLOW_NUM_PACKETS );

    reliable_endpoint_destroy( context.sender );
    reliable_endpoint_destroy( context.receiver );
}

const TEST_MAX_PACKET_BYTES = 4 * 1024;

function generate_packet_data_with_size( sequence: number, packet_data: Uint8Array, packet_bytes: number ): void
{
    reliable_assert( packet_bytes >= 2, "packet_bytes >= 2" );
    reliable_assert( packet_bytes <= TEST_MAX_PACKET_BYTES, "packet_bytes <= TEST_MAX_PACKET_BYTES" );

    packet_data[0] = sequence & 0xFF;
    packet_data[1] = ( sequence >> 8 ) & 0xFF;
    for ( let i = 2; i < packet_bytes; ++i )
    {
        packet_data[i] = ( i + sequence ) % 256;
    }
}

function generate_packet_data( sequence: number, packet_data: Uint8Array ): number
{
    const packet_bytes = ( ( sequence * 1023 ) % ( TEST_MAX_PACKET_BYTES - 2 ) ) + 2;
    generate_packet_data_with_size( sequence, packet_data, packet_bytes );
    return packet_bytes;
}

function validate_packet_data( packet_data: Uint8Array, packet_bytes: number ): void
{
    reliable_assert( packet_bytes >= 2, "packet_bytes >= 2" );
    reliable_assert( packet_bytes <= TEST_MAX_PACKET_BYTES, "packet_bytes <= TEST_MAX_PACKET_BYTES" );
    let sequence = 0;
    sequence |= packet_data[0];
    sequence |= packet_data[1] << 8;
    check( packet_bytes === ( ( sequence * 1023 ) % ( TEST_MAX_PACKET_BYTES - 2 ) ) + 2 );
    for ( let i = 2; i < packet_bytes; ++i )
    {
        check( packet_data[i] === ( ( i + sequence ) % 256 ) );
    }
}

function test_process_packet_function_validate( _context: unknown, _id: bigint, _sequence: number, packet_data: Uint8Array, packet_bytes: number ): boolean
{
    reliable_assert( packet_data != null, "packet_data" );
    reliable_assert( packet_bytes > 0, "packet_bytes > 0" );
    reliable_assert( packet_bytes <= TEST_MAX_PACKET_BYTES, "packet_bytes <= TEST_MAX_PACKET_BYTES" );

    validate_packet_data( packet_data, packet_bytes );

    return true;
}

function generate_packet_data_large( packet_data: Uint8Array ): number
{
    const data_bytes = TEST_MAX_PACKET_BYTES - 2;
    reliable_assert( data_bytes >= 2, "data_bytes >= 2" );
    reliable_assert( data_bytes <= ( 1 << 16 ), "data_bytes <= (1 << 16)" );

    packet_data[0] = data_bytes & 0xFF;
    packet_data[1] = ( data_bytes >> 8 ) & 0xFF;
    for ( let i = 2; i < data_bytes; ++i )
    {
        packet_data[i] = i % 256;
    }
    return data_bytes + 2;
}

function test_process_packet_function_validate_large( _context: unknown, _id: bigint, _sequence: number, packet_data: Uint8Array, packet_bytes: number ): boolean
{
    reliable_assert( packet_data != null, "packet_data" );
    reliable_assert( packet_bytes >= 2, "packet_bytes >= 2" );
    reliable_assert( packet_bytes <= TEST_MAX_PACKET_BYTES, "packet_bytes <= TEST_MAX_PACKET_BYTES" );

    let data_bytes = 0;
    data_bytes |= packet_data[0];
    data_bytes |= packet_data[1] << 8;
    check( packet_bytes === data_bytes + 2 );
    for ( let i = 2; i < data_bytes; ++i )
    {
        check( packet_data[i] === ( i % 256 ) );
    }

    return true;
}

function test_packets(): void
{
    let time = 100.0;

    const context = new test_context_t();
    test_default_context( context );

    const sender_config = test_new_config();
    const receiver_config = test_new_config();

    sender_config.fragment_above = 500;
    receiver_config.fragment_above = 500;

    sender_config.name = "sender";
    sender_config.context = context;
    sender_config.id = 0n;
    sender_config.transmit_packet_function = test_transmit_packet_function;
    sender_config.process_packet_function = test_process_packet_function_validate;

    receiver_config.name = "receiver";
    receiver_config.context = context;
    receiver_config.id = 1n;
    receiver_config.transmit_packet_function = test_transmit_packet_function;
    receiver_config.process_packet_function = test_process_packet_function_validate;

    context.sender = reliable_endpoint_create( sender_config, time );
    context.receiver = reliable_endpoint_create( receiver_config, time );
    check( context.sender != null && context.receiver != null );

    const delta_time = 0.1;

    for ( let i = 0; i < 16; ++i )
    {
        {
            const packet_data = new Uint8Array( TEST_MAX_PACKET_BYTES );
            const sequence = reliable_endpoint_next_packet_sequence( context.sender );
            const packet_bytes = generate_packet_data( sequence, packet_data );
            reliable_endpoint_send_packet( context.sender, packet_data, packet_bytes );
        }

        {
            const packet_data = new Uint8Array( TEST_MAX_PACKET_BYTES );
            const sequence = reliable_endpoint_next_packet_sequence( context.sender );
            const packet_bytes = generate_packet_data( sequence, packet_data );
            reliable_endpoint_send_packet( context.sender, packet_data, packet_bytes );
        }

        reliable_endpoint_update( context.sender, time );
        reliable_endpoint_update( context.receiver, time );

        reliable_endpoint_clear_acks( context.sender );
        reliable_endpoint_clear_acks( context.receiver );

        time += delta_time;
    }

    // (TS: every packet above was validated by the process function; make sure they actually arrived)
    check( reliable_endpoint_counters( context.receiver )[RELIABLE_ENDPOINT_COUNTER_NUM_PACKETS_RECEIVED] === 32 );

    reliable_endpoint_destroy( context.sender );
    reliable_endpoint_destroy( context.receiver );
}

function test_large_packets(): void
{
    const time = 100.0;

    const context = new test_context_t();
    test_default_context( context );

    const sender_config = test_new_config();
    const receiver_config = test_new_config();

    sender_config.max_packet_size = TEST_MAX_PACKET_BYTES;
    receiver_config.max_packet_size = TEST_MAX_PACKET_BYTES;

    sender_config.fragment_above = TEST_MAX_PACKET_BYTES;
    receiver_config.fragment_above = TEST_MAX_PACKET_BYTES;

    sender_config.name = "sender";
    sender_config.context = context;
    sender_config.id = 0n;
    sender_config.transmit_packet_function = test_transmit_packet_function;
    sender_config.process_packet_function = test_process_packet_function_validate_large;

    receiver_config.name = "receiver";
    receiver_config.context = context;
    receiver_config.id = 1n;
    receiver_config.transmit_packet_function = test_transmit_packet_function;
    receiver_config.process_packet_function = test_process_packet_function_validate_large;

    context.sender = reliable_endpoint_create( sender_config, time );
    context.receiver = reliable_endpoint_create( receiver_config, time );
    check( context.sender != null && context.receiver != null );

    {
        const packet_data = new Uint8Array( TEST_MAX_PACKET_BYTES );
        const packet_bytes = generate_packet_data_large( packet_data );
        check( packet_bytes === TEST_MAX_PACKET_BYTES );
        reliable_endpoint_send_packet( context.sender, packet_data, packet_bytes );
    }

    reliable_endpoint_update( context.sender, time );
    reliable_endpoint_update( context.receiver, time );

    reliable_endpoint_clear_acks( context.sender );
    reliable_endpoint_clear_acks( context.receiver );

    const receiver_counters = reliable_endpoint_counters( context.receiver );
    check( receiver_counters[RELIABLE_ENDPOINT_COUNTER_NUM_PACKETS_TOO_LARGE_TO_RECEIVE] === 0 );
    check( receiver_counters[RELIABLE_ENDPOINT_COUNTER_NUM_PACKETS_RECEIVED] === 1 );

    reliable_endpoint_destroy( context.sender );
    reliable_endpoint_destroy( context.receiver );
}

function test_sequence_buffer_rollover(): void
{
    const time = 100.0;

    const context = new test_context_t();
    test_default_context( context );

    const sender_config = test_new_config();
    const receiver_config = test_new_config();

    sender_config.fragment_above = 500;
    receiver_config.fragment_above = 500;

    sender_config.name = "sender";
    sender_config.context = context;
    sender_config.id = 0n;
    sender_config.transmit_packet_function = test_transmit_packet_function;
    sender_config.process_packet_function = test_process_packet_function;

    receiver_config.name = "receiver";
    receiver_config.context = context;
    receiver_config.id = 1n;
    receiver_config.transmit_packet_function = test_transmit_packet_function;
    receiver_config.process_packet_function = test_process_packet_function;

    context.sender = reliable_endpoint_create( sender_config, time );
    context.receiver = reliable_endpoint_create( receiver_config, time );
    check( context.sender != null && context.receiver != null );

    const packet_data = new Uint8Array( TEST_MAX_PACKET_BYTES );

    let num_packets_sent = 0;
    for ( let i = 0; i <= 32767; ++i )
    {
        const small_packet_data = new Uint8Array( 16 );
        const packet_bytes = small_packet_data.length;
        reliable_endpoint_next_packet_sequence( context.sender );
        reliable_endpoint_send_packet( context.sender, small_packet_data, packet_bytes );

        ++num_packets_sent;
    }

    const packet_bytes = packet_data.length;
    reliable_endpoint_next_packet_sequence( context.sender );
    reliable_endpoint_send_packet( context.sender, packet_data, packet_bytes );
    ++num_packets_sent;

    const receiver_counters = reliable_endpoint_counters( context.receiver );

    check( receiver_counters[RELIABLE_ENDPOINT_COUNTER_NUM_PACKETS_RECEIVED] === ( num_packets_sent & 0xFFFF ) );
    check( receiver_counters[RELIABLE_ENDPOINT_COUNTER_NUM_FRAGMENTS_INVALID] === 0 );

    reliable_endpoint_destroy( context.sender );
    reliable_endpoint_destroy( context.receiver );
}

// reliable.c tracks allocations by pointer. the TS allocator hook covers the run time buffers (fragment reassembly), so the
// tracking context records every array it hands out and every array handed back

class test_tracking_allocate_context_t
{
    active_allocations: Set<Uint8Array> = new Set<Uint8Array>();
    fail_allocations: boolean = false;       // when set, the allocator returns null (simulates memory pressure)
}

function test_tracking_allocate_function( context: unknown, bytes: number ): Uint8Array | null
{
    const tracking_context = context as test_tracking_allocate_context_t;
    if ( tracking_context.fail_allocations )
    {
        return null;
    }
    const allocation = new Uint8Array( bytes );
    tracking_context.active_allocations.add( allocation );
    return allocation;
}

function test_tracking_free_function( context: unknown, pointer: unknown ): void
{
    const tracking_context = context as test_tracking_allocate_context_t;
    check( tracking_context.active_allocations.has( pointer as Uint8Array ) );
    tracking_context.active_allocations.delete( pointer as Uint8Array );
}

function test_fragment_cleanup(): void
{
    let time = 100.0;

    const context = new test_context_t();
    test_default_context( context );

    const tracking_alloc_context = new test_tracking_allocate_context_t();

    const sender_config = test_new_config();
    const receiver_config = test_new_config();

    receiver_config.allocator_context = tracking_alloc_context;
    receiver_config.allocate_function = test_tracking_allocate_function;
    receiver_config.free_function = test_tracking_free_function;
    receiver_config.fragment_reassembly_buffer_size = 4;

    sender_config.name = "sender";
    sender_config.context = context;
    sender_config.id = 0n;
    sender_config.transmit_packet_function = test_transmit_packet_function;
    sender_config.process_packet_function = test_process_packet_function;

    receiver_config.name = "receiver";
    receiver_config.context = context;
    receiver_config.id = 1n;
    receiver_config.transmit_packet_function = test_transmit_packet_function;
    receiver_config.process_packet_function = test_process_packet_function;

    context.sender = reliable_endpoint_create( sender_config, time );
    context.receiver = reliable_endpoint_create( receiver_config, time );
    check( context.sender != null && context.receiver != null );

    const delta_time = 0.1;

    const packet_sizes = [
        sender_config.fragment_size + sender_config.fragment_size / 2,
        10,
        10,
        10,
        10,
    ];

    // Make sure we're sending more than receiver_config.fragment_reassembly_buffer_size packets, so the buffer wraps around.
    reliable_assert( packet_sizes.length > receiver_config.fragment_reassembly_buffer_size, "ARRAY_LENGTH( packet_sizes ) > receiver_config.fragment_reassembly_buffer_size" );

    for ( let i = 0; i < packet_sizes.length; ++i )
    {
        // Only allow one packet per transmit, so that our fragmented packets are only partially
        // delivered.
        context.allow_packets = 1;
        {
            const packet_data = new Uint8Array( TEST_MAX_PACKET_BYTES );
            const sequence = reliable_endpoint_next_packet_sequence( context.sender );
            generate_packet_data_with_size( sequence, packet_data, packet_sizes[i] );
            reliable_endpoint_send_packet( context.sender, packet_data, packet_sizes[i] );
        }

        reliable_endpoint_update( context.sender, time );
        reliable_endpoint_update( context.receiver, time );

        reliable_endpoint_clear_acks( context.sender );
        reliable_endpoint_clear_acks( context.receiver );

        time += delta_time;
    }

    // (TS: the partial reassembly buffer was allocated through the hook, so the leak check below checks something)
    check( reliable_endpoint_counters( context.receiver )[RELIABLE_ENDPOINT_COUNTER_NUM_FRAGMENTS_RECEIVED] === 1 );

    reliable_endpoint_destroy( context.sender );
    reliable_endpoint_destroy( context.receiver );

    // Make sure that there is no memory that hasn't been freed.
    check( tracking_alloc_context.active_allocations.size === 0 );
}

function test_fragment_reassembly_alloc_failure(): void
{
    // Regression: a NULL-returning allocator on the fragment reassembly receive path must fail the
    // fragment (bump NUM_FRAGMENTS_INVALID) rather than crash the process. Before the fix, the receive
    // path guarded the reassembly allocation with an assert only, so a release build segfaulted on a
    // NULL+offset memcpy. reliable.h documents NULL-returning allocators as a supported outcome.
    const time = 100.0;

    const context = new test_context_t();
    test_default_context( context );

    const tracking_alloc_context = new test_tracking_allocate_context_t();

    const sender_config = test_new_config();
    const receiver_config = test_new_config();

    receiver_config.allocator_context = tracking_alloc_context;
    receiver_config.allocate_function = test_tracking_allocate_function;
    receiver_config.free_function = test_tracking_free_function;

    sender_config.name = "sender";
    sender_config.context = context;
    sender_config.id = 0n;
    sender_config.transmit_packet_function = test_transmit_packet_function;
    sender_config.process_packet_function = test_process_packet_function;

    receiver_config.name = "receiver";
    receiver_config.context = context;
    receiver_config.id = 1n;
    receiver_config.transmit_packet_function = test_transmit_packet_function;
    receiver_config.process_packet_function = test_process_packet_function;

    context.sender = reliable_endpoint_create( sender_config, time );
    context.receiver = reliable_endpoint_create( receiver_config, time );
    check( context.sender != null && context.receiver != null );

    // create succeeded with a live allocator; now make every subsequent allocation fail, so the
    // failing allocation is specifically the reassembly buffer on the receive path.
    tracking_alloc_context.fail_allocations = true;

    // send a fragmented packet (larger than one fragment) from sender to receiver
    context.allow_packets = 1;
    {
        const packet_data = new Uint8Array( TEST_MAX_PACKET_BYTES );
        const packet_bytes = sender_config.fragment_size + sender_config.fragment_size / 2;
        const sequence = reliable_endpoint_next_packet_sequence( context.sender );
        generate_packet_data_with_size( sequence, packet_data, packet_bytes );
        reliable_endpoint_send_packet( context.sender, packet_data, packet_bytes );
    }

    reliable_endpoint_update( context.sender, time );
    reliable_endpoint_update( context.receiver, time );   // <-- receive path hits the NULL allocation; must not crash

    // the fragment must have been refused, not crashed through
    const receiver_counters = reliable_endpoint_counters( context.receiver );
    check( receiver_counters[RELIABLE_ENDPOINT_COUNTER_NUM_FRAGMENTS_INVALID] > 0 );

    // let the allocator work again so destroy can clean up, and confirm no leak
    tracking_alloc_context.fail_allocations = false;
    reliable_endpoint_destroy( context.sender );
    reliable_endpoint_destroy( context.receiver );

    check( tracking_alloc_context.active_allocations.size === 0 );
}

// security#26-2: the reassembly buffer is allocated through the caller's allocator, which may return memory that is not
// zeroed. Completeness is guaranteed today by the fragment bitmap plus validated offsets, but zeroing the buffer means a
// future logic error that skips storing a fragment leaks zeros into the delivered packet instead of stale contents.

class test_poison_allocate_context_t
{
    poison: boolean = false;             // when set, freshly returned memory is filled with 0xCC
}

function test_poison_allocate_function( context: unknown, bytes: number ): Uint8Array | null
{
    const poison_context = context as test_poison_allocate_context_t;

    const allocation = new Uint8Array( bytes );

    if ( poison_context.poison )
    {
        allocation.fill( 0xCC );
    }

    return allocation;
}

function test_poison_free_function( _context: unknown, _pointer: unknown ): void
{
}

function test_fragment_reassembly_buffer_zeroed(): void
{
    const time = 100.0;

    const context = new test_context_t();
    test_default_context( context );

    const poison_context = new test_poison_allocate_context_t();

    const sender_config = test_new_config();
    const receiver_config = test_new_config();

    receiver_config.allocator_context = poison_context;
    receiver_config.allocate_function = test_poison_allocate_function;
    receiver_config.free_function = test_poison_free_function;

    sender_config.name = "sender";
    sender_config.context = context;
    sender_config.id = 0n;
    sender_config.transmit_packet_function = test_transmit_packet_function;
    sender_config.process_packet_function = test_process_packet_function;

    receiver_config.name = "receiver";
    receiver_config.context = context;
    receiver_config.id = 1n;
    receiver_config.transmit_packet_function = test_transmit_packet_function;
    receiver_config.process_packet_function = test_process_packet_function;

    context.sender = reliable_endpoint_create( sender_config, time );
    context.receiver = reliable_endpoint_create( receiver_config, time );
    check( context.sender != null );
    check( context.receiver != null );

    // from here on the receive path's allocations are filled with the poison byte, so a buffer
    // that is not explicitly zeroed is visibly non-zero
    poison_context.poison = true;

    // deliver only the first fragment: the reassembly buffer is allocated and fragment 0 is
    // stored, but the tail of the buffer is never written
    context.allow_packets = 1;

    const packet_data = new Uint8Array( TEST_MAX_PACKET_BYTES );
    const packet_bytes = sender_config.fragment_size + sender_config.fragment_size / 2;
    const sequence = reliable_endpoint_next_packet_sequence( context.sender );
    generate_packet_data_with_size( sequence, packet_data, packet_bytes );
    reliable_endpoint_send_packet( context.sender, packet_data, packet_bytes );

    const reassembly_data = reliable_sequence_buffer_find( context.receiver.fragment_reassembly, sequence );

    check( reassembly_data != null );
    check( reassembly_data.packet_data != null );

    const packet_buffer_size = RELIABLE_MAX_PACKET_HEADER_BYTES + reassembly_data.num_fragments_total * sender_config.fragment_size + 8;

    // fragment 0 only writes near the front of the buffer, so the last byte is untouched and must
    // be zero. before the fix it still held the allocator's 0xCC poison.
    check( reassembly_data.packet_data.length === packet_buffer_size );
    check( reassembly_data.packet_data[packet_buffer_size - 1] === 0 );

    poison_context.poison = false;

    reliable_endpoint_destroy( context.sender );
    reliable_endpoint_destroy( context.receiver );
}

function test_endpoint_reset(): void
{
    let time = 100.0;

    const context = new test_context_t();
    test_default_context( context );

    const tracking_alloc_context = new test_tracking_allocate_context_t();

    const sender_config = test_new_config();
    const receiver_config = test_new_config();

    sender_config.fragment_above = 500;
    receiver_config.fragment_above = 500;

    receiver_config.allocator_context = tracking_alloc_context;
    receiver_config.allocate_function = test_tracking_allocate_function;
    receiver_config.free_function = test_tracking_free_function;

    sender_config.name = "sender";
    sender_config.context = context;
    sender_config.id = 0n;
    sender_config.transmit_packet_function = test_transmit_packet_function;
    sender_config.process_packet_function = test_process_packet_function;

    receiver_config.name = "receiver";
    receiver_config.context = context;
    receiver_config.id = 1n;
    receiver_config.transmit_packet_function = test_transmit_packet_function;
    receiver_config.process_packet_function = test_process_packet_function;

    context.sender = reliable_endpoint_create( sender_config, time );
    context.receiver = reliable_endpoint_create( receiver_config, time );
    check( context.sender != null && context.receiver != null );

    // exchange packets both ways so acks and counters accumulate

    let i: number;
    for ( i = 0; i < 8; ++i )
    {
        const dummy_packet = new Uint8Array( 8 );

        reliable_endpoint_send_packet( context.sender, dummy_packet, dummy_packet.length );
        reliable_endpoint_send_packet( context.receiver, dummy_packet, dummy_packet.length );

        reliable_endpoint_update( context.sender, time );
        reliable_endpoint_update( context.receiver, time );

        time += 0.01;
    }

    check( reliable_endpoint_get_acks( context.sender ).length > 0 );
    check( reliable_endpoint_counters( context.sender )[RELIABLE_ENDPOINT_COUNTER_NUM_PACKETS_SENT] > 0 );

    // leave a fragment reassembly in progress on the receiver by delivering only the first fragment of a large packet

    context.allow_packets = 1;
    {
        const large_packet = new Uint8Array( 1500 );
        reliable_endpoint_send_packet( context.sender, large_packet, large_packet.length );
    }
    context.allow_packets = -1;

    // (as the C# port: confirm the reassembly really is in progress, so reset has something to release)
    check( tracking_alloc_context.active_allocations.size === 1 );

    reliable_endpoint_reset( context.sender );
    reliable_endpoint_reset( context.receiver );

    check( reliable_endpoint_next_packet_sequence( context.sender ) === 0 );
    check( reliable_endpoint_next_packet_sequence( context.receiver ) === 0 );

    check( reliable_endpoint_get_acks( context.sender ).length === 0 );

    for ( i = 0; i < RELIABLE_ENDPOINT_NUM_COUNTERS; ++i )
    {
        check( reliable_endpoint_counters( context.sender )[i] === 0 );
        check( reliable_endpoint_counters( context.receiver )[i] === 0 );
    }

    // reset must have freed the in-progress reassembly buffer

    check( ( tracking_alloc_context.active_allocations.size as number ) === 0 );

    // the endpoints must work normally after reset

    for ( i = 0; i < 8; ++i )
    {
        const dummy_packet = new Uint8Array( 8 );

        reliable_endpoint_send_packet( context.sender, dummy_packet, dummy_packet.length );
        reliable_endpoint_send_packet( context.receiver, dummy_packet, dummy_packet.length );

        reliable_endpoint_update( context.sender, time );
        reliable_endpoint_update( context.receiver, time );

        time += 0.01;
    }

    check( reliable_endpoint_get_acks( context.sender ).length > 0 );
    check( reliable_endpoint_counters( context.receiver )[RELIABLE_ENDPOINT_COUNTER_NUM_PACKETS_RECEIVED] > 0 );

    reliable_endpoint_destroy( context.sender );
    reliable_endpoint_destroy( context.receiver );

    // reset must have freed the in-progress reassembly buffer, and destroy must not double-free it

    check( ( tracking_alloc_context.active_allocations.size as number ) === 0 );
}

function test_rtt(): void
{
    let time = 100.0;
    const delta_time = 0.01;

    const context = new test_context_t();
    test_default_context( context );

    const sender_config = test_new_config();
    const receiver_config = test_new_config();

    sender_config.context = context;
    sender_config.id = 0n;
    sender_config.transmit_packet_function = test_transmit_packet_function;
    sender_config.process_packet_function = test_process_packet_function;

    receiver_config.context = context;
    receiver_config.id = 1n;
    receiver_config.transmit_packet_function = test_transmit_packet_function;
    receiver_config.process_packet_function = test_process_packet_function;

    context.sender = reliable_endpoint_create( sender_config, time );
    context.receiver = reliable_endpoint_create( receiver_config, time );
    check( context.sender != null && context.receiver != null );

    for ( let i = 0; i < 1000; ++i )
    {
        const dummy_packet = new Uint8Array( 8 );

        reliable_endpoint_send_packet( context.sender, dummy_packet, dummy_packet.length );
        reliable_endpoint_send_packet( context.receiver, dummy_packet, dummy_packet.length );

        reliable_endpoint_update( context.sender, time );
        reliable_endpoint_update( context.receiver, time );

        time += delta_time;
    }

    const rtt = reliable_endpoint_rtt( context.sender );
    const rtt_min = reliable_endpoint_rtt_min( context.sender );
    const rtt_max = reliable_endpoint_rtt_max( context.sender );
    const rtt_avg = reliable_endpoint_rtt_avg( context.sender );

    check( Number.isFinite( rtt ) && rtt >= 0 ); // Check rtt is finite and non-negative
    check( rtt_min >= 0 && rtt_min <= rtt_avg && rtt_avg <= rtt_max );
    check( rtt_max < 1000.0 ); // Assume RTT is in milliseconds

    reliable_endpoint_destroy( context.sender );
    reliable_endpoint_destroy( context.receiver );
}

// a pair of endpoints wired to each other through test_transmit_packet_function

class test_pair_t
{
    context: test_context_t = new test_context_t();
    sender_config: reliable_config_t = new reliable_config_t();
    receiver_config: reliable_config_t = new reliable_config_t();
}

function test_pair_configs( pair: test_pair_t ): void
{
    test_default_context( pair.context );

    reliable_default_config( pair.sender_config );
    reliable_default_config( pair.receiver_config );

    pair.sender_config.name = "sender";
    pair.sender_config.context = pair.context;
    pair.sender_config.id = 0n;
    pair.sender_config.transmit_packet_function = test_transmit_packet_function;
    pair.sender_config.process_packet_function = test_process_packet_function;

    pair.receiver_config.name = "receiver";
    pair.receiver_config.context = pair.context;
    pair.receiver_config.id = 1n;
    pair.receiver_config.transmit_packet_function = test_transmit_packet_function;
    pair.receiver_config.process_packet_function = test_process_packet_function;
}

function test_pair_create( pair: test_pair_t, time: number ): void
{
    pair.context.sender = reliable_endpoint_create( pair.sender_config, time );
    pair.context.receiver = reliable_endpoint_create( pair.receiver_config, time );
    check( pair.context.sender != null );
    check( pair.context.receiver != null );
}

function test_pair_destroy( pair: test_pair_t ): void
{
    reliable_endpoint_destroy( pair.context.sender! );
    reliable_endpoint_destroy( pair.context.receiver! );
}

// RL-02: a round trip long enough to reach any fixed sentinel must still be reported

function test_rtt_min_large(): void
{
    let time = 100.0;

    const pair = new test_pair_t();
    test_pair_configs( pair );
    test_pair_create( pair, time );
    const sender = pair.context.sender!;
    const receiver = pair.context.receiver!;

    const packet = new Uint8Array( 8 );

    reliable_endpoint_send_packet( sender, packet, packet.length );

    // ten seconds pass before the acknowledgment comes back, so the one rtt sample is 10,000 ms

    time += 10.0;

    reliable_endpoint_update( sender, time );
    reliable_endpoint_update( receiver, time );

    reliable_endpoint_send_packet( receiver, packet, packet.length );

    reliable_endpoint_update( sender, time );

    check( reliable_endpoint_get_acks( sender ).length === 1 );

    check( reliable_endpoint_rtt_min( sender ) === 10000.0 );
    check( reliable_endpoint_rtt_max( sender ) === 10000.0 );
    check( reliable_endpoint_rtt_avg( sender ) === 10000.0 );
    check( reliable_endpoint_jitter_avg_vs_min_rtt( sender ) === 0.0 );
    check( reliable_endpoint_jitter_max_vs_min_rtt( sender ) === 0.0 );

    // and an endpoint with no samples at all still reports zero

    check( reliable_endpoint_rtt_min( receiver ) === 0.0 );

    test_pair_destroy( pair );
}

// RL-03: reset clears every field a getter can return, the rtt history included

function test_endpoint_reset_clears_stats(): void
{
    let time = 100.0;

    const pair = new test_pair_t();
    test_pair_configs( pair );
    test_pair_create( pair, time );
    const sender = pair.context.sender!;
    const receiver = pair.context.receiver!;

    // enough packets that the bandwidth window, which samples half the sent packets buffer,
    // lands on packets that were actually sent

    for ( let i = 0; i < 300; ++i )
    {
        const packet = new Uint8Array( 64 );

        // the reply comes back a step later, so the acknowledgment carries a real round trip

        reliable_endpoint_send_packet( sender, packet, packet.length );

        time += 0.1;
        reliable_endpoint_update( sender, time );
        reliable_endpoint_update( receiver, time );

        reliable_endpoint_send_packet( receiver, packet, packet.length );

        time += 0.1;
        reliable_endpoint_update( sender, time );
        reliable_endpoint_update( receiver, time );

        reliable_endpoint_clear_acks( sender );
        reliable_endpoint_clear_acks( receiver );
    }

    check( reliable_endpoint_rtt( sender ) > 0.0 );
    check( reliable_endpoint_rtt_min( sender ) > 0.0 );
    check( reliable_endpoint_rtt_max( sender ) > 0.0 );
    check( reliable_endpoint_rtt_avg( sender ) > 0.0 );

    let bandwidth = reliable_endpoint_bandwidth( sender );
    check( bandwidth.sent_bandwidth_kbps > 0.0 );
    check( bandwidth.received_bandwidth_kbps > 0.0 );
    check( bandwidth.acked_bandwidth_kbps > 0.0 );

    reliable_endpoint_reset( sender );

    check( reliable_endpoint_rtt( sender ) === 0.0 );
    check( reliable_endpoint_rtt_min( sender ) === 0.0 );
    check( reliable_endpoint_rtt_max( sender ) === 0.0 );
    check( reliable_endpoint_rtt_avg( sender ) === 0.0 );
    check( reliable_endpoint_jitter_avg_vs_min_rtt( sender ) === 0.0 );
    check( reliable_endpoint_jitter_max_vs_min_rtt( sender ) === 0.0 );
    check( reliable_endpoint_jitter_stddev_vs_avg_rtt( sender ) === 0.0 );
    check( reliable_endpoint_packet_loss( sender ) === 0.0 );

    bandwidth = reliable_endpoint_bandwidth( sender );
    check( bandwidth.sent_bandwidth_kbps === 0.0 );
    check( bandwidth.received_bandwidth_kbps === 0.0 );
    check( bandwidth.acked_bandwidth_kbps === 0.0 );

    // the rtt history is part of the state, so recomputing the statistics after a reset must
    // not resurrect the samples that were in it

    time += 0.1;
    reliable_endpoint_update( sender, time );

    check( reliable_endpoint_rtt_min( sender ) === 0.0 );
    check( reliable_endpoint_rtt_max( sender ) === 0.0 );
    check( reliable_endpoint_rtt_avg( sender ) === 0.0 );
    check( reliable_endpoint_jitter_avg_vs_min_rtt( sender ) === 0.0 );
    check( reliable_endpoint_jitter_max_vs_min_rtt( sender ) === 0.0 );
    check( reliable_endpoint_jitter_stddev_vs_avg_rtt( sender ) === 0.0 );

    test_pair_destroy( pair );
}

// RL-06: a config the library cannot honor is refused instead of asserted

function test_endpoint_create_invalid_config(): void
{
    const valid = test_new_config();
    valid.transmit_packet_function = test_transmit_packet_function;
    valid.process_packet_function = test_process_packet_function;

    let endpoint = reliable_endpoint_create( valid, 0.0 );
    check( endpoint != null );
    reliable_endpoint_destroy( endpoint );

    check( reliable_endpoint_create( null, 0.0 ) === null );

    let config: reliable_config_t;

    // the two relationships between fields

    config = reliable_config_copy( valid );
    config.fragment_above = config.max_packet_size + 1;
    check( reliable_endpoint_create( config, 0.0 ) === null );

    config = reliable_config_copy( valid );
    config.max_fragments = 4;
    config.fragment_size = 1024;
    config.max_packet_size = 4 * 1024 + 1;
    check( reliable_endpoint_create( config, 0.0 ) === null );

    // exactly covering is allowed, one fragment short is not

    config = reliable_config_copy( valid );
    config.max_fragments = 4;
    config.fragment_size = 1024;
    config.max_packet_size = 4 * 1024;
    config.fragment_above = 1024;
    endpoint = reliable_endpoint_create( config, 0.0 );
    check( endpoint != null );
    reliable_endpoint_destroy( endpoint );

    // ranges

    config = reliable_config_copy( valid ); config.max_packet_size = 0;
    check( reliable_endpoint_create( config, 0.0 ) === null );

    config = reliable_config_copy( valid ); config.fragment_above = 0;
    check( reliable_endpoint_create( config, 0.0 ) === null );

    config = reliable_config_copy( valid ); config.fragment_size = 0;
    check( reliable_endpoint_create( config, 0.0 ) === null );

    config = reliable_config_copy( valid ); config.max_fragments = 0;
    check( reliable_endpoint_create( config, 0.0 ) === null );

    config = reliable_config_copy( valid ); config.max_fragments = 257;
    check( reliable_endpoint_create( config, 0.0 ) === null );

    config = reliable_config_copy( valid ); config.max_fragments = 256; config.fragment_size = 8421505;
    config.max_packet_size = config.fragment_size;
    config.fragment_above = 1;
    check( reliable_endpoint_create( config, 0.0 ) === null );

    config = reliable_config_copy( valid ); config.max_packet_size = INT_MAX - 10;
    config.fragment_above = 1;
    config.fragment_size = config.max_packet_size;
    config.max_fragments = 1;
    check( reliable_endpoint_create( config, 0.0 ) === null );

    config = reliable_config_copy( valid ); config.ack_buffer_size = 0;
    check( reliable_endpoint_create( config, 0.0 ) === null );

    config = reliable_config_copy( valid ); config.sent_packets_buffer_size = -1;
    check( reliable_endpoint_create( config, 0.0 ) === null );

    config = reliable_config_copy( valid ); config.received_packets_buffer_size = 0;
    check( reliable_endpoint_create( config, 0.0 ) === null );

    config = reliable_config_copy( valid ); config.fragment_reassembly_buffer_size = 0;
    check( reliable_endpoint_create( config, 0.0 ) === null );

    config = reliable_config_copy( valid ); config.rtt_history_size = 0;
    check( reliable_endpoint_create( config, 0.0 ) === null );

    config = reliable_config_copy( valid ); config.packet_header_size = -1;
    check( reliable_endpoint_create( config, 0.0 ) === null );

    config = reliable_config_copy( valid ); config.packet_header_size = INT_MAX;
    check( reliable_endpoint_create( config, 0.0 ) === null );

    config = reliable_config_copy( valid ); config.transmit_packet_function = null;
    check( reliable_endpoint_create( config, 0.0 ) === null );

    config = reliable_config_copy( valid ); config.process_packet_function = null;
    check( reliable_endpoint_create( config, 0.0 ) === null );

    // (the reliable_checked_size checks are C only: they test size_t arithmetic, and typed array sizes are checked by the runtime)
}

// security#26-3 adapted (as the C# port): reliable.c bounds the (possibly unterminated) name in its rejection logs. TS strings
// cannot over-read, so this checks the TS side of the same contract: a refused config logs exactly one error line, naming the endpoint

let test_name_log_line: string | null = null;
let test_name_log_calls = 0;

function test_name_log_printf_function( text: string ): void
{
    test_name_log_line = text;
    test_name_log_calls++;
}

function test_config_name_bounded_in_rejection_log(): void
{
    const config = test_new_config();
    config.name = "x".repeat( 255 );
    config.max_packet_size = -1;
    config.fragment_above = -1;
    config.max_fragments = -1;
    config.fragment_size = -1;
    config.ack_buffer_size = -1;
    config.sent_packets_buffer_size = -1;
    config.received_packets_buffer_size = -1;
    config.fragment_reassembly_buffer_size = -1;
    config.rtt_history_size = -1;
    config.packet_header_size = -1;
    config.transmit_packet_function = test_transmit_packet_function;
    config.process_packet_function = test_process_packet_function;

    const previous_printf_function = printf_function;
    const previous_log_level = log_level;

    test_name_log_line = null;
    test_name_log_calls = 0;

    reliable_set_printf_function( test_name_log_printf_function );
    reliable_log_level( RELIABLE_LOG_LEVEL_ERROR );

    const endpoint = reliable_endpoint_create( config, 0.0 );

    reliable_log_level( previous_log_level );
    reliable_set_printf_function( previous_printf_function );

    check( endpoint === null );
    check( test_name_log_calls === 1 );
    const line = test_name_log_line as string | null;
    check( line !== null && line.startsWith( "[" + config.name + "] " ) );
}

// RL-07: the sequence number crosses 65535 to 0

const test_wrap_acked = new Uint8Array( 65536 );

function test_sequence_wrap(): void
{
    const time = 100.0;

    const pair = new test_pair_t();
    test_pair_configs( pair );
    test_pair_create( pair, time );
    const sender = pair.context.sender!;
    const receiver = pair.context.receiver!;

    test_wrap_acked.fill( 0 );

    const num_iterations = 65536 + 64;

    const packet = new Uint8Array( 8 );

    let i: number;
    for ( i = 0; i < num_iterations; ++i )
    {
        reliable_endpoint_send_packet( sender, packet, packet.length );
        reliable_endpoint_send_packet( receiver, packet, packet.length );

        const acks = reliable_endpoint_get_acks( sender );

        for ( let j = 0; j < acks.length; ++j )
        {
            test_wrap_acked[acks[j]] = 1;
        }

        reliable_endpoint_clear_acks( sender );
        reliable_endpoint_clear_acks( receiver );
    }

    check( reliable_endpoint_next_packet_sequence( sender ) === ( num_iterations & 0xFFFF ) );

    // the sequences either side of the wrap were acked like any others

    check( test_wrap_acked[65533] !== 0 );
    check( test_wrap_acked[65534] !== 0 );
    check( test_wrap_acked[65535] !== 0 );
    check( test_wrap_acked[0] !== 0 );
    check( test_wrap_acked[1] !== 0 );
    check( test_wrap_acked[2] !== 0 );

    for ( i = 0; i < 65536; ++i )
    {
        check( test_wrap_acked[i] !== 0 );
    }

    check( reliable_endpoint_counters( receiver )[RELIABLE_ENDPOINT_COUNTER_NUM_PACKETS_RECEIVED] === num_iterations );

    test_pair_destroy( pair );
}

// RL-07: fragment counts at both ends of the range, and a payload that is an exact multiple
// of the fragment size

class test_fragment_context_t extends test_context_t
{
    num_processed: number = 0;
    processed_bytes: number = 0;
    processed: Uint8Array = new Uint8Array( 64 * 1024 );
}

function test_fragment_process_packet_function( _context: unknown, _id: bigint, _sequence: number, packet_data: Uint8Array, packet_bytes: number ): boolean
{
    const context = _context as test_fragment_context_t;

    check( packet_bytes <= context.processed.length );

    context.num_processed++;
    context.processed_bytes = packet_bytes;
    context.processed.set( packet_data.subarray( 0, packet_bytes ) );

    return true;
}

function test_fragment_case( fragment_size: number, max_fragments: number, packet_bytes: number, expected_fragments: number ): void
{
    const context = new test_fragment_context_t();
    test_default_context( context );

    const sender_config = test_new_config();

    sender_config.fragment_size = fragment_size;
    sender_config.max_fragments = max_fragments;
    sender_config.max_packet_size = fragment_size * max_fragments;
    sender_config.fragment_above = fragment_size;
    const receiver_config = reliable_config_copy( sender_config );

    sender_config.name = "sender";
    sender_config.context = context;
    sender_config.id = 0n;
    sender_config.transmit_packet_function = test_transmit_packet_function;
    sender_config.process_packet_function = test_fragment_process_packet_function;

    receiver_config.name = "receiver";
    receiver_config.context = context;
    receiver_config.id = 1n;
    receiver_config.transmit_packet_function = test_transmit_packet_function;
    receiver_config.process_packet_function = test_fragment_process_packet_function;

    context.sender = reliable_endpoint_create( sender_config, 100.0 );
    context.receiver = reliable_endpoint_create( receiver_config, 100.0 );
    check( context.sender != null );
    check( context.receiver != null );

    const packet = new Uint8Array( packet_bytes );

    for ( let i = 0; i < packet_bytes; ++i )
    {
        packet[i] = ( ( i * 31 ) + 7 ) & 0xFF;
    }

    reliable_endpoint_send_packet( context.sender, packet, packet_bytes );

    check( context.num_processed === 1 );
    check( context.processed_bytes === packet_bytes );
    check( test_bytes_equal( context.processed.subarray( 0, packet_bytes ), packet ) );

    const fragments_sent = reliable_endpoint_counters( context.sender )[RELIABLE_ENDPOINT_COUNTER_NUM_FRAGMENTS_SENT];
    const fragments_received = reliable_endpoint_counters( context.receiver )[RELIABLE_ENDPOINT_COUNTER_NUM_FRAGMENTS_RECEIVED];

    if ( expected_fragments === 0 )
    {
        // below the threshold: sent whole, no fragments at all
        check( fragments_sent === 0 );
        check( fragments_received === 0 );
    }
    else
    {
        check( fragments_sent === expected_fragments );
        check( fragments_received === expected_fragments );
    }

    reliable_endpoint_destroy( context.sender );
    reliable_endpoint_destroy( context.receiver );
}

function test_fragment_counts(): void
{
    // an exact multiple of the fragment size, where the last fragment is full rather than a remainder
    test_fragment_case( 512, 16, 512 * 4, 4 );

    // the largest packet the config allows, again an exact multiple
    test_fragment_case( 512, 16, 512 * 16, 16 );

    // one fragment: above the threshold by a single byte
    test_fragment_case( 512, 16, 513, 2 );
    test_fragment_case( 64, 256, 65, 2 );

    // 256 fragments, the maximum the wire format can express
    test_fragment_case( 64, 256, 64 * 256, 256 );
    test_fragment_case( 64, 256, 64 * 255 + 1, 256 );

    // at or below the threshold the packet is not fragmented
    test_fragment_case( 512, 16, 512, 0 );
    test_fragment_case( 512, 16, 1, 0 );
}

// RL-07: truncated packets and fragments are rejected rather than acted on. as in the C# port, every packet handed to the
// receiver is an exact-size array (as a socket delivers them), so a read past packet_bytes would read undefined, not slack

class test_truncation_context_t extends test_context_t
{
    num_processed: number = 0;
    num_captured: number = 0;
    captured_bytes: number[] = new Array<number>( 300 ).fill( 0 );
    captured: Uint8Array[] = new Array<Uint8Array>( 300 );
}

function test_truncation_transmit_packet_function( _context: unknown, _id: bigint, _sequence: number, packet_data: Uint8Array, packet_bytes: number ): void
{
    const context = _context as test_truncation_context_t;

    if ( context.num_captured < context.captured_bytes.length && packet_bytes <= 1024 )
    {
        context.captured[context.num_captured] = packet_data.slice( 0, packet_bytes );
        context.captured_bytes[context.num_captured] = packet_bytes;
        context.num_captured++;
    }
}

function test_truncation_process_packet_function( _context: unknown, _id: bigint, _sequence: number, _packet_data: Uint8Array, _packet_bytes: number ): boolean
{
    const context = _context as test_truncation_context_t;
    context.num_processed++;
    return true;
}

function test_truncate( packet_data: Uint8Array, packet_bytes: number ): Uint8Array
{
    return packet_data.slice( 0, packet_bytes );
}

function test_truncated_packets(): void
{
    const context = new test_truncation_context_t();
    test_default_context( context );

    const config = test_new_config();
    config.fragment_size = 256;
    config.max_fragments = 16;
    config.max_packet_size = 256 * 16;
    config.fragment_above = 256;
    config.context = context;
    config.id = 0n;
    config.transmit_packet_function = test_truncation_transmit_packet_function;
    config.process_packet_function = test_truncation_process_packet_function;

    const sender = reliable_endpoint_create( config, 100.0 );
    const receiver = reliable_endpoint_create( config, 100.0 );
    check( sender != null );
    check( receiver != null );

    // an unfragmented packet, captured on the wire

    const packet = new Uint8Array( 200 ).fill( 0xAB );
    reliable_endpoint_send_packet( sender, packet, packet.length );
    check( context.num_captured === 1 );

    const whole_bytes = context.captured_bytes[0];

    // every truncation of it shorter than the header is rejected, and none is processed

    let truncated_bytes: number;
    for ( truncated_bytes = 1; truncated_bytes < 4; ++truncated_bytes )
    {
        reliable_endpoint_receive_packet( receiver, test_truncate( context.captured[0], truncated_bytes ), truncated_bytes );
    }

    check( reliable_endpoint_counters( receiver )[RELIABLE_ENDPOINT_COUNTER_NUM_PACKETS_INVALID] === 3 );
    check( context.num_processed === 0 );

    // the whole packet still arrives

    reliable_endpoint_receive_packet( receiver, context.captured[0], whole_bytes );
    check( ( context.num_processed as number ) === 1 );

    // now a fragmented packet

    context.num_captured = 0;

    const large_packet = new Uint8Array( 1024 ).fill( 0xCD );
    reliable_endpoint_send_packet( sender, large_packet, large_packet.length );
    check( context.num_captured === 4 );

    // a fragment truncated inside its header is rejected

    for ( truncated_bytes = 1; truncated_bytes < RELIABLE_FRAGMENT_HEADER_BYTES; ++truncated_bytes )
    {
        reliable_endpoint_receive_packet( receiver, test_truncate( context.captured[1], truncated_bytes ), truncated_bytes );
    }

    check( reliable_endpoint_counters( receiver )[RELIABLE_ENDPOINT_COUNTER_NUM_FRAGMENTS_RECEIVED] === 0 );
    check( reliable_endpoint_counters( receiver )[RELIABLE_ENDPOINT_COUNTER_NUM_FRAGMENTS_INVALID] === RELIABLE_FRAGMENT_HEADER_BYTES - 1 );

    // a fragment that is not the last one must carry exactly fragment_size bytes, so a
    // truncated body is rejected too

    reliable_endpoint_receive_packet( receiver, test_truncate( context.captured[1], context.captured_bytes[1] - 1 ), context.captured_bytes[1] - 1 );
    check( reliable_endpoint_counters( receiver )[RELIABLE_ENDPOINT_COUNTER_NUM_FRAGMENTS_RECEIVED] === 0 );
    check( reliable_endpoint_counters( receiver )[RELIABLE_ENDPOINT_COUNTER_NUM_FRAGMENTS_INVALID] === RELIABLE_FRAGMENT_HEADER_BYTES );
    check( ( context.num_processed as number ) === 1 );

    // fragment 0 truncated inside its embedded packet header is rejected (C# port: f0e3be1 used to throw here)

    for ( truncated_bytes = RELIABLE_FRAGMENT_HEADER_BYTES + 1; truncated_bytes < context.captured_bytes[0] && truncated_bytes < RELIABLE_FRAGMENT_HEADER_BYTES + RELIABLE_MAX_PACKET_HEADER_BYTES; ++truncated_bytes )
    {
        reliable_endpoint_receive_packet( receiver, test_truncate( context.captured[0], truncated_bytes ), truncated_bytes );
    }

    check( reliable_endpoint_counters( receiver )[RELIABLE_ENDPOINT_COUNTER_NUM_FRAGMENTS_RECEIVED] === 0 );
    check( ( context.num_processed as number ) === 1 );

    const fragments_invalid = reliable_endpoint_counters( receiver )[RELIABLE_ENDPOINT_COUNTER_NUM_FRAGMENTS_INVALID];

    // the intact fragments reassemble

    for ( let i = 0; i < context.num_captured; ++i )
    {
        reliable_endpoint_receive_packet( receiver, context.captured[i], context.captured_bytes[i] );
    }

    check( reliable_endpoint_counters( receiver )[RELIABLE_ENDPOINT_COUNTER_NUM_FRAGMENTS_RECEIVED] === 4 );
    check( reliable_endpoint_counters( receiver )[RELIABLE_ENDPOINT_COUNTER_NUM_FRAGMENTS_INVALID] === fragments_invalid );
    check( ( context.num_processed as number ) === 2 );

    reliable_endpoint_destroy( sender );
    reliable_endpoint_destroy( receiver );
}

// every public function is called at least once by the suite. this test names them all in one place so a new entry point
// cannot be added without being exercised

let test_surface_printf_calls = 0;

function test_surface_printf_function( _text: string ): void
{
    test_surface_printf_calls++;
}

function test_public_api_surface(): void
{
    check( reliable_init() === RELIABLE_OK );

    reliable_set_assert_function( reliable_assert_function );

    reliable_set_printf_function( test_surface_printf_function );
    reliable_log_level( RELIABLE_LOG_LEVEL_NONE );

    const pair = new test_pair_t();
    test_pair_configs( pair );
    test_pair_create( pair, 100.0 );
    const sender = pair.context.sender!;
    const receiver = pair.context.receiver!;

    check( reliable_endpoint_next_packet_sequence( sender ) === 0 );

    const packet = new Uint8Array( 64 );

    reliable_endpoint_send_packet( sender, packet, packet.length );
    reliable_endpoint_send_packet( receiver, packet, packet.length );

    reliable_endpoint_receive_packet( sender, packet, packet.length );

    reliable_endpoint_update( sender, 100.1 );

    const acks = reliable_endpoint_get_acks( sender );
    check( acks != null );
    check( acks.length === 1 );
    reliable_endpoint_clear_acks( sender );
    check( reliable_endpoint_get_acks( sender ).length === 0 );

    reliable_endpoint_rtt( sender );
    reliable_endpoint_rtt_min( sender );
    reliable_endpoint_rtt_max( sender );
    reliable_endpoint_rtt_avg( sender );
    reliable_endpoint_jitter_avg_vs_min_rtt( sender );
    reliable_endpoint_jitter_max_vs_min_rtt( sender );
    reliable_endpoint_jitter_stddev_vs_avg_rtt( sender );
    reliable_endpoint_packet_loss( sender );

    reliable_endpoint_bandwidth( sender );

    check( reliable_endpoint_counters( sender )[RELIABLE_ENDPOINT_COUNTER_NUM_PACKETS_SENT] === 1 );

    reliable_endpoint_reset( sender );
    check( reliable_endpoint_next_packet_sequence( sender ) === 0 );

    const owned = new Uint8Array( 32 );
    reliable_endpoint_free_packet( sender, owned );

    // (reliable_copy_string is C only: see the note where it would be)

    const defaults = test_new_config();
    check( defaults.max_packet_size > 0 );
    check( defaults.rtt_history_size === 512 );

    check( RELIABLE_VERSION_FULL === `${RELIABLE_VERSION_MAJOR}.${RELIABLE_VERSION_MINOR}.${RELIABLE_VERSION_PATCH}` );

    test_pair_destroy( pair );

    reliable_set_printf_function( default_printf_function );

    reliable_term();
    check( reliable_init() === RELIABLE_OK );
}

// ---------------------------------------------------------------
// C# port specific regression tests (cs/reliable/reliable.cs)
// ---------------------------------------------------------------

// the endpoint keeps its own copy of the config (reliable.c: endpoint->config = *config), so changing the caller's
// config after create must not change the endpoint

function test_endpoint_config_copied(): void
{
    const config = test_new_config();
    config.name = "original";
    config.transmit_packet_function = test_transmit_packet_function;
    config.process_packet_function = test_process_packet_function;

    const endpoint = reliable_endpoint_create( config, 0.0 );
    check( endpoint != null );

    config.name = "changed";
    config.max_packet_size = 1;
    config.id = 99n;

    check( endpoint.config.name === "original" );
    check( endpoint.config.max_packet_size === 16 * 1024 );
    check( endpoint.config.id === 0n );

    reliable_endpoint_destroy( endpoint );
}

// C# regression (f0e3be1): a fragment 0 whose embedded packet header is cut short must be rejected without reading past
// packet_bytes

function test_fragment_header_truncated_embedded_header(): void
{
    const pair = new test_pair_t();
    test_pair_configs( pair );
    test_pair_create( pair, 100.0 );
    const receiver = pair.context.receiver!;

    const processed_before = reliable_endpoint_counters( receiver )[RELIABLE_ENDPOINT_COUNTER_NUM_PACKETS_RECEIVED];

    // prefix 0x1E: 16 bit ack and all four ack_bits bytes present, so the embedded header needs 9 bytes

    const full = new Uint8Array( [ 0x01, 0x00, 0x00, 0x00, 0x00, 0x1E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ] );

    let num_sent = 0;
    for ( let packet_bytes = RELIABLE_FRAGMENT_HEADER_BYTES + 1; packet_bytes < RELIABLE_FRAGMENT_HEADER_BYTES + RELIABLE_MAX_PACKET_HEADER_BYTES; ++packet_bytes )
    {
        reliable_endpoint_receive_packet( receiver, test_truncate( full, packet_bytes ), packet_bytes );
        num_sent++;
    }

    // and a regular prefix (0x00) with just the sequence, which needs at least 5 header bytes

    const short_regular = new Uint8Array( [ 0x01, 0x00, 0x00, 0x00, 0x00, 0x00 ] );
    reliable_endpoint_receive_packet( receiver, short_regular, short_regular.length );
    num_sent++;

    const counters = reliable_endpoint_counters( receiver );
    check( counters[RELIABLE_ENDPOINT_COUNTER_NUM_FRAGMENTS_INVALID] === num_sent );
    check( counters[RELIABLE_ENDPOINT_COUNTER_NUM_FRAGMENTS_RECEIVED] === 0 );
    check( counters[RELIABLE_ENDPOINT_COUNTER_NUM_PACKETS_RECEIVED] === processed_before );

    test_pair_destroy( pair );
}

// C# regression (42e6725): fragment 0 must carry a canonically encoded packet header. a non-canonical 9 byte header in a
// single fragment packet used to make store_fragment_data copy fragment_size + 5 bytes into a 9 + fragment_size buffer

let test_non_canonical_num_processed = 0;

function test_non_canonical_process_packet_function( _context: unknown, _id: bigint, _sequence: number, _packet_data: Uint8Array, _packet_bytes: number ): boolean
{
    test_non_canonical_num_processed++;
    return true;
}

function test_fragment_non_canonical_header(): void
{
    const pair = new test_pair_t();
    test_pair_configs( pair );
    pair.receiver_config.process_packet_function = test_non_canonical_process_packet_function;
    test_pair_create( pair, 100.0 );
    const receiver = pair.context.receiver!;

    test_non_canonical_num_processed = 0;

    const fragment_size = pair.receiver_config.fragment_size;

    // sequence 0, ack 0, ack_bits 0xFFFFFFFF written the long way: 16 bit ack and all four ack_bits bytes (each 0xFF)

    const non_canonical_header = new Uint8Array( [ 0x1E, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF ] );
    let packet = new Uint8Array( RELIABLE_FRAGMENT_HEADER_BYTES + non_canonical_header.length + fragment_size );
    packet[0] = 0x01;           // fragment
    packet[1] = 0x00;           // sequence 0
    packet[2] = 0x00;
    packet[3] = 0x00;           // fragment id 0
    packet[4] = 0x00;           // num fragments - 1 = 0
    packet.set( non_canonical_header, RELIABLE_FRAGMENT_HEADER_BYTES );

    reliable_endpoint_receive_packet( receiver, packet, packet.length );

    check( reliable_endpoint_counters( receiver )[RELIABLE_ENDPOINT_COUNTER_NUM_FRAGMENTS_INVALID] === 1 );
    check( reliable_endpoint_counters( receiver )[RELIABLE_ENDPOINT_COUNTER_NUM_FRAGMENTS_RECEIVED] === 0 );
    check( test_non_canonical_num_processed === 0 );

    // the same packet with the canonical header for sequence 1 (prefix bit 5: one byte ack delta, ack_bits all set) is accepted

    const canonical_header = new Uint8Array( RELIABLE_MAX_PACKET_HEADER_BYTES );
    const canonical_header_bytes = reliable_write_packet_header( canonical_header, 1, 1, 0xFFFFFFFF );
    check( canonical_header_bytes === 4 );
    packet = new Uint8Array( RELIABLE_FRAGMENT_HEADER_BYTES + canonical_header_bytes + fragment_size );
    packet[0] = 0x01;
    packet[1] = 0x01;           // sequence 1
    packet[2] = 0x00;
    packet[3] = 0x00;
    packet[4] = 0x00;
    packet.set( canonical_header.subarray( 0, canonical_header_bytes ), RELIABLE_FRAGMENT_HEADER_BYTES );

    reliable_endpoint_receive_packet( receiver, packet, packet.length );

    check( reliable_endpoint_counters( receiver )[RELIABLE_ENDPOINT_COUNTER_NUM_FRAGMENTS_INVALID] === 1 );
    check( reliable_endpoint_counters( receiver )[RELIABLE_ENDPOINT_COUNTER_NUM_FRAGMENTS_RECEIVED] === 1 );
    check( ( test_non_canonical_num_processed as number ) === 1 );

    test_pair_destroy( pair );
}

// C# hardening (no reliable.c equivalent): a packet_bytes that is out of range for the array is dropped, never acted on

function test_receive_invalid_length(): void
{
    const pair = new test_pair_t();
    test_pair_configs( pair );
    test_pair_create( pair, 100.0 );
    const receiver = pair.context.receiver!;

    reliable_endpoint_receive_packet( receiver, new Uint8Array( 0 ), 0 );
    reliable_endpoint_receive_packet( receiver, new Uint8Array( 4 ), 5 );
    reliable_endpoint_receive_packet( receiver, new Uint8Array( 4 ), -1 );

    check( reliable_endpoint_counters( receiver )[RELIABLE_ENDPOINT_COUNTER_NUM_PACKETS_INVALID] === 3 );
    check( reliable_endpoint_counters( receiver )[RELIABLE_ENDPOINT_COUNTER_NUM_PACKETS_RECEIVED] === 0 );

    test_pair_destroy( pair );
}

// C# regression (f65b33b): bandwidth over a window whose samples share a timestamp must stay finite (the old guard divided by zero)

function test_bandwidth_finite(): void
{
    const time = 100.0;

    const pair = new test_pair_t();
    test_pair_configs( pair );
    test_pair_create( pair, time );
    const sender = pair.context.sender!;
    const receiver = pair.context.receiver!;

    let i: number;
    for ( i = 0; i < 200; ++i )
    {
        const packet = new Uint8Array( 32 );
        reliable_endpoint_send_packet( sender, packet, packet.length );
        reliable_endpoint_send_packet( receiver, packet, packet.length );
    }

    for ( i = 0; i < 4; ++i )
    {
        reliable_endpoint_update( sender, time );
        reliable_endpoint_update( receiver, time );

        const bandwidth = reliable_endpoint_bandwidth( sender );
        check( Number.isFinite( bandwidth.sent_bandwidth_kbps ) );
        check( Number.isFinite( bandwidth.received_bandwidth_kbps ) );
        check( Number.isFinite( bandwidth.acked_bandwidth_kbps ) );
        check( Number.isFinite( reliable_endpoint_packet_loss( sender ) ) );
    }

    test_pair_destroy( pair );
}

// C# regression (42e466b): packet loss is the fraction of packets actually sent in the window, not of the window size

function test_packet_loss_num_sent(): void
{
    const time = 100.0;

    const pair = new test_pair_t();
    test_pair_configs( pair );
    test_pair_create( pair, time );
    const sender = pair.context.sender!;
    const receiver = pair.context.receiver!;

    // 200 sends with every odd one dropped. the loss window covers sequences [sequence - 255, sequence - 128], so only
    // sequences 0..71 of it were sent: 36 of them were dropped, which is 50% of the packets sent (28% of the window)

    for ( let i = 0; i < 200; ++i )
    {
        const packet = new Uint8Array( 8 );

        pair.context.drop = ( i % 2 ) !== 0;
        reliable_endpoint_send_packet( sender, packet, packet.length );

        pair.context.drop = false;
        reliable_endpoint_send_packet( receiver, packet, packet.length );

        reliable_endpoint_clear_acks( sender );
        reliable_endpoint_clear_acks( receiver );
    }

    reliable_endpoint_update( sender, time );

    // one smoothing step from 0 toward 50% with the default factor of 0.1

    const packet_loss = reliable_endpoint_packet_loss( sender );
    check( packet_loss > 4.99 && packet_loss < 5.01 );

    test_pair_destroy( pair );
}

// wire conformance: headers and fragments written by this port must match the reference implementation byte for byte.
// the vectors below were generated by cpp/reliable tools/conformance/gen_vectors.c (reliable 1.4.5), as used by the C# port

const test_conformance_seqs = [ 0, 1, 255, 256, 1000, 32768, 65535, 7 ];
const test_conformance_acks = [ 0, 1, 254, 255, 256, 999, 65535, 32760 ];
const test_conformance_bits = [ 0xFFFFFFFF, 0x00000000, 0xFFFFFF00, 0x00FFFFFF, 0xDEADBEEF, 0xFF00FF00, 0x000000FF, 0xFFFF00FF ];

const test_conformance_headers = `
    20000000 3e00000000000000 2200000000 3000000000 3e000000efbeadde 2a0000000000 3c000000000000 2400000000 0000000100 1e0000010000000000
    020000010000 100000010000 1e00000100efbeadde 0a000001000000 1c00000100000000 040000010000 000000fe00 1e0000fe0000000000 020000fe0000
    100000fe0000 1e0000fe00efbeadde 0a0000fe000000 1c0000fe00000000 040000fe0000 000000ff00 1e0000ff0000000000 020000ff0000 100000ff0000
    1e0000ff00efbeadde 0a0000ff000000 1c0000ff00000000 040000ff0000 0000000001 1e0000000100000000 020000000100 100000000100 1e00000001efbeadde
    0a000000010000 1c00000001000000 040000000100 000000e703 1e0000e70300000000 020000e70300 100000e70300 1e0000e703efbeadde 0a0000e7030000
    1c0000e703000000 040000e70300 20000001 3e00000100000000 2200000100 3000000100 3e000001efbeadde 2a0000010000 3c000001000000 2400000100
    000000f87f 1e0000f87f00000000 020000f87f00 100000f87f00 1e0000f87fefbeadde 0a0000f87f0000 1c0000f87f000000 040000f87f00 20010001
    3e01000100000000 2201000100 3001000100 3e010001efbeadde 2a0100010000 3c010001000000 2401000100 20010000 3e01000000000000 2201000000
    3001000000 3e010000efbeadde 2a0100000000 3c010000000000 2401000000 000100fe00 1e0100fe0000000000 020100fe0000 100100fe0000
    1e0100fe00efbeadde 0a0100fe000000 1c0100fe00000000 040100fe0000 000100ff00 1e0100ff0000000000 020100ff0000 100100ff0000 1e0100ff00efbeadde
    0a0100ff000000 1c0100ff00000000 040100ff0000 0001000001 1e0100000100000000 020100000100 100100000100 1e01000001efbeadde 0a010000010000
    1c01000001000000 040100000100 000100e703 1e0100e70300000000 020100e70300 100100e70300 1e0100e703efbeadde 0a0100e7030000 1c0100e703000000
    040100e70300 20010002 3e01000200000000 2201000200 3001000200 3e010002efbeadde 2a0100020000 3c010002000000 2401000200 000100f87f
    1e0100f87f00000000 020100f87f00 100100f87f00 1e0100f87fefbeadde 0a0100f87f0000 1c0100f87f000000 040100f87f00 20ff00ff 3eff00ff00000000
    22ff00ff00 30ff00ff00 3eff00ffefbeadde 2aff00ff0000 3cff00ff000000 24ff00ff00 20ff00fe 3eff00fe00000000 22ff00fe00 30ff00fe00
    3eff00feefbeadde 2aff00fe0000 3cff00fe000000 24ff00fe00 20ff0001 3eff000100000000 22ff000100 30ff000100 3eff0001efbeadde 2aff00010000
    3cff0001000000 24ff000100 20ff0000 3eff000000000000 22ff000000 30ff000000 3eff0000efbeadde 2aff00000000 3cff0000000000 24ff000000
    00ff000001 1eff00000100000000 02ff00000100 10ff00000100 1eff000001efbeadde 0aff0000010000 1cff000001000000 04ff00000100 00ff00e703
    1eff00e70300000000 02ff00e70300 10ff00e70300 1eff00e703efbeadde 0aff00e7030000 1cff00e703000000 04ff00e70300 00ff00ffff 1eff00ffff00000000
    02ff00ffff00 10ff00ffff00 1eff00ffffefbeadde 0aff00ffff0000 1cff00ffff000000 04ff00ffff00 00ff00f87f 1eff00f87f00000000 02ff00f87f00
    10ff00f87f00 1eff00f87fefbeadde 0aff00f87f0000 1cff00f87f000000 04ff00f87f00 0000010000 1e0001000000000000 020001000000 100001000000
    1e00010000efbeadde 0a000100000000 1c00010000000000 040001000000 200001ff 3e0001ff00000000 220001ff00 300001ff00 3e0001ffefbeadde
    2a0001ff0000 3c0001ff000000 240001ff00 20000102 3e00010200000000 2200010200 3000010200 3e000102efbeadde 2a0001020000 3c000102000000
    2400010200 20000101 3e00010100000000 2200010100 3000010100 3e000101efbeadde 2a0001010000 3c000101000000 2400010100 20000100
    3e00010000000000 2200010000 3000010000 3e000100efbeadde 2a0001000000 3c000100000000 2400010000 000001e703 1e0001e70300000000 020001e70300
    100001e70300 1e0001e703efbeadde 0a0001e7030000 1c0001e703000000 040001e70300 000001ffff 1e0001ffff00000000 020001ffff00 100001ffff00
    1e0001ffffefbeadde 0a0001ffff0000 1c0001ffff000000 040001ffff00 000001f87f 1e0001f87f00000000 020001f87f00 100001f87f00 1e0001f87fefbeadde
    0a0001f87f0000 1c0001f87f000000 040001f87f00 00e8030000 1ee803000000000000 02e803000000 10e803000000 1ee8030000efbeadde 0ae80300000000
    1ce8030000000000 04e803000000 00e8030100 1ee803010000000000 02e803010000 10e803010000 1ee8030100efbeadde 0ae80301000000 1ce8030100000000
    04e803010000 00e803fe00 1ee803fe0000000000 02e803fe0000 10e803fe0000 1ee803fe00efbeadde 0ae803fe000000 1ce803fe00000000 04e803fe0000
    00e803ff00 1ee803ff0000000000 02e803ff0000 10e803ff0000 1ee803ff00efbeadde 0ae803ff000000 1ce803ff00000000 04e803ff0000 00e8030001
    1ee803000100000000 02e803000100 10e803000100 1ee8030001efbeadde 0ae80300010000 1ce8030001000000 04e803000100 20e80301 3ee8030100000000
    22e8030100 30e8030100 3ee80301efbeadde 2ae803010000 3ce80301000000 24e8030100 00e803ffff 1ee803ffff00000000 02e803ffff00 10e803ffff00
    1ee803ffffefbeadde 0ae803ffff0000 1ce803ffff000000 04e803ffff00 00e803f87f 1ee803f87f00000000 02e803f87f00 10e803f87f00 1ee803f87fefbeadde
    0ae803f87f0000 1ce803f87f000000 04e803f87f00 0000800000 1e0080000000000000 020080000000 100080000000 1e00800000efbeadde 0a008000000000
    1c00800000000000 040080000000 0000800100 1e0080010000000000 020080010000 100080010000 1e00800100efbeadde 0a008001000000 1c00800100000000
    040080010000 000080fe00 1e0080fe0000000000 020080fe0000 100080fe0000 1e0080fe00efbeadde 0a0080fe000000 1c0080fe00000000 040080fe0000
    000080ff00 1e0080ff0000000000 020080ff0000 100080ff0000 1e0080ff00efbeadde 0a0080ff000000 1c0080ff00000000 040080ff0000 0000800001
    1e0080000100000000 020080000100 100080000100 1e00800001efbeadde 0a008000010000 1c00800001000000 040080000100 000080e703 1e0080e70300000000
    020080e70300 100080e70300 1e0080e703efbeadde 0a0080e7030000 1c0080e703000000 040080e70300 000080ffff 1e0080ffff00000000 020080ffff00
    100080ffff00 1e0080ffffefbeadde 0a0080ffff0000 1c0080ffff000000 040080ffff00 20008008 3e00800800000000 2200800800 3000800800
    3e008008efbeadde 2a0080080000 3c008008000000 2400800800 00ffff0000 1effff000000000000 02ffff000000 10ffff000000 1effff0000efbeadde
    0affff00000000 1cffff0000000000 04ffff000000 00ffff0100 1effff010000000000 02ffff010000 10ffff010000 1effff0100efbeadde 0affff01000000
    1cffff0100000000 04ffff010000 00fffffe00 1efffffe0000000000 02fffffe0000 10fffffe0000 1efffffe00efbeadde 0afffffe000000 1cfffffe00000000
    04fffffe0000 00ffffff00 1effffff0000000000 02ffffff0000 10ffffff0000 1effffff00efbeadde 0affffff000000 1cffffff00000000 04ffffff0000
    00ffff0001 1effff000100000000 02ffff000100 10ffff000100 1effff0001efbeadde 0affff00010000 1cffff0001000000 04ffff000100 00ffffe703
    1effffe70300000000 02ffffe70300 10ffffe70300 1effffe703efbeadde 0affffe7030000 1cffffe703000000 04ffffe70300 20ffff00 3effff0000000000
    22ffff0000 30ffff0000 3effff00efbeadde 2affff000000 3cffff00000000 24ffff0000 00fffff87f 1efffff87f00000000 02fffff87f00 10fffff87f00
    1efffff87fefbeadde 0afffff87f0000 1cfffff87f000000 04fffff87f00 20070007 3e07000700000000 2207000700 3007000700 3e070007efbeadde
    2a0700070000 3c070007000000 2407000700 20070006 3e07000600000000 2207000600 3007000600 3e070006efbeadde 2a0700060000 3c070006000000
    2407000600 000700fe00 1e0700fe0000000000 020700fe0000 100700fe0000 1e0700fe00efbeadde 0a0700fe000000 1c0700fe00000000 040700fe0000
    000700ff00 1e0700ff0000000000 020700ff0000 100700ff0000 1e0700ff00efbeadde 0a0700ff000000 1c0700ff00000000 040700ff0000 0007000001
    1e0700000100000000 020700000100 100700000100 1e07000001efbeadde 0a070000010000 1c07000001000000 040700000100 000700e703 1e0700e70300000000
    020700e70300 100700e70300 1e0700e703efbeadde 0a0700e7030000 1c0700e703000000 040700e70300 20070008 3e07000800000000 2207000800 3007000800
    3e070008efbeadde 2a0700080000 3c070008000000 2407000800 000700f87f 1e0700f87f00000000 020700f87f00 100700f87f00 1e0700f87fefbeadde
    0a0700f87f0000 1c0700f87f000000 040700f87f00
`;

// SHA-256 of the five fragments (concatenated) of a 2200 byte packet (byte i = i * 7) sent with fragment_size 500

const test_conformance_fragments_sha256 = "0ad4c8f62ad15bd0910ef0319b68ff7399685221e970ccb4a2a993afa6807bde";

const test_conformance_fragments: Uint8Array[] = [];

function test_conformance_transmit( _context: unknown, _id: bigint, _sequence: number, packet_data: Uint8Array, packet_bytes: number ): void
{
    test_conformance_fragments.push( packet_data.slice( 0, packet_bytes ) );
}

let test_conformance_ack_receiver: reliable_endpoint_t | null = null;
let test_conformance_deliver_now = false;
let test_conformance_reply: Uint8Array | null = null;

function test_conformance_transmit_a( _context: unknown, _id: bigint, _sequence: number, packet_data: Uint8Array, packet_bytes: number ): void
{
    if ( test_conformance_deliver_now )
        reliable_endpoint_receive_packet( test_conformance_ack_receiver!, packet_data, packet_bytes );
}

function test_conformance_transmit_b( _context: unknown, _id: bigint, _sequence: number, packet_data: Uint8Array, packet_bytes: number ): void
{
    test_conformance_reply = packet_data.slice( 0, packet_bytes );
}

function test_conformance_ack_vector( num_sends: number, deliver_index: number[], expected_header: string, expected_acks: number[] ): void
{
    const config_a = test_new_config();
    config_a.transmit_packet_function = test_conformance_transmit_a;
    config_a.process_packet_function = test_process_packet_function;

    const config_b = test_new_config();
    config_b.transmit_packet_function = test_conformance_transmit_b;
    config_b.process_packet_function = test_process_packet_function;

    const a = reliable_endpoint_create( config_a, 0.0 );
    const b = reliable_endpoint_create( config_b, 0.0 );
    check( a != null && b != null );

    test_conformance_ack_receiver = b;
    test_conformance_reply = null;

    const deliver = new Set<number>( deliver_index );

    const payload = new Uint8Array( [ 1, 2, 3, 4, 5, 6, 7, 8 ] );

    for ( let i = 0; i < num_sends; i++ )
    {
        test_conformance_deliver_now = deliver.has( i );
        reliable_endpoint_send_packet( a, payload, payload.length );
    }
    test_conformance_deliver_now = false;

    reliable_endpoint_send_packet( b, payload, payload.length );
    const reply = test_conformance_reply as Uint8Array | null;
    check( reply !== null );
    check( test_hex( reply ) === expected_header );

    reliable_endpoint_receive_packet( a, reply, reply.length );

    const acks = reliable_endpoint_get_acks( a );
    check( acks.length === expected_acks.length );
    for ( let i = 0; i < acks.length; i++ )
        check( acks[i] === expected_acks[i] );

    reliable_endpoint_destroy( a );
    reliable_endpoint_destroy( b );
    test_conformance_ack_receiver = null;
}

function test_wire_conformance(): void
{
    // the SHA-256 below is checked against its own known answer first, so a mismatch further down is the wire, not the hash

    check( test_hex( test_sha256( new Uint8Array( [ 0x61, 0x62, 0x63 ] ) ) ) === "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" );

    // packet headers across the interesting corners of the elision rules

    const expected = test_conformance_headers.split( /\s+/ ).filter( ( x ) => x.length > 0 );
    check( expected.length === 512 );

    const buffer = new Uint8Array( RELIABLE_MAX_PACKET_HEADER_BYTES );
    const read = new reliable_packet_header_t();
    let index = 0;
    for ( let a = 0; a < 8; a++ )
        for ( let b = 0; b < 8; b++ )
            for ( let c = 0; c < 8; c++ )
            {
                const n = reliable_write_packet_header( buffer, test_conformance_seqs[a], test_conformance_acks[b], test_conformance_bits[c] );
                check( test_hex( buffer.subarray( 0, n ) ) === expected[index] );

                // and the reader recovers the same values from the reference bytes
                const reference = test_from_hex( expected[index] );
                const bytes_read = reliable_read_packet_header( "conformance", reference, 0, reference.length, read );
                check( bytes_read === reference.length );
                check( read.sequence === test_conformance_seqs[a] );
                check( read.ack === test_conformance_acks[b] );
                check( read.ack_bits === test_conformance_bits[c] );
                index++;
            }

    // real fragments: a packet well above the fragment threshold

    const config = test_new_config();
    config.fragment_above = 500;
    config.fragment_size = 500;
    config.max_fragments = 16;
    config.max_packet_size = 16 * 500;
    config.transmit_packet_function = test_conformance_transmit;
    config.process_packet_function = test_process_packet_function;
    const endpoint = reliable_endpoint_create( config, 0.0 );
    check( endpoint != null );
    const payload = new Uint8Array( 2200 );
    for ( let i = 0; i < payload.length; i++ )
        payload[i] = ( i * 7 ) & 0xFF;
    test_conformance_fragments.length = 0;
    reliable_endpoint_send_packet( endpoint, payload, payload.length );
    reliable_endpoint_destroy( endpoint );

    check( test_conformance_fragments.length === 5 );
    check( test_conformance_fragments[0].length === 513 );
    check( test_conformance_fragments[4].length === 205 );
    let total_bytes = 0;
    for ( const fragment of test_conformance_fragments )
        total_bytes += fragment.length;
    const all_fragments = new Uint8Array( total_bytes );
    let offset = 0;
    for ( const fragment of test_conformance_fragments )
    {
        all_fragments.set( fragment, offset );
        offset += fragment.length;
    }
    check( test_hex( test_sha256( all_fragments ) ) === test_conformance_fragments_sha256 );

    // stateful acknowledgment vectors

    // a run with no wrap: the delivered set straddles the 32-wide window edge, so sequences 8 and below fall outside it
    test_conformance_ack_vector( 41, [ 8, 9, 20, 40 ], "1e00002800010010800102030405060708", [ 40, 20, 9 ] );

    // a run that crosses 65535 to 0
    test_conformance_ack_vector( 65541, [ 65530, 65531, 65533, 65535, 65536, 65537, 65540 ], "1e00000400b90600000102030405060708", [ 4, 1, 0, 65535, 65533, 65531, 65530 ] );
}

// ---------------------------------------------------------------
// TS port specific tests
// ---------------------------------------------------------------

// a config field that is not a 32 bit integer has no C equivalent, and would pass every range check as a NaN

function test_endpoint_create_non_integer_config(): void
{
    const valid = test_new_config();
    valid.transmit_packet_function = test_transmit_packet_function;
    valid.process_packet_function = test_process_packet_function;

    let config = reliable_config_copy( valid ); config.max_packet_size = NaN;
    check( reliable_endpoint_create( config, 0.0 ) === null );

    config = reliable_config_copy( valid ); config.fragment_size = 1024.5;
    check( reliable_endpoint_create( config, 0.0 ) === null );

    config = reliable_config_copy( valid ); config.ack_buffer_size = 2 ** 40;
    check( reliable_endpoint_create( config, 0.0 ) === null );

    config = reliable_config_copy( valid ); config.rtt_history_size = Infinity;
    check( reliable_endpoint_create( config, 0.0 ) === null );

    // and the one log line names the problem

    const previous_printf_function = printf_function;
    const previous_log_level = log_level;
    test_name_log_line = null;
    test_name_log_calls = 0;
    reliable_set_printf_function( test_name_log_printf_function );
    reliable_log_level( RELIABLE_LOG_LEVEL_ERROR );

    config = reliable_config_copy( valid ); config.max_packet_size = NaN;
    check( reliable_endpoint_create( config, 0.0 ) === null );

    reliable_log_level( previous_log_level );
    reliable_set_printf_function( previous_printf_function );

    check( test_name_log_calls === 1 );
    check( test_name_log_line === "[endpoint] config sizes must be 32 bit integers\n" );
}

// a packet_bytes that is not an integer does not describe bytes the array holds

function test_receive_non_integer_length(): void
{
    const pair = new test_pair_t();
    test_pair_configs( pair );
    test_pair_create( pair, 100.0 );
    const receiver = pair.context.receiver!;

    reliable_endpoint_receive_packet( receiver, new Uint8Array( 8 ), 4.5 );
    reliable_endpoint_receive_packet( receiver, new Uint8Array( 8 ), NaN );

    check( reliable_endpoint_counters( receiver )[RELIABLE_ENDPOINT_COUNTER_NUM_PACKETS_INVALID] === 2 );
    check( reliable_endpoint_counters( receiver )[RELIABLE_ENDPOINT_COUNTER_NUM_PACKETS_RECEIVED] === 0 );

    test_pair_destroy( pair );
}

// sending more bytes than the array holds is a broken caller contract: it asserts instead of putting the previous packet's
// bytes from the scratch buffer on the wire

let test_assert_calls = 0;

function test_assert_function( _condition: string, _function_name: string, _file: string, _line: number ): void
{
    test_assert_calls++;
}

function test_send_packet_bytes_beyond_array(): void
{
    const pair = new test_pair_t();
    test_pair_configs( pair );
    test_pair_create( pair, 100.0 );
    const sender = pair.context.sender!;

    const previous_assert_function = reliable_assert_function;
    reliable_set_assert_function( test_assert_function );
    test_assert_calls = 0;

    let threw = false;
    try
    {
        reliable_endpoint_send_packet( sender, new Uint8Array( 8 ), 16 );
    }
    catch
    {
        threw = true;
    }

    reliable_set_assert_function( previous_assert_function );

    check( threw );
    check( test_assert_calls === 1 );
    check( reliable_endpoint_counters( sender )[RELIABLE_ENDPOINT_COUNTER_NUM_PACKETS_SENT] === 0 );
    check( reliable_endpoint_next_packet_sequence( sender ) === 0 );

    test_pair_destroy( pair );
}

// an allocator that hands back an array smaller than asked for is treated like one that returned null, and the short array
// is handed back to free_function

let test_short_allocations = 0;
let test_short_frees = 0;

function test_short_allocate_function( _context: unknown, bytes: number ): Uint8Array | null
{
    test_short_allocations++;
    return new Uint8Array( bytes - 1 );
}

function test_short_free_function( _context: unknown, _pointer: unknown ): void
{
    test_short_frees++;
}

function test_fragment_reassembly_short_allocation(): void
{
    const pair = new test_pair_t();
    test_pair_configs( pair );
    pair.receiver_config.allocate_function = test_short_allocate_function;
    pair.receiver_config.free_function = test_short_free_function;
    test_pair_create( pair, 100.0 );
    const sender = pair.context.sender!;
    const receiver = pair.context.receiver!;

    test_short_allocations = 0;
    test_short_frees = 0;

    const packet = new Uint8Array( 2048 );
    reliable_endpoint_send_packet( sender, packet, packet.length );

    // both fragments try to start a reassembly, both are refused

    check( test_short_allocations === 2 );
    check( test_short_frees === 2 );
    check( reliable_endpoint_counters( receiver )[RELIABLE_ENDPOINT_COUNTER_NUM_FRAGMENTS_INVALID] === 2 );
    check( reliable_endpoint_counters( receiver )[RELIABLE_ENDPOINT_COUNTER_NUM_FRAGMENTS_RECEIVED] === 0 );
    check( reliable_endpoint_counters( receiver )[RELIABLE_ENDPOINT_COUNTER_NUM_PACKETS_RECEIVED] === 0 );

    test_pair_destroy( pair );
}

// a fragment whose fragment count disagrees with the reassembly in progress is refused. without the check, a forged fragment
// counts toward completion, and the packet is delivered with a real fragment still missing

function test_fragment_count_mismatch(): void
{
    const capture = new test_truncation_context_t();
    test_default_context( capture );

    const sender_config = test_new_config();
    sender_config.fragment_size = 256;
    sender_config.max_fragments = 16;
    sender_config.max_packet_size = 256 * 16;
    sender_config.fragment_above = 256;
    const receiver_config = reliable_config_copy( sender_config );

    sender_config.context = capture;
    sender_config.transmit_packet_function = test_truncation_transmit_packet_function;
    sender_config.process_packet_function = test_process_packet_function;

    const context = new test_fragment_context_t();
    test_default_context( context );
    receiver_config.context = context;
    receiver_config.transmit_packet_function = test_transmit_packet_function;
    receiver_config.process_packet_function = test_fragment_process_packet_function;

    const sender = reliable_endpoint_create( sender_config, 100.0 );
    const receiver = reliable_endpoint_create( receiver_config, 100.0 );
    check( sender != null && receiver != null );

    const packet = new Uint8Array( 1024 );
    for ( let i = 0; i < packet.length; ++i )
        packet[i] = ( i * 13 + 1 ) & 0xFF;
    reliable_endpoint_send_packet( sender, packet, packet.length );
    check( capture.num_captured === 4 );

    // the last fragment re-labelled as fragment 4 of 5: a valid header on its own, but not part of a 4 fragment packet

    const forged = capture.captured[3].slice();
    forged[3] = 4;
    forged[4] = 4;

    reliable_endpoint_receive_packet( receiver, capture.captured[0], capture.captured_bytes[0] );
    reliable_endpoint_receive_packet( receiver, forged, forged.length );
    reliable_endpoint_receive_packet( receiver, capture.captured[1], capture.captured_bytes[1] );
    reliable_endpoint_receive_packet( receiver, capture.captured[2], capture.captured_bytes[2] );

    check( reliable_endpoint_counters( receiver )[RELIABLE_ENDPOINT_COUNTER_NUM_FRAGMENTS_INVALID] === 1 );
    check( context.num_processed === 0 );

    // the real last fragment completes the packet, intact

    reliable_endpoint_receive_packet( receiver, capture.captured[3], capture.captured_bytes[3] );

    check( ( context.num_processed as number ) === 1 );
    check( context.processed_bytes === packet.length );
    check( test_bytes_equal( context.processed.subarray( 0, packet.length ), packet ) );

    reliable_endpoint_destroy( sender );
    reliable_endpoint_destroy( receiver );
}

// logging is formatted only when the level is enabled, and follows the upstream format strings

class test_log_argument_t
{
    conversions: number = 0;
    toString(): string
    {
        this.conversions++;
        return "argument";
    }
}

const test_log_lines: string[] = [];

function test_log_printf_function( text: string ): void
{
    test_log_lines.push( text );
}

function test_log_levels(): void
{
    const previous_printf_function = printf_function;
    const previous_log_level = log_level;

    reliable_set_printf_function( test_log_printf_function );
    test_log_lines.length = 0;

    // filtered: the argument is never converted and the printf function is never called

    const argument = new test_log_argument_t();
    reliable_log_level( RELIABLE_LOG_LEVEL_ERROR );
    reliable_printf( RELIABLE_LOG_LEVEL_DEBUG, "[%s] filtered %d\n", argument, 1 );
    check( argument.conversions === 0 );
    check( test_log_lines.length === 0 );

    // enabled: formatted once

    reliable_printf( RELIABLE_LOG_LEVEL_ERROR, "[%s] shown %d %zu%%\n", argument, 7, 9 );
    check( ( argument.conversions as number ) === 1 );
    check( ( test_log_lines.length as number ) === 1 );
    check( test_log_lines[0] === "[argument] shown 7 9%\n" );

    // a real packet path at debug level

    reliable_log_level( RELIABLE_LOG_LEVEL_DEBUG );

    const pair = new test_pair_t();
    test_pair_configs( pair );
    test_pair_create( pair, 100.0 );

    test_log_lines.length = 0;
    const packet = new Uint8Array( 8 );
    reliable_endpoint_send_packet( pair.context.sender!, packet, packet.length );
    check( ( test_log_lines[0] as string ) === "[sender] sending packet 0\n" );
    check( test_log_lines.indexOf( "[receiver] processing packet 0\n" ) >= 0 );

    test_pair_destroy( pair );

    reliable_log_level( previous_log_level );
    reliable_set_printf_function( previous_printf_function );
}

// ---------------------------------------------------------------
// test helpers
// ---------------------------------------------------------------

function test_bytes_equal( a: Uint8Array, b: Uint8Array ): boolean
{
    if ( a.length !== b.length )
        return false;
    for ( let i = 0; i < a.length; i++ )
    {
        if ( a[i] !== b[i] )
            return false;
    }
    return true;
}

function test_hex( data: Uint8Array ): string
{
    let text = "";
    for ( let i = 0; i < data.length; i++ )
        text += data[i].toString( 16 ).padStart( 2, "0" );
    return text;
}

function test_from_hex( text: string ): Uint8Array
{
    const data = new Uint8Array( text.length >>> 1 );
    for ( let i = 0; i < data.length; i++ )
        data[i] = parseInt( text.substring( i * 2, i * 2 + 2 ), 16 );
    return data;
}

// a small synchronous SHA-256 for the fragment conformance vector (crypto.subtle is async, and the core takes no Node imports)

const test_sha256_k = new Uint32Array( [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
] );

function test_sha256( data: Uint8Array ): Uint8Array
{
    const h = new Uint32Array( [ 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 ] );
    const padded_length = ( ( data.length + 9 + 63 ) >>> 6 ) << 6;
    const padded = new Uint8Array( padded_length );
    padded.set( data );
    padded[data.length] = 0x80;
    const view = new DataView( padded.buffer );
    const bit_length = data.length * 8;
    view.setUint32( padded_length - 8, Math.floor( bit_length / 0x100000000 ) );
    view.setUint32( padded_length - 4, bit_length >>> 0 );
    const w = new Uint32Array( 64 );
    for ( let block = 0; block < padded_length; block += 64 )
    {
        for ( let i = 0; i < 16; i++ )
            w[i] = view.getUint32( block + i * 4 );
        for ( let i = 16; i < 64; i++ )
        {
            const x = w[i - 15];
            const y = w[i - 2];
            const s0 = ( ( x >>> 7 ) | ( x << 25 ) ) ^ ( ( x >>> 18 ) | ( x << 14 ) ) ^ ( x >>> 3 );
            const s1 = ( ( y >>> 17 ) | ( y << 15 ) ) ^ ( ( y >>> 19 ) | ( y << 13 ) ) ^ ( y >>> 10 );
            w[i] = ( w[i - 16] + s0 + w[i - 7] + s1 ) | 0;
        }
        let a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
        for ( let i = 0; i < 64; i++ )
        {
            const S1 = ( ( e >>> 6 ) | ( e << 26 ) ) ^ ( ( e >>> 11 ) | ( e << 21 ) ) ^ ( ( e >>> 25 ) | ( e << 7 ) );
            const ch = ( e & f ) ^ ( ~e & g );
            const t1 = ( hh + S1 + ch + test_sha256_k[i] + w[i] ) | 0;
            const S0 = ( ( a >>> 2 ) | ( a << 30 ) ) ^ ( ( a >>> 13 ) | ( a << 19 ) ) ^ ( ( a >>> 22 ) | ( a << 10 ) );
            const maj = ( a & b ) ^ ( a & c ) ^ ( b & c );
            const t2 = ( S0 + maj ) | 0;
            hh = g;
            g = f;
            f = e;
            e = ( d + t1 ) | 0;
            d = c;
            c = b;
            b = a;
            a = ( t1 + t2 ) | 0;
        }
        h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
    }
    const digest = new Uint8Array( 32 );
    const digest_view = new DataView( digest.buffer );
    for ( let i = 0; i < 8; i++ )
        digest_view.setUint32( i * 4, h[i] );
    return digest;
}

function RUN_TEST( name: string, test_function: () => void ): void
{
    console.log( name );
    test_function();
}

// runs every test. throws on the first failed check. skipped from reliable.c, because they need C allocators or NUL
// terminated strings: test_endpoint_create_allocation_failure (create's storage is runtime allocated, never through
// allocate_function, so there is no partial-create unwind to fail), test_endpoint_name_terminated (a TS string has no
// terminator to force), and the reliable_checked_size / reliable_copy_string checks inside
// test_endpoint_create_invalid_config / test_public_api_surface (size_t arithmetic and char arrays)

export function reliable_test(): void
{
    RUN_TEST( "test_endian", test_endian );
    RUN_TEST( "test_sequence_buffer", test_sequence_buffer );
    RUN_TEST( "test_generate_ack_bits", test_generate_ack_bits );
    RUN_TEST( "test_packet_header", test_packet_header );
    RUN_TEST( "test_acks", test_acks );
    RUN_TEST( "test_acks_packet_loss", test_acks_packet_loss );
    RUN_TEST( "test_duplicate_packets", test_duplicate_packets );
    RUN_TEST( "test_stale_packets", test_stale_packets );
    RUN_TEST( "test_ack_buffer_overflow", test_ack_buffer_overflow );
    RUN_TEST( "test_packets", test_packets );
    RUN_TEST( "test_large_packets", test_large_packets );
    RUN_TEST( "test_sequence_buffer_rollover", test_sequence_buffer_rollover );
    RUN_TEST( "test_fragment_cleanup", test_fragment_cleanup );
    RUN_TEST( "test_fragment_reassembly_alloc_failure", test_fragment_reassembly_alloc_failure );
    RUN_TEST( "test_fragment_reassembly_buffer_zeroed", test_fragment_reassembly_buffer_zeroed );
    RUN_TEST( "test_rtt", test_rtt );
    RUN_TEST( "test_endpoint_reset", test_endpoint_reset );
    RUN_TEST( "test_endpoint_reset_clears_stats", test_endpoint_reset_clears_stats );
    RUN_TEST( "test_rtt_min_large", test_rtt_min_large );
    RUN_TEST( "test_endpoint_create_invalid_config", test_endpoint_create_invalid_config );
    // test_endpoint_create_allocation_failure, test_endpoint_name_terminated: C only (see above)
    RUN_TEST( "test_config_name_bounded_in_rejection_log", test_config_name_bounded_in_rejection_log );
    RUN_TEST( "test_sequence_wrap", test_sequence_wrap );
    RUN_TEST( "test_fragment_counts", test_fragment_counts );
    RUN_TEST( "test_truncated_packets", test_truncated_packets );
    RUN_TEST( "test_public_api_surface", test_public_api_surface );

    // C# port specific
    RUN_TEST( "test_endpoint_config_copied", test_endpoint_config_copied );
    RUN_TEST( "test_fragment_header_truncated_embedded_header", test_fragment_header_truncated_embedded_header );
    RUN_TEST( "test_fragment_non_canonical_header", test_fragment_non_canonical_header );
    RUN_TEST( "test_receive_invalid_length", test_receive_invalid_length );
    RUN_TEST( "test_bandwidth_finite", test_bandwidth_finite );
    RUN_TEST( "test_packet_loss_num_sent", test_packet_loss_num_sent );
    RUN_TEST( "test_wire_conformance", test_wire_conformance );

    // TS port specific
    RUN_TEST( "test_endpoint_create_non_integer_config", test_endpoint_create_non_integer_config );
    RUN_TEST( "test_receive_non_integer_length", test_receive_non_integer_length );
    RUN_TEST( "test_send_packet_bytes_beyond_array", test_send_packet_bytes_beyond_array );
    RUN_TEST( "test_fragment_reassembly_short_allocation", test_fragment_reassembly_short_allocation );
    RUN_TEST( "test_fragment_count_mismatch", test_fragment_count_mismatch );
    RUN_TEST( "test_log_levels", test_log_levels );
}
