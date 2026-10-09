/*
    Yojimbo Client/Server Network Library.

    Copyright © 2016 - 2026, Más Bandwidth LLC.

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
    TypeScript port of include/yojimbo_utils.h + source/yojimbo_utils.cpp (yojimbo 1.13.5).

    Port notes:
      - yojimbo_random_int / yojimbo_random_float use the C library's rand() upstream. The port has its own small
        deterministic generator behind yojimbo_srand / yojimbo_rand (RAND_MAX = 2^31 - 1), so the tests and the network
        simulator are reproducible from a seed. It is not the C library's sequence, and it is not cryptographically secure.
      - yojimbo_random_float keeps upstream's float32 arithmetic (Math.fround at each step).
      - yojimbo_random_bytes is cryptographically secure (libsodium randombytes_buf, as netcode_random_bytes upstream).
      - yojimbo_swap has no by-reference form in TypeScript and is not ported; swap with a destructuring assignment.
      - yojimbo_copy_string returns the truncated string: at most dest_size - 1 characters, as upstream copies.
*/

import { randombytes_buf } from '../sodium/sodium.ts';
import { yojimbo_assert } from './yojimbo_platform.ts';

/**
    Get the minimum of two values.
    @returns The minimum of a and b.
 */

export function yojimbo_min<T extends number | bigint>( a: T, b: T ): T
{
    return ( a < b ) ? a : b;
}

/**
    Get the maximum of two values.
    @returns The maximum of a and b.
 */

export function yojimbo_max<T extends number | bigint>( a: T, b: T ): T
{
    return ( a > b ) ? a : b;
}

/**
    Clamp a value.
    @param value The value to be clamped.
    @param a The minimum value.
    @param b The maximum value.
    @returns The clamped value in [a,b].
 */

export function yojimbo_clamp<T extends number | bigint>( value: T, a: T, b: T ): T
{
    if ( value < a )
        return a;
    else if ( value > b )
        return b;
    else
        return value;
}

/**
    Get the absolute value.
    @param value The input value.
    @returns The absolute value.
 */

export function yojimbo_abs<T extends number | bigint>( value: T ): T
{
    return ( value < 0 ) ? ( -value as T ) : value;
}

/**
    Generate cryptographically secure random data.
    @param data The buffer to store the random data.
    @param bytes The number of bytes of random data to generate.
 */

export function yojimbo_random_bytes( data: Uint8Array, bytes: number = data.length ): void
{
    randombytes_buf( data, bytes );
}

// ---------------------------------------------------------------------------------------------

/** The largest value yojimbo_rand returns, like RAND_MAX on glibc and macOS. */
export const RAND_MAX = 0x7FFFFFFF;

let rand_state = 1;

/**
    Seed the pseudo random number generator behind yojimbo_rand, yojimbo_random_int and yojimbo_random_float
    (the network simulator and tests). The C srand equivalent. The initial state is as if seeded with 1.
    @param seed The seed value (uint32).
 */

export function yojimbo_srand( seed: number ): void
{
    rand_state = seed >>> 0;
}

/**
    Pseudo random integer in [0,RAND_MAX]. The C rand equivalent (mulberry32). Not cryptographically secure.
 */

export function yojimbo_rand(): number
{
    rand_state = ( rand_state + 0x6D2B79F5 ) >>> 0;
    let t = rand_state;
    t = Math.imul( t ^ ( t >>> 15 ), t | 1 );
    t ^= t + Math.imul( t ^ ( t >>> 7 ), t | 61 );
    return ( ( t ^ ( t >>> 14 ) ) >>> 0 ) >>> 1;
}

/**
    Generate a random integer between a and b (inclusive).
    IMPORTANT: This is not a cryptographically secure random. It's used only for test functions and in the network simulator.
    @param a The minimum integer value to generate.
    @param b The maximum integer value to generate.
    @returns A pseudo random integer value in [a,b].
 */

export function yojimbo_random_int( a: number, b: number ): number
{
    yojimbo_assert( a < b, "a < b", "yojimbo_random_int" );
    const result = a + yojimbo_rand() % ( b - a + 1 );
    yojimbo_assert( result >= a, "result >= a", "yojimbo_random_int" );
    yojimbo_assert( result <= b, "result <= b", "yojimbo_random_int" );
    return result;
}

/**
    Generate a random float between a and b (float32 arithmetic, as upstream).
    IMPORTANT: This is not a cryptographically secure random. It's used only for test functions and in the network simulator.
    @param a The minimum value to generate.
    @param b The maximum value to generate.
    @returns A pseudo random float value in [a,b].
 */

export function yojimbo_random_float( a: number, b: number ): number
{
    yojimbo_assert( a < b, "a < b", "yojimbo_random_float" );
    const random = Math.fround( Math.fround( yojimbo_rand() ) / Math.fround( RAND_MAX ) );
    const diff = Math.fround( Math.fround( b ) - Math.fround( a ) );
    const r = Math.fround( random * diff );
    return Math.fround( Math.fround( a ) + r );
}

// ---------------------------------------------------------------------------------------------

/**
    Compares two 16 bit sequence numbers and returns true if the first one is greater than the second (considering wrapping).
    IMPORTANT: This is not the same as s1 > s2!
    Greater than is defined specially to handle wrapping sequence numbers.
    If the two sequence numbers are close together, it is as normal, but they are far apart, it is assumed that they have wrapped around.
    Thus, sequence_greater_than( 1, 0 ) returns true, and so does sequence_greater_than( 0, 65535 )!
    Both arguments are truncated to uint16, like the uint16_t parameters upstream.
    @param s1 The first sequence number.
    @param s2 The second sequence number.
    @returns True if the s1 is greater than s2, with sequence number wrapping considered.
 */

export function yojimbo_sequence_greater_than( s1: number, s2: number ): boolean
{
    s1 &= 0xFFFF;
    s2 &= 0xFFFF;
    return ( ( s1 > s2 ) && ( s1 - s2 <= 32768 ) ) ||
           ( ( s1 < s2 ) && ( s2 - s1  > 32768 ) );
}

/**
    Compares two 16 bit sequence numbers and returns true if the first one is less than the second (considering wrapping).
    IMPORTANT: This is not the same as s1 < s2!
    Thus, sequence_less_than( 0, 1 ) returns true, and so does sequence_greater_than( 65535, 0 )!
    @param s1 The first sequence number.
    @param s2 The second sequence number.
    @returns True if the s1 is less than s2, with sequence number wrapping considered.
 */

export function yojimbo_sequence_less_than( s1: number, s2: number ): boolean
{
    return yojimbo_sequence_greater_than( s2, s1 );
}

/**
    Copy a string without being stupid.
    Returns at most dest_size - 1 characters of source, stopping at the first NUL, as upstream copies into a buffer of dest_size bytes.
 */

export function yojimbo_copy_string( source: string, dest_size: number ): string
{
    yojimbo_assert( source != null, "source", "yojimbo_copy_string" );
    yojimbo_assert( dest_size >= 1, "dest_size >= 1", "yojimbo_copy_string" );
    const nul = source.indexOf( "\0" );
    const end = Math.min( nul >= 0 ? nul : source.length, dest_size - 1 );
    return source.substring( 0, end );
}

/**
    Print bytes with a label. Useful for printing out packets, encryption keys, nonce etc.
    @param label The label to print out before the bytes.
    @param data The data to print out.
    @param data_bytes The number of bytes of data to print.
 */

export function yojimbo_print_bytes( label: string, data: Uint8Array, data_bytes: number = data.length ): void
{
    let text = label + ": ";
    for ( let i = 0; i < data_bytes; ++i )
        text += "0x" + data[i].toString( 16 ).padStart( 2, "0" ) + ",";
    text += " (" + data_bytes + " bytes)";
    console.log( text );
}
