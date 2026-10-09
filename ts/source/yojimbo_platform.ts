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
    TypeScript port of include/yojimbo_platform.h + source/yojimbo_platform.cpp (yojimbo 1.13.5).

    Platform seams, kept platform neutral (Node and the browser):

      - yojimbo_time() is performance.now() based: seconds since the first call, monotonic, as a double.
      - yojimbo_sleep() cannot block a JavaScript thread, so it returns a Promise that resolves after the time
        has elapsed: `await yojimbo_sleep( 0.01 )`. A sleep of zero (upstream's "yield") is a zero timer, so the
        event loop runs (and drains the sockets) before it resolves. A loop over real sockets must await it.
      - yojimbo_printf( level, format, ...args ) formats the upstream printf style format strings (%d %i %u %s %x %f
        %.Nf %p %zu %llu %%) only when the level is enabled, then hands the text to the printf function, which by
        default writes to the console. The text keeps upstream's trailing "\n"; the default printf function drops a
        single trailing newline because console.log adds one.
      - yojimbo_assert( condition, text ) is the YOJIMBO_DEBUG assert. Upstream calls the assert function then
        exit(1); here the assert function is called and then an Error is thrown, so a broken programmer contract
        never continues and a test harness can catch it. Asserts can be switched off with
        yojimbo_set_asserts_enabled( false ) for the release build behaviour (YOJIMBO_RELEASE).
        Per upstream, asserts guard programmer contracts only. Wire data is never asserted on.

    yojimbo_log_level, yojimbo_set_printf_function and yojimbo_set_assert_function also forward to netcode and
    reliable, as upstream.
*/

import { reliable_log_level, reliable_set_printf_function, reliable_set_assert_function } from '../reliable/reliable.ts';
import { netcode_log_level, netcode_set_printf_function, netcode_set_assert_function } from '../netcode/netcode.ts';

export const YOJIMBO_LOG_LEVEL_NONE = 0;
export const YOJIMBO_LOG_LEVEL_ERROR = 1;
export const YOJIMBO_LOG_LEVEL_INFO = 2;
export const YOJIMBO_LOG_LEVEL_DEBUG = 3;

/** Logging is on by default, matching upstream's YOJIMBO_ENABLE_LOGGING. */
export const YOJIMBO_ENABLE_LOGGING = true;

export type yojimbo_printf_function_t = ( text: string ) => void;

export type yojimbo_assert_function_t = ( condition: string, function_name: string, file: string, line: number ) => void;

// ---------------------------------------------------------------------------------------------

/**
    Sleep for approximately this number of seconds.
    JavaScript cannot block, so this returns a Promise: `await yojimbo_sleep( time )`.
    @param time number of seconds to sleep for.
 */

export function yojimbo_sleep( time: number ): Promise<void>
{
    // A zero sleep is a timer of zero (clamped to about a millisecond), not setImmediate: while the timer is pending
    // the event loop keeps turning and draining sockets (libuv reads at most 32 datagrams per socket per turn), which a
    // single setImmediate turn does not. A server pumping many clients falls behind its sockets with setImmediate.
    const milliseconds = Math.max( 0, time * 1000 );
    return new Promise<void>( ( resolve ) => { setTimeout( resolve, milliseconds ); } );
}

let time_start = -1;

/**
    Get a high precision time in seconds since the application has started.
    Monotonic (performance.now). The first call returns 0.
    Please store time in doubles so you retain sufficient precision as time increases.
    @returns Time value in seconds.
 */

export function yojimbo_time(): number
{
    const now = globalThis.performance.now();
    if ( time_start < 0 )
    {
        time_start = now;
        return 0.0;
    }
    let current = now;
    if ( current < time_start )
        current = time_start;
    return ( current - time_start ) / 1000.0;
}

// ---------------------------------------------------------------------------------------------

function default_assert_handler( condition: string, function_name: string, file: string, line: number ): void
{
    // We use YOJIMBO_LOG_LEVEL_NONE because it's lower than YOJIMBO_LOG_LEVEL_ERROR, so even if you suppress errors (by setting
    // yojimbo_log_level(YOJIMBO_LOG_LEVEL_NONE)), this will still be logged.
    yojimbo_printf( YOJIMBO_LOG_LEVEL_NONE, "assert failed: ( %s ), function %s, file %s, line %d\n", condition, function_name, file, line );
}

function default_printf_function( text: string ): void
{
    console.log( text.endsWith( "\n" ) ? text.slice( 0, -1 ) : text );
}

let log_level = 0;

let printf_function: yojimbo_printf_function_t = default_printf_function;

let assert_function: yojimbo_assert_function_t = default_assert_handler;

let asserts_enabled = true;

/**
    Set the yojimbo log level.
    Valid log levels are: YOJIMBO_LOG_LEVEL_NONE, YOJIMBO_LOG_LEVEL_ERROR, YOJIMBO_LOG_LEVEL_INFO and YOJIMBO_LOG_LEVEL_DEBUG
    @param level The log level to set. Initially set to YOJIMBO_LOG_LEVEL_NONE.
 */

export function yojimbo_log_level( level: number ): void
{
    log_level = level;
    netcode_log_level( level );
    reliable_log_level( level );
}

/** Get the current yojimbo log level. */

export function yojimbo_get_log_level(): number
{
    return log_level;
}

/**
    Call this to set the printf function to use for logging.
    @param fn The printf callback function. It receives fully formatted text.
 */

export function yojimbo_set_printf_function( fn: yojimbo_printf_function_t ): void
{
    yojimbo_assert( fn != null, "function" );
    printf_function = fn;
    netcode_set_printf_function( fn );
    reliable_set_printf_function( fn );
}

/**
    Call this to set the function to call when an assert triggers.
    The assert still throws after the function returns (upstream exits).
    @param fn The assert callback function.
 */

export function yojimbo_set_assert_function( fn: yojimbo_assert_function_t ): void
{
    assert_function = fn;
    netcode_set_assert_function( fn );
    reliable_set_assert_function( fn );
}

/** Get the current assert function (so a test can install its own and restore the previous one). */

export function yojimbo_get_assert_function(): yojimbo_assert_function_t
{
    return assert_function;
}

/**
    Enable or disable yojimbo_assert. Enabled by default: the "debug build" (YOJIMBO_DEBUG).
    Disabled gives the release build behaviour (YOJIMBO_RELEASE), where caller contracts are not checked and API misuse
    degrades gracefully through the error levels instead.
 */

export function yojimbo_set_asserts_enabled( enabled: boolean ): void
{
    asserts_enabled = enabled;
}

/** Are yojimbo asserts enabled? */

export function yojimbo_get_asserts_enabled(): boolean
{
    return asserts_enabled;
}

/**
    Assert function used by yojimbo (the YOJIMBO_DEBUG yojimbo_assert macro).
    On failure calls the assert function, then throws. Does nothing when asserts are disabled.
    @param condition The condition that must hold.
    @param condition_text The condition as text, for the report (upstream's #condition).
    @param function_name The function the assert is in, for the report (upstream's __FUNCTION__).
 */

export function yojimbo_assert( condition: unknown, condition_text: string = "condition", function_name: string = "" ): asserts condition
{
    if ( !condition && asserts_enabled )
    {
        assert_function( condition_text, function_name, "yojimbo", 0 );
        throw new Error( `yojimbo assert failed: ( ${condition_text} )` + ( function_name ? `, function ${function_name}` : "" ) );
    }
}

// ---------------------------------------------------------------------------------------------

/**
    Format a printf style string. Supports the conversions yojimbo's messages use:
    %d %i %u %s %x %X %f %.Nf %p %c and the length modifiers h l ll z (ignored), plus %%.
 */

export function yojimbo_format( format: string, args: readonly unknown[] ): string
{
    let index = 0;
    return format.replace( /%(%|[-+ 0#]*\d*(?:\.(\d+))?(?:hh|h|ll|l|z|j|t)?([diusxXfpc]))/g, ( match: string, spec: string, precision: string | undefined, conversion: string | undefined ): string =>
    {
        if ( spec === "%" )
            return "%";
        const value = args[index++];
        switch ( conversion )
        {
            case "d":
            case "i":
            case "u":
                return typeof value === "bigint" ? value.toString() : String( typeof value === "number" ? Math.trunc( value ) : value );
            case "x":
                return typeof value === "bigint" ? value.toString( 16 ) : ( Number( value ) >>> 0 ).toString( 16 );
            case "X":
                return typeof value === "bigint" ? value.toString( 16 ).toUpperCase() : ( Number( value ) >>> 0 ).toString( 16 ).toUpperCase();
            case "f":
                return Number( value ).toFixed( precision !== undefined ? Number( precision ) : 6 );
            case "c":
                return typeof value === "number" ? String.fromCharCode( value ) : String( value );
            case "p":
                return String( value );
            case "s":
                return String( value );
            default:
                return match;
        }
    } );
}

/**
    Printf function used by yojimbo to emit logs.
    The text is only formatted when the level is enabled, so a filtered call costs a comparison.
    This function internally calls the printf callback set by the user.
    @see yojimbo_set_printf_function
 */

export function yojimbo_printf( level: number, format: string, ...args: unknown[] ): void
{
    if ( !YOJIMBO_ENABLE_LOGGING )
        return;
    if ( level > log_level )
        return;
    printf_function( args.length > 0 ? yojimbo_format( format, args ) : format.replace( /%%/g, "%" ) );
}
