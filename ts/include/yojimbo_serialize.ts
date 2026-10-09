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
    TypeScript port of include/yojimbo_serialize.h (yojimbo 1.13.5).

    serialize_sequence_relative follows the slot API of ts/serialize/serialize.ts (see its header comment):

        C++:  serialize_sequence_relative( stream, messageIds[i-1], messageIds[i] );
        TS:   if ( !serialize_sequence_relative( stream, messageIds[i-1], messageIds, i ) ) return false;

    Serializable replaces upstream's three SerializeInternal( Read/Write/MeasureStream ) virtuals plus the
    YOJIMBO_VIRTUAL_SERIALIZE_FUNCTIONS macro: implement Serialize( stream ) once, with the serialize_* functions, and it
    serves read, write and measure streams. SerializeInternal( stream ) is what the library calls; by default it
    forwards to Serialize (which is all the macro did), and it can still be overridden.
*/

import { BaseStream, serialize_int_relative, type Slot } from '../serialize/serialize.ts';

/** Scratch slot for serialize_sequence_relative_internal (single threaded, never re-entered). */
const relative_scratch = { b: 0 };

/**
    Serialize a sequence number relative to another (read/write/measure). The function form behind the macro.
    The wrap is handled by lifting the second sequence into the next 65536 window when it is below the first, so the
    encoded difference is always positive.
    @param stream The stream object. May be a read, write or measure stream.
    @param sequence1 The first sequence number to serialize relative to (uint16).
    @param obj The object holding the second sequence number.
    @param key The key of the second sequence number (uint16) in obj. Assigned on read.
    @returns True on success, false if the serialize failed. The caller MUST propagate false.
 */

export function serialize_sequence_relative_internal<K extends PropertyKey>( stream: BaseStream, sequence1: number, obj: Slot<K, number>, key: K ): boolean
{
    const slot = obj as unknown as Record<PropertyKey, number>;

    if ( stream.IsWriting )
    {
        const a = sequence1 & 0xFFFF;
        const sequence2 = slot[key] & 0xFFFF;
        relative_scratch.b = sequence2 + ( ( a > sequence2 ) ? 65536 : 0 );
        if ( !serialize_int_relative( stream, a, relative_scratch, 'b' ) )
            return false;
    }
    else
    {
        const a = sequence1 & 0xFFFF;
        relative_scratch.b = 0;
        if ( !serialize_int_relative( stream, a, relative_scratch, 'b' ) )
            return false;
        let b = relative_scratch.b;
        if ( b >= 65536 )
        {
            b -= 65536;
        }
        slot[key] = b & 0xFFFF;
    }

    return true;
}

/**
    Serialize a sequence number relative to another (read/write/measure).
    Returns false on error so the caller can propagate it: `if ( !serialize_sequence_relative( stream, a, obj, 'b' ) ) return false;`.
    This is an important safety measure because packet data comes from the network and may be malicious.
    @param stream The stream object. May be a read, write or measure stream.
    @param sequence1 The first sequence number to serialize relative to.
    @param obj, key The slot holding the second sequence number to be encoded relative to the first.
 */

export function serialize_sequence_relative<K extends PropertyKey>( stream: BaseStream, sequence1: number, obj: Slot<K, number>, key: K ): boolean
{
    return serialize_sequence_relative_internal( stream, sequence1, obj, key );
}

/**
    Interface for an object that knows how to read, write and measure how many bits it would take up in a bit stream.
    Implement Serialize( stream ) once with the serialize_* functions: the same method handles read, write and measure streams.
    See shared.ts for some examples of this.
    @see ReadStream
    @see WriteStream
    @see MeasureStream
 */

export abstract class Serializable
{
    /**
        The unified serialize function (upstream's templated Serialize( Stream & stream )).
        @param stream The read, write or measure stream.
        @returns True on success, false if the serialize failed.
     */

    abstract Serialize( stream: BaseStream ): boolean;

    /**
        Virtual serialize function (read, write and measure). This is what the library calls.
        Defaults to Serialize( stream ), which is what YOJIMBO_VIRTUAL_SERIALIZE_FUNCTIONS generates upstream.
        @param stream The stream to serialize with.
     */

    SerializeInternal( stream: BaseStream ): boolean
    {
        return this.Serialize( stream );
    }
}
