/*
    serialize

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
    If you use this library in a product, please credit
    "serialize - Glenn Fiedler and Rowan Claude" in your product credits. The
    license doesn't require this credit. It's an official request, and honoring
    it is appreciated.
*/

/*
    TypeScript port of cpp/serialize/serialize.h (serialize 1.16.2).

    The wire format is bit-identical to the C++ library: same bit order (values packed LSB
    first into a 64 bit scratch word that is stored little endian, a qword at a time), same
    range encodings, same float32 quantization arithmetic, same read-side refusals and the
    same terminal failure latch.

    ------------------------------------------------------------------------------------------
    THE API PATTERN: slots
    ------------------------------------------------------------------------------------------

    In C++ every serialize_* macro takes its value as an lvalue: on write it reads the value,
    on read it assigns it, and on failure it does `return false` from the enclosing function.
    TypeScript has no by-reference parameters and no macros, so the port spells the lvalue as
    an (object, key) pair -- a "slot" -- and every primitive returns a boolean that the caller
    MUST propagate:

        C++:  serialize_int( stream, sequence, 0, 65535 );
        TS:   if ( !serialize_int( stream, this, 'sequence', 0, 65535 ) ) return false;

    The same call works for write, read and measure streams, exactly like the templated C++
    serialize function. On write and measure the slot is read; on read the slot is assigned
    ONLY when the read succeeds (a refused read leaves the slot exactly as the caller left it,
    as upstream). Slots are allocation free: the object is usually `this`, an array element is
    `( array, index )`, and a typed array works too:

        class TestObject
        {
            a = 0;
            flag = false;
            sequence = 0n;                              // 64 bit wire values are bigint
            numItems = 0;
            items = new Array<number>( MaxItems ).fill( 0 );
            name = '';

            Serialize( stream: BaseStream ): boolean
            {
                if ( !serialize_int( stream, this, 'a', -10, +10 ) ) return false;
                if ( !serialize_bool( stream, this, 'flag' ) ) return false;
                if ( !serialize_uint64( stream, this, 'sequence' ) ) return false;
                if ( !serialize_int( stream, this, 'numItems', 0, MaxItems ) ) return false;
                for ( let i = 0; i < this.numItems; i++ )
                    if ( !serialize_bits( stream, this.items, i, 8 ) ) return false;
                if ( !serialize_string( stream, this, 'name', 64 ) ) return false;
                return true;
            }
        }

    A C++ local becomes a field on a small object declared at the top of the function
    (`const local = { hasData: false };`), which keeps the call site identical in shape.
    `stream.IsWriting` / `stream.IsReading` replace `Stream::IsWriting` / `Stream::IsReading`.

    Value types per slot (README conventions):
        number   serialize_int, serialize_bits (1..32 bits), serialize_uint8/16/32,
                 serialize_float, serialize_double, serialize_compressed_float,
                 serialize_int_relative, serialize_fixed with <= 32 bit storage
        bigint   serialize_int64, serialize_int128, serialize_uint64, serialize_uint128,
                 serialize_bits with a bigint slot (1..64 bits, the 64 bit path),
                 serialize_fixed with 64 and 128 bit storage
        boolean  serialize_bool
        string   serialize_string (UTF-8 on the wire), serialize_wstring (UTF-16 code units)
        bytes    serialize_bytes takes a Uint8Array directly (it is already a reference)

    serialize_bits picks its path from the slot's current type: a number slot is the
    1..32 bit path, a bigint slot is the 1..64 bit path (low dword, then the high remainder).

    The read_* forms take slots like serialize_*; the write_* forms take plain values
    (`write_int( stream, 55, 10, 90 )`), matching how upstream's write macros take rvalues.

    The stream classes' own methods (SerializeInteger, SerializeBits, ...) are the low level
    layer, as upstream ("you don't call methods on this class directly"). They take the value
    to write and return a boolean; the value read (or echoed, on write and measure) is left in
    `stream.value` (number methods) or `stream.value_bigint` (64/128 bit methods).

    Asserts: serialize_assert throws on a failed programmer contract (write side values out of
    range, bad parameters), standing in for upstream's debug asserts. Asserts are never what
    refuses wire data: malformed reads return false and latch the stream. Asserts can be
    switched off with serialize_set_asserts_enabled( false ) for the "release build" behaviour.

    Buffers: the WriteStream buffer size must be a multiple of 8 (qword stores), as upstream.
    The ReadStream does NOT need upstream's 8 bytes of allocation past the data: the reader
    bounds checks its window loads.
*/

// ------------------------------------------------------------------------------------------

export const SERIALIZE_VERSION_MAJOR = 1;
export const SERIALIZE_VERSION_MINOR = 16;
export const SERIALIZE_VERSION_PATCH = 2;
export const SERIALIZE_VERSION = '1.16.2';

/** True when this host is little endian. The wire is little endian regardless: words are stored byte by byte. */
export const SERIALIZE_LITTLE_ENDIAN: boolean = new Uint8Array( new Uint32Array( [ 0x11223344 ] ).buffer )[0] === 0x44;

/** True when this host is big endian. */
export const SERIALIZE_BIG_ENDIAN: boolean = !SERIALIZE_LITTLE_ENDIAN;

let serialize_asserts_on = true;

/**
    Enable or disable serialize_assert. Enabled by default (the "debug build").
    Disabling it gives the release build behaviour, where caller contracts are not checked.
 */
export function serialize_set_asserts_enabled( enabled: boolean ): void
{
    serialize_asserts_on = enabled;
}

/** Are serialize asserts enabled? */
export function serialize_get_asserts_enabled(): boolean
{
    return serialize_asserts_on;
}

/**
    The debug assert. Throws when the condition is false and asserts are enabled.
    Used for programmer contracts only (write side values, parameters), never for wire data.
 */
export function serialize_assert( condition: boolean, message: string = 'condition' ): void
{
    if ( !condition && serialize_asserts_on )
    {
        throw new Error( 'serialize_assert failed: ' + message );
    }
}

const f32 = Math.fround;

const float_scratch = new DataView( new ArrayBuffer( 8 ) );

function float_to_bits( value: number ): number
{
    float_scratch.setFloat32( 0, value, true );
    return float_scratch.getUint32( 0, true );
}

function bits_to_float( bits: number ): number
{
    float_scratch.setUint32( 0, bits >>> 0, true );
    return float_scratch.getFloat32( 0, true );
}

const UINT32_MASK_BIGINT = 0xFFFFFFFFn;

/** number of bits needed to represent a non-negative bigint: floor( log2( x ) ) + 1, and zero for zero */
function bigint_bit_length( x: bigint ): number
{
    let bits = 0;
    while ( x > UINT32_MASK_BIGINT )
    {
        x >>= 32n;
        bits += 32;
    }
    return bits + ( 32 - Math.clz32( Number( x ) ) );
}

// ------------------------------------------------------------------------------------------

/**
    Calculates the population count of an unsigned 32 bit integer.
    The population count is the number of bits in the integer set to 1.
    @param x The input integer value.
    @returns The number of bits set to 1 in the input value.
 */

export function popcount( x: number ): number
{
    x = x >>> 0;
    const a = ( x - ( ( x >>> 1 ) & 0x55555555 ) ) >>> 0;
    const b = ( ( ( a >>> 2 ) & 0x33333333 ) + ( a & 0x33333333 ) ) >>> 0;
    const c = ( ( ( b >>> 4 ) + b ) & 0x0f0f0f0f ) >>> 0;
    const d = ( c + ( c >>> 8 ) ) >>> 0;
    const e = ( d + ( d >>> 16 ) ) >>> 0;
    return e & 0x0000003f;
}

/**
    Calculates the log base 2 of an unsigned 32 bit integer.
    @param x The input integer value.
    @returns The log base 2 of the input.
 */

export function log2( x: number ): number
{
    x = x >>> 0;
    const a = ( x | ( x >>> 1 ) ) >>> 0;
    const b = ( a | ( a >>> 2 ) ) >>> 0;
    const c = ( b | ( b >>> 4 ) ) >>> 0;
    const d = ( c | ( c >>> 8 ) ) >>> 0;
    const e = ( d | ( d >>> 16 ) ) >>> 0;
    const f = e >>> 1;
    return popcount( f );
}

/**
    Calculates the number of bits required to serialize an integer in range [min,max].
    The bounds are taken in the uint32 domain, so int32 bounds (sign extended) work, as upstream.
    @param min The minimum value.
    @param max The maximum value.
    @returns The number of bits required to serialize the integer.
 */

export function bits_required( min: number, max: number ): number
{
    const diff = ( max - min ) >>> 0;
    return ( diff === 0 ) ? 0 : 32 - Math.clz32( diff );
}

/**
    Calculates the number of bits required to serialize a 64 bit integer in range [min,max].
    The subtraction is performed in the unsigned 64 bit domain, so ranges wider than 2^63 work, and signed bounds work too.
    @param min The minimum value.
    @param max The maximum value.
    @returns The number of bits required to serialize the integer in [0,64].
 */

export function bits_required64( min: bigint, max: bigint ): number
{
    return bigint_bit_length( BigInt.asUintN( 64, max - min ) );
}

/**
    Calculates the number of bits required to serialize a 128 bit integer in range [min,max].
    The subtraction is performed in the unsigned 128 bit domain, so ranges wider than 2^127 work.
    @param min The minimum value.
    @param max The maximum value.
    @returns The number of bits required to serialize the integer in [0,128].
 */

export function bits_required128( min: bigint, max: bigint ): number
{
    return bigint_bit_length( BigInt.asUintN( 128, max - min ) );
}

/**
    Does a value fit in a raw bit field of this width?
    The write side range check for serialize_bits and write_bits. A negative value is widened to uint64 (as upstream) and fails.
    @param value The caller's value.
    @param bits The field width in [1,64].
    @returns True if the value fits in that many bits.
 */

export function value_fits_in_bits( value: number | bigint, bits: number ): boolean
{
    if ( bits >= 64 )
        return true;
    if ( typeof value === 'number' )
    {
        if ( !Number.isInteger( value ) || value < 0 )
            return false;
        if ( bits <= 52 )
            return value <= 2 ** bits - 1;
        value = BigInt( value );
    }
    return BigInt.asUintN( 64, value ) <= ( 1n << BigInt( bits ) ) - 1n;
}

/**
    Reverse the order of bytes in a 64 bit integer.
    @param value The input value.
    @returns The input value with the byte order reversed.
 */

export function bswap64( value: bigint ): bigint
{
    value = BigInt.asUintN( 64, value );
    const lo = Number( value & UINT32_MASK_BIGINT );
    const hi = Number( value >> 32n );
    return ( BigInt( bswap32( lo ) ) << 32n ) | BigInt( bswap32( hi ) );
}

/**
    Reverse the order of bytes in a 32 bit integer.
    @param value The input value.
    @returns The input value with the byte order reversed.
 */

export function bswap32( value: number ): number
{
    return ( ( ( value & 0x000000ff ) << 24 ) | ( ( value & 0x0000ff00 ) << 8 ) | ( ( value & 0x00ff0000 ) >>> 8 ) | ( ( value >>> 24 ) & 0xff ) ) >>> 0;
}

/**
    Reverse the order of bytes in a 16 bit integer.
    @param value The input value.
    @returns The input value with the byte order reversed.
 */

export function bswap16( value: number ): number
{
    return ( ( ( value & 0x00ff ) << 8 ) | ( ( value & 0xff00 ) >>> 8 ) ) & 0xffff;
}

/*
    Convert an integer value from local byte order to network byte order, and back.
    IMPORTANT: Because most machines are little endian, serialize defines network byte order to be little endian.
    If this processor is little endian the output is the same as the input. If the processor is big endian, the output is byte swapped.
    These matter only for values reinterpreted through host-order typed array views: the bit packer stores bytes explicitly little endian.
 */

export function host_to_network64( value: bigint ): bigint { return SERIALIZE_BIG_ENDIAN ? bswap64( value ) : BigInt.asUintN( 64, value ); }
export function host_to_network32( value: number ): number { return SERIALIZE_BIG_ENDIAN ? bswap32( value ) : value >>> 0; }
export function host_to_network16( value: number ): number { return SERIALIZE_BIG_ENDIAN ? bswap16( value ) : value & 0xffff; }
export function network_to_host64( value: bigint ): bigint { return SERIALIZE_BIG_ENDIAN ? bswap64( value ) : BigInt.asUintN( 64, value ); }
export function network_to_host32( value: number ): number { return SERIALIZE_BIG_ENDIAN ? bswap32( value ) : value >>> 0; }
export function network_to_host16( value: number ): number { return SERIALIZE_BIG_ENDIAN ? bswap16( value ) : value & 0xffff; }

/**
    Convert a signed integer to an unsigned integer with zig-zag encoding.
    0,-1,+1,-2,+2... becomes 0,1,2,3,4 ...
    @param n The input value (int32).
    @returns The input value converted from signed to unsigned with zig-zag encoding (uint32).
 */

export function signed_to_unsigned( n: number ): number
{
    return ( ( n << 1 ) ^ ( n >> 31 ) ) >>> 0;
}

/**
    Convert an unsigned integer to as signed integer with zig-zag encoding.
    0,1,2,3,4... becomes 0,-1,+1,-2,+2...
    @param n The input value (uint32).
    @returns The input value converted from unsigned to signed with zig-zag encoding (int32).
 */

export function unsigned_to_signed( n: number ): number
{
    return ( ( n >>> 1 ) ^ -( n & 1 ) ) | 0;
}

// ------------------------------------------------------------------------------------------

/**
    Bitpacks unsigned integer values to a buffer.
    Integer bit values are written to a 64 bit scratch value from right to left.
    Once the scratch fills to 64 bits it is flushed to memory as a qword; the handful of bits that spilled past 64 carry over into the next scratch.
    The bit stream is written to memory in little endian order, which is considered network byte order for this library.
    The 64 bit scratch is held as two uint32 halves.
    IMPORTANT: The buffer size must be a multiple of 8 bytes, because words are stored to memory 8 bytes at a time. Bytes past the end of the written data are only ever written as zeros.
    @see BitReader
 */

export class BitWriter
{
    private m_data: Uint8Array | null = null;     ///< The buffer we are writing to. The buffer size is a multiple of 8, so qword stores always stay in bounds.
    private m_scratch_lo = 0;                     ///< The low 32 bits of the 64 bit scratch value where we write bits to (right to left).
    private m_scratch_hi = 0;                     ///< The high 32 bits of the 64 bit scratch value.
    private m_numBits = 0;                        ///< The number of bits in the buffer. This is equivalent to the size of the buffer in bytes multiplied by 8.
    private m_bitsWritten = 0;                    ///< The number of bits written so far.
    private m_wordIndex = 0;                      ///< The current word index. The next word flushed to memory will be at this index in m_data.
    private m_scratchBits = 0;                    ///< The number of valid bits in scratch, in [0,63].

    /**
        Bit writer constructor.
        Creates a bit writer object to write to the specified buffer.
        @param data The buffer to fill with bitpacked data.
        @param bytes The size of the buffer in bytes. Must be a multiple of 8, because the bit writer stores qwords to memory. Defaults to data.length.
     */

    constructor( data?: Uint8Array, bytes?: number )
    {
        if ( data !== undefined )
        {
            this.Initialize( data, bytes ?? data.length );
        }
    }

    Initialize( data: Uint8Array, bytes: number = data.length ): void
    {
        serialize_assert( data != null, 'BitWriter: data' );
        serialize_assert( ( bytes % 8 ) === 0, 'BitWriter: the buffer size must be a multiple of 8' );
        serialize_assert( bytes >= 0 && bytes <= data.length, 'BitWriter: bytes must fit the buffer' );
        this.m_data = data;
        this.m_numBits = bytes * 8;
        this.m_bitsWritten = 0;
        this.m_wordIndex = 0;
        this.m_scratch_lo = 0;
        this.m_scratch_hi = 0;
        this.m_scratchBits = 0;
    }

    private StoreScratchWord(): void
    {
        const data = this.m_data as Uint8Array;
        const offset = this.m_wordIndex * 8;
        const lo = this.m_scratch_lo;
        const hi = this.m_scratch_hi;
        data[offset]     = lo;
        data[offset + 1] = lo >>> 8;
        data[offset + 2] = lo >>> 16;
        data[offset + 3] = lo >>> 24;
        data[offset + 4] = hi;
        data[offset + 5] = hi >>> 8;
        data[offset + 6] = hi >>> 16;
        data[offset + 7] = hi >>> 24;
    }

    /**
        Write bits to the buffer.
        Bits are written to the buffer as-is, without padding to nearest byte. Will assert if you try to write past the end of the buffer.
        IMPORTANT: When you have finished writing to your buffer, take care to call BitWriter.FlushBits, otherwise the last word of data will not get flushed to memory!
        @param value The integer value to write to the buffer. Must be in [0,(1<<bits)-1].
        @param bits The number of bits to encode in [1,32].
        @see BitReader.ReadBits
     */

    WriteBits( value: number, bits: number ): void
    {
        serialize_assert( this.m_data !== null, 'BitWriter.WriteBits: used before Initialize' );
        serialize_assert( bits > 0, 'BitWriter.WriteBits: bits > 0' );
        serialize_assert( bits <= 32, 'BitWriter.WriteBits: bits <= 32' );
        serialize_assert( this.m_bitsWritten + bits <= this.m_numBits, 'BitWriter.WriteBits: write past the end of the buffer' );
        serialize_assert( value_fits_in_bits( value, bits ), 'BitWriter.WriteBits: value must be in [0,(1<<bits)-1]' );

        value = value >>> 0;

        const scratchBits = this.m_scratchBits;

        // m_scratch |= uint64_t( value ) << m_scratchBits
        if ( scratchBits < 32 )
        {
            this.m_scratch_lo = ( this.m_scratch_lo | ( value << scratchBits ) ) >>> 0;
            if ( scratchBits > 0 )
            {
                this.m_scratch_hi = ( this.m_scratch_hi | ( value >>> ( 32 - scratchBits ) ) ) >>> 0;
            }
        }
        else
        {
            this.m_scratch_hi = ( this.m_scratch_hi | ( value << ( scratchBits - 32 ) ) ) >>> 0;
        }

        const newScratchBits = scratchBits + bits;

        if ( newScratchBits >= 64 )
        {
            this.StoreScratchWord();
            this.m_wordIndex++;
            // recover the bits that spilled past 64. newScratchBits >= 64 with bits <= 32 implies the shift is in [1,32]
            const shift = 64 - scratchBits;
            this.m_scratch_lo = ( shift >= 32 ) ? 0 : ( value >>> shift );
            this.m_scratch_hi = 0;
            this.m_scratchBits = newScratchBits - 64;
        }
        else
        {
            this.m_scratchBits = newScratchBits;
        }

        this.m_bitsWritten += bits;
    }

    /**
        Write an alignment to the bit stream, padding zeros so the bit index becomes is a multiple of 8.
        IMPORTANT: If the current bit index is already a multiple of 8, nothing is written.
        @see BitReader.ReadAlign
     */

    WriteAlign(): void
    {
        const remainderBits = this.m_bitsWritten % 8;

        if ( remainderBits !== 0 )
        {
            this.WriteBits( 0, 8 - remainderBits );
            serialize_assert( ( this.m_bitsWritten % 8 ) === 0, 'BitWriter.WriteAlign' );
        }
    }

    /**
        Write an array of bytes to the bit stream.
        The body is fused as upstream: one qword store flushes the partial scratch word (its high bytes are zero and the payload overwrites them), one bulk copy lands the whole payload at the byte cursor, and one qword load reloads the trailing partial word into the scratch, masked to its tail bits.
        @param data The byte array data to write to the bit stream.
        @param bytes The number of bytes to write.
        @see BitReader.ReadBytes
     */

    WriteBytes( data: Uint8Array, bytes: number ): void
    {
        serialize_assert( this.m_data !== null, 'BitWriter.WriteBytes: used before Initialize' );
        serialize_assert( this.m_bitsWritten + bytes * 8 <= this.m_numBits, 'BitWriter.WriteBytes: write past the end of the buffer' );
        serialize_assert( ( this.m_bitsWritten % 8 ) === 0, 'BitWriter.WriteBytes: byte aligned' );
        serialize_assert( this.m_scratchBits === this.m_bitsWritten % 64, 'BitWriter.WriteBytes: scratch tracks the cursor' );
        serialize_assert( data.length >= bytes, 'BitWriter.WriteBytes: data.length >= bytes' );

        const buffer = this.m_data as Uint8Array;

        // the head: one word store. the partial scratch word goes to the buffer whole -- its low
        // scratchBits are the bytes already written, its high bytes are zero, and the payload copy
        // below overwrites exactly those zero bytes.
        if ( this.m_scratchBits !== 0 )
        {
            this.StoreScratchWord();
        }

        // the body: the whole payload, straight in at the byte cursor
        if ( bytes > 0 )
        {
            buffer.set( bytes === data.length ? data : data.subarray( 0, bytes ), this.m_bitsWritten / 8 );
        }

        this.m_bitsWritten += bytes * 8;
        this.m_wordIndex = Math.floor( this.m_bitsWritten / 64 );

        // the tail: reload the trailing partial word into the scratch, masked to its tail bits
        const tailBits = this.m_bitsWritten % 64;
        if ( tailBits !== 0 )
        {
            const offset = this.m_wordIndex * 8;
            const lo = ( buffer[offset] | ( buffer[offset + 1] << 8 ) | ( buffer[offset + 2] << 16 ) | ( buffer[offset + 3] << 24 ) ) >>> 0;
            const hi = ( buffer[offset + 4] | ( buffer[offset + 5] << 8 ) | ( buffer[offset + 6] << 16 ) | ( buffer[offset + 7] << 24 ) ) >>> 0;
            if ( tailBits < 32 )
            {
                this.m_scratch_lo = ( lo & ( ( 1 << tailBits ) - 1 ) ) >>> 0;
                this.m_scratch_hi = 0;
            }
            else if ( tailBits === 32 )
            {
                this.m_scratch_lo = lo;
                this.m_scratch_hi = 0;
            }
            else
            {
                this.m_scratch_lo = lo;
                this.m_scratch_hi = ( hi & ( ( 1 << ( tailBits - 32 ) ) - 1 ) ) >>> 0;
            }
        }
        else
        {
            this.m_scratch_lo = 0;
            this.m_scratch_hi = 0;
        }
        this.m_scratchBits = tailBits;
    }

    /**
        Flush any remaining bits to memory.
        Call this once after you've finished writing bits to flush the last word of scratch to memory!
        Stores a full qword: the buffer size is a multiple of 8 so this stays in bounds, and bytes past the written data are zeros.
        @see BitWriter.WriteBits
     */

    FlushBits(): void
    {
        if ( this.m_scratchBits !== 0 )
        {
            serialize_assert( this.m_data !== null, 'BitWriter.FlushBits: used before Initialize' );
            serialize_assert( this.m_scratchBits < 64, 'BitWriter.FlushBits' );
            this.StoreScratchWord();
            this.m_scratch_lo = 0;
            this.m_scratch_hi = 0;
            this.m_scratchBits = 0;
            this.m_wordIndex++;
        }
    }

    /**
        How many align bits would be written, if we were to write an align right now?
        @returns Result in [0,7], where 0 is zero bits required to align (already aligned) and 7 is worst case.
     */

    GetAlignBits(): number
    {
        return ( 8 - ( this.m_bitsWritten % 8 ) ) % 8;
    }

    /** How many bits have we written so far? */

    GetBitsWritten(): number
    {
        return this.m_bitsWritten;
    }

    /** How many bits are still available to write? */

    GetBitsAvailable(): number
    {
        return this.m_numBits - this.m_bitsWritten;
    }

    /** Get the buffer written by the bit writer. Corresponds to the data block passed in to the constructor. */

    GetData(): Uint8Array
    {
        return this.m_data as Uint8Array;
    }

    /**
        The number of bytes flushed to memory.
        This is effectively the size of the packet that you should send after you have finished bitpacking values with this class.
        IMPORTANT: Make sure you call BitWriter.FlushBits before calling this method, otherwise you risk missing the last word of data.
     */

    GetBytesWritten(): number
    {
        return Math.floor( ( this.m_bitsWritten + 7 ) / 8 );
    }
}

/**
    Reads bit packed integer values from a buffer.
    Relies on the user reconstructing the exact same set of bit reads as bit writes when the buffer was written. This is an unattributed bitpacked binary stream!
    Branchless in spirit, as upstream: each read loads a window from the current byte position and shifts by the bit remainder; there is no scratch state.
    Unlike upstream, the window load is bounds checked, so the buffer does NOT need to extend 8 bytes past the data. Bytes past the end are never interpreted.
 */

export class BitReader
{
    private m_data: Uint8Array | null = null;   ///< The bitpacked data we're reading.
    private m_numBits = 0;                      ///< Number of bits to read in the buffer.
    private m_numBytes = 0;                     ///< Number of bytes to read in the buffer.
    private m_bitsRead = 0;                     ///< Number of bits read from the buffer so far. This is the only state the reader carries between reads.

    /**
        Bit reader constructor.
        Any buffer size is supported, as non-multiples of four naturally occur when packets are read from the network.
        @param data The bitpacked data to read.
        @param bytes The number of bytes of bitpacked data to read. Defaults to data.length.
     */

    constructor( data?: Uint8Array, bytes?: number )
    {
        if ( data !== undefined )
        {
            this.Initialize( data, bytes ?? data.length );
        }
    }

    Initialize( data: Uint8Array, bytes: number = data.length ): void
    {
        serialize_assert( data != null, 'BitReader: data' );
        serialize_assert( bytes >= 0 && bytes <= data.length, 'BitReader: bytes must fit the buffer' );
        this.m_data = data;
        this.m_numBytes = bytes;
        this.m_numBits = this.m_numBytes * 8;
        this.m_bitsRead = 0;
    }

    /**
        Would the bit reader would read past the end of the buffer if it read this many bits?
        A reader whose position has been poisoned (see BitReader.PoisonPosition) answers true for every bit count, zero included, which is what makes the failure latch total.
     */

    WouldReadPastEnd( bits: number ): boolean
    {
        return this.m_bitsRead + bits > this.m_numBits;
    }

    /**
        Latch the reader into the failed state.
        The position is poisoned one bit past the end of the buffer, so the past-end check every read already performs refuses every later read. Cleared only by Initialize.
     */

    PoisonPosition(): void
    {
        this.m_bitsRead = this.m_numBits + 1;
    }

    /**
        Read bits from the bit buffer.
        This function will assert if this read would read past the end of the buffer.
        In production situations, the higher level ReadStream takes care of checking all packet data and never calling this function if it would read past the end of the buffer.
        @param bits The number of bits to read in [1,32].
        @returns The integer value read in range [0,(1<<bits)-1].
     */

    ReadBits( bits: number ): number
    {
        serialize_assert( this.m_data !== null, 'BitReader.ReadBits: used before Initialize' );
        serialize_assert( bits > 0, 'BitReader.ReadBits: bits > 0' );
        serialize_assert( bits <= 32, 'BitReader.ReadBits: bits <= 32' );
        serialize_assert( this.m_bitsRead + bits <= this.m_numBits, 'BitReader.ReadBits: read past the end' );

        const data = this.m_data as Uint8Array;
        const shift = this.m_bitsRead & 7;
        const index = ( this.m_bitsRead - shift ) / 8;

        // a 40 bit window from the current byte: shift <= 7 plus bits <= 32 never needs more
        let lo: number;
        let hi: number;
        if ( index + 5 <= data.length )
        {
            lo = ( data[index] | ( data[index + 1] << 8 ) | ( data[index + 2] << 16 ) | ( data[index + 3] << 24 ) ) >>> 0;
            hi = data[index + 4];
        }
        else
        {
            const length = data.length;
            lo = ( ( index     < length ? data[index]     : 0 )
                 | ( ( index + 1 < length ? data[index + 1] : 0 ) << 8 )
                 | ( ( index + 2 < length ? data[index + 2] : 0 ) << 16 )
                 | ( ( index + 3 < length ? data[index + 3] : 0 ) << 24 ) ) >>> 0;
            hi = index + 4 < length ? data[index + 4] : 0;
        }

        let output = ( shift === 0 ) ? lo : ( ( lo >>> shift ) | ( hi << ( 32 - shift ) ) ) >>> 0;
        if ( bits < 32 )
        {
            output = ( output & ( ( 1 << bits ) - 1 ) ) >>> 0;
        }

        this.m_bitsRead += bits;

        return output;
    }

    /**
        Read an align.
        Call this on read to correspond to a WriteAlign call when the bitpacked buffer was written.
        As a safety check, we verify that the padding to next byte is zero bits and return false if that's not the case.
        @returns True if we successfully read an align and skipped ahead past zero pad, false otherwise.
     */

    ReadAlign(): boolean
    {
        const remainderBits = this.m_bitsRead % 8;
        if ( remainderBits !== 0 )
        {
            const value = this.ReadBits( 8 - remainderBits );
            serialize_assert( this.m_bitsRead % 8 === 0, 'BitReader.ReadAlign' );
            if ( value !== 0 )
                return false;
        }
        return true;
    }

    /**
        Read bytes from the bitpacked data.
        @see BitWriter.WriteBytes
     */

    ReadBytes( data: Uint8Array, bytes: number ): void
    {
        serialize_assert( this.m_data !== null, 'BitReader.ReadBytes: used before Initialize' );
        serialize_assert( this.GetAlignBits() === 0, 'BitReader.ReadBytes: byte aligned' );
        serialize_assert( this.m_bitsRead + bytes * 8 <= this.m_numBits, 'BitReader.ReadBytes: read past the end' );
        serialize_assert( data.length >= bytes, 'BitReader.ReadBytes: data.length >= bytes' );

        if ( bytes > 0 )
        {
            const start = this.m_bitsRead / 8;
            data.set( ( this.m_data as Uint8Array ).subarray( start, start + bytes ) );
        }

        this.m_bitsRead += bytes * 8;
    }

    /**
        How many align bits would be read, if we were to read an align right now?
        @returns Result in [0,7], where 0 is zero bits required to align (already aligned) and 7 is worst case.
     */

    GetAlignBits(): number
    {
        return ( 8 - this.m_bitsRead % 8 ) % 8;
    }

    /** How many bits have we read so far? */

    GetBitsRead(): number
    {
        return this.m_bitsRead;
    }

    /** How many bits are still available to read? */

    GetBitsRemaining(): number
    {
        return this.m_numBits - this.m_bitsRead;
    }
}

// ------------------------------------------------------------------------------------------

/**
    Functionality common to all stream classes.
    The Serialize* methods are the low level layer: they take the value to write (ignored on read) and return a boolean.
    The value read -- or echoed, on write and measure -- is left in `value` (SerializeInteger, SerializeBits) or `value_bigint` (SerializeInteger64, SerializeInteger128).
 */

export abstract class BaseStream
{
    /** Stream::IsWriting: true for write and measure streams. */
    abstract readonly IsWriting: boolean;

    /** Stream::IsReading: true for read streams. */
    abstract readonly IsReading: boolean;

    /** The result of the last SerializeInteger / SerializeBits call: the value read, or the value written. */
    value = 0;

    /** The result of the last SerializeInteger64 / SerializeInteger128 call: the value read, or the value written. */
    value_bigint = 0n;

    private m_context: unknown = null;              ///< The context set on the stream. May be null.
    private m_allocator: unknown = null;            ///< The allocator set on the stream. May be null.

    /**
        Set a context on the stream.
        The context lets you pass data through to your serialize functions, for example lookup tables or min/max ranges needed to read and write values.
     */

    SetContext( context: unknown ): void
    {
        this.m_context = context;
    }

    /** Get the context set on the stream. May be null. */

    GetContext(): unknown
    {
        return this.m_context;
    }

    /** Set an allocator on the stream, for allocations within serialize functions. */

    SetAllocator( allocator: unknown ): void
    {
        this.m_allocator = allocator;
    }

    /** Get the allocator set on the stream. May be null. */

    GetAllocator(): unknown
    {
        return this.m_allocator;
    }

    abstract SerializeInteger( value: number, min: number, max: number ): boolean;
    abstract SerializeInteger64( value: bigint, min: bigint, max: bigint ): boolean;
    abstract SerializeInteger128( value: bigint, min: bigint, max: bigint ): boolean;
    abstract SerializeBits( value: number, bits: number ): boolean;
    abstract SerializeBytes( data: Uint8Array, bytes: number ): boolean;
    abstract SerializeAlign(): boolean;
    abstract GetAlignBits(): number;
    abstract GetBitsProcessed(): number;
    abstract GetBytesProcessed(): number;
}

/**
    Stream class for writing bitpacked data.
    This class is a wrapper around the bit writer class. Its purpose is to provide unified interface for reading and writing.
    IMPORTANT: Generally, you don't call methods on this class directly. Use the serialize_* functions instead.
    @see BitWriter
 */

export class WriteStream extends BaseStream
{
    readonly IsWriting = true;
    readonly IsReading = false;

    private m_writer = new BitWriter();           ///< The bit writer used for all bitpacked write operations.

    /**
        Write stream constructor.
        @param buffer The buffer to write to.
        @param bytes The number of bytes in the buffer. Must be a multiple of 8, because the bit writer stores qwords to memory. Defaults to buffer.length.
     */

    constructor( buffer?: Uint8Array, bytes?: number )
    {
        super();
        if ( buffer !== undefined )
        {
            this.m_writer.Initialize( buffer, bytes ?? buffer.length );
        }
    }

    Initialize( buffer: Uint8Array, bytes: number = buffer.length ): void
    {
        this.m_writer.Initialize( buffer, bytes );
    }

    /**
        Serialize an integer (write).
        @param value The integer value in [min,max].
        @returns Always returns true. All checking is performed by debug asserts only on write.
     */

    SerializeInteger( value: number, min: number, max: number ): boolean
    {
        serialize_assert( min <= max, 'WriteStream.SerializeInteger: min <= max' );
        serialize_assert( value >= min, 'WriteStream.SerializeInteger: value >= min' );
        serialize_assert( value <= max, 'WriteStream.SerializeInteger: value <= max' );
        this.value = value;
        const bits = bits_required( min, max );
        if ( bits === 0 )
        {
            return true;                // degenerate range: the value IS the range, nothing to send
        }
        // subtract in the unsigned domain
        const unsigned_value = ( value - min ) >>> 0;
        this.m_writer.WriteBits( unsigned_value, bits );
        return true;
    }

    /**
        Serialize a 64 bit integer (write).
        @returns Always returns true. All checking is performed by debug asserts only on write.
     */

    SerializeInteger64( value: bigint, min: bigint, max: bigint ): boolean
    {
        serialize_assert( min <= max, 'WriteStream.SerializeInteger64: min <= max' );
        serialize_assert( value >= min, 'WriteStream.SerializeInteger64: value >= min' );
        serialize_assert( value <= max, 'WriteStream.SerializeInteger64: value <= max' );
        this.value_bigint = value;
        const bits = bits_required64( min, max );
        if ( bits === 0 )
        {
            return true;                // degenerate range: the value IS the range, nothing to send
        }
        // subtract in the unsigned domain
        const unsigned_value = BigInt.asUintN( 64, value - min );
        if ( bits <= 32 )
        {
            this.m_writer.WriteBits( Number( unsigned_value ), bits );
        }
        else
        {
            // low dword first, then the high remainder: same convention as serialize_bits and serialize_uint64
            this.m_writer.WriteBits( Number( unsigned_value & UINT32_MASK_BIGINT ), 32 );
            this.m_writer.WriteBits( Number( unsigned_value >> 32n ), bits - 32 );
        }
        return true;
    }

    /**
        Serialize a 128 bit integer (write).
        @returns Always returns true. All checking is performed by debug asserts only on write.
     */

    SerializeInteger128( value: bigint, min: bigint, max: bigint ): boolean
    {
        serialize_assert( min <= max, 'WriteStream.SerializeInteger128: min <= max' );
        serialize_assert( value >= min, 'WriteStream.SerializeInteger128: value >= min' );
        serialize_assert( value <= max, 'WriteStream.SerializeInteger128: value <= max' );
        this.value_bigint = value;
        const bits = bits_required128( min, max );
        if ( bits === 0 )
        {
            return true;                // degenerate range: the value IS the range, nothing to send
        }
        // subtract in the unsigned domain
        const unsigned_value = BigInt.asUintN( 128, value - min );
        // 32 bit groups, least significant first: the same convention as serialize_bits, serialize_uint64 and the wide fixed point path
        const group0 = Number( unsigned_value & UINT32_MASK_BIGINT );
        const group1 = Number( ( unsigned_value >> 32n ) & UINT32_MASK_BIGINT );
        const group2 = Number( ( unsigned_value >> 64n ) & UINT32_MASK_BIGINT );
        const group3 = Number( ( unsigned_value >> 96n ) & UINT32_MASK_BIGINT );
        if ( bits <= 32 )
        {
            this.m_writer.WriteBits( group0, bits );
        }
        else if ( bits <= 64 )
        {
            this.m_writer.WriteBits( group0, 32 );
            this.m_writer.WriteBits( group1, bits - 32 );
        }
        else if ( bits <= 96 )
        {
            this.m_writer.WriteBits( group0, 32 );
            this.m_writer.WriteBits( group1, 32 );
            this.m_writer.WriteBits( group2, bits - 64 );
        }
        else
        {
            this.m_writer.WriteBits( group0, 32 );
            this.m_writer.WriteBits( group1, 32 );
            this.m_writer.WriteBits( group2, 32 );
            this.m_writer.WriteBits( group3, bits - 96 );
        }
        return true;
    }

    /**
        Serialize a number of bits (write).
        @param value The unsigned integer value to serialize. Must be in range [0,(1<<bits)-1].
        @param bits The number of bits to write in [1,32].
        @returns Always returns true. All checking is performed by debug asserts on write.
     */

    SerializeBits( value: number, bits: number ): boolean
    {
        serialize_assert( bits > 0, 'WriteStream.SerializeBits: bits > 0' );
        serialize_assert( bits <= 32, 'WriteStream.SerializeBits: bits <= 32' );
        this.value = value;
        this.m_writer.WriteBits( value, bits );
        return true;
    }

    /**
        Serialize an array of bytes (write). Aligns first.
        @returns Always returns true. All checking is performed by debug asserts on write.
     */

    SerializeBytes( data: Uint8Array, bytes: number ): boolean
    {
        serialize_assert( data != null, 'WriteStream.SerializeBytes: data' );
        serialize_assert( bytes >= 0, 'WriteStream.SerializeBytes: bytes >= 0' );
        this.SerializeAlign();
        this.m_writer.WriteBytes( data, bytes );
        return true;
    }

    /**
        Serialize an align (write).
        @returns Always returns true.
     */

    SerializeAlign(): boolean
    {
        this.m_writer.WriteAlign();
        return true;
    }

    /** If we were to write an align right now, how many bits would be required? */

    GetAlignBits(): number
    {
        return this.m_writer.GetAlignBits();
    }

    /**
        Flush the stream to memory after you finish writing.
        Always call this after you finish writing and before you call WriteStream.GetData, or you'll potentially truncate the last word of data you wrote.
     */

    Flush(): void
    {
        this.m_writer.FlushBits();
    }

    /** Get the buffer written by the stream. IMPORTANT: Call WriteStream.Flush first! */

    GetData(): Uint8Array
    {
        return this.m_writer.GetData();
    }

    /** How many bytes have been written so far? This is effectively the packet size. */

    GetBytesProcessed(): number
    {
        return this.m_writer.GetBytesWritten();
    }

    /** Get number of bits written so far. */

    GetBitsProcessed(): number
    {
        return this.m_writer.GetBitsWritten();
    }
}

/**
    Stream class for reading bitpacked data.
    This class is a wrapper around the bit reader class. Its purpose is to provide unified interface for reading and writing.
    Failure is terminal: the first refused read latches the stream, and every later read fails until Initialize points it at a new buffer.
    IMPORTANT: Generally, you don't call methods on this class directly. Use the serialize_* functions instead.
    @see BitReader
 */

export class ReadStream extends BaseStream
{
    readonly IsWriting = false;
    readonly IsReading = true;

    private m_reader = new BitReader();           ///< The bit reader used for all bitpacked read operations.

    /**
        Read stream constructor.
        @param buffer The buffer to read from.
        @param bytes The number of bytes of packet data to read. Defaults to buffer.length.
     */

    constructor( buffer?: Uint8Array, bytes?: number )
    {
        super();
        if ( buffer !== undefined )
        {
            this.m_reader.Initialize( buffer, bytes ?? buffer.length );
        }
    }

    /**
        Point the stream at a new buffer.
        This is the re-initialization that clears a failed stream.
     */

    Initialize( buffer: Uint8Array, bytes: number = buffer.length ): void
    {
        this.m_reader.Initialize( buffer, bytes );
    }

    /**
        Refuse the read in progress and latch the stream into the failed state.
        @returns Always false, so a refusing read reads `return this.Fail();`.
     */

    Fail(): boolean
    {
        this.m_reader.PoisonPosition();
        return false;
    }

    /**
        Serialize an integer (read).
        The value read is stored in this.value. It is guaranteed to be in [min,max] if this function succeeds.
        @returns Returns true if the serialize succeeded and the value is in the correct range. False otherwise.
     */

    SerializeInteger( _value: number, min: number, max: number ): boolean
    {
        serialize_assert( min <= max, 'ReadStream.SerializeInteger: min <= max' );
        const bits = bits_required( min, max );
        // the past-end check comes before the degenerate case so a failed stream refuses a zero bit read too
        if ( this.m_reader.WouldReadPastEnd( bits ) )
            return this.Fail();
        if ( bits === 0 )
        {
            this.value = min;           // degenerate range: the value IS the range
            return true;
        }
        const unsigned_value = this.m_reader.ReadBits( bits );
        // the read side range rule: the offset is compared against the span in the unsigned domain
        if ( unsigned_value > ( ( max - min ) >>> 0 ) )
            return this.Fail();
        this.value = min + unsigned_value;
        return true;
    }

    /**
        Serialize a 64 bit integer (read).
        The value read is stored in this.value_bigint. It is guaranteed to be in [min,max] if this function succeeds.
        @returns Returns true if the serialize succeeded and the value is in the correct range. False otherwise.
     */

    SerializeInteger64( _value: bigint, min: bigint, max: bigint ): boolean
    {
        serialize_assert( min <= max, 'ReadStream.SerializeInteger64: min <= max' );
        const bits = bits_required64( min, max );
        // the past-end check comes before the degenerate case so a failed stream refuses a zero bit read too
        if ( this.m_reader.WouldReadPastEnd( bits ) )
            return this.Fail();
        if ( bits === 0 )
        {
            this.value_bigint = min;    // degenerate range: the value IS the range
            return true;
        }
        let unsigned_value: bigint;
        if ( bits <= 32 )
        {
            unsigned_value = BigInt( this.m_reader.ReadBits( bits ) );
        }
        else
        {
            // low dword first, then the high remainder: same convention as serialize_bits and serialize_uint64
            const lo = this.m_reader.ReadBits( 32 );
            const hi = this.m_reader.ReadBits( bits - 32 );
            unsigned_value = ( BigInt( hi ) << 32n ) | BigInt( lo );
        }
        // the read side range rule at this width
        if ( unsigned_value > BigInt.asUintN( 64, max - min ) )
            return this.Fail();
        this.value_bigint = min + unsigned_value;
        return true;
    }

    /**
        Serialize a 128 bit integer (read).
        The value read is stored in this.value_bigint. It is guaranteed to be in [min,max] if this function succeeds.
        @returns Returns true if the serialize succeeded and the value is in the correct range. False otherwise.
     */

    SerializeInteger128( _value: bigint, min: bigint, max: bigint ): boolean
    {
        serialize_assert( min <= max, 'ReadStream.SerializeInteger128: min <= max' );
        const bits = bits_required128( min, max );
        // the past-end check comes before the degenerate case so a failed stream refuses a zero bit read too
        if ( this.m_reader.WouldReadPastEnd( bits ) )
            return this.Fail();
        if ( bits === 0 )
        {
            this.value_bigint = min;    // degenerate range: the value IS the range
            return true;
        }
        // 32 bit groups, least significant first: the same convention as the write path
        let group0 = 0;
        let group1 = 0;
        let group2 = 0;
        let group3 = 0;
        if ( bits <= 32 )
        {
            group0 = this.m_reader.ReadBits( bits );
        }
        else if ( bits <= 64 )
        {
            group0 = this.m_reader.ReadBits( 32 );
            group1 = this.m_reader.ReadBits( bits - 32 );
        }
        else if ( bits <= 96 )
        {
            group0 = this.m_reader.ReadBits( 32 );
            group1 = this.m_reader.ReadBits( 32 );
            group2 = this.m_reader.ReadBits( bits - 64 );
        }
        else
        {
            group0 = this.m_reader.ReadBits( 32 );
            group1 = this.m_reader.ReadBits( 32 );
            group2 = this.m_reader.ReadBits( 32 );
            group3 = this.m_reader.ReadBits( bits - 96 );
        }
        const unsigned_value = ( BigInt( group3 ) << 96n ) | ( BigInt( group2 ) << 64n ) | ( BigInt( group1 ) << 32n ) | BigInt( group0 );
        // the read side range rule at this width
        if ( unsigned_value > BigInt.asUintN( 128, max - min ) )
            return this.Fail();
        this.value_bigint = min + unsigned_value;
        return true;
    }

    /**
        Serialize a number of bits (read).
        The value read is stored in this.value, in range [0,(1<<bits)-1].
        @param bits The number of bits to read in [1,32].
        @returns Returns true if the serialize read succeeded, false otherwise.
     */

    SerializeBits( _value: number, bits: number ): boolean
    {
        serialize_assert( bits > 0, 'ReadStream.SerializeBits: bits > 0' );
        serialize_assert( bits <= 32, 'ReadStream.SerializeBits: bits <= 32' );
        if ( this.m_reader.WouldReadPastEnd( bits ) )
            return this.Fail();
        this.value = this.m_reader.ReadBits( bits );
        return true;
    }

    /**
        Serialize an array of bytes (read). Aligns first.
        IMPORTANT: on a refused read the caller's buffer contents are unspecified.
        @param data The buffer to read into. Must hold at least `bytes` bytes.
        @param bytes The number of bytes to read.
        @returns Returns true if the serialize read succeeded. False otherwise.
     */

    SerializeBytes( data: Uint8Array, bytes: number ): boolean
    {
        if ( bytes < 0 )
            return this.Fail();
        // the align is what refuses on a failed stream: a poisoned position reads past the end at every align width
        if ( !this.SerializeAlign() )
            return false;
        // compare in bytes rather than bits
        if ( bytes > Math.floor( this.m_reader.GetBitsRemaining() / 8 ) )
            return this.Fail();
        this.m_reader.ReadBytes( data, bytes );
        return true;
    }

    /**
        Serialize an align (read).
        @returns Returns true if the serialize read succeeded. False otherwise.
     */

    SerializeAlign(): boolean
    {
        const alignBits = this.m_reader.GetAlignBits();
        if ( this.m_reader.WouldReadPastEnd( alignBits ) )
            return this.Fail();
        if ( !this.m_reader.ReadAlign() )
            return this.Fail();
        return true;
    }

    /** If we were to read an align right now, how many bits would we need to read? */

    GetAlignBits(): number
    {
        return this.m_reader.GetAlignBits();
    }

    /** Get number of bits read so far. */

    GetBitsProcessed(): number
    {
        return this.m_reader.GetBitsRead();
    }

    /** How many bytes have been read so far? The number of bits read, rounded up to the next byte. */

    GetBytesProcessed(): number
    {
        return Math.floor( ( this.m_reader.GetBitsRead() + 7 ) / 8 );
    }
}

/**
    Stream class for estimating how many bits it would take to serialize something.
    This class acts like a bit writer (IsWriting is true, IsReading is false), but instead of writing data, it counts how many bits would be written.
    Note that when the serialization includes alignment to byte (see MeasureStream.SerializeAlign), this is an estimate and not an exact measurement. The estimate is guaranteed to be conservative.
 */

export class MeasureStream extends BaseStream
{
    readonly IsWriting = true;
    readonly IsReading = false;

    private m_bitsWritten = 0;          ///< Counts the number of bits written.

    SerializeInteger( value: number, min: number, max: number ): boolean
    {
        serialize_assert( min <= max, 'MeasureStream.SerializeInteger: min <= max' );
        serialize_assert( value >= min, 'MeasureStream.SerializeInteger: value >= min' );
        serialize_assert( value <= max, 'MeasureStream.SerializeInteger: value <= max' );
        this.value = value;
        this.m_bitsWritten += bits_required( min, max );
        return true;
    }

    SerializeInteger64( value: bigint, min: bigint, max: bigint ): boolean
    {
        serialize_assert( min <= max, 'MeasureStream.SerializeInteger64: min <= max' );
        serialize_assert( value >= min, 'MeasureStream.SerializeInteger64: value >= min' );
        serialize_assert( value <= max, 'MeasureStream.SerializeInteger64: value <= max' );
        this.value_bigint = value;
        this.m_bitsWritten += bits_required64( min, max );
        return true;
    }

    SerializeInteger128( value: bigint, min: bigint, max: bigint ): boolean
    {
        serialize_assert( min <= max, 'MeasureStream.SerializeInteger128: min <= max' );
        serialize_assert( value >= min, 'MeasureStream.SerializeInteger128: value >= min' );
        serialize_assert( value <= max, 'MeasureStream.SerializeInteger128: value <= max' );
        this.value_bigint = value;
        this.m_bitsWritten += bits_required128( min, max );
        return true;
    }

    SerializeBits( value: number, bits: number ): boolean
    {
        serialize_assert( bits > 0, 'MeasureStream.SerializeBits: bits > 0' );
        serialize_assert( bits <= 32, 'MeasureStream.SerializeBits: bits <= 32' );
        this.value = value;
        this.m_bitsWritten += bits;
        return true;
    }

    SerializeBytes( _data: Uint8Array, bytes: number ): boolean
    {
        serialize_assert( bytes >= 0, 'MeasureStream.SerializeBytes: bytes >= 0' );
        this.SerializeAlign();
        this.m_bitsWritten += bytes * 8;
        return true;
    }

    SerializeAlign(): boolean
    {
        this.m_bitsWritten += this.GetAlignBits();
        return true;
    }

    /**
        If we were to write an align right now, how many bits would be required?
        IMPORTANT: Since the number of bits required for alignment depends on where an object is written in the final bit stream, this measurement is conservative.
        @returns Always returns worst case 7 bits.
     */

    GetAlignBits(): number
    {
        return 7;
    }

    /** Get number of bits written so far. */

    GetBitsProcessed(): number
    {
        return this.m_bitsWritten;
    }

    /** How many bytes have been written so far? */

    GetBytesProcessed(): number
    {
        return Math.floor( ( this.m_bitsWritten + 7 ) / 8 );
    }
}

// ------------------------------------------------------------------------------------------

/**
    A slot: the TypeScript spelling of a C++ lvalue, as an ( object, key ) pair.
    `Slot<'x', number>` is any object with a number property `x`; a numeric key is any array-like of T.
 */

export type Slot<K extends PropertyKey, T> = K extends number ? { [index: number]: T } : { [P in K]: T };

type AnySlot<T> = Record<PropertyKey, T>;

/** Anything with a Serialize( stream ) method, for serialize_object. */

export interface Serializable
{
    Serialize( stream: BaseStream ): boolean;
}

/**
    Refuse the read in progress on this stream.
    Some refusals are decided outside the stream (a malformed string payload, an int_relative reconstruction outside the domain); those still latch a read stream. Write and measure streams never refuse.
    @returns Always false, so a refusing read reads `return serialize_fail( stream );`.
 */

export function serialize_fail( stream: BaseStream ): boolean
{
    if ( stream instanceof ReadStream )
    {
        return stream.Fail();
    }
    return false;
}

/**
    Serialize integer value (read/write/measure).
    min <= max is the legal relation. A degenerate range where min == max costs zero bits.
    On read, a refused read leaves the slot exactly as the caller left it, and fails the stream.
    @param stream The stream object. May be a read, write or measure stream.
    @param obj, key The slot holding the integer value to serialize in [min,max].
    @param min The minimum value.
    @param max The maximum value.
 */

export function serialize_int<K extends PropertyKey>( stream: BaseStream, obj: Slot<K, number>, key: K, min: number, max: number ): boolean
{
    serialize_assert( min <= max, 'serialize_int: min <= max' );
    const slot = obj as unknown as AnySlot<number>;
    let int32_value = 0;
    if ( stream.IsWriting )
    {
        int32_value = slot[key];
        serialize_assert( int32_value >= min, 'serialize_int: value >= min' );
        serialize_assert( int32_value <= max, 'serialize_int: value <= max' );
    }
    if ( !stream.SerializeInteger( int32_value, min, max ) )
    {
        return false;
    }
    if ( stream.IsReading )
    {
        slot[key] = stream.value;
    }
    return true;
}

/**
    Serialize a 64 bit integer value (read/write/measure).
    The full 64 bit range is supported, and the minimal number of bits for [min,max] is used on the wire.
    @param obj, key The slot holding the bigint value to serialize in [min,max].
 */

export function serialize_int64<K extends PropertyKey>( stream: BaseStream, obj: Slot<K, bigint>, key: K, min: bigint, max: bigint ): boolean
{
    serialize_assert( min <= max, 'serialize_int64: min <= max' );
    const slot = obj as unknown as AnySlot<bigint>;
    let int64_value = 0n;
    if ( stream.IsWriting )
    {
        int64_value = slot[key];
        serialize_assert( int64_value >= min, 'serialize_int64: value >= min' );
        serialize_assert( int64_value <= max, 'serialize_int64: value <= max' );
    }
    if ( !stream.SerializeInteger64( int64_value, min, max ) )
    {
        return false;
    }
    if ( stream.IsReading )
    {
        slot[key] = stream.value_bigint;
    }
    return true;
}

/**
    Serialize a ranged 128 bit integer to the stream (read/write/measure).
    Where the range fits 64 bits or fewer the bytes are identical to serialize_int64 over the same bounds.
    Do not confuse this with serialize_uint128, which is not ranged: it is a raw 128 bit field.
    @param obj, key The slot holding the bigint value to serialize in [min,max].
 */

export function serialize_int128<K extends PropertyKey>( stream: BaseStream, obj: Slot<K, bigint>, key: K, min: bigint, max: bigint ): boolean
{
    serialize_assert( min <= max, 'serialize_int128: min <= max' );
    const slot = obj as unknown as AnySlot<bigint>;
    let int128_value = 0n;
    if ( stream.IsWriting )
    {
        int128_value = slot[key];
        serialize_assert( int128_value >= min, 'serialize_int128: value >= min' );
        serialize_assert( int128_value <= max, 'serialize_int128: value <= max' );
    }
    if ( !stream.SerializeInteger128( int128_value, min, max ) )
    {
        return false;
    }
    if ( stream.IsReading )
    {
        slot[key] = stream.value_bigint;
    }
    return true;
}

/**
    Serialize bits to the stream (read/write/measure).
    A number slot serializes 1..32 bits. A bigint slot serializes 1..64 bits: up to 32 bits it is one group, above that the low dword first, then the high remainder.
    @param obj, key The slot holding the unsigned value. Must be in [0,(1<<bits)-1].
    @param bits The number of bits to serialize.
 */

export function serialize_bits<K extends PropertyKey>( stream: BaseStream, obj: Slot<K, number>, key: K, bits: number ): boolean;
export function serialize_bits<K extends PropertyKey>( stream: BaseStream, obj: Slot<K, bigint>, key: K, bits: number ): boolean;
export function serialize_bits( stream: BaseStream, obj: unknown, key: PropertyKey, bits: number ): boolean
{
    serialize_assert( bits > 0, 'serialize_bits: bits > 0' );
    serialize_assert( bits <= 64, 'serialize_bits: bits <= 64' );
    const slot = obj as AnySlot<number | bigint>;
    const current = slot[key];
    if ( typeof current !== 'bigint' )
    {
        serialize_assert( bits <= 32, 'serialize_bits: a number slot carries at most 32 bits. use a bigint slot for wider values' );
        let uint32_value = 0;
        if ( stream.IsWriting )
        {
            uint32_value = current;
            serialize_assert( value_fits_in_bits( uint32_value, bits ), 'serialize_bits: value fits in bits' );
        }
        if ( !stream.SerializeBits( uint32_value, bits ) )
        {
            return false;
        }
        if ( stream.IsReading )
        {
            slot[key] = stream.value;
        }
        return true;
    }
    serialize_assert( !stream.IsWriting || value_fits_in_bits( current, bits ), 'serialize_bits: value fits in bits' );
    if ( bits <= 32 )
    {
        let uint32_value = 0;
        if ( stream.IsWriting )
        {
            uint32_value = Number( BigInt.asUintN( 32, current ) );
        }
        if ( !stream.SerializeBits( uint32_value, bits ) )
        {
            return false;
        }
        if ( stream.IsReading )
        {
            slot[key] = BigInt( stream.value );
        }
    }
    else
    {
        let hi = 0;
        let lo = 0;
        if ( stream.IsWriting )
        {
            const uint64_value = BigInt.asUintN( 64, current );
            lo = Number( uint64_value & UINT32_MASK_BIGINT );
            hi = Number( uint64_value >> 32n );
        }
        if ( !stream.SerializeBits( lo, 32 ) )
        {
            return false;
        }
        lo = stream.value;
        if ( !stream.SerializeBits( hi, bits - 32 ) )
        {
            return false;
        }
        hi = stream.value;
        if ( stream.IsReading )
        {
            slot[key] = ( BigInt( hi ) << 32n ) | BigInt( lo );
        }
    }
    return true;
}

/**
    Serialize a boolean value to the stream (read/write/measure). One bit.
    @param obj, key The slot holding the boolean value.
 */

export function serialize_bool<K extends PropertyKey>( stream: BaseStream, obj: Slot<K, boolean>, key: K ): boolean
{
    const slot = obj as unknown as AnySlot<boolean>;
    let uint32_bool_value = 0;
    if ( stream.IsWriting )
    {
        uint32_bool_value = slot[key] ? 1 : 0;
    }
    if ( !stream.SerializeBits( uint32_bool_value, 1 ) )
    {
        return false;
    }
    if ( stream.IsReading )
    {
        slot[key] = stream.value !== 0;
    }
    return true;
}

/**
    Serialize floating point value (read/write/measure).
    The value is a float32 on the wire: 32 bits, the IEEE 754 bit pattern. On write the number is rounded to float32.
    NOTE: a float32 signaling NaN cannot survive conversion to a JavaScript number (the engine quiets it), so it reads back as the quiet NaN with the same payload. Every other pattern, quiet NaN payloads included, round trips.
    @param obj, key The slot holding the float value.
 */

export function serialize_float<K extends PropertyKey>( stream: BaseStream, obj: Slot<K, number>, key: K ): boolean
{
    const slot = obj as unknown as AnySlot<number>;
    let int_value = 0;
    if ( stream.IsWriting )
    {
        int_value = float_to_bits( slot[key] );
    }
    if ( !stream.SerializeBits( int_value, 32 ) )
    {
        return false;                   // a refused read leaves value exactly as the caller left it
    }
    if ( stream.IsReading )
    {
        slot[key] = bits_to_float( stream.value );
    }
    return true;
}

/**
    The compressed float wire constants derived from a (min,max,res) declaration.
    @see serialize_compressed_float_params
 */

export class CompressedFloatParams
{
    max_integer_value = 0;          ///< The quantization step count: ceil( ( max - min ) / res ), clamped to [1,4294967040].
    bits = 0;                       ///< The wire width: bits_required( 0, max_integer_value ), in [1,32].
    delta = 0;                      ///< The range width max - min, computed in float32.
}

/**
    Derive the compressed float wire constants from a (min,max,res) declaration.
    This is the derivation serialize_compressed_float performs on every call, exposed so it can be paid once instead.
    All arithmetic is float32, exactly as upstream: min, max and res are rounded to float32 first, as a C++ float parameter would be.
    A declaration whose delta = max - min, or whose delta / res, is not finite in float32 is non-conforming and asserts.
    @param min The minimum float value. Must be less than max.
    @param max The maximum float value.
    @param res The resolution the float value is quantized to.
    @param params Where to store the result. A new object when omitted.
    @returns params, filled with max_integer_value, bits and delta.
 */

export function serialize_compressed_float_params( min: number, max: number, res: number, params: CompressedFloatParams = new CompressedFloatParams() ): CompressedFloatParams
{
    min = f32( min );
    max = f32( max );
    res = f32( res );

    serialize_assert( min < max && res > 0, 'serialize_compressed_float_params: min < max && res > 0' );

    const delta = f32( max - min );

    let values = f32( delta / res );

    // a declaration whose delta or values is not finite in float32 is non-conforming
    serialize_assert( delta - delta === 0, 'serialize_compressed_float_params: delta is finite in float32' );
    serialize_assert( values - values === 0, 'serialize_compressed_float_params: delta / res is finite in float32' );

    // clamp so the uint32 conversion below is defined even for pathological delta / res (the !>= form also catches NaN)
    if ( !( values >= 1 ) )
    {
        values = 1;
    }
    else if ( values > 4294967040 )         // largest float below 2^32
    {
        values = 4294967040;
    }

    const max_integer_value = Math.ceil( values ) >>> 0;

    params.max_integer_value = max_integer_value;
    params.bits = bits_required( 0, max_integer_value );
    params.delta = delta;
    return params;
}

/**
    Serialize compressed floating point value from precomputed wire constants (read/write/measure).
    The audited home of the compressed float quantization arithmetic, float32 throughout with TWO roundings each way:
    on write the product rounds to float32 before 0.5 is added, on read the product rounds to float32 before min is added.
    On write, the value is clamped into the declared range and quantized; writing a non-finite value is non-conforming and asserts.
    On read, an integer above max_integer_value smuggled into the bit headroom is rejected and the function returns false.
    @param obj, key The slot holding the float value.
    @param max_integer_value The quantization step count, in [1,4294967040].
    @param bits The wire width in bits. Must equal bits_required( 0, max_integer_value ).
    @param delta The range width max - min, in float32.
    @param min The minimum float value of the range.
 */

export function serialize_compressed_float_precomputed<K extends PropertyKey>( stream: BaseStream, obj: Slot<K, number>, key: K, max_integer_value: number, bits: number, delta: number, min: number ): boolean
{
    delta = f32( delta );
    min = f32( min );

    serialize_assert( max_integer_value >= 1, 'serialize_compressed_float_precomputed: max_integer_value >= 1' );
    serialize_assert( bits === bits_required( 0, max_integer_value ), 'serialize_compressed_float_precomputed: bits == bits_required( 0, max_integer_value )' );
    serialize_assert( delta > 0, 'serialize_compressed_float_precomputed: delta > 0' );
    serialize_assert( delta - delta === 0, 'serialize_compressed_float_precomputed: delta is finite' );

    const slot = obj as unknown as AnySlot<number>;

    let integerValue = 0;

    if ( stream.IsWriting )
    {
        const value = f32( slot[key] );

        // writing a non-finite value (NaN, +/-Inf) through compressed_float is non-conforming. the clamp below remains the backstop
        serialize_assert( value - value === 0, 'serialize_compressed_float: the value must be finite' );

        // clamp with the !>= / !<= form so a NaN value is forced into range
        let normalizedValue = f32( f32( value - min ) / delta );
        if ( !( normalizedValue >= 0 ) )
        {
            normalizedValue = 0;
        }
        else if ( !( normalizedValue <= 1 ) )
        {
            normalizedValue = 1;
        }
        // TWO roundings: the product rounds to float32 before 0.5 is added (STANDARD.md)
        const scaled = f32( normalizedValue * f32( max_integer_value ) );
        integerValue = Math.floor( f32( scaled + 0.5 ) ) >>> 0;
        // the integer clamp is normative: in [2^23, 2^24) the rounded sum can exceed max_integer_value itself
        if ( integerValue > max_integer_value )
        {
            integerValue = max_integer_value;
        }
    }

    if ( !stream.SerializeBits( integerValue, bits ) )
    {
        return false;
    }

    if ( stream.IsReading )
    {
        integerValue = stream.value;
        if ( integerValue > max_integer_value )
        {
            return serialize_fail( stream );
        }
        const normalizedValue = f32( f32( integerValue ) / f32( max_integer_value ) );
        // TWO roundings: the product rounds to float32 before min is added (STANDARD.md)
        const scaledValue = f32( normalizedValue * delta );
        slot[key] = f32( scaledValue + min );
    }

    return true;
}

const compressed_float_params_scratch = new CompressedFloatParams();

/**
    Serialize compressed floating point value (read/write/measure).
    Derives the wire constants with serialize_compressed_float_params and forwards to serialize_compressed_float_precomputed, so the two entry points are wire identical by construction.
    @param obj, key The slot holding the float value.
    @param min The minimum value of the range.
    @param max The maximum value of the range.
    @param res The resolution.
 */

export function serialize_compressed_float<K extends PropertyKey>( stream: BaseStream, obj: Slot<K, number>, key: K, min: number, max: number, res: number ): boolean
{
    const params = serialize_compressed_float_params( min, max, res, compressed_float_params_scratch );
    return serialize_compressed_float_precomputed( stream, obj, key, params.max_integer_value, params.bits, params.delta, min );
}

/**
    Serialize double precision floating point value to the stream (read/write/measure).
    Bit-cast, 64 bits: low dword first, then high dword.
    @param obj, key The slot holding the double value.
 */

export function serialize_double<K extends PropertyKey>( stream: BaseStream, obj: Slot<K, number>, key: K ): boolean
{
    const slot = obj as unknown as AnySlot<number>;
    let lo = 0;
    let hi = 0;
    if ( stream.IsWriting )
    {
        float_scratch.setFloat64( 0, slot[key], true );
        lo = float_scratch.getUint32( 0, true );
        hi = float_scratch.getUint32( 4, true );
    }
    if ( !stream.SerializeBits( lo, 32 ) )
    {
        return false;
    }
    lo = stream.value;
    if ( !stream.SerializeBits( hi, 32 ) )
    {
        return false;
    }
    hi = stream.value;
    if ( stream.IsReading )
    {
        float_scratch.setUint32( 0, lo, true );
        float_scratch.setUint32( 4, hi, true );
        slot[key] = float_scratch.getFloat64( 0, true );
    }
    return true;
}

/** Serialize unsigned 8 bit integer (read/write/measure). */

export function serialize_uint8<K extends PropertyKey>( stream: BaseStream, obj: Slot<K, number>, key: K ): boolean
{
    return serialize_bits( stream, obj, key, 8 );
}

/** Serialize unsigned 16 bit integer (read/write/measure). */

export function serialize_uint16<K extends PropertyKey>( stream: BaseStream, obj: Slot<K, number>, key: K ): boolean
{
    return serialize_bits( stream, obj, key, 16 );
}

/** Serialize unsigned 32 bit integer (read/write/measure). */

export function serialize_uint32<K extends PropertyKey>( stream: BaseStream, obj: Slot<K, number>, key: K ): boolean
{
    return serialize_bits( stream, obj, key, 32 );
}

/** Serialize unsigned 64 bit integer (read/write/measure). The slot holds a bigint. Low dword first, then high dword. */

export function serialize_uint64<K extends PropertyKey>( stream: BaseStream, obj: Slot<K, bigint>, key: K ): boolean
{
    return serialize_bits( stream, obj, key, 64 );
}

/**
    Serialize unsigned 128 bit integer (read/write/measure). The slot holds a bigint.
    The wire format is 128 bits raw: the low 64 bit half first, then the high half, following the lo-then-hi convention of serialize_bits.
 */

export function serialize_uint128<K extends PropertyKey>( stream: BaseStream, obj: Slot<K, bigint>, key: K ): boolean
{
    const slot = obj as unknown as AnySlot<bigint>;
    let group0 = 0;
    let group1 = 0;
    let group2 = 0;
    let group3 = 0;
    if ( stream.IsWriting )
    {
        const value = BigInt.asUintN( 128, slot[key] );
        group0 = Number( value & UINT32_MASK_BIGINT );
        group1 = Number( ( value >> 32n ) & UINT32_MASK_BIGINT );
        group2 = Number( ( value >> 64n ) & UINT32_MASK_BIGINT );
        group3 = Number( ( value >> 96n ) & UINT32_MASK_BIGINT );
    }
    // serialize_bits( low_half, 64 ) then serialize_bits( high_half, 64 ): each half low dword first
    if ( !stream.SerializeBits( group0, 32 ) )
        return false;
    group0 = stream.value;
    if ( !stream.SerializeBits( group1, 32 ) )
        return false;
    group1 = stream.value;
    if ( !stream.SerializeBits( group2, 32 ) )
        return false;
    group2 = stream.value;
    if ( !stream.SerializeBits( group3, 32 ) )
        return false;
    group3 = stream.value;
    if ( stream.IsReading )
    {
        slot[key] = ( BigInt( group3 ) << 96n ) | ( BigInt( group2 ) << 64n ) | ( BigInt( group1 ) << 32n ) | BigInt( group0 );
    }
    return true;
}

/**
    Serialize an array of bytes to the stream (read/write/measure). Aligns to a byte boundary first, even for zero bytes.
    @param data The data to be serialized. On read it is filled, and must hold at least `bytes` bytes.
    @param bytes The number of bytes to serialize.
 */

export function serialize_bytes( stream: BaseStream, data: Uint8Array, bytes: number ): boolean
{
    return stream.SerializeBytes( data, bytes );
}

/*
    UTF-8 well-formedness, one validator with two callers (STANDARD.md): the WRITE path's contract
    check (an assert), and the READ path's refusal rule, which binds in every build mode. Rejects
    overlong encodings, surrogate code points, values above U+10FFFF, truncated sequences and stray
    continuation bytes. NUL bytes are VALID UTF-8: the interior-NUL refusal is a separate rule.
*/

export function serialize_string_is_valid_utf8( string: Uint8Array, length: number ): boolean
{
    let i = 0;
    while ( i < length )
    {
        const lead = string[i];
        if ( lead < 0x80 )
        {
            i += 1;
        }
        else if ( ( lead & 0xE0 ) === 0xC0 )
        {
            if ( lead < 0xC2 )                                                              // overlong
                return false;
            if ( i + 1 >= length )
                return false;
            if ( ( string[i+1] & 0xC0 ) !== 0x80 )
                return false;
            i += 2;
        }
        else if ( ( lead & 0xF0 ) === 0xE0 )
        {
            if ( i + 2 >= length )
                return false;
            const byte1 = string[i+1];
            const byte2 = string[i+2];
            if ( ( byte1 & 0xC0 ) !== 0x80 || ( byte2 & 0xC0 ) !== 0x80 )
                return false;
            if ( lead === 0xE0 && byte1 < 0xA0 )                                            // overlong
                return false;
            if ( lead === 0xED && byte1 >= 0xA0 )                                           // surrogate code point
                return false;
            i += 3;
        }
        else if ( ( lead & 0xF8 ) === 0xF0 )
        {
            if ( lead > 0xF4 )                                                              // above U+10FFFF
                return false;
            if ( i + 3 >= length )
                return false;
            const byte1 = string[i+1];
            const byte2 = string[i+2];
            const byte3 = string[i+3];
            if ( ( byte1 & 0xC0 ) !== 0x80 || ( byte2 & 0xC0 ) !== 0x80 || ( byte3 & 0xC0 ) !== 0x80 )
                return false;
            if ( lead === 0xF0 && byte1 < 0x90 )                                            // overlong
                return false;
            if ( lead === 0xF4 && byte1 >= 0x90 )                                           // above U+10FFFF
                return false;
            i += 4;
        }
        else
        {
            return false;                                                                   // continuation or invalid lead byte
        }
    }
    return true;
}

/** the string up to its first NUL: what C strlen / wcslen would see */
function serialize_string_terminated( string: string ): string
{
    const nul = string.indexOf( '\0' );
    return nul >= 0 ? string.substring( 0, nul ) : string;
}

const utf8_encoder = new TextEncoder();
const utf8_decoder = new TextDecoder();

let string_scratch = new Uint8Array( 256 );

function string_scratch_reserve( bytes: number ): Uint8Array
{
    if ( string_scratch.length < bytes )
    {
        let size = string_scratch.length;
        while ( size < bytes )
            size *= 2;
        string_scratch = new Uint8Array( size );
    }
    return string_scratch;
}

/**
    Serialize a string to the stream (read/write/measure).
    Wire format: serialize_int( length, 0, buffer_size - 1 ) then serialize_bytes of the UTF-8 bytes (no terminator), as upstream.
    On write the string ends at its first NUL (the C++ writer derives the length with strlen), must be well-formed UTF-16 (no lone surrogates), and must encode to fewer than buffer_size UTF-8 bytes.
    On read, malformed payloads are refused: invalid UTF-8 fails the read, and so does an interior NUL byte among the transmitted bytes.
    @param obj, key The slot holding the string.
    @param buffer_size The size of the C++ string buffer: the UTF-8 bytes plus the terminating null must fit into it.
 */

export function serialize_string<K extends PropertyKey>( stream: BaseStream, obj: Slot<K, string>, key: K, buffer_size: number ): boolean
{
    const slot = obj as unknown as AnySlot<string>;
    let length = 0;
    if ( stream.IsWriting )
    {
        const string = serialize_string_terminated( slot[key] );
        serialize_assert( buffer_size > 0, 'serialize_string: buffer_size > 0' );
        serialize_assert( serialize_wstring_is_valid_utf16( string ), 'serialize_string: the string must be well-formed UTF-16' );
        const scratch = string_scratch_reserve( string.length * 3 );
        length = utf8_encoder.encodeInto( string, scratch ).written;
        serialize_assert( length < buffer_size, 'serialize_string: the string (with its terminator) must fit buffer_size' );
        // the writer's contract, debug only. See serialize_string_is_valid_utf8.
        serialize_assert( serialize_string_is_valid_utf8( scratch, length ), 'serialize_string: valid UTF-8' );
    }
    if ( !stream.SerializeInteger( length, 0, buffer_size - 1 ) )
    {
        return false;
    }
    length = stream.value;
    const scratch = string_scratch_reserve( length );
    if ( !stream.SerializeBytes( scratch, length ) )
    {
        return false;
    }
    if ( stream.IsReading )
    {
        // interior NUL first: a conforming writer derives the length from strlen, so a zero byte among
        // the transmitted bytes only arrives doctored -- and it gives the payload two lengths.
        for ( let i = 0; i < length; i++ )
        {
            if ( scratch[i] === 0 )
            {
                return serialize_fail( stream );
            }
        }
        if ( !serialize_string_is_valid_utf8( scratch, length ) )
        {
            return serialize_fail( stream );
        }
        slot[key] = utf8_decoder.decode( scratch.subarray( 0, length ) );
    }
    return true;
}

/**
    Counts the UTF-16 code units a wide string transmits: the count the wstring length field carries.
    A JavaScript string already is UTF-16, so this is its length up to the first NUL.
 */

export function serialize_wstring_unit_count( string: string ): number
{
    return serialize_string_terminated( string ).length;
}

/**
    Is the string (up to its first NUL) well-formed UTF-16: no unpaired surrogates?
    The wstring payload is well-formed UTF-16 BY CONTRACT; this is the writer's assert.
 */

export function serialize_wstring_is_valid_utf16( string: string ): boolean
{
    const length = string.length;
    let i = 0;
    while ( i < length )
    {
        const character = string.charCodeAt( i );
        if ( character === 0 )
            break;
        if ( character >= 0xD800 && character <= 0xDBFF )
        {
            const next = i + 1 < length ? string.charCodeAt( i + 1 ) : 0;
            if ( next < 0xDC00 || next > 0xDFFF )               // high surrogate without its pair
                return false;
            i += 2;
        }
        else if ( character >= 0xDC00 && character <= 0xDFFF )
        {
            return false;                                       // low surrogate with no high before it
        }
        else
        {
            i += 1;
        }
    }
    return true;
}

let wstring_scratch = new Uint16Array( 256 );

/**
    Serialize a wide string to the stream (read/write/measure).
    The wire format is serialize_int( units, 0, buffer_size - 1 ), then 32 bits per group, each group one UTF-16 code unit, as upstream.
    A JavaScript string is UTF-16, so units are written as they are (byte identical to C++ on both 2 and 4 byte wchar_t platforms).
    On write the string ends at its first NUL and must be well-formed UTF-16 (asserted).
    On read, malformed payloads are refused: a group above 0xFFFF, an unpaired surrogate, or an interior NUL group fails the read.
    @param obj, key The slot holding the string.
    @param buffer_size The size of the C++ wchar_t buffer in UTF-16 units. The string's units plus the terminating null must fit into it.
 */

export function serialize_wstring<K extends PropertyKey>( stream: BaseStream, obj: Slot<K, string>, key: K, buffer_size: number ): boolean
{
    const slot = obj as unknown as AnySlot<string>;
    let length = 0;
    let string = '';
    if ( stream.IsWriting )
    {
        string = serialize_string_terminated( slot[key] );
        // the writer's contract, debug only. See serialize_wstring_is_valid_utf16.
        serialize_assert( serialize_wstring_is_valid_utf16( string ), 'serialize_wstring: the string must be well-formed UTF-16' );
        length = string.length;
        serialize_assert( length < buffer_size, 'serialize_wstring: the string (with its terminator) must fit buffer_size' );
    }
    if ( !stream.SerializeInteger( length, 0, buffer_size - 1 ) )
    {
        return false;
    }
    length = stream.value;
    if ( stream.IsWriting )
    {
        for ( let i = 0; i < length; i++ )
        {
            if ( !stream.SerializeBits( string.charCodeAt( i ), 32 ) )
            {
                return false;
            }
        }
        return true;
    }
    if ( wstring_scratch.length < length )
    {
        wstring_scratch = new Uint16Array( Math.max( length, wstring_scratch.length * 2 ) );
    }
    const units = wstring_scratch;
    let have_pending = false;               // a high surrogate awaiting its pair
    for ( let i = 0; i < length; i++ )
    {
        if ( !stream.SerializeBits( 0, 32 ) )
        {
            return false;
        }
        const character = stream.value;
        if ( character > 0xFFFF )
        {
            return serialize_fail( stream );    // not a UTF-16 code unit: nothing conforming emits one
        }
        if ( character === 0 )
        {
            return serialize_fail( stream );    // interior NUL: the two-lengths smuggling primitive
        }
        if ( have_pending )
        {
            if ( character < 0xDC00 || character > 0xDFFF )
            {
                return serialize_fail( stream );    // high surrogate without its low
            }
            have_pending = false;
        }
        else if ( character >= 0xDC00 && character <= 0xDFFF )
        {
            return serialize_fail( stream );    // low surrogate with no high before it
        }
        else if ( character >= 0xD800 && character <= 0xDBFF )
        {
            have_pending = true;
        }
        units[i] = character;
    }
    if ( have_pending )
    {
        return serialize_fail( stream );        // the final group is a dangling high surrogate
    }
    let result = '';
    for ( let i = 0; i < length; i += 4096 )
    {
        result += String.fromCharCode( ...units.subarray( i, Math.min( length, i + 4096 ) ) );
    }
    slot[key] = result;
    return true;
}

/** Serialize an alignment to the stream (read/write/measure). */

export function serialize_align( stream: BaseStream ): boolean
{
    return stream.SerializeAlign();
}

/** Serialize an object to the stream (read/write/measure). The object must have a Serialize( stream ) method. */

export function serialize_object( stream: BaseStream, object: Serializable ): boolean
{
    return object.Serialize( stream );
}

/**
    The int_relative domain: 0 to 2^31 - 1 inclusive. Both previous and current lie in it.
 */

export const serialize_int_relative_max = 2147483647;

/** Is a value inside the int_relative domain? */

export function value_in_int_relative_domain( value: number | bigint ): boolean
{
    return value >= 0 && value <= serialize_int_relative_max;
}

function serialize_int_relative_accept( stream: BaseStream, previous: number, slot: AnySlot<number>, key: PropertyKey, reconstructed: number ): boolean
{
    if ( reconstructed < 0 || reconstructed > serialize_int_relative_max || reconstructed <= previous )
    {
        return serialize_fail( stream );
    }
    slot[key] = reconstructed;
    return true;
}

/**
    Serialize an integer relative to a previous one (read/write/measure).
    The encoding is a ladder of one-bit flags: a difference of 1 costs a single bit, then five bounded tiers of 3, 5, 9, 13 and 17 payload bits, then an absolute tier that transmits current itself as 32 raw bits.
    The sequence is strictly increasing in [0,2^31-1] and no wrap semantics exist.
    On read every tier's reconstruction is checked against the domain and against previous; a refused read writes nothing to current and fails the stream.
    @param previous The previous integer value, in [0,2^31-1].
    @param obj, key The slot holding the current integer value, in [0,2^31-1] and strictly greater than previous.
 */

export function serialize_int_relative<K extends PropertyKey>( stream: BaseStream, previous: number, obj: Slot<K, number>, key: K ): boolean
{
    // previous is the caller's own state and never arrives off the wire, so one outside the domain is caller error
    serialize_assert( previous >= 0, 'serialize_int_relative: previous >= 0' );
    serialize_assert( previous <= serialize_int_relative_max, 'serialize_int_relative: previous in the domain' );

    const slot = obj as unknown as AnySlot<number>;

    let difference = 0;
    let current = 0;
    if ( stream.IsWriting )
    {
        current = slot[key];
        serialize_assert( previous < current, 'serialize_int_relative: previous < current' );
        serialize_assert( current <= serialize_int_relative_max, 'serialize_int_relative: current in the domain' );
        difference = ( current - previous ) >>> 0;
    }

    // each tier is serialize_bool( flag ) then, when set, serialize_int( difference, lo, hi )

    if ( !stream.SerializeBits( ( stream.IsWriting && difference === 1 ) ? 1 : 0, 1 ) )
        return false;
    if ( stream.value )
    {
        if ( stream.IsReading )
        {
            return serialize_int_relative_accept( stream, previous, slot, key, previous + 1 );
        }
        return true;
    }

    if ( !stream.SerializeBits( ( stream.IsWriting && difference <= 6 ) ? 1 : 0, 1 ) )
        return false;
    if ( stream.value )
    {
        if ( !stream.SerializeInteger( difference, 2, 6 ) )
            return false;
        if ( stream.IsReading )
        {
            return serialize_int_relative_accept( stream, previous, slot, key, previous + stream.value );
        }
        return true;
    }

    if ( !stream.SerializeBits( ( stream.IsWriting && difference <= 23 ) ? 1 : 0, 1 ) )
        return false;
    if ( stream.value )
    {
        if ( !stream.SerializeInteger( difference, 7, 23 ) )
            return false;
        if ( stream.IsReading )
        {
            return serialize_int_relative_accept( stream, previous, slot, key, previous + stream.value );
        }
        return true;
    }

    if ( !stream.SerializeBits( ( stream.IsWriting && difference <= 280 ) ? 1 : 0, 1 ) )
        return false;
    if ( stream.value )
    {
        if ( !stream.SerializeInteger( difference, 24, 280 ) )
            return false;
        if ( stream.IsReading )
        {
            return serialize_int_relative_accept( stream, previous, slot, key, previous + stream.value );
        }
        return true;
    }

    if ( !stream.SerializeBits( ( stream.IsWriting && difference <= 4377 ) ? 1 : 0, 1 ) )
        return false;
    if ( stream.value )
    {
        if ( !stream.SerializeInteger( difference, 281, 4377 ) )
            return false;
        if ( stream.IsReading )
        {
            return serialize_int_relative_accept( stream, previous, slot, key, previous + stream.value );
        }
        return true;
    }

    if ( !stream.SerializeBits( ( stream.IsWriting && difference <= 69914 ) ? 1 : 0, 1 ) )
        return false;
    if ( stream.value )
    {
        if ( !stream.SerializeInteger( difference, 4378, 69914 ) )
            return false;
        if ( stream.IsReading )
        {
            return serialize_int_relative_accept( stream, previous, slot, key, previous + stream.value );
        }
        return true;
    }

    // the absolute tier transmits current, not the difference, as 32 raw bits. the group is
    // UNSIGNED, so a value with the top bit set is outside the domain and is refused
    if ( !stream.SerializeBits( current >>> 0, 32 ) )
        return false;
    if ( stream.IsReading )
    {
        return serialize_int_relative_accept( stream, previous, slot, key, stream.value );
    }

    return true;
}

// ------------------------------------------------------------------------------------------

/**
    Fixed point storage types. In C++ the storage is the C++ type of the value; here it is named.
    Storage of 32 bits or fewer is a number slot; 64 and 128 bit storage is a bigint slot.
    Storage of 64 bits or fewer uses the narrow codec (64 bit domain), 128 bit storage the wide codec, as upstream.
 */

export type FixedStorageNarrow = 'int8' | 'uint8' | 'int16' | 'uint16' | 'int32' | 'uint32';
export type FixedStorageWide = 'int64' | 'uint64' | 'int128' | 'uint128';
export type FixedStorage = FixedStorageNarrow | FixedStorageWide;

function fixed_storage_bits( storage: FixedStorage ): number
{
    switch ( storage )
    {
        case 'int8': case 'uint8': return 8;
        case 'int16': case 'uint16': return 16;
        case 'int32': case 'uint32': return 32;
        case 'int64': case 'uint64': return 64;
        case 'int128': case 'uint128': return 128;
    }
}

const INT64_MIN_BIGINT = -( 1n << 63n );
const INT64_MAX_BIGINT = ( 1n << 63n ) - 1n;

/*
    Fixed point codec on raw two's complement patterns, specialized on storage width as upstream's
    FixedPointSerializer<WideStorage>. raw is the storage value as a bigint. The result (read, or
    echoed on write) is left in stream.value_bigint as the unsigned pattern of the codec's domain.
*/

function fixed_point_serialize_narrow( stream: BaseStream, raw: bigint, integer_bits: number, fraction_bits: number, min_units: bigint, max_units: bigint, is_signed: boolean ): boolean
{
    // the whole unit capacity of the Q format
    const min_representable_units = is_signed ? -( 1n << BigInt( integer_bits - 1 ) ) : 0n;
    const max_representable_units = is_signed ? ( 1n << BigInt( integer_bits - 1 ) ) - 1n :
        ( ( integer_bits >= 64 ) ? INT64_MAX_BIGINT : ( 1n << BigInt( integer_bits ) ) - 1n );

    serialize_assert( min_units >= min_representable_units, 'serialize_fixed: min bound in whole units does not fit the Q format' );
    serialize_assert( max_units <= max_representable_units, 'serialize_fixed: max bound in whole units does not fit the Q format' );

    // shift the whole unit bounds into raw fixed point units in the unsigned 64 bit domain
    const fb = BigInt( fraction_bits );
    const raw_min = BigInt.asUintN( 64, min_units << fb );
    const raw_max = BigInt.asUintN( 64, max_units << fb );
    const raw_range = BigInt.asUintN( 64, raw_max - raw_min );

    if ( min_units === max_units )
    {
        // degenerate range: the value IS the range, nothing to send. the zero bit field still goes
        // through the stream, so a fixed point field on a stream that has already failed refuses
        if ( !stream.SerializeInteger( 0, 0, 0 ) )
        {
            return false;
        }
        if ( stream.IsWriting )
        {
            serialize_assert( BigInt.asUintN( 64, raw ) === raw_min, 'serialize_fixed: value == min' );
        }
        stream.value_bigint = raw_min;
        return true;
    }

    const bits = bits_required64( raw_min, raw_max );

    let offset = 0n;

    if ( stream.IsWriting )
    {
        // subtract in the unsigned domain
        offset = BigInt.asUintN( 64, BigInt.asUintN( 64, raw ) - raw_min );
        serialize_assert( offset <= raw_range, 'serialize_fixed: the value must be within [min,max] whole units' );
    }

    if ( bits <= 32 )
    {
        if ( !stream.SerializeBits( Number( offset ), bits ) )
        {
            return false;
        }
        offset = BigInt( stream.value );
    }
    else
    {
        // low dword first, then the high remainder: same convention as serialize_bits and serialize_int64
        if ( !stream.SerializeBits( Number( offset & UINT32_MASK_BIGINT ), 32 ) )
        {
            return false;
        }
        const low_half = stream.value;
        if ( !stream.SerializeBits( Number( offset >> 32n ), bits - 32 ) )
        {
            return false;
        }
        const high_half = stream.value;
        offset = ( BigInt( high_half ) << 32n ) | BigInt( low_half );
    }

    if ( stream.IsReading )
    {
        // reject raw values outside [raw_min,raw_max] smuggled into the bit headroom. reject, never clamp
        if ( offset > raw_range )
        {
            return serialize_fail( stream );
        }
    }

    // reconstruct in the unsigned domain
    stream.value_bigint = BigInt.asUintN( 64, raw_min + offset );
    return true;
}

function fixed_point_serialize_wide( stream: BaseStream, raw: bigint, integer_bits: number, fraction_bits: number, min_units: bigint, max_units: bigint, is_signed: boolean ): boolean
{
    // the whole unit capacity of the Q format, exact. bounds are int64, so with 65 or more
    // integer bits the capacity covers any bound, as upstream
    const min_representable_units = is_signed ? -( 1n << BigInt( integer_bits - 1 ) ) : 0n;
    const max_representable_units = is_signed ? ( 1n << BigInt( integer_bits - 1 ) ) - 1n : ( 1n << BigInt( integer_bits ) ) - 1n;

    serialize_assert( min_units >= min_representable_units, 'serialize_fixed: min bound in whole units does not fit the Q format' );
    serialize_assert( max_units <= max_representable_units, 'serialize_fixed: max bound in whole units does not fit the Q format' );

    // shift the whole unit bounds into raw fixed point units in the unsigned 128 bit domain (sign extended for signed storage)
    const fb = BigInt( fraction_bits );
    const raw_min = BigInt.asUintN( 128, min_units << fb );
    const raw_max = BigInt.asUintN( 128, max_units << fb );
    const raw_range = BigInt.asUintN( 128, raw_max - raw_min );

    if ( min_units === max_units )
    {
        // degenerate range: zero bits on every storage width, NOT fraction_bits of zeros
        if ( !stream.SerializeInteger( 0, 0, 0 ) )
        {
            return false;
        }
        if ( stream.IsWriting )
        {
            serialize_assert( BigInt.asUintN( 128, raw ) === raw_min, 'serialize_fixed: value == min' );
        }
        stream.value_bigint = raw_min;
        return true;
    }

    // the wire cost: the range in whole units is exact in a uint64, and shifting it left by fraction_bits adds exactly fraction_bits to its bit length
    const bits = bits_required64( min_units, max_units ) + fraction_bits;

    let offset = 0n;

    if ( stream.IsWriting )
    {
        offset = BigInt.asUintN( 128, BigInt.asUintN( 128, raw ) - raw_min );
        serialize_assert( offset <= raw_range, 'serialize_fixed: the value must be within [min,max] whole units' );
    }

    // the offset is written in 32 bit groups, least significant group first
    let group0 = Number( offset & UINT32_MASK_BIGINT );
    let group1 = Number( ( offset >> 32n ) & UINT32_MASK_BIGINT );
    let group2 = Number( ( offset >> 64n ) & UINT32_MASK_BIGINT );
    let group3 = Number( ( offset >> 96n ) & UINT32_MASK_BIGINT );

    if ( bits <= 32 )
    {
        if ( !stream.SerializeBits( group0, bits ) ) return false;
        group0 = stream.value;
    }
    else if ( bits <= 64 )
    {
        if ( !stream.SerializeBits( group0, 32 ) ) return false;
        group0 = stream.value;
        if ( !stream.SerializeBits( group1, bits - 32 ) ) return false;
        group1 = stream.value;
    }
    else if ( bits <= 96 )
    {
        if ( !stream.SerializeBits( group0, 32 ) ) return false;
        group0 = stream.value;
        if ( !stream.SerializeBits( group1, 32 ) ) return false;
        group1 = stream.value;
        if ( !stream.SerializeBits( group2, bits - 64 ) ) return false;
        group2 = stream.value;
    }
    else
    {
        if ( !stream.SerializeBits( group0, 32 ) ) return false;
        group0 = stream.value;
        if ( !stream.SerializeBits( group1, 32 ) ) return false;
        group1 = stream.value;
        if ( !stream.SerializeBits( group2, 32 ) ) return false;
        group2 = stream.value;
        if ( !stream.SerializeBits( group3, bits - 96 ) ) return false;
        group3 = stream.value;
    }

    if ( stream.IsReading )
    {
        offset = ( BigInt( group3 ) << 96n ) | ( BigInt( group2 ) << 64n ) | ( BigInt( group1 ) << 32n ) | BigInt( group0 );

        // reject raw values outside [raw_min,raw_max] smuggled into the bit headroom. reject, never clamp
        if ( offset > raw_range )
        {
            return serialize_fail( stream );
        }
    }

    stream.value_bigint = BigInt.asUintN( 128, raw_min + offset );
    return true;
}

/** the fixed point codec on a raw storage value. the result pattern is left in stream.value_bigint */

function serialize_fixed_internal( stream: BaseStream, raw: bigint, integer_bits: number, fraction_bits: number, min: number | bigint, max: number | bigint, storage: FixedStorage ): boolean
{
    const storage_bits = fixed_storage_bits( storage );
    const is_signed = storage.charCodeAt( 0 ) === 0x69;        // 'i'
    const min_units = BigInt( min );
    const max_units = BigInt( max );

    serialize_assert( integer_bits >= 1, 'serialize_fixed needs at least one integer bit. the sign bit counts for signed storage' );
    serialize_assert( fraction_bits >= 0, 'serialize_fixed fractional bits can\'t be negative' );
    serialize_assert( integer_bits + fraction_bits === storage_bits, 'serialize_fixed integer bits plus fractional bits must equal the number of bits in the storage type' );
    serialize_assert( min_units <= max_units, 'serialize_fixed min must not exceed max' );
    serialize_assert( min_units >= INT64_MIN_BIGINT && max_units <= INT64_MAX_BIGINT, 'serialize_fixed bounds are int64 whole units' );

    if ( storage_bits > 64 )
    {
        return fixed_point_serialize_wide( stream, raw, integer_bits, fraction_bits, min_units, max_units, is_signed );
    }
    return fixed_point_serialize_narrow( stream, raw, integer_bits, fraction_bits, min_units, max_units, is_signed );
}

/** convert a codec result pattern to the storage type's value */

function fixed_storage_value( pattern: bigint, storage: FixedStorage ): number | bigint
{
    switch ( storage )
    {
        case 'int8': return Number( BigInt.asIntN( 8, pattern ) );
        case 'uint8': return Number( BigInt.asUintN( 8, pattern ) );
        case 'int16': return Number( BigInt.asIntN( 16, pattern ) );
        case 'uint16': return Number( BigInt.asUintN( 16, pattern ) );
        case 'int32': return Number( BigInt.asIntN( 32, pattern ) );
        case 'uint32': return Number( BigInt.asUintN( 32, pattern ) );
        case 'int64': return BigInt.asIntN( 64, pattern );
        case 'uint64': return BigInt.asUintN( 64, pattern );
        case 'int128': return BigInt.asIntN( 128, pattern );
        case 'uint128': return BigInt.asUintN( 128, pattern );
    }
}

/**
    Serialize a fixed point value to the stream (read/write/measure).
    The slot holds the RAW storage value (the Q format integer), exactly as the C++ storage variable does.
    integer_bits plus fraction_bits must equal the number of bits in the storage type, with the sign bit counting towards integer_bits for signed storage:
    Q48.16 in an int64 is ( 48, 16, ..., 'int64' ) and Q112.16 in an int128 is ( 112, 16, ..., 'int128' ).
    The bounds are whole units (int64). The value is serialized as an offset from min in the minimal number of bits for the range, and the round trip is exact.
    A degenerate range where min == max is legal and costs zero bits on every storage width.
    For storage of 64 bits or fewer the wire format is byte identical to serialize_int64 of the raw value over the raw bounds.
    @param obj, key The slot holding the raw fixed point value: a number for <= 32 bit storage, a bigint for 64 and 128 bit storage.
    @param integer_bits The number of integer bits in the Q format, including the sign bit for signed storage.
    @param fraction_bits The number of fractional bits in the Q format.
    @param min The minimum value in whole units.
    @param max The maximum value in whole units.
    @param storage The storage type: what the C++ type of the value would be.
 */

export function serialize_fixed<K extends PropertyKey>( stream: BaseStream, obj: Slot<K, number>, key: K, integer_bits: number, fraction_bits: number, min: number | bigint, max: number | bigint, storage: FixedStorageNarrow ): boolean;
export function serialize_fixed<K extends PropertyKey>( stream: BaseStream, obj: Slot<K, bigint>, key: K, integer_bits: number, fraction_bits: number, min: number | bigint, max: number | bigint, storage: FixedStorageWide ): boolean;
export function serialize_fixed( stream: BaseStream, obj: unknown, key: PropertyKey, integer_bits: number, fraction_bits: number, min: number | bigint, max: number | bigint, storage: FixedStorage ): boolean
{
    const slot = obj as AnySlot<number | bigint>;
    let raw = 0n;
    if ( stream.IsWriting )
    {
        raw = BigInt( slot[key] );
    }
    if ( !serialize_fixed_internal( stream, raw, integer_bits, fraction_bits, min, max, storage ) )
    {
        return false;
    }
    if ( stream.IsReading )
    {
        slot[key] = fixed_storage_value( stream.value_bigint, storage );
    }
    return true;
}

// ------------------------------------------------------------------------------------------
//
//      read_* functions corresponding to each serialize_*. useful when you want separate read and write functions.
//      They take slots, exactly like the serialize_* functions, and assert that the stream is a read stream.
//
// ------------------------------------------------------------------------------------------

export function read_bits<K extends PropertyKey>( stream: BaseStream, obj: Slot<K, number>, key: K, bits: number ): boolean;
export function read_bits<K extends PropertyKey>( stream: BaseStream, obj: Slot<K, bigint>, key: K, bits: number ): boolean;
export function read_bits( stream: BaseStream, obj: unknown, key: PropertyKey, bits: number ): boolean
{
    serialize_assert( stream.IsReading, 'read_bits: read stream' );
    return serialize_bits( stream, obj as AnySlot<number>, key, bits );
}

export function read_int<K extends PropertyKey>( stream: BaseStream, obj: Slot<K, number>, key: K, min: number, max: number ): boolean
{
    serialize_assert( stream.IsReading, 'read_int: read stream' );
    return serialize_int( stream, obj, key, min, max );
}

export function read_int64<K extends PropertyKey>( stream: BaseStream, obj: Slot<K, bigint>, key: K, min: bigint, max: bigint ): boolean
{
    serialize_assert( stream.IsReading, 'read_int64: read stream' );
    return serialize_int64( stream, obj, key, min, max );
}

export function read_int128<K extends PropertyKey>( stream: BaseStream, obj: Slot<K, bigint>, key: K, min: bigint, max: bigint ): boolean
{
    serialize_assert( stream.IsReading, 'read_int128: read stream' );
    return serialize_int128( stream, obj, key, min, max );
}

export function read_fixed<K extends PropertyKey>( stream: BaseStream, obj: Slot<K, number>, key: K, integer_bits: number, fraction_bits: number, min: number | bigint, max: number | bigint, storage: FixedStorageNarrow ): boolean;
export function read_fixed<K extends PropertyKey>( stream: BaseStream, obj: Slot<K, bigint>, key: K, integer_bits: number, fraction_bits: number, min: number | bigint, max: number | bigint, storage: FixedStorageWide ): boolean;
export function read_fixed( stream: BaseStream, obj: unknown, key: PropertyKey, integer_bits: number, fraction_bits: number, min: number | bigint, max: number | bigint, storage: FixedStorage ): boolean
{
    serialize_assert( stream.IsReading, 'read_fixed: read stream' );
    return serialize_fixed( stream, obj as AnySlot<number>, key, integer_bits, fraction_bits, min, max, storage as FixedStorageNarrow );
}

export function read_bool<K extends PropertyKey>( stream: BaseStream, obj: Slot<K, boolean>, key: K ): boolean
{
    serialize_assert( stream.IsReading, 'read_bool: read stream' );
    return serialize_bool( stream, obj, key );
}

export function read_uint8<K extends PropertyKey>( stream: BaseStream, obj: Slot<K, number>, key: K ): boolean
{
    serialize_assert( stream.IsReading, 'read_uint8: read stream' );
    return serialize_bits( stream, obj, key, 8 );
}

export function read_uint16<K extends PropertyKey>( stream: BaseStream, obj: Slot<K, number>, key: K ): boolean
{
    serialize_assert( stream.IsReading, 'read_uint16: read stream' );
    return serialize_bits( stream, obj, key, 16 );
}

export function read_uint32<K extends PropertyKey>( stream: BaseStream, obj: Slot<K, number>, key: K ): boolean
{
    serialize_assert( stream.IsReading, 'read_uint32: read stream' );
    return serialize_bits( stream, obj, key, 32 );
}

export function read_uint64<K extends PropertyKey>( stream: BaseStream, obj: Slot<K, bigint>, key: K ): boolean
{
    serialize_assert( stream.IsReading, 'read_uint64: read stream' );
    return serialize_bits( stream, obj, key, 64 );
}

export function read_uint128<K extends PropertyKey>( stream: BaseStream, obj: Slot<K, bigint>, key: K ): boolean
{
    serialize_assert( stream.IsReading, 'read_uint128: read stream' );
    return serialize_uint128( stream, obj, key );
}

export function read_float<K extends PropertyKey>( stream: BaseStream, obj: Slot<K, number>, key: K ): boolean
{
    return serialize_float( stream, obj, key );
}

export function read_double<K extends PropertyKey>( stream: BaseStream, obj: Slot<K, number>, key: K ): boolean
{
    return serialize_double( stream, obj, key );
}

export function read_bytes( stream: BaseStream, data: Uint8Array, bytes: number ): boolean
{
    serialize_assert( stream.IsReading, 'read_bytes: read stream' );
    return stream.SerializeBytes( data, bytes );
}

export function read_string<K extends PropertyKey>( stream: BaseStream, obj: Slot<K, string>, key: K, buffer_size: number ): boolean
{
    serialize_assert( stream.IsReading, 'read_string: read stream' );
    return serialize_string( stream, obj, key, buffer_size );
}

export function read_wstring<K extends PropertyKey>( stream: BaseStream, obj: Slot<K, string>, key: K, buffer_size: number ): boolean
{
    serialize_assert( stream.IsReading, 'read_wstring: read stream' );
    return serialize_wstring( stream, obj, key, buffer_size );
}

export function read_align( stream: BaseStream ): boolean
{
    return serialize_align( stream );
}

export function read_object( stream: BaseStream, object: Serializable ): boolean
{
    return serialize_object( stream, object );
}

export function read_int_relative<K extends PropertyKey>( stream: BaseStream, previous: number, obj: Slot<K, number>, key: K ): boolean
{
    return serialize_int_relative( stream, previous, obj, key );
}

// ------------------------------------------------------------------------------------------
//
//      write_* functions corresponding to each serialize_*. useful when you want separate read and write functions.
//      They take plain values (upstream's write macros take rvalues) and assert that the stream writes.
//
// ------------------------------------------------------------------------------------------

/** scratch slots for the write_* forms, which take values. writes never re-enter, so one set suffices */
const write_scratch = { number: 0, bigint: 0n, string: '' };

/**
    Write bits to the stream, the write-only companion to serialize_bits.
    @param value The unsigned value to write: a number up to 2^53, or a bigint. Must be in [0,(1<<bits)-1].
    @param bits The number of bits to write in [1,64].
 */

export function write_bits( stream: BaseStream, value: number | bigint, bits: number ): boolean
{
    serialize_assert( stream.IsWriting, 'write_bits: write stream' );
    serialize_assert( bits > 0, 'write_bits: bits > 0' );
    serialize_assert( bits <= 64, 'write_bits: bits <= 64' );
    serialize_assert( value_fits_in_bits( value, bits ), 'write_bits: value fits in bits' );
    if ( bits <= 32 )
    {
        return stream.SerializeBits( typeof value === 'bigint' ? Number( BigInt.asUintN( 32, value ) ) : value >>> 0, bits );
    }
    const uint64_value = BigInt.asUintN( 64, BigInt( value ) );
    if ( !stream.SerializeBits( Number( uint64_value & UINT32_MASK_BIGINT ), 32 ) )
        return false;
    return stream.SerializeBits( Number( uint64_value >> 32n ), bits - 32 );
}

export function write_int( stream: BaseStream, value: number, min: number, max: number ): boolean
{
    serialize_assert( stream.IsWriting, 'write_int: write stream' );
    serialize_assert( min <= max, 'write_int: min <= max' );
    serialize_assert( value >= min, 'write_int: value >= min' );
    serialize_assert( value <= max, 'write_int: value <= max' );
    return stream.SerializeInteger( value, min, max );
}

export function write_int64( stream: BaseStream, value: bigint, min: bigint, max: bigint ): boolean
{
    serialize_assert( stream.IsWriting, 'write_int64: write stream' );
    serialize_assert( min <= max, 'write_int64: min <= max' );
    serialize_assert( value >= min, 'write_int64: value >= min' );
    serialize_assert( value <= max, 'write_int64: value <= max' );
    return stream.SerializeInteger64( value, min, max );
}

export function write_int128( stream: BaseStream, value: bigint, min: bigint, max: bigint ): boolean
{
    serialize_assert( stream.IsWriting, 'write_int128: write stream' );
    serialize_assert( min <= max, 'write_int128: min <= max' );
    serialize_assert( value >= min, 'write_int128: value >= min' );
    serialize_assert( value <= max, 'write_int128: value <= max' );
    return stream.SerializeInteger128( value, min, max );
}

export function write_fixed( stream: BaseStream, value: number | bigint, integer_bits: number, fraction_bits: number, min: number | bigint, max: number | bigint, storage: FixedStorage ): boolean
{
    serialize_assert( stream.IsWriting, 'write_fixed: write stream' );
    return serialize_fixed_internal( stream, BigInt( value ), integer_bits, fraction_bits, min, max, storage );
}

export function write_bool( stream: BaseStream, value: boolean ): boolean
{
    return write_bits( stream, value ? 1 : 0, 1 );
}

export function write_uint8( stream: BaseStream, value: number ): boolean
{
    return write_bits( stream, value, 8 );
}

export function write_uint16( stream: BaseStream, value: number ): boolean
{
    return write_bits( stream, value, 16 );
}

export function write_uint32( stream: BaseStream, value: number ): boolean
{
    return write_bits( stream, value, 32 );
}

export function write_uint64( stream: BaseStream, value: bigint ): boolean
{
    return write_bits( stream, value, 64 );
}

export function write_uint128( stream: BaseStream, value: bigint ): boolean
{
    serialize_assert( stream.IsWriting, 'write_uint128: write stream' );
    write_scratch.bigint = value;
    return serialize_uint128( stream, write_scratch, 'bigint' );
}

export function write_float( stream: BaseStream, value: number ): boolean
{
    serialize_assert( stream.IsWriting, 'write_float: write stream' );
    return stream.SerializeBits( float_to_bits( value ), 32 );
}

export function write_double( stream: BaseStream, value: number ): boolean
{
    serialize_assert( stream.IsWriting, 'write_double: write stream' );
    write_scratch.number = value;
    return serialize_double( stream, write_scratch, 'number' );
}

export function write_bytes( stream: BaseStream, data: Uint8Array, bytes: number ): boolean
{
    serialize_assert( stream.IsWriting, 'write_bytes: write stream' );
    return stream.SerializeBytes( data, bytes );
}

export function write_string( stream: BaseStream, string: string, buffer_size: number ): boolean
{
    serialize_assert( stream.IsWriting, 'write_string: write stream' );
    write_scratch.string = string;
    return serialize_string( stream, write_scratch, 'string', buffer_size );
}

export function write_wstring( stream: BaseStream, string: string, buffer_size: number ): boolean
{
    serialize_assert( stream.IsWriting, 'write_wstring: write stream' );
    write_scratch.string = string;
    return serialize_wstring( stream, write_scratch, 'string', buffer_size );
}

export function write_align( stream: BaseStream ): boolean
{
    return stream.SerializeAlign();
}

export function write_object( stream: BaseStream, object: Serializable ): boolean
{
    return object.Serialize( stream );
}

/**
    Write an integer relative to a previous one, the write-only companion to serialize_int_relative.
    @param previous The previous integer value, in [0,2^31-1].
    @param current The current integer value, in [0,2^31-1] and strictly greater than previous.
 */

export function write_int_relative( stream: BaseStream, previous: number, current: number ): boolean
{
    serialize_assert( stream.IsWriting, 'write_int_relative: write stream' );
    serialize_assert( value_in_int_relative_domain( current ), 'write_int_relative: current in the domain' );
    write_scratch.number = current;
    return serialize_int_relative( stream, previous, write_scratch, 'number' );
}

// ------------------------------------------------------------------------------------------
//
//      Compile time parameter surface (upstream: experimental, for generated code).
//
//      Upstream moves min/max/bits into template argument position so the bit count is a compile
//      time constant. TypeScript has no templates, so here the "template arguments" are trailing
//      parameters; what is kept is the surface (names, read-side validation, the Min < Max rule)
//      and the wire identity property: the bytes are identical to the runtime forms.
//
// ------------------------------------------------------------------------------------------

/**
    Calculates the number of bits required to serialize an integer in range [min,max] (the constexpr companion to bits_required64).
    @returns The number of bits required to serialize the integer in [0,64].
 */

export function bits_required64_constexpr( min: bigint, max: bigint ): number
{
    let bits = 0;
    for ( let diff = BigInt.asUintN( 64, max - min ); diff !== 0n; diff >>= 1n )
    {
        bits++;
    }
    return bits;
}

/**
    Serialize an integer with "compile time" bounds (read/write/measure). Min must be less than Max.
    Wire bytes are identical to the runtime form given identical inputs.
 */

export function SerializeIntConst<K extends PropertyKey>( stream: BaseStream, obj: Slot<K, number>, key: K, Min: number, Max: number ): boolean
{
    serialize_assert( Min < Max, 'serialize: min must be less than max' );
    const bits = bits_required64_constexpr( BigInt( Min ), BigInt( Max ) );
    const slot = obj as unknown as AnySlot<number>;
    let unsigned_value = 0;
    if ( stream.IsWriting )
    {
        const value = slot[key];
        serialize_assert( value >= Min, 'SerializeIntConst: value >= Min' );
        serialize_assert( value <= Max, 'SerializeIntConst: value <= Max' );
        unsigned_value = ( value - Min ) >>> 0;
    }
    if ( !stream.SerializeBits( unsigned_value, bits ) )
    {
        return false;
    }
    if ( stream.IsReading )
    {
        unsigned_value = stream.value;
        if ( unsigned_value > ( ( Max - Min ) >>> 0 ) )
        {
            return serialize_fail( stream );
        }
        slot[key] = Min + unsigned_value;
    }
    return true;
}

/**
    Serialize a 64 bit integer with "compile time" bounds (read/write/measure). Min must be less than Max.
    Wire bytes are identical to the runtime form: low dword first, then the high remainder.
 */

export function SerializeInt64Const<K extends PropertyKey>( stream: BaseStream, obj: Slot<K, bigint>, key: K, Min: bigint, Max: bigint ): boolean
{
    serialize_assert( Min < Max, 'serialize: min must be less than max' );
    const bits = bits_required64_constexpr( Min, Max );
    const slot = obj as unknown as AnySlot<bigint>;
    let unsigned_value = 0n;
    if ( stream.IsWriting )
    {
        const value = slot[key];
        serialize_assert( value >= Min, 'SerializeInt64Const: value >= Min' );
        serialize_assert( value <= Max, 'SerializeInt64Const: value <= Max' );
        unsigned_value = BigInt.asUintN( 64, value - Min );
    }
    if ( bits <= 32 )
    {
        if ( !stream.SerializeBits( Number( unsigned_value ), bits ) )
        {
            return false;
        }
        unsigned_value = BigInt( stream.value );
    }
    else
    {
        if ( !stream.SerializeBits( Number( unsigned_value & UINT32_MASK_BIGINT ), 32 ) )
        {
            return false;
        }
        const lo = stream.value;
        if ( !stream.SerializeBits( Number( unsigned_value >> 32n ), bits - 32 ) )
        {
            return false;
        }
        const hi = stream.value;
        unsigned_value = ( BigInt( hi ) << 32n ) | BigInt( lo );
    }
    if ( stream.IsReading )
    {
        if ( unsigned_value > BigInt.asUintN( 64, Max - Min ) )
        {
            return serialize_fail( stream );
        }
        slot[key] = Min + unsigned_value;
    }
    return true;
}

/** Serialize a "compile time" number of bits, in [1,32] (read/write/measure). */

export function SerializeBitsConst<K extends PropertyKey>( stream: BaseStream, obj: Slot<K, number>, key: K, Bits: number ): boolean
{
    serialize_assert( Bits > 0, 'serialize: bits must be greater than zero' );
    serialize_assert( Bits <= 32, 'serialize: bits must be less than or equal to 32. use SerializeBits64Const for wider values' );
    const slot = obj as unknown as AnySlot<number>;
    if ( !stream.SerializeBits( stream.IsWriting ? slot[key] : 0, Bits ) )
    {
        return false;
    }
    if ( stream.IsReading )
    {
        slot[key] = stream.value;
    }
    return true;
}

/** Serialize a "compile time" number of bits from a 64 bit (bigint) value, in [1,64] (read/write/measure). */

export function SerializeBits64Const<K extends PropertyKey>( stream: BaseStream, obj: Slot<K, bigint>, key: K, Bits: number ): boolean
{
    serialize_assert( Bits > 0, 'serialize: bits must be greater than zero' );
    serialize_assert( Bits <= 64, 'serialize: bits must be less than or equal to 64' );
    const slot = obj as unknown as AnySlot<bigint>;
    const value = stream.IsWriting ? BigInt.asUintN( 64, slot[key] ) : 0n;
    if ( Bits <= 32 )
    {
        if ( !stream.SerializeBits( Number( value ), Bits ) )
        {
            return false;
        }
        if ( stream.IsReading )
        {
            slot[key] = BigInt( stream.value );
        }
    }
    else
    {
        if ( !stream.SerializeBits( Number( value & UINT32_MASK_BIGINT ), 32 ) )
        {
            return false;
        }
        const lo = stream.value;
        if ( !stream.SerializeBits( Number( value >> 32n ), Bits - 32 ) )
        {
            return false;
        }
        const hi = stream.value;
        if ( stream.IsReading )
        {
            slot[key] = ( BigInt( hi ) << 32n ) | BigInt( lo );
        }
    }
    return true;
}

/** Serialize integer value with "compile time" bounds (read/write/measure). The companion to serialize_int. */

export function serialize_int_compile_time<K extends PropertyKey>( stream: BaseStream, obj: Slot<K, number>, key: K, min: number, max: number ): boolean
{
    return SerializeIntConst( stream, obj, key, min, max );
}

/** Serialize a 64 bit integer value with "compile time" bounds (read/write/measure). The companion to serialize_int64. */

export function serialize_int64_compile_time<K extends PropertyKey>( stream: BaseStream, obj: Slot<K, bigint>, key: K, min: bigint, max: bigint ): boolean
{
    return SerializeInt64Const( stream, obj, key, min, max );
}

/** Serialize a "compile time" number of bits, in [1,32] (read/write/measure). The companion to serialize_bits. */

export function serialize_bits_compile_time<K extends PropertyKey>( stream: BaseStream, obj: Slot<K, number>, key: K, bits: number ): boolean
{
    serialize_assert( !stream.IsWriting || value_fits_in_bits( ( obj as unknown as AnySlot<number> )[key], bits ), 'serialize_bits_compile_time: value fits in bits' );
    return SerializeBitsConst( stream, obj, key, bits );
}

/** Serialize a "compile time" number of bits from a bigint, in [1,64] (read/write/measure). The companion to serialize_bits. */

export function serialize_bits64_compile_time<K extends PropertyKey>( stream: BaseStream, obj: Slot<K, bigint>, key: K, bits: number ): boolean
{
    serialize_assert( !stream.IsWriting || value_fits_in_bits( ( obj as unknown as AnySlot<bigint> )[key], bits ), 'serialize_bits64_compile_time: value fits in bits' );
    return SerializeBits64Const( stream, obj, key, bits );
}

/** Serialize a boolean value through the "compile time" surface (read/write/measure). One bit. */

export function serialize_bool_compile_time<K extends PropertyKey>( stream: BaseStream, obj: Slot<K, boolean>, key: K ): boolean
{
    const slot = obj as unknown as AnySlot<boolean>;
    if ( !stream.SerializeBits( ( stream.IsWriting && slot[key] ) ? 1 : 0, 1 ) )
    {
        return false;
    }
    if ( stream.IsReading )
    {
        slot[key] = stream.value !== 0;
    }
    return true;
}

// ------------------------------------------------------------------------------------------
//
//      Tests: the port of serialize.h's SERIALIZE_ENABLE_TESTS section.
//
//      Ported test for test, in upstream order. Not ported, because the thing they test does not
//      exist in TypeScript: test_uint128_emulation, test_int128_emulation, test_uint128_differential
//      and test_int128_differential (the C++ emulated 128 bit struct and its agreement with native
//      __int128 -- here 128 bit values are bigint, which is exact), and the floating point
//      contraction probes (JavaScript arithmetic never contracts: every float32 rounding is pinned
//      by Math.fround). Blocks upstream runs only under NDEBUG run here with asserts switched off,
//      and the fork-based "assert fires" tests catch the thrown assert instead.
//
// ------------------------------------------------------------------------------------------

const INT32_MIN = -2147483648;
const INT32_MAX = 2147483647;
const INT64_MIN = -( 1n << 63n );
const INT64_MAX = ( 1n << 63n ) - 1n;

function serialize_test_verbose(): boolean
{
    const process = ( globalThis as { process?: { env?: Record<string, string | undefined> } } ).process;
    const value = process?.env?.SERIALIZE_TEST_VERBOSE;
    return value !== undefined && value !== '' && value !== '0';
}

function serialize_check( condition: boolean, what: string = 'condition' ): void
{
    if ( !condition )
    {
        throw new Error( 'check failed: ( ' + what + ' )' );
    }
}

function bytes_equal( a: Uint8Array, b: Uint8Array, bytes: number ): boolean
{
    for ( let i = 0; i < bytes; i++ )
    {
        if ( a[i] !== b[i] )
            return false;
    }
    return true;
}

/** run fn with serialize asserts off: the NDEBUG ("release build") behaviour */
function serialize_test_release_build( fn: () => void ): void
{
    const previous = serialize_get_asserts_enabled();
    serialize_set_asserts_enabled( false );
    try
    {
        fn();
    }
    finally
    {
        serialize_set_asserts_enabled( previous );
    }
}

/** run fn with serialize asserts on, and report whether a serialize assert fired */
function serialize_test_assert_fires( fn: () => void ): boolean
{
    const previous = serialize_get_asserts_enabled();
    serialize_set_asserts_enabled( true );
    try
    {
        fn();
        return false;
    }
    catch ( error )
    {
        return error instanceof Error && error.message.startsWith( 'serialize_assert failed' );
    }
    finally
    {
        serialize_set_asserts_enabled( previous );
    }
}

function test_endian(): void
{
    const bytes = new Uint8Array( new Uint32Array( [ 0x11223344 ] ).buffer );

    if ( SERIALIZE_LITTLE_ENDIAN )
    {
        serialize_check( bytes[0] === 0x44 );
        serialize_check( bytes[1] === 0x33 );
        serialize_check( bytes[2] === 0x22 );
        serialize_check( bytes[3] === 0x11 );
    }
    else
    {
        serialize_check( bytes[3] === 0x44 );
        serialize_check( bytes[2] === 0x33 );
        serialize_check( bytes[1] === 0x22 );
        serialize_check( bytes[0] === 0x11 );
    }

    // the byte order helpers
    serialize_check( bswap32( 0x11223344 ) === 0x44332211 );
    serialize_check( bswap16( 0x1122 ) === 0x2211 );
    serialize_check( bswap64( 0x1122334455667788n ) === 0x8877665544332211n );
    serialize_check( network_to_host32( host_to_network32( 0xDEADBEEF ) ) === 0xDEADBEEF );
    serialize_check( network_to_host16( host_to_network16( 0xBEEF ) ) === 0xBEEF );
    serialize_check( network_to_host64( host_to_network64( 0x0123456789ABCDEFn ) ) === 0x0123456789ABCDEFn );
    serialize_check( popcount( 0xFFFFFFFF ) === 32 && popcount( 0 ) === 0 && popcount( 0x80000001 ) === 2 );
    serialize_check( log2( 1 ) === 0 && log2( 2 ) === 1 && log2( 255 ) === 7 && log2( 256 ) === 8 && log2( 0xFFFFFFFF ) === 31 );
}

function test_bitpacker(): void
{
    const BufferSize = 256;

    const buffer = new Uint8Array( BufferSize );

    const writer = new BitWriter( buffer, BufferSize );

    serialize_check( writer.GetData() === buffer );
    serialize_check( writer.GetBitsWritten() === 0 );
    serialize_check( writer.GetBytesWritten() === 0 );
    serialize_check( writer.GetBitsAvailable() === BufferSize * 8 );

    writer.WriteBits( 0, 1 );
    writer.WriteBits( 1, 1 );
    writer.WriteBits( 10, 8 );
    writer.WriteBits( 255, 8 );
    writer.WriteBits( 1000, 10 );
    writer.WriteBits( 50000, 16 );
    writer.WriteBits( 9999999, 32 );
    writer.FlushBits();

    const bitsWritten = 1 + 1 + 8 + 8 + 10 + 16 + 32;

    serialize_check( writer.GetBytesWritten() === 10 );
    serialize_check( writer.GetBitsWritten() === bitsWritten );
    serialize_check( writer.GetBitsAvailable() === BufferSize * 8 - bitsWritten );

    const bytesWritten = writer.GetBytesWritten();

    serialize_check( bytesWritten === 10 );

    buffer.fill( 0, bytesWritten );

    const reader = new BitReader( buffer, bytesWritten );

    serialize_check( reader.GetBitsRead() === 0 );
    serialize_check( reader.GetBitsRemaining() === bytesWritten * 8 );

    const a = reader.ReadBits( 1 );
    const b = reader.ReadBits( 1 );
    const c = reader.ReadBits( 8 );
    const d = reader.ReadBits( 8 );
    const e = reader.ReadBits( 10 );
    const f = reader.ReadBits( 16 );
    const g = reader.ReadBits( 32 );

    serialize_check( a === 0 );
    serialize_check( b === 1 );
    serialize_check( c === 10 );
    serialize_check( d === 255 );
    serialize_check( e === 1000 );
    serialize_check( f === 50000 );
    serialize_check( g === 9999999 );

    serialize_check( reader.GetBitsRead() === bitsWritten );
    serialize_check( reader.GetBitsRemaining() === bytesWritten * 8 - bitsWritten );
}

function test_bits_required(): void
{
    serialize_check( bits_required( 0, 0 ) === 0 );
    serialize_check( bits_required( 0, 1 ) === 1 );
    serialize_check( bits_required( 0, 2 ) === 2 );
    serialize_check( bits_required( 0, 3 ) === 2 );
    serialize_check( bits_required( 0, 4 ) === 3 );
    serialize_check( bits_required( 0, 5 ) === 3 );
    serialize_check( bits_required( 0, 6 ) === 3 );
    serialize_check( bits_required( 0, 7 ) === 3 );
    serialize_check( bits_required( 0, 8 ) === 4 );
    serialize_check( bits_required( 0, 255 ) === 8 );
    serialize_check( bits_required( 0, 65535 ) === 16 );
    serialize_check( bits_required( 0, 4294967295 ) === 32 );
}

function test_bits_required64(): void
{
    serialize_check( bits_required64( 0n, 0n ) === 0 );
    serialize_check( bits_required64( 0n, 1n ) === 1 );
    serialize_check( bits_required64( 0n, 255n ) === 8 );
    serialize_check( bits_required64( 0n, 4294967295n ) === 32 );
    serialize_check( bits_required64( 0n, 4294967296n ) === 33 );
    serialize_check( bits_required64( 0n, 1n << 40n ) === 41 );
    serialize_check( bits_required64( 0n, 0xFFFFFFFFFFFFFFFFn ) === 64 );
    serialize_check( bits_required64( BigInt.asUintN( 64, INT64_MIN ), BigInt.asUintN( 64, INT64_MAX ) ) === 64 );
    serialize_check( bits_required64( BigInt.asUintN( 64, -5000000000n ), BigInt.asUintN( 64, 5000000000n ) ) === 34 );
}

function test_bits_required128(): void
{
    const all_ones = ( 1n << 128n ) - 1n;

    serialize_check( bits_required128( 0n, 0n ) === 0 );
    serialize_check( bits_required128( 0n, 1n ) === 1 );
    serialize_check( bits_required128( 0n, 255n ) === 8 );
    serialize_check( bits_required128( 0n, 4294967295n ) === 32 );
    serialize_check( bits_required128( 0n, 4294967296n ) === 33 );
    serialize_check( bits_required128( 0n, 0xFFFFFFFFFFFFFFFFn ) === 64 );

    // the boundary the 64 bit helper cannot reach: one past a full low lane needs the high lane
    serialize_check( bits_required128( 0n, 1n << 64n ) === 65 );
    serialize_check( bits_required128( 0n, 1n << 127n ) === 128 );
    serialize_check( bits_required128( 0n, all_ones ) === 128 );

    // the two helpers must agree wherever the range fits 64 bits
    serialize_check( bits_required128( 0n, 4294967296n ) === bits_required64( 0n, 4294967296n ) );
    serialize_check( bits_required128( 0n, 1n << 40n ) === bits_required64( 0n, 1n << 40n ) );

    // NEGATIVE BOUNDS MUST ARRIVE SIGN EXTENDED: the same 34 bits the 64 bit helper reports
    serialize_check( bits_required128( BigInt.asUintN( 128, -5000000000n ), BigInt.asUintN( 128, 5000000000n ) ) === 34 );

    // AND THE TRAP: widening an ALREADY WRAPPED uint64 bound zero extends instead of sign extending
    serialize_check( bits_required128( BigInt.asUintN( 64, -5000000000n ), BigInt.asUintN( 64, 5000000000n ) ) === 128 );

    // a range wider than 2^127: the subtraction must run in the unsigned domain
    serialize_check( bits_required128( 1n, all_ones ) === 128 );
}

function test_zigzag(): void
{
    serialize_check( signed_to_unsigned( 0 ) === 0 );
    serialize_check( signed_to_unsigned( -1 ) === 1 );
    serialize_check( signed_to_unsigned( +1 ) === 2 );
    serialize_check( signed_to_unsigned( -2 ) === 3 );
    serialize_check( signed_to_unsigned( +2 ) === 4 );
    serialize_check( signed_to_unsigned( INT32_MAX ) === 0xFFFFFFFE );
    serialize_check( signed_to_unsigned( INT32_MIN ) === 0xFFFFFFFF );

    serialize_check( unsigned_to_signed( 0 ) === 0 );
    serialize_check( unsigned_to_signed( 1 ) === -1 );
    serialize_check( unsigned_to_signed( 2 ) === +1 );
    serialize_check( unsigned_to_signed( 3 ) === -2 );
    serialize_check( unsigned_to_signed( 4 ) === +2 );
    serialize_check( unsigned_to_signed( 0xFFFFFFFE ) === INT32_MAX );
    serialize_check( unsigned_to_signed( 0xFFFFFFFF ) === INT32_MIN );

    const values = [ 0, -1, +1, -2, +2, 12345, -12345, INT32_MAX, INT32_MIN ];

    for ( let i = 0; i < values.length; i++ )
    {
        serialize_check( unsigned_to_signed( signed_to_unsigned( values[i] ) ) === values[i] );
    }
}

const MaxItems = 11;

class TestData
{
    a = 0;
    b = 0;
    c = 0;
    d = 0;
    e = 0;
    f = 0;
    g = false;
    numItems = 0;
    items = new Array<number>( MaxItems ).fill( 0 );
    float_value = 0;
    compressed_float_value = 0;
    double_value = 0;
    uint8_value = 0;
    uint16_value = 0;
    uint32_value = 0;
    uint64_value = 0n;
    int_relative = 0;
    int64_full = 0n;
    int64_range = 0n;
    bytes = new Uint8Array( 17 );
    string = '';
    wstring = '';
}

class TestContext
{
    min = 0;
    max = 0;
}

class TestObject
{
    data = new TestData();

    Init(): void
    {
        const data = this.data;

        data.a = 1;
        data.b = -2;
        data.c = 150;
        data.d = 55;
        data.e = 255;
        data.f = 127;
        data.g = true;

        data.numItems = Math.floor( MaxItems / 2 );
        for ( let i = 0; i < data.numItems; ++i )
            data.items[i] = i + 10;

        data.compressed_float_value = f32( 2.13 );
        data.float_value = f32( 3.1415926 );
        data.double_value = 1 / 3.0;
        data.uint8_value = 123;
        data.uint16_value = 0x1234;
        data.uint32_value = 0x12345678;
        data.uint64_value = 0x1234567898765432n;
        data.int_relative = 5;
        data.int64_full = -123456789012345n;
        data.int64_range = 4123456789n;

        for ( let i = 0; i < data.bytes.length; ++i )
            data.bytes[i] = ( i + 5 ) * 13;

        data.string = 'hello world!';

        // explicit code points: privit, svit!
        data.wstring = String.fromCharCode( 0x043F, 0x0440, 0x0438, 0x0432, 0x0456, 0x0442, 0x002C, 0x0020, 0x0441, 0x0432, 0x0456, 0x0442, 0x0021 );
    }

    Serialize( stream: BaseStream ): boolean
    {
        const context = stream.GetContext() as TestContext;
        const data = this.data;

        if ( !serialize_int( stream, data, 'a', context.min, context.max ) ) return false;
        if ( !serialize_int( stream, data, 'b', context.min, context.max ) ) return false;

        if ( !serialize_int( stream, data, 'c', -100, 10000 ) ) return false;

        if ( !serialize_bits( stream, data, 'd', 6 ) ) return false;
        if ( !serialize_bits( stream, data, 'e', 8 ) ) return false;
        if ( !serialize_bits( stream, data, 'f', 7 ) ) return false;

        if ( !serialize_align( stream ) ) return false;

        if ( !serialize_bool( stream, data, 'g' ) ) return false;

        if ( !serialize_int( stream, data, 'numItems', 0, MaxItems - 1 ) ) return false;
        for ( let i = 0; i < data.numItems; ++i )
            if ( !serialize_bits( stream, data.items, i, 8 ) ) return false;

        if ( !serialize_float( stream, data, 'float_value' ) ) return false;

        if ( !serialize_compressed_float( stream, data, 'compressed_float_value', 0, 10, 0.01 ) ) return false;

        if ( !serialize_double( stream, data, 'double_value' ) ) return false;

        if ( !serialize_uint8( stream, data, 'uint8_value' ) ) return false;
        if ( !serialize_uint16( stream, data, 'uint16_value' ) ) return false;
        if ( !serialize_uint32( stream, data, 'uint32_value' ) ) return false;
        if ( !serialize_uint64( stream, data, 'uint64_value' ) ) return false;

        if ( !serialize_int_relative( stream, data.a, data, 'int_relative' ) ) return false;

        if ( !serialize_int64( stream, data, 'int64_full', INT64_MIN, INT64_MAX ) ) return false;
        if ( !serialize_int64( stream, data, 'int64_range', -5000000000n, 5000000000n ) ) return false;

        if ( !serialize_bytes( stream, data.bytes, data.bytes.length ) ) return false;

        if ( !serialize_string( stream, data, 'string', 256 ) ) return false;
        if ( !serialize_wstring( stream, data, 'wstring', 256 ) ) return false;

        return true;
    }

    equals( other: TestObject ): boolean
    {
        const a = this.data;
        const b = other.data;
        for ( let i = 0; i < MaxItems; i++ )
        {
            if ( a.items[i] !== b.items[i] )
                return false;
        }
        return a.a === b.a && a.b === b.b && a.c === b.c && a.d === b.d && a.e === b.e && a.f === b.f && a.g === b.g &&
               a.numItems === b.numItems &&
               a.float_value === b.float_value &&
               a.compressed_float_value === b.compressed_float_value &&
               a.double_value === b.double_value &&
               a.uint8_value === b.uint8_value &&
               a.uint16_value === b.uint16_value &&
               a.uint32_value === b.uint32_value &&
               a.uint64_value === b.uint64_value &&
               a.int_relative === b.int_relative &&
               a.int64_full === b.int64_full &&
               a.int64_range === b.int64_range &&
               a.bytes.length === b.bytes.length && bytes_equal( a.bytes, b.bytes, a.bytes.length ) &&
               a.string === b.string &&
               a.wstring === b.wstring;
    }
}

function test_serialize(): void
{
    const BufferSize = 1024;

    const buffer = new Uint8Array( BufferSize );

    const context = new TestContext();
    context.min = -10;
    context.max = +10;

    const writeStream = new WriteStream( buffer, BufferSize );

    const writeObject = new TestObject();
    writeObject.Init();
    writeStream.SetContext( context );
    serialize_check( writeObject.Serialize( writeStream ) );
    writeStream.Flush();

    const bytesWritten = writeStream.GetBytesProcessed();

    buffer.fill( 0, bytesWritten );

    const readObject = new TestObject();
    const readStream = new ReadStream( buffer, bytesWritten );
    readStream.SetContext( context );
    serialize_check( readObject.Serialize( readStream ) );

    serialize_check( readObject.equals( writeObject ) );

    // the measure stream is a bound on the written size
    const measureStream = new MeasureStream();
    measureStream.SetContext( context );
    serialize_check( writeObject.Serialize( measureStream ) );
    serialize_check( measureStream.GetBitsProcessed() >= writeStream.GetBitsProcessed() );
}

function ReadFunction( readStream: ReadStream ): boolean
{
    // IMPORTANT: You wouldn't normally write a read function like this, but I'm just checking each value as it's read in
    // Note that the only thing the read function has to have is to return bool: true on success, false on failing to read.
    // This is important because protects you from maliciously crafted packets.

    {
        const value = { value: 0 };
        if ( !read_bits( readStream, value, 'value', 4 ) ) return false;
        serialize_check( value.value === 13 );
    }

    {
        const value = { value: false };
        if ( !read_bool( readStream, value, 'value' ) ) return false;
        serialize_check( value.value === true );
    }

    {
        const value = { value: 0 };
        if ( !read_uint8( readStream, value, 'value' ) ) return false;
        serialize_check( value.value === 255 );
    }

    {
        const value = { value: 0 };
        if ( !read_uint16( readStream, value, 'value' ) ) return false;
        serialize_check( value.value === 65535 );
    }

    {
        const value = { value: 0 };
        if ( !read_uint32( readStream, value, 'value' ) ) return false;
        serialize_check( value.value === 0xFFFFFFFF );
    }

    {
        const value = { value: 0n };
        if ( !read_uint64( readStream, value, 'value' ) ) return false;
        serialize_check( value.value === 0xFFFFFFFFFFFFFFFFn );      // i am very full
    }

    {
        const value = { value: 0 };
        if ( !read_int( readStream, value, 'value', 10, 90 ) ) return false;
        serialize_check( value.value === 55 );
    }

    {
        const value = { value: 0n };
        if ( !read_int64( readStream, value, 'value', -60000000000n, 60000000000n ) ) return false;
        serialize_check( value.value === -50000000001n );
    }

    {
        const value = { value: 0n };
        if ( !read_fixed( readStream, value, 'value', 48, 16, -100000, +100000, 'int64' ) ) return false;
        serialize_check( value.value === 12345n * 65536n + 32768n );       // 12345.5 in Q48.16
    }

    {
        const value = { value: 0n };
        if ( !read_uint128( readStream, value, 'value' ) ) return false;
        serialize_check( value.value === ( ( 0x0123456789ABCDEFn << 64n ) | 0xFEDCBA9876543210n ) );
    }

    {
        const value = { value: 0 };
        if ( !read_float( readStream, value, 'value' ) ) return false;
        serialize_check( value.value === 100.0 );
    }

    {
        const value = { value: 0 };
        if ( !read_double( readStream, value, 'value' ) ) return false;
        serialize_check( value.value === 1000000000.0 );
    }

    {
        const value = new Uint8Array( 5 );
        if ( !read_bytes( readStream, value, 5 ) ) return false;
        serialize_check( value[0] === 1 );
        serialize_check( value[1] === 2 );
        serialize_check( value[2] === 3 );
        serialize_check( value[3] === 4 );
        serialize_check( value[4] === 5 );
    }

    {
        const string = { value: '' };
        if ( !read_string( readStream, string, 'value', 10 ) ) return false;
        serialize_check( string.value === 'hello' );
    }

    {
        const wstring = { value: '' };
        if ( !read_wstring( readStream, wstring, 'value', 20 ) ) return false;
        serialize_check( wstring.value.charCodeAt( 0 ) === 0x043F );
        serialize_check( wstring.value.charCodeAt( 1 ) === 0x0440 );
        serialize_check( wstring.value.charCodeAt( 2 ) === 0x0438 );
        serialize_check( wstring.value.charCodeAt( 3 ) === 0x0432 );
        serialize_check( wstring.value.charCodeAt( 4 ) === 0x0456 );
        serialize_check( wstring.value.charCodeAt( 5 ) === 0x0442 );
        serialize_check( wstring.value.length === 6 );
    }

    if ( !read_align( readStream ) ) return false;

    const context = new TestContext();
    context.min = -10;
    context.max = +10;

    readStream.SetContext( context );
    {
        const expectedObject = new TestObject();
        expectedObject.Init();

        const readObject = new TestObject();

        if ( !read_object( readStream, readObject ) ) return false;

        serialize_check( readObject.equals( expectedObject ) );
    }

    {
        const value = { value: 0 };
        if ( !read_int_relative( readStream, 100, value, 'value' ) ) return false;
        serialize_check( value.value === 105 );
    }

    return true;
}

function test_read_write(): void
{
    const BufferSize = 10 * 1024;

    const buffer = new Uint8Array( BufferSize );

    let bytesWritten = 0;

    // write to the buffer
    {
        const writeStream = new WriteStream();
        writeStream.Initialize( buffer, BufferSize );

        write_bits( writeStream, 13, 4 );
        write_bool( writeStream, true );
        write_uint8( writeStream, 255 );
        write_uint16( writeStream, 65535 );
        write_uint32( writeStream, 0xFFFFFFFF );
        write_uint64( writeStream, 0xFFFFFFFFFFFFFFFFn );
        write_int( writeStream, 55, 10, 90 );
        write_int64( writeStream, -50000000001n, -60000000000n, 60000000000n );

        const fixed_point_value = 12345n * 65536n + 32768n;               // 12345.5 in Q48.16
        write_fixed( writeStream, fixed_point_value, 48, 16, -100000, +100000, 'int64' );

        const big_value = ( 0x0123456789ABCDEFn << 64n ) | 0xFEDCBA9876543210n;
        write_uint128( writeStream, big_value );

        write_float( writeStream, 100.0 );
        write_double( writeStream, f32( 1000000000.0 ) );

        const data = new Uint8Array( [ 1, 2, 3, 4, 5 ] );
        write_bytes( writeStream, data, 5 );

        write_string( writeStream, 'hello', 10 );

        // explicit code points, see the note above
        write_wstring( writeStream, String.fromCharCode( 0x043F, 0x0440, 0x0438, 0x0432, 0x0456, 0x0442 ), 20 );

        write_align( writeStream );

        const context = new TestContext();
        context.min = -10;
        context.max = +10;

        writeStream.SetContext( context );

        const object = new TestObject();
        object.Init();

        write_object( writeStream, object );

        write_int_relative( writeStream, 100, 105 );

        writeStream.Flush();

        bytesWritten = writeStream.GetBytesProcessed();

        buffer.fill( 0, bytesWritten );
    }

    // read from the buffer
    {
        const readStream = new ReadStream();
        readStream.Initialize( buffer, bytesWritten );
        serialize_check( ReadFunction( readStream ) );
    }
}

function test_serialize_integer_validation(): void
{
    // bits_required(0,5) is 3 bits, so a malicious packet can encode 6 or 7. reads must reject values above max.
    const buffer = new Uint8Array( 4 + 8 );

    const writeStream = new WriteStream( buffer, 8 );
    writeStream.SerializeBits( 7, 3 );
    writeStream.Flush();

    const readStream = new ReadStream( buffer, 4 );
    serialize_check( readStream.SerializeInteger( 0, 0, 5 ) === false );
}

function test_serialize_degenerate_range(): void
{
    // STANDARD.md: a degenerate range where min == max costs ZERO BITS -- the value is known from the range alone and nothing is written.
    const buffer = new Uint8Array( 16 );

    const writeStream = new WriteStream( buffer, 16 );
    serialize_check( writeStream.SerializeInteger( 5, 5, 5 ) );
    serialize_check( writeStream.GetBitsProcessed() === 0 );      // nothing written
    serialize_check( writeStream.SerializeInteger( 3, 0, 7 ) );
    serialize_check( writeStream.GetBitsProcessed() === 3 );      // the NEXT field starts at bit 0
    writeStream.Flush();

    const readStream = new ReadStream( buffer, writeStream.GetBytesProcessed() );
    const read_degenerate = { value: 0 };
    const read_after = { value: 0 };
    serialize_check( serialize_int( readStream, read_degenerate, 'value', 5, 5 ) );
    serialize_check( read_degenerate.value === 5 );               // recovered from the range
    serialize_check( readStream.GetBitsProcessed() === 0 );
    serialize_check( serialize_int( readStream, read_after, 'value', 0, 7 ) );
    serialize_check( read_after.value === 3 );

    // and the measure stream must agree that it costs nothing
    const measureStream = new MeasureStream();
    serialize_check( measureStream.SerializeInteger( 5, 5, 5 ) );
    serialize_check( measureStream.GetBitsProcessed() === 0 );
}

function test_serialize_degenerate_range_64(): void
{
    // The 64 bit twin of the test above. The bounds are deliberately wider than 2^32 so the field would take the two-dword path if it took any path at all.
    const buffer = new Uint8Array( 16 );

    const point = 1n << 40n;

    const writeStream = new WriteStream( buffer, 16 );
    serialize_check( writeStream.SerializeInteger64( point, point, point ) );
    serialize_check( writeStream.GetBitsProcessed() === 0 );      // nothing written
    serialize_check( writeStream.SerializeInteger( 3, 0, 7 ) );
    serialize_check( writeStream.GetBitsProcessed() === 3 );      // the NEXT field starts at bit 0
    writeStream.Flush();

    const readStream = new ReadStream( buffer, writeStream.GetBytesProcessed() );
    const read_degenerate = { value: 0n };
    const read_after = { value: 0 };
    serialize_check( serialize_int64( readStream, read_degenerate, 'value', point, point ) );
    serialize_check( read_degenerate.value === point );           // recovered from the range
    serialize_check( readStream.GetBitsProcessed() === 0 );
    serialize_check( serialize_int( readStream, read_after, 'value', 0, 7 ) );
    serialize_check( read_after.value === 3 );

    const measureStream = new MeasureStream();
    serialize_check( measureStream.SerializeInteger64( point, point, point ) );
    serialize_check( measureStream.GetBitsProcessed() === 0 );
}

function DegenerateInt128Serialize( stream: BaseStream, value: { value: bigint }, point: bigint ): boolean
{
    if ( !serialize_int128( stream, value, 'value', point, point ) ) return false;
    return true;
}

function test_serialize_degenerate_range_128(): void
{
    // The 128 bit twin. The point is the conformance corpus's int128 vector: 2^100 + 7, far past 64 bits.
    const buffer = new Uint8Array( 16 );

    const point = ( 1n << 100n ) + 7n;

    const writeStream = new WriteStream( buffer, 16 );
    const degenerate = { value: point };
    serialize_check( DegenerateInt128Serialize( writeStream, degenerate, point ) );
    serialize_check( writeStream.GetBitsProcessed() === 0 );      // nothing written
    serialize_check( writeStream.SerializeInteger( 3, 0, 7 ) );
    serialize_check( writeStream.GetBitsProcessed() === 3 );      // the NEXT field starts at bit 0
    writeStream.Flush();

    const readStream = new ReadStream( buffer, writeStream.GetBytesProcessed() );
    const read_degenerate = { value: 0n };
    const read_after = { value: 0 };
    serialize_check( DegenerateInt128Serialize( readStream, read_degenerate, point ) );
    serialize_check( read_degenerate.value === point );           // recovered from the range
    serialize_check( readStream.GetBitsProcessed() === 0 );
    serialize_check( serialize_int( readStream, read_after, 'value', 0, 7 ) );
    serialize_check( read_after.value === 3 );

    const measureStream = new MeasureStream();
    const measured = { value: point };
    serialize_check( DegenerateInt128Serialize( measureStream, measured, point ) );
    serialize_check( measureStream.GetBitsProcessed() === 0 );
}

function test_serialize_integer_full_range(): void
{
    // ranges wider than 2^31 overflow if [min,max] arithmetic is done signed
    const values = [ INT32_MIN, INT32_MIN + 1, -1, 0, +1, INT32_MAX - 1, INT32_MAX ];

    for ( let i = 0; i < values.length; i++ )
    {
        const buffer = new Uint8Array( 8 + 8 );

        const writeStream = new WriteStream( buffer, 8 );
        serialize_check( writeStream.SerializeInteger( values[i], INT32_MIN, INT32_MAX ) === true );
        writeStream.Flush();

        const readStream = new ReadStream( buffer, 8 );
        serialize_check( readStream.SerializeInteger( 0, INT32_MIN, INT32_MAX ) === true );
        serialize_check( readStream.value === values[i] );
    }

    {
        const buffer = new Uint8Array( 8 + 8 );

        const writeStream = new WriteStream( buffer, 8 );
        serialize_check( writeStream.SerializeInteger( 1000000000, -2000000000, 2000000000 ) === true );
        writeStream.Flush();

        const readStream = new ReadStream( buffer, 8 );
        serialize_check( readStream.SerializeInteger( 0, -2000000000, 2000000000 ) === true );
        serialize_check( readStream.value === 1000000000 );
    }
}

function test_serialize_int64_full_range(): void
{
    // ranges wider than 2^63 overflow if [min,max] arithmetic is done signed
    {
        const values = [ INT64_MIN, INT64_MIN + 1n, -1n, 0n, 1n, INT64_MAX - 1n, INT64_MAX ];

        for ( let i = 0; i < values.length; i++ )
        {
            const buffer = new Uint8Array( 16 + 8 );

            const writeStream = new WriteStream( buffer, 16 );
            serialize_check( writeStream.SerializeInteger64( values[i], INT64_MIN, INT64_MAX ) === true );
            writeStream.Flush();

            const readStream = new ReadStream( buffer, 16 );
            serialize_check( readStream.SerializeInteger64( 0n, INT64_MIN, INT64_MAX ) === true );
            serialize_check( readStream.value_bigint === values[i] );
        }
    }

    // ranges spanning more than 32 bits use the two dword path
    {
        const min = -5000000000n;
        const max = 5000000000n;
        const values = [ min, min + 1n, -1n, 0n, 1n, 4123456789n, max - 1n, max ];

        for ( let i = 0; i < values.length; i++ )
        {
            const buffer = new Uint8Array( 16 + 8 );

            const writeStream = new WriteStream( buffer, 16 );
            serialize_check( writeStream.SerializeInteger64( values[i], min, max ) === true );
            writeStream.Flush();

            const readStream = new ReadStream( buffer, 16 );
            serialize_check( readStream.SerializeInteger64( 0n, min, max ) === true );
            serialize_check( readStream.value_bigint === values[i] );
        }
    }

    // small ranges use the single dword path and the minimal number of bits
    {
        const buffer = new Uint8Array( 8 + 8 );

        const writeStream = new WriteStream( buffer, 8 );
        serialize_check( writeStream.SerializeInteger64( 55n, -100n, 100n ) === true );
        writeStream.Flush();

        serialize_check( writeStream.GetBitsProcessed() === 8 );        // bits_required64(-100,100) == 8, same as the 32 bit path

        const readStream = new ReadStream( buffer, 8 );
        serialize_check( readStream.SerializeInteger64( 0n, -100n, 100n ) === true );
        serialize_check( readStream.value_bigint === 55n );
    }
}

function test_serialize_int64_validation(): void
{
    // a malicious packet can smuggle an out of range value into the bit headroom of the two dword path. reads must reject it.
    {
        const buffer = new Uint8Array( 16 + 8 );

        const writeStream = new WriteStream( buffer, 16 );
        const out_of_range = ( 1n << 34n ) + 5n;               // range [0, 2^34] is 35 bits, so values above 2^34 fit in the headroom
        writeStream.SerializeBits( Number( out_of_range & 0xFFFFFFFFn ), 32 );
        writeStream.SerializeBits( Number( out_of_range >> 32n ), 3 );
        writeStream.Flush();

        const readStream = new ReadStream( buffer, 16 );
        serialize_check( readStream.SerializeInteger64( 0n, 0n, 1n << 34n ) === false );
    }

    // reads past the end of the buffer must fail cleanly
    {
        const buffer = new Uint8Array( 4 + 8 );

        const readStream = new ReadStream( buffer, 4 );
        serialize_check( readStream.SerializeInteger64( 0n, INT64_MIN, INT64_MAX ) === false );
    }
}

function test_serialize_bytes_validation(): void
{
    // negative and huge byte counts must be rejected, not overflow the bounds check in bits
    const buffer = new Uint8Array( 16 + 8 );
    const data = new Uint8Array( 16 );

    {
        const readStream = new ReadStream( buffer, 16 );
        serialize_check( readStream.SerializeBytes( data, -1 ) === false );
    }

    {
        const readStream = new ReadStream( buffer, 16 );
        serialize_check( readStream.SerializeBytes( data, 1 << 29 ) === false );
    }
}

function test_wstring_validation(): void
{
    const BufferSize = 32;

    // empty string: length 0, no characters
    {
        const buffer = new Uint8Array( 256 );
        const writeStream = new WriteStream( buffer );
        serialize_check( serialize_wstring( writeStream, { value: '' }, 'value', BufferSize ) );
        writeStream.Flush();

        const read_back = { value: 'not empty' };
        const readStream = new ReadStream( buffer, writeStream.GetBytesProcessed() );
        serialize_check( serialize_wstring( readStream, read_back, 'value', BufferSize ) );
        serialize_check( read_back.value === '' );
    }

    // longest legal string: buffer_size - 1 characters, since the terminator is not sent
    {
        const buffer = new Uint8Array( 512 );
        let full = '';
        for ( let i = 0; i < BufferSize - 1; ++i )
            full += String.fromCharCode( 0x0041 + ( i % 26 ) );

        const writeStream = new WriteStream( buffer );
        serialize_check( serialize_wstring( writeStream, { value: full }, 'value', BufferSize ) );
        writeStream.Flush();

        const read_back = { value: '' };
        const readStream = new ReadStream( buffer, writeStream.GetBytesProcessed() );
        serialize_check( serialize_wstring( readStream, read_back, 'value', BufferSize ) );
        serialize_check( read_back.value === full );
    }

    // the measure stream must agree with the write stream on cost
    {
        const buffer = new Uint8Array( 256 );
        const text = { value: 'ABC' };

        const measureStream = new MeasureStream();
        serialize_check( serialize_wstring( measureStream, text, 'value', BufferSize ) );

        const writeStream = new WriteStream( buffer );
        serialize_check( serialize_wstring( writeStream, text, 'value', BufferSize ) );
        writeStream.Flush();

        serialize_check( measureStream.GetBitsProcessed() === writeStream.GetBitsProcessed() );
    }

    // A GROUP ABOVE 0xFFFF IS NOT A UTF-16 CODE UNIT: the doctored group is REFUSED
    {
        const buffer = new Uint8Array( 256 );
        const above_bmp = 0x0001F600;      // beyond 16 bits by construction

        const writeStream = new WriteStream( buffer );
        serialize_check( writeStream.SerializeInteger( 1, 0, BufferSize - 1 ) );   // length 1
        serialize_check( writeStream.SerializeBits( above_bmp, 32 ) );
        writeStream.Flush();

        const read_back = { value: 'untouched' };
        const readStream = new ReadStream( buffer, writeStream.GetBytesProcessed() );
        const result = serialize_wstring( readStream, read_back, 'value', BufferSize );

        serialize_check( result === false );
        serialize_check( read_back.value === 'untouched' );    // nothing truncated left behind
    }
}

function test_wstring_utf16_code_units(): void
{
    // wstring transmits UTF-16 CODE UNITS: an astral code point is a surrogate pair on the wire.
    // A JavaScript string already holds the pair, like a 2 byte wchar_t platform.

    const BufferSize = 8;

    // U+1F600 is the surrogate pair 0xD83D 0xDE00
    const ws_in = String.fromCodePoint( 0x1F600 ) + 'A';
    serialize_check( ws_in.length === 3 && ws_in.charCodeAt( 0 ) === 0xD83D && ws_in.charCodeAt( 1 ) === 0xDE00 );

    // the wire, spelled out with raw bit operations: three units in a [0,7] length field, then each unit as a 32 bit group
    const expected_bytes = new Uint8Array( 64 );
    let expected_bytes_processed = 0;
    {
        const expectedStream = new WriteStream( expected_bytes );
        serialize_check( expectedStream.SerializeInteger( 3, 0, BufferSize - 1 ) );
        serialize_check( expectedStream.SerializeBits( 0xD83D, 32 ) );
        serialize_check( expectedStream.SerializeBits( 0xDE00, 32 ) );
        serialize_check( expectedStream.SerializeBits( 0x0041, 32 ) );
        expectedStream.Flush();
        expected_bytes_processed = expectedStream.GetBytesProcessed();
    }

    // write side: the unified serialize path must produce exactly those bytes
    let bits_written = 0;
    {
        const buffer = new Uint8Array( 64 );
        const writeStream = new WriteStream( buffer );
        serialize_check( serialize_wstring( writeStream, { value: ws_in }, 'value', BufferSize ) );
        writeStream.Flush();
        serialize_check( writeStream.GetBytesProcessed() === expected_bytes_processed );
        serialize_check( bytes_equal( buffer, expected_bytes, expected_bytes_processed ) );
        bits_written = writeStream.GetBitsProcessed();
    }

    // the measure counts the units transmitted, not the characters held
    {
        const measureStream = new MeasureStream();
        serialize_check( serialize_wstring( measureStream, { value: ws_in }, 'value', BufferSize ) );
        serialize_check( measureStream.GetBitsProcessed() === bits_written );
        serialize_check( serialize_wstring_unit_count( ws_in ) === 3 );
    }

    // the write-only form must stay byte-identical to the unified path
    {
        const macro_buffer = new Uint8Array( 64 );
        const writeStream = new WriteStream( macro_buffer );
        write_wstring( writeStream, ws_in, BufferSize );
        writeStream.Flush();
        serialize_check( writeStream.GetBytesProcessed() === expected_bytes_processed );
        serialize_check( bytes_equal( macro_buffer, expected_bytes, expected_bytes_processed ) );
    }

    // read side: the code unit stream decodes to the pair itself
    {
        const read_back = { value: '' };
        const readStream = new ReadStream( expected_bytes, expected_bytes_processed );
        serialize_check( serialize_wstring( readStream, read_back, 'value', BufferSize ) );
        serialize_check( read_back.value === ws_in );
    }
}

function test_string_read_validation(): void
{
    // STANDARD.md, "Readers must refuse malformed string payloads". Every refused stream below is DOCTORED with raw bit operations.

    const BufferSize = 16;

    const doctored = ( payload: number[] ): Uint8Array =>
    {
        const buffer = new Uint8Array( 64 );
        const writeStream = new WriteStream( buffer );
        serialize_check( writeStream.SerializeInteger( payload.length, 0, BufferSize - 1 ) );
        serialize_check( writeStream.SerializeBytes( new Uint8Array( payload ), payload.length ) );
        writeStream.Flush();
        return buffer.subarray( 0, writeStream.GetBytesProcessed() );
    };

    // invalid UTF-8: 0xFF can never appear anywhere in well-formed UTF-8
    {
        const readStream = new ReadStream( doctored( [ 0xFF, 0xFE, 0xFF ] ) );
        serialize_check( serialize_string( readStream, { value: '' }, 'value', BufferSize ) === false );
    }

    // truncated UTF-8: a 3 byte lead as the final transmitted byte
    {
        const readStream = new ReadStream( doctored( [ 0x61, 0xE2 ] ) );
        serialize_check( serialize_string( readStream, { value: '' }, 'value', BufferSize ) === false );
    }

    // interior NUL: wire length 3, strlen 1 -- the TWO-LENGTHS smuggling primitive
    {
        const readStream = new ReadStream( doctored( [ 0x61, 0x00, 0x62 ] ) );
        serialize_check( serialize_string( readStream, { value: '' }, 'value', BufferSize ) === false );
    }

    // control: valid multi-byte UTF-8 -- 2, 3 and 4 byte sequences, built from explicit bytes -- still round trips
    {
        const buffer = new Uint8Array( 64 );
        const utf8 = new Uint8Array( [ 0x68, 0xC3, 0xA9, 0xE2, 0x82, 0xAC, 0xF0, 0x9F, 0x98, 0x80 ] );  // h, e-acute, euro sign, U+1F600
        const text = new TextDecoder().decode( utf8 );

        const writeStream = new WriteStream( buffer );
        serialize_check( serialize_string( writeStream, { value: text }, 'value', BufferSize ) );
        writeStream.Flush();

        // the wire carries exactly those bytes
        const expected = doctored( Array.from( utf8 ) );
        serialize_check( writeStream.GetBytesProcessed() === expected.length && bytes_equal( buffer, expected, expected.length ) );

        const read_back = { value: '' };
        const readStream = new ReadStream( buffer, writeStream.GetBytesProcessed() );
        serialize_check( serialize_string( readStream, read_back, 'value', BufferSize ) );
        serialize_check( read_back.value === text );
    }
}

function test_wstring_read_validation(): void
{
    // STANDARD.md, "Readers must refuse malformed wstring payloads".

    const BufferSize = 8;

    const doctored = ( groups: number[] ): Uint8Array =>
    {
        const buffer = new Uint8Array( 64 );
        const writeStream = new WriteStream( buffer );
        serialize_check( writeStream.SerializeInteger( groups.length, 0, BufferSize - 1 ) );
        for ( const group of groups )
            serialize_check( writeStream.SerializeBits( group, 32 ) );
        writeStream.Flush();
        return buffer.subarray( 0, writeStream.GetBytesProcessed() );
    };

    // high surrogate followed by a non-surrogate: unpaired, refused
    serialize_check( serialize_wstring( new ReadStream( doctored( [ 0xD800, 0x0041 ] ) ), { value: '' }, 'value', BufferSize ) === false );

    // low surrogate with no high before it: refused
    serialize_check( serialize_wstring( new ReadStream( doctored( [ 0xDC00 ] ) ), { value: '' }, 'value', BufferSize ) === false );

    // high surrogate as the final transmitted group: dangling, refused
    serialize_check( serialize_wstring( new ReadStream( doctored( [ 0xD83D ] ) ), { value: '' }, 'value', BufferSize ) === false );

    // interior NUL group: wire length 3, wcslen 1, refused
    serialize_check( serialize_wstring( new ReadStream( doctored( [ 0x0041, 0x0000, 0x0042 ] ) ), { value: '' }, 'value', BufferSize ) === false );

    // control: a well-formed surrogate PAIR is valid UTF-16 and must be ACCEPTED
    {
        const read_back = { value: '' };
        serialize_check( serialize_wstring( new ReadStream( doctored( [ 0xD83D, 0xDE00 ] ) ), read_back, 'value', BufferSize ) === true );
        serialize_check( read_back.value === String.fromCodePoint( 0x1F600 ) );
    }
}

function test_int_relative_validation(): void
{
    // the absolute tier must reject values that violate the previous < current contract
    {
        const buffer = new Uint8Array( 8 + 8 );

        const writeStream = new WriteStream( buffer, 8 );
        writeStream.SerializeBits( 0, 6 );              // six false bools
        writeStream.SerializeBits( 50, 32 );            // bad current
        writeStream.Flush();

        const readStream = new ReadStream( buffer, 8 );
        const current = { value: 0 };
        serialize_check( serialize_int_relative( readStream, 100, current, 'value' ) === false );
        serialize_check( current.value === 0 );        // a refused read writes nothing to the destination
    }

    // a legitimate absolute tier round trip must still succeed
    {
        const buffer = new Uint8Array( 8 + 8 );

        const writeStream = new WriteStream( buffer, 8 );
        const previous = 100;
        const written = 100000;
        serialize_check( serialize_int_relative( writeStream, previous, { value: written }, 'value' ) === true );
        writeStream.Flush();

        const readStream = new ReadStream( buffer, 8 );
        const current = { value: 0 };
        serialize_check( serialize_int_relative( readStream, previous, current, 'value' ) === true );
        serialize_check( current.value === written );
    }

    // the widest gap the domain allows: previous at the floor, current at the top
    {
        const buffer = new Uint8Array( 8 + 8 );

        const writeStream = new WriteStream( buffer, 8 );
        const previous = 0;
        const written = INT32_MAX;
        serialize_check( serialize_int_relative( writeStream, previous, { value: written }, 'value' ) === true );
        writeStream.Flush();

        const readStream = new ReadStream( buffer, 8 );
        const current = { value: 0 };
        serialize_check( serialize_int_relative( readStream, previous, current, 'value' ) === true );
        serialize_check( current.value === written );
    }

    // every tier reconstructs current in a width that cannot wrap and refuses the read when the result leaves the domain
    {
        const differences = [ 1, 2, 7, 24, 281, 4378 ];        // the one-bit tier, then the five bounded tiers

        for ( let d = 0; d < differences.length; d++ )
        {
            const buffer = new Uint8Array( 8 + 8 );

            const writeStream = new WriteStream( buffer, 8 );
            const prevWrite = 10;
            const curWrite = prevWrite + differences[d];
            serialize_check( serialize_int_relative( writeStream, prevWrite, { value: curWrite }, 'value' ) === true );
            writeStream.Flush();

            const readStream = new ReadStream( buffer, 8 );
            const previous = INT32_MAX;           // previous + difference is past the top of the domain
            const current = { value: -1 };
            serialize_check( serialize_int_relative( readStream, previous, current, 'value' ) === false );
            serialize_check( current.value === -1 );   // a refused read writes nothing to the destination
        }
    }

    // the absolute tier's 32 raw bits are UNSIGNED: a value with the top bit set is outside the domain
    {
        const buffer = new Uint8Array( 8 + 8 );

        const writeStream = new WriteStream( buffer, 8 );
        writeStream.SerializeBits( 0, 6 );
        writeStream.SerializeBits( 0x80000000, 32 );
        writeStream.Flush();

        const readStream = new ReadStream( buffer, 8 );
        const current = { value: 0 };
        serialize_check( serialize_int_relative( readStream, 100, current, 'value' ) === false );
        serialize_check( current.value === 0 );
    }
}

// STANDARD.md, Reader Obligations: failure is terminal. The first refused read latches the stream,
// and every later read on it fails, consuming no bits and writing no destination, until the stream
// is re-initialized onto a new buffer.

function test_read_stream_failure_is_terminal(): void
{
    const buffer = new Uint8Array( 64 + 8 );

    // a valid stream of known content: 8 bits of 0xAF, then a ranged int over [0,10]
    let writtenBytes = 0;
    {
        const writeStream = new WriteStream( buffer, 64 );
        writeStream.SerializeBits( 0xAF, 8 );
        writeStream.SerializeInteger( 7, 0, 10 );
        writeStream.Flush();
        writtenBytes = writeStream.GetBytesProcessed();
    }

    // failure before any consumption: the first read runs past the end of an empty stream
    {
        const readStream = new ReadStream( buffer, 0 );
        const value = { value: 0xFFFFFFFF };
        serialize_check( serialize_bits( readStream, value, 'value', 8 ) === false );
        serialize_check( value.value === 0xFFFFFFFF );
        const after = { value: -1 };
        serialize_check( serialize_int( readStream, after, 'value', 5, 5 ) === false );      // a zero bit read, which needs no bits at all
        serialize_check( after.value === -1 );
    }

    // failure after partial consumption: the first read succeeds, the second runs past the end
    {
        const readStream = new ReadStream( buffer, writtenBytes );
        const marker = { value: 0 };
        serialize_check( serialize_bits( readStream, marker, 'value', 8 ) === true );
        serialize_check( marker.value === 0xAF );
        const past_end = { value: 0xFFFFFFFF };
        serialize_check( serialize_bits( readStream, past_end, 'value', 32 ) === false );
        serialize_check( past_end.value === 0xFFFFFFFF );
        const after = { value: 0xFFFFFFFF };
        serialize_check( serialize_bits( readStream, after, 'value', 1 ) === false );         // one bit was still available before the failure
        serialize_check( after.value === 0xFFFFFFFF );
    }

    // failure on range headroom: 0xAF read as a ranged int over [0,10] is a value the range cannot hold
    {
        const readStream = new ReadStream( buffer, writtenBytes );
        const out_of_range = { value: -1 };
        serialize_check( serialize_int( readStream, out_of_range, 'value', 0, 10 ) === false );
        serialize_check( out_of_range.value === -1 );
        const after = { value: -1 };
        serialize_check( serialize_int( readStream, after, 'value', 0, 255 ) === false );
        serialize_check( after.value === -1 );
    }

    // failure on alignment: the padding bits after the 0xAF marker are not zero
    {
        const readStream = new ReadStream( buffer, writtenBytes );
        const bits = { value: 0 };
        serialize_check( serialize_bits( readStream, bits, 'value', 4 ) === true );           // leaves 4 non-zero padding bits, 0xA
        serialize_check( readStream.SerializeAlign() === false );
        const after = { value: 0xFFFFFFFF };
        serialize_check( serialize_bits( readStream, after, 'value', 4 ) === false );
        serialize_check( after.value === 0xFFFFFFFF );
    }

    // failure on a malformed string: an interior NUL among the transmitted bytes
    {
        const stringBuffer = new Uint8Array( 32 + 8 );
        let stringBytes = 0;
        {
            const writeStream = new WriteStream( stringBuffer, 32 );
            writeStream.SerializeInteger( 3, 0, 15 );                                // length 3, buffer_size 16
            writeStream.SerializeBytes( new Uint8Array( [ 0x61, 0, 0x62 ] ), 3 );
            writeStream.SerializeBits( 0x2A, 8 );
            writeStream.Flush();
            stringBytes = writeStream.GetBytesProcessed();
        }

        const readStream = new ReadStream( stringBuffer, stringBytes );
        const string = { value: 'untouched' };
        serialize_check( serialize_string( readStream, string, 'value', 16 ) === false );
        serialize_check( string.value === 'untouched' );
        const after = { value: 0xFFFFFFFF };
        serialize_check( serialize_bits( readStream, after, 'value', 8 ) === false );          // the trailing byte is still in the stream
        serialize_check( after.value === 0xFFFFFFFF );
    }

    // failure on int_relative: a reconstruction past the top of the domain
    {
        const relativeBuffer = new Uint8Array( 8 + 8 );
        {
            const writeStream = new WriteStream( relativeBuffer, 8 );
            writeStream.SerializeBits( 1, 1 );          // the one bit tier
            writeStream.SerializeBits( 0x2A, 8 );
            writeStream.Flush();
        }

        const readStream = new ReadStream( relativeBuffer, 8 );
        const current = { value: -1 };
        serialize_check( serialize_int_relative( readStream, INT32_MAX, current, 'value' ) === false );
        serialize_check( current.value === -1 );
        const after = { value: 0xFFFFFFFF };
        serialize_check( serialize_bits( readStream, after, 'value', 8 ) === false );          // the trailing byte is still in the stream
        serialize_check( after.value === 0xFFFFFFFF );
    }

    // re-initialization is what clears the latch: the same stream object reads cleanly afterwards
    {
        const readStream = new ReadStream( buffer, 0 );
        const value = { value: 0 };
        serialize_check( serialize_bits( readStream, value, 'value', 8 ) === false );
        readStream.Initialize( buffer, writtenBytes );
        serialize_check( serialize_bits( readStream, value, 'value', 8 ) === true );
        serialize_check( value.value === 0xAF );
    }
}

function test_compressed_float_validation(): void
{
    // a malicious packet can encode integer values above maxIntegerValue in the bit headroom. reads must reject them.
    {
        const buffer = new Uint8Array( 8 + 8 );

        const writeStream = new WriteStream( buffer, 8 );
        writeStream.SerializeBits( 1023, 10 );          // maxIntegerValue is 1000 for [0,10] at res 0.01 -> 10 bits
        writeStream.Flush();

        const readStream = new ReadStream( buffer, 8 );
        const value = { value: 0 };
        serialize_check( serialize_compressed_float( readStream, value, 'value', 0, 10, 0.01 ) === false );
    }

    // huge delta / res ratios must not overflow the uint32 quantization range
    {
        const buffer = new Uint8Array( 8 + 8 );

        const writeStream = new WriteStream( buffer, 8 );
        const written = f32( 5000000000.0 );
        serialize_check( serialize_compressed_float( writeStream, { value: written }, 'value', 0, 10000000000.0, 1.0 ) === true );
        writeStream.Flush();

        const readStream = new ReadStream( buffer, 8 );
        const value = { value: 0 };
        serialize_check( serialize_compressed_float( readStream, value, 'value', 0, 10000000000.0, 1.0 ) === true );
        serialize_check( Math.abs( value.value - written ) <= 4096 );
    }

    // writing NaN is non-conforming and asserts (test_compressed_float_non_finite_asserts). in the release
    // build the asserts are off and the clamp is the backstop: a NaN value must not reach the uint32 conversion
    serialize_test_release_build( () =>
    {
        const buffer = new Uint8Array( 8 + 8 );

        const writeStream = new WriteStream( buffer, 8 );
        serialize_check( serialize_compressed_float( writeStream, { value: bits_to_float( 0x7fc00000 ) }, 'value', 0, 10, 0.01 ) === true );
        writeStream.Flush();

        const readStream = new ReadStream( buffer, 8 );
        const value = { value: -1 };
        serialize_check( serialize_compressed_float( readStream, value, 'value', 0, 10, 0.01 ) === true );
        serialize_check( value.value >= 0 && value.value <= 10 );      // NaN clamps to the low end of the range
    } );
}

function serialize_test_write_non_finite_declaration(): void
{
    // delta = max - min overflows float32 to +Inf: a non-conforming declaration
    const writeStream = new WriteStream( new Uint8Array( 8 ) );
    serialize_compressed_float( writeStream, { value: 0 }, 'value', -3e38, 3e38, 1.0 );
}

function serialize_test_write_non_finite_value(): void
{
    // a NaN value over a perfectly good declaration: a non-conforming write
    const writeStream = new WriteStream( new Uint8Array( 8 ) );
    serialize_compressed_float( writeStream, { value: bits_to_float( 0x7fc00000 ) }, 'value', 0, 10, 0.01 );
}

function serialize_test_write_non_finite_value_precomputed(): void
{
    // the same non-conforming NaN write, through the precomputed entry point directly
    const writeStream = new WriteStream( new Uint8Array( 8 ) );
    serialize_compressed_float_precomputed( writeStream, { value: bits_to_float( 0x7fc00000 ) }, 'value', 1000, 10, 10, 0 );
}

function serialize_test_precomputed_inconsistent_bits(): void
{
    // a wire width that disagrees with the step count is a caller bug
    const writeStream = new WriteStream( new Uint8Array( 8 ) );
    serialize_compressed_float_precomputed( writeStream, { value: 5 }, 'value', 1000, 11, 10, 0 );
}

function test_compressed_float_non_finite_asserts(): void
{
    // a declaration whose delta or values is not finite in float32 is non-conforming, and writing a non-finite value is non-conforming. prove each assert fires.
    serialize_check( serialize_test_assert_fires( serialize_test_write_non_finite_declaration ) === true );
    serialize_check( serialize_test_assert_fires( serialize_test_write_non_finite_value ) === true );
}

function test_compressed_float_precomputed_asserts(): void
{
    serialize_check( serialize_test_assert_fires( serialize_test_write_non_finite_value_precomputed ) === true );
    serialize_check( serialize_test_assert_fires( serialize_test_precomputed_inconsistent_bits ) === true );
}

function test_compressed_float_precomputed_validation(): void
{
    const params = serialize_compressed_float_params( 0, 10, 0.01 );
    const max_integer_value = params.max_integer_value;
    const bits = params.bits;
    const delta = params.delta;
    serialize_check( max_integer_value === 1000 );
    serialize_check( bits === 10 );
    serialize_check( delta === 10 );

    // a malicious packet can encode integer values above max_integer_value in the bit headroom. reads must reject them.
    {
        const buffer = new Uint8Array( 8 + 8 );

        const writeStream = new WriteStream( buffer, 8 );
        writeStream.SerializeBits( 1023, 10 );
        writeStream.Flush();

        const readStream = new ReadStream( buffer, 8 );
        serialize_check( serialize_compressed_float_precomputed( readStream, { value: 0 }, 'value', max_integer_value, bits, delta, 0 ) === false );
    }

    // the highest conforming integer still decodes
    {
        const buffer = new Uint8Array( 8 + 8 );

        const writeStream = new WriteStream( buffer, 8 );
        writeStream.SerializeBits( 1000, 10 );
        writeStream.Flush();

        const readStream = new ReadStream( buffer, 8 );
        const value = { value: 0 };
        serialize_check( serialize_compressed_float_precomputed( readStream, value, 'value', max_integer_value, bits, delta, 0 ) === true );
        serialize_check( value.value === 10 );                  // 1000 / 1000 * 10 + 0: exact at the top of the range
    }
}

// Fixed point test helpers. Every configuration in the matrix runs the same case list, and every
// round trip also runs the measure stream and requires exact agreement with the write stream.
// Raw values travel through the helpers as bigint and are narrowed to the storage type's slot type.

type FixedHolder = { value: number | bigint };

function fixed_storage_wrap( raw: bigint, storage: FixedStorage ): bigint
{
    return BigInt( fixed_storage_value( raw, storage ) );
}

function fixed_holder( raw: bigint, storage: FixedStorage ): FixedHolder
{
    return { value: fixed_storage_value( raw, storage ) };
}

function fixed_serialize( stream: BaseStream, holder: FixedHolder, integer_bits: number, fraction_bits: number, min: bigint, max: bigint, storage: FixedStorage ): boolean
{
    if ( fixed_storage_bits( storage ) <= 32 )
    {
        return serialize_fixed( stream, holder as { value: number }, 'value', integer_bits, fraction_bits, min, max, storage as FixedStorageNarrow );
    }
    return serialize_fixed( stream, holder as { value: bigint }, 'value', integer_bits, fraction_bits, min, max, storage as FixedStorageWide );
}

function check_fixed_round_trip( integer_bits: number, fraction_bits: number, min: bigint, max: bigint, storage: FixedStorage, raw_value: bigint ): void
{
    const buffer = new Uint8Array( 32 + 8 );

    const writeStream = new WriteStream( buffer, 32 );
    serialize_check( fixed_serialize( writeStream, fixed_holder( raw_value, storage ), integer_bits, fraction_bits, min, max, storage ) === true );
    writeStream.Flush();

    const measureStream = new MeasureStream();
    serialize_check( fixed_serialize( measureStream, fixed_holder( raw_value, storage ), integer_bits, fraction_bits, min, max, storage ) === true );
    serialize_check( measureStream.GetBitsProcessed() === writeStream.GetBitsProcessed() );

    const readStream = new ReadStream( buffer, writeStream.GetBytesProcessed() );
    const read_back = fixed_holder( 0n, storage );
    serialize_check( fixed_serialize( readStream, read_back, integer_bits, fraction_bits, min, max, storage ) === true );
    serialize_check( read_back.value === fixed_storage_value( raw_value, storage ) );
}

function check_fixed_cases( integer_bits: number, fraction_bits: number, min: bigint, max: bigint, storage: FixedStorage, one_unit: bigint ): void
{
    const rt = ( raw: bigint ): void => check_fixed_round_trip( integer_bits, fraction_bits, min, max, storage, raw );
    const wrap = ( raw: bigint ): bigint => fixed_storage_wrap( raw, storage );

    const raw_min = wrap( one_unit * min );
    const raw_max = wrap( one_unit * max );

    // exact raw bounds, and one raw step inside each
    rt( raw_min );
    rt( raw_max );
    rt( wrap( raw_min + 1n ) );
    rt( wrap( raw_max - 1n ) );

    // whole unit values one unit inside each bound
    rt( wrap( one_unit * ( min + 1n ) ) );
    rt( wrap( one_unit * ( max - 1n ) ) );

    // a value with every fraction bit set
    rt( wrap( raw_min + one_unit - 1n ) );

    // the middle of the range (bigint division truncates toward zero, like C++)
    rt( wrap( raw_min / 2n + raw_max / 2n ) );

    // zero, one and minus one whole units, where the bounds allow them
    if ( min <= 0n && max >= 0n )
    {
        rt( 0n );
    }
    if ( min <= 1n && max >= 1n )
    {
        rt( one_unit );
    }
    if ( min <= -1n && max >= -1n )
    {
        rt( wrap( 0n - one_unit ) );
    }
}

function check_fixed_rejects_out_of_range( integer_bits: number, fraction_bits: number, min: bigint, max: bigint, storage: FixedStorage ): void
{
    // recompute the wire parameters independently of the codec, then hand build a stream encoding
    // an offset of exactly raw_range + 1: one raw step past raw_max, smuggled into the bit headroom
    const fb = BigInt( fraction_bits );
    const raw_range = BigInt.asUintN( 64, BigInt.asUintN( 64, BigInt.asUintN( 64, max ) << fb ) - BigInt.asUintN( 64, BigInt.asUintN( 64, min ) << fb ) );
    const bits = bits_required64( 0n, raw_range );

    const max_encodable = ( bits < 64 ) ? ( ( 1n << BigInt( bits ) ) - 1n ) : 0xFFFFFFFFFFFFFFFFn;
    if ( raw_range === max_encodable )
    {
        return;                             // no headroom: every encoding decodes in range for this configuration
    }

    const smuggled = raw_range + 1n;

    const buffer = new Uint8Array( 16 + 8 );

    const writeStream = new WriteStream( buffer, 16 );
    if ( bits <= 32 )
    {
        writeStream.SerializeBits( Number( smuggled ), bits );
    }
    else
    {
        writeStream.SerializeBits( Number( smuggled & 0xFFFFFFFFn ), 32 );
        writeStream.SerializeBits( Number( smuggled >> 32n ), bits - 32 );
    }
    writeStream.Flush();

    const readStream = new ReadStream( buffer, 16 );
    const value = fixed_holder( 0n, storage );
    serialize_check( fixed_serialize( readStream, value, integer_bits, fraction_bits, min, max, storage ) === false );
    serialize_check( value.value === fixed_storage_value( 0n, storage ) );          // a refused read writes nothing
}

function test_serialize_fixed(): void
{
    // int16_t
    check_fixed_cases( 8, 8, -100n, 100n, 'int16', 256n );
    check_fixed_cases( 12, 4, -2000n, 2000n, 'int16', 16n );

    // int32_t
    check_fixed_cases( 16, 16, -30000n, 30000n, 'int32', 65536n );
    check_fixed_cases( 24, 8, -8000000n, 8000000n, 'int32', 256n );
    check_fixed_cases( 32, 0, -100000n, 100000n, 'int32', 1n );                                  // pure integer Q: fraction_bits == 0 is legal

    // int64_t
    check_fixed_cases( 48, 16, -100000000000n, 100000000000n, 'int64', 65536n );
    check_fixed_cases( 32, 32, -1000000n, 1000000n, 'int64', 1n << 32n );
    check_fixed_cases( 64, 0, -5000000000n, 5000000000n, 'int64', 1n );                         // pure integer Q at full width

    // unsigned storage
    check_fixed_cases( 16, 0, 0n, 60000n, 'uint16', 1n );
    check_fixed_cases( 16, 16, 0n, 60000n, 'uint32', 65536n );
    check_fixed_cases( 48, 16, 0n, 1000000000n, 'uint64', 65536n );

    // single unit range: the whole wire is the fractional part
    check_fixed_cases( 16, 16, 0n, 1n, 'int32', 65536n );

    // asymmetric bounds
    check_fixed_cases( 48, 16, -3n, 100000n, 'int64', 65536n );

    // eight bit storage, which upstream's trait table also covers
    check_fixed_cases( 4, 4, -7n, 7n, 'int8', 16n );
    check_fixed_cases( 8, 0, 0n, 200n, 'uint8', 1n );

    // the wire cost is a constant of the call site. pin a few
    {
        const stream = new WriteStream( new Uint8Array( 16 ) );
        const value = { value: 12345n * 65536n + 32768n };                                     // 12345.5 in Q48.16
        serialize_check( serialize_fixed( stream, value, 'value', 48, 16, -100000, +100000, 'int64' ) === true );
        serialize_check( stream.GetBitsProcessed() === 34 );         // 200000 << 16 raw values needs 34 bits
    }
    {
        const stream = new WriteStream( new Uint8Array( 8 ) );
        const value = { value: 65536 / 2 };                                                     // 0.5 in Q16.16
        serialize_check( serialize_fixed( stream, value, 'value', 16, 16, 0, 1, 'int32' ) === true );
        serialize_check( stream.GetBitsProcessed() === 17 );         // 1 << 16 raw values needs 17 bits
    }
    {
        const stream = new WriteStream( new Uint8Array( 8 ) );
        const value = { value: -832 };                                                          // -3.25 in Q8.8
        serialize_check( serialize_fixed( stream, value, 'value', 8, 8, -100, +100, 'int16' ) === true );
        serialize_check( stream.GetBitsProcessed() === 16 );         // 200 << 8 raw values needs 16 bits
    }

    // upstream's compile time refusals are asserts here. prove each fires
    {
        const stream = new WriteStream( new Uint8Array( 8 ) );
        serialize_check( serialize_test_assert_fires( () => { serialize_fixed( stream, { value: 0 }, 'value', 16, 8, 0, 100, 'int32' ); } ) );           // 16 + 8 != 32
        serialize_check( serialize_test_assert_fires( () => { serialize_fixed( stream, { value: 0 }, 'value', 16, 16, -40000, +40000, 'int32' ); } ) );  // bounds exceed Q16.16 capacity
        serialize_check( serialize_test_assert_fires( () => { serialize_fixed( stream, { value: 0 }, 'value', 16, 16, 200, 100, 'int32' ); } ) );        // min must not exceed max
    }
}

function test_serialize_fixed_validation(): void
{
    check_fixed_rejects_out_of_range( 8, 8, -100n, 100n, 'int16' );
    check_fixed_rejects_out_of_range( 12, 4, -2000n, 2000n, 'int16' );
    check_fixed_rejects_out_of_range( 16, 16, -30000n, 30000n, 'int32' );
    check_fixed_rejects_out_of_range( 24, 8, -8000000n, 8000000n, 'int32' );
    check_fixed_rejects_out_of_range( 32, 0, -100000n, 100000n, 'int32' );
    check_fixed_rejects_out_of_range( 48, 16, -100000000000n, 100000000000n, 'int64' );
    check_fixed_rejects_out_of_range( 32, 32, -1000000n, 1000000n, 'int64' );
    check_fixed_rejects_out_of_range( 64, 0, -5000000000n, 5000000000n, 'int64' );
    check_fixed_rejects_out_of_range( 16, 0, 0n, 60000n, 'uint16' );
    check_fixed_rejects_out_of_range( 16, 16, 0n, 60000n, 'uint32' );
    check_fixed_rejects_out_of_range( 48, 16, 0n, 1000000000n, 'uint64' );
    check_fixed_rejects_out_of_range( 16, 16, 0n, 1n, 'int32' );
    check_fixed_rejects_out_of_range( 48, 16, -3n, 100000n, 'int64' );

    // reads past the end of the buffer must fail cleanly
    {
        const buffer = new Uint8Array( 4 + 8 );

        const readStream = new ReadStream( buffer, 2 );
        serialize_check( serialize_fixed( readStream, { value: 0n }, 'value', 48, 16, -100000000000n, 100000000000n, 'int64' ) === false );
    }
}

function test_serialize_fixed_matches_int64(): void
{
    // for storage of 64 bits or fewer the fixed point wire format is byte identical to serialize_int64 of the raw value over the raw bounds

    const values = [ -5000000000n, -4999999999n, -1n, 0n, 1n, 12345678n, 4999999999n, 5000000000n ];

    for ( let i = 0; i < values.length; i++ )
    {
        // > 32 bit range: the two group path
        const fixed_buffer = new Uint8Array( 16 );
        const fixedStream = new WriteStream( fixed_buffer, 16 );
        serialize_check( serialize_fixed( fixedStream, { value: values[i] }, 'value', 64, 0, -5000000000n, 5000000000n, 'int64' ) === true );
        fixedStream.Flush();

        const int64_buffer = new Uint8Array( 16 );
        const int64Stream = new WriteStream( int64_buffer, 16 );
        serialize_check( int64Stream.SerializeInteger64( values[i], -5000000000n, 5000000000n ) === true );
        int64Stream.Flush();

        serialize_check( fixedStream.GetBitsProcessed() === int64Stream.GetBitsProcessed() );
        serialize_check( bytes_equal( fixed_buffer, int64_buffer, 16 ) );
    }

    // <= 32 bit range: the single group path, on 32 bit storage
    const narrow_values = [ -100000, -99999, -1, 0, +1, 54321, 99999, 100000 ];

    for ( let i = 0; i < narrow_values.length; i++ )
    {
        const fixed_buffer = new Uint8Array( 16 );
        const fixedStream = new WriteStream( fixed_buffer, 16 );
        serialize_check( serialize_fixed( fixedStream, { value: narrow_values[i] }, 'value', 32, 0, -100000, +100000, 'int32' ) === true );
        fixedStream.Flush();

        const int64_buffer = new Uint8Array( 16 );
        const int64Stream = new WriteStream( int64_buffer, 16 );
        serialize_check( int64Stream.SerializeInteger64( BigInt( narrow_values[i] ), -100000n, 100000n ) === true );
        int64Stream.Flush();

        serialize_check( fixedStream.GetBitsProcessed() === int64Stream.GetBitsProcessed() );
        serialize_check( bytes_equal( fixed_buffer, int64_buffer, 16 ) );
    }

    // the equivalence is not limited to fraction_bits == 0
    const q16_16_raw_values = [ -30000 * 65536, -( 3 * 65536 + 16384 ), 0, 65536 / 2, 12345 * 65536 + 1, 30000 * 65536 ];

    for ( let i = 0; i < q16_16_raw_values.length; i++ )
    {
        const fixed_buffer = new Uint8Array( 16 );
        const fixedStream = new WriteStream( fixed_buffer, 16 );
        serialize_check( serialize_fixed( fixedStream, { value: q16_16_raw_values[i] }, 'value', 16, 16, -30000, +30000, 'int32' ) === true );
        fixedStream.Flush();

        const int64_buffer = new Uint8Array( 16 );
        const int64Stream = new WriteStream( int64_buffer, 16 );
        serialize_check( int64Stream.SerializeInteger64( BigInt( q16_16_raw_values[i] ), -30000n * 65536n, 30000n * 65536n ) === true );
        int64Stream.Flush();

        serialize_check( fixedStream.GetBitsProcessed() === int64Stream.GetBitsProcessed() );
        serialize_check( bytes_equal( fixed_buffer, int64_buffer, 16 ) );
    }
}

function check_fixed_wide_rejects_out_of_range( integer_bits: number, fraction_bits: number, min: bigint, max: bigint, storage: FixedStorageWide ): void
{
    const fb = BigInt( fraction_bits );
    const raw_min = BigInt.asUintN( 128, min ) << fb;
    const raw_max = BigInt.asUintN( 128, max ) << fb;
    const raw_range = BigInt.asUintN( 128, BigInt.asUintN( 128, raw_max ) - BigInt.asUintN( 128, raw_min ) );

    let bits = 0;
    for ( let x = raw_range; x !== 0n; x >>= 1n )
    {
        bits++;
    }

    const max_encodable = ( bits < 128 ) ? ( ( 1n << BigInt( bits ) ) - 1n ) : ( ( 1n << 128n ) - 1n );
    if ( raw_range === max_encodable )
    {
        return;                             // no headroom: every encoding decodes in range for this configuration
    }

    let smuggled = raw_range + 1n;

    const buffer = new Uint8Array( 24 + 8 );

    const writeStream = new WriteStream( buffer, 24 );
    let bits_left = bits;
    while ( bits_left > 0 )
    {
        const group_bits = ( bits_left < 32 ) ? bits_left : 32;
        writeStream.SerializeBits( Number( smuggled & 0xFFFFFFFFn ), group_bits );
        smuggled >>= BigInt( group_bits );
        bits_left -= group_bits;
    }
    writeStream.Flush();

    const readStream = new ReadStream( buffer, 24 );
    serialize_check( serialize_fixed( readStream, { value: 0n }, 'value', integer_bits, fraction_bits, min, max, storage ) === false );
}

function test_serialize_fixed_wide(): void
{
    // upstream checks the compile time BitsRequired128 metafunction here; the runtime twin carries it
    serialize_check( bits_required128( 0n, 0n ) === 0 );
    serialize_check( bits_required128( 0n, 1n ) === 1 );
    serialize_check( bits_required128( 0n, 1n << 64n ) === 65 );
    serialize_check( bits_required128( 0n, ( 1n << 128n ) - 1n ) === 128 );

    // the matrix, wide
    check_fixed_cases( 112, 16, -1152921504606846976n, 1152921504606846976n, 'int128', 65536n );     // +-2^60 units: 78 bits on the wire
    check_fixed_cases( 112, 16, -2n, 2n, 'int128', 65536n );
    check_fixed_cases( 64, 64, -1000n, 1000n, 'int128', 1n << 64n );
    check_fixed_cases( 64, 64, INT64_MIN, INT64_MAX, 'int128', 1n << 64n );                              // full unit range: 128 bits on the wire
    check_fixed_cases( 112, 16, 0n, 2305843009213693952n, 'uint128', 65536n );                           // 2^61 units, unsigned

    // the 33..64 bit two group band on wide storage
    check_fixed_cases( 112, 16, -32768n, 32768n, 'int128', 65536n );                                     // 33 bits: the band's low edge
    check_fixed_cases( 112, 16, -100000000000n, 100000000000n, 'int128', 65536n );                       // 54 bits: the example's shape
    check_fixed_cases( 112, 16, -140737488355328n, 140737488355327n, 'int128', 65536n );                 // 64 bits: the band's high edge

    // the wire cost is a constant of the call site, wide paths included. pin a few
    {
        const stream = new WriteStream( new Uint8Array( 16 ) );
        serialize_check( serialize_fixed( stream, { value: 12345n * 65536n }, 'value', 112, 16, -1152921504606846976n, 1152921504606846976n, 'int128' ) === true );
        serialize_check( stream.GetBitsProcessed() === 78 );         // 2^61 << 16 raw values needs 78 bits
    }
    {
        const stream = new WriteStream( new Uint8Array( 24 ) );
        serialize_check( serialize_fixed( stream, { value: 0n }, 'value', 64, 64, INT64_MIN, INT64_MAX, 'int128' ) === true );
        serialize_check( stream.GetBitsProcessed() === 128 );        // the full unit range costs the full storage width
    }
    {
        const stream = new WriteStream( new Uint8Array( 16 ) );
        serialize_check( serialize_fixed( stream, { value: 12345678901n * 65536n }, 'value', 112, 16, -100000000000n, 100000000000n, 'int128' ) === true );
        serialize_check( stream.GetBitsProcessed() === 54 );
    }
    {
        const stream = new WriteStream( new Uint8Array( 16 ) );
        serialize_check( serialize_fixed( stream, { value: 0n }, 'value', 112, 16, -32768n, 32768n, 'int128' ) === true );
        serialize_check( stream.GetBitsProcessed() === 33 );         // the band's low edge
    }
    {
        const stream = new WriteStream( new Uint8Array( 16 ) );
        serialize_check( serialize_fixed( stream, { value: 0n }, 'value', 112, 16, -140737488355328n, 140737488355327n, 'int128' ) === true );
        serialize_check( stream.GetBitsProcessed() === 64 );         // the band's high edge
    }

    // one raw step past raw_max must be rejected on read, through every group structure
    check_fixed_wide_rejects_out_of_range( 112, 16, -1152921504606846976n, 1152921504606846976n, 'int128' );
    check_fixed_wide_rejects_out_of_range( 112, 16, -2n, 2n, 'int128' );
    check_fixed_wide_rejects_out_of_range( 64, 64, -1000n, 1000n, 'int128' );
    check_fixed_wide_rejects_out_of_range( 112, 16, 0n, 2305843009213693952n, 'uint128' );
    check_fixed_wide_rejects_out_of_range( 112, 16, -32768n, 32768n, 'int128' );
    check_fixed_wide_rejects_out_of_range( 112, 16, -100000000000n, 100000000000n, 'int128' );
    check_fixed_wide_rejects_out_of_range( 112, 16, -140737488355328n, 140737488355327n, 'int128' );

    // reads past the end of the buffer must fail cleanly
    {
        const buffer = new Uint8Array( 4 + 8 );

        const readStream = new ReadStream( buffer, 4 );
        serialize_check( serialize_fixed( readStream, { value: 0n }, 'value', 112, 16, -1152921504606846976n, 1152921504606846976n, 'int128' ) === false );
    }
}

function test_serialize_fixed_wide_emulated(): void
{
    // Upstream runs the wide case list through the emulated 128 bit struct and proves native and
    // emulated storage produce identical wire. There is one 128 bit representation here (bigint),
    // so the TypeScript analog pins the wide codec against the independent ranged codec instead:
    // the wide fixed point wire is serialize_int128 of the raw value over the raw bounds, byte for
    // byte, and each decodes the other's bytes.
    const shapes: [ number, number, bigint, bigint ][] =
    [
        [ 112, 16, -1152921504606846976n, 1152921504606846976n ],
        [ 112, 16, -2n, 2n ],
        [ 64, 64, -1000n, 1000n ],
        [ 64, 64, INT64_MIN, INT64_MAX ],
        [ 112, 16, -32768n, 32768n ],
        [ 112, 16, -100000000000n, 100000000000n ],
        [ 112, 16, -140737488355328n, 140737488355327n ],
    ];

    for ( const [ integer_bits, fraction_bits, min, max ] of shapes )
    {
        const one_unit = 1n << BigInt( fraction_bits );
        const raw_min = min * one_unit;
        const raw_max = max * one_unit;
        const raws = [ raw_min, raw_max, raw_min + 1n, raw_max - 1n, raw_min / 2n + raw_max / 2n, -( 54321n * one_unit + 12345n ) ];
        for ( const raw of raws )
        {
            if ( raw < raw_min || raw > raw_max )
                continue;

            const fixed_buffer = new Uint8Array( 24 );
            const fixedStream = new WriteStream( fixed_buffer );
            serialize_check( serialize_fixed( fixedStream, { value: raw }, 'value', integer_bits, fraction_bits, min, max, 'int128' ) === true );
            fixedStream.Flush();

            const int128_buffer = new Uint8Array( 24 );
            const int128Stream = new WriteStream( int128_buffer );
            serialize_check( int128Stream.SerializeInteger128( raw, raw_min, raw_max ) === true );
            int128Stream.Flush();

            serialize_check( fixedStream.GetBitsProcessed() === int128Stream.GetBitsProcessed() );
            serialize_check( bytes_equal( fixed_buffer, int128_buffer, 24 ) );

            const read_fixed_back = { value: 0n };
            serialize_check( serialize_fixed( new ReadStream( int128_buffer, int128Stream.GetBytesProcessed() ), read_fixed_back, 'value', integer_bits, fraction_bits, min, max, 'int128' ) );
            serialize_check( read_fixed_back.value === raw );

            const readStream = new ReadStream( fixed_buffer, fixedStream.GetBytesProcessed() );
            serialize_check( readStream.SerializeInteger128( 0n, raw_min, raw_max ) );
            serialize_check( readStream.value_bigint === raw );
        }
    }
}

function test_serialize_fixed_degenerate(): void
{
    // STANDARD.md: a degenerate range where min == max is LEGAL and costs ZERO BITS on every storage width

    // narrow storage: Q16.16
    {
        const buffer = new Uint8Array( 16 );

        const writeStream = new WriteStream( buffer, 16 );
        serialize_check( serialize_fixed( writeStream, { value: 5 * 65536 }, 'value', 16, 16, 5, 5, 'int32' ) === true );
        serialize_check( writeStream.GetBitsProcessed() === 0 );      // nothing written
        serialize_check( writeStream.SerializeInteger( 3, 0, 7 ) );
        serialize_check( writeStream.GetBitsProcessed() === 3 );      // the NEXT field starts at bit 0
        writeStream.Flush();

        const readStream = new ReadStream( buffer, writeStream.GetBytesProcessed() );
        const read_degenerate = { value: 0 };
        const read_after = { value: 0 };
        serialize_check( serialize_fixed( readStream, read_degenerate, 'value', 16, 16, 5, 5, 'int32' ) === true );
        serialize_check( read_degenerate.value === 5 * 65536 );       // recovered from the range
        serialize_check( readStream.GetBitsProcessed() === 0 );
        serialize_check( serialize_int( readStream, read_after, 'value', 0, 7 ) );
        serialize_check( read_after.value === 3 );

        const measureStream = new MeasureStream();
        serialize_check( serialize_fixed( measureStream, { value: 5 * 65536 }, 'value', 16, 16, 5, 5, 'int32' ) === true );
        serialize_check( measureStream.GetBitsProcessed() === 0 );
    }

    // narrow storage, negative degenerate bound: Q48.16 at -7.0
    {
        const buffer = new Uint8Array( 16 );

        const writeStream = new WriteStream( buffer, 16 );
        serialize_check( serialize_fixed( writeStream, { value: -7n * 65536n }, 'value', 48, 16, -7, -7, 'int64' ) === true );
        serialize_check( writeStream.GetBitsProcessed() === 0 );
        serialize_check( writeStream.SerializeInteger( 3, 0, 7 ) );
        writeStream.Flush();

        const readStream = new ReadStream( buffer, writeStream.GetBytesProcessed() );
        const read_degenerate = { value: 0n };
        const read_after = { value: 0 };
        serialize_check( serialize_fixed( readStream, read_degenerate, 'value', 48, 16, -7, -7, 'int64' ) === true );
        serialize_check( read_degenerate.value === -7n * 65536n );
        serialize_check( serialize_int( readStream, read_after, 'value', 0, 7 ) );
        serialize_check( read_after.value === 3 );
    }

    // wide storage: Q112.16 -- zero bits here, exactly like the narrow path
    {
        const buffer = new Uint8Array( 16 );

        const writeStream = new WriteStream( buffer, 16 );
        serialize_check( serialize_fixed( writeStream, { value: 9n * 65536n }, 'value', 112, 16, 9, 9, 'int128' ) === true );
        serialize_check( writeStream.GetBitsProcessed() === 0 );      // zero bits, NOT fraction_bits
        serialize_check( writeStream.SerializeInteger( 3, 0, 7 ) );
        serialize_check( writeStream.GetBitsProcessed() === 3 );
        writeStream.Flush();

        const readStream = new ReadStream( buffer, writeStream.GetBytesProcessed() );
        const read_degenerate = { value: 0n };
        const read_after = { value: 0 };
        serialize_check( serialize_fixed( readStream, read_degenerate, 'value', 112, 16, 9, 9, 'int128' ) === true );
        serialize_check( read_degenerate.value === 9n * 65536n );
        serialize_check( readStream.GetBitsProcessed() === 0 );
        serialize_check( serialize_int( readStream, read_after, 'value', 0, 7 ) );
        serialize_check( read_after.value === 3 );

        const measureStream = new MeasureStream();
        serialize_check( serialize_fixed( measureStream, { value: 9n * 65536n }, 'value', 112, 16, 9, 9, 'int128' ) === true );
        serialize_check( measureStream.GetBitsProcessed() === 0 );
    }

    // wide storage, negative degenerate bound: Q112.16 at -9.0
    {
        const buffer = new Uint8Array( 16 );

        const writeStream = new WriteStream( buffer, 16 );
        serialize_check( serialize_fixed( writeStream, { value: -9n * 65536n }, 'value', 112, 16, -9, -9, 'int128' ) === true );
        serialize_check( writeStream.GetBitsProcessed() === 0 );
        serialize_check( writeStream.SerializeInteger( 3, 0, 7 ) );
        writeStream.Flush();

        const readStream = new ReadStream( buffer, writeStream.GetBytesProcessed() );
        const read_degenerate = { value: 0n };
        const read_after = { value: 0 };
        serialize_check( serialize_fixed( readStream, read_degenerate, 'value', 112, 16, -9, -9, 'int128' ) === true );
        serialize_check( read_degenerate.value === -9n * 65536n );
        serialize_check( serialize_int( readStream, read_after, 'value', 0, 7 ) );
        serialize_check( read_after.value === 3 );
    }

    // wide storage: Q64.64 over min == max == 0. the old wide formula would have made this 64 bits of zeros
    {
        const buffer = new Uint8Array( 16 );

        const writeStream = new WriteStream( buffer, 16 );
        serialize_check( serialize_fixed( writeStream, { value: 0n }, 'value', 64, 64, 0, 0, 'int128' ) === true );
        serialize_check( writeStream.GetBitsProcessed() === 0 );      // zero bits, not the 64 bit fractional field
        serialize_check( writeStream.SerializeInteger( 3, 0, 7 ) );
        writeStream.Flush();

        const readStream = new ReadStream( buffer, writeStream.GetBytesProcessed() );
        const read_degenerate = { value: 1n };                      // a wrong value, so recovery is observable
        const read_after = { value: 0 };
        serialize_check( serialize_fixed( readStream, read_degenerate, 'value', 64, 64, 0, 0, 'int128' ) === true );
        serialize_check( read_degenerate.value === 0n );
        serialize_check( serialize_int( readStream, read_after, 'value', 0, 7 ) );
        serialize_check( read_after.value === 3 );
    }

    // a failed stream refuses even the zero bit degenerate field
    {
        const readStream = new ReadStream( new Uint8Array( 8 ), 0 );
        serialize_check( readStream.SerializeBits( 0, 1 ) === false );
        const value = { value: -1 };
        serialize_check( serialize_fixed( readStream, value, 'value', 16, 16, 5, 5, 'int32' ) === false );
        serialize_check( value.value === -1 );
    }
}

function test_serialize_uint128(): void
{
    // round trips across the value patterns: zero, max, each half alone, alternating bits, distinct halves
    {
        const values =
        [
            0n,
            ( 1n << 128n ) - 1n,
            0xFFFFFFFFFFFFFFFFn << 64n,                                 // high half only
            0xFFFFFFFFFFFFFFFFn,                                        // low half only
            ( 0xAAAAAAAAAAAAAAAAn << 64n ) | 0x5555555555555555n,       // alternating bits
            ( 0x0123456789ABCDEFn << 64n ) | 0xFEDCBA9876543210n,       // distinct halves
        ];

        for ( let i = 0; i < values.length; i++ )
        {
            const buffer = new Uint8Array( 16 + 8 );

            const writeStream = new WriteStream( buffer, 16 );
            serialize_check( serialize_uint128( writeStream, { value: values[i] }, 'value' ) === true );
            writeStream.Flush();

            const measureStream = new MeasureStream();
            serialize_check( serialize_uint128( measureStream, { value: values[i] }, 'value' ) === true );
            serialize_check( measureStream.GetBitsProcessed() === writeStream.GetBitsProcessed() );
            serialize_check( writeStream.GetBitsProcessed() === 128 );

            const readStream = new ReadStream( buffer, writeStream.GetBytesProcessed() );
            const read_back = { value: 0n };
            serialize_check( serialize_uint128( readStream, read_back, 'value' ) === true );
            serialize_check( read_back.value === values[i] );
        }
    }

    // cross form consistency: serialize_uint128 must be byte identical to two serialize_uint64 operations on the halves, low half first
    {
        const low_half = 0xFEDCBA9876543210n;
        const high_half = 0x0123456789ABCDEFn;

        const uint128_buffer = new Uint8Array( 16 + 8 );
        const uint128Stream = new WriteStream( uint128_buffer, 16 );
        serialize_check( serialize_uint128( uint128Stream, { value: ( high_half << 64n ) | low_half }, 'value' ) === true );
        uint128Stream.Flush();

        const halves_buffer = new Uint8Array( 16 + 8 );
        const halvesStream = new WriteStream( halves_buffer, 16 );
        write_uint64( halvesStream, low_half );
        write_uint64( halvesStream, high_half );
        halvesStream.Flush();

        serialize_check( uint128Stream.GetBitsProcessed() === halvesStream.GetBitsProcessed() );
        serialize_check( bytes_equal( uint128_buffer, halves_buffer, 16 ) );
    }

    // golden pin: the wire format for a uint128 is its 16 bytes in little endian order, low half first
    {
        const golden_uint128_bytes = new Uint8Array(
        [
            0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE,
            0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01
        ] );

        const golden_value = ( 0x0123456789ABCDEFn << 64n ) | 0xFEDCBA9876543210n;

        const buffer = new Uint8Array( 16 + 8 );

        const writeStream = new WriteStream( buffer, 16 );
        serialize_check( serialize_uint128( writeStream, { value: golden_value }, 'value' ) === true );
        writeStream.Flush();
        serialize_check( writeStream.GetBytesProcessed() === 16 );
        serialize_check( bytes_equal( buffer, golden_uint128_bytes, 16 ) );

        buffer.set( golden_uint128_bytes );
        const readStream = new ReadStream( buffer, 16 );
        const read_back = { value: 0n };
        serialize_check( serialize_uint128( readStream, read_back, 'value' ) === true );
        serialize_check( read_back.value === golden_value );
    }
}

function test_serialize_int128(): void
{
    const INT128_MIN = -( 1n << 127n );
    const INT128_MAX = ( 1n << 127n ) - 1n;

    // 1. WIRE IDENTITY WITH serialize_int64 wherever the range fits 64 bits
    {
        const min64 = -5000000000n;
        const max64 = 5000000000n;
        const values = [ min64, min64 + 1n, -1n, 0n, 1n, 4123456789n, max64 - 1n, max64 ];

        for ( let i = 0; i < values.length; i++ )
        {
            const buffer128 = new Uint8Array( 32 + 8 );
            const buffer64 = new Uint8Array( 32 + 8 );

            const w128 = new WriteStream( buffer128, 32 );
            serialize_check( w128.SerializeInteger128( values[i], min64, max64 ) === true );
            w128.Flush();

            const w64 = new WriteStream( buffer64, 32 );
            serialize_check( w64.SerializeInteger64( values[i], min64, max64 ) === true );
            w64.Flush();

            serialize_check( w128.GetBitsProcessed() === w64.GetBitsProcessed() );
            serialize_check( w128.GetBytesProcessed() === w64.GetBytesProcessed() );
            serialize_check( bytes_equal( buffer128, buffer64, w64.GetBytesProcessed() ) );

            const readStream = new ReadStream( buffer128, 32 );
            serialize_check( readStream.SerializeInteger128( 0n, min64, max64 ) === true );
            serialize_check( readStream.value_bigint === values[i] );
        }
    }

    // 2. the wide bands the 64 bit path cannot express at all
    {
        const wide_min = -( 1n << 100n );
        const wide_max = ( 1n << 100n );
        const values = [ wide_min, wide_min + 1n, -1n, 0n, 1n, 1n << 99n, wide_max - 1n, wide_max ];

        for ( let i = 0; i < values.length; i++ )
        {
            const buffer = new Uint8Array( 32 + 8 );

            const writeStream = new WriteStream( buffer, 32 );
            serialize_check( writeStream.SerializeInteger128( values[i], wide_min, wide_max ) === true );
            writeStream.Flush();
            serialize_check( writeStream.GetBitsProcessed() === 102 );        // bits_required128( -2^100, 2^100 ) == 102

            const readStream = new ReadStream( buffer, 32 );
            const read_back = { value: 0n };
            serialize_check( serialize_int128( readStream, read_back, 'value', wide_min, wide_max ) === true );
            serialize_check( read_back.value === values[i] );
        }
    }

    // 3. the full 128 bit range: every group full, and the range is wider than 2^127
    {
        const values = [ INT128_MIN, INT128_MIN + 1n, -1n, 0n, 1n, INT128_MAX - 1n, INT128_MAX ];

        for ( let i = 0; i < values.length; i++ )
        {
            const buffer = new Uint8Array( 32 + 8 );

            const writeStream = new WriteStream( buffer, 32 );
            serialize_check( serialize_int128( writeStream, { value: values[i] }, 'value', INT128_MIN, INT128_MAX ) === true );
            writeStream.Flush();
            serialize_check( writeStream.GetBitsProcessed() === 128 );

            const readStream = new ReadStream( buffer, 32 );
            serialize_check( readStream.SerializeInteger128( 0n, INT128_MIN, INT128_MAX ) === true );
            serialize_check( readStream.value_bigint === values[i] );
        }
    }

    // 4. the measure stream must agree with the write stream exactly, at every group width
    {
        const cases: [ bigint, bigint, bigint ][] =
        [
            [ 0n, 0n, 255n ],
            [ 7n, -5000000000n, 5000000000n ],
            [ 1n, -( 1n << 100n ), ( 1n << 100n ) ],
            [ 0n, INT128_MIN, INT128_MAX ],
        ];

        for ( let i = 0; i < cases.length; i++ )
        {
            const buffer = new Uint8Array( 32 + 8 );

            const writeStream = new WriteStream( buffer, 32 );
            serialize_check( writeStream.SerializeInteger128( cases[i][0], cases[i][1], cases[i][2] ) === true );
            writeStream.Flush();

            const measureStream = new MeasureStream();
            serialize_check( measureStream.SerializeInteger128( cases[i][0], cases[i][1], cases[i][2] ) === true );
            serialize_check( measureStream.GetBitsProcessed() === writeStream.GetBitsProcessed() );
        }
    }

    // 5. a value outside the bounds must be REFUSED on read
    {
        const buffer = new Uint8Array( 32 + 8 );

        const writeStream = new WriteStream( buffer, 32 );
        serialize_check( writeStream.SerializeInteger128( 255n, 0n, 255n ) === true );
        writeStream.Flush();

        serialize_check( bits_required128( 0n, 200n ) === 8 );

        const readStream = new ReadStream( buffer, 32 );
        const read_back = { value: -1n };
        serialize_check( serialize_int128( readStream, read_back, 'value', 0n, 200n ) === false );
        serialize_check( read_back.value === -1n );
    }

    // 6. a truncated buffer must be refused rather than read past the end
    {
        const buffer = new Uint8Array( 32 + 8 );

        const readStream = new ReadStream( buffer, 4 );          // 32 bits available, 128 required
        serialize_check( readStream.SerializeInteger128( 0n, INT128_MIN, INT128_MAX ) === false );
    }

    // 7. THE GOLDEN PIN. Bounds of +/- 2^70 need 72 bits, which is the THREE GROUP structure: 32, 32, then 8.
    {
        const golden_int128_bytes = new Uint8Array(
        [
            0x11, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE,
            0x3F, 0x00, 0x00, 0x00
        ] );

        const golden_min = -( 1n << 70n );
        const golden_max = ( 1n << 70n );
        const golden_value = -0x0123456789ABCDEFn;

        const buffer = new Uint8Array( 16 + 8 );

        const writeStream = new WriteStream( buffer, 16 );
        serialize_check( writeStream.SerializeInteger128( golden_value, golden_min, golden_max ) === true );
        writeStream.Flush();
        serialize_check( writeStream.GetBitsProcessed() === 72 );
        serialize_check( bytes_equal( buffer, golden_int128_bytes, golden_int128_bytes.length ) );

        buffer.set( golden_int128_bytes );
        const readStream = new ReadStream( buffer, 16 );
        serialize_check( readStream.SerializeInteger128( 0n, golden_min, golden_max ) === true );
        serialize_check( readStream.value_bigint === golden_value );
    }
}

// Compile time surface tests. Every "compile time" form is held to the coverage of its runtime twin
// and to the wire identity property: given identical inputs, the bytes are identical.

function serialize_int_runtime_form( stream: BaseStream, value: { value: number }, min: number, max: number ): boolean
{
    if ( !serialize_int( stream, value, 'value', min, max ) ) return false;
    return true;
}

function serialize_int64_runtime_form( stream: BaseStream, value: { value: bigint }, min: bigint, max: bigint ): boolean
{
    if ( !serialize_int64( stream, value, 'value', min, max ) ) return false;
    return true;
}

function serialize_bits64_runtime_form( stream: BaseStream, value: { value: bigint }, bits: number ): boolean
{
    if ( !serialize_bits( stream, value, 'value', bits ) ) return false;
    return true;
}

function serialize_int_compile_time_form( stream: BaseStream, value: { value: number }, Min: number, Max: number ): boolean
{
    if ( !serialize_int_compile_time( stream, value, 'value', Min, Max ) ) return false;
    return true;
}

function serialize_int64_compile_time_form( stream: BaseStream, value: { value: bigint }, Min: bigint, Max: bigint ): boolean
{
    if ( !serialize_int64_compile_time( stream, value, 'value', Min, Max ) ) return false;
    return true;
}

function serialize_bits_compile_time_form( stream: BaseStream, value: { value: number }, Bits: number ): boolean
{
    if ( !serialize_bits_compile_time( stream, value, 'value', Bits ) ) return false;
    return true;
}

function serialize_bits64_compile_time_form( stream: BaseStream, value: { value: bigint }, Bits: number ): boolean
{
    if ( !serialize_bits64_compile_time( stream, value, 'value', Bits ) ) return false;
    return true;
}

function test_compile_time_bits_required(): void
{
    serialize_check( bits_required64_constexpr( 0n, 0n ) === 0 );
    serialize_check( bits_required64_constexpr( 0n, 1n ) === 1 );
    serialize_check( bits_required64_constexpr( 0n, 2n ) === 2 );
    serialize_check( bits_required64_constexpr( 0n, 3n ) === 2 );
    serialize_check( bits_required64_constexpr( 0n, 4n ) === 3 );
    serialize_check( bits_required64_constexpr( 0n, 7n ) === 3 );
    serialize_check( bits_required64_constexpr( 0n, 8n ) === 4 );
    serialize_check( bits_required64_constexpr( 0n, 255n ) === 8 );
    serialize_check( bits_required64_constexpr( 0n, 65535n ) === 16 );
    serialize_check( bits_required64_constexpr( 0n, 4294967295n ) === 32 );

    serialize_check( bits_required64_constexpr( 0n, 4294967296n ) === 33 );
    serialize_check( bits_required64_constexpr( 0n, 1n << 40n ) === 41 );
    serialize_check( bits_required64_constexpr( 0n, 0xFFFFFFFFFFFFFFFFn ) === 64 );
    serialize_check( bits_required64_constexpr( BigInt.asUintN( 64, INT64_MIN ), BigInt.asUintN( 64, INT64_MAX ) ) === 64 );
    serialize_check( bits_required64_constexpr( BigInt.asUintN( 64, -5000000000n ), BigInt.asUintN( 64, 5000000000n ) ) === 34 );

    // sign extended int32 bounds wrap to the same difference as the uint32 runtime path
    serialize_check( bits_required64_constexpr( BigInt.asUintN( 64, -100n ), BigInt.asUintN( 64, 100n ) ) === bits_required( -100 >>> 0, 100 ) );
    serialize_check( bits_required64_constexpr( BigInt.asUintN( 64, BigInt( INT32_MIN ) ), BigInt.asUintN( 64, BigInt( INT32_MAX ) ) ) === 32 );

    // sweep agreement with the runtime form
    for ( let max = 0; max <= 1000; max++ )
    {
        serialize_check( bits_required64_constexpr( 0n, BigInt( max ) ) === bits_required( 0, max ) );
    }
}

function check_compile_time_int_range( Min: number, Max: number, values: number[] ): void
{
    for ( let i = 0; i < values.length; i++ )
    {
        const value = values[i];

        // measure: both forms agree on cost
        const measureRuntime = new MeasureStream();
        serialize_check( serialize_int_runtime_form( measureRuntime, { value }, Min, Max ) === true );
        const measureCompileTime = new MeasureStream();
        serialize_check( serialize_int_compile_time_form( measureCompileTime, { value }, Min, Max ) === true );
        serialize_check( measureRuntime.GetBitsProcessed() === measureCompileTime.GetBitsProcessed() );

        // write: the wire identity property, byte for byte
        const buffer_runtime = new Uint8Array( 8 + 8 );
        const buffer_compile_time = new Uint8Array( 8 + 8 );

        const writeRuntime = new WriteStream( buffer_runtime, 8 );
        serialize_check( serialize_int_runtime_form( writeRuntime, { value }, Min, Max ) === true );
        writeRuntime.Flush();

        const writeCompileTime = new WriteStream( buffer_compile_time, 8 );
        serialize_check( serialize_int_compile_time_form( writeCompileTime, { value }, Min, Max ) === true );
        writeCompileTime.Flush();

        serialize_check( writeRuntime.GetBitsProcessed() === writeCompileTime.GetBitsProcessed() );
        serialize_check( bytes_equal( buffer_runtime, buffer_compile_time, 8 ) );

        // round trip through the compile time form
        const read_value = { value: 0 };
        serialize_check( serialize_int_compile_time_form( new ReadStream( buffer_compile_time, writeCompileTime.GetBytesProcessed() ), read_value, Min, Max ) === true );
        serialize_check( read_value.value === value );

        // cross decode: runtime written bytes through the compile time form
        read_value.value = 0;
        serialize_check( serialize_int_compile_time_form( new ReadStream( buffer_runtime, writeRuntime.GetBytesProcessed() ), read_value, Min, Max ) === true );
        serialize_check( read_value.value === value );
    }
}

function test_compile_time_int(): void
{
    check_compile_time_int_range( -100, +100, [ -100, -99, -37, 0, +1, +99, +100 ] );
    check_compile_time_int_range( 0, 65535, [ 0, 1, 255, 32768, 65534, 65535 ] );
    check_compile_time_int_range( INT32_MIN, INT32_MAX, [ INT32_MIN, INT32_MIN + 1, -1, 0, +1, INT32_MAX - 1, INT32_MAX ] );
    check_compile_time_int_range( -2000000000, +2000000000, [ -2000000000, -1, 0, +1000000000, +2000000000 ] );
}

function check_compile_time_int64_range( Min: bigint, Max: bigint, values: bigint[] ): void
{
    for ( let i = 0; i < values.length; i++ )
    {
        const value = values[i];

        const measureRuntime = new MeasureStream();
        serialize_check( serialize_int64_runtime_form( measureRuntime, { value }, Min, Max ) === true );
        const measureCompileTime = new MeasureStream();
        serialize_check( serialize_int64_compile_time_form( measureCompileTime, { value }, Min, Max ) === true );
        serialize_check( measureRuntime.GetBitsProcessed() === measureCompileTime.GetBitsProcessed() );

        const buffer_runtime = new Uint8Array( 8 + 8 );
        const buffer_compile_time = new Uint8Array( 8 + 8 );

        const writeRuntime = new WriteStream( buffer_runtime, 8 );
        serialize_check( serialize_int64_runtime_form( writeRuntime, { value }, Min, Max ) === true );
        writeRuntime.Flush();

        const writeCompileTime = new WriteStream( buffer_compile_time, 8 );
        serialize_check( serialize_int64_compile_time_form( writeCompileTime, { value }, Min, Max ) === true );
        writeCompileTime.Flush();

        serialize_check( writeRuntime.GetBitsProcessed() === writeCompileTime.GetBitsProcessed() );
        serialize_check( bytes_equal( buffer_runtime, buffer_compile_time, 8 ) );

        const read_value = { value: 0n };
        serialize_check( serialize_int64_compile_time_form( new ReadStream( buffer_compile_time, writeCompileTime.GetBytesProcessed() ), read_value, Min, Max ) === true );
        serialize_check( read_value.value === value );

        read_value.value = 0n;
        serialize_check( serialize_int64_compile_time_form( new ReadStream( buffer_runtime, writeRuntime.GetBytesProcessed() ), read_value, Min, Max ) === true );
        serialize_check( read_value.value === value );
    }
}

function test_compile_time_int64(): void
{
    check_compile_time_int64_range( -100n, 100n, [ -100n, -99n, -1n, 0n, 1n, 55n, 99n, 100n ] );
    check_compile_time_int64_range( -5000000000n, 5000000000n, [ -5000000000n, -5000000000n + 1n, -1n, 0n, 1n, 4123456789n, 5000000000n - 1n, 5000000000n ] );
    check_compile_time_int64_range( INT64_MIN, INT64_MAX, [ INT64_MIN, INT64_MIN + 1n, -1n, 0n, 1n, INT64_MAX - 1n, INT64_MAX ] );

    // the single dword path uses the minimal number of bits, same as the runtime form
    {
        const writeStream = new WriteStream( new Uint8Array( 8 + 8 ), 8 );
        serialize_check( SerializeInt64Const( writeStream, { value: 55n }, 'value', -100n, 100n ) === true );
        writeStream.Flush();
        serialize_check( writeStream.GetBitsProcessed() === 8 );
    }
}

function check_compile_time_bits_width( Bits: number ): void
{
    const max_value = Bits === 32 ? 0xFFFFFFFF : 2 ** Bits - 1;
    const values = [ 0, 1, max_value >>> 1, max_value ];

    for ( let i = 0; i < values.length; i++ )
    {
        const value = values[i];

        const measureRuntime = new MeasureStream();
        serialize_check( serialize_bits64_runtime_form( measureRuntime, { value: BigInt( value ) }, Bits ) === true );
        const measureCompileTime = new MeasureStream();
        serialize_check( serialize_bits_compile_time_form( measureCompileTime, { value }, Bits ) === true );
        serialize_check( measureRuntime.GetBitsProcessed() === measureCompileTime.GetBitsProcessed() );

        const buffer_runtime = new Uint8Array( 8 + 8 );
        const buffer_compile_time = new Uint8Array( 8 + 8 );

        const writeRuntime = new WriteStream( buffer_runtime, 8 );
        serialize_check( serialize_bits64_runtime_form( writeRuntime, { value: BigInt( value ) }, Bits ) === true );
        writeRuntime.Flush();

        const writeCompileTime = new WriteStream( buffer_compile_time, 8 );
        serialize_check( serialize_bits_compile_time_form( writeCompileTime, { value }, Bits ) === true );
        writeCompileTime.Flush();

        serialize_check( writeRuntime.GetBitsProcessed() === writeCompileTime.GetBitsProcessed() );
        serialize_check( bytes_equal( buffer_runtime, buffer_compile_time, 8 ) );

        const read_value = { value: 0 };
        serialize_check( serialize_bits_compile_time_form( new ReadStream( buffer_compile_time, writeCompileTime.GetBytesProcessed() ), read_value, Bits ) === true );
        serialize_check( read_value.value === value );

        read_value.value = 0;
        serialize_check( serialize_bits_compile_time_form( new ReadStream( buffer_runtime, writeRuntime.GetBytesProcessed() ), read_value, Bits ) === true );
        serialize_check( read_value.value === value );
    }
}

function check_compile_time_bits64_width( Bits: number ): void
{
    const max_value = ( 1n << BigInt( Bits ) ) - 1n;
    const values = [ 0n, 1n, max_value >> 1n, max_value ];

    for ( let i = 0; i < values.length; i++ )
    {
        const value = values[i];

        const measureRuntime = new MeasureStream();
        serialize_check( serialize_bits64_runtime_form( measureRuntime, { value }, Bits ) === true );
        const measureCompileTime = new MeasureStream();
        serialize_check( serialize_bits64_compile_time_form( measureCompileTime, { value }, Bits ) === true );
        serialize_check( measureRuntime.GetBitsProcessed() === measureCompileTime.GetBitsProcessed() );

        const buffer_runtime = new Uint8Array( 8 + 8 );
        const buffer_compile_time = new Uint8Array( 8 + 8 );

        const writeRuntime = new WriteStream( buffer_runtime, 8 );
        serialize_check( serialize_bits64_runtime_form( writeRuntime, { value }, Bits ) === true );
        writeRuntime.Flush();

        const writeCompileTime = new WriteStream( buffer_compile_time, 8 );
        serialize_check( serialize_bits64_compile_time_form( writeCompileTime, { value }, Bits ) === true );
        writeCompileTime.Flush();

        serialize_check( writeRuntime.GetBitsProcessed() === writeCompileTime.GetBitsProcessed() );
        serialize_check( bytes_equal( buffer_runtime, buffer_compile_time, 8 ) );

        const read_value = { value: 0n };
        serialize_check( serialize_bits64_compile_time_form( new ReadStream( buffer_compile_time, writeCompileTime.GetBytesProcessed() ), read_value, Bits ) === true );
        serialize_check( read_value.value === value );

        read_value.value = 0n;
        serialize_check( serialize_bits64_compile_time_form( new ReadStream( buffer_runtime, writeRuntime.GetBytesProcessed() ), read_value, Bits ) === true );
        serialize_check( read_value.value === value );
    }
}

function test_compile_time_bits(): void
{
    for ( const Bits of [ 1, 2, 7, 8, 13, 23, 31, 32 ] )
        check_compile_time_bits_width( Bits );

    for ( const Bits of [ 1, 20, 32, 33, 48, 63, 64 ] )
        check_compile_time_bits64_width( Bits );
}

function test_compile_time_int_validation(): void
{
    // bits_required(0,5) is 3 bits, so a malicious packet can encode 6 or 7. reads must reject values above max.
    {
        const buffer = new Uint8Array( 4 + 8 );

        const writeStream = new WriteStream( buffer, 8 );
        writeStream.SerializeBits( 7, 3 );
        writeStream.Flush();

        const readStream = new ReadStream( buffer, 4 );
        serialize_check( SerializeIntConst( readStream, { value: 0 }, 'value', 0, 5 ) === false );
    }

    // reads past the end of the buffer must fail cleanly
    {
        const readStream = new ReadStream( new Uint8Array( 8 + 8 ), 1 );
        serialize_check( SerializeIntConst( readStream, { value: 0 }, 'value', 0, 65535 ) === false );
    }
}

function test_compile_time_int64_validation(): void
{
    // a malicious packet can smuggle an out of range value into the bit headroom of the two dword path. reads must reject it.
    {
        const buffer = new Uint8Array( 16 + 8 );

        const writeStream = new WriteStream( buffer, 16 );
        const out_of_range = ( 1n << 34n ) + 5n;
        writeStream.SerializeBits( Number( out_of_range & 0xFFFFFFFFn ), 32 );
        writeStream.SerializeBits( Number( out_of_range >> 32n ), 3 );
        writeStream.Flush();

        const readStream = new ReadStream( buffer, 16 );
        serialize_check( SerializeInt64Const( readStream, { value: 0n }, 'value', 0n, 1n << 34n ) === false );
    }

    // reads past the end of the buffer must fail cleanly (the low dword fits, the high remainder does not)
    {
        const readStream = new ReadStream( new Uint8Array( 4 + 8 ), 4 );
        serialize_check( SerializeInt64Const( readStream, { value: 0n }, 'value', INT64_MIN, INT64_MAX ) === false );
    }
}

function test_compile_time_bits_validation(): void
{
    // reads past the end of the buffer must fail cleanly
    {
        const readStream = new ReadStream( new Uint8Array( 8 + 8 ), 1 );
        serialize_check( SerializeBitsConst( readStream, { value: 0 }, 'value', 13 ) === false );
    }

    // the two dword path: the low dword fits, the high remainder does not
    {
        const readStream = new ReadStream( new Uint8Array( 4 + 8 ), 4 );
        serialize_check( SerializeBits64Const( readStream, { value: 0n }, 'value', 48 ) === false );
    }
}

// a packet exercising every compile time form next to its runtime twin, field for field

class CompileTimeTestPacket
{
    int_a = 0;          // [-100,+100]
    int_b = 0;          // [0,65535]
    int_c = 0;          // [INT32_MIN,INT32_MAX]
    int64_small = 0n;   // [-100,+100]: single dword path
    int64_wide = 0n;    // [-5000000000,+5000000000]: two dword path
    int64_full = 0n;    // [INT64_MIN,INT64_MAX]
    bits1 = 0;
    bits7 = 0;
    bits13 = 0;
    bits23 = 0;
    bits32 = 0;
    bits48 = 0n;        // the >32 bit serialize_bits case
    bits64 = 0n;
    flag_a = false;
    flag_b = false;

    InitTypical(): void
    {
        this.int_a = -37;
        this.int_b = 12345;
        this.int_c = -123456789;
        this.int64_small = 55n;
        this.int64_wide = 4123456789n;
        this.int64_full = -123456789012345n;
        this.bits1 = 1;
        this.bits7 = 97;
        this.bits13 = 5000;
        this.bits23 = 1234567;
        this.bits32 = 0xDEADBEEF;
        this.bits48 = 0x123456789ABCn;
        this.bits64 = 0x123456789ABCDEF0n;
        this.flag_a = true;
        this.flag_b = false;
    }

    InitLow(): void          // every field at its minimum legal value
    {
        this.int_a = -100;
        this.int_b = 0;
        this.int_c = INT32_MIN;
        this.int64_small = -100n;
        this.int64_wide = -5000000000n;
        this.int64_full = INT64_MIN;
        this.bits1 = 0;
        this.bits7 = 0;
        this.bits13 = 0;
        this.bits23 = 0;
        this.bits32 = 0;
        this.bits48 = 0n;
        this.bits64 = 0n;
        this.flag_a = false;
        this.flag_b = false;
    }

    InitHigh(): void         // every field at its maximum legal value
    {
        this.int_a = +100;
        this.int_b = 65535;
        this.int_c = INT32_MAX;
        this.int64_small = 100n;
        this.int64_wide = 5000000000n;
        this.int64_full = INT64_MAX;
        this.bits1 = 1;
        this.bits7 = 127;
        this.bits13 = 8191;
        this.bits23 = 8388607;
        this.bits32 = 0xFFFFFFFF;
        this.bits48 = ( 1n << 48n ) - 1n;
        this.bits64 = 0xFFFFFFFFFFFFFFFFn;
        this.flag_a = true;
        this.flag_b = true;
    }

    SerializeRuntime( stream: BaseStream ): boolean
    {
        if ( !serialize_int( stream, this, 'int_a', -100, +100 ) ) return false;
        if ( !serialize_int( stream, this, 'int_b', 0, 65535 ) ) return false;
        if ( !serialize_int( stream, this, 'int_c', INT32_MIN, INT32_MAX ) ) return false;
        if ( !serialize_int64( stream, this, 'int64_small', -100n, 100n ) ) return false;
        if ( !serialize_int64( stream, this, 'int64_wide', -5000000000n, 5000000000n ) ) return false;
        if ( !serialize_int64( stream, this, 'int64_full', INT64_MIN, INT64_MAX ) ) return false;
        if ( !serialize_bits( stream, this, 'bits1', 1 ) ) return false;
        if ( !serialize_bits( stream, this, 'bits7', 7 ) ) return false;
        if ( !serialize_bits( stream, this, 'bits13', 13 ) ) return false;
        if ( !serialize_bits( stream, this, 'bits23', 23 ) ) return false;
        if ( !serialize_bits( stream, this, 'bits32', 32 ) ) return false;
        if ( !serialize_bits( stream, this, 'bits48', 48 ) ) return false;
        if ( !serialize_bits( stream, this, 'bits64', 64 ) ) return false;
        if ( !serialize_bool( stream, this, 'flag_a' ) ) return false;
        if ( !serialize_bool( stream, this, 'flag_b' ) ) return false;
        return true;
    }

    SerializeCompileTime( stream: BaseStream ): boolean
    {
        if ( !serialize_int_compile_time( stream, this, 'int_a', -100, +100 ) ) return false;
        if ( !serialize_int_compile_time( stream, this, 'int_b', 0, 65535 ) ) return false;
        if ( !serialize_int_compile_time( stream, this, 'int_c', INT32_MIN, INT32_MAX ) ) return false;
        if ( !serialize_int64_compile_time( stream, this, 'int64_small', -100n, 100n ) ) return false;
        if ( !serialize_int64_compile_time( stream, this, 'int64_wide', -5000000000n, 5000000000n ) ) return false;
        if ( !serialize_int64_compile_time( stream, this, 'int64_full', INT64_MIN, INT64_MAX ) ) return false;
        if ( !serialize_bits_compile_time( stream, this, 'bits1', 1 ) ) return false;
        if ( !serialize_bits_compile_time( stream, this, 'bits7', 7 ) ) return false;
        if ( !serialize_bits_compile_time( stream, this, 'bits13', 13 ) ) return false;
        if ( !serialize_bits_compile_time( stream, this, 'bits23', 23 ) ) return false;
        if ( !serialize_bits_compile_time( stream, this, 'bits32', 32 ) ) return false;
        if ( !serialize_bits64_compile_time( stream, this, 'bits48', 48 ) ) return false;
        if ( !serialize_bits64_compile_time( stream, this, 'bits64', 64 ) ) return false;
        if ( !serialize_bool_compile_time( stream, this, 'flag_a' ) ) return false;
        if ( !serialize_bool_compile_time( stream, this, 'flag_b' ) ) return false;
        return true;
    }

    equals( other: CompileTimeTestPacket ): boolean
    {
        return this.int_a === other.int_a &&
               this.int_b === other.int_b &&
               this.int_c === other.int_c &&
               this.int64_small === other.int64_small &&
               this.int64_wide === other.int64_wide &&
               this.int64_full === other.int64_full &&
               this.bits1 === other.bits1 &&
               this.bits7 === other.bits7 &&
               this.bits13 === other.bits13 &&
               this.bits23 === other.bits23 &&
               this.bits32 === other.bits32 &&
               this.bits48 === other.bits48 &&
               this.bits64 === other.bits64 &&
               this.flag_a === other.flag_a &&
               this.flag_b === other.flag_b;
    }
}

function check_compile_time_packet( packet: CompileTimeTestPacket ): void
{
    const BufferSize = 64;

    const buffer_runtime = new Uint8Array( BufferSize + 8 );
    const buffer_compile_time = new Uint8Array( BufferSize + 8 );

    const writeRuntime = new WriteStream( buffer_runtime, BufferSize );
    serialize_check( packet.SerializeRuntime( writeRuntime ) === true );
    writeRuntime.Flush();

    const writeCompileTime = new WriteStream( buffer_compile_time, BufferSize );
    serialize_check( packet.SerializeCompileTime( writeCompileTime ) === true );
    writeCompileTime.Flush();

    // the wire identity property
    serialize_check( writeRuntime.GetBitsProcessed() === writeCompileTime.GetBitsProcessed() );
    serialize_check( bytes_equal( buffer_runtime, buffer_compile_time, BufferSize ) );

    // measure streams agree with the write streams (no aligns in this packet, so the measure is exact)
    const measureRuntime = new MeasureStream();
    serialize_check( packet.SerializeRuntime( measureRuntime ) === true );
    const measureCompileTime = new MeasureStream();
    serialize_check( packet.SerializeCompileTime( measureCompileTime ) === true );
    serialize_check( measureRuntime.GetBitsProcessed() === writeRuntime.GetBitsProcessed() );
    serialize_check( measureCompileTime.GetBitsProcessed() === writeCompileTime.GetBitsProcessed() );

    const bytesWritten = writeRuntime.GetBytesProcessed();

    // cross decode: runtime written bytes through the compile time form...
    {
        const read_packet = new CompileTimeTestPacket();
        serialize_check( read_packet.SerializeCompileTime( new ReadStream( buffer_runtime, bytesWritten ) ) === true );
        serialize_check( read_packet.equals( packet ) );
    }

    // ...and compile time written bytes through the runtime form
    {
        const read_packet = new CompileTimeTestPacket();
        serialize_check( read_packet.SerializeRuntime( new ReadStream( buffer_compile_time, bytesWritten ) ) === true );
        serialize_check( read_packet.equals( packet ) );
    }
}

function test_compile_time_packet(): void
{
    const packet = new CompileTimeTestPacket();

    packet.InitTypical();
    check_compile_time_packet( packet );

    packet.InitLow();
    check_compile_time_packet( packet );

    packet.InitHigh();
    check_compile_time_packet( packet );
}

// Golden wire format test. The exact bytes produced by the serializer are pinned down here and must never change.

class GoldenWireData
{
    bits4 = 0;
    bits11 = 0;
    bits24 = 0;
    bits32 = 0;
    int_small = 0;
    int_full = 0;
    flag = false;
    float_value = 0;
    compressed_float_value = 0;
    double_value = 0;
    uint8_value = 0;
    uint16_value = 0;
    uint32_value = 0;
    uint64_value = 0n;
    relative_near = 0;
    relative_far = 0;
    bytes = new Uint8Array( 7 );
    string = '';
    wstring = '';
    fixed_q8_8 = 0;                 // int16 storage
    fixed_q16_16 = 0;               // int32 storage
    fixed_q48_16 = 0n;              // int64 storage
    fixed_q16_16_unsigned = 0;      // uint32 storage
    fixed_q112_16_wide = 0n;        // int128 storage
    fixed_q64_64_wide = 0n;         // int128 storage

    equals( other: GoldenWireData ): boolean
    {
        return this.bits4 === other.bits4 &&
               this.bits11 === other.bits11 &&
               this.bits24 === other.bits24 &&
               this.bits32 === other.bits32 &&
               this.int_small === other.int_small &&
               this.int_full === other.int_full &&
               this.flag === other.flag &&
               Object.is( this.float_value, other.float_value ) &&
               Object.is( this.compressed_float_value, other.compressed_float_value ) &&
               Object.is( this.double_value, other.double_value ) &&
               this.uint8_value === other.uint8_value &&
               this.uint16_value === other.uint16_value &&
               this.uint32_value === other.uint32_value &&
               this.uint64_value === other.uint64_value &&
               this.relative_near === other.relative_near &&
               this.relative_far === other.relative_far &&
               bytes_equal( this.bytes, other.bytes, 7 ) &&
               this.string === other.string &&
               this.wstring === other.wstring &&
               this.fixed_q8_8 === other.fixed_q8_8 &&
               this.fixed_q16_16 === other.fixed_q16_16 &&
               this.fixed_q48_16 === other.fixed_q48_16 &&
               this.fixed_q16_16_unsigned === other.fixed_q16_16_unsigned &&
               this.fixed_q112_16_wide === other.fixed_q112_16_wide &&
               this.fixed_q64_64_wide === other.fixed_q64_64_wide;
    }
}

function GoldenWireInit( data: GoldenWireData ): void
{
    data.bits4 = 13;
    data.bits11 = 1445;
    data.bits24 = 11259375;
    data.bits32 = 0xDEADBEEF;
    data.int_small = -37;
    data.int_full = -123456789;
    data.flag = true;
    data.float_value = f32( 3.1415926 );
    data.compressed_float_value = 5.0;
    data.double_value = 1.0 / 3.0;
    data.uint8_value = 0x7F;
    data.uint16_value = 0x1234;
    data.uint32_value = 0x12345678;
    data.uint64_value = 0x123456789ABCDEF0n;
    data.relative_near = 101;                   // difference of 1 from the base: exercises the one bit branch
    data.relative_far = 2100;                   // difference of 2000 from the base: exercises the twelve bit bucket
    data.bytes.set( [ 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0x01 ] );
    data.string = 'golden';
    data.wstring = String.fromCharCode( 0x043C, 0x0438, 0x0440 );                  // cyrillic, BMP only
    data.fixed_q8_8 = -( 3 * 256 + 64 );                                            // -3.25 in Q8.8
    data.fixed_q16_16 = 1234 * 65536 + 32768;                                       // 1234.5 in Q16.16
    data.fixed_q48_16 = -( 54321n * 65536n + 12345n );                              // -54321.1883... in Q48.16
    data.fixed_q16_16_unsigned = 29999 * 65536 + 65535;                             // every fraction bit set
    data.fixed_q112_16_wide = -( 98765432109n * 65536n + 4321n );                   // 75 bits on the wire, three groups
    data.fixed_q64_64_wide = ( 0x0123456789ABCDEFn << 64n ) + 0x0FEDCBA987654321n;  // 128 bits, four groups, every group distinct
}

function GoldenWireSerialize( stream: BaseStream, data: GoldenWireData ): boolean
{
    const relative_base = 100;
    if ( !serialize_bits( stream, data, 'bits4', 4 ) ) return false;
    if ( !serialize_bits( stream, data, 'bits11', 11 ) ) return false;
    if ( !serialize_bits( stream, data, 'bits24', 24 ) ) return false;
    if ( !serialize_bits( stream, data, 'bits32', 32 ) ) return false;
    if ( !serialize_int( stream, data, 'int_small', -100, +100 ) ) return false;
    if ( !serialize_int( stream, data, 'int_full', INT32_MIN, INT32_MAX ) ) return false;
    if ( !serialize_bool( stream, data, 'flag' ) ) return false;
    if ( !serialize_float( stream, data, 'float_value' ) ) return false;
    if ( !serialize_compressed_float( stream, data, 'compressed_float_value', 0.0, 10.0, 0.01 ) ) return false;
    if ( !serialize_double( stream, data, 'double_value' ) ) return false;
    if ( !serialize_uint8( stream, data, 'uint8_value' ) ) return false;
    if ( !serialize_uint16( stream, data, 'uint16_value' ) ) return false;
    if ( !serialize_uint32( stream, data, 'uint32_value' ) ) return false;
    if ( !serialize_uint64( stream, data, 'uint64_value' ) ) return false;
    if ( !serialize_int_relative( stream, relative_base, data, 'relative_near' ) ) return false;
    if ( !serialize_int_relative( stream, relative_base, data, 'relative_far' ) ) return false;
    if ( !serialize_align( stream ) ) return false;
    if ( !serialize_bytes( stream, data.bytes, 7 ) ) return false;
    if ( !serialize_string( stream, data, 'string', 16 ) ) return false;
    if ( !serialize_wstring( stream, data, 'wstring', 8 ) ) return false;
    if ( !serialize_align( stream ) ) return false;                  // the fixed point section starts byte aligned
    if ( !serialize_fixed( stream, data, 'fixed_q8_8', 8, 8, -100, +100, 'int16' ) ) return false;
    if ( !serialize_fixed( stream, data, 'fixed_q16_16', 16, 16, -2000, +2000, 'int32' ) ) return false;
    if ( !serialize_fixed( stream, data, 'fixed_q48_16', 48, 16, -100000, +100000, 'int64' ) ) return false;
    if ( !serialize_fixed( stream, data, 'fixed_q16_16_unsigned', 16, 16, 0, 30000, 'uint32' ) ) return false;
    if ( !serialize_align( stream ) ) return false;                  // the wide fixed section starts byte aligned
    if ( !serialize_fixed( stream, data, 'fixed_q112_16_wide', 112, 16, -144115188075855872n, 144115188075855872n, 'int128' ) ) return false;      // +-2^57 units: 75 bits, the three group structure
    if ( !serialize_fixed( stream, data, 'fixed_q64_64_wide', 64, 64, INT64_MIN, INT64_MAX, 'int128' ) ) return false;                              // full unit range: 128 bits, the four group structure
    return true;
}

const golden_wire_bytes = new Uint8Array(
[
    0x5D, 0xDA, 0xF7, 0xE6, 0xD5, 0x77, 0xDF, 0x56, 0xEF, 0x9F, 0x75, 0x19,
    0x52, 0xBC, 0xDA, 0x0F, 0x49, 0x40, 0xF4, 0x55, 0x55, 0x55, 0x55, 0x55,
    0x55, 0x55, 0xFF, 0xFC, 0xD1, 0x48, 0xE0, 0x59, 0xD1, 0x48, 0xC0, 0x7B,
    0xF3, 0x6A, 0xE2, 0x59, 0xD1, 0x48, 0x84, 0xB7, 0x06, 0xDE, 0xAD, 0xBE,
    0xEF, 0xCA, 0xFE, 0x01, 0x06, 0x67, 0x6F, 0x6C, 0x64, 0x65, 0x6E, 0xE3,
    0x21, 0x00, 0x00, 0xC0, 0x21, 0x00, 0x00, 0x00, 0x22, 0x00, 0x00, 0x00,
    0xC0, 0x60, 0x00, 0x80, 0xA2, 0x7C, 0xFC, 0xEC, 0x26, 0xCB, 0xFF, 0xFF,
    0x4B, 0x1D, 0x1F, 0xEF, 0xD2, 0x1A, 0x1F, 0x01, 0xE9, 0xFF, 0xFF, 0x09,
    0x19, 0x2A, 0x3B, 0x4C, 0x5D, 0x6E, 0x7F, 0x78, 0x6F, 0x5E, 0x4D, 0x3C,
    0x2B, 0x1A, 0x09, 0x04
] );

function test_golden_wire_format(): void
{
    // write side: serializing the golden values must produce exactly the golden bytes
    {
        const buffer = new Uint8Array( 256 );
        const stream = new WriteStream( buffer );
        const data = new GoldenWireData();
        GoldenWireInit( data );
        serialize_check( GoldenWireSerialize( stream, data ) === true );
        stream.Flush();
        serialize_check( stream.GetBytesProcessed() === golden_wire_bytes.length );
        serialize_check( bytes_equal( buffer, golden_wire_bytes, golden_wire_bytes.length ) );
    }

    // read side: the golden bytes must decode to the expected values, on every platform, forever
    {
        const buffer = new Uint8Array( 256 );
        buffer.set( golden_wire_bytes );
        const stream = new ReadStream( buffer, golden_wire_bytes.length );
        const data = new GoldenWireData();
        serialize_check( GoldenWireSerialize( stream, data ) === true );

        const expected = new GoldenWireData();
        GoldenWireInit( expected );
        serialize_check( data.bits4 === expected.bits4 );
        serialize_check( data.bits11 === expected.bits11 );
        serialize_check( data.bits24 === expected.bits24 );
        serialize_check( data.bits32 === expected.bits32 );
        serialize_check( data.int_small === expected.int_small );
        serialize_check( data.int_full === expected.int_full );
        serialize_check( data.flag === expected.flag );
        serialize_check( data.float_value === expected.float_value );
        serialize_check( Math.abs( data.compressed_float_value - expected.compressed_float_value ) <= f32( 0.01 ) );
        serialize_check( data.double_value === expected.double_value );
        serialize_check( data.uint8_value === expected.uint8_value );
        serialize_check( data.uint16_value === expected.uint16_value );
        serialize_check( data.uint32_value === expected.uint32_value );
        serialize_check( data.uint64_value === expected.uint64_value );
        serialize_check( data.relative_near === expected.relative_near );
        serialize_check( data.relative_far === expected.relative_far );
        serialize_check( bytes_equal( data.bytes, expected.bytes, 7 ) );
        serialize_check( data.string === expected.string );
        serialize_check( data.wstring === expected.wstring );
        serialize_check( data.fixed_q8_8 === expected.fixed_q8_8 );
        serialize_check( data.fixed_q16_16 === expected.fixed_q16_16 );
        serialize_check( data.fixed_q48_16 === expected.fixed_q48_16 );
        serialize_check( data.fixed_q16_16_unsigned === expected.fixed_q16_16_unsigned );
        serialize_check( data.fixed_q112_16_wide === expected.fixed_q112_16_wide );
        serialize_check( data.fixed_q64_64_wide === expected.fixed_q64_64_wide );
    }
}

function test_trailing_bits(): void
{
    // writer obligation: emit a message that ends 3 bits into its final byte, into a buffer pre-filled with 0xFF
    {
        const buffer = new Uint8Array( 64 ).fill( 0xFF );

        const writeStream = new WriteStream( buffer );
        serialize_check( writeStream.SerializeBits( 0xDEADBEEF, 32 ) === true );
        serialize_check( writeStream.SerializeBits( 5, 3 ) === true );
        writeStream.Flush();

        const bytesWritten = writeStream.GetBytesProcessed();
        const bitsInFinalByte = writeStream.GetBitsProcessed() % 8;
        serialize_check( bitsInFinalByte === 3 );                                        // the stream really does end unaligned
        const trailingMask = ( 0xFF << bitsInFinalByte ) & 0xFF;
        serialize_check( ( buffer[bytesWritten-1] & trailingMask ) === 0 );               // writers must write zero

        // reader indifference, small stream: set every trailing bit and read back
        buffer[bytesWritten-1] |= trailingMask;
        const readStream = new ReadStream( buffer, bytesWritten );
        serialize_check( readStream.SerializeBits( 0, 32 ) === true );
        serialize_check( readStream.value === 0xDEADBEEF );
        serialize_check( readStream.SerializeBits( 0, 3 ) === true );
        serialize_check( readStream.value === 5 );
    }

    // reader indifference, full message: doctor the trailing bits of the golden stream
    {
        const buffer = new Uint8Array( 256 );
        buffer.set( golden_wire_bytes );

        const cleanStream = new ReadStream( buffer, golden_wire_bytes.length );
        const cleanData = new GoldenWireData();
        serialize_check( GoldenWireSerialize( cleanStream, cleanData ) === true );

        const bitsInFinalByte = cleanStream.GetBitsProcessed() % 8;
        serialize_check( bitsInFinalByte !== 0 );                                        // golden ends unaligned, so this test can discriminate
        const trailingMask = ( 0xFF << bitsInFinalByte ) & 0xFF;
        serialize_check( ( golden_wire_bytes[golden_wire_bytes.length - 1] & trailingMask ) === 0 );

        buffer[golden_wire_bytes.length - 1] |= trailingMask;                            // set every trailing bit

        const doctoredStream = new ReadStream( buffer, golden_wire_bytes.length );
        const doctoredData = new GoldenWireData();
        serialize_check( GoldenWireSerialize( doctoredStream, doctoredData ) === true );   // readers must not reject
        serialize_check( doctoredData.equals( cleanData ) );                              // and must decode identically
        serialize_check( doctoredStream.GetBitsProcessed() === cleanStream.GetBitsProcessed() );
    }
}

function test_past_end_poison(): void
{
    // bytes past the end of the stream must never be interpreted: poison planted beyond the stream end must not change a single decoded byte, and must not change refusal behavior

    // accept path: identical decode with a zeroed tail and a poisoned tail
    {
        const cleanBuffer = new Uint8Array( 256 );
        const poisonBuffer = new Uint8Array( 256 ).fill( 0xFF );
        cleanBuffer.set( golden_wire_bytes );
        poisonBuffer.set( golden_wire_bytes );

        const cleanStream = new ReadStream( cleanBuffer, golden_wire_bytes.length );
        const cleanData = new GoldenWireData();
        serialize_check( GoldenWireSerialize( cleanStream, cleanData ) === true );

        const poisonStream = new ReadStream( poisonBuffer, golden_wire_bytes.length );
        const poisonData = new GoldenWireData();
        serialize_check( GoldenWireSerialize( poisonStream, poisonData ) === true );

        serialize_check( poisonData.equals( cleanData ) );
        serialize_check( poisonStream.GetBitsProcessed() === cleanStream.GetBitsProcessed() );
    }

    // refusal path: truncate the stream one byte short so the decode must fail
    {
        const truncatedBytes = golden_wire_bytes.length - 1;

        const cleanBuffer = new Uint8Array( 256 );
        const poisonBuffer = new Uint8Array( 256 ).fill( 0xFF );
        cleanBuffer.set( golden_wire_bytes.subarray( 0, truncatedBytes ) );
        poisonBuffer.set( golden_wire_bytes.subarray( 0, truncatedBytes ) );

        const cleanStream = new ReadStream( cleanBuffer, truncatedBytes );
        const cleanData = new GoldenWireData();
        serialize_check( GoldenWireSerialize( cleanStream, cleanData ) === false );

        const poisonStream = new ReadStream( poisonBuffer, truncatedBytes );
        const poisonData = new GoldenWireData();
        serialize_check( GoldenWireSerialize( poisonStream, poisonData ) === false );

        serialize_check( poisonStream.GetBitsProcessed() === cleanStream.GetBitsProcessed() );   // both latched by the refusal
        serialize_check( poisonData.equals( cleanData ) );                                         // with identical partial state
    }
}

// Conformance vector for compressed_float over a range with a NON-ZERO min: the decoded BIT PATTERNS are pinned,
// over [-100,100] at resolution 0.01 (max_integer_value = 20000, 15 bits per value), where the reader's add is load-bearing.

function CompressedFloatNonZeroMinSerialize( stream: BaseStream, values: { a: number, b: number, c: number } ): boolean
{
    if ( !serialize_compressed_float( stream, values, 'a', -100.0, 100.0, 0.01 ) ) return false;
    if ( !serialize_compressed_float( stream, values, 'b', -100.0, 100.0, 0.01 ) ) return false;
    if ( !serialize_compressed_float( stream, values, 'c', -100.0, 100.0, 0.01 ) ) return false;
    if ( !serialize_align( stream ) ) return false;
    return true;
}

function test_compressed_float_conformance_nonzero_min(): void
{
    const pinned_bytes = new Uint8Array( [ 0x10, 0xA7, 0x06, 0x80, 0x82, 0x06 ] );

    // write side: the strict two-rounding quantization must produce exactly these bytes
    {
        const buffer = new Uint8Array( 64 );
        const stream = new WriteStream( buffer );
        serialize_check( CompressedFloatNonZeroMinSerialize( stream, { a: 0.0, b: f32( -99.875 ), c: f32( -33.34 ) } ) === true );
        stream.Flush();
        serialize_check( stream.GetBytesProcessed() === pinned_bytes.length );
        serialize_check( bytes_equal( buffer, pinned_bytes, pinned_bytes.length ) );
    }

    // read side: the decoded floats are pinned bit-exactly
    {
        const buffer = new Uint8Array( 64 );
        buffer.set( pinned_bytes );
        const stream = new ReadStream( buffer, pinned_bytes.length );
        const values = { a: -1, b: -1, c: -1 };
        serialize_check( CompressedFloatNonZeroMinSerialize( stream, values ) === true );
        serialize_check( float_to_bits( values.a ) === 0x00000000 );
        serialize_check( float_to_bits( values.b ) === 0xC2C7BD71 );
        serialize_check( float_to_bits( values.c ) === 0xC2055C2A );
    }
}

// Conformance vector for the WRITER's fusion class: [0, 16777215] at resolution 1 (max_integer_value = 2^24 - 1, 24 bits per value).

function CompressedFloatWriterFusionSerialize( stream: BaseStream, values: { a: number, b: number, c: number } ): boolean
{
    if ( !serialize_compressed_float( stream, values, 'a', 0.0, 16777215.0, 1.0 ) ) return false;
    if ( !serialize_compressed_float( stream, values, 'b', 0.0, 16777215.0, 1.0 ) ) return false;
    if ( !serialize_compressed_float( stream, values, 'c', 0.0, 16777215.0, 1.0 ) ) return false;
    if ( !serialize_align( stream ) ) return false;
    return true;
}

function test_compressed_float_conformance_writer_fusion(): void
{
    const pinned_bytes = new Uint8Array( [ 0x00, 0x00, 0x80, 0xAC, 0xAA, 0xAA, 0xFF, 0xFF, 0xFF ] );

    {
        const buffer = new Uint8Array( 64 );
        const stream = new WriteStream( buffer );
        serialize_check( CompressedFloatWriterFusionSerialize( stream, { a: 8388608.0, b: 11184811.0, c: 16777215.0 } ) === true );
        stream.Flush();
        serialize_check( stream.GetBytesProcessed() === pinned_bytes.length );
        serialize_check( bytes_equal( buffer, pinned_bytes, pinned_bytes.length ) );
    }

    {
        const buffer = new Uint8Array( 64 );
        buffer.set( pinned_bytes );
        const stream = new ReadStream( buffer, pinned_bytes.length );
        const values = { a: -1, b: -1, c: -1 };
        serialize_check( CompressedFloatWriterFusionSerialize( stream, values ) === true );
        serialize_check( float_to_bits( values.a ) === 0x4B000000 );       // 8388608.0
        serialize_check( float_to_bits( values.b ) === 0x4B2AAAAC );       // 11184812.0
        serialize_check( float_to_bits( values.c ) === 0x4B7FFFFF );       // 16777215.0
    }
}

// The non-zero-min conformance vector again, through the PRECOMPUTED entry point, with the constants written as literals.

function CompressedFloatPrecomputedConformanceSerialize( stream: BaseStream, values: { a: number, b: number, c: number } ): boolean
{
    if ( !serialize_compressed_float_precomputed( stream, values, 'a', 20000, 15, 200.0, -100.0 ) ) return false;
    if ( !serialize_compressed_float_precomputed( stream, values, 'b', 20000, 15, 200.0, -100.0 ) ) return false;
    if ( !serialize_compressed_float_precomputed( stream, values, 'c', 20000, 15, 200.0, -100.0 ) ) return false;
    if ( !serialize_align( stream ) ) return false;
    return true;
}

function test_compressed_float_precomputed_conformance(): void
{
    const pinned_bytes = new Uint8Array( [ 0x10, 0xA7, 0x06, 0x80, 0x82, 0x06 ] );

    {
        const buffer = new Uint8Array( 64 );
        const stream = new WriteStream( buffer );
        serialize_check( CompressedFloatPrecomputedConformanceSerialize( stream, { a: 0.0, b: f32( -99.875 ), c: f32( -33.34 ) } ) === true );
        stream.Flush();
        serialize_check( stream.GetBytesProcessed() === pinned_bytes.length );
        serialize_check( bytes_equal( buffer, pinned_bytes, pinned_bytes.length ) );
    }

    {
        const buffer = new Uint8Array( 64 );
        buffer.set( pinned_bytes );
        const stream = new ReadStream( buffer, pinned_bytes.length );
        const values = { a: -1, b: -1, c: -1 };
        serialize_check( CompressedFloatPrecomputedConformanceSerialize( stream, values ) === true );
        serialize_check( float_to_bits( values.a ) === 0x00000000 );
        serialize_check( float_to_bits( values.b ) === 0xC2C7BD71 );
        serialize_check( float_to_bits( values.c ) === 0xC2055C2A );
    }
}

// The derive-per-call compressed float against the precomputed one, plus a frozen copy of the pre-split
// body: measured bits, wire bytes, read acceptance and decoded BIT PATTERNS must agree on every input.

function serialize_compressed_float_frozen_reference( stream: BaseStream, holder: { value: number }, min: number, max: number, res: number ): boolean
{
    // verbatim pre-split serialize_compressed_float_internal, float32 at every statement as the C++ float locals pin. DO NOT EDIT.
    min = f32( min );
    max = f32( max );
    res = f32( res );

    serialize_assert( min < max && res > 0 );

    const delta = f32( max - min );

    let values = f32( delta / res );

    serialize_assert( delta - delta === 0 );
    serialize_assert( values - values === 0 );

    if ( !( values >= 1 ) )
    {
        values = 1;
    }
    else if ( values > 4294967040 )
    {
        values = 4294967040;
    }

    const maxIntegerValue = Math.ceil( values ) >>> 0;

    const bits = bits_required( 0, maxIntegerValue );

    let integerValue = 0;

    if ( stream.IsWriting )
    {
        const value = f32( holder.value );

        serialize_assert( value - value === 0 );

        let normalizedValue = f32( f32( value - min ) / delta );
        if ( !( normalizedValue >= 0 ) )
        {
            normalizedValue = 0;
        }
        else if ( !( normalizedValue <= 1 ) )
        {
            normalizedValue = 1;
        }
        const scaled = f32( normalizedValue * f32( maxIntegerValue ) );
        integerValue = Math.floor( f32( scaled + 0.5 ) ) >>> 0;
        if ( integerValue > maxIntegerValue )
        {
            integerValue = maxIntegerValue;
        }
    }

    if ( !stream.SerializeBits( integerValue, bits ) )
    {
        return false;
    }

    if ( stream.IsReading )
    {
        integerValue = stream.value;
        if ( integerValue > maxIntegerValue )
        {
            return false;
        }
        const normalizedValue = f32( f32( integerValue ) / f32( maxIntegerValue ) );
        const scaledValue = f32( normalizedValue * delta );
        holder.value = f32( scaledValue + min );
    }

    return true;
}

function serialize_compressed_float_legacy_form( stream: BaseStream, holder: { value: number }, min: number, max: number, res: number ): boolean
{
    if ( !serialize_compressed_float( stream, holder, 'value', min, max, res ) ) return false;
    return true;
}

function serialize_compressed_float_precomputed_form( stream: BaseStream, holder: { value: number }, max_integer_value: number, bits: number, delta: number, min: number ): boolean
{
    if ( !serialize_compressed_float_precomputed( stream, holder, 'value', max_integer_value, bits, delta, min ) ) return false;
    return true;
}

// THE NEGATIVE CONTROLS: one-rounding perturbations spelled in double. They must keep diverging from
// the shipped path somewhere in the corpus, or the comparisons above have gone blind.

let compressed_float_sentinel_write_divergences = 0;
let compressed_float_sentinel_read_divergences = 0;
let compressed_float_differential_check_count = 0;

function compressed_float_sentinel_write_code_one_rounding( value: number, max_integer_value: number, delta: number, min: number ): number
{
    let normalized = f32( f32( value - min ) / delta );
    if ( !( normalized >= 0 ) )
    {
        normalized = 0;
    }
    else if ( !( normalized <= 1 ) )
    {
        normalized = 1;
    }
    return Math.floor( normalized * max_integer_value + 0.5 ) >>> 0;
}

function compressed_float_sentinel_read_value_one_rounding( integer_value: number, max_integer_value: number, delta: number, min: number ): number
{
    const normalized = f32( f32( integer_value ) / f32( max_integer_value ) );
    return f32( normalized * delta + min );
}

function serialize_differential_check( condition: boolean ): void
{
    serialize_check( condition );
    compressed_float_differential_check_count++;
}

function check_compressed_float_value_agrees( value: number, min: number, max: number, res: number, max_integer_value: number, bits: number, delta: number ): void
{
    // measure: all three forms agree on cost
    const measureReference = new MeasureStream();
    serialize_differential_check( serialize_compressed_float_frozen_reference( measureReference, { value }, min, max, res ) === true );
    const measureLegacy = new MeasureStream();
    serialize_differential_check( serialize_compressed_float_legacy_form( measureLegacy, { value }, min, max, res ) === true );
    const measurePrecomputed = new MeasureStream();
    serialize_differential_check( serialize_compressed_float_precomputed_form( measurePrecomputed, { value }, max_integer_value, bits, delta, min ) === true );
    serialize_differential_check( measureReference.GetBitsProcessed() === measureLegacy.GetBitsProcessed() );
    serialize_differential_check( measureReference.GetBitsProcessed() === measurePrecomputed.GetBitsProcessed() );

    // write: byte identical wire from all three
    const buffer_reference = new Uint8Array( 8 + 8 );
    const buffer_legacy = new Uint8Array( 8 + 8 );
    const buffer_precomputed = new Uint8Array( 8 + 8 );

    const writeReference = new WriteStream( buffer_reference, 8 );
    serialize_differential_check( serialize_compressed_float_frozen_reference( writeReference, { value }, min, max, res ) === true );
    writeReference.Flush();

    const writeLegacy = new WriteStream( buffer_legacy, 8 );
    serialize_differential_check( serialize_compressed_float_legacy_form( writeLegacy, { value }, min, max, res ) === true );
    writeLegacy.Flush();

    const writePrecomputed = new WriteStream( buffer_precomputed, 8 );
    serialize_differential_check( serialize_compressed_float_precomputed_form( writePrecomputed, { value }, max_integer_value, bits, delta, min ) === true );
    writePrecomputed.Flush();

    serialize_differential_check( writeReference.GetBitsProcessed() === writeLegacy.GetBitsProcessed() );
    serialize_differential_check( writeReference.GetBitsProcessed() === writePrecomputed.GetBitsProcessed() );
    serialize_differential_check( bytes_equal( buffer_legacy, buffer_precomputed, 8 ) );
    serialize_differential_check( bytes_equal( buffer_reference, buffer_legacy, 8 ) );
    serialize_differential_check( bytes_equal( buffer_reference, buffer_precomputed, 8 ) );

    // read: decoded BIT PATTERNS agree exactly -- one ulp of divergence must fail
    const decoded_reference = { value: 0 };
    serialize_differential_check( serialize_compressed_float_frozen_reference( new ReadStream( buffer_precomputed, 8 ), decoded_reference, min, max, res ) === true );
    const decoded_legacy = { value: 0 };
    serialize_differential_check( serialize_compressed_float_legacy_form( new ReadStream( buffer_precomputed, 8 ), decoded_legacy, min, max, res ) === true );
    const decoded_precomputed = { value: 0 };
    serialize_differential_check( serialize_compressed_float_precomputed_form( new ReadStream( buffer_precomputed, 8 ), decoded_precomputed, max_integer_value, bits, delta, min ) === true );

    const pattern_reference = float_to_bits( decoded_reference.value );
    const pattern_legacy = float_to_bits( decoded_legacy.value );
    const pattern_precomputed = float_to_bits( decoded_precomputed.value );
    serialize_differential_check( pattern_legacy === pattern_precomputed );
    serialize_differential_check( pattern_reference === pattern_legacy );
    serialize_differential_check( pattern_reference === pattern_precomputed );

    // the write-side negative control, measured against the bytes the shipped path actually made
    {
        const sentinelStream = new ReadStream( buffer_precomputed, 8 );
        if ( sentinelStream.SerializeBits( 0, bits ) )
        {
            if ( compressed_float_sentinel_write_code_one_rounding( value, max_integer_value, delta, min ) !== sentinelStream.value )
            {
                compressed_float_sentinel_write_divergences++;
            }
        }
    }
}

function check_compressed_float_code_agrees( code: number, min: number, max: number, res: number, max_integer_value: number, bits: number, delta: number ): void
{
    const buffer = new Uint8Array( 8 + 8 );
    const writeStream = new WriteStream( buffer, 8 );
    serialize_differential_check( writeStream.SerializeBits( code, bits ) === true );
    writeStream.Flush();

    const decoded_reference = { value: 0 };
    const ok_reference = serialize_compressed_float_frozen_reference( new ReadStream( buffer, 8 ), decoded_reference, min, max, res );

    const decoded_legacy = { value: 0 };
    const ok_legacy = serialize_compressed_float_legacy_form( new ReadStream( buffer, 8 ), decoded_legacy, min, max, res );

    const decoded_precomputed = { value: 0 };
    const ok_precomputed = serialize_compressed_float_precomputed_form( new ReadStream( buffer, 8 ), decoded_precomputed, max_integer_value, bits, delta, min );

    serialize_differential_check( ok_reference === ok_legacy );
    serialize_differential_check( ok_reference === ok_precomputed );
    serialize_differential_check( ok_reference === ( code <= max_integer_value ) );      // the headroom refusal itself

    if ( ok_reference )
    {
        const pattern_reference = float_to_bits( decoded_reference.value );
        const pattern_legacy = float_to_bits( decoded_legacy.value );
        const pattern_precomputed = float_to_bits( decoded_precomputed.value );
        serialize_differential_check( pattern_legacy === pattern_precomputed );
        serialize_differential_check( pattern_reference === pattern_legacy );
        serialize_differential_check( pattern_reference === pattern_precomputed );

        // the read-side negative control
        const pattern_sentinel = float_to_bits( compressed_float_sentinel_read_value_one_rounding( code, max_integer_value, delta, min ) );
        if ( pattern_sentinel !== pattern_precomputed )
        {
            compressed_float_sentinel_read_divergences++;
        }
    }
}

/** nextafterf: the next float32 after x in the direction of y */
function nextafterf( x: number, y: number ): number
{
    x = f32( x );
    y = f32( y );
    if ( Number.isNaN( x ) || Number.isNaN( y ) )
        return NaN;
    if ( x === y )
        return y;
    if ( x === 0 )
        return y > 0 ? bits_to_float( 1 ) : bits_to_float( 0x80000001 );
    let bits = float_to_bits( x );
    if ( ( x < y ) === ( x > 0 ) )
        bits += 1;
    else
        bits -= 1;
    return bits_to_float( bits >>> 0 );
}

type CompressedFloatShape = [ number, number, number, number, number ];    // min, max, res, expected max_integer_value, expected bits

const compressed_float_shapes: CompressedFloatShape[] =
[
    // the schema compiler's corpus: examples, bench/corpus/RealWorld.schema and its test data
    [ 0.0,       2000.0,        0.1,       20000,       15 ],
    [ -2.0,      2.0,           0.25,      16,          5  ],
    [ -90.0,     90.0,          0.5,       360,         9  ],
    [ 0.0,       30.0,          0.5,       60,          6  ],
    [ -100.0,    100.0,         0.25,      800,         10 ],
    [ 0.0,       2000.0,        1.0,       2000,        11 ],
    [ 0.0,       10.0,          0.02,      500,         9  ],
    [ 0.0,       100.0,         0.01,      10000,       14 ],
    [ -180.0,    180.0,         0.01,      36000,       16 ],
    [ 0.0,       10.0,          0.01,      1000,        10 ],       // also this repo's golden wire declaration
    [ -5.0,      5.0,           0.001,     10000,       14 ],
    // this repo's own declarations
    [ -100.0,    100.0,         0.01,      20000,       15 ],       // the non-zero-min conformance vector
    [ -10.0,     10.0,          0.01,      2000,        11 ],       // the fuzz harness declaration
    [ -1.0,      1.0,           0.001,     2000,        11 ],       // example.cpp's orientation declaration
    // shapes at the edges of the derivation itself
    [ 0.0,       1.0,           2.0,       1,           1  ],       // resolution coarser than the range: values clamps up to 1
    [ 0.0,       15.0,          1.0,       15,          4  ],       // step count exactly fills the wire width: no headroom to refuse
    [ 0.0,       1000000.0,     1.0,       1000000,     20 ],       // a million steps
    [ 0.0,       10000000000.0, 1.0,       4294967040,  32 ],       // values clamps down to the largest float below 2^32
    // shapes that discriminate the rounding rule itself
    [ 0.0,       10.0,          0.3,       34,          6  ],       // 33.333332 steps: ceil 34, round 33
    [ 0.0,       63.3,          1.0,       64,          7  ],       // 63.3 steps: ceil 64 (7 bits), round 63 (6 bits)
    // shapes in [2^23, 2^24), where the float32 ulp reaches 1
    [ 0.0,       8388609.0,     1.0,       8388609,     24 ],       // 2^23+1: the reader-rejects witness
    [ 0.0,       16777215.0,    1.0,       16777215,    24 ],       // 2^24-1: the wire-divergence witness
];

function test_compressed_float_top_of_range_clamp(): void
{
    // STANDARD.md's normative integer clamp: in [2^23, 2^24) the float32 ulp is 1, so scaled + 0.5f lands on a tie
    {
        // witness A: [0, 8388609] at resolution 1 -> max_integer_value 2^23+1, 24 bits
        const buffer = new Uint8Array( 16 + 8 );
        const writeStream = new WriteStream( buffer, 16 );
        serialize_check( serialize_compressed_float( writeStream, { value: 8388609.0 }, 'value', 0.0, 8388609.0, 1.0 ) === true );
        writeStream.Flush();
        const value = { value: 0 };
        serialize_check( serialize_compressed_float( new ReadStream( buffer, 16 ), value, 'value', 0.0, 8388609.0, 1.0 ) === true );
        serialize_check( value.value === 8388609.0 );
    }
    {
        // witness B: [0, 16777215] at resolution 1 -> max_integer_value 2^24-1, 24 bits
        const buffer = new Uint8Array( 16 + 8 );
        const writeStream = new WriteStream( buffer, 16 );
        serialize_check( serialize_compressed_float( writeStream, { value: 16777215.0 }, 'value', 0.0, 16777215.0, 1.0 ) === true );
        writeStream.Flush();
        const value = { value: 0 };
        serialize_check( serialize_compressed_float( new ReadStream( buffer, 16 ), value, 'value', 0.0, 16777215.0, 1.0 ) === true );
        serialize_check( value.value === 16777215.0 );
    }
}

function test_compressed_float_precomputed_differential(): void
{
    compressed_float_sentinel_write_divergences = 0;
    compressed_float_sentinel_read_divergences = 0;
    compressed_float_differential_check_count = 0;

    const float_max = f32( 3.402823466e+38 );               // FLT_MAX

    let lcg = 0xC0FFEE1234567890n;                          // fixed seed: failures reproduce

    const next_lcg = (): bigint =>
    {
        lcg = BigInt.asUintN( 64, lcg * 6364136223846793005n + 1442695040888963407n );
        return lcg;
    };

    for ( let s = 0; s < compressed_float_shapes.length; s++ )
    {
        const min = f32( compressed_float_shapes[s][0] );
        const max = f32( compressed_float_shapes[s][1] );
        const res = f32( compressed_float_shapes[s][2] );

        const params = serialize_compressed_float_params( min, max, res );
        const max_integer_value = params.max_integer_value;
        const bits = params.bits;
        const delta = params.delta;

        // the derived constants are pinned against the schema compiler's generation-time table
        serialize_differential_check( max_integer_value === compressed_float_shapes[s][3] );
        serialize_differential_check( bits === compressed_float_shapes[s][4] );
        serialize_differential_check( delta === f32( max - min ) );

        const dmin = min;
        const ddelta = delta;

        // dense sweep with overshoot a quarter of the range past both bounds
        {
            const sweep_steps = 2048;
            const lo = dmin - 0.25 * ddelta;
            const span = 1.5 * ddelta;
            for ( let i = 0; i <= sweep_steps; i++ )
            {
                const value = f32( lo + span * i / sweep_steps );
                check_compressed_float_value_agrees( value, min, max, res, max_integer_value, bits, delta );
            }
        }

        // quantization step edges and midpoints, with their one-ulp neighbors
        {
            const stride = Math.floor( max_integer_value / 512 ) + 1;
            for ( let k = 0; k <= max_integer_value; k += stride )
            {
                const on_quantum = f32( dmin + ddelta * ( k / max_integer_value ) );
                const midpoint = f32( dmin + ddelta * ( ( k + 0.5 ) / max_integer_value ) );
                check_compressed_float_value_agrees( on_quantum, min, max, res, max_integer_value, bits, delta );
                check_compressed_float_value_agrees( nextafterf( on_quantum, -float_max ), min, max, res, max_integer_value, bits, delta );
                check_compressed_float_value_agrees( nextafterf( on_quantum, +float_max ), min, max, res, max_integer_value, bits, delta );
                check_compressed_float_value_agrees( midpoint, min, max, res, max_integer_value, bits, delta );
                check_compressed_float_value_agrees( nextafterf( midpoint, -float_max ), min, max, res, max_integer_value, bits, delta );
                check_compressed_float_value_agrees( nextafterf( midpoint, +float_max ), min, max, res, max_integer_value, bits, delta );
            }
        }

        // specials: the bounds and their one-ulp neighbors, both zeros, subnormals, extremes (float32 arithmetic, as the C++ float expressions)
        {
            const specials =
            [
                min,
                max,
                nextafterf( min, -float_max ),
                nextafterf( min, +float_max ),
                nextafterf( max, -float_max ),
                nextafterf( max, +float_max ),
                f32( min - res ),
                f32( max + res ),
                f32( min + f32( res * 0.5 ) ),
                f32( max - f32( res * 0.5 ) ),
                f32( min - delta ),
                f32( max + delta ),
                0.0,
                -0.0,
                res,
                -res,
                float_max,
                -float_max,
                f32( 1.175494351e-38 ),               // FLT_MIN
                f32( -1.175494351e-38 ),
                f32( 1.401298464e-45 ),               // the smallest subnormal
                f32( -1.401298464e-45 ),
                f32( 1.0e30 ),
                f32( -1.0e30 ),
            ];
            for ( let i = 0; i < specials.length; i++ )
            {
                check_compressed_float_value_agrees( specials[i], min, max, res, max_integer_value, bits, delta );
            }
        }

        // non-finite inputs are non-conforming and assert, so the release build is where the
        // differential drives them: the clamp must force NaN and both infinities to the same wire
        serialize_test_release_build( () =>
        {
            const non_finite_patterns = [ 0x7F800000, 0xFF800000, 0x7FC00000, 0x7F800001, 0xFFC00001 ];
            for ( let i = 0; i < non_finite_patterns.length; i++ )
            {
                check_compressed_float_value_agrees( bits_to_float( non_finite_patterns[i] ), min, max, res, max_integer_value, bits, delta );
            }
        } );

        // LCG uniform values across the range and its overshoot band
        for ( let i = 0; i < 2048; i++ )
        {
            const fraction = Number( next_lcg() >> 11n ) * ( 1.0 / 9007199254740992.0 );     // [0,1) in 53 bits
            const value = f32( dmin - 0.25 * ddelta + fraction * 1.5 * ddelta );
            check_compressed_float_value_agrees( value, min, max, res, max_integer_value, bits, delta );
        }

        // LCG uniform float32 bit patterns, finite ones
        for ( let i = 0; i < 2048; i++ )
        {
            const value = bits_to_float( Number( next_lcg() >> 32n ) );
            if ( value - value === 0 )
            {
                check_compressed_float_value_agrees( value, min, max, res, max_integer_value, bits, delta );
            }
        }

        // the read side: every representable wire integer, including the bit headroom. exhaustive up to 16-bit widths; above that the boundary codes are pinned and the interior is sampled
        {
            const top_code = ( bits === 32 ) ? 0xFFFFFFFF : ( 2 ** bits - 1 );
            if ( bits <= 16 )
            {
                for ( let code = 0; code <= top_code; code++ )
                {
                    check_compressed_float_code_agrees( code, min, max, res, max_integer_value, bits, delta );
                }
            }
            else
            {
                for ( let code = 0; code <= 1024; code++ )
                {
                    check_compressed_float_code_agrees( code, min, max, res, max_integer_value, bits, delta );
                }
                const window_lo = max_integer_value - 512;
                const window_hi = ( top_code - max_integer_value < 512 ) ? top_code : max_integer_value + 512;
                for ( let code = window_lo; code <= window_hi; code++ )
                {
                    check_compressed_float_code_agrees( code, min, max, res, max_integer_value, bits, delta );
                }
                for ( let code = top_code - 64; code <= top_code; code++ )
                {
                    check_compressed_float_code_agrees( code, min, max, res, max_integer_value, bits, delta );
                }
                for ( let i = 0; i < 2048; i++ )
                {
                    const code = ( Number( next_lcg() >> 32n ) & top_code ) >>> 0;
                    check_compressed_float_code_agrees( code, min, max, res, max_integer_value, bits, delta );
                }
            }
        }
    }

    // the coverage floor: if the differential ever silently shrinks below the mass it was built with, that is a test bug
    serialize_check( compressed_float_differential_check_count >= 2000000 );

    if ( serialize_test_verbose() )
    {
        console.log( '    (' + compressed_float_differential_check_count + ' checks, three implementations, ' + compressed_float_shapes.length + ' declarations)' );
    }

    // the negative controls, CHECKED rather than merely reported
    serialize_check( compressed_float_sentinel_write_divergences > 0 );
    serialize_check( compressed_float_sentinel_read_divergences > 0 );

    if ( serialize_test_verbose() )
    {
        console.log( '    (negative controls diverge on ' + compressed_float_sentinel_write_divergences + ' wire codes and ' + compressed_float_sentinel_read_divergences + ' decoded patterns)' );
    }
}

// Conformance vector for float/double BIT TRANSPARENCY. The patterns are the ones a sanitizer breaks, constructed by bit-cast and compared by bits.
// JavaScript caveat: a SIGNALING NaN cannot be relied on to survive in a JavaScript number -- V8 quiets a float32 one when it converts
// it to float64, and quiets a float64 one when it is stored into a double array -- so signaling NaN patterns are allowed to come back as
// their quieted twin (quiet bit set, payload and sign kept). Every other pattern, quiet NaN payloads included, must be exact.

const golden_float_bytes = new Uint8Array(
[
    0x01, 0x00, 0xC0, 0x7F,                             // f32 0x7FC00001: quiet NaN, payload 1
    0x01, 0x00, 0x80, 0x7F,                             // f32 0x7F800001: SIGNALING NaN
    0x00, 0x00, 0x80, 0xFF,                             // f32 0xFF800000: -Inf
    0x00, 0x00, 0x00, 0x80,                             // f32 0x80000000: -0.0
    0x01, 0x00, 0x00, 0x00,                             // f32 0x00000001: smallest denormal
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF4, 0x7F,     // f64 0x7FF4000000000001: signaling NaN, payload 1
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80      // f64 0x8000000000000000: -0.0
] );

const golden_float_patterns = [ 0x7FC00001, 0x7F800001, 0xFF800000, 0x80000000, 0x00000001 ];
const golden_double_patterns = [ 0x7FF4000000000001n, 0x8000000000000000n ];

function float_pattern_transparent( got: number, expected: number ): boolean
{
    if ( got === expected )
        return true;
    // a signaling float32 NaN may only come back as its quieted twin
    const is_signaling_nan = ( expected & 0x7F800000 ) === 0x7F800000 && ( expected & 0x007FFFFF ) !== 0 && ( expected & 0x00400000 ) === 0;
    return is_signaling_nan && got === ( ( expected | 0x00400000 ) >>> 0 );
}

function double_pattern_transparent( got: bigint, expected: bigint ): boolean
{
    if ( got === expected )
        return true;
    // a signaling float64 NaN may only come back as its quieted twin
    const exponent = 0x7FF0000000000000n;
    const quiet = 0x0008000000000000n;
    const is_signaling_nan = ( expected & exponent ) === exponent && ( expected & 0x000FFFFFFFFFFFFFn ) !== 0n && ( expected & quiet ) === 0n;
    return is_signaling_nan && got === ( expected | quiet );
}

function double_to_bits( value: number ): bigint
{
    const view = new DataView( new ArrayBuffer( 8 ) );
    view.setFloat64( 0, value, true );
    return view.getBigUint64( 0, true );
}

function bits_to_double( bits: bigint ): number
{
    const view = new DataView( new ArrayBuffer( 8 ) );
    view.setBigUint64( 0, bits, true );
    return view.getFloat64( 0, true );
}

type GoldenFloatValues = { f0: number, f1: number, f2: number, f3: number, f4: number, d0: number, d1: number };

function GoldenFloatSerialize( stream: BaseStream, values: GoldenFloatValues ): boolean
{
    if ( !serialize_float( stream, values, 'f0' ) ) return false;
    if ( !serialize_float( stream, values, 'f1' ) ) return false;
    if ( !serialize_float( stream, values, 'f2' ) ) return false;
    if ( !serialize_float( stream, values, 'f3' ) ) return false;
    if ( !serialize_float( stream, values, 'f4' ) ) return false;
    if ( !serialize_double( stream, values, 'd0' ) ) return false;
    if ( !serialize_double( stream, values, 'd1' ) ) return false;
    return true;
}

function golden_float_values(): GoldenFloatValues
{
    // object slots, not array elements: V8 canonicalizes NaN payloads when an array changes elements kind
    return {
        f0: bits_to_float( golden_float_patterns[0] ),
        f1: bits_to_float( golden_float_patterns[1] ),
        f2: bits_to_float( golden_float_patterns[2] ),
        f3: bits_to_float( golden_float_patterns[3] ),
        f4: bits_to_float( golden_float_patterns[4] ),
        d0: bits_to_double( golden_double_patterns[0] ),
        d1: bits_to_double( golden_double_patterns[1] ),
    };
}

function test_golden_float_bit_transparency(): void
{
    // write side: the bit patterns above, bit-cast into float/double and serialized
    {
        const buffer = new Uint8Array( 64 );
        const stream = new WriteStream( buffer );
        serialize_check( GoldenFloatSerialize( stream, golden_float_values() ) === true );
        stream.Flush();
        serialize_check( stream.GetBytesProcessed() === golden_float_bytes.length );
        const words = new DataView( buffer.buffer );
        for ( let i = 0; i < 5; i++ )
        {
            serialize_check( float_pattern_transparent( words.getUint32( i * 4, true ), golden_float_patterns[i] ) );
        }
        for ( let i = 0; i < 2; i++ )
        {
            serialize_check( double_pattern_transparent( words.getBigUint64( 20 + i * 8, true ), golden_double_patterns[i] ) );
        }

        // the wire layout itself is exact: the raw words written as integers produce exactly the pinned bytes
        const raw = new Uint8Array( 64 );
        const rawStream = new WriteStream( raw );
        for ( let i = 0; i < 5; i++ )
            write_uint32( rawStream, golden_float_patterns[i] );
        for ( let i = 0; i < 2; i++ )
            write_uint64( rawStream, golden_double_patterns[i] );
        rawStream.Flush();
        serialize_check( bytes_equal( raw, golden_float_bytes, golden_float_bytes.length ) );
    }

    // read side: the recovered BIT PATTERNS must equal the transmitted ones exactly
    {
        const buffer = new Uint8Array( 64 );
        buffer.set( golden_float_bytes );
        const stream = new ReadStream( buffer, golden_float_bytes.length );
        const values: GoldenFloatValues = { f0: 0, f1: 0, f2: 0, f3: 0, f4: 0, d0: 0, d1: 0 };
        serialize_check( GoldenFloatSerialize( stream, values ) === true );
        const floats = [ values.f0, values.f1, values.f2, values.f3, values.f4 ];
        for ( let i = 0; i < 5; i++ )
        {
            serialize_check( float_pattern_transparent( float_to_bits( floats[i] ), golden_float_patterns[i] ) );
        }
        serialize_check( double_pattern_transparent( double_to_bits( values.d0 ), golden_double_patterns[0] ) );
        serialize_check( double_pattern_transparent( double_to_bits( values.d1 ), golden_double_patterns[1] ) );
    }
}

// Conformance vectors for the zero-count and unaligned bytes paths. Each one discriminates.

function ZeroLengthBytesSerialize( stream: BaseStream, values: { head: number, tail: number }, data: Uint8Array ): boolean
{
    if ( !serialize_bits( stream, values, 'head', 3 ) ) return false;
    if ( !serialize_bytes( stream, data, 0 ) ) return false;
    if ( !serialize_bits( stream, values, 'tail', 8 ) ) return false;
    return true;
}

function test_golden_zero_length_bytes(): void
{
    // { bits(5,3); bytes(count=0); bits(0xA5,8) }. The zero-length bytes still ALIGNS.
    const pinned_bytes = new Uint8Array( [ 0x05, 0xA5 ] );

    {
        const buffer = new Uint8Array( 64 );
        const stream = new WriteStream( buffer );
        serialize_check( ZeroLengthBytesSerialize( stream, { head: 5, tail: 0xA5 }, new Uint8Array( 1 ) ) === true );
        stream.Flush();
        serialize_check( stream.GetBytesProcessed() === pinned_bytes.length );
        serialize_check( bytes_equal( buffer, pinned_bytes, pinned_bytes.length ) );
    }

    {
        const buffer = new Uint8Array( 64 );
        buffer.set( pinned_bytes );
        const stream = new ReadStream( buffer, pinned_bytes.length );
        const values = { head: 0, tail: 0 };
        serialize_check( ZeroLengthBytesSerialize( stream, values, new Uint8Array( 1 ) ) === true );
        serialize_check( values.head === 5 );
        serialize_check( values.tail === 0xA5 );
        serialize_check( stream.GetBytesProcessed() === pinned_bytes.length );
    }
}

function ZeroLengthStringSerialize( stream: BaseStream, values: { head: number, string: string, tail: number } ): boolean
{
    if ( !serialize_bits( stream, values, 'head', 3 ) ) return false;
    if ( !serialize_string( stream, values, 'string', 8 ) ) return false;
    if ( !serialize_bits( stream, values, 'tail', 8 ) ) return false;
    return true;
}

function test_golden_zero_length_string(): void
{
    // { bits(5,3); string("", buffer_size 8); bits(0xA5,8) }. The empty string is a 3-bit length of 0, then the zero-length payload's align pads bits [6,8).
    const pinned_bytes = new Uint8Array( [ 0x05, 0xA5 ] );

    {
        const buffer = new Uint8Array( 64 );
        const stream = new WriteStream( buffer );
        serialize_check( ZeroLengthStringSerialize( stream, { head: 5, string: '', tail: 0xA5 } ) === true );
        stream.Flush();
        serialize_check( stream.GetBytesProcessed() === pinned_bytes.length );
        serialize_check( bytes_equal( buffer, pinned_bytes, pinned_bytes.length ) );
    }

    {
        const buffer = new Uint8Array( 64 );
        buffer.set( pinned_bytes );
        const stream = new ReadStream( buffer, pinned_bytes.length );
        const values = { head: 0, string: 'not empty', tail: 0 };
        serialize_check( ZeroLengthStringSerialize( stream, values ) === true );
        serialize_check( values.head === 5 );
        serialize_check( values.string === '' );
        serialize_check( values.tail === 0xA5 );
        serialize_check( stream.GetBytesProcessed() === pinned_bytes.length );
    }
}

function UnalignedBytesSerialize( stream: BaseStream, values: { head: number, tail: number }, data: Uint8Array ): boolean
{
    if ( !serialize_bits( stream, values, 'head', 1 ) ) return false;
    if ( !serialize_bytes( stream, data, 2 ) ) return false;
    if ( !serialize_bits( stream, values, 'tail', 4 ) ) return false;
    return true;
}

function test_golden_unaligned_bytes(): void
{
    // { bits(1,1); bytes({0xEF,0xBE}, 2); bits(0x0F,4) }. Exercises serialize_bytes' OWN align from bit index 1.
    const pinned_bytes = new Uint8Array( [ 0x01, 0xEF, 0xBE, 0x0F ] );

    {
        const buffer = new Uint8Array( 64 );
        const stream = new WriteStream( buffer );
        serialize_check( UnalignedBytesSerialize( stream, { head: 1, tail: 0x0F }, new Uint8Array( [ 0xEF, 0xBE ] ) ) === true );
        stream.Flush();
        serialize_check( stream.GetBytesProcessed() === pinned_bytes.length );
        serialize_check( bytes_equal( buffer, pinned_bytes, pinned_bytes.length ) );
    }

    {
        const buffer = new Uint8Array( 64 );
        buffer.set( pinned_bytes );
        const stream = new ReadStream( buffer, pinned_bytes.length );
        const values = { head: 0, tail: 0 };
        const data = new Uint8Array( 2 );
        serialize_check( UnalignedBytesSerialize( stream, values, data ) === true );
        serialize_check( values.head === 1 );
        serialize_check( data[0] === 0xEF );
        serialize_check( data[1] === 0xBE );
        serialize_check( values.tail === 0x0F );
        serialize_check( stream.GetBytesProcessed() === pinned_bytes.length );
    }
}

function test_measure_bound(): void
{
    // a measure reports a size sufficient at ANY starting bit position -- a bound, not the packet size

    // the ruling's worked example: { bits(8); align; bits(8) }
    {
        const measureStream = new MeasureStream();
        const byte_value = 0xAB;
        serialize_check( measureStream.SerializeBits( byte_value, 8 ) === true );
        serialize_check( measureStream.SerializeAlign() === true );
        serialize_check( measureStream.SerializeBits( byte_value, 8 ) === true );
        serialize_check( measureStream.GetBitsProcessed() === 23 );      // 8 + 7 + 8: the conservative charge

        // written at every starting offset, the message's actual span never exceeds the measure
        for ( let offset = 0; offset < 8; offset++ )
        {
            const writeStream = new WriteStream( new Uint8Array( 64 ) );
            for ( let i = 0; i < offset; i++ )
            {
                serialize_check( writeStream.SerializeBits( 1, 1 ) === true );
            }
            const start = writeStream.GetBitsProcessed();
            serialize_check( writeStream.SerializeBits( byte_value, 8 ) === true );
            serialize_check( writeStream.SerializeAlign() === true );
            serialize_check( writeStream.SerializeBits( byte_value, 8 ) === true );
            const span = writeStream.GetBitsProcessed() - start;
            serialize_check( span <= measureStream.GetBitsProcessed() );
            if ( offset === 0 )
                serialize_check( span === 16 );
            if ( offset === 1 )
                serialize_check( span === 23 );
        }
    }

    // measure >= written, across every message this suite pins
    {
        const data = new GoldenWireData();
        GoldenWireInit( data );
        const measureStream = new MeasureStream();
        serialize_check( GoldenWireSerialize( measureStream, data ) === true );
        const writeStream = new WriteStream( new Uint8Array( 256 ) );
        serialize_check( GoldenWireSerialize( writeStream, data ) === true );
        writeStream.Flush();
        serialize_check( measureStream.GetBitsProcessed() >= writeStream.GetBitsProcessed() );
    }

    {
        const measureStream = new MeasureStream();
        serialize_check( GoldenFloatSerialize( measureStream, golden_float_values() ) === true );
        serialize_check( measureStream.GetBitsProcessed() >= 5 * 32 + 2 * 64 );
    }

    {
        const measureStream = new MeasureStream();
        serialize_check( ZeroLengthBytesSerialize( measureStream, { head: 5, tail: 0xA5 }, new Uint8Array( 1 ) ) === true );
        serialize_check( measureStream.GetBitsProcessed() >= 16 );
    }

    {
        const measureStream = new MeasureStream();
        serialize_check( ZeroLengthStringSerialize( measureStream, { head: 5, string: '', tail: 0xA5 } ) === true );
        serialize_check( measureStream.GetBitsProcessed() >= 16 );
    }

    {
        const measureStream = new MeasureStream();
        serialize_check( UnalignedBytesSerialize( measureStream, { head: 1, tail: 0x0F }, new Uint8Array( [ 0xEF, 0xBE ] ) ) === true );
        serialize_check( measureStream.GetBitsProcessed() >= 28 );
    }
}

function test_unaligned_writer(): void
{
    // the write buffer does not need any alignment: exercise every offset within a dword, through the WriteBits, WriteBytes and FlushBits store paths

    const storage = new Uint8Array( 256 + 4 );

    for ( let offset = 0; offset < 4; offset++ )
    {
        storage.fill( 0 );

        const buffer = storage.subarray( offset, offset + 256 );

        const data = new Uint8Array( 13 );
        for ( let i = 0; i < data.length; i++ )
            data[i] = i * 47 + offset;

        const writeStream = new WriteStream( buffer, 256 );
        writeStream.SerializeBits( 0x12345678, 32 );
        writeStream.SerializeBits( 123, 7 );
        writeStream.SerializeBytes( data, data.length );
        writeStream.SerializeBits( 0xDEADBEEF, 32 );
        writeStream.Flush();

        const bytesWritten = writeStream.GetBytesProcessed();

        const readStream = new ReadStream( buffer, bytesWritten );
        serialize_check( readStream.SerializeBits( 0, 32 ) === true );
        serialize_check( readStream.value === 0x12345678 );
        serialize_check( readStream.SerializeBits( 0, 7 ) === true );
        serialize_check( readStream.value === 123 );
        const read_data = new Uint8Array( 13 );
        serialize_check( readStream.SerializeBytes( read_data, read_data.length ) === true );
        serialize_check( bytes_equal( read_data, data, data.length ) );
        serialize_check( readStream.SerializeBits( 0, 32 ) === true );
        serialize_check( readStream.value === 0xDEADBEEF );
    }
}

function test_large_buffer(): void
{
    // bit counts are not 32 bit, so buffers larger than 256 MB work. write a bulk block that carries the
    // stream past the 2^31 bit boundary, then verify that bitpacked values round trip on the far side of it.

    const bufferSize = 320 * 1024 * 1024;
    let buffer: Uint8Array;
    try
    {
        buffer = new Uint8Array( bufferSize );
    }
    catch
    {
        if ( serialize_test_verbose() )
        {
            console.log( '(skipped test_large_buffer: could not allocate the buffer)' );
        }
        return;
    }

    const chunk = new Uint8Array( 1024 * 1024 );
    for ( let i = 0; i < chunk.length; i++ )
        chunk[i] = i * 37;

    const numChunks = 300;                                              // 300 MB of bulk data: past the 256 MB boundary

    let bytesWritten = 0;
    {
        const writeStream = new WriteStream( buffer, bufferSize );
        for ( let i = 0; i < numChunks; i++ )
            serialize_check( writeStream.SerializeBytes( chunk, chunk.length ) === true );
        serialize_check( writeStream.SerializeBits( 0xDEADBEEF, 32 ) === true );
        serialize_check( writeStream.SerializeInteger( -12345, -100000, +100000 ) === true );
        writeStream.Flush();
        bytesWritten = writeStream.GetBytesProcessed();
        serialize_check( writeStream.GetBitsProcessed() > 2 ** 31 );    // the bit count really did cross the 32 bit boundary
    }

    {
        const readStream = new ReadStream( buffer, bytesWritten );
        const readChunk = new Uint8Array( 1024 * 1024 );
        for ( let i = 0; i < numChunks; i++ )
            serialize_check( readStream.SerializeBytes( readChunk, readChunk.length ) === true );
        serialize_check( bytes_equal( readChunk, chunk, chunk.length ) );        // the final chunk, decoded from past the boundary
        serialize_check( readStream.SerializeBits( 0, 32 ) === true );
        serialize_check( readStream.value === 0xDEADBEEF );
        serialize_check( readStream.SerializeInteger( 0, -100000, +100000 ) === true );
        serialize_check( readStream.value === -12345 );
        serialize_check( readStream.GetBitsProcessed() > 2 ** 31 );
    }
}

function SERIALIZE_RUN_TEST( test_function: () => void ): void
{
    console.log( test_function.name );
    test_function();
}

/**
    Run the serialize test suite: the port of upstream's serialize_test(). Throws on the first failed check.
 */

export function serialize_test(): void
{
    SERIALIZE_RUN_TEST( test_endian );
    SERIALIZE_RUN_TEST( test_bitpacker );
    SERIALIZE_RUN_TEST( test_bits_required );
    SERIALIZE_RUN_TEST( test_bits_required64 );
    SERIALIZE_RUN_TEST( test_bits_required128 );
    SERIALIZE_RUN_TEST( test_zigzag );
    SERIALIZE_RUN_TEST( test_serialize );
    SERIALIZE_RUN_TEST( test_read_write );
    SERIALIZE_RUN_TEST( test_serialize_integer_validation );
    SERIALIZE_RUN_TEST( test_serialize_degenerate_range );
    SERIALIZE_RUN_TEST( test_serialize_degenerate_range_64 );
    SERIALIZE_RUN_TEST( test_serialize_degenerate_range_128 );
    SERIALIZE_RUN_TEST( test_serialize_integer_full_range );
    SERIALIZE_RUN_TEST( test_serialize_int64_full_range );
    SERIALIZE_RUN_TEST( test_serialize_int64_validation );
    SERIALIZE_RUN_TEST( test_serialize_bytes_validation );
    SERIALIZE_RUN_TEST( test_wstring_validation );
    SERIALIZE_RUN_TEST( test_wstring_utf16_code_units );
    SERIALIZE_RUN_TEST( test_string_read_validation );
    SERIALIZE_RUN_TEST( test_wstring_read_validation );
    SERIALIZE_RUN_TEST( test_int_relative_validation );
    SERIALIZE_RUN_TEST( test_read_stream_failure_is_terminal );
    SERIALIZE_RUN_TEST( test_compressed_float_validation );
    SERIALIZE_RUN_TEST( test_compressed_float_top_of_range_clamp );
    SERIALIZE_RUN_TEST( test_compressed_float_non_finite_asserts );
    SERIALIZE_RUN_TEST( test_compressed_float_precomputed_validation );
    SERIALIZE_RUN_TEST( test_compressed_float_precomputed_asserts );
    SERIALIZE_RUN_TEST( test_serialize_fixed );
    SERIALIZE_RUN_TEST( test_serialize_fixed_validation );
    SERIALIZE_RUN_TEST( test_serialize_fixed_matches_int64 );
    SERIALIZE_RUN_TEST( test_serialize_fixed_wide );
    SERIALIZE_RUN_TEST( test_serialize_fixed_wide_emulated );
    SERIALIZE_RUN_TEST( test_serialize_fixed_degenerate );
    SERIALIZE_RUN_TEST( test_serialize_uint128 );
    SERIALIZE_RUN_TEST( test_serialize_int128 );
    SERIALIZE_RUN_TEST( test_compile_time_bits_required );
    SERIALIZE_RUN_TEST( test_compile_time_int );
    SERIALIZE_RUN_TEST( test_compile_time_int64 );
    SERIALIZE_RUN_TEST( test_compile_time_bits );
    SERIALIZE_RUN_TEST( test_compile_time_int_validation );
    SERIALIZE_RUN_TEST( test_compile_time_int64_validation );
    SERIALIZE_RUN_TEST( test_compile_time_bits_validation );
    SERIALIZE_RUN_TEST( test_compile_time_packet );
    SERIALIZE_RUN_TEST( test_golden_wire_format );
    SERIALIZE_RUN_TEST( test_trailing_bits );
    SERIALIZE_RUN_TEST( test_past_end_poison );
    SERIALIZE_RUN_TEST( test_compressed_float_conformance_nonzero_min );
    SERIALIZE_RUN_TEST( test_compressed_float_conformance_writer_fusion );
    SERIALIZE_RUN_TEST( test_compressed_float_precomputed_conformance );
    SERIALIZE_RUN_TEST( test_compressed_float_precomputed_differential );
    SERIALIZE_RUN_TEST( test_golden_float_bit_transparency );
    SERIALIZE_RUN_TEST( test_golden_zero_length_bytes );
    SERIALIZE_RUN_TEST( test_golden_zero_length_string );
    SERIALIZE_RUN_TEST( test_golden_unaligned_bytes );
    SERIALIZE_RUN_TEST( test_measure_bound );
    SERIALIZE_RUN_TEST( test_unaligned_writer );
    SERIALIZE_RUN_TEST( test_large_buffer );
}
