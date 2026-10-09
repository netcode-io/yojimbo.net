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
    TypeScript port of include/yojimbo_bit_array.h (yojimbo 1.13.5).

    The bits live in a block allocated from the allocator, as upstream (8 * ceil(size/64) bytes), viewed as 32 bit words.
*/

import { Allocator, YOJIMBO_ALLOCATE, YOJIMBO_FREE } from '../source/yojimbo_allocator.ts';
import { yojimbo_assert } from '../source/yojimbo_platform.ts';

/**
    A simple bit array class.
    You can create a bit array with a number of bits, set, clear and test if each bit is set.
 */

export class BitArray
{
    private m_allocator: Allocator | null;                  ///< Allocator passed in to the constructor.
    private m_size: number;                                 ///< The size of the bit array in bits.
    private m_bytes: number;                                ///< The size of the bit array in bytes.
    private m_memory: Uint8Array | null;                    ///< The block backing the bit array.
    private m_data: Uint32Array;                            ///< The bit array data, as 32 bit words (upstream: 64 bit words).

    /**
        The bit array constructor.
        @param allocator The allocator to use.
        @param size The number of bits in the bit array.
        All bits are initially set to zero.
     */

    constructor( allocator: Allocator, size: number )
    {
        yojimbo_assert( size > 0, "size > 0", "BitArray::BitArray" );
        this.m_allocator = allocator;
        this.m_size = size;
        this.m_bytes = 8 * ( Math.floor( size / 64 ) + ( ( size % 64 ) !== 0 ? 1 : 0 ) );
        yojimbo_assert( this.m_bytes > 0, "m_bytes > 0", "BitArray::BitArray" );
        this.m_memory = YOJIMBO_ALLOCATE( allocator, this.m_bytes );
        yojimbo_assert( this.m_memory, "m_data", "BitArray::BitArray" );
        this.m_data = new Uint32Array( this.m_memory.buffer, this.m_memory.byteOffset, this.m_bytes / 4 );
        this.Clear();
    }

    /**
        The bit array destructor.
     */

    Dispose(): void
    {
        yojimbo_assert( this.m_memory, "m_data", "BitArray::~BitArray" );
        yojimbo_assert( this.m_allocator, "m_allocator", "BitArray::~BitArray" );
        this.m_memory = YOJIMBO_FREE( this.m_allocator, this.m_memory );
        this.m_allocator = null;
    }

    /**
        Clear all bit values to zero.
     */

    Clear(): void
    {
        yojimbo_assert( this.m_memory, "m_data", "BitArray::Clear" );
        this.m_data.fill( 0 );
    }

    /**
        Set a bit to 1.
        @param index The index of the bit.
     */

    SetBit( index: number ): void
    {
        yojimbo_assert( index >= 0, "index >= 0", "BitArray::SetBit" );
        yojimbo_assert( index < this.m_size, "index < m_size", "BitArray::SetBit" );
        const data_index = index >>> 5;
        const bit_index = index & 31;
        this.m_data[data_index] |= ( 1 << bit_index );
    }

    /**
        Clear a bit to 0.
        @param index The index of the bit.
     */

    ClearBit( index: number ): void
    {
        yojimbo_assert( index >= 0, "index >= 0", "BitArray::ClearBit" );
        yojimbo_assert( index < this.m_size, "index < m_size", "BitArray::ClearBit" );
        const data_index = index >>> 5;
        const bit_index = index & 31;
        this.m_data[data_index] &= ~( 1 << bit_index );
    }

    /**
        Get the value of the bit.
        Returns 1 if the bit is set, 0 if the bit is not set.
        @param index The index of the bit.
     */

    GetBit( index: number ): number
    {
        yojimbo_assert( index >= 0, "index >= 0", "BitArray::GetBit" );
        yojimbo_assert( index < this.m_size, "index < m_size", "BitArray::GetBit" );
        const data_index = index >>> 5;
        const bit_index = index & 31;
        return ( this.m_data[data_index] >>> bit_index ) & 1;
    }

    /**
        Gets the size of the bit array, in number of bits.
        @returns The number of bits.
     */

    GetSize(): number
    {
        return this.m_size;
    }
}
