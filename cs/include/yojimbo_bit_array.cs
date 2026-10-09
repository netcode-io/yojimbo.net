/*
    Yojimbo Client/Server Network Library.

    Copyright © 2016 - 2019, The Network Protocol Company, Inc.

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

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Text;
using System.Threading;

namespace networkprotocol
{
    /**
        A simple bit array class.
        You can create a bit array with a number of bits, set, clear and test if each bit is set.
     */
    public class BitArray
    {
        /**
            The bit array constructor.
            @param allocator The allocator to use.
            @param size The number of bits in the bit array.
            All bits are initially set to zero.
         */
        public BitArray(Allocator allocator, int size)
        {
            yojimbo.assert(size > 0);
            m_allocator = allocator;
            m_size = size;
            m_bytes = 8 * ((size / 64) + ((size % 64) != 0 ? 1 : 0));
            yojimbo.assert(m_bytes > 0);
            m_data = new ulong[m_bytes / 8];
            Clear();
        }

        /**
            The bit array destructor.
         */
        public void Dispose()
        {
            yojimbo.assert(m_data != null);
            yojimbo.assert(m_allocator != null);
            m_data = null;
            m_allocator = null;
        }

        /**
            Clear all bit values to zero.
         */
        public void Clear()
        {
            yojimbo.assert(m_data != null);
            Array.Clear(m_data, 0, m_data.Length);
        }

        /**
            Set a bit to 1.
            @param index The index of the bit.
         */
        public void SetBit(int index)
        {
            yojimbo.assert(index >= 0);
            yojimbo.assert(index < m_size);
            var data_index = index >> 6;
            var bit_index = index & ((1 << 6) - 1);
            yojimbo.assert(bit_index >= 0);
            yojimbo.assert(bit_index < 64);
            m_data[data_index] |= 1UL << bit_index;
        }

        /**
            Clear a bit to 0.
            @param index The index of the bit.
         */

        public void ClearBit(int index)
        {
            yojimbo.assert(index >= 0);
            yojimbo.assert(index < m_size);
            var data_index = index >> 6;
            var bit_index = index & ((1 << 6) - 1);
            m_data[data_index] &= ~(1UL << bit_index);
        }

        /**
            Get the value of the bit.
            Returns 1 if the bit is set, 0 if the bit is not set.
            @param index The index of the bit.
         */

        public ulong GetBit(int index)
        {
            yojimbo.assert(index >= 0);
            yojimbo.assert(index < m_size);
            var data_index = index >> 6;
            var bit_index = index & ((1 << 6) - 1);
            yojimbo.assert(bit_index >= 0);
            yojimbo.assert(bit_index < 64);
            return (m_data[data_index] >> bit_index) & 1;
        }

        /**
            Gets the size of the bit array, in number of bits.
            @returns The number of bits.
         */
        public int GetSize() =>
            m_size;

        Allocator m_allocator;                      ///< Allocator passed in to the constructor.
        int m_size;                                 ///< The size of the bit array in bits.
        int m_bytes;                                ///< The size of the bit array in bytes.
        ulong[] m_data;                             ///< The data backing the bit array is an array of 64 bit integer values.

        //BitArray( const BitArray & other );
        //BitArray & operator = ( const BitArray & other );
    }
}
