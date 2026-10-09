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
        Data structure that stores data indexed by sequence number.
        Entries may or may not exist. If they don't exist the sequence value for the entry at that index is set to 0xFFFFFFFF. 
        This provides a constant time lookup for an entry by sequence number. If the entry at sequence modulo buffer size doesn't have the same sequence number, that sequence number is not stored.
        This is incredibly useful and is used as the foundation of the packet level ack system and the reliable message send and receive queues.
        @see Connection
     */
    public class SequenceBuffer<T> : IDisposable where T : class, new()
    {
        /**
            Sequence buffer constructor.
            @param allocator The allocator to use.
            @param size The size of the sequence buffer.
         */
        public SequenceBuffer(Allocator allocator, int size)
        {
            yojimbo.assert(size > 0);
            m_size = size;
            m_sequence = 0;
            m_allocator = allocator;
            m_entry_sequence = yojimbo.YOJIMBO_ALLOCATE<uint>(allocator, size);
            m_entries = yojimbo.YOJIMBO_ALLOCATE<T>(allocator, size);
            for (var i = 0; i < size; ++i)
                m_entries[i] = new T();
            Reset();
        }

        /**
            Sequence buffer destructor.
         */
        public void Dispose()
        {
            yojimbo.assert(m_allocator != null);
            yojimbo.YOJIMBO_FREE(m_allocator, ref m_entries);
            yojimbo.YOJIMBO_FREE(m_allocator, ref m_entry_sequence);
            m_allocator = null;
        }

        /**
            Reset the sequence buffer.
            Removes all entries from the sequence buffer and restores it to initial state.
         */
        public void Reset()
        {
            m_sequence = 0;
            Array.Fill(m_entry_sequence, 0xFFFFFFFFU);
        }

        /**
            Insert an entry in the sequence buffer.
            IMPORTANT: If another entry exists at the sequence modulo buffer size, it is overwritten.
            @param sequence The sequence number.
            @param guaranteed_order Set this to true if you know the sequence number is always newer than the most recent one inserted (for example, outgoing packet sequence numbers). The entry is then never rejected as too old, even after the sequence number has advanced more than half the sequence space without an insert (#138).
            @returns The sequence buffer entry, which you must fill with your data. null if a sequence buffer entry could not be added for your sequence number (if the sequence number is too old for example).
         */
        public T Insert(ushort sequence, bool guaranteed_order = false)
        {
            if (yojimbo.sequence_greater_than((ushort)(sequence + 1), m_sequence) || guaranteed_order)
            {
                RemoveEntries(m_sequence, sequence);
                m_sequence = (ushort)(sequence + 1);
            }
            else if (yojimbo.sequence_less_than(sequence, (ushort)(m_sequence - m_size)))
                return null;
            var index = sequence % m_size;
            m_entry_sequence[index] = sequence;
            return m_entries[index];
        }

        /**
            Remove an entry from the sequence buffer.
            @param sequence The sequence number of the entry to remove.
         */
        public void Remove(ushort sequence) =>
            m_entry_sequence[sequence % m_size] = 0xFFFFFFFF;

        /**
            Is the entry corresponding to the sequence number available? eg. Currently unoccupied.
            This works because older entries are automatically set back to unoccupied state as the sequence buffer advances forward.
            @param sequence The sequence number.
            @returns True if the sequence buffer entry is available, false if it is already occupied.
         */

        public bool Available(ushort sequence) =>
            m_entry_sequence[sequence % m_size] == 0xFFFFFFFF;

        /**
            Does an entry exist for a sequence number?
            @param sequence The sequence number.
            @returns True if an entry exists for this sequence number.
         */
        public bool Exists(ushort sequence) =>
            m_entry_sequence[sequence % m_size] == sequence;

        /**
            Get the entry corresponding to a sequence number.
            @param sequence The sequence number.
            @returns The entry if it exists. null if no entry is in the buffer for this sequence number.
         */
        public T Find(ushort sequence)
        {
            var index = sequence % m_size;
            return (m_entry_sequence[index] == sequence) ?
                m_entries[index] :
                null;
        }

        /**
            Get the entry at the specified index.
            Use this to iterate across entries in the sequence buffer.
            @param index The entry index in [0,GetSize()-1].
            @returns The entry if it exists. null if no entry is in the buffer at the specified index.
         */
        public T GetAtIndex(int index)
        {
            yojimbo.assert(index >= 0);
            yojimbo.assert(index < m_size);
            return m_entry_sequence[index] != 0xFFFFFFFF ? m_entries[index] : null;
        }

        /**
            Get the most recent sequence number added to the buffer.
            This sequence number can wrap around, so if you are at 65535 and add an entry for sequence 0, then 0 becomes the new "most recent" sequence number.
            @returns The most recent sequence number.
            @see yojimbo::sequence_greater_than
            @see yojimbo::sequence_less_than
         */
        public ushort GetSequence() =>
            m_sequence;

        /**
            Get the entry index for a sequence number.
            This is simply the sequence number modulo the sequence buffer size.
            @param sequence The sequence number.
            @returns The sequence buffer index corresponding of the sequence number.
         */

        public int GetIndex(ushort sequence) =>
            sequence % m_size;

        /** 
            Get the size of the sequence buffer.
            @returns The size of the sequence buffer (number of entries).
         */
        public int GetSize() =>
            m_size;

        /** 
            Helper function to remove entries.
            This is used to remove old entries as we advance the sequence buffer forward. 
            Otherwise, if when entries are added with holes (eg. receive buffer for packets or messages, where not all sequence numbers are added to the buffer because we have high packet loss), 
            and we are extremely unlucky, we can have old sequence buffer entries from the previous sequence # wrap around still in the buffer, which corrupts our internal connection state.
            This actually happened in the soak test at high packet loss levels (>90%). It took me days to track it down :)
         */
        protected void RemoveEntries(int start_sequence, int finish_sequence)
        {
            if (finish_sequence < start_sequence)
                finish_sequence += 65535;
            yojimbo.assert(finish_sequence >= start_sequence);
            if (finish_sequence - start_sequence < m_size)
                for (int sequence = start_sequence; sequence <= finish_sequence; ++sequence)
                    m_entry_sequence[sequence % m_size] = 0xFFFFFFFF;
            else
                for (int i = 0; i < m_size; ++i)
                    m_entry_sequence[i] = 0xFFFFFFFF;
        }

        Allocator m_allocator;                      ///< The allocator passed in to the constructor.
        int m_size;                                 ///< The size of the sequence buffer.
        ushort m_sequence;                          ///< The most recent sequence number added to the buffer.
        uint[] m_entry_sequence;                    ///< Array of sequence numbers corresponding to each sequence buffer entry for fast lookup. Set to 0xFFFFFFFF if no entry exists at that index.
        T[] m_entries;                              ///< The sequence buffer entries. This is where the data is stored per-entry. Separate from the sequence numbers for fast lookup (hot/cold split) when the data per-sequence number is relatively large.

        //SequenceBuffer( SequenceBuffer<T>  other );
        //SequenceBuffer<T> & operator = ( const SequenceBuffer<T> & other );
    }
}
