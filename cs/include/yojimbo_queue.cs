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
        A simple templated queue.
        This is a FIFO queue. First entry in, first entry out. Fixed size circular buffer, mirrors yojimbo::Queue<T> (upstream include/yojimbo_queue.h).
        Named QueueEx so it does not collide with System.Collections.Generic.Queue<T>.
     */
    public class QueueEx<T> : IDisposable
    {
        /**
            Queue constructor.
            @param allocator The allocator to use.
            @param size The maximum number of entries in the queue.
         */
        public QueueEx(Allocator allocator, int size)
        {
            yojimbo.assert(size > 0);
            m_arraySize = size;
            m_startIndex = 0;
            m_numEntries = 0;
            m_allocator = allocator;
            m_entries = yojimbo.YOJIMBO_ALLOCATE<T>(allocator, size);
        }

        /**
            Queue destructor.
         */
        public void Dispose()
        {
            yojimbo.assert(m_allocator != null);
            yojimbo.YOJIMBO_FREE(m_allocator, ref m_entries);
            m_arraySize = 0;
            m_startIndex = 0;
            m_numEntries = 0;
            m_allocator = null;
        }

        /**
            Clear all entries in the queue and reset back to default state.
         */
        public void Clear()
        {
            Array.Clear(m_entries, 0, m_entries.Length);
            m_numEntries = 0;
            m_startIndex = 0;
        }

        /**
            Pop a value off the queue.
            IMPORTANT: This will assert if the queue is empty. Check Queue::IsEmpty or Queue::GetNumEntries first!
            @returns The value popped off the queue.
         */
        public T Pop()
        {
            yojimbo.assert(!IsEmpty);
            var entry = m_entries[m_startIndex];
            m_entries[m_startIndex] = default;
            m_startIndex = (m_startIndex + 1) % m_arraySize;
            m_numEntries--;
            return entry;
        }

        /**
            Push a value on to the queue.
            @param value The value to push onto the queue.
            IMPORTANT: Will assert if the queue is already full. Check Queue::IsFull before calling this!
         */
        public void Push(T value)
        {
            yojimbo.assert(!IsFull);
            var index = (m_startIndex + m_numEntries) % m_arraySize;
            m_entries[index] = value;
            m_numEntries++;
        }

        /**
            Random access for entries in the queue.
            @param index The index into the queue. 0 is the oldest entry, Queue::GetNumEntries() - 1 is the newest.
            @returns The value in the queue at the index.
         */
        public T this[int index]
        {
            get
            {
                yojimbo.assert(!IsEmpty);
                yojimbo.assert(index >= 0);
                yojimbo.assert(index < m_numEntries);
                return m_entries[(m_startIndex + index) % m_arraySize];
            }
            set
            {
                yojimbo.assert(!IsEmpty);
                yojimbo.assert(index >= 0);
                yojimbo.assert(index < m_numEntries);
                m_entries[(m_startIndex + index) % m_arraySize] = value;
            }
        }

        /**
            Get the size of the queue.
            This is the maximum number of values that can be pushed on the queue.
            @returns The size of the queue.
         */
        public int Size => m_arraySize;
        public int GetSize() => m_arraySize;

        /**
            Is the queue currently full?
            @returns True if the queue is full. False otherwise.
         */
        public bool IsFull => m_numEntries == m_arraySize;

        /**
            Is the queue currently empty?
            @returns True if there are no entries in the queue.
         */
        public bool IsEmpty => m_numEntries == 0;

        /**
            Get the number of entries in the queue.
            @returns The number of entries in the queue in [0,GetSize()].
         */
        public int NumEntries => m_numEntries;
        public int GetNumEntries() => m_numEntries;

        Allocator m_allocator;                          ///< The allocator passed in to the constructor.
        T[] m_entries;                                  ///< Array of entries backing the queue (circular buffer).
        int m_arraySize;                                ///< The size of the array, in number of entries. This is the "size" of the queue.
        int m_startIndex;                               ///< The start index for the queue. This is the next value that gets popped off.
        int m_numEntries;                               ///< The number of entries currently stored in the queue.
    }
}
