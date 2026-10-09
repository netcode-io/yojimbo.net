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
    TypeScript port of include/yojimbo_queue.h (yojimbo 1.13.5).

    The entry array is charged to the allocator as one block (8 bytes per entry) and freed by Dispose(), the destructor.
    operator[] is Get( index ) / Set( index, value ).
*/

import { Allocator, YOJIMBO_NEW, YOJIMBO_DELETE } from '../source/yojimbo_allocator.ts';
import { yojimbo_assert } from '../source/yojimbo_platform.ts';

/**
    A simple templated queue.
    This is a FIFO queue. First entry in, first entry out.
 */

export class Queue<T>
{
    private m_allocator: Allocator | null;                  ///< The allocator passed in to the constructor.
    private m_entries: Array<T | undefined> | null;         ///< Array of entries backing the queue (circular buffer).
    private m_arraySize: number;                            ///< The size of the array, in number of entries. This is the "size" of the queue.
    private m_startIndex: number;                           ///< The start index for the queue. This is the next value that gets popped off.
    private m_numEntries: number;                           ///< The number of entries currently stored in the queue.

    /**
        Queue constructor.
        @param allocator The allocator to use.
        @param size The maximum number of entries in the queue.
     */

    constructor( allocator: Allocator, size: number )
    {
        yojimbo_assert( size > 0, "size > 0", "Queue::Queue" );
        this.m_arraySize = size;
        this.m_startIndex = 0;
        this.m_numEntries = 0;
        this.m_allocator = allocator;
        this.m_entries = YOJIMBO_NEW( allocator, () => new Array<T | undefined>( size ).fill( undefined ), 8 * size );
        yojimbo_assert( this.m_entries, "m_entries", "Queue::Queue" );
    }

    /**
        Queue destructor.
     */

    Dispose(): void
    {
        yojimbo_assert( this.m_allocator, "m_allocator", "Queue::~Queue" );
        this.m_entries = YOJIMBO_DELETE( this.m_allocator, this.m_entries );
        this.m_arraySize = 0;
        this.m_startIndex = 0;
        this.m_numEntries = 0;
        this.m_allocator = null;
    }

    /**
        Clear all entries in the queue and reset back to default state.
     */

    Clear(): void
    {
        this.m_entries!.fill( undefined );          // drop the references (upstream leaves the values in place)
        this.m_numEntries = 0;
        this.m_startIndex = 0;
    }

    /**
        Pop a value off the queue.
        IMPORTANT: This will assert if the queue is empty. Check Queue::IsEmpty or Queue::GetNumEntries first!
        @returns The value popped off the queue.
     */

    Pop(): T
    {
        yojimbo_assert( !this.IsEmpty(), "!IsEmpty()", "Queue::Pop" );
        const entries = this.m_entries!;
        const entry = entries[this.m_startIndex] as T;
        entries[this.m_startIndex] = undefined;
        this.m_startIndex = ( this.m_startIndex + 1 ) % this.m_arraySize;
        this.m_numEntries--;
        return entry;
    }

    /**
        Push a value on to the queue.
        @param value The value to push onto the queue.
        IMPORTANT: Will assert if the queue is already full. Check Queue::IsFull before calling this!
     */

    Push( value: T ): void
    {
        yojimbo_assert( !this.IsFull(), "!IsFull()", "Queue::Push" );
        const index = ( this.m_startIndex + this.m_numEntries ) % this.m_arraySize;
        this.m_entries![index] = value;
        this.m_numEntries++;
    }

    /**
        Random access for entries in the queue (operator[]).
        @param index The index into the queue. 0 is the oldest entry, Queue::GetNumEntries() - 1 is the newest.
        @returns The value in the queue at the index.
     */

    Get( index: number ): T
    {
        yojimbo_assert( !this.IsEmpty(), "!IsEmpty()", "Queue::operator[]" );
        yojimbo_assert( index >= 0, "index >= 0", "Queue::operator[]" );
        yojimbo_assert( index < this.m_numEntries, "index < m_numEntries", "Queue::operator[]" );
        return this.m_entries![( this.m_startIndex + index ) % this.m_arraySize] as T;
    }

    /**
        Random access assignment for entries in the queue (operator[] as an lvalue).
        @param index The index into the queue. 0 is the oldest entry, Queue::GetNumEntries() - 1 is the newest.
        @param value The value to store.
     */

    Set( index: number, value: T ): void
    {
        yojimbo_assert( !this.IsEmpty(), "!IsEmpty()", "Queue::operator[]" );
        yojimbo_assert( index >= 0, "index >= 0", "Queue::operator[]" );
        yojimbo_assert( index < this.m_numEntries, "index < m_numEntries", "Queue::operator[]" );
        this.m_entries![( this.m_startIndex + index ) % this.m_arraySize] = value;
    }

    /**
        Get the size of the queue.
        This is the maximum number of values that can be pushed on the queue.
        @returns The size of the queue.
     */

    GetSize(): number
    {
        return this.m_arraySize;
    }

    /**
        Is the queue currently full?
        @returns True if the queue is full. False otherwise.
     */

    IsFull(): boolean
    {
        return this.m_numEntries === this.m_arraySize;
    }

    /**
        Is the queue currently empty?
        @returns True if there are no entries in the queue.
     */

    IsEmpty(): boolean
    {
        return this.m_numEntries === 0;
    }

    /**
        Get the number of entries in the queue.
        @returns The number of entries in the queue in [0,GetSize()].
     */

    GetNumEntries(): number
    {
        return this.m_numEntries;
    }
}
