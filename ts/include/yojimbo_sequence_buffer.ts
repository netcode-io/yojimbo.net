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
    TypeScript port of include/yojimbo_sequence_buffer.h (yojimbo 1.13.5).

    Port notes:
      - Upstream allocates the entries as raw memory of sizeof(T) * size. Here the entries are objects made once by the
        `create` factory passed to the constructor and reused in place: Insert returns the entry for the caller to fill,
        exactly as upstream returns a pointer into the array. The entry array is charged to the allocator as one block.
      - The entry sequence numbers are a Uint32Array view over a block allocated from the allocator, as upstream.
      - Sequence numbers are uint16 held in numbers; arithmetic is truncated with & 0xFFFF where upstream converts to uint16_t.
*/

import { Allocator, YOJIMBO_ALLOCATE, YOJIMBO_FREE, YOJIMBO_NEW, YOJIMBO_DELETE } from '../source/yojimbo_allocator.ts';
import { yojimbo_assert } from '../source/yojimbo_platform.ts';
import { yojimbo_sequence_greater_than, yojimbo_sequence_less_than } from '../source/yojimbo_utils.ts';

const ENTRY_EMPTY = 0xFFFFFFFF;

/**
    Data structure that stores data indexed by sequence number.
    Entries may or may not exist. If they don't exist the sequence value for the entry at that index is set to 0xFFFFFFFF.
    This provides a constant time lookup for an entry by sequence number. If the entry at sequence modulo buffer size doesn't have the same sequence number, that sequence number is not stored.
    This is incredibly useful and is used as the foundation of the packet level ack system and the reliable message send and receive queues.
    @see Connection
 */

export class SequenceBuffer<T>
{
    private m_allocator: Allocator | null;                  ///< The allocator passed in to the constructor.
    private m_size: number;                                 ///< The size of the sequence buffer.
    private m_sequence: number;                             ///< The most recent sequence number added to the buffer (uint16).
    private m_entry_sequence_memory: Uint8Array | null;     ///< The block backing m_entry_sequence.
    private m_entry_sequence: Uint32Array;                  ///< Array of sequence numbers corresponding to each sequence buffer entry for fast lookup. Set to 0xFFFFFFFF if no entry exists at that index.
    private m_entries: T[] | null;                          ///< The sequence buffer entries. This is where the data is stored per-entry. Separate from the sequence numbers for fast lookup (hot/cold split) when the data per-sequence number is relatively large.

    /**
        Sequence buffer constructor.
        @param allocator The allocator to use.
        @param size The size of the sequence buffer.
        @param create Creates one entry object (the entries are created up front and reused).
     */

    constructor( allocator: Allocator, size: number, create: () => T )
    {
        yojimbo_assert( size > 0, "size > 0", "SequenceBuffer::SequenceBuffer" );
        this.m_size = size;
        this.m_sequence = 0;
        this.m_allocator = allocator;
        this.m_entry_sequence_memory = YOJIMBO_ALLOCATE( allocator, 4 * size );
        yojimbo_assert( this.m_entry_sequence_memory, "m_entry_sequence", "SequenceBuffer::SequenceBuffer" );
        this.m_entry_sequence = new Uint32Array( this.m_entry_sequence_memory.buffer, this.m_entry_sequence_memory.byteOffset, size );
        this.m_entries = YOJIMBO_NEW( allocator, () => { const entries = new Array<T>( size ); for ( let i = 0; i < size; ++i ) entries[i] = create(); return entries; }, 8 * size );
        yojimbo_assert( this.m_entries, "m_entries", "SequenceBuffer::SequenceBuffer" );
        this.Reset();
    }

    /**
        Sequence buffer destructor.
     */

    Dispose(): void
    {
        yojimbo_assert( this.m_allocator, "m_allocator", "SequenceBuffer::~SequenceBuffer" );
        this.m_entries = YOJIMBO_DELETE( this.m_allocator, this.m_entries );
        this.m_entry_sequence_memory = YOJIMBO_FREE( this.m_allocator, this.m_entry_sequence_memory );
        this.m_allocator = null;
    }

    /**
        Reset the sequence buffer.
        Removes all entries from the sequence buffer and restores it to initial state.
     */

    Reset(): void
    {
        this.m_sequence = 0;
        this.m_entry_sequence.fill( ENTRY_EMPTY );
    }

    /**
        Insert an entry in the sequence buffer.
        IMPORTANT: If another entry exists at the sequence modulo buffer size, it is overwritten.
        @param sequence The sequence number.
        @param guaranteed_order Whether sequence is always the newest value (when sending) or can be out of order (when receiving).
        @returns The sequence buffer entry, which you must fill with your data. null if a sequence buffer entry could not be added for your sequence number (if the sequence number is too old for example).
     */

    Insert( sequence: number, guaranteed_order: boolean = false ): T | null
    {
        sequence &= 0xFFFF;
        if ( yojimbo_sequence_greater_than( sequence + 1, this.m_sequence ) || guaranteed_order )
        {
            this.RemoveEntries( this.m_sequence, sequence );
            this.m_sequence = ( sequence + 1 ) & 0xFFFF;
        }
        else if ( yojimbo_sequence_less_than( sequence, this.m_sequence - this.m_size ) )
        {
            return null;
        }
        const index = sequence % this.m_size;
        this.m_entry_sequence[index] = sequence;
        return this.m_entries![index];
    }

    /**
        Remove an entry from the sequence buffer.
        @param sequence The sequence number of the entry to remove.
     */

    Remove( sequence: number ): void
    {
        this.m_entry_sequence[( sequence & 0xFFFF ) % this.m_size] = ENTRY_EMPTY;
    }

    /**
        Is the entry corresponding to the sequence number available? eg. Currently unoccupied.
        This works because older entries are automatically set back to unoccupied state as the sequence buffer advances forward.
        @param sequence The sequence number.
        @returns True if the sequence buffer entry is available, false if it is already occupied.
     */

    Available( sequence: number ): boolean
    {
        return this.m_entry_sequence[( sequence & 0xFFFF ) % this.m_size] === ENTRY_EMPTY;
    }

    /**
        Does an entry exist for a sequence number?
        @param sequence The sequence number.
        @returns True if an entry exists for this sequence number.
     */

    Exists( sequence: number ): boolean
    {
        sequence &= 0xFFFF;
        return this.m_entry_sequence[sequence % this.m_size] === sequence;
    }

    /**
        Get the entry corresponding to a sequence number.
        @param sequence The sequence number.
        @returns The entry if it exists. null if no entry is in the buffer for this sequence number.
     */

    Find( sequence: number ): T | null
    {
        sequence &= 0xFFFF;
        const index = sequence % this.m_size;
        if ( this.m_entry_sequence[index] === sequence )
            return this.m_entries![index];
        else
            return null;
    }

    /**
        Get the entry at the specified index.
        Use this to iterate across entries in the sequence buffer.
        @param index The entry index in [0,GetSize()-1].
        @returns The entry if it exists. null if no entry is in the buffer at the specified index.
     */

    GetAtIndex( index: number ): T | null
    {
        yojimbo_assert( index >= 0, "index >= 0", "SequenceBuffer::GetAtIndex" );
        yojimbo_assert( index < this.m_size, "index < m_size", "SequenceBuffer::GetAtIndex" );
        return this.m_entry_sequence[index] !== ENTRY_EMPTY ? this.m_entries![index] : null;
    }

    /**
        Get the most recent sequence number added to the buffer.
        This sequence number can wrap around, so if you are at 65535 and add an entry for sequence 0, then 0 becomes the new "most recent" sequence number.
        @returns The most recent sequence number.
        @see yojimbo_sequence_greater_than
        @see yojimbo_sequence_less_than
     */

    GetSequence(): number
    {
        return this.m_sequence;
    }

    /**
        Get the entry index for a sequence number.
        This is simply the sequence number modulo the sequence buffer size.
        @param sequence The sequence number.
        @returns The sequence buffer index corresponding of the sequence number.
     */

    GetIndex( sequence: number ): number
    {
        return ( sequence & 0xFFFF ) % this.m_size;
    }

    /**
        Get the size of the sequence buffer.
        @returns The size of the sequence buffer (number of entries).
     */

    GetSize(): number
    {
        return this.m_size;
    }

    /**
        Helper function to remove entries.
        This is used to remove old entries as we advance the sequence buffer forward.
        Otherwise, if when entries are added with holes (eg. receive buffer for packets or messages, where not all sequence numbers are added to the buffer because we have high packet loss),
        and we are extremely unlucky, we can have old sequence buffer entries from the previous sequence # wrap around still in the buffer, which corrupts our internal connection state.
        This actually happened in the soak test at high packet loss levels (>90%). It took me days to track it down :)
     */

    protected RemoveEntries( start_sequence: number, finish_sequence: number ): void
    {
        if ( finish_sequence < start_sequence )
            finish_sequence += 65535;
        yojimbo_assert( finish_sequence >= start_sequence, "finish_sequence >= start_sequence", "SequenceBuffer::RemoveEntries" );
        if ( finish_sequence - start_sequence < this.m_size )
        {
            for ( let sequence = start_sequence; sequence <= finish_sequence; ++sequence )
                this.m_entry_sequence[sequence % this.m_size] = ENTRY_EMPTY;
        }
        else
        {
            for ( let i = 0; i < this.m_size; ++i )
                this.m_entry_sequence[i] = ENTRY_EMPTY;
        }
    }
}
