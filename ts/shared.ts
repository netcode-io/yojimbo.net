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
    TypeScript port of shared.h (yojimbo 1.13.5): the message types, message factories and adapter shared by the
    tests and samples.
*/

import {
    BaseStream, serialize_bits,
    Message, BlockMessage, MessageFactory, YOJIMBO_MESSAGE_FACTORY,
    Adapter, Allocator, YOJIMBO_NEW, YOJIMBO_ALLOCATE, YOJIMBO_FREE,
} from './source/yojimbo.ts';

export const ProtocolId = 0x11223344556677n;

export const ClientPort = 30000;
export const ServerPort = 40000;

const messageBitsArray = [ 1, 320, 120, 4, 256, 45, 11, 13, 101, 100, 84, 95, 203, 2, 3, 8, 512, 5, 3, 7, 50 ];

export function GetNumBitsForMessage( sequence: number ): number
{
    const modulus = messageBitsArray.length;
    const index = sequence % modulus;
    return messageBitsArray[index];
}

/** Scratch slot for the dummy bits (single threaded). */
const dummy = { value: 0 };

export class TestMessage extends Message
{
    sequence = 0;                       // uint16

    Serialize( stream: BaseStream ): boolean
    {
        if ( !serialize_bits( stream, this, 'sequence', 16 ) )
            return false;

        const numBits = GetNumBitsForMessage( this.sequence );
        const numWords = Math.floor( numBits / 32 );
        dummy.value = 0;
        for ( let i = 0; i < numWords; ++i )
        {
            if ( !serialize_bits( stream, dummy, 'value', 32 ) )
                return false;
        }
        const numRemainderBits = numBits - numWords * 32;
        if ( numRemainderBits > 0 )
        {
            if ( !serialize_bits( stream, dummy, 'value', numRemainderBits ) )
                return false;
        }

        return true;
    }
}

export class TestBlockMessage extends BlockMessage
{
    sequence = 0;                       // uint16

    override Serialize( stream: BaseStream ): boolean
    {
        if ( !serialize_bits( stream, this, 'sequence', 16 ) )
            return false;
        return true;
    }
}

export class TestSerializeFailOnReadMessage extends Message
{
    Serialize( stream: BaseStream ): boolean
    {
        return !stream.IsReading;
    }
}

export class TestExhaustStreamAllocatorOnReadMessage extends Message
{
    Serialize( stream: BaseStream ): boolean
    {
        if ( stream.IsReading )
        {
            const NumBuffers = 100;

            const buffers = new Array<Uint8Array | null>( NumBuffers ).fill( null );

            const allocator = stream.GetAllocator() as Allocator;

            for ( let i = 0; i < NumBuffers; ++i )
            {
                buffers[i] = YOJIMBO_ALLOCATE( allocator, 1024 * 1024 );
            }

            for ( let i = 0; i < NumBuffers; ++i )
            {
                buffers[i] = YOJIMBO_FREE( allocator, buffers[i] );
            }
        }

        return true;
    }
}

export const TEST_MESSAGE = 0;
export const TEST_BLOCK_MESSAGE = 1;
export const TEST_SERIALIZE_FAIL_ON_READ_MESSAGE = 2;
export const TEST_EXHAUST_STREAM_ALLOCATOR_ON_READ_MESSAGE = 3;
export const NUM_TEST_MESSAGE_TYPES = 4;

export const TestMessageFactory = YOJIMBO_MESSAGE_FACTORY( NUM_TEST_MESSAGE_TYPES, [
    [ TEST_MESSAGE, TestMessage ],
    [ TEST_BLOCK_MESSAGE, TestBlockMessage ],
    [ TEST_SERIALIZE_FAIL_ON_READ_MESSAGE, TestSerializeFailOnReadMessage ],
    [ TEST_EXHAUST_STREAM_ALLOCATOR_ON_READ_MESSAGE, TestExhaustStreamAllocatorOnReadMessage ],
], "TestMessageFactory" );

export const SINGLE_TEST_MESSAGE = 0;
export const NUM_SINGLE_TEST_MESSAGE_TYPES = 1;

export const SingleTestMessageFactory = YOJIMBO_MESSAGE_FACTORY( NUM_SINGLE_TEST_MESSAGE_TYPES, [
    [ SINGLE_TEST_MESSAGE, TestMessage ],
], "SingleTestMessageFactory" );

export const SINGLE_BLOCK_TEST_MESSAGE = 0;
export const NUM_SINGLE_BLOCK_TEST_MESSAGE_TYPES = 1;

export const SingleBlockTestMessageFactory = YOJIMBO_MESSAGE_FACTORY( NUM_SINGLE_BLOCK_TEST_MESSAGE_TYPES, [
    [ SINGLE_BLOCK_TEST_MESSAGE, TestBlockMessage ],
], "SingleBlockTestMessageFactory" );

export class TestAdapter extends Adapter
{
    override CreateMessageFactory( allocator: Allocator ): MessageFactory | null
    {
        return YOJIMBO_NEW( allocator, () => new TestMessageFactory( allocator ) );
    }
}

export const adapter = new TestAdapter();
