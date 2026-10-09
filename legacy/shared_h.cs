/*
    Shared Code for Tests and Examples.

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

using networkprotocol;

public static class shared
{
    public const ulong ProtocolId = 0x11223344556677UL;

    public const int ClientPort = 30001;
    public const int ServerPort = 40001;

    static int[] messageBitsArray = { 1, 320, 120, 4, 256, 45, 11, 13, 101, 100, 84, 95, 203, 2, 3, 8, 512, 5, 3, 7, 50 };
    public static int GetNumBitsForMessage(ushort sequence)
    {
        var modulus = messageBitsArray.Length;
        var index = sequence % modulus;
        return messageBitsArray[index];
    }

    public static TestAdapter adapter= new TestAdapter();
}

internal class TestMessage : Message
{
    public ushort sequence = 0;

    public override bool Serialize(BaseStream stream)
    {
        yojimbo.serialize_bits(stream, ref sequence, 16);

        var numBits = shared.GetNumBitsForMessage(sequence);
        var numWords = numBits / 32;
        var dummy = 0U;
        for (var i = 0; i < numWords; ++i)
            yojimbo.serialize_bits(stream, ref dummy, 32);
        var numRemainderBits = numBits - numWords * 32;
        if (numRemainderBits > 0)
            yojimbo.serialize_bits(stream, ref dummy, numRemainderBits);

        return true;
    }
}

internal class TestBlockMessage : BlockMessage
{
    public ushort sequence = 0;

    public override bool Serialize(BaseStream stream)
    {
        yojimbo.serialize_bits(stream, ref sequence, 16);
        return true;
    }
}

internal class TestSerializeFailOnReadMessage : Message
{
    public override bool Serialize(BaseStream stream) =>
        !stream.IsReading;
}

internal class TestExhaustStreamAllocatorOnReadMessage : Message
{
    public override bool Serialize(BaseStream stream)
    {
        if (stream.IsReading)
        {
            const int NumBuffers = 100;

            var buffers = new byte[NumBuffers][];

            for (var i = 0; i < NumBuffers; ++i)
                buffers[i] = new byte[1024 * 1024];

            for (var i = 0; i < NumBuffers; ++i)
                buffers[i] = null;
        }

        return true;
    }
}

internal enum TestMessageType
{
    TEST_MESSAGE,
    TEST_BLOCK_MESSAGE,
    TEST_SERIALIZE_FAIL_ON_READ_MESSAGE,
    TEST_EXHAUST_STREAM_ALLOCATOR_ON_READ_MESSAGE,
    NUM_TEST_MESSAGE_TYPES
}

internal class TestMessageFactory : MESSAGE_FACTORY_START
{
    public TestMessageFactory(Allocator allocator) : base(allocator, (int)TestMessageType.NUM_TEST_MESSAGE_TYPES)
    {
        DECLARE_MESSAGE_TYPE((int)TestMessageType.TEST_MESSAGE, typeof(TestMessage));
        DECLARE_MESSAGE_TYPE((int)TestMessageType.TEST_BLOCK_MESSAGE, typeof(TestBlockMessage));
        DECLARE_MESSAGE_TYPE((int)TestMessageType.TEST_SERIALIZE_FAIL_ON_READ_MESSAGE, typeof(TestSerializeFailOnReadMessage));
        DECLARE_MESSAGE_TYPE((int)TestMessageType.TEST_EXHAUST_STREAM_ALLOCATOR_ON_READ_MESSAGE, typeof(TestExhaustStreamAllocatorOnReadMessage));
        MESSAGE_FACTORY_FINISH();
    }
}

internal enum SingleTestMessageType
{
    SINGLE_TEST_MESSAGE,
    NUM_SINGLE_TEST_MESSAGE_TYPES
}

internal class SingleTestMessageFactory : MESSAGE_FACTORY_START
{
    public SingleTestMessageFactory(Allocator allocator) : base(allocator, (int)SingleTestMessageType.NUM_SINGLE_TEST_MESSAGE_TYPES)
    {
        DECLARE_MESSAGE_TYPE((int)SingleTestMessageType.SINGLE_TEST_MESSAGE, typeof(TestMessage));
        MESSAGE_FACTORY_FINISH();
    }
}

internal enum SingleBlockTestMessageType
{
    SINGLE_BLOCK_TEST_MESSAGE,
    NUM_SINGLE_BLOCK_TEST_MESSAGE_TYPES
}

internal class SingleBlockTestMessageFactory : MESSAGE_FACTORY_START
{
    public SingleBlockTestMessageFactory(Allocator allocator) : base(allocator, (int)SingleBlockTestMessageType.NUM_SINGLE_BLOCK_TEST_MESSAGE_TYPES)
    {
        DECLARE_MESSAGE_TYPE((int)SingleBlockTestMessageType.SINGLE_BLOCK_TEST_MESSAGE, typeof(TestBlockMessage));
        MESSAGE_FACTORY_FINISH();
    }
}

public class TestAdapter : Adapter
{
    public override MessageFactory CreateMessageFactory(Allocator allocator) =>
        new TestMessageFactory(allocator);
}
