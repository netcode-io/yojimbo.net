/*
    Yojimbo Unit Tests.

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
//#define SOAK

using networkprotocol;
using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;
using static networkprotocol.yojimbo;

public static class test
{
    static void CheckHandler(string condition, string function, string file, int line)
    {
        Console.Write($"check failed: ( {condition} ), function {function}, file {file}, line {line}\n");
        Debugger.Break();
        Environment.Exit(1);
    }

    [DebuggerStepThrough]
    public static void check(bool condition)
    {
        if (!condition)
        {
            var stackFrame = new StackTrace().GetFrame(1);
            CheckHandler("n/a", stackFrame.GetMethod().Name, stackFrame.GetFileName(), stackFrame.GetFileLineNumber());
        }
    }

    static void test_endian()
    {
        const ulong value = 0x11223344UL;

        var bytes = BitConverter.GetBytes(value);
        check(bytes[0] == 0x44);
        check(bytes[1] == 0x33);
        check(bytes[2] == 0x22);
        check(bytes[3] == 0x11);
        //check(bytes[3] == 0x44);
        //check(bytes[2] == 0x33);
        //check(bytes[1] == 0x22);
        //check(bytes[0] == 0x11);
    }

    static void test_queue()
    {
        const int QueueSize = 1024;

        var queue = new QueueEx<int>(DefaultAllocator, QueueSize);

        check(queue.IsEmpty);
        check(!queue.IsFull);
        check(queue.NumEntries == 0);
        check(queue.Size == QueueSize);

        const int NumEntries = 100;

        for (var i = 0; i < NumEntries; ++i)
            queue.Enqueue(i);

        check(!queue.IsEmpty);
        check(!queue.IsFull);
        check(queue.NumEntries == NumEntries);
        check(queue.Size == QueueSize);

        for (var i = 0; i < NumEntries; ++i)
            check(queue[i] == i);

        for (var i = 0; i < NumEntries; ++i)
            check(queue.Dequeue() == i);

        check(queue.IsEmpty);
        check(!queue.IsFull);
        check(queue.NumEntries == 0);
        check(queue.Size == QueueSize);

        for (var i = 0; i < QueueSize; ++i)
            queue.Enqueue(i);

        check(!queue.IsEmpty);
        check(queue.IsFull);
        check(queue.NumEntries == QueueSize);
        check(queue.Size == QueueSize);

        queue.Clear();

        check(queue.IsEmpty);
        check(!queue.IsFull);
        check(queue.NumEntries == 0);
        check(queue.Size == QueueSize);
    }

#if YOJIMBO_WITH_MBEDTLS

static void test_base64()
{
    const int BufferSize = 256;

    char input[BufferSize];
    char encoded[BufferSize*2];
    char decoded[BufferSize];

    strcpy( input, "[2001:4860:4860::8888]:50000" );

    const int encoded_bytes = base64_encode_string( input, encoded, sizeof( encoded ) );
 
    check( encoded_bytes == (int) strlen( encoded ) + 1 );

    char encoded_expected[] = "WzIwMDE6NDg2MDo0ODYwOjo4ODg4XTo1MDAwMAA=";

    check( strcmp( encoded, encoded_expected ) == 0 );

    const int decoded_bytes = base64_decode_string( encoded, decoded, sizeof( decoded ) );

    check( decoded_bytes == (int) strlen( decoded ) + 1 );

    check( strcmp( input, decoded ) == 0 );

    uint8_t key[KeyBytes];
    random_bytes( key, KeyBytes );

    char base64_key[KeyBytes*2];
    base64_encode_data( key, KeyBytes, base64_key, (int) sizeof( base64_key ) );

    uint8_t decoded_key[KeyBytes];
    base64_decode_data( base64_key, decoded_key, KeyBytes );

    check( memcmp( key, decoded_key, KeyBytes ) == 0 );
}

#endif

    static void test_bitpacker()
    {
        const int BufferSize = 256;

        var buffer = new byte[BufferSize];

        var writer = new BitWriter(buffer, BufferSize);

        check(writer.Data == buffer);
        check(writer.BitsWritten == 0);
        check(writer.BytesWritten == 0);
        check(writer.BitsAvailable == BufferSize * 8);

        writer.WriteBits(0, 1);
        writer.WriteBits(1, 1);
        writer.WriteBits(10, 8);
        writer.WriteBits(255, 8);
        writer.WriteBits(1000, 10);
        writer.WriteBits(50000, 16);
        writer.WriteBits(9999999, 32);
        writer.FlushBits();

        const int bitsWritten = 1 + 1 + 8 + 8 + 10 + 16 + 32;

        check(writer.BytesWritten == 10);
        check(writer.BitsWritten == bitsWritten);
        check(writer.BitsAvailable == BufferSize * 8 - bitsWritten);

        var bytesWritten = writer.BytesWritten;

        check(bytesWritten == 10);

        BufferEx.SetWithOffset(buffer, bytesWritten, 0, BufferSize - bytesWritten);

        var reader = new BitReader(buffer, bytesWritten);

        check(reader.BitsRead == 0);
        check(reader.BitsRemaining == bytesWritten * 8);

        var a = reader.ReadBits(1);
        var b = reader.ReadBits(1);
        var c = reader.ReadBits(8);
        var d = reader.ReadBits(8);
        var e = reader.ReadBits(10);
        var f = reader.ReadBits(16);
        var g = reader.ReadBits(32);

        check(a == 0);
        check(b == 1);
        check(c == 10);
        check(d == 255);
        check(e == 1000);
        check(f == 50000);
        check(g == 9999999);

        check(reader.BitsRead == bitsWritten);
        check(reader.BitsRemaining == bytesWritten * 8 - bitsWritten);
    }

    static void test_bits_required()
    {
        check(bits_required(0, 0) == 0);
        check(bits_required(0, 1) == 1);
        check(bits_required(0, 2) == 2);
        check(bits_required(0, 3) == 2);
        check(bits_required(0, 4) == 3);
        check(bits_required(0, 5) == 3);
        check(bits_required(0, 6) == 3);
        check(bits_required(0, 7) == 3);
        check(bits_required(0, 8) == 4);
        check(bits_required(0, 255) == 8);
        check(bits_required(0, 65535) == 16);
        check(bits_required(0, 4294967295) == 32);
    }

    const int MaxItems = 11;

    [Serializable]
    class TestData
    {
        public int a, b, c;
        public byte d;
        public byte e;
        public byte f;
        public bool g;
        public int numItems;
        public int[] items = new int[MaxItems];
        public float float_value;
        public double double_value;
        public ulong uint64_value;
        public byte[] bytes = new byte[17];
        public string @string;
    }

    class TestContext
    {
        public int min;
        public int max;
    }

    class TestObject : Serializable
    {
        TestData data = new TestData();

        void Init()
        {
            data.a = 1;
            data.b = -2;
            data.c = 150;
            data.d = 55;
            data.e = 255;
            data.f = 127;
            data.g = true;

            data.numItems = MaxItems / 2;
            for (var i = 0; i < data.numItems; ++i)
                data.items[i] = i + 10;

            data.float_value = 3.1415926f;
            data.double_value = 1 / 3.0;
            data.uint64_value = 0x1234567898765432L;

            for (var i = 0; i < data.bytes.Length; ++i)
                data.bytes[i] = (byte)(BufferEx.Rand() % 255);

            data.@string = "hello world!";
        }

        public override bool Serialize(BaseStream stream)
        {
            var context = (TestContext)stream.Context;

            stream.serialize_int(ref data.a, context.min, context.max);
            stream.serialize_int(ref data.b, context.min, context.max);

            stream.serialize_int(ref data.c, -100, 10000);

            stream.serialize_bits(ref data.d, 6);
            stream.serialize_bits(ref data.e, 8);
            stream.serialize_bits(ref data.f, 7);

            stream.serialize_align();

            stream.serialize_bool(ref data.g);

            stream.serialize_check();

            stream.serialize_int(ref data.numItems, 0, MaxItems - 1);
            for (var i = 0; i < data.numItems; ++i)
                stream.serialize_bits(ref data.items[i], 8);

            stream.serialize_float(ref data.float_value);

            stream.serialize_double(ref data.double_value);

            stream.serialize_uint64(ref data.uint64_value);

            stream.serialize_bytes(data.bytes, data.bytes.Length);

            stream.serialize_string(ref data.@string, MaxAddressLength);

            stream.serialize_check();

            return true;
        }

        public override bool Equals(object obj) =>
            (this == obj as TestObject);

        public override int GetHashCode() =>
            base.GetHashCode();

        public static bool operator ==(TestObject t, TestObject other)
        {
            var bf = new BinaryFormatter();
            using (var s0 = new MemoryStream())
            using (var s1 = new MemoryStream())
            {
                bf.Serialize(s0, t.data); s0.Position = 0;
                bf.Serialize(s1, other.data); s1.Position = 0;
                return BufferEx.Equal(s0.ToArray(), s1.ToArray());
            }
        }

        public static bool operator !=(TestObject t, TestObject other) =>
             !(t == other);

        static void test_stream()
        {
            const int BufferSize = 1024;

            var buffer = new byte[BufferSize];

            var context = new TestContext();
            context.min = -10;
            context.max = +10;

            var writeStream = new WriteStream(DefaultAllocator, buffer, BufferSize);

            var writeObject = new TestObject();
            writeObject.Init();
            writeStream.Context = context;
            writeObject.Serialize(writeStream);
            writeStream.Flush();

            var bytesWritten = writeStream.BytesProcessed;

            BufferEx.SetWithOffset(buffer, bytesWritten, 0, BufferSize - bytesWritten);

            var readObject = new TestObject();
            var readStream = new ReadStream(DefaultAllocator, buffer, bytesWritten);
            readStream.Context = context;
            readObject.Serialize(readStream);

            check(readObject == writeObject);
        }

        static bool parse_address(string string_)
        {
            var address = new Address(string_);
            return address.IsValid;
        }

        static void test_address()
        {
            check(parse_address("") == false);
            check(parse_address("[") == false);
            check(parse_address("[]") == false);
            check(parse_address("[]:") == false);
            check(parse_address(":") == false);
            //check(parse_address("1") == false);
            //check(parse_address("12") == false);
            //check(parse_address("123") == false);
            //check(parse_address("1234") == false);
            check(parse_address("1234.0.12313.0000") == false);
            check(parse_address("1234.0.12313.0000.0.0.0.0.0") == false);
            check(parse_address("1312313:123131:1312313:123131:1312313:123131:1312313:123131:1312313:123131:1312313:123131") == false);
            check(parse_address(".") == false);
            check(parse_address("..") == false);
            check(parse_address("...") == false);
            check(parse_address("....") == false);
            check(parse_address(".....") == false);

            {
                var address = new Address("107.77.207.77");
                check(address.IsValid);
                check(address.Type == AddressType.ADDRESS_IPV4);
                check(address.Port == 0);
                check(address.GetAddress4()[0] == 107);
                check(address.GetAddress4()[1] == 77);
                check(address.GetAddress4()[2] == 207);
                check(address.GetAddress4()[3] == 77);
                check(!address.IsLoopback);
            }

            {
                var address = new Address("127.0.0.1");
                check(address.IsValid);
                check(address.Type == AddressType.ADDRESS_IPV4);
                check(address.Port == 0);
                check(address.GetAddress4()[0] == 127);
                check(address.GetAddress4()[1] == 0);
                check(address.GetAddress4()[2] == 0);
                check(address.GetAddress4()[3] == 1);
                check(address.IsLoopback);
            }

            {
                var address = new Address("107.77.207.77:40000");
                check(address.IsValid);
                check(address.Type == AddressType.ADDRESS_IPV4);
                check(address.Port == 40000);
                check(address.GetAddress4()[0] == 107);
                check(address.GetAddress4()[1] == 77);
                check(address.GetAddress4()[2] == 207);
                check(address.GetAddress4()[3] == 77);
                check(!address.IsLoopback);
            }

            {
                var address = new Address("127.0.0.1:40000");
                check(address.IsValid);
                check(address.Type == AddressType.ADDRESS_IPV4);
                check(address.Port == 40000);
                check(address.GetAddress4()[0] == 127);
                check(address.GetAddress4()[1] == 0);
                check(address.GetAddress4()[2] == 0);
                check(address.GetAddress4()[3] == 1);
                check(address.IsLoopback);
            }

            {
                var address = new Address("fe80::202:b3ff:fe1e:8329");
                check(address.IsValid);
                check(address.Type == AddressType.ADDRESS_IPV6);
                check(address.Port == 0);
                check(address.GetAddress6()[0] == 0xfe80);
                check(address.GetAddress6()[1] == 0x0000);
                check(address.GetAddress6()[2] == 0x0000);
                check(address.GetAddress6()[3] == 0x0000);
                check(address.GetAddress6()[4] == 0x0202);
                check(address.GetAddress6()[5] == 0xb3ff);
                check(address.GetAddress6()[6] == 0xfe1e);
                check(address.GetAddress6()[7] == 0x8329);
                check(!address.IsLoopback);
            }

            {
                var address = new Address("::");
                check(address.IsValid);
                check(address.Type == AddressType.ADDRESS_IPV6);
                check(address.Port == 0);
                check(address.GetAddress6()[0] == 0x0000);
                check(address.GetAddress6()[1] == 0x0000);
                check(address.GetAddress6()[2] == 0x0000);
                check(address.GetAddress6()[3] == 0x0000);
                check(address.GetAddress6()[4] == 0x0000);
                check(address.GetAddress6()[5] == 0x0000);
                check(address.GetAddress6()[6] == 0x0000);
                check(address.GetAddress6()[7] == 0x0000);
                check(!address.IsLoopback);
            }

            {
                var address = new Address("::1");
                check(address.IsValid);
                check(address.Type == AddressType.ADDRESS_IPV6);
                check(address.Port == 0);
                check(address.GetAddress6()[0] == 0x0000);
                check(address.GetAddress6()[1] == 0x0000);
                check(address.GetAddress6()[2] == 0x0000);
                check(address.GetAddress6()[3] == 0x0000);
                check(address.GetAddress6()[4] == 0x0000);
                check(address.GetAddress6()[5] == 0x0000);
                check(address.GetAddress6()[6] == 0x0000);
                check(address.GetAddress6()[7] == 0x0001);
                check(address.IsLoopback);
            }

            {
                var address = new Address("[fe80::202:b3ff:fe1e:8329]:40000");
                check(address.IsValid);
                check(address.Type == AddressType.ADDRESS_IPV6);
                check(address.Port == 40000);
                check(address.GetAddress6()[0] == 0xfe80);
                check(address.GetAddress6()[1] == 0x0000);
                check(address.GetAddress6()[2] == 0x0000);
                check(address.GetAddress6()[3] == 0x0000);
                check(address.GetAddress6()[4] == 0x0202);
                check(address.GetAddress6()[5] == 0xb3ff);
                check(address.GetAddress6()[6] == 0xfe1e);
                check(address.GetAddress6()[7] == 0x8329);
                check(!address.IsLoopback);
            }

            {
                var address = new Address("[::]:40000");
                check(address.IsValid);
                check(address.Type == AddressType.ADDRESS_IPV6);
                check(address.Port == 40000);
                check(address.GetAddress6()[0] == 0x0000);
                check(address.GetAddress6()[1] == 0x0000);
                check(address.GetAddress6()[2] == 0x0000);
                check(address.GetAddress6()[3] == 0x0000);
                check(address.GetAddress6()[4] == 0x0000);
                check(address.GetAddress6()[5] == 0x0000);
                check(address.GetAddress6()[6] == 0x0000);
                check(address.GetAddress6()[7] == 0x0000);
                check(!address.IsLoopback);
            }

            {
                var address = new Address("[::1]:40000");
                check(address.IsValid);
                check(address.Type == AddressType.ADDRESS_IPV6);
                check(address.Port == 40000);
                check(address.GetAddress6()[0] == 0x0000);
                check(address.GetAddress6()[1] == 0x0000);
                check(address.GetAddress6()[2] == 0x0000);
                check(address.GetAddress6()[3] == 0x0000);
                check(address.GetAddress6()[4] == 0x0000);
                check(address.GetAddress6()[5] == 0x0000);
                check(address.GetAddress6()[6] == 0x0000);
                check(address.GetAddress6()[7] == 0x0001);
                check(address.IsLoopback);
            }

            {
                ushort[] address6 = { 0xFE80, 0x0000, 0x0000, 0x0000, 0x0202, 0xB3FF, 0xFE1E, 0x8329 };

                var address = new Address(
                    address6[0], address6[1], address6[2], address6[2],
                    address6[4], address6[5], address6[6], address6[7]);

                check(address.IsValid);
                check(address.Type == AddressType.ADDRESS_IPV6);
                check(address.Port == 0);

                for (var i = 0; i < 8; ++i)
                    check(address6[i] == address.GetAddress6()[i]);

                check(address.ToString() == "fe80::202:b3ff:fe1e:8329");
            }

            {
                ushort[] address6 = { 0xFE80, 0x0000, 0x0000, 0x0000, 0x0202, 0xB3FF, 0xFE1E, 0x8329 };

                var address = new Address(address6);

                check(address.IsValid);
                check(address.Type == AddressType.ADDRESS_IPV6);
                check(address.Port == 0);

                for (var i = 0; i < 8; ++i)
                    check(address6[i] == address.GetAddress6()[i]);

                check(address.ToString() == "fe80::202:b3ff:fe1e:8329");
            }

            {
                ushort[] address6 = { 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0001 };

                var address = new Address(address6);

                check(address.IsValid);
                check(address.Type == AddressType.ADDRESS_IPV6);
                check(address.Port == 0);

                for (var i = 0; i < 8; ++i)
                    check(address6[i] == address.GetAddress6()[i]);

                check(address.ToString() == "::1");
            }

            {
                ushort[] address6 = { 0xFE80, 0x0000, 0x0000, 0x0000, 0x0202, 0xB3FF, 0xFE1E, 0x8329 };

                var address = new Address(
                    address6[0], address6[1], address6[2], address6[2],
                    address6[4], address6[5], address6[6], address6[7], 65535);

                check(address.IsValid);
                check(address.Type == AddressType.ADDRESS_IPV6);
                check(address.Port == 65535);

                for (var i = 0; i < 8; ++i)
                    check(address6[i] == address.GetAddress6()[i]);

                check(address.ToString() == "[fe80::202:b3ff:fe1e:8329]:65535");
            }

            {
                ushort[] address6 = { 0xFE80, 0x0000, 0x0000, 0x0000, 0x0202, 0xB3FF, 0xFE1E, 0x8329 };

                var address = new Address(address6, 65535);

                check(address.IsValid);
                check(address.Type == AddressType.ADDRESS_IPV6);
                check(address.Port == 65535);

                for (var i = 0; i < 8; ++i)
                    check(address6[i] == address.GetAddress6()[i]);

                check(address.ToString() == "[fe80::202:b3ff:fe1e:8329]:65535");
            }

            {
                ushort[] address6 = { 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0001 };

                var address = new Address(address6, 65535);

                check(address.IsValid);
                check(address.Type == AddressType.ADDRESS_IPV6);
                check(address.Port == 65535);

                for (var i = 0; i < 8; ++i)
                    check(address6[i] == address.GetAddress6()[i]);

                check(address.ToString() == "[::1]:65535");
            }

            {
                var address = new Address("fe80::202:b3ff:fe1e:8329");
                check(address.IsValid);
                check(address.Type == AddressType.ADDRESS_IPV6);
                check(address.Port == 0);
                check(address.ToString() == "fe80::202:b3ff:fe1e:8329");
            }

            {
                var address = new Address("::1");
                check(address.IsValid);
                check(address.Type == AddressType.ADDRESS_IPV6);
                check(address.Port == 0);
                check(address.ToString() == "::1");
            }

            {
                var address = new Address("[fe80::202:b3ff:fe1e:8329]:65535");
                check(address.IsValid);
                check(address.Type == AddressType.ADDRESS_IPV6);
                check(address.Port == 65535);
                check(address.ToString() == "[fe80::202:b3ff:fe1e:8329]:65535");
            }

            {
                var address = new Address("[::1]:65535");
                check(address.IsValid);
                check(address.Type == AddressType.ADDRESS_IPV6);
                check(address.Port == 65535);
                check(address.ToString() == "[::1]:65535");
            }
        }

        static void test_bit_array()
        {
            const int Size = 300;

            var bit_array = new BitArray(DefaultAllocator, Size);

            // verify initial conditions

            check(bit_array.GetSize() == Size);

            for (var i = 0; i < Size; ++i)
                check(bit_array.GetBit(i) == 0);

            // set every third bit and verify correct bits are set on read

            for (var i = 0; i < Size; ++i)
                if ((i % 3) == 0)
                    bit_array.SetBit(i);

            for (var i = 0; i < Size; ++i)
                if ((i % 3) == 0)
                    check(bit_array.GetBit(i) == 1);
                else
                    check(bit_array.GetBit(i) == 0);

            // now clear every third bit to zero and verify all bits are zero

            for (var i = 0; i < Size; ++i)
                if ((i % 3) == 0)
                    bit_array.ClearBit(i);

            for (var i = 0; i < Size; ++i)
                check(bit_array.GetBit(i) == 0);

            // now set some more bits

            for (var i = 0; i < Size; ++i)
                if ((i % 10) == 0)
                    bit_array.SetBit(i);

            for (var i = 0; i < Size; ++i)
                if ((i % 10) == 0)
                    check(bit_array.GetBit(i) == 1);
                else
                    check(bit_array.GetBit(i) == 0);

            // clear and verify all bits are zero

            bit_array.Clear();

            for (var i = 0; i < Size; ++i)
                check(bit_array.GetBit(i) == 0);
        }

        class TestSequenceData
        {
            public ushort sequence = 0xFFFF;
        }

        static void test_sequence_buffer()
        {
            const int Size = 256;

            var sequence_buffer = new SequenceBuffer<TestSequenceData>(DefaultAllocator, Size);

            for (ushort i = 0; i < Size; ++i)
                check(sequence_buffer.Find(i) == null);

            for (ushort i = 0; i <= Size * 4; ++i)
            {
                var entry = sequence_buffer.Insert(i);
                entry.sequence = i;
                check(sequence_buffer.GetSequence() == i + 1);
            }

            for (ushort i = 0; i <= Size; ++i)
            {
                var entry = sequence_buffer.Insert(i);
                check(entry == null);
            }

            ushort index = Size * 4;
            for (var i = 0; i < Size; ++i)
            {
                var entry = sequence_buffer.Find(index);
                check(entry != null);
                check(entry.sequence == (uint)index);
                index--;
            }

            sequence_buffer.Reset();

            check(sequence_buffer.GetSequence() == 0);

            for (ushort i = 0; i < Size; ++i)
                check(sequence_buffer.Find(i) == null);
        }

        static void test_allocator_tlsf()
        {
        }

        static void PumpConnectionUpdate(ConnectionConfig connectionConfig, ref double time, Connection sender, Connection receiver, ushort senderSequence, ushort receiverSequence, float deltaTime = 0.1f, int packetLossPercent = 0) //: packetLossPercent = 90
        {
            var packetData = new byte[connectionConfig.maxPacketSize];

            if (sender.GeneratePacket(null, senderSequence, packetData, connectionConfig.maxPacketSize, out var packetBytes))
                if (random_int(0, 100) >= packetLossPercent)
                {
                    receiver.ProcessPacket(null, senderSequence, packetData, packetBytes);
                    sender.ProcessAcks(new[] { senderSequence }, 1);
                }

            if (receiver.GeneratePacket(null, receiverSequence, packetData, connectionConfig.maxPacketSize, out packetBytes))
                if (random_int(0, 100) >= packetLossPercent)
                {
                    sender.ProcessPacket(null, receiverSequence, packetData, packetBytes);
                    receiver.ProcessAcks(new[] { receiverSequence }, 1);
                }

            time += deltaTime;

            sender.AdvanceTime(time);
            receiver.AdvanceTime(time);

            senderSequence++;
            receiverSequence++;
        }

        static void test_connection_reliable_ordered_messages()
        {
            var messageFactory = new TestMessageFactory(DefaultAllocator);

            var time = 100.0;

            var connectionConfig = new ConnectionConfig();

            var sender = new Connection(DefaultAllocator, messageFactory, connectionConfig, time);
            var receiver = new Connection(DefaultAllocator, messageFactory, connectionConfig, time);

            const int NumMessagesSent = 64;

            for (ushort i = 0; i < NumMessagesSent; ++i)
            {
                var message = (TestMessage)messageFactory.CreateMessage((int)TestMessageType.TEST_MESSAGE);
                check(message != null);
                message.sequence = i;
                sender.SendMessage(0, message);
            }

            const int SenderPort = 10000;
            const int ReceiverPort = 10001;

            var senderAddress = new Address("::1", SenderPort);
            var receiverAddress = new Address("::1", ReceiverPort);

            var numMessagesReceived = 0;

            const int NumIterations = 1000;

            ushort senderSequence = 0;
            ushort receiverSequence = 0;

            for (var i = 0; i < NumIterations; ++i)
            {
                PumpConnectionUpdate(connectionConfig, ref time, sender, receiver, senderSequence, receiverSequence);

                while (true)
                {
                    var message = receiver.ReceiveMessage(0);
                    if (message == null)
                        break;

                    check(message.Id == numMessagesReceived);
                    check(message.Type == (int)TestMessageType.TEST_MESSAGE);

                    var testMessage = (TestMessage)message;

                    check(testMessage.sequence == numMessagesReceived);

                    ++numMessagesReceived;

                    messageFactory.ReleaseMessage(ref message);
                }

                if (numMessagesReceived == NumMessagesSent)
                    break;
            }

            check(numMessagesReceived == NumMessagesSent);
        }

        static void test_connection_reliable_ordered_blocks()
        {
            var messageFactory = new TestMessageFactory(DefaultAllocator);

            var time = 100.0;

            var connectionConfig = new ConnectionConfig();

            var sender = new Connection(DefaultAllocator, messageFactory, connectionConfig, time);
            var receiver = new Connection(DefaultAllocator, messageFactory, connectionConfig, time);

            const int NumMessagesSent = 32;

            for (ushort i = 0; i < NumMessagesSent; ++i)
            {
                var message = (TestBlockMessage)messageFactory.CreateMessage((int)TestMessageType.TEST_BLOCK_MESSAGE);
                check(message != null);
                message.sequence = i;
                var blockSize = 1 + ((i * 901) % 3333);
                var blockData = new byte[blockSize];
                for (var j = 0; j < blockSize; ++j)
                    blockData[j] = (byte)(i + j);
                message.AttachBlock(messageFactory.Allocator, blockData, blockSize);
                sender.SendMessage(0, message);
            }

            const int SenderPort = 10000;
            const int ReceiverPort = 10001;

            var senderAddress = new Address("::1", SenderPort);
            var receiverAddress = new Address("::1", ReceiverPort);

            var numMessagesReceived = 0;

            ushort senderSequence = 0;
            ushort receiverSequence = 0;

            const int NumIterations = 10000;

            for (var i = 0; i < NumIterations; ++i)
            {
                PumpConnectionUpdate(connectionConfig, ref time, sender, receiver, senderSequence, receiverSequence);

                while (true)
                {
                    var message = receiver.ReceiveMessage(0);
                    if (message == null)
                        break;

                    check(message.Id == numMessagesReceived);

                    check(message.Type == (int)TestMessageType.TEST_BLOCK_MESSAGE);

                    var blockMessage = (TestBlockMessage)message;

                    check(blockMessage.sequence == (ushort)numMessagesReceived);

                    var blockSize = blockMessage.BlockSize;

                    check(blockSize == 1 + ((numMessagesReceived * 901) % 3333));

                    var blockData = blockMessage.BlockData;

                    check(blockData != null);

                    for (var j = 0; j < blockSize; ++j)
                        check(blockData[j] == (byte)(numMessagesReceived + j));

                    ++numMessagesReceived;

                    messageFactory.ReleaseMessage(ref message);
                }

                if (numMessagesReceived == NumMessagesSent)
                    break;
            }

            check(numMessagesReceived == NumMessagesSent);
        }

        static void test_connection_reliable_ordered_messages_and_blocks()
        {
            var messageFactory = new TestMessageFactory(DefaultAllocator);

            var time = 100.0;

            var connectionConfig = new ConnectionConfig();

            var sender = new Connection(DefaultAllocator, messageFactory, connectionConfig, time);

            var receiver = new Connection(DefaultAllocator, messageFactory, connectionConfig, time);

            const int NumMessagesSent = 32;

            for (ushort i = 0; i < NumMessagesSent; ++i)
                if ((BufferEx.Rand() % 2) != 0)
                {
                    var message = (TestMessage)messageFactory.CreateMessage((int)TestMessageType.TEST_MESSAGE);
                    check(message != null);
                    message.sequence = i;
                    sender.SendMessage(0, message);
                }
                else
                {
                    var message = (TestBlockMessage)messageFactory.CreateMessage((int)TestMessageType.TEST_BLOCK_MESSAGE);
                    check(message != null);
                    message.sequence = i;
                    var blockSize = 1 + ((i * 901) % 3333);
                    var blockData = new byte[blockSize];
                    for (var j = 0; j < blockSize; ++j)
                        blockData[j] = (byte)(i + j);
                    message.AttachBlock(messageFactory.Allocator, blockData, blockSize);
                    sender.SendMessage(0, message);
                }

            const int SenderPort = 10000;
            const int ReceiverPort = 10001;

            var senderAddress = new Address("::1", SenderPort);
            var receiverAddress = new Address("::1", ReceiverPort);

            var numMessagesReceived = 0;

            ushort senderSequence = 0;
            ushort receiverSequence = 0;

            const int NumIterations = 10000;

            for (var i = 0; i < NumIterations; ++i)
            {
                PumpConnectionUpdate(connectionConfig, ref time, sender, receiver, senderSequence, receiverSequence);

                while (true)
                {
                    var message = receiver.ReceiveMessage(0);
                    if (message == null)
                        break;

                    check(message.Id == numMessagesReceived);

                    switch (message.Type)
                    {
                        case (int)TestMessageType.TEST_MESSAGE:
                            {
                                var testMessage = (TestMessage)message;

                                check(testMessage.sequence == (ushort)numMessagesReceived);

                                ++numMessagesReceived;
                            }
                            break;

                        case (int)TestMessageType.TEST_BLOCK_MESSAGE:
                            {
                                var blockMessage = (TestBlockMessage)message;

                                check(blockMessage.sequence == (ushort)numMessagesReceived);

                                var blockSize = blockMessage.BlockSize;

                                check(blockSize == 1 + ((numMessagesReceived * 901) % 3333));

                                var blockData = blockMessage.BlockData;

                                check(blockData != null);

                                for (var j = 0; j < blockSize; ++j)
                                    check(blockData[j] == (byte)(numMessagesReceived + j));

                                ++numMessagesReceived;
                            }
                            break;
                    }

                    messageFactory.ReleaseMessage(ref message);
                }

                if (numMessagesReceived == NumMessagesSent)
                    break;
            }

            check(numMessagesReceived == NumMessagesSent);
        }

        static void test_connection_reliable_ordered_messages_and_blocks_multiple_channels()
        {
            const int NumChannels = 2;

            var time = 100.0;

            var messageFactory = new TestMessageFactory(DefaultAllocator);

            var connectionConfig = new ConnectionConfig();
            connectionConfig.numChannels = NumChannels;
            connectionConfig.channel[0].type = ChannelType.CHANNEL_TYPE_RELIABLE_ORDERED;
            connectionConfig.channel[0].maxMessagesPerPacket = 8;
            connectionConfig.channel[1].type = ChannelType.CHANNEL_TYPE_RELIABLE_ORDERED;
            connectionConfig.channel[1].maxMessagesPerPacket = 8;

            var sender = new Connection(DefaultAllocator, messageFactory, connectionConfig, time);

            var receiver = new Connection(DefaultAllocator, messageFactory, connectionConfig, time);

            const int NumMessagesSent = 32;

            for (var channelIndex = 0; channelIndex < NumChannels; ++channelIndex)
                for (ushort i = 0; i < NumMessagesSent; ++i)
                    if ((BufferEx.Rand() % 2) != 0)
                    {
                        var message = (TestMessage)messageFactory.CreateMessage((int)TestMessageType.TEST_MESSAGE);
                        check(message != null);
                        message.sequence = i;
                        sender.SendMessage(channelIndex, message);
                    }
                    else
                    {
                        var message = (TestBlockMessage)messageFactory.CreateMessage((int)TestMessageType.TEST_BLOCK_MESSAGE);
                        check(message != null);
                        message.sequence = i;
                        var blockSize = 1 + ((i * 901) % 3333);
                        var blockData = new byte[blockSize];
                        for (var j = 0; j < blockSize; ++j)
                            blockData[j] = (byte)(i + j);
                        message.AttachBlock(messageFactory.Allocator, blockData, blockSize);
                        sender.SendMessage(channelIndex, message);
                    }

            const int SenderPort = 10000;
            const int ReceiverPort = 10001;

            var senderAddress = new Address("::1", SenderPort);
            var receiverAddress = new Address("::1", ReceiverPort);

            const int NumIterations = 10000;

            var numMessagesReceived = new int[NumChannels];

            ushort senderSequence = 0;
            ushort receiverSequence = 0;

            for (var i = 0; i < NumIterations; ++i)
            {
                PumpConnectionUpdate(connectionConfig, ref time, sender, receiver, senderSequence, receiverSequence);

                for (var channelIndex = 0; channelIndex < NumChannels; ++channelIndex)
                {
                    while (true)
                    {
                        var message = receiver.ReceiveMessage(channelIndex);
                        if (message == null)
                            break;

                        check(message.Id == numMessagesReceived[channelIndex]);

                        switch (message.Type)
                        {
                            case (int)TestMessageType.TEST_MESSAGE:
                                {
                                    var testMessage = (TestMessage)message;

                                    check(testMessage.sequence == (ushort)numMessagesReceived[channelIndex]);

                                    ++numMessagesReceived[channelIndex];
                                }
                                break;

                            case (int)TestMessageType.TEST_BLOCK_MESSAGE:
                                {
                                    var blockMessage = (TestBlockMessage)message;

                                    check(blockMessage.sequence == (ushort)numMessagesReceived[channelIndex]);

                                    var blockSize = blockMessage.BlockSize;

                                    check(blockSize == 1 + ((numMessagesReceived[channelIndex] * 901) % 3333));

                                    var blockData = blockMessage.BlockData;

                                    check(blockData != null);

                                    for (var j = 0; j < blockSize; ++j)
                                        check(blockData[j] == (byte)(numMessagesReceived[channelIndex] + j));

                                    ++numMessagesReceived[channelIndex];
                                }
                                break;
                        }

                        messageFactory.ReleaseMessage(ref message);
                    }
                }

                var receivedAllMessages = true;

                for (var channelIndex = 0; channelIndex < NumChannels; ++channelIndex)
                    if (numMessagesReceived[channelIndex] != NumMessagesSent)
                    {
                        receivedAllMessages = false;
                        break;
                    }

                if (receivedAllMessages)
                    break;
            }

            for (var channelIndex = 0; channelIndex < NumChannels; ++channelIndex)
                check(numMessagesReceived[channelIndex] == NumMessagesSent);
        }

        static void test_connection_unreliable_unordered_messages()
        {
            var messageFactory = new TestMessageFactory(DefaultAllocator);

            var time = 100.0;

            var connectionConfig = new ConnectionConfig();
            connectionConfig.numChannels = 1;
            connectionConfig.channel[0].type = ChannelType.CHANNEL_TYPE_UNRELIABLE_UNORDERED;

            var sender = new Connection(DefaultAllocator, messageFactory, connectionConfig, time);
            var receiver = new Connection(DefaultAllocator, messageFactory, connectionConfig, time);

            const int SenderPort = 10000;
            const int ReceiverPort = 10001;

            var senderAddress = new Address("::1", SenderPort);
            var receiverAddress = new Address("::1", ReceiverPort);

            const int NumIterations = 256;

            const int NumMessagesSent = 16;

            for (ushort j = 0; j < NumMessagesSent; ++j)
            {
                var message = (TestMessage)messageFactory.CreateMessage((int)TestMessageType.TEST_MESSAGE);
                check(message != null);
                message.sequence = j;
                sender.SendMessage(0, message);
            }

            var numMessagesReceived = 0;

            ushort senderSequence = 0;
            ushort receiverSequence = 0;

            for (var i = 0; i < NumIterations; ++i)
            {
                PumpConnectionUpdate(connectionConfig, ref time, sender, receiver, senderSequence, receiverSequence, 0.1f, 0);

                while (true)
                {
                    var message = receiver.ReceiveMessage(0);
                    if (message == null)
                        break;

                    check(message.Type == (int)TestMessageType.TEST_MESSAGE);

                    var testMessage = (TestMessage)message;

                    check(testMessage.sequence == (ushort)numMessagesReceived);

                    ++numMessagesReceived;

                    messageFactory.ReleaseMessage(ref message);
                }

                if (numMessagesReceived == NumMessagesSent)
                    break;
            }

            check(numMessagesReceived == NumMessagesSent);
        }

        static void test_connection_unreliable_unordered_blocks()
        {
            var messageFactory = new TestMessageFactory(DefaultAllocator);

            var time = 100.0;

            var connectionConfig = new ConnectionConfig();
            connectionConfig.numChannels = 1;
            connectionConfig.channel[0].type = ChannelType.CHANNEL_TYPE_UNRELIABLE_UNORDERED;

            var sender = new Connection(DefaultAllocator, messageFactory, connectionConfig, time);

            var receiver = new Connection(DefaultAllocator, messageFactory, connectionConfig, time);

            const int SenderPort = 10000;
            const int ReceiverPort = 10001;

            var senderAddress = new Address("::1", SenderPort);
            var receiverAddress = new Address("::1", ReceiverPort);

            const int NumIterations = 256;

            const int NumMessagesSent = 8;

            for (ushort j = 0; j < NumMessagesSent; ++j)
            {
                var message = (TestBlockMessage)messageFactory.CreateMessage((int)TestMessageType.TEST_BLOCK_MESSAGE);
                check(message != null);
                message.sequence = j;
                var blockSize = 1 + (j * 7);
                var blockData = new byte[blockSize];
                for (var k = 0; k < blockSize; ++k)
                    blockData[k] = (byte)(j + k);
                message.AttachBlock(messageFactory.Allocator, blockData, blockSize);
                sender.SendMessage(0, message);
            }

            var numMessagesReceived = 0;

            ushort senderSequence = 0;
            ushort receiverSequence = 0;

            for (var i = 0; i < NumIterations; ++i)
            {
                PumpConnectionUpdate(connectionConfig, ref time, sender, receiver, senderSequence, receiverSequence, 0.1f, 0);

                while (true)
                {
                    var message = receiver.ReceiveMessage(0);
                    if (message == null)
                        break;

                    check(message.Type == (int)TestMessageType.TEST_BLOCK_MESSAGE);

                    var blockMessage = (TestBlockMessage)message;

                    check(blockMessage.sequence == (ushort)numMessagesReceived);

                    var blockSize = blockMessage.BlockSize;

                    check(blockSize == 1 + (numMessagesReceived * 7));

                    var blockData = blockMessage.BlockData;

                    check(blockData != null);

                    for (var j = 0; j < blockSize; ++j)
                        check(blockData[j] == (byte)(numMessagesReceived + j));

                    ++numMessagesReceived;

                    messageFactory.ReleaseMessage(ref message);
                }

                if (numMessagesReceived == NumMessagesSent)
                    break;
            }

            check(numMessagesReceived == NumMessagesSent);
        }

        static void PumpClientServerUpdate(ref double time, Client[] client, int numClients, Server[] server, int numServers, float deltaTime = 0.1f)
        {
            for (var i = 0; i < numClients; ++i)
                client[i].SendPackets();

            for (var i = 0; i < numServers; ++i)
                server[i].SendPackets();

            for (var i = 0; i < numClients; ++i)
                client[i].ReceivePackets();

            for (var i = 0; i < numServers; ++i)
                server[i].ReceivePackets();

            time += deltaTime;

            for (var i = 0; i < numClients; ++i)
                client[i].AdvanceTime(time);

            for (var i = 0; i < numServers; ++i)
                server[i].AdvanceTime(time);

            sleep(0.0f);
        }

        static void SendClientToServerMessages(Client client, int numMessagesToSend, int channelIndex = 0)
        {
            for (ushort i = 0; i < numMessagesToSend; ++i)
            {
                if (!client.CanSendMessage(channelIndex))
                    break;

                if ((BufferEx.Rand() % 10) != 0)
                {
                    var message = (TestMessage)client.CreateMessage((int)TestMessageType.TEST_MESSAGE);
                    check(message != null);
                    message.sequence = i;
                    client.SendMessage(channelIndex, message);
                }
                else
                {
                    var message = (TestBlockMessage)client.CreateMessage((int)TestMessageType.TEST_BLOCK_MESSAGE);
                    check(message != null);
                    message.sequence = i;
                    var blockSize = 1 + ((i * 901) % 1001);
                    var blockData = client.AllocateBlock(blockSize);
                    check(blockData != null);
                    for (var j = 0; j < blockSize; ++j)
                        blockData[j] = (byte)(i + j);
                    client.AttachBlockToMessage(message, blockData, blockSize);
                    client.SendMessage(channelIndex, message);
                }
            }
        }

        static void SendServerToClientMessages(Server server, int clientIndex, int numMessagesToSend, int channelIndex = 0)
        {
            for (ushort i = 0; i < numMessagesToSend; ++i)
            {
                if (!server.CanSendMessage(clientIndex, channelIndex))
                    break;

                if ((BufferEx.Rand() % 10) != 0)
                {
                    var message = (TestMessage)server.CreateMessage(clientIndex, (int)TestMessageType.TEST_MESSAGE);
                    check(message != null);
                    message.sequence = i;
                    server.SendMessage(clientIndex, channelIndex, message);
                }
                else
                {
                    var message = (TestBlockMessage)server.CreateMessage(clientIndex, (int)TestMessageType.TEST_BLOCK_MESSAGE);
                    check(message != null);
                    message.sequence = i;
                    var blockSize = 1 + ((i * 901) % 1001);
                    var blockData = server.AllocateBlock(clientIndex, blockSize);
                    check(blockData != null);
                    for (int j = 0; j < blockSize; ++j)
                        blockData[j] = (byte)(i + j);
                    server.AttachBlockToMessage(clientIndex, message, blockData, blockSize);
                    server.SendMessage(clientIndex, channelIndex, message);
                }
            }
        }

        static void ProcessServerToClientMessages(Client client, ref int numMessagesReceivedFromServer)
        {
            while (true)
            {
                var message = client.ReceiveMessage(0);

                if (message == null)
                    break;

                check(message.Id == numMessagesReceivedFromServer);

                switch (message.Type)
                {
                    case (int)TestMessageType.TEST_MESSAGE:
                        {
                            var testMessage = (TestMessage)message;
                            check(!message.IsBlockMessage);
                            check(testMessage.sequence == (ushort)numMessagesReceivedFromServer);
                            ++numMessagesReceivedFromServer;
                        }
                        break;

                    case (int)TestMessageType.TEST_BLOCK_MESSAGE:
                        {
                            check(message.IsBlockMessage);
                            var blockMessage = (TestBlockMessage)message;
                            check(blockMessage.sequence == (ushort)numMessagesReceivedFromServer);
                            var blockSize = blockMessage.BlockSize;
                            check(blockSize == 1 + ((numMessagesReceivedFromServer * 901) % 1001));
                            var blockData = blockMessage.BlockData;
                            check(blockData != null);
                            for (var j = 0; j < blockSize; ++j)
                                check(blockData[j] == (byte)(numMessagesReceivedFromServer + j));
                            ++numMessagesReceivedFromServer;
                        }
                        break;
                }

                client.ReleaseMessage(ref message);
            }
        }

        static void ProcessClientToServerMessages(Server server, int clientIndex, ref int numMessagesReceivedFromClient)
        {
            while (true)
            {
                var message = server.ReceiveMessage(clientIndex, 0);

                if (message == null)
                    break;

                check(message.Id == numMessagesReceivedFromClient);

                switch (message.Type)
                {
                    case (int)TestMessageType.TEST_MESSAGE:
                        {
                            check(!message.IsBlockMessage);
                            var testMessage = (TestMessage)message;
                            check(testMessage.sequence == (ushort)numMessagesReceivedFromClient);
                            ++numMessagesReceivedFromClient;
                        }
                        break;

                    case (int)TestMessageType.TEST_BLOCK_MESSAGE:
                        {
                            check(message.IsBlockMessage);
                            var blockMessage = (TestBlockMessage)message;
                            check(blockMessage.sequence == (ushort)numMessagesReceivedFromClient);
                            var blockSize = blockMessage.BlockSize;
                            check(blockSize == 1 + ((numMessagesReceivedFromClient * 901) % 1001));
                            var blockData = blockMessage.BlockData;
                            check(blockData != null);
                            for (var j = 0; j < blockSize; ++j)
                                check(blockData[j] == (byte)(numMessagesReceivedFromClient + j));
                            ++numMessagesReceivedFromClient;
                        }
                        break;
                }

                server.ReleaseMessage(clientIndex, ref message);
            }
        }

        static void test_client_server_messages()
        {
            const ulong clientId = 1UL;

            var clientAddress = new Address("0.0.0.0", shared.ClientPort);
            var serverAddress = new Address("127.0.0.1", shared.ServerPort);

            var time = 100.0;

            var config = new ClientServerConfig();
            config.channel[0].messageSendQueueSize = 32;
            config.channel[0].maxMessagesPerPacket = 8;
            config.channel[0].maxBlockSize = 1024;
            config.channel[0].blockFragmentSize = 200;

            var client = new Client(DefaultAllocator, clientAddress, config, shared.adapter, time);

            var privateKey = new byte[KeyBytes];

            var server = new Server(DefaultAllocator, privateKey, serverAddress, config, shared.adapter, time);

            server.Start(MaxClients);

            client.SetLatency(250);
            client.SetJitter(100);
            client.SetPacketLoss(25);
            client.SetDuplicates(25);

            server.SetLatency(250);
            server.SetJitter(100);
            server.SetPacketLoss(25);
            server.SetDuplicates(25);

            for (var iteration = 0; iteration < 2; ++iteration)
            {
                client.InsecureConnect(privateKey, clientId, serverAddress);

                const int NumIterations = 10000;

                for (var i = 0; i < NumIterations; ++i)
                {
                    Client[] clients = { client };
                    Server[] servers = { server };

                    PumpClientServerUpdate(ref time, clients, 1, servers, 1);

                    if (client.ConnectionFailed)
                        break;

                    if (!client.IsConnecting && client.IsConnected && server.NumConnectedClients == 1)
                        break;
                }

                check(!client.IsConnecting);
                check(client.IsConnected);
                check(server.NumConnectedClients == 1);
                check(client.ClientIndex == 0);
                check(server.IsClientConnected(0));

                var NumMessagesSent = config.channel[0].messageSendQueueSize;

                SendClientToServerMessages(client, NumMessagesSent);

                SendServerToClientMessages(server, client.ClientIndex, NumMessagesSent);

                var numMessagesReceivedFromClient = 0;
                var numMessagesReceivedFromServer = 0;

                for (var i = 0; i < NumIterations; ++i)
                {
                    if (!client.IsConnected)
                        break;

                    Client[] clients = { client };
                    Server[] servers = { server };

                    PumpClientServerUpdate(ref time, clients, 1, servers, 1);

                    ProcessServerToClientMessages(client, ref numMessagesReceivedFromServer);

                    ProcessClientToServerMessages(server, client.ClientIndex, ref numMessagesReceivedFromClient);

                    if (numMessagesReceivedFromClient == NumMessagesSent && numMessagesReceivedFromServer == NumMessagesSent)
                        break;
                }

                check(client.IsConnected);
                check(server.IsClientConnected(client.ClientIndex));
                check(numMessagesReceivedFromClient == NumMessagesSent);
                check(numMessagesReceivedFromServer == NumMessagesSent);

                client.Disconnect();

                for (var i = 0; i < NumIterations; ++i)
                {
                    Client[] clients = { client };
                    Server[] servers = { server };

                    PumpClientServerUpdate(ref time, clients, 1, servers, 1);

                    if (!client.IsConnected && server.NumConnectedClients == 0)
                        break;
                }

                check(!client.IsConnected && server.NumConnectedClients == 0);
            }

            server.Stop();
        }

        static void CreateClients(int numClients, Client[] clients, Address address, ClientServerConfig config, Adapter _adapter, double time)
        {
            for (var i = 0; i < numClients; ++i)
            {
                clients[i] = new Client(DefaultAllocator, address, config, _adapter, time);
                clients[i].SetLatency(250);
                clients[i].SetJitter(100);
                clients[i].SetPacketLoss(25);
                clients[i].SetDuplicates(25);
            }
        }

        static void ConnectClients(int numClients, Client[] clients, byte[] privateKey, Address serverAddress)
        {
            for (var i = 0; i < numClients; ++i)
                clients[i].InsecureConnect(privateKey, (ulong)(i + 1), serverAddress);
        }

        static void DestroyClients(int numClients, Client[] clients)
        {
            for (var i = 0; i < numClients; ++i)
            {
                clients[i].Disconnect();

                clients[i] = null;
            }
        }

        static bool AllClientsConnected(int numClients, Server server, Client[] clients)
        {
            if (server.NumConnectedClients != numClients)
                return false;

            for (var i = 0; i < numClients; ++i)
                if (!clients[i].IsConnected)
                    return false;

            return true;
        }

        static bool AnyClientDisconnected(int numClients, Client[] clients)
        {
            for (var i = 0; i < numClients; ++i)
                if (clients[i].IsDisconnected)
                    return true;

            return false;
        }

        static void test_client_server_start_stop_restart()
        {
            var clientAddress = new Address("0.0.0.0", 0);
            var serverAddress = new Address("127.0.0.1", shared.ServerPort);

            var time = 100.0;

            var config = new ClientServerConfig();
            config.channel[0].messageSendQueueSize = 32;
            config.channel[0].maxMessagesPerPacket = 8;
            config.channel[0].maxBlockSize = 1024;
            config.channel[0].blockFragmentSize = 200;

            var privateKey = new byte[KeyBytes];

            var server = new Server(DefaultAllocator, privateKey, serverAddress, config, shared.adapter, time);

            server.Start(MaxClients);

            server.SetLatency(250);
            server.SetJitter(100);
            server.SetPacketLoss(25);
            server.SetDuplicates(25);

            int[] numClients = { 3, 5, 1 };

            var NumIterations = numClients.Length;

            for (var iteration = 0; iteration < NumIterations; ++iteration)
            {
                server.Start(numClients[iteration]);

                var clients = new Client[MaxClients];

                CreateClients(numClients[iteration], clients, clientAddress, config, shared.adapter, time);

                ConnectClients(numClients[iteration], clients, privateKey, serverAddress);

                while (true)
                {
                    Server[] servers = { server };

                    PumpClientServerUpdate(ref time, clients, numClients[iteration], servers, 1);

                    if (AnyClientDisconnected(numClients[iteration], clients))
                        break;

                    if (AllClientsConnected(numClients[iteration], server, clients))
                        break;
                }

                check(AllClientsConnected(numClients[iteration], server, clients));

                var NumMessagesSent = config.channel[0].messageSendQueueSize;

                for (var clientIndex = 0; clientIndex < numClients[iteration]; ++clientIndex)
                {
                    SendClientToServerMessages(clients[clientIndex], NumMessagesSent);
                    SendServerToClientMessages(server, clientIndex, NumMessagesSent);
                }

                var numMessagesReceivedFromClient = new int[MaxClients];
                var numMessagesReceivedFromServer = new int[MaxClients];

                const int NumInternalIterations = 10000;

                for (var i = 0; i < NumInternalIterations; ++i)
                {
                    Server[] servers = { server };

                    PumpClientServerUpdate(ref time, clients, numClients[iteration], servers, 1);

                    var allMessagesReceived = true;

                    for (var j = 0; j < numClients[iteration]; ++j)
                    {
                        ProcessServerToClientMessages(clients[j], ref numMessagesReceivedFromServer[j]);

                        if (numMessagesReceivedFromServer[j] != NumMessagesSent)
                            allMessagesReceived = false;

                        var clientIndex = clients[j].ClientIndex;

                        ProcessClientToServerMessages(server, clientIndex, ref numMessagesReceivedFromClient[clientIndex]);

                        if (numMessagesReceivedFromClient[clientIndex] != NumMessagesSent)
                            allMessagesReceived = false;
                    }

                    if (allMessagesReceived)
                        break;
                }

                for (var clientIndex = 0; clientIndex < numClients[iteration]; ++clientIndex)
                {
                    check(numMessagesReceivedFromClient[clientIndex] == NumMessagesSent);
                    check(numMessagesReceivedFromServer[clientIndex] == NumMessagesSent);
                }

                DestroyClients(numClients[iteration], clients);

                server.Stop();
            }
        }

        static void test_client_server_message_failed_to_serialize_reliable_ordered()
        {
            const ulong clientId = 1UL;

            var clientAddress = new Address("0.0.0.0", shared.ClientPort);
            var serverAddress = new Address("127.0.0.1", shared.ServerPort);

            var time = 100.0;

            var config = new ClientServerConfig();
            config.maxPacketSize = 1100;
            config.numChannels = 1;
            config.channel[0].type = ChannelType.CHANNEL_TYPE_RELIABLE_ORDERED;
            config.channel[0].maxBlockSize = 1024;
            config.channel[0].blockFragmentSize = 200;

            var privateKey = new byte[KeyBytes];

            var server = new Server(DefaultAllocator, privateKey, serverAddress, config, shared.adapter, time);

            server.Start(MaxClients);

            var client = new Client(DefaultAllocator, clientAddress, config, shared.adapter, time);

            client.InsecureConnect(privateKey, clientId, serverAddress);

            const int NumIterations = 10000;

            for (var i = 0; i < NumIterations; ++i)
            {
                Client[] clients = { client };
                Server[] servers = { server };

                PumpClientServerUpdate(ref time, clients, 1, servers, 1);

                if (client.ConnectionFailed)
                    break;

                if (!client.IsConnecting && client.IsConnected && server.NumConnectedClients == 1)
                    break;
            }

            check(!client.IsConnecting);
            check(client.IsConnected);
            check(server.NumConnectedClients == 1);
            check(client.ClientIndex == 0);
            check(server.IsClientConnected(0));

            // send a message from client to server that fails to serialize on read, this should disconnect the client from the server

            var message = client.CreateMessage((int)TestMessageType.TEST_SERIALIZE_FAIL_ON_READ_MESSAGE);
            check(message != null);
            client.SendMessage(0, message);

            for (var i = 0; i < 256; ++i)
            {
                Client[] clients = { client };
                Server[] servers = { server };

                PumpClientServerUpdate(ref time, clients, 1, servers, 1);

                if (!client.IsConnected && server.NumConnectedClients == 0)
                    break;
            }

            check(!client.IsConnected && server.NumConnectedClients == 0);

            client.Disconnect();

            server.Stop();
        }

        static void test_client_server_message_failed_to_serialize_unreliable_unordered()
        {
            const ulong clientId = 1UL;

            var clientAddress = new Address("0.0.0.0", shared.ClientPort);
            var serverAddress = new Address("127.0.0.1", shared.ServerPort);

            var time = 100.0;

            var config = new ClientServerConfig();
            config.maxPacketSize = 1100;
            config.numChannels = 1;
            config.channel[0].type = ChannelType.CHANNEL_TYPE_UNRELIABLE_UNORDERED;
            config.channel[0].maxBlockSize = 1024;
            config.channel[0].blockFragmentSize = 200;

            var privateKey = new byte[KeyBytes];

            var server = new Server(DefaultAllocator, privateKey, serverAddress, config, shared.adapter, time);

            server.Start(MaxClients);

            var client = new Client(DefaultAllocator, clientAddress, config, shared.adapter, time);

            client.InsecureConnect(privateKey, clientId, serverAddress);

            const int NumIterations = 10000;

            for (var i = 0; i < NumIterations; ++i)
            {
                Client[] clients = { client };
                Server[] servers = { server };

                PumpClientServerUpdate(ref time, clients, 1, servers, 1);

                if (client.ConnectionFailed)
                    break;

                if (!client.IsConnecting && client.IsConnected && server.NumConnectedClients == 1)
                    break;
            }

            check(!client.IsConnecting);
            check(client.IsConnected);
            check(server.NumConnectedClients == 1);
            check(client.ClientIndex == 0);
            check(server.IsClientConnected(0));

            // send a message from client to server that fails to serialize on read, this should disconnect the client from the server

            for (var i = 0; i < 256; ++i)
            {
                Client[] clients = { client };
                Server[] servers = { server };

                var message = client.CreateMessage((int)TestMessageType.TEST_SERIALIZE_FAIL_ON_READ_MESSAGE);
                check(message != null);
                client.SendMessage(0, message);

                PumpClientServerUpdate(ref time, clients, 1, servers, 1);

                if (!client.IsConnected && server.NumConnectedClients == 0)
                    break;
            }

            check(!client.IsConnected);
            check(server.NumConnectedClients == 0);

            client.Disconnect();

            server.Stop();
        }

        static void test_client_server_message_exhaust_stream_allocator()
        {
            return;
            const ulong clientId = 1UL;

            var clientAddress = new Address("0.0.0.0", shared.ClientPort);
            var serverAddress = new Address("127.0.0.1", shared.ServerPort);

            var time = 100.0;

            var config = new ClientServerConfig();
            config.maxPacketSize = 1100;
            config.numChannels = 1;
            config.channel[0].type = ChannelType.CHANNEL_TYPE_RELIABLE_ORDERED;
            config.channel[0].maxBlockSize = 1024;
            config.channel[0].blockFragmentSize = 200;

            var privateKey = new byte[KeyBytes];

            var server = new Server(DefaultAllocator, privateKey, serverAddress, config, shared.adapter, time);

            server.Start(MaxClients);

            var client = new Client(DefaultAllocator, clientAddress, config, shared.adapter, time);

            client.InsecureConnect(privateKey, clientId, serverAddress);

            const int NumIterations = 10000;

            for (var i = 0; i < NumIterations; ++i)
            {
                Client[] clients = { client };
                Server[] servers = { server };

                PumpClientServerUpdate(ref time, clients, 1, servers, 1);

                if (client.ConnectionFailed)
                    break;

                if (!client.IsConnecting && client.IsConnected && server.NumConnectedClients == 1)
                    break;
            }

            check(!client.IsConnecting);
            check(client.IsConnected);
            check(server.NumConnectedClients == 1);
            check(client.ClientIndex == 0);
            check(server.IsClientConnected(0));

            // send a message from client to server that exhausts the stream allocator on read, this should disconnect the client from the server

            var message = client.CreateMessage((int)TestMessageType.TEST_EXHAUST_STREAM_ALLOCATOR_ON_READ_MESSAGE);
            check(message != null);
            client.SendMessage(0, message);

            for (var i = 0; i < 256; ++i)
            {
                Client[] clients = { client };
                Server[] servers = { server };

                PumpClientServerUpdate(ref time, clients, 1, servers, 1);

                if (!client.IsConnected && server.NumConnectedClients == 0)
                    break;
            }

            check(!client.IsConnected && server.NumConnectedClients == 0);

            client.Disconnect();

            server.Stop();
        }

        static void test_client_server_message_receive_queue_overflow()
        {
            const ulong clientId = 1UL;

            var clientAddress = new Address("0.0.0.0", shared.ClientPort);
            var serverAddress = new Address("127.0.0.1", shared.ServerPort);

            var time = 100.0;

            var config = new ClientServerConfig();
            config.maxPacketSize = 1100;
            config.numChannels = 1;
            config.channel[0].type = ChannelType.CHANNEL_TYPE_RELIABLE_ORDERED;
            config.channel[0].maxBlockSize = 1024;
            config.channel[0].blockFragmentSize = 200;
            config.channel[0].messageSendQueueSize = 1024;
            config.channel[0].messageReceiveQueueSize = 256;

            var privateKey = new byte[KeyBytes];

            var server = new Server(DefaultAllocator, privateKey, serverAddress, config, shared.adapter, time);

            server.Start(MaxClients);

            var client = new Client(DefaultAllocator, clientAddress, config, shared.adapter, time);

            client.InsecureConnect(privateKey, clientId, serverAddress);

            while (true)
            {
                Client[] clients = { client };
                Server[] servers = { server };

                PumpClientServerUpdate(ref time, clients, 1, servers, 1);

                if (client.ConnectionFailed)
                    break;

                if (!client.IsConnecting && client.IsConnected && server.NumConnectedClients == 1)
                    break;
            }

            check(!client.IsConnecting);
            check(client.IsConnected);
            check(server.NumConnectedClients == 1);
            check(client.ClientIndex == 0);
            check(server.IsClientConnected(0));

            // send a lot of messages, but don't dequeue them, this tests that the receive queue is able to handle overflow
            // eg. the receiver should detect an error and disconnect the client, because the message is out of bounds.

            var NumMessagesSent = config.channel[0].messageSendQueueSize;

            SendClientToServerMessages(client, NumMessagesSent);

            for (var i = 0; i < NumMessagesSent * 4; ++i)
            {
                Client[] clients = { client };
                Server[] servers = { server };

                PumpClientServerUpdate(ref time, clients, 1, servers, 1);
            }

            check(!client.IsConnected);
            check(server.NumConnectedClients == 0);

            client.Disconnect();

            server.Stop();
        }

        // Github Issue #78
        static void test_reliable_fragment_overflow_bug()
        {
            var time = 100.0;

            var config = new ClientServerConfig();
            config.numChannels = 2;
            config.channel[0].type = ChannelType.CHANNEL_TYPE_UNRELIABLE_UNORDERED;
            // Large enough that after this channel fills this budget, the amount of space left in the packet isn't large enough for a reliable block fragment.
            config.channel[0].packetBudget = 8000;
            config.channel[1].type = ChannelType.CHANNEL_TYPE_RELIABLE_ORDERED;
            config.channel[1].packetBudget = -1;

            var privateKey = new byte[KeyBytes];
            var server = new Server(DefaultAllocator, privateKey, new Address("127.0.0.1", shared.ServerPort), config, shared.adapter, time);

            server.Start(MaxClients);
            check(server.IsRunning);

            var clientId = 0UL;
            random_bytes(ref clientId, 8);

            var client = new Client(DefaultAllocator, new Address("0.0.0.0"), config, shared.adapter, time);

            var serverAddress = new Address("127.0.0.1", shared.ServerPort);

            client.InsecureConnect(privateKey, clientId, serverAddress);

            Client[] clients = { client };
            Server[] servers = { server };

            while (true)
            {
                PumpClientServerUpdate(ref time, clients, 1, servers, 1);

                if (client.ConnectionFailed)
                    break;

                if (!client.IsConnecting && client.IsConnected && server.NumConnectedClients == 1)
                    break;
            }

            check(!client.IsConnecting);
            check(client.IsConnected);
            check(server.NumConnectedClients == 1);
            check(client.ClientIndex == 0);
            check(server.IsClientConnected(0));

            PumpClientServerUpdate(ref time, clients, 1, servers, 1);
            check(!client.IsDisconnected);

            // The max packet size is 8192. Fill up the packet so there's still space left, but not enough for a full reliable block fragment.
            var testBlockMessage = (TestBlockMessage)client.CreateMessage((int)TestMessageType.TEST_BLOCK_MESSAGE);
            var blockData = client.AllocateBlock(7169);
            client.AttachBlockToMessage(testBlockMessage, blockData, 7169);
            client.SendMessage(0, testBlockMessage); // Unreliable channel

            // Send a block message on the reliable channel. The message will be split into 1024 byte fragments. The first fragment will attempt to write beyond the end of the packet buffer and crash.
            testBlockMessage = (TestBlockMessage)client.CreateMessage((int)TestMessageType.TEST_BLOCK_MESSAGE);
            blockData = client.AllocateBlock(1024);
            client.AttachBlockToMessage(testBlockMessage, blockData, 1024);
            client.SendMessage(1, testBlockMessage); // Reliable channel

            // Pump once to send the first message on the unreliable channel (If the bug is present, it will assert here as the second message will overflow)
            PumpClientServerUpdate(ref time, clients, 1, servers, 1);

            // Pump again to send the second message on the reliable channel and receive the first message on the server side.
            PumpClientServerUpdate(ref time, clients, 1, servers, 1);

            // Pump one more time to receive the second message on the server side.
            PumpClientServerUpdate(ref time, clients, 1, servers, 1);
            check(!client.IsDisconnected);

            // Verify that we received a TestBlockMessage on both channels.
            // Unreliable channel
            var message = server.ReceiveMessage(0, 0);
            check(message != null);
            check(message.Type == (int)TestMessageType.TEST_BLOCK_MESSAGE);
            server.ReleaseMessage(0, ref message);

            // Reliable channel
            message = server.ReceiveMessage(0, 1);
            check(message != null);
            check(message.Type == (int)TestMessageType.TEST_BLOCK_MESSAGE);
            server.ReleaseMessage(0, ref message);

            client.Disconnect();
            server.Stop();
        }

        // Github Issue #77
        static void test_single_message_type_reliable()
        {
            var messageFactory = new SingleTestMessageFactory(DefaultAllocator);

            var time = 100.0;

            var connectionConfig = new ConnectionConfig();
            var sender = new Connection(DefaultAllocator, messageFactory, connectionConfig, time);
            var receiver = new Connection(DefaultAllocator, messageFactory, connectionConfig, time);

            const int NumMessagesSent = 64;

            for (ushort i = 0; i < NumMessagesSent; ++i)
            {
                var message = (TestMessage)messageFactory.CreateMessage((int)SingleTestMessageType.SINGLE_TEST_MESSAGE);
                check(message != null);
                message.sequence = i;
                sender.SendMessage(0, message);
            }

            const int SenderPort = 10000;
            const int ReceiverPort = 10001;

            var senderAddress = new Address("::1", SenderPort);
            var receiverAddress = new Address("::1", ReceiverPort);

            var numMessagesReceived = 0;

            const int NumIterations = 1000;

            ushort senderSequence = 0;
            ushort receiverSequence = 0;

            for (var i = 0; i < NumIterations; ++i)
            {
                PumpConnectionUpdate(connectionConfig, ref time, sender, receiver, senderSequence, receiverSequence);

                while (true)
                {
                    var message = receiver.ReceiveMessage(0);
                    if (message == null)
                        break;

                    check(message.Id == numMessagesReceived);
                    check(message.Type == (int)SingleTestMessageType.SINGLE_TEST_MESSAGE);

                    var testMessage = (TestMessage)message;

                    check(testMessage.sequence == numMessagesReceived);

                    ++numMessagesReceived;

                    messageFactory.ReleaseMessage(ref message);
                }

                if (numMessagesReceived == NumMessagesSent)
                    break;
            }

            check(numMessagesReceived == NumMessagesSent);
        }

        static void test_single_message_type_reliable_blocks()
        {
            var messageFactory = new SingleBlockTestMessageFactory(DefaultAllocator);

            var time = 100.0;

            var connectionConfig = new ConnectionConfig();

            var sender = new Connection(DefaultAllocator, messageFactory, connectionConfig, time);
            var receiver = new Connection(DefaultAllocator, messageFactory, connectionConfig, time);

            const int NumMessagesSent = 32;

            for (ushort i = 0; i < NumMessagesSent; ++i)
            {
                var message = (TestBlockMessage)messageFactory.CreateMessage((int)SingleBlockTestMessageType.SINGLE_BLOCK_TEST_MESSAGE);
                check(message != null);
                message.sequence = i;
                var blockSize = 1 + ((i * 901) % 3333);
                var blockData = new byte[blockSize];
                for (var j = 0; j < blockSize; ++j)
                    blockData[j] = (byte)(i + j);
                message.AttachBlock(messageFactory.Allocator, blockData, blockSize);
                sender.SendMessage(0, message);
            }

            const int SenderPort = 10000;
            const int ReceiverPort = 10001;

            var senderAddress = new Address("::1", SenderPort);
            var receiverAddress = new Address("::1", ReceiverPort);

            var numMessagesReceived = 0;

            ushort senderSequence = 0;
            ushort receiverSequence = 0;

            const int NumIterations = 10000;

            for (var i = 0; i < NumIterations; ++i)
            {
                PumpConnectionUpdate(connectionConfig, ref time, sender, receiver, senderSequence, receiverSequence);

                while (true)
                {
                    var message = receiver.ReceiveMessage(0);
                    if (message == null)
                        break;

                    check(message.Id == numMessagesReceived);

                    check(message.Type == (int)SingleBlockTestMessageType.SINGLE_BLOCK_TEST_MESSAGE);

                    var blockMessage = (TestBlockMessage)message;

                    check(blockMessage.sequence == (ushort)numMessagesReceived);

                    var blockSize = blockMessage.BlockSize;

                    check(blockSize == 1 + ((numMessagesReceived * 901) % 3333));

                    var blockData = blockMessage.BlockData;

                    check(blockData != null);

                    for (var j = 0; j < blockSize; ++j)
                        check(blockData[j] == (byte)(numMessagesReceived + j));

                    ++numMessagesReceived;

                    messageFactory.ReleaseMessage(ref message);
                }

                if (numMessagesReceived == NumMessagesSent)
                    break;
            }

            check(numMessagesReceived == NumMessagesSent);
        }

        static void test_single_message_type_unreliable()
        {
            var messageFactory = new SingleTestMessageFactory(DefaultAllocator);

            var time = 100.0;

            var connectionConfig = new ConnectionConfig();
            connectionConfig.numChannels = 1;
            connectionConfig.channel[0].type = ChannelType.CHANNEL_TYPE_UNRELIABLE_UNORDERED;

            var sender = new Connection(DefaultAllocator, messageFactory, connectionConfig, time);
            var receiver = new Connection(DefaultAllocator, messageFactory, connectionConfig, time);

            const int SenderPort = 10000;
            const int ReceiverPort = 10001;

            var senderAddress = new Address("::1", SenderPort);
            var receiverAddress = new Address("::1", ReceiverPort);

            const int NumIterations = 256;

            const int NumMessagesSent = 16;

            for (ushort j = 0; j < NumMessagesSent; ++j)
            {
                var message = (TestMessage)messageFactory.CreateMessage((int)SingleTestMessageType.SINGLE_TEST_MESSAGE);
                check(message != null);
                message.sequence = j;
                sender.SendMessage(0, message);
            }

            var numMessagesReceived = 0;

            ushort senderSequence = 0;
            ushort receiverSequence = 0;

            for (var i = 0; i < NumIterations; ++i)
            {
                PumpConnectionUpdate(connectionConfig, ref time, sender, receiver, senderSequence, receiverSequence, 0.1f, 0);

                while (true)
                {
                    var message = receiver.ReceiveMessage(0);
                    if (message == null)
                        break;

                    check(message.Type == (int)SingleTestMessageType.SINGLE_TEST_MESSAGE);

                    var testMessage = (TestMessage)message;

                    check(testMessage.sequence == (ushort)numMessagesReceived);

                    ++numMessagesReceived;

                    messageFactory.ReleaseMessage(ref message);
                }

                if (numMessagesReceived == NumMessagesSent)
                    break;
            }

            check(numMessagesReceived == NumMessagesSent);
        }

        static void RUN_TEST(string name, Action test_function)
        {
            Console.Write($"{name}\n");
            if (!InitializeYojimbo())
            {
                Console.Write("error: failed to initialize yojimbo\n");
                Environment.Exit(1);
            }
            test_function();
            ShutdownYojimbo();
        }

#if SOAK
        static volatile bool quit = false;

        static void interrupt_handler(object sender, ConsoleCancelEventArgs e) { quit = true; e.Cancel = true; }
#endif

        static int Main(string[] args)
        {
            Console.Write("\n");

            //log_level(LOG_LEVEL_DEBUG);

#if SOAK
            Console.CancelKeyPress += interrupt_handler;

            var iter = 0;
            while (true)
#endif
            {
                {
                    Console.Write("[netcode.io]\n\n");

                    check(InitializeYojimbo());

                    netcode.test();

                    ShutdownYojimbo();
                }

                {
                    Console.Write("\n[reliable.io]\n\n");

                    check(InitializeYojimbo());

                    reliable.test();

                    ShutdownYojimbo();
                }

                Console.Write("\n[yojimbo]\n\n");

                RUN_TEST("test_endian", test_endian);
                RUN_TEST("test_queue", test_queue);
#if YOJIMBO_WITH_MBEDTLS
		        RUN_TEST("test_base64", test_base64);
#endif
                RUN_TEST("test_bitpacker", test_bitpacker);
                RUN_TEST("test_bits_required", test_bits_required);
                RUN_TEST("test_stream", test_stream);
                RUN_TEST("test_address", test_address);
                RUN_TEST("test_bit_array", test_bit_array);
                RUN_TEST("test_sequence_buffer", test_sequence_buffer);
                RUN_TEST("test_allocator_tlsf", test_allocator_tlsf);

                RUN_TEST("test_connection_reliable_ordered_messages", test_connection_reliable_ordered_messages);
                RUN_TEST("test_connection_reliable_ordered_blocks", test_connection_reliable_ordered_blocks);
                RUN_TEST("test_connection_reliable_ordered_messages_and_blocks", test_connection_reliable_ordered_messages_and_blocks);
                RUN_TEST("test_connection_reliable_ordered_messages_and_blocks_multiple_channels", test_connection_reliable_ordered_messages_and_blocks_multiple_channels);
                RUN_TEST("test_connection_unreliable_unordered_messages", test_connection_unreliable_unordered_messages);
                RUN_TEST("test_connection_unreliable_unordered_blocks", test_connection_unreliable_unordered_blocks);

                RUN_TEST("test_client_server_messages", test_client_server_messages);
                RUN_TEST("test_client_server_start_stop_restart", test_client_server_start_stop_restart);
                RUN_TEST("test_client_server_message_failed_to_serialize_reliable_ordered", test_client_server_message_failed_to_serialize_reliable_ordered);
                RUN_TEST("test_client_server_message_failed_to_serialize_unreliable_unordered", test_client_server_message_failed_to_serialize_unreliable_unordered);
                RUN_TEST("test_client_server_message_exhaust_stream_allocator", test_client_server_message_exhaust_stream_allocator);
                RUN_TEST("test_client_server_message_receive_queue_overflow", test_client_server_message_receive_queue_overflow);
                RUN_TEST("test_reliable_fragment_overflow_bug", test_reliable_fragment_overflow_bug);
                RUN_TEST("test_single_message_type_reliable", test_single_message_type_reliable);
                RUN_TEST("test_single_message_type_reliable_blocks", test_single_message_type_reliable_blocks);
                RUN_TEST("test_single_message_type_unreliable", test_single_message_type_unreliable);

#if SOAK
                if (quit)
                    break;
                iter++;
                for (var j = 0; j < iter % 10; ++j)
                    Console.Write(".");
                Console.Write("\n");
#endif
            }

#if SOAK
            if (quit)
                Console.Write("\n");
#else
            Console.Write("\n*** ALL TESTS PASS ***\n\n");
#endif

            return 0;
        }
    }
}