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
using System.Runtime.CompilerServices;
using static networkprotocol.yojimbo;

public static class test
{
    static void CheckHandler(string condition, string function, string file, int line)
    {
        Console.Write($"check failed: ( {condition} ), function {function}, file {file}, line {line}\n");
        if (Debugger.IsAttached)
            Debugger.Break();
        Environment.Exit(1);
    }

    [DebuggerStepThrough]
    public static void check(bool condition, [CallerArgumentExpression(nameof(condition))] string conditionText = null, [CallerMemberName] string function = null, [CallerFilePath] string file = null, [CallerLineNumber] int line = 0)
    {
        if (!condition)
            CheckHandler(conditionText, function, file, line);
    }

    // Allocator used by the allocation-failure tests. Delegates to the GC, tracks the number of
    // outstanding blocks so leaks are observable, and can be "armed" to start returning null after a
    // given number of successful allocations (to force a failure at a specific point).
    class ArmableAllocator : Allocator
    {
        public void Arm(int allocsUntilFail) => m_allocsUntilFail = allocsUntilFail;
        public void Disarm() => m_allocsUntilFail = -1;
        public int Outstanding => m_outstanding;

        public override T Allocate<T>(int size, Func<T> create, string file, int line)
        {
            if (m_allocsUntilFail == 0)
            {
                SetErrorLevel(AllocatorErrorLevel.ALLOCATOR_ERROR_OUT_OF_MEMORY);
                return null;
            }
            if (m_allocsUntilFail > 0)
                m_allocsUntilFail--;
            var p = create();
            if (p == null)
            {
                SetErrorLevel(AllocatorErrorLevel.ALLOCATOR_ERROR_OUT_OF_MEMORY);
                return null;
            }
            m_outstanding++;
            TrackAlloc(p, size, file, line);
            return p;
        }

        public override void Free(object p, string file, int line)
        {
            if (p == null)
                return;
            m_outstanding--;
            TrackFree(p, file, line);
        }

        int m_allocsUntilFail = -1;
        int m_outstanding = 0;
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

        using var queue = new QueueEx<int>(GetDefaultAllocator(), QueueSize);

        check(queue.IsEmpty);
        check(!queue.IsFull);
        check(queue.NumEntries == 0);
        check(queue.Size == QueueSize);

        const int NumEntries = 100;

        for (var i = 0; i < NumEntries; ++i)
            queue.Push(i);

        check(!queue.IsEmpty);
        check(!queue.IsFull);
        check(queue.NumEntries == NumEntries);
        check(queue.Size == QueueSize);

        for (var i = 0; i < NumEntries; ++i)
            check(queue[i] == i);

        for (var i = 0; i < NumEntries; ++i)
            check(queue.Pop() == i);

        check(queue.IsEmpty);
        check(!queue.IsFull);
        check(queue.NumEntries == 0);
        check(queue.Size == QueueSize);

        for (var i = 0; i < QueueSize; ++i)
            queue.Push(i);

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

        Array.Clear(buffer, bytesWritten, BufferSize - bytesWritten);

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
                data.bytes[i] = (byte)(rand() % 255);

            data.@string = "hello world!";
        }

        public override bool Serialize(BaseStream stream)
        {
            var context = (TestContext)stream.Context;

            if (!stream.serialize_int(ref data.a, context.min, context.max)) return false;
            if (!stream.serialize_int(ref data.b, context.min, context.max)) return false;

            if (!stream.serialize_int(ref data.c, -100, 10000)) return false;

            if (!stream.serialize_bits(ref data.d, 6)) return false;
            if (!stream.serialize_bits(ref data.e, 8)) return false;
            if (!stream.serialize_bits(ref data.f, 7)) return false;

            if (!stream.serialize_align()) return false;

            if (!stream.serialize_bool(ref data.g)) return false;

            if (!stream.serialize_int(ref data.numItems, 0, MaxItems - 1)) return false;
            for (var i = 0; i < data.numItems; ++i)
                if (!stream.serialize_bits(ref data.items[i], 8)) return false;

            if (!stream.serialize_float(ref data.float_value)) return false;

            if (!stream.serialize_double(ref data.double_value)) return false;

            if (!stream.serialize_uint64(ref data.uint64_value)) return false;

            if (!stream.serialize_bytes(data.bytes, data.bytes.Length)) return false;

            if (!stream.serialize_string(ref data.@string, MaxAddressLength)) return false;

            return true;
        }

        public override bool Equals(object obj) =>
            (this == obj as TestObject);

        public override int GetHashCode() =>
            base.GetHashCode();

        public static bool operator ==(TestObject t, TestObject other)
        {
            TestData a = t.data, b = other.data;
            return a.a == b.a && a.b == b.b && a.c == b.c && a.d == b.d && a.e == b.e && a.f == b.f && a.g == b.g
                && a.numItems == b.numItems && a.items.AsSpan().SequenceEqual(b.items)
                && a.float_value == b.float_value && a.double_value == b.double_value && a.uint64_value == b.uint64_value
                && a.bytes.AsSpan().SequenceEqual(b.bytes) && a.@string == b.@string;
        }

        public static bool operator !=(TestObject t, TestObject other) =>
             !(t == other);

        internal static TestObject CreateInitialized() { var o = new TestObject(); o.Init(); return o; }
    }

        static void test_stream()
        {
            const int BufferSize = 1024;

            var buffer = new byte[BufferSize];

            var context = new TestContext();
            context.min = -10;
            context.max = +10;

            var writeStream = new WriteStream(GetDefaultAllocator(), buffer, BufferSize);

            var writeObject = TestObject.CreateInitialized();
            writeStream.Context = context;
            check(writeObject.Serialize(writeStream));
            writeStream.Flush();

            var bytesWritten = writeStream.BytesProcessed;

            Array.Clear(buffer, bytesWritten, BufferSize - bytesWritten);

            var readObject = new TestObject();
            var readStream = new ReadStream(GetDefaultAllocator(), buffer, bytesWritten);
            readStream.Context = context;
            check(readObject.Serialize(readStream));
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
            check(parse_address("1") == false);
            check(parse_address("12") == false);
            check(parse_address("123") == false);
            check(parse_address("1234") == false);
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

            // bracketed IPv6 with no port (d3d4f33)

            {
                var address = new Address("[::1]");
                check(address.IsValid);
                check(address.Type == AddressType.ADDRESS_IPV6);
                check(address.Port == 0);
                check(address.ToString() == "::1");
            }

            {
                var address = new Address("[::]");
                check(address.IsValid);
                check(address.Type == AddressType.ADDRESS_IPV6);
                check(address.Port == 0);
                check(address.ToString() == "::");
            }

            {
                var address = new Address("[fe80::202:b3ff:fe1e:8329]");
                check(address.IsValid);
                check(address.Type == AddressType.ADDRESS_IPV6);
                check(address.Port == 0);
                check(address.ToString() == "fe80::202:b3ff:fe1e:8329");
            }

            // forms System.Net.IPAddress accepts but inet_pton does not

            check(parse_address("127.1") == false);
            check(parse_address("0x7f.0.0.1") == false);
            check(parse_address("127.0.0.01") == false);
            check(parse_address("fe80::1%3") == false);

            // equality and hashing are by value

            {
                var a = new Address("127.0.0.1:40000");
                var b = new Address(127, 0, 0, 1, 40000);
                check(a == b);
                check(a.Equals(b));
                check(a.GetHashCode() == b.GetHashCode());
                check(a != new Address("127.0.0.1:40001"));
                check(!a.Equals(null));
                check(!(a == null));
                Address n = null;
                check(n == null);
            }
        }

        static void test_address_classification()
        {
            // multicast is ff00::/8 -- the whole range, not just the group ff00

            check(new Address("ff00::1").IsMulticast);
            check(new Address("ff02::1").IsMulticast);            // all nodes: the common one
            check(new Address("ff05::1:3").IsMulticast);
            check(new Address("ffff::1").IsMulticast);
            check(!new Address("ff02::1").IsGlobalUnicast);
            check(!new Address("ff05::1:3").IsGlobalUnicast);

            // link local is fe80::/10, so fe80 through febf

            check(new Address("fe80::1").IsLinkLocal);
            check(new Address("febf::1").IsLinkLocal);
            check(!new Address("febf::1").IsGlobalUnicast);
            check(!new Address("fec0::1").IsLinkLocal);           // fec0 is site local, not link local

            // site local is fec0::/10, so fec0 through feff

            check(new Address("fec0::1").IsSiteLocal);
            check(new Address("feff::1").IsSiteLocal);
            check(!new Address("fe80::1").IsSiteLocal);

            // and the boundaries below the ranges must NOT be classified

            check(!new Address("fe7f::1").IsLinkLocal);
            check(!new Address("fe7f::1").IsSiteLocal);
            check(new Address("fe7f::1").IsGlobalUnicast);
            check(!new Address("feff::1").IsGlobalUnicast);

            // genuine global unicast still classifies, so the fix cannot pass by returning false

            check(new Address("2001:4860:4860::8888").IsGlobalUnicast);
            check(!new Address("2001:4860:4860::8888").IsMulticast);
            check(!new Address("2001:4860:4860::8888").IsLoopback);

            // loopback is unchanged, and is excluded from global unicast

            check(new Address("::1").IsLoopback);
            check(!new Address("::1").IsGlobalUnicast);
            check(new Address("127.0.0.1").IsLoopback);

            // IPv4 is never any of the IPv6 classifications

            check(!new Address("127.0.0.1").IsMulticast);
            check(!new Address("10.0.0.1").IsGlobalUnicast);
            check(!new Address("224.0.0.1").IsMulticast);
        }

        // YJ-11: an unparseable address must be cleared to ADDRESS_NONE
        static void test_address_malformed_port()
        {
            // trailing junk after the digits
            check(parse_address("127.0.0.1:40k") == false);
            check(parse_address("127.0.0.1:40 ") == false);
            check(parse_address("127.0.0.1:4.0") == false);
            check(parse_address("[::1]:40k") == false);

            // no digits at all
            check(parse_address("127.0.0.1:") == false);
            check(parse_address("[::1]:") == false);

            // a sign or leading whitespace is not a port
            check(parse_address("127.0.0.1:+40") == false);
            check(parse_address("127.0.0.1:-1") == false);
            check(parse_address("[::1]:+40") == false);
            check(parse_address("[::1]: 40") == false);

            // out of range, including more digits than fit in the parser's own integer
            check(parse_address("127.0.0.1:65536") == false);
            check(parse_address("127.0.0.1:99999") == false);
            check(parse_address("127.0.0.1:99999999999999999999999") == false);
            check(parse_address("[::1]:65536") == false);
            check(parse_address("[::1]:99999999999999999999999") == false);

            // bracket syntax is exact
            check(parse_address("[::1") == false);
            check(parse_address("[::1]junk") == false);
            check(parse_address("[::1]]") == false);
            check(parse_address("[::1]40000") == false);

            // ...and the forms that were always valid still are, with the port they say
            {
                var address = new Address("127.0.0.1:65535");
                check(address.IsValid);
                check(address.Port == 65535);
            }
            {
                var address = new Address("127.0.0.1:0");
                check(address.IsValid);
                check(address.Port == 0);
            }
            {
                var address = new Address("[::1]:40000");
                check(address.IsValid);
                check(address.Type == AddressType.ADDRESS_IPV6);
                check(address.Port == 40000);
            }
            {
                var address = new Address("[::1]");
                check(address.IsValid);
                check(address.Type == AddressType.ADDRESS_IPV6);
                check(address.Port == 0);
            }
        }

        static void test_network_simulator_drains_all_slots()
        {
            // Regression (c27a0dd): ReceivePackets used to scan only the first min(numEntries, maxPackets) ring
            // slots. Packets are stored across the whole ring (at m_currentIndex), so when a caller
            // passes maxPackets < numEntries, any packet held in a tail slot was never drained.

            const int NumEntries = 4;

            using var sim = new NetworkSimulator(GetDefaultAllocator(), NumEntries, 0.0);

            // Negative loss/duplicate rates make those RNG checks impossible to fire (random_float is
            // always >= 0), so sends are fully deterministic, and they mark the simulator active.
            sim.SetPacketLoss(-1.0f);
            sim.SetDuplicates(-1.0f);

            var payload = new byte[8];
            for (var i = 0; i < NumEntries; ++i)
            {
                Array.Fill(payload, (byte)i);
                sim.SendPacket(i, payload, payload.Length);    // fills ring slots 0..NumEntries-1, "to" == slot
            }

            sim.AdvanceTime(1.0);     // past every delivery time (latency 0)

            var seen = new bool[NumEntries];
            var totalReceived = 0;

            for (var iter = 0; iter < NumEntries + 2; ++iter)
            {
                var packetData = new byte[2][];
                var packetBytes = new int[2];
                var to = new int[2];
                var n = sim.ReceivePackets(2, packetData, packetBytes, to);
                check(n <= 2);        // never returns more than maxPackets
                for (var i = 0; i < n; ++i)
                {
                    check(to[i] >= 0 && to[i] < NumEntries);
                    check(!seen[to[i]]);      // no packet delivered twice
                    check(packetBytes[i] == payload.Length);
                    check(packetData[i][0] == (byte)to[i]);
                    seen[to[i]] = true;
                    totalReceived++;
                    YOJIMBO_FREE(sim.Allocator, ref packetData[i]);
                }
            }

            check(totalReceived == NumEntries);
            for (var i = 0; i < NumEntries; ++i)
                check(seen[i]);       // tail slots (index >= maxPackets) were drained too
        }

        static void test_network_simulator_overwrite_slot()
        {
            // C# regression: when the ring wrapped onto an occupied slot, SendPacket assigned a new PacketEntry
            // to a local variable only, so the new packet was written to an orphan object and lost.

            const int NumEntries = 2;

            using var sim = new NetworkSimulator(GetDefaultAllocator(), NumEntries, 0.0);
            sim.SetPacketLoss(-1.0f);
            sim.SetDuplicates(-1.0f);

            var payload = new byte[4];
            for (var i = 0; i < NumEntries + 1; ++i)      // the third send wraps onto slot 0
            {
                Array.Fill(payload, (byte)(i + 1));
                sim.SendPacket(i, payload, payload.Length);
            }

            sim.AdvanceTime(1.0);

            var packetData = new byte[NumEntries][];
            var packetBytes = new int[NumEntries];
            var to = new int[NumEntries];
            var n = sim.ReceivePackets(NumEntries, packetData, packetBytes, to);
            check(n == NumEntries);
            var sawNewest = false;
            for (var i = 0; i < n; ++i)
            {
                if (to[i] == NumEntries && packetData[i][0] == NumEntries + 1)
                    sawNewest = true;
                YOJIMBO_FREE(sim.Allocator, ref packetData[i]);
            }
            check(sawNewest);
        }

        static void test_bit_array()
        {
            const int Size = 300;

            using var bit_array = new BitArray(GetDefaultAllocator(), Size);

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

            using var sequence_buffer = new SequenceBuffer<TestSequenceData>(GetDefaultAllocator(), Size);

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

            for (ushort i = 0; i <= Size; ++i)
            {
                var entry = sequence_buffer.Insert(i, true);
                check(entry != null);
                entry.sequence = i;
                check(sequence_buffer.GetSequence() == i + 1);
            }

            sequence_buffer.Reset();

            check(sequence_buffer.GetSequence() == 0);

            for (ushort i = 0; i < Size; ++i)
                check(sequence_buffer.Find(i) == null);
        }

        static void test_allocator_tlsf()
        {
            const int NumBlocks = 256;
            const int BlockSize = 1024;
            const int MemorySize = NumBlocks * BlockSize;

            // the C# TLSF_Allocator draws its blocks from the GC, so it needs no backing memory, only its size
            using var allocator = new TLSF_Allocator(null, MemorySize);

            var blockData = new byte[NumBlocks][];

            var stopIndex = 0;

            for (var i = 0; i < NumBlocks; ++i)
            {
                blockData[i] = YOJIMBO_ALLOCATE(allocator, BlockSize);

                if (blockData[i] == null)
                {
                    check(allocator.ErrorLevel == AllocatorErrorLevel.ALLOCATOR_ERROR_OUT_OF_MEMORY);
                    allocator.ClearError();
                    check(allocator.ErrorLevel == AllocatorErrorLevel.ALLOCATOR_ERROR_NONE);
                    stopIndex = i;
                    break;
                }

                check(blockData[i] != null);
                check(allocator.ErrorLevel == AllocatorErrorLevel.ALLOCATOR_ERROR_NONE);

                Array.Fill(blockData[i], (byte)(i + 10));
            }

            check(stopIndex > NumBlocks / 2);

            for (var i = 0; i < NumBlocks - 1; ++i)
            {
                if (blockData[i] != null)
                {
                    for (var j = 0; j < BlockSize; ++j)
                        check(blockData[i][j] == (byte)(i + 10));
                }

                YOJIMBO_FREE(allocator, ref blockData[i]);
            }

            // C#: freeing returns the bytes to the heap
            check(allocator.BytesAllocated == 0);
        }

        static void PumpConnectionUpdate(ConnectionConfig connectionConfig, ref double time, Connection sender, Connection receiver, ref ushort senderSequence, ref ushort receiverSequence, float deltaTime = 0.1f, int packetLossPercent = 90)
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
            using var messageFactory = new TestMessageFactory(GetDefaultAllocator());

            var time = 100.0;

            var connectionConfig = new ConnectionConfig();

            using var sender = new Connection(GetDefaultAllocator(), messageFactory, connectionConfig, time);
            using var receiver = new Connection(GetDefaultAllocator(), messageFactory, connectionConfig, time);

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
                PumpConnectionUpdate(connectionConfig, ref time, sender, receiver, ref senderSequence, ref receiverSequence);

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
            using var messageFactory = new TestMessageFactory(GetDefaultAllocator());

            var time = 100.0;

            var connectionConfig = new ConnectionConfig();

            using var sender = new Connection(GetDefaultAllocator(), messageFactory, connectionConfig, time);
            using var receiver = new Connection(GetDefaultAllocator(), messageFactory, connectionConfig, time);

            const int NumMessagesSent = 32;

            for (ushort i = 0; i < NumMessagesSent; ++i)
            {
                var message = (TestBlockMessage)messageFactory.CreateMessage((int)TestMessageType.TEST_BLOCK_MESSAGE);
                check(message != null);
                message.sequence = i;
                var blockSize = 1 + ((i * 901) % 3333);
                var blockData = YOJIMBO_ALLOCATE(messageFactory.Allocator, blockSize);
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
                PumpConnectionUpdate(connectionConfig, ref time, sender, receiver, ref senderSequence, ref receiverSequence);

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
            using var messageFactory = new TestMessageFactory(GetDefaultAllocator());

            var time = 100.0;

            var connectionConfig = new ConnectionConfig();

            using var sender = new Connection(GetDefaultAllocator(), messageFactory, connectionConfig, time);

            using var receiver = new Connection(GetDefaultAllocator(), messageFactory, connectionConfig, time);

            const int NumMessagesSent = 32;

            for (ushort i = 0; i < NumMessagesSent; ++i)
                if ((rand() % 2) != 0)
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
                    var blockData = YOJIMBO_ALLOCATE(messageFactory.Allocator, blockSize);
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
                PumpConnectionUpdate(connectionConfig, ref time, sender, receiver, ref senderSequence, ref receiverSequence);

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

            using var messageFactory = new TestMessageFactory(GetDefaultAllocator());

            var connectionConfig = new ConnectionConfig();
            connectionConfig.numChannels = NumChannels;
            connectionConfig.channel[0].type = ChannelType.CHANNEL_TYPE_RELIABLE_ORDERED;
            connectionConfig.channel[0].maxMessagesPerPacket = 8;
            connectionConfig.channel[1].type = ChannelType.CHANNEL_TYPE_RELIABLE_ORDERED;
            connectionConfig.channel[1].maxMessagesPerPacket = 8;

            using var sender = new Connection(GetDefaultAllocator(), messageFactory, connectionConfig, time);

            using var receiver = new Connection(GetDefaultAllocator(), messageFactory, connectionConfig, time);

            const int NumMessagesSent = 32;

            for (var channelIndex = 0; channelIndex < NumChannels; ++channelIndex)
                for (ushort i = 0; i < NumMessagesSent; ++i)
                    if ((rand() % 2) != 0)
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
                        var blockData = YOJIMBO_ALLOCATE(messageFactory.Allocator, blockSize);
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
                PumpConnectionUpdate(connectionConfig, ref time, sender, receiver, ref senderSequence, ref receiverSequence);

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
            using var messageFactory = new TestMessageFactory(GetDefaultAllocator());

            var time = 100.0;

            var connectionConfig = new ConnectionConfig();
            connectionConfig.numChannels = 1;
            connectionConfig.channel[0].type = ChannelType.CHANNEL_TYPE_UNRELIABLE_UNORDERED;

            using var sender = new Connection(GetDefaultAllocator(), messageFactory, connectionConfig, time);
            using var receiver = new Connection(GetDefaultAllocator(), messageFactory, connectionConfig, time);

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
                PumpConnectionUpdate(connectionConfig, ref time, sender, receiver, ref senderSequence, ref receiverSequence, 0.1f, 0);

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
            using var messageFactory = new TestMessageFactory(GetDefaultAllocator());

            var time = 100.0;

            var connectionConfig = new ConnectionConfig();
            connectionConfig.numChannels = 1;
            connectionConfig.channel[0].type = ChannelType.CHANNEL_TYPE_UNRELIABLE_UNORDERED;

            using var sender = new Connection(GetDefaultAllocator(), messageFactory, connectionConfig, time);

            using var receiver = new Connection(GetDefaultAllocator(), messageFactory, connectionConfig, time);

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
                var blockData = YOJIMBO_ALLOCATE(messageFactory.Allocator, blockSize);
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
                PumpConnectionUpdate(connectionConfig, ref time, sender, receiver, ref senderSequence, ref receiverSequence, 0.1f, 0);

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

                if ((rand() % 10) != 0)
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

                if ((rand() % 10) != 0)
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

            var client = new Client(GetDefaultAllocator(), clientAddress, config, shared.adapter, time);

            var privateKey = new byte[KeyBytes];

            var server = new Server(GetDefaultAllocator(), privateKey, serverAddress, config, shared.adapter, time);

            server.Start(MaxClients);

            server.SetLatency(250);
            server.SetJitter(100);
            server.SetPacketLoss(25);
            server.SetDuplicates(25);

            for (var iteration = 0; iteration < 2; ++iteration)
            {
                // connect and wait until connection completes

                client.InsecureConnect(privateKey, clientId, serverAddress);

                // the client network simulator is created on connect, so apply its settings after (e79ad2a)

                client.SetLatency(250);
                client.SetJitter(100);
                client.SetPacketLoss(25);
                client.SetDuplicates(25);

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
                clients[i] = new Client(GetDefaultAllocator(), address, config, _adapter, time);
            }
        }

        static void ConnectClients(int numClients, Client[] clients, byte[] privateKey, Address serverAddress)
        {
            for (var i = 0; i < numClients; ++i)
            {
                clients[i].InsecureConnect(privateKey, (ulong)(i + 1), serverAddress);
                clients[i].SetLatency(250);
                clients[i].SetJitter(100);
                clients[i].SetPacketLoss(25);
                clients[i].SetDuplicates(25);
            }
        }

        static void DestroyClients(int numClients, Client[] clients)
        {
            for (var i = 0; i < numClients; ++i)
            {
                clients[i].Disconnect();
                clients[i].Dispose();
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

            var server = new Server(GetDefaultAllocator(), privateKey, serverAddress, config, shared.adapter, time);

            int[] numClients = { 3, 5, 1, 32, 5 };

            var NumIterations = numClients.Length;

            for (var iteration = 0; iteration < NumIterations; ++iteration)
            {
                numClients[iteration] = numClients[iteration] % MaxClients;
                if (numClients[iteration] == 0)
                    numClients[iteration] = 1;

                server.Start(numClients[iteration]);

                // the server network simulator is recreated by every Start, so apply its settings after each one (e79ad2a)

                server.SetLatency(250);
                server.SetJitter(100);
                server.SetPacketLoss(25);
                server.SetDuplicates(25);

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

            var server = new Server(GetDefaultAllocator(), privateKey, serverAddress, config, shared.adapter, time);

            server.Start(MaxClients);

            var client = new Client(GetDefaultAllocator(), clientAddress, config, shared.adapter, time);

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

            var server = new Server(GetDefaultAllocator(), privateKey, serverAddress, config, shared.adapter, time);

            server.Start(MaxClients);

            var client = new Client(GetDefaultAllocator(), clientAddress, config, shared.adapter, time);

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

            var server = new Server(GetDefaultAllocator(), privateKey, serverAddress, config, shared.adapter, time);

            server.Start(MaxClients);

            var client = new Client(GetDefaultAllocator(), clientAddress, config, shared.adapter, time);

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

            var server = new Server(GetDefaultAllocator(), privateKey, serverAddress, config, shared.adapter, time);

            server.Start(MaxClients);

            var client = new Client(GetDefaultAllocator(), clientAddress, config, shared.adapter, time);

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
            var server = new Server(GetDefaultAllocator(), privateKey, new Address("127.0.0.1", shared.ServerPort), config, shared.adapter, time);

            server.Start(MaxClients);
            check(server.IsRunning);

            var clientId = 0UL;
            random_bytes(ref clientId, 8);

            var client = new Client(GetDefaultAllocator(), new Address("0.0.0.0"), config, shared.adapter, time);

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
            using var messageFactory = new SingleTestMessageFactory(GetDefaultAllocator());

            var time = 100.0;

            var connectionConfig = new ConnectionConfig();
            using var sender = new Connection(GetDefaultAllocator(), messageFactory, connectionConfig, time);
            using var receiver = new Connection(GetDefaultAllocator(), messageFactory, connectionConfig, time);

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
                PumpConnectionUpdate(connectionConfig, ref time, sender, receiver, ref senderSequence, ref receiverSequence);

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
            using var messageFactory = new SingleBlockTestMessageFactory(GetDefaultAllocator());

            var time = 100.0;

            var connectionConfig = new ConnectionConfig();

            using var sender = new Connection(GetDefaultAllocator(), messageFactory, connectionConfig, time);
            using var receiver = new Connection(GetDefaultAllocator(), messageFactory, connectionConfig, time);

            const int NumMessagesSent = 32;

            for (ushort i = 0; i < NumMessagesSent; ++i)
            {
                var message = (TestBlockMessage)messageFactory.CreateMessage((int)SingleBlockTestMessageType.SINGLE_BLOCK_TEST_MESSAGE);
                check(message != null);
                message.sequence = i;
                var blockSize = 1 + ((i * 901) % 3333);
                var blockData = YOJIMBO_ALLOCATE(messageFactory.Allocator, blockSize);
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
                PumpConnectionUpdate(connectionConfig, ref time, sender, receiver, ref senderSequence, ref receiverSequence);

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
            using var messageFactory = new SingleTestMessageFactory(GetDefaultAllocator());

            var time = 100.0;

            var connectionConfig = new ConnectionConfig();
            connectionConfig.numChannels = 1;
            connectionConfig.channel[0].type = ChannelType.CHANNEL_TYPE_UNRELIABLE_UNORDERED;

            using var sender = new Connection(GetDefaultAllocator(), messageFactory, connectionConfig, time);
            using var receiver = new Connection(GetDefaultAllocator(), messageFactory, connectionConfig, time);

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
                PumpConnectionUpdate(connectionConfig, ref time, sender, receiver, ref senderSequence, ref receiverSequence, 0.1f, 0);

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

        // ---------------------------------------------------------------------------------------------
        // serialize (upstream moved these into the vendored serialize library's own test suite)

        class SerializePrimitivesObject : Serializable
        {
            public long i64;
            public Int128 i128;
            public UInt128 u128;
            public ulong bits64;
            public ulong bits40;
            public float cf;
            public string s;
            public string ws;
            public long fixed48_16;
            public int fixed16_16;
            public int degenerate;
            public int rel;
            public ushort seq;

            public override bool Serialize(BaseStream stream)
            {
                if (!stream.serialize_int64(ref i64, long.MinValue, long.MaxValue)) return false;
                if (!stream.serialize_int128(ref i128, Int128.MinValue / 2, Int128.MaxValue / 3)) return false;
                if (!stream.serialize_uint128(ref u128)) return false;
                if (!stream.serialize_bits(ref bits64, 64)) return false;
                if (!stream.serialize_bits(ref bits40, 40)) return false;
                if (!stream.serialize_compressed_float(ref cf, -100.0f, 100.0f, 0.01f)) return false;
                if (!stream.serialize_string(ref s, 64)) return false;
                if (!stream.serialize_wstring(ref ws, 64)) return false;
                if (!stream.serialize_fixed(ref fixed48_16, 48, 16, -1000, 1000)) return false;
                if (!stream.serialize_fixed(ref fixed16_16, 16, 16, -100, 100)) return false;
                if (!stream.serialize_int(ref degenerate, 7, 7)) return false;
                if (!stream.serialize_int_relative(1000, ref rel)) return false;
                if (!stream.serialize_sequence_relative(65530, ref seq)) return false;
                return true;
            }
        }

        static void test_serialize_primitives()
        {
            const int BufferSize = 1024;

            var write = new SerializePrimitivesObject
            {
                i64 = -1234567890123456789L,
                i128 = Int128.MinValue / 3,
                u128 = UInt128.MaxValue - 12345,
                bits64 = 0xFEDCBA9876543210UL,
                bits40 = 0xAB_CDEF_0123UL,
                cf = 12.345f,
                s = "héllo wörld ✓",
                ws = "wide \U0001F600 string",
                fixed48_16 = (-123L << 16) | 0x8000,
                fixed16_16 = (99 << 16) | 0x1234,
                degenerate = 7,
                rel = 1000 + 300,
                seq = 4,                                            // wraps relative to 65530
            };

            var buffer = new byte[BufferSize];
            var writeStream = new WriteStream(buffer, BufferSize);
            check(write.Serialize(writeStream));
            writeStream.Flush();

            // measure is an upper bound on what is written
            var measureStream = new MeasureStream();
            check(write.Serialize(measureStream));
            check(measureStream.BitsProcessed >= writeStream.BitsProcessed);

            var read = new SerializePrimitivesObject { degenerate = -1 };
            var readStream = new ReadStream(buffer, writeStream.BytesProcessed);
            check(read.Serialize(readStream));

            check(read.i64 == write.i64);
            check(read.i128 == write.i128);
            check(read.u128 == write.u128);
            check(read.bits64 == write.bits64);
            check(read.bits40 == write.bits40);
            check(Math.Abs(read.cf - write.cf) <= 0.01f);
            check(read.s == write.s);
            check(read.ws == write.ws);
            check(read.fixed48_16 == write.fixed48_16);
            check(read.fixed16_16 == write.fixed16_16);
            check(read.degenerate == 7);
            check(read.rel == write.rel);
            check(read.seq == write.seq);

            // a degenerate range costs zero bits
            {
                var m = new MeasureStream();
                var v = 5;
                check(m.serialize_int(ref v, 5, 5));
                check(m.BitsProcessed == 0);
            }

            // bit layout: LSB first, little endian, identical to upstream
            {
                var b = new byte[8];
                var w = new WriteStream(b, 8);
                var x = 0x12345678U;
                check(w.serialize_bits(ref x, 32));
                var y = 1U;
                check(w.serialize_bits(ref y, 1));
                w.Flush();
                check(w.BytesProcessed == 5);
                check(b[0] == 0x78 && b[1] == 0x56 && b[2] == 0x34 && b[3] == 0x12 && b[4] == 0x01);
            }
        }

        static void test_serialize_failure_latch()
        {
            // a refused read leaves the destination untouched and fails every later read on the stream
            var buffer = new byte[8];
            var w = new WriteStream(buffer, 8);
            var raw = 7U;
            check(w.serialize_bits(ref raw, 3));
            var more = 0x3FU;
            check(w.serialize_bits(ref more, 6));
            w.Flush();

            var r = new ReadStream(buffer, w.BytesProcessed);
            var x = 42;
            check(!r.serialize_int(ref x, 0, 5));             // 3 bits read 7, which is out of [0,5]
            check(x == 42);
            var b = false;
            check(!r.serialize_bool(ref b));                  // latched: bits remain, but the stream has failed
            var d = 0;
            check(!r.serialize_int(ref d, 3, 3));             // even a zero bit read refuses
            check(!r.serialize_align());

            // reading past the end fails cleanly
            {
                var r2 = new ReadStream(buffer, 1);
                var v = 0U;
                check(!r2.serialize_bits(ref v, 9));
            }

            // int_relative refuses a reconstruction that does not move forward
            {
                var b2 = new byte[16];
                var w2 = new WriteStream(b2, 16);
                for (var i = 0; i < 6; ++i)
                {
                    var flag = false;
                    check(w2.serialize_bool(ref flag));
                }
                var absolute = 5U;                            // absolute tier: 5 <= previous (10)
                check(w2.serialize_bits(ref absolute, 32));
                w2.Flush();
                var r3 = new ReadStream(b2, w2.BytesProcessed);
                var current = -1;
                check(!r3.serialize_int_relative(10, ref current));
                check(current == -1);
            }

            // strings: an interior NUL or invalid UTF-8 is refused
            {
                var b3 = new byte[32];
                var w3 = new WriteStream(b3, 32);
                var length = 3;
                check(w3.serialize_int(ref length, 0, 63));
                check(w3.serialize_bytes(new byte[] { (byte)'a', 0, (byte)'b' }, 3));
                w3.Flush();
                string s = null;
                check(!new ReadStream(b3, w3.BytesProcessed).serialize_string(ref s, 64));
                check(s == null);

                var b4 = new byte[32];
                var w4 = new WriteStream(b4, 32);
                length = 2;
                check(w4.serialize_int(ref length, 0, 63));
                check(w4.serialize_bytes(new byte[] { 0xC0, 0x80 }, 2));      // overlong NUL
                w4.Flush();
                check(!new ReadStream(b4, w4.BytesProcessed).serialize_string(ref s, 64));
            }

            // wstring: an unpaired surrogate is refused
            {
                var b5 = new byte[32];
                var w5 = new WriteStream(b5, 32);
                var length = 2;
                check(w5.serialize_int(ref length, 0, 63));
                var u0 = 0xD800U;
                var u1 = (uint)'a';
                check(w5.serialize_bits(ref u0, 32));
                check(w5.serialize_bits(ref u1, 32));
                w5.Flush();
                string ws = null;
                check(!new ReadStream(b5, w5.BytesProcessed).serialize_wstring(ref ws, 64));
            }

            // compressed float: an integer above max_integer_value smuggled into the headroom is refused
            {
                serialize_compressed_float_params(0.0f, 10.0f, 1.0f, out var max_integer_value, out var bits, out var delta);
                check(max_integer_value == 10);
                check(bits == 4);
                var b6 = new byte[8];
                var w6 = new WriteStream(b6, 8);
                var smuggled = 15U;
                check(w6.serialize_bits(ref smuggled, bits));
                w6.Flush();
                var f = 1.5f;
                check(!new ReadStream(b6, w6.BytesProcessed).serialize_compressed_float(ref f, 0.0f, 10.0f, 1.0f));
                check(f == 1.5f);
            }
        }

        // ---------------------------------------------------------------------------------------------
        // connection hardening

        static void test_connection_reject_empty_packet()
        {
            // A packet that is exactly a reliable header reaches Connection.ProcessPacket with
            // zero payload bytes. That must be rejected cleanly, not fed to the bit reader (50d2ae0).

            using var messageFactory = new TestMessageFactory(GetDefaultAllocator());

            var time = 100.0;

            var connectionConfig = new ConnectionConfig();
            connectionConfig.numChannels = 1;
            connectionConfig.channel[0].type = ChannelType.CHANNEL_TYPE_RELIABLE_ORDERED;

            using var connection = new Connection(GetDefaultAllocator(), messageFactory, connectionConfig, time);

            var buffer = new byte[1];

            check(!connection.ProcessPacket(null, 0, buffer, 0));
            check(connection.ErrorLevel == ConnectionErrorLevel.CONNECTION_ERROR_READ_PACKET_FAILED);
        }

        static void test_connection_process_packet_exact_allocation()
        {
            // Production receive hands ProcessPacket an exact payload allocation (1d59976). The C# BitReader
            // bounds checks its loads, so this must work without the +8 slack copy upstream needs.
            using var messageFactory = new TestMessageFactory(GetDefaultAllocator());
            var time = 100.0;
            var connectionConfig = new ConnectionConfig();
            connectionConfig.numChannels = 1;
            connectionConfig.channel[0].type = ChannelType.CHANNEL_TYPE_RELIABLE_ORDERED;
            using var sender = new Connection(GetDefaultAllocator(), messageFactory, connectionConfig, time);
            using var receiver = new Connection(GetDefaultAllocator(), messageFactory, connectionConfig, time);

            var message = (TestMessage)messageFactory.CreateMessage((int)TestMessageType.TEST_MESSAGE);
            check(message != null);
            message.sequence = 0;
            sender.SendMessage(0, message);

            var packet = new byte[2048];
            check(sender.GeneratePacket(null, 0, packet, packet.Length, out var packetBytes));
            check(packetBytes > 0);

            var exact = new byte[packetBytes];
            Buffer.BlockCopy(packet, 0, exact, 0, packetBytes);
            check(receiver.ProcessPacket(null, 0, exact, packetBytes));

            var received = receiver.ReceiveMessage(0);
            check(received != null);
            check(received.Type == (int)TestMessageType.TEST_MESSAGE);
            messageFactory.ReleaseMessage(ref received);
        }

        static void test_connection_unreliable_rejects_block_fragment()
        {
            // An unreliable-unordered channel never sends a top-level block fragment (its blocks
            // are serialized inline). A peer that puts a block fragment on that channel index must be
            // rejected as a serialize failure (50d2ae0).

            using var messageFactory = new TestMessageFactory(GetDefaultAllocator());

            var time = 100.0;

            // Sender speaks reliable-ordered on channel 0, so it emits a top-level block fragment.
            var senderConfig = new ConnectionConfig();
            senderConfig.numChannels = 1;
            senderConfig.channel[0].type = ChannelType.CHANNEL_TYPE_RELIABLE_ORDERED;

            // Receiver treats channel 0 as unreliable-unordered.
            var receiverConfig = new ConnectionConfig();
            receiverConfig.numChannels = 1;
            receiverConfig.channel[0].type = ChannelType.CHANNEL_TYPE_UNRELIABLE_UNORDERED;

            using var sender = new Connection(GetDefaultAllocator(), messageFactory, senderConfig, time);
            using var receiver = new Connection(GetDefaultAllocator(), messageFactory, receiverConfig, time);

            var message = (TestBlockMessage)messageFactory.CreateMessage((int)TestMessageType.TEST_BLOCK_MESSAGE);
            check(message != null);
            message.sequence = 0;
            const int blockSize = 64;
            var blockData = YOJIMBO_ALLOCATE(messageFactory.Allocator, blockSize);
            for (var i = 0; i < blockSize; ++i)
                blockData[i] = (byte)i;
            message.AttachBlock(messageFactory.Allocator, blockData, blockSize);
            sender.SendMessage(0, message);

            var packetData = new byte[senderConfig.maxPacketSize];
            ushort sequence = 0;
            var sawChannelError = false;

            for (var i = 0; i < 64 && !sawChannelError; ++i)
            {
                if (sender.GeneratePacket(null, sequence, packetData, senderConfig.maxPacketSize, out var packetBytes) && packetBytes > 0)
                    receiver.ProcessPacket(null, sequence, packetData, packetBytes);

                sender.AdvanceTime(time);
                receiver.AdvanceTime(time);
                time += 0.1;
                sequence++;

                if (receiver.ErrorLevel == ConnectionErrorLevel.CONNECTION_ERROR_CHANNEL)
                    sawChannelError = true;
            }

            check(sawChannelError);
            check(receiver.GetChannelErrorLevel(0) == ChannelErrorLevel.CHANNEL_ERROR_FAILED_TO_SERIALIZE);
        }

        static void test_connection_reliable_block_fragment_on_disabled_blocks()
        {
            // A peer sends a block fragment on a reliable-ordered channel, but the receiver has
            // blocks disabled on that channel. The read must fail cleanly (b2fccb2).

            using var messageFactory = new TestMessageFactory(GetDefaultAllocator());

            var time = 100.0;

            var senderConfig = new ConnectionConfig();
            senderConfig.numChannels = 1;
            senderConfig.channel[0].type = ChannelType.CHANNEL_TYPE_RELIABLE_ORDERED;

            var receiverConfig = new ConnectionConfig();
            receiverConfig.numChannels = 1;
            receiverConfig.channel[0].type = ChannelType.CHANNEL_TYPE_RELIABLE_ORDERED;
            receiverConfig.channel[0].disableBlocks = true;

            using var sender = new Connection(GetDefaultAllocator(), messageFactory, senderConfig, time);
            using var receiver = new Connection(GetDefaultAllocator(), messageFactory, receiverConfig, time);

            var message = (TestBlockMessage)messageFactory.CreateMessage((int)TestMessageType.TEST_BLOCK_MESSAGE);
            check(message != null);
            message.sequence = 0;
            const int blockSize = 2000;
            var blockData = YOJIMBO_ALLOCATE(messageFactory.Allocator, blockSize);
            for (var i = 0; i < blockSize; ++i)
                blockData[i] = (byte)i;
            message.AttachBlock(messageFactory.Allocator, blockData, blockSize);
            sender.SendMessage(0, message);

            var packetData = new byte[senderConfig.maxPacketSize];
            ushort sequence = 0;

            for (var i = 0; i < 64; ++i)
            {
                if (sender.GeneratePacket(null, sequence, packetData, senderConfig.maxPacketSize, out var packetBytes) && packetBytes > 0)
                    receiver.ProcessPacket(null, sequence, packetData, packetBytes);

                sender.AdvanceTime(time);
                receiver.AdvanceTime(time);
                time += 0.1;
                sequence++;

                if (receiver.ErrorLevel != ConnectionErrorLevel.CONNECTION_ERROR_NONE)
                    break;
            }

            check(receiver.ErrorLevel != ConnectionErrorLevel.CONNECTION_ERROR_NONE);
        }

        // Hand-serialize a connection packet carrying a single reliable-ordered channel entry that is
        // a block fragment, for a numChannels == 1 config. Lets tests inject fragment fields a well-behaved sender never would.
        static bool SerializeRawBlockFragmentPacket(BaseStream stream, int maxFragmentsPerBlock, int blockFragmentSize, int numFragments, int fragmentId, int fragmentSize)
        {
            var numChannelEntries = 1;
            if (!stream.serialize_int(ref numChannelEntries, 0, 1)) return false;   // numChannels == 1, so channelIndex is not serialized

            var blockMessage = true;
            if (!stream.serialize_bool(ref blockMessage)) return false;

            var messageId = 0U;
            if (!stream.serialize_bits(ref messageId, 16)) return false;

            if (maxFragmentsPerBlock > 1)
                if (!stream.serialize_int(ref numFragments, 1, maxFragmentsPerBlock)) return false;

            if (numFragments > 1)
                if (!stream.serialize_int(ref fragmentId, 0, numFragments - 1)) return false;

            if (!stream.serialize_int(ref fragmentSize, 1, blockFragmentSize)) return false;

            var payload = new byte[2048];
            Array.Fill(payload, (byte)0xAB);
            if (!stream.serialize_bytes(payload, fragmentSize)) return false;

            // fragmentId != 0 here, so no message type / block message is serialized.
            return true;
        }

        static void test_connection_reliable_block_fragment_overflow()
        {
            // A peer sends a final block fragment that claims a full blockFragmentSize of data when maxBlockSize is
            // not a multiple of blockFragmentSize. The receive buffer is maxBlockSize bytes, so the fragment must be
            // rejected before the copy (d3d4f33) rather than overflowing (C++) or throwing (C#).

            using var messageFactory = new TestMessageFactory(GetDefaultAllocator());

            var time = 100.0;

            var config = new ConnectionConfig();
            config.numChannels = 1;
            config.channel[0].type = ChannelType.CHANNEL_TYPE_RELIABLE_ORDERED;
            config.channel[0].maxBlockSize = 1100;      // deliberately not a multiple of blockFragmentSize
            config.channel[0].blockFragmentSize = 500;  // => upstream GetMaxFragmentsPerBlock() == ceil(1100/500) == 3

            var maxFragmentsPerBlock = config.channel[0].MaxFragmentsPerBlock;
            var blockFragmentSize = config.channel[0].blockFragmentSize;

            check(maxFragmentsPerBlock == 3);

            using var receiver = new Connection(GetDefaultAllocator(), messageFactory, config, time);

            // messageId=0 (== expected receive sequence), final fragment, full blockFragmentSize payload.
            var numFragments = maxFragmentsPerBlock;
            var fragmentId = numFragments - 1;
            var fragmentSize = blockFragmentSize;

            var buffer = new byte[4096];
            var stream = new WriteStream(buffer, buffer.Length);
            check(SerializeRawBlockFragmentPacket(stream, maxFragmentsPerBlock, blockFragmentSize, numFragments, fragmentId, fragmentSize));
            stream.Flush();
            var packetBytes = stream.BytesProcessed;
            check(packetBytes > 0);

            var processed = receiver.ProcessPacket(null, 0, buffer, packetBytes);
            check(!processed);

            receiver.AdvanceTime(time);
            check(receiver.ErrorLevel == ConnectionErrorLevel.CONNECTION_ERROR_CHANNEL);
        }

        static void test_connection_reliable_over_budget_packet()
        {
            // A peer sends more channel data than the receiver's configured packetBudget. On read this
            // used to trip the YOJIMBO_DEBUG_MESSAGE_BUDGET assert, a remote crash in debug builds (1b6bec0).

            using var messageFactory = new TestMessageFactory(GetDefaultAllocator());

            var time = 100.0;

            var senderConfig = new ConnectionConfig();
            senderConfig.numChannels = 1;
            senderConfig.channel[0].type = ChannelType.CHANNEL_TYPE_RELIABLE_ORDERED;

            var receiverConfig = new ConnectionConfig();
            receiverConfig.numChannels = 1;
            receiverConfig.channel[0].type = ChannelType.CHANNEL_TYPE_RELIABLE_ORDERED;
            receiverConfig.channel[0].packetBudget = 32;

            using var sender = new Connection(GetDefaultAllocator(), messageFactory, senderConfig, time);
            using var receiver = new Connection(GetDefaultAllocator(), messageFactory, receiverConfig, time);

            const int NumMessages = 64;
            for (var i = 0; i < NumMessages; ++i)
            {
                var message = (TestMessage)messageFactory.CreateMessage((int)TestMessageType.TEST_MESSAGE);
                check(message != null);
                message.sequence = (ushort)i;
                sender.SendMessage(0, message);
            }

            var packetData = new byte[senderConfig.maxPacketSize];
            ushort sequence = 0;
            var processed = false;

            for (var i = 0; i < 8 && !processed; ++i)
            {
                if (sender.GeneratePacket(null, sequence, packetData, senderConfig.maxPacketSize, out var packetBytes) && packetBytes > 0)
                {
                    check(receiver.ProcessPacket(null, sequence, packetData, packetBytes));
                    processed = true;
                }

                sender.AdvanceTime(time);
                receiver.AdvanceTime(time);
                time += 0.1;
                sequence++;
            }

            check(processed);
            check(receiver.ErrorLevel == ConnectionErrorLevel.CONNECTION_ERROR_NONE);
        }

        static void test_connection_reliable_ordered_blocks_max_size()
        {
            // Regression (760ebc2): when maxBlockSize is not a multiple of blockFragmentSize, a full-size block
            // needs ceil(maxBlockSize/blockFragmentSize) fragments. Here 1100/500 => floor 2, ceil 3.
            var connectionConfig = new ConnectionConfig();
            connectionConfig.channel[0].maxBlockSize = 1100;
            connectionConfig.channel[0].blockFragmentSize = 500;

            check(connectionConfig.channel[0].MaxFragmentsPerBlock == 3);

            using var messageFactory = new TestMessageFactory(GetDefaultAllocator());

            var time = 100.0;

            using var sender = new Connection(GetDefaultAllocator(), messageFactory, connectionConfig, time);
            using var receiver = new Connection(GetDefaultAllocator(), messageFactory, connectionConfig, time);

            const int NumMessagesSent = 8;
            var BlockSize = connectionConfig.channel[0].maxBlockSize;

            for (var i = 0; i < NumMessagesSent; ++i)
            {
                var message = (TestBlockMessage)messageFactory.CreateMessage((int)TestMessageType.TEST_BLOCK_MESSAGE);
                check(message != null);
                message.sequence = (ushort)i;
                var blockData = YOJIMBO_ALLOCATE(messageFactory.Allocator, BlockSize);
                for (var j = 0; j < BlockSize; ++j)
                    blockData[j] = (byte)(i + j);
                message.AttachBlock(messageFactory.Allocator, blockData, BlockSize);
                sender.SendMessage(0, message);
            }

            var numMessagesReceived = 0;
            ushort senderSequence = 0;
            ushort receiverSequence = 0;
            const int NumIterations = 10000;

            for (var i = 0; i < NumIterations; ++i)
            {
                PumpConnectionUpdate(connectionConfig, ref time, sender, receiver, ref senderSequence, ref receiverSequence);

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
                    check(blockSize == BlockSize);

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

        static void test_connection_reliable_message_alloc_failure()
        {
            // Regression: on the send path, GetMessagePacketData allocated the message-pointer array
            // without checking for null and then wrote through it - a crash on allocator exhaustion.
            // Arm the allocator to fail that first allocation inside GeneratePacket and verify we neither
            // crash nor leak (the queued reliable message is retained and freed at teardown).
            var allocator = new ArmableAllocator();
            {
                using var messageFactory = new TestMessageFactory(allocator);

                var config = new ConnectionConfig();
                config.numChannels = 1;
                config.channel[0].type = ChannelType.CHANNEL_TYPE_RELIABLE_ORDERED;

                {
                    using var connection = new Connection(allocator, messageFactory, config, 100.0);

                    var message = messageFactory.CreateMessage((int)TestMessageType.TEST_MESSAGE);
                    check(message != null);
                    connection.SendMessage(0, message);

                    var packetData = new byte[4096];

                    allocator.Arm(0);     // fail the first allocation inside GeneratePacket (message array)
                    connection.GeneratePacket(null, 0, packetData, packetData.Length, out var packetBytes);
                    allocator.Disarm();
                }
            }
            check(allocator.Outstanding == 0);   // no leak across teardown
            allocator.Dispose();
        }

        static void test_connection_unreliable_message_alloc_failure()
        {
            // Regression: the unreliable channel's GetPacketData allocated the message-pointer array
            // without a null check and then wrote through it. The messages had already been popped off
            // the send queue, so a failure crashed (null deref) and would have leaked the popped
            // messages. Arm the allocator to fail that allocation and verify no crash and no leak.
            var allocator = new ArmableAllocator();
            {
                using var messageFactory = new TestMessageFactory(allocator);

                var config = new ConnectionConfig();
                config.numChannels = 1;
                config.channel[0].type = ChannelType.CHANNEL_TYPE_UNRELIABLE_UNORDERED;

                {
                    using var connection = new Connection(allocator, messageFactory, config, 100.0);

                    for (var i = 0; i < 4; ++i)
                    {
                        var message = messageFactory.CreateMessage((int)TestMessageType.TEST_MESSAGE);
                        check(message != null);
                        connection.SendMessage(0, message);
                    }

                    var packetData = new byte[4096];

                    allocator.Arm(0);     // fail the message-pointer array allocation in GetPacketData
                    connection.GeneratePacket(null, 0, packetData, packetData.Length, out var packetBytes);
                    allocator.Disarm();
                }
            }
            check(allocator.Outstanding == 0);   // popped messages released, nothing leaked
            allocator.Dispose();
        }

        static void test_connection_generate_packet_channel_data_alloc_failure()
        {
            // Regression: when AllocateChannelData failed, GeneratePacket returned without freeing the
            // per-channel packet data GetPacketData had already populated (acquired message references
            // and the allocated message-pointer array), leaking them. Arm the allocator so the message
            // array allocation succeeds but the subsequent channel-data allocation fails, and verify
            // nothing leaks.
            var allocator = new ArmableAllocator();
            {
                using var messageFactory = new TestMessageFactory(allocator);

                var config = new ConnectionConfig();
                config.numChannels = 1;
                config.channel[0].type = ChannelType.CHANNEL_TYPE_RELIABLE_ORDERED;

                {
                    using var connection = new Connection(allocator, messageFactory, config, 100.0);

                    var message = messageFactory.CreateMessage((int)TestMessageType.TEST_MESSAGE);
                    check(message != null);
                    connection.SendMessage(0, message);

                    var packetData = new byte[4096];

                    allocator.Arm(1);     // 1st alloc (message array) succeeds, 2nd (channel data) fails
                    var result = connection.GeneratePacket(null, 0, packetData, packetData.Length, out var packetBytes);
                    allocator.Disarm();
                    check(!result);       // the channel-data allocation failure fails the generate
                }
            }
            check(allocator.Outstanding == 0);   // no leak across teardown
            allocator.Dispose();
        }

        static void test_message_factory_create_message_alloc_failure()
        {
            // Regression: YOJIMBO_NEW used to run the constructor on a null pointer when the allocation
            // failed (undefined behavior / crash) before CreateMessage's null check. CreateMessage must
            // return null cleanly on allocator exhaustion and flag the factory.
            var allocator = new ArmableAllocator();
            {
                using var factory = new TestMessageFactory(allocator);
                allocator.Arm(0);     // fail the next allocation (the message object)
                var message = factory.CreateMessage((int)TestMessageType.TEST_MESSAGE);
                allocator.Disarm();
                check(message == null);
                check(factory.ErrorLevel == MessageFactoryErrorLevel.MESSAGE_FACTORY_ERROR_FAILED_TO_ALLOCATE_MESSAGE);
            }
            check(allocator.Outstanding == 0);
            allocator.Dispose();
        }

        static void test_connection_process_packet_channel_data_alloc_failure()
        {
            // Regression: on the read path, if AllocateChannelData failed, numChannelEntries had already
            // been read from the wire, so the ConnectionPacket destructor iterated a null channelEntry
            // array (crash). Feed a valid packet to a receiver whose allocator fails the channel-data
            // allocation, and verify the read fails cleanly without crashing or leaking.
            var senderAlloc = new ArmableAllocator();
            var receiverAlloc = new ArmableAllocator();
            {
                using var senderFactory = new TestMessageFactory(senderAlloc);
                using var receiverFactory = new TestMessageFactory(receiverAlloc);

                var config = new ConnectionConfig();
                config.numChannels = 1;
                config.channel[0].type = ChannelType.CHANNEL_TYPE_RELIABLE_ORDERED;

                {
                    using var sender = new Connection(senderAlloc, senderFactory, config, 100.0);
                    using var receiver = new Connection(receiverAlloc, receiverFactory, config, 100.0);

                    var message = senderFactory.CreateMessage((int)TestMessageType.TEST_MESSAGE);
                    check(message != null);
                    sender.SendMessage(0, message);

                    var packetData = new byte[4096];
                    check(sender.GeneratePacket(null, 0, packetData, packetData.Length, out var packetBytes));
                    check(packetBytes > 0);

                    // C#: the first allocation in the read is the channel data (upstream allocates a padded copy of the packet first)
                    receiverAlloc.Arm(0);     // fail the channel-data allocation in the connection-packet read
                    var ok = receiver.ProcessPacket(null, 0, packetData, packetBytes);
                    receiverAlloc.Disarm();
                    check(!ok);               // read fails cleanly rather than crashing in the destructor
                }
            }
            check(senderAlloc.Outstanding == 0);
            check(receiverAlloc.Outstanding == 0);
            senderAlloc.Dispose();
            receiverAlloc.Dispose();
        }

        static void test_connection_message_refcounts()
        {
            // C# regression: ConnectionPacket was never disposed, so the references packets take on messages
            // (C++: released by ~ConnectionPacket) were never released. Every sent message must end at refcount
            // zero once acked (reliable) or written (unreliable), and every received message once released.

            var messageFactory = new TestMessageFactory(GetDefaultAllocator());

            var time = 100.0;

            var connectionConfig = new ConnectionConfig();
            connectionConfig.numChannels = 2;
            connectionConfig.channel[0].type = ChannelType.CHANNEL_TYPE_RELIABLE_ORDERED;
            connectionConfig.channel[1].type = ChannelType.CHANNEL_TYPE_UNRELIABLE_UNORDERED;

            var sender = new Connection(GetDefaultAllocator(), messageFactory, connectionConfig, time);
            var receiver = new Connection(GetDefaultAllocator(), messageFactory, connectionConfig, time);

            const int NumMessages = 32;

            var sent = new System.Collections.Generic.List<Message>();

            for (var i = 0; i < NumMessages; ++i)
            {
                Message message;
                if (i == NumMessages / 2)
                {
                    var blockMessage = (TestBlockMessage)messageFactory.CreateMessage((int)TestMessageType.TEST_BLOCK_MESSAGE);
                    var blockData = YOJIMBO_ALLOCATE(messageFactory.Allocator, 3000);
                    blockMessage.AttachBlock(messageFactory.Allocator, blockData, blockData.Length);
                    message = blockMessage;
                }
                else
                    message = messageFactory.CreateMessage((int)TestMessageType.TEST_MESSAGE);
                check(message != null);
                if (message is TestMessage tm) tm.sequence = (ushort)i; else ((TestBlockMessage)message).sequence = (ushort)i;
                sent.Add(message);
                sender.SendMessage(0, message);

                var unreliable = (TestMessage)messageFactory.CreateMessage((int)TestMessageType.TEST_MESSAGE);
                unreliable.sequence = (ushort)i;
                sent.Add(unreliable);
                sender.SendMessage(1, unreliable);
            }

            var received = new System.Collections.Generic.List<Message>();
            var numReliableReceived = 0;
            ushort senderSequence = 0;
            ushort receiverSequence = 0;

            for (var i = 0; i < 1000; ++i)
            {
                PumpConnectionUpdate(connectionConfig, ref time, sender, receiver, ref senderSequence, ref receiverSequence, 0.1f, 0);

                for (var channelIndex = 0; channelIndex < 2; ++channelIndex)
                {
                    while (true)
                    {
                        var message = receiver.ReceiveMessage(channelIndex);
                        if (message == null)
                            break;
                        check(message.RefCount == 1);         // the caller owns the only reference
                        received.Add(message);
                        if (channelIndex == 0)
                            numReliableReceived++;
                        messageFactory.ReleaseMessage(ref message);
                        check(message == null);
                    }
                }

                if (numReliableReceived == NumMessages && !sender.HasMessagesToSend(0) && !sender.HasMessagesToSend(1))
                    break;
            }

            check(numReliableReceived == NumMessages);
            check(received.Count == NumMessages * 2);

            foreach (var message in sent)
                check(message.RefCount == 0);
            foreach (var message in received)
                check(message.RefCount == 0);

            sender.Dispose();
            receiver.Dispose();
            messageFactory.Dispose();             // fails through the assert handler on any leaked message (debug)
        }

        static void test_connection_truncated_and_garbage_packets()
        {
            // Every serialize_* failure must propagate. A truncated packet must be refused, never throw or be
            // partially applied, and random garbage must never crash the reader.

            using var messageFactory = new TestMessageFactory(GetDefaultAllocator());

            var time = 100.0;

            var connectionConfig = new ConnectionConfig();
            connectionConfig.numChannels = 3;     // not a power of two: out of range channel indices are encodable
            connectionConfig.channel[0].type = ChannelType.CHANNEL_TYPE_RELIABLE_ORDERED;
            connectionConfig.channel[1].type = ChannelType.CHANNEL_TYPE_UNRELIABLE_UNORDERED;
            connectionConfig.channel[2].type = ChannelType.CHANNEL_TYPE_RELIABLE_ORDERED;

            var sender = new Connection(GetDefaultAllocator(), messageFactory, connectionConfig, time);

            for (var i = 0; i < 16; ++i)
            {
                var message = (TestMessage)messageFactory.CreateMessage((int)TestMessageType.TEST_MESSAGE);
                message.sequence = (ushort)i;
                sender.SendMessage(i % 3, message);
            }

            var packetData = new byte[connectionConfig.maxPacketSize];
            check(sender.GeneratePacket(null, 0, packetData, connectionConfig.maxPacketSize, out var packetBytes));
            check(packetBytes > 0);

            {
                var receiver = new Connection(GetDefaultAllocator(), messageFactory, connectionConfig, time);
                check(receiver.ProcessPacket(null, 0, packetData, packetBytes));
                receiver.Dispose();
            }

            for (var truncated = 1; truncated < packetBytes; ++truncated)
            {
                var receiver = new Connection(GetDefaultAllocator(), messageFactory, connectionConfig, time);
                var copy = new byte[truncated];
                Buffer.BlockCopy(packetData, 0, copy, 0, truncated);
                // either the packet framing fails (READ_PACKET_FAILED) or a message body fails, which puts the channel
                // into CHANNEL_ERROR_FAILED_TO_SERIALIZE; either way nothing is accepted
                check(!receiver.ProcessPacket(null, 0, copy, truncated));
                receiver.AdvanceTime(time);
                check(receiver.ErrorLevel != ConnectionErrorLevel.CONNECTION_ERROR_NONE);
                receiver.Dispose();
            }

            var garbage = new byte[256];
            for (var i = 0; i < 2000; ++i)
            {
                var receiver = new Connection(GetDefaultAllocator(), messageFactory, connectionConfig, time);
                var bytes = 1 + random_int(0, garbage.Length - 1);
                for (var j = 0; j < bytes; ++j)
                    garbage[j] = (byte)random_int(0, 255);
                receiver.ProcessPacket(null, (ushort)i, garbage, bytes);
                receiver.AdvanceTime(time);
                receiver.Dispose();
            }

            sender.Dispose();
        }

        class AssertException : Exception
        {
            public AssertException(string condition) : base(condition) { }
        }

        static void test_connection_message_too_large()
        {
            // 16feb21: a message that can never fit into a packet is rejected with CHANNEL_ERROR_MESSAGE_TOO_LARGE
            // instead of blocking the head of the reliable send queue forever (#185). It also asserts in debug.

            using var messageFactory = new TestMessageFactory(GetDefaultAllocator());

            var time = 100.0;

            var connectionConfig = new ConnectionConfig();
            connectionConfig.numChannels = 2;
            connectionConfig.channel[0].type = ChannelType.CHANNEL_TYPE_RELIABLE_ORDERED;
            connectionConfig.channel[0].packetBudget = 8;           // 64 bits: TestMessage 1 (sequence 1) is 16 + 320 bits
            connectionConfig.channel[1].type = ChannelType.CHANNEL_TYPE_UNRELIABLE_UNORDERED;
            connectionConfig.channel[1].packetBudget = 8;

            var previous = assert_function;
            var asserted = 0;
            assert_function = (condition, function, file, line) => { asserted++; throw new AssertException(condition); };
            try
            {
                using var connection = new Connection(GetDefaultAllocator(), messageFactory, connectionConfig, time);

                // reliable: rejected in SendMessage
                {
                    var message = (TestMessage)messageFactory.CreateMessage((int)TestMessageType.TEST_MESSAGE);
                    message.sequence = 1;
                    // the assert throws before the channel releases the message, so release it here
                    try { connection.SendMessage(0, message); } catch (AssertException) { messageFactory.ReleaseMessage(message); }
                }

                // unreliable: rejected when the packet is generated
                {
                    var message = (TestMessage)messageFactory.CreateMessage((int)TestMessageType.TEST_MESSAGE);
                    message.sequence = 1;
                    connection.SendMessage(1, message);
                    var packetData = new byte[connectionConfig.maxPacketSize];
                    try { connection.GeneratePacket(null, 0, packetData, connectionConfig.maxPacketSize, out var packetBytes); } catch (AssertException) { messageFactory.ReleaseMessage(message); }
                }

#if DEBUG
                check(asserted == 2);
#else
                check(connection.GetChannelErrorLevel(0) == ChannelErrorLevel.CHANNEL_ERROR_MESSAGE_TOO_LARGE);
                check(connection.GetChannelErrorLevel(1) == ChannelErrorLevel.CHANNEL_ERROR_MESSAGE_TOO_LARGE);
#endif
            }
            finally
            {
                assert_function = previous;
            }
        }

        static void test_reliable_outbound_sequence_outdated()
        {
            // b42ece5 (#138/#156): after more than half the 16 bit packet sequence space passes with no reliable
            // traffic, the next outgoing packet must still be recorded for acks (SequenceBuffer.Insert guaranteed_order).
            const ulong clientId = 1UL;

            var clientAddress = new Address("0.0.0.0", shared.ClientPort);
            var serverAddress = new Address("127.0.0.1", shared.ServerPort);

            var time = 100.0;
            var deltaTime = 1.0f / 60.0f;

            var config = new ClientServerConfig();
            config.numChannels = 2;
            config.timeout = -1;

            assert(config.numChannels <= MaxChannels);

            var BlockSize = config.channel[0].blockFragmentSize * 2;

            var client = new Client(GetDefaultAllocator(), clientAddress, config, shared.adapter, time);

            var privateKey = new byte[KeyBytes];

            var server = new Server(GetDefaultAllocator(), privateKey, serverAddress, config, shared.adapter, time);

            server.Start(MaxClients);

            client.InsecureConnect(privateKey, clientId, serverAddress);

            Client[] clients = { client };
            Server[] servers = { server };

            const int NumIterations = 50000;

            for (var i = 0; i < NumIterations; ++i)
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

            var numMessagesSent = 0;

            var clientMessage = (TestMessage)client.CreateMessage((int)TestMessageType.TEST_MESSAGE);
            check(clientMessage != null);
            client.SendMessage(0, clientMessage);
            ++numMessagesSent;

            var clientBlockMessage = (TestBlockMessage)client.CreateMessage((int)TestMessageType.TEST_BLOCK_MESSAGE);
            check(clientBlockMessage != null);
            var clientBlockData = client.AllocateBlock(BlockSize);
            client.AttachBlockToMessage(clientBlockMessage, clientBlockData, BlockSize);
            client.SendMessage(1, clientBlockMessage);
            ++numMessagesSent;

            // Simulate packet sequence being incremented by unreliable messages until it appears outdated.
            for (var i = 0; i < 32000; ++i)
                client.SendPackets();
            PumpClientServerUpdate(ref time, clients, 1, servers, 1, deltaTime);
            for (var j = 0; j < 768; ++j)
                client.SendPackets();

            var clientMessage2 = (TestMessage)client.CreateMessage((int)TestMessageType.TEST_MESSAGE);
            check(clientMessage2 != null);
            client.SendMessage(0, clientMessage2);
            ++numMessagesSent;

            var clientBlockMessage2 = (TestBlockMessage)client.CreateMessage((int)TestMessageType.TEST_BLOCK_MESSAGE);
            check(clientBlockMessage2 != null);
            var clientBlockData2 = client.AllocateBlock(BlockSize);
            client.AttachBlockToMessage(clientBlockMessage2, clientBlockData2, BlockSize);
            client.SendMessage(1, clientBlockMessage2);
            ++numMessagesSent;

            var numMessagesReceived = 0;

            for (var i = 0; i < NumIterations; ++i)
            {
                if (!client.IsConnected)
                    break;

                PumpClientServerUpdate(ref time, clients, 1, servers, 1, deltaTime);

                for (var channelIndex = 0; channelIndex < config.numChannels; ++channelIndex)
                {
                    var messageFromClient = server.ReceiveMessage(0, channelIndex);
                    if (messageFromClient != null)
                    {
                        server.ReleaseMessage(0, ref messageFromClient);
                        ++numMessagesReceived;
                    }
                }

                if (numMessagesReceived == numMessagesSent)
                    break;
            }

            check(client.IsConnected);
            check(server.IsClientConnected(client.ClientIndex));
            check(numMessagesReceived == numMessagesSent);

            client.Disconnect();

            for (var i = 0; i < NumIterations; ++i)
            {
                PumpClientServerUpdate(ref time, clients, 1, servers, 1);

                if (!client.IsConnected && server.NumConnectedClients == 0)
                    break;
            }

            check(!client.IsConnected && server.NumConnectedClients == 0);

            server.Stop();
        }

        static void test_client_server_messages_network_sim_leak()
        {
            // c78f4e4 / 760ebc2: 2000 unreliable messages through the network simulator at 500ms latency, 5% loss
            // and 5% duplicates. In C# this is a smoke test of the simulator (duplicate path, ring wrap) under load.
            const ulong clientId = 1UL;

            var clientAddress = new Address("0.0.0.0", shared.ClientPort);
            var serverAddress = new Address("127.0.0.1", shared.ServerPort);

            var time = 100.0;

            var config = new ClientServerConfig();
            config.networkSimulator = true;
            config.channel[0].type = ChannelType.CHANNEL_TYPE_UNRELIABLE_UNORDERED;

            var client = new Client(GetDefaultAllocator(), clientAddress, config, shared.adapter, time);

            var privateKey = new byte[KeyBytes];

            var server = new Server(GetDefaultAllocator(), privateKey, serverAddress, config, shared.adapter, time);

            server.Start(MaxClients);

            server.SetLatency(500);
            server.SetJitter(100);
            server.SetPacketLoss(5);
            server.SetDuplicates(5);

            Client[] clients = { client };
            Server[] servers = { server };

            for (var iteration = 0; iteration < 2; ++iteration)
            {
                client.InsecureConnect(privateKey, clientId, serverAddress);

                client.SetLatency(500);
                client.SetJitter(100);
                client.SetPacketLoss(5);
                client.SetDuplicates(5);

                const int NumIterations = 10000;

                for (var i = 0; i < NumIterations; ++i)
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

                const int NumMessagesSent = 2000;

                for (var i = 0; i < NumMessagesSent; ++i)
                {
                    if (!client.CanSendMessage(0))
                        break;
                    var message = (TestMessage)client.CreateMessage((int)TestMessageType.TEST_MESSAGE);
                    check(message != null);
                    message.sequence = (ushort)i;
                    client.SendMessage(0, message);
                }

                for (var i = 0; i < NumMessagesSent; ++i)
                {
                    if (!server.CanSendMessage(client.ClientIndex, 0))
                        break;
                    var message = (TestMessage)server.CreateMessage(client.ClientIndex, (int)TestMessageType.TEST_MESSAGE);
                    check(message != null);
                    message.sequence = (ushort)i;
                    server.SendMessage(client.ClientIndex, 0, message);
                }

                var numMessagesReceivedFromClient = 0;
                var numMessagesReceivedFromServer = 0;

                for (var i = 0; i < 100; ++i)
                {
                    if (!client.IsConnected)
                        break;

                    PumpClientServerUpdate(ref time, clients, 1, servers, 1);

                    while (true)
                    {
                        var message = client.ReceiveMessage(0);
                        if (message == null)
                            break;
                        if (message.Type == (int)TestMessageType.TEST_MESSAGE)
                            ++numMessagesReceivedFromServer;
                        client.ReleaseMessage(ref message);
                    }

                    while (true)
                    {
                        var message = server.ReceiveMessage(client.ClientIndex, 0);
                        if (message == null)
                            break;
                        if (message.Type == (int)TestMessageType.TEST_MESSAGE)
                        {
                            check(!message.IsBlockMessage);
                            ++numMessagesReceivedFromClient;
                        }
                        server.ReleaseMessage(client.ClientIndex, ref message);
                    }
                }

                check(client.IsConnected);
                check(server.IsClientConnected(client.ClientIndex));

                client.Disconnect();

                for (var i = 0; i < NumIterations; ++i)
                {
                    PumpClientServerUpdate(ref time, clients, 1, servers, 1);

                    if (!client.IsConnected && server.NumConnectedClients == 0)
                        break;
                }

                check(!client.IsConnected && server.NumConnectedClients == 0);
            }

            server.Stop();
        }

        // ---------------------------------------------------------------------------------------------
        // config, transactional startup, disconnect reasons

        static void test_channel_config_fragment_counts_without_overflow()
        {
            // yojimbo#347: ceil(maxBlockSize / blockFragmentSize) used to add in int and overflow for a legal huge
            // maxBlockSize. The add is 64-bit; a too-large result stays well-defined and still fails Validate's cap.
            var channel = new ChannelConfig();
            channel.maxBlockSize = 2147483647;
            channel.blockFragmentSize = 1024;
            var n = channel.GetMaxFragmentsPerBlock();
            check(n == (int)((2147483647L + 1023) / 1024));
            check(n > 65535);

            // yojimbo#346: fragmentSize on the wire is 16 bits.
            var small = new ChannelConfig();
            small.maxBlockSize = 256 * 1024;
            small.blockFragmentSize = 1024;
            check(small.GetMaxFragmentsPerBlock() == 256);
            check(small.blockFragmentSize <= 65535);

            // 760ebc2: rounds up
            var odd = new ChannelConfig();
            odd.maxBlockSize = 1100;
            odd.blockFragmentSize = 500;
            check(odd.MaxFragmentsPerBlock == 3);

            // no divide by zero
            var zero = new ChannelConfig();
            zero.blockFragmentSize = 0;
            check(zero.GetMaxFragmentsPerBlock() == 0);

            // the library keeps private copies of configs, like the C++ by-value members
            var config = new ClientServerConfig();
            var copy = config.Clone();
            copy.channel[0].maxBlockSize = 5;
            check(config.channel[0].maxBlockSize == 256 * 1024);
            check(new ConnectionConfig().numChannels == 2);
            check(config.timeout == DEFAULT_TIMEOUT && DEFAULT_TIMEOUT == 10);
        }

        static void test_interface_methods_link()
        {
            // YJ-02: every interface method is reachable through the base reference.
            var config = new ClientServerConfig();
            var privateKey = new byte[KeyBytes];

            var server = new Server(GetDefaultAllocator(), privateKey, new Address("127.0.0.1", shared.ServerPort), config, shared.adapter, 100.0);
            var client = new Client(GetDefaultAllocator(), new Address("0.0.0.0", 0), config, shared.adapter, 100.0);

            check(server.Start(1));
            IServer serverInterface = server;
            check(serverInterface.GetClientUserData(0) == server.GetClientUserData(0));
            check(serverInterface.GetClientAddress(0) == server.GetClientAddress(0));
            check(serverInterface.MaxClients == 1);
            server.Stop();

            IClient clientInterface = client;
            check(clientInterface.ClientState == client.ClientState);

            client.Dispose();
            server.Dispose();
        }

        // Adapter whose factory methods can be made to fail, so the transactional startup paths are exercised (f7cb323).
        class FailingFactoryAdapter : TestAdapter
        {
            int m_allocatorsUntilFail = -1;
            int m_factoriesUntilFail = -1;

            public void FailAllocatorAfter(int n) => m_allocatorsUntilFail = n;
            public void FailMessageFactoryAfter(int n) => m_factoriesUntilFail = n;

            public override Allocator CreateAllocator(Allocator allocator, object memory, int bytes)
            {
                if (m_allocatorsUntilFail == 0)
                    return null;
                if (m_allocatorsUntilFail > 0)
                    m_allocatorsUntilFail--;
                return base.CreateAllocator(allocator, memory, bytes);
            }

            public override MessageFactory CreateMessageFactory(Allocator allocator)
            {
                if (m_factoriesUntilFail == 0)
                    return null;
                if (m_factoriesUntilFail > 0)
                    m_factoriesUntilFail--;
                return base.CreateMessageFactory(allocator);
            }
        }

        // The number of startup allocations a sweep is allowed to walk before we call it a runaway. Well
        // above the real counts (6 for a two-client server, 3 for a client) so the sweep terminates on a
        // bug instead of looping forever.
        const int MaxStartupAllocations = 64;

        static void test_server_start_alloc_failure()
        {
            // YJ-01: BaseServer::Start guarded its allocations with yojimbo_assert, which compiles out
            // under NDEBUG, so a release build bound references to failed allocations and ran on with a
            // half-built server. Fail at allocation N for every N up to the first N that succeeds: each
            // failure must return false, leave the server stopped, and free everything already taken.
            var serverAddress = new Address("127.0.0.1", shared.ServerPort);

            var config = new ClientServerConfig();

            var privateKey = new byte[KeyBytes];

            var n = 0;
            for (; n < MaxStartupAllocations; ++n)
            {
                var allocator = new ArmableAllocator();
                {
                    var server = new Server(allocator, privateKey, serverAddress, config, shared.adapter, 100.0);
                    allocator.Arm(n);
                    var started = server.Start(2);
                    allocator.Disarm();
                    if (started)
                    {
                        check(server.IsRunning);
                        server.Stop();
                        check(!server.IsRunning);
                        server.Dispose();
                        check(allocator.Outstanding == 0);
                        allocator.Dispose();
                        break;
                    }
                    check(!server.IsRunning);           // no half-built server left behind
                    check(server.MaxClients == 0);
                    server.Dispose();
                }
                check(allocator.Outstanding == 0);   // everything already allocated was unwound
                allocator.Dispose();
            }
            check(n > 0);                                 // the sweep really did force failures
            check(n < MaxStartupAllocations);             // ...and a fully armed start eventually succeeds
        }

        static void test_server_start_factory_failure()
        {
            // Same contract for the adapter factory results, which no allocator arming can reach: a user
            // allocator or message factory that fails to construct returns null and must be handled like
            // an allocation failure rather than dereferenced.
            var serverAddress = new Address("127.0.0.1", shared.ServerPort);
            var config = new ClientServerConfig();
            var privateKey = new byte[KeyBytes];

            // allocator index 0 is the global allocator, 1 and 2 are the two per-client allocators
            for (var n = 0; n < 3; ++n)
            {
                var allocator = new ArmableAllocator();
                {
                    var failingAdapter = new FailingFactoryAdapter();
                    failingAdapter.FailAllocatorAfter(n);
                    var server = new Server(allocator, privateKey, serverAddress, config, failingAdapter, 100.0);
                    check(!server.Start(2));
                    check(!server.IsRunning);
                    server.Dispose();
                }
                check(allocator.Outstanding == 0);
                allocator.Dispose();
            }

            for (var n = 0; n < 2; ++n)
            {
                var allocator = new ArmableAllocator();
                {
                    var failingAdapter = new FailingFactoryAdapter();
                    failingAdapter.FailMessageFactoryAfter(n);
                    var server = new Server(allocator, privateKey, serverAddress, config, failingAdapter, 100.0);
                    check(!server.Start(2));
                    check(!server.IsRunning);
                    server.Dispose();
                }
                check(allocator.Outstanding == 0);
                allocator.Dispose();
            }

            // and a server that failed to start can still start
            {
                var server = new Server(GetDefaultAllocator(), privateKey, serverAddress, config, shared.adapter, 100.0);
                check(server.Start(2));
                check(server.IsRunning);
                server.Stop();
                server.Dispose();
            }
        }

        static void test_client_connect_alloc_failure()
        {
            // YJ-01 on the client side: BaseClient::CreateInternal bound a reference to *m_clientAllocator
            // one line after allocating it, with no check in any build. Same sweep: every failure point
            // returns false, leaves the client disconnected with an out-of-memory reason, and leaks
            // nothing.
            var clientAddress = new Address("0.0.0.0", 0);
            var serverAddress = new Address("127.0.0.1", shared.ServerPort);

            var config = new ClientServerConfig();

            var privateKey = new byte[KeyBytes];

            var n = 0;
            for (; n < MaxStartupAllocations; ++n)
            {
                var allocator = new ArmableAllocator();
                {
                    var client = new Client(allocator, clientAddress, config, shared.adapter, 100.0);
                    allocator.Arm(n);
                    var connecting = client.InsecureConnect(privateKey, 1, serverAddress);
                    allocator.Disarm();
                    if (connecting)
                    {
                        check(client.IsConnecting);
                        client.Disconnect();
                        client.Dispose();
                        check(allocator.Outstanding == 0);
                        allocator.Dispose();
                        break;
                    }
                    check(!client.IsConnecting);
                    check(!client.IsConnected);
                    check(client.ConnectionFailed);
                    check(client.GetDisconnectReason() == ClientDisconnectReason.YOJIMBO_CLIENT_DISCONNECT_REASON_OUT_OF_MEMORY);
                    client.Dispose();
                }
                check(allocator.Outstanding == 0);
                allocator.Dispose();
            }
            check(n > 0);
            check(n < MaxStartupAllocations);
        }

        static void test_client_connect_factory_failure()
        {
            var clientAddress = new Address("0.0.0.0", 0);
            var serverAddress = new Address("127.0.0.1", shared.ServerPort);
            var config = new ClientServerConfig();
            var privateKey = new byte[KeyBytes];

            {
                var allocator = new ArmableAllocator();
                {
                    var failingAdapter = new FailingFactoryAdapter();
                    failingAdapter.FailAllocatorAfter(0);
                    var client = new Client(allocator, clientAddress, config, failingAdapter, 100.0);
                    check(!client.InsecureConnect(privateKey, 1, serverAddress));
                    check(client.ConnectionFailed);
                    check(client.GetDisconnectReason() == ClientDisconnectReason.YOJIMBO_CLIENT_DISCONNECT_REASON_OUT_OF_MEMORY);
                    client.Dispose();
                }
                check(allocator.Outstanding == 0);
                allocator.Dispose();
            }

            {
                var allocator = new ArmableAllocator();
                {
                    var failingAdapter = new FailingFactoryAdapter();
                    failingAdapter.FailMessageFactoryAfter(0);
                    var client = new Client(allocator, clientAddress, config, failingAdapter, 100.0);
                    check(!client.InsecureConnect(privateKey, 1, serverAddress));
                    check(client.ConnectionFailed);
                    client.Dispose();
                }
                check(allocator.Outstanding == 0);
                allocator.Dispose();
            }
        }

        static void test_client_connect_socket_failure_no_crash()
        {
            // Regression (9c4de3d): Connect and ConnectLoopback called into netcode without checking that CreateClient succeeded.
            var config = new ClientServerConfig();

            var invalidAddress = new Address();             // ADDRESS_NONE -> "NONE" -> client_create fails
            check(!invalidAddress.IsValid);

            var client = new Client(GetDefaultAllocator(), invalidAddress, config, shared.adapter, 100.0);

            var connectToken = new byte[ConnectTokenBytes];

            check(!client.Connect(1, connectToken));        // must not crash - CreateClient failed
            check(!client.IsConnected);

            check(!client.ConnectLoopback(0, 1, 1));        // must not crash either
            check(!client.IsConnected);

            client.Disconnect();
            client.Dispose();
        }

        static void test_client_is_loopback_when_disconnected()
        {
            // Regression (997109d): IsLoopback must be safe to query in any state.
            var config = new ClientServerConfig();
            var client = new Client(GetDefaultAllocator(), new Address("0.0.0.0", shared.ClientPort), config, shared.adapter, 100.0);

            check(!client.IsLoopback);
            check(client.ClientIndex == -1);
            check(!client.IsConnected);
            client.Dispose();
        }

        static bool ConnectClient(ref double time, Client client, Server server, int NumIterations = 10000)
        {
            Client[] clients = { client };
            Server[] servers = { server };
            for (var i = 0; i < NumIterations; ++i)
            {
                PumpClientServerUpdate(ref time, clients, 1, servers, 1);
                if (client.ConnectionFailed)
                    break;
                if (!client.IsConnecting && client.IsConnected && server.NumConnectedClients == 1)
                    break;
            }
            return client.IsConnected;
        }

        static void test_client_connect_twice_with_one_connect_token()
        {
            // A connect token is spent by the connection it admits (netcode 1.4.5, GHSA-v29p-3vj4-vg4f).
            const ulong clientId = 1UL;

            var clientAddress = new Address("0.0.0.0", shared.ClientPort);
            var serverAddress = new Address("127.0.0.1", shared.ServerPort);

            var time = 100.0;

            var config = new ClientServerConfig();
            config.timeout = 2;

            var privateKey = new byte[KeyBytes];

            var server = new Server(GetDefaultAllocator(), privateKey, serverAddress, config, shared.adapter, time);

            check(server.Start(MaxClients));

            string[] serverAddressStrings = { serverAddress.ToString() };
            var userData = new byte[256];
            var connectToken = new byte[ConnectTokenBytes];
            check(netcode.generate_connect_token(1, serverAddressStrings, serverAddressStrings, InsecureConnectTokenExpirySeconds, config.timeout, clientId, config.protocolId, privateKey, userData, connectToken) == netcode.OK);

            const int NumIterations = 1000;

            var client = new Client(GetDefaultAllocator(), clientAddress, config, shared.adapter, time);
            Client[] clients = { client };
            Server[] servers = { server };

            // First use of the token connects.

            check(client.Connect(clientId, connectToken));
            check(ConnectClient(ref time, client, server, NumIterations));
            check(server.NumConnectedClients == 1);
            check(client.ClientIndex == 0);

            server.DisconnectClient(0);

            for (var i = 0; i < NumIterations; ++i)
            {
                PumpClientServerUpdate(ref time, clients, 1, servers, 1);
                if (!client.IsConnected && server.NumConnectedClients == 0)
                    break;
            }

            check(!client.IsConnected);
            check(server.NumConnectedClients == 0);

            // Second use of the same token connects nothing.

            check(client.Connect(clientId, connectToken));

            for (var i = 0; i < NumIterations; ++i)
            {
                PumpClientServerUpdate(ref time, clients, 1, servers, 1);
                if (client.ConnectionFailed)
                    break;
                check(!client.IsConnected);
                check(server.NumConnectedClients == 0);
            }

            check(client.ConnectionFailed);
            check(!client.IsConnected);
            check(server.NumConnectedClients == 0);
            check(client.GetDisconnectReason() == ClientDisconnectReason.YOJIMBO_CLIENT_DISCONNECT_REASON_CONNECTION_REQUEST_TIMED_OUT);

            client.Disconnect();
            server.Stop();
            client.Dispose();
            server.Dispose();
        }

        static void test_server_client_disconnect_reason()
        {
            const ulong clientId = 1UL;

            var clientAddress = new Address("0.0.0.0", shared.ClientPort);
            var serverAddress = new Address("127.0.0.1", shared.ServerPort);

            var time = 100.0;

            var config = new ClientServerConfig();
            var privateKey = new byte[KeyBytes];

            var server = new Server(GetDefaultAllocator(), privateKey, serverAddress, config, shared.adapter, time);

            server.Start(MaxClients);

            // all client slots are cleared to none at server start

            for (var i = 0; i < MaxClients; ++i)
                check(server.GetClientDisconnectReason(i) == ServerClientDisconnectReason.YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_NONE);

            var client = new Client(GetDefaultAllocator(), clientAddress, config, shared.adapter, time);
            Client[] clients = { client };
            Server[] servers = { server };

            const int NumIterations = 10000;

            // connect a client. while it is connected the reason stays none

            client.InsecureConnect(privateKey, clientId, serverAddress);
            check(ConnectClient(ref time, client, server));
            check(server.IsClientConnected(0));
            check(server.GetClientDisconnectReason(0) == ServerClientDisconnectReason.YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_NONE);

            // kick the client. the reason is recorded immediately, before the adapter callback fires

            server.DisconnectClient(0);

            check(server.GetClientDisconnectReason(0) == ServerClientDisconnectReason.YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_KICKED);

            for (var i = 0; i < NumIterations; ++i)
            {
                PumpClientServerUpdate(ref time, clients, 1, servers, 1);
                if (!client.IsConnected)
                    break;
            }

            check(!client.IsConnected);
            check(server.GetClientDisconnectReason(0) == ServerClientDisconnectReason.YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_KICKED);

            // reconnect. a new client connecting to the slot clears the reason back to none

            client.InsecureConnect(privateKey, clientId, serverAddress);
            check(ConnectClient(ref time, client, server));
            check(server.IsClientConnected(0));
            check(server.GetClientDisconnectReason(0) == ServerClientDisconnectReason.YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_NONE);

            // clean client-side disconnect is recorded as disconnected, distinct from a timeout

            client.Disconnect();

            for (var i = 0; i < NumIterations; ++i)
            {
                PumpClientServerUpdate(ref time, clients, 1, servers, 1);
                if (server.NumConnectedClients == 0)
                    break;
            }

            check(server.NumConnectedClients == 0);
            check(server.GetClientDisconnectReason(0) == ServerClientDisconnectReason.YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_DISCONNECTED);

            // reconnect, then let the client go silent. the server times it out

            client.InsecureConnect(privateKey, clientId, serverAddress);
            check(ConnectClient(ref time, client, server));
            check(server.GetClientDisconnectReason(0) == ServerClientDisconnectReason.YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_NONE);

            for (var i = 0; i < NumIterations; ++i)
            {
                PumpClientServerUpdate(ref time, null, 0, servers, 1);
                if (server.NumConnectedClients == 0)
                    break;
            }

            check(server.NumConnectedClients == 0);
            check(server.GetClientDisconnectReason(0) == ServerClientDisconnectReason.YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_TIMED_OUT);

            client.Disconnect();

            // restarting the server clears all slots back to none

            server.Stop();

            server.Start(MaxClients);

            for (var i = 0; i < MaxClients; ++i)
                check(server.GetClientDisconnectReason(i) == ServerClientDisconnectReason.YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_NONE);

            server.Stop();
            client.Dispose();
            server.Dispose();
        }

        static ClientServerConfig FailToSerializeConfig()
        {
            var config = new ClientServerConfig();
            config.maxPacketSize = 1100;
            config.numChannels = 1;
            config.channel[0].type = ChannelType.CHANNEL_TYPE_RELIABLE_ORDERED;
            config.channel[0].maxBlockSize = 1024;
            config.channel[0].blockFragmentSize = 200;
            return config;
        }

        static void test_server_client_disconnect_reason_failed_to_serialize()
        {
            const ulong clientId = 1UL;

            var clientAddress = new Address("0.0.0.0", shared.ClientPort);
            var serverAddress = new Address("127.0.0.1", shared.ServerPort);

            var time = 100.0;

            var config = FailToSerializeConfig();
            var privateKey = new byte[KeyBytes];

            var server = new Server(GetDefaultAllocator(), privateKey, serverAddress, config, shared.adapter, time);
            server.Start(MaxClients);

            var client = new Client(GetDefaultAllocator(), clientAddress, config, shared.adapter, time);
            client.InsecureConnect(privateKey, clientId, serverAddress);
            check(ConnectClient(ref time, client, server));
            check(server.NumConnectedClients == 1);

            // send a message that fails to serialize on read. the server disconnects the client
            // and records the specific channel error as the disconnect reason

            var message = client.CreateMessage((int)TestMessageType.TEST_SERIALIZE_FAIL_ON_READ_MESSAGE);
            check(message != null);
            client.SendMessage(0, message);

            Client[] clients = { client };
            Server[] servers = { server };

            for (var i = 0; i < 256; ++i)
            {
                PumpClientServerUpdate(ref time, clients, 1, servers, 1);
                if (!client.IsConnected && server.NumConnectedClients == 0)
                    break;
            }

            check(!client.IsConnected && server.NumConnectedClients == 0);
            check(server.GetClientDisconnectReason(0) == ServerClientDisconnectReason.YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_FAILED_TO_SERIALIZE);

            client.Disconnect();
            server.Stop();
            client.Dispose();
            server.Dispose();
        }

        static void test_client_disconnect_reason()
        {
            const ulong clientId = 1UL;

            var clientAddress = new Address("0.0.0.0", shared.ClientPort);
            var serverAddress = new Address("127.0.0.1", shared.ServerPort);

            var time = 100.0;

            var config = new ClientServerConfig();
            var privateKey = new byte[KeyBytes];

            var server = new Server(GetDefaultAllocator(), privateKey, serverAddress, config, shared.adapter, time);
            server.Start(MaxClients);

            var client = new Client(GetDefaultAllocator(), clientAddress, config, shared.adapter, time);
            Client[] clients = { client };
            Server[] servers = { server };

            // no disconnect has happened yet

            check(client.GetDisconnectReason() == ClientDisconnectReason.YOJIMBO_CLIENT_DISCONNECT_REASON_NONE);

            const int NumIterations = 10000;

            client.InsecureConnect(privateKey, clientId, serverAddress);
            check(ConnectClient(ref time, client, server));
            check(client.GetDisconnectReason() == ClientDisconnectReason.YOJIMBO_CLIENT_DISCONNECT_REASON_NONE);

            // deliberate local disconnect is recorded immediately

            client.Disconnect();

            check(client.GetDisconnectReason() == ClientDisconnectReason.YOJIMBO_CLIENT_DISCONNECT_REASON_DISCONNECTED);

            for (var i = 0; i < NumIterations; ++i)
            {
                PumpClientServerUpdate(ref time, clients, 1, servers, 1);
                if (server.NumConnectedClients == 0)
                    break;
            }

            check(server.NumConnectedClients == 0);

            // reconnect. a new connect attempt clears the reason back to none

            client.InsecureConnect(privateKey, clientId, serverAddress);

            check(client.GetDisconnectReason() == ClientDisconnectReason.YOJIMBO_CLIENT_DISCONNECT_REASON_NONE);

            check(ConnectClient(ref time, client, server));

            // when the server kicks us, the client records disconnected by server

            server.DisconnectClient(0);

            for (var i = 0; i < NumIterations; ++i)
            {
                PumpClientServerUpdate(ref time, clients, 1, servers, 1);
                if (!client.IsConnected)
                    break;
            }

            check(!client.IsConnected);
            check(client.GetDisconnectReason() == ClientDisconnectReason.YOJIMBO_CLIENT_DISCONNECT_REASON_DISCONNECTED_BY_SERVER);

            // connecting to a server that isn't there times out at the connection request stage (fd8091c)

            server.Stop();

            client.InsecureConnect(privateKey, clientId, serverAddress);

            check(client.GetDisconnectReason() == ClientDisconnectReason.YOJIMBO_CLIENT_DISCONNECT_REASON_NONE);

            for (var i = 0; i < NumIterations; ++i)
            {
                PumpClientServerUpdate(ref time, clients, 1, null, 0);
                if (client.ConnectionFailed)
                    break;
            }

            check(client.ConnectionFailed);
            check(client.GetDisconnectReason() == ClientDisconnectReason.YOJIMBO_CLIENT_DISCONNECT_REASON_CONNECTION_REQUEST_TIMED_OUT);
            check(GetClientDisconnectReasonString(client.GetDisconnectReason()) == "connection request timed out");

            client.Disconnect();
            client.Dispose();
            server.Dispose();
        }

        static void test_client_disconnect_reason_failed_to_serialize()
        {
            const ulong clientId = 1UL;

            var clientAddress = new Address("0.0.0.0", shared.ClientPort);
            var serverAddress = new Address("127.0.0.1", shared.ServerPort);

            var time = 100.0;

            var config = FailToSerializeConfig();
            var privateKey = new byte[KeyBytes];

            var server = new Server(GetDefaultAllocator(), privateKey, serverAddress, config, shared.adapter, time);
            server.Start(MaxClients);

            var client = new Client(GetDefaultAllocator(), clientAddress, config, shared.adapter, time);
            client.InsecureConnect(privateKey, clientId, serverAddress);
            check(ConnectClient(ref time, client, server));
            check(server.NumConnectedClients == 1);

            // send a message from the server that fails to serialize on read. the client disconnects
            // itself and records the specific channel error as its disconnect reason

            var message = server.CreateMessage(0, (int)TestMessageType.TEST_SERIALIZE_FAIL_ON_READ_MESSAGE);
            check(message != null);
            server.SendMessage(0, 0, message);

            Client[] clients = { client };
            Server[] servers = { server };

            for (var i = 0; i < 256; ++i)
            {
                PumpClientServerUpdate(ref time, clients, 1, servers, 1);
                if (!client.IsConnected)
                    break;
            }

            check(!client.IsConnected);
            check(client.GetDisconnectReason() == ClientDisconnectReason.YOJIMBO_CLIENT_DISCONNECT_REASON_FAILED_TO_SERIALIZE);

            client.Disconnect();
            server.Stop();
            client.Dispose();
            server.Dispose();
        }

        static void test_message_sends_across_reconnect()
        {
            // 06358cf: messages queued on a connection must not leak across a disconnect/reconnect. After the client
            // disconnects and reconnects, message ids start again from 0 on both sides.
            const ulong clientId = 1UL;

            var clientAddress = new Address("0.0.0.0", shared.ClientPort);
            var serverAddress = new Address("127.0.0.1", shared.ServerPort);

            var time = 100.0;

            var config = new ClientServerConfig();
            var privateKey = new byte[KeyBytes];

            var server = new Server(GetDefaultAllocator(), privateKey, serverAddress, config, shared.adapter, time);
            server.Start(MaxClients);

            var client = new Client(GetDefaultAllocator(), clientAddress, config, shared.adapter, time);
            Client[] clients = { client };
            Server[] servers = { server };

            for (var iteration = 0; iteration < 3; ++iteration)
            {
                client.InsecureConnect(privateKey, clientId, serverAddress);
                check(ConnectClient(ref time, client, server));

                // queue messages on the server for this client, then kick the client before they can all be delivered
                for (var i = 0; i < 8; ++i)
                {
                    var message = (TestMessage)server.CreateMessage(0, (int)TestMessageType.TEST_MESSAGE);
                    message.sequence = (ushort)i;
                    server.SendMessage(0, 0, message);
                }

                var numReceived = 0;
                for (var i = 0; i < 1000 && numReceived < 8; ++i)
                {
                    PumpClientServerUpdate(ref time, clients, 1, servers, 1);
                    while (true)
                    {
                        var message = client.ReceiveMessage(0);
                        if (message == null)
                            break;
                        check(message.Id == numReceived);           // ids restart from zero on each connection
                        check(((TestMessage)message).sequence == numReceived);
                        numReceived++;
                        client.ReleaseMessage(ref message);
                    }
                }
                check(numReceived == 8);

                // leave a message queued on each side, then disconnect
                var leftover = (TestMessage)server.CreateMessage(0, (int)TestMessageType.TEST_MESSAGE);
                server.SendMessage(0, 0, leftover);
                var leftover2 = (TestMessage)client.CreateMessage((int)TestMessageType.TEST_MESSAGE);
                client.SendMessage(0, leftover2);

                server.DisconnectClient(0);
                for (var i = 0; i < 1000; ++i)
                {
                    PumpClientServerUpdate(ref time, clients, 1, servers, 1);
                    if (!client.IsConnected && server.NumConnectedClients == 0)
                        break;
                }
                check(!client.IsConnected && server.NumConnectedClients == 0);
                check(!server.HasMessagesToSend(0, 0));      // the server connection was reset on disconnect
            }

            client.Disconnect();
            server.Stop();
            client.Dispose();
            server.Dispose();
        }

        static void test_network_info()
        {
            const ulong clientId = 1UL;

            var clientAddress = new Address("0.0.0.0", shared.ClientPort);
            var serverAddress = new Address("127.0.0.1", shared.ServerPort);

            var time = 100.0;

            var config = new ClientServerConfig();
            var privateKey = new byte[KeyBytes];

            var server = new Server(GetDefaultAllocator(), privateKey, serverAddress, config, shared.adapter, time);
            server.Start(MaxClients);

            var client = new Client(GetDefaultAllocator(), clientAddress, config, shared.adapter, time);
            client.InsecureConnect(privateKey, clientId, serverAddress);
            check(ConnectClient(ref time, client, server));

            Client[] clients = { client };
            Server[] servers = { server };
            for (var i = 0; i < 100; ++i)
                PumpClientServerUpdate(ref time, clients, 1, servers, 1);

            client.GetNetworkInfo(out var clientInfo);
            server.GetNetworkInfo(0, out var serverInfo);
            check(clientInfo.numPacketsSent > 0 && clientInfo.numPacketsAcked > 0);
            check(serverInfo.numPacketsSent > 0 && serverInfo.numPacketsAcked > 0);
            check(clientInfo.minRTT <= clientInfo.maxRTT);
            check(serverInfo.minRTT <= serverInfo.maxRTT);
            check(serverInfo.averageJitter >= 0 && serverInfo.maxJitter >= 0 && serverInfo.stddevJitter >= 0);

            check(server.GetClientUserData(0) != null && server.GetClientUserData(0).Length == 256);
            check(server.GetClientAddress(0) != null);

            client.Disconnect();
            server.Stop();
            client.Dispose();
            server.Dispose();
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
            // The tests are randomized (packet loss, ordering, ids). Seed rand() from the clock by
            // default, but let a seed be passed on the command line so a flaky failure can be
            // reproduced exactly: rerun `test <seed>` with the value printed below (94ef867).
            var seed = args.Length > 0 ? (int)Convert.ToUInt32(args[0], args[0].StartsWith("0x") ? 16 : 10) : (int)(uint)Environment.TickCount64;

            Console.Write($"test random seed {(uint)seed}\n");
            Console.Out.Flush();

            srand(seed);

            Console.Write("\n");

            //log_level(LOG_LEVEL_DEBUG);

#if SOAK
            Console.CancelKeyPress += interrupt_handler;

            var iter = 0;
            while (true)
#endif
            {
                {
                    Console.Write("[serialize]\n\n");

                    RUN_TEST("test_endian", test_endian);
                    RUN_TEST("test_bitpacker", test_bitpacker);
                    RUN_TEST("test_bits_required", test_bits_required);
                    RUN_TEST("test_stream", test_stream);
                    RUN_TEST("test_serialize_primitives", test_serialize_primitives);
                    RUN_TEST("test_serialize_failure_latch", test_serialize_failure_latch);
                }

                {
                    Console.Write("\n[netcode]\n\n");

                    check(InitializeYojimbo());

                    netcode.test();

                    ShutdownYojimbo();
                }

                {
                    Console.Write("\n[reliable]\n\n");

                    check(InitializeYojimbo());

                    reliable.test();

                    ShutdownYojimbo();
                }

                Console.Write("\n[yojimbo]\n\n");

                RUN_TEST("test_queue", test_queue);
                RUN_TEST("test_address_classification", test_address_classification);
                RUN_TEST("test_address_malformed_port", test_address_malformed_port);
                RUN_TEST("test_address", test_address);
                RUN_TEST("test_network_simulator_drains_all_slots", test_network_simulator_drains_all_slots);
                RUN_TEST("test_network_simulator_overwrite_slot", test_network_simulator_overwrite_slot);
                RUN_TEST("test_bit_array", test_bit_array);
                RUN_TEST("test_sequence_buffer", test_sequence_buffer);
                RUN_TEST("test_allocator_tlsf", test_allocator_tlsf);

                RUN_TEST("test_connection_reliable_ordered_messages", test_connection_reliable_ordered_messages);
                RUN_TEST("test_connection_reliable_ordered_blocks", test_connection_reliable_ordered_blocks);
                RUN_TEST("test_connection_reliable_ordered_blocks_max_size", test_connection_reliable_ordered_blocks_max_size);
                RUN_TEST("test_connection_reliable_ordered_messages_and_blocks", test_connection_reliable_ordered_messages_and_blocks);
                RUN_TEST("test_connection_reliable_ordered_messages_and_blocks_multiple_channels", test_connection_reliable_ordered_messages_and_blocks_multiple_channels);
                RUN_TEST("test_connection_unreliable_unordered_messages", test_connection_unreliable_unordered_messages);
                RUN_TEST("test_connection_unreliable_unordered_blocks", test_connection_unreliable_unordered_blocks);
                RUN_TEST("test_connection_reject_empty_packet", test_connection_reject_empty_packet);
                RUN_TEST("test_connection_process_packet_exact_allocation", test_connection_process_packet_exact_allocation);
                RUN_TEST("test_connection_unreliable_rejects_block_fragment", test_connection_unreliable_rejects_block_fragment);
                RUN_TEST("test_connection_reliable_block_fragment_on_disabled_blocks", test_connection_reliable_block_fragment_on_disabled_blocks);
                RUN_TEST("test_connection_reliable_block_fragment_overflow", test_connection_reliable_block_fragment_overflow);
                RUN_TEST("test_connection_reliable_over_budget_packet", test_connection_reliable_over_budget_packet);
                RUN_TEST("test_connection_reliable_message_alloc_failure", test_connection_reliable_message_alloc_failure);
                RUN_TEST("test_connection_unreliable_message_alloc_failure", test_connection_unreliable_message_alloc_failure);
                RUN_TEST("test_connection_generate_packet_channel_data_alloc_failure", test_connection_generate_packet_channel_data_alloc_failure);
                RUN_TEST("test_message_factory_create_message_alloc_failure", test_message_factory_create_message_alloc_failure);
                RUN_TEST("test_connection_process_packet_channel_data_alloc_failure", test_connection_process_packet_channel_data_alloc_failure);
                RUN_TEST("test_connection_message_refcounts", test_connection_message_refcounts);
                RUN_TEST("test_connection_truncated_and_garbage_packets", test_connection_truncated_and_garbage_packets);
                RUN_TEST("test_connection_message_too_large", test_connection_message_too_large);

                RUN_TEST("test_channel_config_fragment_counts_without_overflow", test_channel_config_fragment_counts_without_overflow);
                RUN_TEST("test_interface_methods_link", test_interface_methods_link);
                RUN_TEST("test_server_start_alloc_failure", test_server_start_alloc_failure);
                RUN_TEST("test_server_start_factory_failure", test_server_start_factory_failure);
                RUN_TEST("test_client_connect_alloc_failure", test_client_connect_alloc_failure);
                RUN_TEST("test_client_connect_factory_failure", test_client_connect_factory_failure);
                RUN_TEST("test_client_connect_socket_failure_no_crash", test_client_connect_socket_failure_no_crash);
                RUN_TEST("test_client_is_loopback_when_disconnected", test_client_is_loopback_when_disconnected);
                RUN_TEST("test_client_connect_twice_with_one_connect_token", test_client_connect_twice_with_one_connect_token);
                RUN_TEST("test_client_server_messages", test_client_server_messages);
                RUN_TEST("test_client_server_start_stop_restart", test_client_server_start_stop_restart);
                RUN_TEST("test_client_server_message_failed_to_serialize_reliable_ordered", test_client_server_message_failed_to_serialize_reliable_ordered);
                RUN_TEST("test_server_client_disconnect_reason", test_server_client_disconnect_reason);
                RUN_TEST("test_server_client_disconnect_reason_failed_to_serialize", test_server_client_disconnect_reason_failed_to_serialize);
                RUN_TEST("test_client_disconnect_reason", test_client_disconnect_reason);
                RUN_TEST("test_client_disconnect_reason_failed_to_serialize", test_client_disconnect_reason_failed_to_serialize);
                RUN_TEST("test_message_sends_across_reconnect", test_message_sends_across_reconnect);
                RUN_TEST("test_network_info", test_network_info);
                RUN_TEST("test_client_server_message_failed_to_serialize_unreliable_unordered", test_client_server_message_failed_to_serialize_unreliable_unordered);
                RUN_TEST("test_client_server_message_exhaust_stream_allocator", test_client_server_message_exhaust_stream_allocator);
                RUN_TEST("test_client_server_message_receive_queue_overflow", test_client_server_message_receive_queue_overflow);
                RUN_TEST("test_reliable_outbound_sequence_outdated", test_reliable_outbound_sequence_outdated);
                RUN_TEST("test_reliable_fragment_overflow_bug", test_reliable_fragment_overflow_bug);
                RUN_TEST("test_single_message_type_reliable", test_single_message_type_reliable);
                RUN_TEST("test_single_message_type_reliable_blocks", test_single_message_type_reliable_blocks);
                RUN_TEST("test_single_message_type_unreliable", test_single_message_type_unreliable);
                RUN_TEST("test_client_server_messages_network_sim_leak", test_client_server_messages_network_sim_leak);

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
