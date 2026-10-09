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
    static partial class yojimbo
    {
        #region utils

        /**
            Template function to get the minimum of two values.
         */
        public static T min<T>(T a, T b) where T : IComparable<T> =>
            a.CompareTo(b) < 0 ? a : b;

        /**
            Template function to get the maximum of two values.
         */
        public static T max<T>(T a, T b) where T : IComparable<T> =>
            a.CompareTo(b) > 0 ? a : b;

        /**
            Template function to clamp a value.
            @returns The clamped value in [a,b].
         */
        public static T clamp<T>(T value, T a, T b) where T : IComparable<T> =>
            value.CompareTo(a) < 0 ? a : value.CompareTo(b) > 0 ? b : value;

        /**
            Generate cryptographically secure random data.
            @param data The buffer to store the random data.
            @param bytes The number of bytes of random data to generate.
         */
        public static void random_bytes(byte[] data, int bytes) =>
            netcode.random_bytes(data, bytes);
        public static void random_bytes(ref ulong data, int bytes)
        {
            assert(bytes > 0 && bytes <= 8);
            var buffer = new byte[8];
            netcode.random_bytes(buffer, bytes);
            data = BitConverter.ToUInt64(buffer, 0);
        }

        /**
            Maximum value returned by yojimbo.rand(), like RAND_MAX on glibc and macOS.
         */
        public const int RAND_MAX = int.MaxValue;

        static Random rand_state = new Random();
        static readonly object rand_lock = new object();

        /**
            Seed the pseudo random number generator used by random_int and random_float (the network simulator and tests). Equivalent to C srand.
            @param seed The seed value.
         */
        public static void srand(int seed)
        {
            lock (rand_lock)
                rand_state = new Random(seed);
        }

        /**
            Pseudo random integer in [0,RAND_MAX]. Equivalent to C rand(). Not cryptographically secure.
         */
        public static int rand()
        {
            lock (rand_lock)
                return (int)(rand_state.NextInt64(0, (long)RAND_MAX + 1));
        }

        /**
            Generate a random integer between a and b (inclusive).
            IMPORTANT: This is not a cryptographically secure random. It's used only for test functions and in the network simulator.
            @param a The minimum integer value to generate.
            @param b The maximum integer value to generate.
            @returns A pseudo random integer value in [a,b].
         */
        public static int random_int(int a, int b)
        {
            assert(a < b);
            var result = a + rand() % (b - a + 1);
            assert(result >= a);
            assert(result <= b);
            return result;
        }

        /** 
            Generate a random float between a and b.
            IMPORTANT: This is not a cryptographically secure random. It's used only for test functions and in the network simulator.
            @param a The minimum integer value to generate.
            @param b The maximum integer value to generate.
            @returns A pseudo random float value in [a,b].
         */
        public static float random_float(float a, float b)
        {
            assert(a < b);
            var random = rand() / (float)RAND_MAX;
            var diff = b - a;
            var r = random * diff;
            return a + r;
        }

        /** 
            Compares two 16 bit sequence numbers and returns true if the first one is greater than the second (considering wrapping).
            IMPORTANT: This is not the same as s1 > s2!
            Greater than is defined specially to handle wrapping sequence numbers. 
            If the two sequence numbers are close together, it is as normal, but they are far apart, it is assumed that they have wrapped around.
            Thus, sequence_greater_than( 1, 0 ) returns true, and so does sequence_greater_than( 0, 65535 )!
            @param s1 The first sequence number.
            @param s2 The second sequence number.
            @returns True if the s1 is greater than s2, with sequence number wrapping considered.
         */
        public static bool sequence_greater_than(ushort s1, ushort s2) =>
            ((s1 > s2) && (s1 - s2 <= 32768)) ||
            ((s1 < s2) && (s2 - s1 > 32768));

        /** 
            Compares two 16 bit sequence numbers and returns true if the first one is less than the second (considering wrapping).
            IMPORTANT: This is not the same as s1 < s2!
            @param s1 The first sequence number.
            @param s2 The second sequence number.
            @returns True if the s1 is less than s2, with sequence number wrapping considered.
         */
        public static bool sequence_less_than(ushort s1, ushort s2) =>
            sequence_greater_than(s2, s1);

        /**
            Print bytes with a label. 
            Useful for printing out packets, encryption keys, nonce etc.
            @param label The label to print out before the bytes.
            @param data The data to print out to stdout.
            @param data_bytes The number of bytes of data to print.
         */
        public static void print_bytes(string label, byte[] data, int data_bytes)
        {
            var sb = new System.Text.StringBuilder();
            sb.Append($"{label}: ");
            for (var i = 0; i < data_bytes; ++i)
                sb.Append($"0x{data[i]:x2},");
            sb.Append($" ({data_bytes} bytes)\n");
            Console.Write(sb.ToString());
        }

        #endregion
    }
}
