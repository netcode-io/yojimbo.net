/*
    reliable.io

    Copyright © 2017 - 2019, The Network Protocol Company, Inc.

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
using System.Reflection;
using System.Reflection.Emit;
using System.Runtime.InteropServices;

namespace networkprotocol
{
    #region reliable_h

    public static partial class reliable
    {
        public const int ENDPOINT_COUNTER_NUM_PACKETS_SENT = 0;
        public const int ENDPOINT_COUNTER_NUM_PACKETS_RECEIVED = 1;
        public const int ENDPOINT_COUNTER_NUM_PACKETS_ACKED = 2;
        public const int ENDPOINT_COUNTER_NUM_PACKETS_STALE = 3;
        public const int ENDPOINT_COUNTER_NUM_PACKETS_INVALID = 4;
        public const int ENDPOINT_COUNTER_NUM_PACKETS_TOO_LARGE_TO_SEND = 5;
        public const int ENDPOINT_COUNTER_NUM_PACKETS_TOO_LARGE_TO_RECEIVE = 6;
        public const int ENDPOINT_COUNTER_NUM_FRAGMENTS_SENT = 7;
        public const int ENDPOINT_COUNTER_NUM_FRAGMENTS_RECEIVED = 8;
        public const int ENDPOINT_COUNTER_NUM_FRAGMENTS_INVALID = 9;
        public const int ENDPOINT_NUM_COUNTERS = 10;

        public const int MAX_PACKET_HEADER_BYTES = 9;
        public const int FRAGMENT_HEADER_BYTES = 5;

        public const int LOG_LEVEL_NONE = 0;
        public const int LOG_LEVEL_ERROR = 1;
        public const int LOG_LEVEL_INFO = 2;
        public const int LOG_LEVEL_DEBUG = 3;

        public const int OK = 1;
        public const int ERROR = 0;

        [DebuggerStepThrough, Conditional("DEBUG")]
        public static void assert(bool condition)
        {
            if (!condition)
            {
                var stackFrame = new StackTrace().GetFrame(1);
                assert_function?.Invoke(null, stackFrame.GetMethod().Name, stackFrame.GetFileName(), stackFrame.GetFileLineNumber());
                Environment.Exit(1);
            }
        }
    }

    public class reliable_config_t
    {
        public string name;
        public object context;
        public int index;
        public int max_packet_size;
        public int fragment_above;
        public int max_fragments;
        public int fragment_size;
        public int ack_buffer_size;
        public int sent_packets_buffer_size;
        public int received_packets_buffer_size;
        public int fragment_reassembly_buffer_size;
        public float rtt_smoothing_factor;
        public float packet_loss_smoothing_factor;
        public float bandwidth_smoothing_factor;
        public int packet_header_size;
        public Action<object, int, ushort, byte[], int> transmit_packet_function;
        public Func<object, int, ushort, byte[], int, bool> process_packet_function;
        public object allocator_context;
        public Func<object, ulong, object> allocate_function;
        public Action<object, object> free_function;
    }

    #endregion

    public static partial class reliable
    {
        #region assert / logging

        static void default_assert_handler(string condition, string function, string file, int line)
        {
            Console.Write($"assert failed: ( {condition} ), function {function}, file {file}, line {line}\n");
            Debugger.Break();
            Environment.Exit(1);
        }

        static int log_level_ = 0;

        static Action<string> printf_function =
            x => Console.Write(x);

        public static Action<string, string, string, int> assert_function = default_assert_handler;

        public static void log_level(int level) =>
            log_level_ = level;

        public static void set_printf_function(Action<string> function)
        {
            assert(function != null);
            printf_function = function;
        }

        public static void set_assert_function(Action<string, string, string, int> function) =>
            assert_function = function;

#if !RELIABLE_ENABLE_LOGGING
        static void printf(int level, string format)
        {
            if (level > log_level_) return;
            printf_function(format);
        }
#else
        static void printf(int level, string format) { }
#endif

        static object default_allocate_function(object context, ulong bytes) => null;

        static void default_free_function(object context, object pointer) { }

        #endregion

        #region init / term

        public static int init() => OK;

        public static void term() { }

        #endregion

        #region sequence > / <

        static bool sequence_greater_than(ushort s1, ushort s2) =>
            (s1 > s2 && s1 - s2 <= 32768) ||
            (s1 < s2 && s2 - s1 > 32768);

        static bool sequence_less_than(ushort s1, ushort s2) =>
            sequence_greater_than(s2, s1);

        #endregion

        #region sequence_buffer_t

        internal class sequence_buffer_t<T>
        {
            public object allocator_context;
            public Func<object, ulong, object> allocate_function;
            public Action<object, object> free_function;
            public ushort sequence;
            public int num_entries;
            //public Type entry_stride;
            public uint[] entry_sequence;
            public T[] entry_data;
        }

        static sequence_buffer_t<T> sequence_buffer_create<T>(
            int num_entries,
            //Type entry_stride,
            object allocator_context,
            Func<object, ulong, object> allocate_function,
            Action<object, object> free_function) where T : new()
        {
            assert(num_entries > 0);
            //assert(entry_stride != null);

            if (allocate_function == null)
                allocate_function = default_allocate_function;

            if (free_function == null)
                free_function = default_free_function;

            var sequence_buffer = new sequence_buffer_t<T>();
            sequence_buffer.allocator_context = allocator_context;
            sequence_buffer.allocate_function = allocate_function;
            sequence_buffer.free_function = free_function;
            sequence_buffer.sequence = 0;
            sequence_buffer.num_entries = num_entries;
            //sequence_buffer.entry_stride = entry_stride;
            sequence_buffer.entry_sequence = new uint[num_entries];
            sequence_buffer.entry_data = new T[num_entries];
            assert(sequence_buffer.entry_sequence != null);
            assert(sequence_buffer.entry_data != null);
            BufferEx.Set(sequence_buffer.entry_sequence, 0xFF, sizeof(uint) * sequence_buffer.num_entries);
            BufferEx.SetT(sequence_buffer.entry_data, 0, num_entries);

            return sequence_buffer;
        }

        static void sequence_buffer_destroy<T>(ref sequence_buffer_t<T> sequence_buffer)
        {
            assert(sequence_buffer != null);
            sequence_buffer.entry_sequence = null;
            sequence_buffer.entry_data = null;
            sequence_buffer = null;
        }

        static void sequence_buffer_reset<T>(sequence_buffer_t<T> sequence_buffer)
        {
            assert(sequence_buffer != null);
            sequence_buffer.sequence = 0;
            BufferEx.Set(sequence_buffer.entry_sequence, 0xFF, sizeof(uint) * sequence_buffer.num_entries);
        }

        static void sequence_buffer_remove_entries<T>(
            sequence_buffer_t<T> sequence_buffer,
            int start_sequence,
            int finish_sequence,
            Action<object, object, Action<object, object>> cleanup_function)
        {
            assert(sequence_buffer != null);
            if (finish_sequence < start_sequence)
                finish_sequence += 65536;
            int i;
            if (finish_sequence - start_sequence < sequence_buffer.num_entries)
                for (i = start_sequence; i <= finish_sequence; ++i)
                {
                    cleanup_function?.Invoke(
                        sequence_buffer.entry_data[i % sequence_buffer.num_entries],
                        sequence_buffer.allocator_context,
                        sequence_buffer.free_function);
                    sequence_buffer.entry_sequence[i % sequence_buffer.num_entries] = 0xFFFFFFFF;
                }
            else
                for (i = 0; i < sequence_buffer.num_entries; ++i)
                {
                    cleanup_function?.Invoke(
                        sequence_buffer.entry_data[i],
                        sequence_buffer.allocator_context,
                        sequence_buffer.free_function);
                    sequence_buffer.entry_sequence[i] = 0xFFFFFFFF;
                }
        }

        static bool sequence_buffer_test_insert<T>(sequence_buffer_t<T> sequence_buffer, ushort sequence) =>
            sequence_less_than(sequence, (ushort)(sequence_buffer.sequence - sequence_buffer.num_entries)) ? false : true;

        static T sequence_buffer_insert<T>(sequence_buffer_t<T> sequence_buffer, ushort sequence)
        {
            assert(sequence_buffer != null);
            if (sequence_less_than(sequence, (ushort)(sequence_buffer.sequence - sequence_buffer.num_entries)))
                return default(T);
            if (sequence_greater_than((ushort)(sequence + 1), sequence_buffer.sequence))
            {
                sequence_buffer_remove_entries(sequence_buffer, sequence_buffer.sequence, sequence, null);
                sequence_buffer.sequence = (ushort)(sequence + 1);
            }
            var index = sequence % sequence_buffer.num_entries;
            sequence_buffer.entry_sequence[index] = sequence;
            return sequence_buffer.entry_data[index];
        }

        static void sequence_buffer_advance<T>(sequence_buffer_t<T> sequence_buffer, ushort sequence)
        {
            assert(sequence_buffer != null);
            if (sequence_greater_than((ushort)(sequence + 1), sequence_buffer.sequence))
            {
                sequence_buffer_remove_entries(sequence_buffer, sequence_buffer.sequence, sequence, null);
                sequence_buffer.sequence = (ushort)(sequence + 1);
            }
        }

        static T sequence_buffer_insert_with_cleanup<T>(
            sequence_buffer_t<T> sequence_buffer,
            ushort sequence,
            Action<object, object, Action<object, object>> cleanup_function)
        {
            assert(sequence_buffer != null);
            if (sequence_greater_than((ushort)(sequence + 1), sequence_buffer.sequence))
            {
                sequence_buffer_remove_entries(sequence_buffer, sequence_buffer.sequence, sequence, cleanup_function);
                sequence_buffer.sequence = (ushort)(sequence + 1);
            }
            else if (sequence_less_than(sequence, (ushort)(sequence_buffer.sequence - sequence_buffer.num_entries)))
                return default(T);
            var index = sequence % sequence_buffer.num_entries;
            if (sequence_buffer.entry_sequence[index] != 0xFFFFFFFF)
                cleanup_function(
                    sequence_buffer.entry_data[sequence % sequence_buffer.num_entries],
                    sequence_buffer.allocator_context,
                    sequence_buffer.free_function);
            sequence_buffer.entry_sequence[index] = sequence;
            return sequence_buffer.entry_data[index];
        }

        static void sequence_buffer_remove<T>(sequence_buffer_t<T> sequence_buffer, ushort sequence)
        {
            assert(sequence_buffer != null);
            sequence_buffer.entry_sequence[sequence % sequence_buffer.num_entries] = 0xFFFFFFFF;
        }

        static void sequence_buffer_remove_with_cleanup<T>(
            sequence_buffer_t<T> sequence_buffer,
            ushort sequence,
            Action<object, object, Action<object, object>> cleanup_function)
        {
            assert(sequence_buffer != null);
            var index = sequence % sequence_buffer.num_entries;
            if (sequence_buffer.entry_sequence[index] != 0xFFFFFFFF)
            {
                sequence_buffer.entry_sequence[index] = 0xFFFFFFFF;
                cleanup_function(sequence_buffer.entry_data[index], sequence_buffer.allocator_context, sequence_buffer.free_function);
            }
        }

        static bool sequence_buffer_available<T>(sequence_buffer_t<T> sequence_buffer, ushort sequence)
        {
            assert(sequence_buffer != null);
            return sequence_buffer.entry_sequence[sequence % sequence_buffer.num_entries] == 0xFFFFFFFF;
        }

        static bool sequence_buffer_exists<T>(sequence_buffer_t<T> sequence_buffer, ushort sequence)
        {
            assert(sequence_buffer != null);
            return sequence_buffer.entry_sequence[sequence % sequence_buffer.num_entries] == sequence;
        }

        static T sequence_buffer_find<T>(sequence_buffer_t<T> sequence_buffer, ushort sequence)
        {
            assert(sequence_buffer != null);
            var index = sequence % sequence_buffer.num_entries;
            return (sequence_buffer.entry_sequence[index] == sequence) ? sequence_buffer.entry_data[index] : default(T);
        }

        static T sequence_buffer_at_index<T>(sequence_buffer_t<T> sequence_buffer, int index)
        {
            assert(sequence_buffer != null);
            assert(index >= 0);
            assert(index < sequence_buffer.num_entries);
            return sequence_buffer.entry_sequence[index] != 0xFFFFFFFF ? sequence_buffer.entry_data[index] : default(T);
        }

        static void sequence_buffer_generate_ack_bits<T>(sequence_buffer_t<T> sequence_buffer, out ushort ack, out uint ack_bits)
        {
            assert(sequence_buffer != null);
            //assert(ack != null);
            //assert(ack_bits != null);
            ack = (ushort)(sequence_buffer.sequence - 1);
            ack_bits = 0;
            var mask = 1U;
            int i;
            for (i = 0; i < 32; ++i)
            {
                var sequence = (ushort)(ack - i);
                if (sequence_buffer_exists(sequence_buffer, sequence))
                    ack_bits |= mask;
                mask <<= 1;
            }
        }

        #endregion

        #region binary serdes

        internal static void write_uint8(byte[] b, ref int p, byte value)
        {
            b[p] = value;
            ++p;
        }

        internal static void write_uint16(byte[] b, ref int p, ushort value)
        {
            b[p] = (byte)value;
            b[p + 1] = (byte)(value >> 8);
            p += 2;
        }

        internal static void write_uint32(byte[] b, ref int p, uint value)
        {
            b[p] = (byte)value;
            b[p + 1] = (byte)(value >> 8);
            b[p + 2] = (byte)(value >> 0x10);
            b[p + 3] = (byte)(value >> 0x18);
            p += 4;
        }

        internal static void write_uint64(byte[] b, ref int p, ulong value)
        {
            b[p + 0] = (byte)value;
            b[p + 1] = (byte)(value >> 8);
            b[p + 2] = (byte)(value >> 0x10);
            b[p + 3] = (byte)(value >> 0x18);
            b[p + 4] = (byte)(value >> 0x20);
            b[p + 5] = (byte)(value >> 0x28);
            b[p + 6] = (byte)(value >> 0x30);
            b[p + 7] = (byte)(value >> 0x38);
            p += 8;
        }

        internal static void write_bytes(byte[] b, ref int p, byte[] byte_array, int num_bytes)
        {
            int i;
            for (i = 0; i < num_bytes; ++i)
                write_uint8(b, ref p, byte_array[i]);
        }

        internal static byte read_uint8(byte[] b, ref int p)
        {
            var value = b[p];
            ++p;
            return value;
        }

        internal static ushort read_uint16(byte[] b, ref int p)
        {
            var value = (ushort)(b[p] | (b[p + 1] << 8));
            p += 2;
            return value;
        }

        internal static uint read_uint32(byte[] b, ref int p)
        {
            var value = (uint)(b[p] | (b[p + 1] << 8) | (b[p + 2] << 0x10) | (b[p + 3] << 0x18));
            p += 4;
            return value;
        }

        internal static ulong read_uint64(byte[] b, ref int p)
        {
            var num = (uint)(b[p] | (b[p + 1] << 8) | (b[p + 2] << 0x10) | (b[p + 3] << 0x18));
            var num2 = (uint)(b[p + 4] | (b[p + 5] << 8) | (b[p + 6] << 0x10) | (b[p + 7] << 0x18));
            var value = ((ulong)num2 << 0x20) | num;
            p += 8;
            return value;
        }

        internal static byte[] read_bytes(byte[] b, ref int p, byte[] byte_array, int num_bytes)
        {
            int i;
            for (i = 0; i < num_bytes; ++i)
                byte_array[i] = read_uint8(b, ref p);
            return byte_array;
        }

        #endregion

        #region fragment_reassembly_data_t

        internal class fragment_reassembly_data_t
        {
            public ushort sequence;
            public ushort ack;
            public uint ack_bits;
            public int num_fragments_received;
            public int num_fragments_total;
            public byte[] packet_data;
            public int packet_bytes;
            public int packet_header_bytes;
            public byte[] fragment_received = new byte[256];
        }

        static void fragment_reassembly_data_cleanup(object data, object allocator_context, Action<object, object> free_function)
        {
            assert(free_function != null);
            var reassembly_data = (fragment_reassembly_data_t)data;
            if (reassembly_data.packet_data != null)
                reassembly_data.packet_data = null;
        }

        #endregion

        #region reliable_endpoint_t
    }

    public class reliable_endpoint_t
    {
        internal object allocator_context;
        internal Func<object, ulong, object> allocate_function;
        internal Action<object, object> free_function;
        internal reliable_config_t config;
        internal double time;
        internal float rtt;
        internal float packet_loss;
        internal float sent_bandwidth_kbps;
        internal float received_bandwidth_kbps;
        internal float acked_bandwidth_kbps;
        internal int num_acks;
        internal ushort[] acks;
        internal ushort sequence;
        internal reliable.sequence_buffer_t<reliable.reliable_sent_packet_data_t> sent_packets;
        internal reliable.sequence_buffer_t<reliable.reliable_received_packet_data_t> received_packets;
        internal reliable.sequence_buffer_t<reliable.fragment_reassembly_data_t> fragment_reassembly;
        internal ulong[] counters = new ulong[reliable.ENDPOINT_NUM_COUNTERS];
    }

    static partial class reliable
    {
        internal class reliable_sent_packet_data_t
        {
            public double time;
            public bool acked; // : 1;
            public uint packet_bytes; // : 31;
        }

        internal class reliable_received_packet_data_t
        {
            public double time;
            public uint packet_bytes;
        }

        public static void default_config(out reliable_config_t config) =>
            //assert(config != null);
            config = new reliable_config_t
            {
                name = "endpoint",
                max_packet_size = 16 * 1024,
                fragment_above = 1024,
                max_fragments = 16,
                fragment_size = 1024,
                ack_buffer_size = 256,
                sent_packets_buffer_size = 256,
                received_packets_buffer_size = 256,
                fragment_reassembly_buffer_size = 64,
                rtt_smoothing_factor = 0.0025f,
                packet_loss_smoothing_factor = 0.1f,
                bandwidth_smoothing_factor = 0.1f,
                packet_header_size = 28, // note: UDP over IPv4 = 20 + 8 bytes, UDP over IPv6 = 40 + 8 bytes
            };

        public static reliable_endpoint_t endpoint_create(reliable_config_t config, double time)
        {
            assert(config != null);
            assert(config.max_packet_size > 0);
            assert(config.fragment_above > 0);
            assert(config.max_fragments > 0);
            assert(config.max_fragments <= 256);
            assert(config.fragment_size > 0);
            assert(config.ack_buffer_size > 0);
            assert(config.sent_packets_buffer_size > 0);
            assert(config.received_packets_buffer_size > 0);
            assert(config.transmit_packet_function != null);
            assert(config.process_packet_function != null);

            var allocator_context = config.allocator_context;
            var allocate_function = config.allocate_function;
            var free_function = config.free_function;

            if (allocate_function == null)
                allocate_function = default_allocate_function;

            if (free_function == null)
                free_function = default_free_function;

            var endpoint = new reliable_endpoint_t();

            assert(endpoint != null);

            endpoint.allocator_context = allocator_context;
            endpoint.allocate_function = allocate_function;
            endpoint.free_function = free_function;
            endpoint.config = config;
            endpoint.time = time;

            endpoint.acks = new ushort[config.ack_buffer_size];

            endpoint.sent_packets = sequence_buffer_create<reliable_sent_packet_data_t>(
                config.sent_packets_buffer_size,
                //typeof(reliable_sent_packet_data_t),
                allocator_context,
                allocate_function,
                free_function);

            endpoint.received_packets = sequence_buffer_create<reliable_received_packet_data_t>(
                config.received_packets_buffer_size,
                //typeof(reliable_received_packet_data_t),
                allocator_context,
                allocate_function,
                free_function);

            endpoint.fragment_reassembly = sequence_buffer_create<fragment_reassembly_data_t>(
                config.fragment_reassembly_buffer_size,
                //typeof(fragment_reassembly_data_t),
                allocator_context,
                allocate_function,
                free_function);

            BufferEx.Set(endpoint.acks, 0, config.ack_buffer_size * sizeof(ushort));

            return endpoint;
        }

        public static void endpoint_destroy(ref reliable_endpoint_t endpoint)
        {
            assert(endpoint != null);
            assert(endpoint.acks != null);
            assert(endpoint.sent_packets != null);
            assert(endpoint.received_packets != null);

            int i;
            for (i = 0; i < endpoint.config.fragment_reassembly_buffer_size; ++i)
            {
                var reassembly_data = sequence_buffer_at_index(endpoint.fragment_reassembly, i);
                if (reassembly_data != null && reassembly_data.packet_data != null)
                    reassembly_data.packet_data = null;
            }

            endpoint.acks = null;

            sequence_buffer_destroy(ref endpoint.sent_packets);
            sequence_buffer_destroy(ref endpoint.received_packets);
            sequence_buffer_destroy(ref endpoint.fragment_reassembly);

            endpoint = null;
        }

        public static ushort endpoint_next_packet_sequence(this reliable_endpoint_t endpoint)
        {
            assert(endpoint != null);
            return endpoint.sequence;
        }

        static int write_packet_header(byte[] packet_data, ushort sequence, ushort ack, uint ack_bits)
        {
            var p = 0;

            byte prefix_byte = 0;
            if ((ack_bits & 0x000000FF) != 0x000000FF)
                prefix_byte |= (1 << 1);
            if ((ack_bits & 0x0000FF00) != 0x0000FF00)
                prefix_byte |= (1 << 2);
            if ((ack_bits & 0x00FF0000) != 0x00FF0000)
                prefix_byte |= (1 << 3);
            if ((ack_bits & 0xFF000000) != 0xFF000000)
                prefix_byte |= (1 << 4);

            var sequence_difference = sequence - ack;
            if (sequence_difference < 0)
                sequence_difference += 65536;
            if (sequence_difference <= 255)
                prefix_byte |= (1 << 5);

            write_uint8(packet_data, ref p, prefix_byte);
            write_uint16(packet_data, ref p, sequence);
            if (sequence_difference <= 255)
                write_uint8(packet_data, ref p, (byte)sequence_difference);
            else
                write_uint16(packet_data, ref p, ack);
            if ((ack_bits & 0x000000FF) != 0x000000FF)
                write_uint8(packet_data, ref p, (byte)(ack_bits & 0x000000FF));
            if ((ack_bits & 0x0000FF00) != 0x0000FF00)
                write_uint8(packet_data, ref p, (byte)((ack_bits & 0x0000FF00) >> 8));
            if ((ack_bits & 0x00FF0000) != 0x00FF0000)
                write_uint8(packet_data, ref p, (byte)((ack_bits & 0x00FF0000) >> 16));
            if ((ack_bits & 0xFF000000) != 0xFF000000)
                write_uint8(packet_data, ref p, (byte)((ack_bits & 0xFF000000) >> 24));

            assert(p <= MAX_PACKET_HEADER_BYTES);

            return p;
        }

        public static void endpoint_send_packet(this reliable_endpoint_t endpoint, byte[] packet_data, int packet_bytes)
        {
            assert(endpoint != null);
            assert(packet_data != null);
            assert(packet_bytes > 0);

            var p_ = 0;

            if (packet_bytes > endpoint.config.max_packet_size)
            {
                printf(LOG_LEVEL_ERROR, $"[{endpoint.config.name}] packet too large to send. packet is {packet_bytes} bytes, maximum is {endpoint.config.max_packet_size}\n");
                endpoint.counters[ENDPOINT_COUNTER_NUM_PACKETS_TOO_LARGE_TO_SEND]++;
                return;
            }

            var sequence = endpoint.sequence++;
            sequence_buffer_generate_ack_bits(endpoint.received_packets, out var ack, out var ack_bits);

            printf(LOG_LEVEL_DEBUG, $"[{endpoint.config.name}] sending packet {sequence}\n");

            var sent_packet_data = sequence_buffer_insert(endpoint.sent_packets, sequence);

            assert(sent_packet_data != null);

            sent_packet_data.time = endpoint.time;
            sent_packet_data.packet_bytes = (uint)(endpoint.config.packet_header_size + packet_bytes);
            sent_packet_data.acked = false;

            if (packet_bytes <= endpoint.config.fragment_above)
            {
                // regular packet

                printf(LOG_LEVEL_DEBUG, $"[{endpoint.config.name}] sending packet {sequence} without fragmentation\n");

                var transmit_packet_data = new byte[packet_bytes + MAX_PACKET_HEADER_BYTES];

                var packet_header_bytes = write_packet_header(transmit_packet_data, sequence, ack, ack_bits);

                BufferEx.Copy(transmit_packet_data, packet_header_bytes, packet_data, p_, packet_bytes);

                endpoint.config.transmit_packet_function(endpoint.config.context, endpoint.config.index, sequence, transmit_packet_data, packet_header_bytes + packet_bytes);

                transmit_packet_data = null;
            }
            else
            {
                // fragmented packet

                var packet_header = new byte[MAX_PACKET_HEADER_BYTES];

                var packet_header_bytes = write_packet_header(packet_header, sequence, ack, ack_bits);

                var num_fragments = (packet_bytes / endpoint.config.fragment_size) + ((packet_bytes % endpoint.config.fragment_size) != 0 ? 1 : 0);

                printf(LOG_LEVEL_DEBUG, $"[{endpoint.config.name}] sending packet {sequence} as {num_fragments} fragments\n");

                assert(num_fragments >= 1);
                assert(num_fragments <= endpoint.config.max_fragments);

                var fragment_buffer_size = FRAGMENT_HEADER_BYTES + MAX_PACKET_HEADER_BYTES + endpoint.config.fragment_size;

                var fragment_packet_data = new byte[fragment_buffer_size];

                var q = p_;
                var end = q + packet_bytes;

                int fragment_id;
                for (fragment_id = 0; fragment_id < num_fragments; ++fragment_id)
                {
                    var p = 0;
                    write_uint8(fragment_packet_data, ref p, 1);
                    write_uint16(fragment_packet_data, ref p, sequence);
                    write_uint8(fragment_packet_data, ref p, (byte)fragment_id);
                    write_uint8(fragment_packet_data, ref p, (byte)(num_fragments - 1));

                    if (fragment_id == 0)
                    {
                        BufferEx.Copy(fragment_packet_data, p, packet_header, 0, packet_header_bytes);
                        p += packet_header_bytes;
                    }

                    var bytes_to_copy = endpoint.config.fragment_size;
                    if (q + bytes_to_copy > end)
                        bytes_to_copy = end - q;

                    BufferEx.Copy(fragment_packet_data, p, packet_data, q, bytes_to_copy);

                    p += bytes_to_copy;
                    q += bytes_to_copy;

                    var fragment_packet_bytes = p;

                    endpoint.config.transmit_packet_function(endpoint.config.context, endpoint.config.index, sequence, fragment_packet_data, fragment_packet_bytes);

                    endpoint.counters[ENDPOINT_COUNTER_NUM_FRAGMENTS_SENT]++;
                }

                fragment_packet_data = null;
            }

            endpoint.counters[ENDPOINT_COUNTER_NUM_PACKETS_SENT]++;
        }

        static int read_packet_header(string name, byte[] packet_data, int p_, int packet_bytes, out ushort sequence, out ushort ack, out uint ack_bits)
        {
            ack_bits = sequence = ack = 0;
            if (packet_bytes < 3)
            {
                printf(LOG_LEVEL_ERROR, $"[{name}] packet too small for packet header (1)\n");
                return -1;
            }

            var p = p_;

            var prefix_byte = read_uint8(packet_data, ref p);

            if ((prefix_byte & 1) != 0)
            {
                printf(LOG_LEVEL_ERROR, $"[{name}] prefix byte does not indicate a regular packet\n");
                return -1;
            }

            sequence = read_uint16(packet_data, ref p);

            if ((prefix_byte & (1 << 5)) != 0)
            {
                if (packet_bytes < 3 + 1)
                {
                    printf(LOG_LEVEL_ERROR, $"[{name}] packet too small for packet header (2)\n");
                    return -1;
                }
                var sequence_difference = read_uint8(packet_data, ref p);
                ack = (ushort)(sequence - sequence_difference);
            }
            else
            {
                if (packet_bytes < 3 + 2)
                {
                    printf(LOG_LEVEL_ERROR, $"[{name}] packet too small for packet header (3)\n");
                    return -1;
                }
                ack = read_uint16(packet_data, ref p);
            }

            var expected_bytes = 0;
            int i;
            for (i = 1; i <= 4; ++i)
                if ((prefix_byte & (1 << i)) != 0)
                    expected_bytes++;
            if (packet_bytes < (p - p_) + expected_bytes)
            {
                printf(LOG_LEVEL_ERROR, $"[{name}] packet too small for packet header (4)\n");
                return -1;
            }

            ack_bits = 0xFFFFFFFF;
            if ((prefix_byte & (1 << 1)) != 0)
            {
                ack_bits &= 0xFFFFFF00;
                ack_bits |= (uint)(read_uint8(packet_data, ref p));
            }
            if ((prefix_byte & (1 << 2)) != 0)
            {
                ack_bits &= 0xFFFF00FF;
                ack_bits |= (uint)(read_uint8(packet_data, ref p)) << 8;
            }
            if ((prefix_byte & (1 << 3)) != 0)
            {
                ack_bits &= 0xFF00FFFF;
                ack_bits |= (uint)(read_uint8(packet_data, ref p)) << 16;
            }
            if ((prefix_byte & (1 << 4)) != 0)
            {
                ack_bits &= 0x00FFFFFF;
                ack_bits |= (uint)(read_uint8(packet_data, ref p)) << 24;
            }
            return p - p_;
        }

        static int read_fragment_header(
            string name,
            byte[] packet_data, int p_,
            int packet_bytes,
            int max_fragments,
            int fragment_size,
            out int fragment_id,
            out int num_fragments,
            out int fragment_bytes,
            out ushort sequence,
            out ushort ack,
            out uint ack_bits)
        {
            fragment_id = num_fragments = fragment_bytes = 0;
            ack_bits = sequence = ack = 0;

            if (packet_bytes < FRAGMENT_HEADER_BYTES)
            {
                printf(LOG_LEVEL_ERROR, $"[{name}] packet is too small to read fragment header\n");
                return -1;
            }

            var p = p_;

            var prefix_byte = read_uint8(packet_data, ref p);
            if (prefix_byte != 1)
            {
                printf(LOG_LEVEL_ERROR, $"[{name}] prefix byte is not a fragment\n");
                return -1;
            }

            sequence = read_uint16(packet_data, ref p);
            fragment_id = read_uint8(packet_data, ref p);
            num_fragments = read_uint8(packet_data, ref p) + 1;

            if (num_fragments > max_fragments)
            {
                printf(LOG_LEVEL_ERROR, $"[{name}] num fragments {num_fragments} outside of range of max fragments {max_fragments}\n");
                return -1;
            }

            if (fragment_id >= num_fragments)
            {
                printf(LOG_LEVEL_ERROR, $"[{name}] fragment id {fragment_id} outside of range of num fragments {num_fragments}\n");
                return -1;
            }

            fragment_bytes = packet_bytes - FRAGMENT_HEADER_BYTES;

            ushort packet_sequence = 0;
            ushort packet_ack = 0;
            var packet_ack_bits = 0U;

            if (fragment_id == 0)
            {
                var packet_header_bytes = read_packet_header(
                    name,
                    packet_data, p_ + FRAGMENT_HEADER_BYTES,
                    packet_bytes,
                    out packet_sequence,
                    out packet_ack,
                    out packet_ack_bits);

                if (packet_header_bytes < 0)
                {
                    printf(LOG_LEVEL_ERROR, $"[{name}] bad packet header in fragment\n");
                    return -1;
                }

                if (packet_sequence != sequence)
                {
                    printf(LOG_LEVEL_ERROR, $"[{name}] bad packet sequence in fragment. expected {sequence}, got {packet_sequence}\n");
                    return -1;
                }

                fragment_bytes = packet_bytes - packet_header_bytes - FRAGMENT_HEADER_BYTES;
            }

            ack = packet_ack;
            ack_bits = packet_ack_bits;

            if (fragment_bytes > fragment_size)
            {
                printf(LOG_LEVEL_ERROR, $"[{name}] fragment bytes {fragment_bytes} > fragment size {fragment_size}\n");
                return -1;
            }

            if (fragment_id != num_fragments - 1 && fragment_bytes != fragment_size)
            {
                printf(LOG_LEVEL_ERROR, $"[{name}] fragment {fragment_id} is {fragment_bytes} bytes, which is not the expected fragment size fragment_size\n");
                return -1;
            }

            return p - p_;
        }

        static void store_fragment_data(
            fragment_reassembly_data_t reassembly_data,
            ushort sequence,
            ushort ack,
            uint ack_bits,
            int fragment_id,
            int fragment_size,
            byte[] fragment_data, int p_,
            int fragment_bytes)
        {
            var p = p_;

            if (fragment_id == 0)
            {
                var packet_header = new byte[MAX_PACKET_HEADER_BYTES];

                reassembly_data.packet_header_bytes = write_packet_header(packet_header, sequence, ack, ack_bits);

                BufferEx.Copy(reassembly_data.packet_data, MAX_PACKET_HEADER_BYTES - reassembly_data.packet_header_bytes,
                        packet_header, 0,
                        reassembly_data.packet_header_bytes);

                p += reassembly_data.packet_header_bytes;
                fragment_bytes -= reassembly_data.packet_header_bytes;
            }

            if (fragment_id == reassembly_data.num_fragments_total - 1)
                reassembly_data.packet_bytes = (reassembly_data.num_fragments_total - 1) * fragment_size + fragment_bytes;

            BufferEx.Copy(reassembly_data.packet_data, MAX_PACKET_HEADER_BYTES + fragment_id * fragment_size, fragment_data, p, fragment_bytes);
        }

        public static void endpoint_receive_packet(this reliable_endpoint_t endpoint, byte[] packet_data, int packet_bytes)
        {
            assert(endpoint != null);
            assert(packet_data != null);
            assert(packet_bytes > 0);

            if (packet_bytes > endpoint.config.max_packet_size)
            {
                printf(LOG_LEVEL_ERROR, $"[{endpoint.config.name}] packet too large to receive. packet is {packet_bytes} bytes, maximum is {endpoint.config.max_packet_size}\n");
                endpoint.counters[ENDPOINT_COUNTER_NUM_PACKETS_TOO_LARGE_TO_RECEIVE]++;
                return;
            }

            var p_ = 0;
            var prefix_byte = packet_data[p_];

            if ((prefix_byte & 1) == 0)
            {
                // regular packet

                endpoint.counters[ENDPOINT_COUNTER_NUM_PACKETS_RECEIVED]++;

                var packet_header_bytes = read_packet_header(endpoint.config.name, packet_data, p_, packet_bytes, out var sequence, out var ack, out var ack_bits);
                if (packet_header_bytes < 0)
                {
                    printf(LOG_LEVEL_ERROR, $"[{endpoint.config.name}] ignoring invalid packet. could not read packet header\n");
                    endpoint.counters[ENDPOINT_COUNTER_NUM_PACKETS_INVALID]++;
                    return;
                }

                if (!sequence_buffer_test_insert(endpoint.received_packets, sequence))
                {
                    printf(LOG_LEVEL_DEBUG, $"[{endpoint.config.name}] ignoring stale packet {sequence}\n");
                    endpoint.counters[ENDPOINT_COUNTER_NUM_PACKETS_STALE]++;
                    return;
                }

                printf(LOG_LEVEL_DEBUG, $"[{endpoint.config.name}] processing packet {sequence}\n");

                if (endpoint.config.process_packet_function(
                    endpoint.config.context,
                    endpoint.config.index,
                    sequence,
                    BufferEx.Slice(packet_data, p_ + packet_header_bytes, packet_bytes - packet_header_bytes),
                    packet_bytes - packet_header_bytes))
                {
                    printf(LOG_LEVEL_DEBUG, $"[{endpoint.config.name}] process packet {sequence} successful\n");

                    var received_packet_data = sequence_buffer_insert(endpoint.received_packets, sequence);

                    sequence_buffer_advance(endpoint.fragment_reassembly, sequence);

                    assert(received_packet_data != null);

                    received_packet_data.time = endpoint.time;
                    received_packet_data.packet_bytes = (uint)(endpoint.config.packet_header_size + packet_bytes);

                    int i;
                    for (i = 0; i < 32; ++i)
                    {
                        if ((ack_bits & 1) != 0)
                        {
                            var ack_sequence = (ushort)(ack - i);

                            var sent_packet_data = sequence_buffer_find(endpoint.sent_packets, ack_sequence);

                            if (sent_packet_data != null && !sent_packet_data.acked && endpoint.num_acks < endpoint.config.ack_buffer_size)
                            {
                                printf(LOG_LEVEL_DEBUG, $"[{endpoint.config.name}] acked packet {ack_sequence}\n");
                                endpoint.acks[endpoint.num_acks++] = ack_sequence;
                                endpoint.counters[ENDPOINT_COUNTER_NUM_PACKETS_ACKED]++;
                                sent_packet_data.acked = true;

                                var rtt = (float)(endpoint.time - sent_packet_data.time) * 1000.0f;
                                assert(rtt >= 0.0);
                                if ((endpoint.rtt == 0.0f && rtt > 0.0f) || Math.Abs(endpoint.rtt - rtt) < 0.00001)
                                    endpoint.rtt = rtt;
                                else
                                    endpoint.rtt += (rtt - endpoint.rtt) * endpoint.config.rtt_smoothing_factor;
                            }
                        }
                        ack_bits >>= 1;
                    }
                }
                else printf(LOG_LEVEL_ERROR, $"[{endpoint.config.name}] process packet failed\n");
            }
            else
            {
                // fragment packet

                var fragment_header_bytes = read_fragment_header(
                    endpoint.config.name,
                    packet_data, p_,
                    packet_bytes,
                    endpoint.config.max_fragments,
                    endpoint.config.fragment_size,
                    out var fragment_id,
                    out var num_fragments,
                    out var fragment_bytes,
                    out var sequence,
                    out var ack,
                    out var ack_bits);

                if (fragment_header_bytes < 0)
                {
                    printf(LOG_LEVEL_ERROR, $"[{endpoint.config.name}] ignoring invalid fragment. could not read fragment header\n");
                    endpoint.counters[ENDPOINT_COUNTER_NUM_FRAGMENTS_INVALID]++;
                    return;
                }

                var reassembly_data = sequence_buffer_find(endpoint.fragment_reassembly, sequence);

                if (reassembly_data == null)
                {
                    reassembly_data = sequence_buffer_insert_with_cleanup(endpoint.fragment_reassembly, sequence, fragment_reassembly_data_cleanup);

                    if (reassembly_data == null)
                    {
                        printf(LOG_LEVEL_ERROR, $"[{endpoint.config.name}] ignoring invalid fragment. could not insert in reassembly buffer (stale)\n");
                        endpoint.counters[ENDPOINT_COUNTER_NUM_FRAGMENTS_INVALID]++;
                        return;
                    }

                    sequence_buffer_advance(endpoint.received_packets, sequence);

                    var packet_buffer_size = MAX_PACKET_HEADER_BYTES + num_fragments * endpoint.config.fragment_size;

                    reassembly_data.sequence = sequence;
                    reassembly_data.ack = 0;
                    reassembly_data.ack_bits = 0;
                    reassembly_data.num_fragments_received = 0;
                    reassembly_data.num_fragments_total = num_fragments;
                    reassembly_data.packet_data = new byte[packet_buffer_size];
                    reassembly_data.packet_bytes = 0;
                    BufferEx.Set(reassembly_data.fragment_received, 0, reassembly_data.fragment_received.Length);
                }

                if (num_fragments != reassembly_data.num_fragments_total)
                {
                    printf(LOG_LEVEL_ERROR, $"[{endpoint.config.name}] ignoring invalid fragment. fragment count mismatch. expected {reassembly_data.num_fragments_total}, got {num_fragments}\n");
                    endpoint.counters[ENDPOINT_COUNTER_NUM_FRAGMENTS_INVALID]++;
                    return;
                }

                if (reassembly_data.fragment_received[fragment_id] != 0)
                {
                    printf(LOG_LEVEL_ERROR, $"[{endpoint.config.name}] ignoring fragment {fragment_id} of packet {sequence}. fragment already received\n");
                    return;
                }

                printf(LOG_LEVEL_DEBUG, $"[{endpoint.config.name}] received fragment {fragment_id} of packet {sequence} ({reassembly_data.num_fragments_received + 1}/{num_fragments})\n");

                reassembly_data.num_fragments_received++;
                reassembly_data.fragment_received[fragment_id] = 1;

                store_fragment_data(
                    reassembly_data,
                    sequence,
                    ack,
                    ack_bits,
                    fragment_id,
                    endpoint.config.fragment_size,
                    packet_data, p_ + fragment_header_bytes,
                    packet_bytes - fragment_header_bytes);

                if (reassembly_data.num_fragments_received == reassembly_data.num_fragments_total)
                {
                    printf(LOG_LEVEL_DEBUG, $"[{endpoint.config.name}] completed reassembly of packet {sequence}\n");

                    endpoint_receive_packet(
                        endpoint,
                        BufferEx.Slice(reassembly_data.packet_data, MAX_PACKET_HEADER_BYTES - reassembly_data.packet_header_bytes, reassembly_data.packet_header_bytes + reassembly_data.packet_bytes),
                        reassembly_data.packet_header_bytes + reassembly_data.packet_bytes);

                    sequence_buffer_remove_with_cleanup(endpoint.fragment_reassembly, sequence, fragment_reassembly_data_cleanup);
                }

                endpoint.counters[ENDPOINT_COUNTER_NUM_FRAGMENTS_RECEIVED]++;
            }
        }

        public static void endpoint_free_packet(this reliable_endpoint_t endpoint, ref object packet)
        {
            assert(endpoint != null);
            assert(packet != null);
            packet = null;
        }

        public static ushort[] endpoint_get_acks(this reliable_endpoint_t endpoint, out int num_acks)
        {
            assert(endpoint != null);
            //assert(num_acks != null);
            num_acks = endpoint.num_acks;
            return endpoint.acks;
        }

        public static void endpoint_clear_acks(this reliable_endpoint_t endpoint)
        {
            assert(endpoint != null);
            endpoint.num_acks = 0;
        }

        public static void endpoint_reset(this reliable_endpoint_t endpoint)
        {
            assert(endpoint != null);

            endpoint.num_acks = 0;
            endpoint.sequence = 0;

            BufferEx.Set(endpoint.acks, 0, endpoint.config.ack_buffer_size * sizeof(ushort));

            int i;
            for (i = 0; i < endpoint.config.fragment_reassembly_buffer_size; ++i)
            {
                var reassembly_data = sequence_buffer_at_index(endpoint.fragment_reassembly, i);

                if (reassembly_data != null && reassembly_data.packet_data != null)
                    reassembly_data.packet_data = null;
            }

            sequence_buffer_reset(endpoint.sent_packets);
            sequence_buffer_reset(endpoint.received_packets);
            sequence_buffer_reset(endpoint.fragment_reassembly);
        }

        public static void endpoint_update(this reliable_endpoint_t endpoint, double time)
        {
            assert(endpoint != null);

            endpoint.time = time;

            // calculate packet loss
            {
                var base_sequence = (uint)((endpoint.sent_packets.sequence - endpoint.config.sent_packets_buffer_size + 1) + 0xFFFF);
                int i;
                var num_dropped = 0;
                var num_samples = endpoint.config.sent_packets_buffer_size / 2;
                for (i = 0; i < num_samples; ++i)
                {
                    var sequence = (ushort)(base_sequence + i);
                    var sent_packet_data = sequence_buffer_find(endpoint.sent_packets, sequence);
                    if (sent_packet_data != null && !sent_packet_data.acked)
                        num_dropped++;
                }
                var packet_loss = num_dropped / (float)num_samples * 100.0f;
                if (Math.Abs(endpoint.packet_loss - packet_loss) > 0.00001)
                    endpoint.packet_loss += (packet_loss - endpoint.packet_loss) * endpoint.config.packet_loss_smoothing_factor;
                else
                    endpoint.packet_loss = packet_loss;
            }

            // calculate sent bandwidth
            {
                var base_sequence = (uint)(endpoint.sent_packets.sequence - endpoint.config.sent_packets_buffer_size + 1) + 0xFFFFU;
                int i;
                var bytes_sent = 0;
                var start_time = double.MaxValue;
                var finish_time = 0.0;
                var num_samples = endpoint.config.sent_packets_buffer_size / 2;
                for (i = 0; i < num_samples; ++i)
                {
                    var sequence = (ushort)(base_sequence + i);
                    var sent_packet_data = sequence_buffer_find(endpoint.sent_packets, sequence);
                    if (sent_packet_data == null)
                        continue;
                    bytes_sent += (int)sent_packet_data.packet_bytes;
                    if (sent_packet_data.time < start_time)
                        start_time = sent_packet_data.time;
                    if (sent_packet_data.time > finish_time)
                        finish_time = sent_packet_data.time;
                }
                if (start_time != double.MaxValue && finish_time != 0.0)
                {
                    var sent_bandwidth_kbps = (float)(bytes_sent / (finish_time - start_time) * 8.0f / 1000.0f);
                    if (Math.Abs(endpoint.sent_bandwidth_kbps - sent_bandwidth_kbps) > 0.00001)
                        endpoint.sent_bandwidth_kbps += (sent_bandwidth_kbps - endpoint.sent_bandwidth_kbps) * endpoint.config.bandwidth_smoothing_factor;
                    else
                        endpoint.sent_bandwidth_kbps = sent_bandwidth_kbps;
                }
            }

            // calculate received bandwidth
            {
                var base_sequence = (uint)(endpoint.received_packets.sequence - endpoint.config.received_packets_buffer_size + 1) + 0xFFFFU;
                int i;
                var bytes_sent = 0;
                var start_time = double.MaxValue;
                var finish_time = 0.0;
                var num_samples = endpoint.config.received_packets_buffer_size / 2;
                for (i = 0; i < num_samples; ++i)
                {
                    var sequence = (ushort)(base_sequence + i);
                    var received_packet_data = sequence_buffer_find(endpoint.received_packets, sequence);
                    if (received_packet_data == null)
                        continue;
                    bytes_sent += (int)received_packet_data.packet_bytes;
                    if (received_packet_data.time < start_time)
                        start_time = received_packet_data.time;
                    if (received_packet_data.time > finish_time)
                        finish_time = received_packet_data.time;
                }
                if (start_time != double.MaxValue && finish_time != 0.0)
                {
                    var received_bandwidth_kbps = (float)(bytes_sent / (finish_time - start_time) * 8.0f / 1000.0f);
                    if (Math.Abs(endpoint.received_bandwidth_kbps - received_bandwidth_kbps) > 0.00001)
                        endpoint.received_bandwidth_kbps += (received_bandwidth_kbps - endpoint.received_bandwidth_kbps) * endpoint.config.bandwidth_smoothing_factor;
                    else
                        endpoint.received_bandwidth_kbps = received_bandwidth_kbps;
                }
            }

            // calculate acked bandwidth
            {
                var base_sequence = (uint)(endpoint.sent_packets.sequence - endpoint.config.sent_packets_buffer_size + 1) + 0xFFFFU;
                int i;
                var bytes_sent = 0;
                var start_time = double.MaxValue;
                var finish_time = 0.0;
                var num_samples = endpoint.config.sent_packets_buffer_size / 2;
                for (i = 0; i < num_samples; ++i)
                {
                    var sequence = (ushort)(base_sequence + i);
                    var sent_packet_data = sequence_buffer_find(endpoint.sent_packets, sequence);
                    if (sent_packet_data == null || !sent_packet_data.acked)
                        continue;
                    bytes_sent += (int)sent_packet_data.packet_bytes;
                    if (sent_packet_data.time < start_time)
                        start_time = sent_packet_data.time;
                    if (sent_packet_data.time > finish_time)
                        finish_time = sent_packet_data.time;
                }
                if (start_time != double.MaxValue && finish_time != 0.0)
                {
                    var acked_bandwidth_kbps = (float)(bytes_sent / (finish_time - start_time) * 8.0f / 1000.0f);
                    if (Math.Abs(endpoint.acked_bandwidth_kbps - acked_bandwidth_kbps) > 0.00001)
                        endpoint.acked_bandwidth_kbps += (acked_bandwidth_kbps - endpoint.acked_bandwidth_kbps) * endpoint.config.bandwidth_smoothing_factor;
                    else
                        endpoint.acked_bandwidth_kbps = acked_bandwidth_kbps;
                }
            }
        }

        public static float endpoint_rtt(this reliable_endpoint_t endpoint)
        {
            assert(endpoint != null);
            return endpoint.rtt;
        }

        public static float endpoint_packet_loss(this reliable_endpoint_t endpoint)
        {
            assert(endpoint != null);
            return endpoint.packet_loss;
        }

        public static void endpoint_bandwidth(this reliable_endpoint_t endpoint, out float sent_bandwidth_kbps, out float received_bandwidth_kbps, out float acked_bandwidth_kbps)
        {
            assert(endpoint != null);
            //assert(sent_bandwidth_kbps != null);
            //assert(acked_bandwidth_kbps != null);
            //assert(received_bandwidth_kbps != null);
            sent_bandwidth_kbps = endpoint.sent_bandwidth_kbps;
            received_bandwidth_kbps = endpoint.received_bandwidth_kbps;
            acked_bandwidth_kbps = endpoint.acked_bandwidth_kbps;
        }

        public static ulong[] endpoint_counters(this reliable_endpoint_t endpoint)
        {
            assert(endpoint != null);
            return endpoint.counters;
        }

        #endregion
    }

#if !YOJIMBO
    #region BufferEx

    internal static class BufferEx
    {
        readonly static Random Random = new Random(Guid.NewGuid().GetHashCode());
        readonly static Action<IntPtr, byte, int> MemsetDelegate;

        static BufferEx()
        {
            var dynamicMethod = new DynamicMethod("Memset", MethodAttributes.Public | MethodAttributes.Static, CallingConventions.Standard,
            null, new[] { typeof(IntPtr), typeof(byte), typeof(int) }, typeof(BufferEx), true);
            var generator = dynamicMethod.GetILGenerator();
            generator.Emit(OpCodes.Ldarg_0);
            generator.Emit(OpCodes.Ldarg_1);
            generator.Emit(OpCodes.Ldarg_2);
            generator.Emit(OpCodes.Initblk);
            generator.Emit(OpCodes.Ret);
            MemsetDelegate = (Action<IntPtr, byte, int>)dynamicMethod.CreateDelegate(typeof(Action<IntPtr, byte, int>));
        }

        public const int RAND_MAX = 0x7fff;
        public static int Rand() { lock (Random) return Random.Next(RAND_MAX); }

        public static void Copy(Array dst, Array src, int length) =>
            Buffer.BlockCopy(src, 0, dst, 0, length);
        public static void Copy(Array dst, int dstOffset, Array src, int srcOffset, int length) =>
            Buffer.BlockCopy(src, srcOffset, dst, dstOffset, length);
        public static void Copy<T>(ref T dst, T src = null, int? length = null) where T : class, new() =>
            dst = src ?? new T();

        public static byte[] Slice(Array src, int srcOffset, int length)
        {
            var r = new byte[length]; Buffer.BlockCopy(src, srcOffset, r, 0, length); return r;
        }

        public static void Set(Array array, byte value, int? length = null)
        {
            var gcHandle = GCHandle.Alloc(array, GCHandleType.Pinned);
            MemsetDelegate(gcHandle.AddrOfPinnedObject(), value, length ?? Buffer.ByteLength(array));
            gcHandle.Free();
        }
        public static void SetWithOffset(Array array, int offset, byte value, int? length = null)
        {
            var gcHandle = GCHandle.Alloc(array, GCHandleType.Pinned);
            MemsetDelegate(gcHandle.AddrOfPinnedObject() + offset, value, length ?? Buffer.ByteLength(array));
            gcHandle.Free();
        }

        public static void SetT<T>(IList<T> array, object value, int? length = null) where T : new()
        {
            for (var i = 0; i < (length ?? array.Count); i++)
                array[i] = value != null ? new T() : default(T);
        }
        public static void SetT<T>(ref T dst, object value, int? length = null) where T : new()
        {
            dst = value != null ? new T() : default(T);
        }

        public static T[] NewT<T>(int length) where T : new()
        {
            var array = new T[length];
            for (var i = 0; i < length; i++)
                array[i] = new T();
            return array;
        }
        public static T[][] NewT<T>(int length, int length2) where T : new()
        {
            var array = new T[length][];
            for (var i = 0; i < length; i++)
                array[i] = new T[length2];
            return array;
        }

        public static bool Equal<T>(IList<T> first, IList<T> second, int? length) =>
            (length == null) || (first.Count == length && second.Count == length) ?
                Enumerable.SequenceEqual(first, second) :
                Enumerable.SequenceEqual(first.Take(length.Value), second.Take(length.Value));
        public static bool Equal<T>(IList<T> first, int firstOffset, IList<T> second, int secondOffset, int? length = null) =>
            (length == null) || (first.Count - firstOffset == length && second.Count - secondOffset == length) ?
                Enumerable.SequenceEqual(first.Skip(firstOffset), second.Skip(firstOffset)) :
                Enumerable.SequenceEqual(first.Skip(firstOffset).Take(length.Value), second.Skip(firstOffset).Take(length.Value));
    }

    #endregion
#endif
}