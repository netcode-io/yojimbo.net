/*
    reliable.io reference implementation

    Copyright © 2017, The Network Protocol Company, Inc.

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
using System.Diagnostics;

namespace networkprotocol
{
    public static partial class reliable
    {
        static void check_handler(string condition, string function, string file, int line)
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
                check_handler(null, stackFrame.GetMethod().Name, stackFrame.GetFileName(), stackFrame.GetFileLineNumber());
            }
        }

        static void test_endian()
        {
            const ulong value = 0x11223344U;

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

        class test_sequence_data_t
        {
            public ushort sequence;
        }

        const int TEST_SEQUENCE_BUFFER_SIZE = 256;

        static void test_sequence_buffer()
        {
            var sequence_buffer = sequence_buffer_create<test_sequence_data_t>(
                TEST_SEQUENCE_BUFFER_SIZE,
                //typeof(test_sequence_data_t),
                null,
                null,
                null);

            check(sequence_buffer != null);
            check(sequence_buffer.sequence == 0);
            check(sequence_buffer.num_entries == TEST_SEQUENCE_BUFFER_SIZE);
            //check(sequence_buffer.entry_stride == typeof(test_sequence_data_t));

            int i;
            for (i = 0; i < TEST_SEQUENCE_BUFFER_SIZE; ++i)
                check(sequence_buffer_find(sequence_buffer, (ushort)i) == null);

            for (i = 0; i <= TEST_SEQUENCE_BUFFER_SIZE * 4; ++i)
            {
                var entry = sequence_buffer_insert(sequence_buffer, (ushort)i);
                check(entry != null);
                entry.sequence = (ushort)i;
                check(sequence_buffer.sequence == i + 1);
            }

            for (i = 0; i <= TEST_SEQUENCE_BUFFER_SIZE; ++i)
            {
                var entry = sequence_buffer_insert(sequence_buffer, (ushort)i);
                check(entry == null);
            }

            var index = TEST_SEQUENCE_BUFFER_SIZE * 4;
            for (i = 0; i < TEST_SEQUENCE_BUFFER_SIZE; ++i)
            {
                var entry = sequence_buffer_find(sequence_buffer, (ushort)index);
                check(entry != null);
                check(entry.sequence == (ushort)index);
                index--;
            }

            sequence_buffer_reset(sequence_buffer);

            check(sequence_buffer != null);
            check(sequence_buffer.sequence == 0);
            check(sequence_buffer.num_entries == TEST_SEQUENCE_BUFFER_SIZE);
            //check(sequence_buffer.entry_stride == typeof(test_sequence_data_t));

            for (i = 0; i < TEST_SEQUENCE_BUFFER_SIZE; ++i)
                check(sequence_buffer_find(sequence_buffer, (ushort)i) == null);

            sequence_buffer_destroy(ref sequence_buffer);
        }

        static void test_generate_ack_bits()
        {
            var sequence_buffer = sequence_buffer_create<test_sequence_data_t>(
                TEST_SEQUENCE_BUFFER_SIZE,
                //typeof(test_sequence_data_t),
                null,
                null,
                null);

            sequence_buffer_generate_ack_bits(sequence_buffer, out var ack, out var ack_bits);
            check(ack == 0xFFFF);
            check(ack_bits == 0);

            int i;
            for (i = 0; i <= TEST_SEQUENCE_BUFFER_SIZE; ++i)
                sequence_buffer_insert(sequence_buffer, (ushort)i);

            sequence_buffer_generate_ack_bits(sequence_buffer, out ack, out ack_bits);
            check(ack == TEST_SEQUENCE_BUFFER_SIZE);
            check(ack_bits == 0xFFFFFFFF);

            sequence_buffer_reset(sequence_buffer);

            var input_acks = new ushort[] { 1, 5, 9, 11 };
            var input_num_acks = input_acks.Length;
            for (i = 0; i < input_num_acks; ++i)
                sequence_buffer_insert(sequence_buffer, input_acks[i]);

            sequence_buffer_generate_ack_bits(sequence_buffer, out ack, out ack_bits);

            check(ack == 11);
            check(ack_bits == (1 | (1 << (11 - 9)) | (1 << (11 - 5)) | (1 << (11 - 1))));

            sequence_buffer_destroy(ref sequence_buffer);
        }

        static void test_packet_header()
        {
            var packet_data = new byte[MAX_PACKET_HEADER_BYTES];

            // worst case, sequence and ack are far apart, no packets acked.

            ushort write_sequence = 10000;
            ushort write_ack = 100;
            var write_ack_bits = 0U;

            var bytes_written = write_packet_header(packet_data, write_sequence, write_ack, write_ack_bits);

            check(bytes_written == MAX_PACKET_HEADER_BYTES);

            var bytes_read = read_packet_header("test_packet_header", packet_data, 0, bytes_written, out var read_sequence, out var read_ack, out var read_ack_bits);

            check(bytes_read == bytes_written);

            check(read_sequence == write_sequence);
            check(read_ack == write_ack);
            check(read_ack_bits == write_ack_bits);

            // rare case. sequence and ack are far apart, significant # of acks are missing

            write_sequence = 10000;
            write_ack = 100;
            write_ack_bits = 0xFEFEFFFEU;

            bytes_written = write_packet_header(packet_data, write_sequence, write_ack, write_ack_bits);

            check(bytes_written == 1 + 2 + 2 + 3);

            bytes_read = read_packet_header("test_packet_header", packet_data, 0, bytes_written, out read_sequence, out read_ack, out read_ack_bits);

            check(bytes_read == bytes_written);

            check(read_sequence == write_sequence);
            check(read_ack == write_ack);
            check(read_ack_bits == write_ack_bits);

            // common case under packet loss. sequence and ack are close together, some acks are missing

            write_sequence = 200;
            write_ack = 100;
            write_ack_bits = 0xFFFEFFFF;

            bytes_written = write_packet_header(packet_data, write_sequence, write_ack, write_ack_bits);

            check(bytes_written == 1 + 2 + 1 + 1);

            bytes_read = read_packet_header("test_packet_header", packet_data, 0, bytes_written, out read_sequence, out read_ack, out read_ack_bits);

            check(bytes_read == bytes_written);

            check(read_sequence == write_sequence);
            check(read_ack == write_ack);
            check(read_ack_bits == write_ack_bits);

            // ideal case. no packet loss.

            write_sequence = 200;
            write_ack = 100;
            write_ack_bits = 0xFFFFFFFF;

            bytes_written = write_packet_header(packet_data, write_sequence, write_ack, write_ack_bits);

            check(bytes_written == 1 + 2 + 1);

            bytes_read = read_packet_header("test_packet_header", packet_data, 0, bytes_written, out read_sequence, out read_ack, out read_ack_bits);

            check(bytes_read == bytes_written);

            check(read_sequence == write_sequence);
            check(read_ack == write_ack);
            check(read_ack_bits == write_ack_bits);
        }

        class test_context_t
        {
            public bool drop;
            public reliable_endpoint_t sender;
            public reliable_endpoint_t receiver;
        }

        static void test_transmit_packet_function(object _context, int index, ushort sequence, byte[] packet_data, int packet_bytes)
        {
            var context = (test_context_t)_context;

            if (context.drop)
                return;

            if (index == 0)
                endpoint_receive_packet(context.receiver, packet_data, packet_bytes);
            else if (index == 1)
                endpoint_receive_packet(context.sender, packet_data, packet_bytes);
        }

        static bool test_process_packet_function(object _context, int index, ushort sequence, byte[] packet_data, int packet_bytes)
        {
            var context = (test_context_t)_context;

            return true;
        }

        const int TEST_ACKS_NUM_ITERATIONS = 256;

        static void test_acks()
        {
            var time = 100.0;

            var context = new test_context_t();

            default_config(out var sender_config);
            default_config(out var receiver_config);

            sender_config.context = context;
            sender_config.index = 0;
            sender_config.transmit_packet_function = test_transmit_packet_function;
            sender_config.process_packet_function = test_process_packet_function;

            receiver_config.context = context;
            receiver_config.index = 1;
            receiver_config.transmit_packet_function = test_transmit_packet_function;
            receiver_config.process_packet_function = test_process_packet_function;

            context.sender = endpoint_create(sender_config, time);
            context.receiver = endpoint_create(receiver_config, time);

            const double delta_time = 0.01;

            int i;
            for (i = 0; i < TEST_ACKS_NUM_ITERATIONS; ++i)
            {
                var dummy_packet = new byte[8];

                endpoint_send_packet(context.sender, dummy_packet, dummy_packet.Length);
                endpoint_send_packet(context.receiver, dummy_packet, dummy_packet.Length);

                endpoint_update(context.sender, time);
                endpoint_update(context.receiver, time);

                time += delta_time;
            }

            var sender_acked_packet = new byte[TEST_ACKS_NUM_ITERATIONS];
            var sender_acks = endpoint_get_acks(context.sender, out var sender_num_acks);
            for (i = 0; i < sender_num_acks; ++i)
                if (sender_acks[i] < TEST_ACKS_NUM_ITERATIONS)
                    sender_acked_packet[sender_acks[i]] = 1;
            for (i = 0; i < TEST_ACKS_NUM_ITERATIONS / 2; ++i)
                check(sender_acked_packet[i] == 1);

            var receiver_acked_packet = new byte[TEST_ACKS_NUM_ITERATIONS];
            var receiver_acks = endpoint_get_acks(context.receiver, out var receiver_num_acks);
            for (i = 0; i < receiver_num_acks; ++i)
                if (receiver_acks[i] < TEST_ACKS_NUM_ITERATIONS)
                    receiver_acked_packet[receiver_acks[i]] = 1;
            for (i = 0; i < TEST_ACKS_NUM_ITERATIONS / 2; ++i)
                check(receiver_acked_packet[i] == 1);

            endpoint_destroy(ref context.sender);
            endpoint_destroy(ref context.receiver);
        }

        static void test_acks_packet_loss()
        {
            var time = 100.0;

            var context = new test_context_t();

            default_config(out var sender_config);
            default_config(out var receiver_config);

            sender_config.context = context;
            sender_config.index = 0;
            sender_config.transmit_packet_function = test_transmit_packet_function;
            sender_config.process_packet_function = test_process_packet_function;

            receiver_config.context = context;
            receiver_config.index = 1;
            receiver_config.transmit_packet_function = test_transmit_packet_function;
            receiver_config.process_packet_function = test_process_packet_function;

            context.sender = endpoint_create(sender_config, time);
            context.receiver = endpoint_create(receiver_config, time);

            const double delta_time = 0.1;

            int i;
            for (i = 0; i < TEST_ACKS_NUM_ITERATIONS; ++i)
            {
                var dummy_packet = new byte[8];

                context.drop = (i % 2) != 0;

                endpoint_send_packet(context.sender, dummy_packet, dummy_packet.Length);
                endpoint_send_packet(context.receiver, dummy_packet, dummy_packet.Length);

                endpoint_update(context.sender, time);
                endpoint_update(context.receiver, time);

                time += delta_time;
            }

            var sender_acked_packet = new byte[TEST_ACKS_NUM_ITERATIONS];
            var sender_acks = endpoint_get_acks(context.sender, out var sender_num_acks);
            for (i = 0; i < sender_num_acks; ++i)
                if (sender_acks[i] < TEST_ACKS_NUM_ITERATIONS)
                    sender_acked_packet[sender_acks[i]] = 1;
            for (i = 0; i < TEST_ACKS_NUM_ITERATIONS / 2; ++i)
                check(sender_acked_packet[i] == (i + 1) % 2);

            var receiver_acked_packet = new byte[TEST_ACKS_NUM_ITERATIONS];
            var receiver_acks = endpoint_get_acks(context.sender, out var receiver_num_acks);
            for (i = 0; i < receiver_num_acks; ++i)
                if (receiver_acks[i] < TEST_ACKS_NUM_ITERATIONS)
                    receiver_acked_packet[receiver_acks[i]] = 1;
            for (i = 0; i < TEST_ACKS_NUM_ITERATIONS / 2; ++i)
                check(receiver_acked_packet[i] == (i + 1) % 2);

            endpoint_destroy(ref context.sender);
            endpoint_destroy(ref context.receiver);
        }

        const int TEST_MAX_PACKET_BYTES = 4 * 1024;

        static int generate_packet_data(ushort sequence, byte[] packet_data)
        {
            var packet_bytes = ((sequence * 1023) % (TEST_MAX_PACKET_BYTES - 2)) + 2;
            assert(packet_bytes >= 2);
            assert(packet_bytes <= TEST_MAX_PACKET_BYTES);
            packet_data[0] = (byte)(sequence & 0xFF);
            packet_data[1] = (byte)((sequence >> 8) & 0xFF);
            int i;
            for (i = 2; i < packet_bytes; ++i)
                packet_data[i] = (byte)((i + sequence) % 256);
            return packet_bytes;
        }

        static void validate_packet_data(byte[] packet_data, int packet_bytes)
        {
            assert(packet_bytes >= 2);
            assert(packet_bytes <= TEST_MAX_PACKET_BYTES);
            ushort sequence = 0;
            sequence |= packet_data[0];
            sequence |= (ushort)(packet_data[1] << 8);
            check(packet_bytes == (sequence * 1023 % (TEST_MAX_PACKET_BYTES - 2)) + 2);
            int i;
            for (i = 2; i < packet_bytes; ++i)
                check(packet_data[i] == (byte)((i + sequence) % 256));
        }

        static bool test_process_packet_function_validate(object context, int index, ushort sequence, byte[] packet_data, int packet_bytes)
        {
            assert(packet_data != null);
            assert(packet_bytes > 0);
            assert(packet_bytes <= TEST_MAX_PACKET_BYTES);

            validate_packet_data(packet_data, packet_bytes);

            return true;
        }

        static void test_packets()
        {
            var time = 100.0;

            var context = new test_context_t();

            default_config(out var sender_config);
            default_config(out var receiver_config);

            sender_config.fragment_above = 500;
            receiver_config.fragment_above = 500;

            sender_config.name = "sender";
            sender_config.context = context;
            sender_config.index = 0;
            sender_config.transmit_packet_function = test_transmit_packet_function;
            sender_config.process_packet_function = test_process_packet_function_validate;

            receiver_config.name = "receiver";
            receiver_config.context = context;
            receiver_config.index = 1;
            receiver_config.transmit_packet_function = test_transmit_packet_function;
            receiver_config.process_packet_function = test_process_packet_function_validate;

            context.sender = endpoint_create(sender_config, time);
            context.receiver = endpoint_create(receiver_config, time);

            const double delta_time = 0.1;

            int i;
            for (i = 0; i < 16; ++i)
            {
                {
                    var packet_data = new byte[TEST_MAX_PACKET_BYTES];
                    var sequence = endpoint_next_packet_sequence(context.sender);
                    var packet_bytes = generate_packet_data(sequence, packet_data);
                    endpoint_send_packet(context.sender, packet_data, packet_bytes);
                }

                {
                    var packet_data = new byte[TEST_MAX_PACKET_BYTES];
                    var sequence = endpoint_next_packet_sequence(context.sender);
                    var packet_bytes = generate_packet_data(sequence, packet_data);
                    endpoint_send_packet(context.sender, packet_data, packet_bytes);
                }

                endpoint_update(context.sender, time);
                endpoint_update(context.receiver, time);

                endpoint_clear_acks(context.sender);
                endpoint_clear_acks(context.receiver);

                time += delta_time;
            }

            endpoint_destroy(ref context.sender);
            endpoint_destroy(ref context.receiver);
        }

        static void test_sequence_buffer_rollover()
        {
            var time = 100.0;

            var context = new test_context_t();

            default_config(out var sender_config);
            default_config(out var receiver_config);

            sender_config.fragment_above = 500;
            receiver_config.fragment_above = 500;

            sender_config.name = "sender";
            sender_config.context = context;
            sender_config.index = 0;
            sender_config.transmit_packet_function = test_transmit_packet_function;
            sender_config.process_packet_function = test_process_packet_function;

            receiver_config.name = "receiver";
            receiver_config.context = context;
            receiver_config.index = 1;
            receiver_config.transmit_packet_function = test_transmit_packet_function;
            receiver_config.process_packet_function = test_process_packet_function;

            context.sender = endpoint_create(sender_config, time);
            context.receiver = endpoint_create(receiver_config, time);

            int num_packets_sent = 0;
            int i;
            for (i = 0; i <= 32767; ++i)
            {
                var packet_data = new byte[16];
                var packet_bytes = 16;
                endpoint_next_packet_sequence(context.sender);
                endpoint_send_packet(context.sender, packet_data, packet_bytes);

                ++num_packets_sent;
            }

            {
                var packet_data = new byte[TEST_MAX_PACKET_BYTES];
                var packet_bytes = TEST_MAX_PACKET_BYTES;
                endpoint_next_packet_sequence(context.sender);
                endpoint_send_packet(context.sender, packet_data, packet_bytes);
                ++num_packets_sent;
            }

            var receiver_counters = endpoint_counters(context.receiver);

            check(receiver_counters[ENDPOINT_COUNTER_NUM_PACKETS_RECEIVED] == (ushort)num_packets_sent);
            check(receiver_counters[ENDPOINT_COUNTER_NUM_FRAGMENTS_INVALID] == 0);

            endpoint_destroy(ref context.sender);
            endpoint_destroy(ref context.receiver);
        }

        public static void test()
        {
            //log_level(LOG_LEVEL_DEBUG);
            //while (true)
            {
                Console.WriteLine("test_endian"); test_endian();
                Console.WriteLine("test_sequence_buffer"); test_sequence_buffer();
                Console.WriteLine("test_generate_ack_bits"); test_generate_ack_bits();
                Console.WriteLine("test_packet_header"); test_packet_header();
                Console.WriteLine("test_acks"); test_acks();
                Console.WriteLine("test_acks_packet_loss"); test_acks_packet_loss();
                Console.WriteLine("test_packets"); test_packets();
                Console.WriteLine("test_sequence_buffer_rollover"); test_sequence_buffer_rollover();
            }
        }
    }
}
