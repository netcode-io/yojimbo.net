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

using networkprotocol;
using System;
using System.Diagnostics;

public static class stats
{
    const int MAX_PACKET_BYTES = 290;

    static volatile bool quit = false;

    static void interrupt_handler(object sender, ConsoleCancelEventArgs e) { quit = true; e.Cancel = true; }

    static int random_int(int a, int b)
    {
        Debug.Assert(a < b);
        var result = a + BufferEx.Rand() % (b - a + 1);
        Debug.Assert(result >= a);
        Debug.Assert(result <= b);
        return result;
    }

    class test_context_t
    {
        public reliable_endpoint_t client;
        public reliable_endpoint_t server;
    }

    static double global_time = 100.0;

    static test_context_t global_context;

    static void test_transmit_packet_function(object _context, int index, ushort sequence, byte[] packet_data, int packet_bytes)
    {
        var context = (test_context_t)_context;

        if ((sequence % 5) == 0)
            return;

        if (index == 0)
            reliable.endpoint_receive_packet(context.server, packet_data, packet_bytes);
        else if (index == 1)
            reliable.endpoint_receive_packet(context.client, packet_data, packet_bytes);
    }

    static int generate_packet_data(ushort sequence, byte[] packet_data)
    {
        var packet_bytes = MAX_PACKET_BYTES;
        Debug.Assert(packet_bytes >= 2);
        Debug.Assert(packet_bytes <= MAX_PACKET_BYTES);
        packet_data[0] = (byte)sequence;
        packet_data[1] = (byte)(sequence >> 8);
        int i;
        for (i = 2; i < packet_bytes; ++i)
            packet_data[i] = (byte)((i + sequence) % 256);
        return packet_bytes;
    }

    static void check_handler(string condition, string function, string file, int line)
    {
        Console.Write($"check failed: ( {condition} ), function {function}, file {file}, line {line}\n");
        Environment.Exit(1);
    }

    [Conditional("DEBUG")]
    public static void check(bool condition)
    {
        if (!condition)
        {
            var stackFrame = new StackTrace().GetFrame(1);
            check_handler(null, stackFrame.GetMethod().Name, stackFrame.GetFileName(), stackFrame.GetFileLineNumber());
        }
    }

    static void check_packet_data(byte[] packet_data, int packet_bytes)
    {
        Debug.Assert(packet_bytes == MAX_PACKET_BYTES);
        ushort sequence = 0;
        sequence |= packet_data[0];
        sequence |= (ushort)(packet_data[1] << 8);
        int i;
        for (i = 2; i < packet_bytes; ++i)
            check(packet_data[i] == (byte)((i + sequence) % 256));
    }

    static bool test_process_packet_function(object context, int index, ushort sequence, byte[] packet_data, int packet_bytes)
    {
        Debug.Assert(packet_data != null);
        Debug.Assert(packet_bytes > 0);
        Debug.Assert(packet_bytes <= MAX_PACKET_BYTES);

        check_packet_data(packet_data, packet_bytes);

        return true;
    }

    static void stats_initialize()
    {
        Console.Write("initializing\n");

        reliable.init();

        global_context = new test_context_t();

        reliable.default_config(out var client_config);
        reliable.default_config(out var server_config);

        client_config.fragment_above = MAX_PACKET_BYTES;
        server_config.fragment_above = MAX_PACKET_BYTES;

        client_config.name = "client";
        client_config.context = global_context;
        client_config.index = 0;
        client_config.transmit_packet_function = test_transmit_packet_function;
        client_config.process_packet_function = test_process_packet_function;

        server_config.name = "server";
        server_config.context = global_context;
        server_config.index = 1;
        server_config.transmit_packet_function = test_transmit_packet_function;
        server_config.process_packet_function = test_process_packet_function;

        global_context.client = reliable.endpoint_create(client_config, global_time);
        global_context.server = reliable.endpoint_create(server_config, global_time);
    }

    static void stats_shutdown()
    {
        Console.Write("shutdown\n");

        reliable.endpoint_destroy(ref global_context.client);
        reliable.endpoint_destroy(ref global_context.server);

        reliable.term();
    }

    static void stats_iteration(double time)
    {
        var packet_data = new byte[MAX_PACKET_BYTES];
        int packet_bytes;
        ushort sequence;

        sequence = reliable.endpoint_next_packet_sequence(global_context.client);
        packet_bytes = generate_packet_data(sequence, packet_data);
        reliable.endpoint_send_packet(global_context.client, packet_data, packet_bytes);

        sequence = reliable.endpoint_next_packet_sequence(global_context.server);
        packet_bytes = generate_packet_data(sequence, packet_data);
        reliable.endpoint_send_packet(global_context.server, packet_data, packet_bytes);

        reliable.endpoint_update(global_context.client, time);
        reliable.endpoint_update(global_context.server, time);

        reliable.endpoint_clear_acks(global_context.client);
        reliable.endpoint_clear_acks(global_context.server);

        var counters = reliable.endpoint_counters(global_context.client);

        reliable.endpoint_bandwidth(global_context.client, out var sent_bandwidth_kbps, out var received_bandwidth_kbps, out var acked_bandwidth_kbps);

        Console.Write("{0} sent | {1} received | {2} acked | rtt = {3}ms | packet loss = {4}% | sent = {5}kbps | recv = {6}kbps | acked = {7}kbps\n",
            counters[reliable.ENDPOINT_COUNTER_NUM_PACKETS_SENT],
            counters[reliable.ENDPOINT_COUNTER_NUM_PACKETS_RECEIVED],
            counters[reliable.ENDPOINT_COUNTER_NUM_PACKETS_ACKED],
            (int)reliable.endpoint_rtt(global_context.client),
            (int)Math.Floor(reliable.endpoint_packet_loss(global_context.client) + 0.5f),
            (int)sent_bandwidth_kbps,
            (int)received_bandwidth_kbps,
            (int)acked_bandwidth_kbps);
    }

    static int Main(string[] args)
    {
        var num_iterations = -1;

        if (args.Length == 2)
            num_iterations = int.Parse(args[1]);

        stats_initialize();

        Console.CancelKeyPress += interrupt_handler;

        const double delta_time = 0.01;

        if (num_iterations > 0)
        {
            int i;
            for (i = 0; i < num_iterations; ++i)
            {
                if (quit)
                    break;

                stats_iteration(global_time);

                global_time += delta_time;
            }
        }
        else
            while (!quit)
            {
                stats_iteration(global_time);

                global_time += delta_time;
            }

        stats_shutdown();

        return 0;
    }
}