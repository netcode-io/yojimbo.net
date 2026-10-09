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

public static class fuzz
{
    const int MAX_PACKET_BYTES = 16 * 1024;

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

    static double global_time = 100.0;

    static reliable_endpoint_t endpoint;

    static void test_transmit_packet_function(object context, int index, ushort sequence, byte[] packet_data, int packet_bytes)
    {
    }

    static bool test_process_packet_function(object context, int index, ushort sequence, byte[] packet_data, int packet_bytes)
    {
        return true;
    }

    static void fuzz_initialize()
    {
        reliable.init();

        reliable.default_config(out var config);

        config.index = 0;
        config.transmit_packet_function = test_transmit_packet_function;
        config.process_packet_function = test_process_packet_function;

        endpoint = reliable.endpoint_create(config, global_time);
    }

    static void fuzz_shutdown()
    {
        Console.Write("shutdown\n");

        reliable.endpoint_destroy(ref endpoint);

        reliable.term();
    }

    static void fuzz_iteration(double time)
    {
        Console.Write(".");
        Console.Out.Flush();

        var packet_data = new byte[MAX_PACKET_BYTES];
        var packet_bytes = random_int(1, MAX_PACKET_BYTES);
        int i;
        for (i = 0; i < packet_bytes; ++i)
            packet_data[i] = (byte)(BufferEx.Rand() % 256);

        reliable.endpoint_receive_packet(endpoint, packet_data, packet_bytes);

        reliable.endpoint_update(endpoint, time);

        reliable.endpoint_clear_acks(endpoint);
    }

    static int Main(string[] args)
    {
        Console.Write("[fuzz]\n");

        var num_iterations = -1;

        if (args.Length == 2)
            num_iterations = int.Parse(args[1]);

        fuzz_initialize();

        Console.CancelKeyPress += interrupt_handler;

        const double delta_time = 0.1;

        if (num_iterations > 0)
        {
            int i;
            for (i = 0; i < num_iterations; ++i)
            {
                if (quit)
                    break;

                fuzz_iteration(global_time);

                global_time += delta_time;
            }
        }
        else
            while (!quit)
            {
                fuzz_iteration(global_time);

                global_time += delta_time;
            }

        fuzz_shutdown();

        return 0;
    }
}