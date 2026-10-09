/*
    netcode.io reference implementation

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

public static class soak
{
    const int MAX_SERVERS = 64;
    const int MAX_CLIENTS = 1024;
    const int SERVER_BASE_PORT = 40000;
    const int CONNECT_TOKEN_EXPIRY = 45;
    const int CONNECT_TOKEN_TIMEOUT = 5;
    const ulong PROTOCOL_ID = 0x1122334455667788;

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

    static float random_float(float a, float b)
    {
        Debug.Assert(a < b);
        var random = BufferEx.Rand() / (float)BufferEx.RAND_MAX;
        var diff = b - a;
        var r = random * diff;
        return a + r;
    }

    static netcode_server_t[] server = new netcode_server_t[MAX_SERVERS];
    static netcode_client_t[] client = new netcode_client_t[MAX_CLIENTS];
    static byte[] packet_data = new byte[netcode.MAX_PACKET_SIZE];
    static byte[] private_key = new byte[netcode.KEY_BYTES];

    static void soak_initialize()
    {
        Console.Write("initializing\n");

        netcode.init();

        netcode.log_level(netcode.LOG_LEVEL_INFO);

        netcode.random_bytes(private_key, netcode.KEY_BYTES);

        int i;
        for (i = 0; i < netcode.MAX_PACKET_SIZE; ++i)
            packet_data[i] = (byte)i;
    }

    static void soak_shutdown()
    {
        Console.Write("shutdown\n");

        int i;

        for (i = 0; i < MAX_SERVERS; ++i)
            if (server[i] != null)
            {
                netcode.server_destroy(ref server[i]);
                server[i] = null;
            }

        for (i = 0; i < MAX_CLIENTS; ++i)
            if (client[i] != null)
            {
                netcode.client_destroy(ref client[i]);
                client[i] = null;
            }

        netcode.term();
    }

    static void soak_iteration(double time)
    {
        int i;

        netcode.default_server_config(out var server_config);
        server_config.protocol_id = PROTOCOL_ID;
        BufferEx.Copy(server_config.private_key, private_key, netcode.KEY_BYTES);

        for (i = 0; i < MAX_SERVERS; ++i)
        {
            if (server[i] == null && random_int(0, 10) == 0)
            {
                var server_address = $"127.0.0.1:{SERVER_BASE_PORT + i }";
                server[i] = netcode.server_create(server_address, server_config, time);

                Console.Write($"created server {server[i]}\n");
            }

            if (server[i] != null && netcode.server_num_connected_clients(server[i]) == netcode.server_max_clients(server[i]) && random_int(0, 10000) == 0)
            {
                Console.Write($"destroy server {server[i]}\n");
                netcode.server_destroy(ref server[i]);
                server[i] = null;
            }
        }

        for (i = 0; i < MAX_CLIENTS; ++i)
        {
            if (client[i] == null && random_int(0, 10) == 0)
            {
                netcode.default_client_config(out var client_config);
                client[i] = netcode.client_create("0.0.0.0", client_config, time);
                Console.Write($"created client {client[i]}\n");
            }

            if (client[i] != null && random_int(0, 1000) == 0)
            {
                Console.Write($"destroy client {client[i]}\n");
                netcode.client_destroy(ref client[i]);
                client[i] = null;
            }
        }

        for (i = 0; i < MAX_SERVERS; ++i)
        {
            if (server[i] != null)
            {
                if (random_int(0, 10) == 0 && !netcode.server_running(server[i]))
                    netcode.server_start(server[i], random_int(1, netcode.MAX_CLIENTS));

                if (random_int(0, 1000) == 0 && netcode.server_num_connected_clients(server[i]) == netcode.server_max_clients(server[i]) && netcode.server_running(server[i]))
                    netcode.server_stop(server[i]);

                if (netcode.server_running(server[i]))
                {
                    var max_clients = netcode.server_max_clients(server[i]);
                    int client_index;
                    for (client_index = 0; client_index < max_clients; ++client_index)
                        if (netcode.server_client_connected(server[i], client_index))
                            netcode.server_send_packet(server[i], 0, packet_data, random_int(1, netcode.MAX_PACKET_SIZE));

                    for (client_index = 0; client_index < max_clients; ++client_index)
                        if (netcode.server_client_connected(server[i], client_index))
                            while (true)
                            {
                                var packet = netcode.server_receive_packet(server[i], client_index, out var packet_bytes, out var packet_sequence);
                                if (packet == null)
                                    break;
                                Debug.Assert(BufferEx.Equal(packet, packet_data, (int)packet_bytes));
                                netcode.server_free_packet(server[i], ref packet);
                            }
                }

                netcode.server_update(server[i], time);
            }

        }

        for (i = 0; i < MAX_CLIENTS; ++i)
            if (client[i] != null)
            {
                if (random_int(0, 10) == 0 && netcode.client_state(client[i]) <= netcode.CLIENT_STATE_DISCONNECTED)
                {
                    var client_id = 0UL;
                    netcode.random_bytes(ref client_id, 8);

                    var user_data = new byte[netcode.USER_DATA_BYTES];
                    netcode.random_bytes(user_data, netcode.USER_DATA_BYTES);

                    var connect_token = new byte[netcode.CONNECT_TOKEN_BYTES];

                    var num_server_addresses = 0;
                    var server_address = new string[netcode.MAX_SERVERS_PER_CONNECT];
                    int j;
                    for (j = 0; j < MAX_SERVERS; ++j)
                    {
                        if (num_server_addresses == netcode.MAX_SERVERS_PER_CONNECT)
                            break;

                        if (server[j] != null && netcode.server_running(server[j]))
                        {
                            server_address[num_server_addresses] = $"127.0.0.1:{SERVER_BASE_PORT + j}";
                            num_server_addresses++;
                        }
                    }

                    if (num_server_addresses > 0 && netcode.generate_connect_token(num_server_addresses, server_address, server_address, CONNECT_TOKEN_EXPIRY, CONNECT_TOKEN_TIMEOUT, client_id, PROTOCOL_ID, private_key, user_data, connect_token) == netcode.OK)
                        netcode.client_connect(client[i], connect_token);

                    for (j = 0; j < num_server_addresses; ++j)
                        server_address[j] = null;
                }

                if (random_int(0, 100) == 0 && netcode.client_state(client[i]) == netcode.CLIENT_STATE_CONNECTED)
                    netcode.client_disconnect(client[i]);

                if (netcode.client_state(client[i]) == netcode.CLIENT_STATE_CONNECTED)
                {
                    netcode.client_send_packet(client[i], packet_data, random_int(1, netcode.MAX_PACKET_SIZE));

                    while (true)
                    {
                        var packet = netcode.client_receive_packet(client[i], out var packet_bytes, out var packet_sequence);
                        if (packet == null)
                            break;
                        Debug.Assert(BufferEx.Equal(packet, packet_data, packet_bytes));
                        netcode.client_free_packet(client[i], ref packet);
                    }
                }

                netcode.client_update(client[i], time);
            }
    }

    static int Main(string[] args)
    {
        var num_iterations = -1;

        if (args.Length == 2)
            num_iterations = int.Parse(args[1]);

        Console.Write($"[soak]\nnum_iterations = {num_iterations}\n");

        soak_initialize();

        Console.Write("starting\n");

        Console.CancelKeyPress += interrupt_handler;

        var time = 0.0;
        const double delta_time = 0.1;

        if (num_iterations > 0)
        {
            int i;
            for (i = 0; i < num_iterations; ++i)
            {
                if (quit)
                    break;

                soak_iteration(time);

                time += delta_time;
            }
        }
        else
            while (!quit)
            {
                soak_iteration(time);

                time += delta_time;
            }

        soak_shutdown();

        return 0;
    }
}