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

public static class client
{
    const int CONNECT_TOKEN_EXPIRY = 30;
    const int CONNECT_TOKEN_TIMEOUT = 5;
    const ulong PROTOCOL_ID = 0x1122334455667788;

    static volatile bool quit = false;

    static void interrupt_handler(object sender, ConsoleCancelEventArgs e) { quit = true; e.Cancel = true; }

    static readonly byte[] private_key = new byte[netcode.KEY_BYTES] {
        0x60, 0x6a, 0xbe, 0x6e, 0xc9, 0x19, 0x10, 0xea,
        0x9a, 0x65, 0x62, 0xf6, 0x6f, 0x2b, 0x30, 0xe4,
        0x43, 0x71, 0xd6, 0x2c, 0xd1, 0x99, 0x27, 0x26,
        0x6b, 0x3c, 0x60, 0xf4, 0xb7, 0x15, 0xab, 0xa1 };

    static int Main(string[] args)
    {
        if (netcode.init() != netcode.OK)
        {
            Console.Write("error: failed to initialize netcode.io\n");
            return 1;
        }

        netcode.log_level(netcode.LOG_LEVEL_INFO);

        var time = 0.0;
        const double delta_time = 1.0 / 60.0;

        Console.Write("[client]\n");

        netcode.default_client_config(out var client_config);
        var client = netcode.client_create("0.0.0.0", client_config, time);

        if (client == null)
        {
            Console.Write("error: failed to create client\n");
            return 1;
        }

        var server_address = (args.Length != 2) ? "127.0.0.1:40000" : args[1];

        var client_id = 0UL;
        netcode.random_bytes(ref client_id, 8);
        Console.Write($"client id is {client_id,16}\n");

        var user_data = new byte[netcode.USER_DATA_BYTES];
        netcode.random_bytes(user_data, netcode.USER_DATA_BYTES);

        var connect_token = new byte[netcode.CONNECT_TOKEN_BYTES];

        if (netcode.generate_connect_token(1, new[] { server_address }, new[] { server_address }, CONNECT_TOKEN_EXPIRY, CONNECT_TOKEN_TIMEOUT, client_id, PROTOCOL_ID, private_key, user_data, connect_token) != netcode.OK)
        {
            Console.Write("error: failed to generate connect token\n");
            return 1;
        }

        netcode.client_connect(client, connect_token);

        Console.CancelKeyPress += interrupt_handler;

        var packet_data = new byte[netcode.MAX_PACKET_SIZE];
        int i;
        for (i = 0; i < netcode.MAX_PACKET_SIZE; ++i)
            packet_data[i] = (byte)i;

        while (!quit)
        {
            netcode.client_update(client, time);

            if (netcode.client_state(client) == netcode.CLIENT_STATE_CONNECTED)
                netcode.client_send_packet(client, packet_data, netcode.MAX_PACKET_SIZE);

            while (true)
            {
                var packet = netcode.client_receive_packet(client, out var packet_bytes, out var packet_sequence);
                if (packet == null)
                    break;
                Debug.Assert(packet_bytes == netcode.MAX_PACKET_SIZE);
                Debug.Assert(BufferEx.Equal(packet, packet_data, netcode.MAX_PACKET_SIZE));
                netcode.client_free_packet(client, ref packet);
            }

            if (netcode.client_state(client) <= netcode.CLIENT_STATE_DISCONNECTED)
                break;

            netcode.sleep(delta_time);

            time += delta_time;
        }

        if (quit)
            Console.Write("\nshutting down\n");

        netcode.client_destroy(ref client);

        netcode.term();

        return 0;
    }

}