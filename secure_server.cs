/*
    Yojimbo Secure Server Example.

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
using System;
using static networkprotocol.yojimbo;

public static class secure_server
{
    static volatile bool quit = false;

    static void interrupt_handler(object sender, ConsoleCancelEventArgs e) { quit = true; e.Cancel = true; }

    static int ServerMain()
    {
        Console.Write($"started server on port {shared.ServerPort} (secure)\n");

        var time = 100.0;

        var config = new ClientServerConfig();
        config.protocolId = shared.ProtocolId;

        var privateKey = new byte[KeyBytes] {
        0x60, 0x6a, 0xbe, 0x6e, 0xc9, 0x19, 0x10, 0xea,
        0x9a, 0x65, 0x62, 0xf6, 0x6f, 0x2b, 0x30, 0xe4,
        0x43, 0x71, 0xd6, 0x2c, 0xd1, 0x99, 0x27, 0x26,
        0x6b, 0x3c, 0x60, 0xf4, 0xb7, 0x15, 0xab, 0xa1 };

        var server = new Server(DefaultAllocator, privateKey, new Address("127.0.0.1", shared.ServerPort), config, shared.adapter, time);

        server.Start(MaxClients);

        const double deltaTime = 0.1;

        var addressString = server.Address.ToString();
        Console.Write($"server address is {addressString}\n");

        Console.CancelKeyPress += interrupt_handler;

        while (!quit)
        {
            server.SendPackets();

            server.ReceivePackets();

            time += deltaTime;

            server.AdvanceTime(time);

            if (!server.IsRunning)
                break;

            sleep(deltaTime);
        }

        server.Stop();

        return 0;
    }

    static int Main(string[] args)
    {
        Console.Write("\n");

        if (!InitializeYojimbo())
        {
            Console.Write("error: failed to initialize Yojimbo!\n");
            return 1;
        }

        log_level(LOG_LEVEL_INFO);

        var result = ServerMain();

        ShutdownYojimbo();

        Console.Write("\n");

        return result;
    }
}