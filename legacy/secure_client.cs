/*
    Yojimbo Secure Client Example.

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

public static class secure_client
{
    static volatile bool quit = false;

    static void interrupt_handler(object sender, ConsoleCancelEventArgs e) { quit = true; e.Cancel = true; }

    static int ClientMain(string[] args)
    {
        Console.Write("\nconnecting client (secure)\n");

        var clientId = 0UL;
        random_bytes(ref clientId, 8);
        Console.Write($"client id is {clientId:x16}\n");

        var matcher = new Matcher(DefaultAllocator);

        if (!matcher.Initialize())
        {
            Console.Write("error: failed to initialize matcher\n");
            return 1;
        }

        Console.Write("requesting match from https://localhost:8080\n");

        matcher.RequestMatch(shared.ProtocolId, clientId, false);

        if (matcher.MatchStatus == MatchStatus.MATCH_FAILED)
        {
            Console.Write("\nRequest match failed. Is the matcher running? Please run \"premake5 matcher\" before you connect a secure client\n");
            return 1;
        }

        var connectToken = new byte[ConnectTokenBytes];
        matcher.GetConnectToken(connectToken);
        Console.Write("received connect token from matcher\n");

        var time = 100.0;

        var config = new ClientServerConfig();
        config.protocolId = shared.ProtocolId;

        var client = new Client(DefaultAllocator, new Address("0.0.0.0"), config, shared.adapter, time);

        var serverAddress = new Address("127.0.0.1", shared.ServerPort);

        if (args.Length == 2)
        {
            var commandLineAddress = new Address(args[1]);
            if (commandLineAddress.IsValid)
            {
                if (commandLineAddress.Port == 0)
                    commandLineAddress.Port = shared.ServerPort;
                serverAddress = commandLineAddress;
            }
        }

        client.Connect(clientId, connectToken);

        if (client.IsDisconnected)
            return 1;

        var addressString = client.Address.ToString();
        Console.Write($"client address is {addressString}\n");

        const double deltaTime = 0.1;

        Console.CancelKeyPress += interrupt_handler;

        while (!quit)
        {
            client.SendPackets();

            client.ReceivePackets();

            if (client.IsDisconnected)
                break;

            time += deltaTime;

            client.AdvanceTime(time);

            if (client.ConnectionFailed)
                break;

            sleep(deltaTime);
        }

        client.Disconnect();

        return 0;
    }

    static int Main(string[] args)
    {
        if (!InitializeYojimbo())
        {
            Console.Write("error: failed to initialize Yojimbo!\n");
            return 1;
        }

        log_level(LOG_LEVEL_INFO);

        var result = ClientMain(args);

        ShutdownYojimbo();

        Console.Write("\n");

        return result;
    }
}