/*
    Yojimbo Soak Test.

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

public static class soak
{
    static volatile bool quit = false;

    static void interrupt_handler(object sender, ConsoleCancelEventArgs e) { quit = true; e.Cancel = true; }

    const int MaxPacketSize = 16 * 1024;
    const int MaxSnapshotSize = 8 * 1024;
    const int MaxBlockSize = 10 * 1024;

    const int UNRELIABLE_UNORDERED_CHANNEL = 0;
    const int RELIABLE_ORDERED_CHANNEL = 1;

    static bool SendClientMessages(Client client, ref ulong numMessagesSentToServer)
    {
        var messagesToSend = random_int(0, 64);

        for (var i = 0; i < messagesToSend; ++i)
        {
            if (!client.CanSendMessage(RELIABLE_ORDERED_CHANNEL))
                break;

            if ((rand() % 100) != 0)
            {
                var message = (TestMessage)client.CreateMessage((int)TestMessageType.TEST_MESSAGE);
                if (message != null)
                {
                    message.sequence = (ushort)numMessagesSentToServer;
                    client.SendMessage(RELIABLE_ORDERED_CHANNEL, message);
                    numMessagesSentToServer++;
                }
            }
            else
            {
                var numBlocks = random_int(1, 3);

                for (var k = 0; k < numBlocks; k++)
                {
                    if (!client.CanSendMessage(RELIABLE_ORDERED_CHANNEL))
                        break;

                    var blockMessage = (TestBlockMessage)client.CreateMessage((int)TestMessageType.TEST_BLOCK_MESSAGE);
                    if (blockMessage != null)
                    {
                        blockMessage.sequence = (ushort)numMessagesSentToServer;
                        var blockSize = 1 + ((int)numMessagesSentToServer * 33) % MaxBlockSize;
                        var blockData = client.AllocateBlock(blockSize);
                        if (blockData != null)
                        {
                            for (var j = 0; j < blockSize; ++j)
                                blockData[j] = (byte)((int)numMessagesSentToServer + j);
                            client.AttachBlockToMessage(blockMessage, blockData, blockSize);
                            client.SendMessage(RELIABLE_ORDERED_CHANNEL, blockMessage);
                            numMessagesSentToServer++;
                        }
                        else
                            client.ReleaseMessage(ref blockMessage);
                    }
                }
            }
        }
        return true;
    }

    static bool SendServerMessages(Server server, int clientIndex, ref ulong numMessagesSentToClient)
    {
        var messagesToSend = random_int(0, 64);

        for (var i = 0; i < messagesToSend; ++i)
        {
            if (!server.CanSendMessage(clientIndex, RELIABLE_ORDERED_CHANNEL))
                break;

            if ((rand() % 100) != 0)
            {
                var message = (TestMessage)server.CreateMessage(clientIndex, (int)TestMessageType.TEST_MESSAGE);
                if (message != null)
                {
                    message.sequence = (ushort)numMessagesSentToClient;
                    server.SendMessage(clientIndex, RELIABLE_ORDERED_CHANNEL, message);
                    numMessagesSentToClient++;
                }
            }
            else
            {
                var numBlocks = random_int(1, 3);

                for (var k = 0; k < numBlocks; k++)
                {
                    if (!server.CanSendMessage(clientIndex, RELIABLE_ORDERED_CHANNEL))
                        break;

                    var blockMessage = (TestBlockMessage)server.CreateMessage(clientIndex, (int)TestMessageType.TEST_BLOCK_MESSAGE);
                    if (blockMessage != null)
                    {
                        blockMessage.sequence = (ushort)numMessagesSentToClient;
                        var blockSize = 1 + ((int)numMessagesSentToClient * 33) % MaxBlockSize;
                        var blockData = server.AllocateBlock(clientIndex, blockSize);
                        if (blockData != null)
                        {
                            for (var j = 0; j < blockSize; ++j)
                                blockData[j] = (byte)((int)numMessagesSentToClient + j);
                            server.AttachBlockToMessage(clientIndex, blockMessage, blockData, blockSize);
                            server.SendMessage(clientIndex, RELIABLE_ORDERED_CHANNEL, blockMessage);
                            numMessagesSentToClient++;
                        }
                        else
                            server.ReleaseMessage(clientIndex, ref blockMessage);
                    }
                }
            }
        }
        return true;
    }

    // returns false on a data mismatch
    static bool CheckReceivedMessage(Message message, ulong numMessagesReceived, string who)
    {
        assert(message.Id == (ushort)numMessagesReceived);

        switch (message.Type)
        {
            case (int)TestMessageType.TEST_MESSAGE:
                {
                    var testMessage = (TestMessage)message;
                    assert(testMessage.sequence == (ushort)numMessagesReceived);
                    Console.Write($"{who} received message {testMessage.sequence}\n");
                }
                break;

            case (int)TestMessageType.TEST_BLOCK_MESSAGE:
                {
                    var blockMessage = (TestBlockMessage)message;
                    assert(blockMessage.sequence == (ushort)numMessagesReceived);
                    var blockSize = blockMessage.BlockSize;
                    var expectedBlockSize = 1 + ((int)numMessagesReceived * 33) % MaxBlockSize;
                    if (blockSize != expectedBlockSize)
                    {
                        Console.Write($"error: block size mismatch. expected {expectedBlockSize}, got {blockSize}\n");
                        return false;
                    }
                    var blockData = blockMessage.BlockData;
                    assert(blockData != null);
                    for (var i = 0; i < blockSize; ++i)
                    {
                        if (blockData[i] != (byte)((int)numMessagesReceived + i))
                        {
                            Console.Write($"error: block data mismatch. expected {(byte)((int)numMessagesReceived + i)}, but blockData[{i}] = {blockData[i]}\n");
                            return false;
                        }
                    }
                    Console.Write($"{who} received message {(ushort)numMessagesReceived}\n");
                }
                break;
        }
        return true;
    }

    static int SoakMain(int iterations)
    {
        var config = new ClientServerConfig();
        config.maxPacketSize = MaxPacketSize;
        // maxPacketFragments was derived from the default maxPacketSize in the ClientServerConfig
        // constructor. We just doubled maxPacketSize, so recompute it or packets larger than
        // packetFragmentSize * maxPacketFragments can't be fragmented (config.Validate() catches this).
        config.maxPacketFragments = (int)Math.Ceiling(config.maxPacketSize / (double)config.packetFragmentSize);
        config.clientMemory = 100 * 1024 * 1024;
        config.serverGlobalMemory = 10 * 1024 * 1024;
        config.serverPerClientMemory = 100 * 1024 * 1024;
        config.numChannels = 2;
        config.channel[UNRELIABLE_UNORDERED_CHANNEL].type = ChannelType.CHANNEL_TYPE_UNRELIABLE_UNORDERED;
        config.channel[UNRELIABLE_UNORDERED_CHANNEL].maxBlockSize = MaxSnapshotSize;
        config.channel[RELIABLE_ORDERED_CHANNEL].type = ChannelType.CHANNEL_TYPE_RELIABLE_ORDERED;
        config.channel[RELIABLE_ORDERED_CHANNEL].maxBlockSize = MaxBlockSize;
        config.channel[RELIABLE_ORDERED_CHANNEL].blockFragmentSize = 1024;

        var privateKey = new byte[KeyBytes];

        var time = 0.0;

        var serverAddress = new Address("127.0.0.1", shared.ServerPort);

        var server = new Server(GetDefaultAllocator(), privateKey, serverAddress, config, shared.adapter, time);

        server.Start(1);

        // the network simulator only exists once the server has started (e79ad2a)
        server.SetLatency(1000.0f);
        server.SetJitter(100.0f);
        server.SetPacketLoss(25.0f);
        server.SetDuplicates(25.0f);

        var clientId = 0UL;
        random_bytes(ref clientId, 8);

        var client = new Client(GetDefaultAllocator(), new Address("0.0.0.0"), config, shared.adapter, time);

        client.InsecureConnect(privateKey, clientId, serverAddress);

        // ...and the client one once the client has connected
        client.SetLatency(1000.0f);
        client.SetJitter(100.0f);
        client.SetPacketLoss(25.0f);
        client.SetDuplicates(25.0f);

        var numMessagesSentToServer = 0UL;
        var numMessagesSentToClient = 0UL;
        var numMessagesReceivedFromClient = 0UL;
        var numMessagesReceivedFromServer = 0UL;

        Console.CancelKeyPress += interrupt_handler;

        var clientConnected = false;
        var serverConnected = false;

        var timeForNextClientMessage = 0.0;
        var timeForNextServerMessage = 0.0;

        // iterations <= 0 runs until interrupted; a positive count time-boxes the run so it exits cleanly (e72105e)
        var iteration = 0;

        while (!quit && (iterations <= 0 || iteration < iterations))
        {
            iteration++;

            client.SendPackets();
            server.SendPackets();

            client.ReceivePackets();
            server.ReceivePackets();

            if (client.ConnectionFailed)
            {
                Console.Write("error: client connect failed!\n");
                break;
            }

            time += 0.1f;

            if (client.IsConnected)
            {
                // occasionally reconnect, so message sends across reconnect are soaked too (3b3ba95, 06358cf)
                if ((rand() % 100000) == 0)
                {
                    Console.Write("client reconnect\n");
                    client.Disconnect();
                    client.InsecureConnect(privateKey, clientId, serverAddress);
                    client.SetLatency(1000.0f);
                    client.SetJitter(100.0f);
                    client.SetPacketLoss(25.0f);
                    client.SetDuplicates(25.0f);
                    clientConnected = false;
                    numMessagesSentToServer = 0;
                    numMessagesSentToClient = 0;
                    numMessagesReceivedFromClient = 0;
                    numMessagesReceivedFromServer = 0;
                }
            }

            if (client.IsConnected)
            {
                clientConnected = true;

                // sometimes stop sending for a while, which catches desyncs when messages are sent infrequently (e9e16a1)
                if (timeForNextClientMessage < time && (rand() % 1000) == 0)
                    timeForNextClientMessage = time + random_int(1, 1000);

                if (timeForNextClientMessage <= time)
                    SendClientMessages(client, ref numMessagesSentToServer);

                var clientIndex = client.ClientIndex;

                if (timeForNextServerMessage < time && (rand() % 1000) == 0)
                    timeForNextServerMessage = time + random_int(1, 1000);

                if (server.IsClientConnected(clientIndex))
                {
                    serverConnected = true;

                    if (timeForNextServerMessage <= time)
                        SendServerMessages(server, clientIndex, ref numMessagesSentToClient);

                    while (true)
                    {
                        var message = server.ReceiveMessage(clientIndex, RELIABLE_ORDERED_CHANNEL);
                        if (message == null)
                            break;
                        if (!CheckReceivedMessage(message, numMessagesReceivedFromClient, "server"))
                            return 1;
                        server.ReleaseMessage(clientIndex, ref message);
                        numMessagesReceivedFromClient++;
                    }
                }

                while (true)
                {
                    var message = client.ReceiveMessage(RELIABLE_ORDERED_CHANNEL);
                    if (message == null)
                        break;
                    if (!CheckReceivedMessage(message, numMessagesReceivedFromServer, "client"))
                        return 1;
                    client.ReleaseMessage(ref message);
                    numMessagesReceivedFromServer++;
                }

                if (clientConnected && !client.IsConnected)
                    break;

                if (serverConnected && server.NumConnectedClients == 0)
                    break;
            }

            client.AdvanceTime(time);
            server.AdvanceTime(time);
        }

        if (quit)
            Console.Write("\nstopped\n");

        client.Disconnect();

        server.Stop();

        client.Dispose();
        server.Dispose();

        return 0;
    }

    static int Main(string[] args)
    {
        Console.Write("\nsoak\n");

        // Optional iteration count: `soak [iterations]`. Zero or absent runs until Ctrl-C.
        var iterations = args.Length > 0 && int.TryParse(args[0], out var n) ? n : 0;

        if (!InitializeYojimbo())
        {
            Console.Write("error: failed to initialize Yojimbo!\n");
            return 1;
        }

        log_level(LOG_LEVEL_INFO);

        var result = SoakMain(iterations);

        ShutdownYojimbo();

        Console.Write("\n");

        return result;
    }
}
