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
    const int MaxBlockSize = 64 * 1024;

    const int UNRELIABLE_UNORDERED_CHANNEL = 0;
    const int RELIABLE_ORDERED_CHANNEL = 1;

    static int SoakMain()
    {
        var config = new ClientServerConfig();
        config.maxPacketSize = MaxPacketSize;
        config.clientMemory = 10 * 1024 * 1024;
        config.serverGlobalMemory = 10 * 1024 * 1024;
        config.serverPerClientMemory = 10 * 1024 * 1024;
        config.numChannels = 2;
        config.channel[UNRELIABLE_UNORDERED_CHANNEL].type = ChannelType.CHANNEL_TYPE_UNRELIABLE_UNORDERED;
        config.channel[UNRELIABLE_UNORDERED_CHANNEL].maxBlockSize = MaxSnapshotSize;
        config.channel[RELIABLE_ORDERED_CHANNEL].type = ChannelType.CHANNEL_TYPE_RELIABLE_ORDERED;
        config.channel[RELIABLE_ORDERED_CHANNEL].maxBlockSize = MaxBlockSize;
        config.channel[RELIABLE_ORDERED_CHANNEL].blockFragmentSize = 1024;

        var privateKey = new byte[KeyBytes];

        var time = 0.0;

        var serverAddress = new Address("127.0.0.1", shared.ServerPort);

        var server = new Server(DefaultAllocator, privateKey, serverAddress, config, shared.adapter, time);

        server.Start(1);

        var clientId = 0UL;
        random_bytes(ref clientId, 8);

        var client = new Client(DefaultAllocator, new Address("0.0.0.0"), config, shared.adapter, time);

        client.InsecureConnect(privateKey, clientId, serverAddress);

        var numMessagesSentToServer = 0UL;
        var numMessagesSentToClient = 0UL;
        var numMessagesReceivedFromClient = 0UL;
        var numMessagesReceivedFromServer = 0UL;

        Console.CancelKeyPress += interrupt_handler;

        var clientConnected = false;
        var serverConnected = false;

        while (!quit)
        {
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
                clientConnected = true;

                {
                    var messagesToSend = random_int(0, 64);

                    for (var i = 0; i < messagesToSend; ++i)
                    {
                        if (!client.CanSendMessage(RELIABLE_ORDERED_CHANNEL))
                            break;

                        if ((BufferEx.Rand() % 25) != 0)
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

                var clientIndex = client.ClientIndex;

                if (server.IsClientConnected(clientIndex))
                {
                    serverConnected = true;

                    var messagesToSend = random_int(0, 64);

                    for (var i = 0; i < messagesToSend; ++i)
                    {
                        if (!server.CanSendMessage(clientIndex, RELIABLE_ORDERED_CHANNEL))
                            break;

                        if ((BufferEx.Rand() % 25) != 0)
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

                    while (true)
                    {
                        var message = server.ReceiveMessage(clientIndex, RELIABLE_ORDERED_CHANNEL);
                        if (message == null)
                            break;

                        assert(message.Id == (ushort)numMessagesReceivedFromClient);

                        switch (message.Type)
                        {
                            case (int)TestMessageType.TEST_MESSAGE:
                                {
                                    var testMessage = (TestMessage)message;
                                    assert(testMessage.sequence == (ushort)numMessagesReceivedFromClient);
                                    Console.Write($"server received message {testMessage.sequence}\n");
                                    server.ReleaseMessage(clientIndex, ref message);
                                    numMessagesReceivedFromClient++;
                                }
                                break;

                            case (int)TestMessageType.TEST_BLOCK_MESSAGE:
                                {
                                    var blockMessage = (TestBlockMessage)message;
                                    assert(blockMessage.sequence == (ushort)numMessagesReceivedFromClient);
                                    var blockSize = blockMessage.BlockSize;
                                    var expectedBlockSize = 1 + ((int)numMessagesReceivedFromClient * 33) % MaxBlockSize;
                                    if (blockSize != expectedBlockSize)
                                    {
                                        Console.Write($"error: block size mismatch. expected {expectedBlockSize}, got {blockSize}\n");
                                        return 1;
                                    }
                                    var blockData = blockMessage.BlockData;
                                    assert(blockData != null);
                                    for (var i = 0; i < blockSize; ++i)
                                    {
                                        if (blockData[i] != (byte)((int)numMessagesReceivedFromClient + i))
                                        {
                                            Console.Write($"error: block data mismatch. expected {(byte)((int)numMessagesReceivedFromClient + i)}, but blockData[{i}] = {blockData[i]}\n");
                                            return 1;
                                        }
                                    }
                                    Console.Write($"server received message {(ushort)numMessagesReceivedFromClient}\n");
                                    server.ReleaseMessage(clientIndex, ref message);
                                    numMessagesReceivedFromClient++;
                                }
                                break;
                        }
                    }
                }

                while (true)
                {
                    var message = client.ReceiveMessage(RELIABLE_ORDERED_CHANNEL);

                    if (message == null)
                        break;

                    assert(message.Id == (ushort)numMessagesReceivedFromServer);

                    switch (message.Type)
                    {
                        case (int)TestMessageType.TEST_MESSAGE:
                            {
                                var testMessage = (TestMessage)message;
                                assert(testMessage.sequence == (ushort)numMessagesReceivedFromServer);
                                Console.Write($"client received message {testMessage.sequence}\n");
                                client.ReleaseMessage(ref message);
                                numMessagesReceivedFromServer++;
                            }
                            break;

                        case (int)TestMessageType.TEST_BLOCK_MESSAGE:
                            {
                                var blockMessage = (TestBlockMessage)message;
                                assert(blockMessage.sequence == (ushort)numMessagesReceivedFromServer);
                                var blockSize = blockMessage.BlockSize;
                                var expectedBlockSize = 1 + ((int)numMessagesReceivedFromServer * 33) % MaxBlockSize;
                                if (blockSize != expectedBlockSize)
                                {
                                    Console.Write($"error: block size mismatch. expected {expectedBlockSize}, got {blockSize}\n");
                                    return 1;
                                }
                                var blockData = blockMessage.BlockData;
                                assert(blockData != null);
                                for (var i = 0; i < blockSize; ++i)
                                    if (blockData[i] != (byte)((int)numMessagesReceivedFromServer + i))
                                    {
                                        Console.Write($"error: block data mismatch. expected {(byte)((int)numMessagesReceivedFromServer + i)}, but blockData[{i}] = {blockData[i]}\n");
                                        return 1;
                                    }
                                Console.Write($"client received message {(ushort)numMessagesReceivedFromServer}\n");
                                client.ReleaseMessage(ref message);
                                numMessagesReceivedFromServer++;
                            }
                            break;
                    }
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
        {
            Console.Write("\nstopped\n");
        }

        client.Disconnect();

        server.Stop();

        return 0;
    }

    static int Main(string[] args)
    {
        Console.Write("\nsoak\n");

        if (!InitializeYojimbo())
        {
            Console.Write("error: failed to initialize Yojimbo!\n");
            return 1;
        }

        log_level(LOG_LEVEL_INFO);

        var result = SoakMain();

        ShutdownYojimbo();

        Console.Write("\n");

        return result;
    }
}