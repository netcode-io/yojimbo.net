/*
    Cross-implementation interop test (C# side). Mirrors interop/interop.cpp line for line; see that file for
    the protocol. Any pairing of the C++ and C# sides can be run:

        dotnet run --project interop/cs -- server [port]
        dotnet run --project interop/cs -- client [port]
*/

using networkprotocol;
using System;
using static networkprotocol.yojimbo;

public static class interop
{
    const int NumMessages = 1000;
    const int BlockEvery = 8;
    const double TimeoutSeconds = 60.0;

    static int BlockSizeFor(int sequence) => 1 + (sequence * 977) % 5000;

    static byte BlockByte(int sequence, int i) => (byte)((sequence * 31 + i * 7) & 0xFF);

    static ClientServerConfig CreateConfig()
    {
        var config = new ClientServerConfig();
        config.protocolId = shared.ProtocolId;
        config.numChannels = 2;
        config.channel[0].type = ChannelType.CHANNEL_TYPE_RELIABLE_ORDERED;
        config.channel[1].type = ChannelType.CHANNEL_TYPE_UNRELIABLE_UNORDERED;
        return config;
    }

    static int ServerMain(int port)
    {
        var config = CreateConfig();

        var privateKey = new byte[KeyBytes];

        var time = 100.0;
        const double deltaTime = 0.01;

        var server = new Server(GetDefaultAllocator(), privateKey, new Address("127.0.0.1", (ushort)port), config, shared.adapter, time);
        if (!server.Start(MaxClients))
        {
            Console.Write("server: failed to start\n");
            return 1;
        }
        Console.Write($"server: listening on 127.0.0.1:{port}\n");

        var hadClient = false;
        var idleSince = time;
        while (true)
        {
            server.SendPackets();
            server.ReceivePackets();
            time += deltaTime;
            server.AdvanceTime(time);

            var anyConnected = false;
            for (var clientIndex = 0; clientIndex < MaxClients; ++clientIndex)
            {
                if (!server.IsClientConnected(clientIndex))
                    continue;
                anyConnected = true;
                hadClient = true;
                for (var channel = 0; channel < config.numChannels; ++channel)
                {
                    Message message;
                    while ((message = server.ReceiveMessage(clientIndex, channel)) != null)
                    {
                        if (!server.CanSendMessage(clientIndex, channel))
                        {
                            server.ReleaseMessage(clientIndex, ref message);
                            continue;
                        }
                        if (message.Type == (int)TestMessageType.TEST_BLOCK_MESSAGE)
                        {
                            var input = (TestBlockMessage)message;
                            var output = (TestBlockMessage)server.CreateMessage(clientIndex, (int)TestMessageType.TEST_BLOCK_MESSAGE);
                            output.sequence = input.sequence;
                            var block = server.AllocateBlock(clientIndex, input.BlockSize);
                            Buffer.BlockCopy(input.BlockData, 0, block, 0, input.BlockSize);
                            server.AttachBlockToMessage(clientIndex, output, block, input.BlockSize);
                            server.SendMessage(clientIndex, channel, output);
                        }
                        else if (message.Type == (int)TestMessageType.TEST_MESSAGE)
                        {
                            var output = (TestMessage)server.CreateMessage(clientIndex, (int)TestMessageType.TEST_MESSAGE);
                            output.sequence = ((TestMessage)message).sequence;
                            server.SendMessage(clientIndex, channel, output);
                        }
                        server.ReleaseMessage(clientIndex, ref message);
                    }
                }
            }

            // exit once the client has come and gone, or nobody shows up
            if (anyConnected)
                idleSince = time;
            else if (hadClient && time - idleSince > 1.0)
                break;
            else if (!hadClient && time - idleSince > TimeoutSeconds)
            {
                Console.Write("server: no client connected\n");
                server.Stop();
                return 1;
            }

            sleep(deltaTime);
        }

        server.Stop();
        server.Dispose();
        Console.Write("server: done\n");
        return 0;
    }

    static int ClientMain(int port)
    {
        var config = CreateConfig();

        var privateKey = new byte[KeyBytes];

        var clientId = 0UL;
        random_bytes(ref clientId, 8);

        var time = 100.0;
        const double deltaTime = 0.01;

        var client = new Client(GetDefaultAllocator(), new Address("0.0.0.0"), config, shared.adapter, time);
        client.InsecureConnect(privateKey, clientId, new Address("127.0.0.1", (ushort)port));

        var numSent = 0;
        var numReceived = 0;
        var numUnreliableEchoes = 0;
        ushort unreliableSequence = 0;
        var start = time;
        var result = 1;

        while (true)
        {
            client.SendPackets();
            client.ReceivePackets();
            time += deltaTime;
            client.AdvanceTime(time);

            if (client.ConnectionFailed || (client.IsDisconnected && time - start > 1.0))
            {
                Console.Write($"client: connection failed ({GetClientDisconnectReasonString(client.GetDisconnectReason())})\n");
                break;
            }

            if (time - start > TimeoutSeconds)
            {
                Console.Write($"client: timed out with {numReceived}/{NumMessages} echoes\n");
                break;
            }

            if (client.IsConnected)
            {
                while (numSent < NumMessages && client.CanSendMessage(0))
                {
                    if (numSent % BlockEvery == 0)
                    {
                        var message = (TestBlockMessage)client.CreateMessage((int)TestMessageType.TEST_BLOCK_MESSAGE);
                        message.sequence = (ushort)numSent;
                        var blockSize = BlockSizeFor(numSent);
                        var block = client.AllocateBlock(blockSize);
                        for (var i = 0; i < blockSize; ++i)
                            block[i] = BlockByte(numSent, i);
                        client.AttachBlockToMessage(message, block, blockSize);
                        client.SendMessage(0, message);
                    }
                    else
                    {
                        var message = (TestMessage)client.CreateMessage((int)TestMessageType.TEST_MESSAGE);
                        message.sequence = (ushort)numSent;
                        client.SendMessage(0, message);
                    }
                    numSent++;
                }

                if (client.CanSendMessage(1))
                {
                    var message = (TestMessage)client.CreateMessage((int)TestMessageType.TEST_MESSAGE);
                    message.sequence = unreliableSequence++;
                    client.SendMessage(1, message);
                }

                Message received;
                while ((received = client.ReceiveMessage(0)) != null)
                {
                    var expected = numReceived;
                    bool ok;
                    if (expected % BlockEvery == 0)
                    {
                        ok = received.Type == (int)TestMessageType.TEST_BLOCK_MESSAGE && ((TestBlockMessage)received).sequence == (ushort)expected;
                        if (ok)
                        {
                            var blockMessage = (TestBlockMessage)received;
                            ok = blockMessage.BlockSize == BlockSizeFor(expected);
                            for (var i = 0; ok && i < blockMessage.BlockSize; ++i)
                                ok = blockMessage.BlockData[i] == BlockByte(expected, i);
                        }
                    }
                    else
                    {
                        ok = received.Type == (int)TestMessageType.TEST_MESSAGE && ((TestMessage)received).sequence == (ushort)expected;
                    }
                    client.ReleaseMessage(ref received);
                    if (!ok)
                    {
                        Console.Write($"client: echo {expected} is wrong\n");
                        client.Disconnect();
                        return 1;
                    }
                    numReceived++;
                }

                while ((received = client.ReceiveMessage(1)) != null)
                {
                    numUnreliableEchoes++;
                    client.ReleaseMessage(ref received);
                }

                if (numReceived == NumMessages)
                {
                    Console.Write($"client: {numReceived} reliable echoes verified ({(NumMessages + BlockEvery - 1) / BlockEvery} blocks), {numUnreliableEchoes} unreliable echoes\n");
                    result = numUnreliableEchoes > 0 ? 0 : 1;
                    if (result != 0)
                        Console.Write("client: no unreliable echoes\n");
                    break;
                }
            }

            sleep(deltaTime);
        }

        client.Disconnect();
        client.Dispose();
        return result;
    }

    static int Main(string[] args)
    {
        if (args.Length < 1 || (args[0] != "server" && args[0] != "client"))
        {
            Console.Write("usage: interop server|client [port]\n");
            return 1;
        }

        var port = args.Length >= 2 ? int.Parse(args[1]) : shared.ServerPort;

        if (!InitializeYojimbo())
        {
            Console.Write("error: failed to initialize yojimbo\n");
            return 1;
        }

        log_level(LOG_LEVEL_ERROR);

        var result = args[0] == "server" ? ServerMain(port) : ClientMain(port);

        ShutdownYojimbo();

        Console.Write(result == 0 ? "PASS\n" : "FAIL\n");

        return result;
    }
}
