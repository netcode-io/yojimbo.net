/*
    Yojimbo custom packet I/O test (port of custom_packet_io_test.cpp).

    Copyright © 2016 - 2026, Mas Bandwidth LLC.

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
using System.Collections.Generic;
using static networkprotocol.yojimbo;

class MemoryPacket
{
    public Address from;
    public int bytes;
    public byte[] data = new byte[MaxAdapterPacketBytes];
}

class MemoryPacketAdapter : TestAdapter
{
    public MemoryPacketAdapter(Address localAddress)
    {
        m_localAddress = new Address(localAddress);
    }

    public void Connect(MemoryPacketAdapter peer) =>
        m_peer = peer;

    public override bool UseCustomPacketIO() => true;

    public override void SendPacket(Address to, byte[] packetData, int packetBytes)
    {
        if (m_peer == null || to != m_peer.m_localAddress || packetBytes <= 0 || packetBytes > MaxAdapterPacketBytes)
            return;

        // packetData is only valid during this call and its Length may exceed packetBytes: copy packetBytes bytes
        var packet = new MemoryPacket();
        packet.from = new Address(m_localAddress);
        packet.bytes = packetBytes;
        Buffer.BlockCopy(packetData, 0, packet.data, 0, packetBytes);
        m_peer.m_packets.Enqueue(packet);
        ++m_sentPackets;
    }

    public override int ReceivePacket(ref Address from, byte[] packetData, int maxPacketBytes)
    {
        if (m_packets.Count == 0)
            return 0;

        var packet = m_packets.Dequeue();
        if (packet.bytes > maxPacketBytes)
            return 0;

        from = packet.from;
        Buffer.BlockCopy(packet.data, 0, packetData, 0, packet.bytes);
        ++m_receivedPackets;
        return packet.bytes;
    }

    public int SentPackets => m_sentPackets;
    public int ReceivedPackets => m_receivedPackets;

    Address m_localAddress;
    MemoryPacketAdapter m_peer;
    Queue<MemoryPacket> m_packets = new Queue<MemoryPacket>();
    int m_sentPackets;
    int m_receivedPackets;
}

/**
    Hostile adapter for the teardown-reentrancy regression: once armed, every teardown-time
    SendPacket re-enters the owning object's own Disconnect/Stop from inside the callback.
    The stop-in-progress guards in Client.Disconnect and Server.Stop must make those
    reentrant calls harmless no-ops.
 */
class ReentrantTeardownAdapter : MemoryPacketAdapter
{
    public ReentrantTeardownAdapter(Address localAddress) : base(localAddress) { }

    public void BeginHostileTeardown(Client client, Server server)
    {
        m_client = client;
        m_server = server;
        m_teardown = true;
    }

    public override void SendPacket(Address to, byte[] packetData, int packetBytes)
    {
        if (m_teardown)
        {
            ++m_reentrantCalls;
            m_client?.Disconnect();
            m_server?.Stop();
        }
        base.SendPacket(to, packetData, packetBytes);
    }

    public int ReentrantCalls => m_reentrantCalls;

    Client m_client;
    Server m_server;
    bool m_teardown;
    int m_reentrantCalls;
}

public static class custom_packet_io_test
{
    static bool Require(bool condition, string message)
    {
        if (condition)
            return true;
        Console.Write($"FAIL: {message}\n");
        return false;
    }

    static void Pump(ref double time, Client client, Server server)
    {
        client.SendPackets();
        server.SendPackets();
        client.ReceivePackets();
        server.ReceivePackets();
        time += 0.1;
        client.AdvanceTime(time);
        server.AdvanceTime(time);
    }

    static int Main(string[] args)
    {
        if (!InitializeYojimbo())
            return 1;

        var ok = true;
        {
            var clientAddress = new Address("203.0.113.2", 41230);
            var serverAddress = new Address("203.0.113.1", 41230);
            var clientAdapter = new MemoryPacketAdapter(clientAddress);
            var serverAdapter = new MemoryPacketAdapter(serverAddress);
            clientAdapter.Connect(serverAdapter);
            serverAdapter.Connect(clientAdapter);

            var config = new ClientServerConfig();
            config.numChannels = 2;
            config.channel[0].type = ChannelType.CHANNEL_TYPE_RELIABLE_ORDERED;
            config.channel[1].type = ChannelType.CHANNEL_TYPE_UNRELIABLE_UNORDERED;

            var privateKey = new byte[KeyBytes];
            var time = 100.0;

            var server = new Server(DefaultAllocator, privateKey, serverAddress, config, serverAdapter, time);
            server.Start(1);
            var client = new Client(DefaultAllocator, clientAddress, config, clientAdapter, time);
            client.InsecureConnect(privateKey, 1, serverAddress);

            for (var i = 0; i < 256 && !client.IsConnected; ++i)
                Pump(ref time, client, server);

            ok &= Require(client.Address == clientAddress, "client synthetic local address changed");
            ok &= Require(server.Address == serverAddress, "server synthetic local address changed");
            ok &= Require(client.IsConnected, "client did not connect over custom packet I/O");
            ok &= Require(server.NumConnectedClients == 1, "server did not admit the custom-I/O client");
            ok &= Require(clientAdapter.SentPackets > 0 && clientAdapter.ReceivedPackets > 0, "client adapter did not send and receive packets");
            ok &= Require(serverAdapter.SentPackets > 0 && serverAdapter.ReceivedPackets > 0, "server adapter did not send and receive packets");

            var toServer = (TestMessage)client.CreateMessage((int)TestMessageType.TEST_MESSAGE);
            var toClient = (TestMessage)server.CreateMessage(0, (int)TestMessageType.TEST_MESSAGE);
            ok &= Require(toServer != null && toClient != null, "could not allocate channel test messages");
            if (toServer != null && toClient != null)
            {
                toServer.sequence = 11;
                toClient.sequence = 22;
                client.SendMessage(0, toServer);
                server.SendMessage(0, 1, toClient);

                Message fromClient = null;
                Message fromServer = null;
                for (var i = 0; i < 256 && (fromClient == null || fromServer == null); ++i)
                {
                    client.SendPackets();
                    server.SendPackets();
                    client.ReceivePackets();
                    server.ReceivePackets();
                    if (fromClient == null)
                        fromClient = server.ReceiveMessage(0, 0);
                    if (fromServer == null)
                        fromServer = client.ReceiveMessage(1);
                    time += 0.1;
                    client.AdvanceTime(time);
                    server.AdvanceTime(time);
                }

                ok &= Require(fromClient != null && ((TestMessage)fromClient).sequence == 11, "reliable client message did not cross custom packet I/O");
                ok &= Require(fromServer != null && ((TestMessage)fromServer).sequence == 22, "unreliable server message did not cross custom packet I/O");
                if (fromClient != null)
                    server.ReleaseMessage(0, ref fromClient);
                if (fromServer != null)
                    client.ReleaseMessage(ref fromServer);
            }

            client.Disconnect();
            server.Stop();
        }

        // Scenario 2: hostile reentrant teardown. Connect and exchange messages as above, then tear
        // down with adapters that call the owning object's Disconnect/Stop from inside its own
        // teardown-time SendPacket callback. The test completing cleanly is the proof that teardown is reentrancy-safe.
        {
            var clientAddress = new Address("203.0.113.2", 41230);
            var serverAddress = new Address("203.0.113.1", 41230);
            var clientAdapter = new ReentrantTeardownAdapter(clientAddress);
            var serverAdapter = new ReentrantTeardownAdapter(serverAddress);
            clientAdapter.Connect(serverAdapter);
            serverAdapter.Connect(clientAdapter);

            var config = new ClientServerConfig();
            config.numChannels = 2;
            config.channel[0].type = ChannelType.CHANNEL_TYPE_RELIABLE_ORDERED;
            config.channel[1].type = ChannelType.CHANNEL_TYPE_UNRELIABLE_UNORDERED;

            var privateKey = new byte[KeyBytes];
            var time = 100.0;

            var server = new Server(DefaultAllocator, privateKey, serverAddress, config, serverAdapter, time);
            server.Start(1);
            var client = new Client(DefaultAllocator, clientAddress, config, clientAdapter, time);
            client.InsecureConnect(privateKey, 1, serverAddress);

            for (var i = 0; i < 256 && !client.IsConnected; ++i)
                Pump(ref time, client, server);

            ok &= Require(client.IsConnected, "client did not connect before the hostile teardown");
            ok &= Require(server.NumConnectedClients == 1, "server did not admit the client before the hostile teardown");

            var toServer = (TestMessage)client.CreateMessage((int)TestMessageType.TEST_MESSAGE);
            var toClient = (TestMessage)server.CreateMessage(0, (int)TestMessageType.TEST_MESSAGE);
            ok &= Require(toServer != null && toClient != null, "could not allocate hostile-teardown test messages");
            if (toServer != null && toClient != null)
            {
                toServer.sequence = 33;
                toClient.sequence = 44;
                client.SendMessage(0, toServer);
                server.SendMessage(0, 1, toClient);

                Message fromClient = null;
                Message fromServer = null;
                for (var i = 0; i < 256 && (fromClient == null || fromServer == null); ++i)
                {
                    client.SendPackets();
                    server.SendPackets();
                    client.ReceivePackets();
                    server.ReceivePackets();
                    if (fromClient == null)
                        fromClient = server.ReceiveMessage(0, 0);
                    if (fromServer == null)
                        fromServer = client.ReceiveMessage(1);
                    time += 0.1;
                    client.AdvanceTime(time);
                    server.AdvanceTime(time);
                }

                ok &= Require(fromClient != null && fromServer != null, "messages did not cross before the hostile teardown");
                if (fromClient != null)
                    server.ReleaseMessage(0, ref fromClient);
                if (fromServer != null)
                    client.ReleaseMessage(ref fromServer);
            }

            // Arm the adapters, then tear down. Stop the server first, while the client is still
            // connected, so server_stop actually sends disconnect packets (the reentrancy window).
            serverAdapter.BeginHostileTeardown(null, server);
            clientAdapter.BeginHostileTeardown(client, null);
            server.Stop();
            client.Disconnect();

            // Prove the hostile path actually ran.
            ok &= Require(serverAdapter.ReentrantCalls > 0, "server teardown did not exercise the reentrant Stop path");
            ok &= Require(clientAdapter.ReentrantCalls > 0, "client teardown did not exercise the reentrant Disconnect path");

            // Teardown completed and the guards cleared: calling again must still be a safe no-op.
            server.Stop();
            client.Disconnect();
        }
        ShutdownYojimbo();

        if (!ok)
            return 1;

        Console.Write("OK: custom packet I/O handshake and hostile reentrant teardown passed without native sockets\n");
        return 0;
    }
}
