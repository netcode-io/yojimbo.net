/*
    Yojimbo Client/Server Network Library.

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

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Text;
using System.Threading;

namespace networkprotocol
{
    /**
        The reason the client in a server client slot was last disconnected.
        This lets you distinguish problems you need to act on (eg. serialize failures indicating a client/server protocol
        mismatch, or per-client memory exhaustion indicating an undersized config) from normal network behavior (a client
        cleanly disconnecting or timing out), and route that into your own logging, metrics and analytics.
        Tracked per-client slot. All slots reset to NONE when the server starts, and a slot resets back to NONE when a new
        client connects to it. The reason is recorded before Adapter.OnServerClientDisconnected is called, so you can query
        it from inside that callback.
        @see BaseServer::GetClientDisconnectReason
     */
    public enum ServerClientDisconnectReason
    {
        YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_NONE = 0,                   ///< No client has disconnected from this slot since the server started, or a new client has since connected to this slot.
        YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_DISCONNECTED,               ///< The client cleanly disconnected. It sent disconnect packets, eg. the player quit.
        YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_TIMED_OUT,                  ///< The client timed out. We stopped hearing from it, eg. network problem or the client crashed.
        YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_KICKED,                     ///< Server code called Server::DisconnectClient or Server::DisconnectAllClients for this client.
        YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_FAILED_TO_SERIALIZE,        ///< A message from this client failed to serialize read. Usually a client/server protocol version mismatch, or a bug in a message serialize function.
        YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_DESYNC,                     ///< A channel for this client desynced and cannot recover. See CHANNEL_ERROR_DESYNC.
        YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_SEND_QUEUE_FULL,            ///< A channel send queue for this client filled up. See CHANNEL_ERROR_SEND_QUEUE_FULL.
        YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_BLOCKS_DISABLED,            ///< This client sent block data on a channel that is configured with blocks disabled.
        YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_MESSAGE_TOO_LARGE,          ///< A message sent to this client is too large to ever fit into a packet. See CHANNEL_ERROR_MESSAGE_TOO_LARGE.
        YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_OUT_OF_MEMORY,              ///< The per-client memory budget for this client was exhausted.
        YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_READ_PACKET_FAILED,         ///< A connection packet from this client failed to deserialize.
    }

    static partial class yojimbo
    {
        /// Helper function to convert a server client disconnect reason to a user friendly string.
        public static string GetServerClientDisconnectReasonString(ServerClientDisconnectReason reason)
        {
            switch (reason)
            {
                case ServerClientDisconnectReason.YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_NONE: return "none";
                case ServerClientDisconnectReason.YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_DISCONNECTED: return "disconnected";
                case ServerClientDisconnectReason.YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_TIMED_OUT: return "timed out";
                case ServerClientDisconnectReason.YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_KICKED: return "kicked";
                case ServerClientDisconnectReason.YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_FAILED_TO_SERIALIZE: return "failed to serialize";
                case ServerClientDisconnectReason.YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_DESYNC: return "desync";
                case ServerClientDisconnectReason.YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_SEND_QUEUE_FULL: return "send queue full";
                case ServerClientDisconnectReason.YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_BLOCKS_DISABLED: return "blocks disabled";
                case ServerClientDisconnectReason.YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_MESSAGE_TOO_LARGE: return "message too large";
                case ServerClientDisconnectReason.YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_OUT_OF_MEMORY: return "out of memory";
                case ServerClientDisconnectReason.YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_READ_PACKET_FAILED: return "read packet failed";
                default:
                    assert(false);
                    return "(unknown)";
            }
        }
    }

    /**
        Dedicated server implementation.
     */
    public class Server : BaseServer
    {
        public Server(Allocator allocator, byte[] privateKey, Address address, ClientServerConfig config, Adapter adapter, double time)
            : base(allocator, config, adapter, time)
        {
            yojimbo.assert(yojimbo.KeyBytes == netcode.KEY_BYTES);
            yojimbo.assert(yojimbo.DefaultMaxConnectTokenLifetime == netcode.DEFAULT_MAX_CONNECT_TOKEN_LIFETIME);
            Buffer.BlockCopy(privateKey, 0, m_privateKey, 0, netcode.KEY_BYTES);
            m_address = new Address(address);
            m_boundAddress = new Address(address);
            m_config = config.Clone();
            m_server = null;
            m_stopping = false;
        }

        public override void Dispose()
        {
            // IMPORTANT: Please stop the server before destroying it!
            yojimbo.assert(m_server == null);
            base.Dispose();
        }

        /**
            Start the server.
            Startup is transactional: on any failure the server is left stopped and holding nothing, and this returns false.
         */
        public override bool Start(int maxClients)
        {
            yojimbo.assert(maxClients <= yojimbo.MaxClients);

            if (!base.Start(maxClients))
                return false;

            var addressString = m_address.ToString();

            netcode.default_server_config(out var netcodeConfig);
            netcodeConfig.protocol_id = m_config.protocolId;
            Buffer.BlockCopy(m_privateKey, 0, netcodeConfig.private_key, 0, netcode.KEY_BYTES);
            netcodeConfig.allocator_context = GlobalAllocator;
            netcodeConfig.allocate_function = StaticAllocateFunction;
            netcodeConfig.free_function = StaticFreeFunction;
            netcodeConfig.max_connect_token_lifetime = m_config.maxConnectTokenLifetime;
            netcodeConfig.callback_context = this;
            netcodeConfig.connect_disconnect_callback = StaticConnectDisconnectCallbackFunction;
            netcodeConfig.send_loopback_packet_callback = StaticSendLoopbackPacketCallbackFunction;

            var useCustomPacketIO = Adapter.UseCustomPacketIO();
            if (useCustomPacketIO)
            {
                netcodeConfig.override_send_and_receive = true;
                netcodeConfig.send_packet_override = StaticSendPacketOverride;
                netcodeConfig.receive_packet_override = StaticReceivePacketOverride;
            }

            m_server = netcode.server_create(addressString, netcodeConfig, Time);

            if (m_server == null)
            {
                Stop();
                return false;
            }

            netcode.server_start(m_server, maxClients);

            if (!useCustomPacketIO)
                m_boundAddress.Port = netcode.server_get_port(m_server);

            return true;
        }

        public override void Stop()
        {
            // Stop-in-progress guard: server_stop below sends disconnect packets and fires
            // OnServerClientDisconnected, so an adapter callback can call Stop from inside this
            // teardown. That reentrant call must be a harmless no-op (bd8a01b).
            if (m_stopping)
                return;
            m_stopping = true;
            if (m_server != null)
            {
                m_boundAddress = new Address(m_address);
                // Clear the member before stopping, so a reentrant Stop can't stop/destroy the same netcode server twice.
                // ConnectDisconnectCallbackFunction handles m_server being null during this window.
                var server = m_server;
                m_server = null;
                netcode.server_stop(server);
                netcode.server_destroy(ref server);
            }
            base.Stop();
            m_stopping = false;
        }

        public override void DisconnectClient(int clientIndex)
        {
            yojimbo.assert(m_server != null);
            // Record the kick, but only if no reason is set yet: when the disconnect comes from
            // BaseServer.AdvanceTime, the specific connection error reason is already recorded.
            if (IsClientConnected(clientIndex) && GetClientDisconnectReason(clientIndex) == ServerClientDisconnectReason.YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_NONE)
                SetClientDisconnectReason(clientIndex, ServerClientDisconnectReason.YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_KICKED);
            netcode.server_disconnect_client(m_server, clientIndex);
            ResetClient(clientIndex);
        }

        public override void DisconnectAllClients()
        {
            yojimbo.assert(m_server != null);
            var maxClients = MaxClients;
            for (var i = 0; i < maxClients; ++i)
                if (IsClientConnected(i) && GetClientDisconnectReason(i) == ServerClientDisconnectReason.YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_NONE)
                    SetClientDisconnectReason(i, ServerClientDisconnectReason.YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_KICKED);
            netcode.server_disconnect_all_clients(m_server);
            for (var i = 0; i < maxClients; ++i)
                ResetClient(i);
        }

        public override void SendPackets()
        {
            if (m_server != null)
            {
                var maxClients = MaxClients;
                for (var i = 0; i < maxClients; ++i)
                {
                    if (IsClientConnected(i))
                    {
                        var packetData = PacketBuffer;
                        var packetSequence = reliable.endpoint_next_packet_sequence(GetClientEndpoint(i));
                        if (GetClientConnection(i).GeneratePacket(Context, packetSequence, packetData, m_config.maxPacketSize, out var packetBytes))
                            reliable.endpoint_send_packet(GetClientEndpoint(i), packetData, packetBytes);
                    }
                }
            }
        }

        public override void ReceivePackets()
        {
            if (m_server != null)
            {
                var maxClients = MaxClients;
                for (var clientIndex = 0; clientIndex < maxClients; ++clientIndex)
                    while (true)
                    {
                        var packetData = netcode.server_receive_packet(m_server, clientIndex, out var packetBytes, out var packetSequence);
                        if (packetData == null)
                            break;
                        reliable.endpoint_receive_packet(GetClientEndpoint(clientIndex), packetData, packetBytes);
                        netcode.server_free_packet(m_server, ref packetData);
                    }
            }
        }

        public override void AdvanceTime(double time)
        {
            if (m_server != null)
                netcode.server_update(m_server, time);
            base.AdvanceTime(time);
            var networkSimulator = NetworkSimulator;
            if (networkSimulator != null && networkSimulator.IsActive)
            {
                // Drain the simulator in fixed size batches (df89f67).
                const int MaxBatchPackets = 64;
                var packetData = new byte[MaxBatchPackets][];
                var packetBytes = new int[MaxBatchPackets];
                var to = new int[MaxBatchPackets];
                while (true)
                {
                    var numPackets = networkSimulator.ReceivePackets(MaxBatchPackets, packetData, packetBytes, to);
                    if (numPackets == 0)
                        break;
                    for (var i = 0; i < numPackets; ++i)
                    {
                        netcode.server_send_packet(m_server, to[i], packetData[i], packetBytes[i]);
                        packetData[i] = null;
                    }
                }
            }
        }

        public override bool IsClientConnected(int clientIndex) =>
            netcode.server_client_connected(m_server, clientIndex);

        public override ulong GetClientId(int clientIndex) =>
            netcode.server_client_id(m_server, clientIndex);

        /// Get the 256 bytes of user data from the client's connect token, or null if not running or out of range.
        public override byte[] GetClientUserData(int clientIndex) =>
            netcode.server_client_user_data(m_server, clientIndex);

        /// Get the netcode address of the client, or null if not running or out of range.
        public override netcode_address_t GetClientAddress(int clientIndex) =>
            netcode.server_client_address(m_server, clientIndex);

        public override int NumConnectedClients =>
            netcode.server_num_connected_clients(m_server);

        public override void ConnectLoopbackClient(int clientIndex, ulong clientId, byte[] userData) =>
            netcode.server_connect_loopback_client(m_server, clientIndex, clientId, userData);

        public override void DisconnectLoopbackClient(int clientIndex)
        {
            // Same recording rule as DisconnectClient: disconnecting a loopback client is a kick (b6c0cee).
            if (IsClientConnected(clientIndex) && GetClientDisconnectReason(clientIndex) == ServerClientDisconnectReason.YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_NONE)
                SetClientDisconnectReason(clientIndex, ServerClientDisconnectReason.YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_KICKED);
            netcode.server_disconnect_loopback_client(m_server, clientIndex);
        }

        public override bool IsLoopbackClient(int clientIndex) =>
            netcode.server_client_loopback(m_server, clientIndex);

        public override void ProcessLoopbackPacket(int clientIndex, byte[] packetData, int packetBytes, ulong packetSequence) =>
            netcode.server_process_loopback_packet(m_server, clientIndex, packetData, packetBytes, packetSequence);

        /**
            Gets the local address the server socket is bound to (with the actual port, when port 0 was passed in).
            Under custom packet I/O there is no socket: this is the constructor-supplied synthetic address, unchanged.
            Returns a copy.
         */
        public Address Address => new Address(m_boundAddress);

        protected override void TransmitPacketFunction(int clientIndex, ushort packetSequence, byte[] packetData, int packetBytes)
        {
            var networkSimulator = NetworkSimulator;
            if (networkSimulator != null && networkSimulator.IsActive)
                networkSimulator.SendPacket(clientIndex, packetData, packetBytes);
            else
                netcode.server_send_packet(m_server, clientIndex, packetData, packetBytes);
        }

        protected override bool ProcessPacketFunction(int clientIndex, ushort packetSequence, byte[] packetData, int packetBytes) =>
            GetClientConnection(clientIndex).ProcessPacket(Context, packetSequence, packetData, packetBytes);

        void ConnectDisconnectCallbackFunction(int clientIndex, int connected)
        {
            if (connected == 0)
            {
                // If no reason was recorded before the transport-level disconnect (connection error,
                // kick), ask netcode why: the client either timed out or cleanly disconnected.
                // Record it before the adapter callback, so OnServerClientDisconnected can query it.
                if (GetClientDisconnectReason(clientIndex) == ServerClientDisconnectReason.YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_NONE)
                {
                    // m_server is null while Stop tears the netcode server down. Disconnects delivered during that
                    // window are always netcode SERVER_DISCONNECT, never TIMED_OUT.
                    var netcodeReason = m_server != null ? netcode.server_client_disconnect_reason(m_server, clientIndex)
                                                         : netcode.SERVER_CLIENT_DISCONNECT_REASON_SERVER_DISCONNECT;
                    SetClientDisconnectReason(clientIndex, netcodeReason == netcode.SERVER_CLIENT_DISCONNECT_REASON_TIMED_OUT
                        ? ServerClientDisconnectReason.YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_TIMED_OUT
                        : ServerClientDisconnectReason.YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_DISCONNECTED);
                }
                Adapter.OnServerClientDisconnected(clientIndex);
                var endpoint = GetClientEndpoint(clientIndex);
                if (endpoint != null)
                    reliable.endpoint_reset(endpoint);
                GetClientConnection(clientIndex).Reset();
                var networkSimulator = NetworkSimulator;
                if (networkSimulator != null && networkSimulator.IsActive)
                    networkSimulator.DiscardClientPackets(clientIndex);
            }
            else
            {
                // This slot now belongs to a new client: clear any disconnect reason left behind by the previous occupant.
                SetClientDisconnectReason(clientIndex, ServerClientDisconnectReason.YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_NONE);
                Adapter.OnServerClientConnected(clientIndex);
            }
        }

        void SendLoopbackPacketCallbackFunction(int clientIndex, byte[] packetData, int packetBytes, ulong packetSequence) =>
            Adapter.ServerSendLoopbackPacket(clientIndex, packetData, packetBytes, packetSequence);

        static void StaticConnectDisconnectCallbackFunction(object context, int clientIndex, int connected)
        {
            var server = (Server)context;
            server.ConnectDisconnectCallbackFunction(clientIndex, connected);
        }

        static void StaticSendLoopbackPacketCallbackFunction(object context, int clientIndex, byte[] packetData, int packetBytes, ulong packetSequence)
        {
            var server = (Server)context;
            server.SendLoopbackPacketCallbackFunction(clientIndex, packetData, packetBytes, packetSequence);
        }

        static void StaticSendPacketOverride(object context, netcode_address_t to, byte[] packetData, int packetBytes)
        {
            var server = (Server)context;
            var address = yojimbo.AddressFromNetcode(to);
            if (address.IsValid)
                server.Adapter.SendPacket(address, packetData, packetBytes);
        }

        static int StaticReceivePacketOverride(object context, netcode_address_t from, byte[] packetData, int maxPacketBytes)
        {
            var server = (Server)context;
            var address = new Address();
            var packetBytes = server.Adapter.ReceivePacket(ref address, packetData, maxPacketBytes);
            if (packetBytes <= 0 || packetBytes > maxPacketBytes || !yojimbo.AddressToNetcode(address, from))
                return 0;
            return packetBytes;
        }

        ClientServerConfig m_config;                        ///< Client/server configuration (a private copy).
        netcode_server_t m_server;                          ///< netcode server.
        Address m_address;                                  ///< Original address passed to ctor.
        Address m_boundAddress;                             ///< Address after socket bind, eg. valid port. Custom packet I/O: stays the ctor-supplied synthetic address (no socket bind).
        byte[] m_privateKey = new byte[yojimbo.KeyBytes];   ///< The private key.
        bool m_stopping;                                    ///< True while Stop tears the server down. Makes a reentrant Stop from an adapter callback during teardown a harmless no-op.
    }
}
