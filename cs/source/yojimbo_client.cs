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
        The reason this client was last disconnected.
        This lets you distinguish what to show the player and what to do next: a denied connection (eg. server full),
        an expired or invalid connect token (eg. matchmaking took too long, or a client/server version mismatch),
        a timeout, or a protocol error such as a message that failed to serialize.
        Cleared to NONE when a new connect attempt starts. The first reason recorded for a disconnect wins, so a
        specific error is never overwritten by the generic disconnect that follows it.
        @see BaseClient::GetDisconnectReason
     */
    public enum ClientDisconnectReason
    {
        YOJIMBO_CLIENT_DISCONNECT_REASON_NONE = 0,                          ///< No disconnect has happened yet (or a new connect attempt is in progress).
        YOJIMBO_CLIENT_DISCONNECT_REASON_DISCONNECTED,                      ///< You called Client::Disconnect. A deliberate local disconnect.
        YOJIMBO_CLIENT_DISCONNECT_REASON_DISCONNECTED_BY_SERVER,            ///< The server disconnected us. The server was stopped, or it kicked this client.
        YOJIMBO_CLIENT_DISCONNECT_REASON_CONNECTION_DENIED,                 ///< The server denied the connection request. For example, the server is full.
        YOJIMBO_CLIENT_DISCONNECT_REASON_CONNECTION_REQUEST_TIMED_OUT,      ///< No response from the server to our connection request. Server not running, unreachable, or wrong address.
        YOJIMBO_CLIENT_DISCONNECT_REASON_CONNECTION_RESPONSE_TIMED_OUT,     ///< No response from the server to our challenge response while establishing the connection.
        YOJIMBO_CLIENT_DISCONNECT_REASON_CONNECTION_TIMED_OUT,              ///< The established connection timed out. We stopped hearing from the server.
        YOJIMBO_CLIENT_DISCONNECT_REASON_INVALID_CONNECT_TOKEN,             ///< The connect token is invalid, or could not be generated.
        YOJIMBO_CLIENT_DISCONNECT_REASON_CONNECT_TOKEN_EXPIRED,             ///< The connect token expired before we could connect. Request a fresh one from the matchmaker and retry.
        YOJIMBO_CLIENT_DISCONNECT_REASON_FAILED_TO_SERIALIZE,               ///< A message from the server failed to serialize read. Usually a client/server protocol version mismatch, or a bug in a message serialize function.
        YOJIMBO_CLIENT_DISCONNECT_REASON_DESYNC,                            ///< A channel desynced and cannot recover. See CHANNEL_ERROR_DESYNC.
        YOJIMBO_CLIENT_DISCONNECT_REASON_SEND_QUEUE_FULL,                   ///< A channel send queue filled up. See CHANNEL_ERROR_SEND_QUEUE_FULL.
        YOJIMBO_CLIENT_DISCONNECT_REASON_BLOCKS_DISABLED,                   ///< The server sent block data on a channel that is configured with blocks disabled.
        YOJIMBO_CLIENT_DISCONNECT_REASON_MESSAGE_TOO_LARGE,                 ///< Tried to send a message too large to ever fit into a packet. See CHANNEL_ERROR_MESSAGE_TOO_LARGE.
        YOJIMBO_CLIENT_DISCONNECT_REASON_OUT_OF_MEMORY,                     ///< The client memory budget was exhausted, or an adapter factory failed.
        YOJIMBO_CLIENT_DISCONNECT_REASON_READ_PACKET_FAILED,                ///< A connection packet from the server failed to deserialize.
    }

    static partial class yojimbo
    {
        /// Helper function to convert a client disconnect reason to a user friendly string.
        public static string GetClientDisconnectReasonString(ClientDisconnectReason reason)
        {
            switch (reason)
            {
                case ClientDisconnectReason.YOJIMBO_CLIENT_DISCONNECT_REASON_NONE: return "none";
                case ClientDisconnectReason.YOJIMBO_CLIENT_DISCONNECT_REASON_DISCONNECTED: return "disconnected";
                case ClientDisconnectReason.YOJIMBO_CLIENT_DISCONNECT_REASON_DISCONNECTED_BY_SERVER: return "disconnected by server";
                case ClientDisconnectReason.YOJIMBO_CLIENT_DISCONNECT_REASON_CONNECTION_DENIED: return "connection denied";
                case ClientDisconnectReason.YOJIMBO_CLIENT_DISCONNECT_REASON_CONNECTION_REQUEST_TIMED_OUT: return "connection request timed out";
                case ClientDisconnectReason.YOJIMBO_CLIENT_DISCONNECT_REASON_CONNECTION_RESPONSE_TIMED_OUT: return "connection response timed out";
                case ClientDisconnectReason.YOJIMBO_CLIENT_DISCONNECT_REASON_CONNECTION_TIMED_OUT: return "connection timed out";
                case ClientDisconnectReason.YOJIMBO_CLIENT_DISCONNECT_REASON_INVALID_CONNECT_TOKEN: return "invalid connect token";
                case ClientDisconnectReason.YOJIMBO_CLIENT_DISCONNECT_REASON_CONNECT_TOKEN_EXPIRED: return "connect token expired";
                case ClientDisconnectReason.YOJIMBO_CLIENT_DISCONNECT_REASON_FAILED_TO_SERIALIZE: return "failed to serialize";
                case ClientDisconnectReason.YOJIMBO_CLIENT_DISCONNECT_REASON_DESYNC: return "desync";
                case ClientDisconnectReason.YOJIMBO_CLIENT_DISCONNECT_REASON_SEND_QUEUE_FULL: return "send queue full";
                case ClientDisconnectReason.YOJIMBO_CLIENT_DISCONNECT_REASON_BLOCKS_DISABLED: return "blocks disabled";
                case ClientDisconnectReason.YOJIMBO_CLIENT_DISCONNECT_REASON_MESSAGE_TOO_LARGE: return "message too large";
                case ClientDisconnectReason.YOJIMBO_CLIENT_DISCONNECT_REASON_OUT_OF_MEMORY: return "out of memory";
                case ClientDisconnectReason.YOJIMBO_CLIENT_DISCONNECT_REASON_READ_PACKET_FAILED: return "read packet failed";
                default:
                    assert(false);
                    return "(unknown)";
            }
        }
    }

    /**
        Implementation of client for dedicated servers.
     */
    public class Client : BaseClient
    {
        /**
            Map a netcode client error state to the disconnect reason we record for this client.
            This is where "server is full" vs "update your client" vs "network problem" comes from.
         */
        static ClientDisconnectReason ClientDisconnectReasonForNetcodeState(int netcodeState)
        {
            switch (netcodeState)
            {
                case netcode.CLIENT_STATE_CONNECT_TOKEN_EXPIRED: return ClientDisconnectReason.YOJIMBO_CLIENT_DISCONNECT_REASON_CONNECT_TOKEN_EXPIRED;
                case netcode.CLIENT_STATE_INVALID_CONNECT_TOKEN: return ClientDisconnectReason.YOJIMBO_CLIENT_DISCONNECT_REASON_INVALID_CONNECT_TOKEN;
                case netcode.CLIENT_STATE_CONNECTION_TIMED_OUT: return ClientDisconnectReason.YOJIMBO_CLIENT_DISCONNECT_REASON_CONNECTION_TIMED_OUT;
                case netcode.CLIENT_STATE_CONNECTION_RESPONSE_TIMED_OUT: return ClientDisconnectReason.YOJIMBO_CLIENT_DISCONNECT_REASON_CONNECTION_RESPONSE_TIMED_OUT;
                case netcode.CLIENT_STATE_CONNECTION_REQUEST_TIMED_OUT: return ClientDisconnectReason.YOJIMBO_CLIENT_DISCONNECT_REASON_CONNECTION_REQUEST_TIMED_OUT;
                case netcode.CLIENT_STATE_CONNECTION_DENIED: return ClientDisconnectReason.YOJIMBO_CLIENT_DISCONNECT_REASON_CONNECTION_DENIED;
                default: return ClientDisconnectReason.YOJIMBO_CLIENT_DISCONNECT_REASON_DISCONNECTED_BY_SERVER;
            }
        }

        /**
            The client constructor.
            @param allocator The allocator for all memory used by the client.
            @param address The address the client should bind to.
            @param config The client/server configuration.
            @param time The current time in seconds. See ClientInterface::AdvanceTime
         */
        public Client(Allocator allocator, Address address, ClientServerConfig config, Adapter adapter, double time)
            : base(allocator, config, adapter, time)
        {
            m_config = config.Clone();
            m_address = new Address(address);
            m_clientId = 0;
            m_client = null;
            m_boundAddress = new Address(address);
            m_disconnecting = false;
        }

        public override void Dispose()
        {
            // IMPORTANT: Please disconnect the client before destroying it
            yojimbo.assert(m_client == null);
            base.Dispose();
        }

        /// Connect to a server with an insecure connect token generated on the client (testing only). @returns False if the connect could not be started.
        public bool InsecureConnect(byte[] privateKey, ulong clientId, Address address) =>
            InsecureConnect(privateKey, clientId, new[] { address }, 1);

        public bool InsecureConnect(byte[] privateKey, ulong clientId, Address[] serverAddresses, int numServerAddresses)
        {
            yojimbo.assert(serverAddresses != null);
            yojimbo.assert(numServerAddresses > 0);
            yojimbo.assert(numServerAddresses <= netcode.MAX_SERVERS_PER_CONNECT);
            Disconnect();
            if (!CreateInternal())
            {
                // CreateInternal already unwound everything it had allocated, so the client is exactly as it was before this call.
                SetDisconnectReason(ClientDisconnectReason.YOJIMBO_CLIENT_DISCONNECT_REASON_OUT_OF_MEMORY);
                SetClientState(ClientState.CLIENT_STATE_ERROR);
                return false;
            }
            SetDisconnectReason(ClientDisconnectReason.YOJIMBO_CLIENT_DISCONNECT_REASON_NONE);    // new connect attempt: clear the reason from any previous disconnect
            m_clientId = clientId;
            CreateClient(m_address);
            if (m_client == null)
            {
                Disconnect();
                return false;
            }
            var connectToken = new byte[netcode.CONNECT_TOKEN_BYTES];
            if (!GenerateInsecureConnectToken(connectToken, privateKey, clientId, serverAddresses, numServerAddresses))
            {
                yojimbo.printf(yojimbo.LOG_LEVEL_ERROR, "error: failed to generate insecure connect token\n");
                SetDisconnectReason(ClientDisconnectReason.YOJIMBO_CLIENT_DISCONNECT_REASON_INVALID_CONNECT_TOKEN);
                SetClientState(ClientState.CLIENT_STATE_ERROR);
                return false;
            }
            netcode.client_connect(m_client, connectToken);
            SetClientState(ClientState.CLIENT_STATE_CONNECTING);
            return true;
        }

        /// Connect to a server with a secure connect token from a matchmaker. @returns False if the connect failed immediately (see GetDisconnectReason).
        public bool Connect(ulong clientId, byte[] connectToken)
        {
            yojimbo.assert(connectToken != null);
            Disconnect();
            if (!CreateInternal())
            {
                SetDisconnectReason(ClientDisconnectReason.YOJIMBO_CLIENT_DISCONNECT_REASON_OUT_OF_MEMORY);
                SetClientState(ClientState.CLIENT_STATE_ERROR);
                return false;
            }
            SetDisconnectReason(ClientDisconnectReason.YOJIMBO_CLIENT_DISCONNECT_REASON_NONE);    // new connect attempt: clear the reason from any previous disconnect
            m_clientId = clientId;
            CreateClient(m_address);
            if (m_client == null)
            {
                // Socket creation/bind failed (e.g. port in use, invalid bind address). Bail before calling into netcode (9c4de3d).
                Disconnect();
                return false;
            }
            netcode.client_connect(m_client, connectToken);
            if (netcode.client_state(m_client) > netcode.CLIENT_STATE_DISCONNECTED)
            {
                SetClientState(ClientState.CLIENT_STATE_CONNECTING);
                return true;
            }
            // The connect failed immediately, eg. an invalid connect token.
            SetDisconnectReason(ClientDisconnectReasonForNetcodeState(netcode.client_state(m_client)));
            Disconnect();
            return false;
        }

        public override void Disconnect()
        {
            // Stop-in-progress guard: client_destroy (inside DestroyClient below) sends disconnect packets, so an adapter
            // SendPacket callback can call Disconnect from inside this teardown. That reentrant call must be a no-op (bd8a01b).
            if (m_disconnecting)
                return;
            m_disconnecting = true;
            // Record a deliberate local disconnect, but only if no more specific reason was already recorded.
            // Checked before base.Disconnect below, because that resets the client state.
            if ((IsConnecting || IsConnected) && GetDisconnectReason() == ClientDisconnectReason.YOJIMBO_CLIENT_DISCONNECT_REASON_NONE)
                SetDisconnectReason(ClientDisconnectReason.YOJIMBO_CLIENT_DISCONNECT_REASON_DISCONNECTED);
            base.Disconnect();
            DestroyClient();
            DestroyInternal();
            m_clientId = 0;
            m_disconnecting = false;
        }

        public override void SendPackets()
        {
            if (!IsConnected)
                return;
            yojimbo.assert(m_client != null);
            var packetData = PacketBuffer;
            var packetSequence = reliable.endpoint_next_packet_sequence(Endpoint);
            if (Connection.GeneratePacket(Context, packetSequence, packetData, m_config.maxPacketSize, out var packetBytes))
                reliable.endpoint_send_packet(Endpoint, packetData, packetBytes);
        }

        public override void ReceivePackets()
        {
            if (!IsConnected)
                return;
            yojimbo.assert(m_client != null);
            while (true)
            {
                var packetData = netcode.client_receive_packet(m_client, out var packetBytes, out var packetSequence);
                if (packetData == null)
                    break;
                reliable.endpoint_receive_packet(Endpoint, packetData, packetBytes);
                netcode.client_free_packet(m_client, ref packetData);
            }
        }

        public override void AdvanceTime(double time)
        {
            base.AdvanceTime(time);
            if (m_client != null)
            {
                netcode.client_update(m_client, time);
                var state = netcode.client_state(m_client);
                if (state < netcode.CLIENT_STATE_DISCONNECTED)
                {
                    // Record why netcode failed (denied, token expired/invalid, timed out) before the disconnect.
                    if (GetDisconnectReason() == ClientDisconnectReason.YOJIMBO_CLIENT_DISCONNECT_REASON_NONE)
                        SetDisconnectReason(ClientDisconnectReasonForNetcodeState(state));
                    Disconnect();
                    SetClientState(ClientState.CLIENT_STATE_ERROR);
                }
                else if (state == netcode.CLIENT_STATE_DISCONNECTED)
                {
                    // netcode dropped to disconnected while we thought we were connecting/connected:
                    // the server disconnected us (server stopped, or kicked this client).
                    if (GetDisconnectReason() == ClientDisconnectReason.YOJIMBO_CLIENT_DISCONNECT_REASON_NONE)
                        SetDisconnectReason(ClientDisconnectReason.YOJIMBO_CLIENT_DISCONNECT_REASON_DISCONNECTED_BY_SERVER);
                    Disconnect();
                    SetClientState(ClientState.CLIENT_STATE_DISCONNECTED);
                }
                else if (state == netcode.CLIENT_STATE_SENDING_CONNECTION_REQUEST || state == netcode.CLIENT_STATE_SENDING_CONNECTION_RESPONSE)
                    SetClientState(ClientState.CLIENT_STATE_CONNECTING);
                else
                    SetClientState(ClientState.CLIENT_STATE_CONNECTED);
                var networkSimulator = NetworkSimulator;
                if (m_client != null && networkSimulator != null && networkSimulator.IsActive)
                {
                    // Drain the simulator in fixed size batches (df89f67).
                    const int MaxBatchPackets = 64;
                    var packetData = new byte[MaxBatchPackets][];
                    var packetBytes = new int[MaxBatchPackets];
                    while (true)
                    {
                        var numPackets = networkSimulator.ReceivePackets(MaxBatchPackets, packetData, packetBytes, null);
                        if (numPackets == 0)
                            break;
                        for (var i = 0; i < numPackets; ++i)
                        {
                            netcode.client_send_packet(m_client, packetData[i], packetBytes[i]);
                            yojimbo.YOJIMBO_FREE(networkSimulator.Allocator, ref packetData[i]);
                        }
                    }
                }
            }
        }

        public override int ClientIndex =>
            m_client != null ? netcode.client_index(m_client) : -1;

        public override ulong ClientId => m_clientId;

        public override bool ConnectLoopback(int clientIndex, ulong clientId, int maxClients)
        {
            Disconnect();
            if (!CreateInternal())
            {
                SetDisconnectReason(ClientDisconnectReason.YOJIMBO_CLIENT_DISCONNECT_REASON_OUT_OF_MEMORY);
                SetClientState(ClientState.CLIENT_STATE_ERROR);
                return false;
            }
            SetDisconnectReason(ClientDisconnectReason.YOJIMBO_CLIENT_DISCONNECT_REASON_NONE);    // new connect attempt: clear the reason from any previous disconnect
            m_clientId = clientId;
            CreateClient(m_address);
            if (m_client == null)
            {
                // Socket creation/bind failed. Bail before netcode dereferences the client (9c4de3d).
                Disconnect();
                return false;
            }
            netcode.client_connect_loopback(m_client, clientIndex, maxClients);
            SetClientState(ClientState.CLIENT_STATE_CONNECTED);
            return true;
        }

        public override void DisconnectLoopback()
        {
            // Same stop-in-progress guard as Client.Disconnect.
            if (m_disconnecting)
                return;
            m_disconnecting = true;
            if ((IsConnecting || IsConnected) && GetDisconnectReason() == ClientDisconnectReason.YOJIMBO_CLIENT_DISCONNECT_REASON_NONE)
                SetDisconnectReason(ClientDisconnectReason.YOJIMBO_CLIENT_DISCONNECT_REASON_DISCONNECTED);
            if (m_client != null)
                netcode.client_disconnect_loopback(m_client);
            base.Disconnect();
            DestroyClient();
            DestroyInternal();
            m_clientId = 0;
            m_disconnecting = false;
        }

        /// Safe to query in any state: when not connected there is no netcode client, so this is not a loopback client (997109d).
        public override bool IsLoopback =>
            m_client != null && netcode.client_loopback(m_client);

        public override void ProcessLoopbackPacket(byte[] packetData, int packetBytes, ulong packetSequence) =>
            netcode.client_process_loopback_packet(m_client, packetData, packetBytes, packetSequence);

        /**
            Gets the local address the client socket is bound to (with the actual port).
            Under custom packet I/O there is no socket: this is the constructor-supplied synthetic address, unchanged.
            Returns a copy.
         */
        public Address Address => new Address(m_boundAddress);

        protected bool GenerateInsecureConnectToken(
            byte[] connectToken,
            byte[] privateKey,
            ulong clientId,
            Address[] serverAddresses,
            int numServerAddresses)
        {
            var serverAddressStringPointers = new string[netcode.MAX_SERVERS_PER_CONNECT];
            for (var i = 0; i < numServerAddresses; ++i)
                serverAddressStringPointers[i] = serverAddresses[i].ToString();
            var userData = new byte[256];

            // Give the insecure connect token an expiry well above the connection timeout, so a
            // failed insecure connect reports "connection request timed out" just like a secure
            // connect token from a matchmaker would (fd8091c). It must also be at least the server's
            // max_connect_token_lifetime, or netcode refuses it as predating the server start.
            var expireSeconds = Math.Max(yojimbo.InsecureConnectTokenExpirySeconds, m_config.timeout * 2);

            return netcode.generate_connect_token(
                numServerAddresses,
                serverAddressStringPointers,
                serverAddressStringPointers,
                expireSeconds,
                m_config.timeout,
                clientId,
                m_config.protocolId,
                privateKey,
                userData,
                connectToken) == netcode.OK;
        }

        protected void CreateClient(Address address)
        {
            DestroyClient();
            var addressString = address.ToString();

            netcode.default_client_config(out var netcodeConfig);
            netcodeConfig.allocator_context = ClientAllocator;
            netcodeConfig.allocate_function = StaticAllocateFunction;
            netcodeConfig.free_function = StaticFreeFunction;
            netcodeConfig.callback_context = this;
            netcodeConfig.state_change_callback = StaticStateChangeCallbackFunction;
            netcodeConfig.send_loopback_packet_callback = StaticSendLoopbackPacketCallbackFunction;
            var useCustomPacketIO = Adapter.UseCustomPacketIO();
            if (useCustomPacketIO)
            {
                netcodeConfig.override_send_and_receive = true;
                netcodeConfig.send_packet_override = StaticSendPacketOverride;
                netcodeConfig.receive_packet_override = StaticReceivePacketOverride;
            }
            m_client = netcode.client_create(addressString, netcodeConfig, Time);

            if (m_client != null && !useCustomPacketIO)
                m_boundAddress.Port = netcode.client_get_port(m_client);
        }

        protected void DestroyClient()
        {
            if (m_client != null)
            {
                m_boundAddress = new Address(m_address);
                // Clear the member before destroying, so an adapter that calls Disconnect from inside a teardown-time
                // SendPacket callback can't re-enter here and destroy the same netcode client twice.
                var client = m_client;
                m_client = null;
                netcode.client_destroy(ref client);
            }
        }

        protected void StateChangeCallbackFunction(int previous, int current)
        {
        }

        protected static void StaticStateChangeCallbackFunction(object context, int previous, int current)
        {
            var client = (Client)context;
            client.StateChangeCallbackFunction(previous, current);
        }

        protected override void TransmitPacketFunction(ushort packetSequence, byte[] packetData, int packetBytes)
        {
            var networkSimulator = NetworkSimulator;
            if (networkSimulator != null && networkSimulator.IsActive)
                networkSimulator.SendPacket(0, packetData, packetBytes);
            else
                netcode.client_send_packet(m_client, packetData, packetBytes);
        }

        protected override bool ProcessPacketFunction(ushort packetSequence, byte[] packetData, int packetBytes) =>
            Connection.ProcessPacket(Context, packetSequence, packetData, packetBytes);

        protected void SendLoopbackPacketCallbackFunction(int clientIndex, byte[] packetData, int packetBytes, ulong packetSequence) =>
            Adapter.ClientSendLoopbackPacket(clientIndex, packetData, packetBytes, packetSequence);

        protected static void StaticSendLoopbackPacketCallbackFunction(object context, int clientIndex, byte[] packetData, int packetBytes, ulong packetSequence)
        {
            var client = (Client)context;
            client.SendLoopbackPacketCallbackFunction(clientIndex, packetData, packetBytes, packetSequence);
        }

        static void StaticSendPacketOverride(object context, netcode_address_t to, byte[] packetData, int packetBytes)
        {
            var client = (Client)context;
            var address = yojimbo.AddressFromNetcode(to);
            if (address.IsValid)
                client.Adapter.SendPacket(address, packetData, packetBytes);
        }

        static int StaticReceivePacketOverride(object context, netcode_address_t from, byte[] packetData, int maxPacketBytes)
        {
            var client = (Client)context;
            var address = new Address();
            var packetBytes = client.Adapter.ReceivePacket(ref address, packetData, maxPacketBytes);
            if (packetBytes <= 0 || packetBytes > maxPacketBytes || !yojimbo.AddressToNetcode(address, from))
                return 0;
            return packetBytes;
        }

        ClientServerConfig m_config;                    ///< Client/server configuration (a private copy).
        netcode_client_t m_client;                      ///< netcode.io client data.
        Address m_address;                              ///< Original address passed to ctor.
        Address m_boundAddress;                         ///< Address after socket bind, eg. with valid port. Custom packet I/O: stays the ctor-supplied synthetic address.
        ulong m_clientId;                               ///< The globally unique client id (set on each call to connect)
        bool m_disconnecting;                           ///< True while Disconnect tears the client down. Makes a reentrant Disconnect from an adapter callback a harmless no-op.
    }
}
