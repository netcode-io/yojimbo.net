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
        Functionality that is common across all client implementations.
     */
    public abstract class BaseClient : IClient
    {
        /**
            Base client constructor.
            @param allocator The allocator for all memory used by the client.
            @param config The base client/server configuration.
            @param time The current time in seconds. See ClientInterface::AdvanceTime
            @param allocator The adapter to the game program. Specifies allocators, message factory to use etc.
         */
        public BaseClient(Allocator allocator, ClientServerConfig config, Adapter adapter, double time)
        {
            m_config = config.Clone();
            m_allocator = allocator;
            m_adapter = adapter;
            m_time = time;
            m_context = null;
            m_clientMemory = null;
            m_clientAllocator = null;
            m_endpoint = null;
            m_connection = null;
            m_messageFactory = null;
            m_networkSimulator = null;
            m_clientState = ClientState.CLIENT_STATE_DISCONNECTED;
            m_clientIndex = -1;
            m_disconnectReason = ClientDisconnectReason.YOJIMBO_CLIENT_DISCONNECT_REASON_NONE;
            m_packetBuffer = null;
        }

        public virtual void Dispose()
        {
            // IMPORTANT: Please disconnect the client before destroying it
            yojimbo.assert(m_clientState <= ClientState.CLIENT_STATE_DISCONNECTED);
            yojimbo.assert(m_packetBuffer == null);
            m_allocator = null;
        }

        public virtual object Context
        {
            get => m_context;
            set { yojimbo.assert(IsDisconnected); m_context = value; }
        }

        public virtual void Disconnect()
        {
            SetClientState(ClientState.CLIENT_STATE_DISCONNECTED);
            Reset();
        }

        /**
            Map the error that drove the connection into an error state to the disconnect reason we
            record for this client. For channel errors, drill into the channels to find the one in error.
         */
        static ClientDisconnectReason ClientDisconnectReasonForConnectionError(Connection connection, ConnectionErrorLevel errorLevel, int numChannels)
        {
            switch (errorLevel)
            {
                case ConnectionErrorLevel.CONNECTION_ERROR_ALLOCATOR: return ClientDisconnectReason.YOJIMBO_CLIENT_DISCONNECT_REASON_OUT_OF_MEMORY;
                case ConnectionErrorLevel.CONNECTION_ERROR_MESSAGE_FACTORY: return ClientDisconnectReason.YOJIMBO_CLIENT_DISCONNECT_REASON_OUT_OF_MEMORY;
                case ConnectionErrorLevel.CONNECTION_ERROR_READ_PACKET_FAILED: return ClientDisconnectReason.YOJIMBO_CLIENT_DISCONNECT_REASON_READ_PACKET_FAILED;
                case ConnectionErrorLevel.CONNECTION_ERROR_CHANNEL:
                    for (var i = 0; i < numChannels; ++i)
                    {
                        switch (connection.GetChannelErrorLevel(i))
                        {
                            case ChannelErrorLevel.CHANNEL_ERROR_DESYNC: return ClientDisconnectReason.YOJIMBO_CLIENT_DISCONNECT_REASON_DESYNC;
                            case ChannelErrorLevel.CHANNEL_ERROR_SEND_QUEUE_FULL: return ClientDisconnectReason.YOJIMBO_CLIENT_DISCONNECT_REASON_SEND_QUEUE_FULL;
                            case ChannelErrorLevel.CHANNEL_ERROR_BLOCKS_DISABLED: return ClientDisconnectReason.YOJIMBO_CLIENT_DISCONNECT_REASON_BLOCKS_DISABLED;
                            case ChannelErrorLevel.CHANNEL_ERROR_FAILED_TO_SERIALIZE: return ClientDisconnectReason.YOJIMBO_CLIENT_DISCONNECT_REASON_FAILED_TO_SERIALIZE;
                            case ChannelErrorLevel.CHANNEL_ERROR_OUT_OF_MEMORY: return ClientDisconnectReason.YOJIMBO_CLIENT_DISCONNECT_REASON_OUT_OF_MEMORY;
                            case ChannelErrorLevel.CHANNEL_ERROR_MESSAGE_TOO_LARGE: return ClientDisconnectReason.YOJIMBO_CLIENT_DISCONNECT_REASON_MESSAGE_TOO_LARGE;
                            case ChannelErrorLevel.CHANNEL_ERROR_NONE: break;
                        }
                    }
                    break;
                case ConnectionErrorLevel.CONNECTION_ERROR_NONE:
                    break;
            }
            return ClientDisconnectReason.YOJIMBO_CLIENT_DISCONNECT_REASON_DISCONNECTED;
        }

        public virtual void AdvanceTime(double time)
        {
            m_time = time;
            if (m_endpoint != null)
            {
                m_connection.AdvanceTime(time);
                var connectionErrorLevel = m_connection.ErrorLevel;
                if (connectionErrorLevel != ConnectionErrorLevel.CONNECTION_ERROR_NONE)
                {
                    yojimbo.printf(yojimbo.LOG_LEVEL_DEBUG, "connection error. disconnecting client\n");
                    SetDisconnectReason(ClientDisconnectReasonForConnectionError(m_connection, connectionErrorLevel, m_config.numChannels));
                    Disconnect();
                    return;
                }
                reliable.endpoint_update(m_endpoint, m_time);
                var acks = reliable.endpoint_get_acks(m_endpoint, out var numAcks);
                m_connection.ProcessAcks(acks, numAcks);
                reliable.endpoint_clear_acks(m_endpoint);
            }
            var networkSimulator = NetworkSimulator;
            if (networkSimulator != null)
                networkSimulator.AdvanceTime(time);
        }

        public virtual bool IsConnecting => m_clientState == ClientState.CLIENT_STATE_CONNECTING;

        public virtual bool IsConnected => m_clientState == ClientState.CLIENT_STATE_CONNECTED;

        public virtual bool IsDisconnected => m_clientState <= ClientState.CLIENT_STATE_DISCONNECTED;

        public virtual bool ConnectionFailed => m_clientState == ClientState.CLIENT_STATE_ERROR;

        public virtual ClientState ClientState => m_clientState;

        public virtual int ClientIndex => m_clientIndex;

        public virtual double Time => m_time;

        /**
            Get the reason this client was last disconnected.
            Cleared to NONE when a new connect attempt starts. The first reason recorded for a disconnect wins.
         */
        public ClientDisconnectReason GetDisconnectReason() => m_disconnectReason;
        public ClientDisconnectReason DisconnectReason => m_disconnectReason;

        /// Set the network simulator latency. IMPORTANT: the simulator is created on connect, so call this after connecting (e79ad2a).
        public void SetLatency(float milliseconds)
        {
            yojimbo.assert(m_networkSimulator != null);
            if (m_networkSimulator != null)
                m_networkSimulator.SetLatency(milliseconds);
        }

        /// Set the network simulator jitter. IMPORTANT: call after connecting.
        public void SetJitter(float milliseconds)
        {
            yojimbo.assert(m_networkSimulator != null);
            if (m_networkSimulator != null)
                m_networkSimulator.SetJitter(milliseconds);
        }

        /// Set the network simulator packet loss. IMPORTANT: call after connecting.
        public void SetPacketLoss(float percent)
        {
            yojimbo.assert(m_networkSimulator != null);
            if (m_networkSimulator != null)
                m_networkSimulator.SetPacketLoss(percent);
        }

        /// Set the network simulator duplicate packet percentage. IMPORTANT: call after connecting.
        public void SetDuplicates(float percent)
        {
            yojimbo.assert(m_networkSimulator != null);
            if (m_networkSimulator != null)
                m_networkSimulator.SetDuplicates(percent);
        }

        public virtual Message CreateMessage(int type)
        {
            yojimbo.assert(m_messageFactory != null);
            return m_messageFactory.CreateMessage(type);
        }

        public virtual byte[] AllocateBlock(int bytes) =>
            yojimbo.YOJIMBO_ALLOCATE(m_clientAllocator, bytes);

        public virtual void AttachBlockToMessage(Message message, byte[] block, int bytes)
        {
            yojimbo.assert(message != null);
            yojimbo.assert(block != null);
            yojimbo.assert(bytes > 0);
            yojimbo.assert(message.IsBlockMessage);
            var blockMessage = (BlockMessage)message;
            blockMessage.AttachBlock(m_clientAllocator, block, bytes);
        }

        public virtual void FreeBlock(ref byte[] block) =>
            yojimbo.YOJIMBO_FREE(m_clientAllocator, ref block);

        public virtual bool CanSendMessage(int channelIndex)
        {
            yojimbo.assert(m_connection != null);
            yojimbo.assert(channelIndex >= 0);
            yojimbo.assert(channelIndex < m_config.numChannels);
            return m_connection.CanSendMessage(channelIndex);
        }

        public bool HasMessagesToSend(int channelIndex)
        {
            yojimbo.assert(m_connection != null);
            yojimbo.assert(channelIndex >= 0);
            yojimbo.assert(channelIndex < m_config.numChannels);
            return m_connection.HasMessagesToSend(channelIndex);
        }

        public virtual void SendMessage(int channelIndex, Message message)
        {
            yojimbo.assert(m_connection != null);
            yojimbo.assert(channelIndex >= 0);
            yojimbo.assert(channelIndex < m_config.numChannels);
            m_connection.SendMessage(channelIndex, message, Context);
        }

        public virtual Message ReceiveMessage(int channelIndex)
        {
            yojimbo.assert(m_connection != null);
            yojimbo.assert(channelIndex >= 0);
            yojimbo.assert(channelIndex < m_config.numChannels);
            return m_connection.ReceiveMessage(channelIndex);
        }

        public virtual void ReleaseMessage<TMessage>(ref TMessage message) where TMessage : Message
        {
            yojimbo.assert(m_connection != null);
            m_connection.ReleaseMessage(ref message);
        }

        public virtual void GetNetworkInfo(out NetworkInfo info)
        {
            info = new NetworkInfo();
            if (m_connection != null)
            {
                yojimbo.assert(m_endpoint != null);
                var counters = reliable.endpoint_counters(m_endpoint);
                info.numPacketsSent = counters[reliable.ENDPOINT_COUNTER_NUM_PACKETS_SENT];
                info.numPacketsReceived = counters[reliable.ENDPOINT_COUNTER_NUM_PACKETS_RECEIVED];
                info.numPacketsAcked = counters[reliable.ENDPOINT_COUNTER_NUM_PACKETS_ACKED];
                info.RTT = reliable.endpoint_rtt(m_endpoint);
                info.minRTT = reliable.endpoint_rtt_min(m_endpoint);
                info.maxRTT = reliable.endpoint_rtt_max(m_endpoint);
                info.averageRTT = reliable.endpoint_rtt_avg(m_endpoint);
                info.averageJitter = reliable.endpoint_jitter_avg_vs_min_rtt(m_endpoint);
                info.maxJitter = reliable.endpoint_jitter_max_vs_min_rtt(m_endpoint);
                info.stddevJitter = reliable.endpoint_jitter_stddev_vs_avg_rtt(m_endpoint);
                info.packetLoss = reliable.endpoint_packet_loss(m_endpoint);
                reliable.endpoint_bandwidth(m_endpoint, out info.sentBandwidth, out info.receivedBandwidth, out info.ackedBandwidth);
            }
        }

        protected byte[] PacketBuffer => m_packetBuffer;

        protected Adapter Adapter { get { yojimbo.assert(m_adapter != null); return m_adapter; } }

        /**
            Create the per-connection internals.
            Startup is transactional: every allocation and every adapter factory result is checked in every build, and the
            first failure unwinds everything already created and leaves the client exactly as it was before the call (f7cb323).
            @returns True on success.
         */
        protected bool CreateInternal()
        {
            yojimbo.assert(m_allocator != null);
            yojimbo.assert(m_adapter != null);
            yojimbo.assert(m_clientMemory == null);
            yojimbo.assert(m_clientAllocator == null);
            yojimbo.assert(m_messageFactory == null);
            m_config.Validate();
            m_packetBuffer = yojimbo.YOJIMBO_ALLOCATE(m_allocator, m_config.maxPacketSize);
            if (m_packetBuffer == null)
            {
                DestroyInternal();
                return false;
            }
            m_clientMemory = yojimbo.YOJIMBO_ALLOCATE_MEMORY(m_allocator, m_config.clientMemory);
            if (m_clientMemory == null)
            {
                DestroyInternal();
                return false;
            }
            m_clientAllocator = m_adapter.CreateAllocator(m_allocator, m_clientMemory, m_config.clientMemory);
            if (m_clientAllocator == null)
            {
                DestroyInternal();
                return false;
            }
            m_messageFactory = m_adapter.CreateMessageFactory(m_clientAllocator);
            if (m_messageFactory == null)
            {
                DestroyInternal();
                return false;
            }
            m_connection = yojimbo.YOJIMBO_NEW(m_clientAllocator, () => new Connection(m_clientAllocator, m_messageFactory, m_config, m_time));
            if (m_connection == null)
            {
                DestroyInternal();
                return false;
            }
            if (m_config.networkSimulator)
            {
                m_networkSimulator = yojimbo.YOJIMBO_NEW(m_clientAllocator, () => new NetworkSimulator(m_clientAllocator, m_config.maxSimulatorPackets, m_time));
                if (m_networkSimulator == null)
                {
                    DestroyInternal();
                    return false;
                }
            }
            reliable.default_config(out var reliable_config);
            reliable_config.name = "client endpoint";
            reliable_config.context = this;
            reliable_config.max_packet_size = m_config.maxPacketSize;
            reliable_config.fragment_above = m_config.fragmentPacketsAbove;
            reliable_config.max_fragments = m_config.maxPacketFragments;
            reliable_config.fragment_size = m_config.packetFragmentSize;
            reliable_config.ack_buffer_size = m_config.ackedPacketsBufferSize;
            reliable_config.received_packets_buffer_size = m_config.receivedPacketsBufferSize;
            reliable_config.fragment_reassembly_buffer_size = m_config.packetReassemblyBufferSize;
            reliable_config.rtt_smoothing_factor = m_config.rttSmoothingFactor;
            reliable_config.transmit_packet_function = StaticTransmitPacketFunction;
            reliable_config.process_packet_function = StaticProcessPacketFunction;
            reliable_config.allocator_context = m_clientAllocator;
            reliable_config.allocate_function = StaticAllocateFunction;
            reliable_config.free_function = StaticFreeFunction;
            m_endpoint = reliable.endpoint_create(reliable_config, m_time);
            if (m_endpoint == null)
            {
                // reliable refuses configs it cannot honor (e.g. maxPacketFragments * packetFragmentSize < maxPacketSize)
                yojimbo.printf(yojimbo.LOG_LEVEL_ERROR, "error: failed to create reliable endpoint. check the ClientServerConfig packet and fragment sizes\n");
                DestroyInternal();
                return false;
            }
            reliable.endpoint_reset(m_endpoint);
            return true;
        }

        /**
            Destroy the per-connection internals.
            Safe to call on a partially created client: CreateInternal unwinds through it.
         */
        protected void DestroyInternal()
        {
            yojimbo.assert(m_allocator != null);
            if (m_endpoint != null)
            {
                reliable.endpoint_destroy(ref m_endpoint);
                m_endpoint = null;
            }
            if (m_clientAllocator != null)
            {
                yojimbo.YOJIMBO_DELETE(m_clientAllocator, ref m_networkSimulator);
                yojimbo.YOJIMBO_DELETE(m_clientAllocator, ref m_connection);
                yojimbo.YOJIMBO_DELETE(m_clientAllocator, ref m_messageFactory);
                yojimbo.YOJIMBO_DELETE(m_allocator, ref m_clientAllocator);
            }
            else
            {
                // Nothing was ever built inside the client allocator, so nothing can be outstanding.
                m_networkSimulator = null;
                m_connection = null;
                m_messageFactory = null;
            }
            yojimbo.YOJIMBO_FREE(m_allocator, ref m_clientMemory);
            yojimbo.YOJIMBO_FREE(m_allocator, ref m_packetBuffer);
        }

        protected void SetClientState(ClientState clientState) =>
            m_clientState = clientState;

        protected void SetDisconnectReason(ClientDisconnectReason disconnectReason) =>
            m_disconnectReason = disconnectReason;

        /// Reset the connection, so messages queued before a disconnect are not sent across a reconnect (06358cf).
        protected virtual void Reset() =>
            m_connection?.Reset();

        protected Allocator ClientAllocator { get { yojimbo.assert(m_clientAllocator != null); return m_clientAllocator; } }

        protected MessageFactory MessageFactory { get { yojimbo.assert(m_messageFactory != null); return m_messageFactory; } }

        protected NetworkSimulator NetworkSimulator => m_networkSimulator;

        protected reliable_endpoint_t Endpoint => m_endpoint;

        protected Connection Connection { get { yojimbo.assert(m_connection != null); return m_connection; } }

        public abstract ulong ClientId { get; }
        public abstract bool IsLoopback { get; }

        protected abstract void TransmitPacketFunction(ushort packetSequence, byte[] packetData, int packetBytes);

        protected abstract bool ProcessPacketFunction(ushort packetSequence, byte[] packetData, int packetBytes);

        protected static void StaticTransmitPacketFunction(object context, ulong index, ushort packetSequence, byte[] packetData, int packetBytes)
        {
            var client = (BaseClient)context;
            client.TransmitPacketFunction(packetSequence, packetData, packetBytes);
        }

        protected static bool StaticProcessPacketFunction(object context, ulong index, ushort packetSequence, byte[] packetData, int packetBytes)
        {
            var client = (BaseClient)context;
            return client.ProcessPacketFunction(packetSequence, packetData, packetBytes);
        }

        protected static object StaticAllocateFunction(object context, ulong bytes) => null;

        protected static void StaticFreeFunction(object context, object pointer) { }

        public abstract void SendPackets();
        public abstract void ReceivePackets();
        public abstract bool ConnectLoopback(int clientIndex, ulong clientId, int maxClients);
        public abstract void DisconnectLoopback();
        public abstract void ProcessLoopbackPacket(byte[] packetData, int packetBytes, ulong packetSequence);

        ClientServerConfig m_config;                                        ///< The client/server configuration (a private copy).
        Allocator m_allocator;                                              ///< The allocator passed to the client on creation.
        Adapter m_adapter;                                                  ///< The adapter specifies the allocator to use, and the message factory class.
        object m_context;                                                   ///< Context lets the user pass information to packet serialize functions.
        object m_clientMemory;                                              ///< The memory backing the client allocator (a placeholder in C#, see yojimbo.YOJIMBO_ALLOCATE_MEMORY). Allocated with m_allocator.
        Allocator m_clientAllocator;                                        ///< The client allocator. Everything allocated between connect and disconnected is allocated and freed via this allocator.
        reliable_endpoint_t m_endpoint;                                     ///< reliable.io endpoint.
        MessageFactory m_messageFactory;                                    ///< The client message factory. Created and destroyed on each connection attempt.
        Connection m_connection;                                            ///< The client connection for exchanging messages with the server.
        NetworkSimulator m_networkSimulator;                                ///< The network simulator used to simulate packet loss, latency, jitter etc. Optional. 
        ClientState m_clientState;                                          ///< The current client state. See ClientInterface::GetClientState
        int m_clientIndex;                                                  ///< The client slot index on the server [0,maxClients-1]. -1 if not connected.
        ClientDisconnectReason m_disconnectReason;                          ///< Why this client was last disconnected. First reason recorded wins; cleared on each connect attempt.
        double m_time;                                                      ///< The current client time. See ClientInterface::AdvanceTime
        byte[] m_packetBuffer;                                              ///< Buffer used to read and write packets. Allocated by CreateInternal, freed by DestroyInternal.
    }
}
