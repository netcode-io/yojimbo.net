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
        Common functionality across all server implementations.
     */
    public abstract class BaseServer : IServer
    {
        public BaseServer(Allocator allocator, ClientServerConfig config, Adapter adapter, double time)
        {
            m_config = config.Clone();
            m_allocator = allocator;
            m_adapter = adapter;
            m_context = null;
            m_time = time;
            m_running = false;
            m_maxClients = 0;
            m_globalMemory = null;
            m_globalAllocator = null;
            for (var i = 0; i < yojimbo.MaxClients; ++i)
            {
                m_clientMemory[i] = null;
                m_clientAllocator[i] = null;
                m_clientMessageFactory[i] = null;
                m_clientConnection[i] = null;
                m_clientEndpoint[i] = null;
                m_clientDisconnectReason[i] = ServerClientDisconnectReason.YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_NONE;
            }
            m_networkSimulator = null;
            m_packetBuffer = null;
        }

        public virtual void Dispose()
        {
            // IMPORTANT: Please stop the server before destroying it!
            yojimbo.assert(!IsRunning);
            m_allocator = null;
        }

        public virtual object Context
        {
            get => m_context;
            set
            {
                yojimbo.assert(!IsRunning);
                m_context = value;
            }
        }

        /**
            Start the server.
            Startup is transactional: every allocation and every adapter factory result is checked in every build,
            and the first failure unwinds through Stop() and leaves the server stopped and holding nothing (f7cb323).
            @returns True if the server started.
         */
        public virtual bool Start(int maxClients)
        {
            yojimbo.assert(maxClients > 0);
            yojimbo.assert(maxClients <= yojimbo.MaxClients);
            m_config.Validate();
            Stop();
            m_running = true;
            m_maxClients = maxClients;
            for (var i = 0; i < yojimbo.MaxClients; ++i)
                m_clientDisconnectReason[i] = ServerClientDisconnectReason.YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_NONE;
            yojimbo.assert(m_globalMemory == null);
            yojimbo.assert(m_globalAllocator == null);
            m_globalMemory = yojimbo.YOJIMBO_ALLOCATE_MEMORY(m_allocator, m_config.serverGlobalMemory);
            if (m_globalMemory == null)
            {
                Stop();
                return false;
            }
            m_globalAllocator = m_adapter.CreateAllocator(m_allocator, m_globalMemory, m_config.serverGlobalMemory);
            if (m_globalAllocator == null)
            {
                Stop();
                return false;
            }
            if (m_config.networkSimulator)
            {
                m_networkSimulator = yojimbo.YOJIMBO_NEW(m_globalAllocator, () => new NetworkSimulator(m_globalAllocator, m_config.maxSimulatorPackets, m_time));
                if (m_networkSimulator == null)
                {
                    Stop();
                    return false;
                }
            }
            for (var i = 0; i < m_maxClients; ++i)
            {
                yojimbo.assert(m_clientMemory[i] == null);
                yojimbo.assert(m_clientAllocator[i] == null);

                m_clientMemory[i] = yojimbo.YOJIMBO_ALLOCATE_MEMORY(m_allocator, m_config.serverPerClientMemory);
                if (m_clientMemory[i] == null)
                {
                    Stop();
                    return false;
                }

                m_clientAllocator[i] = m_adapter.CreateAllocator(m_allocator, m_clientMemory[i], m_config.serverPerClientMemory);
                if (m_clientAllocator[i] == null)
                {
                    Stop();
                    return false;
                }

                m_clientMessageFactory[i] = m_adapter.CreateMessageFactory(m_clientAllocator[i]);
                if (m_clientMessageFactory[i] == null)
                {
                    Stop();
                    return false;
                }

                m_clientConnection[i] = yojimbo.YOJIMBO_NEW(m_clientAllocator[i], () => new Connection(m_clientAllocator[i], m_clientMessageFactory[i], m_config, m_time));
                if (m_clientConnection[i] == null)
                {
                    Stop();
                    return false;
                }

                reliable.default_config(out var reliable_config);
                reliable_config.name = "server endpoint";
                reliable_config.context = this;
                reliable_config.id = (ulong)i;
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
                reliable_config.allocator_context = GlobalAllocator;
                reliable_config.allocate_function = StaticAllocateFunction;
                reliable_config.free_function = StaticFreeFunction;
                m_clientEndpoint[i] = reliable.endpoint_create(reliable_config, m_time);
                if (m_clientEndpoint[i] == null)
                {
                    // reliable refuses configs it cannot honor (e.g. maxPacketFragments * packetFragmentSize < maxPacketSize)
                    yojimbo.printf(yojimbo.LOG_LEVEL_ERROR, "error: failed to create reliable endpoint for client slot. check the ClientServerConfig packet and fragment sizes\n");
                    Stop();
                    return false;
                }
                reliable.endpoint_reset(m_clientEndpoint[i]);
            }
            m_packetBuffer = yojimbo.YOJIMBO_ALLOCATE(m_globalAllocator, m_config.maxPacketSize);
            if (m_packetBuffer == null)
            {
                Stop();
                return false;
            }
            return true;
        }

        /**
            Stop the server.
            Safe to call on a partially started server: Start unwinds through it, so every slot is
            torn down by what it actually holds rather than by what a complete start would have held.
         */
        public virtual void Stop()
        {
            if (IsRunning)
            {
                if (m_globalAllocator != null)
                {
                    yojimbo.YOJIMBO_FREE(m_globalAllocator, ref m_packetBuffer);
                    yojimbo.YOJIMBO_DELETE(m_globalAllocator, ref m_networkSimulator);
                }
                for (var i = 0; i < yojimbo.MaxClients; ++i)
                {
                    if (m_clientEndpoint[i] != null)
                        reliable.endpoint_destroy(ref m_clientEndpoint[i]);
                    m_clientEndpoint[i] = null;
                    if (m_clientAllocator[i] != null)
                    {
                        yojimbo.YOJIMBO_DELETE(m_clientAllocator[i], ref m_clientConnection[i]);
                        yojimbo.YOJIMBO_DELETE(m_clientAllocator[i], ref m_clientMessageFactory[i]);
                        yojimbo.YOJIMBO_DELETE(m_allocator, ref m_clientAllocator[i]);
                    }
                    yojimbo.YOJIMBO_FREE(m_allocator, ref m_clientMemory[i]);
                }
                yojimbo.YOJIMBO_DELETE(m_allocator, ref m_globalAllocator);
                yojimbo.YOJIMBO_FREE(m_allocator, ref m_globalMemory);
            }
            for (var i = 0; i < yojimbo.MaxClients; ++i)
            {
                m_clientMemory[i] = null;
                m_clientAllocator[i] = null;
                m_clientMessageFactory[i] = null;
                m_clientConnection[i] = null;
                m_clientEndpoint[i] = null;
            }
            m_networkSimulator = null;
            m_running = false;
            m_maxClients = 0;
            m_packetBuffer = null;
        }

        /**
            Map the error that drove a connection into an error state to the disconnect reason we
            record for the client slot. For channel errors, drill into the channels to find the one
            in error, because that is where the actionable detail lives.
         */
        static ServerClientDisconnectReason ClientDisconnectReasonForConnectionError(Connection connection, ConnectionErrorLevel errorLevel, int numChannels)
        {
            switch (errorLevel)
            {
                case ConnectionErrorLevel.CONNECTION_ERROR_ALLOCATOR: return ServerClientDisconnectReason.YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_OUT_OF_MEMORY;
                case ConnectionErrorLevel.CONNECTION_ERROR_MESSAGE_FACTORY: return ServerClientDisconnectReason.YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_OUT_OF_MEMORY;
                case ConnectionErrorLevel.CONNECTION_ERROR_READ_PACKET_FAILED: return ServerClientDisconnectReason.YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_READ_PACKET_FAILED;
                case ConnectionErrorLevel.CONNECTION_ERROR_CHANNEL:
                    for (var i = 0; i < numChannels; ++i)
                    {
                        switch (connection.GetChannelErrorLevel(i))
                        {
                            case ChannelErrorLevel.CHANNEL_ERROR_DESYNC: return ServerClientDisconnectReason.YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_DESYNC;
                            case ChannelErrorLevel.CHANNEL_ERROR_SEND_QUEUE_FULL: return ServerClientDisconnectReason.YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_SEND_QUEUE_FULL;
                            case ChannelErrorLevel.CHANNEL_ERROR_BLOCKS_DISABLED: return ServerClientDisconnectReason.YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_BLOCKS_DISABLED;
                            case ChannelErrorLevel.CHANNEL_ERROR_FAILED_TO_SERIALIZE: return ServerClientDisconnectReason.YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_FAILED_TO_SERIALIZE;
                            case ChannelErrorLevel.CHANNEL_ERROR_OUT_OF_MEMORY: return ServerClientDisconnectReason.YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_OUT_OF_MEMORY;
                            case ChannelErrorLevel.CHANNEL_ERROR_MESSAGE_TOO_LARGE: return ServerClientDisconnectReason.YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_MESSAGE_TOO_LARGE;
                            case ChannelErrorLevel.CHANNEL_ERROR_NONE: break;
                        }
                    }
                    break;
                case ConnectionErrorLevel.CONNECTION_ERROR_NONE:
                    break;
            }
            // A connection in an error state always matches one of the cases above; keep a sane value if that ever changes.
            return ServerClientDisconnectReason.YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_DISCONNECTED;
        }

        public virtual void AdvanceTime(double time)
        {
            m_time = time;
            if (IsRunning)
            {
                for (var i = 0; i < m_maxClients; ++i)
                {
                    m_clientConnection[i].AdvanceTime(time);
                    var connectionErrorLevel = m_clientConnection[i].ErrorLevel;
                    if (connectionErrorLevel != ConnectionErrorLevel.CONNECTION_ERROR_NONE)
                    {
                        yojimbo.printf(yojimbo.LOG_LEVEL_ERROR, $"client {i} connection is in error state. disconnecting client\n");
                        SetClientDisconnectReason(i, ClientDisconnectReasonForConnectionError(m_clientConnection[i], connectionErrorLevel, m_config.numChannels));
                        DisconnectClient(i);
                        continue;
                    }
                    reliable.endpoint_update(m_clientEndpoint[i], m_time);
                    var acks = reliable.endpoint_get_acks(m_clientEndpoint[i], out var numAcks);
                    m_clientConnection[i].ProcessAcks(acks, numAcks);
                    reliable.endpoint_clear_acks(m_clientEndpoint[i]);
                }
                var networkSimulator = NetworkSimulator;
                if (networkSimulator != null)
                    networkSimulator.AdvanceTime(time);
            }
        }

        public virtual bool IsRunning => m_running;

        public virtual int MaxClients => m_maxClients;

        public virtual double Time => m_time;

        /// Set the network simulator latency. IMPORTANT: the simulator is created by Start, so call this after Start (e79ad2a).
        public void SetLatency(float milliseconds)
        {
            yojimbo.assert(m_networkSimulator != null);
            if (m_networkSimulator != null)
                m_networkSimulator.SetLatency(milliseconds);
        }

        /// Set the network simulator jitter. IMPORTANT: call after Start.
        public void SetJitter(float milliseconds)
        {
            yojimbo.assert(m_networkSimulator != null);
            if (m_networkSimulator != null)
                m_networkSimulator.SetJitter(milliseconds);
        }

        /// Set the network simulator packet loss. IMPORTANT: call after Start.
        public void SetPacketLoss(float percent)
        {
            yojimbo.assert(m_networkSimulator != null);
            if (m_networkSimulator != null)
                m_networkSimulator.SetPacketLoss(percent);
        }

        /// Set the network simulator duplicate packet percentage. IMPORTANT: call after Start.
        public void SetDuplicates(float percent)
        {
            yojimbo.assert(m_networkSimulator != null);
            if (m_networkSimulator != null)
                m_networkSimulator.SetDuplicates(percent);
        }

        public virtual Message CreateMessage(int clientIndex, int type)
        {
            yojimbo.assert(clientIndex >= 0);
            yojimbo.assert(clientIndex < m_maxClients);
            yojimbo.assert(m_clientMessageFactory[clientIndex] != null);
            return m_clientMessageFactory[clientIndex].CreateMessage(type);
        }

        public virtual byte[] AllocateBlock(int clientIndex, int bytes)
        {
            yojimbo.assert(clientIndex >= 0);
            yojimbo.assert(clientIndex < m_maxClients);
            yojimbo.assert(m_clientAllocator[clientIndex] != null);
            return yojimbo.YOJIMBO_ALLOCATE(m_clientAllocator[clientIndex], bytes);
        }

        public virtual void AttachBlockToMessage(int clientIndex, Message message, byte[] block, int bytes)
        {
            yojimbo.assert(clientIndex >= 0);
            yojimbo.assert(clientIndex < m_maxClients);
            yojimbo.assert(message != null);
            yojimbo.assert(block != null);
            yojimbo.assert(bytes > 0);
            yojimbo.assert(message.IsBlockMessage);
            var blockMessage = (BlockMessage)message;
            blockMessage.AttachBlock(m_clientAllocator[clientIndex], block, bytes);
        }

        public virtual void FreeBlock(int clientIndex, ref byte[] block)
        {
            yojimbo.assert(clientIndex >= 0);
            yojimbo.assert(clientIndex < m_maxClients);
            yojimbo.YOJIMBO_FREE(m_clientAllocator[clientIndex], ref block);
        }

        public virtual bool CanSendMessage(int clientIndex, int channelIndex)
        {
            yojimbo.assert(clientIndex >= 0);
            yojimbo.assert(clientIndex < m_maxClients);
            yojimbo.assert(channelIndex >= 0);
            yojimbo.assert(channelIndex < m_config.numChannels);
            yojimbo.assert(m_clientConnection[clientIndex] != null);
            return m_clientConnection[clientIndex].CanSendMessage(channelIndex);
        }

        public bool HasMessagesToSend(int clientIndex, int channelIndex)
        {
            yojimbo.assert(clientIndex >= 0);
            yojimbo.assert(clientIndex < m_maxClients);
            yojimbo.assert(m_clientConnection[clientIndex] != null);
            yojimbo.assert(channelIndex >= 0);
            yojimbo.assert(channelIndex < m_config.numChannels);
            return m_clientConnection[clientIndex].HasMessagesToSend(channelIndex);
        }

        public virtual void SendMessage(int clientIndex, int channelIndex, Message message)
        {
            yojimbo.assert(clientIndex >= 0);
            yojimbo.assert(clientIndex < m_maxClients);
            yojimbo.assert(m_clientConnection[clientIndex] != null);
            yojimbo.assert(channelIndex >= 0);
            yojimbo.assert(channelIndex < m_config.numChannels);
            m_clientConnection[clientIndex].SendMessage(channelIndex, message, Context);
        }

        public virtual Message ReceiveMessage(int clientIndex, int channelIndex)
        {
            yojimbo.assert(clientIndex >= 0);
            yojimbo.assert(clientIndex < m_maxClients);
            yojimbo.assert(m_clientConnection[clientIndex] != null);
            yojimbo.assert(channelIndex >= 0);
            yojimbo.assert(channelIndex < m_config.numChannels);
            return m_clientConnection[clientIndex].ReceiveMessage(channelIndex);
        }

        public virtual void ReleaseMessage<TMessage>(int clientIndex, ref TMessage message) where TMessage : Message
        {
            yojimbo.assert(clientIndex >= 0);
            yojimbo.assert(clientIndex < m_maxClients);
            yojimbo.assert(m_clientConnection[clientIndex] != null);
            m_clientConnection[clientIndex].ReleaseMessage(ref message);
        }

        public virtual void GetNetworkInfo(int clientIndex, out NetworkInfo info)
        {
            yojimbo.assert(IsRunning);
            yojimbo.assert(clientIndex >= 0);
            yojimbo.assert(clientIndex < m_maxClients);
            info = new NetworkInfo();
            if (IsClientConnected(clientIndex))
            {
                var endpoint = m_clientEndpoint[clientIndex];
                yojimbo.assert(endpoint != null);
                var counters = reliable.endpoint_counters(endpoint);
                info.numPacketsSent = counters[reliable.ENDPOINT_COUNTER_NUM_PACKETS_SENT];
                info.numPacketsReceived = counters[reliable.ENDPOINT_COUNTER_NUM_PACKETS_RECEIVED];
                info.numPacketsAcked = counters[reliable.ENDPOINT_COUNTER_NUM_PACKETS_ACKED];
                info.RTT = reliable.endpoint_rtt(endpoint);
                info.minRTT = reliable.endpoint_rtt_min(endpoint);
                info.maxRTT = reliable.endpoint_rtt_max(endpoint);
                info.averageRTT = reliable.endpoint_rtt_avg(endpoint);
                info.averageJitter = reliable.endpoint_jitter_avg_vs_min_rtt(endpoint);
                info.maxJitter = reliable.endpoint_jitter_max_vs_min_rtt(endpoint);
                info.stddevJitter = reliable.endpoint_jitter_stddev_vs_avg_rtt(endpoint);
                info.packetLoss = reliable.endpoint_packet_loss(endpoint);
                reliable.endpoint_bandwidth(endpoint, out info.sentBandwidth, out info.receivedBandwidth, out info.ackedBandwidth);
            }
        }

        /**
            Get the reason the client in this slot was last disconnected.
            Reset to NONE when the server starts and when a new client connects to the slot. Recorded before
            Adapter.OnServerClientDisconnected is called, so you can query it from inside that callback.
         */
        public ServerClientDisconnectReason GetClientDisconnectReason(int clientIndex)
        {
            yojimbo.assert(clientIndex >= 0);
            yojimbo.assert(clientIndex < m_maxClients);
            return m_clientDisconnectReason[clientIndex];
        }

        protected void SetClientDisconnectReason(int clientIndex, ServerClientDisconnectReason disconnectReason)
        {
            yojimbo.assert(clientIndex >= 0);
            yojimbo.assert(clientIndex < m_maxClients);
            m_clientDisconnectReason[clientIndex] = disconnectReason;
        }

        /// Reset the connection for a client slot, so messages queued for the previous occupant are not delivered to the next (06358cf).
        protected virtual void ResetClient(int clientIndex) =>
            m_clientConnection[clientIndex]?.Reset();

        protected byte[] PacketBuffer => m_packetBuffer;

        protected Adapter Adapter { get { yojimbo.assert(m_adapter != null); return m_adapter; } }

        protected Allocator GlobalAllocator { get { yojimbo.assert(m_globalAllocator != null); return m_globalAllocator; } }

        protected MessageFactory GetClientMessageFactory(int clientIndex)
        {
            yojimbo.assert(IsRunning);
            yojimbo.assert(clientIndex >= 0);
            yojimbo.assert(clientIndex < m_maxClients);
            return m_clientMessageFactory[clientIndex];
        }

        protected NetworkSimulator NetworkSimulator => m_networkSimulator;

        protected reliable_endpoint_t GetClientEndpoint(int clientIndex)
        {
            yojimbo.assert(IsRunning);
            yojimbo.assert(clientIndex >= 0);
            yojimbo.assert(clientIndex < m_maxClients);
            return m_clientEndpoint[clientIndex];
        }

        protected Connection GetClientConnection(int clientIndex)
        {
            yojimbo.assert(IsRunning);
            yojimbo.assert(clientIndex >= 0);
            yojimbo.assert(clientIndex < m_maxClients);
            yojimbo.assert(m_clientConnection[clientIndex] != null);
            return m_clientConnection[clientIndex];
        }

        protected abstract void TransmitPacketFunction(int clientIndex, ushort packetSequence, byte[] packetData, int packetBytes);

        protected abstract bool ProcessPacketFunction(int clientIndex, ushort packetSequence, byte[] packetData, int packetBytes);

        protected static void StaticTransmitPacketFunction(object context, ulong index, ushort packetSequence, byte[] packetData, int packetBytes)
        {
            var server = (BaseServer)context;
            server.TransmitPacketFunction((int)index, packetSequence, packetData, packetBytes);
        }

        protected static bool StaticProcessPacketFunction(object context, ulong index, ushort packetSequence, byte[] packetData, int packetBytes)
        {
            var server = (BaseServer)context;
            return server.ProcessPacketFunction((int)index, packetSequence, packetData, packetBytes);
        }

        protected static object StaticAllocateFunction(object context, ulong bytes) => null;

        protected static void StaticFreeFunction(object context, object pointer) { }

        public abstract int NumConnectedClients { get; }
        public abstract void DisconnectClient(int clientIndex);
        public abstract void DisconnectAllClients();
        public abstract void SendPackets();
        public abstract void ReceivePackets();
        public abstract bool IsClientConnected(int clientIndex);
        public abstract ulong GetClientId(int clientIndex);
        public abstract byte[] GetClientUserData(int clientIndex);
        public abstract netcode_address_t GetClientAddress(int clientIndex);
        public abstract void ConnectLoopbackClient(int clientIndex, ulong clientId, byte[] userData);
        public abstract void DisconnectLoopbackClient(int clientIndex);
        public abstract bool IsLoopbackClient(int clientIndex);
        public abstract void ProcessLoopbackPacket(int clientIndex, byte[] packetData, int packetBytes, ulong packetSequence);

        ClientServerConfig m_config;                                    ///< Base client/server config (a private copy).
        Allocator m_allocator;                                          ///< Allocator passed in to constructor.
        Adapter m_adapter;                                              ///< The adapter specifies the allocator to use, and the message factory class.
        object m_context;                                               ///< Optional serialization context.
        int m_maxClients;                                               ///< Maximum number of clients supported.
        bool m_running;                                                 ///< True if server is currently running, eg. after "Start" is called, before "Stop".
        double m_time;                                                  ///< Current server time in seconds.
        object m_globalMemory;                                          ///< The block of memory backing the global allocator (a placeholder in C#, see yojimbo.YOJIMBO_ALLOCATE_MEMORY).
        object[] m_clientMemory = new object[yojimbo.MaxClients];       ///< The block of memory backing the per-client allocators (placeholders in C#).
        Allocator m_globalAllocator;                                    ///< The global allocator. Used for allocations that don't belong to a specific client.
        Allocator[] m_clientAllocator = new Allocator[yojimbo.MaxClients];                      ///< Array of per-client allocator. These are used for allocations related to connected clients.
        MessageFactory[] m_clientMessageFactory = new MessageFactory[yojimbo.MaxClients];       ///< Array of per-client message factories. This silos message allocations per-client slot.
        Connection[] m_clientConnection = new Connection[yojimbo.MaxClients];                   ///< Array of per-client connection classes. This is how messages are exchanged with clients.
        reliable_endpoint_t[] m_clientEndpoint = new reliable_endpoint_t[yojimbo.MaxClients];   ///< Array of per-client reliable.io endpoints.
        ServerClientDisconnectReason[] m_clientDisconnectReason = new ServerClientDisconnectReason[yojimbo.MaxClients]; ///< Why the client in each slot was last disconnected.
        NetworkSimulator m_networkSimulator;                            ///< The network simulator used to simulate packet loss, latency, jitter etc. Optional. 
        byte[] m_packetBuffer;                                          ///< Buffer used when writing packets.
    }
}
