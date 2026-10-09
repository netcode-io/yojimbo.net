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
    internal class ConnectionPacket : IDisposable
    {
        public int numChannelEntries = 0;
        public ChannelPacketData[] channelEntry = null;
        public MessageFactory messageFactory = null;

        public ConnectionPacket()
        {
            messageFactory = null;
            numChannelEntries = 0;
            channelEntry = null;
        }

        /**
            Releases every message reference held by the packet (the C++ destructor).
            IMPORTANT: always dispose a ConnectionPacket once it has been written or read, otherwise message reference counts never return to zero.
         */
        public void Dispose()
        {
            if (messageFactory != null)
            {
                for (var i = 0; i < numChannelEntries; ++i)
                    channelEntry[i].Free(messageFactory);
                yojimbo.YOJIMBO_FREE(messageFactory.Allocator, ref channelEntry);
                numChannelEntries = 0;
                messageFactory = null;
            }
        }

        public bool AllocateChannelData(MessageFactory _messageFactory, int numEntries)
        {
            yojimbo.assert(numEntries > 0);
            yojimbo.assert(numEntries <= yojimbo.MaxChannels);
            messageFactory = _messageFactory;
            var allocator = messageFactory.Allocator;
            channelEntry = yojimbo.YOJIMBO_ALLOCATE<ChannelPacketData>(allocator, numEntries);
            if (channelEntry == null)
            {
                // On the read path numChannelEntries was already set from the wire before this
                // call; reset it so Dispose doesn't iterate a null channelEntry array.
                numChannelEntries = 0;
                return false;
            }
            for (var i = 0; i < numEntries; ++i)
            {
                channelEntry[i] = new ChannelPacketData();
                channelEntry[i].Initialize();
            }
            numChannelEntries = numEntries;
            return true;
        }

        public bool Serialize(BaseStream stream, MessageFactory messageFactory, ConnectionConfig connectionConfig)
        {
            var numChannels = connectionConfig.numChannels;

            if (!stream.serialize_int(ref numChannelEntries, 0, connectionConfig.numChannels))
                return false;

#if YOJIMBO_DEBUG_MESSAGE_BUDGET
            // Write/measure only: validates our own header-size estimate. Keep it off the untrusted read path.
            if (!stream.IsReading)
                yojimbo.assert(stream.BitsProcessed <= yojimbo.ConservativePacketHeaderBits);
#endif

            if (numChannelEntries > 0)
            {
                if (stream.IsReading)
                {
                    if (!AllocateChannelData(messageFactory, numChannelEntries))
                    {
                        yojimbo.printf(yojimbo.LOG_LEVEL_ERROR, "error: failed to allocate channel data (ConnectionPacket)\n");
                        return false;
                    }
                    for (var i = 0; i < numChannelEntries; ++i)
                        yojimbo.assert(channelEntry[i].messageFailedToSerialize == false);
                }

                for (var i = 0; i < numChannelEntries; ++i)
                {
                    yojimbo.assert(channelEntry[i].messageFailedToSerialize == false);
                    if (!channelEntry[i].Serialize(stream, messageFactory, connectionConfig.channel, numChannels))
                    {
                        yojimbo.printf(yojimbo.LOG_LEVEL_ERROR, $"error: failed to serialize channel {i}\n");
                        return false;
                    }
                }
            }

            return true;
        }
    }

    /// Connection error level.
    public enum ConnectionErrorLevel
    {
        CONNECTION_ERROR_NONE = 0,                              ///< No error. All is well.
        CONNECTION_ERROR_CHANNEL,                               ///< A channel is in an error state.
        CONNECTION_ERROR_ALLOCATOR,                             ///< The allocator is an error state.
        CONNECTION_ERROR_MESSAGE_FACTORY,                       ///< The message factory is in an error state.
        CONNECTION_ERROR_READ_PACKET_FAILED,                    ///< Failed to read packet. Received an invalid packet?     
    }

    /**
        Sends and receives messages across a set of user defined channels.
     */
    public class Connection : IDisposable
    {
        public Connection(Allocator allocator, MessageFactory messageFactory, ConnectionConfig connectionConfig, double time)
        {
            m_connectionConfig = CopyConnectionConfig(connectionConfig);
            m_allocator = allocator;
            m_messageFactory = messageFactory;
            m_errorLevel = ConnectionErrorLevel.CONNECTION_ERROR_NONE;
            m_channel = new Channel[yojimbo.MaxChannels];
            yojimbo.assert(m_connectionConfig.numChannels >= 1);
            yojimbo.assert(m_connectionConfig.numChannels <= yojimbo.MaxChannels);
            for (var channelIndex = 0; channelIndex < m_connectionConfig.numChannels; ++channelIndex)
            {
                switch (m_connectionConfig.channel[channelIndex].type)
                {
                    case ChannelType.CHANNEL_TYPE_RELIABLE_ORDERED:
                        m_channel[channelIndex] = yojimbo.YOJIMBO_NEW<Channel>(m_allocator, () => new ReliableOrderedChannel(m_allocator, messageFactory, m_connectionConfig.channel[channelIndex], m_connectionConfig.maxPacketSize, channelIndex, time));
                        break;

                    case ChannelType.CHANNEL_TYPE_UNRELIABLE_UNORDERED:
                        m_channel[channelIndex] = yojimbo.YOJIMBO_NEW<Channel>(m_allocator, () => new UnreliableUnorderedChannel(m_allocator, messageFactory, m_connectionConfig.channel[channelIndex], m_connectionConfig.maxPacketSize, channelIndex, time));
                        break;

                    default: yojimbo.assert(false, "unknown channel type"); break;
                }
            }
        }

        public void Dispose()
        {
            yojimbo.assert(m_allocator != null);
            Reset();
            for (var i = 0; i < m_connectionConfig.numChannels; ++i)
                yojimbo.YOJIMBO_DELETE(m_allocator, ref m_channel[i]);
            m_allocator = null;
        }

        public void Reset()
        {
            m_errorLevel = ConnectionErrorLevel.CONNECTION_ERROR_NONE;
            for (var i = 0; i < m_connectionConfig.numChannels; ++i)
                m_channel[i].Reset();
        }

        public bool CanSendMessage(int channelIndex)
        {
            yojimbo.assert(channelIndex >= 0);
            yojimbo.assert(channelIndex < m_connectionConfig.numChannels);
            return m_channel[channelIndex].CanSendMessage();
        }

        public bool HasMessagesToSend(int channelIndex)
        {
            yojimbo.assert(channelIndex >= 0);
            yojimbo.assert(channelIndex < m_connectionConfig.numChannels);
            return m_channel[channelIndex].HasMessagesToSend();
        }

        public void SendMessage(int channelIndex, Message message, object context = null)
        {
            yojimbo.assert(channelIndex >= 0);
            yojimbo.assert(channelIndex < m_connectionConfig.numChannels);
            m_channel[channelIndex].SendMessage(ref message, context);
        }

        public Message ReceiveMessage(int channelIndex)
        {
            yojimbo.assert(channelIndex >= 0);
            yojimbo.assert(channelIndex < m_connectionConfig.numChannels);
            return m_channel[channelIndex].ReceiveMessage();
        }

        public void ReleaseMessage<TMessage>(ref TMessage message) where TMessage : Message
        {
            yojimbo.assert(message != null);
            m_messageFactory.ReleaseMessage(ref message);
        }

        static int WritePacket(
            object context,
            MessageFactory messageFactory,
            ConnectionConfig connectionConfig,
            ConnectionPacket packet,
            byte[] buffer,
            int bufferSize)
        {
            var stream = new WriteStream(messageFactory.Allocator, buffer, bufferSize);

            stream.Context = context;

            if (!packet.Serialize(stream, messageFactory, connectionConfig))
            {
                yojimbo.printf(yojimbo.LOG_LEVEL_ERROR, "error: serialize connection packet failed (write packet)\n");
                return 0;
            }

            stream.Flush();

            return stream.BytesProcessed;
        }

        public bool GeneratePacket(object context, ushort packetSequence, byte[] packetData, int maxPacketBytes, out int packetBytes)
        {
            packetBytes = 0;

            using var packet = new ConnectionPacket();

            // Upstream's BitWriter stores qwords, so it rounds the write size down to a multiple of 8. Do the same so
            // packing decisions (and therefore the bytes on the wire) match upstream exactly; it also satisfies the
            // C# writer's multiple-of-4 requirement. Rounding down keeps packets within maxPacketSize.
            maxPacketBytes &= ~7;

            if (m_connectionConfig.numChannels > 0)
            {
                var numChannelsWithData = 0;
                var channelHasData = new bool[yojimbo.MaxChannels];
                var channelData = new ChannelPacketData[yojimbo.MaxChannels];

                var availableBits = maxPacketBytes * 8 - yojimbo.ConservativePacketHeaderBits;

                for (var channelIndex = 0; channelIndex < m_connectionConfig.numChannels; ++channelIndex)
                {
                    channelData[channelIndex] = new ChannelPacketData();
                    var packetDataBits = m_channel[channelIndex].GetPacketData(context, channelData[channelIndex], packetSequence, availableBits);
                    if (packetDataBits > 0)
                    {
                        availableBits -= yojimbo.ConservativeChannelHeaderBits;
                        availableBits -= packetDataBits;
                        channelHasData[channelIndex] = true;
                        numChannelsWithData++;
                    }
                }

                if (numChannelsWithData > 0)
                {
                    if (!packet.AllocateChannelData(m_messageFactory, numChannelsWithData))
                    {
                        yojimbo.printf(yojimbo.LOG_LEVEL_ERROR, "error: failed to allocate channel data\n");
                        // GetPacketData already acquired message references for each channel with data. Ownership hasn't
                        // transferred to the packet yet, so free those entries here or they leak on this error path.
                        for (var channelIndex = 0; channelIndex < m_connectionConfig.numChannels; ++channelIndex)
                            if (channelHasData[channelIndex])
                                channelData[channelIndex].Free(m_messageFactory);
                        return false;
                    }

                    var index = 0;
                    for (var channelIndex = 0; channelIndex < m_connectionConfig.numChannels; ++channelIndex)
                        if (channelHasData[channelIndex])
                        {
                            // ownership of the channel data (and its message references) moves to the packet
                            packet.channelEntry[index] = channelData[channelIndex];
                            index++;
                        }
                }
            }

            packetBytes = WritePacket(context, m_messageFactory, m_connectionConfig, packet, packetData, maxPacketBytes);

            return true;
        }

        static bool ReadPacket(
            object context,
            MessageFactory messageFactory,
            ConnectionConfig connectionConfig,
            ConnectionPacket packet,
            byte[] buffer,
            int bufferSize)
        {
            yojimbo.assert(buffer != null);
            yojimbo.assert(bufferSize > 0);

            var stream = new ReadStream(messageFactory.Allocator, buffer, bufferSize);

            stream.Context = context;

            if (!packet.Serialize(stream, messageFactory, connectionConfig))
            {
                yojimbo.printf(yojimbo.LOG_LEVEL_ERROR, "error: serialize connection packet failed (read packet)\n");
                return false;
            }

            return true;
        }

        public bool ProcessPacket(object context, ushort packetSequence, byte[] packetData, int packetBytes)
        {
            if (m_errorLevel != ConnectionErrorLevel.CONNECTION_ERROR_NONE)
            {
                yojimbo.printf(yojimbo.LOG_LEVEL_DEBUG, "failed to read packet because connection is in error state\n");
                return false;
            }

            // A packet that is exactly a reliable header reaches us with zero payload bytes.
            // That's never a valid connection packet, so fail it like any other malformed read.
            if (packetData == null || packetBytes <= 0 || packetBytes > packetData.Length)
            {
                yojimbo.printf(yojimbo.LOG_LEVEL_ERROR, "error: failed to read packet (empty payload)\n");
                m_errorLevel = ConnectionErrorLevel.CONNECTION_ERROR_READ_PACKET_FAILED;
                return false;
            }

            // NOTE: upstream copies the payload into packetBytes+8 because its BitReader loads an 8 byte window (1d59976).
            // The C# BitReader bounds checks its dword loads, so the exact payload is read in place.

            using var packet = new ConnectionPacket();

            if (!ReadPacket(context, m_messageFactory, m_connectionConfig, packet, packetData, packetBytes))
            {
                yojimbo.printf(yojimbo.LOG_LEVEL_ERROR, "error: failed to read packet\n");
                m_errorLevel = ConnectionErrorLevel.CONNECTION_ERROR_READ_PACKET_FAILED;
                return false;
            }

            for (var i = 0; i < packet.numChannelEntries; ++i)
            {
                int channelIndex = packet.channelEntry[i].channelIndex;
                // the serializer range checks the channel index, so this is an invariant, not a wire check
                yojimbo.assert(channelIndex >= 0);
                yojimbo.assert(channelIndex < m_connectionConfig.numChannels);
                if (channelIndex >= m_connectionConfig.numChannels)
                {
                    m_errorLevel = ConnectionErrorLevel.CONNECTION_ERROR_READ_PACKET_FAILED;
                    return false;
                }
                m_channel[channelIndex].ProcessPacketData(packet.channelEntry[i], packetSequence);
                if (m_channel[channelIndex].ErrorLevel != ChannelErrorLevel.CHANNEL_ERROR_NONE)
                {
                    yojimbo.printf(yojimbo.LOG_LEVEL_DEBUG, $"failed to read packet because channel {channelIndex} is in error state\n");
                    return false;
                }
            }

            return true;
        }

        /**
            Get the error level of a channel on this connection.
            Use this to find out which channel error drove the connection into CONNECTION_ERROR_CHANNEL.
         */
        public ChannelErrorLevel GetChannelErrorLevel(int channelIndex)
        {
            yojimbo.assert(channelIndex >= 0);
            yojimbo.assert(channelIndex < m_connectionConfig.numChannels);
            return m_channel[channelIndex].ErrorLevel;
        }

        public void ProcessAcks(ushort[] acks, int numAcks)
        {
            for (var i = 0; i < numAcks; ++i)
                for (var channelIndex = 0; channelIndex < m_connectionConfig.numChannels; ++channelIndex)
                    m_channel[channelIndex].ProcessAck(acks[i]);
        }

        public void AdvanceTime(double time)
        {
            for (var i = 0; i < m_connectionConfig.numChannels; ++i)
            {
                m_channel[i].AdvanceTime(time);

                if (m_channel[i].ErrorLevel != ChannelErrorLevel.CHANNEL_ERROR_NONE)
                {
                    m_errorLevel = ConnectionErrorLevel.CONNECTION_ERROR_CHANNEL;
                    return;
                }
            }

            if (m_allocator.ErrorLevel != AllocatorErrorLevel.ALLOCATOR_ERROR_NONE)
            {
                m_errorLevel = ConnectionErrorLevel.CONNECTION_ERROR_ALLOCATOR;
                return;
            }

            if (m_messageFactory.ErrorLevel != MessageFactoryErrorLevel.MESSAGE_FACTORY_ERROR_NONE)
            {
                m_errorLevel = ConnectionErrorLevel.CONNECTION_ERROR_MESSAGE_FACTORY;
                return;
            }
        }

        public ConnectionErrorLevel ErrorLevel =>
            m_errorLevel;

        /// The connection keeps its own copy of the config, like the C++ by-value ConnectionConfig member.
        static ConnectionConfig CopyConnectionConfig(ConnectionConfig config) => config.Clone();

        Allocator m_allocator;                                  ///< Allocator passed in to the connection constructor.
        MessageFactory m_messageFactory;                        ///< Message factory for creating and destroying messages.
        ConnectionConfig m_connectionConfig;                    ///< Connection configuration (a private copy).
        Channel[] m_channel;                                    ///< Array of connection channels. Array size corresponds to m_connectionConfig.numChannels
        ConnectionErrorLevel m_errorLevel;                      ///< The connection error level.
    }
}
