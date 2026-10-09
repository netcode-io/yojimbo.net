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
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace networkprotocol
{
    public class ChannelPacketData
    {
        public ushort channelIndex;
        public bool initialized;
        public bool blockMessage;
        public bool messageFailedToSerialize;

        public class MessageData
        {
            public int numMessages;
            public Message[] messages;
        }

        public class BlockData
        {
            public BlockMessage message;
            public byte[] fragmentData;
            public ushort messageId;
            public ushort fragmentId;
            public ushort fragmentSize;
            public ushort numFragments;
            public int messageType;
        }

        // `blockMessage` selects which of these is live for a given packet. Both are always present and fully
        // initialized (upstream de-unioned them in 665577e), so a mistaken access is benign rather than a wild pointer.
        public MessageData message = new MessageData();
        public BlockData block = new BlockData();

        public void Initialize()
        {
            channelIndex = 0;
            blockMessage = false;
            messageFailedToSerialize = false;
            // Fully initialize both arms so Free() and any reader are safe no matter which one the
            // serializer populates (or if it bails out early, e.g. a block fragment on a
            // disableBlocks channel).
            message.numMessages = 0;
            message.messages = null;
            block.message = null;
            block.fragmentData = null;
            block.messageId = 0;
            block.fragmentId = 0;
            block.fragmentSize = 0;
            block.numFragments = 0;
            block.messageType = 0;
            initialized = true;
        }

        public void Free(MessageFactory messageFactory)
        {
            yojimbo.assert(initialized);
            var allocator = messageFactory.Allocator;
            if (!blockMessage)
            {
                if (message.numMessages > 0)
                {
                    for (var i = 0; i < message.numMessages; ++i)
                        if (message.messages[i] != null)
                            messageFactory.ReleaseMessage(ref message.messages[i]);
                    yojimbo.YOJIMBO_FREE(allocator, ref message.messages);
                }
            }
            else
            {
                if (block.message != null)
                    messageFactory.ReleaseMessage(ref block.message);
                yojimbo.YOJIMBO_FREE(allocator, ref block.fragmentData);
            }
            initialized = false;
        }

        static bool SerializeOrderedMessagesInternal(
            BaseStream stream,
            MessageFactory messageFactory,
            ref int numMessages,
            ref Message[] messages,
            Span<int> messageTypes,
            Span<ushort> messageIds)
        {
            var maxMessageType = messageFactory.NumTypes - 1;

            messageTypes.Slice(0, numMessages).Clear();
            messageIds.Slice(0, numMessages).Clear();

            if (stream.IsWriting)
            {
                yojimbo.assert(messages != null);

                for (var i = 0; i < numMessages; ++i)
                {
                    yojimbo.assert(messages[i] != null);
                    messageTypes[i] = messages[i].Type;
                    messageIds[i] = messages[i].Id;
                }
            }
            else
            {
                var allocator = messageFactory.Allocator;

                messages = yojimbo.YOJIMBO_ALLOCATE<Message>(allocator, numMessages);

                if (messages == null)
                {
                    // Out of memory. Leave the arm empty (numMessages = 0) so ChannelPacketData.Free
                    // stays safe, then fail the read; the channel treats this as a serialize failure.
                    numMessages = 0;
                    yojimbo.printf(yojimbo.LOG_LEVEL_ERROR, "error: failed to allocate messages (SerializeOrderedMessages)\n");
                    return false;
                }
            }

            if (!stream.serialize_bits(ref messageIds[0], 16))
                return false;

            for (var i = 1; i < numMessages; ++i)
                if (!stream.serialize_sequence_relative(messageIds[i - 1], ref messageIds[i]))
                    return false;

            for (var i = 0; i < numMessages; ++i)
            {
                if (maxMessageType > 0)
                {
                    if (!stream.serialize_int(ref messageTypes[i], 0, maxMessageType))
                        return false;
                }
                else
                    messageTypes[i] = 0;

                if (stream.IsReading)
                {
                    messages[i] = messageFactory.CreateMessage(messageTypes[i]);

                    if (messages[i] == null)
                    {
                        yojimbo.printf(yojimbo.LOG_LEVEL_ERROR, $"error: failed to create message of type {messageTypes[i]} (SerializeOrderedMessages)\n");
                        return false;
                    }

                    messages[i].Id = messageIds[i];
                }

                yojimbo.assert(messages[i] != null);

                if (!messages[i].SerializeInternal(stream))
                {
                    yojimbo.printf(yojimbo.LOG_LEVEL_ERROR, $"error: failed to serialize message of type {messageTypes[i]} (SerializeOrderedMessages)\n");
                    return false;
                }
            }

            return true;
        }

        static bool SerializeOrderedMessages(
            BaseStream stream,
            MessageFactory messageFactory,
            ref int numMessages,
            ref Message[] messages,
            int maxMessagesPerPacket)
        {
            var hasMessages = stream.IsWriting && numMessages != 0;

            if (!stream.serialize_bool(ref hasMessages))
                return false;

            if (!hasMessages)
                return true;

            if (!stream.serialize_int(ref numMessages, 1, maxMessagesPerPacket))
                return false;

            // One heap block for the message type and id scratch arrays, so stack usage doesn't
            // scale with maxMessagesPerPacket. The serialize body lives in a separate function so
            // all its early returns funnel through the single free below.
            var allocator = messageFactory.Allocator;

            var scratch = yojimbo.YOJIMBO_ALLOCATE(allocator, (sizeof(int) + sizeof(ushort)) * numMessages);

            if (scratch == null)
            {
                if (stream.IsReading)
                {
                    // Leave the arm empty (numMessages = 0) so ChannelPacketData.Free stays safe.
                    // On write the messages remain owned by the packet data, so leave them alone.
                    numMessages = 0;
                }
                yojimbo.printf(yojimbo.LOG_LEVEL_ERROR, "error: failed to allocate serialize scratch (SerializeOrderedMessages)\n");
                return false;
            }

            var messageTypes = MemoryMarshal.Cast<byte, int>(scratch.AsSpan(0, sizeof(int) * numMessages));
            var messageIds = MemoryMarshal.Cast<byte, ushort>(scratch.AsSpan(sizeof(int) * numMessages, sizeof(ushort) * numMessages));

            var result = SerializeOrderedMessagesInternal(stream, messageFactory, ref numMessages, ref messages, messageTypes, messageIds);

            yojimbo.YOJIMBO_FREE(allocator, ref scratch);

            return result;
        }

        static bool SerializeUnorderedMessagesInternal(
            BaseStream stream,
            MessageFactory messageFactory,
            ref int numMessages,
            ref Message[] messages,
            int maxBlockSize,
            int[] messageTypes)
        {
            var maxMessageType = messageFactory.NumTypes - 1;

            Array.Clear(messageTypes, 0, numMessages);

            if (stream.IsWriting)
            {
                yojimbo.assert(messages != null);

                for (var i = 0; i < numMessages; ++i)
                {
                    yojimbo.assert(messages[i] != null);
                    messageTypes[i] = messages[i].Type;
                }
            }
            else
            {
                var allocator = messageFactory.Allocator;

                messages = yojimbo.YOJIMBO_ALLOCATE<Message>(allocator, numMessages);

                if (messages == null)
                {
                    // Out of memory. Leave the arm empty (numMessages = 0) so ChannelPacketData.Free
                    // stays safe, then fail the read; the channel treats this as a serialize failure.
                    numMessages = 0;
                    yojimbo.printf(yojimbo.LOG_LEVEL_ERROR, "error: failed to allocate messages (SerializeUnorderedMessages)\n");
                    return false;
                }
            }

            for (var i = 0; i < numMessages; ++i)
            {
                if (maxMessageType > 0)
                {
                    if (!stream.serialize_int(ref messageTypes[i], 0, maxMessageType))
                        return false;
                }
                else
                    messageTypes[i] = 0;

                if (stream.IsReading)
                {
                    messages[i] = messageFactory.CreateMessage(messageTypes[i]);

                    if (messages[i] == null)
                    {
                        yojimbo.printf(yojimbo.LOG_LEVEL_ERROR, $"error: failed to create message type {messageTypes[i]} (SerializeUnorderedMessages)\n");
                        return false;
                    }
                }

                yojimbo.assert(messages[i] != null);

                if (!messages[i].SerializeInternal(stream))
                {
                    yojimbo.printf(yojimbo.LOG_LEVEL_ERROR, $"error: failed to serialize message type {messageTypes[i]} (SerializeUnorderedMessages)\n");
                    return false;
                }

                if (messages[i].IsBlockMessage)
                {
                    var blockMessage = (BlockMessage)messages[i];
                    if (!yojimbo.SerializeMessageBlock(stream, messageFactory, blockMessage, maxBlockSize))
                    {
                        yojimbo.printf(yojimbo.LOG_LEVEL_ERROR, "error: failed to serialize message block (SerializeUnorderedMessages)\n");
                        return false;
                    }
                }
            }

            return true;
        }

        static bool SerializeUnorderedMessages(
            BaseStream stream,
            MessageFactory messageFactory,
            ref int numMessages,
            ref Message[] messages,
            int maxMessagesPerPacket,
            int maxBlockSize)
        {
            var hasMessages = stream.IsWriting && numMessages != 0;

            if (!stream.serialize_bool(ref hasMessages))
                return false;

            if (!hasMessages)
                return true;

            if (!stream.serialize_int(ref numMessages, 1, maxMessagesPerPacket))
                return false;

            // Heap scratch for the message types, so stack usage doesn't scale with
            // maxMessagesPerPacket. The serialize body lives in a separate function so all its
            // early returns funnel through the single free below.
            var allocator = messageFactory.Allocator;

            var messageTypes = yojimbo.YOJIMBO_ALLOCATE<int>(allocator, numMessages);

            if (messageTypes == null)
            {
                if (stream.IsReading)
                {
                    // Leave the arm empty (numMessages = 0) so ChannelPacketData.Free stays safe.
                    // On write the messages remain owned by the packet data, so leave them alone.
                    numMessages = 0;
                }
                yojimbo.printf(yojimbo.LOG_LEVEL_ERROR, "error: failed to allocate serialize scratch (SerializeUnorderedMessages)\n");
                return false;
            }

            var result = SerializeUnorderedMessagesInternal(stream, messageFactory, ref numMessages, ref messages, maxBlockSize, messageTypes);

            yojimbo.YOJIMBO_FREE(allocator, ref messageTypes);

            return result;
        }

        static bool SerializeBlockFragment(
            BaseStream stream,
            MessageFactory messageFactory,
            ChannelPacketData.BlockData block,
            ChannelConfig channelConfig)
        {
            var maxMessageType = messageFactory.NumTypes - 1;

            if (stream.IsReading)
            {
                block.message = null;
                block.fragmentData = null;
                // messageType is only serialized with fragment 0 (below); default it so a
                // non-zero fragment leaves it defined.
                block.messageType = 0;
            }

            if (!stream.serialize_bits(ref block.messageId, 16))
                return false;

            var maxFragmentsPerBlock = channelConfig.MaxFragmentsPerBlock;

            if (maxFragmentsPerBlock > 1)
            {
                if (!stream.serialize_int(ref block.numFragments, 1, maxFragmentsPerBlock))
                    return false;
            }
            else if (stream.IsReading)
                block.numFragments = 1;

            if (block.numFragments > 1)
            {
                if (!stream.serialize_int(ref block.fragmentId, 0, block.numFragments - 1))
                    return false;
            }
            else if (stream.IsReading)
                block.fragmentId = 0;

            if (!stream.serialize_int(ref block.fragmentSize, 1, channelConfig.blockFragmentSize))
                return false;

            if (stream.IsReading)
            {
                block.fragmentData = yojimbo.YOJIMBO_ALLOCATE(messageFactory.Allocator, block.fragmentSize);

                if (block.fragmentData == null)
                {
                    yojimbo.printf(yojimbo.LOG_LEVEL_ERROR, "error: failed to serialize block fragment (SerializeBlockFragment)\n");
                    return false;
                }
            }

            if (!stream.serialize_bytes(block.fragmentData, block.fragmentSize))
                return false;

            if (block.fragmentId == 0)
            {
                // block message

                if (maxMessageType > 0)
                {
                    if (!stream.serialize_int(ref block.messageType, 0, maxMessageType))
                        return false;
                }
                else
                    block.messageType = 0;

                if (stream.IsReading)
                {
                    var message = messageFactory.CreateMessage(block.messageType);

                    if (message == null)
                    {
                        yojimbo.printf(yojimbo.LOG_LEVEL_ERROR, $"error: failed to create block message type {block.messageType} (SerializeBlockFragment)\n");
                        return false;
                    }

                    if (!message.IsBlockMessage)
                    {
                        yojimbo.printf(yojimbo.LOG_LEVEL_ERROR, "error: received block fragment attached to non-block message (SerializeBlockFragment)\n");
                        messageFactory.ReleaseMessage(ref message);
                        return false;
                    }

                    block.message = (BlockMessage)message;
                }

                yojimbo.assert(block.message != null);

                if (!block.message.SerializeInternal(stream))
                {
                    yojimbo.printf(yojimbo.LOG_LEVEL_ERROR, $"error: failed to serialize block message of type {block.messageType} (SerializeBlockFragment)\n");
                    return false;
                }
            }

            return true;
        }

        public bool Serialize(BaseStream stream, MessageFactory messageFactory, ChannelConfig[] channelConfigs, int numChannels)
        {
            yojimbo.assert(initialized);

#if YOJIMBO_DEBUG_MESSAGE_BUDGET
            var startBits = stream.BitsProcessed;
#endif

            if (numChannels > 1)
            {
                if (!stream.serialize_int(ref channelIndex, 0, numChannels - 1))
                    return false;
            }
            else
                channelIndex = 0;

            var channelConfig = channelConfigs[channelIndex];

            if (!stream.serialize_bool(ref blockMessage))
                return false;

            if (!blockMessage)
            {
                switch (channelConfig.type)
                {
                    case ChannelType.CHANNEL_TYPE_RELIABLE_ORDERED:
                        {
                            if (!SerializeOrderedMessages(stream, messageFactory, ref message.numMessages, ref message.messages, channelConfig.maxMessagesPerPacket))
                            {
                                messageFailedToSerialize = true;
                                return true;
                            }
                        }
                        break;

                    case ChannelType.CHANNEL_TYPE_UNRELIABLE_UNORDERED:
                        {
                            if (!SerializeUnorderedMessages(
                                stream,
                                messageFactory,
                                ref message.numMessages,
                                ref message.messages,
                                channelConfig.maxMessagesPerPacket,
                                channelConfig.maxBlockSize))
                            {
                                messageFailedToSerialize = true;
                                return true;
                            }
                        }
                        break;
                }

#if YOJIMBO_DEBUG_MESSAGE_BUDGET
                // Only assert on write/measure: this validates that *we* stay within the packet
                // budget when producing a packet. On read the data is untrusted, so a peer that ignores
                // the budget must not be able to crash a debug build (1b6bec0).
                if (!stream.IsReading && channelConfig.packetBudget > 0)
                    yojimbo.assert(stream.BitsProcessed - startBits <= channelConfig.packetBudget * 8);
#endif
            }
            else
            {
                if (channelConfig.disableBlocks)
                    return false;

                if (!SerializeBlockFragment(stream, messageFactory, block, channelConfig))
                    return false;
            }

            return true;
        }
    }

    /**
        Channel counters provide insight into the number of times an action was performed by a channel.
        They are intended for use in a telemetry system, eg. reported to some backend logging system to track behavior in a production environment.
     */
    public enum ChannelCounters
    {
        CHANNEL_COUNTER_MESSAGES_SENT,              ///< Number of messages sent over this channel.
        CHANNEL_COUNTER_MESSAGES_RECEIVED,          ///< Number of messages received over this channel.
        CHANNEL_COUNTER_NUM_COUNTERS                ///< The number of channel counters.
    }

    /**
        Channel error level.
        If the channel gets into an error state, it sets an error state on the corresponding connection. See yojimbo::CONNECTION_ERROR_CHANNEL.
        This way if any channel on a client/server connection gets into a bad state, that client is automatically kicked from the server.
        @see Client
        @see Server
        @see Connection
     */
    public enum ChannelErrorLevel
    {
        CHANNEL_ERROR_NONE = 0,                     ///< No error. All is well.
        CHANNEL_ERROR_DESYNC,                       ///< This channel has desynced. This means that the connection protocol has desynced and cannot recover. The client should be disconnected.
        CHANNEL_ERROR_SEND_QUEUE_FULL,              ///< The user tried to send a message but the send queue was full. This will assert out in development, but in production it sets this error on the channel.
        CHANNEL_ERROR_BLOCKS_DISABLED,              ///< The channel received a packet containing data for blocks, but this channel is configured to disable blocks. See ChannelConfig::disableBlocks.
        CHANNEL_ERROR_FAILED_TO_SERIALIZE,          ///< Serialize read failed for a message sent to this channel. Check your message serialize functions, one of them is returning false on serialize read. This can also be caused by a desync in message read and write.
        CHANNEL_ERROR_OUT_OF_MEMORY,                ///< The channel tried to allocate some memory but couldn't.
        CHANNEL_ERROR_MESSAGE_TOO_LARGE,            ///< The user tried to send a message that is too large to ever fit into a packet for this channel. Large data should be sent as a block message instead. This will assert out in development, but in production it sets this error on the channel.
    }

    static partial class yojimbo
    {
        /// Helper function to convert a channel error to a user friendly string.
        public static string GetChannelErrorString(ChannelErrorLevel error)
        {
            switch (error)
            {
                case ChannelErrorLevel.CHANNEL_ERROR_NONE: return "none";
                case ChannelErrorLevel.CHANNEL_ERROR_DESYNC: return "desync";
                case ChannelErrorLevel.CHANNEL_ERROR_SEND_QUEUE_FULL: return "send queue full";
                case ChannelErrorLevel.CHANNEL_ERROR_OUT_OF_MEMORY: return "out of memory";
                case ChannelErrorLevel.CHANNEL_ERROR_BLOCKS_DISABLED: return "blocks disabled";
                case ChannelErrorLevel.CHANNEL_ERROR_FAILED_TO_SERIALIZE: return "failed to serialize";
                case ChannelErrorLevel.CHANNEL_ERROR_MESSAGE_TOO_LARGE: return "message too large";
                default:
                    assert(false);
                    return "(unknown)";
            }
        }
    }

    /// Common functionality shared across all channel types.
    public abstract class Channel : IDisposable
    {
        /**
            Channel constructor.
         */
        public Channel(Allocator allocator, MessageFactory messageFactory, ChannelConfig config, int maxPacketSize, int channelIndex, double time)
        {
            m_config = CopyChannelConfig(config);
            m_maxPacketSize = maxPacketSize;
            yojimbo.assert(channelIndex >= 0);
            yojimbo.assert(channelIndex < yojimbo.MaxChannels);
            m_channelIndex = channelIndex;
            m_allocator = allocator;
            m_messageFactory = messageFactory;
            m_errorLevel = ChannelErrorLevel.CHANNEL_ERROR_NONE;
            m_time = time;
            ResetCounters();
        }

        /**
            Channel destructor.
         */
        public virtual void Dispose() { }

        /**
            Reset the channel. 
         */
        public abstract void Reset();

        /**
            Returns true if a message can be sent over this channel.
         */
        public abstract bool CanSendMessage();

        /**
            Are there any messages in the send queue?
            @returns True if there is at least one message in the send queue.            
         */
        public abstract bool HasMessagesToSend();

        /**
            Queue a message to be sent across this channel.
            @param message The message to be sent.
         */
        public abstract void SendMessage(ref Message message, object context);

        /** 
            Pops the next message off the receive queue if one is available.
            @returns A pointer to the received message, null if there are no messages to receive. The caller owns the message object returned by this function and is responsible for releasing it via Message::Release.
         */
        public abstract Message ReceiveMessage();

        /**
            Advance channel time.
            Called by Connection::AdvanceTime for each channel configured on the connection.
         */
        public abstract void AdvanceTime(double time);

        /**
            Get channel packet data for this channel.
            @param packetData The channel packet data to be filled [out]
            @param packetSequence The sequence number of the packet being generated.
            @param availableBits The maximum number of bits of packet data the channel is allowed to write.
            @returns The number of bits of packet data written by the channel.
            @see ConnectionPacket
            @see Connection::GeneratePacket
         */
        public abstract int GetPacketData(object context, ChannelPacketData packetData, ushort packetSequence, int availableBits);

        /**
            Process packet data included in a connection packet.
            @param packetData The channel packet data to process.
            @param packetSequence The sequence number of the connection packet that contains the channel packet data.
            @see ConnectionPacket
            @see Connection::ProcessPacket
         */
        public abstract void ProcessPacketData(ChannelPacketData packetData, ushort packetSequence);

        /**
            Process a connection packet ack.
            Depending on the channel type: 
                1. Acks messages and block fragments so they stop being included in outgoing connection packets (reliable-ordered channel), 
                2. Does nothing at all (unreliable-unordered).
            @param sequence The sequence number of the connection packet that was acked.
         */
        public abstract void ProcessAck(ushort sequence);

        /**
            Get the channel error level.
            @returns The channel error level.
         */
        public ChannelErrorLevel ErrorLevel =>
            m_errorLevel;

        /** 
            Gets the channel index.
            @returns The channel index in [0,numChannels-1].
         */
        public int ChannelIndex =>
            m_channelIndex;

        /**
            Get a counter value.
            @param index The index of the counter to retrieve. See ChannelCounters.
            @returns The value of the counter.
            @see ResetCounters
         */
        public ulong GetCounter(int index)
        {
            yojimbo.assert(index >= 0);
            yojimbo.assert(index < (int)ChannelCounters.CHANNEL_COUNTER_NUM_COUNTERS);
            return m_counters[index];
        }

        /**
            Resets all counter values to zero.
         */
        public void ResetCounters() =>
            Array.Clear(m_counters, 0, m_counters.Length);

        /**
            Set the channel error level.
            All errors go through this function to make debug logging easier. 
         */
        protected void SetErrorLevel(ChannelErrorLevel errorLevel)
        {
            if (errorLevel != m_errorLevel && errorLevel != ChannelErrorLevel.CHANNEL_ERROR_NONE)
                yojimbo.printf(yojimbo.LOG_LEVEL_ERROR, $"channel went into error state: {yojimbo.GetChannelErrorString(errorLevel)}\n");
            m_errorLevel = errorLevel;
        }

        /// The channel keeps its own copy of the config, like the C++ by-value const ChannelConfig, so later changes to the caller's config cannot affect a live channel.
        internal static ChannelConfig CopyChannelConfig(ChannelConfig config) => config.Clone();

        protected readonly ChannelConfig m_config;                                      ///< Channel configuration data (a private copy).
        protected readonly int m_maxPacketSize;                                         ///< The maximum packet size in bytes (from ConnectionConfig::maxPacketSize). Used to detect messages that are too large to ever fit into a packet.
        protected Allocator m_allocator;                                                ///< Allocator for allocations matching life cycle of this channel.
        protected int m_channelIndex;                                                   ///< The channel index in [0,numChannels-1].
        protected double m_time;                                                        ///< The current time.
        protected ChannelErrorLevel m_errorLevel;                                       ///< The channel error level.
        protected MessageFactory m_messageFactory;                                      ///< Message factory for creating and destroying messages.
        protected ulong[] m_counters = new ulong[(int)ChannelCounters.CHANNEL_COUNTER_NUM_COUNTERS]; ///< Counters for unit testing, stats etc.
    }
}
