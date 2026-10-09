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
        Messages sent across this channel are not guaranteed to arrive, and may be received in a different order than they were sent.
        This channel type is best used for time critical data like snapshots and object state.
     */
    public class UnreliableUnorderedChannel : Channel
    {
        /** 
            Unreliable unordered channel constructor.
            @param allocator The allocator to use.
            @param messageFactory Message factory for creating and destroying messages.
            @param config The configuration for this channel.
            @param maxPacketSize The maximum packet size in bytes (ConnectionConfig::maxPacketSize).
            @param channelIndex The channel index in [0,numChannels-1].
         */
        public UnreliableUnorderedChannel(
                Allocator allocator,
                MessageFactory messageFactory,
                ChannelConfig config,
                int maxPacketSize,
                int channelIndex,
                double time)
        : base(allocator, messageFactory, config, maxPacketSize, channelIndex, time)
        {
            yojimbo.assert(config.type == ChannelType.CHANNEL_TYPE_UNRELIABLE_UNORDERED);
            m_messageSendQueue = yojimbo.YOJIMBO_NEW(m_allocator, () => new QueueEx<Message>(m_allocator, m_config.messageSendQueueSize));
            m_messageReceiveQueue = yojimbo.YOJIMBO_NEW(m_allocator, () => new QueueEx<Message>(m_allocator, m_config.messageReceiveQueueSize));
            m_packetMessages = yojimbo.YOJIMBO_ALLOCATE<Message>(m_allocator, m_config.maxMessagesPerPacket);
            Reset();
        }

        /**
            Unreliable unordered channel destructor.
            Any messages still in the send or receive queues will be released.
         */
        public override void Dispose()
        {
            Reset();
            yojimbo.YOJIMBO_DELETE(m_allocator, ref m_messageSendQueue);
            yojimbo.YOJIMBO_DELETE(m_allocator, ref m_messageReceiveQueue);
            yojimbo.YOJIMBO_FREE(m_allocator, ref m_packetMessages);
        }

        public override void Reset()
        {
            SetErrorLevel(ChannelErrorLevel.CHANNEL_ERROR_NONE);

            for (var i = 0; i < m_messageSendQueue.GetNumEntries(); ++i)
                m_messageFactory.ReleaseMessage(m_messageSendQueue[i]);
            for (var i = 0; i < m_messageReceiveQueue.GetNumEntries(); ++i)
                m_messageFactory.ReleaseMessage(m_messageReceiveQueue[i]);

            m_messageSendQueue.Clear();
            m_messageReceiveQueue.Clear();

            ResetCounters();
        }

        public override bool CanSendMessage()
        {
            yojimbo.assert(m_messageSendQueue != null);
            return !m_messageSendQueue.IsFull;
        }

        public override bool HasMessagesToSend()
        {
            yojimbo.assert(m_messageSendQueue != null);
            return !m_messageSendQueue.IsEmpty;
        }

        public override void SendMessage(ref Message message, object context)
        {
            yojimbo.assert(message != null);
            yojimbo.assert(CanSendMessage());

            if (ErrorLevel != ChannelErrorLevel.CHANNEL_ERROR_NONE)
            {
                m_messageFactory.ReleaseMessage(ref message);
                return;
            }

            if (!CanSendMessage())
            {
                SetErrorLevel(ChannelErrorLevel.CHANNEL_ERROR_SEND_QUEUE_FULL);
                m_messageFactory.ReleaseMessage(ref message);
                return;
            }

            yojimbo.assert(!(message.IsBlockMessage && m_config.disableBlocks));

            if (message.IsBlockMessage && m_config.disableBlocks)
            {
                SetErrorLevel(ChannelErrorLevel.CHANNEL_ERROR_BLOCKS_DISABLED);
                m_messageFactory.ReleaseMessage(ref message);
                return;
            }

            if (message.IsBlockMessage)
            {
                yojimbo.assert(((BlockMessage)message).BlockSize > 0);
                yojimbo.assert(((BlockMessage)message).BlockSize <= m_config.maxBlockSize);
            }

            m_messageSendQueue.Push(message);

            m_counters[(int)ChannelCounters.CHANNEL_COUNTER_MESSAGES_SENT]++;
        }

        public override Message ReceiveMessage()
        {
            if (ErrorLevel != ChannelErrorLevel.CHANNEL_ERROR_NONE)
                return null;

            if (m_messageReceiveQueue.IsEmpty)
                return null;

            m_counters[(int)ChannelCounters.CHANNEL_COUNTER_MESSAGES_RECEIVED]++;

            return m_messageReceiveQueue.Pop();
        }

        public override void AdvanceTime(double time) { }

        public override int GetPacketData(object context, ChannelPacketData packetData, ushort packetSequence, int availableBits)
        {
            if (m_messageSendQueue.IsEmpty)
                return 0;

            if (m_config.packetBudget > 0)
                availableBits = Math.Min(m_config.packetBudget * 8, availableBits);

            var giveUpBits = 4 * 8;

            var messageTypeBits = yojimbo.bits_required(0, (uint)(m_messageFactory.NumTypes - 1));

            var usedBits = yojimbo.ConservativeMessageHeaderBits;
            var numMessages = 0;
            var messages = m_packetMessages;

            while (true)
            {
                if (m_messageSendQueue.IsEmpty)
                    break;

                if (availableBits - usedBits < giveUpBits)
                    break;

                if (numMessages == m_config.maxMessagesPerPacket)
                    break;

                var message = m_messageSendQueue.Pop();

                yojimbo.assert(message != null);

                var measureStream = new MeasureStream(m_messageFactory.Allocator);
                measureStream.Context = context;
                message.SerializeInternal(measureStream);

                if (message.IsBlockMessage)
                {
                    var blockMessage = (BlockMessage)message;
                    yojimbo.SerializeMessageBlock(measureStream, m_messageFactory, blockMessage, m_config.maxBlockSize);
                }
                var messageBits = messageTypeBits + measureStream.BitsProcessed;
                var isOverBudget = m_config.packetBudget > 0 && messageBits > m_config.packetBudget * 8;
                var isOverPacketSize = messageBits > m_maxPacketSize * 8;
                var isTooLarge = isOverBudget || isOverPacketSize;
                yojimbo.assert(!isTooLarge);
                if (isTooLarge)
                {
                    // You tried to send a message that is too large to ever fit into a packet for this channel. Large data should be sent as a block message over a reliable-ordered channel.
                    SetErrorLevel(ChannelErrorLevel.CHANNEL_ERROR_MESSAGE_TOO_LARGE);
                    m_messageFactory.ReleaseMessage(ref message);
                    break;
                }

                if (usedBits + messageBits > availableBits)
                {
                    m_messageFactory.ReleaseMessage(ref message);
                    continue;
                }

                usedBits += messageBits;

                yojimbo.assert(usedBits <= availableBits);

                messages[numMessages++] = message;
            }

            if (numMessages == 0)
                return 0;

            var allocator = m_messageFactory.Allocator;

            packetData.Initialize();
            packetData.channelIndex = (ushort)ChannelIndex;
            packetData.message.numMessages = numMessages;
            packetData.message.messages = yojimbo.YOJIMBO_ALLOCATE<Message>(allocator, numMessages);

            if (packetData.message.messages == null)
            {
                // Out of memory. These messages were already popped off the send queue, so this
                // channel owns the only reference to each: release them here or they leak. Leave the
                // arm empty (numMessages = 0) so packetData stays safe, and send no data this packet.
                for (var i = 0; i < numMessages; ++i)
                    m_messageFactory.ReleaseMessage(ref messages[i]);
                packetData.message.numMessages = 0;
                SetErrorLevel(ChannelErrorLevel.CHANNEL_ERROR_OUT_OF_MEMORY);
                return 0;
            }

            for (var i = 0; i < numMessages; ++i)
            {
                packetData.message.messages[i] = messages[i];
                messages[i] = null;
            }

            return usedBits;
        }

        public override void ProcessPacketData(ChannelPacketData packetData, ushort packetSequence)
        {
            if (m_errorLevel != ChannelErrorLevel.CHANNEL_ERROR_NONE)
                return;

            if (packetData.messageFailedToSerialize)
            {
                SetErrorLevel(ChannelErrorLevel.CHANNEL_ERROR_FAILED_TO_SERIALIZE);
                return;
            }
            // An unreliable-unordered channel never sends a top-level block fragment
            // (its block messages are serialized inline, see SerializeUnorderedMessages),
            // so if blockMessage is set the packet is malformed. Treat it as a serialize failure (50d2ae0).
            if (packetData.blockMessage)
            {
                SetErrorLevel(ChannelErrorLevel.CHANNEL_ERROR_FAILED_TO_SERIALIZE);
                return;
            }

            for (var i = 0; i < packetData.message.numMessages; ++i)
            {
                var message = packetData.message.messages[i];
                yojimbo.assert(message != null);
                message.Id = packetSequence;
                if (!m_messageReceiveQueue.IsFull)
                {
                    m_messageFactory.AcquireMessage(message);
                    m_messageReceiveQueue.Push(message);
                }
            }
        }

        public override void ProcessAck(ushort ack) { }

        protected QueueEx<Message> m_messageSendQueue;                                  ///< Message send queue.
        protected QueueEx<Message> m_messageReceiveQueue;                               ///< Message receive queue.
        protected Message[] m_packetMessages;                                           ///< Scratch array of messages for the packet being generated (maxMessagesPerPacket entries). Allocated once, not per packet.
    }
}
