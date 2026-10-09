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
        Messages sent across this channel are guaranteed to arrive in the order they were sent.
        This channel type is best used for control messages and RPCs.
        Messages sent over this channel are included in connection packets until one of those packets is acked. Messages are acked individually and remain in the send queue until acked.
        Blocks attached to messages sent over this channel are split up into fragments. Each fragment of the block is included in a connection packet until one of those packets are acked. Eventually, all fragments are received on the other side, and block is reassembled and attached to the message.
        Only one message block may be in flight over the network at any time, so blocks stall out message delivery slightly. Therefore, only use blocks for large data that won't fit inside a single connection packet where you actually need the channel to split it up into fragments. If your block fits inside a packet, just serialize it inside your message serialize via serialize_bytes instead.
     */
    public class ReliableOrderedChannel : Channel
    {
        /** 
            Reliable ordered channel constructor.
            @param allocator The allocator to use.
            @param messageFactory Message factory for creating and destroying messages.
            @param config The configuration for this channel.
            @param maxPacketSize The maximum packet size in bytes (ConnectionConfig::maxPacketSize).
            @param channelIndex The channel index in [0,numChannels-1].
         */
        public ReliableOrderedChannel(Allocator allocator, MessageFactory messageFactory, ChannelConfig config, int maxPacketSize, int channelIndex, double time)
            : base(allocator, messageFactory, config, maxPacketSize, channelIndex, time)
        {
            yojimbo.assert(config.type == ChannelType.CHANNEL_TYPE_RELIABLE_ORDERED);

            yojimbo.assert((65536 % config.sentPacketBufferSize) == 0);
            yojimbo.assert((65536 % config.messageSendQueueSize) == 0);
            yojimbo.assert((65536 % config.messageReceiveQueueSize) == 0);

            m_sentPackets = new SequenceBuffer<SentPacketEntry>(m_allocator, m_config.sentPacketBufferSize);
            m_messageSendQueue = new SequenceBuffer<MessageSendQueueEntry>(m_allocator, m_config.messageSendQueueSize);
            m_messageReceiveQueue = new SequenceBuffer<MessageReceiveQueueEntry>(m_allocator, m_config.messageReceiveQueueSize);
            m_sentPacketMessageIds = new ushort[m_config.sentPacketBufferSize][];
            for (var i = 0; i < m_config.sentPacketBufferSize; ++i)
                m_sentPacketMessageIds[i] = new ushort[m_config.maxMessagesPerPacket];
            m_packetMessageIds = new ushort[m_config.maxMessagesPerPacket];

            if (!config.disableBlocks)
            {
                m_sendBlock = new SendBlockData(m_allocator, m_config.MaxFragmentsPerBlock);
                m_receiveBlock = new ReceiveBlockData(m_allocator, m_config.maxBlockSize, m_config.MaxFragmentsPerBlock);
            }
            else
            {
                m_sendBlock = null;
                m_receiveBlock = null;
            }

            Reset();
        }

        /**
            Reliable ordered channel destructor.
            Any messages still in the send or receive queues will be released.
         */
        public override void Dispose()
        {
            Reset();

            m_sendBlock?.Dispose(); m_sendBlock = null;
            m_receiveBlock?.Dispose(); m_receiveBlock = null;
            m_sentPackets?.Dispose(); m_sentPackets = null;
            m_messageSendQueue?.Dispose(); m_messageSendQueue = null;
            m_messageReceiveQueue?.Dispose(); m_messageReceiveQueue = null;

            m_sentPacketMessageIds = null;
            m_packetMessageIds = null;
        }

        public override void Reset()
        {
            SetErrorLevel(ChannelErrorLevel.CHANNEL_ERROR_NONE);

            m_sendMessageId = 0;
            m_receiveMessageId = 0;
            m_oldestUnackedMessageId = 0;

            for (var i = 0; i < m_messageSendQueue.GetSize(); ++i)
            {
                var entry = m_messageSendQueue.GetAtIndex(i);
                if (entry != null && entry.message != null)
                    m_messageFactory.ReleaseMessage(ref entry.message);
            }

            for (var i = 0; i < m_messageReceiveQueue.GetSize(); ++i)
            {
                var entry = m_messageReceiveQueue.GetAtIndex(i);
                if (entry != null && entry.message != null)
                    m_messageFactory.ReleaseMessage(ref entry.message);
            }

            m_sentPackets.Reset();
            m_messageSendQueue.Reset();
            m_messageReceiveQueue.Reset();

            if (m_sendBlock != null)
                m_sendBlock.Reset();

            if (m_receiveBlock != null)
            {
                m_receiveBlock.Reset();
                if (m_receiveBlock.blockMessage != null)
                {
                    m_messageFactory.ReleaseMessage(ref m_receiveBlock.blockMessage);
                    m_receiveBlock.blockMessage = null;
                }
            }

            ResetCounters();
        }

        public override bool CanSendMessage()
        {
            yojimbo.assert(m_messageSendQueue != null);
            return m_messageSendQueue.Available(m_sendMessageId);
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
                // Increase your send queue size!
                SetErrorLevel(ChannelErrorLevel.CHANNEL_ERROR_SEND_QUEUE_FULL);
                m_messageFactory.ReleaseMessage(ref message);
                return;
            }

            yojimbo.assert(!(message.IsBlockMessage && m_config.disableBlocks));

            if (message.IsBlockMessage && m_config.disableBlocks)
            {
                // You tried to send a block message, but block messages are disabled for this channel!
                SetErrorLevel(ChannelErrorLevel.CHANNEL_ERROR_BLOCKS_DISABLED);
                m_messageFactory.ReleaseMessage(ref message);
                return;
            }

            message.Id = m_sendMessageId;

            var measureStream = new MeasureStream(m_messageFactory.Allocator);
            measureStream.Context = context;
            message.SerializeInternal(measureStream);
            var measuredBits = measureStream.BitsProcessed;

            var isOverBudget = m_config.packetBudget > 0 && measuredBits > m_config.packetBudget * 8;
            var isOverPacketSize = measuredBits > m_maxPacketSize * 8;
            var isTooLarge = (isOverBudget || isOverPacketSize) && !message.IsBlockMessage;
            yojimbo.assert(!isTooLarge);
            if (isTooLarge)
            {
                // You tried to send a message that is too large to ever fit into a packet for this channel. Large data should be sent as a block message instead.
                SetErrorLevel(ChannelErrorLevel.CHANNEL_ERROR_MESSAGE_TOO_LARGE);
                m_messageFactory.ReleaseMessage(ref message);
                return;
            }

            var entry = m_messageSendQueue.Insert(m_sendMessageId);
            yojimbo.assert(entry != null);

            entry.block = message.IsBlockMessage;
            entry.message = message;
            entry.measuredBits = 0;
            entry.timeLastSent = -1.0;

            if (message.IsBlockMessage)
            {
                yojimbo.assert(((BlockMessage)message).BlockSize > 0);
                yojimbo.assert(((BlockMessage)message).BlockSize <= m_config.maxBlockSize);
            }

            entry.measuredBits = (uint)measuredBits;

            m_counters[(int)ChannelCounters.CHANNEL_COUNTER_MESSAGES_SENT]++;

            m_sendMessageId++;
        }

        public override Message ReceiveMessage()
        {
            if (ErrorLevel != ChannelErrorLevel.CHANNEL_ERROR_NONE)
                return null;

            var entry = m_messageReceiveQueue.Find(m_receiveMessageId);
            if (entry == null)
                return null;

            var message = entry.message;
            yojimbo.assert(message != null);
            yojimbo.assert(message.Id == m_receiveMessageId);
            m_messageReceiveQueue.Remove(m_receiveMessageId);
            m_counters[(int)ChannelCounters.CHANNEL_COUNTER_MESSAGES_RECEIVED]++;
            m_receiveMessageId++;

            return message;
        }

        public override void AdvanceTime(double time) =>
            m_time = time;

        public override int GetPacketData(object context, ChannelPacketData packetData, ushort packetSequence, int availableBits)
        {
            if (!HasMessagesToSend())
                return 0;

            if (SendingBlockMessage())
            {
                if (m_config.blockFragmentSize * 8 > availableBits)
                    return 0;

                var fragmentData = GetFragmentToSend(out var messageId, out var fragmentId, out var fragmentBytes, out var numFragments, out var messageType);

                if (fragmentData != null)
                {
                    var fragmentBits = GetFragmentPacketData(packetData, messageId, fragmentId, fragmentData, fragmentBytes, numFragments, messageType);
                    AddFragmentPacketEntry(messageId, fragmentId, packetSequence);
                    return fragmentBits;
                }
            }
            else
            {
                var messageIds = m_packetMessageIds;
                var messageBits = GetMessagesToSend(messageIds, out var numMessageIds, availableBits, context);
                if (numMessageIds > 0)
                {
                    if (!GetMessagePacketData(packetData, messageIds, numMessageIds))
                        return 0;
                    AddMessagePacketEntry(messageIds, numMessageIds, packetSequence);
                    return messageBits;
                }
            }

            return 0;
        }

        public override void ProcessPacketData(ChannelPacketData packetData, ushort packetSequence)
        {
            if (m_errorLevel != ChannelErrorLevel.CHANNEL_ERROR_NONE)
                return;

            if (packetData.messageFailedToSerialize)
            {
                // A message failed to serialize read for some reason, eg. mismatched read/write.
                SetErrorLevel(ChannelErrorLevel.CHANNEL_ERROR_FAILED_TO_SERIALIZE);
                return;
            }

            if (packetData.blockMessage)
                ProcessPacketFragment(
                    packetData.block.messageType,
                    packetData.block.messageId,
                    packetData.block.numFragments,
                    packetData.block.fragmentId,
                    packetData.block.fragmentData,
                    packetData.block.fragmentSize,
                    packetData.block.message);
            else
                ProcessPacketMessages(packetData.message.numMessages, packetData.message.messages);
        }

        public override void ProcessAck(ushort ack)
        {
            var sentPacketEntry = m_sentPackets.Find(ack);
            if (sentPacketEntry == null)
                return;

            yojimbo.assert(!sentPacketEntry.acked);
            sentPacketEntry.acked = true;

            for (var i = 0; i < sentPacketEntry.numMessageIds; ++i)
            {
                var messageId = sentPacketEntry.messageIds[i];
                var sendQueueEntry = m_messageSendQueue.Find(messageId);
                if (sendQueueEntry != null)
                {
                    yojimbo.assert(sendQueueEntry.message != null);
                    yojimbo.assert(sendQueueEntry.message.Id == messageId);
                    m_messageFactory.ReleaseMessage(ref sendQueueEntry.message);
                    m_messageSendQueue.Remove(messageId);
                    UpdateOldestUnackedMessageId();
                }
            }

            if (!m_config.disableBlocks && sentPacketEntry.block && m_sendBlock.active && m_sendBlock.blockMessageId == sentPacketEntry.blockMessageId)
            {
                var messageId = sentPacketEntry.blockMessageId;
                var fragmentId = sentPacketEntry.blockFragmentId;

                if (m_sendBlock.ackedFragment.GetBit(fragmentId) == 0)
                {
                    m_sendBlock.ackedFragment.SetBit(fragmentId);
                    m_sendBlock.numAckedFragments++;
                    if (m_sendBlock.numAckedFragments == m_sendBlock.numFragments)
                    {
                        m_sendBlock.active = false;
                        var sendQueueEntry = m_messageSendQueue.Find(messageId);
                        yojimbo.assert(sendQueueEntry != null);
                        m_messageFactory.ReleaseMessage(ref sendQueueEntry.message);
                        m_messageSendQueue.Remove(messageId);
                        UpdateOldestUnackedMessageId();
                    }
                }
            }
        }

        /**
            Are there any unacked messages in the send queue?
            Messages are acked individually and remain in the send queue until acked.
            @returns True if there is at least one unacked message in the send queue.            
         */
        public override bool HasMessagesToSend() =>
            m_oldestUnackedMessageId != m_sendMessageId;

        /**
            Get messages to include in a packet.
            Messages are measured to see how many bits they take, and only messages that fit within the channel packet budget will be included. See ChannelConfig::packetBudget.
            Takes care not to send messages too rapidly by respecting ChannelConfig::messageResendTime for each message, and to only include messages that that the receiver is able to buffer in their receive queue. In other words, won't run ahead of the receiver.
            @param messageIds Array of message ids to be filled [out]. Fills up to ChannelConfig::maxMessagesPerPacket messages, make sure your array is at least this size.
            @param numMessageIds The number of message ids written to the array.
            @param remainingPacketBits Number of bits remaining in the packet. Considers this as a hard limit when determining how many messages can fit into the packet.
            @returns Estimate of the number of bits required to serialize the messages (upper bound).
            @see GetMessagePacketData
         */
        public int GetMessagesToSend(ushort[] messageIds, out int numMessageIds, int availableBits, object context)
        {
            yojimbo.assert(HasMessagesToSend());

            numMessageIds = 0;

            if (m_config.packetBudget > 0)
                availableBits = Math.Min(m_config.packetBudget * 8, availableBits);

            var giveUpBits = 4 * 8;
            var messageTypeBits = yojimbo.bits_required(0, (uint)(m_messageFactory.NumTypes - 1));
            var messageLimit = Math.Min(m_config.messageSendQueueSize, m_config.messageReceiveQueueSize);
            ushort previousMessageId = 0;
            var usedBits = yojimbo.ConservativeMessageHeaderBits;
            var giveUpCounter = 0;

            for (var i = 0; i < messageLimit; ++i)
            {
                if (availableBits - usedBits < giveUpBits)
                    break;

                if (giveUpCounter > m_config.messageSendQueueSize)
                    break;

                var messageId = (ushort)(m_oldestUnackedMessageId + i);
                var entry = m_messageSendQueue.Find(messageId);
                if (entry == null)
                    continue;

                if (entry.block)
                    break;
                // Messages that are too large to fit in a packet are rejected in SendMessage()
                yojimbo.assert((m_config.packetBudget <= 0 || entry.measuredBits <= (uint)(m_config.packetBudget * 8)) && entry.measuredBits <= (uint)(m_maxPacketSize * 8));

                if (entry.timeLastSent + m_config.messageResendTime <= m_time && availableBits >= (int)entry.measuredBits)
                {
                    var messageBits = (int)(entry.measuredBits + messageTypeBits);

                    if (numMessageIds == 0)
                        messageBits += 16;
                    else
                    {
                        var stream = new MeasureStream(m_messageFactory.Allocator);
                        stream.Context = context;
                        stream.serialize_sequence_relative(previousMessageId, ref messageId);
                        messageBits += stream.BitsProcessed;
                    }

                    if (usedBits + messageBits > availableBits)
                    {
                        giveUpCounter++;
                        continue;
                    }

                    usedBits += messageBits;
                    messageIds[numMessageIds++] = messageId;
                    previousMessageId = messageId;
                    entry.timeLastSent = m_time;
                }

                if (numMessageIds == m_config.maxMessagesPerPacket)
                    break;
            }

            return usedBits;
        }

        /**
            Fill channel packet data with messages.
            This is the payload function to fill packet data while sending regular messages (without blocks attached).
            Messages have references added to them when they are added to the packet. They also have a reference while they are stored in a send or receive queue. Messages are cleaned up when they are no longer in a queue, and no longer referenced by any packets.
            @param packetData The packet data to fill [out]
            @param messageIds Array of message ids identifying which messages to add to the packet from the message send queue.
            @param numMessageIds The number of message ids in the array.
            @see GetMessagesToSend
         */
        public bool GetMessagePacketData(ChannelPacketData packetData, ushort[] messageIds, int numMessageIds)
        {
            yojimbo.assert(messageIds != null);

            packetData.Initialize();
            packetData.channelIndex = (ushort)ChannelIndex;
            packetData.message.numMessages = numMessageIds;
            if (numMessageIds == 0)
                return true;

            packetData.message.messages = new Message[numMessageIds];

            for (var i = 0; i < numMessageIds; ++i)
            {
                var entry = m_messageSendQueue.Find(messageIds[i]);
                yojimbo.assert(entry != null);
                yojimbo.assert(entry.message != null);
                yojimbo.assert(entry.message.RefCount > 0);
                packetData.message.messages[i] = entry.message;
                m_messageFactory.AcquireMessage(packetData.message.messages[i]);
            }
            return true;
        }

        /**
            Add a packet entry for the set of messages included in a packet.
            This lets us look up the set of messages that were included in that packet later on when it is acked, so we can ack those messages individually.
            @param messageIds The set of message ids that were included in the packet.
            @param numMessageIds The number of message ids in the array.
            @param sequence The sequence number of the connection packet the messages were included in.
         */
        public void AddMessagePacketEntry(ushort[] messageIds, int numMessageIds, ushort sequence)
        {
            var sentPacket = m_sentPackets.Insert(sequence, true);
            yojimbo.assert(sentPacket != null);
            if (sentPacket != null)
            {
                sentPacket.acked = false;
                sentPacket.block = false;
                sentPacket.timeSent = m_time;
                sentPacket.messageIds = m_sentPacketMessageIds[(sequence % m_config.sentPacketBufferSize)]; //: m_config.maxMessagesPerPacket
                sentPacket.numMessageIds = (ushort)numMessageIds;
                for (var i = 0; i < numMessageIds; ++i)
                    sentPacket.messageIds[i] = messageIds[i];
            }
        }

        /**
            Process messages included in a packet.
            Any messages that have not already been received are added to the message receive queue. Messages that are added to the receive queue have a reference added. See Message::AddRef.
            @param numMessages The number of messages to process.
            @param messages Array of pointers to messages.
         */
        public void ProcessPacketMessages(int numMessages, Message[] messages)
        {
            var minMessageId = m_receiveMessageId;
            var maxMessageId = (ushort)(m_receiveMessageId + m_config.messageReceiveQueueSize - 1);

            for (var i = 0; i < numMessages; ++i)
            {
                var message = messages[i];

                yojimbo.assert(message != null);

                var messageId = message.Id;

                if (yojimbo.sequence_less_than(messageId, minMessageId))
                    continue;

                if (yojimbo.sequence_greater_than(messageId, maxMessageId))
                {
                    // Did you forget to dequeue messages on the receiver?
                    yojimbo.printf(yojimbo.LOG_LEVEL_ERROR, $"sequence overflow: {messageId} vs. [{minMessageId},{maxMessageId}]\n");
                    SetErrorLevel(ChannelErrorLevel.CHANNEL_ERROR_DESYNC);
                    return;
                }
                if (m_messageReceiveQueue.Find(messageId) != null)
                    continue;

                yojimbo.assert(m_messageReceiveQueue.GetAtIndex(m_messageReceiveQueue.GetIndex(messageId)) == null);

                var entry = m_messageReceiveQueue.Insert(messageId);
                if (entry == null)
                {
                    // For some reason we can't insert the message in the receive queue
                    SetErrorLevel(ChannelErrorLevel.CHANNEL_ERROR_DESYNC);
                    return;
                }

                entry.message = message;

                m_messageFactory.AcquireMessage(message);
            }
        }

        /**
            Track the oldest unacked message id in the send queue.
            Because messages are acked individually, the send queue is not a true queue and may have holes. 
            Because of this it is necessary to periodically walk forward from the previous oldest unacked message id, to find the current oldest unacked message id. 
            This lets us know our starting point for considering messages to include in the next packet we send.
            @see GetMessagesToSend
         */
        public void UpdateOldestUnackedMessageId()
        {
            var stopMessageId = m_messageSendQueue.GetSequence();

            while (true)
            {
                if (m_oldestUnackedMessageId == stopMessageId || m_messageSendQueue.Find(m_oldestUnackedMessageId) != null)
                    break;
                ++m_oldestUnackedMessageId;
            }

            yojimbo.assert(!yojimbo.sequence_greater_than(m_oldestUnackedMessageId, stopMessageId));
        }

        /**
            True if we are currently sending a block message.
            Block messages are treated differently to regular messages. 
            Regular messages are small so we try to fit as many into the packet we can. See ReliableChannelData::GetMessagesToSend.
            Blocks attached to block messages are usually larger than the maximum packet size or channel budget, so they are split up fragments. 
            While in the mode of sending a block message, each channel packet data generated has exactly one fragment from the current block in it. Fragments keep getting included in packets until all fragments of that block are acked.
            @returns True if currently sending a block message over the network, false otherwise.
            @see BlockMessage
            @see GetFragmentToSend
         */
        public bool SendingBlockMessage()
        {
            yojimbo.assert(HasMessagesToSend());

            var entry = m_messageSendQueue.Find(m_oldestUnackedMessageId);

            return entry != null ? entry.block : false;
        }

        /**
            Get the next block fragment to send.
            The next block fragment is selected by scanning left to right over the set of fragments in the block, skipping over any fragments that have already been acked or have been sent within ChannelConfig::fragmentResendTime.
            @param messageId The id of the message that the block is attached to [out].
            @param fragmentId The id of the fragment to send [out].
            @param fragmentBytes The size of the fragment in bytes.
            @param numFragments The total number of fragments in this block.
            @param messageType The type of message the block is attached to. See MessageFactory.
            @returns Pointer to the fragment data.
         */
        public byte[] GetFragmentToSend(out ushort messageId, out ushort fragmentId, out int fragmentBytes, out int numFragments, out int messageType)
        {
            messageId = fragmentId = 0;
            fragmentBytes = numFragments = messageType = 0;

            var entry = m_messageSendQueue.Find(m_oldestUnackedMessageId);

            yojimbo.assert(entry != null);
            yojimbo.assert(entry.block);

            var blockMessage = (BlockMessage)entry.message;

            yojimbo.assert(blockMessage != null);

            messageId = blockMessage.Id;

            var blockSize = blockMessage.BlockSize;

            if (!m_sendBlock.active)
            {
                // start sending this block

                m_sendBlock.active = true;
                m_sendBlock.blockSize = blockSize;
                m_sendBlock.blockMessageId = messageId;
                m_sendBlock.numFragments = (int)Math.Ceiling(blockSize / (float)m_config.blockFragmentSize);
                m_sendBlock.numAckedFragments = 0;

                var MaxFragmentsPerBlock = m_config.MaxFragmentsPerBlock;

                yojimbo.assert(m_sendBlock.numFragments > 0);
                yojimbo.assert(m_sendBlock.numFragments <= MaxFragmentsPerBlock);

                m_sendBlock.ackedFragment.Clear();

                for (var i = 0; i < MaxFragmentsPerBlock; ++i)
                    m_sendBlock.fragmentSendTime[i] = -1.0;
            }

            numFragments = m_sendBlock.numFragments;

            // find the next fragment to send (there may not be one)

            fragmentId = 0xFFFF;

            for (var i = 0; i < m_sendBlock.numFragments; ++i)
                if (m_sendBlock.ackedFragment.GetBit(i) == 0 && m_sendBlock.fragmentSendTime[i] + m_config.blockFragmentResendTime < m_time)
                {
                    fragmentId = (ushort)i;
                    break;
                }

            if (fragmentId == 0xFFFF)
                return null;

            // allocate and return a copy of the fragment data

            messageType = blockMessage.Type;

            fragmentBytes = m_config.blockFragmentSize;

            var fragmentRemainder = blockSize % m_config.blockFragmentSize;

            if (fragmentRemainder != 0 && fragmentId == m_sendBlock.numFragments - 1)
                fragmentBytes = fragmentRemainder;

            var fragmentData = new byte[fragmentBytes];

            if (fragmentData != null)
            {
                Buffer.BlockCopy(blockMessage.BlockData, fragmentId * m_config.blockFragmentSize, fragmentData, 0, fragmentBytes);

                m_sendBlock.fragmentSendTime[fragmentId] = m_time;
            }

            return fragmentData;
        }

        /**
            Fill the packet data with block and fragment data.
            This is the payload function that fills the channel packet data while we are sending a block message.
            @param packetData The packet data to fill [out]
            @param messageId The id of the message that the block is attached to.
            @param fragmentId The id of the block fragment being sent.
            @param fragmentData The fragment data.
            @param fragmentSize The size of the fragment data (bytes).
            @param numFragments The number of fragments in the block.
            @param messageType The type of message the block is attached to.
            @returns An estimate of the number of bits required to serialize the block message and fragment data (upper bound).
         */
        public int GetFragmentPacketData(
            ChannelPacketData packetData,
            ushort messageId,
            ushort fragmentId,
            byte[] fragmentData,
            int fragmentSize,
            int numFragments,
            int messageType)
        {
            packetData.Initialize();

            packetData.channelIndex = (ushort)ChannelIndex;

            packetData.blockMessage = true;

            packetData.block.fragmentData = fragmentData;
            packetData.block.messageId = messageId;
            packetData.block.fragmentId = fragmentId;
            packetData.block.fragmentSize = (ushort)fragmentSize;
            packetData.block.numFragments = (ushort)numFragments;
            packetData.block.messageType = messageType;

            var messageTypeBits = yojimbo.bits_required(0, (uint)(m_messageFactory.NumTypes - 1));

            var fragmentBits = yojimbo.ConservativeFragmentHeaderBits + fragmentSize * 8;

            if (fragmentId == 0)
            {
                var entry = m_messageSendQueue.Find(packetData.block.messageId);

                yojimbo.assert(entry != null);
                yojimbo.assert(entry.message != null);

                packetData.block.message = (BlockMessage)entry.message;

                m_messageFactory.AcquireMessage(packetData.block.message);

                fragmentBits += (int)(entry.measuredBits + messageTypeBits);
            }
            else
                packetData.block.message = null;

            return fragmentBits;
        }

        /**
            Adds a packet entry for the fragment.
            This lets us look up the fragment that was in the packet later on when it is acked, so we can ack that block fragment.
            @param messageId The message id that the block was attached to.
            @param fragmentId The fragment id.
            @param sequence The sequence number of the packet the fragment was included in.
         */
        public void AddFragmentPacketEntry(ushort messageId, ushort fragmentId, ushort sequence)
        {
            var sentPacket = m_sentPackets.Insert(sequence, true);
            yojimbo.assert(sentPacket != null);
            if (sentPacket != null)
            {
                sentPacket.numMessageIds = 0;
                sentPacket.messageIds = null;
                sentPacket.timeSent = m_time;
                sentPacket.acked = false;
                sentPacket.block = true;
                sentPacket.blockMessageId = messageId;
                sentPacket.blockFragmentId = fragmentId;
            }
        }

        /**
            Process a packet fragment.
            The fragment is added to the set of received fragments for the block. When all packet fragments are received, that block is reconstructed, attached to the block message and added to the message receive queue.
            @param messageType The type of the message this block fragment is attached to. This is used to make sure this message type actually allows blocks to be attached to it.
            @param messageId The id of the message the block fragment belongs to.
            @param numFragments The number of fragments in the block.
            @param fragmentId The id of the fragment in [0,numFragments-1].
            @param fragmentData The fragment data.
            @param fragmentBytes The size of the fragment data in bytes.
            @param blockMessage Pointer to the block message. Passed this in only with the first fragment (0), pass null for all other fragments.
         */
        public void ProcessPacketFragment(
            int messageType,
            ushort messageId,
            int numFragments,
            ushort fragmentId,
            byte[] fragmentData,
            int fragmentBytes,
            BlockMessage blockMessage)
        {
            yojimbo.assert(!m_config.disableBlocks);

            if (fragmentData != null)
            {
                var expectedMessageId = m_messageReceiveQueue.GetSequence();
                if (messageId != expectedMessageId)
                    return;

                // start receiving a new block

                if (!m_receiveBlock.active)
                {
                    yojimbo.assert(numFragments >= 0);
                    yojimbo.assert(numFragments <= m_config.MaxFragmentsPerBlock);

                    m_receiveBlock.active = true;
                    m_receiveBlock.numFragments = numFragments;
                    m_receiveBlock.numReceivedFragments = 0;
                    m_receiveBlock.messageId = messageId;
                    m_receiveBlock.blockSize = 0;
                    m_receiveBlock.receivedFragment.Clear();
                }

                // validate fragment

                if (fragmentId >= m_receiveBlock.numFragments)
                {
                    // The fragment id is out of range.
                    SetErrorLevel(ChannelErrorLevel.CHANNEL_ERROR_DESYNC);
                    return;
                }

                if (numFragments != m_receiveBlock.numFragments)
                {
                    // The number of fragments is out of range.
                    SetErrorLevel(ChannelErrorLevel.CHANNEL_ERROR_DESYNC);
                    return;
                }

                // Validate the fragment write against the receive buffer BEFORE copying (d3d4f33).
                // blockData is allocated at maxBlockSize bytes, but when maxBlockSize is not a
                // multiple of blockFragmentSize the fragment count rounds up, so the final fragment
                // starts at an offset where a full blockFragmentSize write would run past the buffer.
                // fragmentBytes is attacker-controlled in [1,blockFragmentSize], so reject anything that wouldn't fit.
                if ((long)fragmentId * m_config.blockFragmentSize + fragmentBytes > m_config.maxBlockSize)
                {
                    // The fragment would write past the end of the block buffer.
                    SetErrorLevel(ChannelErrorLevel.CHANNEL_ERROR_DESYNC);
                    return;
                }

                // receive the fragment

                if (m_receiveBlock.receivedFragment.GetBit(fragmentId) == 0)
                {
                    m_receiveBlock.receivedFragment.SetBit(fragmentId);

                    Buffer.BlockCopy(fragmentData, 0, m_receiveBlock.blockData, fragmentId * m_config.blockFragmentSize, fragmentBytes);

                    if (fragmentId == 0)
                        m_receiveBlock.messageType = messageType;

                    if (fragmentId == m_receiveBlock.numFragments - 1)
                    {
                        m_receiveBlock.blockSize = (uint)((m_receiveBlock.numFragments - 1) * m_config.blockFragmentSize + fragmentBytes);

                        if (m_receiveBlock.blockSize > (uint)m_config.maxBlockSize)
                        {
                            // The block size is outside range
                            SetErrorLevel(ChannelErrorLevel.CHANNEL_ERROR_DESYNC);
                            return;
                        }
                    }

                    m_receiveBlock.numReceivedFragments++;

                    if (fragmentId == 0)
                    {
                        // save block message (sent with fragment 0)
                        m_receiveBlock.blockMessage = blockMessage;
                        m_messageFactory.AcquireMessage(m_receiveBlock.blockMessage);
                    }

                    if (m_receiveBlock.numReceivedFragments == m_receiveBlock.numFragments)
                    {
                        // finished receiving block

                        if (m_messageReceiveQueue.GetAtIndex(m_messageReceiveQueue.GetIndex(messageId)) != null)
                        {
                            // Did you forget to dequeue messages on the receiver?
                            SetErrorLevel(ChannelErrorLevel.CHANNEL_ERROR_DESYNC);
                            return;
                        }

                        blockMessage = m_receiveBlock.blockMessage;

                        yojimbo.assert(blockMessage != null);

                        var blockData = new byte[m_receiveBlock.blockSize];

                        if (blockData == null)
                        {
                            // Not enough memory to allocate block data
                            SetErrorLevel(ChannelErrorLevel.CHANNEL_ERROR_OUT_OF_MEMORY);
                            return;
                        }

                        Buffer.BlockCopy(m_receiveBlock.blockData, 0, blockData, 0, (int)m_receiveBlock.blockSize);

                        blockMessage.AttachBlock(m_messageFactory.Allocator, blockData, (int)m_receiveBlock.blockSize);

                        blockMessage.Id = messageId;

                        var entry = m_messageReceiveQueue.Insert(messageId);
                        yojimbo.assert(entry != null);
                        entry.message = blockMessage;
                        m_receiveBlock.active = false;
                        m_receiveBlock.blockMessage = null;
                    }
                }
            }
        }

        /**
            An entry in the send queue of the reliable-ordered channel.
            Messages stay into the send queue until acked. Each message is acked individually, so there can be "holes" in the message send queue.
         */
        protected class MessageSendQueueEntry
        {
            public Message message;                                                     ///< Pointer to the message. When inserted in the send queue the message has one reference. It is released when the message is acked and removed from the send queue.
            public double timeLastSent;                                                 ///< The time the message was last sent. Used to implement ChannelConfig::messageResendTime.
            public uint measuredBits;                                                   ///< The number of bits the message takes up in a bit stream.
            public bool block;                                                          ///< 1 if this is a block message. Block messages are treated differently to regular messages when sent over a reliable-ordered channel.
        }

        /**
            An entry in the receive queue of the reliable-ordered channel.
         */
        protected class MessageReceiveQueueEntry
        {
            public Message message;                                                     ///< The message pointer. Has at a reference count of at least 1 while in the receive queue. Ownership of the message is passed back to the caller when the message is dequeued.
        }

        /**
            Maps packet level acks to messages and fragments for the reliable-ordered channel.
         */
        protected class SentPacketEntry
        {
            public double timeSent;                                                     ///< The time the packet was sent. Used to estimate round trip time.
            public ushort[] messageIds;                                                 ///< Pointer to an array of message ids. Dynamically allocated because the user can configure the maximum number of messages in a packet per-channel with ChannelConfig::maxMessagesPerPacket.
            public ushort numMessageIds;                                                ///< The number of message ids in in the array.
            public bool acked;                                                          ///< 1 if this packet has been acked.
            public bool block;                                                          ///< 1 if this packet contains a fragment of a block message.
            public ushort blockMessageId;                                               ///< The block message id. Valid only if "block" is 1.
            public ushort blockFragmentId;                                              ///< The block fragment id. Valid only if "block" is 1.
        }

        /**
            Internal state for a block being sent across the reliable ordered channel.
            Stores the block data and tracks which fragments have been acked. The block send completes when all fragments have been acked.
            IMPORTANT: Although there can be multiple block messages in the message send and receive queues, only one data block can be in flights over the wire at a time.
         */
        protected class SendBlockData
        {
            public SendBlockData(Allocator allocator, int maxFragmentsPerBlock)
            {
                m_allocator = allocator;
                ackedFragment = new BitArray(allocator, maxFragmentsPerBlock);
                fragmentSendTime = new double[maxFragmentsPerBlock];
                yojimbo.assert(ackedFragment != null);
                yojimbo.assert(fragmentSendTime != null);
                Reset();
            }

            public void Dispose()
            {
                ackedFragment?.Dispose(); ackedFragment = null;
                fragmentSendTime = null;
            }

            public void Reset()
            {
                active = false;
                numFragments = 0;
                numAckedFragments = 0;
                blockMessageId = 0;
                blockSize = 0;
            }

            public bool active;                                                         ///< True if we are currently sending a block.
            public int blockSize;                                                       ///< The size of the block (bytes).
            public int numFragments;                                                    ///< Number of fragments in the block being sent.
            public int numAckedFragments;                                               ///< Number of acked fragments in the block being sent.
            public ushort blockMessageId;                                               ///< The message id the block is attached to.
            public BitArray ackedFragment;                                              ///< Has fragment n been received?
            public double[] fragmentSendTime;                                           ///< Last time fragment was sent.

            Allocator m_allocator;                                                      ///< Allocator used to create the block data.
        }

        /**
            Internal state for a block being received across the reliable ordered channel.
            Stores the fragments received over the network for the block, and completes once all fragments have been received.
            IMPORTANT: Although there can be multiple block messages in the message send and receive queues, only one data block can be in flights over the wire at a time.
         */
        protected class ReceiveBlockData
        {
            public ReceiveBlockData(Allocator allocator, int maxBlockSize, int maxFragmentsPerBlock)
            {
                m_allocator = allocator;
                receivedFragment = new BitArray(allocator, maxFragmentsPerBlock);
                blockData = new byte[maxBlockSize];
                yojimbo.assert(receivedFragment != null && blockData != null);
                blockMessage = null;
                Reset();
            }

            public void Dispose()
            {
                receivedFragment?.Dispose(); receivedFragment = null;
                blockData = null;
            }

            public void Reset()
            {
                active = false;
                numFragments = 0;
                numReceivedFragments = 0;
                messageId = 0;
                messageType = 0;
                blockSize = 0;
            }

            public bool active;                                                         ///< True if we are currently receiving a block.
            public int numFragments;                                                    ///< The number of fragments in this block
            public int numReceivedFragments;                                            ///< The number of fragments received.
            public ushort messageId;                                                    ///< The message id corresponding to the block.
            public int messageType;                                                     ///< Message type of the block being received.
            public uint blockSize;                                                      ///< Block size in bytes.
            public BitArray receivedFragment;                                           ///< Has fragment n been received?
            public byte[] blockData;                                                    ///< Block data for receive.
            public BlockMessage blockMessage;                                           ///< Block message (sent with fragment 0).

            Allocator m_allocator;                                                      ///< Allocator used to free the data on shutdown.
        }

        ushort m_sendMessageId;                                                         ///< Id of the next message to be added to the send queue.
        ushort m_receiveMessageId;                                                      ///< Id of the next message to be added to the receive queue.
        ushort m_oldestUnackedMessageId;                                                ///< Id of the oldest unacked message in the send queue.
        SequenceBuffer<SentPacketEntry> m_sentPackets;                                  ///< Stores information per sent connection packet about messages and block data included in each packet. Used to walk from connection packet level acks to message and data block fragment level acks.
        SequenceBuffer<MessageSendQueueEntry> m_messageSendQueue;                       ///< Message send queue.
        SequenceBuffer<MessageReceiveQueueEntry> m_messageReceiveQueue;                 ///< Message receive queue.
        ushort[] m_packetMessageIds;                                                    ///< Scratch array of message ids for the packet being generated (maxMessagesPerPacket entries). Allocated once, not per packet.
        ushort[][] m_sentPacketMessageIds;                                              ///< Array of n message ids per sent connection packet. Allows the maximum number of messages per-packet to be allocated dynamically.
        SendBlockData m_sendBlock;                                                      ///< Data about the block being currently sent.
        ReceiveBlockData m_receiveBlock;                                                ///< Data about the block being currently received.
    }
}
