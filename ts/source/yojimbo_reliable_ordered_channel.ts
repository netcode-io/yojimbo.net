/*
    Yojimbo Client/Server Network Library.

    Copyright © 2016 - 2026, Más Bandwidth LLC.

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

/*
    TypeScript port of include/yojimbo_reliable_ordered_channel.h + source/yojimbo_reliable_ordered_channel.cpp (yojimbo 1.13.5).

    Port notes:
      - Out parameters (GetMessagesToSend's numMessageIds, GetFragmentToSend's ids and sizes) are fields of small out
        objects owned by the channel.
      - Message ids and sequences are uint16 held in numbers (& 0xFFFF wherever upstream converts to uint16_t).
      - The per-packet message id storage, the packet message id scratch, the block fragment send times and the receive
        block buffer are allocated from the channel's allocator as upstream, viewed as Uint16Array / Float64Array.
      - numFragments for a block is ceil( blockSize / float( blockFragmentSize ) ) in float32, as upstream.
*/

import { MeasureStream, bits_required } from '../serialize/serialize.ts';
import { serialize_sequence_relative_internal } from '../include/yojimbo_serialize.ts';
import { BitArray } from '../include/yojimbo_bit_array.ts';
import { SequenceBuffer } from '../include/yojimbo_sequence_buffer.ts';
import { ConservativeMessageHeaderBits, ConservativeFragmentHeaderBits } from '../include/yojimbo_constants.ts';
import { YOJIMBO_ALLOCATE, YOJIMBO_FREE, YOJIMBO_NEW, YOJIMBO_DELETE, type Allocator } from './yojimbo_allocator.ts';
import { ChannelConfig, CHANNEL_TYPE_RELIABLE_ORDERED } from './yojimbo_config.ts';
import { Message, BlockMessage, MessageFactory } from './yojimbo_message.ts';
import { Channel, ChannelPacketData, yojimbo_allocate_message_array,
         CHANNEL_ERROR_NONE, CHANNEL_ERROR_SEND_QUEUE_FULL, CHANNEL_ERROR_BLOCKS_DISABLED, CHANNEL_ERROR_MESSAGE_TOO_LARGE,
         CHANNEL_ERROR_OUT_OF_MEMORY, CHANNEL_ERROR_DESYNC, CHANNEL_ERROR_FAILED_TO_SERIALIZE,
         CHANNEL_COUNTER_MESSAGES_SENT, CHANNEL_COUNTER_MESSAGES_RECEIVED } from './yojimbo_channel.ts';
import { yojimbo_assert, yojimbo_printf, YOJIMBO_LOG_LEVEL_ERROR } from './yojimbo_platform.ts';
import { yojimbo_min, yojimbo_sequence_greater_than, yojimbo_sequence_less_than } from './yojimbo_utils.ts';

/**
    An entry in the send queue of the reliable-ordered channel.
    Messages stay into the send queue until acked. Each message is acked individually, so there can be "holes" in the message send queue.
 */

class MessageSendQueueEntry
{
    message: Message | null = null;                 ///< The message. When inserted in the send queue the message has one reference. It is released when the message is acked and removed from the send queue.
    timeLastSent = 0;                               ///< The time the message was last sent. Used to implement ChannelConfig::messageResendTime.
    measuredBits = 0;                               ///< The number of bits the message takes up in a bit stream.
    block = false;                                  ///< True if this is a block message. Block messages are treated differently to regular messages when sent over a reliable-ordered channel.
}

/**
    An entry in the receive queue of the reliable-ordered channel.
 */

class MessageReceiveQueueEntry
{
    message: Message | null = null;                 ///< The message. Has a reference count of at least 1 while in the receive queue. Ownership of the message is passed back to the caller when the message is dequeued.
}

/**
    Maps packet level acks to messages and fragments for the reliable-ordered channel.
 */

class SentPacketEntry
{
    timeSent = 0;                                   ///< The time the packet was sent. Used to estimate round trip time.
    messageIdsOffset = 0;                           ///< Offset of this packet's message ids in m_sentPacketMessageIds (upstream: a pointer into it).
    numMessageIds = 0;                              ///< The number of message ids in in the array.
    acked = false;                                  ///< True if this packet has been acked.
    block = false;                                  ///< True if this packet contains a fragment of a block message.
    blockMessageId = 0;                             ///< The block message id. Valid only if "block" is true.
    blockFragmentId = 0;                            ///< The block fragment id. Valid only if "block" is true.
}

/**
    Internal state for a block being sent across the reliable ordered channel.
    Stores the block data and tracks which fragments have been acked. The block send completes when all fragments have been acked.
    IMPORTANT: Although there can be multiple block messages in the message send and receive queues, only one data block can be in flights over the wire at a time.
 */

class SendBlockData
{
    active = false;                                 ///< True if we are currently sending a block.
    blockSize = 0;                                  ///< The size of the block (bytes).
    numFragments = 0;                               ///< Number of fragments in the block being sent.
    numAckedFragments = 0;                          ///< Number of acked fragments in the block being sent.
    blockMessageId = 0;                             ///< The message id the block is attached to.
    ackedFragment: BitArray | null;                 ///< Has fragment n been received?
    fragmentSendTime: Float64Array;                 ///< Last time fragment was sent.

    private m_allocator: Allocator;                 ///< Allocator used to create the block data.
    private m_fragmentSendTimeMemory: Uint8Array | null;

    constructor( allocator: Allocator, maxFragmentsPerBlock: number )
    {
        this.m_allocator = allocator;
        this.ackedFragment = YOJIMBO_NEW( allocator, () => new BitArray( allocator, maxFragmentsPerBlock ) );
        this.m_fragmentSendTimeMemory = YOJIMBO_ALLOCATE( allocator, 8 * maxFragmentsPerBlock );
        yojimbo_assert( this.ackedFragment, "ackedFragment", "SendBlockData::SendBlockData" );
        yojimbo_assert( this.m_fragmentSendTimeMemory, "fragmentSendTime", "SendBlockData::SendBlockData" );
        this.fragmentSendTime = new Float64Array( this.m_fragmentSendTimeMemory.buffer, this.m_fragmentSendTimeMemory.byteOffset, maxFragmentsPerBlock );
        this.Reset();
    }

    Dispose(): void
    {
        this.ackedFragment = YOJIMBO_DELETE( this.m_allocator, this.ackedFragment );
        this.m_fragmentSendTimeMemory = YOJIMBO_FREE( this.m_allocator, this.m_fragmentSendTimeMemory );
    }

    Reset(): void
    {
        this.active = false;
        this.numFragments = 0;
        this.numAckedFragments = 0;
        this.blockMessageId = 0;
        this.blockSize = 0;
    }
}

/**
    Internal state for a block being received across the reliable ordered channel.
    Stores the fragments received over the network for the block, and completes once all fragments have been received.
 */

class ReceiveBlockData
{
    active = false;                                 ///< True if we are currently receiving a block.
    numFragments = 0;                               ///< The number of fragments in this block
    numReceivedFragments = 0;                       ///< The number of fragments received.
    messageId = 0;                                  ///< The message id corresponding to the block.
    messageType = 0;                                ///< Message type of the block being received.
    blockSize = 0;                                  ///< Block size in bytes.
    receivedFragment: BitArray | null;              ///< Has fragment n been received?
    blockData: Uint8Array | null;                   ///< Block data for receive.
    blockMessage: BlockMessage | null;              ///< Block message (sent with fragment 0).

    private m_allocator: Allocator;                 ///< Allocator used to free the data on shutdown.

    constructor( allocator: Allocator, maxBlockSize: number, maxFragmentsPerBlock: number )
    {
        this.m_allocator = allocator;
        this.receivedFragment = YOJIMBO_NEW( allocator, () => new BitArray( allocator, maxFragmentsPerBlock ) );
        this.blockData = YOJIMBO_ALLOCATE( allocator, maxBlockSize );
        yojimbo_assert( this.receivedFragment && this.blockData, "receivedFragment && blockData", "ReceiveBlockData::ReceiveBlockData" );
        this.blockMessage = null;
        this.Reset();
    }

    Dispose(): void
    {
        this.receivedFragment = YOJIMBO_DELETE( this.m_allocator, this.receivedFragment );
        this.blockData = YOJIMBO_FREE( this.m_allocator, this.blockData );
    }

    Reset(): void
    {
        this.active = false;
        this.numFragments = 0;
        this.numReceivedFragments = 0;
        this.messageId = 0;
        this.messageType = 0;
        this.blockSize = 0;
    }
}

/** Out parameters of ReliableOrderedChannel::GetMessagesToSend. */

export class MessagesToSend
{
    numMessageIds = 0;
}

/** Out parameters of ReliableOrderedChannel::GetFragmentToSend. */

export class FragmentToSend
{
    messageId = 0;
    fragmentId = 0;
    fragmentBytes = 0;
    numFragments = 0;
    messageType = 0;
}

/**
    Messages sent across this channel are guaranteed to arrive in the order they were sent.
    This channel type is best used for control messages and RPCs.
    Messages sent over this channel are included in connection packets until one of those packets is acked. Messages are acked individually and remain in the send queue until acked.
    Blocks attached to messages sent over this channel are split up into fragments. Each fragment of the block is included in a connection packet until one of those packets are acked. Eventually, all fragments are received on the other side, and block is reassembled and attached to the message.
    Only one message block may be in flight over the network at any time, so blocks stall out message delivery slightly. Therefore, only use blocks for large data that won't fit inside a single connection packet where you actually need the channel to split it up into fragments. If your block fits inside a packet, just serialize it inside your message serialize via serialize_bytes instead.
 */

export class ReliableOrderedChannel extends Channel
{
    private m_sendMessageId = 0;                                                    ///< Id of the next message to be added to the send queue.
    private m_receiveMessageId = 0;                                                 ///< Id of the next message to be added to the receive queue.
    private m_oldestUnackedMessageId = 0;                                           ///< Id of the oldest unacked message in the send queue.
    private m_sentPackets: SequenceBuffer<SentPacketEntry> | null;                  ///< Stores information per sent connection packet about messages and block data included in each packet. Used to walk from connection packet level acks to message and data block fragment level acks.
    private m_messageSendQueue: SequenceBuffer<MessageSendQueueEntry> | null;       ///< Message send queue.
    private m_messageReceiveQueue: SequenceBuffer<MessageReceiveQueueEntry> | null; ///< Message receive queue.
    private m_sentPacketMessageIdsMemory: Uint8Array | null;                        ///< The block backing m_sentPacketMessageIds.
    private m_sentPacketMessageIds: Uint16Array;                                    ///< Array of n message ids per sent connection packet. Allows the maximum number of messages per-packet to be allocated dynamically.
    private m_packetMessageIdsMemory: Uint8Array | null;                            ///< The block backing m_packetMessageIds.
    private m_packetMessageIds: Uint16Array;                                        ///< Scratch space for the message ids gathered for the packet currently being generated (maxMessagesPerPacket entries).
    private m_sendBlock: SendBlockData | null;                                      ///< Data about the block being currently sent.
    private m_receiveBlock: ReceiveBlockData | null;                                ///< Data about the block being currently received.

    private m_messagesToSend = new MessagesToSend();
    private m_fragmentToSend = new FragmentToSend();

    /**
        Reliable ordered channel constructor.
        @param allocator The allocator to use.
        @param messageFactory Message factory for creating and destroying messages.
        @param config The configuration for this channel.
        @param maxPacketSize The maximum packet size in bytes (from ConnectionConfig::maxPacketSize).
        @param channelIndex The channel index in [0,numChannels-1].
        @param time The current time.
     */

    constructor( allocator: Allocator, messageFactory: MessageFactory, config: ChannelConfig, maxPacketSize: number, channelIndex: number, time: number )
    {
        super( allocator, messageFactory, config, maxPacketSize, channelIndex, time );

        yojimbo_assert( config.type === CHANNEL_TYPE_RELIABLE_ORDERED, "config.type == CHANNEL_TYPE_RELIABLE_ORDERED", "ReliableOrderedChannel::ReliableOrderedChannel" );

        yojimbo_assert( ( 65536 % config.sentPacketBufferSize ) === 0, "( 65536 % config.sentPacketBufferSize ) == 0", "ReliableOrderedChannel::ReliableOrderedChannel" );
        yojimbo_assert( ( 65536 % config.messageSendQueueSize ) === 0, "( 65536 % config.messageSendQueueSize ) == 0", "ReliableOrderedChannel::ReliableOrderedChannel" );
        yojimbo_assert( ( 65536 % config.messageReceiveQueueSize ) === 0, "( 65536 % config.messageReceiveQueueSize ) == 0", "ReliableOrderedChannel::ReliableOrderedChannel" );

        const a = this.m_allocator;
        const c = this.m_config;

        this.m_sentPackets = YOJIMBO_NEW( a, () => new SequenceBuffer<SentPacketEntry>( a, c.sentPacketBufferSize, () => new SentPacketEntry() ) );
        this.m_messageSendQueue = YOJIMBO_NEW( a, () => new SequenceBuffer<MessageSendQueueEntry>( a, c.messageSendQueueSize, () => new MessageSendQueueEntry() ) );
        this.m_messageReceiveQueue = YOJIMBO_NEW( a, () => new SequenceBuffer<MessageReceiveQueueEntry>( a, c.messageReceiveQueueSize, () => new MessageReceiveQueueEntry() ) );
        this.m_sentPacketMessageIdsMemory = YOJIMBO_ALLOCATE( a, 2 * c.maxMessagesPerPacket * c.sentPacketBufferSize );
        this.m_packetMessageIdsMemory = YOJIMBO_ALLOCATE( a, 2 * c.maxMessagesPerPacket );

        yojimbo_assert( this.m_sentPackets && this.m_messageSendQueue && this.m_messageReceiveQueue, "sequence buffers", "ReliableOrderedChannel::ReliableOrderedChannel" );
        yojimbo_assert( this.m_sentPacketMessageIdsMemory && this.m_packetMessageIdsMemory, "message id arrays", "ReliableOrderedChannel::ReliableOrderedChannel" );

        this.m_sentPacketMessageIds = new Uint16Array( this.m_sentPacketMessageIdsMemory.buffer, this.m_sentPacketMessageIdsMemory.byteOffset, c.maxMessagesPerPacket * c.sentPacketBufferSize );
        this.m_packetMessageIds = new Uint16Array( this.m_packetMessageIdsMemory.buffer, this.m_packetMessageIdsMemory.byteOffset, c.maxMessagesPerPacket );

        if ( !config.disableBlocks )
        {
            this.m_sendBlock = YOJIMBO_NEW( a, () => new SendBlockData( a, c.GetMaxFragmentsPerBlock() ) );
            this.m_receiveBlock = YOJIMBO_NEW( a, () => new ReceiveBlockData( a, c.maxBlockSize, c.GetMaxFragmentsPerBlock() ) );
        }
        else
        {
            this.m_sendBlock = null;
            this.m_receiveBlock = null;
        }

        this.Reset();
    }

    /**
        Reliable ordered channel destructor.
        Any messages still in the send or receive queues will be released.
     */

    override Dispose(): void
    {
        this.Reset();

        const a = this.m_allocator;

        this.m_sendBlock = YOJIMBO_DELETE( a, this.m_sendBlock );
        this.m_receiveBlock = YOJIMBO_DELETE( a, this.m_receiveBlock );
        this.m_sentPackets = YOJIMBO_DELETE( a, this.m_sentPackets );
        this.m_messageSendQueue = YOJIMBO_DELETE( a, this.m_messageSendQueue );
        this.m_messageReceiveQueue = YOJIMBO_DELETE( a, this.m_messageReceiveQueue );

        this.m_sentPacketMessageIdsMemory = YOJIMBO_FREE( a, this.m_sentPacketMessageIdsMemory );
        this.m_packetMessageIdsMemory = YOJIMBO_FREE( a, this.m_packetMessageIdsMemory );
    }

    Reset(): void
    {
        this.SetErrorLevel( CHANNEL_ERROR_NONE );

        this.m_sendMessageId = 0;
        this.m_receiveMessageId = 0;
        this.m_oldestUnackedMessageId = 0;

        const sendQueue = this.m_messageSendQueue!;
        const receiveQueue = this.m_messageReceiveQueue!;

        for ( let i = 0; i < sendQueue.GetSize(); ++i )
        {
            const entry = sendQueue.GetAtIndex( i );
            if ( entry && entry.message )
            {
                this.m_messageFactory.ReleaseMessage( entry.message );
                entry.message = null;
            }
        }

        for ( let i = 0; i < receiveQueue.GetSize(); ++i )
        {
            const entry = receiveQueue.GetAtIndex( i );
            if ( entry && entry.message )
            {
                this.m_messageFactory.ReleaseMessage( entry.message );
                entry.message = null;
            }
        }

        this.m_sentPackets!.Reset();
        sendQueue.Reset();
        receiveQueue.Reset();

        if ( this.m_sendBlock )
        {
            this.m_sendBlock.Reset();
        }

        if ( this.m_receiveBlock )
        {
            this.m_receiveBlock.Reset();
            if ( this.m_receiveBlock.blockMessage )
            {
                this.m_messageFactory.ReleaseMessage( this.m_receiveBlock.blockMessage );
                this.m_receiveBlock.blockMessage = null;
            }
        }

        this.ResetCounters();
    }

    CanSendMessage(): boolean
    {
        yojimbo_assert( this.m_messageSendQueue, "m_messageSendQueue", "ReliableOrderedChannel::CanSendMessage" );
        return this.m_messageSendQueue.Available( this.m_sendMessageId );
    }

    SendMessage( message: Message, context: unknown ): void
    {
        yojimbo_assert( message, "message", "ReliableOrderedChannel::SendMessage" );

        yojimbo_assert( this.CanSendMessage(), "CanSendMessage()", "ReliableOrderedChannel::SendMessage" );

        if ( this.GetErrorLevel() !== CHANNEL_ERROR_NONE )
        {
            this.m_messageFactory.ReleaseMessage( message );
            return;
        }

        if ( !this.CanSendMessage() )
        {
            // Increase your send queue size!
            this.SetErrorLevel( CHANNEL_ERROR_SEND_QUEUE_FULL );
            this.m_messageFactory.ReleaseMessage( message );
            return;
        }

        yojimbo_assert( !( message.IsBlockMessage() && this.m_config.disableBlocks ), "!( message->IsBlockMessage() && m_config.disableBlocks )", "ReliableOrderedChannel::SendMessage" );

        if ( message.IsBlockMessage() && this.m_config.disableBlocks )
        {
            // You tried to send a block message, but block messages are disabled for this channel!
            this.SetErrorLevel( CHANNEL_ERROR_BLOCKS_DISABLED );
            this.m_messageFactory.ReleaseMessage( message );
            return;
        }

        message.SetId( this.m_sendMessageId );

        const measureStream = new MeasureStream();
        measureStream.SetContext( context );
        measureStream.SetAllocator( this.m_messageFactory.GetAllocator() );
        message.SerializeInternal( measureStream );

        const measuredBits = measureStream.GetBitsProcessed();

        const isOverBudget = this.m_config.packetBudget > 0 && measuredBits > this.m_config.packetBudget * 8;
        const isOverPacketSize = measuredBits > this.m_maxPacketSize * 8;
        const isTooLarge = ( isOverBudget || isOverPacketSize ) && !message.IsBlockMessage();

        yojimbo_assert( !isTooLarge, "!isTooLarge", "ReliableOrderedChannel::SendMessage" );

        if ( isTooLarge )
        {
            // You tried to send a message that is too large to ever fit into a packet for this channel. Large data should be sent as a block message instead.
            this.SetErrorLevel( CHANNEL_ERROR_MESSAGE_TOO_LARGE );
            this.m_messageFactory.ReleaseMessage( message );
            return;
        }

        const entry = this.m_messageSendQueue!.Insert( this.m_sendMessageId );

        yojimbo_assert( entry, "entry", "ReliableOrderedChannel::SendMessage" );

        entry.block = message.IsBlockMessage();
        entry.message = message;
        entry.measuredBits = 0;
        entry.timeLastSent = -1.0;

        if ( message.IsBlockMessage() )
        {
            yojimbo_assert( ( message as BlockMessage ).GetBlockSize() > 0, "GetBlockSize() > 0", "ReliableOrderedChannel::SendMessage" );
            yojimbo_assert( ( message as BlockMessage ).GetBlockSize() <= this.m_config.maxBlockSize, "GetBlockSize() <= m_config.maxBlockSize", "ReliableOrderedChannel::SendMessage" );
        }

        entry.measuredBits = measuredBits;
        this.m_counters[CHANNEL_COUNTER_MESSAGES_SENT]++;
        this.m_sendMessageId = ( this.m_sendMessageId + 1 ) & 0xFFFF;
    }

    ReceiveMessage(): Message | null
    {
        if ( this.GetErrorLevel() !== CHANNEL_ERROR_NONE )
            return null;

        const receiveQueue = this.m_messageReceiveQueue!;
        const entry = receiveQueue.Find( this.m_receiveMessageId );
        if ( !entry )
            return null;

        const message = entry.message;
        yojimbo_assert( message, "message", "ReliableOrderedChannel::ReceiveMessage" );
        yojimbo_assert( message.GetId() === this.m_receiveMessageId, "message->GetId() == m_receiveMessageId", "ReliableOrderedChannel::ReceiveMessage" );
        entry.message = null;
        receiveQueue.Remove( this.m_receiveMessageId );
        this.m_counters[CHANNEL_COUNTER_MESSAGES_RECEIVED]++;
        this.m_receiveMessageId = ( this.m_receiveMessageId + 1 ) & 0xFFFF;

        return message;
    }

    AdvanceTime( time: number ): void
    {
        this.m_time = time;
    }

    GetPacketData( context: unknown, packetData: ChannelPacketData, packetSequence: number, availableBits: number ): number
    {
        if ( !this.HasMessagesToSend() )
            return 0;

        if ( this.SendingBlockMessage() )
        {
            if ( this.m_config.blockFragmentSize * 8 > availableBits )
                return 0;

            const out = this.m_fragmentToSend;

            const fragmentData = this.GetFragmentToSend( out );

            if ( fragmentData )
            {
                const fragmentBits = this.GetFragmentPacketData( packetData, out.messageId, out.fragmentId, fragmentData, out.fragmentBytes, out.numFragments, out.messageType );
                this.AddFragmentPacketEntry( out.messageId, out.fragmentId, packetSequence );
                return fragmentBits;
            }
        }
        else
        {
            const out = this.m_messagesToSend;
            const messageIds = this.m_packetMessageIds;
            const messageBits = this.GetMessagesToSend( messageIds, out, availableBits, context );

            if ( out.numMessageIds > 0 )
            {
                if ( !this.GetMessagePacketData( packetData, messageIds, out.numMessageIds ) )
                    return 0;
                this.AddMessagePacketEntry( messageIds, out.numMessageIds, packetSequence );
                return messageBits;
            }
        }

        return 0;
    }

    /**
        Are there any unacked messages in the send queue?
        Messages are acked individually and remain in the send queue until acked.
     */

    HasMessagesToSend(): boolean
    {
        return this.m_oldestUnackedMessageId !== this.m_sendMessageId;
    }

    /**
        Get messages to include in a packet.
        Messages are measured to see how many bits they take, and only messages that fit within the channel packet budget will be included. See ChannelConfig::packetBudget.
        Takes care not to send messages too rapidly by respecting ChannelConfig::messageResendTime for each message, and to only include messages that that the receiver is able to buffer in their receive queue. In other words, won't run ahead of the receiver.
        @param messageIds Array of message ids to be filled [out]. Fills up to ChannelConfig::maxMessagesPerPacket messages, make sure your array is at least this size.
        @param out out.numMessageIds is set to the number of message ids written to the array.
        @param availableBits Number of bits remaining in the packet. Considers this as a hard limit when determining how many messages can fit into the packet.
        @param context The serialization context. May be null.
        @returns Number of bits that will be written to the packet.
     */

    GetMessagesToSend( messageIds: Uint16Array, out: MessagesToSend, availableBits: number, context: unknown ): number
    {
        yojimbo_assert( this.HasMessagesToSend(), "HasMessagesToSend()", "ReliableOrderedChannel::GetMessagesToSend" );

        out.numMessageIds = 0;

        if ( this.m_config.packetBudget > 0 )
            availableBits = yojimbo_min( this.m_config.packetBudget * 8, availableBits );

        const giveUpBits = 4 * 8;
        const messageTypeBits = bits_required( 0, this.m_messageFactory.GetNumTypes() - 1 );
        const messageLimit = yojimbo_min( this.m_config.messageSendQueueSize, this.m_config.messageReceiveQueueSize );
        let previousMessageId = 0;
        let usedBits = ConservativeMessageHeaderBits;
        let giveUpCounter = 0;
        const sendQueue = this.m_messageSendQueue!;
        const resendTime = this.m_config.messageResendTime;

        for ( let i = 0; i < messageLimit; ++i )
        {
            if ( availableBits - usedBits < giveUpBits )
                break;

            if ( giveUpCounter > this.m_config.messageSendQueueSize )
                break;

            const messageId = ( this.m_oldestUnackedMessageId + i ) & 0xFFFF;
            const entry = sendQueue.Find( messageId );
            if ( !entry )
                continue;

            if ( entry.block )
                break;

            // Messages that are too large to fit in a packet are rejected in SendMessage()
            yojimbo_assert( ( this.m_config.packetBudget <= 0 || entry.measuredBits <= this.m_config.packetBudget * 8 ) && entry.measuredBits <= this.m_maxPacketSize * 8, "measuredBits fits", "ReliableOrderedChannel::GetMessagesToSend" );

            if ( entry.timeLastSent + resendTime <= this.m_time && availableBits >= entry.measuredBits )
            {
                let messageBits = entry.measuredBits + messageTypeBits;

                if ( out.numMessageIds === 0 )
                {
                    messageBits += 16;
                }
                else
                {
                    const stream = new MeasureStream();
                    stream.SetContext( context );
                    stream.SetAllocator( this.m_messageFactory.GetAllocator() );
                    relative_scratch.id = messageId;
                    serialize_sequence_relative_internal( stream, previousMessageId, relative_scratch, 'id' );
                    messageBits += stream.GetBitsProcessed();
                }

                if ( usedBits + messageBits > availableBits )
                {
                    giveUpCounter++;
                    continue;
                }

                usedBits += messageBits;
                messageIds[out.numMessageIds++] = messageId;
                previousMessageId = messageId;
                entry.timeLastSent = this.m_time;
            }

            if ( out.numMessageIds === this.m_config.maxMessagesPerPacket )
                break;
        }

        return usedBits;
    }

    /**
        Fill channel packet data with messages.
        This is the payload function to fill packet data while sending regular messages (without blocks attached).
        Messages have references added to them when they are added to the packet. They also have a reference while they are stored in a send or receive queue. Messages are cleaned up when they are no longer in a queue, and no longer referenced by any packets.
        @returns False if the message array could not be allocated (the channel goes into CHANNEL_ERROR_OUT_OF_MEMORY).
     */

    GetMessagePacketData( packetData: ChannelPacketData, messageIds: Uint16Array, numMessageIds: number ): boolean
    {
        yojimbo_assert( messageIds, "messageIds", "ReliableOrderedChannel::GetMessagePacketData" );

        packetData.Initialize();
        packetData.channelIndex = this.GetChannelIndex();
        packetData.message.numMessages = numMessageIds;

        if ( numMessageIds === 0 )
            return true;

        packetData.message.messages = yojimbo_allocate_message_array( this.m_messageFactory.GetAllocator(), numMessageIds );

        if ( !packetData.message.messages )
        {
            // Out of memory. Leave the arm empty (numMessages = 0) so packetData stays safe to
            // Free/serialize, and report failure so the caller drops this channel's data. We
            // haven't acquired any message references yet, so there is nothing to release.
            packetData.message.numMessages = 0;
            this.SetErrorLevel( CHANNEL_ERROR_OUT_OF_MEMORY );
            return false;
        }

        const sendQueue = this.m_messageSendQueue!;

        for ( let i = 0; i < numMessageIds; ++i )
        {
            const entry = sendQueue.Find( messageIds[i] );
            yojimbo_assert( entry, "entry", "ReliableOrderedChannel::GetMessagePacketData" );
            yojimbo_assert( entry.message, "entry->message", "ReliableOrderedChannel::GetMessagePacketData" );
            yojimbo_assert( entry.message.GetRefCount() > 0, "entry->message->GetRefCount() > 0", "ReliableOrderedChannel::GetMessagePacketData" );
            packetData.message.messages[i] = entry.message;
            this.m_messageFactory.AcquireMessage( entry.message );
        }

        return true;
    }

    /**
        Add a packet entry for the set of messages included in a packet.
        This lets us look up the set of messages that were included in that packet later on when it is acked, so we can ack those messages individually.
     */

    AddMessagePacketEntry( messageIds: Uint16Array, numMessageIds: number, sequence: number ): void
    {
        const sentPacket = this.m_sentPackets!.Insert( sequence, true );
        yojimbo_assert( sentPacket, "sentPacket", "ReliableOrderedChannel::AddMessagePacketEntry" );
        if ( sentPacket )
        {
            sentPacket.acked = false;
            sentPacket.block = false;
            sentPacket.timeSent = this.m_time;
            sentPacket.messageIdsOffset = ( ( sequence & 0xFFFF ) % this.m_config.sentPacketBufferSize ) * this.m_config.maxMessagesPerPacket;
            sentPacket.numMessageIds = numMessageIds;
            for ( let i = 0; i < numMessageIds; ++i )
            {
                this.m_sentPacketMessageIds[sentPacket.messageIdsOffset + i] = messageIds[i];
            }
        }
    }

    /**
        Process messages included in a packet.
        Any messages that have not already been received are added to the message receive queue. Messages that are added to the receive queue have a reference added.
     */

    ProcessPacketMessages( numMessages: number, messages: ReadonlyArray<Message | null> | null ): void
    {
        const minMessageId = this.m_receiveMessageId;
        const maxMessageId = ( this.m_receiveMessageId + this.m_config.messageReceiveQueueSize - 1 ) & 0xFFFF;
        const receiveQueue = this.m_messageReceiveQueue!;

        for ( let i = 0; i < numMessages; ++i )
        {
            const message = messages![i];

            yojimbo_assert( message, "message", "ReliableOrderedChannel::ProcessPacketMessages" );

            const messageId = message.GetId();

            if ( yojimbo_sequence_less_than( messageId, minMessageId ) )
                continue;

            if ( yojimbo_sequence_greater_than( messageId, maxMessageId ) )
            {
                // Did you forget to dequeue messages on the receiver?
                yojimbo_printf( YOJIMBO_LOG_LEVEL_ERROR, "sequence overflow: %d vs. [%d,%d]\n", messageId, minMessageId, maxMessageId );
                this.SetErrorLevel( CHANNEL_ERROR_DESYNC );
                return;
            }

            if ( receiveQueue.Find( messageId ) )
                continue;

            yojimbo_assert( !receiveQueue.GetAtIndex( receiveQueue.GetIndex( messageId ) ), "!m_messageReceiveQueue->GetAtIndex( ... )", "ReliableOrderedChannel::ProcessPacketMessages" );

            const entry = receiveQueue.Insert( messageId );
            if ( !entry )
            {
                // For some reason we can't insert the message in the receive queue
                this.SetErrorLevel( CHANNEL_ERROR_DESYNC );
                return;
            }

            entry.message = message;

            this.m_messageFactory.AcquireMessage( message );
        }
    }

    ProcessPacketData( packetData: ChannelPacketData, packetSequence: number ): void
    {
        if ( this.m_errorLevel !== CHANNEL_ERROR_NONE )
            return;

        if ( packetData.messageFailedToSerialize )
        {
            // A message failed to serialize read for some reason, eg. mismatched read/write.
            this.SetErrorLevel( CHANNEL_ERROR_FAILED_TO_SERIALIZE );
            return;
        }

        void packetSequence;

        if ( packetData.blockMessage )
        {
            this.ProcessPacketFragment( packetData.block.messageType,
                                        packetData.block.messageId,
                                        packetData.block.numFragments,
                                        packetData.block.fragmentId,
                                        packetData.block.fragmentData,
                                        packetData.block.fragmentSize,
                                        packetData.block.message );
        }
        else
        {
            this.ProcessPacketMessages( packetData.message.numMessages, packetData.message.messages );
        }
    }

    ProcessAck( ack: number ): void
    {
        const sentPacketEntry = this.m_sentPackets!.Find( ack );
        if ( !sentPacketEntry )
            return;

        yojimbo_assert( !sentPacketEntry.acked, "!sentPacketEntry->acked", "ReliableOrderedChannel::ProcessAck" );
        sentPacketEntry.acked = true;

        const sendQueue = this.m_messageSendQueue!;

        for ( let i = 0; i < sentPacketEntry.numMessageIds; ++i )
        {
            const messageId = this.m_sentPacketMessageIds[sentPacketEntry.messageIdsOffset + i];
            const sendQueueEntry = sendQueue.Find( messageId );
            if ( sendQueueEntry )
            {
                yojimbo_assert( sendQueueEntry.message, "sendQueueEntry->message", "ReliableOrderedChannel::ProcessAck" );
                yojimbo_assert( sendQueueEntry.message.GetId() === messageId, "sendQueueEntry->message->GetId() == messageId", "ReliableOrderedChannel::ProcessAck" );
                this.m_messageFactory.ReleaseMessage( sendQueueEntry.message );
                sendQueueEntry.message = null;
                sendQueue.Remove( messageId );
                this.UpdateOldestUnackedMessageId();
            }
        }

        const sendBlock = this.m_sendBlock;

        if ( !this.m_config.disableBlocks && sentPacketEntry.block && sendBlock!.active && sendBlock!.blockMessageId === sentPacketEntry.blockMessageId )
        {
            const messageId = sentPacketEntry.blockMessageId;
            const fragmentId = sentPacketEntry.blockFragmentId;

            if ( !sendBlock!.ackedFragment!.GetBit( fragmentId ) )
            {
                sendBlock!.ackedFragment!.SetBit( fragmentId );
                sendBlock!.numAckedFragments++;
                if ( sendBlock!.numAckedFragments === sendBlock!.numFragments )
                {
                    sendBlock!.active = false;
                    const sendQueueEntry = sendQueue.Find( messageId );
                    yojimbo_assert( sendQueueEntry, "sendQueueEntry", "ReliableOrderedChannel::ProcessAck" );
                    this.m_messageFactory.ReleaseMessage( sendQueueEntry.message );
                    sendQueueEntry.message = null;
                    sendQueue.Remove( messageId );
                    this.UpdateOldestUnackedMessageId();
                }
            }
        }
    }

    /**
        Track the oldest unacked message id in the send queue.
        Because messages are acked individually, the send queue is not a true queue and may have holes.
        Because of this it is necessary to periodically walk forward from the previous oldest unacked message id, to find the current oldest unacked message id.
        This lets us know our starting point for considering messages to include in the next packet we send.
     */

    UpdateOldestUnackedMessageId(): void
    {
        const sendQueue = this.m_messageSendQueue!;
        const stopMessageId = sendQueue.GetSequence();

        while ( true )
        {
            if ( this.m_oldestUnackedMessageId === stopMessageId || sendQueue.Find( this.m_oldestUnackedMessageId ) )
            {
                break;
            }
            this.m_oldestUnackedMessageId = ( this.m_oldestUnackedMessageId + 1 ) & 0xFFFF;
        }

        yojimbo_assert( !yojimbo_sequence_greater_than( this.m_oldestUnackedMessageId, stopMessageId ), "!sequence_greater_than( m_oldestUnackedMessageId, stopMessageId )", "ReliableOrderedChannel::UpdateOldestUnackedMessageId" );
    }

    /**
        True if we are currently sending a block message.
        Block messages are treated differently to regular messages.
        While in the mode of sending a block message, each channel packet data generated has exactly one fragment from the current block in it. Fragments keep getting included in packets until all fragments of that block are acked.
     */

    SendingBlockMessage(): boolean
    {
        yojimbo_assert( this.HasMessagesToSend(), "HasMessagesToSend()", "ReliableOrderedChannel::SendingBlockMessage" );

        const entry = this.m_messageSendQueue!.Find( this.m_oldestUnackedMessageId );

        return entry ? entry.block : false;
    }

    /**
        Get the next block fragment to send.
        The next block fragment is selected by scanning left to right over the set of fragments in the block, skipping over any fragments that have already been acked or have been sent within ChannelConfig::fragmentResendTime.
        @param out Filled with the message id, fragment id, fragment size, number of fragments in the block and the message type [out].
        @returns A copy of the fragment data (allocated from the message factory's allocator; ownership passes to the packet data), or null if no fragment should be sent.
     */

    GetFragmentToSend( out: FragmentToSend ): Uint8Array | null
    {
        const entry = this.m_messageSendQueue!.Find( this.m_oldestUnackedMessageId );

        yojimbo_assert( entry, "entry", "ReliableOrderedChannel::GetFragmentToSend" );
        yojimbo_assert( entry.block, "entry->block", "ReliableOrderedChannel::GetFragmentToSend" );

        const blockMessage = entry.message as BlockMessage;

        yojimbo_assert( blockMessage, "blockMessage", "ReliableOrderedChannel::GetFragmentToSend" );

        const messageId = blockMessage.GetId();
        out.messageId = messageId;

        const blockSize = blockMessage.GetBlockSize();

        const sendBlock = this.m_sendBlock!;

        if ( !sendBlock.active )
        {
            // start sending this block

            sendBlock.active = true;
            sendBlock.blockSize = blockSize;
            sendBlock.blockMessageId = messageId;
            sendBlock.numFragments = Math.ceil( Math.fround( Math.fround( blockSize ) / Math.fround( this.m_config.blockFragmentSize ) ) );
            sendBlock.numAckedFragments = 0;

            const MaxFragmentsPerBlock = this.m_config.GetMaxFragmentsPerBlock();

            yojimbo_assert( sendBlock.numFragments > 0, "m_sendBlock->numFragments > 0", "ReliableOrderedChannel::GetFragmentToSend" );
            yojimbo_assert( sendBlock.numFragments <= MaxFragmentsPerBlock, "m_sendBlock->numFragments <= MaxFragmentsPerBlock", "ReliableOrderedChannel::GetFragmentToSend" );

            sendBlock.ackedFragment!.Clear();

            for ( let i = 0; i < MaxFragmentsPerBlock; ++i )
                sendBlock.fragmentSendTime[i] = -1.0;
        }

        out.numFragments = sendBlock.numFragments;

        // find the next fragment to send (there may not be one)

        let fragmentId = 0xFFFF;

        for ( let i = 0; i < sendBlock.numFragments; ++i )
        {
            if ( !sendBlock.ackedFragment!.GetBit( i ) && sendBlock.fragmentSendTime[i] + this.m_config.blockFragmentResendTime < this.m_time )
            {
                fragmentId = i & 0xFFFF;
                break;
            }
        }

        out.fragmentId = fragmentId;

        if ( fragmentId === 0xFFFF )
            return null;

        // allocate and return a copy of the fragment data

        out.messageType = blockMessage.GetType();

        let fragmentBytes = this.m_config.blockFragmentSize;

        const fragmentRemainder = blockSize % this.m_config.blockFragmentSize;

        if ( fragmentRemainder && fragmentId === sendBlock.numFragments - 1 )
            fragmentBytes = fragmentRemainder;

        out.fragmentBytes = fragmentBytes;

        const fragmentData = YOJIMBO_ALLOCATE( this.m_messageFactory.GetAllocator(), fragmentBytes );

        if ( fragmentData )
        {
            const start = fragmentId * this.m_config.blockFragmentSize;
            fragmentData.set( blockMessage.GetBlockData()!.subarray( start, start + fragmentBytes ) );

            sendBlock.fragmentSendTime[fragmentId] = this.m_time;
        }

        return fragmentData;
    }

    /**
        Fill the packet data with block and fragment data.
        This is the payload function that fills the channel packet data while we are sending a block message.
        @returns An estimate of the number of bits required to serialize the block message and fragment data (upper bound).
     */

    GetFragmentPacketData( packetData: ChannelPacketData,
                           messageId: number,
                           fragmentId: number,
                           fragmentData: Uint8Array,
                           fragmentSize: number,
                           numFragments: number,
                           messageType: number ): number
    {
        packetData.Initialize();

        packetData.channelIndex = this.GetChannelIndex();

        packetData.blockMessage = true;

        packetData.block.fragmentData = fragmentData;
        packetData.block.messageId = messageId;
        packetData.block.fragmentId = fragmentId;
        packetData.block.fragmentSize = fragmentSize;
        packetData.block.numFragments = numFragments;
        packetData.block.messageType = messageType;

        const messageTypeBits = bits_required( 0, this.m_messageFactory.GetNumTypes() - 1 );

        let fragmentBits = ConservativeFragmentHeaderBits + fragmentSize * 8;

        if ( fragmentId === 0 )
        {
            const entry = this.m_messageSendQueue!.Find( packetData.block.messageId );

            yojimbo_assert( entry, "entry", "ReliableOrderedChannel::GetFragmentPacketData" );
            yojimbo_assert( entry.message, "entry->message", "ReliableOrderedChannel::GetFragmentPacketData" );

            packetData.block.message = entry.message as BlockMessage;

            this.m_messageFactory.AcquireMessage( packetData.block.message );

            fragmentBits += entry.measuredBits + messageTypeBits;
        }
        else
        {
            packetData.block.message = null;
        }

        return fragmentBits;
    }

    /**
        Adds a packet entry for the fragment.
        This lets us look up the fragment that was in the packet later on when it is acked, so we can ack that block fragment.
     */

    AddFragmentPacketEntry( messageId: number, fragmentId: number, sequence: number ): void
    {
        const sentPacket = this.m_sentPackets!.Insert( sequence, true );
        yojimbo_assert( sentPacket, "sentPacket", "ReliableOrderedChannel::AddFragmentPacketEntry" );
        if ( sentPacket )
        {
            sentPacket.numMessageIds = 0;
            sentPacket.messageIdsOffset = 0;
            sentPacket.timeSent = this.m_time;
            sentPacket.acked = false;
            sentPacket.block = true;
            sentPacket.blockMessageId = messageId;
            sentPacket.blockFragmentId = fragmentId;
        }
    }

    /**
        Process a packet fragment.
        The fragment is added to the set of received fragments for the block. When all packet fragments are received, that block is reconstructed, attached to the block message and added to the message receive queue.
        @param blockMessage The block message. Passed in only with the first fragment (0), null for all other fragments.
     */

    ProcessPacketFragment( messageType: number,
                           messageId: number,
                           numFragments: number,
                           fragmentId: number,
                           fragmentData: Uint8Array | null,
                           fragmentBytes: number,
                           blockMessage: BlockMessage | null ): void
    {
        yojimbo_assert( !this.m_config.disableBlocks, "!m_config.disableBlocks", "ReliableOrderedChannel::ProcessPacketFragment" );

        if ( fragmentData )
        {
            const receiveQueue = this.m_messageReceiveQueue!;
            const receiveBlock = this.m_receiveBlock!;

            const expectedMessageId = receiveQueue.GetSequence();
            if ( messageId !== expectedMessageId )
                return;

            // start receiving a new block

            if ( !receiveBlock.active )
            {
                yojimbo_assert( numFragments >= 0, "numFragments >= 0", "ReliableOrderedChannel::ProcessPacketFragment" );
                yojimbo_assert( numFragments <= this.m_config.GetMaxFragmentsPerBlock(), "numFragments <= m_config.GetMaxFragmentsPerBlock()", "ReliableOrderedChannel::ProcessPacketFragment" );

                receiveBlock.active = true;
                receiveBlock.numFragments = numFragments;
                receiveBlock.numReceivedFragments = 0;
                receiveBlock.messageId = messageId;
                receiveBlock.blockSize = 0;
                receiveBlock.receivedFragment!.Clear();
            }

            // validate fragment

            if ( fragmentId >= receiveBlock.numFragments )
            {
                // The fragment id is out of range.
                this.SetErrorLevel( CHANNEL_ERROR_DESYNC );
                return;
            }

            if ( numFragments !== receiveBlock.numFragments )
            {
                // The number of fragments is out of range.
                this.SetErrorLevel( CHANNEL_ERROR_DESYNC );
                return;
            }

            // Validate the fragment write against the receive buffer BEFORE copying.
            // blockData is allocated at maxBlockSize bytes, but when maxBlockSize is not a
            // multiple of blockFragmentSize the fragment count rounds up, so the final fragment
            // starts at an offset where a full blockFragmentSize write would run past the buffer.
            // fragmentBytes is attacker-controlled in [1,blockFragmentSize], so a peer can send an
            // over-long final fragment. Reject anything that wouldn't fit.
            if ( fragmentId * this.m_config.blockFragmentSize + fragmentBytes > this.m_config.maxBlockSize )
            {
                // The fragment would write past the end of the block buffer.
                this.SetErrorLevel( CHANNEL_ERROR_DESYNC );
                return;
            }

            // receive the fragment

            if ( !receiveBlock.receivedFragment!.GetBit( fragmentId ) )
            {
                receiveBlock.receivedFragment!.SetBit( fragmentId );

                receiveBlock.blockData!.set( fragmentData.subarray( 0, fragmentBytes ), fragmentId * this.m_config.blockFragmentSize );

                if ( fragmentId === 0 )
                {
                    receiveBlock.messageType = messageType;
                }

                if ( fragmentId === receiveBlock.numFragments - 1 )
                {
                    receiveBlock.blockSize = ( receiveBlock.numFragments - 1 ) * this.m_config.blockFragmentSize + fragmentBytes;

                    if ( receiveBlock.blockSize > this.m_config.maxBlockSize )
                    {
                        // The block size is outside range
                        this.SetErrorLevel( CHANNEL_ERROR_DESYNC );
                        return;
                    }
                }

                receiveBlock.numReceivedFragments++;

                if ( fragmentId === 0 )
                {
                    // save block message (sent with fragment 0)
                    receiveBlock.blockMessage = blockMessage;
                    this.m_messageFactory.AcquireMessage( receiveBlock.blockMessage );
                }

                if ( receiveBlock.numReceivedFragments === receiveBlock.numFragments )
                {
                    // finished receiving block

                    if ( receiveQueue.GetAtIndex( receiveQueue.GetIndex( messageId ) ) )
                    {
                        // Did you forget to dequeue messages on the receiver?
                        this.SetErrorLevel( CHANNEL_ERROR_DESYNC );
                        return;
                    }

                    const completedBlockMessage = receiveBlock.blockMessage;

                    yojimbo_assert( completedBlockMessage, "blockMessage", "ReliableOrderedChannel::ProcessPacketFragment" );

                    const allocator = this.m_messageFactory.GetAllocator();

                    const blockData = YOJIMBO_ALLOCATE( allocator, receiveBlock.blockSize );

                    if ( !blockData )
                    {
                        // Not enough memory to allocate block data
                        this.SetErrorLevel( CHANNEL_ERROR_OUT_OF_MEMORY );
                        return;
                    }

                    blockData.set( receiveBlock.blockData!.subarray( 0, receiveBlock.blockSize ) );

                    completedBlockMessage.AttachBlock( allocator, blockData, receiveBlock.blockSize );

                    completedBlockMessage.SetId( messageId );

                    const entry = receiveQueue.Insert( messageId );
                    yojimbo_assert( entry, "entry", "ReliableOrderedChannel::ProcessPacketFragment" );
                    entry.message = completedBlockMessage;
                    receiveBlock.active = false;
                    receiveBlock.blockMessage = null;
                }
            }
        }
    }
}

/** Scratch slot for measuring the relative message id encoding (single threaded, never re-entered). */
const relative_scratch = { id: 0 };
