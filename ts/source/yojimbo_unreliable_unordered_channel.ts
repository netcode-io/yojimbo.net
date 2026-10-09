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
    TypeScript port of include/yojimbo_unreliable_unordered_channel.h + source/yojimbo_unreliable_unordered_channel.cpp (yojimbo 1.13.5).
*/

import { MeasureStream, bits_required } from '../serialize/serialize.ts';
import { Queue } from '../include/yojimbo_queue.ts';
import { ConservativeMessageHeaderBits } from '../include/yojimbo_constants.ts';
import { YOJIMBO_NEW, YOJIMBO_DELETE, type Allocator } from './yojimbo_allocator.ts';
import { ChannelConfig, CHANNEL_TYPE_UNRELIABLE_UNORDERED } from './yojimbo_config.ts';
import { Message, BlockMessage, MessageFactory, SerializeMessageBlock } from './yojimbo_message.ts';
import { Channel, ChannelPacketData, yojimbo_allocate_message_array,
         CHANNEL_ERROR_NONE, CHANNEL_ERROR_SEND_QUEUE_FULL, CHANNEL_ERROR_BLOCKS_DISABLED, CHANNEL_ERROR_MESSAGE_TOO_LARGE,
         CHANNEL_ERROR_OUT_OF_MEMORY, CHANNEL_ERROR_FAILED_TO_SERIALIZE,
         CHANNEL_COUNTER_MESSAGES_SENT, CHANNEL_COUNTER_MESSAGES_RECEIVED } from './yojimbo_channel.ts';
import { yojimbo_assert } from './yojimbo_platform.ts';
import { yojimbo_min } from './yojimbo_utils.ts';

/**
    Messages sent across this channel are not guaranteed to arrive, and may be received in a different order than they were sent.
    This channel type is best used for time critical data like snapshots and object state.
 */

export class UnreliableUnorderedChannel extends Channel
{
    private m_messageSendQueue: Queue<Message> | null;                  ///< Message send queue.
    private m_messageReceiveQueue: Queue<Message> | null;               ///< Message receive queue.
    private m_packetMessages: Array<Message | null> | null;             ///< Scratch space for the messages gathered for the packet currently being generated (maxMessagesPerPacket entries).

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
        yojimbo_assert( config.type === CHANNEL_TYPE_UNRELIABLE_UNORDERED, "config.type == CHANNEL_TYPE_UNRELIABLE_UNORDERED", "UnreliableUnorderedChannel::UnreliableUnorderedChannel" );
        const a = this.m_allocator;
        this.m_messageSendQueue = YOJIMBO_NEW( a, () => new Queue<Message>( a, this.m_config.messageSendQueueSize ) );
        this.m_messageReceiveQueue = YOJIMBO_NEW( a, () => new Queue<Message>( a, this.m_config.messageReceiveQueueSize ) );
        this.m_packetMessages = yojimbo_allocate_message_array( a, this.m_config.maxMessagesPerPacket );
        yojimbo_assert( this.m_messageSendQueue && this.m_messageReceiveQueue && this.m_packetMessages, "queues", "UnreliableUnorderedChannel::UnreliableUnorderedChannel" );
        this.Reset();
    }

    /**
        Unreliable unordered channel destructor.
        Any messages still in the send or receive queues will be released.
     */

    override Dispose(): void
    {
        this.Reset();
        const a = this.m_allocator;
        this.m_messageSendQueue = YOJIMBO_DELETE( a, this.m_messageSendQueue );
        this.m_messageReceiveQueue = YOJIMBO_DELETE( a, this.m_messageReceiveQueue );
        this.m_packetMessages = YOJIMBO_DELETE( a, this.m_packetMessages );
    }

    Reset(): void
    {
        this.SetErrorLevel( CHANNEL_ERROR_NONE );

        const sendQueue = this.m_messageSendQueue!;
        const receiveQueue = this.m_messageReceiveQueue!;

        for ( let i = 0; i < sendQueue.GetNumEntries(); ++i )
            this.m_messageFactory.ReleaseMessage( sendQueue.Get( i ) );

        for ( let i = 0; i < receiveQueue.GetNumEntries(); ++i )
            this.m_messageFactory.ReleaseMessage( receiveQueue.Get( i ) );

        sendQueue.Clear();
        receiveQueue.Clear();

        this.ResetCounters();
    }

    CanSendMessage(): boolean
    {
        yojimbo_assert( this.m_messageSendQueue, "m_messageSendQueue", "UnreliableUnorderedChannel::CanSendMessage" );
        return !this.m_messageSendQueue.IsFull();
    }

    HasMessagesToSend(): boolean
    {
        yojimbo_assert( this.m_messageSendQueue, "m_messageSendQueue", "UnreliableUnorderedChannel::HasMessagesToSend" );
        return !this.m_messageSendQueue.IsEmpty();
    }

    SendMessage( message: Message, _context: unknown ): void
    {
        yojimbo_assert( message, "message", "UnreliableUnorderedChannel::SendMessage" );
        yojimbo_assert( this.CanSendMessage(), "CanSendMessage()", "UnreliableUnorderedChannel::SendMessage" );

        if ( this.GetErrorLevel() !== CHANNEL_ERROR_NONE )
        {
            this.m_messageFactory.ReleaseMessage( message );
            return;
        }

        if ( !this.CanSendMessage() )
        {
            this.SetErrorLevel( CHANNEL_ERROR_SEND_QUEUE_FULL );
            this.m_messageFactory.ReleaseMessage( message );
            return;
        }

        yojimbo_assert( !( message.IsBlockMessage() && this.m_config.disableBlocks ), "!( message->IsBlockMessage() && m_config.disableBlocks )", "UnreliableUnorderedChannel::SendMessage" );

        if ( message.IsBlockMessage() && this.m_config.disableBlocks )
        {
            this.SetErrorLevel( CHANNEL_ERROR_BLOCKS_DISABLED );
            this.m_messageFactory.ReleaseMessage( message );
            return;
        }

        if ( message.IsBlockMessage() )
        {
            yojimbo_assert( ( message as BlockMessage ).GetBlockSize() > 0, "GetBlockSize() > 0", "UnreliableUnorderedChannel::SendMessage" );
            yojimbo_assert( ( message as BlockMessage ).GetBlockSize() <= this.m_config.maxBlockSize, "GetBlockSize() <= m_config.maxBlockSize", "UnreliableUnorderedChannel::SendMessage" );
        }

        this.m_messageSendQueue!.Push( message );

        this.m_counters[CHANNEL_COUNTER_MESSAGES_SENT]++;
    }

    ReceiveMessage(): Message | null
    {
        if ( this.GetErrorLevel() !== CHANNEL_ERROR_NONE )
            return null;

        const receiveQueue = this.m_messageReceiveQueue!;

        if ( receiveQueue.IsEmpty() )
            return null;

        this.m_counters[CHANNEL_COUNTER_MESSAGES_RECEIVED]++;

        return receiveQueue.Pop();
    }

    AdvanceTime( _time: number ): void
    {
    }

    GetPacketData( context: unknown, packetData: ChannelPacketData, _packetSequence: number, availableBits: number ): number
    {
        const sendQueue = this.m_messageSendQueue!;

        if ( sendQueue.IsEmpty() )
            return 0;

        if ( this.m_config.packetBudget > 0 )
            availableBits = yojimbo_min( this.m_config.packetBudget * 8, availableBits );

        const giveUpBits = 4 * 8;

        const messageTypeBits = bits_required( 0, this.m_messageFactory.GetNumTypes() - 1 );

        let usedBits = ConservativeMessageHeaderBits;
        let numMessages = 0;
        const messages = this.m_packetMessages!;

        while ( true )
        {
            if ( sendQueue.IsEmpty() )
                break;

            if ( availableBits - usedBits < giveUpBits )
                break;

            if ( numMessages === this.m_config.maxMessagesPerPacket )
                break;

            const message = sendQueue.Pop();

            yojimbo_assert( message, "message", "UnreliableUnorderedChannel::GetPacketData" );

            const measureStream = new MeasureStream();
            measureStream.SetContext( context );
            measureStream.SetAllocator( this.m_messageFactory.GetAllocator() );
            message.SerializeInternal( measureStream );

            if ( message.IsBlockMessage() )
            {
                const blockMessage = message as BlockMessage;
                SerializeMessageBlock( measureStream, this.m_messageFactory, blockMessage, this.m_config.maxBlockSize );
            }

            const messageBits = messageTypeBits + measureStream.GetBitsProcessed();

            const isOverBudget = this.m_config.packetBudget > 0 && messageBits > this.m_config.packetBudget * 8;
            const isOverPacketSize = messageBits > this.m_maxPacketSize * 8;
            const isTooLarge = isOverBudget || isOverPacketSize;

            yojimbo_assert( !isTooLarge, "!isTooLarge", "UnreliableUnorderedChannel::GetPacketData" );

            if ( isTooLarge )
            {
                // You tried to send a message that is too large to ever fit into a packet for this channel. Large data should be sent as a block message over a reliable-ordered channel.
                this.SetErrorLevel( CHANNEL_ERROR_MESSAGE_TOO_LARGE );
                this.m_messageFactory.ReleaseMessage( message );
                break;
            }

            if ( usedBits + messageBits > availableBits )
            {
                this.m_messageFactory.ReleaseMessage( message );
                continue;
            }

            usedBits += messageBits;

            yojimbo_assert( usedBits <= availableBits, "usedBits <= availableBits", "UnreliableUnorderedChannel::GetPacketData" );

            messages[numMessages++] = message;
        }

        if ( numMessages === 0 )
            return 0;

        const allocator = this.m_messageFactory.GetAllocator();

        packetData.Initialize();
        packetData.channelIndex = this.GetChannelIndex();
        packetData.message.numMessages = numMessages;
        packetData.message.messages = yojimbo_allocate_message_array( allocator, numMessages );

        if ( !packetData.message.messages )
        {
            // Out of memory. These messages were already popped off the send queue, so this
            // channel owns the only reference to each: release them here or they leak. Leave the
            // arm empty (numMessages = 0) so packetData stays safe, and send no data this packet.
            for ( let i = 0; i < numMessages; ++i )
            {
                this.m_messageFactory.ReleaseMessage( messages[i] );
                messages[i] = null;
            }
            packetData.message.numMessages = 0;
            this.SetErrorLevel( CHANNEL_ERROR_OUT_OF_MEMORY );
            return 0;
        }

        for ( let i = 0; i < numMessages; ++i )
        {
            packetData.message.messages[i] = messages[i];
            messages[i] = null;
        }

        return usedBits;
    }

    ProcessPacketData( packetData: ChannelPacketData, packetSequence: number ): void
    {
        if ( this.m_errorLevel !== CHANNEL_ERROR_NONE )
            return;

        if ( packetData.messageFailedToSerialize )
        {
            this.SetErrorLevel( CHANNEL_ERROR_FAILED_TO_SERIALIZE );
            return;
        }

        // An unreliable-unordered channel never sends a top-level block fragment
        // (its block messages are serialized inline, see SerializeUnorderedMessages),
        // so packetData here must hold the message arm. If blockMessage is set
        // the packet is malformed. Treat it as a serialize failure.
        if ( packetData.blockMessage )
        {
            this.SetErrorLevel( CHANNEL_ERROR_FAILED_TO_SERIALIZE );
            return;
        }

        const receiveQueue = this.m_messageReceiveQueue!;

        for ( let i = 0; i < packetData.message.numMessages; ++i )
        {
            const message = packetData.message.messages![i];
            yojimbo_assert( message, "message", "UnreliableUnorderedChannel::ProcessPacketData" );
            message.SetId( packetSequence );
            if ( !receiveQueue.IsFull() )
            {
                this.m_messageFactory.AcquireMessage( message );
                receiveQueue.Push( message );
            }
        }
    }

    ProcessAck( _ack: number ): void
    {
    }
}
