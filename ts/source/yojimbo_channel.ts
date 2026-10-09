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
    TypeScript port of include/yojimbo_channel.h + source/yojimbo_channel.cpp (yojimbo 1.13.5).

    Port notes:
      - Every serialize_* result is propagated (the C++ macros return false from the enclosing function).
      - Allocations happen where upstream allocates, from the message factory's allocator, and every failure is handled
        as upstream: the message pointer arrays (one block per array, 8 bytes per entry), the serialize scratch for
        message types and ids, and block fragment data.
      - ChannelPacketData keeps both arms (message and block) always present and fully initialized, as upstream.
      - The channel keeps its own copy of its config (C++ const ChannelConfig by value), with the float32 resend times
        rounded with Math.fround.
*/

import { BaseStream, serialize_int, serialize_bool, serialize_bits, serialize_bytes } from '../serialize/serialize.ts';
import { serialize_sequence_relative } from '../include/yojimbo_serialize.ts';
import { MaxChannels } from '../include/yojimbo_constants.ts';
import { YOJIMBO_ALLOCATE, YOJIMBO_FREE, YOJIMBO_NEW, YOJIMBO_DELETE, type Allocator } from './yojimbo_allocator.ts';
import { ChannelConfig, CHANNEL_TYPE_RELIABLE_ORDERED, CHANNEL_TYPE_UNRELIABLE_UNORDERED, YOJIMBO_DEBUG_MESSAGE_BUDGET } from './yojimbo_config.ts';
import { Message, BlockMessage, MessageFactory, SerializeMessageBlock } from './yojimbo_message.ts';
import { yojimbo_assert, yojimbo_printf, YOJIMBO_LOG_LEVEL_ERROR } from './yojimbo_platform.ts';

/** Allocate a message pointer array (upstream: YOJIMBO_ALLOCATE( allocator, sizeof( Message* ) * n )). */

export function yojimbo_allocate_message_array( allocator: Allocator, numMessages: number ): Array<Message | null> | null
{
    return YOJIMBO_NEW( allocator, () => new Array<Message | null>( numMessages ).fill( null ), 8 * numMessages );
}

/** The message arm of ChannelPacketData. */

export class ChannelPacketMessageData
{
    numMessages = 0;
    messages: Array<Message | null> | null = null;
}

/** The block arm of ChannelPacketData. */

export class ChannelPacketBlockData
{
    message: BlockMessage | null = null;
    fragmentData: Uint8Array | null = null;
    messageId = 0;                              // uint16
    fragmentId = 0;                             // uint16
    fragmentSize = 0;                           // uint16
    numFragments = 0;                           // uint16
    messageType = 0;
}

export class ChannelPacketData
{
    channelIndex = 0;                           // 16 bits
    initialized = false;
    blockMessage = false;
    messageFailedToSerialize = false;

    // `blockMessage` selects which of these is live for a given packet. They were once a
    // union to save a few bytes; that overlap made every access unsafe. As separate
    // members both are always present and zero-initialized, so a mistaken access is benign.
    message = new ChannelPacketMessageData();
    block = new ChannelPacketBlockData();

    Initialize(): void
    {
        this.channelIndex = 0;
        this.blockMessage = false;
        this.messageFailedToSerialize = false;
        // Fully initialize both arms so Free() and any reader are safe no matter which one the
        // serializer populates (or if it bails out early, e.g. a block fragment on a
        // disableBlocks channel).
        this.message.numMessages = 0;
        this.message.messages = null;
        this.block.message = null;
        this.block.fragmentData = null;
        this.block.messageId = 0;
        this.block.fragmentId = 0;
        this.block.fragmentSize = 0;
        this.block.numFragments = 0;
        this.block.messageType = 0;
        this.initialized = true;
    }

    /** Copy every field of another channel packet data into this one (upstream memcpy). Ownership moves with it. */

    CopyFrom( other: ChannelPacketData ): void
    {
        this.channelIndex = other.channelIndex;
        this.initialized = other.initialized;
        this.blockMessage = other.blockMessage;
        this.messageFailedToSerialize = other.messageFailedToSerialize;
        this.message.numMessages = other.message.numMessages;
        this.message.messages = other.message.messages;
        this.block.message = other.block.message;
        this.block.fragmentData = other.block.fragmentData;
        this.block.messageId = other.block.messageId;
        this.block.fragmentId = other.block.fragmentId;
        this.block.fragmentSize = other.block.fragmentSize;
        this.block.numFragments = other.block.numFragments;
        this.block.messageType = other.block.messageType;
    }

    Free( messageFactory: MessageFactory ): void
    {
        yojimbo_assert( this.initialized, "initialized", "ChannelPacketData::Free" );
        const allocator = messageFactory.GetAllocator();
        if ( !this.blockMessage )
        {
            if ( this.message.numMessages > 0 )
            {
                const messages = this.message.messages!;
                for ( let i = 0; i < this.message.numMessages; ++i )
                {
                    if ( messages[i] )
                    {
                        messageFactory.ReleaseMessage( messages[i] );
                    }
                }
                this.message.messages = YOJIMBO_DELETE( allocator, this.message.messages );
            }
        }
        else
        {
            if ( this.block.message )
            {
                messageFactory.ReleaseMessage( this.block.message );
                this.block.message = null;
            }
            this.block.fragmentData = YOJIMBO_FREE( allocator, this.block.fragmentData );
        }
        this.initialized = false;
    }

    Serialize( stream: BaseStream, messageFactory: MessageFactory, channelConfigs: readonly ChannelConfig[], numChannels: number ): boolean
    {
        yojimbo_assert( this.initialized, "initialized", "ChannelPacketData::Serialize" );

        const startBits = stream.GetBitsProcessed();

        if ( numChannels > 1 )
        {
            if ( !serialize_int( stream, this, 'channelIndex', 0, numChannels - 1 ) )
                return false;
        }
        else
            this.channelIndex = 0;

        const channelConfig = channelConfigs[this.channelIndex];

        if ( !serialize_bool( stream, this, 'blockMessage' ) )
            return false;

        if ( !this.blockMessage )
        {
            switch ( channelConfig.type )
            {
                case CHANNEL_TYPE_RELIABLE_ORDERED:
                {
                    if ( !SerializeOrderedMessages( stream, messageFactory, this.message, channelConfig.maxMessagesPerPacket ) )
                    {
                        this.messageFailedToSerialize = true;
                        return true;
                    }
                }
                break;

                case CHANNEL_TYPE_UNRELIABLE_UNORDERED:
                {
                    if ( !SerializeUnorderedMessages( stream,
                                                      messageFactory,
                                                      this.message,
                                                      channelConfig.maxMessagesPerPacket,
                                                      channelConfig.maxBlockSize ) )
                    {
                        this.messageFailedToSerialize = true;
                        return true;
                    }
                }
                break;
            }

            if ( YOJIMBO_DEBUG_MESSAGE_BUDGET )
            {
                // Only assert on write/measure: this validates that *we* stay within the packet
                // budget when producing a packet. On read the data is untrusted, so a peer that
                // ignores the budget must not be able to crash a debug build.
                if ( !stream.IsReading && channelConfig.packetBudget > 0 )
                {
                    yojimbo_assert( stream.GetBitsProcessed() - startBits <= channelConfig.packetBudget * 8, "stream.GetBitsProcessed() - startBits <= channelConfig.packetBudget * 8", "ChannelPacketData::Serialize" );
                }
            }
        }
        else
        {
            if ( channelConfig.disableBlocks )
                return false;

            if ( !SerializeBlockFragment( stream, messageFactory, this.block, channelConfig ) )
                return false;
        }

        return true;
    }

    SerializeInternal( stream: BaseStream, messageFactory: MessageFactory, channelConfigs: readonly ChannelConfig[], numChannels: number ): boolean
    {
        return this.Serialize( stream, messageFactory, channelConfigs, numChannels );
    }
}

function SerializeOrderedMessagesInternal( stream: BaseStream,
                                           messageFactory: MessageFactory,
                                           data: ChannelPacketMessageData,
                                           messageTypes: Int32Array,
                                           messageIds: Uint16Array ): boolean
{
    const maxMessageType = messageFactory.GetNumTypes() - 1;
    const numMessages = data.numMessages;

    messageTypes.fill( 0 );
    messageIds.fill( 0 );

    if ( stream.IsWriting )
    {
        yojimbo_assert( data.messages, "messages", "SerializeOrderedMessages" );

        for ( let i = 0; i < numMessages; ++i )
        {
            const message = data.messages[i];
            yojimbo_assert( message, "messages[i]", "SerializeOrderedMessages" );
            messageTypes[i] = message.GetType();
            messageIds[i] = message.GetId();
        }
    }
    else
    {
        const allocator = messageFactory.GetAllocator();

        data.messages = yojimbo_allocate_message_array( allocator, numMessages );

        if ( !data.messages )
        {
            // Out of memory. Leave the arm empty (numMessages = 0) so ChannelPacketData::Free
            // stays safe, then fail the read; the channel treats this as a serialize failure.
            data.numMessages = 0;
            yojimbo_printf( YOJIMBO_LOG_LEVEL_ERROR, "error: failed to allocate messages (SerializeOrderedMessages)\n" );
            return false;
        }
    }

    const messages = data.messages!;

    if ( !serialize_bits( stream, messageIds, 0, 16 ) )
        return false;

    for ( let i = 1; i < numMessages; ++i )
    {
        if ( !serialize_sequence_relative( stream, messageIds[i - 1], messageIds, i ) )
            return false;
    }

    for ( let i = 0; i < numMessages; ++i )
    {
        if ( maxMessageType > 0 )
        {
            if ( !serialize_int( stream, messageTypes, i, 0, maxMessageType ) )
                return false;
        }
        else
        {
            messageTypes[i] = 0;
        }

        if ( stream.IsReading )
        {
            messages[i] = messageFactory.CreateMessage( messageTypes[i] );

            if ( !messages[i] )
            {
                yojimbo_printf( YOJIMBO_LOG_LEVEL_ERROR, "error: failed to create message of type %d (SerializeOrderedMessages)\n", messageTypes[i] );
                return false;
            }

            messages[i]!.SetId( messageIds[i] );
        }

        const message = messages[i];

        yojimbo_assert( message, "messages[i]", "SerializeOrderedMessages" );

        if ( !message.SerializeInternal( stream ) )
        {
            yojimbo_printf( YOJIMBO_LOG_LEVEL_ERROR, "error: failed to serialize message of type %d (SerializeOrderedMessages)\n", messageTypes[i] );
            return false;
        }
    }

    return true;
}

/** Scratch slot for the hasMessages flag (single threaded, never re-entered). */
const has_messages_scratch = { hasMessages: false };

function SerializeOrderedMessages( stream: BaseStream,
                                   messageFactory: MessageFactory,
                                   data: ChannelPacketMessageData,
                                   maxMessagesPerPacket: number ): boolean
{
    has_messages_scratch.hasMessages = stream.IsWriting && data.numMessages !== 0;

    if ( !serialize_bool( stream, has_messages_scratch, 'hasMessages' ) )
        return false;

    if ( !has_messages_scratch.hasMessages )
        return true;

    if ( !serialize_int( stream, data, 'numMessages', 1, maxMessagesPerPacket ) )
        return false;

    const numMessages = data.numMessages;

    // One heap block for the message type and id scratch arrays, so stack usage doesn't
    // scale with maxMessagesPerPacket. The serialize body lives in a separate function so
    // all its early returns funnel through the single free below.
    const allocator = messageFactory.GetAllocator();

    const scratch = YOJIMBO_ALLOCATE( allocator, ( 4 + 2 ) * numMessages );

    if ( !scratch )
    {
        if ( stream.IsReading )
        {
            // Leave the arm empty (numMessages = 0) so ChannelPacketData::Free stays safe.
            // On write the messages remain owned by the packet data, so leave them alone.
            data.numMessages = 0;
        }
        yojimbo_printf( YOJIMBO_LOG_LEVEL_ERROR, "error: failed to allocate serialize scratch (SerializeOrderedMessages)\n" );
        return false;
    }

    const messageTypes = new Int32Array( scratch.buffer, scratch.byteOffset, numMessages );
    const messageIds = new Uint16Array( scratch.buffer, scratch.byteOffset + 4 * numMessages, numMessages );

    const result = SerializeOrderedMessagesInternal( stream, messageFactory, data, messageTypes, messageIds );

    YOJIMBO_FREE( allocator, scratch );

    return result;
}

function SerializeUnorderedMessagesInternal( stream: BaseStream,
                                             messageFactory: MessageFactory,
                                             data: ChannelPacketMessageData,
                                             maxBlockSize: number,
                                             messageTypes: Int32Array ): boolean
{
    const maxMessageType = messageFactory.GetNumTypes() - 1;
    const numMessages = data.numMessages;

    messageTypes.fill( 0 );

    if ( stream.IsWriting )
    {
        yojimbo_assert( data.messages, "messages", "SerializeUnorderedMessages" );

        for ( let i = 0; i < numMessages; ++i )
        {
            const message = data.messages[i];
            yojimbo_assert( message, "messages[i]", "SerializeUnorderedMessages" );
            messageTypes[i] = message.GetType();
        }
    }
    else
    {
        const allocator = messageFactory.GetAllocator();

        data.messages = yojimbo_allocate_message_array( allocator, numMessages );

        if ( !data.messages )
        {
            // Out of memory. Leave the arm empty (numMessages = 0) so ChannelPacketData::Free
            // stays safe, then fail the read; the channel treats this as a serialize failure.
            data.numMessages = 0;
            yojimbo_printf( YOJIMBO_LOG_LEVEL_ERROR, "error: failed to allocate messages (SerializeUnorderedMessages)\n" );
            return false;
        }
    }

    const messages = data.messages!;

    for ( let i = 0; i < numMessages; ++i )
    {
        if ( maxMessageType > 0 )
        {
            if ( !serialize_int( stream, messageTypes, i, 0, maxMessageType ) )
                return false;
        }
        else
        {
            messageTypes[i] = 0;
        }

        if ( stream.IsReading )
        {
            messages[i] = messageFactory.CreateMessage( messageTypes[i] );

            if ( !messages[i] )
            {
                yojimbo_printf( YOJIMBO_LOG_LEVEL_ERROR, "error: failed to create message type %d (SerializeUnorderedMessages)\n", messageTypes[i] );
                return false;
            }
        }

        const message = messages[i];

        yojimbo_assert( message, "messages[i]", "SerializeUnorderedMessages" );

        if ( !message.SerializeInternal( stream ) )
        {
            yojimbo_printf( YOJIMBO_LOG_LEVEL_ERROR, "error: failed to serialize message type %d (SerializeUnorderedMessages)\n", messageTypes[i] );
            return false;
        }

        if ( message.IsBlockMessage() )
        {
            const blockMessage = message as BlockMessage;
            if ( !SerializeMessageBlock( stream, messageFactory, blockMessage, maxBlockSize ) )
            {
                yojimbo_printf( YOJIMBO_LOG_LEVEL_ERROR, "error: failed to serialize message block (SerializeUnorderedMessages)\n" );
                return false;
            }
        }
    }

    return true;
}

function SerializeUnorderedMessages( stream: BaseStream,
                                     messageFactory: MessageFactory,
                                     data: ChannelPacketMessageData,
                                     maxMessagesPerPacket: number,
                                     maxBlockSize: number ): boolean
{
    has_messages_scratch.hasMessages = stream.IsWriting && data.numMessages !== 0;

    if ( !serialize_bool( stream, has_messages_scratch, 'hasMessages' ) )
        return false;

    if ( !has_messages_scratch.hasMessages )
        return true;

    if ( !serialize_int( stream, data, 'numMessages', 1, maxMessagesPerPacket ) )
        return false;

    const numMessages = data.numMessages;

    // Heap scratch for the message types, so stack usage doesn't scale with maxMessagesPerPacket.
    const allocator = messageFactory.GetAllocator();

    const scratch = YOJIMBO_ALLOCATE( allocator, 4 * numMessages );

    if ( !scratch )
    {
        if ( stream.IsReading )
        {
            // Leave the arm empty (numMessages = 0) so ChannelPacketData::Free stays safe.
            // On write the messages remain owned by the packet data, so leave them alone.
            data.numMessages = 0;
        }
        yojimbo_printf( YOJIMBO_LOG_LEVEL_ERROR, "error: failed to allocate serialize scratch (SerializeUnorderedMessages)\n" );
        return false;
    }

    const messageTypes = new Int32Array( scratch.buffer, scratch.byteOffset, numMessages );

    const result = SerializeUnorderedMessagesInternal( stream, messageFactory, data, maxBlockSize, messageTypes );

    YOJIMBO_FREE( allocator, scratch );

    return result;
}

function SerializeBlockFragment( stream: BaseStream,
                                 messageFactory: MessageFactory,
                                 block: ChannelPacketBlockData,
                                 channelConfig: ChannelConfig ): boolean
{
    const maxMessageType = messageFactory.GetNumTypes() - 1;

    if ( stream.IsReading )
    {
        block.message = null;
        block.fragmentData = null;
        // messageType is only serialized with fragment 0 (below); default it so a
        // non-zero fragment leaves it defined rather than read uninitialized by callers.
        block.messageType = 0;
    }

    if ( !serialize_bits( stream, block, 'messageId', 16 ) )
        return false;

    const maxFragmentsPerBlock = channelConfig.GetMaxFragmentsPerBlock();

    if ( maxFragmentsPerBlock > 1 )
    {
        if ( !serialize_int( stream, block, 'numFragments', 1, maxFragmentsPerBlock ) )
            return false;
    }
    else
    {
        if ( stream.IsReading )
            block.numFragments = 1;
    }

    if ( block.numFragments > 1 )
    {
        if ( !serialize_int( stream, block, 'fragmentId', 0, block.numFragments - 1 ) )
            return false;
    }
    else
    {
        if ( stream.IsReading )
            block.fragmentId = 0;
    }

    if ( !serialize_int( stream, block, 'fragmentSize', 1, channelConfig.blockFragmentSize ) )
        return false;

    if ( stream.IsReading )
    {
        block.fragmentData = YOJIMBO_ALLOCATE( messageFactory.GetAllocator(), block.fragmentSize );

        if ( !block.fragmentData )
        {
            yojimbo_printf( YOJIMBO_LOG_LEVEL_ERROR, "error: failed to serialize block fragment (SerializeBlockFragment)\n" );
            return false;
        }
    }

    if ( !serialize_bytes( stream, block.fragmentData!, block.fragmentSize ) )
        return false;

    if ( block.fragmentId === 0 )
    {
        // block message

        if ( maxMessageType > 0 )
        {
            if ( !serialize_int( stream, block, 'messageType', 0, maxMessageType ) )
                return false;
        }
        else
        {
            block.messageType = 0;
        }

        if ( stream.IsReading )
        {
            const message = messageFactory.CreateMessage( block.messageType );

            if ( !message )
            {
                yojimbo_printf( YOJIMBO_LOG_LEVEL_ERROR, "error: failed to create block message type %d (SerializeBlockFragment)\n", block.messageType );
                return false;
            }

            if ( !message.IsBlockMessage() )
            {
                yojimbo_printf( YOJIMBO_LOG_LEVEL_ERROR, "error: received block fragment attached to non-block message (SerializeBlockFragment)\n" );
                messageFactory.ReleaseMessage( message );
                return false;
            }

            block.message = message as BlockMessage;
        }

        yojimbo_assert( block.message, "block.message", "SerializeBlockFragment" );

        if ( !block.message.SerializeInternal( stream ) )
        {
            yojimbo_printf( YOJIMBO_LOG_LEVEL_ERROR, "error: failed to serialize block message of type %d (SerializeBlockFragment)\n", block.messageType );
            return false;
        }
    }

    return true;
}

// ------------------------------------------------------------------------------------

/**
    Channel counters provide insight into the number of times an action was performed by a channel.
    They are intended for use in a telemetry system, eg. reported to some backend logging system to track behavior in a production environment.
 */

export const CHANNEL_COUNTER_MESSAGES_SENT = 0;                 ///< Number of messages sent over this channel.
export const CHANNEL_COUNTER_MESSAGES_RECEIVED = 1;             ///< Number of messages received over this channel.
export const CHANNEL_COUNTER_NUM_COUNTERS = 2;                  ///< The number of channel counters.

/**
    Channel error level.
    If the channel gets into an error state, it sets an error state on the corresponding connection. See CONNECTION_ERROR_CHANNEL.
    This way if any channel on a client/server connection gets into a bad state, that client is automatically kicked from the server.
 */

export const CHANNEL_ERROR_NONE = 0;                            ///< No error. All is well.
export const CHANNEL_ERROR_DESYNC = 1;                          ///< This channel has desynced. This means that the connection protocol has desynced and cannot recover. The client should be disconnected.
export const CHANNEL_ERROR_SEND_QUEUE_FULL = 2;                 ///< The user tried to send a message but the send queue was full. This will assert out in development, but in production it sets this error on the channel.
export const CHANNEL_ERROR_BLOCKS_DISABLED = 3;                 ///< The channel received a packet containing data for blocks, but this channel is configured to disable blocks. See ChannelConfig::disableBlocks.
export const CHANNEL_ERROR_FAILED_TO_SERIALIZE = 4;             ///< Serialize read failed for a message sent to this channel. Check your message serialize functions, one of them is returning false on serialize read. This can also be caused by a desync in message read and write.
export const CHANNEL_ERROR_OUT_OF_MEMORY = 5;                   ///< The channel tried to allocate some memory but couldn't.
export const CHANNEL_ERROR_MESSAGE_TOO_LARGE = 6;               ///< The user tried to send a message that is too large to ever fit into a packet for this channel. Large data should be sent as a block message instead. This will assert out in development, but in production it sets this error on the channel.

export type ChannelErrorLevel = 0 | 1 | 2 | 3 | 4 | 5 | 6;

/// Helper function to convert a channel error to a user friendly string.
export function GetChannelErrorString( error: ChannelErrorLevel ): string
{
    switch ( error )
    {
        case CHANNEL_ERROR_NONE:                    return "none";
        case CHANNEL_ERROR_DESYNC:                  return "desync";
        case CHANNEL_ERROR_SEND_QUEUE_FULL:         return "send queue full";
        case CHANNEL_ERROR_OUT_OF_MEMORY:           return "out of memory";
        case CHANNEL_ERROR_BLOCKS_DISABLED:         return "blocks disabled";
        case CHANNEL_ERROR_FAILED_TO_SERIALIZE:     return "failed to serialize";
        case CHANNEL_ERROR_MESSAGE_TOO_LARGE:       return "message too large";
        default:
            yojimbo_assert( false, "unknown channel error", "GetChannelErrorString" );
            return "(unknown)";
    }
}

/// Common functionality shared across all channel types.
export abstract class Channel
{
    protected readonly m_config: ChannelConfig;                     ///< Channel configuration data (a private copy).
    protected readonly m_maxPacketSize: number;                     ///< The maximum packet size in bytes (from ConnectionConfig::maxPacketSize). Used to detect messages that are too large to ever fit into a packet.
    protected m_allocator: Allocator;                               ///< Allocator for allocations matching life cycle of this channel.
    protected m_channelIndex: number;                               ///< The channel index in [0,numChannels-1].
    protected m_time: number;                                       ///< The current time.
    protected m_errorLevel: ChannelErrorLevel;                      ///< The channel error level.
    protected m_messageFactory: MessageFactory;                     ///< Message factory for creating and destroying messages.
    protected m_counters: number[];                                 ///< Counters for unit testing, stats etc.

    /**
        Channel constructor.
     */

    constructor( allocator: Allocator, messageFactory: MessageFactory, config: ChannelConfig, maxPacketSize: number, channelIndex: number, time: number )
    {
        this.m_config = config.Clone();
        this.m_config.messageResendTime = Math.fround( this.m_config.messageResendTime );
        this.m_config.blockFragmentResendTime = Math.fround( this.m_config.blockFragmentResendTime );
        this.m_maxPacketSize = maxPacketSize;
        yojimbo_assert( channelIndex >= 0, "channelIndex >= 0", "Channel::Channel" );
        yojimbo_assert( channelIndex < MaxChannels, "channelIndex < MaxChannels", "Channel::Channel" );
        this.m_channelIndex = channelIndex;
        this.m_allocator = allocator;
        this.m_messageFactory = messageFactory;
        this.m_errorLevel = CHANNEL_ERROR_NONE;
        this.m_time = time;
        this.m_counters = new Array<number>( CHANNEL_COUNTER_NUM_COUNTERS ).fill( 0 );
    }

    /**
        Channel destructor.
     */

    Dispose(): void
    {
    }

    /**
        Reset the channel.
     */

    abstract Reset(): void;

    /**
        Returns true if a message can be sent over this channel.
     */

    abstract CanSendMessage(): boolean;

    /**
        Are there any messages in the send queue?
        @returns True if there is at least one message in the send queue.
     */

    abstract HasMessagesToSend(): boolean;

    /**
        Queue a message to be sent across this channel. Ownership of the message's reference passes to the channel.
        @param message The message to be sent.
        @param context The serialization context, from Client::GetContext or Server::GetContext. Passed through to the message serialize functions. May be null.
     */

    abstract SendMessage( message: Message, context: unknown ): void;

    /**
        Pops the next message off the receive queue if one is available.
        @returns The received message, null if there are no messages to receive. The caller owns the message returned by this function and is responsible for releasing it.
     */

    abstract ReceiveMessage(): Message | null;

    /**
        Advance channel time.
        Called by Connection::AdvanceTime for each channel configured on the connection.
     */

    abstract AdvanceTime( time: number ): void;

    /**
        Get channel packet data for this channel.
        @param context The serialization context. Passed through to the message serialize functions. May be null.
        @param packetData The channel packet data to be filled [out]
        @param packetSequence The sequence number of the packet being generated.
        @param availableBits The maximum number of bits of packet data the channel is allowed to write.
        @returns The number of bits of packet data written by the channel.
     */

    abstract GetPacketData( context: unknown, packetData: ChannelPacketData, packetSequence: number, availableBits: number ): number;

    /**
        Process packet data included in a connection packet.
        @param packetData The channel packet data to process.
        @param packetSequence The sequence number of the connection packet that contains the channel packet data.
     */

    abstract ProcessPacketData( packetData: ChannelPacketData, packetSequence: number ): void;

    /**
        Process a connection packet ack.
        Depending on the channel type:
            1. Acks messages and block fragments so they stop being included in outgoing connection packets (reliable-ordered channel),
            2. Does nothing at all (unreliable-unordered).
        @param sequence The sequence number of the connection packet that was acked.
     */

    abstract ProcessAck( sequence: number ): void;

    /**
        Get the channel error level.
        @returns The channel error level.
     */

    GetErrorLevel(): ChannelErrorLevel
    {
        return this.m_errorLevel;
    }

    /**
        Gets the channel index.
        @returns The channel index in [0,numChannels-1].
     */

    GetChannelIndex(): number
    {
        return this.m_channelIndex;
    }

    /**
        Get a counter value.
        @param index The index of the counter to retrieve. See ChannelCounters.
        @returns The value of the counter.
     */

    GetCounter( index: number ): number
    {
        yojimbo_assert( index >= 0, "index >= 0", "Channel::GetCounter" );
        yojimbo_assert( index < CHANNEL_COUNTER_NUM_COUNTERS, "index < CHANNEL_COUNTER_NUM_COUNTERS", "Channel::GetCounter" );
        return this.m_counters[index];
    }

    /**
        Resets all counter values to zero.
     */

    ResetCounters(): void
    {
        this.m_counters.fill( 0 );
    }

    /**
        Set the channel error level.
        All errors go through this function to make debug logging easier.
     */

    protected SetErrorLevel( errorLevel: ChannelErrorLevel ): void
    {
        if ( errorLevel !== this.m_errorLevel && errorLevel !== CHANNEL_ERROR_NONE )
        {
            yojimbo_printf( YOJIMBO_LOG_LEVEL_ERROR, "channel went into error state: %s\n", GetChannelErrorString( errorLevel ) );
        }
        this.m_errorLevel = errorLevel;
    }
}
