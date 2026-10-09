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
    TypeScript port of include/yojimbo_connection.h + source/yojimbo_connection.cpp (yojimbo 1.13.5).

    Port notes:
      - ConnectionPacket's destructor (which releases every message reference the packet holds) is Dispose(), called on
        every exit path of GeneratePacket and ProcessPacket.
      - The per-channel packet data scratch is owned by the connection and reused; it is copied into the packet's
        channel entries (upstream memcpy), which is where ownership of the message references moves.
      - ProcessPacket reads the payload in place. Upstream copies it into a packetBytes + 8 allocation because its
        BitReader loads an 8 byte window; the TypeScript ReadStream bounds checks its loads, so no copy is needed
        (as in the C# port). packetBytes larger than the buffer is refused as a read failure.
      - The connection keeps its own deep copy of the config, as the C++ by-value member.
*/

import { WriteStream, ReadStream, BaseStream, serialize_int } from '../serialize/serialize.ts';
import { MaxChannels, ConservativePacketHeaderBits, ConservativeChannelHeaderBits } from '../include/yojimbo_constants.ts';
import { YOJIMBO_NEW, YOJIMBO_DELETE, ALLOCATOR_ERROR_NONE, type Allocator } from './yojimbo_allocator.ts';
import { ConnectionConfig, CHANNEL_TYPE_RELIABLE_ORDERED, CHANNEL_TYPE_UNRELIABLE_UNORDERED, YOJIMBO_DEBUG_MESSAGE_BUDGET } from './yojimbo_config.ts';
import { Message, MessageFactory, MESSAGE_FACTORY_ERROR_NONE } from './yojimbo_message.ts';
import { Channel, ChannelPacketData, CHANNEL_ERROR_NONE, type ChannelErrorLevel } from './yojimbo_channel.ts';
import { ReliableOrderedChannel } from './yojimbo_reliable_ordered_channel.ts';
import { UnreliableUnorderedChannel } from './yojimbo_unreliable_unordered_channel.ts';
import { yojimbo_assert, yojimbo_printf, YOJIMBO_LOG_LEVEL_ERROR, YOJIMBO_LOG_LEVEL_DEBUG } from './yojimbo_platform.ts';

class ConnectionPacket
{
    numChannelEntries = 0;
    channelEntry: ChannelPacketData[] | null = null;
    messageFactory: MessageFactory | null = null;

    /** The C++ destructor: frees every channel entry (releasing its message references) and the entry array. */

    Dispose(): void
    {
        if ( this.messageFactory )
        {
            for ( let i = 0; i < this.numChannelEntries; ++i )
            {
                this.channelEntry![i].Free( this.messageFactory );
            }
            this.channelEntry = YOJIMBO_DELETE( this.messageFactory.GetAllocator(), this.channelEntry );
            this.messageFactory = null;
        }
    }

    AllocateChannelData( messageFactory: MessageFactory, numEntries: number ): boolean
    {
        yojimbo_assert( numEntries > 0, "numEntries > 0", "ConnectionPacket::AllocateChannelData" );
        yojimbo_assert( numEntries <= MaxChannels, "numEntries <= MaxChannels", "ConnectionPacket::AllocateChannelData" );
        this.messageFactory = messageFactory;
        const allocator = messageFactory.GetAllocator();
        this.channelEntry = YOJIMBO_NEW( allocator, () => { const entries = new Array<ChannelPacketData>( numEntries ); for ( let i = 0; i < numEntries; ++i ) entries[i] = new ChannelPacketData(); return entries; }, 64 * numEntries );
        if ( this.channelEntry == null )
        {
            // On the read path numChannelEntries was already set from the wire before this
            // call; reset it so the destructor doesn't iterate a null channelEntry array.
            this.numChannelEntries = 0;
            return false;
        }
        for ( let i = 0; i < numEntries; ++i )
        {
            this.channelEntry[i].Initialize();
        }
        this.numChannelEntries = numEntries;
        return true;
    }

    Serialize( stream: BaseStream, messageFactory: MessageFactory, connectionConfig: ConnectionConfig ): boolean
    {
        const numChannels = connectionConfig.numChannels;
        if ( !serialize_int( stream, this, 'numChannelEntries', 0, connectionConfig.numChannels ) )
            return false;
        if ( YOJIMBO_DEBUG_MESSAGE_BUDGET )
        {
            // Write/measure only — validates our own header-size estimate. Keep it off the untrusted path.
            if ( !stream.IsReading )
                yojimbo_assert( stream.GetBitsProcessed() <= ConservativePacketHeaderBits, "stream.GetBitsProcessed() <= ConservativePacketHeaderBits", "ConnectionPacket::Serialize" );
        }
        if ( this.numChannelEntries > 0 )
        {
            if ( stream.IsReading )
            {
                if ( !this.AllocateChannelData( messageFactory, this.numChannelEntries ) )
                {
                    yojimbo_printf( YOJIMBO_LOG_LEVEL_ERROR, "error: failed to allocate channel data (ConnectionPacket)\n" );
                    return false;
                }
                for ( let i = 0; i < this.numChannelEntries; ++i )
                {
                    yojimbo_assert( !this.channelEntry![i].messageFailedToSerialize, "messageFailedToSerialize == 0", "ConnectionPacket::Serialize" );
                }
            }
            for ( let i = 0; i < this.numChannelEntries; ++i )
            {
                const entry = this.channelEntry![i];
                yojimbo_assert( !entry.messageFailedToSerialize, "messageFailedToSerialize == 0", "ConnectionPacket::Serialize" );
                if ( !entry.SerializeInternal( stream, messageFactory, connectionConfig.channel, numChannels ) )
                {
                    yojimbo_printf( YOJIMBO_LOG_LEVEL_ERROR, "error: failed to serialize channel %d\n", i );
                    return false;
                }
            }
        }
        return true;
    }

    SerializeInternal( stream: BaseStream, messageFactory: MessageFactory, connectionConfig: ConnectionConfig ): boolean
    {
        return this.Serialize( stream, messageFactory, connectionConfig );
    }
}

// ------------------------------------------------------------------------------

/// Connection error level.
export const CONNECTION_ERROR_NONE = 0;                             ///< No error. All is well.
export const CONNECTION_ERROR_CHANNEL = 1;                          ///< A channel is in an error state.
export const CONNECTION_ERROR_ALLOCATOR = 2;                        ///< The allocator is an error state.
export const CONNECTION_ERROR_MESSAGE_FACTORY = 3;                  ///< The message factory is in an error state.
export const CONNECTION_ERROR_READ_PACKET_FAILED = 4;               ///< Failed to read packet. Received an invalid packet?

export type ConnectionErrorLevel = 0 | 1 | 2 | 3 | 4;

/**
    Sends and receives messages across a set of user defined channels.
 */

export class Connection
{
    private m_allocator: Allocator | null;                          ///< Allocator passed in to the connection constructor.
    private m_messageFactory: MessageFactory;                       ///< Message factory for creating and destroying messages.
    private m_connectionConfig: ConnectionConfig;                   ///< Connection configuration (a private copy).
    private m_channel: Array<Channel | null>;                       ///< Array of connection channels. Array size corresponds to m_connectionConfig.numChannels
    private m_errorLevel: ConnectionErrorLevel;                     ///< The connection error level.
    private m_channelData: ChannelPacketData[];                     ///< Per-channel packet data scratch for GeneratePacket (upstream: a stack array).
    private m_channelHasData: boolean[];                            ///< Per-channel scratch for GeneratePacket.

    constructor( allocator: Allocator, messageFactory: MessageFactory, connectionConfig: ConnectionConfig, time: number )
    {
        this.m_connectionConfig = connectionConfig.Clone();
        this.m_allocator = allocator;
        this.m_messageFactory = messageFactory;
        this.m_errorLevel = CONNECTION_ERROR_NONE;
        this.m_channel = new Array<Channel | null>( MaxChannels ).fill( null );
        yojimbo_assert( this.m_connectionConfig.numChannels >= 1, "m_connectionConfig.numChannels >= 1", "Connection::Connection" );
        yojimbo_assert( this.m_connectionConfig.numChannels <= MaxChannels, "m_connectionConfig.numChannels <= MaxChannels", "Connection::Connection" );
        for ( let channelIndex = 0; channelIndex < this.m_connectionConfig.numChannels; ++channelIndex )
        {
            const channelConfig = this.m_connectionConfig.channel[channelIndex];
            const maxPacketSize = this.m_connectionConfig.maxPacketSize;
            switch ( channelConfig.type )
            {
                case CHANNEL_TYPE_RELIABLE_ORDERED:
                {
                    this.m_channel[channelIndex] = YOJIMBO_NEW( allocator, () => new ReliableOrderedChannel( allocator, messageFactory, channelConfig, maxPacketSize, channelIndex, time ) );
                }
                break;

                case CHANNEL_TYPE_UNRELIABLE_UNORDERED:
                {
                    this.m_channel[channelIndex] = YOJIMBO_NEW( allocator, () => new UnreliableUnorderedChannel( allocator, messageFactory, channelConfig, maxPacketSize, channelIndex, time ) );
                }
                break;

                default:
                    yojimbo_assert( false, "unknown channel type", "Connection::Connection" );
            }
            yojimbo_assert( this.m_channel[channelIndex], "m_channel[channelIndex]", "Connection::Connection" );
        }
        this.m_channelData = new Array<ChannelPacketData>( this.m_connectionConfig.numChannels );
        for ( let i = 0; i < this.m_connectionConfig.numChannels; ++i )
            this.m_channelData[i] = new ChannelPacketData();
        this.m_channelHasData = new Array<boolean>( this.m_connectionConfig.numChannels ).fill( false );
    }

    /** The C++ destructor: resets the channels (releasing queued messages) and deletes them. */

    Dispose(): void
    {
        yojimbo_assert( this.m_allocator, "m_allocator", "Connection::~Connection" );
        this.Reset();
        for ( let i = 0; i < this.m_connectionConfig.numChannels; ++i )
        {
            this.m_channel[i] = YOJIMBO_DELETE( this.m_allocator, this.m_channel[i] );
        }
        this.m_allocator = null;
    }

    Reset(): void
    {
        this.m_errorLevel = CONNECTION_ERROR_NONE;
        for ( let i = 0; i < this.m_connectionConfig.numChannels; ++i )
        {
            this.m_channel[i]!.Reset();
        }
    }

    CanSendMessage( channelIndex: number ): boolean
    {
        yojimbo_assert( channelIndex >= 0, "channelIndex >= 0", "Connection::CanSendMessage" );
        yojimbo_assert( channelIndex < this.m_connectionConfig.numChannels, "channelIndex < m_connectionConfig.numChannels", "Connection::CanSendMessage" );
        return this.m_channel[channelIndex]!.CanSendMessage();
    }

    HasMessagesToSend( channelIndex: number ): boolean
    {
        yojimbo_assert( channelIndex >= 0, "channelIndex >= 0", "Connection::HasMessagesToSend" );
        yojimbo_assert( channelIndex < this.m_connectionConfig.numChannels, "channelIndex < m_connectionConfig.numChannels", "Connection::HasMessagesToSend" );
        return this.m_channel[channelIndex]!.HasMessagesToSend();
    }

    SendMessage( channelIndex: number, message: Message, context: unknown = null ): void
    {
        yojimbo_assert( channelIndex >= 0, "channelIndex >= 0", "Connection::SendMessage" );
        yojimbo_assert( channelIndex < this.m_connectionConfig.numChannels, "channelIndex < m_connectionConfig.numChannels", "Connection::SendMessage" );
        this.m_channel[channelIndex]!.SendMessage( message, context );
    }

    ReceiveMessage( channelIndex: number ): Message | null
    {
        yojimbo_assert( channelIndex >= 0, "channelIndex >= 0", "Connection::ReceiveMessage" );
        yojimbo_assert( channelIndex < this.m_connectionConfig.numChannels, "channelIndex < m_connectionConfig.numChannels", "Connection::ReceiveMessage" );
        return this.m_channel[channelIndex]!.ReceiveMessage();
    }

    ReleaseMessage( message: Message ): void
    {
        yojimbo_assert( message, "message", "Connection::ReleaseMessage" );
        this.m_messageFactory.ReleaseMessage( message );
    }

    /**
        Generate a connection packet.
        @param context The serialization context. May be null.
        @param packetSequence The sequence number of the packet (uint16).
        @param packetData The buffer to write the packet to.
        @param maxPacketBytes The maximum number of bytes to write (rounded down to a multiple of 8).
        @param out out.packetBytes is set to the number of bytes written.
        @returns False if the packet could not be generated (channel data allocation failed).
     */

    GeneratePacket( context: unknown, packetSequence: number, packetData: Uint8Array, maxPacketBytes: number, out: { packetBytes: number } ): boolean
    {
        const packet = new ConnectionPacket();

        // The serialize BitWriter stores qwords, so its buffer size must be a multiple of 8
        // bytes. Round the write size down to the nearest multiple of 8: rounding down (never up)
        // keeps packets within the configured maxPacketSize on the wire. Budget the channels
        // against the same rounded size so what we pack always fits what we write.
        maxPacketBytes &= ~7;

        const numChannels = this.m_connectionConfig.numChannels;

        if ( numChannels > 0 )
        {
            let numChannelsWithData = 0;
            const channelHasData = this.m_channelHasData;
            channelHasData.fill( false );
            const channelData = this.m_channelData;

            let availableBits = maxPacketBytes * 8 - ConservativePacketHeaderBits;

            for ( let channelIndex = 0; channelIndex < numChannels; ++channelIndex )
            {
                const packetDataBits = this.m_channel[channelIndex]!.GetPacketData( context, channelData[channelIndex], packetSequence, availableBits );
                if ( packetDataBits > 0 )
                {
                    availableBits -= ConservativeChannelHeaderBits;
                    availableBits -= packetDataBits;
                    channelHasData[channelIndex] = true;
                    numChannelsWithData++;
                }
            }

            if ( numChannelsWithData > 0 )
            {
                if ( !packet.AllocateChannelData( this.m_messageFactory, numChannelsWithData ) )
                {
                    yojimbo_printf( YOJIMBO_LOG_LEVEL_ERROR, "error: failed to allocate channel data\n" );
                    // GetPacketData already populated channelData for each channel with data
                    // (acquired message references, allocated message arrays, copied fragment data).
                    // Ownership hasn't transferred to the packet yet, so free those entries here or they leak.
                    for ( let channelIndex = 0; channelIndex < numChannels; ++channelIndex )
                    {
                        if ( channelHasData[channelIndex] )
                            channelData[channelIndex].Free( this.m_messageFactory );
                    }
                    out.packetBytes = 0;
                    return false;
                }

                let index = 0;

                for ( let channelIndex = 0; channelIndex < numChannels; ++channelIndex )
                {
                    if ( channelHasData[channelIndex] )
                    {
                        packet.channelEntry![index].CopyFrom( channelData[channelIndex] );
                        channelData[channelIndex].Initialize();         // ownership moved to the packet: drop the scratch's references
                        index++;
                    }
                }
            }
        }

        out.packetBytes = WritePacket( context, this.m_messageFactory, this.m_connectionConfig, packet, packetData, maxPacketBytes );

        packet.Dispose();

        return true;
    }

    /**
        Process a connection packet.
        @param context The serialization context. May be null.
        @param packetSequence The sequence number of the packet (uint16).
        @param packetData The packet payload. Read in place; only valid during the call is fine.
        @param packetBytes The number of bytes of payload.
        @returns True if the packet was processed, false if it was malformed or a channel went into an error state.
     */

    ProcessPacket( context: unknown, packetSequence: number, packetData: Uint8Array | null, packetBytes: number ): boolean
    {
        if ( this.m_errorLevel !== CONNECTION_ERROR_NONE )
        {
            yojimbo_printf( YOJIMBO_LOG_LEVEL_DEBUG, "failed to read packet because connection is in error state\n" );
            return false;
        }

        // A packet that is exactly a reliable header reaches us with zero payload bytes.
        // That's never a valid connection packet, so fail it like any other malformed read.
        if ( !packetData || packetBytes <= 0 || packetBytes > packetData.length )
        {
            yojimbo_printf( YOJIMBO_LOG_LEVEL_ERROR, "error: failed to read packet (empty payload)\n" );
            this.m_errorLevel = CONNECTION_ERROR_READ_PACKET_FAILED;
            return false;
        }

        const packet = new ConnectionPacket();

        const readOk = ReadPacket( context, this.m_messageFactory, this.m_connectionConfig, packet, packetData, packetBytes );

        if ( !readOk )
        {
            packet.Dispose();
            yojimbo_printf( YOJIMBO_LOG_LEVEL_ERROR, "error: failed to read packet\n" );
            this.m_errorLevel = CONNECTION_ERROR_READ_PACKET_FAILED;
            return false;
        }

        for ( let i = 0; i < packet.numChannelEntries; ++i )
        {
            const entry = packet.channelEntry![i];
            const channelIndex = entry.channelIndex;
            yojimbo_assert( channelIndex >= 0, "channelIndex >= 0", "Connection::ProcessPacket" );
            yojimbo_assert( channelIndex < this.m_connectionConfig.numChannels, "channelIndex < m_connectionConfig.numChannels", "Connection::ProcessPacket" );
            const channel = this.m_channel[channelIndex]!;
            channel.ProcessPacketData( entry, packetSequence );
            if ( channel.GetErrorLevel() !== CHANNEL_ERROR_NONE )
            {
                yojimbo_printf( YOJIMBO_LOG_LEVEL_DEBUG, "failed to read packet because channel %d is in error state\n", channelIndex );
                packet.Dispose();
                return false;
            }
        }

        packet.Dispose();

        return true;
    }

    /**
        Get the error level of a channel on this connection.
        Use this to find out which channel error drove the connection into CONNECTION_ERROR_CHANNEL.
        @param channelIndex The channel index in [0,numChannels-1].
        @returns The channel error level.
     */

    GetChannelErrorLevel( channelIndex: number ): ChannelErrorLevel
    {
        yojimbo_assert( channelIndex >= 0, "channelIndex >= 0", "Connection::GetChannelErrorLevel" );
        yojimbo_assert( channelIndex < this.m_connectionConfig.numChannels, "channelIndex < m_connectionConfig.numChannels", "Connection::GetChannelErrorLevel" );
        return this.m_channel[channelIndex]!.GetErrorLevel();
    }

    /**
        Process acked packet sequences.
        @param acks The acked packet sequence numbers (uint16).
        @param numAcks The number of acks. Defaults to acks.length.
     */

    ProcessAcks( acks: ArrayLike<number>, numAcks: number = acks.length ): void
    {
        for ( let i = 0; i < numAcks; ++i )
        {
            for ( let channelIndex = 0; channelIndex < this.m_connectionConfig.numChannels; ++channelIndex )
            {
                this.m_channel[channelIndex]!.ProcessAck( acks[i] );
            }
        }
    }

    AdvanceTime( time: number ): void
    {
        for ( let i = 0; i < this.m_connectionConfig.numChannels; ++i )
        {
            const channel = this.m_channel[i]!;

            channel.AdvanceTime( time );

            if ( channel.GetErrorLevel() !== CHANNEL_ERROR_NONE )
            {
                this.m_errorLevel = CONNECTION_ERROR_CHANNEL;
                return;
            }
        }
        if ( this.m_allocator!.GetErrorLevel() !== ALLOCATOR_ERROR_NONE )
        {
            this.m_errorLevel = CONNECTION_ERROR_ALLOCATOR;
            return;
        }
        if ( this.m_messageFactory.GetErrorLevel() !== MESSAGE_FACTORY_ERROR_NONE )
        {
            this.m_errorLevel = CONNECTION_ERROR_MESSAGE_FACTORY;
            return;
        }
    }

    GetErrorLevel(): ConnectionErrorLevel
    {
        return this.m_errorLevel;
    }
}

function WritePacket( context: unknown,
                      messageFactory: MessageFactory,
                      connectionConfig: ConnectionConfig,
                      packet: ConnectionPacket,
                      buffer: Uint8Array,
                      bufferSize: number ): number
{
    const stream = new WriteStream( buffer, bufferSize );

    stream.SetContext( context );

    stream.SetAllocator( messageFactory.GetAllocator() );

    if ( !packet.SerializeInternal( stream, messageFactory, connectionConfig ) )
    {
        yojimbo_printf( YOJIMBO_LOG_LEVEL_ERROR, "error: serialize connection packet failed (write packet)\n" );
        return 0;
    }

    stream.Flush();

    return stream.GetBytesProcessed();
}

function ReadPacket( context: unknown,
                     messageFactory: MessageFactory,
                     connectionConfig: ConnectionConfig,
                     packet: ConnectionPacket,
                     buffer: Uint8Array,
                     bufferSize: number ): boolean
{
    yojimbo_assert( buffer, "buffer", "ReadPacket" );
    yojimbo_assert( bufferSize > 0, "bufferSize > 0", "ReadPacket" );

    const stream = new ReadStream( buffer, bufferSize );

    stream.SetContext( context );

    stream.SetAllocator( messageFactory.GetAllocator() );

    if ( !packet.SerializeInternal( stream, messageFactory, connectionConfig ) )
    {
        yojimbo_printf( YOJIMBO_LOG_LEVEL_ERROR, "error: serialize connection packet failed (read packet)\n" );
        return false;
    }

    return true;
}
