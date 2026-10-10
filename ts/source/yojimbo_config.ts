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
    TypeScript port of include/yojimbo_config.h + source/yojimbo_config.cpp (yojimbo 1.13.5).

    Port notes:
      - C++ copies config structs by value and the library keeps private copies. Here the config classes have
        Clone() (deep, including the channel array), and Connection / channels clone what they are given.
      - The float32 fields (messageResendTime, blockFragmentResendTime, rttSmoothingFactor) default to their float32
        values (Math.fround( 0.1 ) etc.) so time comparisons round exactly as upstream; the channels round whatever
        is set with Math.fround when they copy the config.
      - protocolId is uint64 on the wire, so it is a bigint.
      - Validate() is the YOJIMBO_DEBUG validation: each check prints what is wrong, then asserts. With asserts
        disabled (yojimbo_set_asserts_enabled( false ), the release build) nothing is checked, as upstream.
*/

import { MaxChannels, DefaultMaxConnectTokenLifetime } from '../include/yojimbo_constants.ts';
import { yojimbo_assert, yojimbo_get_asserts_enabled, yojimbo_printf, YOJIMBO_LOG_LEVEL_ERROR } from './yojimbo_platform.ts';

export const YOJIMBO_MAJOR_VERSION = 1;
export const YOJIMBO_MINOR_VERSION = 13;
export const YOJIMBO_PATCH_VERSION = 5;

export const YOJIMBO_DEFAULT_TIMEOUT = 10;

/** Message leak tracking in MessageFactory (upstream: on in YOJIMBO_DEBUG builds). */
export const YOJIMBO_DEBUG_MESSAGE_LEAKS = true;

/** Packet budget asserts on the write path (upstream: on in YOJIMBO_DEBUG builds). */
export const YOJIMBO_DEBUG_MESSAGE_BUDGET = true;

/// Determines the reliability and ordering guarantees for a channel.
export const CHANNEL_TYPE_RELIABLE_ORDERED = 0;                  ///< Messages are received reliably and in the same order they were sent.
export const CHANNEL_TYPE_UNRELIABLE_UNORDERED = 1;              ///< Messages are sent unreliably. Messages may arrive out of order, or not at all.

export type ChannelType = typeof CHANNEL_TYPE_RELIABLE_ORDERED | typeof CHANNEL_TYPE_UNRELIABLE_UNORDERED;

/**
    Configuration properties for a message channel.

    Channels let you specify different reliability and ordering guarantees for messages sent across a connection.

    They may be configured as one of two types: reliable-ordered or unreliable-unordered.

    Reliable ordered channels guarantee that messages (see Message) are received reliably and in the same order they were sent.
    This channel type is designed for control messages and RPCs sent between the client and server.

    Unreliable unordered channels are like UDP. There is no guarantee that messages will arrive, and messages may arrive out of order.
    This channel type is designed for data that is time critical and should not be resent if dropped, like snapshots of world state sent rapidly
    from server to client, or cosmetic events such as effects and sounds.

    Both channel types support blocks of data attached to messages (see BlockMessage), but their treatment of blocks is quite different.

    Reliable ordered channels are designed for blocks that must be received reliably and in-order with the rest of the messages sent over the channel.
    These blocks are sent by splitting them into fragments and resending each fragment until the other side has received the entire block.

    Unreliable-unordered channels send blocks as-is without splitting them up into fragments, so the maximum block size for an
    unreliable-unordered channel must fit within the maximum packet size.

    Channels are typically configured as part of a ConnectionConfig, which is included inside the ClientServerConfig that is passed into the Client and Server constructors.
 */

export class ChannelConfig
{
    type: ChannelType = CHANNEL_TYPE_RELIABLE_ORDERED;          ///< Channel type: reliable-ordered or unreliable-unordered.
    disableBlocks = false;                                      ///< Disables blocks being sent across this channel.
    sentPacketBufferSize = 1024;                                ///< Number of packet entries in the sent packet sequence buffer. Please consider your packet send rate and make sure you have at least a few seconds worth of entries in this buffer.
    messageSendQueueSize = 1024;                                ///< Number of messages in the send queue for this channel.
    messageReceiveQueueSize = 1024;                             ///< Number of messages in the receive queue for this channel.
    maxMessagesPerPacket = 256;                                 ///< Maximum number of messages to include in each packet. Will write up to this many messages, provided the messages fit into the channel packet budget and the number of bytes remaining in the packet.
    packetBudget = -1;                                          ///< Maximum amount of message data to write to the packet for this channel (bytes). Specifying -1 means the channel can use up to the rest of the bytes remaining in the packet.
    maxBlockSize = 256 * 1024;                                  ///< The size of the largest block that can be sent across this channel (bytes).
    blockFragmentSize = 1024;                                   ///< Blocks are split up into fragments of this size (bytes). Reliable-ordered channel only.
    messageResendTime = Math.fround( 0.1 );                     ///< Minimum delay between message resends (seconds, float32). Avoids sending the same message too frequently. Reliable-ordered channel only.
    blockFragmentResendTime = Math.fround( 0.25 );              ///< Minimum delay between block fragment resends (seconds, float32). Avoids sending the same fragment too frequently. Reliable-ordered channel only.
    allocateBlocksOnDemand = false;                             ///< Port addition (not in upstream): allocate the block receive buffer when a block starts arriving, sized to that block, and free it once delivered, instead of reserving maxBlockSize per connection when the channel is created. Lets a server raise maxBlockSize without reserving it for every client. Local only, not on the wire. Reliable-ordered channel only.

    /**
        The number of fragments a block of maxBlockSize is split into: ceil( maxBlockSize / blockFragmentSize ).
        Rounds up, so the send-side fragment buffers are sized for a final partial fragment. Computed without overflow
        and clamped to [0,2^31-1] like upstream's 64 bit computation (yojimbo#347).
        NOTE: this value sets the bit width of numFragments on the wire, so it must match the peer.
     */

    GetMaxFragmentsPerBlock(): number
    {
        if ( this.blockFragmentSize <= 0 )
            return 0;
        // integer ceil division in the 64 bit domain (values are int32, so the result is exact in a double)
        const n = Math.floor( ( this.maxBlockSize + this.blockFragmentSize - 1 ) / this.blockFragmentSize );
        if ( n > 2147483647 )
            return 2147483647;
        if ( n < 0 )
            return 0;
        return n;
    }

    /**
        Validate this channel configuration.
        Asserts (debug build only) on invariants the channel implementations rely on,
        so an invalid channel config fails loudly at startup rather than corrupting channel state at runtime.
        Called for each channel by ConnectionConfig::Validate.
        @param channelIndex The index of this channel in the connection config. Used for error reporting.
        @param maxPacketSize The maximum packet size from the connection config (bytes).
     */

    Validate( channelIndex: number, maxPacketSize: number ): void
    {
        if ( !yojimbo_get_asserts_enabled() )
            return;

        YOJIMBO_CONFIG_CHECK( this.messageSendQueueSize > 0, "messageSendQueueSize > 0",
            "error: invalid config: channel %d messageSendQueueSize (%d) must be > 0\n", channelIndex, this.messageSendQueueSize );

        YOJIMBO_CONFIG_CHECK( this.messageReceiveQueueSize > 0, "messageReceiveQueueSize > 0",
            "error: invalid config: channel %d messageReceiveQueueSize (%d) must be > 0\n", channelIndex, this.messageReceiveQueueSize );

        YOJIMBO_CONFIG_CHECK( this.maxMessagesPerPacket > 0, "maxMessagesPerPacket > 0",
            "error: invalid config: channel %d maxMessagesPerPacket (%d) must be > 0\n", channelIndex, this.maxMessagesPerPacket );

        if ( !this.disableBlocks )
        {
            YOJIMBO_CONFIG_CHECK( this.maxBlockSize > 0, "maxBlockSize > 0",
                "error: invalid config: channel %d maxBlockSize (%d) must be > 0\n", channelIndex, this.maxBlockSize );
        }

        if ( this.type === CHANNEL_TYPE_RELIABLE_ORDERED )
        {
            // The reliable-ordered channel stores its state in sequence buffers indexed by
            // sequence % size, which only works when the size divides 65536 (ie. a power of two).
            // Any other size aliases sequence numbers and corrupts channel state.

            YOJIMBO_CONFIG_CHECK( this.sentPacketBufferSize > 0, "sentPacketBufferSize > 0",
                "error: invalid config: channel %d sentPacketBufferSize (%d) must be > 0\n", channelIndex, this.sentPacketBufferSize );

            YOJIMBO_CONFIG_CHECK( ( 65536 % this.sentPacketBufferSize ) === 0, "( 65536 % sentPacketBufferSize ) == 0",
                "error: invalid config: channel %d sentPacketBufferSize (%d) must be a power of two\n", channelIndex, this.sentPacketBufferSize );

            YOJIMBO_CONFIG_CHECK( ( 65536 % this.messageSendQueueSize ) === 0, "( 65536 % messageSendQueueSize ) == 0",
                "error: invalid config: channel %d messageSendQueueSize (%d) must be a power of two\n", channelIndex, this.messageSendQueueSize );

            YOJIMBO_CONFIG_CHECK( ( 65536 % this.messageReceiveQueueSize ) === 0, "( 65536 % messageReceiveQueueSize ) == 0",
                "error: invalid config: channel %d messageReceiveQueueSize (%d) must be a power of two\n", channelIndex, this.messageReceiveQueueSize );

            if ( !this.disableBlocks )
            {
                YOJIMBO_CONFIG_CHECK( this.blockFragmentSize > 0, "blockFragmentSize > 0",
                    "error: invalid config: channel %d blockFragmentSize (%d) must be > 0\n", channelIndex, this.blockFragmentSize );

                // On the wire fragmentSize is a 16-bit field (yojimbo#346).
                YOJIMBO_CONFIG_CHECK( this.blockFragmentSize <= 65535, "blockFragmentSize <= 65535",
                    "error: invalid config: channel %d blockFragmentSize (%d) must be <= 65535\n", channelIndex, this.blockFragmentSize );

                // A block fragment must fit inside a packet, or the channel stalls forever trying
                // to send the block (see ReliableOrderedChannel::GetPacketData).
                YOJIMBO_CONFIG_CHECK( this.blockFragmentSize <= maxPacketSize, "blockFragmentSize <= maxPacketSize",
                    "error: invalid config: channel %d blockFragmentSize (%d) must be <= maxPacketSize (%d)\n", channelIndex, this.blockFragmentSize, maxPacketSize );

                // Fragment id 0xFFFF is reserved as a sentinel (see GetFragmentToSend).
                YOJIMBO_CONFIG_CHECK( this.GetMaxFragmentsPerBlock() <= 65535, "GetMaxFragmentsPerBlock() <= 65535",
                    "error: invalid config: channel %d maxBlockSize (%d) / blockFragmentSize (%d) gives too many fragments per block (max 65535)\n", channelIndex, this.maxBlockSize, this.blockFragmentSize );
            }
        }
    }

    /** Copy this channel config (C++ copies config structs by value). */

    Clone(): ChannelConfig
    {
        return Object.assign( new ChannelConfig(), this );
    }
}

/**
    Configures connection properties and the set of channels for sending and receiving messages.
    Specifies the maximum packet size to generate, and the number of message channels, and the per-channel configuration data. See ChannelConfig for details.
    Typically configured as part of a ClientServerConfig which is passed into Client and Server constructors.
 */

export class ConnectionConfig
{
    numChannels = 2;                                            ///< Number of message channels in [1,MaxChannels]. Each message channel must have a corresponding configuration below.
    maxPacketSize = 8 * 1024;                                   ///< The maximum size of packets generated to transmit messages between client and server (bytes).
    channel: ChannelConfig[];                                   ///< Per-channel configuration (MaxChannels entries). See ChannelConfig for details.

    constructor()
    {
        this.channel = new Array<ChannelConfig>( MaxChannels );
        for ( let i = 0; i < MaxChannels; ++i )
            this.channel[i] = new ChannelConfig();
        this.channel[0].type = CHANNEL_TYPE_RELIABLE_ORDERED;
    }

    /**
        Validate this connection configuration.
        Asserts (debug build only) on invariants the connection and channels rely on,
        so an invalid config fails loudly at startup rather than corrupting state at runtime.
        IMPORTANT: The connection config must be identical on the client and the server. This validates each side
        locally — keeping the two sides in sync is your responsibility.
     */

    Validate(): void
    {
        if ( !yojimbo_get_asserts_enabled() )
            return;

        YOJIMBO_CONFIG_CHECK( this.numChannels >= 1 && this.numChannels <= MaxChannels, "numChannels >= 1 && numChannels <= MaxChannels",
            "error: invalid config: numChannels (%d) must be in [1,%d]\n", this.numChannels, MaxChannels );

        YOJIMBO_CONFIG_CHECK( this.maxPacketSize > 0, "maxPacketSize > 0",
            "error: invalid config: maxPacketSize (%d) must be > 0\n", this.maxPacketSize );

        for ( let i = 0; i < this.numChannels; ++i )
        {
            this.channel[i].Validate( i, this.maxPacketSize );
        }
    }

    /** Deep copy (including the channel array), keeping the class (a ClientServerConfig clones to a ClientServerConfig). */

    Clone(): this
    {
        const copy = Object.assign( Object.create( Object.getPrototypeOf( this ) as object ) as this, this );
        copy.channel = this.channel.map( ( channel ) => channel.Clone() );
        return copy;
    }
}

/**
    Configuration shared between client and server.
    Passed to Client and Server constructors to configure their behavior.
    Please make sure that the message configuration is identical between client and server.
 */

export class ClientServerConfig extends ConnectionConfig
{
    protocolId = 0n;                                            ///< Clients can only connect to servers with the same protocol id. Use this for versioning (uint64).
    timeout = YOJIMBO_DEFAULT_TIMEOUT;                          ///< Timeout value in seconds. Set to negative value to disable timeouts (for debugging only).
    clientMemory = 10 * 1024 * 1024;                            ///< Memory allocated inside Client for packets, messages and stream allocations (bytes)
    serverGlobalMemory = 10 * 1024 * 1024;                      ///< Memory allocated inside Server for global connection request and challenge response packets (bytes)
    serverPerClientMemory = 10 * 1024 * 1024;                   ///< Memory allocated inside Server for packets, messages and stream allocations per-client (bytes)
    networkSimulator = true;                                    ///< If true then a network simulator is created for simulating latency, jitter, packet loss and duplicates.
    maxSimulatorPackets = 4 * 1024;                             ///< Maximum number of packets that can be stored in the network simulator. Additional packets are dropped.
    fragmentPacketsAbove = 1024;                                ///< Packets above this size (bytes) are split apart into fragments and reassembled on the other side.
    packetFragmentSize = 1024;                                  ///< Size of each packet fragment (bytes).
    maxPacketFragments: number;                                 ///< Maximum number of fragments a packet can be split up into.
    packetReassemblyBufferSize = 64;                            ///< Number of packet entries in the fragmentation reassembly buffer.
    ackedPacketsBufferSize = 256;                               ///< Number of packet entries in the acked packet buffer. Consider your packet send rate and aim to have at least a few seconds worth of entries.
    receivedPacketsBufferSize = 256;                            ///< Number of packet entries in the received packet sequence buffer. Consider your packet send rate and aim to have at least a few seconds worth of entries.
    rttSmoothingFactor = Math.fround( 0.0025 );                 ///< Round-Trip Time (RTT) smoothing factor over time (float32).
    maxConnectTokenLifetime = DefaultMaxConnectTokenLifetime;   ///< The longest lifetime in seconds your backend issues connect tokens with. Server only. The server refuses any connect token whose expiry, minus this lifetime, is earlier than the time the server started, so a token that could have been issued before a restart cannot be presented after it. Set it to the lifetime your matchmaker actually issues. Zero or less takes DefaultMaxConnectTokenLifetime.

    constructor()
    {
        super();
        this.maxPacketFragments = Math.ceil( this.maxPacketSize / this.packetFragmentSize );
    }

    /**
        Validate this client/server configuration.
        Asserts (debug build only) on invariants the client and server rely on,
        so an invalid config fails loudly at startup rather than misbehaving at runtime.
        Called automatically by Server::Start and when the client connects. You can also call it directly.
        IMPORTANT: If you increase maxPacketSize after construction, you must also update maxPacketFragments,
        because it is derived from maxPacketSize inside the ClientServerConfig constructor. This is one of the
        things validated here.
     */

    override Validate(): void
    {
        if ( !yojimbo_get_asserts_enabled() )
            return;

        super.Validate();

        YOJIMBO_CONFIG_CHECK( this.clientMemory > 0, "clientMemory > 0",
            "error: invalid config: clientMemory (%d) must be > 0\n", this.clientMemory );

        YOJIMBO_CONFIG_CHECK( this.serverGlobalMemory > 0, "serverGlobalMemory > 0",
            "error: invalid config: serverGlobalMemory (%d) must be > 0\n", this.serverGlobalMemory );

        YOJIMBO_CONFIG_CHECK( this.serverPerClientMemory > 0, "serverPerClientMemory > 0",
            "error: invalid config: serverPerClientMemory (%d) must be > 0\n", this.serverPerClientMemory );

        if ( this.networkSimulator )
        {
            YOJIMBO_CONFIG_CHECK( this.maxSimulatorPackets > 0, "maxSimulatorPackets > 0",
                "error: invalid config: maxSimulatorPackets (%d) must be > 0\n", this.maxSimulatorPackets );
        }

        YOJIMBO_CONFIG_CHECK( this.packetFragmentSize > 0, "packetFragmentSize > 0",
            "error: invalid config: packetFragmentSize (%d) must be > 0\n", this.packetFragmentSize );

        YOJIMBO_CONFIG_CHECK( this.fragmentPacketsAbove > 0, "fragmentPacketsAbove > 0",
            "error: invalid config: fragmentPacketsAbove (%d) must be > 0\n", this.fragmentPacketsAbove );

        // maxPacketFragments is derived from maxPacketSize inside the ClientServerConfig
        // constructor, which runs *before* your code adjusts any fields. If you increase
        // maxPacketSize you must update maxPacketFragments too, otherwise packets larger than
        // packetFragmentSize * maxPacketFragments cannot be fragmented and are dropped.
        const neededPacketFragments = Math.ceil( this.maxPacketSize / this.packetFragmentSize );

        YOJIMBO_CONFIG_CHECK( this.maxPacketFragments >= neededPacketFragments, "maxPacketFragments >= neededPacketFragments",
            "error: invalid config: maxPacketFragments (%d) is too small for maxPacketSize (%d) with packetFragmentSize (%d). It must be at least %d.\n" +
            "maxPacketFragments is computed in the ClientServerConfig constructor, so if you increase maxPacketSize afterwards, update maxPacketFragments as well\n",
            this.maxPacketFragments, this.maxPacketSize, this.packetFragmentSize, neededPacketFragments );

        // The reliable endpoint encodes (num fragments - 1) as a uint8_t and asserts max_fragments <= 256.
        YOJIMBO_CONFIG_CHECK( this.maxPacketFragments <= 256, "maxPacketFragments <= 256",
            "error: invalid config: maxPacketFragments (%d) must be <= 256\n", this.maxPacketFragments );

        YOJIMBO_CONFIG_CHECK( this.packetReassemblyBufferSize > 0, "packetReassemblyBufferSize > 0",
            "error: invalid config: packetReassemblyBufferSize (%d) must be > 0\n", this.packetReassemblyBufferSize );

        YOJIMBO_CONFIG_CHECK( this.ackedPacketsBufferSize > 0, "ackedPacketsBufferSize > 0",
            "error: invalid config: ackedPacketsBufferSize (%d) must be > 0\n", this.ackedPacketsBufferSize );

        YOJIMBO_CONFIG_CHECK( this.receivedPacketsBufferSize > 0, "receivedPacketsBufferSize > 0",
            "error: invalid config: receivedPacketsBufferSize (%d) must be > 0\n", this.receivedPacketsBufferSize );
    }
}

/**
    Print what is wrong with the config (with the offending values), then assert.
    Debug build only: config validation follows the library-wide contract that asserts enforce correct usage in debug.
 */

function YOJIMBO_CONFIG_CHECK( condition: boolean, condition_text: string, format: string, ...args: unknown[] ): void
{
    if ( !condition )
    {
        yojimbo_printf( YOJIMBO_LOG_LEVEL_ERROR, format, ...args );
        yojimbo_assert( condition, condition_text, "Validate" );
    }
}
