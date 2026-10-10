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
    public static partial class yojimbo
    {
        public const int MAJOR_VERSION = 1;
        public const int MINOR_VERSION = 13;
        public const int PATCH_VERSION = 5;

        public const int DEFAULT_TIMEOUT = 10;

    }

    /// Determines the reliability and ordering guarantees for a channel.
    public enum ChannelType
    {
        CHANNEL_TYPE_RELIABLE_ORDERED,                                          ///< Messages are received reliably and in the same order they were sent. 
        CHANNEL_TYPE_UNRELIABLE_UNORDERED                                       ///< Messages are sent unreliably. Messages may arrive out of order, or not at all.
    }

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
        Examples of these sort of blocks include the initial state of a level, or server configuration data sent down to a client on connect. These blocks 
        are sent by splitting them into fragments and resending each fragment until the other side has received the entire block. This allows for sending
        blocks of data larger that maximum packet size quickly and reliably even under packet loss.
        
        Unreliable-unordered channels send blocks as-is without splitting them up into fragments. The idea is that transport level packet fragmentation
        should be used on top of the generated packet to split it up into into smaller packets that can be sent across typical Internet MTU (<1500 bytes). 
        Because of this, you need to make sure that the maximum block size for an unreliable-unordered channel fits within the maximum packet size.
        
        Channels are typically configured as part of a ConnectionConfig, which is included inside the ClientServerConfig that is passed into the Client and Server constructors.
     */
    public class ChannelConfig
    {
        public ChannelType type = ChannelType.CHANNEL_TYPE_RELIABLE_ORDERED;    ///< Channel type: reliable-ordered or unreliable-unordered.
        public bool disableBlocks = false;                                      ///< Disables blocks being sent across this channel.
        public int sentPacketBufferSize = 1024;                                 ///< Number of packet entries in the sent packet sequence buffer. Please consider your packet send rate and make sure you have at least a few seconds worth of entries in this buffer.
        public int messageSendQueueSize = 1024;                                 ///< Number of messages in the send queue for this channel.
        public int messageReceiveQueueSize = 1024;                              ///< Number of messages in the receive queue for this channel.
        public int maxMessagesPerPacket = 256;                                  ///< Maximum number of messages to include in each packet. Will write up to this many messages, provided the messages fit into the channel packet budget and the number of bytes remaining in the packet.
        public int packetBudget = -1;                                           ///< Maximum amount of message data to write to the packet for this channel (bytes). Specifying -1 means the channel can use up to the rest of the bytes remaining in the packet.
        public int maxBlockSize = 256 * 1024;                                   ///< The size of the largest block that can be sent across this channel (bytes).
        public int blockFragmentSize = 1024;                                    ///< Blocks are split up into fragments of this size (bytes). Reliable-ordered channel only.
        public float messageResendTime = 0.1f;                                  ///< Minimum delay between message resends (seconds). Avoids sending the same message too frequently. Reliable-ordered channel only.
        public float blockFragmentResendTime = 0.25f;                           ///< Minimum delay between block fragment resends (seconds). Avoids sending the same fragment too frequently. Reliable-ordered channel only.
        public bool allocateBlocksOnDemand = false;                             ///< Port addition (not in upstream): allocate the block receive buffer when a block starts arriving, sized to that block, and free it once delivered, instead of reserving maxBlockSize per connection when the channel is created. Lets a server raise maxBlockSize without reserving it for every client. Local only, not on the wire. Reliable-ordered channel only.

        /**
            The maximum number of fragments a block can be split into: ceil(maxBlockSize / blockFragmentSize).
            Rounds up: a block of maxBlockSize needs ceil(maxBlockSize/blockFragmentSize) fragments. Using floor here
            under-sizes the send-side fragment buffers when maxBlockSize is not a multiple of blockFragmentSize (760ebc2).
            The add is 64-bit so a legal huge maxBlockSize cannot overflow before the 65535 check in Validate (yojimbo#347).
            NOTE: this value sets the bit width of numFragments on the wire, so it must match the peer.
         */
        public int MaxFragmentsPerBlock => GetMaxFragmentsPerBlock();

        public int GetMaxFragmentsPerBlock()
        {
            if (blockFragmentSize <= 0)
                return 0;
            var n = ((long)maxBlockSize + blockFragmentSize - 1) / blockFragmentSize;
            if (n > int.MaxValue)
                return int.MaxValue;
            if (n < 0)
                return 0;
            return (int)n;
        }

        /**
            Validate this channel configuration.
            Asserts (debug builds only) on invariants the channel implementations rely on,
            so an invalid channel config fails loudly at startup rather than corrupting channel state at runtime.
            Called for each channel by ConnectionConfig.Validate.
         */
        public void Validate(int channelIndex, int maxPacketSize)
        {
            yojimbo.CONFIG_CHECK(messageSendQueueSize > 0, $"error: invalid config: channel {channelIndex} messageSendQueueSize ({messageSendQueueSize}) must be > 0\n");
            yojimbo.CONFIG_CHECK(messageReceiveQueueSize > 0, $"error: invalid config: channel {channelIndex} messageReceiveQueueSize ({messageReceiveQueueSize}) must be > 0\n");
            yojimbo.CONFIG_CHECK(maxMessagesPerPacket > 0, $"error: invalid config: channel {channelIndex} maxMessagesPerPacket ({maxMessagesPerPacket}) must be > 0\n");
            if (!disableBlocks)
                yojimbo.CONFIG_CHECK(maxBlockSize > 0, $"error: invalid config: channel {channelIndex} maxBlockSize ({maxBlockSize}) must be > 0\n");
            if (type == ChannelType.CHANNEL_TYPE_RELIABLE_ORDERED)
            {
                // The reliable-ordered channel stores its state in sequence buffers indexed by
                // sequence % size, which only works when the size divides 65536 (ie. a power of two).
                yojimbo.CONFIG_CHECK(sentPacketBufferSize > 0, $"error: invalid config: channel {channelIndex} sentPacketBufferSize ({sentPacketBufferSize}) must be > 0\n");
                yojimbo.CONFIG_CHECK(sentPacketBufferSize > 0 && (65536 % sentPacketBufferSize) == 0, $"error: invalid config: channel {channelIndex} sentPacketBufferSize ({sentPacketBufferSize}) must be a power of two\n");
                yojimbo.CONFIG_CHECK(messageSendQueueSize > 0 && (65536 % messageSendQueueSize) == 0, $"error: invalid config: channel {channelIndex} messageSendQueueSize ({messageSendQueueSize}) must be a power of two\n");
                yojimbo.CONFIG_CHECK(messageReceiveQueueSize > 0 && (65536 % messageReceiveQueueSize) == 0, $"error: invalid config: channel {channelIndex} messageReceiveQueueSize ({messageReceiveQueueSize}) must be a power of two\n");
                if (!disableBlocks)
                {
                    yojimbo.CONFIG_CHECK(blockFragmentSize > 0, $"error: invalid config: channel {channelIndex} blockFragmentSize ({blockFragmentSize}) must be > 0\n");
                    // On the wire fragmentSize is a 16-bit field (yojimbo#346).
                    yojimbo.CONFIG_CHECK(blockFragmentSize <= 65535, $"error: invalid config: channel {channelIndex} blockFragmentSize ({blockFragmentSize}) must be <= 65535\n");
                    // A block fragment must fit inside a packet, or the channel stalls forever trying to send the block.
                    yojimbo.CONFIG_CHECK(blockFragmentSize <= maxPacketSize, $"error: invalid config: channel {channelIndex} blockFragmentSize ({blockFragmentSize}) must be <= maxPacketSize ({maxPacketSize})\n");
                    // Fragment id 0xFFFF is reserved as a sentinel (see GetFragmentToSend).
                    yojimbo.CONFIG_CHECK(GetMaxFragmentsPerBlock() <= 65535, $"error: invalid config: channel {channelIndex} maxBlockSize ({maxBlockSize}) / blockFragmentSize ({blockFragmentSize}) gives too many fragments per block (max 65535)\n");
                }
            }
        }

        /// Copy this channel config. C++ copies config structs by value; the library keeps private copies.
        public ChannelConfig Clone() => (ChannelConfig)MemberwiseClone();
    }

    /** 
        Configures connection properties and the set of channels for sending and receiving messages.
        Specifies the maximum packet size to generate, and the number of message channels, and the per-channel configuration data. See ChannelConfig for details.
        Typically configured as part of a ClientServerConfig which is passed into Client and Server constructors.
     */
    public class ConnectionConfig
    {
        public int numChannels = 2;                                             ///< Number of message channels in [1,MaxChannels]. Each message channel must have a corresponding configuration below.
        public int maxPacketSize = 8 * 1024;                                    ///< The maximum size of packets generated to transmit messages between client and server (bytes).
        public ChannelConfig[] channel = NewChannelConfigs();                   ///< Per-channel configuration. See ChannelConfig for details.

        static ChannelConfig[] NewChannelConfigs()
        {
            var channel = new ChannelConfig[yojimbo.MaxChannels];
            for (var i = 0; i < channel.Length; ++i)
                channel[i] = new ChannelConfig();
            channel[0].type = ChannelType.CHANNEL_TYPE_RELIABLE_ORDERED;
            return channel;
        }

        /**
            Validate this connection configuration.
            Asserts (debug builds only) on invariants the connection and channels rely on,
            so an invalid config fails loudly at startup rather than corrupting state at runtime.
            IMPORTANT: The connection config must be identical on the client and the server. This validates each side
            locally — keeping the two sides in sync is your responsibility.
         */
        public void Validate()
        {
            yojimbo.CONFIG_CHECK(numChannels >= 1 && numChannels <= yojimbo.MaxChannels, $"error: invalid config: numChannels ({numChannels}) must be in [1,{yojimbo.MaxChannels}]\n");
            yojimbo.CONFIG_CHECK(maxPacketSize > 0, $"error: invalid config: maxPacketSize ({maxPacketSize}) must be > 0\n");
            for (var i = 0; i < numChannels && i < channel.Length; ++i)
                channel[i].Validate(i, maxPacketSize);
        }

        /// Deep copy (including the channel array). C++ copies config structs by value; the library keeps private copies.
        public ConnectionConfig Clone()
        {
            var copy = (ConnectionConfig)MemberwiseClone();
            copy.channel = new ChannelConfig[channel.Length];
            for (var i = 0; i < channel.Length; ++i)
                copy.channel[i] = channel[i].Clone();
            return copy;
        }
    }

    /** 
        Configuration shared between client and server.
        Passed to Client and Server constructors to configure their behavior.
        Please make sure that the message configuration is identical between client and server.
     */
    public class ClientServerConfig : ConnectionConfig
    {
        public ulong protocolId = 0;                                            ///< Clients can only connect to servers with the same protocol id. Use this for versioning.
        public int timeout = yojimbo.DEFAULT_TIMEOUT;                           ///< Timeout value in seconds. Set to negative value to disable timeouts (for debugging only).
        public int clientMemory = 10 * 1024 * 1024;                             ///< Memory allocated inside Client for packets, messages and stream allocations (bytes). NOTE: the C# port allocates from the GC; this is the byte budget of the client allocator (see TLSF_Allocator).
        public int serverGlobalMemory = 10 * 1024 * 1024;                       ///< Memory allocated inside Server for global connection request and challenge response packets (bytes). See note on clientMemory.
        public int serverPerClientMemory = 10 * 1024 * 1024;                    ///< Memory allocated inside Server for packets, messages and stream allocations per-client (bytes). See note on clientMemory.
        public bool networkSimulator = true;                                    ///< If true then a network simulator is created for simulating latency, jitter, packet loss and duplicates.
        public int maxSimulatorPackets = 4 * 1024;                              ///< Maximum number of packets that can be stored in the network simulator. Additional packets are dropped.
        public int fragmentPacketsAbove = 1024;                                 ///< Packets above this size (bytes) are split apart into fragments and reassembled on the other side.
        public int packetFragmentSize = 1024;                                   ///< Size of each packet fragment (bytes).
        public int maxPacketFragments;                                          ///< Maximum number of fragments a packet can be split up into.
        public int packetReassemblyBufferSize = 64;                             ///< Number of packet entries in the fragmentation reassembly buffer.
        public int ackedPacketsBufferSize = 256;                                ///< Number of packet entries in the acked packet buffer. Consider your packet send rate and aim to have at least a few seconds worth of entries.
        public int receivedPacketsBufferSize = 256;                             ///< Number of packet entries in the received packet sequence buffer. Consider your packet send rate and aim to have at least a few seconds worth of entries.
        public float rttSmoothingFactor = 0.0025f;                              ///< Round-Trip Time (RTT) smoothing factor over time.
        public int maxConnectTokenLifetime = yojimbo.DefaultMaxConnectTokenLifetime; ///< The longest lifetime in seconds your backend issues connect tokens with. Server only. The server refuses any connect token whose expiry, minus this lifetime, is earlier than the time the server started. Set it to the lifetime your matchmaker actually issues (45 for the bundled matcher). Zero or less takes DefaultMaxConnectTokenLifetime.

        public ClientServerConfig()
        {
            maxPacketFragments = (int)Math.Ceiling(maxPacketSize / (double)packetFragmentSize);
        }

        /**
            Validate this client/server configuration.
            Asserts (debug builds only) on invariants the client and server rely on,
            so an invalid config fails loudly at startup rather than misbehaving at runtime.
            Called automatically by Server.Start and when the client connects. You can also call it directly.
            IMPORTANT: If you increase maxPacketSize after construction, you must also update maxPacketFragments,
            because it is derived from maxPacketSize inside the ClientServerConfig constructor. This is one of the
            things validated here.
         */
        public new void Validate()
        {
            base.Validate();
            yojimbo.CONFIG_CHECK(clientMemory > 0, $"error: invalid config: clientMemory ({clientMemory}) must be > 0\n");
            yojimbo.CONFIG_CHECK(serverGlobalMemory > 0, $"error: invalid config: serverGlobalMemory ({serverGlobalMemory}) must be > 0\n");
            yojimbo.CONFIG_CHECK(serverPerClientMemory > 0, $"error: invalid config: serverPerClientMemory ({serverPerClientMemory}) must be > 0\n");
            if (networkSimulator)
                yojimbo.CONFIG_CHECK(maxSimulatorPackets > 0, $"error: invalid config: maxSimulatorPackets ({maxSimulatorPackets}) must be > 0\n");
            yojimbo.CONFIG_CHECK(packetFragmentSize > 0, $"error: invalid config: packetFragmentSize ({packetFragmentSize}) must be > 0\n");
            yojimbo.CONFIG_CHECK(fragmentPacketsAbove > 0, $"error: invalid config: fragmentPacketsAbove ({fragmentPacketsAbove}) must be > 0\n");
            // maxPacketFragments is derived from maxPacketSize inside the ClientServerConfig constructor, which runs *before*
            // your code adjusts any fields. If you increase maxPacketSize you must update maxPacketFragments too.
            var neededPacketFragments = packetFragmentSize > 0 ? (int)Math.Ceiling(maxPacketSize / (double)packetFragmentSize) : 0;
            yojimbo.CONFIG_CHECK(maxPacketFragments >= neededPacketFragments,
                $"error: invalid config: maxPacketFragments ({maxPacketFragments}) is too small for maxPacketSize ({maxPacketSize}) with packetFragmentSize ({packetFragmentSize}). It must be at least {neededPacketFragments}.\n" +
                "maxPacketFragments is computed in the ClientServerConfig constructor, so if you increase maxPacketSize afterwards, update maxPacketFragments as well\n");
            // The reliable endpoint encodes (num fragments - 1) as a byte.
            yojimbo.CONFIG_CHECK(maxPacketFragments <= 256, $"error: invalid config: maxPacketFragments ({maxPacketFragments}) must be <= 256\n");
            yojimbo.CONFIG_CHECK(packetReassemblyBufferSize > 0, $"error: invalid config: packetReassemblyBufferSize ({packetReassemblyBufferSize}) must be > 0\n");
            yojimbo.CONFIG_CHECK(ackedPacketsBufferSize > 0, $"error: invalid config: ackedPacketsBufferSize ({ackedPacketsBufferSize}) must be > 0\n");
            yojimbo.CONFIG_CHECK(receivedPacketsBufferSize > 0, $"error: invalid config: receivedPacketsBufferSize ({receivedPacketsBufferSize}) must be > 0\n");
        }

        /// Deep copy (including the channel array). C++ copies config structs by value; the library keeps private copies.
        public new ClientServerConfig Clone() => (ClientServerConfig)base.Clone();
    }
}

namespace networkprotocol
{
    static partial class yojimbo
    {
        /**
            Print what is wrong with the config (with the offending values), then assert. Debug builds only:
            config validation follows the library-wide contract that asserts enforce correct usage in debug.
         */
        [System.Diagnostics.Conditional("DEBUG")]
        internal static void CONFIG_CHECK(bool condition, string message, [System.Runtime.CompilerServices.CallerArgumentExpression(nameof(condition))] string conditionText = null)
        {
            if (!condition)
            {
                printf(LOG_LEVEL_ERROR, message);
                assert(condition, conditionText);
            }
        }
    }
}
