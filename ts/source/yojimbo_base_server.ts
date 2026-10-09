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
    TypeScript port of include/yojimbo_base_server.h + source/yojimbo_base_server.cpp (yojimbo 1.13.5).

    Port notes:
      - The ServerClientDisconnectReason enum and its string function are declared in yojimbo_server.h upstream (and
        used here). They are defined here and re-exported by yojimbo_server.ts, so the two modules do not import each
        other.
      - The memory blocks backing the global and per-client allocators are not allocated: allocators in the
        TypeScript port are bookkeeping over GC'd blocks, so the adapter's CreateAllocator gets memory = null and the
        budget in bytes (as the C# port). Everything else Start allocates is allocated and checked exactly as upstream,
        and a failure unwinds through Stop.
      - The config is copied (protected m_config, shared with the derived Server, which upstream keeps an identical copy of).
*/

import {
    reliable_config_t, reliable_default_config, reliable_endpoint_create, reliable_endpoint_destroy, reliable_endpoint_reset,
    reliable_endpoint_update, reliable_endpoint_get_acks, reliable_endpoint_clear_acks, type reliable_endpoint_t,
} from '../reliable/reliable.ts';
import type { netcode_address_t } from '../netcode/netcode.ts';
import { MaxClients } from '../include/yojimbo_constants.ts';
import { NetworkInfo } from '../include/yojimbo_network_info.ts';
import type { ServerInterface } from '../include/yojimbo_server_interface.ts';
import type { Adapter } from '../include/yojimbo_adapter.ts';
import { Allocator, YOJIMBO_ALLOCATE, YOJIMBO_FREE, YOJIMBO_NEW, YOJIMBO_DELETE } from './yojimbo_allocator.ts';
import { ClientServerConfig } from './yojimbo_config.ts';
import { Message, BlockMessage, MessageFactory } from './yojimbo_message.ts';
import { Connection, CONNECTION_ERROR_NONE, CONNECTION_ERROR_CHANNEL, CONNECTION_ERROR_ALLOCATOR, CONNECTION_ERROR_MESSAGE_FACTORY, CONNECTION_ERROR_READ_PACKET_FAILED, type ConnectionErrorLevel } from './yojimbo_connection.ts';
import { CHANNEL_ERROR_NONE, CHANNEL_ERROR_DESYNC, CHANNEL_ERROR_SEND_QUEUE_FULL, CHANNEL_ERROR_BLOCKS_DISABLED, CHANNEL_ERROR_FAILED_TO_SERIALIZE, CHANNEL_ERROR_OUT_OF_MEMORY, CHANNEL_ERROR_MESSAGE_TOO_LARGE } from './yojimbo_channel.ts';
import { NetworkSimulator } from './yojimbo_network_simulator.ts';
import { FillNetworkInfo } from './yojimbo_base_client.ts';
import { yojimbo_assert, yojimbo_printf, YOJIMBO_LOG_LEVEL_ERROR } from './yojimbo_platform.ts';

// ---------------------------------------------------------------------------------------------
// ServerClientDisconnectReason (upstream: yojimbo_server.h)

/**
    The reason the client in a server client slot was last disconnected.
    Tracked per-client slot. All slots reset to YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_NONE when the server starts,
    and a slot resets back to NONE when a new client connects to it. The reason is recorded before
    Adapter::OnServerClientDisconnected is called, so you can query it from inside that callback.
 */

export const YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_NONE = 0;                      ///< No client has disconnected from this slot since the server started, or a new client has since connected to this slot.
export const YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_DISCONNECTED = 1;              ///< The client cleanly disconnected. It sent disconnect packets, eg. the player quit.
export const YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_TIMED_OUT = 2;                 ///< The client timed out. We stopped hearing from it, eg. network problem or the client crashed.
export const YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_KICKED = 3;                    ///< Server code called Server::DisconnectClient or Server::DisconnectAllClients for this client.
export const YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_FAILED_TO_SERIALIZE = 4;       ///< A message from this client failed to serialize read. Usually a client/server protocol version mismatch, or a bug in a message serialize function.
export const YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_DESYNC = 5;                    ///< A channel for this client desynced and cannot recover. See CHANNEL_ERROR_DESYNC.
export const YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_SEND_QUEUE_FULL = 6;           ///< A channel send queue for this client filled up. See CHANNEL_ERROR_SEND_QUEUE_FULL.
export const YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_BLOCKS_DISABLED = 7;           ///< This client sent block data on a channel that is configured with blocks disabled.
export const YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_MESSAGE_TOO_LARGE = 8;         ///< A message sent to this client is too large to ever fit into a packet. See CHANNEL_ERROR_MESSAGE_TOO_LARGE.
export const YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_OUT_OF_MEMORY = 9;             ///< The per-client memory budget for this client was exhausted. Consider increasing ClientServerConfig::serverPerClientMemory.
export const YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_READ_PACKET_FAILED = 10;       ///< A connection packet from this client failed to deserialize.

export type ServerClientDisconnectReason = number;

/// Helper function to convert a server client disconnect reason to a user friendly string.
export function GetServerClientDisconnectReasonString( reason: number ): string
{
    switch ( reason )
    {
        case YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_NONE:                  return "none";
        case YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_DISCONNECTED:          return "disconnected";
        case YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_TIMED_OUT:             return "timed out";
        case YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_KICKED:                return "kicked";
        case YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_FAILED_TO_SERIALIZE:   return "failed to serialize";
        case YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_DESYNC:                return "desync";
        case YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_SEND_QUEUE_FULL:       return "send queue full";
        case YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_BLOCKS_DISABLED:       return "blocks disabled";
        case YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_MESSAGE_TOO_LARGE:     return "message too large";
        case YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_OUT_OF_MEMORY:         return "out of memory";
        case YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_READ_PACKET_FAILED:    return "read packet failed";
        default:
            yojimbo_assert( false, "unknown server client disconnect reason", "GetServerClientDisconnectReasonString" );
            return "(unknown)";
    }
}

// ---------------------------------------------------------------------------------------------

// Map the error that drove a connection into an error state to the disconnect reason we
// record for the client slot.
function ClientDisconnectReasonForConnectionError( connection: Connection, errorLevel: ConnectionErrorLevel, numChannels: number ): number
{
    switch ( errorLevel )
    {
        case CONNECTION_ERROR_ALLOCATOR:            return YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_OUT_OF_MEMORY;
        case CONNECTION_ERROR_MESSAGE_FACTORY:      return YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_OUT_OF_MEMORY;
        case CONNECTION_ERROR_READ_PACKET_FAILED:   return YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_READ_PACKET_FAILED;

        case CONNECTION_ERROR_CHANNEL:
        {
            for ( let i = 0; i < numChannels; ++i )
            {
                switch ( connection.GetChannelErrorLevel( i ) )
                {
                    case CHANNEL_ERROR_DESYNC:                  return YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_DESYNC;
                    case CHANNEL_ERROR_SEND_QUEUE_FULL:         return YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_SEND_QUEUE_FULL;
                    case CHANNEL_ERROR_BLOCKS_DISABLED:         return YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_BLOCKS_DISABLED;
                    case CHANNEL_ERROR_FAILED_TO_SERIALIZE:     return YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_FAILED_TO_SERIALIZE;
                    case CHANNEL_ERROR_OUT_OF_MEMORY:           return YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_OUT_OF_MEMORY;
                    case CHANNEL_ERROR_MESSAGE_TOO_LARGE:       return YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_MESSAGE_TOO_LARGE;
                    case CHANNEL_ERROR_NONE:                    break;
                }
            }
        }
        break;

        case CONNECTION_ERROR_NONE:
            break;
    }

    return YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_DISCONNECTED;
}

/**
    Common functionality across all server implementations.
 */

export abstract class BaseServer implements ServerInterface
{
    protected m_config: ClientServerConfig;                             ///< Base client/server config (a private copy).
    private m_allocator: Allocator | null;                              ///< Allocator passed in to constructor.
    private m_adapter: Adapter;                                         ///< The adapter specifies the allocator to use, and the message factory class.
    private m_context: unknown;                                         ///< Optional serialization context.
    private m_maxClients: number;                                       ///< Maximum number of clients supported.
    private m_running: boolean;                                         ///< True if server is currently running, eg. after "Start" is called, before "Stop".
    private m_time: number;                                             ///< Current server time in seconds.
    private m_globalAllocator: Allocator | null;                        ///< The global allocator. Used for allocations that don't belong to a specific client.
    private m_clientAllocator: Array<Allocator | null>;                 ///< Array of per-client allocator. These are used for allocations related to connected clients.
    private m_clientMessageFactory: Array<MessageFactory | null>;       ///< Array of per-client message factories. This silos message allocations per-client slot.
    private m_clientConnection: Array<Connection | null>;               ///< Array of per-client connection classes. This is how messages are exchanged with clients.
    private m_clientEndpoint: Array<reliable_endpoint_t | null>;        ///< Array of per-client reliable endpoints.
    private m_clientDisconnectReason: number[];                         ///< Per-client slot reason the last client in that slot was disconnected (ServerClientDisconnectReason).
    private m_networkSimulator: NetworkSimulator | null;                ///< The network simulator used to simulate packet loss, latency, jitter etc. Optional.
    private m_packetBuffer: Uint8Array | null;                          ///< Buffer used when writing packets.

    constructor( allocator: Allocator, config: ClientServerConfig, adapter: Adapter, time: number )
    {
        this.m_config = config.Clone();
        this.m_allocator = allocator;
        this.m_adapter = adapter;
        this.m_context = null;
        this.m_time = time;
        this.m_running = false;
        this.m_maxClients = 0;
        this.m_globalAllocator = null;
        this.m_clientAllocator = new Array<Allocator | null>( MaxClients ).fill( null );
        this.m_clientMessageFactory = new Array<MessageFactory | null>( MaxClients ).fill( null );
        this.m_clientConnection = new Array<Connection | null>( MaxClients ).fill( null );
        this.m_clientEndpoint = new Array<reliable_endpoint_t | null>( MaxClients ).fill( null );
        this.m_clientDisconnectReason = new Array<number>( MaxClients ).fill( YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_NONE );
        this.m_networkSimulator = null;
        this.m_packetBuffer = null;
    }

    /**
        Base server destructor.
        IMPORTANT: Please stop the server before destroying it!
     */

    Dispose(): void
    {
        yojimbo_assert( !this.IsRunning(), "!IsRunning()", "BaseServer::~BaseServer" );
        this.m_allocator = null;
    }

    SetContext( context: unknown ): void
    {
        yojimbo_assert( !this.IsRunning(), "!IsRunning()", "BaseServer::SetContext" );
        this.m_context = context;
    }

    /**
        Allocate the global and per-client memory the server needs to run.
        Transactional: on the first allocation or adapter factory failure everything already
        created is destroyed, the server is left stopped, and false is returned.
     */

    Start( maxClients: number ): boolean
    {
        yojimbo_assert( maxClients > 0, "maxClients > 0", "BaseServer::Start" );
        yojimbo_assert( maxClients <= MaxClients, "maxClients <= MaxClients", "BaseServer::Start" );

        this.m_config.Validate();

        this.Stop();

        this.m_running = true;
        this.m_maxClients = maxClients;

        for ( let i = 0; i < MaxClients; ++i )
        {
            this.m_clientDisconnectReason[i] = YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_NONE;
        }

        const allocator = this.m_allocator!;
        const config = this.m_config;

        yojimbo_assert( !this.m_globalAllocator, "!m_globalAllocator", "BaseServer::Start" );

        // NOTE: upstream allocates serverGlobalMemory bytes from m_allocator here to back the global allocator (see header).

        this.m_globalAllocator = this.m_adapter.CreateAllocator( allocator, null, config.serverGlobalMemory );
        if ( !this.m_globalAllocator )
        {
            this.Stop();
            return false;
        }

        const globalAllocator = this.m_globalAllocator;

        if ( config.networkSimulator )
        {
            this.m_networkSimulator = YOJIMBO_NEW( globalAllocator, () => new NetworkSimulator( globalAllocator, config.maxSimulatorPackets, this.m_time ) );
            if ( !this.m_networkSimulator )
            {
                this.Stop();
                return false;
            }
        }

        for ( let i = 0; i < this.m_maxClients; ++i )
        {
            yojimbo_assert( !this.m_clientAllocator[i], "!m_clientAllocator[i]", "BaseServer::Start" );

            // NOTE: upstream allocates serverPerClientMemory bytes from m_allocator here to back the client allocator (see header).

            const clientAllocator = this.m_adapter.CreateAllocator( allocator, null, config.serverPerClientMemory );
            this.m_clientAllocator[i] = clientAllocator;
            if ( !clientAllocator )
            {
                this.Stop();
                return false;
            }

            const messageFactory = this.m_adapter.CreateMessageFactory( clientAllocator );
            this.m_clientMessageFactory[i] = messageFactory;
            if ( !messageFactory )
            {
                this.Stop();
                return false;
            }

            this.m_clientConnection[i] = YOJIMBO_NEW( clientAllocator, () => new Connection( clientAllocator, messageFactory, config, this.m_time ) );
            if ( !this.m_clientConnection[i] )
            {
                this.Stop();
                return false;
            }

            const reliable_config = new reliable_config_t();
            reliable_default_config( reliable_config );
            reliable_config.name = "server endpoint";
            reliable_config.context = this;
            reliable_config.id = BigInt( i );
            reliable_config.max_packet_size = config.maxPacketSize;
            reliable_config.fragment_above = config.fragmentPacketsAbove;
            reliable_config.max_fragments = config.maxPacketFragments;
            reliable_config.fragment_size = config.packetFragmentSize;
            reliable_config.ack_buffer_size = config.ackedPacketsBufferSize;
            reliable_config.received_packets_buffer_size = config.receivedPacketsBufferSize;
            reliable_config.fragment_reassembly_buffer_size = config.packetReassemblyBufferSize;
            reliable_config.rtt_smoothing_factor = Math.fround( config.rttSmoothingFactor );
            reliable_config.transmit_packet_function = BaseServer.StaticTransmitPacketFunction;
            reliable_config.process_packet_function = BaseServer.StaticProcessPacketFunction;
            reliable_config.allocator_context = this.GetGlobalAllocator();
            reliable_config.allocate_function = BaseServer.StaticAllocateFunction;
            reliable_config.free_function = BaseServer.StaticFreeFunction;
            this.m_clientEndpoint[i] = reliable_endpoint_create( reliable_config, this.m_time );
            if ( !this.m_clientEndpoint[i] )
            {
                this.Stop();
                return false;
            }
            reliable_endpoint_reset( this.m_clientEndpoint[i]! );
        }
        this.m_packetBuffer = YOJIMBO_ALLOCATE( globalAllocator, config.maxPacketSize );
        if ( !this.m_packetBuffer )
        {
            this.Stop();
            return false;
        }
        return true;
    }

    /**
        Stop the server and free client slots.
        Safe to call on a partially started server: Start unwinds through it, so every slot is
        torn down by what it actually holds rather than by what a complete start would have held.
     */

    Stop(): void
    {
        if ( this.IsRunning() )
        {
            const allocator = this.m_allocator!;
            if ( this.m_globalAllocator )
            {
                this.m_packetBuffer = YOJIMBO_FREE( this.m_globalAllocator, this.m_packetBuffer );
                this.m_networkSimulator = YOJIMBO_DELETE( this.m_globalAllocator, this.m_networkSimulator );
            }
            for ( let i = 0; i < MaxClients; ++i )
            {
                const endpoint = this.m_clientEndpoint[i];
                if ( endpoint )
                {
                    reliable_endpoint_destroy( endpoint );
                    this.m_clientEndpoint[i] = null;
                }
                const clientAllocator = this.m_clientAllocator[i];
                if ( clientAllocator )
                {
                    this.m_clientConnection[i] = YOJIMBO_DELETE( clientAllocator, this.m_clientConnection[i] );
                    this.m_clientMessageFactory[i] = YOJIMBO_DELETE( clientAllocator, this.m_clientMessageFactory[i] );
                    this.m_clientAllocator[i] = YOJIMBO_DELETE( allocator, clientAllocator );
                }
            }
            this.m_globalAllocator = YOJIMBO_DELETE( allocator, this.m_globalAllocator );
        }
        for ( let i = 0; i < MaxClients; ++i )
        {
            this.m_clientAllocator[i] = null;
            this.m_clientMessageFactory[i] = null;
            this.m_clientConnection[i] = null;
            this.m_clientEndpoint[i] = null;
        }
        this.m_networkSimulator = null;
        this.m_running = false;
        this.m_maxClients = 0;
        this.m_packetBuffer = null;
    }

    abstract DisconnectClient( clientIndex: number ): void;

    abstract DisconnectAllClients(): void;

    abstract SendPackets(): void;

    abstract ReceivePackets(): void;

    AdvanceTime( time: number ): void
    {
        this.m_time = time;
        if ( this.IsRunning() )
        {
            for ( let i = 0; i < this.m_maxClients; ++i )
            {
                const connection = this.m_clientConnection[i];
                if ( !connection )
                    break;          // the server was stopped from inside a callback
                connection.AdvanceTime( time );
                const connectionErrorLevel = connection.GetErrorLevel();
                if ( connectionErrorLevel !== CONNECTION_ERROR_NONE )
                {
                    yojimbo_printf( YOJIMBO_LOG_LEVEL_ERROR, "client %d connection is in error state. disconnecting client\n", i );
                    this.SetClientDisconnectReason( i, ClientDisconnectReasonForConnectionError( connection, connectionErrorLevel, this.m_config.numChannels ) );
                    this.DisconnectClient( i );
                    continue;
                }
                const endpoint = this.m_clientEndpoint[i]!;
                reliable_endpoint_update( endpoint, this.m_time );
                const acks = reliable_endpoint_get_acks( endpoint );
                connection.ProcessAcks( acks, acks.length );
                reliable_endpoint_clear_acks( endpoint );
            }
            const networkSimulator = this.GetNetworkSimulator();
            if ( networkSimulator )
            {
                networkSimulator.AdvanceTime( time );
            }
        }
    }

    IsRunning(): boolean { return this.m_running; }

    GetMaxClients(): number { return this.m_maxClients; }

    abstract IsClientConnected( clientIndex: number ): boolean;

    abstract GetClientId( clientIndex: number ): bigint;

    abstract GetClientUserData( clientIndex: number ): Uint8Array | null;

    abstract GetClientAddress( clientIndex: number ): netcode_address_t | null;

    abstract GetNumConnectedClients(): number;

    GetTime(): number { return this.m_time; }

    SetLatency( milliseconds: number ): void
    {
        yojimbo_assert( this.m_networkSimulator, "m_networkSimulator", "BaseServer::SetLatency" );
        if ( this.m_networkSimulator )
        {
            this.m_networkSimulator.SetLatency( milliseconds );
        }
    }

    SetJitter( milliseconds: number ): void
    {
        yojimbo_assert( this.m_networkSimulator, "m_networkSimulator", "BaseServer::SetJitter" );
        if ( this.m_networkSimulator )
        {
            this.m_networkSimulator.SetJitter( milliseconds );
        }
    }

    SetPacketLoss( percent: number ): void
    {
        yojimbo_assert( this.m_networkSimulator, "m_networkSimulator", "BaseServer::SetPacketLoss" );
        if ( this.m_networkSimulator )
        {
            this.m_networkSimulator.SetPacketLoss( percent );
        }
    }

    SetDuplicates( percent: number ): void
    {
        yojimbo_assert( this.m_networkSimulator, "m_networkSimulator", "BaseServer::SetDuplicates" );
        if ( this.m_networkSimulator )
        {
            this.m_networkSimulator.SetDuplicates( percent );
        }
    }

    CreateMessage( clientIndex: number, type: number ): Message | null
    {
        yojimbo_assert( clientIndex >= 0, "clientIndex >= 0", "BaseServer::CreateMessage" );
        yojimbo_assert( clientIndex < this.m_maxClients, "clientIndex < m_maxClients", "BaseServer::CreateMessage" );
        const messageFactory = this.m_clientMessageFactory[clientIndex];
        yojimbo_assert( messageFactory, "m_clientMessageFactory[clientIndex]", "BaseServer::CreateMessage" );
        return messageFactory.CreateMessage( type );
    }

    AllocateBlock( clientIndex: number, bytes: number ): Uint8Array | null
    {
        yojimbo_assert( clientIndex >= 0, "clientIndex >= 0", "BaseServer::AllocateBlock" );
        yojimbo_assert( clientIndex < this.m_maxClients, "clientIndex < m_maxClients", "BaseServer::AllocateBlock" );
        const allocator = this.m_clientAllocator[clientIndex];
        yojimbo_assert( allocator, "m_clientAllocator[clientIndex]", "BaseServer::AllocateBlock" );
        return YOJIMBO_ALLOCATE( allocator, bytes );
    }

    AttachBlockToMessage( clientIndex: number, message: Message, block: Uint8Array, bytes: number ): void
    {
        yojimbo_assert( clientIndex >= 0, "clientIndex >= 0", "BaseServer::AttachBlockToMessage" );
        yojimbo_assert( clientIndex < this.m_maxClients, "clientIndex < m_maxClients", "BaseServer::AttachBlockToMessage" );
        yojimbo_assert( message, "message", "BaseServer::AttachBlockToMessage" );
        yojimbo_assert( block, "block", "BaseServer::AttachBlockToMessage" );
        yojimbo_assert( bytes > 0, "bytes > 0", "BaseServer::AttachBlockToMessage" );
        yojimbo_assert( message.IsBlockMessage(), "message->IsBlockMessage()", "BaseServer::AttachBlockToMessage" );
        const blockMessage = message as BlockMessage;
        blockMessage.AttachBlock( this.m_clientAllocator[clientIndex]!, block, bytes );
    }

    FreeBlock( clientIndex: number, block: Uint8Array ): void
    {
        yojimbo_assert( clientIndex >= 0, "clientIndex >= 0", "BaseServer::FreeBlock" );
        yojimbo_assert( clientIndex < this.m_maxClients, "clientIndex < m_maxClients", "BaseServer::FreeBlock" );
        YOJIMBO_FREE( this.m_clientAllocator[clientIndex]!, block );
    }

    CanSendMessage( clientIndex: number, channelIndex: number ): boolean
    {
        yojimbo_assert( clientIndex >= 0, "clientIndex >= 0", "BaseServer::CanSendMessage" );
        yojimbo_assert( clientIndex < this.m_maxClients, "clientIndex < m_maxClients", "BaseServer::CanSendMessage" );
        yojimbo_assert( channelIndex >= 0, "channelIndex >= 0", "BaseServer::CanSendMessage" );
        yojimbo_assert( channelIndex < this.m_config.numChannels, "channelIndex < m_config.numChannels", "BaseServer::CanSendMessage" );
        const connection = this.m_clientConnection[clientIndex];
        yojimbo_assert( connection, "m_clientConnection[clientIndex]", "BaseServer::CanSendMessage" );
        return connection.CanSendMessage( channelIndex );
    }

    HasMessagesToSend( clientIndex: number, channelIndex: number ): boolean
    {
        yojimbo_assert( clientIndex >= 0, "clientIndex >= 0", "BaseServer::HasMessagesToSend" );
        yojimbo_assert( clientIndex < this.m_maxClients, "clientIndex < m_maxClients", "BaseServer::HasMessagesToSend" );
        const connection = this.m_clientConnection[clientIndex];
        yojimbo_assert( connection, "m_clientConnection[clientIndex]", "BaseServer::HasMessagesToSend" );
        yojimbo_assert( channelIndex >= 0, "channelIndex >= 0", "BaseServer::HasMessagesToSend" );
        yojimbo_assert( channelIndex < this.m_config.numChannels, "channelIndex < m_config.numChannels", "BaseServer::HasMessagesToSend" );
        return connection.HasMessagesToSend( channelIndex );
    }

    SendMessage( clientIndex: number, channelIndex: number, message: Message ): void
    {
        yojimbo_assert( clientIndex >= 0, "clientIndex >= 0", "BaseServer::SendMessage" );
        yojimbo_assert( clientIndex < this.m_maxClients, "clientIndex < m_maxClients", "BaseServer::SendMessage" );
        const connection = this.m_clientConnection[clientIndex];
        yojimbo_assert( connection, "m_clientConnection[clientIndex]", "BaseServer::SendMessage" );
        yojimbo_assert( channelIndex >= 0, "channelIndex >= 0", "BaseServer::SendMessage" );
        yojimbo_assert( channelIndex < this.m_config.numChannels, "channelIndex < m_config.numChannels", "BaseServer::SendMessage" );
        connection.SendMessage( channelIndex, message, this.GetContext() );
    }

    ReceiveMessage( clientIndex: number, channelIndex: number ): Message | null
    {
        yojimbo_assert( clientIndex >= 0, "clientIndex >= 0", "BaseServer::ReceiveMessage" );
        yojimbo_assert( clientIndex < this.m_maxClients, "clientIndex < m_maxClients", "BaseServer::ReceiveMessage" );
        const connection = this.m_clientConnection[clientIndex];
        yojimbo_assert( connection, "m_clientConnection[clientIndex]", "BaseServer::ReceiveMessage" );
        yojimbo_assert( channelIndex >= 0, "channelIndex >= 0", "BaseServer::ReceiveMessage" );
        yojimbo_assert( channelIndex < this.m_config.numChannels, "channelIndex < m_config.numChannels", "BaseServer::ReceiveMessage" );
        return connection.ReceiveMessage( channelIndex );
    }

    ReleaseMessage( clientIndex: number, message: Message ): void
    {
        yojimbo_assert( clientIndex >= 0, "clientIndex >= 0", "BaseServer::ReleaseMessage" );
        yojimbo_assert( clientIndex < this.m_maxClients, "clientIndex < m_maxClients", "BaseServer::ReleaseMessage" );
        const connection = this.m_clientConnection[clientIndex];
        yojimbo_assert( connection, "m_clientConnection[clientIndex]", "BaseServer::ReleaseMessage" );
        connection.ReleaseMessage( message );
    }

    GetNetworkInfo( clientIndex: number, info: NetworkInfo ): void
    {
        yojimbo_assert( this.IsRunning(), "IsRunning()", "BaseServer::GetNetworkInfo" );
        yojimbo_assert( clientIndex >= 0, "clientIndex >= 0", "BaseServer::GetNetworkInfo" );
        yojimbo_assert( clientIndex < this.m_maxClients, "clientIndex < m_maxClients", "BaseServer::GetNetworkInfo" );
        Object.assign( info, new NetworkInfo() );
        if ( this.IsClientConnected( clientIndex ) )
        {
            const endpoint = this.m_clientEndpoint[clientIndex];
            yojimbo_assert( endpoint, "m_clientEndpoint[clientIndex]", "BaseServer::GetNetworkInfo" );
            FillNetworkInfo( endpoint, info );
        }
    }

    abstract ConnectLoopbackClient( clientIndex: number, clientId: bigint, userData: Uint8Array | null ): void;

    abstract DisconnectLoopbackClient( clientIndex: number ): void;

    abstract IsLoopbackClient( clientIndex: number ): boolean;

    abstract ProcessLoopbackPacket( clientIndex: number, packetData: Uint8Array, packetBytes: number, packetSequence: bigint ): void;

    /**
        Get the reason the client in this slot was last disconnected.
        Valid while the server is running. Recorded before Adapter::OnServerClientDisconnected is called,
        so you can query it from inside that callback. See ServerClientDisconnectReason for the values.
     */

    GetClientDisconnectReason( clientIndex: number ): number
    {
        yojimbo_assert( clientIndex >= 0, "clientIndex >= 0", "BaseServer::GetClientDisconnectReason" );
        yojimbo_assert( clientIndex < this.m_maxClients, "clientIndex < m_maxClients", "BaseServer::GetClientDisconnectReason" );
        return this.m_clientDisconnectReason[clientIndex];
    }

    protected SetClientDisconnectReason( clientIndex: number, disconnectReason: number ): void
    {
        yojimbo_assert( clientIndex >= 0, "clientIndex >= 0", "BaseServer::SetClientDisconnectReason" );
        yojimbo_assert( clientIndex < this.m_maxClients, "clientIndex < m_maxClients", "BaseServer::SetClientDisconnectReason" );
        this.m_clientDisconnectReason[clientIndex] = disconnectReason;
    }

    protected GetPacketBuffer(): Uint8Array
    {
        return this.m_packetBuffer!;
    }

    protected GetContext(): unknown
    {
        return this.m_context;
    }

    protected GetAdapter(): Adapter
    {
        yojimbo_assert( this.m_adapter, "m_adapter", "BaseServer::GetAdapter" );
        return this.m_adapter;
    }

    protected GetGlobalAllocator(): Allocator
    {
        yojimbo_assert( this.m_globalAllocator, "m_globalAllocator", "BaseServer::GetGlobalAllocator" );
        return this.m_globalAllocator;
    }

    protected GetClientMessageFactory( clientIndex: number ): MessageFactory
    {
        yojimbo_assert( this.IsRunning(), "IsRunning()", "BaseServer::GetClientMessageFactory" );
        yojimbo_assert( clientIndex >= 0, "clientIndex >= 0", "BaseServer::GetClientMessageFactory" );
        yojimbo_assert( clientIndex < this.m_maxClients, "clientIndex < m_maxClients", "BaseServer::GetClientMessageFactory" );
        return this.m_clientMessageFactory[clientIndex]!;
    }

    protected GetNetworkSimulator(): NetworkSimulator | null
    {
        return this.m_networkSimulator;
    }

    protected GetClientEndpoint( clientIndex: number ): reliable_endpoint_t
    {
        yojimbo_assert( this.IsRunning(), "IsRunning()", "BaseServer::GetClientEndpoint" );
        yojimbo_assert( clientIndex >= 0, "clientIndex >= 0", "BaseServer::GetClientEndpoint" );
        yojimbo_assert( clientIndex < this.m_maxClients, "clientIndex < m_maxClients", "BaseServer::GetClientEndpoint" );
        return this.m_clientEndpoint[clientIndex]!;
    }

    protected GetClientConnection( clientIndex: number ): Connection
    {
        yojimbo_assert( this.IsRunning(), "IsRunning()", "BaseServer::GetClientConnection" );
        yojimbo_assert( clientIndex >= 0, "clientIndex >= 0", "BaseServer::GetClientConnection" );
        yojimbo_assert( clientIndex < this.m_maxClients, "clientIndex < m_maxClients", "BaseServer::GetClientConnection" );
        const connection = this.m_clientConnection[clientIndex];
        yojimbo_assert( connection, "m_clientConnection[clientIndex]", "BaseServer::GetClientConnection" );
        return connection;
    }

    protected abstract TransmitPacketFunction( clientIndex: number, packetSequence: number, packetData: Uint8Array, packetBytes: number ): void;

    protected abstract ProcessPacketFunction( clientIndex: number, packetSequence: number, packetData: Uint8Array, packetBytes: number ): boolean;

    protected static StaticTransmitPacketFunction( context: unknown, index: bigint, packetSequence: number, packetData: Uint8Array, packetBytes: number ): void
    {
        const server = context as BaseServer;
        server.TransmitPacketFunction( Number( index ), packetSequence, packetData, packetBytes );
    }

    protected static StaticProcessPacketFunction( context: unknown, index: bigint, packetSequence: number, packetData: Uint8Array, packetBytes: number ): boolean
    {
        const server = context as BaseServer;
        return server.ProcessPacketFunction( Number( index ), packetSequence, packetData, packetBytes );
    }

    protected static StaticAllocateFunction( context: unknown, bytes: number ): Uint8Array | null
    {
        yojimbo_assert( context, "context", "BaseServer::StaticAllocateFunction" );
        const allocator = context as Allocator;
        return YOJIMBO_ALLOCATE( allocator, bytes );
    }

    protected static StaticFreeFunction( context: unknown, pointer: unknown ): void
    {
        yojimbo_assert( context, "context", "BaseServer::StaticFreeFunction" );
        yojimbo_assert( pointer, "pointer", "BaseServer::StaticFreeFunction" );
        const allocator = context as Allocator;
        YOJIMBO_FREE( allocator, pointer as Uint8Array );
    }

    protected ResetClient( clientIndex: number ): void
    {
        this.m_clientConnection[clientIndex]!.Reset();
    }
}
