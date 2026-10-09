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
    TypeScript port of include/yojimbo_base_client.h + source/yojimbo_base_client.cpp (yojimbo 1.13.5).

    Port notes:
      - The ClientDisconnectReason enum and its string function are declared in yojimbo_client.h upstream (and
        included by yojimbo_base_client.cpp). They are defined here and re-exported by yojimbo_client.ts, so the
        two modules do not import each other (an ES module cycle through a base class is order dependent).
      - The memory block backing the client allocator is not allocated: allocators in the TypeScript port are
        bookkeeping over GC'd blocks, so the adapter's CreateAllocator gets memory = null and the budget in bytes
        (as the C# port). Everything else CreateInternal allocates is allocated and checked exactly as upstream.
      - reliable's allocate / free callbacks map to YOJIMBO_ALLOCATE / YOJIMBO_FREE on the client allocator.
*/

import {
    reliable_config_t, reliable_default_config, reliable_endpoint_create, reliable_endpoint_destroy, reliable_endpoint_reset,
    reliable_endpoint_update, reliable_endpoint_get_acks, reliable_endpoint_clear_acks, reliable_endpoint_counters,
    reliable_endpoint_rtt, reliable_endpoint_rtt_min, reliable_endpoint_rtt_max, reliable_endpoint_rtt_avg,
    reliable_endpoint_jitter_avg_vs_min_rtt, reliable_endpoint_jitter_max_vs_min_rtt, reliable_endpoint_jitter_stddev_vs_avg_rtt,
    reliable_endpoint_packet_loss, reliable_endpoint_bandwidth,
    RELIABLE_ENDPOINT_COUNTER_NUM_PACKETS_SENT, RELIABLE_ENDPOINT_COUNTER_NUM_PACKETS_RECEIVED, RELIABLE_ENDPOINT_COUNTER_NUM_PACKETS_ACKED,
    type reliable_endpoint_t,
} from '../reliable/reliable.ts';
import { CLIENT_STATE_ERROR, CLIENT_STATE_DISCONNECTED, CLIENT_STATE_CONNECTING, CLIENT_STATE_CONNECTED, type ClientInterface, type ClientState } from '../include/yojimbo_client_interface.ts';
import { NetworkInfo } from '../include/yojimbo_network_info.ts';
import type { Adapter } from '../include/yojimbo_adapter.ts';
import { Allocator, YOJIMBO_ALLOCATE, YOJIMBO_FREE, YOJIMBO_NEW, YOJIMBO_DELETE } from './yojimbo_allocator.ts';
import { ClientServerConfig } from './yojimbo_config.ts';
import { Message, BlockMessage, MessageFactory } from './yojimbo_message.ts';
import { Connection, CONNECTION_ERROR_NONE, CONNECTION_ERROR_CHANNEL, CONNECTION_ERROR_ALLOCATOR, CONNECTION_ERROR_MESSAGE_FACTORY, CONNECTION_ERROR_READ_PACKET_FAILED, type ConnectionErrorLevel } from './yojimbo_connection.ts';
import { CHANNEL_ERROR_NONE, CHANNEL_ERROR_DESYNC, CHANNEL_ERROR_SEND_QUEUE_FULL, CHANNEL_ERROR_BLOCKS_DISABLED, CHANNEL_ERROR_FAILED_TO_SERIALIZE, CHANNEL_ERROR_OUT_OF_MEMORY, CHANNEL_ERROR_MESSAGE_TOO_LARGE } from './yojimbo_channel.ts';
import { NetworkSimulator } from './yojimbo_network_simulator.ts';
import { yojimbo_assert, yojimbo_printf, YOJIMBO_LOG_LEVEL_DEBUG } from './yojimbo_platform.ts';

// ---------------------------------------------------------------------------------------------
// ClientDisconnectReason (upstream: yojimbo_client.h)

/**
    The reason this client was last disconnected.
    Cleared to YOJIMBO_CLIENT_DISCONNECT_REASON_NONE when a new connect attempt starts. The first reason recorded
    for a disconnect wins, so a specific error is never overwritten by the generic disconnect that follows it.
 */

export const YOJIMBO_CLIENT_DISCONNECT_REASON_NONE = 0;                             ///< No disconnect has happened yet (or a new connect attempt is in progress).
export const YOJIMBO_CLIENT_DISCONNECT_REASON_DISCONNECTED = 1;                     ///< You called Client::Disconnect. A deliberate local disconnect.
export const YOJIMBO_CLIENT_DISCONNECT_REASON_DISCONNECTED_BY_SERVER = 2;           ///< The server disconnected us. The server was stopped, or it kicked this client.
export const YOJIMBO_CLIENT_DISCONNECT_REASON_CONNECTION_DENIED = 3;                ///< The server denied the connection request. For example, the server is full.
export const YOJIMBO_CLIENT_DISCONNECT_REASON_CONNECTION_REQUEST_TIMED_OUT = 4;     ///< No response from the server to our connection request. Server not running, unreachable, or wrong address.
export const YOJIMBO_CLIENT_DISCONNECT_REASON_CONNECTION_RESPONSE_TIMED_OUT = 5;    ///< No response from the server to our challenge response while establishing the connection.
export const YOJIMBO_CLIENT_DISCONNECT_REASON_CONNECTION_TIMED_OUT = 6;             ///< The established connection timed out. We stopped hearing from the server.
export const YOJIMBO_CLIENT_DISCONNECT_REASON_INVALID_CONNECT_TOKEN = 7;            ///< The connect token is invalid, or could not be generated.
export const YOJIMBO_CLIENT_DISCONNECT_REASON_CONNECT_TOKEN_EXPIRED = 8;            ///< The connect token expired before we could connect. Request a fresh one from the matchmaker and retry.
export const YOJIMBO_CLIENT_DISCONNECT_REASON_FAILED_TO_SERIALIZE = 9;              ///< A message from the server failed to serialize read. Usually a client/server protocol version mismatch, or a bug in a message serialize function.
export const YOJIMBO_CLIENT_DISCONNECT_REASON_DESYNC = 10;                          ///< A channel desynced and cannot recover. See CHANNEL_ERROR_DESYNC.
export const YOJIMBO_CLIENT_DISCONNECT_REASON_SEND_QUEUE_FULL = 11;                 ///< A channel send queue filled up. See CHANNEL_ERROR_SEND_QUEUE_FULL.
export const YOJIMBO_CLIENT_DISCONNECT_REASON_BLOCKS_DISABLED = 12;                 ///< The server sent block data on a channel that is configured with blocks disabled.
export const YOJIMBO_CLIENT_DISCONNECT_REASON_MESSAGE_TOO_LARGE = 13;               ///< Tried to send a message too large to ever fit into a packet. See CHANNEL_ERROR_MESSAGE_TOO_LARGE.
export const YOJIMBO_CLIENT_DISCONNECT_REASON_OUT_OF_MEMORY = 14;                   ///< The client memory budget was exhausted. Consider increasing ClientServerConfig::clientMemory.
export const YOJIMBO_CLIENT_DISCONNECT_REASON_READ_PACKET_FAILED = 15;              ///< A connection packet from the server failed to deserialize.

export type ClientDisconnectReason = number;

/// Helper function to convert a client disconnect reason to a user friendly string.
export function GetClientDisconnectReasonString( reason: number ): string
{
    switch ( reason )
    {
        case YOJIMBO_CLIENT_DISCONNECT_REASON_NONE:                             return "none";
        case YOJIMBO_CLIENT_DISCONNECT_REASON_DISCONNECTED:                     return "disconnected";
        case YOJIMBO_CLIENT_DISCONNECT_REASON_DISCONNECTED_BY_SERVER:           return "disconnected by server";
        case YOJIMBO_CLIENT_DISCONNECT_REASON_CONNECTION_DENIED:                return "connection denied";
        case YOJIMBO_CLIENT_DISCONNECT_REASON_CONNECTION_REQUEST_TIMED_OUT:     return "connection request timed out";
        case YOJIMBO_CLIENT_DISCONNECT_REASON_CONNECTION_RESPONSE_TIMED_OUT:    return "connection response timed out";
        case YOJIMBO_CLIENT_DISCONNECT_REASON_CONNECTION_TIMED_OUT:             return "connection timed out";
        case YOJIMBO_CLIENT_DISCONNECT_REASON_INVALID_CONNECT_TOKEN:            return "invalid connect token";
        case YOJIMBO_CLIENT_DISCONNECT_REASON_CONNECT_TOKEN_EXPIRED:            return "connect token expired";
        case YOJIMBO_CLIENT_DISCONNECT_REASON_FAILED_TO_SERIALIZE:              return "failed to serialize";
        case YOJIMBO_CLIENT_DISCONNECT_REASON_DESYNC:                           return "desync";
        case YOJIMBO_CLIENT_DISCONNECT_REASON_SEND_QUEUE_FULL:                  return "send queue full";
        case YOJIMBO_CLIENT_DISCONNECT_REASON_BLOCKS_DISABLED:                  return "blocks disabled";
        case YOJIMBO_CLIENT_DISCONNECT_REASON_MESSAGE_TOO_LARGE:                return "message too large";
        case YOJIMBO_CLIENT_DISCONNECT_REASON_OUT_OF_MEMORY:                    return "out of memory";
        case YOJIMBO_CLIENT_DISCONNECT_REASON_READ_PACKET_FAILED:               return "read packet failed";
        default:
            yojimbo_assert( false, "unknown client disconnect reason", "GetClientDisconnectReasonString" );
            return "(unknown)";
    }
}

// ---------------------------------------------------------------------------------------------

// Map the error that drove the connection into an error state to the disconnect reason we
// record for this client. For channel errors, drill into the channels to find the one in
// error, because that is where the actionable detail lives.
function ClientDisconnectReasonForConnectionError( connection: Connection, errorLevel: ConnectionErrorLevel, numChannels: number ): number
{
    switch ( errorLevel )
    {
        case CONNECTION_ERROR_ALLOCATOR:            return YOJIMBO_CLIENT_DISCONNECT_REASON_OUT_OF_MEMORY;
        case CONNECTION_ERROR_MESSAGE_FACTORY:      return YOJIMBO_CLIENT_DISCONNECT_REASON_OUT_OF_MEMORY;
        case CONNECTION_ERROR_READ_PACKET_FAILED:   return YOJIMBO_CLIENT_DISCONNECT_REASON_READ_PACKET_FAILED;

        case CONNECTION_ERROR_CHANNEL:
        {
            for ( let i = 0; i < numChannels; ++i )
            {
                switch ( connection.GetChannelErrorLevel( i ) )
                {
                    case CHANNEL_ERROR_DESYNC:                  return YOJIMBO_CLIENT_DISCONNECT_REASON_DESYNC;
                    case CHANNEL_ERROR_SEND_QUEUE_FULL:         return YOJIMBO_CLIENT_DISCONNECT_REASON_SEND_QUEUE_FULL;
                    case CHANNEL_ERROR_BLOCKS_DISABLED:         return YOJIMBO_CLIENT_DISCONNECT_REASON_BLOCKS_DISABLED;
                    case CHANNEL_ERROR_FAILED_TO_SERIALIZE:     return YOJIMBO_CLIENT_DISCONNECT_REASON_FAILED_TO_SERIALIZE;
                    case CHANNEL_ERROR_OUT_OF_MEMORY:           return YOJIMBO_CLIENT_DISCONNECT_REASON_OUT_OF_MEMORY;
                    case CHANNEL_ERROR_MESSAGE_TOO_LARGE:       return YOJIMBO_CLIENT_DISCONNECT_REASON_MESSAGE_TOO_LARGE;
                    case CHANNEL_ERROR_NONE:                    break;
                }
            }
        }
        break;

        case CONNECTION_ERROR_NONE:
            break;
    }

    // A connection in an error state always matches one of the cases above; keep a sane
    // value if that ever changes rather than reporting garbage.
    return YOJIMBO_CLIENT_DISCONNECT_REASON_DISCONNECTED;
}

/**
    Functionality that is common across all client implementations.
 */

export abstract class BaseClient implements ClientInterface
{
    protected m_config: ClientServerConfig;                         ///< The client/server configuration (a private copy, shared with the derived client: upstream Client keeps an identical copy of its own).
    private m_allocator: Allocator | null;                          ///< The allocator passed to the client on creation.
    private m_adapter: Adapter;                                     ///< The adapter specifies the allocator to use, and the message factory class.
    private m_context: unknown;                                     ///< Context lets the user pass information to packet serialize functions.
    private m_clientAllocator: Allocator | null;                    ///< The client allocator. Everything allocated between connect and disconnected is allocated and freed via this allocator.
    private m_endpoint: reliable_endpoint_t | null;                 ///< reliable endpoint.
    private m_messageFactory: MessageFactory | null;                ///< The client message factory. Created and destroyed on each connection attempt.
    private m_connection: Connection | null;                        ///< The client connection for exchanging messages with the server.
    private m_networkSimulator: NetworkSimulator | null;            ///< The network simulator used to simulate packet loss, latency, jitter etc. Optional.
    private m_clientState: ClientState;                             ///< The current client state.
    private m_clientIndex: number;                                  ///< The client slot index on the server [0,maxClients-1]. -1 if not connected.
    private m_disconnectReason: number;                             ///< The reason this client was last disconnected (ClientDisconnectReason).
    private m_time: number;                                         ///< The current client time.
    private m_packetBuffer: Uint8Array | null;                      ///< Buffer used to read and write packets.

    /**
        Base client constructor.
        @param allocator The allocator for all memory used by the client.
        @param config The base client/server configuration (copied).
        @param adapter The adapter, used to create the allocator and message factory.
        @param time The current time in seconds.
     */

    constructor( allocator: Allocator, config: ClientServerConfig, adapter: Adapter, time: number )
    {
        this.m_config = config.Clone();
        this.m_allocator = allocator;
        this.m_adapter = adapter;
        this.m_time = time;
        this.m_context = null;
        this.m_clientAllocator = null;
        this.m_endpoint = null;
        this.m_connection = null;
        this.m_messageFactory = null;
        this.m_networkSimulator = null;
        this.m_clientState = CLIENT_STATE_DISCONNECTED;
        this.m_clientIndex = -1;
        this.m_disconnectReason = YOJIMBO_CLIENT_DISCONNECT_REASON_NONE;
        this.m_packetBuffer = null;
    }

    /**
        The base client destructor.
        IMPORTANT: Please disconnect the client before destroying it.
     */

    Dispose(): void
    {
        yojimbo_assert( this.m_clientState <= CLIENT_STATE_DISCONNECTED, "m_clientState <= CLIENT_STATE_DISCONNECTED", "BaseClient::~BaseClient" );
        yojimbo_assert( this.m_packetBuffer == null, "m_packetBuffer == NULL", "BaseClient::~BaseClient" );
        this.m_allocator = null;
    }

    SetContext( context: unknown ): void
    {
        yojimbo_assert( this.IsDisconnected(), "IsDisconnected()", "BaseClient::SetContext" );
        this.m_context = context;
    }

    Disconnect(): void
    {
        this.SetClientState( CLIENT_STATE_DISCONNECTED );
        this.Reset();
    }

    abstract SendPackets(): void;

    abstract ReceivePackets(): void;

    AdvanceTime( time: number ): void
    {
        this.m_time = time;
        if ( this.m_endpoint )
        {
            const connection = this.m_connection!;
            connection.AdvanceTime( time );
            const connectionErrorLevel = connection.GetErrorLevel();
            if ( connectionErrorLevel !== CONNECTION_ERROR_NONE )
            {
                yojimbo_printf( YOJIMBO_LOG_LEVEL_DEBUG, "connection error. disconnecting client\n" );
                this.SetDisconnectReason( ClientDisconnectReasonForConnectionError( connection, connectionErrorLevel, this.m_config.numChannels ) );
                this.Disconnect();
                return;
            }
            reliable_endpoint_update( this.m_endpoint, this.m_time );
            const acks = reliable_endpoint_get_acks( this.m_endpoint );
            connection.ProcessAcks( acks, acks.length );
            reliable_endpoint_clear_acks( this.m_endpoint );
        }
        const networkSimulator = this.GetNetworkSimulator();
        if ( networkSimulator )
        {
            networkSimulator.AdvanceTime( time );
        }
    }

    IsConnecting(): boolean { return this.m_clientState === CLIENT_STATE_CONNECTING; }

    IsConnected(): boolean { return this.m_clientState === CLIENT_STATE_CONNECTED; }

    IsDisconnected(): boolean { return this.m_clientState <= CLIENT_STATE_DISCONNECTED; }

    ConnectionFailed(): boolean { return this.m_clientState === CLIENT_STATE_ERROR; }

    GetClientState(): ClientState { return this.m_clientState; }

    GetClientIndex(): number { return this.m_clientIndex; }

    abstract GetClientId(): bigint;

    GetTime(): number { return this.m_time; }

    SetLatency( milliseconds: number ): void
    {
        yojimbo_assert( this.m_networkSimulator, "m_networkSimulator", "BaseClient::SetLatency" );
        if ( this.m_networkSimulator )
        {
            this.m_networkSimulator.SetLatency( milliseconds );
        }
    }

    SetJitter( milliseconds: number ): void
    {
        yojimbo_assert( this.m_networkSimulator, "m_networkSimulator", "BaseClient::SetJitter" );
        if ( this.m_networkSimulator )
        {
            this.m_networkSimulator.SetJitter( milliseconds );
        }
    }

    SetPacketLoss( percent: number ): void
    {
        yojimbo_assert( this.m_networkSimulator, "m_networkSimulator", "BaseClient::SetPacketLoss" );
        if ( this.m_networkSimulator )
        {
            this.m_networkSimulator.SetPacketLoss( percent );
        }
    }

    SetDuplicates( percent: number ): void
    {
        yojimbo_assert( this.m_networkSimulator, "m_networkSimulator", "BaseClient::SetDuplicates" );
        if ( this.m_networkSimulator )
        {
            this.m_networkSimulator.SetDuplicates( percent );
        }
    }

    CreateMessage( type: number ): Message | null
    {
        yojimbo_assert( this.m_messageFactory, "m_messageFactory", "BaseClient::CreateMessage" );
        return this.m_messageFactory.CreateMessage( type );
    }

    AllocateBlock( bytes: number ): Uint8Array | null
    {
        return YOJIMBO_ALLOCATE( this.m_clientAllocator!, bytes );
    }

    AttachBlockToMessage( message: Message, block: Uint8Array, bytes: number ): void
    {
        yojimbo_assert( message, "message", "BaseClient::AttachBlockToMessage" );
        yojimbo_assert( block, "block", "BaseClient::AttachBlockToMessage" );
        yojimbo_assert( bytes > 0, "bytes > 0", "BaseClient::AttachBlockToMessage" );
        yojimbo_assert( message.IsBlockMessage(), "message->IsBlockMessage()", "BaseClient::AttachBlockToMessage" );
        const blockMessage = message as BlockMessage;
        blockMessage.AttachBlock( this.m_clientAllocator!, block, bytes );
    }

    FreeBlock( block: Uint8Array ): void
    {
        YOJIMBO_FREE( this.m_clientAllocator!, block );
    }

    CanSendMessage( channelIndex: number ): boolean
    {
        yojimbo_assert( this.m_connection, "m_connection", "BaseClient::CanSendMessage" );
        yojimbo_assert( channelIndex >= 0, "channelIndex >= 0", "BaseClient::CanSendMessage" );
        yojimbo_assert( channelIndex < this.m_config.numChannels, "channelIndex < m_config.numChannels", "BaseClient::CanSendMessage" );
        return this.m_connection.CanSendMessage( channelIndex );
    }

    HasMessagesToSend( channelIndex: number ): boolean
    {
        yojimbo_assert( this.m_connection, "m_connection", "BaseClient::HasMessagesToSend" );
        yojimbo_assert( channelIndex >= 0, "channelIndex >= 0", "BaseClient::HasMessagesToSend" );
        yojimbo_assert( channelIndex < this.m_config.numChannels, "channelIndex < m_config.numChannels", "BaseClient::HasMessagesToSend" );
        return this.m_connection.HasMessagesToSend( channelIndex );
    }

    SendMessage( channelIndex: number, message: Message ): void
    {
        yojimbo_assert( this.m_connection, "m_connection", "BaseClient::SendMessage" );
        yojimbo_assert( channelIndex >= 0, "channelIndex >= 0", "BaseClient::SendMessage" );
        yojimbo_assert( channelIndex < this.m_config.numChannels, "channelIndex < m_config.numChannels", "BaseClient::SendMessage" );
        this.m_connection.SendMessage( channelIndex, message, this.GetContext() );
    }

    ReceiveMessage( channelIndex: number ): Message | null
    {
        yojimbo_assert( this.m_connection, "m_connection", "BaseClient::ReceiveMessage" );
        yojimbo_assert( channelIndex >= 0, "channelIndex >= 0", "BaseClient::ReceiveMessage" );
        yojimbo_assert( channelIndex < this.m_config.numChannels, "channelIndex < m_config.numChannels", "BaseClient::ReceiveMessage" );
        return this.m_connection.ReceiveMessage( channelIndex );
    }

    ReleaseMessage( message: Message ): void
    {
        yojimbo_assert( this.m_connection, "m_connection", "BaseClient::ReleaseMessage" );
        this.m_connection.ReleaseMessage( message );
    }

    GetNetworkInfo( info: NetworkInfo ): void
    {
        Object.assign( info, new NetworkInfo() );
        if ( this.m_connection )
        {
            yojimbo_assert( this.m_endpoint, "m_endpoint", "BaseClient::GetNetworkInfo" );
            FillNetworkInfo( this.m_endpoint, info );
        }
    }

    /**
        Get the reason this client was last disconnected.
        See ClientDisconnectReason for the values. Cleared back to YOJIMBO_CLIENT_DISCONNECT_REASON_NONE
        when a new connect attempt starts.
     */

    GetDisconnectReason(): number
    {
        return this.m_disconnectReason;
    }

    abstract ConnectLoopback( clientIndex: number, clientId: bigint, maxClients: number ): boolean;

    abstract DisconnectLoopback(): void;

    abstract IsLoopback(): boolean;

    abstract ProcessLoopbackPacket( packetData: Uint8Array, packetBytes: number, packetSequence: bigint ): void;

    protected SetDisconnectReason( disconnectReason: number ): void
    {
        this.m_disconnectReason = disconnectReason;
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
        yojimbo_assert( this.m_adapter, "m_adapter", "BaseClient::GetAdapter" );
        return this.m_adapter;
    }

    /**
        Allocate everything the client needs to run.
        Transactional: on the first allocation or adapter factory failure everything already
        created is destroyed, the client is left as it was before the call, and false is
        returned. Checked in every build, not by an assert.
     */

    protected CreateInternal(): boolean
    {
        yojimbo_assert( this.m_allocator, "m_allocator", "BaseClient::CreateInternal" );
        yojimbo_assert( this.m_adapter, "m_adapter", "BaseClient::CreateInternal" );
        yojimbo_assert( this.m_clientAllocator == null, "m_clientAllocator == NULL", "BaseClient::CreateInternal" );
        yojimbo_assert( this.m_messageFactory == null, "m_messageFactory == NULL", "BaseClient::CreateInternal" );

        const allocator = this.m_allocator;

        this.m_config.Validate();

        this.m_packetBuffer = YOJIMBO_ALLOCATE( allocator, this.m_config.maxPacketSize );
        if ( !this.m_packetBuffer )
        {
            this.DestroyInternal();
            return false;
        }

        // NOTE: upstream allocates m_config.clientMemory bytes from m_allocator here to back the client allocator.
        // TypeScript allocators are bookkeeping over GC'd blocks, so the backing block is not allocated (see header).

        this.m_clientAllocator = this.m_adapter.CreateAllocator( allocator, null, this.m_config.clientMemory );
        if ( !this.m_clientAllocator )
        {
            this.DestroyInternal();
            return false;
        }

        const clientAllocator = this.m_clientAllocator;

        this.m_messageFactory = this.m_adapter.CreateMessageFactory( clientAllocator );
        if ( !this.m_messageFactory )
        {
            this.DestroyInternal();
            return false;
        }

        const messageFactory = this.m_messageFactory;
        const config = this.m_config;
        const time = this.m_time;

        this.m_connection = YOJIMBO_NEW( clientAllocator, () => new Connection( clientAllocator, messageFactory, config, time ) );
        if ( !this.m_connection )
        {
            this.DestroyInternal();
            return false;
        }

        if ( this.m_config.networkSimulator )
        {
            this.m_networkSimulator = YOJIMBO_NEW( clientAllocator, () => new NetworkSimulator( clientAllocator, config.maxSimulatorPackets, time ) );
            if ( !this.m_networkSimulator )
            {
                this.DestroyInternal();
                return false;
            }
        }

        const reliable_config = new reliable_config_t();
        reliable_default_config( reliable_config );
        reliable_config.name = "client endpoint";
        reliable_config.context = this;
        reliable_config.max_packet_size = this.m_config.maxPacketSize;
        reliable_config.fragment_above = this.m_config.fragmentPacketsAbove;
        reliable_config.max_fragments = this.m_config.maxPacketFragments;
        reliable_config.fragment_size = this.m_config.packetFragmentSize;
        reliable_config.ack_buffer_size = this.m_config.ackedPacketsBufferSize;
        reliable_config.received_packets_buffer_size = this.m_config.receivedPacketsBufferSize;
        reliable_config.fragment_reassembly_buffer_size = this.m_config.packetReassemblyBufferSize;
        reliable_config.rtt_smoothing_factor = Math.fround( this.m_config.rttSmoothingFactor );
        reliable_config.transmit_packet_function = BaseClient.StaticTransmitPacketFunction;
        reliable_config.process_packet_function = BaseClient.StaticProcessPacketFunction;
        reliable_config.allocator_context = clientAllocator;
        reliable_config.allocate_function = BaseClient.StaticAllocateFunction;
        reliable_config.free_function = BaseClient.StaticFreeFunction;

        this.m_endpoint = reliable_endpoint_create( reliable_config, this.m_time );
        if ( !this.m_endpoint )
        {
            this.DestroyInternal();
            return false;
        }

        reliable_endpoint_reset( this.m_endpoint );

        return true;
    }

    /**
        Destroy everything CreateInternal created.
        Safe to call on a partially created client: CreateInternal unwinds through it, so every
        member is checked rather than assumed.
     */

    protected DestroyInternal(): void
    {
        yojimbo_assert( this.m_allocator, "m_allocator", "BaseClient::DestroyInternal" );
        if ( this.m_endpoint )
        {
            reliable_endpoint_destroy( this.m_endpoint );
            this.m_endpoint = null;
        }
        if ( this.m_clientAllocator )
        {
            this.m_networkSimulator = YOJIMBO_DELETE( this.m_clientAllocator, this.m_networkSimulator );
            this.m_connection = YOJIMBO_DELETE( this.m_clientAllocator, this.m_connection );
            this.m_messageFactory = YOJIMBO_DELETE( this.m_clientAllocator, this.m_messageFactory );
            this.m_clientAllocator = YOJIMBO_DELETE( this.m_allocator, this.m_clientAllocator );
        }
        else
        {
            // Nothing was ever built inside the client allocator, so nothing can be outstanding.
            this.m_networkSimulator = null;
            this.m_connection = null;
            this.m_messageFactory = null;
        }
        this.m_packetBuffer = YOJIMBO_FREE( this.m_allocator, this.m_packetBuffer );
    }

    protected SetClientState( clientState: ClientState ): void
    {
        this.m_clientState = clientState;
    }

    protected GetClientAllocator(): Allocator
    {
        yojimbo_assert( this.m_clientAllocator, "m_clientAllocator", "BaseClient::GetClientAllocator" );
        return this.m_clientAllocator;
    }

    protected GetMessageFactory(): MessageFactory
    {
        yojimbo_assert( this.m_messageFactory, "m_messageFactory", "BaseClient::GetMessageFactory" );
        return this.m_messageFactory;
    }

    protected GetNetworkSimulator(): NetworkSimulator | null
    {
        return this.m_networkSimulator;
    }

    protected GetEndpoint(): reliable_endpoint_t
    {
        return this.m_endpoint!;
    }

    protected GetConnection(): Connection
    {
        yojimbo_assert( this.m_connection, "m_connection", "BaseClient::GetConnection" );
        return this.m_connection;
    }

    protected abstract TransmitPacketFunction( packetSequence: number, packetData: Uint8Array, packetBytes: number ): void;

    protected abstract ProcessPacketFunction( packetSequence: number, packetData: Uint8Array, packetBytes: number ): boolean;

    protected static StaticTransmitPacketFunction( context: unknown, _index: bigint, packetSequence: number, packetData: Uint8Array, packetBytes: number ): void
    {
        const client = context as BaseClient;
        client.TransmitPacketFunction( packetSequence, packetData, packetBytes );
    }

    protected static StaticProcessPacketFunction( context: unknown, _index: bigint, packetSequence: number, packetData: Uint8Array, packetBytes: number ): boolean
    {
        const client = context as BaseClient;
        return client.ProcessPacketFunction( packetSequence, packetData, packetBytes );
    }

    protected static StaticAllocateFunction( context: unknown, bytes: number ): Uint8Array | null
    {
        yojimbo_assert( context, "context", "BaseClient::StaticAllocateFunction" );
        const allocator = context as Allocator;
        return YOJIMBO_ALLOCATE( allocator, bytes );
    }

    protected static StaticFreeFunction( context: unknown, pointer: unknown ): void
    {
        yojimbo_assert( context, "context", "BaseClient::StaticFreeFunction" );
        yojimbo_assert( pointer, "pointer", "BaseClient::StaticFreeFunction" );
        const allocator = context as Allocator;
        YOJIMBO_FREE( allocator, pointer as Uint8Array );
    }

    protected Reset(): void
    {
        if ( this.m_connection )
        {
            this.m_connection.Reset();
        }
    }
}

/** Fill network info from a reliable endpoint (shared by the client and the server). */

export function FillNetworkInfo( endpoint: reliable_endpoint_t, info: NetworkInfo ): void
{
    const counters = reliable_endpoint_counters( endpoint );
    info.numPacketsSent = counters[RELIABLE_ENDPOINT_COUNTER_NUM_PACKETS_SENT];
    info.numPacketsReceived = counters[RELIABLE_ENDPOINT_COUNTER_NUM_PACKETS_RECEIVED];
    info.numPacketsAcked = counters[RELIABLE_ENDPOINT_COUNTER_NUM_PACKETS_ACKED];
    info.RTT = reliable_endpoint_rtt( endpoint );
    info.minRTT = reliable_endpoint_rtt_min( endpoint );
    info.maxRTT = reliable_endpoint_rtt_max( endpoint );
    info.averageRTT = reliable_endpoint_rtt_avg( endpoint );
    info.averageJitter = reliable_endpoint_jitter_avg_vs_min_rtt( endpoint );
    info.maxJitter = reliable_endpoint_jitter_max_vs_min_rtt( endpoint );
    info.stddevJitter = reliable_endpoint_jitter_stddev_vs_avg_rtt( endpoint );
    info.packetLoss = reliable_endpoint_packet_loss( endpoint );
    const bandwidth = reliable_endpoint_bandwidth( endpoint );
    info.sentBandwidth = bandwidth.sent_bandwidth_kbps;
    info.receivedBandwidth = bandwidth.received_bandwidth_kbps;
    info.ackedBandwidth = bandwidth.acked_bandwidth_kbps;
}
