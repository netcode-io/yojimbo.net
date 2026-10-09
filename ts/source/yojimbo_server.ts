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
    TypeScript port of include/yojimbo_server.h + source/yojimbo_server.cpp (yojimbo 1.13.5).

    Port notes:
      - The ServerClientDisconnectReason enum is defined in yojimbo_base_server.ts and re-exported here (see that file).
      - netcode's allocations are checked against the global allocator, as in the client (see yojimbo_client.ts).
      - Under custom packet I/O (Adapter.UseCustomPacketIO) netcode's send and receive go through the adapter's
        SendPacket / ReceivePacket with yojimbo Addresses.
*/

import {
    netcode_server_config_t, netcode_default_server_config, netcode_server_create, netcode_server_destroy, netcode_server_start,
    netcode_server_stop, netcode_server_disconnect_client, netcode_server_disconnect_all_clients, netcode_server_receive_packet,
    netcode_server_free_packet, netcode_server_update, netcode_server_send_packet, netcode_server_client_connected,
    netcode_server_client_id, netcode_server_client_user_data, netcode_server_client_address, netcode_server_num_connected_clients,
    netcode_server_connect_loopback_client, netcode_server_disconnect_loopback_client, netcode_server_client_loopback,
    netcode_server_process_loopback_packet, netcode_server_get_port, netcode_server_client_disconnect_reason,
    NETCODE_KEY_BYTES, NETCODE_DEFAULT_MAX_CONNECT_TOKEN_LIFETIME, NETCODE_SERVER_CLIENT_DISCONNECT_REASON_SERVER_DISCONNECT,
    NETCODE_SERVER_CLIENT_DISCONNECT_REASON_TIMED_OUT,
    type netcode_server_t, type netcode_address_t,
} from '../netcode/netcode.ts';
import { reliable_endpoint_next_packet_sequence, reliable_endpoint_send_packet, reliable_endpoint_receive_packet, reliable_endpoint_reset } from '../reliable/reliable.ts';
import { KeyBytes, MaxClients, DefaultMaxConnectTokenLifetime } from '../include/yojimbo_constants.ts';
import type { Adapter } from '../include/yojimbo_adapter.ts';
import { Address } from './yojimbo_address.ts';
import { Allocator, YOJIMBO_FREE } from './yojimbo_allocator.ts';
import { ClientServerConfig } from './yojimbo_config.ts';
import {
    BaseServer,
    YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_NONE, YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_DISCONNECTED,
    YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_TIMED_OUT, YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_KICKED,
} from './yojimbo_base_server.ts';
import { AddressFromNetcode, AddressToNetcode, yojimbo_netcode_allocate_function, yojimbo_netcode_free_function } from './yojimbo_client.ts';
import { yojimbo_assert } from './yojimbo_platform.ts';

export {
    YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_NONE, YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_DISCONNECTED, YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_TIMED_OUT,
    YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_KICKED, YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_FAILED_TO_SERIALIZE, YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_DESYNC,
    YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_SEND_QUEUE_FULL, YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_BLOCKS_DISABLED,
    YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_MESSAGE_TOO_LARGE, YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_OUT_OF_MEMORY,
    YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_READ_PACKET_FAILED, GetServerClientDisconnectReasonString, type ServerClientDisconnectReason,
} from './yojimbo_base_server.ts';

/** Scratch out parameters for netcode_server_receive_packet. */
const receive_packet_bytes = { value: 0 };
const receive_packet_sequence = { value: 0n };

/** Simulator batch size (upstream: fixed size stack arrays). */
const MaxBatchPackets = 64;

/**
    Server implementation.
 */

export class Server extends BaseServer
{
    private m_server: netcode_server_t | null;
    private m_address: Address;                                 // original address passed to ctor
    private m_boundAddress: Address;                            // address after socket bind, eg. valid port. custom packet I/O: stays the ctor-supplied synthetic address (no socket bind)
    private m_privateKey: Uint8Array;
    private m_stopping: boolean;                                // true while Stop tears the server down. makes a reentrant Stop from an adapter callback during teardown a harmless no-op

    private m_batchPacketData = new Array<Uint8Array | null>( MaxBatchPackets ).fill( null );
    private m_batchPacketBytes = new Array<number>( MaxBatchPackets ).fill( 0 );
    private m_batchTo = new Array<number>( MaxBatchPackets ).fill( 0 );

    /**
        Server constructor.
        @param allocator The allocator for all memory used by the server.
        @param privateKey The private key for connect tokens (KeyBytes).
        @param address The address the server binds to.
        @param config The client/server configuration.
        @param adapter The adapter, used to create the allocators and message factories, for the connect/disconnect callbacks, and for custom packet I/O.
        @param time The current time in seconds.
     */

    constructor( allocator: Allocator, privateKey: Uint8Array, address: Address, config: ClientServerConfig, adapter: Adapter, time: number )
    {
        super( allocator, config, adapter, time );
        yojimbo_assert( KeyBytes === NETCODE_KEY_BYTES, "KeyBytes == NETCODE_KEY_BYTES", "Server::Server" );
        yojimbo_assert( DefaultMaxConnectTokenLifetime === NETCODE_DEFAULT_MAX_CONNECT_TOKEN_LIFETIME, "DefaultMaxConnectTokenLifetime == NETCODE_DEFAULT_MAX_CONNECT_TOKEN_LIFETIME", "Server::Server" );
        this.m_privateKey = privateKey.slice( 0, NETCODE_KEY_BYTES );
        this.m_address = address.Clone();
        this.m_boundAddress = address.Clone();
        this.m_server = null;
        this.m_stopping = false;
    }

    /**
        Server destructor.
        IMPORTANT: Please stop the server before destroying it!
     */

    override Dispose(): void
    {
        yojimbo_assert( !this.m_server, "!m_server", "Server::~Server" );
        super.Dispose();
    }

    override Start( maxClients: number ): boolean
    {
        yojimbo_assert( maxClients <= MaxClients, "maxClients <= MaxClients", "Server::Start" );

        if ( !super.Start( maxClients ) )
            return false;

        const addressString = this.m_address.ToString();

        const netcodeConfig = new netcode_server_config_t();
        netcode_default_server_config( netcodeConfig );
        netcodeConfig.protocol_id = this.m_config.protocolId;
        netcodeConfig.private_key.set( this.m_privateKey );
        netcodeConfig.allocator_context = this.GetGlobalAllocator();
        netcodeConfig.allocate_function = yojimbo_netcode_allocate_function;
        netcodeConfig.free_function     = yojimbo_netcode_free_function;
        netcodeConfig.max_connect_token_lifetime = this.m_config.maxConnectTokenLifetime;
        netcodeConfig.callback_context = this;
        netcodeConfig.connect_disconnect_callback = Server.StaticConnectDisconnectCallbackFunction;
        netcodeConfig.send_loopback_packet_callback = Server.StaticSendLoopbackPacketCallbackFunction;
        const useCustomPacketIO = this.GetAdapter().UseCustomPacketIO();
        if ( useCustomPacketIO )
        {
            netcodeConfig.override_send_and_receive = 1;
            netcodeConfig.send_packet_override = Server.StaticSendPacketOverride;
            netcodeConfig.receive_packet_override = Server.StaticReceivePacketOverride;
        }

        this.m_server = netcode_server_create( addressString, netcodeConfig, this.GetTime() );

        if ( !this.m_server )
        {
            this.Stop();
            return false;
        }

        netcode_server_start( this.m_server, maxClients );

        if ( !useCustomPacketIO )
            this.m_boundAddress.SetPort( netcode_server_get_port( this.m_server ) );

        return true;
    }

    override Stop(): void
    {
        // Stop-in-progress guard: netcode_server_stop below sends disconnect packets and fires
        // OnServerClientDisconnected, so an adapter callback can call Stop from inside this
        // teardown. That reentrant call must be a harmless no-op.
        if ( this.m_stopping )
            return;
        this.m_stopping = true;
        try
        {
            if ( this.m_server )
            {
                this.m_boundAddress = this.m_address.Clone();
                // Clear the member before stopping, so an adapter that calls Stop from inside a
                // teardown-time SendPacket callback can't re-enter here and stop/destroy the same
                // netcode server twice. ConnectDisconnectCallbackFunction handles m_server being null during this window.
                const server = this.m_server;
                this.m_server = null;
                netcode_server_stop( server );
                netcode_server_destroy( server );
            }
            super.Stop();
        }
        finally
        {
            this.m_stopping = false;
        }
    }

    DisconnectClient( clientIndex: number ): void
    {
        yojimbo_assert( this.m_server, "m_server", "Server::DisconnectClient" );
        // Record the kick, but only if no reason is set yet: when the disconnect comes from
        // BaseServer::AdvanceTime, the specific connection error reason is already recorded.
        if ( this.IsClientConnected( clientIndex ) && this.GetClientDisconnectReason( clientIndex ) === YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_NONE )
        {
            this.SetClientDisconnectReason( clientIndex, YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_KICKED );
        }
        netcode_server_disconnect_client( this.m_server, clientIndex );
        this.ResetClient( clientIndex );
    }

    DisconnectAllClients(): void
    {
        yojimbo_assert( this.m_server, "m_server", "Server::DisconnectAllClients" );
        const maxClients = this.GetMaxClients();
        for ( let i = 0; i < maxClients; ++i )
        {
            if ( this.IsClientConnected( i ) && this.GetClientDisconnectReason( i ) === YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_NONE )
            {
                this.SetClientDisconnectReason( i, YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_KICKED );
            }
        }
        netcode_server_disconnect_all_clients( this.m_server );
        for ( let i = 0; i < maxClients; ++i )
        {
            this.ResetClient( i );
        }
    }

    SendPackets(): void
    {
        if ( this.m_server )
        {
            const maxClients = this.GetMaxClients();
            const out = { packetBytes: 0 };
            for ( let i = 0; i < maxClients; ++i )
            {
                if ( this.IsClientConnected( i ) )
                {
                    const packetData = this.GetPacketBuffer();
                    const packetSequence = reliable_endpoint_next_packet_sequence( this.GetClientEndpoint( i ) );
                    if ( this.GetClientConnection( i ).GeneratePacket( this.GetContext(), packetSequence, packetData, this.m_config.maxPacketSize, out ) )
                    {
                        reliable_endpoint_send_packet( this.GetClientEndpoint( i ), packetData, out.packetBytes );
                    }
                }
                if ( !this.m_server )
                    break;          // stopped from inside a callback
            }
        }
    }

    ReceivePackets(): void
    {
        if ( this.m_server )
        {
            const maxClients = this.GetMaxClients();
            for ( let clientIndex = 0; clientIndex < maxClients; ++clientIndex )
            {
                while ( this.m_server )
                {
                    const packetData = netcode_server_receive_packet( this.m_server, clientIndex, receive_packet_bytes, receive_packet_sequence );
                    if ( !packetData )
                        break;
                    reliable_endpoint_receive_packet( this.GetClientEndpoint( clientIndex ), packetData, receive_packet_bytes.value );
                    if ( this.m_server )
                        netcode_server_free_packet( this.m_server, packetData );
                }
            }
        }
    }

    override AdvanceTime( time: number ): void
    {
        if ( this.m_server )
        {
            netcode_server_update( this.m_server, time );
        }
        super.AdvanceTime( time );
        const networkSimulator = this.GetNetworkSimulator();
        if ( networkSimulator && networkSimulator.IsActive() )
        {
            // Drain the simulator in fixed size batches.
            const packetData = this.m_batchPacketData;
            const packetBytes = this.m_batchPacketBytes;
            const to = this.m_batchTo;
            while ( true )
            {
                const numPackets = networkSimulator.ReceivePackets( MaxBatchPackets, packetData, packetBytes, to );
                if ( numPackets === 0 )
                    break;
                for ( let i = 0; i < numPackets; ++i )
                {
                    if ( this.m_server )
                        netcode_server_send_packet( this.m_server, to[i], packetData[i]!, packetBytes[i] );
                    YOJIMBO_FREE( networkSimulator.GetAllocator(), packetData[i] );
                    packetData[i] = null;
                }
            }
        }
    }

    IsClientConnected( clientIndex: number ): boolean
    {
        return this.m_server ? netcode_server_client_connected( this.m_server, clientIndex ) !== 0 : false;
    }

    GetClientId( clientIndex: number ): bigint
    {
        return this.m_server ? netcode_server_client_id( this.m_server, clientIndex ) : 0n;
    }

    GetClientUserData( clientIndex: number ): Uint8Array | null
    {
        return this.m_server ? netcode_server_client_user_data( this.m_server, clientIndex ) : null;
    }

    GetClientAddress( clientIndex: number ): netcode_address_t | null
    {
        return this.m_server ? netcode_server_client_address( this.m_server, clientIndex ) : null;
    }

    GetNumConnectedClients(): number
    {
        return this.m_server ? netcode_server_num_connected_clients( this.m_server ) : 0;
    }

    ConnectLoopbackClient( clientIndex: number, clientId: bigint, userData: Uint8Array | null ): void
    {
        yojimbo_assert( this.m_server, "m_server", "Server::ConnectLoopbackClient" );
        netcode_server_connect_loopback_client( this.m_server, clientIndex, clientId, userData );
    }

    DisconnectLoopbackClient( clientIndex: number ): void
    {
        yojimbo_assert( this.m_server, "m_server", "Server::DisconnectLoopbackClient" );
        // Same recording rule as DisconnectClient: disconnecting a loopback client is a kick,
        // and must not overwrite a more specific reason recorded before the disconnect.
        if ( this.IsClientConnected( clientIndex ) && this.GetClientDisconnectReason( clientIndex ) === YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_NONE )
        {
            this.SetClientDisconnectReason( clientIndex, YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_KICKED );
        }
        netcode_server_disconnect_loopback_client( this.m_server, clientIndex );
    }

    IsLoopbackClient( clientIndex: number ): boolean
    {
        return this.m_server ? netcode_server_client_loopback( this.m_server, clientIndex ) !== 0 : false;
    }

    ProcessLoopbackPacket( clientIndex: number, packetData: Uint8Array, packetBytes: number, packetSequence: bigint ): void
    {
        yojimbo_assert( this.m_server, "m_server", "Server::ProcessLoopbackPacket" );
        netcode_server_process_loopback_packet( this.m_server, clientIndex, packetData, packetBytes, packetSequence );
    }

    /**
        Gets the local address the server socket is bound to (with the actual port, when port 0 was passed in).
        Under custom packet I/O (Adapter::UseCustomPacketIO) there is no socket: this is the
        constructor-supplied synthetic address, unchanged.
     */

    GetAddress(): Address
    {
        return this.m_boundAddress;
    }

    protected TransmitPacketFunction( clientIndex: number, _packetSequence: number, packetData: Uint8Array, packetBytes: number ): void
    {
        const networkSimulator = this.GetNetworkSimulator();
        if ( networkSimulator && networkSimulator.IsActive() )
        {
            networkSimulator.SendPacket( clientIndex, packetData, packetBytes );
        }
        else if ( this.m_server )
        {
            netcode_server_send_packet( this.m_server, clientIndex, packetData, packetBytes );
        }
    }

    protected ProcessPacketFunction( clientIndex: number, packetSequence: number, packetData: Uint8Array, packetBytes: number ): boolean
    {
        return this.GetClientConnection( clientIndex ).ProcessPacket( this.GetContext(), packetSequence, packetData, packetBytes );
    }

    private ConnectDisconnectCallbackFunction( clientIndex: number, connected: number ): void
    {
        if ( connected === 0 )
        {
            // If no reason was recorded before the transport-level disconnect (connection error,
            // kick), ask netcode why: the client either timed out or cleanly disconnected.
            // Record it before the adapter callback, so OnServerClientDisconnected can query it.
            if ( this.GetClientDisconnectReason( clientIndex ) === YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_NONE )
            {
                // m_server is null while Stop tears the netcode server down (cleared before
                // netcode_server_stop, see Server::Stop). Disconnects delivered during that
                // window are always netcode SERVER_DISCONNECT, never TIMED_OUT.
                const netcodeReason = this.m_server ? netcode_server_client_disconnect_reason( this.m_server, clientIndex )
                                                    : NETCODE_SERVER_CLIENT_DISCONNECT_REASON_SERVER_DISCONNECT;
                this.SetClientDisconnectReason( clientIndex, netcodeReason === NETCODE_SERVER_CLIENT_DISCONNECT_REASON_TIMED_OUT
                                                                ? YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_TIMED_OUT
                                                                : YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_DISCONNECTED );
            }
            this.GetAdapter().OnServerClientDisconnected( clientIndex );
            if ( !this.IsRunning() )
                return;             // the adapter stopped the server from inside the callback
            reliable_endpoint_reset( this.GetClientEndpoint( clientIndex ) );
            this.GetClientConnection( clientIndex ).Reset();
            const networkSimulator = this.GetNetworkSimulator();
            if ( networkSimulator && networkSimulator.IsActive() )
            {
                networkSimulator.DiscardClientPackets( clientIndex );
            }
        }
        else
        {
            // This slot now belongs to a new client: clear any disconnect reason left behind by
            // the previous occupant of the slot.
            this.SetClientDisconnectReason( clientIndex, YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_NONE );
            this.GetAdapter().OnServerClientConnected( clientIndex );
        }
    }

    private SendLoopbackPacketCallbackFunction( clientIndex: number, packetData: Uint8Array, packetBytes: number, packetSequence: bigint ): void
    {
        this.GetAdapter().ServerSendLoopbackPacket( clientIndex, packetData, packetBytes, packetSequence );
    }

    private static StaticConnectDisconnectCallbackFunction( context: unknown, clientIndex: number, connected: number ): void
    {
        const server = context as Server;
        server.ConnectDisconnectCallbackFunction( clientIndex, connected );
    }

    private static StaticSendLoopbackPacketCallbackFunction( context: unknown, clientIndex: number, packetData: Uint8Array, packetBytes: number, packetSequence: bigint ): void
    {
        const server = context as Server;
        server.SendLoopbackPacketCallbackFunction( clientIndex, packetData, packetBytes, packetSequence );
    }

    private static StaticSendPacketOverride( context: unknown, to: netcode_address_t, packetData: Uint8Array, packetBytes: number ): void
    {
        const server = context as Server;
        const address = AddressFromNetcode( to );
        if ( address.IsValid() )
            server.GetAdapter().SendPacket( address, packetData, packetBytes );
    }

    private static StaticReceivePacketOverride( context: unknown, from: netcode_address_t, packetData: Uint8Array, maxPacketBytes: number ): number
    {
        const server = context as Server;
        const address = new Address();
        const packetBytes = server.GetAdapter().ReceivePacket( address, packetData, maxPacketBytes );
        if ( !( packetBytes > 0 ) || packetBytes > maxPacketBytes || !Number.isInteger( packetBytes ) || !AddressToNetcode( address, from ) )
            return 0;
        return packetBytes;
    }
}
