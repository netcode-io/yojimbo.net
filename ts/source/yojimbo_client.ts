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
    TypeScript port of include/yojimbo_client.h + source/yojimbo_client.cpp (yojimbo 1.13.5), plus the address
    conversion helpers of source/yojimbo_address_conversion.h.

    Port notes:
      - The ClientDisconnectReason enum is defined in yojimbo_base_client.ts and re-exported here (see that file).
      - netcode's allocate_function only reports success or failure (netcode allocates its own JS objects) and its
        free_function is called with the object being released, not with what allocate returned. So the client
        routes netcode's allocations through the client allocator as a check (the allocation is made and returned
        at once, so allocator exhaustion still fails netcode exactly where it fails upstream) and frees nothing.
      - Under custom packet I/O (Adapter.UseCustomPacketIO) netcode's send and receive go through the adapter's
        SendPacket / ReceivePacket with yojimbo Addresses.
      - Connect tokens are Uint8Array( ConnectTokenBytes ); client ids are bigint.
*/

import {
    netcode_client_config_t, netcode_default_client_config, netcode_client_create, netcode_client_destroy, netcode_client_connect,
    netcode_client_state, netcode_client_receive_packet, netcode_client_free_packet, netcode_client_update, netcode_client_send_packet,
    netcode_client_index, netcode_client_connect_loopback, netcode_client_disconnect_loopback, netcode_client_loopback,
    netcode_client_process_loopback_packet, netcode_client_get_port, netcode_generate_connect_token,
    netcode_address_t, netcode_address_zero,
    NETCODE_OK, NETCODE_CONNECT_TOKEN_BYTES, NETCODE_MAX_SERVERS_PER_CONNECT, NETCODE_USER_DATA_BYTES, NETCODE_ADDRESS_IPV4, NETCODE_ADDRESS_IPV6,
    NETCODE_CLIENT_STATE_CONNECT_TOKEN_EXPIRED, NETCODE_CLIENT_STATE_INVALID_CONNECT_TOKEN, NETCODE_CLIENT_STATE_CONNECTION_TIMED_OUT,
    NETCODE_CLIENT_STATE_CONNECTION_RESPONSE_TIMED_OUT, NETCODE_CLIENT_STATE_CONNECTION_REQUEST_TIMED_OUT, NETCODE_CLIENT_STATE_CONNECTION_DENIED,
    NETCODE_CLIENT_STATE_DISCONNECTED, NETCODE_CLIENT_STATE_SENDING_CONNECTION_REQUEST, NETCODE_CLIENT_STATE_SENDING_CONNECTION_RESPONSE,
    type netcode_client_t,
} from '../netcode/netcode.ts';
import { reliable_endpoint_next_packet_sequence, reliable_endpoint_send_packet, reliable_endpoint_receive_packet } from '../reliable/reliable.ts';
import { CLIENT_STATE_ERROR, CLIENT_STATE_DISCONNECTED, CLIENT_STATE_CONNECTING, CLIENT_STATE_CONNECTED } from '../include/yojimbo_client_interface.ts';
import { InsecureConnectTokenExpirySeconds } from '../include/yojimbo_constants.ts';
import type { Adapter } from '../include/yojimbo_adapter.ts';
import { Address, ADDRESS_IPV4, ADDRESS_IPV6 } from './yojimbo_address.ts';
import { Allocator, YOJIMBO_ALLOCATE, YOJIMBO_FREE } from './yojimbo_allocator.ts';
import { ClientServerConfig } from './yojimbo_config.ts';
import {
    BaseClient,
    YOJIMBO_CLIENT_DISCONNECT_REASON_NONE, YOJIMBO_CLIENT_DISCONNECT_REASON_DISCONNECTED, YOJIMBO_CLIENT_DISCONNECT_REASON_DISCONNECTED_BY_SERVER,
    YOJIMBO_CLIENT_DISCONNECT_REASON_CONNECTION_DENIED, YOJIMBO_CLIENT_DISCONNECT_REASON_CONNECTION_REQUEST_TIMED_OUT,
    YOJIMBO_CLIENT_DISCONNECT_REASON_CONNECTION_RESPONSE_TIMED_OUT, YOJIMBO_CLIENT_DISCONNECT_REASON_CONNECTION_TIMED_OUT,
    YOJIMBO_CLIENT_DISCONNECT_REASON_INVALID_CONNECT_TOKEN, YOJIMBO_CLIENT_DISCONNECT_REASON_CONNECT_TOKEN_EXPIRED,
    YOJIMBO_CLIENT_DISCONNECT_REASON_OUT_OF_MEMORY,
} from './yojimbo_base_client.ts';
import { yojimbo_assert, yojimbo_printf, YOJIMBO_LOG_LEVEL_ERROR } from './yojimbo_platform.ts';
import { yojimbo_max } from './yojimbo_utils.ts';

export {
    YOJIMBO_CLIENT_DISCONNECT_REASON_NONE, YOJIMBO_CLIENT_DISCONNECT_REASON_DISCONNECTED, YOJIMBO_CLIENT_DISCONNECT_REASON_DISCONNECTED_BY_SERVER,
    YOJIMBO_CLIENT_DISCONNECT_REASON_CONNECTION_DENIED, YOJIMBO_CLIENT_DISCONNECT_REASON_CONNECTION_REQUEST_TIMED_OUT,
    YOJIMBO_CLIENT_DISCONNECT_REASON_CONNECTION_RESPONSE_TIMED_OUT, YOJIMBO_CLIENT_DISCONNECT_REASON_CONNECTION_TIMED_OUT,
    YOJIMBO_CLIENT_DISCONNECT_REASON_INVALID_CONNECT_TOKEN, YOJIMBO_CLIENT_DISCONNECT_REASON_CONNECT_TOKEN_EXPIRED,
    YOJIMBO_CLIENT_DISCONNECT_REASON_FAILED_TO_SERIALIZE, YOJIMBO_CLIENT_DISCONNECT_REASON_DESYNC, YOJIMBO_CLIENT_DISCONNECT_REASON_SEND_QUEUE_FULL,
    YOJIMBO_CLIENT_DISCONNECT_REASON_BLOCKS_DISABLED, YOJIMBO_CLIENT_DISCONNECT_REASON_MESSAGE_TOO_LARGE, YOJIMBO_CLIENT_DISCONNECT_REASON_OUT_OF_MEMORY,
    YOJIMBO_CLIENT_DISCONNECT_REASON_READ_PACKET_FAILED, GetClientDisconnectReasonString, type ClientDisconnectReason,
} from './yojimbo_base_client.ts';

// ---------------------------------------------------------------------------------------------
// yojimbo_address_conversion.h

/** Convert a netcode address to a yojimbo address (ADDRESS_NONE if it is not IPv4 or IPv6). */

export function AddressFromNetcode( address: netcode_address_t ): Address
{
    if ( address.type === NETCODE_ADDRESS_IPV4 )
        return new Address( address.data.ipv4, address.port );
    if ( address.type === NETCODE_ADDRESS_IPV6 )
        return new Address( address.data.ipv6, address.port );
    return new Address();
}

/** Convert a yojimbo address to a netcode address, in place. Returns false (with result zeroed) if the address is not valid. */

export function AddressToNetcode( address: Address, result: netcode_address_t ): boolean
{
    netcode_address_zero( result );
    result.port = address.GetPort();
    if ( address.GetType() === ADDRESS_IPV4 )
    {
        result.type = NETCODE_ADDRESS_IPV4;
        result.data.ipv4.set( address.GetAddress4() );
        return true;
    }
    if ( address.GetType() === ADDRESS_IPV6 )
    {
        result.type = NETCODE_ADDRESS_IPV6;
        result.data.ipv6.set( address.GetAddress6() );
        return true;
    }
    return false;
}

/** netcode allocate_function: the allocation is checked against the yojimbo allocator (see header). */

export function yojimbo_netcode_allocate_function( context: unknown, bytes: number ): unknown
{
    yojimbo_assert( context, "context", "yojimbo_netcode_allocate_function" );
    const allocator = context as Allocator;
    const p = YOJIMBO_ALLOCATE( allocator, bytes );
    if ( !p )
        return null;
    YOJIMBO_FREE( allocator, p );
    return true;
}

/** netcode free_function: nothing to return to the allocator (see header). */

export function yojimbo_netcode_free_function( _context: unknown, _pointer: unknown ): void
{
}

// ---------------------------------------------------------------------------------------------

// Map a netcode client error state to the disconnect reason we record for this client.
// This is where "server is full" vs "update your client" vs "network problem" comes from.
function ClientDisconnectReasonForNetcodeState( netcodeState: number ): number
{
    switch ( netcodeState )
    {
        case NETCODE_CLIENT_STATE_CONNECT_TOKEN_EXPIRED:            return YOJIMBO_CLIENT_DISCONNECT_REASON_CONNECT_TOKEN_EXPIRED;
        case NETCODE_CLIENT_STATE_INVALID_CONNECT_TOKEN:            return YOJIMBO_CLIENT_DISCONNECT_REASON_INVALID_CONNECT_TOKEN;
        case NETCODE_CLIENT_STATE_CONNECTION_TIMED_OUT:             return YOJIMBO_CLIENT_DISCONNECT_REASON_CONNECTION_TIMED_OUT;
        case NETCODE_CLIENT_STATE_CONNECTION_RESPONSE_TIMED_OUT:    return YOJIMBO_CLIENT_DISCONNECT_REASON_CONNECTION_RESPONSE_TIMED_OUT;
        case NETCODE_CLIENT_STATE_CONNECTION_REQUEST_TIMED_OUT:     return YOJIMBO_CLIENT_DISCONNECT_REASON_CONNECTION_REQUEST_TIMED_OUT;
        case NETCODE_CLIENT_STATE_CONNECTION_DENIED:                return YOJIMBO_CLIENT_DISCONNECT_REASON_CONNECTION_DENIED;
        default:                                                    return YOJIMBO_CLIENT_DISCONNECT_REASON_DISCONNECTED_BY_SERVER;
    }
}

/** Scratch out parameters for netcode_client_receive_packet. */
const receive_packet_bytes = { value: 0 };
const receive_packet_sequence = { value: 0n };

/** Simulator batch scratch (upstream: fixed size stack arrays). */
const MaxBatchPackets = 64;

/**
    Client implementation.
 */

export class Client extends BaseClient
{
    private m_client: netcode_client_t | null;              ///< netcode client data.
    private m_address: Address;                             ///< Original address passed to ctor.
    private m_boundAddress: Address;                        ///< Address after socket bind, eg. with valid port. Custom packet I/O: stays the ctor-supplied synthetic address (no socket bind).
    private m_clientId: bigint;                             ///< The globally unique client id (set on each call to connect)
    private m_disconnecting: boolean;                       ///< True while Disconnect tears the client down. Makes a reentrant Disconnect from an adapter callback during teardown a harmless no-op.

    private m_batchPacketData = new Array<Uint8Array | null>( MaxBatchPackets ).fill( null );
    private m_batchPacketBytes = new Array<number>( MaxBatchPackets ).fill( 0 );

    /**
        The client constructor.
        @param allocator The allocator for all memory used by the client.
        @param address The address the client should bind to.
        @param config The client/server configuration.
        @param adapter The adapter, used to create the allocator and message factory, and for custom packet I/O.
        @param time The current time in seconds.
     */

    constructor( allocator: Allocator, address: Address, config: ClientServerConfig, adapter: Adapter, time: number )
    {
        super( allocator, config, adapter, time );
        this.m_address = address.Clone();
        this.m_clientId = 0n;
        this.m_client = null;
        this.m_boundAddress = this.m_address.Clone();
        this.m_disconnecting = false;
    }

    /**
        Client destructor.
        IMPORTANT: Please disconnect the client before destroying it.
     */

    override Dispose(): void
    {
        yojimbo_assert( this.m_client == null, "m_client == NULL", "Client::~Client" );
        super.Dispose();
    }

    /**
        Connect to a server with a locally generated connect token (insecure: the private key is on the client).
        @param privateKey The private key (KeyBytes).
        @param clientId The unique client id.
        @param serverAddresses The server address, or an array of up to NETCODE_MAX_SERVERS_PER_CONNECT addresses to try in order.
        @returns True if the connect attempt started. False if it failed immediately (out of memory, socket, connect token).
     */

    InsecureConnect( privateKey: Uint8Array, clientId: bigint, serverAddresses: Address | readonly Address[], numServerAddresses?: number ): boolean
    {
        const addresses = serverAddresses instanceof Address ? [ serverAddresses ] : serverAddresses;
        const count = numServerAddresses ?? addresses.length;
        yojimbo_assert( addresses, "serverAddresses", "Client::InsecureConnect" );
        yojimbo_assert( count > 0, "numServerAddresses > 0", "Client::InsecureConnect" );
        yojimbo_assert( count <= NETCODE_MAX_SERVERS_PER_CONNECT, "numServerAddresses <= NETCODE_MAX_SERVERS_PER_CONNECT", "Client::InsecureConnect" );
        this.Disconnect();
        if ( !this.CreateInternal() )
        {
            // Out of memory. CreateInternal already unwound everything it had allocated, so the
            // client is exactly as it was before this call: disconnected and holding nothing.
            this.SetDisconnectReason( YOJIMBO_CLIENT_DISCONNECT_REASON_OUT_OF_MEMORY );
            this.SetClientState( CLIENT_STATE_ERROR );
            return false;
        }
        this.SetDisconnectReason( YOJIMBO_CLIENT_DISCONNECT_REASON_NONE );       // new connect attempt: clear the reason from any previous disconnect
        this.m_clientId = clientId;
        this.CreateClient( this.m_address );
        if ( !this.m_client )
        {
            this.Disconnect();
            return false;
        }
        const connectToken = new Uint8Array( NETCODE_CONNECT_TOKEN_BYTES );
        if ( !this.GenerateInsecureConnectToken( connectToken, privateKey, clientId, addresses, count ) )
        {
            yojimbo_printf( YOJIMBO_LOG_LEVEL_ERROR, "error: failed to generate insecure connect token\n" );
            this.SetDisconnectReason( YOJIMBO_CLIENT_DISCONNECT_REASON_INVALID_CONNECT_TOKEN );
            this.SetClientState( CLIENT_STATE_ERROR );
            return false;
        }
        netcode_client_connect( this.m_client, connectToken );
        this.SetClientState( CLIENT_STATE_CONNECTING );
        return true;
    }

    private GenerateInsecureConnectToken( connectToken: Uint8Array, privateKey: Uint8Array, clientId: bigint, serverAddresses: readonly Address[], numServerAddresses: number ): boolean
    {
        const serverAddressStrings: string[] = [];
        for ( let i = 0; i < numServerAddresses; ++i )
            serverAddressStrings.push( serverAddresses[i].ToString() );

        const userData = new Uint8Array( NETCODE_USER_DATA_BYTES );

        // Give the insecure connect token an expiry well above the connection timeout, so a
        // failed insecure connect reports "connection request timed out" just like a secure
        // connect token from a matchmaker would.
        const expireSeconds = yojimbo_max( InsecureConnectTokenExpirySeconds, this.m_config.timeout * 2 );

        return netcode_generate_connect_token( numServerAddresses,
                                               serverAddressStrings,
                                               serverAddressStrings,
                                               expireSeconds,
                                               this.m_config.timeout,
                                               clientId,
                                               this.m_config.protocolId,
                                               privateKey,
                                               userData,
                                               connectToken ) === NETCODE_OK;
    }

    /**
        Connect to a server with a connect token from a matchmaker.
        @param clientId The unique client id.
        @param connectToken The connect token (ConnectTokenBytes).
        @returns True if the connect attempt started. False if it failed immediately; see GetDisconnectReason.
     */

    Connect( clientId: bigint, connectToken: Uint8Array ): boolean
    {
        yojimbo_assert( connectToken, "connectToken", "Client::Connect" );
        this.Disconnect();
        if ( !this.CreateInternal() )
        {
            this.SetDisconnectReason( YOJIMBO_CLIENT_DISCONNECT_REASON_OUT_OF_MEMORY );
            this.SetClientState( CLIENT_STATE_ERROR );
            return false;
        }
        this.SetDisconnectReason( YOJIMBO_CLIENT_DISCONNECT_REASON_NONE );       // new connect attempt: clear the reason from any previous disconnect
        this.m_clientId = clientId;
        this.CreateClient( this.m_address );
        if ( !this.m_client )
        {
            // Socket creation/bind failed (e.g. port in use, invalid bind address). Bail before
            // calling into netcode, which dereferences the client without checking.
            this.Disconnect();
            return false;
        }
        netcode_client_connect( this.m_client, connectToken );
        if ( netcode_client_state( this.m_client ) > NETCODE_CLIENT_STATE_DISCONNECTED )
        {
            this.SetClientState( CLIENT_STATE_CONNECTING );
            return true;
        }
        // The connect failed immediately, eg. an invalid connect token.
        this.SetDisconnectReason( ClientDisconnectReasonForNetcodeState( netcode_client_state( this.m_client ) ) );
        this.Disconnect();
        return false;
    }

    override Disconnect(): void
    {
        // Stop-in-progress guard: netcode_client_destroy (inside DestroyClient below) sends
        // disconnect packets, so an adapter SendPacket callback can call Disconnect from inside
        // this teardown. That reentrant call must be a harmless no-op.
        if ( this.m_disconnecting )
            return;
        this.m_disconnecting = true;
        try
        {
            // Record a deliberate local disconnect, but only if no more specific reason was already
            // recorded (connection error, netcode error state) — the first reason recorded wins.
            if ( ( this.IsConnecting() || this.IsConnected() ) && this.GetDisconnectReason() === YOJIMBO_CLIENT_DISCONNECT_REASON_NONE )
            {
                this.SetDisconnectReason( YOJIMBO_CLIENT_DISCONNECT_REASON_DISCONNECTED );
            }
            super.Disconnect();
            this.DestroyClient();
            this.DestroyInternal();
            this.m_clientId = 0n;
        }
        finally
        {
            this.m_disconnecting = false;
        }
    }

    SendPackets(): void
    {
        if ( !this.IsConnected() )
            return;
        yojimbo_assert( this.m_client, "m_client", "Client::SendPackets" );
        const packetData = this.GetPacketBuffer();
        const out = { packetBytes: 0 };
        const packetSequence = reliable_endpoint_next_packet_sequence( this.GetEndpoint() );
        if ( this.GetConnection().GeneratePacket( this.GetContext(), packetSequence, packetData, this.m_config.maxPacketSize, out ) )
        {
            reliable_endpoint_send_packet( this.GetEndpoint(), packetData, out.packetBytes );
        }
    }

    ReceivePackets(): void
    {
        if ( !this.IsConnected() )
            return;
        yojimbo_assert( this.m_client, "m_client", "Client::ReceivePackets" );
        while ( true )
        {
            const packetData = netcode_client_receive_packet( this.m_client, receive_packet_bytes, receive_packet_sequence );
            if ( !packetData )
                break;
            reliable_endpoint_receive_packet( this.GetEndpoint(), packetData, receive_packet_bytes.value );
            netcode_client_free_packet( this.m_client, packetData );
            if ( !this.m_client )
                break;          // a callback disconnected the client
        }
    }

    override AdvanceTime( time: number ): void
    {
        super.AdvanceTime( time );
        if ( this.m_client )
        {
            netcode_client_update( this.m_client, time );
            const state = netcode_client_state( this.m_client );
            if ( state < NETCODE_CLIENT_STATE_DISCONNECTED )
            {
                // Record why netcode failed (denied, token expired/invalid, timed out) before the
                // disconnect, so the game can tell the player what actually happened.
                if ( this.GetDisconnectReason() === YOJIMBO_CLIENT_DISCONNECT_REASON_NONE )
                {
                    this.SetDisconnectReason( ClientDisconnectReasonForNetcodeState( state ) );
                }
                this.Disconnect();
                this.SetClientState( CLIENT_STATE_ERROR );
            }
            else if ( state === NETCODE_CLIENT_STATE_DISCONNECTED )
            {
                // netcode dropped to disconnected while we thought we were connecting/connected:
                // the server disconnected us (server stopped, or kicked this client).
                if ( this.GetDisconnectReason() === YOJIMBO_CLIENT_DISCONNECT_REASON_NONE )
                {
                    this.SetDisconnectReason( YOJIMBO_CLIENT_DISCONNECT_REASON_DISCONNECTED_BY_SERVER );
                }
                this.Disconnect();
                this.SetClientState( CLIENT_STATE_DISCONNECTED );
            }
            else if ( state === NETCODE_CLIENT_STATE_SENDING_CONNECTION_REQUEST || state === NETCODE_CLIENT_STATE_SENDING_CONNECTION_RESPONSE )
            {
                this.SetClientState( CLIENT_STATE_CONNECTING );
            }
            else
            {
                this.SetClientState( CLIENT_STATE_CONNECTED );
            }
            const networkSimulator = this.GetNetworkSimulator();
            if ( networkSimulator && networkSimulator.IsActive() )
            {
                // Drain the simulator in fixed size batches.
                const packetData = this.m_batchPacketData;
                const packetBytes = this.m_batchPacketBytes;
                while ( true )
                {
                    const numPackets = networkSimulator.ReceivePackets( MaxBatchPackets, packetData, packetBytes, null );
                    if ( numPackets === 0 )
                        break;
                    for ( let i = 0; i < numPackets; ++i )
                    {
                        if ( this.m_client )
                            netcode_client_send_packet( this.m_client, packetData[i]!, packetBytes[i] );
                        YOJIMBO_FREE( networkSimulator.GetAllocator(), packetData[i] );
                        packetData[i] = null;
                    }
                }
            }
        }
    }

    override GetClientIndex(): number
    {
        return this.m_client ? netcode_client_index( this.m_client ) : -1;
    }

    GetClientId(): bigint
    {
        return this.m_clientId;
    }

    ConnectLoopback( clientIndex: number, clientId: bigint, maxClients: number ): boolean
    {
        this.Disconnect();
        if ( !this.CreateInternal() )
        {
            this.SetDisconnectReason( YOJIMBO_CLIENT_DISCONNECT_REASON_OUT_OF_MEMORY );
            this.SetClientState( CLIENT_STATE_ERROR );
            return false;
        }
        this.SetDisconnectReason( YOJIMBO_CLIENT_DISCONNECT_REASON_NONE );       // new connect attempt: clear the reason from any previous disconnect
        this.m_clientId = clientId;
        this.CreateClient( this.m_address );
        if ( !this.m_client )
        {
            // Socket creation/bind failed. Bail before netcode dereferences the client.
            this.Disconnect();
            return false;
        }
        netcode_client_connect_loopback( this.m_client, clientIndex, maxClients );
        this.SetClientState( CLIENT_STATE_CONNECTED );
        return true;
    }

    DisconnectLoopback(): void
    {
        // Same stop-in-progress guard as Client::Disconnect.
        if ( this.m_disconnecting )
            return;
        this.m_disconnecting = true;
        try
        {
            // Same recording rule as Client::Disconnect: a deliberate local disconnect, unless a more
            // specific reason was already recorded.
            if ( ( this.IsConnecting() || this.IsConnected() ) && this.GetDisconnectReason() === YOJIMBO_CLIENT_DISCONNECT_REASON_NONE )
            {
                this.SetDisconnectReason( YOJIMBO_CLIENT_DISCONNECT_REASON_DISCONNECTED );
            }
            if ( this.m_client )
                netcode_client_disconnect_loopback( this.m_client );
            super.Disconnect();
            this.DestroyClient();
            this.DestroyInternal();
            this.m_clientId = 0n;
        }
        finally
        {
            this.m_disconnecting = false;
        }
    }

    IsLoopback(): boolean
    {
        // Safe to query in any state: when not connected there is no netcode client, so this is
        // not a loopback client.
        return this.m_client ? ( netcode_client_loopback( this.m_client ) !== 0 ) : false;
    }

    ProcessLoopbackPacket( packetData: Uint8Array, packetBytes: number, packetSequence: bigint ): void
    {
        yojimbo_assert( this.m_client, "m_client", "Client::ProcessLoopbackPacket" );
        netcode_client_process_loopback_packet( this.m_client, packetData, packetBytes, packetSequence );
    }

    /**
        Gets the local address the client socket is bound to (with the actual port, when port 0 was passed in).
        Under custom packet I/O (Adapter::UseCustomPacketIO) there is no socket: this is the
        constructor-supplied synthetic address, unchanged.
     */

    GetAddress(): Address
    {
        return this.m_boundAddress;
    }

    private CreateClient( address: Address ): void
    {
        this.DestroyClient();
        const addressString = address.ToString();

        const netcodeConfig = new netcode_client_config_t();
        netcode_default_client_config( netcodeConfig );
        netcodeConfig.allocator_context             = this.GetClientAllocator();
        netcodeConfig.allocate_function             = yojimbo_netcode_allocate_function;
        netcodeConfig.free_function                 = yojimbo_netcode_free_function;
        netcodeConfig.callback_context              = this;
        netcodeConfig.state_change_callback         = Client.StaticStateChangeCallbackFunction;
        netcodeConfig.send_loopback_packet_callback = Client.StaticSendLoopbackPacketCallbackFunction;
        const useCustomPacketIO = this.GetAdapter().UseCustomPacketIO();
        if ( useCustomPacketIO )
        {
            netcodeConfig.override_send_and_receive = 1;
            netcodeConfig.send_packet_override = Client.StaticSendPacketOverride;
            netcodeConfig.receive_packet_override = Client.StaticReceivePacketOverride;
        }
        this.m_client = netcode_client_create( addressString, netcodeConfig, this.GetTime() );

        if ( this.m_client )
        {
            if ( !useCustomPacketIO )
                this.m_boundAddress.SetPort( netcode_client_get_port( this.m_client ) );
        }
    }

    private DestroyClient(): void
    {
        if ( this.m_client )
        {
            this.m_boundAddress = this.m_address.Clone();
            // Clear the member before destroying, so an adapter that calls Disconnect from
            // inside a teardown-time SendPacket callback can't re-enter here and destroy
            // the same netcode client twice.
            const client = this.m_client;
            this.m_client = null;
            netcode_client_destroy( client );
        }
    }

    private StateChangeCallbackFunction( _previous: number, _current: number ): void
    {
    }

    private static StaticStateChangeCallbackFunction( context: unknown, previous: number, current: number ): void
    {
        const client = context as Client;
        client.StateChangeCallbackFunction( previous, current );
    }

    protected TransmitPacketFunction( _packetSequence: number, packetData: Uint8Array, packetBytes: number ): void
    {
        const networkSimulator = this.GetNetworkSimulator();
        if ( networkSimulator && networkSimulator.IsActive() )
        {
            networkSimulator.SendPacket( 0, packetData, packetBytes );
        }
        else if ( this.m_client )
        {
            netcode_client_send_packet( this.m_client, packetData, packetBytes );
        }
    }

    protected ProcessPacketFunction( packetSequence: number, packetData: Uint8Array, packetBytes: number ): boolean
    {
        return this.GetConnection().ProcessPacket( this.GetContext(), packetSequence, packetData, packetBytes );
    }

    private SendLoopbackPacketCallbackFunction( clientIndex: number, packetData: Uint8Array, packetBytes: number, packetSequence: bigint ): void
    {
        this.GetAdapter().ClientSendLoopbackPacket( clientIndex, packetData, packetBytes, packetSequence );
    }

    private static StaticSendLoopbackPacketCallbackFunction( context: unknown, clientIndex: number, packetData: Uint8Array, packetBytes: number, packetSequence: bigint ): void
    {
        const client = context as Client;
        client.SendLoopbackPacketCallbackFunction( clientIndex, packetData, packetBytes, packetSequence );
    }

    private static StaticSendPacketOverride( context: unknown, to: netcode_address_t, packetData: Uint8Array, packetBytes: number ): void
    {
        const client = context as Client;
        const address = AddressFromNetcode( to );
        if ( address.IsValid() )
            client.GetAdapter().SendPacket( address, packetData, packetBytes );
    }

    private static StaticReceivePacketOverride( context: unknown, from: netcode_address_t, packetData: Uint8Array, maxPacketBytes: number ): number
    {
        const client = context as Client;
        const address = new Address();
        const packetBytes = client.GetAdapter().ReceivePacket( address, packetData, maxPacketBytes );
        if ( !( packetBytes > 0 ) || packetBytes > maxPacketBytes || !Number.isInteger( packetBytes ) || !AddressToNetcode( address, from ) )
            return 0;
        return packetBytes;
    }
}

