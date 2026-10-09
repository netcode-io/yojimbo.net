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
    TypeScript port of custom_packet_io_test.cpp (yojimbo 1.13.5).

    A client and server connect and exchange messages through Adapter custom packet I/O (an in-memory datagram
    transport, no sockets), then tear down with adapters that re-enter Disconnect / Stop from inside their own
    teardown-time SendPacket callbacks. This is the transport path a browser uses (no UDP).

        node custom_packet_io_test.ts
*/

import {
    InitializeYojimbo, ShutdownYojimbo, GetDefaultAllocator,
    Address, Client, Server, Message, ClientServerConfig, MaxAdapterPacketBytes, KeyBytes,
    CHANNEL_TYPE_RELIABLE_ORDERED, CHANNEL_TYPE_UNRELIABLE_UNORDERED,
} from './source/yojimbo.ts';
import { TestAdapter, TestMessage, TEST_MESSAGE } from './shared.ts';

class MemoryPacket
{
    from = new Address();
    bytes = 0;
    data = new Uint8Array( MaxAdapterPacketBytes );
}

class MemoryPacketAdapter extends TestAdapter
{
    private m_localAddress: Address;
    private m_peer: MemoryPacketAdapter | null = null;
    private m_packets: MemoryPacket[] = [];
    private m_sentPackets = 0;
    private m_receivedPackets = 0;

    constructor( localAddress: Address )
    {
        super();
        this.m_localAddress = localAddress.Clone();
    }

    Connect( peer: MemoryPacketAdapter ): void
    {
        this.m_peer = peer;
    }

    override UseCustomPacketIO(): boolean
    {
        return true;
    }

    override SendPacket( to: Address, packetData: Uint8Array, packetBytes: number ): void
    {
        if ( !this.m_peer || to.NotEquals( this.m_peer.m_localAddress ) || packetBytes <= 0 || packetBytes > MaxAdapterPacketBytes )
            return;

        // packetData is only valid during the call (and may be longer than packetBytes): copy it
        const packet = new MemoryPacket();
        packet.from.Assign( this.m_localAddress );
        packet.bytes = packetBytes;
        packet.data.set( packetData.subarray( 0, packetBytes ) );
        this.m_peer.m_packets.push( packet );
        ++this.m_sentPackets;
    }

    override ReceivePacket( from: Address, packetData: Uint8Array, maxPacketBytes: number ): number
    {
        const packet = this.m_packets.shift();
        if ( !packet )
            return 0;

        if ( packet.bytes > maxPacketBytes )
            return 0;

        from.Assign( packet.from );
        packetData.set( packet.data.subarray( 0, packet.bytes ) );
        ++this.m_receivedPackets;
        return packet.bytes;
    }

    SentPackets(): number { return this.m_sentPackets; }
    ReceivedPackets(): number { return this.m_receivedPackets; }
}

/**
    Hostile adapter for the teardown-reentrancy regression: once armed, every teardown-time
    SendPacket re-enters the owning object's own Disconnect/Stop from inside the callback.
    The stop-in-progress guards in Client::Disconnect and Server::Stop must make those
    reentrant calls harmless no-ops.
 */

class ReentrantTeardownAdapter extends MemoryPacketAdapter
{
    private m_client: Client | null = null;
    private m_server: Server | null = null;
    private m_teardown = false;
    private m_reentrantCalls = 0;

    BeginHostileTeardown( client: Client | null, server: Server | null ): void
    {
        this.m_client = client;
        this.m_server = server;
        this.m_teardown = true;
    }

    override SendPacket( to: Address, packetData: Uint8Array, packetBytes: number ): void
    {
        if ( this.m_teardown )
        {
            ++this.m_reentrantCalls;
            if ( this.m_client )
                this.m_client.Disconnect();
            if ( this.m_server )
                this.m_server.Stop();
        }
        super.SendPacket( to, packetData, packetBytes );
    }

    ReentrantCalls(): number { return this.m_reentrantCalls; }
}

function Require( condition: unknown, message: string ): boolean
{
    if ( condition )
        return true;
    console.log( `FAIL: ${message}` );
    return false;
}

function MakeConfig(): ClientServerConfig
{
    const config = new ClientServerConfig();
    config.numChannels = 2;
    config.channel[0].type = CHANNEL_TYPE_RELIABLE_ORDERED;
    config.channel[1].type = CHANNEL_TYPE_UNRELIABLE_UNORDERED;
    return config;
}

function Pump( client: Client, server: Server, state: { time: number } ): void
{
    client.SendPackets();
    server.SendPackets();
    client.ReceivePackets();
    server.ReceivePackets();
    state.time += 0.1;
    client.AdvanceTime( state.time );
    server.AdvanceTime( state.time );
}

function ExchangeMessages( client: Client, server: Server, state: { time: number }, toServerSequence: number, toClientSequence: number ): [ Message | null, Message | null ]
{
    const toServer = client.CreateMessage( TEST_MESSAGE ) as TestMessage | null;
    const toClient = server.CreateMessage( 0, TEST_MESSAGE ) as TestMessage | null;
    if ( !toServer || !toClient )
        return [ null, null ];

    toServer.sequence = toServerSequence;
    toClient.sequence = toClientSequence;
    client.SendMessage( 0, toServer );
    server.SendMessage( 0, 1, toClient );

    let fromClient: Message | null = null;
    let fromServer: Message | null = null;
    for ( let i = 0; i < 256 && ( !fromClient || !fromServer ); ++i )
    {
        client.SendPackets();
        server.SendPackets();
        client.ReceivePackets();
        server.ReceivePackets();
        if ( !fromClient )
            fromClient = server.ReceiveMessage( 0, 0 );
        if ( !fromServer )
            fromServer = client.ReceiveMessage( 1 );
        state.time += 0.1;
        client.AdvanceTime( state.time );
        server.AdvanceTime( state.time );
    }
    return [ fromClient, fromServer ];
}

function main(): number
{
    if ( !InitializeYojimbo() )
        return 1;

    let ok = true;

    const privateKey = new Uint8Array( KeyBytes );

    {
        const clientAddress = new Address( "203.0.113.2", 41230 );
        const serverAddress = new Address( "203.0.113.1", 41230 );
        const clientAdapter = new MemoryPacketAdapter( clientAddress );
        const serverAdapter = new MemoryPacketAdapter( serverAddress );
        clientAdapter.Connect( serverAdapter );
        serverAdapter.Connect( clientAdapter );

        const config = MakeConfig();

        const state = { time: 100.0 };

        const server = new Server( GetDefaultAllocator(), privateKey, serverAddress, config, serverAdapter, state.time );
        server.Start( 1 );
        const client = new Client( GetDefaultAllocator(), clientAddress, config, clientAdapter, state.time );
        client.InsecureConnect( privateKey, 1n, serverAddress );

        for ( let i = 0; i < 256 && !client.IsConnected(); ++i )
            Pump( client, server, state );

        ok = Require( client.GetAddress().Equals( clientAddress ), "client synthetic local address changed" ) && ok;
        ok = Require( server.GetAddress().Equals( serverAddress ), "server synthetic local address changed" ) && ok;
        ok = Require( client.IsConnected(), "client did not connect over custom packet I/O" ) && ok;
        ok = Require( server.GetNumConnectedClients() === 1, "server did not admit the custom-I/O client" ) && ok;
        ok = Require( clientAdapter.SentPackets() > 0 && clientAdapter.ReceivedPackets() > 0, "client adapter did not send and receive packets" ) && ok;
        ok = Require( serverAdapter.SentPackets() > 0 && serverAdapter.ReceivedPackets() > 0, "server adapter did not send and receive packets" ) && ok;

        const [ fromClient, fromServer ] = ExchangeMessages( client, server, state, 11, 22 );

        ok = Require( fromClient && ( fromClient as TestMessage ).sequence === 11, "reliable client message did not cross custom packet I/O" ) && ok;
        ok = Require( fromServer && ( fromServer as TestMessage ).sequence === 22, "unreliable server message did not cross custom packet I/O" ) && ok;
        if ( fromClient )
            server.ReleaseMessage( 0, fromClient );
        if ( fromServer )
            client.ReleaseMessage( fromServer );

        client.Disconnect();
        server.Stop();
        client.Dispose();
        server.Dispose();
    }

    // Scenario 2: hostile reentrant teardown. The test completing cleanly (no assert, no leak) is the proof that
    // teardown is reentrancy-safe.
    {
        const clientAddress = new Address( "203.0.113.2", 41230 );
        const serverAddress = new Address( "203.0.113.1", 41230 );
        const clientAdapter = new ReentrantTeardownAdapter( clientAddress );
        const serverAdapter = new ReentrantTeardownAdapter( serverAddress );
        clientAdapter.Connect( serverAdapter );
        serverAdapter.Connect( clientAdapter );

        const config = MakeConfig();

        const state = { time: 100.0 };

        const server = new Server( GetDefaultAllocator(), privateKey, serverAddress, config, serverAdapter, state.time );
        server.Start( 1 );
        const client = new Client( GetDefaultAllocator(), clientAddress, config, clientAdapter, state.time );
        client.InsecureConnect( privateKey, 1n, serverAddress );

        for ( let i = 0; i < 256 && !client.IsConnected(); ++i )
            Pump( client, server, state );

        ok = Require( client.IsConnected(), "client did not connect before the hostile teardown" ) && ok;
        ok = Require( server.GetNumConnectedClients() === 1, "server did not admit the client before the hostile teardown" ) && ok;

        const [ fromClient, fromServer ] = ExchangeMessages( client, server, state, 33, 44 );

        ok = Require( fromClient && fromServer, "messages did not cross before the hostile teardown" ) && ok;
        if ( fromClient )
            server.ReleaseMessage( 0, fromClient );
        if ( fromServer )
            client.ReleaseMessage( fromServer );

        // Arm the adapters, then tear down. Stop the server first, while the client is still
        // connected, so netcode_server_stop actually sends disconnect packets (the reentrancy
        // window). The client has not processed those packets, so its own disconnect also
        // sends packets and re-enters on the client side.
        serverAdapter.BeginHostileTeardown( null, server );
        clientAdapter.BeginHostileTeardown( client, null );
        server.Stop();
        client.Disconnect();

        // Prove the hostile path actually ran.
        ok = Require( serverAdapter.ReentrantCalls() > 0, "server teardown did not exercise the reentrant Stop path" ) && ok;
        ok = Require( clientAdapter.ReentrantCalls() > 0, "client teardown did not exercise the reentrant Disconnect path" ) && ok;

        // Teardown completed and the guards cleared: calling again must still be a safe no-op.
        server.Stop();
        client.Disconnect();

        client.Dispose();
        server.Dispose();
    }

    ShutdownYojimbo();

    if ( !ok )
        return 1;

    console.log( "OK: custom packet I/O handshake and hostile reentrant teardown passed without native sockets" );
    return 0;
}

try
{
    process.exitCode = main();
}
catch ( error )
{
    console.log( error instanceof Error ? ( error.stack ?? error.message ) : String( error ) );
    process.exitCode = 1;
}
