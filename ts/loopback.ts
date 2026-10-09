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
    TypeScript port of loopback.cpp (yojimbo 1.13.5): a server with a loopback client in the same process (no sockets
    between them; packets are handed across by the adapter's loopback callbacks).

        node loopback.ts

    Ctrl-C stops it.
*/

import {
    InitializeYojimbo, ShutdownYojimbo, GetDefaultAllocator, yojimbo_log_level, YOJIMBO_LOG_LEVEL_INFO, yojimbo_assert,
    yojimbo_random_bytes, yojimbo_sleep, yojimbo_srand, YOJIMBO_NEW,
    Adapter, Allocator, MessageFactory, Address, Client, Server, ClientServerConfig, KeyBytes, MaxClients,
} from './source/yojimbo.ts';
import { TestMessageFactory, ServerPort } from './shared.ts';

let quit = false;

function interrupt_handler(): void
{
    quit = true;
}

class LoopbackAdapter extends Adapter
{
    client: Client | null = null;
    server: Server | null = null;

    override CreateMessageFactory( allocator: Allocator ): MessageFactory | null
    {
        return YOJIMBO_NEW( allocator, () => new TestMessageFactory( allocator ) );
    }

    override ClientSendLoopbackPacket( clientIndex: number, packetData: Uint8Array, packetBytes: number, packetSequence: bigint ): void
    {
        yojimbo_assert( this.server, "server" );
        this.server.ProcessLoopbackPacket( clientIndex, packetData, packetBytes, packetSequence );
    }

    override ServerSendLoopbackPacket( clientIndex: number, packetData: Uint8Array, packetBytes: number, packetSequence: bigint ): void
    {
        yojimbo_assert( this.client, "client" );
        yojimbo_assert( clientIndex === 0, "clientIndex == 0" );
        this.client.ProcessLoopbackPacket( packetData, packetBytes, packetSequence );
    }
}

async function ClientServerMain(): Promise<number>
{
    let time = 100.0;

    const config = new ClientServerConfig();

    const loopbackAdapter = new LoopbackAdapter();

    const privateKey = new Uint8Array( KeyBytes );

    console.log( `starting server on port ${ServerPort}` );

    const server = new Server( GetDefaultAllocator(), privateKey, new Address( "127.0.0.1", ServerPort ), config, loopbackAdapter, time );

    server.Start( MaxClients );

    if ( !server.IsRunning() )
    {
        server.Dispose();
        return 1;
    }

    console.log( "started server" );

    const clientIdBytes = new Uint8Array( 8 );
    yojimbo_random_bytes( clientIdBytes, 8 );
    const clientId = new DataView( clientIdBytes.buffer ).getBigUint64( 0, true );
    console.log( `client id is ${clientId.toString( 16 ).padStart( 16, "0" )}` );

    const client = new Client( GetDefaultAllocator(), new Address( "0.0.0.0" ), config, loopbackAdapter, time );

    client.ConnectLoopback( 0, clientId, MaxClients );

    server.ConnectLoopbackClient( 0, clientId, null );

    loopbackAdapter.client = client;
    loopbackAdapter.server = server;

    const deltaTime = 0.1;

    process.on( 'SIGINT', interrupt_handler );
    process.on( 'SIGTERM', interrupt_handler );

    while ( !quit )
    {
        server.SendPackets();
        client.SendPackets();

        server.ReceivePackets();
        client.ReceivePackets();

        time += deltaTime;

        client.AdvanceTime( time );

        if ( client.IsDisconnected() )
            break;

        time += deltaTime;

        server.AdvanceTime( time );

        await yojimbo_sleep( deltaTime );
    }

    process.off( 'SIGINT', interrupt_handler );
    process.off( 'SIGTERM', interrupt_handler );

    client.DisconnectLoopback();

    server.Stop();

    client.Dispose();
    server.Dispose();

    return 0;
}

async function main(): Promise<number>
{
    console.log( "\n[loopback]" );

    if ( !InitializeYojimbo() )
    {
        console.log( "error: failed to initialize Yojimbo!" );
        return 1;
    }

    yojimbo_log_level( YOJIMBO_LOG_LEVEL_INFO );

    yojimbo_srand( Date.now() >>> 0 );

    const result = await ClientServerMain();

    ShutdownYojimbo();

    console.log( "" );

    return result;
}

process.exitCode = await main();
