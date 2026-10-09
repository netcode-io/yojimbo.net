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
    TypeScript port of server.cpp (yojimbo 1.13.5): an insecure server on 127.0.0.1:40000 for client.ts.

        node server.ts

    Ctrl-C stops the server. The loop awaits yojimbo_sleep between updates, which is what lets the socket receive packets.
*/

import {
    InitializeYojimbo, ShutdownYojimbo, GetDefaultAllocator, yojimbo_log_level, YOJIMBO_LOG_LEVEL_INFO, yojimbo_assert,
    yojimbo_sleep, yojimbo_srand, Address, Server, ClientServerConfig, KeyBytes, MaxClients,
    GetServerClientDisconnectReasonString,
} from './source/yojimbo.ts';
import { TestAdapter, ServerPort } from './shared.ts';

let quit = false;

function interrupt_handler(): void
{
    quit = true;
}

// Adapter that logs when clients connect and disconnect. The disconnect reason is recorded
// before OnServerClientDisconnected is called, so it can be queried inside the callback.
class ServerAdapter extends TestAdapter
{
    server: Server | null = null;

    override OnServerClientConnected( clientIndex: number ): void
    {
        console.log( `client ${clientIndex} connected` );
    }

    override OnServerClientDisconnected( clientIndex: number ): void
    {
        yojimbo_assert( this.server, "server" );
        console.log( `client ${clientIndex} disconnected: ${GetServerClientDisconnectReasonString( this.server.GetClientDisconnectReason( clientIndex ) )}` );
    }
}

async function ServerMain(): Promise<number>
{
    console.log( `started server on port ${ServerPort} (insecure)` );

    let time = 100.0;

    const config = new ClientServerConfig();

    const privateKey = new Uint8Array( KeyBytes );

    const serverAdapter = new ServerAdapter();

    const server = new Server( GetDefaultAllocator(), privateKey, new Address( "127.0.0.1", ServerPort ), config, serverAdapter, time );

    serverAdapter.server = server;

    if ( !server.Start( MaxClients ) )
    {
        console.log( "error: failed to start server" );
        server.Dispose();
        return 1;
    }

    console.log( `server address is ${server.GetAddress().ToString()}` );

    const deltaTime = Math.fround( 0.01 );

    process.on( 'SIGINT', interrupt_handler );
    process.on( 'SIGTERM', interrupt_handler );

    while ( !quit )
    {
        server.SendPackets();

        server.ReceivePackets();

        time += deltaTime;

        server.AdvanceTime( time );

        if ( !server.IsRunning() )
            break;

        await yojimbo_sleep( deltaTime );
    }

    process.off( 'SIGINT', interrupt_handler );
    process.off( 'SIGTERM', interrupt_handler );

    server.Stop();

    server.Dispose();

    return 0;
}

async function main(): Promise<number>
{
    console.log( "" );

    if ( !InitializeYojimbo() )
    {
        console.log( "error: failed to initialize Yojimbo!" );
        return 1;
    }

    yojimbo_log_level( YOJIMBO_LOG_LEVEL_INFO );

    yojimbo_srand( Date.now() >>> 0 );

    const result = await ServerMain();

    ShutdownYojimbo();

    console.log( "" );

    return result;
}

process.exitCode = await main();
