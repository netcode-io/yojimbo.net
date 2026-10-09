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
    TypeScript port of client.cpp (yojimbo 1.13.5): an insecure client that connects to server.ts.

        node client.ts [server address]

    Ctrl-C disconnects. The loop awaits yojimbo_sleep between updates, which is what lets the socket receive packets.
*/

import {
    InitializeYojimbo, ShutdownYojimbo, GetDefaultAllocator, yojimbo_log_level, YOJIMBO_LOG_LEVEL_INFO,
    yojimbo_random_bytes, yojimbo_sleep, yojimbo_srand, Address, Client, ClientServerConfig, KeyBytes,
    GetClientDisconnectReasonString,
} from './source/yojimbo.ts';
import { adapter, ServerPort } from './shared.ts';

let quit = false;

function interrupt_handler(): void
{
    quit = true;
}

async function ClientMain( argv: string[] ): Promise<number>
{
    console.log( "\nconnecting client (insecure)" );

    let time = 100.0;

    const clientIdBytes = new Uint8Array( 8 );
    yojimbo_random_bytes( clientIdBytes, 8 );
    const clientId = new DataView( clientIdBytes.buffer ).getBigUint64( 0, true );
    console.log( `client id is ${clientId.toString( 16 ).padStart( 16, "0" )}` );

    const config = new ClientServerConfig();

    const client = new Client( GetDefaultAllocator(), new Address( "0.0.0.0" ), config, adapter, time );

    let serverAddress = new Address( "127.0.0.1", ServerPort );

    if ( argv.length === 1 )
    {
        const commandLineAddress = new Address( argv[0] );
        if ( commandLineAddress.IsValid() )
        {
            if ( commandLineAddress.GetPort() === 0 )
                commandLineAddress.SetPort( ServerPort );
            serverAddress = commandLineAddress;
        }
    }

    const privateKey = new Uint8Array( KeyBytes );

    client.InsecureConnect( privateKey, clientId, serverAddress );

    console.log( `client address is ${client.GetAddress().ToString()}` );

    const deltaTime = Math.fround( 0.01 );

    process.on( 'SIGINT', interrupt_handler );

    while ( !quit )
    {
        client.SendPackets();

        client.ReceivePackets();

        if ( client.IsDisconnected() )
            break;

        time += deltaTime;

        client.AdvanceTime( time );

        if ( client.ConnectionFailed() )
            break;

        await yojimbo_sleep( deltaTime );
    }

    process.off( 'SIGINT', interrupt_handler );

    client.Disconnect();

    // Why did we end up disconnected? Deliberate disconnect (ctrl-c), kicked by the server,
    // connect failure (eg. no server running), timeout etc. See ClientDisconnectReason.
    console.log( `client disconnected: ${GetClientDisconnectReasonString( client.GetDisconnectReason() )}` );

    client.Dispose();

    return 0;
}

async function main(): Promise<number>
{
    if ( !InitializeYojimbo() )
    {
        console.log( "error: failed to initialize Yojimbo!" );
        return 1;
    }

    yojimbo_log_level( YOJIMBO_LOG_LEVEL_INFO );

    yojimbo_srand( Date.now() >>> 0 );

    const result = await ClientMain( process.argv.slice( 2 ) );

    ShutdownYojimbo();

    console.log( "" );

    return result;
}

process.exitCode = await main();
