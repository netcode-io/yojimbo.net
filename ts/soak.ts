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
    TypeScript port of soak.cpp (yojimbo 1.13.5): a client and server on real sockets under heavy simulated latency,
    jitter, loss and duplication, exchanging reliable messages and blocks and checking every one.

        node soak.ts [iterations]

    Zero or absent iterations runs until Ctrl-C. Each iteration yields to the event loop (await yojimbo_sleep( 0 )) so
    the sockets receive; upstream's loop does not sleep.
*/

import {
    InitializeYojimbo, ShutdownYojimbo, GetDefaultAllocator, yojimbo_log_level, YOJIMBO_LOG_LEVEL_INFO, yojimbo_assert,
    yojimbo_random_bytes, yojimbo_random_int, yojimbo_rand, yojimbo_srand, yojimbo_sleep,
    Address, Client, Server, ClientServerConfig, KeyBytes, CHANNEL_TYPE_UNRELIABLE_UNORDERED, CHANNEL_TYPE_RELIABLE_ORDERED,
} from './source/yojimbo.ts';
import { adapter, ServerPort, TestMessage, TestBlockMessage, TEST_MESSAGE, TEST_BLOCK_MESSAGE } from './shared.ts';

const MaxPacketSize = 16 * 1024;
const MaxSnapshotSize = 8 * 1024;
const MaxBlockSize = 10 * 1024;

let quit = false;

function interrupt_handler(): void
{
    quit = true;
}

const UNRELIABLE_UNORDERED_CHANNEL = 0;
const RELIABLE_ORDERED_CHANNEL = 1;

function log( text: string ): void
{
    console.log( text );
}

async function SoakMain( iterations: number ): Promise<number>
{
    const config = new ClientServerConfig();
    config.maxPacketSize = MaxPacketSize;
    // maxPacketFragments was derived from the default maxPacketSize in the ClientServerConfig
    // constructor. We just doubled maxPacketSize, so recompute it (config.Validate() catches this).
    config.maxPacketFragments = Math.ceil( config.maxPacketSize / config.packetFragmentSize );
    config.clientMemory = 100 * 1024 * 1024;
    config.serverGlobalMemory = 10 * 1024 * 1024;
    config.serverPerClientMemory = 100 * 1024 * 1024;
    config.numChannels = 2;
    config.channel[UNRELIABLE_UNORDERED_CHANNEL].type = CHANNEL_TYPE_UNRELIABLE_UNORDERED;
    config.channel[UNRELIABLE_UNORDERED_CHANNEL].maxBlockSize = MaxSnapshotSize;
    config.channel[RELIABLE_ORDERED_CHANNEL].type = CHANNEL_TYPE_RELIABLE_ORDERED;
    config.channel[RELIABLE_ORDERED_CHANNEL].maxBlockSize = MaxBlockSize;
    config.channel[RELIABLE_ORDERED_CHANNEL].blockFragmentSize = 1024;

    const privateKey = new Uint8Array( KeyBytes );

    let time = 0.0;

    const serverAddress = new Address( "127.0.0.1", ServerPort );

    const server = new Server( GetDefaultAllocator(), privateKey, serverAddress, config, adapter, time );

    server.Start( 1 );

    server.SetLatency( 1000.0 );
    server.SetJitter( 100.0 );
    server.SetPacketLoss( 25.0 );
    server.SetDuplicates( 25.0 );

    const clientIdBytes = new Uint8Array( 8 );
    yojimbo_random_bytes( clientIdBytes, 8 );
    const clientId = new DataView( clientIdBytes.buffer ).getBigUint64( 0, true );

    const client = new Client( GetDefaultAllocator(), new Address( "0.0.0.0" ), config, adapter, time );

    client.InsecureConnect( privateKey, clientId, serverAddress );

    client.SetLatency( 1000.0 );
    client.SetJitter( 100.0 );
    client.SetPacketLoss( 25.0 );
    client.SetDuplicates( 25.0 );

    let numMessagesSentToServer = 0;
    let numMessagesSentToClient = 0;
    let numMessagesReceivedFromClient = 0;
    let numMessagesReceivedFromServer = 0;

    process.on( 'SIGINT', interrupt_handler );

    let clientConnected = false;
    let serverConnected = false;

    let timeForNextClientMessage = 0;
    let timeForNextServerMessage = 0;

    // iterations <= 0 runs until interrupted (SIGINT); a positive count time-boxes the run so it exits cleanly.
    let iteration = 0;

    let result = 0;

    while ( !quit && ( iterations <= 0 || iteration < iterations ) )
    {
        iteration++;

        client.SendPackets();
        server.SendPackets();

        client.ReceivePackets();
        server.ReceivePackets();

        if ( client.ConnectionFailed() )
        {
            log( "error: client connect failed!" );
            break;
        }

        time += Math.fround( 0.1 );

        if ( client.IsConnected() )
        {
            if ( ( yojimbo_rand() % 100000 ) === 0 )
            {
                log( "client reconnect" );
                client.Disconnect();
                client.InsecureConnect( privateKey, clientId, serverAddress );
                clientConnected = false;
                numMessagesSentToServer = 0;
                numMessagesSentToClient = 0;
                numMessagesReceivedFromClient = 0;
                numMessagesReceivedFromServer = 0;
            }
        }

        if ( client.IsConnected() )
        {
            clientConnected = true;

            if ( timeForNextClientMessage < time && ( yojimbo_rand() % 1000 ) === 0 )
            {
                timeForNextClientMessage = time + yojimbo_random_int( 1, 1000 );
            }

            if ( timeForNextClientMessage <= time )
            {
                const messagesToSend = yojimbo_random_int( 0, 64 );

                for ( let i = 0; i < messagesToSend; ++i )
                {
                    if ( !client.CanSendMessage( RELIABLE_ORDERED_CHANNEL ) )
                        break;

                    if ( yojimbo_rand() % 100 )
                    {
                        const message = client.CreateMessage( TEST_MESSAGE ) as TestMessage | null;
                        if ( message )
                        {
                            message.sequence = numMessagesSentToServer & 0xFFFF;
                            client.SendMessage( RELIABLE_ORDERED_CHANNEL, message );
                            numMessagesSentToServer++;
                        }
                    }
                    else
                    {
                        const numBlocks = yojimbo_random_int( 1, 3 );

                        for ( let k = 0; k < numBlocks; k++ )
                        {
                            if ( !client.CanSendMessage( RELIABLE_ORDERED_CHANNEL ) )
                                break;

                            const blockMessage = client.CreateMessage( TEST_BLOCK_MESSAGE ) as TestBlockMessage | null;
                            if ( blockMessage )
                            {
                                blockMessage.sequence = numMessagesSentToServer & 0xFFFF;
                                const blockSize = 1 + ( numMessagesSentToServer * 33 ) % MaxBlockSize;
                                const blockData = client.AllocateBlock( blockSize );
                                if ( blockData )
                                {
                                    for ( let j = 0; j < blockSize; ++j )
                                        blockData[j] = ( numMessagesSentToServer + j ) & 0xFF;
                                    client.AttachBlockToMessage( blockMessage, blockData, blockSize );
                                    client.SendMessage( RELIABLE_ORDERED_CHANNEL, blockMessage );
                                    numMessagesSentToServer++;
                                }
                                else
                                {
                                    client.ReleaseMessage( blockMessage );
                                }
                            }
                        }
                    }
                }
            }

            const clientIndex = client.GetClientIndex();

            if ( timeForNextServerMessage < time && ( yojimbo_rand() % 1000 ) === 0 )
            {
                const delay = yojimbo_random_int( 1, 1000 );

                timeForNextServerMessage = time + delay;
            }

            if ( server.IsClientConnected( clientIndex ) )
            {
                serverConnected = true;

                if ( timeForNextServerMessage <= time )
                {
                    const messagesToSend = yojimbo_random_int( 0, 64 );

                    for ( let i = 0; i < messagesToSend; ++i )
                    {
                        if ( !server.CanSendMessage( clientIndex, RELIABLE_ORDERED_CHANNEL ) )
                            break;

                        if ( yojimbo_rand() % 100 )
                        {
                            const message = server.CreateMessage( clientIndex, TEST_MESSAGE ) as TestMessage | null;
                            if ( message )
                            {
                                message.sequence = numMessagesSentToClient & 0xFFFF;
                                server.SendMessage( clientIndex, RELIABLE_ORDERED_CHANNEL, message );
                                numMessagesSentToClient++;
                            }
                        }
                        else
                        {
                            const numBlocks = yojimbo_random_int( 1, 3 );

                            for ( let k = 0; k < numBlocks; k++ )
                            {
                                if ( !server.CanSendMessage( clientIndex, RELIABLE_ORDERED_CHANNEL ) )
                                    break;

                                const blockMessage = server.CreateMessage( clientIndex, TEST_BLOCK_MESSAGE ) as TestBlockMessage | null;
                                if ( blockMessage )
                                {
                                    blockMessage.sequence = numMessagesSentToClient & 0xFFFF;
                                    const blockSize = 1 + ( numMessagesSentToClient * 33 ) % MaxBlockSize;
                                    const blockData = server.AllocateBlock( clientIndex, blockSize );
                                    if ( blockData )
                                    {
                                        for ( let j = 0; j < blockSize; ++j )
                                            blockData[j] = ( numMessagesSentToClient + j ) & 0xFF;
                                        server.AttachBlockToMessage( clientIndex, blockMessage, blockData, blockSize );
                                        server.SendMessage( clientIndex, RELIABLE_ORDERED_CHANNEL, blockMessage );
                                        numMessagesSentToClient++;
                                    }
                                    else
                                    {
                                        server.ReleaseMessage( clientIndex, blockMessage );
                                    }
                                }
                            }
                        }
                    }
                }

                while ( true )
                {
                    const message = server.ReceiveMessage( clientIndex, RELIABLE_ORDERED_CHANNEL );
                    if ( !message )
                        break;

                    yojimbo_assert( message.GetId() === ( numMessagesReceivedFromClient & 0xFFFF ), "message->GetId() == (uint16_t) numMessagesReceivedFromClient" );

                    const error = CheckSoakMessage( message, numMessagesReceivedFromClient );
                    if ( error )
                    {
                        log( error );
                        result = 1;
                        quit = true;
                    }
                    else
                    {
                        log( `server received message ${numMessagesReceivedFromClient & 0xFFFF}` );
                    }
                    server.ReleaseMessage( clientIndex, message );
                    numMessagesReceivedFromClient++;
                }
            }

            while ( true )
            {
                const message = client.ReceiveMessage( RELIABLE_ORDERED_CHANNEL );

                if ( !message )
                    break;

                yojimbo_assert( message.GetId() === ( numMessagesReceivedFromServer & 0xFFFF ), "message->GetId() == (uint16_t) numMessagesReceivedFromServer" );

                const error = CheckSoakMessage( message, numMessagesReceivedFromServer );
                if ( error )
                {
                    log( error );
                    result = 1;
                    quit = true;
                }
                else
                {
                    log( `client received message ${numMessagesReceivedFromServer & 0xFFFF}` );
                }
                client.ReleaseMessage( message );
                numMessagesReceivedFromServer++;
            }

            if ( clientConnected && !client.IsConnected() )
                break;

            if ( serverConnected && server.GetNumConnectedClients() === 0 )
                break;
        }

        client.AdvanceTime( time );
        server.AdvanceTime( time );

        await yojimbo_sleep( 0 );
    }

    process.off( 'SIGINT', interrupt_handler );

    if ( quit && result === 0 )
    {
        log( "\nstopped" );
    }

    log( `soak: ${iteration} iterations, ${numMessagesReceivedFromClient} messages received by the server, ${numMessagesReceivedFromServer} by the client` );

    client.Disconnect();

    server.Stop();

    client.Dispose();
    server.Dispose();

    return result;
}

/** Check a received soak message. Returns an error string, or null if it is the expected message. */

function CheckSoakMessage( message: TestMessage | TestBlockMessage | { GetType(): number }, expected: number ): string | null
{
    switch ( message.GetType() )
    {
        case TEST_MESSAGE:
        {
            const testMessage = message as TestMessage;
            yojimbo_assert( testMessage.sequence === ( expected & 0xFFFF ), "testMessage->sequence == uint16_t( expected )" );
            return null;
        }

        case TEST_BLOCK_MESSAGE:
        {
            const blockMessage = message as TestBlockMessage;
            yojimbo_assert( blockMessage.sequence === ( expected & 0xFFFF ), "blockMessage->sequence == uint16_t( expected )" );
            const blockSize = blockMessage.GetBlockSize();
            const expectedBlockSize = 1 + ( expected * 33 ) % MaxBlockSize;
            if ( blockSize !== expectedBlockSize )
                return `error: block size mismatch. expected ${expectedBlockSize}, got ${blockSize}`;
            const blockData = blockMessage.GetBlockData();
            yojimbo_assert( blockData, "blockData" );
            for ( let i = 0; i < blockSize; ++i )
            {
                if ( blockData[i] !== ( ( expected + i ) & 0xFF ) )
                    return `error: block data mismatch. expected ${( expected + i ) & 0xFF}, but blockData[${i}] = ${blockData[i]}`;
            }
            return null;
        }
    }
    return null;
}

async function main(): Promise<number>
{
    console.log( "\nsoak" );

    // Optional iteration count: `soak [iterations]`. Zero or absent runs until Ctrl-C.
    const iterations = process.argv.length > 2 ? ( parseInt( process.argv[2], 10 ) || 0 ) : 0;

    if ( !InitializeYojimbo() )
    {
        console.log( "error: failed to initialize Yojimbo!" );
        return 1;
    }

    yojimbo_log_level( YOJIMBO_LOG_LEVEL_INFO );

    yojimbo_srand( Date.now() >>> 0 );

    const result = await SoakMain( iterations );

    ShutdownYojimbo();

    console.log( "" );

    return result;
}

process.exitCode = await main();
