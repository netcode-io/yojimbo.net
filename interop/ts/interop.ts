/*
    Cross-implementation interop test (TypeScript side). Mirrors interop/interop.cpp line for line; see that
    file for the protocol. Any pairing of the C++, C# and TypeScript sides can be run:

        node interop/ts/interop.ts server [port]
        node interop/ts/interop.ts client [port]
*/

import {
    InitializeYojimbo, ShutdownYojimbo, GetDefaultAllocator, yojimbo_log_level, YOJIMBO_LOG_LEVEL_ERROR,
    yojimbo_random_bytes, yojimbo_sleep, Address, Client, Server, ClientServerConfig, KeyBytes, MaxClients,
    CHANNEL_TYPE_RELIABLE_ORDERED, CHANNEL_TYPE_UNRELIABLE_UNORDERED, GetClientDisconnectReasonString,
} from '../../ts/source/yojimbo.ts';
import { adapter, ProtocolId, ServerPort, TestMessage, TestBlockMessage, TEST_MESSAGE, TEST_BLOCK_MESSAGE } from '../../ts/shared.ts';

const NumMessages = 1000;
const BlockEvery = 8;
const TimeoutSeconds = 60.0;

function BlockSizeFor( sequence: number ): number { return 1 + ( sequence * 977 ) % 5000; }

function BlockByte( sequence: number, i: number ): number { return ( sequence * 31 + i * 7 ) & 0xFF; }

function CreateConfig(): ClientServerConfig
{
    const config = new ClientServerConfig();
    config.protocolId = ProtocolId;
    config.numChannels = 2;
    config.channel[0].type = CHANNEL_TYPE_RELIABLE_ORDERED;
    config.channel[1].type = CHANNEL_TYPE_UNRELIABLE_UNORDERED;
    return config;
}

async function ServerMain( port: number ): Promise<number>
{
    const config = CreateConfig();

    const privateKey = new Uint8Array( KeyBytes );

    let time = 100.0;
    const deltaTime = 0.01;

    const server = new Server( GetDefaultAllocator(), privateKey, new Address( "127.0.0.1", port ), config, adapter, time );
    if ( !server.Start( MaxClients ) )
    {
        console.log( "server: failed to start" );
        return 1;
    }
    console.log( `server: listening on 127.0.0.1:${port}` );

    let hadClient = false;
    let idleSince = time;
    while ( true )
    {
        server.SendPackets();
        server.ReceivePackets();
        time += deltaTime;
        server.AdvanceTime( time );

        let anyConnected = false;
        for ( let clientIndex = 0; clientIndex < MaxClients; ++clientIndex )
        {
            if ( !server.IsClientConnected( clientIndex ) )
                continue;
            anyConnected = true;
            hadClient = true;
            for ( let channel = 0; channel < config.numChannels; ++channel )
            {
                let message;
                while ( ( message = server.ReceiveMessage( clientIndex, channel ) ) !== null )
                {
                    if ( !server.CanSendMessage( clientIndex, channel ) )
                    {
                        server.ReleaseMessage( clientIndex, message );
                        continue;
                    }
                    if ( message.GetType() === TEST_BLOCK_MESSAGE )
                    {
                        const input = message as TestBlockMessage;
                        const output = server.CreateMessage( clientIndex, TEST_BLOCK_MESSAGE ) as TestBlockMessage;
                        output.sequence = input.sequence;
                        const block = server.AllocateBlock( clientIndex, input.GetBlockSize() )!;
                        block.set( input.GetBlockData()!.subarray( 0, input.GetBlockSize() ) );
                        server.AttachBlockToMessage( clientIndex, output, block, input.GetBlockSize() );
                        server.SendMessage( clientIndex, channel, output );
                    }
                    else if ( message.GetType() === TEST_MESSAGE )
                    {
                        const output = server.CreateMessage( clientIndex, TEST_MESSAGE ) as TestMessage;
                        output.sequence = ( message as TestMessage ).sequence;
                        server.SendMessage( clientIndex, channel, output );
                    }
                    server.ReleaseMessage( clientIndex, message );
                }
            }
        }

        // exit once the client has come and gone, or nobody shows up
        if ( anyConnected )
            idleSince = time;
        else if ( hadClient && time - idleSince > 1.0 )
            break;
        else if ( !hadClient && time - idleSince > TimeoutSeconds )
        {
            console.log( "server: no client connected" );
            server.Stop();
            return 1;
        }

        await yojimbo_sleep( deltaTime );
    }

    server.Stop();
    server.Dispose();
    console.log( "server: done" );
    return 0;
}

async function ClientMain( port: number ): Promise<number>
{
    const config = CreateConfig();

    const privateKey = new Uint8Array( KeyBytes );

    const clientIdBytes = new Uint8Array( 8 );
    yojimbo_random_bytes( clientIdBytes, 8 );
    const clientId = new DataView( clientIdBytes.buffer ).getBigUint64( 0, true );

    let time = 100.0;
    const deltaTime = 0.01;

    const client = new Client( GetDefaultAllocator(), new Address( "0.0.0.0" ), config, adapter, time );
    client.InsecureConnect( privateKey, clientId, new Address( "127.0.0.1", port ) );

    let numSent = 0;
    let numReceived = 0;
    let numUnreliableEchoes = 0;
    let unreliableSequence = 0;
    const start = time;
    let result = 1;

    while ( true )
    {
        client.SendPackets();
        client.ReceivePackets();
        time += deltaTime;
        client.AdvanceTime( time );

        if ( client.ConnectionFailed() || ( client.IsDisconnected() && time - start > 1.0 ) )
        {
            console.log( `client: connection failed (${GetClientDisconnectReasonString( client.GetDisconnectReason() )})` );
            break;
        }

        if ( time - start > TimeoutSeconds )
        {
            console.log( `client: timed out with ${numReceived}/${NumMessages} echoes` );
            break;
        }

        if ( client.IsConnected() )
        {
            while ( numSent < NumMessages && client.CanSendMessage( 0 ) )
            {
                if ( numSent % BlockEvery === 0 )
                {
                    const message = client.CreateMessage( TEST_BLOCK_MESSAGE ) as TestBlockMessage;
                    message.sequence = numSent & 0xFFFF;
                    const blockSize = BlockSizeFor( numSent );
                    const block = client.AllocateBlock( blockSize )!;
                    for ( let i = 0; i < blockSize; ++i )
                        block[i] = BlockByte( numSent, i );
                    client.AttachBlockToMessage( message, block, blockSize );
                    client.SendMessage( 0, message );
                }
                else
                {
                    const message = client.CreateMessage( TEST_MESSAGE ) as TestMessage;
                    message.sequence = numSent & 0xFFFF;
                    client.SendMessage( 0, message );
                }
                numSent++;
            }

            if ( client.CanSendMessage( 1 ) )
            {
                const message = client.CreateMessage( TEST_MESSAGE ) as TestMessage;
                message.sequence = unreliableSequence;
                unreliableSequence = ( unreliableSequence + 1 ) & 0xFFFF;
                client.SendMessage( 1, message );
            }

            let received;
            while ( ( received = client.ReceiveMessage( 0 ) ) !== null )
            {
                const expected = numReceived;
                let ok: boolean;
                if ( expected % BlockEvery === 0 )
                {
                    ok = received.GetType() === TEST_BLOCK_MESSAGE && ( received as TestBlockMessage ).sequence === ( expected & 0xFFFF );
                    if ( ok )
                    {
                        const blockMessage = received as TestBlockMessage;
                        const data = blockMessage.GetBlockData()!;
                        ok = blockMessage.GetBlockSize() === BlockSizeFor( expected );
                        for ( let i = 0; ok && i < blockMessage.GetBlockSize(); ++i )
                            ok = data[i] === BlockByte( expected, i );
                    }
                }
                else
                {
                    ok = received.GetType() === TEST_MESSAGE && ( received as TestMessage ).sequence === ( expected & 0xFFFF );
                }
                client.ReleaseMessage( received );
                if ( !ok )
                {
                    console.log( `client: echo ${expected} is wrong` );
                    client.Disconnect();
                    return 1;
                }
                numReceived++;
            }

            while ( ( received = client.ReceiveMessage( 1 ) ) !== null )
            {
                numUnreliableEchoes++;
                client.ReleaseMessage( received );
            }

            if ( numReceived === NumMessages )
            {
                console.log( `client: ${numReceived} reliable echoes verified (${Math.floor( ( NumMessages + BlockEvery - 1 ) / BlockEvery )} blocks), ${numUnreliableEchoes} unreliable echoes` );
                result = numUnreliableEchoes > 0 ? 0 : 1;
                if ( result !== 0 )
                    console.log( "client: no unreliable echoes" );
                break;
            }
        }

        await yojimbo_sleep( deltaTime );
    }

    client.Disconnect();
    client.Dispose();
    return result;
}

async function main( argv: string[] ): Promise<number>
{
    if ( argv.length < 1 || ( argv[0] !== "server" && argv[0] !== "client" ) )
    {
        console.log( "usage: interop server|client [port]" );
        return 1;
    }

    const port = argv.length >= 2 ? parseInt( argv[1], 10 ) : ServerPort;

    if ( !InitializeYojimbo() )
    {
        console.log( "error: failed to initialize yojimbo" );
        return 1;
    }

    yojimbo_log_level( YOJIMBO_LOG_LEVEL_ERROR );

    const result = argv[0] === "server" ? await ServerMain( port ) : await ClientMain( port );

    ShutdownYojimbo();

    console.log( result === 0 ? "PASS" : "FAIL" );

    return result;
}

process.exitCode = await main( process.argv.slice( 2 ) );
