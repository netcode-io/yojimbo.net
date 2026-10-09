/*
    yojimbo TypeScript port: WebRTC transport extension.

    This folder is an EXTENSION of the TypeScript port, not a mirror of an upstream file: upstream yojimbo has no
    WebRTC transport. It is distributed under the same BSD 3-Clause license as the rest of this package.

    webrtc_echo.ts: the interop echo protocol (interop/ts/interop.ts) as reusable, platform neutral pieces, so the
    Node test, the demo server and the browser demo page all run the same check:

      - the client sends NumMessages reliable messages on channel 0, every BlockEvery-th a block message of
        1..5000 bytes (multi-fragment), plus one unreliable message per update on channel 1;
      - the server echoes every message back on the channel it came in on;
      - the client verifies every reliable echo in order, byte for byte, and needs at least one unreliable echo.
*/

import {
    Server, Client, ClientServerConfig, CHANNEL_TYPE_RELIABLE_ORDERED, CHANNEL_TYPE_UNRELIABLE_UNORDERED,
} from '../source/yojimbo.ts';
import { ProtocolId, TestMessage, TestBlockMessage, TEST_MESSAGE, TEST_BLOCK_MESSAGE } from '../shared.ts';

export const EchoNumMessages = 1000;
export const EchoBlockEvery = 8;

export function EchoBlockSizeFor( sequence: number ): number { return 1 + ( sequence * 977 ) % 5000; }

export function EchoBlockByte( sequence: number, i: number ): number { return ( sequence * 31 + i * 7 ) & 0xFF; }

/** The interop config: protocol id from shared.ts, channel 0 reliable ordered, channel 1 unreliable unordered. */

export function CreateEchoConfig(): ClientServerConfig
{
    const config = new ClientServerConfig();
    config.protocolId = ProtocolId;
    config.numChannels = 2;
    config.channel[0].type = CHANNEL_TYPE_RELIABLE_ORDERED;
    config.channel[1].type = CHANNEL_TYPE_UNRELIABLE_UNORDERED;
    return config;
}

/** Echo every message every connected client sent back to it. Call once per server update (after ReceivePackets). */

export function EchoServerUpdate( server: Server, config: ClientServerConfig ): void
{
    const maxClients = server.GetMaxClients();
    for ( let clientIndex = 0; clientIndex < maxClients; ++clientIndex )
    {
        if ( !server.IsClientConnected( clientIndex ) )
            continue;
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
}

export type EchoStatus = 'running' | 'pass' | 'fail';

/** Client side of the echo protocol. Call Update() once per client update, after ReceivePackets / AdvanceTime. */

export class EchoClient
{
    readonly client: Client;
    readonly numMessages: number;
    numSent = 0;
    numReceived = 0;
    numUnreliableEchoes = 0;
    status: EchoStatus = 'running';
    detail = '';
    private m_unreliableSequence = 0;

    constructor( client: Client, numMessages = EchoNumMessages )
    {
        this.client = client;
        this.numMessages = numMessages;
    }

    Update(): EchoStatus
    {
        if ( this.status !== 'running' || !this.client.IsConnected() )
            return this.status;

        const client = this.client;

        while ( this.numSent < this.numMessages && client.CanSendMessage( 0 ) )
        {
            if ( this.numSent % EchoBlockEvery === 0 )
            {
                const message = client.CreateMessage( TEST_BLOCK_MESSAGE ) as TestBlockMessage;
                message.sequence = this.numSent & 0xFFFF;
                const blockSize = EchoBlockSizeFor( this.numSent );
                const block = client.AllocateBlock( blockSize )!;
                for ( let i = 0; i < blockSize; ++i )
                    block[i] = EchoBlockByte( this.numSent, i );
                client.AttachBlockToMessage( message, block, blockSize );
                client.SendMessage( 0, message );
            }
            else
            {
                const message = client.CreateMessage( TEST_MESSAGE ) as TestMessage;
                message.sequence = this.numSent & 0xFFFF;
                client.SendMessage( 0, message );
            }
            this.numSent++;
        }

        if ( client.CanSendMessage( 1 ) )
        {
            const message = client.CreateMessage( TEST_MESSAGE ) as TestMessage;
            message.sequence = this.m_unreliableSequence;
            this.m_unreliableSequence = ( this.m_unreliableSequence + 1 ) & 0xFFFF;
            client.SendMessage( 1, message );
        }

        let received;
        while ( ( received = client.ReceiveMessage( 0 ) ) !== null )
        {
            const expected = this.numReceived;
            let ok: boolean;
            if ( expected % EchoBlockEvery === 0 )
            {
                ok = received.GetType() === TEST_BLOCK_MESSAGE && ( received as TestBlockMessage ).sequence === ( expected & 0xFFFF );
                if ( ok )
                {
                    const blockMessage = received as TestBlockMessage;
                    const data = blockMessage.GetBlockData()!;
                    ok = blockMessage.GetBlockSize() === EchoBlockSizeFor( expected );
                    for ( let i = 0; ok && i < blockMessage.GetBlockSize(); ++i )
                        ok = data[i] === EchoBlockByte( expected, i );
                }
            }
            else
            {
                ok = received.GetType() === TEST_MESSAGE && ( received as TestMessage ).sequence === ( expected & 0xFFFF );
            }
            client.ReleaseMessage( received );
            if ( !ok )
            {
                this.status = 'fail';
                this.detail = `echo ${expected} is wrong`;
                return this.status;
            }
            this.numReceived++;
        }

        while ( ( received = client.ReceiveMessage( 1 ) ) !== null )
        {
            this.numUnreliableEchoes++;
            client.ReleaseMessage( received );
        }

        if ( this.numReceived === this.numMessages )
        {
            const blocks = Math.floor( ( this.numMessages + EchoBlockEvery - 1 ) / EchoBlockEvery );
            if ( this.numUnreliableEchoes > 0 )
            {
                this.status = 'pass';
                this.detail = `${this.numReceived} reliable echoes verified (${blocks} blocks), ${this.numUnreliableEchoes} unreliable echoes`;
            }
            else
            {
                this.status = 'fail';
                this.detail = 'no unreliable echoes';
            }
        }

        return this.status;
    }
}
