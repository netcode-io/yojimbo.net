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
    TypeScript port of include/yojimbo_client_interface.h (yojimbo 1.13.5).

    The pure virtual class becomes a TypeScript interface. uint64 values (client id, loopback packet sequence) are
    bigint; GetNetworkInfo fills the NetworkInfo it is given.
*/

import type { Message } from '../source/yojimbo_message.ts';
import type { NetworkInfo } from './yojimbo_network_info.ts';

/**
    The set of client states.
 */

export const CLIENT_STATE_ERROR = -1;
export const CLIENT_STATE_DISCONNECTED = 0;
export const CLIENT_STATE_CONNECTING = 1;
export const CLIENT_STATE_CONNECTED = 2;

export type ClientState = typeof CLIENT_STATE_ERROR | typeof CLIENT_STATE_DISCONNECTED | typeof CLIENT_STATE_CONNECTING | typeof CLIENT_STATE_CONNECTED;

/**
    The common interface for all clients.
 */

export interface ClientInterface
{
    /**
        Set the context for reading and writing packets.
        This is optional. It lets you pass in some structure that you want to have available when reading and writing packets via Stream::GetContext.
        Typical use case is to pass in an array of min/max ranges for values determined by some data that is loaded from a toolchain vs. being known at compile time.
        If you do use a context, make sure the same context data is set on client and server, and include a checksum of the context data in the protocol id.
     */
    SetContext( context: unknown ): void;

    /** Disconnect from the server. */
    Disconnect(): void;

    /** Send packets to server. */
    SendPackets(): void;

    /** Receive packets from the server. */
    ReceivePackets(): void;

    /**
        Advance client time.
        Call this at the end of each frame to advance the client time forward.
        IMPORTANT: Please use a double for your time value so it maintains sufficient accuracy as time increases.
     */
    AdvanceTime( time: number ): void;

    /** Is the client connecting to a server? */
    IsConnecting(): boolean;

    /** Is the client connected to a server? */
    IsConnected(): boolean;

    /** Is the client in a disconnected state? A disconnected state corresponds to the client being in the disconnected, or in an error state. */
    IsDisconnected(): boolean;

    /** Is the client in an error state? When the client disconnects because of an error, it enters into this error state. */
    ConnectionFailed(): boolean;

    /** Get the current client state. */
    GetClientState(): ClientState;

    /** Get the client index: the slot number that the client is occupying on the server, in [0,maxClients-1]. -1 if not connected. */
    GetClientIndex(): number;

    /** Get the client id: a unique identifier of this client (uint64). */
    GetClientId(): bigint;

    /** Get the current client time. */
    GetTime(): number;

    /** Create a message of the specified type. The message types corresponds to the message factory created by the adapter set on this client. */
    CreateMessage( type: number ): Message | null;

    /** Allocate a data block to attach to a block message. Attach it with AttachBlockToMessage, or free it with FreeBlock. */
    AllocateBlock( bytes: number ): Uint8Array | null;

    /** Attach a data block created via AllocateBlock to a block message. */
    AttachBlockToMessage( message: Message, block: Uint8Array, bytes: number ): void;

    /** Free a block of memory created by AllocateBlock. */
    FreeBlock( block: Uint8Array ): void;

    /** Can we send a message on a channel? */
    CanSendMessage( channelIndex: number ): boolean;

    /** Send a message on a channel. Ownership of the message reference passes to the client. */
    SendMessage( channelIndex: number, message: Message ): void;

    /** Receive a message from a channel. Returns null if no message is available. Release the message with ReleaseMessage. */
    ReceiveMessage( channelIndex: number ): Message | null;

    /** Release a message received by ReceiveMessage. */
    ReleaseMessage( message: Message ): void;

    /** Get client network info (round trip time, packet loss %, # of packets sent and so on). @param info The struct to be filled [out]. */
    GetNetworkInfo( info: NetworkInfo ): void;

    /**
        Connect to server over loopback.
        @returns True if the loopback connection was established. False if the client ran out of memory, in which case the client is left disconnected and nothing is allocated.
     */
    ConnectLoopback( clientIndex: number, clientId: bigint, maxClients: number ): boolean;

    /** Disconnect from server over loopback. */
    DisconnectLoopback(): void;

    /** Is this a loopback client? */
    IsLoopback(): boolean;

    /** Process loopback packet: pass packets from a server directly to the loopback client. */
    ProcessLoopbackPacket( packetData: Uint8Array, packetBytes: number, packetSequence: bigint ): void;
}
