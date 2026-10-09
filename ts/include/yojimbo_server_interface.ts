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
    TypeScript port of include/yojimbo_server_interface.h (yojimbo 1.13.5).

    The pure virtual class becomes a TypeScript interface. uint64 values (client id, loopback packet sequence) are
    bigint. GetClientAddress returns netcode's address for the slot (as upstream returns netcode_address_t*).
*/

import type { netcode_address_t } from '../netcode/netcode.ts';
import type { Message } from '../source/yojimbo_message.ts';
import type { NetworkInfo } from './yojimbo_network_info.ts';

/**
    The server interface.
 */

export interface ServerInterface
{
    /**
        Set the context for reading and writing packets.
        If you do use a context, make sure the same context data is set on client and server, and include a checksum of the context data in the protocol id.
     */
    SetContext( context: unknown ): void;

    /**
        Start the server and allocate client slots.
        @param maxClients The number of client slots to allocate. Must be in range [1,MaxClients]
        @returns True if the server started. False if it ran out of memory or could not open its socket, in which case the server is left stopped and holding nothing.
     */
    Start( maxClients: number ): boolean;

    /** Stop the server and free client slots. Any clients that are connected are disconnected. */
    Stop(): void;

    /** Disconnect the client at the specified client index. */
    DisconnectClient( clientIndex: number ): void;

    /** Disconnect all clients from the server. Client slots remain allocated. */
    DisconnectAllClients(): void;

    /** Send packets to connected clients. */
    SendPackets(): void;

    /** Receive packets from connected clients. */
    ReceivePackets(): void;

    /** Advance server time. IMPORTANT: Please use a double for your time value so it maintains sufficient accuracy as time increases. */
    AdvanceTime( time: number ): void;

    /** Is the server running? */
    IsRunning(): boolean;

    /** Get the maximum number of clients that can connect to the server (the number of client slots). */
    GetMaxClients(): number;

    /** Is a client connected to a client slot? */
    IsClientConnected( clientIndex: number ): boolean;

    /** Get the unique id of the client (uint64). */
    GetClientId( clientIndex: number ): bigint;

    /** Get the user data of the client (NETCODE_USER_DATA_BYTES bytes), or null. */
    GetClientUserData( clientIndex: number ): Uint8Array | null;

    /** Get the address of the client, or null. */
    GetClientAddress( clientIndex: number ): netcode_address_t | null;

    /** Get the number of clients that are currently connected to the server. */
    GetNumConnectedClients(): number;

    /** Gets the current server time. */
    GetTime(): number;

    /** Create a message of the specified type for a specific client. The client index determines which client heap is used. */
    CreateMessage( clientIndex: number, type: number ): Message | null;

    /** Allocate a data block for a client, to attach to a block message. */
    AllocateBlock( clientIndex: number, bytes: number ): Uint8Array | null;

    /** Attach a data block created via AllocateBlock to a block message. */
    AttachBlockToMessage( clientIndex: number, message: Message, block: Uint8Array, bytes: number ): void;

    /** Free a block of memory created by AllocateBlock. */
    FreeBlock( clientIndex: number, block: Uint8Array ): void;

    /** Can we send a message to a particular client on a channel? */
    CanSendMessage( clientIndex: number, channelIndex: number ): boolean;

    /** Send a message to a client over a channel. Ownership of the message reference passes to the server. */
    SendMessage( clientIndex: number, channelIndex: number, message: Message ): void;

    /** Receive a message from a client over a channel. Returns null if no message is available. Release it with ReleaseMessage. */
    ReceiveMessage( clientIndex: number, channelIndex: number ): Message | null;

    /** Release a message received by ReceiveMessage. */
    ReleaseMessage( clientIndex: number, message: Message ): void;

    /** Get client network info. @param info The struct to be filled [out]. */
    GetNetworkInfo( clientIndex: number, info: NetworkInfo ): void;

    /** Connect a loopback client. @param userData User data for this client. Optional, null if not needed. */
    ConnectLoopbackClient( clientIndex: number, clientId: bigint, userData: Uint8Array | null ): void;

    /** Disconnect a loopback client. Loopback clients are not disconnected by regular Disconnect or DisconnectAllClient calls. */
    DisconnectLoopbackClient( clientIndex: number ): void;

    /** Is this client a loopback client? */
    IsLoopbackClient( clientIndex: number ): boolean;

    /** Process loopback packet: pass packets from a client directly to the loopback client slot on the server. */
    ProcessLoopbackPacket( clientIndex: number, packetData: Uint8Array, packetBytes: number, packetSequence: bigint ): void;
}
