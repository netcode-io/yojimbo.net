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
    TypeScript port of include/yojimbo_adapter.h (yojimbo 1.13.5).

    Port notes:
      - SendPacket / ReceivePacket take yojimbo Address objects. ReceivePacket's `from` is an out parameter: the adapter
        sets it in place (from.Assign( address ), or by parsing into it).
      - packetData passed to SendPacket and the loopback callbacks is only valid during the call, and its length may
        exceed packetBytes: copy packetBytes bytes if you keep them.
      - The loopback packet sequence is uint64 (netcode), so it is a bigint.
*/

import { Allocator, TLSF_Allocator, YOJIMBO_NEW } from '../source/yojimbo_allocator.ts';
import { Address } from '../source/yojimbo_address.ts';
import { MessageFactory } from '../source/yojimbo_message.ts';
import { yojimbo_assert } from '../source/yojimbo_platform.ts';

/**
    Complete netcode.io datagrams passed to and from the adapter are at most this many bytes
    (netcode's internal NETCODE_MAX_PACKET_BYTES). Size custom transport buffers to THIS
    constant, not to the payload-size constants — a full datagram carries netcode framing
    and encryption overhead on top of the payload.
    @see Adapter::SendPacket
    @see Adapter::ReceivePacket
 */

export const MaxAdapterPacketBytes = 1300;

/**
    Specifies the message factory and callbacks for clients and servers.
    An instance of this class is passed into the client and server constructors.
    You can share the same adapter across a client/server pair if you have local multiplayer, eg. loopback.
 */

export class Adapter
{
    /** Adapter destructor (no-op by default). */

    Dispose(): void
    {
    }

    /**
        Override this function to specify your own custom allocator class.
        @param allocator The base allocator that must be used to allocate your allocator instance (YOJIMBO_NEW).
        @param memory The block of memory backing your allocator.
        @param bytes The number of bytes of memory available to your allocator.
        @returns The allocator instance you created, or null if it could not be created.
     */

    CreateAllocator( allocator: Allocator, memory: Uint8Array | null, bytes: number ): Allocator | null
    {
        return YOJIMBO_NEW( allocator, () => new TLSF_Allocator( memory, bytes ) );
    }

    /**
        You must override this method to create the message factory used by the client and server.
        @param allocator The allocator that must be used to create your message factory instance via YOJIMBO_NEW
        @returns The message factory you created.
     */

    CreateMessageFactory( _allocator: Allocator ): MessageFactory | null
    {
        yojimbo_assert( false, "CreateMessageFactory must be overridden", "Adapter::CreateMessageFactory" );
        return null;
    }

    /**
        Override to route netcode.io packets through a custom datagram transport.
        The result must remain stable for the lifetime of the client or server.
        The default is false and preserves yojimbo's native UDP sockets.
     */

    UseCustomPacketIO(): boolean
    {
        return false;
    }

    /**
        Send one complete netcode.io datagram through the custom transport.
        Called only when UseCustomPacketIO returns true. packetBytes is never larger than
        MaxAdapterPacketBytes, so buffers sized to that constant always fit the datagram.
        IMPORTANT: packetData is only valid during the call, and its length may exceed packetBytes. Copy packetBytes bytes.
        An adapter with UseCustomPacketIO() == true must be dedicated to a single Client
        or Server instance — never share it between two objects.
     */

    SendPacket( _to: Address, _packetData: Uint8Array, _packetBytes: number ): void
    {
        yojimbo_assert( false, "SendPacket must be overridden for custom packet I/O", "Adapter::SendPacket" );
    }

    /**
        Receive one complete netcode.io datagram from the custom transport.
        Set from to the stable transport-visible source address and return the byte count.
        Return zero when no packet is available.
        This function MUST be non-blocking: netcode calls it in a loop each update and
        drains packets until it returns zero. maxPacketBytes is MaxAdapterPacketBytes.
        @param from Set this to the address the packet came from [out] (it is passed in cleared).
        @param packetData The buffer to copy the datagram into.
        @param maxPacketBytes The size of the buffer.
     */

    ReceivePacket( _from: Address, _packetData: Uint8Array, _maxPacketBytes: number ): number
    {
        yojimbo_assert( false, "ReceivePacket must be overridden for custom packet I/O", "Adapter::ReceivePacket" );
        return 0;
    }

    /**
        Override this callback to process packets sent from client to server over loopback.
        @param clientIndex The client index in range [0,maxClients-1]
        @param packetData The packet data (raw) to be sent to the server. Only valid during the call.
        @param packetBytes The number of packet bytes.
        @param packetSequence The sequence number of the packet.
        @see Client::ConnectLoopback
     */

    ClientSendLoopbackPacket( _clientIndex: number, _packetData: Uint8Array, _packetBytes: number, _packetSequence: bigint ): void
    {
        yojimbo_assert( false, "ClientSendLoopbackPacket must be overridden for loopback", "Adapter::ClientSendLoopbackPacket" );
    }

    /**
        Override this callback to process packets sent from server to client over loopback.
        @param clientIndex The client index in range [0,maxClients-1]
        @param packetData The packet data (raw) to be sent to the client. Only valid during the call.
        @param packetBytes The number of packet bytes.
        @param packetSequence The sequence number of the packet.
        @see Server::ConnectLoopbackClient
     */

    ServerSendLoopbackPacket( _clientIndex: number, _packetData: Uint8Array, _packetBytes: number, _packetSequence: bigint ): void
    {
        yojimbo_assert( false, "ServerSendLoopbackPacket must be overridden for loopback", "Adapter::ServerSendLoopbackPacket" );
    }

    /**
        Override this to get a callback when a client connects on the server.
     */

    OnServerClientConnected( _clientIndex: number ): void
    {
    }

    /**
        Override this to get a callback when a client disconnects from the server.
     */

    OnServerClientDisconnected( _clientIndex: number ): void
    {
    }
}
