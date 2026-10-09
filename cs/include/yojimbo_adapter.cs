/*
    Yojimbo Client/Server Network Library.

    Copyright © 2016 - 2019, The Network Protocol Company, Inc.

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

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Text;
using System.Threading;

namespace networkprotocol
{
    static partial class yojimbo
    {
        /**
            Complete netcode.io datagrams passed to and from the adapter are at most this many bytes
            (netcode's internal NETCODE_MAX_PACKET_BYTES). Size custom transport buffers to THIS
            constant, not to the payload-size constants — a full datagram carries netcode framing
            and encryption overhead on top of the payload.
            @see Adapter::SendPacket
            @see Adapter::ReceivePacket
         */
        public const int MaxAdapterPacketBytes = netcode.MAX_PACKET_BYTES;
    }

    /** 
        Specifies the message factory and callbacks for clients and servers.
        An instance of this class is passed into the client and server constructors. 
        You can share the same adapter across a client/server pair if you have local multiplayer, eg. loopback.
     */
    public class Adapter : IDisposable
    {
        public virtual void Dispose() { }

        /**
            Override this function to specify your own custom allocator class.
            @param allocator The base allocator that must be used to allocate your allocator instance.
            @param memory The block of memory backing your allocator. In C# this is a placeholder (see yojimbo.YOJIMBO_ALLOCATE_MEMORY).
            @param bytes The number of bytes of memory available to your allocator.
            @returns A pointer to the allocator instance you created.
         */
        public virtual Allocator CreateAllocator(Allocator allocator, object memory, int bytes) =>
            yojimbo.YOJIMBO_NEW(allocator, () => new TLSF_Allocator(memory, bytes));

        /**
            You must override this method to create the message factory used by the client and server.
            @param allocator The allocator that must be used to create your message factory instance via YOJIMBO_NEW
            @returns The message factory pointer you created.

         */
        public virtual MessageFactory CreateMessageFactory(Allocator allocator)
        {
            yojimbo.assert(false);
            return null;
        }

        /**
            Override to route netcode.io packets through a custom datagram transport (v1.10).
            The result must remain stable for the lifetime of the client or server.
            The default is false and preserves yojimbo's native UDP sockets.
         */
        public virtual bool UseCustomPacketIO() => false;

        /**
            Send one complete netcode.io datagram through the custom transport.
            Called only when UseCustomPacketIO returns true. packetBytes is never larger than
            MaxAdapterPacketBytes, so buffers sized to that constant always fit the datagram.
            IMPORTANT: packetData is only valid during the call, and its Length may exceed packetBytes. Copy packetBytes bytes.
            An adapter with UseCustomPacketIO() == true must be dedicated to a single Client
            or Server instance — never share it between two objects.
         */
        public virtual void SendPacket(Address to, byte[] packetData, int packetBytes) =>
            yojimbo.assert(false);

        /**
            Receive one complete netcode.io datagram from the custom transport.
            Set from to the stable transport-visible source address and return the byte count.
            Return zero when no packet is available.
            This function MUST be non-blocking: netcode calls it in a loop each update and
            drains packets until it returns zero. maxPacketBytes is MaxAdapterPacketBytes.
            @param from Set this to the address the packet came from (a new, invalid Address is passed in).
         */
        public virtual int ReceivePacket(ref Address from, byte[] packetData, int maxPacketBytes)
        {
            yojimbo.assert(false);
            return 0;
        }

        /** 
            Override this callback to process packets sent from client to server over loopback.
            @param clientIndex The client index in range [0,maxClients-1]
            @param packetData The packet data (raw) to be sent to the server.
            @param packetBytes The number of packet bytes in the server.
            @param packetSequence The sequence number of the packet.
            @see Client::ConnectLoopback
         */
        public virtual void ClientSendLoopbackPacket(int clientIndex, byte[] packetData, int packetBytes, ulong packetSequence) =>
            yojimbo.assert(false);

        /**
            Override this callback to process packets sent from client to server over loopback.
            @param clientIndex The client index in range [0,maxClients-1]
            @param packetData The packet data (raw) to be sent to the server.
            @param packetBytes The number of packet bytes in the server.
            @param packetSequence The sequence number of the packet.
            @see Server::ConnectLoopbackClient
         */
        public virtual void ServerSendLoopbackPacket(int clientIndex, byte[] packetData, int packetBytes, ulong packetSequence) =>
            yojimbo.assert(false);

        /**
            Override this to get a callback when a client connects on the server.
         */
        public virtual void OnServerClientConnected(int clientIndex) { }

        /**
            Override this to get a callback when a client disconnects from the server.
         */
        public virtual void OnServerClientDisconnected(int clientIndex) { }
    }
}
