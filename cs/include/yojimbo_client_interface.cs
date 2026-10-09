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
    /**
        The set of client states.
     */
    public enum ClientState
    {
        CLIENT_STATE_ERROR = -1,
        CLIENT_STATE_DISCONNECTED = 0,
        CLIENT_STATE_CONNECTING,
        CLIENT_STATE_CONNECTED,
    }

    /** 
        The common interface for all clients. //: ClientInterface -> IClient
     */
    public interface IClient : IDisposable
    {
        /**
            Set the context for reading and writing packets.
            This is optional. It lets you pass in a pointer to some structure that you want to have available when reading and writing packets via Stream::GetContext.
            Typical use case is to pass in an array of min/max ranges for values determined by some data that is loaded from a toolchain vs. being known at compile time. 
            If you do use a context, make sure the same context data is set on client and server, and include a checksum of the context data in the protocol id.
         */
        object Context { get; }

        /**
            Disconnect from the server.
         */
        void Disconnect();

        /**
            Send packets to server.
         */
        void SendPackets();

        /**
            Receive packets from the server.
         */
        void ReceivePackets();

        /**
            Advance client time.
            Call this at the end of each frame to advance the client time forward. 
            IMPORTANT: Please use a double for your time value so it maintains sufficient accuracy as time increases.
         */
        void AdvanceTime(double time);

        /**
            Is the client connecting to a server?
            This is true while the client is negotiation connection with a server.
            @returns true if the client is currently connecting to, but is not yet connected to a server.
         */
        bool IsConnecting { get; }

        /**
            Is the client connected to a server?
            This is true once a client successfully finishes connection negotiatio, and connects to a server. It is false while connecting to a server.
            @returns true if the client is connected to a server.
         */
        bool IsConnected { get; }

        /**
            Is the client in a disconnected state?
            A disconnected state corresponds to the client being in the disconnected, or in an error state. Both are logically "disconnected".
            @returns true if the client is disconnected.
         */
        bool IsDisconnected { get; }

        /**
            Is the client in an error state?
            When the client disconnects because of an error, it enters into this error state.
            @returns true if the client is in an error state.
         */
        bool ConnectionFailed { get; }

        /**
            Get the current client state.
         */
        ClientState ClientState { get; }

        /**
            Get the client index.
            The client index is the slot number that the client is occupying on the server. 
            @returns The client index in [0,maxClients-1], where maxClients is the number of client slots allocated on the server in Server::Start.
         */
        int ClientIndex { get; }

        /**
            Get the client id.
            The client id is a unique identifier of this client.
            @returns The client id.
         */
        ulong ClientId { get; }

        /**
            Get the current client time.
            @see Client::AdvanceTime
         */
        double Time { get; }

        /**
            Create a message of the specified type.
            @param type The type of the message to create. The message types corresponds to the message factory created by the adaptor set on this client.
         */
        Message CreateMessage(int type);

        /**
            Helper function to allocate a data block.
            This is typically used to create blocks of data to attach to block messages. See BlockMessage for details.
            @param bytes The number of bytes to allocate.
            @returns The pointer to the data block. This must be attached to a message via Client::AttachBlockToMessage, or freed via Client::FreeBlock.
         */
        byte[] AllocateBlock(int bytes);

        /**
            Attach data block to message.
            @param message The message to attach the block to. This message must be derived from BlockMessage.
            @param block Pointer to the block of data to attach. Must be created via Client::AllocateBlock.
            @param bytes Length of the block of data in bytes.
         */
        void AttachBlockToMessage(Message message, byte[] block, int bytes);

        /**
            Free a block of memory.
            @param block The block of memory created by Client::AllocateBlock.
         */
        void FreeBlock(ref byte[] block);

        /**
            Can we send a message on a channel?
            @param channelIndex The channel index in range [0,numChannels-1].
            @returns True if a message can be sent over the channel, false otherwise.
         */
        bool CanSendMessage(int channelIndex);

        /**
            Send a message on a channel.
            @param channelIndex The channel index in range [0,numChannels-1].
            @param message The message to send.
         */
        void SendMessage(int channelIndex, Message message);

        /**
            Receive a message from a channel.
            @param channelIndex The channel index in range [0,numChannels-1].
            @returns The message received, or null if no message is available. Make sure to release this message by calling Client::ReleaseMessage.
         */
        Message ReceiveMessage(int channelIndex);

        /**
            Release a message.
            Call this for messages received by Client::ReceiveMessage.
            @param message The message to release.
         */
        void ReleaseMessage<TMessage>(ref TMessage message) where TMessage : Message;

        /**
            Get client network info.
            Call this to receive information about the client network connection to the server, eg. round trip time, packet loss %, # of packets sent and so on.
            @param info The struct to be filled with network info [out].
         */
        void GetNetworkInfo(out NetworkInfo info);

        /**
            Connect to server over loopback.
            This allows you to have local clients connected to a server, for example for integrated server or singleplayer.
            @param clientIndex The index of the client.
            @param clientId The unique client id.
            @param maxClients The maximum number of clients supported by the server.
         */
        /// @returns True if the loopback connection was set up. On failure the client is left disconnected or in the error state.
        bool ConnectLoopback(int clientIndex, ulong clientId, int maxClients);

        /**
            Disconnect from server over loopback.
         */
        void DisconnectLoopback();

        /**
            Is this a loopback client?
            @returns true if the client is a loopback client, false otherwise.
         */
        bool IsLoopback { get; }

        /**
            Process loopback packet.
            Use this to pass packets from a server directly to the loopback client.
            @param packetData The packet data to process.
            @param packetBytes The number of bytes of packet data.
            @param packetSequence The packet sequence number.
         */
        void ProcessLoopbackPacket(byte[] packetData, int packetBytes, ulong packetSequence);
    }
}
