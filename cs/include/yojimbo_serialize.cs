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
            Serialize a sequence number relative to another (read/write/measure).
            The wrap is handled by lifting the smaller value into a second 65536-wide window before taking the difference, so the difference is always positive and usually tiny.
            IMPORTANT: Check the result! `if (!stream.serialize_sequence_relative(a, ref b)) return false;`
            @param stream The stream object. May be a read, write or measure stream.
            @param sequence1 The first sequence number to serialize relative to.
            @param sequence2 The second sequence number to be encoded relative to the first.
         */
        public static bool serialize_sequence_relative(this BaseStream stream, ushort sequence1, ref ushort sequence2)
        {
            if (stream.IsWriting)
            {
                int a = sequence1;
                int b = sequence2 + ((sequence1 > sequence2) ? 65536 : 0);
                if (!serialize_int_relative(stream, a, ref b))
                    return false;
            }
            else
            {
                int a = sequence1;
                var b = 0;
                if (!serialize_int_relative(stream, a, ref b))
                    return false;
                if (b >= 65536)
                    b -= 65536;
                sequence2 = (ushort)b;
            }
            return true;
        }
    }

    /**
        Interface for an object that knows how to read, write and measure how many bits it would take up in a bit stream.
        IMPORTANT: Instead of overriding the serialize virtual methods method directly, use the YOJIMBO_VIRTUAL_SERIALIZE_FUNCTIONS macro in your derived class to override and redirect them to your templated serialize method.
        This way you can implement read and write for your messages in a single method and the C++ compiler takes care of generating specialized read, write and measure implementations for you.
        See tests/shared.h for some examples of this.
        @see ReadStream
        @see WriteStream
        @see MeasureStream
     */

    public abstract class Serializable : IDisposable
    {
        public virtual void Dispose() { }

        /**
            Templated serialize function for the block message. Doesn't do anything. The block data is serialized elsewhere.
            You can override the serialize methods on a block message to implement your own serialize function. It's just like a regular message with a block attached to it.
            @see ConnectionPacket
            @see ChannelPacketData
            @see ReliableOrderedChannel
            @see UnreliableUnorderedChannel
         */
        public virtual bool Serialize(BaseStream stream) => true;

        /**
            Virtual serialize function (read).
            Reads the object in from a bitstream.
            @param stream The stream to read from.
         */
        public virtual bool SerializeInternal(ReadStream stream) =>
            Serialize(stream);

        /**
            Virtual serialize function (write).
            Writes the object to a bitstream.
            @param stream The stream to write to.
         */
        public virtual bool SerializeInternal(WriteStream stream) =>
            Serialize(stream);

        /**
            Virtual serialize function (measure).
            Quickly measures how many bits the object would take if it were written to a bit stream.
            @param stream The read stream.
         */
        public virtual bool SerializeInternal(MeasureStream stream) =>
            Serialize(stream);

        public bool SerializeInternal(BaseStream stream) =>
            stream is ReadStream ? SerializeInternal((ReadStream)stream) :
            stream is WriteStream ? SerializeInternal((WriteStream)stream) :
            stream is MeasureStream ? SerializeInternal((MeasureStream)stream) :
            Serialize(stream);
    }
}
