/*
    Serialize - C# port of the serialize library vendored by yojimbo (serialize/serialize.h).

    Copyright © 2016 - 2026, Mas Bandwidth LLC.

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
    PORTING NOTE: C++ serialize_* are macros that `return false` from the enclosing serialize function when a
    read fails. C# has no such macros, so every serialize_* here is an extension method returning bool, and
    EVERY call site must propagate it:

        if (!stream.serialize_int(ref value, 0, 10)) return false;

    Ignoring the result means a truncated or malformed (attacker controlled) packet is partially accepted.

    Wire format: bits are packed LSB first and flushed little endian. The C# writer flushes 32 bit words and the
    reader refills 32 bit words with a bounds checked load, so the byte stream is identical to upstream's 64 bit
    qword writer/reader, and no read slack is needed past the end of the buffer.
 */

using System;
using System.Numerics;
using System.Text;

namespace networkprotocol
{
    static partial class yojimbo
    {
        #region bit utils

        /**
            Calculates the population count of an unsigned 32 bit integer.
            The population count is the number of bits in the integer set to 1.
            @param x The input integer value.
            @returns The number of bits set to 1 in the input value.
         */
        public static uint popcount(uint x) =>
            (uint)BitOperations.PopCount(x);

        /**
            Calculates the log base 2 of an unsigned 32 bit integer.
            @param x The input integer value.
            @returns The log base 2 of the input.
         */
        public static uint log2(uint x)
        {
            var a = x | (x >> 1);
            var b = a | (a >> 2);
            var c = b | (b >> 4);
            var d = c | (c >> 8);
            var e = d | (d >> 16);
            var f = e >> 1;
            return popcount(f);
        }

        /**
            Calculates the number of bits required to serialize an integer in range [min,max].
            The subtraction is performed in the unsigned domain.
            @param min The minimum value.
            @param max The maximum value.
            @returns The number of bits required to serialize the integer in [0,32].
         */
        public static int bits_required(uint min, uint max) =>
            (min == max) ? 0 : (int)log2(max - min) + 1;

        /**
            Calculates the number of bits required to serialize a 64 bit integer in range [min,max].
            The subtraction is performed in the unsigned domain, so ranges wider than 2^63 work.
            @returns The number of bits required to serialize the integer in [0,64].
         */
        public static int bits_required64(ulong min, ulong max) =>
            (min == max) ? 0 : 64 - BitOperations.LeadingZeroCount(max - min);

        /**
            Calculates the number of bits required to serialize a 128 bit integer in range [min,max].
            The subtraction is performed in the unsigned domain, so ranges wider than 2^127 work.
            @returns The number of bits required to serialize the integer in [0,128].
         */
        public static int bits_required128(UInt128 min, UInt128 max) =>
            (min == max) ? 0 : 128 - (int)UInt128.LeadingZeroCount(max - min);

        /**
            Reverse the order of bytes in a 64 bit integer.
            @param value The input value.
            @returns The input value with the byte order reversed.
         */
        public static ulong bswap(ulong value)
        {
            value = (value & 0x00000000FFFFFFFF) << 32 | (value & 0xFFFFFFFF00000000) >> 32;
            value = (value & 0x0000FFFF0000FFFF) << 16 | (value & 0xFFFF0000FFFF0000) >> 16;
            value = (value & 0x00FF00FF00FF00FF) << 8 | (value & 0xFF00FF00FF00FF00) >> 8;
            return value;
        }

        /**
            Reverse the order of bytes in a 32 bit integer.
            @param value The input value.
            @returns The input value with the byte order reversed.
         */
        public static uint bswap(uint value) =>
            (value & 0x000000ff) << 24 | (value & 0x0000ff00) << 8 | (value & 0x00ff0000) >> 8 | (value & 0xff000000) >> 24;

        /**
            Reverse the order of bytes in a 16 bit integer.
            @param value The input value.
            @returns The input value with the byte order reversed.
         */
        public static ushort bswap(ushort value) =>
            (ushort)((value & 0x00ff) << 8 | (value & 0xff00) >> 8);

        /**
            Convert an integer value from local byte order to network byte order.
            IMPORTANT: Because most machines running yojimbo are little endian, yojimbo defines network byte order to be little endian.
            @returns The input value converted to network byte order. If this processor is little endian the output is the same as the input. If the processor is big endian, the output is the input byte swapped.
         */
        public static ulong host_to_network(ulong value) => BitConverter.IsLittleEndian ? value : bswap(value);
        public static uint host_to_network(uint value) => BitConverter.IsLittleEndian ? value : bswap(value);
        public static ushort host_to_network(ushort value) => BitConverter.IsLittleEndian ? value : bswap(value);

        /**
            Convert an integer value from network byte order to local byte order.
            IMPORTANT: Because most machines running yojimbo are little endian, yojimbo defines network byte order to be little endian.
            @returns The input value converted to local byte order. If this processor is little endian the output is the same as the input. If the processor is big endian, the output is the input byte swapped.
         */
        public static ulong network_to_host(ulong value) => BitConverter.IsLittleEndian ? value : bswap(value);
        public static uint network_to_host(uint value) => BitConverter.IsLittleEndian ? value : bswap(value);
        public static ushort network_to_host(ushort value) => BitConverter.IsLittleEndian ? value : bswap(value);

        /**
            Convert a signed integer to an unsigned integer with zig-zag encoding.
            0,-1,+1,-2,+2... becomes 0,1,2,3,4 ...
            @param n The input value.
            @returns The input value converted from signed to unsigned with zig-zag encoding.
         */
        public static uint signed_to_unsigned(int n) =>
            unchecked((uint)((n << 1) ^ (n >> 31)));

        /**
            Convert an unsigned integer to as signed integer with zig-zag encoding.
            0,1,2,3,4... becomes 0,-1,+1,-2,+2...
            @param n The input value.
            @returns The input value converted from unsigned to signed with zig-zag encoding.
         */
        public static int unsigned_to_signed(uint n) =>
            unchecked((int)((n >> 1) ^ (uint)(-(int)(n & 1))));

        #endregion
    }

    /**
        Bitpacks unsigned integer values to a buffer.
        Integer bit values are written to a 64 bit scratch value from right to left.
        Once the low 32 bits of the scratch is filled with bits it is flushed to memory as a little endian dword and the scratch value is shifted right by 32.
        The bit stream is written to memory in little endian order, which is considered network byte order for this library.
        The byte stream is identical to upstream's 64 bit qword writer: bit k of the stream always lands in byte k/8, bit k%8.
        @see BitReader
     */
    public class BitWriter
    {
        /**
            Bit writer constructor.
            Creates a bit writer object to write to the specified buffer.
            @param data The pointer to the buffer to fill with bitpacked data.
            @param bytes The size of the buffer in bytes. Must be a multiple of 4, because the bitpacker writes memory as dwords, not bytes.
         */
        public BitWriter(byte[] data, int bytes)
        {
            yojimbo.assert(data != null);
            yojimbo.assert((bytes % 4) == 0);
            yojimbo.assert(bytes <= data.Length);
            m_data = data;
            m_numWords = bytes / 4;
            m_numBits = m_numWords * 32;
            m_bitsWritten = 0;
            m_wordIndex = 0;
            m_scratch = 0;
            m_scratchBits = 0;
        }

        static void write32(byte[] b, int p, uint value)
        {
            p *= sizeof(uint);
            b[p] = (byte)value;
            b[p + 1] = (byte)(value >> 8);
            b[p + 2] = (byte)(value >> 0x10);
            b[p + 3] = (byte)(value >> 0x18);
        }

        /**
            Write bits to the buffer.
            Bits are written to the buffer as-is, without padding to nearest byte. Will assert if you try to write past the end of the buffer.
            A boolean value writes just 1 bit to the buffer, a value in range [0,31] can be written with just 5 bits and so on.
            IMPORTANT: When you have finished writing to your buffer, take care to call BitWrite::FlushBits, otherwise the last dword of data will not get flushed to memory!
            @param value The integer value to write to the buffer. Must be in [0,(1<<bits)-1].
            @param bits The number of bits to encode in [1,32].
            @see BitReader::ReadBits
         */
        public void WriteBits(uint value, int bits)
        {
            yojimbo.assert(bits > 0);
            yojimbo.assert(bits <= 32);
            yojimbo.assert(m_bitsWritten + bits <= m_numBits);
            yojimbo.assert(value <= (1UL << bits) - 1);

            m_scratch |= (ulong)value << m_scratchBits;

            m_scratchBits += bits;

            if (m_scratchBits >= 32)
            {
                yojimbo.assert(m_wordIndex < m_numWords);
                write32(m_data, m_wordIndex, (uint)(m_scratch & 0xFFFFFFFF));
                m_scratch >>= 32;
                m_scratchBits -= 32;
                m_wordIndex++;
            }

            m_bitsWritten += bits;
        }

        /**
            Write an alignment to the bit stream, padding zeros so the bit index becomes is a multiple of 8.
            This is useful if you want to write some data to a packet that should be byte aligned. For example, an array of bytes, or a string.
            IMPORTANT: If the current bit index is already a multiple of 8, nothing is written.
            @see BitReader::ReadAlign
         */
        public void WriteAlign()
        {
            var remainderBits = m_bitsWritten % 8;

            if (remainderBits != 0)
            {
                WriteBits(0U, 8 - remainderBits);
                yojimbo.assert((m_bitsWritten % 8) == 0);
            }
        }

        /**
            Write an array of bytes to the bit stream.
            Use this when you have to copy a large block of data into your bitstream.
            Faster than just writing each byte to the bit stream via BitWriter::WriteBits( value, 8 ), because it aligns to byte index and copies into the buffer without bitpacking.
            @param data The byte array data to write to the bit stream.
            @param bytes The number of bytes to write.
            @see BitReader::ReadBytes
         */
        public void WriteBytes(byte[] data, int bytes)
        {
            yojimbo.assert(AlignBits == 0);
            yojimbo.assert(m_bitsWritten + bytes * 8 <= m_numBits);
            yojimbo.assert((m_bitsWritten % 32) == 0 || (m_bitsWritten % 32) == 8 || (m_bitsWritten % 32) == 16 || (m_bitsWritten % 32) == 24);

            var headBytes = (4 - (m_bitsWritten % 32) / 8) % 4;
            if (headBytes > bytes)
                headBytes = bytes;
            for (var i = 0; i < headBytes; ++i)
                WriteBits(data[i], 8);
            if (headBytes == bytes)
                return;

            FlushBits();

            yojimbo.assert(AlignBits == 0);

            var numWords = (bytes - headBytes) / 4;
            if (numWords > 0)
            {
                yojimbo.assert((m_bitsWritten % 32) == 0);
                Buffer.BlockCopy(data, headBytes, m_data, m_wordIndex * sizeof(uint), numWords * 4);
                m_bitsWritten += numWords * 32;
                m_wordIndex += numWords;
                m_scratch = 0;
            }

            yojimbo.assert(AlignBits == 0);

            var tailStart = headBytes + numWords * 4;
            var tailBytes = bytes - tailStart;
            yojimbo.assert(tailBytes >= 0 && tailBytes < 4);
            for (var i = 0; i < tailBytes; ++i)
                WriteBits(data[tailStart + i], 8);

            yojimbo.assert(AlignBits == 0);

            yojimbo.assert(headBytes + numWords * 4 + tailBytes == bytes);
        }

        /**
            Flush any remaining bits to memory.
            Call this once after you've finished writing bits to flush the last dword of scratch to memory!
            @see BitWriter::WriteBits
         */
        public void FlushBits()
        {
            if (m_scratchBits != 0)
            {
                yojimbo.assert(m_scratchBits <= 32);
                yojimbo.assert(m_wordIndex < m_numWords);
                write32(m_data, m_wordIndex, (uint)(m_scratch & 0xFFFFFFFF));
                m_scratch >>= 32;
                m_scratchBits = 0;
                m_wordIndex++;
            }
        }

        /**
            How many align bits would be written, if we were to write an align right now?
            @returns Result in [0,7], where 0 is zero bits required to align (already aligned) and 7 is worst case.
         */
        public int AlignBits =>
            (8 - (m_bitsWritten % 8)) % 8;

        /**
            How many bits have we written so far?
            @returns The number of bits written to the bit buffer.
         */
        public int BitsWritten =>
            m_bitsWritten;

        /**
            How many bits are still available to write?
            For example, if the buffer size is 4, we have 32 bits available to write, if we have already written 10 bytes then 22 are still available to write.
            @returns The number of bits available to write.
         */
        public int BitsAvailable =>
            m_numBits - m_bitsWritten;

        /**
            Get a pointer to the data written by the bit writer.
            Corresponds to the data block passed in to the constructor.
            @returns Pointer to the data written by the bit writer.
         */
        public byte[] Data =>
            m_data;

        /**
            The number of bytes flushed to memory.
            This is effectively the size of the packet that you should send after you have finished bitpacking values with this class.
            The returned value is not always a multiple of 4, even though we flush dwords to memory. You won't miss any data in this case because the order of bits written is designed to work with the little endian memory layout.
            IMPORTANT: Make sure you call BitWriter::FlushBits before calling this method, otherwise you risk missing the last dword of data.
         */
        public int BytesWritten =>
            (m_bitsWritten + 7) / 8;

        byte[] m_data;                              ///< The buffer we are writing to.
        ulong m_scratch;                            ///< The scratch value where we write bits to (right to left). 64 bit for overflow. Once # of bits in scratch is >= 32, the low 32 bits are flushed to memory.
        int m_numBits;                              ///< The number of bits in the buffer. This is equivalent to the size of the buffer in bytes multiplied by 8. Note that the buffer size must always be a multiple of 4.
        int m_numWords;                             ///< The number of words in the buffer. This is equivalent to the size of the buffer in bytes divided by 4. Note that the buffer size must always be a multiple of 4.
        int m_bitsWritten;                          ///< The number of bits written so far.
        int m_wordIndex;                            ///< The current word index. The next word flushed to memory will be at this index in m_data.
        int m_scratchBits;                          ///< The number of bits in scratch. When this is >= 32, the low 32 bits of scratch is flushed to memory as a dword and scratch is shifted right by 32.
    }

    /**
        Reads bit packed integer values from a buffer.
        Relies on the user reconstructing the exact same set of bit reads as bit writes when the buffer was written. This is an unattributed bitpacked binary stream!
        Implementation: 32 bit dwords are read in from memory to the high bits of a scratch value as required. The user reads off bit values from the scratch value from the right, after which the scratch value is shifted by the same number of bits.
        Unlike upstream (which loads an 8 byte window and needs 8 bytes of slack past the data), dword loads here are bounds checked against the array, so an exact size buffer is fine.
     */
    public class BitReader
    {
        /**
            Bit reader constructor.
            Non-multiples of four buffer sizes are supported, as this naturally tends to occur when packets are read from the network.
            @param data Pointer to the bitpacked data to read.
            @param bytes The number of bytes of bitpacked data to read.
            @see BitWriter
         */
        public BitReader(byte[] data, int bytes)
        {
            yojimbo.assert(data != null);
            yojimbo.assert(bytes >= 0 && bytes <= data.Length);
            m_data = data;
            m_numBytes = bytes;
            m_numWords = (bytes + 3) / 4;
            m_numBits = m_numBytes * 8;
            m_bitsRead = 0;
            m_scratch = 0;
            m_scratchBits = 0;
            m_wordIndex = 0;
        }

        // bounds checked little endian dword load: bytes past the end of the data read as zero
        uint read32(int p)
        {
            p *= sizeof(uint);
            var value = 0U;
            for (var i = 0; i < 4; ++i)
                if (p + i < m_numBytes)
                    value |= (uint)m_data[p + i] << (8 * i);
            return value;
        }

        /**
            Would the bit reader would read past the end of the buffer if it read this many bits?
            A reader whose position has been poisoned (see BitReader::PoisonPosition) answers true for every bit count, zero included, which is what makes the failure latch total.
            @param bits The number of bits that would be read.
            @returns True if reading the number of bits would read past the end of the buffer.
         */
        public bool WouldReadPastEnd(int bits) =>
            (long)m_bitsRead + bits > m_numBits;

        /**
            Poison the read position so every later read on this reader fails.
            @see ReadStream::Fail
         */
        public void PoisonPosition() =>
            m_bitsRead = m_numBits + 1;

        /**
            Read bits from the bit buffer.
            This function will assert in debug builds if this read would read past the end of the buffer.
            In production situations, the higher level ReadStream takes care of checking all packet data and never calling this function if it would read past the end of the buffer.
            @param bits The number of bits to read in [1,32].
            @returns The integer value read in range [0,(1<<bits)-1].
            @see BitReader::WouldReadPastEnd
            @see BitWriter::WriteBits
         */
        public uint ReadBits(int bits)
        {
            yojimbo.assert(bits > 0);
            yojimbo.assert(bits <= 32);
            yojimbo.assert(m_bitsRead + bits <= m_numBits);

            m_bitsRead += bits;

            yojimbo.assert(m_scratchBits >= 0 && m_scratchBits <= 64);

            if (m_scratchBits < bits)
            {
                yojimbo.assert(m_wordIndex < m_numWords);
                m_scratch |= (ulong)read32(m_wordIndex) << m_scratchBits;
                m_scratchBits += 32;
                m_wordIndex++;
            }

            yojimbo.assert(m_scratchBits >= bits);

            var output = (uint)(m_scratch & ((1UL << bits) - 1));

            m_scratch >>= bits;
            m_scratchBits -= bits;

            return output;
        }

        /**
            Read an align.
            Call this on read to correspond to a WriteAlign call when the bitpacked buffer was written.
            This makes sure we skip ahead to the next aligned byte index. As a safety check, we verify that the padding to next byte is zero bits and return false if that's not the case.
            @returns True if we successfully read an align and skipped ahead past zero pad, false otherwise (probably means, no align was written to the stream).
            @see BitWriter::WriteAlign
         */
        public bool ReadAlign()
        {
            var remainderBits = m_bitsRead % 8;
            if (remainderBits != 0)
            {
                var value = ReadBits(8 - remainderBits);
                yojimbo.assert(m_bitsRead % 8 == 0);
                if (value != 0)
                    return false;
            }
            return true;
        }

        /**
            Read bytes from the bitpacked data.
            @see BitWriter::WriteBytes
         */
        public void ReadBytes(byte[] data, int bytes)
        {
            yojimbo.assert(AlignBits == 0);
            yojimbo.assert(m_bitsRead + bytes * 8 <= m_numBits);
            yojimbo.assert((m_bitsRead % 32) == 0 || (m_bitsRead % 32) == 8 || (m_bitsRead % 32) == 16 || (m_bitsRead % 32) == 24);

            var headBytes = (4 - (m_bitsRead % 32) / 8) % 4;
            if (headBytes > bytes)
                headBytes = bytes;
            for (var i = 0; i < headBytes; ++i)
                data[i] = (byte)ReadBits(8);
            if (headBytes == bytes)
                return;

            yojimbo.assert(AlignBits == 0);

            var numWords = (bytes - headBytes) / 4;
            if (numWords > 0)
            {
                yojimbo.assert((m_bitsRead % 32) == 0);
                Buffer.BlockCopy(m_data, m_wordIndex * sizeof(uint), data, headBytes, numWords * 4);
                m_bitsRead += numWords * 32;
                m_wordIndex += numWords;
                m_scratchBits = 0;
            }

            yojimbo.assert(AlignBits == 0);

            var tailStart = headBytes + numWords * 4;
            var tailBytes = bytes - tailStart;
            yojimbo.assert(tailBytes >= 0 && tailBytes < 4);
            for (var i = 0; i < tailBytes; ++i)
                data[tailStart + i] = (byte)ReadBits(8);

            yojimbo.assert(AlignBits == 0);

            yojimbo.assert(headBytes + numWords * 4 + tailBytes == bytes);
        }

        /**
            How many align bits would be read, if we were to read an align right now?
            @returns Result in [0,7], where 0 is zero bits required to align (already aligned) and 7 is worst case.
         */
        public int AlignBits =>
            (8 - m_bitsRead % 8) % 8;

        /**
            How many bits have we read so far?
            @returns The number of bits read from the bit buffer so far.
         */
        public int BitsRead =>
            m_bitsRead;

        /**
            How many bits are still available to read?
            For example, if the buffer size is 4, we have 32 bits available to read, if we have already written 10 bytes then 22 are still available.
            @returns The number of bits available to read.
         */
        public int BitsRemaining =>
            m_numBits - m_bitsRead;

        byte[] m_data;                              ///< The bitpacked data we're reading.
        ulong m_scratch;                            ///< The scratch value. New data is read in 32 bits at a top to the left of this buffer, and data is read off to the right.
        int m_numBits;                              ///< Number of bits to read in the buffer. Of course, we can't *really* know this so it's actually m_numBytes * 8.
        int m_numBytes;                             ///< Number of bytes to read in the buffer. We know this, and this is the non-rounded up version.
        int m_numWords;                             ///< Number of words to read in the buffer. This is rounded up to the next word if necessary.
        int m_bitsRead;                             ///< Number of bits read from the buffer so far.
        int m_scratchBits;                          ///< Number of bits currently in the scratch value. If the user wants to read more bits than this, we have to go fetch another dword from memory.
        int m_wordIndex;                            ///< Index of the next word to read from memory.
    }

    /**
        Functionality common to all stream classes.
     */
    public abstract class BaseStream
    {
        /**
            Base stream constructor.
            @param allocator The allocator to use for stream allocations. This lets you dynamically allocate memory as you read and write packets. May be null.
         */
        public BaseStream(Allocator allocator = null)
        {
            m_allocator = allocator;
            m_context = null;
        }

        public abstract bool IsWriting { get; }
        public abstract bool IsReading { get; }

        public abstract bool SerializeInteger(ref int value, int min, int max);
        public abstract bool SerializeInteger64(ref long value, long min, long max);
        public abstract bool SerializeInteger128(ref Int128 value, Int128 min, Int128 max);
        public abstract bool SerializeBits(ref uint value, int bits);
        public abstract bool SerializeBytes(byte[] data, int bytes);
        public abstract bool SerializeAlign();
        public abstract int AlignBits { get; }
        public abstract int BytesProcessed { get; }
        public abstract int BitsProcessed { get; }

        /**
            Refuse the read in progress and latch the stream into the failed state.
            Only a read stream has a failure state; write and measure streams never refuse, so this just returns false for them.
            @returns Always false.
            @see ReadStream::Fail
         */
        public virtual bool Fail() => false;

        /**
           Gets or sets a context on the stream.
           The context lets you pass data through to your serialize functions, for example lookup tables or min/max ranges needed to read and write values.
           If you are using the yojimbo client/server or connection classes you should NOT set this manually. It's already taken!
        */
        public object Context
        {
            get => m_context;
            set => m_context = value;
        }

        /**
            Gets or sets the allocator on the stream.
            You can use this allocator to dynamically allocate memory while reading and writing packets.
         */
        public Allocator Allocator
        {
            get => m_allocator;
            set => m_allocator = value;
        }

        public void SetContext(object context) => m_context = context;
        public object GetContext() => m_context;
        public void SetAllocator(Allocator allocator) => m_allocator = allocator;
        public Allocator GetAllocator() => m_allocator;

        Allocator m_allocator;                      ///< The allocator pointer set on the stream. May be null.
        object m_context;                           ///< The context pointer set on the stream. May be null.
    }

    /**
        Stream class for writing bitpacked data.
        This class is a wrapper around the bit writer class. Its purpose is to provide unified interface for reading and writing.
        IMPORTANT: Generally, you don't call methods on this class directly. Use the serialize_* functions instead. See shared.cs for some examples.
        @see BitWriter
     */
    public class WriteStream : BaseStream
    {
        public override bool IsWriting => true;
        public override bool IsReading => false;

        /**
            Write stream constructor.
            @param buffer The buffer to write to.
            @param bytes The number of bytes in the buffer. Must be a multiple of four.
         */
        public WriteStream(byte[] buffer, int bytes) : this(null, buffer, bytes) { }

        /**
            Write stream constructor.
            @param allocator The allocator to use for stream allocations. May be null.
            @param buffer The buffer to write to.
            @param bytes The number of bytes in the buffer. Must be a multiple of four.
         */
        public WriteStream(Allocator allocator, byte[] buffer, int bytes) : base(allocator)
        {
            m_writer = new BitWriter(buffer, bytes);
        }

        /**
            Serialize an integer (write).
            A degenerate range (min == max) costs zero bits.
            @returns Always returns true. All checking is performed by debug asserts only on write.
         */
        public override bool SerializeInteger(ref int value, int min, int max)
        {
            yojimbo.assert(min <= max);
            yojimbo.assert(value >= min);
            yojimbo.assert(value <= max);
            var bits = yojimbo.bits_required((uint)min, (uint)max);
            if (bits == 0)
                return true;                // degenerate range: the value IS the range, nothing to send
            var unsigned_value = unchecked((uint)value - (uint)min);
            m_writer.WriteBits(unsigned_value, bits);
            return true;
        }

        /**
            Serialize a 64 bit integer (write).
            @returns Always returns true. All checking is performed by debug asserts only on write.
         */
        public override bool SerializeInteger64(ref long value, long min, long max)
        {
            yojimbo.assert(min <= max);
            yojimbo.assert(value >= min);
            yojimbo.assert(value <= max);
            var bits = yojimbo.bits_required64((ulong)min, (ulong)max);
            if (bits == 0)
                return true;
            var unsigned_value = unchecked((ulong)value - (ulong)min);
            if (bits <= 32)
                m_writer.WriteBits((uint)unsigned_value, bits);
            else
            {
                m_writer.WriteBits((uint)(unsigned_value & 0xFFFFFFFF), 32);
                m_writer.WriteBits((uint)(unsigned_value >> 32), bits - 32);
            }
            return true;
        }

        /**
            Serialize a 128 bit integer (write). 32 bit groups, least significant first.
            @returns Always returns true. All checking is performed by debug asserts only on write.
         */
        public override bool SerializeInteger128(ref Int128 value, Int128 min, Int128 max)
        {
            yojimbo.assert(min <= max);
            yojimbo.assert(value >= min);
            yojimbo.assert(value <= max);
            var bits = yojimbo.bits_required128((UInt128)min, (UInt128)max);
            if (bits == 0)
                return true;
            var unsigned_value = unchecked((UInt128)value - (UInt128)min);
            var group0 = (uint)(ulong)(unsigned_value & 0xFFFFFFFF);
            var group1 = (uint)(ulong)((unsigned_value >> 32) & 0xFFFFFFFF);
            var group2 = (uint)(ulong)((unsigned_value >> 64) & 0xFFFFFFFF);
            var group3 = (uint)(ulong)((unsigned_value >> 96) & 0xFFFFFFFF);
            if (bits <= 32)
                m_writer.WriteBits(group0, bits);
            else if (bits <= 64)
            {
                m_writer.WriteBits(group0, 32);
                m_writer.WriteBits(group1, bits - 32);
            }
            else if (bits <= 96)
            {
                m_writer.WriteBits(group0, 32);
                m_writer.WriteBits(group1, 32);
                m_writer.WriteBits(group2, bits - 64);
            }
            else
            {
                m_writer.WriteBits(group0, 32);
                m_writer.WriteBits(group1, 32);
                m_writer.WriteBits(group2, 32);
                m_writer.WriteBits(group3, bits - 96);
            }
            return true;
        }

        /**
            Serialize a number of bits (write).
            @param value The unsigned integer value to serialize. Must be in range [0,(1<<bits)-1].
            @param bits The number of bits to write in [1,32].
            @returns Always returns true. All checking is performed by debug asserts on write.
         */
        public override bool SerializeBits(ref uint value, int bits)
        {
            yojimbo.assert(bits > 0);
            yojimbo.assert(bits <= 32);
            m_writer.WriteBits(value, bits);
            return true;
        }

        /**
            Serialize an array of bytes (write).
            @param data Array of bytes to be written.
            @param bytes The number of bytes to write.
            @returns Always returns true. All checking is performed by debug asserts on write.
         */
        public override bool SerializeBytes(byte[] data, int bytes)
        {
            yojimbo.assert(data != null);
            yojimbo.assert(bytes >= 0);
            SerializeAlign();
            m_writer.WriteBytes(data, bytes);
            return true;
        }

        /**
            Serialize an align (write).
            @returns Always returns true. All checking is performed by debug asserts on write.
         */
        public override bool SerializeAlign()
        {
            m_writer.WriteAlign();
            return true;
        }

        /**
            If we were to write an align right now, how many bits would be required?
            @returns The number of zero pad bits required to achieve byte alignment in [0,7].
         */
        public override int AlignBits =>
             m_writer.AlignBits;

        /**
            Flush the stream to memory after you finish writing.
            Always call this after you finish writing and before you call WriteStream::GetData, or you'll potentially truncate the last dword of data you wrote.
            @see BitWriter::FlushBits
         */
        public void Flush() =>
            m_writer.FlushBits();

        /**
            Get a pointer to the data written by the stream.
            IMPORTANT: Call WriteStream::Flush before you call this function!
            @returns A pointer to the data written by the stream
         */
        public byte[] Data =>
            m_writer.Data;

        /**
            How many bytes have been written so far?
            @returns Number of bytes written. This is effectively the packet size.
         */
        public override int BytesProcessed =>
            m_writer.BytesWritten;

        /**
            Get number of bits written so far.
            @returns Number of bits written.
         */
        public override int BitsProcessed =>
            m_writer.BitsWritten;

        BitWriter m_writer;                         ///< The bit writer used for all bitpacked write operations.
    }

    /**
        Stream class for reading bitpacked data.
        This class is a wrapper around the bit reader class. Its purpose is to provide unified interface for reading and writing.
        Failure is terminal: the first refused read latches the stream, and every later read on it fails, consuming no bits and writing no destination.
        IMPORTANT: Generally, you don't call methods on this class directly. Use the serialize_* functions instead. See shared.cs for some examples.
        @see BitReader
     */
    public class ReadStream : BaseStream
    {
        public override bool IsWriting => false;
        public override bool IsReading => true;

        /**
            Read stream constructor.
            @param buffer The buffer to read from.
            @param bytes The number of bytes in the buffer. May be a non-multiple of four.
         */
        public ReadStream(byte[] buffer, int bytes) : this(null, buffer, bytes) { }

        /**
            Read stream constructor.
            @param allocator The allocator to use for stream allocations. May be null.
            @param buffer The buffer to read from.
            @param bytes The number of bytes in the buffer. May be a non-multiple of four.
         */
        public ReadStream(Allocator allocator, byte[] buffer, int bytes) : base(allocator)
        {
            m_reader = new BitReader(buffer, bytes);
        }

        /**
            Refuse the read in progress and latch the stream into the failed state.
            Failure is terminal: the first refused read poisons the reader's position, and every later read on this stream fails, consuming no bits and writing no destination.
            Every refusal on this stream goes through here, including refusals decided outside the stream (a malformed string payload, an int_relative reconstruction outside the domain), which reach it through yojimbo.serialize_fail.
            @returns Always false.
         */
        public override bool Fail()
        {
            m_reader.PoisonPosition();
            return false;
        }

        /**
            Serialize an integer (read).
            @param value The integer value read is stored here. It is guaranteed to be in [min,max] if this function succeeds. Untouched on failure.
            @param min The minimum allowed value.
            @param max The maximum allowed value.
            @returns Returns true if the serialize succeeded and the value is in the correct range. False otherwise.
         */
        public override bool SerializeInteger(ref int value, int min, int max)
        {
            yojimbo.assert(min <= max);
            var bits = yojimbo.bits_required((uint)min, (uint)max);
            // the past-end check comes before the degenerate case so a failed stream refuses a zero bit read too
            if (m_reader.WouldReadPastEnd(bits))
                return Fail();
            if (bits == 0)
            {
                value = min;                // degenerate range: the value IS the range
                return true;
            }
            var unsigned_value = m_reader.ReadBits(bits);
            // the read side range rule: compared in the unsigned domain, which cannot overflow on hostile input
            if (unsigned_value > unchecked((uint)max - (uint)min))
                return Fail();
            value = unchecked((int)(unsigned_value + (uint)min));
            return true;
        }

        /**
            Serialize a 64 bit integer (read).
            @returns Returns true if the serialize succeeded and the value is in the correct range. False otherwise.
         */
        public override bool SerializeInteger64(ref long value, long min, long max)
        {
            yojimbo.assert(min <= max);
            var bits = yojimbo.bits_required64((ulong)min, (ulong)max);
            if (m_reader.WouldReadPastEnd(bits))
                return Fail();
            if (bits == 0)
            {
                value = min;
                return true;
            }
            ulong unsigned_value;
            if (bits <= 32)
                unsigned_value = m_reader.ReadBits(bits);
            else
            {
                // low dword first, then the high remainder: same convention as serialize_bits and serialize_uint64
                var lo = m_reader.ReadBits(32);
                var hi = m_reader.ReadBits(bits - 32);
                unsigned_value = ((ulong)hi << 32) | lo;
            }
            if (unsigned_value > unchecked((ulong)max - (ulong)min))
                return Fail();
            value = unchecked((long)(unsigned_value + (ulong)min));
            return true;
        }

        /**
            Serialize a 128 bit integer (read). 32 bit groups, least significant first.
            @returns Returns true if the serialize succeeded and the value is in the correct range. False otherwise.
         */
        public override bool SerializeInteger128(ref Int128 value, Int128 min, Int128 max)
        {
            yojimbo.assert(min <= max);
            var bits = yojimbo.bits_required128((UInt128)min, (UInt128)max);
            if (m_reader.WouldReadPastEnd(bits))
                return Fail();
            if (bits == 0)
            {
                value = min;
                return true;
            }
            uint group0 = 0, group1 = 0, group2 = 0, group3 = 0;
            if (bits <= 32)
                group0 = m_reader.ReadBits(bits);
            else if (bits <= 64)
            {
                group0 = m_reader.ReadBits(32);
                group1 = m_reader.ReadBits(bits - 32);
            }
            else if (bits <= 96)
            {
                group0 = m_reader.ReadBits(32);
                group1 = m_reader.ReadBits(32);
                group2 = m_reader.ReadBits(bits - 64);
            }
            else
            {
                group0 = m_reader.ReadBits(32);
                group1 = m_reader.ReadBits(32);
                group2 = m_reader.ReadBits(32);
                group3 = m_reader.ReadBits(bits - 96);
            }
            var unsigned_value = ((UInt128)group3 << 96) | ((UInt128)group2 << 64) | ((UInt128)group1 << 32) | group0;
            if (unsigned_value > unchecked((UInt128)max - (UInt128)min))
                return Fail();
            value = unchecked((Int128)(unsigned_value + (UInt128)min));
            return true;
        }

        /**
            Serialize a number of bits (read).
            @param value The integer value read is stored here. Will be in range [0,(1<<bits)-1]. Untouched on failure.
            @param bits The number of bits to read in [1,32].
            @returns Returns true if the serialize read succeeded, false otherwise.
         */
        public override bool SerializeBits(ref uint value, int bits)
        {
            yojimbo.assert(bits > 0);
            yojimbo.assert(bits <= 32);
            if (m_reader.WouldReadPastEnd(bits))
                return Fail();
            var read_value = m_reader.ReadBits(bits);
            value = read_value;
            return true;
        }

        /**
            Serialize an array of bytes (read).
            IMPORTANT: on a refused read the caller's buffer contents are unspecified.
            @param data Array of bytes to read into. Must be at least bytes long.
            @param bytes The number of bytes to read.
            @returns Returns true if the serialize read succeeded. False otherwise.
         */
        public override bool SerializeBytes(byte[] data, int bytes)
        {
            if (bytes < 0)
                return Fail();
            // the align is what refuses on a failed stream: a poisoned position reads past the end at every align width
            if (!SerializeAlign())
                return false;
            // compare in bytes rather than bits, so a huge byte count cannot overflow
            if (bytes > m_reader.BitsRemaining / 8)
                return Fail();
            // C# only: refuse rather than throw if the destination is too small
            if (data == null || data.Length < bytes)
                return Fail();
            m_reader.ReadBytes(data, bytes);
            return true;
        }

        /**
            Serialize an align (read).
            @returns Returns true if the serialize read succeeded. False otherwise.
         */
        public override bool SerializeAlign()
        {
            var alignBits = m_reader.AlignBits;
            if (m_reader.WouldReadPastEnd(alignBits))
                return Fail();
            if (!m_reader.ReadAlign())
                return Fail();
            return true;
        }

        /**
            If we were to read an align right now, how many bits would we need to read?
            @returns The number of zero pad bits required to achieve byte alignment in [0,7].
         */
        public override int AlignBits =>
            m_reader.AlignBits;

        /**
            Get number of bits read so far.
            @returns Number of bits read.
         */
        public override int BitsProcessed =>
            m_reader.BitsRead;

        /**
            How many bytes have been read so far?
            @returns Number of bytes read. Effectively this is the number of bits read, rounded up to the next byte where necessary.
         */
        public override int BytesProcessed =>
            (m_reader.BitsRead + 7) / 8;

        BitReader m_reader;                         ///< The bit reader used for all bitpacked read operations.
    }

    /**
        Stream class for estimating how many bits it would take to serialize something.
        This class acts like a bit writer (IsWriting is 1, IsReading is 0), but instead of writing data, it counts how many bits would be written.
        It's used by the connection channel classes to work out how many messages will fit in the channel packet budget.
        Note that when the serialization includes alignment to byte (see MeasureStream::SerializeAlign), this is an estimate and not an exact measurement. The estimate is guaranteed to be conservative.
        @see BitWriter
        @see BitReader
     */
    public class MeasureStream : BaseStream
    {
        public override bool IsWriting => true;
        public override bool IsReading => false;

        /**
            Measure stream constructor.
            @param allocator The allocator to use for stream allocations. May be null.
         */
        public MeasureStream(Allocator allocator = null) : base(allocator)
        {
            m_bitsWritten = 0;
        }

        /**
            Serialize an integer (measure).
            @returns Always returns true. All checking is performed by debug asserts only on measure.
         */
        public override bool SerializeInteger(ref int value, int min, int max)
        {
            yojimbo.assert(min <= max);
            yojimbo.assert(value >= min);
            yojimbo.assert(value <= max);
            m_bitsWritten += yojimbo.bits_required((uint)min, (uint)max);
            return true;
        }

        /**
            Serialize a 64 bit integer (measure).
            @returns Always returns true. All checking is performed by debug asserts only on measure.
         */
        public override bool SerializeInteger64(ref long value, long min, long max)
        {
            yojimbo.assert(min <= max);
            yojimbo.assert(value >= min);
            yojimbo.assert(value <= max);
            m_bitsWritten += yojimbo.bits_required64((ulong)min, (ulong)max);
            return true;
        }

        /**
            Serialize a 128 bit integer (measure).
            @returns Always returns true. All checking is performed by debug asserts only on measure.
         */
        public override bool SerializeInteger128(ref Int128 value, Int128 min, Int128 max)
        {
            yojimbo.assert(min <= max);
            yojimbo.assert(value >= min);
            yojimbo.assert(value <= max);
            m_bitsWritten += yojimbo.bits_required128((UInt128)min, (UInt128)max);
            return true;
        }

        /**
            Serialize a number of bits (measure).
            @returns Always returns true. All checking is performed by debug asserts on write.
         */
        public override bool SerializeBits(ref uint value, int bits)
        {
            yojimbo.assert(bits > 0);
            yojimbo.assert(bits <= 32);
            m_bitsWritten += bits;
            return true;
        }

        /**
            Serialize an array of bytes (measure).
            @returns Always returns true. All checking is performed by debug asserts on write.
         */
        public override bool SerializeBytes(byte[] data, int bytes)
        {
            yojimbo.assert(bytes >= 0);
            SerializeAlign();
            m_bitsWritten += bytes * 8;
            return true;
        }

        /**
            Serialize an align (measure).
            @returns Always returns true. All checking is performed by debug asserts on write.
         */
        public override bool SerializeAlign()
        {
            m_bitsWritten += AlignBits;
            return true;
        }

        /**
            If we were to write an align right now, how many bits would be required?
            IMPORTANT: Since the number of bits required for alignment depends on where an object is written in the final bit stream, this measurement is conservative.
            @returns Always returns worst case 7 bits.
         */
        public override int AlignBits =>
            7;

        /**
            Get number of bits written so far.
            @returns Number of bits written.
         */
        public override int BitsProcessed =>
            m_bitsWritten;

        /**
            How many bytes have been written so far?
            @returns Number of bytes written.
         */
        public override int BytesProcessed =>
            (m_bitsWritten + 7) / 8;

        int m_bitsWritten;                          ///< Counts the number of bits written.
    }

    static partial class yojimbo
    {
        /**
            Refuse the read in progress on this stream.
            @param stream The stream the refusal happened on.
            @returns Always false, so a refusing read reads `return serialize_fail( stream );`.
            @see ReadStream::Fail
         */
        public static bool serialize_fail(this BaseStream stream) =>
            stream.Fail();

        #region serialize_int

        /**
            Serialize integer value (read/write/measure).
            min <= max is the legal relation. A degenerate range where min == max costs zero bits.
            On read, a refused read leaves value exactly as the caller left it, and fails the stream.
            IMPORTANT: Check the result! `if (!stream.serialize_int(ref value, min, max)) return false;`
            @param stream The stream object. May be a read, write or measure stream.
            @param value The integer value to serialize in [min,max].
            @param min The minimum value.
            @param max The maximum value.
         */
        public static bool serialize_int(this BaseStream stream, ref int value, int min, int max)
        {
            assert(min <= max);
            var int32_value = 0;
            if (stream.IsWriting)
            {
                assert(value >= min);
                assert(value <= max);
                int32_value = value;
            }
            if (!stream.SerializeInteger(ref int32_value, min, max))
                return false;
            if (stream.IsReading)
                value = int32_value;
            return true;
        }
        public static bool serialize_int(this BaseStream stream, ref uint value, int min, int max) { int v = (int)value; if (!serialize_int(stream, ref v, min, max)) return false; value = (uint)v; return true; }
        public static bool serialize_int(this BaseStream stream, ref short value, int min, int max) { int v = value; if (!serialize_int(stream, ref v, min, max)) return false; value = (short)v; return true; }
        public static bool serialize_int(this BaseStream stream, ref ushort value, int min, int max) { int v = value; if (!serialize_int(stream, ref v, min, max)) return false; value = (ushort)v; return true; }
        public static bool serialize_int(this BaseStream stream, ref sbyte value, int min, int max) { int v = value; if (!serialize_int(stream, ref v, min, max)) return false; value = (sbyte)v; return true; }
        public static bool serialize_int(this BaseStream stream, ref byte value, int min, int max) { int v = value; if (!serialize_int(stream, ref v, min, max)) return false; value = (byte)v; return true; }

        /**
            Serialize a 64 bit integer value (read/write/measure).
            The full 64 bit range is supported, and the minimal number of bits for [min,max] is used on the wire.
            @param stream The stream object. May be a read, write or measure stream.
            @param value The 64 bit integer value to serialize in [min,max].
            @param min The minimum value.
            @param max The maximum value.
         */
        public static bool serialize_int64(this BaseStream stream, ref long value, long min, long max)
        {
            assert(min <= max);
            var int64_value = 0L;
            if (stream.IsWriting)
            {
                assert(value >= min);
                assert(value <= max);
                int64_value = value;
            }
            if (!stream.SerializeInteger64(ref int64_value, min, max))
                return false;
            if (stream.IsReading)
                value = int64_value;
            return true;
        }

        /**
            Serialize a ranged 128 bit integer to the stream (read/write/measure).
            Where the range fits 64 bits or fewer the bytes are identical to serialize_int64 over the same bounds.
            Do not confuse this with serialize_uint128, which is not ranged.
         */
        public static bool serialize_int128(this BaseStream stream, ref Int128 value, Int128 min, Int128 max)
        {
            assert(min <= max);
            var int128_value = Int128.Zero;
            if (stream.IsWriting)
            {
                assert(value >= min);
                assert(value <= max);
                int128_value = value;
            }
            if (!stream.SerializeInteger128(ref int128_value, min, max))
                return false;
            if (stream.IsReading)
                value = int128_value;
            return true;
        }

        #endregion

        #region serialize_bits

        /**
            Serialize bits to the stream (read/write/measure).
            @param stream The stream object. May be a read, write or measure stream.
            @param value The unsigned integer value to serialize. Must be in [0,(1<<bits)-1].
            @param bits The number of bits to serialize in [1,32].
         */
        public static bool serialize_bits(this BaseStream stream, ref uint value, int bits)
        {
            assert(bits > 0);
            assert(bits <= 32);
            assert(!stream.IsWriting || bits == 32 || value <= (1U << bits) - 1);
            var uint32_value = 0U;
            if (stream.IsWriting)
                uint32_value = value;
            if (!stream.SerializeBits(ref uint32_value, bits))
                return false;
            if (stream.IsReading)
                value = uint32_value;
            return true;
        }

        /**
            Serialize up to 64 bits to the stream (read/write/measure).
            Values wider than 32 bits are serialized low dword first, then the high remainder.
            @param bits The number of bits to serialize in [1,64].
         */
        public static bool serialize_bits(this BaseStream stream, ref ulong value, int bits)
        {
            assert(bits > 0);
            assert(bits <= 64);
            assert(!stream.IsWriting || bits == 64 || value <= (1UL << bits) - 1);
            if (bits <= 32)
            {
                var uint32_value = 0U;
                if (stream.IsWriting)
                    uint32_value = (uint)value;
                if (!stream.SerializeBits(ref uint32_value, bits))
                    return false;
                if (stream.IsReading)
                    value = uint32_value;
            }
            else
            {
                uint hi = 0, lo = 0;
                if (stream.IsWriting)
                {
                    lo = (uint)(value & 0xFFFFFFFF);
                    hi = (uint)(value >> 32);
                }
                if (!stream.SerializeBits(ref lo, 32))
                    return false;
                if (!stream.SerializeBits(ref hi, bits - 32))
                    return false;
                if (stream.IsReading)
                    value = ((ulong)hi << 32) | lo;
            }
            return true;
        }
        public static bool serialize_bits(this BaseStream stream, ref byte value, int bits) { uint v = value; if (!serialize_bits(stream, ref v, bits)) return false; value = (byte)v; return true; }
        public static bool serialize_bits(this BaseStream stream, ref ushort value, int bits) { uint v = value; if (!serialize_bits(stream, ref v, bits)) return false; value = (ushort)v; return true; }
        public static bool serialize_bits(this BaseStream stream, ref short value, int bits) { uint v = (ushort)value; if (!serialize_bits(stream, ref v, bits)) return false; value = (short)v; return true; }
        public static bool serialize_bits(this BaseStream stream, ref int value, int bits) { uint v = (uint)value; if (!serialize_bits(stream, ref v, bits)) return false; value = (int)v; return true; }

        /**
            Serialize a boolean value to the stream (read/write/measure).
            @param stream The stream object. May be a read, write or measure stream.
            @param value The boolean value to serialize.
         */
        public static bool serialize_bool(this BaseStream stream, ref bool value)
        {
            var uint32_bool_value = 0U;
            if (stream.IsWriting)
                uint32_bool_value = value ? 1U : 0U;
            if (!serialize_bits(stream, ref uint32_bool_value, 1))
                return false;
            if (stream.IsReading)
                value = uint32_bool_value != 0;
            return true;
        }

        /// Serialize unsigned 8 bit integer (read/write/measure).
        public static bool serialize_uint8(this BaseStream stream, ref byte value) => serialize_bits(stream, ref value, 8);
        /// Serialize unsigned 16 bit integer (read/write/measure).
        public static bool serialize_uint16(this BaseStream stream, ref ushort value) => serialize_bits(stream, ref value, 16);
        /// Serialize unsigned 32 bit integer (read/write/measure).
        public static bool serialize_uint32(this BaseStream stream, ref uint value) => serialize_bits(stream, ref value, 32);
        /// Serialize unsigned 64 bit integer (read/write/measure). Low dword first, then high dword.
        public static bool serialize_uint64(this BaseStream stream, ref ulong value) => serialize_bits(stream, ref value, 64);

        /**
            Serialize an unsigned 128 bit integer (read/write/measure).
            The wire format is 128 bits raw: the low 64 bit half first, then the high half.
         */
        public static bool serialize_uint128(this BaseStream stream, ref UInt128 value)
        {
            ulong low_half = 0, high_half = 0;
            if (stream.IsWriting)
            {
                low_half = (ulong)(value & ulong.MaxValue);
                high_half = (ulong)(value >> 64);
            }
            if (!serialize_bits(stream, ref low_half, 64))
                return false;
            if (!serialize_bits(stream, ref high_half, 64))
                return false;
            if (stream.IsReading)
                value = ((UInt128)high_half << 64) | low_half;
            return true;
        }

        #endregion

        #region serialize_float

        /**
            Serialize floating point value (read/write/measure).
            Bit-cast, 32 bits: NaN and infinities are passed through verbatim. A refused read leaves value exactly as the caller left it.
         */
        public static bool serialize_float(this BaseStream stream, ref float value)
        {
            var int_value = 0U;
            if (stream.IsWriting)
                int_value = BitConverter.SingleToUInt32Bits(value);
            if (!stream.SerializeBits(ref int_value, 32))
                return false;
            if (stream.IsReading)
                value = BitConverter.UInt32BitsToSingle(int_value);
            return true;
        }

        /**
            Serialize double precision floating point value to the stream (read/write/measure).
            Bit-cast, 64 bits: low dword first, then high dword.
         */
        public static bool serialize_double(this BaseStream stream, ref double value)
        {
            var int_value = 0UL;
            if (stream.IsWriting)
                int_value = BitConverter.DoubleToUInt64Bits(value);
            if (!serialize_bits(stream, ref int_value, 64))
                return false;
            if (stream.IsReading)
                value = BitConverter.UInt64BitsToDouble(int_value);
            return true;
        }

        /**
            Derive the compressed float wire constants from a (min,max,res) declaration.
            @param max_integer_value The quantization step count: ceil( ( max - min ) / res ), clamped to [1,4294967040].
            @param bits The wire width: bits_required( 0, max_integer_value ).
            @param delta The range width max - min, computed in float32.
         */
        public static void serialize_compressed_float_params(float min, float max, float res, out uint max_integer_value, out int bits, out float delta)
        {
            assert(min < max && res > 0);
            delta = max - min;
            float values = delta / res;
            // a declaration whose delta or values is not finite in float32 is non-conforming
            assert(delta - delta == 0.0f);
            assert(values - values == 0.0f);
            // clamp so the uint cast below is defined even for pathological delta / res (the !>= form also catches NaN)
            if (!(values >= 1.0f))
                values = 1.0f;
            else if (values > 4294967040.0f)      // largest float below 2^32
                values = 4294967040.0f;
            max_integer_value = (uint)Math.Ceiling((double)values);
            bits = bits_required(0, max_integer_value);
        }

        /**
            Serialize compressed floating point value from precomputed wire constants (read/write/measure).
            On write, the value is clamped into the declared range and quantized. On read, an integer above max_integer_value smuggled into the bit headroom is rejected.
            IMPORTANT: the quantization arithmetic is pinned to float32 with TWO roundings each way (the product rounds before 0.5 / min is added).
            Every intermediate is stored in a float local; do not fold these into one expression or use FusedMultiplyAdd.
         */
        public static bool serialize_compressed_float_precomputed(this BaseStream stream, ref float value, uint max_integer_value, int bits, float delta, float min)
        {
            assert(max_integer_value >= 1);
            assert(bits == bits_required(0, max_integer_value));
            assert(delta > 0.0f);
            assert(delta - delta == 0.0f);

            var integerValue = 0U;

            if (stream.IsWriting)
            {
                // writing a non-finite value is non-conforming; in release the clamp below keeps the uint cast defined
                assert(value - value == 0.0f);
                // clamp with the !>= / !<= form so a NaN value is forced into range
                float normalizedValue = (value - min) / delta;
                if (!(normalizedValue >= 0.0f))
                    normalizedValue = 0.0f;
                else if (!(normalizedValue <= 1.0f))
                    normalizedValue = 1.0f;
                float scaled = normalizedValue * (float)max_integer_value;
                scaled = ForceRound(scaled);
                integerValue = (uint)Math.Floor((double)(float)(scaled + 0.5f));
                // the integer clamp is normative: near 2^24 the rounded sum can exceed max_integer_value itself
                if (integerValue > max_integer_value)
                    integerValue = max_integer_value;
            }

            if (!stream.SerializeBits(ref integerValue, bits))
                return false;

            if (stream.IsReading)
            {
                if (integerValue > max_integer_value)
                    return serialize_fail(stream);
                float normalizedValue = (float)integerValue / (float)max_integer_value;
                float scaledValue = normalizedValue * delta;
                scaledValue = ForceRound(scaledValue);
                value = scaledValue + min;
            }

            return true;
        }

        // keeps the JIT from fusing a multiply and add across the float local (the C# equivalent of SERIALIZE_FLOAT_FORCE_ROUND)
        [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.NoInlining)]
        static float ForceRound(float value) => value;

        /**
            Serialize compressed floating point value (read/write/measure).
            Derives the wire constants with serialize_compressed_float_params and forwards to serialize_compressed_float_precomputed, so the two entry points are wire identical by construction.
         */
        public static bool serialize_compressed_float(this BaseStream stream, ref float value, float min, float max, float res)
        {
            serialize_compressed_float_params(min, max, res, out var max_integer_value, out var bits, out var delta);
            return serialize_compressed_float_precomputed(stream, ref value, max_integer_value, bits, delta, min);
        }

        #endregion

        #region serialize_bytes / string / wstring

        /**
            Serialize an array of bytes to the stream (read/write/measure).
            Aligns to a byte boundary first.
            @param stream The stream object. May be a read, write or measure stream.
            @param data The data to be serialized. On read it must be at least bytes long.
            @param bytes The number of bytes to serialize.
         */
        public static bool serialize_bytes(this BaseStream stream, byte[] data, int bytes) =>
            stream.SerializeBytes(data, bytes);

        /**
            UTF-8 well-formedness. Rejects overlong encodings, surrogate code points, values above U+10FFFF, truncated sequences and stray continuation bytes.
            NUL bytes are VALID UTF-8: the interior-NUL refusal is a separate rule.
         */
        public static bool serialize_string_is_valid_utf8(byte[] data, int length)
        {
            var i = 0;
            while (i < length)
            {
                uint lead = data[i];
                if (lead < 0x80)
                    i += 1;
                else if ((lead & 0xE0) == 0xC0)
                {
                    if (lead < 0xC2) return false;                                                          // overlong
                    if (i + 1 >= length) return false;
                    if ((data[i + 1] & 0xC0) != 0x80) return false;
                    i += 2;
                }
                else if ((lead & 0xF0) == 0xE0)
                {
                    if (i + 2 >= length) return false;
                    uint byte1 = data[i + 1], byte2 = data[i + 2];
                    if ((byte1 & 0xC0) != 0x80 || (byte2 & 0xC0) != 0x80) return false;
                    if (lead == 0xE0 && byte1 < 0xA0) return false;                                       // overlong
                    if (lead == 0xED && byte1 >= 0xA0) return false;                                      // surrogate code point
                    i += 3;
                }
                else if ((lead & 0xF8) == 0xF0)
                {
                    if (lead > 0xF4) return false;                                                          // above U+10FFFF
                    if (i + 3 >= length) return false;
                    uint byte1 = data[i + 1], byte2 = data[i + 2], byte3 = data[i + 3];
                    if ((byte1 & 0xC0) != 0x80 || (byte2 & 0xC0) != 0x80 || (byte3 & 0xC0) != 0x80) return false;
                    if (lead == 0xF0 && byte1 < 0x90) return false;                                       // overlong
                    if (lead == 0xF4 && byte1 >= 0x90) return false;                                      // above U+10FFFF
                    i += 4;
                }
                else
                    return false;                                                                           // continuation or invalid lead byte
            }
            return true;
        }

        static readonly UTF8Encoding StrictUtf8 = new UTF8Encoding(false, true);

        /**
            Serialize a string to the stream (read/write/measure).
            Wire format: serialize_int( length, 0, buffer_size - 1 ) then serialize_bytes of the UTF-8 bytes (no terminator).
            On write the string is truncated at its first NUL (the C++ writer derives the length with strlen).
            On read, malformed payloads are refused: invalid UTF-8 fails the read, and so does an interior NUL byte among the transmitted bytes.
            @param stream The stream object. May be a read, write or measure stream.
            @param value The string to serialize write/measure. Filled on read.
            @param buffer_size The size of the C++ string buffer. String bytes plus terminating null must fit into this buffer.
         */
        public static bool serialize_string(this BaseStream stream, ref string value, int buffer_size)
        {
            assert(buffer_size > 0);
            var length = 0;
            byte[] stringBytes = null;
            if (stream.IsWriting)
            {
                var s = value ?? string.Empty;
                var nul = s.IndexOf('\0');
                if (nul >= 0)
                    s = s.Substring(0, nul);
                stringBytes = Encoding.UTF8.GetBytes(s);
                length = stringBytes.Length;
                assert(length < buffer_size);
            }
            if (!serialize_int(stream, ref length, 0, buffer_size - 1))
                return false;
            if (stream.IsReading)
                stringBytes = new byte[length];
            if (!serialize_bytes(stream, stringBytes, length))
                return false;
            if (stream.IsReading)
            {
                for (var i = 0; i < length; i++)
                    if (stringBytes[i] == 0)
                        return serialize_fail(stream);      // interior NUL: the two-lengths smuggling primitive
                if (!serialize_string_is_valid_utf8(stringBytes, length))
                    return serialize_fail(stream);
                value = StrictUtf8.GetString(stringBytes, 0, length);
            }
            return true;
        }

        /**
            Serialize a wide string to the stream (read/write/measure).
            Wire format: serialize_int( units, 0, buffer_size - 1 ) then 32 bits per group, each group one UTF-16 code unit.
            C# strings are UTF-16, so units are written as they are. On write the string is truncated at its first NUL.
            On read, malformed payloads are refused: a group above 0xFFFF, an unpaired surrogate, or an interior NUL group fails the read.
         */
        public static bool serialize_wstring(this BaseStream stream, ref string value, int buffer_size)
        {
            assert(buffer_size > 0);
            var length = 0;
            string s = null;
            if (stream.IsWriting)
            {
                s = value ?? string.Empty;
                var nul = s.IndexOf('\0');
                if (nul >= 0)
                    s = s.Substring(0, nul);
                assert(serialize_wstring_is_valid_utf16(s));
                length = s.Length;
                assert(length < buffer_size);
            }
            if (!serialize_int(stream, ref length, 0, buffer_size - 1))
                return false;
            if (stream.IsWriting)
            {
                for (var i = 0; i < length; i++)
                {
                    uint unit = s[i];
                    if (!serialize_bits(stream, ref unit, 32))
                        return false;
                }
            }
            else
            {
                var chars = new char[length];
                var have_pending = false;
                for (var i = 0; i < length; i++)
                {
                    var character = 0U;
                    if (!serialize_bits(stream, ref character, 32))
                        return false;
                    if (character > 0xFFFF)
                        return serialize_fail(stream);      // not a UTF-16 code unit
                    if (character == 0)
                        return serialize_fail(stream);      // interior NUL
                    if (have_pending)
                    {
                        if (character < 0xDC00 || character > 0xDFFF)
                            return serialize_fail(stream);  // high surrogate without its low
                        have_pending = false;
                    }
                    else if (character >= 0xDC00 && character <= 0xDFFF)
                        return serialize_fail(stream);      // low surrogate with no high before it
                    else if (character >= 0xD800 && character <= 0xDBFF)
                        have_pending = true;
                    chars[i] = (char)character;
                }
                if (have_pending)
                    return serialize_fail(stream);          // the final group is a dangling high surrogate
                value = new string(chars);
            }
            return true;
        }

        /// Is the string well-formed UTF-16 (no unpaired surrogates)?
        public static bool serialize_wstring_is_valid_utf16(string s)
        {
            for (var i = 0; i < s.Length; i++)
            {
                var c = s[i];
                if (char.IsHighSurrogate(c))
                {
                    if (i + 1 >= s.Length || !char.IsLowSurrogate(s[i + 1]))
                        return false;
                    i++;
                }
                else if (char.IsLowSurrogate(c))
                    return false;
            }
            return true;
        }

        /**
            Serialize an alignment to the stream (read/write/measure).
            @param stream The stream object. May be a read, write or measure stream.
         */
        public static bool serialize_align(this BaseStream stream) =>
            stream.SerializeAlign();

        #endregion

        #region serialize_object

        public interface ICanSerialize
        {
            bool Serialize(BaseStream stream);
        }

        /**
            Serialize an object to the stream (read/write/measure).
            @param stream The stream object. May be a read, write or measure stream.
            @param obj The object to serialize. Must have a serialize method on it.
         */
        public static bool serialize_object(this BaseStream stream, ICanSerialize obj) =>
            obj.Serialize(stream);
        public static bool serialize_object(this BaseStream stream, ref ICanSerialize obj) =>
            obj.Serialize(stream);

        #endregion

        #region serialize_int_relative

        /**
            The int_relative domain: 0 to 2^31 - 1 inclusive. Both previous and current lie in it.
         */
        public const long serialize_int_relative_max = 2147483647;

        /// Is a value inside the int_relative domain?
        public static bool value_in_int_relative_domain(long value) =>
            value >= 0 && value <= serialize_int_relative_max;

        /**
            Accept a reconstructed int_relative value, or refuse the read.
            current is written only once the reconstruction is in the domain and strictly greater than previous.
         */
        static bool serialize_int_relative_accept(BaseStream stream, long previous, ref int current, long reconstructed)
        {
            if (reconstructed < 0 || reconstructed > serialize_int_relative_max || reconstructed <= previous)
                return serialize_fail(stream);
            current = (int)reconstructed;
            return true;
        }

        /**
            Serialize an integer value relative to another (read/write/measure).
            The encoding is a ladder of one-bit flags: a difference of 1 costs a single bit, then five bounded tiers of 3, 5, 9, 13 and 17 payload bits, then an absolute tier that transmits current itself as 32 raw bits.
            The sequence is strictly increasing in [0,2^31-1] and no wrap semantics exist.
            On read every tier's reconstruction is checked against the domain and against previous; a refused read writes nothing to current and fails the stream.
            @param stream The stream object. May be a read, write or measure stream.
            @param previous The previous integer value, in [0,2^31-1].
            @param current The current integer value, in [0,2^31-1] and strictly greater than previous.
         */
        public static bool serialize_int_relative(this BaseStream stream, int previous, ref int current)
        {
            // previous is the caller's own state and never arrives off the wire
            assert(previous >= 0);

            var difference = 0U;
            if (stream.IsWriting)
            {
                assert(previous < current);
                difference = (uint)current - (uint)previous;
            }

            var oneBit = false;
            if (stream.IsWriting)
                oneBit = difference == 1;
            if (!serialize_bool(stream, ref oneBit))
                return false;
            if (oneBit)
            {
                if (stream.IsReading)
                    return serialize_int_relative_accept(stream, previous, ref current, (long)previous + 1);
                return true;
            }

            var twoBits = false;
            if (stream.IsWriting)
                twoBits = difference <= 6;
            if (!serialize_bool(stream, ref twoBits))
                return false;
            if (twoBits)
            {
                if (!serialize_int(stream, ref difference, 2, 6))
                    return false;
                if (stream.IsReading)
                    return serialize_int_relative_accept(stream, previous, ref current, (long)previous + difference);
                return true;
            }

            var fourBits = false;
            if (stream.IsWriting)
                fourBits = difference <= 23;
            if (!serialize_bool(stream, ref fourBits))
                return false;
            if (fourBits)
            {
                if (!serialize_int(stream, ref difference, 7, 23))
                    return false;
                if (stream.IsReading)
                    return serialize_int_relative_accept(stream, previous, ref current, (long)previous + difference);
                return true;
            }

            var eightBits = false;
            if (stream.IsWriting)
                eightBits = difference <= 280;
            if (!serialize_bool(stream, ref eightBits))
                return false;
            if (eightBits)
            {
                if (!serialize_int(stream, ref difference, 24, 280))
                    return false;
                if (stream.IsReading)
                    return serialize_int_relative_accept(stream, previous, ref current, (long)previous + difference);
                return true;
            }

            var twelveBits = false;
            if (stream.IsWriting)
                twelveBits = difference <= 4377;
            if (!serialize_bool(stream, ref twelveBits))
                return false;
            if (twelveBits)
            {
                if (!serialize_int(stream, ref difference, 281, 4377))
                    return false;
                if (stream.IsReading)
                    return serialize_int_relative_accept(stream, previous, ref current, (long)previous + difference);
                return true;
            }

            var sixteenBits = false;
            if (stream.IsWriting)
                sixteenBits = difference <= 69914;
            if (!serialize_bool(stream, ref sixteenBits))
                return false;
            if (sixteenBits)
            {
                if (!serialize_int(stream, ref difference, 4378, 69914))
                    return false;
                if (stream.IsReading)
                    return serialize_int_relative_accept(stream, previous, ref current, (long)previous + difference);
                return true;
            }

            // the absolute tier transmits current, not the difference, as 32 raw bits. the group is
            // UNSIGNED, so a value with the top bit set is outside the domain and is refused
            var value = 0U;
            if (stream.IsWriting)
                value = (uint)current;
            if (!serialize_bits(stream, ref value, 32))
                return false;
            if (stream.IsReading)
                return serialize_int_relative_accept(stream, previous, ref current, value);
            return true;
        }

        #endregion

        #region serialize_fixed

        /**
            Serialize a fixed point value with storage of 64 bits or fewer (read/write/measure).
            The Q format and the bounds are constants of the call site: integerBits plus fractionBits must equal the number of bits in the storage type,
            with the sign bit counting towards integerBits for signed storage. The bounds are whole units.
            The value is serialized as an offset from min in the minimal number of bits for the range, so the wire format is byte identical to serialize_int64 of the raw value over the raw bounds.
            A degenerate range where min == max is legal and costs zero bits.
            @param raw The raw storage value, as a 64 bit two's complement pattern (sign extended for signed storage, zero extended for unsigned storage).
         */
        static bool serialize_fixed_narrow(BaseStream stream, ref ulong raw, int integerBits, int fractionBits, long minUnits, long maxUnits, bool isSigned, int storageBits)
        {
            assert(integerBits >= 1);
            assert(fractionBits >= 0);
            assert(integerBits + fractionBits == storageBits);
            assert(storageBits <= 64);
            assert(minUnits <= maxUnits);

            // the whole unit capacity of the Q format, computed in the unsigned domain
            var min_representable_units = isSigned ? unchecked((long)(0UL - (1UL << (integerBits - 1)))) : 0L;
            var max_representable_units = isSigned
                ? unchecked((long)((1UL << (integerBits - 1)) - 1))
                : (integerBits >= 64 ? long.MaxValue : unchecked((long)((1UL << integerBits) - 1)));
            assert(minUnits >= min_representable_units);
            assert(maxUnits <= max_representable_units);

            // shift the whole unit bounds into raw fixed point units in the unsigned domain
            var raw_min = unchecked((ulong)minUnits << fractionBits);
            var raw_max = unchecked((ulong)maxUnits << fractionBits);
            var raw_range = unchecked(raw_max - raw_min);

            if (minUnits == maxUnits)
            {
                // degenerate range: the value IS the range. still consult the failure state through the stream
                var degenerate = 0;
                if (!stream.SerializeInteger(ref degenerate, 0, 0))
                    return false;
                if (stream.IsWriting)
                    assert(raw == raw_min);
                if (stream.IsReading)
                    raw = raw_min;
                return true;
            }

            var bits = bits_required64(raw_min, raw_max);

            var offset = 0UL;
            if (stream.IsWriting)
            {
                offset = unchecked(raw - raw_min);
                assert(offset <= raw_range);
            }

            if (bits <= 32)
            {
                var unsigned_value = (uint)offset;
                if (!stream.SerializeBits(ref unsigned_value, bits))
                    return false;
                offset = unsigned_value;
            }
            else
            {
                var low_half = (uint)(offset & 0xFFFFFFFF);
                var high_half = (uint)(offset >> 32);
                if (!stream.SerializeBits(ref low_half, 32))
                    return false;
                if (!stream.SerializeBits(ref high_half, bits - 32))
                    return false;
                offset = ((ulong)high_half << 32) | low_half;
            }

            if (stream.IsReading)
            {
                // reject raw values outside [raw_min,raw_max] smuggled into the bit headroom. reject, never clamp
                if (offset > raw_range)
                    return serialize_fail(stream);
                raw = unchecked(raw_min + offset);
            }
            return true;
        }

        public static bool serialize_fixed(this BaseStream stream, ref long value, int integerBits, int fractionBits, long minUnits, long maxUnits)
        { var raw = (ulong)value; if (!serialize_fixed_narrow(stream, ref raw, integerBits, fractionBits, minUnits, maxUnits, true, 64)) return false; value = (long)raw; return true; }
        public static bool serialize_fixed(this BaseStream stream, ref ulong value, int integerBits, int fractionBits, long minUnits, long maxUnits)
        { var raw = value; if (!serialize_fixed_narrow(stream, ref raw, integerBits, fractionBits, minUnits, maxUnits, false, 64)) return false; value = raw; return true; }
        public static bool serialize_fixed(this BaseStream stream, ref int value, int integerBits, int fractionBits, long minUnits, long maxUnits)
        { var raw = unchecked((ulong)(long)value); if (!serialize_fixed_narrow(stream, ref raw, integerBits, fractionBits, minUnits, maxUnits, true, 32)) return false; value = unchecked((int)raw); return true; }
        public static bool serialize_fixed(this BaseStream stream, ref uint value, int integerBits, int fractionBits, long minUnits, long maxUnits)
        { var raw = (ulong)value; if (!serialize_fixed_narrow(stream, ref raw, integerBits, fractionBits, minUnits, maxUnits, false, 32)) return false; value = unchecked((uint)raw); return true; }
        public static bool serialize_fixed(this BaseStream stream, ref short value, int integerBits, int fractionBits, long minUnits, long maxUnits)
        { var raw = unchecked((ulong)(long)value); if (!serialize_fixed_narrow(stream, ref raw, integerBits, fractionBits, minUnits, maxUnits, true, 16)) return false; value = unchecked((short)raw); return true; }
        public static bool serialize_fixed(this BaseStream stream, ref ushort value, int integerBits, int fractionBits, long minUnits, long maxUnits)
        { var raw = (ulong)value; if (!serialize_fixed_narrow(stream, ref raw, integerBits, fractionBits, minUnits, maxUnits, false, 16)) return false; value = unchecked((ushort)raw); return true; }
        public static bool serialize_fixed(this BaseStream stream, ref sbyte value, int integerBits, int fractionBits, long minUnits, long maxUnits)
        { var raw = unchecked((ulong)(long)value); if (!serialize_fixed_narrow(stream, ref raw, integerBits, fractionBits, minUnits, maxUnits, true, 8)) return false; value = unchecked((sbyte)raw); return true; }
        public static bool serialize_fixed(this BaseStream stream, ref byte value, int integerBits, int fractionBits, long minUnits, long maxUnits)
        { var raw = (ulong)value; if (!serialize_fixed_narrow(stream, ref raw, integerBits, fractionBits, minUnits, maxUnits, false, 8)) return false; value = unchecked((byte)raw); return true; }

        /**
            Serialize a fixed point value with 128 bit storage (read/write/measure).
            The offset is written in 32 bit groups, least significant group first.
         */
        static bool serialize_fixed_wide(BaseStream stream, ref UInt128 raw, int integerBits, int fractionBits, long minUnits, long maxUnits, bool isSigned)
        {
            assert(integerBits >= 1);
            assert(fractionBits >= 0);
            assert(integerBits + fractionBits == 128);
            assert(minUnits <= maxUnits);
            if (!isSigned)
                assert(minUnits >= 0);
            if (integerBits < 64)
            {
                var min_representable_units = isSigned ? unchecked((long)(0UL - (1UL << (integerBits - 1)))) : 0L;
                var max_representable_units = isSigned ? unchecked((long)((1UL << (integerBits - 1)) - 1)) : unchecked((long)((1UL << integerBits) - 1));
                assert(minUnits >= min_representable_units);
                assert(maxUnits <= max_representable_units);
            }

            // the storage constructor sign extends the int64 bounds for signed storage
            var raw_min = unchecked((UInt128)(Int128)minUnits << fractionBits);
            var raw_max = unchecked((UInt128)(Int128)maxUnits << fractionBits);
            var raw_range = unchecked(raw_max - raw_min);

            if (minUnits == maxUnits)
            {
                var degenerate = 0;
                if (!stream.SerializeInteger(ref degenerate, 0, 0))
                    return false;
                if (stream.IsWriting)
                    assert(raw == raw_min);
                if (stream.IsReading)
                    raw = raw_min;
                return true;
            }

            // the wire cost: the range in whole units is exact in a uint64, and shifting it left by fractionBits adds exactly fractionBits to its bit length
            var bits = bits_required64((ulong)minUnits, (ulong)maxUnits) + fractionBits;

            var offset = UInt128.Zero;
            if (stream.IsWriting)
            {
                offset = unchecked(raw - raw_min);
                assert(offset <= raw_range);
            }

            uint group0 = 0, group1 = 0, group2 = 0, group3 = 0;
            if (stream.IsWriting)
            {
                group0 = (uint)(ulong)(offset & 0xFFFFFFFF);
                group1 = (uint)(ulong)((offset >> 32) & 0xFFFFFFFF);
                group2 = (uint)(ulong)((offset >> 64) & 0xFFFFFFFF);
                group3 = (uint)(ulong)((offset >> 96) & 0xFFFFFFFF);
            }
            if (bits <= 32)
            {
                if (!stream.SerializeBits(ref group0, bits)) return false;
            }
            else if (bits <= 64)
            {
                if (!stream.SerializeBits(ref group0, 32)) return false;
                if (!stream.SerializeBits(ref group1, bits - 32)) return false;
            }
            else if (bits <= 96)
            {
                if (!stream.SerializeBits(ref group0, 32)) return false;
                if (!stream.SerializeBits(ref group1, 32)) return false;
                if (!stream.SerializeBits(ref group2, bits - 64)) return false;
            }
            else
            {
                if (!stream.SerializeBits(ref group0, 32)) return false;
                if (!stream.SerializeBits(ref group1, 32)) return false;
                if (!stream.SerializeBits(ref group2, 32)) return false;
                if (!stream.SerializeBits(ref group3, bits - 96)) return false;
            }

            if (stream.IsReading)
            {
                offset = ((UInt128)group3 << 96) | ((UInt128)group2 << 64) | ((UInt128)group1 << 32) | group0;
                if (offset > raw_range)
                    return serialize_fail(stream);
                raw = unchecked(raw_min + offset);
            }
            return true;
        }

        public static bool serialize_fixed(this BaseStream stream, ref Int128 value, int integerBits, int fractionBits, long minUnits, long maxUnits)
        { var raw = unchecked((UInt128)value); if (!serialize_fixed_wide(stream, ref raw, integerBits, fractionBits, minUnits, maxUnits, true)) return false; value = unchecked((Int128)raw); return true; }
        public static bool serialize_fixed(this BaseStream stream, ref UInt128 value, int integerBits, int fractionBits, long minUnits, long maxUnits)
        { var raw = value; if (!serialize_fixed_wide(stream, ref raw, integerBits, fractionBits, minUnits, maxUnits, false)) return false; value = raw; return true; }

        #endregion

        #region read_* / write_*

        // read functions corresponding to each serialize_*. useful when you want separate read and write functions.

        public static bool read_bits(this BaseStream stream, ref uint value, int bits) { assert(stream.IsReading); return serialize_bits(stream, ref value, bits); }
        public static bool read_bits(this BaseStream stream, ref ulong value, int bits) { assert(stream.IsReading); return serialize_bits(stream, ref value, bits); }
        public static bool read_int(this BaseStream stream, ref int value, int min, int max) { assert(stream.IsReading); return serialize_int(stream, ref value, min, max); }
        public static bool read_int64(this BaseStream stream, ref long value, long min, long max) { assert(stream.IsReading); return serialize_int64(stream, ref value, min, max); }
        public static bool read_int128(this BaseStream stream, ref Int128 value, Int128 min, Int128 max) { assert(stream.IsReading); return serialize_int128(stream, ref value, min, max); }
        public static bool read_bool(this BaseStream stream, ref bool value) { assert(stream.IsReading); return serialize_bool(stream, ref value); }
        public static bool read_uint8(this BaseStream stream, ref byte value) { assert(stream.IsReading); return serialize_uint8(stream, ref value); }
        public static bool read_uint16(this BaseStream stream, ref ushort value) { assert(stream.IsReading); return serialize_uint16(stream, ref value); }
        public static bool read_uint32(this BaseStream stream, ref uint value) { assert(stream.IsReading); return serialize_uint32(stream, ref value); }
        public static bool read_uint64(this BaseStream stream, ref ulong value) { assert(stream.IsReading); return serialize_uint64(stream, ref value); }
        public static bool read_uint128(this BaseStream stream, ref UInt128 value) { assert(stream.IsReading); return serialize_uint128(stream, ref value); }
        public static bool read_float(this BaseStream stream, ref float value) => serialize_float(stream, ref value);
        public static bool read_double(this BaseStream stream, ref double value) => serialize_double(stream, ref value);
        public static bool read_bytes(this BaseStream stream, byte[] data, int bytes) { assert(stream.IsReading); return serialize_bytes(stream, data, bytes); }
        public static bool read_string(this BaseStream stream, ref string value, int buffer_size) { assert(stream.IsReading); return serialize_string(stream, ref value, buffer_size); }
        public static bool read_wstring(this BaseStream stream, ref string value, int buffer_size) { assert(stream.IsReading); return serialize_wstring(stream, ref value, buffer_size); }
        public static bool read_align(this BaseStream stream) => serialize_align(stream);
        public static bool read_object(this BaseStream stream, ICanSerialize obj) => serialize_object(stream, obj);
        public static bool read_int_relative(this BaseStream stream, int previous, ref int current) => serialize_int_relative(stream, previous, ref current);

        // write functions corresponding to each serialize_*. useful when you want separate read and write functions for some reason.

        public static bool write_bits(this BaseStream stream, uint value, int bits) { assert(stream.IsWriting); return serialize_bits(stream, ref value, bits); }
        public static bool write_bits(this BaseStream stream, ulong value, int bits) { assert(stream.IsWriting); return serialize_bits(stream, ref value, bits); }
        public static bool write_int(this BaseStream stream, int value, int min, int max) { assert(stream.IsWriting); return serialize_int(stream, ref value, min, max); }
        public static bool write_int64(this BaseStream stream, long value, long min, long max) { assert(stream.IsWriting); return serialize_int64(stream, ref value, min, max); }
        public static bool write_int128(this BaseStream stream, Int128 value, Int128 min, Int128 max) { assert(stream.IsWriting); return serialize_int128(stream, ref value, min, max); }
        public static bool write_bool(this BaseStream stream, bool value) { assert(stream.IsWriting); return serialize_bool(stream, ref value); }
        public static bool write_uint8(this BaseStream stream, byte value) { assert(stream.IsWriting); return serialize_uint8(stream, ref value); }
        public static bool write_uint16(this BaseStream stream, ushort value) { assert(stream.IsWriting); return serialize_uint16(stream, ref value); }
        public static bool write_uint32(this BaseStream stream, uint value) { assert(stream.IsWriting); return serialize_uint32(stream, ref value); }
        public static bool write_uint64(this BaseStream stream, ulong value) { assert(stream.IsWriting); return serialize_uint64(stream, ref value); }
        public static bool write_uint128(this BaseStream stream, UInt128 value) { assert(stream.IsWriting); return serialize_uint128(stream, ref value); }
        public static bool write_float(this BaseStream stream, float value) => serialize_float(stream, ref value);
        public static bool write_double(this BaseStream stream, double value) => serialize_double(stream, ref value);
        public static bool write_bytes(this BaseStream stream, byte[] data, int bytes) { assert(stream.IsWriting); return serialize_bytes(stream, data, bytes); }
        public static bool write_string(this BaseStream stream, string value, int buffer_size) { assert(stream.IsWriting); return serialize_string(stream, ref value, buffer_size); }
        public static bool write_wstring(this BaseStream stream, string value, int buffer_size) { assert(stream.IsWriting); return serialize_wstring(stream, ref value, buffer_size); }
        public static bool write_align(this BaseStream stream) => serialize_align(stream);
        public static bool write_object(this BaseStream stream, ICanSerialize obj) => serialize_object(stream, obj);
        public static bool write_int_relative(this BaseStream stream, int previous, int current) => serialize_int_relative(stream, previous, ref current);

        #endregion
    }
}
