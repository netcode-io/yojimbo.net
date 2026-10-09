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

#define YOJIMBO_SERIALIZE_CHECKS
#define YOJIMBO_DEBUG_MEMORY_LEAKS
//#define YOJIMBO_DEBUG_MESSAGE_LEAKS
#define YOJIMBO_DEBUG_MESSAGE_BUDGET
#define YOJIMBO_ENABLE_LOGGING

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
    #region defines

    public class Allocator : IDisposable
    {
        internal static Allocator Default = new Allocator();

        public void Dispose() { }
    }

    public static partial class yojimbo
    {
        public const int MAJOR_VERSION = 1;
        public const int MINOR_VERSION = 0;
        public const int PATCH_VERSION = 0;

        public const int DEFAULT_TIMEOUT = 5;

        public static Allocator DefaultAllocator => Allocator.Default;
    }

    #endregion

    #region config

    /// The library namespace.
    static partial class yojimbo
    {
        public const int MaxClients = 64;                                       ///< The maximum number of clients supported by this library. You can increase this if you want, but this library is designed around patterns that work best for [2,64] player games. If your game has less than 64 clients, reducing this will save memory.
        public const int MaxChannels = 64;                                      ///< The maximum number of message channels supported by this library. If you need less than 64 channels per-packet, reducing this will save memory.
        public const int KeyBytes = 32;                                         ///< Size of encryption key for dedicated client/server in bytes. Must be equal to key size for libsodium encryption primitive. Do not change.
        public const int ConnectTokenBytes = 2048;                              ///< Size of the encrypted connect token data return from the matchmaker. Must equal size of NETCODE_CONNECT_TOKEN_BYTE (2048).
        public const uint SerializeCheckValue = 0x12345678U;                    ///< The value written to the stream for serialize checks. See WriteStream::SerializeCheck and ReadStream::SerializeCheck.
        public const int ConservativeMessageHeaderBits = 32;                    ///< Conservative number of bits per-message header.
        public const int ConservativeFragmentHeaderBits = 64;                   ///< Conservative number of bits per-fragment header.
        public const int ConservativeChannelHeaderBits = 32;                    ///< Conservative number of bits per-channel header.
        public const int ConservativePacketHeaderBits = 16;                     ///< Conservative number of bits per-packet header.
    }

    /// Determines the reliability and ordering guarantees for a channel.
    public enum ChannelType
    {
        CHANNEL_TYPE_RELIABLE_ORDERED,                                          ///< Messages are received reliably and in the same order they were sent. 
        CHANNEL_TYPE_UNRELIABLE_UNORDERED                                       ///< Messages are sent unreliably. Messages may arrive out of order, or not at all.
    }

    /** 
        Configuration properties for a message channel.
     
        Channels let you specify different reliability and ordering guarantees for messages sent across a connection.
     
        They may be configured as one of two types: reliable-ordered or unreliable-unordered.
     
        Reliable ordered channels guarantee that messages (see Message) are received reliably and in the same order they were sent. 
        This channel type is designed for control messages and RPCs sent between the client and server.
    
        Unreliable unordered channels are like UDP. There is no guarantee that messages will arrive, and messages may arrive out of order.
        This channel type is designed for data that is time critical and should not be resent if dropped, like snapshots of world state sent rapidly 
        from server to client, or cosmetic events such as effects and sounds.
        
        Both channel types support blocks of data attached to messages (see BlockMessage), but their treatment of blocks is quite different.
        
        Reliable ordered channels are designed for blocks that must be received reliably and in-order with the rest of the messages sent over the channel. 
        Examples of these sort of blocks include the initial state of a level, or server configuration data sent down to a client on connect. These blocks 
        are sent by splitting them into fragments and resending each fragment until the other side has received the entire block. This allows for sending
        blocks of data larger that maximum packet size quickly and reliably even under packet loss.
        
        Unreliable-unordered channels send blocks as-is without splitting them up into fragments. The idea is that transport level packet fragmentation
        should be used on top of the generated packet to split it up into into smaller packets that can be sent across typical Internet MTU (<1500 bytes). 
        Because of this, you need to make sure that the maximum block size for an unreliable-unordered channel fits within the maximum packet size.
        
        Channels are typically configured as part of a ConnectionConfig, which is included inside the ClientServerConfig that is passed into the Client and Server constructors.
     */
    public class ChannelConfig
    {
        public ChannelType type = ChannelType.CHANNEL_TYPE_RELIABLE_ORDERED;    ///< Channel type: reliable-ordered or unreliable-unordered.
        public bool disableBlocks = false;                                      ///< Disables blocks being sent across this channel.
        public int sentPacketBufferSize = 1024;                                 ///< Number of packet entries in the sent packet sequence buffer. Please consider your packet send rate and make sure you have at least a few seconds worth of entries in this buffer.
        public int messageSendQueueSize = 1024;                                 ///< Number of messages in the send queue for this channel.
        public int messageReceiveQueueSize = 1024;                              ///< Number of messages in the receive queue for this channel.
        public int maxMessagesPerPacket = 256;                                  ///< Maximum number of messages to include in each packet. Will write up to this many messages, provided the messages fit into the channel packet budget and the number of bytes remaining in the packet.
        public int packetBudget = -1;                                           ///< Maximum amount of message data to write to the packet for this channel (bytes). Specifying -1 means the channel can use up to the rest of the bytes remaining in the packet.
        public int maxBlockSize = 256 * 1024;                                   ///< The size of the largest block that can be sent across this channel (bytes).
        public int blockFragmentSize = 1024;                                    ///< Blocks are split up into fragments of this size (bytes). Reliable-ordered channel only.
        public float messageResendTime = 0.1f;                                  ///< Minimum delay between message resends (seconds). Avoids sending the same message too frequently. Reliable-ordered channel only.
        public float blockFragmentResendTime = 0.25f;                           ///< Minimum delay between block fragment resends (seconds). Avoids sending the same fragment too frequently. Reliable-ordered channel only.

        public int MaxFragmentsPerBlock =>
            maxBlockSize / blockFragmentSize;
    }

    /** 
        Configures connection properties and the set of channels for sending and receiving messages.
        Specifies the maximum packet size to generate, and the number of message channels, and the per-channel configuration data. See ChannelConfig for details.
        Typically configured as part of a ClientServerConfig which is passed into Client and Server constructors.
     */
    public class ConnectionConfig
    {
        public int numChannels = 1;                                             ///< Number of message channels in [1,MaxChannels]. Each message channel must have a corresponding configuration below.
        public int maxPacketSize = 8 * 1024;                                    ///< The maximum size of packets generated to transmit messages between client and server (bytes).
        public ChannelConfig[] channel = BufferEx.NewT<ChannelConfig>(yojimbo.MaxChannels); ///< Per-channel configuration. See ChannelConfig for details.
    }

    /** 
        Configuration shared between client and server.
        Passed to Client and Server constructors to configure their behavior.
        Please make sure that the message configuration is identical between client and server.
     */
    public class ClientServerConfig : ConnectionConfig
    {
        public ulong protocolId = 0;                                            ///< Clients can only connect to servers with the same protocol id. Use this for versioning.
        public int timeout = yojimbo.DEFAULT_TIMEOUT;                           ///< Timeout value in seconds. Set to negative value to disable timeouts (for debugging only).
        public int clientMemory = 0; /* 10 * 1024 * 1024 */                     ///< Memory allocated inside Client for packets, messages and stream allocations (bytes)
        public int serverGlobalMemory = 0; /* 10 * 1024 * 1024 */               ///< Memory allocated inside Server for global connection request and challenge response packets (bytes)
        public int serverPerClientMemory = 0; /* 10 * 1024 * 1024 */            ///< Memory allocated inside Server for packets, messages and stream allocations per-client (bytes)
        public bool networkSimulator = true;                                    ///< If true then a network simulator is created for simulating latency, jitter, packet loss and duplicates.
        public int maxSimulatorPackets = 4 * 1024;                              ///< Maximum number of packets that can be stored in the network simulator. Additional packets are dropped.
        public int fragmentPacketsAbove = 1024;                                 ///< Packets above this size (bytes) are split apart into fragments and reassembled on the other side.
        public int packetFragmentSize = 1024;                                   ///< Size of each packet fragment (bytes).
        public int maxPacketFragments;                                          ///< Maximum number of fragments a packet can be split up into.
        public int packetReassemblyBufferSize = 64;                             ///< Number of packet entries in the fragmentation reassembly buffer.
        public int ackedPacketsBufferSize = 256;                                ///< Number of packet entries in the acked packet buffer. Consider your packet send rate and aim to have at least a few seconds worth of entries.
        public int receivedPacketsBufferSize = 256;                             ///< Number of packet entries in the received packet sequence buffer. Consider your packet send rate and aim to have at least a few seconds worth of entries.

        public ClientServerConfig()
        {
            maxPacketFragments = (int)Math.Ceiling((decimal)(maxPacketSize / packetFragmentSize));
        }
    }

    #endregion

    static partial class yojimbo
    {
        #region init / term

        /**
            Initialize the yojimbo library.
            Call this before calling any yojimbo library functions.
            @returns True if the library was successfully initialized, false otherwise.
         */
        public static bool InitializeYojimbo()
        {
            if (netcode.init() != netcode.OK)
                return false;
            if (reliable.init() != reliable.OK)
                return false;
            return true;
        }

        /**
            Shutdown the yojimbo library.
            Call this after you finish using the library and it will run some checks for you (for example, checking for memory leaks in debug build).
         */
        public static void ShutdownYojimbo()
        {
            reliable.term();
            netcode.term();
        }

        #endregion

        #region utils

        ///**
        //    Template function to get the minimum of two values.
        //    @param a The first value.
        //    @param b The second value.
        //    @returns The minimum of a and b.
        // */
        //public static T min<T>(T a, T b) where T : IComparable =>
        //    (a < b) ? a : b;

        ///**
        //    Template function to get the maximum of two values.
        //    @param a The first value.
        //    @param b The second value.
        //    @returns The maximum of a and b.
        // */
        //public static T max<T>(T a, T b) where T : IComparable =>
        //    (a > b) ? a : b;

        ///**
        //    Template function to clamp a value.
        //    @param value The value to be clamped.
        //    @param a The minimum value.
        //    @param b The minimum value.
        //    @returns The clamped value in [a,b].
        // */
        //public static T clamp<T>(T value, T a, T b) where T : IComparable
        //{
        //    if (value < a)
        //        return a;
        //    else if (value > b)
        //        return b;
        //    else
        //        return value;
        //}

        ///**
        //    Swap two values.
        //    @param a First value.
        //    @param b Second value.
        // */
        //public static void swap<T>(T a, T b)
        //{
        //    T tmp = a;
        //    a = b;
        //    b = tmp;
        //}

        ///**
        //    Get the absolute value.

        //    @param value The input value.

        //    @returns The absolute value.
        // */
        //public static T abs<T>(T value) where T : IComparable =>
        //    (value < 0) ? -value : value;

        /**
            Sleep for approximately this number of seconds.
            @param time number of seconds to sleep for.
         */
        public static void sleep(double time)
        {
            var milliseconds = (int)(time * 1000);
            Thread.Sleep(milliseconds);
        }

        /**
            Get a high precision time in seconds since the application has started.
            Please store time in doubles so you retain sufficient precision as time increases.
            @returns Time value in seconds.
         */
        public static double time() => DateTime.Now.ToOADate();

        public static ulong ctime() => (ulong)(DateTime.UtcNow - new DateTime(1970, 1, 1)).TotalSeconds;

        #endregion

        #region assert / logging

        public const int LOG_LEVEL_NONE = 0;
        public const int LOG_LEVEL_ERROR = 1;
        public const int LOG_LEVEL_INFO = 2;
        public const int LOG_LEVEL_DEBUG = 3;

        static int log_level_ = 0;

        /**
            Set the yojimbo log level.
            Valid log levels are: YOJIMBO_LOG_LEVEL_NONE, YOJIMBO_LOG_LEVEL_ERROR, YOJIMBO_LOG_LEVEL_INFO and YOJIMBO_LOG_LEVEL_DEBUG
            @param level The log level to set. Initially set to YOJIMBO_LOG_LEVEL_NONE.
         */
        public static void log_level(int level)
        {
            log_level_ = level;
            netcode.log_level(level);
            reliable.log_level(level);
        }

        public static Action<string, string, string, int> assert_function = default_assert_handler;

        static void default_assert_handler(string condition, string function, string file, int line)
        {
            Console.Write($"assert failed: ( {condition} ), function {function}, file {file}, line {line}\n");
            Debugger.Break();
            Environment.Exit(1);
        }

        static Action<string> printf_function =
            x => Console.Write(x);

        /**
            Printf function used by yojimbo to emit logs.
            This function internally calls the printf callback set by the user. 
            @see yojimbo_set_printf_function
         */
#if YOJIMBO_ENABLE_LOGGING
        public static void printf(int level, string format)
        {
            if (level > log_level_) return;
            printf_function(format);
        }
#else
        public static void printf(int level, string format) { }
#endif

        /**
            Assert function used by yojimbo.
            This assert function lets the user override the assert presentation.
            @see yojimbo_set_assert_functio
         */
        [DebuggerStepThrough, Conditional("DEBUG")]
        public static void assert(bool condition)
        {
            if (!condition)
            {
                var stackFrame = new StackTrace().GetFrame(1);
                assert_function?.Invoke(null, stackFrame.GetMethod().Name, stackFrame.GetFileName(), stackFrame.GetFileLineNumber());
                Environment.Exit(1);
            }
        }

        /**
            Call this to set the printf function to use for logging.
            @param function The printf callback function.
         */
        public static void set_printf_function(Action<string> function)
        {
            assert(function != null);
            printf_function = function;
            netcode.set_printf_function(function);
            reliable.set_printf_function(function);
        }

        /**
            Call this to set the function to call when an assert triggers.
            @param function The assert callback function.
         */
        public static void set_assert_function(Action<string, string, string, int> function)
        {
            assert_function = function;
            netcode.set_assert_function(function);
            reliable.set_assert_function(function);
        }

        #endregion

        #region utils

        /**
            Generate cryptographically secure random data.
            @param data The buffer to store the random data.
            @param bytes The number of bytes of random data to generate.
         */
        public static void random_bytes(ref ulong data, int bytes) =>
           netcode.random_bytes(ref data, bytes);
        public static void random_bytes(byte[] data, int bytes) =>
            netcode.random_bytes(data, bytes);

        /**
            Generate a random integer between a and b (inclusive).
            IMPORTANT: This is not a cryptographically secure random. It's used only for test functions and in the network simulator.
            @param a The minimum integer value to generate.
            @param b The maximum integer value to generate.
            @returns A pseudo random integer value in [a,b].
         */
        public static int random_int(int a, int b)
        {
            assert(a < b);
            var result = a + BufferEx.Rand() % (b - a + 1);
            assert(result >= a);
            assert(result <= b);
            return result;
        }

        /** 
            Generate a random float between a and b.
            IMPORTANT: This is not a cryptographically secure random. It's used only for test functions and in the network simulator.
            @param a The minimum integer value to generate.
            @param b The maximum integer value to generate.
            @returns A pseudo random float value in [a,b].
         */
        public static float random_float(float a, float b)
        {
            assert(a < b);
            var random = BufferEx.Rand() / (float)BufferEx.RAND_MAX;
            var diff = b - a;
            var r = random * diff;
            return a + r;
        }

        ///**
        //    Calculates the population count of an unsigned 32 bit integer at compile time.
        //    Population count is the number of bits in the integer that set to 1.
        //    See "Hacker's Delight" and http://www.hackersdelight.org/hdcodetxt/popArrayHS.c.txt
        //    @see yojimbo::Log2
        //    @see yojimbo::BitsRequired
        // */
        //template<uint x> struct PopCount
        //{
        //    enum {
        //        a = x - ((x >> 1) & 0x55555555),
        //        b = (((a >> 2) & 0x33333333) + (a & 0x33333333)),
        //        c = (((b >> 4) + b) & 0x0f0f0f0f),
        //        d = c + (c >> 8),
        //        e = d + (d >> 16),

        //        result = e & 0x0000003f
        //    };
        //};

        ///**
        //    Calculates the log 2 of an unsigned 32 bit integer at compile time.
        //    @see yojimbo::Log2
        //    @see yojimbo::BitsRequired
        // */

        //template<uint x> struct Log2
        //{
        //    enum {
        //        a = x | (x >> 1),
        //        b = a | (a >> 2),
        //        c = b | (b >> 4),
        //        d = c | (c >> 8),
        //        e = d | (d >> 16),
        //        f = e >> 1,

        //        result = PopCount < f >::result
        //    };
        //};

        ///**
        //    Calculates the number of bits required to serialize an integer value in [min,max] at compile time.
        //    @see Log2
        //    @see PopCount
        // */

        //template<int64_t min, int64_t max> struct BitsRequired
        //{
        //    static const uint result = (min == max) ? 0 : (Log2 < uint(max - min) >::result + 1);
        //};

        /**
            Calculates the population count of an unsigned 32 bit integer.
            The population count is the number of bits in the integer set to 1.
            @param x The input integer value.
            @returns The number of bits set to 1 in the input value.
         */
        public static uint popcount(uint x)
        {
            var result = x - ((x >> 1) & 0x5555555555555555UL);
            result = (result & 0x3333333333333333UL) + ((result >> 2) & 0x3333333333333333UL);
            return (byte)(unchecked(((result + (result >> 4)) & 0xF0F0F0F0F0F0F0FUL) * 0x101010101010101UL) >> 56);
        }

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
            @param min The minimum value.
            @param max The maximum value.
            @returns The number of bits required to serialize the integer.
         */
        public static int bits_required(uint min, uint max) =>
            (min == max) ? 0 : (int)log2(max - min) + 1;

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
            Template to convert an integer value from local byte order to network byte order.
            IMPORTANT: Because most machines running yojimbo are little endian, yojimbo defines network byte order to be little endian.
            @param value The input value in local byte order. Supported integer types: uint64_t, uint, uint16_t.
            @returns The input value converted to network byte order. If this processor is little endian the output is the same as the input. If the processor is big endian, the output is the input byte swapped.
            @see yojimbo::bswap
         */
        public static T host_to_network<T>(T value) =>
#if YOJIMBO_BIG_ENDIAN
        bswap(value);
#else
        value;
#endif

        /**
            Template to convert an integer value from network byte order to local byte order.
            IMPORTANT: Because most machines running yojimbo are little endian, yojimbo defines network byte order to be little endian.
            @param value The input value in network byte order. Supported integer types: uint64_t, uint, uint16_t.
            @returns The input value converted to local byte order. If this processor is little endian the output is the same as the input. If the processor is big endian, the output is the input byte swapped.
            @see yojimbo::bswap
         */
        public static T network_to_host<T>(T value) =>
#if YOJIMBO_BIG_ENDIAN
        bswap(value);
#else
        value;
#endif

        /** 
            Compares two 16 bit sequence numbers and returns true if the first one is greater than the second (considering wrapping).
            IMPORTANT: This is not the same as s1 > s2!
            Greater than is defined specially to handle wrapping sequence numbers. 
            If the two sequence numbers are close together, it is as normal, but they are far apart, it is assumed that they have wrapped around.
            Thus, sequence_greater_than( 1, 0 ) returns true, and so does sequence_greater_than( 0, 65535 )!
            @param s1 The first sequence number.
            @param s2 The second sequence number.
            @returns True if the s1 is greater than s2, with sequence number wrapping considered.
         */
        public static bool sequence_greater_than(ushort s1, ushort s2) =>
            ((s1 > s2) && (s1 - s2 <= 32768)) ||
            ((s1 < s2) && (s2 - s1 > 32768));

        /** 
            Compares two 16 bit sequence numbers and returns true if the first one is less than the second (considering wrapping).
            IMPORTANT: This is not the same as s1 < s2!
            Greater than is defined specially to handle wrapping sequence numbers. 
            If the two sequence numbers are close together, it is as normal, but they are far apart, it is assumed that they have wrapped around.
            Thus, sequence_less_than( 0, 1 ) returns true, and so does sequence_greater_than( 65535, 0 )!
            @param s1 The first sequence number.
            @param s2 The second sequence number.
            @returns True if the s1 is less than s2, with sequence number wrapping considered.
         */
        public static bool sequence_less_than(ushort s1, ushort s2) =>
            sequence_greater_than(s2, s1);

        /**
            Convert a signed integer to an unsigned integer with zig-zag encoding.
            0,-1,+1,-2,+2... becomes 0,1,2,3,4 ...
            @param n The input value.
            @returns The input value converted from signed to unsigned with zig-zag encoding.
         */
        public static int signed_to_unsigned(int n) =>
            (n << 1) ^ (n >> 31);

        /**
            Convert an unsigned integer to as signed integer with zig-zag encoding.
            0,1,2,3,4... becomes 0,-1,+1,-2,+2...
            @param n The input value.
            @returns The input value converted from unsigned to signed with zig-zag encoding.
         */
        public static int unsigned_to_signed(uint n) =>
            (int)((n >> 1) ^ (-(int)(n & 1)));

#if YOJIMBO_WITH_MBEDTLS

        /**
            Base 64 encode a string.
            @param input The input string value. Must be null terminated.
            @param output The output base64 encoded string. Will be null terminated.
            @param output_size The size of the output buffer (bytes). Must be large enough to store the base 64 encoded string.
            @returns The number of bytes in the base64 encoded string, including terminating null. -1 if the base64 encode failed because the output buffer was too small.
         */
        public static int base64_encode_string(string input, string output, int output_size) =>
            throw new NotImplementedException();

        /**
            Base 64 decode a string.
            @param input The base64 encoded string.
            @param output The decoded string. Guaranteed to be null terminated, even if the base64 is maliciously encoded.
            @param output_size The size of the output buffer (bytes).
            @returns The number of bytes in the decoded string, including terminating null. -1 if the base64 decode failed.
         */
        public static int base64_decode_string(string input, string output, int output_size) =>
            throw new NotImplementedException();

        /**
            Base 64 encode a block of data.
            @param input The data to encode.
            @param input_length The length of the input data (bytes).
            @param output The output base64 encoded string. Will be null terminated.
            @param output_size The size of the output buffer. Must be large enough to store the base 64 encoded string.
            @returns The number of bytes in the base64 encoded string, including terminating null. -1 if the base64 encode failed because the output buffer was too small.
         */

        public static int base64_encode_data(byte[] input, int input_length, string output, int output_size) =>
            throw new NotImplementedException();

        /**
            Base 64 decode a block of data.
            @param input The base 64 data to decode. Must be a null terminated string.
            @param output The output data. Will *not* be null terminated.
            @param output_size The size of the output buffer.
            @returns The number of bytes of decoded data. -1 if the base64 decode failed.
         */
        public static int base64_decode_data(string input, byte[] output, int output_size) =>
            throw new NotImplementedException();

        /**
            Print bytes with a label. 
            Useful for printing out packets, encryption keys, nonce etc.
            @param label The label to print out before the bytes.
            @param data The data to print out to stdout.
            @param data_bytes The number of bytes of data to print.
         */
        public static void print_bytes(string label, byte[] data, int data_bytes)
        {
            Console.Write($"{label}: ");
            for (var i = 0; i < data_bytes; ++i)
                Console.Write($"0x{(int)data[i]},");
            Console.Write($" ({data_bytes} bytes)\n");
        }

#endif

        #endregion
    }

    #region BitArray

    /**
        A simple bit array class.
        You can create a bit array with a number of bits, set, clear and test if each bit is set.
     */
    public class BitArray
    {
        /**
            The bit array constructor.
            @param allocator The allocator to use.
            @param size The number of bits in the bit array.
            All bits are initially set to zero.
         */
        public BitArray(Allocator allocator, int size)
        {
            yojimbo.assert(size > 0);
            m_allocator = allocator;
            m_size = size;
            m_bytes = 8 * ((size / 64) + ((size % 64) != 0 ? 1 : 0));
            yojimbo.assert(m_bytes > 0);
            m_data = new ulong[m_bytes];
            Clear();
        }

        /**
            The bit array destructor.
         */
        public void Dispose()
        {
            yojimbo.assert(m_data != null);
            yojimbo.assert(m_allocator != null);
            m_data = null;
            m_allocator = null;
        }

        /**
            Clear all bit values to zero.
         */
        public void Clear()
        {
            yojimbo.assert(m_data != null);
            BufferEx.Set(m_data, 0, m_bytes);
        }

        /**
            Set a bit to 1.
            @param index The index of the bit.
         */
        public void SetBit(int index)
        {
            yojimbo.assert(index >= 0);
            yojimbo.assert(index < m_size);
            var data_index = index >> 6;
            var bit_index = index & ((1 << 6) - 1);
            yojimbo.assert(bit_index >= 0);
            yojimbo.assert(bit_index < 64);
            m_data[data_index] |= 1UL << bit_index;
        }

        /**
            Clear a bit to 0.
            @param index The index of the bit.
         */

        public void ClearBit(int index)
        {
            yojimbo.assert(index >= 0);
            yojimbo.assert(index < m_size);
            var data_index = index >> 6;
            var bit_index = index & ((1 << 6) - 1);
            m_data[data_index] &= ~(1UL << bit_index);
        }

        /**
            Get the value of the bit.
            Returns 1 if the bit is set, 0 if the bit is not set.
            @param index The index of the bit.
         */

        public ulong GetBit(int index)
        {
            yojimbo.assert(index >= 0);
            yojimbo.assert(index < m_size);
            var data_index = index >> 6;
            var bit_index = index & ((1 << 6) - 1);
            yojimbo.assert(bit_index >= 0);
            yojimbo.assert(bit_index < 64);
            return (m_data[data_index] >> bit_index) & 1;
        }

        /**
            Gets the size of the bit array, in number of bits.
            @returns The number of bits.
         */
        public int GetSize() =>
            m_size;

        Allocator m_allocator;                      ///< Allocator passed in to the constructor.
        int m_size;                                 ///< The size of the bit array in bits.
        int m_bytes;                                ///< The size of the bit array in bytes.
        ulong[] m_data;                             ///< The data backing the bit array is an array of 64 bit integer values.

        //BitArray( const BitArray & other );
        //BitArray & operator = ( const BitArray & other );
    }

    #endregion

    #region QueueEx<T>

    /**
        A simple templated queue.
        This is a FIFO queue. First entry in, first entry out.
     */
    public class QueueEx<T> : Queue<T>, IDisposable
    {
        static readonly MethodInfo GetElementInfo = typeof(Queue<T>).GetMethod("GetElement", BindingFlags.Instance | BindingFlags.NonPublic);
        public QueueEx(Allocator allocator, int capacity) : base(capacity) { Size = capacity; }
        T[] _elements;

        public T this[int id] => GetElementInfo != null
            ? (T)GetElementInfo.Invoke(this, new object[] { id })
            : (_elements ?? (_elements = ToArray()))[id];

        public bool IsEmpty => Count == 0;
        public bool IsFull => Count == Size;
        public int NumEntries => Count;
        public readonly int Size;

        public void Dispose() { }

        public new T Dequeue()
        {
            _elements = null;
            yojimbo.assert(!IsEmpty);
            return base.Dequeue();
        }

        public new void Enqueue(T item)
        {
            _elements = null;
            yojimbo.assert(!IsFull);
            base.Enqueue(item);
        }
    }

    #endregion

    #region SequenceBuffer<T>

    /**
        Data structure that stores data indexed by sequence number.
        Entries may or may not exist. If they don't exist the sequence value for the entry at that index is set to 0xFFFFFFFF. 
        This provides a constant time lookup for an entry by sequence number. If the entry at sequence modulo buffer size doesn't have the same sequence number, that sequence number is not stored.
        This is incredibly useful and is used as the foundation of the packet level ack system and the reliable message send and receive queues.
        @see Connection
     */
    public class SequenceBuffer<T> where T : class, new()
    {
        /**
            Sequence buffer constructor.
            @param allocator The allocator to use.
            @param size The size of the sequence buffer.
         */
        public SequenceBuffer(Allocator allocator, int size)
        {
            yojimbo.assert(size > 0);
            m_size = size;
            m_sequence = 0;
            m_allocator = allocator;
            m_entry_sequence = new uint[size];
            m_entries = BufferEx.NewT<T>(size);
            Reset();
        }

        /**
            Sequence buffer destructor.
         */
        public void Dispose()
        {
            yojimbo.assert(m_allocator != null);
            m_entries = null;
            m_entry_sequence = null;
            m_allocator = null;
        }

        /**
            Reset the sequence buffer.
            Removes all entries from the sequence buffer and restores it to initial state.
         */
        public void Reset()
        {
            m_sequence = 0;
            BufferEx.Set(m_entry_sequence, 0xFF, sizeof(uint) * m_size);
        }

        /**
            Insert an entry in the sequence buffer.
            IMPORTANT: If another entry exists at the sequence modulo buffer size, it is overwritten.
            @param sequence The sequence number.
            @returns The sequence buffer entry, which you must fill with your data. null if a sequence buffer entry could not be added for your sequence number (if the sequence number is too old for example).
         */
        public T Insert(ushort sequence)
        {
            if (yojimbo.sequence_greater_than((ushort)(sequence + 1), m_sequence))
            {
                RemoveEntries(m_sequence, sequence);
                m_sequence = (ushort)(sequence + 1);
            }
            else if (yojimbo.sequence_less_than(sequence, (ushort)(m_sequence - m_size)))
                return null;
            var index = sequence % m_size;
            m_entry_sequence[index] = sequence;
            return m_entries[index];
        }

        /**
            Remove an entry from the sequence buffer.
            @param sequence The sequence number of the entry to remove.
         */
        public void Remove(ushort sequence) =>
            m_entry_sequence[sequence % m_size] = 0xFFFFFFFF;

        /**
            Is the entry corresponding to the sequence number available? eg. Currently unoccupied.
            This works because older entries are automatically set back to unoccupied state as the sequence buffer advances forward.
            @param sequence The sequence number.
            @returns True if the sequence buffer entry is available, false if it is already occupied.
         */

        public bool Available(ushort sequence) =>
            m_entry_sequence[sequence % m_size] == 0xFFFFFFFF;

        /**
            Does an entry exist for a sequence number?
            @param sequence The sequence number.
            @returns True if an entry exists for this sequence number.
         */
        public bool Exists(ushort sequence) =>
            m_entry_sequence[sequence % m_size] == sequence;

        /**
            Get the entry corresponding to a sequence number.
            @param sequence The sequence number.
            @returns The entry if it exists. null if no entry is in the buffer for this sequence number.
         */
        public T Find(ushort sequence)
        {
            var index = sequence % m_size;
            return (m_entry_sequence[index] == sequence) ?
                m_entries[index] :
                null;
        }

        /**
            Get the entry at the specified index.
            Use this to iterate across entries in the sequence buffer.
            @param index The entry index in [0,GetSize()-1].
            @returns The entry if it exists. null if no entry is in the buffer at the specified index.
         */
        public T GetAtIndex(int index)
        {
            yojimbo.assert(index >= 0);
            yojimbo.assert(index < m_size);
            return m_entry_sequence[index] != 0xFFFFFFFF ? m_entries[index] : null;
        }

        /**
            Get the most recent sequence number added to the buffer.
            This sequence number can wrap around, so if you are at 65535 and add an entry for sequence 0, then 0 becomes the new "most recent" sequence number.
            @returns The most recent sequence number.
            @see yojimbo::sequence_greater_than
            @see yojimbo::sequence_less_than
         */
        public ushort GetSequence() =>
            m_sequence;

        /**
            Get the entry index for a sequence number.
            This is simply the sequence number modulo the sequence buffer size.
            @param sequence The sequence number.
            @returns The sequence buffer index corresponding of the sequence number.
         */

        public int GetIndex(ushort sequence) =>
            sequence % m_size;

        /** 
            Get the size of the sequence buffer.
            @returns The size of the sequence buffer (number of entries).
         */
        public int GetSize() =>
            m_size;

        /** 
            Helper function to remove entries.
            This is used to remove old entries as we advance the sequence buffer forward. 
            Otherwise, if when entries are added with holes (eg. receive buffer for packets or messages, where not all sequence numbers are added to the buffer because we have high packet loss), 
            and we are extremely unlucky, we can have old sequence buffer entries from the previous sequence # wrap around still in the buffer, which corrupts our internal connection state.
            This actually happened in the soak test at high packet loss levels (>90%). It took me days to track it down :)
         */
        protected void RemoveEntries(int start_sequence, int finish_sequence)
        {
            if (finish_sequence < start_sequence)
                finish_sequence += 65535;
            yojimbo.assert(finish_sequence >= start_sequence);
            if (finish_sequence - start_sequence < m_size)
                for (int sequence = start_sequence; sequence <= finish_sequence; ++sequence)
                    m_entry_sequence[sequence % m_size] = 0xFFFFFFFF;
            else
                for (int i = 0; i < m_size; ++i)
                    m_entry_sequence[i] = 0xFFFFFFFF;
        }

        Allocator m_allocator;                      ///< The allocator passed in to the constructor.
        int m_size;                                 ///< The size of the sequence buffer.
        ushort m_sequence;                          ///< The most recent sequence number added to the buffer.
        uint[] m_entry_sequence;                    ///< Array of sequence numbers corresponding to each sequence buffer entry for fast lookup. Set to 0xFFFFFFFF if no entry exists at that index.
        T[] m_entries;                              ///< The sequence buffer entries. This is where the data is stored per-entry. Separate from the sequence numbers for fast lookup (hot/cold split) when the data per-sequence number is relatively large.

        //SequenceBuffer( SequenceBuffer<T>  other );
        //SequenceBuffer<T> & operator = ( const SequenceBuffer<T> & other );
    }

    #endregion

    #region BitWriter

    /**
        Bitpacks unsigned integer values to a buffer.
        Integer bit values are written to a 64 bit scratch value from right to left.
        Once the low 32 bits of the scratch is filled with bits it is flushed to memory as a dword and the scratch value is shifted right by 32.
        The bit stream is written to memory in little endian order, which is considered network byte order for this library.
        @see BitReader
     */
    public class BitWriter
    {
        /**
            Bit writer constructor.
            Creates a bit writer object to write to the specified buffer. 
            @param data The pointer to the buffer to fill with bitpacked data.
            @param bytes The size of the buffer in bytes. Must be a multiple of 4, because the bitpacker reads and writes memory as dwords, not bytes.
         */
        public BitWriter(byte[] data, int bytes)
        {
            m_data = data;
            m_numWords = bytes / 4;
            yojimbo.assert(data != null);
            yojimbo.assert((bytes % 4) == 0);
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
                write32(m_data, m_wordIndex, yojimbo.host_to_network((uint)(m_scratch & 0xFFFFFFFF)));
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
                var zero = 0U;
                WriteBits(zero, 8 - remainderBits);
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
                BufferEx.Copy(m_data, m_wordIndex * sizeof(uint), data, headBytes, numWords * 4);
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
                write32(m_data, m_wordIndex, yojimbo.host_to_network((uint)(m_scratch & 0xFFFFFFFF)));
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

        byte[] m_data;                              ///< The buffer we are writing to, as a uint * because we're writing dwords at a time.
        ulong m_scratch;                            ///< The scratch value where we write bits to (right to left). 64 bit for overflow. Once # of bits in scratch is >= 32, the low 32 bits are flushed to memory.
        int m_numBits;                              ///< The number of bits in the buffer. This is equivalent to the size of the buffer in bytes multiplied by 8. Note that the buffer size must always be a multiple of 4.
        int m_numWords;                             ///< The number of words in the buffer. This is equivalent to the size of the buffer in bytes divided by 4. Note that the buffer size must always be a multiple of 4.
        int m_bitsWritten;                          ///< The number of bits written so far.
        int m_wordIndex;                            ///< The current word index. The next word flushed to memory will be at this index in m_data.
        int m_scratchBits;                          ///< The number of bits in scratch. When this is >= 32, the low 32 bits of scratch is flushed to memory as a dword and scratch is shifted right by 32.
    }

    #endregion

    #region BitReader

    /**
        Reads bit packed integer values from a buffer.
        Relies on the user reconstructing the exact same set of bit reads as bit writes when the buffer was written. This is an unattributed bitpacked binary stream!
        Implementation: 32 bit dwords are read in from memory to the high bits of a scratch value as required. The user reads off bit values from the scratch value from the right, after which the scratch value is shifted by the same number of bits.
     */
    public class BitReader
    {
        /**
            Bit reader constructor.
            Non-multiples of four buffer sizes are supported, as this naturally tends to occur when packets are read from the network.
            However, actual buffer allocated for the packet data must round up at least to the next 4 bytes in memory, because the bit reader reads dwords from memory not bytes.
            @param data Pointer to the bitpacked data to read.
            @param bytes The number of bytes of bitpacked data to read.
            @see BitWriter
         */
        public BitReader(byte[] data, int bytes)
        {
            m_data = data;
            m_numBytes = bytes;
#if DEBUG
            m_numWords = (bytes + 3) / 4;
#endif
            yojimbo.assert(data != null);
            m_numBits = m_numBytes * 8;
            m_bitsRead = 0;
            m_scratch = 0;
            m_scratchBits = 0;
            m_wordIndex = 0;
        }

        static uint read32(byte[] b, int p)
        {
            p *= sizeof(uint);
            var r = b.Length - p - 4;
            var value = (uint)b[p];
            if (r > -3) value |= (uint)(b[p + 1] << 8);
            if (r > -2) value |= (uint)(b[p + 2] << 0x10);
            if (r > -1) value |= (uint)(b[p + 3] << 0x18);
            return value;
        }

        /**
            Would the bit reader would read past the end of the buffer if it read this many bits?
            @param bits The number of bits that would be read.
            @returns True if reading the number of bits would read past the end of the buffer.
         */
        public bool WouldReadPastEnd(int bits) =>
            m_bitsRead + bits > m_numBits;

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
#if DEBUG
                yojimbo.assert(m_wordIndex < m_numWords);
#endif
                m_scratch |= (ulong)(yojimbo.network_to_host(read32(m_data, m_wordIndex))) << m_scratchBits;
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
            This will typically abort packet read. Just another safety measure...
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
                BufferEx.Copy(data, headBytes, m_data, m_wordIndex * sizeof(uint), numWords * 4);
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

        byte[] m_data;                              ///< The bitpacked data we're reading as a dword array.
        ulong m_scratch;                            ///< The scratch value. New data is read in 32 bits at a top to the left of this buffer, and data is read off to the right.
        int m_numBits;                              ///< Number of bits to read in the buffer. Of course, we can't *really* know this so it's actually m_numBytes * 8.
        int m_numBytes;                             ///< Number of bytes to read in the buffer. We know this, and this is the non-rounded up version.
#if DEBUG
        int m_numWords;                             ///< Number of words to read in the buffer. This is rounded up to the next word if necessary.
#endif
        int m_bitsRead;                             ///< Number of bits read from the buffer so far.
        int m_scratchBits;                          ///< Number of bits currently in the scratch value. If the user wants to read more bits than this, we have to go fetch another dword from memory.
        int m_wordIndex;                            ///< Index of the next word to read from memory.
    }

    #endregion

    #region BaseStream

    /** 
        Functionality common to all stream classes.
     */
    public abstract class BaseStream
    {
        /**
            Base stream constructor.
            @param allocator The allocator to use for stream allocations. This lets you dynamically allocate memory as you read and write packets.
         */
        public BaseStream(Allocator allocator)
        {
            m_allocator = allocator;
            m_context = null;
        }

        public abstract bool IsWriting { get; }
        public abstract bool IsReading { get; }

        public abstract bool SerializeInteger(ref int value, int min, int max);
        public abstract bool SerializeBits(ref uint value, int bits);
        public abstract bool SerializeBytes(byte[] data, int bytes);
        public abstract bool SerializeAlign();
        public abstract int AlignBits { get; }
        public abstract bool SerializeCheck();
        public abstract int BytesProcessed { get; }
        public abstract int BitsProcessed { get; }

        /**
           Gets or sets a context on the stream.
           Contexts are used by the library supply data that is needed to read and write packets.
           Specifically, this context is used by the connection to supply data needed to read and write connection packets.
           If you are using the yojimbo client/server or connection classes you should NOT set this manually. It's already taken!
           However, if you are using only the low-level parts of yojimbo, feel free to take this over and use it for whatever you want.
           @see ConnectionContext
           @see ConnectionPacket
        */
        public object Context
        {
            get => m_context;
            set => m_context = value;
        }

        /**
            Get the allocator set on the stream.
            You can use this allocator to dynamically allocate memory while reading and writing packets.
            @returns The stream allocator.
         */
        public Allocator Allocator =>
            m_allocator;

        Allocator m_allocator;                      ///< The allocator passed into the constructor.
        object m_context;                           ///< The context pointer set on the stream. May be null.
    }

    #endregion

    #region WriteStream

    /**
        Stream class for writing bitpacked data.
        This class is a wrapper around the bit writer class. Its purpose is to provide unified interface for reading and writing.
        You can determine if you are writing to a stream by calling Stream::IsWriting inside your templated serialize method.
        This is evaluated at compile time, letting the compiler generate optimized serialize functions without the hassle of maintaining separate read and write functions.
        IMPORTANT: Generally, you don't call methods on this class directly. Use the serialize_* macros instead. See test/shared.h for some examples.
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
            @param allocator The allocator to use for stream allocations. This lets you dynamically allocate memory as you read and write packets.
         */
        public WriteStream(Allocator allocator, byte[] buffer, int bytes) : base(allocator)
        {
            m_writer = new BitWriter(buffer, bytes);
        }

        /**
            Serialize an integer (write).
            @param value The integer value in [min,max].
            @param min The minimum value.
            @param max The maximum value.
            @returns Always returns true. All checking is performed by debug asserts only on write.
         */
        public override bool SerializeInteger(ref int value, int min, int max)
        {
            yojimbo.assert(min < max);
            yojimbo.assert(value >= min);
            yojimbo.assert(value <= max);
            var bits = yojimbo.bits_required((uint)min, (uint)max);
            var unsigned_value = (uint)(value - min);
            m_writer.WriteBits(unsigned_value, bits);
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
            Serialize a safety check to the stream (write).
            Safety checks help track down desyncs. A check is written to the stream, and on the other side if the check is not present it asserts and fails the serialize.
            @returns Always returns true. All checking is performed by debug asserts on write.
         */
        public override bool SerializeCheck()
        {
#if YOJIMBO_SERIALIZE_CHECKS
            SerializeAlign();
            var serializeCheckValue = yojimbo.SerializeCheckValue;
            SerializeBits(ref serializeCheckValue, 32);
#endif
            return true;
        }

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

    #endregion

    #region ReadStream

    /**
        Stream class for reading bitpacked data.
        This class is a wrapper around the bit reader class. Its purpose is to provide unified interface for reading and writing.
        You can determine if you are reading from a stream by calling Stream::IsReading inside your templated serialize method.
        This is evaluated at compile time, letting the compiler generate optimized serialize functions without the hassle of maintaining separate read and write functions.
        IMPORTANT: Generally, you don't call methods on this class directly. Use the serialize_* macros instead. See test/shared.h for some examples.
        @see BitReader
     */
    public class ReadStream : BaseStream
    {
        public override bool IsWriting => false;
        public override bool IsReading => true;

        /**
            Read stream constructor.
            @param buffer The buffer to read from.
            @param bytes The number of bytes in the buffer. May be a non-multiple of four, however if it is, the underlying buffer allocated should be large enough to read the any remainder bytes as a dword.
            @param allocator The allocator to use for stream allocations. This lets you dynamically allocate memory as you read and write packets.
         */
        public ReadStream(Allocator allocator, byte[] buffer, int bytes) : base(allocator)
        {
            m_reader = new BitReader(buffer, bytes);
        }

        /**
            Serialize an integer (read).
            @param value The integer value read is stored here. It is guaranteed to be in [min,max] if this function succeeds.
            @param min The minimum allowed value.
            @param max The maximum allowed value.
            @returns Returns true if the serialize succeeded and the value is in the correct range. False otherwise.
         */
        public override bool SerializeInteger(ref int value, int min, int max)
        {
            yojimbo.assert(min < max);
            var bits = yojimbo.bits_required((uint)min, (uint)max);
            if (m_reader.WouldReadPastEnd(bits))
                return false;
            var unsigned_value = m_reader.ReadBits(bits);
            value = (int)unsigned_value + min;
            return true;
        }

        /**
            Serialize a number of bits (read).
            @param value The integer value read is stored here. Will be in range [0,(1<<bits)-1].
            @param bits The number of bits to read in [1,32].
            @returns Returns true if the serialize read succeeded, false otherwise.
         */
        public override bool SerializeBits(ref uint value, int bits)
        {
            yojimbo.assert(bits > 0);
            yojimbo.assert(bits <= 32);
            if (m_reader.WouldReadPastEnd(bits))
                return false;
            var read_value = m_reader.ReadBits(bits);
            value = read_value;
            return true;
        }

        /**
            Serialize an array of bytes (read).
            @param data Array of bytes to read.
            @param bytes The number of bytes to read.
            @returns Returns true if the serialize read succeeded. False otherwise.
         */
        public override bool SerializeBytes(byte[] data, int bytes)
        {
            if (!SerializeAlign())
                return false;
            if (m_reader.WouldReadPastEnd(bytes * 8))
                return false;
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
                return false;
            if (!m_reader.ReadAlign())
                return false;
            return true;
        }

        /** 
            If we were to read an align right now, how many bits would we need to read?
            @returns The number of zero pad bits required to achieve byte alignment in [0,7].
         */
        public override int AlignBits =>
            m_reader.AlignBits;

        /**
            Serialize a safety check from the stream (read).
            Safety checks help track down desyncs. A check is written to the stream, and on the other side if the check is not present it asserts and fails the serialize.
            @returns Returns true if the serialize check passed. False otherwise.
         */
        public override bool SerializeCheck()
        {
#if YOJIMBO_SERIALIZE_CHECKS
            if (!SerializeAlign())
                return false;
            var value = 0U;
            if (!SerializeBits(ref value, 32))
                return false;
            if (value != yojimbo.SerializeCheckValue)
                yojimbo.printf(yojimbo.LOG_LEVEL_DEBUG, $"serialize check failed: expected {yojimbo.SerializeCheckValue:x}, got {value:x}\n");
            return value == yojimbo.SerializeCheckValue;
#else
            return true;
#endif
        }

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

    #endregion

    #region MeasureStream

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
            @param allocator The allocator to use for stream allocations. This lets you dynamically allocate memory as you read and write packets.
         */
        public MeasureStream(Allocator allocator) : base(allocator)
        {
            m_bitsWritten = 0;
        }

        /**
            Serialize an integer (measure).
            @param value The integer value to write. Not actually used or checked.
            @param min The minimum value.
            @param max The maximum value.
            @returns Always returns true. All checking is performed by debug asserts only on measure.
         */
        public override bool SerializeInteger(ref int value, int min, int max)
        {
            yojimbo.assert(min < max);
            yojimbo.assert(value >= min);
            yojimbo.assert(value <= max);
            var bits = yojimbo.bits_required((uint)min, (uint)max);
            m_bitsWritten += bits;
            return true;
        }

        /**
            Serialize a number of bits (write).
            @param value The unsigned integer value to serialize. Not actually used or checked.
            @param bits The number of bits to write in [1,32].
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
            @param data Array of bytes to 'write'. Not actually used.
            @param bytes The number of bytes to 'write'.
            @returns Always returns true. All checking is performed by debug asserts on write.
         */
        public override bool SerializeBytes(byte[] data, int bytes)
        {
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
            var alignBits = AlignBits;
            m_bitsWritten += alignBits;
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
            Serialize a safety check to the stream (measure).
            @returns Always returns true. All checking is performed by debug asserts on write.
         */
        public override bool SerializeCheck()
        {
#if YOJIMBO_SERIALIZE_CHECKS
            SerializeAlign();
            m_bitsWritten += 32;
#endif
            return true;
        }

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

    #endregion

    #region Address

    static partial class yojimbo
    {
        public const int MaxAddressLength = 256;    ///< The maximum length of an address when converted to a string (includes terminating null). @see Address::ToString
    }

    /** 
        Address type.
        @see Address::GetType.
     */
    public enum AddressType
    {
        ADDRESS_NONE,                               ///< Not an address. Set by the default constructor.
        ADDRESS_IPV4,                               ///< An IPv4 address, eg: "146.95.129.237"
        ADDRESS_IPV6                                ///< An IPv6 address, eg: "48d9:4a08:b543:ae31:89d8:3226:b92c:cbba"
    }

    /** 
        An IP address and port number.
        Supports both IPv4 and IPv6 addresses.
        Identifies where a packet came from, and where a packet should be sent.
     */
    public class Address
    {
        AddressType m_type;                         ///< The address type: IPv4 or IPv6.
        IPAddress m_address;
        ushort m_port;                              ///< The IP port. Valid for IPv4 and IPv6 address types.

        /**
            Address default constructor.
            Designed for convenience so you can have address members of classes and initialize them via assignment.
            An address created by the default constructor will have address type set to ADDRESS_NONE. Address::IsValid will return false.
            @see IsValid
         */
        public Address() =>
            Clear();

        // Clone
        public Address(Address address)
        {
            m_type = address.m_type;
            m_address = new IPAddress(address.m_address.GetAddressBytes());
            m_port = address.m_port;
        }

        /**
            Create an IPv4 address.
            IMPORTANT: Pass in port in local byte order. The address class handles the conversion to network order for you.
            @param a The first field of the IPv4 address.
            @param b The second field of the IPv4 address.
            @param c The third field of the IPv4 address.
            @param d The fourth field of the IPv4 address.
            @param port The IPv4 port (local byte order).
         */
        public Address(byte a, byte b, byte c, byte d, ushort port = 0)
        {
            m_type = AddressType.ADDRESS_IPV4;
            m_address = new IPAddress(new byte[] { a, b, c, d });
            m_port = port;
        }

        /**
            Create an IPv4 address.
            @param address Array of four address fields for the IPv4 address.
            @param port The port number (local byte order).
         */
        public Address(byte[] address, ushort port = 0)
        {
            m_type = AddressType.ADDRESS_IPV4;
            if (address.Length != 4)
                throw new ArgumentOutOfRangeException(nameof(address));
            m_address = new IPAddress(address);
            m_port = port;
        }

        /**
            Create an IPv6 address.
            IMPORTANT: Pass in address fields and the port in local byte order. The address class handles the conversion to network order for you.
            @param a First field of the IPv6 address (local byte order).
            @param b Second field of the IPv6 address (local byte order).
            @param c Third field of the IPv6 address (local byte order).
            @param d Fourth field of the IPv6 address (local byte order).
            @param e Fifth field of the IPv6 address (local byte order).
            @param f Sixth field of the IPv6 address (local byte order).
            @param g Seventh field of the IPv6 address (local byte order).
            @param h Eighth field of the IPv6 address (local byte order).
            @param port The port number (local byte order).
         */
        public Address(ushort a, ushort b, ushort c, ushort d, ushort e, ushort f, ushort g, ushort h, ushort port = 0)
        {
            m_type = AddressType.ADDRESS_IPV6;
            m_address = new IPAddress(new ushort[] { a, b, c, d, e, f, g, h }.SelectMany(z => BitConverter.GetBytes(z).Reverse()).ToArray());
            m_port = port;
        }

        /**
            Create an IPv6 address.
            IMPORTANT: Pass in address fields and the port in local byte order. The address class handles the conversion to network order for you.
            @param address Array of 8 16 bit address fields for the IPv6 address (local byte order).
            @param port The IPv6 port (local byte order).
         */
        public Address(ushort[] address, ushort port = 0)
        {
            m_type = AddressType.ADDRESS_IPV6;
            if (address.Length != 8)
                throw new ArgumentOutOfRangeException(nameof(address));
            m_address = new IPAddress(address.SelectMany(z => BitConverter.GetBytes(z).Reverse()).ToArray());
            m_port = port;
        }

        /**
            Parse a string to an address.
            This versions supports parsing a port included in the address string. For example, "127.0.0.1:4000" and "[::1]:40000". 
            Parsing is performed via inet_pton once the port # has been extracted from the string, so you may specify any IPv4 or IPv6 address formatted in any valid way, and it should work as you expect.
            Depending on the type of data in the string the address will become ADDRESS_TYPE_IPV4 or ADDRESS_TYPE_IPV6.
            If the string is not recognized as a valid address, the address type is set to ADDRESS_TYPE_NONE, causing Address::IsValid to return false. Please check that after creating an address from a string.
            @param address The string to parse to create the address.
            @see Address::IsValid
            @see Address::GetType
         */
        public Address(string address) =>
            Parse(address);

        /**
            Parse a string to an address.
            This versions overrides any port read in the address with the port parameter. This lets you parse "127.0.0.1" and "[::1]" and pass in the port you want programmatically.
            Parsing is performed via inet_pton once the port # has been extracted from the string, so you may specify any IPv4 or IPv6 address formatted in any valid way, and it should work as you expect.
            Depending on the type of data in the string the address will become ADDRESS_TYPE_IPV4 or ADDRESS_TYPE_IPV6.
            If the string is not recognized as a valid address, the address type is set to ADDRESS_TYPE_NONE, causing Address::IsValid to return false. Please check that after creating an address from a string.
            @param address The string to parse to create the address.
            @param port Overrides the port number read from the string (if any).
            @see Address::IsValid
            @see Address::GetType
         */
        public Address(string address, ushort port)
        {
            Parse(address);
            m_port = port;
        }

        /**
            Clear the address.
            The address type is set to ADDRESS_TYPE_NONE.
            After this function is called Address::IsValid will return false.
         */
        public void Clear()
        {
            m_type = AddressType.ADDRESS_NONE;
            m_address = IPAddress.Any;
            m_port = 0;
        }

        /**
            Get the IPv4 address data.
            @returns The IPv4 address as an array of bytes.
         */
        public byte[] GetAddress4()
        {
            yojimbo.assert(m_type == AddressType.ADDRESS_IPV4);
            return m_address.GetAddressBytes();
        }

        /**
            Get the IPv6 address data.
            @returns the IPv6 address data as an array of uint16_t (local byte order).
         */
        public ushort[] GetAddress6()
        {
            yojimbo.assert(m_type == AddressType.ADDRESS_IPV6);
            var b = m_address.GetAddressBytes();
            var r = new ushort[8];
            for (var p = 0; p < 16; p += 2)
                r[p >> 1] = (ushort)(b[p + 1] | (b[p] << 8));
            return r;
        }

        /**
            Gets or Sets the port.
            This is useful when you want to programmatically set a server port, eg. try to open a server on ports 40000, 40001, etc...
            @param port The port number (local byte order). Works for both IPv4 and IPv6 addresses.
         */
        public ushort Port
        {
            get => m_port;
            set => m_port = value;
        }

        /**
            Get the address type.
            @returns The address type: ADDRESS_NONE, ADDRESS_IPV4 or ADDRESS_IPV6.
         */
        public AddressType Type => m_type;

        /**
            Convert the address to a string.
            @param buffer The buffer the address will be written to.
            @param bufferSize The size of the buffer in bytes. Must be at least MaxAddressLength.
         */
        public override string ToString()
        {
            if (m_type == AddressType.ADDRESS_IPV4)
                return (m_port != 0) ? $"{m_address}:{m_port}" : $"{m_address}";
            else if (m_type == AddressType.ADDRESS_IPV6)
                return (m_port == 0) ? $"{m_address}" : $"[{m_address}]:{m_port}";
            else return "NONE";
        }

        /**
            True if the address is valid.
            A valid address is any address with a type other than ADDRESS_TYPE_NONE.
            @returns True if the address is valid, false otherwise.
         */
        public bool IsValid =>
            m_type != AddressType.ADDRESS_NONE;

        /**
            Is this a loopback address?
            Corresponds to an IPv4 address of "127.0.0.1", or an IPv6 address of "::1".
            @returns True if this is the loopback address.
         */
        public bool IsLoopback =>
            (m_type == AddressType.ADDRESS_IPV4 && BufferEx.Equal(m_address.GetAddressBytes(), IPAddress.Loopback.GetAddressBytes())) ||
            (m_type == AddressType.ADDRESS_IPV6 && BufferEx.Equal(m_address.GetAddressBytes(), IPAddress.IPv6Loopback.GetAddressBytes()));

        /**
            Is this an IPv6 link local address?
            Corresponds to the first field of the address being 0xfe80
            @returns True if this address is a link local IPv6 address.
         */
        public bool IsLinkLocal =>
            m_type == AddressType.ADDRESS_IPV6 && m_address.IsIPv6LinkLocal;

        /**
            Is this an IPv6 site local address?
            Corresponds to the first field of the address being 0xfec0
            @returns True if this address is a site local IPv6 address.
         */
        public bool IsSiteLocal =>
            m_type == AddressType.ADDRESS_IPV6 && m_address.IsIPv6SiteLocal;

        /**
            Is this an IPv6 multicast address?
            Corresponds to the first field of the IPv6 address being 0xff00
            @returns True if this address is a multicast IPv6 address.
         */
        public bool IsMulticast =>
            m_type == AddressType.ADDRESS_IPV6 && m_address.IsIPv6Multicast;

        /**
            Is this in IPv6 global unicast address?
            Corresponds to any IPv6 address that is not any of the following: Link Local, Site Local, Multicast or Loopback.
            @returns True if this is a global unicast IPv6 address.
         */
        public bool IsGlobalUnicast =>
            m_type == AddressType.ADDRESS_IPV6 && !m_address.IsIPv6LinkLocal
                && !m_address.IsIPv6SiteLocal
                && !m_address.IsIPv6Multicast
                && !IsLoopback;

        public override bool Equals(object obj) =>
            (this == obj as Address);

        public override int GetHashCode() =>
            base.GetHashCode();

        public static bool operator ==(Address a, Address b)
        {
            if (a.m_type != b.m_type)
                return false;
            if (a.m_port != b.m_port)
                return false;
            if (a.m_type == AddressType.ADDRESS_IPV4 && BufferEx.Equal(a.m_address.GetAddressBytes(), b.m_address.GetAddressBytes()))
                return true;
            else if (a.m_type == AddressType.ADDRESS_IPV6 && BufferEx.Equal(a.m_address.GetAddressBytes(), b.m_address.GetAddressBytes()))
                return true;
            else return false;
        }

        public static bool operator !=(Address a, Address b) =>
            !(a == b);

        /** 
            Helper function to parse an address string. 
            Used by the constructors that take a string parameter.
            @param address The string to parse.
         */
        protected void Parse(string address)
        {
            // first try to parse as an IPv6 address:
            // 1. if the first character is '[' then it's probably an ipv6 in form "[addr6]:portnum"
            // 2. otherwise try to parse as raw IPv6 address, parse using inet_pton

            yojimbo.assert(address != null);

            int base_index;
            var addressLength = address.Length;
            m_port = 0;
            if (address.Length > 0 && address[0] == '[')
            {
                base_index = addressLength - 1;
                for (var i = 0; i < 6; ++i)                 // note: no need to search past 6 characters as ":65535" is longest port value
                {
                    var index = base_index - i;
                    if (index < 3)
                        break;
                    if (address[index] == ':')
                    {
                        string value;
                        m_port = (ushort)((value = address.Substring(index + 1)).Length > 0 ? int.Parse(value) : 0);
                        address = address.Substring(0, index - 1);
                    }
                }
                address = address.Substring(1);
            }
            if (IPAddress.TryParse(address, out var ipaddress) && ipaddress.AddressFamily == AddressFamily.InterNetworkV6)
            {
                m_address = ipaddress;
                m_type = AddressType.ADDRESS_IPV6;
                return;
            }

            // otherwise it's probably an IPv4 address:
            // 1. look for ":portnum", if found save the portnum and strip it out
            // 2. parse remaining ipv4 address via inet_pton

            addressLength = address.Length;
            base_index = addressLength - 1;
            for (var i = 0; i < 6; ++i)
            {
                var index = base_index - i;
                if (index < 0)
                    break;
                if (address[index] == ':')
                {
                    string value;
                    m_port = (ushort)((value = address.Substring(index + 1)).Length > 0 ? int.Parse(value) : 0);
                    address = address.Substring(0, index);
                }
            }

            if (IPAddress.TryParse(address, out ipaddress) && ipaddress.AddressFamily == AddressFamily.InterNetwork)
            {
                m_type = AddressType.ADDRESS_IPV4;
                m_address = ipaddress;
            }
            else
                // Not a valid IPv4 address. Set address as invalid.
                Clear();
        }
    }

    #endregion

    #region serialize

    static partial class yojimbo
    {
        /**
            Serialize integer value (read/write/measure).
            This is a helper macro to make writing unified serialize functions easier.
            Serialize macros returns false on error so we don't need to use exceptions for error handling on read. This is an important safety measure because packet data comes from the network and may be malicious.
            IMPORTANT: This macro must be called inside a templated serialize function with template \<typename Stream\>. The serialize method must have a bool return value.
            @param stream The stream object. May be a read, write or measure stream.
            @param value The integer value to serialize in [min,max].
            @param min The minimum value.
            @param max The maximum value.
         */
        public static bool serialize_int(this BaseStream stream, ref ushort value, int min, int max) { int v = value; var r = serialize_int(stream, ref v, min, max); value = (ushort)v; return r; }
        public static bool serialize_int(this BaseStream stream, ref int value, int min, int max)
        {
            assert(min < max);
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
            {
                value = int32_value;
                if (value < min ||
                    value > max)
                    return false;
            }
            return true;
        }

        /**
            Serialize bits to the stream (read/write/measure).
            This is a helper macro to make writing unified serialize functions easier.
            Serialize macros returns false on error so we don't need to use exceptions for error handling on read. This is an important safety measure because packet data comes from the network and may be malicious.
            IMPORTANT: This macro must be called inside a templated serialize function with template \<typename Stream\>. The serialize method must have a bool return value.
            @param stream The stream object. May be a read, write or measure stream.
            @param value The unsigned integer value to serialize.
            @param bits The number of bits to serialize in [1,32].
         */
        public static bool serialize_bits(this BaseStream stream, ref byte value, int bits) { uint v = value; var r = serialize_bits(stream, ref v, bits); value = (byte)v; return r; }
        public static bool serialize_bits(this BaseStream stream, ref ushort value, int bits) { uint v = value; var r = serialize_bits(stream, ref v, bits); value = (ushort)v; return r; }
        public static bool serialize_bits(this BaseStream stream, ref short value, int bits) { uint v = (uint)value; var r = serialize_bits(stream, ref v, bits); value = (short)v; return r; }
        public static bool serialize_bits(this BaseStream stream, ref int value, int bits) { uint v = (uint)value; var r = serialize_bits(stream, ref v, bits); value = (int)v; return r; }
        public static bool serialize_bits(this BaseStream stream, ref uint value, int bits)
        {
            assert(bits > 0);
            assert(bits <= 32);
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
            Serialize a boolean value to the stream (read/write/measure).
            This is a helper macro to make writing unified serialize functions easier.
            Serialize macros returns false on error so we don't need to use exceptions for error handling on read. This is an important safety measure because packet data comes from the network and may be malicious.
            IMPORTANT: This macro must be called inside a templated serialize function with template \<typename Stream\>. The serialize method must have a bool return value.
            @param stream The stream object. May be a read, write or measure stream.
            @param value The boolean value to serialize.
         */
        public static bool serialize_bool(this BaseStream stream, ref bool value)
        {
            var uint32_bool_value = 0U;
            if (stream.IsWriting)
                uint32_bool_value = value ? 1U : 0U;
            serialize_bits(stream, ref uint32_bool_value, 1);
            if (stream.IsReading)
                value = uint32_bool_value != 0 ? true : false;
            return true;
        }

        /**
            Serialize floating point value (read/write/measure).
            This is a helper macro to make writing unified serialize functions easier.
            Serialize macros returns false on error so we don't need to use exceptions for error handling on read. This is an important safety measure because packet data comes from the network and may be malicious.
            IMPORTANT: This macro must be called inside a templated serialize function with template \<typename Stream\>. The serialize method must have a bool return value.
            @param stream The stream object. May be a read, write or measure stream.
            @param value The float value to serialize.
         */
        public static bool serialize_float(this BaseStream stream, ref float value)
        {
            var int_value = 0U;
            if (stream.IsWriting)
                int_value = BitConverter.ToUInt32(BitConverter.GetBytes(value), 0);
            var result = stream.SerializeBits(ref int_value, 32);
            if (stream.IsReading)
                value = BitConverter.ToSingle(BitConverter.GetBytes(int_value), 0);
            return result;
        }

        /**
            Serialize a 32 bit unsigned integer to the stream (read/write/measure).
            This is a helper macro to make unified serialize functions easier.
            Serialize macros returns false on error so we don't need to use exceptions for error handling on read. This is an important safety measure because packet data comes from the network and may be malicious.
            IMPORTANT: This macro must be called inside a templated serialize function with template \<typename Stream\>. The serialize method must have a bool return value.
            @param stream The stream object. May be a read, write or measure stream.
            @param value The unsigned 32 bit integer value to serialize.
         */
        public static bool serialize_uint32(this BaseStream stream, ref uint value) =>
            serialize_bits(stream, ref value, 32);

        /**
            Serialize a 64 bit unsigned integer to the stream (read/write/measure).
            This is a helper macro to make unified serialize functions easier.
            Serialize macros returns false on error so we don't need to use exceptions for error handling on read. This is an important safety measure because packet data comes from the network and may be malicious.
            IMPORTANT: This macro must be called inside a templated serialize function with template \<typename Stream\>. The serialize method must have a bool return value.
            @param stream The stream object. May be a read, write or measure stream.
            @param value The unsigned 64 bit integer value to serialize.
         */
        public static bool serialize_uint64(this BaseStream stream, ref ulong value)
        {
            uint hi = 0, lo = 0U;
            if (stream.IsWriting)
            {
                lo = (uint)value;
                hi = (uint)(value >> 32);
            }
            serialize_bits(stream, ref lo, 32);
            serialize_bits(stream, ref hi, 32);
            if (stream.IsReading)
                value = ((ulong)hi << 32) | lo;
            return true;
        }

        /**
            Serialize double precision floating point value to the stream (read/write/measure).
            This is a helper macro to make writing unified serialize functions easier.
            Serialize macros returns false on error so we don't need to use exceptions for error handling on read. This is an important safety measure because packet data comes from the network and may be malicious.
            IMPORTANT: This macro must be called inside a templated serialize function with template \<typename Stream\>. The serialize method must have a bool return value.
            @param stream The stream object. May be a read, write or measure stream.
            @param value The double precision floating point value to serialize.
         */
        public static bool serialize_double(this BaseStream stream, ref double value)
        {
            var long_value = 0UL;
            if (stream.IsWriting)
                long_value = BitConverter.ToUInt64(BitConverter.GetBytes(value), 0);
            serialize_uint64(stream, ref long_value);
            if (stream.IsReading)
                value = BitConverter.ToDouble(BitConverter.GetBytes(long_value), 0);
            return true;
        }

        /**
            Serialize an array of bytes to the stream (read/write/measure).
            This is a helper macro to make unified serialize functions easier.
            Serialize macros returns false on error so we don't need to use exceptions for error handling on read. This is an important safety measure because packet data comes from the network and may be malicious.
            IMPORTANT: This macro must be called inside a templated serialize function with template \<typename Stream\>. The serialize method must have a bool return value.
            @param stream The stream object. May be a read, write or measure stream.
            @param data Pointer to the data to be serialized.
            @param bytes The number of bytes to serialize.
         */
        public static bool serialize_bytes(this BaseStream stream, byte[] data, int bytes) =>
            stream.SerializeBytes(data, bytes);

        /**
            Serialize a string to the stream (read/write/measure).
            This is a helper macro to make writing unified serialize functions easier.
            Serialize macros returns false on error so we don't need to use exceptions for error handling on read. This is an important safety measure because packet data comes from the network and may be malicious.
            IMPORTANT: This macro must be called inside a templated serialize function with template \<typename Stream\>. The serialize method must have a bool return value.
            @param stream The stream object. May be a read, write or measure stream.
            @param string The string to serialize write/measure. Pointer to buffer to be filled on read.
            @param buffer_size The size of the string buffer. String with terminating null character must fit into this buffer.
         */
        public static bool serialize_string(this BaseStream stream, ref string value, int buffer_size)
        {
            var length = 0;
            if (stream.IsWriting)
            {
                length = value.Length;
                assert(length < buffer_size);
            }
            serialize_int(stream, ref length, 0, buffer_size - 1);
            var stringBytes = stream.IsReading ?
                new byte[buffer_size] :
                value != null ? Encoding.ASCII.GetBytes(value) : new byte[0];
            serialize_bytes(stream, stringBytes, length);
            if (stream.IsReading)
                value = Encoding.ASCII.GetString(stringBytes, 0, length);
            return true;
        }

        /**
            Serialize an alignment to the stream (read/write/measure).
            This is a helper macro to make writing unified serialize functions easier.
            Serialize macros returns false on error so we don't need to use exceptions for error handling on read. This is an important safety measure because packet data comes from the network and may be malicious.
            IMPORTANT: This macro must be called inside a templated serialize function with template \<typename Stream\>. The serialize method must have a bool return value.
            @param stream The stream object. May be a read, write or measure stream.
         */
        public static bool serialize_align(this BaseStream stream)
        {
            if (!stream.SerializeAlign())
                return false;
            return true;
        }

        /**
            Serialize a safety check to the stream (read/write/measure).
            This is a helper macro to make writing unified serialize functions easier.
            Serialize macros returns false on error so we don't need to use exceptions for error handling on read. This is an important safety measure because packet data comes from the network and may be malicious.
            IMPORTANT: This macro must be called inside a templated serialize function with template \<typename Stream\>. The serialize method must have a bool return value.
            @param stream The stream object. May be a read, write or measure stream.
         */
        public static bool serialize_check(this BaseStream stream)
        {
            if (!stream.SerializeCheck())
                return false;
            return true;
        }

        public interface ICanSerialize
        {
            bool Serialize(BaseStream stream);
        }

        /**
            Serialize an object to the stream (read/write/measure).
            This is a helper macro to make writing unified serialize functions easier.
            Serialize macros returns false on error so we don't need to use exceptions for error handling on read. This is an important safety measure because packet data comes from the network and may be malicious.
            IMPORTANT: This macro must be called inside a templated serialize function with template \<typename Stream\>. The serialize method must have a bool return value.
            @param stream The stream object. May be a read, write or measure stream.
            @param object The object to serialize. Must have a serialize method on it.
         */
        public static bool serialize_object(this BaseStream stream, ref ICanSerialize obj)
        {
            if (!obj.Serialize(stream))
                return false;
            return true;
        }

        /**
            Serialize an address to the stream (read/write/measure).
            This is a helper macro to make writing unified serialize functions easier.
            Serialize macros returns false on error so we don't need to use exceptions for error handling on read. This is an important safety measure because packet data comes from the network and may be malicious.
            IMPORTANT: This macro must be called inside a templated serialize function with template \<typename Stream\>. The serialize method must have a bool return value.
            @param stream The stream object. May be a read, write or measure stream.
            @param value The address to serialize. Must be a valid address.
         */
        public static bool serialize_address(this BaseStream stream, ref Address address)
        {
            string buffer = null;
            if (stream.IsWriting)
            {
                assert(address.IsValid);
                buffer = address.ToString();
            }
            serialize_string(stream, ref buffer, MaxAddressLength);
            if (stream.IsReading)
            {
                address = new Address(buffer);
                if (!address.IsValid)
                    return false;
            }
            return true;
        }

        /**
            Serialize an integer value relative to another (read/write/measure).
            This is a helper macro to make writing unified serialize functions easier.
            Serialize macros returns false on error so we don't need to use exceptions for error handling on read. This is an important safety measure because packet data comes from the network and may be malicious.
            IMPORTANT: This macro must be called inside a templated serialize function with template \<typename Stream\>. The serialize method must have a bool return value.
            @param stream The stream object. May be a read, write or measure stream.
            @param previous The previous integer value.
            @param current The current integer value.
         */
        public static bool serialize_int_relative(this BaseStream stream, int previous, ref int current)
        {
            var difference = 0;
            if (stream.IsWriting)
            {
                assert(previous < (uint)current);
                difference = current - previous;
            }

            var oneBit = false;
            if (stream.IsWriting)
                oneBit = difference == 1;
            serialize_bool(stream, ref oneBit);
            if (oneBit)
            {
                if (stream.IsReading)
                    current = previous + 1;
                return true;
            }

            var twoBits = false;
            if (stream.IsWriting)
                twoBits = difference <= 6;
            serialize_bool(stream, ref twoBits);
            if (twoBits)
            {
                serialize_int(stream, ref difference, 2, 6);
                if (stream.IsReading)
                    current = previous + difference;
                return true;
            }

            var fourBits = false;
            if (stream.IsWriting)
                fourBits = difference <= 23;
            serialize_bool(stream, ref fourBits);
            if (fourBits)
            {
                serialize_int(stream, ref difference, 7, 23);
                if (stream.IsReading)
                    current = previous + difference;
                return true;
            }

            var eightBits = false;
            if (stream.IsWriting)
                eightBits = difference <= 280;
            serialize_bool(stream, ref eightBits);
            if (eightBits)
            {
                serialize_int(stream, ref difference, 24, 280);
                if (stream.IsReading)
                    current = previous + difference;
                return true;
            }

            var twelveBits = false;
            if (stream.IsWriting)
                twelveBits = difference <= 4377;
            serialize_bool(stream, ref twelveBits);
            if (twelveBits)
            {
                serialize_int(stream, ref difference, 281, 4377);
                if (stream.IsReading)
                    current = previous + difference;
                return true;
            }

            var sixteenBits = false;
            if (stream.IsWriting)
                sixteenBits = difference <= 69914;
            serialize_bool(stream, ref sixteenBits);
            if (sixteenBits)
            {
                serialize_int(stream, ref difference, 4378, 69914);
                if (stream.IsReading)
                    current = previous + difference;
                return true;
            }

            var value = (uint)current;
            serialize_uint32(stream, ref value);
            if (stream.IsReading)
                current = (int)value;
            return true;
        }

        /**
            Serialize an ack relative to the current sequence number (read/write/measure).
            This is a helper macro to make writing unified serialize functions easier.
            Serialize macros returns false on error so we don't need to use exceptions for error handling on read. This is an important safety measure because packet data comes from the network and may be malicious.
            IMPORTANT: This macro must be called inside a templated serialize function with template \<typename Stream\>. The serialize method must have a bool return value.
            @param stream The stream object. May be a read, write or measure stream.
            @param sequence The current sequence number.
            @param ack The ack sequence number, which is typically near the current sequence number.
         */
        public static bool serialize_ack_relative(this BaseStream stream, ushort sequence, ref ushort ack)
        {
            var ack_delta = 0;
            var ack_in_range = false;
            if (stream.IsWriting)
            {
                if (ack < sequence)
                    ack_delta = sequence - ack;
                else
                    ack_delta = sequence + 65536 - ack;
                assert(ack_delta > 0);
                assert((ushort)(sequence - ack_delta) == ack);
                ack_in_range = ack_delta <= 64;
            }
            serialize_bool(stream, ref ack_in_range);
            if (ack_in_range)
            {
                serialize_int(stream, ref ack_delta, 1, 64);
                if (stream.IsReading)
                    ack = (ushort)(sequence - ack_delta);
            }
            else { var ack_int = 0U; serialize_bits(stream, ref ack_int, 16); ack = (ushort)ack_int; }
            return true;
        }

        /**
            Serialize a sequence number relative to another (read/write/measure).
            This is a helper macro to make writing unified serialize functions easier.
            Serialize macros returns false on error so we don't need to use exceptions for error handling on read. This is an important safety measure because packet data comes from the network and may be malicious.
            IMPORTANT: This macro must be called inside a templated serialize function with template \<typename Stream\>. The serialize method must have a bool return value.
            @param stream The stream object. May be a read, write or measure stream.
            @param sequence1 The first sequence number to serialize relative to.
            @param sequence2 The second sequence number to be encoded relative to the first.
         */
        public static bool serialize_sequence_relative(this BaseStream stream, ushort sequence1, ref ushort sequence2)
        {
            if (stream.IsWriting)
            {
                var a = sequence1;
                var b = sequence2 + ((sequence1 > sequence2) ? 65536 : 0);
                serialize_int_relative(stream, a, ref b);
            }
            else
            {
                var a = sequence1;
                var b = 0;
                serialize_int_relative(stream, a, ref b);
                if (b >= 65536)
                    b -= 65536;
                sequence2 = (ushort)b;
            }
            return true;
        }

        // read macros corresponding to each serialize_*. useful when you want separate read and write functions.

        public static bool read_bits(this BaseStream stream, ref uint value, int bits)
        {
            assert(bits > 0);
            assert(bits <= 32);
            var uint32_value = 0U;
            if (!stream.SerializeBits(ref uint32_value, bits))
                return false;
            value = uint32_value;
            return true;
        }

        public static bool read_int(this BaseStream stream, ref int value, int min, int max)
        {
            assert(min < max);
            var int32_value = 0;
            if (!stream.SerializeInteger(ref int32_value, min, max))
                return false;
            value = int32_value;
            if (value < min || value > max)
                return false;
            return true;
        }

        public static bool read_bool(this BaseStream stream, ref bool value) { var v = 0U; var r = read_bits(stream, ref v, 1); value = v != 0; return r; }
        public static bool read_float(this BaseStream stream, ref float value) => serialize_float(stream, ref value);
        public static bool read_uint32(this BaseStream stream, ref uint value) => serialize_uint32(stream, ref value);
        public static bool read_uint64(this BaseStream stream, ref ulong value) => serialize_uint64(stream, ref value);
        public static bool read_double(this BaseStream stream, ref double value) => serialize_double(stream, ref value);
        public static bool read_bytes(this BaseStream stream, byte[] data, int bytes) => serialize_bytes(stream, data, bytes);
        public static bool read_string(this BaseStream stream, ref string value, int buffer_size) => serialize_string(stream, ref value, buffer_size);
        public static bool read_align(this BaseStream stream) => serialize_align(stream);
        public static bool read_check(this BaseStream stream) => serialize_check(stream);
        public static bool read_object(this BaseStream stream, ref ICanSerialize obj) => serialize_object(stream, ref obj);
        public static bool read_address(this BaseStream stream, ref Address address) => serialize_address(stream, ref address);
        public static bool read_int_relative(this BaseStream stream, int previous, ref int current) => serialize_int_relative(stream, previous, ref current);
        public static bool read_ack_relative(this BaseStream stream, ushort sequence, ref ushort ack) => serialize_ack_relative(stream, sequence, ref ack);
        public static bool read_sequence_relative(this BaseStream stream, ushort sequence1, ref ushort sequence2) => serialize_sequence_relative(stream, sequence1, ref sequence2);

        // write macros corresponding to each serialize_*. useful when you want separate read and write functions for some reason.

        public static bool write_bits(this BaseStream stream, uint value, int bits)
        {
            assert(bits > 0);
            assert(bits <= 32);
            var uint32_value = (uint)value;
            if (!stream.SerializeBits(ref uint32_value, bits))
                return false;
            return true;
        }

        public static bool write_int(this BaseStream stream, int value, int min, int max)
        {
            assert(min < max);
            assert(value >= min);
            assert(value <= max);
            var int32_value = value;
            if (!stream.SerializeInteger(ref int32_value, min, max))
                return false;
            return true;
        }

        public static bool write_float(this BaseStream stream, float value) => serialize_float(stream, ref value);
        public static bool write_uint32(this BaseStream stream, uint value) => serialize_uint32(stream, ref value);
        public static bool write_uint64(this BaseStream stream, ulong value) => serialize_uint64(stream, ref value);
        public static bool write_double(this BaseStream stream, double value) => serialize_double(stream, ref value);
        public static bool write_bytes(this BaseStream stream, byte[] data, int bytes) => serialize_bytes(stream, data, bytes);
        public static bool write_string(this BaseStream stream, string value, int buffer_size) => serialize_string(stream, ref value, buffer_size);
        public static bool write_align(this BaseStream stream) => serialize_align(stream);
        public static bool write_check(this BaseStream stream) => serialize_check(stream);
        public static bool write_object(this BaseStream stream, ICanSerialize obj) => serialize_object(stream, ref obj);
        public static bool write_address(this BaseStream stream, Address address) => serialize_address(stream, ref address);
        public static bool write_int_relative(this BaseStream stream, int previous, int current) => serialize_int_relative(stream, previous, ref current);
        public static bool write_ack_relative(this BaseStream stream, ushort sequence, ushort ack) => serialize_ack_relative(stream, sequence, ref ack);
        public static bool write_sequence_relative(this BaseStream stream, ushort sequence1, ushort sequence2) => serialize_sequence_relative(stream, sequence1, ref sequence2);
    }

    #endregion

    #region Serializable

    /**
        Interface for an object that knows how to read, write and measure how many bits it would take up in a bit stream.
        IMPORTANT: Instead of overriding the serialize virtual methods method directly, use the YOJIMBO_VIRTUAL_SERIALIZE_FUNCTIONS macro in your derived class to override and redirect them to your templated serialize method.
        This way you can implement read and write for your messages in a single method and the C++ compiler takes care of generating specialized read, write and measure implementations for you.
        See tests/shared.h for some examples of this.
        @see ReadStream
        @see WriteStream
        @see MeasureStream
     */

    public abstract class Serializable
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
            throw new InvalidOperationException();
    }

    #endregion

    #region Message

    /**
        A reference counted object that can be serialized to a bitstream.

        Messages are objects that are sent between client and server across the connection. They are carried inside the ConnectionPacket generated by the Connection class. Messages can be sent reliable-ordered, or unreliable-unordered, depending on the configuration of the channel they are sent over.
        
        To use messages, create your own set of message classes by inheriting from this class (or from BlockMessage, if you want to attach data blocks to your message), then setup an enum of all your message types and derive a message factory class to create your message instances by type.
        
        There are macros to help make defining your message factory painless:
        
            YOJIMBO_MESSAGE_FACTORY_START
            YOJIMBO_DECLARE_MESSAGE_TYPE
            YOJIMBO_MESSAGE_FACTORY_FINISH
        
        Once you have a message factory, register it with your declared inside your client and server classes using:
        
            YOJIMBO_MESSAGE_FACTORY
        
        which overrides the Client::CreateMessageFactory and Server::CreateMessageFactory methods so the client and server classes use your message factory type.
        
        See tests/shared.h for an example showing you how to do this, and the functional tests inside tests/test.cpp for examples showing how how to send and receive messages.
        
        @see BlockMessage
        @see MessageFactory
        @see Connection
     */
    public abstract class Message : Serializable
    {
        /**
            Message constructor.
            Don't call this directly, use a message factory instead.
            @param blockMessage 1 if this is a block message, 0 otherwise.
            @see MessageFactory::Create
         */
        public Message(bool blockMessage = false)
        {
            m_refCount = 1;
            m_id = 0;
            m_type = 0;
            m_blockMessage = blockMessage;
        }

        /** 
            Gets or sets the message id.
            When messages are sent over a reliable-ordered channel, the message id starts at 0 and increases with each message sent over that channel.
            When messages are sent over an unreliable-unordered channel, the message id is set to the sequence number of the packet it was delivered in.
            @param id The message id.
         */
        public ushort Id
        {
            get => m_id;
            set => m_id = value;
        }

        /**
            Get the message type.
            This corresponds to the type enum value used to create the message in the message factory.
            @returns The message type.
            @see MessageFactory.
         */
        public int Type
        {
            get => m_type;
            // Called by the message factory after it creates a message.
            protected internal set => m_type = (ushort)value;
        }

        /**
            Get the reference count on the message.
            Messages start with a reference count of 1 when they are created. This is decreased when they are released. 
            When the reference count reaches 0, the message is destroyed.
            @returns The reference count on the message.
         */
        public int RefCount => m_refCount;

        /**
            Is this a block message?
            Block messages are of type BlockMessage and can have a data block attached to the message.
            @returns True if this is a block message, false otherwise.
            @see BlockMessage.
         */
        public bool IsBlockMessage => m_blockMessage;

        /**
            Virtual serialize function (read).
            Reads the message in from a bitstream.
            Don't override this method directly, instead, use the YOJIMBO_VIRTUAL_SERIALIZE_FUNCTIONS macro in your derived message class to redirect it to a templated serialize method.
            This way you can implement serialization for your packets in a single method and the C++ compiler takes care of generating specialized read, write and measure implementations for you. 
            See tests/shared.h for examples of this.
         */
        //public abstract bool SerializeInternal(ReadStream stream);

        /**
            Virtual serialize function (write).
            Write the message to a bitstream.
            Don't override this method directly, instead, use the YOJIMBO_VIRTUAL_SERIALIZE_FUNCTIONS macro in your derived message class to redirect it to a templated serialize method.
            This way you can implement serialization for your packets in a single method and the C++ compiler takes care of generating specialized read, write and measure implementations for you. 
            See tests/shared.h for examples of this.
         */
        //public abstract bool SerializeInternal(WriteStream stream);

        /**
            Virtual serialize function (measure).
            Measure how many bits this message would take to write. This is used when working out how many messages will fit within the channel packet budget.
            Don't override this method directly, instead, use the YOJIMBO_VIRTUAL_SERIALIZE_FUNCTIONS macro in your derived message class to redirect it to a templated serialize method.
            This way you can implement serialization for your packets in a single method and the C++ compiler takes care of generating specialized read, write and measure implementations for you. 
            See tests/shared.h for examples of this.
         */
        //public abstract bool SerializeInternal(MeasureStream stream);

        /**
            Add a reference to the message.
            This is called when a message is included in a packet and added to the receive queue. 
            This way we don't have to pass messages by value (more efficient) and messages get cleaned up when they are delivered and no packets refer to them.
         */
        protected internal void Acquire() { yojimbo.assert(m_refCount > 0); m_refCount++; }

        /**
            Remove a reference from the message.
            Message are deleted when the number of references reach zero. Messages have reference count of 1 after creation.
         */
        protected internal void Release() { yojimbo.assert(m_refCount > 0); m_refCount--; }

        /**
            Message destructor.
            @see MessageFactory::Release
         */
        public override void Dispose()
        {
            yojimbo.assert(m_refCount == 0);
        }

        int m_refCount;                             ///< Number of references on this message object. Starts at 1. Message is destroyed when it reaches 0.
        ushort m_id;                                ///< The message id. For messages sent over reliable-ordered channels, this starts at 0 and increases with each message sent. For unreliable-unordered channels this is set to the sequence number of the packet the message was included in.
        ushort m_type;                              ///< The message type. Corresponds to the type integer used when the message was created though the message factory.
        bool m_blockMessage;                        ///< 1 if this is a block message. 0 otherwise. If 1 then you can cast the Message* to BlockMessage*. Lightweight RTTI.
    }

    #endregion

    #region BlockMessage

    /**
        A message which can have a block of data attached to it.
        @see ChannelConfig
     */
    public class BlockMessage : Message
    {
        /**
            Block message constructor.
            Don't call this directly, use a message factory instead.
            @see MessageFactory::CreateMessage
         */
        public BlockMessage() : base(true)
        {
            m_allocator = null;
            m_blockData = null;
            m_blockSize = 0;
        }

        /**
            Attach a block to this message.
            You can only attach one block. This method will assert if a block is already attached.
            @see Client::AttachBlockToMessage
            @see Server::AttachBlockToMessage
         */
        public void AttachBlock(Allocator allocator, byte[] blockData, int blockSize)
        {
            yojimbo.assert(blockData != null);
            yojimbo.assert(blockSize > 0);
            yojimbo.assert(m_blockData == null);
            m_allocator = allocator;
            m_blockData = blockData;
            m_blockSize = blockSize;
        }

        /** 
            Detach the block from this message.
            By doing this you are responsible for copying the block pointer and allocator and making sure the block is freed.
            This could be used for example, if you wanted to copy off the block and store it somewhere, without the cost of copying it.
            @see Client::DetachBlockFromMessage
            @see Server::DetachBlockFromMessage
         */
        void DetachBlock()
        {
            m_allocator = null;
            m_blockData = null;
            m_blockSize = 0;
        }

        /**
            Get the allocator used to allocate the block.
            @returns The allocator for the block. null if no block is attached to this message.
         */
        public Allocator Allocator =>
            m_allocator;

        /**
            Get the block data pointer.
            @returns The block data pointer. null if no block is attached.
         */
        public byte[] BlockData =>
            m_blockData;

        /**
            Get the size of the block attached to this message.
            @returns The size of the block (bytes). 0 if no block is attached.
         */
        public int BlockSize =>
            m_blockSize;

        ///**
        //    Templated serialize function for the block message. Doesn't do anything. The block data is serialized elsewhere.
        //    You can override the serialize methods on a block message to implement your own serialize function. It's just like a regular message with a block attached to it.
        //    @see ConnectionPacket
        //    @see ChannelPacketData
        //    @see ReliableOrderedChannel
        //    @see UnreliableUnorderedChannel
        // */
        //public bool Serialize(BaseStream stream) => true;

        /**
            If a block was attached to the message, it is freed here.
         */
        public override void Dispose()
        {
            if (m_allocator != null)
            {
                m_blockData = null;
                m_blockSize = 0;
                m_allocator = null;
            }
        }

        Allocator m_allocator;                      ///< Allocator for the block attached to the message. null if no block is attached.
        byte[] m_blockData;                         ///< The block data. null if no block is attached.
        int m_blockSize;                            ///< The block size (bytes). 0 if no block is attached.
    }

    #endregion

    #region MessageFactory

    /**
        Message factory error level.
     */
    public enum MessageFactoryErrorLevel
    {
        MESSAGE_FACTORY_ERROR_NONE,                         ///< No error. All is well.
        MESSAGE_FACTORY_ERROR_FAILED_TO_ALLOCATE_MESSAGE,   ///< Failed to allocate a message. Typically this means we ran out of memory on the allocator backing the message factory.
    }

    /**
        Defines the set of message types that can be created.

        You can derive a message factory yourself to create your own message types, or you can use these helper macros to do it for you:
        
            YOJIMBO_MESSAGE_FACTORY_START
            YOJIMBO_DECLARE_MESSAGE_TYPE
            YOJIMBO_MESSAGE_FACTORY_FINISH
        
        See tests/shared.h for an example showing how to use the macros.
     */
    public class MessageFactory
    {
        /**
            Message factory allocator.
            Pass in the number of message types for the message factory from the derived class.
            @param allocator The allocator used to create messages.
            @param numTypes The number of message types. Valid types are in [0,numTypes-1].
         */
        public MessageFactory(Allocator allocator, int numTypes)
        {
            m_allocator = allocator;
            m_numTypes = numTypes;
            m_errorLevel = MessageFactoryErrorLevel.MESSAGE_FACTORY_ERROR_NONE;
        }

        /**
            Message factory destructor.
            Checks for message leaks if YOJIMBO_DEBUG_MESSAGE_LEAKS is defined and not equal to zero. This is on by default in debug build.
         */
        public virtual void Dispose()
        {
            yojimbo.assert(m_allocator != null);

            m_allocator = null;

#if YOJIMBO_DEBUG_MESSAGE_LEAKS
            if (allocated_messages.Count != 0)
            {
                Console.Write("you leaked messages!\n");
                Console.Write($"{allocated_messages.Count} messages leaked\n");
                foreach (var i in allocated_messages)
                {
                    var message = i.Key;
                    Console.Write($"leaked message {message} (type {message.Type}, refcount {message.RefCount})\n");
                }
                Environment.Exit(1);
            }
#endif
        }

        /**
            Create a message by type.
            IMPORTANT: Check the message pointer returned by this call. It can be null if there is no memory to create a message!
            Messages returned from this function have one reference added to them. When you are finished with the message, pass it to MessageFactory::Release.
            @param type The message type in [0,numTypes-1].
            @returns The allocated message, or null if the message could not be allocated. If the message allocation fails, the message factory error level is set to MESSAGE_FACTORY_ERROR_FAILED_TO_ALLOCATE_MESSAGE.
            @see MessageFactory::AddRef
            @see MessageFactory::ReleaseMessage
         */
        public Message CreateMessage(int type)
        {
            yojimbo.assert(type >= 0);
            yojimbo.assert(type < m_numTypes);
            var message = CreateMessageInternal(type);
            if (message == null)
            {
                m_errorLevel = MessageFactoryErrorLevel.MESSAGE_FACTORY_ERROR_FAILED_TO_ALLOCATE_MESSAGE;
                return null;
            }
#if YOJIMBO_DEBUG_MESSAGE_LEAKS
            allocated_messages[message] = 1;
            yojimbo.assert(allocated_messages.ContainsKey(message));
#endif
            return message;
        }

        /**
            Add a reference to a message.
            @param message The message to add a reference to.
            @see MessageFactory::Create
            @see MessageFactory::Release
         */
        public void AcquireMessage(Message message)
        {
            yojimbo.assert(message != null);
            if (message != null)
                message.Acquire();
        }

        /**
            Remove a reference from a message.
            Messages have 1 reference when created. When the reference count reaches 0, they are destroyed.
            @see MessageFactory::Create
            @see MessageFactory::AddRef
         */
        public void ReleaseMessage<TMessage>(ref TMessage message) where TMessage : Message
        {
            yojimbo.assert(message != null);
            if (message == null)
                return;
            message.Release();
            if (message.RefCount == 0)
            {
#if YOJIMBO_DEBUG_MESSAGE_LEAKS
                yojimbo.assert(allocated_messages.ContainsKey(message));
                allocated_messages.Remove(message);
#endif
                yojimbo.assert(m_allocator != null);
                message?.Dispose(); message = null;
            }
        }

        /**
            Get the number of message types supported by this message factory.
            @returns The number of message types.
         */
        public int NumTypes =>
            m_numTypes;

        /**
            Get the allocator used to create messages.
            @returns The allocator.
         */
        public Allocator Allocator
        {
            get
            {
                yojimbo.assert(m_allocator != null);
                return m_allocator;
            }
        }

        /**
            Get the error level.
            When used with a client or server, an error level on a message factory other than MESSAGE_FACTORY_ERROR_NONE triggers a client disconnect.
         */
        public MessageFactoryErrorLevel ErrorLevel =>
            m_errorLevel;

        /**
            Clear the error level back to no error.
         */
        public void ClearErrorLevel() =>
            m_errorLevel = MessageFactoryErrorLevel.MESSAGE_FACTORY_ERROR_NONE;

        /**
            This method is overridden to create messages by type.
            @param type The type of message to be created.
            @returns The message created. Its reference count is 1.
         */
        protected virtual Message CreateMessageInternal(int type) => null;

        /**
            Set the message type of a message.
            @param message The message object.
            @param type The message type to set.
         */
        protected void SetMessageType(Message message, int type) => message.Type = type;

#if YOJIMBO_DEBUG_MESSAGE_LEAKS
        Dictionary<Message, int> allocated_messages = new Dictionary<Message, int>();   ///< The set of allocated messages for this factory. Used to track down message leaks.
#endif
        Allocator m_allocator;                      ///< The allocator used to create messages.
        int m_numTypes;                             ///< The number of message types.
        MessageFactoryErrorLevel m_errorLevel;      ///< The message factory error level.
    }

    #endregion

    #region FACTORY MACRO

    /** 
        Start a definition of a new message factory.
        This is a helper macro to make declaring your own message factory class easier.
        @param factory_class The name of the message factory class to generate.
        @param num_message_types The number of message types for this factory.
        See tests/shared.h for an example of usage.
     */
    //#define YOJIMBO_MESSAGE_FACTORY_START(factory_class, num_message_types)
    public class MESSAGE_FACTORY_START : MessageFactory
    {
        readonly Dictionary<int, Type> Types = new Dictionary<int, Type>();

        public MESSAGE_FACTORY_START(Allocator allocator, int num_message_types) : base(allocator, num_message_types) { }

        /** 
            Add a message type to a message factory.
            This is a helper macro to make declaring your own message factory class easier.
            @param message_type The message type value. This is typically an enum value.
            @param message_class The message class to instantiate when a message of this type is created.
            See tests/shared.h for an example of usage.
         */
        //#define YOJIMBO_DECLARE_MESSAGE_TYPE(message_type, message_class)
        public void DECLARE_MESSAGE_TYPE(int message_type, Type message_class) =>
            Types.Add(message_type, message_class);

        protected override Message CreateMessageInternal(int type)
        {
            if (!Types.TryGetValue(type, out var message_class))
                return null;
            var message = (Message)Activator.CreateInstance(message_class);
            if (message == null)
                return null;
            SetMessageType(message, type);
            return message;
        }

        /** 
        Finish the definition of a new message factory.
        This is a helper macro to make declaring your own message factory class easier.
        See tests/shared.h for an example of usage.
        */
        //#define YOJIMBO_MESSAGE_FACTORY_FINISH()
        public void MESSAGE_FACTORY_FINISH() { }
    }

    #endregion

    #region ChannelPacketData

    public class ChannelPacketData
    {
        public ushort channelIndex;
        public bool initialized;
        public bool blockMessage;
        public bool messageFailedToSerialize;

        public class MessageData
        {
            public int numMessages;
            public Message[] messages;
        }

        public class BlockData
        {
            public BlockMessage message;
            public byte[] fragmentData;
            public ushort messageId;
            public ushort fragmentId;
            public ushort fragmentSize;
            public ushort numFragments;
            public int messageType;
        }

        public MessageData message = new MessageData();
        public BlockData block = new BlockData();

        public void Initialize()
        {
            channelIndex = 0;
            blockMessage = false;
            messageFailedToSerialize = false;
            message.numMessages = 0;
            initialized = true;
        }

        public void Free(ref MessageFactory messageFactory)
        {
            yojimbo.assert(initialized);
            var allocator = messageFactory.Allocator;
            if (!blockMessage)
            {
                if (message.numMessages > 0)
                {
                    for (var i = 0; i < message.numMessages; ++i)
                        if (message.messages[i] != null)
                            messageFactory.ReleaseMessage(ref message.messages[i]);
                    message.messages = null;
                }
            }
            else
            {
                if (block.message != null)
                {
                    messageFactory.ReleaseMessage(ref block.message);
                    block.message = null;
                }
                block.fragmentData = null;
            }
            initialized = false;
        }

        static bool SerializeOrderedMessages(
            BaseStream stream,
            MessageFactory messageFactory,
            ref int numMessages,
            ref Message[] messages,
            int maxMessagesPerPacket)
        {
            var maxMessageType = messageFactory.NumTypes - 1;

            var hasMessages = stream.IsWriting && numMessages != 0;

            yojimbo.serialize_bool(stream, ref hasMessages);

            if (hasMessages)
            {
                yojimbo.serialize_int(stream, ref numMessages, 1, maxMessagesPerPacket);

                var messageTypes = new int[numMessages];
                var messageIds = new ushort[numMessages];

                if (stream.IsWriting)
                {
                    yojimbo.assert(messages != null);

                    for (var i = 0; i < numMessages; ++i)
                    {
                        yojimbo.assert(messages[i] != null);
                        messageTypes[i] = messages[i].Type;
                        messageIds[i] = messages[i].Id;
                    }
                }
                else
                {
                    var allocator = messageFactory.Allocator;
                    messages = new Message[numMessages];
                }

                yojimbo.serialize_bits(stream, ref messageIds[0], 16);

                for (var i = 1; i < numMessages; ++i)
                    yojimbo.serialize_sequence_relative(stream, messageIds[i - 1], ref messageIds[i]);

                for (var i = 0; i < numMessages; ++i)
                {
                    if (maxMessageType > 0)
                        yojimbo.serialize_int(stream, ref messageTypes[i], 0, maxMessageType);
                    else
                        messageTypes[i] = 0;

                    if (stream.IsReading)
                    {
                        messages[i] = messageFactory.CreateMessage(messageTypes[i]);

                        if (messages[i] == null)
                        {
                            yojimbo.printf(yojimbo.LOG_LEVEL_ERROR, $"error: failed to create message of type {messageTypes[i]} (SerializeOrderedMessages)\n");
                            return false;
                        }

                        messages[i].Id = messageIds[i];
                    }

                    yojimbo.assert(messages[i] != null);

                    if (!messages[i].SerializeInternal(stream))
                    {
                        yojimbo.printf(yojimbo.LOG_LEVEL_ERROR, $"error: failed to serialize message of type {messageTypes[i]} (SerializeOrderedMessages)\n");
                        return false;
                    }
                }
            }

            return true;
        }

        internal static bool SerializeMessageBlock(BaseStream stream, MessageFactory messageFactory, BlockMessage blockMessage, int maxBlockSize)
        {
            var blockSize = stream.IsWriting ? blockMessage.BlockSize : 0;

            yojimbo.serialize_int(stream, ref blockSize, 1, maxBlockSize);

            byte[] blockData;

            if (stream.IsReading)
            {
                var allocator = messageFactory.Allocator;
                blockData = new byte[blockSize];
                if (blockData == null)
                {
                    yojimbo.printf(yojimbo.LOG_LEVEL_ERROR, "error: failed to allocate message block (SerializeMessageBlock)\n");
                    return false;
                }
                blockMessage.AttachBlock(allocator, blockData, blockSize);
            }
            else
                blockData = blockMessage.BlockData;

            yojimbo.serialize_bytes(stream, blockData, blockSize);

            return true;
        }

        static bool SerializeUnorderedMessages(
            BaseStream stream,
            MessageFactory messageFactory,
            ref int numMessages,
            ref Message[] messages,
            int maxMessagesPerPacket,
            int maxBlockSize)
        {
            var maxMessageType = messageFactory.NumTypes - 1;

            var hasMessages = stream.IsWriting && numMessages != 0;

            yojimbo.serialize_bool(stream, ref hasMessages);

            if (hasMessages)
            {
                yojimbo.serialize_int(stream, ref numMessages, 1, maxMessagesPerPacket);

                var messageTypes = new int[numMessages];

                if (stream.IsWriting)
                {
                    yojimbo.assert(messages != null);

                    for (var i = 0; i < numMessages; ++i)
                    {
                        yojimbo.assert(messages[i] != null);
                        messageTypes[i] = messages[i].Type;
                    }
                }
                else
                {
                    var allocator = messageFactory.Allocator;

                    messages = new Message[numMessages];

                    for (var i = 0; i < numMessages; ++i)
                        messages[i] = null;
                }

                for (var i = 0; i < numMessages; ++i)
                {
                    if (maxMessageType > 0)
                        yojimbo.serialize_int(stream, ref messageTypes[i], 0, maxMessageType);
                    else
                        messageTypes[i] = 0;

                    if (stream.IsReading)
                    {
                        messages[i] = messageFactory.CreateMessage(messageTypes[i]);

                        if (messages[i] == null)
                        {
                            yojimbo.printf(yojimbo.LOG_LEVEL_ERROR, $"error: failed to create message type {messageTypes[i]} (SerializeUnorderedMessages)\n");
                            return false;
                        }
                    }

                    yojimbo.assert(messages[i] != null);

                    if (!messages[i].SerializeInternal(stream))
                    {
                        yojimbo.printf(yojimbo.LOG_LEVEL_ERROR, $"error: failed to serialize message type {messageTypes[i]} (SerializeUnorderedMessages)\n");
                        return false;
                    }

                    if (messages[i].IsBlockMessage)
                    {
                        var blockMessage = (BlockMessage)messages[i];
                        if (!SerializeMessageBlock(stream, messageFactory, blockMessage, maxBlockSize))
                        {
                            yojimbo.printf(yojimbo.LOG_LEVEL_ERROR, "error: failed to serialize message block (SerializeUnorderedMessages)\n");
                            return false;
                        }
                    }
                }
            }

            return true;
        }

        static bool SerializeBlockFragment(
            BaseStream stream,
            MessageFactory messageFactory,
            ChannelPacketData.BlockData block,
            ChannelConfig channelConfig)
        {
            var maxMessageType = messageFactory.NumTypes - 1;

            yojimbo.serialize_bits(stream, ref block.messageId, 16);

            if (channelConfig.MaxFragmentsPerBlock > 1)
                yojimbo.serialize_int(stream, ref block.numFragments, 1, channelConfig.MaxFragmentsPerBlock);
            else if (stream.IsReading)
                block.numFragments = 1;

            if (block.numFragments > 1)
                yojimbo.serialize_int(stream, ref block.fragmentId, 0, block.numFragments - 1);
            else if (stream.IsReading)
                block.fragmentId = 0;

            yojimbo.serialize_int(stream, ref block.fragmentSize, 1, channelConfig.blockFragmentSize);

            if (stream.IsReading)
            {
                block.fragmentData = new byte[block.fragmentSize];

                if (block.fragmentData == null)
                {
                    yojimbo.printf(yojimbo.LOG_LEVEL_ERROR, "error: failed to serialize block fragment (SerializeBlockFragment)\n");
                    return false;
                }
            }

            yojimbo.serialize_bytes(stream, block.fragmentData, block.fragmentSize);

            if (block.fragmentId == 0)
            {
                // block message

                if (maxMessageType > 0)
                    yojimbo.serialize_int(stream, ref block.messageType, 0, maxMessageType);
                else
                    block.messageType = 0;

                if (stream.IsReading)
                {
                    var message = messageFactory.CreateMessage(block.messageType);

                    if (message == null)
                    {
                        yojimbo.printf(yojimbo.LOG_LEVEL_ERROR, $"error: failed to create block message type {block.messageType} (SerializeBlockFragment)\n");
                        return false;
                    }

                    if (!message.IsBlockMessage)
                    {
                        yojimbo.printf(yojimbo.LOG_LEVEL_ERROR, "error: received block fragment attached to non-block message (SerializeBlockFragment)\n");
                        return false;
                    }

                    block.message = (BlockMessage)message;
                }

                yojimbo.assert(block.message != null);

                if (!block.message.SerializeInternal(stream))
                {
                    yojimbo.printf(yojimbo.LOG_LEVEL_ERROR, $"error: failed to serialize block message of type {block.messageType} (SerializeBlockFragment)\n");
                    return false;
                }
            }
            else if (stream.IsReading)
                block.message = null;

            return true;
        }

        public bool Serialize(BaseStream stream, MessageFactory messageFactory, ChannelConfig[] channelConfigs, int numChannels)
        {
            yojimbo.assert(initialized);

#if YOJIMBO_DEBUG_MESSAGE_BUDGET
            var startBits = stream.BitsProcessed;
#endif

            if (numChannels > 1)
                yojimbo.serialize_int(stream, ref channelIndex, 0, numChannels - 1);
            else
                channelIndex = 0;

            var channelConfig = channelConfigs[channelIndex];

            yojimbo.serialize_bool(stream, ref blockMessage);

            if (!blockMessage)
            {
                switch (channelConfig.type)
                {
                    case ChannelType.CHANNEL_TYPE_RELIABLE_ORDERED:
                        {
                            if (!SerializeOrderedMessages(stream, messageFactory, ref message.numMessages, ref message.messages, channelConfig.maxMessagesPerPacket))
                            {
                                messageFailedToSerialize = true;
                                return true;
                            }
                        }
                        break;

                    case ChannelType.CHANNEL_TYPE_UNRELIABLE_UNORDERED:
                        {
                            if (!SerializeUnorderedMessages(
                                stream,
                                messageFactory,
                                ref message.numMessages,
                                ref message.messages,
                                channelConfig.maxMessagesPerPacket,
                                channelConfig.maxBlockSize))
                            {
                                messageFailedToSerialize = true;
                                return true;
                            }
                        }
                        break;
                }

#if YOJIMBO_DEBUG_MESSAGE_BUDGET
                if (channelConfig.packetBudget > 0)
                    yojimbo.assert(stream.BitsProcessed - startBits <= channelConfig.packetBudget * 8);
#endif
            }
            else
            {
                if (channelConfig.disableBlocks)
                    return false;

                if (!SerializeBlockFragment(stream, messageFactory, block, channelConfig))
                    return false;
            }

            return true;
        }

        //public bool SerializeInternal(ReadStream stream, MessageFactory messageFactory, ChannelConfig[] channelConfigs, int numChannels) =>
        //    Serialize(stream, messageFactory, channelConfigs, numChannels);
        //public bool SerializeInternal(WriteStream stream, MessageFactory messageFactory, ChannelConfig[] channelConfigs, int numChannels) =>
        //    Serialize(stream, messageFactory, channelConfigs, numChannels);
        //public bool SerializeInternal(MeasureStream stream, MessageFactory messageFactory, ChannelConfig[] channelConfigs, int numChannels) =>
        //    Serialize(stream, messageFactory, channelConfigs, numChannels);
    }

    #endregion

    #region Channel

    /**
        Channel counters provide insight into the number of times an action was performed by a channel.
        They are intended for use in a telemetry system, eg. reported to some backend logging system to track behavior in a production environment.
     */
    public enum ChannelCounters
    {
        CHANNEL_COUNTER_MESSAGES_SENT,              ///< Number of messages sent over this channel.
        CHANNEL_COUNTER_MESSAGES_RECEIVED,          ///< Number of messages received over this channel.
        CHANNEL_COUNTER_NUM_COUNTERS                ///< The number of channel counters.
    }

    /**
        Channel error level.
        If the channel gets into an error state, it sets an error state on the corresponding connection. See yojimbo::CONNECTION_ERROR_CHANNEL.
        This way if any channel on a client/server connection gets into a bad state, that client is automatically kicked from the server.
        @see Client
        @see Server
        @see Connection
     */
    public enum ChannelErrorLevel
    {
        CHANNEL_ERROR_NONE = 0,                     ///< No error. All is well.
        CHANNEL_ERROR_DESYNC,                       ///< This channel has desynced. This means that the connection protocol has desynced and cannot recover. The client should be disconnected.
        CHANNEL_ERROR_SEND_QUEUE_FULL,              ///< The user tried to send a message but the send queue was full. This will assert out in development, but in production it sets this error on the channel.
        CHANNEL_ERROR_BLOCKS_DISABLED,              ///< The channel received a packet containing data for blocks, but this channel is configured to disable blocks. See ChannelConfig::disableBlocks.
        CHANNEL_ERROR_FAILED_TO_SERIALIZE,          ///< Serialize read failed for a message sent to this channel. Check your message serialize functions, one of them is returning false on serialize read. This can also be caused by a desync in message read and write.
        CHANNEL_ERROR_OUT_OF_MEMORY,                ///< The channel tried to allocate some memory but couldn't.
    }

    static partial class yojimbo
    {
        /// Helper function to convert a channel error to a user friendly string.
        public static string GetChannelErrorString(ChannelErrorLevel error)
        {
            switch (error)
            {
                case ChannelErrorLevel.CHANNEL_ERROR_NONE: return "none";
                case ChannelErrorLevel.CHANNEL_ERROR_DESYNC: return "desync";
                case ChannelErrorLevel.CHANNEL_ERROR_SEND_QUEUE_FULL: return "send queue full";
                case ChannelErrorLevel.CHANNEL_ERROR_OUT_OF_MEMORY: return "out of memory";
                case ChannelErrorLevel.CHANNEL_ERROR_BLOCKS_DISABLED: return "blocks disabled";
                case ChannelErrorLevel.CHANNEL_ERROR_FAILED_TO_SERIALIZE: return "failed to serialize";
                default: return "(unknown)";
            }
        }
    }

    /// Common functionality shared across all channel types.
    public abstract class Channel
    {
        /**
            Channel constructor.
         */
        public Channel(Allocator allocator, MessageFactory messageFactory, ChannelConfig config, int channelIndex, double time)
        {
            m_config = config;
            yojimbo.assert(channelIndex >= 0);
            yojimbo.assert(channelIndex < yojimbo.MaxChannels);
            m_channelIndex = channelIndex;
            m_allocator = allocator;
            m_messageFactory = messageFactory;
            m_errorLevel = ChannelErrorLevel.CHANNEL_ERROR_NONE;
            m_time = time;
            ResetCounters();
        }

        /**
            Channel destructor.
         */
        public virtual void Dispose() { }

        /**
            Reset the channel. 
         */
        public abstract void Reset();

        /**
            Returns true if a message can be sent over this channel.
         */
        public abstract bool CanSendMessage();

        /**
            Are there any messages in the send queue?
            @returns True if there is at least one message in the send queue.            
         */
        public abstract bool HasMessagesToSend();

        /**
            Queue a message to be sent across this channel.
            @param message The message to be sent.
         */
        public abstract void SendMessage(ref Message message, object context);

        /** 
            Pops the next message off the receive queue if one is available.
            @returns A pointer to the received message, null if there are no messages to receive. The caller owns the message object returned by this function and is responsible for releasing it via Message::Release.
         */
        public abstract Message ReceiveMessage();

        /**
            Advance channel time.
            Called by Connection::AdvanceTime for each channel configured on the connection.
         */
        public abstract void AdvanceTime(double time);

        /**
            Get channel packet data for this channel.
            @param packetData The channel packet data to be filled [out]
            @param packetSequence The sequence number of the packet being generated.
            @param availableBits The maximum number of bits of packet data the channel is allowed to write.
            @returns The number of bits of packet data written by the channel.
            @see ConnectionPacket
            @see Connection::GeneratePacket
         */
        public abstract int GetPacketData(object context, ChannelPacketData packetData, ushort packetSequence, int availableBits);

        /**
            Process packet data included in a connection packet.
            @param packetData The channel packet data to process.
            @param packetSequence The sequence number of the connection packet that contains the channel packet data.
            @see ConnectionPacket
            @see Connection::ProcessPacket
         */
        public abstract void ProcessPacketData(ChannelPacketData packetData, ushort packetSequence);

        /**
            Process a connection packet ack.
            Depending on the channel type: 
                1. Acks messages and block fragments so they stop being included in outgoing connection packets (reliable-ordered channel), 
                2. Does nothing at all (unreliable-unordered).
            @param sequence The sequence number of the connection packet that was acked.
         */
        public abstract void ProcessAck(ushort sequence);

        /**
            Get the channel error level.
            @returns The channel error level.
         */
        public ChannelErrorLevel ErrorLevel =>
            m_errorLevel;

        /** 
            Gets the channel index.
            @returns The channel index in [0,numChannels-1].
         */
        public int ChannelIndex =>
            m_channelIndex;

        /**
            Get a counter value.
            @param index The index of the counter to retrieve. See ChannelCounters.
            @returns The value of the counter.
            @see ResetCounters
         */
        public ulong GetCounter(int index)
        {
            yojimbo.assert(index >= 0);
            yojimbo.assert(index < (int)ChannelCounters.CHANNEL_COUNTER_NUM_COUNTERS);
            return m_counters[index];
        }

        /**
            Resets all counter values to zero.
         */
        public void ResetCounters() =>
            BufferEx.Set(m_counters, 0);

        /**
            Set the channel error level.
            All errors go through this function to make debug logging easier. 
         */
        protected void SetErrorLevel(ChannelErrorLevel errorLevel)
        {
            if (errorLevel != m_errorLevel && errorLevel != ChannelErrorLevel.CHANNEL_ERROR_NONE)
                yojimbo.printf(yojimbo.LOG_LEVEL_ERROR, $"channel went into error state: {yojimbo.GetChannelErrorString(errorLevel)}\n");
            m_errorLevel = errorLevel;
        }

        protected ChannelConfig m_config;                                               ///< Channel configuration data.
        protected Allocator m_allocator;                                                ///< Allocator for allocations matching life cycle of this channel.
        protected int m_channelIndex;                                                   ///< The channel index in [0,numChannels-1].
        protected double m_time;                                                        ///< The current time.
        protected ChannelErrorLevel m_errorLevel;                                       ///< The channel error level.
        protected MessageFactory m_messageFactory;                                      ///< Message factory for creating and destroying messages.
        protected ulong[] m_counters = new ulong[(int)ChannelCounters.CHANNEL_COUNTER_NUM_COUNTERS]; ///< Counters for unit testing, stats etc.
    }

    #endregion

    #region ReliableOrderedChannel

    /**
        Messages sent across this channel are guaranteed to arrive in the order they were sent.
        This channel type is best used for control messages and RPCs.
        Messages sent over this channel are included in connection packets until one of those packets is acked. Messages are acked individually and remain in the send queue until acked.
        Blocks attached to messages sent over this channel are split up into fragments. Each fragment of the block is included in a connection packet until one of those packets are acked. Eventually, all fragments are received on the other side, and block is reassembled and attached to the message.
        Only one message block may be in flight over the network at any time, so blocks stall out message delivery slightly. Therefore, only use blocks for large data that won't fit inside a single connection packet where you actually need the channel to split it up into fragments. If your block fits inside a packet, just serialize it inside your message serialize via serialize_bytes instead.
     */
    public class ReliableOrderedChannel : Channel
    {
        /** 
            Reliable ordered channel constructor.
            @param allocator The allocator to use.
            @param messageFactory Message factory for creating and destroying messages.
            @param config The configuration for this channel.
            @param channelIndex The channel index in [0,numChannels-1].
         */
        public ReliableOrderedChannel(Allocator allocator, MessageFactory messageFactory, ChannelConfig config, int channelIndex, double time)
            : base(allocator, messageFactory, config, channelIndex, time)
        {
            yojimbo.assert(config.type == ChannelType.CHANNEL_TYPE_RELIABLE_ORDERED);

            yojimbo.assert((65536 % config.sentPacketBufferSize) == 0);
            yojimbo.assert((65536 % config.messageSendQueueSize) == 0);
            yojimbo.assert((65536 % config.messageReceiveQueueSize) == 0);

            m_sentPackets = new SequenceBuffer<SentPacketEntry>(m_allocator, m_config.sentPacketBufferSize);
            m_messageSendQueue = new SequenceBuffer<MessageSendQueueEntry>(m_allocator, m_config.messageSendQueueSize);
            m_messageReceiveQueue = new SequenceBuffer<MessageReceiveQueueEntry>(m_allocator, m_config.messageReceiveQueueSize);
            m_sentPacketMessageIds = BufferEx.NewT<ushort>(m_config.sentPacketBufferSize, m_config.maxMessagesPerPacket);

            if (!config.disableBlocks)
            {
                m_sendBlock = new SendBlockData(m_allocator, m_config.MaxFragmentsPerBlock);
                m_receiveBlock = new ReceiveBlockData(m_allocator, m_config.maxBlockSize, m_config.MaxFragmentsPerBlock);
            }
            else
            {
                m_sendBlock = null;
                m_receiveBlock = null;
            }

            Reset();
        }

        /**
            Reliable ordered channel destructor.
            Any messages still in the send or receive queues will be released.
         */
        public override void Dispose()
        {
            Reset();

            m_sendBlock?.Dispose(); m_sendBlock = null;
            m_receiveBlock?.Dispose(); m_receiveBlock = null;
            m_sentPackets?.Dispose(); m_sentPackets = null;
            m_messageSendQueue?.Dispose(); m_messageSendQueue = null;
            m_messageReceiveQueue?.Dispose(); m_messageReceiveQueue = null;

            m_sentPacketMessageIds = null;
        }

        public override void Reset()
        {
            SetErrorLevel(ChannelErrorLevel.CHANNEL_ERROR_NONE);

            m_sendMessageId = 0;
            m_receiveMessageId = 0;
            m_oldestUnackedMessageId = 0;

            for (var i = 0; i < m_messageSendQueue.GetSize(); ++i)
            {
                var entry = m_messageSendQueue.GetAtIndex(i);
                if (entry != null && entry.message != null)
                    m_messageFactory.ReleaseMessage(ref entry.message);
            }

            for (var i = 0; i < m_messageReceiveQueue.GetSize(); ++i)
            {
                var entry = m_messageReceiveQueue.GetAtIndex(i);
                if (entry != null && entry.message != null)
                    m_messageFactory.ReleaseMessage(ref entry.message);
            }

            m_sentPackets.Reset();
            m_messageSendQueue.Reset();
            m_messageReceiveQueue.Reset();

            if (m_sendBlock != null)
                m_sendBlock.Reset();

            if (m_receiveBlock != null)
            {
                m_receiveBlock.Reset();
                if (m_receiveBlock.blockMessage != null)
                    m_messageFactory.ReleaseMessage(ref m_receiveBlock.blockMessage);
            }

            ResetCounters();
        }

        public override bool CanSendMessage()
        {
            yojimbo.assert(m_messageSendQueue != null);
            return m_messageSendQueue.Available(m_sendMessageId);
        }

        public override void SendMessage(ref Message message, object context)
        {
            yojimbo.assert(message != null);

            yojimbo.assert(CanSendMessage());

            if (ErrorLevel != ChannelErrorLevel.CHANNEL_ERROR_NONE)
            {
                m_messageFactory.ReleaseMessage(ref message);
                return;
            }

            if (!CanSendMessage())
            {
                // Increase your send queue size!
                SetErrorLevel(ChannelErrorLevel.CHANNEL_ERROR_SEND_QUEUE_FULL);
                m_messageFactory.ReleaseMessage(ref message);
                return;
            }

            yojimbo.assert(!(message.IsBlockMessage && m_config.disableBlocks));

            if (message.IsBlockMessage && m_config.disableBlocks)
            {
                // You tried to send a block message, but block messages are disabled for this channel!
                SetErrorLevel(ChannelErrorLevel.CHANNEL_ERROR_BLOCKS_DISABLED);
                m_messageFactory.ReleaseMessage(ref message);
                return;
            }

            message.Id = m_sendMessageId;

            var entry = m_messageSendQueue.Insert(m_sendMessageId);

            yojimbo.assert(entry != null);

            entry.block = message.IsBlockMessage;
            entry.message = message;
            entry.measuredBits = 0;
            entry.timeLastSent = -1.0;

            if (message.IsBlockMessage)
            {
                yojimbo.assert(((BlockMessage)message).BlockSize > 0);
                yojimbo.assert(((BlockMessage)message).BlockSize <= m_config.maxBlockSize);
            }

            var measureStream = new MeasureStream(m_messageFactory.Allocator);
            measureStream.Context = context;
            message.SerializeInternal(measureStream);
            entry.measuredBits = (uint)measureStream.BitsProcessed;
            m_counters[(int)ChannelCounters.CHANNEL_COUNTER_MESSAGES_SENT]++;
            m_sendMessageId++;
        }

        public override Message ReceiveMessage()
        {
            if (ErrorLevel != ChannelErrorLevel.CHANNEL_ERROR_NONE)
                return null;

            var entry = m_messageReceiveQueue.Find(m_receiveMessageId);
            if (entry == null)
                return null;

            var message = entry.message;
            yojimbo.assert(message != null);
            yojimbo.assert(message.Id == m_receiveMessageId);
            m_messageReceiveQueue.Remove(m_receiveMessageId);
            m_counters[(int)ChannelCounters.CHANNEL_COUNTER_MESSAGES_RECEIVED]++;
            m_receiveMessageId++;

            return message;
        }

        public override void AdvanceTime(double time) =>
            m_time = time;

        public override int GetPacketData(object context, ChannelPacketData packetData, ushort packetSequence, int availableBits)
        {
            if (!HasMessagesToSend())
                return 0;

            if (SendingBlockMessage())
            {
                if (m_config.blockFragmentSize * 8 > availableBits)
                    return 0;

                var fragmentData = GetFragmentToSend(out var messageId, out var fragmentId, out var fragmentBytes, out var numFragments, out var messageType);

                if (fragmentData != null)
                {
                    var fragmentBits = GetFragmentPacketData(packetData, messageId, fragmentId, fragmentData, fragmentBytes, numFragments, messageType);
                    AddFragmentPacketEntry(messageId, fragmentId, packetSequence);
                    return fragmentBits;
                }
            }
            else
            {
                var messageIds = new ushort[m_config.maxMessagesPerPacket];
                var messageBits = GetMessagesToSend(messageIds, out var numMessageIds, availableBits, context);

                if (numMessageIds > 0)
                {
                    GetMessagePacketData(packetData, messageIds, numMessageIds);
                    AddMessagePacketEntry(messageIds, numMessageIds, packetSequence);
                    return messageBits;
                }
            }

            return 0;
        }

        public override void ProcessPacketData(ChannelPacketData packetData, ushort packetSequence)
        {
            if (m_errorLevel != ChannelErrorLevel.CHANNEL_ERROR_NONE)
                return;

            if (packetData.messageFailedToSerialize)
            {
                // A message failed to serialize read for some reason, eg. mismatched read/write.
                SetErrorLevel(ChannelErrorLevel.CHANNEL_ERROR_FAILED_TO_SERIALIZE);
                return;
            }

            if (packetData.blockMessage)
                ProcessPacketFragment(
                    packetData.block.messageType,
                    packetData.block.messageId,
                    packetData.block.numFragments,
                    packetData.block.fragmentId,
                    packetData.block.fragmentData,
                    packetData.block.fragmentSize,
                    packetData.block.message);
            else
                ProcessPacketMessages(packetData.message.numMessages, packetData.message.messages);
        }

        public override void ProcessAck(ushort ack)
        {
            var sentPacketEntry = m_sentPackets.Find(ack);
            if (sentPacketEntry == null)
                return;

            yojimbo.assert(!sentPacketEntry.acked);

            for (var i = 0; i < sentPacketEntry.numMessageIds; ++i)
            {
                var messageId = sentPacketEntry.messageIds[i];
                var sendQueueEntry = m_messageSendQueue.Find(messageId);
                if (sendQueueEntry != null)
                {
                    yojimbo.assert(sendQueueEntry.message != null);
                    yojimbo.assert(sendQueueEntry.message.Id == messageId);
                    m_messageFactory.ReleaseMessage(ref sendQueueEntry.message);
                    m_messageSendQueue.Remove(messageId);
                    UpdateOldestUnackedMessageId();
                }
            }

            if (!m_config.disableBlocks && sentPacketEntry.block && m_sendBlock.active && m_sendBlock.blockMessageId == sentPacketEntry.blockMessageId)
            {
                var messageId = sentPacketEntry.blockMessageId;
                var fragmentId = sentPacketEntry.blockFragmentId;

                if (m_sendBlock.ackedFragment.GetBit(fragmentId) == 0)
                {
                    m_sendBlock.ackedFragment.SetBit(fragmentId);
                    m_sendBlock.numAckedFragments++;
                    if (m_sendBlock.numAckedFragments == m_sendBlock.numFragments)
                    {
                        m_sendBlock.active = false;
                        var sendQueueEntry = m_messageSendQueue.Find(messageId);
                        yojimbo.assert(sendQueueEntry != null);
                        m_messageFactory.ReleaseMessage(ref sendQueueEntry.message);
                        m_messageSendQueue.Remove(messageId);
                        UpdateOldestUnackedMessageId();
                    }
                }
            }
        }

        /**
            Are there any unacked messages in the send queue?
            Messages are acked individually and remain in the send queue until acked.
            @returns True if there is at least one unacked message in the send queue.            
         */
        public override bool HasMessagesToSend() =>
            m_oldestUnackedMessageId != m_sendMessageId;

        /**
            Get messages to include in a packet.
            Messages are measured to see how many bits they take, and only messages that fit within the channel packet budget will be included. See ChannelConfig::packetBudget.
            Takes care not to send messages too rapidly by respecting ChannelConfig::messageResendTime for each message, and to only include messages that that the receiver is able to buffer in their receive queue. In other words, won't run ahead of the receiver.
            @param messageIds Array of message ids to be filled [out]. Fills up to ChannelConfig::maxMessagesPerPacket messages, make sure your array is at least this size.
            @param numMessageIds The number of message ids written to the array.
            @param remainingPacketBits Number of bits remaining in the packet. Considers this as a hard limit when determining how many messages can fit into the packet.
            @returns Estimate of the number of bits required to serialize the messages (upper bound).
            @see GetMessagePacketData
         */
        public int GetMessagesToSend(ushort[] messageIds, out int numMessageIds, int availableBits, object context)
        {
            yojimbo.assert(HasMessagesToSend());

            numMessageIds = 0;

            if (m_config.packetBudget > 0)
                availableBits = Math.Min(m_config.packetBudget * 8, availableBits);

            var giveUpBits = 4 * 8;
            var messageTypeBits = yojimbo.bits_required(0, (uint)(m_messageFactory.NumTypes - 1));
            var messageLimit = Math.Min(m_config.messageSendQueueSize, m_config.messageReceiveQueueSize);
            ushort previousMessageId = 0;
            var usedBits = yojimbo.ConservativeMessageHeaderBits;
            var giveUpCounter = 0;

            for (var i = 0; i < messageLimit; ++i)
            {
                if (availableBits - usedBits < giveUpBits)
                    break;

                if (giveUpCounter > m_config.messageSendQueueSize)
                    break;

                var messageId = (ushort)(m_oldestUnackedMessageId + i);
                var entry = m_messageSendQueue.Find(messageId);
                if (entry == null)
                    continue;

                if (entry.block)
                    break;

                if (entry.timeLastSent + m_config.messageResendTime <= m_time && availableBits >= (int)entry.measuredBits)
                {
                    var messageBits = (int)(entry.measuredBits + messageTypeBits);

                    if (numMessageIds == 0)
                        messageBits += 16;
                    else
                    {
                        var stream = new MeasureStream(yojimbo.DefaultAllocator);
                        stream.Context = context;
                        yojimbo.serialize_sequence_relative(stream, previousMessageId, ref messageId);
                        messageBits += stream.BitsProcessed;
                    }

                    if (usedBits + messageBits > availableBits)
                    {
                        giveUpCounter++;
                        continue;
                    }

                    usedBits += messageBits;
                    messageIds[numMessageIds++] = messageId;
                    previousMessageId = messageId;
                    entry.timeLastSent = m_time;
                }

                if (numMessageIds == m_config.maxMessagesPerPacket)
                    break;
            }

            return usedBits;
        }

        /**
            Fill channel packet data with messages.
            This is the payload function to fill packet data while sending regular messages (without blocks attached).
            Messages have references added to them when they are added to the packet. They also have a reference while they are stored in a send or receive queue. Messages are cleaned up when they are no longer in a queue, and no longer referenced by any packets.
            @param packetData The packet data to fill [out]
            @param messageIds Array of message ids identifying which messages to add to the packet from the message send queue.
            @param numMessageIds The number of message ids in the array.
            @see GetMessagesToSend
         */
        public void GetMessagePacketData(ChannelPacketData packetData, ushort[] messageIds, int numMessageIds)
        {
            yojimbo.assert(messageIds != null);

            packetData.Initialize();
            packetData.channelIndex = (ushort)ChannelIndex;
            packetData.message.numMessages = numMessageIds;

            if (numMessageIds == 0)
                return;

            packetData.message.messages = new Message[numMessageIds];

            for (var i = 0; i < numMessageIds; ++i)
            {
                var entry = m_messageSendQueue.Find(messageIds[i]);
                yojimbo.assert(entry != null);
                yojimbo.assert(entry.message != null);
                yojimbo.assert(entry.message.RefCount > 0);
                packetData.message.messages[i] = entry.message;
                m_messageFactory.AcquireMessage(packetData.message.messages[i]);
            }
        }

        /**
            Add a packet entry for the set of messages included in a packet.
            This lets us look up the set of messages that were included in that packet later on when it is acked, so we can ack those messages individually.
            @param messageIds The set of message ids that were included in the packet.
            @param numMessageIds The number of message ids in the array.
            @param sequence The sequence number of the connection packet the messages were included in.
         */
        public void AddMessagePacketEntry(ushort[] messageIds, int numMessageIds, ushort sequence)
        {
            var sentPacket = m_sentPackets.Insert(sequence);
            yojimbo.assert(sentPacket != null);
            if (sentPacket != null)
            {
                sentPacket.acked = false;
                sentPacket.block = false;
                sentPacket.timeSent = m_time;
                sentPacket.messageIds = m_sentPacketMessageIds[(sequence % m_config.sentPacketBufferSize)]; //: m_config.maxMessagesPerPacket
                sentPacket.numMessageIds = (ushort)numMessageIds;
                for (var i = 0; i < numMessageIds; ++i)
                    sentPacket.messageIds[i] = messageIds[i];
            }
        }

        /**
            Process messages included in a packet.
            Any messages that have not already been received are added to the message receive queue. Messages that are added to the receive queue have a reference added. See Message::AddRef.
            @param numMessages The number of messages to process.
            @param messages Array of pointers to messages.
         */
        public void ProcessPacketMessages(int numMessages, Message[] messages)
        {
            var minMessageId = m_receiveMessageId;
            var maxMessageId = (ushort)(m_receiveMessageId + m_config.messageReceiveQueueSize - 1);

            for (var i = 0; i < numMessages; ++i)
            {
                var message = messages[i];

                yojimbo.assert(message != null);

                var messageId = message.Id;

                if (yojimbo.sequence_less_than(messageId, minMessageId))
                    continue;

                if (yojimbo.sequence_greater_than(messageId, maxMessageId))
                {
                    // Did you forget to dequeue messages on the receiver?
                    SetErrorLevel(ChannelErrorLevel.CHANNEL_ERROR_DESYNC);
                    return;
                }

                if (m_messageReceiveQueue.Find(messageId) != null)
                    continue;

                yojimbo.assert(m_messageReceiveQueue.GetAtIndex(m_messageReceiveQueue.GetIndex(messageId)) == null);

                var entry = m_messageReceiveQueue.Insert(messageId);
                if (entry == null)
                {
                    // For some reason we can't insert the message in the receive queue
                    SetErrorLevel(ChannelErrorLevel.CHANNEL_ERROR_DESYNC);
                    return;
                }

                entry.message = message;

                m_messageFactory.AcquireMessage(message);
            }
        }

        /**
            Track the oldest unacked message id in the send queue.
            Because messages are acked individually, the send queue is not a true queue and may have holes. 
            Because of this it is necessary to periodically walk forward from the previous oldest unacked message id, to find the current oldest unacked message id. 
            This lets us know our starting point for considering messages to include in the next packet we send.
            @see GetMessagesToSend
         */
        public void UpdateOldestUnackedMessageId()
        {
            var stopMessageId = m_messageSendQueue.GetSequence();

            while (true)
            {
                if (m_oldestUnackedMessageId == stopMessageId || m_messageSendQueue.Find(m_oldestUnackedMessageId) != null)
                    break;
                ++m_oldestUnackedMessageId;
            }

            yojimbo.assert(!yojimbo.sequence_greater_than(m_oldestUnackedMessageId, stopMessageId));
        }

        /**
            True if we are currently sending a block message.
            Block messages are treated differently to regular messages. 
            Regular messages are small so we try to fit as many into the packet we can. See ReliableChannelData::GetMessagesToSend.
            Blocks attached to block messages are usually larger than the maximum packet size or channel budget, so they are split up fragments. 
            While in the mode of sending a block message, each channel packet data generated has exactly one fragment from the current block in it. Fragments keep getting included in packets until all fragments of that block are acked.
            @returns True if currently sending a block message over the network, false otherwise.
            @see BlockMessage
            @see GetFragmentToSend
         */
        public bool SendingBlockMessage()
        {
            yojimbo.assert(HasMessagesToSend());

            var entry = m_messageSendQueue.Find(m_oldestUnackedMessageId);

            return entry != null ? entry.block : false;
        }

        /**
            Get the next block fragment to send.
            The next block fragment is selected by scanning left to right over the set of fragments in the block, skipping over any fragments that have already been acked or have been sent within ChannelConfig::fragmentResendTime.
            @param messageId The id of the message that the block is attached to [out].
            @param fragmentId The id of the fragment to send [out].
            @param fragmentBytes The size of the fragment in bytes.
            @param numFragments The total number of fragments in this block.
            @param messageType The type of message the block is attached to. See MessageFactory.
            @returns Pointer to the fragment data.
         */
        public byte[] GetFragmentToSend(out ushort messageId, out ushort fragmentId, out int fragmentBytes, out int numFragments, out int messageType)
        {
            messageId = fragmentId = 0;
            fragmentBytes = numFragments = messageType = 0;

            var entry = m_messageSendQueue.Find(m_oldestUnackedMessageId);

            yojimbo.assert(entry != null);
            yojimbo.assert(entry.block);

            var blockMessage = (BlockMessage)entry.message;

            yojimbo.assert(blockMessage != null);

            messageId = blockMessage.Id;

            var blockSize = blockMessage.BlockSize;

            if (!m_sendBlock.active)
            {
                // start sending this block

                m_sendBlock.active = true;
                m_sendBlock.blockSize = blockSize;
                m_sendBlock.blockMessageId = messageId;
                m_sendBlock.numFragments = (int)Math.Ceiling(blockSize / (float)m_config.blockFragmentSize);
                m_sendBlock.numAckedFragments = 0;

                var MaxFragmentsPerBlock = m_config.MaxFragmentsPerBlock;

                yojimbo.assert(m_sendBlock.numFragments > 0);
                yojimbo.assert(m_sendBlock.numFragments <= MaxFragmentsPerBlock);

                m_sendBlock.ackedFragment.Clear();

                for (var i = 0; i < MaxFragmentsPerBlock; ++i)
                    m_sendBlock.fragmentSendTime[i] = -1.0;
            }

            numFragments = m_sendBlock.numFragments;

            // find the next fragment to send (there may not be one)

            fragmentId = 0xFFFF;

            for (var i = 0; i < m_sendBlock.numFragments; ++i)
                if (m_sendBlock.ackedFragment.GetBit(i) == 0 && m_sendBlock.fragmentSendTime[i] + m_config.blockFragmentResendTime < m_time)
                {
                    fragmentId = (ushort)i;
                    break;
                }

            if (fragmentId == 0xFFFF)
                return null;

            // allocate and return a copy of the fragment data

            messageType = blockMessage.Type;

            fragmentBytes = m_config.blockFragmentSize;

            var fragmentRemainder = blockSize % m_config.blockFragmentSize;

            if (fragmentRemainder != 0 && fragmentId == m_sendBlock.numFragments - 1)
                fragmentBytes = fragmentRemainder;

            var fragmentData = new byte[fragmentBytes];

            if (fragmentData != null)
            {
                BufferEx.Copy(fragmentData, 0, blockMessage.BlockData, fragmentId * m_config.blockFragmentSize, fragmentBytes);

                m_sendBlock.fragmentSendTime[fragmentId] = m_time;
            }

            return fragmentData;
        }

        /**
            Fill the packet data with block and fragment data.
            This is the payload function that fills the channel packet data while we are sending a block message.
            @param packetData The packet data to fill [out]
            @param messageId The id of the message that the block is attached to.
            @param fragmentId The id of the block fragment being sent.
            @param fragmentData The fragment data.
            @param fragmentSize The size of the fragment data (bytes).
            @param numFragments The number of fragments in the block.
            @param messageType The type of message the block is attached to.
            @returns An estimate of the number of bits required to serialize the block message and fragment data (upper bound).
         */
        public int GetFragmentPacketData(
            ChannelPacketData packetData,
            ushort messageId,
            ushort fragmentId,
            byte[] fragmentData,
            int fragmentSize,
            int numFragments,
            int messageType)
        {
            packetData.Initialize();

            packetData.channelIndex = (ushort)ChannelIndex;

            packetData.blockMessage = true;

            packetData.block.fragmentData = fragmentData;
            packetData.block.messageId = messageId;
            packetData.block.fragmentId = fragmentId;
            packetData.block.fragmentSize = (ushort)fragmentSize;
            packetData.block.numFragments = (ushort)numFragments;
            packetData.block.messageType = messageType;

            var messageTypeBits = yojimbo.bits_required(0, (uint)(m_messageFactory.NumTypes - 1));

            var fragmentBits = yojimbo.ConservativeFragmentHeaderBits + fragmentSize * 8;

            if (fragmentId == 0)
            {
                var entry = m_messageSendQueue.Find(packetData.block.messageId);

                yojimbo.assert(entry != null);
                yojimbo.assert(entry.message != null);

                packetData.block.message = (BlockMessage)entry.message;

                m_messageFactory.AcquireMessage(packetData.block.message);

                fragmentBits += (int)(entry.measuredBits + messageTypeBits);
            }
            else
                packetData.block.message = null;

            return fragmentBits;
        }

        /**
            Adds a packet entry for the fragment.
            This lets us look up the fragment that was in the packet later on when it is acked, so we can ack that block fragment.
            @param messageId The message id that the block was attached to.
            @param fragmentId The fragment id.
            @param sequence The sequence number of the packet the fragment was included in.
         */
        public void AddFragmentPacketEntry(ushort messageId, ushort fragmentId, ushort sequence)
        {
            var sentPacket = m_sentPackets.Insert(sequence);
            yojimbo.assert(sentPacket != null);
            if (sentPacket != null)
            {
                sentPacket.numMessageIds = 0;
                sentPacket.messageIds = null;
                sentPacket.timeSent = m_time;
                sentPacket.acked = false;
                sentPacket.block = true;
                sentPacket.blockMessageId = messageId;
                sentPacket.blockFragmentId = fragmentId;
            }
        }

        /**
            Process a packet fragment.
            The fragment is added to the set of received fragments for the block. When all packet fragments are received, that block is reconstructed, attached to the block message and added to the message receive queue.
            @param messageType The type of the message this block fragment is attached to. This is used to make sure this message type actually allows blocks to be attached to it.
            @param messageId The id of the message the block fragment belongs to.
            @param numFragments The number of fragments in the block.
            @param fragmentId The id of the fragment in [0,numFragments-1].
            @param fragmentData The fragment data.
            @param fragmentBytes The size of the fragment data in bytes.
            @param blockMessage Pointer to the block message. Passed this in only with the first fragment (0), pass null for all other fragments.
         */
        public void ProcessPacketFragment(
            int messageType,
            ushort messageId,
            int numFragments,
            ushort fragmentId,
            byte[] fragmentData,
            int fragmentBytes,
            BlockMessage blockMessage)
        {
            yojimbo.assert(!m_config.disableBlocks);

            if (fragmentData != null)
            {
                var expectedMessageId = m_messageReceiveQueue.GetSequence();
                if (messageId != expectedMessageId)
                    return;

                // start receiving a new block

                if (!m_receiveBlock.active)
                {
                    yojimbo.assert(numFragments >= 0);
                    yojimbo.assert(numFragments <= m_config.MaxFragmentsPerBlock);

                    m_receiveBlock.active = true;
                    m_receiveBlock.numFragments = numFragments;
                    m_receiveBlock.numReceivedFragments = 0;
                    m_receiveBlock.messageId = messageId;
                    m_receiveBlock.blockSize = 0;
                    m_receiveBlock.receivedFragment.Clear();
                }

                // validate fragment

                if (fragmentId >= m_receiveBlock.numFragments)
                {
                    // The fragment id is out of range.
                    SetErrorLevel(ChannelErrorLevel.CHANNEL_ERROR_DESYNC);
                    return;
                }

                if (numFragments != m_receiveBlock.numFragments)
                {
                    // The number of fragments is out of range.
                    SetErrorLevel(ChannelErrorLevel.CHANNEL_ERROR_DESYNC);
                    return;
                }

                // receive the fragment

                if (m_receiveBlock.receivedFragment.GetBit(fragmentId) == 0)
                {
                    m_receiveBlock.receivedFragment.SetBit(fragmentId);

                    BufferEx.Copy(m_receiveBlock.blockData, fragmentId * m_config.blockFragmentSize, fragmentData, 0, fragmentBytes);

                    if (fragmentId == 0)
                        m_receiveBlock.messageType = messageType;

                    if (fragmentId == m_receiveBlock.numFragments - 1)
                    {
                        m_receiveBlock.blockSize = (uint)((m_receiveBlock.numFragments - 1) * m_config.blockFragmentSize + fragmentBytes);

                        if (m_receiveBlock.blockSize > (uint)m_config.maxBlockSize)
                        {
                            // The block size is outside range
                            SetErrorLevel(ChannelErrorLevel.CHANNEL_ERROR_DESYNC);
                            return;
                        }
                    }

                    m_receiveBlock.numReceivedFragments++;

                    if (fragmentId == 0)
                    {
                        // save block message (sent with fragment 0)
                        m_receiveBlock.blockMessage = blockMessage;
                        m_messageFactory.AcquireMessage(m_receiveBlock.blockMessage);
                    }

                    if (m_receiveBlock.numReceivedFragments == m_receiveBlock.numFragments)
                    {
                        // finished receiving block

                        if (m_messageReceiveQueue.GetAtIndex(m_messageReceiveQueue.GetIndex(messageId)) != null)
                        {
                            // Did you forget to dequeue messages on the receiver?
                            SetErrorLevel(ChannelErrorLevel.CHANNEL_ERROR_DESYNC);
                            return;
                        }

                        blockMessage = m_receiveBlock.blockMessage;

                        yojimbo.assert(blockMessage != null);

                        var blockData = new byte[m_receiveBlock.blockSize];

                        if (blockData == null)
                        {
                            // Not enough memory to allocate block data
                            SetErrorLevel(ChannelErrorLevel.CHANNEL_ERROR_OUT_OF_MEMORY);
                            return;
                        }

                        BufferEx.Copy(blockData, m_receiveBlock.blockData, (int)m_receiveBlock.blockSize);

                        blockMessage.AttachBlock(m_messageFactory.Allocator, blockData, (int)m_receiveBlock.blockSize);

                        blockMessage.Id = messageId;

                        var entry = m_messageReceiveQueue.Insert(messageId);
                        yojimbo.assert(entry != null);
                        entry.message = blockMessage;
                        m_receiveBlock.active = false;
                        m_receiveBlock.blockMessage = null;
                    }
                }
            }
        }

        /**
            An entry in the send queue of the reliable-ordered channel.
            Messages stay into the send queue until acked. Each message is acked individually, so there can be "holes" in the message send queue.
         */
        protected class MessageSendQueueEntry
        {
            public Message message;                                                     ///< Pointer to the message. When inserted in the send queue the message has one reference. It is released when the message is acked and removed from the send queue.
            public double timeLastSent;                                                 ///< The time the message was last sent. Used to implement ChannelConfig::messageResendTime.
            public uint measuredBits;                                                   ///< The number of bits the message takes up in a bit stream.
            public bool block;                                                          ///< 1 if this is a block message. Block messages are treated differently to regular messages when sent over a reliable-ordered channel.
        }

        /**
            An entry in the receive queue of the reliable-ordered channel.
         */
        protected class MessageReceiveQueueEntry
        {
            public Message message;                                                     ///< The message pointer. Has at a reference count of at least 1 while in the receive queue. Ownership of the message is passed back to the caller when the message is dequeued.
        }

        /**
            Maps packet level acks to messages and fragments for the reliable-ordered channel.
         */
        protected class SentPacketEntry
        {
            public double timeSent;                                                     ///< The time the packet was sent. Used to estimate round trip time.
            public ushort[] messageIds;                                                 ///< Pointer to an array of message ids. Dynamically allocated because the user can configure the maximum number of messages in a packet per-channel with ChannelConfig::maxMessagesPerPacket.
            public ushort numMessageIds;                                                ///< The number of message ids in in the array.
            public bool acked;                                                          ///< 1 if this packet has been acked.
            public bool block;                                                          ///< 1 if this packet contains a fragment of a block message.
            public ushort blockMessageId;                                               ///< The block message id. Valid only if "block" is 1.
            public ushort blockFragmentId;                                              ///< The block fragment id. Valid only if "block" is 1.
        }

        /**
            Internal state for a block being sent across the reliable ordered channel.
            Stores the block data and tracks which fragments have been acked. The block send completes when all fragments have been acked.
            IMPORTANT: Although there can be multiple block messages in the message send and receive queues, only one data block can be in flights over the wire at a time.
         */
        protected class SendBlockData
        {
            public SendBlockData(Allocator allocator, int maxFragmentsPerBlock)
            {
                m_allocator = allocator;
                ackedFragment = new BitArray(allocator, maxFragmentsPerBlock);
                fragmentSendTime = new double[maxFragmentsPerBlock];
                yojimbo.assert(ackedFragment != null);
                yojimbo.assert(fragmentSendTime != null);
                Reset();
            }

            public void Dispose()
            {
                ackedFragment?.Dispose(); ackedFragment = null;
                fragmentSendTime = null;
            }

            public void Reset()
            {
                active = false;
                numFragments = 0;
                numAckedFragments = 0;
                blockMessageId = 0;
                blockSize = 0;
            }

            public bool active;                                                         ///< True if we are currently sending a block.
            public int blockSize;                                                       ///< The size of the block (bytes).
            public int numFragments;                                                    ///< Number of fragments in the block being sent.
            public int numAckedFragments;                                               ///< Number of acked fragments in the block being sent.
            public ushort blockMessageId;                                               ///< The message id the block is attached to.
            public BitArray ackedFragment;                                              ///< Has fragment n been received?
            public double[] fragmentSendTime;                                           ///< Last time fragment was sent.

            Allocator m_allocator;                                                      ///< Allocator used to create the block data.
        }

        /**
            Internal state for a block being received across the reliable ordered channel.
            Stores the fragments received over the network for the block, and completes once all fragments have been received.
            IMPORTANT: Although there can be multiple block messages in the message send and receive queues, only one data block can be in flights over the wire at a time.
         */
        protected class ReceiveBlockData
        {
            public ReceiveBlockData(Allocator allocator, int maxBlockSize, int maxFragmentsPerBlock)
            {
                m_allocator = allocator;
                receivedFragment = new BitArray(allocator, maxFragmentsPerBlock);
                blockData = new byte[maxBlockSize];
                yojimbo.assert(receivedFragment != null && blockData != null);
                blockMessage = null;
                Reset();
            }

            public void Dispose()
            {
                receivedFragment?.Dispose(); receivedFragment = null;
                blockData = null;
            }

            public void Reset()
            {
                active = false;
                numFragments = 0;
                numReceivedFragments = 0;
                messageId = 0;
                messageType = 0;
                blockSize = 0;
            }

            public bool active;                                                         ///< True if we are currently receiving a block.
            public int numFragments;                                                    ///< The number of fragments in this block
            public int numReceivedFragments;                                            ///< The number of fragments received.
            public ushort messageId;                                                    ///< The message id corresponding to the block.
            public int messageType;                                                     ///< Message type of the block being received.
            public uint blockSize;                                                      ///< Block size in bytes.
            public BitArray receivedFragment;                                           ///< Has fragment n been received?
            public byte[] blockData;                                                    ///< Block data for receive.
            public BlockMessage blockMessage;                                           ///< Block message (sent with fragment 0).

            Allocator m_allocator;                                                      ///< Allocator used to free the data on shutdown.
        }

        ushort m_sendMessageId;                                                         ///< Id of the next message to be added to the send queue.
        ushort m_receiveMessageId;                                                      ///< Id of the next message to be added to the receive queue.
        ushort m_oldestUnackedMessageId;                                                ///< Id of the oldest unacked message in the send queue.
        SequenceBuffer<SentPacketEntry> m_sentPackets;                                  ///< Stores information per sent connection packet about messages and block data included in each packet. Used to walk from connection packet level acks to message and data block fragment level acks.
        SequenceBuffer<MessageSendQueueEntry> m_messageSendQueue;                       ///< Message send queue.
        SequenceBuffer<MessageReceiveQueueEntry> m_messageReceiveQueue;                 ///< Message receive queue.
        ushort[][] m_sentPacketMessageIds;                                              ///< Array of n message ids per sent connection packet. Allows the maximum number of messages per-packet to be allocated dynamically.
        SendBlockData m_sendBlock;                                                      ///< Data about the block being currently sent.
        ReceiveBlockData m_receiveBlock;                                                ///< Data about the block being currently received.
    }

    #endregion

    #region UnreliableUnorderedChannel

    /**
        Messages sent across this channel are not guaranteed to arrive, and may be received in a different order than they were sent.
        This channel type is best used for time critical data like snapshots and object state.
     */
    public class UnreliableUnorderedChannel : Channel
    {
        /** 
            Reliable ordered channel constructor.
            @param allocator The allocator to use.
            @param messageFactory Message factory for creating and destroying messages.
            @param config The configuration for this channel.
            @param channelIndex The channel index in [0,numChannels-1].
         */
        public UnreliableUnorderedChannel(
                Allocator allocator,
                MessageFactory messageFactory,
                ChannelConfig config,
                int channelIndex,
                double time)
        : base(allocator, messageFactory, config, channelIndex, time)
        {
            yojimbo.assert(config.type == ChannelType.CHANNEL_TYPE_UNRELIABLE_UNORDERED);
            m_messageSendQueue = new QueueEx<Message>(allocator, m_config.messageSendQueueSize);
            m_messageReceiveQueue = new QueueEx<Message>(allocator, m_config.messageReceiveQueueSize);
            Reset();
        }

        /**
            Unreliable unordered channel destructor.
            Any messages still in the send or receive queues will be released.
         */
        public override void Dispose()
        {
            Reset();
            m_messageSendQueue?.Dispose(); m_messageSendQueue = null;
            m_messageReceiveQueue?.Dispose(); m_messageReceiveQueue = null;
        }

        public override void Reset()
        {
            SetErrorLevel(ChannelErrorLevel.CHANNEL_ERROR_NONE);

            for (var i = 0; i < m_messageSendQueue.Count; ++i)
            {
                var message = m_messageSendQueue[i];
                m_messageFactory.ReleaseMessage(ref message); ;
            }

            for (var i = 0; i < m_messageReceiveQueue.Count; ++i)
            {
                var message = m_messageReceiveQueue[i];
                m_messageFactory.ReleaseMessage(ref message);
            }

            m_messageSendQueue.Clear();
            m_messageReceiveQueue.Clear();

            ResetCounters();
        }

        public override bool CanSendMessage()
        {
            yojimbo.assert(m_messageSendQueue != null);
            return !m_messageSendQueue.IsFull;
        }

        public override bool HasMessagesToSend()
        {
            yojimbo.assert(m_messageSendQueue != null);
            return !m_messageSendQueue.IsEmpty;
        }

        public override void SendMessage(ref Message message, object context)
        {
            yojimbo.assert(message != null);
            yojimbo.assert(CanSendMessage());

            if (ErrorLevel != ChannelErrorLevel.CHANNEL_ERROR_NONE)
            {
                m_messageFactory.ReleaseMessage(ref message);
                return;
            }

            if (!CanSendMessage())
            {
                SetErrorLevel(ChannelErrorLevel.CHANNEL_ERROR_SEND_QUEUE_FULL);
                m_messageFactory.ReleaseMessage(ref message);
                return;
            }

            yojimbo.assert(!(message.IsBlockMessage && m_config.disableBlocks));

            if (message.IsBlockMessage && m_config.disableBlocks)
            {
                SetErrorLevel(ChannelErrorLevel.CHANNEL_ERROR_BLOCKS_DISABLED);
                m_messageFactory.ReleaseMessage(ref message);
                return;
            }

            if (message.IsBlockMessage)
            {
                yojimbo.assert(((BlockMessage)message).BlockSize > 0);
                yojimbo.assert(((BlockMessage)message).BlockSize <= m_config.maxBlockSize);
            }

            m_messageSendQueue.Enqueue(message);

            m_counters[(int)ChannelCounters.CHANNEL_COUNTER_MESSAGES_SENT]++;
        }

        public override Message ReceiveMessage()
        {
            if (ErrorLevel != ChannelErrorLevel.CHANNEL_ERROR_NONE)
                return null;

            if (m_messageReceiveQueue.IsEmpty)
                return null;

            m_counters[(int)ChannelCounters.CHANNEL_COUNTER_MESSAGES_RECEIVED]++;

            return m_messageReceiveQueue.Dequeue();
        }

        public override void AdvanceTime(double time) { }

        public override int GetPacketData(object context, ChannelPacketData packetData, ushort packetSequence, int availableBits)
        {
            if (m_messageSendQueue.IsEmpty)
                return 0;

            if (m_config.packetBudget > 0)
                availableBits = Math.Min(m_config.packetBudget * 8, availableBits);

            var giveUpBits = 4 * 8;

            var messageTypeBits = yojimbo.bits_required(0, (uint)(m_messageFactory.NumTypes - 1));

            var usedBits = yojimbo.ConservativeMessageHeaderBits;
            var numMessages = 0;
            var messages = new Message[m_config.maxMessagesPerPacket];

            while (true)
            {
                if (m_messageSendQueue.IsEmpty)
                    break;

                if (availableBits - usedBits < giveUpBits)
                    break;

                if (numMessages == m_config.maxMessagesPerPacket)
                    break;

                var message = m_messageSendQueue.Dequeue();

                yojimbo.assert(message != null);

                var measureStream = new MeasureStream(m_messageFactory.Allocator);
                measureStream.Context = context;
                message.SerializeInternal(measureStream);

                if (message.IsBlockMessage)
                {
                    var blockMessage = (BlockMessage)message;
                    ChannelPacketData.SerializeMessageBlock(measureStream, m_messageFactory, blockMessage, m_config.maxBlockSize);
                }

                var messageBits = messageTypeBits + measureStream.BitsProcessed;

                if (usedBits + messageBits > availableBits)
                {
                    m_messageFactory.ReleaseMessage(ref message);
                    continue;
                }

                usedBits += messageBits;

                yojimbo.assert(usedBits <= availableBits);

                messages[numMessages++] = message;
            }

            if (numMessages == 0)
                return 0;

            var allocator = m_messageFactory.Allocator;

            packetData.Initialize();
            packetData.channelIndex = (ushort)ChannelIndex;
            packetData.message.numMessages = numMessages;
            packetData.message.messages = new Message[numMessages];
            for (var i = 0; i < numMessages; ++i)
                packetData.message.messages[i] = messages[i];

            return usedBits;
        }

        public override void ProcessPacketData(ChannelPacketData packetData, ushort packetSequence)
        {
            if (m_errorLevel != ChannelErrorLevel.CHANNEL_ERROR_NONE)
                return;

            if (packetData.messageFailedToSerialize)
            {
                SetErrorLevel(ChannelErrorLevel.CHANNEL_ERROR_FAILED_TO_SERIALIZE);
                return;
            }

            for (var i = 0; i < packetData.message.numMessages; ++i)
            {
                var message = packetData.message.messages[i];
                yojimbo.assert(message != null);
                message.Id = packetSequence;
                if (!m_messageReceiveQueue.IsFull)
                {
                    m_messageFactory.AcquireMessage(message);
                    m_messageReceiveQueue.Enqueue(message);
                }
            }
        }

        public override void ProcessAck(ushort ack) { }

        protected QueueEx<Message> m_messageSendQueue;                                  ///< Message send queue.
        protected QueueEx<Message> m_messageReceiveQueue;                               ///< Message receive queue.
    }

    #endregion

    #region ConnectionPacket

    internal class ConnectionPacket
    {
        public int numChannelEntries = 0;
        public ChannelPacketData[] channelEntry = null;
        public MessageFactory messageFactory = null;

        public ConnectionPacket()
        {
            messageFactory = null;
            numChannelEntries = 0;
            channelEntry = null;
        }

        public void Dispose()
        {
            if (messageFactory != null)
            {
                for (var i = 0; i < numChannelEntries; ++i)
                    channelEntry[i].Free(ref messageFactory);
                channelEntry = null;
                messageFactory = null;
            }
        }

        public bool AllocateChannelData(MessageFactory _messageFactory, int numEntries)
        {
            yojimbo.assert(numEntries > 0);
            yojimbo.assert(numEntries <= yojimbo.MaxChannels);
            messageFactory = _messageFactory;
            var allocator = messageFactory.Allocator;
            channelEntry = new ChannelPacketData[numEntries];
            if (channelEntry == null)
                return false;
            for (var i = 0; i < numEntries; ++i)
            {
                channelEntry[i] = new ChannelPacketData();
                channelEntry[i].Initialize();
            }
            numChannelEntries = numEntries;
            return true;
        }

        public bool Serialize(BaseStream stream, MessageFactory messageFactory, ConnectionConfig connectionConfig)
        {
            var numChannels = connectionConfig.numChannels;
            yojimbo.serialize_int(stream, ref numChannelEntries, 0, connectionConfig.numChannels);
#if YOJIMBO_DEBUG_MESSAGE_BUDGET
            yojimbo.assert(stream.BitsProcessed <= yojimbo.ConservativePacketHeaderBits);
#endif
            if (numChannelEntries > 0)
            {
                if (stream.IsReading)
                {
                    if (!AllocateChannelData(messageFactory, numChannelEntries))
                    {
                        yojimbo.printf(yojimbo.LOG_LEVEL_ERROR, "error: failed to allocate channel data (ConnectionPacket)\n");
                        return false;
                    }
                    for (var i = 0; i < numChannelEntries; ++i)
                        yojimbo.assert(channelEntry[i].messageFailedToSerialize == false);
                }
                for (var i = 0; i < numChannelEntries; ++i)
                {
                    yojimbo.assert(channelEntry[i].messageFailedToSerialize == false);
                    if (!channelEntry[i].Serialize(stream, messageFactory, connectionConfig.channel, numChannels)) //: SerializeInternal
                    {
                        yojimbo.printf(yojimbo.LOG_LEVEL_ERROR, $"error: failed to serialize channel {i}\n");
                        return false;
                    }
                }
            }
            return true;
        }

        //public bool SerializeInternal(ReadStream stream, MessageFactory _messageFactory, ConnectionConfig connectionConfig) =>
        //    Serialize(stream, _messageFactory, connectionConfig);
        //public bool SerializeInternal(WriteStream stream, MessageFactory _messageFactory, ConnectionConfig connectionConfig) =>
        //    Serialize(stream, _messageFactory, connectionConfig);
        //public bool SerializeInternal(MeasureStream stream, MessageFactory _messageFactory, ConnectionConfig connectionConfig) =>
        //    Serialize(stream, _messageFactory, connectionConfig);
    }

    #endregion

    #region Connection

    /// Connection error level.
    public enum ConnectionErrorLevel
    {
        CONNECTION_ERROR_NONE = 0,                              ///< No error. All is well.
        CONNECTION_ERROR_CHANNEL,                               ///< A channel is in an error state.
        CONNECTION_ERROR_ALLOCATOR,                             ///< The allocator is an error state.
        CONNECTION_ERROR_MESSAGE_FACTORY,                       ///< The message factory is in an error state.
        CONNECTION_ERROR_READ_PACKET_FAILED,                    ///< Failed to read packet. Received an invalid packet?     
    }

    /**
        Sends and receives messages across a set of user defined channels.
     */
    public class Connection
    {
        public Connection(Allocator allocator, MessageFactory messageFactory, ConnectionConfig connectionConfig, double time)
        {
            m_connectionConfig = connectionConfig;
            m_allocator = allocator;
            m_messageFactory = messageFactory;
            m_errorLevel = ConnectionErrorLevel.CONNECTION_ERROR_NONE;
            m_channel = new Channel[yojimbo.MaxChannels];
            yojimbo.assert(m_connectionConfig.numChannels >= 1);
            yojimbo.assert(m_connectionConfig.numChannels <= yojimbo.MaxChannels);
            for (var channelIndex = 0; channelIndex < m_connectionConfig.numChannels; ++channelIndex)
            {
                switch (m_connectionConfig.channel[channelIndex].type)
                {
                    case ChannelType.CHANNEL_TYPE_RELIABLE_ORDERED:
                        m_channel[channelIndex] = new ReliableOrderedChannel(m_allocator, messageFactory, m_connectionConfig.channel[channelIndex], channelIndex, time);
                        break;
                    case ChannelType.CHANNEL_TYPE_UNRELIABLE_UNORDERED:
                        m_channel[channelIndex] = new UnreliableUnorderedChannel(m_allocator, messageFactory, m_connectionConfig.channel[channelIndex], channelIndex, time);
                        break;
                    default: Console.WriteLine("unknown channel type"); yojimbo.assert(false); break;
                }
            }
        }

        public void Dispose()
        {
            yojimbo.assert(m_allocator != null);
            Reset();
            for (var i = 0; i < m_connectionConfig.numChannels; ++i)
            {
                m_channel[i]?.Dispose(); m_channel[i] = null;
            }
            m_allocator = null;
        }

        public void Reset()
        {
            m_errorLevel = ConnectionErrorLevel.CONNECTION_ERROR_NONE;
            for (var i = 0; i < m_connectionConfig.numChannels; ++i)
                m_channel[i].Reset();
        }

        public bool CanSendMessage(int channelIndex)
        {
            yojimbo.assert(channelIndex >= 0);
            yojimbo.assert(channelIndex < m_connectionConfig.numChannels);
            return m_channel[channelIndex].CanSendMessage();
        }

        public bool HasMessagesToSend(int channelIndex)
        {
            yojimbo.assert(channelIndex >= 0);
            yojimbo.assert(channelIndex < m_connectionConfig.numChannels);
            return m_channel[channelIndex].HasMessagesToSend();
        }

        public void SendMessage(int channelIndex, Message message, object context = null)
        {
            yojimbo.assert(channelIndex >= 0);
            yojimbo.assert(channelIndex < m_connectionConfig.numChannels);
            m_channel[channelIndex].SendMessage(ref message, context);
        }

        public Message ReceiveMessage(int channelIndex)
        {
            yojimbo.assert(channelIndex >= 0);
            yojimbo.assert(channelIndex < m_connectionConfig.numChannels);
            return m_channel[channelIndex].ReceiveMessage();
        }

        public void ReleaseMessage<TMessage>(ref TMessage message) where TMessage : Message
        {
            yojimbo.assert(message != null);
            m_messageFactory.ReleaseMessage(ref message);
        }

        static int WritePacket(
            object context,
            MessageFactory messageFactory,
            ConnectionConfig connectionConfig,
            ConnectionPacket packet,
            byte[] buffer,
            int bufferSize)
        {
            var stream = new WriteStream(messageFactory.Allocator, buffer, bufferSize);

            stream.Context = context;

            if (!packet.Serialize(stream, messageFactory, connectionConfig)) //: SerializeInternal
            {
                yojimbo.printf(yojimbo.LOG_LEVEL_ERROR, "error: serialize connection packet failed (write packet)\n");
                return 0;
            }

#if YOJIMBO_SERIALIZE_CHECKS
            if (!stream.SerializeCheck())
            {
                yojimbo.printf(yojimbo.LOG_LEVEL_ERROR, "error: serialize check at end of connection packed failed (write packet)\n");
                return 0;
            }
#endif

            stream.Flush();

            return stream.BytesProcessed;
        }

        public bool GeneratePacket(object context, ushort packetSequence, byte[] packetData, int maxPacketBytes, out int packetBytes)
        {
            packetBytes = 0;
            var packet = new ConnectionPacket();

            if (m_connectionConfig.numChannels > 0)
            {
                var numChannelsWithData = 0;
                var channelHasData = new bool[yojimbo.MaxChannels];
                var channelData = BufferEx.NewT<ChannelPacketData>(yojimbo.MaxChannels);

                var availableBits = maxPacketBytes * 8 - yojimbo.ConservativePacketHeaderBits;

                for (var channelIndex = 0; channelIndex < m_connectionConfig.numChannels; ++channelIndex)
                {
                    var packetDataBits = m_channel[channelIndex].GetPacketData(context, channelData[channelIndex], packetSequence, availableBits);
                    if (packetDataBits > 0)
                    {
                        availableBits -= yojimbo.ConservativeChannelHeaderBits;
                        availableBits -= packetDataBits;
                        channelHasData[channelIndex] = true;
                        numChannelsWithData++;
                    }
                }

                if (numChannelsWithData > 0)
                {
                    if (!packet.AllocateChannelData(m_messageFactory, numChannelsWithData))
                    {
                        yojimbo.printf(yojimbo.LOG_LEVEL_ERROR, "error: failed to allocate channel data\n");
                        return false;
                    }

                    var index = 0;

                    for (var channelIndex = 0; channelIndex < m_connectionConfig.numChannels; ++channelIndex)
                        if (channelHasData[channelIndex])
                        {
                            BufferEx.Copy(ref packet.channelEntry[index], channelData[channelIndex]);
                            index++;
                        }
                }
            }

            packetBytes = WritePacket(context, m_messageFactory, m_connectionConfig, packet, packetData, maxPacketBytes);

            return true;
        }

        static bool ReadPacket(
            object context,
            MessageFactory messageFactory,
            ConnectionConfig connectionConfig,
            ConnectionPacket packet,
            byte[] buffer,
            int bufferSize)
        {
            yojimbo.assert(buffer != null);
            yojimbo.assert(bufferSize > 0);

            var stream = new ReadStream(messageFactory.Allocator, buffer, bufferSize);

            stream.Context = context;

            if (!packet.Serialize(stream, messageFactory, connectionConfig)) //: SerializeInternal
            {
                yojimbo.printf(yojimbo.LOG_LEVEL_ERROR, "error: serialize connection packet failed (read packet)\n");
                return false;
            }

#if YOJIMBO_SERIALIZE_CHECKS
            if (!stream.SerializeCheck())
            {
                yojimbo.printf(yojimbo.LOG_LEVEL_ERROR, "error: serialize check failed at end of connection packet (read packet)\n");
                return false;
            }
#endif

            return true;
        }

        public bool ProcessPacket(object context, ushort packetSequence, byte[] packetData, int packetBytes)
        {
            if (m_errorLevel != ConnectionErrorLevel.CONNECTION_ERROR_NONE)
            {
                yojimbo.printf(yojimbo.LOG_LEVEL_DEBUG, "failed to read packet because connection is in error state\n");
                return false;
            }

            var packet = new ConnectionPacket();

            if (!ReadPacket(context, m_messageFactory, m_connectionConfig, packet, packetData, packetBytes))
            {
                yojimbo.printf(yojimbo.LOG_LEVEL_ERROR, "error: failed to read packet\n");
                m_errorLevel = ConnectionErrorLevel.CONNECTION_ERROR_READ_PACKET_FAILED;
                return false;
            }

            for (var i = 0; i < packet.numChannelEntries; ++i)
            {
                var channelIndex = packet.channelEntry[i].channelIndex;
                yojimbo.assert(channelIndex >= 0);
                yojimbo.assert(channelIndex <= m_connectionConfig.numChannels);
                m_channel[channelIndex].ProcessPacketData(packet.channelEntry[i], packetSequence);
                if (m_channel[channelIndex].ErrorLevel != ChannelErrorLevel.CHANNEL_ERROR_NONE)
                {
                    yojimbo.printf(yojimbo.LOG_LEVEL_DEBUG, $"failed to read packet because channel {channelIndex} is in error state\n");
                    return false;
                }
            }

            return true;
        }

        public void ProcessAcks(ushort[] acks, int numAcks)
        {
            for (var i = 0; i < numAcks; ++i)
                for (var channelIndex = 0; channelIndex < m_connectionConfig.numChannels; ++channelIndex)
                    m_channel[channelIndex].ProcessAck(acks[i]);
        }

        public void AdvanceTime(double time)
        {
            for (var i = 0; i < m_connectionConfig.numChannels; ++i)
            {
                m_channel[i].AdvanceTime(time);

                if (m_channel[i].ErrorLevel != ChannelErrorLevel.CHANNEL_ERROR_NONE)
                {
                    m_errorLevel = ConnectionErrorLevel.CONNECTION_ERROR_CHANNEL;
                    return;
                }
            }
            //if (m_allocator.ErrorLevel != AllocatorErrorLevel.ALLOCATOR_ERROR_NONE)
            //{
            //    m_errorLevel = ConnectionErrorLevel.CONNECTION_ERROR_ALLOCATOR;
            //    return;
            //}
            if (m_messageFactory.ErrorLevel != MessageFactoryErrorLevel.MESSAGE_FACTORY_ERROR_NONE)
            {
                m_errorLevel = ConnectionErrorLevel.CONNECTION_ERROR_MESSAGE_FACTORY;
                return;
            }
        }

        public ConnectionErrorLevel ErrorLevel =>
            m_errorLevel;

        Allocator m_allocator;                                  ///< Allocator passed in to the connection constructor.
        MessageFactory m_messageFactory;                        ///< Message factory for creating and destroying messages.
        ConnectionConfig m_connectionConfig;                    ///< Connection configuration.
        Channel[] m_channel;                                    ///< Array of connection channels. Array size corresponds to m_connectionConfig.numChannels
        ConnectionErrorLevel m_errorLevel;                      ///< The connection error level.
    }

    #endregion

    #region NetworkSimulator

    /**
        Simulates packet loss, latency, jitter and duplicate packets.
        This is useful during development, so your game is tested and played under real world conditions, instead of ideal LAN conditions.
        This simulator works on packet send. This means that if you want 125ms of latency (round trip), you must to add 125/2 = 62.5ms of latency to each side.
     */
    public class NetworkSimulator
    {
        /**
            Create a network simulator.
            Initial network conditions are set to:
                Latency: 0ms
                Jitter: 0ms
                Packet Loss: 0%
                Duplicates: 0%
            @param allocator The allocator to use.
            @param numPackets The maximum number of packets that can be stored in the simulator at any time.
            @param time The initial time value in seconds.
         */
        public NetworkSimulator(Allocator allocator, int numPackets, double time)
        {
            yojimbo.assert(numPackets > 0);
            m_allocator = allocator;
            m_currentIndex = 0;
            m_time = time;
            m_latency = 0.0f;
            m_jitter = 0.0f;
            m_packetLoss = 0.0f;
            m_duplicates = 0.0f;
            m_active = false;
            m_numPacketEntries = numPackets;
            m_packetEntries = new PacketEntry[numPackets];
            yojimbo.assert(m_packetEntries != null);
            BufferEx.SetT(m_packetEntries, 0);
        }

        /**
            Network simulator destructor.
            Any packet data still in the network simulator is destroyed.
         */
        public void Dispose()
        {
            yojimbo.assert(m_allocator != null);
            yojimbo.assert(m_packetEntries != null);
            yojimbo.assert(m_numPacketEntries > 0);
            DiscardPackets();
            m_packetEntries = null;
            m_numPacketEntries = 0;
            m_allocator = null;
        }

        /**
            Set the latency in milliseconds.
            This latency is added on packet send. To simulate a round trip time of 100ms, add 50ms of latency to both sides of the connection.
            @param milliseconds The latency to add in milliseconds.
         */
        public void SetLatency(float milliseconds)
        {
            m_latency = milliseconds;
            UpdateActive();
        }

        /**
            Set the packet jitter in milliseconds.
            Jitter is applied +/- this amount in milliseconds. To be truly effective, jitter must be applied together with some latency.
            @param milliseconds The amount of jitter to add in milliseconds (+/-).
         */
        public void SetJitter(float milliseconds)
        {
            m_jitter = milliseconds;
            UpdateActive();
        }

        /**
            Set the amount of packet loss to apply on send.
            @param percent The packet loss percentage. 0% = no packet loss. 100% = all packets are dropped.
         */
        public void SetPacketLoss(float percent)
        {
            m_packetLoss = percent;
            UpdateActive();
        }

        /**
            Set percentage chance of packet duplicates.
            If the duplicate chance succeeds, a duplicate packet is added to the queue with a random delay of up to 1 second.
            @param percent The percentage chance of a packet duplicate being sent. 0% = no duplicate packets. 100% = all packets have a duplicate sent.
         */
        public void SetDuplicates(float percent)
        {
            m_duplicates = percent;
            UpdateActive();
        }

        /**
            Is the network simulator active?
            The network simulator is active when packet loss, latency, duplicates or jitter are non-zero values.
            This is used by the transport to know whether it should shunt packets through the simulator, or send them directly to the network. This is a minor optimization.
         */
        public bool IsActive =>
            m_active;

        /**
            Queue a packet to send.
            IMPORTANT: Ownership of the packet data pointer is *not* transferred to the network simulator. It makes a copy of the data instead.
            @param to The slot index the packet should be sent to.
            @param packetData The packet data.
            @param packetBytes The packet size (bytes).
         */
        public void SendPacket(int to, byte[] packetData, int packetBytes)
        {
            yojimbo.assert(m_allocator != null);
            yojimbo.assert(packetData != null);
            yojimbo.assert(packetBytes > 0);

            if (yojimbo.random_float(0.0f, 100.0f) <= m_packetLoss)
            {
                return;
            }

            var packetEntry = m_packetEntries[m_currentIndex];

            if (packetEntry.packetData != null)
            {
                packetEntry.packetData = null;
                packetEntry = new PacketEntry();
            }

            var delay = m_latency / 1000.0;

            if (m_jitter > 0)
                delay += yojimbo.random_float(-m_jitter, +m_jitter) / 1000.0;

            packetEntry.to = to;
            packetEntry.packetData = new byte[packetBytes];
            BufferEx.Copy(packetEntry.packetData, packetData, packetBytes);
            packetEntry.packetBytes = packetBytes;
            packetEntry.deliveryTime = m_time + delay;
            m_currentIndex = (m_currentIndex + 1) % m_numPacketEntries;

            if (yojimbo.random_float(0.0f, 100.0f) <= m_duplicates)
            {
                var nextPacketEntry = m_packetEntries[m_currentIndex];
                nextPacketEntry.to = to;
                nextPacketEntry.packetData = new byte[packetBytes];
                BufferEx.Copy(nextPacketEntry.packetData, packetData, packetBytes);
                nextPacketEntry.packetBytes = packetBytes;
                nextPacketEntry.deliveryTime = m_time + delay + yojimbo.random_float(0, +1.0f);
                m_currentIndex = (m_currentIndex + 1) % m_numPacketEntries;
            }
        }

        /**
            Receive packets sent to any address.
            IMPORTANT: You take ownership of the packet data you receive and are responsible for freeing it. See NetworkSimulator::GetAllocator.
            @param maxPackets The maximum number of packets to receive.
            @param packetData Array of packet data pointers to be filled [out].
            @param packetBytes Array of packet sizes to be filled [out].
            @param to Array of to indices to be filled [out].
            @returns The number of packets received.
         */
        public int ReceivePackets(int maxPackets, byte[][] packetData, int[] packetBytes, int[] to)
        {
            if (!IsActive)
                return 0;

            int numPackets = 0;

            for (var i = 0; i < Math.Min(m_numPacketEntries, maxPackets); ++i)
            {
                if (m_packetEntries[i].packetData == null)
                    continue;

                if (m_packetEntries[i].deliveryTime < m_time)
                {
                    packetData[numPackets] = m_packetEntries[i].packetData;
                    packetBytes[numPackets] = m_packetEntries[i].packetBytes;
                    if (to != null)
                        to[numPackets] = m_packetEntries[i].to;
                    m_packetEntries[i].packetData = null;
                    numPackets++;
                }
            }

            return numPackets;
        }

        /**
            Discard all packets in the network simulator.
            This is useful if the simulator needs to be reset and used for another purpose.
         */
        public void DiscardPackets()
        {
            for (int i = 0; i < m_numPacketEntries; ++i)
            {
                var packetEntry = m_packetEntries[i];
                if (packetEntry.packetData == null)
                    continue;
                packetEntry.packetData = null;
                packetEntry = new PacketEntry();
            }
        }

        /**
            Discard packets sent to a particular client index.
            This is called when a client disconnects from the server.
         */
        public void DiscardClientPackets(int clientIndex)
        {
            for (var i = 0; i < m_numPacketEntries; ++i)
            {
                var packetEntry = m_packetEntries[i];
                if (packetEntry.packetData == null || packetEntry.to != clientIndex)
                    continue;
                packetEntry.packetData = null;
                packetEntry = new PacketEntry();
            }
        }

        /**
            Advance network simulator time.
            You must pump this regularly otherwise the network simulator won't work.
            @param time The current time value. Please make sure you use double values for time so you retain sufficient precision as time increases.
         */
        public void AdvanceTime(double time)
        {
            m_time = time;
        }

        /**
            Get the allocator to use to free packet data.
            @returns The allocator that packet data is allocated with.
         */
        public Allocator Allocator { get { yojimbo.assert(m_allocator != null); return m_allocator; } }

        /**
            Helper function to update the active flag whenever network settings are changed.
            Active is set to true if any of the network conditions are non-zero. This allows you to quickly check if the network simulator is active and would actually do something.
         */
        protected void UpdateActive()
        {
            bool previous = m_active;
            m_active = m_latency != 0.0f || m_jitter != 0.0f || m_packetLoss != 0.0f || m_duplicates != 0.0f;
            if (previous && !m_active)
            {
                DiscardPackets();
            }
        }

        Allocator m_allocator;                          ///< The allocator passed in to the constructor. It's used to allocate and free packet data.
        float m_latency;                                ///< Latency in milliseconds
        float m_jitter;                                 ///< Jitter in milliseconds +/-
        float m_packetLoss;                             ///< Packet loss percentage.
        float m_duplicates;                             ///< Duplicate packet percentage
        bool m_active;                                  ///< True if network simulator is active, eg. if any of the network settings above are enabled.

        /// A packet buffered in the network simulator.
        public class PacketEntry
        {
            public int to = 0;                          ///< To index this packet should be sent to (for server . client packets).
            public double deliveryTime = 0.0;           ///< Delivery time for this packet (seconds).
            public byte[] packetData = null;            ///< Packet data (owns this pointer).
            public int packetBytes = 0;                 ///< Size of packet in bytes.
        }

        double m_time;                                  ///< Current time from last call to advance time.
        int m_currentIndex;                             ///< Current index in the packet entry array. New packets are inserted here.
        int m_numPacketEntries;                         ///< Number of elements in the packet entry array.
        PacketEntry[] m_packetEntries;                  ///< Pointer to dynamically allocated packet entries. This is where buffered packets are stored.
    }

    #endregion

    #region Adapter

    /** 
        Specifies the message factory and callbacks for clients and servers.
        An instance of this class is passed into the client and server constructors. 
        You can share the same adapter across a client/server pair if you have local multiplayer, eg. loopback.
     */
    public class Adapter
    {
        public void Dispose() { }

        /**
            Override this function to specify your own custom allocator class.
            @param allocator The base allocator that must be used to allocate your allocator instance.
            @param memory The block of memory backing your allocator.
            @param bytes The number of bytes of memory available to your allocator.
            @returns A pointer to the allocator instance you created.
         */
        public virtual Allocator CreateAllocator(Allocator allocator, object memory, int bytes) =>
            new Allocator();

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

    #endregion

    #region NetworkInfo

    /**
        Network information for a connection.
        Contains statistics like round trip time (RTT), packet loss %, bandwidth estimates, number of packets sent, received and acked.
     */
    public class NetworkInfo
    {
        public float RTT;                               ///< Round trip time estimate (milliseconds).
        public float packetLoss;                        ///< Packet loss percent.
        public float sentBandwidth;                     ///< Sent bandwidth (kbps).
        public float receivedBandwidth;                 ///< Received bandwidth (kbps).
        public float ackedBandwidth;                    ///< Acked bandwidth (kbps).
        public ulong numPacketsSent;                    ///< Number of packets sent.
        public ulong numPacketsReceived;                ///< Number of packets received.
        public ulong numPacketsAcked;                   ///< Number of packets acked.
    }

    #endregion

    #region Server

    /**
        The server interface. //: ServerInterface -> IServer
     */
    public interface IServer : IDisposable
    {
        /**
            Gets or set the context for reading and writing packets.
            This is optional. It lets you pass in a pointer to some structure that you want to have available when reading and writing packets via Stream::GetContext.
            Typical use case is to pass in an array of min/max ranges for values determined by some data that is loaded from a toolchain vs. being known at compile time. 
            If you do use a context, make sure the same context data is set on client and server, and include a checksum of the context data in the protocol id.
         */
        object Context { get; set; }

        /**
            Start the server and allocate client slots.
            Each client that connects to this server occupies one of the client slots allocated by this function.
            @param maxClients The number of client slots to allocate. Must be in range [1,MaxClients]
            @see Server::Stop
         */
        void Start(int maxClients);

        /**
            Stop the server and free client slots.
            Any clients that are connected at the time you call stop will be disconnected.
            When the server is stopped, clients cannot connect to the server.
            @see Server::Start.
         */
        void Stop();

        /**
            Disconnect the client at the specified client index.
            @param clientIndex The index of the client to disconnect in range [0,maxClients-1], where maxClients is the number of client slots allocated in Server::Start.
            @see Server::IsClientConnected
         */
        void DisconnectClient(int clientIndex);

        /**
            Disconnect all clients from the server.
            Client slots remain allocated as per the last call to Server::Start, they are simply made available for new clients to connect.
         */
        void DisconnectAllClients();

        /**
            Send packets to connected clients.
            This function drives the sending of packets that transmit messages to clients.
         */
        void SendPackets();

        /**
            Receive packets from connected clients.
            This function drives the procesing of messages included in packets received from connected clients.
         */
        void ReceivePackets();

        /**
            Advance server time.
            Call this at the end of each frame to advance the server time forward. 
            IMPORTANT: Please use a double for your time value so it maintains sufficient accuracy as time increases.
         */
        void AdvanceTime(double time);

        /**
            Is the server running?
            The server is running after you have called Server::Start. It is not running before the first server start, and after you call Server::Stop.
            Clients can only connect to the server while it is running.
            @returns true if the server is currently running.
         */
        bool IsRunning { get; }

        /**
            Get the maximum number of clients that can connect to the server.
            Corresponds to the maxClients parameter passed into the last call to Server::Start.
            @returns The maximum number of clients that can connect to the server. In other words, the number of client slots.
         */
        int MaxClients { get; }

        /**
            Is a client connected to a client slot?
            @param clientIndex the index of the client slot in [0,maxClients-1], where maxClients corresponds to the value passed into the last call to Server::Start.
            @returns True if the client is connected.
         */
        bool IsClientConnected(int clientIndex);

        /**
            Get the unique id of the client
            @param clientIndex the index of the client slot in [0,maxClients-1], where maxClients corresponds to the value passed into the last call to Server::Start.
            @returns The unique id of the client.
         */
        ulong GetClientId(int clientIndex);

        /** 
            Get the number of clients that are currently connected to the server.
            @returns the number of connected clients.
         */
        int NumConnectedClients { get; }

        /**
            Gets the current server time.
            @see Server::AdvanceTime
         */
        double Time { get; }

        /**
            Create a message of the specified type for a specific client.
            @param clientIndex The index of the client this message belongs to. Determines which client heap is used to allocate the message.
            @param type The type of the message to create. The message types corresponds to the message factory created by the adaptor set on the server.
         */
        Message CreateMessage(int clientIndex, int type);

        /**
            Helper function to allocate a data block.
            This is typically used to create blocks of data to attach to block messages. See BlockMessage for details.
            @param clientIndex The index of the client this message belongs to. Determines which client heap is used to allocate the data.
            @param bytes The number of bytes to allocate.
            @returns The pointer to the data block. This must be attached to a message via Client::AttachBlockToMessage, or freed via Client::FreeBlock.
         */
        byte[] AllocateBlock(int clientIndex, int bytes);

        /**
            Attach data block to message.
            @param clientIndex The index of the client this block belongs to.
            @param message The message to attach the block to. This message must be derived from BlockMessage.
            @param block Pointer to the block of data to attach. Must be created via Client::AllocateBlock.
            @param bytes Length of the block of data in bytes.
         */
        void AttachBlockToMessage(int clientIndex, Message message, byte[] block, int bytes);

        /**
            Free a block of memory.
            @param clientIndex The index of the client this block belongs to.
            @param block The block of memory created by Client::AllocateBlock.
         */
        void FreeBlock(int clientIndex, ref byte[] block);

        /**
            Can we send a message to a particular client on a channel?
            @param clientIndex The index of the client to send a message to.
            @param channelIndex The channel index in range [0,numChannels-1].
            @returns True if a message can be sent over the channel, false otherwise.
         */
        bool CanSendMessage(int clientIndex, int channelIndex);

        /**
            Send a message to a client over a channel.
            @param clientIndex The index of the client to send a message to.
            @param channelIndex The channel index in range [0,numChannels-1].
            @param message The message to send.
         */
        void SendMessage(int clientIndex, int channelIndex, Message message);

        /**
            Receive a message from a client over a channel.
            @param clientIndex The index of the client to receive messages from.
            @param channelIndex The channel index in range [0,numChannels-1].
            @returns The message received, or null if no message is available. Make sure to release this message by calling Server::ReleaseMessage.
         */
        Message ReceiveMessage(int clientIndex, int channelIndex);

        /**
            Release a message.
            Call this for messages received by Server::ReceiveMessage.
            @param clientIndex The index of the client that the message belongs to.
            @param message The message to release.
         */
        void ReleaseMessage<TMessage>(int clientIndex, ref TMessage message) where TMessage : Message;

        /**
            Get client network info.
            Call this to receive information about the client network connection, eg. round trip time, packet loss %, # of packets sent and so on.
            @param clientIndex The index of the client.
            @param info The struct to be filled with network info [out].
         */
        void GetNetworkInfo(int clientIndex, out NetworkInfo info);

        /**
            Connect a loopback client.
            This allows you to have local clients connected to a server, for example for integrated server or singleplayer.
            @param clientIndex The index of the client.
            @param clientId The unique client id.
            @param userData User data for this client. Optional. Pass null if not needed.
         */
        void ConnectLoopbackClient(int clientIndex, ulong clientId, byte[] userData);

        /**
            Disconnect a loopback client.
            Loopback clients are not disconnected by regular Disconnect or DisconnectAllClient calls. You need to call this function instead.
            @param clientIndex The index of the client to disconnect. Must already be a connected loopback client.
         */
        void DisconnectLoopbackClient(int clientIndex);

        /**
            Is this client a loopback client?
            @param clientIndex The client index.
            @returns true if the client is a connected loopback client, false otherwise.
         */
        bool IsLoopbackClient(int clientIndex);

        /**
            Process loopback packet.
            Use this to pass packets from a client directly to the loopback client slot on the server.
            @param clientIndex The client index. Must be an already connected loopback client.
            @param packetData The packet data to process.
            @param packetBytes The number of bytes of packet data.
            @param packetSequence The packet sequence number.
         */
        void ProcessLoopbackPacket(int clientIndex, byte[] packetData, int packetBytes, ulong packetSequence);
    }

    /**
        Common functionality across all server implementations.
     */
    public abstract class BaseServer : IServer
    {
        public BaseServer(Allocator allocator, ClientServerConfig config, Adapter adapter, double time)
        {
            m_config = config;
            m_allocator = allocator;
            m_adapter = adapter;
            m_context = null;
            m_time = time;
            m_running = false;
            m_maxClients = 0;
            m_globalMemory = null;
            m_globalAllocator = null;
            for (var i = 0; i < MaxClients; ++i)
            {
                m_clientMemory[i] = null;
                m_clientAllocator[i] = null;
                m_clientMessageFactory[i] = null;
                m_clientConnection[i] = null;
                m_clientEndpoint[i] = null;
            }
            m_networkSimulator = null;
            m_packetBuffer = null;
        }

        public virtual void Dispose()
        {
            // IMPORTANT: Please stop the server before destroying it!
            yojimbo.assert(!IsRunning);
            m_allocator = null;
        }

        public virtual object Context
        {
            get => m_context;
            set
            {
                yojimbo.assert(!IsRunning);
                m_context = value;
            }
        }

        public virtual void Start(int maxClients)
        {
            Stop();
            m_running = true;
            m_maxClients = maxClients;
            yojimbo.assert(m_globalMemory == null);
            yojimbo.assert(m_globalAllocator == null);
            m_globalMemory = new byte[m_config.serverGlobalMemory];
            m_globalAllocator = m_adapter.CreateAllocator(m_allocator, m_globalMemory, m_config.serverGlobalMemory);
            yojimbo.assert(m_globalAllocator != null);
            if (m_config.networkSimulator)
                m_networkSimulator = new NetworkSimulator(m_globalAllocator, m_config.maxSimulatorPackets, m_time);
            for (var i = 0; i < m_maxClients; ++i)
            {
                yojimbo.assert(m_clientMemory[i] == null);
                yojimbo.assert(m_clientAllocator[i] == null);

                m_clientMemory[i] = new byte[m_config.serverPerClientMemory];
                m_clientAllocator[i] = m_adapter.CreateAllocator(m_allocator, m_clientMemory[i], m_config.serverPerClientMemory);
                yojimbo.assert(m_clientAllocator[i] != null);

                m_clientMessageFactory[i] = m_adapter.CreateMessageFactory(m_clientAllocator[i]);
                yojimbo.assert(m_clientMessageFactory[i] != null);

                m_clientConnection[i] = new Connection(m_clientAllocator[i], m_clientMessageFactory[i], m_config, m_time);
                yojimbo.assert(m_clientConnection[i] != null);

                reliable.default_config(out var reliable_config);
                reliable_config.name = "server endpoint";
                reliable_config.context = this;
                reliable_config.index = i;
                reliable_config.max_packet_size = m_config.maxPacketSize;
                reliable_config.fragment_above = m_config.fragmentPacketsAbove;
                reliable_config.max_fragments = m_config.maxPacketFragments;
                reliable_config.fragment_size = m_config.packetFragmentSize;
                reliable_config.ack_buffer_size = m_config.ackedPacketsBufferSize;
                reliable_config.received_packets_buffer_size = m_config.receivedPacketsBufferSize;
                reliable_config.fragment_reassembly_buffer_size = m_config.packetReassemblyBufferSize;
                reliable_config.transmit_packet_function = StaticTransmitPacketFunction;
                reliable_config.process_packet_function = StaticProcessPacketFunction;
                reliable_config.allocator_context = GlobalAllocator;
                reliable_config.allocate_function = StaticAllocateFunction;
                reliable_config.free_function = StaticFreeFunction;
                m_clientEndpoint[i] = reliable.endpoint_create(reliable_config, m_time);
                reliable.endpoint_reset(m_clientEndpoint[i]);
            }
            m_packetBuffer = new byte[m_config.maxPacketSize];
        }

        public virtual void Stop()
        {
            if (IsRunning)
            {
                m_packetBuffer = null;
                yojimbo.assert(m_globalMemory != null);
                yojimbo.assert(m_globalAllocator != null);
                m_networkSimulator?.Dispose(); m_networkSimulator = null;
                for (var i = 0; i < m_maxClients; ++i)
                {
                    yojimbo.assert(m_clientMemory[i] != null);
                    yojimbo.assert(m_clientAllocator[i] != null);
                    yojimbo.assert(m_clientMessageFactory[i] != null);
                    yojimbo.assert(m_clientEndpoint[i] != null);
                    reliable.endpoint_destroy(ref m_clientEndpoint[i]); m_clientEndpoint[i] = null;
                    m_clientConnection[i]?.Dispose(); m_clientConnection[i] = null;
                    m_clientMessageFactory[i]?.Dispose(); m_clientMessageFactory[i] = null;
                    m_clientAllocator[i]?.Dispose(); m_clientAllocator[i] = null;
                    m_clientMemory[i] = null;
                }
                m_globalAllocator?.Dispose(); m_globalAllocator = null;
                m_globalMemory = null;
            }
            m_running = false;
            m_maxClients = 0;
            m_packetBuffer = null;
        }

        public virtual void AdvanceTime(double time)
        {
            m_time = time;
            if (IsRunning)
            {
                for (var i = 0; i < m_maxClients; ++i)
                {
                    m_clientConnection[i].AdvanceTime(time);
                    if (m_clientConnection[i].ErrorLevel != ConnectionErrorLevel.CONNECTION_ERROR_NONE)
                    {
                        yojimbo.printf(yojimbo.LOG_LEVEL_ERROR, $"client {m_clientConnection[i].ErrorLevel} connection is in error state. disconnecting client\n");
                        DisconnectClient(i);
                        continue;
                    }
                    reliable.endpoint_update(m_clientEndpoint[i], m_time);
                    var acks = reliable.endpoint_get_acks(m_clientEndpoint[i], out var numAcks);
                    m_clientConnection[i].ProcessAcks(acks, numAcks);
                    reliable.endpoint_clear_acks(m_clientEndpoint[i]);
                }
                var networkSimulator = NetworkSimulator;
                if (networkSimulator != null)
                    networkSimulator.AdvanceTime(time);
            }
        }

        public virtual bool IsRunning => m_running;

        public virtual int MaxClients => m_maxClients;

        public virtual double Time => m_time;

        public void SetLatency(float milliseconds)
        {
            if (m_networkSimulator != null)
                m_networkSimulator.SetLatency(milliseconds);
        }

        public void SetJitter(float milliseconds)
        {
            if (m_networkSimulator != null)
                m_networkSimulator.SetJitter(milliseconds);
        }

        public void SetPacketLoss(float percent)
        {
            if (m_networkSimulator != null)
                m_networkSimulator.SetPacketLoss(percent);
        }

        public void SetDuplicates(float percent)
        {
            if (m_networkSimulator != null)
                m_networkSimulator.SetDuplicates(percent);
        }

        public virtual Message CreateMessage(int clientIndex, int type)
        {
            yojimbo.assert(clientIndex >= 0);
            yojimbo.assert(clientIndex < m_maxClients);
            yojimbo.assert(m_clientMessageFactory[clientIndex] != null);
            return m_clientMessageFactory[clientIndex].CreateMessage(type);
        }

        public virtual byte[] AllocateBlock(int clientIndex, int bytes)
        {
            yojimbo.assert(clientIndex >= 0);
            yojimbo.assert(clientIndex < m_maxClients);
            yojimbo.assert(m_clientAllocator[clientIndex] != null);
            return new byte[bytes];
        }

        public virtual void AttachBlockToMessage(int clientIndex, Message message, byte[] block, int bytes)
        {
            yojimbo.assert(clientIndex >= 0);
            yojimbo.assert(clientIndex < m_maxClients);
            yojimbo.assert(message != null);
            yojimbo.assert(block != null);
            yojimbo.assert(bytes > 0);
            yojimbo.assert(message.IsBlockMessage);
            var blockMessage = (BlockMessage)message;
            blockMessage.AttachBlock(m_clientAllocator[clientIndex], block, bytes);
        }

        public virtual void FreeBlock(int clientIndex, ref byte[] block)
        {
            yojimbo.assert(clientIndex >= 0);
            yojimbo.assert(clientIndex < m_maxClients);
            block = null;
        }

        public virtual bool CanSendMessage(int clientIndex, int channelIndex)
        {
            yojimbo.assert(clientIndex >= 0);
            yojimbo.assert(clientIndex < m_maxClients);
            yojimbo.assert(m_clientConnection[clientIndex] != null);
            return m_clientConnection[clientIndex].CanSendMessage(channelIndex);
        }

        public bool HasMessagesToSend(int clientIndex, int channelIndex)
        {
            yojimbo.assert(clientIndex >= 0);
            yojimbo.assert(clientIndex < m_maxClients);
            yojimbo.assert(m_clientConnection[clientIndex] != null);
            return m_clientConnection[clientIndex].HasMessagesToSend(channelIndex);
        }

        public virtual void SendMessage(int clientIndex, int channelIndex, Message message)
        {
            yojimbo.assert(clientIndex >= 0);
            yojimbo.assert(clientIndex < m_maxClients);
            yojimbo.assert(m_clientConnection[clientIndex] != null);
            m_clientConnection[clientIndex].SendMessage(channelIndex, message, Context);
        }

        public virtual Message ReceiveMessage(int clientIndex, int channelIndex)
        {
            yojimbo.assert(clientIndex >= 0);
            yojimbo.assert(clientIndex < m_maxClients);
            yojimbo.assert(m_clientConnection[clientIndex] != null);
            return m_clientConnection[clientIndex].ReceiveMessage(channelIndex);
        }

        public virtual void ReleaseMessage<TMessage>(int clientIndex, ref TMessage message) where TMessage : Message
        {
            yojimbo.assert(clientIndex >= 0);
            yojimbo.assert(clientIndex < m_maxClients);
            yojimbo.assert(m_clientConnection[clientIndex] != null);
            m_clientConnection[clientIndex].ReleaseMessage(ref message);
        }

        public virtual void GetNetworkInfo(int clientIndex, out NetworkInfo info)
        {
            yojimbo.assert(IsRunning);
            yojimbo.assert(clientIndex >= 0);
            yojimbo.assert(clientIndex < m_maxClients);
            info = new NetworkInfo();
            if (IsClientConnected(clientIndex))
            {
                yojimbo.assert(m_clientEndpoint[clientIndex] != null);
                var counters = reliable.endpoint_counters(m_clientEndpoint[clientIndex]);
                info.numPacketsSent = counters[reliable.ENDPOINT_COUNTER_NUM_PACKETS_SENT];
                info.numPacketsReceived = counters[reliable.ENDPOINT_COUNTER_NUM_PACKETS_RECEIVED];
                info.numPacketsAcked = counters[reliable.ENDPOINT_COUNTER_NUM_PACKETS_ACKED];
                info.RTT = reliable.endpoint_rtt(m_clientEndpoint[clientIndex]);
                info.packetLoss = reliable.endpoint_packet_loss(m_clientEndpoint[clientIndex]);
                reliable.endpoint_bandwidth(m_clientEndpoint[clientIndex], out info.sentBandwidth, out info.receivedBandwidth, out info.ackedBandwidth);
            }
        }

        protected byte[] PacketBuffer => m_packetBuffer;

        protected Adapter Adapter { get { yojimbo.assert(m_adapter != null); return m_adapter; } }

        protected Allocator GlobalAllocator { get { yojimbo.assert(m_globalAllocator != null); return m_globalAllocator; } }

        protected MessageFactory GetClientMessageFactory(int clientIndex)
        {
            yojimbo.assert(IsRunning);
            yojimbo.assert(clientIndex >= 0);
            yojimbo.assert(clientIndex < m_maxClients);
            return m_clientMessageFactory[clientIndex];
        }

        protected NetworkSimulator NetworkSimulator => m_networkSimulator;

        protected reliable_endpoint_t GetClientEndpoint(int clientIndex)
        {
            yojimbo.assert(IsRunning);
            yojimbo.assert(clientIndex >= 0);
            yojimbo.assert(clientIndex < m_maxClients);
            return m_clientEndpoint[clientIndex];
        }

        protected Connection GetClientConnection(int clientIndex)
        {
            yojimbo.assert(IsRunning);
            yojimbo.assert(clientIndex >= 0);
            yojimbo.assert(clientIndex < m_maxClients);
            yojimbo.assert(m_clientConnection[clientIndex] != null);
            return m_clientConnection[clientIndex];
        }

        protected abstract void TransmitPacketFunction(int clientIndex, ushort packetSequence, byte[] packetData, int packetBytes);

        protected abstract bool ProcessPacketFunction(int clientIndex, ushort packetSequence, byte[] packetData, int packetBytes);

        protected static void StaticTransmitPacketFunction(object context, int index, ushort packetSequence, byte[] packetData, int packetBytes)
        {
            var server = (BaseServer)context;
            server.TransmitPacketFunction(index, packetSequence, packetData, packetBytes);
        }

        protected static bool StaticProcessPacketFunction(object context, int index, ushort packetSequence, byte[] packetData, int packetBytes)
        {
            var server = (BaseServer)context;
            return server.ProcessPacketFunction(index, packetSequence, packetData, packetBytes);
        }

        protected static object StaticAllocateFunction(object context, ulong bytes) => null;

        protected static void StaticFreeFunction(object context, object pointer) { }

        public abstract int NumConnectedClients { get; }
        public abstract void DisconnectClient(int clientIndex);
        public abstract void DisconnectAllClients();
        public abstract void SendPackets();
        public abstract void ReceivePackets();
        public abstract bool IsClientConnected(int clientIndex);
        public abstract ulong GetClientId(int clientIndex);
        public abstract void ConnectLoopbackClient(int clientIndex, ulong clientId, byte[] userData);
        public abstract void DisconnectLoopbackClient(int clientIndex);
        public abstract bool IsLoopbackClient(int clientIndex);
        public abstract void ProcessLoopbackPacket(int clientIndex, byte[] packetData, int packetBytes, ulong packetSequence);

        ClientServerConfig m_config;                                    ///< Base client/server config.
        Allocator m_allocator;                                          ///< Allocator passed in to constructor.
        Adapter m_adapter;                                              ///< The adapter specifies the allocator to use, and the message factory class.
        object m_context;                                               ///< Optional serialization context.
        int m_maxClients;                                               ///< Maximum number of clients supported.
        bool m_running;                                                 ///< True if server is currently running, eg. after "Start" is called, before "Stop".
        double m_time;                                                  ///< Current server time in seconds.
        byte[] m_globalMemory;                                          ///< The block of memory backing the global allocator. Allocated with m_allocator.
        byte[][] m_clientMemory = new byte[yojimbo.MaxClients][];       ///< The block of memory backing the per-client allocators. Allocated with m_allocator.
        Allocator m_globalAllocator;                                    ///< The global allocator. Used for allocations that don't belong to a specific client.
        Allocator[] m_clientAllocator = new Allocator[yojimbo.MaxClients];                      ///< Array of per-client allocator. These are used for allocations related to connected clients.
        MessageFactory[] m_clientMessageFactory = new MessageFactory[yojimbo.MaxClients];       ///< Array of per-client message factories. This silos message allocations per-client slot.
        Connection[] m_clientConnection = new Connection[yojimbo.MaxClients];                   ///< Array of per-client connection classes. This is how messages are exchanged with clients.
        reliable_endpoint_t[] m_clientEndpoint = new reliable_endpoint_t[yojimbo.MaxClients];   ///< Array of per-client reliable.io endpoints.
        NetworkSimulator m_networkSimulator;                            ///< The network simulator used to simulate packet loss, latency, jitter etc. Optional. 
        byte[] m_packetBuffer;                                          ///< Buffer used when writing packets.
    }

    /**
        Dedicated server implementation.
     */
    public class Server : BaseServer
    {
        public Server(Allocator allocator, byte[] privateKey, Address address, ClientServerConfig config, Adapter adapter, double time)
            : base(allocator, config, adapter, time)
        {
            yojimbo.assert(yojimbo.KeyBytes == netcode.KEY_BYTES);
            BufferEx.Copy(m_privateKey, privateKey, netcode.KEY_BYTES);
            m_address = new Address(address);
            m_boundAddress = new Address(address);
            m_config = config;
            m_server = null;
        }

        public override void Dispose()
        {
            // IMPORTANT: Please stop the server before destroying it!
            yojimbo.assert(m_server == null);
        }

        public override void Start(int maxClients)
        {
            if (IsRunning)
                Stop();

            base.Start(maxClients);

            var addressString = m_address.ToString();

            netcode.default_server_config(out var netcodeConfig);
            netcodeConfig.protocol_id = m_config.protocolId;
            BufferEx.Copy(netcodeConfig.private_key, m_privateKey, netcode.KEY_BYTES);
            netcodeConfig.allocator_context = GlobalAllocator;
            netcodeConfig.allocate_function = StaticAllocateFunction;
            netcodeConfig.free_function = StaticFreeFunction;
            netcodeConfig.callback_context = this;
            netcodeConfig.connect_disconnect_callback = StaticConnectDisconnectCallbackFunction;
            netcodeConfig.send_loopback_packet_callback = StaticSendLoopbackPacketCallbackFunction;

            m_server = netcode.server_create(addressString, netcodeConfig, Time);

            if (m_server == null)
            {
                Stop();
                return;
            }

            netcode.server_start(m_server, maxClients);

            m_boundAddress.Port = netcode.server_get_port(m_server);
        }

        public override void Stop()
        {
            if (m_server != null)
            {
                m_boundAddress = new Address(m_address);
                netcode.server_stop(m_server);
                netcode.server_destroy(ref m_server);
                m_server = null;
            }
            base.Stop();
        }

        public override void DisconnectClient(int clientIndex)
        {
            yojimbo.assert(m_server != null);
            netcode.server_disconnect_client(m_server, clientIndex);
        }

        public override void DisconnectAllClients()
        {
            yojimbo.assert(m_server != null);
            netcode.server_disconnect_all_clients(m_server);
        }

        public override void SendPackets()
        {
            if (m_server != null)
            {
                var maxClients = MaxClients;
                for (var i = 0; i < maxClients; ++i)
                {
                    if (IsClientConnected(i))
                    {
                        var packetData = PacketBuffer;
                        var packetSequence = reliable.endpoint_next_packet_sequence(GetClientEndpoint(i));
                        if (GetClientConnection(i).GeneratePacket(Context, packetSequence, packetData, m_config.maxPacketSize, out var packetBytes))
                            reliable.endpoint_send_packet(GetClientEndpoint(i), packetData, packetBytes);
                    }
                }
            }
        }

        public override void ReceivePackets()
        {
            if (m_server != null)
            {
                var maxClients = MaxClients;
                for (var clientIndex = 0; clientIndex < maxClients; ++clientIndex)
                    while (true)
                    {
                        var packetData = netcode.server_receive_packet(m_server, clientIndex, out var packetBytes, out var packetSequence);
                        if (packetData == null)
                            break;
                        reliable.endpoint_receive_packet(GetClientEndpoint(clientIndex), packetData, packetBytes);
                        netcode.server_free_packet(m_server, ref packetData);
                    }
            }
        }

        public override void AdvanceTime(double time)
        {
            if (m_server != null)
                netcode.server_update(m_server, time);
            base.AdvanceTime(time);
            var networkSimulator = NetworkSimulator;
            if (networkSimulator != null && networkSimulator.IsActive)
            {
                var packetData = new byte[m_config.maxSimulatorPackets][];
                var packetBytes = new int[m_config.maxSimulatorPackets];
                var to = new int[m_config.maxSimulatorPackets];
                var numPackets = networkSimulator.ReceivePackets(m_config.maxSimulatorPackets, packetData, packetBytes, to);
                for (var i = 0; i < numPackets; ++i)
                {
                    netcode.server_send_packet(m_server, to[i], packetData[i], packetBytes[i]);
                    packetData[i] = null;
                }
            }
        }

        public override bool IsClientConnected(int clientIndex) =>
            netcode.server_client_connected(m_server, clientIndex);

        public override ulong GetClientId(int clientIndex) =>
            netcode.server_client_id(m_server, clientIndex);

        public override int NumConnectedClients =>
            netcode.server_num_connected_clients(m_server);

        public override void ConnectLoopbackClient(int clientIndex, ulong clientId, byte[] userData) =>
            netcode.server_connect_loopback_client(m_server, clientIndex, clientId, userData);

        public override void DisconnectLoopbackClient(int clientIndex) =>
            netcode.server_disconnect_loopback_client(m_server, clientIndex);

        public override bool IsLoopbackClient(int clientIndex) =>
            netcode.server_client_loopback(m_server, clientIndex);

        public override void ProcessLoopbackPacket(int clientIndex, byte[] packetData, int packetBytes, ulong packetSequence) =>
            netcode.server_process_loopback_packet(m_server, clientIndex, packetData, packetBytes, packetSequence);

        public Address Address => m_boundAddress;

        protected override void TransmitPacketFunction(int clientIndex, ushort packetSequence, byte[] packetData, int packetBytes)
        {
            var networkSimulator = NetworkSimulator;
            if (networkSimulator != null && networkSimulator.IsActive)
                networkSimulator.SendPacket(clientIndex, packetData, packetBytes);
            else
                netcode.server_send_packet(m_server, clientIndex, packetData, packetBytes);
        }

        protected override bool ProcessPacketFunction(int clientIndex, ushort packetSequence, byte[] packetData, int packetBytes) =>
            GetClientConnection(clientIndex).ProcessPacket(Context, packetSequence, packetData, packetBytes);

        void ConnectDisconnectCallbackFunction(int clientIndex, int connected)
        {
            if (connected == 0)
            {
                Adapter.OnServerClientDisconnected(clientIndex);
                reliable.endpoint_reset(GetClientEndpoint(clientIndex));
                GetClientConnection(clientIndex).Reset();
                var networkSimulator = NetworkSimulator;
                if (networkSimulator != null && networkSimulator.IsActive)
                    networkSimulator.DiscardClientPackets(clientIndex);
            }
            else
                Adapter.OnServerClientConnected(clientIndex);
        }

        void SendLoopbackPacketCallbackFunction(int clientIndex, byte[] packetData, int packetBytes, ulong packetSequence) =>
            Adapter.ServerSendLoopbackPacket(clientIndex, packetData, packetBytes, packetSequence);

        static void StaticConnectDisconnectCallbackFunction(object context, int clientIndex, int connected)
        {
            var server = (Server)context;
            server.ConnectDisconnectCallbackFunction(clientIndex, connected);
        }

        static void StaticSendLoopbackPacketCallbackFunction(object context, int clientIndex, byte[] packetData, int packetBytes, ulong packetSequence)
        {
            var server = (Server)context;
            server.SendLoopbackPacketCallbackFunction(clientIndex, packetData, packetBytes, packetSequence);
        }

        ClientServerConfig m_config;
        netcode_server_t m_server;
        Address m_address;                                  // original address passed to ctor
        Address m_boundAddress;                             // address after socket bind, eg. valid port
        byte[] m_privateKey = new byte[yojimbo.KeyBytes];
    }

    #endregion

    #region Client

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
        void ConnectLoopback(int clientIndex, ulong clientId, int maxClients);

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

    /**
        Functionality that is common across all client implementations.
     */
    public abstract class BaseClient : IClient
    {
        /**
            Base client constructor.
            @param allocator The allocator for all memory used by the client.
            @param config The base client/server configuration.
            @param time The current time in seconds. See ClientInterface::AdvanceTime
            @param allocator The adapter to the game program. Specifies allocators, message factory to use etc.
         */
        public BaseClient(Allocator allocator, ClientServerConfig config, Adapter adapter, double time)
        {
            m_config = config;
            m_allocator = allocator;
            m_adapter = adapter;
            m_time = time;
            m_context = null;
            m_clientMemory = null;
            m_clientAllocator = null;
            m_endpoint = null;
            m_connection = null;
            m_messageFactory = null;
            m_networkSimulator = null;
            m_clientState = ClientState.CLIENT_STATE_DISCONNECTED;
            m_clientIndex = -1;
            m_packetBuffer = new byte[config.maxPacketSize];
        }

        public virtual void Dispose()
        {
            // IMPORTANT: Please disconnect the client before destroying it
            yojimbo.assert(m_clientState <= ClientState.CLIENT_STATE_DISCONNECTED);
            m_packetBuffer = null;
            m_allocator = null;
        }

        public virtual object Context
        {
            get => m_context;
            set { yojimbo.assert(IsDisconnected); m_context = value; }
        }

        public virtual void Disconnect()
        {
            SetClientState(ClientState.CLIENT_STATE_DISCONNECTED);
        }

        public virtual void AdvanceTime(double time)
        {
            m_time = time;
            if (m_endpoint != null)
            {
                m_connection.AdvanceTime(time);
                if (m_connection.ErrorLevel != ConnectionErrorLevel.CONNECTION_ERROR_NONE)
                {
                    yojimbo.printf(yojimbo.LOG_LEVEL_DEBUG, "connection error. disconnecting client\n");
                    Disconnect();
                    return;
                }
                reliable.endpoint_update(m_endpoint, m_time);
                var acks = reliable.endpoint_get_acks(m_endpoint, out var numAcks);
                m_connection.ProcessAcks(acks, numAcks);
                reliable.endpoint_clear_acks(m_endpoint);
            }
            var networkSimulator = NetworkSimulator;
            if (networkSimulator != null)
                networkSimulator.AdvanceTime(time);
        }

        public virtual bool IsConnecting => m_clientState == ClientState.CLIENT_STATE_CONNECTING;

        public virtual bool IsConnected => m_clientState == ClientState.CLIENT_STATE_CONNECTED;

        public virtual bool IsDisconnected => m_clientState <= ClientState.CLIENT_STATE_DISCONNECTED;

        public virtual bool ConnectionFailed => m_clientState == ClientState.CLIENT_STATE_ERROR;

        public virtual ClientState ClientState => m_clientState;

        public virtual int ClientIndex => m_clientIndex;

        public virtual double Time => m_time;

        public void SetLatency(float milliseconds)
        {
            if (m_networkSimulator != null)
                m_networkSimulator.SetLatency(milliseconds);
        }

        public void SetJitter(float milliseconds)
        {
            if (m_networkSimulator != null)
                m_networkSimulator.SetJitter(milliseconds);
        }

        public void SetPacketLoss(float percent)
        {
            if (m_networkSimulator != null)
                m_networkSimulator.SetPacketLoss(percent);
        }

        public void SetDuplicates(float percent)
        {
            if (m_networkSimulator != null)
                m_networkSimulator.SetDuplicates(percent);
        }

        public virtual Message CreateMessage(int type)
        {
            yojimbo.assert(m_messageFactory != null);
            return m_messageFactory.CreateMessage(type);
        }

        public virtual byte[] AllocateBlock(int bytes) =>
            new byte[bytes];

        public virtual void AttachBlockToMessage(Message message, byte[] block, int bytes)
        {
            yojimbo.assert(message != null);
            yojimbo.assert(block != null);
            yojimbo.assert(bytes > 0);
            yojimbo.assert(message.IsBlockMessage);
            var blockMessage = (BlockMessage)message;
            blockMessage.AttachBlock(m_clientAllocator, block, bytes);
        }

        public virtual void FreeBlock(ref byte[] block)
        {
            block = null;
        }

        public virtual bool CanSendMessage(int channelIndex)
        {
            yojimbo.assert(m_connection != null);
            return m_connection.CanSendMessage(channelIndex);
        }

        public bool HasMessagesToSend(int channelIndex)
        {
            yojimbo.assert(m_connection != null);
            return m_connection.HasMessagesToSend(channelIndex);
        }

        public virtual void SendMessage(int channelIndex, Message message)
        {
            yojimbo.assert(m_connection != null);
            m_connection.SendMessage(channelIndex, message, Context);
        }

        public virtual Message ReceiveMessage(int channelIndex)
        {
            yojimbo.assert(m_connection != null);
            return m_connection.ReceiveMessage(channelIndex);
        }

        public virtual void ReleaseMessage<TMessage>(ref TMessage message) where TMessage : Message
        {
            yojimbo.assert(m_connection != null);
            m_connection.ReleaseMessage(ref message);
        }

        public virtual void GetNetworkInfo(out NetworkInfo info)
        {
            info = new NetworkInfo();
            if (m_connection != null)
            {
                yojimbo.assert(m_endpoint != null);
                var counters = reliable.endpoint_counters(m_endpoint);
                info.numPacketsSent = counters[reliable.ENDPOINT_COUNTER_NUM_PACKETS_SENT];
                info.numPacketsReceived = counters[reliable.ENDPOINT_COUNTER_NUM_PACKETS_RECEIVED];
                info.numPacketsAcked = counters[reliable.ENDPOINT_COUNTER_NUM_PACKETS_ACKED];
                info.RTT = reliable.endpoint_rtt(m_endpoint);
                info.packetLoss = reliable.endpoint_packet_loss(m_endpoint);
                reliable.endpoint_bandwidth(m_endpoint, out info.sentBandwidth, out info.receivedBandwidth, out info.ackedBandwidth);
            }
        }

        protected byte[] PacketBuffer => m_packetBuffer;

        protected Adapter Adapter { get { yojimbo.assert(m_adapter != null); return m_adapter; } }

        protected void CreateInternal()
        {
            yojimbo.assert(m_allocator != null);
            yojimbo.assert(m_adapter != null);
            yojimbo.assert(m_clientMemory == null);
            yojimbo.assert(m_clientAllocator == null);
            yojimbo.assert(m_messageFactory == null);
            m_clientMemory = new byte[m_config.clientMemory];
            m_clientAllocator = m_adapter.CreateAllocator(m_allocator, m_clientMemory, m_config.clientMemory);
            m_messageFactory = m_adapter.CreateMessageFactory(m_clientAllocator);
            m_connection = new Connection(m_clientAllocator, m_messageFactory, m_config, m_time);
            yojimbo.assert(m_connection != null);
            if (m_config.networkSimulator)
                m_networkSimulator = new NetworkSimulator(m_clientAllocator, m_config.maxSimulatorPackets, m_time);
            reliable.default_config(out var reliable_config);
            reliable_config.name = "client endpoint";
            reliable_config.context = this;
            reliable_config.max_packet_size = m_config.maxPacketSize;
            reliable_config.fragment_above = m_config.fragmentPacketsAbove;
            reliable_config.max_fragments = m_config.maxPacketFragments;
            reliable_config.fragment_size = m_config.packetFragmentSize;
            reliable_config.ack_buffer_size = m_config.ackedPacketsBufferSize;
            reliable_config.received_packets_buffer_size = m_config.receivedPacketsBufferSize;
            reliable_config.fragment_reassembly_buffer_size = m_config.packetReassemblyBufferSize;
            reliable_config.transmit_packet_function = StaticTransmitPacketFunction;
            reliable_config.process_packet_function = StaticProcessPacketFunction;
            reliable_config.allocator_context = m_clientAllocator;
            reliable_config.allocate_function = StaticAllocateFunction;
            reliable_config.free_function = StaticFreeFunction;
            m_endpoint = reliable.endpoint_create(reliable_config, m_time);
            reliable.endpoint_reset(m_endpoint);
        }

        protected void DestroyInternal()
        {
            yojimbo.assert(m_allocator != null);
            if (m_endpoint != null)
            {
                reliable.endpoint_destroy(ref m_endpoint);
                m_endpoint = null;
            }
            m_networkSimulator?.Dispose(); m_networkSimulator = null;
            m_connection?.Dispose(); m_connection = null;
            m_messageFactory?.Dispose(); m_messageFactory = null;
            m_clientAllocator?.Dispose(); m_clientAllocator = null;
            m_clientMemory = null;
        }

        protected void SetClientState(ClientState clientState)
        {
            m_clientState = clientState;
        }

        protected Allocator ClientAllocator { get { yojimbo.assert(m_clientAllocator != null); return m_clientAllocator; } }

        protected MessageFactory MessageFactory { get { yojimbo.assert(m_messageFactory != null); return m_messageFactory; } }

        protected NetworkSimulator NetworkSimulator => m_networkSimulator;

        protected reliable_endpoint_t Endpoint => m_endpoint;

        protected Connection Connection { get { yojimbo.assert(m_connection != null); return m_connection; } }

        public abstract ulong ClientId { get; }
        public abstract bool IsLoopback { get; }

        protected abstract void TransmitPacketFunction(ushort packetSequence, byte[] packetData, int packetBytes);

        protected abstract bool ProcessPacketFunction(ushort packetSequence, byte[] packetData, int packetBytes);

        protected static void StaticTransmitPacketFunction(object context, int index, ushort packetSequence, byte[] packetData, int packetBytes)
        {
            var client = (BaseClient)context;
            client.TransmitPacketFunction(packetSequence, packetData, packetBytes);
        }

        protected static bool StaticProcessPacketFunction(object context, int index, ushort packetSequence, byte[] packetData, int packetBytes)
        {
            var client = (BaseClient)context;
            return client.ProcessPacketFunction(packetSequence, packetData, packetBytes);
        }

        protected static object StaticAllocateFunction(object context, ulong bytes) => null;

        protected static void StaticFreeFunction(object context, object pointer) { }

        public abstract void SendPackets();
        public abstract void ReceivePackets();
        public abstract void ConnectLoopback(int clientIndex, ulong clientId, int maxClients);
        public abstract void DisconnectLoopback();
        public abstract void ProcessLoopbackPacket(byte[] packetData, int packetBytes, ulong packetSequence);

        ClientServerConfig m_config;                                        ///< The client/server configuration.
        Allocator m_allocator;                                              ///< The allocator passed to the client on creation.
        Adapter m_adapter;                                                  ///< The adapter specifies the allocator to use, and the message factory class.
        object m_context;                                                   ///< Context lets the user pass information to packet serialize functions.
        byte[] m_clientMemory;                                              ///< The memory backing the client allocator. Allocated from m_allocator.
        Allocator m_clientAllocator;                                        ///< The client allocator. Everything allocated between connect and disconnected is allocated and freed via this allocator.
        reliable_endpoint_t m_endpoint;                                     ///< reliable.io endpoint.
        MessageFactory m_messageFactory;                                    ///< The client message factory. Created and destroyed on each connection attempt.
        Connection m_connection;                                            ///< The client connection for exchanging messages with the server.
        NetworkSimulator m_networkSimulator;                                ///< The network simulator used to simulate packet loss, latency, jitter etc. Optional. 
        ClientState m_clientState;                                          ///< The current client state. See ClientInterface::GetClientState
        int m_clientIndex;                                                  ///< The client slot index on the server [0,maxClients-1]. -1 if not connected.
        double m_time;                                                      ///< The current client time. See ClientInterface::AdvanceTime
        byte[] m_packetBuffer;                                              ///< Buffer used to read and write packets.

        //BaseClient( const BaseClient & other );
        //const BaseClient & operator = ( const BaseClient & other );
    }

    /**
        Implementation of client for dedicated servers.
     */
    public class Client : BaseClient
    {
        /**
            The client constructor.
            @param allocator The allocator for all memory used by the client.
            @param address The address the client should bind to.
            @param config The client/server configuration.
            @param time The current time in seconds. See ClientInterface::AdvanceTime
         */
        public Client(Allocator allocator, Address address, ClientServerConfig config, Adapter adapter, double time)
            : base(allocator, config, adapter, time)
        {
            m_config = config;
            m_address = new Address(address);
            m_clientId = 0;
            m_client = null;
            m_boundAddress = new Address(address);
        }

        public override void Dispose()
        {
            // IMPORTANT: Please disconnect the client before destroying it
            yojimbo.assert(m_client == null);
        }

        public void InsecureConnect(byte[] privateKey, ulong clientId, Address address) =>
            InsecureConnect(privateKey, clientId, new[] { address }, 1);
        public void InsecureConnect(byte[] privateKey, ulong clientId, Address[] serverAddresses, int numServerAddresses)
        {
            yojimbo.assert(serverAddresses != null);
            yojimbo.assert(numServerAddresses > 0);
            yojimbo.assert(numServerAddresses <= netcode.MAX_SERVERS_PER_CONNECT);
            Disconnect();
            CreateInternal();
            m_clientId = clientId;
            CreateClient(m_address);
            if (m_client == null)
            {
                Disconnect();
                return;
            }
            var connectToken = new byte[netcode.CONNECT_TOKEN_BYTES];
            if (!GenerateInsecureConnectToken(connectToken, privateKey, clientId, serverAddresses, numServerAddresses))
            {
                yojimbo.printf(yojimbo.LOG_LEVEL_ERROR, "error: failed to generate insecure connect token\n");
                SetClientState(ClientState.CLIENT_STATE_ERROR);
                return;
            }
            netcode.client_connect(m_client, connectToken);
            SetClientState(ClientState.CLIENT_STATE_CONNECTING);
        }

        public void Connect(ulong clientId, byte[] connectToken)
        {
            yojimbo.assert(connectToken != null);
            Disconnect();
            CreateInternal();
            m_clientId = clientId;
            CreateClient(m_address);
            netcode.client_connect(m_client, connectToken);
            if (netcode.client_state(m_client) > netcode.CLIENT_STATE_DISCONNECTED)
                SetClientState(ClientState.CLIENT_STATE_CONNECTING);
            else
                Disconnect();
        }

        public override void Disconnect()
        {
            base.Disconnect();
            DestroyClient();
            DestroyInternal();
            m_clientId = 0;
        }

        public override void SendPackets()
        {
            if (!IsConnected)
                return;
            yojimbo.assert(m_client != null);
            var packetData = PacketBuffer;
            var packetSequence = reliable.endpoint_next_packet_sequence(Endpoint);
            if (Connection.GeneratePacket(Context, packetSequence, packetData, m_config.maxPacketSize, out var packetBytes))
                reliable.endpoint_send_packet(Endpoint, packetData, packetBytes);
        }

        public override void ReceivePackets()
        {
            if (!IsConnected)
                return;
            yojimbo.assert(m_client != null);
            while (true)
            {
                var packetData = netcode.client_receive_packet(m_client, out var packetBytes, out var packetSequence);
                if (packetData == null)
                    break;
                reliable.endpoint_receive_packet(Endpoint, packetData, packetBytes);
                netcode.client_free_packet(m_client, ref packetData);
            }
        }

        public override void AdvanceTime(double time)
        {
            base.AdvanceTime(time);
            if (m_client != null)
            {
                netcode.client_update(m_client, time);
                var state = netcode.client_state(m_client);
                if (state < netcode.CLIENT_STATE_DISCONNECTED)
                {
                    Disconnect();
                    SetClientState(ClientState.CLIENT_STATE_ERROR);
                }
                else if (state == netcode.CLIENT_STATE_DISCONNECTED)
                {
                    Disconnect();
                    SetClientState(ClientState.CLIENT_STATE_DISCONNECTED);
                }
                else if (state == netcode.CLIENT_STATE_SENDING_CONNECTION_REQUEST)
                    SetClientState(ClientState.CLIENT_STATE_CONNECTING);
                else
                    SetClientState(ClientState.CLIENT_STATE_CONNECTED);
                var networkSimulator = NetworkSimulator;
                if (networkSimulator != null && networkSimulator.IsActive)
                {
                    var packetData = new byte[m_config.maxSimulatorPackets][];
                    var packetBytes = new int[m_config.maxSimulatorPackets];
                    var numPackets = networkSimulator.ReceivePackets(m_config.maxSimulatorPackets, packetData, packetBytes, null);
                    for (var i = 0; i < numPackets; ++i)
                    {
                        netcode.client_send_packet(m_client, packetData[i], packetBytes[i]);
                        packetData[i] = null;
                    }
                }
            }
        }

        public override int ClientIndex =>
            m_client != null ? netcode.client_index(m_client) : -1;

        public override ulong ClientId => m_clientId;

        public override void ConnectLoopback(int clientIndex, ulong clientId, int maxClients)
        {
            Disconnect();
            CreateInternal();
            m_clientId = clientId;
            CreateClient(m_address);
            netcode.client_connect_loopback(m_client, clientIndex, maxClients);
            SetClientState(ClientState.CLIENT_STATE_CONNECTED);
        }

        public override void DisconnectLoopback()
        {
            netcode.client_disconnect_loopback(m_client);
            base.Disconnect();
            DestroyClient();
            DestroyInternal();
            m_clientId = 0;
        }

        public override bool IsLoopback =>
            netcode.client_loopback(m_client);

        public override void ProcessLoopbackPacket(byte[] packetData, int packetBytes, ulong packetSequence) =>
            netcode.client_process_loopback_packet(m_client, packetData, packetBytes, packetSequence);

        public Address Address => m_boundAddress;

        protected bool GenerateInsecureConnectToken(
            byte[] connectToken,
            byte[] privateKey,
            ulong clientId,
            Address[] serverAddresses,
            int numServerAddresses)
        {
            //char serverAddressStrings[netcode.MAX_SERVERS_PER_CONNECT][yojimbo.MaxAddressLength];
            var serverAddressStringPointers = new string[netcode.MAX_SERVERS_PER_CONNECT];
            for (var i = 0; i < numServerAddresses; ++i)
                serverAddressStringPointers[i] = serverAddresses[i].ToString();
            var userData = new byte[256];
            return netcode.generate_connect_token(
                numServerAddresses,
                serverAddressStringPointers,
                serverAddressStringPointers,
                m_config.timeout,
                m_config.timeout,
                clientId,
                m_config.protocolId,
                privateKey,
                userData,
                connectToken) == netcode.OK;
        }

        protected void CreateClient(Address address)
        {
            DestroyClient();
            var addressString = address.ToString();

            netcode.default_client_config(out var netcodeConfig);
            netcodeConfig.allocator_context = ClientAllocator;
            netcodeConfig.allocate_function = StaticAllocateFunction;
            netcodeConfig.free_function = StaticFreeFunction;
            netcodeConfig.callback_context = this;
            netcodeConfig.state_change_callback = StaticStateChangeCallbackFunction;
            netcodeConfig.send_loopback_packet_callback = StaticSendLoopbackPacketCallbackFunction;
            m_client = netcode.client_create(addressString, netcodeConfig, Time);

            if (m_client != null)
                m_boundAddress.Port = netcode.client_get_port(m_client);
        }

        protected void DestroyClient()
        {
            if (m_client != null)
            {
                m_boundAddress = new Address(m_address);
                netcode.client_destroy(ref m_client);
                m_client = null;
            }
        }

        protected void StateChangeCallbackFunction(int previous, int current)
        {
        }

        protected static void StaticStateChangeCallbackFunction(object context, int previous, int current)
        {
            var client = (Client)context;
            client.StateChangeCallbackFunction(previous, current);
        }

        protected override void TransmitPacketFunction(ushort packetSequence, byte[] packetData, int packetBytes)
        {
            var networkSimulator = NetworkSimulator;
            if (networkSimulator != null && networkSimulator.IsActive)
                networkSimulator.SendPacket(0, packetData, packetBytes);
            else
                netcode.client_send_packet(m_client, packetData, packetBytes);
        }

        protected override bool ProcessPacketFunction(ushort packetSequence, byte[] packetData, int packetBytes) =>
            Connection.ProcessPacket(Context, packetSequence, packetData, packetBytes);

        protected void SendLoopbackPacketCallbackFunction(int clientIndex, byte[] packetData, int packetBytes, ulong packetSequence) =>
            Adapter.ClientSendLoopbackPacket(clientIndex, packetData, packetBytes, packetSequence);

        protected static void StaticSendLoopbackPacketCallbackFunction(object context, int clientIndex, byte[] packetData, int packetBytes, ulong packetSequence)
        {
            var client = (Client)context;
            client.SendLoopbackPacketCallbackFunction(clientIndex, packetData, packetBytes, packetSequence);
        }

        ClientServerConfig m_config;                    ///< Client/server configuration.
        netcode_client_t m_client;                      ///< netcode.io client data.
        Address m_address;                              ///< Original address passed to ctor.
        Address m_boundAddress;                         ///< Address after socket bind, eg. with valid port
        ulong m_clientId;                               ///< The globally unique client id (set on each call to connect)
    }

    #endregion

    #region Match

    /**
        Matcher status enum.
        Designed for when the matcher will be made non-blocking. The matcher is currently blocking in Matcher::RequestMatch
     */
    public enum MatchStatus
    {
        MATCH_IDLE,                 ///< The matcher is idle.
        MATCH_BUSY,                 ///< The matcher is requesting a match.
        MATCH_READY,                ///< The match response is ready to read with Matcher::GetConnectToken.
        MATCH_FAILED                ///< The matcher failed to find a match.
    }

    static partial class yojimbo
    {
        const string SERVER_PORT = "8080";
        const string SERVER_NAME = "localhost";
    }

    public class MatcherInternal
    {
#if YOJIMBO_WITH_MBEDTLS
        mbedtls_net_context server_fd;
        mbedtls_entropy_context entropy;
        mbedtls_ctr_drbg_context ctr_drbg;
        mbedtls_ssl_context ssl;
        mbedtls_ssl_config conf;
        mbedtls_x509_crt cacert;
#endif
    }

    /**
        Communicates with the matcher web service over HTTPS.
        See docker/matcher/matcher.go for details. Launch the matcher via "premake5 matcher".
        This class will be improved in the future, most importantly to make Matcher::RequestMatch a non-blocking operation.
     */
    public class Matcher
    {
        /**
            Matcher constructor.
            @param allocator The allocator to use for allocations.
         */
        public Matcher(Allocator allocator)
        {
#if YOJIMBO_WITH_MBEDTLS
        assert( ConnectTokenBytes == NETCODE_CONNECT_TOKEN_BYTES );
        m_allocator = &allocator;
        m_initialized = false;
        m_matchStatus = MATCH_IDLE;
        m_internal = YOJIMBO_NEW( allocator, MatcherInternal );
        memset( m_connectToken, 0, sizeof( m_connectToken ) );
#endif
        }

        /**
            Matcher destructor.
         */
        public void Dispose()
        {
#if YOJIMBO_WITH_MBEDTLS
        mbedtls_net_free( &m_internal.server_fd );
        mbedtls_x509_crt_free( &m_internal.cacert );
        mbedtls_ssl_free( &m_internal.ssl );
        mbedtls_ssl_config_free( &m_internal.conf );
        mbedtls_ctr_drbg_free( &m_internal.ctr_drbg );
        mbedtls_entropy_free( &m_internal.entropy );
        m_internal?.Dispose(); m_internal = null;
#endif
        }

        /**
            Initialize the matcher. 
            @returns True if the matcher initialized successfully, false otherwise.
         */
        public bool Initialize()
        {
#if YOJIMBO_WITH_MBEDTLS
		
		const char * pers = "yojimbo_client";

        mbedtls_net_init( &m_internal.server_fd );
        mbedtls_ssl_init( &m_internal.ssl );
        mbedtls_ssl_config_init( &m_internal.conf );
        mbedtls_x509_crt_init( &m_internal.cacert );
        mbedtls_ctr_drbg_init( &m_internal.ctr_drbg );
        mbedtls_entropy_init( &m_internal.entropy );

        int result;

        if ( ( result = mbedtls_ctr_drbg_seed( &m_internal.ctr_drbg, mbedtls_entropy_func, &m_internal.entropy, (const unsigned char *) pers, strlen( pers ) ) ) != 0 )
        {
            yojimbo_printf( YOJIMBO_LOG_LEVEL_ERROR, $"error: mbedtls_ctr_drbg_seed failed ({result})\n");
            return false;
        }

        if ( mbedtls_x509_crt_parse( &m_internal.cacert, (const unsigned char *) mbedtls_test_cas_pem, mbedtls_test_cas_pem_len ) < 0 )
        {
            yojimbo_printf( YOJIMBO_LOG_LEVEL_ERROR, $"error: mbedtls_x509_crt_parse failed ({result})\n");
            return false;
        }

        memset( m_connectToken, 0, sizeof( m_connectToken ) );
#endif
            m_initialized = true;
            return true;
        }

        /** 
            Request a match.
            This is how clients get connect tokens from matcher.go. 
            They request a match and the server replies with a set of servers to connect to, and a connect token to pass to that server.
            IMPORTANT: This function is currently blocking. It will be made non-blocking in the near future.
            @param protocolId The protocol id that we are using. Used to filter out servers with different protocol versions.
            @param clientId A unique client identifier that identifies each client to your back end services. If you don't have this yet, just roll a random 64 bit number.
            @see Matcher::GetMatchStatus
            @see Matcher::GetConnectToken
         */
        public void RequestMatch(ulong protocolId, ulong clientId, bool verifyCertificate)
        {
#if YOJIMBO_WITH_MBEDTLS
		
		assert( m_initialized );

        const char * data;
        char request[1024];
        int bytesRead = 0;

        int result;

        if ( ( result = mbedtls_net_connect( &m_internal.server_fd, SERVER_NAME, SERVER_PORT, MBEDTLS_NET_PROTO_TCP ) ) != 0 )
        {
            yojimbo_printf( YOJIMBO_LOG_LEVEL_ERROR, $"error: mbedtls_net_connect failed ({result})\n",  );
            m_matchStatus = MATCH_FAILED;
            goto cleanup;
        }

        if ( ( result = mbedtls_ssl_config_defaults( &m_internal.conf,
                        MBEDTLS_SSL_IS_CLIENT,
                        MBEDTLS_SSL_TRANSPORT_STREAM,
                        MBEDTLS_SSL_PRESET_DEFAULT ) ) != 0 )
        
            yojimbo_printf( YOJIMBO_LOG_LEVEL_ERROR, $"error: mbedtls_net_connect failed ({result})\n",  );
            m_matchStatus = MATCH_FAILED;
            goto cleanup;
        }

        mbedtls_ssl_conf_authmode( &m_internal.conf, verifyCertificate ? MBEDTLS_SSL_VERIFY_REQUIRED : MBEDTLS_SSL_VERIFY_OPTIONAL );
        mbedtls_ssl_conf_ca_chain( &m_internal.conf, &m_internal.cacert, null );
        mbedtls_ssl_conf_rng( &m_internal.conf, mbedtls_ctr_drbg_random, &m_internal.ctr_drbg );

        if ( ( result = mbedtls_ssl_setup( &m_internal.ssl, &m_internal.conf ) ) != 0 )
        {
            yojimbo_printf( YOJIMBO_LOG_LEVEL_ERROR, $"error: mbedtls_ssl_setup failed ({result})\n");
            m_matchStatus = MATCH_FAILED;
            goto cleanup;
        }

        if ( ( result = mbedtls_ssl_set_hostname( &m_internal.ssl, "yojimbo" ) ) != 0 )
        {
            yojimbo_printf( YOJIMBO_LOG_LEVEL_ERROR, $"error: mbedtls_ssl_set_hostname failed ({result})\n");
            m_matchStatus = MATCH_FAILED;
            goto cleanup;
        }

        mbedtls_ssl_set_bio( &m_internal.ssl, &m_internal.server_fd, mbedtls_net_send, mbedtls_net_recv, null );

        while ( ( result = mbedtls_ssl_handshake( &m_internal.ssl ) ) != 0 )
        {
            if ( result != MBEDTLS_ERR_SSL_WANT_READ && result != MBEDTLS_ERR_SSL_WANT_WRITE )
            {
                yojimbo_printf( YOJIMBO_LOG_LEVEL_ERROR, $"error: mbedtls_ssl_handshake failed ({result})\n");
                m_matchStatus = MATCH_FAILED;
                goto cleanup;
            }
        }

        if ( verifyCertificate )
        {
            uint flags;
            if ( ( flags = mbedtls_ssl_get_verify_result( &m_internal.ssl ) ) != 0 )
            {
                // IMPORTANT: certificate verification failed!
                yojimbo_printf( YOJIMBO_LOG_LEVEL_ERROR, "error: mbedtls_ssl_get_verify_result failed - flags = %x\n", flags );
                m_matchStatus = MATCH_FAILED;
                goto cleanup;
            }
        }
        
        sprintf( request, "GET /match/%" PRIu64 "/%" PRIu64 " HTTP/1.0\r\n\r\n", protocolId, clientId );

        yojimbo_printf( YOJIMBO_LOG_LEVEL_DEBUG, "match request:\n" );
        yojimbo_printf( YOJIMBO_LOG_LEVEL_DEBUG, "%s\n", request );

        while ( ( result = mbedtls_ssl_write( &m_internal.ssl, (uint8_t*) request, strlen( request ) ) ) <= 0 )
        {
            if ( result != MBEDTLS_ERR_SSL_WANT_READ && result != MBEDTLS_ERR_SSL_WANT_WRITE )
            {
                yojimbo_printf( YOJIMBO_LOG_LEVEL_ERROR, $"error: mbedtls_ssl_write failed ({result})\n");
                m_matchStatus = MATCH_FAILED;
                goto cleanup;
            }
        }

        char buffer[2*ConnectTokenBytes];
        memset( buffer, 0, sizeof( buffer ) );
        do
        {
            result = mbedtls_ssl_read( &m_internal.ssl, (uint8_t*) ( buffer + bytesRead ), sizeof( buffer ) - bytesRead - 1 );

            if ( result == MBEDTLS_ERR_SSL_WANT_READ || result == MBEDTLS_ERR_SSL_WANT_WRITE )
                continue;

            if ( result == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY )
                break;

            if ( result <= 0 )
                break;

            bytesRead += result;
        }
        while( 1 );

        assert( bytesRead <= (int) sizeof( buffer ) );

        data = strstr( (const char*)buffer, "\r\n\r\n" );
        if ( !data )
        {
            yojimbo_printf( YOJIMBO_LOG_LEVEL_ERROR, "error: invalid http response from matcher\n" );
            m_matchStatus = MATCH_FAILED;
            goto cleanup;
        }

        while ( *data == 13 || *data == 10 )
            ++data;

        yojimbo_printf( YOJIMBO_LOG_LEVEL_DEBUG, "================================================\n%s\n================================================\n", data );

        result = base64_decode_data( data, m_connectToken, sizeof( m_connectToken ) );
        if ( result == ConnectTokenBytes )
        {
            m_matchStatus = MATCH_READY;
        }
        else
        {
            yojimbo_printf( YOJIMBO_LOG_LEVEL_ERROR, "error: failed to decode connect token base64\n" );
            m_matchStatus = MATCH_FAILED;
        }

    cleanup:

        mbedtls_ssl_close_notify( &m_internal.ssl );

#else
            m_matchStatus = MatchStatus.MATCH_FAILED;
#endif
        }

        /**
            Get the current match status.
            Because Matcher::RequestMatch is currently blocking this will be MATCH_READY or MATCH_FAILED immediately after that function returns.
            If the status is MATCH_READY you can call Matcher::GetMatchResponse to get the match response data corresponding to the last call to Matcher::RequestMatch.
            @returns The current match status.
         */
        public MatchStatus MatchStatus =>
            m_matchStatus;

        /**
            Get connect token.
            This can only be called if the match status is MATCH_READY.
            @param connectToken The connect token data to fill [out].
            @see Matcher::RequestMatch
            @see Matcher::GetMatchStatus
         */
        public void GetConnectToken(byte[] connectToken)
        {
#if YOJIMBO_WITH_MBEDTLS
            yojimbo.assert(connectToken != null);
            yojimbo.assert(m_matchStatus == MATCH_READY);
            if (m_matchStatus == MATCH_READY)
                memcpy(connectToken, m_connectToken, ConnectTokenBytes);
#else
            yojimbo.assert(false);
#endif
        }

        internal Matcher(Matcher matcher)
        {
        }

        //const Matcher & operator = ( const Matcher & other );

        Allocator m_allocator;                                ///< The allocator passed into the constructor.
        bool m_initialized;                                     ///< True if the matcher was successfully initialized. See Matcher::Initialize.
        MatchStatus m_matchStatus;                              ///< The current match status.
#if YOJIMBO_WITH_MBEDTLS
		MatcherInternal m_internal;                    ///< Internals are in here to avoid spilling details of mbedtls library outside of yojimbo_matcher.cpp
        byte[] m_connectToken = new byte[yojimbo.ConnectTokenBytes];              ///< The connect token data from the last call to Matcher::RequestMatch once the match status is MATCH_READY.
#endif
    }

    #endregion
}
