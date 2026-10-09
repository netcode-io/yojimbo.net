/*
    reliable

    Copyright © 2017 - 2026, Más Bandwidth LLC

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
    C# port of reliable 1.4.5 (upstream cpp/reliable/reliable.c). Function order follows reliable.c so upstream
    diffs map cleanly. Logging is on by default; define RELIABLE_DISABLE_LOGGING to compile it out.
*/

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Reflection;
using System.Reflection.Emit;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace networkprotocol
{
    #region reliable_h

    public static partial class reliable
    {
        public const string VERSION_FULL = "1.4.5";
        public const int VERSION_MAJOR = 1;
        public const int VERSION_MINOR = 4;
        public const int VERSION_PATCH = 5;

        public const int ENDPOINT_COUNTER_NUM_PACKETS_SENT = 0;
        public const int ENDPOINT_COUNTER_NUM_PACKETS_RECEIVED = 1;
        public const int ENDPOINT_COUNTER_NUM_PACKETS_ACKED = 2;
        public const int ENDPOINT_COUNTER_NUM_PACKETS_STALE = 3;
        public const int ENDPOINT_COUNTER_NUM_PACKETS_INVALID = 4;
        public const int ENDPOINT_COUNTER_NUM_PACKETS_TOO_LARGE_TO_SEND = 5;
        public const int ENDPOINT_COUNTER_NUM_PACKETS_TOO_LARGE_TO_RECEIVE = 6;
        public const int ENDPOINT_COUNTER_NUM_FRAGMENTS_SENT = 7;
        public const int ENDPOINT_COUNTER_NUM_FRAGMENTS_RECEIVED = 8;
        public const int ENDPOINT_COUNTER_NUM_FRAGMENTS_INVALID = 9;
        public const int ENDPOINT_COUNTER_NUM_PACKETS_DUPLICATE = 10;
        public const int ENDPOINT_NUM_COUNTERS = 11;

        public const int MAX_PACKET_HEADER_BYTES = 9;
        public const int FRAGMENT_HEADER_BYTES = 5;

        public const int LOG_LEVEL_NONE = 0;
        public const int LOG_LEVEL_ERROR = 1;
        public const int LOG_LEVEL_INFO = 2;
        public const int LOG_LEVEL_DEBUG = 3;

        public const int OK = 1;
        public const int ERROR = 0;

        [DebuggerStepThrough, Conditional("DEBUG")]
        public static void assert(bool condition, [CallerArgumentExpression(nameof(condition))] string condition_text = null)
        {
            if (!condition)
            {
                var stackFrame = new StackTrace(1, true).GetFrame(0);
                assert_function?.Invoke(condition_text, stackFrame?.GetMethod()?.Name, stackFrame?.GetFileName(), stackFrame?.GetFileLineNumber() ?? 0);
                Environment.Exit(1);
            }
        }
    }

    public class reliable_config_t
    {
        public string name;                                                     // name of the endpoint. used in log output
        public object context;                                                  // passed to the transmit and process packet callbacks
        public ulong id;                                                        // id of the endpoint. passed to callbacks so shared callbacks can tell endpoints apart
        public int max_packet_size;                                             // maximum packet size that can be sent or received (bytes)
        public int fragment_above;                                              // packets larger than this many bytes are sent as fragments
        public int max_fragments;                                               // maximum number of fragments per-packet. 256 max. must cover max_packet_size / fragment_size
        public int fragment_size;                                               // size of each fragment (bytes)
        public int ack_buffer_size;                                             // maximum number of acks buffered between calls to endpoint_clear_acks
        public int sent_packets_buffer_size;                                    // number of sent packets tracked for acks, packet loss and bandwidth stats
        public int received_packets_buffer_size;                                // number of received packets tracked. also the window for stale and duplicate packet rejection
        public int fragment_reassembly_buffer_size;                             // number of packets that can be under reassembly from fragments at the same time
        public float rtt_smoothing_factor;                                      // exponential smoothing factor for the rtt moving average
        public int rtt_history_size;                                            // number of rtt samples kept for min/max/avg rtt and jitter
        public float packet_loss_smoothing_factor;                              // exponential smoothing factor for packet loss
        public float bandwidth_smoothing_factor;                                // exponential smoothing factor for bandwidth
        public int packet_header_size;                                          // assumed network header overhead per-packet, used only for bandwidth stats. 28 = IPv4 + UDP
        public Action<object, ulong, ushort, byte[], int> transmit_packet_function;     // called to send a packet: (context, id, sequence, packet_data, packet_bytes). must not send packets on the same endpoint
        public Func<object, ulong, ushort, byte[], int, bool> process_packet_function;  // called when a packet is received: (context, id, sequence, packet_data, packet_bytes). return true to accept and ack the packet, false to reject it (rejected packets are not acked and may be processed again if they arrive again)
        public object allocator_context;                                        // passed to the allocate and free functions
        public Func<object, ulong, object> allocate_function;                   // custom allocator (unused by the C# port: buffers are managed arrays)
        public Action<object, object> free_function;                            // custom free (unused by the C# port)

        // the endpoint keeps its own copy of the config, as reliable.c does with endpoint->config = *config
        internal reliable_config_t copy() => (reliable_config_t)MemberwiseClone();
    }

    // pointer lifetimes across the callbacks and the config:
    //
    //   transmit_packet_function
    //     packet_data                   is the endpoint's own transmit scratch buffer and is valid only for the duration of the call.
    //                                   the next send on that endpoint overwrites it, which is why the callback must not send on the
    //                                   same endpoint. packet_data.Length may exceed packet_bytes. copy the bytes if you need them later.
    //
    //   process_packet_function
    //     packet_data                   holds exactly the packet payload. it is yours to read for the duration of the call.
    //
    //   endpoint_get_acks
    //     the returned array belongs to the endpoint and is read only. it stays valid until the next call to endpoint_receive_packet,
    //     endpoint_clear_acks, endpoint_reset or endpoint_destroy on that endpoint. only the first num_acks entries are meaningful.
    //
    //   endpoint_create returns null if the config is not valid.

    #endregion

    public static partial class reliable
    {
        #region assert / logging

        static void default_assert_handler(string condition, string function, string file, int line)
        {
            Console.Write($"assert failed: ( {condition} ), function {function}, file {file}, line {line}\n");
            Console.Out.Flush();
            Debugger.Break();
            Environment.Exit(1);
        }

        static int log_level_ = 0;

        static Action<string> printf_function =
            x => Console.Write(x);

        public static Action<string, string, string, int> assert_function = default_assert_handler;

        public static void log_level(int level) =>
            log_level_ = level;

        public static void set_printf_function(Action<string> function)
        {
            assert(function != null);
            printf_function = function;
        }

        public static void set_assert_function(Action<string, string, string, int> function) =>
            assert_function = function;

        // reliable_printf. interpolated strings passed to printf are only formatted when the level is enabled, so a debug log on
        // the packet path costs nothing at the default log level (reliable.c checks the level before vsnprintf for the same reason)

#if !RELIABLE_DISABLE_LOGGING
        static void printf(int level, string format)
        {
            if (level > log_level_) return;
            printf_function(format);
        }

        static void printf(int level, [InterpolatedStringHandlerArgument("level")] ref printf_handler format)
        {
            if (!format.enabled) return;
            printf_function(format.to_string_and_clear());
        }
#else
        static void printf(int level, string format) { }

        static void printf(int level, [InterpolatedStringHandlerArgument("level")] ref printf_handler format) { }
#endif

        [InterpolatedStringHandler]
        internal ref struct printf_handler
        {
            DefaultInterpolatedStringHandler builder;
            internal readonly bool enabled;

            public printf_handler(int literalLength, int formattedCount, int level, out bool shouldAppend)
            {
#if !RELIABLE_DISABLE_LOGGING
                enabled = level <= log_level_;
#else
                enabled = false;
#endif
                shouldAppend = enabled;
                builder = enabled ? new DefaultInterpolatedStringHandler(literalLength, formattedCount) : default;
            }

            public void AppendLiteral(string value) => builder.AppendLiteral(value);
            public void AppendFormatted<T>(T value) => builder.AppendFormatted(value);
            public void AppendFormatted<T>(T value, string format) => builder.AppendFormatted(value, format);
            public void AppendFormatted<T>(T value, int alignment) => builder.AppendFormatted(value, alignment);
            internal string to_string_and_clear() => builder.ToStringAndClear();
        }

        static object default_allocate_function(object context, ulong bytes) => null;

        static void default_free_function(object context, object pointer) { }

        #endregion

        #region init / term

        public static int init() => OK;

        public static void term() { }

        #endregion

        #region sequence > / <

        static bool sequence_greater_than(ushort s1, ushort s2) =>
            (s1 > s2 && s1 - s2 <= 32768) ||
            (s1 < s2 && s2 - s1 > 32768);

        static bool sequence_less_than(ushort s1, ushort s2) =>
            sequence_greater_than(s2, s1);

        #endregion

        #region sequence_buffer_t

        internal class sequence_buffer_t<T>
        {
            public object allocator_context;
            public Func<object, ulong, object> allocate_function;
            public Action<object, object> free_function;
            public ushort sequence;
            public int num_entries;
            public uint[] entry_sequence;
            public T[] entry_data;
        }

        static sequence_buffer_t<T> sequence_buffer_create<T>(
            int num_entries,
            object allocator_context,
            Func<object, ulong, object> allocate_function,
            Action<object, object> free_function) where T : new()
        {
            assert(num_entries > 0);

            if (allocate_function == null)
                allocate_function = default_allocate_function;

            if (free_function == null)
                free_function = default_free_function;

            if (num_entries <= 0)
                return null;

            var sequence_buffer = new sequence_buffer_t<T>();
            sequence_buffer.allocator_context = allocator_context;
            sequence_buffer.allocate_function = allocate_function;
            sequence_buffer.free_function = free_function;
            sequence_buffer.sequence = 0;
            sequence_buffer.num_entries = num_entries;
            sequence_buffer.entry_sequence = new uint[num_entries];
            sequence_buffer.entry_data = new T[num_entries];
            Array.Fill(sequence_buffer.entry_sequence, 0xFFFFFFFFU);
            for (var i = 0; i < num_entries; ++i)
                sequence_buffer.entry_data[i] = new T();

            return sequence_buffer;
        }

        static void sequence_buffer_destroy<T>(ref sequence_buffer_t<T> sequence_buffer)
        {
            assert(sequence_buffer != null);
            sequence_buffer.entry_sequence = null;
            sequence_buffer.entry_data = null;
            sequence_buffer = null;
        }

        static void sequence_buffer_reset<T>(sequence_buffer_t<T> sequence_buffer)
        {
            assert(sequence_buffer != null);
            sequence_buffer.sequence = 0;
            Array.Fill(sequence_buffer.entry_sequence, 0xFFFFFFFFU);
        }

        static void sequence_buffer_remove_entries<T>(
            sequence_buffer_t<T> sequence_buffer,
            int start_sequence,
            int finish_sequence,
            Action<object, object, Action<object, object>> cleanup_function)
        {
            assert(sequence_buffer != null);
            if (finish_sequence < start_sequence)
                finish_sequence += 65536;
            int i;
            if (finish_sequence - start_sequence < sequence_buffer.num_entries)
                for (i = start_sequence; i <= finish_sequence; ++i)
                {
                    cleanup_function?.Invoke(
                        sequence_buffer.entry_data[i % sequence_buffer.num_entries],
                        sequence_buffer.allocator_context,
                        sequence_buffer.free_function);
                    sequence_buffer.entry_sequence[i % sequence_buffer.num_entries] = 0xFFFFFFFF;
                }
            else
                for (i = 0; i < sequence_buffer.num_entries; ++i)
                {
                    cleanup_function?.Invoke(
                        sequence_buffer.entry_data[i],
                        sequence_buffer.allocator_context,
                        sequence_buffer.free_function);
                    sequence_buffer.entry_sequence[i] = 0xFFFFFFFF;
                }
        }

        static bool sequence_buffer_test_insert<T>(sequence_buffer_t<T> sequence_buffer, ushort sequence) =>
            sequence_less_than(sequence, (ushort)(sequence_buffer.sequence - sequence_buffer.num_entries)) ? false : true;

        static T sequence_buffer_insert<T>(sequence_buffer_t<T> sequence_buffer, ushort sequence)
        {
            assert(sequence_buffer != null);
            if (sequence_less_than(sequence, (ushort)(sequence_buffer.sequence - sequence_buffer.num_entries)))
                return default(T);
            if (sequence_greater_than((ushort)(sequence + 1), sequence_buffer.sequence))
            {
                sequence_buffer_remove_entries(sequence_buffer, sequence_buffer.sequence, sequence, null);
                sequence_buffer.sequence = (ushort)(sequence + 1);
            }
            var index = sequence % sequence_buffer.num_entries;
            sequence_buffer.entry_sequence[index] = sequence;
            return sequence_buffer.entry_data[index];
        }

        static void sequence_buffer_advance<T>(sequence_buffer_t<T> sequence_buffer, ushort sequence)
        {
            assert(sequence_buffer != null);
            if (sequence_greater_than((ushort)(sequence + 1), sequence_buffer.sequence))
            {
                sequence_buffer_remove_entries(sequence_buffer, sequence_buffer.sequence, sequence, null);
                sequence_buffer.sequence = (ushort)(sequence + 1);
            }
        }

        static T sequence_buffer_insert_with_cleanup<T>(
            sequence_buffer_t<T> sequence_buffer,
            ushort sequence,
            Action<object, object, Action<object, object>> cleanup_function)
        {
            assert(sequence_buffer != null);
            if (sequence_greater_than((ushort)(sequence + 1), sequence_buffer.sequence))
            {
                sequence_buffer_remove_entries(sequence_buffer, sequence_buffer.sequence, sequence, cleanup_function);
                sequence_buffer.sequence = (ushort)(sequence + 1);
            }
            else if (sequence_less_than(sequence, (ushort)(sequence_buffer.sequence - sequence_buffer.num_entries)))
                return default(T);
            var index = sequence % sequence_buffer.num_entries;
            if (sequence_buffer.entry_sequence[index] != 0xFFFFFFFF)
                cleanup_function(
                    sequence_buffer.entry_data[sequence % sequence_buffer.num_entries],
                    sequence_buffer.allocator_context,
                    sequence_buffer.free_function);
            sequence_buffer.entry_sequence[index] = sequence;
            return sequence_buffer.entry_data[index];
        }

        static void sequence_buffer_advance_with_cleanup<T>(
            sequence_buffer_t<T> sequence_buffer,
            ushort sequence,
            Action<object, object, Action<object, object>> cleanup_function)
        {
            assert(sequence_buffer != null);
            if (sequence_greater_than((ushort)(sequence + 1), sequence_buffer.sequence))
            {
                sequence_buffer_remove_entries(sequence_buffer, sequence_buffer.sequence, sequence, cleanup_function);
                sequence_buffer.sequence = (ushort)(sequence + 1);
            }
        }

        static void sequence_buffer_remove_with_cleanup<T>(
            sequence_buffer_t<T> sequence_buffer,
            ushort sequence,
            Action<object, object, Action<object, object>> cleanup_function)
        {
            assert(sequence_buffer != null);
            var index = sequence % sequence_buffer.num_entries;
            if (sequence_buffer.entry_sequence[index] != 0xFFFFFFFF)
            {
                sequence_buffer.entry_sequence[index] = 0xFFFFFFFF;
                cleanup_function(sequence_buffer.entry_data[index], sequence_buffer.allocator_context, sequence_buffer.free_function);
            }
        }

        static bool sequence_buffer_exists<T>(sequence_buffer_t<T> sequence_buffer, ushort sequence)
        {
            assert(sequence_buffer != null);
            return sequence_buffer.entry_sequence[sequence % sequence_buffer.num_entries] == sequence;
        }

        static T sequence_buffer_find<T>(sequence_buffer_t<T> sequence_buffer, ushort sequence)
        {
            assert(sequence_buffer != null);
            var index = sequence % sequence_buffer.num_entries;
            return (sequence_buffer.entry_sequence[index] == sequence) ? sequence_buffer.entry_data[index] : default(T);
        }

        static T sequence_buffer_at_index<T>(sequence_buffer_t<T> sequence_buffer, int index)
        {
            assert(sequence_buffer != null);
            assert(index >= 0);
            assert(index < sequence_buffer.num_entries);
            return sequence_buffer.entry_sequence[index] != 0xFFFFFFFF ? sequence_buffer.entry_data[index] : default(T);
        }

        static void sequence_buffer_generate_ack_bits<T>(sequence_buffer_t<T> sequence_buffer, out ushort ack, out uint ack_bits)
        {
            assert(sequence_buffer != null);
            ack = (ushort)(sequence_buffer.sequence - 1);
            ack_bits = 0;
            var mask = 1U;
            int i;
            for (i = 0; i < 32; ++i)
            {
                var sequence = (ushort)(ack - i);
                if (sequence_buffer_exists(sequence_buffer, sequence))
                    ack_bits |= mask;
                mask <<= 1;
            }
        }

        #endregion

        #region binary serdes

        internal static void write_uint8(byte[] b, ref int p, byte value)
        {
            b[p] = value;
            ++p;
        }

        internal static void write_uint16(byte[] b, ref int p, ushort value)
        {
            b[p] = (byte)value;
            b[p + 1] = (byte)(value >> 8);
            p += 2;
        }

        internal static byte read_uint8(byte[] b, ref int p)
        {
            var value = b[p];
            ++p;
            return value;
        }

        internal static ushort read_uint16(byte[] b, ref int p)
        {
            var value = (ushort)(b[p] | (b[p + 1] << 8));
            p += 2;
            return value;
        }

        #endregion

        #region fragment_reassembly_data_t

        internal class fragment_reassembly_data_t
        {
            public ushort sequence;
            public ushort ack;
            public uint ack_bits;
            public int num_fragments_received;
            public int num_fragments_total;
            public byte[] packet_data;
            public int packet_bytes;
            public int packet_header_bytes;
            public byte[] fragment_received = new byte[256];
        }

        static void fragment_reassembly_data_cleanup(object data, object allocator_context, Action<object, object> free_function)
        {
            assert(free_function != null);
            var reassembly_data = (fragment_reassembly_data_t)data;
            if (reassembly_data.packet_data != null)
            {
                free_function(allocator_context, reassembly_data.packet_data);
                reassembly_data.packet_data = null;
            }
        }

        #endregion

        #region reliable_endpoint_t
    }

    public class reliable_endpoint_t
    {
        internal object allocator_context;
        internal Func<object, ulong, object> allocate_function;
        internal Action<object, object> free_function;
        internal reliable_config_t config;
        internal double time;
        internal float rtt;
        internal float rtt_min;
        internal float rtt_max;
        internal float rtt_avg;
        internal float jitter_avg_vs_min_rtt;
        internal float jitter_max_vs_min_rtt;
        internal float jitter_stddev_vs_avg_rtt;
        internal float packet_loss;
        internal float sent_bandwidth_kbps;
        internal float received_bandwidth_kbps;
        internal float acked_bandwidth_kbps;
        internal int num_acks;
        internal ushort[] acks;
        internal ushort sequence;
        internal float[] rtt_history_buffer;
        internal byte[] transmit_buffer;
        internal reliable.sequence_buffer_t<reliable.reliable_sent_packet_data_t> sent_packets;
        internal reliable.sequence_buffer_t<reliable.reliable_received_packet_data_t> received_packets;
        internal reliable.sequence_buffer_t<reliable.fragment_reassembly_data_t> fragment_reassembly;
        internal ulong[] counters = new ulong[reliable.ENDPOINT_NUM_COUNTERS];
    }

    static partial class reliable
    {
        internal class reliable_sent_packet_data_t
        {
            public double time;
            public bool acked; // : 1;
            public uint packet_bytes; // : 31;
        }

        internal class reliable_received_packet_data_t
        {
            public double time;
            public uint packet_bytes;
        }

        public static void default_config(out reliable_config_t config) =>
            config = new reliable_config_t
            {
                name = "endpoint",
                max_packet_size = 16 * 1024,
                fragment_above = 1024,
                max_fragments = 16,
                fragment_size = 1024,
                ack_buffer_size = 256,
                sent_packets_buffer_size = 256,
                received_packets_buffer_size = 256,
                fragment_reassembly_buffer_size = 64,
                rtt_smoothing_factor = 0.0025f,
                rtt_history_size = 512,
                packet_loss_smoothing_factor = 0.1f,
                bandwidth_smoothing_factor = 0.1f,
                packet_header_size = 28, // note: UDP over IPv4 = 20 + 8 bytes, UDP over IPv6 = 40 + 8 bytes
            };

        // checks the config a caller hands to endpoint_create. every field is range checked and the two relationships between
        // fields are checked: a fragment threshold above the maximum packet size can never fire, and a fragment count that does
        // not cover the maximum packet size means a large packet has nowhere to go. logs what is wrong and returns false to refuse

        static bool config_valid(reliable_config_t config)
        {
            if (config == null)
            {
                printf(LOG_LEVEL_ERROR, "[reliable] config is NULL\n");
                return false;
            }

            if (config.max_packet_size <= 0)
            {
                printf(LOG_LEVEL_ERROR, $"[{config.name}] max_packet_size must be positive\n");
                return false;
            }

            if (config.fragment_above <= 0)
            {
                printf(LOG_LEVEL_ERROR, $"[{config.name}] fragment_above must be positive\n");
                return false;
            }

            if (config.fragment_size <= 0)
            {
                printf(LOG_LEVEL_ERROR, $"[{config.name}] fragment_size must be positive\n");
                return false;
            }

            if (config.max_fragments <= 0 || config.max_fragments > 256)
            {
                printf(LOG_LEVEL_ERROR, $"[{config.name}] max_fragments must be between 1 and 256\n");
                return false;
            }

            if (config.ack_buffer_size <= 0 || config.sent_packets_buffer_size <= 0 ||
                config.received_packets_buffer_size <= 0 || config.fragment_reassembly_buffer_size <= 0 ||
                config.rtt_history_size <= 0)
            {
                printf(LOG_LEVEL_ERROR, $"[{config.name}] buffer sizes must be positive\n");
                return false;
            }

            if (config.transmit_packet_function == null || config.process_packet_function == null)
            {
                printf(LOG_LEVEL_ERROR, $"[{config.name}] transmit and process packet functions are required\n");
                return false;
            }

            if (config.fragment_above > config.max_packet_size)
            {
                printf(LOG_LEVEL_ERROR, $"[{config.name}] fragment_above ({config.fragment_above}) is above max_packet_size ({config.max_packet_size})\n");
                return false;
            }

            // max_fragments * fragment_size must cover max_packet_size. written as a division of the
            // two values already known to be positive, so neither side can overflow

            if (config.max_fragments <= (config.max_packet_size - 1) / config.fragment_size)
            {
                printf(LOG_LEVEL_ERROR, $"[{config.name}] max_fragments ({config.max_fragments}) times fragment_size ({config.fragment_size}) does not cover max_packet_size ({config.max_packet_size})\n");
                return false;
            }

            if ((long)config.max_fragments * config.fragment_size > (long)int.MaxValue - MAX_PACKET_HEADER_BYTES)
            {
                printf(LOG_LEVEL_ERROR, $"[{config.name}] max_fragments ({config.max_fragments}) times fragment_size ({config.fragment_size}) does not fit in a packet length\n");
                return false;
            }

            if (config.max_packet_size > int.MaxValue - MAX_PACKET_HEADER_BYTES - FRAGMENT_HEADER_BYTES)
            {
                printf(LOG_LEVEL_ERROR, $"[{config.name}] max_packet_size ({config.max_packet_size}) is too large for the receive length check\n");
                return false;
            }

            if (config.packet_header_size < 0)
            {
                printf(LOG_LEVEL_ERROR, $"[{config.name}] packet_header_size must not be negative\n");
                return false;
            }

            if ((long)config.packet_header_size + (long)config.max_packet_size > int.MaxValue)
            {
                printf(LOG_LEVEL_ERROR, $"[{config.name}] packet_header_size ({config.packet_header_size}) plus max_packet_size ({config.max_packet_size}) does not fit a packet length\n");
                return false;
            }

            return true;
        }

        public static reliable_endpoint_t endpoint_create(reliable_config_t config, double time)
        {
            if (!config_valid(config))
                return null;

            var allocator_context = config.allocator_context;
            var allocate_function = config.allocate_function;
            var free_function = config.free_function;

            if (allocate_function == null)
                allocate_function = default_allocate_function;

            if (free_function == null)
                free_function = default_free_function;

            // scratch buffer for outgoing packets, so the send path doesn't allocate. sized for whichever is larger: a regular packet or a fragment

            if (config.max_packet_size > int.MaxValue - MAX_PACKET_HEADER_BYTES ||
                config.fragment_size > int.MaxValue - FRAGMENT_HEADER_BYTES - MAX_PACKET_HEADER_BYTES)
                return null;

            var transmit_buffer_size = config.max_packet_size + MAX_PACKET_HEADER_BYTES;
            var fragment_transmit_buffer_size = FRAGMENT_HEADER_BYTES + MAX_PACKET_HEADER_BYTES + config.fragment_size;
            if (fragment_transmit_buffer_size > transmit_buffer_size)
                transmit_buffer_size = fragment_transmit_buffer_size;

            var endpoint = new reliable_endpoint_t();

            endpoint.allocator_context = allocator_context;
            endpoint.allocate_function = allocate_function;
            endpoint.free_function = free_function;
            endpoint.config = config.copy();
            endpoint.time = time;

            endpoint.acks = new ushort[config.ack_buffer_size];

            endpoint.sent_packets = sequence_buffer_create<reliable_sent_packet_data_t>(
                config.sent_packets_buffer_size,
                allocator_context,
                allocate_function,
                free_function);

            endpoint.received_packets = sequence_buffer_create<reliable_received_packet_data_t>(
                config.received_packets_buffer_size,
                allocator_context,
                allocate_function,
                free_function);

            endpoint.fragment_reassembly = sequence_buffer_create<fragment_reassembly_data_t>(
                config.fragment_reassembly_buffer_size,
                allocator_context,
                allocate_function,
                free_function);

            endpoint.rtt_history_buffer = new float[config.rtt_history_size];

            endpoint.transmit_buffer = new byte[transmit_buffer_size];

            if (endpoint.acks == null ||
                endpoint.sent_packets == null ||
                endpoint.received_packets == null ||
                endpoint.fragment_reassembly == null ||
                endpoint.rtt_history_buffer == null ||
                endpoint.transmit_buffer == null)
            {
                printf(LOG_LEVEL_ERROR, $"[{endpoint.config.name}] failed to allocate endpoint\n");
                endpoint_destroy(ref endpoint);
                return null;
            }

            Array.Fill(endpoint.rtt_history_buffer, -1.0f);

            return endpoint;
        }

        public static void endpoint_destroy(ref reliable_endpoint_t endpoint)
        {
            assert(endpoint != null);

            // every member is checked rather than asserted, because endpoint_create hands a
            // partly built endpoint to this function to unwind an allocation failure

            if (endpoint.fragment_reassembly != null)
            {
                int i;
                for (i = 0; i < endpoint.config.fragment_reassembly_buffer_size; ++i)
                {
                    var reassembly_data = sequence_buffer_at_index(endpoint.fragment_reassembly, i);
                    if (reassembly_data != null && reassembly_data.packet_data != null)
                    {
                        endpoint.free_function(endpoint.allocator_context, reassembly_data.packet_data);
                        reassembly_data.packet_data = null;
                    }
                }
            }

            endpoint.acks = null;

            if (endpoint.sent_packets != null)
                sequence_buffer_destroy(ref endpoint.sent_packets);

            if (endpoint.received_packets != null)
                sequence_buffer_destroy(ref endpoint.received_packets);

            if (endpoint.fragment_reassembly != null)
                sequence_buffer_destroy(ref endpoint.fragment_reassembly);

            endpoint.rtt_history_buffer = null;

            endpoint.transmit_buffer = null;

            endpoint = null;
        }

        public static ushort endpoint_next_packet_sequence(this reliable_endpoint_t endpoint)
        {
            assert(endpoint != null);
            return endpoint.sequence;
        }

        static int write_packet_header(byte[] packet_data, ushort sequence, ushort ack, uint ack_bits)
        {
            var p = 0;

            byte prefix_byte = 0;
            if ((ack_bits & 0x000000FF) != 0x000000FF)
                prefix_byte |= (1 << 1);
            if ((ack_bits & 0x0000FF00) != 0x0000FF00)
                prefix_byte |= (1 << 2);
            if ((ack_bits & 0x00FF0000) != 0x00FF0000)
                prefix_byte |= (1 << 3);
            if ((ack_bits & 0xFF000000) != 0xFF000000)
                prefix_byte |= (1 << 4);

            var sequence_difference = sequence - ack;
            if (sequence_difference < 0)
                sequence_difference += 65536;
            if (sequence_difference <= 255)
                prefix_byte |= (1 << 5);

            write_uint8(packet_data, ref p, prefix_byte);
            write_uint16(packet_data, ref p, sequence);
            if (sequence_difference <= 255)
                write_uint8(packet_data, ref p, (byte)sequence_difference);
            else
                write_uint16(packet_data, ref p, ack);
            if ((ack_bits & 0x000000FF) != 0x000000FF)
                write_uint8(packet_data, ref p, (byte)(ack_bits & 0x000000FF));
            if ((ack_bits & 0x0000FF00) != 0x0000FF00)
                write_uint8(packet_data, ref p, (byte)((ack_bits & 0x0000FF00) >> 8));
            if ((ack_bits & 0x00FF0000) != 0x00FF0000)
                write_uint8(packet_data, ref p, (byte)((ack_bits & 0x00FF0000) >> 16));
            if ((ack_bits & 0xFF000000) != 0xFF000000)
                write_uint8(packet_data, ref p, (byte)((ack_bits & 0xFF000000) >> 24));

            assert(p <= MAX_PACKET_HEADER_BYTES);

            return p;
        }

        public static void endpoint_send_packet(this reliable_endpoint_t endpoint, byte[] packet_data, int packet_bytes)
        {
            assert(endpoint != null);
            assert(packet_data != null);
            assert(packet_bytes > 0);

            if (packet_bytes > endpoint.config.max_packet_size)
            {
                printf(LOG_LEVEL_ERROR, $"[{endpoint.config.name}] packet too large to send. packet is {packet_bytes} bytes, maximum is {endpoint.config.max_packet_size}\n");
                endpoint.counters[ENDPOINT_COUNTER_NUM_PACKETS_TOO_LARGE_TO_SEND]++;
                return;
            }

            var sequence = endpoint.sequence++;
            sequence_buffer_generate_ack_bits(endpoint.received_packets, out var ack, out var ack_bits);

            printf(LOG_LEVEL_DEBUG, $"[{endpoint.config.name}] sending packet {sequence}\n");

            var sent_packet_data = sequence_buffer_insert(endpoint.sent_packets, sequence);

            assert(sent_packet_data != null);

            sent_packet_data.time = endpoint.time;
            sent_packet_data.packet_bytes = (uint)(endpoint.config.packet_header_size + packet_bytes);
            sent_packet_data.acked = false;

            if (packet_bytes <= endpoint.config.fragment_above)
            {
                // regular packet

                printf(LOG_LEVEL_DEBUG, $"[{endpoint.config.name}] sending packet {sequence} without fragmentation\n");

                var transmit_packet_data = endpoint.transmit_buffer;

                var packet_header_bytes = write_packet_header(transmit_packet_data, sequence, ack, ack_bits);

                Buffer.BlockCopy(packet_data, 0, transmit_packet_data, packet_header_bytes, packet_bytes);

                endpoint.config.transmit_packet_function(endpoint.config.context, endpoint.config.id, sequence, transmit_packet_data, packet_header_bytes + packet_bytes);
            }
            else
            {
                // fragmented packet

                var packet_header = new byte[MAX_PACKET_HEADER_BYTES];

                var packet_header_bytes = write_packet_header(packet_header, sequence, ack, ack_bits);

                var num_fragments = (packet_bytes / endpoint.config.fragment_size) + ((packet_bytes % endpoint.config.fragment_size) != 0 ? 1 : 0);

                printf(LOG_LEVEL_DEBUG, $"[{endpoint.config.name}] sending packet {sequence} as {num_fragments} fragments\n");

                assert(num_fragments >= 1);
                assert(num_fragments <= endpoint.config.max_fragments);

                var fragment_packet_data = endpoint.transmit_buffer;

                var q = 0;
                var end = q + packet_bytes;

                int fragment_id;
                for (fragment_id = 0; fragment_id < num_fragments; ++fragment_id)
                {
                    var p = 0;
                    write_uint8(fragment_packet_data, ref p, 1);
                    write_uint16(fragment_packet_data, ref p, sequence);
                    write_uint8(fragment_packet_data, ref p, (byte)fragment_id);
                    write_uint8(fragment_packet_data, ref p, (byte)(num_fragments - 1));

                    if (fragment_id == 0)
                    {
                        Buffer.BlockCopy(packet_header, 0, fragment_packet_data, p, packet_header_bytes);
                        p += packet_header_bytes;
                    }

                    var bytes_to_copy = endpoint.config.fragment_size;
                    if (q + bytes_to_copy > end)
                        bytes_to_copy = end - q;

                    Buffer.BlockCopy(packet_data, q, fragment_packet_data, p, bytes_to_copy);

                    p += bytes_to_copy;
                    q += bytes_to_copy;

                    var fragment_packet_bytes = p;

                    endpoint.config.transmit_packet_function(endpoint.config.context, endpoint.config.id, sequence, fragment_packet_data, fragment_packet_bytes);

                    endpoint.counters[ENDPOINT_COUNTER_NUM_FRAGMENTS_SENT]++;
                }
            }

            endpoint.counters[ENDPOINT_COUNTER_NUM_PACKETS_SENT]++;
        }

        // reads a packet header from packet_data[p_ .. p_ + packet_bytes). packet_bytes is the number of bytes available from p_

        static int read_packet_header(string name, byte[] packet_data, int p_, int packet_bytes, out ushort sequence, out ushort ack, out uint ack_bits)
        {
            ack_bits = sequence = ack = 0;
            if (packet_bytes < 3)
            {
                printf(LOG_LEVEL_DEBUG, $"[{name}] packet too small for packet header (1)\n");
                return -1;
            }

            var p = p_;

            var prefix_byte = read_uint8(packet_data, ref p);

            if ((prefix_byte & 1) != 0)
            {
                printf(LOG_LEVEL_DEBUG, $"[{name}] prefix byte does not indicate a regular packet\n");
                return -1;
            }

            sequence = read_uint16(packet_data, ref p);

            if ((prefix_byte & (1 << 5)) != 0)
            {
                if (packet_bytes < 3 + 1)
                {
                    printf(LOG_LEVEL_DEBUG, $"[{name}] packet too small for packet header (2)\n");
                    return -1;
                }
                var sequence_difference = read_uint8(packet_data, ref p);
                ack = (ushort)(sequence - sequence_difference);
            }
            else
            {
                if (packet_bytes < 3 + 2)
                {
                    printf(LOG_LEVEL_DEBUG, $"[{name}] packet too small for packet header (3)\n");
                    return -1;
                }
                ack = read_uint16(packet_data, ref p);
            }

            var expected_bytes = 0;
            int i;
            for (i = 1; i <= 4; ++i)
                if ((prefix_byte & (1 << i)) != 0)
                    expected_bytes++;
            if (packet_bytes < (p - p_) + expected_bytes)
            {
                printf(LOG_LEVEL_DEBUG, $"[{name}] packet too small for packet header (4)\n");
                return -1;
            }

            ack_bits = 0xFFFFFFFF;
            if ((prefix_byte & (1 << 1)) != 0)
            {
                ack_bits &= 0xFFFFFF00;
                ack_bits |= (uint)(read_uint8(packet_data, ref p));
            }
            if ((prefix_byte & (1 << 2)) != 0)
            {
                ack_bits &= 0xFFFF00FF;
                ack_bits |= (uint)(read_uint8(packet_data, ref p)) << 8;
            }
            if ((prefix_byte & (1 << 3)) != 0)
            {
                ack_bits &= 0xFF00FFFF;
                ack_bits |= (uint)(read_uint8(packet_data, ref p)) << 16;
            }
            if ((prefix_byte & (1 << 4)) != 0)
            {
                ack_bits &= 0x00FFFFFF;
                ack_bits |= (uint)(read_uint8(packet_data, ref p)) << 24;
            }
            return p - p_;
        }

        static int read_fragment_header(
            string name,
            byte[] packet_data, int p_,
            int packet_bytes,
            int max_fragments,
            int fragment_size,
            out int fragment_id,
            out int num_fragments,
            out int fragment_bytes,
            out ushort sequence,
            out ushort ack,
            out uint ack_bits)
        {
            fragment_id = num_fragments = fragment_bytes = 0;
            ack_bits = sequence = ack = 0;

            if (packet_bytes < FRAGMENT_HEADER_BYTES)
            {
                printf(LOG_LEVEL_DEBUG, $"[{name}] packet is too small to read fragment header\n");
                return -1;
            }

            var p = p_;

            var prefix_byte = read_uint8(packet_data, ref p);
            if (prefix_byte != 1)
            {
                printf(LOG_LEVEL_DEBUG, $"[{name}] prefix byte is not a fragment\n");
                return -1;
            }

            sequence = read_uint16(packet_data, ref p);
            fragment_id = read_uint8(packet_data, ref p);
            num_fragments = read_uint8(packet_data, ref p) + 1;

            if (num_fragments > max_fragments)
            {
                printf(LOG_LEVEL_DEBUG, $"[{name}] num fragments {num_fragments} outside of range of max fragments {max_fragments}\n");
                return -1;
            }

            if (fragment_id >= num_fragments)
            {
                printf(LOG_LEVEL_DEBUG, $"[{name}] fragment id {fragment_id} outside of range of num fragments {num_fragments}\n");
                return -1;
            }

            fragment_bytes = packet_bytes - FRAGMENT_HEADER_BYTES;

            ushort packet_sequence = 0;
            ushort packet_ack = 0;
            var packet_ack_bits = 0U;

            if (fragment_id == 0)
            {
                var packet_header_bytes = read_packet_header(
                    name,
                    packet_data, p_ + FRAGMENT_HEADER_BYTES,
                    packet_bytes - FRAGMENT_HEADER_BYTES,
                    out packet_sequence,
                    out packet_ack,
                    out packet_ack_bits);

                if (packet_header_bytes < 0)
                {
                    printf(LOG_LEVEL_DEBUG, $"[{name}] bad packet header in fragment\n");
                    return -1;
                }

                if (packet_sequence != sequence)
                {
                    printf(LOG_LEVEL_DEBUG, $"[{name}] bad packet sequence in fragment. expected {sequence}, got {packet_sequence}\n");
                    return -1;
                }

                // the packet header is re-encoded canonically during reassembly, so a non-canonical
                // header would shift where the fragment payload lands. reject it here instead.

                var canonical_header = new byte[MAX_PACKET_HEADER_BYTES];
                var canonical_header_bytes = write_packet_header(canonical_header, packet_sequence, packet_ack, packet_ack_bits);
                if (canonical_header_bytes != packet_header_bytes ||
                    !canonical_header.AsSpan(0, canonical_header_bytes).SequenceEqual(packet_data.AsSpan(p_ + FRAGMENT_HEADER_BYTES, canonical_header_bytes)))
                {
                    printf(LOG_LEVEL_DEBUG, $"[{name}] non-canonical packet header in fragment\n");
                    return -1;
                }

                fragment_bytes = packet_bytes - packet_header_bytes - FRAGMENT_HEADER_BYTES;
            }

            ack = packet_ack;
            ack_bits = packet_ack_bits;

            if (fragment_bytes > fragment_size)
            {
                printf(LOG_LEVEL_DEBUG, $"[{name}] fragment bytes {fragment_bytes} > fragment size {fragment_size}\n");
                return -1;
            }

            if (fragment_id != num_fragments - 1 && fragment_bytes != fragment_size)
            {
                printf(LOG_LEVEL_DEBUG, $"[{name}] fragment {fragment_id} is {fragment_bytes} bytes, which is not the expected fragment size {fragment_size}\n");
                return -1;
            }

            return p - p_;
        }

        static void store_fragment_data(
            fragment_reassembly_data_t reassembly_data,
            ushort sequence,
            ushort ack,
            uint ack_bits,
            int fragment_id,
            int fragment_size,
            byte[] fragment_data, int p_,
            int fragment_bytes)
        {
            var p = p_;

            if (fragment_id == 0)
            {
                var packet_header = new byte[MAX_PACKET_HEADER_BYTES];

                reassembly_data.packet_header_bytes = write_packet_header(packet_header, sequence, ack, ack_bits);

                Buffer.BlockCopy(packet_header, 0,
                    reassembly_data.packet_data, MAX_PACKET_HEADER_BYTES - reassembly_data.packet_header_bytes,
                    reassembly_data.packet_header_bytes);

                p += reassembly_data.packet_header_bytes;
                fragment_bytes -= reassembly_data.packet_header_bytes;
            }

            if (fragment_id == reassembly_data.num_fragments_total - 1)
            {
                var packet_bytes = (long)(reassembly_data.num_fragments_total - 1) * fragment_size + fragment_bytes;
                if (packet_bytes < 0 || packet_bytes > int.MaxValue)
                    return;
                reassembly_data.packet_bytes = (int)packet_bytes;
            }

            var offset = (long)MAX_PACKET_HEADER_BYTES + (long)fragment_id * fragment_size;
            var end_offset = offset + fragment_bytes;
            var max_size = (long)MAX_PACKET_HEADER_BYTES + (long)reassembly_data.num_fragments_total * fragment_size;

            if (fragment_bytes < 0 || end_offset > max_size)
            {
                printf(LOG_LEVEL_DEBUG, $"[reliable] invalid fragment size {fragment_bytes} (would write past {end_offset}/{max_size})\n");
                return;
            }

            Buffer.BlockCopy(fragment_data, p, reassembly_data.packet_data, (int)offset, fragment_bytes);
        }

        public static void endpoint_receive_packet(this reliable_endpoint_t endpoint, byte[] packet_data, int packet_bytes)
        {
            assert(endpoint != null);
            assert(packet_data != null);

            // C# hardening: reliable.c only asserts packet_bytes > 0. here a bad length is dropped instead, so a malformed call can
            // never throw out of the receive path (an exception here would take down the caller's packet loop)

            if (packet_data == null || packet_bytes <= 0 || packet_bytes > packet_data.Length)
            {
                printf(LOG_LEVEL_DEBUG, $"[{endpoint.config.name}] ignoring invalid packet. packet bytes {packet_bytes} out of range\n");
                endpoint.counters[ENDPOINT_COUNTER_NUM_PACKETS_INVALID]++;
                return;
            }

            if ((long)packet_bytes > (long)endpoint.config.max_packet_size + MAX_PACKET_HEADER_BYTES + FRAGMENT_HEADER_BYTES)
            {
                printf(LOG_LEVEL_DEBUG, $"[{endpoint.config.name}] packet too large to receive. packet is at least {packet_bytes - (MAX_PACKET_HEADER_BYTES + FRAGMENT_HEADER_BYTES)} bytes, maximum is {endpoint.config.max_packet_size}\n");
                endpoint.counters[ENDPOINT_COUNTER_NUM_PACKETS_TOO_LARGE_TO_RECEIVE]++;
                return;
            }

            var p_ = 0;
            var prefix_byte = packet_data[p_];

            if ((prefix_byte & 1) == 0)
            {
                // regular packet

                endpoint.counters[ENDPOINT_COUNTER_NUM_PACKETS_RECEIVED]++;

                var packet_header_bytes = read_packet_header(endpoint.config.name, packet_data, p_, packet_bytes, out var sequence, out var ack, out var ack_bits);
                if (packet_header_bytes < 0)
                {
                    printf(LOG_LEVEL_DEBUG, $"[{endpoint.config.name}] ignoring invalid packet. could not read packet header\n");
                    endpoint.counters[ENDPOINT_COUNTER_NUM_PACKETS_INVALID]++;
                    return;
                }

                assert(packet_header_bytes <= packet_bytes);

                var packet_payload_bytes = packet_bytes - packet_header_bytes;

                if (packet_payload_bytes > endpoint.config.max_packet_size)
                {
                    printf(LOG_LEVEL_ERROR, $"[{endpoint.config.name}] packet too large to receive. packet is at {packet_payload_bytes} bytes, maximum is {endpoint.config.max_packet_size}\n");
                    endpoint.counters[ENDPOINT_COUNTER_NUM_PACKETS_TOO_LARGE_TO_RECEIVE]++;
                    return;
                }

                if (!sequence_buffer_test_insert(endpoint.received_packets, sequence))
                {
                    printf(LOG_LEVEL_DEBUG, $"[{endpoint.config.name}] ignoring stale packet {sequence}\n");
                    endpoint.counters[ENDPOINT_COUNTER_NUM_PACKETS_STALE]++;
                    return;
                }

                if (sequence_buffer_exists(endpoint.received_packets, sequence))
                {
                    printf(LOG_LEVEL_DEBUG, $"[{endpoint.config.name}] ignoring duplicate packet {sequence}\n");
                    endpoint.counters[ENDPOINT_COUNTER_NUM_PACKETS_DUPLICATE]++;
                    return;
                }

                printf(LOG_LEVEL_DEBUG, $"[{endpoint.config.name}] processing packet {sequence}\n");

                var payload = new byte[packet_payload_bytes];
                Buffer.BlockCopy(packet_data, p_ + packet_header_bytes, payload, 0, packet_payload_bytes);

                if (endpoint.config.process_packet_function(
                    endpoint.config.context,
                    endpoint.config.id,
                    sequence,
                    payload,
                    packet_payload_bytes))
                {
                    printf(LOG_LEVEL_DEBUG, $"[{endpoint.config.name}] process packet {sequence} successful\n");

                    var received_packet_data = sequence_buffer_insert(endpoint.received_packets, sequence);

                    sequence_buffer_advance_with_cleanup(endpoint.fragment_reassembly, sequence, fragment_reassembly_data_cleanup);

                    assert(received_packet_data != null);

                    received_packet_data.time = endpoint.time;
                    received_packet_data.packet_bytes = (uint)(endpoint.config.packet_header_size + packet_bytes);

                    int i;
                    for (i = 0; i < 32; ++i)
                    {
                        if ((ack_bits & 1) != 0)
                        {
                            var ack_sequence = (ushort)(ack - i);

                            var sent_packet_data = sequence_buffer_find(endpoint.sent_packets, ack_sequence);

                            if (sent_packet_data != null && !sent_packet_data.acked)
                            {
                                if (endpoint.num_acks < endpoint.config.ack_buffer_size)
                                {
                                    printf(LOG_LEVEL_DEBUG, $"[{endpoint.config.name}] acked packet {ack_sequence}\n");
                                    endpoint.acks[endpoint.num_acks++] = ack_sequence;
                                    endpoint.counters[ENDPOINT_COUNTER_NUM_PACKETS_ACKED]++;
                                    sent_packet_data.acked = true;

                                    var rtt = (float)(endpoint.time - sent_packet_data.time) * 1000.0f;

                                    assert(rtt >= 0.0);

                                    var index = ack_sequence % endpoint.config.rtt_history_size;

                                    endpoint.rtt_history_buffer[index] = rtt;

                                    if ((endpoint.rtt == 0.0f && rtt > 0.0f) || Math.Abs(endpoint.rtt - rtt) < 0.00001)
                                        endpoint.rtt = rtt;
                                    else
                                        endpoint.rtt += (rtt - endpoint.rtt) * endpoint.config.rtt_smoothing_factor;
                                }
                                else
                                {
                                    printf(LOG_LEVEL_ERROR, $"[{endpoint.config.name}] ack buffer is full. dropped ack for packet {ack_sequence}. make sure you call reliable_endpoint_clear_acks\n");
                                }
                            }
                        }
                        ack_bits >>= 1;
                    }
                }
                else
                {
                    printf(LOG_LEVEL_ERROR, $"[{endpoint.config.name}] process packet failed\n");
                }
            }
            else
            {
                // fragment packet

                var fragment_header_bytes = read_fragment_header(
                    endpoint.config.name,
                    packet_data, p_,
                    packet_bytes,
                    endpoint.config.max_fragments,
                    endpoint.config.fragment_size,
                    out var fragment_id,
                    out var num_fragments,
                    out var fragment_bytes,
                    out var sequence,
                    out var ack,
                    out var ack_bits);

                if (fragment_header_bytes < 0)
                {
                    printf(LOG_LEVEL_DEBUG, $"[{endpoint.config.name}] ignoring invalid fragment. could not read fragment header\n");
                    endpoint.counters[ENDPOINT_COUNTER_NUM_FRAGMENTS_INVALID]++;
                    return;
                }

                if (sequence_buffer_exists(endpoint.received_packets, sequence))
                {
                    printf(LOG_LEVEL_DEBUG, $"[{endpoint.config.name}] ignoring fragment {fragment_id} of packet {sequence}. packet already received\n");
                    return;
                }

                var reassembly_data = sequence_buffer_find(endpoint.fragment_reassembly, sequence);

                if (reassembly_data == null)
                {
                    reassembly_data = sequence_buffer_insert_with_cleanup(endpoint.fragment_reassembly, sequence, fragment_reassembly_data_cleanup);

                    if (reassembly_data == null)
                    {
                        printf(LOG_LEVEL_ERROR, $"[{endpoint.config.name}] ignoring invalid fragment. could not insert in reassembly buffer (stale)\n");
                        endpoint.counters[ENDPOINT_COUNTER_NUM_FRAGMENTS_INVALID]++;
                        return;
                    }

                    sequence_buffer_advance(endpoint.received_packets, sequence);

                    var packet_buffer_size = (long)MAX_PACKET_HEADER_BYTES + (long)num_fragments * endpoint.config.fragment_size + 8;

                    reassembly_data.sequence = sequence;
                    reassembly_data.ack = 0;
                    reassembly_data.ack_bits = 0;
                    reassembly_data.num_fragments_received = 0;
                    reassembly_data.num_fragments_total = num_fragments;
                    reassembly_data.packet_data = new byte[packet_buffer_size];         // managed arrays are zeroed (security#26-2)
                    reassembly_data.packet_bytes = 0;
                    reassembly_data.packet_header_bytes = 0;
                    Array.Clear(reassembly_data.fragment_received);
                }

                if (num_fragments != reassembly_data.num_fragments_total)
                {
                    printf(LOG_LEVEL_ERROR, $"[{endpoint.config.name}] ignoring invalid fragment. fragment count mismatch. expected {reassembly_data.num_fragments_total}, got {num_fragments}\n");
                    endpoint.counters[ENDPOINT_COUNTER_NUM_FRAGMENTS_INVALID]++;
                    return;
                }

                if (reassembly_data.fragment_received[fragment_id] != 0)
                {
                    printf(LOG_LEVEL_ERROR, $"[{endpoint.config.name}] ignoring fragment {fragment_id} of packet {sequence}. fragment already received\n");
                    return;
                }

                printf(LOG_LEVEL_DEBUG, $"[{endpoint.config.name}] received fragment {fragment_id} of packet {sequence} ({reassembly_data.num_fragments_received + 1}/{num_fragments})\n");

                reassembly_data.num_fragments_received++;
                reassembly_data.fragment_received[fragment_id] = 1;

                store_fragment_data(
                    reassembly_data,
                    sequence,
                    ack,
                    ack_bits,
                    fragment_id,
                    endpoint.config.fragment_size,
                    packet_data, p_ + fragment_header_bytes,
                    packet_bytes - fragment_header_bytes);

                if (reassembly_data.num_fragments_received == reassembly_data.num_fragments_total)
                {
                    printf(LOG_LEVEL_DEBUG, $"[{endpoint.config.name}] completed reassembly of packet {sequence}\n");

                    var reassembled_bytes = reassembly_data.packet_header_bytes + reassembly_data.packet_bytes;
                    var reassembled_packet = new byte[reassembled_bytes];
                    Buffer.BlockCopy(reassembly_data.packet_data, MAX_PACKET_HEADER_BYTES - reassembly_data.packet_header_bytes, reassembled_packet, 0, reassembled_bytes);

                    endpoint_receive_packet(endpoint, reassembled_packet, reassembled_bytes);

                    sequence_buffer_remove_with_cleanup(endpoint.fragment_reassembly, sequence, fragment_reassembly_data_cleanup);
                }

                endpoint.counters[ENDPOINT_COUNTER_NUM_FRAGMENTS_RECEIVED]++;
            }
        }

        public static void endpoint_free_packet(this reliable_endpoint_t endpoint, ref object packet)
        {
            assert(endpoint != null);
            assert(packet != null);
            endpoint.free_function(endpoint.allocator_context, packet);
            packet = null;
        }

        public static ushort[] endpoint_get_acks(this reliable_endpoint_t endpoint, out int num_acks)
        {
            assert(endpoint != null);
            num_acks = endpoint.num_acks;
            return endpoint.acks;
        }

        public static void endpoint_clear_acks(this reliable_endpoint_t endpoint)
        {
            assert(endpoint != null);
            endpoint.num_acks = 0;
        }

        // resets the endpoint to its initial state: acks, counters, sequence number, all tracking buffers, the rtt history and every
        // rtt, jitter, packet loss and bandwidth statistic are cleared. the config and the time are kept, so the endpoint is immediately usable again

        public static void endpoint_reset(this reliable_endpoint_t endpoint)
        {
            assert(endpoint != null);

            endpoint.num_acks = 0;
            endpoint.sequence = 0;

            // every value a getter can return goes back to what it was at create, so the header's
            // promise holds for the statistics as well as for the buffers

            endpoint.rtt = 0.0f;
            endpoint.rtt_min = 0.0f;
            endpoint.rtt_max = 0.0f;
            endpoint.rtt_avg = 0.0f;
            endpoint.jitter_avg_vs_min_rtt = 0.0f;
            endpoint.jitter_max_vs_min_rtt = 0.0f;
            endpoint.jitter_stddev_vs_avg_rtt = 0.0f;
            endpoint.packet_loss = 0.0f;
            endpoint.sent_bandwidth_kbps = 0.0f;
            endpoint.received_bandwidth_kbps = 0.0f;
            endpoint.acked_bandwidth_kbps = 0.0f;

            Array.Clear(endpoint.acks);
            Array.Clear(endpoint.counters);

            Array.Fill(endpoint.rtt_history_buffer, -1.0f);

            int i;
            for (i = 0; i < endpoint.config.fragment_reassembly_buffer_size; ++i)
            {
                var reassembly_data = sequence_buffer_at_index(endpoint.fragment_reassembly, i);

                if (reassembly_data != null && reassembly_data.packet_data != null)
                {
                    endpoint.free_function(endpoint.allocator_context, reassembly_data.packet_data);
                    reassembly_data.packet_data = null;
                }
            }

            sequence_buffer_reset(endpoint.sent_packets);
            sequence_buffer_reset(endpoint.received_packets);
            sequence_buffer_reset(endpoint.fragment_reassembly);
        }

        public static void endpoint_update(this reliable_endpoint_t endpoint, double time)
        {
            assert(endpoint != null);

            endpoint.time = time;

            // calculate min and max rtt
            {
                var min_rtt = float.MaxValue;
                var max_rtt = 0.0f;
                var sum_rtt = 0.0f;
                var count = 0;
                for (var i = 0; i < endpoint.config.rtt_history_size; i++)
                {
                    var rtt = endpoint.rtt_history_buffer[i];
                    if (rtt >= 0.0f)
                    {
                        if (rtt < min_rtt)
                            min_rtt = rtt;
                        if (rtt > max_rtt)
                            max_rtt = rtt;
                        sum_rtt += rtt;
                        count++;
                    }
                }

                // the sample count, not the value of min_rtt, says whether the history is empty. a
                // sentinel compared against a real rtt reports 0 for a link slow enough to reach it

                if (count > 0)
                {
                    endpoint.rtt_min = min_rtt;
                    endpoint.rtt_max = max_rtt;
                    endpoint.rtt_avg = sum_rtt / (float)count;
                }
                else
                {
                    endpoint.rtt_min = 0.0f;
                    endpoint.rtt_max = 0.0f;
                    endpoint.rtt_avg = 0.0f;
                }
            }

            // calculate average jitter vs. min rtt
            {
                var sum = 0.0f;
                var count = 0;
                for (var i = 0; i < endpoint.config.rtt_history_size; i++)
                {
                    if (endpoint.rtt_history_buffer[i] >= 0.0f)
                    {
                        sum += (endpoint.rtt_history_buffer[i] - endpoint.rtt_min);
                        count++;
                    }
                }
                if (count > 0)
                    endpoint.jitter_avg_vs_min_rtt = sum / (float)count;
                else
                    endpoint.jitter_avg_vs_min_rtt = 0.0f;
            }

            // calculate max jitter vs. min rtt
            {
                var max = 0.0f;
                for (var i = 0; i < endpoint.config.rtt_history_size; i++)
                {
                    if (endpoint.rtt_history_buffer[i] >= 0.0f)
                    {
                        var difference = (endpoint.rtt_history_buffer[i] - endpoint.rtt_min);
                        if (difference > max)
                            max = difference;
                    }
                }
                endpoint.jitter_max_vs_min_rtt = max;
            }

            // calculate stddev jitter vs. avg rtt
            {
                var sum = 0.0f;
                var count = 0;
                for (var i = 0; i < endpoint.config.rtt_history_size; i++)
                {
                    if (endpoint.rtt_history_buffer[i] >= 0.0f)
                    {
                        var deviation = (endpoint.rtt_history_buffer[i] - endpoint.rtt_avg);
                        sum += deviation * deviation;
                        count++;
                    }
                }
                if (count > 0)
                    endpoint.jitter_stddev_vs_avg_rtt = (float)Math.Pow(sum / (float)count, 0.5f);
                else
                    endpoint.jitter_stddev_vs_avg_rtt = 0.0f;
            }

            // calculate packet loss
            {
                var base_sequence = (uint)((endpoint.sent_packets.sequence - endpoint.config.sent_packets_buffer_size + 1) + 0xFFFF);
                int i;
                var num_sent = 0;
                var num_dropped = 0;
                var num_samples = endpoint.config.sent_packets_buffer_size / 2;
                for (i = 0; i < num_samples; ++i)
                {
                    var sequence = (ushort)(base_sequence + i);
                    var sent_packet_data = sequence_buffer_find(endpoint.sent_packets, sequence);
                    if (sent_packet_data != null)
                    {
                        num_sent++;
                        if (!sent_packet_data.acked)
                            num_dropped++;
                    }
                }
                if (num_sent > 0)
                {
                    var packet_loss = num_dropped / (float)num_sent * 100.0f;
                    if (Math.Abs(endpoint.packet_loss - packet_loss) > 0.00001)
                        endpoint.packet_loss += (packet_loss - endpoint.packet_loss) * endpoint.config.packet_loss_smoothing_factor;
                    else
                        endpoint.packet_loss = packet_loss;
                }
                else
                {
                    endpoint.packet_loss = 0.0f;
                }
            }

            // calculate sent bandwidth
            {
                var base_sequence = (uint)((endpoint.sent_packets.sequence - endpoint.config.sent_packets_buffer_size + 1) + 0xFFFF);
                int i;
                long bytes_sent = 0;
                double start_time = float.MaxValue;
                var finish_time = 0.0;
                var num_samples = endpoint.config.sent_packets_buffer_size / 2;
                for (i = 0; i < num_samples; ++i)
                {
                    var sequence = (ushort)(base_sequence + i);
                    var sent_packet_data = sequence_buffer_find(endpoint.sent_packets, sequence);
                    if (sent_packet_data == null)
                        continue;
                    bytes_sent += sent_packet_data.packet_bytes;
                    if (sent_packet_data.time < start_time)
                        start_time = sent_packet_data.time;
                    if (sent_packet_data.time > finish_time)
                        finish_time = sent_packet_data.time;
                }
                if (start_time != float.MaxValue && finish_time > start_time)
                {
                    var sent_bandwidth_kbps = (float)(((double)bytes_sent) / (finish_time - start_time) * 8.0f / 1000.0f);
                    if (Math.Abs(endpoint.sent_bandwidth_kbps - sent_bandwidth_kbps) > 0.00001)
                        endpoint.sent_bandwidth_kbps += (sent_bandwidth_kbps - endpoint.sent_bandwidth_kbps) * endpoint.config.bandwidth_smoothing_factor;
                    else
                        endpoint.sent_bandwidth_kbps = sent_bandwidth_kbps;
                }
            }

            // calculate received bandwidth
            {
                var base_sequence = (uint)((endpoint.received_packets.sequence - endpoint.config.received_packets_buffer_size + 1) + 0xFFFF);
                int i;
                long bytes_sent = 0;
                double start_time = float.MaxValue;
                var finish_time = 0.0;
                var num_samples = endpoint.config.received_packets_buffer_size / 2;
                for (i = 0; i < num_samples; ++i)
                {
                    var sequence = (ushort)(base_sequence + i);
                    var received_packet_data = sequence_buffer_find(endpoint.received_packets, sequence);
                    if (received_packet_data == null)
                        continue;
                    bytes_sent += received_packet_data.packet_bytes;
                    if (received_packet_data.time < start_time)
                        start_time = received_packet_data.time;
                    if (received_packet_data.time > finish_time)
                        finish_time = received_packet_data.time;
                }
                if (start_time != float.MaxValue && finish_time > start_time)
                {
                    var received_bandwidth_kbps = (float)(((double)bytes_sent) / (finish_time - start_time) * 8.0f / 1000.0f);
                    if (Math.Abs(endpoint.received_bandwidth_kbps - received_bandwidth_kbps) > 0.00001)
                        endpoint.received_bandwidth_kbps += (received_bandwidth_kbps - endpoint.received_bandwidth_kbps) * endpoint.config.bandwidth_smoothing_factor;
                    else
                        endpoint.received_bandwidth_kbps = received_bandwidth_kbps;
                }
            }

            // calculate acked bandwidth
            {
                var base_sequence = (uint)((endpoint.sent_packets.sequence - endpoint.config.sent_packets_buffer_size + 1) + 0xFFFF);
                int i;
                long bytes_sent = 0;
                double start_time = float.MaxValue;
                var finish_time = 0.0;
                var num_samples = endpoint.config.sent_packets_buffer_size / 2;
                for (i = 0; i < num_samples; ++i)
                {
                    var sequence = (ushort)(base_sequence + i);
                    var sent_packet_data = sequence_buffer_find(endpoint.sent_packets, sequence);
                    if (sent_packet_data == null || !sent_packet_data.acked)
                        continue;
                    bytes_sent += sent_packet_data.packet_bytes;
                    if (sent_packet_data.time < start_time)
                        start_time = sent_packet_data.time;
                    if (sent_packet_data.time > finish_time)
                        finish_time = sent_packet_data.time;
                }
                if (start_time != float.MaxValue && finish_time > start_time)
                {
                    var acked_bandwidth_kbps = (float)(((double)bytes_sent) / (finish_time - start_time) * 8.0f / 1000.0f);
                    if (Math.Abs(endpoint.acked_bandwidth_kbps - acked_bandwidth_kbps) > 0.00001)
                        endpoint.acked_bandwidth_kbps += (acked_bandwidth_kbps - endpoint.acked_bandwidth_kbps) * endpoint.config.bandwidth_smoothing_factor;
                    else
                        endpoint.acked_bandwidth_kbps = acked_bandwidth_kbps;
                }
            }
        }

        // rtt and jitter are in milliseconds, packet loss is a percentage, bandwidth is in kilobits per-second

        public static float endpoint_rtt(this reliable_endpoint_t endpoint)
        {
            assert(endpoint != null);
            return endpoint.rtt;
        }

        public static float endpoint_rtt_min(this reliable_endpoint_t endpoint)
        {
            assert(endpoint != null);
            return endpoint.rtt_min;
        }

        public static float endpoint_rtt_max(this reliable_endpoint_t endpoint)
        {
            assert(endpoint != null);
            return endpoint.rtt_max;
        }

        public static float endpoint_rtt_avg(this reliable_endpoint_t endpoint)
        {
            assert(endpoint != null);
            return endpoint.rtt_avg;
        }

        public static float endpoint_jitter_avg_vs_min_rtt(this reliable_endpoint_t endpoint)
        {
            assert(endpoint != null);
            return endpoint.jitter_avg_vs_min_rtt;
        }

        public static float endpoint_jitter_max_vs_min_rtt(this reliable_endpoint_t endpoint)
        {
            assert(endpoint != null);
            return endpoint.jitter_max_vs_min_rtt;
        }

        public static float endpoint_jitter_stddev_vs_avg_rtt(this reliable_endpoint_t endpoint)
        {
            assert(endpoint != null);
            return endpoint.jitter_stddev_vs_avg_rtt;
        }

        public static float endpoint_packet_loss(this reliable_endpoint_t endpoint)
        {
            assert(endpoint != null);
            return endpoint.packet_loss;
        }

        public static void endpoint_bandwidth(this reliable_endpoint_t endpoint, out float sent_bandwidth_kbps, out float received_bandwidth_kbps, out float acked_bandwidth_kbps)
        {
            assert(endpoint != null);
            sent_bandwidth_kbps = endpoint.sent_bandwidth_kbps;
            received_bandwidth_kbps = endpoint.received_bandwidth_kbps;
            acked_bandwidth_kbps = endpoint.acked_bandwidth_kbps;
        }

        public static ulong[] endpoint_counters(this reliable_endpoint_t endpoint)
        {
            assert(endpoint != null);
            return endpoint.counters;
        }

        #endregion
    }

#if !YOJIMBO
    #region BufferEx

    internal static class BufferEx
    {
        readonly static Random Random = new Random(Guid.NewGuid().GetHashCode());
        readonly static Action<IntPtr, byte, int> MemsetDelegate;

        static BufferEx()
        {
            var dynamicMethod = new DynamicMethod("Memset", MethodAttributes.Public | MethodAttributes.Static, CallingConventions.Standard,
            null, new[] { typeof(IntPtr), typeof(byte), typeof(int) }, typeof(BufferEx), true);
            var generator = dynamicMethod.GetILGenerator();
            generator.Emit(OpCodes.Ldarg_0);
            generator.Emit(OpCodes.Ldarg_1);
            generator.Emit(OpCodes.Ldarg_2);
            generator.Emit(OpCodes.Initblk);
            generator.Emit(OpCodes.Ret);
            MemsetDelegate = (Action<IntPtr, byte, int>)dynamicMethod.CreateDelegate(typeof(Action<IntPtr, byte, int>));
        }

        public const int RAND_MAX = 0x7fff;
        public static int Rand() { lock (Random) return Random.Next(RAND_MAX); }

        public static void Copy(Array dst, Array src, int length) =>
            Buffer.BlockCopy(src, 0, dst, 0, length);
        public static void Copy(Array dst, int dstOffset, Array src, int srcOffset, int length) =>
            Buffer.BlockCopy(src, srcOffset, dst, dstOffset, length);
        public static void Copy<T>(ref T dst, T src = null, int? length = null) where T : class, new() =>
            dst = src ?? new T();

        public static byte[] Slice(Array src, int srcOffset, int length)
        {
            var r = new byte[length]; Buffer.BlockCopy(src, srcOffset, r, 0, length); return r;
        }

        public static void Set(Array array, byte value, int? length = null)
        {
            var gcHandle = GCHandle.Alloc(array, GCHandleType.Pinned);
            MemsetDelegate(gcHandle.AddrOfPinnedObject(), value, length ?? Buffer.ByteLength(array));
            gcHandle.Free();
        }
        public static void SetWithOffset(Array array, int offset, byte value, int? length = null)
        {
            var gcHandle = GCHandle.Alloc(array, GCHandleType.Pinned);
            MemsetDelegate(gcHandle.AddrOfPinnedObject() + offset, value, length ?? Buffer.ByteLength(array));
            gcHandle.Free();
        }

        public static void SetT<T>(IList<T> array, object value, int? length = null) where T : new()
        {
            for (var i = 0; i < (length ?? array.Count); i++)
                array[i] = value != null ? new T() : default(T);
        }
        public static void SetT<T>(ref T dst, object value, int? length = null) where T : new()
        {
            dst = value != null ? new T() : default(T);
        }

        public static T[] NewT<T>(int length) where T : new()
        {
            var array = new T[length];
            for (var i = 0; i < length; i++)
                array[i] = new T();
            return array;
        }
        public static T[][] NewT<T>(int length, int length2) where T : new()
        {
            var array = new T[length][];
            for (var i = 0; i < length; i++)
                array[i] = new T[length2];
            return array;
        }

        public static bool Equal<T>(IList<T> first, IList<T> second, int? length) =>
            (length == null) || (first.Count == length && second.Count == length) ?
                Enumerable.SequenceEqual(first, second) :
                Enumerable.SequenceEqual(first.Take(length.Value), second.Take(length.Value));
        public static bool Equal<T>(IList<T> first, int firstOffset, IList<T> second, int secondOffset, int? length = null) =>
            (length == null) || (first.Count - firstOffset == length && second.Count - secondOffset == length) ?
                Enumerable.SequenceEqual(first.Skip(firstOffset), second.Skip(firstOffset)) :
                Enumerable.SequenceEqual(first.Skip(firstOffset).Take(length.Value), second.Skip(firstOffset).Take(length.Value));
    }

    #endregion
#endif
}

namespace networkprotocol
{
    public static partial class reliable
    {
        static void check_handler(string condition, string function, string file, int line)
        {
            Console.Write($"check failed: ( {condition} ), function {function}, file {file}, line {line}\n");
            Debugger.Break();
            Environment.Exit(1);
        }

        [DebuggerStepThrough]
        public static void check(bool condition, [System.Runtime.CompilerServices.CallerArgumentExpression(nameof(condition))] string condition_text = null)
        {
            if (!condition)
            {
                var stackFrame = new StackTrace(1, true).GetFrame(0);
                check_handler(condition_text, stackFrame?.GetMethod()?.Name, stackFrame?.GetFileName(), stackFrame?.GetFileLineNumber() ?? 0);
            }
        }

        static void test_endian()
        {
            const ulong value = 0x11223344U;

            var bytes = BitConverter.GetBytes(value);

            check(bytes[0] == 0x44);
            check(bytes[1] == 0x33);
            check(bytes[2] == 0x22);
            check(bytes[3] == 0x11);
            //check(bytes[3] == 0x44);
            //check(bytes[2] == 0x33);
            //check(bytes[1] == 0x22);
            //check(bytes[0] == 0x11);
        }

        class test_sequence_data_t
        {
            public ushort sequence;
        }

        const int TEST_SEQUENCE_BUFFER_SIZE = 256;

        static void test_sequence_buffer()
        {
            var sequence_buffer = sequence_buffer_create<test_sequence_data_t>(
                TEST_SEQUENCE_BUFFER_SIZE,
                //typeof(test_sequence_data_t),
                null,
                null,
                null);

            check(sequence_buffer != null);
            check(sequence_buffer.sequence == 0);
            check(sequence_buffer.num_entries == TEST_SEQUENCE_BUFFER_SIZE);
            //check(sequence_buffer.entry_stride == typeof(test_sequence_data_t));

            int i;
            for (i = 0; i < TEST_SEQUENCE_BUFFER_SIZE; ++i)
                check(sequence_buffer_find(sequence_buffer, (ushort)i) == null);

            for (i = 0; i <= TEST_SEQUENCE_BUFFER_SIZE * 4; ++i)
            {
                var entry = sequence_buffer_insert(sequence_buffer, (ushort)i);
                check(entry != null);
                entry.sequence = (ushort)i;
                check(sequence_buffer.sequence == i + 1);
            }

            for (i = 0; i <= TEST_SEQUENCE_BUFFER_SIZE; ++i)
            {
                var entry = sequence_buffer_insert(sequence_buffer, (ushort)i);
                check(entry == null);
            }

            var index = TEST_SEQUENCE_BUFFER_SIZE * 4;
            for (i = 0; i < TEST_SEQUENCE_BUFFER_SIZE; ++i)
            {
                var entry = sequence_buffer_find(sequence_buffer, (ushort)index);
                check(entry != null);
                check(entry.sequence == (ushort)index);
                index--;
            }

            sequence_buffer_reset(sequence_buffer);

            check(sequence_buffer != null);
            check(sequence_buffer.sequence == 0);
            check(sequence_buffer.num_entries == TEST_SEQUENCE_BUFFER_SIZE);
            //check(sequence_buffer.entry_stride == typeof(test_sequence_data_t));

            for (i = 0; i < TEST_SEQUENCE_BUFFER_SIZE; ++i)
                check(sequence_buffer_find(sequence_buffer, (ushort)i) == null);

            sequence_buffer_destroy(ref sequence_buffer);
        }

        static void test_generate_ack_bits()
        {
            var sequence_buffer = sequence_buffer_create<test_sequence_data_t>(
                TEST_SEQUENCE_BUFFER_SIZE,
                //typeof(test_sequence_data_t),
                null,
                null,
                null);

            sequence_buffer_generate_ack_bits(sequence_buffer, out var ack, out var ack_bits);
            check(ack == 0xFFFF);
            check(ack_bits == 0);

            int i;
            for (i = 0; i <= TEST_SEQUENCE_BUFFER_SIZE; ++i)
                sequence_buffer_insert(sequence_buffer, (ushort)i);

            sequence_buffer_generate_ack_bits(sequence_buffer, out ack, out ack_bits);
            check(ack == TEST_SEQUENCE_BUFFER_SIZE);
            check(ack_bits == 0xFFFFFFFF);

            sequence_buffer_reset(sequence_buffer);

            var input_acks = new ushort[] { 1, 5, 9, 11 };
            var input_num_acks = input_acks.Length;
            for (i = 0; i < input_num_acks; ++i)
                sequence_buffer_insert(sequence_buffer, input_acks[i]);

            sequence_buffer_generate_ack_bits(sequence_buffer, out ack, out ack_bits);

            check(ack == 11);
            check(ack_bits == (1 | (1 << (11 - 9)) | (1 << (11 - 5)) | (1 << (11 - 1))));

            sequence_buffer_destroy(ref sequence_buffer);
        }

        static void test_packet_header()
        {
            var packet_data = new byte[MAX_PACKET_HEADER_BYTES];

            // worst case, sequence and ack are far apart, no packets acked.

            ushort write_sequence = 10000;
            ushort write_ack = 100;
            var write_ack_bits = 0U;

            var bytes_written = write_packet_header(packet_data, write_sequence, write_ack, write_ack_bits);

            check(bytes_written == MAX_PACKET_HEADER_BYTES);

            var bytes_read = read_packet_header("test_packet_header", packet_data, 0, bytes_written, out var read_sequence, out var read_ack, out var read_ack_bits);

            check(bytes_read == bytes_written);

            check(read_sequence == write_sequence);
            check(read_ack == write_ack);
            check(read_ack_bits == write_ack_bits);

            // rare case. sequence and ack are far apart, significant # of acks are missing

            write_sequence = 10000;
            write_ack = 100;
            write_ack_bits = 0xFEFEFFFEU;

            bytes_written = write_packet_header(packet_data, write_sequence, write_ack, write_ack_bits);

            check(bytes_written == 1 + 2 + 2 + 3);

            bytes_read = read_packet_header("test_packet_header", packet_data, 0, bytes_written, out read_sequence, out read_ack, out read_ack_bits);

            check(bytes_read == bytes_written);

            check(read_sequence == write_sequence);
            check(read_ack == write_ack);
            check(read_ack_bits == write_ack_bits);

            // common case under packet loss. sequence and ack are close together, some acks are missing

            write_sequence = 200;
            write_ack = 100;
            write_ack_bits = 0xFFFEFFFF;

            bytes_written = write_packet_header(packet_data, write_sequence, write_ack, write_ack_bits);

            check(bytes_written == 1 + 2 + 1 + 1);

            bytes_read = read_packet_header("test_packet_header", packet_data, 0, bytes_written, out read_sequence, out read_ack, out read_ack_bits);

            check(bytes_read == bytes_written);

            check(read_sequence == write_sequence);
            check(read_ack == write_ack);
            check(read_ack_bits == write_ack_bits);

            // ideal case. no packet loss.

            write_sequence = 200;
            write_ack = 100;
            write_ack_bits = 0xFFFFFFFF;

            bytes_written = write_packet_header(packet_data, write_sequence, write_ack, write_ack_bits);

            check(bytes_written == 1 + 2 + 1);

            bytes_read = read_packet_header("test_packet_header", packet_data, 0, bytes_written, out read_sequence, out read_ack, out read_ack_bits);

            check(bytes_read == bytes_written);

            check(read_sequence == write_sequence);
            check(read_ack == write_ack);
            check(read_ack_bits == write_ack_bits);
        }

        class test_context_t
        {
            public bool drop;
            public int allow_packets;
            public reliable_endpoint_t sender;
            public reliable_endpoint_t receiver;
        }

        static void test_default_context(test_context_t context)
        {
            context.drop = false;
            context.allow_packets = -1;
            context.sender = null;
            context.receiver = null;
        }

        static void test_transmit_packet_function(object _context, ulong id, ushort sequence, byte[] packet_data, int packet_bytes)
        {
            var context = (test_context_t)_context;

            if (context.drop)
                return;

            if (context.allow_packets >= 0)
            {
                if (context.allow_packets == 0)
                    return;

                context.allow_packets--;
            }

            if (id == 0)
                endpoint_receive_packet(context.receiver, packet_data, packet_bytes);
            else if (id == 1)
                endpoint_receive_packet(context.sender, packet_data, packet_bytes);
        }

        static bool test_process_packet_function(object _context, ulong id, ushort sequence, byte[] packet_data, int packet_bytes)
        {
            var context = (test_context_t)_context;

            return true;
        }

        const int TEST_ACKS_NUM_ITERATIONS = 256;

        static void test_acks()
        {
            var time = 100.0;

            var context = new test_context_t();
            test_default_context(context);

            default_config(out var sender_config);
            default_config(out var receiver_config);

            sender_config.context = context;
            sender_config.id = 0;
            sender_config.transmit_packet_function = test_transmit_packet_function;
            sender_config.process_packet_function = test_process_packet_function;

            receiver_config.context = context;
            receiver_config.id = 1;
            receiver_config.transmit_packet_function = test_transmit_packet_function;
            receiver_config.process_packet_function = test_process_packet_function;

            context.sender = endpoint_create(sender_config, time);
            context.receiver = endpoint_create(receiver_config, time);

            const double delta_time = 0.01;

            int i;
            for (i = 0; i < TEST_ACKS_NUM_ITERATIONS; ++i)
            {
                var dummy_packet = new byte[8];

                endpoint_send_packet(context.sender, dummy_packet, dummy_packet.Length);
                endpoint_send_packet(context.receiver, dummy_packet, dummy_packet.Length);

                endpoint_update(context.sender, time);
                endpoint_update(context.receiver, time);

                time += delta_time;
            }

            var sender_acked_packet = new byte[TEST_ACKS_NUM_ITERATIONS];
            var sender_acks = endpoint_get_acks(context.sender, out var sender_num_acks);
            for (i = 0; i < sender_num_acks; ++i)
                if (sender_acks[i] < TEST_ACKS_NUM_ITERATIONS)
                    sender_acked_packet[sender_acks[i]] = 1;
            for (i = 0; i < TEST_ACKS_NUM_ITERATIONS / 2; ++i)
                check(sender_acked_packet[i] == 1);

            var receiver_acked_packet = new byte[TEST_ACKS_NUM_ITERATIONS];
            var receiver_acks = endpoint_get_acks(context.receiver, out var receiver_num_acks);
            for (i = 0; i < receiver_num_acks; ++i)
                if (receiver_acks[i] < TEST_ACKS_NUM_ITERATIONS)
                    receiver_acked_packet[receiver_acks[i]] = 1;
            for (i = 0; i < TEST_ACKS_NUM_ITERATIONS / 2; ++i)
                check(receiver_acked_packet[i] == 1);

            endpoint_destroy(ref context.sender);
            endpoint_destroy(ref context.receiver);
        }

        static void test_acks_packet_loss()
        {
            var time = 100.0;

            var context = new test_context_t();
            test_default_context(context);

            default_config(out var sender_config);
            default_config(out var receiver_config);

            sender_config.context = context;
            sender_config.id = 0;
            sender_config.transmit_packet_function = test_transmit_packet_function;
            sender_config.process_packet_function = test_process_packet_function;

            receiver_config.context = context;
            receiver_config.id = 1;
            receiver_config.transmit_packet_function = test_transmit_packet_function;
            receiver_config.process_packet_function = test_process_packet_function;

            context.sender = endpoint_create(sender_config, time);
            context.receiver = endpoint_create(receiver_config, time);

            const double delta_time = 0.1f;

            int i;
            for (i = 0; i < TEST_ACKS_NUM_ITERATIONS; ++i)
            {
                var dummy_packet = new byte[8];

                context.drop = (i % 2) != 0;

                endpoint_send_packet(context.sender, dummy_packet, dummy_packet.Length);
                endpoint_send_packet(context.receiver, dummy_packet, dummy_packet.Length);

                endpoint_update(context.sender, time);
                endpoint_update(context.receiver, time);

                time += delta_time;
            }

            var sender_acked_packet = new byte[TEST_ACKS_NUM_ITERATIONS];
            var sender_acks = endpoint_get_acks(context.sender, out var sender_num_acks);
            for (i = 0; i < sender_num_acks; ++i)
                if (sender_acks[i] < TEST_ACKS_NUM_ITERATIONS)
                    sender_acked_packet[sender_acks[i]] = 1;
            for (i = 0; i < TEST_ACKS_NUM_ITERATIONS / 2; ++i)
                check(sender_acked_packet[i] == (i + 1) % 2);

            var receiver_acked_packet = new byte[TEST_ACKS_NUM_ITERATIONS];
            var receiver_acks = endpoint_get_acks(context.receiver, out var receiver_num_acks);
            for (i = 0; i < receiver_num_acks; ++i)
                if (receiver_acks[i] < TEST_ACKS_NUM_ITERATIONS)
                    receiver_acked_packet[receiver_acks[i]] = 1;
            for (i = 0; i < TEST_ACKS_NUM_ITERATIONS / 2; ++i)
                check(receiver_acked_packet[i] == (i + 1) % 2);

            endpoint_destroy(ref context.sender);
            endpoint_destroy(ref context.receiver);
        }

        static int test_duplicate_packets_num_processed = 0;

        static void test_duplicate_packets_transmit_packet_function(object _context, ulong id, ushort sequence, byte[] packet_data, int packet_bytes)
        {
            var context = (test_context_t)_context;

            if (id == 0)
            {
                // deliver each packet to the receiver twice, simulating duplication on the network
                endpoint_receive_packet(context.receiver, packet_data, packet_bytes);
                endpoint_receive_packet(context.receiver, packet_data, packet_bytes);
            }
        }

        static bool test_duplicate_packets_process_packet_function(object context, ulong id, ushort sequence, byte[] packet_data, int packet_bytes)
        {
            test_duplicate_packets_num_processed++;
            return true;
        }

        const int TEST_DUPLICATE_PACKETS_NUM_ITERATIONS = 16;

        static void test_duplicate_packets()
        {
            var time = 100.0;

            var context = new test_context_t();
            test_default_context(context);

            default_config(out var sender_config);
            default_config(out var receiver_config);

            sender_config.name = "sender";
            sender_config.context = context;
            sender_config.id = 0;
            sender_config.transmit_packet_function = test_duplicate_packets_transmit_packet_function;
            sender_config.process_packet_function = test_process_packet_function;

            receiver_config.name = "receiver";
            receiver_config.context = context;
            receiver_config.id = 1;
            receiver_config.transmit_packet_function = test_duplicate_packets_transmit_packet_function;
            receiver_config.process_packet_function = test_duplicate_packets_process_packet_function;

            context.sender = endpoint_create(sender_config, time);
            context.receiver = endpoint_create(receiver_config, time);

            test_duplicate_packets_num_processed = 0;

            int i;
            for (i = 0; i < TEST_DUPLICATE_PACKETS_NUM_ITERATIONS; ++i)
            {
                var dummy_packet = new byte[8];
                endpoint_send_packet(context.sender, dummy_packet, dummy_packet.Length);
            }

            check(test_duplicate_packets_num_processed == TEST_DUPLICATE_PACKETS_NUM_ITERATIONS);

            var receiver_counters = endpoint_counters(context.receiver);

            check(receiver_counters[ENDPOINT_COUNTER_NUM_PACKETS_RECEIVED] == 2 * TEST_DUPLICATE_PACKETS_NUM_ITERATIONS);
            check(receiver_counters[ENDPOINT_COUNTER_NUM_PACKETS_DUPLICATE] == TEST_DUPLICATE_PACKETS_NUM_ITERATIONS);

            // duplicate fragments arriving after their packet was delivered must not restart reassembly

            var fragmented_sequence = endpoint_next_packet_sequence(context.sender);

            var large_packet = new byte[2048];
            endpoint_send_packet(context.sender, large_packet, large_packet.Length);

            check(test_duplicate_packets_num_processed == TEST_DUPLICATE_PACKETS_NUM_ITERATIONS + 1);
            check(!sequence_buffer_exists(context.receiver.fragment_reassembly, fragmented_sequence));

            endpoint_destroy(ref context.sender);
            endpoint_destroy(ref context.receiver);
        }

        static byte[] test_stale_packets_first_packet = new byte[64];
        static int test_stale_packets_first_packet_bytes = 0;
        static int test_stale_packets_num_processed = 0;

        static void test_stale_packets_transmit_packet_function(object _context, ulong id, ushort sequence, byte[] packet_data, int packet_bytes)
        {
            var context = (test_context_t)_context;

            if (id == 0)
            {
                if (sequence == 0 && test_stale_packets_first_packet_bytes == 0)
                {
                    assert(packet_bytes <= test_stale_packets_first_packet.Length);
                    Buffer.BlockCopy(packet_data, 0, test_stale_packets_first_packet, 0, packet_bytes);
                    test_stale_packets_first_packet_bytes = packet_bytes;
                }

                endpoint_receive_packet(context.receiver, packet_data, packet_bytes);
            }
        }

        static bool test_stale_packets_process_packet_function(object context, ulong id, ushort sequence, byte[] packet_data, int packet_bytes)
        {
            test_stale_packets_num_processed++;
            return true;
        }

        const int TEST_STALE_PACKETS_NUM_ITERATIONS = 300;

        static void test_stale_packets()
        {
            var time = 100.0;

            var context = new test_context_t();
            test_default_context(context);

            default_config(out var sender_config);
            default_config(out var receiver_config);

            sender_config.name = "sender";
            sender_config.context = context;
            sender_config.id = 0;
            sender_config.transmit_packet_function = test_stale_packets_transmit_packet_function;
            sender_config.process_packet_function = test_process_packet_function;

            receiver_config.name = "receiver";
            receiver_config.context = context;
            receiver_config.id = 1;
            receiver_config.transmit_packet_function = test_stale_packets_transmit_packet_function;
            receiver_config.process_packet_function = test_stale_packets_process_packet_function;

            context.sender = endpoint_create(sender_config, time);
            context.receiver = endpoint_create(receiver_config, time);

            test_stale_packets_first_packet_bytes = 0;
            test_stale_packets_num_processed = 0;

            // send enough packets that sequence 0 falls out of the receive window (256 entries)

            int i;
            for (i = 0; i < TEST_STALE_PACKETS_NUM_ITERATIONS; ++i)
            {
                var dummy_packet = new byte[8];
                endpoint_send_packet(context.sender, dummy_packet, dummy_packet.Length);
            }

            check(test_stale_packets_num_processed == TEST_STALE_PACKETS_NUM_ITERATIONS);
            check(test_stale_packets_first_packet_bytes > 0);

            // replaying the first packet must be rejected as stale, not processed

            endpoint_receive_packet(context.receiver, test_stale_packets_first_packet, test_stale_packets_first_packet_bytes);

            check(test_stale_packets_num_processed == TEST_STALE_PACKETS_NUM_ITERATIONS);

            var receiver_counters = endpoint_counters(context.receiver);

            check(receiver_counters[ENDPOINT_COUNTER_NUM_PACKETS_STALE] == 1);

            endpoint_destroy(ref context.sender);
            endpoint_destroy(ref context.receiver);
        }

        const int TEST_ACK_BUFFER_OVERFLOW_NUM_PACKETS = 32;
        const int TEST_ACK_BUFFER_OVERFLOW_BUFFER_SIZE = 16;

        static void test_ack_buffer_overflow()
        {
            var time = 100.0;

            var context = new test_context_t();
            test_default_context(context);

            default_config(out var sender_config);
            default_config(out var receiver_config);

            // undersized ack buffer on the sender, so a single received packet acking 32 sent packets overflows it

            sender_config.ack_buffer_size = TEST_ACK_BUFFER_OVERFLOW_BUFFER_SIZE;

            sender_config.name = "sender";
            sender_config.context = context;
            sender_config.id = 0;
            sender_config.transmit_packet_function = test_transmit_packet_function;
            sender_config.process_packet_function = test_process_packet_function;

            receiver_config.name = "receiver";
            receiver_config.context = context;
            receiver_config.id = 1;
            receiver_config.transmit_packet_function = test_transmit_packet_function;
            receiver_config.process_packet_function = test_process_packet_function;

            context.sender = endpoint_create(sender_config, time);
            context.receiver = endpoint_create(receiver_config, time);

            int i;
            for (i = 0; i < TEST_ACK_BUFFER_OVERFLOW_NUM_PACKETS; ++i)
            {
                var dummy_packet = new byte[8];
                endpoint_send_packet(context.sender, dummy_packet, dummy_packet.Length);
            }

            // one packet back from the receiver acks all 32, but only 16 fit in the ack buffer. the rest are dropped

            {
                var dummy_packet = new byte[8];
                endpoint_send_packet(context.receiver, dummy_packet, dummy_packet.Length);
            }

            endpoint_get_acks(context.sender, out var num_acks);
            check(num_acks == TEST_ACK_BUFFER_OVERFLOW_BUFFER_SIZE);

            var sender_counters = endpoint_counters(context.sender);
            check(sender_counters[ENDPOINT_COUNTER_NUM_PACKETS_ACKED] == TEST_ACK_BUFFER_OVERFLOW_BUFFER_SIZE);

            // once the caller clears acks, the dropped acks are reported on the next packet that covers them

            endpoint_clear_acks(context.sender);

            {
                var dummy_packet = new byte[8];
                endpoint_send_packet(context.receiver, dummy_packet, dummy_packet.Length);
            }

            endpoint_get_acks(context.sender, out num_acks);
            check(num_acks == TEST_ACK_BUFFER_OVERFLOW_NUM_PACKETS - TEST_ACK_BUFFER_OVERFLOW_BUFFER_SIZE);
            check(sender_counters[ENDPOINT_COUNTER_NUM_PACKETS_ACKED] == TEST_ACK_BUFFER_OVERFLOW_NUM_PACKETS);

            endpoint_destroy(ref context.sender);
            endpoint_destroy(ref context.receiver);
        }

        const int TEST_MAX_PACKET_BYTES = 4 * 1024;

        static void generate_packet_data_with_size(ushort sequence, byte[] packet_data, int packet_bytes)
        {
            assert(packet_bytes >= 2);
            assert(packet_bytes <= TEST_MAX_PACKET_BYTES);

            packet_data[0] = (byte)(sequence & 0xFF);
            packet_data[1] = (byte)((sequence >> 8) & 0xFF);
            int i;
            for (i = 2; i < packet_bytes; ++i)
                packet_data[i] = (byte)((i + sequence) % 256);
        }

        static int generate_packet_data(ushort sequence, byte[] packet_data)
        {
            var packet_bytes = ((sequence * 1023) % (TEST_MAX_PACKET_BYTES - 2)) + 2;
            generate_packet_data_with_size(sequence, packet_data, packet_bytes);
            return packet_bytes;
        }

        static void validate_packet_data(byte[] packet_data, int packet_bytes)
        {
            assert(packet_bytes >= 2);
            assert(packet_bytes <= TEST_MAX_PACKET_BYTES);
            ushort sequence = 0;
            sequence |= packet_data[0];
            sequence |= (ushort)(packet_data[1] << 8);
            check(packet_bytes == (sequence * 1023 % (TEST_MAX_PACKET_BYTES - 2)) + 2);
            int i;
            for (i = 2; i < packet_bytes; ++i)
                check(packet_data[i] == (byte)((i + sequence) % 256));
        }

        static bool test_process_packet_function_validate(object context, ulong id, ushort sequence, byte[] packet_data, int packet_bytes)
        {
            assert(packet_data != null);
            assert(packet_bytes > 0);
            assert(packet_bytes <= TEST_MAX_PACKET_BYTES);

            validate_packet_data(packet_data, packet_bytes);

            return true;
        }

        static int generate_packet_data_large(byte[] packet_data)
        {
            var data_bytes = TEST_MAX_PACKET_BYTES - 2;
            assert(data_bytes >= 2);
            assert(data_bytes <= (1 << 16));

            packet_data[0] = (byte)(data_bytes & 0xFF);
            packet_data[1] = (byte)((data_bytes >> 8) & 0xFF);
            int i;
            for (i = 2; i < data_bytes; ++i)
                packet_data[i] = (byte)(i % 256);
            return data_bytes + 2;
        }

        static bool test_process_packet_function_validate_large(object context, ulong id, ushort sequence, byte[] packet_data, int packet_bytes)
        {
            assert(packet_data != null);
            assert(packet_bytes >= 2);
            assert(packet_bytes <= TEST_MAX_PACKET_BYTES);

            ushort data_bytes = 0;
            data_bytes |= packet_data[0];
            data_bytes |= (ushort)(packet_data[1] << 8);
            check(packet_bytes == data_bytes + 2);
            int i;
            for (i = 2; i < data_bytes; ++i)
                check(packet_data[i] == (byte)(i % 256));

            return true;
        }

        static void test_packets()
        {
            var time = 100.0;

            var context = new test_context_t();
            test_default_context(context);

            default_config(out var sender_config);
            default_config(out var receiver_config);

            sender_config.fragment_above = 500;
            receiver_config.fragment_above = 500;

            sender_config.name = "sender";
            sender_config.context = context;
            sender_config.id = 0;
            sender_config.transmit_packet_function = test_transmit_packet_function;
            sender_config.process_packet_function = test_process_packet_function_validate;

            receiver_config.name = "receiver";
            receiver_config.context = context;
            receiver_config.id = 1;
            receiver_config.transmit_packet_function = test_transmit_packet_function;
            receiver_config.process_packet_function = test_process_packet_function_validate;

            context.sender = endpoint_create(sender_config, time);
            context.receiver = endpoint_create(receiver_config, time);

            const double delta_time = 0.1;

            int i;
            for (i = 0; i < 16; ++i)
            {
                {
                    var packet_data = new byte[TEST_MAX_PACKET_BYTES];
                    var sequence = endpoint_next_packet_sequence(context.sender);
                    var packet_bytes = generate_packet_data(sequence, packet_data);
                    endpoint_send_packet(context.sender, packet_data, packet_bytes);
                }

                {
                    var packet_data = new byte[TEST_MAX_PACKET_BYTES];
                    var sequence = endpoint_next_packet_sequence(context.sender);
                    var packet_bytes = generate_packet_data(sequence, packet_data);
                    endpoint_send_packet(context.sender, packet_data, packet_bytes);
                }

                endpoint_update(context.sender, time);
                endpoint_update(context.receiver, time);

                endpoint_clear_acks(context.sender);
                endpoint_clear_acks(context.receiver);

                time += delta_time;
            }

            endpoint_destroy(ref context.sender);
            endpoint_destroy(ref context.receiver);
        }

        static void test_large_packets()
        {
            var time = 100.0;

            var context = new test_context_t();
            test_default_context(context);

            default_config(out var sender_config);
            default_config(out var receiver_config);

            sender_config.max_packet_size = TEST_MAX_PACKET_BYTES;
            receiver_config.max_packet_size = TEST_MAX_PACKET_BYTES;

            sender_config.fragment_above = TEST_MAX_PACKET_BYTES;
            receiver_config.fragment_above = TEST_MAX_PACKET_BYTES;

            sender_config.name = "sender";
            sender_config.context = context;
            sender_config.id = 0;
            sender_config.transmit_packet_function = test_transmit_packet_function;
            sender_config.process_packet_function = test_process_packet_function_validate_large;

            receiver_config.name = "receiver";
            receiver_config.context = context;
            receiver_config.id = 1;
            receiver_config.transmit_packet_function = test_transmit_packet_function;
            receiver_config.process_packet_function = test_process_packet_function_validate_large;

            context.sender = endpoint_create(sender_config, time);
            context.receiver = endpoint_create(receiver_config, time);

            {
                var packet_data = new byte[TEST_MAX_PACKET_BYTES];
                var packet_bytes = generate_packet_data_large(packet_data);
                check(packet_bytes == TEST_MAX_PACKET_BYTES);
                endpoint_send_packet(context.sender, packet_data, packet_bytes);
            }

            endpoint_update(context.sender, time);
            endpoint_update(context.receiver, time);

            endpoint_clear_acks(context.sender);
            endpoint_clear_acks(context.receiver);

            var receiver_counters = endpoint_counters(context.receiver);
            check(receiver_counters[ENDPOINT_COUNTER_NUM_PACKETS_TOO_LARGE_TO_RECEIVE] == 0);
            check(receiver_counters[ENDPOINT_COUNTER_NUM_PACKETS_RECEIVED] == 1);

            endpoint_destroy(ref context.sender);
            endpoint_destroy(ref context.receiver);
        }

        static void test_sequence_buffer_rollover()
        {
            var time = 100.0;

            var context = new test_context_t();
            test_default_context(context);

            default_config(out var sender_config);
            default_config(out var receiver_config);

            sender_config.fragment_above = 500;
            receiver_config.fragment_above = 500;

            sender_config.name = "sender";
            sender_config.context = context;
            sender_config.id = 0;
            sender_config.transmit_packet_function = test_transmit_packet_function;
            sender_config.process_packet_function = test_process_packet_function;

            receiver_config.name = "receiver";
            receiver_config.context = context;
            receiver_config.id = 1;
            receiver_config.transmit_packet_function = test_transmit_packet_function;
            receiver_config.process_packet_function = test_process_packet_function;

            context.sender = endpoint_create(sender_config, time);
            context.receiver = endpoint_create(receiver_config, time);

            var num_packets_sent = 0;
            int i;
            for (i = 0; i <= 32767; ++i)
            {
                var packet_data = new byte[16];
                var packet_bytes = 16;
                endpoint_next_packet_sequence(context.sender);
                endpoint_send_packet(context.sender, packet_data, packet_bytes);

                ++num_packets_sent;
            }

            {
                var packet_data = new byte[TEST_MAX_PACKET_BYTES];
                var packet_bytes = TEST_MAX_PACKET_BYTES;
                endpoint_next_packet_sequence(context.sender);
                endpoint_send_packet(context.sender, packet_data, packet_bytes);
                ++num_packets_sent;
            }

            var receiver_counters = endpoint_counters(context.receiver);

            check(receiver_counters[ENDPOINT_COUNTER_NUM_PACKETS_RECEIVED] == (ushort)num_packets_sent);
            check(receiver_counters[ENDPOINT_COUNTER_NUM_FRAGMENTS_INVALID] == 0);

            endpoint_destroy(ref context.sender);
            endpoint_destroy(ref context.receiver);
        }

        // reliable.c checks for leaks with a tracking allocator. the C# port allocates managed arrays, so the equivalent check is that no
        // reassembly slot that is not in use still holds a buffer (which is what the leak was: an evicted entry kept its packet_data)

        static void check_no_stale_reassembly_buffers(reliable_endpoint_t endpoint)
        {
            var fragment_reassembly = endpoint.fragment_reassembly;
            int i;
            for (i = 0; i < fragment_reassembly.num_entries; ++i)
                if (fragment_reassembly.entry_sequence[i] == 0xFFFFFFFF)
                    check(fragment_reassembly.entry_data[i].packet_data == null);
        }

        static void test_fragment_cleanup()
        {
            var time = 100.0;

            var context = new test_context_t();
            test_default_context(context);

            default_config(out var sender_config);
            default_config(out var receiver_config);

            receiver_config.fragment_reassembly_buffer_size = 4;

            sender_config.name = "sender";
            sender_config.context = context;
            sender_config.id = 0;
            sender_config.transmit_packet_function = test_transmit_packet_function;
            sender_config.process_packet_function = test_process_packet_function;

            receiver_config.name = "receiver";
            receiver_config.context = context;
            receiver_config.id = 1;
            receiver_config.transmit_packet_function = test_transmit_packet_function;
            receiver_config.process_packet_function = test_process_packet_function;

            context.sender = endpoint_create(sender_config, time);
            context.receiver = endpoint_create(receiver_config, time);

            const double delta_time = 0.1;

            var packet_sizes = new int[] {
                sender_config.fragment_size + sender_config.fragment_size / 2,
                10,
                10,
                10,
                10,
            };

            // Make sure we're sending more than receiver_config.fragment_reassembly_buffer_size packets, so the buffer wraps around.
            assert(packet_sizes.Length > receiver_config.fragment_reassembly_buffer_size);

            int i;
            for (i = 0; i < packet_sizes.Length; ++i)
            {
                // Only allow one packet per transmit, so that our fragmented packets are only partially delivered.
                context.allow_packets = 1;
                {
                    var packet_data = new byte[TEST_MAX_PACKET_BYTES];
                    var sequence = endpoint_next_packet_sequence(context.sender);
                    generate_packet_data_with_size(sequence, packet_data, packet_sizes[i]);
                    endpoint_send_packet(context.sender, packet_data, packet_sizes[i]);
                }

                endpoint_update(context.sender, time);
                endpoint_update(context.receiver, time);

                endpoint_clear_acks(context.sender);
                endpoint_clear_acks(context.receiver);

                time += delta_time;
            }

            // Make sure that the partially reassembled packet was released when the buffer wrapped past it.
            check_no_stale_reassembly_buffers(context.receiver);

            endpoint_destroy(ref context.sender);
            endpoint_destroy(ref context.receiver);
        }

        // security#26-2: the reassembly buffer must not leak stale memory into a delivered packet. managed arrays are zeroed,
        // so this is a regression test that the port keeps it that way (and keeps the 8 bytes of slack reliable.c allocates)

        static void test_fragment_reassembly_buffer_zeroed()
        {
            var time = 100.0;

            var context = new test_context_t();
            test_default_context(context);

            default_config(out var sender_config);
            default_config(out var receiver_config);

            sender_config.name = "sender";
            sender_config.context = context;
            sender_config.id = 0;
            sender_config.transmit_packet_function = test_transmit_packet_function;
            sender_config.process_packet_function = test_process_packet_function;

            receiver_config.name = "receiver";
            receiver_config.context = context;
            receiver_config.id = 1;
            receiver_config.transmit_packet_function = test_transmit_packet_function;
            receiver_config.process_packet_function = test_process_packet_function;

            context.sender = endpoint_create(sender_config, time);
            context.receiver = endpoint_create(receiver_config, time);
            check(context.sender != null);
            check(context.receiver != null);

            // deliver only the first fragment: the reassembly buffer is allocated and fragment 0 is stored, but the tail of the buffer is never written
            context.allow_packets = 1;

            var packet_data = new byte[TEST_MAX_PACKET_BYTES];
            var packet_bytes = sender_config.fragment_size + sender_config.fragment_size / 2;
            var sequence = endpoint_next_packet_sequence(context.sender);
            generate_packet_data_with_size(sequence, packet_data, packet_bytes);
            endpoint_send_packet(context.sender, packet_data, packet_bytes);

            var reassembly_data = sequence_buffer_find(context.receiver.fragment_reassembly, sequence);

            check(reassembly_data != null);
            check(reassembly_data.packet_data != null);

            var packet_buffer_size = MAX_PACKET_HEADER_BYTES + reassembly_data.num_fragments_total * sender_config.fragment_size + 8;

            check(reassembly_data.packet_data.Length == packet_buffer_size);
            check(reassembly_data.packet_data[packet_buffer_size - 1] == 0);

            endpoint_destroy(ref context.sender);
            endpoint_destroy(ref context.receiver);
        }

        static void test_endpoint_reset()
        {
            var time = 100.0;

            var context = new test_context_t();
            test_default_context(context);

            default_config(out var sender_config);
            default_config(out var receiver_config);

            sender_config.fragment_above = 500;
            receiver_config.fragment_above = 500;

            sender_config.name = "sender";
            sender_config.context = context;
            sender_config.id = 0;
            sender_config.transmit_packet_function = test_transmit_packet_function;
            sender_config.process_packet_function = test_process_packet_function;

            receiver_config.name = "receiver";
            receiver_config.context = context;
            receiver_config.id = 1;
            receiver_config.transmit_packet_function = test_transmit_packet_function;
            receiver_config.process_packet_function = test_process_packet_function;

            context.sender = endpoint_create(sender_config, time);
            context.receiver = endpoint_create(receiver_config, time);

            // exchange packets both ways so acks and counters accumulate

            int i;
            for (i = 0; i < 8; ++i)
            {
                var dummy_packet = new byte[8];

                endpoint_send_packet(context.sender, dummy_packet, dummy_packet.Length);
                endpoint_send_packet(context.receiver, dummy_packet, dummy_packet.Length);

                endpoint_update(context.sender, time);
                endpoint_update(context.receiver, time);

                time += 0.01;
            }

            endpoint_get_acks(context.sender, out var num_acks);
            check(num_acks > 0);
            check(endpoint_counters(context.sender)[ENDPOINT_COUNTER_NUM_PACKETS_SENT] > 0);

            // leave a fragment reassembly in progress on the receiver by delivering only the first fragment of a large packet

            context.allow_packets = 1;
            {
                var large_packet = new byte[1500];
                endpoint_send_packet(context.sender, large_packet, large_packet.Length);
            }
            context.allow_packets = -1;

            var in_progress = 0;
            for (i = 0; i < context.receiver.fragment_reassembly.num_entries; ++i)
                if (context.receiver.fragment_reassembly.entry_data[i].packet_data != null)
                    in_progress++;
            check(in_progress == 1);

            endpoint_reset(context.sender);
            endpoint_reset(context.receiver);

            check(endpoint_next_packet_sequence(context.sender) == 0);
            check(endpoint_next_packet_sequence(context.receiver) == 0);

            endpoint_get_acks(context.sender, out num_acks);
            check(num_acks == 0);

            for (i = 0; i < ENDPOINT_NUM_COUNTERS; ++i)
            {
                check(endpoint_counters(context.sender)[i] == 0);
                check(endpoint_counters(context.receiver)[i] == 0);
            }

            // reset must have released the in-progress reassembly buffer

            for (i = 0; i < context.receiver.fragment_reassembly.num_entries; ++i)
                check(context.receiver.fragment_reassembly.entry_data[i].packet_data == null);

            // the endpoints must work normally after reset

            for (i = 0; i < 8; ++i)
            {
                var dummy_packet = new byte[8];

                endpoint_send_packet(context.sender, dummy_packet, dummy_packet.Length);
                endpoint_send_packet(context.receiver, dummy_packet, dummy_packet.Length);

                endpoint_update(context.sender, time);
                endpoint_update(context.receiver, time);

                time += 0.01;
            }

            endpoint_get_acks(context.sender, out num_acks);
            check(num_acks > 0);
            check(endpoint_counters(context.receiver)[ENDPOINT_COUNTER_NUM_PACKETS_RECEIVED] > 0);

            endpoint_destroy(ref context.sender);
            endpoint_destroy(ref context.receiver);
        }

        static void test_rtt()
        {
            var time = 100.0;
            const double delta_time = 0.01;

            var context = new test_context_t();
            test_default_context(context);

            default_config(out var sender_config);
            default_config(out var receiver_config);

            sender_config.context = context;
            sender_config.id = 0;
            sender_config.transmit_packet_function = test_transmit_packet_function;
            sender_config.process_packet_function = test_process_packet_function;

            receiver_config.context = context;
            receiver_config.id = 1;
            receiver_config.transmit_packet_function = test_transmit_packet_function;
            receiver_config.process_packet_function = test_process_packet_function;

            context.sender = endpoint_create(sender_config, time);
            context.receiver = endpoint_create(receiver_config, time);

            int i;
            for (i = 0; i < 1000; ++i)
            {
                var dummy_packet = new byte[8];

                endpoint_send_packet(context.sender, dummy_packet, dummy_packet.Length);
                endpoint_send_packet(context.receiver, dummy_packet, dummy_packet.Length);

                endpoint_update(context.sender, time);
                endpoint_update(context.receiver, time);

                time += delta_time;
            }

            var rtt = endpoint_rtt(context.sender);
            var rtt_min = endpoint_rtt_min(context.sender);
            var rtt_max = endpoint_rtt_max(context.sender);
            var rtt_avg = endpoint_rtt_avg(context.sender);

            check(float.IsFinite(rtt) && rtt >= 0); // Check rtt is finite and non-negative
            check(rtt_min >= 0 && rtt_min <= rtt_avg && rtt_avg <= rtt_max);
            check(rtt_max < 1000.0); // Assume RTT is in milliseconds

            endpoint_destroy(ref context.sender);
            endpoint_destroy(ref context.receiver);
        }

        // a pair of endpoints wired to each other through test_transmit_packet_function

        class test_pair_t
        {
            public test_context_t context = new test_context_t();
            public reliable_config_t sender_config;
            public reliable_config_t receiver_config;
        }

        static void test_pair_configs(test_pair_t pair)
        {
            test_default_context(pair.context);

            default_config(out pair.sender_config);
            default_config(out pair.receiver_config);

            pair.sender_config.name = "sender";
            pair.sender_config.context = pair.context;
            pair.sender_config.id = 0;
            pair.sender_config.transmit_packet_function = test_transmit_packet_function;
            pair.sender_config.process_packet_function = test_process_packet_function;

            pair.receiver_config.name = "receiver";
            pair.receiver_config.context = pair.context;
            pair.receiver_config.id = 1;
            pair.receiver_config.transmit_packet_function = test_transmit_packet_function;
            pair.receiver_config.process_packet_function = test_process_packet_function;
        }

        static void test_pair_create(test_pair_t pair, double time)
        {
            pair.context.sender = endpoint_create(pair.sender_config, time);
            pair.context.receiver = endpoint_create(pair.receiver_config, time);
            check(pair.context.sender != null);
            check(pair.context.receiver != null);
        }

        static void test_pair_destroy(test_pair_t pair)
        {
            endpoint_destroy(ref pair.context.sender);
            endpoint_destroy(ref pair.context.receiver);
        }

        // RL-02: a round trip long enough to reach any fixed sentinel must still be reported

        static void test_rtt_min_large()
        {
            var time = 100.0;

            var pair = new test_pair_t();
            test_pair_configs(pair);
            test_pair_create(pair, time);

            var packet = new byte[8];

            endpoint_send_packet(pair.context.sender, packet, packet.Length);

            // ten seconds pass before the acknowledgment comes back, so the one rtt sample is 10,000 ms

            time += 10.0;

            endpoint_update(pair.context.sender, time);
            endpoint_update(pair.context.receiver, time);

            endpoint_send_packet(pair.context.receiver, packet, packet.Length);

            endpoint_update(pair.context.sender, time);

            endpoint_get_acks(pair.context.sender, out var num_acks);
            check(num_acks == 1);

            check(endpoint_rtt_min(pair.context.sender) == 10000.0f);
            check(endpoint_rtt_max(pair.context.sender) == 10000.0f);
            check(endpoint_rtt_avg(pair.context.sender) == 10000.0f);
            check(endpoint_jitter_avg_vs_min_rtt(pair.context.sender) == 0.0f);
            check(endpoint_jitter_max_vs_min_rtt(pair.context.sender) == 0.0f);

            // and an endpoint with no samples at all still reports zero

            check(endpoint_rtt_min(pair.context.receiver) == 0.0f);

            test_pair_destroy(pair);
        }

        // RL-03: reset clears every field a getter can return, the rtt history included

        static void test_endpoint_reset_clears_stats()
        {
            var time = 100.0;

            var pair = new test_pair_t();
            test_pair_configs(pair);
            test_pair_create(pair, time);

            // enough packets that the bandwidth window, which samples half the sent packets buffer,
            // lands on packets that were actually sent

            int i;
            for (i = 0; i < 300; ++i)
            {
                var packet = new byte[64];

                // the reply comes back a step later, so the acknowledgment carries a real round trip

                endpoint_send_packet(pair.context.sender, packet, packet.Length);

                time += 0.1;
                endpoint_update(pair.context.sender, time);
                endpoint_update(pair.context.receiver, time);

                endpoint_send_packet(pair.context.receiver, packet, packet.Length);

                time += 0.1;
                endpoint_update(pair.context.sender, time);
                endpoint_update(pair.context.receiver, time);

                endpoint_clear_acks(pair.context.sender);
                endpoint_clear_acks(pair.context.receiver);
            }

            check(endpoint_rtt(pair.context.sender) > 0.0f);
            check(endpoint_rtt_min(pair.context.sender) > 0.0f);
            check(endpoint_rtt_max(pair.context.sender) > 0.0f);
            check(endpoint_rtt_avg(pair.context.sender) > 0.0f);

            endpoint_bandwidth(pair.context.sender, out var sent_bandwidth, out var received_bandwidth, out var acked_bandwidth);
            check(sent_bandwidth > 0.0f);
            check(received_bandwidth > 0.0f);
            check(acked_bandwidth > 0.0f);

            endpoint_reset(pair.context.sender);

            check(endpoint_rtt(pair.context.sender) == 0.0f);
            check(endpoint_rtt_min(pair.context.sender) == 0.0f);
            check(endpoint_rtt_max(pair.context.sender) == 0.0f);
            check(endpoint_rtt_avg(pair.context.sender) == 0.0f);
            check(endpoint_jitter_avg_vs_min_rtt(pair.context.sender) == 0.0f);
            check(endpoint_jitter_max_vs_min_rtt(pair.context.sender) == 0.0f);
            check(endpoint_jitter_stddev_vs_avg_rtt(pair.context.sender) == 0.0f);
            check(endpoint_packet_loss(pair.context.sender) == 0.0f);

            endpoint_bandwidth(pair.context.sender, out sent_bandwidth, out received_bandwidth, out acked_bandwidth);
            check(sent_bandwidth == 0.0f);
            check(received_bandwidth == 0.0f);
            check(acked_bandwidth == 0.0f);

            // the rtt history is part of the state, so recomputing the statistics after a reset must
            // not resurrect the samples that were in it

            time += 0.1;
            endpoint_update(pair.context.sender, time);

            check(endpoint_rtt_min(pair.context.sender) == 0.0f);
            check(endpoint_rtt_max(pair.context.sender) == 0.0f);
            check(endpoint_rtt_avg(pair.context.sender) == 0.0f);
            check(endpoint_jitter_avg_vs_min_rtt(pair.context.sender) == 0.0f);
            check(endpoint_jitter_max_vs_min_rtt(pair.context.sender) == 0.0f);
            check(endpoint_jitter_stddev_vs_avg_rtt(pair.context.sender) == 0.0f);

            test_pair_destroy(pair);
        }

        // RL-06: a config the library cannot honor is refused instead of asserted

        static void test_endpoint_create_invalid_config()
        {
            default_config(out var valid);
            valid.transmit_packet_function = test_transmit_packet_function;
            valid.process_packet_function = test_process_packet_function;

            var endpoint = endpoint_create(valid, 0.0);
            check(endpoint != null);
            endpoint_destroy(ref endpoint);

            check(endpoint_create(null, 0.0) == null);

            reliable_config_t config;

            // the two relationships between fields

            config = valid.copy();
            config.fragment_above = config.max_packet_size + 1;
            check(endpoint_create(config, 0.0) == null);

            config = valid.copy();
            config.max_fragments = 4;
            config.fragment_size = 1024;
            config.max_packet_size = 4 * 1024 + 1;
            check(endpoint_create(config, 0.0) == null);

            // exactly covering is allowed, one fragment short is not

            config = valid.copy();
            config.max_fragments = 4;
            config.fragment_size = 1024;
            config.max_packet_size = 4 * 1024;
            config.fragment_above = 1024;
            endpoint = endpoint_create(config, 0.0);
            check(endpoint != null);
            endpoint_destroy(ref endpoint);

            // ranges

            config = valid.copy(); config.max_packet_size = 0;
            check(endpoint_create(config, 0.0) == null);

            config = valid.copy(); config.fragment_above = 0;
            check(endpoint_create(config, 0.0) == null);

            config = valid.copy(); config.fragment_size = 0;
            check(endpoint_create(config, 0.0) == null);

            config = valid.copy(); config.max_fragments = 0;
            check(endpoint_create(config, 0.0) == null);

            config = valid.copy(); config.max_fragments = 257;
            check(endpoint_create(config, 0.0) == null);

            config = valid.copy(); config.max_fragments = 256; config.fragment_size = 8421505;
            config.max_packet_size = config.fragment_size;
            config.fragment_above = 1;
            check(endpoint_create(config, 0.0) == null);

            config = valid.copy(); config.max_packet_size = int.MaxValue - 10;
            config.fragment_above = 1;
            config.fragment_size = config.max_packet_size;
            config.max_fragments = 1;
            check(endpoint_create(config, 0.0) == null);

            config = valid.copy(); config.ack_buffer_size = 0;
            check(endpoint_create(config, 0.0) == null);

            config = valid.copy(); config.sent_packets_buffer_size = -1;
            check(endpoint_create(config, 0.0) == null);

            config = valid.copy(); config.received_packets_buffer_size = 0;
            check(endpoint_create(config, 0.0) == null);

            config = valid.copy(); config.fragment_reassembly_buffer_size = 0;
            check(endpoint_create(config, 0.0) == null);

            config = valid.copy(); config.rtt_history_size = 0;
            check(endpoint_create(config, 0.0) == null);

            config = valid.copy(); config.packet_header_size = -1;
            check(endpoint_create(config, 0.0) == null);

            config = valid.copy(); config.packet_header_size = int.MaxValue;
            check(endpoint_create(config, 0.0) == null);

            config = valid.copy(); config.transmit_packet_function = null;
            check(endpoint_create(config, 0.0) == null);

            config = valid.copy(); config.process_packet_function = null;
            check(endpoint_create(config, 0.0) == null);

            // (reliable_checked_size is C only: managed array sizes are checked by the runtime)
        }

        // the endpoint keeps its own copy of the config (reliable.c: endpoint->config = *config), so changing the caller's
        // config after create must not change the endpoint

        static void test_endpoint_config_copied()
        {
            default_config(out var config);
            config.name = "original";
            config.transmit_packet_function = test_transmit_packet_function;
            config.process_packet_function = test_process_packet_function;

            var endpoint = endpoint_create(config, 0.0);
            check(endpoint != null);

            config.name = "changed";
            config.max_packet_size = 1;
            config.id = 99;

            check(endpoint.config.name == "original");
            check(endpoint.config.max_packet_size == 16 * 1024);
            check(endpoint.config.id == 0);

            endpoint_destroy(ref endpoint);
        }

        // security#26-3 adapted: reliable.c bounds the (possibly unterminated) name in its rejection logs. C# strings cannot over-read,
        // so this checks the C# side of the same contract: a refused config logs exactly one error line, naming the endpoint

        static string test_name_log_line;
        static int test_name_log_calls = 0;

        static void test_name_log_printf_function(string text)
        {
            test_name_log_line = text;
            test_name_log_calls++;
        }

        static void test_config_name_bounded_in_rejection_log()
        {
            default_config(out var config);
            config.name = new string('x', 255);
            config.max_packet_size = -1;
            config.fragment_above = -1;
            config.max_fragments = -1;
            config.fragment_size = -1;
            config.ack_buffer_size = -1;
            config.sent_packets_buffer_size = -1;
            config.received_packets_buffer_size = -1;
            config.fragment_reassembly_buffer_size = -1;
            config.rtt_history_size = -1;
            config.packet_header_size = -1;
            config.transmit_packet_function = test_transmit_packet_function;
            config.process_packet_function = test_process_packet_function;

            var previous_printf_function = printf_function;
            var previous_log_level = log_level_;

            test_name_log_line = null;
            test_name_log_calls = 0;

            set_printf_function(test_name_log_printf_function);
            log_level(LOG_LEVEL_ERROR);

            var endpoint = endpoint_create(config, 0.0);

            log_level(previous_log_level);
            set_printf_function(previous_printf_function);

            check(endpoint == null);
            check(test_name_log_calls == 1);
            check(test_name_log_line != null && test_name_log_line.StartsWith("[" + config.name + "] "));
        }

        // RL-07: the sequence number crosses 65535 to 0

        static readonly byte[] test_wrap_acked = new byte[65536];

        static void test_sequence_wrap()
        {
            var time = 100.0;

            var pair = new test_pair_t();
            test_pair_configs(pair);
            test_pair_create(pair, time);

            Array.Clear(test_wrap_acked);

            const int num_iterations = 65536 + 64;

            var packet = new byte[8];

            int i;
            for (i = 0; i < num_iterations; ++i)
            {
                endpoint_send_packet(pair.context.sender, packet, packet.Length);
                endpoint_send_packet(pair.context.receiver, packet, packet.Length);

                var acks = endpoint_get_acks(pair.context.sender, out var num_acks);

                int j;
                for (j = 0; j < num_acks; ++j)
                    test_wrap_acked[acks[j]] = 1;

                endpoint_clear_acks(pair.context.sender);
                endpoint_clear_acks(pair.context.receiver);
            }

            check(endpoint_next_packet_sequence(pair.context.sender) == unchecked((ushort)num_iterations));

            // the sequences either side of the wrap were acked like any others

            check(test_wrap_acked[65533] != 0);
            check(test_wrap_acked[65534] != 0);
            check(test_wrap_acked[65535] != 0);
            check(test_wrap_acked[0] != 0);
            check(test_wrap_acked[1] != 0);
            check(test_wrap_acked[2] != 0);

            for (i = 0; i < 65536; ++i)
                check(test_wrap_acked[i] != 0);

            check(endpoint_counters(pair.context.receiver)[ENDPOINT_COUNTER_NUM_PACKETS_RECEIVED] == (ulong)num_iterations);

            test_pair_destroy(pair);
        }

        // RL-07: fragment counts at both ends of the range, and a payload that is an exact multiple of the fragment size

        class test_fragment_context_t : test_context_t
        {
            public int num_processed;
            public int processed_bytes;
            public byte[] processed = new byte[64 * 1024];
        }

        static bool test_fragment_process_packet_function(object _context, ulong id, ushort sequence, byte[] packet_data, int packet_bytes)
        {
            var context = (test_fragment_context_t)_context;

            check(packet_bytes <= context.processed.Length);

            context.num_processed++;
            context.processed_bytes = packet_bytes;
            Buffer.BlockCopy(packet_data, 0, context.processed, 0, packet_bytes);

            return true;
        }

        static void test_fragment_case(int fragment_size, int max_fragments, int packet_bytes, int expected_fragments)
        {
            var context = new test_fragment_context_t();
            test_default_context(context);

            default_config(out var sender_config);

            sender_config.fragment_size = fragment_size;
            sender_config.max_fragments = max_fragments;
            sender_config.max_packet_size = fragment_size * max_fragments;
            sender_config.fragment_above = fragment_size;
            var receiver_config = sender_config.copy();

            sender_config.name = "sender";
            sender_config.context = context;
            sender_config.id = 0;
            sender_config.transmit_packet_function = test_transmit_packet_function;
            sender_config.process_packet_function = test_fragment_process_packet_function;

            receiver_config.name = "receiver";
            receiver_config.context = context;
            receiver_config.id = 1;
            receiver_config.transmit_packet_function = test_transmit_packet_function;
            receiver_config.process_packet_function = test_fragment_process_packet_function;

            context.sender = endpoint_create(sender_config, 100.0);
            context.receiver = endpoint_create(receiver_config, 100.0);
            check(context.sender != null);
            check(context.receiver != null);

            var packet = new byte[packet_bytes];

            int i;
            for (i = 0; i < packet_bytes; ++i)
                packet[i] = (byte)((i * 31) + 7);

            endpoint_send_packet(context.sender, packet, packet_bytes);

            check(context.num_processed == 1);
            check(context.processed_bytes == packet_bytes);
            check(context.processed.AsSpan(0, packet_bytes).SequenceEqual(packet));

            var fragments_sent = endpoint_counters(context.sender)[ENDPOINT_COUNTER_NUM_FRAGMENTS_SENT];
            var fragments_received = endpoint_counters(context.receiver)[ENDPOINT_COUNTER_NUM_FRAGMENTS_RECEIVED];

            if (expected_fragments == 0)
            {
                // below the threshold: sent whole, no fragments at all
                check(fragments_sent == 0);
                check(fragments_received == 0);
            }
            else
            {
                check(fragments_sent == (ulong)expected_fragments);
                check(fragments_received == (ulong)expected_fragments);
            }

            endpoint_destroy(ref context.sender);
            endpoint_destroy(ref context.receiver);
        }

        static void test_fragment_counts()
        {
            // an exact multiple of the fragment size, where the last fragment is full rather than a remainder
            test_fragment_case(512, 16, 512 * 4, 4);

            // the largest packet the config allows, again an exact multiple
            test_fragment_case(512, 16, 512 * 16, 16);

            // one fragment: above the threshold by a single byte
            test_fragment_case(512, 16, 513, 2);
            test_fragment_case(64, 256, 65, 2);

            // 256 fragments, the maximum the wire format can express
            test_fragment_case(64, 256, 64 * 256, 256);
            test_fragment_case(64, 256, 64 * 255 + 1, 256);

            // at or below the threshold the packet is not fragmented
            test_fragment_case(512, 16, 512, 0);
            test_fragment_case(512, 16, 1, 0);
        }

        // RL-07: truncated packets and fragments are rejected rather than acted on. every packet handed to the receiver is an
        // exact-size array (as netcode delivers them), so a read past packet_bytes would throw instead of reading slack

        class test_truncation_context_t : test_context_t
        {
            public int num_processed;
            public int num_captured;
            public int[] captured_bytes = new int[300];
            public byte[][] captured = new byte[300][];
        }

        static void test_truncation_transmit_packet_function(object _context, ulong id, ushort sequence, byte[] packet_data, int packet_bytes)
        {
            var context = (test_truncation_context_t)_context;

            if (context.num_captured < context.captured_bytes.Length && packet_bytes <= 1024)
            {
                context.captured[context.num_captured] = packet_data.AsSpan(0, packet_bytes).ToArray();
                context.captured_bytes[context.num_captured] = packet_bytes;
                context.num_captured++;
            }
        }

        static bool test_truncation_process_packet_function(object _context, ulong id, ushort sequence, byte[] packet_data, int packet_bytes)
        {
            var context = (test_truncation_context_t)_context;
            context.num_processed++;
            return true;
        }

        static byte[] test_truncate(byte[] packet_data, int packet_bytes) =>
            packet_data.AsSpan(0, packet_bytes).ToArray();

        static void test_truncated_packets()
        {
            var context = new test_truncation_context_t();
            test_default_context(context);

            default_config(out var config);
            config.fragment_size = 256;
            config.max_fragments = 16;
            config.max_packet_size = 256 * 16;
            config.fragment_above = 256;
            config.context = context;
            config.id = 0;
            config.transmit_packet_function = test_truncation_transmit_packet_function;
            config.process_packet_function = test_truncation_process_packet_function;

            var sender = endpoint_create(config, 100.0);
            var receiver = endpoint_create(config, 100.0);
            check(sender != null);
            check(receiver != null);

            // an unfragmented packet, captured on the wire

            var packet = new byte[200];
            Array.Fill(packet, (byte)0xAB);
            endpoint_send_packet(sender, packet, packet.Length);
            check(context.num_captured == 1);

            var whole_bytes = context.captured_bytes[0];

            // every truncation of it shorter than the header is rejected, and none is processed

            int truncated_bytes;
            for (truncated_bytes = 1; truncated_bytes < 4; ++truncated_bytes)
                endpoint_receive_packet(receiver, test_truncate(context.captured[0], truncated_bytes), truncated_bytes);

            check(endpoint_counters(receiver)[ENDPOINT_COUNTER_NUM_PACKETS_INVALID] == 3);
            check(context.num_processed == 0);

            // the whole packet still arrives

            endpoint_receive_packet(receiver, context.captured[0], whole_bytes);
            check(context.num_processed == 1);

            // now a fragmented packet

            context.num_captured = 0;

            var large_packet = new byte[1024];
            Array.Fill(large_packet, (byte)0xCD);
            endpoint_send_packet(sender, large_packet, large_packet.Length);
            check(context.num_captured == 4);

            // a fragment truncated inside its header is rejected

            for (truncated_bytes = 1; truncated_bytes < FRAGMENT_HEADER_BYTES; ++truncated_bytes)
                endpoint_receive_packet(receiver, test_truncate(context.captured[1], truncated_bytes), truncated_bytes);

            check(endpoint_counters(receiver)[ENDPOINT_COUNTER_NUM_FRAGMENTS_RECEIVED] == 0);
            check(endpoint_counters(receiver)[ENDPOINT_COUNTER_NUM_FRAGMENTS_INVALID] == FRAGMENT_HEADER_BYTES - 1);

            // a fragment that is not the last one must carry exactly fragment_size bytes, so a truncated body is rejected too

            endpoint_receive_packet(receiver, test_truncate(context.captured[1], context.captured_bytes[1] - 1), context.captured_bytes[1] - 1);
            check(endpoint_counters(receiver)[ENDPOINT_COUNTER_NUM_FRAGMENTS_RECEIVED] == 0);
            check(endpoint_counters(receiver)[ENDPOINT_COUNTER_NUM_FRAGMENTS_INVALID] == FRAGMENT_HEADER_BYTES);
            check(context.num_processed == 1);

            // fragment 0 truncated inside its embedded packet header is rejected (C#: f0e3be1 used to throw here)

            for (truncated_bytes = FRAGMENT_HEADER_BYTES + 1; truncated_bytes < context.captured_bytes[0] && truncated_bytes < FRAGMENT_HEADER_BYTES + MAX_PACKET_HEADER_BYTES; ++truncated_bytes)
                endpoint_receive_packet(receiver, test_truncate(context.captured[0], truncated_bytes), truncated_bytes);

            check(endpoint_counters(receiver)[ENDPOINT_COUNTER_NUM_FRAGMENTS_RECEIVED] == 0);
            check(context.num_processed == 1);

            var fragments_invalid = endpoint_counters(receiver)[ENDPOINT_COUNTER_NUM_FRAGMENTS_INVALID];

            // the intact fragments reassemble

            int i;
            for (i = 0; i < context.num_captured; ++i)
                endpoint_receive_packet(receiver, context.captured[i], context.captured_bytes[i]);

            check(endpoint_counters(receiver)[ENDPOINT_COUNTER_NUM_FRAGMENTS_RECEIVED] == 4);
            check(endpoint_counters(receiver)[ENDPOINT_COUNTER_NUM_FRAGMENTS_INVALID] == fragments_invalid);
            check(context.num_processed == 2);

            endpoint_destroy(ref sender);
            endpoint_destroy(ref receiver);
        }

        // C# regression (f0e3be1): a fragment 0 whose embedded packet header is cut short must be rejected without reading past
        // packet_bytes. with an exact-size array the old code threw IndexOutOfRangeException out of endpoint_receive_packet

        static void test_fragment_header_truncated_embedded_header()
        {
            var pair = new test_pair_t();
            test_pair_configs(pair);
            test_pair_create(pair, 100.0);

            var processed_before = endpoint_counters(pair.context.receiver)[ENDPOINT_COUNTER_NUM_PACKETS_RECEIVED];

            // prefix 0x1E: 16 bit ack and all four ack_bits bytes present, so the embedded header needs 9 bytes

            var full = new byte[] { 0x01, 0x00, 0x00, 0x00, 0x00, 0x1E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

            int packet_bytes;
            var num_sent = 0;
            for (packet_bytes = FRAGMENT_HEADER_BYTES + 1; packet_bytes < FRAGMENT_HEADER_BYTES + MAX_PACKET_HEADER_BYTES; ++packet_bytes)
            {
                endpoint_receive_packet(pair.context.receiver, test_truncate(full, packet_bytes), packet_bytes);
                num_sent++;
            }

            // and a regular prefix (0x00) with just the sequence, which needs at least 5 header bytes

            var short_regular = new byte[] { 0x01, 0x00, 0x00, 0x00, 0x00, 0x00 };
            endpoint_receive_packet(pair.context.receiver, short_regular, short_regular.Length);
            num_sent++;

            var counters = endpoint_counters(pair.context.receiver);
            check(counters[ENDPOINT_COUNTER_NUM_FRAGMENTS_INVALID] == (ulong)num_sent);
            check(counters[ENDPOINT_COUNTER_NUM_FRAGMENTS_RECEIVED] == 0);
            check(counters[ENDPOINT_COUNTER_NUM_PACKETS_RECEIVED] == processed_before);

            test_pair_destroy(pair);
        }

        // C# regression (42e6725): fragment 0 must carry a canonically encoded packet header. a non-canonical 9 byte header in a
        // single fragment packet used to make store_fragment_data copy fragment_size + 5 bytes into a 9 + fragment_size buffer

        static int test_non_canonical_num_processed = 0;

        static bool test_non_canonical_process_packet_function(object context, ulong id, ushort sequence, byte[] packet_data, int packet_bytes)
        {
            test_non_canonical_num_processed++;
            return true;
        }

        static void test_fragment_non_canonical_header()
        {
            var pair = new test_pair_t();
            test_pair_configs(pair);
            pair.receiver_config.process_packet_function = test_non_canonical_process_packet_function;
            test_pair_create(pair, 100.0);

            test_non_canonical_num_processed = 0;

            var fragment_size = pair.receiver_config.fragment_size;

            // sequence 0, ack 0, ack_bits 0xFFFFFFFF written the long way: 16 bit ack and all four ack_bits bytes (each 0xFF)

            var non_canonical_header = new byte[] { 0x1E, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF };
            var packet = new byte[FRAGMENT_HEADER_BYTES + non_canonical_header.Length + fragment_size];
            packet[0] = 0x01;           // fragment
            packet[1] = 0x00;           // sequence 0
            packet[2] = 0x00;
            packet[3] = 0x00;           // fragment id 0
            packet[4] = 0x00;           // num fragments - 1 = 0
            Buffer.BlockCopy(non_canonical_header, 0, packet, FRAGMENT_HEADER_BYTES, non_canonical_header.Length);

            endpoint_receive_packet(pair.context.receiver, packet, packet.Length);

            check(endpoint_counters(pair.context.receiver)[ENDPOINT_COUNTER_NUM_FRAGMENTS_INVALID] == 1);
            check(endpoint_counters(pair.context.receiver)[ENDPOINT_COUNTER_NUM_FRAGMENTS_RECEIVED] == 0);
            check(test_non_canonical_num_processed == 0);

            // the same packet with the canonical header for sequence 1 (prefix bit 5: one byte ack delta, ack_bits all set) is accepted

            var canonical_header = new byte[MAX_PACKET_HEADER_BYTES];
            var canonical_header_bytes = write_packet_header(canonical_header, 1, 1, 0xFFFFFFFF);
            check(canonical_header_bytes == 4);
            packet = new byte[FRAGMENT_HEADER_BYTES + canonical_header_bytes + fragment_size];
            packet[0] = 0x01;
            packet[1] = 0x01;           // sequence 1
            packet[2] = 0x00;
            packet[3] = 0x00;
            packet[4] = 0x00;
            Buffer.BlockCopy(canonical_header, 0, packet, FRAGMENT_HEADER_BYTES, canonical_header_bytes);

            endpoint_receive_packet(pair.context.receiver, packet, packet.Length);

            check(endpoint_counters(pair.context.receiver)[ENDPOINT_COUNTER_NUM_FRAGMENTS_INVALID] == 1);
            check(endpoint_counters(pair.context.receiver)[ENDPOINT_COUNTER_NUM_FRAGMENTS_RECEIVED] == 1);
            check(test_non_canonical_num_processed == 1);

            test_pair_destroy(pair);
        }

        // C# hardening (no reliable.c equivalent): a packet_bytes that is out of range for the array is dropped, never thrown

        static void test_receive_invalid_length()
        {
            var pair = new test_pair_t();
            test_pair_configs(pair);
            test_pair_create(pair, 100.0);

            endpoint_receive_packet(pair.context.receiver, new byte[0], 0);
            endpoint_receive_packet(pair.context.receiver, new byte[4], 5);
            endpoint_receive_packet(pair.context.receiver, new byte[4], -1);

            check(endpoint_counters(pair.context.receiver)[ENDPOINT_COUNTER_NUM_PACKETS_INVALID] == 3);
            check(endpoint_counters(pair.context.receiver)[ENDPOINT_COUNTER_NUM_PACKETS_RECEIVED] == 0);

            test_pair_destroy(pair);
        }

        // C# regression (f65b33b): bandwidth over a window whose samples share a timestamp must stay finite (the old guard divided by zero)

        static void test_bandwidth_finite()
        {
            var time = 100.0;

            var pair = new test_pair_t();
            test_pair_configs(pair);
            test_pair_create(pair, time);

            int i;
            for (i = 0; i < 200; ++i)
            {
                var packet = new byte[32];
                endpoint_send_packet(pair.context.sender, packet, packet.Length);
                endpoint_send_packet(pair.context.receiver, packet, packet.Length);
            }

            for (i = 0; i < 4; ++i)
            {
                endpoint_update(pair.context.sender, time);
                endpoint_update(pair.context.receiver, time);

                endpoint_bandwidth(pair.context.sender, out var sent_bandwidth, out var received_bandwidth, out var acked_bandwidth);
                check(float.IsFinite(sent_bandwidth));
                check(float.IsFinite(received_bandwidth));
                check(float.IsFinite(acked_bandwidth));
                check(float.IsFinite(endpoint_packet_loss(pair.context.sender)));
            }

            test_pair_destroy(pair);
        }

        // C# regression (42e466b): packet loss is the fraction of packets actually sent in the window, not of the window size

        static void test_packet_loss_num_sent()
        {
            var time = 100.0;

            var pair = new test_pair_t();
            test_pair_configs(pair);
            test_pair_create(pair, time);

            // 200 sends with every odd one dropped. the loss window covers sequences [sequence - 255, sequence - 128], so only
            // sequences 0..71 of it were sent: 36 of them were dropped, which is 50% of the packets sent (28% of the window)

            int i;
            for (i = 0; i < 200; ++i)
            {
                var packet = new byte[8];

                pair.context.drop = (i % 2) != 0;
                endpoint_send_packet(pair.context.sender, packet, packet.Length);

                pair.context.drop = false;
                endpoint_send_packet(pair.context.receiver, packet, packet.Length);

                endpoint_clear_acks(pair.context.sender);
                endpoint_clear_acks(pair.context.receiver);
            }

            endpoint_update(pair.context.sender, time);

            // one smoothing step from 0 toward 50% with the default factor of 0.1

            var packet_loss = endpoint_packet_loss(pair.context.sender);
            check(packet_loss > 4.99f && packet_loss < 5.01f);

            test_pair_destroy(pair);
        }

        // wire conformance: headers and fragments written by this port must match the reference implementation byte for byte.
        // the vectors below were generated by cpp/reliable tools/conformance/gen_vectors.c (reliable 1.4.5)

        static readonly ushort[] test_conformance_seqs = { 0, 1, 255, 256, 1000, 32768, 65535, 7 };
        static readonly ushort[] test_conformance_acks = { 0, 1, 254, 255, 256, 999, 65535, 32760 };
        static readonly uint[] test_conformance_bits = { 0xFFFFFFFF, 0x00000000, 0xFFFFFF00, 0x00FFFFFF, 0xDEADBEEF, 0xFF00FF00, 0x000000FF, 0xFFFF00FF };

        const string test_conformance_headers = @"
            20000000 3e00000000000000 2200000000 3000000000 3e000000efbeadde 2a0000000000 3c000000000000 2400000000 0000000100 1e0000010000000000
            020000010000 100000010000 1e00000100efbeadde 0a000001000000 1c00000100000000 040000010000 000000fe00 1e0000fe0000000000 020000fe0000
            100000fe0000 1e0000fe00efbeadde 0a0000fe000000 1c0000fe00000000 040000fe0000 000000ff00 1e0000ff0000000000 020000ff0000 100000ff0000
            1e0000ff00efbeadde 0a0000ff000000 1c0000ff00000000 040000ff0000 0000000001 1e0000000100000000 020000000100 100000000100 1e00000001efbeadde
            0a000000010000 1c00000001000000 040000000100 000000e703 1e0000e70300000000 020000e70300 100000e70300 1e0000e703efbeadde 0a0000e7030000
            1c0000e703000000 040000e70300 20000001 3e00000100000000 2200000100 3000000100 3e000001efbeadde 2a0000010000 3c000001000000 2400000100
            000000f87f 1e0000f87f00000000 020000f87f00 100000f87f00 1e0000f87fefbeadde 0a0000f87f0000 1c0000f87f000000 040000f87f00 20010001
            3e01000100000000 2201000100 3001000100 3e010001efbeadde 2a0100010000 3c010001000000 2401000100 20010000 3e01000000000000 2201000000
            3001000000 3e010000efbeadde 2a0100000000 3c010000000000 2401000000 000100fe00 1e0100fe0000000000 020100fe0000 100100fe0000
            1e0100fe00efbeadde 0a0100fe000000 1c0100fe00000000 040100fe0000 000100ff00 1e0100ff0000000000 020100ff0000 100100ff0000 1e0100ff00efbeadde
            0a0100ff000000 1c0100ff00000000 040100ff0000 0001000001 1e0100000100000000 020100000100 100100000100 1e01000001efbeadde 0a010000010000
            1c01000001000000 040100000100 000100e703 1e0100e70300000000 020100e70300 100100e70300 1e0100e703efbeadde 0a0100e7030000 1c0100e703000000
            040100e70300 20010002 3e01000200000000 2201000200 3001000200 3e010002efbeadde 2a0100020000 3c010002000000 2401000200 000100f87f
            1e0100f87f00000000 020100f87f00 100100f87f00 1e0100f87fefbeadde 0a0100f87f0000 1c0100f87f000000 040100f87f00 20ff00ff 3eff00ff00000000
            22ff00ff00 30ff00ff00 3eff00ffefbeadde 2aff00ff0000 3cff00ff000000 24ff00ff00 20ff00fe 3eff00fe00000000 22ff00fe00 30ff00fe00
            3eff00feefbeadde 2aff00fe0000 3cff00fe000000 24ff00fe00 20ff0001 3eff000100000000 22ff000100 30ff000100 3eff0001efbeadde 2aff00010000
            3cff0001000000 24ff000100 20ff0000 3eff000000000000 22ff000000 30ff000000 3eff0000efbeadde 2aff00000000 3cff0000000000 24ff000000
            00ff000001 1eff00000100000000 02ff00000100 10ff00000100 1eff000001efbeadde 0aff0000010000 1cff000001000000 04ff00000100 00ff00e703
            1eff00e70300000000 02ff00e70300 10ff00e70300 1eff00e703efbeadde 0aff00e7030000 1cff00e703000000 04ff00e70300 00ff00ffff 1eff00ffff00000000
            02ff00ffff00 10ff00ffff00 1eff00ffffefbeadde 0aff00ffff0000 1cff00ffff000000 04ff00ffff00 00ff00f87f 1eff00f87f00000000 02ff00f87f00
            10ff00f87f00 1eff00f87fefbeadde 0aff00f87f0000 1cff00f87f000000 04ff00f87f00 0000010000 1e0001000000000000 020001000000 100001000000
            1e00010000efbeadde 0a000100000000 1c00010000000000 040001000000 200001ff 3e0001ff00000000 220001ff00 300001ff00 3e0001ffefbeadde
            2a0001ff0000 3c0001ff000000 240001ff00 20000102 3e00010200000000 2200010200 3000010200 3e000102efbeadde 2a0001020000 3c000102000000
            2400010200 20000101 3e00010100000000 2200010100 3000010100 3e000101efbeadde 2a0001010000 3c000101000000 2400010100 20000100
            3e00010000000000 2200010000 3000010000 3e000100efbeadde 2a0001000000 3c000100000000 2400010000 000001e703 1e0001e70300000000 020001e70300
            100001e70300 1e0001e703efbeadde 0a0001e7030000 1c0001e703000000 040001e70300 000001ffff 1e0001ffff00000000 020001ffff00 100001ffff00
            1e0001ffffefbeadde 0a0001ffff0000 1c0001ffff000000 040001ffff00 000001f87f 1e0001f87f00000000 020001f87f00 100001f87f00 1e0001f87fefbeadde
            0a0001f87f0000 1c0001f87f000000 040001f87f00 00e8030000 1ee803000000000000 02e803000000 10e803000000 1ee8030000efbeadde 0ae80300000000
            1ce8030000000000 04e803000000 00e8030100 1ee803010000000000 02e803010000 10e803010000 1ee8030100efbeadde 0ae80301000000 1ce8030100000000
            04e803010000 00e803fe00 1ee803fe0000000000 02e803fe0000 10e803fe0000 1ee803fe00efbeadde 0ae803fe000000 1ce803fe00000000 04e803fe0000
            00e803ff00 1ee803ff0000000000 02e803ff0000 10e803ff0000 1ee803ff00efbeadde 0ae803ff000000 1ce803ff00000000 04e803ff0000 00e8030001
            1ee803000100000000 02e803000100 10e803000100 1ee8030001efbeadde 0ae80300010000 1ce8030001000000 04e803000100 20e80301 3ee8030100000000
            22e8030100 30e8030100 3ee80301efbeadde 2ae803010000 3ce80301000000 24e8030100 00e803ffff 1ee803ffff00000000 02e803ffff00 10e803ffff00
            1ee803ffffefbeadde 0ae803ffff0000 1ce803ffff000000 04e803ffff00 00e803f87f 1ee803f87f00000000 02e803f87f00 10e803f87f00 1ee803f87fefbeadde
            0ae803f87f0000 1ce803f87f000000 04e803f87f00 0000800000 1e0080000000000000 020080000000 100080000000 1e00800000efbeadde 0a008000000000
            1c00800000000000 040080000000 0000800100 1e0080010000000000 020080010000 100080010000 1e00800100efbeadde 0a008001000000 1c00800100000000
            040080010000 000080fe00 1e0080fe0000000000 020080fe0000 100080fe0000 1e0080fe00efbeadde 0a0080fe000000 1c0080fe00000000 040080fe0000
            000080ff00 1e0080ff0000000000 020080ff0000 100080ff0000 1e0080ff00efbeadde 0a0080ff000000 1c0080ff00000000 040080ff0000 0000800001
            1e0080000100000000 020080000100 100080000100 1e00800001efbeadde 0a008000010000 1c00800001000000 040080000100 000080e703 1e0080e70300000000
            020080e70300 100080e70300 1e0080e703efbeadde 0a0080e7030000 1c0080e703000000 040080e70300 000080ffff 1e0080ffff00000000 020080ffff00
            100080ffff00 1e0080ffffefbeadde 0a0080ffff0000 1c0080ffff000000 040080ffff00 20008008 3e00800800000000 2200800800 3000800800
            3e008008efbeadde 2a0080080000 3c008008000000 2400800800 00ffff0000 1effff000000000000 02ffff000000 10ffff000000 1effff0000efbeadde
            0affff00000000 1cffff0000000000 04ffff000000 00ffff0100 1effff010000000000 02ffff010000 10ffff010000 1effff0100efbeadde 0affff01000000
            1cffff0100000000 04ffff010000 00fffffe00 1efffffe0000000000 02fffffe0000 10fffffe0000 1efffffe00efbeadde 0afffffe000000 1cfffffe00000000
            04fffffe0000 00ffffff00 1effffff0000000000 02ffffff0000 10ffffff0000 1effffff00efbeadde 0affffff000000 1cffffff00000000 04ffffff0000
            00ffff0001 1effff000100000000 02ffff000100 10ffff000100 1effff0001efbeadde 0affff00010000 1cffff0001000000 04ffff000100 00ffffe703
            1effffe70300000000 02ffffe70300 10ffffe70300 1effffe703efbeadde 0affffe7030000 1cffffe703000000 04ffffe70300 20ffff00 3effff0000000000
            22ffff0000 30ffff0000 3effff00efbeadde 2affff000000 3cffff00000000 24ffff0000 00fffff87f 1efffff87f00000000 02fffff87f00 10fffff87f00
            1efffff87fefbeadde 0afffff87f0000 1cfffff87f000000 04fffff87f00 20070007 3e07000700000000 2207000700 3007000700 3e070007efbeadde
            2a0700070000 3c070007000000 2407000700 20070006 3e07000600000000 2207000600 3007000600 3e070006efbeadde 2a0700060000 3c070006000000
            2407000600 000700fe00 1e0700fe0000000000 020700fe0000 100700fe0000 1e0700fe00efbeadde 0a0700fe000000 1c0700fe00000000 040700fe0000
            000700ff00 1e0700ff0000000000 020700ff0000 100700ff0000 1e0700ff00efbeadde 0a0700ff000000 1c0700ff00000000 040700ff0000 0007000001
            1e0700000100000000 020700000100 100700000100 1e07000001efbeadde 0a070000010000 1c07000001000000 040700000100 000700e703 1e0700e70300000000
            020700e70300 100700e70300 1e0700e703efbeadde 0a0700e7030000 1c0700e703000000 040700e70300 20070008 3e07000800000000 2207000800 3007000800
            3e070008efbeadde 2a0700080000 3c070008000000 2407000800 000700f87f 1e0700f87f00000000 020700f87f00 100700f87f00 1e0700f87fefbeadde
            0a0700f87f0000 1c0700f87f000000 040700f87f00
";

        // SHA-256 of the five fragments (concatenated) of a 2200 byte packet (byte i = i * 7) sent with fragment_size 500

        const string test_conformance_fragments_sha256 = "0ad4c8f62ad15bd0910ef0319b68ff7399685221e970ccb4a2a993afa6807bde";

        static readonly List<byte[]> test_conformance_fragments = new List<byte[]>();

        static void test_conformance_transmit(object context, ulong id, ushort sequence, byte[] packet_data, int packet_bytes) =>
            test_conformance_fragments.Add(packet_data.AsSpan(0, packet_bytes).ToArray());

        static reliable_endpoint_t test_conformance_ack_receiver;
        static bool test_conformance_deliver_now;
        static byte[] test_conformance_reply;

        static void test_conformance_transmit_a(object context, ulong id, ushort sequence, byte[] packet_data, int packet_bytes)
        {
            if (test_conformance_deliver_now)
                endpoint_receive_packet(test_conformance_ack_receiver, packet_data, packet_bytes);
        }

        static void test_conformance_transmit_b(object context, ulong id, ushort sequence, byte[] packet_data, int packet_bytes) =>
            test_conformance_reply = packet_data.AsSpan(0, packet_bytes).ToArray();

        static void test_conformance_ack_vector(int num_sends, int[] deliver_index, string expected_header, int[] expected_acks)
        {
            default_config(out var config_a);
            config_a.transmit_packet_function = test_conformance_transmit_a;
            config_a.process_packet_function = test_process_packet_function;

            default_config(out var config_b);
            config_b.transmit_packet_function = test_conformance_transmit_b;
            config_b.process_packet_function = test_process_packet_function;

            var a = endpoint_create(config_a, 0.0);
            var b = endpoint_create(config_b, 0.0);
            check(a != null && b != null);

            test_conformance_ack_receiver = b;
            test_conformance_reply = null;

            var payload = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };

            int i;
            for (i = 0; i < num_sends; i++)
            {
                test_conformance_deliver_now = Array.IndexOf(deliver_index, i) >= 0;
                endpoint_send_packet(a, payload, payload.Length);
            }
            test_conformance_deliver_now = false;

            endpoint_send_packet(b, payload, payload.Length);
            check(test_conformance_reply != null);
            check(Convert.ToHexString(test_conformance_reply).ToLowerInvariant() == expected_header);

            endpoint_receive_packet(a, test_conformance_reply, test_conformance_reply.Length);

            var acks = endpoint_get_acks(a, out var num_acks);
            check(num_acks == expected_acks.Length);
            for (i = 0; i < num_acks; i++)
                check(acks[i] == expected_acks[i]);

            endpoint_destroy(ref a);
            endpoint_destroy(ref b);
            test_conformance_ack_receiver = null;
        }

        static void test_wire_conformance()
        {
            // packet headers across the interesting corners of the elision rules

            var expected = test_conformance_headers.Split(new[] { ' ', '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
            check(expected.Length == 512);

            var buffer = new byte[MAX_PACKET_HEADER_BYTES];
            var index = 0;
            for (var a = 0; a < 8; a++)
                for (var b = 0; b < 8; b++)
                    for (var c = 0; c < 8; c++)
                    {
                        var n = write_packet_header(buffer, test_conformance_seqs[a], test_conformance_acks[b], test_conformance_bits[c]);
                        check(Convert.ToHexString(buffer, 0, n).ToLowerInvariant() == expected[index]);

                        // and the reader recovers the same values from the reference bytes
                        var reference = Convert.FromHexString(expected[index]);
                        var bytes_read = read_packet_header("conformance", reference, 0, reference.Length, out var sequence, out var ack, out var ack_bits);
                        check(bytes_read == reference.Length);
                        check(sequence == test_conformance_seqs[a]);
                        check(ack == test_conformance_acks[b]);
                        check(ack_bits == test_conformance_bits[c]);
                        index++;
                    }

            // real fragments: a packet well above the fragment threshold

            default_config(out var config);
            config.fragment_above = 500;
            config.fragment_size = 500;
            config.max_fragments = 16;
            config.max_packet_size = 16 * 500;
            config.transmit_packet_function = test_conformance_transmit;
            config.process_packet_function = test_process_packet_function;
            var endpoint = endpoint_create(config, 0.0);
            check(endpoint != null);
            var payload = new byte[2200];
            for (var i = 0; i < payload.Length; i++)
                payload[i] = (byte)(i * 7);
            test_conformance_fragments.Clear();
            endpoint_send_packet(endpoint, payload, payload.Length);
            endpoint_destroy(ref endpoint);

            check(test_conformance_fragments.Count == 5);
            check(test_conformance_fragments[0].Length == 513);
            check(test_conformance_fragments[4].Length == 205);
            var all_fragments = test_conformance_fragments.SelectMany(x => x).ToArray();
            check(Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(all_fragments)).ToLowerInvariant() == test_conformance_fragments_sha256);

            // stateful acknowledgment vectors

            // a run with no wrap: the delivered set straddles the 32-wide window edge, so sequences 8 and below fall outside it
            test_conformance_ack_vector(41, new[] { 8, 9, 20, 40 }, "1e00002800010010800102030405060708", new[] { 40, 20, 9 });

            // a run that crosses 65535 to 0
            test_conformance_ack_vector(65541, new[] { 65530, 65531, 65533, 65535, 65536, 65537, 65540 }, "1e00000400b90600000102030405060708", new[] { 4, 1, 0, 65535, 65533, 65531, 65530 });
        }

        // every public function is called at least once by the suite. this test names them all in one place so a new entry point
        // cannot be added without being exercised

        static int test_surface_printf_calls = 0;

        static void test_surface_printf_function(string text) =>
            test_surface_printf_calls++;

        static void test_public_api_surface()
        {
            check(init() == OK);

            set_assert_function(assert_function);

            set_printf_function(test_surface_printf_function);
            log_level(LOG_LEVEL_NONE);

            var pair = new test_pair_t();
            test_pair_configs(pair);
            test_pair_create(pair, 100.0);

            check(endpoint_next_packet_sequence(pair.context.sender) == 0);

            var packet = new byte[64];

            endpoint_send_packet(pair.context.sender, packet, packet.Length);
            endpoint_send_packet(pair.context.receiver, packet, packet.Length);

            endpoint_receive_packet(pair.context.sender, packet, packet.Length);

            endpoint_update(pair.context.sender, 100.1);

            var acks = endpoint_get_acks(pair.context.sender, out var num_acks);
            check(acks != null);
            check(num_acks == 1);
            endpoint_clear_acks(pair.context.sender);
            endpoint_get_acks(pair.context.sender, out num_acks);
            check(num_acks == 0);

            endpoint_rtt(pair.context.sender);
            endpoint_rtt_min(pair.context.sender);
            endpoint_rtt_max(pair.context.sender);
            endpoint_rtt_avg(pair.context.sender);
            endpoint_jitter_avg_vs_min_rtt(pair.context.sender);
            endpoint_jitter_max_vs_min_rtt(pair.context.sender);
            endpoint_jitter_stddev_vs_avg_rtt(pair.context.sender);
            endpoint_packet_loss(pair.context.sender);

            endpoint_bandwidth(pair.context.sender, out var sent_bandwidth, out var received_bandwidth, out var acked_bandwidth);

            check(endpoint_counters(pair.context.sender)[ENDPOINT_COUNTER_NUM_PACKETS_SENT] == 1);

            endpoint_reset(pair.context.sender);
            check(endpoint_next_packet_sequence(pair.context.sender) == 0);

            object owned = new byte[32];
            endpoint_free_packet(pair.context.sender, ref owned);
            check(owned == null);

            default_config(out var defaults);
            check(defaults.max_packet_size > 0);
            check(defaults.rtt_history_size == 512);

            check(VERSION_FULL == $"{VERSION_MAJOR}.{VERSION_MINOR}.{VERSION_PATCH}");

            test_pair_destroy(pair);

            set_printf_function(x => Console.Write(x));

            term();
            check(init() == OK);
        }

        static void RUN_TEST(string name, Action test_function)
        {
            Console.Write($"{name}\n");
            test_function();
        }

        public static void test()
        {
            //log_level(LOG_LEVEL_DEBUG);
            //while (true)
            {
                RUN_TEST("test_endian", test_endian);
                RUN_TEST("test_sequence_buffer", test_sequence_buffer);
                RUN_TEST("test_generate_ack_bits", test_generate_ack_bits);
                RUN_TEST("test_packet_header", test_packet_header);
                RUN_TEST("test_acks", test_acks);
                RUN_TEST("test_acks_packet_loss", test_acks_packet_loss);
                RUN_TEST("test_duplicate_packets", test_duplicate_packets);
                RUN_TEST("test_stale_packets", test_stale_packets);
                RUN_TEST("test_ack_buffer_overflow", test_ack_buffer_overflow);
                RUN_TEST("test_packets", test_packets);
                RUN_TEST("test_large_packets", test_large_packets);
                RUN_TEST("test_sequence_buffer_rollover", test_sequence_buffer_rollover);
                RUN_TEST("test_fragment_cleanup", test_fragment_cleanup);
                // test_fragment_reassembly_alloc_failure: C only (the C# port does not route buffers through allocate_function)
                RUN_TEST("test_fragment_reassembly_buffer_zeroed", test_fragment_reassembly_buffer_zeroed);
                RUN_TEST("test_rtt", test_rtt);
                RUN_TEST("test_endpoint_reset", test_endpoint_reset);
                RUN_TEST("test_endpoint_reset_clears_stats", test_endpoint_reset_clears_stats);
                RUN_TEST("test_rtt_min_large", test_rtt_min_large);
                RUN_TEST("test_endpoint_create_invalid_config", test_endpoint_create_invalid_config);
                // test_endpoint_create_allocation_failure, test_endpoint_name_terminated: C only (allocator hooks, NUL termination)
                RUN_TEST("test_config_name_bounded_in_rejection_log", test_config_name_bounded_in_rejection_log);
                RUN_TEST("test_sequence_wrap", test_sequence_wrap);
                RUN_TEST("test_fragment_counts", test_fragment_counts);
                RUN_TEST("test_truncated_packets", test_truncated_packets);
                RUN_TEST("test_public_api_surface", test_public_api_surface);

                // C# port specific
                RUN_TEST("test_endpoint_config_copied", test_endpoint_config_copied);
                RUN_TEST("test_fragment_header_truncated_embedded_header", test_fragment_header_truncated_embedded_header);
                RUN_TEST("test_fragment_non_canonical_header", test_fragment_non_canonical_header);
                RUN_TEST("test_receive_invalid_length", test_receive_invalid_length);
                RUN_TEST("test_bandwidth_finite", test_bandwidth_finite);
                RUN_TEST("test_packet_loss_num_sent", test_packet_loss_num_sent);
                RUN_TEST("test_wire_conformance", test_wire_conformance);
            }
        }
    }
}
