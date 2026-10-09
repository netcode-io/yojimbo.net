/*
    reliable.io

    Copyright © 2017 - 2019, The Network Protocol Company, Inc.

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
using System.Diagnostics;

namespace networkprotocol
{
    public static partial class reliable
    {
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
        public const int ENDPOINT_NUM_COUNTERS = 10;

        public const int MAX_PACKET_HEADER_BYTES = 9;
        public const int FRAGMENT_HEADER_BYTES = 5;

        public const int LOG_LEVEL_NONE = 0;
        public const int LOG_LEVEL_ERROR = 1;
        public const int LOG_LEVEL_INFO = 2;
        public const int LOG_LEVEL_DEBUG = 3;

        public const int OK = 1;
        public const int ERROR = 0;
    }

    static partial class reliable
    {
        public static void init() { }

        public static void term() { }
    }

    public class reliable_config_t
    {
        public string name;
        public object context;
        public int index;
        public int max_packet_size;
        public int fragment_above;
        public int max_fragments;
        public int fragment_size;
        public int ack_buffer_size;
        public int sent_packets_buffer_size;
        public int received_packets_buffer_size;
        public int fragment_reassembly_buffer_size;
        public float rtt_smoothing_factor;
        public float packet_loss_smoothing_factor;
        public float bandwidth_smoothing_factor;
        public int packet_header_size;
        public Action<object, int, ushort, byte[], int> transmit_packet_function;
        public Func<object, int, ushort, byte[], int, int> process_packet_function;
        public object allocator_context;
        public Func<object, ulong, object> allocate_function;
        public Action<object, object> free_function;
    }

    public class reliable_endpoint_t { }

    static partial class reliable
    {
        public static void default_config(out reliable_config_t config) { config = null; }

        public static reliable_endpoint_t endpoint_create(reliable_config_t config, double time) => null;

        public static ushort endpoint_next_packet_sequence(this reliable_endpoint_t endpoint) => 0;

        public static void endpoint_send_packet(this reliable_endpoint_t endpoint, byte[] packet_data, int packet_bytes) { }

        public static void endpoint_receive_packet(this reliable_endpoint_t endpoint, byte[] packet_data, int packet_bytes) { }

        public static void endpoint_free_packet(this reliable_endpoint_t endpoint, object packet) { }

        public static ushort[] endpoint_get_acks(this reliable_endpoint_t endpoint, out int num_acks) { num_acks = 0; return null; }

        public static void endpoint_clear_acks(this reliable_endpoint_t endpoint) { }

        public static void endpoint_reset(this reliable_endpoint_t endpoint) { }

        public static void endpoint_update(this reliable_endpoint_t endpoint, double time) { }

        public static float endpoint_rtt(this reliable_endpoint_t endpoint) => 0f;

        public static float endpoint_packet_loss(this reliable_endpoint_t endpoint) => 0f;

        public static void endpoint_bandwidth(this reliable_endpoint_t endpoint, out float sent_bandwidth_kbps, out float received_bandwidth_kbps, out float acked_bandwidth_kpbs) { sent_bandwidth_kbps = 0; received_bandwidth_kbps = 0; acked_bandwidth_kpbs = 0; }

        public static ulong[] endpoint_counters(this reliable_endpoint_t endpoint) => null;

        public static void endpoint_destroy(ref reliable_endpoint_t endpoint) { endpoint = null; }
    }

    public static partial class reliable
    {
        public static void log_level(int level) { }

        public static void set_printf_function(Func<string, int> function) { }

        public static Action<string, string, string, int> _assert_function;

        [Conditional("DEBUG")]
        public static void assert(bool condition) { }

        public static void set_assert_function(Action<string, string, string, int> function) => _assert_function = function;
    }
}

