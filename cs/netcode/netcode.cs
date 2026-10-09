/*
    netcode.io reference implementation

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

using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Reflection.Emit;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

namespace networkprotocol
{
    #region netcode_h

    /*
        IMPORTANT: netcode is single-threaded by design and is not thread safe.

        The library uses global state (init/term, the log level, and the printf and assert hooks)
        and performs no internal synchronization. Call all netcode functions from the same thread,
        or provide your own locking around them. Each client and server object must only be updated
        from one thread at a time.
    */

    public static partial class netcode
    {
        public const string VERSION_FULL = "1.4.8";
        public const int VERSION_MAJOR = 1;
        public const int VERSION_MINOR = 4;
        public const int VERSION_PATCH = 8;

        public const int CONNECT_TOKEN_BYTES = 2048;
        public const int KEY_BYTES = 32;
        public const int MAC_BYTES = 16;
        public const int USER_DATA_BYTES = 256;
        public const int MAX_SERVERS_PER_CONNECT = 32;
        public const int DEFAULT_MAX_CONNECT_TOKEN_LIFETIME = 30;

        public const int CLIENT_STATE_CONNECT_TOKEN_EXPIRED = -6;
        public const int CLIENT_STATE_INVALID_CONNECT_TOKEN = -5;
        public const int CLIENT_STATE_CONNECTION_TIMED_OUT = -4;
        public const int CLIENT_STATE_CONNECTION_RESPONSE_TIMED_OUT = -3;
        public const int CLIENT_STATE_CONNECTION_REQUEST_TIMED_OUT = -2;
        public const int CLIENT_STATE_CONNECTION_DENIED = -1;
        public const int CLIENT_STATE_DISCONNECTED = 0;
        public const int CLIENT_STATE_SENDING_CONNECTION_REQUEST = 1;
        public const int CLIENT_STATE_SENDING_CONNECTION_RESPONSE = 2;
        public const int CLIENT_STATE_CONNECTED = 3;

        // The reason the client in a server slot was last disconnected. Tracked per-client slot:
        // reset to NONE when the server starts and when a new client connects to the slot, and
        // recorded before the connect_disconnect_callback fires, so it can be queried from inside
        // that callback via server_client_disconnect_reason.
        public const int SERVER_CLIENT_DISCONNECT_REASON_NONE = 0;
        public const int SERVER_CLIENT_DISCONNECT_REASON_TIMED_OUT = 1;
        public const int SERVER_CLIENT_DISCONNECT_REASON_CLIENT_DISCONNECT = 2;
        public const int SERVER_CLIENT_DISCONNECT_REASON_SERVER_DISCONNECT = 3;

        public const int CLIENT_CREATE_ERROR_NONE = 0;
        public const int CLIENT_CREATE_ERROR_PARSE_ADDRESS_FAILED = 1;
        public const int CLIENT_CREATE_ERROR_PARSE_ADDRESS2_FAILED = 2;
        public const int CLIENT_CREATE_ERROR_SIMULATOR_REQUIRES_PORT = 3;
        public const int CLIENT_CREATE_ERROR_CREATE_SOCKET_IPV4_FAILED = 4;
        public const int CLIENT_CREATE_ERROR_CREATE_SOCKET_IPV6_FAILED = 5;
        public const int CLIENT_CREATE_ERROR_ALLOCATE_CLIENT_FAILED = 6;
        public const int CLIENT_CREATE_ERROR_MISSING_OVERRIDE_CALLBACK = 7;

        public const int SERVER_CREATE_ERROR_NONE = 0;
        public const int SERVER_CREATE_ERROR_PARSE_ADDRESS_FAILED = 1;
        public const int SERVER_CREATE_ERROR_PARSE_ADDRESS2_FAILED = 2;
        public const int SERVER_CREATE_ERROR_CREATE_SOCKET_IPV4_FAILED = 3;
        public const int SERVER_CREATE_ERROR_CREATE_SOCKET_IPV6_FAILED = 4;
        public const int SERVER_CREATE_ERROR_BIND_SOCKET_IPV4_FAILED = 5;
        public const int SERVER_CREATE_ERROR_BIND_SOCKET_IPV6_FAILED = 6;
        public const int SERVER_CREATE_ERROR_ALLOCATE_SERVER_FAILED = 7;
        public const int SERVER_CREATE_ERROR_MISSING_OVERRIDE_CALLBACK = 8;

        public const int MAX_CLIENTS = 256;
        public const int MAX_PACKET_SIZE = 1200;

        public const int MAX_ADDRESS_STRING_LENGTH = 256;

        public const int LOG_LEVEL_NONE = 0;
        public const int LOG_LEVEL_ERROR = 1;
        public const int LOG_LEVEL_INFO = 2;
        public const int LOG_LEVEL_DEBUG = 3;

        public const int OK = 1;
        public const int ERROR = 0;

        public const int ADDRESS_NONE = 0;
        public const int ADDRESS_IPV4 = 1;
        public const int ADDRESS_IPV6 = 2;
    }

    /// <summary>
    /// An address. NOTE: this is a class, but the C original is a value type. netcode always stores
    /// a copy (netcode.address_copy) when it keeps an address, so callers may reuse their instances.
    /// </summary>
    public class netcode_address_t
    {
        public IPAddress data;
        public ushort port;
        public byte type;
    }

    public class netcode_client_config_t
    {
        public object allocator_context;
        public Func<object, ulong, object> allocate_function;
        public Action<object, object> free_function;
        public netcode_network_simulator_t network_simulator;
        public object callback_context;
        public Action<object, int, int> state_change_callback;
        public Action<object, int, byte[], int, ulong> send_loopback_packet_callback;
        public bool override_send_and_receive;
        public Action<object, netcode_address_t, byte[], int> send_packet_override;
        public Func<object, netcode_address_t, byte[], int, int> receive_packet_override;

        // the client keeps its own copy, as C copies the config struct
        internal netcode_client_config_t copy() => (netcode_client_config_t)MemberwiseClone();
    }

    public class netcode_server_config_t
    {
        public ulong protocol_id;
        public byte[] private_key = new byte[netcode.KEY_BYTES];
        public object allocator_context;
        public Func<object, ulong, object> allocate_function;
        public Action<object, object> free_function;
        public netcode_network_simulator_t network_simulator;
        public object callback_context;
        public Action<object, int, int> connect_disconnect_callback;
        public Action<object, int, byte[], int, ulong> send_loopback_packet_callback;
        public bool override_send_and_receive;
        public Action<object, netcode_address_t, byte[], int> send_packet_override;
        public Func<object, netcode_address_t, byte[], int, int> receive_packet_override;

        /*
            max_connect_token_lifetime is the longest lifetime in seconds that the backend issues
            connect tokens with, as passed to generate_connect_token. The server ignores any
            connection request whose connect token expire timestamp minus this lifetime is earlier
            than the time the server started, so a connect token that could have been issued before
            the server started cannot be presented after it. Set it to the lifetime your backend
            issues: a larger value rejects legitimate connect tokens until the difference has elapsed,
            and a smaller value lets connect tokens issued shortly before the server started through.
            A value of zero or less takes DEFAULT_MAX_CONNECT_TOKEN_LIFETIME instead.
        */
        public int max_connect_token_lifetime;

        // the server keeps its own copy, as C copies the config struct (including the private key)
        internal netcode_server_config_t copy()
        {
            var config = (netcode_server_config_t)MemberwiseClone();
            config.private_key = new byte[netcode.KEY_BYTES];
            if (private_key != null)
                Buffer.BlockCopy(private_key, 0, config.private_key, 0, Math.Min(private_key.Length, netcode.KEY_BYTES));
            return config;
        }
    }

    #endregion

    public static partial class netcode
    {
        #region defines

        internal const int SOCKET_IPV6 = 1;
        internal const int SOCKET_IPV4 = 2;

        internal const int CONNECT_TOKEN_NONCE_BYTES = 24;
        internal const int CONNECT_TOKEN_PRIVATE_BYTES = 1024;
        internal const int CHALLENGE_TOKEN_BYTES = 300;
        internal const int VERSION_INFO_BYTES = 13;
        internal const int MAX_PACKET_BYTES = 1300;
        internal const int MAX_PAYLOAD_BYTES = 1200;
        internal const int PACKET_QUEUE_SIZE = 256;
        internal const int REPLAY_PROTECTION_BUFFER_SIZE = 256;
        internal const int CLIENT_MAX_RECEIVE_PACKETS = 64;
        internal const int SERVER_MAX_RECEIVE_PACKETS = 64 * MAX_CLIENTS;
        internal const int CLIENT_SOCKET_SNDBUF_SIZE = 256 * 1024;
        internal const int CLIENT_SOCKET_RCVBUF_SIZE = 256 * 1024;
        internal const int SERVER_SOCKET_SNDBUF_SIZE = 4 * 1024 * 1024;
        internal const int SERVER_SOCKET_RCVBUF_SIZE = 4 * 1024 * 1024;

        internal static byte[] VERSION_INFO = Encoding.ASCII.GetBytes("NETCODE 1.02\0");
        internal const float PACKET_SEND_RATE = 10.0f;
        internal const int NUM_DISCONNECT_PACKETS = 10;

        /*
            The default assert handler prints the failed condition, breaks into the debugger and
            exits. A custom assert handler may return instead, in which case execution continues
            past the failed assert -- that is the caller's choice and their responsibility.
        */

        [DebuggerStepThrough, Conditional("DEBUG")]
        public static void assert(bool condition,
            [CallerArgumentExpression(nameof(condition))] string condition_string = null,
            [CallerMemberName] string function = null,
            [CallerFilePath] string file = null,
            [CallerLineNumber] int line = 0)
        {
            if (!condition)
                assert_function?.Invoke(condition_string, function, file, line);
        }

        #endregion

        #region assert / logging

        internal static void default_assert_handler(string condition, string function, string file, int line)
        {
            Console.Write($"assert failed: ( {condition} ), function {function}, file {file}, line {line}\n");
            if (Debugger.IsAttached) Debugger.Break();
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

        // logging is compiled in unless NETCODE_DISABLE_LOGGING is defined
#if !NETCODE_DISABLE_LOGGING
        static void printf(int level, string format)
        {
            if (level > log_level_) return;
            printf_function(format);
        }
#else
        static void printf(int level, string format) { }
#endif

        static object default_allocate_function(object context, ulong bytes) => null;

        static void default_free_function(object context, object pointer) { }

        #endregion

        #region netcode_address_t

        static int parse_port(string str, out ushort port)
        {
            // the port must be all digits and fit in [0,65535]. anything else is an error,
            // rather than whatever atoi truncation used to produce.

            port = 0;

            if (str.Length == 0)
                return ERROR;

            var value = 0;
            for (var i = 0; i < str.Length; i++)
            {
                if (str[i] < '0' || str[i] > '9')
                    return ERROR;
                value = value * 10 + (str[i] - '0');
                if (value > 65535)
                    return ERROR;
            }

            port = (ushort)value;

            return OK;
        }

        // inet_pton( AF_INET6 ) equivalent: IPAddress.TryParse also accepts brackets, ports and scope ids, which inet_pton does not
        static bool inet_pton_ipv6(string str, out IPAddress ipaddress)
        {
            ipaddress = null;
            if (str.Length == 0 || str.IndexOfAny(new[] { '[', ']', '%', '/', ' ' }) >= 0 || str.IndexOf(':') < 0)
                return false;
            return IPAddress.TryParse(str, out ipaddress) && ipaddress.AddressFamily == AddressFamily.InterNetworkV6;
        }

        // inet_pton( AF_INET ) equivalent: exactly four dotted decimal octets. IPAddress.TryParse also accepts "1" and "127.1"
        static bool inet_pton_ipv4(string str, out IPAddress ipaddress)
        {
            ipaddress = null;
            var parts = str.Split('.');
            if (parts.Length != 4)
                return false;
            var bytes = new byte[4];
            for (var i = 0; i < 4; i++)
            {
                var part = parts[i];
                if (part.Length < 1 || part.Length > 3)
                    return false;
                var value = 0;
                foreach (var c in part)
                {
                    if (c < '0' || c > '9')
                        return false;
                    value = value * 10 + (c - '0');
                }
                if (value > 255)
                    return false;
                bytes[i] = (byte)value;
            }
            ipaddress = new IPAddress(bytes);
            return true;
        }

        public static int parse_address(string address_string_in, out netcode_address_t address)
        {
            assert(address_string_in != null);
            address = new netcode_address_t(); //: assert(address != null);

            if (address_string_in == null)
                return ERROR;

            // first try to parse the string as an IPv6 address:
            // 1. if the first character is '[' then it's probably an ipv6 in form "[addr6]:portnum"
            // 2. otherwise try to parse as a raw IPv6 address using inet_pton

            var address_string = address_string_in;
            var terminator = address_string.IndexOf('\0');
            if (terminator >= 0)
                address_string = address_string.Substring(0, terminator);
            if (address_string.Length > MAX_ADDRESS_STRING_LENGTH - 1)
                address_string = address_string.Substring(0, MAX_ADDRESS_STRING_LENGTH - 1);

            var address_string_length = address_string.Length;

            if (address_string_length > 0 && address_string[0] == '[')
            {
                var base_index = address_string_length - 1;
                var found_port = false;

                for (var i = 0; i < 6; i++)         // note: no need to search past 6 characters as ":65535" is longest possible port value
                {
                    var index = base_index - i;
                    if (index < 3)
                        break;
                    if (address_string[index] == ':' && address_string[index - 1] == ']')
                    {
                        if (parse_port(address_string.Substring(index + 1), out var port) != OK)
                            return ERROR;
                        address.port = port;
                        address_string = address_string.Substring(0, index - 1);
                        found_port = true;
                        break;
                    }
                }

                // if a port is omitted, it is assumed to be zero. strip the trailing ']' so "[addr]" parses as just the address

                if (!found_port && address_string[base_index] == ']')
                    address_string = address_string.Substring(0, base_index);

                address_string = address_string.Substring(1);
            }

            if (inet_pton_ipv6(address_string, out var ipaddress))
            {
                address.type = ADDRESS_IPV6;
                address.data = ipaddress;
                return OK;
            }

            // otherwise it's probably an IPv4 address:
            // 1. look for ":portnum", if found save the portnum and strip it out
            // 2. parse remaining ipv4 address via inet_pton

            address_string_length = address_string.Length;
            {
                var base_index = address_string_length - 1;
                for (var i = 0; i < 6; i++)
                {
                    var index = base_index - i;
                    if (index < 0)
                        break;
                    if (address_string[index] == ':')
                    {
                        if (parse_port(address_string.Substring(index + 1), out var port) != OK)
                            return ERROR;
                        address.port = port;
                        address_string = address_string.Substring(0, index);
                        break;
                    }
                }
            }

            if (inet_pton_ipv4(address_string, out ipaddress))
            {
                address.type = ADDRESS_IPV4;
                address.data = ipaddress;
                return OK;
            }

            address.port = 0;

            return ERROR;
        }

        /// <summary>
        /// Returns the address in its printable form, at most MAX_ADDRESS_STRING_LENGTH-1 characters.
        /// </summary>
        public static string address_to_string(netcode_address_t address)
        {
            assert(address != null);
            string result;
            if (address.type == ADDRESS_IPV6) result = address.port == 0 ? $"{address.data}" : $"[{address.data}]:{address.port}";
            else if (address.type == ADDRESS_IPV4) result = address.port == 0 ? $"{address.data}" : $"{address.data}:{address.port}";
            else result = "NONE";
            return result.Length < MAX_ADDRESS_STRING_LENGTH ? result : result.Substring(0, MAX_ADDRESS_STRING_LENGTH - 1);
        }

        public static bool address_equal(netcode_address_t a, netcode_address_t b)
        {
            assert(a != null);
            assert(b != null);

            if (a.type != b.type)
                return false;

            if (a.port != b.port)
                return false;

            if (a.type != ADDRESS_IPV4 && a.type != ADDRESS_IPV6)
                return false;

            if (a.data == null || b.data == null)
                return false;

            return a.data.GetAddressBytes().AsSpan().SequenceEqual(b.data.GetAddressBytes());
        }

        // C copies netcode_address_t by value. netcode_address_t is a class here, so every place that keeps an
        // address keeps its own copy. otherwise a later mutation through one reference would change the others.
        internal static netcode_address_t address_copy(netcode_address_t address) =>
            address == null ? new netcode_address_t() : new netcode_address_t { data = address.data, port = address.port, type = address.type };

        #endregion

        #region netcode_t

        internal struct netcode_t
        {
            public int initialized;
        }

        static netcode_t netcode_;

        public static int init()
        {
            // reference counted so multiple subsystems in the same application can call
            // init and term independently

            if (netcode_.initialized != 0)
            {
                netcode_.initialized++;
                return OK;
            }

            netcode_.initialized = 1;

            return OK;
        }

        public static void term()
        {
            assert(netcode_.initialized != 0);

            if (netcode_.initialized == 0)
                return;

            netcode_.initialized--;
        }

        static bool packet_tagging_enabled = false;

        /// <summary>
        /// Tag packets sent from sockets created after this call as low latency (DSCP EF / TOS 46).
        /// Supported on Linux and macOS. On Windows this needs the qWAVE API and is a no-op here.
        /// </summary>
        public static void enable_packet_tagging() =>
            packet_tagging_enabled = true;

        #endregion

        #region socket_t

        internal class socket_t
        {
            public netcode_address_t address = new netcode_address_t();
            public Socket handle;
        }

        internal class socket_holder_t
        {
            public socket_t ipv4;
            public socket_t ipv6;
        }

        const int SOCKET_ERROR_NONE = 0;
        const int SOCKET_ERROR_CREATE_FAILED = 1;
        const int SOCKET_ERROR_SET_NON_BLOCKING_FAILED = 2;
        const int SOCKET_ERROR_SOCKOPT_IPV6_ONLY_FAILED = 3;
        const int SOCKET_ERROR_SOCKOPT_RCVBUF_FAILED = 4;
        const int SOCKET_ERROR_SOCKOPT_SNDBUF_FAILED = 5;
        const int SOCKET_ERROR_BIND_IPV4_FAILED = 6;
        const int SOCKET_ERROR_BIND_IPV6_FAILED = 7;
        const int SOCKET_ERROR_GET_SOCKNAME_IPV4_FAILED = 8;
        const int SOCKET_ERROR_GET_SOCKNAME_IPV6_FAILED = 9;
        const int SOCKET_ERROR_DISABLE_UDP_PORT_CONNRESET_FAILED = 10;
        const int SOCKET_ERROR_ENABLE_PACKET_TAGGING_FAILED = 11;

        static void socket_destroy(ref socket_t socket)
        {
            assert(socket != null);
            assert(netcode_.initialized != 0);

            if (socket == null)
                return;

            if (socket.handle != null)
            {
                socket.handle.Close();
                socket.handle = null;
            }
        }

        // SIO_UDP_CONNRESET = _WSAIOW(IOC_VENDOR, 12)
        const int SIO_UDP_CONNRESET = unchecked((int)0x9800000C);

        // IPV6_TCLASS has no SocketOptionName in .NET and its value is platform specific
        const int IPPROTO_IPV6 = 41;
        const int IPV6_TCLASS_LINUX = 67;
        const int IPV6_TCLASS_MAC = 36;

        static bool socket_set_buffer_size(Socket handle, bool send, int requested_size, out int size)
        {
            // increase socket send and receive buffer sizes. linux and windows clamp requests that
            // exceed the OS limit, but the BSDs (and macOS) reject them instead, so back off until accepted.

            size = requested_size;
            while (true)
            {
                try
                {
                    if (send) handle.SendBufferSize = size;
                    else handle.ReceiveBufferSize = size;
                    return true;
                }
                catch (SocketException)
                {
                    size /= 2;
                    if (size < 256 * 1024)
                        return false;
                }
            }
        }

        static int socket_create(ref socket_t s, netcode_address_t address, int send_buffer_size, int receive_buffer_size)
        {
            assert(s != null);
            assert(address != null);
            assert(netcode_.initialized != 0);

            assert(address.type != ADDRESS_NONE);

            s.address = address_copy(address);

            // create socket

            try { s.handle = new Socket((address.type == ADDRESS_IPV6) ? AddressFamily.InterNetworkV6 : AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp); }
            catch
            {
                printf(LOG_LEVEL_ERROR, "error: failed to create socket\n");
                s.handle = null;
                return SOCKET_ERROR_CREATE_FAILED;
            }

            // IMPORTANT: tell windows we don't want to receive any connection reset messages for this socket
            // If we don't do this, clients disconnecting hard will cause recvfrom on the server to repeatedly error out
            // due to ICMP disconnected packets, causing long periods where the server doesn't receive any packets from clients.

            if (OperatingSystem.IsWindows())
            {
                try { s.handle.IOControl(SIO_UDP_CONNRESET, new byte[4], null); }
                catch
                {
                    printf(LOG_LEVEL_ERROR, "error: failed to disable UDP CONNRESET (port unreachable) message reporting on socket\n");
                    socket_destroy(ref s);
                    return SOCKET_ERROR_DISABLE_UDP_PORT_CONNRESET_FAILED;
                }
            }

            // force IPv6 only if necessary

            if (address.type == ADDRESS_IPV6)
            {
                try { s.handle.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.IPv6Only, true); }
                catch
                {
                    printf(LOG_LEVEL_ERROR, "error: failed to set socket ipv6 only\n");
                    socket_destroy(ref s);
                    return SOCKET_ERROR_SOCKOPT_IPV6_ONLY_FAILED;
                }
            }

            // increase socket send and receive buffer sizes

            if (!socket_set_buffer_size(s.handle, true, send_buffer_size, out var size))
            {
                printf(LOG_LEVEL_ERROR, "error: failed to set socket send buffer size\n");
                socket_destroy(ref s);
                return SOCKET_ERROR_SOCKOPT_SNDBUF_FAILED;
            }
            if (size != send_buffer_size)
                printf(LOG_LEVEL_INFO, $"socket send buffer size reduced from {send_buffer_size} to {size}\n");

            if (!socket_set_buffer_size(s.handle, false, receive_buffer_size, out size))
            {
                printf(LOG_LEVEL_ERROR, "error: failed to set socket receive buffer size\n");
                socket_destroy(ref s);
                return SOCKET_ERROR_SOCKOPT_RCVBUF_FAILED;
            }
            if (size != receive_buffer_size)
                printf(LOG_LEVEL_INFO, $"socket receive buffer size reduced from {receive_buffer_size} to {size}\n");

            // bind to port

            var endpoint = new IPEndPoint(address.data ?? (address.type == ADDRESS_IPV6 ? IPAddress.IPv6Any : IPAddress.Any), address.port);
            try { s.handle.Bind(endpoint); }
            catch
            {
                printf(LOG_LEVEL_ERROR, $"error: failed to bind socket ({(address.type == ADDRESS_IPV6 ? "ipv6" : "ipv4")})\n");
                socket_destroy(ref s);
                return address.type == ADDRESS_IPV6 ? SOCKET_ERROR_BIND_IPV6_FAILED : SOCKET_ERROR_BIND_IPV4_FAILED;
            }

            // if bound to port 0 find the actual port we got

            if (address.port == 0)
            {
                if (!(s.handle.LocalEndPoint is IPEndPoint local_endpoint))
                {
                    printf(LOG_LEVEL_ERROR, $"error: failed to get socket port ({(address.type == ADDRESS_IPV6 ? "ipv6" : "ipv4")})\n");
                    socket_destroy(ref s);
                    return address.type == ADDRESS_IPV6 ? SOCKET_ERROR_GET_SOCKNAME_IPV6_FAILED : SOCKET_ERROR_GET_SOCKNAME_IPV4_FAILED;
                }
                s.address.port = (ushort)local_endpoint.Port;
            }

            // set non-blocking io

            try { s.handle.Blocking = false; }
            catch
            {
                socket_destroy(ref s);
                return SOCKET_ERROR_SET_NON_BLOCKING_FAILED;
            }

            // tag packets as low latency

            if (packet_tagging_enabled && (OperatingSystem.IsLinux() || OperatingSystem.IsMacOS()))
            {
                const int tos = 46;
                try
                {
                    if (address.type == ADDRESS_IPV6)
                        s.handle.SetRawSocketOption(IPPROTO_IPV6, OperatingSystem.IsLinux() ? IPV6_TCLASS_LINUX : IPV6_TCLASS_MAC, BitConverter.GetBytes(tos));
                    else
                        s.handle.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.TypeOfService, tos);
                }
                catch
                {
                    printf(LOG_LEVEL_ERROR, $"error: failed to enable packet tagging ({(address.type == ADDRESS_IPV6 ? "ipv6" : "ipv4")})\n");
                    socket_destroy(ref s);
                    return SOCKET_ERROR_ENABLE_PACKET_TAGGING_FAILED;
                }
            }

            return SOCKET_ERROR_NONE;
        }

        static void socket_send_packet(socket_t socket, netcode_address_t to, byte[] packet_data, int packet_bytes)
        {
            assert(socket != null);
            assert(socket.handle != null);
            assert(to != null);
            assert(to.type == ADDRESS_IPV6 || to.type == ADDRESS_IPV4);
            assert(packet_data != null);
            assert(packet_bytes > 0);
            var socket_address = new IPEndPoint(to.data, to.port);
            try { socket.handle.SendTo(packet_data, packet_bytes, SocketFlags.None, socket_address); }
            catch (SocketException) { }
        }

        static int socket_receive_packet(socket_t socket, netcode_address_t from, byte[] packet_data, int max_packet_size)
        {
            assert(socket != null);
            assert(socket.handle != null);
            assert(from != null);
            assert(packet_data != null);
            assert(max_packet_size > 0);
            if (socket.handle.Available == 0)
                return 0;
            var sockaddr_from = (EndPoint)new IPEndPoint(socket.address.type == ADDRESS_IPV4 ? IPAddress.Any : IPAddress.IPv6Any, 0);
            int result;
            try { result = socket.handle.ReceiveFrom(packet_data, 0, max_packet_size, SocketFlags.None, ref sockaddr_from); }
            catch (SocketException e)
            {
                var error = e.SocketErrorCode;

                if (error == SocketError.WouldBlock)
                    return 0;

                // SIO_UDP_CONNRESET is disabled on windows in socket_create, so this should not happen. if it does,
                // skip the ICMP port unreachable report and keep reading rather than stalling the receive loop

                if (error == SocketError.ConnectionReset)
                    return socket_receive_packet(socket, from, packet_data, max_packet_size);

                printf(LOG_LEVEL_ERROR, $"error: recvfrom failed with error {error}\n");

                return 0;
            }
            if (result <= 0)
            {
                printf(LOG_LEVEL_ERROR, $"error: recvfrom failed with result {result}\n");
                return 0;
            }

            var endpoint = (IPEndPoint)sockaddr_from;
            if (endpoint.AddressFamily == AddressFamily.InterNetworkV6)
            {
                from.type = ADDRESS_IPV6;
                from.data = endpoint.Address;
                from.port = (ushort)endpoint.Port;
            }
            else if (endpoint.AddressFamily == AddressFamily.InterNetwork)
            {
                from.type = ADDRESS_IPV4;
                from.data = endpoint.Address;
                from.port = (ushort)endpoint.Port;
            }
            else
            {
                assert(false);
                return 0;
            }

            assert(result >= 0);

            var bytes_read = result;

            return bytes_read;
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

        internal static void write_uint32(byte[] b, ref int p, uint value)
        {
            b[p] = (byte)value;
            b[p + 1] = (byte)(value >> 8);
            b[p + 2] = (byte)(value >> 0x10);
            b[p + 3] = (byte)(value >> 0x18);
            p += 4;
        }

        internal static void write_uint64(byte[] b, ref int p, ulong value)
        {
            b[p + 0] = (byte)value;
            b[p + 1] = (byte)(value >> 8);
            b[p + 2] = (byte)(value >> 0x10);
            b[p + 3] = (byte)(value >> 0x18);
            b[p + 4] = (byte)(value >> 0x20);
            b[p + 5] = (byte)(value >> 0x28);
            b[p + 6] = (byte)(value >> 0x30);
            b[p + 7] = (byte)(value >> 0x38);
            p += 8;
        }

        internal static void write_bytes(byte[] b, ref int p, byte[] byte_array, int num_bytes)
        {
            int i;
            for (i = 0; i < num_bytes; ++i)
                write_uint8(b, ref p, byte_array[i]);
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

        internal static uint read_uint32(byte[] b, ref int p)
        {
            var value = (uint)(b[p] | (b[p + 1] << 8) | (b[p + 2] << 0x10) | (b[p + 3] << 0x18));
            p += 4;
            return value;
        }

        internal static ulong read_uint64(byte[] b, ref int p)
        {
            var num = (uint)(b[p] | (b[p + 1] << 8) | (b[p + 2] << 0x10) | (b[p + 3] << 0x18));
            var num2 = (uint)(b[p + 4] | (b[p + 5] << 8) | (b[p + 6] << 0x10) | (b[p + 7] << 0x18));
            var value = ((ulong)num2 << 0x20) | num;
            p += 8;
            return value;
        }

        internal static byte[] read_bytes(byte[] b, ref int p, byte[] byte_array, int num_bytes)
        {
            int i;
            for (i = 0; i < num_bytes; ++i)
                byte_array[i] = read_uint8(b, ref p);
            return byte_array;
        }

        #endregion

        #region generate / encrypt

                static void generate_key(byte[] key) { assert(key != null); RandomNumberGenerator.Fill(key); }

        static void generate_nonce(byte[] nonce) { assert(nonce != null); RandomNumberGenerator.Fill(nonce); }

        // fills the low "bytes" bytes of data with random bytes (like random_bytes( (uint8_t*) &data, bytes ) on little endian)
        public static void random_bytes(ref ulong data, int bytes)
        {
            assert(bytes > 0 && bytes <= 8);
            if (bytes <= 0 || bytes > 8) return;
            var v = new byte[8];
            BitConverter.TryWriteBytes(v, data);
            RandomNumberGenerator.Fill(v.AsSpan(0, bytes));
            data = BitConverter.ToUInt64(v, 0);
        }

        public static void random_bytes(byte[] data, int bytes) { assert(data != null); assert(bytes > 0); assert(bytes == data.Length); RandomNumberGenerator.Fill(data); } //: randombytes_buf(data, bytes);

        static int encrypt_aead_bignonce(
           byte[] message, int p, ulong message_length,
           byte[] additional, ulong additional_length,
           byte[] nonce,
           byte[] key)
        {
            var result = Crypto_aead.CurrentThread.Encrypt(true,
                message, p, out var encrypted_length,
                message, message_length,
                additional, additional_length,
                null, nonce, key);
            if (result != 0)
                return ERROR;
            assert(encrypted_length == message_length + MAC_BYTES);
            return OK;
        }

        static int decrypt_aead_bignonce(
            byte[] message, int p, ulong message_length,
            byte[] additional, ulong additional_length,
            byte[] nonce,
            byte[] key)
        {
            var result = Crypto_aead.CurrentThread.Decrypt(true,
                message, p, out var decrypted_length,
                null,
                message, message_length,
                additional, additional_length,
                nonce, key);
            if (result != 0)
                return ERROR;
            assert(decrypted_length == message_length - MAC_BYTES);
            return OK;
        }

        static int encrypt_aead(
            byte[] message, int p, ulong message_length,
            byte[] additional, ulong additional_length,
            byte[] nonce,
            byte[] key)
        {
            var result = Crypto_aead.CurrentThread.Encrypt(false,
                message, p, out var encrypted_length,
                message, message_length,
                additional, additional_length,
                null, nonce, key);
            if (result != 0)
                return ERROR;
            assert(encrypted_length == message_length + MAC_BYTES);
            return OK;
        }

        static int decrypt_aead(
            byte[] message, int p, ulong message_length,
            byte[] additional, ulong additional_length,
            byte[] nonce,
            byte[] key)
        {
            var result = Crypto_aead.CurrentThread.Decrypt(false,
                message, p, out var decrypted_length,
                null,
                message, message_length,
                additional, additional_length,
                nonce, key);
            if (result != 0)
                return ERROR;
            assert(decrypted_length == message_length - MAC_BYTES);
            return OK;
        }

        #endregion

        #region connect_token_private

        internal class connect_token_private_t
        {
            public ulong client_id;
            public int timeout_seconds;
            public int num_server_addresses;
            public netcode_address_t[] server_addresses = BufferEx.NewT<netcode_address_t>(MAX_SERVERS_PER_CONNECT);
            public byte[] client_to_server_key = new byte[KEY_BYTES];
            public byte[] server_to_client_key = new byte[KEY_BYTES];
            public byte[] user_data = new byte[USER_DATA_BYTES];
        }

        static void generate_connect_token_private(
            connect_token_private_t connect_token,
            ulong client_id,
            int timeout_seconds,
            int num_server_addresses,
            netcode_address_t[] server_addresses,
            byte[] user_data)
        {
            assert(connect_token != null);
            assert(num_server_addresses > 0);
            assert(num_server_addresses <= MAX_SERVERS_PER_CONNECT);
            assert(server_addresses != null);
            assert(user_data != null);

            connect_token.client_id = client_id;
            connect_token.timeout_seconds = timeout_seconds;
            connect_token.num_server_addresses = num_server_addresses;

            for (var i = 0; i < num_server_addresses; ++i)
                BufferEx.Copy(ref connect_token.server_addresses[i], server_addresses[i]);

            generate_key(connect_token.client_to_server_key);
            generate_key(connect_token.server_to_client_key);

            if (user_data != null)
                BufferEx.Copy(connect_token.user_data, user_data, USER_DATA_BYTES);
            else
                BufferEx.Set(connect_token.user_data, 0, USER_DATA_BYTES);
        }

        static void write_connect_token_private(
            connect_token_private_t connect_token,
            byte[] buffer, int buffer_length)
        {
            assert(connect_token != null);
            assert(connect_token.num_server_addresses > 0);
            assert(connect_token.num_server_addresses <= MAX_SERVERS_PER_CONNECT);
            assert(buffer != null);
            assert(buffer_length >= CONNECT_TOKEN_PRIVATE_BYTES);

            var p = 0;
            write_uint64(buffer, ref p, connect_token.client_id);
            write_uint32(buffer, ref p, (uint)connect_token.timeout_seconds);
            write_uint32(buffer, ref p, (uint)connect_token.num_server_addresses);
            for (var i = 0; i < connect_token.num_server_addresses; ++i)
                // todo: should really have a function to write an address
                if (connect_token.server_addresses[i].type == ADDRESS_IPV4)
                {
                    write_uint8(buffer, ref p, ADDRESS_IPV4);
                    write_bytes(buffer, ref p, connect_token.server_addresses[i].data.GetAddressBytes(), 4);
                    write_uint16(buffer, ref p, connect_token.server_addresses[i].port);
                }
                else if (connect_token.server_addresses[i].type == ADDRESS_IPV6)
                {
                    write_uint8(buffer, ref p, ADDRESS_IPV6);
                    write_bytes(buffer, ref p, connect_token.server_addresses[i].data.GetAddressBytes(), 16);
                    write_uint16(buffer, ref p, connect_token.server_addresses[i].port);
                }
                else assert(false);
            write_bytes(buffer, ref p, connect_token.client_to_server_key, KEY_BYTES);
            write_bytes(buffer, ref p, connect_token.server_to_client_key, KEY_BYTES);
            write_bytes(buffer, ref p, connect_token.user_data, USER_DATA_BYTES);
            assert(p <= CONNECT_TOKEN_PRIVATE_BYTES - MAC_BYTES);

            BufferEx.SetWithOffset(buffer, p, 0, CONNECT_TOKEN_PRIVATE_BYTES - p);
        }

        static int encrypt_connect_token_private(
            byte[] buffer, int p,
            int buffer_length,
            byte[] version_info,
            ulong protocol_id,
            ulong expire_timestamp,
            byte[] nonce,
            byte[] key)
        {
            assert(buffer != null);
            assert(buffer_length == CONNECT_TOKEN_PRIVATE_BYTES);
            assert(key != null);

            var additional_data = new byte[VERSION_INFO_BYTES + 8 + 8];
            {
                var p2 = 0;
                write_bytes(additional_data, ref p2, version_info, VERSION_INFO_BYTES);
                write_uint64(additional_data, ref p2, protocol_id);
                write_uint64(additional_data, ref p2, expire_timestamp);
            }
            return encrypt_aead_bignonce(buffer, p, CONNECT_TOKEN_PRIVATE_BYTES - MAC_BYTES, additional_data, (ulong)additional_data.Length, nonce, key);
        }

        static int decrypt_connect_token_private(
            byte[] buffer, int p,
            int buffer_length,
            byte[] version_info,
            ulong protocol_id,
            ulong expire_timestamp,
            byte[] nonce,
            byte[] key)
        {
            assert(buffer != null);
            assert(buffer_length == CONNECT_TOKEN_PRIVATE_BYTES);
            assert(key != null);

            var additional_data = new byte[VERSION_INFO_BYTES + 8 + 8];
            {
                var p2 = 0;
                write_bytes(additional_data, ref p2, version_info, VERSION_INFO_BYTES);
                write_uint64(additional_data, ref p2, protocol_id);
                write_uint64(additional_data, ref p2, expire_timestamp);
            }
            return decrypt_aead_bignonce(buffer, p, CONNECT_TOKEN_PRIVATE_BYTES, additional_data, (ulong)additional_data.Length, nonce, key);
        }

        static int read_connect_token_private(
            byte[] buffer, int buffer_length, connect_token_private_t connect_token)
        {
            assert(buffer != null);
            assert(connect_token != null);
            if (buffer_length < CONNECT_TOKEN_PRIVATE_BYTES)
                return ERROR;

            var p = 0;
            connect_token.client_id = read_uint64(buffer, ref p);
            connect_token.timeout_seconds = (int)read_uint32(buffer, ref p);
            connect_token.num_server_addresses = (int)read_uint32(buffer, ref p);
            if (connect_token.num_server_addresses <= 0)
                return ERROR;
            if (connect_token.num_server_addresses > MAX_SERVERS_PER_CONNECT)
                return ERROR;

            int i;
            for (i = 0; i < connect_token.num_server_addresses; ++i)
            {
                // todo: should really have a function to read an address
                connect_token.server_addresses[i].type = read_uint8(buffer, ref p);
                if (connect_token.server_addresses[i].type == ADDRESS_IPV4)
                {
                    var buf = new byte[4];
                    connect_token.server_addresses[i].data = new IPAddress(read_bytes(buffer, ref p, buf, 4));
                    connect_token.server_addresses[i].port = read_uint16(buffer, ref p);
                }
                else if (connect_token.server_addresses[i].type == ADDRESS_IPV6)
                {
                    var buf = new byte[16];
                    connect_token.server_addresses[i].data = new IPAddress(read_bytes(buffer, ref p, buf, 16));
                    connect_token.server_addresses[i].port = read_uint16(buffer, ref p);
                }
                else return ERROR;
            }
            read_bytes(buffer, ref p, connect_token.client_to_server_key, KEY_BYTES);
            read_bytes(buffer, ref p, connect_token.server_to_client_key, KEY_BYTES);
            read_bytes(buffer, ref p, connect_token.user_data, USER_DATA_BYTES);
            return OK;
        }

        #endregion

        #region challenge_token_t

        internal class challenge_token_t
        {
            public ulong client_id;
            public byte[] user_data = new byte[USER_DATA_BYTES];
        }

        static void write_challenge_token(challenge_token_t challenge_token, byte[] buffer, int buffer_length)
        {
            assert(challenge_token != null);
            assert(buffer != null);
            assert(buffer_length >= CHALLENGE_TOKEN_BYTES);

            BufferEx.Set(buffer, 0, CHALLENGE_TOKEN_BYTES);

            var p = 0;
            write_uint64(buffer, ref p, challenge_token.client_id);
            write_bytes(buffer, ref p, challenge_token.user_data, USER_DATA_BYTES);
            assert(p <= CHALLENGE_TOKEN_BYTES - MAC_BYTES);
        }

        static int encrypt_challenge_token(byte[] buffer, int p, int buffer_length, ulong sequence, byte[] key)
        {
            assert(buffer != null);
            assert(buffer_length >= CHALLENGE_TOKEN_BYTES);
            assert(key != null);

            var nonce = new byte[12];
            {
                var p2 = 0;
                write_uint32(nonce, ref p2, 0);
                write_uint64(nonce, ref p2, sequence);
            }
            return encrypt_aead(buffer, p, CHALLENGE_TOKEN_BYTES - MAC_BYTES, null, 0, nonce, key);
        }

        static int decrypt_challenge_token(byte[] buffer, int p, int buffer_length, ulong sequence, byte[] key)
        {
            assert(buffer != null);
            assert(buffer_length >= CHALLENGE_TOKEN_BYTES);
            assert(key != null);

            var nonce = new byte[12];
            {
                var p2 = 0;
                write_uint32(nonce, ref p2, 0);
                write_uint64(nonce, ref p2, sequence);
            }
            return decrypt_aead(buffer, p, CHALLENGE_TOKEN_BYTES, null, 0, nonce, key);
        }

        static int read_challenge_token(byte[] buffer, int buffer_length, challenge_token_t challenge_token)
        {
            assert(buffer != null);
            assert(challenge_token != null);
            if (buffer_length < CHALLENGE_TOKEN_BYTES)
                return ERROR;

            var p = 0;
            challenge_token.client_id = read_uint64(buffer, ref p);
            read_bytes(buffer, ref p, challenge_token.user_data, USER_DATA_BYTES);
            assert(p == 8 + USER_DATA_BYTES);
            return OK;
        }

        #endregion

        #region challenge_token_t

        const int CONNECTION_REQUEST_PACKET = 0;
        const int CONNECTION_DENIED_PACKET = 1;
        const int CONNECTION_CHALLENGE_PACKET = 2;
        const int CONNECTION_RESPONSE_PACKET = 3;
        const int CONNECTION_KEEP_ALIVE_PACKET = 4;
        const int CONNECTION_PAYLOAD_PACKET = 5;
        const int CONNECTION_DISCONNECT_PACKET = 6;
        const int CONNECTION_NUM_PACKETS = 7;

        internal class base_request_packet_t
        {
            public byte packet_type;
        }

        internal class connection_request_packet_t : base_request_packet_t
        {
            public byte[] version_info = new byte[VERSION_INFO_BYTES];
            public ulong protocol_id;
            public ulong connect_token_expire_timestamp;
            public byte[] connect_token_nonce = new byte[CONNECT_TOKEN_NONCE_BYTES];
            public byte[] connect_token_data = new byte[CONNECT_TOKEN_PRIVATE_BYTES];
        }

        internal class connection_denied_packet_t : base_request_packet_t
        {
        }

        internal class connection_challenge_packet_t : base_request_packet_t
        {
            public ulong challenge_token_sequence;
            public byte[] challenge_token_data = new byte[CHALLENGE_TOKEN_BYTES];
        }

        internal class connection_response_packet_t : base_request_packet_t
        {
            public ulong challenge_token_sequence;
            public byte[] challenge_token_data = new byte[CHALLENGE_TOKEN_BYTES];
        }

        internal class connection_keep_alive_packet_t : base_request_packet_t
        {
            public int client_index;
            public int max_clients;
        }

        internal class connection_payload_packet_t : base_request_packet_t
        {
            public ulong payload_bytes;
            public byte[] payload_data;
        }

        internal class connection_disconnect_packet_t : base_request_packet_t
        {
        }

        static connection_payload_packet_t create_payload_packet(int payload_bytes, object allocator_context, Func<object, ulong, object> allocate_function)
        {
            assert(payload_bytes >= 0);
            assert(payload_bytes <= MAX_PAYLOAD_BYTES);

            if (allocate_function == null)
                allocate_function = default_allocate_function;

            var packet = new connection_payload_packet_t { payload_data = new byte[payload_bytes] };
            if (packet == null)
                return null;
            packet.packet_type = CONNECTION_PAYLOAD_PACKET;
            packet.payload_bytes = (ulong)payload_bytes;
            return packet;
        }

        internal class context_t
        {
            public byte[] write_packet_key = new byte[KEY_BYTES];
            public byte[] read_packet_key = new byte[KEY_BYTES];
        }

        static int sequence_number_bytes_required(ulong sequence)
        {
            int i;
            var mask = 0xFF00000000000000UL;
            for (i = 0; i < 7; ++i)
            {
                if ((sequence & mask) != 0)
                    break;
                mask >>= 8;
            }
            return 8 - i;
        }

        static int write_packet(object packet, byte[] buffer, int buffer_length, ulong sequence, byte[] write_packet_key, ulong protocol_id)
        {
            assert(packet != null);
            assert(buffer != null);
            assert(write_packet_key != null);

            var packet_type = ((base_request_packet_t)packet).packet_type;

            if (packet_type == CONNECTION_REQUEST_PACKET)
            {
                // connection request packet: first byte is zero

                assert(buffer_length >= 1 + 13 + 8 + 8 + CONNECT_TOKEN_NONCE_BYTES + CONNECT_TOKEN_PRIVATE_BYTES);

                var p = (connection_request_packet_t)packet;

                var q = 0;
                write_uint8(buffer, ref q, CONNECTION_REQUEST_PACKET);
                write_bytes(buffer, ref q, p.version_info, VERSION_INFO_BYTES);
                write_uint64(buffer, ref q, p.protocol_id);
                write_uint64(buffer, ref q, p.connect_token_expire_timestamp);
                write_bytes(buffer, ref q, p.connect_token_nonce, CONNECT_TOKEN_NONCE_BYTES);
                write_bytes(buffer, ref q, p.connect_token_data, CONNECT_TOKEN_PRIVATE_BYTES);

                assert(q == 1 + 13 + 8 + 8 + CONNECT_TOKEN_NONCE_BYTES + CONNECT_TOKEN_PRIVATE_BYTES);
                return q;
            }
            else
            {
                // *** encrypted packets ***

                // write the prefix byte (this is a combination of the packet type and number of sequence bytes)

                var q = 0;
                var sequence_bytes = (byte)sequence_number_bytes_required(sequence);

                assert(sequence_bytes >= 1);
                assert(sequence_bytes <= 8);
                assert(packet_type <= 0xF);

                var prefix_byte = (byte)(packet_type | (sequence_bytes << 4));

                write_uint8(buffer, ref q, prefix_byte);

                // write the variable length sequence number [1,8] bytes.

                var sequence_temp = sequence;

                int i;
                for (i = 0; i < sequence_bytes; ++i)
                {
                    write_uint8(buffer, ref q, (byte)(sequence_temp & 0xFF));
                    sequence_temp >>= 8;
                }

                // write packet data according to type. this data will be encrypted.

                var encrypted_start = q;

                switch (packet_type)
                {
                    case CONNECTION_DENIED_PACKET: break;

                    case CONNECTION_CHALLENGE_PACKET:
                        {
                            var p = (connection_challenge_packet_t)packet;
                            write_uint64(buffer, ref q, p.challenge_token_sequence);
                            write_bytes(buffer, ref q, p.challenge_token_data, CHALLENGE_TOKEN_BYTES);
                        }
                        break;

                    case CONNECTION_RESPONSE_PACKET:
                        {
                            var p = (connection_response_packet_t)packet;
                            write_uint64(buffer, ref q, p.challenge_token_sequence);
                            write_bytes(buffer, ref q, p.challenge_token_data, CHALLENGE_TOKEN_BYTES);
                        }
                        break;

                    case CONNECTION_KEEP_ALIVE_PACKET:
                        {
                            var p = (connection_keep_alive_packet_t)packet;
                            write_uint32(buffer, ref q, (uint)p.client_index);
                            write_uint32(buffer, ref q, (uint)p.max_clients);
                        }
                        break;

                    case CONNECTION_PAYLOAD_PACKET:
                        {
                            var p = (connection_payload_packet_t)packet;
                            assert(p.payload_bytes <= MAX_PAYLOAD_BYTES);
                            write_bytes(buffer, ref q, p.payload_data, (int)p.payload_bytes);
                        }
                        break;

                    case CONNECTION_DISCONNECT_PACKET: break;

                    default: assert(false); break;
                }

                assert(q <= buffer_length - MAC_BYTES);

                var encrypted_finish = q;

                // encrypt the per-packet packet written with the prefix byte, protocol id and version as the associated data. this must match to decrypt.

                var additional_data = new byte[VERSION_INFO_BYTES + 8 + 1];
                {
                    var p2 = 0;
                    write_bytes(additional_data, ref p2, VERSION_INFO, VERSION_INFO_BYTES);
                    write_uint64(additional_data, ref p2, protocol_id);
                    write_uint8(additional_data, ref p2, prefix_byte);
                }

                var nonce = new byte[12];
                {
                    var p2 = 0;
                    write_uint32(nonce, ref p2, 0);
                    write_uint64(nonce, ref p2, sequence);
                }
                if (encrypt_aead(
                    buffer, encrypted_start,
                    (ulong)(encrypted_finish - encrypted_start),
                    additional_data, (ulong)additional_data.Length,
                    nonce, write_packet_key) != OK)
                    return ERROR;

                q += MAC_BYTES;

                assert(q <= buffer_length);
                return q;
            }
        }

        internal class netcode_replay_protection_t
        {
            public ulong most_recent_sequence;
            public ulong[] received_packet = new ulong[REPLAY_PROTECTION_BUFFER_SIZE];
        }

        static void replay_protection_reset(netcode_replay_protection_t replay_protection)
        {
            assert(replay_protection != null);
            replay_protection.most_recent_sequence = 0;
            BufferEx.Set(replay_protection.received_packet, 0xFF);
        }

        static bool replay_protection_already_received(netcode_replay_protection_t replay_protection, ulong sequence)
        {
            assert(replay_protection != null);
            // written so it cannot overflow: "sequence + BUFFER_SIZE <= most_recent" wraps for
            // sequence values near UINT64_MAX and falsely rejects them as replays

            if (replay_protection.most_recent_sequence >= REPLAY_PROTECTION_BUFFER_SIZE &&
                sequence <= replay_protection.most_recent_sequence - REPLAY_PROTECTION_BUFFER_SIZE)
                return true;

            var index = (int)(sequence % REPLAY_PROTECTION_BUFFER_SIZE);
            if (replay_protection.received_packet[index] == 0xFFFFFFFFFFFFFFFFL)
                return false;
            if (replay_protection.received_packet[index] >= sequence)
                return true;
            return false;
        }

        static void replay_protection_advance_sequence(netcode_replay_protection_t replay_protection, ulong sequence)
        {
            assert(replay_protection != null);

            if (sequence > replay_protection.most_recent_sequence)
                replay_protection.most_recent_sequence = sequence;

            var index = (int)(sequence % REPLAY_PROTECTION_BUFFER_SIZE);
            replay_protection.received_packet[index] = sequence;
        }

        static object read_packet(
            byte[] buffer,
            int buffer_length,
            out ulong sequence,
            byte[] read_packet_key,
            ulong protocol_id,
            ulong current_timestamp,
            ulong min_connect_token_expire_timestamp,
            byte[] private_key,
            bool[] allowed_packets,
            netcode_replay_protection_t replay_protection,
            object allocator_context,
            Func<object, ulong, object> allocate_function)
        {
            assert(allowed_packets != null);

            sequence = 0;
            if (allocate_function == null)
                allocate_function = default_allocate_function;

            if (buffer_length < 1)
            {
                printf(LOG_LEVEL_DEBUG, "ignored packet. buffer length is less than 1\n");
                return null;
            }

            var p = 0;
            var prefix_byte = read_uint8(buffer, ref p);

            if (prefix_byte == CONNECTION_REQUEST_PACKET)
            {
                // connection request packet: first byte is zero
                if (!allowed_packets[CONNECTION_REQUEST_PACKET])
                {
                    printf(LOG_LEVEL_DEBUG, "ignored connection request packet. packet type is not allowed\n");
                    return null;
                }
                if (buffer_length != 1 + VERSION_INFO_BYTES + 8 + 8 + CONNECT_TOKEN_NONCE_BYTES + CONNECT_TOKEN_PRIVATE_BYTES)
                {
                    printf(LOG_LEVEL_DEBUG, $"ignored connection request packet. bad packet length (expected {1 + VERSION_INFO_BYTES + 8 + 8 + CONNECT_TOKEN_NONCE_BYTES + CONNECT_TOKEN_PRIVATE_BYTES}, got {buffer_length})\n");
                    return null;
                }
                if (private_key == null)
                {
                    printf(LOG_LEVEL_DEBUG, "ignored connection request packet. no private key\n");
                    return null;
                }

                var version_info = new byte[VERSION_INFO_BYTES];
                read_bytes(buffer, ref p, version_info, VERSION_INFO_BYTES);
                if (version_info[0] != 'N' ||
                     version_info[1] != 'E' ||
                     version_info[2] != 'T' ||
                     version_info[3] != 'C' ||
                     version_info[4] != 'O' ||
                     version_info[5] != 'D' ||
                     version_info[6] != 'E' ||
                     version_info[7] != ' ' ||
                     version_info[8] != '1' ||
                     version_info[9] != '.' ||
                     version_info[10] != '0' ||
                     version_info[11] != '2' ||
                     version_info[12] != '\0')
                {
                    printf(LOG_LEVEL_DEBUG, "ignored connection request packet. bad version info\n");
                    return null;
                }

                var packet_protocol_id = read_uint64(buffer, ref p);
                if (packet_protocol_id != protocol_id)
                {
                    printf(LOG_LEVEL_DEBUG, $"ignored connection request packet. wrong protocol id. expected {protocol_id:x16}, got {packet_protocol_id:x16}\n");
                    return null;
                }

                var packet_connect_token_expire_timestamp = read_uint64(buffer, ref p);
                if (packet_connect_token_expire_timestamp <= current_timestamp)
                {
                    printf(LOG_LEVEL_DEBUG, "ignored connection request packet. connect token expired\n");
                    return null;
                }

                // a connect token that could have been issued before the server started is refused: its keys
                // were already used to encrypt packets under sequence numbers that start again from zero.

                if (packet_connect_token_expire_timestamp < min_connect_token_expire_timestamp)
                {
                    printf(LOG_LEVEL_DEBUG, "ignored connection request packet. connect token predates the server start\n");
                    return null;
                }

                var packet_connect_token_nonce = new byte[CONNECT_TOKEN_NONCE_BYTES];
                read_bytes(buffer, ref p, packet_connect_token_nonce, packet_connect_token_nonce.Length);

                assert(p == 1 + VERSION_INFO_BYTES + 8 + 8 + CONNECT_TOKEN_NONCE_BYTES);

                if (decrypt_connect_token_private(
                    buffer, p,
                    CONNECT_TOKEN_PRIVATE_BYTES,
                    version_info,
                    protocol_id,
                    packet_connect_token_expire_timestamp,
                    packet_connect_token_nonce,
                    private_key) != OK)
                {
                    printf(LOG_LEVEL_DEBUG, "ignored connection request packet. connect token failed to decrypt\n");
                    return null;
                }

                var packet = new connection_request_packet_t();
                if (packet == null)
                {
                    printf(LOG_LEVEL_DEBUG, "ignored connection request packet. failed to allocate packet\n");
                    return null;
                }

                packet.packet_type = CONNECTION_REQUEST_PACKET;
                BufferEx.Copy(packet.version_info, version_info, VERSION_INFO_BYTES);
                packet.protocol_id = packet_protocol_id;
                packet.connect_token_expire_timestamp = packet_connect_token_expire_timestamp;
                BufferEx.Copy(packet.connect_token_nonce, packet_connect_token_nonce, CONNECT_TOKEN_NONCE_BYTES);
                read_bytes(buffer, ref p, packet.connect_token_data, CONNECT_TOKEN_PRIVATE_BYTES);

                assert(p == 1 + VERSION_INFO_BYTES + 8 + 8 + CONNECT_TOKEN_NONCE_BYTES + CONNECT_TOKEN_PRIVATE_BYTES);
                return packet;
            }
            else
            {
                // *** encrypted packets ***

                if (read_packet_key == null)
                {
                    printf(LOG_LEVEL_DEBUG, "ignored encrypted packet. no read packet key for this address\n");
                    return null;
                }
                if (buffer_length < 1 + 1 + MAC_BYTES)
                {
                    printf(LOG_LEVEL_DEBUG, $"ignored encrypted packet. packet is too small to be valid ({buffer_length} bytes)\n");
                    return null;
                }
                // extract the packet type and number of sequence bytes from the prefix byte
                var packet_type = prefix_byte & 0xF;
                if (packet_type >= CONNECTION_NUM_PACKETS)
                {
                    printf(LOG_LEVEL_DEBUG, $"ignored encrypted packet. packet type {packet_type} is invalid\n");
                    return null;
                }
                if (!allowed_packets[packet_type])
                {
                    printf(LOG_LEVEL_DEBUG, $"ignored encrypted packet. packet type {packet_type} is not allowed\n");
                    return null;
                }
                var sequence_bytes = prefix_byte >> 4;
                if (sequence_bytes < 1 || sequence_bytes > 8)
                {
                    printf(LOG_LEVEL_DEBUG, $"ignored encrypted packet. sequence bytes {sequence_bytes} is out of range [1,8]\n");
                    return null;
                }
                if (buffer_length < 1 + sequence_bytes + MAC_BYTES)
                {
                    printf(LOG_LEVEL_DEBUG, "ignored encrypted packet. buffer is too small for sequence bytes + encryption mac\n");
                    return null;
                }

                // read variable length sequence number [1,8]

                int i;
                for (i = 0; i < sequence_bytes; ++i)
                {
                    var value = read_uint8(buffer, ref p);
                    sequence |= (ulong)(value) << (8 * i);
                }

                // ignore the packet if it has already been received

                if (replay_protection != null && packet_type >= CONNECTION_KEEP_ALIVE_PACKET)
                    if (replay_protection_already_received(replay_protection, sequence))
                    {
                        printf(LOG_LEVEL_DEBUG, $"ignored packet. sequence {sequence:x16} already received (replay protection)\n");
                        return null;
                    }

                // decrypt the per-packet type data

                var additional_data = new byte[VERSION_INFO_BYTES + 8 + 1];
                {
                    var p2 = 0;
                    write_bytes(additional_data, ref p2, VERSION_INFO, VERSION_INFO_BYTES);
                    write_uint64(additional_data, ref p2, protocol_id);
                    write_uint8(additional_data, ref p2, prefix_byte);
                }

                var nonce = new byte[12];
                {
                    var p2 = 0;
                    write_uint32(nonce, ref p2, 0);
                    write_uint64(nonce, ref p2, sequence);
                }

                var encrypted_bytes = buffer_length - p;
                if (encrypted_bytes < MAC_BYTES)
                {
                    printf(LOG_LEVEL_DEBUG, "ignored encrypted packet. encrypted payload is too small\n");
                    return null;
                }

                if (decrypt_aead(buffer, p, (ulong)encrypted_bytes, additional_data, (ulong)additional_data.Length, nonce, read_packet_key) != OK)
                {
                    printf(LOG_LEVEL_DEBUG, "ignored encrypted packet. failed to decrypt\n");
                    return null;
                }

                var decrypted_bytes = encrypted_bytes - MAC_BYTES;

                // update the latest replay protection sequence #

                if (replay_protection != null && packet_type >= CONNECTION_KEEP_ALIVE_PACKET)
                    replay_protection_advance_sequence(replay_protection, sequence);

                // process the per-packet type data that was just decrypted

                switch (packet_type)
                {
                    case CONNECTION_DENIED_PACKET:
                        {
                            if (decrypted_bytes != 0)
                            {
                                printf(LOG_LEVEL_DEBUG, "ignored connection denied packet. decrypted packet data is wrong size\n");
                                return null;
                            }
                            var packet = new connection_denied_packet_t();
                            if (packet == null)
                            {
                                printf(LOG_LEVEL_DEBUG, "ignored connection denied packet. could not allocate packet struct\n");
                                return null;
                            }
                            packet.packet_type = CONNECTION_DENIED_PACKET;
                            return packet;
                        }

                    case CONNECTION_CHALLENGE_PACKET:
                        {
                            if (decrypted_bytes != 8 + CHALLENGE_TOKEN_BYTES)
                            {
                                printf(LOG_LEVEL_DEBUG, "ignored connection challenge packet. decrypted packet data is wrong size\n");
                                return null;
                            }
                            var packet = new connection_challenge_packet_t();
                            if (packet == null)
                            {
                                printf(LOG_LEVEL_DEBUG, "ignored connection challenge packet. could not allocate packet struct\n");
                                return null;
                            }
                            packet.packet_type = CONNECTION_CHALLENGE_PACKET;
                            packet.challenge_token_sequence = read_uint64(buffer, ref p);
                            read_bytes(buffer, ref p, packet.challenge_token_data, CHALLENGE_TOKEN_BYTES);
                            return packet;
                        }

                    case CONNECTION_RESPONSE_PACKET:
                        {
                            if (decrypted_bytes != 8 + CHALLENGE_TOKEN_BYTES)
                            {
                                printf(LOG_LEVEL_DEBUG, "ignored connection response packet. decrypted packet data is wrong size\n");
                                return null;
                            }
                            var packet = new connection_response_packet_t();
                            if (packet == null)
                            {
                                printf(LOG_LEVEL_DEBUG, "ignored connection response packet. could not allocate packet struct\n");
                                return null;
                            }
                            packet.packet_type = CONNECTION_RESPONSE_PACKET;
                            packet.challenge_token_sequence = read_uint64(buffer, ref p);
                            read_bytes(buffer, ref p, packet.challenge_token_data, CHALLENGE_TOKEN_BYTES);
                            return packet;
                        }

                    case CONNECTION_KEEP_ALIVE_PACKET:
                        {
                            if (decrypted_bytes != 8)
                            {
                                printf(LOG_LEVEL_DEBUG, "ignored connection keep alive packet. decrypted packet data is wrong size\n");
                                return null;
                            }
                            var packet = new connection_keep_alive_packet_t();
                            if (packet == null)
                            {
                                printf(LOG_LEVEL_DEBUG, "ignored connection keep alive packet. could not allocate packet struct\n");
                                return null;
                            }
                            packet.packet_type = CONNECTION_KEEP_ALIVE_PACKET;
                            packet.client_index = (int)read_uint32(buffer, ref p);
                            packet.max_clients = (int)read_uint32(buffer, ref p);
                            return packet;
                        }

                    case CONNECTION_PAYLOAD_PACKET:
                        {
                            if (decrypted_bytes < 1)
                            {
                                printf(LOG_LEVEL_DEBUG, "ignored connection payload packet. payload is too small\n");
                                return null;
                            }
                            if (decrypted_bytes > MAX_PAYLOAD_BYTES)
                            {
                                printf(LOG_LEVEL_DEBUG, "ignored connection payload packet. payload is too large\n");
                                return null;
                            }
                            var packet = create_payload_packet(decrypted_bytes, allocator_context, allocate_function);
                            if (packet == null)
                            {
                                printf(LOG_LEVEL_DEBUG, "ignored connection payload packet. could not allocate packet struct\n");
                                return null;
                            }
                            BufferEx.Copy(packet.payload_data, 0, buffer, p, decrypted_bytes);
                            return packet;
                        }

                    case CONNECTION_DISCONNECT_PACKET:
                        {
                            if (decrypted_bytes != 0)
                            {
                                printf(LOG_LEVEL_DEBUG, "ignored connection disconnect packet. decrypted packet data is wrong size\n");
                                return null;
                            }
                            var packet = new connection_disconnect_packet_t();
                            if (packet == null)
                            {
                                printf(LOG_LEVEL_DEBUG, "ignored connection disconnect packet. could not allocate packet struct\n");
                                return null;
                            }
                            packet.packet_type = CONNECTION_DISCONNECT_PACKET;
                            return packet;
                        }

                    default: return null;
                }
            }
        }

        #endregion

        #region connect_token_t

        internal class connect_token_t
        {
            public byte[] version_info = new byte[VERSION_INFO_BYTES];
            public ulong protocol_id;
            public ulong create_timestamp;
            public ulong expire_timestamp;
            public byte[] nonce = new byte[CONNECT_TOKEN_NONCE_BYTES];
            public byte[] private_data = new byte[CONNECT_TOKEN_PRIVATE_BYTES];
            public int timeout_seconds;
            public int num_server_addresses;
            public netcode_address_t[] server_addresses = BufferEx.NewT<netcode_address_t>(MAX_SERVERS_PER_CONNECT);
            public byte[] client_to_server_key = new byte[KEY_BYTES];
            public byte[] server_to_client_key = new byte[KEY_BYTES];
        }

        static void write_connect_token(connect_token_t connect_token, byte[] buffer, int buffer_length)
        {
            assert(connect_token != null);
            assert(buffer != null);
            assert(buffer_length >= CONNECT_TOKEN_BYTES);

            var p = 0;
            write_bytes(buffer, ref p, connect_token.version_info, VERSION_INFO_BYTES);
            write_uint64(buffer, ref p, connect_token.protocol_id);
            write_uint64(buffer, ref p, connect_token.create_timestamp);
            write_uint64(buffer, ref p, connect_token.expire_timestamp);
            write_bytes(buffer, ref p, connect_token.nonce, CONNECT_TOKEN_NONCE_BYTES);
            write_bytes(buffer, ref p, connect_token.private_data, CONNECT_TOKEN_PRIVATE_BYTES);
            write_uint32(buffer, ref p, (uint)connect_token.timeout_seconds);
            write_uint32(buffer, ref p, (uint)connect_token.num_server_addresses);
            int i;
            for (i = 0; i < connect_token.num_server_addresses; ++i)
                // todo: really just need a function to write an address. too much cut & paste here
                if (connect_token.server_addresses[i].type == ADDRESS_IPV4)
                {
                    write_uint8(buffer, ref p, ADDRESS_IPV4);
                    write_bytes(buffer, ref p, connect_token.server_addresses[i].data.GetAddressBytes(), 4);
                    write_uint16(buffer, ref p, connect_token.server_addresses[i].port);
                }
                else if (connect_token.server_addresses[i].type == ADDRESS_IPV6)
                {
                    write_uint8(buffer, ref p, ADDRESS_IPV6);
                    write_bytes(buffer, ref p, connect_token.server_addresses[i].data.GetAddressBytes(), 16);
                    write_uint16(buffer, ref p, connect_token.server_addresses[i].port);
                }
                else assert(false);
            write_bytes(buffer, ref p, connect_token.client_to_server_key, KEY_BYTES);
            write_bytes(buffer, ref p, connect_token.server_to_client_key, KEY_BYTES);
            assert(p <= CONNECT_TOKEN_BYTES);
            BufferEx.SetWithOffset(buffer, p, 0, CONNECT_TOKEN_BYTES - p);
        }

        static int read_connect_token(byte[] buffer, int buffer_length, connect_token_t connect_token)
        {
            assert(buffer != null);
            assert(connect_token != null);

            if (buffer_length != CONNECT_TOKEN_BYTES)
            {
                printf(LOG_LEVEL_ERROR, $"error: read connect data has bad buffer length ({buffer_length})\n");
                return ERROR;
            }

            var p = 0;
            read_bytes(buffer, ref p, connect_token.version_info, VERSION_INFO_BYTES);
            if (connect_token.version_info[0] != 'N' ||
                 connect_token.version_info[1] != 'E' ||
                 connect_token.version_info[2] != 'T' ||
                 connect_token.version_info[3] != 'C' ||
                 connect_token.version_info[4] != 'O' ||
                 connect_token.version_info[5] != 'D' ||
                 connect_token.version_info[6] != 'E' ||
                 connect_token.version_info[7] != ' ' ||
                 connect_token.version_info[8] != '1' ||
                 connect_token.version_info[9] != '.' ||
                 connect_token.version_info[10] != '0' ||
                 connect_token.version_info[11] != '2' ||
                 connect_token.version_info[12] != '\0')
            {
                connect_token.version_info[12] = 0;
                printf(LOG_LEVEL_ERROR, $"error: read connect data has bad version info (got {Encoding.ASCII.GetString(connect_token.version_info, 0, VERSION_INFO_BYTES - 1)}, expected {Encoding.ASCII.GetString(VERSION_INFO, 0, VERSION_INFO_BYTES - 1)})\n");
                return ERROR;
            }

            connect_token.protocol_id = read_uint64(buffer, ref p);
            connect_token.create_timestamp = read_uint64(buffer, ref p);
            connect_token.expire_timestamp = read_uint64(buffer, ref p);
            if (connect_token.create_timestamp > connect_token.expire_timestamp)
                return ERROR;
            read_bytes(buffer, ref p, connect_token.nonce, CONNECT_TOKEN_NONCE_BYTES);
            read_bytes(buffer, ref p, connect_token.private_data, CONNECT_TOKEN_PRIVATE_BYTES);
            connect_token.timeout_seconds = (int)read_uint32(buffer, ref p);
            connect_token.num_server_addresses = (int)read_uint32(buffer, ref p);
            if (connect_token.num_server_addresses <= 0 || connect_token.num_server_addresses > MAX_SERVERS_PER_CONNECT)
            {
                printf(LOG_LEVEL_ERROR, $"error: read connect data has bad number of server addresses ({connect_token.num_server_addresses})\n");
                return ERROR;
            }
            int i;
            for (i = 0; i < connect_token.num_server_addresses; ++i)
            {
                // todo: really need a function to read an address
                connect_token.server_addresses[i].type = read_uint8(buffer, ref p);

                if (connect_token.server_addresses[i].type == ADDRESS_IPV4)
                {
                    var buf = new byte[4];
                    connect_token.server_addresses[i].data = new IPAddress(read_bytes(buffer, ref p, buf, 4));
                    connect_token.server_addresses[i].port = read_uint16(buffer, ref p);
                }
                else if (connect_token.server_addresses[i].type == ADDRESS_IPV6)
                {
                    var buf = new byte[16];
                    connect_token.server_addresses[i].data = new IPAddress(read_bytes(buffer, ref p, buf, 16));
                    connect_token.server_addresses[i].port = read_uint16(buffer, ref p);
                }
                else
                {
                    printf(LOG_LEVEL_ERROR, $"error: read connect data has bad address type ({connect_token.server_addresses[i].type})\n");
                    return ERROR;
                }
            }
            read_bytes(buffer, ref p, connect_token.client_to_server_key, KEY_BYTES);
            read_bytes(buffer, ref p, connect_token.server_to_client_key, KEY_BYTES);
            return OK;
        }

        #endregion

        #region packet_queue_t

        internal class packet_queue_t
        {
            public object allocator_context;
            public Func<object, ulong, object> allocate_function;
            public Action<object, object> free_function;
            public int num_packets;
            public int start_index;
            public object[] packet_data = new object[PACKET_QUEUE_SIZE];
            public ulong[] packet_sequence = new ulong[PACKET_QUEUE_SIZE];
        }

        static void packet_queue_init(packet_queue_t queue, object allocator_context, Func<object, ulong, object> allocate_function, Action<object, object> free_function)
        {
            assert(queue != null);
            if (allocate_function == null)
                allocate_function = default_allocate_function;
            if (free_function == null)
                free_function = default_free_function;
            queue.allocator_context = allocator_context;
            queue.allocate_function = allocate_function;
            queue.free_function = free_function;
            queue.num_packets = 0;
            queue.start_index = 0;
            BufferEx.SetT(queue.packet_data, null);
            BufferEx.Set(queue.packet_sequence, 0);
        }


        static bool packet_queue_push<T>(packet_queue_t queue, ref T packet_data, ulong packet_sequence)
        {
            assert(queue != null);
            assert(packet_data != null);
            if (queue.num_packets == PACKET_QUEUE_SIZE)
            {
                packet_data = default(T);
                return false;
            }
            var index = (queue.start_index + queue.num_packets) % PACKET_QUEUE_SIZE;
            queue.packet_data[index] = packet_data;
            queue.packet_sequence[index] = packet_sequence;
            queue.num_packets++;
            return true;
        }

        static object packet_queue_pop(packet_queue_t queue, out ulong packet_sequence)
        {
            if (queue.num_packets == 0)
            {
                packet_sequence = 0;
                return null;
            }
            var packet = queue.packet_data[queue.start_index];
            packet_sequence = queue.packet_sequence[queue.start_index];
            queue.start_index = (queue.start_index + 1) % PACKET_QUEUE_SIZE;
            queue.num_packets--;
            return packet;
        }

        static void packet_queue_clear(packet_queue_t queue)
        {
            assert(queue != null);
            while (queue.num_packets > 0)
                queue.free_function?.Invoke(queue.allocator_context, packet_queue_pop(queue, out _));
            queue.start_index = 0;
            BufferEx.SetT(queue.packet_data, null);
            BufferEx.Set(queue.packet_sequence, 0);
        }

        #endregion

        #region network_simulator_t

        internal const int NETWORK_SIMULATOR_NUM_PACKET_ENTRIES = MAX_CLIENTS * 256;
        internal const int NETWORK_SIMULATOR_NUM_PENDING_RECEIVE_PACKETS = MAX_CLIENTS * 64;
        internal const ulong NETWORK_SIMULATOR_RNG_SEED = 0x9E3779B97F4A7C15UL;

        internal struct network_simulator_packet_entry_t
        {
            public netcode_address_t from;
            public netcode_address_t to;
            public double delivery_time;
            public byte[] packet_data;
            public int packet_bytes;
        }
    }

    public class netcode_network_simulator_t
    {
        internal object allocator_context;
        internal Func<object, ulong, object> allocate_function;
        internal Action<object, object> free_function;
        internal float latency_milliseconds;
        internal float jitter_milliseconds;
        internal float packet_loss_percent;
        internal float duplicate_packet_percent;
        internal ulong rng_state;
        internal double time;
        internal int current_index;
        internal int num_pending_receive_packets;
        internal netcode.network_simulator_packet_entry_t[] packet_entries = new netcode.network_simulator_packet_entry_t[netcode.NETWORK_SIMULATOR_NUM_PACKET_ENTRIES];
        internal netcode.network_simulator_packet_entry_t[] pending_receive_packets = new netcode.network_simulator_packet_entry_t[netcode.NETWORK_SIMULATOR_NUM_PENDING_RECEIVE_PACKETS];
    }

    static partial class netcode
    {
        static netcode_network_simulator_t network_simulator_create(object allocator_context, Func<object, ulong, object> allocate_function, Action<object, object> free_function)
        {
            if (allocate_function == null)
                allocate_function = default_allocate_function;

            if (free_function == null)
                free_function = default_free_function;

            var network_simulator = new netcode_network_simulator_t();

            assert(network_simulator != null);

            network_simulator.allocator_context = allocator_context;
            network_simulator.allocate_function = allocate_function;
            network_simulator.free_function = free_function;
            network_simulator.rng_state = NETWORK_SIMULATOR_RNG_SEED;
            return network_simulator;
        }

        static void network_simulator_reset(netcode_network_simulator_t network_simulator)
        {
            assert(network_simulator != null);

            printf(LOG_LEVEL_DEBUG, "network simulator reset\n");

            int i;
            for (i = 0; i < NETWORK_SIMULATOR_NUM_PACKET_ENTRIES; ++i)
            {
                network_simulator.packet_entries[i].packet_data = null;
                BufferEx.SetT(ref network_simulator.packet_entries[i], 0);
            }
            for (i = 0; i < network_simulator.num_pending_receive_packets; ++i)
            {
                network_simulator.pending_receive_packets[i].packet_data = null;
                BufferEx.SetT(ref network_simulator.pending_receive_packets[i], 0);
            }
            network_simulator.current_index = 0;
            network_simulator.num_pending_receive_packets = 0;
            network_simulator.rng_state = NETWORK_SIMULATOR_RNG_SEED;
        }

        static void network_simulator_destroy(ref netcode_network_simulator_t network_simulator)
        {
            assert(network_simulator != null);
            network_simulator_reset(network_simulator);
            network_simulator = null;
        }

        static ulong network_simulator_random_uint64(netcode_network_simulator_t network_simulator)
        {
            // xorshift64*. self-contained and deterministic: the simulator produces the same loss, jitter
            // and duplication sequence on every run, and shares no state with the application or other
            // simulator instances.

            var x = network_simulator.rng_state;
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            network_simulator.rng_state = x;
            return unchecked(x * 0x2545F4914F6CDD1DUL);
        }

        static float network_simulator_random_float(netcode_network_simulator_t network_simulator, float a, float b)
        {
            assert(a < b);
            var random = (float)(network_simulator_random_uint64(network_simulator) >> 40) / (float)(1 << 24);
            return a + random * (b - a);
        }

        static void network_simulator_queue_packet(
            netcode_network_simulator_t network_simulator,
            netcode_address_t from,
            netcode_address_t to,
            byte[] packet_data,
            int packet_bytes,
            float delay)
        {
            network_simulator.packet_entries[network_simulator.current_index].from = address_copy(from);
            network_simulator.packet_entries[network_simulator.current_index].to = address_copy(to);
            network_simulator.packet_entries[network_simulator.current_index].packet_data = new byte[packet_bytes];
            BufferEx.Copy(network_simulator.packet_entries[network_simulator.current_index].packet_data, packet_data, packet_bytes);
            network_simulator.packet_entries[network_simulator.current_index].packet_bytes = packet_bytes;
            network_simulator.packet_entries[network_simulator.current_index].delivery_time = network_simulator.time + delay;
            network_simulator.current_index++;
            network_simulator.current_index %= NETWORK_SIMULATOR_NUM_PACKET_ENTRIES;
        }

        static void network_simulator_send_packet(
            netcode_network_simulator_t network_simulator,
            netcode_address_t from,
            netcode_address_t to,
            byte[] packet_data,
            int packet_bytes)
        {
            assert(network_simulator != null);
            assert(from != null);
            assert(from.type != 0);
            assert(to != null);
            assert(to.type != 0);
            assert(packet_data != null);
            assert(packet_bytes > 0);
            assert(packet_bytes <= MAX_PACKET_BYTES);

            if (network_simulator_random_float(network_simulator, 0.0f, 100.0f) <= network_simulator.packet_loss_percent)
                return;

            var delay = network_simulator.latency_milliseconds / 1000.0f;

            if (network_simulator.jitter_milliseconds > 0.0)
                delay += network_simulator_random_float(network_simulator, -network_simulator.jitter_milliseconds, +network_simulator.jitter_milliseconds) / 1000.0f;

            network_simulator_queue_packet(network_simulator, from, to, packet_data, packet_bytes, delay);

            if (network_simulator_random_float(network_simulator, 0.0f, 100.0f) <= network_simulator.duplicate_packet_percent)
                network_simulator_queue_packet(network_simulator, from, to, packet_data, packet_bytes, delay + network_simulator_random_float(network_simulator, 0, 1.0f));
        }

        static int network_simulator_receive_packets(
            netcode_network_simulator_t network_simulator,
            netcode_address_t to,
            int max_packets,
            byte[][] packet_data,
            int[] packet_bytes,
            netcode_address_t[] from)
        {
            assert(network_simulator != null);
            assert(max_packets >= 0);
            assert(packet_data != null);
            assert(packet_bytes != null);
            assert(from != null);
            assert(to != null);

            var num_packets = 0;

            int i;
            for (i = 0; i < network_simulator.num_pending_receive_packets; ++i)
            {
                if (num_packets == max_packets)
                    break;
                if (network_simulator.pending_receive_packets[i].packet_data == null)
                    continue;
                if (!address_equal(network_simulator.pending_receive_packets[i].to, to))
                    continue;
                packet_data[num_packets] = network_simulator.pending_receive_packets[i].packet_data;
                packet_bytes[num_packets] = network_simulator.pending_receive_packets[i].packet_bytes;
                from[num_packets] = network_simulator.pending_receive_packets[i].from;

                network_simulator.pending_receive_packets[i].packet_data = null;

                num_packets++;
            }

            assert(num_packets <= max_packets);
            return num_packets;
        }

        static void network_simulator_update(netcode_network_simulator_t network_simulator, double time)
        {
            assert(network_simulator != null);

            network_simulator.time = time;

            // discard any pending receive packets that are still in the buffer

            int i;
            for (i = 0; i < network_simulator.num_pending_receive_packets; ++i)
                if (network_simulator.pending_receive_packets[i].packet_data != null)
                    network_simulator.pending_receive_packets[i].packet_data = null;
            network_simulator.num_pending_receive_packets = 0;

            // walk across packet entries and move any that are ready to be received into the pending receive buffer

            for (i = 0; i < NETWORK_SIMULATOR_NUM_PACKET_ENTRIES; ++i)
            {
                if (network_simulator.packet_entries[i].packet_data == null)
                    continue;
                if (network_simulator.num_pending_receive_packets == NETWORK_SIMULATOR_NUM_PENDING_RECEIVE_PACKETS)
                    break;
                if (network_simulator.packet_entries[i].packet_data != null && network_simulator.packet_entries[i].delivery_time <= time)
                {
                    network_simulator.pending_receive_packets[network_simulator.num_pending_receive_packets] = network_simulator.packet_entries[i];
                    network_simulator.num_pending_receive_packets++;
                    network_simulator.packet_entries[i].packet_data = null;
                }
            }
        }

        #endregion

        #region netcode_client_t

        static string client_state_name(int client_state)
        {
            switch (client_state)
            {
                case CLIENT_STATE_CONNECT_TOKEN_EXPIRED: return "connect token expired";
                case CLIENT_STATE_INVALID_CONNECT_TOKEN: return "invalid connect token";
                case CLIENT_STATE_CONNECTION_TIMED_OUT: return "connection timed out";
                case CLIENT_STATE_CONNECTION_REQUEST_TIMED_OUT: return "connection request timed out";
                case CLIENT_STATE_CONNECTION_RESPONSE_TIMED_OUT: return "connection response timed out";
                case CLIENT_STATE_CONNECTION_DENIED: return "connection denied";
                case CLIENT_STATE_DISCONNECTED: return "disconnected";
                case CLIENT_STATE_SENDING_CONNECTION_REQUEST: return "sending connection request";
                case CLIENT_STATE_SENDING_CONNECTION_RESPONSE: return "sending connection response";
                case CLIENT_STATE_CONNECTED: return "connected";
                default: assert(false); return "???";
            }
        }

        public static void default_client_config(out netcode_client_config_t config) =>
            //: assert(config != null);
            config = new netcode_client_config_t
            {
                allocator_context = null,
                allocate_function = default_allocate_function,
                free_function = default_free_function,
                network_simulator = null,
                callback_context = null,
                state_change_callback = null,
                send_loopback_packet_callback = null,
                override_send_and_receive = false,
                send_packet_override = null,
                receive_packet_override = null
            };
    }

    public class netcode_client_t
    {
        internal netcode_client_config_t config;
        internal int state;
        internal double time;
        internal double connect_start_time;
        internal double last_packet_send_time;
        internal double last_packet_receive_time;
        internal bool should_disconnect;
        internal int should_disconnect_state;
        internal ulong sequence;
        internal int client_index;
        internal int max_clients;
        internal int server_address_index;
        internal netcode_address_t address;
        internal netcode_address_t server_address;
        internal netcode.connect_token_t connect_token;
        internal netcode.socket_holder_t socket_holder = new netcode.socket_holder_t();
        internal netcode.context_t context;
        internal netcode.netcode_replay_protection_t replay_protection = new netcode.netcode_replay_protection_t();
        internal netcode.packet_queue_t packet_receive_queue = new netcode.packet_queue_t();
        internal ulong challenge_token_sequence;
        internal byte[] challenge_token_data = new byte[netcode.CHALLENGE_TOKEN_BYTES];
        internal byte[][] receive_packet_data = new byte[netcode.CLIENT_MAX_RECEIVE_PACKETS][];
        internal int[] receive_packet_bytes = new int[netcode.CLIENT_MAX_RECEIVE_PACKETS];
        internal netcode_address_t[] receive_from = new netcode_address_t[netcode.CLIENT_MAX_RECEIVE_PACKETS];
        internal bool loopback;
    }

    static partial class netcode
    {
        static int client_create_error_;

        /*
            If client_create or client_create_dual returns null, call this to find out why.
            Returns the CLIENT_CREATE_ERROR_* value from the most recent client create call,
            or CLIENT_CREATE_ERROR_NONE if that call succeeded.
        */

        public static int client_create_error() => client_create_error_;

        static bool client_socket_create(ref socket_t socket, netcode_address_t address, int send_buffer_size, int receive_buffer_size, netcode_client_config_t config)
        {
            assert(socket != null);
            assert(address != null);
            assert(config != null);

            if (config.network_simulator == null)
            {
                if (!config.override_send_and_receive)
                    if (socket_create(ref socket, address, send_buffer_size, receive_buffer_size) != SOCKET_ERROR_NONE)
                    {
                        client_create_error_ = address.type == ADDRESS_IPV6 ? CLIENT_CREATE_ERROR_CREATE_SOCKET_IPV6_FAILED : CLIENT_CREATE_ERROR_CREATE_SOCKET_IPV4_FAILED;
                        return false;
                    }
            }
            else if (address.port == 0)
            {
                printf(LOG_LEVEL_ERROR, "error: must bind to a specific port when using network simulator\n");
                client_create_error_ = CLIENT_CREATE_ERROR_SIMULATOR_REQUIRES_PORT;
                return false;
            }
            return true;
        }

        public static netcode_client_t client_create_dual(string address1_string, string address2_string, netcode_client_config_t config, double time)
        {
            assert(config != null);
            assert(netcode_.initialized != 0);

            client_create_error_ = CLIENT_CREATE_ERROR_NONE;

            // tolerate a zeroed config: default the allocator functions so a forgotten
            // default_client_config is an inconvenience, not a crash. the client keeps its own copy.

            config = config.copy();
            if (config.allocate_function == null)
                config.allocate_function = default_allocate_function;
            if (config.free_function == null)
                config.free_function = default_free_function;

            // the overrides are called on the update path with no null check. a missing one is a
            // configuration error, refused here rather than dereferenced on the first update.

            if (config.override_send_and_receive && (config.send_packet_override == null || config.receive_packet_override == null))
            {
                printf(LOG_LEVEL_ERROR, "error: override_send_and_receive requires both send_packet_override and receive_packet_override\n");
                client_create_error_ = CLIENT_CREATE_ERROR_MISSING_OVERRIDE_CALLBACK;
                return null;
            }

            if (parse_address(address1_string, out var address1) != OK)
            {
                printf(LOG_LEVEL_ERROR, "error: failed to parse client address\n");
                client_create_error_ = CLIENT_CREATE_ERROR_PARSE_ADDRESS_FAILED;
                return null;
            }
            var address2 = new netcode_address_t();
            if (address2_string != null && parse_address(address2_string, out address2) != OK)
            {
                printf(LOG_LEVEL_ERROR, "error: failed to parse client address2\n");
                client_create_error_ = CLIENT_CREATE_ERROR_PARSE_ADDRESS2_FAILED;
                return null;
            }

            var socket_ipv4 = new socket_t();
            var socket_ipv6 = new socket_t();
            if (address1.type == ADDRESS_IPV4 || address2.type == ADDRESS_IPV4)
            {
                if (!client_socket_create(ref socket_ipv4, address1.type == ADDRESS_IPV4 ? address1 : address2, CLIENT_SOCKET_SNDBUF_SIZE, CLIENT_SOCKET_RCVBUF_SIZE, config))
                    return null;
            }
            if (address1.type == ADDRESS_IPV6 || address2.type == ADDRESS_IPV6)
            {
                if (!client_socket_create(ref socket_ipv6, address1.type == ADDRESS_IPV6 ? address1 : address2, CLIENT_SOCKET_SNDBUF_SIZE, CLIENT_SOCKET_RCVBUF_SIZE, config))
                {
                    socket_destroy(ref socket_ipv4);
                    return null;
                }
            }

            // managed allocation does not fail by returning null, so CLIENT_CREATE_ERROR_ALLOCATE_CLIENT_FAILED is never reported

            var client = new netcode_client_t();

            var socket_address = address1.type == ADDRESS_IPV4 ? socket_ipv4.address : socket_ipv6.address;

            if (config.network_simulator == null)
                printf(LOG_LEVEL_INFO, $"client started on port {socket_address.port}\n");
            else
                printf(LOG_LEVEL_INFO, $"client started on port {socket_address.port} (network simulator)\n");

            client.config = config;
            client.socket_holder.ipv4 = socket_ipv4;
            client.socket_holder.ipv6 = socket_ipv6;
            client.address = address_copy(config.network_simulator != null ? address1 : socket_address);
            client.state = CLIENT_STATE_DISCONNECTED;
            client.time = time;
            client.connect_start_time = 0.0;
            client.last_packet_send_time = -1000.0;
            client.last_packet_receive_time = -1000.0;
            client.should_disconnect = false;
            client.should_disconnect_state = CLIENT_STATE_DISCONNECTED;
            client.sequence = 0;
            client.client_index = 0;
            client.max_clients = 0;
            client.server_address_index = 0;
            client.challenge_token_sequence = 0;
            client.loopback = false;
            BufferEx.SetT(ref client.server_address, 0);
            BufferEx.SetT(ref client.connect_token, 0);
            BufferEx.SetT(ref client.context, 0);
            BufferEx.Set(client.challenge_token_data, 0, CHALLENGE_TOKEN_BYTES);

            packet_queue_init(client.packet_receive_queue, config.allocator_context, config.allocate_function, config.free_function);

            replay_protection_reset(client.replay_protection);

            return client;
        }

        public static netcode_client_t client_create(string address, netcode_client_config_t config, double time) =>
            client_create_dual(address, null, config, time);

        public static void client_destroy(ref netcode_client_t client)
        {
            assert(client != null);
            if (!client.loopback) client_disconnect(client);
            else client_disconnect_loopback(client);
            socket_destroy(ref client.socket_holder.ipv4);
            socket_destroy(ref client.socket_holder.ipv6);
            packet_queue_clear(client.packet_receive_queue);
            client = null;
        }

        static void client_set_state(netcode_client_t client, int client_state)
        {
            printf(LOG_LEVEL_DEBUG, $"client changed state from '{client_state_name(client.state)}' to '{client_state_name(client_state) }'\n");
            client.config.state_change_callback?.Invoke(client.config.callback_context, client.state, client_state);
            client.state = client_state;
        }

        static void client_reset_before_next_connect(netcode_client_t client)
        {
            client.connect_start_time = client.time;
            client.last_packet_send_time = client.time - 1.0f;
            client.last_packet_receive_time = client.time;
            client.should_disconnect = false;
            client.should_disconnect_state = CLIENT_STATE_DISCONNECTED;
            client.challenge_token_sequence = 0;

            BufferEx.Set(client.challenge_token_data, 0, CHALLENGE_TOKEN_BYTES);

            replay_protection_reset(client.replay_protection);
        }

        // key material is erased before the objects holding it are dropped (sodium_memzero in C)
        static void client_erase_keys(netcode_client_t client)
        {
            if (client.connect_token != null)
            {
                CryptographicOperations.ZeroMemory(client.connect_token.client_to_server_key);
                CryptographicOperations.ZeroMemory(client.connect_token.server_to_client_key);
                CryptographicOperations.ZeroMemory(client.connect_token.private_data);
            }
            if (client.context != null)
            {
                CryptographicOperations.ZeroMemory(client.context.read_packet_key);
                CryptographicOperations.ZeroMemory(client.context.write_packet_key);
            }
        }

        static void client_reset_connection_data(netcode_client_t client, int client_state)
        {
            assert(client != null);

            client.sequence = 0;
            client.loopback = false;
            client.client_index = 0;
            client.max_clients = 0;
            client.connect_start_time = 0.0;
            client.server_address_index = 0;
            BufferEx.SetT(ref client.server_address, 0);
            client_erase_keys(client);
            BufferEx.SetT(ref client.connect_token, 0);
            BufferEx.SetT(ref client.context, 0);

            client_set_state(client, client_state);

            client_reset_before_next_connect(client);

            packet_queue_clear(client.packet_receive_queue);
        }

        public static void client_connect(this netcode_client_t client, byte[] connect_token)
        {
            assert(client != null);
            assert(connect_token != null);

            client_disconnect(client);

            if (read_connect_token(connect_token, CONNECT_TOKEN_BYTES, client.connect_token) != OK)
            {
                client_set_state(client, CLIENT_STATE_INVALID_CONNECT_TOKEN);
                return;
            }

            client.server_address_index = 0;
            client.server_address = address_copy(client.connect_token.server_addresses[0]);

            if (client.connect_token.num_server_addresses == 1)
                printf(LOG_LEVEL_INFO, $"client connecting to server {address_to_string(client.server_address)}\n");
            else
                printf(LOG_LEVEL_INFO, $"client connecting to server {address_to_string(client.server_address)} [{client.server_address_index + 1}/{client.connect_token.num_server_addresses}]\n");

            BufferEx.Copy(client.context.read_packet_key, client.connect_token.server_to_client_key, KEY_BYTES);
            BufferEx.Copy(client.context.write_packet_key, client.connect_token.client_to_server_key, KEY_BYTES);

            client_reset_before_next_connect(client);

            client_set_state(client, CLIENT_STATE_SENDING_CONNECTION_REQUEST);
        }

        static void client_process_packet_internal(netcode_client_t client, netcode_address_t from, object packet, ulong sequence)
        {
            assert(client != null);
            assert(packet != null);

            var packet_type = ((base_request_packet_t)packet).packet_type;
            switch (packet_type)
            {
                case CONNECTION_DENIED_PACKET:
                    {
                        if ((client.state == CLIENT_STATE_SENDING_CONNECTION_REQUEST || client.state == CLIENT_STATE_SENDING_CONNECTION_RESPONSE) && address_equal(from, client.server_address))
                        {
                            client.should_disconnect = true;
                            client.should_disconnect_state = CLIENT_STATE_CONNECTION_DENIED;
                            client.last_packet_receive_time = client.time;
                        }
                    }
                    break;

                case CONNECTION_CHALLENGE_PACKET:
                    {
                        if (client.state == CLIENT_STATE_SENDING_CONNECTION_REQUEST && address_equal(from, client.server_address))
                        {
                            printf(LOG_LEVEL_DEBUG, "client received connection challenge packet from server\n");

                            var p = (connection_challenge_packet_t)packet;
                            client.challenge_token_sequence = p.challenge_token_sequence;
                            BufferEx.Copy(client.challenge_token_data, p.challenge_token_data, CHALLENGE_TOKEN_BYTES);
                            client.last_packet_receive_time = client.time;

                            client_set_state(client, CLIENT_STATE_SENDING_CONNECTION_RESPONSE);
                        }
                    }
                    break;

                case CONNECTION_KEEP_ALIVE_PACKET:
                    {
                        if (address_equal(from, client.server_address))
                        {
                            var p = (connection_keep_alive_packet_t)packet;
                            if (client.state == CLIENT_STATE_CONNECTED)
                            {
                                printf(LOG_LEVEL_DEBUG, "client received connection keep alive packet from server\n");

                                client.last_packet_receive_time = client.time;
                            }
                            else if (client.state == CLIENT_STATE_SENDING_CONNECTION_RESPONSE)
                            {
                                printf(LOG_LEVEL_DEBUG, "client received connection keep alive packet from server\n");

                                client.last_packet_receive_time = client.time;
                                client.client_index = p.client_index;
                                client.max_clients = p.max_clients;

                                client_set_state(client, CLIENT_STATE_CONNECTED);

                                printf(LOG_LEVEL_INFO, "client connected to server\n");
                            }
                        }
                    }
                    break;

                case CONNECTION_PAYLOAD_PACKET:
                    {
                        if (client.state == CLIENT_STATE_CONNECTED && address_equal(from, client.server_address))
                        {
                            printf(LOG_LEVEL_DEBUG, "client received connection payload packet from server\n");

                            packet_queue_push(client.packet_receive_queue, ref packet, sequence);

                            client.last_packet_receive_time = client.time;
                            return;
                        }
                    }
                    break;

                case CONNECTION_DISCONNECT_PACKET:
                    {
                        if (client.state == CLIENT_STATE_CONNECTED && address_equal(from, client.server_address))
                        {
                            printf(LOG_LEVEL_DEBUG, "client received disconnect packet from server\n");

                            client.should_disconnect = true;
                            client.should_disconnect_state = CLIENT_STATE_DISCONNECTED;
                            client.last_packet_receive_time = client.time;
                        }
                    }
                    break;

                default: break;
            }

            packet = null;
        }

        static void client_process_packet(netcode_client_t client, netcode_address_t from, byte[] packet_data, int packet_bytes)
        {
            var allowed_packets = new bool[CONNECTION_NUM_PACKETS];
            allowed_packets[CONNECTION_DENIED_PACKET] = true;
            allowed_packets[CONNECTION_CHALLENGE_PACKET] = true;
            allowed_packets[CONNECTION_KEEP_ALIVE_PACKET] = true;
            allowed_packets[CONNECTION_PAYLOAD_PACKET] = true;
            allowed_packets[CONNECTION_DISCONNECT_PACKET] = true;

            var current_timestamp = ctime();

            var packet = read_packet(
                packet_data,
                packet_bytes,
                out var sequence,
                client.context.read_packet_key,
                client.connect_token.protocol_id,
                current_timestamp,
                0,
                null,
                allowed_packets,
                client.replay_protection,
                client.config.allocator_context,
                client.config.allocate_function);

            if (packet == null)
                return;

            client_process_packet_internal(client, from, packet, sequence);
        }

        static void client_receive_packets(netcode_client_t client)
        {
            assert(client != null);
            assert(!client.loopback);

            if (client.config.network_simulator == null)
            {
                // process packets received from socket

                var packet_data = new byte[MAX_PACKET_BYTES];

                while (true)
                {
                    var from = new netcode_address_t();
                    var packet_bytes = 0;

                    if (client.config.override_send_and_receive)
                        packet_bytes = client.config.receive_packet_override(client.config.callback_context, from, packet_data, MAX_PACKET_BYTES);
                    else if (client.server_address.type == ADDRESS_IPV4)
                        packet_bytes = socket_receive_packet(client.socket_holder.ipv4, from, packet_data, MAX_PACKET_BYTES);
                    else if (client.server_address.type == ADDRESS_IPV6)
                        packet_bytes = socket_receive_packet(client.socket_holder.ipv6, from, packet_data, MAX_PACKET_BYTES);

                    if (packet_bytes == 0)
                        break;

                    client_process_packet(client, from, packet_data, packet_bytes);
                }
            }
            else
            {
                // process packets received from network simulator

                var num_packets_received = network_simulator_receive_packets(
                    client.config.network_simulator,
                    client.address,
                    CLIENT_MAX_RECEIVE_PACKETS,
                    client.receive_packet_data,
                    client.receive_packet_bytes,
                    client.receive_from);

                int i;
                for (i = 0; i < num_packets_received; i++)
                {
                    client_process_packet(client, client.receive_from[i], client.receive_packet_data[i], client.receive_packet_bytes[i]);

                    client.receive_packet_data[i] = null;
                }
            }
        }

        static void client_send_packet_to_server_internal(netcode_client_t client, object packet)
        {
            assert(client != null);
            assert(!client.loopback);

            var packet_data = new byte[MAX_PACKET_BYTES];

            var packet_bytes = write_packet(
                packet,
                packet_data,
                MAX_PACKET_BYTES,
                client.sequence++,
                client.context.write_packet_key,
                client.connect_token.protocol_id);

            assert(packet_bytes <= MAX_PACKET_BYTES);

            if (client.config.network_simulator != null)
                network_simulator_send_packet(client.config.network_simulator, client.address, client.server_address, packet_data, packet_bytes);
            else
            {
                if (client.config.override_send_and_receive)
                    client.config.send_packet_override(client.config.callback_context, client.server_address, packet_data, packet_bytes);
                else if (client.server_address.type == ADDRESS_IPV4)
                    socket_send_packet(client.socket_holder.ipv4, client.server_address, packet_data, packet_bytes);
                else if (client.server_address.type == ADDRESS_IPV6)
                    socket_send_packet(client.socket_holder.ipv6, client.server_address, packet_data, packet_bytes);
            }

            client.last_packet_send_time = client.time;
        }

        static void client_send_packets(netcode_client_t client)
        {
            assert(client != null);
            assert(!client.loopback);

            switch (client.state)
            {
                case CLIENT_STATE_SENDING_CONNECTION_REQUEST:
                    {
                        if (client.last_packet_send_time + (1.0 / PACKET_SEND_RATE) >= client.time)
                            return;

                        printf(LOG_LEVEL_DEBUG, "client sent connection request packet to server\n");

                        var packet = new connection_request_packet_t();
                        packet.packet_type = CONNECTION_REQUEST_PACKET;
                        BufferEx.Copy(packet.version_info, VERSION_INFO, VERSION_INFO_BYTES);
                        packet.protocol_id = client.connect_token.protocol_id;
                        packet.connect_token_expire_timestamp = client.connect_token.expire_timestamp;
                        BufferEx.Copy(packet.connect_token_nonce, client.connect_token.nonce, CONNECT_TOKEN_NONCE_BYTES);
                        BufferEx.Copy(packet.connect_token_data, client.connect_token.private_data, CONNECT_TOKEN_PRIVATE_BYTES);

                        client_send_packet_to_server_internal(client, packet);
                    }
                    break;

                case CLIENT_STATE_SENDING_CONNECTION_RESPONSE:
                    {
                        if (client.last_packet_send_time + (1.0 / PACKET_SEND_RATE) >= client.time)
                            return;

                        printf(LOG_LEVEL_DEBUG, "client sent connection response packet to server\n");

                        var packet = new connection_response_packet_t();
                        packet.packet_type = CONNECTION_RESPONSE_PACKET;
                        packet.challenge_token_sequence = client.challenge_token_sequence;
                        BufferEx.Copy(packet.challenge_token_data, client.challenge_token_data, CHALLENGE_TOKEN_BYTES);

                        client_send_packet_to_server_internal(client, packet);
                    }
                    break;

                case CLIENT_STATE_CONNECTED:
                    {
                        if (client.last_packet_send_time + (1.0 / PACKET_SEND_RATE) >= client.time)
                            return;

                        printf(LOG_LEVEL_DEBUG, "client sent connection keep-alive packet to server\n");

                        var packet = new connection_keep_alive_packet_t();
                        packet.packet_type = CONNECTION_KEEP_ALIVE_PACKET;
                        packet.client_index = 0;
                        packet.max_clients = 0;

                        client_send_packet_to_server_internal(client, packet);
                    }
                    break;

                default: break;
            }
        }

        static bool client_connect_to_next_server(netcode_client_t client)
        {
            assert(client != null);

            if (client.server_address_index + 1 >= client.connect_token.num_server_addresses)
            {
                printf(LOG_LEVEL_DEBUG, "client has no more servers to connect to\n");
                return false;
            }

            client.server_address_index++;
            client.server_address = client.connect_token.server_addresses[client.server_address_index];

            client_reset_before_next_connect(client);

            printf(LOG_LEVEL_INFO, $"client connecting to next server {address_to_string(client.server_address)} [{client.server_address_index + 1}/{client.connect_token.num_server_addresses}]\n");

            client_set_state(client, CLIENT_STATE_SENDING_CONNECTION_REQUEST);

            return true;
        }

        public static void client_update(this netcode_client_t client, double time)
        {
            assert(client != null);

            client.time = time;

            if (client.loopback)
                return;

            client_receive_packets(client);

            client_send_packets(client);

            if (client.state > CLIENT_STATE_DISCONNECTED && client.state < CLIENT_STATE_CONNECTED)
            {
                var connect_token_expire_seconds = (client.connect_token.expire_timestamp - client.connect_token.create_timestamp);
                if (client.time - client.connect_start_time >= connect_token_expire_seconds)
                {
                    printf(LOG_LEVEL_INFO, "client connect failed. connect token expired\n");
                    client_disconnect_internal(client, CLIENT_STATE_CONNECT_TOKEN_EXPIRED, false);
                    return;
                }
            }

            if (client.should_disconnect)
            {
                printf(LOG_LEVEL_DEBUG, $"client should disconnect -> {client_state_name(client.should_disconnect_state)}\n");
                if (client_connect_to_next_server(client))
                    return;
                client_disconnect_internal(client, client.should_disconnect_state, false);
                return;
            }

            switch (client.state)
            {
                case CLIENT_STATE_SENDING_CONNECTION_REQUEST:
                    {
                        if (client.connect_token.timeout_seconds > 0 && client.last_packet_receive_time + client.connect_token.timeout_seconds < time)
                        {
                            printf(LOG_LEVEL_INFO, "client connect failed. connection request timed out\n");
                            if (client_connect_to_next_server(client))
                                return;
                            client_disconnect_internal(client, CLIENT_STATE_CONNECTION_REQUEST_TIMED_OUT, false);
                            return;
                        }
                    }
                    break;

                case CLIENT_STATE_SENDING_CONNECTION_RESPONSE:
                    {
                        if (client.connect_token.timeout_seconds > 0 && client.last_packet_receive_time + client.connect_token.timeout_seconds < time)
                        {
                            printf(LOG_LEVEL_INFO, "client connect failed. connection response timed out\n");
                            if (client_connect_to_next_server(client))
                                return;
                            client_disconnect_internal(client, CLIENT_STATE_CONNECTION_RESPONSE_TIMED_OUT, false);
                            return;
                        }
                    }
                    break;

                case CLIENT_STATE_CONNECTED:
                    {
                        if (client.connect_token.timeout_seconds > 0 && client.last_packet_receive_time + client.connect_token.timeout_seconds < time)
                        {
                            printf(LOG_LEVEL_INFO, "client connection timed out\n");
                            client_disconnect_internal(client, CLIENT_STATE_CONNECTION_TIMED_OUT, false);
                            return;
                        }
                    }
                    break;
                default: break;
            }
        }

        public static ulong client_next_packet_sequence(this netcode_client_t client)
        {
            assert(client != null);
            return client.sequence;
        }

        public static void client_send_packet(this netcode_client_t client, byte[] packet_data, int packet_bytes)
        {
            assert(client != null);
            assert(packet_data != null);
            assert(packet_bytes > 0);
            assert(packet_bytes <= MAX_PACKET_SIZE);

            // zero byte payloads are not valid on the wire and would silently vanish at the receiver

            if (packet_bytes <= 0 || packet_bytes > MAX_PACKET_SIZE)
            {
                printf(LOG_LEVEL_ERROR, $"error: payload packet size is out of range ({packet_bytes})\n");
                return;
            }

            if (client.state != CLIENT_STATE_CONNECTED)
                return;

            if (!client.loopback)
            {
                var packet = new connection_payload_packet_t { payload_data = new byte[packet_bytes] };
                packet.packet_type = CONNECTION_PAYLOAD_PACKET;
                packet.payload_bytes = (ulong)packet_bytes;
                BufferEx.Copy(packet.payload_data, packet_data, packet_bytes);

                client_send_packet_to_server_internal(client, packet);
            }
            else client.config.send_loopback_packet_callback(
                    client.config.callback_context,
                    client.client_index,
                    packet_data,
                    packet_bytes,
                    client.sequence++);
        }

        public static byte[] client_receive_packet(this netcode_client_t client, out int packet_bytes, out ulong packet_sequence)
        {
            assert(client != null);

            var packet = (connection_payload_packet_t)packet_queue_pop(client.packet_receive_queue, out packet_sequence);

            if (packet != null)
            {
                assert(packet.packet_type == CONNECTION_PAYLOAD_PACKET);
                packet_bytes = (int)packet.payload_bytes;
                assert(packet_bytes >= 0);
                assert(packet_bytes <= MAX_PAYLOAD_BYTES);
                return packet.payload_data;
            }
            else { packet_bytes = 0; packet_sequence = 0; return null; }
        }

        public static void client_free_packet(this netcode_client_t client, ref byte[] packet)
        {
            assert(client != null);
            assert(packet != null);
            packet = null;
        }

        public static void client_disconnect(this netcode_client_t client)
        {
            assert(client != null);
            assert(!client.loopback);
            client_disconnect_internal(client, CLIENT_STATE_DISCONNECTED, true);
        }

        static void client_disconnect_internal(netcode_client_t client, int destination_state, bool send_disconnect_packets)
        {
            assert(!client.loopback);
            assert(destination_state <= CLIENT_STATE_DISCONNECTED);

            if (client.state <= CLIENT_STATE_DISCONNECTED || client.state == destination_state)
                return;

            printf(LOG_LEVEL_INFO, "client disconnected\n");

            if (!client.loopback && send_disconnect_packets && client.state > CLIENT_STATE_DISCONNECTED)
            {
                printf(LOG_LEVEL_DEBUG, "client sent disconnect packets to server\n");

                int i;
                for (i = 0; i < NUM_DISCONNECT_PACKETS; ++i)
                {
                    printf(LOG_LEVEL_DEBUG, $"client sent disconnect packet {i}\n");

                    var packet = new connection_disconnect_packet_t();
                    packet.packet_type = CONNECTION_DISCONNECT_PACKET;

                    client_send_packet_to_server_internal(client, packet);
                }
            }

            client_reset_connection_data(client, destination_state);
        }

        public static int client_state(this netcode_client_t client)
        {
            assert(client != null);
            return client.state;
        }

        public static int client_index(this netcode_client_t client)
        {
            assert(client != null);
            return client.client_index;
        }

        public static int client_max_clients(this netcode_client_t client)
        {
            assert(client != null);
            return client.max_clients;
        }

        public static void client_connect_loopback(this netcode_client_t client, int client_index, int max_clients)
        {
            assert(client != null);
            assert(client.state <= CLIENT_STATE_DISCONNECTED);

            // a loopback client sends only through this callback. without it the first send would
            // call a null reference, so refuse to enter loopback at all, in every build.

            assert(client.config.send_loopback_packet_callback != null);

            if (client.config.send_loopback_packet_callback == null)
            {
                printf(LOG_LEVEL_ERROR, "error: a loopback client requires send_loopback_packet_callback\n");
                return;
            }

            printf(LOG_LEVEL_INFO, $"client connected to server via loopback as client {client_index}\n");
            client.state = CLIENT_STATE_CONNECTED;
            client.client_index = client_index;
            client.max_clients = max_clients;
            client.loopback = true;
        }

        public static void client_disconnect_loopback(this netcode_client_t client)
        {
            assert(client != null);
            assert(client.loopback);
            client_reset_connection_data(client, CLIENT_STATE_DISCONNECTED);
        }

        public static bool client_loopback(this netcode_client_t client)
        {
            assert(client != null);
            return client.loopback;
        }

        public static void client_process_loopback_packet(this netcode_client_t client, byte[] packet_data, int packet_bytes, ulong packet_sequence)
        {
            assert(client != null);
            assert(client.loopback);
            assert(packet_data != null);
            assert(packet_bytes > 0);
            assert(packet_bytes <= MAX_PACKET_SIZE);

            if (!client.loopback)
                return;

            if (packet_bytes <= 0 || packet_bytes > MAX_PACKET_SIZE)
                return;

            var packet = create_payload_packet(packet_bytes, client.config.allocator_context, client.config.allocate_function);
            if (packet == null)
                return;
            BufferEx.Copy(packet.payload_data, packet_data, packet_bytes);
            printf(LOG_LEVEL_DEBUG, "client processing loopback packet from server\n");
            packet_queue_push(client.packet_receive_queue, ref packet, packet_sequence);
        }

        public static ushort client_get_port(this netcode_client_t client) { assert(client != null); return client.address.type == ADDRESS_IPV4 ? client.socket_holder.ipv4.address.port : client.socket_holder.ipv6.address.port; }

        public static netcode_address_t client_server_address(this netcode_client_t client) { assert(client != null); return client.server_address; }

        #endregion

        #region encryption_manager_t

        const int MAX_ENCRYPTION_MAPPINGS = MAX_CLIENTS * 4;

        internal class encryption_manager_t
        {
            public int num_encryption_mappings;
            public int[] timeout = new int[MAX_ENCRYPTION_MAPPINGS];
            public double[] expire_time = new double[MAX_ENCRYPTION_MAPPINGS];
            public double[] last_access_time = new double[MAX_ENCRYPTION_MAPPINGS];
            public netcode_address_t[] address = BufferEx.NewT<netcode_address_t>(MAX_ENCRYPTION_MAPPINGS);
            public int[] client_index = new int[MAX_ENCRYPTION_MAPPINGS];
            public int[] connect_token_entry_index = new int[MAX_ENCRYPTION_MAPPINGS];
            public byte[] send_key = new byte[KEY_BYTES * MAX_ENCRYPTION_MAPPINGS];
            public byte[] receive_key = new byte[KEY_BYTES * MAX_ENCRYPTION_MAPPINGS];
        }

        static void encryption_manager_reset(encryption_manager_t encryption_manager)
        {
            printf(LOG_LEVEL_DEBUG, "reset encryption manager\n");

            assert(encryption_manager != null);

            encryption_manager.num_encryption_mappings = 0;

            int i;
            for (i = 0; i < MAX_ENCRYPTION_MAPPINGS; i++)
            {
                encryption_manager.client_index[i] = -1;
                encryption_manager.connect_token_entry_index[i] = -1;
                encryption_manager.expire_time[i] = -1.0;
                encryption_manager.last_access_time[i] = -1000.0;
                BufferEx.SetT(ref encryption_manager.address[i], 0);
            }

            BufferEx.Set(encryption_manager.timeout, 0);
            CryptographicOperations.ZeroMemory(encryption_manager.send_key);
            CryptographicOperations.ZeroMemory(encryption_manager.receive_key);
        }

        static bool encryption_manager_entry_expired(encryption_manager_t encryption_manager, int index, double time) =>
            (encryption_manager.timeout[index] > 0 && (encryption_manager.last_access_time[index] + encryption_manager.timeout[index]) < time) ||
            (encryption_manager.expire_time[index] >= 0.0 && encryption_manager.expire_time[index] < time);

        static bool encryption_manager_add_encryption_mapping(
            encryption_manager_t encryption_manager,
            netcode_address_t address,
            byte[] send_key,
            byte[] receive_key,
            double time,
            double expire_time,
            int timeout,
            int connect_token_entry_index)
        {
            int i;
            for (i = 0; i < encryption_manager.num_encryption_mappings; i++)
                if (address_equal(encryption_manager.address[i], address) && !encryption_manager_entry_expired(encryption_manager, i, time))
                {
                    encryption_manager.timeout[i] = timeout;
                    encryption_manager.expire_time[i] = expire_time;
                    encryption_manager.last_access_time[i] = time;
                    encryption_manager.connect_token_entry_index[i] = connect_token_entry_index;
                    BufferEx.Copy(encryption_manager.send_key, i * KEY_BYTES, send_key, 0, KEY_BYTES);
                    BufferEx.Copy(encryption_manager.receive_key, i * KEY_BYTES, receive_key, 0, KEY_BYTES);
                    return true;
                }

            for (i = 0; i < MAX_ENCRYPTION_MAPPINGS; i++)
                if (encryption_manager.address[i].type == ADDRESS_NONE ||
                    (encryption_manager_entry_expired(encryption_manager, i, time) && encryption_manager.client_index[i] == -1))
                {
                    encryption_manager.timeout[i] = timeout;
                    encryption_manager.address[i] = address_copy(address);
                    encryption_manager.expire_time[i] = expire_time;
                    encryption_manager.last_access_time[i] = time;
                    encryption_manager.connect_token_entry_index[i] = connect_token_entry_index;
                    BufferEx.Copy(encryption_manager.send_key, i * KEY_BYTES, send_key, 0, KEY_BYTES);
                    BufferEx.Copy(encryption_manager.receive_key, i * KEY_BYTES, receive_key, 0, KEY_BYTES);
                    if (i + 1 > encryption_manager.num_encryption_mappings)
                        encryption_manager.num_encryption_mappings = i + 1;
                    return true;
                }

            return false;
        }

        static bool encryption_manager_remove_encryption_mapping(encryption_manager_t encryption_manager, netcode_address_t address, double time)
        {
            assert(encryption_manager != null);
            assert(address != null);

            int i;
            for (i = 0; i < encryption_manager.num_encryption_mappings; i++)
            {
                if (address_equal(encryption_manager.address[i], address))
                {
                    encryption_manager.expire_time[i] = -1.0f;
                    encryption_manager.last_access_time[i] = -1000.0f;
                    encryption_manager.connect_token_entry_index[i] = -1;
                    BufferEx.SetT(ref encryption_manager.address[i], 0);
                    CryptographicOperations.ZeroMemory(encryption_manager.send_key.AsSpan(i * KEY_BYTES, KEY_BYTES));
                    CryptographicOperations.ZeroMemory(encryption_manager.receive_key.AsSpan(i * KEY_BYTES, KEY_BYTES));

                    if (i + 1 == encryption_manager.num_encryption_mappings)
                    {
                        var index = i - 1;
                        while (index >= 0)
                        {
                            if (!encryption_manager_entry_expired(encryption_manager, index, time) || encryption_manager.client_index[index] != -1)
                                break;
                            encryption_manager.address[index].type = ADDRESS_NONE;
                            index--;
                        }
                        encryption_manager.num_encryption_mappings = index + 1;
                    }

                    return true;
                }
            }

            return false;
        }

        static int encryption_manager_find_encryption_mapping(encryption_manager_t encryption_manager, netcode_address_t address, double time)
        {
            int i;
            for (i = 0; i < encryption_manager.num_encryption_mappings; i++)
                if (address_equal(encryption_manager.address[i], address) && !encryption_manager_entry_expired(encryption_manager, i, time))
                {
                    encryption_manager.last_access_time[i] = time;
                    return i;
                }
            return -1;
        }

        static bool encryption_manager_touch(encryption_manager_t encryption_manager, int index, netcode_address_t address, double time)
        {
            assert(index >= 0);
            assert(index < encryption_manager.num_encryption_mappings);
            if (!address_equal(encryption_manager.address[index], address))
                return false;
            encryption_manager.last_access_time[index] = time;
            return true;
        }

        static void encryption_manager_set_expire_time(encryption_manager_t encryption_manager, int index, double expire_time)
        {
            assert(index >= 0);
            assert(index < encryption_manager.num_encryption_mappings);
            encryption_manager.expire_time[index] = expire_time;
        }

        static byte[] encryption_manager_get_send_key(encryption_manager_t encryption_manager, int index)
        {
            assert(encryption_manager != null);
            if (index == -1)
                return null;
            assert(index >= 0);
            assert(index < encryption_manager.num_encryption_mappings);
            return BufferEx.Slice(encryption_manager.send_key, index * KEY_BYTES, KEY_BYTES);
        }

        static byte[] encryption_manager_get_receive_key(encryption_manager_t encryption_manager, int index)
        {
            assert(encryption_manager != null);
            if (index == -1)
                return null;
            assert(index >= 0);
            assert(index < encryption_manager.num_encryption_mappings);
            return BufferEx.Slice(encryption_manager.receive_key, index * KEY_BYTES, KEY_BYTES);
        }

        static int encryption_manager_get_timeout(encryption_manager_t encryption_manager, int index)
        {
            assert(encryption_manager != null);
            if (index == -1)
                return 0;
            assert(index >= 0);
            assert(index < encryption_manager.num_encryption_mappings);
            return encryption_manager.timeout[index];
        }

        static int encryption_manager_get_connect_token_entry_index(encryption_manager_t encryption_manager, int index)
        {
            assert(encryption_manager != null);
            if (index == -1)
                return -1;
            assert(index >= 0);
            assert(index < encryption_manager.num_encryption_mappings);
            return encryption_manager.connect_token_entry_index[index];
        }

        #endregion

        #region connect_token_entry_t

        internal const int MAX_CONNECT_TOKEN_ENTRIES = MAX_CLIENTS * 8;

        internal const int CONNECT_TOKEN_ENTRY_FREE = 0;
        internal const int CONNECT_TOKEN_ENTRY_PENDING = 1;
        internal const int CONNECT_TOKEN_ENTRY_CONSUMED = 2;

        internal const int CONNECT_TOKEN_ENTRY_REFUSED = -1;
        internal const int CONNECT_TOKEN_HISTORY_FULL = -2;

        internal class connect_token_entry_t
        {
            public int state;
            public double time;                 // server time the entry was created. never refreshed afterwards
            public ulong expire_timestamp;      // when the connect token expires, and with it this entry
            public byte[] mac = new byte[MAC_BYTES];
            public netcode_address_t address = new netcode_address_t();
        }

        static void connect_token_entries_reset(connect_token_entry_t[] connect_token_entries)
        {
            int i;
            for (i = 0; i < MAX_CONNECT_TOKEN_ENTRIES; i++)
            {
                connect_token_entries[i].state = CONNECT_TOKEN_ENTRY_FREE;
                connect_token_entries[i].time = -1000.0;
                connect_token_entries[i].expire_timestamp = 0;
                BufferEx.Set(connect_token_entries[i].mac, 0, MAC_BYTES);
                BufferEx.SetT(ref connect_token_entries[i].address, 0);
            }
        }

        /*
            Returns the index of the entry that admits this connection request, or one of
            CONNECT_TOKEN_ENTRY_REFUSED and CONNECT_TOKEN_HISTORY_FULL.

            An entry is created pending the first time a connect token is seen, and becomes consumed
            when the client that presented it is installed in a client slot. A pending entry admits
            a retransmitted connection request from the address that created it, so a handshake that
            loses a packet still completes. A consumed entry admits nothing, whatever the address, so
            the keys inside a connect token encrypt exactly one session.

            An entry lives until its connect token expires. A history whose entries all hold unexpired
            connect tokens refuses a new connect token instead of evicting one, because evicting is
            how a flood of connect tokens would reopen a token that has already been used.
        */

        static int connect_token_entries_find_or_add(
            connect_token_entry_t[] connect_token_entries,
            netcode_address_t address,
            byte[] mac, int mac_offset,
            ulong expire_timestamp,
            ulong current_timestamp,
            double time)
        {
            assert(connect_token_entries != null);
            assert(address != null);
            assert(mac != null);

            // find the matching entry for the token mac and the first entry free to take a new token.
            // constant time worst case. This is intentional!

            var matching_token_index = -1;
            var free_token_index = -1;

            var mac_span = new ReadOnlySpan<byte>(mac, mac_offset, MAC_BYTES);

            int i;
            for (i = 0; i < MAX_CONNECT_TOKEN_ENTRIES; i++)
            {
                if (connect_token_entries[i].state != CONNECT_TOKEN_ENTRY_FREE &&
                    mac_span.SequenceEqual(connect_token_entries[i].mac))
                {
                    matching_token_index = i;
                }

                if (free_token_index == -1 &&
                    (connect_token_entries[i].state == CONNECT_TOKEN_ENTRY_FREE ||
                     connect_token_entries[i].expire_timestamp <= current_timestamp))
                {
                    free_token_index = i;
                }
            }

            // if no entry is found with the mac, this is a new connect token

            if (matching_token_index == -1)
            {
                if (free_token_index == -1)
                    return CONNECT_TOKEN_HISTORY_FULL;

                connect_token_entries[free_token_index].state = CONNECT_TOKEN_ENTRY_PENDING;
                connect_token_entries[free_token_index].time = time;
                connect_token_entries[free_token_index].expire_timestamp = expire_timestamp;
                connect_token_entries[free_token_index].address = address_copy(address);
                BufferEx.Copy(connect_token_entries[free_token_index].mac, 0, mac, mac_offset, MAC_BYTES);
                return free_token_index;
            }

            // a pending entry admits the address that created it, and nothing else. a consumed entry admits nothing.
            // the entry time is set when the entry is created and is never refreshed.

            assert(matching_token_index >= 0);
            assert(matching_token_index < MAX_CONNECT_TOKEN_ENTRIES);

            if (connect_token_entries[matching_token_index].state == CONNECT_TOKEN_ENTRY_PENDING &&
                address_equal(connect_token_entries[matching_token_index].address, address))
            {
                return matching_token_index;
            }

            return CONNECT_TOKEN_ENTRY_REFUSED;
        }

        static void connect_token_entries_consume(connect_token_entry_t[] connect_token_entries, int index)
        {
            assert(connect_token_entries != null);
            assert(index >= 0);
            assert(index < MAX_CONNECT_TOKEN_ENTRIES);

            connect_token_entries[index].state = CONNECT_TOKEN_ENTRY_CONSUMED;
        }

        #endregion

        #region netcode_server_t

        const int SERVER_FLAG_IGNORE_CONNECTION_REQUEST_PACKETS = 1;
        const int SERVER_FLAG_IGNORE_CONNECTION_RESPONSE_PACKETS = 1 << 1;

        public static void default_server_config(out netcode_server_config_t config)
        {
            //assert(config != null);
            config = new netcode_server_config_t();
            config.max_connect_token_lifetime = DEFAULT_MAX_CONNECT_TOKEN_LIFETIME;
            config.allocator_context = null;
            config.allocate_function = default_allocate_function;
            config.free_function = default_free_function;
            config.network_simulator = null;
            config.callback_context = null;
            config.connect_disconnect_callback = null;
            config.send_loopback_packet_callback = null;
            config.override_send_and_receive = false;
            config.send_packet_override = null;
            config.receive_packet_override = null;
        }
    }

    public class netcode_server_t
    {
        internal netcode_server_config_t config;
        internal netcode.socket_holder_t socket_holder = new netcode.socket_holder_t();
        internal netcode_address_t address;
        internal netcode_address_t address2;
        internal byte flags;
        internal double time;
        internal bool running;
        internal int max_clients;
        internal int num_connected_clients;
        internal ulong global_sequence;
        internal ulong challenge_sequence;
        internal ulong min_connect_token_expire_timestamp;
        internal byte[] challenge_key = new byte[netcode.KEY_BYTES];
        internal bool[] client_connected = new bool[netcode.MAX_CLIENTS];
        internal int[] client_timeout = new int[netcode.MAX_CLIENTS];
        internal bool[] client_loopback = new bool[netcode.MAX_CLIENTS];
        internal bool[] client_confirmed = new bool[netcode.MAX_CLIENTS];
        internal int[] client_disconnect_reason = new int[netcode.MAX_CLIENTS];
        internal int[] client_encryption_index = new int[netcode.MAX_CLIENTS];
        internal ulong[] client_id = new ulong[netcode.MAX_CLIENTS];
        internal ulong[] client_sequence = new ulong[netcode.MAX_CLIENTS];
        internal double[] client_last_packet_send_time = new double[netcode.MAX_CLIENTS];
        internal double[] client_last_packet_receive_time = new double[netcode.MAX_CLIENTS];
        internal byte[][] client_user_data = BufferEx.NewT<byte>(netcode.MAX_CLIENTS, netcode.USER_DATA_BYTES);
        internal netcode.netcode_replay_protection_t[] client_replay_protection = BufferEx.NewT<netcode.netcode_replay_protection_t>(netcode.MAX_CLIENTS);
        internal netcode.packet_queue_t[] client_packet_queue = new netcode.packet_queue_t[netcode.MAX_CLIENTS];
        internal netcode_address_t[] client_address = new netcode_address_t[netcode.MAX_CLIENTS];
        internal netcode.connect_token_entry_t[] connect_token_entries = BufferEx.NewT<netcode.connect_token_entry_t>(netcode.MAX_CONNECT_TOKEN_ENTRIES);
        internal netcode.encryption_manager_t encryption_manager = new netcode.encryption_manager_t();
        internal byte[][] receive_packet_data = new byte[netcode.SERVER_MAX_RECEIVE_PACKETS][];
        internal int[] receive_packet_bytes = new int[netcode.SERVER_MAX_RECEIVE_PACKETS];
        internal netcode_address_t[] receive_from = new netcode_address_t[netcode.SERVER_MAX_RECEIVE_PACKETS];
    }

    static partial class netcode
    {
        static int server_create_error_;

        /*
            If server_create or server_create_dual returns null, call this to find out why.
            Returns the SERVER_CREATE_ERROR_* value from the most recent server create call,
            or SERVER_CREATE_ERROR_NONE if that call succeeded. Bind failures are reported
            separately from other socket errors because a port already in use is the common
            operational failure for dedicated servers.
        */

        public static int server_create_error() => server_create_error_;

        static bool server_socket_create(
            out socket_t socket,
            netcode_address_t address,
            int send_buffer_size,
            int receive_buffer_size,
            netcode_server_config_t config)
        {
            socket = new socket_t();
            assert(address != null);
            assert(config != null);
            address.data = address.type == ADDRESS_IPV4 ? IPAddress.Any : IPAddress.IPv6Any;

            if (config.network_simulator == null)
            {
                if (!config.override_send_and_receive)
                {
                    var socket_error = socket_create(ref socket, address, send_buffer_size, receive_buffer_size);

                    if (socket_error != SOCKET_ERROR_NONE)
                    {
                        // report bind failures separately: a port already in use is the common
                        // operational failure for dedicated servers, and callers want to react
                        // to it differently than to a socket that could not be created at all

                        if (socket_error == SOCKET_ERROR_BIND_IPV4_FAILED || socket_error == SOCKET_ERROR_BIND_IPV6_FAILED)
                            server_create_error_ = address.type == ADDRESS_IPV6 ? SERVER_CREATE_ERROR_BIND_SOCKET_IPV6_FAILED : SERVER_CREATE_ERROR_BIND_SOCKET_IPV4_FAILED;
                        else
                            server_create_error_ = address.type == ADDRESS_IPV6 ? SERVER_CREATE_ERROR_CREATE_SOCKET_IPV6_FAILED : SERVER_CREATE_ERROR_CREATE_SOCKET_IPV4_FAILED;
                        return false;
                    }
                }
            }
            return true;
        }

        public static netcode_server_t server_create_dual(string server_address1_string, string server_address2_string, netcode_server_config_t config, double time)
        {
            assert(config != null);
            assert(netcode_.initialized != 0);

            server_create_error_ = SERVER_CREATE_ERROR_NONE;

            // tolerate a zeroed config: default the allocator functions so a forgotten
            // default_server_config is an inconvenience, not a crash. the server keeps its own copy.

            config = config.copy();
            if (config.allocate_function == null)
                config.allocate_function = default_allocate_function;
            if (config.free_function == null)
                config.free_function = default_free_function;
            if (config.max_connect_token_lifetime <= 0)
                config.max_connect_token_lifetime = DEFAULT_MAX_CONNECT_TOKEN_LIFETIME;

            // the overrides are called on the update path with no null check. a missing one is a
            // configuration error, refused here rather than dereferenced on the first update.

            if (config.override_send_and_receive && (config.send_packet_override == null || config.receive_packet_override == null))
            {
                printf(LOG_LEVEL_ERROR, "error: override_send_and_receive requires both send_packet_override and receive_packet_override\n");
                server_create_error_ = SERVER_CREATE_ERROR_MISSING_OVERRIDE_CALLBACK;
                return null;
            }

            var server_address2 = new netcode_address_t();

            if (parse_address(server_address1_string, out var server_address1) != OK)
            {
                printf(LOG_LEVEL_ERROR, "error: failed to parse server public address\n");
                server_create_error_ = SERVER_CREATE_ERROR_PARSE_ADDRESS_FAILED;
                return null;
            }
            if (server_address2_string != null && parse_address(server_address2_string, out server_address2) != OK)
            {
                printf(LOG_LEVEL_ERROR, "error: failed to parse server public address2\n");
                server_create_error_ = SERVER_CREATE_ERROR_PARSE_ADDRESS2_FAILED;
                return null;
            }

            var bind_address_ipv4 = new netcode_address_t();
            var bind_address_ipv6 = new netcode_address_t();

            var socket_ipv4 = new socket_t();
            var socket_ipv6 = new socket_t();

            if (server_address1.type == ADDRESS_IPV4 || server_address2.type == ADDRESS_IPV4)
            {
                bind_address_ipv4.type = ADDRESS_IPV4;
                bind_address_ipv4.port = server_address1.type == ADDRESS_IPV4 ? server_address1.port : server_address2.port;

                if (!server_socket_create(out socket_ipv4, bind_address_ipv4, SERVER_SOCKET_SNDBUF_SIZE, SERVER_SOCKET_RCVBUF_SIZE, config))
                    return null;
            }

            if (server_address1.type == ADDRESS_IPV6 || server_address2.type == ADDRESS_IPV6)
            {
                bind_address_ipv6.type = ADDRESS_IPV6;
                bind_address_ipv6.port = server_address1.type == ADDRESS_IPV6 ? server_address1.port : server_address2.port;

                if (!server_socket_create(out socket_ipv6, bind_address_ipv6, SERVER_SOCKET_SNDBUF_SIZE, SERVER_SOCKET_RCVBUF_SIZE, config))
                {
                    socket_destroy(ref socket_ipv4);
                    return null;
                }
            }

            // managed allocation does not fail by returning null, so SERVER_CREATE_ERROR_ALLOCATE_SERVER_FAILED is never reported

            var server = new netcode_server_t();

            if (config.network_simulator == null)
                printf(LOG_LEVEL_INFO, $"server listening on {server_address1_string}\n");
            else
                printf(LOG_LEVEL_INFO, $"server listening on {server_address1_string} (network simulator)\n");

            server.config = config;
            server.socket_holder.ipv4 = socket_ipv4;
            server.socket_holder.ipv6 = socket_ipv6;
            server.address = server_address1;
            server.address2 = server_address2;
            server.flags = 0;
            server.time = time;
            server.running = false;
            server.max_clients = 0;
            server.num_connected_clients = 0;
            server.global_sequence = 1UL << 63;

            BufferEx.Set(server.client_connected, 0);
            BufferEx.Set(server.client_loopback, 0);
            BufferEx.Set(server.client_confirmed, 0);
            BufferEx.Set(server.client_id, 0);
            BufferEx.Set(server.client_sequence, 0);
            BufferEx.Set(server.client_last_packet_send_time, 0);
            BufferEx.Set(server.client_last_packet_receive_time, 0);
            BufferEx.SetT(server.client_address, 0);

            int i;
            for (i = 0; i < MAX_CLIENTS; i++)
                server.client_encryption_index[i] = -1;

            connect_token_entries_reset(server.connect_token_entries);

            encryption_manager_reset(server.encryption_manager);

            for (i = 0; i < MAX_CLIENTS; i++)
                replay_protection_reset(server.client_replay_protection[i]);

            BufferEx.SetT(server.client_packet_queue, 0);

            return server;
        }

        public static netcode_server_t server_create(string server_address_string, netcode_server_config_t config, double time) =>
            server_create_dual(server_address_string, null, config, time);

        public static void server_destroy(ref netcode_server_t server)
        {
            assert(server != null);

            server_stop(server);

            socket_destroy(ref server.socket_holder.ipv4);
            socket_destroy(ref server.socket_holder.ipv6);

            CryptographicOperations.ZeroMemory(server.config.private_key);

            server = null;
        }

        public static void server_start(this netcode_server_t server, int max_clients)
        {
            assert(server != null);
            assert(max_clients > 0);
            assert(max_clients <= MAX_CLIENTS);

            // the per-client arrays are sized MAX_CLIENTS. an out of range value here
            // must not get through in release builds where asserts compile out

            if (max_clients <= 0 || max_clients > MAX_CLIENTS)
            {
                printf(LOG_LEVEL_ERROR, $"error: max clients must be in [1,{MAX_CLIENTS}], got {max_clients}\n");
                return;
            }

            if (server.running)
                server_stop(server);

            printf(LOG_LEVEL_INFO, $"server started with {max_clients} client slots\n");

            server.running = true;
            server.max_clients = max_clients;
            server.num_connected_clients = 0;
            server.challenge_sequence = 0;
            generate_key(server.challenge_key);

            // a connect token issued before this server started carries keys that already encrypted
            // packets at sequence numbers this run starts again from. the earliest expire timestamp a
            // connect token issued after the start can carry is the start time plus the maximum
            // lifetime the backend issues, so anything earlier than that is refused.

            server.min_connect_token_expire_timestamp = ctime() + (ulong)server.config.max_connect_token_lifetime;

            // global packets (challenge, denied) encrypt with the same per-token server to client
            // keys as per-client packets, whose sequences start at zero, so the global sequence
            // lives in the top half of the sequence space to keep AEAD nonces disjoint under a
            // shared key. server_stop zeroes it, so it must be re-seeded on every start,
            // not just in server_create -- otherwise a stopped and restarted server would
            // reuse nonces between global and per-client packets.

            server.global_sequence = 1UL << 63;

            int i;
            for (i = 0; i < server.max_clients; i++)
                packet_queue_init(server.client_packet_queue[i], server.config.allocator_context, server.config.allocate_function, server.config.free_function);

            for (i = 0; i < MAX_CLIENTS; i++)
                server.client_disconnect_reason[i] = SERVER_CLIENT_DISCONNECT_REASON_NONE;
        }

        static void server_send_global_packet(netcode_server_t server, object packet, netcode_address_t to, byte[] packet_key)
        {
            assert(server != null);
            assert(packet != null);
            assert(to != null);
            assert(packet_key != null);

            var packet_data = new byte[MAX_PACKET_BYTES];

            var packet_bytes = write_packet(packet, packet_data, MAX_PACKET_BYTES, server.global_sequence, packet_key, server.config.protocol_id);

            assert(packet_bytes <= MAX_PACKET_BYTES);

            if (server.config.network_simulator != null)
                network_simulator_send_packet(server.config.network_simulator, server.address, to, packet_data, packet_bytes);
            else
            {
                if (server.config.override_send_and_receive) server.config.send_packet_override(server.config.callback_context, to, packet_data, packet_bytes);
                else if (to.type == ADDRESS_IPV4) socket_send_packet(server.socket_holder.ipv4, to, packet_data, packet_bytes);
                else if (to.type == ADDRESS_IPV6) socket_send_packet(server.socket_holder.ipv6, to, packet_data, packet_bytes);
            }

            server.global_sequence++;
        }

        static void server_send_client_packet(netcode_server_t server, object packet, int client_index)
        {
            assert(server != null);
            assert(packet != null);
            assert(client_index >= 0);
            assert(client_index < server.max_clients);
            assert(server.client_connected[client_index]);
            assert(!server.client_loopback[client_index]);

            var packet_data = new byte[MAX_PACKET_BYTES];

            if (!encryption_manager_touch(
                server.encryption_manager,
                server.client_encryption_index[client_index],
                server.client_address[client_index],
                server.time))
            {
                printf(LOG_LEVEL_ERROR, $"error: encryption mapping is out of date for client {client_index}\n");
                return;
            }

            var packet_key = encryption_manager_get_send_key(server.encryption_manager, server.client_encryption_index[client_index]);

            var packet_bytes = write_packet(packet, packet_data, MAX_PACKET_BYTES, server.client_sequence[client_index], packet_key, server.config.protocol_id);

            assert(packet_bytes <= MAX_PACKET_BYTES);

            if (server.config.network_simulator != null)
                network_simulator_send_packet(server.config.network_simulator, server.address, server.client_address[client_index], packet_data, packet_bytes);
            else
            {
                if (server.config.override_send_and_receive) server.config.send_packet_override(server.config.callback_context, server.client_address[client_index], packet_data, packet_bytes);
                else
                {
                    if (server.client_address[client_index].type == ADDRESS_IPV4) socket_send_packet(server.socket_holder.ipv4, server.client_address[client_index], packet_data, packet_bytes);
                    else if (server.client_address[client_index].type == ADDRESS_IPV6) socket_send_packet(server.socket_holder.ipv6, server.client_address[client_index], packet_data, packet_bytes);
                }
            }

            server.client_sequence[client_index]++;

            server.client_last_packet_send_time[client_index] = server.time;
        }

        static void server_reset_client_slot(netcode_server_t server, int client_index)
        {
            packet_queue_clear(server.client_packet_queue[client_index]);

            server.client_connected[client_index] = false;
            server.client_loopback[client_index] = false;
            server.client_confirmed[client_index] = false;
            server.client_id[client_index] = 0;
            server.client_sequence[client_index] = 0;
            server.client_last_packet_send_time[client_index] = 0.0;
            server.client_last_packet_receive_time[client_index] = 0.0;
            BufferEx.SetT(ref server.client_address[client_index], 0);
            server.client_encryption_index[client_index] = -1;
            BufferEx.Set(server.client_user_data[client_index], 0, USER_DATA_BYTES);

            server.num_connected_clients--;

            assert(server.num_connected_clients >= 0);
        }

        static void server_disconnect_client_internal(netcode_server_t server, int client_index, bool send_disconnect_packets, int disconnect_reason)
        {
            assert(server != null);
            assert(server.running);
            assert(client_index >= 0);
            assert(client_index < server.max_clients);
            assert(server.client_connected[client_index]);
            assert(!server.client_loopback[client_index]);
            assert(server.encryption_manager.client_index[server.client_encryption_index[client_index]] == client_index);

            printf(LOG_LEVEL_INFO, $"server disconnected client {client_index}\n");

            // record why before the callback fires, so the reason can be queried from inside the callback

            server.client_disconnect_reason[client_index] = disconnect_reason;

            server.config.connect_disconnect_callback?.Invoke(server.config.callback_context, client_index, 0);

            if (send_disconnect_packets)
            {
                printf(LOG_LEVEL_DEBUG, $"server sent disconnect packets to client {client_index}\n");

                int i;
                for (i = 0; i < NUM_DISCONNECT_PACKETS; i++)
                {
                    printf(LOG_LEVEL_DEBUG, $"server sent disconnect packet {i}\n");

                    var packet = new connection_disconnect_packet_t();
                    packet.packet_type = CONNECTION_DISCONNECT_PACKET;

                    server_send_client_packet(server, packet, client_index);
                }
            }

            replay_protection_reset(server.client_replay_protection[client_index]);

            server.encryption_manager.client_index[server.client_encryption_index[client_index]] = -1;

            encryption_manager_remove_encryption_mapping(server.encryption_manager, server.client_address[client_index], server.time);

            server_reset_client_slot(server, client_index);
        }

        public static void server_disconnect_client(this netcode_server_t server, int client_index)
        {
            assert(server != null);

            if (!server.running)
                return;

            assert(client_index >= 0);
            assert(client_index < server.max_clients);

            if (client_index < 0 || client_index >= server.max_clients)
                return;

            assert(!server.client_loopback[client_index]);

            if (!server.client_connected[client_index])
                return;

            if (server.client_loopback[client_index])
                return;

            server_disconnect_client_internal(server, client_index, true, SERVER_CLIENT_DISCONNECT_REASON_SERVER_DISCONNECT);
        }

        public static void server_disconnect_all_clients(this netcode_server_t server)
        {
            assert(server != null);

            if (!server.running)
                return;

            int i;
            for (i = 0; i < server.max_clients; i++)
                if (server.client_connected[i] && !server.client_loopback[i])
                    server_disconnect_client_internal(server, i, true, SERVER_CLIENT_DISCONNECT_REASON_SERVER_DISCONNECT);
        }

        public static void server_stop(this netcode_server_t server)
        {
            assert(server != null);

            if (!server.running)
                return;

            server_disconnect_all_clients(server);

            // loopback clients are not disconnected above, but they must not survive a server stop

            int i;
            for (i = 0; i < server.max_clients; i++)
                if (server.client_connected[i] && server.client_loopback[i])
                    server_disconnect_loopback_client(server, i);

            server.running = false;
            server.max_clients = 0;
            server.num_connected_clients = 0;

            server.global_sequence = 0;
            server.challenge_sequence = 0;
            CryptographicOperations.ZeroMemory(server.challenge_key);

            connect_token_entries_reset(server.connect_token_entries);

            encryption_manager_reset(server.encryption_manager);

            printf(LOG_LEVEL_INFO, "server stopped\n");
        }

        static int server_find_client_index_by_id(netcode_server_t server, ulong client_id)
        {
            assert(server != null);

            int i;
            for (i = 0; i < server.max_clients; ++i)
                if (server.client_connected[i] && server.client_id[i] == client_id)
                    return i;
            return -1;
        }

        static int server_find_client_index_by_address(netcode_server_t server, netcode_address_t address)
        {
            assert(server != null);
            assert(address != null);

            if (address.type == 0)
                return -1;

            int i;
            for (i = 0; i < server.max_clients; ++i)
                if (server.client_connected[i] && address_equal(server.client_address[i], address))
                    return i;
            return -1;
        }

        static void server_process_connection_request_packet(
            netcode_server_t server,
            netcode_address_t from,
            connection_request_packet_t packet,
            ulong current_timestamp)
        {
            assert(server != null);

            var connect_token_private = new connect_token_private_t();
            if (read_connect_token_private(packet.connect_token_data, CONNECT_TOKEN_PRIVATE_BYTES, connect_token_private) != OK)
            {
                printf(LOG_LEVEL_DEBUG, "server ignored connection request. failed to read connect token\n");
                return;
            }

            var found_server_address = false;
            int i;
            for (i = 0; i < connect_token_private.num_server_addresses; i++)
            {
                if (address_equal(server.address, connect_token_private.server_addresses[i]))
                    found_server_address = true;
                if (server.address2.type != ADDRESS_NONE && address_equal(server.address2, connect_token_private.server_addresses[i]))
                    found_server_address = true;
            }
            if (!found_server_address)
            {
                printf(LOG_LEVEL_DEBUG, "server ignored connection request. server address not in connect token whitelist\n");
                return;
            }

            if (server_find_client_index_by_address(server, from) != -1)
            {
                printf(LOG_LEVEL_DEBUG, "server ignored connection request. a client with this address is already connected\n");
                return;
            }

            if (server_find_client_index_by_id(server, connect_token_private.client_id) != -1)
            {
                printf(LOG_LEVEL_DEBUG, "server ignored connection request. a client with this id is already connected\n");
                return;
            }

            var connect_token_entry_index = connect_token_entries_find_or_add(
                server.connect_token_entries,
                from,
                packet.connect_token_data, CONNECT_TOKEN_PRIVATE_BYTES - MAC_BYTES,
                packet.connect_token_expire_timestamp,
                current_timestamp,
                server.time);

            if (connect_token_entry_index == CONNECT_TOKEN_HISTORY_FULL)
            {
                printf(LOG_LEVEL_DEBUG, "server ignored connection request. connect token history is full\n");
                return;
            }

            if (connect_token_entry_index == CONNECT_TOKEN_ENTRY_REFUSED)
            {
                printf(LOG_LEVEL_DEBUG, "server ignored connection request. connect token has already been used\n");
                return;
            }

            if (server.num_connected_clients == server.max_clients)
            {
                printf(LOG_LEVEL_DEBUG, "server denied connection request. server is full\n");

                var p = new connection_denied_packet_t();
                p.packet_type = CONNECTION_DENIED_PACKET;

                server_send_global_packet(server, p, from, connect_token_private.server_to_client_key);

                return;
            }

            var expire_time = (connect_token_private.timeout_seconds >= 0) ? server.time + connect_token_private.timeout_seconds : -1.0f;

            if (!encryption_manager_add_encryption_mapping(
                server.encryption_manager,
                from,
                connect_token_private.server_to_client_key,
                connect_token_private.client_to_server_key,
                server.time,
                expire_time,
                connect_token_private.timeout_seconds,
                connect_token_entry_index))
            {
                printf(LOG_LEVEL_DEBUG, "server ignored connection request. failed to add encryption mapping\n");
                return;
            }

            var challenge_token = new challenge_token_t();
            challenge_token.client_id = connect_token_private.client_id;
            BufferEx.Copy(challenge_token.user_data, connect_token_private.user_data, USER_DATA_BYTES);

            var challenge_packet = new connection_challenge_packet_t();
            challenge_packet.packet_type = CONNECTION_CHALLENGE_PACKET;
            challenge_packet.challenge_token_sequence = server.challenge_sequence;
            write_challenge_token(challenge_token, challenge_packet.challenge_token_data, CHALLENGE_TOKEN_BYTES);
            if (encrypt_challenge_token(
                challenge_packet.challenge_token_data, 0,
                CHALLENGE_TOKEN_BYTES,
                server.challenge_sequence,
                server.challenge_key) != OK)
            {
                printf(LOG_LEVEL_DEBUG, "server ignored connection request. failed to encrypt challenge token\n");
                return;
            }

            server.challenge_sequence++;

            printf(LOG_LEVEL_DEBUG, "server sent connection challenge packet\n");

            server_send_global_packet(server, challenge_packet, from, connect_token_private.server_to_client_key);
        }

        static int server_find_free_client_index(netcode_server_t server)
        {
            assert(server != null);

            int i;
            for (i = 0; i < server.max_clients; ++i)
                if (!server.client_connected[i])
                    return i;
            return -1;
        }

        static void server_connect_client(
            netcode_server_t server,
            int client_index,
            netcode_address_t address,
            ulong client_id,
            int encryption_index,
            int timeout_seconds,
            byte[] user_data)
        {
            assert(server != null);
            assert(server.running);
            assert(client_index >= 0);
            assert(client_index < server.max_clients);
            assert(address != null);
            assert(encryption_index != -1);
            assert(user_data != null);
            assert(server.encryption_manager.client_index[encryption_index] == -1);

            server.num_connected_clients++;

            assert(server.num_connected_clients <= server.max_clients);

            assert(!server.client_connected[client_index]);

            encryption_manager_set_expire_time(server.encryption_manager, encryption_index, -1.0);

            server.encryption_manager.client_index[encryption_index] = client_index;

            server.client_connected[client_index] = true;
            server.client_timeout[client_index] = timeout_seconds;
            server.client_encryption_index[client_index] = encryption_index;
            server.client_id[client_index] = client_id;
            server.client_sequence[client_index] = 0;
            server.client_address[client_index] = address_copy(address);
            server.client_disconnect_reason[client_index] = SERVER_CLIENT_DISCONNECT_REASON_NONE;

            assert(server_find_client_index_by_id(server, client_id) == client_index);
            assert(server_find_client_index_by_address(server, address) == client_index);

            server.client_last_packet_send_time[client_index] = server.time;
            server.client_last_packet_receive_time[client_index] = server.time;
            BufferEx.Copy(server.client_user_data[client_index], user_data, USER_DATA_BYTES);

            // the connect token that got this client here is spent: its history entry admits nothing from now on

            var connect_token_entry_index = encryption_manager_get_connect_token_entry_index(server.encryption_manager, encryption_index);
            if (connect_token_entry_index >= 0)
                connect_token_entries_consume(server.connect_token_entries, connect_token_entry_index);

            printf(LOG_LEVEL_INFO, $"server accepted client {address_to_string(address)} {client_id:x16} in slot {client_index}\n");

            var packet = new connection_keep_alive_packet_t();
            packet.packet_type = CONNECTION_KEEP_ALIVE_PACKET;
            packet.client_index = client_index;
            packet.max_clients = server.max_clients;

            server_send_client_packet(server, packet, client_index);

            server.config.connect_disconnect_callback?.Invoke(server.config.callback_context, client_index, 1);
        }

        static void server_process_connection_response_packet(
            netcode_server_t server,
            netcode_address_t from,
            connection_response_packet_t packet,
            int encryption_index)
        {
            assert(server != null);

            if (decrypt_challenge_token(
                packet.challenge_token_data, 0,
                CHALLENGE_TOKEN_BYTES,
                packet.challenge_token_sequence,
                server.challenge_key) != OK)
            {
                printf(LOG_LEVEL_DEBUG, "server ignored connection response. failed to decrypt challenge token\n");
                return;
            }

            var challenge_token = new challenge_token_t();
            if (read_challenge_token(packet.challenge_token_data, CHALLENGE_TOKEN_BYTES, challenge_token) != OK)
            {
                printf(LOG_LEVEL_DEBUG, "server ignored connection response. failed to read challenge token\n");
                return;
            }

            var packet_send_key = encryption_manager_get_send_key(server.encryption_manager, encryption_index);

            if (packet_send_key == null)
            {
                printf(LOG_LEVEL_DEBUG, "server ignored connection response. no packet send key\n");
                return;
            }

            if (server_find_client_index_by_address(server, from) != -1)
            {
                printf(LOG_LEVEL_DEBUG, "server ignored connection response. a client with this address is already connected\n");
                return;
            }

            if (server_find_client_index_by_id(server, challenge_token.client_id) != -1)
            {
                printf(LOG_LEVEL_DEBUG, "server ignored connection response. a client with this id is already connected\n");
                return;
            }

            if (server.num_connected_clients == server.max_clients)
            {
                printf(LOG_LEVEL_DEBUG, "server denied connection response. server is full\n");

                var p = new connection_denied_packet_t();
                p.packet_type = CONNECTION_DENIED_PACKET;

                server_send_global_packet(server, p, from, packet_send_key);

                return;
            }

            var client_index = server_find_free_client_index(server);

            assert(client_index != -1);

            var timeout_seconds = encryption_manager_get_timeout(server.encryption_manager, encryption_index);

            server_connect_client(server, client_index, from, challenge_token.client_id, encryption_index, timeout_seconds, challenge_token.user_data);
        }

        static void server_process_packet_internal(
            netcode_server_t server,
            netcode_address_t from,
            object packet,
            ulong sequence,
            ulong current_timestamp,
            int encryption_index,
            int client_index)
        {
            assert(server != null);
            assert(packet != null);

            var packet_type = ((base_request_packet_t)packet).packet_type;
            switch (packet_type)
            {
                case CONNECTION_REQUEST_PACKET:
                    {
                        if ((server.flags & SERVER_FLAG_IGNORE_CONNECTION_REQUEST_PACKETS) == 0)
                        {
                            printf(LOG_LEVEL_DEBUG, $"server received connection request from {address_to_string(from)}\n");
                            server_process_connection_request_packet(server, from, (connection_request_packet_t)packet, current_timestamp);
                        }
                    }
                    break;

                case CONNECTION_RESPONSE_PACKET:
                    {
                        if ((server.flags & SERVER_FLAG_IGNORE_CONNECTION_RESPONSE_PACKETS) == 0)
                        {
                            printf(LOG_LEVEL_DEBUG, $"server received connection response from {address_to_string(from)}\n");
                            server_process_connection_response_packet(server, from, (connection_response_packet_t)packet, encryption_index);
                        }
                    }
                    break;

                case CONNECTION_KEEP_ALIVE_PACKET:
                    {
                        if (client_index != -1)
                        {
                            printf(LOG_LEVEL_DEBUG, $"server received connection keep alive packet from client {client_index}\n");
                            server.client_last_packet_receive_time[client_index] = server.time;
                            if (!server.client_confirmed[client_index])
                            {
                                printf(LOG_LEVEL_DEBUG, $"server confirmed connection with client {client_index}\n");
                                server.client_confirmed[client_index] = true;
                            }
                        }
                    }
                    break;

                case CONNECTION_PAYLOAD_PACKET:
                    {
                        if (client_index != -1)
                        {
                            printf(LOG_LEVEL_DEBUG, $"server received connection payload packet from client {client_index}\n");
                            server.client_last_packet_receive_time[client_index] = server.time;
                            if (!server.client_confirmed[client_index])
                            {
                                printf(LOG_LEVEL_DEBUG, $"server confirmed connection with client {client_index}\n");
                                server.client_confirmed[client_index] = true;
                            }
                            packet_queue_push(server.client_packet_queue[client_index], ref packet, sequence);
                            return;
                        }
                    }
                    break;

                case CONNECTION_DISCONNECT_PACKET:
                    {
                        if (client_index != -1)
                        {
                            printf(LOG_LEVEL_DEBUG, $"server received disconnect packet from client {client_index}\n");
                            server_disconnect_client_internal(server, client_index, false, SERVER_CLIENT_DISCONNECT_REASON_CLIENT_DISCONNECT);
                        }
                    }
                    break;

                default: break;
            }

            packet = null;
        }

        public static void server_process_packet(this netcode_server_t server, netcode_address_t from, byte[] packet_data, int packet_bytes)
        {
            var allowed_packets = new bool[CONNECTION_NUM_PACKETS];
            allowed_packets[CONNECTION_REQUEST_PACKET] = true;
            allowed_packets[CONNECTION_RESPONSE_PACKET] = true;
            allowed_packets[CONNECTION_KEEP_ALIVE_PACKET] = true;
            allowed_packets[CONNECTION_PAYLOAD_PACKET] = true;
            allowed_packets[CONNECTION_DISCONNECT_PACKET] = true;

            var current_timestamp = ctime();

            server_read_and_process_packet(server, from, packet_data, packet_bytes, current_timestamp, allowed_packets);
        }

        static void server_read_and_process_packet(
            netcode_server_t server,
            netcode_address_t from,
            byte[] packet_data,
            int packet_bytes,
            ulong current_timestamp,
            bool[] allowed_packets)
        {
            if (!server.running)
                return;

            if (packet_bytes <= 1)
                return;

            var encryption_index = -1;
            var client_index = server_find_client_index_by_address(server, from);
            if (client_index != -1)
            {
                assert(client_index >= 0);
                assert(client_index < server.max_clients);
                encryption_index = server.client_encryption_index[client_index];
            }
            else
                encryption_index = encryption_manager_find_encryption_mapping(server.encryption_manager, from, server.time);

            var read_packet_key = encryption_manager_get_receive_key(server.encryption_manager, encryption_index);

            if (read_packet_key == null && packet_data[0] != 0)
            {
                printf(LOG_LEVEL_DEBUG, $"server could not process packet because no encryption mapping exists for {address_to_string(from)}\n");
                return;
            }

            var packet = read_packet(
                packet_data,
                packet_bytes,
                out var sequence,
                read_packet_key,
                server.config.protocol_id,
                current_timestamp,
                server.min_connect_token_expire_timestamp,
                server.config.private_key,
                allowed_packets,
                (client_index != -1) ? server.client_replay_protection[client_index] : null,
                server.config.allocator_context,
                server.config.allocate_function);

            if (packet == null)
                return;

            server_process_packet_internal(server, from, packet, sequence, current_timestamp, encryption_index, client_index);
        }

        static void server_receive_packets(netcode_server_t server)
        {
            assert(server != null);

            var allowed_packets = new bool[CONNECTION_NUM_PACKETS];
            allowed_packets[CONNECTION_REQUEST_PACKET] = true;
            allowed_packets[CONNECTION_RESPONSE_PACKET] = true;
            allowed_packets[CONNECTION_KEEP_ALIVE_PACKET] = true;
            allowed_packets[CONNECTION_PAYLOAD_PACKET] = true;
            allowed_packets[CONNECTION_DISCONNECT_PACKET] = true;

            var current_timestamp = ctime();

            if (server.config.network_simulator == null)
            {
                // process packets received from socket

                while (true)
                {
                    var from = new netcode_address_t();
                    var packet_data = new byte[MAX_PACKET_BYTES];
                    var packet_bytes = 0;

                    if (server.config.override_send_and_receive) packet_bytes = server.config.receive_packet_override(server.config.callback_context, from, packet_data, MAX_PACKET_BYTES);
                    else
                    {
                        if (server.socket_holder.ipv4.handle != null) packet_bytes = socket_receive_packet(server.socket_holder.ipv4, from, packet_data, MAX_PACKET_BYTES);
                        if (packet_bytes == 0 && server.socket_holder.ipv6.handle != null) packet_bytes = socket_receive_packet(server.socket_holder.ipv6, from, packet_data, MAX_PACKET_BYTES);
                    }

                    if (packet_bytes == 0)
                        break;

                    server_read_and_process_packet(server, from, packet_data, packet_bytes, current_timestamp, allowed_packets);
                }
            }
            else
            {
                // process packets received from network simulator

                var num_packets_received = network_simulator_receive_packets(
                    server.config.network_simulator,
                    server.address,
                    SERVER_MAX_RECEIVE_PACKETS,
                    server.receive_packet_data,
                    server.receive_packet_bytes,
                    server.receive_from);

                int i;
                for (i = 0; i < num_packets_received; ++i)
                {
                    server_read_and_process_packet(
                        server,
                        server.receive_from[i],
                        server.receive_packet_data[i],
                        server.receive_packet_bytes[i],
                        current_timestamp,
                        allowed_packets);

                    server.receive_packet_data[i] = null;
                }
            }
        }

        static void server_send_packets(netcode_server_t server)
        {
            assert(server != null);

            if (!server.running)
                return;

            int i;
            for (i = 0; i < server.max_clients; ++i)
                if (server.client_connected[i] && !server.client_loopback[i] && (server.client_last_packet_send_time[i] + (1.0f / PACKET_SEND_RATE) <= server.time))
                {
                    printf(LOG_LEVEL_DEBUG, $"server sent connection keep alive packet to client {i}\n");
                    var packet = new connection_keep_alive_packet_t();
                    packet.packet_type = CONNECTION_KEEP_ALIVE_PACKET;
                    packet.client_index = i;
                    packet.max_clients = server.max_clients;
                    server_send_client_packet(server, packet, i);
                }
        }

        static void server_check_for_timeouts(netcode_server_t server)
        {
            assert(server != null);

            if (!server.running)
                return;

            int i;
            for (i = 0; i < server.max_clients; i++)
            {
                if (!server.client_connected[i])
                    continue;

                if (server.client_timeout[i] <= 0)
                    continue;

                if (server.client_loopback[i])
                    continue;

                if ((server.time - server.client_last_packet_receive_time[i]) >= 1.0f)
                    printf(LOG_LEVEL_DEBUG, $"server has not received a packet from client {i} for {server.time - server.client_last_packet_receive_time[i]:0.00} seconds\n");

                if (server.client_last_packet_receive_time[i] + server.client_timeout[i] <= server.time)
                {
                    printf(LOG_LEVEL_INFO, $"server timed out client {i}\n");
                    server_disconnect_client_internal(server, i, false, SERVER_CLIENT_DISCONNECT_REASON_TIMED_OUT);
                }
            }
        }

        public static bool server_client_connected(this netcode_server_t server, int client_index)
        {
            assert(server != null);

            if (!server.running)
                return false;
            if (client_index < 0 || client_index >= server.max_clients)
                return false;
            return server.client_connected[client_index];
        }

        public static int server_client_disconnect_reason(this netcode_server_t server, int client_index)
        {
            assert(server != null);

            if (!server.running)
                return SERVER_CLIENT_DISCONNECT_REASON_NONE;
            if (client_index < 0 || client_index >= server.max_clients)
                return SERVER_CLIENT_DISCONNECT_REASON_NONE;
            return server.client_disconnect_reason[client_index];
        }

        public static ulong server_client_id(this netcode_server_t server, int client_index)
        {
            assert(server != null);

            if (!server.running)
                return 0;
            if (client_index < 0 || client_index >= server.max_clients)
                return 0;
            return server.client_id[client_index];
        }

        public static netcode_address_t server_client_address(this netcode_server_t server, int client_index)
        {
            assert(server != null);

            if (!server.running)
                return null;
            if (client_index < 0 || client_index >= server.max_clients)
                return null;
            return server.client_address[client_index];
        }

        public static ulong server_next_packet_sequence(this netcode_server_t server, int client_index)
        {
            assert(server != null);
            assert(client_index >= 0);
            assert(client_index < server.max_clients);
            if (!server.running)
                return 0;
            if (client_index < 0 || client_index >= server.max_clients)
                return 0;
            if (!server.client_connected[client_index])
                return 0;
            return server.client_sequence[client_index];
        }

        public static void server_send_packet(this netcode_server_t server, int client_index, byte[] packet_data, int packet_bytes)
        {
            assert(server != null);
            assert(packet_data != null);
            assert(packet_bytes > 0);
            assert(packet_bytes <= MAX_PACKET_SIZE);

            // zero byte payloads are not valid on the wire and would silently vanish at the receiver

            if (packet_bytes <= 0 || packet_bytes > MAX_PACKET_SIZE)
            {
                printf(LOG_LEVEL_ERROR, $"error: payload packet size is out of range ({packet_bytes})\n");
                return;
            }

            if (!server.running)
                return;

            assert(client_index >= 0);
            assert(client_index < server.max_clients);

            if (client_index < 0 || client_index >= server.max_clients)
                return;

            if (!server.client_connected[client_index])
                return;

            if (!server.client_loopback[client_index])
            {
                var packet = new connection_payload_packet_t { payload_data = new byte[packet_bytes] };
                packet.packet_type = CONNECTION_PAYLOAD_PACKET;
                packet.payload_bytes = (ulong)packet_bytes;
                BufferEx.Copy(packet.payload_data, packet_data, packet_bytes);

                if (!server.client_confirmed[client_index])
                {
                    var keep_alive_packet = new connection_keep_alive_packet_t();
                    keep_alive_packet.packet_type = CONNECTION_KEEP_ALIVE_PACKET;
                    keep_alive_packet.client_index = client_index;
                    keep_alive_packet.max_clients = server.max_clients;
                    server_send_client_packet(server, keep_alive_packet, client_index);
                }

                server_send_client_packet(server, packet, client_index);
            }
            else
            {
                assert(server.config.send_loopback_packet_callback != null);

                server.config.send_loopback_packet_callback(
                    server.config.callback_context,
                    client_index,
                    packet_data,
                    packet_bytes,
                    server.client_sequence[client_index]++);

                server.client_last_packet_send_time[client_index] = server.time;
            }
        }

        public static byte[] server_receive_packet(this netcode_server_t server, int client_index, out int packet_bytes, out ulong packet_sequence)
        {
            assert(server != null);

            assert(client_index >= 0);

            packet_bytes = 0;
            packet_sequence = 0;
            if (!server.running)
                return null;

            assert(client_index < server.max_clients);

            if (client_index < 0 || client_index >= server.max_clients)
                return null;

            if (!server.client_connected[client_index])
                return null;

            var packet = (connection_payload_packet_t)packet_queue_pop(server.client_packet_queue[client_index], out packet_sequence);

            if (packet != null)
            {
                assert(packet.packet_type == CONNECTION_PAYLOAD_PACKET);
                packet_bytes = (int)packet.payload_bytes;
                assert(packet_bytes >= 0);
                assert(packet_bytes <= MAX_PAYLOAD_BYTES);
                return packet.payload_data;
            }
            else return null;
        }

        public static void server_free_packet<T>(this netcode_server_t server, ref T packet) where T : class
        {
            assert(server != null);
            assert(packet != null);

            packet = null;
        }

        public static int server_num_connected_clients(this netcode_server_t server)
        {
            assert(server != null);
            return server.num_connected_clients;
        }

        public static byte[] server_client_user_data(this netcode_server_t server, int client_index)
        {
            assert(server != null);
            assert(client_index >= 0);
            assert(client_index < server.max_clients);
            if (!server.running)
                return null;
            if (client_index < 0 || client_index >= server.max_clients)
                return null;
            return server.client_user_data[client_index];
        }

        public static bool server_running(this netcode_server_t server)
        {
            assert(server != null);
            return server.running;
        }

        public static int server_max_clients(this netcode_server_t server) => server.max_clients;

        public static void server_update(this netcode_server_t server, double time)
        {
            assert(server != null);
            server.time = time;
            server_receive_packets(server);
            server_send_packets(server);
            server_check_for_timeouts(server);
        }

        public static void server_connect_loopback_client(this netcode_server_t server, int client_index, ulong client_id, byte[] user_data)
        {
            assert(server != null);
            assert(client_index >= 0);
            assert(client_index < server.max_clients);
            assert(server.running);

            // the server sends to a loopback client only through this callback. without it the
            // first send would call a null reference, so refuse the slot at all, in every build.

            assert(server.config.send_loopback_packet_callback != null);

            if (server.config.send_loopback_packet_callback == null)
            {
                printf(LOG_LEVEL_ERROR, "error: a loopback client requires send_loopback_packet_callback\n");
                return;
            }

            if (!server.running)
                return;

            if (client_index < 0 || client_index >= server.max_clients)
                return;

            assert(!server.client_connected[client_index]);

            if (server.client_connected[client_index])
                return;

            server.num_connected_clients++;

            assert(server.num_connected_clients <= server.max_clients);

            server.client_loopback[client_index] = true;
            server.client_connected[client_index] = true;
            server.client_confirmed[client_index] = true;
            server.client_encryption_index[client_index] = -1;
            server.client_id[client_index] = client_id;
            server.client_sequence[client_index] = 0;
            server.client_disconnect_reason[client_index] = SERVER_CLIENT_DISCONNECT_REASON_NONE;
            BufferEx.SetT(ref server.client_address[client_index], 0);
            server.client_last_packet_send_time[client_index] = server.time;
            server.client_last_packet_receive_time[client_index] = server.time;

            if (user_data != null)
                BufferEx.Copy(server.client_user_data[client_index], user_data, USER_DATA_BYTES);
            else
                BufferEx.Set(server.client_user_data[client_index], 0, USER_DATA_BYTES);

            printf(LOG_LEVEL_INFO, $"server connected loopback client {client_id:x16} in slot {client_index}\n");

            server.config.connect_disconnect_callback?.Invoke(server.config.callback_context, client_index, 1);
        }

        public static void server_disconnect_loopback_client(this netcode_server_t server, int client_index)
        {
            assert(server != null);
            assert(client_index >= 0);
            assert(client_index < server.max_clients);
            assert(server.running);

            if (!server.running)
                return;

            if (client_index < 0 || client_index >= server.max_clients)
                return;

            assert(server.client_connected[client_index]);
            assert(server.client_loopback[client_index]);

            if (!server.client_connected[client_index] || !server.client_loopback[client_index])
                return;

            printf(LOG_LEVEL_INFO, $"server disconnected loopback client {client_index}\n");

            server.client_disconnect_reason[client_index] = SERVER_CLIENT_DISCONNECT_REASON_SERVER_DISCONNECT;

            server.config.connect_disconnect_callback?.Invoke(server.config.callback_context, client_index, 0);

            server_reset_client_slot(server, client_index);
        }

        public static bool server_client_loopback(this netcode_server_t server, int client_index)
        {
            assert(server != null);
            assert(server.running);
            assert(client_index >= 0);
            assert(client_index < server.max_clients);
            if (!server.running)
                return false;
            if (client_index < 0 || client_index >= server.max_clients)
                return false;
            return server.client_loopback[client_index];
        }

        public static void server_process_loopback_packet(this netcode_server_t server, int client_index, byte[] packet_data, int packet_bytes, ulong packet_sequence)
        {
            assert(server != null);
            assert(client_index >= 0);
            assert(client_index < server.max_clients);
            assert(packet_data != null);
            assert(packet_bytes > 0);
            assert(packet_bytes <= MAX_PACKET_SIZE);
            assert(server.running);

            if (!server.running)
                return;

            if (client_index < 0 || client_index >= server.max_clients)
                return;

            assert(server.client_connected[client_index]);
            assert(server.client_loopback[client_index]);

            if (!server.client_connected[client_index] || !server.client_loopback[client_index])
                return;

            if (packet_bytes <= 0 || packet_bytes > MAX_PACKET_SIZE)
                return;

            var packet = create_payload_packet(packet_bytes, server.config.allocator_context, server.config.allocate_function);
            if (packet == null)
                return;

            BufferEx.Copy(packet.payload_data, packet_data, packet_bytes);

            printf(LOG_LEVEL_DEBUG, $"server processing loopback packet from client {client_index}\n");

            server.client_last_packet_receive_time[client_index] = server.time;

            packet_queue_push(server.client_packet_queue[client_index], ref packet, packet_sequence);
        }

        public static ushort server_get_port(this netcode_server_t server)
        {
            assert(server != null);
            return server.address.type == ADDRESS_IPV4 ? server.socket_holder.ipv4.address.port : server.socket_holder.ipv6.address.port;
        }

        #endregion

        #region generate_connect_token

        public static int generate_connect_token(
            int num_server_addresses,
            IList<string> public_server_addresses,
            IList<string> internal_server_addresses,
            int expire_seconds,
            int timeout_seconds,
            ulong client_id,
            ulong protocol_id,
            byte[] private_key,
            byte[] user_data,
            byte[] output_buffer)
        {
            assert(num_server_addresses > 0);
            assert(num_server_addresses <= MAX_SERVERS_PER_CONNECT);
            assert(public_server_addresses != null);
            assert(internal_server_addresses != null);

            // the parsed address arrays below are sized MAX_SERVERS_PER_CONNECT. an out of
            // range value here must not get through in release builds where asserts compile out

            if (num_server_addresses <= 0 || num_server_addresses > MAX_SERVERS_PER_CONNECT)
            {
                printf(LOG_LEVEL_ERROR, $"error: number of server addresses must be in [1,{MAX_SERVERS_PER_CONNECT}], got {num_server_addresses}\n");
                return ERROR;
            }
            assert(private_key != null);
            assert(user_data != null);
            assert(output_buffer != null);

            // parse public server addresses

            var parsed_public_server_addresses = new netcode_address_t[MAX_SERVERS_PER_CONNECT];
            int i;
            for (i = 0; i < num_server_addresses; ++i)
                if (parse_address(public_server_addresses[i], out parsed_public_server_addresses[i]) != OK)
                    return ERROR;

            // parse internal server addresses

            var parsed_internal_server_addresses = new netcode_address_t[MAX_SERVERS_PER_CONNECT];
            for (i = 0; i < num_server_addresses; ++i)
                if (parse_address(internal_server_addresses[i], out parsed_internal_server_addresses[i]) != OK)
                    return ERROR;

            // generate a connect token

            var nonce = new byte[CONNECT_TOKEN_NONCE_BYTES];
            generate_nonce(nonce);

            var connect_token_private = new connect_token_private_t();
            generate_connect_token_private(connect_token_private, client_id, timeout_seconds, num_server_addresses, parsed_internal_server_addresses, user_data);

            // write it to a buffer

            var connect_token_data = new byte[CONNECT_TOKEN_PRIVATE_BYTES];
            write_connect_token_private(connect_token_private, connect_token_data, CONNECT_TOKEN_PRIVATE_BYTES);

            // encrypt the buffer

            var create_timestamp = ctime();
            var expire_timestamp = (expire_seconds >= 0) ? (create_timestamp + (ulong)expire_seconds) : 0xFFFFFFFFFFFFFFFFUL;
            if (encrypt_connect_token_private(connect_token_data, 0, CONNECT_TOKEN_PRIVATE_BYTES, VERSION_INFO, protocol_id, expire_timestamp, nonce, private_key) != OK)
                return ERROR;

            // wrap a connect token around the private connect token data

            var connect_token = new connect_token_t();
            BufferEx.Copy(connect_token.version_info, VERSION_INFO, VERSION_INFO_BYTES);
            connect_token.protocol_id = protocol_id;
            connect_token.create_timestamp = create_timestamp;
            connect_token.expire_timestamp = expire_timestamp;
            BufferEx.Copy(connect_token.nonce, nonce, CONNECT_TOKEN_NONCE_BYTES);
            BufferEx.Copy(connect_token.private_data, connect_token_data, CONNECT_TOKEN_PRIVATE_BYTES);
            connect_token.num_server_addresses = num_server_addresses;
            for (i = 0; i < num_server_addresses; ++i)
                connect_token.server_addresses[i] = parsed_public_server_addresses[i];
            BufferEx.Copy(connect_token.client_to_server_key, connect_token_private.client_to_server_key, KEY_BYTES);
            BufferEx.Copy(connect_token.server_to_client_key, connect_token_private.server_to_client_key, KEY_BYTES);
            connect_token.timeout_seconds = timeout_seconds;

            // write the connect token to the output buffer

            write_connect_token(connect_token, output_buffer, CONNECT_TOKEN_BYTES);

            return OK;
        }

        #endregion

        #region utils

        public static void sleep(double time) => Thread.Sleep((int)(time * 1000));
        public static ulong ctime() => (ulong)(DateTime.UtcNow - new DateTime(1970, 1, 1)).TotalSeconds;
        static readonly Stopwatch time_stopwatch = Stopwatch.StartNew();

        // monotonic seconds since first use, like netcode_time() in C
        public static double time() => time_stopwatch.Elapsed.TotalSeconds;

        #endregion
    }

    #region BufferEx

    public static class BufferEx
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
            //Arrays.CopyOfRange
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

        // memcmp semantics: compares the first length elements (or the whole of both lists when length is null)
        public static bool Equal<T>(IList<T> first, IList<T> second, int? length = null) =>
            Equal(first, 0, second, 0, length);
        public static bool Equal<T>(IList<T> first, int firstOffset, IList<T> second, int secondOffset, int? length = null)
        {
            if (length == null)
            {
                if (first.Count - firstOffset != second.Count - secondOffset)
                    return false;
                length = first.Count - firstOffset;
            }
            if (first.Count - firstOffset < length || second.Count - secondOffset < length)
                return false;
            var comparer = EqualityComparer<T>.Default;
            for (var i = 0; i < length; i++)
                if (!comparer.Equals(first[firstOffset + i], second[secondOffset + i]))
                    return false;
            return true;
        }
    }

    #endregion

    #region Crypto

    /**
        ChaCha20-Poly1305 AEAD (RFC 8439, libsodium "ietf") and XChaCha20-Poly1305 (libsodium "xchacha20poly1305_ietf").
        XChaCha derives a subkey with HChaCha20 over the first 16 nonce bytes, then runs the IETF construction
        with the nonce 0x00000000 || nonce[16..24]. This must match libsodium bit for bit or connect tokens
        will not interoperate with other netcode implementations.
     */
    internal class Crypto_aead
    {
        readonly Org.BouncyCastle.Crypto.Modes.ChaCha20Poly1305 cipher = new Org.BouncyCastle.Crypto.Modes.ChaCha20Poly1305();
        readonly byte[] nonce12 = new byte[12];
        readonly uint[] state = new uint[16];
        readonly byte[] subkey = new byte[32];

        void Prepare(bool bigNonce, byte[] nonce, byte[] key, out byte[] k, out byte[] n)
        {
            if (!bigNonce) { k = key; n = nonce; return; }
            HChaCha20(key, nonce, subkey);
            Array.Clear(nonce12, 0, 4);
            Array.Copy(nonce, 16, nonce12, 4, 8);
            k = subkey; n = nonce12;
        }

        static uint Rotl(uint v, int c) => (v << c) | (v >> (32 - c));

        static void QuarterRound(uint[] x, int a, int b, int c, int d)
        {
            x[a] += x[b]; x[d] = Rotl(x[d] ^ x[a], 16);
            x[c] += x[d]; x[b] = Rotl(x[b] ^ x[c], 12);
            x[a] += x[b]; x[d] = Rotl(x[d] ^ x[a], 8);
            x[c] += x[d]; x[b] = Rotl(x[b] ^ x[c], 7);
        }

        static uint Load32(byte[] b, int o) => (uint)(b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24));

        static void Store32(byte[] b, int o, uint v) { b[o] = (byte)v; b[o + 1] = (byte)(v >> 8); b[o + 2] = (byte)(v >> 16); b[o + 3] = (byte)(v >> 24); }

        void HChaCha20(byte[] key, byte[] nonce, byte[] output)
        {
            var x = state;
            x[0] = 0x61707865; x[1] = 0x3320646e; x[2] = 0x79622d32; x[3] = 0x6b206574;
            for (var i = 0; i < 8; i++) x[4 + i] = Load32(key, i * 4);
            for (var i = 0; i < 4; i++) x[12 + i] = Load32(nonce, i * 4);
            for (var i = 0; i < 10; i++)
            {
                QuarterRound(x, 0, 4, 8, 12); QuarterRound(x, 1, 5, 9, 13); QuarterRound(x, 2, 6, 10, 14); QuarterRound(x, 3, 7, 11, 15);
                QuarterRound(x, 0, 5, 10, 15); QuarterRound(x, 1, 6, 11, 12); QuarterRound(x, 2, 7, 8, 13); QuarterRound(x, 3, 4, 9, 14);
            }
            for (var i = 0; i < 4; i++) Store32(output, i * 4, x[i]);
            for (var i = 0; i < 4; i++) Store32(output, 16 + i * 4, x[12 + i]);
            Array.Clear(x, 0, 16);
        }

        static byte[] Additional(byte[] additional, ulong additional_length)
        {
            if (additional == null) return new byte[0];
            if ((ulong)additional.Length == additional_length) return additional;
            var r = new byte[additional_length];
            Array.Copy(additional, r, (int)additional_length);
            return r;
        }

        /// encrypts message_length bytes of buffer at p in place and appends the MAC. buffer must have MAC_BYTES of room.
        public int Encrypt(bool bigNonce,
            byte[] buffer, int p, out ulong buffer_length,
            byte[] message, ulong message_length,
            byte[] additional, ulong additional_length,
            object unkn, byte[] nonce, byte[] key)
        {
            buffer_length = message_length + netcode.MAC_BYTES;
            try
            {
                Prepare(bigNonce, nonce, key, out var k, out var n);
                cipher.Init(true, new AeadParameters(new KeyParameter(k), netcode.MAC_BYTES * 8, n, Additional(additional, additional_length)));
                var output = new byte[(int)buffer_length];
                var len = cipher.ProcessBytes(buffer, p, (int)message_length, output, 0);
                len += cipher.DoFinal(output, len);
                if ((ulong)len != buffer_length) return -1;
                Array.Copy(output, 0, buffer, p, len);
            }
            catch (CryptoException) { return -1; }
            finally { Array.Clear(subkey, 0, subkey.Length); }
            return 0;
        }

        /// decrypts message_length bytes (ciphertext + MAC) of buffer at p in place. returns -1 if authentication fails.
        public int Decrypt(bool bigNonce,
            byte[] buffer, int p, out ulong buffer_length,
            object unkn,
            byte[] message, ulong message_length,
            byte[] additional, ulong additional_length,
            byte[] nonce, byte[] key)
        {
            buffer_length = message_length - netcode.MAC_BYTES;
            if (message_length < netcode.MAC_BYTES) return -1;
            try
            {
                Prepare(bigNonce, nonce, key, out var k, out var n);
                cipher.Init(false, new AeadParameters(new KeyParameter(k), netcode.MAC_BYTES * 8, n, Additional(additional, additional_length)));
                var output = new byte[(int)buffer_length];
                var len = cipher.ProcessBytes(buffer, p, (int)message_length, output, 0);
                len += cipher.DoFinal(output, len);
                if ((ulong)len != buffer_length) return -1;
                Array.Copy(output, 0, buffer, p, len);
            }
            catch (CryptoException) { return -1; }
            finally { Array.Clear(subkey, 0, subkey.Length); }
            return 0;
        }

        static readonly ConditionalWeakTable<Thread, Crypto_aead> WeakTable = new ConditionalWeakTable<Thread, Crypto_aead>();

        public static Crypto_aead CurrentThread => WeakTable.GetOrCreateValue(Thread.CurrentThread);
    }

    #endregion

}

namespace networkprotocol
{
    public static partial class netcode
    {
        static void check_handler(string condition, string function, string file, int line)
        {
            Console.Write($"check failed: ( {condition} ), function {function}, file {file}, line {line}\n");
            Debugger.Break();
            Environment.Exit(1);
        }

        public static void check(bool condition,
            [CallerArgumentExpression(nameof(condition))] string condition_string = null,
            [CallerMemberName] string function = null,
            [CallerFilePath] string file = null,
            [CallerLineNumber] int line = 0)
        {
            if (!condition)
                check_handler(condition_string, function, file, line);
        }

        // known-answer test against libsodium output (upstream test_crypto_aead_vectors).
        // a failure here means the port no longer interoperates with other netcode implementations.
        static void test_crypto_aead_vectors()
        {
            var kat_key = new byte[] {
                0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,0x49,0x4a,0x4b,
                0x4c,0x4d,0x4e,0x4f,0x50,0x51,0x52,0x53,0x54,0x55,0x56,0x57,
                0x58,0x59,0x5a,0x5b,0x5c,0x5d,0x5e,0x5f,
            };
            var kat_ad = new byte[] {
                0xc0,0xc1,0xc2,0xc3,0xc4,0xc5,0xc6,0xc7,0xc8,0xc9,0xca,0xcb,
            };
            var kat_msg = new byte[] {
                0x79,0x6f,0x6a,0x69,0x6d,0x62,0x6f,0x20,0x76,0x65,0x6e,0x64,0x6f,0x72,0x65,0x64,0x20,0x6c,0x69,0x62,
                0x73,0x6f,0x64,0x69,0x75,0x6d,0x20,0x41,0x45,0x41,0x44,0x20,0x6b,0x6e,0x6f,0x77,0x6e,0x2d,0x61,0x6e,
                0x73,0x77,0x65,0x72,0x20,0x74,0x65,0x73,0x74,0x20,0x76,0x65,0x63,0x74,0x6f,0x72,0x21,0x21,
            };
            var kat_npub_ietf = new byte[] {
                0xa0,0xa1,0xa2,0xa3,0xa4,0xa5,0xa6,0xa7,0xa8,0xa9,0xaa,0xab,
            };
            var kat_ct_ietf = new byte[] {
                0xd5,0xae,0xb1,0x85,0x15,0x8b,0x07,0xb3,0x01,0x15,0xf0,0x59,
                0xb4,0x4e,0x9d,0x45,0x91,0x58,0xab,0xff,0xaf,0xbd,0x81,0x4f,
                0xbf,0x52,0xc2,0x4c,0xa1,0x5e,0x60,0x5f,0x58,0x63,0x31,0x96,
                0xda,0x90,0x07,0x63,0xb9,0x0c,0x21,0x46,0xf2,0xe4,0x65,0x96,
                0x7a,0x81,0x7f,0xa2,0x5d,0xd1,0x79,0xf6,0x9b,0x18,0x5d,0xe0,
                0xb6,0x57,0x93,0xbe,0x8c,0xb5,0xa9,0x75,0x98,0xa4,0x6f,0xd5,
                0xbe,0x9d,
            };
            var kat_npub_xchacha = new byte[] {
                0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,
                0x1c,0x1d,0x1e,0x1f,0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,
            };
            var kat_ct_xchacha = new byte[] {
                0x2b,0x24,0x83,0x2a,0x6c,0x9e,0x21,0x02,0x2a,0x14,0x32,0x56,
                0x4b,0x27,0x37,0x92,0x24,0x40,0xa9,0x92,0xd3,0x53,0xa7,0xa5,
                0x64,0xd3,0x8e,0x0c,0x75,0x79,0x75,0x3f,0xca,0x82,0xfa,0x85,
                0xf0,0xa6,0xac,0x08,0x9a,0x25,0xf1,0x8f,0x42,0x20,0x70,0x8e,
                0x38,0x25,0xd1,0x08,0x45,0x81,0x75,0x18,0xe4,0xd1,0x88,0xbd,
                0x92,0xfa,0x84,0xdc,0xd6,0xa3,0x9a,0x67,0x52,0x91,0x62,0xf4,
                0x86,0x7b,
            };

            foreach (var (npub, ct, big) in new[] { (kat_npub_ietf, kat_ct_ietf, false), (kat_npub_xchacha, kat_ct_xchacha, true) })
            {
                var c = new byte[kat_msg.Length + MAC_BYTES];
                Array.Copy(kat_msg, c, kat_msg.Length);
                check(Crypto_aead.CurrentThread.Encrypt(big, c, 0, out var clen, c, (ulong)kat_msg.Length, kat_ad, (ulong)kat_ad.Length, null, npub, kat_key) == 0);
                check(clen == (ulong)ct.Length);
                check(c.AsSpan().SequenceEqual(ct));
                check(Crypto_aead.CurrentThread.Decrypt(big, c, 0, out var mlen, null, c, clen, kat_ad, (ulong)kat_ad.Length, npub, kat_key) == 0);
                check(mlen == (ulong)kat_msg.Length);
                check(c.AsSpan(0, kat_msg.Length).SequenceEqual(kat_msg));

                // a tampered ciphertext must be rejected
                Array.Copy(ct, c, ct.Length);
                c[0] ^= 0x01;
                check(Crypto_aead.CurrentThread.Decrypt(big, c, 0, out _, null, c, (ulong)ct.Length, kat_ad, (ulong)kat_ad.Length, npub, kat_key) != 0);
            }
        }

        static void test_queue()
        {
            var queue = new packet_queue_t();

            packet_queue_init(queue, null, null, null);

            check(queue.num_packets == 0);
            check(queue.start_index == 0);

            // attempting to pop a packet off an empty queue should return null

            check(packet_queue_pop(queue, out var na) == null);

            // add some packets to the queue and make sure they pop off in the correct order
            {
                const int NUM_PACKETS = 100;

                var packets2 = new object[NUM_PACKETS];

                int i2;
                for (i2 = 0; i2 < NUM_PACKETS; ++i2)
                {
                    packets2[i2] = new byte[(i2 + 1) * 256];
                    check(packet_queue_push(queue, ref packets2[i2], (ulong)i2));
                }

                check(queue.num_packets == NUM_PACKETS);

                for (i2 = 0; i2 < NUM_PACKETS; ++i2)
                {
                    var packet = packet_queue_pop(queue, out var sequence);
                    check(sequence == (ulong)i2);
                    check(packet == packets2[i2]);
                    packet = null;
                }
            }

            // after all entries are popped off, the queue is empty, so calls to pop should return null

            check(queue.num_packets == 0);

            check(packet_queue_pop(queue, out var na2) == null);

            // test that the packet queue can be filled to max capacity

            var packets = new object[PACKET_QUEUE_SIZE];

            int i;
            for (i = 0; i < PACKET_QUEUE_SIZE; ++i)
            {
                packets[i] = new byte[i * 256];
                check(packet_queue_push(queue, ref packets[i], (ulong)i));
            }

            check(queue.num_packets == PACKET_QUEUE_SIZE);

            // when the queue is full, attempting to push a packet should fail and return 0
            var packet3 = (object)new byte[100];
            check(!packet_queue_push(queue, ref packet3, 0));

            // make sure all packets pop off in the correct order

            for (i = 0; i < PACKET_QUEUE_SIZE; ++i)
            {
                var packet = packet_queue_pop(queue, out var sequence);
                check(sequence == (ulong)i);
                check(packet == packets[i]);
                packet = null;
            }

            // add some packets again

            for (i = 0; i < PACKET_QUEUE_SIZE; ++i)
            {
                packets[i] = new byte[i * 256];
                check(packet_queue_push(queue, ref packets[i], (ulong)i));
            }

            // clear the queue and make sure that all packets are freed

            packet_queue_clear(queue);

            check(queue.start_index == 0);
            check(queue.num_packets == 0);
            for (i = 0; i < PACKET_QUEUE_SIZE; ++i)
                check(queue.packet_data[i] == null);
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

        static void test_sequence()
        {
            check(sequence_number_bytes_required(0) == 1);
            check(sequence_number_bytes_required(0x11) == 1);
            check(sequence_number_bytes_required(0x1122) == 2);
            check(sequence_number_bytes_required(0x112233) == 3);
            check(sequence_number_bytes_required(0x11223344) == 4);
            check(sequence_number_bytes_required(0x1122334455) == 5);
            check(sequence_number_bytes_required(0x112233445566) == 6);
            check(sequence_number_bytes_required(0x11223344556677) == 7);
            check(sequence_number_bytes_required(0x1122334455667788) == 8);
        }

        static void test_address()
        {
            {
                check(parse_address("", out var address) == ERROR);
                check(parse_address("[", out address) == ERROR);
                check(parse_address("[]", out address) == ERROR);
                check(parse_address("[]:", out address) == ERROR);
                check(parse_address(":", out address) == ERROR);
                //check(parse_address("1", out address) == ERROR);
                //check(parse_address("12", out address) == ERROR);
                //check(parse_address("123", out address) == ERROR);
                //check(parse_address("1234", out address) == ERROR);
                check(parse_address("1234.0.12313.0000", out address) == ERROR);
                check(parse_address("1234.0.12313.0000.0.0.0.0.0", out address) == ERROR);
                check(parse_address("1312313:123131:1312313:123131:1312313:123131:1312313:123131:1312313:123131:1312313:123131", out address) == ERROR);
                check(parse_address(".", out address) == ERROR);
                check(parse_address("..", out address) == ERROR);
                check(parse_address("...", out address) == ERROR);
                check(parse_address("....", out address) == ERROR);
                check(parse_address(".....", out address) == ERROR);
            }

            {
                check(parse_address("107.77.207.77", out var address) == OK);
                check(address.type == ADDRESS_IPV4);
                check(address.port == 0);
                check(BufferEx.Equal(address.data.GetAddressBytes(), new byte[] {
                    107, 77, 207, 77
                }, 4));
            }

            {
                check(parse_address("127.0.0.1", out var address) == OK);
                check(address.type == ADDRESS_IPV4);
                check(address.port == 0);
                check(BufferEx.Equal(address.data.GetAddressBytes(), new byte[] {
                    127, 0, 0, 1
                }, 4));
            }

            {
                check(parse_address("107.77.207.77:40000", out var address) == OK);
                check(address.type == ADDRESS_IPV4);
                check(address.port == 40000);
                check(BufferEx.Equal(address.data.GetAddressBytes(), new byte[] {
                    107, 77, 207, 77
                }, 4));
            }

            {
                check(parse_address("127.0.0.1:40000", out var address) == OK);
                check(address.type == ADDRESS_IPV4);
                check(address.port == 40000);
                check(BufferEx.Equal(address.data.GetAddressBytes(), new byte[] {
                    127, 0, 0, 1
                }, 4));
            }

            {
                check(parse_address("fe80::202:b3ff:fe1e:8329", out var address) == OK);
                check(address.type == ADDRESS_IPV6);
                check(address.port == 0);
                check(BufferEx.Equal(address.data.GetAddressBytes(), new ushort[] {
                    0xfe80, 0x0000, 0x0000, 0x0000, 0x0202, 0xb3ff, 0xfe1e, 0x8329
                }.SelectMany(z => BitConverter.GetBytes(z).Reverse()).ToArray(), 16));
            }

            {
                check(parse_address("::", out var address) == OK);
                check(address.type == ADDRESS_IPV6);
                check(address.port == 0);
                check(BufferEx.Equal(address.data.GetAddressBytes(), new ushort[] {
                    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000
                }.SelectMany(z => BitConverter.GetBytes(z).Reverse()).ToArray(), 16));
            }

            {
                check(parse_address("::1", out var address) == OK);
                check(address.type == ADDRESS_IPV6);
                check(address.port == 0);
                check(BufferEx.Equal(address.data.GetAddressBytes(), new ushort[] {
                    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0001
                }.SelectMany(z => BitConverter.GetBytes(z).Reverse()).ToArray(), 16));
            }

            {
                check(parse_address("[fe80::202:b3ff:fe1e:8329]:40000", out var address) == OK);
                check(address.type == ADDRESS_IPV6);
                check(address.port == 40000);
                check(BufferEx.Equal(address.data.GetAddressBytes(), new ushort[] {
                    0xfe80, 0x0000, 0x0000, 0x0000, 0x0202, 0xb3ff, 0xfe1e, 0x8329
                }.SelectMany(z => BitConverter.GetBytes(z).Reverse()).ToArray(), 16));
            }

            {
                check(parse_address("[::]:40000", out var address) == OK);
                check(address.type == ADDRESS_IPV6);
                check(address.port == 40000);
                check(BufferEx.Equal(address.data.GetAddressBytes(), new ushort[] {
                    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000
                }.SelectMany(z => BitConverter.GetBytes(z).Reverse()).ToArray(), 16));
            }

            {
                check(parse_address("[::1]:40000", out var address) == OK);
                check(address.type == ADDRESS_IPV6);
                check(address.port == 40000);
                check(BufferEx.Equal(address.data.GetAddressBytes(), new ushort[] {
                    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0001
                }.SelectMany(z => BitConverter.GetBytes(z).Reverse()).ToArray(), 16));
            }

            // ports must be all digits in [0,65535]. out of range and non-numeric ports must not silently truncate

            {
                check(parse_address("127.0.0.1:65535", out var address) == OK);
                check(address.type == ADDRESS_IPV4);
                check(address.port == 65535);
                check(parse_address("[::1]:65535", out address) == OK);
                check(address.type == ADDRESS_IPV6);
                check(address.port == 65535);
                check(parse_address("127.0.0.1:65536", out address) == ERROR);
                check(parse_address("127.0.0.1:99999", out address) == ERROR);
                check(parse_address("127.0.0.1:", out address) == ERROR);
                check(parse_address("127.0.0.1:40k", out address) == ERROR);
                check(parse_address("[::1]:65536", out address) == ERROR);
                check(parse_address("[::1]:", out address) == ERROR);
                check(parse_address("[::1]:40k", out address) == ERROR);
            }

            // inet_pton only accepts four dotted decimal octets

            {
                check(parse_address("1", out var address) == ERROR);
                check(parse_address("12", out address) == ERROR);
                check(parse_address("123", out address) == ERROR);
                check(parse_address("1234", out address) == ERROR);
                check(parse_address("127.1", out address) == ERROR);
                check(parse_address("127.1:5", out address) == ERROR);
            }

            // bracketed ipv6 addresses with short ports, and without a port

            test_address_ipv6("::0", 0, new ushort[] { 0, 0, 0, 0, 0, 0, 0, 0 });
            test_address_ipv6("[::1]", 0, new ushort[] { 0, 0, 0, 0, 0, 0, 0, 1 });
            test_address_ipv6("[::0]", 0, new ushort[] { 0, 0, 0, 0, 0, 0, 0, 0 });
            test_address_ipv6("[fe80::1]", 0, new ushort[] { 0xfe80, 0, 0, 0, 0, 0, 0, 1 });
            test_address_ipv6("[::1]:5", 5, new ushort[] { 0, 0, 0, 0, 0, 0, 0, 1 });
            test_address_ipv6("[fe80::1]:5", 5, new ushort[] { 0xfe80, 0, 0, 0, 0, 0, 0, 1 });
            test_address_ipv6("[::1]:400", 400, new ushort[] { 0, 0, 0, 0, 0, 0, 0, 1 });
            test_address_ipv6("[::1]:4000", 4000, new ushort[] { 0, 0, 0, 0, 0, 0, 0, 1 });

            // address equality, including addresses that were never set

            {
                check(!address_equal(new netcode_address_t(), new netcode_address_t()));
                check(parse_address("127.0.0.1:40000", out var a) == OK);
                check(parse_address("127.0.0.1:40000", out var b) == OK);
                check(address_equal(a, b));
                check(parse_address("127.0.0.1:40001", out b) == OK);
                check(!address_equal(a, b));
                check(!address_equal(a, new netcode_address_t()));
            }

            // address to string matches the C formatting

            {
                check(parse_address("127.0.0.1:40000", out var address) == OK);
                check(address_to_string(address) == "127.0.0.1:40000");
                check(parse_address("127.0.0.1", out address) == OK);
                check(address_to_string(address) == "127.0.0.1");
                check(parse_address("[::1]:40000", out address) == OK);
                check(address_to_string(address) == "[::1]:40000");
                check(parse_address("::1", out address) == OK);
                check(address_to_string(address) == "::1");
            }
        }

        static void test_address_ipv6(string address_string, ushort port, ushort[] expected)
        {
            check(parse_address(address_string, out var address) == OK);
            check(address.type == ADDRESS_IPV6);
            check(address.port == port);
            var bytes = address.data.GetAddressBytes();
            for (var i = 0; i < 8; i++)
                check(((bytes[i * 2] << 8) | bytes[i * 2 + 1]) == expected[i]);
        }

        const ulong TEST_PROTOCOL_ID = 0x1122334455667788UL;
        const ulong TEST_CLIENT_ID = 0x1UL;
        const int TEST_SERVER_PORT = 40000;
        const int TEST_CONNECT_TOKEN_EXPIRY = 30;
        const int TEST_TIMEOUT_SECONDS = 15;

        static void test_connect_token()
        {
            // generate a connect token

            var server_address = new netcode_address_t();
            server_address.type = ADDRESS_IPV4;
            server_address.data = IPAddress.Loopback;
            server_address.port = TEST_SERVER_PORT;

            var user_data = new byte[USER_DATA_BYTES];
            random_bytes(user_data, USER_DATA_BYTES);

            var input_token = new connect_token_private_t();

            generate_connect_token_private(input_token, TEST_CLIENT_ID, TEST_TIMEOUT_SECONDS, 1, new[] { server_address }, user_data);

            check(input_token.client_id == TEST_CLIENT_ID);
            check(input_token.num_server_addresses == 1);
            check(BufferEx.Equal(input_token.user_data, user_data, USER_DATA_BYTES));
            check(address_equal(input_token.server_addresses[0], server_address));

            // write it to a buffer

            var buffer = new byte[CONNECT_TOKEN_PRIVATE_BYTES];

            write_connect_token_private(input_token, buffer, CONNECT_TOKEN_PRIVATE_BYTES);

            // encrypt the buffer

            var expire_timestamp = (ulong)(DateTime.Now.Ticks + 30);
            var nonce = new byte[CONNECT_TOKEN_NONCE_BYTES];
            generate_nonce(nonce);
            var key = new byte[KEY_BYTES];
            generate_key(key);

            check(encrypt_connect_token_private(
                buffer, 0,
                CONNECT_TOKEN_PRIVATE_BYTES,
                VERSION_INFO,
                TEST_PROTOCOL_ID,
                expire_timestamp,
                nonce,
                key) == OK);

            // decrypt the buffer

            check(decrypt_connect_token_private(
                buffer, 0,
                CONNECT_TOKEN_PRIVATE_BYTES,
                VERSION_INFO,
                TEST_PROTOCOL_ID,
                expire_timestamp,
                nonce,
                key) == OK);

            // read the connect token back in

            var output_token = new connect_token_private_t();

            check(read_connect_token_private(buffer, CONNECT_TOKEN_PRIVATE_BYTES, output_token) == OK);

            // make sure that everything matches the original connect token

            check(output_token.client_id == input_token.client_id);
            check(output_token.timeout_seconds == input_token.timeout_seconds);
            check(output_token.num_server_addresses == input_token.num_server_addresses);
            check(address_equal(output_token.server_addresses[0], input_token.server_addresses[0]));
            check(BufferEx.Equal(output_token.client_to_server_key, input_token.client_to_server_key, KEY_BYTES));
            check(BufferEx.Equal(output_token.server_to_client_key, input_token.server_to_client_key, KEY_BYTES));
            check(BufferEx.Equal(output_token.user_data, input_token.user_data, USER_DATA_BYTES));
        }

        static int test_oor_asserts_fired = 0;

        static void test_oor_assert_handler(string condition, string function, string file, int line)
        {
            test_oor_asserts_fired++;
            // deliberately RETURNS. a custom handler may do this and execution continues past the failed
            // assert -- which is the only way to reach the release-build code path from a debug test build.
        }

        static void test_generate_connect_token_out_of_range()
        {
            // generate_connect_token parses into arrays sized MAX_SERVERS_PER_CONNECT. the bounds used
            // to be assert-only. the asserts fire first by design, so this installs a handler that returns
            // in order to reach the runtime check underneath them.

            var private_key = new byte[KEY_BYTES];
            var user_data = new byte[USER_DATA_BYTES];
            var connect_token = new byte[CONNECT_TOKEN_BYTES];

            var server_address = new[] { "127.0.0.1:40000" };

            test_oor_asserts_fired = 0;
            set_assert_function(test_oor_assert_handler);

            check(generate_connect_token(0, server_address, server_address, 30, 5, 1000UL, TEST_PROTOCOL_ID, private_key, user_data, connect_token) == ERROR);
            check(generate_connect_token(-1, server_address, server_address, 30, 5, 1000UL, TEST_PROTOCOL_ID, private_key, user_data, connect_token) == ERROR);
            check(generate_connect_token(MAX_SERVERS_PER_CONNECT + 1, server_address, server_address, 30, 5, 1000UL, TEST_PROTOCOL_ID, private_key, user_data, connect_token) == ERROR);

            // in a DEBUG build the asserts must still have fired -- they are the caller's debug aid

#if DEBUG
            check(test_oor_asserts_fired > 0);
#endif

            set_assert_function(default_assert_handler);

            // and an in-range call still succeeds, so the guard cannot pass by rejecting everything

            check(generate_connect_token(1, server_address, server_address, 30, 5, 1000UL, TEST_PROTOCOL_ID, private_key, user_data, connect_token) == OK);
        }

        static void test_challenge_token()
        {
            // generate a challenge token

            var input_token = new challenge_token_t();

            input_token.client_id = TEST_CLIENT_ID;
            random_bytes(input_token.user_data, USER_DATA_BYTES);

            // write it to a buffer

            var buffer = new byte[CHALLENGE_TOKEN_BYTES];

            write_challenge_token(input_token, buffer, CHALLENGE_TOKEN_BYTES);

            // encrypt the buffer

            var sequence = 1000UL;
            var key = new byte[KEY_BYTES];
            generate_key(key);

            check(encrypt_challenge_token(buffer, 0, CHALLENGE_TOKEN_BYTES, sequence, key) == OK);

            // decrypt the buffer

            check(decrypt_challenge_token(buffer, 0, CHALLENGE_TOKEN_BYTES, sequence, key) == OK);

            // read the challenge token back in

            var output_token = new challenge_token_t();

            check(read_challenge_token(buffer, CHALLENGE_TOKEN_BYTES, output_token) == OK);

            // make sure that everything matches the original challenge token

            check(output_token.client_id == input_token.client_id);
            check(BufferEx.Equal(output_token.user_data, input_token.user_data, USER_DATA_BYTES));
        }

        static void test_connection_request_packet()
        {
            // generate a connect token

            var server_address = new netcode_address_t();
            server_address.type = ADDRESS_IPV4;
            server_address.data = IPAddress.Loopback;
            server_address.port = TEST_SERVER_PORT;

            var user_data = new byte[USER_DATA_BYTES];
            random_bytes(user_data, USER_DATA_BYTES);

            var input_token = new connect_token_private_t();

            generate_connect_token_private(input_token, TEST_CLIENT_ID, TEST_TIMEOUT_SECONDS, 1, new[] { server_address }, user_data);

            check(input_token.client_id == TEST_CLIENT_ID);
            check(input_token.num_server_addresses == 1);
            check(BufferEx.Equal(input_token.user_data, user_data, USER_DATA_BYTES));
            check(address_equal(input_token.server_addresses[0], server_address));

            // write the conect token to a buffer (non-encrypted)

            var connect_token_data = new byte[CONNECT_TOKEN_PRIVATE_BYTES];

            write_connect_token_private(input_token, connect_token_data, CONNECT_TOKEN_PRIVATE_BYTES);

            // copy to a second buffer then encrypt it in place (we need the unencrypted token for verification later on)

            var encrypted_connect_token_data = new byte[CONNECT_TOKEN_PRIVATE_BYTES];

            BufferEx.Copy(encrypted_connect_token_data, connect_token_data, CONNECT_TOKEN_PRIVATE_BYTES);

            var connect_token_expire_timestamp = (ulong)(DateTime.Now.Ticks + 30);
            var connect_token_nonce = new byte[CONNECT_TOKEN_NONCE_BYTES];
            generate_nonce(connect_token_nonce);
            var connect_token_key = new byte[KEY_BYTES];
            generate_key(connect_token_key);

            check(encrypt_connect_token_private(
                encrypted_connect_token_data, 0,
                CONNECT_TOKEN_PRIVATE_BYTES,
                VERSION_INFO,
                TEST_PROTOCOL_ID,
                connect_token_expire_timestamp,
                connect_token_nonce,
                connect_token_key) == OK);

            // setup a connection request packet wrapping the encrypted connect token

            var input_packet = new connection_request_packet_t();

            input_packet.packet_type = CONNECTION_REQUEST_PACKET;
            BufferEx.Copy(input_packet.version_info, VERSION_INFO, VERSION_INFO_BYTES);
            input_packet.protocol_id = TEST_PROTOCOL_ID;
            input_packet.connect_token_expire_timestamp = connect_token_expire_timestamp;
            BufferEx.Copy(input_packet.connect_token_nonce, connect_token_nonce, CONNECT_TOKEN_NONCE_BYTES);
            BufferEx.Copy(input_packet.connect_token_data, encrypted_connect_token_data, CONNECT_TOKEN_PRIVATE_BYTES);

            // write the connection request packet to a buffer

            var buffer = new byte[2048];

            var packet_key = new byte[KEY_BYTES];

            generate_key(packet_key);

            var bytes_written = write_packet(input_packet, buffer, buffer.Length, 1000, packet_key, TEST_PROTOCOL_ID);

            check(bytes_written > 0);

            // read the connection request packet back in from the buffer (the connect token data is decrypted as part of the read packet validation)

            var allowed_packets = new bool[CONNECTION_NUM_PACKETS];
            BufferEx.Set(allowed_packets, 1);

            var output_packet = (connection_request_packet_t)read_packet(buffer, bytes_written, out var sequence, packet_key, TEST_PROTOCOL_ID, ctime(), 0, connect_token_key, allowed_packets, null, null, null);

            check(output_packet != null);

            // make sure the read packet matches what was written

            check(output_packet.packet_type == CONNECTION_REQUEST_PACKET);
            check(BufferEx.Equal(output_packet.version_info, input_packet.version_info, VERSION_INFO_BYTES));
            check(output_packet.protocol_id == input_packet.protocol_id);
            check(output_packet.connect_token_expire_timestamp == input_packet.connect_token_expire_timestamp);
            check(BufferEx.Equal(output_packet.connect_token_nonce, input_packet.connect_token_nonce, CONNECT_TOKEN_NONCE_BYTES));
            check(BufferEx.Equal(output_packet.connect_token_data, connect_token_data, CONNECT_TOKEN_PRIVATE_BYTES - MAC_BYTES));

            output_packet = null;
        }

        static void test_connection_denied_packet()
        {
            // setup a connection denied packet

            var input_packet = new connection_denied_packet_t();

            input_packet.packet_type = CONNECTION_DENIED_PACKET;

            // write the packet to a buffer

            var buffer = new byte[MAX_PACKET_BYTES];

            var packet_key = new byte[KEY_BYTES];

            generate_key(packet_key);

            var bytes_written = write_packet(input_packet, buffer, buffer.Length, 1000, packet_key, TEST_PROTOCOL_ID);

            check(bytes_written > 0);

            // read the packet back in from the buffer

            var allowed_packet_types = new bool[CONNECTION_NUM_PACKETS];
            BufferEx.Set(allowed_packet_types, 1);

            var output_packet = (connection_denied_packet_t)read_packet(buffer, bytes_written, out var sequence, packet_key, TEST_PROTOCOL_ID, ctime(), 0, null, allowed_packet_types, null, null, null);

            check(output_packet != null);

            // make sure the read packet matches what was written

            check(output_packet.packet_type == CONNECTION_DENIED_PACKET);

            output_packet = null;
        }

        static void test_connection_challenge_packet()
        {
            // setup a connection challenge packet

            var input_packet = new connection_challenge_packet_t();

            input_packet.packet_type = CONNECTION_CHALLENGE_PACKET;
            input_packet.challenge_token_sequence = 0;
            random_bytes(input_packet.challenge_token_data, CHALLENGE_TOKEN_BYTES);

            // write the packet to a buffer

            var buffer = new byte[MAX_PACKET_BYTES];

            var packet_key = new byte[KEY_BYTES];

            generate_key(packet_key);

            var bytes_written = write_packet(input_packet, buffer, buffer.Length, 1000, packet_key, TEST_PROTOCOL_ID);

            check(bytes_written > 0);

            // read the packet back in from the buffer

            var allowed_packet_types = new bool[CONNECTION_NUM_PACKETS];
            BufferEx.Set(allowed_packet_types, 1);

            var output_packet = (connection_challenge_packet_t)read_packet(buffer, bytes_written, out var sequence, packet_key, TEST_PROTOCOL_ID, ctime(), 0, null, allowed_packet_types, null, null, null);

            check(output_packet != null);

            // make sure the read packet packet matches what was written

            check(output_packet.packet_type == CONNECTION_CHALLENGE_PACKET);
            check(output_packet.challenge_token_sequence == input_packet.challenge_token_sequence);
            check(BufferEx.Equal(output_packet.challenge_token_data, input_packet.challenge_token_data, CHALLENGE_TOKEN_BYTES));

            output_packet = null;
        }

        static void test_connection_response_packet()
        {
            // setup a connection response packet

            var input_packet = new connection_response_packet_t();

            input_packet.packet_type = CONNECTION_RESPONSE_PACKET;
            input_packet.challenge_token_sequence = 0;
            random_bytes(input_packet.challenge_token_data, CHALLENGE_TOKEN_BYTES);

            // write the packet to a buffer

            var buffer = new byte[MAX_PACKET_BYTES];

            var packet_key = new byte[KEY_BYTES];

            generate_key(packet_key);

            var bytes_written = write_packet(input_packet, buffer, buffer.Length, 1000, packet_key, TEST_PROTOCOL_ID);

            check(bytes_written > 0);

            // read the packet back in from the buffer

            var allowed_packet_types = new bool[CONNECTION_NUM_PACKETS];
            BufferEx.Set(allowed_packet_types, 1);

            var output_packet = (connection_response_packet_t)read_packet(buffer, bytes_written, out var sequence, packet_key, TEST_PROTOCOL_ID, ctime(), 0, null, allowed_packet_types, null, null, null);

            check(output_packet != null);

            // make sure the read packet matches what was written

            check(output_packet.packet_type == CONNECTION_RESPONSE_PACKET);
            check(output_packet.challenge_token_sequence == input_packet.challenge_token_sequence);
            check(BufferEx.Equal(output_packet.challenge_token_data, input_packet.challenge_token_data, CHALLENGE_TOKEN_BYTES));

            output_packet = null;
        }

        static void test_connection_keep_alive_packet()
        {
            // setup a connection keep alive packet

            var input_packet = new connection_keep_alive_packet_t();

            input_packet.packet_type = CONNECTION_KEEP_ALIVE_PACKET;
            input_packet.client_index = 10;
            input_packet.max_clients = 16;

            // write the packet to a buffer

            var buffer = new byte[MAX_PACKET_BYTES];

            var packet_key = new byte[KEY_BYTES];

            generate_key(packet_key);

            var bytes_written = write_packet(input_packet, buffer, buffer.Length, 1000, packet_key, TEST_PROTOCOL_ID);

            check(bytes_written > 0);

            // read the packet back in from the buffer

            var allowed_packet_types = new bool[CONNECTION_NUM_PACKETS];
            BufferEx.Set(allowed_packet_types, 1);

            var output_packet = (connection_keep_alive_packet_t)read_packet(buffer, bytes_written, out var sequence, packet_key, TEST_PROTOCOL_ID, ctime(), 0, null, allowed_packet_types, null, null, null);

            check(output_packet != null);

            // make sure the read packet matches what was written

            check(output_packet.packet_type == CONNECTION_KEEP_ALIVE_PACKET);
            check(output_packet.client_index == input_packet.client_index);
            check(output_packet.max_clients == input_packet.max_clients);

            output_packet = null;
        }

        static void test_connection_payload_packet()
        {
            // setup a connection payload packet

            var input_packet = create_payload_packet(MAX_PAYLOAD_BYTES, null, null);

            check(input_packet.packet_type == CONNECTION_PAYLOAD_PACKET);
            check(input_packet.payload_bytes == MAX_PAYLOAD_BYTES);

            random_bytes(input_packet.payload_data, MAX_PAYLOAD_BYTES);

            // write the packet to a buffer

            var buffer = new byte[MAX_PACKET_BYTES];

            var packet_key = new byte[KEY_BYTES];

            generate_key(packet_key);

            var bytes_written = write_packet(input_packet, buffer, buffer.Length, 1000, packet_key, TEST_PROTOCOL_ID);

            check(bytes_written > 0);

            // read the packet back in from the buffer

            var allowed_packet_types = new bool[CONNECTION_NUM_PACKETS];
            BufferEx.Set(allowed_packet_types, 1);

            var output_packet = (connection_payload_packet_t)read_packet(buffer, bytes_written, out var sequence, packet_key, TEST_PROTOCOL_ID, ctime(), 0, null, allowed_packet_types, null, null, null);

            check(output_packet != null);

            // make sure the read packet matches what was written

            check(output_packet.packet_type == CONNECTION_PAYLOAD_PACKET);
            check(output_packet.payload_bytes == input_packet.payload_bytes);
            check(BufferEx.Equal(output_packet.payload_data, input_packet.payload_data, MAX_PAYLOAD_BYTES));

            input_packet = null;
            output_packet = null;
        }

        static void test_connection_disconnect_packet()
        {
            // setup a connection disconnect packet

            var input_packet = new connection_disconnect_packet_t();

            input_packet.packet_type = CONNECTION_DISCONNECT_PACKET;

            // write the packet to a buffer

            var buffer = new byte[MAX_PACKET_BYTES];

            var packet_key = new byte[KEY_BYTES];

            generate_key(packet_key);

            var bytes_written = write_packet(input_packet, buffer, buffer.Length, 1000, packet_key, TEST_PROTOCOL_ID);

            check(bytes_written > 0);

            // read the packet back in from the buffer

            var allowed_packet_types = new bool[CONNECTION_NUM_PACKETS];
            BufferEx.Set(allowed_packet_types, 1);

            var output_packet = (connection_disconnect_packet_t)read_packet(buffer, bytes_written, out var sequence, packet_key, TEST_PROTOCOL_ID, ctime(), 0, null, allowed_packet_types, null, null, null);

            check(output_packet != null);

            // make sure the read packet matches what was written

            check(output_packet.packet_type == CONNECTION_DISCONNECT_PACKET);

            output_packet = null;
        }

        static void test_connect_token_public()
        {
            // generate a private connect token

            var server_address = new netcode_address_t();
            server_address.type = ADDRESS_IPV4;
            server_address.data = IPAddress.Loopback;
            server_address.port = TEST_SERVER_PORT;

            var user_data = new byte[USER_DATA_BYTES];
            random_bytes(user_data, USER_DATA_BYTES);

            var connect_token_private = new connect_token_private_t();

            generate_connect_token_private(connect_token_private, TEST_CLIENT_ID, TEST_TIMEOUT_SECONDS, 1, new[] { server_address }, user_data);

            check(connect_token_private.client_id == TEST_CLIENT_ID);
            check(connect_token_private.num_server_addresses == 1);
            check(BufferEx.Equal(connect_token_private.user_data, user_data, USER_DATA_BYTES));
            check(address_equal(connect_token_private.server_addresses[0], server_address));

            // write it to a buffer

            var connect_token_private_data = new byte[CONNECT_TOKEN_PRIVATE_BYTES];
            write_connect_token_private(connect_token_private, connect_token_private_data, CONNECT_TOKEN_PRIVATE_BYTES);

            // encrypt the buffer

            var create_timestamp = ctime();
            var expire_timestamp = create_timestamp + 30;
            var connect_token_nonce = new byte[CONNECT_TOKEN_NONCE_BYTES];
            generate_nonce(connect_token_nonce);
            var key = new byte[KEY_BYTES];
            generate_key(key);
            check(encrypt_connect_token_private(
                connect_token_private_data, 0,
                CONNECT_TOKEN_PRIVATE_BYTES,
                VERSION_INFO,
                TEST_PROTOCOL_ID,
                expire_timestamp,
                connect_token_nonce,
                key) == 1);

            // wrap a public connect token around the private connect token data

            var input_connect_token = new connect_token_t();
            BufferEx.Copy(input_connect_token.version_info, VERSION_INFO, VERSION_INFO_BYTES);
            input_connect_token.protocol_id = TEST_PROTOCOL_ID;
            input_connect_token.create_timestamp = create_timestamp;
            input_connect_token.expire_timestamp = expire_timestamp;
            BufferEx.Copy(input_connect_token.nonce, connect_token_nonce, CONNECT_TOKEN_NONCE_BYTES);
            BufferEx.Copy(input_connect_token.private_data, connect_token_private_data, CONNECT_TOKEN_PRIVATE_BYTES);
            input_connect_token.num_server_addresses = 1;
            input_connect_token.server_addresses[0] = server_address;
            BufferEx.Copy(input_connect_token.client_to_server_key, connect_token_private.client_to_server_key, KEY_BYTES);
            BufferEx.Copy(input_connect_token.server_to_client_key, connect_token_private.server_to_client_key, KEY_BYTES);
            input_connect_token.timeout_seconds = TEST_TIMEOUT_SECONDS;

            // write the connect token to a buffer

            var buffer = new byte[CONNECT_TOKEN_BYTES];
            write_connect_token(input_connect_token, buffer, CONNECT_TOKEN_BYTES);

            // read the buffer back in

            var output_connect_token = new connect_token_t();
            check(read_connect_token(buffer, CONNECT_TOKEN_BYTES, output_connect_token) == 1);

            // make sure the public connect token matches what was written

            check(BufferEx.Equal(output_connect_token.version_info, input_connect_token.version_info, VERSION_INFO_BYTES));
            check(output_connect_token.protocol_id == input_connect_token.protocol_id);
            check(output_connect_token.create_timestamp == input_connect_token.create_timestamp);
            check(output_connect_token.expire_timestamp == input_connect_token.expire_timestamp);
            check(BufferEx.Equal(output_connect_token.nonce, input_connect_token.nonce, CONNECT_TOKEN_NONCE_BYTES));
            check(BufferEx.Equal(output_connect_token.private_data, input_connect_token.private_data, CONNECT_TOKEN_PRIVATE_BYTES));
            check(output_connect_token.num_server_addresses == input_connect_token.num_server_addresses);
            check(address_equal(output_connect_token.server_addresses[0], input_connect_token.server_addresses[0]));
            check(BufferEx.Equal(output_connect_token.client_to_server_key, input_connect_token.client_to_server_key, KEY_BYTES));
            check(BufferEx.Equal(output_connect_token.server_to_client_key, input_connect_token.server_to_client_key, KEY_BYTES));
            check(output_connect_token.timeout_seconds == input_connect_token.timeout_seconds);
        }

        internal class encryption_mapping_t
        {
            public netcode_address_t address = new netcode_address_t();
            public byte[] send_key = new byte[KEY_BYTES];
            public byte[] receive_key = new byte[KEY_BYTES];
        }

        const int NUM_ENCRYPTION_MAPPINGS = 5;

        static void test_encryption_manager()
        {
            var encryption_manager = new encryption_manager_t();

            encryption_manager_reset(encryption_manager);

            var time = 100.0;

            // generate some test encryption mappings

            var encryption_mapping = new encryption_mapping_t[NUM_ENCRYPTION_MAPPINGS];
            BufferEx.SetT(encryption_mapping, 0);
            int i;
            for (i = 0; i < NUM_ENCRYPTION_MAPPINGS; ++i)
            {
                encryption_mapping[i].address.type = ADDRESS_IPV6;
                encryption_mapping[i].address.data = IPAddress.Loopback;
                encryption_mapping[i].address.port = (ushort)(20000 + i);
                generate_key(encryption_mapping[i].send_key);
                generate_key(encryption_mapping[i].receive_key);
            }

            // add the encryption mappings to the manager and make sure they can be looked up by address

            for (i = 0; i < NUM_ENCRYPTION_MAPPINGS; ++i)
            {
                var encryption_index = encryption_manager_find_encryption_mapping(encryption_manager, encryption_mapping[i].address, time);

                check(encryption_index == -1);

                check(encryption_manager_get_send_key(encryption_manager, encryption_index) == null);
                check(encryption_manager_get_receive_key(encryption_manager, encryption_index) == null);

                check(encryption_manager_add_encryption_mapping(
                    encryption_manager,
                    encryption_mapping[i].address,
                    encryption_mapping[i].send_key,
                    encryption_mapping[i].receive_key,
                    time,
                    -1.0,
                    TEST_TIMEOUT_SECONDS,
                    -1));

                encryption_index = encryption_manager_find_encryption_mapping(encryption_manager, encryption_mapping[i].address, time);

                var send_key = encryption_manager_get_send_key(encryption_manager, encryption_index);
                var receive_key = encryption_manager_get_receive_key(encryption_manager, encryption_index);

                check(send_key != null);
                check(receive_key != null);

                check(BufferEx.Equal(send_key, encryption_mapping[i].send_key, KEY_BYTES));
                check(BufferEx.Equal(receive_key, encryption_mapping[i].receive_key, KEY_BYTES));
            }

            // removing an encryption mapping that doesn't exist should return 0
            {
                var address = new netcode_address_t();
                address.type = ADDRESS_IPV6;
                address.data = IPAddress.Loopback;
                address.port = 50000;

                check(!encryption_manager_remove_encryption_mapping(encryption_manager, address, time));
            }

            // remove the first and last encryption mappings

            check(encryption_manager_remove_encryption_mapping(encryption_manager, encryption_mapping[0].address, time));

            check(encryption_manager_remove_encryption_mapping(encryption_manager, encryption_mapping[NUM_ENCRYPTION_MAPPINGS - 1].address, time));

            // make sure the encryption mappings that were removed can no longer be looked up by address

            for (i = 0; i < NUM_ENCRYPTION_MAPPINGS; ++i)
            {
                var encryption_index = encryption_manager_find_encryption_mapping(encryption_manager, encryption_mapping[i].address, time);

                var send_key = encryption_manager_get_send_key(encryption_manager, encryption_index);
                var receive_key = encryption_manager_get_receive_key(encryption_manager, encryption_index);

                if (i != 0 && i != NUM_ENCRYPTION_MAPPINGS - 1)
                {
                    check(send_key != null);
                    check(receive_key != null);

                    check(BufferEx.Equal(send_key, encryption_mapping[i].send_key, KEY_BYTES));
                    check(BufferEx.Equal(receive_key, encryption_mapping[i].receive_key, KEY_BYTES));
                }
                else
                {
                    check(send_key == null);
                    check(receive_key == null);
                }
            }

            // add the encryption mappings back in

            check(encryption_manager_add_encryption_mapping(
                encryption_manager,
                encryption_mapping[0].address,
                encryption_mapping[0].send_key,
                encryption_mapping[0].receive_key,
                time,
                -1.0,
                TEST_TIMEOUT_SECONDS,
                    -1));

            check(encryption_manager_add_encryption_mapping(
                encryption_manager,
                encryption_mapping[NUM_ENCRYPTION_MAPPINGS - 1].address,
                encryption_mapping[NUM_ENCRYPTION_MAPPINGS - 1].send_key,
                encryption_mapping[NUM_ENCRYPTION_MAPPINGS - 1].receive_key,
                time,
                -1.0,
                TEST_TIMEOUT_SECONDS,
                    -1));

            // all encryption mappings should be able to be looked up by address again

            for (i = 0; i < NUM_ENCRYPTION_MAPPINGS; ++i)
            {
                var encryption_index = encryption_manager_find_encryption_mapping(encryption_manager, encryption_mapping[i].address, time);

                var send_key = encryption_manager_get_send_key(encryption_manager, encryption_index);
                var receive_key = encryption_manager_get_receive_key(encryption_manager, encryption_index);

                check(send_key != null);
                check(receive_key != null);

                check(BufferEx.Equal(send_key, encryption_mapping[i].send_key, KEY_BYTES));
                check(BufferEx.Equal(receive_key, encryption_mapping[i].receive_key, KEY_BYTES));
            }

            // check that encryption mappings time out properly

            time += TEST_TIMEOUT_SECONDS * 2;

            for (i = 0; i < NUM_ENCRYPTION_MAPPINGS; ++i)
            {
                var encryption_index = encryption_manager_find_encryption_mapping(encryption_manager, encryption_mapping[i].address, time);

                var send_key = encryption_manager_get_send_key(encryption_manager, encryption_index);
                var receive_key = encryption_manager_get_receive_key(encryption_manager, encryption_index);

                check(send_key == null);
                check(receive_key == null);
            }

            // add the same encryption mappings after timeout

            for (i = 0; i < NUM_ENCRYPTION_MAPPINGS; ++i)
            {
                var encryption_index = encryption_manager_find_encryption_mapping(encryption_manager, encryption_mapping[i].address, time);

                check(encryption_index == -1);

                check(encryption_manager_get_send_key(encryption_manager, encryption_index) == null);
                check(encryption_manager_get_receive_key(encryption_manager, encryption_index) == null);

                check(encryption_manager_add_encryption_mapping(
                    encryption_manager,
                    encryption_mapping[i].address,
                    encryption_mapping[i].send_key,
                    encryption_mapping[i].receive_key,
                    time,
                    -1.0,
                    TEST_TIMEOUT_SECONDS,
                    -1));

                encryption_index = encryption_manager_find_encryption_mapping(encryption_manager, encryption_mapping[i].address, time);

                var send_key = encryption_manager_get_send_key(encryption_manager, encryption_index);
                var receive_key = encryption_manager_get_receive_key(encryption_manager, encryption_index);

                check(send_key != null);
                check(receive_key != null);

                check(BufferEx.Equal(send_key, encryption_mapping[i].send_key, KEY_BYTES));
                check(BufferEx.Equal(receive_key, encryption_mapping[i].receive_key, KEY_BYTES));
            }

            // reset the encryption mapping and verify that all encryption mappings have been removed

            encryption_manager_reset(encryption_manager);

            for (i = 0; i < NUM_ENCRYPTION_MAPPINGS; ++i)
            {
                var encryption_index = encryption_manager_find_encryption_mapping(encryption_manager, encryption_mapping[i].address, time);

                var send_key = encryption_manager_get_send_key(encryption_manager, encryption_index);
                var receive_key = encryption_manager_get_receive_key(encryption_manager, encryption_index);

                check(send_key == null);
                check(receive_key == null);
            }

            // test the expire time for encryption mapping works as expected

            check(encryption_manager_add_encryption_mapping(
                encryption_manager,
                encryption_mapping[0].address,
                encryption_mapping[0].send_key,
                encryption_mapping[0].receive_key,
                time,
                time + 1.0,
                TEST_TIMEOUT_SECONDS,
                    -1));

            var encryption_index2 = encryption_manager_find_encryption_mapping(encryption_manager, encryption_mapping[0].address, time);

            check(encryption_index2 != -1);

            check(encryption_manager_find_encryption_mapping(encryption_manager, encryption_mapping[0].address, time + 1.1f) == -1);

            encryption_manager_set_expire_time(encryption_manager, encryption_index2, -1.0);

            check(encryption_manager_find_encryption_mapping(encryption_manager, encryption_mapping[0].address, time) == encryption_index2);
        }

        static void test_replay_protection()
        {
            var replay_protection = new netcode_replay_protection_t();

            int i;
            for (i = 0; i < 2; ++i)
            {
                replay_protection_reset(replay_protection);

                check(replay_protection.most_recent_sequence == 0);

                // the first time we receive packets, they should not be already received

                const int MAX_SEQUENCE = REPLAY_PROTECTION_BUFFER_SIZE * 4;

                ulong sequence;
                for (sequence = 0; sequence < MAX_SEQUENCE; ++sequence)
                {
                    check(!replay_protection_already_received(replay_protection, sequence));
                    replay_protection_advance_sequence(replay_protection, sequence);
                }

                // old packets outside buffer should be considered already received

                check(replay_protection_already_received(replay_protection, 0));

                // packets received a second time should be flagged already received

                for (sequence = MAX_SEQUENCE - 10; sequence < MAX_SEQUENCE; ++sequence)
                    check(replay_protection_already_received(replay_protection, sequence));

                // jumping ahead to a much higher sequence should be considered not already received

                check(!replay_protection_already_received(replay_protection, MAX_SEQUENCE + REPLAY_PROTECTION_BUFFER_SIZE));

                // old packets should be considered already received

                for (sequence = 0; sequence < MAX_SEQUENCE; ++sequence)
                    check(replay_protection_already_received(replay_protection, sequence));
            }

            // sequence numbers near UINT64_MAX must not be falsely rejected as replays.
            // "sequence + buffer size" overflowed in the already received check and treated
            // the top of the sequence space as ancient packets. found by fuzz_read_packet.

            replay_protection_reset(replay_protection);

            check(!replay_protection_already_received(replay_protection, ulong.MaxValue - REPLAY_PROTECTION_BUFFER_SIZE));
            replay_protection_advance_sequence(replay_protection, ulong.MaxValue - REPLAY_PROTECTION_BUFFER_SIZE);

            check(!replay_protection_already_received(replay_protection, ulong.MaxValue - 1));
            replay_protection_advance_sequence(replay_protection, ulong.MaxValue - 1);

            // and a replayed packet up there is still caught

            check(replay_protection_already_received(replay_protection, ulong.MaxValue - 1));

            // while packets that fell out of the window are rejected as before

            check(replay_protection_already_received(replay_protection, ulong.MaxValue - 1 - REPLAY_PROTECTION_BUFFER_SIZE));
        }

        static int num_ignored_asserts = 0;

        static void test_runtime_guards_assert_handler(string condition, string function, string file, int line) =>
            num_ignored_asserts++;

        static void test_runtime_guards()
        {
            // out of range arguments to public entry points must return cleanly rather than throw or
            // corrupt state. install an assert handler that continues instead of exiting so this test
            // also runs in debug builds.

            set_assert_function(test_runtime_guards_assert_handler);

            // no private key needed: nothing in this test decrypts anything

            default_server_config(out var server_config);
            server_config.protocol_id = TEST_PROTOCOL_ID;

            var server = server_create("127.0.0.1:40000", server_config, 0.0);

            check(server != null);

            // starting with an out of range number of clients must not start the server

            server_start(server, 0);
            check(!server_running(server));

            server_start(server, -1);
            check(!server_running(server));

            server_start(server, MAX_CLIENTS + 1);
            check(!server_running(server));

            server_start(server, 1);
            check(server_running(server));
            check(server_max_clients(server) == 1);

            // out of range client indices must return cleanly. max clients is 1, so 1 is out of range

            check(server_client_user_data(server, -1) == null);
            check(server_client_user_data(server, 1) == null);
            check(server_client_user_data(server, MAX_CLIENTS) == null);

            check(server_next_packet_sequence(server, -1) == 0);
            check(server_next_packet_sequence(server, 1) == 0);

            check(!server_client_loopback(server, -1));
            check(!server_client_loopback(server, 1));

            check(server_receive_packet(server, -1, out var packet_bytes, out var packet_sequence) == null);
            check(server_receive_packet(server, 1, out packet_bytes, out packet_sequence) == null);

            var payload = new byte[MAX_PACKET_SIZE];

            server_send_packet(server, -1, payload, MAX_PACKET_SIZE);
            server_send_packet(server, 1, payload, MAX_PACKET_SIZE);

            server_disconnect_client(server, -1);
            server_disconnect_client(server, 1);

            server_connect_loopback_client(server, -1, 1, null);
            server_connect_loopback_client(server, 1, 1, null);

            server_disconnect_loopback_client(server, -1);
            server_disconnect_loopback_client(server, 1);

            server_process_loopback_packet(server, -1, payload, MAX_PACKET_SIZE, 0);
            server_process_loopback_packet(server, 1, payload, MAX_PACKET_SIZE, 0);

            check(server_client_disconnect_reason(server, -1) == SERVER_CLIENT_DISCONNECT_REASON_NONE);
            check(server_client_disconnect_reason(server, 1) == SERVER_CLIENT_DISCONNECT_REASON_NONE);

            // none of the above may have connected anybody or torn anything down

            check(server_running(server));
            check(server_num_connected_clients(server) == 0);

            server_destroy(ref server);

            set_assert_function(default_assert_handler);
        }

        static void test_init_and_defaults()
        {
            // init is reference counted, so multiple subsystems in the same application can call
            // init and term independently. the test runner has already called init once.

            check(netcode_.initialized == 1);
            check(init() == OK);
            check(netcode_.initialized == 2);
            term();
            check(netcode_.initialized == 1);

            // a zeroed config must give working defaults instead of crashing on a null allocator

            {
                var client_config = new netcode_client_config_t();

                var client = client_create("127.0.0.1:50000", client_config, 0.0);

                check(client != null);

                client_destroy(ref client);
            }

            {
                var server_config = new netcode_server_config_t();

                var server = server_create("127.0.0.1:40000", server_config, 0.0);

                check(server != null);
                check(server.config.max_connect_token_lifetime == DEFAULT_MAX_CONNECT_TOKEN_LIFETIME);

                server_destroy(ref server);
            }

            // the server and client keep their own copy of the config, as C copies the struct

            {
                default_server_config(out var server_config);
                server_config.protocol_id = TEST_PROTOCOL_ID;
                server_config.private_key[0] = 1;

                var server = server_create("127.0.0.1:40000", server_config, 0.0);

                check(server != null);

                server_config.protocol_id = 0;
                server_config.private_key[0] = 2;

                check(server.config.protocol_id == TEST_PROTOCOL_ID);
                check(server.config.private_key[0] == 1);

                server_destroy(ref server);

                // and destroying the server erases its copy of the private key, not the caller's

                check(server_config.private_key[0] == 2);
            }
        }

        static void test_override_send_packet(object context, netcode_address_t to, byte[] packet_data, int packet_bytes) { }

        static int test_override_receive_packet(object context, netcode_address_t from, byte[] packet_data, int max_packet_bytes) => 0;

        static void test_client_create_error()
        {
            default_client_config(out var client_config);

            // successful create leaves the create error as NONE

            {
                var client = client_create("0.0.0.0:50000", client_config, 0.0);

                check(client != null);
                check(client_create_error() == CLIENT_CREATE_ERROR_NONE);

                client_destroy(ref client);
            }

            // bad first address

            check(client_create("not an address", client_config, 0.0) == null);
            check(client_create_error() == CLIENT_CREATE_ERROR_PARSE_ADDRESS_FAILED);

            // bad second address

            check(client_create_dual("0.0.0.0:50000", "not an address", client_config, 0.0) == null);
            check(client_create_error() == CLIENT_CREATE_ERROR_PARSE_ADDRESS2_FAILED);

            // the network simulator requires binding to a specific port

            {
                var network_simulator = network_simulator_create(null, null, null);

                default_client_config(out var simulator_config);
                simulator_config.network_simulator = network_simulator;

                check(client_create("0.0.0.0", simulator_config, 0.0) == null);
                check(client_create_error() == CLIENT_CREATE_ERROR_SIMULATOR_REQUIRES_PORT);

                network_simulator_destroy(ref network_simulator);
            }

            // binding a second client to a port already in use fails at socket creation (ipv4)

            {
                var first_client = client_create("127.0.0.1:50000", client_config, 0.0);

                check(first_client != null);

                check(client_create("127.0.0.1:50000", client_config, 0.0) == null);
                check(client_create_error() == CLIENT_CREATE_ERROR_CREATE_SOCKET_IPV4_FAILED);

                client_destroy(ref first_client);
            }

            // and the same over ipv6 reports the ipv6 error

            {
                var first_client = client_create("[::1]:50000", client_config, 0.0);

                check(first_client != null);

                check(client_create("[::1]:50000", client_config, 0.0) == null);
                check(client_create_error() == CLIENT_CREATE_ERROR_CREATE_SOCKET_IPV6_FAILED);

                client_destroy(ref first_client);
            }

            // CLIENT_CREATE_ERROR_ALLOCATE_CLIENT_FAILED is not reachable: managed allocation does not return null

            // override_send_and_receive with either override callback missing is refused at create time,
            // rather than calling a null reference on the first update

            {
                default_client_config(out var override_config);
                override_config.override_send_and_receive = true;
                override_config.send_packet_override = test_override_send_packet;

                check(client_create("0.0.0.0:50000", override_config, 0.0) == null);
                check(client_create_error() == CLIENT_CREATE_ERROR_MISSING_OVERRIDE_CALLBACK);

                override_config.send_packet_override = null;
                override_config.receive_packet_override = test_override_receive_packet;

                check(client_create("0.0.0.0:50000", override_config, 0.0) == null);
                check(client_create_error() == CLIENT_CREATE_ERROR_MISSING_OVERRIDE_CALLBACK);
            }
        }

        static void test_server_create_error()
        {
            default_server_config(out var server_config);

            // successful create leaves the create error as NONE

            {
                var server = server_create("127.0.0.1:40000", server_config, 0.0);

                check(server != null);
                check(server_create_error() == SERVER_CREATE_ERROR_NONE);

                server_destroy(ref server);
            }

            // bad first address

            check(server_create("not an address", server_config, 0.0) == null);
            check(server_create_error() == SERVER_CREATE_ERROR_PARSE_ADDRESS_FAILED);

            // bad second address

            check(server_create_dual("127.0.0.1:40000", "not an address", server_config, 0.0) == null);
            check(server_create_error() == SERVER_CREATE_ERROR_PARSE_ADDRESS2_FAILED);

            // a port already in use is reported as a bind failure, distinct from other socket errors (ipv4)

            {
                var first_server = server_create("127.0.0.1:40000", server_config, 0.0);

                check(first_server != null);

                check(server_create("127.0.0.1:40000", server_config, 0.0) == null);
                check(server_create_error() == SERVER_CREATE_ERROR_BIND_SOCKET_IPV4_FAILED);

                server_destroy(ref first_server);
            }

            // and the same over ipv6 reports the ipv6 bind error

            {
                var first_server = server_create("[::1]:40000", server_config, 0.0);

                check(first_server != null);

                check(server_create("[::1]:40000", server_config, 0.0) == null);
                check(server_create_error() == SERVER_CREATE_ERROR_BIND_SOCKET_IPV6_FAILED);

                server_destroy(ref first_server);
            }

            // SERVER_CREATE_ERROR_ALLOCATE_SERVER_FAILED is not reachable: managed allocation does not return null

            // override_send_and_receive with either override callback missing is refused at create time

            {
                default_server_config(out var override_config);
                override_config.override_send_and_receive = true;
                override_config.send_packet_override = test_override_send_packet;

                check(server_create("127.0.0.1:40000", override_config, 0.0) == null);
                check(server_create_error() == SERVER_CREATE_ERROR_MISSING_OVERRIDE_CALLBACK);

                override_config.send_packet_override = null;
                override_config.receive_packet_override = test_override_receive_packet;

                check(server_create("127.0.0.1:40000", override_config, 0.0) == null);
                check(server_create_error() == SERVER_CREATE_ERROR_MISSING_OVERRIDE_CALLBACK);
            }
        }

        static void test_network_simulator_determinism()
        {
            // the network simulator has its own seeded rng, so two simulators given
            // identical inputs must drop, delay and duplicate identically

            const int DETERMINISM_NUM_PACKETS = 100;
            const int DETERMINISM_MAX_RECEIVE = 256;

            var simulator_a = network_simulator_create(null, null, null);
            var simulator_b = network_simulator_create(null, null, null);

            check(simulator_a != null);
            check(simulator_b != null);

            simulator_a.latency_milliseconds = 100.0f;
            simulator_a.jitter_milliseconds = 50.0f;
            simulator_a.packet_loss_percent = 25.0f;
            simulator_a.duplicate_packet_percent = 25.0f;

            simulator_b.latency_milliseconds = 100.0f;
            simulator_b.jitter_milliseconds = 50.0f;
            simulator_b.packet_loss_percent = 25.0f;
            simulator_b.duplicate_packet_percent = 25.0f;

            check(parse_address("127.0.0.1:40000", out var from) == OK);
            check(parse_address("127.0.0.1:50000", out var to) == OK);

            int i, j;
            var packet_data = new byte[256];
            for (i = 0; i < DETERMINISM_NUM_PACKETS; i++)
            {
                for (j = 0; j < packet_data.Length; j++)
                    packet_data[j] = (byte)(i + j);
                network_simulator_send_packet(simulator_a, from, to, packet_data, packet_data.Length);
                network_simulator_send_packet(simulator_b, from, to, packet_data, packet_data.Length);
            }

            var total_received = 0;

            var packet_data_a = new byte[DETERMINISM_MAX_RECEIVE][];
            var packet_data_b = new byte[DETERMINISM_MAX_RECEIVE][];
            var packet_bytes_a = new int[DETERMINISM_MAX_RECEIVE];
            var packet_bytes_b = new int[DETERMINISM_MAX_RECEIVE];
            var from_a = new netcode_address_t[DETERMINISM_MAX_RECEIVE];
            var from_b = new netcode_address_t[DETERMINISM_MAX_RECEIVE];

            for (var time = 0.0; time < 2.0; time += 0.01)
            {
                network_simulator_update(simulator_a, time);
                network_simulator_update(simulator_b, time);

                var num_packets_a = network_simulator_receive_packets(simulator_a, to, DETERMINISM_MAX_RECEIVE, packet_data_a, packet_bytes_a, from_a);
                var num_packets_b = network_simulator_receive_packets(simulator_b, to, DETERMINISM_MAX_RECEIVE, packet_data_b, packet_bytes_b, from_b);

                check(num_packets_a == num_packets_b);

                for (i = 0; i < num_packets_a; i++)
                {
                    check(packet_bytes_a[i] == packet_bytes_b[i]);
                    check(BufferEx.Equal(packet_data_a[i], packet_data_b[i], packet_bytes_a[i]));
                }

                total_received += num_packets_a;
            }

            check(total_received > 0);

            network_simulator_destroy(ref simulator_a);
            network_simulator_destroy(ref simulator_b);
        }

        static void test_client_create()
        {
            {
                default_client_config(out var client_config);

                var client = client_create("127.0.0.1:40000", client_config, 0.0);

                parse_address("127.0.0.1:40000", out var test_address);

                check(client != null);
                check(client.socket_holder.ipv4.handle != null);
                check(client.socket_holder.ipv6.handle == null);
                check(address_equal(client.address, test_address));

                client_destroy(ref client);
            }

            {
                default_client_config(out var client_config);

                var client = client_create("[::]:50000", client_config, 0.0);

                parse_address("[::]:50000", out var test_address);

                check(client != null);
                check(client.socket_holder.ipv4.handle == null);
                check(client.socket_holder.ipv6.handle != null);
                check(address_equal(client.address, test_address));

                client_destroy(ref client);
            }

            {
                default_client_config(out var client_config);

                var client = client_create_dual("127.0.0.1:40000", "[::]:50000", client_config, 0.0);

                parse_address("127.0.0.1:40000", out var test_address);

                check(client != null);
                check(client.socket_holder.ipv4.handle != null);
                check(client.socket_holder.ipv6.handle != null);
                check(address_equal(client.address, test_address));

                client_destroy(ref client);
            }

            {
                default_client_config(out var client_config);

                var client = client_create_dual("[::]:50000", "127.0.0.1:40000", client_config, 0.0);

                parse_address("[::]:50000", out var test_address);

                check(client != null);
                check(client.socket_holder.ipv4?.handle != null);
                check(client.socket_holder.ipv6?.handle != null);
                check(address_equal(client.address, test_address));

                client_destroy(ref client);
            }
        }

        static void test_server_create()
        {
            {
                default_server_config(out var server_config);

                var server = server_create("127.0.0.1:40000", server_config, 0.0);

                parse_address("127.0.0.1:40000", out var test_address);

                check(server != null);
                check(server.socket_holder.ipv4.handle != null);
                check(server.socket_holder.ipv6.handle == null);
                check(address_equal(server.address, test_address));

                server_destroy(ref server);
            }

            {
                default_server_config(out var server_config);

                var server = server_create("[::1]:50000", server_config, 0.0);

                parse_address("[::1]:50000", out var test_address);

                check(server != null);
                check(server.socket_holder.ipv4.handle == null);
                check(server.socket_holder.ipv6.handle != null);
                check(address_equal(server.address, test_address));

                server_destroy(ref server);
            }

            {
                default_server_config(out var server_config);

                var server = server_create_dual("127.0.0.1:40000", "[::1]:50000", server_config, 0.0);

                parse_address("127.0.0.1:40000", out var test_address);

                check(server != null);
                check(server.socket_holder.ipv4.handle != null);
                check(server.socket_holder.ipv6.handle != null);
                check(address_equal(server.address, test_address));

                server_destroy(ref server);
            }

            {
                default_server_config(out var server_config);

                var server = server_create_dual("[::1]:50000", "127.0.0.1:40000", server_config, 0.0);

                parse_address("[::1]:50000", out var test_address);

                check(server != null);
                check(server.socket_holder.ipv4.handle != null);
                check(server.socket_holder.ipv6.handle != null);
                check(address_equal(server.address, test_address));

                server_destroy(ref server);
            }
        }

        static readonly byte[] private_key = new byte[KEY_BYTES] {
            0x60, 0x6a, 0xbe, 0x6e, 0xc9, 0x19, 0x10, 0xea,
            0x9a, 0x65, 0x62, 0xf6, 0x6f, 0x2b, 0x30, 0xe4,
            0x43, 0x71, 0xd6, 0x2c, 0xd1, 0x99, 0x27, 0x26,
            0x6b, 0x3c, 0x60, 0xf4, 0xb7, 0x15, 0xab, 0xa1 };

        static void test_server_restart_global_sequence()
        {
            // global packets (challenge, denied) share per-token server to client keys with
            // per-client packets, so the global sequence must stay in the top half of the
            // sequence space or a stopped and restarted server reuses AEAD nonces. regression
            // test: server_stop zeroes the global sequence, start must re-seed it.

            default_server_config(out var server_config);

            var server = server_create("127.0.0.1:40000", server_config, 0.0);

            check(server != null);
            check(server.global_sequence == 1UL << 63);

            server_start(server, 1);

            check(server.global_sequence == 1UL << 63);

            server.global_sequence += 1000;        // as if the server had sent some global packets

            server_stop(server);

            server_start(server, 1);

            check(server.global_sequence == 1UL << 63);

            server_destroy(ref server);
        }

        static void test_client_server_connect()
        {
            var network_simulator = network_simulator_create(null, null, null);

            network_simulator.latency_milliseconds = 250;
            network_simulator.jitter_milliseconds = 250;
            network_simulator.packet_loss_percent = 5;
            network_simulator.duplicate_packet_percent = 10;

            var time = 0.0;
            const double delta_time = 1.0 / 10.0;

            default_client_config(out var client_config);
            client_config.network_simulator = network_simulator;

            var client = client_create("[::]:50000", client_config, time);

            check(client != null);

            default_server_config(out var server_config);
            server_config.protocol_id = TEST_PROTOCOL_ID;
            server_config.network_simulator = network_simulator;
            BufferEx.Copy(server_config.private_key, private_key, KEY_BYTES);

            var server = server_create("[::1]:40000", server_config, time);

            check(server != null);

            server_start(server, 1);

            const string server_address = "[::1]:40000";

            var connect_token = new byte[CONNECT_TOKEN_BYTES];

            var client_id = 0UL;
            random_bytes(ref client_id, 8);

            var user_data = new byte[USER_DATA_BYTES];
            random_bytes(user_data, USER_DATA_BYTES);

            check(generate_connect_token(1, new[] { server_address }, new[] { server_address }, TEST_CONNECT_TOKEN_EXPIRY, TEST_TIMEOUT_SECONDS, client_id, TEST_PROTOCOL_ID, private_key, user_data, connect_token) != 0);

            client_connect(client, connect_token);

            while (true)
            {
                network_simulator_update(network_simulator, time);
                client_update(client, time);
                server_update(server, time);

                if (client_state(client) <= CLIENT_STATE_DISCONNECTED)
                    break;
                if (client_state(client) == CLIENT_STATE_CONNECTED)
                    break;

                time += delta_time;
            }

            check(client_state(client) == CLIENT_STATE_CONNECTED);
            check(client_index(client) == 0);
            check(server_client_connected(server, 0));
            check(server_num_connected_clients(server) == 1);

            var server_num_packets_received = 0;
            var client_num_packets_received = 0;

            var packet_data = new byte[MAX_PACKET_SIZE];
            int i;
            for (i = 0; i < MAX_PACKET_SIZE; ++i)
                packet_data[i] = (byte)i;

            while (true)
            {
                network_simulator_update(network_simulator, time);

                client_update(client, time);
                server_update(server, time);
                client_send_packet(client, packet_data, MAX_PACKET_SIZE);
                server_send_packet(server, 0, packet_data, MAX_PACKET_SIZE);

                while (true)
                {
                    var packet = client_receive_packet(client, out var packet_bytes, out var packet_sequence);
                    if (packet == null)
                        break;
                    assert(packet_bytes == MAX_PACKET_SIZE);
                    assert(BufferEx.Equal(packet, packet_data, MAX_PACKET_SIZE));
                    client_num_packets_received++;
                    client_free_packet(client, ref packet);
                }

                while (true)
                {
                    var packet = server_receive_packet(server, 0, out var packet_bytes, out var packet_sequence);
                    if (packet == null)
                        break;
                    assert(packet_bytes == MAX_PACKET_SIZE);
                    assert(BufferEx.Equal(packet, packet_data, MAX_PACKET_SIZE));
                    server_num_packets_received++;
                    server_free_packet(server, ref packet);
                }

                if (client_num_packets_received >= 10 && server_num_packets_received >= 10)
                    if (server_client_connected(server, 0))
                        server_disconnect_client(server, 0);

                if (client_state(client) <= CLIENT_STATE_DISCONNECTED)
                    break;

                time += delta_time;
            }

            check(client_num_packets_received >= 10 && server_num_packets_received >= 10);

            server_destroy(ref server);
            client_destroy(ref client);
            network_simulator_destroy(ref network_simulator);
        }

        static void client_server_socket_connect_to(string client_address, string client_address2, string server_address, string server_address2, string connect_address)
        {
            var time = 0.0;
            const double delta_time = 1.0 / 10.0;

            default_client_config(out var client_config);

            var client = client_create_dual(client_address, client_address2, client_config, time);

            check(client != null);

            default_server_config(out var server_config);
            server_config.protocol_id = TEST_PROTOCOL_ID;
            BufferEx.Copy(server_config.private_key, private_key, KEY_BYTES);

            var server = server_create_dual(server_address, server_address2, server_config, time);

            check(server != null);

            server_start(server, 1);

            var client_id = 0UL;
            random_bytes(ref client_id, 8);

            var user_data = new byte[USER_DATA_BYTES];
            random_bytes(user_data, USER_DATA_BYTES);

            var connect_token = new byte[CONNECT_TOKEN_BYTES];

            check(generate_connect_token(1, new[] { connect_address }, new[] { connect_address }, TEST_CONNECT_TOKEN_EXPIRY, TEST_TIMEOUT_SECONDS, client_id, TEST_PROTOCOL_ID, private_key, user_data, connect_token) == OK);

            client_connect(client, connect_token);

            while (true)
            {
                client_update(client, time);

                server_update(server, time);

                if (client_state(client) <= CLIENT_STATE_DISCONNECTED)
                    break;

                if (client_state(client) == CLIENT_STATE_CONNECTED)
                    break;

                // this test runs over real sockets while advancing virtual time, so it must yield
                // real time each iteration or the virtual timeouts can expire before the OS delivers
                // a single loopback packet

                sleep(0.01);

                time += delta_time;
            }

            check(client_state(client) == CLIENT_STATE_CONNECTED);
            check(server_num_connected_clients(server) == 1);

            server_destroy(ref server);

            client_destroy(ref client);
        }

        static void client_server_socket_connect(string client_address, string client_address2, string server_address, string server_address2) =>
            client_server_socket_connect_to(client_address, client_address2, server_address, server_address2, server_address);

        static void test_client_server_ipv4_socket_connect()
        {
            client_server_socket_connect("0.0.0.0:50000", null, "127.0.0.1:40000", null);
            client_server_socket_connect("0.0.0.0:50000", null, "127.0.0.1:40000", "[::1]:40000");
            client_server_socket_connect("0.0.0.0:50000", "[::]:50000", "127.0.0.1:40000", null);
            client_server_socket_connect("0.0.0.0:50000", "[::]:50000", "127.0.0.1:40000", "[::1]:40000");
        }

        static void test_client_server_ipv6_socket_connect()
        {
            client_server_socket_connect("[::]:50000", null, "[::1]:40000", null);
            client_server_socket_connect("[::]:50000", null, "[::1]:40000", "127.0.0.1:40000");
            client_server_socket_connect("0.0.0.0:50000", "[::]:50000", "[::1]:40000", null);
            client_server_socket_connect("0.0.0.0:50000", "[::]:50000", "[::1]:40000", "127.0.0.1:40000");
        }

        static void test_client_server_dual_socket_connect()
        {
            // dual stack client connects to dual stack server over ipv4

            client_server_socket_connect("0.0.0.0:50000", "[::]:50000", "127.0.0.1:40000", "[::1]:40000");

            // dual stack client connects to dual stack server over ipv6

            client_server_socket_connect("0.0.0.0:50000", "[::]:50000", "[::1]:40000", "127.0.0.1:40000");

            // dual stack client connects to the second address of a dual stack server (ipv6, then ipv4)

            client_server_socket_connect_to("0.0.0.0:50000", "[::]:50000", "127.0.0.1:40000", "[::1]:40000", "[::1]:40000");

            client_server_socket_connect_to("0.0.0.0:50000", "[::]:50000", "[::1]:40000", "127.0.0.1:40000", "127.0.0.1:40000");
        }

        static void test_client_server_keep_alive()
        {
            var network_simulator = network_simulator_create(null, null, null);

            network_simulator.latency_milliseconds = 250;
            network_simulator.jitter_milliseconds = 250;
            network_simulator.packet_loss_percent = 5;
            network_simulator.duplicate_packet_percent = 10;

            var time = 0.0;
            const double delta_time = 1.0 / 10.0;

            // connect client to server

            default_client_config(out var client_config);
            client_config.network_simulator = network_simulator;

            var client = client_create("[::]:50000", client_config, time);

            check(client != null);

            default_server_config(out var server_config);
            server_config.protocol_id = TEST_PROTOCOL_ID;
            server_config.network_simulator = network_simulator;
            BufferEx.Copy(server_config.private_key, private_key, KEY_BYTES);

            var server = server_create("[::1]:40000", server_config, time);

            check(server != null);

            server_start(server, 1);

            const string server_address = "[::1]:40000";

            var connect_token = new byte[CONNECT_TOKEN_BYTES];

            var client_id = 0UL;
            random_bytes(ref client_id, 8);

            var user_data = new byte[USER_DATA_BYTES];
            random_bytes(user_data, USER_DATA_BYTES);

            check(generate_connect_token(1, new[] { server_address }, new[] { server_address }, TEST_CONNECT_TOKEN_EXPIRY, TEST_TIMEOUT_SECONDS, client_id, TEST_PROTOCOL_ID, private_key, user_data, connect_token) != 0);

            client_connect(client, connect_token);

            while (true)
            {
                network_simulator_update(network_simulator, time);

                client_update(client, time);
                server_update(server, time);

                if (client_state(client) <= CLIENT_STATE_DISCONNECTED)
                    break;
                if (client_state(client) == CLIENT_STATE_CONNECTED)
                    break;

                time += delta_time;
            }

            check(client_state(client) == CLIENT_STATE_CONNECTED);
            check(client_index(client) == 0);
            check(server_client_connected(server, 0));
            check(server_num_connected_clients(server) == 1);

            // pump the client and server long enough that they would timeout without keep alive packets

            var num_iterations = (int)(1.25f * TEST_TIMEOUT_SECONDS / delta_time) + 1;

            int i;
            for (i = 0; i < num_iterations; ++i)
            {
                network_simulator_update(network_simulator, time);

                client_update(client, time);
                server_update(server, time);

                if (client_state(client) <= CLIENT_STATE_DISCONNECTED)
                    break;

                time += delta_time;
            }

            check(client_state(client) == CLIENT_STATE_CONNECTED);
            check(client_index(client) == 0);
            check(server_client_connected(server, 0));
            check(server_num_connected_clients(server) == 1);

            server_destroy(ref server);
            client_destroy(ref client);
            network_simulator_destroy(ref network_simulator);
        }

        static void test_client_server_multiple_clients()
        {
            const int NUM_START_STOP_ITERATIONS = 3;

            var max_clients = new int[NUM_START_STOP_ITERATIONS] { 2, 32, 5 };

            var network_simulator = network_simulator_create(null, null, null);

            network_simulator.latency_milliseconds = 250;
            network_simulator.jitter_milliseconds = 250;
            network_simulator.packet_loss_percent = 5;
            network_simulator.duplicate_packet_percent = 10;

            var time = 0.0;
            const double delta_time = 1.0 / 10.0;

            default_server_config(out var server_config);
            server_config.protocol_id = TEST_PROTOCOL_ID;
            server_config.network_simulator = network_simulator;
            BufferEx.Copy(server_config.private_key, private_key, KEY_BYTES);

            var server = server_create("[::1]:40000", server_config, time);

            check(server != null);

            int i;
            for (i = 0; i < NUM_START_STOP_ITERATIONS; ++i)
            {
                // start the server with max # of clients for this iteration

                server_start(server, max_clients[i]);

                // create # of client objects for this iteration and connect to server

                var client = new netcode_client_t[max_clients[i]];

                check(client != null);

                int j;
                for (j = 0; j < max_clients[i]; ++j)
                {
                    var client_address = $"[::]:{50000 + j}";

                    default_client_config(out var client_config);
                    client_config.network_simulator = network_simulator;

                    client[j] = client_create(client_address, client_config, time);

                    check(client[j] != null);

                    var client_id = (ulong)j;
                    random_bytes(ref client_id, 8);

                    var user_data = new byte[USER_DATA_BYTES];
                    random_bytes(user_data, USER_DATA_BYTES);

                    const string server_address = "[::1]:40000";

                    var connect_token = new byte[CONNECT_TOKEN_BYTES];

                    check(generate_connect_token(
                        1,
                        new[] { server_address },
                        new[] { server_address },
                        TEST_CONNECT_TOKEN_EXPIRY,
                        TEST_TIMEOUT_SECONDS,
                        client_id,
                        TEST_PROTOCOL_ID,
                        private_key,
                        user_data,
                        connect_token) != 0);

                    client_connect(client[j], connect_token);
                }

                // make sure all clients can connect

                while (true)
                {
                    network_simulator_update(network_simulator, time);

                    for (j = 0; j < max_clients[i]; ++j)
                        client_update(client[j], time);

                    server_update(server, time);

                    var num_connected_clients = 0;

                    for (j = 0; j < max_clients[i]; ++j)
                    {
                        if (client_state(client[j]) <= CLIENT_STATE_DISCONNECTED)
                            break;
                        if (client_state(client[j]) == CLIENT_STATE_CONNECTED)
                            num_connected_clients++;
                    }

                    if (num_connected_clients == max_clients[i])
                        break;

                    time += delta_time;
                }

                var x = server.num_connected_clients;
                check(server_num_connected_clients(server) == max_clients[i]);

                for (j = 0; j < max_clients[i]; ++j)
                {
                    check(client_state(client[j]) == CLIENT_STATE_CONNECTED);
                    check(server_client_connected(server, j));
                }

                // make sure all clients can exchange packets with the server

                var server_num_packets_received = new int[max_clients[i]];
                var client_num_packets_received = new int[max_clients[i]];

                var packet_data = new byte[MAX_PACKET_SIZE];
                for (j = 0; j < MAX_PACKET_SIZE; ++j)
                    packet_data[j] = (byte)j;

                while (true)
                {
                    network_simulator_update(network_simulator, time);

                    for (j = 0; j < max_clients[i]; ++j)
                        client_update(client[j], time);

                    server_update(server, time);

                    for (j = 0; j < max_clients[i]; ++j)
                        client_send_packet(client[j], packet_data, MAX_PACKET_SIZE);

                    for (j = 0; j < max_clients[i]; ++j)
                        server_send_packet(server, j, packet_data, MAX_PACKET_SIZE);

                    for (j = 0; j < max_clients[i]; ++j)
                        while (true)
                        {
                            var packet = client_receive_packet(client[j], out var packet_bytes, out var packet_sequence);
                            if (packet == null)
                                break;
                            assert(packet_bytes == MAX_PACKET_SIZE);
                            assert(BufferEx.Equal(packet, packet_data, MAX_PACKET_SIZE));
                            client_num_packets_received[j]++;
                            client_free_packet(client[j], ref packet);
                        }

                    for (j = 0; j < max_clients[i]; ++j)
                        while (true)
                        {
                            var packet = server_receive_packet(server, j, out var packet_bytes, out var packet_sequence);
                            if (packet == null)
                                break;
                            assert(packet_bytes == MAX_PACKET_SIZE);
                            assert(BufferEx.Equal(packet, packet_data, MAX_PACKET_SIZE));
                            server_num_packets_received[j]++;
                            server_free_packet(server, ref packet);
                        }

                    var num_clients_ready2 = 0;

                    for (j = 0; j < max_clients[i]; ++j)
                        if (client_num_packets_received[j] >= 1 && server_num_packets_received[j] >= 1)
                            num_clients_ready2++;

                    if (num_clients_ready2 == max_clients[i])
                        break;

                    for (j = 0; j < max_clients[i]; ++j)
                        if (client_state(client[j]) <= CLIENT_STATE_DISCONNECTED)
                            break;

                    time += delta_time;
                }

                var num_clients_ready = 0;

                for (j = 0; j < max_clients[i]; ++j)
                    if (client_num_packets_received[j] >= 1 && server_num_packets_received[j] >= 1)
                        num_clients_ready++;

                check(num_clients_ready == max_clients[i]);

                server_num_packets_received = null;
                client_num_packets_received = null;

                network_simulator_reset(network_simulator);

                for (j = 0; j < max_clients[i]; ++j)
                    client_destroy(ref client[j]);

                client = null;

                server_stop(server);
            }

            server_destroy(ref server);
            network_simulator_destroy(ref network_simulator);
        }

        static void test_client_server_multiple_servers()
        {
            var network_simulator = network_simulator_create(null, null, null);

            network_simulator.latency_milliseconds = 250;
            network_simulator.jitter_milliseconds = 250;
            network_simulator.packet_loss_percent = 5;
            network_simulator.duplicate_packet_percent = 10;

            var time = 0.0;
            const double delta_time = 1.0 / 10.0;

            default_client_config(out var client_config);
            client_config.network_simulator = network_simulator;

            var client = client_create("[::]:50000", client_config, time);

            check(client != null);

            default_server_config(out var server_config);
            server_config.protocol_id = TEST_PROTOCOL_ID;
            server_config.network_simulator = network_simulator;
            BufferEx.Copy(server_config.private_key, private_key, KEY_BYTES);

            var server = server_create("[::1]:40000", server_config, time);

            check(server != null);

            server_start(server, 1);

            string[] server_address = { "10.10.10.10:1000", "100.100.100.100:50000", "[::1]:40000" };

            var connect_token = new byte[CONNECT_TOKEN_BYTES];

            var client_id = 0UL;
            random_bytes(ref client_id, 8);

            var user_data = new byte[USER_DATA_BYTES];
            random_bytes(user_data, USER_DATA_BYTES);

            check(generate_connect_token(3, server_address, server_address, TEST_CONNECT_TOKEN_EXPIRY, TEST_TIMEOUT_SECONDS, client_id, TEST_PROTOCOL_ID, private_key, user_data, connect_token) == 1);

            client_connect(client, connect_token);

            while (true)
            {
                network_simulator_update(network_simulator, time);
                client_update(client, time);
                server_update(server, time);

                if (client_state(client) <= CLIENT_STATE_DISCONNECTED)
                    break;
                if (client_state(client) == CLIENT_STATE_CONNECTED)
                    break;

                time += delta_time;
            }

            check(client_state(client) == CLIENT_STATE_CONNECTED);
            check(client_index(client) == 0);
            check(server_client_connected(server, 0));
            check(server_num_connected_clients(server) == 1);

            var server_num_packets_received = 0;
            var client_num_packets_received = 0;

            var packet_data = new byte[MAX_PACKET_SIZE];
            int i;
            for (i = 0; i < MAX_PACKET_SIZE; ++i)
                packet_data[i] = (byte)i;

            while (true)
            {
                network_simulator_update(network_simulator, time);
                client_update(client, time);
                server_update(server, time);
                client_send_packet(client, packet_data, MAX_PACKET_SIZE);
                server_send_packet(server, 0, packet_data, MAX_PACKET_SIZE);

                while (true)
                {
                    var packet = client_receive_packet(client, out var packet_bytes, out var packet_sequence);
                    if (packet == null)
                        break;
                    assert(packet_bytes == MAX_PACKET_SIZE);
                    assert(BufferEx.Equal(packet, packet_data, MAX_PACKET_SIZE));
                    client_num_packets_received++;
                    client_free_packet(client, ref packet);
                }

                while (true)
                {
                    var packet = server_receive_packet(server, 0, out var packet_bytes, out var packet_sequence);
                    if (packet == null)
                        break;
                    assert(packet_bytes == MAX_PACKET_SIZE);
                    assert(BufferEx.Equal(packet, packet_data, MAX_PACKET_SIZE));
                    server_num_packets_received++;
                    server_free_packet(server, ref packet);
                }

                if (client_num_packets_received >= 10 && server_num_packets_received >= 10)
                    if (server_client_connected(server, 0))
                        server_disconnect_client(server, 0);

                if (client_state(client) <= CLIENT_STATE_DISCONNECTED)
                    break;

                time += delta_time;
            }

            check(client_num_packets_received >= 10 && server_num_packets_received >= 10);

            server_destroy(ref server);
            client_destroy(ref client);
            network_simulator_destroy(ref network_simulator);
        }

        static void test_client_error_connect_token_expired()
        {
            var network_simulator = network_simulator_create(null, null, null);

            network_simulator.latency_milliseconds = 250;
            network_simulator.jitter_milliseconds = 250;
            network_simulator.packet_loss_percent = 5;
            network_simulator.duplicate_packet_percent = 10;

            var time = 0.0;

            default_client_config(out var client_config);
            client_config.network_simulator = network_simulator;

            var client = client_create("[::]:50000", client_config, time);

            check(client != null);

            const string server_address = "[::1]:40000";

            var connect_token = new byte[CONNECT_TOKEN_BYTES];

            var client_id = 0UL;
            random_bytes(ref client_id, 8);

            var user_data = new byte[USER_DATA_BYTES];
            random_bytes(user_data, USER_DATA_BYTES);

            check(generate_connect_token(1, new[] { server_address }, new[] { server_address }, 0, TEST_TIMEOUT_SECONDS, client_id, TEST_PROTOCOL_ID, private_key, user_data, connect_token) != 0);

            client_connect(client, connect_token);

            client_update(client, time);

            check(client_state(client) == CLIENT_STATE_CONNECT_TOKEN_EXPIRED);

            client_destroy(ref client);
            network_simulator_destroy(ref network_simulator);
        }

        static void test_client_error_invalid_connect_token()
        {
            var network_simulator = network_simulator_create(null, null, null);

            network_simulator.latency_milliseconds = 250;
            network_simulator.jitter_milliseconds = 250;
            network_simulator.packet_loss_percent = 5;
            network_simulator.duplicate_packet_percent = 10;

            var time = 0.0;

            default_client_config(out var client_config);
            client_config.network_simulator = network_simulator;

            var client = client_create("[::]:50000", client_config, time);

            check(client != null);

            var connect_token = new byte[CONNECT_TOKEN_BYTES];
            random_bytes(connect_token, CONNECT_TOKEN_BYTES);

            var client_id = 0UL;
            random_bytes(ref client_id, 8);

            client_connect(client, connect_token);

            check(client_state(client) == CLIENT_STATE_INVALID_CONNECT_TOKEN);

            client_destroy(ref client);
            network_simulator_destroy(ref network_simulator);
        }

        static void test_client_error_connection_timed_out()
        {
            var network_simulator = network_simulator_create(null, null, null);

            network_simulator.latency_milliseconds = 250;
            network_simulator.jitter_milliseconds = 250;
            network_simulator.packet_loss_percent = 5;
            network_simulator.duplicate_packet_percent = 10;

            var time = 0.0;
            const double delta_time = 1.0 / 10.0;

            // connect a client to the server

            default_client_config(out var client_config);
            client_config.network_simulator = network_simulator;

            var client = client_create("[::]:50000", client_config, time);

            check(client != null);

            default_server_config(out var server_config);
            server_config.protocol_id = TEST_PROTOCOL_ID;
            server_config.network_simulator = network_simulator;
            BufferEx.Copy(server_config.private_key, private_key, KEY_BYTES);

            var server = server_create("[::1]:40000", server_config, time);

            check(server != null);

            server_start(server, 1);

            const string server_address = "[::1]:40000";

            var connect_token = new byte[CONNECT_TOKEN_BYTES];

            var client_id = 0UL;
            random_bytes(ref client_id, 8);

            var user_data = new byte[USER_DATA_BYTES];
            random_bytes(user_data, USER_DATA_BYTES);

            check(generate_connect_token(1, new[] { server_address }, new[] { server_address }, TEST_CONNECT_TOKEN_EXPIRY, TEST_TIMEOUT_SECONDS, client_id, TEST_PROTOCOL_ID, private_key, user_data, connect_token) != 0);

            client_connect(client, connect_token);

            while (true)
            {
                network_simulator_update(network_simulator, time);

                client_update(client, time);
                server_update(server, time);

                if (client_state(client) <= CLIENT_STATE_DISCONNECTED)
                    break;
                if (client_state(client) == CLIENT_STATE_CONNECTED)
                    break;

                time += delta_time;
            }

            check(client_state(client) == CLIENT_STATE_CONNECTED);
            check(client_index(client) == 0);
            check(server_client_connected(server, 0));
            check(server_num_connected_clients(server) == 1);

            // now disable updating the server and verify that the client times out

            while (true)
            {
                network_simulator_update(network_simulator, time);

                client_update(client, time);

                if (client_state(client) <= CLIENT_STATE_DISCONNECTED)
                    break;

                time += delta_time;
            }

            check(client_state(client) == CLIENT_STATE_CONNECTION_TIMED_OUT);

            server_destroy(ref server);
            client_destroy(ref client);
            network_simulator_destroy(ref network_simulator);
        }

        static void test_client_error_connection_response_timeout()
        {
            var network_simulator = network_simulator_create(null, null, null);

            network_simulator.latency_milliseconds = 250;
            network_simulator.jitter_milliseconds = 250;
            network_simulator.packet_loss_percent = 5;
            network_simulator.duplicate_packet_percent = 10;

            var time = 0.0;
            const double delta_time = 1.0 / 10.0;

            default_client_config(out var client_config);
            client_config.network_simulator = network_simulator;

            var client = client_create("[::]:50000", client_config, time);

            check(client != null);

            default_server_config(out var server_config);
            server_config.protocol_id = TEST_PROTOCOL_ID;
            server_config.network_simulator = network_simulator;
            BufferEx.Copy(server_config.private_key, private_key, KEY_BYTES);

            var server = server_create("[::1]:40000", server_config, time);

            check(server != null);

            server.flags = SERVER_FLAG_IGNORE_CONNECTION_RESPONSE_PACKETS;

            server_start(server, 1);

            const string server_address = "[::1]:40000";

            var connect_token = new byte[CONNECT_TOKEN_BYTES];

            var client_id = 0UL;
            random_bytes(ref client_id, 8);

            var user_data = new byte[USER_DATA_BYTES];
            random_bytes(user_data, USER_DATA_BYTES);

            check(generate_connect_token(1, new[] { server_address }, new[] { server_address }, TEST_CONNECT_TOKEN_EXPIRY, TEST_TIMEOUT_SECONDS, client_id, TEST_PROTOCOL_ID, private_key, user_data, connect_token) != 0);

            client_connect(client, connect_token);

            while (true)
            {
                network_simulator_update(network_simulator, time);
                client_update(client, time);
                server_update(server, time);

                if (client_state(client) <= CLIENT_STATE_DISCONNECTED)
                    break;
                if (client_state(client) == CLIENT_STATE_CONNECTED)
                    break;

                time += delta_time;
            }

            check(client_state(client) == CLIENT_STATE_CONNECTION_RESPONSE_TIMED_OUT);

            server_destroy(ref server);
            client_destroy(ref client);
            network_simulator_destroy(ref network_simulator);
        }

        static void test_client_error_connection_request_timeout()
        {
            var network_simulator = network_simulator_create(null, null, null);

            network_simulator.latency_milliseconds = 250;
            network_simulator.jitter_milliseconds = 250;
            network_simulator.packet_loss_percent = 5;
            network_simulator.duplicate_packet_percent = 10;

            var time = 0.0;
            const double delta_time = 1.0 / 60.0;

            default_client_config(out var client_config);
            client_config.network_simulator = network_simulator;

            var client = client_create("[::]:50000", client_config, time);

            check(client != null);

            default_server_config(out var server_config);
            server_config.protocol_id = TEST_PROTOCOL_ID;
            server_config.network_simulator = network_simulator;
            BufferEx.Copy(server_config.private_key, private_key, KEY_BYTES);

            var server = server_create("[::1]:40000", server_config, time);

            check(server != null);

            server.flags = SERVER_FLAG_IGNORE_CONNECTION_REQUEST_PACKETS;

            server_start(server, 1);

            const string server_address = "[::1]:40000";

            var connect_token = new byte[CONNECT_TOKEN_BYTES];

            var client_id = 0UL;
            random_bytes(ref client_id, 8);

            var user_data = new byte[USER_DATA_BYTES];
            random_bytes(user_data, USER_DATA_BYTES);

            check(generate_connect_token(1, new[] { server_address }, new[] { server_address }, TEST_CONNECT_TOKEN_EXPIRY, TEST_TIMEOUT_SECONDS, client_id, TEST_PROTOCOL_ID, private_key, user_data, connect_token) != 0);

            client_connect(client, connect_token);

            while (true)
            {
                network_simulator_update(network_simulator, time);
                client_update(client, time);
                server_update(server, time);

                if (client_state(client) <= CLIENT_STATE_DISCONNECTED)
                    break;
                if (client_state(client) == CLIENT_STATE_CONNECTED)
                    break;

                time += delta_time;
            }

            check(client_state(client) == CLIENT_STATE_CONNECTION_REQUEST_TIMED_OUT);

            server_destroy(ref server);
            client_destroy(ref client);
            network_simulator_destroy(ref network_simulator);
        }

        static void test_client_error_connection_denied()
        {
            var network_simulator = network_simulator_create(null, null, null);

            network_simulator.latency_milliseconds = 250;
            network_simulator.jitter_milliseconds = 250;
            network_simulator.packet_loss_percent = 5;
            network_simulator.duplicate_packet_percent = 10;

            // start a server and connect one client

            var time = 0.0;
            const double delta_time = 1.0 / 10.0;

            default_client_config(out var client_config);
            client_config.network_simulator = network_simulator;

            var client = client_create("[::]:50000", client_config, time);

            check(client != null);

            default_server_config(out var server_config);
            server_config.protocol_id = TEST_PROTOCOL_ID;
            server_config.network_simulator = network_simulator;
            BufferEx.Copy(server_config.private_key, private_key, KEY_BYTES);

            var server = server_create("[::1]:40000", server_config, time);

            check(server != null);

            server_start(server, 1);

            const string server_address = "[::1]:40000";

            var connect_token = new byte[CONNECT_TOKEN_BYTES];

            var client_id = 0UL;
            random_bytes(ref client_id, 8);

            var user_data = new byte[USER_DATA_BYTES];
            random_bytes(user_data, USER_DATA_BYTES);

            check(generate_connect_token(1, new[] { server_address }, new[] { server_address }, TEST_CONNECT_TOKEN_EXPIRY, TEST_TIMEOUT_SECONDS, client_id, TEST_PROTOCOL_ID, private_key, user_data, connect_token) != 0);

            client_connect(client, connect_token);

            while (true)
            {
                network_simulator_update(network_simulator, time);
                client_update(client, time);
                server_update(server, time);

                if (client_state(client) <= CLIENT_STATE_DISCONNECTED)
                    break;
                if (client_state(client) == CLIENT_STATE_CONNECTED)
                    break;

                time += delta_time;
            }

            check(client_state(client) == CLIENT_STATE_CONNECTED);
            check(client_index(client) == 0);
            check(server_client_connected(server, 0));
            check(server_num_connected_clients(server) == 1);

            // now attempt to connect a second client. the connection should be denied.

            var client2 = client_create("[::]:50001", client_config, time);

            check(client2 != null);

            var connect_token2 = new byte[CONNECT_TOKEN_BYTES];

            var client_id2 = 0UL;
            random_bytes(ref client_id2, 8);

            var user_data2 = new byte[USER_DATA_BYTES];
            random_bytes(user_data2, USER_DATA_BYTES);

            check(generate_connect_token(1, new[] { server_address }, new[] { server_address }, TEST_CONNECT_TOKEN_EXPIRY, TEST_TIMEOUT_SECONDS, client_id2, TEST_PROTOCOL_ID, private_key, user_data2, connect_token2) != 0);

            client_connect(client2, connect_token2);

            while (true)
            {
                network_simulator_update(network_simulator, time);
                client_update(client, time);
                client_update(client2, time);
                server_update(server, time);

                if (client_state(client) <= CLIENT_STATE_DISCONNECTED)
                    break;
                if (client_state(client2) <= CLIENT_STATE_DISCONNECTED)
                    break;

                time += delta_time;
            }

            check(client_state(client) == CLIENT_STATE_CONNECTED);
            check(client_state(client2) == CLIENT_STATE_CONNECTION_DENIED);
            check(server_client_connected(server, 0));
            check(server_num_connected_clients(server) == 1);

            server_destroy(ref server);
            client_destroy(ref client);
            client_destroy(ref client2);
            network_simulator_destroy(ref network_simulator);
        }

        static void test_client_side_disconnect()
        {
            var network_simulator = network_simulator_create(null, null, null);

            // start a server and connect one client

            var time = 0.0;
            const double delta_time = 1.0 / 10.0;

            default_client_config(out var client_config);
            client_config.network_simulator = network_simulator;

            var client = client_create("[::]:50000", client_config, time);

            check(client != null);

            default_server_config(out var server_config);
            server_config.protocol_id = TEST_PROTOCOL_ID;
            server_config.network_simulator = network_simulator;
            BufferEx.Copy(server_config.private_key, private_key, KEY_BYTES);

            var server = server_create("[::1]:40000", server_config, time);

            check(server != null);

            server_start(server, 1);

            const string server_address = "[::1]:40000";

            var connect_token = new byte[CONNECT_TOKEN_BYTES];

            var client_id = 0UL;
            random_bytes(ref client_id, 8);

            var user_data = new byte[USER_DATA_BYTES];
            random_bytes(user_data, USER_DATA_BYTES);

            check(generate_connect_token(1, new[] { server_address }, new[] { server_address }, TEST_CONNECT_TOKEN_EXPIRY, TEST_TIMEOUT_SECONDS, client_id, TEST_PROTOCOL_ID, private_key, user_data, connect_token) != 0);

            client_connect(client, connect_token);

            while (true)
            {
                network_simulator_update(network_simulator, time);
                client_update(client, time);
                server_update(server, time);

                if (client_state(client) <= CLIENT_STATE_DISCONNECTED)
                    break;
                if (client_state(client) == CLIENT_STATE_CONNECTED)
                    break;

                time += delta_time;
            }

            check(client_state(client) == CLIENT_STATE_CONNECTED);
            check(client_index(client) == 0);
            check(server_client_connected(server, 0));
            check(server_num_connected_clients(server) == 1);

            // disconnect client side and verify that the server sees that client disconnect cleanly, rather than timing out.

            client_disconnect(client);

            int i;
            for (i = 0; i < 10; ++i)
            {
                network_simulator_update(network_simulator, time);
                client_update(client, time);
                server_update(server, time);

                if (!server_client_connected(server, 0))
                    break;

                time += delta_time;
            }

            check(!server_client_connected(server, 0));
            check(server_num_connected_clients(server) == 0);
            check(server_client_disconnect_reason(server, 0) == SERVER_CLIENT_DISCONNECT_REASON_CLIENT_DISCONNECT);

            server_destroy(ref server);
            client_destroy(ref client);
            network_simulator_destroy(ref network_simulator);
        }

        static void test_server_side_disconnect()
        {
            var network_simulator = network_simulator_create(null, null, null);

            // start a server and connect one client

            var time = 0.0;
            const double delta_time = 1.0 / 10.0;

            default_client_config(out var client_config);
            client_config.network_simulator = network_simulator;

            var client = client_create("[::]:50000", client_config, time);

            check(client != null);

            default_server_config(out var server_config);
            server_config.protocol_id = TEST_PROTOCOL_ID;
            server_config.network_simulator = network_simulator;
            BufferEx.Copy(server_config.private_key, private_key, KEY_BYTES);

            var server = server_create("[::1]:40000", server_config, time);

            check(server != null);

            server_start(server, 1);

            const string server_address = "[::1]:40000";

            var connect_token = new byte[CONNECT_TOKEN_BYTES];

            var client_id = 0UL;
            random_bytes(ref client_id, 8);

            var user_data = new byte[USER_DATA_BYTES];
            random_bytes(user_data, USER_DATA_BYTES);

            check(generate_connect_token(1, new[] { server_address }, new[] { server_address }, TEST_CONNECT_TOKEN_EXPIRY, TEST_TIMEOUT_SECONDS, client_id, TEST_PROTOCOL_ID, private_key, user_data, connect_token) != 0);

            client_connect(client, connect_token);

            while (true)
            {
                network_simulator_update(network_simulator, time);
                client_update(client, time);
                server_update(server, time);

                if (client_state(client) <= CLIENT_STATE_DISCONNECTED)
                    break;
                if (client_state(client) == CLIENT_STATE_CONNECTED)
                    break;

                time += delta_time;
            }

            check(client_state(client) == CLIENT_STATE_CONNECTED);
            check(client_index(client) == 0);
            check(server_client_connected(server, 0));
            check(server_num_connected_clients(server) == 1);

            // disconnect server side and verify that the client disconnects cleanly, rather than timing out.

            server_disconnect_client(server, 0);

            int i;
            for (i = 0; i < 10; ++i)
            {
                network_simulator_update(network_simulator, time);
                client_update(client, time);
                server_update(server, time);

                if (client_state(client) == CLIENT_STATE_DISCONNECTED)
                    break;

                time += delta_time;
            }

            check(client_state(client) == CLIENT_STATE_DISCONNECTED);
            check(!server_client_connected(server, 0));
            check(server_num_connected_clients(server) == 0);
            check(server_client_disconnect_reason(server, 0) == SERVER_CLIENT_DISCONNECT_REASON_SERVER_DISCONNECT);

            server_destroy(ref server);
            client_destroy(ref client);
            network_simulator_destroy(ref network_simulator);
        }

        static void test_server_client_disconnect_reason()
        {
            var network_simulator = network_simulator_create(null, null, null);

            // start a server and connect one client

            var time = 0.0;
            const double delta_time = 1.0 / 10.0;

            default_client_config(out var client_config);
            client_config.network_simulator = network_simulator;

            var client = client_create("[::]:50000", client_config, time);

            check(client != null);

            default_server_config(out var server_config);
            server_config.protocol_id = TEST_PROTOCOL_ID;
            server_config.network_simulator = network_simulator;
            BufferEx.Copy(server_config.private_key, private_key, KEY_BYTES);

            var server = server_create("[::1]:40000", server_config, time);

            check(server != null);

            server_start(server, 1);

            // no disconnect has happened yet, so the client slot reason is none

            check(server_client_disconnect_reason(server, 0) == SERVER_CLIENT_DISCONNECT_REASON_NONE);

            const string server_address = "[::1]:40000";

            var connect_token = new byte[CONNECT_TOKEN_BYTES];

            var client_id = 0UL;
            random_bytes(ref client_id, 8);

            var user_data = new byte[USER_DATA_BYTES];
            random_bytes(user_data, USER_DATA_BYTES);

            check(generate_connect_token(1, new[] { server_address }, new[] { server_address }, TEST_CONNECT_TOKEN_EXPIRY, TEST_TIMEOUT_SECONDS, client_id, TEST_PROTOCOL_ID, private_key, user_data, connect_token) == OK);

            client_connect(client, connect_token);

            while (true)
            {
                network_simulator_update(network_simulator, time);
                client_update(client, time);
                server_update(server, time);

                if (client_state(client) <= CLIENT_STATE_DISCONNECTED)
                    break;
                if (client_state(client) == CLIENT_STATE_CONNECTED)
                    break;

                time += delta_time;
            }

            check(client_state(client) == CLIENT_STATE_CONNECTED);
            check(server_client_connected(server, 0));
            check(server_client_disconnect_reason(server, 0) == SERVER_CLIENT_DISCONNECT_REASON_NONE);

            // stop updating the client so it goes silent. the server should time it out
            // and record that as the disconnect reason, distinct from a clean disconnect

            int i;
            for (i = 0; i < 200; i++)
            {
                network_simulator_update(network_simulator, time);
                server_update(server, time);

                if (!server_client_connected(server, 0))
                    break;

                time += delta_time;
            }

            check(!server_client_connected(server, 0));
            check(server_num_connected_clients(server) == 0);
            check(server_client_disconnect_reason(server, 0) == SERVER_CLIENT_DISCONNECT_REASON_TIMED_OUT);

            // reconnect. a new client connecting to the slot clears the reason back to none

            client_disconnect(client);

            // catch the client's internal clock up to the current time before reconnecting, since it
            // was deliberately not updated above. otherwise the first update after connect sees the
            // whole timeout leg as elapsed time and immediately times out the connection request.
            client_update(client, time);

            network_simulator_reset(network_simulator);

            check(generate_connect_token(1, new[] { server_address }, new[] { server_address }, TEST_CONNECT_TOKEN_EXPIRY, TEST_TIMEOUT_SECONDS, client_id, TEST_PROTOCOL_ID, private_key, user_data, connect_token) == OK);

            client_connect(client, connect_token);

            while (true)
            {
                network_simulator_update(network_simulator, time);
                client_update(client, time);
                server_update(server, time);

                if (client_state(client) <= CLIENT_STATE_DISCONNECTED)
                    break;
                if (client_state(client) == CLIENT_STATE_CONNECTED)
                    break;

                time += delta_time;
            }

            check(client_state(client) == CLIENT_STATE_CONNECTED);
            check(server_client_connected(server, 0));
            check(server_client_disconnect_reason(server, 0) == SERVER_CLIENT_DISCONNECT_REASON_NONE);

            server_destroy(ref server);
            client_destroy(ref client);
            network_simulator_destroy(ref network_simulator);
        }

        static void test_client_reconnect()
        {
            var network_simulator = network_simulator_create(null, null, null);

            network_simulator.latency_milliseconds = 250;
            network_simulator.jitter_milliseconds = 250;
            network_simulator.packet_loss_percent = 5;
            network_simulator.duplicate_packet_percent = 10;

            // start a server and connect one client

            var time = 0.0;
            const double delta_time = 1.0 / 10.0;

            default_client_config(out var client_config);
            client_config.network_simulator = network_simulator;

            var client = client_create("[::]:50000", client_config, time);

            check(client != null);

            default_server_config(out var server_config);
            server_config.protocol_id = TEST_PROTOCOL_ID;
            server_config.network_simulator = network_simulator;
            BufferEx.Copy(server_config.private_key, private_key, KEY_BYTES);

            var server = server_create("[::1]:40000", server_config, time);

            check(server != null);

            server_start(server, 1);

            const string server_address = "[::1]:40000";

            var connect_token = new byte[CONNECT_TOKEN_BYTES];

            var client_id = 0UL;
            random_bytes(ref client_id, 8);

            var user_data = new byte[USER_DATA_BYTES];
            random_bytes(user_data, USER_DATA_BYTES);

            check(generate_connect_token(1, new[] { server_address }, new[] { server_address }, TEST_CONNECT_TOKEN_EXPIRY, TEST_TIMEOUT_SECONDS, client_id, TEST_PROTOCOL_ID, private_key, user_data, connect_token) != 0);

            client_connect(client, connect_token);

            while (true)
            {
                network_simulator_update(network_simulator, time);
                client_update(client, time);
                server_update(server, time);

                if (client_state(client) <= CLIENT_STATE_DISCONNECTED)
                    break;
                if (client_state(client) == CLIENT_STATE_CONNECTED)
                    break;

                time += delta_time;
            }

            check(client_state(client) == CLIENT_STATE_CONNECTED);
            check(client_index(client) == 0);
            check(server_client_connected(server, 0));
            check(server_num_connected_clients(server) == 1);

            // disconnect client on the server-side and wait until client sees the disconnect

            network_simulator_reset(network_simulator);

            server_disconnect_client(server, 0);

            while (true)
            {
                network_simulator_update(network_simulator, time);
                client_update(client, time);
                server_update(server, time);

                if (client_state(client) <= CLIENT_STATE_DISCONNECTED)
                    break;

                time += delta_time;
            }

            check(client_state(client) == CLIENT_STATE_DISCONNECTED);
            check(!server_client_connected(server, 0));
            check(server_num_connected_clients(server) == 0);

            // now reconnect the client and verify they connect

            network_simulator_reset(network_simulator);

            check(generate_connect_token(1, new[] { server_address }, new[] { server_address }, TEST_CONNECT_TOKEN_EXPIRY, TEST_TIMEOUT_SECONDS, client_id, TEST_PROTOCOL_ID, private_key, user_data, connect_token) != 0);

            client_connect(client, connect_token);

            while (true)
            {
                network_simulator_update(network_simulator, time);
                client_update(client, time);
                server_update(server, time);

                if (client_state(client) <= CLIENT_STATE_DISCONNECTED)
                    break;
                if (client_state(client) == CLIENT_STATE_CONNECTED)
                    break;

                time += delta_time;
            }

            check(client_state(client) == CLIENT_STATE_CONNECTED);
            check(client_index(client) == 0);
            check(server_client_connected(server, 0));
            check(server_num_connected_clients(server) == 1);

            server_destroy(ref server);
            client_destroy(ref client);
            network_simulator_destroy(ref network_simulator);
        }

        internal class test_loopback_context_t
        {
            public netcode_client_t client;
            public netcode_server_t server;
            public int num_loopback_packets_sent_to_client;
            public int num_loopback_packets_sent_to_server;
        }

        static void client_send_loopback_packet_callback(object _context, int client_index, byte[] packet_data, int packet_bytes, ulong packet_sequence)
        {
            check(_context != null);
            check(client_index == 0);
            check(packet_data != null);
            check(packet_bytes == MAX_PACKET_SIZE);
            int i;
            for (i = 0; i < packet_bytes; ++i)
                check(packet_data[i] == (byte)i);
            var context = (test_loopback_context_t)_context;
            context.num_loopback_packets_sent_to_server++;
            server_process_loopback_packet(context.server, client_index, packet_data, packet_bytes, packet_sequence);
        }

        static void server_send_loopback_packet_callback(object _context, int client_index, byte[] packet_data, int packet_bytes, ulong packet_sequence)
        {
            check(_context != null);
            check(client_index == 0);
            check(packet_data != null);
            check(packet_bytes == MAX_PACKET_SIZE);
            int i;
            for (i = 0; i < packet_bytes; ++i)
                check(packet_data[i] == (byte)i);
            var context = (test_loopback_context_t)_context;
            context.num_loopback_packets_sent_to_client++;
            client_process_loopback_packet(context.client, packet_data, packet_bytes, packet_sequence);
        }

        static void test_connect_token_entries()
        {
            var connect_token_entries = BufferEx.NewT<connect_token_entry_t>(MAX_CONNECT_TOKEN_ENTRIES);

            connect_token_entries_reset(connect_token_entries);

            check(parse_address("[::1]:50000", out var address_a) == OK);
            check(parse_address("[::1]:50001", out var address_b) == OK);

            const ulong current_timestamp = 1000;
            const ulong expire_timestamp = current_timestamp + 30;

            var mac = new byte[MAC_BYTES];

            // a connect token the history has not seen creates a pending entry

            mac[0] = 1;

            var index = connect_token_entries_find_or_add(connect_token_entries, address_a, mac, 0, expire_timestamp, current_timestamp, 100.0);

            check(index >= 0);
            check(connect_token_entries[index].state == CONNECT_TOKEN_ENTRY_PENDING);
            check(connect_token_entries[index].time == 100.0);

            // a pending entry admits a retransmitted connection request from the address that created it,
            // and the entry time is not refreshed

            check(connect_token_entries_find_or_add(connect_token_entries, address_a, mac, 0, expire_timestamp, current_timestamp, 200.0) == index);
            check(connect_token_entries[index].time == 100.0);

            // a pending entry refuses every other address

            check(connect_token_entries_find_or_add(connect_token_entries, address_b, mac, 0, expire_timestamp, current_timestamp, 200.0) == CONNECT_TOKEN_ENTRY_REFUSED);

            // a consumed entry admits nothing, including the address that used the connect token

            connect_token_entries_consume(connect_token_entries, index);

            check(connect_token_entries[index].state == CONNECT_TOKEN_ENTRY_CONSUMED);
            check(connect_token_entries_find_or_add(connect_token_entries, address_a, mac, 0, expire_timestamp, current_timestamp, 300.0) == CONNECT_TOKEN_ENTRY_REFUSED);
            check(connect_token_entries_find_or_add(connect_token_entries, address_b, mac, 0, expire_timestamp, current_timestamp, 300.0) == CONNECT_TOKEN_ENTRY_REFUSED);

            // the mac may sit at an offset inside a larger buffer, as it does at the end of the private connect token

            {
                var token = new byte[CONNECT_TOKEN_PRIVATE_BYTES];
                Array.Copy(mac, 0, token, CONNECT_TOKEN_PRIVATE_BYTES - MAC_BYTES, MAC_BYTES);
                check(connect_token_entries_find_or_add(connect_token_entries, address_a, token, CONNECT_TOKEN_PRIVATE_BYTES - MAC_BYTES, expire_timestamp, current_timestamp, 300.0) == CONNECT_TOKEN_ENTRY_REFUSED);
            }

            // a history whose entries all hold unexpired connect tokens refuses a new connect token
            // instead of evicting one

            int i;
            for (i = 1; i < MAX_CONNECT_TOKEN_ENTRIES; i++)
            {
                Array.Clear(mac, 0, MAC_BYTES);
                mac[0] = (byte)(i + 1);
                mac[1] = (byte)((i + 1) >> 8);
                check(connect_token_entries_find_or_add(connect_token_entries, address_a, mac, 0, expire_timestamp, current_timestamp, 400.0) >= 0);
            }

            Array.Clear(mac, 0, MAC_BYTES);
            mac[0] = 0xFF;
            mac[1] = 0xFF;

            check(connect_token_entries_find_or_add(connect_token_entries, address_a, mac, 0, expire_timestamp, current_timestamp, 500.0) == CONNECT_TOKEN_HISTORY_FULL);

            // the consumed entry is still refusing its connect token, and was not evicted by the flood

            Array.Clear(mac, 0, MAC_BYTES);
            mac[0] = 1;

            check(connect_token_entries_find_or_add(connect_token_entries, address_a, mac, 0, expire_timestamp, current_timestamp, 500.0) == CONNECT_TOKEN_ENTRY_REFUSED);

            // entries live until their connect token expires. once they have, the history takes new connect tokens again

            Array.Clear(mac, 0, MAC_BYTES);
            mac[0] = 0xFF;
            mac[1] = 0xFF;

            check(connect_token_entries_find_or_add(connect_token_entries, address_a, mac, 0, expire_timestamp, expire_timestamp, 600.0) >= 0);
        }

        /*
            A client and a server wired directly to each other through the send and receive overrides.
            Packets are handed straight to the other side, so the handshake is exercised with no sockets,
            no network simulator and no randomness at all. The wire can drop the first packets the server
            sends, which is what makes the client retransmit its connection request, and it keeps a copy
            of the first payload packet the client sends so it can be replayed later.
        */

        class test_wire_t
        {
            public netcode_client_t client;
            public netcode_server_t server;
            public netcode_address_t client_address;
            public netcode_address_t server_address;
            public bool shutting_down;
            public int drop_server_packets;
            public int num_connection_requests;
            public byte[] payload_packet = new byte[MAX_PACKET_BYTES];
            public int payload_packet_bytes;
        }

        static test_wire_t test_wire = new test_wire_t();

        static void test_wire_client_send_packet(object context, netcode_address_t to, byte[] packet_data, int packet_bytes)
        {
            // the wire is down once either end is being destroyed. the disconnect packets they send
            // on the way out have nowhere to go, exactly as an application shutting down would find

            if (test_wire.shutting_down)
                return;

            if (packet_data[0] == CONNECTION_REQUEST_PACKET)
                test_wire.num_connection_requests++;

            if ((packet_data[0] & 0xF) == CONNECTION_PAYLOAD_PACKET && test_wire.payload_packet_bytes == 0)
            {
                Array.Copy(packet_data, test_wire.payload_packet, packet_bytes);
                test_wire.payload_packet_bytes = packet_bytes;
            }

            var copy = new byte[packet_bytes];
            Array.Copy(packet_data, copy, packet_bytes);
            server_process_packet(test_wire.server, test_wire.client_address, copy, packet_bytes);
        }

        static void test_wire_server_send_packet(object context, netcode_address_t to, byte[] packet_data, int packet_bytes)
        {
            if (test_wire.shutting_down)
                return;

            if (test_wire.drop_server_packets > 0)
            {
                test_wire.drop_server_packets--;
                return;
            }

            var copy = new byte[packet_bytes];
            Array.Copy(packet_data, copy, packet_bytes);
            client_process_packet(test_wire.client, test_wire.server_address, copy, packet_bytes);
        }

        static int test_wire_receive_packet(object context, netcode_address_t from, byte[] packet_data, int max_packet_bytes) => 0;

        static void test_wire_create(int drop_server_packets)
        {
            test_wire = new test_wire_t();

            test_wire.drop_server_packets = drop_server_packets;

            check(parse_address("[::1]:50000", out test_wire.client_address) == OK);
            check(parse_address("[::1]:40000", out test_wire.server_address) == OK);

            default_client_config(out var client_config);
            client_config.override_send_and_receive = true;
            client_config.send_packet_override = test_wire_client_send_packet;
            client_config.receive_packet_override = test_wire_receive_packet;

            test_wire.client = client_create("[::1]:50000", client_config, 0.0);

            check(test_wire.client != null);

            default_server_config(out var server_config);
            server_config.protocol_id = TEST_PROTOCOL_ID;
            server_config.override_send_and_receive = true;
            server_config.send_packet_override = test_wire_server_send_packet;
            server_config.receive_packet_override = test_wire_receive_packet;
            BufferEx.Copy(server_config.private_key, private_key, KEY_BYTES);

            test_wire.server = server_create("[::1]:40000", server_config, 0.0);

            check(test_wire.server != null);

            server_start(test_wire.server, 1);
        }

        static void test_wire_destroy()
        {
            test_wire.shutting_down = true;
            server_destroy(ref test_wire.server);
            client_destroy(ref test_wire.client);
            test_wire = new test_wire_t();
        }

        static void test_wire_connect_client(byte[] connect_token, ref double time, double delta_time)
        {
            client_connect(test_wire.client, connect_token);

            while (true)
            {
                client_update(test_wire.client, time);

                server_update(test_wire.server, time);

                if (client_state(test_wire.client) <= CLIENT_STATE_DISCONNECTED)
                    break;

                if (client_state(test_wire.client) == CLIENT_STATE_CONNECTED)
                    break;

                time += delta_time;
            }
        }

        static void test_wire_generate_connect_token(byte[] connect_token, ulong client_id, int expire_seconds)
        {
            var server_address = new[] { "[::1]:40000" };

            var user_data = new byte[USER_DATA_BYTES];
            random_bytes(user_data, USER_DATA_BYTES);

            check(generate_connect_token(1, server_address, server_address, expire_seconds, TEST_TIMEOUT_SECONDS, client_id, TEST_PROTOCOL_ID, private_key, user_data, connect_token) == OK);
        }

        static void test_client_server_connection_request_retransmission()
        {
            // the first three packets the server sends are dropped, so the client retransmits its
            // connection request into a handshake the server already has a pending history entry for

            test_wire_create(3);

            var time = 0.0;
            const double delta_time = 1.0 / 10.0;

            var connect_token = new byte[CONNECT_TOKEN_BYTES];
            test_wire_generate_connect_token(connect_token, TEST_CLIENT_ID, TEST_CONNECT_TOKEN_EXPIRY);

            test_wire_connect_client(connect_token, ref time, delta_time);

            check(client_state(test_wire.client) == CLIENT_STATE_CONNECTED);
            check(server_client_connected(test_wire.server, 0));
            check(server_num_connected_clients(test_wire.server) == 1);
            check(test_wire.num_connection_requests >= 4);

            test_wire_destroy();
        }

        static void test_client_server_replay_across_sessions()
        {
            test_wire_create(0);

            var time = 0.0;
            const double delta_time = 1.0 / 10.0;

            // connect a first session and keep a copy of a payload packet the client sends in it

            var connect_token = new byte[CONNECT_TOKEN_BYTES];
            test_wire_generate_connect_token(connect_token, TEST_CLIENT_ID, TEST_CONNECT_TOKEN_EXPIRY);

            test_wire_connect_client(connect_token, ref time, delta_time);

            check(client_state(test_wire.client) == CLIENT_STATE_CONNECTED);

            var payload = new byte[MAX_PACKET_SIZE];
            int i;
            for (i = 0; i < MAX_PACKET_SIZE; i++)
                payload[i] = (byte)i;

            client_send_packet(test_wire.client, payload, MAX_PACKET_SIZE);

            check(test_wire.payload_packet_bytes > 0);

            // disconnect, then connect a second session with a new connect token

            server_disconnect_client(test_wire.server, 0);

            while (client_state(test_wire.client) > CLIENT_STATE_DISCONNECTED)
            {
                client_update(test_wire.client, time);
                server_update(test_wire.server, time);
                time += delta_time;
            }

            var second_connect_token = new byte[CONNECT_TOKEN_BYTES];
            test_wire_generate_connect_token(second_connect_token, TEST_CLIENT_ID, TEST_CONNECT_TOKEN_EXPIRY);

            test_wire_connect_client(second_connect_token, ref time, delta_time);

            check(client_state(test_wire.client) == CLIENT_STATE_CONNECTED);

            // drain anything the second session has delivered so far

            while (true)
            {
                var packet = server_receive_packet(test_wire.server, 0, out var bytes, out var sequence);
                if (packet == null)
                    break;
                server_free_packet(test_wire.server, ref packet);
            }

            // the datagram from the first session is refused by the second

            var replay = new byte[test_wire.payload_packet_bytes];
            Array.Copy(test_wire.payload_packet, replay, replay.Length);
            server_process_packet(test_wire.server, test_wire.client_address, replay, replay.Length);

            check(server_receive_packet(test_wire.server, 0, out var packet_bytes, out var packet_sequence) == null);

            test_wire_destroy();
        }

        static void test_client_reconnect_with_used_connect_token()
        {
            test_wire_create(0);

            var time = 0.0;
            const double delta_time = 1.0 / 10.0;

            var connect_token = new byte[CONNECT_TOKEN_BYTES];
            test_wire_generate_connect_token(connect_token, TEST_CLIENT_ID, TEST_CONNECT_TOKEN_EXPIRY);

            test_wire_connect_client(connect_token, ref time, delta_time);

            check(client_state(test_wire.client) == CLIENT_STATE_CONNECTED);
            check(server_num_connected_clients(test_wire.server) == 1);

            // disconnect the client server side and wait until the client sees it

            server_disconnect_client(test_wire.server, 0);

            while (client_state(test_wire.client) > CLIENT_STATE_DISCONNECTED)
            {
                client_update(test_wire.client, time);
                server_update(test_wire.server, time);
                time += delta_time;
            }

            check(server_num_connected_clients(test_wire.server) == 0);

            // the connect token is spent. presenting it again, from the same address that used it,
            // connects nothing: the client runs out of connection request retries instead

            test_wire_connect_client(connect_token, ref time, delta_time);

            check(client_state(test_wire.client) == CLIENT_STATE_CONNECTION_REQUEST_TIMED_OUT);
            check(server_num_connected_clients(test_wire.server) == 0);

            test_wire_destroy();
        }

        static void test_client_error_connect_token_predates_server_start()
        {
            test_wire_create(0);

            var time = 0.0;
            const double delta_time = 1.0 / 10.0;

            // a connect token with a shorter lifetime than the server's configured maximum expires
            // earlier than any connect token the backend could have issued after the server started,
            // which is exactly the shape of a connect token issued before it started

            var connect_token = new byte[CONNECT_TOKEN_BYTES];
            test_wire_generate_connect_token(connect_token, TEST_CLIENT_ID, DEFAULT_MAX_CONNECT_TOKEN_LIFETIME - 10);

            test_wire_connect_client(connect_token, ref time, delta_time);

            check(client_state(test_wire.client) == CLIENT_STATE_CONNECTION_REQUEST_TIMED_OUT);
            check(server_num_connected_clients(test_wire.server) == 0);

            // a connect token with the full lifetime connects

            test_wire_generate_connect_token(connect_token, TEST_CLIENT_ID, TEST_CONNECT_TOKEN_EXPIRY);

            test_wire_connect_client(connect_token, ref time, delta_time);

            check(client_state(test_wire.client) == CLIENT_STATE_CONNECTED);
            check(server_num_connected_clients(test_wire.server) == 1);

            test_wire_destroy();
        }

        static void test_disable_timeout()
        {
            var network_simulator = network_simulator_create(null, null, null);

            network_simulator.latency_milliseconds = 250;
            network_simulator.jitter_milliseconds = 250;
            network_simulator.packet_loss_percent = 5;
            network_simulator.duplicate_packet_percent = 10;

            var time = 0.0;
            const double delta_time = 1.0 / 10.0;

            default_client_config(out var client_config);
            client_config.network_simulator = network_simulator;

            var client = client_create("[::]:50000", client_config, time);

            check(client != null);

            default_server_config(out var server_config);
            server_config.protocol_id = TEST_PROTOCOL_ID;
            server_config.network_simulator = network_simulator;
            BufferEx.Copy(server_config.private_key, private_key, KEY_BYTES);

            var server = server_create("[::1]:40000", server_config, time);

            check(server != null);

            server_start(server, 1);

            const string server_address = "[::1]:40000";

            var connect_token = new byte[CONNECT_TOKEN_BYTES];

            var client_id = 0UL;
            random_bytes(ref client_id, 8);

            var user_data = new byte[USER_DATA_BYTES];
            random_bytes(user_data, USER_DATA_BYTES);

            check(generate_connect_token(1, new[] { server_address }, new[] { server_address }, TEST_CONNECT_TOKEN_EXPIRY, -1, client_id, TEST_PROTOCOL_ID, private_key, user_data, connect_token) != 0);

            client_connect(client, connect_token);

            while (true)
            {
                network_simulator_update(network_simulator, time);
                client_update(client, time);
                server_update(server, time);

                if (client_state(client) <= CLIENT_STATE_DISCONNECTED)
                    break;
                if (client_state(client) == CLIENT_STATE_CONNECTED)
                    break;

                time += delta_time;
            }

            check(client_state(client) == CLIENT_STATE_CONNECTED);
            check(client_index(client) == 0);
            check(server_client_connected(server, 0));
            check(server_num_connected_clients(server) == 1);

            var server_num_packets_received = 0;
            var client_num_packets_received = 0;

            var packet_data = new byte[MAX_PACKET_SIZE];
            int i;
            for (i = 0; i < MAX_PACKET_SIZE; ++i)
                packet_data[i] = (byte)i;

            while (true)
            {
                network_simulator_update(network_simulator, time);
                client_update(client, time);
                server_update(server, time);
                client_send_packet(client, packet_data, MAX_PACKET_SIZE);
                server_send_packet(server, 0, packet_data, MAX_PACKET_SIZE);

                while (true)
                {
                    var packet = client_receive_packet(client, out var packet_bytes, out var packet_sequence);
                    if (packet == null)
                        break;
                    assert(packet_bytes == MAX_PACKET_SIZE);
                    assert(BufferEx.Equal(packet, packet_data, MAX_PACKET_SIZE));
                    client_num_packets_received++;
                    client_free_packet(client, ref packet);
                }

                while (true)
                {
                    var packet = server_receive_packet(server, 0, out var packet_bytes, out var packet_sequence);
                    if (packet == null)
                        break;
                    assert(packet_bytes == MAX_PACKET_SIZE);
                    assert(BufferEx.Equal(packet, packet_data, MAX_PACKET_SIZE));
                    server_num_packets_received++;
                    server_free_packet(server, ref packet);
                }

                if (client_num_packets_received >= 10 && server_num_packets_received >= 10)
                    if (server_client_connected(server, 0))
                        server_disconnect_client(server, 0);

                if (client_state(client) <= CLIENT_STATE_DISCONNECTED)
                    break;

                time += 1000.0f;        // normally this would timeout the client
            }

            check(client_num_packets_received >= 10 && server_num_packets_received >= 10);

            server_destroy(ref server);
            client_destroy(ref client);
            network_simulator_destroy(ref network_simulator);
        }

        static void test_loopback()
        {
            var context = new test_loopback_context_t();

            var network_simulator = network_simulator_create(null, null, null);

            network_simulator.latency_milliseconds = 250;
            network_simulator.jitter_milliseconds = 250;
            network_simulator.packet_loss_percent = 5;
            network_simulator.duplicate_packet_percent = 10;

            var time = 0.0;
            const double delta_time = 1.0 / 10.0;

            // start the server

            default_server_config(out var server_config);
            server_config.protocol_id = TEST_PROTOCOL_ID;
            server_config.network_simulator = network_simulator;
            server_config.callback_context = context;
            server_config.send_loopback_packet_callback = server_send_loopback_packet_callback;
            BufferEx.Copy(server_config.private_key, private_key, KEY_BYTES);

            var server = server_create("[::1]:40000", server_config, time);

            check(server != null);

            var max_clients = 2;

            server_start(server, max_clients);

            context.server = server;

            // connect a loopback client in slot 0

            default_client_config(out var client_config);
            client_config.callback_context = context;
            client_config.send_loopback_packet_callback = client_send_loopback_packet_callback;
            client_config.network_simulator = network_simulator;

            var loopback_client = client_create("[::]:50000", client_config, time);
            check(loopback_client != null);
            client_connect_loopback(loopback_client, 0, max_clients);
            context.client = loopback_client;

            check(client_index(loopback_client) == 0);
            check(client_loopback(loopback_client));
            check(client_max_clients(loopback_client) == max_clients);
            check(client_state(loopback_client) == CLIENT_STATE_CONNECTED);

            var client_id = 0UL;
            random_bytes(ref client_id, 8);
            server_connect_loopback_client(server, 0, client_id, null);

            check(server_client_loopback(server, 0));
            check(server_client_connected(server, 0));
            check(server_num_connected_clients(server) == 1);

            // connect a regular client in the other slot

            var regular_client = client_create("[::]:50001", client_config, time);

            check(regular_client != null);

            const string server_address = "[::1]:40000";

            var connect_token = new byte[CONNECT_TOKEN_BYTES];
            random_bytes(ref client_id, 8);

            var user_data = new byte[USER_DATA_BYTES];
            random_bytes(user_data, USER_DATA_BYTES);

            check(generate_connect_token(1, new[] { server_address }, new[] { server_address }, TEST_CONNECT_TOKEN_EXPIRY, TEST_TIMEOUT_SECONDS, client_id, TEST_PROTOCOL_ID, private_key, user_data, connect_token) != 0);

            client_connect(regular_client, connect_token);

            while (true)
            {
                network_simulator_update(network_simulator, time);
                client_update(regular_client, time);
                server_update(server, time);

                if (client_state(regular_client) <= CLIENT_STATE_DISCONNECTED)
                    break;
                if (client_state(regular_client) == CLIENT_STATE_CONNECTED)
                    break;

                time += delta_time;
            }

            check(client_state(regular_client) == CLIENT_STATE_CONNECTED);
            check(client_index(regular_client) == 1);
            check(server_client_connected(server, 0));
            check(server_client_connected(server, 1));
            check(server_client_loopback(server, 0));
            check(!server_client_loopback(server, 1));
            check(server_num_connected_clients(server) == 2);

            // test that we can exchange packets for the regular client and the loopback client

            var loopback_client_num_packets_received = 0;
            var loopback_server_num_packets_received = 0;
            var regular_server_num_packets_received = 0;
            var regular_client_num_packets_received = 0;

            var packet_data = new byte[MAX_PACKET_SIZE];
            int i;
            for (i = 0; i < MAX_PACKET_SIZE; ++i)
                packet_data[i] = (byte)i;

            while (true)
            {
                network_simulator_update(network_simulator, time);
                client_update(regular_client, time);
                server_update(server, time);
                client_send_packet(loopback_client, packet_data, MAX_PACKET_SIZE);
                client_send_packet(regular_client, packet_data, MAX_PACKET_SIZE);
                server_send_packet(server, 0, packet_data, MAX_PACKET_SIZE);
                server_send_packet(server, 1, packet_data, MAX_PACKET_SIZE);

                while (true)
                {
                    var packet = client_receive_packet(loopback_client, out var packet_bytes, out var packet_sequence);
                    if (packet == null)
                        break;
                    assert(packet_bytes == MAX_PACKET_SIZE);
                    assert(BufferEx.Equal(packet, packet_data, MAX_PACKET_SIZE));
                    loopback_client_num_packets_received++;
                    client_free_packet(loopback_client, ref packet);
                }

                while (true)
                {
                    var packet = client_receive_packet(regular_client, out var packet_bytes, out var packet_sequence);
                    if (packet == null)
                        break;
                    assert(packet_bytes == MAX_PACKET_SIZE);
                    assert(BufferEx.Equal(packet, packet_data, MAX_PACKET_SIZE));
                    regular_client_num_packets_received++;
                    client_free_packet(regular_client, ref packet);
                }

                while (true)
                {
                    var packet = server_receive_packet(server, 0, out var packet_bytes, out var packet_sequence);
                    if (packet == null)
                        break;
                    assert(packet_bytes == MAX_PACKET_SIZE);
                    assert(BufferEx.Equal(packet, packet_data, MAX_PACKET_SIZE));
                    loopback_server_num_packets_received++;
                    server_free_packet(server, ref packet);
                }

                while (true)
                {
                    var packet = server_receive_packet(server, 1, out var packet_bytes, out var packet_sequence);
                    if (packet == null)
                        break;
                    assert(packet_bytes == MAX_PACKET_SIZE);
                    assert(BufferEx.Equal(packet, packet_data, MAX_PACKET_SIZE));
                    regular_server_num_packets_received++;
                    server_free_packet(server, ref packet);
                }

                if (loopback_client_num_packets_received >= 10 && loopback_server_num_packets_received >= 10 &&
                     regular_client_num_packets_received >= 10 && regular_server_num_packets_received >= 10)
                    break;

                if (client_state(regular_client) <= CLIENT_STATE_DISCONNECTED)
                    break;

                time += delta_time;
            }

            check(loopback_client_num_packets_received >= 10);
            check(loopback_server_num_packets_received >= 10);
            check(regular_client_num_packets_received >= 10);
            check(regular_server_num_packets_received >= 10);
            check(context.num_loopback_packets_sent_to_client >= 10);
            check(context.num_loopback_packets_sent_to_server >= 10);

            // verify that we can disconnect the loopback client

            check(server_client_loopback(server, 0));
            check(server_client_connected(server, 0));
            check(server_num_connected_clients(server) == 2);

            server_disconnect_loopback_client(server, 0);

            check(!server_client_loopback(server, 0));
            check(!server_client_connected(server, 0));
            check(server_num_connected_clients(server) == 1);

            client_disconnect_loopback(loopback_client);

            check(client_state(loopback_client) == CLIENT_STATE_DISCONNECTED);

            // verify that we can reconnect the loopback client

            random_bytes(ref client_id, 8);
            server_connect_loopback_client(server, 0, client_id, null);

            check(server_client_loopback(server, 0));
            check(!server_client_loopback(server, 1));
            check(server_client_connected(server, 0));
            check(server_client_connected(server, 1));
            check(server_num_connected_clients(server) == 2);

            client_connect_loopback(loopback_client, 0, max_clients);

            check(client_index(loopback_client) == 0);
            check(client_loopback(loopback_client));
            check(client_max_clients(loopback_client) == max_clients);
            check(client_state(loopback_client) == CLIENT_STATE_CONNECTED);

            // verify that we can exchange packets for both regular and loopback client post reconnect

            loopback_server_num_packets_received = 0;
            loopback_client_num_packets_received = 0;
            regular_server_num_packets_received = 0;
            regular_client_num_packets_received = 0;
            context.num_loopback_packets_sent_to_client = 0;
            context.num_loopback_packets_sent_to_server = 0;

            while (true)
            {
                network_simulator_update(network_simulator, time);
                client_update(regular_client, time);
                server_update(server, time);
                client_send_packet(loopback_client, packet_data, MAX_PACKET_SIZE);
                client_send_packet(regular_client, packet_data, MAX_PACKET_SIZE);
                server_send_packet(server, 0, packet_data, MAX_PACKET_SIZE);
                server_send_packet(server, 1, packet_data, MAX_PACKET_SIZE);

                while (true)
                {
                    var packet = client_receive_packet(loopback_client, out var packet_bytes, out var packet_sequence);
                    if (packet == null)
                        break;
                    assert(packet_bytes == MAX_PACKET_SIZE);
                    assert(BufferEx.Equal(packet, packet_data, MAX_PACKET_SIZE));
                    loopback_client_num_packets_received++;
                    client_free_packet(loopback_client, ref packet);
                }

                while (true)
                {
                    var packet = client_receive_packet(regular_client, out var packet_bytes, out var packet_sequence);
                    if (packet == null)
                        break;
                    assert(packet_bytes == MAX_PACKET_SIZE);
                    assert(BufferEx.Equal(packet, packet_data, MAX_PACKET_SIZE));
                    regular_client_num_packets_received++;
                    client_free_packet(regular_client, ref packet);
                }

                while (true)
                {
                    var packet = server_receive_packet(server, 0, out var packet_bytes, out var packet_sequence);
                    if (packet == null)
                        break;
                    assert(packet_bytes == MAX_PACKET_SIZE);
                    assert(BufferEx.Equal(packet, packet_data, MAX_PACKET_SIZE));
                    loopback_server_num_packets_received++;
                    server_free_packet(server, ref packet);
                }

                while (true)
                {
                    var packet = server_receive_packet(server, 1, out var packet_bytes, out var packet_sequence);
                    if (packet == null)
                        break;
                    assert(packet_bytes == MAX_PACKET_SIZE);
                    assert(BufferEx.Equal(packet, packet_data, MAX_PACKET_SIZE));
                    regular_server_num_packets_received++;
                    server_free_packet(server, ref packet);
                }

                if (loopback_client_num_packets_received >= 10 && loopback_server_num_packets_received >= 10 &&
                     regular_client_num_packets_received >= 10 && regular_server_num_packets_received >= 10)
                    break;

                if (client_state(regular_client) <= CLIENT_STATE_DISCONNECTED)
                    break;

                time += delta_time;
            }

            check(loopback_client_num_packets_received >= 10);
            check(loopback_server_num_packets_received >= 10);
            check(regular_client_num_packets_received >= 10);
            check(regular_server_num_packets_received >= 10);
            check(context.num_loopback_packets_sent_to_client >= 10);
            check(context.num_loopback_packets_sent_to_server >= 10);

            // verify the regular client times out but loopback client doesn't

            time += 100000.0;

            server_update(server, time);

            check(server_client_connected(server, 0));
            check(!server_client_connected(server, 1));

            client_update(loopback_client, time);

            check(client_state(loopback_client) == CLIENT_STATE_CONNECTED);

            // verify that disconnect all clients leaves loopback clients alone

            server_disconnect_all_clients(server);

            check(server_client_connected(server, 0));
            check(!server_client_connected(server, 1));
            check(server_client_loopback(server, 0));

            // clean up

            client_destroy(ref regular_client);
            client_destroy(ref loopback_client);
            server_destroy(ref server);
            network_simulator_destroy(ref network_simulator);
        }

        static void test_packet_tagging()
        {
            // IMPORTANT: Packet tagging is off by default because it doesn't play well with some older home routers.
            // However, providing players with a way to turn it on is recommended, since it can significantly reduce
            // jitter playing over Wi-Fi.

            enable_packet_tagging();

            foreach (var (server_address, client_address) in new[] { ("127.0.0.1:40000", "127.0.0.1:50000"), ("[::1]:40000", "[::1]:50000") })
            {
                default_server_config(out var server_config);

                var server = server_create(server_address, server_config, 0.0);

                check(server != null);

                default_client_config(out var client_config);

                var client = client_create(client_address, client_config, 0.0);

                check(client != null);

                var connect_token = new byte[CONNECT_TOKEN_BYTES];

                var client_id = 0UL;
                random_bytes(ref client_id, 8);

                var user_data = new byte[USER_DATA_BYTES];
                random_bytes(user_data, USER_DATA_BYTES);

                check(generate_connect_token(1, new[] { server_address }, new[] { server_address }, TEST_CONNECT_TOKEN_EXPIRY, TEST_TIMEOUT_SECONDS, client_id, TEST_PROTOCOL_ID, private_key, user_data, connect_token) == OK);

                client_connect(client, connect_token);

                client_destroy(ref client);

                server_destroy(ref server);
            }

            // tagging is process wide. turn it back off so the tests that follow run with the default
            packet_tagging_enabled = false;
        }

        static void test_loopback_callback_required()
        {
            // entering loopback with send_loopback_packet_callback unset would call a null reference
            // on the next send. both sides must refuse to enter loopback instead. the guard asserts
            // as well as returning, so install the handler that continues to run this in debug.

            set_assert_function(test_runtime_guards_assert_handler);

            default_client_config(out var client_config);

            var client = client_create("0.0.0.0:50000", client_config, 0.0);

            check(client != null);

            client_connect_loopback(client, 0, 1);

            check(!client_loopback(client));
            check(client_state(client) == CLIENT_STATE_DISCONNECTED);

            var payload = new byte[MAX_PACKET_SIZE];

            client_send_packet(client, payload, MAX_PACKET_SIZE);

            client_destroy(ref client);

            default_server_config(out var server_config);

            var server = server_create("127.0.0.1:40000", server_config, 0.0);

            check(server != null);

            server_start(server, 1);

            server_connect_loopback_client(server, 0, 1, null);

            check(!server_client_loopback(server, 0));
            check(!server_client_connected(server, 0));
            check(server_num_connected_clients(server) == 0);

            server_send_packet(server, 0, payload, MAX_PACKET_SIZE);

            server_destroy(ref server);

            set_assert_function(default_assert_handler);
        }

        public static void test()
        {
            //log_level(LOG_LEVEL_DEBUG);
            //while (true)
            {
                Console.WriteLine("test_crypto_aead_vectors"); test_crypto_aead_vectors();
                Console.WriteLine("test_queue"); test_queue();
                Console.WriteLine("test_endian"); test_endian();
                Console.WriteLine("test_address"); test_address();
                Console.WriteLine("test_sequence"); test_sequence();
                Console.WriteLine("test_connect_token"); test_connect_token();
                Console.WriteLine("test_generate_connect_token_out_of_range"); test_generate_connect_token_out_of_range();
                Console.WriteLine("test_challenge_token"); test_challenge_token();
                Console.WriteLine("test_connection_request_packet"); test_connection_request_packet();
                Console.WriteLine("test_connection_denied_packet"); test_connection_denied_packet();
                Console.WriteLine("test_connection_challenge_packet"); test_connection_challenge_packet();
                Console.WriteLine("test_connection_response_packet"); test_connection_response_packet();
                Console.WriteLine("test_connection_keep_alive_packet"); test_connection_keep_alive_packet();
                Console.WriteLine("test_connection_payload_packet"); test_connection_payload_packet();
                Console.WriteLine("test_connection_disconnect_packet"); test_connection_disconnect_packet();
                Console.WriteLine("test_connect_token_public"); test_connect_token_public();
                Console.WriteLine("test_encryption_manager"); test_encryption_manager();
                Console.WriteLine("test_replay_protection"); test_replay_protection();
                Console.WriteLine("test_runtime_guards"); test_runtime_guards();
                Console.WriteLine("test_init_and_defaults"); test_init_and_defaults();
                Console.WriteLine("test_client_create_error"); test_client_create_error();
                Console.WriteLine("test_server_create_error"); test_server_create_error();
                Console.WriteLine("test_network_simulator_determinism"); test_network_simulator_determinism();
                Console.WriteLine("test_client_create"); test_client_create();
                Console.WriteLine("test_server_create"); test_server_create();
                Console.WriteLine("test_server_restart_global_sequence"); test_server_restart_global_sequence();
                Console.WriteLine("test_client_server_connect"); test_client_server_connect();
                Console.WriteLine("test_client_server_ipv4_socket_connect"); test_client_server_ipv4_socket_connect();
                Console.WriteLine("test_client_server_ipv6_socket_connect"); test_client_server_ipv6_socket_connect();
                Console.WriteLine("test_client_server_dual_socket_connect"); test_client_server_dual_socket_connect();
                Console.WriteLine("test_client_server_keep_alive"); test_client_server_keep_alive();
                Console.WriteLine("test_client_server_multiple_clients"); test_client_server_multiple_clients();
                Console.WriteLine("test_client_server_multiple_servers"); test_client_server_multiple_servers();
                Console.WriteLine("test_client_error_connect_token_expired"); test_client_error_connect_token_expired();
                Console.WriteLine("test_client_error_invalid_connect_token"); test_client_error_invalid_connect_token();
                Console.WriteLine("test_client_error_connection_timed_out"); test_client_error_connection_timed_out();
                Console.WriteLine("test_client_error_connection_response_timeout"); test_client_error_connection_response_timeout();
                Console.WriteLine("test_client_error_connection_request_timeout"); test_client_error_connection_request_timeout();
                Console.WriteLine("test_client_error_connection_denied"); test_client_error_connection_denied();
                Console.WriteLine("test_client_side_disconnect"); test_client_side_disconnect();
                Console.WriteLine("test_server_side_disconnect"); test_server_side_disconnect();
                Console.WriteLine("test_server_client_disconnect_reason"); test_server_client_disconnect_reason();
                Console.WriteLine("test_client_reconnect"); test_client_reconnect();
                Console.WriteLine("test_connect_token_entries"); test_connect_token_entries();
                Console.WriteLine("test_client_server_connection_request_retransmission"); test_client_server_connection_request_retransmission();
                Console.WriteLine("test_client_server_replay_across_sessions"); test_client_server_replay_across_sessions();
                Console.WriteLine("test_client_reconnect_with_used_connect_token"); test_client_reconnect_with_used_connect_token();
                Console.WriteLine("test_client_error_connect_token_predates_server_start"); test_client_error_connect_token_predates_server_start();
                Console.WriteLine("test_disable_timeout"); test_disable_timeout();
                Console.WriteLine("test_loopback"); test_loopback();
                Console.WriteLine("test_loopback_callback_required"); test_loopback_callback_required();
                Console.WriteLine("test_packet_tagging"); test_packet_tagging();
            }
        }
    }
}
