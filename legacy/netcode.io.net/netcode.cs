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
using Org.BouncyCastle.Crypto.Tls;
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

    public static partial class netcode
    {
        public const int CONNECT_TOKEN_BYTES = 2048;
        public const int KEY_BYTES = 32;
        public const int MAC_BYTES = 16;
        public const int USER_DATA_BYTES = 256;
        public const int MAX_SERVERS_PER_CONNECT = 32;

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

        public const int MAX_CLIENTS = 256;
        public const int MAX_PACKET_SIZE = 1200;

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
        internal const int MAX_ADDRESS_STRING_LENGTH = 256;
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

        [DebuggerStepThrough, Conditional("DEBUG")]
        public static void assert(bool condition)
        {
            if (!condition)
            {
                var stackFrame = new StackTrace().GetFrame(1);
                assert_function?.Invoke("n/a", stackFrame.GetMethod().Name, stackFrame.GetFileName(), stackFrame.GetFileLineNumber());
                Environment.Exit(1);
            }
        }

        #endregion

        #region assert / logging

        static void default_assert_handler(string condition, string function, string file, int line)
        {
            Console.Write($"assert failed: ( {condition} ), function {function}, file {file}, line {line}\n");
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

#if !NETCODE_ENABLE_LOGGING
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

        public static int parse_address(string address_string, out netcode_address_t address)
        {
            assert(address_string != null);
            address = new netcode_address_t(); //: assert(address != null);

            // first try to parse the string as an IPv6 address:
            // 1. if the first character is '[' then it's probably an ipv6 in form "[addr6]:portnum"
            // 2. otherwise try to parse as a raw IPv6 address using inet_pton
            int base_index;
            var address_string_length = address_string.Length;

            if (address_string_length > 0 && address_string[0] == '[')
            {
                base_index = address_string_length - 1;
                for (var i = 0; i < 6; ++i)         // note: no need to search past 6 characters as ":65535" is longest possible port value
                {
                    var index = base_index - i;
                    if (index < 3)
                        return ERROR;
                    if (address_string[index] == ':')
                    {
                        string value;
                        address.port = (ushort)((value = address_string.Substring(index + 1)).Length > 0 ? int.Parse(value) : 0);
                        address_string = address_string.Substring(0, index - 1);
                    }
                }
                address_string = address_string.Substring(1);
            }

            if (IPAddress.TryParse(address_string, out var ipaddress) && ipaddress.AddressFamily == AddressFamily.InterNetworkV6)
            {
                address.type = ADDRESS_IPV6;
                address.data = ipaddress;
                return OK;
            }

            // otherwise it's probably an IPv4 address:
            // 1. look for ":portnum", if found save the portnum and strip it out
            // 2. parse remaining ipv4 address via inet_pton

            address_string_length = address_string.Length;
            base_index = address_string_length - 1;
            for (var i = 0; i < 6; ++i)
            {
                int index = base_index - i;
                if (index < 0)
                    break;
                if (address_string[index] == ':')
                {
                    string value;
                    address.port = (ushort)((value = address_string.Substring(index + 1)).Length > 0 ? int.Parse(value) : 0);
                    address_string = address_string.Substring(0, index);
                }
            }

            if (IPAddress.TryParse(address_string, out ipaddress) && ipaddress.AddressFamily == AddressFamily.InterNetwork)
            {
                address.type = ADDRESS_IPV4;
                address.data = ipaddress;
                return OK;
            }

            return ERROR;
        }

        public static string address_to_string(netcode_address_t address)
        {
            assert(address != null);
            if (address.type == ADDRESS_IPV6) return $"[{address.data}]{(address.port != 0 ? $":{address.port}" : null)}";
            else if (address.type == ADDRESS_IPV4) return $"{address.data}{(address.port != 0 ? $":{address.port}" : null)}";
            else return "NONE";
        }

        public static bool address_equal(netcode_address_t a, netcode_address_t b)
        {
            assert(a != null);
            assert(b != null);
            return a.type == b.type &&
                a.port == b.port &&
                Enumerable.SequenceEqual(a.data.GetAddressBytes(), b.data.GetAddressBytes());
        }

        #endregion

        #region netcode_t

        internal struct netcode_t
        {
            public bool initialized;
        }

        static netcode_t netcode_;

        public static int init()
        {
            assert(!netcode_.initialized);

            netcode_.initialized = true;

            return OK;
        }

        public static void term()
        {
            assert(netcode_.initialized);

            netcode_.initialized = false;
        }

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
        const int SOCKET_ERROR_BIND_FAILED = 6;
        const int SOCKET_ERROR_GET_SOCKNAME_FAILED = 8;

        static void socket_destroy(ref socket_t socket)
        {
            assert(socket != null);
            assert(netcode_.initialized);

            if (socket.handle != null)
                socket.handle.Close();
            socket = null;
        }

        static int socket_create(ref socket_t s, netcode_address_t address, int send_buffer_size, int receive_buffer_size)
        {
            assert(s != null);
            assert(address != null);
            assert(netcode_.initialized);

            assert(address.type != ADDRESS_NONE);

            s.address = address;

            // create socket

            try { s.handle = new Socket((address.type == ADDRESS_IPV6) ? AddressFamily.InterNetworkV6 : AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp); }
            catch
            {
                printf(LOG_LEVEL_ERROR, "error: failed to create socket\n");
                return SOCKET_ERROR_CREATE_FAILED;
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
            try { s.handle.SendBufferSize = send_buffer_size; }
            catch
            {
                printf(LOG_LEVEL_ERROR, "error: failed to set socket send buffer size\n");
                socket_destroy(ref s);
                return SOCKET_ERROR_SOCKOPT_SNDBUF_FAILED;
            }

            try { s.handle.ReceiveBufferSize = receive_buffer_size; }
            catch
            {
                printf(LOG_LEVEL_ERROR, "error: failed to set socket receive buffer size\n");
                socket_destroy(ref s);
                return SOCKET_ERROR_SOCKOPT_RCVBUF_FAILED;
            }

            // bind to port

            var endpoint = new IPEndPoint(address.data, address.port);
            try { s.handle.Bind(endpoint); }
            catch
            {
                printf(LOG_LEVEL_ERROR, "error: failed to bind socket\n");
                socket_destroy(ref s);
                return SOCKET_ERROR_BIND_FAILED;
            }

            // if bound to port 0 find the actual port we got

            if (address.port == 0)
            {
                if (s.handle.LocalEndPoint == null)
                {
                    printf(LOG_LEVEL_ERROR, "error: failed to get socket port\n");
                    socket_destroy(ref s);
                    return SOCKET_ERROR_GET_SOCKNAME_FAILED;
                }
                s.address.port = (ushort)((IPEndPoint)s.handle.LocalEndPoint).Port;
            }

            // set non-blocking io

            try { s.handle.Blocking = false; }
            catch
            {
                socket_destroy(ref s);
                return SOCKET_ERROR_SET_NON_BLOCKING_FAILED;
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

                if (error == SocketError.WouldBlock || error == SocketError.ConnectionReset)
                    return 0;

                printf(LOG_LEVEL_ERROR, $"error: recvfrom failed with error {error}\n");

                return 0;
            }
            if (result <= 0)
            {
                printf(LOG_LEVEL_ERROR, "error: recvfrom failed with error {}\n");
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

        readonly static RNGCryptoServiceProvider rngCrypto = new RNGCryptoServiceProvider();

        static void generate_key(byte[] key) { assert(key != null); rngCrypto.GetBytes(key); }

        static void generate_nonce(byte[] nonce) { assert(nonce != null); rngCrypto.GetBytes(nonce); }

        public static void random_bytes(ref ulong data, int bytes) { var v = new byte[bytes]; random_bytes(v, bytes); data = BitConverter.ToUInt64(v, 0); }

        public static void random_bytes(byte[] data, int bytes) { assert(data != null); assert(bytes > 0); assert(bytes == data.Length); rngCrypto.GetBytes(data); } //: randombytes_buf(data, bytes);

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
            if (sequence + REPLAY_PROTECTION_BUFFER_SIZE <= replay_protection.most_recent_sequence)
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
                    printf(LOG_LEVEL_DEBUG, $"ignored connection request packet. bad packet length (expected {1 + VERSION_INFO_BYTES + 8 + 8 + 8 + CONNECT_TOKEN_PRIVATE_BYTES}, got {buffer_length})\n");
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
                printf(LOG_LEVEL_ERROR, $"error: read connect data has bad version info (got {connect_token.version_info}, expected {VERSION_INFO})\n");
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

        static void packet_queue_clear(packet_queue_t queue)
        {
            int i;
            for (i = 0; i < queue.num_packets; ++i)
                queue.packet_data[i] = null;
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

        #endregion

        #region network_simulator_t

        internal const int NETWORK_SIMULATOR_NUM_PACKET_ENTRIES = MAX_CLIENTS * 256;
        internal const int NETWORK_SIMULATOR_NUM_PENDING_RECEIVE_PACKETS = MAX_CLIENTS * 64;

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
        }

        static void network_simulator_destroy(ref netcode_network_simulator_t network_simulator)
        {
            assert(network_simulator != null);
            network_simulator_reset(network_simulator);
            network_simulator = null;
        }

        static float random_float(float a, float b)
        {
            assert(a < b);
            var random = BufferEx.Rand() / (float)BufferEx.RAND_MAX;
            var diff = b - a;
            var r = random * diff;
            return a + r;
        }

        static void network_simulator_queue_packet(
            netcode_network_simulator_t network_simulator,
            netcode_address_t from,
            netcode_address_t to,
            byte[] packet_data,
            int packet_bytes,
            float delay)
        {
            network_simulator.packet_entries[network_simulator.current_index].from = from;
            network_simulator.packet_entries[network_simulator.current_index].to = to;
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

            if (random_float(0.0f, 100.0f) <= network_simulator.packet_loss_percent)
                return;

            if (network_simulator.packet_entries[network_simulator.current_index].packet_data != null)
                network_simulator.packet_entries[network_simulator.current_index].packet_data = null;

            var delay = network_simulator.latency_milliseconds / 1000.0f;

            if (network_simulator.jitter_milliseconds > 0.0)
                delay += random_float(-network_simulator.jitter_milliseconds, +network_simulator.jitter_milliseconds) / 1000.0f;

            network_simulator_queue_packet(network_simulator, from, to, packet_data, packet_bytes, delay);

            if (random_float(0.0f, 100.0f) <= network_simulator.duplicate_packet_percent)
                network_simulator_queue_packet(network_simulator, from, to, packet_data, packet_bytes, delay + random_float(0, 1.0f));
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
        static bool client_socket_create(ref socket_t socket, netcode_address_t address, int send_buffer_size, int receive_buffer_size, netcode_client_config_t config)
        {
            assert(socket != null);
            assert(address != null);
            assert(config != null);

            if (config.network_simulator == null)
            {
                if (!config.override_send_and_receive)
                    if (socket_create(ref socket, address, send_buffer_size, receive_buffer_size) != SOCKET_ERROR_NONE)
                        return false;
            }
            else if (address.port == 0)
            {
                printf(LOG_LEVEL_ERROR, "error: must bind to a specific port when using network simulator\n");
                return false;
            }
            return true;
        }

        static netcode_client_t client_create_overload(string address1_string, string address2_string, netcode_client_config_t config, double time)
        {
            assert(config != null);
            assert(netcode_.initialized);

            if (parse_address(address1_string, out var address1) != OK)
            {
                printf(LOG_LEVEL_ERROR, "error: failed to parse client address\n");
                return null;
            }
            var address2 = new netcode_address_t();
            if (address2_string != null && parse_address(address2_string, out address2) != OK)
            {
                printf(LOG_LEVEL_ERROR, "error: failed to parse client address2\n");
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
                    return null;
            }

            var client = new netcode_client_t();
            if (client == null)
            {
                socket_destroy(ref socket_ipv4);
                socket_destroy(ref socket_ipv6);
                return null;
            }

            var socket_address = address1.type == ADDRESS_IPV4 ? socket_ipv4.address : socket_ipv6.address;

            if (config.network_simulator == null)
                printf(LOG_LEVEL_INFO, $"client started on port {socket_address.port}\n");
            else
                printf(LOG_LEVEL_INFO, $"client started on port {socket_address.port} (network simulator)\n");

            client.config = config;
            client.socket_holder.ipv4 = socket_ipv4;
            client.socket_holder.ipv6 = socket_ipv6;
            client.address = config.network_simulator != null ? address1 : socket_address;
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
            client_create_overload(address, null, config, time);

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
            BufferEx.SetT(ref client.connect_token, 0);
            BufferEx.SetT(ref client.context, 0);

            client_set_state(client, client_state);

            client_reset_before_next_connect(client);

            while (true)
            {
                var packet = packet_queue_pop(client.packet_receive_queue, out var packet_sequence);
                if (packet == null)
                    break;
                packet = null;
            }

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
            client.server_address = client.connect_token.server_addresses[0];

            var server_address_string = new string[MAX_ADDRESS_STRING_LENGTH];

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

            var allowed_packets = new bool[CONNECTION_NUM_PACKETS];
            allowed_packets[CONNECTION_DENIED_PACKET] = true;
            allowed_packets[CONNECTION_CHALLENGE_PACKET] = true;
            allowed_packets[CONNECTION_KEEP_ALIVE_PACKET] = true;
            allowed_packets[CONNECTION_PAYLOAD_PACKET] = true;
            allowed_packets[CONNECTION_DISCONNECT_PACKET] = true;

            var current_timestamp = ctime();

            if (client.config.network_simulator == null)
            {
                // process packets received from socket

                var from = new netcode_address_t();
                var packet_data = new byte[MAX_PACKET_BYTES];
                var packet_bytes = 0;

                while (true)
                {
                    if (client.config.override_send_and_receive)
                        packet_bytes = client.config.receive_packet_override(client.config.callback_context, from, packet_data, MAX_PACKET_BYTES);
                    else if (client.server_address.type == ADDRESS_IPV4)
                        packet_bytes = socket_receive_packet(client.socket_holder.ipv4, from, packet_data, MAX_PACKET_BYTES);
                    else if (client.server_address.type == ADDRESS_IPV6)
                        packet_bytes = socket_receive_packet(client.socket_holder.ipv6, from, packet_data, MAX_PACKET_BYTES);

                    if (packet_bytes == 0)
                        break;

                    var packet = read_packet(
                        packet_data,
                        packet_bytes,
                        out var sequence,
                        client.context.read_packet_key,
                        client.connect_token.protocol_id,
                        current_timestamp,
                        null,
                        allowed_packets,
                        client.replay_protection,
                        client.config.allocator_context,
                        client.config.allocate_function);

                    if (packet == null)
                        continue;

                    client_process_packet_internal(client, from, packet, sequence);
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
                for (i = 0; i < num_packets_received; ++i)
                {
                    var packet = read_packet(
                        client.receive_packet_data[i],
                        client.receive_packet_bytes[i],
                        out var sequence,
                        client.context.read_packet_key,
                        client.connect_token.protocol_id,
                        current_timestamp,
                        null,
                        allowed_packets,
                        client.replay_protection,
                        client.config.allocator_context,
                        client.config.allocate_function);

                    client.receive_packet_data[i] = null;

                    if (packet == null)
                        continue;

                    client_process_packet_internal(client, client.receive_from[i], packet, sequence);
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
            assert(packet_bytes >= 0);
            assert(packet_bytes <= MAX_PACKET_SIZE);

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
            public byte[] send_key = new byte[KEY_BYTES * MAX_ENCRYPTION_MAPPINGS];
            public byte[] receive_key = new byte[KEY_BYTES * MAX_ENCRYPTION_MAPPINGS];
        }

        static void encryption_manager_reset(encryption_manager_t encryption_manager)
        {
            printf(LOG_LEVEL_DEBUG, "reset encryption manager\n");

            assert(encryption_manager != null);

            encryption_manager.num_encryption_mappings = 0;

            int i;
            for (i = 0; i < MAX_ENCRYPTION_MAPPINGS; ++i)
            {
                encryption_manager.expire_time[i] = -1.0;
                encryption_manager.last_access_time[i] = -1000.0;
                BufferEx.SetT(ref encryption_manager.address[i], 0);
            }

            BufferEx.Set(encryption_manager.timeout, 0);
            BufferEx.Set(encryption_manager.send_key, 0);
            BufferEx.Set(encryption_manager.receive_key, 0);
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
            int timeout)
        {
            int i;
            for (i = 0; i < encryption_manager.num_encryption_mappings; ++i)
                if (address_equal(encryption_manager.address[i], address) && !encryption_manager_entry_expired(encryption_manager, i, time))
                {
                    encryption_manager.timeout[i] = timeout;
                    encryption_manager.expire_time[i] = expire_time;
                    encryption_manager.last_access_time[i] = time;
                    BufferEx.Copy(encryption_manager.send_key, i * KEY_BYTES, send_key, 0, KEY_BYTES);
                    BufferEx.Copy(encryption_manager.receive_key, i * KEY_BYTES, receive_key, 0, KEY_BYTES);
                    return true;
                }
            for (i = 0; i < MAX_ENCRYPTION_MAPPINGS; ++i)
                if (encryption_manager.address[i].type == ADDRESS_NONE || encryption_manager_entry_expired(encryption_manager, i, time))
                {
                    encryption_manager.timeout[i] = timeout;
                    encryption_manager.address[i] = address;
                    encryption_manager.expire_time[i] = expire_time;
                    encryption_manager.last_access_time[i] = time;
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
            for (i = 0; i < encryption_manager.num_encryption_mappings; ++i)
            {
                if (address_equal(encryption_manager.address[i], address))
                {
                    encryption_manager.expire_time[i] = -1.0f;
                    encryption_manager.last_access_time[i] = -1000.0f;
                    BufferEx.SetT(ref encryption_manager.address[i], 0);
                    BufferEx.SetWithOffset(encryption_manager.send_key, i * KEY_BYTES, 0, KEY_BYTES);
                    BufferEx.SetWithOffset(encryption_manager.receive_key, i * KEY_BYTES, 0, KEY_BYTES);

                    if (i + 1 == encryption_manager.num_encryption_mappings)
                    {
                        var index = i - 1;
                        while (index >= 0)
                        {
                            if (!encryption_manager_entry_expired(encryption_manager, index, time))
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
            for (i = 0; i < encryption_manager.num_encryption_mappings; ++i)
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

        #endregion

        #region connect_token_entry_t

        internal const int MAX_CONNECT_TOKEN_ENTRIES = MAX_CLIENTS * 8;

        internal class connect_token_entry_t
        {
            public double time;
            public byte[] mac = new byte[MAC_BYTES];
            public netcode_address_t address = new netcode_address_t();
        }

        static void connect_token_entries_reset(connect_token_entry_t[] connect_token_entries)
        {
            int i;
            for (i = 0; i < MAX_CONNECT_TOKEN_ENTRIES; ++i)
            {
                connect_token_entries[i].time = -1000.0;
                BufferEx.Set(connect_token_entries[i].mac, 0, MAC_BYTES);
                BufferEx.SetT(ref connect_token_entries[i].address, 0);
            }
        }

        static bool connect_token_entries_find_or_add(
            connect_token_entry_t[] connect_token_entries,
            netcode_address_t address,
            byte[] mac, int p_,
            double time)
        {
            assert(connect_token_entries != null);
            assert(address != null);
            assert(mac != null);

            // find the matching entry for the token mac and the oldest token entry. constant time worst case. This is intentional!

            var matching_token_index = -1;
            var oldest_token_index = -1;
            var oldest_token_time = 0.0;

            int i;
            for (i = 0; i < MAX_CONNECT_TOKEN_ENTRIES; ++i)
            {
                if (BufferEx.Equal(mac, p_, connect_token_entries[i].mac, 0, MAC_BYTES))
                    matching_token_index = i;

                if (oldest_token_index == -1 || connect_token_entries[i].time < oldest_token_time)
                {
                    oldest_token_time = connect_token_entries[i].time;
                    oldest_token_index = i;
                }
            }

            // if no entry is found with the mac, this is a new connect token. replace the oldest token entry.

            assert(oldest_token_index != -1);

            if (matching_token_index == -1)
            {
                connect_token_entries[oldest_token_index].time = time;
                connect_token_entries[oldest_token_index].address = address;
                BufferEx.Copy(connect_token_entries[oldest_token_index].mac, 0, mac, p_, MAC_BYTES);
                return true;
            }

            // allow connect tokens we have already seen from the same address

            assert(matching_token_index >= 0);
            assert(matching_token_index < MAX_CONNECT_TOKEN_ENTRIES);
            if (address_equal(connect_token_entries[matching_token_index].address, address))
                return true;

            return false;
        }

        #endregion

        #region netcode_server_t

        const int SERVER_FLAG_IGNORE_CONNECTION_REQUEST_PACKETS = 1;
        const int SERVER_FLAG_IGNORE_CONNECTION_RESPONSE_PACKETS = 1 << 1;

        public static void default_server_config(out netcode_server_config_t config)
        {
            //assert(config != null);
            config = new netcode_server_config_t();
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
        internal byte flags;
        internal double time;
        internal bool running;
        internal int max_clients;
        internal int num_connected_clients;
        internal ulong global_sequence;
        internal ulong challenge_sequence;
        internal byte[] challenge_key = new byte[netcode.KEY_BYTES];
        internal bool[] client_connected = new bool[netcode.MAX_CLIENTS];
        internal int[] client_timeout = new int[netcode.MAX_CLIENTS];
        internal bool[] client_loopback = new bool[netcode.MAX_CLIENTS];
        internal bool[] client_confirmed = new bool[netcode.MAX_CLIENTS];
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
                if (!config.override_send_and_receive)
                    if (socket_create(ref socket, address, send_buffer_size, receive_buffer_size) != SOCKET_ERROR_NONE)
                        return false;
            return true;
        }

        static netcode_server_t server_create_overload(string server_address1_string, string server_address2_string, netcode_server_config_t config, double time)
        {
            assert(config != null);
            assert(netcode_.initialized);

            var server_address2 = new netcode_address_t();

            if (parse_address(server_address1_string, out var server_address1) != OK)
            {
                printf(LOG_LEVEL_ERROR, "error: failed to parse server public address\n");
                return null;
            }
            if (server_address2_string != null && parse_address(server_address2_string, out server_address2) != OK)
            {
                printf(LOG_LEVEL_ERROR, "error: failed to parse server public address2\n");
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
                    return null;
            }

            var server = new netcode_server_t();
            if (server == null)
            {
                socket_destroy(ref socket_ipv4);
                socket_destroy(ref socket_ipv6);
                return null;
            }

            if (config.network_simulator == null)
                printf(LOG_LEVEL_INFO, $"server listening on {server_address1_string}\n");
            else
                printf(LOG_LEVEL_INFO, $"server listening on {server_address1_string} (network simulator)\n");

            server.config = config;
            server.socket_holder.ipv4 = socket_ipv4;
            server.socket_holder.ipv6 = socket_ipv6;
            server.address = server_address1;
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
            //BufferEx.SetT(server.client_user_data, new byte[netcode.USER_DATA_BYTES]);

            int i;
            for (i = 0; i < MAX_CLIENTS; ++i)
                server.client_encryption_index[i] = -1;

            connect_token_entries_reset(server.connect_token_entries);

            encryption_manager_reset(server.encryption_manager);

            for (i = 0; i < MAX_CLIENTS; ++i)
                replay_protection_reset(server.client_replay_protection[i]);

            BufferEx.SetT(server.client_packet_queue, 0);

            return server;
        }

        public static netcode_server_t server_create(string server_address_string, netcode_server_config_t config, double time) =>
            server_create_overload(server_address_string, null, config, time);

        public static void server_destroy(ref netcode_server_t server)
        {
            assert(server != null);

            server_stop(server);

            socket_destroy(ref server.socket_holder.ipv4);
            socket_destroy(ref server.socket_holder.ipv6);

            server = null;
        }

        public static void server_start(this netcode_server_t server, int max_clients)
        {
            assert(server != null);
            assert(max_clients > 0);
            assert(max_clients <= MAX_CLIENTS);

            if (server.running)
                server_stop(server);

            printf(LOG_LEVEL_INFO, $"server started with {max_clients} client slots\n");

            server.running = true;
            server.max_clients = max_clients;
            server.num_connected_clients = 0;
            server.challenge_sequence = 0;
            generate_key(server.challenge_key);

            int i;
            for (i = 0; i < server.max_clients; ++i)
                packet_queue_init(server.client_packet_queue[i], server.config.allocator_context, server.config.allocate_function, server.config.free_function);
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

        static void server_disconnect_client_internal(netcode_server_t server, int client_index, bool send_disconnect_packets)
        {
            assert(server != null);
            assert(server.running);
            assert(client_index >= 0);
            assert(client_index < server.max_clients);
            assert(server.client_connected[client_index]);
            assert(!server.client_loopback[client_index]);

            printf(LOG_LEVEL_INFO, $"server disconnected client {client_index}\n");

            server.config.connect_disconnect_callback?.Invoke(server.config.callback_context, client_index, 0);

            if (send_disconnect_packets)
            {
                printf(LOG_LEVEL_DEBUG, $"server sent disconnect packets to client {client_index}\n");

                int i;
                for (i = 0; i < NUM_DISCONNECT_PACKETS; ++i)
                {
                    printf(LOG_LEVEL_DEBUG, $"server sent disconnect packet {i}\n");

                    var packet = new connection_disconnect_packet_t();
                    packet.packet_type = CONNECTION_DISCONNECT_PACKET;

                    server_send_client_packet(server, packet, client_index);
                }
            }

            while (true)
            {
                var packet = packet_queue_pop(server.client_packet_queue[client_index], out var na1);
                if (packet == null)
                    break;
                packet = null;
            }

            packet_queue_clear(server.client_packet_queue[client_index]);

            replay_protection_reset(server.client_replay_protection[client_index]);

            encryption_manager_remove_encryption_mapping(server.encryption_manager, server.client_address[client_index], server.time);

            server.client_connected[client_index] = false;
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

        public static void server_disconnect_client(this netcode_server_t server, int client_index)
        {
            assert(server != null);

            if (!server.running)
                return;

            assert(client_index >= 0);
            assert(client_index < server.max_clients);
            assert(!server.client_loopback[client_index]);

            if (!server.client_connected[client_index])
                return;

            if (server.client_loopback[client_index])
                return;

            server_disconnect_client_internal(server, client_index, true);
        }

        public static void server_disconnect_all_clients(this netcode_server_t server)
        {
            assert(server != null);

            if (!server.running)
                return;

            int i;
            for (i = 0; i < server.max_clients; ++i)
                if (server.client_connected[i] && !server.client_loopback[i])
                    server_disconnect_client_internal(server, i, true);
        }

        public static void server_stop(this netcode_server_t server)
        {
            assert(server != null);

            if (!server.running)
                return;

            server_disconnect_all_clients(server);

            server.running = false;
            server.max_clients = 0;
            server.num_connected_clients = 0;

            server.global_sequence = 0;
            server.challenge_sequence = 0;
            BufferEx.Set(server.challenge_key, 0, KEY_BYTES);

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
            connection_request_packet_t packet)
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
            for (i = 0; i < connect_token_private.num_server_addresses; ++i)
                if (address_equal(server.address, connect_token_private.server_addresses[i]))
                    found_server_address = true;
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

            if (!connect_token_entries_find_or_add(
                server.connect_token_entries,
                from,
                packet.connect_token_data, CONNECT_TOKEN_PRIVATE_BYTES - MAC_BYTES,
                server.time))
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
                connect_token_private.timeout_seconds))
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

            server.num_connected_clients++;

            assert(server.num_connected_clients <= server.max_clients);

            assert(!server.client_connected[client_index]);

            encryption_manager_set_expire_time(server.encryption_manager, encryption_index, -1.0);

            server.client_connected[client_index] = true;
            server.client_timeout[client_index] = timeout_seconds;
            server.client_encryption_index[client_index] = encryption_index;
            server.client_id[client_index] = client_id;
            server.client_sequence[client_index] = 0;
            server.client_address[client_index] = address;
            server.client_last_packet_send_time[client_index] = server.time;
            server.client_last_packet_receive_time[client_index] = server.time;
            BufferEx.Copy(server.client_user_data[client_index], user_data, USER_DATA_BYTES);

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
                            server_process_connection_request_packet(server, from, (connection_request_packet_t)packet);
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
                            server_disconnect_client_internal(server, client_index, false);
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
                server.config.private_key,
                allowed_packets,
                (client_index != -1) ? server.client_replay_protection[client_index] : null,
                server.config.allocator_context,
                server.config.allocate_function);

            if (packet == null)
                return;

            server_process_packet_internal(server, from, packet, sequence, encryption_index, client_index);
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
                server.config.private_key,
                allowed_packets,
                (client_index != -1) ? server.client_replay_protection[client_index] : null,
                server.config.allocator_context,
                server.config.allocate_function);

            if (packet == null)
                return;

            server_process_packet_internal(server, from, packet, sequence, encryption_index, client_index);
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
            for (i = 0; i < server.max_clients; ++i)
                if (server.client_connected[i] && server.client_timeout[i] > 0 && !server.client_loopback[i] && (server.client_last_packet_receive_time[i] + server.client_timeout[i] <= server.time))
                {
                    printf(LOG_LEVEL_INFO, $"server timed out client {i}\n");
                    server_disconnect_client_internal(server, i, false);
                    return;
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
            assert(client_index >= 0);
            assert(client_index < server.max_clients);

            if (!server.client_connected[client_index])
                return 0;
            return server.client_sequence[client_index];
        }

        public static void server_send_packet(this netcode_server_t server, int client_index, byte[] packet_data, int packet_bytes)
        {
            assert(server != null);
            assert(packet_data != null);
            assert(packet_bytes >= 0);
            assert(packet_bytes <= MAX_PACKET_SIZE);

            if (!server.running)
                return;

            assert(client_index >= 0);
            assert(client_index < server.max_clients);
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
            //assert(packet_bytes != null);

            packet_bytes = 0;
            packet_sequence = 0;
            if (!server.running)
                return null;

            if (!server.client_connected[client_index])
                return null;

            assert(client_index >= 0);
            assert(client_index < server.max_clients);

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
            assert(!server.client_connected[client_index]);

            server.num_connected_clients++;

            assert(server.num_connected_clients <= server.max_clients);

            server.client_loopback[client_index] = true;
            server.client_connected[client_index] = true;
            server.client_confirmed[client_index] = true;
            server.client_encryption_index[client_index] = -1;
            server.client_id[client_index] = client_id;
            server.client_sequence[client_index] = 0;
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
            assert(server.client_connected[client_index]);
            assert(server.client_loopback[client_index]);

            printf(LOG_LEVEL_INFO, $"server disconnected loopback client {client_index}\n");

            server.config.connect_disconnect_callback?.Invoke(server.config.callback_context, client_index, 0);

            while (true)
            {
                var packet = packet_queue_pop(server.client_packet_queue[client_index], out var notused);
                if (packet == null)
                    break;
                server.config.free_function(server.config.allocator_context, packet);
            }

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

        public static bool server_client_loopback(this netcode_server_t server, int client_index)
        {
            assert(server != null);
            assert(server.running);
            assert(client_index >= 0);
            assert(client_index < server.max_clients);
            return server.client_loopback[client_index];
        }

        public static void server_process_loopback_packet(this netcode_server_t server, int client_index, byte[] packet_data, int packet_bytes, ulong packet_sequence)
        {
            assert(server != null);
            assert(client_index >= 0);
            assert(client_index < server.max_clients);
            assert(packet_data != null);
            assert(packet_bytes >= 0);
            assert(packet_bytes <= MAX_PACKET_SIZE);
            assert(server.client_connected[client_index]);
            assert(server.client_loopback[client_index]);
            assert(server.running);

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
        public static double time() => DateTime.Now.ToOADate();

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

        public static bool Equal<T>(IList<T> first, IList<T> second, int? length = null) =>
            (length == null) || (first.Count == length && second.Count == length) ?
                Enumerable.SequenceEqual(first, second) :
                Enumerable.SequenceEqual(first.Take(length.Value), second.Take(length.Value));
        public static bool Equal<T>(IList<T> first, int firstOffset, IList<T> second, int secondOffset, int? length = null) =>
            (length == null) || (first.Count - firstOffset == length && second.Count - secondOffset == length) ?
                Enumerable.SequenceEqual(first.Skip(firstOffset), second.Skip(firstOffset)) :
                Enumerable.SequenceEqual(first.Skip(firstOffset).Take(length.Value), second.Skip(firstOffset).Take(length.Value));
    }

    #endregion

    #region Crypto

    internal class Crypto_aead : Chacha20Poly1305
    {
        class SecurityParametersEx : SecurityParameters
        {
            public override byte[] MasterSecret => new byte[0];
            public override byte[] ClientRandom => new byte[0];
            public override byte[] ServerRandom => new byte[0];
            public override int PrfAlgorithm => 0;
        }

        class Context : TlsContext
        {
            public IRandomGenerator NonceRandomGenerator => throw new NotImplementedException();
            public SecureRandom SecureRandom => throw new NotImplementedException();
            public SecurityParameters SecurityParameters { get; set; }
            public bool IsServer => true;
            public ProtocolVersion ClientVersion => throw new NotImplementedException();
            public ProtocolVersion ServerVersion => ProtocolVersion.TLSv12;
            public TlsSession ResumableSession => throw new NotImplementedException();
            public object UserObject { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
            public byte[] ExportKeyingMaterial(string asciiLabel, byte[] context_value, int length) => throw new NotImplementedException();
        }

        protected class ChaCha7539EngineEx : ChaCha7539Engine
        {
            protected override int NonceSize => netcode.CONNECT_TOKEN_NONCE_BYTES;
        }

        protected readonly ChaCha7539EngineEx encryptCipherEx;
        protected readonly ChaCha7539EngineEx decryptCipherEx;

        public Crypto_aead() : base(new Context { SecurityParameters = new SecurityParametersEx() })
        {
            encryptCipherEx = new ChaCha7539EngineEx();
            decryptCipherEx = new ChaCha7539EngineEx();
        }

        public byte[] DecodeCipherText(bool bigNonce, byte[] message, int offset, int len, byte[] additional, byte[] nonce, byte[] key)
        {
            var decryptCipher = bigNonce ? decryptCipherEx : this.decryptCipher;
            if (GetPlaintextLimit(len) < 0)
                throw new TlsFatalAlert(AlertDescription.decode_error);
            decryptCipher.Init(false, new ParametersWithIV(new KeyParameter(key), nonce));
            var macKey = GenerateRecordMacKey(decryptCipher);
            var plaintextLength = len - 0x10;
            if (!Arrays.ConstantTimeAreEqual(CalculateRecordMac(macKey, additional, message, offset, plaintextLength), Arrays.CopyOfRange(message, offset + plaintextLength, offset + len)))
                throw new TlsFatalAlert(AlertDescription.bad_record_mac);
            //var calculatedMac = CalculateRecordMac(macKey, additional, message, offset, plaintextLength);
            //var receivedMac = Arrays.CopyOfRange(message, offset + plaintextLength, offset + len);
            //if (!Arrays.ConstantTimeAreEqual(calculatedMac, receivedMac))
            //    throw new TlsFatalAlert(AlertDescription.bad_record_mac);
            var outBytes = new byte[plaintextLength];
            decryptCipher.ProcessBytes(message, offset, plaintextLength, outBytes, 0);
            return outBytes;
        }

        public byte[] EncodePlaintext(bool bigNonce, byte[] message, int offset, int len, byte[] additional, byte[] nonce, byte[] key)
        {
            var encryptCipher = bigNonce ? encryptCipherEx : this.encryptCipher;
            encryptCipher.Init(true, new ParametersWithIV(new KeyParameter(key), nonce));
            var macKey = GenerateRecordMacKey(encryptCipher);
            var outBytes = new byte[len + 0x10];
            encryptCipher.ProcessBytes(message, offset, len, outBytes, 0);
            var calculatedMac = CalculateRecordMac(macKey, additional, outBytes, 0, len);
            Array.Copy(calculatedMac, 0, outBytes, len, calculatedMac.Length);
            return outBytes;
        }

        public int Encrypt(bool bigNonce,
            byte[] buffer, int p, out ulong buffer_length,
            byte[] message, ulong message_length,
            byte[] additional, ulong additional_length,
            object unkn, byte[] nonce, byte[] key)
        {
            buffer_length = message_length + netcode.MAC_BYTES;
            try
            {
                var r = EncodePlaintext(bigNonce, buffer, p, (int)message_length, additional ?? new byte[0], nonce, key);
                Array.Copy(r, 0, buffer, p, (int)buffer_length);
            }
            catch (TlsException) { return -1; }
            return 0;
        }

        public int Decrypt(bool bigNonce,
            byte[] buffer, int p, out ulong buffer_length,
            object unkn,
            byte[] message, ulong message_length,
            byte[] additional, ulong additional_length,
            byte[] nonce, byte[] key)
        {
            buffer_length = message_length - netcode.MAC_BYTES;
            try
            {
                var r = DecodeCipherText(bigNonce, buffer, p, (int)message_length, additional ?? new byte[0], nonce, key);
                Array.Copy(r, 0, buffer, p, (int)buffer_length);
            }
            catch (TlsException) { return -1; }
            return 0;
        }

        static readonly ConditionalWeakTable<Thread, Crypto_aead> WeakTable = new ConditionalWeakTable<Thread, Crypto_aead>();

        public static Crypto_aead CurrentThread => WeakTable.GetOrCreateValue(Thread.CurrentThread);
    }

    #endregion

}