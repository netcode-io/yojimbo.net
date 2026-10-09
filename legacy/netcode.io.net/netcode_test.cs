using System;
using System.Diagnostics;
using System.Linq;
using System.Net;

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

        public static void check(bool condition)
        {
            if (!condition)
            {
                var stackFrame = new StackTrace().GetFrame(1);
                check_handler("n/a", stackFrame.GetMethod().Name, stackFrame.GetFileName(), stackFrame.GetFileLineNumber());
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

            var output_packet = (connection_request_packet_t)read_packet(buffer, bytes_written, out var sequence, packet_key, TEST_PROTOCOL_ID, ctime(), connect_token_key, allowed_packets, null, null, null);

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

            var output_packet = (connection_denied_packet_t)read_packet(buffer, bytes_written, out var sequence, packet_key, TEST_PROTOCOL_ID, ctime(), null, allowed_packet_types, null, null, null);

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

            var output_packet = (connection_challenge_packet_t)read_packet(buffer, bytes_written, out var sequence, packet_key, TEST_PROTOCOL_ID, ctime(), null, allowed_packet_types, null, null, null);

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

            var output_packet = (connection_response_packet_t)read_packet(buffer, bytes_written, out var sequence, packet_key, TEST_PROTOCOL_ID, ctime(), null, allowed_packet_types, null, null, null);

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

            var output_packet = (connection_keep_alive_packet_t)read_packet(buffer, bytes_written, out var sequence, packet_key, TEST_PROTOCOL_ID, ctime(), null, allowed_packet_types, null, null, null);

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

            var output_packet = (connection_payload_packet_t)read_packet(buffer, bytes_written, out var sequence, packet_key, TEST_PROTOCOL_ID, ctime(), null, allowed_packet_types, null, null, null);

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

            var output_packet = (connection_disconnect_packet_t)read_packet(buffer, bytes_written, out var sequence, packet_key, TEST_PROTOCOL_ID, ctime(), null, allowed_packet_types, null, null, null);

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
                    TEST_TIMEOUT_SECONDS));

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
                TEST_TIMEOUT_SECONDS));

            check(encryption_manager_add_encryption_mapping(
                encryption_manager,
                encryption_mapping[NUM_ENCRYPTION_MAPPINGS - 1].address,
                encryption_mapping[NUM_ENCRYPTION_MAPPINGS - 1].send_key,
                encryption_mapping[NUM_ENCRYPTION_MAPPINGS - 1].receive_key,
                time,
                -1.0,
                TEST_TIMEOUT_SECONDS));

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
                    TEST_TIMEOUT_SECONDS));

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
                TEST_TIMEOUT_SECONDS));

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

                var client = client_create_overload("127.0.0.1:40000", "[::]:50000", client_config, 0.0);

                parse_address("127.0.0.1:40000", out var test_address);

                check(client != null);
                check(client.socket_holder.ipv4.handle != null);
                check(client.socket_holder.ipv6.handle != null);
                check(address_equal(client.address, test_address));

                client_destroy(ref client);
            }

            {
                default_client_config(out var client_config);

                var client = client_create_overload("[::]:50000", "127.0.0.1:40000", client_config, 0.0);

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

                var server = server_create_overload("127.0.0.1:40000", "[::1]:50000", server_config, 0.0);

                parse_address("127.0.0.1:40000", out var test_address);

                check(server != null);
                check(server.socket_holder.ipv4.handle != null);
                check(server.socket_holder.ipv6.handle != null);
                check(address_equal(server.address, test_address));

                server_destroy(ref server);
            }

            {
                default_server_config(out var server_config);

                var server = server_create_overload("[::1]:50000", "127.0.0.1:40000", server_config, 0.0);

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

        static void test_client_server_ipv4_socket_connect()
        {
            {
                var time = 0.0;
                const double delta_time = 1.0 / 10.0;

                default_client_config(out var client_config);

                var client = client_create("0.0.0.0:50000", client_config, time);

                check(client != null);

                default_server_config(out var server_config);
                server_config.protocol_id = TEST_PROTOCOL_ID;
                BufferEx.Copy(server_config.private_key, private_key, KEY_BYTES);

                var server = server_create("127.0.0.1:40000", server_config, time);

                check(server != null);

                server_start(server, 1);

                const string server_address = "127.0.0.1:40000";

                var connect_token = new byte[CONNECT_TOKEN_BYTES];

                var client_id = 0UL;
                random_bytes(ref client_id, 8);

                var user_data = new byte[USER_DATA_BYTES];
                random_bytes(user_data, USER_DATA_BYTES);

                check(generate_connect_token(1, new[] { server_address }, new[] { server_address }, TEST_CONNECT_TOKEN_EXPIRY, TEST_TIMEOUT_SECONDS, client_id, TEST_PROTOCOL_ID, private_key, user_data, connect_token) != 0);

                client_connect(client, connect_token);

                while (true)
                {
                    client_update(client, time);

                    server_update(server, time);

                    if (client_state(client) <= CLIENT_STATE_DISCONNECTED)
                        break;

                    if (client_state(client) == CLIENT_STATE_CONNECTED)
                        break;

                    time += delta_time;
                }

                server_destroy(ref server);
                client_destroy(ref client);
            }

            {
                var time = 0.0;
                const double delta_time = 1.0 / 10.0;

                default_client_config(out var client_config);

                var client = client_create("0.0.0.0:50000", client_config, time);

                check(client != null);

                default_server_config(out var server_config);
                server_config.protocol_id = TEST_PROTOCOL_ID;
                BufferEx.Copy(server_config.private_key, private_key, KEY_BYTES);

                var server = server_create_overload("127.0.0.1:40000", "[::1]:40000", server_config, time);

                check(server != null);

                server_start(server, 1);

                const string server_address = "127.0.0.1:40000";

                var connect_token = new byte[CONNECT_TOKEN_BYTES];

                ulong client_id = 0;
                random_bytes(ref client_id, 8);

                var user_data = new byte[USER_DATA_BYTES];
                random_bytes(user_data, USER_DATA_BYTES);

                check(generate_connect_token(1, new[] { server_address }, new[] { server_address }, TEST_CONNECT_TOKEN_EXPIRY, TEST_TIMEOUT_SECONDS, client_id, TEST_PROTOCOL_ID, private_key, user_data, connect_token) != 0);

                client_connect(client, connect_token);

                while (true)
                {
                    client_update(client, time);

                    server_update(server, time);

                    if (client_state(client) <= CLIENT_STATE_DISCONNECTED)
                        break;

                    if (client_state(client) == CLIENT_STATE_CONNECTED)
                        break;

                    time += delta_time;
                }

                server_destroy(ref server);
                client_destroy(ref client);
            }

            {
                var time = 0.0;
                const double delta_time = 1.0 / 10.0;

                default_client_config(out var client_config);

                var client = client_create_overload("0.0.0.0:50000", "[::]:50000", client_config, time);

                check(client != null);

                default_server_config(out var server_config);
                server_config.protocol_id = TEST_PROTOCOL_ID;
                BufferEx.Copy(server_config.private_key, private_key, KEY_BYTES);

                var server = server_create("127.0.0.1:40000", server_config, time);

                check(server != null);

                server_start(server, 1);

                const string server_address = "127.0.0.1:40000";

                var connect_token = new byte[CONNECT_TOKEN_BYTES];

                var client_id = 0UL;
                random_bytes(ref client_id, 8);

                var user_data = new byte[USER_DATA_BYTES];
                random_bytes(user_data, USER_DATA_BYTES);

                check(generate_connect_token(1, new[] { server_address }, new[] { server_address }, TEST_CONNECT_TOKEN_EXPIRY, TEST_TIMEOUT_SECONDS, client_id, TEST_PROTOCOL_ID, private_key, user_data, connect_token) != 0);

                client_connect(client, connect_token);

                while (true)
                {
                    client_update(client, time);
                    server_update(server, time);

                    if (client_state(client) <= CLIENT_STATE_DISCONNECTED)
                        break;
                    if (client_state(client) == CLIENT_STATE_CONNECTED)
                        break;

                    time += delta_time;
                }

                server_destroy(ref server);
                client_destroy(ref client);
            }

            {
                var time = 0.0;
                const double delta_time = 1.0 / 10.0;

                default_client_config(out var client_config);

                var client = client_create_overload("0.0.0.0:50000", "[::]:50000", client_config, time);

                check(client != null);

                default_server_config(out var server_config);
                server_config.protocol_id = TEST_PROTOCOL_ID;
                BufferEx.Copy(server_config.private_key, private_key, KEY_BYTES);

                var server = server_create_overload("127.0.0.1:40000", "[::1]:40000", server_config, time);

                check(server != null);

                server_start(server, 1);

                const string server_address = "127.0.0.1:40000";

                var connect_token = new byte[CONNECT_TOKEN_BYTES];

                var client_id = 0UL;
                random_bytes(ref client_id, 8);

                var user_data = new byte[USER_DATA_BYTES];
                random_bytes(user_data, USER_DATA_BYTES);

                check(generate_connect_token(1, new[] { server_address }, new[] { server_address }, TEST_CONNECT_TOKEN_EXPIRY, TEST_TIMEOUT_SECONDS, client_id, TEST_PROTOCOL_ID, private_key, user_data, connect_token) != 0);

                client_connect(client, connect_token);

                while (true)
                {
                    client_update(client, time);
                    server_update(server, time);

                    if (client_state(client) <= CLIENT_STATE_DISCONNECTED)
                        break;
                    if (client_state(client) == CLIENT_STATE_CONNECTED)
                        break;

                    time += delta_time;
                }

                server_destroy(ref server);
                client_destroy(ref client);
            }
        }

        static void test_client_server_ipv6_socket_connect()
        {
            {
                var time = 0.0;
                const double delta_time = 1.0 / 10.0;

                default_client_config(out var client_config);

                var client = client_create("[::]:50000", client_config, time);

                check(client != null);

                default_server_config(out var server_config);
                server_config.protocol_id = TEST_PROTOCOL_ID;
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
                    client_update(client, time);
                    server_update(server, time);

                    if (client_state(client) <= CLIENT_STATE_DISCONNECTED)
                        break;
                    if (client_state(client) == CLIENT_STATE_CONNECTED)
                        break;

                    time += delta_time;
                }

                server_destroy(ref server);
                client_destroy(ref client);
            }

            {
                var time = 0.0;
                const double delta_time = 1.0 / 10.0;

                default_client_config(out var client_config);

                var client = client_create("[::]:50000", client_config, time);

                check(client != null);

                default_server_config(out var server_config);
                server_config.protocol_id = TEST_PROTOCOL_ID;
                BufferEx.Copy(server_config.private_key, private_key, KEY_BYTES);

                var server = server_create_overload("127.0.0.1:40000", "[::1]:40000", server_config, time);

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
                    client_update(client, time);
                    server_update(server, time);

                    if (client_state(client) <= CLIENT_STATE_DISCONNECTED)
                        break;
                    if (client_state(client) == CLIENT_STATE_CONNECTED)
                        break;

                    time += delta_time;
                }

                server_destroy(ref server);
                client_destroy(ref client);
            }

            {
                var time = 0.0;
                const double delta_time = 1.0 / 10.0;

                default_client_config(out var client_config);

                var client = client_create_overload("0.0.0.0:50000", "[::]:50000", client_config, time);

                check(client != null);

                default_server_config(out var server_config);
                server_config.protocol_id = TEST_PROTOCOL_ID;
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
                    client_update(client, time);
                    server_update(server, time);

                    if (client_state(client) <= CLIENT_STATE_DISCONNECTED)
                        break;
                    if (client_state(client) == CLIENT_STATE_CONNECTED)
                        break;

                    time += delta_time;
                }

                server_destroy(ref server);
                client_destroy(ref client);
            }

            {
                var time = 0.0;
                const double delta_time = 1.0 / 10.0;

                default_client_config(out var client_config);

                var client = client_create_overload("0.0.0.0:50000", "[::]:50000", client_config, time);

                check(client != null);

                default_server_config(out var server_config);
                server_config.protocol_id = TEST_PROTOCOL_ID;
                BufferEx.Copy(server_config.private_key, private_key, KEY_BYTES);

                var server = server_create_overload("127.0.0.1:40000", "[::1]:40000", server_config, time);

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
                    client_update(client, time);
                    server_update(server, time);

                    if (client_state(client) <= CLIENT_STATE_DISCONNECTED)
                        break;
                    if (client_state(client) == CLIENT_STATE_CONNECTED)
                        break;

                    time += delta_time;
                }

                server_destroy(ref server);
                client_destroy(ref client);
            }
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

            var num_iterations = (int)Math.Ceiling(1.25f * TEST_TIMEOUT_SECONDS / delta_time);

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

        public static void test()
        {
            //log_level(LOG_LEVEL_DEBUG);
            //while (true)
            {
                Console.WriteLine("test_queue"); test_queue();
                Console.WriteLine("test_endian"); test_endian();
                Console.WriteLine("test_address"); test_address();
                Console.WriteLine("test_sequence"); test_sequence();
                Console.WriteLine("test_connect_token"); test_connect_token();
                Console.WriteLine("test_challenge_token"); test_challenge_token();
                Console.WriteLine("test_connection_request_packet"); test_connection_request_packet();
                Console.WriteLine("test_connection_denied_packet"); test_connection_denied_packet();
                Console.WriteLine("test_connection_challenge_packet"); test_connection_challenge_packet();
                Console.WriteLine("test_connection_response_packet"); test_connection_response_packet();
                Console.WriteLine("test_connection_payload_packet"); test_connection_payload_packet();
                Console.WriteLine("test_connection_disconnect_packet"); test_connection_disconnect_packet();
                Console.WriteLine("test_connect_token_public"); test_connect_token_public();
                Console.WriteLine("test_encryption_manager"); test_encryption_manager();
                Console.WriteLine("test_replay_protection"); test_replay_protection();
                Console.WriteLine("test_client_create"); test_client_create();
                Console.WriteLine("test_server_create"); test_server_create();
                Console.WriteLine("test_client_server_connect"); test_client_server_connect();
                Console.WriteLine("test_client_server_ipv4_socket_connect"); test_client_server_ipv4_socket_connect();
                Console.WriteLine("test_client_server_ipv6_socket_connect"); test_client_server_ipv6_socket_connect();
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
                Console.WriteLine("test_client_reconnect"); test_client_reconnect();
                Console.WriteLine("test_disable_timeout"); test_disable_timeout();
                Console.WriteLine("test_loopback"); test_loopback();
            }
        }
    }
}