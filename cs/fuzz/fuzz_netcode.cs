/*
    Fuzz target: netcode_read_packet().

    Feeds arbitrary bytes into netcode's packet-read path — prefix/type parsing, length
    checks, sequence decoding, AEAD decryption and connect-token decryption — the code
    that runs on raw, attacker-controlled UDP payloads before a client or server trusts
    anything. Every packet type is allowed and fixed (zero) keys are used, so the header
    parse and the decrypt/MAC-reject paths are all exercised.

    read_packet and the replay-protection / packet-type symbols are internal to netcode,
    so upstream includes netcode.c directly. C#: fuzz.csproj compiles the library sources
    into the fuzz program, and the target is a part of the netcode class.
*/

namespace networkprotocol
{
    static partial class netcode
    {
        static byte[] fuzz_packet_key = new byte[KEY_BYTES];
        static byte[] fuzz_private_key = new byte[KEY_BYTES];

        /// C#: the packet type read_packet decoded, or -1 if it rejected the input. Lets the corpus replay check every seed still decrypts.
        internal static int fuzz_netcode_last_packet_type = -1;

        internal const int FUZZ_NETCODE_NUM_PACKET_TYPES = CONNECTION_NUM_PACKETS;

        internal static int fuzz_netcode(byte[] data, int size)
        {
            fuzz_netcode_last_packet_type = -1;

            // Mirror the real receive path: netcode never hands more than a full UDP packet to
            // the reader, and it ignores empty buffers.
            if (size == 0 || size > MAX_PACKET_BYTES)
                return 0;

            // read_packet takes a mutable buffer; copy the immutable fuzzer input.
            var buffer = new byte[MAX_PACKET_BYTES];
            System.Buffer.BlockCopy(data, 0, buffer, 0, size);

            var allowed_packets = new bool[CONNECTION_NUM_PACKETS];
            for (var i = 0; i < allowed_packets.Length; ++i)
                allowed_packets[i] = true;

            // Reset replay protection every input so a repeated sequence number never masks the
            // post-decrypt path on a later input.
            var replay_protection = new netcode_replay_protection_t();
            replay_protection_reset(replay_protection);

            var packet = read_packet(buffer,
                                     size,
                                     out var sequence,
                                     fuzz_packet_key,
                                     fuzz_netcode_params.FUZZ_PROTOCOL_ID,
                                     fuzz_netcode_params.FUZZ_TIMESTAMP,
                                     0,                 // minimum expire timestamp: zero, so no connect token is refused for predating a server start and the fuzzer keeps reaching the parser
                                     fuzz_private_key,
                                     allowed_packets,
                                     replay_protection,
                                     null,
                                     null);

            if (packet != null)
                fuzz_netcode_last_packet_type = ((base_request_packet_t)packet).packet_type;

            return 0;
        }
    }
}
