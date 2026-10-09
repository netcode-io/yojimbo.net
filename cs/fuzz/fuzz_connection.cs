/*
    Fuzz target: yojimbo::Connection::ProcessPacket(), stateful / multi-packet.

    Drives the yojimbo deserialization path on arbitrary bytes: the bitpacker ReadStream,
    ConnectionPacket / ChannelPacketData serialization, and per-channel message +
    block-fragment reading, over a reliable-ordered and an unreliable-unordered channel.
    This is the code that turns an authenticated but otherwise attacker-controlled packet
    payload into messages.

    One fuzz input is a *sequence* of packets fed to a single long-lived Connection, so the
    reliable-ordered channel's multi-packet state — block-fragment reassembly and the
    out-of-order message receive queue — is reachable (a single packet on a fresh connection
    can never complete a multi-fragment block). Input framing:

        [u8 config selector][u16 little-endian length][length bytes of packet] ...

    The first byte selects the ConnectionConfig (fuzz_config); then length-prefixed packets
    repeat until the input is consumed. A length longer than what remains uses the rest. The
    messages use a factory (fuzz_messages) that drives the whole serialize_* vocabulary, not
    just serialize_bits.

    Note: a malformed packet drops the Connection into an error state, after which it rejects
    everything — so reaching deep reassembly state requires several *valid* packets in a row.
    The committed seed corpus carries such sequences (see cpp/tools/gen_seed_corpus_connection.cpp);
    the structure-aware target fuzz_connection_structured reaches the same state from a
    higher-level script.
*/

using networkprotocol;
using System;
using static networkprotocol.yojimbo;

static class fuzz_connection
{
    /// C#: true if every packet of the last input was read and the connection never went into an error state. The corpus replay checks the seeds still read back.
    public static bool g_all_packets_accepted;

    // C#: upstream pads the copy by 16 bytes because its BitReader loads an 8 byte window past
    // the read position. The C# BitReader bounds checks its loads, but the buffer keeps the slack.
    static byte[] buf = new byte[8 * 1024 + 16];

    public static int LLVMFuzzerTestOneInput(byte[] data, int size)
    {
        g_all_packets_accepted = false;

        if (size < 1)
            return 0;

        // first byte selects the connection config
        var config = new ConnectionConfig();
        fuzz_config.fuzz_make_config(data[0], config);
        var pos = 1;

        using var messageFactory = new FuzzMessageFactory(GetDefaultAllocator());
        using var connection = new Connection(GetDefaultAllocator(), messageFactory, config, 100.0);

        if (config.maxPacketSize + 16 > buf.Length)
            return 0;

        var maxPacket = config.maxPacketSize;
        const int MAX_PACKETS = 64;

        var time = 100.0;
        ushort sequence = 0;

        var accepted = true;

        for (var p = 0; p < MAX_PACKETS && pos < size; ++p)
        {
            // read a 2-byte length prefix (missing bytes read as zero)
            int len = data[pos];
            pos++;
            if (pos < size)
            {
                len |= data[pos] << 8;
                pos++;
            }

            var avail = size - pos;
            if (len > avail)
                len = avail;                 // last packet takes the remainder

            var packetBytes = len > maxPacket ? maxPacket : len;

            if (packetBytes > 0)
            {
                Array.Clear(buf, 0, packetBytes + 16);
                Buffer.BlockCopy(data, pos, buf, 0, packetBytes);
                if (!connection.ProcessPacket(null, sequence, buf, packetBytes))
                    accepted = false;
            }

            pos += len;
            sequence++;

            time += 0.1;
            connection.AdvanceTime(time);

            // drain anything delivered so messages don't accumulate across packets
            for (var channelIndex = 0; channelIndex < config.numChannels; ++channelIndex)
            {
                Message message;
                while ((message = connection.ReceiveMessage(channelIndex)) != null)
                    messageFactory.ReleaseMessage(message);
            }
        }

        g_all_packets_accepted = accepted && connection.ErrorLevel == ConnectionErrorLevel.CONNECTION_ERROR_NONE;

        return 0;
    }
}
