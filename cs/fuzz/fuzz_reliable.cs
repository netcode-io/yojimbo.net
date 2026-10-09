/*
    Fuzz target: reliable_endpoint_receive_packet().

    Feeds arbitrary bytes into the reliable.io packet-receive path — packet-header
    parsing, ack decoding, and fragment reassembly — the code that runs on raw,
    attacker-controlled UDP payloads. The process-packet callback accepts everything
    so reassembled payloads are exercised too.
*/

using networkprotocol;
using System;

static class fuzz_reliable
{
    static reliable_endpoint_t g_endpoint = null;
    static double g_time = 100.0;

    /// C#: number of packets the endpoint delivered (directly or reassembled). The corpus replay checks the seeds still deliver.
    public static int g_received = 0;

    static bool fuzz_process_packet(object context, ulong id, ushort sequence, byte[] data, int bytes)
    {
        g_received++;
        return true; // accept every packet
    }

    static void fuzz_transmit_packet(object context, ulong id, ushort sequence, byte[] data, int bytes)
    {
    }

    static void ensure_init()
    {
        if (g_endpoint != null)
            return;
        reliable.default_config(out var config);
        config.transmit_packet_function = fuzz_transmit_packet;
        config.process_packet_function = fuzz_process_packet;
        g_endpoint = reliable.endpoint_create(config, g_time);
        if (g_endpoint == null)
            throw new InvalidOperationException("reliable endpoint create failed"); // a null here is a broken target, not an input finding
    }

    /// C#: drop the long-lived endpoint so a corpus replay starts from a fresh one.
    public static void reset()
    {
        if (g_endpoint != null)
            reliable.endpoint_destroy(ref g_endpoint);
        g_endpoint = null;
        g_time = 100.0;
        g_received = 0;
    }

    public static int LLVMFuzzerTestOneInput(byte[] data, int size)
    {
        ensure_init();

        // reliable_endpoint_receive_packet asserts packet_bytes > 0 and rejects packets
        // larger than max_packet_size + headers; keep inputs in a sane range.
        if (size == 0 || size > 4096)
            return 0;

        // the API takes a mutable buffer, so copy the immutable fuzzer input
        var buf = new byte[4096];
        Buffer.BlockCopy(data, 0, buf, 0, size);

        reliable.endpoint_receive_packet(g_endpoint, buf, size);

        // advance time so the reassembly / received-packet sequence buffers cycle
        g_time += 0.01;
        reliable.endpoint_update(g_endpoint, g_time);
        reliable.endpoint_clear_acks(g_endpoint);

        return 0;
    }
}
