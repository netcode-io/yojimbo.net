/*
    Fuzz target: yojimbo::Connection round trip, driven by a structured script.

    Where fuzz_connection feeds arbitrary bytes to ProcessPacket (great for malformed input,
    but random bytes rarely form a valid packet), this target interprets the fuzz input as a
    *script* of operations against a sender/receiver Connection pair:

        - send a message (fuzz picks type, channel, and contents) on the sender;
        - "tick": generate a packet from the sender and either deliver it to the receiver (and
          ack it) or drop it (fuzz-controlled loss), then advance time and drain the receiver.

    Every packet is produced by the real write path, so it is always structurally valid and the
    receiver never bails out early — which lets the fuzzer drive the reliable-ordered channel's
    reassembly and in-order delivery state machine (out-of-order arrival via loss + resend)
    under fuzzer-chosen message streams.

    Shares the config table (fuzz_config) and message factory (fuzz_messages) with
    fuzz_connection. Seeds: cpp/fuzz/corpus/fuzz_connection_structured.
*/

using networkprotocol;
using System;
using static networkprotocol.yojimbo;

static class fuzz_connection_structured
{
    // Minimal cursor over the fuzz input; out-of-data reads return 0.
    class Reader
    {
        public byte[] data;
        public int size;
        public int pos;

        public byte u8() => pos < size ? data[pos++] : (byte)0;
        public ushort u16() { ushort a = u8(); ushort b = u8(); return (ushort)(a | (b << 8)); }
        public bool done() => pos >= size;
    }

    // Returns false if the message should be discarded rather than sent (e.g. a block message whose
    // block couldn't be allocated - sending a zero-size block would trip a send-time assert; under
    // allocation-fault injection that path is reachable).
    static bool fill_message(Message message, int type, Reader r, ConnectionConfig config, int channel, Allocator allocator)
    {
        switch ((FuzzMessageType)type)
        {
            case FuzzMessageType.FUZZ_MESSAGE_PRIMITIVES:
            {
                var m = (FuzzPrimitivesMessage)message;
                m.i = r.u16() - 32768;
                m.bits = r.u16();
                m.flag = (r.u8() & 1) != 0;
                m.f = r.u16() - 32768;
                m.d = r.u16() - 32768;
                m.cf = (r.u8() % 101) / 100.0f;   // [0,1]
                m.@base = r.u16() % 900;
                m.rel = m.@base + 1 + (r.u8() % 100);   // serialize_int_relative needs base < rel
                break;
            }
            case FuzzMessageType.FUZZ_MESSAGE_STRING:
            {
                var m = (FuzzStringMessage)message;
                var n = r.u8() % fuzz_messages.FuzzMaxString;       // leave room for the terminator
                var str = new char[n];
                for (var i = 0; i < n; ++i)
                {
                    // masked to ASCII: the string payload is well-formed UTF-8 by the writer's
                    // contract (serialize debug-asserts it, and asserts are live in this
                    // harness), so this write-path target must generate conforming content.
                    // Arbitrary bytes still reach the reader's malformed-string refusal path via
                    // fuzz_connection's raw packets.
                    var c = (byte)(r.u8() & 0x7F);
                    str[i] = c != 0 ? (char)c : ' ';   // no embedded NUL
                }
                m.str = new string(str);
                break;
            }
            case FuzzMessageType.FUZZ_MESSAGE_BYTES:
            {
                var m = (FuzzBytesMessage)message;
                m.count = r.u16() % (fuzz_messages.FuzzMaxBytes + 1);
                for (var i = 0; i < m.count; ++i)
                    m.data[i] = r.u8();
                break;
            }
            case FuzzMessageType.FUZZ_MESSAGE_BLOCK:
            {
                var m = (FuzzBlockMessage)message;
                m.sequence = r.u16();
                var maxBlock = config.channel[channel].maxBlockSize;
                var blockSize = 1 + (r.u16() % (maxBlock < 8192 ? maxBlock : 8192));
                var block = YOJIMBO_ALLOCATE(allocator, blockSize);
                if (block == null)
                    return false;   // allocation failed (fault injection) -> don't send a blockless block message
                var seed = r.u8();
                for (var i = 0; i < blockSize; ++i)
                    block[i] = (byte)(i + seed);
                m.AttachBlock(allocator, block, blockSize);
                break;
            }
            default: break;
        }
        return true;
    }

    // Allocator used to fuzz allocation-failure paths. Delegates to the GC but can be told to
    // fail the Nth upcoming allocation (then it disarms), driven by the fuzz input. Failures are only
    // armed *after* construction, since the library allocates its fixed pools up front and treats
    // those as infallible; every runtime allocation (packet generate/process, message create, block
    // attach) is expected to handle null gracefully - that is exactly what this exercises.
    class FaultAllocator : Allocator
    {
        public void FailIn(int n) => m_countdown = n;       // fail the n-th allocation from now, once
        public void Disarm() => m_countdown = -1;

        public override T Allocate<T>(int size, Func<T> create, string file, int line)
        {
            if (m_countdown == 0)
            {
                m_countdown = -1;                           // one-shot: fail this allocation, then rearm off
                SetErrorLevel(AllocatorErrorLevel.ALLOCATOR_ERROR_OUT_OF_MEMORY);
                return null;
            }
            if (m_countdown > 0)
                m_countdown--;
            var p = create();
            if (p == null)
            {
                SetErrorLevel(AllocatorErrorLevel.ALLOCATOR_ERROR_OUT_OF_MEMORY);
                return null;
            }
            TrackAlloc(p, size, file, line);
            return p;
        }

        public override void Free(object p, string file, int line)
        {
            if (p == null)
                return;
            TrackFree(p, file, line);
        }

        int m_countdown = -1;
    }

    // Serialize just the connection-packet channel-entry count, matching ConnectionPacket.Serialize.
    // (ConnectionPacket itself is internal; the per-entry body is written by the library below.)
    static bool write_channel_entry_count(BaseStream stream, ref int numChannelEntries, int numChannels) =>
        stream.serialize_int(ref numChannelEntries, 0, numChannels);

    // Feed the receiver a *hand-built* reliable-ordered block fragment whose header fields
    // (numFragments / fragmentId / fragmentSize) are fuzz-chosen and deliberately out of spec - the
    // thing the real write path never emits (e.g. a full-size final fragment). The wire bytes are
    // produced by the library's own ChannelPacketData writer, so the format stays in sync; only the
    // adversarial field *values* come from the fuzzer. advConfig uses a maxBlockSize that is not a
    // multiple of blockFragmentSize, so this targets the block-reassembly bounds check directly. The
    // receiver is Reset first so messageId 0 is the expected next block and the fragment reaches the
    // reassembly copy.
    static void inject_adversarial_fragment(Connection receiver, ConnectionConfig advConfig, FuzzMessageFactory factory, Reader r)
    {
        var cc = advConfig.channel[0];
        var maxFrags = cc.MaxFragmentsPerBlock;

        receiver.Reset();

        var channelData = new ChannelPacketData();
        channelData.Initialize();
        channelData.channelIndex = 0;
        channelData.blockMessage = true;
        channelData.block.messageId = 0;

        var numFragments = (maxFrags > 1) ? (1 + (r.u8() % maxFrags)) : 1;
        channelData.block.numFragments = (ushort)numFragments;

        var fragmentId = (numFragments > 1) ? (r.u8() % numFragments) : 0;
        if ((r.u8() & 1) != 0)
            fragmentId = numFragments - 1;              // bias toward the final fragment (overflow case)
        channelData.block.fragmentId = (ushort)fragmentId;

        var fragmentSize = 1 + (r.u16() % cc.blockFragmentSize);
        if ((r.u8() & 1) != 0)
            fragmentSize = cc.blockFragmentSize;        // bias toward a full-size (adversarial) fragment
        channelData.block.fragmentSize = (ushort)fragmentSize;

        channelData.block.fragmentData = YOJIMBO_ALLOCATE(factory.Allocator, fragmentSize);
        if (channelData.block.fragmentData == null)
        {
            channelData.Free(factory);
            return;
        }
        Array.Fill(channelData.block.fragmentData, r.u8());
        channelData.block.messageType = (int)FuzzMessageType.FUZZ_MESSAGE_BLOCK;

        if (fragmentId == 0)
        {
            // Fragment 0 carries the block message; the writer serializes it after the fragment data.
            var bm = (FuzzBlockMessage)factory.CreateMessage((int)FuzzMessageType.FUZZ_MESSAGE_BLOCK);
            if (bm == null)
            {
                channelData.Free(factory);
                return;
            }
            bm.sequence = r.u16();
            channelData.block.message = bm;
        }

        // Zero-initialized, with 8 bytes of slack past the write size (upstream's reader loads a
        // 64-bit window past the packet data end).
        var packet = new byte[8 * 1024 + 8];
        var stream = new WriteStream(null, packet, 8 * 1024);
        var numChannelEntries = 1;
        if (write_channel_entry_count(stream, ref numChannelEntries, advConfig.numChannels) &&
            channelData.Serialize(stream, factory, advConfig.channel, advConfig.numChannels))
        {
            stream.Flush();
            var packetBytes = stream.BytesProcessed;
            channelData.Free(factory);                // release our write-side fragment data + message
            if (packetBytes > 0)
                receiver.ProcessPacket(null, 0, packet, packetBytes);
        }
        else
        {
            channelData.Free(factory);
        }

        Message m;
        while ((m = receiver.ReceiveMessage(0)) != null)
            factory.ReleaseMessage(m);
    }

    public static int LLVMFuzzerTestOneInput(byte[] data, int size)
    {
        if (size < 1)
            return 0;

        var r = new Reader { data = data, size = size, pos = 0 };

        // The fault allocator is declared first so it outlives (and its leak check runs after) the
        // factories and connections built on top of it.
        using var allocator = new FaultAllocator();

        var config = new ConnectionConfig();
        fuzz_config.fuzz_make_config(r.u8(), config);

        using var senderFactory = new FuzzMessageFactory(allocator);
        using var receiverFactory = new FuzzMessageFactory(allocator);

        var time = 100.0;
        using var sender = new Connection(allocator, senderFactory, config, time);
        using var receiver = new Connection(allocator, receiverFactory, config, time);

        // A dedicated receiver + factory for adversarial block fragments, on a config whose
        // maxBlockSize is not a multiple of blockFragmentSize (the overflow-prone geometry).
        var advConfig = new ConnectionConfig();
        advConfig.numChannels = 1;
        advConfig.channel[0].type = ChannelType.CHANNEL_TYPE_RELIABLE_ORDERED;
        advConfig.channel[0].maxBlockSize = 1100;
        advConfig.channel[0].blockFragmentSize = 500;
        using var advFactory = new FuzzMessageFactory(allocator);
        using var advReceiver = new Connection(allocator, advFactory, advConfig, time);

        // Zero-initialized with 8 bytes of slack past the generate size, for the reader's 64-bit
        // over-read window (see the note on the block-fragment packet buffer above).
        var packetData = new byte[8 * 1024 + 8];
        ushort sequence = 0;
        const int MAX_OPS = 512;

        for (var op = 0; op < MAX_OPS && !r.done(); ++op)
        {
            var action = r.u8();

            // Occasionally schedule an allocation failure a few allocations out (one-shot). Armed only
            // here, inside the op loop, so it never disturbs the up-front pool allocations.
            if ((action & 0x20) != 0)
                allocator.FailIn(1 + (r.u8() % 12));

            // Occasionally feed the dedicated receiver an adversarial block fragment.
            if ((action & 0xC0) == 0xC0)
                inject_adversarial_fragment(advReceiver, advConfig, advFactory, r);

            if ((action & 3) != 0)
            {
                // send a message
                var type = r.u8() % (int)FuzzMessageType.FUZZ_NUM_MESSAGE_TYPES;
                var channel = (config.numChannels > 1) ? (r.u8() % config.numChannels) : 0;

                // Block messages are only valid on a reliable-ordered channel with blocks enabled:
                // the unreliable channel serializes blocks inline and asserts if one won't fit a
                // single packet, and a disableBlocks channel asserts outright. Fall back otherwise.
                if (type == (int)FuzzMessageType.FUZZ_MESSAGE_BLOCK &&
                    (config.channel[channel].type != ChannelType.CHANNEL_TYPE_RELIABLE_ORDERED ||
                     config.channel[channel].disableBlocks))
                {
                    type = (int)FuzzMessageType.FUZZ_MESSAGE_PRIMITIVES;
                }

                if (sender.CanSendMessage(channel))
                {
                    var message = senderFactory.CreateMessage(type);
                    if (message != null)
                    {
                        if (fill_message(message, type, r, config, channel, senderFactory.Allocator))
                            sender.SendMessage(channel, message);
                        else
                            senderFactory.ReleaseMessage(message);
                    }
                }
            }
            else
            {
                // tick: generate a packet and deliver or drop it
                if (sender.GeneratePacket(null, sequence, packetData, 8 * 1024, out var packetBytes) && packetBytes > 0)
                {
                    var drop = (action & 4) != 0;   // fuzz-controlled packet loss
                    if (!drop)
                    {
                        receiver.ProcessPacket(null, sequence, packetData, packetBytes);
                        sender.ProcessAcks(new[] { sequence }, 1);
                    }
                }

                time += 0.1;
                sender.AdvanceTime(time);
                receiver.AdvanceTime(time);
                sequence++;

                for (var ch = 0; ch < config.numChannels; ++ch)
                {
                    Message m;
                    while ((m = receiver.ReceiveMessage(ch)) != null)
                        receiverFactory.ReleaseMessage(m);
                }
            }
        }

        // final drain
        for (var ch = 0; ch < config.numChannels; ++ch)
        {
            Message m;
            while ((m = receiver.ReceiveMessage(ch)) != null)
                receiverFactory.ReleaseMessage(m);
        }

        return 0;
    }
}
