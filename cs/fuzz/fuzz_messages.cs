/*
    Message types for the connection fuzz targets.

    The stock TestMessage only calls serialize_bits, so it exercises almost none of the
    serialize vocabulary. These messages deliberately drive the full set — int / bits / bool /
    float / double / compressed_float / int_relative / align, a bounded string, and a
    variable-length byte array — so fuzzing Connection.ProcessPacket reaches the read paths of
    each serialize helper (and their length/bounds checks, a classic bug surface). One block
    message type covers the reliable-ordered block path.

    Shared by fuzz_connection, fuzz_connection_structured, and the seed generator so the
    message-type indices line up between what writes the seeds and what reads them.
*/

using networkprotocol;

enum FuzzMessageType
{
    FUZZ_MESSAGE_PRIMITIVES,
    FUZZ_MESSAGE_STRING,
    FUZZ_MESSAGE_BYTES,
    FUZZ_MESSAGE_BLOCK,
    FUZZ_NUM_MESSAGE_TYPES
}

static class fuzz_messages
{
    public const int FuzzMaxBytes = 512;
    public const int FuzzMaxString = 64;
}

// Every fixed-width serialize helper, including an odd bit width and a relative int.
class FuzzPrimitivesMessage : Message
{
    public int i;           // serialize_int with an asymmetric range
    public uint bits;       // serialize_bits, odd width
    public bool flag;       // serialize_bool
    public float f;         // serialize_float
    public double d;        // serialize_double
    public float cf;        // serialize_compressed_float, [0,1]
    public int @base;       // serialize_int
    public int rel;         // serialize_int_relative against base

    public override bool Serialize(BaseStream stream)
    {
        if (!stream.serialize_int(ref i, -100000, 100000)) return false;
        if (!stream.serialize_bits(ref bits, 17)) return false;
        if (!stream.serialize_bool(ref flag)) return false;
        if (!stream.serialize_float(ref f)) return false;
        if (!stream.serialize_double(ref d)) return false;
        if (!stream.serialize_compressed_float(ref cf, 0.0f, 1.0f, 0.01f)) return false;
        if (!stream.serialize_align()) return false;
        if (!stream.serialize_int(ref @base, 0, 1000)) return false;
        if (!stream.serialize_int_relative(@base, ref rel)) return false;
        return true;
    }
}

// Bounded string: exercises serialize_string's length read + bounds check.
class FuzzStringMessage : Message
{
    public string str = "";

    public override bool Serialize(BaseStream stream) =>
        stream.serialize_string(ref str, fuzz_messages.FuzzMaxString);
}

// Variable-length byte array: a count then that many bytes — the read path where a bad count
// would over-read if unchecked.
class FuzzBytesMessage : Message
{
    public int count;
    public byte[] data = new byte[fuzz_messages.FuzzMaxBytes];

    public override bool Serialize(BaseStream stream)
    {
        if (!stream.serialize_int(ref count, 0, fuzz_messages.FuzzMaxBytes)) return false;
        if (!stream.serialize_bytes(data, count)) return false;
        return true;
    }
}

// Block message for the reliable-ordered block path.
class FuzzBlockMessage : BlockMessage
{
    public ushort sequence;

    public override bool Serialize(BaseStream stream) =>
        stream.serialize_bits(ref sequence, 16);
}

class FuzzMessageFactory : MESSAGE_FACTORY_START
{
    public FuzzMessageFactory(Allocator allocator) : base(allocator, (int)FuzzMessageType.FUZZ_NUM_MESSAGE_TYPES)
    {
        DECLARE_MESSAGE_TYPE((int)FuzzMessageType.FUZZ_MESSAGE_PRIMITIVES, typeof(FuzzPrimitivesMessage));
        DECLARE_MESSAGE_TYPE((int)FuzzMessageType.FUZZ_MESSAGE_STRING, typeof(FuzzStringMessage));
        DECLARE_MESSAGE_TYPE((int)FuzzMessageType.FUZZ_MESSAGE_BYTES, typeof(FuzzBytesMessage));
        DECLARE_MESSAGE_TYPE((int)FuzzMessageType.FUZZ_MESSAGE_BLOCK, typeof(FuzzBlockMessage));
        MESSAGE_FACTORY_FINISH();
    }
}
