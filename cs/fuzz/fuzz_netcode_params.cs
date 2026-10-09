/*
    Shared parameters for the netcode fuzz target and its seed generator (fuzz_netcode_params.h).

    The generator (cpp/tools/gen_seed_corpus) writes packets with the same protocol id and keys
    the harness reads with, or the seeds won't decrypt and would be no better than random bytes.

    The harness reads with all-zero packet and private keys, so the generator writes with the
    same zero key.
*/

static class fuzz_netcode_params
{
    public const ulong FUZZ_PROTOCOL_ID = 0x1122334455667788UL;
    public const ulong FUZZ_TIMESTAMP = 1000000UL;
}
