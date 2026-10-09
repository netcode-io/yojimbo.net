/*
    Fuzz target: netcode_read_connect_token_private().

    This is the parser for the *decrypted* private connect token — the server-side path that
    reads a client id, a timeout, and a variable-length list of server addresses (each tagged
    IPv4 or IPv6), plus the session keys and user data. It's a separate target from
    fuzz_netcode because the AEAD boundary makes it unreachable by mutation there: any change
    to the encrypted token bytes fails the MAC in read_packet, so the bytes that reach this
    parser in production are never attacker-mutated through that path. Fuzzing it directly
    exercises the address-list loop and length handling on arbitrary input.

    The reader is internal to netcode, like fuzz_netcode (see the note there).

    Seed corpus: cpp/fuzz/corpus/fuzz_netcode_connect_token (a valid serialized private token).
*/

namespace networkprotocol
{
    static partial class netcode
    {
        /// C#: the result of the last read (OK or ERROR), so the corpus replay can check every seed still parses.
        internal static int fuzz_netcode_connect_token_last_result = ERROR;

        internal static int fuzz_netcode_connect_token(byte[] data, int size)
        {
            fuzz_netcode_connect_token_last_result = ERROR;

            // The reader requires a full private-token buffer (CONNECT_TOKEN_PRIVATE_BYTES)
            // and never reads past it; mirror the caller by copying the input into a zero-padded
            // buffer of exactly that size. Larger inputs are ignored, as in the real receive path.
            if (size > CONNECT_TOKEN_PRIVATE_BYTES)
                return 0;

            var buffer = new byte[CONNECT_TOKEN_PRIVATE_BYTES];
            System.Buffer.BlockCopy(data, 0, buffer, 0, size);

            var token = new connect_token_private_t();
            fuzz_netcode_connect_token_last_result = read_connect_token_private(buffer, buffer.Length, token);

            return 0;
        }
    }
}
