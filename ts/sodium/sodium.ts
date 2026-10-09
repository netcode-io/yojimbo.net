/*
    sodium.ts

    TypeScript port of the libsodium subset netcode uses (cpp/sodium/sodium.c, libsodium 1.0.22):

        ChaCha20 (IETF, 96-bit nonce), HChaCha20, Poly1305,
        ChaCha20-Poly1305 (IETF) and XChaCha20-Poly1305 (IETF) AEAD,
        crypto_verify_16/32/64, sodium_memzero, randombytes_buf.

    Only the portable reference code paths are ported (chacha-merged "ref" ChaCha20, poly1305-donna
    32-bit). Output is byte-for-byte identical to libsodium; sodium_test() checks the RFC 8439 and
    draft-irtf-cfrg-xchacha vectors and netcode's known-answer vectors.

    Conventions:

        - Byte strings are Uint8Array. Lengths are passed explicitly, exactly as libsodium takes them,
          and are plain numbers (all lengths here are far below 2^53).
        - Pointer arithmetic (c + mlen, ...) is not available, so pass subarray() views when you need
          an offset. The output and input of the stream and AEAD functions may be the SAME bytes
          (in place, as netcode does: c === m, or two views of the same memory at the same offset).
          Partially overlapping buffers are not supported (they are undefined behaviour in libsodium).
        - `unsigned long long *` out-params are `{ value: number } | null`.
        - Functions return 0 on success and -1 on failure like libsodium. Misuse that libsodium
          aborts on (sodium_misuse) throws an Error here; so does passing a buffer shorter than the
          length given for it.

    Constant time: the code is free of secret-dependent branches and memory indices, and the tag
    comparison is branchless, but JavaScript gives no hard guarantees (JIT tiers, GC). Treat it
    with the same caution as any JS crypto.
*/

// ---------------------------------------------------------------------------------------------
// constants

export const crypto_verify_16_BYTES = 16;
export const crypto_verify_32_BYTES = 32;
export const crypto_verify_64_BYTES = 64;

export const crypto_stream_chacha20_ietf_KEYBYTES = 32;
export const crypto_stream_chacha20_ietf_NONCEBYTES = 12;
export const crypto_stream_chacha20_ietf_MESSAGEBYTES_MAX = 64 * 4294967296; // 64 * 2^32

export const crypto_core_hchacha20_OUTPUTBYTES = 32;
export const crypto_core_hchacha20_INPUTBYTES = 16;
export const crypto_core_hchacha20_KEYBYTES = 32;
export const crypto_core_hchacha20_CONSTBYTES = 16;

export const crypto_onetimeauth_poly1305_BYTES = 16;
export const crypto_onetimeauth_poly1305_KEYBYTES = 32;

export const crypto_aead_chacha20poly1305_ietf_KEYBYTES = 32;
export const crypto_aead_chacha20poly1305_ietf_NSECBYTES = 0;
export const crypto_aead_chacha20poly1305_ietf_NPUBBYTES = 12;
export const crypto_aead_chacha20poly1305_ietf_ABYTES = 16;
export const crypto_aead_chacha20poly1305_ietf_MESSAGEBYTES_MAX = 64 * 4294967295; // 64 * (2^32 - 1)

export const crypto_aead_xchacha20poly1305_ietf_KEYBYTES = 32;
export const crypto_aead_xchacha20poly1305_ietf_NSECBYTES = 0;
export const crypto_aead_xchacha20poly1305_ietf_NPUBBYTES = 24;
export const crypto_aead_xchacha20poly1305_ietf_ABYTES = 16;
// libsodium: SODIUM_SIZE_MAX - ABYTES. Lengths are numbers here, so the bound is 2^53.
export const crypto_aead_xchacha20poly1305_ietf_MESSAGEBYTES_MAX = Number.MAX_SAFE_INTEGER - 16;

/** out-param for libsodium's `unsigned long long *` length outputs */
export type sodium_length_out = { value: number };

// ---------------------------------------------------------------------------------------------
// misuse / argument checks

export function sodium_misuse(): never
{
    throw new Error( 'sodium_misuse' );
}

function check_length( len: number ): void
{
    if ( !( len >= 0 ) || len !== Math.floor( len ) || len > Number.MAX_SAFE_INTEGER )
        throw new Error( 'sodium: invalid length ' + len );
}

function check_buffer( buf: Uint8Array | null, len: number, name: string ): void
{
    check_length( len );
    if ( buf === null ? len !== 0 : len > buf.length )
        throw new Error( 'sodium: ' + name + ' is shorter than ' + len + ' bytes' );
}

function load32_le( b: Uint8Array, p: number ): number
{
    return ( b[p] | ( b[p + 1] << 8 ) | ( b[p + 2] << 16 ) | ( b[p + 3] << 24 ) ) >>> 0;
}

function store32_le( b: Uint8Array, p: number, v: number ): void
{
    b[p] = v;
    b[p + 1] = v >>> 8;
    b[p + 2] = v >>> 16;
    b[p + 3] = v >>> 24;
}

function store64_le( b: Uint8Array, p: number, v: number ): void
{
    const lo = v % 4294967296;
    store32_le( b, p, lo );
    store32_le( b, p + 4, ( v - lo ) / 4294967296 );
}

// ---------------------------------------------------------------------------------------------
// sodium_utils.c

export function sodium_memzero( pnt: Uint8Array, len: number = pnt.length ): void
{
    pnt.fill( 0, 0, len );
}

// ---------------------------------------------------------------------------------------------
// sodium_verify.c

function crypto_verify_n( x: Uint8Array, xp: number, y: Uint8Array, yp: number, n: number ): number
{
    let d = 0;
    for ( let i = 0; i < n; i++ )
        d |= x[xp + i] ^ y[yp + i];
    // d is 0..255: (d - 1) >>> 8 has bit 0 set only when d == 0. branchless, like upstream.
    return ( ( ( d - 1 ) >>> 8 ) & 1 ) - 1;
}

export function crypto_verify_16( x: Uint8Array, y: Uint8Array ): number
{
    check_buffer( x, 16, 'x' );
    check_buffer( y, 16, 'y' );
    return crypto_verify_n( x, 0, y, 0, crypto_verify_16_BYTES );
}

export function crypto_verify_32( x: Uint8Array, y: Uint8Array ): number
{
    check_buffer( x, 32, 'x' );
    check_buffer( y, 32, 'y' );
    return crypto_verify_n( x, 0, y, 0, crypto_verify_32_BYTES );
}

export function crypto_verify_64( x: Uint8Array, y: Uint8Array ): number
{
    check_buffer( x, 64, 'x' );
    check_buffer( y, 64, 'y' );
    return crypto_verify_n( x, 0, y, 0, crypto_verify_64_BYTES );
}

// ---------------------------------------------------------------------------------------------
// randombytes.c

const RANDOMBYTES_CHUNK = 65536; // getRandomValues() refuses more than 65536 bytes per call

export function randombytes_buf( buf: Uint8Array, size: number = buf.length ): void
{
    check_buffer( buf, size, 'buf' );
    for ( let i = 0; i < size; i += RANDOMBYTES_CHUNK )
        globalThis.crypto.getRandomValues( buf.subarray( i, Math.min( size, i + RANDOMBYTES_CHUNK ) ) );
}

// ---------------------------------------------------------------------------------------------
// core.c

let sodium_initialized = false;

/** returns 0 on first success, 1 if already initialized, -1 if no CSPRNG is available */
export function sodium_init(): number
{
    if ( sodium_initialized )
        return 1;
    if ( typeof globalThis.crypto?.getRandomValues !== 'function' )
        return -1;
    sodium_initialized = true;
    return 0;
}

// ---------------------------------------------------------------------------------------------
// sodium_chacha20_ref.c (chacha-merged.c version 20080118, D. J. Bernstein, public domain)

// chacha_ctx.input, and the keystream block. module scratch, zeroed after every use.
const chacha_ctx_input = new Uint32Array( 16 );
const chacha_keystream = new Uint8Array( 64 );

function chacha_keysetup( input: Uint32Array, k: Uint8Array ): void
{
    input[0] = 0x61707865;
    input[1] = 0x3320646e;
    input[2] = 0x79622d32;
    input[3] = 0x6b206574;
    for ( let i = 0; i < 8; i++ )
        input[4 + i] = load32_le( k, i * 4 );
}

function chacha_ietf_ivsetup( input: Uint32Array, iv: Uint8Array, counter: number ): void
{
    input[12] = counter;
    input[13] = load32_le( iv, 0 );
    input[14] = load32_le( iv, 4 );
    input[15] = load32_le( iv, 8 );
}

// the ChaCha20 block function: 20 rounds over input, feed-forward, serialized little endian to out[0..64)
function chacha20_block( input: Uint32Array, out: Uint8Array ): void
{
    const j0 = input[0] | 0, j1 = input[1] | 0, j2 = input[2] | 0, j3 = input[3] | 0;
    const j4 = input[4] | 0, j5 = input[5] | 0, j6 = input[6] | 0, j7 = input[7] | 0;
    const j8 = input[8] | 0, j9 = input[9] | 0, j10 = input[10] | 0, j11 = input[11] | 0;
    const j12 = input[12] | 0, j13 = input[13] | 0, j14 = input[14] | 0, j15 = input[15] | 0;

    let x0 = j0, x1 = j1, x2 = j2, x3 = j3, x4 = j4, x5 = j5, x6 = j6, x7 = j7;
    let x8 = j8, x9 = j9, x10 = j10, x11 = j11, x12 = j12, x13 = j13, x14 = j14, x15 = j15;

    for ( let i = 20; i > 0; i -= 2 )
    {
        // QUARTERROUND( x0, x4, x8, x12 )
        x0 = ( x0 + x4 ) | 0; x12 ^= x0; x12 = ( x12 << 16 ) | ( x12 >>> 16 );
        x8 = ( x8 + x12 ) | 0; x4 ^= x8; x4 = ( x4 << 12 ) | ( x4 >>> 20 );
        x0 = ( x0 + x4 ) | 0; x12 ^= x0; x12 = ( x12 << 8 ) | ( x12 >>> 24 );
        x8 = ( x8 + x12 ) | 0; x4 ^= x8; x4 = ( x4 << 7 ) | ( x4 >>> 25 );
        // QUARTERROUND( x1, x5, x9, x13 )
        x1 = ( x1 + x5 ) | 0; x13 ^= x1; x13 = ( x13 << 16 ) | ( x13 >>> 16 );
        x9 = ( x9 + x13 ) | 0; x5 ^= x9; x5 = ( x5 << 12 ) | ( x5 >>> 20 );
        x1 = ( x1 + x5 ) | 0; x13 ^= x1; x13 = ( x13 << 8 ) | ( x13 >>> 24 );
        x9 = ( x9 + x13 ) | 0; x5 ^= x9; x5 = ( x5 << 7 ) | ( x5 >>> 25 );
        // QUARTERROUND( x2, x6, x10, x14 )
        x2 = ( x2 + x6 ) | 0; x14 ^= x2; x14 = ( x14 << 16 ) | ( x14 >>> 16 );
        x10 = ( x10 + x14 ) | 0; x6 ^= x10; x6 = ( x6 << 12 ) | ( x6 >>> 20 );
        x2 = ( x2 + x6 ) | 0; x14 ^= x2; x14 = ( x14 << 8 ) | ( x14 >>> 24 );
        x10 = ( x10 + x14 ) | 0; x6 ^= x10; x6 = ( x6 << 7 ) | ( x6 >>> 25 );
        // QUARTERROUND( x3, x7, x11, x15 )
        x3 = ( x3 + x7 ) | 0; x15 ^= x3; x15 = ( x15 << 16 ) | ( x15 >>> 16 );
        x11 = ( x11 + x15 ) | 0; x7 ^= x11; x7 = ( x7 << 12 ) | ( x7 >>> 20 );
        x3 = ( x3 + x7 ) | 0; x15 ^= x3; x15 = ( x15 << 8 ) | ( x15 >>> 24 );
        x11 = ( x11 + x15 ) | 0; x7 ^= x11; x7 = ( x7 << 7 ) | ( x7 >>> 25 );
        // QUARTERROUND( x0, x5, x10, x15 )
        x0 = ( x0 + x5 ) | 0; x15 ^= x0; x15 = ( x15 << 16 ) | ( x15 >>> 16 );
        x10 = ( x10 + x15 ) | 0; x5 ^= x10; x5 = ( x5 << 12 ) | ( x5 >>> 20 );
        x0 = ( x0 + x5 ) | 0; x15 ^= x0; x15 = ( x15 << 8 ) | ( x15 >>> 24 );
        x10 = ( x10 + x15 ) | 0; x5 ^= x10; x5 = ( x5 << 7 ) | ( x5 >>> 25 );
        // QUARTERROUND( x1, x6, x11, x12 )
        x1 = ( x1 + x6 ) | 0; x12 ^= x1; x12 = ( x12 << 16 ) | ( x12 >>> 16 );
        x11 = ( x11 + x12 ) | 0; x6 ^= x11; x6 = ( x6 << 12 ) | ( x6 >>> 20 );
        x1 = ( x1 + x6 ) | 0; x12 ^= x1; x12 = ( x12 << 8 ) | ( x12 >>> 24 );
        x11 = ( x11 + x12 ) | 0; x6 ^= x11; x6 = ( x6 << 7 ) | ( x6 >>> 25 );
        // QUARTERROUND( x2, x7, x8, x13 )
        x2 = ( x2 + x7 ) | 0; x13 ^= x2; x13 = ( x13 << 16 ) | ( x13 >>> 16 );
        x8 = ( x8 + x13 ) | 0; x7 ^= x8; x7 = ( x7 << 12 ) | ( x7 >>> 20 );
        x2 = ( x2 + x7 ) | 0; x13 ^= x2; x13 = ( x13 << 8 ) | ( x13 >>> 24 );
        x8 = ( x8 + x13 ) | 0; x7 ^= x8; x7 = ( x7 << 7 ) | ( x7 >>> 25 );
        // QUARTERROUND( x3, x4, x9, x14 )
        x3 = ( x3 + x4 ) | 0; x14 ^= x3; x14 = ( x14 << 16 ) | ( x14 >>> 16 );
        x9 = ( x9 + x14 ) | 0; x4 ^= x9; x4 = ( x4 << 12 ) | ( x4 >>> 20 );
        x3 = ( x3 + x4 ) | 0; x14 ^= x3; x14 = ( x14 << 8 ) | ( x14 >>> 24 );
        x9 = ( x9 + x14 ) | 0; x4 ^= x9; x4 = ( x4 << 7 ) | ( x4 >>> 25 );
    }

    store32_le( out, 0, x0 + j0 );
    store32_le( out, 4, x1 + j1 );
    store32_le( out, 8, x2 + j2 );
    store32_le( out, 12, x3 + j3 );
    store32_le( out, 16, x4 + j4 );
    store32_le( out, 20, x5 + j5 );
    store32_le( out, 24, x6 + j6 );
    store32_le( out, 28, x7 + j7 );
    store32_le( out, 32, x8 + j8 );
    store32_le( out, 36, x9 + j9 );
    store32_le( out, 40, x10 + j10 );
    store32_le( out, 44, x11 + j11 );
    store32_le( out, 48, x12 + j12 );
    store32_le( out, 52, x13 + j13 );
    store32_le( out, 56, x14 + j14 );
    store32_le( out, 60, x15 + j15 );
}

// c[0..bytes) = m[0..bytes) ^ keystream. c and m may be the same bytes: each byte is read before it
// is written. like upstream, a block counter wrap carries into input[13].
function chacha20_encrypt_bytes( input: Uint32Array, m: Uint8Array, c: Uint8Array, bytes: number ): void
{
    const ks = chacha_keystream;
    let p = 0;
    while ( bytes > 0 )
    {
        chacha20_block( input, ks );
        input[12] = input[12] + 1;
        if ( input[12] === 0 )
            input[13] = input[13] + 1;
        const n = bytes < 64 ? bytes : 64;
        for ( let i = 0; i < n; i++ )
            c[p + i] = m[p + i] ^ ks[i];
        p += n;
        bytes -= n;
    }
    ks.fill( 0 );
}

function stream_ietf_ext_ref( c: Uint8Array, clen: number, n: Uint8Array, k: Uint8Array ): number
{
    if ( !clen )
        return 0;
    const ctx = chacha_ctx_input;
    chacha_keysetup( ctx, k );
    chacha_ietf_ivsetup( ctx, n, 0 );
    c.fill( 0, 0, clen );
    chacha20_encrypt_bytes( ctx, c, c, clen );
    ctx.fill( 0 );
    return 0;
}

function stream_ietf_ext_ref_xor_ic( c: Uint8Array, m: Uint8Array, mlen: number, n: Uint8Array, ic: number, k: Uint8Array ): number
{
    if ( !mlen )
        return 0;
    const ctx = chacha_ctx_input;
    chacha_keysetup( ctx, k );
    chacha_ietf_ivsetup( ctx, n, ic );
    chacha20_encrypt_bytes( ctx, m, c, mlen );
    ctx.fill( 0 );
    return 0;
}

// ---------------------------------------------------------------------------------------------
// sodium_stream_chacha20.c (IETF variants only)

function check_stream_args( c: Uint8Array, m: Uint8Array | null, len: number, n: Uint8Array, k: Uint8Array ): void
{
    check_buffer( c, len, 'c' );
    if ( m !== null )
        check_buffer( m, len, 'm' );
    check_buffer( n, crypto_stream_chacha20_ietf_NONCEBYTES, 'n' );
    check_buffer( k, crypto_stream_chacha20_ietf_KEYBYTES, 'k' );
}

/** c[0..clen) = ChaCha20 keystream for (k, n) starting at block 0 */
export function crypto_stream_chacha20_ietf( c: Uint8Array, clen: number, n: Uint8Array, k: Uint8Array ): number
{
    check_stream_args( c, null, clen, n, k );
    if ( clen > crypto_stream_chacha20_ietf_MESSAGEBYTES_MAX )
        sodium_misuse();
    return stream_ietf_ext_ref( c, clen, n, k );
}

/** c[0..mlen) = m[0..mlen) ^ ChaCha20 keystream for (k, n) starting at block ic. c may be m. */
export function crypto_stream_chacha20_ietf_xor_ic( c: Uint8Array, m: Uint8Array, mlen: number, n: Uint8Array, ic: number, k: Uint8Array ): number
{
    check_stream_args( c, m, mlen, n, k );
    if ( ic !== ( ic >>> 0 ) )
        sodium_misuse();
    if ( ic > ( 64 * 4294967296 ) / 64 - Math.floor( ( mlen + 63 ) / 64 ) )
        sodium_misuse();
    return stream_ietf_ext_ref_xor_ic( c, m, mlen, n, ic, k );
}

/** c[0..mlen) = m[0..mlen) ^ ChaCha20 keystream for (k, n) starting at block 0. c may be m. */
export function crypto_stream_chacha20_ietf_xor( c: Uint8Array, m: Uint8Array, mlen: number, n: Uint8Array, k: Uint8Array ): number
{
    check_stream_args( c, m, mlen, n, k );
    if ( mlen > crypto_stream_chacha20_ietf_MESSAGEBYTES_MAX )
        sodium_misuse();
    return stream_ietf_ext_ref_xor_ic( c, m, mlen, n, 0, k );
}

export function crypto_stream_chacha20_ietf_keygen( k: Uint8Array ): void
{
    randombytes_buf( k, crypto_stream_chacha20_ietf_KEYBYTES );
}

// ---------------------------------------------------------------------------------------------
// sodium_core_hchacha20.c

/** out[0..32) = HChaCha20(k, in[0..16)), with the "expand 32-byte k" constant when c is null */
export function crypto_core_hchacha20( out: Uint8Array, in_: Uint8Array, k: Uint8Array, c: Uint8Array | null ): number
{
    check_buffer( out, crypto_core_hchacha20_OUTPUTBYTES, 'out' );
    check_buffer( in_, crypto_core_hchacha20_INPUTBYTES, 'in' );
    check_buffer( k, crypto_core_hchacha20_KEYBYTES, 'k' );
    if ( c !== null )
        check_buffer( c, crypto_core_hchacha20_CONSTBYTES, 'c' );

    let x0: number, x1: number, x2: number, x3: number;
    if ( c === null )
    {
        x0 = 0x61707865;
        x1 = 0x3320646e;
        x2 = 0x79622d32;
        x3 = 0x6b206574;
    }
    else
    {
        x0 = load32_le( c, 0 ) | 0;
        x1 = load32_le( c, 4 ) | 0;
        x2 = load32_le( c, 8 ) | 0;
        x3 = load32_le( c, 12 ) | 0;
    }
    let x4 = load32_le( k, 0 ) | 0;
    let x5 = load32_le( k, 4 ) | 0;
    let x6 = load32_le( k, 8 ) | 0;
    let x7 = load32_le( k, 12 ) | 0;
    let x8 = load32_le( k, 16 ) | 0;
    let x9 = load32_le( k, 20 ) | 0;
    let x10 = load32_le( k, 24 ) | 0;
    let x11 = load32_le( k, 28 ) | 0;
    let x12 = load32_le( in_, 0 ) | 0;
    let x13 = load32_le( in_, 4 ) | 0;
    let x14 = load32_le( in_, 8 ) | 0;
    let x15 = load32_le( in_, 12 ) | 0;

    for ( let i = 0; i < 10; i++ )
    {
        // QUARTERROUND( x0, x4, x8, x12 )
        x0 = ( x0 + x4 ) | 0; x12 ^= x0; x12 = ( x12 << 16 ) | ( x12 >>> 16 );
        x8 = ( x8 + x12 ) | 0; x4 ^= x8; x4 = ( x4 << 12 ) | ( x4 >>> 20 );
        x0 = ( x0 + x4 ) | 0; x12 ^= x0; x12 = ( x12 << 8 ) | ( x12 >>> 24 );
        x8 = ( x8 + x12 ) | 0; x4 ^= x8; x4 = ( x4 << 7 ) | ( x4 >>> 25 );
        // QUARTERROUND( x1, x5, x9, x13 )
        x1 = ( x1 + x5 ) | 0; x13 ^= x1; x13 = ( x13 << 16 ) | ( x13 >>> 16 );
        x9 = ( x9 + x13 ) | 0; x5 ^= x9; x5 = ( x5 << 12 ) | ( x5 >>> 20 );
        x1 = ( x1 + x5 ) | 0; x13 ^= x1; x13 = ( x13 << 8 ) | ( x13 >>> 24 );
        x9 = ( x9 + x13 ) | 0; x5 ^= x9; x5 = ( x5 << 7 ) | ( x5 >>> 25 );
        // QUARTERROUND( x2, x6, x10, x14 )
        x2 = ( x2 + x6 ) | 0; x14 ^= x2; x14 = ( x14 << 16 ) | ( x14 >>> 16 );
        x10 = ( x10 + x14 ) | 0; x6 ^= x10; x6 = ( x6 << 12 ) | ( x6 >>> 20 );
        x2 = ( x2 + x6 ) | 0; x14 ^= x2; x14 = ( x14 << 8 ) | ( x14 >>> 24 );
        x10 = ( x10 + x14 ) | 0; x6 ^= x10; x6 = ( x6 << 7 ) | ( x6 >>> 25 );
        // QUARTERROUND( x3, x7, x11, x15 )
        x3 = ( x3 + x7 ) | 0; x15 ^= x3; x15 = ( x15 << 16 ) | ( x15 >>> 16 );
        x11 = ( x11 + x15 ) | 0; x7 ^= x11; x7 = ( x7 << 12 ) | ( x7 >>> 20 );
        x3 = ( x3 + x7 ) | 0; x15 ^= x3; x15 = ( x15 << 8 ) | ( x15 >>> 24 );
        x11 = ( x11 + x15 ) | 0; x7 ^= x11; x7 = ( x7 << 7 ) | ( x7 >>> 25 );
        // QUARTERROUND( x0, x5, x10, x15 )
        x0 = ( x0 + x5 ) | 0; x15 ^= x0; x15 = ( x15 << 16 ) | ( x15 >>> 16 );
        x10 = ( x10 + x15 ) | 0; x5 ^= x10; x5 = ( x5 << 12 ) | ( x5 >>> 20 );
        x0 = ( x0 + x5 ) | 0; x15 ^= x0; x15 = ( x15 << 8 ) | ( x15 >>> 24 );
        x10 = ( x10 + x15 ) | 0; x5 ^= x10; x5 = ( x5 << 7 ) | ( x5 >>> 25 );
        // QUARTERROUND( x1, x6, x11, x12 )
        x1 = ( x1 + x6 ) | 0; x12 ^= x1; x12 = ( x12 << 16 ) | ( x12 >>> 16 );
        x11 = ( x11 + x12 ) | 0; x6 ^= x11; x6 = ( x6 << 12 ) | ( x6 >>> 20 );
        x1 = ( x1 + x6 ) | 0; x12 ^= x1; x12 = ( x12 << 8 ) | ( x12 >>> 24 );
        x11 = ( x11 + x12 ) | 0; x6 ^= x11; x6 = ( x6 << 7 ) | ( x6 >>> 25 );
        // QUARTERROUND( x2, x7, x8, x13 )
        x2 = ( x2 + x7 ) | 0; x13 ^= x2; x13 = ( x13 << 16 ) | ( x13 >>> 16 );
        x8 = ( x8 + x13 ) | 0; x7 ^= x8; x7 = ( x7 << 12 ) | ( x7 >>> 20 );
        x2 = ( x2 + x7 ) | 0; x13 ^= x2; x13 = ( x13 << 8 ) | ( x13 >>> 24 );
        x8 = ( x8 + x13 ) | 0; x7 ^= x8; x7 = ( x7 << 7 ) | ( x7 >>> 25 );
        // QUARTERROUND( x3, x4, x9, x14 )
        x3 = ( x3 + x4 ) | 0; x14 ^= x3; x14 = ( x14 << 16 ) | ( x14 >>> 16 );
        x9 = ( x9 + x14 ) | 0; x4 ^= x9; x4 = ( x4 << 12 ) | ( x4 >>> 20 );
        x3 = ( x3 + x4 ) | 0; x14 ^= x3; x14 = ( x14 << 8 ) | ( x14 >>> 24 );
        x9 = ( x9 + x14 ) | 0; x4 ^= x9; x4 = ( x4 << 7 ) | ( x4 >>> 25 );
    }

    store32_le( out, 0, x0 );
    store32_le( out, 4, x1 );
    store32_le( out, 8, x2 );
    store32_le( out, 12, x3 );
    store32_le( out, 16, x12 );
    store32_le( out, 20, x13 );
    store32_le( out, 24, x14 );
    store32_le( out, 28, x15 );

    return 0;
}

// ---------------------------------------------------------------------------------------------
// sodium_poly1305_donna.c (poly1305-donna 32-bit: five 26-bit limbs)
//
// donna32 forms d_k = sum of five (h_i * r_j) or (h_i * 5 r_j) products in 64-bit integers. In JS
// numbers those sums are not exact: h_i < 2^27 and 5 r_j < 2^28.4, so a single product can reach
// 2^55.4 > 2^53. Each r_j is therefore split once into 13-bit halves, r_j = rh_j * 2^13 + rl_j (and
// 5 r_j = 5 rh_j * 2^13 + 5 rl_j), and every d_k is carried as d_k = L_k + H_k * 2^13 with
//
//     L_k = sum h_i * (rl_j or 5 rl_j),   H_k = sum h_i * (rh_j or 5 rh_j).
//
// Bounds (h_i < 2^27 + 2^9 on entry to a block; rl_j, rh_j < 2^13, so 5 rl_j, 5 rh_j < 2^15.33):
// each product < 2^42.4, each five-term sum < 2^44.8, and the carry into the next limb is < 2^32.1,
// so every intermediate is an integer below 2^46: exact in a double. The carry chain then computes
// exactly donna32's (d_k mod 2^26, floor(d_k / 2^26)), so h evolves identically to the C code.
// % and / by powers of two are exact on these values. The final carry and the reduction mod p run on
// limbs < 2^27 and use 32-bit integer operations, as in the C code.

const TWO26 = 67108864;     // 2^26
const TWO13 = 8192;         // 2^13
const TWO32 = 4294967296;   // 2^32

/** crypto_onetimeauth_poly1305_state (poly1305_state_internal_t) */
export class crypto_onetimeauth_poly1305_state
{
    r = new Float64Array( 5 );
    h = new Float64Array( 5 );
    pad = new Float64Array( 4 );
    leftover = 0;
    buffer = new Uint8Array( 16 );
    final = 0;
}

const poly1305_block_size = 16;

function poly1305_init( st: crypto_onetimeauth_poly1305_state, key: Uint8Array ): void
{
    // r &= 0xffffffc0ffffffc0ffffffc0fffffff - wiped after finalization
    st.r[0] = ( load32_le( key, 0 ) ) & 0x3ffffff;
    st.r[1] = ( load32_le( key, 3 ) >>> 2 ) & 0x3ffff03;
    st.r[2] = ( load32_le( key, 6 ) >>> 4 ) & 0x3ffc0ff;
    st.r[3] = ( load32_le( key, 9 ) >>> 6 ) & 0x3f03fff;
    st.r[4] = ( load32_le( key, 12 ) >>> 8 ) & 0x00fffff;

    // h = 0
    st.h.fill( 0 );

    // save pad for later
    st.pad[0] = load32_le( key, 16 );
    st.pad[1] = load32_le( key, 20 );
    st.pad[2] = load32_le( key, 24 );
    st.pad[3] = load32_le( key, 28 );

    st.leftover = 0;
    st.final = 0;
}

function poly1305_blocks( st: crypto_onetimeauth_poly1305_state, m: Uint8Array, mp: number, bytes: number ): void
{
    const hibit = st.final ? 0 : ( 1 << 24 ); // 1 << 128

    const r0 = st.r[0], r1 = st.r[1], r2 = st.r[2], r3 = st.r[3], r4 = st.r[4];

    const rl0 = r0 % TWO13, rh0 = ( r0 - rl0 ) / TWO13;
    const rl1 = r1 % TWO13, rh1 = ( r1 - rl1 ) / TWO13;
    const rl2 = r2 % TWO13, rh2 = ( r2 - rl2 ) / TWO13;
    const rl3 = r3 % TWO13, rh3 = ( r3 - rl3 ) / TWO13;
    const rl4 = r4 % TWO13, rh4 = ( r4 - rl4 ) / TWO13;

    // s_j = r_j * 5, split the same way
    const sl1 = rl1 * 5, sh1 = rh1 * 5;
    const sl2 = rl2 * 5, sh2 = rh2 * 5;
    const sl3 = rl3 * 5, sh3 = rh3 * 5;
    const sl4 = rl4 * 5, sh4 = rh4 * 5;

    let h0 = st.h[0], h1 = st.h[1], h2 = st.h[2], h3 = st.h[3], h4 = st.h[4];

    while ( bytes >= poly1305_block_size )
    {
        // h += m[i]
        h0 += ( load32_le( m, mp + 0 ) ) & 0x3ffffff;
        h1 += ( load32_le( m, mp + 3 ) >>> 2 ) & 0x3ffffff;
        h2 += ( load32_le( m, mp + 6 ) >>> 4 ) & 0x3ffffff;
        h3 += ( load32_le( m, mp + 9 ) >>> 6 ) & 0x3ffffff;
        h4 += ( load32_le( m, mp + 12 ) >>> 8 ) | hibit;

        // h *= r, as d_k = L_k + H_k * 2^13
        const L0 = h0 * rl0 + h1 * sl4 + h2 * sl3 + h3 * sl2 + h4 * sl1;
        const H0 = h0 * rh0 + h1 * sh4 + h2 * sh3 + h3 * sh2 + h4 * sh1;
        const L1 = h0 * rl1 + h1 * rl0 + h2 * sl4 + h3 * sl3 + h4 * sl2;
        const H1 = h0 * rh1 + h1 * rh0 + h2 * sh4 + h3 * sh3 + h4 * sh2;
        const L2 = h0 * rl2 + h1 * rl1 + h2 * rl0 + h3 * sl4 + h4 * sl3;
        const H2 = h0 * rh2 + h1 * rh1 + h2 * rh0 + h3 * sh4 + h4 * sh3;
        const L3 = h0 * rl3 + h1 * rl2 + h2 * rl1 + h3 * rl0 + h4 * sl4;
        const H3 = h0 * rh3 + h1 * rh2 + h2 * rh1 + h3 * rh0 + h4 * sh4;
        const L4 = h0 * rl4 + h1 * rl3 + h2 * rl2 + h3 * rl1 + h4 * rl0;
        const H4 = h0 * rh4 + h1 * rh3 + h2 * rh2 + h3 * rh1 + h4 * rh0;

        // (partial) h %= p. for each limb: d = L + c + Hl * 2^13 + Hh * 2^26, with Hl = H mod 2^13,
        // so h_k = (L + c + Hl * 2^13) mod 2^26 and c' = floor((L + c + Hl * 2^13) / 2^26) + Hh
        let t: number, u: number, c: number;

        t = H0 % TWO13; u = L0 + t * TWO13;
        h0 = u % TWO26; c = ( u - h0 ) / TWO26 + ( H0 - t ) / TWO13;

        t = H1 % TWO13; u = L1 + c + t * TWO13;
        h1 = u % TWO26; c = ( u - h1 ) / TWO26 + ( H1 - t ) / TWO13;

        t = H2 % TWO13; u = L2 + c + t * TWO13;
        h2 = u % TWO26; c = ( u - h2 ) / TWO26 + ( H2 - t ) / TWO13;

        t = H3 % TWO13; u = L3 + c + t * TWO13;
        h3 = u % TWO26; c = ( u - h3 ) / TWO26 + ( H3 - t ) / TWO13;

        t = H4 % TWO13; u = L4 + c + t * TWO13;
        h4 = u % TWO26; c = ( u - h4 ) / TWO26 + ( H4 - t ) / TWO13;

        h0 += c * 5;              // < 2^26 + 5 * 2^32.1
        c = h0 % TWO26;
        h1 += ( h0 - c ) / TWO26;
        h0 = c;

        mp += poly1305_block_size;
        bytes -= poly1305_block_size;
    }

    st.h[0] = h0;
    st.h[1] = h1;
    st.h[2] = h2;
    st.h[3] = h3;
    st.h[4] = h4;
}

function poly1305_finish( st: crypto_onetimeauth_poly1305_state, mac: Uint8Array, macp: number ): void
{
    // process the remaining block
    if ( st.leftover )
    {
        let i = st.leftover;
        st.buffer[i++] = 1;
        for ( ; i < poly1305_block_size; i++ )
            st.buffer[i] = 0;
        st.final = 1;
        poly1305_blocks( st, st.buffer, 0, poly1305_block_size );
    }

    // fully carry h. limbs are < 2^27 + 2^9 here, so int32 operations are exact
    let h0 = st.h[0] | 0, h1 = st.h[1] | 0, h2 = st.h[2] | 0, h3 = st.h[3] | 0, h4 = st.h[4] | 0;
    let c: number;

    c = h1 >>> 26; h1 = h1 & 0x3ffffff;
    h2 += c; c = h2 >>> 26; h2 = h2 & 0x3ffffff;
    h3 += c; c = h3 >>> 26; h3 = h3 & 0x3ffffff;
    h4 += c; c = h4 >>> 26; h4 = h4 & 0x3ffffff;
    h0 += c * 5; c = h0 >>> 26; h0 = h0 & 0x3ffffff;
    h1 += c;

    // compute h + -p
    let g0 = h0 + 5; c = g0 >>> 26; g0 &= 0x3ffffff;
    let g1 = h1 + c; c = g1 >>> 26; g1 &= 0x3ffffff;
    let g2 = h2 + c; c = g2 >>> 26; g2 &= 0x3ffffff;
    let g3 = h3 + c; c = g3 >>> 26; g3 &= 0x3ffffff;
    let g4 = ( h4 + c - ( 1 << 26 ) ) | 0;

    // select h if h < p, or h + -p if h >= p
    let mask = ( ( g4 >>> 31 ) - 1 ) | 0;
    g0 &= mask;
    g1 &= mask;
    g2 &= mask;
    g3 &= mask;
    g4 &= mask;
    mask = ~mask;

    h0 = ( h0 & mask ) | g0;
    h1 = ( h1 & mask ) | g1;
    h2 = ( h2 & mask ) | g2;
    h3 = ( h3 & mask ) | g3;
    h4 = ( h4 & mask ) | g4;

    // h = h % (2^128)
    h0 = ( h0 | ( h1 << 26 ) ) >>> 0;
    h1 = ( ( h1 >>> 6 ) | ( h2 << 20 ) ) >>> 0;
    h2 = ( ( h2 >>> 12 ) | ( h3 << 14 ) ) >>> 0;
    h3 = ( ( h3 >>> 18 ) | ( h4 << 8 ) ) >>> 0;

    // mac = (h + pad) % (2^128). f < 2^33: exact
    let f: number;
    f = h0 + st.pad[0];                                     h0 = f >>> 0;
    f = h1 + st.pad[1] + ( f - ( f >>> 0 ) ) / TWO32;      h1 = f >>> 0;
    f = h2 + st.pad[2] + ( f - ( f >>> 0 ) ) / TWO32;      h2 = f >>> 0;
    f = h3 + st.pad[3] + ( f - ( f >>> 0 ) ) / TWO32;      h3 = f >>> 0;

    store32_le( mac, macp + 0, h0 );
    store32_le( mac, macp + 4, h1 );
    store32_le( mac, macp + 8, h2 );
    store32_le( mac, macp + 12, h3 );

    // zero out the state
    poly1305_state_zero( st );
}

function poly1305_state_zero( st: crypto_onetimeauth_poly1305_state ): void
{
    st.r.fill( 0 );
    st.h.fill( 0 );
    st.pad.fill( 0 );
    st.leftover = 0;
    st.buffer.fill( 0 );
    st.final = 0;
}

function poly1305_update( st: crypto_onetimeauth_poly1305_state, m: Uint8Array, mp: number, bytes: number ): void
{
    // handle leftover
    if ( st.leftover )
    {
        let want = poly1305_block_size - st.leftover;
        if ( want > bytes )
            want = bytes;
        for ( let i = 0; i < want; i++ )
            st.buffer[st.leftover + i] = m[mp + i];
        bytes -= want;
        mp += want;
        st.leftover += want;
        if ( st.leftover < poly1305_block_size )
            return;
        poly1305_blocks( st, st.buffer, 0, poly1305_block_size );
        st.leftover = 0;
    }

    // process full blocks
    if ( bytes >= poly1305_block_size )
    {
        const want = bytes - ( bytes % poly1305_block_size );
        poly1305_blocks( st, m, mp, want );
        mp += want;
        bytes -= want;
    }

    // store leftover
    if ( bytes )
    {
        for ( let i = 0; i < bytes; i++ )
            st.buffer[st.leftover + i] = m[mp + i];
        st.leftover += bytes;
    }
}

// ---------------------------------------------------------------------------------------------
// sodium_onetimeauth_poly1305.c

const onetimeauth_state = new crypto_onetimeauth_poly1305_state();

/** out[0..16) = Poly1305(k, in[0..inlen)) */
export function crypto_onetimeauth_poly1305( out: Uint8Array, in_: Uint8Array, inlen: number, k: Uint8Array ): number
{
    check_buffer( out, crypto_onetimeauth_poly1305_BYTES, 'out' );
    check_buffer( in_, inlen, 'in' );
    check_buffer( k, crypto_onetimeauth_poly1305_KEYBYTES, 'k' );
    poly1305_init( onetimeauth_state, k );
    poly1305_update( onetimeauth_state, in_, 0, inlen );
    poly1305_finish( onetimeauth_state, out, 0 );
    return 0;
}

const onetimeauth_correct = new Uint8Array( 16 );

/** 0 if h[0..16) is the Poly1305 tag of in[0..inlen) under k, else -1. constant time. */
export function crypto_onetimeauth_poly1305_verify( h: Uint8Array, in_: Uint8Array, inlen: number, k: Uint8Array ): number
{
    check_buffer( h, crypto_onetimeauth_poly1305_BYTES, 'h' );
    crypto_onetimeauth_poly1305( onetimeauth_correct, in_, inlen, k );
    const ret = crypto_verify_n( h, 0, onetimeauth_correct, 0, 16 );
    onetimeauth_correct.fill( 0 );
    return ret;
}

export function crypto_onetimeauth_poly1305_init( state: crypto_onetimeauth_poly1305_state, key: Uint8Array ): number
{
    check_buffer( key, crypto_onetimeauth_poly1305_KEYBYTES, 'key' );
    poly1305_init( state, key );
    return 0;
}

export function crypto_onetimeauth_poly1305_update( state: crypto_onetimeauth_poly1305_state, in_: Uint8Array, inlen: number ): number
{
    check_buffer( in_, inlen, 'in' );
    poly1305_update( state, in_, 0, inlen );
    return 0;
}

export function crypto_onetimeauth_poly1305_final( state: crypto_onetimeauth_poly1305_state, out: Uint8Array ): number
{
    check_buffer( out, crypto_onetimeauth_poly1305_BYTES, 'out' );
    poly1305_finish( state, out, 0 );
    return 0;
}

export function crypto_onetimeauth_poly1305_keygen( k: Uint8Array ): void
{
    randombytes_buf( k, crypto_onetimeauth_poly1305_KEYBYTES );
}

// ---------------------------------------------------------------------------------------------
// sodium_aead_chacha20poly1305.c (IETF construction) and sodium_aead_xchacha20poly1305.c
//
// tag = Poly1305( otk = ChaCha20(k, n, block 0)[0..32),
//                 ad || pad16 || c || pad16 || le64(adlen) || le64(clen) )
// the message is encrypted with ChaCha20 starting at block 1.

const _pad0 = new Uint8Array( 16 );

// module scratch for the AEAD functions. key-derived material is zeroed after every call.
const aead_state = new crypto_onetimeauth_poly1305_state();
const aead_block0 = new Uint8Array( 64 );
const aead_slen = new Uint8Array( 8 );
const aead_computed_mac = new Uint8Array( 16 );
const xchacha_k2 = new Uint8Array( crypto_core_hchacha20_OUTPUTBYTES );
const xchacha_npub2 = new Uint8Array( crypto_aead_chacha20poly1305_ietf_NPUBBYTES );

function aead_mac( mac: Uint8Array, macp: number, c: Uint8Array, clen: number, ad: Uint8Array | null, adlen: number, npub: Uint8Array, k: Uint8Array ): void
{
    const state = aead_state;
    const block0 = aead_block0;
    const slen = aead_slen;

    stream_ietf_ext_ref( block0, 64, npub, k );
    poly1305_init( state, block0 );
    block0.fill( 0 );

    if ( ad !== null )
        poly1305_update( state, ad, 0, adlen );
    poly1305_update( state, _pad0, 0, ( 0x10 - ( adlen % 16 ) ) & 0xf );

    poly1305_update( state, c, 0, clen );
    poly1305_update( state, _pad0, 0, ( 0x10 - ( clen % 16 ) ) & 0xf );

    store64_le( slen, 0, adlen );
    poly1305_update( state, slen, 0, 8 );

    store64_le( slen, 0, clen );
    poly1305_update( state, slen, 0, 8 );

    poly1305_finish( state, mac, macp );   // zeroes the state
}

// shared body of the IETF and XChaCha detached encrypt (k, npub are the IETF key and 96-bit nonce)
function aead_ietf_encrypt_detached( c: Uint8Array, mac: Uint8Array, macp: number, m: Uint8Array, mlen: number, ad: Uint8Array | null, adlen: number, npub: Uint8Array, k: Uint8Array ): void
{
    stream_ietf_ext_ref_xor_ic( c, m, mlen, npub, 1, k );
    aead_mac( mac, macp, c, mlen, ad, adlen, npub, k );
}

// shared body of the IETF and XChaCha detached decrypt. the tag is checked before any plaintext is
// written; on failure m[0..mlen) is zeroed and -1 returned (as upstream). m === null: verify only.
function aead_ietf_decrypt_detached( m: Uint8Array | null, c: Uint8Array, clen: number, mac: Uint8Array, macp: number, ad: Uint8Array | null, adlen: number, npub: Uint8Array, k: Uint8Array ): number
{
    const mlen = clen;
    const computed_mac = aead_computed_mac;

    aead_mac( computed_mac, 0, c, mlen, ad, adlen, npub, k );
    const ret = crypto_verify_n( computed_mac, 0, mac, macp, 16 );
    computed_mac.fill( 0 );
    if ( m === null )
        return ret;
    if ( ret !== 0 )
    {
        m.fill( 0, 0, mlen );
        return -1;
    }
    stream_ietf_ext_ref_xor_ic( m, c, mlen, npub, 1, k );
    return 0;
}

function check_aead_args( out: Uint8Array | null, outlen: number, in_: Uint8Array, inlen: number, ad: Uint8Array | null, adlen: number, npub: Uint8Array, npubbytes: number, k: Uint8Array ): void
{
    if ( out !== null )
        check_buffer( out, outlen, 'output' );
    check_buffer( in_, inlen, 'input' );
    check_buffer( ad, adlen, 'ad' );
    check_buffer( npub, npubbytes, 'npub' );
    check_buffer( k, 32, 'k' );
}

// --- ChaCha20-Poly1305 (IETF)

/** c[0..mlen) = encrypt(m[0..mlen)), mac[0..16) = tag. c may be m. nsec is unused (pass null). */
export function crypto_aead_chacha20poly1305_ietf_encrypt_detached( c: Uint8Array, mac: Uint8Array, maclen_p: sodium_length_out | null,
                                                                    m: Uint8Array, mlen: number,
                                                                    ad: Uint8Array | null, adlen: number,
                                                                    nsec: Uint8Array | null, npub: Uint8Array, k: Uint8Array ): number
{
    void nsec;
    check_aead_args( c, mlen, m, mlen, ad, adlen, npub, crypto_aead_chacha20poly1305_ietf_NPUBBYTES, k );
    check_buffer( mac, crypto_aead_chacha20poly1305_ietf_ABYTES, 'mac' );
    if ( mlen > crypto_aead_chacha20poly1305_ietf_MESSAGEBYTES_MAX )
        sodium_misuse();
    aead_ietf_encrypt_detached( c, mac, 0, m, mlen, ad, adlen, npub, k );
    if ( maclen_p !== null )
        maclen_p.value = crypto_aead_chacha20poly1305_ietf_ABYTES;
    return 0;
}

/** c[0..mlen+16) = encrypt(m[0..mlen)) || tag. c may be m (in place; c needs 16 bytes of room). */
export function crypto_aead_chacha20poly1305_ietf_encrypt( c: Uint8Array, clen_p: sodium_length_out | null,
                                                           m: Uint8Array, mlen: number,
                                                           ad: Uint8Array | null, adlen: number,
                                                           nsec: Uint8Array | null, npub: Uint8Array, k: Uint8Array ): number
{
    void nsec;
    check_aead_args( c, mlen + crypto_aead_chacha20poly1305_ietf_ABYTES, m, mlen, ad, adlen, npub, crypto_aead_chacha20poly1305_ietf_NPUBBYTES, k );
    if ( mlen > crypto_aead_chacha20poly1305_ietf_MESSAGEBYTES_MAX )
        sodium_misuse();
    aead_ietf_encrypt_detached( c, c, mlen, m, mlen, ad, adlen, npub, k );
    if ( clen_p !== null )
        clen_p.value = mlen + crypto_aead_chacha20poly1305_ietf_ABYTES;
    return 0;
}

/** verifies mac over c[0..clen), then m[0..clen) = decrypt(c). returns -1 (m zeroed) on forgery. m may be c, or null to only verify. */
export function crypto_aead_chacha20poly1305_ietf_decrypt_detached( m: Uint8Array | null, nsec: Uint8Array | null,
                                                                    c: Uint8Array, clen: number, mac: Uint8Array,
                                                                    ad: Uint8Array | null, adlen: number,
                                                                    npub: Uint8Array, k: Uint8Array ): number
{
    void nsec;
    check_aead_args( m, clen, c, clen, ad, adlen, npub, crypto_aead_chacha20poly1305_ietf_NPUBBYTES, k );
    check_buffer( mac, crypto_aead_chacha20poly1305_ietf_ABYTES, 'mac' );
    return aead_ietf_decrypt_detached( m, c, clen, mac, 0, ad, adlen, npub, k );
}

/** c[0..clen) is ciphertext || tag. on success m[0..clen-16) = plaintext and 0 is returned; on failure -1. m may be c. */
export function crypto_aead_chacha20poly1305_ietf_decrypt( m: Uint8Array | null, mlen_p: sodium_length_out | null, nsec: Uint8Array | null,
                                                           c: Uint8Array, clen: number,
                                                           ad: Uint8Array | null, adlen: number,
                                                           npub: Uint8Array, k: Uint8Array ): number
{
    void nsec;
    const ABYTES = crypto_aead_chacha20poly1305_ietf_ABYTES;
    let ret = -1;
    check_aead_args( null, 0, c, clen, ad, adlen, npub, crypto_aead_chacha20poly1305_ietf_NPUBBYTES, k );
    if ( clen >= ABYTES )
    {
        if ( m !== null )
            check_buffer( m, clen - ABYTES, 'm' );
        ret = aead_ietf_decrypt_detached( m, c, clen - ABYTES, c, clen - ABYTES, ad, adlen, npub, k );
    }
    if ( mlen_p !== null )
        mlen_p.value = ret === 0 ? clen - ABYTES : 0;
    return ret;
}

export function crypto_aead_chacha20poly1305_ietf_keygen( k: Uint8Array ): void
{
    randombytes_buf( k, crypto_aead_chacha20poly1305_ietf_KEYBYTES );
}

// --- XChaCha20-Poly1305 (IETF): subkey = HChaCha20(k, npub[0..16)), nonce = 0^4 || npub[16..24)

function xchacha_subkey( npub: Uint8Array, k: Uint8Array ): void
{
    crypto_core_hchacha20( xchacha_k2, npub, k, null );
    xchacha_npub2.fill( 0, 0, 4 );
    for ( let i = 0; i < 8; i++ )
        xchacha_npub2[4 + i] = npub[crypto_core_hchacha20_INPUTBYTES + i];
}

function xchacha_subkey_zero(): void
{
    xchacha_k2.fill( 0 );
    xchacha_npub2.fill( 0 );
}

/** c[0..mlen) = encrypt(m[0..mlen)), mac[0..16) = tag. c may be m. nsec is unused (pass null). */
export function crypto_aead_xchacha20poly1305_ietf_encrypt_detached( c: Uint8Array, mac: Uint8Array, maclen_p: sodium_length_out | null,
                                                                     m: Uint8Array, mlen: number,
                                                                     ad: Uint8Array | null, adlen: number,
                                                                     nsec: Uint8Array | null, npub: Uint8Array, k: Uint8Array ): number
{
    void nsec;
    check_aead_args( c, mlen, m, mlen, ad, adlen, npub, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES, k );
    check_buffer( mac, crypto_aead_xchacha20poly1305_ietf_ABYTES, 'mac' );
    if ( mlen > crypto_aead_xchacha20poly1305_ietf_MESSAGEBYTES_MAX )
        sodium_misuse();
    xchacha_subkey( npub, k );
    aead_ietf_encrypt_detached( c, mac, 0, m, mlen, ad, adlen, xchacha_npub2, xchacha_k2 );
    xchacha_subkey_zero();
    if ( maclen_p !== null )
        maclen_p.value = crypto_aead_xchacha20poly1305_ietf_ABYTES;
    return 0;
}

/** c[0..mlen+16) = encrypt(m[0..mlen)) || tag. c may be m (in place; c needs 16 bytes of room). */
export function crypto_aead_xchacha20poly1305_ietf_encrypt( c: Uint8Array, clen_p: sodium_length_out | null,
                                                            m: Uint8Array, mlen: number,
                                                            ad: Uint8Array | null, adlen: number,
                                                            nsec: Uint8Array | null, npub: Uint8Array, k: Uint8Array ): number
{
    void nsec;
    check_aead_args( c, mlen + crypto_aead_xchacha20poly1305_ietf_ABYTES, m, mlen, ad, adlen, npub, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES, k );
    if ( mlen > crypto_aead_xchacha20poly1305_ietf_MESSAGEBYTES_MAX )
        sodium_misuse();
    xchacha_subkey( npub, k );
    aead_ietf_encrypt_detached( c, c, mlen, m, mlen, ad, adlen, xchacha_npub2, xchacha_k2 );
    xchacha_subkey_zero();
    if ( clen_p !== null )
        clen_p.value = mlen + crypto_aead_xchacha20poly1305_ietf_ABYTES;
    return 0;
}

/** verifies mac over c[0..clen), then m[0..clen) = decrypt(c). returns -1 (m zeroed) on forgery. m may be c, or null to only verify. */
export function crypto_aead_xchacha20poly1305_ietf_decrypt_detached( m: Uint8Array | null, nsec: Uint8Array | null,
                                                                     c: Uint8Array, clen: number, mac: Uint8Array,
                                                                     ad: Uint8Array | null, adlen: number,
                                                                     npub: Uint8Array, k: Uint8Array ): number
{
    void nsec;
    check_aead_args( m, clen, c, clen, ad, adlen, npub, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES, k );
    check_buffer( mac, crypto_aead_xchacha20poly1305_ietf_ABYTES, 'mac' );
    xchacha_subkey( npub, k );
    const ret = aead_ietf_decrypt_detached( m, c, clen, mac, 0, ad, adlen, xchacha_npub2, xchacha_k2 );
    xchacha_subkey_zero();
    return ret;
}

/** c[0..clen) is ciphertext || tag. on success m[0..clen-16) = plaintext and 0 is returned; on failure -1. m may be c. */
export function crypto_aead_xchacha20poly1305_ietf_decrypt( m: Uint8Array | null, mlen_p: sodium_length_out | null, nsec: Uint8Array | null,
                                                            c: Uint8Array, clen: number,
                                                            ad: Uint8Array | null, adlen: number,
                                                            npub: Uint8Array, k: Uint8Array ): number
{
    void nsec;
    const ABYTES = crypto_aead_xchacha20poly1305_ietf_ABYTES;
    let ret = -1;
    check_aead_args( null, 0, c, clen, ad, adlen, npub, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES, k );
    if ( clen >= ABYTES )
    {
        if ( m !== null )
            check_buffer( m, clen - ABYTES, 'm' );
        xchacha_subkey( npub, k );
        ret = aead_ietf_decrypt_detached( m, c, clen - ABYTES, c, clen - ABYTES, ad, adlen, xchacha_npub2, xchacha_k2 );
        xchacha_subkey_zero();
    }
    if ( mlen_p !== null )
        mlen_p.value = ret === 0 ? clen - ABYTES : 0;
    return ret;
}

export function crypto_aead_xchacha20poly1305_ietf_keygen( k: Uint8Array ): void
{
    randombytes_buf( k, crypto_aead_xchacha20poly1305_ietf_KEYBYTES );
}

// ---------------------------------------------------------------------------------------------
// tests

function check( condition: boolean, message: string ): void
{
    if ( !condition )
        throw new Error( 'sodium_test: check failed: ' + message );
}

function hex( s: string ): Uint8Array
{
    const t = s.replace( /[^0-9a-fA-F]/g, '' );
    const out = new Uint8Array( t.length >> 1 );
    for ( let i = 0; i < out.length; i++ )
        out[i] = parseInt( t.slice( i * 2, i * 2 + 2 ), 16 );
    return out;
}

function to_hex( b: Uint8Array ): string
{
    let s = '';
    for ( let i = 0; i < b.length; i++ )
        s += ( b[i] < 16 ? '0' : '' ) + b[i].toString( 16 );
    return s;
}

function equal( a: Uint8Array, b: Uint8Array ): boolean
{
    if ( a.length !== b.length )
        return false;
    for ( let i = 0; i < a.length; i++ )
        if ( a[i] !== b[i] )
            return false;
    return true;
}

function check_bytes( actual: Uint8Array, expected: Uint8Array, message: string ): void
{
    check( equal( actual, expected ), message + ': got ' + to_hex( actual ) + ', expected ' + to_hex( expected ) );
}

function check_throws( fn: () => void, message: string ): void
{
    let threw = false;
    try { fn(); } catch { threw = true; }
    check( threw, message + ' should throw' );
}

function ascii( s: string ): Uint8Array
{
    const out = new Uint8Array( s.length );
    for ( let i = 0; i < s.length; i++ )
        out[i] = s.charCodeAt( i );
    return out;
}

// deterministic xorshift32, so failures reproduce
let test_rng_state = 0x9e3779b9;

function test_random_bytes( b: Uint8Array ): void
{
    for ( let i = 0; i < b.length; i++ )
    {
        let x = test_rng_state;
        x ^= x << 13; x ^= x >>> 17; x ^= x << 5;
        test_rng_state = x >>> 0;
        b[i] = x;
    }
}

function test_random_int( n: number ): number
{
    const b = new Uint8Array( 4 );
    test_random_bytes( b );
    return load32_le( b, 0 ) % n;
}

// straightforward BigInt Poly1305 (RFC 8439 2.5.1), an independent reference for the limb arithmetic
function poly1305_reference( m: Uint8Array, key: Uint8Array ): Uint8Array
{
    const le = ( b: Uint8Array, start: number, end: number ): bigint =>
    {
        let v = 0n;
        for ( let i = end - 1; i >= start; i-- )
            v = ( v << 8n ) | BigInt( b[i] );
        return v;
    };
    const p = ( 1n << 130n ) - 5n;
    const r = le( key, 0, 16 ) & 0x0ffffffc0ffffffc0ffffffc0fffffffn;
    const s = le( key, 16, 32 );
    let acc = 0n;
    for ( let i = 0; i < m.length; i += 16 )
    {
        const end = Math.min( i + 16, m.length );
        acc = ( ( acc + le( m, i, end ) + ( 1n << BigInt( 8 * ( end - i ) ) ) ) * r ) % p;
    }
    let tag = ( acc + s ) & ( ( 1n << 128n ) - 1n );
    const out = new Uint8Array( 16 );
    for ( let i = 0; i < 16; i++ )
    {
        out[i] = Number( tag & 0xffn );
        tag >>= 8n;
    }
    return out;
}

// the AEAD tag from its definition, via the public stream and Poly1305 functions
function aead_tag_reference( big: boolean, c: Uint8Array, ad: Uint8Array, npub: Uint8Array, k: Uint8Array ): Uint8Array
{
    let key = k, nonce = npub;
    if ( big )
    {
        key = new Uint8Array( 32 );
        crypto_core_hchacha20( key, npub, k, null );
        nonce = new Uint8Array( 12 );
        nonce.set( npub.subarray( 16, 24 ), 4 );
    }
    const otk = new Uint8Array( 32 );
    crypto_stream_chacha20_ietf( otk, 32, nonce, key );
    const pad = ( n: number ) => ( 16 - ( n % 16 ) ) % 16;
    const data = new Uint8Array( ad.length + pad( ad.length ) + c.length + pad( c.length ) + 16 );
    data.set( ad, 0 );
    data.set( c, ad.length + pad( ad.length ) );
    store64_le( data, data.length - 16, ad.length );
    store64_le( data, data.length - 8, c.length );
    return poly1305_reference( data, otk );
}

const rfc8439_sunscreen = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

function test_chacha20(): void
{
    const key = new Uint8Array( 32 );
    for ( let i = 0; i < 32; i++ )
        key[i] = i;

    // RFC 8439 2.3.2: block function, counter 1
    {
        const nonce = hex( '000000090000004a00000000' );
        const out = new Uint8Array( 64 );
        check( crypto_stream_chacha20_ietf_xor_ic( out, new Uint8Array( 64 ), 64, nonce, 1, key ) === 0, 'xor_ic returns 0' );
        check_bytes( out, hex(
            '10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e' +
            'd2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e' ), 'RFC 8439 2.3.2 chacha20 block' );
    }

    // RFC 8439 2.4.2: encryption, counter 1; also in place
    {
        const nonce = hex( '000000000000004a00000000' );
        const plaintext = ascii( rfc8439_sunscreen );
        const expected = hex(
            '6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b' +
            'f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8' +
            '07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736' +
            '5af90bbf74a35be6b40b8eedf2785e42874d' );
        const out = new Uint8Array( plaintext.length );
        crypto_stream_chacha20_ietf_xor_ic( out, plaintext, plaintext.length, nonce, 1, key );
        check_bytes( out, expected, 'RFC 8439 2.4.2 chacha20 encryption' );
        const inplace = plaintext.slice();
        crypto_stream_chacha20_ietf_xor_ic( inplace, inplace, inplace.length, nonce, 1, key );
        check_bytes( inplace, expected, 'RFC 8439 2.4.2 chacha20 encryption in place' );
        crypto_stream_chacha20_ietf_xor_ic( inplace, inplace, inplace.length, nonce, 1, key );
        check_bytes( inplace, plaintext, 'RFC 8439 2.4.2 chacha20 decryption in place' );
    }

    // RFC 8439 2.6.2: Poly1305 key generation = keystream block 0
    {
        const k = hex( '808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f' );
        const out = new Uint8Array( 32 );
        crypto_stream_chacha20_ietf( out, 32, hex( '000000000001020304050607' ), k );
        check_bytes( out, hex( '8ad5a08b905f81cc815040274ab29471a833b637e3fd0da508dbb8e2fdd1a646' ), 'RFC 8439 2.6.2 poly1305 key generation' );
    }

    // the keystream is continuous across 64-byte blocks: one call over n blocks equals block-by-block
    // calls with increasing ic, and xor with zeros equals crypto_stream_chacha20_ietf
    {
        const k = new Uint8Array( 32 ), n = new Uint8Array( 12 );
        test_random_bytes( k );
        test_random_bytes( n );
        const whole = new Uint8Array( 300 );
        crypto_stream_chacha20_ietf( whole, 300, n, k );
        const xored = new Uint8Array( 300 );
        crypto_stream_chacha20_ietf_xor( xored, new Uint8Array( 300 ), 300, n, k );
        check_bytes( xored, whole, 'stream == xor of zeros' );
        for ( let block = 0; block * 64 < 300; block++ )
        {
            const len = Math.min( 64, 300 - block * 64 );
            const piece = new Uint8Array( len );
            crypto_stream_chacha20_ietf_xor_ic( piece, new Uint8Array( len ), len, n, block, k );
            check_bytes( piece, whole.subarray( block * 64, block * 64 + len ), 'keystream block ' + block );
        }
    }

    // ic bounds: the 32-bit block counter must not wrap
    {
        const k = new Uint8Array( 32 ), n = new Uint8Array( 12 ), buf = new Uint8Array( 65 );
        check( crypto_stream_chacha20_ietf_xor_ic( buf, buf, 64, n, 0xffffffff, k ) === 0, 'last block counter is allowed' );
        check_throws( () => crypto_stream_chacha20_ietf_xor_ic( buf, buf, 65, n, 0xffffffff, k ), 'counter wrap' );
        check_throws( () => crypto_stream_chacha20_ietf_xor_ic( buf, buf, 1, n, 4294967296, k ), 'ic >= 2^32' );
        check_throws( () => crypto_stream_chacha20_ietf_xor( buf, buf, 66, n, k ), 'length beyond buffer' );
    }
}

function test_hchacha20(): void
{
    // draft-irtf-cfrg-xchacha-03 2.2.1
    const key = new Uint8Array( 32 );
    for ( let i = 0; i < 32; i++ )
        key[i] = i;
    const out = new Uint8Array( 32 );
    check( crypto_core_hchacha20( out, hex( '000000090000004a0000000031415927' ), key, null ) === 0, 'hchacha20 returns 0' );
    check_bytes( out, hex( '82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc' ), 'draft-irtf-cfrg-xchacha 2.2.1 hchacha20' );

    // an explicit constant equal to the default gives the same result
    const out2 = new Uint8Array( 32 );
    crypto_core_hchacha20( out2, hex( '000000090000004a0000000031415927' ), key, ascii( 'expand 32-byte k' ) );
    check_bytes( out2, out, 'hchacha20 with explicit sigma' );
}

function test_poly1305(): void
{
    const out = new Uint8Array( 16 );

    // RFC 8439 2.5.2
    {
        const key = hex( '85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b' );
        const msg = ascii( 'Cryptographic Forum Research Group' );
        crypto_onetimeauth_poly1305( out, msg, msg.length, key );
        check_bytes( out, hex( 'a8061dc1305136c6c22b8baf0c0127a9' ), 'RFC 8439 2.5.2 poly1305' );
        check( crypto_onetimeauth_poly1305_verify( out, msg, msg.length, key ) === 0, 'poly1305 verify accepts' );
        out[15] ^= 0x80;
        check( crypto_onetimeauth_poly1305_verify( out, msg, msg.length, key ) === -1, 'poly1305 verify rejects' );
    }

    // RFC 8439 A.3 #5..#11: the vectors that exercise the final carry and the reduction mod 2^130-5
    {
        const r1 = '0100000000000000000000000000000000000000000000000000000000000000';
        const r2 = '0200000000000000000000000000000000000000000000000000000000000000';
        const r1b = '0100000000000000040000000000000000000000000000000000000000000000';
        const vectors: [ string, string, string ][] = [
            [ r2, 'ffffffffffffffffffffffffffffffff', '03000000000000000000000000000000' ],
            [ '02000000000000000000000000000000ffffffffffffffffffffffffffffffff', '02000000000000000000000000000000', '03000000000000000000000000000000' ],
            [ r1, 'fffffffffffffffffffffffffffffffff0ffffffffffffffffffffffffffffff11000000000000000000000000000000', '05000000000000000000000000000000' ],
            [ r1, 'fffffffffffffffffffffffffffffffffbfefefefefefefefefefefefefefefe01010101010101010101010101010101', '00000000000000000000000000000000' ],
            [ r2, 'fdffffffffffffffffffffffffffffff', 'faffffffffffffffffffffffffffffff' ],
            [ r1b, 'e33594d7505e43b900000000000000003394d7505e4379cd01000000000000000000000000000000000000000000000001000000000000000000000000000000', '14000000000000005500000000000000' ],
            [ r1b, 'e33594d7505e43b900000000000000003394d7505e4379cd010000000000000000000000000000000000000000000000', '13000000000000000000000000000000' ],
        ];
        for ( let i = 0; i < vectors.length; i++ )
        {
            const key = hex( vectors[i][0] ), msg = hex( vectors[i][1] );
            crypto_onetimeauth_poly1305( out, msg, msg.length, key );
            check_bytes( out, hex( vectors[i][2] ), 'RFC 8439 A.3 #' + ( i + 5 ) );
            check_bytes( poly1305_reference( msg, key ), hex( vectors[i][2] ), 'reference poly1305 on RFC 8439 A.3 #' + ( i + 5 ) );
        }
    }

    // edge lengths x key/message patterns against the BigInt reference. all-0xff keys give the largest
    // clamped r and a pad that carries out of every word; all-0xff messages give the largest limbs
    {
        const lengths = [ 0, 1, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 255, 256, 257, 1000 ];
        const patterns = [ 'zero', 'ff', 'random' ];
        const fill = ( b: Uint8Array, pattern: string ) =>
        {
            if ( pattern === 'zero' ) b.fill( 0 );
            else if ( pattern === 'ff' ) b.fill( 0xff );
            else test_random_bytes( b );
        };
        for ( const len of lengths )
        {
            for ( const kp of patterns )
            {
                for ( const mp of patterns )
                {
                    const key = new Uint8Array( 32 ), msg = new Uint8Array( len );
                    fill( key, kp );
                    fill( msg, mp );
                    crypto_onetimeauth_poly1305( out, msg, len, key );
                    check_bytes( out, poly1305_reference( msg, key ), 'poly1305 len ' + len + ' key ' + kp + ' msg ' + mp );
                }
            }
        }

        // r with all clamp bits set but s = 0, and r = 0 (tag = s)
        const key = new Uint8Array( 32 );
        key.fill( 0xff, 0, 16 );
        const msg = new Uint8Array( 64 ).fill( 0xff );
        crypto_onetimeauth_poly1305( out, msg, 64, key );
        check_bytes( out, poly1305_reference( msg, key ), 'poly1305 max r, s = 0' );
        key.fill( 0, 0, 16 );
        key.fill( 0xab, 16, 32 );
        crypto_onetimeauth_poly1305( out, msg, 64, key );
        check_bytes( out, key.subarray( 16, 32 ), 'poly1305 r = 0 gives tag = s' );

        // random keys and lengths
        for ( let i = 0; i < 200; i++ )
        {
            const k = new Uint8Array( 32 ), m = new Uint8Array( test_random_int( 300 ) );
            test_random_bytes( k );
            test_random_bytes( m );
            if ( i % 4 === 0 ) m.fill( 0xff );
            crypto_onetimeauth_poly1305( out, m, m.length, k );
            check_bytes( out, poly1305_reference( m, k ), 'poly1305 random case ' + i );
        }
    }

    // streaming: any split of the input gives the one-shot tag
    {
        const key = new Uint8Array( 32 ), msg = new Uint8Array( 100 );
        test_random_bytes( key );
        test_random_bytes( msg );
        const expected = new Uint8Array( 16 );
        crypto_onetimeauth_poly1305( expected, msg, msg.length, key );
        const state = new crypto_onetimeauth_poly1305_state();
        for ( let a = 0; a <= 40; a++ )
        {
            for ( const b of [ a, a + 1, a + 15, a + 16, a + 17, 100 ] )
            {
                if ( b > 100 ) continue;
                crypto_onetimeauth_poly1305_init( state, key );
                crypto_onetimeauth_poly1305_update( state, msg, a );
                crypto_onetimeauth_poly1305_update( state, msg.subarray( a ), b - a );
                crypto_onetimeauth_poly1305_update( state, msg.subarray( b ), 100 - b );
                crypto_onetimeauth_poly1305_final( state, out );
                check_bytes( out, expected, 'poly1305 streaming split ' + a + '/' + b );
            }
        }
        check( state.h.every( ( x ) => x === 0 ) && state.r.every( ( x ) => x === 0 ) && state.pad.every( ( x ) => x === 0 ), 'poly1305 state zeroed after final' );
    }
}

function test_aead_rfc(): void
{
    const key = hex( '808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f' );
    const ad = hex( '50515253c0c1c2c3c4c5c6c7' );
    const plaintext = ascii( rfc8439_sunscreen );
    const c = new Uint8Array( plaintext.length + 16 );
    const m = new Uint8Array( plaintext.length );
    const len: sodium_length_out = { value: 0 };

    // RFC 8439 2.8.2
    {
        const nonce = hex( '070000004041424344454647' );
        const expected = hex(
            'd31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6' +
            '3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36' +
            '92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc' +
            '3ff4def08e4b7a9de576d26586cec64b6116' +
            '1ae10b594f09e26a7e902ecbd0600691' );
        check( crypto_aead_chacha20poly1305_ietf_encrypt( c, len, plaintext, plaintext.length, ad, ad.length, null, nonce, key ) === 0, 'RFC 8439 2.8.2 encrypt returns 0' );
        check( len.value === plaintext.length + 16, 'RFC 8439 2.8.2 clen' );
        check_bytes( c, expected, 'RFC 8439 2.8.2 aead' );
        check( crypto_aead_chacha20poly1305_ietf_decrypt( m, len, null, c, c.length, ad, ad.length, nonce, key ) === 0, 'RFC 8439 2.8.2 decrypt' );
        check( len.value === plaintext.length, 'RFC 8439 2.8.2 mlen' );
        check_bytes( m, plaintext, 'RFC 8439 2.8.2 plaintext' );

        const cd = new Uint8Array( plaintext.length ), mac = new Uint8Array( 16 );
        const maclen: sodium_length_out = { value: 0 };
        crypto_aead_chacha20poly1305_ietf_encrypt_detached( cd, mac, maclen, plaintext, plaintext.length, ad, ad.length, null, nonce, key );
        check( maclen.value === 16, 'detached maclen' );
        check_bytes( cd, expected.subarray( 0, plaintext.length ), 'RFC 8439 2.8.2 detached ciphertext' );
        check_bytes( mac, expected.subarray( plaintext.length ), 'RFC 8439 2.8.2 detached tag' );
        const md = new Uint8Array( plaintext.length );
        check( crypto_aead_chacha20poly1305_ietf_decrypt_detached( md, null, cd, cd.length, mac, ad, ad.length, nonce, key ) === 0, 'RFC 8439 2.8.2 decrypt detached' );
        check_bytes( md, plaintext, 'RFC 8439 2.8.2 detached plaintext' );
        check( crypto_aead_chacha20poly1305_ietf_decrypt_detached( null, null, cd, cd.length, mac, ad, ad.length, nonce, key ) === 0, 'verify-only decrypt accepts' );
        mac[0] ^= 1;
        check( crypto_aead_chacha20poly1305_ietf_decrypt_detached( null, null, cd, cd.length, mac, ad, ad.length, nonce, key ) === -1, 'verify-only decrypt rejects' );
        check( crypto_aead_chacha20poly1305_ietf_decrypt_detached( md, null, cd, cd.length, mac, ad, ad.length, nonce, key ) === -1, 'detached decrypt rejects' );
        check( md.every( ( x ) => x === 0 ), 'rejected detached decrypt zeroes m' );
    }

    // draft-irtf-cfrg-xchacha-03 A.3.1
    {
        const nonce = hex( '404142434445464748494a4b4c4d4e4f5051525354555657' );
        const expected = hex(
            'bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb' +
            '731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452' +
            '2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9' +
            '21f9664c97637da9768812f615c68b13b52e' +
            'c0875924c1c7987947deafd8780acf49' );
        check( crypto_aead_xchacha20poly1305_ietf_encrypt( c, len, plaintext, plaintext.length, ad, ad.length, null, nonce, key ) === 0, 'xchacha encrypt returns 0' );
        check( len.value === plaintext.length + 16, 'xchacha clen' );
        check_bytes( c, expected, 'draft-irtf-cfrg-xchacha A.3.1 aead' );
        m.fill( 0 );
        check( crypto_aead_xchacha20poly1305_ietf_decrypt( m, len, null, c, c.length, ad, ad.length, nonce, key ) === 0, 'xchacha decrypt' );
        check( len.value === plaintext.length, 'xchacha mlen' );
        check_bytes( m, plaintext, 'xchacha plaintext' );

        const cd = new Uint8Array( plaintext.length ), mac = new Uint8Array( 16 );
        crypto_aead_xchacha20poly1305_ietf_encrypt_detached( cd, mac, null, plaintext, plaintext.length, ad, ad.length, null, nonce, key );
        check_bytes( cd, expected.subarray( 0, plaintext.length ), 'xchacha detached ciphertext' );
        check_bytes( mac, expected.subarray( plaintext.length ), 'xchacha detached tag' );
        const md = new Uint8Array( plaintext.length );
        check( crypto_aead_xchacha20poly1305_ietf_decrypt_detached( md, null, cd, cd.length, mac, ad, ad.length, nonce, key ) === 0, 'xchacha decrypt detached' );
        check_bytes( md, plaintext, 'xchacha detached plaintext' );
        cd[5] ^= 0x10;
        check( crypto_aead_xchacha20poly1305_ietf_decrypt_detached( md, null, cd, cd.length, mac, ad, ad.length, nonce, key ) === -1, 'xchacha detached decrypt rejects' );
        check( md.every( ( x ) => x === 0 ), 'rejected xchacha detached decrypt zeroes m' );
    }
}

// cpp/netcode/netcode.c test_crypto_aead_vectors
function test_crypto_aead_vectors(): void
{
    const kat_key = hex( '404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f' );
    const kat_ad = hex( 'c0c1c2c3c4c5c6c7c8c9cacb' );
    const kat_msg = hex(
        '796f6a696d626f2076656e646f726564206c6962736f6469756d2041454144206b6e6f776e2d616e73776572207465737420766563746f722121' );
    const kat_npub_ietf = hex( 'a0a1a2a3a4a5a6a7a8a9aaab' );
    const kat_ct_ietf = hex(
        'd5aeb185158b07b30115f059b44e9d459158abffafbd814fbf52c24ca15e605f586331' +
        '96da900763b90c2146f2e465967a817fa25dd179f69b185de0b65793be8cb5a97598a46fd5be9d' );
    const kat_npub_xchacha = hex( '101112131415161718191a1b1c1d1e1f2021222324252627' );
    const kat_ct_xchacha = hex(
        '2b24832a6c9e21022a1432564b2737922440a992d353a7a564d38e0c7579753fca82fa' +
        '85f0a6ac089a25f18f4220708e3825d10845817518e4d188bd92fa84dcd6a39a67529162f4867b' );

    check( kat_msg.length === 58 && kat_ct_ietf.length === 74 && kat_ct_xchacha.length === 74, 'kat sizes' );

    const c = new Uint8Array( 128 );
    const m = new Uint8Array( 128 );
    const clen: sodium_length_out = { value: 0 };
    const mlen: sodium_length_out = { value: 0 };

    // ChaCha20-Poly1305 (IETF) -- the construction netcode uses on the wire

    check( crypto_aead_chacha20poly1305_ietf_encrypt( c, clen, kat_msg, kat_msg.length, kat_ad, kat_ad.length, null, kat_npub_ietf, kat_key ) === 0, 'kat ietf encrypt' );
    check( clen.value === kat_ct_ietf.length, 'kat ietf clen' );
    check_bytes( c.subarray( 0, clen.value ), kat_ct_ietf, 'kat ietf ciphertext' );
    check( crypto_aead_chacha20poly1305_ietf_decrypt( m, mlen, null, c, clen.value, kat_ad, kat_ad.length, kat_npub_ietf, kat_key ) === 0, 'kat ietf decrypt' );
    check( mlen.value === kat_msg.length, 'kat ietf mlen' );
    check_bytes( m.subarray( 0, mlen.value ), kat_msg, 'kat ietf plaintext' );

    // a tampered tag must be rejected

    c[0] ^= 0x01;
    check( crypto_aead_chacha20poly1305_ietf_decrypt( m, mlen, null, c, clen.value, kat_ad, kat_ad.length, kat_npub_ietf, kat_key ) !== 0, 'kat ietf tamper rejected' );
    check( mlen.value === 0, 'kat ietf tamper mlen' );

    // XChaCha20-Poly1305

    check( crypto_aead_xchacha20poly1305_ietf_encrypt( c, clen, kat_msg, kat_msg.length, kat_ad, kat_ad.length, null, kat_npub_xchacha, kat_key ) === 0, 'kat xchacha encrypt' );
    check( clen.value === kat_ct_xchacha.length, 'kat xchacha clen' );
    check_bytes( c.subarray( 0, clen.value ), kat_ct_xchacha, 'kat xchacha ciphertext' );
    check( crypto_aead_xchacha20poly1305_ietf_decrypt( m, mlen, null, c, clen.value, kat_ad, kat_ad.length, kat_npub_xchacha, kat_key ) === 0, 'kat xchacha decrypt' );
    check( mlen.value === kat_msg.length, 'kat xchacha mlen' );
    check_bytes( m.subarray( 0, mlen.value ), kat_msg, 'kat xchacha plaintext' );
    c[0] ^= 0x01;
    check( crypto_aead_xchacha20poly1305_ietf_decrypt( m, mlen, null, c, clen.value, kat_ad, kat_ad.length, kat_npub_xchacha, kat_key ) !== 0, 'kat xchacha tamper rejected' );

    // the constant-time comparison that checks the Poly1305 tag

    const a = new Uint8Array( 64 ), b = new Uint8Array( 64 );
    for ( let i = 0; i < 64; i++ ) { a[i] = i; b[i] = i; }
    check( crypto_verify_16( a, b ) === 0, 'verify_16 equal' );
    check( crypto_verify_32( a, b ) === 0, 'verify_32 equal' );
    check( crypto_verify_64( a, b ) === 0, 'verify_64 equal' );
    for ( let i = 0; i < 8; i++ )
    {
        b[0] = a[0] ^ ( 1 << i );
        check( crypto_verify_16( a, b ) === -1, 'verify_16 bit ' + i );
        check( crypto_verify_32( a, b ) === -1, 'verify_32 bit ' + i );
        check( crypto_verify_64( a, b ) === -1, 'verify_64 bit ' + i );
    }
    b[0] = a[0];
    b[63] = a[63] ^ 0x80;
    check( crypto_verify_64( a, b ) === -1, 'verify_64 last byte' );
    check( crypto_verify_16( a, b ) === 0 && crypto_verify_32( a, b ) === 0, 'verify_16/32 ignore bytes past n' );
    b[15] = a[15] ^ 0xff;
    check( crypto_verify_16( a, b ) === -1, 'verify_16 byte 15' );
}

// in-place (aliased) round trips across lengths 0..300, both AEADs: same output as separate buffers,
// tag as defined, decrypt in place, and every kind of tampering rejected with the plaintext wiped
function test_aead_round_trips(): void
{
    const key = new Uint8Array( 32 ), npub = new Uint8Array( 24 );
    const len: sodium_length_out = { value: 0 };

    for ( let big = 0; big < 2; big++ )
    {
        const encrypt = big ? crypto_aead_xchacha20poly1305_ietf_encrypt : crypto_aead_chacha20poly1305_ietf_encrypt;
        const decrypt = big ? crypto_aead_xchacha20poly1305_ietf_decrypt : crypto_aead_chacha20poly1305_ietf_decrypt;
        const nonce = big ? npub : npub.subarray( 0, 12 );
        const name = big ? 'xchacha' : 'ietf';

        for ( let mlen = 0; mlen <= 300; mlen++ )
        {
            test_random_bytes( key );
            test_random_bytes( npub );
            const adlen = mlen % 3 === 0 ? 0 : test_random_int( 40 );
            const ad = new Uint8Array( adlen );
            test_random_bytes( ad );
            const adp = adlen === 0 && mlen % 2 === 0 ? null : ad;

            const msg = new Uint8Array( mlen );
            test_random_bytes( msg );

            // separate buffers
            const c = new Uint8Array( mlen + 16 );
            check( encrypt( c, len, msg, mlen, adp, adlen, null, nonce, key ) === 0 && len.value === mlen + 16, name + ' encrypt ' + mlen );
            check_bytes( c.subarray( mlen ), aead_tag_reference( big === 1, c.subarray( 0, mlen ), ad, nonce, key ), name + ' tag definition ' + mlen );

            // in place, at an offset inside a larger buffer as netcode does with packet buffers
            const packet = new Uint8Array( mlen + 16 + 8 );
            packet.fill( 0xee );
            const view = packet.subarray( 3, 3 + mlen + 16 );
            view.set( msg );
            check( encrypt( view, len, view, mlen, adp, adlen, null, nonce, key ) === 0 && len.value === mlen + 16, name + ' encrypt in place ' + mlen );
            check_bytes( view, c, name + ' in place ciphertext ' + mlen );
            check( packet[0] === 0xee && packet[1] === 0xee && packet[2] === 0xee && packet[packet.length - 5] === 0xee, name + ' in place stays in bounds ' + mlen );

            check( decrypt( view, len, null, view, mlen + 16, adp, adlen, nonce, key ) === 0 && len.value === mlen, name + ' decrypt in place ' + mlen );
            check_bytes( view.subarray( 0, mlen ), msg, name + ' in place plaintext ' + mlen );

            // tamper: flip a bit in the ciphertext/tag, the ad, the nonce or the key
            const tamper = ( what: string, fn: ( cc: Uint8Array, aa: Uint8Array, nn: Uint8Array, kk: Uint8Array ) => void ) =>
            {
                const cc = c.slice(), aa = ad.slice(), nn = nonce.slice(), kk = key.slice();
                fn( cc, aa, nn, kk );
                len.value = 12345;
                check( decrypt( cc, len, null, cc, mlen + 16, aa, adlen, nn, kk ) === -1, name + ' tamper ' + what + ' rejected ' + mlen );
                check( len.value === 0, name + ' tamper ' + what + ' mlen 0 ' + mlen );
                for ( let i = 0; i < mlen; i++ )
                    check( cc[i] === 0, name + ' tamper ' + what + ' leaves no plaintext ' + mlen );
            };
            const bit = 1 << ( mlen & 7 );
            tamper( 'ciphertext/tag', ( cc ) => { cc[test_random_int( mlen + 16 )] ^= bit; } );
            tamper( 'tag', ( cc ) => { cc[mlen + 15] ^= 0x80; } );
            if ( adlen > 0 )
                tamper( 'ad', ( _cc, aa ) => { aa[test_random_int( adlen )] ^= bit; } );
            tamper( 'nonce', ( _cc, _aa, nn ) => { nn[test_random_int( nn.length )] ^= bit; } );
            tamper( 'key', ( _cc, _aa, _nn, kk ) => { kk[test_random_int( 32 )] ^= bit; } );
        }

        // ciphertext shorter than the tag
        const short = new Uint8Array( 15 );
        len.value = 7;
        check( decrypt( short, len, null, short, 15, null, 0, nonce, key ) === -1 && len.value === 0, name + ' short ciphertext' );
        check( decrypt( null, null, null, short, 0, null, 0, nonce, key ) === -1, name + ' empty ciphertext' );
    }
}

function test_utils(): void
{
    const b = new Uint8Array( 70000 + 16 );
    randombytes_buf( b, 70000 );
    let nonzero = 0;
    for ( let i = 65536; i < 70000; i++ )
        nonzero += b[i] !== 0 ? 1 : 0;
    check( nonzero > 4000, 'randombytes_buf fills past the 65536-byte chunk' );
    check( b.subarray( 70000 ).every( ( x ) => x === 0 ), 'randombytes_buf respects size' );

    sodium_memzero( b, 100 );
    check( b.subarray( 0, 100 ).every( ( x ) => x === 0 ), 'sodium_memzero zeroes len bytes' );
    sodium_memzero( b );
    check( b.every( ( x ) => x === 0 ), 'sodium_memzero zeroes the buffer' );

    const k = new Uint8Array( 32 );
    crypto_aead_chacha20poly1305_ietf_keygen( k );
    check( !k.every( ( x ) => x === 0 ), 'keygen' );

    check( sodium_init() >= 0, 'sodium_init' );
    check( sodium_init() === 1, 'sodium_init twice' );
}

export function sodium_test(): void
{
    test_chacha20();
    test_hchacha20();
    test_poly1305();
    test_aead_rfc();
    test_crypto_aead_vectors();
    test_aead_round_trips();
    test_utils();
}
