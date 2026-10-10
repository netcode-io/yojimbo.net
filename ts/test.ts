/*
    Yojimbo Unit Tests.

    Copyright © 2016 - 2026, Más Bandwidth LLC.

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

/*
    Yojimbo Unit Tests.

    TypeScript port of test.cpp (yojimbo 1.13.5). Runs the serialize, netcode and reliable suites, then the yojimbo
    tests, and prints "*** ALL TESTS PASS ***". Any failure exits with a non-zero code.

        node test.ts [seed]

    The tests are randomized (packet loss, ordering). The seed is printed first; pass it back to reproduce a run.
*/

import {
    serialize_test, WriteStream, BaseStream, serialize_int, serialize_bool, serialize_bits, serialize_bytes,
    InitializeYojimbo, ShutdownYojimbo, GetDefaultAllocator,
    Allocator, DefaultAllocator, TLSF_Allocator, ALLOCATOR_ERROR_NONE, ALLOCATOR_ERROR_OUT_OF_MEMORY,
    YOJIMBO_ALLOCATE, YOJIMBO_FREE,
    Queue, BitArray, SequenceBuffer,
    Address, ADDRESS_IPV4, ADDRESS_IPV6, MaxChannels,
    NetworkSimulator,
    ConnectionConfig, ChannelConfig, ClientServerConfig, CHANNEL_TYPE_RELIABLE_ORDERED, CHANNEL_TYPE_UNRELIABLE_UNORDERED,
    Connection, CONNECTION_ERROR_NONE, CONNECTION_ERROR_CHANNEL, CONNECTION_ERROR_READ_PACKET_FAILED,
    CHANNEL_ERROR_MESSAGE_TOO_LARGE, CHANNEL_ERROR_OUT_OF_MEMORY,
    Message, MessageFactory, MESSAGE_FACTORY_ERROR_FAILED_TO_ALLOCATE_MESSAGE,
    yojimbo_srand, yojimbo_rand, yojimbo_random_int,
    yojimbo_set_assert_function, yojimbo_get_assert_function, yojimbo_set_asserts_enabled,
    yojimbo_sequence_greater_than, yojimbo_sequence_less_than, yojimbo_sleep, yojimbo_random_bytes,
    Client, Server, NetworkInfo, KeyBytes, MaxClients, ConnectTokenBytes, InsecureConnectTokenExpirySeconds,
    YOJIMBO_CLIENT_DISCONNECT_REASON_NONE, YOJIMBO_CLIENT_DISCONNECT_REASON_DISCONNECTED, YOJIMBO_CLIENT_DISCONNECT_REASON_DISCONNECTED_BY_SERVER,
    YOJIMBO_CLIENT_DISCONNECT_REASON_CONNECTION_REQUEST_TIMED_OUT, YOJIMBO_CLIENT_DISCONNECT_REASON_FAILED_TO_SERIALIZE, YOJIMBO_CLIENT_DISCONNECT_REASON_OUT_OF_MEMORY,
    YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_NONE, YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_DISCONNECTED, YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_TIMED_OUT,
    YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_KICKED, YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_FAILED_TO_SERIALIZE,
    type ServerInterface, type ClientInterface,
} from './source/yojimbo.ts';
import { netcode_generate_connect_token, NETCODE_OK } from './netcode/netcode.ts';
import { reliable_test } from './reliable/reliable.ts';
import {
    crypto_aead_chacha20poly1305_ietf_encrypt, crypto_aead_chacha20poly1305_ietf_decrypt,
    crypto_aead_xchacha20poly1305_ietf_encrypt, crypto_aead_xchacha20poly1305_ietf_decrypt,
} from './sodium/sodium.ts';
import {
    TestMessage, TestBlockMessage, TestMessageFactory, SingleTestMessageFactory, SingleBlockTestMessageFactory,
    TEST_MESSAGE, TEST_BLOCK_MESSAGE, SINGLE_TEST_MESSAGE, SINGLE_BLOCK_TEST_MESSAGE,
    TEST_SERIALIZE_FAIL_ON_READ_MESSAGE, TEST_EXHAUST_STREAM_ALLOCATOR_ON_READ_MESSAGE, TestAdapter, adapter, ServerPort, ClientPort,
} from './shared.ts';

// ---------------------------------------------------------------------------------------------

function CheckHandler( condition: string, location: string ): never
{
    console.log( `check failed: ( ${condition} ), ${location}` );
    process.exit( 1 );
}

/** Upstream's check(): on failure prints the condition and where, then exits with code 1. */

export function check( condition: unknown, text: string = "condition" ): asserts condition
{
    if ( !condition )
    {
        const stack = ( new Error().stack ?? "" ).split( "\n" );
        CheckHandler( text, ( stack[2] ?? "" ).trim() );
    }
}

/**
    Allocator used by the allocation-failure tests. Tracks the number of outstanding blocks so leaks are observable,
    and can be "armed" to start returning null after a given number of successful allocations (to force a failure at
    a specific point).
 */

export class ArmableAllocator extends Allocator
{
    private m_allocsUntilFail = -1;
    private m_outstanding = 0;

    Arm( allocsUntilFail: number ): void { this.m_allocsUntilFail = allocsUntilFail; }
    Disarm(): void { this.m_allocsUntilFail = -1; }
    GetOutstanding(): number { return this.m_outstanding; }

    Allocate( size: number, file: string = "", line: number = 0 ): Uint8Array | null
    {
        if ( this.m_allocsUntilFail === 0 )
        {
            this.SetErrorLevel( ALLOCATOR_ERROR_OUT_OF_MEMORY );
            return null;
        }
        if ( this.m_allocsUntilFail > 0 )
            this.m_allocsUntilFail--;
        const p = new Uint8Array( size );
        this.m_outstanding++;
        this.TrackAlloc( p, size, file, line );
        return p;
    }

    Free( p: Uint8Array | null, file: string = "", line: number = 0 ): void
    {
        if ( !p )
            return;
        this.m_outstanding--;
        this.TrackFree( p, file, line );
    }
}

// ---------------------------------------------------------------------------------------------

function test_crypto_aead_vectors(): void
{
    // Known-answer test for the two AEAD primitives netcode relies on. Expected ciphertext was
    // generated from libsodium 1.0.20 reference output.
    const kat_key = new Uint8Array( [
        0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,0x49,0x4a,0x4b,
        0x4c,0x4d,0x4e,0x4f,0x50,0x51,0x52,0x53,0x54,0x55,0x56,0x57,
        0x58,0x59,0x5a,0x5b,0x5c,0x5d,0x5e,0x5f ] );
    const kat_ad = new Uint8Array( [ 0xc0,0xc1,0xc2,0xc3,0xc4,0xc5,0xc6,0xc7,0xc8,0xc9,0xca,0xcb ] );
    const kat_msg = new Uint8Array( [
        0x79,0x6f,0x6a,0x69,0x6d,0x62,0x6f,0x20,0x76,0x65,0x6e,0x64,0x6f,0x72,0x65,0x64,0x20,0x6c,0x69,0x62,
        0x73,0x6f,0x64,0x69,0x75,0x6d,0x20,0x41,0x45,0x41,0x44,0x20,0x6b,0x6e,0x6f,0x77,0x6e,0x2d,0x61,0x6e,
        0x73,0x77,0x65,0x72,0x20,0x74,0x65,0x73,0x74,0x20,0x76,0x65,0x63,0x74,0x6f,0x72,0x21,0x21 ] );
    const kat_npub_ietf = new Uint8Array( [ 0xa0,0xa1,0xa2,0xa3,0xa4,0xa5,0xa6,0xa7,0xa8,0xa9,0xaa,0xab ] );
    const kat_ct_ietf = new Uint8Array( [
        0xd5,0xae,0xb1,0x85,0x15,0x8b,0x07,0xb3,0x01,0x15,0xf0,0x59,
        0xb4,0x4e,0x9d,0x45,0x91,0x58,0xab,0xff,0xaf,0xbd,0x81,0x4f,
        0xbf,0x52,0xc2,0x4c,0xa1,0x5e,0x60,0x5f,0x58,0x63,0x31,0x96,
        0xda,0x90,0x07,0x63,0xb9,0x0c,0x21,0x46,0xf2,0xe4,0x65,0x96,
        0x7a,0x81,0x7f,0xa2,0x5d,0xd1,0x79,0xf6,0x9b,0x18,0x5d,0xe0,
        0xb6,0x57,0x93,0xbe,0x8c,0xb5,0xa9,0x75,0x98,0xa4,0x6f,0xd5,
        0xbe,0x9d ] );
    const kat_npub_xchacha = new Uint8Array( [
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,
        0x1c,0x1d,0x1e,0x1f,0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27 ] );
    const kat_ct_xchacha = new Uint8Array( [
        0x2b,0x24,0x83,0x2a,0x6c,0x9e,0x21,0x02,0x2a,0x14,0x32,0x56,
        0x4b,0x27,0x37,0x92,0x24,0x40,0xa9,0x92,0xd3,0x53,0xa7,0xa5,
        0x64,0xd3,0x8e,0x0c,0x75,0x79,0x75,0x3f,0xca,0x82,0xfa,0x85,
        0xf0,0xa6,0xac,0x08,0x9a,0x25,0xf1,0x8f,0x42,0x20,0x70,0x8e,
        0x38,0x25,0xd1,0x08,0x45,0x81,0x75,0x18,0xe4,0xd1,0x88,0xbd,
        0x92,0xfa,0x84,0xdc,0xd6,0xa3,0x9a,0x67,0x52,0x91,0x62,0xf4,
        0x86,0x7b ] );

    const c = new Uint8Array( 128 );
    const m = new Uint8Array( 128 );
    const clen = { value: 0 };
    const mlen = { value: 0 };

    const equal = ( a: Uint8Array, b: Uint8Array, n: number ): boolean => { for ( let i = 0; i < n; ++i ) if ( a[i] !== b[i] ) return false; return true; };

    // ChaCha20-Poly1305 (IETF)
    check( crypto_aead_chacha20poly1305_ietf_encrypt( c, clen, kat_msg, kat_msg.length, kat_ad, kat_ad.length, null, kat_npub_ietf, kat_key ) === 0 );
    check( clen.value === kat_ct_ietf.length );
    check( equal( c, kat_ct_ietf, clen.value ) );
    check( crypto_aead_chacha20poly1305_ietf_decrypt( m, mlen, null, c, clen.value, kat_ad, kat_ad.length, kat_npub_ietf, kat_key ) === 0 );
    check( mlen.value === kat_msg.length );
    check( equal( m, kat_msg, mlen.value ) );
    c[0] ^= 0x01;
    check( crypto_aead_chacha20poly1305_ietf_decrypt( m, mlen, null, c, clen.value, kat_ad, kat_ad.length, kat_npub_ietf, kat_key ) !== 0 );

    // XChaCha20-Poly1305
    check( crypto_aead_xchacha20poly1305_ietf_encrypt( c, clen, kat_msg, kat_msg.length, kat_ad, kat_ad.length, null, kat_npub_xchacha, kat_key ) === 0 );
    check( clen.value === kat_ct_xchacha.length );
    check( equal( c, kat_ct_xchacha, clen.value ) );
    check( crypto_aead_xchacha20poly1305_ietf_decrypt( m, mlen, null, c, clen.value, kat_ad, kat_ad.length, kat_npub_xchacha, kat_key ) === 0 );
    check( mlen.value === kat_msg.length );
    check( equal( m, kat_msg, mlen.value ) );
    c[0] ^= 0x01;
    check( crypto_aead_xchacha20poly1305_ietf_decrypt( m, mlen, null, c, clen.value, kat_ad, kat_ad.length, kat_npub_xchacha, kat_key ) !== 0 );
}

function test_queue(): void
{
    const QueueSize = 1024;

    const queue = new Queue<number>( GetDefaultAllocator(), QueueSize );

    check( queue.IsEmpty() );
    check( !queue.IsFull() );
    check( queue.GetNumEntries() === 0 );
    check( queue.GetSize() === QueueSize );

    const NumEntries = 100;

    for ( let i = 0; i < NumEntries; ++i )
        queue.Push( i );

    check( !queue.IsEmpty() );
    check( !queue.IsFull() );
    check( queue.GetNumEntries() === NumEntries );
    check( queue.GetSize() === QueueSize );

    for ( let i = 0; i < NumEntries; ++i )
        check( queue.Get( i ) === i );

    for ( let i = 0; i < NumEntries; ++i )
        check( queue.Pop() === i );

    check( queue.IsEmpty() );
    check( !queue.IsFull() );
    check( queue.GetNumEntries() === 0 );
    check( queue.GetSize() === QueueSize );

    for ( let i = 0; i < QueueSize; ++i )
        queue.Push( i );

    check( !queue.IsEmpty() );
    check( queue.IsFull() );
    check( queue.GetNumEntries() === QueueSize );
    check( queue.GetSize() === QueueSize );

    queue.Clear();

    check( queue.IsEmpty() );
    check( !queue.IsFull() );
    check( queue.GetNumEntries() === 0 );
    check( queue.GetSize() === QueueSize );

    queue.Dispose();
}

function parse_address( string: string ): boolean
{
    const address = new Address( string );
    return address.IsValid();
}

function test_address_classification(): void
{
    // multicast is ff00::/8 -- the whole range, not just the group ff00

    check( new Address( "ff00::1" ).IsMulticast() );
    check( new Address( "ff02::1" ).IsMulticast() );
    check( new Address( "ff05::1:3" ).IsMulticast() );
    check( new Address( "ffff::1" ).IsMulticast() );
    check( !new Address( "ff02::1" ).IsGlobalUnicast() );
    check( !new Address( "ff05::1:3" ).IsGlobalUnicast() );

    // link local is fe80::/10, so fe80 through febf

    check( new Address( "fe80::1" ).IsLinkLocal() );
    check( new Address( "febf::1" ).IsLinkLocal() );
    check( !new Address( "febf::1" ).IsGlobalUnicast() );
    check( !new Address( "fec0::1" ).IsLinkLocal() );

    // site local is fec0::/10, so fec0 through feff

    check( new Address( "fec0::1" ).IsSiteLocal() );
    check( new Address( "feff::1" ).IsSiteLocal() );
    check( !new Address( "fe80::1" ).IsSiteLocal() );

    // and the boundaries below the ranges must NOT be classified

    check( !new Address( "fe7f::1" ).IsLinkLocal() );
    check( !new Address( "fe7f::1" ).IsSiteLocal() );
    check( new Address( "fe7f::1" ).IsGlobalUnicast() );
    check( !new Address( "feff::1" ).IsGlobalUnicast() );

    // genuine global unicast still classifies, so the fix cannot pass by returning false

    check( new Address( "2001:4860:4860::8888" ).IsGlobalUnicast() );
    check( !new Address( "2001:4860:4860::8888" ).IsMulticast() );
    check( !new Address( "2001:4860:4860::8888" ).IsLoopback() );

    // loopback is unchanged, and is excluded from global unicast

    check( new Address( "::1" ).IsLoopback() );
    check( !new Address( "::1" ).IsGlobalUnicast() );
    check( new Address( "127.0.0.1" ).IsLoopback() );

    // IPv4 is never any of the IPv6 classifications

    check( !new Address( "127.0.0.1" ).IsMulticast() );
    check( !new Address( "10.0.0.1" ).IsGlobalUnicast() );
    check( !new Address( "224.0.0.1" ).IsMulticast() );
}

function test_address_malformed_port(): void
{
    // trailing junk after the digits
    check( parse_address( "127.0.0.1:40k" ) === false );
    check( parse_address( "127.0.0.1:40 " ) === false );
    check( parse_address( "127.0.0.1:4.0" ) === false );
    check( parse_address( "[::1]:40k" ) === false );

    // no digits at all
    check( parse_address( "127.0.0.1:" ) === false );
    check( parse_address( "[::1]:" ) === false );

    // a sign or leading whitespace is not a port
    check( parse_address( "127.0.0.1:+40" ) === false );
    check( parse_address( "127.0.0.1:-1" ) === false );
    check( parse_address( "[::1]:+40" ) === false );
    check( parse_address( "[::1]: 40" ) === false );

    // out of range, including more digits than fit in the parser's own integer
    check( parse_address( "127.0.0.1:65536" ) === false );
    check( parse_address( "127.0.0.1:99999" ) === false );
    check( parse_address( "127.0.0.1:99999999999999999999999" ) === false );
    check( parse_address( "[::1]:65536" ) === false );
    check( parse_address( "[::1]:99999999999999999999999" ) === false );

    // bracket syntax is exact
    check( parse_address( "[::1" ) === false );
    check( parse_address( "[::1]junk" ) === false );
    check( parse_address( "[::1]]" ) === false );
    check( parse_address( "[::1]40000" ) === false );

    // ...and the forms that were always valid still are, with the port they say
    {
        const address = new Address( "127.0.0.1:65535" );
        check( address.IsValid() );
        check( address.GetPort() === 65535 );
    }
    {
        const address = new Address( "127.0.0.1:0" );
        check( address.IsValid() );
        check( address.GetPort() === 0 );
    }
    {
        const address = new Address( "[::1]:40000" );
        check( address.IsValid() );
        check( address.GetType() === ADDRESS_IPV6 );
        check( address.GetPort() === 40000 );
    }
    {
        const address = new Address( "[::1]" );
        check( address.IsValid() );
        check( address.GetType() === ADDRESS_IPV6 );
        check( address.GetPort() === 0 );
    }
}

function check_address6( address: Address, expected: number[] ): void
{
    for ( let i = 0; i < 8; ++i )
        check( address.GetAddress6()[i] === expected[i], `GetAddress6()[${i}] == ${expected[i]}` );
}

function test_address(): void
{
    check( parse_address( "" ) === false );
    check( parse_address( "[" ) === false );
    check( parse_address( "[]" ) === false );
    check( parse_address( "[]:" ) === false );
    check( parse_address( ":" ) === false );
    check( parse_address( "1" ) === false );
    check( parse_address( "12" ) === false );
    check( parse_address( "123" ) === false );
    check( parse_address( "1234" ) === false );
    check( parse_address( "1234.0.12313.0000" ) === false );
    check( parse_address( "1234.0.12313.0000.0.0.0.0.0" ) === false );
    check( parse_address( "1312313:123131:1312313:123131:1312313:123131:1312313:123131:1312313:123131:1312313:123131" ) === false );
    check( parse_address( "." ) === false );
    check( parse_address( ".." ) === false );
    check( parse_address( "..." ) === false );
    check( parse_address( "...." ) === false );
    check( parse_address( "....." ) === false );

    {
        const address = new Address( "107.77.207.77" );
        check( address.IsValid() );
        check( address.GetType() === ADDRESS_IPV4 );
        check( address.GetPort() === 0 );
        check( address.GetAddress4()[0] === 107 );
        check( address.GetAddress4()[1] === 77 );
        check( address.GetAddress4()[2] === 207 );
        check( address.GetAddress4()[3] === 77 );
        check( !address.IsLoopback() );
    }

    {
        const address = new Address( "127.0.0.1" );
        check( address.IsValid() );
        check( address.GetType() === ADDRESS_IPV4 );
        check( address.GetPort() === 0 );
        check( address.GetAddress4()[0] === 127 );
        check( address.GetAddress4()[1] === 0 );
        check( address.GetAddress4()[2] === 0 );
        check( address.GetAddress4()[3] === 1 );
        check( address.IsLoopback() );
    }

    {
        const address = new Address( "107.77.207.77:40000" );
        check( address.IsValid() );
        check( address.GetType() === ADDRESS_IPV4 );
        check( address.GetPort() === 40000 );
        check( address.GetAddress4()[0] === 107 );
        check( address.GetAddress4()[1] === 77 );
        check( address.GetAddress4()[2] === 207 );
        check( address.GetAddress4()[3] === 77 );
        check( !address.IsLoopback() );
    }

    {
        const address = new Address( "127.0.0.1:40000" );
        check( address.IsValid() );
        check( address.GetType() === ADDRESS_IPV4 );
        check( address.GetPort() === 40000 );
        check( address.GetAddress4()[0] === 127 );
        check( address.GetAddress4()[1] === 0 );
        check( address.GetAddress4()[2] === 0 );
        check( address.GetAddress4()[3] === 1 );
        check( address.IsLoopback() );
    }

    {
        const address = new Address( "fe80::202:b3ff:fe1e:8329" );
        check( address.IsValid() );
        check( address.GetType() === ADDRESS_IPV6 );
        check( address.GetPort() === 0 );
        check_address6( address, [ 0xfe80, 0, 0, 0, 0x0202, 0xb3ff, 0xfe1e, 0x8329 ] );
        check( !address.IsLoopback() );
    }

    {
        const address = new Address( "::" );
        check( address.IsValid() );
        check( address.GetType() === ADDRESS_IPV6 );
        check( address.GetPort() === 0 );
        check_address6( address, [ 0, 0, 0, 0, 0, 0, 0, 0 ] );
        check( !address.IsLoopback() );
    }

    {
        const address = new Address( "::1" );
        check( address.IsValid() );
        check( address.GetType() === ADDRESS_IPV6 );
        check( address.GetPort() === 0 );
        check_address6( address, [ 0, 0, 0, 0, 0, 0, 0, 1 ] );
        check( address.IsLoopback() );
    }

    {
        const address = new Address( "[fe80::202:b3ff:fe1e:8329]:40000" );
        check( address.IsValid() );
        check( address.GetType() === ADDRESS_IPV6 );
        check( address.GetPort() === 40000 );
        check_address6( address, [ 0xfe80, 0, 0, 0, 0x0202, 0xb3ff, 0xfe1e, 0x8329 ] );
        check( !address.IsLoopback() );
    }

    {
        const address = new Address( "[::]:40000" );
        check( address.IsValid() );
        check( address.GetType() === ADDRESS_IPV6 );
        check( address.GetPort() === 40000 );
        check_address6( address, [ 0, 0, 0, 0, 0, 0, 0, 0 ] );
        check( !address.IsLoopback() );
    }

    {
        const address = new Address( "[::1]:40000" );
        check( address.IsValid() );
        check( address.GetType() === ADDRESS_IPV6 );
        check( address.GetPort() === 40000 );
        check_address6( address, [ 0, 0, 0, 0, 0, 0, 0, 1 ] );
        check( address.IsLoopback() );
    }

    // Regression: bracketed IPv6 with no port.
    {
        const address = new Address( "[::1]" );
        check( address.IsValid() );
        check( address.GetType() === ADDRESS_IPV6 );
        check( address.GetPort() === 0 );
        check_address6( address, [ 0, 0, 0, 0, 0, 0, 0, 1 ] );
        check( address.IsLoopback() );
    }

    {
        const address = new Address( "[::]" );
        check( address.IsValid() );
        check( address.GetType() === ADDRESS_IPV6 );
        check( address.GetPort() === 0 );
        check_address6( address, [ 0, 0, 0, 0, 0, 0, 0, 0 ] );
        check( !address.IsLoopback() );
    }

    {
        const address = new Address( "[fe80::202:b3ff:fe1e:8329]" );
        check( address.IsValid() );
        check( address.GetType() === ADDRESS_IPV6 );
        check( address.GetPort() === 0 );
        check_address6( address, [ 0xfe80, 0, 0, 0, 0x0202, 0xb3ff, 0xfe1e, 0x8329 ] );
        check( !address.IsLoopback() );
    }

    {
        const address6 = [ 0xFE80, 0x0000, 0x0000, 0x0000, 0x0202, 0xB3FF, 0xFE1E, 0x8329 ];

        const address = new Address( address6[0], address6[1], address6[2], address6[2],
                                     address6[4], address6[5], address6[6], address6[7] );

        check( address.IsValid() );
        check( address.GetType() === ADDRESS_IPV6 );
        check( address.GetPort() === 0 );
        check_address6( address, address6 );
        check( address.ToString() === "fe80::202:b3ff:fe1e:8329" );
    }

    {
        const address6 = new Uint16Array( [ 0xFE80, 0x0000, 0x0000, 0x0000, 0x0202, 0xB3FF, 0xFE1E, 0x8329 ] );

        const address = new Address( address6 );

        check( address.IsValid() );
        check( address.GetType() === ADDRESS_IPV6 );
        check( address.GetPort() === 0 );
        check_address6( address, Array.from( address6 ) );
        check( address.ToString() === "fe80::202:b3ff:fe1e:8329" );
    }

    {
        const address6 = new Uint16Array( [ 0, 0, 0, 0, 0, 0, 0, 1 ] );

        const address = new Address( address6 );

        check( address.IsValid() );
        check( address.GetType() === ADDRESS_IPV6 );
        check( address.GetPort() === 0 );
        check_address6( address, Array.from( address6 ) );
        check( address.ToString() === "::1" );
    }

    {
        const address6 = [ 0xFE80, 0x0000, 0x0000, 0x0000, 0x0202, 0xB3FF, 0xFE1E, 0x8329 ];

        const address = new Address( address6[0], address6[1], address6[2], address6[2],
                                     address6[4], address6[5], address6[6], address6[7], 65535 );

        check( address.IsValid() );
        check( address.GetType() === ADDRESS_IPV6 );
        check( address.GetPort() === 65535 );
        check_address6( address, address6 );
        check( address.ToString() === "[fe80::202:b3ff:fe1e:8329]:65535" );
    }

    {
        const address6 = new Uint16Array( [ 0xFE80, 0x0000, 0x0000, 0x0000, 0x0202, 0xB3FF, 0xFE1E, 0x8329 ] );

        const address = new Address( address6, 65535 );

        check( address.IsValid() );
        check( address.GetType() === ADDRESS_IPV6 );
        check( address.GetPort() === 65535 );
        check_address6( address, Array.from( address6 ) );
        check( address.ToString() === "[fe80::202:b3ff:fe1e:8329]:65535" );
    }

    {
        const address6 = new Uint16Array( [ 0, 0, 0, 0, 0, 0, 0, 1 ] );

        const address = new Address( address6, 65535 );

        check( address.IsValid() );
        check( address.GetType() === ADDRESS_IPV6 );
        check( address.GetPort() === 65535 );
        check_address6( address, Array.from( address6 ) );
        check( address.ToString() === "[::1]:65535" );
    }

    {
        const address = new Address( "fe80::202:b3ff:fe1e:8329" );
        check( address.IsValid() );
        check( address.GetType() === ADDRESS_IPV6 );
        check( address.GetPort() === 0 );
        check( address.ToString() === "fe80::202:b3ff:fe1e:8329" );
    }

    {
        const address = new Address( "::1" );
        check( address.IsValid() );
        check( address.GetType() === ADDRESS_IPV6 );
        check( address.GetPort() === 0 );
        check( address.ToString() === "::1" );
    }

    {
        const address = new Address( "[fe80::202:b3ff:fe1e:8329]:65535" );
        check( address.IsValid() );
        check( address.GetType() === ADDRESS_IPV6 );
        check( address.GetPort() === 65535 );
        check( address.ToString() === "[fe80::202:b3ff:fe1e:8329]:65535" );
    }

    {
        const address = new Address( "[::1]:65535" );
        check( address.IsValid() );
        check( address.GetType() === ADDRESS_IPV6 );
        check( address.GetPort() === 65535 );
        check( address.ToString() === "[::1]:65535" );
    }

    // TypeScript extras: the IPv4 forms, the port override, equality, the libc inet_pton / inet_ntop corner cases

    {
        const address = new Address( 127, 0, 0, 1, 40000 );
        check( address.ToString() === "127.0.0.1:40000" );
        check( address.Equals( new Address( "127.0.0.1:40000" ) ) );
        check( address.NotEquals( new Address( "127.0.0.1:40001" ) ) );
        check( new Address( new Uint8Array( [ 10, 0, 0, 2 ] ), 7 ).ToString() === "10.0.0.2:7" );
        check( new Address( "127.0.0.1:5", 6 ).GetPort() === 6 );
        check( new Address().ToString() === "NONE" );
        check( !new Address().Equals( new Address() ) );
    }

    check( parse_address( "01.2.3.4" ) === false );             // inet_pton4 refuses leading zeros
    check( parse_address( "256.0.0.1" ) === false );
    check( parse_address( "1.2.3" ) === false );
    check( parse_address( "1::2::3" ) === false );               // a single "::" only
    check( parse_address( "12345::1" ) === false );              // at most four hex digits per group
    check( parse_address( "1:2:3:4:5:6:7:8:9" ) === false );
    check( parse_address( "1:2:3:4:5:6:7:" ) === false );
    check( parse_address( ":1:2:3:4:5:6:7" ) === false );
    check( new Address( "::ffff:1.2.3.4" ).ToString() === "::ffff:1.2.3.4" );
    check( new Address( "1:0:0:2:0:0:0:3" ).ToString() === "1:0:0:2::3" );
    check( new Address( "1:0:2:3:4:5:6:7" ).ToString() === "1:0:2:3:4:5:6:7" );
    check( new Address( "FE80::A" ).ToString() === "fe80::a" );
    check( new Address( "[1.2.3.4]:5" ).GetType() === ADDRESS_IPV4 );   // upstream falls through to the IPv4 parse
}

function test_network_simulator_drains_all_slots(): void
{
    // Regression: ReceivePackets used to scan only the first min(numEntries, maxPackets) ring slots.

    const NumEntries = 4;

    const sim = new NetworkSimulator( GetDefaultAllocator(), NumEntries, 0.0 );

    // Negative loss/duplicate rates make those RNG checks impossible to fire, so sends are fully deterministic.
    sim.SetPacketLoss( -1.0 );
    sim.SetDuplicates( -1.0 );

    const payload = new Uint8Array( 8 );
    for ( let i = 0; i < NumEntries; ++i )
    {
        payload.fill( i );
        sim.SendPacket( i, payload, payload.length );     // fills ring slots 0..NumEntries-1, "to" == slot
    }

    sim.AdvanceTime( 1.0 );     // past every delivery time (latency 0)

    const seen = new Array<boolean>( NumEntries ).fill( false );
    let totalReceived = 0;

    for ( let iter = 0; iter < NumEntries + 2; ++iter )
    {
        const packetData: Array<Uint8Array | null> = [ null, null ];
        const packetBytes = [ 0, 0 ];
        const to = [ 0, 0 ];
        const n = sim.ReceivePackets( 2, packetData, packetBytes, to );
        check( n <= 2 );
        for ( let i = 0; i < n; ++i )
        {
            check( to[i] >= 0 && to[i] < NumEntries );
            check( !seen[to[i]] );
            check( packetBytes[i] === payload.length );
            seen[to[i]] = true;
            totalReceived++;
            YOJIMBO_FREE( sim.GetAllocator(), packetData[i] );
        }
    }

    check( totalReceived === NumEntries );
    for ( let i = 0; i < NumEntries; ++i )
        check( seen[i] );

    sim.Dispose();
}

function test_network_simulator_overwrite_slot(): void
{
    // From the C# port: when the ring wraps onto an occupied slot, the new packet must replace the old one.

    const NumEntries = 2;

    const sim = new NetworkSimulator( GetDefaultAllocator(), NumEntries, 0.0 );
    sim.SetPacketLoss( -1.0 );
    sim.SetDuplicates( -1.0 );

    const payload = new Uint8Array( 4 );
    for ( let i = 0; i < NumEntries + 1; ++i )      // the third send wraps onto slot 0
    {
        payload.fill( i + 1 );
        sim.SendPacket( i, payload, payload.length );
    }

    sim.AdvanceTime( 1.0 );

    const packetData = new Array<Uint8Array | null>( NumEntries ).fill( null );
    const packetBytes = new Array<number>( NumEntries ).fill( 0 );
    const to = new Array<number>( NumEntries ).fill( 0 );
    const n = sim.ReceivePackets( NumEntries, packetData, packetBytes, to );
    check( n === NumEntries );
    let sawNewest = false;
    for ( let i = 0; i < n; ++i )
    {
        if ( to[i] === NumEntries && packetData[i]![0] === NumEntries + 1 )
            sawNewest = true;
        YOJIMBO_FREE( sim.GetAllocator(), packetData[i] );
    }
    check( sawNewest );

    sim.Dispose();
}

function test_bit_array(): void
{
    const Size = 300;

    const bit_array = new BitArray( GetDefaultAllocator(), Size );

    // verify initial conditions

    check( bit_array.GetSize() === Size );

    for ( let i = 0; i < Size; ++i )
        check( bit_array.GetBit( i ) === 0 );

    // set every third bit and verify correct bits are set on read

    for ( let i = 0; i < Size; ++i )
        if ( ( i % 3 ) === 0 )
            bit_array.SetBit( i );

    for ( let i = 0; i < Size; ++i )
        check( bit_array.GetBit( i ) === ( ( i % 3 ) === 0 ? 1 : 0 ) );

    // now clear every third bit to zero and verify all bits are zero

    for ( let i = 0; i < Size; ++i )
        if ( ( i % 3 ) === 0 )
            bit_array.ClearBit( i );

    for ( let i = 0; i < Size; ++i )
        check( bit_array.GetBit( i ) === 0 );

    // now set some more bits

    for ( let i = 0; i < Size; ++i )
        if ( ( i % 10 ) === 0 )
            bit_array.SetBit( i );

    for ( let i = 0; i < Size; ++i )
        check( bit_array.GetBit( i ) === ( ( i % 10 ) === 0 ? 1 : 0 ) );

    // clear and verify all bits are zero

    bit_array.Clear();

    for ( let i = 0; i < Size; ++i )
        check( bit_array.GetBit( i ) === 0 );

    bit_array.Dispose();
}

class TestSequenceData
{
    sequence = 0xFFFF;
}

function test_sequence_buffer(): void
{
    const Size = 256;

    const sequence_buffer = new SequenceBuffer<TestSequenceData>( GetDefaultAllocator(), Size, () => new TestSequenceData() );

    for ( let i = 0; i < Size; ++i )
        check( sequence_buffer.Find( i ) === null );

    for ( let i = 0; i <= Size * 4; ++i )
    {
        const entry = sequence_buffer.Insert( i );
        check( entry );
        entry.sequence = i;
        check( sequence_buffer.GetSequence() === i + 1 );
    }

    for ( let i = 0; i <= Size; ++i )
    {
        const entry = sequence_buffer.Insert( i );
        check( !entry );
    }

    let index = Size * 4;
    for ( let i = 0; i < Size; ++i )
    {
        const entry = sequence_buffer.Find( index );
        check( entry );
        check( entry.sequence === index );
        index--;
    }

    for ( let i = 0; i <= Size; ++i )
    {
        const entry = sequence_buffer.Insert( i, true );
        check( entry );
        entry.sequence = i;
        check( sequence_buffer.GetSequence() === i + 1 );
    }

    sequence_buffer.Reset();

    check( sequence_buffer.GetSequence() === 0 );

    for ( let i = 0; i < Size; ++i )
        check( sequence_buffer.Find( i ) === null );

    // TypeScript extra: the wrap helpers truncate to uint16 like the uint16_t parameters upstream
    check( yojimbo_sequence_greater_than( 0, 65535 ) );
    check( yojimbo_sequence_greater_than( 65536, 65535 ) );
    check( yojimbo_sequence_less_than( 65535, 0 ) );

    sequence_buffer.Dispose();
}

function test_allocator_tlsf(): void
{
    const NumBlocks = 256;
    const BlockSize = 1024;
    const MemorySize = NumBlocks * BlockSize;

    const memory = new Uint8Array( MemorySize );

    const allocator = new TLSF_Allocator( memory, MemorySize );

    const blockData = new Array<Uint8Array | null>( NumBlocks ).fill( null );

    let stopIndex = 0;

    for ( let i = 0; i < NumBlocks; ++i )
    {
        blockData[i] = YOJIMBO_ALLOCATE( allocator, BlockSize );

        if ( !blockData[i] )
        {
            check( allocator.GetErrorLevel() === ALLOCATOR_ERROR_OUT_OF_MEMORY );
            allocator.ClearError();
            check( allocator.GetErrorLevel() === ALLOCATOR_ERROR_NONE );
            stopIndex = i;
            break;
        }

        check( blockData[i] );
        check( allocator.GetErrorLevel() === ALLOCATOR_ERROR_NONE );

        blockData[i]!.fill( ( i + 10 ) & 0xFF );
    }

    check( stopIndex > NumBlocks / 2 );

    for ( let i = 0; i < NumBlocks - 1; ++i )
    {
        if ( blockData[i] )
        {
            for ( let j = 0; j < BlockSize; ++j )
                check( blockData[i]![j] === ( ( i + 10 ) & 0xFF ) );
        }

        blockData[i] = YOJIMBO_FREE( allocator, blockData[i] );
    }

    check( allocator.GetUsedBytes() === 0 );

    allocator.Dispose();
}

function test_allocator_leak_tracking(): void
{
    // TypeScript extra: the leak checker reports an unfreed block through the assert function, and freeing a block the
    // allocator does not own asserts.
    const allocator = new DefaultAllocator();
    const block = YOJIMBO_ALLOCATE( allocator, 16 );
    check( block );
    check( allocator.IsTracked( block ) );

    const previous = yojimbo_get_assert_function();
    const asserts = { count: 0 };
    yojimbo_set_assert_function( () => { asserts.count++; } );
    try
    {
        try { allocator.Dispose(); } catch { /* the assert throws */ }
        check( asserts.count === 1 );
        try { allocator.Free( new Uint8Array( 4 ) ); } catch { /* the assert throws */ }
        check( ( asserts.count as number ) === 2 );
    }
    finally
    {
        yojimbo_set_assert_function( previous );
    }
}

// ---------------------------------------------------------------------------------------------

class PumpState
{
    time = 100.0;
    senderSequence = 0;
    receiverSequence = 0;
}

const pumpPacketBytes = { packetBytes: 0 };

function PumpConnectionUpdate( connectionConfig: ConnectionConfig, state: PumpState, sender: Connection, receiver: Connection, deltaTime: number = Math.fround( 0.1 ), packetLossPercent: number = 90 ): void
{
    const packetData = new Uint8Array( connectionConfig.maxPacketSize );

    if ( sender.GeneratePacket( null, state.senderSequence, packetData, connectionConfig.maxPacketSize, pumpPacketBytes ) )
    {
        if ( yojimbo_random_int( 0, 100 ) >= packetLossPercent )
        {
            receiver.ProcessPacket( null, state.senderSequence, packetData, pumpPacketBytes.packetBytes );
            sender.ProcessAcks( [ state.senderSequence ], 1 );
        }
    }

    if ( receiver.GeneratePacket( null, state.receiverSequence, packetData, connectionConfig.maxPacketSize, pumpPacketBytes ) )
    {
        if ( yojimbo_random_int( 0, 100 ) >= packetLossPercent )
        {
            sender.ProcessPacket( null, state.receiverSequence, packetData, pumpPacketBytes.packetBytes );
            receiver.ProcessAcks( [ state.receiverSequence ], 1 );
        }
    }

    state.time += deltaTime;

    sender.AdvanceTime( state.time );
    receiver.AdvanceTime( state.time );

    state.senderSequence = ( state.senderSequence + 1 ) & 0xFFFF;
    state.receiverSequence = ( state.receiverSequence + 1 ) & 0xFFFF;
}

const ReliableChannel = 0;

function AttachTestBlock( messageFactory: MessageFactory, message: TestBlockMessage, blockSize: number, value: number ): void
{
    const blockData = YOJIMBO_ALLOCATE( messageFactory.GetAllocator(), blockSize );
    check( blockData );
    for ( let j = 0; j < blockSize; ++j )
        blockData[j] = ( value + j ) & 0xFF;
    message.AttachBlock( messageFactory.GetAllocator(), blockData, blockSize );
}

function CheckTestBlock( message: TestBlockMessage, blockSize: number, value: number ): void
{
    check( message.GetBlockSize() === blockSize );
    const blockData = message.GetBlockData();
    check( blockData );
    for ( let j = 0; j < blockSize; ++j )
        check( blockData[j] === ( ( value + j ) & 0xFF ) );
}

function test_connection_reliable_ordered_messages(): void
{
    const messageFactory = new TestMessageFactory( GetDefaultAllocator() );

    const state = new PumpState();

    const connectionConfig = new ConnectionConfig();

    const sender = new Connection( GetDefaultAllocator(), messageFactory, connectionConfig, state.time );
    const receiver = new Connection( GetDefaultAllocator(), messageFactory, connectionConfig, state.time );

    const NumMessagesSent = 64;

    for ( let i = 0; i < NumMessagesSent; ++i )
    {
        const message = messageFactory.CreateMessage( TEST_MESSAGE ) as TestMessage;
        check( message );
        message.sequence = i;
        sender.SendMessage( ReliableChannel, message );
    }

    let numMessagesReceived = 0;

    const NumIterations = 1000;

    for ( let i = 0; i < NumIterations; ++i )
    {
        PumpConnectionUpdate( connectionConfig, state, sender, receiver );

        while ( true )
        {
            const message = receiver.ReceiveMessage( ReliableChannel );
            if ( !message )
                break;

            check( message.GetId() === numMessagesReceived );
            check( message.GetType() === TEST_MESSAGE );

            const testMessage = message as TestMessage;

            check( testMessage.sequence === numMessagesReceived );

            ++numMessagesReceived;

            messageFactory.ReleaseMessage( message );
        }

        if ( numMessagesReceived === NumMessagesSent )
            break;
    }

    check( numMessagesReceived === NumMessagesSent );

    receiver.Dispose();
    sender.Dispose();
    messageFactory.Dispose();
}

function RunReliableBlocks( messageFactory: MessageFactory, connectionConfig: ConnectionConfig, NumMessagesSent: number, blockSizeFor: ( i: number ) => number, blockType: number ): void
{
    const state = new PumpState();

    const sender = new Connection( GetDefaultAllocator(), messageFactory, connectionConfig, state.time );
    const receiver = new Connection( GetDefaultAllocator(), messageFactory, connectionConfig, state.time );

    for ( let i = 0; i < NumMessagesSent; ++i )
    {
        const message = messageFactory.CreateMessage( blockType ) as TestBlockMessage;
        check( message );
        message.sequence = i;
        AttachTestBlock( messageFactory, message, blockSizeFor( i ), i );
        sender.SendMessage( ReliableChannel, message );
    }

    let numMessagesReceived = 0;

    const NumIterations = 10000;

    for ( let i = 0; i < NumIterations; ++i )
    {
        PumpConnectionUpdate( connectionConfig, state, sender, receiver );

        while ( true )
        {
            const message = receiver.ReceiveMessage( ReliableChannel );
            if ( !message )
                break;

            check( message.GetId() === numMessagesReceived );
            check( message.GetType() === blockType );

            const blockMessage = message as TestBlockMessage;

            check( blockMessage.sequence === ( numMessagesReceived & 0xFFFF ) );

            CheckTestBlock( blockMessage, blockSizeFor( numMessagesReceived ), numMessagesReceived );

            ++numMessagesReceived;

            messageFactory.ReleaseMessage( message );
        }

        if ( numMessagesReceived === NumMessagesSent )
            break;
    }

    check( numMessagesReceived === NumMessagesSent );

    receiver.Dispose();
    sender.Dispose();
}

function test_connection_reliable_ordered_blocks(): void
{
    const messageFactory = new TestMessageFactory( GetDefaultAllocator() );
    RunReliableBlocks( messageFactory, new ConnectionConfig(), 32, ( i ) => 1 + ( ( i * 901 ) % 3333 ), TEST_BLOCK_MESSAGE );
    messageFactory.Dispose();
}

function test_connection_reliable_ordered_blocks_max_size(): void
{
    // Regression test: when maxBlockSize is not a multiple of blockFragmentSize, a full-size block needs
    // ceil(maxBlockSize/blockFragmentSize) fragments. Here 1100/500 => floor 2, ceil 3.
    const messageFactory = new TestMessageFactory( GetDefaultAllocator() );
    const connectionConfig = new ConnectionConfig();
    connectionConfig.channel[ReliableChannel].maxBlockSize = 1100;
    connectionConfig.channel[ReliableChannel].blockFragmentSize = 500;
    const BlockSize = connectionConfig.channel[ReliableChannel].maxBlockSize;
    RunReliableBlocks( messageFactory, connectionConfig, 8, () => BlockSize, TEST_BLOCK_MESSAGE );
    messageFactory.Dispose();
}

function test_connection_reliable_ordered_blocks_on_demand(): void
{
    // Port addition: ChannelConfig.allocateBlocksOnDemand. The reliable-ordered channel reserves no maxBlockSize receive
    // buffer when it is created; it allocates one sized to each incoming block and frees it once the block is delivered.

    const MaxBlockSize = 4 * 1024 * 1024;
    const HeapBytes = 64 * 1024 * 1024;

    const messageFactory = new TestMessageFactory( GetDefaultAllocator() );

    const onDemand = new ConnectionConfig();
    onDemand.channel[ReliableChannel].maxBlockSize = MaxBlockSize;
    onDemand.channel[ReliableChannel].allocateBlocksOnDemand = true;
    const preallocated = onDemand.Clone();
    preallocated.channel[ReliableChannel].allocateBlocksOnDemand = false;

    // a connection no longer reserves maxBlockSize up front

    let connectionBytes = 0;
    {
        const preallocatedAllocator = new TLSF_Allocator( null, HeapBytes );
        const onDemandAllocator = new TLSF_Allocator( null, HeapBytes );
        const withBuffer = new Connection( preallocatedAllocator, messageFactory, preallocated, 0.0 );
        const withoutBuffer = new Connection( onDemandAllocator, messageFactory, onDemand, 0.0 );
        check( preallocatedAllocator.GetUsedBytes() - onDemandAllocator.GetUsedBytes() >= MaxBlockSize );
        connectionBytes = onDemandAllocator.GetUsedBytes();
        withBuffer.Dispose();
        withoutBuffer.Dispose();
        preallocatedAllocator.Dispose();
        onDemandAllocator.Dispose();
    }

    // blocks arrive intact, and each receive buffer is freed once its block is delivered

    {
        const senderAllocator = new TLSF_Allocator( null, HeapBytes );
        const receiverAllocator = new TLSF_Allocator( null, HeapBytes );
        const state = new PumpState();
        const sender = new Connection( senderAllocator, messageFactory, onDemand, state.time );
        const receiver = new Connection( receiverAllocator, messageFactory, onDemand, state.time );
        const baseline = receiverAllocator.GetUsedBytes();

        const NumBlocks = 16;
        const blockSizeFor = ( i: number ): number => 1 + ( ( i * 7919 ) % 20000 );
        for ( let i = 0; i < NumBlocks; ++i )
        {
            const message = messageFactory.CreateMessage( TEST_BLOCK_MESSAGE ) as TestBlockMessage;
            check( message );
            message.sequence = i;
            AttachTestBlock( messageFactory, message, blockSizeFor( i ), i );
            sender.SendMessage( ReliableChannel, message );
        }

        let numReceived = 0;
        for ( let i = 0; i < 10000 && numReceived < NumBlocks; ++i )
        {
            PumpConnectionUpdate( onDemand, state, sender, receiver, Math.fround( 0.1 ), 0 );
            let message;
            while ( ( message = receiver.ReceiveMessage( ReliableChannel ) ) !== null )
            {
                check( message.GetId() === numReceived );
                CheckTestBlock( message as TestBlockMessage, blockSizeFor( numReceived ), numReceived );
                messageFactory.ReleaseMessage( message );
                ++numReceived;
            }
        }
        check( numReceived === NumBlocks );
        check( receiver.GetErrorLevel() === CONNECTION_ERROR_NONE );
        check( receiverAllocator.GetUsedBytes() === baseline );

        sender.Dispose();
        receiver.Dispose();
        senderAllocator.Dispose();
        receiverAllocator.Dispose();
    }

    // with a budget far below maxBlockSize, small blocks still arrive; a block that doesn't fit is a channel
    // out-of-memory error (the connection fails as for any allocation failure) rather than a crash

    {
        const Headroom = 64 * 1024;
        const probe = new TLSF_Allocator( null, HeapBytes );
        const controlOverhead = HeapBytes - probe.GetCapacityBytes();
        probe.Dispose();

        const senderAllocator = new TLSF_Allocator( null, HeapBytes );
        const receiverAllocator = new TLSF_Allocator( null, controlOverhead + connectionBytes + Headroom );
        const state = new PumpState();
        const sender = new Connection( senderAllocator, messageFactory, onDemand, state.time );
        const receiver = new Connection( receiverAllocator, messageFactory, onDemand, state.time );

        const SmallBlock = 2000;
        const LargeBlock = 256 * 1024;
        for ( let i = 0; i < 2; ++i )
        {
            const message = messageFactory.CreateMessage( TEST_BLOCK_MESSAGE ) as TestBlockMessage;
            check( message );
            message.sequence = i;
            AttachTestBlock( messageFactory, message, i === 0 ? SmallBlock : LargeBlock, i );
            sender.SendMessage( ReliableChannel, message );
        }

        let receivedSmall = false;
        for ( let i = 0; i < 1000 && receiver.GetErrorLevel() === CONNECTION_ERROR_NONE; ++i )
        {
            PumpConnectionUpdate( onDemand, state, sender, receiver, Math.fround( 0.1 ), 0 );
            let message;
            while ( ( message = receiver.ReceiveMessage( ReliableChannel ) ) !== null )
            {
                check( message.GetId() === 0 );
                CheckTestBlock( message as TestBlockMessage, SmallBlock, 0 );
                messageFactory.ReleaseMessage( message );
                receivedSmall = true;
            }
        }
        check( receivedSmall );
        check( receiver.GetErrorLevel() === CONNECTION_ERROR_CHANNEL );
        check( receiver.GetChannelErrorLevel( ReliableChannel ) === CHANNEL_ERROR_OUT_OF_MEMORY );

        sender.Dispose();
        receiver.Dispose();
        senderAllocator.Dispose();
        receiverAllocator.Dispose();
    }

    messageFactory.Dispose();
}

function SendRandomMessagesAndBlocks( messageFactory: MessageFactory, sender: Connection, channelIndex: number, NumMessagesSent: number ): void
{
    for ( let i = 0; i < NumMessagesSent; ++i )
    {
        if ( yojimbo_rand() % 2 )
        {
            const message = messageFactory.CreateMessage( TEST_MESSAGE ) as TestMessage;
            check( message );
            message.sequence = i;
            sender.SendMessage( channelIndex, message );
        }
        else
        {
            const message = messageFactory.CreateMessage( TEST_BLOCK_MESSAGE ) as TestBlockMessage;
            check( message );
            message.sequence = i;
            AttachTestBlock( messageFactory, message, 1 + ( ( i * 901 ) % 3333 ), i );
            sender.SendMessage( channelIndex, message );
        }
    }
}

function CheckRandomMessageOrBlock( message: Message, expected: number ): void
{
    check( message.GetId() === expected );

    switch ( message.GetType() )
    {
        case TEST_MESSAGE:
        {
            check( ( message as TestMessage ).sequence === ( expected & 0xFFFF ) );
        }
        break;

        case TEST_BLOCK_MESSAGE:
        {
            const blockMessage = message as TestBlockMessage;
            check( blockMessage.sequence === ( expected & 0xFFFF ) );
            CheckTestBlock( blockMessage, 1 + ( ( expected * 901 ) % 3333 ), expected );
        }
        break;
    }
}

function test_connection_reliable_ordered_messages_and_blocks(): void
{
    const messageFactory = new TestMessageFactory( GetDefaultAllocator() );

    const state = new PumpState();

    const connectionConfig = new ConnectionConfig();

    const sender = new Connection( GetDefaultAllocator(), messageFactory, connectionConfig, state.time );
    const receiver = new Connection( GetDefaultAllocator(), messageFactory, connectionConfig, state.time );

    const NumMessagesSent = 32;

    SendRandomMessagesAndBlocks( messageFactory, sender, ReliableChannel, NumMessagesSent );

    let numMessagesReceived = 0;

    const NumIterations = 10000;

    for ( let i = 0; i < NumIterations; ++i )
    {
        PumpConnectionUpdate( connectionConfig, state, sender, receiver );

        while ( true )
        {
            const message = receiver.ReceiveMessage( ReliableChannel );
            if ( !message )
                break;

            CheckRandomMessageOrBlock( message, numMessagesReceived );

            ++numMessagesReceived;

            messageFactory.ReleaseMessage( message );
        }

        if ( numMessagesReceived === NumMessagesSent )
            break;
    }

    check( numMessagesReceived === NumMessagesSent );

    receiver.Dispose();
    sender.Dispose();
    messageFactory.Dispose();
}

function test_connection_reliable_ordered_messages_and_blocks_multiple_channels(): void
{
    const NumChannels = 2;

    check( NumChannels >= 0 && NumChannels <= MaxChannels );

    const state = new PumpState();

    const messageFactory = new TestMessageFactory( GetDefaultAllocator() );

    const connectionConfig = new ConnectionConfig();
    connectionConfig.numChannels = NumChannels;
    connectionConfig.channel[0].type = CHANNEL_TYPE_RELIABLE_ORDERED;
    connectionConfig.channel[0].maxMessagesPerPacket = 8;
    connectionConfig.channel[1].type = CHANNEL_TYPE_RELIABLE_ORDERED;
    connectionConfig.channel[1].maxMessagesPerPacket = 8;

    const sender = new Connection( GetDefaultAllocator(), messageFactory, connectionConfig, state.time );
    const receiver = new Connection( GetDefaultAllocator(), messageFactory, connectionConfig, state.time );

    const NumMessagesSent = 32;

    for ( let channelIndex = 0; channelIndex < NumChannels; ++channelIndex )
        SendRandomMessagesAndBlocks( messageFactory, sender, channelIndex, NumMessagesSent );

    const NumIterations = 10000;

    const numMessagesReceived = new Array<number>( NumChannels ).fill( 0 );

    for ( let i = 0; i < NumIterations; ++i )
    {
        PumpConnectionUpdate( connectionConfig, state, sender, receiver );

        for ( let channelIndex = 0; channelIndex < NumChannels; ++channelIndex )
        {
            while ( true )
            {
                const message = receiver.ReceiveMessage( channelIndex );
                if ( !message )
                    break;

                CheckRandomMessageOrBlock( message, numMessagesReceived[channelIndex] );

                ++numMessagesReceived[channelIndex];

                messageFactory.ReleaseMessage( message );
            }
        }

        let receivedAllMessages = true;

        for ( let channelIndex = 0; channelIndex < NumChannels; ++channelIndex )
        {
            if ( numMessagesReceived[channelIndex] !== NumMessagesSent )
            {
                receivedAllMessages = false;
                break;
            }
        }

        if ( receivedAllMessages )
            break;
    }

    for ( let channelIndex = 0; channelIndex < NumChannels; ++channelIndex )
        check( numMessagesReceived[channelIndex] === NumMessagesSent );

    receiver.Dispose();
    sender.Dispose();
    messageFactory.Dispose();
}

function RunUnreliableMessages( messageFactory: MessageFactory, messageType: number ): void
{
    const state = new PumpState();

    const connectionConfig = new ConnectionConfig();
    connectionConfig.numChannels = 1;
    connectionConfig.channel[0].type = CHANNEL_TYPE_UNRELIABLE_UNORDERED;

    const sender = new Connection( GetDefaultAllocator(), messageFactory, connectionConfig, state.time );
    const receiver = new Connection( GetDefaultAllocator(), messageFactory, connectionConfig, state.time );

    const NumIterations = 256;

    const NumMessagesSent = 16;

    for ( let j = 0; j < NumMessagesSent; ++j )
    {
        const message = messageFactory.CreateMessage( messageType ) as TestMessage;
        check( message );
        message.sequence = j;
        sender.SendMessage( 0, message );
    }

    let numMessagesReceived = 0;

    for ( let i = 0; i < NumIterations; ++i )
    {
        PumpConnectionUpdate( connectionConfig, state, sender, receiver, Math.fround( 0.1 ), 0 );

        while ( true )
        {
            const message = receiver.ReceiveMessage( 0 );
            if ( !message )
                break;

            check( message.GetType() === messageType );

            check( ( message as TestMessage ).sequence === ( numMessagesReceived & 0xFFFF ) );

            ++numMessagesReceived;

            messageFactory.ReleaseMessage( message );
        }

        if ( numMessagesReceived === NumMessagesSent )
            break;
    }

    check( numMessagesReceived === NumMessagesSent );

    receiver.Dispose();
    sender.Dispose();
}

function test_connection_unreliable_unordered_messages(): void
{
    const messageFactory = new TestMessageFactory( GetDefaultAllocator() );
    RunUnreliableMessages( messageFactory, TEST_MESSAGE );
    messageFactory.Dispose();
}

function test_connection_unreliable_unordered_blocks(): void
{
    const messageFactory = new TestMessageFactory( GetDefaultAllocator() );

    const state = new PumpState();

    const connectionConfig = new ConnectionConfig();
    connectionConfig.numChannels = 1;
    connectionConfig.channel[0].type = CHANNEL_TYPE_UNRELIABLE_UNORDERED;

    const sender = new Connection( GetDefaultAllocator(), messageFactory, connectionConfig, state.time );
    const receiver = new Connection( GetDefaultAllocator(), messageFactory, connectionConfig, state.time );

    const NumIterations = 256;

    const NumMessagesSent = 8;

    for ( let j = 0; j < NumMessagesSent; ++j )
    {
        const message = messageFactory.CreateMessage( TEST_BLOCK_MESSAGE ) as TestBlockMessage;
        check( message );
        message.sequence = j;
        AttachTestBlock( messageFactory, message, 1 + j * 7, j );
        sender.SendMessage( 0, message );
    }

    let numMessagesReceived = 0;

    for ( let i = 0; i < NumIterations; ++i )
    {
        PumpConnectionUpdate( connectionConfig, state, sender, receiver, Math.fround( 0.1 ), 0 );

        while ( true )
        {
            const message = receiver.ReceiveMessage( 0 );
            if ( !message )
                break;

            check( message.GetType() === TEST_BLOCK_MESSAGE );

            const blockMessage = message as TestBlockMessage;

            check( blockMessage.sequence === ( numMessagesReceived & 0xFFFF ) );

            CheckTestBlock( blockMessage, 1 + numMessagesReceived * 7, numMessagesReceived );

            ++numMessagesReceived;

            messageFactory.ReleaseMessage( message );
        }

        if ( numMessagesReceived === NumMessagesSent )
            break;
    }

    check( numMessagesReceived === NumMessagesSent );

    receiver.Dispose();
    sender.Dispose();
    messageFactory.Dispose();
}

function test_connection_reject_empty_packet(): void
{
    // A packet that is exactly a reliable header reaches Connection::ProcessPacket with zero payload bytes.
    // That must be rejected cleanly.

    const messageFactory = new TestMessageFactory( GetDefaultAllocator() );

    const connectionConfig = new ConnectionConfig();
    connectionConfig.numChannels = 1;
    connectionConfig.channel[0].type = CHANNEL_TYPE_RELIABLE_ORDERED;

    const connection = new Connection( GetDefaultAllocator(), messageFactory, connectionConfig, 100.0 );

    const buffer = new Uint8Array( 1 );

    check( !connection.ProcessPacket( null, 0, buffer, 0 ) );
    check( connection.GetErrorLevel() === CONNECTION_ERROR_READ_PACKET_FAILED );

    connection.Dispose();
    messageFactory.Dispose();
}

function test_connection_process_packet_exact_allocation(): void
{
    // Production receive hands ProcessPacket an exact payload allocation.
    const messageFactory = new TestMessageFactory( GetDefaultAllocator() );
    const connectionConfig = new ConnectionConfig();
    connectionConfig.numChannels = 1;
    connectionConfig.channel[0].type = CHANNEL_TYPE_RELIABLE_ORDERED;
    const sender = new Connection( GetDefaultAllocator(), messageFactory, connectionConfig, 100.0 );
    const receiver = new Connection( GetDefaultAllocator(), messageFactory, connectionConfig, 100.0 );

    const message = messageFactory.CreateMessage( TEST_MESSAGE ) as TestMessage;
    check( message );
    message.sequence = 0;
    sender.SendMessage( 0, message );

    const packet = new Uint8Array( 2048 );
    const out = { packetBytes: 0 };
    check( sender.GeneratePacket( null, 0, packet, packet.length, out ) );
    check( out.packetBytes > 0 );

    const exact = packet.slice( 0, out.packetBytes );
    check( receiver.ProcessPacket( null, 0, exact, out.packetBytes ) );

    const received = receiver.ReceiveMessage( 0 );
    check( received );
    check( received.GetType() === TEST_MESSAGE );
    messageFactory.ReleaseMessage( received );

    receiver.Dispose();
    sender.Dispose();
    messageFactory.Dispose();
}

function test_connection_unreliable_rejects_block_fragment(): void
{
    // An unreliable-unordered channel never sends a top-level block fragment. A peer that puts a block fragment on that
    // channel index must be rejected as a serialize failure.

    const messageFactory = new TestMessageFactory( GetDefaultAllocator() );

    let time = 100.0;

    const senderConfig = new ConnectionConfig();
    senderConfig.numChannels = 1;
    senderConfig.channel[0].type = CHANNEL_TYPE_RELIABLE_ORDERED;

    const receiverConfig = new ConnectionConfig();
    receiverConfig.numChannels = 1;
    receiverConfig.channel[0].type = CHANNEL_TYPE_UNRELIABLE_UNORDERED;

    const sender = new Connection( GetDefaultAllocator(), messageFactory, senderConfig, time );
    const receiver = new Connection( GetDefaultAllocator(), messageFactory, receiverConfig, time );

    const message = messageFactory.CreateMessage( TEST_BLOCK_MESSAGE ) as TestBlockMessage;
    check( message );
    message.sequence = 0;
    AttachTestBlock( messageFactory, message, 64, 0 );
    sender.SendMessage( 0, message );

    const packetData = new Uint8Array( senderConfig.maxPacketSize );
    const out = { packetBytes: 0 };
    let sequence = 0;
    let sawChannelError = false;

    for ( let i = 0; i < 64 && !sawChannelError; ++i )
    {
        if ( sender.GeneratePacket( null, sequence, packetData, senderConfig.maxPacketSize, out ) && out.packetBytes > 0 )
            receiver.ProcessPacket( null, sequence, packetData, out.packetBytes );

        sender.AdvanceTime( time );
        receiver.AdvanceTime( time );
        time += 0.1;
        sequence++;

        if ( receiver.GetErrorLevel() === CONNECTION_ERROR_CHANNEL )
            sawChannelError = true;
    }

    check( sawChannelError );

    receiver.Dispose();
    sender.Dispose();
    messageFactory.Dispose();
}

function test_connection_reliable_block_fragment_on_disabled_blocks(): void
{
    // A peer sends a block fragment on a reliable-ordered channel, but the receiver has blocks disabled on that channel.

    const messageFactory = new TestMessageFactory( GetDefaultAllocator() );

    let time = 100.0;

    const senderConfig = new ConnectionConfig();
    senderConfig.numChannels = 1;
    senderConfig.channel[0].type = CHANNEL_TYPE_RELIABLE_ORDERED;

    const receiverConfig = new ConnectionConfig();
    receiverConfig.numChannels = 1;
    receiverConfig.channel[0].type = CHANNEL_TYPE_RELIABLE_ORDERED;
    receiverConfig.channel[0].disableBlocks = true;

    const sender = new Connection( GetDefaultAllocator(), messageFactory, senderConfig, time );
    const receiver = new Connection( GetDefaultAllocator(), messageFactory, receiverConfig, time );

    const message = messageFactory.CreateMessage( TEST_BLOCK_MESSAGE ) as TestBlockMessage;
    check( message );
    message.sequence = 0;
    AttachTestBlock( messageFactory, message, 2000, 0 );
    sender.SendMessage( 0, message );

    const packetData = new Uint8Array( senderConfig.maxPacketSize );
    const out = { packetBytes: 0 };
    let sequence = 0;

    for ( let i = 0; i < 64; ++i )
    {
        if ( sender.GeneratePacket( null, sequence, packetData, senderConfig.maxPacketSize, out ) && out.packetBytes > 0 )
            receiver.ProcessPacket( null, sequence, packetData, out.packetBytes );

        sender.AdvanceTime( time );
        receiver.AdvanceTime( time );
        time += 0.1;
        sequence++;

        if ( receiver.GetErrorLevel() !== CONNECTION_ERROR_NONE )
            break;
    }

    check( receiver.GetErrorLevel() !== CONNECTION_ERROR_NONE );

    receiver.Dispose();
    sender.Dispose();
    messageFactory.Dispose();
}

/** Hand-serialize a connection packet carrying a single reliable-ordered channel entry that is a block fragment. */

function SerializeRawBlockFragmentPacket( stream: BaseStream, maxFragmentsPerBlock: number, blockFragmentSize: number, numFragments: number, fragmentId: number, fragmentSize: number ): boolean
{
    const v = { numChannelEntries: 1, blockMessage: true, messageId: 0, numFragments, fragmentId, fragmentSize };
    if ( !serialize_int( stream, v, 'numChannelEntries', 0, 1 ) ) return false;     // numChannels == 1, so channelIndex is not serialized
    if ( !serialize_bool( stream, v, 'blockMessage' ) ) return false;
    if ( !serialize_bits( stream, v, 'messageId', 16 ) ) return false;
    if ( maxFragmentsPerBlock > 1 )
        if ( !serialize_int( stream, v, 'numFragments', 1, maxFragmentsPerBlock ) ) return false;
    if ( numFragments > 1 )
        if ( !serialize_int( stream, v, 'fragmentId', 0, numFragments - 1 ) ) return false;
    if ( !serialize_int( stream, v, 'fragmentSize', 1, blockFragmentSize ) ) return false;
    const payload = new Uint8Array( 2048 ).fill( 0xAB );
    check( fragmentSize <= payload.length );
    if ( !serialize_bytes( stream, payload, fragmentSize ) ) return false;
    // fragmentId != 0 here, so no message type / block message is serialized.
    return true;
}

function test_channel_config_fragment_counts_without_overflow(): void
{
    // yojimbo#347: ceil(maxBlockSize / blockFragmentSize) must not overflow for a legal huge maxBlockSize.
    const channel = new ChannelConfig();
    channel.maxBlockSize = 2147483647;
    channel.blockFragmentSize = 1024;
    const n = channel.GetMaxFragmentsPerBlock();
    check( n === Math.floor( ( 2147483647 + 1023 ) / 1024 ) );
    check( n > 65535 );

    // yojimbo#346: fragmentSize on the wire is 16 bits.
    const small = new ChannelConfig();
    small.maxBlockSize = 256 * 1024;
    small.blockFragmentSize = 1024;
    check( small.GetMaxFragmentsPerBlock() === 256 );
    check( small.blockFragmentSize <= 65535 );
}

function test_connection_reliable_block_fragment_overflow(): void
{
    // Regression test: a peer sends a reliable-ordered block fragment whose final fragment claims a full
    // blockFragmentSize of data. The fragment must be rejected before the copy.

    const messageFactory = new TestMessageFactory( GetDefaultAllocator() );

    const time = 100.0;

    const config = new ConnectionConfig();
    config.numChannels = 1;
    config.channel[0].type = CHANNEL_TYPE_RELIABLE_ORDERED;
    config.channel[0].maxBlockSize = 1100;      // deliberately not a multiple of blockFragmentSize
    config.channel[0].blockFragmentSize = 500;  // => GetMaxFragmentsPerBlock() == 3

    const receiver = new Connection( GetDefaultAllocator(), messageFactory, config, time );

    const maxFragmentsPerBlock = config.channel[0].GetMaxFragmentsPerBlock();
    const blockFragmentSize = config.channel[0].blockFragmentSize;

    const numFragments = maxFragmentsPerBlock;      // 3
    const fragmentId = numFragments - 1;            // 2 (final fragment)
    const fragmentSize = blockFragmentSize;         // 500 -> write [1000,1500) into a 1100-byte buffer

    const buffer = new Uint8Array( 4096 );
    const stream = new WriteStream( buffer, buffer.length );
    check( SerializeRawBlockFragmentPacket( stream, maxFragmentsPerBlock, blockFragmentSize, numFragments, fragmentId, fragmentSize ) );
    stream.Flush();
    const packetBytes = stream.GetBytesProcessed();
    check( packetBytes > 0 );

    const processed = receiver.ProcessPacket( null, 0, buffer, packetBytes );
    check( !processed );

    receiver.AdvanceTime( time );
    check( receiver.GetErrorLevel() === CONNECTION_ERROR_CHANNEL );

    receiver.Dispose();
    messageFactory.Dispose();
}

function test_connection_reliable_over_budget_packet(): void
{
    // A peer sends more channel data than the receiver's configured packetBudget. The over-budget read must simply be accepted.

    const messageFactory = new TestMessageFactory( GetDefaultAllocator() );

    let time = 100.0;

    const senderConfig = new ConnectionConfig();
    senderConfig.numChannels = 1;
    senderConfig.channel[0].type = CHANNEL_TYPE_RELIABLE_ORDERED;

    const receiverConfig = new ConnectionConfig();
    receiverConfig.numChannels = 1;
    receiverConfig.channel[0].type = CHANNEL_TYPE_RELIABLE_ORDERED;
    receiverConfig.channel[0].packetBudget = 32;

    const sender = new Connection( GetDefaultAllocator(), messageFactory, senderConfig, time );
    const receiver = new Connection( GetDefaultAllocator(), messageFactory, receiverConfig, time );

    const NumMessages = 64;
    for ( let i = 0; i < NumMessages; ++i )
    {
        const message = messageFactory.CreateMessage( TEST_MESSAGE ) as TestMessage;
        check( message );
        message.sequence = i;
        sender.SendMessage( 0, message );
    }

    const packetData = new Uint8Array( senderConfig.maxPacketSize );
    const out = { packetBytes: 0 };
    let sequence = 0;
    let processed = false;

    for ( let i = 0; i < 8 && !processed; ++i )
    {
        if ( sender.GeneratePacket( null, sequence, packetData, senderConfig.maxPacketSize, out ) && out.packetBytes > 0 )
        {
            check( receiver.ProcessPacket( null, sequence, packetData, out.packetBytes ) );
            processed = true;
        }

        sender.AdvanceTime( time );
        receiver.AdvanceTime( time );
        time += 0.1;
        sequence++;
    }

    check( processed );
    check( receiver.GetErrorLevel() === CONNECTION_ERROR_NONE );

    receiver.Dispose();
    sender.Dispose();
    messageFactory.Dispose();
}

function test_connection_reliable_message_alloc_failure(): void
{
    // Arm the allocator to fail the message array allocation inside GeneratePacket and verify we neither
    // crash nor leak (the queued reliable message is retained and freed at teardown).
    const allocator = new ArmableAllocator();
    {
        const messageFactory = new TestMessageFactory( allocator );

        const config = new ConnectionConfig();
        config.numChannels = 1;
        config.channel[0].type = CHANNEL_TYPE_RELIABLE_ORDERED;

        {
            const connection = new Connection( allocator, messageFactory, config, 100.0 );

            const message = messageFactory.CreateMessage( TEST_MESSAGE );
            check( message );
            connection.SendMessage( 0, message );

            const packetData = new Uint8Array( 4096 );
            const out = { packetBytes: 0 };

            allocator.Arm( 0 );     // fail the first allocation inside GeneratePacket (message array)
            connection.GeneratePacket( null, 0, packetData, packetData.length, out );
            allocator.Disarm();

            connection.Dispose();
        }

        messageFactory.Dispose();
    }
    check( allocator.GetOutstanding() === 0 );   // no leak across teardown
    allocator.Dispose();
}

function test_connection_unreliable_message_alloc_failure(): void
{
    // Fail the unreliable channel's message array allocation in GetPacketData: no crash and no leak of the popped messages.
    const allocator = new ArmableAllocator();
    {
        const messageFactory = new TestMessageFactory( allocator );

        const config = new ConnectionConfig();
        config.numChannels = 1;
        config.channel[0].type = CHANNEL_TYPE_UNRELIABLE_UNORDERED;

        {
            const connection = new Connection( allocator, messageFactory, config, 100.0 );

            for ( let i = 0; i < 4; ++i )
            {
                const message = messageFactory.CreateMessage( TEST_MESSAGE );
                check( message );
                connection.SendMessage( 0, message );
            }

            const packetData = new Uint8Array( 4096 );
            const out = { packetBytes: 0 };

            allocator.Arm( 0 );     // fail the message array allocation in GetPacketData
            connection.GeneratePacket( null, 0, packetData, packetData.length, out );
            allocator.Disarm();

            connection.Dispose();
        }

        messageFactory.Dispose();
    }
    check( allocator.GetOutstanding() === 0 );   // popped messages released, nothing leaked
    allocator.Dispose();
}

function test_connection_generate_packet_channel_data_alloc_failure(): void
{
    // The message array allocation succeeds but the channel data allocation fails: nothing may leak.
    const allocator = new ArmableAllocator();
    {
        const messageFactory = new TestMessageFactory( allocator );

        const config = new ConnectionConfig();
        config.numChannels = 1;
        config.channel[0].type = CHANNEL_TYPE_RELIABLE_ORDERED;

        {
            const connection = new Connection( allocator, messageFactory, config, 100.0 );

            const message = messageFactory.CreateMessage( TEST_MESSAGE );
            check( message );
            connection.SendMessage( 0, message );

            const packetData = new Uint8Array( 4096 );
            const out = { packetBytes: 0 };

            allocator.Arm( 1 );     // 1st alloc (message array) succeeds, 2nd (channel data) fails
            const result = connection.GeneratePacket( null, 0, packetData, packetData.length, out );
            allocator.Disarm();
            check( !result );       // the channel-data allocation failure fails the generate

            connection.Dispose();
        }

        messageFactory.Dispose();
    }
    check( allocator.GetOutstanding() === 0 );
    allocator.Dispose();
}

function test_message_factory_create_message_alloc_failure(): void
{
    // CreateMessage must return null cleanly on allocator exhaustion (without constructing) and flag the factory.
    const allocator = new ArmableAllocator();
    {
        const factory = new TestMessageFactory( allocator );
        allocator.Arm( 0 );     // fail the next allocation (the message object)
        const message = factory.CreateMessage( TEST_MESSAGE );
        allocator.Disarm();
        check( message === null );
        check( factory.GetErrorLevel() === MESSAGE_FACTORY_ERROR_FAILED_TO_ALLOCATE_MESSAGE );
        factory.Dispose();
    }
    check( allocator.GetOutstanding() === 0 );
    allocator.Dispose();
}

function test_connection_process_packet_channel_data_alloc_failure(): void
{
    // Feed a valid packet to a receiver whose allocator fails the channel-data allocation: the read fails cleanly
    // without crashing or leaking.
    const senderAlloc = new ArmableAllocator();
    const receiverAlloc = new ArmableAllocator();
    {
        const senderFactory = new TestMessageFactory( senderAlloc );
        const receiverFactory = new TestMessageFactory( receiverAlloc );

        const config = new ConnectionConfig();
        config.numChannels = 1;
        config.channel[0].type = CHANNEL_TYPE_RELIABLE_ORDERED;

        {
            const sender = new Connection( senderAlloc, senderFactory, config, 100.0 );
            const receiver = new Connection( receiverAlloc, receiverFactory, config, 100.0 );

            const message = senderFactory.CreateMessage( TEST_MESSAGE );
            check( message );
            sender.SendMessage( 0, message );

            const packetData = new Uint8Array( 4096 );
            const out = { packetBytes: 0 };
            check( sender.GeneratePacket( null, 0, packetData, packetData.length, out ) );
            check( out.packetBytes > 0 );

            receiverAlloc.Arm( 0 );     // fail the channel-data allocation in the connection-packet read
            const ok = receiver.ProcessPacket( null, 0, packetData, out.packetBytes );
            receiverAlloc.Disarm();
            check( !ok );

            receiver.Dispose();
            sender.Dispose();
        }

        receiverFactory.Dispose();
        senderFactory.Dispose();
    }
    check( senderAlloc.GetOutstanding() === 0 );
    check( receiverAlloc.GetOutstanding() === 0 );
    senderAlloc.Dispose();
    receiverAlloc.Dispose();
}

function test_rtti_across_the_abi_boundary(): void
{
    // The C++ test checks typeinfo links across the library boundary. The TypeScript equivalent: the class
    // hierarchy is observable with instanceof for allocators and message factories.
    const allocator = new ArmableAllocator();

    const base: Allocator = allocator;
    check( base instanceof ArmableAllocator );
    check( !( base instanceof DefaultAllocator ) );

    check( GetDefaultAllocator() instanceof DefaultAllocator );

    const factory = new TestMessageFactory( allocator );
    const factoryBase: MessageFactory = factory;
    check( factoryBase instanceof TestMessageFactory );
    check( factoryBase instanceof MessageFactory );
    factory.Dispose();
    allocator.Dispose();
}

function test_single_message_type_reliable(): void
{
    const messageFactory = new SingleTestMessageFactory( GetDefaultAllocator() );

    const state = new PumpState();

    const connectionConfig = new ConnectionConfig();

    const sender = new Connection( GetDefaultAllocator(), messageFactory, connectionConfig, state.time );
    const receiver = new Connection( GetDefaultAllocator(), messageFactory, connectionConfig, state.time );

    const NumMessagesSent = 64;

    for ( let i = 0; i < NumMessagesSent; ++i )
    {
        const message = messageFactory.CreateMessage( SINGLE_TEST_MESSAGE ) as TestMessage;
        check( message );
        message.sequence = i;
        sender.SendMessage( 0, message );
    }

    let numMessagesReceived = 0;

    const NumIterations = 1000;

    for ( let i = 0; i < NumIterations; ++i )
    {
        PumpConnectionUpdate( connectionConfig, state, sender, receiver );

        while ( true )
        {
            const message = receiver.ReceiveMessage( 0 );
            if ( !message )
                break;

            check( message.GetId() === numMessagesReceived );
            check( message.GetType() === SINGLE_TEST_MESSAGE );
            check( ( message as TestMessage ).sequence === numMessagesReceived );

            ++numMessagesReceived;

            messageFactory.ReleaseMessage( message );
        }

        if ( numMessagesReceived === NumMessagesSent )
            break;
    }

    check( numMessagesReceived === NumMessagesSent );

    receiver.Dispose();
    sender.Dispose();
    messageFactory.Dispose();
}

function test_single_message_type_reliable_blocks(): void
{
    const messageFactory = new SingleBlockTestMessageFactory( GetDefaultAllocator() );
    RunReliableBlocks( messageFactory, new ConnectionConfig(), 32, ( i ) => 1 + ( ( i * 901 ) % 3333 ), SINGLE_BLOCK_TEST_MESSAGE );
    messageFactory.Dispose();
}

function test_single_message_type_unreliable(): void
{
    const messageFactory = new SingleTestMessageFactory( GetDefaultAllocator() );
    RunUnreliableMessages( messageFactory, SINGLE_TEST_MESSAGE );
    messageFactory.Dispose();
}

// ---------------------------------------------------------------------------------------------
// Tests from the C# port and TypeScript specific tests

function test_connection_message_refcounts(): void
{
    // Every sent message must end at refcount zero once acked (reliable) or written (unreliable), and every received
    // message once released. ConnectionPacket must release the references packets take on messages.

    const messageFactory = new TestMessageFactory( GetDefaultAllocator() );

    const state = new PumpState();

    const connectionConfig = new ConnectionConfig();
    connectionConfig.numChannels = 2;
    connectionConfig.channel[0].type = CHANNEL_TYPE_RELIABLE_ORDERED;
    connectionConfig.channel[1].type = CHANNEL_TYPE_UNRELIABLE_UNORDERED;

    const sender = new Connection( GetDefaultAllocator(), messageFactory, connectionConfig, state.time );
    const receiver = new Connection( GetDefaultAllocator(), messageFactory, connectionConfig, state.time );

    const NumMessages = 32;

    const sent: Message[] = [];

    for ( let i = 0; i < NumMessages; ++i )
    {
        let message: Message;
        if ( i === NumMessages / 2 )
        {
            const blockMessage = messageFactory.CreateMessage( TEST_BLOCK_MESSAGE ) as TestBlockMessage;
            check( blockMessage );
            blockMessage.sequence = i;
            AttachTestBlock( messageFactory, blockMessage, 3000, i );
            message = blockMessage;
        }
        else
        {
            const testMessage = messageFactory.CreateMessage( TEST_MESSAGE ) as TestMessage;
            check( testMessage );
            testMessage.sequence = i;
            message = testMessage;
        }
        sent.push( message );
        sender.SendMessage( 0, message );

        const unreliable = messageFactory.CreateMessage( TEST_MESSAGE ) as TestMessage;
        check( unreliable );
        unreliable.sequence = i;
        sent.push( unreliable );
        sender.SendMessage( 1, unreliable );
    }

    const received: Message[] = [];
    let numReliableReceived = 0;

    for ( let i = 0; i < 1000; ++i )
    {
        PumpConnectionUpdate( connectionConfig, state, sender, receiver, Math.fround( 0.1 ), 0 );

        for ( let channelIndex = 0; channelIndex < 2; ++channelIndex )
        {
            while ( true )
            {
                const message = receiver.ReceiveMessage( channelIndex );
                if ( !message )
                    break;
                check( message.GetRefCount() === 1 );         // the caller owns the only reference
                received.push( message );
                if ( channelIndex === 0 )
                    numReliableReceived++;
                messageFactory.ReleaseMessage( message );
            }
        }

        if ( numReliableReceived === NumMessages && !sender.HasMessagesToSend( 0 ) && !sender.HasMessagesToSend( 1 ) )
            break;
    }

    check( numReliableReceived === NumMessages );
    check( received.length === NumMessages * 2 );

    for ( const message of sent )
        check( message.GetRefCount() === 0 );
    for ( const message of received )
        check( message.GetRefCount() === 0 );

    check( messageFactory.GetNumAllocatedMessages() === 0 );

    receiver.Dispose();
    sender.Dispose();
    messageFactory.Dispose();             // fails through the assert handler on any leaked message
}

function test_connection_truncated_and_garbage_packets(): void
{
    // Every serialize_* failure must propagate. A truncated packet must be refused, never throw or be partially
    // applied, and random garbage must never crash the reader.

    const messageFactory = new TestMessageFactory( GetDefaultAllocator() );

    const time = 100.0;

    const connectionConfig = new ConnectionConfig();
    connectionConfig.numChannels = 3;     // not a power of two: out of range channel indices are encodable
    connectionConfig.channel[0].type = CHANNEL_TYPE_RELIABLE_ORDERED;
    connectionConfig.channel[1].type = CHANNEL_TYPE_UNRELIABLE_UNORDERED;
    connectionConfig.channel[2].type = CHANNEL_TYPE_RELIABLE_ORDERED;

    const sender = new Connection( GetDefaultAllocator(), messageFactory, connectionConfig, time );

    for ( let i = 0; i < 16; ++i )
    {
        const message = messageFactory.CreateMessage( TEST_MESSAGE ) as TestMessage;
        check( message );
        message.sequence = i;
        sender.SendMessage( i % 3, message );
    }

    const packetData = new Uint8Array( connectionConfig.maxPacketSize );
    const out = { packetBytes: 0 };
    check( sender.GeneratePacket( null, 0, packetData, connectionConfig.maxPacketSize, out ) );
    const packetBytes = out.packetBytes;
    check( packetBytes > 0 );

    {
        const receiver = new Connection( GetDefaultAllocator(), messageFactory, connectionConfig, time );
        check( receiver.ProcessPacket( null, 0, packetData, packetBytes ) );
        receiver.Dispose();
    }

    for ( let truncated = 1; truncated < packetBytes; ++truncated )
    {
        const receiver = new Connection( GetDefaultAllocator(), messageFactory, connectionConfig, time );
        const copy = packetData.slice( 0, truncated );
        // either the packet framing fails (READ_PACKET_FAILED) or a message body fails, which puts the channel
        // into CHANNEL_ERROR_FAILED_TO_SERIALIZE; either way nothing is accepted
        check( !receiver.ProcessPacket( null, 0, copy, truncated ) );
        receiver.AdvanceTime( time );
        check( receiver.GetErrorLevel() !== CONNECTION_ERROR_NONE );
        receiver.Dispose();
    }

    const garbage = new Uint8Array( 256 );
    for ( let i = 0; i < 2000; ++i )
    {
        const receiver = new Connection( GetDefaultAllocator(), messageFactory, connectionConfig, time );
        const bytes = 1 + yojimbo_random_int( 0, garbage.length - 1 );
        for ( let j = 0; j < bytes; ++j )
            garbage[j] = yojimbo_random_int( 0, 255 );
        receiver.ProcessPacket( null, i & 0xFFFF, garbage, bytes );
        receiver.AdvanceTime( time );
        receiver.Dispose();
    }

    sender.Dispose();
    messageFactory.Dispose();
}

function test_connection_message_too_large(): void
{
    // A message that can never fit into a packet is rejected with CHANNEL_ERROR_MESSAGE_TOO_LARGE instead of
    // blocking the head of the reliable send queue forever. It also asserts in the debug build.

    const messageFactory = new TestMessageFactory( GetDefaultAllocator() );

    const connectionConfig = new ConnectionConfig();
    connectionConfig.numChannels = 2;
    connectionConfig.channel[0].type = CHANNEL_TYPE_RELIABLE_ORDERED;
    connectionConfig.channel[0].packetBudget = 8;           // 64 bits: TestMessage 1 (sequence 1) is 16 + 320 bits
    connectionConfig.channel[1].type = CHANNEL_TYPE_UNRELIABLE_UNORDERED;
    connectionConfig.channel[1].packetBudget = 8;

    const previous = yojimbo_get_assert_function();
    let asserted = 0;
    // a hook that returns lets execution continue past the assert in the "release" handling path below, but
    // yojimbo_assert still throws after the hook, so count and catch
    yojimbo_set_assert_function( () => { asserted++; } );
    const connection = new Connection( GetDefaultAllocator(), messageFactory, connectionConfig, 100.0 );
    try
    {
        // reliable: rejected in SendMessage
        {
            const message = messageFactory.CreateMessage( TEST_MESSAGE ) as TestMessage;
            message.sequence = 1;
            try { connection.SendMessage( 0, message ); } catch { /* assert */ }
            // the assert fired before the release path: release the message ourselves, as the release build would
            if ( message.GetRefCount() > 0 )
                messageFactory.ReleaseMessage( message );
        }

        // unreliable: rejected when the packet is generated
        {
            const message = messageFactory.CreateMessage( TEST_MESSAGE ) as TestMessage;
            message.sequence = 1;
            connection.SendMessage( 1, message );
            const packetData = new Uint8Array( connectionConfig.maxPacketSize );
            try { connection.GeneratePacket( null, 0, packetData, connectionConfig.maxPacketSize, { packetBytes: 0 } ); } catch { /* assert */ }
            if ( message.GetRefCount() > 0 )
                messageFactory.ReleaseMessage( message );
        }

        check( asserted === 2 );
    }
    finally
    {
        yojimbo_set_assert_function( previous );
    }

    // and with asserts off (the release build) the channels degrade to CHANNEL_ERROR_MESSAGE_TOO_LARGE
    yojimbo_set_asserts_enabled_for_test( false );
    try
    {
        const releaseConnection = new Connection( GetDefaultAllocator(), messageFactory, connectionConfig, 100.0 );

        const reliable = messageFactory.CreateMessage( TEST_MESSAGE ) as TestMessage;
        reliable.sequence = 1;
        releaseConnection.SendMessage( 0, reliable );

        const unreliable = messageFactory.CreateMessage( TEST_MESSAGE ) as TestMessage;
        unreliable.sequence = 1;
        releaseConnection.SendMessage( 1, unreliable );
        const packetData = new Uint8Array( connectionConfig.maxPacketSize );
        releaseConnection.GeneratePacket( null, 0, packetData, connectionConfig.maxPacketSize, { packetBytes: 0 } );

        check( releaseConnection.GetChannelErrorLevel( 0 ) === CHANNEL_ERROR_MESSAGE_TOO_LARGE );
        check( releaseConnection.GetChannelErrorLevel( 1 ) === CHANNEL_ERROR_MESSAGE_TOO_LARGE );

        releaseConnection.Dispose();
    }
    finally
    {
        yojimbo_set_asserts_enabled_for_test( true );
    }

    connection.Dispose();
    messageFactory.Dispose();
}

function yojimbo_set_asserts_enabled_for_test( enabled: boolean ): void
{
    yojimbo_set_asserts_enabled( enabled );
}

function test_config(): void
{
    // Default configs validate.
    new ConnectionConfig().Validate();
    const config = new ClientServerConfig();
    config.Validate();
    check( config.maxPacketFragments === 8 );
    check( config.protocolId === 0n );
    check( config.channel.length === MaxChannels );
    check( config.channel[0].messageResendTime === Math.fround( 0.1 ) );

    // Clone is deep and keeps the class.
    const copy = config.Clone();
    check( copy instanceof ClientServerConfig );
    check( copy.channel !== config.channel && copy.channel[3] !== config.channel[3] );
    copy.channel[3].maxBlockSize = 7;
    check( config.channel[3].maxBlockSize === 256 * 1024 );

    // Each invalid config prints what is wrong and asserts.
    const expectInvalid = ( name: string, mutate: ( c: ClientServerConfig ) => void ): void =>
    {
        const c = new ClientServerConfig();
        mutate( c );
        const previous = yojimbo_get_assert_function();
        let asserted = 0;
        yojimbo_set_assert_function( () => { asserted++; } );
        try { c.Validate(); } catch { /* assert */ }
        yojimbo_set_assert_function( previous );
        check( asserted === 1, `invalid config detected: ${name}` );
    };

    expectInvalid( "numChannels 0", ( c ) => { c.numChannels = 0; } );
    expectInvalid( "numChannels > MaxChannels", ( c ) => { c.numChannels = MaxChannels + 1; } );
    expectInvalid( "maxPacketSize 0", ( c ) => { c.maxPacketSize = 0; } );
    expectInvalid( "sentPacketBufferSize not a power of two", ( c ) => { c.channel[0].sentPacketBufferSize = 1000; } );
    expectInvalid( "messageSendQueueSize not a power of two", ( c ) => { c.channel[1].messageSendQueueSize = 1000; } );
    expectInvalid( "messageReceiveQueueSize 0", ( c ) => { c.channel[0].messageReceiveQueueSize = 0; } );
    expectInvalid( "maxMessagesPerPacket 0", ( c ) => { c.channel[0].maxMessagesPerPacket = 0; } );
    expectInvalid( "blockFragmentSize > 65535", ( c ) => { c.maxPacketSize = 100000; c.maxPacketFragments = 256; c.packetFragmentSize = 1024; c.channel[0].blockFragmentSize = 70000; } );
    expectInvalid( "blockFragmentSize > maxPacketSize", ( c ) => { c.channel[0].blockFragmentSize = 9000; } );
    expectInvalid( "too many fragments per block", ( c ) => { c.channel[0].maxBlockSize = 2147483647; } );
    expectInvalid( "maxPacketSize raised without maxPacketFragments", ( c ) => { c.maxPacketSize = 16 * 1024; } );
    expectInvalid( "maxPacketFragments > 256", ( c ) => { c.maxPacketFragments = 257; } );
    expectInvalid( "clientMemory 0", ( c ) => { c.clientMemory = 0; } );
    expectInvalid( "maxSimulatorPackets 0", ( c ) => { c.maxSimulatorPackets = 0; } );

    // an unreliable channel is not held to the power of two rules
    const unreliable = new ClientServerConfig();
    unreliable.channel[1].type = CHANNEL_TYPE_UNRELIABLE_UNORDERED;
    unreliable.channel[1].messageSendQueueSize = 1000;
    unreliable.Validate();
}

/*
    Golden bytes for the connection packet, produced by the C++ library (interop/build_cpp.sh, then a generator that
    runs the scenario below against cpp/ and prints every packet). The TypeScript connection must produce exactly the
    same bytes: message and block fragment framing, relative message ids, message types, channel indices, inline
    unreliable blocks, and the float32 resend timing that decides which messages go in which packet.
*/


const GOLDEN_PACKETS: Array<[ string, string ]> = [
    [ "A0",
        "320100e03f000008000000000000000000000000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000008001008000000000000000000000" +
        "0000000000000000000000000000000000000000000000800200000000000080010000380000002000000000000000000000000000001200000000000000000000000000a00390010000000000000000" +
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000005006003003400700630000070e151c232a31383f464d545b" +
        "626970777e858c939aa1a8afb6bdc4cbd2d9e0e7eef5fc030a11181f262d343b424950575e656c737a81888f969da4abb2b9c0c7ced5dce3eaf1f8ff060d141b222930373e454c535a61686f767d848b" +
        "9299a0a7aeb5bc" ],
    [ "A1",
        "314101e03f0a0000000000000000000000c00200000000000000000000000000060000000000000000000000000000000000000000000000000000d000000e00e0010000080000000000000000000000" +
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000220000120060020000" ],
    [ "A2",
        "710200e03fc97f00001000000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000300000100000000000000" +
        "0000000000000000000000000000000000000000000000000000050000000000000003000070000000400000000000000000000000000000240000000000000000000000000000140000000000000050" +
        "01000b00000000000000000000000000000000000000000000000000000000000000000000000000000000002e00000000000000000000000000000000c0000032000000000000000000000000000000" +
        "000000000000000000000000000000000000d0000000000000006c0000000e000040070000000000000000000000000000" ],
    [ "A3",
        "e9012076051e252c333a41484f565d646b727980878e959ca3aab1b8bfc6cdd4dbe2e9f0f7fe050c131a21282f363d444b525960676e757c838a91989fa6adb4bbc2c9d0d7dee5ecf3fa01080f161d24" +
        "2b323940474e555c636a71787f868d949ba2a9b0b7bec5ccd3dae1e8eff6fd040b121920272e353c434a51585f666d747b828990979ea5acb3bac1c8cfd6dde4ebf2f900070e151c232a31383f464d54" +
        "5b626970777e858c939aa1a8afb6bdc4cbd2d9e0e7eef5fc030a11181f262d343b424950575e656c737a81888f969da4abb2b9c0c7ced5dce3eaf1f8ff060d141b222930373e454c535a61686f767d84" +
        "8b9299a0a7aeb5bcc3cad1d8dfe6edf4fb020910171e252c333a41484f565d646b727980878e959ca3aab1b8bfc6cdd4dbe2e9f0f7fe050c131a21282f363d444b525960676e757c838a91989fa6adb4" +
        "bbc2c9d0d7dee5ecf3fa01080f161d242b323940474e555c636a71787f868d949ba2a9b0b7bec5ccd3dae1e8eff6fd040b121920272e353c434a51585f666d747b828990979ea5acb3bac1c8cfd6dde4" +
        "ebf2f900070e151c232a31383f464d545b626970777e858c939aa1a8afb6bdc4cbd2d9e0e7eef5fc030a11181f262d343b424950575e656c737a81888f969da4abb2b9c0c7ced5dce3eaf1f8ff060d14" +
        "1b222930373e454c535a61686f767d848b9299a0a7aeb5bcc3cad1d8dfe6edf4fb020910171e252c333a41484f565d646b727980878e959ca3aab1b8bfc6cdd4dbe2e9f0f7fe050c131a21282f363d44" +
        "4b525960676e757c838a91989fa6adb4bbc2c9d0d7dee5ecf3fa01080f161d242b323940474e555c636a71787f868d949ba2a9b0b7bec5ccd3dae1e8eff6fd040b121920272e353c434a51585f666d74" +
        "7b828990979ea5acb3bac1c8cfd6dde4ebf2f900070e151c232a31383f464d545b626970777e858c939aa1a8afb6bdc4cbd2d9e0e7eef5fc030a11181f262d343b790000" ],
    [ "A4",
        "e901a07605424950575e656c737a81888f969da4abb2b9c0c7ced5dce3eaf1f8ff060d141b222930373e454c535a61686f767d848b9299a0a7aeb5bcc3cad1d8dfe6edf4fb020910171e252c333a4148" +
        "4f565d646b727980878e959ca3aab1b8bfc6cdd4dbe2e9f0f7fe050c131a21282f363d444b525960676e757c838a91989fa6adb4bbc2c9d0d7dee5ecf3fa01080f161d242b323940474e555c636a7178" +
        "7f868d949ba2a9b0b7bec5ccd3dae1e8eff6fd040b121920272e353c434a51585f666d747b828990979ea5acb3bac1c8cfd6dde4ebf2f900070e151c232a31383f464d545b626970777e858c939aa1a8" +
        "afb6bdc4cbd2d9e0e7eef5fc030a11181f262d343b424950575e656c737a81888f969da4abb2b9c0c7ced5dce3eaf1f8ff060d141b222930373e454c535a61686f767d848b9299a0a7aeb5bcc3cad1d8" +
        "dfe6edf4fb020910171e252c333a41484f565d646b727980878e959ca3aab1b8bfc6cdd4dbe2e9f0f7fe050c131a21282f363d444b525960676e757c838a91989fa6adb4bbc2c9d0d7dee5ecf3fa0108" +
        "0f161d242b323940474e555c636a71787f868d949ba2a9b0b7bec5ccd3dae1e8eff6fd040b121920272e353c434a51585f666d747b828990979ea5acb3bac1c8cfd6dde4ebf2f900070e151c232a3138" +
        "3f464d545b626970777e858c939aa1a8afb6bdc4cbd2d9e0e7eef5fc030a11181f262d343b424950575e656c737a81888f969da4abb2b9c0c7ced5dce3eaf1f8ff060d141b222930373e454c535a6168" +
        "6f767d848b9299a0a7aeb5bcc3cad1d8dfe6edf4fb020910171e252c333a41484f565d646b727980878e959ca3aab1b8bfc6cdd4dbe2e9f0f7fe050c131a21282f363d444b525960676e757c838a9198" +
        "9fa6adb4bbc2c9d0d7dee5ecf3fa01080f161d242b323940474e555c636a71787f868d949ba2a9b0b7bec5ccd3dae1e8eff6fd040b121920272e353c434a51585f" ],
    [ "A5",
        "e901207705666d747b828990979ea5acb3bac1c8cfd6dde4ebf2f900070e151c232a31383f464d545b626970777e858c939aa1a8afb6bdc4cbd2d9e0e7eef5fc030a11181f262d343b424950575e656c" +
        "737a81888f969da4abb2b9c0c7ced5dce3eaf1f8ff060d141b222930373e454c535a61686f767d848b9299a0a7aeb5bcc3cad1d8dfe6edf4fb020910171e252c333a41484f565d646b727980878e959c" +
        "a3aab1b8bfc6cdd4dbe2e9f0f7fe050c131a21282f363d444b525960676e757c838a91989fa6adb4bbc2c9d0d7dee5ecf3fa01080f161d242b323940474e555c636a71787f868d949ba2a9b0b7bec5cc" +
        "d3dae1e8eff6fd040b121920272e353c434a51585f666d747b828990979ea5acb3bac1c8cfd6dde4ebf2f900070e151c232a31383f464d545b626970777e858c939aa1a8afb6bdc4cbd2d9e0e7eef5fc" +
        "030a11181f262d343b424950575e656c737a81888f969da4abb2b9c0c7ced5dce3eaf1f8ff060d141b222930373e454c535a61686f767d848b9299a0a7aeb5bcc3cad1d8dfe6edf4fb020910171e252c" +
        "333a41484f565d646b727980878e959ca3aab1b8bfc6cdd4dbe2e9f0f7fe050c131a21282f363d444b525960676e757c838a91989fa6adb4bbc2c9d0d7dee5ecf3fa01080f161d242b323940474e555c" +
        "636a71787f868d949ba2a9b0b7bec5ccd3dae1e8eff6fd040b121920272e353c434a51585f666d747b828990979ea5acb3bac1c8cfd6dde4ebf2f900070e151c232a31383f464d545b626970777e858c" +
        "939aa1a8afb6bdc4cbd2d9e0e7eef5fc030a11181f262d343b424950575e656c737a81888f969da4abb2b9c0c7ced5dce3eaf1f8ff060d141b222930373e454c535a61686f767d848b9299a0a7aeb5bc" +
        "c3cad1d8dfe6edf4fb020910171e252c333a41484f565d646b727980878e959ca3aab1b8bfc6cdd4dbe2e9f0f7fe050c131a21282f363d444b525960676e757c83" ],
    [ "A6",
        "11e003800f000000000000000000000000" ],
    [ "B0",
        "2d0000f801000000000000000000000000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000000" +
        "070000400100000000000000000000001a008000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
        "0000000000" ],
];

function test_connection_packet_golden_bytes(): void
{
    const generated = GenerateGoldenScenario();
    check( generated.length === GOLDEN_PACKETS.length, "number of golden packets" );
    for ( let i = 0; i < generated.length; ++i )
    {
        const [ name, expected ] = GOLDEN_PACKETS[i];
        const [ generatedName, actual ] = generated[i];
        check( name === generatedName );
        if ( actual !== expected )
        {
            console.log( `golden packet ${name} differs:\n  expected ${expected}\n  actual   ${actual}` );
        }
        check( actual === expected, `golden packet ${name} matches the C++ bytes` );
    }
}

function hex( data: Uint8Array, bytes: number ): string
{
    let text = "";
    for ( let i = 0; i < bytes; ++i )
        text += data[i].toString( 16 ).padStart( 2, "0" );
    return text;
}

function GenerateGoldenScenario(): Array<[ string, string ]>
{
    const packets: Array<[ string, string ]> = [];

    const SendTest = ( connection: Connection, factory: MessageFactory, channel: number, sequence: number ): void =>
    {
        const message = factory.CreateMessage( TEST_MESSAGE ) as TestMessage;
        message.sequence = sequence & 0xFFFF;
        connection.SendMessage( channel, message );
    };

    const SendBlock = ( connection: Connection, factory: MessageFactory, channel: number, sequence: number, blockSize: number ): void =>
    {
        const message = factory.CreateMessage( TEST_BLOCK_MESSAGE ) as TestBlockMessage;
        message.sequence = sequence & 0xFFFF;
        const blockData = YOJIMBO_ALLOCATE( factory.GetAllocator(), blockSize )!;
        for ( let i = 0; i < blockSize; ++i )
            blockData[i] = ( i * 7 + sequence ) & 0xFF;
        message.AttachBlock( factory.GetAllocator(), blockData, blockSize );
        connection.SendMessage( channel, message );
    };

    // scenario A
    {
        const factory = new TestMessageFactory( GetDefaultAllocator() );
        const config = new ConnectionConfig();
        config.numChannels = 2;
        config.channel[0].type = CHANNEL_TYPE_RELIABLE_ORDERED;
        config.channel[1].type = CHANNEL_TYPE_UNRELIABLE_UNORDERED;
        config.channel[0].blockFragmentSize = 700;
        config.channel[0].maxBlockSize = 3000;

        let time = 100.0;
        const sender = new Connection( GetDefaultAllocator(), factory, config, time );

        const buffer = new Uint8Array( config.maxPacketSize );
        const out = { packetBytes: 0 };
        let sequence = 0;

        const generate = (): void =>
        {
            sender.GeneratePacket( null, sequence, buffer, config.maxPacketSize, out );
            packets.push( [ `A${sequence}`, hex( buffer, out.packetBytes ) ] );
        };

        for ( let i = 0; i < 10; ++i )
            SendTest( sender, factory, 0, i );
        for ( let i = 0; i < 3; ++i )
            SendTest( sender, factory, 1, 100 + i );
        SendBlock( sender, factory, 1, 7, 100 );

        generate();
        sequence++;

        time += 0.05; sender.AdvanceTime( time );
        for ( let i = 10; i < 20; ++i )
            SendTest( sender, factory, 0, i );

        generate();
        sender.ProcessAcks( [ sequence ] );
        sequence++;

        time += 0.05; sender.AdvanceTime( time );
        for ( let i = 20; i < 30; ++i )
            SendTest( sender, factory, 0, i );

        time += 0.06; sender.AdvanceTime( time );

        generate();
        sender.ProcessAcks( [ sequence ] );
        sequence++;

        SendBlock( sender, factory, 0, 30, 2100 );
        SendTest( sender, factory, 0, 31 );

        for ( let i = 0; i < 4; ++i )
        {
            time += 0.1; sender.AdvanceTime( time );
            generate();
            sender.ProcessAcks( [ sequence ] );
            sequence++;
        }

        sender.Dispose();
        factory.Dispose();
    }

    // scenario B
    {
        const factory = new SingleTestMessageFactory( GetDefaultAllocator() );
        const config = new ConnectionConfig();
        config.numChannels = 1;
        config.channel[0].type = CHANNEL_TYPE_RELIABLE_ORDERED;

        const sender = new Connection( GetDefaultAllocator(), factory, config, 50.0 );

        const buffer = new Uint8Array( 2048 );
        const out = { packetBytes: 0 };

        for ( let i = 0; i < 6; ++i )
        {
            const message = factory.CreateMessage( SINGLE_TEST_MESSAGE ) as TestMessage;
            message.sequence = i * 3 + 1;
            sender.SendMessage( 0, message );
        }

        sender.GeneratePacket( null, 0, buffer, buffer.length, out );
        packets.push( [ "B0", hex( buffer, out.packetBytes ) ] );

        sender.Dispose();
        factory.Dispose();
    }

    return packets;
}


// ---------------------------------------------------------------------------------------------
// Client / server tests (real UDP sockets on 127.0.0.1, so they are async: every pump yields to the event loop)

// event loop turns each test pump yields so the sockets can deliver what was just sent. node reads at most 32
// datagrams per socket per turn on macOS/linux and one on windows, so yielding for a fixed time can leave a server fed
// by 32 clients with a growing receive backlog on a slow machine (seen in CI as 10-12 s of simulated rtt in
// test_client_server_start_stop_restart). a fixed number of turns drains far more than arrives on every platform
const PumpEventLoopTurns = 64;

function YieldEventLoopTurn(): Promise<void>
{
    return new Promise<void>( resolve => setImmediate( resolve ) );
}

class TimeState
{
    time = 100.0;
}

async function PumpClientServerUpdate( state: TimeState, client: Client[], numClients: number, server: Server[], numServers: number, deltaTime: number = Math.fround( 0.1 ) ): Promise<void>
{
    for ( let i = 0; i < numClients; ++i )
        client[i].SendPackets();

    for ( let i = 0; i < numServers; ++i )
        server[i].SendPackets();

    for ( let i = 0; i < numClients; ++i )
        client[i].ReceivePackets();

    for ( let i = 0; i < numServers; ++i )
        server[i].ReceivePackets();

    state.time += deltaTime;

    for ( let i = 0; i < numClients; ++i )
        client[i].AdvanceTime( state.time );

    for ( let i = 0; i < numServers; ++i )
        server[i].AdvanceTime( state.time );

    // the sockets are real but the clock is simulated: let the event loop deliver what was just sent, or the
    // simulated clock outruns delivery
    for ( let turn = 0; turn < PumpEventLoopTurns; ++turn )
        await YieldEventLoopTurn();
}

function SendClientToServerMessages( client: Client, numMessagesToSend: number, channelIndex: number = ReliableChannel ): void
{
    for ( let i = 0; i < numMessagesToSend; ++i )
    {
        if ( !client.CanSendMessage( channelIndex ) )
            break;

        if ( yojimbo_rand() % 10 )
        {
            const message = client.CreateMessage( TEST_MESSAGE ) as TestMessage;
            check( message );
            message.sequence = i;
            client.SendMessage( channelIndex, message );
        }
        else
        {
            const message = client.CreateMessage( TEST_BLOCK_MESSAGE ) as TestBlockMessage;
            check( message );
            message.sequence = i;
            const blockSize = 1 + ( ( i * 901 ) % 1001 );
            const blockData = client.AllocateBlock( blockSize );
            check( blockData );
            for ( let j = 0; j < blockSize; ++j )
                blockData[j] = ( i + j ) & 0xFF;
            client.AttachBlockToMessage( message, blockData, blockSize );
            client.SendMessage( channelIndex, message );
        }
    }
}

function SendServerToClientMessages( server: Server, clientIndex: number, numMessagesToSend: number, channelIndex: number = ReliableChannel ): void
{
    for ( let i = 0; i < numMessagesToSend; ++i )
    {
        if ( !server.CanSendMessage( clientIndex, channelIndex ) )
            break;

        if ( yojimbo_rand() % 10 )
        {
            const message = server.CreateMessage( clientIndex, TEST_MESSAGE ) as TestMessage;
            check( message );
            message.sequence = i;
            server.SendMessage( clientIndex, channelIndex, message );
        }
        else
        {
            const message = server.CreateMessage( clientIndex, TEST_BLOCK_MESSAGE ) as TestBlockMessage;
            check( message );
            message.sequence = i;
            const blockSize = 1 + ( ( i * 901 ) % 1001 );
            const blockData = server.AllocateBlock( clientIndex, blockSize );
            check( blockData );
            for ( let j = 0; j < blockSize; ++j )
                blockData[j] = ( i + j ) & 0xFF;
            server.AttachBlockToMessage( clientIndex, message, blockData, blockSize );
            server.SendMessage( clientIndex, channelIndex, message );
        }
    }
}

function CheckClientServerMessage( message: Message, expected: number ): void
{
    check( message.GetId() === expected );

    switch ( message.GetType() )
    {
        case TEST_MESSAGE:
        {
            check( !message.IsBlockMessage() );
            check( ( message as TestMessage ).sequence === ( expected & 0xFFFF ) );
        }
        break;

        case TEST_BLOCK_MESSAGE:
        {
            check( message.IsBlockMessage() );
            const blockMessage = message as TestBlockMessage;
            check( blockMessage.sequence === ( expected & 0xFFFF ) );
            CheckTestBlock( blockMessage, 1 + ( ( expected * 901 ) % 1001 ), expected );
        }
        break;
    }
}

function ProcessServerToClientMessages( client: Client, received: { count: number }, channelIndex: number = ReliableChannel ): void
{
    while ( true )
    {
        const message = client.ReceiveMessage( channelIndex );

        if ( !message )
            break;

        CheckClientServerMessage( message, received.count );
        ++received.count;

        client.ReleaseMessage( message );
    }
}

function ProcessClientToServerMessages( server: Server, clientIndex: number, received: { count: number }, channelIndex: number = ReliableChannel ): void
{
    while ( true )
    {
        const message = server.ReceiveMessage( clientIndex, channelIndex );

        if ( !message )
            break;

        CheckClientServerMessage( message, received.count );
        ++received.count;

        server.ReleaseMessage( clientIndex, message );
    }
}

/** Pump until the client connects (or fails). Returns client.IsConnected(). */

async function ConnectClient( state: TimeState, client: Client, server: Server, NumIterations: number = 10000 ): Promise<boolean>
{
    for ( let i = 0; i < NumIterations; ++i )
    {
        await PumpClientServerUpdate( state, [ client ], 1, [ server ], 1 );

        if ( client.ConnectionFailed() )
            break;

        if ( !client.IsConnecting() && client.IsConnected() && server.GetNumConnectedClients() === 1 )
            break;
    }
    return client.IsConnected();
}

/** Pump until the client is disconnected and the server has no clients. */

async function DisconnectClientAndWait( state: TimeState, client: Client, server: Server, NumIterations: number = 10000 ): Promise<void>
{
    for ( let i = 0; i < NumIterations; ++i )
    {
        await PumpClientServerUpdate( state, [ client ], 1, [ server ], 1 );

        if ( !client.IsConnected() && server.GetNumConnectedClients() === 0 )
            break;
    }
}

function CheckConnected( client: Client, server: Server ): void
{
    check( !client.IsConnecting() );
    check( client.IsConnected() );
    check( server.GetNumConnectedClients() === 1 );
    check( client.GetClientIndex() === 0 );
    check( server.IsClientConnected( 0 ) );
}

const privateKey = new Uint8Array( KeyBytes );

/** Adapter whose factory methods can be made to fail, so the transactional startup paths are exercised. */

class FailingFactoryAdapter extends TestAdapter
{
    private m_allocatorsUntilFail = -1;
    private m_factoriesUntilFail = -1;

    FailAllocatorAfter( n: number ): void { this.m_allocatorsUntilFail = n; }
    FailMessageFactoryAfter( n: number ): void { this.m_factoriesUntilFail = n; }

    override CreateAllocator( allocator: Allocator, memory: Uint8Array | null, bytes: number ): Allocator | null
    {
        if ( this.m_allocatorsUntilFail === 0 )
            return null;
        if ( this.m_allocatorsUntilFail > 0 )
            this.m_allocatorsUntilFail--;
        return super.CreateAllocator( allocator, memory, bytes );
    }

    override CreateMessageFactory( allocator: Allocator ): MessageFactory | null
    {
        if ( this.m_factoriesUntilFail === 0 )
            return null;
        if ( this.m_factoriesUntilFail > 0 )
            this.m_factoriesUntilFail--;
        return super.CreateMessageFactory( allocator );
    }
}

// The number of startup allocations a sweep is allowed to walk before we call it a runaway.
const MaxStartupAllocations = 64;

function test_interface_methods_link(): void
{
    // YJ-02: every interface method is reachable through the base reference. In TypeScript the interfaces are checked at
    // compile time (Server implements ServerInterface, Client implements ClientInterface); this checks the base
    // references reach the derived implementation.
    const config = new ClientServerConfig();

    const server = new Server( GetDefaultAllocator(), privateKey, new Address( "127.0.0.1", ServerPort ), config, adapter, 100.0 );
    const client = new Client( GetDefaultAllocator(), new Address( "0.0.0.0", 0 ), config, adapter, 100.0 );

    check( server.Start( 1 ) );
    const serverInterface: ServerInterface = server;
    check( serverInterface.GetClientUserData( 0 ) === server.GetClientUserData( 0 ) );
    check( serverInterface.GetClientAddress( 0 ) === server.GetClientAddress( 0 ) );
    check( serverInterface.GetMaxClients() === 1 );
    server.Stop();

    const clientInterface: ClientInterface = client;
    check( clientInterface.GetClientState() === client.GetClientState() );

    client.Dispose();
    server.Dispose();
}

function test_server_start_alloc_failure(): void
{
    // YJ-01: fail at allocation N for every N up to the first N that succeeds: each failure must return false, leave the
    // server stopped, and free everything already taken.
    const serverAddress = new Address( "127.0.0.1", ServerPort );

    const config = new ClientServerConfig();

    let n = 0;
    for ( ; n < MaxStartupAllocations; ++n )
    {
        const allocator = new ArmableAllocator();
        {
            const server = new Server( allocator, privateKey, serverAddress, config, adapter, 100.0 );
            allocator.Arm( n );
            const started = server.Start( 2 );
            allocator.Disarm();
            if ( started )
            {
                check( server.IsRunning() );
                server.Stop();
                check( !server.IsRunning() );
                server.Dispose();
                check( allocator.GetOutstanding() === 0 );
                allocator.Dispose();
                break;
            }
            check( !server.IsRunning() );           // no half-built server left behind
            check( server.GetMaxClients() === 0 );
            server.Dispose();
        }
        check( allocator.GetOutstanding() === 0 );   // everything already allocated was unwound
        allocator.Dispose();
    }
    check( n > 0 );                                 // the sweep really did force failures
    check( n < MaxStartupAllocations );             // ...and a fully armed start eventually succeeds
}

function test_server_start_factory_failure(): void
{
    const serverAddress = new Address( "127.0.0.1", ServerPort );

    const config = new ClientServerConfig();

    // allocator index 0 is the global allocator, 1 and 2 are the two per-client allocators
    for ( let n = 0; n < 3; ++n )
    {
        const allocator = new ArmableAllocator();
        {
            const failingAdapter = new FailingFactoryAdapter();
            failingAdapter.FailAllocatorAfter( n );
            const server = new Server( allocator, privateKey, serverAddress, config, failingAdapter, 100.0 );
            check( !server.Start( 2 ) );
            check( !server.IsRunning() );
            server.Dispose();
        }
        check( allocator.GetOutstanding() === 0 );
        allocator.Dispose();
    }

    for ( let n = 0; n < 2; ++n )
    {
        const allocator = new ArmableAllocator();
        {
            const failingAdapter = new FailingFactoryAdapter();
            failingAdapter.FailMessageFactoryAfter( n );
            const server = new Server( allocator, privateKey, serverAddress, config, failingAdapter, 100.0 );
            check( !server.Start( 2 ) );
            check( !server.IsRunning() );
            server.Dispose();
        }
        check( allocator.GetOutstanding() === 0 );
        allocator.Dispose();
    }
}

function test_client_connect_alloc_failure(): void
{
    // YJ-01 on the client side: every failure point returns false, leaves the client disconnected with an
    // out-of-memory reason, and leaks nothing.
    const clientAddress = new Address( "0.0.0.0", 0 );
    const serverAddress = new Address( "127.0.0.1", ServerPort );

    const config = new ClientServerConfig();

    let n = 0;
    for ( ; n < MaxStartupAllocations; ++n )
    {
        const allocator = new ArmableAllocator();
        let connected = false;
        {
            const client = new Client( allocator, clientAddress, config, adapter, 100.0 );
            allocator.Arm( n );
            const connecting = client.InsecureConnect( privateKey, 1n, serverAddress );
            allocator.Disarm();
            if ( connecting )
            {
                check( client.IsConnecting() );
                client.Disconnect();
                connected = true;
            }
            else
            {
                check( !client.IsConnecting() );
                check( !client.IsConnected() );
                check( client.ConnectionFailed() );
                check( client.GetDisconnectReason() === YOJIMBO_CLIENT_DISCONNECT_REASON_OUT_OF_MEMORY );
            }
            client.Dispose();
        }
        check( allocator.GetOutstanding() === 0 );
        allocator.Dispose();
        if ( connected )
            break;
    }
    check( n > 0 );
    check( n < MaxStartupAllocations );
}

function test_client_connect_factory_failure(): void
{
    const clientAddress = new Address( "0.0.0.0", 0 );
    const serverAddress = new Address( "127.0.0.1", ServerPort );

    const config = new ClientServerConfig();

    {
        const allocator = new ArmableAllocator();
        {
            const failingAdapter = new FailingFactoryAdapter();
            failingAdapter.FailAllocatorAfter( 0 );
            const client = new Client( allocator, clientAddress, config, failingAdapter, 100.0 );
            check( !client.InsecureConnect( privateKey, 1n, serverAddress ) );
            check( client.ConnectionFailed() );
            client.Dispose();
        }
        check( allocator.GetOutstanding() === 0 );
        allocator.Dispose();
    }

    {
        const allocator = new ArmableAllocator();
        {
            const failingAdapter = new FailingFactoryAdapter();
            failingAdapter.FailMessageFactoryAfter( 0 );
            const client = new Client( allocator, clientAddress, config, failingAdapter, 100.0 );
            check( !client.InsecureConnect( privateKey, 1n, serverAddress ) );
            check( client.ConnectionFailed() );
            client.Dispose();
        }
        check( allocator.GetOutstanding() === 0 );
        allocator.Dispose();
    }
}

function test_client_connect_socket_failure_no_crash(): void
{
    // Connect() and ConnectLoopback() must bail when the socket can't be created (forced here with an unparseable
    // bind address) instead of calling into netcode with no client.
    const config = new ClientServerConfig();

    const invalidAddress = new Address();       // ADDRESS_NONE -> "NONE" -> netcode_client_create fails
    check( !invalidAddress.IsValid() );

    const client = new Client( GetDefaultAllocator(), invalidAddress, config, adapter, 100.0 );

    const connectToken = new Uint8Array( ConnectTokenBytes );

    client.Connect( 1n, connectToken );         // must not crash - CreateClient failed
    check( !client.IsConnected() );

    client.ConnectLoopback( 0, 1n, 1 );         // must not crash either
    check( !client.IsConnected() );

    client.Disconnect();
    client.Dispose();
}

function test_client_is_loopback_when_disconnected(): void
{
    const config = new ClientServerConfig();
    const clientAddress = new Address( "0.0.0.0", ClientPort );
    const client = new Client( GetDefaultAllocator(), clientAddress, config, adapter, 100.0 );

    check( !client.IsLoopback() );              // must not crash; not connected -> not a loopback client
    check( client.GetClientIndex() === -1 );
    check( !client.IsConnected() );

    client.Dispose();
}

async function test_client_connect_twice_with_one_connect_token(): Promise<void>
{
    // A connect token is spent by the connection it admits: once the server has accepted a client holding it,
    // presenting the same token again connects nothing, from the same address, after the client's slot is free again.
    const clientId = 1n;

    const clientAddress = new Address( "0.0.0.0", ClientPort );
    const serverAddress = new Address( "127.0.0.1", ServerPort );

    const state = new TimeState();

    const config = new ClientServerConfig();
    config.timeout = 2;

    const server = new Server( GetDefaultAllocator(), privateKey, serverAddress, config, adapter, state.time );

    check( server.Start( MaxClients ) );

    const serverAddressStrings = [ serverAddress.ToString() ];

    const userData = new Uint8Array( 256 );

    const connectToken = new Uint8Array( ConnectTokenBytes );
    check( netcode_generate_connect_token( 1,
                                           serverAddressStrings,
                                           serverAddressStrings,
                                           InsecureConnectTokenExpirySeconds,
                                           config.timeout,
                                           clientId,
                                           config.protocolId,
                                           privateKey,
                                           userData,
                                           connectToken ) === NETCODE_OK );

    const NumIterations = 1000;

    const client = new Client( GetDefaultAllocator(), clientAddress, config, adapter, state.time );

    // First use of the token connects.

    check( client.Connect( clientId, connectToken ) );

    check( await ConnectClient( state, client, server, NumIterations ) );

    check( client.IsConnected() );
    check( server.GetNumConnectedClients() === 1 );
    check( client.GetClientIndex() === 0 );

    server.DisconnectClient( 0 );

    await DisconnectClientAndWait( state, client, server, NumIterations );

    check( !client.IsConnected() );
    check( server.GetNumConnectedClients() === 0 );

    // Second use of the same token connects nothing.

    check( client.Connect( clientId, connectToken ) );

    for ( let i = 0; i < NumIterations; ++i )
    {
        await PumpClientServerUpdate( state, [ client ], 1, [ server ], 1 );

        if ( client.ConnectionFailed() )
            break;

        check( !client.IsConnected() );
        check( server.GetNumConnectedClients() === 0 );
    }

    check( client.ConnectionFailed() );
    check( !client.IsConnected() );
    check( server.GetNumConnectedClients() === 0 );
    check( client.GetDisconnectReason() === YOJIMBO_CLIENT_DISCONNECT_REASON_CONNECTION_REQUEST_TIMED_OUT );

    client.Disconnect();
    server.Stop();
    client.Dispose();
    server.Dispose();
}

async function test_client_server_messages(): Promise<void>
{
    const clientId = 1n;

    const clientAddress = new Address( "0.0.0.0", ClientPort );
    const serverAddress = new Address( "127.0.0.1", ServerPort );

    const state = new TimeState();

    const config = new ClientServerConfig();
    config.channel[0].messageSendQueueSize = 32;
    config.channel[0].maxMessagesPerPacket = 8;
    config.channel[0].maxBlockSize = 1024;
    config.channel[0].blockFragmentSize = 200;

    const client = new Client( GetDefaultAllocator(), clientAddress, config, adapter, state.time );

    const server = new Server( GetDefaultAllocator(), privateKey, serverAddress, config, adapter, state.time );

    server.Start( MaxClients );

    server.SetLatency( 250 );
    server.SetJitter( 100 );
    server.SetPacketLoss( 25 );
    server.SetDuplicates( 25 );

    for ( let iteration = 0; iteration < 2; ++iteration )
    {
        // connect and wait until connection completes

        client.InsecureConnect( privateKey, clientId, serverAddress );

        client.SetLatency( 250 );
        client.SetJitter( 100 );
        client.SetPacketLoss( 25 );
        client.SetDuplicates( 25 );

        const NumIterations = 10000;

        await ConnectClient( state, client, server, NumIterations );

        CheckConnected( client, server );

        // send a bunch of messages and pump until they are received

        const NumMessagesSent = config.channel[0].messageSendQueueSize;

        SendClientToServerMessages( client, NumMessagesSent );

        SendServerToClientMessages( server, client.GetClientIndex(), NumMessagesSent );

        const fromClient = { count: 0 };
        const fromServer = { count: 0 };

        for ( let i = 0; i < NumIterations; ++i )
        {
            await PumpClientServerUpdate( state, [ client ], 1, [ server ], 1 );

            if ( !client.IsConnected() )
                break;

            ProcessServerToClientMessages( client, fromServer );

            ProcessClientToServerMessages( server, client.GetClientIndex(), fromClient );

            if ( fromClient.count === NumMessagesSent && fromServer.count === NumMessagesSent )
                break;
        }

        check( client.IsConnected() );
        check( server.IsClientConnected( client.GetClientIndex() ) );
        check( fromClient.count === NumMessagesSent );
        check( fromServer.count === NumMessagesSent );

        // disconnect and pump until client disconnects

        client.Disconnect();

        await DisconnectClientAndWait( state, client, server, NumIterations );

        check( !client.IsConnected() && server.GetNumConnectedClients() === 0 );
    }

    server.Stop();
    client.Dispose();
    server.Dispose();
}

function AllClientsConnected( numClients: number, server: Server, clients: Client[] ): boolean
{
    if ( server.GetNumConnectedClients() !== numClients )
        return false;

    for ( let i = 0; i < numClients; ++i )
    {
        if ( !clients[i].IsConnected() )
            return false;
    }

    return true;
}

function AnyClientDisconnected( numClients: number, clients: Client[] ): boolean
{
    for ( let i = 0; i < numClients; ++i )
    {
        if ( clients[i].IsDisconnected() )
            return true;
    }

    return false;
}

async function test_client_server_start_stop_restart(): Promise<void>
{
    const clientAddress = new Address( "0.0.0.0", 0 );
    const serverAddress = new Address( "127.0.0.1", ServerPort );

    const state = new TimeState();

    const config = new ClientServerConfig();
    config.channel[0].messageSendQueueSize = 32;
    config.channel[0].maxMessagesPerPacket = 8;
    config.channel[0].maxBlockSize = 1024;
    config.channel[0].blockFragmentSize = 200;

    const server = new Server( GetDefaultAllocator(), privateKey, serverAddress, config, adapter, state.time );

    const numClients = [ 3, 5, 1, 32, 5 ];

    for ( let iteration = 0; iteration < numClients.length; ++iteration )
    {
        numClients[iteration] = numClients[iteration] % MaxClients;
        if ( numClients[iteration] === 0 )
            numClients[iteration] = 1;

        const count = numClients[iteration];

        server.Start( count );

        server.SetLatency( 250 );
        server.SetJitter( 100 );
        server.SetPacketLoss( 25 );
        server.SetDuplicates( 25 );

        const clients: Client[] = [];

        for ( let i = 0; i < count; ++i )
            clients.push( new Client( GetDefaultAllocator(), clientAddress, config, adapter, state.time ) );

        for ( let i = 0; i < count; ++i )
        {
            clients[i].InsecureConnect( privateKey, BigInt( i + 1 ), serverAddress );
            clients[i].SetLatency( 250 );
            clients[i].SetJitter( 100 );
            clients[i].SetPacketLoss( 25 );
            clients[i].SetDuplicates( 25 );
        }

        while ( true )
        {
            await PumpClientServerUpdate( state, clients, count, [ server ], 1 );

            if ( AnyClientDisconnected( count, clients ) )
                break;

            if ( AllClientsConnected( count, server, clients ) )
                break;
        }

        check( AllClientsConnected( count, server, clients ) );

        const NumMessagesSent = config.channel[0].messageSendQueueSize;

        for ( let clientIndex = 0; clientIndex < count; ++clientIndex )
        {
            SendClientToServerMessages( clients[clientIndex], NumMessagesSent );
            SendServerToClientMessages( server, clientIndex, NumMessagesSent );
        }

        const fromClient = Array.from( { length: MaxClients }, () => ( { count: 0 } ) );
        const fromServer = Array.from( { length: MaxClients }, () => ( { count: 0 } ) );

        const NumInternalIterations = 10000;

        for ( let i = 0; i < NumInternalIterations; ++i )
        {
            await PumpClientServerUpdate( state, clients, count, [ server ], 1 );

            let allMessagesReceived = true;

            for ( let j = 0; j < count; ++j )
            {
                ProcessServerToClientMessages( clients[j], fromServer[j] );

                if ( fromServer[j].count !== NumMessagesSent )
                    allMessagesReceived = false;

                const clientIndex = clients[j].GetClientIndex();

                ProcessClientToServerMessages( server, clientIndex, fromClient[clientIndex] );

                if ( fromClient[clientIndex].count !== NumMessagesSent )
                    allMessagesReceived = false;
            }

            if ( allMessagesReceived )
                break;
        }

        // a timing dependent failure has been seen only on windows CI: say where the messages stopped before failing

        let complete = true;
        for ( let j = 0; j < count; ++j )
        {
            const clientIndex = clients[j].GetClientIndex();
            if ( fromClient[clientIndex].count !== NumMessagesSent || fromServer[j].count !== NumMessagesSent )
                complete = false;
        }
        if ( !complete )
        {
            console.log( `    iteration ${iteration}: ${count} clients, simulated time ${state.time.toFixed( 1 )}` );
            for ( let j = 0; j < count; ++j )
            {
                const clientIndex = clients[j].GetClientIndex();
                const clientInfo = new NetworkInfo();
                const serverInfo = new NetworkInfo();
                clients[j].GetNetworkInfo( clientInfo );
                if ( clientIndex >= 0 && server.IsClientConnected( clientIndex ) )
                    server.GetNetworkInfo( clientIndex, serverInfo );
                console.log( `    client ${j} (index ${clientIndex}): state ${clients[j].GetClientState()} reason ${clients[j].GetDisconnectReason()}` +
                             ` server connected ${clientIndex >= 0 && server.IsClientConnected( clientIndex )}` +
                             ` received from client ${clientIndex >= 0 ? fromClient[clientIndex].count : -1}/${NumMessagesSent}` +
                             ` from server ${fromServer[j].count}/${NumMessagesSent}` +
                             ` | client sent ${clientInfo.numPacketsSent} received ${clientInfo.numPacketsReceived} acked ${clientInfo.numPacketsAcked} rtt ${clientInfo.RTT.toFixed( 0 )} loss ${clientInfo.packetLoss.toFixed( 0 )}` +
                             ` | server sent ${serverInfo.numPacketsSent} received ${serverInfo.numPacketsReceived} acked ${serverInfo.numPacketsAcked} rtt ${serverInfo.RTT.toFixed( 0 )}` );
            }
        }

        for ( let clientIndex = 0; clientIndex < count; ++clientIndex )
        {
            check( fromClient[clientIndex].count === NumMessagesSent );
            check( fromServer[clientIndex].count === NumMessagesSent );
        }

        for ( let i = 0; i < count; ++i )
        {
            clients[i].Disconnect();
            clients[i].Dispose();
        }

        server.Stop();
    }

    server.Dispose();
}

async function RunFailedToSerializeTest( channelType: typeof CHANNEL_TYPE_RELIABLE_ORDERED | typeof CHANNEL_TYPE_UNRELIABLE_UNORDERED, direction: 'client' | 'server', messageType: number, checkReason: ( client: Client, server: Server ) => void ): Promise<void>
{
    const clientId = 1n;

    const clientAddress = new Address( "0.0.0.0", ClientPort );
    const serverAddress = new Address( "127.0.0.1", ServerPort );

    const state = new TimeState();

    const config = new ClientServerConfig();
    config.maxPacketSize = 1100;
    config.numChannels = 1;
    config.channel[0].type = channelType;
    config.channel[0].maxBlockSize = 1024;
    config.channel[0].blockFragmentSize = 200;

    const server = new Server( GetDefaultAllocator(), privateKey, serverAddress, config, adapter, state.time );

    server.Start( MaxClients );

    const client = new Client( GetDefaultAllocator(), clientAddress, config, adapter, state.time );

    client.InsecureConnect( privateKey, clientId, serverAddress );

    await ConnectClient( state, client, server );

    CheckConnected( client, server );

    // send a message that fails on read (or exhausts the stream allocator), this should disconnect the client

    const unreliable = channelType === CHANNEL_TYPE_UNRELIABLE_UNORDERED;

    if ( !unreliable )
    {
        const message = direction === 'client' ? client.CreateMessage( messageType ) : server.CreateMessage( 0, messageType );
        check( message );
        if ( direction === 'client' )
            client.SendMessage( 0, message );
        else
            server.SendMessage( 0, 0, message );
    }

    for ( let i = 0; i < 256; ++i )
    {
        if ( unreliable && client.IsConnected() )
        {
            const message = client.CreateMessage( messageType );
            check( message );
            client.SendMessage( 0, message );
        }

        await PumpClientServerUpdate( state, [ client ], 1, [ server ], 1 );

        if ( direction === 'server' ? !client.IsConnected() : ( !client.IsConnected() && server.GetNumConnectedClients() === 0 ) )
            break;
    }

    check( !client.IsConnected() );
    if ( direction === 'client' )
        check( server.GetNumConnectedClients() === 0 );

    checkReason( client, server );

    client.Disconnect();

    server.Stop();

    client.Dispose();
    server.Dispose();
}

async function test_client_server_message_failed_to_serialize_reliable_ordered(): Promise<void>
{
    await RunFailedToSerializeTest( CHANNEL_TYPE_RELIABLE_ORDERED, 'client', TEST_SERIALIZE_FAIL_ON_READ_MESSAGE, () => {} );
}

async function test_server_client_disconnect_reason_failed_to_serialize(): Promise<void>
{
    await RunFailedToSerializeTest( CHANNEL_TYPE_RELIABLE_ORDERED, 'client', TEST_SERIALIZE_FAIL_ON_READ_MESSAGE, ( _client, server ) =>
    {
        check( server.GetClientDisconnectReason( 0 ) === YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_FAILED_TO_SERIALIZE );
    } );
}

async function test_client_disconnect_reason_failed_to_serialize(): Promise<void>
{
    await RunFailedToSerializeTest( CHANNEL_TYPE_RELIABLE_ORDERED, 'server', TEST_SERIALIZE_FAIL_ON_READ_MESSAGE, ( client ) =>
    {
        check( client.GetDisconnectReason() === YOJIMBO_CLIENT_DISCONNECT_REASON_FAILED_TO_SERIALIZE );
    } );
}

async function test_client_server_message_failed_to_serialize_unreliable_unordered(): Promise<void>
{
    await RunFailedToSerializeTest( CHANNEL_TYPE_UNRELIABLE_UNORDERED, 'client', TEST_SERIALIZE_FAIL_ON_READ_MESSAGE, () => {} );
}

async function test_client_server_message_exhaust_stream_allocator(): Promise<void>
{
    await RunFailedToSerializeTest( CHANNEL_TYPE_RELIABLE_ORDERED, 'client', TEST_EXHAUST_STREAM_ALLOCATOR_ON_READ_MESSAGE, () => {} );
}

async function test_server_client_disconnect_reason(): Promise<void>
{
    const clientId = 1n;

    const clientAddress = new Address( "0.0.0.0", ClientPort );
    const serverAddress = new Address( "127.0.0.1", ServerPort );

    const state = new TimeState();

    const config = new ClientServerConfig();

    const server = new Server( GetDefaultAllocator(), privateKey, serverAddress, config, adapter, state.time );

    server.Start( MaxClients );

    // all client slots are cleared to none at server start

    for ( let i = 0; i < MaxClients; ++i )
        check( server.GetClientDisconnectReason( i ) === YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_NONE );

    const client = new Client( GetDefaultAllocator(), clientAddress, config, adapter, state.time );

    const NumIterations = 10000;

    // connect a client. while it is connected the reason stays none

    client.InsecureConnect( privateKey, clientId, serverAddress );

    await ConnectClient( state, client, server, NumIterations );

    check( client.IsConnected() );
    check( server.IsClientConnected( 0 ) );
    check( server.GetClientDisconnectReason( 0 ) === YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_NONE );

    // kick the client. the reason is recorded immediately, before the adapter callback fires

    server.DisconnectClient( 0 );

    check( server.GetClientDisconnectReason( 0 ) === YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_KICKED );

    for ( let i = 0; i < NumIterations; ++i )
    {
        await PumpClientServerUpdate( state, [ client ], 1, [ server ], 1 );

        if ( !client.IsConnected() )
            break;
    }

    check( !client.IsConnected() );
    check( server.GetClientDisconnectReason( 0 ) === YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_KICKED );

    // reconnect. a new client connecting to the slot clears the reason back to none

    client.InsecureConnect( privateKey, clientId, serverAddress );

    await ConnectClient( state, client, server, NumIterations );

    check( client.IsConnected() );
    check( server.IsClientConnected( 0 ) );
    check( server.GetClientDisconnectReason( 0 ) === YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_NONE );

    // clean client-side disconnect is recorded as disconnected, distinct from a timeout

    client.Disconnect();

    for ( let i = 0; i < NumIterations; ++i )
    {
        await PumpClientServerUpdate( state, [ client ], 1, [ server ], 1 );

        if ( server.GetNumConnectedClients() === 0 )
            break;
    }

    check( server.GetNumConnectedClients() === 0 );
    check( server.GetClientDisconnectReason( 0 ) === YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_DISCONNECTED );

    // reconnect, then let the client go silent. the server times it out and records that as timed out

    client.InsecureConnect( privateKey, clientId, serverAddress );

    await ConnectClient( state, client, server, NumIterations );

    check( client.IsConnected() );
    check( server.GetClientDisconnectReason( 0 ) === YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_NONE );

    for ( let i = 0; i < NumIterations; ++i )
    {
        await PumpClientServerUpdate( state, [], 0, [ server ], 1 );

        if ( server.GetNumConnectedClients() === 0 )
            break;
    }

    check( server.GetNumConnectedClients() === 0 );
    check( server.GetClientDisconnectReason( 0 ) === YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_TIMED_OUT );

    client.Disconnect();

    // restarting the server clears all slots back to none

    server.Stop();

    server.Start( MaxClients );

    for ( let i = 0; i < MaxClients; ++i )
        check( server.GetClientDisconnectReason( i ) === YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_NONE );

    server.Stop();

    client.Dispose();
    server.Dispose();
}

async function test_client_disconnect_reason(): Promise<void>
{
    const clientId = 1n;

    const clientAddress = new Address( "0.0.0.0", ClientPort );
    const serverAddress = new Address( "127.0.0.1", ServerPort );

    const state = new TimeState();

    const config = new ClientServerConfig();

    const server = new Server( GetDefaultAllocator(), privateKey, serverAddress, config, adapter, state.time );

    server.Start( MaxClients );

    const client = new Client( GetDefaultAllocator(), clientAddress, config, adapter, state.time );

    // no disconnect has happened yet

    check( client.GetDisconnectReason() === YOJIMBO_CLIENT_DISCONNECT_REASON_NONE );

    const NumIterations = 10000;

    // connect. while connected the reason stays none

    client.InsecureConnect( privateKey, clientId, serverAddress );

    await ConnectClient( state, client, server, NumIterations );

    check( client.IsConnected() );
    check( client.GetDisconnectReason() === YOJIMBO_CLIENT_DISCONNECT_REASON_NONE );

    // deliberate local disconnect is recorded immediately

    client.Disconnect();

    check( client.GetDisconnectReason() === YOJIMBO_CLIENT_DISCONNECT_REASON_DISCONNECTED );

    for ( let i = 0; i < NumIterations; ++i )
    {
        await PumpClientServerUpdate( state, [ client ], 1, [ server ], 1 );

        if ( server.GetNumConnectedClients() === 0 )
            break;
    }

    check( server.GetNumConnectedClients() === 0 );

    // reconnect. a new connect attempt clears the reason back to none

    client.InsecureConnect( privateKey, clientId, serverAddress );

    check( client.GetDisconnectReason() === YOJIMBO_CLIENT_DISCONNECT_REASON_NONE );

    await ConnectClient( state, client, server, NumIterations );

    check( client.IsConnected() );

    // when the server kicks us, the client records disconnected by server

    server.DisconnectClient( 0 );

    for ( let i = 0; i < NumIterations; ++i )
    {
        await PumpClientServerUpdate( state, [ client ], 1, [ server ], 1 );

        if ( !client.IsConnected() )
            break;
    }

    check( !client.IsConnected() );
    check( client.GetDisconnectReason() === YOJIMBO_CLIENT_DISCONNECT_REASON_DISCONNECTED_BY_SERVER );

    // connecting to a server that isn't there times out at the connection request stage.

    server.Stop();

    client.InsecureConnect( privateKey, clientId, serverAddress );

    check( client.GetDisconnectReason() === YOJIMBO_CLIENT_DISCONNECT_REASON_NONE );

    for ( let i = 0; i < NumIterations; ++i )
    {
        await PumpClientServerUpdate( state, [ client ], 1, [], 0 );

        if ( client.ConnectionFailed() )
            break;
    }

    check( client.ConnectionFailed() );
    check( client.GetDisconnectReason() === YOJIMBO_CLIENT_DISCONNECT_REASON_CONNECTION_REQUEST_TIMED_OUT );

    client.Disconnect();

    client.Dispose();
    server.Dispose();
}

async function test_client_server_message_receive_queue_overflow(): Promise<void>
{
    const clientId = 1n;

    const clientAddress = new Address( "0.0.0.0", ClientPort );
    const serverAddress = new Address( "127.0.0.1", ServerPort );

    const state = new TimeState();

    const config = new ClientServerConfig();
    config.maxPacketSize = 1100;
    config.numChannels = 1;
    config.channel[0].type = CHANNEL_TYPE_RELIABLE_ORDERED;
    config.channel[0].maxBlockSize = 1024;
    config.channel[0].blockFragmentSize = 200;
    config.channel[0].messageSendQueueSize = 1024;
    config.channel[0].messageReceiveQueueSize = 256;

    const server = new Server( GetDefaultAllocator(), privateKey, serverAddress, config, adapter, state.time );

    server.Start( MaxClients );

    const client = new Client( GetDefaultAllocator(), clientAddress, config, adapter, state.time );

    client.InsecureConnect( privateKey, clientId, serverAddress );

    while ( true )
    {
        await PumpClientServerUpdate( state, [ client ], 1, [ server ], 1 );

        if ( client.ConnectionFailed() )
            break;

        if ( !client.IsConnecting() && client.IsConnected() && server.GetNumConnectedClients() === 1 )
            break;
    }

    CheckConnected( client, server );

    // send a lot of messages, but don't dequeue them: the receiver detects the overflow and disconnects the client

    const NumMessagesSent = config.channel[0].messageSendQueueSize;

    SendClientToServerMessages( client, NumMessagesSent );

    for ( let i = 0; i < NumMessagesSent * 4; ++i )
    {
        await PumpClientServerUpdate( state, [ client ], 1, [ server ], 1 );
        if ( !client.IsConnected() && server.GetNumConnectedClients() === 0 )
            break;              // (upstream pumps all NumMessagesSent * 4 iterations; nothing changes once both sides are disconnected)
    }

    check( !client.IsConnected() );
    check( server.GetNumConnectedClients() === 0 );

    client.Disconnect();

    server.Stop();

    client.Dispose();
    server.Dispose();
}

async function test_reliable_outbound_sequence_outdated(): Promise<void>
{
    const clientId = 1n;

    const clientAddress = new Address( "0.0.0.0", ClientPort );
    const serverAddress = new Address( "127.0.0.1", ServerPort );

    const state = new TimeState();
    const deltaTime = 1.0 / 60.0;

    const config = new ClientServerConfig();
    config.numChannels = 2;
    config.timeout = -1;

    const BlockSize = config.channel[0].blockFragmentSize * 2;

    const client = new Client( GetDefaultAllocator(), clientAddress, config, adapter, state.time );

    const server = new Server( GetDefaultAllocator(), privateKey, serverAddress, config, adapter, state.time );

    server.Start( MaxClients );

    client.InsecureConnect( privateKey, clientId, serverAddress );

    const clients = [ client ];
    const servers = [ server ];

    const NumIterations = 50000;

    await ConnectClient( state, client, server, NumIterations );

    CheckConnected( client, server );

    let numMessagesSent = 0;

    const clientMessage = client.CreateMessage( TEST_MESSAGE ) as TestMessage;
    check( clientMessage );
    client.SendMessage( 0, clientMessage );
    ++numMessagesSent;

    const clientBlockMessage = client.CreateMessage( TEST_BLOCK_MESSAGE ) as TestBlockMessage;
    check( clientBlockMessage );
    const clientBlockData = client.AllocateBlock( BlockSize );
    check( clientBlockData );
    client.AttachBlockToMessage( clientBlockMessage, clientBlockData, BlockSize );
    client.SendMessage( 1, clientBlockMessage );
    ++numMessagesSent;

    // Simulate packet sequence being incremented by unreliable messages until it appears outdated.
    for ( let i = 0; i < 32000; ++i )
    {
        client.SendPackets();
    }
    await PumpClientServerUpdate( state, clients, 1, servers, 1, deltaTime );
    for ( let j = 0; j < 768; ++j )
    {
        client.SendPackets();
    }

    const clientMessage2 = client.CreateMessage( TEST_MESSAGE ) as TestMessage;
    check( clientMessage2 );
    client.SendMessage( 0, clientMessage2 );
    ++numMessagesSent;

    const clientBlockMessage2 = client.CreateMessage( TEST_BLOCK_MESSAGE ) as TestBlockMessage;
    check( clientBlockMessage2 );
    const clientBlockData2 = client.AllocateBlock( BlockSize );
    check( clientBlockData2 );
    client.AttachBlockToMessage( clientBlockMessage2, clientBlockData2, BlockSize );
    client.SendMessage( 1, clientBlockMessage2 );
    ++numMessagesSent;

    let numMessagesReceived = 0;

    for ( let i = 0; i < NumIterations; ++i )
    {
        if ( !client.IsConnected() )
            break;

        await PumpClientServerUpdate( state, clients, 1, servers, 1, deltaTime );

        for ( let channelIndex = 0; channelIndex < config.numChannels; ++channelIndex )
        {
            const messageFromClient = server.ReceiveMessage( 0, channelIndex );
            if ( messageFromClient )
            {
                server.ReleaseMessage( 0, messageFromClient );
                ++numMessagesReceived;
            }
        }

        if ( numMessagesReceived === numMessagesSent )
            break;
    }

    check( client.IsConnected() );
    check( server.IsClientConnected( client.GetClientIndex() ) );
    check( numMessagesReceived === numMessagesSent );

    client.Disconnect();

    await DisconnectClientAndWait( state, client, server, NumIterations );

    check( !client.IsConnected() && server.GetNumConnectedClients() === 0 );

    server.Stop();

    client.Dispose();
    server.Dispose();
}

async function test_client_server_messages_network_sim_leak(): Promise<void>
{
    const clientId = 1n;

    const clientAddress = new Address( "0.0.0.0", ClientPort );
    const serverAddress = new Address( "127.0.0.1", ServerPort );

    const state = new TimeState();

    const config = new ClientServerConfig();
    config.networkSimulator = true;
    config.channel[0].type = CHANNEL_TYPE_UNRELIABLE_UNORDERED;

    const client = new Client( GetDefaultAllocator(), clientAddress, config, adapter, state.time );

    const server = new Server( GetDefaultAllocator(), privateKey, serverAddress, config, adapter, state.time );

    server.Start( MaxClients );

    server.SetLatency( 500 );
    server.SetJitter( 100 );
    server.SetPacketLoss( 5 );
    server.SetDuplicates( 5 );

    for ( let iteration = 0; iteration < 2; ++iteration )
    {
        client.InsecureConnect( privateKey, clientId, serverAddress );

        client.SetLatency( 500 );
        client.SetJitter( 100 );
        client.SetPacketLoss( 5 );
        client.SetDuplicates( 5 );

        const NumIterations = 10000;

        await ConnectClient( state, client, server, NumIterations );

        CheckConnected( client, server );

        const NumMessagesSent = 2000;

        for ( let i = 0; i < NumMessagesSent; ++i )
        {
            if ( !client.CanSendMessage( 0 ) )
                break;
            const message = client.CreateMessage( TEST_MESSAGE ) as TestMessage;
            check( message );
            message.sequence = i & 0xFFFF;
            client.SendMessage( 0, message );
        }

        for ( let i = 0; i < NumMessagesSent; ++i )
        {
            if ( !server.CanSendMessage( client.GetClientIndex(), 0 ) )
                break;
            const message = server.CreateMessage( client.GetClientIndex(), TEST_MESSAGE ) as TestMessage;
            check( message );
            message.sequence = i & 0xFFFF;
            server.SendMessage( client.GetClientIndex(), 0, message );
        }

        for ( let i = 0; i < 100; ++i )
        {
            if ( !client.IsConnected() )
                break;

            await PumpClientServerUpdate( state, [ client ], 1, [ server ], 1 );

            while ( true )
            {
                const message = client.ReceiveMessage( 0 );
                if ( !message )
                    break;
                client.ReleaseMessage( message );
            }

            while ( true )
            {
                const message = server.ReceiveMessage( client.GetClientIndex(), 0 );
                if ( !message )
                    break;
                check( !message.IsBlockMessage() );
                server.ReleaseMessage( client.GetClientIndex(), message );
            }
        }

        check( client.IsConnected() );
        check( server.IsClientConnected( client.GetClientIndex() ) );

        client.Disconnect();

        await DisconnectClientAndWait( state, client, server, NumIterations );

        check( !client.IsConnected() && server.GetNumConnectedClients() === 0 );
    }

    server.Stop();

    client.Dispose();
    server.Dispose();
}

async function test_reliable_fragment_overflow_bug(): Promise<void>
{
    // From the C# port: after an unreliable channel fills its budget, the space left in the packet is not enough for a
    // reliable block fragment, which must then wait for the next packet instead of overflowing the packet buffer.
    const state = new TimeState();

    const config = new ClientServerConfig();
    config.numChannels = 2;
    config.channel[0].type = CHANNEL_TYPE_UNRELIABLE_UNORDERED;
    config.channel[0].packetBudget = 8000;
    config.channel[1].type = CHANNEL_TYPE_RELIABLE_ORDERED;
    config.channel[1].packetBudget = -1;

    const server = new Server( GetDefaultAllocator(), privateKey, new Address( "127.0.0.1", ServerPort ), config, adapter, state.time );

    server.Start( MaxClients );
    check( server.IsRunning() );

    const clientId = new Uint8Array( 8 );
    yojimbo_random_bytes( clientId );

    const client = new Client( GetDefaultAllocator(), new Address( "0.0.0.0" ), config, adapter, state.time );

    const serverAddress = new Address( "127.0.0.1", ServerPort );

    client.InsecureConnect( privateKey, new DataView( clientId.buffer ).getBigUint64( 0, true ), serverAddress );

    const clients = [ client ];
    const servers = [ server ];

    while ( true )
    {
        await PumpClientServerUpdate( state, clients, 1, servers, 1 );

        if ( client.ConnectionFailed() )
            break;

        if ( !client.IsConnecting() && client.IsConnected() && server.GetNumConnectedClients() === 1 )
            break;
    }

    CheckConnected( client, server );

    await PumpClientServerUpdate( state, clients, 1, servers, 1 );
    check( !client.IsDisconnected() );

    // The max packet size is 8192. Fill up the packet so there's still space left, but not enough for a full reliable block fragment.
    let testBlockMessage = client.CreateMessage( TEST_BLOCK_MESSAGE ) as TestBlockMessage;
    let blockData = client.AllocateBlock( 7169 );
    check( blockData );
    client.AttachBlockToMessage( testBlockMessage, blockData, 7169 );
    client.SendMessage( 0, testBlockMessage );      // unreliable channel

    // Send a block message on the reliable channel. The message will be split into 1024 byte fragments.
    testBlockMessage = client.CreateMessage( TEST_BLOCK_MESSAGE ) as TestBlockMessage;
    blockData = client.AllocateBlock( 1024 );
    check( blockData );
    client.AttachBlockToMessage( testBlockMessage, blockData, 1024 );
    client.SendMessage( 1, testBlockMessage );      // reliable channel

    // Upstream pumps exactly three times: the C sockets deliver a datagram to the netcode_server_update of the same pump.
    // A Node socket delivers it only after the event loop runs (between pumps), so each hop can take one pump more here.
    // Pump until both messages arrive, with a small bound.
    let unreliableMessage: Message | null = null;
    let reliableMessage: Message | null = null;
    for ( let i = 0; i < 10 && ( !unreliableMessage || !reliableMessage ); ++i )
    {
        await PumpClientServerUpdate( state, clients, 1, servers, 1 );
        check( !client.IsDisconnected() );
        unreliableMessage ??= server.ReceiveMessage( 0, 0 );
        reliableMessage ??= server.ReceiveMessage( 0, 1 );
    }

    // Verify that we received a TestBlockMessage on both channels.
    check( unreliableMessage );
    check( unreliableMessage.GetType() === TEST_BLOCK_MESSAGE );
    server.ReleaseMessage( 0, unreliableMessage );

    check( reliableMessage );
    check( reliableMessage.GetType() === TEST_BLOCK_MESSAGE );
    server.ReleaseMessage( 0, reliableMessage );

    client.Disconnect();
    server.Stop();

    client.Dispose();
    server.Dispose();
}

async function test_message_sends_across_reconnect(): Promise<void>
{
    // From the C# port: messages queued on a connection must not leak across a disconnect/reconnect. After the client
    // disconnects and reconnects, message ids start again from 0 on both sides.
    const clientId = 1n;

    const clientAddress = new Address( "0.0.0.0", ClientPort );
    const serverAddress = new Address( "127.0.0.1", ServerPort );

    const state = new TimeState();

    const config = new ClientServerConfig();

    const server = new Server( GetDefaultAllocator(), privateKey, serverAddress, config, adapter, state.time );
    server.Start( MaxClients );

    const client = new Client( GetDefaultAllocator(), clientAddress, config, adapter, state.time );

    for ( let iteration = 0; iteration < 3; ++iteration )
    {
        client.InsecureConnect( privateKey, clientId, serverAddress );
        check( await ConnectClient( state, client, server ) );

        for ( let i = 0; i < 8; ++i )
        {
            const message = server.CreateMessage( 0, TEST_MESSAGE ) as TestMessage;
            message.sequence = i;
            server.SendMessage( 0, 0, message );
        }

        let numReceived = 0;
        for ( let i = 0; i < 1000 && numReceived < 8; ++i )
        {
            await PumpClientServerUpdate( state, [ client ], 1, [ server ], 1 );
            while ( true )
            {
                const message = client.ReceiveMessage( 0 );
                if ( !message )
                    break;
                check( message.GetId() === numReceived );           // ids restart from zero on each connection
                check( ( message as TestMessage ).sequence === numReceived );
                numReceived++;
                client.ReleaseMessage( message );
            }
        }
        check( numReceived === 8 );

        // leave a message queued on each side, then disconnect
        server.SendMessage( 0, 0, server.CreateMessage( 0, TEST_MESSAGE )! );
        client.SendMessage( 0, client.CreateMessage( TEST_MESSAGE )! );

        server.DisconnectClient( 0 );
        await DisconnectClientAndWait( state, client, server, 1000 );
        check( !client.IsConnected() && server.GetNumConnectedClients() === 0 );
        check( !server.HasMessagesToSend( 0, 0 ) );      // the server connection was reset on disconnect
    }

    client.Disconnect();
    server.Stop();
    client.Dispose();
    server.Dispose();
}

async function test_network_info(): Promise<void>
{
    const clientId = 1n;

    const clientAddress = new Address( "0.0.0.0", ClientPort );
    const serverAddress = new Address( "127.0.0.1", ServerPort );

    const state = new TimeState();

    const config = new ClientServerConfig();

    const server = new Server( GetDefaultAllocator(), privateKey, serverAddress, config, adapter, state.time );
    server.Start( MaxClients );

    const client = new Client( GetDefaultAllocator(), clientAddress, config, adapter, state.time );
    client.InsecureConnect( privateKey, clientId, serverAddress );
    check( await ConnectClient( state, client, server ) );

    for ( let i = 0; i < 100; ++i )
        await PumpClientServerUpdate( state, [ client ], 1, [ server ], 1 );

    const clientInfo = new NetworkInfo();
    const serverInfo = new NetworkInfo();
    client.GetNetworkInfo( clientInfo );
    server.GetNetworkInfo( 0, serverInfo );
    check( clientInfo.numPacketsSent > 0 && clientInfo.numPacketsAcked > 0 );
    check( serverInfo.numPacketsSent > 0 && serverInfo.numPacketsAcked > 0 );
    check( clientInfo.minRTT <= clientInfo.maxRTT );
    check( serverInfo.minRTT <= serverInfo.maxRTT );
    check( serverInfo.averageJitter >= 0 && serverInfo.maxJitter >= 0 && serverInfo.stddevJitter >= 0 );

    const userData = server.GetClientUserData( 0 );
    check( userData !== null && userData.length === 256 );
    check( server.GetClientAddress( 0 ) !== null );
    check( client.GetAddress().GetPort() === ClientPort );
    check( server.GetAddress().GetPort() === ServerPort );

    client.Disconnect();
    server.Stop();
    client.Dispose();
    server.Dispose();
}

class LoopbackAdapter extends TestAdapter
{
    client: Client | null = null;
    server: Server | null = null;

    override ClientSendLoopbackPacket( clientIndex: number, packetData: Uint8Array, packetBytes: number, packetSequence: bigint ): void
    {
        this.server!.ProcessLoopbackPacket( clientIndex, packetData, packetBytes, packetSequence );
    }

    override ServerSendLoopbackPacket( _clientIndex: number, packetData: Uint8Array, packetBytes: number, packetSequence: bigint ): void
    {
        this.client!.ProcessLoopbackPacket( packetData, packetBytes, packetSequence );
    }
}

async function test_client_server_loopback(): Promise<void>
{
    // TypeScript extra (loopback.cpp as a test): a loopback client exchanges messages with the server without sockets.
    const state = new TimeState();
    const config = new ClientServerConfig();
    config.networkSimulator = false;

    const loopbackAdapter = new LoopbackAdapter();

    const server = new Server( GetDefaultAllocator(), privateKey, new Address( "127.0.0.1", ServerPort ), config, loopbackAdapter, state.time );
    check( server.Start( MaxClients ) );

    const client = new Client( GetDefaultAllocator(), new Address( "0.0.0.0", 0 ), config, loopbackAdapter, state.time );
    loopbackAdapter.client = client;
    loopbackAdapter.server = server;

    const clientIndex = 0;
    server.ConnectLoopbackClient( clientIndex, 1n, null );
    check( client.ConnectLoopback( clientIndex, 1n, MaxClients ) );
    check( client.IsLoopback() );
    check( server.IsLoopbackClient( clientIndex ) );
    check( client.IsConnected() && server.IsClientConnected( clientIndex ) );

    SendClientToServerMessages( client, 16 );
    SendServerToClientMessages( server, clientIndex, 16 );

    const fromClient = { count: 0 };
    const fromServer = { count: 0 };
    for ( let i = 0; i < 100 && ( fromClient.count < 16 || fromServer.count < 16 ); ++i )
    {
        await PumpClientServerUpdate( state, [ client ], 1, [ server ], 1 );
        ProcessServerToClientMessages( client, fromServer );
        ProcessClientToServerMessages( server, clientIndex, fromClient );
    }
    check( fromClient.count === 16 && fromServer.count === 16 );

    client.DisconnectLoopback();
    server.DisconnectLoopbackClient( clientIndex );
    check( !server.IsClientConnected( clientIndex ) );
    check( server.GetClientDisconnectReason( clientIndex ) === YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_KICKED );

    server.Stop();
    client.Dispose();
    server.Dispose();
}

// ---------------------------------------------------------------------------------------------

type TestFunction = () => void | Promise<void>;

async function RUN_TEST( name: string, test_function: TestFunction ): Promise<void>
{
    console.log( name );
    if ( !InitializeYojimbo() )
    {
        console.log( "error: failed to initialize yojimbo" );
        process.exit( 1 );
    }
    await test_function();
    ShutdownYojimbo();
}

async function main(): Promise<number>
{
    // The tests are randomized (packet loss, ordering, ids). Seed the generator from the clock by default, but let a
    // seed be passed on the command line so a flaky failure can be reproduced exactly: rerun `node test.ts <seed>`.
    const argument = process.argv[2];
    const seed = argument !== undefined ? ( Number( argument ) >>> 0 ) : ( Date.now() >>> 0 );

    console.log( `test random seed ${seed}` );

    yojimbo_srand( seed );

    console.log( "" );

    {
        console.log( "[serialize]\n" );

        check( InitializeYojimbo() );

        serialize_test();

        ShutdownYojimbo();
    }

    {
        console.log( "\n[netcode]\n" );

        check( InitializeYojimbo() );

        let netcode_test: ( () => unknown ) | undefined;
        try
        {
            const netcode = await import( './netcode/netcode.ts' ) as { netcode_test?: () => unknown };
            netcode_test = netcode.netcode_test;
        }
        catch
        {
            netcode_test = undefined;
        }

        if ( typeof netcode_test === 'function' )
            await netcode_test();
        else
            console.log( "netcode_test is not available yet (skipped)" );

        ShutdownYojimbo();
    }

    {
        console.log( "\n[reliable]\n" );

        check( InitializeYojimbo() );

        reliable_test();

        ShutdownYojimbo();
    }

    console.log( "\n[yojimbo]\n" );

    await RUN_TEST( "test_crypto_aead_vectors", test_crypto_aead_vectors );
    await RUN_TEST( "test_queue", test_queue );
    await RUN_TEST( "test_address", test_address );
    await RUN_TEST( "test_address_malformed_port", test_address_malformed_port );
    await RUN_TEST( "test_address_classification", test_address_classification );
    await RUN_TEST( "test_network_simulator_drains_all_slots", test_network_simulator_drains_all_slots );
    await RUN_TEST( "test_network_simulator_overwrite_slot", test_network_simulator_overwrite_slot );
    await RUN_TEST( "test_bit_array", test_bit_array );
    await RUN_TEST( "test_sequence_buffer", test_sequence_buffer );
    await RUN_TEST( "test_allocator_tlsf", test_allocator_tlsf );
    await RUN_TEST( "test_allocator_leak_tracking", test_allocator_leak_tracking );
    await RUN_TEST( "test_config", test_config );

    await RUN_TEST( "test_connection_reliable_ordered_messages", test_connection_reliable_ordered_messages );
    await RUN_TEST( "test_connection_reliable_ordered_blocks", test_connection_reliable_ordered_blocks );
    await RUN_TEST( "test_connection_reliable_ordered_blocks_max_size", test_connection_reliable_ordered_blocks_max_size );
    await RUN_TEST( "test_connection_reliable_ordered_blocks_on_demand", test_connection_reliable_ordered_blocks_on_demand );
    await RUN_TEST( "test_connection_reliable_ordered_messages_and_blocks", test_connection_reliable_ordered_messages_and_blocks );
    await RUN_TEST( "test_connection_reliable_ordered_messages_and_blocks_multiple_channels", test_connection_reliable_ordered_messages_and_blocks_multiple_channels );
    await RUN_TEST( "test_connection_unreliable_unordered_messages", test_connection_unreliable_unordered_messages );
    await RUN_TEST( "test_connection_unreliable_unordered_blocks", test_connection_unreliable_unordered_blocks );
    await RUN_TEST( "test_connection_reject_empty_packet", test_connection_reject_empty_packet );
    await RUN_TEST( "test_connection_process_packet_exact_allocation", test_connection_process_packet_exact_allocation );
    await RUN_TEST( "test_connection_unreliable_rejects_block_fragment", test_connection_unreliable_rejects_block_fragment );
    await RUN_TEST( "test_connection_reliable_block_fragment_on_disabled_blocks", test_connection_reliable_block_fragment_on_disabled_blocks );
    await RUN_TEST( "test_channel_config_fragment_counts_without_overflow", test_channel_config_fragment_counts_without_overflow );
    await RUN_TEST( "test_connection_reliable_block_fragment_overflow", test_connection_reliable_block_fragment_overflow );
    await RUN_TEST( "test_connection_reliable_over_budget_packet", test_connection_reliable_over_budget_packet );
    await RUN_TEST( "test_connection_reliable_message_alloc_failure", test_connection_reliable_message_alloc_failure );
    await RUN_TEST( "test_connection_unreliable_message_alloc_failure", test_connection_unreliable_message_alloc_failure );
    await RUN_TEST( "test_connection_generate_packet_channel_data_alloc_failure", test_connection_generate_packet_channel_data_alloc_failure );
    await RUN_TEST( "test_message_factory_create_message_alloc_failure", test_message_factory_create_message_alloc_failure );
    await RUN_TEST( "test_connection_process_packet_channel_data_alloc_failure", test_connection_process_packet_channel_data_alloc_failure );
    await RUN_TEST( "test_connection_message_refcounts", test_connection_message_refcounts );
    await RUN_TEST( "test_connection_truncated_and_garbage_packets", test_connection_truncated_and_garbage_packets );
    await RUN_TEST( "test_connection_message_too_large", test_connection_message_too_large );
    await RUN_TEST( "test_connection_packet_golden_bytes", test_connection_packet_golden_bytes );

    await RUN_TEST( "test_rtti_across_the_abi_boundary", test_rtti_across_the_abi_boundary );

    // test_public_layout_is_configuration_independent checks C++ class layout across NDEBUG builds: not applicable
    await RUN_TEST( "test_interface_methods_link", test_interface_methods_link );
    await RUN_TEST( "test_server_start_alloc_failure", test_server_start_alloc_failure );
    await RUN_TEST( "test_server_start_factory_failure", test_server_start_factory_failure );
    await RUN_TEST( "test_client_connect_alloc_failure", test_client_connect_alloc_failure );
    await RUN_TEST( "test_client_connect_factory_failure", test_client_connect_factory_failure );
    await RUN_TEST( "test_client_connect_socket_failure_no_crash", test_client_connect_socket_failure_no_crash );
    await RUN_TEST( "test_client_is_loopback_when_disconnected", test_client_is_loopback_when_disconnected );
    await RUN_TEST( "test_client_connect_twice_with_one_connect_token", test_client_connect_twice_with_one_connect_token );
    await RUN_TEST( "test_client_server_messages", test_client_server_messages );
    await RUN_TEST( "test_client_server_start_stop_restart", test_client_server_start_stop_restart );
    await RUN_TEST( "test_client_server_message_failed_to_serialize_reliable_ordered", test_client_server_message_failed_to_serialize_reliable_ordered );
    await RUN_TEST( "test_server_client_disconnect_reason", test_server_client_disconnect_reason );
    await RUN_TEST( "test_server_client_disconnect_reason_failed_to_serialize", test_server_client_disconnect_reason_failed_to_serialize );
    await RUN_TEST( "test_client_disconnect_reason", test_client_disconnect_reason );
    await RUN_TEST( "test_client_disconnect_reason_failed_to_serialize", test_client_disconnect_reason_failed_to_serialize );
    await RUN_TEST( "test_message_sends_across_reconnect", test_message_sends_across_reconnect );
    await RUN_TEST( "test_network_info", test_network_info );
    await RUN_TEST( "test_client_server_loopback", test_client_server_loopback );
    await RUN_TEST( "test_client_server_message_failed_to_serialize_unreliable_unordered", test_client_server_message_failed_to_serialize_unreliable_unordered );
    await RUN_TEST( "test_client_server_message_exhaust_stream_allocator", test_client_server_message_exhaust_stream_allocator );
    await RUN_TEST( "test_client_server_message_receive_queue_overflow", test_client_server_message_receive_queue_overflow );
    await RUN_TEST( "test_reliable_outbound_sequence_outdated", test_reliable_outbound_sequence_outdated );
    await RUN_TEST( "test_reliable_fragment_overflow_bug", test_reliable_fragment_overflow_bug );

    await RUN_TEST( "test_single_message_type_reliable", test_single_message_type_reliable );
    await RUN_TEST( "test_single_message_type_reliable_blocks", test_single_message_type_reliable_blocks );
    await RUN_TEST( "test_single_message_type_unreliable", test_single_message_type_unreliable );

    await RUN_TEST( "test_client_server_messages_network_sim_leak", test_client_server_messages_network_sim_leak );

    console.log( "\n*** ALL TESTS PASS ***\n" );

    return 0;
}

main().then( ( code ) => { process.exitCode = code; }, ( error: unknown ) =>
{
    console.log( "error: test run failed" );
    console.log( error instanceof Error ? ( error.stack ?? error.message ) : String( error ) );
    process.exit( 1 );
} );
