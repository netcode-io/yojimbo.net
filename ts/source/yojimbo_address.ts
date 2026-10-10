/*
    Yojimbo Client/Server Network Library.

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
    TypeScript port of include/yojimbo_address.h + source/yojimbo_address.cpp (yojimbo 1.13.5).

    Port notes:
      - Parsing is strict, exactly as upstream (YJ-11): the port must be all decimal digits in [0,65535], bracket syntax
        is exact, and anything unparseable leaves the address cleared (ADDRESS_NONE).
      - inet_pton and inet_ntop are not available platform neutrally, so the BSD/ISC implementations libc uses
        (inet_pton4, inet_pton6, inet_ntop6) are ported here: IPv4 is four decimal octets with no leading zeros; IPv6
        allows one "::" and an embedded dotted quad in the last 32 bits; inet_ntop6 compresses the longest run of zero
        groups (first wins, at least two groups) and prints ::ffff:a.b.c.d / ::a.b.c.d forms as the C library does.
      - ToString() returns the string (upstream fills a caller buffer of MaxAddressLength).
      - operator== / operator!= are Equals( other ) / NotEquals( other ); operator= is Assign( other ).
*/

import { MaxAddressLength } from '../include/yojimbo_constants.ts';
import { yojimbo_assert } from './yojimbo_platform.ts';
import { yojimbo_copy_string } from './yojimbo_utils.ts';

/**
    Address type.
    @see Address::GetType.
 */

export const ADDRESS_NONE = 0;                                      ///< Not an address. Set by the default constructor.
export const ADDRESS_IPV4 = 1;                                      ///< An IPv4 address, eg: "146.95.129.237"
export const ADDRESS_IPV6 = 2;                                      ///< An IPv6 address, eg: "48d9:4a08:b543:ae31:89d8:3226:b92c:cbba"

export type AddressType = typeof ADDRESS_NONE | typeof ADDRESS_IPV4 | typeof ADDRESS_IPV6;

/**
    An IP address and port number.
    Supports both IPv4 and IPv6 addresses.
    Identifies where a packet came from, and where a packet should be sent.

    Constructors (upstream overloads):
        new Address()                                   ADDRESS_NONE
        new Address( a, b, c, d, port? )                IPv4 from four bytes (four arguments, or five with the port)
        new Address( [a,b,c,d], port? )                 IPv4 from an array of 4 bytes (Uint8Array or number[])
        new Address( a, b, c, d, e, f, g, h, port? )    IPv6 from eight 16 bit fields (local byte order)
        new Address( [a..h], port? )                    IPv6 from an array of 8 fields (Uint16Array or number[])
        new Address( "string" )                         parsed, with an optional port in the string
        new Address( "string", port )                   parsed, then the port is overridden
 */

export class Address
{
    private m_type: AddressType = ADDRESS_NONE;                     ///< The address type: IPv4 or IPv6.
    private m_ipv4: Uint8Array = new Uint8Array( 4 );                           ///< IPv4 address data. Valid if type is ADDRESS_IPV4.
    private m_ipv6: Uint16Array = new Uint16Array( 8 );                          ///< IPv6 address data (local byte order). Valid if type is ADDRESS_IPV6.
    private m_port = 0;                                             ///< The IP port. Valid for IPv4 and IPv6 address types.

    constructor( ...args: Array<number | string | ArrayLike<number>> )
    {
        if ( args.length === 0 )
        {
            this.Clear();
            return;
        }

        const first = args[0];

        if ( typeof first === 'string' )
        {
            this.Parse( first );
            if ( args.length > 1 )
                this.m_port = ( args[1] as number ) & 0xFFFF;
            return;
        }

        if ( typeof first === 'number' )
        {
            if ( args.length <= 5 )
            {
                this.m_type = ADDRESS_IPV4;
                for ( let i = 0; i < 4; ++i )
                    this.m_ipv4[i] = args[i] as number;
                this.m_port = ( ( args[4] as number | undefined ) ?? 0 ) & 0xFFFF;
            }
            else
            {
                this.m_type = ADDRESS_IPV6;
                for ( let i = 0; i < 8; ++i )
                    this.m_ipv6[i] = args[i] as number;
                this.m_port = ( ( args[8] as number | undefined ) ?? 0 ) & 0xFFFF;
            }
            return;
        }

        // array forms: the element count (or the array type) selects IPv4 / IPv6
        const address = first;
        const port = ( ( args[1] as number | undefined ) ?? 0 ) & 0xFFFF;
        if ( address instanceof Uint16Array || address.length === 8 )
        {
            this.m_type = ADDRESS_IPV6;
            for ( let i = 0; i < 8; ++i )
                this.m_ipv6[i] = address[i];
        }
        else
        {
            this.m_type = ADDRESS_IPV4;
            for ( let i = 0; i < 4; ++i )
                this.m_ipv4[i] = address[i];
        }
        this.m_port = port;
    }

    /**
        Clear the address.
        The address type is set to ADDRESS_NONE.
        After this function is called Address::IsValid will return false.
     */

    Clear(): void
    {
        this.m_type = ADDRESS_NONE;
        this.m_ipv4.fill( 0 );
        this.m_ipv6.fill( 0 );
        this.m_port = 0;
    }

    /** Copy another address into this one (operator=). */

    Assign( other: Address ): void
    {
        this.m_type = other.m_type;
        this.m_ipv4.set( other.m_ipv4 );
        this.m_ipv6.set( other.m_ipv6 );
        this.m_port = other.m_port;
    }

    /** A copy of this address. */

    Clone(): Address
    {
        const copy = new Address();
        copy.Assign( this );
        return copy;
    }

    /**
        Get the IPv4 address data.
        @returns The IPv4 address as an array of bytes.
     */

    GetAddress4(): Uint8Array
    {
        yojimbo_assert( this.m_type === ADDRESS_IPV4, "m_type == ADDRESS_IPV4", "Address::GetAddress4" );
        return this.m_ipv4;
    }

    /**
        Get the IPv6 address data.
        @returns the IPv6 address data as an array of uint16 (local byte order).
     */

    GetAddress6(): Uint16Array
    {
        yojimbo_assert( this.m_type === ADDRESS_IPV6, "m_type == ADDRESS_IPV6", "Address::GetAddress6" );
        return this.m_ipv6;
    }

    /**
        Set the port.
        @param port The port number (local byte order). Works for both IPv4 and IPv6 addresses.
     */

    SetPort( port: number ): void
    {
        this.m_port = port & 0xFFFF;
    }

    /**
        Get the port number.
        @returns The port number (local byte order).
     */

    GetPort(): number
    {
        return this.m_port;
    }

    /**
        Get the address type.
        @returns The address type: ADDRESS_NONE, ADDRESS_IPV4 or ADDRESS_IPV6.
     */

    GetType(): AddressType
    {
        return this.m_type;
    }

    /**
        Convert the address to a string.
        @returns "a.b.c.d[:port]", "addr6" or "[addr6]:port", or "NONE".
     */

    ToString(): string
    {
        if ( this.m_type === ADDRESS_IPV4 )
        {
            const a = this.m_ipv4[0];
            const b = this.m_ipv4[1];
            const c = this.m_ipv4[2];
            const d = this.m_ipv4[3];
            if ( this.m_port !== 0 )
                return `${a}.${b}.${c}.${d}:${this.m_port}`;
            else
                return `${a}.${b}.${c}.${d}`;
        }
        else if ( this.m_type === ADDRESS_IPV6 )
        {
            const addressString = inet_ntop6( this.m_ipv6 );
            if ( this.m_port === 0 )
                return addressString;
            else
                return `[${addressString}]:${this.m_port}`;
        }
        else
        {
            return "NONE";
        }
    }

    /** String conversion (ToString). */

    toString(): string
    {
        return this.ToString();
    }

    /**
        True if the address is valid.
        A valid address is any address with a type other than ADDRESS_NONE.
     */

    IsValid(): boolean
    {
        return this.m_type !== ADDRESS_NONE;
    }

    /**
        Is this a loopback address?
        Corresponds to an IPv4 address of "127.0.0.1", or an IPv6 address of "::1".
     */

    IsLoopback(): boolean
    {
        return ( this.m_type === ADDRESS_IPV4 && this.m_ipv4[0] === 127
                                              && this.m_ipv4[1] === 0
                                              && this.m_ipv4[2] === 0
                                              && this.m_ipv4[3] === 1 )
                                                ||
               ( this.m_type === ADDRESS_IPV6 && this.m_ipv6[0] === 0
                                              && this.m_ipv6[1] === 0
                                              && this.m_ipv6[2] === 0
                                              && this.m_ipv6[3] === 0
                                              && this.m_ipv6[4] === 0
                                              && this.m_ipv6[5] === 0
                                              && this.m_ipv6[6] === 0
                                              && this.m_ipv6[7] === 0x0001 );
    }

    /**
        Is this an IPv6 link local address? fe80::/10.
     */

    IsLinkLocal(): boolean
    {
        // fe80::/10 -- the prefix is 10 bits, so mask rather than compare the whole group.
        return this.m_type === ADDRESS_IPV6 && ( this.m_ipv6[0] & 0xffc0 ) === 0xfe80;
    }

    /**
        Is this an IPv6 site local address? fec0::/10.
     */

    IsSiteLocal(): boolean
    {
        return this.m_type === ADDRESS_IPV6 && ( this.m_ipv6[0] & 0xffc0 ) === 0xfec0;
    }

    /**
        Is this an IPv6 multicast address? ff00::/8.
     */

    IsMulticast(): boolean
    {
        return this.m_type === ADDRESS_IPV6 && ( this.m_ipv6[0] & 0xff00 ) === 0xff00;
    }

    /**
        Is this in IPv6 global unicast address?
        Corresponds to any IPv6 address that is not any of the following: Link Local, Site Local, Multicast or Loopback.
     */

    IsGlobalUnicast(): boolean
    {
        return this.m_type === ADDRESS_IPV6 && !this.IsLinkLocal()
                                            && !this.IsSiteLocal()
                                            && !this.IsMulticast()
                                            && !this.IsLoopback();
    }

    /** operator== */

    Equals( other: Address ): boolean
    {
        if ( this.m_type !== other.m_type )
            return false;
        if ( this.m_port !== other.m_port )
            return false;
        if ( this.m_type === ADDRESS_IPV4 )
        {
            for ( let i = 0; i < 4; ++i )
                if ( this.m_ipv4[i] !== other.m_ipv4[i] )
                    return false;
            return true;
        }
        else if ( this.m_type === ADDRESS_IPV6 )
        {
            for ( let i = 0; i < 8; ++i )
                if ( this.m_ipv6[i] !== other.m_ipv6[i] )
                    return false;
            return true;
        }
        else
            return false;
    }

    /** operator!= */

    NotEquals( other: Address ): boolean
    {
        return !this.Equals( other );
    }

    /**
        Helper function to parse an address string.
        Used by the constructors that take a string parameter.
        @param address_in The string to parse.
     */

    protected Parse( address_in: string ): void
    {
        // first try to parse as an IPv6 address:
        // 1. if the first character is '[' then it's probably an ipv6 in form "[addr6]:portnum"
        // 2. otherwise try to parse as raw IPv6 address, parse using inet_pton

        yojimbo_assert( address_in != null, "address_in", "Address::Parse" );

        let address = yojimbo_copy_string( address_in, MaxAddressLength );

        this.m_port = 0;
        if ( address.charCodeAt( 0 ) === 0x5B )   // '['
        {
            // Bracketed IPv6: exactly "[addr6]" or "[addr6]:port", and nothing else. Locate the
            // closing bracket, then treat only a ':' immediately after it as the port separator.
            // A missing bracket, or anything at all after the closing one other than ":port",
            // is invalid (YJ-11).
            const closing = address.indexOf( "]" );
            if ( closing < 0 )
            {
                this.Clear();
                return;
            }
            if ( address[closing + 1] === ":" )
            {
                const port = ParsePort( address.substring( closing + 2 ) );
                if ( port < 0 )
                {
                    this.Clear();
                    return;
                }
                this.m_port = port;
            }
            else if ( closing + 1 < address.length )
            {
                this.Clear();
                return;
            }
            address = address.substring( 1, closing );
        }

        if ( inet_pton6( address, this.m_ipv6 ) )
        {
            this.m_type = ADDRESS_IPV6;
            return;
        }

        // otherwise it's probably an IPv4 address:
        // 1. look for ":portnum", if found save the portnum and strip it out
        // 2. parse remaining ipv4 address via inet_pton

        const base_index = address.length - 1;
        for ( let i = 0; i < 6; ++i )
        {
            const index = base_index - i;
            if ( index < 0 )
                break;
            if ( address[index] === ":" )
            {
                const port = ParsePort( address.substring( index + 1 ) );
                if ( port < 0 )
                {
                    this.Clear();
                    return;
                }
                this.m_port = port;
                address = address.substring( 0, index );
            }
        }

        if ( inet_pton4( address, this.m_ipv4 ) )
        {
            this.m_type = ADDRESS_IPV4;
        }
        else
        {
            // Not a valid IPv4 address. Set address as invalid.
            this.Clear();
        }
    }
}

// Parse a port string. The whole string must be a decimal number in [0,65535] and nothing
// else: at least one digit, no sign, no leading space, no trailing characters, no overflow (YJ-11).
// Returns the port, or -1 if the string is not a valid port.
function ParsePort( string: string ): number
{
    if ( string.length === 0 )
        return -1;
    let value = 0;
    for ( let i = 0; i < string.length; ++i )
    {
        const c = string.charCodeAt( i );
        if ( c < 0x30 || c > 0x39 )
            return -1;                                      // no digits, a sign or space, or trailing junk
        value = value * 10 + ( c - 0x30 );
        if ( value > 65535 )
            return -1;                                      // out of range (also covers overflow)
    }
    return value;
}

// inet_pton4 (ISC / BSD libc): four decimal octets, no leading zeros, each <= 255, nothing else.
function inet_pton4( src: string, dst: Uint8Array ): boolean
{
    const tmp = [ 0, 0, 0, 0 ];
    let saw_digit = false;
    let octets = 0;
    let tp = 0;
    tmp[0] = 0;
    for ( let i = 0; i < src.length; ++i )
    {
        const ch = src.charCodeAt( i );
        if ( ch >= 0x30 && ch <= 0x39 )
        {
            const value = tmp[tp] * 10 + ( ch - 0x30 );
            if ( saw_digit && tmp[tp] === 0 )
                return false;
            if ( value > 255 )
                return false;
            tmp[tp] = value;
            if ( !saw_digit )
            {
                if ( ++octets > 4 )
                    return false;
                saw_digit = true;
            }
        }
        else if ( ch === 0x2E && saw_digit )    // '.'
        {
            if ( octets === 4 )
                return false;
            tmp[++tp] = 0;
            saw_digit = false;
        }
        else
            return false;
    }
    if ( octets < 4 )
        return false;
    for ( let i = 0; i < 4; ++i )
        dst[i] = tmp[i];
    return true;
}

function hex_value( ch: number ): number
{
    if ( ch >= 0x30 && ch <= 0x39 ) return ch - 0x30;
    if ( ch >= 0x61 && ch <= 0x66 ) return ch - 0x61 + 10;
    if ( ch >= 0x41 && ch <= 0x46 ) return ch - 0x41 + 10;
    return -1;
}

// inet_pton6 (ISC / BSD libc). Writes the 8 groups (local byte order) to dst only on success.
function inet_pton6( src: string, dst: Uint16Array ): boolean
{
    const tmp = new Uint8Array( 16 );
    let tp = 0;
    const endp = 16;
    let colonp = -1;
    let i = 0;

    /* Leading :: requires some special handling. */
    if ( src.charCodeAt( 0 ) === 0x3A )
        if ( src.charCodeAt( 1 ) !== 0x3A )
            return false;
    if ( src.charCodeAt( 0 ) === 0x3A )
        i = 1;
    let curtok = i;
    let saw_xdigit = false;
    let seen_xdigits = 0;
    let val = 0;
    for ( ; i < src.length; ++i )
    {
        const ch = src.charCodeAt( i );
        const digit = hex_value( ch );
        if ( digit >= 0 )
        {
            val <<= 4;
            val |= digit;
            if ( ++seen_xdigits > 4 )
                return false;
            saw_xdigit = true;
            continue;
        }
        if ( ch === 0x3A )      // ':'
        {
            curtok = i + 1;
            if ( !saw_xdigit )
            {
                if ( colonp >= 0 )
                    return false;
                colonp = tp;
                continue;
            }
            else if ( i + 1 >= src.length )
            {
                return false;
            }
            if ( tp + 2 > endp )
                return false;
            tmp[tp++] = ( val >> 8 ) & 0xff;
            tmp[tp++] = val & 0xff;
            saw_xdigit = false;
            seen_xdigits = 0;
            val = 0;
            continue;
        }
        if ( ch === 0x2E && ( tp + 4 ) <= endp )    // '.'
        {
            const v4 = new Uint8Array( 4 );
            if ( inet_pton4( src.substring( curtok ), v4 ) )
            {
                tmp.set( v4, tp );
                tp += 4;
                saw_xdigit = false;
                break;  /* '\0' was seen by inet_pton4(). */
            }
        }
        return false;
    }
    if ( saw_xdigit )
    {
        if ( tp + 2 > endp )
            return false;
        tmp[tp++] = ( val >> 8 ) & 0xff;
        tmp[tp++] = val & 0xff;
    }
    if ( colonp >= 0 )
    {
        /*
         * Since some memmove()'s erroneously fail to handle
         * overlapping regions, we'll do the shift by hand.
         */
        const n = tp - colonp;
        if ( tp === endp )
            return false;
        for ( let j = 1; j <= n; j++ )
        {
            tmp[endp - j] = tmp[colonp + n - j];
            tmp[colonp + n - j] = 0;
        }
        tp = endp;
    }
    if ( tp !== endp )
        return false;
    for ( let j = 0; j < 8; ++j )
        dst[j] = ( tmp[j * 2] << 8 ) | tmp[j * 2 + 1];
    return true;
}

// inet_ntop6 (ISC / BSD libc): lowercase hex without leading zeros, the longest run (first on ties) of two or more
// zero groups compressed to "::", and the IPv4 compatible / mapped forms printed with a dotted quad.
function inet_ntop6( words: Uint16Array ): string
{
    let best_base = -1, best_len = 0;
    let cur_base = -1, cur_len = 0;
    for ( let i = 0; i < 8; i++ )
    {
        if ( words[i] === 0 )
        {
            if ( cur_base === -1 )
            {
                cur_base = i;
                cur_len = 1;
            }
            else
                cur_len++;
        }
        else
        {
            if ( cur_base !== -1 )
            {
                if ( best_base === -1 || cur_len > best_len )
                {
                    best_base = cur_base;
                    best_len = cur_len;
                }
                cur_base = -1;
            }
        }
    }
    if ( cur_base !== -1 )
    {
        if ( best_base === -1 || cur_len > best_len )
        {
            best_base = cur_base;
            best_len = cur_len;
        }
    }
    if ( best_base !== -1 && best_len < 2 )
        best_base = -1;

    let text = "";
    for ( let i = 0; i < 8; i++ )
    {
        /* Are we inside the best run of 0x00's? */
        if ( best_base !== -1 && i >= best_base && i < ( best_base + best_len ) )
        {
            if ( i === best_base )
                text += ":";
            continue;
        }
        /* Are we following an initial run of 0x00s or any real hex? */
        if ( i !== 0 )
            text += ":";
        /* Is this address an encapsulated IPv4? */
        if ( i === 6 && best_base === 0 && ( best_len === 6 || ( best_len === 5 && words[5] === 0xffff ) ) )
        {
            text += `${words[6] >> 8}.${words[6] & 0xff}.${words[7] >> 8}.${words[7] & 0xff}`;
            break;
        }
        text += words[i].toString( 16 );
    }
    /* Was it a trailing run of 0x00's? */
    if ( best_base !== -1 && ( best_base + best_len ) === 8 )
        text += ":";
    return text;
}
