/*
    Yojimbo Client/Server Network Library.

    Copyright © 2016 - 2019, The Network Protocol Company, Inc.

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

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Text;
using System.Threading;

namespace networkprotocol
{
    /** 
        Address type.
        @see Address::GetType.
     */
    public enum AddressType
    {
        ADDRESS_NONE,                               ///< Not an address. Set by the default constructor.
        ADDRESS_IPV4,                               ///< An IPv4 address, eg: "146.95.129.237"
        ADDRESS_IPV6                                ///< An IPv6 address, eg: "48d9:4a08:b543:ae31:89d8:3226:b92c:cbba"
    }

    /** 
        An IP address and port number.
        Supports both IPv4 and IPv6 addresses.
        Identifies where a packet came from, and where a packet should be sent.
        Parsing and formatting are ports of inet_pton / inet_ntop, so they accept and produce exactly what the C++ library does on every platform
        (System.Net.IPAddress.TryParse is deliberately not used: it accepts "1", "127.1", octal/hex octets and "%scope" suffixes).
     */
    public class Address : IEquatable<Address>
    {
        AddressType m_type;                         ///< The address type: IPv4 or IPv6.
        readonly byte[] m_ipv4 = new byte[4];       ///< IPv4 address data. Valid if type is ADDRESS_IPV4.
        readonly ushort[] m_ipv6 = new ushort[8];   ///< IPv6 address data (local byte order). Valid if type is ADDRESS_IPV6.
        ushort m_port;                              ///< The IP port. Valid for IPv4 and IPv6 address types.

        /**
            Address default constructor.
            Designed for convenience so you can have address members of classes and initialize them via assignment.
            An address created by the default constructor will have address type set to ADDRESS_NONE. Address::IsValid will return false.
            @see IsValid
         */
        public Address() =>
            Clear();

        /**
            Copy constructor. Address is a value type in C++; use this to take a copy.
         */
        public Address(Address address)
        {
            yojimbo.assert(address != null);
            m_type = address.m_type;
            Array.Copy(address.m_ipv4, m_ipv4, 4);
            Array.Copy(address.m_ipv6, m_ipv6, 8);
            m_port = address.m_port;
        }

        /**
            Create an IPv4 address.
            IMPORTANT: Pass in port in local byte order. The address class handles the conversion to network order for you.
            @param a The first field of the IPv4 address.
            @param b The second field of the IPv4 address.
            @param c The third field of the IPv4 address.
            @param d The fourth field of the IPv4 address.
            @param port The IPv4 port (local byte order).
         */
        public Address(byte a, byte b, byte c, byte d, ushort port = 0)
        {
            m_type = AddressType.ADDRESS_IPV4;
            m_ipv4[0] = a;
            m_ipv4[1] = b;
            m_ipv4[2] = c;
            m_ipv4[3] = d;
            m_port = port;
        }

        /**
            Create an IPv4 address.
            @param address Array of four address fields for the IPv4 address.
            @param port The port number (local byte order).
         */
        public Address(byte[] address, ushort port = 0)
        {
            if (address == null || address.Length != 4)
                throw new ArgumentOutOfRangeException(nameof(address));
            m_type = AddressType.ADDRESS_IPV4;
            Array.Copy(address, m_ipv4, 4);
            m_port = port;
        }

        /**
            Create an IPv6 address.
            IMPORTANT: Pass in address fields and the port in local byte order. The address class handles the conversion to network order for you.
            @param port The port number (local byte order).
         */
        public Address(ushort a, ushort b, ushort c, ushort d, ushort e, ushort f, ushort g, ushort h, ushort port = 0)
        {
            m_type = AddressType.ADDRESS_IPV6;
            m_ipv6[0] = a;
            m_ipv6[1] = b;
            m_ipv6[2] = c;
            m_ipv6[3] = d;
            m_ipv6[4] = e;
            m_ipv6[5] = f;
            m_ipv6[6] = g;
            m_ipv6[7] = h;
            m_port = port;
        }

        /**
            Create an IPv6 address.
            IMPORTANT: Pass in address fields and the port in local byte order. The address class handles the conversion to network order for you.
            @param address Array of 8 16 bit address fields for the IPv6 address (local byte order).
            @param port The IPv6 port (local byte order).
         */
        public Address(ushort[] address, ushort port = 0)
        {
            if (address == null || address.Length != 8)
                throw new ArgumentOutOfRangeException(nameof(address));
            m_type = AddressType.ADDRESS_IPV6;
            Array.Copy(address, m_ipv6, 8);
            m_port = port;
        }

        /**
            Parse a string to an address.
            This versions supports parsing a port included in the address string. For example, "127.0.0.1:4000" and "[::1]:40000". 
            Depending on the type of data in the string the address will become ADDRESS_TYPE_IPV4 or ADDRESS_TYPE_IPV6.
            If the string is not recognized as a valid address, the address type is set to ADDRESS_TYPE_NONE, causing Address::IsValid to return false. Please check that after creating an address from a string.
            @param address The string to parse to create the address.
            @see Address::IsValid
            @see Address::GetType
         */
        public Address(string address) =>
            Parse(address);

        /**
            Parse a string to an address.
            This versions overrides any port read in the address with the port parameter. This lets you parse "127.0.0.1" and "[::1]" and pass in the port you want programmatically.
            @param address The string to parse to create the address.
            @param port Overrides the port number read from the string (if any).
            @see Address::IsValid
            @see Address::GetType
         */
        public Address(string address, ushort port)
        {
            Parse(address);
            m_port = port;
        }

        /**
            Clear the address.
            The address type is set to ADDRESS_TYPE_NONE.
            After this function is called Address::IsValid will return false.
         */
        public void Clear()
        {
            m_type = AddressType.ADDRESS_NONE;
            Array.Clear(m_ipv4, 0, 4);
            Array.Clear(m_ipv6, 0, 8);
            m_port = 0;
        }

        /**
            Get the IPv4 address data.
            @returns The IPv4 address as an array of bytes (a copy).
         */
        public byte[] GetAddress4()
        {
            yojimbo.assert(m_type == AddressType.ADDRESS_IPV4);
            return (byte[])m_ipv4.Clone();
        }

        /**
            Get the IPv6 address data.
            @returns the IPv6 address data as an array of uint16_t (local byte order, a copy).
         */
        public ushort[] GetAddress6()
        {
            yojimbo.assert(m_type == AddressType.ADDRESS_IPV6);
            return (ushort[])m_ipv6.Clone();
        }

        /**
            Gets or Sets the port.
            This is useful when you want to programmatically set a server port, eg. try to open a server on ports 40000, 40001, etc...
            @param port The port number (local byte order). Works for both IPv4 and IPv6 addresses.
         */
        public ushort Port
        {
            get => m_port;
            set => m_port = value;
        }
        public void SetPort(ushort port) => m_port = port;
        public ushort GetPort() => m_port;

        /**
            Get the address type.
            @returns The address type: ADDRESS_NONE, ADDRESS_IPV4 or ADDRESS_IPV6.
         */
        public AddressType Type => m_type;
        public AddressType GetAddressType() => m_type;

        /**
            Convert the address to a string.
            IPv4: "a.b.c.d" or "a.b.c.d:port". IPv6: "addr" or "[addr]:port" (inet_ntop formatting). Invalid: "NONE".
         */
        public override string ToString()
        {
            if (m_type == AddressType.ADDRESS_IPV4)
            {
                var a = m_ipv4[0];
                var b = m_ipv4[1];
                var c = m_ipv4[2];
                var d = m_ipv4[3];
                return m_port != 0 ? $"{a}.{b}.{c}.{d}:{m_port}" : $"{a}.{b}.{c}.{d}";
            }
            else if (m_type == AddressType.ADDRESS_IPV6)
            {
                var addressString = inet_ntop6(m_ipv6);
                return m_port == 0 ? addressString : $"[{addressString}]:{m_port}";
            }
            else
                return "NONE";
        }

        /**
            True if the address is valid.
            A valid address is any address with a type other than ADDRESS_TYPE_NONE.
            @returns True if the address is valid, false otherwise.
         */
        public bool IsValid =>
            m_type != AddressType.ADDRESS_NONE;

        /**
            Is this a loopback address?
            Corresponds to an IPv4 address of "127.0.0.1", or an IPv6 address of "::1".
            @returns True if this is the loopback address.
         */
        public bool IsLoopback =>
            (m_type == AddressType.ADDRESS_IPV4 && m_ipv4[0] == 127
                                                && m_ipv4[1] == 0
                                                && m_ipv4[2] == 0
                                                && m_ipv4[3] == 1)
                                                    ||
            (m_type == AddressType.ADDRESS_IPV6 && m_ipv6[0] == 0
                                                && m_ipv6[1] == 0
                                                && m_ipv6[2] == 0
                                                && m_ipv6[3] == 0
                                                && m_ipv6[4] == 0
                                                && m_ipv6[5] == 0
                                                && m_ipv6[6] == 0
                                                && m_ipv6[7] == 0x0001);

        /**
            Is this an IPv6 link local address? fe80::/10 (the prefix is masked, not compared).
            @returns True if this address is a link local IPv6 address.
         */
        public bool IsLinkLocal =>
            m_type == AddressType.ADDRESS_IPV6 && (m_ipv6[0] & 0xffc0) == 0xfe80;

        /**
            Is this an IPv6 site local address? fec0::/10.
            @returns True if this address is a site local IPv6 address.
         */
        public bool IsSiteLocal =>
            m_type == AddressType.ADDRESS_IPV6 && (m_ipv6[0] & 0xffc0) == 0xfec0;

        /**
            Is this an IPv6 multicast address? ff00::/8.
            @returns True if this address is a multicast IPv6 address.
         */
        public bool IsMulticast =>
            m_type == AddressType.ADDRESS_IPV6 && (m_ipv6[0] & 0xff00) == 0xff00;

        /**
            Is this in IPv6 global unicast address?
            Corresponds to any IPv6 address that is not any of the following: Link Local, Site Local, Multicast or Loopback.
            @returns True if this is a global unicast IPv6 address.
         */
        public bool IsGlobalUnicast =>
            m_type == AddressType.ADDRESS_IPV6 && !IsLinkLocal
                                               && !IsSiteLocal
                                               && !IsMulticast
                                               && !IsLoopback;

        public bool Equals(Address other)
        {
            if (other is null)
                return false;
            if (ReferenceEquals(this, other))
                return true;
            if (m_type != other.m_type)
                return false;
            if (m_port != other.m_port)
                return false;
            if (m_type == AddressType.ADDRESS_IPV4)
                return m_ipv4.AsSpan().SequenceEqual(other.m_ipv4);
            else if (m_type == AddressType.ADDRESS_IPV6)
                return m_ipv6.AsSpan().SequenceEqual(other.m_ipv6);
            else
                return false;   // like C++: two ADDRESS_NONE addresses do not compare equal
        }

        public override bool Equals(object obj) =>
            Equals(obj as Address);

        public override int GetHashCode()
        {
            var hash = new HashCode();
            hash.Add(m_type);
            hash.Add(m_port);
            if (m_type == AddressType.ADDRESS_IPV4)
                foreach (var x in m_ipv4) hash.Add(x);
            else if (m_type == AddressType.ADDRESS_IPV6)
                foreach (var x in m_ipv6) hash.Add(x);
            return hash.ToHashCode();
        }

        public static bool operator ==(Address a, Address b) =>
            a is null ? b is null : a.Equals(b);

        public static bool operator !=(Address a, Address b) =>
            !(a == b);

        // Parse a port string. The whole string must be a decimal number in [0,65535] and nothing
        // else: at least one digit, no sign, no leading space, no trailing characters, no overflow (YJ-11).
        static bool ParsePort(char[] buffer, int start, out ushort port)
        {
            port = 0;
            if (buffer[start] < '0' || buffer[start] > '9')
                return false;                                   // no digits, or a sign or space first
            var value = 0;
            var i = start;
            for (; buffer[i] != '\0'; ++i)
            {
                var ch = buffer[i];
                if (ch < '0' || ch > '9')
                    return false;                               // trailing junk
                value = value * 10 + (ch - '0');
                if (value > 65535)
                    return false;                               // out of range (also stops overflow)
            }
            port = (ushort)value;
            return true;
        }

        static int strlen(char[] buffer, int start)
        {
            var i = start;
            while (buffer[i] != '\0')
                ++i;
            return i - start;
        }

        /** 
            Helper function to parse an address string. 
            Used by the constructors that take a string parameter.
            @param address The string to parse.
         */
        protected void Parse(string address_in)
        {
            // first try to parse as an IPv6 address:
            // 1. if the first character is '[' then it's probably an ipv6 in form "[addr6]:portnum"
            // 2. otherwise try to parse as raw IPv6 address, parse using inet_pton

            yojimbo.assert(address_in != null);
            Clear();
            if (address_in == null)
                return;

            // yojimbo_copy_string into a MaxAddressLength buffer (truncates)
            var buffer = new char[yojimbo.MaxAddressLength];
            for (var i = 0; i < yojimbo.MaxAddressLength - 1 && i < address_in.Length; ++i)
            {
                if (address_in[i] == '\0')
                    break;
                buffer[i] = address_in[i];
            }
            var address = 0;            // start index of the address string in buffer

            m_port = 0;
            if (buffer[address] == '[')
            {
                // Bracketed IPv6: exactly "[addr6]" or "[addr6]:port", and nothing else. Locate the
                // closing bracket, then treat only a ':' immediately after it as the port separator.
                // A missing bracket, or anything at all after the closing one other than ":port", is invalid (YJ-11).
                var closing = Array.IndexOf(buffer, ']');
                if (closing < 0 || closing >= strlen(buffer, 0))
                {
                    Clear();
                    return;
                }
                if (buffer[closing + 1] == ':')
                {
                    if (!ParsePort(buffer, closing + 2, out m_port))
                    {
                        Clear();
                        return;
                    }
                }
                else if (buffer[closing + 1] != '\0')
                {
                    Clear();
                    return;
                }
                buffer[closing] = '\0';
                address += 1;
            }

            if (inet_pton6(buffer, address, strlen(buffer, address), m_ipv6))
            {
                m_type = AddressType.ADDRESS_IPV6;
                return;
            }

            // otherwise it's probably an IPv4 address:
            // 1. look for ":portnum", if found save the portnum and strip it out
            // 2. parse remaining ipv4 address via inet_pton

            var addressLength = strlen(buffer, address);
            var base_index = addressLength - 1;
            for (var i = 0; i < 6; ++i)
            {
                var index = base_index - i;
                if (index < 0)
                    break;
                if (buffer[address + index] == ':')
                {
                    if (!ParsePort(buffer, address + index + 1, out m_port))
                    {
                        Clear();
                        return;
                    }
                    buffer[address + index] = '\0';
                }
            }

            if (inet_pton4(buffer, address, strlen(buffer, address), m_ipv4))
                m_type = AddressType.ADDRESS_IPV4;
            else
                // Not a valid IPv4 address. Set address as invalid.
                Clear();
        }

        // port of glibc inet_pton4: exactly four dotted decimal octets, no leading zeros
        static bool inet_pton4(char[] src, int start, int length, byte[] dst)
        {
            var saw_digit = false;
            var octets = 0;
            var tmp = new byte[4];
            var tp = 0;
            var end = start + length;
            for (var i = start; i < end; ++i)
            {
                var ch = src[i];
                if (ch >= '0' && ch <= '9')
                {
                    var value = tmp[tp] * 10 + (ch - '0');
                    if (saw_digit && tmp[tp] == 0)
                        return false;
                    if (value > 255)
                        return false;
                    tmp[tp] = (byte)value;
                    if (!saw_digit)
                    {
                        if (++octets > 4)
                            return false;
                        saw_digit = true;
                    }
                }
                else if (ch == '.' && saw_digit)
                {
                    if (octets == 4)
                        return false;
                    tmp[++tp] = 0;
                    saw_digit = false;
                }
                else
                    return false;
            }
            if (octets < 4)
                return false;
            Array.Copy(tmp, dst, 4);
            return true;
        }

        static int hex_digit_value(char ch)
        {
            if (ch >= '0' && ch <= '9') return ch - '0';
            if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
            if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
            return -1;
        }

        // port of glibc inet_pton6, including embedded IPv4 ("::ffff:1.2.3.4")
        static bool inet_pton6(char[] src, int start, int length, ushort[] dst)
        {
            var tmp = new byte[16];
            var tp = 0;
            const int endp = 16;
            var colonp = -1;
            var i = start;
            var src_endp = start + length;

            if (i == src_endp)
                return false;
            // Leading :: requires some special handling.
            if (src[i] == ':')
            {
                ++i;
                if (i == src_endp || src[i] != ':')
                    return false;
            }

            var curtok = i;
            var xdigits_seen = 0;
            var val = 0U;
            while (i < src_endp)
            {
                var ch = src[i++];
                var digit = hex_digit_value(ch);
                if (digit >= 0)
                {
                    if (xdigits_seen == 4)
                        return false;
                    val <<= 4;
                    val |= (uint)digit;
                    if (val > 0xffff)
                        return false;
                    ++xdigits_seen;
                    continue;
                }
                if (ch == ':')
                {
                    curtok = i;
                    if (xdigits_seen == 0)
                    {
                        if (colonp >= 0)
                            return false;
                        colonp = tp;
                        continue;
                    }
                    else if (i == src_endp)
                        return false;
                    if (tp + 2 > endp)
                        return false;
                    tmp[tp++] = (byte)((val >> 8) & 0xff);
                    tmp[tp++] = (byte)(val & 0xff);
                    xdigits_seen = 0;
                    val = 0;
                    continue;
                }
                if (ch == '.' && (tp + 4) <= endp)
                {
                    var v4 = new byte[4];
                    if (inet_pton4(src, curtok, src_endp - curtok, v4))
                    {
                        Array.Copy(v4, 0, tmp, tp, 4);
                        tp += 4;
                        xdigits_seen = 0;
                        break;
                    }
                }
                return false;
            }
            if (xdigits_seen > 0)
            {
                if (tp + 2 > endp)
                    return false;
                tmp[tp++] = (byte)((val >> 8) & 0xff);
                tmp[tp++] = (byte)(val & 0xff);
            }
            if (colonp >= 0)
            {
                // Replace :: with zeros.
                if (tp == endp)
                    return false;       // :: would expand to a zero-width field
                var n = tp - colonp;
                Array.Copy(tmp, colonp, tmp, endp - n, n);
                Array.Clear(tmp, colonp, endp - n - colonp);
                tp = endp;
            }
            if (tp != endp)
                return false;
            for (var w = 0; w < 8; ++w)
                dst[w] = (ushort)((tmp[w * 2] << 8) | tmp[w * 2 + 1]);
            return true;
        }

        // port of glibc inet_ntop6: compress the longest run (>= 2) of zero groups, lower case hex, embedded IPv4 for ::a.b.c.d and ::ffff:a.b.c.d
        static string inet_ntop6(ushort[] words)
        {
            int best_base = -1, best_len = 0, cur_base = -1, cur_len = 0;
            for (var i = 0; i < 8; i++)
            {
                if (words[i] == 0)
                {
                    if (cur_base == -1) { cur_base = i; cur_len = 1; }
                    else cur_len++;
                }
                else if (cur_base != -1)
                {
                    if (best_base == -1 || cur_len > best_len) { best_base = cur_base; best_len = cur_len; }
                    cur_base = -1;
                }
            }
            if (cur_base != -1 && (best_base == -1 || cur_len > best_len)) { best_base = cur_base; best_len = cur_len; }
            if (best_base != -1 && best_len < 2)
                best_base = -1;

            var sb = new System.Text.StringBuilder();
            for (var i = 0; i < 8; i++)
            {
                if (best_base != -1 && i >= best_base && i < best_base + best_len)
                {
                    if (i == best_base)
                        sb.Append(':');
                    continue;
                }
                if (i != 0)
                    sb.Append(':');
                if (i == 6 && best_base == 0 && (best_len == 6 || (best_len == 5 && words[5] == 0xffff)))
                {
                    sb.Append($"{words[6] >> 8}.{words[6] & 0xff}.{words[7] >> 8}.{words[7] & 0xff}");
                    return sb.ToString();
                }
                sb.Append(words[i].ToString("x"));
            }
            if (best_base != -1 && best_base + best_len == 8)
                sb.Append(':');
            return sb.ToString();
        }
    }

    static partial class yojimbo
    {
        /// Convert a netcode address to a yojimbo address (upstream yojimbo_address_conversion.h). Used for custom packet I/O.
        internal static Address AddressFromNetcode(netcode_address_t address)
        {
            if (address == null || address.data == null)
                return new Address();
            var bytes = address.data.GetAddressBytes();
            if (address.type == netcode.ADDRESS_IPV4 && bytes.Length == 4)
                return new Address(bytes, address.port);
            if (address.type == netcode.ADDRESS_IPV6 && bytes.Length == 16)
            {
                var words = new ushort[8];
                for (var i = 0; i < 8; ++i)
                    words[i] = (ushort)((bytes[i * 2] << 8) | bytes[i * 2 + 1]);
                return new Address(words, address.port);
            }
            return new Address();
        }

        /// Convert a yojimbo address to a netcode address (upstream yojimbo_address_conversion.h). Used for custom packet I/O.
        internal static bool AddressToNetcode(Address address, netcode_address_t result)
        {
            result.data = null;
            result.type = (byte)netcode.ADDRESS_NONE;
            result.port = 0;
            if (address == null)
                return false;
            result.port = address.Port;
            if (address.Type == AddressType.ADDRESS_IPV4)
            {
                result.type = (byte)netcode.ADDRESS_IPV4;
                result.data = new IPAddress(address.GetAddress4());
                return true;
            }
            if (address.Type == AddressType.ADDRESS_IPV6)
            {
                result.type = (byte)netcode.ADDRESS_IPV6;
                var words = address.GetAddress6();
                var bytes = new byte[16];
                for (var i = 0; i < 8; ++i)
                {
                    bytes[i * 2] = (byte)(words[i] >> 8);
                    bytes[i * 2 + 1] = (byte)words[i];
                }
                result.data = new IPAddress(bytes);
                return true;
            }
            return false;
        }
    }
}
