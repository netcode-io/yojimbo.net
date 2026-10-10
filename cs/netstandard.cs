/*
    .NET Standard 2.1 support (not an upstream mirror).

    The library targets net10.0 and netstandard2.1 (Unity and other runtimes that only take .NET Standard). This file
    fills in what .NET Standard 2.1 lacks, so the ported files compile unchanged on both targets:

    - compiler attributes (recognized by name, so internal copies work)
    - BitOperations, ReferenceEqualityComparer and Unsafe.SizeOf as internal types
    - newer static members on existing types (OperatingSystem.IsWindows, BitConverter.SingleToUInt32Bits, ...) as
      C# 14 extension members

    What .NET Standard 2.1 cannot have: the 128 bit serialize primitives (Int128/UInt128, .NET 7), compiled out there
    with #if NET7_0_OR_GREATER in serialize/serialize.cs. yojimbo itself does not use them.
*/

#if NETSTANDARD

using System;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace System.Runtime.CompilerServices
{
    [AttributeUsage(AttributeTargets.Parameter, AllowMultiple = false, Inherited = false)]
    internal sealed class CallerArgumentExpressionAttribute : Attribute
    {
        public CallerArgumentExpressionAttribute(string parameterName) => ParameterName = parameterName;
        public string ParameterName { get; }
    }

    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Struct, AllowMultiple = false, Inherited = false)]
    internal sealed class InterpolatedStringHandlerAttribute : Attribute { }

    [AttributeUsage(AttributeTargets.Parameter, AllowMultiple = false, Inherited = false)]
    internal sealed class InterpolatedStringHandlerArgumentAttribute : Attribute
    {
        public InterpolatedStringHandlerArgumentAttribute(string argument) => Arguments = new[] { argument };
        public InterpolatedStringHandlerArgumentAttribute(params string[] arguments) => Arguments = arguments;
        public string[] Arguments { get; }
    }

    internal static class Unsafe
    {
        // byte accounting for the allocator. exact for primitives and references; other structs use their marshaled size
        public static int SizeOf<T>()
        {
            var type = typeof(T);
            if (!type.IsValueType) return IntPtr.Size;
            if (type.IsEnum) type = Enum.GetUnderlyingType(type);
            if (type == typeof(bool) || type == typeof(byte) || type == typeof(sbyte)) return 1;
            if (type == typeof(char) || type == typeof(short) || type == typeof(ushort)) return 2;
            if (type == typeof(int) || type == typeof(uint) || type == typeof(float)) return 4;
            if (type == typeof(long) || type == typeof(ulong) || type == typeof(double)) return 8;
            if (type == typeof(IntPtr) || type == typeof(UIntPtr)) return IntPtr.Size;
            try { return Marshal.SizeOf(type); } catch (ArgumentException) { return IntPtr.Size; }
        }
    }
}

namespace System.Numerics
{
    internal static class BitOperations
    {
        public static int PopCount(uint value)
        {
            value -= (value >> 1) & 0x55555555u;
            value = (value & 0x33333333u) + ((value >> 2) & 0x33333333u);
            return (int)((((value + (value >> 4)) & 0x0F0F0F0Fu) * 0x01010101u) >> 24);
        }

        public static int PopCount(ulong value) => PopCount((uint)value) + PopCount((uint)(value >> 32));

        public static int LeadingZeroCount(uint value)
        {
            if (value == 0) return 32;
            var count = 0;
            while ((value & 0x80000000u) == 0) { value <<= 1; ++count; }
            return count;
        }

        public static int LeadingZeroCount(ulong value)
        {
            var high = (uint)(value >> 32);
            return high != 0 ? LeadingZeroCount(high) : 32 + LeadingZeroCount((uint)value);
        }
    }
}

namespace System.Collections.Generic
{
    internal sealed class ReferenceEqualityComparer : IEqualityComparer<object>, System.Collections.IEqualityComparer
    {
        public static ReferenceEqualityComparer Instance { get; } = new ReferenceEqualityComparer();
        ReferenceEqualityComparer() { }
        public new bool Equals(object x, object y) => ReferenceEquals(x, y);
        public int GetHashCode(object obj) => System.Runtime.CompilerServices.RuntimeHelpers.GetHashCode(obj);
    }
}

namespace networkprotocol
{
    internal static class NetStandardExtensions
    {
        extension(OperatingSystem)
        {
            public static bool IsWindows() => RuntimeInformation.IsOSPlatform(OSPlatform.Windows);
            public static bool IsLinux() => RuntimeInformation.IsOSPlatform(OSPlatform.Linux);
            public static bool IsMacOS() => RuntimeInformation.IsOSPlatform(OSPlatform.OSX);
        }

        extension(BitConverter)
        {
            public static uint SingleToUInt32Bits(float value) => unchecked((uint)BitConverter.SingleToInt32Bits(value));
            public static float UInt32BitsToSingle(uint value) => BitConverter.Int32BitsToSingle(unchecked((int)value));
            public static ulong DoubleToUInt64Bits(double value) => unchecked((ulong)BitConverter.DoubleToInt64Bits(value));
            public static double UInt64BitsToDouble(ulong value) => BitConverter.Int64BitsToDouble(unchecked((long)value));
        }

        extension(Array)
        {
            public static void Clear(Array array) => Array.Clear(array, 0, array.Length);
        }

        extension(Convert)
        {
            public static string ToHexString(byte[] bytes) => ToHexString(bytes, 0, bytes.Length);

            public static string ToHexString(byte[] bytes, int offset, int length)
            {
                const string digits = "0123456789ABCDEF";
                var chars = new char[length * 2];
                for (var i = 0; i < length; ++i)
                {
                    chars[i * 2] = digits[bytes[offset + i] >> 4];
                    chars[i * 2 + 1] = digits[bytes[offset + i] & 0xF];
                }
                return new string(chars);
            }

            public static byte[] FromHexString(string hex)
            {
                if (hex.Length % 2 != 0) throw new FormatException("hex string has an odd length");
                var bytes = new byte[hex.Length / 2];
                for (var i = 0; i < bytes.Length; ++i)
                    bytes[i] = System.Convert.ToByte(hex.Substring(i * 2, 2), 16);
                return bytes;
            }
        }

        extension(System.Security.Cryptography.SHA256)
        {
            public static byte[] HashData(byte[] source)
            {
                using (var sha = System.Security.Cryptography.SHA256.Create())
                    return sha.ComputeHash(source);
            }
        }

        extension(Random random)
        {
            public long NextInt64(long minValue, long maxValue)
            {
                var range = unchecked((ulong)(maxValue - minValue));
                if (range == 0) return minValue;
                var buffer = new byte[8];
                ulong sample, limit = ulong.MaxValue - ulong.MaxValue % range;
                do { random.NextBytes(buffer); sample = BitConverter.ToUInt64(buffer, 0); } while (sample >= limit);
                return unchecked(minValue + (long)(sample % range));
            }
        }

        extension(Socket socket)
        {
            // SetSocketOption maps .NET's option names to the platform's and refuses raw values (IPV6_TCLASS), so call the
            // runtime's own SetRawSocketOption (.NET 5+) when it has one. A runtime without it (Unity's Mono) can't do raw
            // socket options: netcode then reports packet tagging as failed, as it does wherever tagging is refused
            public void SetRawSocketOption(int optionLevel, int optionName, ReadOnlySpan<byte> optionValue)
            {
                if (SetRawSocketOptionMethod == null)
                    throw new PlatformNotSupportedException("raw socket options need .NET 5 or later");
                SetRawSocketOptionMethod(socket, optionLevel, optionName, optionValue);
            }
        }

        delegate void SetRawSocketOptionDelegate(Socket socket, int optionLevel, int optionName, ReadOnlySpan<byte> optionValue);

        static readonly SetRawSocketOptionDelegate SetRawSocketOptionMethod = FindSetRawSocketOption();

        static SetRawSocketOptionDelegate FindSetRawSocketOption()
        {
            var method = typeof(Socket).GetMethod("SetRawSocketOption", new[] { typeof(int), typeof(int), typeof(ReadOnlySpan<byte>) });
            return method == null ? null : (SetRawSocketOptionDelegate)Delegate.CreateDelegate(typeof(SetRawSocketOptionDelegate), method);
        }
    }
}

#endif
