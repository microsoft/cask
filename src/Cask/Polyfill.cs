// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

/*
 * https://en.wikipedia.org/wiki/Polyfill_%28programming%29 
 *
 * "In software development, a polyfill is code that implements a new standard
 * feature of a deployment environment within an old version of that environment
 * that does not natively support the feature."
 *
 * This file is only compiled when targeting legacy .NET Framework and fills in
 * BCL gaps there.
 *
 * Principles:
 *
 *  - We will NOT sacrifice performance or developer experiences on modern .NET
 *    by coding to the lowest common denominator of BCL API from ages ago.
 *
 *  - We will NOT spread #if around the codebase or incur other technical debt
 *    to make things faster on .NET Framework.
 *
 *  - We will sacrifice some performance on .NET Framework in order to reduce
 *    maintenance burden.
 *
 * Guidelines:
 *
 *  - Always ask yourself, "how would I write this if .NET Framework went away
 *    for good?" Write that code, and then come here and make it work somehow on
 *    .NET Framework. We want the pain of .NET Framework contained to this file
 *    that we'll hopefully delete one day when .NET Framework support can be
 *    dropped.
 *
 *  - Check if there are official out-of-band .NET Microsoft.Bcl.* or System.*
 *    that support .NET Framework before attempting to write it yourself.
 *
 *  - Use the Polyfill namespace when types exist on .NET Framework, but are
 *    missing functionality. Use extension methods to add instance methods, and
 *    only resort to shadowing types to add static methods.
 *
 *  - Use the real BCL namespace to backport types that don't exist at all on
 *    .NET Framework.
 *
 *  - Keep everything in this file `internal`.
 *
 *  - Only resort to #if if you have exhausted all other options.
 */

#if NET
// It might be tempting to wrap this whole file in #if NETFRAMEWORK and always
// include it in compilation, but don't do that. It leads to a worse IDE
// experience as you have to switch the target framework in the editor to get
// out of the sea of gray. If you see this error, fix the .cproj.
#error This file should be excluded from compilation when targeting modern .NET.
#endif
using System.Buffers;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

using Bcl_HMACSHA256 = System.Security.Cryptography.HMACSHA256;
using Bcl_SHA256 = System.Security.Cryptography.SHA256;

namespace Polyfill
{
    internal static class Extensions
    {
        public static unsafe string GetString(this Encoding encoding, ReadOnlySpan<byte> bytes)
        {
            fixed (byte* ptr = bytes)
            {
                return encoding.GetString(ptr, bytes.Length);
            }
        }

        public static unsafe int GetByteCount(this Encoding encoding, ReadOnlySpan<char> chars)
        {
            fixed (char* ptr = chars)
            {
                return encoding.GetByteCount(ptr, chars.Length);
            }
        }

        public static unsafe int GetBytes(this Encoding encoding, ReadOnlySpan<char> chars, Span<byte> bytes)
        {
            fixed (char* charPtr = chars)
            fixed (byte* bytePtr = bytes)
            {
                return encoding.GetBytes(charPtr, chars.Length, bytePtr, bytes.Length);
            }
        }
    }

    internal static class ArgumentValidation
    {
        public static void ThrowIfNull([NotNull] object? argument, [CallerArgumentExpression(nameof(argument))] string? paramName = null)
        {
            if (argument is null)
            {
                ThrowArgumentNull(paramName);
            }
        }

        public static void ThrowIfGreaterThan(int value, int max, [CallerArgumentExpression(nameof(value))] string? paramName = null)
        {
            if (value > max)
            {
                ThrowGreaterThan(value, max, paramName);
            }
        }

        public static void ThrowIfLessThan(int value, int min, [CallerArgumentExpression(nameof(value))] string? paramName = null)
        {
            if (value < min)
            {
                ThrowLessThan(value, min, paramName);
            }
        }

        [DoesNotReturn]
        private static void ThrowArgumentNull(string? paramName)
        {
            throw new ArgumentNullException(paramName);
        }

        [DoesNotReturn]
        private static void ThrowGreaterThan(int value, int max, string? paramName)
        {
            throw new ArgumentOutOfRangeException(paramName, value, $"Value must be less than or equal to {max}.");
        }

        [DoesNotReturn]
        private static void ThrowLessThan(int value, int min, string? paramName)
        {
            throw new ArgumentOutOfRangeException(paramName, value, $"Value must be greater than or equal to {min}.");
        }
    }

    internal static class ByteArrayPool
    {
        private static readonly ArrayPool<byte> s_pool = ArrayPool<byte>.Create(
            maxArrayLength: CommonAnnotatedSecurityKeys.Limits.MaxStackAlloc,
            maxArraysPerBucket: Environment.ProcessorCount
        );

        public static byte[] Rent(int length)
        {
            return s_pool.Rent(length);
        }

        public static void Return(byte[] array)
        {
            s_pool.Return(array);
        }
    }

    internal static class RandomNumberGenerator
    {
        // RNGCryptoServiceProvider is documented to be thread-safe so we can
        // use a single shared instance. Note, however, that
        // `RandomNumberGenerator.Create()` is not required to return a
        // thread-safe implementation so we must not use it here.
        //
        // https://github.com/dotnet/dotnet-api-docs/issues/3741#issuecomment-718989978
        // https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.rngcryptoserviceprovider?view=netframework-4.7.2#thread-safety
        private static readonly RNGCryptoServiceProvider s_rng = new();


        public static void Fill(Span<byte> buffer)
        {
            byte[] array = ByteArrayPool.Rent(buffer.Length);
            s_rng.GetBytes(array, 0, buffer.Length);
            array.AsSpan()[..buffer.Length].CopyTo(buffer);
            ByteArrayPool.Return(array);
        }
    }

    internal static class Hash
    {
        private const int StreamBufferSizeInBytes = 4096;

        public static void Compute(HashAlgorithm algorithm, ReadOnlySpan<byte> data, Span<byte> destination)
        {
            if (data.Length > StreamBufferSizeInBytes)
            {
                ComputeWithStream(algorithm, data, destination);
                return;
            }

            byte[] dataArray = ByteArrayPool.Rent(data.Length);
            data.CopyTo(dataArray);
            byte[] hash = algorithm.ComputeHash(dataArray, 0, data.Length);
            ByteArrayPool.Return(dataArray);
            hash.CopyTo(destination);
        }

        private static unsafe int ComputeWithStream(HashAlgorithm algorithm, ReadOnlySpan<byte> data, Span<byte> destination)
        {
            byte[] hash;
            fixed (byte* dataPtr = data)
            {
                using var stream = new UnmanagedMemoryStream(dataPtr, data.Length);
                hash = algorithm.ComputeHash(stream);
            }
            hash.CopyTo(destination);
            return hash.Length;
        }
    }

    internal static class HMACSHA256
    {
        public const int HashSizeInBits = 256;
        public const int HashSizeInBytes = HashSizeInBits / 8;
        private const int BlockSize = 64;

#pragma warning disable IDE1006 // https://github.com/dotnet/roslyn/issues/32955
        [ThreadStatic] private static Bcl_HMACSHA256 t_hmac;
#pragma warning restore IDE1006

        public static int HashData(ReadOnlySpan<byte> key, ReadOnlySpan<byte> source, Span<byte> destination)
        {
            ThrowIfDestinationTooSmall(destination, HashSizeInBytes);
            t_hmac ??= new Bcl_HMACSHA256(key: []);
            t_hmac.Key = GetKeyArray(key);
            Hash.Compute(t_hmac, source, destination);
            return HashSizeInBytes;
        }

        private static byte[] GetKeyArray(ReadOnlySpan<byte> key)
        {
            // HMACSHA256 requires that we give it a key array with the exact
            // key length, so we can't pool the key array.
            if (key.Length < BlockSize)
            {
                return key.ToArray();
            }

            // Keys larger than the block size are hashed. We do this ourselves
            // to reduce allocations and copying while marshaling from span to
            // byte[].
            byte[] keyArray = new byte[SHA256.HashSizeInBytes];
            SHA256.HashData(key, keyArray);
            return keyArray;
        }
    }

    internal static class SHA256
    {
        public const int HashSizeInBits = 256;
        public const int HashSizeInBytes = HashSizeInBits / 8;

#pragma warning disable IDE1006 // https://github.com/dotnet/roslyn/issues/32955
        [ThreadStatic] private static Bcl_SHA256 t_sha;
#pragma warning restore IDE1006

        public static int HashData(ReadOnlySpan<byte> source, Span<byte> destination)
        {
            ThrowIfDestinationTooSmall(destination, HashSizeInBytes);
            t_sha ??= Bcl_SHA256.Create();
            Hash.Compute(t_sha, source, destination);
            return HashSizeInBytes;
        }
    }
}

namespace CommonAnnotatedSecurityKeys
{
    public partial record struct CaskKey
    {
        // On modern .NET, the regex will be compiled into this partial method
        // by a source generator. For .NET Framework, fill it in by newing up a
        // Regex that is compiled at runtime.
        private static partial Regex CompiledRegex()
        {
            return new Regex(RegexPattern, RegexFlags);
        }
    }
}

namespace System.Security.Cryptography
{
    internal static class CryptographicOperations
    {
        // WARNING: DO NOT MODIFY EXCEPT TO UPDATE TO A LATER VERSION OF THE
        // CODE FROM THE BCL. THIS IS HARDER THAN IT MAY SEEM TO GET RIGHT!
        //
        // Source:
        // https://github.com/dotnet/runtime/blob/354ec46a63440608bda18e2203bb5538e2f8eae6/src/libraries/System.Security.Cryptography/src/System/Security/Cryptography/CryptographicOperations.cs
        [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
        public static bool FixedTimeEquals(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right)
        {
            // NoOptimization because we want this method to be exactly as
            // non-short-circuiting as written.
            //
            // NoInlining because the NoOptimization would get lost if the
            // method got inlined.

            if (left.Length != right.Length)
            {
                return false;
            }

            int length = left.Length;
            int accum = 0;

            for (int i = 0; i < length; i++)
            {
                accum |= left[i] - right[i];
            }

            return accum == 0;
        }
    }
}

// We break the following rules intentionally when stubbing out attributes.
// The compiler doesn't use reflection to read them.
#pragma warning disable IDE0060 // Remove unused parameter
#pragma warning disable CS9113  // Parameter is unread
#pragma warning disable CA1019  // Define accessors for attribute arguments

namespace System.Runtime.CompilerServices
{
    [ExcludeFromCodeCoverage]
    [AttributeUsage(AttributeTargets.Parameter, AllowMultiple = false, Inherited = false)]
    internal sealed class CallerArgumentExpressionAttribute(string parameterName) : Attribute { }
}

namespace System.Diagnostics.CodeAnalysis
{
    [ExcludeFromCodeCoverage]
    [AttributeUsage(AttributeTargets.Field | AttributeTargets.Parameter | AttributeTargets.Property, Inherited = false)]
    internal sealed class AllowNullAttribute : Attribute { }

    [ExcludeFromCodeCoverage]
    [AttributeUsage(AttributeTargets.Field | AttributeTargets.Parameter | AttributeTargets.Property, Inherited = false)]
    internal sealed class DisallowNullAttribute : Attribute { }

    [ExcludeFromCodeCoverage]
    [AttributeUsage(AttributeTargets.Field | AttributeTargets.Parameter | AttributeTargets.Property | AttributeTargets.ReturnValue, Inherited = false)]
    internal sealed class MaybeNullAttribute : Attribute { }

    [ExcludeFromCodeCoverage]
    [AttributeUsage(AttributeTargets.Field | AttributeTargets.Parameter | AttributeTargets.Property | AttributeTargets.ReturnValue, Inherited = false)]
    internal sealed class NotNullAttribute : Attribute { }

    [ExcludeFromCodeCoverage]
    [AttributeUsage(AttributeTargets.Parameter, Inherited = false)]
    internal sealed class MaybeNullWhenAttribute(bool returnValue) : Attribute { }

    [ExcludeFromCodeCoverage]
    [AttributeUsage(AttributeTargets.Parameter, Inherited = false)]
    internal sealed class NotNullWhenAttribute(bool returnValue) : Attribute { }

    [ExcludeFromCodeCoverage]
    [AttributeUsage(AttributeTargets.Parameter | AttributeTargets.Property | AttributeTargets.ReturnValue, AllowMultiple = true, Inherited = false)]
    internal sealed class NotNullIfNotNullAttribute(string parameterName) : Attribute { }

    [ExcludeFromCodeCoverage]
    [AttributeUsage(AttributeTargets.Method, Inherited = false)]
    internal sealed class DoesNotReturnAttribute : Attribute { }

    [ExcludeFromCodeCoverage]
    [AttributeUsage(AttributeTargets.Parameter, Inherited = false)]
    internal sealed class DoesNotReturnIfAttribute(bool parameterValue) : Attribute { }

    [ExcludeFromCodeCoverage]
    [AttributeUsage(AttributeTargets.Method | AttributeTargets.Property, Inherited = false, AllowMultiple = true)]
    internal sealed class MemberNotNullAttribute(params string[] members) : Attribute { }

    [ExcludeFromCodeCoverage]
    [AttributeUsage(AttributeTargets.Method | AttributeTargets.Property, Inherited = false, AllowMultiple = true)]
    internal sealed class MemberNotNullWhenAttribute(bool returnValue, params string[] members) : Attribute { }
}

namespace System.Text.RegularExpressions
{
    [Conditional("NET")]
    [ExcludeFromCodeCoverage]
    [AttributeUsage(AttributeTargets.Method, AllowMultiple = false, Inherited = false)]
    internal sealed class GeneratedRegexAttribute(string pattern, RegexOptions options = RegexOptions.None) : Attribute { }
}

#pragma warning restore IDE0060 // Remove unused parameter
#pragma warning restore CS9113  // Parameter is unread
#pragma warning restore CA1019  // Define accessors for attribute arguments
