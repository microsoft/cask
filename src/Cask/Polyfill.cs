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

using Bcl_Convert = System.Convert;
using Bcl_HMACSHA256 = System.Security.Cryptography.HMACSHA256;
using Bcl_SHA256 = System.Security.Cryptography.SHA256;

namespace Polyfill
{
    internal static class Extensions
    {
        public static unsafe string GetString(this Encoding encoding, ReadOnlySpan<byte> bytes)
        {
            if (bytes.Length == 0)
            {
                return string.Empty;
            }

            fixed (byte* ptr = bytes)
            {
                return encoding.GetString(ptr, bytes.Length);
            }
        }

        public static unsafe int GetByteCount(this Encoding encoding, ReadOnlySpan<char> chars)
        {
            if (chars.Length == 0)
            {
                return 0;
            }

            fixed (char* ptr = chars)
            {
                return encoding.GetByteCount(ptr, chars.Length);
            }
        }

        public static unsafe int GetBytes(this Encoding encoding, ReadOnlySpan<char> chars, Span<byte> bytes)
        {
            if (chars.Length == 0)
            {
                return 0;
            }

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
            byte[] bytes = new byte[buffer.Length];
            s_rng.GetBytes(bytes);
            bytes.CopyTo(buffer);
        }
    }
}

namespace CommonAnnotatedSecurityKeys
{
    partial record struct CaskKey
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
