// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

global using static CommonAnnotatedSecurityKeys.Helpers;

using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;

namespace CommonAnnotatedSecurityKeys;

internal static class Helpers
{
    public const int FixedKeyComponentSizeInBytes =
        3 +  // CASK signature
        3 +  // Allocator code and timestamp
        3 +  // Provider signature
        3;   // Checksum

    public const string Base64UrlChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    public static int RoundUpTo3ByteAlignment(int bytes)
    {
        return RoundUpToMultipleOf(bytes, 3);
    }

    public static int RoundUpTo4CharAlignment(int chars)
    {
        return RoundUpToMultipleOf(chars, 4);
    }

    public static int BytesToBase64Chars(int bytes)
    {
        return RoundUpTo3ByteAlignment(bytes) / 3 * 4;
    }

    public static int Base64CharsToBytes(int chars)
    {
        return RoundUpTo4CharAlignment(chars) / 4 * 3;
    }

    public static bool Is3ByteAligned(int byteLength)
    {
        return byteLength % 3 == 0;
    }

    public static bool Is4CharAligned(int charLength)
    {
        return charLength % 4 == 0;
    }

    public static int GetKeyLengthInBytes(int secretEntropyInBytes, int providerDataLengthInBytes)
    {
        Debug.Assert(Is3ByteAligned(secretEntropyInBytes), "secretEntropyInBytes should have been rounded up to 3-byte alignment already.");
        Debug.Assert(Is3ByteAligned(providerDataLengthInBytes), "providerDataLengthInBytes should have been validated to 3-byte aligned already.");

        return secretEntropyInBytes + providerDataLengthInBytes + FixedKeyComponentSizeInBytes;
    }

    public static bool IsValidForBase64Url(string value)
    {
        foreach (char c in value)
        {
            if (!IsValidForBase64Url(c))
            {
                return false;
            }
        }
        return true;
    }

    public static bool IsValidForBase64Url(char c)
    {
        if (c > 0x7F)
        {
            return false; // Non-ASCII char
        }

        if ((c >= '0' && c <= '9') || c == '-' || c == '_')
        {
            return true;
        }

        c |= (char)0x20; // Convert to lowercase
        if (c >= 'a' && c <= 'z')
        {
            return true;
        }

        return false;
    }

    private static int RoundUpToMultipleOf(int value, int multiple)
    {
        return (value + multiple - 1) / multiple * multiple;
    }

    public static void ThrowIfEmptyOrAsciiWhitespace(ReadOnlySpan<byte> textUtf8, [CallerArgumentExpression(nameof(textUtf8))] string? paramName = null)
    {
        if (IsEmptyOrAsciiWhiteSpace(textUtf8))
        {
            ThrowEmptyOrAsciiWhiteSpace(paramName);
        }
    }

    public static bool IsEmptyOrAsciiWhiteSpace(ReadOnlySpan<byte> textUtf8)
    {
        for (int i = 0; i < textUtf8.Length; i++)
        {
            if (!IsAsciiWhiteSpace((char)textUtf8[i]))
            {
                return false;
            }
        }
        return true;
    }

    private static bool IsAsciiWhiteSpace(char c)
    {
        return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\v' || c == '\f';
    }

    [DoesNotReturn]
    private static void ThrowEmptyOrAsciiWhiteSpace(string? paramName)
    {
        throw new ArgumentException("Value cannot be empty or consist entirely of ASCII-range white space characters.", paramName);
    }

    public static void ThrowIfDefault<T>(T value, [CallerArgumentExpression(nameof(value))] string? paramName = null) where T : struct
    {
        if (EqualityComparer<T>.Default.Equals(value, default))
        {
            ThrowDefault(paramName);
        }
    }

    public static void ThrowIfDestinationTooSmall<T>(Span<T> destination, int requiredSize, [CallerArgumentExpression(nameof(destination))] string? paramName = null)
    {
        if (destination.Length < requiredSize)
        {
            ThrowDestinationTooSmall(paramName);
        }
    }

    [DoesNotReturn]
    private static void ThrowDefault(string? paramName)
    {
        throw new ArgumentException("Value cannot be the default uninitialized value.", paramName);
    }

    [DoesNotReturn]
    private static void ThrowDestinationTooSmall(string? paramName)
    {
        throw new ArgumentException("Destination buffer is too small.", paramName);
    }

}
