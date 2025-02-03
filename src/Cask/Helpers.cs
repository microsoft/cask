// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

global using static CommonAnnotatedSecurityKeys.Helpers;

using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;

namespace CommonAnnotatedSecurityKeys;

internal static class Helpers
{
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

    public static int GetKeyLengthInBytes(int providerDataLengthInBytes)
    {
        Debug.Assert(Is3ByteAligned(providerDataLengthInBytes), $"{nameof(providerDataLengthInBytes)} should have been validated to 3-byte aligned already.");
        int keyLengthInBytes = PaddedSecretEntropyInBytes + providerDataLengthInBytes + FixedKeyComponentSizeInBytes;
        Debug.Assert(Is3ByteAligned(keyLengthInBytes));
        return keyLengthInBytes;
    }

    public static int GetHashLengthInBytes(int secretSizeInBytes, out int providerDataLengthInBytes)
    {
        providerDataLengthInBytes = secretSizeInBytes - PaddedSecretEntropyInBytes - FixedKeyComponentSizeInBytes;
        int hashLengthInBytes = PaddedHmacSha256SizeInBytes + providerDataLengthInBytes + FixedHashComponentSizeInBytes;
        Debug.Assert(Is3ByteAligned(providerDataLengthInBytes));
        Debug.Assert(Is3ByteAligned(hashLengthInBytes));
        return hashLengthInBytes;
    }

    public static KeyKind CharToKind(char kindChar)
    {
        Debug.Assert(kindChar == 'A' || kindChar == 'H' || kindChar == 'I', "This is only meant to be called using the kind char of a known valid key.");
        return (KeyKind)(kindChar - 'A');
    }

    public static byte KindToByte(KeyKind kind)
    {
        return (byte)((int)kind << KindReservedBits);
    }

    /// <summary>
    /// Converts a byte that encodeds the key kind to the KeyKind enum.
    /// Returns false if the reserved bits in that byte are non-zero.
    /// </summary>
    public static bool TryByteToKind(byte value, out KeyKind kind)
    {
        if ((value & KindReservedMask) != 0)
        {
            kind = default;
            return false;
        }

        kind = (KeyKind)(value >> KindReservedBits);
        return true;
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

    public static void ThrowIfNotInitialized<T>(T value, [CallerArgumentExpression(nameof(value))] string? paramName = null)
        where T : struct, IIsInitialized
    {
        if (!value.IsInitialized)
        {
            ThrowArgumentNotInitialized(paramName);
        }
    }

    public static void ThrowIfNotPrimary(CaskKey value, [CallerArgumentExpression(nameof(value))] string? paramName = null)
    {
        if (!value.IsPrimary)
        {
            ThrowNotPrimary(paramName);
        }
    }

    public static void ThrowIfNotHash(CaskKey value, [CallerArgumentExpression(nameof(value))] string? paramName = null)
    {
        if (!value.IsHash)
        {
            ThrowNotHash(paramName);
        }
    }

    public static void ThrowIfDestinationTooSmall<T>(Span<T> destination, int requiredSize, [CallerArgumentExpression(nameof(destination))] string? paramName = null)
    {
        if (destination.Length < requiredSize)
        {
            ThrowDestinationTooSmall(paramName);
        }
    }

    public static void ThrowIfEmpty<T>(ReadOnlySpan<T> value, [CallerArgumentExpression(nameof(value))] string? paramName = null)
    {
        if (value.IsEmpty)
        {
            ThrowEmpty(paramName);
        }
    }

    [DoesNotReturn]
    private static void ThrowArgumentNotInitialized(string? paramName)
    {
        throw new ArgumentException("Value cannot be the default uninitialized struct value.", paramName);
    }

    [DoesNotReturn]
    public static void ThrowOperationOnUninitializedInstance()
    {
        throw new InvalidOperationException("Operation cannot be performed on the default uninitialized struct value.");
    }

    [DoesNotReturn]
    private static void ThrowDestinationTooSmall(string? paramName)
    {
        throw new ArgumentException("Destination buffer is too small.", paramName);
    }

    [DoesNotReturn]
    private static void ThrowEmpty(string? paramName)
    {
        throw new ArgumentException("Value cannot be empty.", paramName);
    }

    [DoesNotReturn]
    private static void ThrowNotPrimary(string? paramName)
    {
        throw new ArgumentException("Key is not a primary key.", paramName);
    }

    [DoesNotReturn]
    private static void ThrowNotHash(string? paramName)
    {
        throw new ArgumentException("Key is not a hash.", paramName);
    }
}

internal interface IIsInitialized
{
    bool IsInitialized { get; }
}
