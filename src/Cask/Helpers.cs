// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

global using static CommonAnnotatedSecurityKeys.Helpers;

using System;
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
        Debug.Assert(Is3ByteAligned(providerDataLengthInBytes),
                     $"{nameof(providerDataLengthInBytes)} should have been validated to 3-byte aligned already.");
        int keyLengthInBytes = PaddedSecretEntropyInBytes + providerDataLengthInBytes + FixedKeyComponentSizeInBytes;
        Debug.Assert(Is3ByteAligned(keyLengthInBytes));
        return keyLengthInBytes;
    }

    public static SensitiveDataSize CharToSensitiveDataSize(char sensitiveDataSizeChar)
    {
        return (SensitiveDataSize)(sensitiveDataSizeChar - 'A'); ;
    }

    public static CaskKeyKind CharToKind(char kindChar)
    {
        Debug.Assert(kindChar == 'P' || kindChar == 'H',
                     "This is only meant to be called using the kind char of a known valid key.");
        return (CaskKeyKind)(kindChar - 'A');
    }

    public static byte KindToByte(CaskKeyKind kind)
    {
        return (byte)((int)kind << CaskKindReservedBits);
    }

    public static byte ProviderKindToByte(string providerKind)
    {
        Debug.Assert(providerKind?.Length == 1, "Provider kind should be a single character.");

        int base64Index;

        const int uppercaseZIndex = 25; // 'Z' - 'A';
        const int lowercaseZIndex = 51; // 'z' - 'a';


        char providerKindChar = providerKind[0];
        if (providerKindChar >= 'A' && providerKindChar <= 'Z')
        {
            base64Index = providerKindChar - 'A';
        }
        else if (providerKindChar >= 'a' && providerKindChar <= 'z')
        {
            base64Index = providerKindChar - 'a' + uppercaseZIndex;
        }
        else if (providerKindChar >= '0' && providerKindChar <= '9')
        {
            base64Index = providerKindChar - '0' + lowercaseZIndex;
        }
        else if (providerKindChar == '-')
        {
            base64Index = 62;
        }
        else
        {
            Debug.Assert(providerKindChar == '_', "Provider kind should be a valid Base64Url char.");
            base64Index = 63;
        }

        return (byte)(base64Index << ProviderKindReservedBits);
    }

    /// <summary>
    /// Converts a byte that encodes the key kind to the KeyKind enum.
    /// Returns false if the reserved bits in that byte are non-zero.
    /// </summary>
    public static bool TryByteToSensitiveDataSize(byte value, out SensitiveDataSize size)
    {
        if ((value & SensitiveDataReservedMask) != 0)
        {
            size = default;
            return false;
        }

        size = (SensitiveDataSize)(value);
        return true;
    }

    /// <summary>
    /// Converts a byte that encodeds the key kind to the KeyKind enum.
    /// Returns false if the reserved bits in that byte are non-zero.
    /// </summary>
    public static bool TryByteToKind(byte value, out CaskKeyKind kind)
    {
        if ((value & CaskKindReservedMask) != 0)
        {
            kind = default;
            return false;
        }

        kind = (CaskKeyKind)(value >> CaskKindReservedBits);
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

    public static void ThrowIfDestinationTooSmall<T>(Span<T> destination, int requiredSize, [CallerArgumentExpression(nameof(destination))] string? paramName = null)
    {
        if (destination.Length < requiredSize)
        {
            ThrowDestinationTooSmall(paramName);
        }
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
}

internal interface IIsInitialized
{
    bool IsInitialized { get; }
}
