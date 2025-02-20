// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Buffers;
using System.Buffers.Text;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;

namespace CommonAnnotatedSecurityKeys;

public static class Cask
{
    /// <summary>
    /// Validates that the provided string is a valid Cask key in URL-safe base64-encoded form.
    /// </summary>
    public static bool IsCask(string key)
    {
        ThrowIfNull(key);
        return IsCask(key.AsSpan());
    }

    /// <summary>
    /// Validates that the provided UTF16-encoded text sequence represents a valid Cask key.
    /// </summary>
    /// <param name="key"></param>
    public static bool IsCask(ReadOnlySpan<char> key)
    {
        if (key.Length < MinKeyLengthInChars || key.Length > MaxKeyLengthInChars || !Is4CharAligned(key.Length))
        {
            return false;
        }

        // Check for CASK signature, "JQQJ".
        if (!key[CaskSignatureCharRange].SequenceEqual(CaskSignature))
        {
            return false;
        }

        int lengthInBytes = Base64CharsToBytes(key.Length);
        Debug.Assert(lengthInBytes <= MaxKeyLengthInBytes);
        Span<byte> keyBytes = stackalloc byte[lengthInBytes];

        OperationStatus status = Base64Url.DecodeFromChars(
            key,
            keyBytes,
            out int charsConsumed,
            out int bytesWritten,
            isFinalBlock: true);

        Debug.Assert(status is OperationStatus.InvalidData || charsConsumed == key.Length);
        Debug.Assert(status is not OperationStatus.DestinationTooSmall or OperationStatus.NeedMoreData);

        // NOTE: Decoding can succeed with `bytesWritten < lengthInBytes` if the
        //       input has padding or whitespace, which we don't allow.
        if (status != OperationStatus.Done || bytesWritten != lengthInBytes)
        {
            return false;
        }

        return IsCaskBytes(keyBytes);
    }

    /// <summary>
    /// Validates that the provided UTF8-encoded byte sequence represents a valid Cask key.
    /// </summary>
    public static bool IsCaskUtf8(ReadOnlySpan<byte> keyUtf8)
    {
        if (keyUtf8.Length < MinKeyLengthInChars || keyUtf8.Length > MaxKeyLengthInChars || !Is4CharAligned(keyUtf8.Length))
        {
            return false;
        }

        // Check for CASK signature, "JQQJ" UTF-8 encoded.
        if (!keyUtf8[CaskSignatureCharRange].SequenceEqual(CaskSignatureUtf8))
        {
            return false;
        }

        int lengthInBytes = Base64CharsToBytes(keyUtf8.Length);
        Debug.Assert(lengthInBytes <= MaxKeyLengthInBytes);
        Span<byte> keyBytes = stackalloc byte[lengthInBytes];

        OperationStatus status = Base64Url.DecodeFromUtf8(
            keyUtf8,
            keyBytes,
            out int charsConsumed,
            out int bytesWritten,
            isFinalBlock: true);

        Debug.Assert(status is OperationStatus.InvalidData || charsConsumed == keyUtf8.Length);
        Debug.Assert(status is not OperationStatus.DestinationTooSmall or OperationStatus.NeedMoreData);

        // NOTE: Decoding can succeed with `bytesWritten < lengthInBytes` if the
        //       input has padding or whitespace, which we don't allow.
        if (status != OperationStatus.Done || bytesWritten != lengthInBytes)
        {
            return false;
        }

        return IsCaskBytes(keyBytes);
    }

    /// <summary>
    /// Validates that the provided byte sequence represents a valid Cask key in binary decoded form.
    /// </summary>
    public static bool IsCaskBytes(ReadOnlySpan<byte> keyBytes)
    {
        if (keyBytes.Length < MinKeyLengthInBytes || keyBytes.Length > MaxKeyLengthInBytes || !Is3ByteAligned(keyBytes.Length))
        {
            return false;
        }

        // We have not yet implemented a key or HMAC that exceeds 256 bits in size.
        if (!TryByteToSensitiveDataSize(keyBytes[SensitiveDataSizeByteIndex], out SensitiveDataSize size) || size is not SensitiveDataSize.Bits256)
        {
            return false;
        }

        // Check for CASK signature. "JQQJ" base64-decoded.
        if (!keyBytes[CaskSignatureByteRange].SequenceEqual(CaskSignatureBytes))
        {
            return false;
        }

        // Check that kind is valid.
        if (!TryByteToKind(keyBytes[CaskKindByteIndex], out CaskKeyKind kind) || kind is not CaskKeyKind.PrimaryKey and not CaskKeyKind.HMAC)
        {
            return false;
        }

        // TBD More validation? e.g., we have lots of natural limits on the timestamp data.

        return true;
    }

    public static CaskKey GenerateKey(string providerSignature,
                                      string providerKeyKind,
                                      int expiryInFiveMinuteIncrements = 0,
                                      string? providerData = null)
    {
        providerKeyKind ??= "A"; // 'A' comprises index 0 of base64-encoded characters.
        providerData ??= string.Empty;

        ValidateProviderSignature(providerSignature);
        ValidateProviderKeyKind(providerKeyKind);
        ValidateProviderData(providerData);

        // Calculate the length of the key.
        int providerDataLengthInBytes = Base64CharsToBytes(providerData.Length);
        int keyLengthInBytes = GetKeyLengthInBytes(providerDataLengthInBytes);

        // Allocate a buffer on the stack to hold the key bytes.
        Debug.Assert(keyLengthInBytes <= MaxKeyLengthInBytes);
        Span<byte> key = stackalloc byte[keyLengthInBytes];

        // Entropy comprising the sensitive component of the key.
        FillRandom(key[..SecretEntropyInBytes]);

        // Sensitive component size.
        key[SecretEntropyInBytes] = (byte)SensitiveDataSize.Bits256;

        // CASK signature.
        CaskSignatureBytes.CopyTo(key[CaskSignatureByteRange]);

        // Provider signature.
        int bytesWritten = Base64Url.DecodeFromChars(providerSignature.AsSpan(), key[ProviderSignatureByteRange]);
        Debug.Assert(bytesWritten == 3);

        // Provider key kind.
        key[ProviderKindByteIndex] = ProviderKindToByte(providerKeyKind);

        // CASK key kind.
        key[CaskKindByteIndex] = KindToByte(CaskKeyKind.PrimaryKey);

        // Entropy comprising the non-sensitive correlating id of the key.
        FillRandom(key[CorrelatingIdByteRange]);

        FinalizeKey(key, UseCurrentTime, expiryInFiveMinuteIncrements, providerData.AsSpan());
        return CaskKey.Encode(key);
    }

    private static ReadOnlySpan<byte> UseCurrentTime => [];

    private static void FinalizeKey(Span<byte> key,
                                    ReadOnlySpan<byte> timestampAndExpiry,
                                    int expiryInFiveMinuteIncrements,
                                    ReadOnlySpan<char> providerData)
    {
        int bytesWritten;

        if (timestampAndExpiry.IsEmpty)
        {
            DateTimeOffset now = GetUtcNow();
            ValidateTimestamp(now);
            ReadOnlySpan<char> chars = [
                Base64UrlChars[now.Year - 2024], // Years since 2024.
                Base64UrlChars[now.Month - 1],   // Zero-indexed month.
                Base64UrlChars[now.Day - 1],     // Zero-indexed day.
                Base64UrlChars[now.Hour],        // Zero-indexed hour.
            ];

            bytesWritten = Base64Url.DecodeFromChars(chars, key[YearMonthHoursDaysTimestampByteRange]);
            Debug.Assert(bytesWritten == 3);

            Span<byte> expiryBytes = BitConverter.IsLittleEndian
                ? BitConverter.GetBytes(expiryInFiveMinuteIncrements).AsSpan()[..3]
                : BitConverter.GetBytes(expiryInFiveMinuteIncrements).AsSpan()[1..];

            if (BitConverter.IsLittleEndian)
            {
                expiryBytes.Reverse();
            }

            string expiryText = Base64Url.EncodeToString(expiryBytes[..3]);

            chars = [
                Base64UrlChars[now.Minute],    // Zero-indexed minute.
                expiryText[0],
                expiryText[1],
                expiryText[2],
            ];

            bytesWritten = Base64Url.DecodeFromChars(chars, key[MinutesAndExpiryByteRange]);
            Debug.Assert(bytesWritten == 3);
        }
        else
        {
            timestampAndExpiry.CopyTo(key[YearMonthHoursDaysTimestampByteRange]);
        }

        // Provider data.
        Debug.Assert(Is4CharAligned(providerData.Length));
        bytesWritten = Base64Url.DecodeFromChars(providerData, key[OptionalDataByteRange]);
        Debug.Assert(bytesWritten == providerData.Length / 4 * 3);
    }

    private static void FillRandom(Span<byte> buffer)
    {
        if (t_mockedFillRandom != null)
        {
            t_mockedFillRandom(buffer);
            return;
        }

        RandomNumberGenerator.Fill(buffer);
    }

    private static DateTimeOffset GetUtcNow()
    {
        if (t_mockedGetUtcNow != null)
        {
            return t_mockedGetUtcNow();
        }

        return DateTimeOffset.UtcNow;
    }

    private static void ValidateProviderSignature(string providerSignature)
    {
        ThrowIfNull(providerSignature);

        if (providerSignature.Length != 4)
        {
            ThrowLengthNotEqual(providerSignature, 4);
        }

        if (!IsValidForBase64Url(providerSignature))
        {
            ThrowIllegalUrlSafeBase64(providerSignature);
        }
    }
    private static void ValidateProviderKeyKind(string providerKeyKind)
    {
        ThrowIfNull(providerKeyKind);

        if (providerKeyKind.Length != 1)
        {
            ThrowLengthNotEqual(providerKeyKind, 1);
        }

        if (!IsValidForBase64Url(providerKeyKind))
        {
            ThrowIllegalUrlSafeBase64(providerKeyKind);
        }
    }

    private static void ValidateAllocatorCode(string allocatorCode)
    {
        ThrowIfNull(allocatorCode);

        if (allocatorCode.Length != 2)
        {
            ThrowLengthNotEqual(allocatorCode, 2);
        }

        if (!IsValidForBase64Url(allocatorCode))
        {
            ThrowIllegalUrlSafeBase64(allocatorCode);
        }
    }

    private static void ValidateTimestamp(DateTimeOffset now)
    {
        if (now.Year < 2024 || now.Year > 2087)
        {
            ThrowInvalidYear();
        }
    }

    private static void ValidateProviderData(string providerData)
    {
        if (providerData.Length > MaxProviderDataLengthInChars)
        {
            ThrowProviderDataTooLong(providerData);
        }

        if (!Is4CharAligned(providerData.Length))
        {
            ThrowProviderDataUnaligned(providerData);
        }

        if (!IsValidForBase64Url(providerData))
        {
            ThrowIllegalUrlSafeBase64(providerData);
        }
    }

    [DoesNotReturn]
    private static void ThrowProviderDataUnaligned(string value, [CallerArgumentExpression(nameof(value))] string? paramName = null)
    {
        throw new ArgumentException($"Provider data must be a multiple of 4 characters long: '{value}'.", paramName);
    }

    [DoesNotReturn]
    private static void ThrowProviderDataTooLong(string value, [CallerArgumentExpression(nameof(value))] string? paramName = null)
    {
        throw new ArgumentException($"Provider data must be at most {MaxProviderDataLengthInChars} characters: '{value}'.", paramName);
    }

    [DoesNotReturn]
    private static void ThrowIllegalUrlSafeBase64(string value, [CallerArgumentExpression(nameof(value))] string? paramName = null)
    {
        throw new ArgumentException($"Value includes characters that are not legal URL-safe base64: '{value}'.", paramName);
    }

    [DoesNotReturn]
    private static void ThrowLengthNotEqual(string value, int expectedLength, [CallerArgumentExpression(nameof(value))] string? paramName = null)
    {
        throw new ArgumentException($"Value must be {expectedLength} characters long: '{value}'", paramName);
    }

    [DoesNotReturn]
    private static void ThrowInvalidYear()
    {
        throw new InvalidOperationException("CASK requires the current year to be between 2024 and 2087.");
    }

    internal static Mock MockUtcNow(UtcNowFunc getUtcNow)
    {
        t_mockedGetUtcNow = getUtcNow;
        return new Mock(() => t_mockedGetUtcNow = null);
    }

    internal static Mock MockFillRandom(FillRandomAction fillRandom)
    {
        t_mockedFillRandom = fillRandom;
        return new Mock(() => t_mockedFillRandom = null);
    }

#pragma warning disable IDE1006 // https://github.com/dotnet/roslyn/issues/32955
    [ThreadStatic] private static UtcNowFunc? t_mockedGetUtcNow;
    [ThreadStatic] private static FillRandomAction? t_mockedFillRandom;
#pragma warning restore IDE1006
}
