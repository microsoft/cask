// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Buffers;
using System.Buffers.Text;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;

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
        if (!IsValidKeyLengthInChars(key.Length))
        {
            return false;
        }

        SecretSize secretSize = ExtractSensitiveDataSizeFromKeyChars(key, out Range caskSignatureCharRange);
        if (secretSize == 0 || secretSize > SecretSize.Bits512)
        {
            return false;
        }

        // Check for CASK signature, "QJJQ".
        if (!key[caskSignatureCharRange].SequenceEqual(CaskSignature))
        {
            return false;
        }

        int lengthInBytes = Base64CharsToBytes(key.Length);
        Debug.Assert(lengthInBytes <= MaxKeyLengthInBytes);
        Span<byte> keyBytes = stackalloc byte[lengthInBytes];

        OperationStatus status = Base64Url.DecodeFromChars(key,
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
    /// Validates that the provided byte sequence represents a valid Cask key in binary decoded form.
    /// </summary>
    public static bool IsCaskBytes(ReadOnlySpan<byte> keyBytes)
    {
        if (keyBytes.Length < MinKeyLengthInBytes || keyBytes.Length > MaxKeyLengthInBytes || !Is3ByteAligned(keyBytes.Length))
        {
            return false;
        }

        SecretSize secretSize = InferSensitiveDataSizeFromByteLength(keyBytes.Length);
        Range caskSignatureByteRange = ComputeSignatureByteRange(secretSize);

        // Check for CASK signature. "QJJQ" base64-decoded.
        if (!keyBytes[caskSignatureByteRange].SequenceEqual(CaskSignatureBytes))
        {
            return false;
        }

        Range ymdhTimestampRange = caskSignatureByteRange.End..(caskSignatureByteRange.End.Value + 3);
        Range minutesSizesAndKeyKindRange = ymdhTimestampRange.End..(ymdhTimestampRange.End.Value + 3);

        Span<char> minutesSizesAndKeyKindChars = stackalloc char[4];
        int bytesWritten = Base64Url.EncodeToChars(keyBytes[minutesSizesAndKeyKindRange], minutesSizesAndKeyKindChars);

        // 'A' == index 0 of all printable base64-encoded characters.
        var encodedSensitiveDataSize = (SecretSize)(minutesSizesAndKeyKindChars[1] - 'A');
        if (secretSize != encodedSensitiveDataSize)
        {
            return false;
        }

        int providerDataLengthInBytes = (minutesSizesAndKeyKindChars[2] - 'A') * 3;
        if (providerDataLengthInBytes > MaxProviderDataLengthInBytes || !Is3ByteAligned(providerDataLengthInBytes))
        {
            return false;
        }

        int secretSizeInBytes = (int)encodedSensitiveDataSize * 16;
        int paddedSecretSizeInBytes = RoundUpTo3ByteAlignment(secretSizeInBytes);
        int expectedKeyLengthInBytes = paddedSecretSizeInBytes + FixedKeyComponentSizeInBytes + providerDataLengthInBytes;
        if (expectedKeyLengthInBytes != keyBytes.Length)
        {
            return false;
        }

        // TODO: Review Cask.IsCaskBytes and its callers carefully to ensure all useful checks are made.
        // Specifically, we are missing validations and supporting unit tests for invalid timestamps.
        // https://github.com/microsoft/cask/issues/45

        return true;
    }

    internal static SecretSize ExtractSensitiveDataSizeFromKeyChars(ReadOnlySpan<char> key, out Range caskSignatureCharRange)
    {
        SecretSize secretSize = InferSensitiveDataSizeFromCharLength(key.Length);
        caskSignatureCharRange = ComputeSignatureCharRange(secretSize);
        Index sensitiveDataSizeCharIndex = caskSignatureCharRange.End.Value + SensitiveDataSizeOffsetFromCaskSignatureChar;
        return (SecretSize)(key[sensitiveDataSizeCharIndex] - 'A');
    }


    public static CaskKey GenerateKey(string providerSignature,
                                      char providerKeyKind,
                                      string? providerData = null,
                                      SecretSize secretDataSize = SecretSize.Bits256)
    {
        providerData ??= string.Empty;

        ValidateProviderSignature(providerSignature);
        ValidateProviderKeyKind(providerKeyKind);
        ValidateProviderData(providerData);
        ValidateSecretSize(secretDataSize);

        // Calculate the length of the key.
        int providerDataLengthInBytes = Base64CharsToBytes(providerData.Length);

        int keyLengthInBytes = GetKeyLengthInBytes(providerDataLengthInBytes, secretDataSize);

        int secretSizeInBytes = (int)secretDataSize * 16;
        int paddedSecretSizeInBytes = RoundUpTo3ByteAlignment(secretSizeInBytes);
        int intPaddingBytes = paddedSecretSizeInBytes - secretSizeInBytes;

        // Allocate a buffer on the stack to hold the key bytes.
        Debug.Assert(keyLengthInBytes <= MaxKeyLengthInBytes);
        Span<byte> key = stackalloc byte[keyLengthInBytes];

        // Entropy comprising the sensitive component of the key. In the future,
        // we will have primitives that allow callers to provider their own
        // secret bytes, e.g., for HMAC scenarios.
        FillRandom(key[..secretSizeInBytes]);

        int paddingInBytes = paddedSecretSizeInBytes - secretSizeInBytes;
        key.Slice(secretSizeInBytes, paddingInBytes).Clear();

        // CASK signature.
        Range caskSignatureByteRange = ComputeSignatureByteRange(secretDataSize);
        CaskSignatureBytes.CopyTo(key[caskSignatureByteRange]);

        DateTimeOffset now = GetUtcNow();
        ValidateTimestamp(now);
        ReadOnlySpan<char> chars = [
            Base64UrlChars[now.Year - 2025], // Years since 2025.
            Base64UrlChars[now.Month - 1],   // Zero-indexed month.
            Base64UrlChars[now.Day - 1],     // Zero-indexed day.
            Base64UrlChars[now.Hour],        // Zero-indexed hour.
        ];

        Range ymdhByteRange = caskSignatureByteRange.End..(caskSignatureByteRange.End.Value + 3);
        int bytesWritten = Base64Url.DecodeFromChars(chars, key[ymdhByteRange]);
        Debug.Assert(bytesWritten == 3);

        chars = [
            Base64UrlChars[now.Minute],                  // Zero-index minute.
            Base64UrlChars[(int)secretDataSize],      // Zero-indexed month.
            Base64UrlChars[providerDataLengthInBytes/3], // Zero-indexed day.
            providerKeyKind,                             // Zero-indexed hour.
        ];

        Range minutesSizesKeyKindByteRange = ymdhByteRange.End..(ymdhByteRange.End.Value + 3);
        bytesWritten = Base64Url.DecodeFromChars(chars, key[minutesSizesKeyKindByteRange]);
        Debug.Assert(bytesWritten == 3);

        Range optionalProviderDataByteRange = minutesSizesKeyKindByteRange.End..(minutesSizesKeyKindByteRange.End.Value + providerDataLengthInBytes);
        bytesWritten = Base64Url.DecodeFromChars(providerData.AsSpan(), key[optionalProviderDataByteRange]);
        Debug.Assert(bytesWritten == providerDataLengthInBytes);

        Range providerSignatureByteRange = optionalProviderDataByteRange.End..(optionalProviderDataByteRange.End.Value + 3);
        bytesWritten = Base64Url.DecodeFromChars(providerSignature.AsSpan(), key[providerSignatureByteRange]);
        Debug.Assert(bytesWritten == 3);

        // Entropy comprising the non-sensitive correlating id of the key.
        Range correlatingIdByteRange = providerSignatureByteRange.End..(providerSignatureByteRange.End.Value + 15);
        FillRandom(key[correlatingIdByteRange]);

        return CaskKey.Encode(key);
    }


    private static Range ComputeSignatureCharRange(SecretSize secretSize)
    {
        int secretSizeInBytes = (int)secretSize * 16;
        int paddedSecretSizeInBytes = RoundUpTo3ByteAlignment(secretSizeInBytes);
        int sensitiveDataCharOffset = paddedSecretSizeInBytes / 3 * 4;
        return sensitiveDataCharOffset..(sensitiveDataCharOffset + 4);
    }

    private static Range ComputeSignatureByteRange(SecretSize secretSize)
    {
        int secretSizeInBytes = (int)secretSize * 16;
        int paddedSecretSizeInBytes = RoundUpTo3ByteAlignment(secretSizeInBytes);
        return paddedSecretSizeInBytes..(paddedSecretSizeInBytes + 3);
    }

    private static SecretSize InferSensitiveDataSizeFromCharLength(int lengthInChars)
    {
        Debug.Assert(IsValidKeyLengthInChars(lengthInChars));

        int lengthInBytes = lengthInChars / 4 * 3;
        return InferSensitiveDataSizeFromByteLength(lengthInBytes);
    }

    private static SecretSize InferSensitiveDataSizeFromByteLength(int lengthInBytes)
    {
        /* 
         *  Required CASK encoded data, 27 bytes.
         *  
         *      public const int FixedKeyComponentSizeInBytes = ( 3 bytes) CaskSignatureSizeInBytes +
                                                                ( 6 bytes) TimestampSizesAndProviderKindInBytes +
                                                                ( 3 bytes) ProviderSignatureSizeInBytes +
                                                                (15 bytes) CorrelatingIdSizeInBytes;
         *  QJJQ YMDH MLOP TEST 1234 1234 1234 1234 1234
         * 
         *  128-bit : 45 bytes (18 bytes sensitive + 27 reserved) : 12 bytes of optional data permissible < (60 - 45)
         *  256-bit : 60 bytes (33 bytes sensitive + 27 reserved) : 12 bytes of optional data permissible < (75 - 60)
         *  384-bit : 75 bytes (48 bytes sensitive + 27 reserved) : 12 bytes of optional data permissible < (93 - 75)
         *  512-bit : 93 bytes (66 bytes sensitive + 27 reserved) : 12 bytes (value chosen to align with 384 bit keys)
         *  
        */

        Debug.Assert(IsValidKeyLengthInBytes(lengthInBytes));

        if (lengthInBytes >= 93)
        {
            return SecretSize.Bits512;
        }
        else if (lengthInBytes >= 75)
        {
            return SecretSize.Bits384;
        }
        else if (lengthInBytes >= 60)
        {
            return SecretSize.Bits256;
        }

        return SecretSize.Bits128;
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

        SecretSize secretSize = InferSensitiveDataSizeFromCharLength(keyUtf8.Length);
        Range caskSignatureUtf8Range = ComputeSignatureCharRange(secretSize);

        // Check for CASK signature, "QJJQ".
        if (!keyUtf8[caskSignatureUtf8Range].SequenceEqual(CaskSignatureUtf8))
        {
            return false;
        }

        int lengthInBytes = Base64CharsToBytes(keyUtf8.Length);
        Debug.Assert(lengthInBytes <= MaxKeyLengthInBytes);
        Span<byte> keyBytes = stackalloc byte[lengthInBytes];

        OperationStatus status = Base64Url.DecodeFromUtf8(keyUtf8,
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
    private static void ValidateProviderKeyKind(char providerKeyKind)
    {
        if (!IsValidForBase64Url(providerKeyKind))
        {
            ThrowIllegalUrlSafeBase64(providerKeyKind.ToString());
        }
    }

    private static void ValidateTimestamp(DateTimeOffset now)
    {
        if (now.Year < 2025 || now.Year > 2088)
        {
            ThrowInvalidYear();
        }
    }

    private static bool IsValidKeyLengthInChars(int length)
    {
        return length >= MinKeyLengthInChars && length <= MaxKeyLengthInChars && Is4CharAligned(length);
    }

    private static bool IsValidKeyLengthInBytes(int length)
    {
        return length >= MinKeyLengthInBytes && length <= MaxKeyLengthInBytes && Is3ByteAligned(length);
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

    private static void ValidateSecretSize(SecretSize size)
    {
        if (size < SecretSize.Bits128 || size > SecretSize.Bits512)
        {
            ThrowInvalidSecretSize(size);
        }
    }

    [DoesNotReturn]
    private static void ThrowProviderDataUnaligned(string value, [CallerArgumentExpression(nameof(value))] string? paramName = null)
    {
        throw new ArgumentException($"Provider data must be a multiple of 4 characters long: '{value}'.", paramName);
    }

    [DoesNotReturn]
    private static void ThrowInvalidSecretSize(SecretSize value, [CallerArgumentExpression(nameof(value))] string? paramName = null)
    {
        throw new ArgumentException($"Invalid secret size: '{value}'.", paramName);
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
        throw new InvalidOperationException("CASK requires the current year to be between 2025 and 2088.");
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
