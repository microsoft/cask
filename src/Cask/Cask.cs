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
    /// Validates that the provided string is a valid Cask key in URL-safe
    /// base64-encoded form.
    /// </summary>
    public static bool IsCask(string key)
    {
        ThrowIfNull(key);
        return IsCask(key.AsSpan());
    }

    /// <summary>
    /// Validates that the provided UTF16-encoded text sequence represents a
    /// valid Cask key.
    /// </summary>
    /// <param name="key"></param>
    public static bool IsCask(ReadOnlySpan<char> key)
    {
        if (!IsValidKeyLengthInChars(key.Length))
        {
            return false;
        }

        SecretSize secretSize = ExtractSecretSizeFromKeyChars(key, out Range caskSignatureCharRange);
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

        if (keyBytes.Length > Max384BitKeyLengthInBytes && keyBytes.Length < Min512BitKeyLengthInBytes)
        {
            // There is a 3-byte gap in valid keys lengths between the 384-bit
            // and 512-bit sizes. This early check short-circuits validation to
            // avoid length check assertions in the rest of the method.
            // Validation logic later in the method that verifies the encoding
            // of the optional data size and the literal size of the optional
            // data itself would also fail this corner case situation.
            return false;
        }

        SecretSize secretSize = InferSecretSizeFromByteLength(keyBytes.Length);
        Range caskSignatureByteRange = ComputeSignatureByteRange(secretSize);

        // Check for CASK signature. "QJJQ" base64-decoded.
        if (!keyBytes[caskSignatureByteRange].SequenceEqual(CaskSignatureBytes))
        {
            return false;
        }

        Range ymdhTimestampRange = caskSignatureByteRange.End..(caskSignatureByteRange.End.Value + CaskSignatureSizeInBytes);
        Range minutesSizesAndKeyKindRange = ymdhTimestampRange.End..(ymdhTimestampRange.End.Value + YearMonthDayHourSizeInBytes);

        Span<char> minutesSizesAndKeyKindChars = stackalloc char[4];
        int bytesWritten = Base64Url.EncodeToChars(keyBytes[minutesSizesAndKeyKindRange], minutesSizesAndKeyKindChars);

        // 'A' == index 0 of all printable base64-encoded characters.
        var encodedSecretSize = (SecretSize)(minutesSizesAndKeyKindChars[1] - 'A');
        if (secretSize != encodedSecretSize)
        {
            return false;
        }

        int providerDataLengthInBytes = (minutesSizesAndKeyKindChars[2] - 'A') * OptionalDataChunkSizeInBytes;
        if (providerDataLengthInBytes > MaxProviderDataLengthInBytes)
        {
            return false;
        }

        int secretSizeInBytes = (int)encodedSecretSize * SecretChunkSizeInBytes;
        int paddedSecretSizeInBytes = RoundUpTo3ByteAlignment(secretSizeInBytes);
        int expectedKeyLengthInBytes = paddedSecretSizeInBytes + FixedKeyComponentSizeInBytes + providerDataLengthInBytes;
        if (expectedKeyLengthInBytes != keyBytes.Length)
        {
            return false;
        }

        // TODO: Review Cask.IsCaskBytes and its callers carefully to ensure all
        // useful checks are made. Specifically, we are missing validations and
        // supporting unit tests for invalid timestamps.
        // https://github.com/microsoft/cask/issues/45

        return true;
    }

    internal static SecretSize ExtractSecretSizeFromKeyChars(ReadOnlySpan<char> key, out Range caskSignatureCharRange)
    {
        SecretSize secretSize = InferSecretSizeFromCharLength(key.Length);
        caskSignatureCharRange = ComputeCaskSignatureCharRange(secretSize);
        int secretSizeCharOffset = caskSignatureCharRange.Start.Value + SecretSizeOffsetFromCaskSignatureOffset;
        return (SecretSize)(key[secretSizeCharOffset] - 'A');
    }


    public static CaskKey GenerateKey(string providerSignature,
                                      char providerKeyKind,
                                      string? providerData = null,
                                      SecretSize secretSize = SecretSize.Bits256)
    {
        providerData ??= string.Empty;

        ValidateProviderSignature(providerSignature);
        ValidateProviderKeyKind(providerKeyKind);
        ValidateProviderData(providerData);
        ValidateSecretSize(secretSize);

        // Calculate the length of the key.
        int providerDataLengthInBytes = Base64CharsToBytes(providerData.Length);

        int keyLengthInBytes = GetKeyLengthInBytes(providerDataLengthInBytes, secretSize);

        int secretSizeInBytes = (int)secretSize * SecretChunkSizeInBytes;

        // Allocate a buffer on the stack to hold the key bytes.
        Debug.Assert(keyLengthInBytes <= MaxKeyLengthInBytes);
        Span<byte> key = stackalloc byte[keyLengthInBytes];
        Span<byte> destination = key;

        // Entropy comprising the sensitive component of the key. In the future,
        // we will have primitives that allow callers to provider their own
        // secret bytes, e.g., for HMAC scenarios.
        FillRandom(destination[..secretSizeInBytes]);
        destination = destination[secretSizeInBytes..];

        // Padding.
        int paddedSecretSizeInBytes = RoundUpTo3ByteAlignment(secretSizeInBytes);
        int countOfPaddingBytes = paddedSecretSizeInBytes - secretSizeInBytes;
        destination[..countOfPaddingBytes].Clear();
        destination = destination[countOfPaddingBytes..];

        // CASK signature.
        CaskSignatureBytes.CopyTo(destination[..CaskSignatureSizeInBytes]);
        destination = destination[CaskSignatureSizeInBytes..];

        DateTimeOffset now = GetUtcNow();
        ValidateTimestamp(now);
        ReadOnlySpan<char> chars = [
            Base64UrlChars[now.Year - 2025], // Years since 2025.
            Base64UrlChars[now.Month - 1],   // Zero-indexed month.
            Base64UrlChars[now.Day - 1],     // Zero-indexed day.
            Base64UrlChars[now.Hour],        // Zero-indexed hour.
        ];

        int bytesWritten = Base64Url.DecodeFromChars(chars, destination[..YearMonthDayHourSizeInBytes]);
        Debug.Assert(bytesWritten == YearMonthDayHourSizeInBytes);
        destination = destination[YearMonthDayHourSizeInBytes..];

        chars = [
            Base64UrlChars[now.Minute],                  // Zero-index minute.
            Base64UrlChars[(int)secretSize],             // Zero-indexed month.
            Base64UrlChars[providerDataLengthInBytes/3], // Zero-indexed day.
            providerKeyKind,                             // Zero-indexed hour.
        ];

        bytesWritten = Base64Url.DecodeFromChars(chars, destination[..MinuteSizesAndKeyKindSizeInBytes]);
        Debug.Assert(bytesWritten == MinuteSizesAndKeyKindSizeInBytes);
        destination = destination[MinuteSizesAndKeyKindSizeInBytes..];

        bytesWritten = Base64Url.DecodeFromChars(providerData.AsSpan(), destination[..providerDataLengthInBytes]);
        Debug.Assert(bytesWritten == providerDataLengthInBytes);
        destination = destination[providerDataLengthInBytes..];

        bytesWritten = Base64Url.DecodeFromChars(providerSignature.AsSpan(), destination[..ProviderSignatureSizeInBytes]);
        Debug.Assert(bytesWritten == ProviderSignatureSizeInBytes);
        destination = destination[ProviderSignatureSizeInBytes..];

        // Entropy comprising the non-sensitive correlating id of the key.
        FillRandom(destination[..CorrelatingIdSizeInBytes]);

        return CaskKey.Encode(key);
    }


    private static Range ComputeCaskSignatureCharRange(SecretSize secretSize)
    {
        int secretSizeInBytes = (int)secretSize * SecretChunkSizeInBytes;
        int paddedSecretSizeInBytes = RoundUpTo3ByteAlignment(secretSizeInBytes);
        int caskSignatureCharOffset = paddedSecretSizeInBytes / 3 * 4;
        return caskSignatureCharOffset..(caskSignatureCharOffset + CaskSignature.Length);
    }

    private static Range ComputeSignatureByteRange(SecretSize secretSize)
    {
        int secretSizeInBytes = (int)secretSize * SecretChunkSizeInBytes;
        int paddedSecretSizeInBytes = RoundUpTo3ByteAlignment(secretSizeInBytes);
        return paddedSecretSizeInBytes..(paddedSecretSizeInBytes + CaskSignatureSizeInBytes);
    }

    private static SecretSize InferSecretSizeFromCharLength(int lengthInChars)
    {
        Debug.Assert(IsValidKeyLengthInChars(lengthInChars));

        int lengthInBytes = lengthInChars / 4 * 3;
        return InferSecretSizeFromByteLength(lengthInBytes);
    }

    private static SecretSize InferSecretSizeFromByteLength(int lengthInBytes)
    {
        /* 
         *  Required CASK encoded data, 27 bytes.
         *  
         *      public const int FixedKeyComponentSizeInBytes = ( 3 bytes) CaskSignatureSizeInBytes +
                                                                ( 6 bytes) TimestampSizesAndProviderKindInBytes +
                                                                ( 3 bytes) ProviderSignatureSizeInBytes +
                                                                (15 bytes) CorrelatingIdSizeInBytes;
         *  QJJQ YMDH MLOP TEST 1111 2222 3333 4444
         * 
         *  For all keys, there is a maximum of 12 bytes of optional data.
         *  128-bit : 45 -  57 bytes (18 bytes sensitive + 27 reserved, 0 - 12 bytes optional data)
         *  256-bit : 60 -  72 byte  (33 bytes sensitive + 27 reserved, 0 - 12 bytes optional data)
         *  384-bit : 75 -  87 bytes (48 bytes sensitive + 27 reserved, 0 - 12 bytes optional data)
         *  512-bit : 93 - 105 bytes (66 bytes sensitive + 27 reserved, 0 - 12 bytes optional data)
         *  
        */

        Debug.Assert(lengthInBytes >= MinKeyLengthInBytes);
        Debug.Assert(lengthInBytes <= MaxKeyLengthInBytes);
        Debug.Assert(IsValidKeyLengthInBytes(lengthInBytes));

        if (lengthInBytes >= Min512BitKeyLengthInBytes)
        {
            Debug.Assert(lengthInBytes <= Max512BitKeyLengthInBytes);
            return SecretSize.Bits512;
        }
        else if (lengthInBytes >= Min384BitKeyLengthInBytes)
        {
            // A key length of 90 bytes isn't valid for our format. The reason
            // is that the standard limits optionally provided data length to 12
            // bytes, no matter what the size of the sensitive data. Because a
            // 48-byte sensitive data size is already 3-byte aligned, the
            // maximum length of this key is 87 bytes. The next key size (a
            // 64-byte secret) rounds the sensitive data size up to 66 bytes. As
            // a result, the minimal key length for the key size is 93 bytes. It
            // is unfortunate that we have this embedded illegal key size, as it
            // allows an unusual corner case.
            Debug.Assert(lengthInBytes <= Max384BitKeyLengthInBytes);
            return SecretSize.Bits384;
        }
        else if (lengthInBytes >= Min256BitKeyLengthInBytes)
        {
            Debug.Assert(lengthInBytes <= Max256BitKeyLengthInBytes);
            return SecretSize.Bits256;
        }

        Debug.Assert(lengthInBytes >= Min128BitKeyLengthInBytes);
        Debug.Assert(lengthInBytes <= Max128BitKeyLengthInBytes);

        return SecretSize.Bits128;
    }

    /// <summary>
    /// Validates that the provided UTF8-encoded byte sequence represents a valid Cask key.
    /// </summary>
    public static bool IsCaskUtf8(ReadOnlySpan<byte> keyUtf8)
    {
        if (!IsValidKeyLengthInChars(keyUtf8.Length))
        {
            return false;
        }

        SecretSize secretSize = InferSecretSizeFromCharLength(keyUtf8.Length);
        Range caskSignatureCharRange = ComputeCaskSignatureCharRange(secretSize);

        // Check for CASK signature, "QJJQ".
        if (!keyUtf8[caskSignatureCharRange].SequenceEqual(CaskSignatureUtf8))
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
        if (length < MinKeyLengthInChars || length > MaxKeyLengthInChars || !Is4CharAligned(length))
        {
            return false;
        }

        return length <= Max384BitKeyLengthInChars || length >= Min512BitKeyLengthInChars;
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
