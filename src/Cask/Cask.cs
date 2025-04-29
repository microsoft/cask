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
    /// Validates that the provided UTF16-encoded text represents a valid
    /// base64url-encoded CASK key.
    /// </summary>
    public static bool IsCask(ReadOnlySpan<char> encodedKey)
    {
        if (!IsValidKeyLengthInChars(encodedKey.Length))
        {
            return false;
        }

        Range caskSignatureCharRange = ComputeCaskSignatureCharRange(encodedKey.Length, out SecretSize _);

        // Check for CASK signature, "QJJQ".
        if (!encodedKey[caskSignatureCharRange].SequenceEqual(CaskSignature))
        {
            return false;
        }

        int lengthInBytes = Base64CharsToBytes(encodedKey.Length);
        Debug.Assert(lengthInBytes <= MaxKeyLengthInBytes);
        Span<byte> keyBytes = stackalloc byte[lengthInBytes];

        OperationStatus status = Base64Url.DecodeFromChars(encodedKey,
                                                           keyBytes,
                                                           out int charsConsumed,
                                                           out int bytesWritten,
                                                           isFinalBlock: true);

        Debug.Assert(status is OperationStatus.InvalidData || charsConsumed == encodedKey.Length);
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
    /// Validates that the provided UTF8-encoded text represents a valid
    /// base64url-encoded CASK key.
    /// </summary>
    public static bool IsCaskUtf8(ReadOnlySpan<byte> encodedKey)
    {
        if (!IsValidKeyLengthInChars(encodedKey.Length))
        {
            return false;
        }

        Range caskSignatureCharRange = ComputeCaskSignatureCharRange(encodedKey.Length, out SecretSize _);

        // Check for CASK signature, "QJJQ".
        if (!encodedKey[caskSignatureCharRange].SequenceEqual(CaskSignatureUtf8))
        {
            return false;
        }

        int lengthInBytes = Base64CharsToBytes(encodedKey.Length);
        Debug.Assert(lengthInBytes <= MaxKeyLengthInBytes);
        Span<byte> keyBytes = stackalloc byte[lengthInBytes];

        OperationStatus status = Base64Url.DecodeFromUtf8(encodedKey,
                                                          keyBytes,
                                                          out int charsConsumed,
                                                          out int bytesWritten,
                                                          isFinalBlock: true);

        Debug.Assert(status is OperationStatus.InvalidData || charsConsumed == encodedKey.Length);
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
    public static bool IsCaskBytes(ReadOnlySpan<byte> decodedKey)
    {
        if (!IsValidKeyLengthInBytes(decodedKey.Length))
        {
            return false;
        }

        int caskSignatureByteOffset = ComputeSignatureByteOffset(decodedKey.Length, out SecretSize secretSize);

        int paddingBytesCount = secretSize == SecretSize.Bits256 ? 1 : 2;

        for (int i = 1; i <= paddingBytesCount; i++)
        {
            if (decodedKey[caskSignatureByteOffset - i] != 0)
            {
                return false;
            }
        }

        ReadOnlySpan<byte> source = decodedKey[caskSignatureByteOffset..];

        // Check for CASK signature. "QJJQ" base64-decoded.
        if (!source[..CaskSignatureSizeInBytes].SequenceEqual(CaskSignatureBytes))
        {
            return false;
        }
        source = source[CaskSignatureSizeInBytes..];

        ReadOnlySpan<byte> paddingSizesAndProviderKindBytes = source[..PaddingSizesAndProviderKindInBytes];
        source = source[PaddingSizesAndProviderKindInBytes..];

        Span<char> paddingSizesAndProviderKindChars = stackalloc char[PaddingSizesAndProviderKindInChars];
        int bytesWritten = Base64Url.EncodeToChars(paddingSizesAndProviderKindBytes, paddingSizesAndProviderKindChars);
        Debug.Assert(bytesWritten == PaddingSizesAndProviderKindInChars);

        if (paddingSizesAndProviderKindChars[0] != 'A')
        {
            return false;
        }

        // 'A' == index 0 of all printable base64-encoded characters.
        var encodedSecretSize = (SecretSize)(paddingSizesAndProviderKindChars[1] - 'A');
        if (secretSize != encodedSecretSize)
        {
            return false;
        }

        int encodedProviderDataSizeInBytes = (paddingSizesAndProviderKindChars[2] - 'A') * OptionalDataChunkSizeInBytes;

        // Any encoded provider key kind, i.e.,
        // paddingSizesAndProviderKindChars[3], is legal.

        int secretSizeInBytes = (int)encodedSecretSize * SecretChunkSizeInBytes;
        int paddedSecretSizeInBytes = RoundUpTo3ByteAlignment(secretSizeInBytes);
        int expectedKeyLengthInBytes = paddedSecretSizeInBytes + FixedKeyComponentSizeInBytes + encodedProviderDataSizeInBytes;
        if (expectedKeyLengthInBytes != decodedKey.Length)
        {
            return false;
        }

        // All provider signatures are legal, so no validity check.
        source = source[ProviderSignatureSizeInBytes..];

        // Any  provider data is legal, so no validity check.
        source = source[encodedProviderDataSizeInBytes..];

        ReadOnlySpan<byte> paddingAndTimestampBytes = source[..PaddingAndTimestampSizeInBytes];
        Span<char> paddingAndTimestampChars = stackalloc char[PaddingAndTimestampSizeInChars];
        bytesWritten = Base64Url.EncodeToChars(paddingAndTimestampBytes, paddingAndTimestampChars);
        Debug.Assert(bytesWritten == PaddingAndTimestampSizeInChars);

        if (paddingAndTimestampChars[0] != 'A' || paddingAndTimestampChars[1] != 'A')
        {
            return false;
        }

        // Any encoded year, i.e., paddingAndTimestampChars[2], is legal.

        char month = paddingAndTimestampChars[3];
        // An encoded month (a zero-indexed value) that exceeds 11 ('L') is not valid.
        if (month < 'A' || month > 'L')
        {
            return false;
        }

        char day = paddingAndTimestampChars[4];
        // An encoded day (a zero-indexed value) that exceeds 30 ('e') is not valid.
        if (!((day >= 'A' && day <= 'Z') || (day >= 'a' && day <= 'e')))
        {
            return false;
        }

        char hour = paddingAndTimestampChars[5];
        // An encoded hour (a zero-indexed value) that exceeds 23 (base64-encoded 'X') is not valid.
        if (hour < 'A' || hour > 'X')
        {
            return false;
        }

        char minute = paddingAndTimestampChars[6];
        // An encoded minute (a zero-indexed value) that exceeds 59 ('7') is not valid.
        if (!((minute >= 'A' && minute <= 'Z') ||
             (minute >= 'a' && minute <= 'z') ||
             (minute >= '0' && minute <= '7')))
        {
            return false;
        }

        char second = paddingAndTimestampChars[7];
        // An encoded second (a zero-indexed value) that exceeds 59 ('7') is not valid.
        return
            (second >= 'A' && second <= 'Z') ||
            (second >= 'a' && second <= 'z') ||
            (second >= '0' && second <= '7');
    }

    internal static SecretSize ExtractSecretSizeFromKeyChars(ReadOnlySpan<char> key, out Range caskSignatureCharRange)
    {
        caskSignatureCharRange = ComputeCaskSignatureCharRange(key.Length, out _);
        int secretSizeCharOffset = caskSignatureCharRange.End.Value + 1;
        var encodedSecretSize = (SecretSize)(key[secretSizeCharOffset] - 'A');
        return encodedSecretSize;
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

        ReadOnlySpan<char> chars = [
            'A',
            Base64UrlChars[(int)secretSize],
            Base64UrlChars[providerDataLengthInBytes/3],
            providerKeyKind,
        ];

        int bytesWritten = Base64Url.DecodeFromChars(chars, destination[..PaddingSizesAndProviderKindInBytes]);
        Debug.Assert(bytesWritten == PaddingSizesAndProviderKindInBytes);
        destination = destination[PaddingSizesAndProviderKindInBytes..];

        bytesWritten = Base64Url.DecodeFromChars(providerSignature.AsSpan(), destination[..ProviderSignatureSizeInBytes]);
        Debug.Assert(bytesWritten == ProviderSignatureSizeInBytes);
        destination = destination[ProviderSignatureSizeInBytes..];

        bytesWritten = Base64Url.DecodeFromChars(providerData.AsSpan(), destination[..providerDataLengthInBytes]);
        Debug.Assert(bytesWritten == providerDataLengthInBytes);
        destination = destination[providerDataLengthInBytes..];

        DateTimeOffset now = GetUtcNow();
        ValidateTimestamp(now);
        chars = [
            'A',
            'A',
            Base64UrlChars[now.Year - 2025], // Years since 2025.
            Base64UrlChars[now.Month - 1],   // Zero-indexed month.
            Base64UrlChars[now.Day - 1],     // Zero-indexed day.
            Base64UrlChars[now.Hour],        // Zero-indexed hour.
            Base64UrlChars[now.Minute],      // Zero-index minute.
            Base64UrlChars[now.Second],      // Zero-index second.
        ];

        bytesWritten = Base64Url.DecodeFromChars(chars, destination[..PaddingAndTimestampSizeInBytes]);
        Debug.Assert(bytesWritten == PaddingAndTimestampSizeInBytes);
        destination = destination[PaddingAndTimestampSizeInBytes..];

        return CaskKey.Encode(key);
    }

    private static Range ComputeCaskSignatureCharRange(int keyLengthInChars, out SecretSize secretSize)
    {
        int keyLengthInBytes = keyLengthInChars / 4 * 3;
        secretSize = InferSecretSizeFromByteLength(keyLengthInBytes);
        int secretSizeInBytes = (int)secretSize * SecretChunkSizeInBytes;
        int paddedSecretSizeInBytes = RoundUpTo3ByteAlignment(secretSizeInBytes);
        int caskSignatureCharOffset = paddedSecretSizeInBytes / 3 * 4;
        return caskSignatureCharOffset..(caskSignatureCharOffset + CaskSignature.Length);
    }

    private static int ComputeSignatureByteOffset(int keyLengthInBytes, out SecretSize secretSize)
    {
        secretSize = InferSecretSizeFromByteLength(keyLengthInBytes);
        int secretSizeInBytes = (int)secretSize * SecretChunkSizeInBytes;
        int paddedSecretSizeInBytes = RoundUpTo3ByteAlignment(secretSizeInBytes);
        return paddedSecretSizeInBytes;
    }

    private static SecretSize InferSecretSizeFromByteLength(int lengthInBytes)
    {
        /* 
         *  Required CASK encoded data, 15 bytes, see FixedKeyComponentSizeInBytes.
         *
         *  Each 4-character encoded component below comprises 3 bytes of data.
         *  
         *  QJJQ : CASK fixed signature
         *  ZSOK : Zero padding, secret size, optional data size, provider key kind.
         *  TEST : Provider fixed signature.
         *  ZZYM : Zero padding, zero padding, year and month of time-of-allocation.
         *  DHMS : Day, hour, minute and second of time-of-allocation.
         * 
         *  For all keys, there is a maximum of 30 bytes of optional data.
         *  256-bit : 48 -  78 bytes (33 sensitive bytes, 0 - 30 provider bytes, 15 required bytes).
         *  512-bit : 81 - 111 bytes (66 sensitive bytes, 0 - 30 provider bytes, 15 required bytes).
         *  
        */
        Debug.Assert(IsValidKeyLengthInBytes(lengthInBytes));

        if (lengthInBytes >= Min512BitKeyLengthInBytes)
        {
            Debug.Assert(lengthInBytes <= Max512BitKeyLengthInBytes);
            return SecretSize.Bits512;
        }

        Debug.Assert(lengthInBytes >= Min256BitKeyLengthInBytes);
        Debug.Assert(lengthInBytes <= Max256BitKeyLengthInBytes);

        return SecretSize.Bits256;
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
        return
            length >= MinKeyLengthInChars &&
            length <= MaxKeyLengthInChars &&
            Is4CharAligned(length);
    }

    private static bool IsValidKeyLengthInBytes(int length)
    {
        return
            length >= MinKeyLengthInBytes &&
            length <= MaxKeyLengthInBytes &&
            Is3ByteAligned(length);
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
        if (size < SecretSize.Bits256 || size > SecretSize.Bits512)
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
