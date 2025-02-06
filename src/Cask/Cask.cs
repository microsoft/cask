// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Buffers;
using System.Buffers.Binary;
using System.Buffers.Text;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.IO.Hashing;
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

        // Check for CASK signature. "JQQJ" base64-decoded.
        if (!keyBytes[CaskSignatureByteRange].SequenceEqual(CaskSignatureBytes))
        {
            return false;
        }

        // Check that kind is valid. NOTE: 'Hash384Bit' is not implemented yet
        // and is therefore treated as invalid here for now.
        if (!TryByteToKind(keyBytes[KindByteIndex], out KeyKind kind) || kind is not KeyKind.Key256Bit and not KeyKind.Hash256Bit)
        {
            return false;
        }

        // Check that reserved version byte is zeroed out. If not, this might be
        // a CASK key from a future version that we do not support.
        if (keyBytes[ReservedVersionByteIndex] != 0)
        {
            return false;
        }

        // Validate checksum.
        ReadOnlySpan<byte> keyBytesWithoutCrc = keyBytes[..Crc32ByteRange.Start];
        uint crc = BinaryPrimitives.ReadUInt32LittleEndian(keyBytes[Crc32ByteRange]);
        uint computedCrc = Crc32.HashToUInt32(keyBytesWithoutCrc);
        return crc == computedCrc;
    }

    public static CaskKey GenerateKey(string providerSignature, string? providerData = null)
    {
        providerData ??= "";

        ValidateProviderSignature(providerSignature);
        ValidateProviderData(providerData);

        // Calculate the length of the key.
        int providerDataLengthInBytes = Base64CharsToBytes(providerData.Length);
        int keyLengthInBytes = GetKeyLengthInBytes(providerDataLengthInBytes);

        // Allocate a buffer on the stack to hold the key bytes.
        Debug.Assert(keyLengthInBytes <= MaxKeyLengthInBytes);
        Span<byte> key = stackalloc byte[keyLengthInBytes];

        // Entropy.
        FillRandom(key[..SecretEntropyInBytes]);

        // Padding.
        key[SecretEntropyInBytes] = 0;

        // Provider data.
        int bytesWritten = Base64Url.DecodeFromChars(providerData.AsSpan(), key[PaddedSecretEntropyInBytes..]);
        Debug.Assert(bytesWritten == providerDataLengthInBytes);

        // CASK signature.
        CaskSignatureBytes.CopyTo(key[CaskSignatureByteRange]);

        // Provider signature.
        bytesWritten = Base64Url.DecodeFromChars(providerSignature.AsSpan(), key[ProviderSignatureByteRange]);
        Debug.Assert(bytesWritten == 3);

        FinalizeKey(key, KeyKind.Key256Bit, UseCurrentTime);
        return CaskKey.Encode(key);
    }

    public static CaskKey GenerateHash(string derivationInput, CaskKey secret)
    {
        return GenerateHash(derivationInput.AsSpan(), secret);
    }

    public static CaskKey GenerateHash(ReadOnlySpan<char> derivationInput, CaskKey secret)
    {
        ThrowIfNotPrimary(secret);
        int byteCount = Encoding.UTF8.GetByteCount(derivationInput);
        Span<byte> derivationInputBytes = byteCount <= MaxStackAlloc ? stackalloc byte[byteCount] : new byte[byteCount];
        Encoding.UTF8.GetBytes(derivationInput, derivationInputBytes);
        return GenerateHash(derivationInputBytes, secret);
    }

    public static CaskKey GenerateHash(ReadOnlySpan<byte> derivationInput, CaskKey secret)
    {
        ThrowIfNotPrimary(secret);
        int hashLengthInBytes = GetHashLengthInBytes(secret.SizeInBytes, out int providerDataLengthInBytes);
        Debug.Assert(hashLengthInBytes <= MaxKeyLengthInBytes);
        Span<byte> hash = stackalloc byte[hashLengthInBytes];
        GenerateHashBytes(derivationInput, secret, providerDataLengthInBytes, hash, UseCurrentTime);
        return CaskKey.Encode(hash);
    }

    private static void GenerateHashBytes(
        ReadOnlySpan<byte> derivationInput,
        CaskKey secret,
        int providerDataLengthInBytes,
        Span<byte> hash,
        ReadOnlySpan<byte> timestamp)
    {

        Debug.Assert(secret.SizeInBytes <= MaxKeyLengthInBytes);
        Span<byte> secretBytes = stackalloc byte[secret.SizeInBytes];
        secret.Decode(secretBytes);

        // 32-byte hash.
        HMACSHA256.HashData(secretBytes, derivationInput, hash);

        // 1 padding byte.
        secretBytes[HMACSHA256.HashSizeInBytes] = 0;

        // Provider data: copy from secret.
        ReadOnlySpan<byte> providerData = secretBytes.Slice(PaddedSecretEntropyInBytes, providerDataLengthInBytes);
        providerData.CopyTo(hash[PaddedHmacSha256SizeInBytes..]);

        // C3ID.
        CaskComputedCorrelatingId.ComputeRaw(secret.ToString(), hash[C3IdByteRange]);

        // Cask signature.
        CaskSignatureBytes.CopyTo(hash[CaskSignatureByteRange]);

        // Provider signature: copy from secret.
        secretBytes[ProviderSignatureByteRange].CopyTo(hash[ProviderSignatureByteRange]);

        FinalizeKey(hash, KeyKind.Hash256Bit, timestamp);
    }

    private static ReadOnlySpan<byte> UseCurrentTime => [];

    private static void FinalizeKey(Span<byte> key, KeyKind kind, ReadOnlySpan<byte> timestamp)
    {
        if (timestamp.IsEmpty)
        {
            DateTimeOffset now = GetUtcNow();
            ValidateTimestamp(now);
            ReadOnlySpan<char> chars = [
                Base64UrlChars[now.Year - 2024], // Years since 2024.
                Base64UrlChars[now.Month - 1],   // Zero-indexed month.
                Base64UrlChars[now.Day - 1],     // Zero-indexed day.
                Base64UrlChars[now.Hour],        // Zero-indexed hour.
            ];

            int bytesWritten = Base64Url.DecodeFromChars(chars, key[TimestampByteRange]);
            Debug.Assert(bytesWritten == 3);
        }
        else
        {
            timestamp.CopyTo(key[TimestampByteRange]);
        }

        key[ReservedVersionByteIndex] = 0;
        key[KindByteIndex] = KindToByte(kind);
        Crc32.Hash(key[..Crc32ByteRange.Start], key[Crc32ByteRange]);
    }

    public static bool CompareHash(CaskKey candidateHash, string derivationInput, CaskKey secret)
    {
        ThrowIfNotInitialized(candidateHash);
        return CompareHash(candidateHash, derivationInput.AsSpan(), secret);
    }

    public static bool CompareHash(CaskKey candidateHash, ReadOnlySpan<char> derivationInput, CaskKey secret)
    {
        ThrowIfNotInitialized(candidateHash);
        int byteCount = Encoding.UTF8.GetByteCount(derivationInput);
        Span<byte> derivationInputBytes = byteCount <= MaxStackAlloc ? stackalloc byte[byteCount] : new byte[byteCount];
        Encoding.UTF8.GetBytes(derivationInput, derivationInputBytes);
        return CompareHash(candidateHash, derivationInputBytes, secret);
    }

    public static bool CompareHash(CaskKey candidateHash, ReadOnlySpan<byte> derivationInput, CaskKey secret)
    {
        ThrowIfNotInitialized(candidateHash);
        ThrowIfNotHash(candidateHash);
        ThrowIfNotInitialized(secret);
        ThrowIfNotPrimary(secret);

        // Check if sizes match.
        int length = GetHashLengthInBytes(secret.SizeInBytes, out int providerDataLengthInBytes);
        if (candidateHash.SizeInBytes != length)
        {
            return false;
        }

        // Decode candidate hash.
        Debug.Assert(length <= MaxKeyLengthInBytes);
        Span<byte> candidateBytes = stackalloc byte[length];
        candidateHash.Decode(candidateBytes);

        // Compute hash with candidate timestamp.
        ReadOnlySpan<byte> candidateTimestamp = candidateBytes[TimestampByteRange];
        Debug.Assert(length <= MaxKeyLengthInBytes);
        Span<byte> computedBytes = stackalloc byte[length];
        GenerateHashBytes(derivationInput, secret, providerDataLengthInBytes, computedBytes, candidateTimestamp);

        // Compare.
        return CryptographicOperations.FixedTimeEquals(candidateBytes, computedBytes);
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
