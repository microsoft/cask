// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Buffers;
using System.Buffers.Text;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.IO.Hashing;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;

using static CommonAnnotatedSecurityKeys.Limits;

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

        ReadOnlySpan<char> signature = key[^16..^12];
        if ('J' != signature[0] || 'Q' != signature[1] || 'Q' != signature[2] || 'J' != signature[3])
        {
            return false;
        }

        int maxLength = Base64Url.GetMaxDecodedLength(key.Length);
        Debug.Assert(maxLength < MaxKeyLengthInBytes);
        Span<byte> keyBytes = stackalloc byte[maxLength];

        OperationStatus status = Base64Url.DecodeFromChars(
            key,
            keyBytes,
            out int charsConsumed,
            out int bytesWritten,
            isFinalBlock: true);

        Debug.Assert(status is OperationStatus.InvalidData || charsConsumed == key.Length);
        Debug.Assert(status is not OperationStatus.DestinationTooSmall or OperationStatus.NeedMoreData);

        if (status != OperationStatus.Done)
        {
            return false;
        }

        keyBytes = keyBytes[..bytesWritten];
        return IsCaskBytes(keyBytes);
    }

    /// <summary>
    /// Validates that the provided UTF8-encoded byte sequence represents a valid Cask key.
    /// </summary>
    public static bool IsCaskUtf8(ReadOnlySpan<byte> keyUTF8)
    {
        // NOTE: Since all valid Cask keys are ASCII-safe, we use the same UTF-16 char limits as byte limits..
        if (keyUTF8.Length < MinKeyLengthInChars || keyUTF8.Length > MaxKeyLengthInChars || !Is4CharAligned(keyUTF8.Length))
        {
            return false;
        }

        ReadOnlySpan<byte> signature = keyUTF8[^16..^12];
        if ('J' != signature[0] || 'Q' != signature[1] || 'Q' != signature[2] || 'J' != signature[3])
        {
            return false;
        }

        int maxLength = Base64Url.GetMaxDecodedLength(keyUTF8.Length);
        Debug.Assert(maxLength < MaxKeyLengthInBytes);
        Span<byte> keyBytes = stackalloc byte[maxLength];

        OperationStatus status = Base64Url.DecodeFromUtf8(
            keyUTF8,
            keyBytes,
            out int charsConsumed,
            out int bytesWritten,
            isFinalBlock: true);

        Debug.Assert(status is OperationStatus.InvalidData || charsConsumed == keyUTF8.Length);
        Debug.Assert(status is not OperationStatus.DestinationTooSmall or OperationStatus.NeedMoreData);

        if (status != OperationStatus.Done)
        {
            return false;
        }

        keyBytes = keyBytes[..bytesWritten];
        return IsCaskBytes(keyBytes);
    }

    /// <summary>
    /// Validates that the provided byte sequence represents a valid Cask key in binary decoded form.
    /// </summary>
    public static bool IsCaskBytes(ReadOnlySpan<byte> keyBytes)
    {
        // Check length is within limits and 3-byte aligned.
        if (keyBytes.Length < MinKeyLengthInBytes || keyBytes.Length > MaxKeyLengthInBytes || !Is3ByteAligned(keyBytes.Length))
        {
            return false;
        }

        // Check signature: [0x25, 0x04, 0x09] is JQQJ decoded from base64 to bytes
        ReadOnlySpan<byte> signature = keyBytes[^12..^8];
        if (0x25 != signature[0] || 0x04 != signature[1] || 0x09 != signature[2])
        {
            return false;
        }

        // Validate 3-byte partial CRC32 checksum
        ReadOnlySpan<byte> keyBytesWithoutCrc = keyBytes[..^3];
        ReadOnlySpan<byte> crc = keyBytes[^3..];
        Span<byte> computedCrc = stackalloc byte[4];
        Crc32.Hash(keyBytesWithoutCrc, computedCrc);
        return computedCrc[0] == crc[0] && computedCrc[1] == crc[1] && computedCrc[2] == crc[2];
    }

    public static CaskKey GenerateKey(string providerSignature,
                                      string allocatorCode,
                                      string? providerData = null,
                                      int secretEntropyInBytes = 32)
    {
        providerData ??= "";

        // Ensure that the secretEntropyInBytes is a multiple of 3. We keep all
        // data aligned along a 3-byte boundary to ensure consistent base64
        // encoding in the key for fixed components. 
        secretEntropyInBytes = RoundUpTo3ByteAlignment(secretEntropyInBytes);

        ValidateProviderSignature(providerSignature);
        ValidateAllocatorCode(allocatorCode);
        ValidateProviderData(providerData);
        ValidateSecretEntropy(secretEntropyInBytes);

        // Calculate the length of the key
        int providerDataLengthInBytes = Base64CharsToBytes(providerData.Length);
        int keyLengthInBytes = GetKeyLengthInBytes(secretEntropyInBytes, providerDataLengthInBytes);
        Debug.Assert(keyLengthInBytes <= MaxKeyLengthInBytes);

        // Allocate a buffer on the stack to hold the key bytes
        Span<byte> keyBytes = stackalloc byte[keyLengthInBytes];

        // Use another span like a pointer, moving it forward as we write data.
        Span<byte> destination = keyBytes;

        // Entropy
        FillRandom(destination[..secretEntropyInBytes]);
        destination = destination[secretEntropyInBytes..];

        // Provider data
        int bytesWritten = Base64Url.DecodeFromChars(providerData.AsSpan(), destination);
        Debug.Assert(bytesWritten == providerDataLengthInBytes);
        destination = destination[providerDataLengthInBytes..];

        // CASK signature: [0x25, 0x04, 0x09] is JQQJ decoded from base64 to bytes
        destination[0] = 0x25;
        destination[1] = 0x04;
        destination[2] = 0x09;
        destination = destination[3..];

        // Allocator code and timestamp
        DateTimeOffset now = GetUtcNow();
        ValidateTimestamp(now);
        ReadOnlySpan<char> allocatorAndTimestamp = [
            allocatorCode[0],
            allocatorCode[1],
            Base64UrlChars[now.Year - 2024], // years since 2024
            Base64UrlChars[now.Month - 1],   // zero-indexed month
        ];
        bytesWritten = Base64Url.DecodeFromChars(allocatorAndTimestamp, destination);
        Debug.Assert(bytesWritten == 3);
        destination = destination[3..];

        // Provider signature
        bytesWritten = Base64Url.DecodeFromChars(providerSignature.AsSpan(), destination);
        Debug.Assert(bytesWritten == 3);
        destination = destination[3..];

        ComputeChecksum(keyBytes, destination);
        return CaskKey.Encode(keyBytes);
    }

    public static CaskKey GenerateHash(ReadOnlySpan<byte> derivationInput, CaskKey secret, int secretEntropyInBytes)
    {
        int hashLengthInBytes = GetHashLengthInBytes(secret, ref secretEntropyInBytes, out int providerDataLengthInBytes);
        Span<byte> hash = stackalloc byte[hashLengthInBytes];
        GenerateHashBytes(derivationInput, secret, secretEntropyInBytes, providerDataLengthInBytes, hash);
        return CaskKey.Encode(hash);
    }

    private static int GetHashLengthInBytes(CaskKey secret, ref int secretEntropyInBytes, out int providerDataLengthInBytes)
    {
        secretEntropyInBytes = RoundUpTo3ByteAlignment(secretEntropyInBytes);

        ThrowIfDefault(secret);
        ValidateSecretEntropy(secretEntropyInBytes);

        providerDataLengthInBytes = Base64CharsToBytes(secret.ToString().Length) - secretEntropyInBytes - FixedKeyComponentSizeInBytes;
        return GetKeyLengthInBytes(33, providerDataLengthInBytes);
    }

    private static void GenerateHashBytes(
        ReadOnlySpan<byte> derivationInput,
        CaskKey secret,
        int secretEntropyInBytes,
        int providerDataLengthInBytes,
        Span<byte> hash)
    {
        int keyLengthInBytes = Base64CharsToBytes(secret.ToString().Length);
        Debug.Assert(keyLengthInBytes >= MinKeyLengthInBytes && keyLengthInBytes <= MaxKeyLengthInBytes);
        Span<byte> secretBytes = stackalloc byte[keyLengthInBytes];
        Base64Url.DecodeFromChars(secret.ToString().AsSpan(), secretBytes);

        Span<byte> destination = hash;

        // 32-byte Hash
        HMACSHA256.HashData(secretBytes, derivationInput, destination);
        destination = destination[32..];

        // 1 padding byte
        destination[0] = 0;
        destination = destination[1..];

        // Copy provider data
        ReadOnlySpan<byte> source = secretBytes[secretEntropyInBytes..];
        source[..providerDataLengthInBytes].CopyTo(destination);
        source = source[providerDataLengthInBytes..];
        destination = destination[providerDataLengthInBytes..];

        // TODO: Pseudo-code says allocator code from key with new timestamp?
        // But how can we expect hashes to compare equal if each hash gets a new timestamp?...
        // Was compare hash supposed to mask out the timestamp?
        // So copy all fixed components but checksum: CASK signature, allocator code, timestamp, provider signature
        source[..9].CopyTo(destination);
        destination = destination[9..];

        ComputeChecksum(hash, destination);
    }

    private static void ComputeChecksum(ReadOnlySpan<byte> keyBytes, Span<byte> checksumDestination)
    {
        Debug.Assert(checksumDestination.Length == 3, "There should only be 3 bytes left for the checksum.");
        Span<byte> crc32 = stackalloc byte[4];
        Crc32.Hash(keyBytes[..^3], crc32);
        crc32[..3].CopyTo(checksumDestination);
    }

    public static bool CompareHash(CaskKey candidateHash, ReadOnlySpan<byte> derivationInput, CaskKey secret, int secretEntropyInBytes)
    {
        // Compute hash
        int length = GetHashLengthInBytes(secret, ref secretEntropyInBytes, out int providerDataLengthInBytes);
        Span<byte> computedBytes = stackalloc byte[length];
        GenerateHashBytes(derivationInput, secret, secretEntropyInBytes, providerDataLengthInBytes, computedBytes);

        // Decode candidate hash
        int candidateHashLengthInBytes = Base64CharsToBytes(candidateHash.ToString().Length);
        if (candidateHashLengthInBytes != length)
        {
            return false;
        }
        Span<byte> candidateBytes = stackalloc byte[length];
        Base64Url.DecodeFromChars(candidateHash.ToString().AsSpan(), candidateBytes);

        // Compare
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

    private static void ValidateSecretEntropy(int secretEntropyInBytes)
    {
        ThrowIfLessThan(secretEntropyInBytes, MinSecretEntropyInBytes);
        ThrowIfGreaterThan(secretEntropyInBytes, MaxSecretEntropyInBytes);
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
        throw new ArgumentException($"Provider data must be a multiple of 4 characters long: '{value}'", paramName);
    }

    [DoesNotReturn]
    private static void ThrowProviderDataTooLong(string value, [CallerArgumentExpression(nameof(value))] string? paramName = null)
    {
        throw new ArgumentException($"Provider data must be at most {MaxProviderDataLengthInChars} characters: ", paramName);
    }

    [DoesNotReturn]
    private static void ThrowIllegalUrlSafeBase64(string value, [CallerArgumentExpression(nameof(value))] string? paramName = null)
    {
        throw new ArgumentException($"Value includes characters that are not legal URL-safe base64: '{value}", paramName);
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