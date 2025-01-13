// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Buffers.Text;
using System.IO.Hashing;
using System.Text;

using Xunit;

using static CommonAnnotatedSecurityKeys.Limits;

namespace CommonAnnotatedSecurityKeys.Tests;

public abstract class CaskTestsBase
{
    protected CaskTestsBase(ICask cask)
    {
        Cask = cask;
    }

    protected ICask Cask { get; }

    [Theory, InlineData(16), InlineData(32), InlineData(64)]
    public void CaskSecrets_IsCask(int secretEntropyInBytes)
    {
        string key = Cask.GenerateKey(providerSignature: "TEST",
                                      allocatorCode: "88",
                                      providerData: null,
                                      secretEntropyInBytes);

        IsCaskValidate(key);
    }

    [Fact]
    public void CaskSecrets_EncodedMatchesDecoded()
    {
        // The purpose of this test is to actually produce useful notes in documentation
        // as far as decomposing a CASK key, both from its url-safe base64 form and from
        // the raw bytes.

        // The test key below introduces a single, optional 3-byte data value, encoded
        // as the opaque, uninterpreted value of '----'. The remainder of the code
        // demonstrates the core CASK technique of obtaining metadata from the right
        // end of the key, obtaining size information from the key kind enum, and
        // based on that data isolating the randomized component from the optional data.

        string encodedKey = "VOSUKmuLLhv-Fb8czyM-SLRVC5A1orq0vlp65S3fBNEA----JQQJTESTBACDHACcJrXz";
        byte[] keyBytes = Base64Url.DecodeFromUtf8(Encoding.UTF8.GetBytes(encodedKey));

        string encodedCaskSignature = encodedKey[^20..^16];
        Span<byte> bytewiseCaskSignature = keyBytes.AsSpan()[^15..^12];
        Assert.Equal(Base64Url.EncodeToString(bytewiseCaskSignature), encodedCaskSignature);

        string encodedProviderId = encodedKey[^16..^12];
        Span<byte> bytewiseProviderId = keyBytes.AsSpan()[^12..^9];
        Assert.Equal(Base64Url.EncodeToString(bytewiseProviderId), encodedProviderId);

        string encodedTimestamp = encodedKey[^12..^8];
        Span<byte> bytewiseTimestamp = keyBytes.AsSpan()[^9..^6];
        Assert.Equal(Base64Url.EncodeToString(bytewiseTimestamp), encodedTimestamp);

        // The final 2 bits of this byte are reserved.
        var kind = (KeyKind)(keyBytes.AsSpan()[^6] >> 2);
        Assert.Equal(KeyKind.Hash256Bit, kind);

        var version = (CaskVersion)(keyBytes.AsSpan()[^5] >> 4);
        Assert.Equal(CaskVersion.OneZeroZero, version);

        // Our checksum buffer here is 6 bytes because the 4-byte checksum
        // must itself be decoded from a buffer that properly pads the
        // initial byte. We simulate this by zeroing the first two bytes
        // of the buffer and using the last 4 for the checksum
        string encodedChecksum = encodedKey[^6..];
        Span<byte> crc32 = stackalloc byte[6];
        Crc32.Hash(keyBytes.AsSpan()[..^4], crc32[2..]);
        Assert.Equal(Base64Url.EncodeToString(crc32).Substring(2), encodedChecksum);

        // This follow-on example demonstrates obtaining a three-byte sequence and
        // obtain one of its four constituent 6-bit sequences. This is useful in
        // the core definition to obtain the size and version information, which are
        // 12 bits that precede a 4-bit zero padding sequence followed by the first
        // byte of the checksum.
        // 
        // Obtaining the textual value of a 6-bit sequence is trivial from the
        // encoded form but even in this case, it is inconvenient to convert that
        // data into programmatic constructs such as enums. The 'ThreeByteSequence'
        // struct is intended to assist with this problem.

        Span<byte> sizeAndVersionSequence = keyBytes.AsSpan()[^6..^3];
        var sequence = new ThreeByteSequence(sizeAndVersionSequence);

        kind = (KeyKind)sequence.FirstSixBits;
        Assert.Equal(KeyKind.Hash256Bit, kind);

        version = (CaskVersion)sequence.SecondSixBits;
        Assert.Equal(CaskVersion.OneZeroZero, version);
    }

    byte GetSingleEncodedChar(char input)
    {
        byte[] arg = Encoding.UTF8.GetBytes($"{input}A==");
        return Base64Url.DecodeFromUtf8(arg).First();
    }

    [Fact]
    public void CaskSecrets_IsCask_InvalidKey_Null()
    {
        Assert.Throws<ArgumentNullException>(() => Cask.IsCask(null!));
    }

    [Theory]
    [InlineData("")]
    [MemberData(nameof(TooShortOrLongForAKey))]
    public void CaskSecrets_IsCask_InvalidKey_Basic(string? key)
    {
        // We need helpers to make it easier to create keys that are "nearly
        // valid" as in valid except in one dimension like length. We have an
        // example of this IsKeyValidate where we put back a valid checksum
        // after modifiying a key, but it needs to be easier to reuse in more
        // specific tests. It's hard because the IsValid check has a lot of
        // redunancy (not a bad thing!). For example, if you change the length
        // it can fail alignment, not just checksum. This test and similar
        // trivial tests below were stepped through to check code coverage of
        // current implementation, but they are susceptible to starting to pass
        // for the wrong reason if/when implementation changes.

        bool valid = Cask.IsCask(key!);
        Assert.False(valid, $"'IsCask' unexpectedly succeeded with an invalid key: {key}");
    }
    public static readonly TheoryData<string> TooShortOrLongForAKey = [
        new string('-', MinKeyLengthInChars - 1),
        new string('-', MaxKeyLengthInChars + 1),
     ];

    [Fact]
    public void CaskSecrets_IsCask_InvalidKey_Unaligned()
    {
        string key = Cask.GenerateKey("TEST", "88", "UNALIGN_") + "-";
        bool valid = Cask.IsCask(key);
        Assert.False(valid, $"'IsCask' unexpectedly succeeded with key that was not aligned to 4 chars: {key}");
    }

    [Fact]
    public void CaskSecrets_IsCask_InvalidKey_Whitespace()
    {
        // Replace first 4 characters of secret with whitespace. Whitespace is
        // allowed by `Base64Url` API but is invalid in a Cask key.
        string key = $"    {Cask.GenerateKey("TEST", "88")[4..]}";
        bool valid = Cask.IsCask(key);
        Assert.False(valid, $"'IsCask' unexpectedly succeeded with key that had whitespace: {key}");
    }

    [Fact]
    public void CaskSecrets_IsCask_InvalidKey_InvalidBase64Url()
    {
        string key = Cask.GenerateKey("TEST", "88");
        key = '?' + key[1..];
        bool valid = Cask.IsCask(key);
        Assert.False(valid, $"IsCask' unexpectedly succeeded with key that was not valid URL-Safe Base64: {key}");
    }

    [Theory, InlineData(16), InlineData(32), InlineData(64)]
    public void CaskSecrets_GenerateKey_Basic(int secretEntropyInBytes)
    {
        string key = Cask.GenerateKey(providerSignature: "TEST",
                                      allocatorCode: "88",
                                      providerData: "ABCD",
                                      secretEntropyInBytes);

        byte[] keyBytes = Base64Url.DecodeFromChars(key.AsSpan());
        Assert.True(keyBytes.Length % 3 == 0, "'GenerateKey' output wasn't aligned on a 3-byte boundary.");

        IsCaskValidate(key);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("A")]   // Too short
    [InlineData("ABC")] // Too long
    [InlineData("??")]  // Invalid base64
    public void CaskSecrets_GenerateKey_InvalidAllocatorCode(string? allocatorCode)
    {
        ArgumentException ex = Assert.ThrowsAny<ArgumentException>(() => Cask.GenerateKey("TEST", allocatorCode!));
        Assert.IsType(allocatorCode == null ? typeof(ArgumentNullException) : typeof(ArgumentException), ex);
        Assert.Equal(nameof(allocatorCode), ex.ParamName);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("ABC")]   // Too short
    [InlineData("ABCDE")] // Too long
    [InlineData("????")]  // Invalid base64
    public void CaskSecrets_GenerateKey_InvalidProviderSignature(string? providerSignature)
    {
        ArgumentException ex = Assert.ThrowsAny<ArgumentException>(() => Cask.GenerateKey(providerSignature!, "88"));
        Assert.IsType(providerSignature == null ? typeof(ArgumentNullException) : typeof(ArgumentException), ex);
        Assert.Equal(nameof(providerSignature), ex.ParamName);
    }

    [Theory]
    [InlineData("ABC")]   // Too short
    [InlineData("ABCDE")] // Unaligned
    [InlineData("éééé")]  // Invalid base64
    [InlineData("THIS_IS_TOO_MUCH_PROVIDER_DATA_SERIOUSLY_IT_IS_VERY_VERY_LONG_AND_THAT_IS_NOT_OKAY")]
    public void CaskSecrets_GenerateKey_InvalidProviderData(string providerData)
    {
        ArgumentException ex = Assert.ThrowsAny<ArgumentException>(() => Cask.GenerateKey("TEST", "88", providerData));
        Assert.IsType(providerData == null ? typeof(ArgumentNullException) : typeof(ArgumentException), ex);
        Assert.Equal(nameof(providerData), ex.ParamName);
    }

    [Theory]
    [InlineData(-1), InlineData(0), InlineData(15), InlineData(67)]
    public void CaskSecrets_GenerateKey_InvalidSecretEntropy(int secretEntropyInBytes)
    {
        Assert.Throws<ArgumentOutOfRangeException>(
            nameof(secretEntropyInBytes),
            () => Cask.GenerateKey("TEST", "88", null, secretEntropyInBytes));
    }

    [Fact]
    public void CaskSecrets_GenerateKey_NotDeterministic()
    {
        // We should add more sophistication to checking randomness, but during
        // development, there was once had a bug on .NET Framework polyfill of
        // RNG tha left all the entropy bytes zeroed out, so at least cover that
        // in the meantime. :)

        string key = Cask.GenerateKey("TEST", "88", "ABCD");
        string key2 = Cask.GenerateKey("TEST", "88", "ABCD");

        Assert.True(key != key2, $"'GenerateKey' produced the same key twice: {key}");
    }

    [Fact]
    public void CaskSecrets_GenerateKey_DeterministicUsingMocks()
    {
        using Mock mockRandom = Cask.MockFillRandom(buffer => buffer.Fill(1));
        using Mock mockTimestamp = Cask.MockUtcNow(() => new DateTimeOffset(2024, 1, 1, 0, 0, 0, TimeSpan.Zero));

        string key = Cask.GenerateKey("TEST", "88", "ABCD");
        Assert.Equal("AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBABCDJQQJ88AATESTh4ry", key);
    }

    [Theory]
    [InlineData(2023), InlineData(2088)]
    public void CaskSecrets_GenerateKey_InvalidTimestamps(int invalidYear)
    {
        // The CASK standard timestamp is only valid from 2024 - 2087
        // (where the base64-encoded character 'A' indicates 2024, and
        // the last valid base64 character '_' indicates 2087.

        // It is unnecessary to test every month since the code is dirt simple
        // and correctly only checks the year.
        using Mock mock = Cask.MockUtcNow(
            () => new DateTimeOffset(invalidYear, 1, 1, 0, 0, 0, TimeSpan.Zero));

        Exception ex = Assert.Throws<InvalidOperationException>(
            () => Cask.GenerateKey(providerSignature: "TEST",
                                   allocatorCode: "88",
                                   providerData: "ABCD"));

        Assert.Contains("2024", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void CaskSecrets_GenerateKey_ValidTimestamps()
    {
        // Every year from 2024 - 2087 should produce a valid key. We trust that
        // the CASK standard will be long dead by 2087 or perhaps simply all or
        // most programmers will be.
        for (int year = 0; year < 64; year++)
        {
            // Ìt's unnecessary to test every month for every year since the
            // code only is dirt simple and correctly only needs to check the
            // year. 64 * 12 = 768 tests is excessive for this concern.
            int month = year % 12;
            using Mock mock = Cask.MockUtcNow(
                () => new DateTimeOffset(2024 + year, 1 + month, 1, 0, 0, 0, TimeSpan.Zero));

            string key = Cask.GenerateKey(providerSignature: "TEST",
                                          allocatorCode: "88",
                                          providerData: "ABCD");

            IsCaskValidate(key);
        }
    }

    private void IsCaskValidate(string key)
    {
        // Positive test cases.
        Assert.True(Cask.IsCask(key), $"'GenerateKey' output failed 'IsCask(string)': {key}");

        byte[] keyBytes = Base64Url.DecodeFromChars(key.AsSpan());
        Assert.True(Cask.IsCaskBytes(keyBytes), $"'GenerateKey' output failed 'IsCask(byte[]): {key}'.");

        Assert.True(CaskKey.Regex.IsMatch(key), $"'GenerateKey' output failed 'CaskKey.Regex match': {key}");

        // Now we will modify the CASK standard fixed signature only ('JQQJ').
        // We will recompute the checksum and replace it, to ensure that it 
        // is the signature check, and not the checksum hash, that
        // invalidates the secret.

        int signatureIndex = key.LastIndexOf("JQQJ", StringComparison.Ordinal);
        for (int i = 0; i < 4; i++)
        {
            // Cycle through XQQJ, JXQJ, JQXJ, and JQQX.
            string modifiedKey = $"{key[..(signatureIndex + i)]}X{key[(signatureIndex + i + 1)..]}";

            ReadOnlySpan<byte> toChecksum = keyBytes.AsSpan()[..^3];

            byte[] crc32Bytes = new byte[4];
            Crc32.Hash(toChecksum, crc32Bytes);

            string checksum = Base64Url.EncodeToString(crc32Bytes)[..4];
            modifiedKey = $"{modifiedKey[..^4]}{checksum}";

            Assert.False(Cask.IsCask(modifiedKey), $"'IsCask(string)' unexpectedly succeeded with modified 'JQQJ' signature: {modifiedKey}");

            keyBytes = Base64Url.DecodeFromChars(modifiedKey.AsSpan());
            Assert.False(Cask.IsCaskBytes(keyBytes), $"'IsCask(byte[])' unexpectedly succeeded with modified 'JQQJ' signature: {modifiedKey}");
        }

        // Having established that the key is a CASK secret, we now will modify
        // every character in the key, which should invalidate the checksum.

        for (int i = 0; i < key.Length; i++)
        {
            char replacement = key[i] == '-' ? '_' : '-';
            string modifiedKey = $"{key[..i]}{replacement}{key[(i + 1)..]}";

            bool result = Cask.IsCask(modifiedKey);
            Assert.False(result, $"'IsCask(string)' unexpectedly succeeded after invalidating checksum: {modifiedKey}. Original key was: {key}");

            keyBytes = Base64Url.DecodeFromChars(modifiedKey.AsSpan());
            result = Cask.IsCaskBytes(keyBytes);
            Assert.False(result, $"'IsCask(byte[])' unexpectedly succeeded after invalidating checksum: {modifiedKey}. Original key was: {key}");
        }
    }

    [Fact]
    public void CaskSecrets_CompareHash_DeterministicAndNotTimestampSensitive()
    {
        byte[] derivationInput = Encoding.UTF8.GetBytes("DERIVATION_INPUT");
        string secret = Cask.GenerateKey(providerSignature: "TEST", allocatorCode: "88", secretEntropyInBytes: 32);
        string hash = Cask.GenerateHash(derivationInput, secret, secretEntropyInBytes: 32);
        using Mock mock = Cask.MockUtcNow(() => DateTimeOffset.UtcNow.AddMonths(13));
        bool result = Cask.CompareHash(hash, derivationInput, secret, secretEntropyInBytes: 32);
        Assert.True(result, $"'CompareHash' failed when mock time advanced.");
    }

    [Fact]
    public void CaskSecrets_CompareHash_TwoDifferentSecrets()
    {
        byte[] derivationInput = Encoding.UTF8.GetBytes("DERIVATION_INPUT");
        string secret1 = Cask.GenerateKey(providerSignature: "TEST", allocatorCode: "88", secretEntropyInBytes: 32);
        string secret2 = Cask.GenerateKey(providerSignature: "TEST", allocatorCode: "88", secretEntropyInBytes: 32);
        string hash = Cask.GenerateHash(derivationInput, secret1, secretEntropyInBytes: 32);
        bool result = Cask.CompareHash(hash, derivationInput, secret2, secretEntropyInBytes: 32);
        Assert.False(result, $"'CompareHash' should not have succeeded. Two different secrets were used.");
    }

    [Fact]
    public void CaskSecrets_GenerateHash_SmallDerivationInput()
    {
        byte[] derivationInput = Encoding.UTF8.GetBytes("DERIVATION_INPUT");
        string secret = Cask.GenerateKey(providerSignature: "TEST", allocatorCode: "88", secretEntropyInBytes: 32);
        string hash = Cask.GenerateHash(derivationInput, secret, secretEntropyInBytes: 32);
        IsCaskValidate(hash);
    }

    [Fact]
    public void CaskSecrets_GenerateHash_LargeDerivationInput()
    {
        byte[] derivationInput = new byte[4242];
        string secret = Cask.GenerateKey(providerSignature: "TEST", allocatorCode: "88");
        string hash = Cask.GenerateHash(derivationInput, secret, secretEntropyInBytes: 32);
        IsCaskValidate(hash);
    }

    [Fact]
    public void CaskSecrets_CompareHash_SmallDerivationInput()
    {
        byte[] derivationInput = Encoding.UTF8.GetBytes("DERIVATION_INPUT");
        string secret = Cask.GenerateKey(providerSignature: "TEST", allocatorCode: "88", secretEntropyInBytes: 32);
        string hash = Cask.GenerateHash(derivationInput, secret, secretEntropyInBytes: 32);
        bool result = Cask.CompareHash(hash, derivationInput, secret, secretEntropyInBytes: 32);
        Assert.True(result, $"'CompareHash' failed with same secret and same derivation input.");
    }

    [Fact]
    public void CaskSecrets_CompareHash_LargeDerivationInput()
    {
        byte[] derivationInput = new byte[500];
        string secret = Cask.GenerateKey(providerSignature: "TEST", allocatorCode: "88", secretEntropyInBytes: 32);
        string hash = Cask.GenerateHash(derivationInput, secret, secretEntropyInBytes: 32);
        bool result = Cask.CompareHash(hash, derivationInput, secret, secretEntropyInBytes: 32);
        Assert.True(result, $"'CompareHash' failed with same secret and same derivation input.");
    }
}
