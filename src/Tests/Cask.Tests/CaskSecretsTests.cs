// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Buffers.Text;
using System.IO.Hashing;
using System.Text;

using Xunit;

using static CommonAnnotatedSecurityKeys.Helpers;
using static CommonAnnotatedSecurityKeys.InternalConstants;
using static CommonAnnotatedSecurityKeys.Limits;

namespace CommonAnnotatedSecurityKeys.Tests;

public abstract class CaskTestsBase
{
    protected CaskTestsBase(ICask cask)
    {
        Cask = cask;
    }

    protected ICask Cask { get; }

    [Fact]
    public void CaskSecrets_IsCask()
    {
        string key = Cask.GenerateKey(providerSignature: "TEST",
                                      providerData: null);

        IsCaskValidate(key);
    }

    [Theory]
    [InlineData("xFLPv3MNBm6q607WSVO0LdzW0frQ3K3fNf-z9jq25QMA----JQQJTESTBAQSAAB6sX_c", KeyKind.Key256Bit)]
    [InlineData("kIn1KAwUqd9JA3krJXuCDB1xvoXJBbC8IuAeaqhneasA----5Fwj_iLe-F84hlOsJQQJTESTBAQRHABzvypD", KeyKind.Hash256Bit, "C3ID5Fwj/iLe+F84hlOs")]
    public void CaskSecrets_EncodedMatchesDecoded(string encodedKey, KeyKind expectedKeyKind, string expectedC3Id = "")
    {
        TestEncodedMatchedDecoded(encodedKey, expectedKeyKind, expectedC3Id);
    }

    [Fact]
    public void CaskSecrets_EncodedMatchesDecoded_GeneratedKey()
    {
        string key = Cask.GenerateKey(providerSignature: "TEST", providerData: "----");
        TestEncodedMatchedDecoded(key, KeyKind.Key256Bit);
    }

    [Fact]
    public void CaskSecrets_EncodedMatchesDecoded_GeneratedHash()
    {
        string secret = Cask.GenerateKey(providerSignature: "TEST", providerData: "----");
        string c3Id = CrossCompanyCorrelatingId.Compute(secret);
        string hash = Cask.GenerateHash(derivationInput: Encoding.UTF8.GetBytes("TEST"), secret);
        TestEncodedMatchedDecoded(hash, KeyKind.Hash256Bit, c3Id);
    }

    private void TestEncodedMatchedDecoded(string encodedKey, KeyKind expectedKind, string expectedC3Id = "")
    {
        // The purpose of this test is to actually produce useful notes in documentation
        // as far as decomposing a CASK key, both from its url-safe base64 form and from
        // the raw bytes.
        //
        // The code demonstrates the core CASK technique of obtaining metadata from the right
        // end of the key, obtaining size information from the key kind enum, and
        // based on that data isolating the randomized component from the optional data.

        IsCaskValidate(encodedKey);

        var expectedBytewiseKind = (BytewiseKeyKind)((int)expectedKind << 2);

        byte[] keyBytes = Base64Url.DecodeFromUtf8(Encoding.UTF8.GetBytes(encodedKey));

        if (!string.IsNullOrEmpty(expectedC3Id))
        {
            string encodedC3Id = encodedKey[^36..^20];
            string canonicalC3Id = "C3ID" + encodedC3Id.Replace('_', '/').Replace('-', '+');
            Assert.Equal(expectedC3Id, canonicalC3Id);
        }

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
        char encodedKeyKind = encodedKey[^8];
        var bytewiseKind = (BytewiseKeyKind)(keyBytes.AsSpan()[^6]);
        Assert.Equal(expectedBytewiseKind, bytewiseKind);
        Assert.Equal(Base64Url.EncodeToString([(byte)bytewiseKind]), $"{encodedKeyKind}A");

        int optionalDataIndex = GetOptionalDataByteIndex(bytewiseKind) + 1;
        int encodedOptionalDataIndex = (optionalDataIndex / 3) * 4;
        string encodedOptionalData = encodedKey[encodedOptionalDataIndex..^20];
        Span<byte> optionalData = keyBytes.AsSpan()[(optionalDataIndex)..^15];
        Assert.Equal(Base64Url.EncodeToString(optionalData), encodedOptionalData);

        char encodedReservedForVersion = encodedKey[^7];
        Assert.Equal('A', encodedReservedForVersion);

        // Our checksum buffer here is 6 bytes because the 4-byte checksum
        // must itself be decoded from a buffer that properly pads the
        // initial byte. We simulate this by zeroing the first two bytes
        // of the buffer and using the last 4 for the checksum
        string encodedChecksum = encodedKey[^6..];
        Span<byte> crc32 = stackalloc byte[6];
        Crc32.Hash(keyBytes.AsSpan()[..^4], crc32[2..]);
        Assert.Equal(Base64Url.EncodeToString(crc32)[2..], encodedChecksum);

        // This follow-on demonstrates how to get the key kind and reservd version
        // byte from the bytewise form.
        var kind = (KeyKind)(keyBytes[^6] >> KindReservedBits);
        Assert.Equal(expectedKind, kind);

        byte reservedForVersion = keyBytes[^5];
        Assert.Equal(0, reservedForVersion);
    }

    enum BytewiseKeyKind : byte
    {
        Key256Bit = KeyKind.Key256Bit << KindReservedBits,
        Hash256Bit = KeyKind.Hash256Bit << KindReservedBits,
        Hash384Bit = KeyKind.Hash384Bit << KindReservedBits,
    }

    private static int GetOptionalDataByteIndex(BytewiseKeyKind kind)
    {
        switch (kind)
        {
            case BytewiseKeyKind.Key256Bit:
            case BytewiseKeyKind.Hash256Bit:
                return 32;

            case BytewiseKeyKind.Hash384Bit:
                return 48;
        }

        throw new InvalidOperationException();
    }

    private static byte GetSingleEncodedChar(char input)
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
        string key = Cask.GenerateKey("TEST", "UNALIGN_") + "-";
        bool valid = Cask.IsCask(key);
        Assert.False(valid, $"'IsCask' unexpectedly succeeded with key that was not aligned to 4 chars: {key}");
    }

    [Fact]
    public void CaskSecrets_IsCask_InvalidKey_Whitespace()
    {
        // Replace first 4 characters of secret with whitespace. Whitespace is
        // allowed by `Base64Url` API but is invalid in a Cask key.
        string key = $"    {Cask.GenerateKey("TEST")[4..]}";
        bool valid = Cask.IsCask(key);
        Assert.False(valid, $"'IsCask' unexpectedly succeeded with key that had whitespace: {key}");
    }

    [Fact]
    public void CaskSecrets_IsCask_InvalidKey_InvalidBase64Url()
    {
        string key = Cask.GenerateKey("TEST");
        key = '?' + key[1..];
        bool valid = Cask.IsCask(key);
        Assert.False(valid, $"IsCask' unexpectedly succeeded with key that was not valid URL-Safe Base64: {key}");
    }

    [Fact]
    public void CaskSecrets_GenerateKey_Basic()
    {
        string key = Cask.GenerateKey(providerSignature: "TEST",
                                      providerData: "ABCD");

        byte[] keyBytes = Base64Url.DecodeFromChars(key.AsSpan());
        Assert.True(keyBytes.Length % 3 == 0, "'GenerateKey' output wasn't aligned on a 3-byte boundary.");

        IsCaskValidate(key);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("ABC")]   // Too short
    [InlineData("ABCDE")] // Too long
    [InlineData("????")]  // Invalid base64
    public void CaskSecrets_GenerateKey_InvalidProviderSignature(string? providerSignature)
    {
        ArgumentException ex = Assert.ThrowsAny<ArgumentException>(() => Cask.GenerateKey(providerSignature!));
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
        ArgumentException ex = Assert.ThrowsAny<ArgumentException>(() => Cask.GenerateKey("TEST", providerData));
        Assert.IsType(providerData == null ? typeof(ArgumentNullException) : typeof(ArgumentException), ex);
        Assert.Equal(nameof(providerData), ex.ParamName);
    }

    [Fact]
    public void CaskSecrets_GenerateKey_NotDeterministic()
    {
        // We should add more sophistication to checking randomness, but during
        // development, there was once had a bug on .NET Framework polyfill of
        // RNG tha left all the entropy bytes zeroed out, so at least cover that
        // in the meantime. :)

        string key = Cask.GenerateKey("TEST", "ABCD");
        string key2 = Cask.GenerateKey("TEST", "ABCD");

        Assert.True(key != key2, $"'GenerateKey' produced the same key twice: {key}");
    }

    [Fact]
    public void CaskSecrets_GenerateKey_DeterministicUsingMocks()
    {
        using Mock mockRandom = Cask.MockFillRandom(buffer => buffer.Fill(1));
        using Mock mockTimestamp = Cask.MockUtcNow(() => new DateTimeOffset(2024, 1, 1, 0, 0, 0, TimeSpan.Zero));

        string key = Cask.GenerateKey("TEST", "ABCD");
        Assert.Equal("AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEAABCDJQQJTESTAAAAAADbTNAf", key);
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
            () => Cask.GenerateKey(providerSignature: "TEST", providerData: "ABCD"));

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
            int month = year % 12;
            int day = year % 28;
            int hour = year % 24;

            var timestamp = new DateTimeOffset(2024 + year, 1 + month, 1 + day, hour, minute: 0, second: 0, TimeSpan.Zero);
            using Mock mock = Cask.MockUtcNow(() => timestamp);

            string key = Cask.GenerateKey(providerSignature: "TEST", providerData: "ABCD");
            IsCaskValidate(key);

            string b = Base64UrlChars;
            string expected = $"{b[year]}{b[month]}{b[day]}{b[hour]}";
            string actual = key[TimestampCharRange];
            Assert.True(expected == actual, $"Expected key '{key}' to have encoded timestamp '{expected}' representing '{timestamp}' but found '{actual}'.");
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
        string secret = Cask.GenerateKey(providerSignature: "TEST");
        string hash = Cask.GenerateHash(derivationInput, secret);
        using Mock mock = Cask.MockUtcNow(() => DateTimeOffset.UtcNow.AddMonths(13));
        bool result = Cask.CompareHash(hash, derivationInput, secret);
        Assert.True(result, $"'CompareHash' failed when mock time advanced.");
    }

    [Fact]
    public void CaskSecrets_CompareHash_TwoDifferentSecrets()
    {
        byte[] derivationInput = Encoding.UTF8.GetBytes("DERIVATION_INPUT");
        string secret1 = Cask.GenerateKey(providerSignature: "TEST");
        string secret2 = Cask.GenerateKey(providerSignature: "TEST");
        string hash = Cask.GenerateHash(derivationInput, secret1);
        bool result = Cask.CompareHash(hash, derivationInput, secret2);
        Assert.False(result, $"'CompareHash' should not have succeeded. Two different secrets were used.");
    }

    [Fact]
    public void CaskSecrets_GenerateHash_SmallDerivationInput()
    {
        byte[] derivationInput = Encoding.UTF8.GetBytes("DERIVATION_INPUT");
        string secret = Cask.GenerateKey(providerSignature: "TEST");
        string hash = Cask.GenerateHash(derivationInput, secret);
        IsCaskValidate(hash);
    }

    [Fact]
    public void CaskSecrets_GenerateHash_LargeDerivationInput()
    {
        byte[] derivationInput = new byte[4242];
        string secret = Cask.GenerateKey(providerSignature: "TEST");
        string hash = Cask.GenerateHash(derivationInput, secret);
        IsCaskValidate(hash);
    }

    [Fact]
    public void CaskSecrets_CompareHash_SmallDerivationInput()
    {
        byte[] derivationInput = Encoding.UTF8.GetBytes("DERIVATION_INPUT");
        string secret = Cask.GenerateKey(providerSignature: "TEST");
        string hash = Cask.GenerateHash(derivationInput, secret);
        bool result = Cask.CompareHash(hash, derivationInput, secret);
        Assert.True(result, $"'CompareHash' failed with same secret and same derivation input.");
    }

    [Fact]
    public void CaskSecrets_CompareHash_LargeDerivationInput()
    {
        byte[] derivationInput = new byte[500];
        string secret = Cask.GenerateKey(providerSignature: "TEST");
        string hash = Cask.GenerateHash(derivationInput, secret);
        bool result = Cask.CompareHash(hash, derivationInput, secret);
        Assert.True(result, $"'CompareHash' failed with same secret and same derivation input.");
    }
}
