// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Buffers.Text;
using System.Diagnostics.CodeAnalysis;
using System.Text;

using Xunit;

using static CommonAnnotatedSecurityKeys.Helpers;
using static CommonAnnotatedSecurityKeys.InternalConstants;
using static CommonAnnotatedSecurityKeys.Limits;

namespace CommonAnnotatedSecurityKeys.Tests;

[ExcludeFromCodeCoverage]
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
                                      providerKeyKind: "M",
                                      expiryInFiveMinuteIncrements: 12 * 24, // 1 day.
                                      providerData: "_NG_");

        IsCaskVerifySuccess(key);
    }

    [Theory]
    [InlineData("Y7G_WqVrIxJ9y3kqLdX6OOhTwC1kTF0eWQidLckLqfEAJQQJTESTMPAlrkxagZHvE1rmbBnVwEHZBBRVnAAA_NG_", CaskKeyKind.PrimaryKey)]
    [InlineData("V5ja_SGw4_eyqKw-mBfx8DlqjJfea4Qs5B6AR3HjlgwAJQQJTESTMPCK8K_4JYG3ppYTmdnSS4TcBBQXDAAA_NG_", CaskKeyKind.PrimaryKey, "CK8K_4JYG3ppYTmdnSS4Tc")]
    public void CaskSecrets_EncodedMatchesDecoded(string encodedKey, CaskKeyKind expectedKeyKind, string expectedC2Id = "")
    {
        TestEncodedMatchedDecoded(encodedKey, expectedKeyKind, expectedC2Id);
    }

    [Fact]
    public void CaskSecrets_EncodedMatchesDecoded_GeneratedKey()
    {
        string key = Cask.GenerateKey(providerSignature: "TEST",
                                      providerKeyKind: "B",
                                      expiryInFiveMinuteIncrements: 12 * 24 * 365, // 1 year.
                                      providerData: "----");
        TestEncodedMatchedDecoded(key, CaskKeyKind.PrimaryKey);
    }

    private void TestEncodedMatchedDecoded(string encodedKey,
                                           CaskKeyKind expectedCaskKeyKind,
                                           string expectedC2id = "")
    {
        // The purpose of this test is to actually produce useful notes in documentation
        // as far as decomposing a CASK key, both from its url-safe base64 form and from
        // the raw bytes.
        //
        // The code demonstrates the core CASK technique of obtaining metadata from the right
        // end of the key, obtaining size information from the key kind enum, and
        // based on that data isolating the randomized component from the optional data.

        IsCaskVerifySuccess(encodedKey);

        byte[] keyBytes = Base64Url.DecodeFromChars(encodedKey.AsSpan());

        string encodedSignature = encodedKey[44..48];
        Span<byte> bytewiseCaskSignature = keyBytes.AsSpan()[33..36];
        Assert.Equal(Base64Url.EncodeToString(bytewiseCaskSignature), encodedSignature);

        string encodedProviderId = encodedKey[48..52];
        Span<byte> bytewiseProviderId = keyBytes.AsSpan()[36..39];
        Assert.Equal(Base64Url.EncodeToString(bytewiseProviderId), encodedProviderId);

        if (!string.IsNullOrEmpty(expectedC2id))
        {
            string encodedC2Id = encodedKey[54..76];
            Assert.Equal(expectedC2id, encodedC2Id);
        }

        string encodedYearMonthDay = encodedKey[76..80];
        Span<byte> bytewiseYearMonthDay = keyBytes.AsSpan()[57..60];
        Assert.Equal(Base64Url.EncodeToString(bytewiseYearMonthDay), encodedYearMonthDay);

        string encodedMinuteAndExpiry = encodedKey[80..84];
        Span<byte> bytewiseMinuteAndExpiry = keyBytes.AsSpan()[60..63];
        Assert.Equal(Base64Url.EncodeToString(bytewiseMinuteAndExpiry), encodedMinuteAndExpiry);

        string encodedOptionalData = encodedKey[84..];
        Span<byte> optionalData = keyBytes.AsSpan()[63..];
        Assert.Equal(Base64Url.EncodeToString(optionalData), encodedOptionalData);

        // This follow-on demonstrates how to get the key kind
        // byte from the bytewise form.
        var kind = (CaskKeyKind)(keyBytes[40] >> CaskKindReservedBits);
        Assert.Equal(expectedCaskKeyKind, kind);
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
        // redundancy (not a bad thing!). For example, if you change the length
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
    public void CaskSecrets_IsCask_InvalidKey_InvalidCaskSignature()
    {
        string key = Cask.GenerateKey("TEST",
                                      providerKeyKind: "G",
                                      expiryInFiveMinuteIncrements: 12 * 6, // 6 hours.
                                      providerData: "-__-");
        Span<char> keyChars = key.ToCharArray().AsSpan();
        Span<char> caskSignatureBytes = "JQQJ".ToCharArray().AsSpan();

        bool valid;

        for (int i = 0; i < 4; i++)
        {
            // Reset the CASK fixed signature.
            caskSignatureBytes.CopyTo(keyChars[CaskSignatureCharRange]);

            // Ensure our starting key is valid.
            key = keyChars.ToString();
            IsCaskVerifySuccess(key);

            // Change one byte of the CASK fixed signature.
            keyChars[CaskSignatureCharRange][i] = '-';

            // Ensure our invalidated key fails the IsCask check.
            key = keyChars.ToString();
            valid = Cask.IsCask(key);
            Assert.False(valid, $"'IsCask' unexpectedly succeeded after modifying CASK signature range: {key}");

            IsCaskVerifyFailure(key);
        }
    }

    [Fact]
    public void CaskSecrets_IsCask_InvalidKey_InvalidSensitiveDataSize()
    {
        string key = Cask.GenerateKey("TEST",
                                      providerKeyKind: "_",
                                      expiryInFiveMinuteIncrements: 12 * 24 * 30, // 30 days.
                                      providerData: "oOOo");

        IsCaskVerifySuccess(key);

        Span<char> keyChars = key.ToCharArray().AsSpan();
        keyChars[SensitiveDataSizeCharIndex] = '_';

        key = keyChars.ToString();
        bool valid = Cask.IsCask(key);
        Assert.False(valid, $"'IsCask' unexpectedly succeeded with invalid size: {key}");

        IsCaskVerifyFailure(key);
    }


    [Fact]
    public void CaskSecrets_IsCask_InvalidKey_InvalidCaskKind()
    {
        string key = Cask.GenerateKey("TEST",
                                      providerKeyKind: "F",
                                      expiryInFiveMinuteIncrements: 2, // 10 minutes.
                                      providerData: "OooOOooOOooO");

        IsCaskVerifySuccess(key);

        Span<char> keyChars = key.ToCharArray().AsSpan();
        keyChars[CaskKindCharIndex] = '9';

        key = keyChars.ToString();
        bool valid = Cask.IsCask(key);
        Assert.False(valid, $"'IsCask' unexpectedly succeeded with invalid CASK key kind: {key}");

        IsCaskVerifyFailure(key);
    }

    [Fact]
    public void CaskSecrets_IsCask_InvalidKey_InvalidProviderKindLength()
    {
        Assert.Throws<ArgumentException>(
            () => Cask.GenerateKey("TEST",
                                   providerKeyKind: "TOOLONG",
                                   expiryInFiveMinuteIncrements: 2, // 10 minutes.
                                   providerData: "OooOOooOOooO"));
    }

    [Fact]
    public void CaskSecrets_IsCask_InvalidKey_InvalidForBase64ProviderKind()
    {
        Assert.Throws<ArgumentException>(
            () => Cask.GenerateKey("TEST",
                                   providerKeyKind: "?",
                                   expiryInFiveMinuteIncrements: 2, // 10 minutes.
                                   providerData: null));
    }

    [Fact]
    public void CaskSecrets_IsCask_InvalidKey_Unaligned()
    {
        string key = Cask.GenerateKey("TEST",
                                      providerKeyKind: "X",
                                      expiryInFiveMinuteIncrements: 12 * 24 * 30, // 30 days.
                                      providerData: "UNALIGN_") + "-";
        bool valid = Cask.IsCask(key);
        Assert.False(valid, $"'IsCask' unexpectedly succeeded with key that was not aligned to 4 chars: {key}");
    }

    [Fact]
    public void CaskSecrets_IsCask_InvalidKey_Whitespace()
    {
        // Replace first 4 characters of secret with whitespace. Whitespace is
        // allowed by `Base64Url` API but is invalid in a Cask key.
        string key = $"    {Cask.GenerateKey("TEST",
                            "X",
                            expiryInFiveMinuteIncrements: 12 * 24 * 90, // 90 days.
                            providerData: null)[4..]}";
        bool valid = Cask.IsCask(key);
        Assert.False(valid, $"'IsCask' unexpectedly succeeded with key that had whitespace: {key}");
    }

    [Fact]
    public void CaskSecrets_IsCask_InvalidKey_InvalidBase64Url()
    {
        string key = Cask.GenerateKey(providerSignature: "TEST",
                                      providerKeyKind: "-",
                                      expiryInFiveMinuteIncrements: 262143, // 910 days, the maximal expiry.
                                      providerData: null);
        key = '?' + key[1..];
        bool valid = Cask.IsCask(key);
        Assert.False(valid, $"IsCask' unexpectedly succeeded with key that was not valid URL-Safe Base64: {key}");
    }

    [Theory]
    [InlineData(int.MinValue)]
    [InlineData(-1)]
    [InlineData(262144)] // 64 ^ 3, exceeds legal maximum by 1.
    [InlineData(int.MaxValue)]
    public void CaskSecrets_IsCask_InvalidKey_InvalidExpiry(int expiryInFiveMinuteIncrements)
    {
        Assert.Throws<ArgumentOutOfRangeException>(
            () => Cask.GenerateKey(providerSignature: "TEST",
                                   providerKeyKind: "-",
                                   expiryInFiveMinuteIncrements,
                                   providerData: null));
    }

    [Fact]
    public void CaskSecrets_GenerateKey_Basic()
    {
        string key = Cask.GenerateKey(providerSignature: "TEST",
                                      providerKeyKind: "Q",
                                      expiryInFiveMinuteIncrements: 0, // No expiry specified.
                                      providerData: "ABCD");

        byte[] keyBytes = Base64Url.DecodeFromChars(key.AsSpan());
        Assert.True(keyBytes.Length % 3 == 0, "'GenerateKey' output wasn't aligned on a 3-byte boundary.");

        IsCaskVerifySuccess(key);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("ABC")]   // Too short.
    [InlineData("ABCDE")] // Too long.
    [InlineData("????")]  // Invalid base64
    [InlineData("    ")]  // Whitespace.
    public void CaskSecrets_GenerateKey_InvalidProviderSignature(string? providerSignature)
    {
        ArgumentException ex = Assert.ThrowsAny<ArgumentException>(() => Cask.GenerateKey(providerSignature!, "A", 0, providerData: null));
        Assert.IsType(providerSignature == null ? typeof(ArgumentNullException) : typeof(ArgumentException), ex);
        Assert.Equal(nameof(providerSignature), ex.ParamName);
    }

    [Theory]
    [InlineData("ABC")]   // Too short
    [InlineData("ABCDE")] // Unaligned
    [InlineData("éééé")]  // Invalid base64
    [InlineData("EXCEEDS_THE_MAX_BY_ONE_XX")]
    [InlineData("THIS_IS_TOO_MUCH_PROVIDER_DATA_SERIOUSLY_IT_IS_VERY_VERY_LONG_AND_THAT_IS_NOT_OKAY")]
    public void CaskSecrets_GenerateKey_InvalidProviderData(string providerData)
    {
        ArgumentException ex = Assert.ThrowsAny<ArgumentException>(() => Cask.GenerateKey("TEST", "X", 0, providerData));
        Assert.IsType(providerData == null ? typeof(ArgumentNullException) : typeof(ArgumentException), ex);
        Assert.Equal(nameof(providerData), ex.ParamName);
    }

    [Fact]
    public void CaskSecrets_GenerateKey_NotDeterministic()
    {
        // We should add more sophistication to checking randomness, but during
        // development, there was once had a bug on .NET Framework polyfill of
        // RNG that left all the entropy bytes zeroed out, so at least cover that
        // in the meantime. :)

        string key = Cask.GenerateKey("TEST", "M", 0, "ABCD");
        string key2 = Cask.GenerateKey("TEST", "M", 0, "ABCD");

        Assert.True(key != key2, $"'GenerateKey' produced the same key twice: {key}");
    }

    [Fact]
    public void CaskSecrets_GenerateKey_DeterministicUsingMocks()
    {
        using Mock mockRandom = Cask.MockFillRandom(buffer => buffer.Fill(1));
        using Mock mockTimestamp = Cask.MockUtcNow(() => new DateTimeOffset(2024, 1, 1, 0, 0, 0, TimeSpan.Zero));

        string key = Cask.GenerateKey("TEST", "M", 0, "ABCD");
        Assert.Equal("AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEAJQQJTESTMPABAQEBAQEBAQEBAQEBAQEBAAAAAAAAABCD", key);
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
                                   providerKeyKind: "y",
                                   expiryInFiveMinuteIncrements: 1, // Five minutes.
                                   providerData: "ABCD"));

        Assert.Contains("2087", ex.Message, StringComparison.Ordinal);
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
            int minute = year % 60;

            var timestamp = new DateTimeOffset(2024 + year, 1 + month, 1 + day, hour, minute, second: 0, TimeSpan.Zero);
            using Mock mock = Cask.MockUtcNow(() => timestamp);

            int expiryInFiveMinuteIncrements = 12 * 24 * 180; // 6 months.

            string key = Cask.GenerateKey(providerSignature: "TEST",
                                          providerKeyKind: "Z",
                                          expiryInFiveMinuteIncrements,
                                          providerData: "ABCD");
            IsCaskVerifySuccess(key);

            string b = Base64UrlChars;
            string expected = $"{b[year]}{b[month]}{b[day]}{b[hour]}{b[minute]}";
            string actual = key[TimestampCharRange];
            Assert.True(expected == actual, $"Expected key '{key}' to have encoded timestamp '{expected}' representing '{timestamp}' but found '{actual}'.");

            Span<byte> expiryBytes = BitConverter.IsLittleEndian
                ? BitConverter.GetBytes(expiryInFiveMinuteIncrements).AsSpan()[..3]
                : BitConverter.GetBytes(expiryInFiveMinuteIncrements).AsSpan()[1..];

            if (BitConverter.IsLittleEndian)
            {
                expiryBytes.Reverse();
            }

            expected = Base64Url.EncodeToString(expiryBytes)[..3];
            actual = key[ExpiryCharRange];

            Assert.True(expected == actual,
                        $"Expected key '{key}' to have encoded expiry '{expected}' for expiry " +
                        $"'{expiryInFiveMinuteIncrements}' but found '{actual}'.");
        }
    }

    private void IsCaskVerifySuccess(string key)
    {
        // Positive test cases.
        Assert.True(Cask.IsCask(key), $"'IsCask(string)' failed for: {key}");
        Assert.True(CaskKey.Regex.IsMatch(key), $"'CaskKey.Regex.IsMatch' failed for: {key}");

        byte[] keyBytes = Base64Url.DecodeFromChars(key.AsSpan());
        Assert.True(Cask.IsCaskBytes(keyBytes), $"'IsCask(byte[])' failed for: {key}'.");
    }

    private void IsCaskVerifyFailure(string key)
    {
        // Negative test cases.
        Assert.False(Cask.IsCask(key), $"'IsCask(string)' unexpectedly succeeded for: {key}");
        Assert.False(CaskKey.Regex.IsMatch(key), $"'CaskKey.Regex.IsMatch' unexpectedly succeeded for: {key}");

        byte[] keyBytes;

        try
        {
            keyBytes = Base64Url.DecodeFromChars(key.AsSpan());
        }
        catch (FormatException)
        {
            // On receiving this exception, we have invalid base64
            // input. As a result, we will change test expections.
            return;
        }

        if (keyBytes != null)
        {
            Assert.False(Cask.IsCaskBytes(keyBytes), $"'IsCask(byte[])' unexpectedly succeeded for: {key}'.");
        }
        else
        {
            Assert.Throws<FormatException>(() => Cask.IsCaskBytes(keyBytes!));
        }
    }
}
