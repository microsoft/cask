// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Buffers.Text;
using System.Diagnostics.CodeAnalysis;

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
        foreach (SensitiveDataSize sensitiveDataSize in CaskKeyTests.AllSensitiveDataSizes)
        {
            string key = Cask.GenerateKey(providerSignature: "TEST",
                                          providerKeyKind: "M",
                                          providerData: "_NG_",
                                          sensitiveDataSize);

            IsCaskVerifySuccess(key);
        }
    }

    [Theory]

    

    [InlineData("wMogFlFjZ8hwscMhey01gwAAQJJQACHApBBM_NG_TESThAeRMzD7hjQTtTRWBHeT", SensitiveDataSize.Bits128, "hAeRMzD7hjQTtTRWBHeT")]
    [InlineData("0JCVQ2JHeaWkKTav1pLacOzCV1Xyp9WV8hm77XlRiHAAQJJQACHAoCBM_NG_TESToTXbhEzzLn8y98c9InxI", SensitiveDataSize.Bits256, "oTXbhEzzLn8y98c9InxI")]
    [InlineData("waK9j3ZggRlW615qD5Wgozl_XUvBWg2ivqoQXWWOCW0qWzXeAP1eww9O8NjRf1DVQJJQACHBFDBM_NG_TEST4kWjSsSWJ7cbKR04UfPm", SensitiveDataSize.Bits384, "4kWjSsSWJ7cbKR04UfPm")]
    [InlineData("Zw-OcOy5JMreuHi9CdiXkg3FvCY7ZPzYmfkEwYERY7ZC6fyAHqXPp-OIOW_z9cRmSIJiUTVzsW_-JAyR7URF-gAAQJJQACHBIEBM_NG_TESTg72QxGNa6Y6bwsDn702x", SensitiveDataSize.Bits512, "g72QxGNa6Y6bwsDn702x")]
    public void CaskSecrets_EncodedMatchesDecoded(string encodedKey, SensitiveDataSize expectedSensitiveDataSize, string expectedC2Id)
    {
        TestEncodedMatchedDecoded(encodedKey, expectedSensitiveDataSize, expectedC2Id);
    }

    [Fact]
    public void CaskSecrets_EncodedMatchesDecoded_GeneratedKey()
    {
        string key = Cask.GenerateKey(providerSignature: "TEST",
                                      providerKeyKind: "B",
                                      providerData: "----");
        TestEncodedMatchedDecoded(key, SensitiveDataSize.Bits256);
    }

    private void TestEncodedMatchedDecoded(string encodedKey,
                                           SensitiveDataSize expectedSensitiveDataKind,
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
            string encodedC2Id = encodedKey[^20..];
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
        //var kind = (CaskKeyKind)(keyBytes[40] >> CaskKindReservedBits);
        //Assert.Equal(expectedCaskKeyKind, kind);
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
                                      providerData: "-__-");
        Span<char> keyChars = key.ToCharArray().AsSpan();
        Span<char> caskSignatureBytes = "QJJQ".ToCharArray().AsSpan();

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

    [Theory]
    [InlineData(SensitiveDataSize.Bits128), InlineData(SensitiveDataSize.Bits256), InlineData(SensitiveDataSize.Bits384), InlineData(SensitiveDataSize.Bits512)]
    public void CaskSecrets_IsCask_InvalidKey_InvalidSensitiveDataSize(SensitiveDataSize sensitiveDataSize)
    {
        string key = Cask.GenerateKey("TEST",
                                      providerKeyKind: "_",
                                      providerData: "oOOo",
                                      sensitiveDataSize);

        IsCaskVerifySuccess(key);

        int entropyInBytes = (int)sensitiveDataSize * 16;
        int sensitiveDataSizeInChars = RoundUpTo3ByteAlignment(entropyInBytes) / 3 * 4;
        int sensitiveDataSizeCharIndex = sensitiveDataSizeInChars + CaskSignatureUtf8.Length + 5;

        var encodedSensitiveDataSize = (SensitiveDataSize)(key[sensitiveDataSizeCharIndex] - 'A');
        Assert.Equal(sensitiveDataSize, encodedSensitiveDataSize);

        Span<char> keyChars = key.ToCharArray().AsSpan();
        keyChars[sensitiveDataSizeCharIndex] = '_';

        key = keyChars.ToString();
        bool valid = Cask.IsCask(key);
        Assert.False(valid, $"'IsCask' unexpectedly succeeded with invalid size: {key}");

        IsCaskVerifyFailure(key);
    }


    [Fact]
    public void CaskSecrets_IsCask_InvalidKey_InvalidProviderKindLength()
    {
        Assert.Throws<ArgumentException>(
            () => Cask.GenerateKey("TEST",
                                   providerKeyKind: "TOOLONG",
                                   providerData: "OooOOooOOooO"));
    }

    [Fact]
    public void CaskSecrets_IsCask_InvalidKey_InvalidForBase64ProviderKind()
    {
        Assert.Throws<ArgumentException>(
            () => Cask.GenerateKey("TEST",
                                   providerKeyKind: "?",
                                   providerData: null));
    }

    [Fact]
    public void CaskSecrets_IsCask_InvalidKey_Unaligned()
    {
        string key = Cask.GenerateKey("TEST",
                                      providerKeyKind: "X",
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
                            providerData: null)[4..]}";
        bool valid = Cask.IsCask(key);
        Assert.False(valid, $"'IsCask' unexpectedly succeeded with key that had whitespace: {key}");
    }

    [Fact]
    public void CaskSecrets_IsCask_InvalidKey_InvalidBase64Url()
    {
        string key = Cask.GenerateKey(providerSignature: "TEST",
                                      providerKeyKind: "-",
                                      providerData: null);
        key = '?' + key[1..];
        bool valid = Cask.IsCask(key);
        Assert.False(valid, $"IsCask' unexpectedly succeeded with key that was not valid URL-Safe Base64: {key}");
    }

    [Fact]
    public void CaskSecrets_GenerateKey_Basic()
    {
        string key = Cask.GenerateKey(providerSignature: "TEST",
                                      providerKeyKind: "Q",
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
        ArgumentException ex = Assert.ThrowsAny<ArgumentException>(() => Cask.GenerateKey(providerSignature!, "A", providerData: null));
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
        ArgumentException ex = Assert.ThrowsAny<ArgumentException>(() => Cask.GenerateKey("TEST", "X", providerData));
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

        string key = Cask.GenerateKey("TEST", "M", "ABCD");
        string key2 = Cask.GenerateKey("TEST", "M", "ABCD");

        Assert.True(key != key2, $"'GenerateKey' produced the same key twice: {key}");
    }

    [Theory]
    [InlineData(SensitiveDataSize.Bits128, "_____________________wAAQJJQAAAAABBMABCDTEST____________________")]
    [InlineData(SensitiveDataSize.Bits256, "__________________________________________8AQJJQAAAAACBMABCDTEST____________________")]
    [InlineData(SensitiveDataSize.Bits384, "________________________________________________________________QJJQAAAAADBMABCDTEST____________________")]
    [InlineData(SensitiveDataSize.Bits512, "_____________________________________________________________________________________wAAQJJQAAAAAEBMABCDTEST____________________")]
    public void CaskSecrets_GenerateKey_DeterministicUsingMocks(SensitiveDataSize sensitiveDataSize, string expectedKey)
    {
        using Mock mockRandom = Cask.MockFillRandom(buffer => buffer.Fill(255));
        using Mock mockTimestamp = Cask.MockUtcNow(() => new DateTimeOffset(2025, 1, 1, 0, 0, 0, TimeSpan.Zero));

        string actualKey = Cask.GenerateKey("TEST", "M", "ABCD", sensitiveDataSize);
        Assert.Equal(expectedKey, actualKey);
    }

    [Theory]
    [InlineData(2024), InlineData(2089)]
    public void CaskSecrets_GenerateKey_InvalidTimestamps(int invalidYear)
    {
        // The CASK standard timestamp is only valid from 2025 - 2088
        // (where the base64-encoded character 'A' indicates 2025, and
        // the last valid base64 character '_' indicates 2088.

        // It is unnecessary to test every month since the code is dirt simple
        // and correctly only checks the year.
        using Mock mock = Cask.MockUtcNow(
            () => new DateTimeOffset(invalidYear, 1, 1, 0, 0, 0, TimeSpan.Zero));

        Exception ex = Assert.Throws<InvalidOperationException>(
            () => Cask.GenerateKey(providerSignature: "TEST",
                                   providerKeyKind: "y",
                                   providerData: "ABCD"));

        Assert.Contains("2088", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void CaskSecrets_GenerateKey_ValidTimestamps()
    {
        // Every year from 2025 - 2088 should produce a valid key. We trust that
        // the CASK standard will be long dead by 2088 or perhaps simply all or
        // most programmers will be.
        for (int year = 0; year < 64; year++)
        {
            foreach (SensitiveDataSize sensitiveDataSize in CaskKeyTests.AllSensitiveDataSizes)
            {
                int month = year % 12;
                int day = year % 28;
                int hour = year % 24;
                int minute = year % 60;

                var timestamp = new DateTimeOffset(2025 + year, 1 + month, 1 + day, hour, minute, second: 0, TimeSpan.Zero);
                using Mock mock = Cask.MockUtcNow(() => timestamp);

                string key = Cask.GenerateKey(providerSignature: "TEST",
                                              providerKeyKind: "Z",
                                              providerData: "ABCD",
                                              sensitiveDataSize);
                IsCaskVerifySuccess(key);

                string b = Base64UrlChars;
                string expected = $"{b[year]}{b[month]}{b[day]}{b[hour]}{b[minute]}";

                int entropyInBytes = (int)sensitiveDataSize * 16;
                int sensitiveDataSizeInChars = RoundUpTo3ByteAlignment(entropyInBytes) / 3 * 4;
                int timestampCharOffset = sensitiveDataSizeInChars + CaskSignatureUtf8.Length;
                Range timestampCharRange = timestampCharOffset..(timestampCharOffset + 5);

                string actual = key[timestampCharRange];
                Assert.True(expected == actual, $"Expected key '{key}' to have encoded timestamp '{expected}' representing '{timestamp}' but found '{actual}'.");
            }
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
