// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Buffers.Text;

using Xunit;

using static CommonAnnotatedSecurityKeys.Helpers;
using static CommonAnnotatedSecurityKeys.Limits;

namespace CommonAnnotatedSecurityKeys.Tests;

public abstract class CaskTestsBase
{
    private protected static readonly HashSet<char> s_printableBase64UrlCharacters =
    [.. "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"];

    protected CaskTestsBase(ICask cask)
    {
        Cask = cask;
    }

    protected ICask Cask { get; }

    [Theory, InlineData(SecretSize.Bits256), InlineData(SecretSize.Bits512)]
    public void CaskSecrets_IsCask(SecretSize secretSize)
    {
        for (int optionalDataChunks = 0; optionalDataChunks <= 10; optionalDataChunks++)
        {
            string key = Cask.GenerateKey(providerSignature: "TEST",
                                      providerKeyKind: 'M',
                                      providerData: new string('-', optionalDataChunks * 4),
                                      secretSize);

            IsCaskVerifySuccess(key);
        }
    }

    [Theory]
    [InlineData("", SecretSize.Bits256), InlineData("-MF--NG--RW--RG-", SecretSize.Bits256)]
    [InlineData("", SecretSize.Bits512), InlineData("-MF--NG--RW--RG-", SecretSize.Bits512)]
    public void CaskSecrets_EncodedMatchesDecoded_GeneratedKey(string providerData, SecretSize secretSize)
    {
        string key = Cask.GenerateKey(providerSignature: "TEST",
                                      providerKeyKind: 'B',
                                      providerData,
                                      secretSize);

        TestEncodedMatchedDecoded(key, providerData, secretSize);
    }

    private void TestEncodedMatchedDecoded(string encodedKey,
                                           string providerData,
                                           SecretSize secretSize)
    {
        providerData ??= string.Empty;
        IsCaskVerifySuccess(encodedKey);

        // The purpose of this test is to actually produce useful notes in
        // documentation as far as decomposing a CASK key, both from its
        // url-safe base64-encoded form and from the raw bytes.
        //
        // The code demonstrates the core CASK technique of obtaining the
        // lengths of the sensitive and optional data segments of the key in
        // order to interpret or validate other values.
        ReadOnlySpan<byte> decodedKey = Base64Url.DecodeFromChars(encodedKey.AsSpan());

        ReadOnlySpan<char> encodedSource = encodedKey.AsSpan();
        ReadOnlySpan<byte> decodedSource = decodedKey;

        // A CASK secret may encode 256 or 512 bits of sensitive data and
        // its length will differ accordingly. CASK also allows for optional
        // data to be included by a secret provider. Because CASK limits
        // optional data to 30 bytes at most, a CASK secret of particular
        // sensitive data size will always be smaller than a key of the next
        // larger sensitive data size. Examining the key length, therefore, is a
        // simple way to determine the encoded sensitive data size, after which
        // the size of the optional data is clear.

        if (encodedKey.Length >= 108)
        {
            Assert.True(decodedSource.Length >= 81);
            Assert.Equal(SecretSize.Bits512, secretSize);
        }
        else
        {
            Assert.True(decodedSource.Length >= 48);
            Assert.Equal(SecretSize.Bits256, secretSize);
        }

        // The secret size encoding is simply a count of 32-byte segments of
        // secret entropy or other sensitive data. The CASK standard allows for
        // 1 - 2 segments (comrising a 256-bit or 512-bit key).
        int secretSizeInBytes = (int)secretSize * 32;

        // Because CASK enforces 3-byte alignment to allow for fixed readability
        // in encoded form and convenient bytewise access, the number of bytes
        // of sensitive in a CASK key must be padded for 16-, 32- and 64-byte
        // secrets. A 48-byte secret is already aligned on a 3-byte boundary and
        // therefore is not padded.
        int paddedSecretSizeInBytes = (secretSizeInBytes + 3 - 1) / 3 * 3;

        // A 384-bit secret has no padding. For other sizes, it may be useful to
        // verify that the zero padding is present when validating keys. This is
        // easily accomplished in the bytewise form.
        int paddingInBytes = paddedSecretSizeInBytes - secretSizeInBytes;
        for (int i = 0; i < paddingInBytes; i++)
        {
            Assert.Equal(0, decodedSource[secretSizeInBytes + i]);
        }

        int paddedSecretSizeInChars = (paddedSecretSizeInBytes / 3) * 4;
        string encodedSensitiveData = encodedSource[..paddedSecretSizeInChars].ToString();

        // If we have non-zero padding bytes, there will be an encoded character
        // with either two or four bits of trailing zeros, which bring the data
        // into bytewise alignment.
        if (paddingInBytes > 0)
        {
            // In the encoded key, we should observe an encoded character of 'A'
            // zero for every padding byte. i.e., this test looks for either 0,
            // 6, or 12 bits of trailing zeros in the encoded sensitive data.
            Assert.Equal('A', encodedSensitiveData[^paddingInBytes]);
            Assert.EndsWith(new string('A', paddingInBytes), encodedSensitiveData, StringComparison.Ordinal);

            char partlyZeroedChar = encodedSensitiveData[^(paddingInBytes + 1)];

            if (paddingInBytes == 1)
            {
                var base64IndicesWithTwoTrailingZeroBits = new HashSet<char>
                {
                    'A', 'E', 'I', 'M', 'Q', 'U', 'Y', 'c',
                    'g', 'k', 'o', 's', 'w', '0', '4', '8'
                };
                Assert.Contains(partlyZeroedChar, base64IndicesWithTwoTrailingZeroBits);
            }
            else
            {
                var base64IndicesWithFourTrailingZeroBits = new HashSet<char> { 'A', 'Q', 'g', 'w' };
                Assert.Contains(partlyZeroedChar, base64IndicesWithFourTrailingZeroBits);
            }
        }

        encodedSource = encodedSource[paddedSecretSizeInChars..];
        decodedSource = decodedSource[paddedSecretSizeInBytes..];

        // From here, the computed sensitive data size as bytes or encoded chars
        // becomes the base offset to us to examine and/or validate other data.

        string caskSignature = "QJJQ";
        Span<byte> caskSignatureBytes = stackalloc byte[3];
        Base64Url.DecodeFromChars(caskSignature.AsSpan(), caskSignatureBytes);

        Assert.True(decodedSource[..3].SequenceEqual(caskSignatureBytes));
        Assert.True(decodedSource[..3].SequenceEqual([(byte)0x40, (byte)0x92, (byte)0x50]));
        Assert.Equal(caskSignature, encodedSource[..4].ToString());

        encodedSource = encodedSource[4..];
        decodedSource = decodedSource[3..];

        // The padding (p), secret size (s), optional provider data size (o),
        // and provider key kind (k) are expressed as 4 distinct 6-bit encoded
        // characters (psok) and so the bytewise interpretation of this data is
        // less straightforward. For this segment, it may be easiest to
        // base64-encode key bytes and process the encoded form.
        Span<char> psokChars = stackalloc char[4];
        Base64Url.EncodeToChars(decodedSource[..3], psokChars);
        Assert.Equal(encodedSource[..4].ToString(), psokChars.ToString());

        encodedSource = encodedSource[4..];
        decodedSource = decodedSource[3..];

        Assert.Equal('A', psokChars[0]);

        SecretSize encodedSecretSize = (SecretSize)psokChars[1] - 'A';
        Assert.Equal(secretSize, encodedSecretSize);
        Assert.True(secretSize != 0);

        // The optional data size is expressed as a 6-bit encoded character.
        int optionalDataSizeInBytes = (psokChars[2] - 'A') * 3;
        Assert.True(optionalDataSizeInBytes >= 0 && optionalDataSizeInBytes <= 30);

        // Now we can validate the key size.
        int expectedKeyLengthInBytes = paddedSecretSizeInBytes + optionalDataSizeInBytes + 15;
        Assert.Equal(expectedKeyLengthInBytes, decodedKey.Length);

        int optionalDataSizeInChars = (optionalDataSizeInBytes / 3) * 4;
        int expectedKeyLengthInChars = paddedSecretSizeInChars + optionalDataSizeInChars + 20;
        Assert.Equal(expectedKeyLengthInChars, encodedKey.Length);

        // The provider key kind is provider-defined. Any value is legal
        // and so we do not validate psokChars[3] here.

        // All printable characters in the provider fixed signature are legal
        // and so we do not validate this data.
        encodedSource = encodedSource[4..];
        decodedSource = decodedSource[3..];

        // Now skip past all optional data (for which there are no
        // formatting restrictions).
        encodedSource = encodedSource[optionalDataSizeInChars..];
        decodedSource = decodedSource[optionalDataSizeInBytes..];

        // The final padding characters (pp) and time-of-allocation year (y),
        // month (m), day (d), hour (h) and second (s) are expressed as 8
        // distinct 6-bit encoded characters (ppymdhms) and so the bytewise
        // interpretation of this data is less straightforward. For this
        // segment, it may be easiest to base64-encode key bytes and process the
        // encoded form, particularly if the timestamp will be validated.

        Span<char> ppymdhmsChars = stackalloc char[8];
        Base64Url.EncodeToChars(decodedSource, ppymdhmsChars);
        Assert.Equal(encodedSource.ToString(), ppymdhmsChars.ToString());

        // Outside of the timestamp, the remaining CASK 6-bit components are intended to be
        // easily processed when converted into their base64 printable character index.
        var base64UrlPrintableCharIndices = new Dictionary<char, int>
        {
            ['A'] = 0,
            ['B'] = 1,
            ['C'] = 2,
            ['D'] = 3,
            ['E'] = 4,
            ['F'] = 5,
            ['G'] = 6,
            ['H'] = 7,
            ['I'] = 8,
            ['J'] = 9,
            ['K'] = 10,
            ['L'] = 11,
            ['M'] = 12,
            ['N'] = 13,
            ['O'] = 14,
            ['P'] = 15,
            ['Q'] = 16,
            ['R'] = 17,
            ['S'] = 18,
            ['T'] = 19,
            ['U'] = 20,
            ['V'] = 21,
            ['W'] = 22,
            ['X'] = 23,
            ['Y'] = 24,
            ['Z'] = 25,
            ['a'] = 26,
            ['b'] = 27,
            ['c'] = 28,
            ['d'] = 29,
            ['e'] = 30,
            ['f'] = 31,
            ['g'] = 32,
            ['h'] = 33,
            ['i'] = 34,
            ['j'] = 35,
            ['k'] = 36,
            ['l'] = 37,
            ['m'] = 38,
            ['n'] = 39,
            ['o'] = 40,
            ['p'] = 41,
            ['q'] = 42,
            ['r'] = 43,
            ['s'] = 44,
            ['t'] = 45,
            ['u'] = 46,
            ['v'] = 47,
            ['w'] = 48,
            ['x'] = 49,
            ['y'] = 50,
            ['z'] = 51,
            ['0'] = 52,
            ['1'] = 53,
            ['2'] = 54,
            ['3'] = 55,
            ['4'] = 56,
            ['5'] = 57,
            ['6'] = 58,
            ['7'] = 59,
            ['8'] = 60,
            ['9'] = 61,
            ['-'] = 62,
            ['_'] = 63
        };

        // Ensure encoded zero padding.
        Assert.Equal('A', ppymdhmsChars[0]);
        Assert.Equal('A', ppymdhmsChars[1]);

        char encodedYearChar = ppymdhmsChars[2];
        char encodedMonthChar = ppymdhmsChars[3];
        char encodedDayChar = ppymdhmsChars[4];
        char encodedHourChar = ppymdhmsChars[5];
        char encodedMinuteChar = ppymdhmsChars[6];
        char encodedSecondChar = ppymdhmsChars[7];

        int year = base64UrlPrintableCharIndices[encodedYearChar];
        int month = base64UrlPrintableCharIndices[encodedMonthChar];
        int day = base64UrlPrintableCharIndices[encodedDayChar];
        int hour = base64UrlPrintableCharIndices[encodedHourChar];
        int minute = base64UrlPrintableCharIndices[encodedMinuteChar];
        int second = base64UrlPrintableCharIndices[encodedSecondChar];

        // All encoded year values are legal.
        Assert.True(month >= 0 && month < 12, $"Month value '{month}' is out of range.");
        Assert.True(day >= 0 && day < 31, $"Day value '{day}' is out of range.");
        Assert.True(hour >= 0 && hour < 24, $"Hour value '{hour}' is out of range.");
        Assert.True(minute >= 0 && minute < 60, $"Minute value '{minute}' is out of range.");
        Assert.True(second >= 0 && second < 60, $"Second value '{second}' is out of range.");

        var utcTimestamp = new DateTimeOffset(year + 2025, month + 1, day + 1, hour, minute, second, TimeSpan.Zero);
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

    [Theory, InlineData(SecretSize.Bits256), InlineData(SecretSize.Bits512)]
    public void CaskSecrets_IsCask_InvalidKey_InvalidCaskSignature(SecretSize secretSize)
    {
        string key = Cask.GenerateKey("TEST",
                                      providerKeyKind: 'G',
                                      providerData: "-__-",
                                      secretSize);

        int caskSignatureCharOffset = ComputeCaskSignatureCharOffset(secretSize);

        for (int i = 0; i < 4; i++)
        {
            Span<char> modifiedKeyChars = key.ToCharArray().AsSpan();
            Span<char> destination = modifiedKeyChars;

            // Ensure our starting key is valid.
            IsCaskVerifySuccess(destination.ToString());

            destination = destination[caskSignatureCharOffset..];

            // Change one byte of the CASK fixed signature.
            destination[i] = '-';

            // Ensure our invalidated key fails the IsCask check.
            string modifiedKey = modifiedKeyChars.ToString();
            bool valid = Cask.IsCask(modifiedKey);
            Assert.False(valid, $"'IsCask' unexpectedly succeeded after modifying CASK signature range: {modifiedKey}");

            IsCaskVerifyFailure(modifiedKey);
        }
    }

    [Theory, InlineData(SecretSize.Bits256), InlineData(SecretSize.Bits512)]
    public void CaskSecrets_IsCask_InvalidSecretSize(SecretSize secretSize)
    {
        string key = Cask.GenerateKey("TEST",
                                      providerKeyKind: 'S',
                                      providerData: "-00-",
                                      secretSize);

        bool valid = Cask.IsCask(key);
        Assert.True(valid, $"'IsCask' unexpectedly failed with key: {key}");

        foreach (SecretSize invalidSecretSize in new[] { SecretSize.Bits256 - 1, SecretSize.Bits512 + 1 })
        {
            // The secret size immediately follows the Cask signature.
            int secretSizeCharOffset = ComputeSecretSizeCharOffset(secretSize);

            var encodedSecretSize = (SecretSize)(key[secretSizeCharOffset] - 'A');
            Assert.Equal(secretSize, encodedSecretSize);

            Span<char> destination = key.ToCharArray().AsSpan();
            destination[secretSizeCharOffset] = (char)(invalidSecretSize + 'A');

            string modifiedKey = destination.ToString();
            valid = Cask.IsCask(modifiedKey);
            Assert.False(valid, $"'IsCask' unexpectedly succeeded after modifying CASK signature range: {modifiedKey}");

            IsCaskVerifyFailure(modifiedKey);
        }
    }

    [Theory, InlineData(SecretSize.Bits256), InlineData(SecretSize.Bits512)]
    public void CaskSecrets_IsCask_InvalidProviderDataSize(SecretSize secretSize)
    {
        string providerData = new('O', 12);
        string key = Cask.GenerateKey("TEST",
                                      providerKeyKind: 'P',
                                      providerData,
                                      secretSize);

        bool valid = Cask.IsCask(key);
        Assert.True(valid, $"'IsCask' unexpectedly failed with key: {key}");

        for (int i = 5; i <= 64; i++)
        {
            int optionalDataSizeCharOffset = ComputeOptionalDataSizeCharOffset(secretSize);

            int encodedProviderDataSizeInBytes = (key[optionalDataSizeCharOffset] - 'A') * 3;
            int encodedProviderDataSizeInChars = encodedProviderDataSizeInBytes / 3 * 4;
            Assert.Equal(providerData.Length, encodedProviderDataSizeInChars);

            Span<char> destination = key.ToCharArray().AsSpan();
            destination[optionalDataSizeCharOffset] = (char)(i + 'A');

            string modifiedKey = destination.ToString();
            valid = Cask.IsCask(modifiedKey);
            Assert.False(valid, $"'IsCask' unexpectedly succeeded after modifying CASK signature range: {modifiedKey}");

            IsCaskVerifyFailure(modifiedKey);
        }
    }

    [Theory, InlineData(SecretSize.Bits256), InlineData(SecretSize.Bits512)]
    public void CaskSecrets_IsCask_MismatchedProviderDataSize(SecretSize secretSize)
    {
        int maxProviderDataThreeByteChunks = 4;

        for (int optionalDataSize = 0; optionalDataSize < maxProviderDataThreeByteChunks; optionalDataSize++)
        {
            string providerData = new('O', optionalDataSize * 4);
            string key = Cask.GenerateKey("TEST",
                                          providerKeyKind: 'P',
                                          providerData,
                                          secretSize);

            bool valid = Cask.IsCask(key);
            Assert.True(valid, $"'IsCask' unexpectedly failed with key: {key}");

            for (int modifiedOptionalDataSize = 0; modifiedOptionalDataSize < 4; modifiedOptionalDataSize++)
            {
                if (modifiedOptionalDataSize == optionalDataSize)
                {
                    // We only test scenarios where we are replacing the encoded
                    // value with a different value.
                    continue;
                }

                int optionalDataSizeCharOffset = ComputeOptionalDataSizeCharOffset(secretSize);

                int encodedProviderDataSizeInBytes = (key[optionalDataSizeCharOffset] - 'A') * 3;
                int encodedProviderDataSizeInChars = encodedProviderDataSizeInBytes / 3 * 4;
                Assert.Equal(providerData.Length, encodedProviderDataSizeInChars);

                Span<char> destination = key.ToCharArray().AsSpan();
                destination[optionalDataSizeCharOffset] = (char)(modifiedOptionalDataSize + 'A');

                string modifiedKey = destination.ToString();
                valid = Cask.IsCask(modifiedKey);
                Assert.False(valid, $"'IsCask' unexpectedly succeeded after modifying CASK signature range: {modifiedKey}");

                // This subtle test is a case where the regex will not catch the
                // fact that the key is invalid. Doing so would require building
                // regexes that are tuned for specific encoded optional data
                // sizes. This approach, in concert with the range of sensitive
                // component sizes, would result in many discrete patterns.
                IsCaskVerifyFailure(modifiedKey);
            }
        }
    }

    [Theory, InlineData(SecretSize.Bits256), InlineData(SecretSize.Bits512)]
    public void CaskSecrets_IsCask_AllYears(SecretSize secretSize)
    {
        string providerData = string.Empty;
        string key = Cask.GenerateKey("TEST",
                                      providerKeyKind: 'Y',
                                      providerData,
                                      secretSize);

        bool valid = Cask.IsCask(key);
        Assert.True(valid, $"'IsCask' unexpectedly failed with key: {key}");

        int yearCharOffset = ComputeYearCharOffset(secretSize, providerData.Length);

        for (int base64Index = 0; base64Index < Base64UrlChars.Length; base64Index++)
        {
            Span<char> destination = key.ToCharArray().AsSpan();
            char encodedYear = Base64UrlChars[base64Index];
            destination[yearCharOffset] = encodedYear;

            string modifiedKey = destination.ToString();
            valid = Cask.IsCask(modifiedKey);

            // All encoded year values are legal.
            Assert.True(valid, $"'IsCask' unexpectedly failed after modifying Cask timestamp with valid year '{encodedYear}': {modifiedKey}");
            IsCaskVerifySuccess(modifiedKey);
            continue;
        }
    }

    [Theory, InlineData(SecretSize.Bits256), InlineData(SecretSize.Bits512)]
    public void CaskSecrets_IsCask_AllMonths(SecretSize secretSize)
    {
        string providerData = "MNTH";
        string key = Cask.GenerateKey("TEST",
                                      providerKeyKind: 'M',
                                      providerData,
                                      secretSize);

        bool valid = Cask.IsCask(key);
        Assert.True(valid, $"'IsCask' unexpectedly failed with key: {key}");

        int monthCharOffset = ComputeMonthCharOffset(secretSize, providerData.Length);

        for (int base64Index = 0; base64Index < Base64UrlChars.Length; base64Index++)
        {
            bool expectedValid = base64Index < 12;

            Span<char> destination = key.ToCharArray().AsSpan();
            char encodedMonth = Base64UrlChars[base64Index];
            destination[monthCharOffset] = encodedMonth;

            string modifiedKey = destination.ToString();
            valid = Cask.IsCask(modifiedKey);

            if (expectedValid)
            {
                Assert.True(valid, $"'IsCask' unexpectedly failed after modifying Cask timestamp with valid month '{encodedMonth}': {modifiedKey}");
                IsCaskVerifySuccess(modifiedKey);
                continue;
            }

            Assert.False(valid, $"'IsCask' unexpectedly succeeded after modifying Cask timestamp with invalid month '{encodedMonth}': {modifiedKey}");
            IsCaskVerifyFailure(modifiedKey);
        }
    }

    [Theory, InlineData(SecretSize.Bits256), InlineData(SecretSize.Bits512)]
    public void CaskSecrets_IsCask_AllDays(SecretSize secretSize)
    {
        string providerData = "DAY_DAY_";
        string key = Cask.GenerateKey("TEST",
                                      providerKeyKind: 'D',
                                      providerData,
                                      secretSize);

        bool valid = Cask.IsCask(key);
        Assert.True(valid, $"'IsCask' unexpectedly failed with key: {key}");

        int dayCharOffset = ComputeDayCharOffset(secretSize, providerData.Length);

        for (int base64Index = 0; base64Index < Base64UrlChars.Length; base64Index++)
        {
            bool expectedValid = base64Index < 31;

            Span<char> destination = key.ToCharArray().AsSpan();
            char encodedDay = Base64UrlChars[base64Index];
            destination[dayCharOffset] = encodedDay;

            string modifiedKey = destination.ToString();
            valid = Cask.IsCask(modifiedKey);

            if (expectedValid)
            {
                Assert.True(valid, $"'IsCask' unexpectedly failed after modifying Cask timestamp with valid day '{encodedDay}': {modifiedKey}");
                IsCaskVerifySuccess(modifiedKey);
                continue;
            }

            Assert.False(valid, $"'IsCask' unexpectedly succeeded after modifying Cask timestamp with invalid day '{encodedDay}': {modifiedKey}");
            IsCaskVerifyFailure(modifiedKey);
        }
    }

    [Theory, InlineData(SecretSize.Bits256), InlineData(SecretSize.Bits512)]
    public void CaskSecrets_IsCask_AllHours(SecretSize secretSize)
    {
        string providerData = "_HOUR--HOUR_";
        string key = Cask.GenerateKey("TEST",
                                      providerKeyKind: 'H',
                                      providerData,
                                      secretSize);

        bool valid = Cask.IsCask(key);
        Assert.True(valid, $"'IsCask' unexpectedly failed with key: {key}");

        int hourCharOffset = ComputeHourCharOffset(secretSize, providerData.Length);

        for (int base64Index = 0; base64Index < Base64UrlChars.Length; base64Index++)
        {
            bool expectedValid = base64Index < 24;

            Span<char> destination = key.ToCharArray().AsSpan();
            char encodedHour = Base64UrlChars[base64Index];
            destination[hourCharOffset] = encodedHour;

            string modifiedKey = destination.ToString();
            valid = Cask.IsCask(modifiedKey);

            if (expectedValid)
            {
                Assert.True(valid, $"'IsCask' unexpectedly failed after modifying Cask timestamp with valid hour '{encodedHour}': {modifiedKey}");
                IsCaskVerifySuccess(modifiedKey);
                continue;
            }

            Assert.False(valid, $"'IsCask' unexpectedly succeeded after modifying Cask timestamp with invalid hour '{encodedHour}': {modifiedKey}");
            IsCaskVerifyFailure(modifiedKey);
        }
    }

    [Theory, InlineData(SecretSize.Bits256), InlineData(SecretSize.Bits512)]
    public void CaskSecrets_IsCask_AllMinutes(SecretSize secretSize)
    {
        string providerData = "MINUTEMINUTE";
        string key = Cask.GenerateKey("TEST",
                                      providerKeyKind: 'm',
                                      providerData,
                                      secretSize);

        bool valid = Cask.IsCask(key);
        Assert.True(valid, $"'IsCask' unexpectedly failed with key: {key}");

        int minuteCharOffset = ComputeMinuteCharOffset(secretSize, providerData.Length);

        for (int base64Index = 0; base64Index < Base64UrlChars.Length; base64Index++)
        {
            bool expectedValid = base64Index < 60;

            Span<char> destination = key.ToCharArray().AsSpan();
            char encodedMinute = Base64UrlChars[base64Index];
            destination[minuteCharOffset] = encodedMinute;

            string modifiedKey = destination.ToString();
            valid = Cask.IsCask(modifiedKey);

            if (expectedValid)
            {
                Assert.True(valid, $"'IsCask' unexpectedly failed after modifying Cask timestamp with valid minute '{encodedMinute}': {modifiedKey}");
                IsCaskVerifySuccess(modifiedKey);
                continue;
            }

            Assert.False(valid, $"'IsCask' unexpectedly succeeded after modifying Cask timestamp with invalid minute '{encodedMinute}': {modifiedKey}");
            IsCaskVerifyFailure(modifiedKey);
        }
    }

    [Theory, InlineData(SecretSize.Bits256), InlineData(SecretSize.Bits512)]
    public void CaskSecrets_IsCask_AllSeconds(SecretSize secretSize)
    {
        string? providerData = null;
        string key = Cask.GenerateKey("TEST",
                                      providerKeyKind: 's',
                                      providerData,
                                      secretSize);

        bool valid = Cask.IsCask(key);
        Assert.True(valid, $"'IsCask' unexpectedly failed with key: {key}");

        int minuteCharOffset = ComputeSecondCharOffset(secretSize, 0);

        for (int base64Index = 0; base64Index < Base64UrlChars.Length; base64Index++)
        {
            bool expectedValid = base64Index < 60;

            Span<char> destination = key.ToCharArray().AsSpan();
            char encodedSecond = Base64UrlChars[base64Index];
            destination[minuteCharOffset] = encodedSecond;

            string modifiedKey = destination.ToString();
            valid = Cask.IsCask(modifiedKey);

            if (expectedValid)
            {
                Assert.True(valid, $"'IsCask' unexpectedly failed after modifying Cask timestamp with valid minute '{encodedSecond}': {modifiedKey}");
                IsCaskVerifySuccess(modifiedKey);
                continue;
            }

            Assert.False(valid, $"'IsCask' unexpectedly succeeded after modifying Cask timestamp with invalid second '{encodedSecond}': {modifiedKey}");
            IsCaskVerifyFailure(modifiedKey);
        }
    }

    [Theory, InlineData(SecretSize.Bits256), InlineData(SecretSize.Bits512)]
    public void CaskSecrets_IsCask_AllProviderKeyKinds(SecretSize secretSize)
    {
        string key = Cask.GenerateKey("TEST",
                                      providerKeyKind: 'K',
                                      providerData: "PROVIDER-KEYKIND",
                                      secretSize);

        bool valid = Cask.IsCask(key);
        Assert.True(valid, $"'IsCask' unexpectedly failed with key: {key}");

        int yearCharOffset = ComputeProviderKeyKindCharOffset(secretSize);

        for (int base64Index = 0; base64Index < Base64UrlChars.Length; base64Index++)
        {
            Span<char> destination = key.ToCharArray().AsSpan();
            char encodedKind = Base64UrlChars[base64Index];
            destination[yearCharOffset] = encodedKind;

            string modifiedKey = destination.ToString();
            valid = Cask.IsCask(modifiedKey);

            // All encoded key kind values are legal.
            Assert.True(valid, $"'IsCask' unexpectedly failed after modifying Cask timestamp with valid provider key kind '{encodedKind}': {modifiedKey}");
            IsCaskVerifySuccess(modifiedKey);
            continue;
        }
    }

    [Fact]
    public void CaskSecrets_IsCask_InvalidKey_Unaligned()
    {
        string key = Cask.GenerateKey("TEST",
                                      providerKeyKind: 'X',
                                      providerData: "UNALIGN_") + "-";

        bool valid = Cask.IsCask(key);
        Assert.False(valid, $"'IsCask' unexpectedly succeeded with key that was not aligned to 4 chars: {key}");
    }

    [Theory, InlineData(SecretSize.Bits256), InlineData(SecretSize.Bits512)]
    public void CaskSecrets_IsCask_InvalidKey_Whitespace(SecretSize secretSize)
    {
        // Replace first 4 characters of secret with whitespace. Whitespace is
        // allowed by `Base64Url` API but is invalid in a Cask key.
        string key = $"    {Cask.GenerateKey("TEST",
                            'X',
                            providerData: null,
                            secretSize)[4..]}";
        bool valid = Cask.IsCask(key);
        Assert.False(valid, $"'IsCask' unexpectedly succeeded with key that had whitespace: {key}");
    }

    [Fact]
    public void CaskSecrets_IsCask_InvalidSensitiveDataBits512Padding()
    {
        string providerData = "FIVEHUNDREDTWELV";
        SecretSize secretSize = SecretSize.Bits512;

        string key = Cask.GenerateKey("TEST",
                                      providerKeyKind: 'X',
                                      providerData,
                                      secretSize);

        bool valid = Cask.IsCask(key);
        Assert.True(valid, $"'IsCask' unexpectedly failed with key: {key}");

        // The character (6-bits) immediately preceding the CASK signature
        // should be zeroed out.         
        int paddingIndex = ComputeCaskSignatureCharOffset(secretSize) - 1;
        Assert.Equal('A', key[paddingIndex]);

        for (int base64Index = 1; base64Index < 64; base64Index++)
        {
            Span<char> destination = key.ToCharArray().AsSpan();
            destination[paddingIndex] = Base64UrlChars[base64Index];
            valid = Cask.IsCask(destination.ToString());
            Assert.False(valid, $"'IsCask' unexpectedly succeeded with non-zero padding preceding CASK signature: {destination.ToString()}");
        }

        // The character to the left of the character preceding the CASK
        // signature should be zeroed out (as there are two full bytes of
        // padding).
        paddingIndex--;
        Assert.Equal('A', key[paddingIndex]);

        for (int base64Index = 1; base64Index < 64; base64Index++)
        {
            Span<char> destination = key.ToCharArray().AsSpan();
            destination[paddingIndex] = Base64UrlChars[base64Index];
            valid = Cask.IsCask(destination.ToString());
            Assert.False(valid, $"'IsCask' unexpectedly succeeded with non-zero padding preceding CASK signature: {destination.ToString()}");
        }

        // We have now validated 12 bits of zero padding. That means that the
        // last remaining encoded character to validate should always have four
        // bits of trailing zeros. There are four base64 characters that meet
        // this condition.
        paddingIndex--;

        var permissibleCharacters = new HashSet<char>(['A', 'Q', 'g', 'w']);

        for (int base64Index = 1; base64Index < 64; base64Index++)
        {
            char base64Char = Base64UrlChars[base64Index];
            bool expectedValid = permissibleCharacters.Contains(base64Char);
            Span<char> destination = key.ToCharArray().AsSpan();
            destination[paddingIndex] = base64Char;
            valid = Cask.IsCask(destination.ToString());

            if (expectedValid)
            {
                Assert.True(valid, $"'IsCask' unexpectedly failed with permissible value in final encoded character of sensitive data: {destination.ToString()}");
            }
            else
            {
                Assert.False(valid, $"'IsCask' unexpectedly succeeded with illegal value in final encoded character of sensitive data: {destination.ToString()}");
            }
        }
    }

    [Fact]
    public void CaskSecrets_IsCask_InvalidBits256SensitiveDataPadding()
    {
        string providerData = "256b";
        SecretSize secretSize = SecretSize.Bits256;

        string key = Cask.GenerateKey("TEST",
                                      providerKeyKind: 'X',
                                      providerData,
                                      secretSize);

        bool valid = Cask.IsCask(key);
        Assert.True(valid, $"'IsCask' unexpectedly failed with key: {key}");

        // The character (6-bits) immediately preceding the CASK signature
        // should be zeroed out.         
        int paddingIndex = ComputeCaskSignatureCharOffset(secretSize) - 1;
        Assert.Equal('A', key[paddingIndex]);

        for (int base64Index = 1; base64Index < 64; base64Index++)
        {
            Span<char> destination = key.ToCharArray().AsSpan();
            destination[paddingIndex] = Base64UrlChars[base64Index];
            valid = Cask.IsCask(destination.ToString());
            Assert.False(valid, $"'IsCask' unexpectedly succeeded with non-zero padding preceding CASK signature: {destination.ToString()}");
        }

        // We have now validated 6 bits of zero padding. That means that the
        // last remaining encoded character to validate should always have two
        // bits of trailing zeros. There are sixteen base64 characters that meet
        // this condition.
        paddingIndex--;

        var permissibleCharacters =
            new HashSet<char>(['A', 'E', 'I', 'M', 'Q', 'U', 'Y', 'c', 'g', 'k', 'o', 's', 'w', '0', '4', '8']);

        for (int base64Index = 1; base64Index < 64; base64Index++)
        {
            char base64Char = Base64UrlChars[base64Index];
            bool expectedValid = permissibleCharacters.Contains(base64Char);
            Span<char> destination = key.ToCharArray().AsSpan();
            destination[paddingIndex] = base64Char;
            valid = Cask.IsCask(destination.ToString());

            if (expectedValid)
            {
                Assert.True(valid, $"'IsCask' unexpectedly failed with permissible value in final encoded character of sensitive data: {destination.ToString()}");
            }
            else
            {
                Assert.False(valid, $"'IsCask' unexpectedly succeeded with illegal value in final encoded character of sensitive data: {destination.ToString()}");
            }
        }
    }

    [Theory, InlineData(SecretSize.Bits256), InlineData(SecretSize.Bits512)]
    public void CaskSecrets_IsCask_InvalidPadding(SecretSize secretSize)
    {
        string providerData = new('p', (int)secretSize * 4);

        string key = Cask.GenerateKey("TEST",
                                      providerKeyKind: 'X',
                                      providerData,
                                      secretSize);

        bool valid = Cask.IsCask(key);
        Assert.True(valid, $"'IsCask' unexpectedly failed with key: {key}");

        Span<char> destination = key.ToCharArray().AsSpan();

        // The first reserved character immediately follows the CASK signature.
        int reserved = ComputeCaskSignatureCharOffset(secretSize) + 4;
        Assert.Equal('A', destination[reserved]);

        for (int base64Index = 1; base64Index < 64; base64Index++)
        {
            destination = key.ToCharArray().AsSpan();
            destination[reserved] = Base64UrlChars[base64Index];
            valid = Cask.IsCask(destination.ToString());
            Assert.False(valid, $"'IsCask' unexpectedly succeeded with non-zero padding after CASK signature: {key}");
        }

        // There are two reserved signatures that immediately precede the timestamp.
        reserved = ComputeYearCharOffset(secretSize, providerData.Length) - 2;

        for (int rIndex = reserved; rIndex <= reserved + 1; rIndex++)
        {
            Assert.Equal('A', destination[rIndex]);

            for (int base64Index = 1; base64Index < 64; base64Index++)
            {
                destination = key.ToCharArray().AsSpan();
                destination[rIndex] = (char)base64Index;
                valid = Cask.IsCask(destination.ToString());
                Assert.False(valid, $"'IsCask' unexpectedly succeeded with non-zero padding preceding timestamp: {key}");
            }
        }
    }

    [Fact]
    public void CaskSecrets_IsCask_InvalidKey_InvalidBase64Url()
    {
        string key = Cask.GenerateKey(providerSignature: "TEST",
                                      providerKeyKind: '-',
                                      providerData: null);
        key = '?' + key[1..];
        bool valid = Cask.IsCask(key);
        Assert.False(valid, $"IsCask' unexpectedly succeeded with key that was not valid URL-Safe Base64: {key}");
    }

    [Theory, InlineData(SecretSize.Bits256), InlineData(SecretSize.Bits512)]
    public void CaskSecrets_GenerateKey_Basic(SecretSize secretSize)
    {
        for (int optionalDataChunks = 0; optionalDataChunks <= 4; optionalDataChunks++)
        {
            string key = Cask.GenerateKey(providerSignature: "TEST",
                                          providerKeyKind: 'Q',
                                          providerData: new string('x', optionalDataChunks * 4),
                                          secretSize);

            byte[] keyBytes = Base64Url.DecodeFromChars(key.AsSpan());
            Assert.True(keyBytes.Length % 3 == 0, "'GenerateKey' output wasn't aligned on a 3-byte boundary.");

            IsCaskVerifySuccess(key);
        }
    }

    [Theory]
    [InlineData(SecretSize.Bits256 - 1)]
    [InlineData(SecretSize.Bits512 + 1)]
    public void CaskSecrets_GenerateKey_InvalidKey_InvalidSecretSize(SecretSize secretSize)
    {
        Assert.Throws<ArgumentException>(
            () => Cask.GenerateKey("TEST",
                                   providerKeyKind: '_',
                                   providerData: "oOOo",
                                   secretSize));
    }

    [Theory]
    [InlineData(0, SecretSize.Bits256), InlineData(0, SecretSize.Bits512)]
    [InlineData('?', SecretSize.Bits256), InlineData('?', SecretSize.Bits512)]
    public void CaskSecrets_GenerateKey_InvalidKey_InvalidProviderKind(char providerKeyKind, SecretSize secretSize)
    {
        Assert.Throws<ArgumentException>(
            () => Cask.GenerateKey("TEST",
                                   providerKeyKind,
                                   providerData: "OooOOooOOooO",
                                   secretSize));
    }

    [Fact]
    public void CaskSecrets_GenerateKey_InvalidKey_InvalidForBase64ProviderKind()
    {
        for (char ch = (char)0; ch < char.MaxValue; ch++)
        {
            if (s_printableBase64UrlCharacters.Contains(ch))
            {
                continue;
            }

            Assert.Throws<ArgumentException>(
                () => Cask.GenerateKey("TEST",
                                       providerKeyKind: ch,
                                       providerData: "OooOOooOOooO"));
        }
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
        ArgumentException ex = Assert.ThrowsAny<ArgumentException>(() => Cask.GenerateKey(providerSignature!, 'A', providerData: null));
        Assert.IsType(providerSignature == null ? typeof(ArgumentNullException) : typeof(ArgumentException), ex);
        Assert.Equal(nameof(providerSignature), ex.ParamName);
    }

    [Theory]
    [InlineData("ABC")]   // Too short.
    [InlineData("ABCDE")] // Unaligned.
    [InlineData("éééé")]  // Invalid base64.
    [InlineData("111_222_333_444_555_666-777_888_999_000_X")] // Exceeds max by one.
    [InlineData("111_222_333_444_555_666-777_888_999_000_XXXX")] // Exceeds max by 4-character aligned value.
    [InlineData("THIS_IS_TOO_MUCH_PROVIDER_DATA_SERIOUSLY_IT_IS_VERY_VERY_LONG_AND_THAT_IS_NOT_OKAY")]
    public void CaskSecrets_GenerateKey_InvalidProviderData(string providerData)
    {
        ArgumentException ex = Assert.ThrowsAny<ArgumentException>(() => Cask.GenerateKey("TEST", 'X', providerData));
        Assert.IsType(providerData == null ? typeof(ArgumentNullException) : typeof(ArgumentException), ex);
        Assert.Equal(nameof(providerData), ex.ParamName);
    }

    [Theory, InlineData(SecretSize.Bits256), InlineData(SecretSize.Bits512)]
    public void CaskSecrets_GenerateKey_NotDeterministic(SecretSize secretSize)
    {
        // We should add more sophistication to checking randomness, but during
        // development, there was once had a bug on .NET Framework polyfill of
        // RNG that left all the entropy bytes zeroed out, so at least cover that
        // in the meantime. :)

        string key = Cask.GenerateKey("TEST", 'M', "ABCD", secretSize);
        string key2 = Cask.GenerateKey("TEST", 'M', "ABCD", secretSize);

        Assert.True(key != key2, $"'GenerateKey' produced the same key twice: {key}");
    }

    [Theory]
    [InlineData(SecretSize.Bits256, "__________________________________________8AQJJQABBMTESTABCDAAAAAAAA")]
    [InlineData(SecretSize.Bits512, "_____________________________________________________________________________________wAAQJJQACBMTESTABCDAAAAAAAA")]
    public void CaskSecrets_GenerateKey_DeterministicUsingMocks(SecretSize secretSize, string expectedKey)
    {
        using Mock mockRandom = Cask.MockFillRandom(buffer => buffer.Fill(255));
        using Mock mockTimestamp = Cask.MockUtcNow(() => new DateTimeOffset(2025, 1, 1, 0, 0, 0, TimeSpan.Zero));

        string actualKey = Cask.GenerateKey("TEST", 'M', "ABCD", secretSize);
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
                                   providerKeyKind: 'y',
                                   providerData: "ABCD"));

        Assert.Contains("2088", ex.Message, StringComparison.Ordinal);
    }

    [Theory, InlineData(SecretSize.Bits256), InlineData(SecretSize.Bits512)]
    public void CaskSecrets_GenerateKey_ValidTimestamps(SecretSize secretSize)
    {
        string providerData = "ABCD";

        // Every year from 2025 - 2088 should produce a valid key. We trust that
        // the CASK standard will be long dead by 2088 or perhaps simply all or
        // most programmers will be.
        for (int year = 0; year < 64; year++)
        {
            int month = year % 12;
            int day = year % 28;
            int hour = year % 24;
            int minute = year % 60;

            var timestamp = new DateTimeOffset(2025 + year, 1 + month, 1 + day, hour, minute, second: 0, TimeSpan.Zero);
            using Mock mock = Cask.MockUtcNow(() => timestamp);

            string key = Cask.GenerateKey(providerSignature: "TEST",
                                          providerKeyKind: 'Z',
                                          providerData,
                                          secretSize);
            IsCaskVerifySuccess(key);

            string b = Base64UrlChars;
            string expected = $"{b[year]}{b[month]}{b[day]}{b[hour]}{b[minute]}";

            int entropyInBytes = (int)secretSize * 32;
            int paddedSecretSizeInChars = RoundUpTo3ByteAlignment(entropyInBytes) / 3 * 4;

            // The timestamp follows the Cask signature, the character
            // comprising the secret size, and the character comprising the
            // optional data size.
            int timestampCharOffset = CaskTestsBase.ComputeYearCharOffset(secretSize, providerData.Length);

            Range timestampCharRange = timestampCharOffset..(timestampCharOffset + 5);

            string actual = key[timestampCharRange];
            Assert.True(expected == actual, $"Expected key '{key}' to have encoded timestamp '{expected}' representing '{timestamp}' but found '{actual}'.");
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

    internal static int ComputeCaskSignatureCharOffset(SecretSize secretSize)
    {
        int secretSizeInBytes = (int)secretSize * 32;
        int paddedSecretSizeInBytes = (secretSizeInBytes + 3 - 1) / 3 * 3;
        return (paddedSecretSizeInBytes / 3) * 4;
    }

    internal static int ComputeSecretSizeCharOffset(SecretSize secretSize)
    {
        // Add 4 for signature size + 1 for padding character.
        return ComputeCaskSignatureCharOffset(secretSize) + 4 + 1;
    }

    internal static int ComputeOptionalDataSizeCharOffset(SecretSize secretSize)
    {
        return ComputeSecretSizeCharOffset(secretSize) + 1;
    }

    internal static int ComputeProviderKeyKindCharOffset(SecretSize secretSize)
    {
        return ComputeOptionalDataSizeCharOffset(secretSize) + 1;
    }

    internal static int ComputeProviderSignatureCharOffset(SecretSize secretSize)
    {
        return ComputeProviderKeyKindCharOffset(secretSize) + 1;
    }

    internal static int ComputeOptionalDataOffset(SecretSize secretSize)
    {
        return ComputeProviderSignatureCharOffset(secretSize) + 4;
    }

    internal static int ComputeYearCharOffset(SecretSize secretSize, int providerDataLength)
    {
        // Add two to account for two padding characters preceding the timestamp.
        return ComputeOptionalDataOffset(secretSize) + providerDataLength + 2;
    }

    internal static int ComputeMonthCharOffset(SecretSize secretSize, int providerDataLength)
    {
        return ComputeYearCharOffset(secretSize, providerDataLength) + 1;
    }

    internal static int ComputeDayCharOffset(SecretSize secretSize, int providerDataLength)
    {
        return ComputeMonthCharOffset(secretSize, providerDataLength) + 1;
    }

    internal static int ComputeHourCharOffset(SecretSize secretSize, int providerDataLength)
    {
        return ComputeDayCharOffset(secretSize, providerDataLength) + 1;
    }

    internal static int ComputeMinuteCharOffset(SecretSize secretSize, int providerDataLength)
    {
        return ComputeHourCharOffset(secretSize, providerDataLength) + 1;
    }

    internal static int ComputeSecondCharOffset(SecretSize secretSize, int providerDataLength)
    {
        return ComputeMinuteCharOffset(secretSize, providerDataLength) + 1;
    }
}
