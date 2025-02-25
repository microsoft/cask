// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Buffers.Text;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography.X509Certificates;
using System.Text;

using Xunit;

namespace CommonAnnotatedSecurityKeys.Tests;

[ExcludeFromCodeCoverage]
public class CaskKeyTests
{
    [Fact]
    public void CaskKey_UninitializedKindAccessThrows()
    {
        CaskKey key = default;
        Assert.Throws<InvalidOperationException>(() => key.Kind);
    }

    [Fact]
    public void CaskKey_KindIsPrimaryKey()
    {
        CaskKey key = Cask.GenerateKey("TEST",
                                       providerKeyKind: "_",
                                       expiryInFiveMinuteIncrements: 12 * 2, // 2 hours.
                                       providerData: "AaaA");

        Assert.Equal(CaskKeyKind.PrimaryKey, key.Kind);
    }

    [Fact]
    public void CaskKey_UninitializedSizeInBytesAccessThrows()
    {
        CaskKey key = default;
        Assert.Throws<InvalidOperationException>(() => key.SizeInBytes);
    }

    [Theory]
    [InlineData("")]
    [InlineData(null)]
    [InlineData("1234")]
    [InlineData("12345678")]
    [InlineData("123456789012")]
    public void CaskKey_SizeInBytes(string? providerData)
    {
        providerData ??= string.Empty;

        CaskKey key = Cask.GenerateKey("TEST",
                                       providerKeyKind: "O",
                                       expiryInFiveMinuteIncrements: 0, // No expiry.
                                       providerData);

        const int minimumSizeInBytes = 63;

        int providerDataSizeInBytes = Base64Url.DecodeFromChars(providerData.ToCharArray()).Length;
        Assert.Equal(minimumSizeInBytes + providerDataSizeInBytes, key.SizeInBytes);
    }

    [Fact]
    public void CaskKey_UninitializedSensitiveDateSizeInBytesAccessThrows()
    {
        CaskKey key = default;
        Assert.Throws<InvalidOperationException>(() => key.SensitiveDateSizeInBytes);
    }

    [Fact]
    public void CaskKey_SensitiveDataSizeInBytes()
    {
        CaskKey key = Cask.GenerateKey("TEST",
                                       providerKeyKind: "_",
                                       expiryInFiveMinuteIncrements: (1 << 18) - 1, // 18-bit max value.
                                       providerData: "aBBa");

        Span<char> keyChars = key.ToString().ToCharArray();

        const int sensitiveDataSizeCharIndex = 43;

        Span<byte> sizeBytes = stackalloc byte[3];
        Span<char> sizeChars = stackalloc char[4];

        // We do not validate any keys of size other than 'Bits256', so limiting testing for now.
        foreach (SensitiveDataSize sensitiveDataSize in new[] { SensitiveDataSize.Bits256 })
        {
            sizeBytes[2] = (byte)sensitiveDataSize;
            Base64Url.EncodeToChars(sizeBytes, sizeChars);
            keyChars[sensitiveDataSizeCharIndex] = sizeChars[3];

            int expected = sensitiveDataSize switch
            {
                SensitiveDataSize.Bits256 => 32,
                SensitiveDataSize.Bits384 => 48,
                SensitiveDataSize.Bits512 => 64,
                _ => throw new InvalidOperationException($"Unexpected sensitive data size: {sensitiveDataSize}."),
            };

            key = CaskKey.Create(keyChars.ToString());
            Assert.Equal(expected, key.SensitiveDateSizeInBytes);
        }
    }
    [Fact]
    public void CaskKey_CreateOverloadsAreEquivalent()
    {
        CaskKey key = Cask.GenerateKey("TEST",
                                       providerKeyKind: "J",
                                       expiryInFiveMinuteIncrements: 12 * 72, // 3 days.
                                       providerData: "MSFT");

        byte[] actual = new byte[Limits.MaxKeyLengthInBytes];
        byte[] expected = new byte[Limits.MaxKeyLengthInBytes];
        key.Decode(expected);

        string keyText = key.ToString();
        CaskKey.Create(keyText).Decode(actual);
        Assert.Equal(expected, actual);

        CaskKey.Create(keyText.AsSpan()).Decode(actual);
        Assert.Equal(expected, actual);

        CaskKey.CreateUtf8(Encoding.UTF8.GetBytes(keyText)).Decode(actual);
        Assert.Equal(expected, actual);
    }

    [Fact]
    public void CaskKey_DecodeBasic()
    {
        CaskKey key = Cask.GenerateKey("TEST",
                                       providerKeyKind: "9",
                                       expiryInFiveMinuteIncrements: 5, // 25 minutes.
                                       providerData: "010101010101");

        byte[] decoded = new byte[key.SizeInBytes];
        key.Decode(decoded);

        string expected = key.ToString();
        string actual = Base64Url.EncodeToString(decoded);

        Assert.Equal(expected, actual);
    }

    [Fact]
    public void CaskKey_TryEncodeInvalidKey()
    {
        CaskKey key = Cask.GenerateKey("TEST",
                                       providerKeyKind: "l",
                                       expiryInFiveMinuteIncrements: 5, // 25 minutes.
                                       providerData: "010101010101");

        Span<byte> decoded = stackalloc byte[key.SizeInBytes];
        Base64Url.DecodeFromChars(key.ToString().AsSpan(), decoded);

        const int caskSignatureByteIndex = 33;
        Assert.Equal(0x40, decoded[caskSignatureByteIndex]);

        // Break the key by invaliding the CASK signature.
        decoded[caskSignatureByteIndex] = (byte)'X';

        bool succeeded = CaskKey.TryEncode(decoded, out CaskKey newCaskKey);
        Assert.False(succeeded);
    }

    [Fact]
    public void CaskKey_TryEncodeBasic()
    {
        CaskKey key = Cask.GenerateKey("TEST",
                                       providerKeyKind: "J",
                                       expiryInFiveMinuteIncrements: 0, // 3 days.
                                       providerData: null);

        Span<byte> decoded = stackalloc byte[key.SizeInBytes];
        Base64Url.TryDecodeFromChars(key.ToString().AsSpan(), decoded, out int bytesWritten);

        var newKey = CaskKey.Encode(decoded);

        Assert.Equal(key, newKey);
    }

    [Fact]
    public void CaskKey_CreateOverloadsThrowOnInvalidKey()
    {
        CaskKey key = Cask.GenerateKey("TEST",
                                       providerKeyKind: "R",
                                       expiryInFiveMinuteIncrements: 12 * 24 * 365, // 1 year.
                                       providerData: "ROSS");

        Span<char> keyChars = key.ToString().ToCharArray();

        const int sensitiveDateCharIndex = 43;
        keyChars[sensitiveDateCharIndex] = '_';

        string invalidKeyText = keyChars.ToString();
        byte[] invalidKeyUtf8Bytes = Encoding.UTF8.GetBytes(invalidKeyText);

        Assert.Throws<FormatException>(() => CaskKey.Create(invalidKeyText));
        Assert.Throws<FormatException>(() => CaskKey.Create(invalidKeyText.AsSpan()));
        Assert.Throws<FormatException>(() => CaskKey.CreateUtf8(invalidKeyUtf8Bytes));
    }
}
