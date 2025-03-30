// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Buffers.Text;
using System.Text;

using Xunit;

using static CommonAnnotatedSecurityKeys.Helpers;
using static CommonAnnotatedSecurityKeys.InternalConstants;

namespace CommonAnnotatedSecurityKeys.Tests;

public class CaskKeyTests
{
    [Theory]
    [InlineData(SecretSize.Bits128)]
    [InlineData(SecretSize.Bits256)]
    [InlineData(SecretSize.Bits384)]
    [InlineData(SecretSize.Bits512)]
    public void CaskKey_Basic(SecretSize secretSize)
    {
        CaskKey key = Cask.GenerateKey("TEST",
                                       providerKeyKind: 'O',
                                       providerData: "XXXX",
                                       secretSize);

        Assert.Equal(secretSize, key.SecretSize);
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

        foreach (SecretSize secretSize in CaskTestsBase.AllSecretSizes)
        {
            int secretSizeInBytes = (int)secretSize * 16;
            int paddedSecretSizeInBytes = RoundUpTo3ByteAlignment(secretSizeInBytes);

            CaskKey key = Cask.GenerateKey("TEST",
                                           providerKeyKind: 'O',
                                           providerData,
                                           secretSize);

            int minimumSizeInBytes = paddedSecretSizeInBytes + FixedKeyComponentSizeInBytes;

            int providerDataSizeInBytes = Base64Url.DecodeFromChars(providerData.ToCharArray()).Length;
            Assert.Equal(minimumSizeInBytes + providerDataSizeInBytes, key.SizeInBytes);
        }
    }

    [Theory]
    [InlineData(SecretSize.Bits128)]
    [InlineData(SecretSize.Bits256)]
    [InlineData(SecretSize.Bits384)]
    [InlineData(SecretSize.Bits512)]
    public void CaskKey_SecretSize(SecretSize secretSize)
    {
        CaskKey key = Cask.GenerateKey("TEST",
                                       providerKeyKind: '_',
                                       providerData: "aBBa",
                                       secretSize);

        key = CaskKey.Create(key.ToString());
        Assert.Equal(secretSize, key.SecretSize);
    }

    [Fact]
    public void CaskKey_UninitializedSensitiveDateSizeAccessThrows()
    {
        CaskKey key = default;
        Assert.Throws<InvalidOperationException>(() => key.SecretSize);
    }

    [Fact]
    public void CaskKey_CreateOverloadsAreEquivalent()
    {
        CaskKey key = Cask.GenerateKey("TEST",
                                       providerKeyKind: 'J',
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
    public void CaskKey_Decode_Basic()
    {
        CaskKey key = Cask.GenerateKey("TEST",
                                       providerKeyKind: '9',
                                       providerData: "010101010101");

        byte[] decoded = new byte[key.SizeInBytes];
        key.Decode(decoded);

        string expected = key.ToString();
        string actual = Base64Url.EncodeToString(decoded);

        Assert.Equal(expected, actual);
    }

    [Fact]
    public void CaskKey_Decode_DestinationTooSmall()
    {
        CaskKey key = Cask.GenerateKey("TEST",
                                       providerKeyKind: '9',
                                       providerData: "010101010101");

        byte[] decoded = new byte[key.SizeInBytes];
        key.Decode(decoded);

        Assert.Throws<ArgumentException>(() => key.Decode(decoded.AsSpan()[..^1]));
    }

    [Fact]
    public void CaskKey_TryEncode_InvalidKey()
    {
        CaskKey key = Cask.GenerateKey("TEST",
                                       providerKeyKind: 'l',
                                       providerData: "010101010101");

        Span<byte> decoded = stackalloc byte[key.SizeInBytes];
        Base64Url.DecodeFromChars(key.ToString().AsSpan(), decoded);

        const int caskSignatureByteIndex = 33;
        Assert.Equal(0x40, decoded[caskSignatureByteIndex]);

        // Break the key by invalidating the CASK signature.
        decoded[caskSignatureByteIndex] = (byte)'X';

        bool succeeded = CaskKey.TryEncode(decoded, out CaskKey newCaskKey);
        Assert.False(succeeded);
    }

    [Fact]
    public void CaskKey_Encode_Basic()
    {
        CaskKey key = Cask.GenerateKey("TEST",
                                       providerKeyKind: 'J',
                                       providerData: null);

        Span<byte> decoded = stackalloc byte[key.SizeInBytes];
        Base64Url.TryDecodeFromChars(key.ToString().AsSpan(), decoded, out int _);

        var newKey = CaskKey.Encode(decoded);

        Assert.Equal(key, newKey);
    }

    [Fact]
    public void CaskKey_Encode_InvalidKey()
    {
        CaskKey key = Cask.GenerateKey("TEST",
                                       providerKeyKind: 'J');

        byte[] decoded = new byte[key.SizeInBytes];
        Base64Url.TryDecodeFromChars(key.ToString().AsSpan(), decoded, out int _);

        var newKey = CaskKey.Encode(decoded);
        Assert.Equal(key, newKey);

        Span<char> keyChars = key.ToString().ToCharArray().AsSpan();

        int secretSizeCharOffset = 48;
        var secretSize = (SecretSize)(keyChars[secretSizeCharOffset] - 'A');

        Assert.Equal(SecretSize.Bits256, secretSize);

        keyChars[secretSizeCharOffset] = (char)('A' + ((int)SecretSize.Bits512 + 1));
        Base64Url.TryDecodeFromChars(keyChars, decoded, out int _);

        Assert.Throws<FormatException>(() => CaskKey.Encode(decoded));
    }

    [Fact]
    public void CaskKey_CreateOverloadsThrowOnInvalidKey()
    {
        CaskKey key = Cask.GenerateKey("TEST",
                                       providerKeyKind: 'R',
                                       providerData: "ROSS");

        Span<char> keyChars = key.ToString().ToCharArray();

        const int sensitiveDateCharIndex = 43;
        keyChars[sensitiveDateCharIndex] = '?';

        string invalidKeyText = keyChars.ToString();
        byte[] invalidKeyUtf8Bytes = Encoding.UTF8.GetBytes(invalidKeyText);

        Assert.Throws<FormatException>(() => CaskKey.Create(invalidKeyText));
        Assert.Throws<FormatException>(() => CaskKey.Create(invalidKeyText.AsSpan()));
        Assert.Throws<FormatException>(() => CaskKey.CreateUtf8(invalidKeyUtf8Bytes));
    }
}
