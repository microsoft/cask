// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Buffers.Text;
using System.Diagnostics.CodeAnalysis;
using System.Text;

using static CommonAnnotatedSecurityKeys.Helpers;
using static CommonAnnotatedSecurityKeys.InternalConstants;

using Xunit;

namespace CommonAnnotatedSecurityKeys.Tests;

[ExcludeFromCodeCoverage]
public class CaskKeyTests
{
    internal static SensitiveDataSize[] AllSensitiveDataSizes =>[
        SensitiveDataSize.Bits128, SensitiveDataSize.Bits256,
        SensitiveDataSize.Bits384, SensitiveDataSize.Bits512];

    [Theory]
    [InlineData(SensitiveDataSize.Bits128)]
    [InlineData(SensitiveDataSize.Bits256)]
    [InlineData(SensitiveDataSize.Bits384)]
    [InlineData(SensitiveDataSize.Bits512)]
    public void CaskKey_Basic(SensitiveDataSize sensitiveDataSize)
    {
        CaskKey key = Cask.GenerateKey("TEST",
                                       providerKeyKind: 'O',
                                       providerData: "XXXX",
                                       sensitiveDataSize);

        Assert.Equal(sensitiveDataSize, key.SensitiveDataSize);
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

        foreach (SensitiveDataSize sensitiveDataSize in AllSensitiveDataSizes)
        {
            int entropyInBytes = (int)sensitiveDataSize * 16;
            int sensitiveDataSizeInBytes = RoundUpTo3ByteAlignment(entropyInBytes);

            CaskKey key = Cask.GenerateKey("TEST",
                                           providerKeyKind: 'O',
                                           providerData,
                                           sensitiveDataSize);

            int minimumSizeInBytes = sensitiveDataSizeInBytes + FixedKeyComponentSizeInBytes;

            int providerDataSizeInBytes = Base64Url.DecodeFromChars(providerData.ToCharArray()).Length;
            Assert.Equal(minimumSizeInBytes + providerDataSizeInBytes, key.SizeInBytes);
        }
    }

    [Theory]
    [InlineData(SensitiveDataSize.Bits128)]
    [InlineData(SensitiveDataSize.Bits256)]
    [InlineData(SensitiveDataSize.Bits384)]
    [InlineData(SensitiveDataSize.Bits512)]
    public void CaskKey_SensitiveDataSize(SensitiveDataSize sensitiveDataSize)
    {
        CaskKey key = Cask.GenerateKey("TEST",
                                       providerKeyKind: '_',
                                       providerData: "aBBa",
                                       sensitiveDataSize);

        key = CaskKey.Create(key.ToString());
        Assert.Equal(sensitiveDataSize, key.SensitiveDataSize);
    }

    [Fact]
    public void CaskKey_UninitializedSensitiveDateSizeAccessThrows()
    {
        CaskKey key = default;
        Assert.Throws<InvalidOperationException>(() => key.SensitiveDataSize);
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

        int sensitiveDataSizeCharOffset = 53;
        var sensitiveDataSize = (SensitiveDataSize)(keyChars[sensitiveDataSizeCharOffset] - 'A');

        Assert.Equal(SensitiveDataSize.Bits256, sensitiveDataSize);
        
        keyChars[sensitiveDataSizeCharOffset] = (char)('A' + ((int)SensitiveDataSize.Bits512 + 1));
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
