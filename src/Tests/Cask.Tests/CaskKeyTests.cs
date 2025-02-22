// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Buffers.Text;
using System.Diagnostics.CodeAnalysis;

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
}

