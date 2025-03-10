// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Buffers.Text;
using System.Diagnostics.CodeAnalysis;
using System.Text;

using Xunit;

namespace CommonAnnotatedSecurityKeys.Tests;

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
                                       providerKeyKind: '_',
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
                                       providerKeyKind: 'O',
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
                                       providerKeyKind: '_',
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
                                       providerKeyKind: 'J',
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
                                       providerKeyKind: '9',
                                       expiryInFiveMinuteIncrements: 5, // 25 minutes.
                                       providerData: "010101010101");

        byte[] decoded = new byte[key.SizeInBytes];
        key.Decode(decoded);

        string expected = key.ToString();
        string actual = Base64Url.EncodeToString(decoded);

        Assert.Equal(expected, actual);
    }

    [Fact]
    public void CaskKey_Encode_InvalidKey()
    {
        CaskKey key = Cask.GenerateKey("TEST",
                                       providerKeyKind: 'l',
                                       expiryInFiveMinuteIncrements: 5, // 25 minutes.
                                       providerData: "010101010101");

        byte[] decoded = new byte[key.SizeInBytes];
        byte[] tooSmall = new byte[key.SizeInBytes - 1];

        Base64Url.DecodeFromChars(key.ToString().AsSpan(), decoded);
        Array.Copy(decoded, tooSmall, tooSmall.Length);

        // Break the key by creating an invalid length for decoding.
        Assert.Throws<FormatException>(() => CaskKey.Encode(tooSmall));

        decoded = new byte[key.SizeInBytes];
        const int caskSignatureByteIndex = 33;
        Base64Url.DecodeFromChars(key.ToString().AsSpan(), decoded);
        Assert.Equal(0x40, decoded[caskSignatureByteIndex]);

        // Break the key by invalidating the CASK signature.
        decoded[caskSignatureByteIndex] = (byte)'X';
        Assert.Throws<FormatException>(() => CaskKey.Encode(decoded));
    }

    [Fact]
    public void CaskKey_TryEncode_InvalidKey()
    {
        CaskKey key = Cask.GenerateKey("TEST",
                                       providerKeyKind: 'l',
                                       expiryInFiveMinuteIncrements: 5, // 25 minutes.
                                       providerData: "010101010101");

        Span<byte> decoded = stackalloc byte[key.SizeInBytes];
        Base64Url.DecodeFromChars(key.ToString().AsSpan(), decoded);

        // Break the key by creating an invalid length for decoding.
        bool succeeded = CaskKey.TryEncode(decoded[1..], out CaskKey newCaskKey);
        Assert.False(succeeded);

        const int caskSignatureByteIndex = 33;
        Assert.Equal(0x40, decoded[caskSignatureByteIndex]);

        // Break the key by invalidating the CASK signature.
        decoded[caskSignatureByteIndex] = (byte)'X';

        succeeded = CaskKey.TryEncode(decoded, out newCaskKey);
        Assert.False(succeeded);
    }


    [Fact]
    public void CaskKey_TryEncode_InvalidCaskKeyKind()
    {
        CaskKey key = Cask.GenerateKey("TEST",
                                       providerKeyKind: '4',
                                       expiryInFiveMinuteIncrements: 50, // 250 minutes.
                                       providerData: "l33t");

        Span<byte> decoded = stackalloc byte[key.SizeInBytes];
        Base64Url.DecodeFromChars(key.ToString().AsSpan(), decoded);

        const int caskKindByteIndex = 40;
        const int caskKindReservedBits = 4;
        const int caskKindMask = (1 << caskKindReservedBits) - 1;

        for (byte i = byte.MinValue; i < byte.MaxValue; i++)
        {
            // This operation ensures that every possible byte
            // value is populated and tested in encoding.
            decoded[caskKindByteIndex] = i;

            // Only the most significant 4 bits are valid to store key kind.
            int iMasked = i & ~caskKindMask;

            // Right-shifting by 4 bits gives us the literal key kind enum value;
            var current = (CaskKeyKind)(iMasked >> caskKindReservedBits);

            bool succeeded = CaskKey.TryEncode(decoded, out CaskKey newCaskKey);

            // To test our API behavior, we first need to ensure that no bits
            // were masked away from the input byte. This would indicate someone
            // stepped on reserved padding, resulting in an invalid key. Next,
            // we ensure that any bits stored in the proper place but which are
            // not valid defined key kinds are also invalid.
            bool isValidEncodedByte =
                iMasked == i &&
                current is CaskKeyKind.PrimaryKey or
                           CaskKeyKind.DerivedKey or
                           CaskKeyKind.HMAC;

            if (isValidEncodedByte)
            {
                Assert.True(succeeded, $"Valid CaskKeyKind '{current}' failed 'CaskKey.TryEncode'");
                continue;
            }

            Assert.False(succeeded, $"Invalid CaskKeyKind value '{current}' passed 'CaskKey.TryEncode' check");
        }
    }

    [Fact]
    public void CaskKey_TryEncode_Basic()
    {
        CaskKey key = Cask.GenerateKey("TEST",
                                       providerKeyKind: 'J',
                                       expiryInFiveMinuteIncrements: 0, // 3 days.
                                       providerData: null);

        Span<byte> decoded = stackalloc byte[key.SizeInBytes];
        Base64Url.TryDecodeFromChars(key.ToString().AsSpan(), decoded, out int bytesWritten);

        var newKey = CaskKey.Encode(decoded);

        Assert.Equal(key, newKey);
    }

    [Fact]
    public void CaskKey_CreateOverloads_ThrowOnInvalidKey()
    {
        CaskKey key = Cask.GenerateKey("TEST",
                                       providerKeyKind: 'R',
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

    [Fact]
    public void CaskKey_Decode_DestinationTooSmall()
    {
        CaskKey key = Cask.GenerateKey("TEST",
                                       providerKeyKind: 'W',
                                       expiryInFiveMinuteIncrements: 12 * 24 * 365 * 2, // 2 years.
                                       providerData: "WOLL");

        byte[] destination = new byte[key.SizeInBytes];
        key.Decode(destination);

        destination = new byte[key.SizeInBytes - 1];
        Assert.Throws<ArgumentException>(() => key.Decode(destination));
    }
}
