// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.


/*
 * When these tests are run on .NET Framework, our polyfill implementations are
 * used. When run on modern .NET, the real BCL API are used. Running on both
 * allows us to verify that the polyfills and modern APIs are equivalent.
 *
 * Adapted from:
 *   https://github.com/dotnet/runtime/blob/78ede327fe8c4322cf14e75e30c2f06b2ccca32b/src/libraries/System.Security.Cryptography/tests/Sha256Tests.cs
 *   https://github.com/dotnet/runtime/blob/78ede327fe8c4322cf14e75e30c2f06b2ccca32b/src/libraries/System.Security.Cryptography/tests/HmacSha256Tests.cs
 *   https://github.com/dotnet/runtime/blob/78ede327fe8c4322cf14e75e30c2f06b2ccca32b/src/libraries/System.Security.Cryptography/tests/RandomNumberGeneratorTests.cs
 *
 * References:
 *   https://datatracker.ietf.org/doc/html/rfc4231#section-4.2
 *   http://csrc.nist.gov/publications/fips/fips180-2/fips180-2.pdf Appendix B
 */

#pragma warning disable CA1308 // Normalize strings to uppercase: not an issue for hex
#pragma warning disable CA1307 // Specify StringComparison: not applicable .NET Framework
#pragma warning disable CA1846 // Prefer AsSpan over substring: not applicable on .NET Framework
#pragma warning disable CA1872 // Prefer ToHexString over BitConverter: not applicable on .NET Framework

using System.Globalization;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;

using Xunit;

namespace CommonAnnotatedSecurityKeys.Tests;

public class PolyfillTests
{
    [Fact]
    public void Sha256_DestinationTooSmall()
    {
        byte[] destination = new byte[SHA256.HashSizeInBytes - 1];
        Assert.Throws<ArgumentException>("destination", () => SHA256.HashData([], destination));
    }

    [Fact]
    public void Sha256_Empty()
    {
        ReadOnlySpan<byte> data = [];
        string hash = Sha256(data);
        Assert.Equal("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", hash);
    }

    [Fact]
    public void Sha256_Large_MultipleOf4096()
    {
        ReadOnlySpan<byte> data = RepeatText("0102030405060708", 1024);
        string hash = Sha256(data);
        Assert.Equal("cedca4ad2cce0d0b399931708684800cd16be396ffa5af51297a091650aa3610", hash);
    }

    [Fact]
    public void Sha256_Large_NotMultipleOf4096()
    {
        ReadOnlySpan<byte> data = RepeatText("0102030405060708", 1025);
        string hash = Sha256(data);
        Assert.Equal("9e2e99445f5349c379ceb4c995dde401f63012422183a411d02eb251b1e02e65", hash);
    }

    [Fact]
    public void Sha256_Fips180_1()
    {
        ReadOnlySpan<byte> data = "abc"u8;
        string hash = Sha256(data);
        Assert.Equal("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", hash);
    }

    [Fact]
    public void Sha256_Fips180_2()
    {
        ReadOnlySpan<byte> data = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"u8;
        string hash = Sha256(data);
        Assert.Equal("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1", hash);
    }

    [Fact]
    public void Sha256_Fips180_3()
    {
        ReadOnlySpan<byte> data = RepeatText("a", 1000000);
        string hash = Sha256(data);
        Assert.Equal("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0", hash);
    }

    [Fact]
    public void Sha256_HashSizes()
    {
        Assert.Equal(256, SHA256.HashSizeInBits);
        Assert.Equal(32, SHA256.HashSizeInBytes);
    }

    [Fact]
    public void HmacSha256_DestinationTooSmall()
    {
        byte[] destination = new byte[HMACSHA256.HashSizeInBytes - 1];
        Assert.Throws<ArgumentException>("destination", () => HMACSHA256.HashData([], [], destination));
    }

    [Fact]
    public void HmacSha256_EmptyKey()
    {
        ReadOnlySpan<byte> key = [];
        ReadOnlySpan<byte> data = "Crypto is fun!"u8;
        string hash = HmacSha256(key, data);
        Assert.Equal("de26dd5a23a91021f61eacf8a8dd324ab5637977486a10d701c4dfa4ae33cb4f", hash);
    }

    [Fact]
    public void HmacSha256_Large_MultipleOf4096()
    {
        ReadOnlySpan<byte> key = HexToBytes("000102030405060708090a0b0c0d0e0f");
        ReadOnlySpan<byte> data = RepeatText("0102030405060708", 1024);
        string hash = HmacSha256(key, data);
        Assert.Equal("a47b9f5bd5c2def403a0279d4c6c407a2d34561e7d1f006d7fe8bdc2c78227d5", hash);
    }

    [Fact]
    public void HmacSha256_Large_NotMultipleOf4096()
    {
        ReadOnlySpan<byte> key = HexToBytes("000102030405060708090a0b0c0d0e0f");
        ReadOnlySpan<byte> data = RepeatText("0102030405060708", 1025);
        string hash = HmacSha256(key, data);
        Assert.Equal("1cf6661b6efd25d8b6de734aa39d5d3d44c9a56bb9377a6388eb0fc5e48a108b", hash);
    }

    [Fact]
    public void HmacSha256_KeySmallerThanBlockSize()
    {
        ReadOnlySpan<byte> key = RepeatByte(0x0b, 63);
        ReadOnlySpan<byte> data = "Test data"u8;
        string hash = HmacSha256(key, data);
        Assert.Equal("b015fe206b739aca91dcb0ee5013ac1a55c529df6aa0b589d3a8007f9f006806", hash);
    }

    [Fact]
    public void HmacSha256_KeySizeEqualToBlockSize()
    {
        ReadOnlySpan<byte> key = RepeatByte(0x0b, 64);
        ReadOnlySpan<byte> data = "Test data"u8;
        string hash = HmacSha256(key, data);
        Assert.Equal("63d630b64a86e060a712afc0ac6bf56331d18c0f938c8ac163e328db98ea4597", hash);
    }

    [Fact]
    public void HmacSha256_KeyLargerThanBlockSize()
    {
        ReadOnlySpan<byte> key = RepeatByte(0x0b, 65);
        ReadOnlySpan<byte> data = "Test data"u8;
        string hash = HmacSha256(key, data);
        Assert.Equal("27fb9498207f8e92081154cc60ab759bd46d8dae6a062cb0291f847d12fc4232", hash);
    }

    [Fact]
    public void HmacSha256_Rfc4231_1()
    {
        ReadOnlySpan<byte> key = RepeatByte(0x0b, 20);
        ReadOnlySpan<byte> data = "Hi There"u8;
        string hash = HmacSha256(key, data);
        Assert.Equal("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7", hash);
    }

    [Fact]
    public void HmacSha256_Rfc4231_2()
    {
        ReadOnlySpan<byte> key = "Jefe"u8;
        ReadOnlySpan<byte> data = "what do ya want for nothing?"u8;
        string hash = HmacSha256(key, data);
        Assert.Equal("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843", hash);
    }

    [Fact]
    public void HmacSha256_Rfc4231_3()
    {
        ReadOnlySpan<byte> key = RepeatByte(0xaa, 20);
        ReadOnlySpan<byte> data = RepeatByte(0xdd, 50);
        string hash = HmacSha256(key, data);
        Assert.Equal("773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe", hash);
    }

    [Fact]
    public void HmacSha256_Rfc4231_4()
    {
        ReadOnlySpan<byte> key = HexToBytes("0102030405060708090a0b0c0d0e0f10111213141516171819");
        ReadOnlySpan<byte> data = RepeatByte(0xcd, 50);
        string hash = HmacSha256(key, data);
        Assert.Equal("82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b", hash);
    }

    [Fact]
    public void HmacSha256_Rfc4231_5()
    {
        ReadOnlySpan<byte> key = RepeatByte(0x0c, 20);
        ReadOnlySpan<byte> data = "Test With Truncation"u8;
        string hash = HmacSha256(key, data);
        string truncated = hash[..32];
        Assert.Equal("a3b6167473100ee06e0c796c2955552b", truncated);
    }

    [Fact]
    public void HmacSha256_Rfc4231_6()
    {
        ReadOnlySpan<byte> key = RepeatByte(0xaa, 131);
        ReadOnlySpan<byte> data = "Test Using Larger Than Block-Size Key - Hash Key First"u8;
        string hash = HmacSha256(key, data);
        Assert.Equal("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54", hash);
    }

    [Fact]
    public void HmacSha256_Rfc4231_7()
    {
        ReadOnlySpan<byte> key = RepeatByte(0xaa, 131);
        ReadOnlySpan<byte> data = "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm."u8;
        string hash = HmacSha256(key, data);
        Assert.Equal("9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2", hash);
    }

    [Fact]
    public void HmacSha256_HashSizes()
    {
        Assert.Equal(256, HMACSHA256.HashSizeInBits);
        Assert.Equal(32, HMACSHA256.HashSizeInBytes);
    }

    [Fact]
    public void Random_Distribution()
    {
        byte[] random = new byte[4096];
        RandomNumberGenerator.Fill(random);

        // Better tests for randomness are available. This is just a simple
        // check that compares the number of 0s and 1s in the bits.
        int zeroCount = 0;
        int oneCount = 0;

        for (int i = 0; i < random.Length; i++)
        {
            for (int j = 0; j < 8; j++)
            {
                if (((random[i] >> j) & 1) == 1)
                {
                    oneCount++;
                }
                else
                {
                    zeroCount++;
                }
            }
        }

        // Over the long run there should be about as many 1s as 0s. This isn't
        // a guarantee, just a statistical observation. Allow a 7% tolerance
        // band before considering it to have gotten out of hand.
        double bitDifference = Math.Abs(zeroCount - oneCount) / (double)(zeroCount + oneCount);
        const double tolerance = 0.07;
        Assert.True(bitDifference < tolerance, $"Expected bitDifference < {tolerance}, got {bitDifference}.");
    }

    [Fact]
    public void Random_NotDeterministic()
    {
        Span<byte> random1 = stackalloc byte[32];
        Span<byte> random2 = stackalloc byte[32];
        RandomNumberGenerator.Fill(random1);
        RandomNumberGenerator.Fill(random2);
        Assert.False(random1.SequenceEqual(random2), "RandomNumberGenerator produced two identical 32-byte sequences.");
    }

    [Fact]
    public void Encoding_GetString_Empty()
    {
        ReadOnlySpan<byte> data = [];
        string text = Encoding.UTF8.GetString(data);
        Assert.Equal("", text);
    }

    [Fact]
    public void Encoding_GetByteCount_Empty()
    {
        ReadOnlySpan<char> text = "".AsSpan();
        int byteCount = Encoding.UTF8.GetByteCount(text);
        Assert.Equal(0, byteCount);
    }

    [Fact]
    public void Encoding_GetBytes_Empty()
    {
        ReadOnlySpan<char> text = "".AsSpan();
        Span<byte> bytes = [];
        int bytesWritten = Encoding.UTF8.GetBytes(text, bytes);
        Assert.Equal(0, bytesWritten);
    }

#if NETFRAMEWORK // We don't need to stress test the modern BCL :)
    [Fact]
    public async Task Polyfill_ThreadingStress()
    {
        const int maxMilliseconds = 500;
        const int testsQueuedPerIteration = 64;

        IEnumerable<MethodInfo> methods = GetType()
            .GetMethods(BindingFlags.Public | BindingFlags.Instance)
            .Where(m => m.IsDefined(typeof(FactAttribute)) && m.ReturnType == typeof(void));

        Action[] tests = [.. methods.Select(m => (Action)m.CreateDelegate(typeof(Action), this))];
        var tasks = new Task[testsQueuedPerIteration];

        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(maxMilliseconds));
        while (!cts.IsCancellationRequested)
        {
            for (int i = 0; i < testsQueuedPerIteration; i++)
            {
                tasks[i] = Task.Run(tests[i % tests.Length]);
            }
            await Task.WhenAll(tasks);
        }
    }
#endif

    private static string Sha256(ReadOnlySpan<byte> data)
    {
        byte[] hashBytes = new byte[32];
        int bytesWritten = SHA256.HashData(data, hashBytes);
        Assert.Equal(32, bytesWritten);
        return BytesToHex(hashBytes);
    }

    private static string HmacSha256(ReadOnlySpan<byte> key, ReadOnlySpan<byte> source)
    {
        byte[] hashBytes = new byte[32];
        int bytesWritten = HMACSHA256.HashData(key, source, hashBytes);
        Assert.Equal(32, bytesWritten);
        return BytesToHex(hashBytes);
    }

    private static string BytesToHex(byte[] bytes)
    {
        return BitConverter.ToString(bytes).Replace("-", "").ToLowerInvariant();
    }

    private static byte[] HexToBytes(string hex)
    {
        Assert.True(hex.Length % 2 == 0, "Hex string must have an even number of characters.");
        byte[] bytes = new byte[hex.Length / 2];
        for (int i = 0; i < bytes.Length; i++)
        {
            bytes[i] = byte.Parse(hex.Substring(i * 2, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture);
        }
        return bytes;
    }

    private static byte[] RepeatByte(byte b, int times)
    {
        return [.. Enumerable.Repeat(b, times)];
    }

    private static byte[] RepeatText(string text, int times)
    {
        string fullText = string.Concat(Enumerable.Repeat(text, times));
        return Encoding.UTF8.GetBytes(fullText);
    }
}
