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

using System.Security.Cryptography;
using System.Text;

using Xunit;

namespace CommonAnnotatedSecurityKeys.Tests;

public class PolyfillTests
{
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
    public void Encoding_GetByteCount_Basic()
    {
        string basic = nameof(basic);
        ReadOnlySpan<char> text = basic.AsSpan();
        int byteCount = Encoding.UTF8.GetByteCount(text);
        Assert.Equal(basic.Length, byteCount);
    }

    [Fact]
    public void Encoding_GetBytes_Empty()
    {
        ReadOnlySpan<char> text = "".AsSpan();
        Span<byte> bytes = [];
        int bytesWritten = Encoding.UTF8.GetBytes(text, bytes);
        Assert.Equal(0, bytesWritten);
    }

    [Fact]
    public void Encoding_GetBytes_Basic()
    {
        string basic = nameof(basic);
        ReadOnlySpan<char> text = basic.AsSpan();
        Span<byte> bytes = new byte[basic.Length];
        int bytesWritten = Encoding.UTF8.GetBytes(text, bytes);
        Assert.Equal(basic.Length, bytesWritten);
        Assert.Equal(basic, Encoding.UTF8.GetString(bytes));
    }

#if NETFRAMEWORK // We don't need to stress test the modern BCL :)
    [Fact]
    public async Task Polyfill_ThreadingStress()
    {
        const int maxMilliseconds = 500;
        const int testsQueuedPerIteration = 64;

        IEnumerable<System.Reflection.MethodInfo> methods = GetType()
            .GetMethods(System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Instance)
            .Where(m => m.IsDefined(typeof(FactAttribute), false) && m.ReturnType == typeof(void));

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
}
