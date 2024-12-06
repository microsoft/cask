// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Buffers.Text;
using System.Security.Cryptography;

using BenchmarkDotNet.Attributes;

namespace CommonAnnotatedSecurityKeys.Benchmarks;

[MemoryDiagnoser]
public class CompareHashedSignatureBenchmarks
{
    private const int Iterations = 10000;
    private const string TestProviderSignature = "TEST";
    private static readonly byte[] s_testProviderSignatureBytes = Convert.FromBase64String(TestProviderSignature);

    [Benchmark]
    public void UseCompareHash()
    {
        CaskKey key = Cask.GenerateKey(TestProviderSignature, "99");
        CaskKey hash = Cask.GenerateHash(s_testProviderSignatureBytes, key, 32);

        for (int i = 0; i < Iterations; i++)
        {
            if (!Cask.CompareHash(hash, s_testProviderSignatureBytes, key, 32))
            {
                throw new InvalidOperationException();
            }
        }
    }

    [Benchmark]
    public void UseHmacSha256()
    {
        CaskKey key = Cask.GenerateKey(TestProviderSignature, "99");
        byte[] keyBytes = Base64Url.DecodeFromChars(key.ToString().AsSpan());
        byte[] hashBytes = new byte[HMACSHA256.HashSizeInBytes];
        HMACSHA256.HashData(keyBytes, s_testProviderSignatureBytes, hashBytes);
        Span<byte> computedHashBytes = stackalloc byte[HMACSHA256.HashSizeInBytes];

        for (int i = 0; i < Iterations; i++)
        {
            HMACSHA256.HashData(keyBytes, s_testProviderSignatureBytes, computedHashBytes);
            if (!CryptographicOperations.FixedTimeEquals(hashBytes, computedHashBytes))
            {
                throw new InvalidOperationException();
            }
        }
    }
}
