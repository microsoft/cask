// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using BenchmarkDotNet.Attributes;

using System.Security.Cryptography;

namespace CommonAnnotatedSecurityKeys.Benchmarks;

public class CompareHashedSignatureBenchmarks
{
    private const int iterations = 10000;
    private const string TestProviderSignature = "TEST";
    private static readonly byte[] TestProviderSignatureBytes = Convert.FromBase64String(TestProviderSignature);

    [Benchmark]
    public void UseCompareHash()
    {
        string key = Cask.Instance.GenerateKey(TestProviderSignature, "99");
        byte[] keyBytes = Convert.FromBase64String(key.FromUrlSafe());
        string hash = Cask.Instance.GenerateHash(keyBytes, keyBytes, 32);
        byte[] hashBytes = Convert.FromBase64String(hash.FromUrlSafe());

        for (int i = 0; i < iterations; i++)
        {
            if (!Cask.Instance.CompareHash(hashBytes, keyBytes, keyBytes))
            {
                throw new InvalidOperationException();
            }
        }
    }

    [Benchmark]
    public void UseHmacSha256()
    {
        string key = Cask.Instance.GenerateKey(TestProviderSignature, "99");
        byte[] keyBytes = Convert.FromBase64String(key.FromUrlSafe());
        string hash = Cask.Instance.GenerateHash(TestProviderSignatureBytes, keyBytes, 32);
        var hmac = new HMACSHA256(keyBytes);
        byte[] hashBytes = hmac.ComputeHash(TestProviderSignatureBytes);

        for (int i = 0; i < iterations; i++)
        {
            hmac = new HMACSHA256(keyBytes);
            byte[] computedHashBytes = hmac.ComputeHash(TestProviderSignatureBytes);

            for (int j = 0; j < hashBytes.Length; j++)
            {
                if (hashBytes[j] != computedHashBytes[j])
                {
                    throw new InvalidOperationException();
                }
            }

            computedHashBytes = hmac.ComputeHash(TestProviderSignatureBytes);

            for (int j = 0; j < hashBytes.Length; j++)
            {
                if (hashBytes[j] != computedHashBytes[j])
                {
                    throw new InvalidOperationException();
                }
            }
        }
    }
}