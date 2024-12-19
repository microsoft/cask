// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Buffers.Text;
using System.Security.Cryptography;

using BenchmarkDotNet.Attributes;

using static CommonAnnotatedSecurityKeys.Benchmarks.BenchmarkTestData;

namespace CommonAnnotatedSecurityKeys.Benchmarks;

[MemoryDiagnoser]
public class GenerateHashBenchmarks
{
    [Benchmark]
    public string GenerateHash_Cask()
    {
        CaskKey key = Cask.GenerateHash(
            TestDerivationInput,
            CaskKey.Create(TestCaskSecret),
            TestSecretEntropyInBytes);

        return key.ToString();
    }

    [Benchmark]
    public string GenerateHash_Floor()
    {
        Span<byte> secret = stackalloc byte[TestSecretEntropyInBytes];
        Base64Url.DecodeFromChars(TestNonIdentifiableSecret.AsSpan(), secret);

        Span<byte> hash = stackalloc byte[HMACSHA256.HashSizeInBytes];
        HMACSHA256.HashData(secret, TestDerivationInputUtf8, hash);

        return Base64Url.EncodeToString(hash);
    }
}
