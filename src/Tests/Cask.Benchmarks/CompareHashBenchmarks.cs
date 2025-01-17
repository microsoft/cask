// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;

using BenchmarkDotNet.Attributes;

using static CommonAnnotatedSecurityKeys.Benchmarks.BenchmarkTestData;

namespace CommonAnnotatedSecurityKeys.Benchmarks;

[MemoryDiagnoser]
public class CompareHashBenchmarks
{
    [Benchmark]
    public bool CompareHash_Cask()
    {
        return Cask.CompareHash(
            CaskKey.Create(TestCaskHash),
            TestDerivationInput,
            CaskKey.Create(TestCaskSecret));
    }

    [Benchmark]
    public bool CompareHash_Floor()
    {
        Span<byte> candidateHash = stackalloc byte[HMACSHA256.HashSizeInBytes];
        Base64Url.DecodeFromChars(TestNonIdentifiableHash.AsSpan(), candidateHash);

        Span<byte> secret = stackalloc byte[TestSecretEntropyInBytes];
        Base64Url.DecodeFromChars(TestNonIdentifiableSecret.AsSpan(), secret);

        Span<byte> hash = stackalloc byte[HMACSHA256.HashSizeInBytes];
        HMACSHA256.HashData(secret, TestDerivationInputUtf8, hash);

        return CryptographicOperations.FixedTimeEquals(candidateHash, hash);
    }
}
