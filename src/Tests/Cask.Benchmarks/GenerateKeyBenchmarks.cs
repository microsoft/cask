// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Buffers.Text;
using System.Security.Cryptography;

using BenchmarkDotNet.Attributes;

using static CommonAnnotatedSecurityKeys.Benchmarks.BenchmarkTestData;

namespace CommonAnnotatedSecurityKeys.Benchmarks;

[MemoryDiagnoser]
public class GenerateKeyBenchmarks
{
    [Benchmark]
    public string GenerateKey_Cask()
    {
        CaskKey key = Cask.GenerateKey(
            TestProviderSignature,
            TestProviderData);

        return key.ToString();
    }

    // What someone could do if they weren't using Cask and didn't get identifiable keys.
    [Benchmark]
    public string GenerateKey_Floor()
    {
        Span<byte> bytes = stackalloc byte[TestSecretEntropyInBytes];
        RandomNumberGenerator.Fill(bytes);
        return Base64Url.EncodeToString(bytes);
    }
}
