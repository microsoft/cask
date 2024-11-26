// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using BenchmarkDotNet.Attributes;

namespace CommonAnnotatedSecurityKeys.Benchmarks;

public class IsCaskBenchmarks
{
    private const int iterations = 100000;
    private const string TestProviderSignature = "TEST";
    private static readonly string key = Cask.Instance.GenerateKey(TestProviderSignature, "99");
    private static readonly byte[] keyBytes = Convert.FromBase64String(key);

    [Benchmark]
    public void UseIsCaskString()
    {
        for (int i = 0; i < iterations; i++)
        {
            Cask.Instance.IsCask(key);
        }
    }

    [Benchmark]
    public void UseIsCaskBytes()
    {
        for (int i = 0; i < iterations; i++)
        {
            Cask.Instance.IsCask(keyBytes);
        }
    }
}