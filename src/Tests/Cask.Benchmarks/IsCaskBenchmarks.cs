// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Buffers.Text;

using BenchmarkDotNet.Attributes;

namespace CommonAnnotatedSecurityKeys.Benchmarks;

[MemoryDiagnoser]
public class IsCaskBenchmarks
{
    private const int Iterations = 100000;
    private const string TestProviderSignature = "TEST";
    private static readonly string s_key = Cask.GenerateKey(TestProviderSignature, "99").ToString();
    private static readonly byte[] s_keyBytes = Base64Url.DecodeFromChars(s_key.AsSpan());

    [Benchmark]
    public void UseIsCaskString()
    {
        for (int i = 0; i < Iterations; i++)
        {
            Cask.IsCask(s_key);
        }
    }

    [Benchmark]
    public void UseIsCaskBytes()
    {
        for (int i = 0; i < Iterations; i++)
        {
            Cask.IsCaskBytes(s_keyBytes);
        }
    }
}
