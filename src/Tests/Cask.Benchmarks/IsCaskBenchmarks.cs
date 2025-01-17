// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Buffers.Text;

using BenchmarkDotNet.Attributes;

using static CommonAnnotatedSecurityKeys.Benchmarks.BenchmarkTestData;

namespace CommonAnnotatedSecurityKeys.Benchmarks;

[MemoryDiagnoser]
public class IsCaskBenchmarks
{
    private static readonly byte[] s_testCaskKeyUtf8 = Base64Url.DecodeFromChars(TestCaskSecret.AsSpan());

    [Benchmark]
    public bool IsCaskString()
    {
        return Cask.IsCask(TestCaskSecret);
    }

    [Benchmark]
    public bool IsCaskBytes()
    {
        return Cask.IsCaskBytes(s_testCaskKeyUtf8);
    }
}
