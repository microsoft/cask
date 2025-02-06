// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;

using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Diagnosers;

using static CommonAnnotatedSecurityKeys.Benchmarks.BenchmarkTestData;

namespace CommonAnnotatedSecurityKeys.Benchmarks;

[MemoryDiagnoser]
public class C3IdBenchmarks
{
    private static readonly byte[] s_testCaskSecretUtf8 = Encoding.UTF8.GetBytes(TestCaskSecret);

    [Benchmark]
    public string ComputeC3Id()
    {
        return CaskComputedCorrelatingId.Compute(TestCaskSecret);
    }

    // Measures cost without encoding conversion, converting to base64, or allocating a string for the result.
    [Benchmark]
    public void ComputeC3Id_Utf8Raw()
    {
        Span<byte> c3id = stackalloc byte[CaskComputedCorrelatingId.RawSizeInBytes];
        CaskComputedCorrelatingId.ComputeRawUtf8(s_testCaskSecretUtf8, c3id);
    }

    // Measures the cost of two SHA256 hash rounds and nothing else.
    [Benchmark]
    public void ComputeC3Id_Floor()
    {
        Span<byte> hash1 = stackalloc byte[SHA256.HashSizeInBytes];
        SHA256.HashData(s_testCaskSecretUtf8, hash1);
        Span<byte> hash2 = stackalloc byte[SHA256.HashSizeInBytes];
        SHA256.HashData(hash1, hash2);
    }

    [Benchmark]
    public void ComputeC3Id_Floor_SingleSha256()
    {
        Span<byte> hash = stackalloc byte[SHA256.HashSizeInBytes];
        SHA256.HashData(s_testCaskSecretUtf8, hash);
    }
}
