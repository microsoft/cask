// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using CommonAnnotatedSecurityKeys.Benchmarks;

#if RELEASE
using Runner = BenchmarkDotNet.Running.BenchmarkRunner;
#else
using Runner = CommonAnnotatedSecurityKeys.Benchmarks.DebugBenchmarkRunner;
#endif

/* To run this benchmark, navigate to the benchmark source directory
 * and use the following command:
 * 
 * dotnet run -c Release --framework net8.0 Cask.Benchmarks.csproj
 */
Runner.Run([
    typeof(IsCaskBenchmarks),
    typeof(CompareHashedSignatureBenchmarks),
 ]);
