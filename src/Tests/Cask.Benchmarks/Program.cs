
using BenchmarkDotNet.Reports;
using BenchmarkDotNet.Running;

using CommonAnnotatedSecurityKeys.Benchmarks;

//new CompareHashedSignatureBenchmarks().UseHmacSha256();

/* To run this benchmark, navigate to the benchmark source directory
 * and use the following command:
 * 
 * dotnet run -c Release --framework net8.0 Cask.Benchmarks.csproj
 */
//Summary summary = BenchmarkRunner.Run<IsCaskBenchmarks>();
Summary summary = BenchmarkRunner.Run<CompareHashedSignatureBenchmarks>();