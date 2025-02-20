// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Text;

namespace CommonAnnotatedSecurityKeys.Benchmarks;

internal static class BenchmarkTestData
{
    public const string TestDerivationInput = "Lorem ipsum dolor sit amet, consectetur adipiscing elit";
    public const string TestProviderData = "0123456789ABCDEF";
    public const string TestProviderSignature = "TEST";
    public const string TestProviderKeyKind = "M";

    public const int TestSecretEntropyInBytes = 32;

    public static readonly byte[] TestDerivationInputUtf8 = Encoding.UTF8.GetBytes(TestDerivationInput);

    public static readonly string TestCaskSecret = new GenerateKeyBenchmarks().GenerateKey_Cask();
    public static readonly string TestNonIdentifiableSecret = new GenerateKeyBenchmarks().GenerateKey_Floor();
}
