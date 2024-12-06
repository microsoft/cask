// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Text;

using Xunit;

using CSharpCask = CommonAnnotatedSecurityKeys.Cask;

namespace CommonAnnotatedSecurityKeys.Tests;

public class CSharpCaskTests : CaskTestsBase
{
    public CSharpCaskTests() : base(new Implementation()) { }

    private sealed class Implementation : ICask
    {
        public bool CompareHash(string candidateHash,
                                byte[] derivationInput,
                                string secret,
                                int secretEntropyInBytes = 32)
        {
            return CSharpCask.CompareHash(CaskKey.Parse(candidateHash), derivationInput, CaskKey.Parse(secret), secretEntropyInBytes);
        }

        public string GenerateHash(byte[] derivationInput,
                                   string secret,
                                   int secretEntropyInBytes = 32)
        {
            CaskKey hash = CSharpCask.GenerateHash(derivationInput, CaskKey.Parse(secret), secretEntropyInBytes);
            return hash.ToString();
        }

        public string GenerateKey(string providerSignature,
                                  string allocatorCode,
                                  string? reserved = null,
                                  int secretEntropyInBytes = 32)
        {
            CaskKey key = CSharpCask.GenerateKey(providerSignature, allocatorCode, reserved, secretEntropyInBytes);
            return key.ToString();
        }

        public bool IsCask(string keyOrHash)
        {
            // Test all the C# variants without forcing other languages to have them.
            bool isCaskString = CSharpCask.IsCask(keyOrHash);
            bool isCaskSpan = CSharpCask.IsCask(keyOrHash.AsSpan());
            bool isCaskUtf8 = CSharpCask.IsCaskUtf8(Encoding.UTF8.GetBytes(keyOrHash));
            Assert.True(isCaskSpan == isCaskString, $"IsCask(ReadOnlySpan<char>) -> {isCaskSpan} behaved differently from IsCask(string) -> {isCaskString}");
            Assert.True(isCaskUtf8 == isCaskString, $"IsCaskUtf8(ReadOnlySpan<byte>) -> {isCaskUtf8} behaved differently from IsCask(string) -> {isCaskString}");
            return isCaskString;
        }

        public bool IsCaskBytes(byte[] bytes)
        {
            return CSharpCask.IsCaskBytes(bytes);
        }

        Mock ICask.MockFillRandom(FillRandomAction fillRandom)
        {
            return CSharpCask.MockFillRandom(fillRandom);
        }

        Mock ICask.MockUtcNow(UtcNowFunc getUtcNow)
        {
            return CSharpCask.MockUtcNow(getUtcNow);
        }
    }
}
