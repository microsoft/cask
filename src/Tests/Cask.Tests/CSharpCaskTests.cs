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
            var candidateHashKey = CaskKey.Create(candidateHash);
            var secretKey = CaskKey.Create(secret);
            bool result = CSharpCask.CompareHash(candidateHashKey, derivationInput, secretKey, secretEntropyInBytes);

            string derivationInputString = Encoding.UTF8.GetString(derivationInput);
            (string name, bool value)[] checks = [
                ("ReadOnlySpan<byte>)", result),
                ("string", CSharpCask.CompareHash(candidateHashKey, derivationInputString, secretKey, secretEntropyInBytes)),
                ("ReadOnlySpan<char>)", CSharpCask.CompareHash(candidateHashKey, derivationInputString.AsSpan(), secretKey, secretEntropyInBytes)),
            ];

            if (!checks.All(c => c.value == result))
            {
                Assert.Fail(
                    "Got different results from CompareHash with different forms of derivationInput"
                    + Environment.NewLine
                    + $"derivationInput: {derivationInputString}"
                    + Environment.NewLine
                    + string.Join(Environment.NewLine, checks.Select(c => $"  {c.name} -> {c.value}")));
            }

            return result;
        }

        public string GenerateHash(byte[] derivationInput,
                                   string secret,
                                   int secretEntropyInBytes = 32)
        {
            var secretKey = CaskKey.Create(secret);
            string result = CSharpCask.GenerateHash(derivationInput, secretKey, secretEntropyInBytes).ToString();

            string derivationInputString = Encoding.UTF8.GetString(derivationInput);
            (string name, string value)[] checks = [
                ("ReadOnlySpan<byte>)", result),
                ("string", CSharpCask.GenerateHash(derivationInputString, secretKey, secretEntropyInBytes).ToString()),
                ("ReadOnlySpan<char>)", CSharpCask.GenerateHash(derivationInputString.AsSpan(), secretKey, secretEntropyInBytes).ToString()),
            ];

            if (!checks.All(c => c.value == result))
            {
                Assert.Fail(
                    "Got different results from GenerateHash with different forms of derivationInput"
                    + Environment.NewLine
                    + $"derivationInput: {derivationInputString}"
                    + Environment.NewLine
                    + string.Join(Environment.NewLine, checks.Select(c => $"  {c.name} -> {c.value}")));
            }

            return result;
        }

        public string GenerateKey(string providerSignature,
                                  string allocatorCode,
                                  string? reserved = null,
                                  int secretEntropyInBytes = 32)
        {
            CaskKey key = CSharpCask.GenerateKey(providerSignature, allocatorCode, reserved, secretEntropyInBytes);
            return key.ToString();
        }

        public bool IsCask(string key)
        {
            bool result = CSharpCask.IsCask(key);

            (string name, bool value)[] checks = [
                ("Cask.IsCask(string)", result),
                ("Cask.IsCask(ReadOnlySpan<char>)", CSharpCask.IsCask(key.AsSpan())),
                ("Cask.IsCaskUtf8(ReadOnlySpan<byte>)", CSharpCask.IsCaskUtf8(Encoding.UTF8.GetBytes(key))),
                ("CaskKey.TryCreate(string)", CaskKey.TryCreate(key, out _)),
                ("CaskKey.TryCreate(ReadOnlySpan<char>)", CaskKey.TryCreate(key.AsSpan(), out _)),
                ("CaskKey.TryCreateUtf8(ReadOnlySpan<byte>)", CaskKey.TryCreateUtf8(Encoding.UTF8.GetBytes(key), out _)),
            ];

            if (!checks.All(c => c.value == result))
            {
                Assert.Fail(
                   "Got different answers from different ways to check if key is valid Cask:"
                    + Environment.NewLine
                    + $"key: {key}"
                    + Environment.NewLine
                    + string.Join(Environment.NewLine, checks.Select(c => $"  {c.name} -> {c.value}")));
            }

            return result;
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
