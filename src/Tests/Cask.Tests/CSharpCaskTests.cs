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
        public string GenerateKey(string providerSignature,
                                  string? providerKind = "A",
                                  string? reserved = null)
        {
            CaskKey key = CSharpCask.GenerateKey(providerSignature, providerKind, reserved);
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
