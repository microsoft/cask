// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Buffers.Text;
using System.Diagnostics.CodeAnalysis;
using System.Text;

using Xunit;

using CSharpCask = CommonAnnotatedSecurityKeys.Cask;

namespace CommonAnnotatedSecurityKeys.Tests;

[ExcludeFromCodeCoverage]
public class CSharpCaskTests : CaskTestsBase
{
    public CSharpCaskTests() : base(new Implementation()) { }

    private sealed class Implementation : ICask
    {
        public string GenerateKey(string providerSignature,
                                  string providerKind = "A",
                                  int expiryInFiveMinuteIncrements = 0,
                                  string? reserved = null)
        {
            CaskKey key = CSharpCask.GenerateKey(providerSignature,
                                                 providerKind,
                                                 expiryInFiveMinuteIncrements,
                                                 reserved);
            return key.ToString();
        }

        public bool IsCask(string key)
        {
            bool result = CSharpCask.IsCask(key);

            byte[] keyUtf8 = Encoding.UTF8.GetBytes(key);
            byte[]? keyBytes = null;

            try
            {
                keyBytes = Base64Url.DecodeFromUtf8(keyUtf8);
            }
            catch (FormatException)
            {
                // On receiving this exception, we have invalid base64 input.
                // As a result, we will skip the IsCaskBytes check, which
                // will throw for this condition.
            }

            (string name, bool value)[] checks = [
                ("Cask.IsCask(string)", result),
                ("Cask.IsCask(ReadOnlySpan<char>)", CSharpCask.IsCask(key.AsSpan())),
                ("Cask.IsCaskBytes(ReadOnlySpan<byte>)", keyBytes != null && CSharpCask.IsCaskBytes(keyBytes)),
                ("Cask.IsCaskUtf8(ReadOnlySpan<byte>)", CSharpCask.IsCaskUtf8(keyUtf8)),
                ("CaskKey.TryCreate(string)", CaskKey.TryCreate(key, out _)),
                ("CaskKey.TryCreate(ReadOnlySpan<char>)", CaskKey.TryCreate(key.AsSpan(), out _)),
                ("CaskKey.TryCreateUtf8(ReadOnlySpan<byte>)", CaskKey.TryCreateUtf8(keyUtf8, out _)),
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
