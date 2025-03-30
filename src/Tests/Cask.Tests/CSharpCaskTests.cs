// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Buffers.Text;
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
                                  char providerKind = 'A',
                                  string? reserved = null,
                                  SecretSize secretSize = SecretSize.Bits256)
        {
            CaskKey key = CSharpCask.GenerateKey(providerSignature,
                                                 providerKind,
                                                 reserved,
                                                 secretSize);
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
                // On receiving this exception, we have invalid base64 input. As
                // a result, we will skip the IsCaskBytes check, which throws
                // for this condition.
            }

            if (key.Any((c) => !s_printableBase64UrlCharacters.Contains(c)))
            {
                // This condition will only occur if the input passed to
                // `Base64Url.DecodeFromUtf8` included characters (such as 
                // whitespace) that are not valid ('printable', i.e.,
                // non-padding) base64url characters. Keys that contain
                // these characters are not valid Cask keys. Stripping them
                // might actually result in the resulting bytes comprising
                // a valid Cask key, so we won't test that API in this case.
                // Since the input data has been demonstrated to be invalid,
                // we will also ensure this test is a failure case below.
                keyBytes = null;
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

            if (keyBytes == null && result == true)
            {
                // See comment above for more information on this condition.
                Assert.Fail(
                $"""
                Expected a failure condition as input key bytes did strictly conforming to input key string.
                key: {key}
                """);
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
