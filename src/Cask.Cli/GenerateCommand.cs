// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;

namespace CommonAnnotatedSecurityKeys.Cli;

internal static class GenerateCommand
{
    private static readonly string s_microsoftTenantId = new Guid("782ef2bb-3056-4438-946d-395022a4a19f").ToString();

    internal static int Run(GenerateOptions options)
    {
        string cloudText = "AC";
        string region = EncodeForIdentifiableKey("westus");
        string tenant = EncodeForIdentifiableKey(s_microsoftTenantId);
        string providerReserved = "AAAA";
        string providerData = $"{cloudText}{region}{tenant}{providerReserved}";

        string providerSignature = options.FixedSignature;

        for (int i = 0; i < options.Count; i++)
        {
            CaskKey key = Cask.GenerateKey(providerSignature, providerData);

            string validity = Cask.IsCask(key.ToString()) ? "Valid Key   " : "INVALID KEY ";
            Console.WriteLine($"{validity}: {key}");
        }

        return 0;
    }

    public static string EncodeForIdentifiableKey(string text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return "AAAAA";
        }

        byte[] hashed = SHA256.HashData(Encoding.UTF8.GetBytes(text));
        return Base64Url.EncodeToString(hashed)[..5];
    }
}
