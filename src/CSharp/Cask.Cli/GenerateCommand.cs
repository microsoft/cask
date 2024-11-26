// Copyright (c) Microsoft. All rights reserved.

using System.Text;

namespace CommonAnnotatedSecurityKeys.Cli;

public class GenerateCommand
{
    private readonly string MicrosoftTenantId = new Guid("782ef2bb-3056-4438-946d-395022a4a19f").ToString();

    internal int Run(GenerateOptions options)
    {
        var cask = new Cask();
        byte[] derivationInput = Encoding.UTF8.GetBytes(nameof(derivationInput));

        string cloudText = "AC";
        string region = EncodeForIdentifiableKey("westus");
        string tenant = EncodeForIdentifiableKey(MicrosoftTenantId);
        string providerReserved = "AAAA";
        byte[] reserved = Convert.FromBase64String($"{cloudText}{region}{tenant}{providerReserved}");

        byte[] providerSignature = Convert.FromBase64String(options.FixedSignature.ToUrlSafe());

        for (int i = 0; i < options.Count; i++)
        {

            byte[] keyBytes = cask.GenerateKeyBytes(providerSignature,
                                                   "99",
                                                   reserved,
                                                   secretEntropyInBytes: options.SecretEntropyInBytes,
                                                   testChar: default);


            string key = Convert.ToBase64String(keyBytes).ToUrlSafe();

            string validity = cask.IsCask(key) ? "Valid Key   " : "INVALID KEY ";
            Console.WriteLine($"{validity}: {key}");

            keyBytes = Convert.FromBase64String(key.FromUrlSafe());
            string hash = cask.GenerateHash(derivationInput, keyBytes, options.SecretEntropyInBytes);

            validity = cask.IsCask(hash) ? "Valid Hash  " : "INVALID HASH";
            Console.WriteLine($"{validity}: {hash}");
        }

        return 0;
    }

    public static string EncodeForIdentifiableKey(string text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return "AAAAA";
        }

        byte[] hashed = CaskUtilityApi.Sha256.ComputeHash(Encoding.UTF8.GetBytes(text));
        return Convert.ToBase64String(hashed).ToUrlSafe().Substring(0, 5);
    }
}