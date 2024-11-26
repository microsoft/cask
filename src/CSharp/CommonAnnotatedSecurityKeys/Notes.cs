// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

/*
namespace CommonAnnotatedSecurityKeys
{
    internal class Notes
    {
        public string GenerateKey(string providerSignature, string allocatorCode, string reserved = null, int randomBytesCount = 32)
        {
            ValidateArguments(providerSignature, allocatorCode, reserved, randomBytesCount);

            // Ensure that the randomBytesCount is a multiple of 3. We keep all data
            // aligned along a 3-byte boundary to ensure consistent base64 encoding
            // in the key for fixed components.
            randomBytesCount = ((randomBytesCount + 2) / 3) * 3;
            byte[] randomBytes = new byte[randomBytesCount];
            s_rng.GetBytes(randomBytes);
            string randomComponent = Convert.ToBase64String(randomBytes).Replace('+', '-').Replace('/', '_');

            char yearsSince2024 = (char)('A' + DateTime.UtcNow.Year - 2024);
            char zeroIndexedMonth = (char)('A' + DateTime.UtcNow.Month - 1);

            string key = $"{randomComponent}{reserved}JQQJ{allocatorCode}{yearsSince2024}{zeroIndexedMonth}{providerSignature}";

            key = key.Replace('-', '+').Replace('_', '/');
            byte[] hash = hmac.ComputeHash(Convert.FromBase64String(key));

            return $"{key}{Convert.ToBase64String(hash, 0, 3)}";

        }
    }
}
*/