// Copyright (c) Microsoft. All rights reserved. Licensed under the MIT license.
// See LICENSE file in the project root for full license information.

namespace CommonAnnotatedSecurityKeys
{
    public interface ICask
    {
        ICaskUtilityApi Utilities { get; set; }

        bool IsCask(string keyOrHash);

        bool IsCask(byte[] keyOrHashBytes);

        string GenerateKey(string providerSignature,
                           string allocatorCode,
                           string? reserved = null,
                           int secretEntropyInBytes = 32);

        string GenerateHash(byte[] derivationInput,
                            byte[] secret,
                            int secretEntropyInBytes = 32);

        bool CompareHash(byte[] candidateHash,
                         byte[] derivationInput,
                         byte[] secret,
                         int secretEntropyInBytes = 32);
    }
}


