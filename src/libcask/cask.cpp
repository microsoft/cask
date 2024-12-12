// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

// WIP: This file implements the interop-friendly libcask API
//      The implementation can use C++.

#include <string.h>

#include "cask.h"
#include "cask_dependencies.h"

CASK_API bool Cask_IsCask(const char* keyOrHash)
{
    return false;
}

CASK_API bool Cask_IsCaskBytes(const uint8_t* keyOrHashBytes,
                               int32_t length)
{
     return false; 
}

CASK_API int32_t Cask_GenerateKey(const char* allocatorCode,
                                  const char* providerSignature,
                                  const char* providerData,
                                  int32_t secretEntropyInBytes,
                                  char* output,
                                  int32_t outputSizeInBytes)
{
    // WIP: Demonstrating a calling pattern for caller to be able to ask for
    //      buffer size. We can mimic this in GenerateHash. This is always a
    //      challenge for C API and I'm open to other approaches.

    const char* key = "not_a_real_key";
    int32_t requiredSizeInBytes = int32_t(strlen(key) + 1); // +1 for null terminator

    if (output == nullptr)
    {
        // no buffer: return the minimum size of the buffer needed to succeed.
        // caller can then allocate a buffer of that size and call again.
        return requiredSizeInBytes;
    }

    if (outputSizeInBytes < requiredSizeInBytes)
    {
        // buffer is too small: return 0
        return 0;
    }

    // buffer is big enough: write to buffer and return the number of bytes written
    strncpy_s(output, outputSizeInBytes, key, requiredSizeInBytes);
    return requiredSizeInBytes;
}

CASK_API int32_t Cask_GenerateHash(const uint8_t* derivationInputBytes,
                                   const int32_t derivationInputLength,
                                   const char* secret,
                                   int32_t secretEntropyInBytes,
                                   char* buffer,
                                   int32_t bufferSize)
{
    return 0;
}

CASK_API bool Cask_CompareHash(const char* candidateHash,
                               const uint8_t* derivationInputBytes,
                               const int32_t derivationInputLength,
                               const char* secret,
                               int32_t secretEntropyInBytes)
{
    return false;
}

