// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

// WIP: This header wil define the interop-friendly libcask API that will be
//      exported from .dll/.so. This surface area must remain C compatible and
//      cannot use C++-only types and features

#ifndef CASK_H
#define CASK_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
#define CASK_EXTERN_C extern "C"
#else
#define CASK_EXTERN_C
#endif

#ifdef LIBCASK_EXPORTS
#define CASK_API CASK_EXTERN_C __declspec(dllexport)
#else
#define CASK_API CASK_EXTERN_C __declspec(dllimport)
#endif

CASK_API bool Cask_IsCask(const char* keyOrHash);

CASK_API bool Cask_IsCaskBytes(const uint8_t* keyOrHashBytes,
                               int32_t length);

CASK_API int32_t Cask_GenerateKey(const char* providerSignature,
                                  const char* providerData,
                                  char* buffer,
                                  int32_t bufferSize);

CASK_API int32_t Cask_GenerateHash(const uint8_t* derivationInputBytes,
                                   int32_t derivationInputLength,
                                   const char* secret,
                                   char* buffer,
                                   int32_t bufferSize);

CASK_API bool Cask_CompareHash(const char* candidateHash,
                               const uint8_t* derivationInputBytes,
                               int32_t derivationInputLength,
                               const char* secret);

#endif // CASK_H
