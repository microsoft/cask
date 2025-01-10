// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

// WIP: This file implements the interop-friendly libcask API
//      The implementation can use C++.

#include <string>
#include <vector>
#include <cassert>
#include <ctime>
#include <random>
#include <span>
#include <algorithm>

#include "cask.h"
#include "cask_dependencies.h"
#include "helpers.h"

/// <summary>
/// The maximum length of provider-reserved data when base64-encoded.
/// </summary>
const int32_t MaxProviderDataLengthInBytes = RoundUpTo3ByteAlignment(24);

/// <summary>
/// The maximum length of provider-reserved data when base64-encoded.
/// </summary>
const int32_t MaxProviderDataLengthInChars = BytesToBase64Chars(MaxProviderDataLengthInBytes);

/// <summary>
/// The minimum number of bytes of entropy that must be used to generate a key.
/// </summary>
const int32_t MinSecretEntropyInBytes = RoundUpTo3ByteAlignment(16);

/// <summary>
/// The maximum number of bytes of entropy that can be used to generate a key
/// </summary>
const int32_t MaxSecretEntropyInBytes = RoundUpTo3ByteAlignment(64);

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
                                  int32_t secretEntropyInBytes = 32,
                                  char* output,
                                  int32_t outputSizeInBytes)
{
    auto GetKeyLengthInBytes = [](int secretEntropy, int providerDataLength) {
        return secretEntropy + providerDataLength + 12;
    };

    auto FillRandom = [](std::span<uint8_t> buffer) {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 255);
        std::generate(buffer.begin(), buffer.end(), [&]() { return dis(gen); });
    };

    auto GetUtcNow = []() {
        return std::time(nullptr);
    };

    auto ComputeChecksum = [](std::span<const uint8_t> keyBytes, std::span<uint8_t> checksumDestination) {
        assert(checksumDestination.size() == 3);
        std::vector<uint8_t> crc32(4);
        Crc32::Hash(keyBytes.subspan(0, keyBytes.size() - 3), crc32);
        std::copy(crc32.begin(), crc32.begin() + 3, checksumDestination.begin());
    };

    secretEntropyInBytes = RoundUpTo3ByteAlignment(secretEntropyInBytes);

    ValidateProviderSignature(providerSignature);
    ValidateAllocatorCode(allocatorCode);
    ValidateProviderData(providerData);
    ValidateSecretEntropy(secretEntropyInBytes);

    int providerDataLengthInBytes = Base64Url::CharsToBytes(providerData.length());
    int keyLengthInBytes = GetKeyLengthInBytes(secretEntropyInBytes, providerDataLengthInBytes);

    assert(keyLengthInBytes <= 64);
    std::vector<uint8_t> keyBytes(keyLengthInBytes);

    std::span<uint8_t> destination = keyBytes;

    FillRandom(destination.subspan(0, secretEntropyInBytes));
    destination = destination.subspan(secretEntropyInBytes);

    int bytesWritten = Base64Url::DecodeFromChars(providerData, destination);
    assert(bytesWritten == providerDataLengthInBytes);
    destination = destination.subspan(providerDataLengthInBytes);

    destination[0] = 0x25;
    destination[1] = 0x04;
    destination[2] = 0x09;
    destination = destination.subspan(3);

    std::time_t now = GetUtcNow();
    std::tm* now_tm = std::gmtime(&now);
    int year = now_tm->tm_year + 1900;
    int month = now_tm->tm_mon + 1;

    if (year < 2024 || year > 2087) {
        throw std::invalid_argument("CASK requires the current year to be between 2024 and 2087.");
    }

    std::string allocatorAndTimestamp = {
        allocatorCode[0],
        allocatorCode[1],
        Base64Url::Chars[year - 2024],
        Base64Url::Chars[month - 1]
    };

    bytesWritten = Base64Url::DecodeFromChars(allocatorAndTimestamp, destination);
    assert(bytesWritten == 3);
    destination = destination.subspan(3);

    bytesWritten = Base64Url::DecodeFromChars(providerSignature, destination);
    assert(bytesWritten == 3);
    destination = destination.subspan(3);

    ComputeChecksum(keyBytes, destination);

    std::copy(keyBytes.begin(), keyBytes.end(), output);

    return keyLengthInBytes;
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

void ValidateProviderSignature (const char* providerSignature) 
{
    if (providerSignature == nullptr)
    {
        throw std::invalid_argument("Provider signature must not be null.");
    }

    if (std::strlen(providerSignature) != 4) {
        throw std::invalid_argument("Provider signature must be 4 characters long.");
    }

    if (!IsValidForBase64Url(providerSignature))
    {
        throw std::invalid_argument("Provider signature must be a valid URL-safe Base64 string.");
    }
}

void ValidateAllocatorCode (const char* allocatorCode) 
{
    if (allocatorCode == nullptr) 
    {
        throw std::invalid_argument("Allocator code must not be null.");
    }

    if (std::strlen(allocatorCode) != 2) {
        throw std::invalid_argument("Allocator code must be 2 characters long.");
    }
    
    if (!IsValidForBase64Url(allocatorCode))
    {
        throw std::invalid_argument("Allocator code must be a valid URL-safe Base64 string.");
    }
}

void ValidateProviderData(const char* providerData)
{
    if (providerData == nullptr)
    {
        throw std::invalid_argument("Provider data must not be null.");
    }

    size_t providerDataLength = std::strlen(providerData);

    if (providerDataLength > MaxProviderDataLengthInChars)
    {
        throw std::invalid_argument("Provider data must be at most " + std::to_string(MaxProviderDataLengthInChars) + " characters: '" + std::to_string(providerDataLength) + "'.");
    }

    if (!Is4CharAligned(providerDataLength))
    {
        throw std::invalid_argument("Provider data length must be a multiple of 4: " + std::to_string(providerDataLength));
    }

    if (!IsValidForBase64Url(providerData))
    {
        throw std::invalid_argument("Provider data must be a valid URL-safe Base64 string.");
    }
}

void ValidateSecretEntropy(int32_t secretEntropyInBytes)
{
    if (secretEntropyInBytes < MinSecretEntropyInBytes || secretEntropyInBytes > MaxSecretEntropyInBytes)
    {
        throw std::invalid_argument("Secret entropy must be between " + std::to_string(MinSecretEntropyInBytes) + " and " + std::to_string(MaxSecretEntropyInBytes) + " bytes.");
    }
}



