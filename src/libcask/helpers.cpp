#include <stdexcept>

#include "helpers.h"

int32_t RoundUpTo3ByteAlignment(int32_t bytes)
{
    return RoundUpToMultipleOf(bytes, 3);
}

int32_t RoundUpToMultipleOf(int32_t value, int32_t multiple)
{
    return (value + multiple - 1) / multiple * multiple;
}

int32_t GetKeyLengthInBytes(int secretEntropyInBytes, int providerDataLengthInBytes)
{
    if (!Is3ByteAligned(secretEntropyInBytes))
    {
        throw std::invalid_argument("secretEntropyInBytes should have been rounded up to 3-byte alignment already.");
    }
    
    if (!Is3ByteAligned(providerDataLengthInBytes))
    {
        throw std::invalid_argument("providerDataLengthInBytes should have been validated to 3-byte aligned already.");
    }

    return secretEntropyInBytes + providerDataLengthInBytes + FixedKeyComponentSizeInBytes;
}

bool IsValidForBase64Url(const char* value)
{
    if (value == nullptr) {
        return false;
    }

    while (*value != '\0') {
        if (!IsValidBase64UrlCharacter(*value)) {
            return false;
        }
        value++;
    }

    return true;
}

bool IsValidBase64UrlCharacter(char c)
{
    return (c >= 'A' && c <= 'Z') ||
        (c >= 'a' && c <= 'z') ||
        (c >= '0' && c <= '9') ||
        c == '-' || c == '_';
}

int32_t BytesToBase64Chars(int32_t bytes)
{
    return RoundUpTo3ByteAlignment(bytes) / 3 * 4;
}

bool Is4CharAligned(int32_t charLength)
{
    return charLength % 4 == 0;
}

bool Is3ByteAligned(int32_t byteLength)
{
    return byteLength % 3 == 0;
}

