#include "helpers.h"

int32_t RoundUpTo3ByteAlignment(int32_t bytes)
{
    return RoundUpToMultipleOf(bytes, 3);
}

int32_t RoundUpToMultipleOf(int32_t value, int32_t multiple)
{
    return (value + multiple - 1) / multiple * multiple;
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
