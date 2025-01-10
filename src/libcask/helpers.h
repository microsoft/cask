#pragma once

#include <stdint.h>

int32_t RoundUpTo3ByteAlignment(int32_t value);

int32_t BytesToBase64Chars(int32_t bytes);

bool Is3ByteAligned(int32_t byteLength);

bool Is4CharAligned(int32_t charLength);

bool IsValidForBase64Url(const char* value);
