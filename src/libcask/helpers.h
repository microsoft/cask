#pragma once

#include <stdint.h>

int32_t RoundUpTo3ByteAlignment(int32_t value);

bool IsValidForBase64Url(const char* value);
