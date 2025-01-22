#pragma once

#include <stdint.h>

const std::string Base64UrlChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

int32_t RoundUpTo3ByteAlignment(int32_t value);

int32_t BytesToBase64Chars(int32_t bytes);

int32_t GetKeyLengthInBytes(int secretEntropyInBytes, int providerDataLengthInBytes);

int32_t Base64CharsToBytes(int32_t chars);

bool Is3ByteAligned(int32_t byteLength);

bool Is4CharAligned(int32_t charLength);

bool IsValidForBase64Url(const char* value);
