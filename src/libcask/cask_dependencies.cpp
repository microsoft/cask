// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

// WIP: This is our reference implementation for dependencies. We can pull in
//      external libraries of our choice here and only here. We can use C++
//      here.

#include "cask_dependencies.h"

using namespace std;
using namespace Cask;

#include <vector>
#include <string>
#include <span>
#include <cstdint>
#include <algorithm>
#include <iterator>

using namespace std;

static const char base64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                   "abcdefghijklmnopqrstuvwxyz"
                                   "0123456789-_";

string Base64UrlEncode(const span<uint8_t>& bytes)
{
    string encoded;
    int val = 0, valb = -6;
    for (uint8_t c : bytes) {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            encoded.push_back(base64_chars[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6) encoded.push_back(base64_chars[((val << 8) >> (valb + 8)) & 0x3F]);
    while (encoded.size() % 4) encoded.push_back('=');
    replace(encoded.begin(), encoded.end(), '+', '-');
    replace(encoded.begin(), encoded.end(), '/', '_');
    encoded.erase(remove(encoded.begin(), encoded.end(), '='), encoded.end());
    return encoded;
}

int32_t ComputeCrc32(const span<uint8_t>& bytes)
{
    return 0;
}
