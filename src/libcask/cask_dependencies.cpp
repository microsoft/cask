// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

// WIP: This is our reference implementation for dependencies. We can pull in
//      external libraries of our choice here and only here. We can use C++
//      here.

#include "cask_dependencies.h"

std::string Cask::Base64UrlEncode(const std::span<uint8_t>& bytes)
{
    return "";
}

int32_t Cask::ComputeCrc32(const std::span<uint8_t>& bytes)
{
    return 0;
}
