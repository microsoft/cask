#pragma once

// WIP: This header will define a facade over all dependencies that libcask has
//      that are not provided by the C++ standard library. Our reference
//      implementation will choose external depenencies to implement this.
//      Someone can then take the reference source implementation and
//      replace/edit cask_dependencies.cpp. We can use C++ here.

#include <cstdint>
#include <string>
#include <span>

using namespace std;

namespace Cask {

string Base64UrlEncode(const span<uint8_t>& bytes);
int32_t ComputeCrc32(const span<uint8_t>& bytes);

} // namespace Cask
