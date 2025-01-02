

#include "pch.h"
#include "../libcask/cask_dependencies.h"
#include <cstdint>
#include<span>
#include<string>

using namespace std;
using namespace Cask;

TEST(TestCaseName, TestName) {
  EXPECT_EQ(1, 1);
  EXPECT_TRUE(true);
}

static TEST(CaskDependenciesTests, Base64UrlEncode_EmptyInput) {
    span<uint8_t> input = {};
    string expected = "";
    string result = Base64UrlEncode(input);
    EXPECT_EQ(result, expected);
}
