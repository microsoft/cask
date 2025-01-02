

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

#include "gtest/gtest.h"
#include <vector>

static TEST(CaskDependenciesTests, Base64UrlEncode_EmptyInput) {
    span<uint8_t> input = {};
    std::string expected = "";
    std::string result = Base64UrlEncode(input);
    EXPECT_EQ(result, expected);
}
