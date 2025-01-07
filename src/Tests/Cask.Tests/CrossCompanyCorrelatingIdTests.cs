// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Xunit;

namespace CommonAnnotatedSecurityKeys.Tests;

public class CrossCompanyCorrelatingIdTests
{
    [Theory]
    [InlineData("", "EZ3GxRsKq+Dp21GvyCpQ")]
    [InlineData("Hello world", "R8ogeP7QfTFvL5qAATry")]
    [InlineData("😁", "f/BTV0j6A8km4KDw7aJz")]
    public void Test_Basic(string text, string expected)
    {
        string actual = ComputeC3IDBase64(company: "Microsoft", text);
        Assert.Equal(expected, actual);
    }

    [Fact]
    public void Test_LargeText()
    {
        string actual = ComputeC3IDBase64(company: "Microsoft", text: new string('x', 300));
        Assert.Equal("QjHXB4Bu8voB3eJcJagI", actual);
    }

    [Fact]
    public void Test_LargeCompany()
    {
        string actual = ComputeC3IDBase64(company: new string('x', 300), text: "test");
        Assert.Equal("rG1CONo8M3lcBqzxyIpf", actual);
    }

    private static string ComputeC3IDBase64(string company, string text)
    {
        byte[] bytes = new byte[CrossCompanyCorrelatingId.SizeInBytes];
        CrossCompanyCorrelatingId.Compute(company, text, bytes);
        return Convert.ToBase64String(bytes);
    }
}
