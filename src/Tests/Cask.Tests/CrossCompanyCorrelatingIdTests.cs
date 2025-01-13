// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Cryptography;
using System.Text;

using Xunit;

namespace CommonAnnotatedSecurityKeys.Tests;

public class CrossCompanyCorrelatingIdTests
{
    [Theory]
    [InlineData("Hello world", "C3ID9xeTAR1ewMzk9axi")]
    [InlineData("😁", "C3IDrASY+FVWgFfMcvcw")]
    [InlineData("y_-KPF3BQb2-VHZeqrp28c6dgiL9y7H9TRJmQ5jJe9OvJQQJTESTBAU4AAB5mIhC", "C3IDNucDCyn9NEm713r5")]
    [InlineData("Kq03wDtdCGWvs3sPgbH84H5MDADIJMZEERRhUN73CaGBJQQJTESTBAU4AADqe9ge", "C3IDHW9XUFlW+lHLTNFU")]
    public void C3ID_Basic(string text, string expected)
    {
        string actual = ComputeC3ID(text);
        Assert.Equal(expected, actual);
    }

    [Fact]
    public void C3ID_LargeText()
    {
        string actual = ComputeC3ID(text: new string('x', 300));
        Assert.Equal("C3IDuGJvUr8Loa+4dgYT", actual);
    }

    [Fact]
    public void C3ID_Null_Throws()
    {
        Assert.Throws<ArgumentNullException>("text", () => CrossCompanyCorrelatingId.Compute(null!));
    }

    public static readonly TheoryData<string> EmptyOrAsciiWhitespace =
    [
        "",
        " ",
        "    ",
        " \t\r\n\u000B\u000C ",
    ];

    [Theory]
    [MemberData(nameof(EmptyOrAsciiWhitespace))]
    public void C3ID_EmptyOrAsciiWhitespace_Throws(string text)
    {
        Assert.Throws<ArgumentException>(nameof(text), () => CrossCompanyCorrelatingId.Compute(text));
    }

    [Theory]
    [MemberData(nameof(EmptyOrAsciiWhitespace))]
    public void C3ID_EmptyOrAsciiWhitespaceRaw_Throws(string text)
    {
        char[] input = text.ToCharArray();
        byte[] destination = new byte[CrossCompanyCorrelatingId.RawSizeInBytes];
        Assert.Throws<ArgumentException>(nameof(text), () => CrossCompanyCorrelatingId.ComputeRaw(input, destination));
    }

    [Theory]
    [MemberData(nameof(EmptyOrAsciiWhitespace))]
    public void C3ID_EmptyOrAsciiWhitespaceRawUtf8_Throws(string text)
    {
        byte[] input = Encoding.UTF8.GetBytes(text);
        byte[] destination = new byte[CrossCompanyCorrelatingId.RawSizeInBytes];
        Assert.Throws<ArgumentException>(nameof(text), () => CrossCompanyCorrelatingId.ComputeRawUtf8(input, destination));
    }

    [Fact]
    public void C3ID_DestinationTooSmall_Throws()
    {
        byte[] destination = new byte[CrossCompanyCorrelatingId.RawSizeInBytes - 1];
        Assert.Throws<ArgumentException>(
            "destination",
            () => CrossCompanyCorrelatingId.ComputeRaw("test", destination));
    }

    [Fact]
    public void C3ID_DestinationTooSmallUtf8_Throws()
    {
        byte[] destination = new byte[CrossCompanyCorrelatingId.RawSizeInBytes - 1];
        Assert.Throws<ArgumentException>(
            "destination",
            () => CrossCompanyCorrelatingId.ComputeRawUtf8("test"u8, destination));
    }

    private static string ComputeC3ID(string text)
    {
        string reference = ReferenceCrossCompanyCorrelatingId.Compute(text);
        string actual = CrossCompanyCorrelatingId.Compute(text);

        Assert.True(
            actual == reference,
            $"""
            Actual implementation did not match reference implementation for '{text}'.

              reference: {reference}
                 actual: {actual}
            """);

        return actual;
    }

    /// <summary>
    /// A trival reference implementation of C3ID that is easy to understand,
    /// but not optimized for performance. We compare this to the production
    /// implementation to ensure that it remains equivalent to this.
    /// </summary>
    private static class ReferenceCrossCompanyCorrelatingId
    {
        private static readonly byte[] s_prefix = Convert.FromBase64String("C3ID");

        public static string Compute(string text)
        {
            // Compute the SHA-256 hash of the UTF8-encoded text
            Span<byte> hash = SHA256.HashData(Encoding.UTF8.GetBytes(text));

            // Prefix the result and hash again
            hash = SHA256.HashData([.. s_prefix, .. hash]);

            // Truncate to 12 bytes
            hash = hash[..12];

            // Prefix the result and convert to base64
            return Convert.ToBase64String([.. s_prefix, .. hash]);
        }
    }
}
