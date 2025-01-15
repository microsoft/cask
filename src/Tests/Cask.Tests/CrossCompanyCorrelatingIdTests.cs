// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Cryptography;
using System.Text;

using Xunit;

namespace CommonAnnotatedSecurityKeys.Tests;

public class CrossCompanyCorrelatingIdTests
{
    [Theory]
    [InlineData("Hello world", "C3IDnw4dY6uIibYownZw")]
    [InlineData("😁", "C3IDF8FaWr4yMPcwOOxM")]
    [InlineData("y_-KPF3BQb2-VHZeqrp28c6dgiL9y7H9TRJmQ5jJe9OvJQQJTESTBAU4AAB5mIhC", "C3IDKx9aukbRgOnPEyeu")]
    [InlineData("Kq03wDtdCGWvs3sPgbH84H5MDADIJMZEERRhUN73CaGBJQQJTESTBAU4AADqe9ge", "C3IDO93RBPyuaA6ZRK8+")]
    public void C3Id_Basic(string text, string expected)
    {
        string actual = ComputeC3Id(text);
        Assert.Equal(expected, actual);
    }

    [Fact]
    public void C3Id_LargeText()
    {
        string actual = ComputeC3Id(text: new string('x', 300));
        Assert.Equal("C3IDs+pSKJ1FmRW+7EZk", actual);
    }

    [Fact]
    public void C3Id_Null_Throws()
    {
        Assert.Throws<ArgumentNullException>("text", () => CrossCompanyCorrelatingId.Compute(null!));
    }

    [Fact]
    public void C3Id_Empty_Throws()
    {
        Assert.Throws<ArgumentException>("text", () => CrossCompanyCorrelatingId.Compute(""));
    }

    [Fact]
    public void C3Id_EmptyRaw_Throws()
    {
        byte[] destination = new byte[CrossCompanyCorrelatingId.RawSizeInBytes];
        Assert.Throws<ArgumentException>("text", () => CrossCompanyCorrelatingId.ComputeRaw("", destination));
    }

    [Fact]
    public void C3Id_EmptyRawSpan_Throws()
    {
        byte[] destination = new byte[CrossCompanyCorrelatingId.RawSizeInBytes];
        Assert.Throws<ArgumentException>("text", () => CrossCompanyCorrelatingId.ComputeRaw([], destination));
    }

    [Fact]
    public void C3Id_EmptyRawUtf8_Throws()
    {
        byte[] destination = new byte[CrossCompanyCorrelatingId.RawSizeInBytes];
        Assert.Throws<ArgumentException>("textUtf8", () => CrossCompanyCorrelatingId.ComputeRawUtf8([], destination));
    }

    [Fact]
    public void C3Id_DestinationTooSmall_Throws()
    {
        byte[] destination = new byte[CrossCompanyCorrelatingId.RawSizeInBytes - 1];
        Assert.Throws<ArgumentException>(
            "destination",
            () => CrossCompanyCorrelatingId.ComputeRaw("test", destination));
    }

    [Fact]
    public void C3Id_DestinationTooSmallUtf8_Throws()
    {
        byte[] destination = new byte[CrossCompanyCorrelatingId.RawSizeInBytes - 1];
        Assert.Throws<ArgumentException>(
            "destination",
            () => CrossCompanyCorrelatingId.ComputeRawUtf8("test"u8, destination));
    }

    private static string ComputeC3Id(string text)
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
    /// A trivial reference implementation of C3ID that is easy to understand,
    /// but not optimized for performance. We compare this to the production
    /// implementation to ensure that it remains equivalent to this.
    /// </summary>
    private static class ReferenceCrossCompanyCorrelatingId
    {
        public static string Compute(string text)
        {
            // Compute the SHA-256 hash of the UTF8-encoded text
            Span<byte> hash = SHA256.HashData(Encoding.UTF8.GetBytes(text));

            // Prefix the result with "C3ID" UTF-8 bytes and hash again
            hash = SHA256.HashData([.. "C3ID"u8, .. hash]);

            // Truncate to 12 bytes
            hash = hash[..12];

            // Convert to base64 and prepend "C3ID"
            return "C3ID" + Convert.ToBase64String(hash);
        }
    }
}
