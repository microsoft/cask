// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Cryptography;
using System.Text;

using Xunit;

namespace CommonAnnotatedSecurityKeys.Tests;

public class CaskComputedCorrelatingIdTests
{
    [Theory]
    [InlineData("😁", "C3ID2k7uBmRvHOP6/XHGOE/2")]
    [InlineData("test", "C3IDnG/kvvNePwLu3YsnIvr1")]
    [InlineData("Hello world", "C3IDQlNeQD4fELogjySvjevQ")]
    [InlineData("y_-KPF3BQb2-VHZeqrp28c6dgiL9y7H9TRJmQ5jJe9OvJQQJTESTBAU4AAB5mIhC", "C3IDcyw3MgLExGerWHtTY3b9")]
    [InlineData("Kq03wDtdCGWvs3sPgbH84H5MDADIJMZEERRhUN73CaGBJQQJTESTBAU4AADqe9ge", "C3IDztTI/1mfJBoDgrHolgj0")]
    public void C3Id_Basic(string text, string expected)
    {
        string actual = ComputeC3Id(text);
        Assert.Equal(expected, actual);
    }

    [Fact]
    public void C3Id_Test()
    {
        string test = nameof(test);
        string actual = ComputeC3Id(text: test);
        string expected = "C3IDnG/kvvNePwLu3YsnIvr1";
        Assert.Equal(expected, actual);

        // This simple implementation of the C3ID computation
        // shows the layout of the hashed input, i.e., the
        // standard prefix 'CaskComputedCorrelatingId' followed
        // by the UTF8-encoded text to hash, 'test'.
        string input = "CaskComputedCorrelatingIdtest";
        byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes(input));
        Assert.Equal(expected, $"C3ID{Convert.ToBase64String(hash)[..20]}");
    }

    [Fact]
    public void C3Id_LargeText()
    {
        string actual = ComputeC3Id(text: new string('x', 300));
        Assert.Equal("C3IDSa9GXyMk8rporJr/nB1t", actual);
    }

    [Fact]
    public void C3Id_HugeText()
    {
        // This string size exceeds stack allocation limits.
        string actual = ComputeC3Id(text: new string('x', 5 * 1024 * 1000));
        Assert.Equal("C3IDZ667VxU1F+rFRLrccJGS", actual);
    }

    [Fact]
    public void C3Id_Null_Throws()
    {
        Assert.Throws<ArgumentNullException>("text", () => CaskComputedCorrelatingId.Compute(null!));
    }

    [Fact]
    public void C3Id_Empty_Throws()
    {
        Assert.Throws<ArgumentException>("text", () => CaskComputedCorrelatingId.Compute(""));
    }

    [Fact]
    public void C3Id_EmptyRaw_Throws()
    {
        byte[] destination = new byte[CaskComputedCorrelatingId.RawSizeInBytes];
        Assert.Throws<ArgumentException>("text", () => CaskComputedCorrelatingId.ComputeRaw("", destination));
    }

    [Fact]
    public void C3Id_EmptyRawSpan_Throws()
    {
        byte[] destination = new byte[CaskComputedCorrelatingId.RawSizeInBytes];
        Assert.Throws<ArgumentException>("text", () => CaskComputedCorrelatingId.ComputeRaw([], destination));
    }

    [Fact]
    public void C3Id_EmptyRawUtf8_Throws()
    {
        byte[] destination = new byte[CaskComputedCorrelatingId.RawSizeInBytes];
        Assert.Throws<ArgumentException>("textUtf8", () => CaskComputedCorrelatingId.ComputeRawUtf8([], destination));
    }

    [Fact]
    public void C3Id_DestinationTooSmall_Throws()
    {
        byte[] destination = new byte[CaskComputedCorrelatingId.RawSizeInBytes - 1];
        Assert.Throws<ArgumentException>(
            "destination",
            () => CaskComputedCorrelatingId.ComputeRaw("test", destination));
    }

    [Fact]
    public void C3Id_DestinationTooSmallUtf8_Throws()
    {
        byte[] destination = new byte[CaskComputedCorrelatingId.RawSizeInBytes - 1];
        Assert.Throws<ArgumentException>(
            "destination",
            () => CaskComputedCorrelatingId.ComputeRawUtf8("test"u8, destination));
    }

    private static string ComputeC3Id(string text)
    {
        string reference = ReferenceCaskComputedCorrelatingId.Compute(text);
        string actual = CaskComputedCorrelatingId.Compute(text);

        Assert.True(
            actual == reference,
            $"""
            Actual implementation did not match reference implementation for UTF16 '{text}'.

              reference: {reference}
                 actual: {actual}
            """);

        byte[] textUtf8 = Encoding.UTF8.GetBytes(text);
        actual = CaskComputedCorrelatingId.ComputeUtf8(textUtf8);

        Assert.True(
            actual == reference,
            $"""
            Actual implementation did not match reference implementation for UTF8 '{text}'.

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
    private static class ReferenceCaskComputedCorrelatingId
    {
        public static string Compute(string text)
        {
            // UTF8-encode the input.
            Span<byte> input = Encoding.UTF8.GetBytes(text);

            // Prefix the result with "CaskComputedCorrelatingId" UTF-8 bytes and hash again.
            Span<byte> hash = SHA256.HashData([.. "CaskComputedCorrelatingId"u8, .. input]);

            // Truncate to 15 bytes.
            hash = hash[..15];

            // Convert to base64 and prepend "C3ID"
            return "C3ID" + Convert.ToBase64String(hash);
        }
    }
}
