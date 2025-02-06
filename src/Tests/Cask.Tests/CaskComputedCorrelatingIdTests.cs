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
        // This is a detail test simply to process an explicit value that
        // may be useful to note in the specification. There are actually
        // two reference implementations of C3ID computation in play, one
        // provided by the 'ComputeC3Id' method in this test class, and
        // two-liner below that simply hashes a prefixed string.
        string test = nameof(test);
        string actual = ComputeC3Id(text: test);
        string expected = "C3IDnG/kvvNePwLu3YsnIvr1";

        Assert.Equal(expected, actual);

        string input = $"CaskComputedCorrelatingId{test}";
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
        string reference = ReferenceCrossCompanyCorrelatingId.Compute(text);
        string actual = CaskComputedCorrelatingId.Compute(text);

        Assert.True(
            actual == reference,
            $"""
            Actual implementation did not match reference implementation for '{text}'.

              reference: {reference}
                 actual: {actual}
            """);

        return actual;
    }

    // ...

    private static class ReferenceCrossCompanyCorrelatingId
    {
        public static string Compute(string text)
        {
            // Compute the SHA-256 hash of the UTF8-encoded text
            Span<byte> input = Encoding.UTF8.GetBytes(text);

            // Prefix the result with "C3ID" UTF-8 bytes and hash again
            byte[] hash = SHA256.HashData([.. "CaskComputedCorrelatingId"u8, .. input]);

            // Truncate to 15 bytes
            hash = hash.Take(15).ToArray();

            // Convert to base64 and prepend "C3ID"
            return "C3ID" + Convert.ToBase64String(hash);
        }
    }
}
