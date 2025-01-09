// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Cryptography;
using System.Text;

using static CommonAnnotatedSecurityKeys.Limits;

namespace CommonAnnotatedSecurityKeys;

/// <summary>
/// Cross-Company Correlating Id (C3ID) a 12-byte value used to correlate a
/// high-entropy keys with other data. The canonical textual representation is
/// base64 encoded and prefixed with "C3ID".
/// </summary>
public static class CrossCompanyCorrelatingId
{
    /// <summary>
    /// The size of a Cross-Company Correlating ID (aka C3ID) in raw bytes.
    /// </summary>
    public const int RawSizeInBytes = 12;

    private static ReadOnlySpan<byte> Prefix => "C3ID"u8;
    private static ReadOnlySpan<byte> PrefixBase64Decoded => [0x0B, 0x72, 0x03];

    /// <summary>
    /// Computes the C3ID for the given text in canonical textual form.
    /// </summary>
    public static string Compute(string text)
    {
        ThrowIfNull(text);

        Span<byte> bytes = stackalloc byte[PrefixBase64Decoded.Length + RawSizeInBytes];
        PrefixBase64Decoded.CopyTo(bytes);
        Compute(text, bytes[PrefixBase64Decoded.Length..]);
        return Convert.ToBase64String(bytes);
    }

    /// <summary>
    /// Computes the raw C3ID bytes for the given text and writes them to the
    /// destination span.
    /// </summary>
    public static void Compute(string text, Span<byte> destination)
    {
        ThrowIfNull(text);
        Compute(text.AsSpan(), destination);
    }

    /// <summary>
    /// Computes the raw C3ID bytes for the given UTF-16 encoded text sequence
    /// and writes them to the destination span.
    /// </summary>
    public static void Compute(ReadOnlySpan<char> text, Span<byte> destination)
    {
        ThrowIfDestinationTooSmall(destination, RawSizeInBytes);

        int byteCount = Encoding.UTF8.GetByteCount(text);
        Span<byte> textUtf8 = byteCount <= MaxStackAlloc ? stackalloc byte[byteCount] : new byte[byteCount];
        Encoding.UTF8.GetBytes(text, textUtf8);
        ComputeUtf8(textUtf8, destination);
    }

    /// <summary>
    /// Computes the raw C3ID bytes for the given UTF-8 encoded text sequence
    /// and writes them to the destination span.
    /// </summary>>
    public static void ComputeUtf8(ReadOnlySpan<byte> textUtf8, Span<byte> destination)
    {
        ThrowIfDestinationTooSmall(destination, RawSizeInBytes);

        // Produce input for second hash: "C3ID"u8 + SHA256(text)
        Span<byte> input = stackalloc byte[Prefix.Length + SHA256.HashSizeInBytes];
        Prefix.CopyTo(input);
        SHA256.HashData(textUtf8, input[Prefix.Length..]);

        // Perform second hash, truncate, and copy to destination.
        Span<byte> sha = stackalloc byte[SHA256.HashSizeInBytes];
        SHA256.HashData(input, sha);
        sha[..RawSizeInBytes].CopyTo(destination);
    }
}

