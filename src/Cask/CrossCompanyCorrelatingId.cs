// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;

using static CommonAnnotatedSecurityKeys.Limits;

namespace CommonAnnotatedSecurityKeys;

internal static class CrossCompanyCorrelatingId
{
    /// <summary>
    /// The size of a Cross-Company Correlating ID (aka C3ID) in bytes.
    /// </summary>
    public const int SizeInBytes = 15;

    private static ReadOnlySpan<byte> CompanyPrefix => "Cross"u8;
    private static ReadOnlySpan<byte> CompanySuffix => "CorrelatingId:"u8;
    private static ReadOnlySpan<byte> Hex => "0123456789ABCDEF"u8;
    private const int HexCharsPerByte = 2;

    /// <summary>
    /// Computes the Cross-Company Correlating Id (aka C3ID) bytes for the given
    /// company and text and writes them to the destination span.
    /// </summary>
    public static void Compute(string company, string text, Span<byte> destination)
    {
        Debug.Assert(destination.Length >= SizeInBytes);

        // Input: $"Cross{company}CorrelatingId:{SHA256Hex(text))}" encoded in UTF-8 
        int companyByteCount = Encoding.UTF8.GetByteCount(company);
        int inputByteCount =
            CompanyPrefix.Length +
            companyByteCount +
            CompanySuffix.Length +
            (SHA256.HashSizeInBytes * HexCharsPerByte);

        Span<byte> input = inputByteCount <= MaxStackAlloc ? stackalloc byte[inputByteCount] : new byte[inputByteCount];
        Span<byte> inputDestination = input;

        // 'Cross'
        CompanyPrefix.CopyTo(inputDestination);
        inputDestination = inputDestination[CompanyPrefix.Length..];

        // {company}
        Encoding.UTF8.GetBytes(company.AsSpan(), inputDestination);
        inputDestination = inputDestination[companyByteCount..];

        // 'CorrelatingId:'
        CompanySuffix.CopyTo(inputDestination);
        inputDestination = inputDestination[CompanySuffix.Length..];

        // SHA256 hash of UTF-8 encoded text, converted to uppercase UTF-8 encoded hex
        Sha256Hex(text, inputDestination);

        // Compute second SHA256 of above input, truncate, and copy to destination
        Span<byte> sha = stackalloc byte[SHA256.HashSizeInBytes];
        SHA256.HashData(input, sha);
        sha[..SizeInBytes].CopyTo(destination);
    }

    /// <summary>
    /// Computes the SHA256 of the text encoded as UTF-8 and writes the result
    /// to the destination as UTF-8 encoded uppercase hex.
    /// </summary>
    private static void Sha256Hex(string text, Span<byte> destination)
    {
        Debug.Assert(destination.Length >= SHA256.HashSizeInBytes * HexCharsPerByte);

        int byteCount = Encoding.UTF8.GetByteCount(text);
        Span<byte> bytes = byteCount <= MaxStackAlloc ? stackalloc byte[byteCount] : new byte[byteCount];
        Encoding.UTF8.GetBytes(text.AsSpan(), bytes);

        Span<byte> sha = stackalloc byte[SHA256.HashSizeInBytes];
        SHA256.HashData(bytes, sha);
        ConvertToHex(sha, destination);
    }

    /// <summary>
    /// Converts bytes to UTF-8 encoded uppercase hex. Directly, without
    /// allocation or UTF-16 to UTF-8 conversion.
    /// </summary>
    private static void ConvertToHex(ReadOnlySpan<byte> bytes, Span<byte> destination)
    {
        Debug.Assert(destination.Length >= bytes.Length * HexCharsPerByte);

        for (int src = 0, dst = 0; src < bytes.Length; src++, dst += HexCharsPerByte)
        {
            byte b = bytes[src];
            destination[dst] = Hex[b >> 4];
            destination[dst + 1] = Hex[b & 0xF];
        }
    }
}
