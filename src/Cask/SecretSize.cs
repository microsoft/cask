// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace CommonAnnotatedSecurityKeys;

/// <summary>
/// The size of the literal secret saved to the sensitive data component of a
/// CASK secret. This data may be padded with additional bytes to make it 3-byte
/// aligned. The enum values below comprise a count of 32-byte segments of the
/// secret data and and are also equivalent to the base64url-encoded index of
/// the value's printable character.
/// </summary>
public enum SecretSize
{
    None = 0,

    /// <summary>
    /// Specifies a computed value with one 32-byte (256 bit) segment of
    /// sensitive data.
    /// </summary>
    Bits256 = 1, // Base64: index 1 == 'B'.

    /// <summary>
    /// Specifies a computed value with two 16-byte segments of sensitive data,
    /// comprising 512 bits
    /// </summary>
    Bits512 = 2, // Base64: index 2 == 'C'.
}
