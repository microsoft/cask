// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace CommonAnnotatedSecurityKeys;

/// <summary>
/// The CASK-specific, general key kind. This kind value is distinct
/// from the separate, provider-specific, provider-defined key kind.
/// </summary>
public enum SensitiveDataSize
{
    /// <summary>
    /// Specifies a computed value with 256 bits of data
    /// (32 bytes) comprising random bytes or a SHA-256 hash.
    /// </summary>
    Bits256 = ('A' - 'A'), // Base64: index 0 == 'A'

    /// <summary>
    /// Specifies a computed value with 384 bits of data
    /// (48 bytes) comprising random bytes or a SHA-384 hash.
    /// </summary>
    Bits384 = ('B' - 'A'), // Base64: index 0 == 'B'

    /// <summary>
    /// Specifies a computed value with 512 bits of data
    /// (64 bytes) comprising random bytes or a SHA-384 hash.
    /// </summary>
    Bits512 = ('C' - 'A'), // Base64: index 0 == 'V'
}
