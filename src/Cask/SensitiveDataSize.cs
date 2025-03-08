// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace CommonAnnotatedSecurityKeys;

/// <summary>
/// The CASK-specific, general key kind. This kind value is distinct
/// from the separate, provider-specific, provider-defined key kind.
/// </summary>
public enum SensitiveDataSize
{
    None = 0,

    /// <summary>
    /// Specifies a computed value with one 16-byte
    /// (128 bit) segment of entropy.
    /// </summary>
    Bits128 = 1, // Base64: index 1 == 'B'

    /// <summary>
    /// Specifies a computed value with two 16-byte
    /// segments of entropy, comprising 256 bits
    /// </summary>
    Bits256 = 2, // Base64: index 2 == 'C'

    /// <summary>
    /// Specifies a computed value with three 16-byte
    /// segments of entropy, comprising 384 bits
    /// </summary>
    Bits384 = 3, // Base64: index 3 == 'D'

    /// <summary>
    /// Specifies a computed value with four 16-byte
    /// segments of entropy, comprising 512 bits
    /// </summary>
    Bits512 = 4, // Base64: index 4 == 'E'
}
