// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

global using static CommonAnnotatedSecurityKeys.Limits;

namespace CommonAnnotatedSecurityKeys;

/*
 * VERSIONING: Use properties, not `const` for anything publicly visible so that they
 * do not get embedded into caller assemblies.
 *
 * PERF: Do not change `{ get; } = ComputeConstant(...)` to `=> ComputeConstant(...);` as
 * it's possible that the JIT will not discover that the computation yields a constant on
 * every invocation, but it will treat static readonly fields as constants.
 */

public static class Limits
{
    /// <summary>
    /// The maximum length of provider-reserved data, if any, when decoded to bytes.
    /// </summary>
    public static int MaxProviderDataLengthInBytes { get; } = 12;

    /// <summary>
    /// The maximum length of provider-reserved data, if any, when base64-encoded.
    /// </summary>
    public static int MaxProviderDataLengthInChars { get; } = BytesToBase64Chars(MaxProviderDataLengthInBytes);

    /// <summary>
    /// The minimum length of a Cask secret when decoded to bytes.
    /// </summary>
    public static int MinKeyLengthInBytes { get; } = GetKeyLengthInBytes(0, SensitiveDataSize.Bits128);

    /// <summary>
    /// The maximum length of a Cask secret when decoded to bytes.
    /// </summary>
    public static int MaxKeyLengthInBytes { get; } = GetKeyLengthInBytes(MaxProviderDataLengthInBytes, SensitiveDataSize.Bits512);

    /// <summary>
    /// The minimum length of a Cask secret in its canonical textual form (i.e., when base64-encoded).
    /// </summary>
    public static int MinKeyLengthInChars { get; } = BytesToBase64Chars(MinKeyLengthInBytes);

    /// <summary>
    /// The maximum length of a Cask secret in its canonical textual form (i.e., when base64-encoded).
    /// </summary>
    public static int MaxKeyLengthInChars { get; } = BytesToBase64Chars(MaxKeyLengthInBytes);
}
