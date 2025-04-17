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
    /// The maximum length of provider-reserved data, if any, when decoded to bytes (12 bytes).
    /// </summary>
    public static int MaxProviderDataLengthInBytes { get; } = 30;

    /// <summary>
    /// The maximum length of provider-reserved data, if any, when base64-encoded (16 characters).
    /// </summary>
    public static int MaxProviderDataLengthInChars { get; } = BytesToBase64Chars(MaxProviderDataLengthInBytes);

    /// <summary>
    /// The minimum length in bytes of a key that contains a 256-bit sensitive data component (60 bytes).
    /// </summary>
    public static int Min256BitKeyLengthInBytes { get; } = GetKeyLengthInBytes(0, SecretSize.Bits256);

    /// <summary>
    /// The maximum length in bytes of a key that contains a 256-bit sensitive data component (72 bytes).
    /// </summary>
    public static int Max256BitKeyLengthInBytes { get; } = GetKeyLengthInBytes(MaxProviderDataLengthInBytes, SecretSize.Bits256);

    /// <summary>
    /// The minimum length in bytes of a key that contains a 512-bit sensitive data component (93 bytes).
    /// </summary>
    public static int Min512BitKeyLengthInBytes { get; } = GetKeyLengthInBytes(0, SecretSize.Bits512);

    /// <summary>
    /// The maximum length of a 512-bit Cask key in its canonical base64-encoded form.
    /// </summary>
    public static int Min512BitKeyLengthInChars { get; } = BytesToBase64Chars(Min512BitKeyLengthInBytes);

    /// <summary>
    /// The maximum length in bytes of a key that contains a 512-bit sensitive data component 105 bytes).
    /// </summary>
    public static int Max512BitKeyLengthInBytes { get; } = GetKeyLengthInBytes(MaxProviderDataLengthInBytes, SecretSize.Bits512);

    /// <summary>
    /// The minimum length in bytes of a Cask secret when decoded to bytes (45 bytes).
    /// </summary>
    public static int MinKeyLengthInBytes { get; } = Min256BitKeyLengthInBytes;

    /// <summary>
    /// The minimum length of a Cask secret in its canonical base64-encoded form.
    /// </summary>
    public static int MinKeyLengthInChars { get; } = BytesToBase64Chars(MinKeyLengthInBytes);

    /// <summary>
    /// The maximum length of a Cask secret when decoded to bytes (105 bytes).
    /// </summary>
    public static int MaxKeyLengthInBytes { get; } = Max512BitKeyLengthInBytes;

    /// <summary>
    /// The maximum length of a Cask secret in its canonical base64-encoded form.
    /// </summary>
    public static int MaxKeyLengthInChars { get; } = BytesToBase64Chars(MaxKeyLengthInBytes);
}
