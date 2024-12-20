// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace CommonAnnotatedSecurityKeys;

/*
 * VERSIONING: These are all constant, but we don't want to embed them in caller
 * assemblies so we don't use `const`. The JIT will still inline the trivial
 * properties and turn the static readonly field reads into constants so there
 * is no performance impact in release builds.
 *
 * PERF: Do not change `{ get; }` to `=> value;`. That choice is not purely
 * style and it's possible that the JIT will not discover that the computation
 * yields a constant value if it's invoked on every property access.
 */

public static class Limits
{
    /// <summary>
    /// The minimum number of bytes of entropy that must be used to generate a key.
    /// </summary>
    public static int MinSecretEntropyInBytes { get; } = RoundUpTo3ByteAlignment(16);

    /// <summary>
    /// The maximum number of bytes of entropy that can be used to generate a key
    /// </summary>
    public static int MaxSecretEntropyInBytes { get; } = RoundUpTo3ByteAlignment(64);

    /// <summary>
    /// The maximum length of provider-reserved data when base64-encoded.
    /// </summary>
    public static int MaxProviderDataLengthInBytes { get; } = RoundUpTo3ByteAlignment(24);

    /// <summary>
    /// The maximum length of provider-reserved data when base64-encoded.
    /// </summary>
    public static int MaxProviderDataLengthInChars { get; } = BytesToBase64Chars(MaxProviderDataLengthInBytes);

    /// <summary>
    /// The minimum length of a Cask key when decoded to bytes.
    /// </summary>
    public static int MinKeyLengthInBytes { get; } = GetKeyLengthInBytes(MinSecretEntropyInBytes, 0);

    /// <summary>
    /// The maximum length of a Cask key when decoded to bytes.
    /// </summary>
    public static int MaxKeyLengthInBytes { get; } = GetKeyLengthInBytes(MaxSecretEntropyInBytes, MaxProviderDataLengthInBytes);

    /// <summary>
    /// The minimum length of a Cask key in characters.
    /// </summary>
    public static int MinKeyLengthInChars { get; } = BytesToBase64Chars(MinKeyLengthInBytes);

    /// <summary>
    /// The maximum length of a Cask key in characters.
    /// </summary>
    public static int MaxKeyLengthInChars { get; } = BytesToBase64Chars(MaxKeyLengthInBytes);

    /// <summary>
    /// The maximum amount of bytes that the implementation will stackalloc.
    /// </summary>
    /// <remarks>
    /// Internal and constant because it is an implementation detail. All byte
    /// limits must be less than or equal to this so that the implementation can
    /// stackalloc unconditionally.
    /// </remarks>
    internal const int MaxStackAlloc = 256;
}
