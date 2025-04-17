global using static CommonAnnotatedSecurityKeys.InternalConstants;

namespace CommonAnnotatedSecurityKeys;

/// <summary>
/// Constants which are currently internal to the implementation.
/// </summary>
/// <remarks>
/// Move things elsewhere if/when they need to be made public, and avoid `const` in 
/// public API in favor of static readonly properties.
/// </remarks>
internal static partial class InternalConstants
{
    /// <summary>
    /// The base64-encoded CASK signature "QJJQ" in UTF-16.)
    /// </summary>
    public static ReadOnlySpan<char> CaskSignature => "QJJQ".AsSpan();

    /// <summary>
    /// The base64-encoded CASK signature "QJJQ" in UTF-8.
    /// </summary>
    public static ReadOnlySpan<byte> CaskSignatureUtf8 => "QJJQ"u8;

    /// <summary>
    /// The base64-decoded CASK signature "QJJQ" in bytes.
    /// </summary>
    public static ReadOnlySpan<byte> CaskSignatureBytes => [0x40, 0x92, 0x50];

    /// <summary>
    /// The number of bytes in a CASK signature
    /// </summary>
    public const int CaskSignatureSizeInBytes = 3;

    /// <summary>
    /// The number of bytes in a provider signature.
    /// </summary>
    public const int ProviderSignatureSizeInBytes = 3;

    /// <summary>
    /// The number of bytes per secret size chunk.
    /// </summary>
    public const int SecretChunkSizeInBytes = 32;

    /// <summary>
    /// The number of bytes per optional data size chunk.
    /// </summary>
    public const int OptionalDataChunkSizeInBytes = 3;

    /// <summary>
    /// The number of bytes required to express 6 bits of padding followed by
    /// the secret size, the optional provider data size, and provider key kind.
    /// </summary>
    public const int PaddingSizesAndProviderKindInBytes = 3;

    /// <summary>
    /// The number of base64 characters required to express 6 bits of padding
    /// followed by the secret size, the optional provider data size, and
    /// provider key kind.
    /// </summary>
    public static readonly int PaddingSizesAndProviderKindInChars = BytesToBase64Chars(PaddingSizesAndProviderKindInBytes);

    /// <summary>
    /// The number of bytes required to express 12 bits of padding followed by
    /// the secret time-of-allocation (year, month, day, hour, minute, second).
    /// </summary>
    public const int PaddingAndTimestampSizeInBytes = 6;

    /// <summary>
    /// The number of base64 characters required to express 12 bits of padding
    /// followed by the secret time-of-allocation (year, month, day, hour,
    /// minute, second).
    /// </summary>
    public static readonly int PaddingAndTimestampSizeInChars = BytesToBase64Chars(PaddingAndTimestampSizeInBytes);

    /// <summary>
    /// The number of bytes in the fixed components of a primary key, from the
    /// CASK signature to the end of the key.
    /// </summary>
    public const int FixedKeyComponentSizeInBytes = CaskSignatureSizeInBytes +
                                                    PaddingSizesAndProviderKindInBytes +
                                                    ProviderSignatureSizeInBytes +
                                                    PaddingAndTimestampSizeInBytes;

    /// <summary>
    /// The maximum amount of bytes that the implementation will stackalloc.
    /// </summary>
    public const int MaxStackAlloc = 256;
}
