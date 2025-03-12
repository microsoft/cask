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
    /// The number of bytes for the non-sensitive, unique correlating id of the secret.
    /// </summary>
    public const int CorrelatingIdSizeInBytes = 15;

    /// <summary>
    /// The number of bytes for time-of-allocation (year, month, day, hour, minute),
    /// the size of the sensitive component, the size of optional data, and the
    /// provider-defined key kind.
    /// </summary>
    public const int TimestampSizesAndProviderKindInBytes = 6;

    /// <summary>
    /// The number of bytes in the fixed components of a primary key,
    /// from the CASK signature to the end of the key.
    /// </summary>
    public const int FixedKeyComponentSizeInBytes = CaskSignatureSizeInBytes +
                                                    TimestampSizesAndProviderKindInBytes +
                                                    ProviderSignatureSizeInBytes +
                                                    CorrelatingIdSizeInBytes;

    /// <summary>
    /// The maximum amount of bytes that the implementation will stackalloc.
    /// </summary>
    public const int MaxStackAlloc = 256;

    /// <summary>
    /// The range of chars in a base64-encoded key that hold the Cask signature.
    /// </summary>
    public static Range CaskSignatureCharRange => 44..48;

    /// <summary>
    /// The integer offset of the sensitive data size relative to the
    /// Cask signature in a base64-encoded secret.
    /// </summary>
    public static int SecretSizeOffsetFromCaskSignatureChar => 5;
}
