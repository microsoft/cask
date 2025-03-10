global using static CommonAnnotatedSecurityKeys.InternalConstants;

using System.Security.Cryptography;

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
    /// The number of bytes reserved in the key footer for future use.
    /// </summary>
    public const int VersionAndKindSizeInBytes = 2;

    /// <summary>
    /// The number of bytes for the general CASK and provider-specific key kinds.
    /// </summary>
    public const int CaskAndProviderKeyKindSizeInBytes = 2;

    /// <summary>
    /// The number of bytes for the non-sensitive, unique correlating id of the secret.
    /// </summary>
    public const int CorrelatingIdSizeInBytes = 16;

    /// <summary>
    /// The number of bytes for time-of-allocation and validity lifetime of the secret.
    /// </summary>
    public const int TimestampAndExpirySizeInBytes = 6;

    /// <summary>
    /// The number of bytes in the fixed components of a primary key,
    /// from the CASK signature to the end of the key.
    /// </summary>
    public const int FixedKeyComponentSizeInBytes = CaskSignatureSizeInBytes +
                                                    ProviderSignatureSizeInBytes +
                                                    CaskAndProviderKeyKindSizeInBytes +
                                                    CorrelatingIdSizeInBytes +
                                                    TimestampAndExpirySizeInBytes;

    /// <summary>
    /// The number of bytes of entropy in a primary key. 32-bytes (256 bits) of
    /// entropy generated by a cryptographically secure RNG are currently deemed
    /// unbreakable even in a post-quantum world. 
    /// 
    /// Currently this value is fixed, but may become configurable in future versions.
    /// </summary>
    public const int SecretEntropyInBytes = 32;

    /// <summary>
    /// The size of the entropy in a primary after padding to 3-byte alignment.
    /// </summary>
    public static int PaddedSecretEntropyInBytes { get; } = RoundUpTo3ByteAlignment(SecretEntropyInBytes);

    /// <summary>
    /// The maximum amount of bytes that the implementation will stackalloc.
    /// </summary>
    public const int MaxStackAlloc = 256;

    /// <summary>
    /// The number of least significant bits reserved in the key kind byte.
    /// </summary>
    public const int CaskKindReservedBits = 4;

    /// <summary>
    /// The number of least significant bits reserved in the sensitive key kind byte.
    /// </summary>
    public const int SensitiveDataSizeReservedBits = 6;

    /// <summary>
    /// The number of least significant bits reserved in the provider key kind byte.
    /// </summary>
    public const int ProviderKindReservedBits = 2;

    /// <summary>
    /// A bit mask to obtain the reserved bits from the key kind.
    /// </summary>
    public const int CaskKindReservedMask = (1 << CaskKindReservedBits) - 1;

    /// <summary>
    /// A bit mask to obtain the reserved bits from the key kind.
    /// </summary>
    public const int SensitiveDataReservedMask = (1 << SensitiveDataSizeReservedBits) - 1;

    /// <summary>
    /// The index of the byte in a key that contains the key size.
    /// </summary>
    public static Index SensitiveDataSizeByteIndex => 32;

    /// <summary>
    /// The index of the byte in a key that contains the key size.
    /// </summary>
    public static Index SensitiveDataSizeCharIndex => 43;

    /// <summary>
    /// The range of byte indices in a key for the bytes that contain the CASK signature.
    /// </summary>
    public static Range CaskSignatureByteRange => 33..36;

    /// <summary>
    /// The range of byte indices in a key for the bytes that contain the provider signature.
    /// </summary>
    public static Range ProviderSignatureByteRange => 36..39;

    /// <summary>
    /// The index of the byte in a key that contains the key kind.
    /// </summary>
    public static Index ProviderKindByteIndex => 39;

    /// <summary>
    /// The index of the byte in a key that contains the key kind.
    /// </summary>
    public static Index CaskKindByteIndex => 40;

    /// <summary>
    /// The range of byte indices in a hash for the bytes that contain
    /// the non-sensitive, unique id of the generated secret.
    /// </summary>
    public static Range CorrelatingIdByteRange => 41..57;

    /// <summary>
    /// The range of byte indices in a key for the bytes that contain
    /// the year, month, hour, and day of the time of secret allocation.
    /// </summary>
    public static Range YearMonthHoursDaysTimestampByteRange => 57..60;

    /// <summary>
    /// The range of byte indices in a key for the bytes that contain the
    /// the 6-bit minute component of the time of secret allocation,
    /// followed by the 18-bit secret expiry.
    /// </summary>
    public static Range MinutesAndExpiryByteRange => 60..63;

    /// <summary>
    /// The range of byte indices in a key that, if present,
    /// comprise additional provider-specific data.
    /// </summary>
    public static Range OptionalDataByteRange => 63..;

    /// <summary>
    /// The range of chars in a base64-encoded key that hold the Cask signature.
    /// </summary>
    public static Range CaskSignatureCharRange => 44..48;

    /// <summary>
    /// The range of chars in a base64-encoded key that hold the timestamp.
    /// </summary>
    public static Range TimestampCharRange => 76..81;

    /// <summary>
    /// The range of chars in a base64-encoded key that hold the expiry.
    /// </summary>
    public static Range ExpiryCharRange => 81..84;

    /// <summary>
    /// The index of the provider-specific kind char in a base64-encoded key.
    /// </summary>
    public static Index ProviderKindCharIndex => 52;

    /// <summary>
    /// The index of the CASK kind char in a base64-encoded key.
    /// </summary>
    public static Index CaskKindCharIndex => 53;
}
