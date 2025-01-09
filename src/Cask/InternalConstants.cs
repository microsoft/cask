global using static CommonAnnotatedSecurityKeys.InternalConstants;

namespace CommonAnnotatedSecurityKeys;

/// <summary>
/// Constants which are currently internal to the implementation.
/// </summary>
/// <remarks>
/// Move things elsewhere if/when they need to be made public, and avoid `const` in 
/// public API in favor of static readonly properties.
/// </remarks>
internal static class InternalConstants
{
    public static ReadOnlySpan<char> CaskSignature => "JQQJ".AsSpan();
    public static ReadOnlySpan<byte> CaskSignatureUtf8 => "JQQJ"u8;

    /// <summary>
    /// The bytes that make up the CASK signature. "JQQJ", base64-decoded.
    /// </summary>
    public static ReadOnlySpan<byte> CaskSignatureBytes => [0x25, 0x04, 0x09];

    /// <summary>
    /// Current version of CASK spec that we implement.
    /// </summary>
    public const int CaskVersion = 0;

    /// <summary>
    /// The number of bytes in a CASK signature
    /// </summary>
    public const int CaskSignatureSizeInBytes = 3;

    /// <summary>
    /// The number of bytes used to store the timestamp in a key.
    /// </summary>
    public const int TimestampSizeInBytes = 3;

    /// <summary>
    /// The number of bytes  the provider signature.
    /// </summary>
    public const int ProviderSignatureSizeInBytes = 3;

    /// <summary>
    /// The nubmer of bytes reserved in the key footer for future use.
    /// </summary>
    public const int VersionAndKindSizeInBytes = 2;

    /// <summary>
    /// The number of bytes for the CRC32 of the key.
    /// </summary>
    public const int Crc32SizeInBytes = 4;

    /// <summary>
    /// The number of bytes in the fixed components of a primary key, from the CASK signature to the end of the key.
    /// </summary>
    public const int FixedKeyComponentSizeInBytes =
        CaskSignatureSizeInBytes +
        ProviderSignatureSizeInBytes +
        TimestampSizeInBytes +
        VersionAndKindSizeInBytes +
        Crc32SizeInBytes;

    /// <summary>
    /// The number of bytes in the fixed componet of a hash key, from the C3ID to the end of the key.
    /// </summary>
    public const int FixedHashComponentSizeInBytes = FixedKeyComponentSizeInBytes + CrossCompanyCorrelatingId.RawSizeInBytes;

    /// <summary>
    /// The number of bytes of entropy in a primary key.
    /// Currently fixed, but may become configurable in future versions.
    /// </summary>
    public const int SecretEntropyInBytes = 32;

    /// <summary>
    /// The size of the entropy in a primary after padding to 3-byte alignment.
    /// </summary>
    public const int PaddedSecretEntropyInBytes = 33;

    /// <summary>
    /// The size of the HMAC-SHA256 hash after padding to 3-byte alignment.
    /// </summary>
    public const int PaddedHmacSha256SizeInBytes = 33;

    /// <summary>
    /// The maximum amount of bytes that the implementation will stackalloc.
    /// </summary>
    public const int MaxStackAlloc = 256;

    /// <summary>
    /// The range of byte indices in a key for the bytes that contain the CASK signature.
    /// </summary>
    public static Range CaskSignatureByteRange => ^15..^12;

    /// <summary>
    /// The range of byte indices in a key for the bytes that contain the provider signature.
    /// </summary>
    public static Range ProviderSignatureByteRange => ^12..^9;

    /// <summary>
    /// The range of byte indices in a key for the bytes that contain the timestamp.
    /// </summary>
    public static Range TimestampByteRange => ^9..^6;

    /// <summary>
    /// The index of the byte in a key that contains the key kind.
    /// </summary>
    public static Index KindByteIndex = ^6;

    /// <summary>
    /// The index of the byte in a key that contains the CASK version.
    /// </summary>
    public static Index VersionByteIndex => ^5;
    /// <summary>
    /// The range of byte indices in a key for the bytes that contain the CRC32 of the key.
    /// </summary>
    public static Range Crc32ByteRange => ^4..;

    /// <summary>
    /// The range of byte indices in a hash for the bytes that contain the C3ID of the secret.
    /// </summary>
    public static Range C3IdByteRange => ^27..^15;

    /// <summary>
    /// The number of least significant bits reserved in the version byte.
    /// </summary>
    public const int VersionReservedBits = 4;

    /// <summary>
    /// A bit mask to obtain the reserved bits from the version byte
    /// </summary>
    public const int VersionReservedMask = (1 << VersionReservedBits) - 1;

    /// <summary>
    /// The number of least significant bits reserved in the key kind
    /// </summary>
    public const int KindReservedBits = 2;

    /// <summary>
    /// A bit mask to obtain the reserved bits from the key kind.
    /// </summary>
    public const int KindReservedMask = (1 << KindReservedBits) - 1;

    /// <summary>
    /// The range of chars in a base64-encoded key that hold the Cask signature.
    /// </summary>
    public static Range CaskSignatureCharRange = ^20..^16;

    /// <summary>
    /// The index of the kind char in a base64-encoded key.
    /// </summary>
    public static Index KindCharIndex => ^8;

    /// <summary>
    /// The index of the version char in a base64-encoded key.
    /// </summary>
    public static Index VersionCharIndex => ^7;
}
