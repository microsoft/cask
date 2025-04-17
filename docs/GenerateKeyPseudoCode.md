# GenerateKey Pseudo-Code

*NOTE*: all references to `base64url` in this document refer to the 'printable' (i.e., exclusive of the `=` padding character) base64url alphabet as defined in [RFC 4648](https://datatracker.ietf.org/doc/html/rfc4648#section-5).`

## Inputs:
- Provider signature: string
- Provider key kind: char
- Provider data: string
- Secret data size: int

## Outputs:
- Generated key: string

## Computation
1. Validate input. Return an error if any of the following are NOT true:
    - Provider signature is exactly 4 characters long.
    - Provider signature consists entirely of printable (non-padding) characters that are valid in base64url encoding.
    - Provider key kind is a single base64url character.
    - Provider data (if non-empty) has a length that is a multiple of 4 characters and no more than 12 characters.
    - Provider data (if non-empty) consists entirely of base64url characters.
    - Secret data size is between 1 (a single 16-byte segment of sensitive data = 128 bits) and 4 (four 16-byte segments = 512 bits).
1. Let N = the length of the base64url-decoded provider data.
    - Number of characters in provider data divided by 4, times 3.
1. Compute the sensitive data size in bytes:
    - Multiply the secret data size by 32 to generate a secret size in bytes.
    - If the secret size in bytes is not a multiple of 3, round this value up, i.e., (secret size in bytes + 3 - 1) / 3 * 3.
    - The final padded sensitive data size will be one of 33 or 66 bytes.
1. Allocate storage for the generated key:
    - 33 or 66 bytes bytes for the sensitive data component.
    - 3 bytes for CASK signature.
    - 3 bytes for reserved zero padding, sensitive and optional size designations, and provider key kind.
    - 3 bytes for provider signature.
    - N bytes for provider data. Guaranteed to be a multiple of 3 by input validation.
    - 6 bytes for the reserved zero padding and the time-of-allocation timestamp.
1. Generate cryptographically secure random bytes as specified by the secret size computation. Store the result at the beginning of the generated key.
1. Clear any unused bytes in the sensitive component and the padding bytes that bring alignment to a 3-byte boundary.
1. Write CASK signature [0x40, 0x92, 0x50] ("QJJQ", base64-decoded) to the next 3 bytes.
1. Encode reserved zero padding, secret and optional data sizes, and provider kind in 4 characters, ZSOK:
    - Z = base64url-encoding of 0, 'A'.
    - S = base64url-encoding of secret data size, 'B' (256 bits) or 'C' (512 bits).
    - O = base64url-encoding of optional data size, a count of 3-byte segments, one of 'A' (0 segments) - 'K' (10 segments).
    - K = provider key kind, the base64url printable char specified by the caller.
1. Base64url-decode ZSOK and store the result in the next 3 bytes.
1. Base64url-decode provider signature and store the result in the next 3 bytes.
1. Write provider data bytes, if any.
1. Retrieve the current date and time in UTC and store the result in T.
1. Encode zero padding, zero padding, the year, and month of T in 4 characters, ZZYM:
    - Z = base64url-encoding of 0, 'A'.
    - Z = base64url-encoding of 0, 'A'..
    - Y = base64url-encoding of T.Year - 2025.
    - M = base64url-encoding of T.Month as a zero-based value, 0 - 11.
1. Base64url-decode ZZYM and store the result in the next 3 bytes.
1. Encode the timestamp day, hour, minutes, and seconds in 4 characters, DHMS:
    - D = base64url-encoding of T.Day as a zero-based value, i.e., 0 - 30.
    - H = base64url-encoding of T.Hour as zero-based value, i.e., 0 - 23.
    - M = base64url-encoding of T.Minutes as a zero-based value, i.e., 0 - 59.
    - M = base64url-encoding of T.Seconds as a zero-based value, i.e., 0 - 59.
1. Base64url-decode DHMS and store the result in the next 3 bytes.
1. Encode the resulting bytes as a base64url string and return it.

## References
- Base64url: https://datatracker.ietf.org/doc/html/rfc4648#section-5
