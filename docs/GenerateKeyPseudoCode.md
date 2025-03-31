# GenerateKey Pseudo-Code

*NOTE*: all references to `base64url` in this document refer to the 'printable' (i.e., exclusive of the padding or `=` character) base64url alphabet characters as defined in [RFC 4648](https://datatracker.ietf.org/doc/html/rfc4648#section-5).`

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
    - Provider key kind is a single, printable base64url character.
    - Provider data (if non-empty) has a length that is a multiple of 4 characters and no more than 12 characters.
    - Provider data (if non-empty) consists entirely of base64url printable characters.
    - Secret data size is between 1 (a single 16-byte segment of sensitive data = 128 bits) and 4 (four 16-byte segments = 512 bits).
1. Let N = the length of the base64url-decoded provider data.
    - Number of characters in provider data divided by 4, times 3.
1. Compute the sensitive data size in bytes:
    - Multiply the secret data size by 16 to generate a secret size in bytes.
    - If the secret size in bytes is not a multiple of 3, round this value up, i.e., (secret size in bytes + 3 - 1) / 3 * 3.
    - The final padded sensitive data size will be one of 18, 33, 48, or 66 bytes.
1. Allocate storage for the generated key:
    - 18, 33, 48, or 66 bytes bytes for the sensitive data component.
    - 3 bytes for CASK signature.
    - 6 bytes for the timestamp, sensitive and optional size designations, and provider key kind.
    - N bytes for provider data. (Guaranteed to be a multiple of 3 by input validation.)
    - 3 bytes for provider signature.
    - 15 bytes for the non-sensitive correlating id.
1. Generate cryptographically secure random bytes as specified by the secret size computation. Store the result at the beginning of the generated key.
1. Clear the padding bytes, if any, that follow the secret and which bring alignment to a 3-byte boundary.
1. Write CASK signature [0x40, 0x92, 0x50] ("QJJQ", base64-decoded) to the next 3 bytes.
1. Retrieve the current date and time in UTC and store the result in T.
1. Encode the secret and optional data sizes, year, and month of T in 4 characters, SOYM:
    - S = base64url-encoding of secret data size, one of 1 (128 bits), 2 (256), 3 (384), or 4 (512).
    - O = base64url-encoding of optional data size, a count of 3-byte segments, one of 0 - 4.
    - Y = base64url-encoding of T.Year - 2025.
    - M = base64url-encoding of T.Month as a zero-based value, 0 - 11.
1. Base64url-decode SOYM and store the result in the next 3 bytes.
1. Encode the timestamp day, hour and minutes, and provider key kind in 4 characters, DHMK:
    - D = base64url-encoding of T.Day as a zero-based value, i.e., 0 - 30.
    - H = base64url-encoding of T.Hour as zero-based value, i.e., 0 - 23.
    - M = base64url-encoding of T.Minutes as a zero-based value, i.e., 0 - 59.
    - K = provider key kind, i.e., the exact base64url printable char specified by the caller.
1. Base64url-decode MSOK and store the result in the next 3 bytes.
1. Base64url-decode provider signature and store the result in the next 3 bytes.
1. Generate 120 bits of cryptographically secure random data and store the result in the next 15 bytes.

## References
- Base64url: https://datatracker.ietf.org/doc/html/rfc4648#section-5
