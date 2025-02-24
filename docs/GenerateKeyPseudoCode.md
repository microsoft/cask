# GenerateKey Pseudo-Code

*NOTE*: all references to `base64url` in this document refer to the 'printable' (i.e., exclusive of the padding or `=` character) base64url alphabet characters as defined in [RFC 4648](https://datatracker.ietf.org/doc/html/rfc4648#section-5).`

## Inputs:
- Provider signature: string
- Provider key kind: string
- Key expiry expressed in five minutes increments: integer
- Provider data: string

## Outputs:
- Generated key: string

## Computation
1. Validate input. Return an error if any of the following are NOT true:
    - Provider signature is exactly 4 characters long.
    - Provider signature consists entirely of characters that are valid in base64url encoding.
    - Provider key kind is a single, printable (i.e., non-padding) base64url character.
    - Expiry in five minutes increments is a non-negative integer less than 262,144.
    - Provider data (if non-empty) has a length that is a multiple of 4 characters and no more than 32 characters.
    - Provider data (if non-empty) consists entirely of base64url printable characters.
1. Let N = the length of the base64url-decoded provider data.
    - Number of characters in provider data divided by 4, times 3.
1. Allocate storage for the generated key:
    - 32 bytes for entropy.
    - 1 byte for sensitive-data size.
    - 3 bytes for CASK signature.
    - 3 bytes for provider signature.
    - 1 byte for provider key kind
    - 1 byte for CASK key kind.
    - 16 bytes for the non-sensitive correlating id.
    - 3 bytes for year, month, day and hour of the allocation timestamp.
    - 3 bytes for minutes of the allocation timestamp and the 18-bit expiry.
1.  - N bytes for provider data. (Guaranteed to be a multiple of 3 by input validation.)

1. Generate 256 bits of cryptographically secure random data. Store the result at the beginning of the generated key.
1. Write sensitive data size to next byte, e.g., 0 to indicate 256-bits.
1. Write CASK signature [0x40, 0x92, 0x50] ("QJJQ", base64-decoded) to the next 3 bytes.
1. Base64url-decode provider signature and store the result in the next 3 bytes.
1. Write 0x00 to the next byte to indicate a CASK primary key kind.
1. Left-shift the provider key kind by 2 bits and store the result in the next byte.
1. Left-shift the CASK key key kind by 4 bits and store the result in the next byte.
1. Generate 128 bits of cryptographically secure random data and store the result in the next 16 bytes.
1. Let T = current date and time in UTC.
1. Encode T in 4 characters, YMDH:
    - Y = base64url-encoding of (Year - 2024).
    - M = base64url-encoding of zero-based month.
    - D = base64url-encoding of zero-based hour.
    - H = base64url-encoding of zero-based day.
1. Base64url-decode YMDH and store the result in the next 3 bytes.
1. Base64url-encode T minutes M in a single character
1. Encode the last 3 bytes of the big-endian representation of the 18-bit expiry.
1. Base64url-decode M and the 3-character expiry and store the result in the next 3 bytes.
1. Base64url-decode provider data and store the result in the next N bytes.

## References
- Base64url: https://datatracker.ietf.org/doc/html/rfc4648#section-5
