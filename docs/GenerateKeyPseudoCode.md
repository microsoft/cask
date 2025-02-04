# GenerateKey Pseudo-Code

## Inputs:
- Provider signature: string
- Provider data: string (optional)

## Outputs:
- Generated key: string

## Computation
1. Validate input. Return an error if any of the following are NOT true:
    - Provider signature is exactly 4 characters long.
    - Provider signature consists entirely of characters that are valid in base64url encoding.
    - Provider data (if any) has a length that is a multiple of 4 characters and no more than 32 characters.
    - Provider data (if any) consists entirely of characters that are valid in base64url encoding.
1. Let N = the length of the base64url-decoded provider data.
    - Number of characters in provider data divided by 4, times 3.
1. Allocate storage for the generated key:
    - 32 bytes for entropy.
    - 1 padding byte.
    - N bytes for provider data. (Guaranteed to be a multiple of 3 by input validation.)
    - 3 bytes for CASK signature.
    - 3 bytes for provider signature.
    - 3 bytes for timestamp.
    - 1 reserved byte
    - 1 byte for size and kind
    - 4 bytes for CRC32 checksum
1. Generate 256 bits of cryptographically secure random data. Store the result at the beginning of the generated key.
1. Write 0x00 to the next byte (padding to maintain 3-byte alignment).
1. base64url decode provider data and store the result in the next N bytes.
1. Write CASK signature [0x25, 0x04, 0x09] ("JQQJ", base64-decoded) to the next 3 bytes.
1. base64url decode provider signature and store the result in the next 3 bytes.
1. Let T = current date and time in UTC.
1. Encode T in 4 characters, YMDH:
    - Y = base64url encoding of (Year - 2024).
    - M = base64url encoding of zero-based month.
    - D = base64url encoding of zero-based hour.
    - H = base64url encoding of zero-based day.
1. base64url-decode YMDH and store the result in the next 3 bytes.
1. Write 0x00 to the next byte (reserved).
1. Write 0x00 to the next byte to indicate a 256-bit primary key.
1. Compute the CRC32 of all key bytes written above (everything but the last 4 bytes). Store the result in little-endian byte order in the last 4 bytes.
1. base64url encode the generated key and return the result.

## References
- base64url: https://datatracker.ietf.org/doc/html/rfc4648#section-5
