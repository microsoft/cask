# GenerateHash Pseudo-code

## Inputs:
- Secret: string
- Derivation input: string or bytes

## Outputs
- CASK hash: string

## Computation
1. Examine the provided secret to determine if it is a valid CASK primary key. If it is not, return an error.
1. Let N = number of bytes in the provider data of the CASK secret.
    - N may be 0 if there is no provider data in the CASK primary key.
    - N must be a multiple of 3. Otherwise, the CASK primary key is invalid and an error should have been returned above.
1. Allocate storage for the CASK hash:
    - 33 bytes for padded HMACSHA256 or 48 bytes for HMACSHA384.
    - N bytes for provider data. (Guaranteed to be a multiple of 3 by input validation.)
    - 15 bytes for C3ID.
    - 3 bytes for CASK signature.
    - 3 bytes for provider signature.
    - 3 bytes for timestamp.
    - 1 reserved byte.
    - 1 byte for size and kind.
    - 4 bytes for CRC32 checksum.
1. If the derivation input was provided as a string, UTF-8 encode it to obtain bytes.
1. Compute HMACSHA256 or HMACSHA384 using the CASK secret as the key and the derivation input bytes as the message. Store the result at the beginning of the CASK hash.
1. If using HMACSHA256, write 0x00 to the next byte (padding to maintain 3-byte alignment).
1. Copy provider data from the CASK secret to the next N bytes.
1. Compute C3ID of the CASK secret. Store the result in the next 15 bytes.
1. Write the CASK signature [0x25, 0x04, 0x09] ("JQQJ", base64-decoded) to the next 3 bytes.
1. Copy the provider signature from the CASK secret to the next 3 bytes.
1. Let T = current date and time in UTC.
1. Encode T in 4 characters, YMDH:
    - Y = base64url encoding of (Year - 2024).
    - M = base64url encoding of zero-based month.
    - D = base64url encoding of zero-based hour.
    - H = base64url encoding of zero-based day.
1. base64url-decode YMDH and store the result in the next 3 bytes.
1. Write 0x00 to the next byte (reserved).
1. Write 0x1C to indicate HMACSHA256 or 0x20 to indicate HMACSHA384 to the next byte.
1. Compute the CRC32 of all CASK hash bytes written above (everything but last 4 bytes). Store the result in little-endian byte order in the last 4 bytes.
1. base64url encode the CASK hash and return the result.

## References
- base64url: https://datatracker.ietf.org/doc/html/rfc4648#section-5
