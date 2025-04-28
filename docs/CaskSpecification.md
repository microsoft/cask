# Common Annotated Security Key (CASK) Specification
**Status**: Draft
**Author(s)**: Michael C. Fanning, Ed.
**Date**: 2025-04-15  
**Version**: 0.1.0

---

## Table of Contents
0. [Abstract](#0-abstract)
1. [Motivation](#1-motivation)  
2. [Goals and Design Principles](#2-goals-and-design-principles)  
3. [Definitions](#1-definitions)  
4. [Specification](#1-specification)  
5. [Security Considerations](#1-security-considerations)  
6. [Examples](#1-examples)  
7. [References](#1-references)  

---
## 0. Abstract
`Common Annotated Security Key` (CASK) standardizes the formatting of sensitive data to drive efficient detection and rapid security remediation of secrets exposed in plaintext.

## 1. Motivation
CASK is a standard for encoding information in generated secrets that significantly improves the ability to manage secrets, prevent exposure, and remediate exposed secrets — without compromising the core security of the secret in its primary function of enabling access to an associated resource.

API keys and other secrets are often exposed as plaintext in source code, logs, and other artifacts, leading to costly mitigation efforts. Many secret providers generate patterns (e.g., 128-byte hexadecimal encodings) that are indistinguishable from non-sensitive data, making it difficult for scanners to prevent exposure or detect secrets in stored data. To address this, scanners must be tuned to minimize false positives (inaccurate findings that waste time) and false negatives (missed findings that pose actual risks). The primary goal of the CASK standard is to achieve perfect accuracy in detection, eliminating all false positives and false negatives. This means that all secrets will be found when present, and no reported findings will be mistakenly identified as secrets.

Using a secret store to manage secrets is a recommended security practice. Certain metadata for a secret (such as time-of-allocation or the associated cloud instance) is useful for enforcing other security policies (e.g., secret lifetime or segregating secrets to meet data isolation requirements). A secondary goal of CASK is to enable the encoding of such metadata into secrets, promoting better secrets hygiene. In practice, this encoded information is also valuable for security responders who handle reports of exposure.

## 2. Goals and Design Principles
The CASK specification applies to the generation, storage, and management of secrets in environments where sensitive data must be protected. It is intended for use by:
- Secret providers generating API keys, tokens, or other sensitive data.
- Security tools that detect and remediate exposed secrets.
- Secret stores that manage and safeguard sensitive information.

### Key Design Principles
- The primary CASK use case is to encode useful information in the textual representation of secrets while remaining convenient to generate or validate in a binary, byte-wise form.
- The readable, encoded data in CASK provides value for static consumption, i.e., consumers outside the standard workflow of validating a secret in an authorization context:
  - Scan tools that look for leaked secrets in data streams.
  - Secret stores that import, safeguard, manage, and present secrets.
  - Security engineers and remediation programs tasked with investigation and response of leaked secrets.
- Supplemental data encoded in CASK secrets *MUST NOT* be interpreted as part of an authorization workflow. A CASK secret *MUST* either be presented in its entirety (and treated as a black box) to drive an auth flow, *OR* a secret used to drive the scenario *MUST* be extracted from the CASK data.
- CASK requires minimal API support for key production and validation, viz. base64-encoding and decoding and API to generate the sensitive data component (e.g., a cryptographically secure RNG for generating randomized bytes).
- CASK does not define cryptographic algorithms or methods for generating or consuming sensitive data but provides a framework for encoding and managing such data.

## 3. Definitions
- **base64url**: An encoding format that represents 24-bit input groups as output strings of four encoded characters, restricted to a 65-character subset of US-ASCII. The base64url encoding is technically identical to base64, except for the 62nd and 63rd characters (replacing the plus character (`+) with minus (`-`) and the forward slash character (`/`) with underling (`_`). These adjustments allow for representing base64url data in URL and filenames with no escaping.

## 4. Specification
This section defines the structure of a CASK secret.

### Standard Backus-Naur Form (BNF)
```
<key> ::= <sensitive-data>      ; A sequence of security-sensitive bytes.
          <cask-signature>      ; A fixed signature (`QJJQ`) that anchors high-performance textual identification.
          <6-bits-reserved>     ; 6 bits of reserved (zero) padding.
          <sensitive-data-size> ; A count of 32-byte segments encoded as sensitive data, 'B' = 1 segment = 32 bytes, etc.
          <provider-data-size>  ; A count of 3-byte provider data segments, 'A' = 0 segments = 0 bytes, 'B' = 1 segment = 3 bytes, etc.
          <provider-kind>       ; A provider-defined key kind.
          <provider-signature>  ; A fixed signature that identifies the secret provider.
          [<provider-fields>]   ; Optional 3-byte segments of provider-defined data.
          <12-bits-reserved>    ; 12 bits of reserved (zero) padding.
          <timestamp>           ; The year, month, day, hour, minute, and second of secret allocation.
 
<sensitive-data> ::= <256-bits-padded>  | <512-bits-padded>                 ; The sensitive data is a secret generated for a security purpose,
                                                                            ; such as random data generated by a cryptographically secure random
                                                                            ; number generator (RNG), a Hash Message Authentication Code (HMAC),
                                                                            ; an output of a Key Derivation Function (KDF), etc. CASK specifies
                                                                            ; a storage location and component size for this data but does not
                                                                            ; specify a particular cryptographic algorithm or method for
                                                                            ; generating it. The size of this component must conform to the
                                                                            ; encoded <sensitive-data-size> value. A key producer is not required
                                                                            ; to fully populate the space reserved for the sensitive data (e.g. 
                                                                            ; a 512-bit CASK secret may store a 384 bit symmetric key). All unused
                                                                            ; space must be zero-initialized.
<256-bits-padded> ::= 42 * <base64url> <base64-two-zeros-suffix> 1 * <pad>  ; The total sensitive data comprises 256 bits encoded as 42 characters
                                                                            ; of 6 bits (252 bits) and 1 character providing 4 bits of sensitive
                                                                            ; data padded with 00b. The final character `A` comprises 6 bits of
                                                                            ; padding that brings the component to a 3-byte boundary.
<512-bits-padded> ::= 85 * <base64url> <base64-four-zeros-suffix> 2 * <pad> ; The total sensitive data comprises 512 bits encoded as 85
                                                                            ; characters x 6 bits (510 bits) and 1 character providing
                                                                            ; 2 bits of sensitive data padded with 0000b. The final 
                                                                            ; characters `AA` comprise 12 bits of additional padding
                                                                            ; that brings the component to a 3-byte boundary.
<pad> ::= 'A'                                                               ; An encoded 0 value that comprises padding in the format.
<base64url> ::= 'A'..'Z' | 'a'..'z' | '0'..'9' | '-' | '_'                  ; Base64 URL-safe printable characters. The '=' padding character is excluded.
<base64-two-zeros-suffix> ::= 'A' | 'E' | 'I' | 'M' | 'Q' | 'U' | 'Y' | 'c' ; Base64 printable characters with two trailing zero bits.
                            | 'g' | 'k' | 'o' | 's' | 'w' | '0' | '4' | '8' ;
<base64-four-zeros-suffix> ::= 'A' | 'Q' | 'g' | 'w'                        ; Base64 printable characters with four trailing zero bits.
<cask-signature> ::= 'QJJQ'                                                 ; Fixed signature identifying the CASK key.
<6-bits-reserved> ::= 1 * <pad>                                             ; 6 bits of reserved (zero) padding.
<sensitive-data-size> ::= 'B' | 'C'                                         ; 'B' = 256-bit sensitive data size, 'C' = 512-bit.
<provider-data-size> ::= 'A'..'K'                                           ; 'A' = zero 3-byte optional data segments, 'B' = one optional 3-byte
                                                                            ; segment, up to a maximum of 'K' = 10 optional 3-byte data segments.
<provider-kind> ::= <base64url>                                             ; Provider-defined key kind.
<provider-signature> ::= 4 * <base64url>                                    ; Provider identifier (24 bits).
<provider-data> ::= { <24-bits> }                                           ; 0 - 10 four-character (24-bit) segments of provider data. The 
                                                                            ; count of segments is encoded in the <provider-data-size> field.
<24-bits> ::= 4 * <base64url>                                               ; Three bytes of base64 encoded data. We maintain a 3-byte alignment
                                                                            ; throughout the format to support both encoded and bytewise
                                                                            ; interpretation and to avoid padding characters in the encoded form.
<12-bits-reserved> ::= 2 * <pad>                                            ; 12 bits of reserved (zero) padding.
<timestamp> ::= <year> <month> <day> <hour> <minute> <seconds>              ; Time-of-allocation components.
<year> ::= <base64url>                                                      ; Year of allocation, 'A' (2025) to '_' (2088).
<month> ::= 'A'..'L'                                                        ; Month of allocation, 'A' (January) to 'L' (December).
<day> ::= 'A'..'Z' | 'a'..'e'                                               ; 'A' = day 1, 'B' = day 2, ... 'e' = day 31
<hour> ::= 'A'..'X'                                                         ; Hour of allocation, 0-23. 'A' = hour 0 (midnight), ... 'X' = hour 23.
<minute> ::= 'A'..'7'                                                       ; Minute of allocation, 0-59.
<second> ::= 'A'..'7'                                                       ; Second of allocation, 0-59.
```

- **Overview**: High-level description of the system or feature.
- **Components**: Breakdown of individual components or modules.
- **Data Formats**: Any data structures, schemas, or formats used.
- **Algorithms**: Description of algorithms or processes.
- **APIs**: If applicable, include API signatures, parameters, and expected behavior.
- **Pseudocode**: If applicable, include API pseudocode.

## 5. Security Considerations
Discuss any security implications of the specification. Highlight potential risks and how they are mitigated.

## 6. Examples
### Byte-wise Rendering Example for 256-bit Key (no optional data)
|Byte Range|Decimal|Hex|Binary|Description|
|-|-|-|-|-|
|decodedKey[..31]|0...255|0x0...0xFF|00000000b...11111111b|256 bits of sensitive data produced by a cryptographically secure RNG, an HMAC, etc.|
|decodedKey[32]|0|0x00|00000000b| 8 bits of reserved padding.
|decodedKey[33..36]| 37, 4, 9  |0x40, 0x92, 0x50| 00100000b, 10010010b, 01010000b | Decoded 'QJJQ' signature.
|decodedKey[36..39]||||The value 0, sensitive data size, optional-data-size, and provider key kind encoded in 4 six-bit segments.
|decodedKey[39..42]|0...255|0x0...0xFF|00000000b...11111111b| Provider signature, e.g. , '0x4c', '0x44', '0x93' (base64-encoded as 'TEST')
|decodedKey[42..45]||||The value  0, the value 0, the allocation timestamp year, and timestamp month encoded in 4 six-bit segments.
|decodedKey[45..48]||||The allocation timestamp day, hour, minute, and second encoded in 4 six-bit segments.

### URL-Safe Base64-Encoded Rendering Example for 256-bit Key (no optional data)
|String Range|Text Value|Description|
|-|-|-|
|encodedKey[..42] | 'A'...'_' | 252 bits of randomized data generated by cryptographically secure RNG
|encodedKey[42] | <base64-two-zeros-suffix> | 4 bits of randomized data followed by 2 zero bits. See the <base64-two-zeros-suffix> definition for legal values.
|encodedKey[43] | 'A' | Encoded zero sensitive data padding character.
|encodedKey[44..48]|'QJJQ'| Fixed CASK signature.
|encodedKey[48] | 'A' | Reserved encoded zero character.
|encodedKey[49]|'B'...'C'| Sensitive component size, 'B' (256-bit) or 'C' (512-bit).
|encodedKey[50]|'A'...'K'| Count of optional 3-byte data segments, 'A' == 0 bytes, 'B' == 3 bytes, capped at 'K' == 30 bytes.
|encodedKey[51]|'A'...'_'| Provider-defined key kind.
|encodedKey[52..56]|'TEST'| Provider fixed signature.
|encodedKey[56..58] | 'AA' | Reserved encoded zero characters.
|encodedKey[59]|'A'...'_'| Time-of-allocation year, 'A' (2025) to '_' (2088)|
|encodedKey[60|'A'...'L'| Time-of-allocation month, 'A' (January) to 'L' (December)|
|encodedKey[61]|'A'...'Z'\|'a'..'e'| Time-of-allocation day, 'A' (0) to 'e' (31)|
|encodedKey[62]|'A'...'X'| Time-of-allocation hour, 'A' (hour 0 or midnight) to 'X' (hour 23).
|encodedKey[63]|'A'...'7'| Time-of-allocation minute, 'A' (0) to '7' (59).
|encodedKey[64]|'A'...'7'| Time-of-allocation second, 'A' (0) to '7' (59).
## 7. Testing

## 8. References
- [Base 64 Encoding with URL and Filename Safe Alphabet](https://www.rfc-editor.org/rfc/rfc4648#page-7)

---

## Appendix A: Change Log (Optional)
Track changes made to the specification over time.

## Appendix B: Acknowledgments (Optional)
Acknowledge contributors or organizations that helped in the development of the specification.
