# CASK 256-bit Primary Keys
## Standard Backus-Naur Form (BNF)
```
<key> ::= <payload-data> <checksum>

<payload-data> ::= <random-data> <reserved> [<optional-fields>] <cask-signature> <provider-id> <timestamp> <key-type> <version>

<random-data> ::= 42 * <base64url> <base64-two-zeros-suffix>; The total random data comprises 256 bits encoded as 42
                                                                 ; characters x 6 bit bits of random data = 252 bits and
                                                                 ; 1 character providing 4 bits of random data padded with 00b.

<reserved> ::= '0' ; Reserved for future use.

<optional-fields> ::= { <optional-field> } ; Zero or more 4-character (24 bit) sequences of optional data.

<optional-field> ::= 4 * <base64url> ; Each optional field is 4 characters (24 bits). This keeps
                                          ; data cleanly aligned along 3-byte/4-encoded character boundaries
                                          ; facilitating readability of encoded form as well as byte-wise use.

<cask-signature> ::= 'JQQJ' ; Fixed signature identifying the CASK key

<provider-id> ::= 4 * <base64url> ; Provider identifier (24 bits)

<timestamp> ::= <year> <month> <day> <hour> ; Timestamp components

<year> ::= <base64url> ; Represents the year, 'A' (2024) to '_' (2087)

<month> ::= 'A'..'L' ; For months January to December

<day> ::= 'A'..'Z' | 'a'..'f' ; 'A' = day 1, 'B' = day 2, ... 'e' = day 30, ... 'f' = day 31

<hour> ::= 'A'..'X' ; Represents hours 0-23. 'A' = hour 0 (midnight), ... 'X' = hour 23.

<key-type> ::= <256-bit-key> | 

<256-bit-key> ::= 'A' | <256-bit-hash> | <384-bit-hash>

<256-bit-hash> ::= 'H'

<384-bit-hash> ::= 'I'

<version> ::= 'A' 

<checksum> ::= <four-zeros-prefix-base64> 5 * <base64url> ; The checksum is 32 bits total encoded in six 6-bit characters.
                                                          ; The data starts with 0000b (four leading zero bit) and 2 bits
                                                          ; of checksum data followed by the remaining 30 bits of checksum.


<base64url> ::= 'A'..'Z' | 'a'..'z' | '0'..'9' | '-' | '_'

<four-zeros-prefix-base64> ::= 'A'..'D' ; Base64 characters starting with 0000b (indices 0-3).

<base64-two-zeros-suffix> ::= 'A' | 'E' | 'I' | 'M' | 'Q' | 'U' | 'Y' | 'c' ; Base64 characters ending in 00b. These indices are all
                            | 'g' | 'k' | 'o' | 's' | 'w' | '0' | '4' | '8' ; multiple of 4 (or the value of 0b), a fact that may be
                                                                            ; useful in some contexts.
```
## Byte-wise Rendering
|Byte Range|Decimal|Hex|Binary|Description|
|-|-|-|-|-|
|key[0] - key[31]|0 - 256|0x0 - 0xFF|00000000b - 11111111b|256 bits of random data produced by a cryptographically secure RNG|
|key[32]|0d|0xFF|00000000b| A reserved byte to enforce 3-byte alignment.
|[optional 3-bye sequences]|0 - 256|0x0 - 0xFF|00000000b - 11111111b|Provider-defined data of arbitrary form.
|key[keyLength - 6]|0|0xFF|00000000b - 11111100b| (KeyKind)key[keyLength - 6] >> 2 (leading 6 bits comprises kind enum + two bits of version number). Currently, [keyLength - 6] & 0xFC == 0 (as these bits are undefined in the version data)
|key[key.Length - 5]|0|0xFF|00000000b - 11110000b| (CaskVersion)([key.Length - 6] & 0xFC << 4) & key[key.Length - 5] >> 4) (leading 4 bits comprise final 4 bits of version + 4 bits of zero padding).
|key[keyLength - 4] - key[keyLength - 1]|0 - 256|0x0 - 0xFF|00000000b - 11111111b|CRC32(key[0] - key[key.Length - 5])
