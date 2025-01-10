<key> ::= <payload-data> <checksum>

<payload-data> ::= <random-data> <reserved-char> [<optional-fields>] <cask-signature> <provider-id> <timestamp> <key-type> <version-char>

<random-data> ::= 42 * <base64url-char> <base64-two-zeros-suffix>; The total random data comprises 256 bits encoded as 42
                                                                 ; characters x 6 bit bits of random data = 252 bits and
                                                                 ; 1 character providing 4 bits of random data padded with 00b.

<reserved-char> ::= <base64url-char> ; Reserved for future use.

<optional-fields> ::= { <optional-field> } ; Zero or more 4-character (24 bit) sequences of optional data.

<optional-field> ::= 4 * <base64url-char> ; Each optional field is 4 characters (24 bits). This keeps
                                          ; data cleanly aligned along 3-byte/4-encoded character boundaries
                                          ; facilitating readability of encoded form as well as bytewise use.

<cask-signature> ::= 'JQQJ' ; Fixed signature identifying the CASK key

<provider-id> ::= 4 * <base64url-char> ; Provider identifier (24 bits)

<timestamp> ::= <year-char> <month-char> <day-char> <hour-char> ; Timestamp components

<key-type> ::= 'A' ; Currently 'A' denotes a 256-bit primary key

<version-char> ::= <base64url-char> ; Version information

<checksum> ::= <four-zeros-prefix-base64> 5 * <base64url-char> ; The checksum is 32 bits total encoded in six 6-bit characters.
                                                               ; The data starts with 0000b (four leading zero bit) and 2 bits
                                                               ; of checksum data followed by the remaing 30 bits of checksum.

<year-char> ::= <base64url-char> ; Represents the year, 'A' (2024) to '_' (2087)

<month-char> ::= 'A'..'L' ; For months January to December

<day-char> ::= 'A'..'Z' | 'a'..'f' ; 'A' = day 1, 'B' = day 2, ... 'e' = day 30, ... 'f' = day 31

<hour-char> ::= 'A'..'X' ; Represents hours 0-23. 'A' corresponds to hour 0 (midnight).

<base64url-char> ::= 'A'..'Z' | 'a'..'z' | '0'..'9' | '-' | '_'

<four-zeros-prefix-base64> ::= 'A'..'D' ; Base64 characters starting with 0000b (indices 0–3).

<base64-two-zeros-suffix> ::= 'A' | 'E' | 'I' | 'M' | 'Q' | 'U' | 'Y' | 'c' ; Base64 characters ending in 00b. These indices are all
                            | 'g' | 'k' | 'o' | 's' | 'w' | '0' | '4' | '8' ; multiple of 4 (or the value of 0b), a fact that may be
                                                                            ; useful in some contexts.



