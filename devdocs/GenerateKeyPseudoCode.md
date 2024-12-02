

# GenerateKey Pseudocode

1. Obtain a cryptographically secure, thread-safe pseudo random number generator.
1. Allocate an array of bytes for the generated key. Final size will be:
    - Count of bytes of entropy (16 - 32) + 
    - 12 bytes (for fixed signatures + timestamp)
    - [0 - N] bytes for provider reserved data
    - 3 bytes (for partial HMACSHA256 hash of key)
1. Generate at least 128 bits of random data (256 recommended and required for MS)
1. Copy random bytes to start of key
1. Copy provider reserved bytes to key
1. Copy CASK signature, allocator code, timestamp and provider signature
1. Obtain a CRC32 hashing API/object instance.
1. Compute the 4-byte CRC32 of key bytes (all bytes except the last 3).
1. Persist the first 3 bytes of the hash to the final 3 bytes of the key.
1. Encode as a URL-safe base64 string and return the key.
