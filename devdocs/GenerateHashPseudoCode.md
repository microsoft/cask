

# GenerateHash Pseudo-code

1. Examine the provided secret to determine whether it is a CASK key.
1. If it is CASK, retrieve the allocator code, provider signature and provider reserved bytes (if any).
1. Initialize an HMACSHA256 instance using the provided secret.
1. Hash the provided derivation input using the HMACSHA256 instance.
1. Allocate an array of bytes for the generated hash. Final size will be:
    - Count of bytes for HMAC (32) + 
    - A single padding byte (to keep hash 3-byte aligned)
    - 12 bytes (for fixed signatures + timestamp)
    - [0 - N] bytes for provider reserved data
    - 3 bytes (for partial HMACSHA256 hash of the hash)
1. Copy 32-byte HMAC hash to start of CASK hash
1. Copy provider reserved bytes to CASH hash (if any)
1. Copy CASK signature bytes to CASK hash
1. Generate allocator and timestamp bytes (using current timestamp)
1. Copy allocator and timestamp bytes to CASK hash
1. Obtain a CRC32 hashing API/object instance.
1. Compute the 4-byte CRC32 of key bytes (all bytes except the last 3).
1. Persist the first 3 bytes of the CRC32 hash to the final 3 bytes of the key
1. Encode as a URL-safe base64 string and return the key.
