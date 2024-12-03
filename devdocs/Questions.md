# Questions
1. MD5 vs. CRC32 (or something else)?
   - CRC32 is a good choice, we're using it for its intended purpose.
   - Can we make room for all four bytes? There isn't a lot of prior art for truncating CRC-32 like SHAs.
   - Reserving a byte or two for future use by us might be a good idea anyway?
   - Possible uses:
     - Record secret entropy length. Right now, it's a bit of a footgun that you have to pass the correct length to Generate/CompareHash.

1. Should provider data be allowed to be unaligned. Should we pad it instead of throwing?

1. Should we combine Cask and CaskKey, putting the statics as helpers on the struct?
  - Best name for combined? Or better names (plural) if they should remain separate?
  - Related: can we avoid repeating Cask like Cask.IsCask -> Cask.IsValid.

1. Should we use a new timestamp in GenerateHash and mask it out in CompareHash?
   - The first draft created a new timestamp, but didn't mask so it would fail if the month rolled over between GenerateHash and CompareHash.
   - The second draft copies the timestamp from the secret when generating a hash.
   - It feels wrong for something called "GenerateHash" to not be deterministic.

1. Are the limits on entropy and provider data length reasonable? 
   - Review Limits.cs.
   - Keeping them small allows unconditional stackalloc.
   - These can be increased later.

# TODOs
1. Add hard-coded keys for testing.
1. Stress, concurrency, performance, fuzzing, RNG behavior testing.
1. Code coverage reporting in CI
1. Unit tests for generate/compare hash
1. Test against base64 input with whitespace and padding, which we must disallow.