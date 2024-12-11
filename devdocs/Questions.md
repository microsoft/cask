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

1. Are the limits on entropy and provider data length reasonable? 
   - Review Limits.cs.
   - Keeping them small allows unconditional stackalloc.
   - These can be increased later.

1. We need to think about not overriding ToString() on CaskKey.
   - Consider something like .SensitiveValue as the only way to get the string so people don't print it without thinking or try to use the default-initialed ToString() which musn't throw as a key.

# TODOs
1. Add hard-coded keys for testing.
1. Stress, concurrency, performance, fuzzing, RNG behavior testing.
1. Code coverage reporting in PR validation.
1. Unit tests for generate/compare hash
1. Test against base64 input with whitespace and padding, which we must disallow.
1. Name regex captures and add more regex test coverage.
1. Move magic numbers/chars to constants.
1. Use named arguments or better variables with good names for all string arguments in tests.
1. Reduce repetition between UTF-8 and UTF-16 code paths if performant. If not performant, comment why there is a bit of repetition. Also consider risk of misleading to use UTF-8 API on base64-decoded bytes before changing this.
1. Run benchmarks somewhere on regular basis.
1. Make tests for invalid keys more resilient to implementation changes.
   - Produce keys using helpers that are only invalid in one way (e.g. just the length is wrong.)
   - Return enough info from API (needs design) to assert that the reason the key is invalid is the reason we expect.
