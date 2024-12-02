# Questions
1. MD5 vs. CRC32 (or something else)?
1. Should we have a dedicated return type?
1. Timing attacks in computed hash?

# TODOs
1. Spanify everything in C#, Span<char> to clear up text vs. bytes
1. Code is broken for dates in 2050 forward (need a test injection mechanism to unit test)
1. Create a language neutral interface declaration
1. CompareHash should use heavily optimized MemoryExtensions.SequenceEqual
1. Tests should have their own root folder so they can have their own D.*.props
1. Can we eliminate InternalsVisibleTo?
1. Add hard-coded keys for testing.
1. Fluent assertions vs. xunit assertions (we choose xunit for now)
1. Stress, concurrency, performance, fuzzing, RNG behavior testing.
