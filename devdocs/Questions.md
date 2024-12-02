# Questions
1. MD5 vs. CRC32 (or something else)?
   - CRC32 makes more and perfect sense for this use case, IMHO, but can we make room for all four bytes?
   - Reserving a byte or two for future use by us migt be a good idea anyway so two bytes of padding may be OK? See next question for case in point.

1. It would be useful to be able to determine the boundary between secret and provider data. Can we write the secret entropy length somewhere?
  - Having to pass the secret entropy length to GenerateHash along seems like a footgun.Ideally, you only need to specify this to create a key and never to use it, IMHO.

# NGuerrera's Pre-Code Review Notes
1. I'm sorry, this huge and bordering on a rewrite. I got a little carried away over the holiday. I should have broken this up into smaller pieces. Just like we did for MikeFan's the first draft, we should go over this live together.

1. On checksum question above: CRC32 is a good choice, we're using it for it's intended purpose. MD5 will just trigger false alarms about insecure algorithms. 
   -BUT, can we make room for all four bytes? There isn't any prior art on truncating CRC-32 like SHAs.
     - Possible uses of the 2 padding bytes to get back to 3-byte alignment:
     - [1 byte] Record secret entropy length. Right now, it's a bit of a footgun IMHO, that you have to pass the correct length along with the key to CompareHash.
     - [1 byte] Reserved for future use by us?

1. I have spanified all the things. I'm happy to say that it made the faster AND easier to read IMHO.

1. I renamed reserved -> provider data. "reserved" for a parameter name gives me unwanted memories of ancient native API. Also, I want to reserve the name "reserved" for things reserved by the spec, not reserved for providers.

1. Should provider data be allowed to be unaligned. Should we pad it instead of throwing?

1. What if month rolls over between generate and compare hash? 
  - Should we mask out timestamp in compare hash or copy timestamp in generate hash?
  - I've copied since that's faster and simpler.

1. I put some limits on provider data and secret entropy length. Are they reasonable? This allows us to use stackalloc unconditionally.

1. I made everything pre-existing static and moved the interface to tests only. This one may seem shocking, so let's talk about why I think it's actually liberating. :)
   - See how all the modern .NET crypto API are just static functions too. There are even analyzers telling you to prefer this static API.
   - Consumer doesn't even have to think about lifetime or thread safety, they can just call the function whenever they want.
   - See how our efforts to use the old instance crypto API led to complexity like threadstatic + lazy that was actually wrong. Let's not make new crypto-adjacent API that leads people to the same pain.
   - Object orientation is great for modeling objects, it's not great for modeling math-like functions.
   - Also actually great to be able to diverge the langauge-specific API from the langauge-agnostic test interface. It means we can do better for each language in idiomatic ways without sacrificing on testing them all with the same suite.

1. I ran with Ross' suggestion to have a strong type for the key and I think it came out great. :)
  - There are two types now Cask (static helpers) and CaskKey but I think we can merge them by putting static helpers on struct
  - I don't like "stuttering API like" Cask.IsCask. This could be Cask.IsValid?

1. I changed my mind on internals-visible- to. I don't want to have to commit to the shape of thigns that exist only for testing (like how to override the clock or random number generator)
    - I did, however, remove internals-visible-to for everything that isn't a test
    - And we should still avoid testing internal helpers and prefer to cover the internal helpers via the public API.

1. Also changed my mind on this: Let's try using only strongly typed CaskKey before giving out byte alternatives. We do all conversions on the stack now so it should be fast enough. I will measure, though. Type safety and discouraging persisting the key as bytes seems worth it. Very easy to add later if we change our minds again.

1. I found a happy medium for making .NET Framework support more tolerable if we can agree on some priniciples. I wrote them down in Polyfill.cs.

1. I pushed myself to dogfood while writing this code. 
   - Cranked up the analyzers to eleven and looked where they led me. This was a great exercise even for me because I've been away from .NET for four years I learned a ton. Learning new platform features this way made me very nostalgic for FxCop. :)
   - We will surely decide to turn off some analyzers as we go and that's fine.It's as easy as Ctrl-dot -> Configure Severity -> Silent.

1. I got rid of the CSharp\ folder. It was driving me nuts to have everything one level deeper than ususal. 
   - As we mentioned before we may put C++ in the same sln. 
   - Even if not, I think we can make non-C# projects siblings of C# projects.

1. Dialed back the number of test cases for timestamp. This code path is too simple to spend that many cycles testing on every developer iteration.

1. Surely lots I'm forgetting, but I'll add to here as we go over live.

# TODOs
1. Add hard-coded keys for testing.
1. Stress, concurrency, performance, fuzzing, RNG behavior testing.
1. Code coverage reporting in CI
1. Unit tests for generate/compare hash
