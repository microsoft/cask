// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace CommonAnnotatedSecurityKeys.Tests;

/// <summary>
/// Provides a cross-language common interface matching for testing purposes.
/// Allows for testing Cask implementations in other languages than C# with the
/// same test suite.
/// </summary>
/// <remarks> 
/// We can pragmatically choose lowest common denominator typing for this
/// interface so tests can interop and marshal easily. The actual
/// customer-facing language-specific API are free to be more elaborate,
/// idiomatic, and performance-minded as appropriate for their langauge.
///
/// This interface is defined in the test project because it is purely a test
/// concern to have a common interface across languages.
/// </remarks>
public interface ICask
{
    bool IsCask(string keyOrHash);

    bool IsCaskBytes(byte[] keyOrHash);

    // TBD two sequential optional string arguments is a bad idea.
    string GenerateKey(string providerSignature, string? providerKeyKind, string? providerData = null);

    string GenerateHash(byte[] derivationInput, string secret);

    bool CompareHash(string candidateHash, byte[] derivationInput, string secret);

    internal Mock MockUtcNow(UtcNowFunc getUtcNow);

    internal Mock MockFillRandom(FillRandomAction fillRandom);
}
