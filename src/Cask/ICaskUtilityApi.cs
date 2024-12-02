// Copyright (c) Microsoft. All rights reserved. Licensed under the MIT license.
// See LICENSE file in the project root for full license information.

namespace CommonAnnotatedSecurityKeys;

public interface ICaskUtilityApi
{
    DateTimeOffset GetCurrentDateTimeUtc();

    void ComputeCrc32Hash(ReadOnlySpan<byte> toChecksum, Span<byte> destination);
}