// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace CommonAnnotatedSecurityKeys;

/// <summary>
/// Struct returned by internal methods that provide a way to mock some behavior.
/// The mocking is reverted to the standard behavior when the struct is disposed.
/// </summary>
internal struct Mock(Action revert) : IDisposable
{
    public void Dispose()
    {
        revert?.Invoke();
        revert = null!;
    }
}

/// <summary>
/// Delegate that fills a buffer with random data.
/// Used by tests to mock random-number generation in key creation.
/// </summary>
/// <param name="buffer"></param>
internal delegate void FillRandomAction(Span<byte> buffer);

/// <summary>
/// Delegate that returns the current time in UTC.
/// Used by tests to mock timestamp used in key creation.
/// </summary>
internal delegate DateTimeOffset UtcNowFunc();
