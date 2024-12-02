// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

// WARNING: DO NOT MODIFY EXCEPT TO UPDATE TO A LATER VERSION OF THE CODE FROM THE BCL. THIS IS HARDER THAN IT MAY SEEM TO GET RIGHT!
// Source: https://github.com/dotnet/runtime/blob/354ec46a63440608bda18e2203bb5538e2f8eae6/src/libraries/System.Security.Cryptography/src/System/Security/Cryptography/CryptographicOperations.cs

#if NETFRAMEWORK
using System.Runtime.CompilerServices;

namespace System.Security.Cryptography;

internal static class CryptographicOperations
{
    /// <summary>
    /// Determine the equality of two byte sequences in an amount of time which depends on
    /// the length of the sequences, but not the values.
    /// </summary>
    /// <param name="left">The first buffer to compare.</param>
    /// <param name="right">The second buffer to compare.</param>
    /// <returns>
    ///   <c>true</c> if <paramref name="left"/> and <paramref name="right"/> have the same
    ///   values for <see cref="ReadOnlySpan{T}.Length"/> and the same contents, <c>false</c>
    ///   otherwise.
    /// </returns>
    /// <remarks>
    ///   This method compares two buffers' contents for equality in a manner which does not
    ///   leak timing information, making it ideal for use within cryptographic routines.
    ///   This method will short-circuit and return <c>false</c> only if <paramref name="left"/>
    ///   and <paramref name="right"/> have different lengths.
    ///
    ///   Fixed-time behavior is guaranteed in all other cases, including if <paramref name="left"/>
    ///   and <paramref name="right"/> reference the same address.
    /// </remarks>
    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    public static bool FixedTimeEquals(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right)
    {
        // NoOptimization because we want this method to be exactly as non-short-circuiting
        // as written.
        //
        // NoInlining because the NoOptimization would get lost if the method got inlined.

        if (left.Length != right.Length)
        {
            return false;
        }

        int length = left.Length;
        int accum = 0;

        for (int i = 0; i < length; i++)
        {
            accum |= left[i] - right[i];
        }

        return accum == 0;
    }
}
#endif