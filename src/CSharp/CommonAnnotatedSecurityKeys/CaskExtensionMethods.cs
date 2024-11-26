// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace CommonAnnotatedSecurityKeys;

internal static class CaskExtensionMethods
{
    internal static string FromUrlSafe(this string base64)
    {
        return base64.Replace('-', '+').Replace('_', '/');
    }

    internal static string ToUrlSafe(this string base64)
    {
        return base64.Replace('+', '-').Replace('/', '_');
    }

    internal static int RoundUpToMultipleOf(this int value, int multiple)
    {
        return (value + multiple - 1) / multiple * multiple;
    }
}