// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

using Xunit;

namespace CommonAnnotatedSecurityKeys.Tests;

public class ThreeByteSequenceTests
{
    private const string Base64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    [Fact]
    public void ThreeByteSequence_ExhaustiveBase64Url()
    {
        for (int one = 0; one < 64; one++)
        {
            for (int two = 0; two < 64; two++)
            {
                for (int three = 0; three < 64; three++)
                {
                    for (int four = 0; four < 64; four++)
                    {
                        string base64 = $"{Base64[one]}{Base64[two]}{Base64[three]}{Base64[four]}";
                        byte[] bytes = Convert.FromBase64String(base64);

                        var sequence = new ThreeByteSequence(bytes);

                        byte expected = (byte)one;
                        byte actual = sequence.FirstSixBits;
                        Assert.True(actual == expected,
                                    userMessage: $"On processing '{base64}' the 4th 6-bit component '{actual}' was not '{expected}'");

                        expected = (byte)two;
                        actual = sequence.SecondSixBits;
                        Assert.True(actual == expected,
                                    userMessage: $"On processing '{base64}' the 4th 6-bit component '{actual}' was not '{expected}'");

                        expected = (byte)three;
                        actual = sequence.ThirdSixBits;
                        Assert.True(actual == expected,
                                    userMessage: $"On processing '{base64}' the 4th 6-bit component '{actual}' was not '{expected}'");

                        expected = (byte)four;
                        actual = sequence.FourthSixBits;
                        Assert.True(actual == expected,
                                    userMessage: $"On processing '{base64}' the 4th 6-bit component '{actual}' was not '{expected}'");
                    }
                }
            }
        }
    }
}
