using System.Runtime.CompilerServices;

using Xunit;

using static CommonAnnotatedSecurityKeys.Limits;

namespace CommonAnnotatedSecurityKeys.Tests;

public class LimitTests
{
    [Fact]
    public void Limits_MaxBytesAreStackAllocSafe()
    {
        AssertStackAllocSafe(MaxSecretEntropyInBytes);
        AssertStackAllocSafe(MaxProviderDataLengthInBytes);
        AssertStackAllocSafe(MaxKeyLengthInBytes);
    }

    [Fact]
    public void Limits_MinLessThanMax()
    {
        AssertMinLessThanMax(MinSecretEntropyInBytes, MaxSecretEntropyInBytes);
        AssertMinLessThanMax(MinKeyLengthInBytes, MaxKeyLengthInBytes);
        AssertMinLessThanMax(MinKeyLengthInChars, MaxKeyLengthInChars);
    }

    private static void AssertStackAllocSafe(int limit, [CallerArgumentExpression(nameof(limit))] string? name = null)
    {
        Assert.True(limit <= MaxStackAlloc, $"{name}={limit} is not stackalloc safe.");
    }

    private static void AssertMinLessThanMax(
        int min,
        int max,
        [CallerArgumentExpression(nameof(min))] string? minName = null,
        [CallerArgumentExpression(nameof(max))] string? maxName = null)
    {
        Assert.True(min < max, $"{minName}={min} >= {maxName}={max}.");
    }
}

