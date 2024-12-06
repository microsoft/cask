// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Buffers.Text;
using System.Diagnostics.CodeAnalysis;
using System.Text;
using System.Text.RegularExpressions;

namespace CommonAnnotatedSecurityKeys;

/// <summary>
/// Represents a Cask key or hash.
/// </summary>
public readonly partial record struct CaskKey
{
    // PERF: Do not add more fields. The layout here is intentionally identical
    // to that of a string reference. This means that this type provides type
    // safety without any runtime overhead after creation.
    private readonly string _key;

    public static Regex Regex { get; } = CompiledRegex();

    private CaskKey(string key)
    {
        _key = key;
    }

    public static bool TryParse(string text, out CaskKey key)
    {
        ThrowIfNull(text);
        return TryParse(text.AsSpan(), out key);
    }

    public static bool TryParse(ReadOnlySpan<char> text, out CaskKey key)
    {
        if (!Cask.IsCask(text))
        {
            key = default;
            return false;
        }

        key = new CaskKey(text.ToString());
        return true;
    }

    public static bool TryParseUtf8(ReadOnlySpan<byte> textUtf8, out CaskKey key)
    {
        if (!Cask.IsCaskUtf8(textUtf8))
        {
            key = default;
            return false;
        }

        key = new CaskKey(Encoding.UTF8.GetString(textUtf8));
        return true;
    }

    public static bool TryEncode(ReadOnlySpan<byte> bytes, out CaskKey key)
    {
        if (!Cask.IsCaskBytes(bytes))
        {
            key = default;
            return false;
        }

        key = new CaskKey(Base64Url.EncodeToString(bytes));
        return true;
    }

    public static CaskKey Parse(string text)
    {
        if (!TryParse(text, out CaskKey key))
        {
            ThrowFormat();
        }
        return key;
    }

    public static CaskKey Parse(ReadOnlySpan<char> text)
    {
        if (!TryParse(text, out CaskKey key))
        {
            ThrowFormat();
        }
        return key;
    }

    public static CaskKey ParseUtf8(ReadOnlySpan<byte> text)
    {
        if (!TryParseUtf8(text, out CaskKey key))
        {
            ThrowFormat();
        }
        return key;
    }

    public static CaskKey Encode(ReadOnlySpan<byte> bytes)
    {
        if (!TryEncode(bytes, out CaskKey key))
        {
            ThrowFormat();
        }
        return key;
    }

    public override string ToString()
    {
        return _key ?? "";
    }

    // language=regex
    private const string RegexPattern = """(^|[^A-Za-z0-9+/-_])([A-Za-z0-9-_]{4}){6,}JQQJ[A-Za-z0-9-_]{12}($|[^A-Za-z0-9+/-_])""";
    private const RegexOptions RegexFlags = RegexOptions.Compiled | RegexOptions.ExplicitCapture | RegexOptions.CultureInvariant;

    [GeneratedRegex(RegexPattern, RegexFlags)]
    private static partial Regex CompiledRegex();

    [DoesNotReturn]
    private static void ThrowFormat()
    {
        throw new FormatException("Input is not a valid Cask key.");
    }
}
