// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Buffers.Text;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Text;
using System.Text.RegularExpressions;

namespace CommonAnnotatedSecurityKeys;

/// <summary>
/// Represents a Cask key or hash.
/// </summary>
public readonly partial record struct CaskKey : IIsInitialized
{
    // PERF: Do not add more fields. The layout here is intentionally identical
    // to that of a string reference. This means that this type provides type
    // safety without any runtime overhead after creation.
    private readonly string? _key;

    public static Regex Regex { get; } = CompiledRegex();

    /// <summary>
    /// Indicates if the key is initialized, and not the default struct value.
    /// </summary>
    [MemberNotNullWhen(true, nameof(_key))]
    public bool IsInitialized => _key != null;

    public KeyKind Kind
    {
        get
        {
            ThrowIfUnitialized();
            return CharToKind(_key[KindCharIndex]);
        }
    }

    public CaskVersion CaskVersion
    {
        get
        {
            ThrowIfUnitialized();
            return CharToVersion(_key[VersionCharIndex]);
        }
    }

    public int SizeInBytes
    {
        get
        {
            ThrowIfUnitialized();
            return Base64CharsToBytes(_key.Length);
        }
    }

    public bool IsPrimary => Kind < KeyKind.Hash256Bit;

    public bool IsHash => !IsPrimary;

    private CaskKey(string value)
    {
        _key = value;
    }

    public static bool TryCreate(string text, out CaskKey key)
    {
        // PERF: This doesn't forward to TryCreate with ReadOnlySpan<char>
        // because that would allocate a new string. We can use the existing
        // string to back the new CaskKey instance when the caller has one.
        if (!Cask.IsCask(text))
        {
            key = default;
            return false;
        }

        key = new CaskKey(text);
        return true;
    }

    public static bool TryCreate(ReadOnlySpan<char> text, out CaskKey key)
    {
        if (!Cask.IsCask(text))
        {
            key = default;
            return false;
        }

        key = new CaskKey(text.ToString());
        return true;
    }

    public static bool TryCreateUtf8(ReadOnlySpan<byte> textUtf8, out CaskKey key)
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

    public static CaskKey Create(string text)
    {
        if (!TryCreate(text, out CaskKey key))
        {
            ThrowFormat();
        }

        return key;
    }

    public static CaskKey Create(ReadOnlySpan<char> text)
    {
        if (!TryCreate(text, out CaskKey key))
        {
            ThrowFormat();
        }

        return key;
    }

    public static CaskKey CreateUtf8(ReadOnlySpan<byte> text)
    {
        if (!TryCreateUtf8(text, out CaskKey key))
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

    public void Decode(Span<byte> destination)
    {
        ThrowIfUnitialized();
        ThrowIfDestinationTooSmall(destination, SizeInBytes);

        int bytesWritten = Base64Url.DecodeFromChars(_key.AsSpan(), destination);
        Debug.Assert(bytesWritten == SizeInBytes);
    }

    public override string ToString()
    {
        // Throwing violates the contract for ToString(), but it's a safety
        // measure to block a bug from causing an unitialized key from being
        // used as a production key.
        //
        // This is not considered final and needs more thought. We may move
        // access to the underlying string elsewhere.
        ThrowIfUnitialized();
        return _key;
    }

    [MemberNotNull(nameof(_key))]
    private void ThrowIfUnitialized()
    {
        if (!IsInitialized)
        {
            ThrowOperationOnUnitializedInstance();
        }
    }

    // language=regex
    private const string RegexPattern = """(^|[^A-Za-z0-9+/-_])([A-Za-z0-9-_]{4}){6,}JQQJ[A-Za-z0-9-_]{16}($|[^A-Za-z0-9+/-_])""";
    private const RegexOptions RegexFlags = RegexOptions.Compiled | RegexOptions.ExplicitCapture | RegexOptions.CultureInvariant;

    [GeneratedRegex(RegexPattern, RegexFlags)]
    private static partial Regex CompiledRegex();

    [DoesNotReturn]
    private static void ThrowFormat()
    {
        throw new FormatException("Input is not a valid Cask key.");
    }
}
