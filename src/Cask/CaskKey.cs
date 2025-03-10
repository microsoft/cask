// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Buffers.Text;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Drawing;
using System.Text;
using System.Text.RegularExpressions;

namespace CommonAnnotatedSecurityKeys;

/// <summary>
/// Represents a Cask secret.
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

    public SensitiveDataSize SensitiveDataSize
    {
        get
        {
            ThrowIfNotInitialized();
            SensitiveDataSize sensitiveDataSize = Cask.InferSensitiveDataSizeFromCharLength(_key.Length);
            Range caskSignatureCharRange = Cask.ComputeSignatureCharRange(sensitiveDataSize);
            Index sensitiveDataSizeCharIndex = caskSignatureCharRange.End.Value + SensitiveDataSizeOffsetFromCaskSignatureChar;
            return (SensitiveDataSize)(_key[sensitiveDataSizeCharIndex] - 'A');

        }
    }

    public int SensitiveDateSizeInBytes
    {
        get
        {
            ThrowIfNotInitialized();
            ThrowIfInvalidKeyLengthInChars(_key.Length);
            SensitiveDataSize sensitiveDataSize = CharToSensitiveDataSize(_key[SensitiveDataSizeCharIndex]);
            return sensitiveDataSize switch
            {
                SensitiveDataSize.Bits128 => 16,
                SensitiveDataSize.Bits256 => 32,
                SensitiveDataSize.Bits384 => 48,
                SensitiveDataSize.Bits512 => 64,
                _ => ThrowUnrecognizedSensitiveDataSize(sensitiveDataSize),
            };
        }
    }

    public int SizeInBytes
    {
        get
        {
            ThrowIfNotInitialized();
            return Base64CharsToBytes(_key.Length);
        }
    }

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
        ThrowIfNotInitialized();
        ThrowIfDestinationTooSmall(destination, SizeInBytes);

        int bytesWritten = Base64Url.DecodeFromChars(_key.AsSpan(), destination);
        Debug.Assert(bytesWritten == SizeInBytes);
    }

    public override string ToString()
    {
        // Throwing violates the contract for ToString(), but it's a safety
        // measure to block a bug from causing an uninitialized key from being
        // used as a production key.
        //
        // This is not considered final and needs more thought. We may move
        // access to the underlying string elsewhere.
        ThrowIfNotInitialized();
        return _key;
    }

    [MemberNotNull(nameof(_key))]
    private void ThrowIfNotInitialized()
    {
        if (!IsInitialized)
        {
            ThrowOperationOnUninitializedInstance();
        }
    }

    // language=regex
    private const string RegexPattern = """(^|[^A-Za-z0-9+\/\-_])([A-Za-z0-9\-_]{4}([A-Za-z0-9\-_]{20}){1,3}|[A-Za-z0-9\-_]{88})?QJJQ[A-Za-z0-9\-_][A-L][A-Za-e][A-X][A-Za-z0-7][B-E][A-E][A-Za-z0-9\-_]([A-Za-z0-9\-_]{4}){0,4}[A-Za-z0-9\-_]{24}([^A-Za-z0-9+\/\-_]|$)""";
    private const RegexOptions RegexFlags = RegexOptions.Compiled | RegexOptions.ExplicitCapture | RegexOptions.CultureInvariant;

    [GeneratedRegex(RegexPattern, RegexFlags)]
    private static partial Regex CompiledRegex();

    [DoesNotReturn]
    private static void ThrowFormat()
    {
        throw new FormatException("Input is not a valid Cask key.");
    }

    [DoesNotReturn]
    private static int ThrowUnrecognizedSensitiveDataSize(SensitiveDataSize sensitiveDataSize)
    {
        throw new InvalidOperationException($"Unexpected sensitive data size: {sensitiveDataSize}.");
    }

    private static void ThrowIfInvalidKeyLengthInChars(int length)
    {
        if (!Cask.IsValidKeyLengthInChars(length))
        {
            throw new ArgumentException($"""
                                        Encoded key length must be between than {MinKeyLengthInChars} and {MaxKeyLengthInChars}
                                        and a multiple of 4. Value provided was '{length}'.");
                                        """);
        }
    }
}
