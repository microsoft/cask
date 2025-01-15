// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Buffers.Text;

namespace CommonAnnotatedSecurityKeys;

internal readonly struct ThreeByteSequence
{
    public ThreeByteSequence(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length != 3)
        {
            throw new ArgumentException("Three-byte sequence must be exactly three bytes long.", nameof(bytes));
        }
        Bytes = bytes.ToArray();
        Encoded = Convert.ToBase64String(Bytes);
    }

    public byte[] Bytes { get; }

    public string Encoded { get; }

    public byte FirstSixBits => (byte)(Bytes[0] >> 2);

    public byte SecondSixBits => (byte)(((Bytes[0] & 0b00000011) << 4) | Bytes[1] >> 4);

    public byte ThirdSixBits => (byte)(((Bytes[1] & 0b00001111) << 2) | Bytes[2] >> 6);

    public byte FourthSixBits => (byte)(Bytes[2] & 0b00111111);
}
