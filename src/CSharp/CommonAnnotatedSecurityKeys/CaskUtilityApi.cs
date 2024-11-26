// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Immutable;
using System.IO.Hashing;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace CommonAnnotatedSecurityKeys
{
    public class CaskUtilityApi : ICaskUtilityApi
    {
        [ThreadStatic]
        private static Lazy<ICaskUtilityApi> caskConstants =
            new(() => new CaskUtilityApi());

        [ThreadStatic]
        private static readonly Lazy<Crc32> crc32 =
            new(() => new Crc32());

        [ThreadStatic]
        private static readonly Lazy<SHA256> sha256 =
            new(() => SHA256.Create());

        [ThreadStatic]
        private static readonly Lazy<HMACSHA256> caskHmac256 =
            new(() => new HMACSHA256(Encoding.UTF8.GetBytes("Cask_v1")));

        [ThreadStatic]
        private static readonly Lazy<RandomNumberGenerator> rng =
            new(() => RandomNumberGenerator.Create());

        public static string CaskSignature => "JQQJ";

        public static byte[] CaskSignatureBytes => Convert.FromBase64String(CaskSignature);

        public static readonly Regex CaskKeyRegex =
            new Regex("(^|[^A-Za-z0-9+/-_])([A-Za-z0-9-_]{4}){6,}JQQJ[A-Za-z0-9-_]{12}($|[^A-Za-z0-9+/-_])",
                      RegexOptions.Compiled | RegexOptions.ExplicitCapture | RegexOptions.CultureInvariant);

        public static ICaskUtilityApi Instance
        {
            get 
            {
                if (caskConstants.Value == null)
                {
                    caskConstants = new Lazy<ICaskUtilityApi>(() => new CaskUtilityApi());
                }
                return caskConstants.Value;
            }
            set { caskConstants = new (() => value); }
        }

        public static Crc32 Crc32
        {
            get { return crc32.Value; }
        }

        public static SHA256 Sha256
        {
            get { return sha256.Value; }
        }

        public static HMACSHA256 Hmac256
        {
            get { return caskHmac256.Value; }
        }

        public static RandomNumberGenerator Rng
        {
            get { return rng.Value; }
        }

        private static readonly char[] orderedUrlSafeBase64Characters = new[] {
            'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
            'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
            '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '-', '_' };

        public static ReadOnlySpan<char> OrderedUrlSafeBase64Characters  => orderedUrlSafeBase64Characters;

        public static readonly ISet<char> UrlSafeBase64Characters = orderedUrlSafeBase64Characters.ToImmutableHashSet();

        public virtual DateTimeOffset GetCurrentDateTimeUtc()
        {
            return DateTimeOffset.UtcNow;
        }

        public virtual void ComputeCrc32Hash(ReadOnlySpan<byte> toChecksum, Span<byte> destination)
        {
            Crc32.Reset();
            Crc32.Append(toChecksum);
            Crc32.GetHashAndReset(destination);
        }
    }
}
