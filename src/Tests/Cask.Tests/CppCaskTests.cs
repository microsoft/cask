// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;
using System.Text;

using Xunit;

using static System.Runtime.InteropServices.UnmanagedType;

// CA2101: Specify marshaling for P/Invoke string arguments Supppressed due to
// false positives: https://github.com/dotnet/roslyn-analyzers/issues/7502
#pragma warning disable CA2101

// SYSLIB1054: Use 'LibraryImportAttribute' instead of 'DllImportAttribute' to
// generate P/Invoke marshalling code at compile time This is very cool but
// would require additional work to switch between LibraryImport and DllImport
// based on target framework.
#pragma warning disable SYSLIB1054

// CA5393: Use of unsafe DllImportSearchPath value UseDllDirectoryForDependencies
// DLL fails to load on .NET Framework without it since TestHost application directory
// is not the same directory as the test assembly.
#pragma warning disable CA5393

[assembly: DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories | DllImportSearchPath.UseDllDirectoryForDependencies)]

namespace CommonAnnotatedSecurityKeys.Tests;

// WIP: These tests are disabled because the C++ implementation is stubbed out.
//      To enable them, flip the return value of IsSupportedTestClass in
//      TestFilter.cs.


[ExcludeFromCodeCoverage]
public class CppCaskTests : CaskTestsBase
{
    public CppCaskTests() : base(new Implementation())
    {
    }

    private sealed class Implementation : ICask
    {
        public string GenerateKey(string providerSignature,
                                  string providerKeyKind,
                                  int expiryInFiveMinuteIncrements = 0,
                                  string? providerData = null)
        {
            int size = NativeMethods.Cask_GenerateKey(providerSignature, providerKeyKind, providerData, null, 0);
            byte[] bytes = new byte[size];
            size = NativeMethods.Cask_GenerateKey(providerSignature, providerKeyKind, providerData, bytes, size);
            Assert.True(size == bytes.Length, "Cask_GenerateKey did not use as many bytes as it said it would.");
            return Encoding.UTF8.GetString(bytes, 0, size - 1); // -1 to remove null terminator
        }

        public bool IsCask(string keyOrHash)
        {
            return NativeMethods.Cask_IsCask(keyOrHash);
        }

        public bool IsCaskBytes(byte[] bytes)
        {
            return NativeMethods.Cask_IsCaskBytes(bytes, bytes.Length);
        }

        Mock ICask.MockFillRandom(FillRandomAction fillRandom)
        {
            throw new NotImplementedException();
        }

        Mock ICask.MockUtcNow(UtcNowFunc getUtcNow)
        {
            throw new NotImplementedException();
        }

        private static class NativeMethods
        {
            [DllImport("libcask")]
            [return: MarshalAs(I1)]
            public static extern bool Cask_IsCask([MarshalAs(LPUTF8Str)] string keyOrHash);

            [DllImport("libcask")]
            [return: MarshalAs(I1)]
            public static extern bool Cask_IsCaskBytes(byte[] keyOrHash,
                                                       int length);

            [DllImport("libcask")]
            public static extern int Cask_GenerateKey([MarshalAs(LPUTF8Str)] string providerSignature,
                                                      [MarshalAs(LPUTF8Str)] string? providerKeyKind,
                                                      [MarshalAs(LPUTF8Str)] string? providerData,
                                                      byte[]? output,
                                                      int outputCapacity);
        }
    }
}

