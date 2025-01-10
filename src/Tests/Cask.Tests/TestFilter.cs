// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Reflection;
using System.Runtime.InteropServices;

using Xunit;
using Xunit.Abstractions;
using Xunit.Sdk;

[assembly: TestFramework("CommonAnnotatedSecurityKeys.Tests.TestFilter", "Cask.Tests")]

namespace CommonAnnotatedSecurityKeys.Tests;

public sealed class TestFilter : XunitTestFramework
{
    private static readonly bool s_builtWithCppSupport = IsBuiltWithCppSupport();

    public TestFilter(IMessageSink messageSink) : base(messageSink) { }

    protected override ITestFrameworkDiscoverer CreateDiscoverer(IAssemblyInfo assemblyInfo)
    {
        return new Discoverer(assemblyInfo, SourceInformationProvider, DiagnosticMessageSink);
    }

    private static bool IsSupportedTestClass(ITypeInfo type)
    {
        if (type.Name.EndsWith($".{nameof(CppCaskTests)}", StringComparison.Ordinal))
        {
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                Console.WriteLine("INFO: Skipping C++ tests on non-Windows.");
                return false;
            }

            if (RuntimeInformation.OSArchitecture != Architecture.X64)
            {
                Console.WriteLine("INFO: Skipping C++ tests on non-x64 OS.");
                return false;
            }

            if (!s_builtWithCppSupport)
            {
                Console.WriteLine("INFO: Skipping C++ tests because the test assembly was not built with C++ support.");
                Console.WriteLine("      Use Visual Studio or `msbuild` to build with C++ support.");
                return false;
            }

            // WIP: Flip this to true to enable C++ tests. They are not yet
            //      enabled because they fail as the C++ implementation is
            //      stubbed out..
            return false;
        }

        return true;
    }

    private static bool IsBuiltWithCppSupport()
    {
        foreach (AssemblyMetadataAttribute attribute in Assembly.GetExecutingAssembly().GetCustomAttributes<AssemblyMetadataAttribute>())
        {
            if (attribute.Key == "BuiltWithCppSupport")
            {
                return attribute.Value == "true";
            }
        }

        return false;
    }

    private sealed class Discoverer : XunitTestFrameworkDiscoverer
    {
        public Discoverer(
            IAssemblyInfo assemblyInfo,
            ISourceInformationProvider sourceProvider,
            IMessageSink diagnosticMessageSink,
            IXunitTestCollectionFactory? collectionFactory = null)
            : base(assemblyInfo, sourceProvider, diagnosticMessageSink, collectionFactory) { }

        protected override bool IsValidTestClass(ITypeInfo type)
        {
            return base.IsValidTestClass(type) && IsSupportedTestClass(type);
        }
    }
}
