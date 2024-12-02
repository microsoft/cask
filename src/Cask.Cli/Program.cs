// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Diagnostics.CodeAnalysis;

using CommandLine;

namespace CommonAnnotatedSecurityKeys.Cli;

internal static class Program
{
    [STAThread]
    [SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "Top-level handler")]
    public static int Main(string[] args)
    {
        try
        {
            return Parser.Default.ParseArguments<
                GenerateOptions,
                ValidateOptions
                >(args)
              .MapResult(
                (GenerateOptions options) => GenerateCommand.Run(options),
                (ValidateOptions options) => ValidateCommand.Run(options),
                _ => 1);
        }
        catch (Exception e)
        {
            Console.WriteLine(e);
            return 1;
        }
    }
}