// Copyright (c) Microsoft. All rights reserved.

using CommandLine;

namespace CommonAnnotatedSecurityKeys.Cli
{
    internal class Program
    {
        [STAThread]
        public static int Main(string[] args)
        {
            try
            {
                return Parser.Default.ParseArguments<
                    GenerateOptions,
                    ValidateOptions
                    >(args)
                  .MapResult(
                    (GenerateOptions options) => new GenerateCommand().Run(options),
                    (ValidateOptions options) => new ValidateCommand().Run(options),
                    _ => 1);
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                return 1;
            }
        }
    }
}
