// Copyright (c) Microsoft. All rights reserved.
#nullable disable
using CommandLine;

namespace CommonAnnotatedSecurityKeys.Cli;

[Verb("generate", HelpText = "Generate one or more common annotated security keys.")]
public class GenerateOptions
{
    [Option(
        "test",
        Required = false,
        HelpText = "Generate all test keys.")]
    public bool Test { get; set; }

    [Option(
        "signature",
        Required = false,
        Default = "TEST",
        HelpText = "A fixed signature to inject into the generated key).")]
    public string FixedSignature { get; set; }

    [Option(
        "length",
        Required = false,
        Default = 32,
        HelpText = "The length of the randomized component in bytes. Must be at least 16.")]
    public int SecretEntropyInBytes { get; set; }

    [Option(
        "count",
        Required = false,
        Default = (uint)1,
        HelpText = "The count of keys to generate.")]
    public uint Count { get; set; }
}