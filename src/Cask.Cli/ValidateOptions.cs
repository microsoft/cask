// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Diagnostics.CodeAnalysis;

using CommandLine;

namespace CommonAnnotatedSecurityKeys.Cli;

[Verb("validate", HelpText = "Validate one or more common annotated security keys.")]
[SuppressMessage("Design", "CA1812:Avoid uninstantiated internal classes", Justification = "Instantiated by CommandLineParser")]
internal sealed class ValidateOptions
{
}
