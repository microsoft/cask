// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Reflection;

namespace CommonAnnotatedSecurityKeys.Benchmarks;

internal static class DebugBenchmarkRunner
{
    public static void Run(Type[] types)
    {
        Console.WriteLine("WARNING: Running in debug build. Each benchmark will be run once without measuring anything.");
        foreach (Type type in types)
        {
            object instance = Activator.CreateInstance(type)!;
            foreach (MethodInfo method in type.GetMethods(BindingFlags.Public | BindingFlags.Instance))
            {
                if (method.GetCustomAttributesData().Any(a => a.AttributeType.Name == "BenchmarkAttribute"))
                {
                    Console.WriteLine($"Running {type.Name}.{method.Name}...");
                    method.Invoke(instance, null);
                }
            }
        }
    }
}
