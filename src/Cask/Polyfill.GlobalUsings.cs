// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

// These global usings are used to shadow real BCL types with polyfill implementations. This is
// only necessary when polyfilling static members of types that exist on .NET Framework.

global using Polyfill;

global using static Polyfill.ArgumentValidation;

global using RandomNumberGenerator = Polyfill.RandomNumberGenerator;
