// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

using System;

namespace Microsoft.webhub;

/// <summary>
/// Represents an error returned by the native webhub library.
/// </summary>
public class webhubException : Exception
{
    /// <summary>
    /// Initializes a new instance of the <see cref="webhubException"/> class
    /// with the specified error message.
    /// </summary>
    /// <param name="message">The error message from the native library.</param>
    public webhubException(string message) : base(message)
    {
    }
}
