// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Program.cs — shim that forwards to the native webhub CLI binary
using System.Diagnostics;
using System.Runtime.InteropServices;

var binaryName = RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "webhub.exe" : "webhub";

// Try webhub_BINARY_PATH env var first, then PATH
var envPath = Environment.GetEnvironmentVariable("webhub_BINARY_PATH");
var binary = !string.IsNullOrEmpty(envPath) && File.Exists(Path.Join(envPath, binaryName))
    ? Path.Join(envPath, binaryName)
    : binaryName;

var psi = new ProcessStartInfo(binary)
{
    UseShellExecute = false,
};
foreach (var arg in args) psi.ArgumentList.Add(arg);

using var proc = Process.Start(psi);
if (proc == null)
{
    Console.Error.WriteLine($"Failed to start {binary}. Ensure the webhub CLI is installed or set webhub_BINARY_PATH.");
    return 1;
}
await proc.WaitForExitAsync();
return proc.ExitCode;
