// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Integration tests for the webhub-ffi shared library via P/Invoke.
//
// Usage (macOS):
//   cd crates/webhub-ffi/tests/csharp
//   DYLD_LIBRARY_PATH=../../../../target/debug dotnet test
//
// Usage (Linux):
//   cd crates/webhub-ffi/tests/csharp
//   LD_LIBRARY_PATH=../../../../target/debug dotnet test

using System;
using System.Runtime.InteropServices;
using Xunit;

namespace webhubFFITest;

/// <summary>
/// P/Invoke declarations for the webhub_ffi shared library.
/// </summary>
internal static class webhubFFI
{
    private const string LibName = "webhub_ffi";

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr webhub_handler_create();

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern void webhub_handler_destroy(IntPtr handlerPtr);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr webhub_protocol_create(
        IntPtr protocolData,
        UIntPtr protocolLen);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern void webhub_protocol_destroy(IntPtr protocolPtr);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr webhub_handler_render(
        IntPtr handlerPtr,
        IntPtr protocolPtr,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string dataJson,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string entryId,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string requestPath);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern void webhub_free(IntPtr stringPtr);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr webhub_last_error();

    /// <summary>
    /// Return the last error message, or null if none.
    /// </summary>
    public static string? GetLastError()
    {
        IntPtr ptr = webhub_last_error();
        if (ptr == IntPtr.Zero)
            return null;
        return Marshal.PtrToStringUTF8(ptr);
    }
}

// ---------------------------------------------------------------------------
// Tests: handler lifecycle
// ---------------------------------------------------------------------------

public class HandlerLifecycleTests
{
    [Fact]
    public void CreateAndDestroy()
    {
        IntPtr handler = webhubFFI.webhub_handler_create();
        Assert.NotEqual(IntPtr.Zero, handler);
        webhubFFI.webhub_handler_destroy(handler);
    }

    [Fact]
    public void DestroyNull()
    {
        webhubFFI.webhub_handler_destroy(IntPtr.Zero); // should not crash
    }

    [Fact]
    public void RenderNullArgs()
    {
        IntPtr handler = webhubFFI.webhub_handler_create();

        IntPtr ptr = webhubFFI.webhub_handler_render(
            handler, IntPtr.Zero, "{}", "index.html", "/");
        Assert.Equal(IntPtr.Zero, ptr);
        Assert.NotNull(webhubFFI.GetLastError());

        webhubFFI.webhub_handler_destroy(handler);
    }
}

// ---------------------------------------------------------------------------
// Tests: free string
// ---------------------------------------------------------------------------

public class FreeStringTests
{
    [Fact]
    public void FreeNull()
    {
        webhubFFI.webhub_free(IntPtr.Zero); // should not crash
    }
}
