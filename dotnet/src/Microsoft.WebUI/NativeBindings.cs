// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

using System;
using System.Reflection;
using System.Runtime.InteropServices;

namespace Microsoft.webhub;

/// <summary>
/// Internal P/Invoke bindings to the native <c>webhub_ffi</c> library.
/// </summary>
internal static class NativeBindings
{
    private const string LibName = "webhub_ffi";

    /// <summary>
    /// SafeHandle wrapper for a native <c>webhub_handler</c> pointer.
    /// </summary>
    internal sealed class webhubHandlerSafeHandle : SafeHandle
    {
        internal webhubHandlerSafeHandle()
            : base(IntPtr.Zero, ownsHandle: true)
        {
        }

        internal webhubHandlerSafeHandle(IntPtr handle)
            : this()
        {
            SetHandle(handle);
        }

        public override bool IsInvalid => handle == IntPtr.Zero;

        protected override bool ReleaseHandle()
        {
            webhub_handler_destroy_raw(handle);
            return true;
        }
    }

    /// <summary>
    /// SafeHandle wrapper for a loaded native webhub protocol.
    /// </summary>
    internal sealed class webhubProtocolSafeHandle : SafeHandle
    {
        internal webhubProtocolSafeHandle()
            : base(IntPtr.Zero, ownsHandle: true)
        {
        }

        internal webhubProtocolSafeHandle(IntPtr handle)
            : this()
        {
            SetHandle(handle);
        }

        public override bool IsInvalid => handle == IntPtr.Zero;

        protected override bool ReleaseHandle()
        {
            webhub_protocol_destroy_raw(handle);
            return true;
        }
    }

    static NativeBindings()
    {
        NativeLibrary.SetDllImportResolver(
            typeof(NativeBindings).Assembly,
            ResolveNativeLibrary);
    }

    private static IntPtr ResolveNativeLibrary(
        string libraryName,
        Assembly assembly,
        DllImportSearchPath? searchPath)
    {
        if (libraryName != LibName)
        {
            return IntPtr.Zero;
        }

        // Allow overriding the native library path via environment variable.
        string? customPath = Environment.GetEnvironmentVariable("webhub_LIB_PATH");
        if (!string.IsNullOrEmpty(customPath) &&
            NativeLibrary.TryLoad(customPath, out IntPtr handle))
        {
            return handle;
        }

        // Fall back to default resolution.
        if (NativeLibrary.TryLoad(LibName, assembly, searchPath, out handle))
        {
            return handle;
        }

        return IntPtr.Zero;
    }

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl, EntryPoint = "webhub_handler_create")]
    private static extern IntPtr webhub_handler_create_raw();

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl, EntryPoint = "webhub_handler_create_with_plugin")]
    private static extern IntPtr webhub_handler_create_with_plugin_raw(
        [MarshalAs(UnmanagedType.LPUTF8Str)] string? pluginId);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl, EntryPoint = "webhub_handler_destroy")]
    private static extern void webhub_handler_destroy_raw(IntPtr handlerPtr);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl, EntryPoint = "webhub_protocol_create")]
    private static extern IntPtr webhub_protocol_create_raw(
        byte[] protocolData,
        nuint protocolLen);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl, EntryPoint = "webhub_protocol_destroy")]
    private static extern void webhub_protocol_destroy_raw(IntPtr protocolPtr);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr webhub_handler_render(
        webhubHandlerSafeHandle handlerPtr,
        webhubProtocolSafeHandle protocolPtr,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string dataJson,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string entryId,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string requestPath);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr webhub_protocol_render_partial(
        webhubProtocolSafeHandle protocolPtr,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string stateJson,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string entryId,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string requestPath,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string inventoryHex);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr webhub_protocol_render_component_templates(
        webhubProtocolSafeHandle protocolPtr,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string componentTagsJson,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string inventoryHex);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr webhub_protocol_tokens(
        webhubProtocolSafeHandle protocolPtr);

    internal static webhubHandlerSafeHandle CreateHandler(string? pluginId)
    {
        IntPtr handle = pluginId is null
            ? webhub_handler_create_raw()
            : webhub_handler_create_with_plugin_raw(pluginId);
        return new webhubHandlerSafeHandle(handle);
    }

    internal static webhubProtocolSafeHandle CreateProtocol(byte[] protocolData)
    {
        IntPtr handle = webhub_protocol_create_raw(protocolData, (nuint)protocolData.Length);
        return new webhubProtocolSafeHandle(handle);
    }

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void webhub_free(IntPtr stringPtr);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr webhub_last_error();

    /// <summary>
    /// Reads a UTF-8 string from a native pointer and frees the native memory.
    /// Returns <c>null</c> if the pointer is <see cref="System.IntPtr.Zero"/>.
    /// </summary>
    internal static string? ReadAndFreeString(IntPtr ptr)
    {
        if (ptr == IntPtr.Zero)
        {
            return null;
        }

        try
        {
            return Marshal.PtrToStringUTF8(ptr);
        }
        finally
        {
            webhub_free(ptr);
        }
    }

    /// <summary>
    /// Reads the last error message from the native library.
    /// Returns <c>null</c> if there is no error.
    /// </summary>
    internal static string? GetLastError()
    {
        IntPtr errorPtr = webhub_last_error();
        if (errorPtr == IntPtr.Zero)
        {
            return null;
        }

        return Marshal.PtrToStringUTF8(errorPtr);
    }
}
