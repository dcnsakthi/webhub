# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

"""Integration tests for the loaded-protocol webhub C ABI."""

import ctypes
import os
import platform
import unittest
from ctypes import POINTER, c_char_p, c_size_t, c_ubyte, c_void_p
from typing import Optional


def _load_library():
    system = platform.system()
    if system == "Darwin":
        lib_name = "libwebhub_ffi.dylib"
    elif system == "Windows":
        lib_name = "webhub_ffi.dll"
    else:
        lib_name = "libwebhub_ffi.so"

    script_dir = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.abspath(os.path.join(script_dir, "..", "..", "..", ".."))
    for profile in ("debug", "release"):
        path = os.path.join(repo_root, "target", profile, lib_name)
        if os.path.exists(path):
            return ctypes.cdll.LoadLibrary(path)
    return ctypes.cdll.LoadLibrary(lib_name)


lib = _load_library()

lib.webhub_handler_create.argtypes = []
lib.webhub_handler_create.restype = c_void_p
lib.webhub_handler_destroy.argtypes = [c_void_p]
lib.webhub_handler_destroy.restype = None
lib.webhub_protocol_create.argtypes = [POINTER(c_ubyte), c_size_t]
lib.webhub_protocol_create.restype = c_void_p
lib.webhub_protocol_destroy.argtypes = [c_void_p]
lib.webhub_protocol_destroy.restype = None
lib.webhub_handler_render.argtypes = [
    c_void_p,
    c_void_p,
    c_char_p,
    c_char_p,
    c_char_p,
]
lib.webhub_handler_render.restype = c_void_p
lib.webhub_free.argtypes = [c_void_p]
lib.webhub_free.restype = None
lib.webhub_last_error.argtypes = []
lib.webhub_last_error.restype = c_char_p


def get_last_error() -> Optional[str]:
    error = lib.webhub_last_error()
    return error.decode("utf-8") if error else None


def fixture_protocol_path() -> str:
    script_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.abspath(os.path.join(script_dir, "..", "fixtures", "protocol.bin"))


def load_protocol() -> c_void_p:
    with open(fixture_protocol_path(), "rb") as protocol_file:
        protocol_bytes = protocol_file.read()
    buffer = (c_ubyte * len(protocol_bytes)).from_buffer_copy(protocol_bytes)
    protocol = lib.webhub_protocol_create(buffer, len(protocol_bytes))
    if not protocol:
        raise RuntimeError(get_last_error() or "failed to load protocol")
    return protocol


def render(handler: c_void_p, protocol: c_void_p, state_json: str) -> str:
    pointer = lib.webhub_handler_render(
        handler,
        protocol,
        state_json.encode("utf-8"),
        b"index.html",
        b"/",
    )
    if not pointer:
        raise RuntimeError(get_last_error() or "render failed")
    try:
        return ctypes.cast(pointer, c_char_p).value.decode("utf-8")
    finally:
        lib.webhub_free(pointer)


class TestLoadedProtocol(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.handler = lib.webhub_handler_create()
        cls.protocol = load_protocol()

    @classmethod
    def tearDownClass(cls):
        lib.webhub_protocol_destroy(cls.protocol)
        lib.webhub_handler_destroy(cls.handler)

    def test_signal_substitution(self):
        self.assertEqual(
            render(self.handler, self.protocol, '{"name":"webhub"}'),
            "<p>Hello, webhub!</p>",
        )

    def test_reuses_loaded_protocol(self):
        self.assertIn("First", render(self.handler, self.protocol, '{"name":"First"}'))
        self.assertIn("Second", render(self.handler, self.protocol, '{"name":"Second"}'))

    def test_invalid_json_sets_error(self):
        pointer = lib.webhub_handler_render(
            self.handler,
            self.protocol,
            b"NOT JSON",
            b"index.html",
            b"/",
        )
        self.assertFalse(pointer)
        self.assertIn("JSON", get_last_error() or "")

    def test_success_clears_previous_error(self):
        lib.webhub_handler_render(
            self.handler,
            self.protocol,
            b"NOT JSON",
            b"index.html",
            b"/",
        )
        self.assertIsNotNone(get_last_error())
        render(self.handler, self.protocol, '{"name":"webhub"}')
        self.assertIsNone(get_last_error())

    def test_null_protocol_sets_error(self):
        pointer = lib.webhub_handler_render(
            self.handler,
            None,
            b"{}",
            b"index.html",
            b"/",
        )
        self.assertFalse(pointer)
        self.assertIsNotNone(get_last_error())


class TestLifecycle(unittest.TestCase):
    def test_handler_create_and_destroy(self):
        handler = lib.webhub_handler_create()
        self.assertTrue(handler)
        lib.webhub_handler_destroy(handler)

    def test_null_destroy_and_free_are_safe(self):
        lib.webhub_handler_destroy(None)
        lib.webhub_protocol_destroy(None)
        lib.webhub_free(None)


if __name__ == "__main__":
    unittest.main()
