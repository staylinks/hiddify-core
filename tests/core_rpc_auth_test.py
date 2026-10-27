"""Exercise the actual desktop shared library; never start a VPN or change routes.

Usage: python3 tests/core_rpc_auth_test.py /absolute/path/to/hiddify-core.so
Requires grpcio. Run in a separate process because the core changes its cwd.
"""
import ctypes
import os
import secrets
import socket
import sys
import tempfile
import unittest

import grpc


LIBRARY = None


class CoreRPCAuthenticationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if LIBRARY is None:
            raise unittest.SkipTest("run this probe with an explicit shared-library path")
        cls.directory = tempfile.TemporaryDirectory(prefix="staylink_core_auth_")
        os.makedirs(os.path.join(cls.directory.name, "data"))
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            cls.port = listener.getsockname()[1]
        cls.secret = secrets.token_hex(32)
        cls.library = ctypes.CDLL(LIBRARY)
        cls.library.setup.argtypes = [
            ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int,
            ctypes.c_char_p, ctypes.c_char_p, ctypes.c_longlong, ctypes.c_bool,
        ]
        cls.library.setup.restype = ctypes.c_void_p
        cls.library.freeString.argtypes = [ctypes.c_void_p]
        error = cls.setup_core(cls.secret)
        if error:
            raise RuntimeError(error)
        cls.channel = grpc.insecure_channel(f"127.0.0.1:{cls.port}")
        grpc.channel_ready_future(cls.channel).result(timeout=10)

    @classmethod
    def setup_core(cls, secret):
        directory = cls.directory.name.encode()
        pointer = cls.library.setup(
            directory, directory, directory, 3,
            f"127.0.0.1:{cls.port}".encode(), secret.encode(), 0, False,
        )
        try:
            return ctypes.string_at(pointer).decode()
        finally:
            cls.library.freeString(pointer)

    @classmethod
    def tearDownClass(cls):
        cls.channel.close()
        os.chdir("/tmp")
        cls.directory.cleanup()

    def test_unary_rejects_missing_wrong_and_duplicate_secrets(self):
        call = self.channel.unary_unary("/hello.Hello/SayHello")
        for metadata in [(), (("x-hiddify-secret", "wrong"),),
                         (("x-hiddify-secret", self.secret), ("x-hiddify-secret", "other"))]:
            with self.subTest(metadata_count=len(metadata)):
                with self.assertRaises(grpc.RpcError) as result:
                    call(b"", timeout=5, metadata=metadata)
                self.assertEqual(result.exception.code(), grpc.StatusCode.UNAUTHENTICATED)

    def test_authenticated_unary(self):
        response = self.channel.unary_unary("/hello.Hello/SayHello")(
            b"\x0a\x05probe", timeout=5, metadata=(("x-hiddify-secret", self.secret),),
        )
        self.assertIn(b"Hello, probe", response)

    def test_stream_rejects_missing_secret(self):
        call = self.channel.unary_stream("/hcore.Core/CoreInfoListener")(b"", timeout=5)
        try:
            with self.assertRaises(grpc.RpcError) as result:
                next(call)
            self.assertEqual(result.exception.code(), grpc.StatusCode.UNAUTHENTICATED)
        finally:
            call.cancel()

    def test_authenticated_state_stream(self):
        call = self.channel.unary_stream("/hcore.Core/CoreInfoListener")(
            b"", timeout=5, metadata=(("x-hiddify-secret", self.secret),),
        )
        try:
            self.assertIsInstance(next(call), bytes)
        finally:
            call.cancel()

    def test_desktop_native_launcher_rejects_empty_secret(self):
        self.assertNotEqual(self.setup_core(""), "")

    def test_binary_declares_supported_auth_abi(self):
        self.library.coreAuthVersion.restype = ctypes.c_int
        self.assertEqual(self.library.coreAuthVersion(), 1)

    def test_repeated_native_initialization_keeps_authenticated_connection(self):
        self.assertEqual(self.setup_core(self.secret), "")
        self.test_authenticated_unary()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        raise SystemExit("usage: core_rpc_auth_test.py /absolute/path/to/shared-library")
    LIBRARY = os.path.abspath(sys.argv.pop(1))
    unittest.main(verbosity=2)
