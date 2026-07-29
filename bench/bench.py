#!/usr/bin/env python3
"""Warm, repeated mojo-db crypto benchmarks against Python's hashlib."""

from __future__ import annotations

import ctypes
import hashlib
import hmac
import os
import platform
import statistics
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable


ROOT = Path(__file__).resolve().parents[1]
REPEATS = int(os.environ.get("MOJO_DB_BENCH_REPEATS", "9"))
WARMUPS = 3
TARGET_SAMPLE_SECONDS = float(os.environ.get("MOJO_DB_BENCH_SAMPLE_SECONDS", "0.08"))


@dataclass(frozen=True)
class Case:
    operation: str
    input_size: str
    mojo: Callable[[], bytes]
    baseline: Callable[[], bytes]


def build_library() -> Path:
    configured = os.environ.get("MOJO_DB_BENCH_LIBRARY")
    if configured:
        return Path(configured)
    library = Path(tempfile.gettempdir()) / "libmojo_db_bench.so"
    subprocess.run(
        [
            "mojo",
            "build",
            "--emit",
            "shared-lib",
            str(ROOT / "bench" / "bench_ffi.mojo"),
            "-I",
            str(ROOT / "src"),
            "-o",
            str(library),
        ],
        check=True,
        cwd=ROOT,
    )
    return library


def address(buffer: ctypes.Array[ctypes.c_ubyte]) -> int:
    return ctypes.addressof(buffer)


def as_buffer(data: bytearray) -> ctypes.Array[ctypes.c_ubyte]:
    return (ctypes.c_ubyte * len(data)).from_buffer(data)


def measure(function: Callable[[], bytes]) -> tuple[float, int]:
    for _ in range(WARMUPS):
        function()

    start = time.perf_counter_ns()
    function()
    elapsed = max(time.perf_counter_ns() - start, 1)
    loops = max(1, int(TARGET_SAMPLE_SECONDS * 1e9 / elapsed))
    loops = min(loops, 10_000)

    samples = []
    for _ in range(REPEATS):
        start = time.perf_counter_ns()
        for _ in range(loops):
            function()
        samples.append((time.perf_counter_ns() - start) / loops)
    return statistics.median(samples), loops


def bind_library() -> tuple[ctypes.CDLL, list[Case]]:
    library = ctypes.CDLL(str(build_library()))
    for name, arg_count in (
        ("mojo_db_sha256", 3),
        ("mojo_db_md5", 3),
        ("mojo_db_hmac_sha256", 5),
        ("mojo_db_pbkdf2_sha256", 6),
    ):
        function = getattr(library, name)
        function.argtypes = [ctypes.c_ssize_t] * arg_count
        function.restype = None

    large = bytearray((i * 17 + 31) & 0xFF for i in range(1024 * 1024))
    parallel_data = bytearray(b"a") * (16 * 1024 * 1024)
    medium = bytearray((i * 29 + 7) & 0xFF for i in range(64 * 1024))
    key = bytearray(b"benchmark-key-" * 3)
    password = bytearray(b"correct horse battery staple")
    salt = bytearray(b"postgres-benchmark-salt")
    large_buffer = as_buffer(large)
    parallel_buffer = as_buffer(parallel_data)
    medium_buffer = as_buffer(medium)
    key_buffer = as_buffer(key)
    password_buffer = as_buffer(password)
    salt_buffer = as_buffer(salt)

    sha_out = (ctypes.c_ubyte * 32)()
    parallel_sha_out = (ctypes.c_ubyte * 32)()
    md5_out = (ctypes.c_ubyte * 16)()
    hmac_out = (ctypes.c_ubyte * 32)()
    pbkdf_out = (ctypes.c_ubyte * 32)()

    def mojo_sha256() -> bytes:
        library.mojo_db_sha256(address(large_buffer), len(large), address(sha_out))
        return bytes(sha_out)

    def mojo_md5() -> bytes:
        library.mojo_db_md5(address(large_buffer), len(large), address(md5_out))
        return bytes(md5_out)

    def mojo_parallel_sha256() -> bytes:
        library.mojo_db_sha256(
            address(parallel_buffer),
            len(parallel_data),
            address(parallel_sha_out),
        )
        return bytes(parallel_sha_out)

    def mojo_hmac() -> bytes:
        library.mojo_db_hmac_sha256(
            address(key_buffer),
            len(key),
            address(medium_buffer),
            len(medium),
            address(hmac_out),
        )
        return bytes(hmac_out)

    def mojo_pbkdf2() -> bytes:
        library.mojo_db_pbkdf2_sha256(
            address(password_buffer),
            len(password),
            address(salt_buffer),
            len(salt),
            4096,
            address(pbkdf_out),
        )
        return bytes(pbkdf_out)

    cases = [
        Case(
            "SHA-256",
            "1 MiB",
            mojo_sha256,
            lambda: hashlib.sha256(large).digest(),
        ),
        Case(
            "SHA-256 (parallel copy)",
            "16 MiB",
            mojo_parallel_sha256,
            lambda: hashlib.sha256(parallel_data).digest(),
        ),
        Case("MD5", "1 MiB", mojo_md5, lambda: hashlib.md5(large).digest()),
        Case(
            "HMAC-SHA-256",
            "64 KiB",
            mojo_hmac,
            lambda: hmac.digest(key, medium, "sha256"),
        ),
        Case(
            "PBKDF2-HMAC-SHA-256",
            "4096 iterations",
            mojo_pbkdf2,
            lambda: hashlib.pbkdf2_hmac("sha256", password, salt, 4096, 32),
        ),
    ]
    return library, cases


def format_time(nanoseconds: float) -> str:
    if nanoseconds >= 1e6:
        return f"{nanoseconds / 1e6:.3f} ms"
    return f"{nanoseconds / 1e3:.3f} us"


def main() -> None:
    _, cases = bind_library()
    selected = os.environ.get("MOJO_DB_BENCH_CASE")
    if selected:
        cases = [case for case in cases if case.operation == selected]
        if not cases:
            raise ValueError(f"unknown benchmark case: {selected}")
    print(
        f"Python {platform.python_version()} on {platform.machine()}, "
        f"{REPEATS} repeats, median"
    )
    print("| Operation | Input | mojo-db | Python hashlib | Speedup |")
    print("|---|---:|---:|---:|---:|")
    for case in cases:
        expected = case.baseline()
        actual = case.mojo()
        if actual != expected:
            raise RuntimeError(f"{case.operation} result differs from hashlib")
        mojo_ns, loops = measure(case.mojo)
        baseline_ns, _ = measure(case.baseline)
        speedup = baseline_ns / mojo_ns
        print(
            f"| {case.operation} | {case.input_size} | {format_time(mojo_ns)} | "
            f"{format_time(baseline_ns)} | {speedup:.2f}x |"
        )
        print(
            f"  samples: {loops} calls/sample for mojo-db",
            file=os.sys.stderr,
        )


if __name__ == "__main__":
    main()
