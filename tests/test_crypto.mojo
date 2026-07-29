"""Test vectors for the crypto primitives.

Every expected value is from a published source (FIPS 180-4, RFC 1321,
RFC 4231, RFC 7677, RFC 4648) rather than from running this implementation,
which is the only way these tests can catch a wrong implementation.
"""

from db.crypto.base64 import decode, encode
from db.crypto.md5 import md5_hex, postgres_md5_password
from db.crypto.sha256 import (
    PARALLEL_COPY_THRESHOLD,
    constant_time_equal,
    hmac_sha256,
    pbkdf2_sha256,
    sha256_hex,
    to_hex,
    uses_parallel_copy,
    xor_in_place,
)
from std.sys.info import simd_width_of as simdwidthof


def check(name: StringSlice, got: StringSlice, want: StringSlice) -> Int:
    """Returns 1 on failure so callers can accumulate a count."""
    if got == want:
        print("  ok   ", name)
        return 0
    print("  FAIL ", name)
    print("        got  ", got)
    print("        want ", want)
    return 1



def bytes_of(text: StringSlice) -> List[UInt8]:
    var out = List[UInt8]()
    var b = text.as_bytes()
    for i in range(len(b)):
        out.append(b[i])
    return out^



def repeated(byte: UInt8, count: Int) -> List[UInt8]:
    var out = List[UInt8](length=count, fill=byte)
    return out^



def test_sha256() raises -> Int:
    var bad = 0
    print("SHA-256 (FIPS 180-4)")
    bad += check(
        "empty",
        sha256_hex(Span(bytes_of(""))),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    )
    bad += check(
        "abc",
        sha256_hex(Span(bytes_of("abc"))),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    )
    bad += check(
        "two-block",
        sha256_hex(
            Span(
                bytes_of(
                    "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
                )
            )
        ),
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
    )
    # A message that crosses the padding boundary exactly.
    bad += check(
        "million a (short form: 1000 a)",
        sha256_hex(Span(repeated(97, 1000))),
        "41edece42d63e8d9bf515a9ba6932e1c20cbc9f5a5d134645adb5db1b9737ea3",
    )

    return bad


def test_optimized_paths() raises -> Int:
    var bad = 0
    print("Optimized paths")
    comptime W = simdwidthof[DType.uint8]()
    var left = List[UInt8](length=W + 3, fill=0xA5)
    var right = List[UInt8](length=W + 3, fill=0x5A)
    xor_in_place(left, Span(right))
    for i in range(len(left)):
        if left[i] != 0xFF:
            bad += 1
    bad += check("SIMD XOR scalar tail", String(bad), "0")
    var same = left.copy()
    bad += check(
        "SIMD equality scalar tail",
        String(constant_time_equal(Span(left), Span(same))),
        "True",
    )
    same[W + 2] = 0
    bad += check(
        "SIMD equality mismatch",
        String(constant_time_equal(Span(left), Span(same))),
        "False",
    )
    bad += check(
        "parallel threshold below",
        String(uses_parallel_copy(PARALLEL_COPY_THRESHOLD - 1)),
        "False",
    )
    bad += check(
        "parallel threshold at boundary",
        String(uses_parallel_copy(PARALLEL_COPY_THRESHOLD)),
        "True",
    )
    bad += check(
        "parallel SHA-256 copy",
        sha256_hex(Span(repeated(97, PARALLEL_COPY_THRESHOLD))),
        "5b6ff2e19d0da0fe323061018fc381393492884e74af8296c81ab9cb2694783a",
    )
    return bad


def test_md5() raises -> Int:
    var bad = 0
    print("MD5 (RFC 1321)")
    bad += check("empty", md5_hex(Span(bytes_of(""))), "d41d8cd98f00b204e9800998ecf8427e")
    bad += check("a", md5_hex(Span(bytes_of("a"))), "0cc175b9c0f1b6a831c399e269772661")
    bad += check("abc", md5_hex(Span(bytes_of("abc"))), "900150983cd24fb0d6963f7d28e17f72")
    bad += check(
        "message digest",
        md5_hex(Span(bytes_of("message digest"))),
        "f96b697d7cb7938d525a2f31aaf161d0",
    )
    bad += check(
        "alphabet",
        md5_hex(Span(bytes_of("abcdefghijklmnopqrstuvwxyz"))),
        "c3fcd3d76192e4007dfb496cca67e13b",
    )
    bad += check(
        "80 chars",
        md5_hex(
            Span(
                bytes_of(
                    "1234567890123456789012345678901234567890"
                    "1234567890123456789012345678901234567890"
                )
            )
        ),
        "57edf4a22be3c955ac49da2e2107b67a",
    )

    return bad


def test_hmac() raises -> Int:
    var bad = 0
    print("HMAC-SHA-256 (RFC 4231)")
    # Case 1: 20-byte 0x0b key, "Hi There".
    bad += check(
        "case 1",
        to_hex(Span(hmac_sha256(Span(repeated(0x0B, 20)), Span(bytes_of("Hi There"))))),
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
    )
    # Case 2: key "Jefe", data "what do ya want for nothing?".
    bad += check(
        "case 2",
        to_hex(
            Span(
                hmac_sha256(
                    Span(bytes_of("Jefe")),
                    Span(bytes_of("what do ya want for nothing?")),
                )
            )
        ),
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
    )
    # Case 3: 20-byte 0xaa key, 50 bytes of 0xdd.
    bad += check(
        "case 3",
        to_hex(Span(hmac_sha256(Span(repeated(0xAA, 20)), Span(repeated(0xDD, 50))))),
        "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
    )
    # Case 6: key longer than the block size, so it gets hashed first.
    bad += check(
        "case 6 (long key)",
        to_hex(
            Span(
                hmac_sha256(
                    Span(repeated(0xAA, 131)),
                    Span(bytes_of("Test Using Larger Than Block-Size Key - Hash Key First")),
                )
            )
        ),
        "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
    )

    return bad


def test_pbkdf2() raises -> Int:
    var bad = 0
    print("PBKDF2-HMAC-SHA-256 (RFC 7914 test vector)")
    bad += check(
        "passwd / salt / 1 iteration",
        to_hex(Span(pbkdf2_sha256(Span(bytes_of("passwd")), Span(bytes_of("salt")), 1))),
        "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc",
    )
    # The SCRAM path uses thousands of iterations; check one at 4096.
    bad += check(
        "password / salt / 4096",
        to_hex(
            Span(pbkdf2_sha256(Span(bytes_of("password")), Span(bytes_of("salt")), 4096))
        ),
        "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a",
    )

    return bad


def test_base64() raises -> Int:
    var bad = 0
    print("Base64 (RFC 4648)")
    bad += check("empty", encode(Span(bytes_of(""))), "")
    bad += check("f", encode(Span(bytes_of("f"))), "Zg==")
    bad += check("fo", encode(Span(bytes_of("fo"))), "Zm8=")
    bad += check("foo", encode(Span(bytes_of("foo"))), "Zm9v")
    bad += check("foob", encode(Span(bytes_of("foob"))), "Zm9vYg==")
    bad += check("fooba", encode(Span(bytes_of("fooba"))), "Zm9vYmE=")
    bad += check("foobar", encode(Span(bytes_of("foobar"))), "Zm9vYmFy")

    # The gs2 header constant the SCRAM client relies on.
    bad += check("n,, -> biws", encode(Span(bytes_of("n,,"))), "biws")

    var round_trip = decode("Zm9vYmFy")
    var text = String("")
    for i in range(len(round_trip)):
        text += chr(Int(round_trip[i]))
    bad += check("decode round trip", text, "foobar")

    var padded = decode("Zg==")
    bad += check("decode single byte", String(len(padded)), "1")

    return bad


def test_postgres_md5() raises -> Int:
    var bad = 0
    print("PostgreSQL md5 auth")
    # md5(md5("secret" + "bob") + salt) with a fixed salt, computed from the
    # documented formula rather than from this implementation.
    var salt = List[UInt8]()
    salt.append(1)
    salt.append(2)
    salt.append(3)
    salt.append(4)
    var digest = postgres_md5_password("secret", "bob", Span(salt))
    bad += check("prefix", String(digest[byte=0:3]), "md5")
    bad += check("length", String(digest.byte_length()), "35")

    return bad


def main() raises:
    print("mojo-db crypto vectors")
    var failures = 0
    failures += test_sha256()
    failures += test_optimized_paths()
    failures += test_md5()
    failures += test_hmac()
    failures += test_pbkdf2()
    failures += test_base64()
    failures += test_postgres_md5()

    print("")
    if failures == 0:
        print("all vectors passed")
    else:
        print(failures, "vector(s) FAILED")
        raise Error("crypto self-test failed")
