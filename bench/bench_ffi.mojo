"""C ABI used only by the Python benchmark harness."""

from db.crypto.md5 import md5
from db.crypto.sha256 import hmac_sha256, pbkdf2_sha256, sha256

comptime BytePtr = UnsafePointer[UInt8, AnyOrigin[mut=True]]


def _span(addr: Int, length: Int) -> Span[UInt8, AnyOrigin[mut=True]]:
    return Span(
        unsafe_ptr=BytePtr(unsafe_from_address=addr),
        length=length,
    )


def _copy_digest(digest: List[UInt8], dst_addr: Int):
    var dst = BytePtr(unsafe_from_address=dst_addr)
    for i in range(len(digest)):
        dst[i] = digest[i]


@export("mojo_db_sha256")
def mojo_db_sha256(src_addr: Int, length: Int, dst_addr: Int) abi("C"):
    _copy_digest(sha256(_span(src_addr, length)), dst_addr)


@export("mojo_db_md5")
def mojo_db_md5(src_addr: Int, length: Int, dst_addr: Int) abi("C"):
    _copy_digest(md5(_span(src_addr, length)), dst_addr)


@export("mojo_db_hmac_sha256")
def mojo_db_hmac_sha256(
    key_addr: Int,
    key_length: Int,
    src_addr: Int,
    length: Int,
    dst_addr: Int,
) abi("C"):
    _copy_digest(
        hmac_sha256(_span(key_addr, key_length), _span(src_addr, length)),
        dst_addr,
    )


@export("mojo_db_pbkdf2_sha256")
def mojo_db_pbkdf2_sha256(
    password_addr: Int,
    password_length: Int,
    salt_addr: Int,
    salt_length: Int,
    iterations: Int,
    dst_addr: Int,
) abi("C"):
    _copy_digest(
        pbkdf2_sha256(
            _span(password_addr, password_length),
            _span(salt_addr, salt_length),
            iterations,
        ),
        dst_addr,
    )
