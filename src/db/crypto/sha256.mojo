"""SHA-256, HMAC-SHA-256 and PBKDF2-HMAC-SHA-256.

Implemented here rather than bound to libcrypto so the package has no native
dependency: a Mojo user should be able to `pixi add` this and connect, without
matching an OpenSSL ABI. Verified against the NIST and RFC test vectors in
tests/test_crypto.mojo.
"""

from max.algorithm import parallelize
from std.sys.info import simd_width_of as simdwidthof

comptime SHA256_BLOCK: Int = 64
comptime SHA256_DIGEST: Int = 32
comptime PARALLEL_COPY_THRESHOLD: Int = 16_777_216
comptime COPY_GRAIN: Int = 1_048_576
comptime COPY_WORKERS: Int = 8

def _round_constants() -> List[UInt32]:
    # A fresh list per digest rather than a module-level constant: mojo 1.2
    # dropped `InlineArray`, and the one compile-time fixed-size replacement
    # in this toolchain silently mis-binds its arguments past a few dozen
    # entries. The table is 256 bytes and sha256 already heap-allocates the
    # padded message, so this is not the bottleneck.
    return [
        0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
        0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
        0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
        0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
        0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
        0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
        0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
        0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
        0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
        0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
        0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
        0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
        0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
        0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
        0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
        0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
    ]


def _rotr(value: UInt32, bits: UInt32) -> UInt32:
    return (value >> bits) | (value << (UInt32(32) - bits))


def uses_parallel_copy(length: Int) -> Bool:
    return length >= PARALLEL_COPY_THRESHOLD


def _copy_message(mut target: List[UInt8], source: Span[UInt8, _]):
    comptime W = simdwidthof[DType.uint8]()
    var src = source.unsafe_ptr()
    var dst = Span(target).unsafe_ptr()
    var length = len(source)

    def copy_chunk(chunk: Int) { imm src, imm dst, imm length }:
        var first = chunk * COPY_GRAIN
        var last = min(first + COPY_GRAIN, length)
        var i = first
        while i + W <= last:
            dst.unsafe_store[alignment=1](
                i, src.unsafe_load[width=W, alignment=1](i)
            )
            i += W
        while i < last:
            dst.unsafe_store(i, src.unsafe_load(i))
            i += 1

    var chunks = (length + COPY_GRAIN - 1) // COPY_GRAIN
    if uses_parallel_copy(length):
        parallelize(copy_chunk, chunks, min(chunks, COPY_WORKERS))
    else:
        for chunk in range(chunks):
            copy_chunk(chunk)


@always_inline
def _copy_at(
    mut target: List[UInt8], offset: Int, source: Span[UInt8, _]
):
    comptime W = simdwidthof[DType.uint8]()
    var dst = Span(target).unsafe_ptr()
    var src = source.unsafe_ptr()
    var i = 0
    while i + W <= len(source):
        dst.store[alignment=1](
            offset + i,
            src.load[width=W, alignment=1](i),
        )
        i += W
    while i < len(source):
        target[offset + i] = source[i]
        i += 1


@always_inline
def _fill_hmac_pads(
    block: Span[UInt8, _],
    mut inner: List[UInt8],
    mut outer: List[UInt8],
):
    comptime W = simdwidthof[DType.uint8]()
    var block_ptr = block.unsafe_ptr()
    var inner_ptr = Span(inner).unsafe_ptr()
    var outer_ptr = Span(outer).unsafe_ptr()
    var i = 0
    while i + W <= SHA256_BLOCK:
        var key_chunk = block_ptr.load[width=W, alignment=1](i)
        inner_ptr.store[alignment=1](i, key_chunk ^ UInt8(0x36))
        outer_ptr.store[alignment=1](i, key_chunk ^ UInt8(0x5C))
        i += W
    while i < SHA256_BLOCK:
        inner[i] = block[i] ^ 0x36
        outer[i] = block[i] ^ 0x5C
        i += 1


@always_inline
def xor_in_place(mut target: List[UInt8], value: Span[UInt8, _]):
    comptime W = simdwidthof[DType.uint8]()
    var dst = Span(target).unsafe_ptr()
    var src = value.unsafe_ptr()
    var length = min(len(target), len(value))
    var i = 0
    while i + W <= length:
        dst.store[alignment=1](
            i,
            dst.load[width=W, alignment=1](i)
            ^ src.load[width=W, alignment=1](i),
        )
        i += W
    while i < length:
        dst[i] ^= src[i]
        i += 1


def constant_time_equal(
    left: Span[UInt8, _], right: Span[UInt8, _]
) -> Bool:
    if len(left) != len(right):
        return False
    comptime W = simdwidthof[DType.uint8]()
    var lhs = left.unsafe_ptr()
    var rhs = right.unsafe_ptr()
    var packed = SIMD[DType.uint32, W](0)
    var i = 0
    while i + W <= len(left):
        packed |= (
            lhs.load[width=W, alignment=1](i)
            ^ rhs.load[width=W, alignment=1](i)
        ).cast[DType.uint32]()
        i += W
    var mismatch = Int(packed.reduce_add()[0])
    while i < len(left):
        mismatch |= Int(left[i] ^ right[i])
        i += 1
    return mismatch == 0


def sha256(message: Span[UInt8, _]) -> List[UInt8]:
    """Digest a whole message."""
    return _sha256_core(message, _round_constants())


def _sha256_core(message: Span[UInt8, _], k: List[UInt32]) -> List[UInt8]:
    """Digest a whole message against an already-built round-constant table.

    Callers that hash in a loop build the table once with `_round_constants`
    and pass it in; building it costs about as much as compressing a short
    block, so `sha256` alone would pay that on every iteration.
    """
    var h0: UInt32 = 0x6A09E667
    var h1: UInt32 = 0xBB67AE85
    var h2: UInt32 = 0x3C6EF372
    var h3: UInt32 = 0xA54FF53A
    var h4: UInt32 = 0x510E527F
    var h5: UInt32 = 0x9B05688C
    var h6: UInt32 = 0x1F83D9AB
    var h7: UInt32 = 0x5BE0CD19

    var padded_length = (
        (len(message) + 1 + 8 + SHA256_BLOCK - 1) // SHA256_BLOCK
    ) * SHA256_BLOCK
    var bits = UInt64(len(message)) * 8
    var padded: List[UInt8]
    if uses_parallel_copy(len(message)):
        padded = List[UInt8](length=padded_length, fill=0)
        _copy_message(padded, message)
        padded[len(message)] = 0x80
        for i in range(8):
            padded[padded_length - 8 + i] = UInt8(
                (bits >> UInt64(56 - 8 * i)) & 0xFF
            )
    else:
        padded = List[UInt8](capacity=padded_length)
        for i in range(len(message)):
            padded.append(message[i])
        padded.append(0x80)
        while len(padded) < padded_length - 8:
            padded.append(0)
        for i in range(8):
            padded.append(UInt8((bits >> UInt64(56 - 8 * i)) & 0xFF))

    var w = List[UInt32](length=64, fill=0)
    var blocks = len(padded) // SHA256_BLOCK

    for block in range(blocks):
        var base = block * SHA256_BLOCK
        for i in range(16):
            var o = base + i * 4
            w[i] = (
                (UInt32(padded[o]) << 24)
                | (UInt32(padded[o + 1]) << 16)
                | (UInt32(padded[o + 2]) << 8)
                | UInt32(padded[o + 3])
            )
        for i in range(16, 64):
            var s0 = _rotr(w[i - 15], 7) ^ _rotr(w[i - 15], 18) ^ (w[i - 15] >> 3)
            var s1 = _rotr(w[i - 2], 17) ^ _rotr(w[i - 2], 19) ^ (w[i - 2] >> 10)
            w[i] = w[i - 16] + s0 + w[i - 7] + s1

        var a = h0
        var b = h1
        var c = h2
        var d = h3
        var e = h4
        var f = h5
        var g = h6
        var h = h7

        for i in range(64):
            var s1 = _rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25)
            var ch = (e & f) ^ ((~e) & g)
            var temp1 = h + s1 + ch + k[i] + w[i]
            var s0 = _rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22)
            var maj = (a & b) ^ (a & c) ^ (b & c)
            var temp2 = s0 + maj

            h = g
            g = f
            f = e
            e = d + temp1
            d = c
            c = b
            b = a
            a = temp1 + temp2

        h0 += a
        h1 += b
        h2 += c
        h3 += d
        h4 += e
        h5 += f
        h6 += g
        h7 += h

    var out = List[UInt8](capacity=SHA256_DIGEST)
    var state = List[UInt32](length=8, fill=0)
    state[0] = h0
    state[1] = h1
    state[2] = h2
    state[3] = h3
    state[4] = h4
    state[5] = h5
    state[6] = h6
    state[7] = h7
    for i in range(8):
        out.append(UInt8((state[i] >> 24) & 0xFF))
        out.append(UInt8((state[i] >> 16) & 0xFF))
        out.append(UInt8((state[i] >> 8) & 0xFF))
        out.append(UInt8(state[i] & 0xFF))
    return out^


def hmac_sha256(key: Span[UInt8, _], message: Span[UInt8, _]) -> List[UInt8]:
    """RFC 2104 HMAC over SHA-256."""
    var k = _round_constants()
    var block = List[UInt8](length=SHA256_BLOCK, fill=0)

    if len(key) > SHA256_BLOCK:
        var digest = _sha256_core(key, k)
        for i in range(len(digest)):
            block[i] = digest[i]
    else:
        for i in range(len(key)):
            block[i] = key[i]

    var inner = List[UInt8](
        length=SHA256_BLOCK + len(message), fill=0
    )
    var outer = List[UInt8](
        length=SHA256_BLOCK + SHA256_DIGEST, fill=0
    )
    _fill_hmac_pads(Span(block), inner, outer)
    _copy_at(inner, SHA256_BLOCK, message)

    var inner_digest = _sha256_core(Span(inner), k)
    _copy_at(outer, SHA256_BLOCK, Span(inner_digest))
    return _sha256_core(Span(outer), k)


def pbkdf2_sha256(
    password: Span[UInt8, _], salt: Span[UInt8, _], iterations: Int
) -> List[UInt8]:
    """PBKDF2 with a single output block, which is all SCRAM-SHA-256 needs.

    dkLen equals the digest length, so there is exactly one block and the
    INT(i) suffix is always 1.
    """
    var k = _round_constants()
    var seed = List[UInt8](capacity=len(salt) + 4)
    for i in range(len(salt)):
        seed.append(salt[i])
    seed.append(0)
    seed.append(0)
    seed.append(0)
    seed.append(1)

    var block = List[UInt8](length=SHA256_BLOCK, fill=0)
    if len(password) > SHA256_BLOCK:
        var password_digest = _sha256_core(password, k)
        _copy_at(block, 0, Span(password_digest))
    else:
        _copy_at(block, 0, password)

    var initial_inner = List[UInt8](
        length=SHA256_BLOCK + len(seed), fill=0
    )
    var round_inner = List[UInt8](
        length=SHA256_BLOCK + SHA256_DIGEST, fill=0
    )
    var outer = List[UInt8](
        length=SHA256_BLOCK + SHA256_DIGEST, fill=0
    )
    _fill_hmac_pads(Span(block), initial_inner, outer)
    _fill_hmac_pads(Span(block), round_inner, outer)
    _copy_at(initial_inner, SHA256_BLOCK, Span(seed))

    var inner_digest = _sha256_core(Span(initial_inner), k)
    _copy_at(outer, SHA256_BLOCK, Span(inner_digest))
    var u = _sha256_core(Span(outer), k)
    var result = u.copy()

    for _ in range(1, iterations):
        _copy_at(round_inner, SHA256_BLOCK, Span(u))
        inner_digest = _sha256_core(Span(round_inner), k)
        _copy_at(outer, SHA256_BLOCK, Span(inner_digest))
        u = _sha256_core(Span(outer), k)
        xor_in_place(result, Span(u))

    return result^


def to_hex(data: Span[UInt8, _]) -> String:
    var out = String("")
    for i in range(len(data)):
        var hi = Int(data[i] >> 4)
        var lo = Int(data[i] & 0x0F)
        out += chr(48 + hi if hi < 10 else 87 + hi)
        out += chr(48 + lo if lo < 10 else 87 + lo)
    return out^


def sha256_hex(message: Span[UInt8, _]) -> String:
    return to_hex(Span(sha256(message)))
