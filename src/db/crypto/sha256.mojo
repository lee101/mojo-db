"""SHA-256, HMAC-SHA-256 and PBKDF2-HMAC-SHA-256.

Implemented here rather than bound to libcrypto so the package has no native
dependency: a Mojo user should be able to `pixi add` this and connect, without
matching an OpenSSL ABI. Verified against the NIST and RFC test vectors in
tests/test_crypto.mojo.
"""

comptime SHA256_BLOCK: Int = 64
comptime SHA256_DIGEST: Int = 32

def _round_constants() -> List[Int]:
    """First 32 bits of the fractional parts of the cube roots of the first
    64 primes. Built per call: a comptime list cannot be indexed by a runtime
    value, and hoisting it here keeps the inner loop free of the cast."""
    return [0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5, 0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174, 0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA, 0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967, 0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85, 0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070, 0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3, 0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2]


def _rotr(value: UInt32, bits: UInt32) -> UInt32:
    return (value >> bits) | (value << (UInt32(32) - bits))


def sha256(message: Span[UInt8, _]) -> List[UInt8]:
    """Digest a whole message."""
    var h0: UInt32 = 0x6A09E667
    var h1: UInt32 = 0xBB67AE85
    var h2: UInt32 = 0x3C6EF372
    var h3: UInt32 = 0xA54FF53A
    var h4: UInt32 = 0x510E527F
    var h5: UInt32 = 0x9B05688C
    var h6: UInt32 = 0x1F83D9AB
    var h7: UInt32 = 0x5BE0CD19

    # Pad: 0x80, zeros, then the 64-bit big-endian bit length.
    var padded = List[UInt8](capacity=len(message) + 72)
    for i in range(len(message)):
        padded.append(message[i])
    padded.append(0x80)
    while len(padded) % SHA256_BLOCK != 56:
        padded.append(0)
    var bits = UInt64(len(message)) * 8
    for i in range(8):
        padded.append(UInt8((bits >> UInt64(56 - 8 * i)) & 0xFF))

    var k = _round_constants()
    var w = InlineArray[UInt32, 64](fill=0)
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
            var temp1 = h + s1 + ch + UInt32(k[i]) + w[i]
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
    var state = InlineArray[UInt32, 8](fill=0)
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
    var block = List[UInt8](length=SHA256_BLOCK, fill=0)

    if len(key) > SHA256_BLOCK:
        var digest = sha256(key)
        for i in range(len(digest)):
            block[i] = digest[i]
    else:
        for i in range(len(key)):
            block[i] = key[i]

    var inner = List[UInt8](capacity=SHA256_BLOCK + len(message))
    var outer = List[UInt8](capacity=SHA256_BLOCK + SHA256_DIGEST)
    for i in range(SHA256_BLOCK):
        inner.append(block[i] ^ 0x36)
        outer.append(block[i] ^ 0x5C)
    for i in range(len(message)):
        inner.append(message[i])

    var inner_digest = sha256(Span(inner))
    for i in range(len(inner_digest)):
        outer.append(inner_digest[i])
    return sha256(Span(outer))


def pbkdf2_sha256(
    password: Span[UInt8, _], salt: Span[UInt8, _], iterations: Int
) -> List[UInt8]:
    """PBKDF2 with a single output block, which is all SCRAM-SHA-256 needs.

    dkLen equals the digest length, so there is exactly one block and the
    INT(i) suffix is always 1.
    """
    var seed = List[UInt8](capacity=len(salt) + 4)
    for i in range(len(salt)):
        seed.append(salt[i])
    seed.append(0)
    seed.append(0)
    seed.append(0)
    seed.append(1)

    var u = hmac_sha256(password, Span(seed))
    var result = u.copy()

    for _ in range(1, iterations):
        u = hmac_sha256(password, Span(u))
        for i in range(len(result)):
            result[i] ^= u[i]

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
