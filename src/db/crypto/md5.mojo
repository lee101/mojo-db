"""MD5, for PostgreSQL's legacy `md5` authentication method only.

MD5 is broken for every purpose that matters and must not be used for anything
new. It is here because `password_encryption = md5` servers still exist and a
driver that cannot talk to them is not a complete driver.
"""

from std.sys.info import simd_width_of as simdwidthof

comptime MD5_BLOCK: Int = 64


def _shifts() -> List[Int]:
    return [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21]


def _sines() -> List[Int]:
    return [0xD76AA478, 0xE8C7B756, 0x242070DB, 0xC1BDCEEE, 0xF57C0FAF, 0x4787C62A, 0xA8304613, 0xFD469501, 0x698098D8, 0x8B44F7AF, 0xFFFF5BB1, 0x895CD7BE, 0x6B901122, 0xFD987193, 0xA679438E, 0x49B40821, 0xF61E2562, 0xC040B340, 0x265E5A51, 0xE9B6C7AA, 0xD62F105D, 0x02441453, 0xD8A1E681, 0xE7D3FBC8, 0x21E1CDE6, 0xC33707D6, 0xF4D50D87, 0x455A14ED, 0xA9E3E905, 0xFCEFA3F8, 0x676F02D9, 0x8D2A4C8A, 0xFFFA3942, 0x8771F681, 0x6D9D6122, 0xFDE5380C, 0xA4BEEA44, 0x4BDECFA9, 0xF6BB4B60, 0xBEBFBC70, 0x289B7EC6, 0xEAA127FA, 0xD4EF3085, 0x04881D05, 0xD9D4D039, 0xE6DB99E5, 0x1FA27CF8, 0xC4AC5665, 0xF4292244, 0x432AFF97, 0xAB9423A7, 0xFC93A039, 0x655B59C3, 0x8F0CCC92, 0xFFEFF47D, 0x85845DD1, 0x6FA87E4F, 0xFE2CE6E0, 0xA3014314, 0x4E0811A1, 0xF7537E82, 0xBD3AF235, 0x2AD7D2BB, 0xEB86D391]


def _rotl(value: UInt32, bits: UInt32) -> UInt32:
    return (value << bits) | (value >> (UInt32(32) - bits))


def md5(message: Span[UInt8, _]) -> List[UInt8]:
    var a0: UInt32 = 0x67452301
    var b0: UInt32 = 0xEFCDAB89
    var c0: UInt32 = 0x98BADCFE
    var d0: UInt32 = 0x10325476

    var padded_length = (
        (len(message) + 1 + 8 + MD5_BLOCK - 1) // MD5_BLOCK
    ) * MD5_BLOCK
    var padded = List[UInt8](length=padded_length, fill=0)
    comptime W = simdwidthof[DType.uint8]()
    var src = message.unsafe_ptr()
    var dst = Span(padded).unsafe_ptr()
    var offset = 0
    while offset + W <= len(message):
        dst.store[alignment=1](
            offset, src.load[width=W, alignment=1](offset)
        )
        offset += W
    while offset < len(message):
        padded[offset] = message[offset]
        offset += 1
    padded[len(message)] = 0x80
    var bits = UInt64(len(message)) * 8
    for i in range(8):
        padded[padded_length - 8 + i] = UInt8(
            (bits >> UInt64(8 * i)) & 0xFF
        )

    var shifts = _shifts()
    var sines = _sines()
    var m = List[UInt32](length=16, fill=0)
    var blocks = len(padded) // MD5_BLOCK

    for block in range(blocks):
        var base = block * MD5_BLOCK
        for i in range(16):
            var o = base + i * 4
            m[i] = (
                UInt32(padded[o])
                | (UInt32(padded[o + 1]) << 8)
                | (UInt32(padded[o + 2]) << 16)
                | (UInt32(padded[o + 3]) << 24)
            )

        var a = a0
        var b = b0
        var c = c0
        var d = d0

        for i in range(64):
            var f: UInt32
            var g: Int
            if i < 16:
                f = (b & c) | ((~b) & d)
                g = i
            elif i < 32:
                f = (d & b) | ((~d) & c)
                g = (5 * i + 1) % 16
            elif i < 48:
                f = b ^ c ^ d
                g = (3 * i + 5) % 16
            else:
                f = c ^ (b | (~d))
                g = (7 * i) % 16

            var temp = d
            d = c
            c = b
            b = b + _rotl(a + f + UInt32(sines[i]) + m[g], UInt32(shifts[i]))
            a = temp

        a0 += a
        b0 += b
        c0 += c
        d0 += d

    var out = List[UInt8](capacity=16)
    var state = List[UInt32](length=4, fill=0)
    state[0] = a0
    state[1] = b0
    state[2] = c0
    state[3] = d0
    for i in range(4):
        out.append(UInt8(state[i] & 0xFF))
        out.append(UInt8((state[i] >> 8) & 0xFF))
        out.append(UInt8((state[i] >> 16) & 0xFF))
        out.append(UInt8((state[i] >> 24) & 0xFF))
    return out^


def md5_hex(message: Span[UInt8, _]) -> String:
    var digest = md5(message)
    var out = String("")
    for i in range(len(digest)):
        var hi = Int(digest[i] >> 4)
        var lo = Int(digest[i] & 0x0F)
        out += chr(48 + hi if hi < 10 else 87 + hi)
        out += chr(48 + lo if lo < 10 else 87 + lo)
    return out^


def postgres_md5_password(
    password: StringSlice, user: StringSlice, salt: Span[UInt8, _]
) -> String:
    """"md5" + md5(md5(password + user) + salt), as the server expects."""
    var first = List[UInt8]()
    var pw = password.as_bytes()
    var us = user.as_bytes()
    for i in range(len(pw)):
        first.append(pw[i])
    for i in range(len(us)):
        first.append(us[i])

    var inner = md5_hex(Span(first))
    var second = List[UInt8]()
    var inner_bytes = inner.as_bytes()
    for i in range(len(inner_bytes)):
        second.append(inner_bytes[i])
    for i in range(len(salt)):
        second.append(salt[i])

    return String("md5") + md5_hex(Span(second))
