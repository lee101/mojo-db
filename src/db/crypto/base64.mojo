"""Base64, standard alphabet with padding (RFC 4648)."""

comptime ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def encode(data: Span[UInt8, _]) -> String:
    var table = ALPHABET.as_bytes()
    var out = String("")
    var i = 0

    while i + 2 < len(data):
        var n = (
            (UInt32(data[i]) << 16) | (UInt32(data[i + 1]) << 8) | UInt32(data[i + 2])
        )
        out += chr(Int(table[Int((n >> 18) & 63)]))
        out += chr(Int(table[Int((n >> 12) & 63)]))
        out += chr(Int(table[Int((n >> 6) & 63)]))
        out += chr(Int(table[Int(n & 63)]))
        i += 3

    var remaining = len(data) - i
    if remaining == 1:
        var n = UInt32(data[i]) << 16
        out += chr(Int(table[Int((n >> 18) & 63)]))
        out += chr(Int(table[Int((n >> 12) & 63)]))
        out += "=="
    elif remaining == 2:
        var n = (UInt32(data[i]) << 16) | (UInt32(data[i + 1]) << 8)
        out += chr(Int(table[Int((n >> 18) & 63)]))
        out += chr(Int(table[Int((n >> 12) & 63)]))
        out += chr(Int(table[Int((n >> 6) & 63)]))
        out += "="

    return out^


def _value(c: UInt8) -> Int:
    if c >= 65 and c <= 90:
        return Int(c) - 65
    if c >= 97 and c <= 122:
        return Int(c) - 97 + 26
    if c >= 48 and c <= 57:
        return Int(c) - 48 + 52
    if c == 43:  # '+'
        return 62
    if c == 47:  # '/'
        return 63
    return -1


def decode(text: StringSlice) raises -> List[UInt8]:
    var bytes = text.as_bytes()
    var out = List[UInt8]()
    var accumulator = 0
    var bits = 0

    for i in range(len(bytes)):
        var c = bytes[i]
        if c == 61:  # '=' padding ends the stream
            break
        # Whitespace is tolerated: wrapped base64 is common in config files.
        if c == 10 or c == 13 or c == 32 or c == 9:
            continue
        var value = _value(c)
        if value < 0:
            raise Error("invalid base64 character at offset " + String(i))
        accumulator = (accumulator << 6) | value
        bits += 6
        if bits >= 8:
            bits -= 8
            out.append(UInt8((accumulator >> bits) & 0xFF))

    return out^


def encode_string(text: StringSlice) -> String:
    var data = List[UInt8]()
    var bytes = text.as_bytes()
    for i in range(len(bytes)):
        data.append(bytes[i])
    return encode(Span(data))
