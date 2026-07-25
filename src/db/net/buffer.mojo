"""Byte buffers with big-endian codecs.

Every protocol here is network byte order, so the encoders default to
big-endian and the little-endian case simply does not exist. Buffers own their
storage and are reused across messages: a query loop should not allocate per
round trip.
"""


struct WriteBuffer(Movable):
    """Append-only byte builder."""

    var data: List[UInt8]

    def __init__(out self):
        self.data = List[UInt8]()

    def __init__(out self, capacity: Int):
        self.data = List[UInt8](capacity=capacity)

    def clear(mut self):
        self.data.clear()

    def size(self) -> Int:
        return len(self.data)

    def byte(mut self, value: UInt8):
        self.data.append(value)

    def bytes(mut self, value: Span[UInt8, _]):
        for i in range(len(value)):
            self.data.append(value[i])

    def i16(mut self, value: Int16):
        var u = UInt16(value)
        self.data.append(UInt8((u >> 8) & 0xFF))
        self.data.append(UInt8(u & 0xFF))

    def i32(mut self, value: Int32):
        var u = UInt32(value)
        self.data.append(UInt8((u >> 24) & 0xFF))
        self.data.append(UInt8((u >> 16) & 0xFF))
        self.data.append(UInt8((u >> 8) & 0xFF))
        self.data.append(UInt8(u & 0xFF))

    def string(mut self, value: StringSlice):
        """Raw string bytes, no terminator."""
        var b = value.as_bytes()
        for i in range(len(b)):
            self.data.append(b[i])

    def cstring(mut self, value: StringSlice):
        """Null-terminated string, the shape most of these protocols use."""
        self.string(value)
        self.data.append(0)

    def patch_i32(mut self, offset: Int, value: Int32):
        """Backfill a length prefix once the body length is known."""
        var u = UInt32(value)
        self.data[offset] = UInt8((u >> 24) & 0xFF)
        self.data[offset + 1] = UInt8((u >> 16) & 0xFF)
        self.data[offset + 2] = UInt8((u >> 8) & 0xFF)
        self.data[offset + 3] = UInt8(u & 0xFF)

    def span(self) -> Span[UInt8, origin_of(self.data)]:
        return Span(self.data)


struct ReadBuffer(Movable):
    """Cursor over a received message body."""

    var data: List[UInt8]
    var pos: Int

    def __init__(out self):
        self.data = List[UInt8]()
        self.pos = 0

    def __init__(out self, var data: List[UInt8]):
        self.data = data^
        self.pos = 0

    def reset(mut self):
        self.data.clear()
        self.pos = 0

    def remaining(self) -> Int:
        return len(self.data) - self.pos

    def at_end(self) -> Bool:
        return self.pos >= len(self.data)

    def byte(mut self) raises -> UInt8:
        if self.pos >= len(self.data):
            raise Error("read past end of message")
        var value = self.data[self.pos]
        self.pos += 1
        return value

    def i16(mut self) raises -> Int16:
        if self.pos + 2 > len(self.data):
            raise Error("read past end of message")
        var value = (UInt16(self.data[self.pos]) << 8) | UInt16(self.data[self.pos + 1])
        self.pos += 2
        return Int16(value)

    def i32(mut self) raises -> Int32:
        if self.pos + 4 > len(self.data):
            raise Error("read past end of message")
        var value = (
            (UInt32(self.data[self.pos]) << 24)
            | (UInt32(self.data[self.pos + 1]) << 16)
            | (UInt32(self.data[self.pos + 2]) << 8)
            | UInt32(self.data[self.pos + 3])
        )
        self.pos += 4
        return Int32(value)

    def cstring(mut self) raises -> String:
        var out = String("")
        while True:
            if self.pos >= len(self.data):
                raise Error("unterminated string in message")
            var c = self.data[self.pos]
            self.pos += 1
            if c == 0:
                break
            out += chr(Int(c))
        return out^

    def take(mut self, count: Int) raises -> List[UInt8]:
        if self.pos + count > len(self.data):
            raise Error("read past end of message")
        var out = List[UInt8](capacity=count)
        for i in range(count):
            out.append(self.data[self.pos + i])
        self.pos += count
        return out^

    def take_string(mut self, count: Int) raises -> String:
        if self.pos + count > len(self.data):
            raise Error("read past end of message")
        var out = String("")
        for i in range(count):
            out += chr(Int(self.data[self.pos + i]))
        self.pos += count
        return out^

    def skip(mut self, count: Int) raises:
        if self.pos + count > len(self.data):
            raise Error("read past end of message")
        self.pos += count


def to_bytes(value: StringSlice) -> List[UInt8]:
    var out = List[UInt8]()
    var b = value.as_bytes()
    for i in range(len(b)):
        out.append(b[i])
    return out^


def bytes_to_string(value: Span[UInt8, _]) -> String:
    var out = String("")
    for i in range(len(value)):
        out += chr(Int(value[i]))
    return out^
