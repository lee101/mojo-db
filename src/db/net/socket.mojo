"""Blocking TCP client sockets.

Database clients are request/response and almost always used from a thread
that is willing to wait, so these are blocking sockets with timeouts rather
than an event loop. A caller that wants concurrency runs connections on
separate threads or processes.

Timeouts use SO_RCVTIMEO/SO_SNDTIMEO so a wedged server surfaces as an error
instead of hanging the caller forever - the failure mode that makes a database
outage look like an application hang.
"""

from std.ffi import external_call
from std.memory import UnsafePointer

comptime AF_INET: Int32 = 2
comptime AF_INET6: Int32 = 10
comptime SOCK_STREAM: Int32 = 1
comptime SOL_SOCKET: Int32 = 1
comptime SO_RCVTIMEO: Int32 = 20
comptime SO_SNDTIMEO: Int32 = 21
comptime SO_KEEPALIVE: Int32 = 9
comptime IPPROTO_TCP: Int32 = 6
comptime TCP_NODELAY: Int32 = 1

comptime EINTR: Int32 = 4
comptime EAGAIN: Int32 = 11
comptime EWOULDBLOCK: Int32 = 11

comptime SOCKADDR_IN_SIZE: Int = 16
comptime SOCKADDR_IN6_SIZE: Int = 28
comptime TIMEVAL_SIZE: Int = 16


def errno() -> Int32:
    var addr = external_call["__errno_location", Int]()
    if addr == 0:
        return 0
    return UnsafePointer[Int32, ImmStaticOrigin](unsafe_from_address=addr)[]


def _htons(port: UInt16) -> UInt16:
    return ((port & 0x00FF) << 8) | ((port & 0xFF00) >> 8)


def parse_ipv4(text: StringSlice) -> Tuple[Bool, UInt32]:
    """Parse dotted-quad into a big-endian-ordered byte quartet.

    Returns (ok, packed) where packed holds the octets in memory order, ready
    to copy straight into sin_addr.
    """
    var octets = InlineArray[UInt32, 4](fill=0)
    var index = 0
    var current: UInt32 = 0
    var digits = 0
    var bytes = text.as_bytes()

    for i in range(len(bytes)):
        var c = bytes[i]
        if c == 46:  # '.'
            if digits == 0 or index >= 3:
                return (False, UInt32(0))
            octets[index] = current
            index += 1
            current = 0
            digits = 0
        elif c >= 48 and c <= 57:
            current = current * 10 + UInt32(c - 48)
            digits += 1
            if current > 255 or digits > 3:
                return (False, UInt32(0))
        else:
            return (False, UInt32(0))

    if digits == 0 or index != 3:
        return (False, UInt32(0))
    octets[3] = current

    var packed = octets[0] | (octets[1] << 8) | (octets[2] << 16) | (octets[3] << 24)
    return (True, packed)


struct Socket(Movable):
    """A connected TCP socket."""

    var fd: Int32
    var closed: Bool

    def __init__(out self):
        self.fd = -1
        self.closed = True

    def __del__(deinit self):
        if not self.closed and self.fd >= 0:
            _ = external_call["close", Int](Int(self.fd))

    def is_open(self) -> Bool:
        return not self.closed and self.fd >= 0

    def close(mut self):
        if not self.closed and self.fd >= 0:
            _ = external_call["close", Int](Int(self.fd))
        self.closed = True
        self.fd = -1

    def set_timeout(mut self, seconds: Int) raises:
        """Apply the same deadline to reads and writes."""
        var tv = List[UInt8](length=TIMEVAL_SIZE, fill=0)
        var secs = UInt64(seconds)
        for i in range(8):
            tv[i] = UInt8((secs >> UInt64(8 * i)) & 0xFF)

        var rcv = external_call["setsockopt", Int32](
            self.fd, SOL_SOCKET, SO_RCVTIMEO, tv.unsafe_ptr(), Int32(TIMEVAL_SIZE)
        )
        var snd = external_call["setsockopt", Int32](
            self.fd, SOL_SOCKET, SO_SNDTIMEO, tv.unsafe_ptr(), Int32(TIMEVAL_SIZE)
        )
        if rcv != 0 or snd != 0:
            raise Error("setsockopt(timeout) failed, errno=" + String(errno()))

    def set_nodelay(mut self, on: Bool) raises:
        var value = Int32(1) if on else Int32(0)
        var rc = external_call["setsockopt", Int32](
            self.fd,
            IPPROTO_TCP,
            TCP_NODELAY,
            UnsafePointer(to=value).bitcast[UInt8](),
            Int32(4),
        )
        if rc != 0:
            raise Error("setsockopt(TCP_NODELAY) failed")

    def set_keepalive(mut self, on: Bool) raises:
        var value = Int32(1) if on else Int32(0)
        var rc = external_call["setsockopt", Int32](
            self.fd,
            SOL_SOCKET,
            SO_KEEPALIVE,
            UnsafePointer(to=value).bitcast[UInt8](),
            Int32(4),
        )
        if rc != 0:
            raise Error("setsockopt(SO_KEEPALIVE) failed")

    def send_all(mut self, data: Span[UInt8, _]) raises:
        """Write every byte or raise. Short writes are normal on a socket."""
        var sent = 0
        var total = len(data)
        while sent < total:
            var chunk = data[sent:]
            var n = external_call["write", Int](
                Int(self.fd), chunk.unsafe_ptr(), total - sent
            )
            if n > 0:
                sent += n
                continue
            var e = errno()
            if e == EINTR:
                continue
            if e == EAGAIN:
                raise Error("socket write timed out")
            raise Error("socket write failed, errno=" + String(e))

    def recv_exact(mut self, mut into: List[UInt8], offset: Int, count: Int) raises:
        """Fill exactly `count` bytes. Raises on EOF, which for a database
        connection means the server closed on us mid-message."""
        if count == 0:
            return
        while len(into) < offset + count:
            into.append(0)

        var got = 0
        while got < count:
            var tail = Span(into)[offset + got :]
            var n = external_call["read", Int](
                Int(self.fd), tail.unsafe_ptr(), count - got
            )
            if n > 0:
                got += n
                continue
            if n == 0:
                raise Error("connection closed by peer")
            var e = errno()
            if e == EINTR:
                continue
            if e == EAGAIN:
                raise Error("socket read timed out")
            raise Error("socket read failed, errno=" + String(e))


def connect_tcp(host: StringSlice, port: UInt16, timeout_seconds: Int = 30) raises -> Socket:
    """Open a TCP connection.

    Dotted-quad hosts are handled without a resolver; anything else goes
    through getaddrinfo, which also covers IPv6 and /etc/hosts entries.
    """
    var parsed = parse_ipv4(host)
    if parsed[0]:
        return _connect_ipv4(parsed[1], port, timeout_seconds)
    return _connect_resolved(host, port, timeout_seconds)


def _connect_ipv4(addr_packed: UInt32, port: UInt16, timeout_seconds: Int) raises -> Socket:
    var fd = external_call["socket", Int32](AF_INET, SOCK_STREAM, Int32(0))
    if fd < 0:
        raise Error("socket() failed, errno=" + String(errno()))

    var sa = List[UInt8](length=SOCKADDR_IN_SIZE, fill=0)
    sa[0] = UInt8(AF_INET & 0xFF)
    sa[1] = UInt8((AF_INET >> 8) & 0xFF)
    var netport = _htons(port)
    sa[2] = UInt8(netport & 0xFF)
    sa[3] = UInt8((netport >> 8) & 0xFF)
    sa[4] = UInt8(addr_packed & 0xFF)
    sa[5] = UInt8((addr_packed >> 8) & 0xFF)
    sa[6] = UInt8((addr_packed >> 16) & 0xFF)
    sa[7] = UInt8((addr_packed >> 24) & 0xFF)

    var rc = external_call["connect", Int32](
        fd, sa.unsafe_ptr(), Int32(SOCKADDR_IN_SIZE)
    )
    if rc != 0:
        var e = errno()
        _ = external_call["close", Int](Int(fd))
        raise Error("connect() failed, errno=" + String(e))

    var sock = Socket()
    sock.fd = fd
    sock.closed = False
    sock.set_timeout(timeout_seconds)
    sock.set_nodelay(True)
    sock.set_keepalive(True)
    return sock^


def _connect_resolved(host: StringSlice, port: UInt16, timeout_seconds: Int) raises -> Socket:
    """Resolve with getaddrinfo and connect to the first usable result."""
    # getaddrinfo takes C strings. Mojo's String does not guarantee a NUL
    # terminator behind unsafe_ptr(), so build the bytes explicitly.
    var hostz = _c_string(host)
    var portz = _c_string(String(port))
    var result_addr = Int(0)

    # struct addrinfo hints = {0}; we accept any family, SOCK_STREAM.
    var hints = List[UInt8](length=48, fill=0)
    hints[4] = 0  # ai_family = AF_UNSPEC
    hints[8] = UInt8(SOCK_STREAM)  # ai_socktype

    var rc = external_call["getaddrinfo", Int32](
        hostz.unsafe_ptr(),
        portz.unsafe_ptr(),
        hints.unsafe_ptr(),
        UnsafePointer(to=result_addr).bitcast[UInt8](),
    )
    if rc != 0 or result_addr == 0:
        raise Error(
            "could not resolve host '" + String(host) + "' (getaddrinfo="
            + String(rc) + ")"
        )

    # struct addrinfo layout on glibc/x86-64:
    #   0 ai_flags(i32) 4 ai_family(i32) 8 ai_socktype(i32) 12 ai_protocol(i32)
    #  16 ai_addrlen(u32) 24 ai_addr(ptr) 32 ai_canonname(ptr) 40 ai_next(ptr)
    var node = result_addr
    var fd = Int32(-1)
    var connected = False

    while node != 0 and not connected:
        var base = UnsafePointer[UInt8, ImmStaticOrigin](unsafe_from_address=node)
        var family = _read_i32(base, 4)
        var socktype = _read_i32(base, 8)
        var protocol = _read_i32(base, 12)
        var addrlen = _read_i32(base, 16)
        var addr_ptr = _read_i64(base, 24)

        if addr_ptr != 0:
            fd = external_call["socket", Int32](family, socktype, protocol)
            if fd >= 0:
                var sockaddr = UnsafePointer[UInt8, ImmStaticOrigin](
                    unsafe_from_address=Int(addr_ptr)
                )
                var crc = external_call["connect", Int32](fd, sockaddr, addrlen)
                if crc == 0:
                    connected = True
                else:
                    _ = external_call["close", Int](Int(fd))
                    fd = -1

        node = Int(_read_i64(base, 40))

    _ = external_call["freeaddrinfo", Int32](
        UnsafePointer[UInt8, ImmStaticOrigin](unsafe_from_address=result_addr)
    )

    if not connected or fd < 0:
        raise Error("could not connect to '" + String(host) + ":" + String(port) + "'")

    var sock = Socket()
    sock.fd = fd
    sock.closed = False
    sock.set_timeout(timeout_seconds)
    sock.set_nodelay(True)
    sock.set_keepalive(True)
    return sock^


def _c_string(value: StringSlice) -> List[UInt8]:
    var out = List[UInt8]()
    var b = value.as_bytes()
    for i in range(len(b)):
        out.append(b[i])
    out.append(0)
    return out^


def _read_i32(base: UnsafePointer[UInt8, ImmStaticOrigin], offset: Int) -> Int32:
    var value = (
        UInt32(base[unsafe_offset=offset])
        | (UInt32(base[unsafe_offset = offset + 1]) << 8)
        | (UInt32(base[unsafe_offset = offset + 2]) << 16)
        | (UInt32(base[unsafe_offset = offset + 3]) << 24)
    )
    return Int32(value)


def _read_i64(base: UnsafePointer[UInt8, ImmStaticOrigin], offset: Int) -> Int64:
    var value = UInt64(0)
    for i in range(8):
        value |= UInt64(base[unsafe_offset = offset + i]) << UInt64(8 * i)
    return Int64(value)
