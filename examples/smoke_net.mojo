from db.net.socket import connect_tcp, parse_ipv4
from db.net.buffer import ReadBuffer, WriteBuffer, to_bytes


def main() raises:
    var ok = parse_ipv4("127.0.0.1")
    print("parse 127.0.0.1:", ok[0], ok[1])
    var bad = parse_ipv4("not.an.ip")
    print("parse bad:", bad[0])

    var w = WriteBuffer()
    w.i32(305419896)
    w.i16(-2)
    w.cstring("hello")
    print("encoded bytes:", w.size())

    var r = ReadBuffer(w.data.copy())
    print("i32:", r.i32(), "i16:", r.i16(), "cstr:", r.cstring())

    var sock = connect_tcp("127.0.0.1", 5432, 5)
    print("connected to postgres:", sock.is_open())
    sock.close()
