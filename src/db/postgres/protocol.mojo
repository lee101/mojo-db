"""PostgreSQL frontend/backend protocol version 3.0.

Message framing is uniform except for the startup packet, which omits the type
byte because at that point the server does not yet know which protocol version
it is speaking.

Reference: PostgreSQL docs, "Frontend/Backend Protocol". Every constant here
is from that document rather than observed traffic, so a server that behaves
differently is a bug on its side, not a missing special case on ours.
"""

from db.net.buffer import ReadBuffer, WriteBuffer
from db.net.socket import Socket

comptime PROTOCOL_VERSION_3: Int32 = 196608  # 3 << 16
comptime SSL_REQUEST_CODE: Int32 = 80877103
comptime CANCEL_REQUEST_CODE: Int32 = 80877102

# Backend message types.
comptime MSG_AUTH: UInt8 = 82  # 'R'
comptime MSG_BACKEND_KEY: UInt8 = 75  # 'K'
comptime MSG_BIND_COMPLETE: UInt8 = 50  # '2'
comptime MSG_CLOSE_COMPLETE: UInt8 = 51  # '3'
comptime MSG_COMMAND_COMPLETE: UInt8 = 67  # 'C'
comptime MSG_DATA_ROW: UInt8 = 68  # 'D'
comptime MSG_EMPTY_QUERY: UInt8 = 73  # 'I'
comptime MSG_ERROR: UInt8 = 69  # 'E'
comptime MSG_NO_DATA: UInt8 = 110  # 'n'
comptime MSG_NOTICE: UInt8 = 78  # 'N'
comptime MSG_NOTIFICATION: UInt8 = 65  # 'A'
comptime MSG_PARAMETER_DESC: UInt8 = 116  # 't'
comptime MSG_PARAMETER_STATUS: UInt8 = 83  # 'S'
comptime MSG_PARSE_COMPLETE: UInt8 = 49  # '1'
comptime MSG_PORTAL_SUSPENDED: UInt8 = 115  # 's'
comptime MSG_READY: UInt8 = 90  # 'Z'
comptime MSG_ROW_DESCRIPTION: UInt8 = 84  # 'T'

# Frontend message types.
comptime FE_BIND: UInt8 = 66  # 'B'
comptime FE_CLOSE: UInt8 = 67  # 'C'
comptime FE_DESCRIBE: UInt8 = 68  # 'D'
comptime FE_EXECUTE: UInt8 = 69  # 'E'
comptime FE_FLUSH: UInt8 = 72  # 'H'
comptime FE_PARSE: UInt8 = 80  # 'P'
comptime FE_PASSWORD: UInt8 = 112  # 'p'
comptime FE_QUERY: UInt8 = 81  # 'Q'
comptime FE_SYNC: UInt8 = 83  # 'S'
comptime FE_TERMINATE: UInt8 = 88  # 'X'

# Authentication subtypes.
comptime AUTH_OK: Int32 = 0
comptime AUTH_KERBEROS_V5: Int32 = 2
comptime AUTH_CLEARTEXT: Int32 = 3
comptime AUTH_MD5: Int32 = 5
comptime AUTH_GSS: Int32 = 7
comptime AUTH_GSS_CONTINUE: Int32 = 8
comptime AUTH_SSPI: Int32 = 9
comptime AUTH_SASL: Int32 = 10
comptime AUTH_SASL_CONTINUE: Int32 = 11
comptime AUTH_SASL_FINAL: Int32 = 12

# Transaction status reported by ReadyForQuery.
comptime TX_IDLE: UInt8 = 73  # 'I'
comptime TX_IN_TRANSACTION: UInt8 = 84  # 'T'
comptime TX_FAILED: UInt8 = 69  # 'E'

comptime MAX_MESSAGE_BYTES: Int = 512 * 1024 * 1024


struct ServerError(Movable, Writable):
    """A decoded ErrorResponse or NoticeResponse.

    Postgres sends structured fields, and throwing away everything but the
    message loses the two things that actually help: SQLSTATE, and the
    position of the syntax error inside the statement.
    """

    var severity: String
    var code: String
    var message: String
    var detail: String
    var hint: String
    var position: String
    var where: String
    var schema: String
    var table: String
    var column: String
    var constraint: String

    def __init__(out self):
        self.severity = String("")
        self.code = String("")
        self.message = String("")
        self.detail = String("")
        self.hint = String("")
        self.position = String("")
        self.where = String("")
        self.schema = String("")
        self.table = String("")
        self.column = String("")
        self.constraint = String("")

    def describe(self) -> String:
        var out = String("")
        if self.severity != "":
            out += self.severity
            out += ": "
        out += self.message
        if self.code != "":
            out += " [SQLSTATE "
            out += self.code
            out += "]"
        if self.detail != "":
            out += " detail: "
            out += self.detail
        if self.hint != "":
            out += " hint: "
            out += self.hint
        if self.position != "":
            out += " at position "
            out += self.position
        return out^

    def write_to[W: Writer](self, mut writer: W):
        writer.write(self.describe())


def parse_error(mut body: ReadBuffer) raises -> ServerError:
    """Decode the field-tagged body of an ErrorResponse."""
    var err = ServerError()
    while True:
        var field = body.byte()
        if field == 0:
            break
        var value = body.cstring()
        if field == 83:  # 'S' severity
            err.severity = value^
        elif field == 67:  # 'C' SQLSTATE
            err.code = value^
        elif field == 77:  # 'M' message
            err.message = value^
        elif field == 68:  # 'D' detail
            err.detail = value^
        elif field == 72:  # 'H' hint
            err.hint = value^
        elif field == 80:  # 'P' position
            err.position = value^
        elif field == 87:  # 'W' where
            err.where = value^
        elif field == 115:  # 's' schema
            err.schema = value^
        elif field == 116:  # 't' table
            err.table = value^
        elif field == 99:  # 'c' column
            err.column = value^
        elif field == 110:  # 'n' constraint
            err.constraint = value^
    return err^


struct Message(Movable):
    """One backend message: a type byte plus its decoded body."""

    var kind: UInt8
    var body: ReadBuffer

    def __init__(out self, kind: UInt8, var body: ReadBuffer):
        self.kind = kind
        self.body = body^

    def unpack(deinit self) -> Tuple[UInt8, ReadBuffer]:
        """Consume the message, yielding its parts.

        Moving `body` out of a live Message would destroy one field while the
        struct still owns the rest, which Mojo rejects.
        """
        return (self.kind, self.body^)


def read_message(mut sock: Socket, mut scratch: List[UInt8]) raises -> Message:
    """Read one framed message.

    Frame is: 1 type byte, Int32 length (inclusive of itself), then body.
    """
    scratch.clear()
    sock.recv_exact(scratch, 0, 5)

    var kind = scratch[0]
    var length = (
        (Int(scratch[1]) << 24)
        | (Int(scratch[2]) << 16)
        | (Int(scratch[3]) << 8)
        | Int(scratch[4])
    )
    if length < 4:
        raise Error("malformed message length " + String(length))
    if length > MAX_MESSAGE_BYTES:
        raise Error("message of " + String(length) + " bytes exceeds the cap")

    var body_len = length - 4
    var body = List[UInt8]()
    if body_len > 0:
        sock.recv_exact(body, 0, body_len)
        while len(body) > body_len:
            _ = body.pop()

    return Message(kind, ReadBuffer(body^))


def send_startup(
    mut sock: Socket, user: StringSlice, database: StringSlice, application_name: StringSlice
) raises:
    """The one message with no type byte."""
    var w = WriteBuffer(256)
    w.i32(0)  # length placeholder
    w.i32(PROTOCOL_VERSION_3)
    w.cstring("user")
    w.cstring(user)
    if database.byte_length() > 0:
        w.cstring("database")
        w.cstring(database)
    w.cstring("application_name")
    w.cstring(application_name)
    # Text format everywhere; binary decoding is a later optimisation.
    w.cstring("client_encoding")
    w.cstring("UTF8")
    w.byte(0)
    w.patch_i32(0, Int32(w.size()))
    sock.send_all(w.span())


def send_typed(mut sock: Socket, kind: UInt8, mut payload: WriteBuffer) raises:
    """Frame and send a message whose payload is already built."""
    var w = WriteBuffer(payload.size() + 5)
    w.byte(kind)
    w.i32(Int32(payload.size() + 4))
    w.bytes(payload.span())
    sock.send_all(w.span())


def send_query(mut sock: Socket, sql: StringSlice) raises:
    var payload = WriteBuffer(sql.byte_length() + 1)
    payload.cstring(sql)
    send_typed(sock, FE_QUERY, payload)


def send_terminate(mut sock: Socket) raises:
    var payload = WriteBuffer(0)
    send_typed(sock, FE_TERMINATE, payload)


def send_password(mut sock: Socket, secret: StringSlice) raises:
    var payload = WriteBuffer(secret.byte_length() + 1)
    payload.cstring(secret)
    send_typed(sock, FE_PASSWORD, payload)
