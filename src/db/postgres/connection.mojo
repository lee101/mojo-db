"""A PostgreSQL connection.

The message loop is deliberately flat: read a message, dispatch on its type,
repeat until ReadyForQuery. No mutual recursion anywhere - it is both a
stack-depth hazard on a long result set and, in Mojo specifically, something
the optimiser will chase for minutes at build time.

Also speaks to anything that implements the same wire protocol: Amazon
Redshift, CockroachDB, YugabyteDB, and PgBouncer in session mode.
"""

from db.crypto.md5 import md5_hex, postgres_md5_password
from db.crypto.scram import ScramClient
from db.net.buffer import ReadBuffer, WriteBuffer, bytes_to_string
from db.net.socket import Socket, connect_tcp
from db.postgres.protocol import (
    AUTH_CLEARTEXT,
    AUTH_GSS,
    AUTH_KERBEROS_V5,
    AUTH_MD5,
    AUTH_OK,
    AUTH_SASL,
    AUTH_SASL_CONTINUE,
    AUTH_SASL_FINAL,
    AUTH_SSPI,
    FE_BIND,
    FE_DESCRIBE,
    FE_EXECUTE,
    FE_PARSE,
    FE_PASSWORD,
    FE_SYNC,
    MSG_AUTH,
    MSG_BACKEND_KEY,
    MSG_BIND_COMPLETE,
    MSG_CLOSE_COMPLETE,
    MSG_COMMAND_COMPLETE,
    MSG_DATA_ROW,
    MSG_EMPTY_QUERY,
    MSG_ERROR,
    MSG_NO_DATA,
    MSG_NOTICE,
    MSG_NOTIFICATION,
    MSG_PARAMETER_DESC,
    MSG_PARAMETER_STATUS,
    MSG_PARSE_COMPLETE,
    MSG_PORTAL_SUSPENDED,
    MSG_READY,
    MSG_ROW_DESCRIPTION,
    Message,
    ServerError,
    parse_error,
    read_message,
    send_password,
    send_query,
    send_startup,
    send_terminate,
    send_typed,
)
from db.postgres.result import Column, QueryResult, Row, parse_command_tag


struct ConnectParams(ImplicitlyCopyable, Movable):
    var host: String
    var port: UInt16
    var user: String
    var password: String
    var database: String
    var application_name: String
    var connect_timeout: Int

    def __init__(out self):
        self.host = String("127.0.0.1")
        self.port = 5432
        self.user = String("postgres")
        self.password = String("")
        self.database = String("")
        self.application_name = String("mojo-db")
        self.connect_timeout = 30

    def __init__(
        out self,
        host: StringSlice,
        port: UInt16,
        user: StringSlice,
        password: StringSlice,
        database: StringSlice,
    ):
        self.host = String(host)
        self.port = port
        self.user = String(user)
        self.password = String(password)
        self.database = String(database)
        self.application_name = String("mojo-db")
        self.connect_timeout = 30


struct Connection(Movable):
    var sock: Socket
    var params: ConnectParams
    var scratch: List[UInt8]
    var backend_pid: Int32
    var backend_key: Int32
    var transaction_status: UInt8
    var server_version: String
    var open: Bool
    var last_notices: List[String]

    def __init__(out self, var sock: Socket, params: ConnectParams):
        self.sock = sock^
        self.params = params
        self.scratch = List[UInt8]()
        self.backend_pid = 0
        self.backend_key = 0
        self.transaction_status = 73  # 'I'
        self.server_version = String("")
        self.open = True
        self.last_notices = List[String]()

    def close(mut self):
        if not self.open:
            return
        try:
            send_terminate(self.sock)
        except:
            pass
        self.sock.close()
        self.open = False

    def is_open(self) -> Bool:
        return self.open and self.sock.is_open()

    # ---------------------------------------------------------------- queries

    def query(mut self, sql: StringSlice) raises -> QueryResult:
        """Run one statement through the simple query protocol."""
        if not self.is_open():
            raise Error("connection is closed")
        send_query(self.sock, sql)
        return self._collect()

    def execute(mut self, sql: StringSlice) raises -> Int:
        """Run a statement and return the affected row count."""
        var result = self.query(sql)
        return result.rows_affected

    def query_params(
        mut self, sql: StringSlice, params: List[String]
    ) raises -> QueryResult:
        """Extended protocol: parameters are sent out of band, never spliced
        into the SQL text, so this is the injection-safe path."""
        if not self.is_open():
            raise Error("connection is closed")

        # Parse: unnamed statement, no type hints - let the server infer.
        var parse = WriteBuffer(sql.byte_length() + 8)
        parse.cstring("")
        parse.cstring(sql)
        parse.i16(0)
        send_typed(self.sock, FE_PARSE, parse)

        # Bind: all parameters as text, all results as text.
        var bind = WriteBuffer(128)
        bind.cstring("")  # portal
        bind.cstring("")  # statement
        bind.i16(0)  # zero format codes => all text
        bind.i16(Int16(len(params)))
        for i in range(len(params)):
            var value = params[i]
            bind.i32(Int32(value.byte_length()))
            bind.string(value)
        bind.i16(0)  # result format codes => all text
        send_typed(self.sock, FE_BIND, bind)

        var describe = WriteBuffer(8)
        describe.byte(80)  # 'P' describe portal
        describe.cstring("")
        send_typed(self.sock, FE_DESCRIBE, describe)

        var execute = WriteBuffer(8)
        execute.cstring("")  # portal
        execute.i32(0)  # unlimited rows
        send_typed(self.sock, FE_EXECUTE, execute)

        var sync = WriteBuffer(0)
        send_typed(self.sock, FE_SYNC, sync)

        return self._collect()

    def ping(mut self) raises -> Bool:
        var result = self.query("SELECT 1")
        return result.row_count() == 1


    # ---------------------------------------------------------------- auth

    def _authenticate(mut self) raises:
        """Run the handshake until ReadyForQuery.

        Every branch either completes, sends the next message, or raises. An
        unhandled method must fail loudly rather than fall through and hang
        waiting for a message the server will never send.
        """
        var scram = ScramClient(self.params.user, self.params.password)
        var scram_active = False

        while True:
            # Use the message in place. Moving `body` out of it would
            # destroy one field while the struct still owns the rest, which
            # Mojo rejects outright.
            var message = read_message(self.sock, self.scratch)
            var kind = message.kind

            if kind == MSG_ERROR:
                var failure = parse_error(message.body)
                self.sock.close()
                self.open = False
                raise Error("authentication failed: " + failure.describe())

            elif kind == MSG_AUTH:
                var subtype = message.body.i32()

                if subtype == AUTH_OK:
                    continue

                elif subtype == AUTH_CLEARTEXT:
                    self._require_password("cleartext password")
                    send_password(self.sock, self.params.password)

                elif subtype == AUTH_MD5:
                    self._require_password("md5 password")
                    var salt = message.body.take(4)
                    send_password(
                        self.sock,
                        postgres_md5_password(
                            self.params.password, self.params.user, Span(salt)
                        ),
                    )

                elif subtype == AUTH_SASL:
                    self._require_password("SCRAM authentication")
                    var chosen = String("")
                    while True:
                        var mechanism = message.body.cstring()
                        if mechanism == "":
                            break
                        if mechanism == "SCRAM-SHA-256":
                            chosen = mechanism^
                    if chosen == "":
                        raise Error(
                            "server offered no SCRAM-SHA-256; channel binding "
                            "variants need TLS, which this driver does not "
                            "speak yet"
                        )

                    var first = scram.client_first()
                    var payload = WriteBuffer(first.byte_length() + 32)
                    payload.cstring(chosen)
                    payload.i32(Int32(first.byte_length()))
                    payload.string(first)
                    send_typed(self.sock, FE_PASSWORD, payload)
                    scram_active = True

                elif subtype == AUTH_SASL_CONTINUE:
                    if not scram_active:
                        raise Error("unexpected SASLContinue before SASLInitial")
                    var server_first = message.body.take_string(message.body.remaining())
                    var final = scram.client_final(server_first)
                    var payload = WriteBuffer(final.byte_length())
                    payload.string(final)
                    send_typed(self.sock, FE_PASSWORD, payload)

                elif subtype == AUTH_SASL_FINAL:
                    if not scram_active:
                        raise Error("unexpected SASLFinal before SASLInitial")
                    var server_final = message.body.take_string(message.body.remaining())
                    scram.verify_server_final(server_final)

                elif (
                    subtype == AUTH_KERBEROS_V5
                    or subtype == AUTH_GSS
                    or subtype == AUTH_SSPI
                ):
                    raise Error(
                        "GSSAPI/SSPI authentication is not supported; use "
                        "scram-sha-256, md5, or trust"
                    )

                else:
                    raise Error(
                        "unsupported authentication method "
                        + String(subtype)
                    )

            elif kind == MSG_BACKEND_KEY:
                self.backend_pid = message.body.i32()
                self.backend_key = message.body.i32()

            elif kind == MSG_PARAMETER_STATUS:
                var name = message.body.cstring()
                var value = message.body.cstring()
                if name == "server_version":
                    self.server_version = value^

            elif kind == MSG_NOTICE:
                var notice = parse_error(message.body)
                self.last_notices.append(notice.describe())

            elif kind == MSG_READY:
                self.transaction_status = message.body.byte()
                break

        if scram_active and not scram.finished:
            raise Error("SCRAM exchange never completed; refusing the session")

    def _require_password(mut self, method: StringSlice) raises:
        if self.params.password.byte_length() == 0:
            raise Error(
                "server requested " + String(method) + " but no password was given"
            )

    # ------------------------------------------------------------- internals

    def _collect(mut self) raises -> QueryResult:
        """Drain messages until ReadyForQuery, assembling one result.

        A statement that errors still gets its ReadyForQuery, so the error is
        stashed and raised only after the stream is back in sync. Returning
        early would leave unread bytes and desynchronise the next query.
        """
        var result = QueryResult()
        var failure = ServerError()
        var failed = False

        while True:
            # Use the message in place. Moving `body` out of it would
            # destroy one field while the struct still owns the rest, which
            # Mojo rejects outright.
            var message = read_message(self.sock, self.scratch)
            var kind = message.kind

            if kind == MSG_ROW_DESCRIPTION:
                result.columns = self._read_row_description(message.body)
            elif kind == MSG_DATA_ROW:
                result.rows.append(self._read_data_row(message.body))
            elif kind == MSG_COMMAND_COMPLETE:
                var tag = message.body.cstring()
                result.rows_affected = parse_command_tag(tag)
                result.command_tag = tag^
            elif kind == MSG_ERROR:
                failure = parse_error(message.body)
                failed = True
            elif kind == MSG_NOTICE:
                var notice = parse_error(message.body)
                result.notices.append(notice.describe())
            elif kind == MSG_PARAMETER_STATUS:
                var name = message.body.cstring()
                var value = message.body.cstring()
                if name == "server_version":
                    self.server_version = value^
            elif kind == MSG_READY:
                self.transaction_status = message.body.byte()
                break
            elif kind == MSG_EMPTY_QUERY:
                result.command_tag = String("EMPTY")
            elif (
                kind == MSG_PARSE_COMPLETE
                or kind == MSG_BIND_COMPLETE
                or kind == MSG_CLOSE_COMPLETE
                or kind == MSG_NO_DATA
                or kind == MSG_PARAMETER_DESC
                or kind == MSG_PORTAL_SUSPENDED
                or kind == MSG_NOTIFICATION
                or kind == MSG_BACKEND_KEY
            ):
                pass  # not needed for a plain query
            else:
                # Unknown messages are skipped rather than fatal: the protocol
                # is versioned and a newer server may add one.
                pass

        if failed:
            raise Error(failure.describe())
        return result^

    def _read_row_description(mut self, mut body: ReadBuffer) raises -> List[Column]:
        var count = Int(body.i16())
        var columns = List[Column](capacity=count)
        for _ in range(count):
            var column = Column()
            column.name = body.cstring()
            column.table_oid = body.i32()
            column.column_index = body.i16()
            column.type_oid = body.i32()
            column.type_size = body.i16()
            column.type_modifier = body.i32()
            column.format_code = body.i16()
            columns.append(column)
        return columns^

    def _read_data_row(mut self, mut body: ReadBuffer) raises -> Row:
        var count = Int(body.i16())
        var row = Row()
        for _ in range(count):
            var length = Int(body.i32())
            if length < 0:
                # -1 is NULL, which is not the same as an empty string.
                row.values.append(String(""))
                row.nulls.append(True)
            else:
                row.values.append(body.take_string(length))
                row.nulls.append(False)
        return row^


def connect(params: ConnectParams) raises -> Connection:
    """Open and authenticate a connection."""
    var sock = connect_tcp(params.host, params.port, params.connect_timeout)
    send_startup(sock, params.user, params.database, params.application_name)

    var conn = Connection(sock^, params)
    conn._authenticate()
    return conn^


def connect_to(
    host: StringSlice,
    port: UInt16,
    user: StringSlice,
    password: StringSlice,
    database: StringSlice,
) raises -> Connection:
    return connect(ConnectParams(host, port, user, password, database))
