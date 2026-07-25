# mojo-db

Native database drivers for [Mojo](https://www.modular.com/mojo), with no
Python and no C library in the data path.

Today that means **PostgreSQL**, spoken over its own wire protocol: sockets via
libc, protocol framing, authentication and result decoding all implemented in
Mojo. The same driver works against anything that speaks the PostgreSQL
protocol — Amazon Redshift, CockroachDB, YugabyteDB, and PgBouncer in session
mode.

```mojo
from db.postgres.connection import ConnectParams, connect

def main() raises:
    var conn = connect(ConnectParams("127.0.0.1", 5432, "app", "secret", "shop"))

    var result = conn.query("SELECT id, name, total FROM orders LIMIT 10")
    for i in range(result.row_count()):
        print(result.rows[i].int(0), result.rows[i].text(1), result.rows[i].float(2))

    # Parameters travel out of band; they are never spliced into the SQL.
    var args = List[String]()
    args.append(String("nz"))
    var scoped = conn.query_params("SELECT count(*) FROM orders WHERE region = $1", args)
    print("orders:", scoped.rows[0].int(0))

    conn.close()
```

## What works

- **Protocol v3**: startup, simple query, extended query (Parse/Bind/Describe/
  Execute/Sync), command tags, `ReadyForQuery` transaction status, Terminate.
- **Authentication**: `trust`, `password` (cleartext), `md5`, and
  **SCRAM-SHA-256** — including verification of the server's final signature,
  which is what proves the server actually held the stored key.
- **Errors**: `ErrorResponse` is decoded in full, so you get SQLSTATE, detail,
  hint and the character position of a syntax error, not just a message.
- **Values**: text-format decoding with typed accessors (`int`, `float`,
  `bool`, `text`) and `NULL` kept distinct from the empty string.
- **Crypto**: SHA-256, HMAC-SHA-256, PBKDF2, MD5 and Base64 in pure Mojo,
  verified against the published vectors in FIPS 180-4, RFC 1321, RFC 4231,
  RFC 7914 and RFC 4648.

## What does not work yet

Being explicit, because a database driver that is vague about this is
dangerous:

- **No TLS.** Connections are plaintext. Do not send credentials across a
  network you do not control. `sslmode=require` and SCRAM channel binding both
  depend on this and are therefore unavailable.
- **No connection pooling.** One `Connection` is one socket, and it is not safe
  to share across threads.
- **Text format only.** Values are decoded from PostgreSQL's text
  representation; binary format would be faster for large numeric result sets.
- **No `COPY`, no `LISTEN`/`NOTIFY`, no cursors.**
- **No SASLprep.** Passwords outside ASCII may not normalise the way the server
  expects.

TLS is the next piece, because everything else — a hosted Postgres, and the
HTTPS-based warehouses like Snowflake and BigQuery — is gated behind it.

## Install

Requires Mojo 1.0 or newer.

**As a path dependency**, which is the simplest option today:

```bash
git clone https://github.com/lee101/mojo-db
mojo build your_app.mojo -I mojo-db/src
```

**As a compiled package:**

```bash
mojo package mojo-db/src/db -o db.mojopkg
mojo build your_app.mojo -I .
```

## Layout

```
src/db/
  net/socket.mojo      blocking TCP with timeouts, IPv4 fast path + getaddrinfo
  net/buffer.mojo      big-endian read/write buffers
  crypto/sha256.mojo   SHA-256, HMAC, PBKDF2
  crypto/md5.mojo      MD5 and PostgreSQL's md5 auth formula
  crypto/base64.mojo   RFC 4648
  crypto/scram.mojo    SCRAM-SHA-256 client
  postgres/protocol.mojo    message framing and constants
  postgres/connection.mojo  the connection and its message loop
  postgres/result.mojo      columns, rows, typed accessors, type OIDs
```

## Tests

The crypto vectors run without a database:

```bash
mojo build tests/test_crypto.mojo -I src -o /tmp/test_crypto && /tmp/test_crypto
```

The driver examples need a reachable PostgreSQL:

```bash
mojo build examples/pg_smoke.mojo -I src -o /tmp/pg_smoke && /tmp/pg_smoke
```

## Design notes

**Blocking sockets, not an event loop.** Database access is request/response
and usually happens on a thread that is willing to wait. Timeouts are set with
`SO_RCVTIMEO`/`SO_SNDTIMEO` so a wedged server surfaces as an error instead of
hanging the caller — the failure mode that makes a database outage look like an
application hang.

**The message loop is flat.** Read a message, dispatch on its type, repeat
until `ReadyForQuery`. There is no mutual recursion anywhere, which matters
twice: it is a stack-depth hazard on a large result set, and in Mojo
specifically the optimiser will chase a recursion cycle through the whole
request path and turn a 20-second build into a 15-minute one.

**A failed statement still drains to `ReadyForQuery`.** Returning early on
`ErrorResponse` would leave unread bytes in the socket and desynchronise the
next query, so the error is stashed and raised only once the stream is back in
sync.

## Contributing

Issues and pull requests welcome, particularly for TLS, MySQL, and binary-format
decoding. Please include a test vector or a reproducible query for anything
protocol-related.

## Licence

Apache-2.0. See [LICENSE](LICENSE).
