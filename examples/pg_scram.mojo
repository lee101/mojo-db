from db.postgres.connection import ConnectParams, connect


def main() raises:
    # pg_hba requires scram-sha-256 for this role, so this connection
    # exercises the full SASL exchange including server-signature verification.
    var params = ConnectParams("127.0.0.1", 5432, "mojodb", "mojo_test_pw", "mojodb_test")
    var conn = connect(params)
    print("SCRAM-SHA-256 authenticated; server", conn.server_version)

    var r = conn.query("SELECT current_user, count(*)::int FROM metrics")
    print("user:", r.rows[0].text(0), "metrics:", r.rows[0].int(1))

    # Extended protocol: parameters travel out of band.
    var args = List[String]()
    args.append(String("alpha"))
    var p = conn.query_params("SELECT name, value FROM metrics WHERE name = $1", args)
    print("param query rows:", p.row_count(), "->", p.rows[0].text(0), p.rows[0].text(1))

    # A quoted value that would be an injection if it were spliced into SQL.
    var evil = List[String]()
    evil.append(String("x'; DROP TABLE metrics; --"))
    var safe = conn.query_params("SELECT count(*)::int FROM metrics WHERE name = $1", evil)
    print("injection attempt matched rows:", safe.rows[0].int(0))

    var still = conn.query("SELECT count(*)::int FROM metrics")
    print("table intact, rows:", still.rows[0].int(0))

    conn.close()
