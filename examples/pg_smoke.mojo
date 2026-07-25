from db.postgres.connection import ConnectParams, connect


def main() raises:
    var params = ConnectParams("127.0.0.1", 5432, "mojodb", "", "mojodb_test")
    var conn = connect(params)
    print("connected; server", conn.server_version, "pid", conn.backend_pid)

    var r = conn.query("SELECT 1 AS one, 'hi'::text AS greeting, true AS flag")
    print("cols:", r.column_count(), "rows:", r.row_count())
    for i in range(r.column_count()):
        print("  col", i, r.columns[i].name, r.columns[i].type_name())
    print("values:", r.rows[0].int(0), r.rows[0].text(1), r.rows[0].bool(2))

    var m = conn.query("SELECT id, name, value, ok FROM metrics ORDER BY id")
    print("metrics rows:", m.row_count())
    for i in range(m.row_count()):
        print(
            "  ", m.rows[i].int(0), m.rows[i].text(1),
            "null" if m.rows[i].is_null(2) else String(m.rows[i].float(2)),
            m.rows[i].bool(3),
        )

    conn.close()
    print("closed")
