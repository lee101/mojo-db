"""Query results and typed value access.

Values arrive in text format, so a column is bytes plus an OID. Rather than
guess a Mojo type per column, the row exposes explicit accessors and the
caller decides: `row.int(0)`, `row.float("value")`, `row.is_null(2)`.

NULL is distinct from the empty string. The wire distinguishes them with a
length of -1, and so does this.
"""

from db.net.buffer import bytes_to_string

# Common type OIDs from pg_type. Only the ones worth branching on.
comptime OID_BOOL: Int32 = 16
comptime OID_BYTEA: Int32 = 17
comptime OID_CHAR: Int32 = 18
comptime OID_NAME: Int32 = 19
comptime OID_INT8: Int32 = 20
comptime OID_INT2: Int32 = 21
comptime OID_INT4: Int32 = 23
comptime OID_TEXT: Int32 = 25
comptime OID_OID: Int32 = 26
comptime OID_JSON: Int32 = 114
comptime OID_XML: Int32 = 142
comptime OID_FLOAT4: Int32 = 700
comptime OID_FLOAT8: Int32 = 701
comptime OID_VARCHAR: Int32 = 1043
comptime OID_DATE: Int32 = 1082
comptime OID_TIME: Int32 = 1083
comptime OID_TIMESTAMP: Int32 = 1114
comptime OID_TIMESTAMPTZ: Int32 = 1184
comptime OID_INTERVAL: Int32 = 1186
comptime OID_NUMERIC: Int32 = 1700
comptime OID_UUID: Int32 = 2950
comptime OID_JSONB: Int32 = 3802


def type_name(oid: Int32) -> String:
    if oid == OID_BOOL:
        return String("bool")
    if oid == OID_INT2:
        return String("int2")
    if oid == OID_INT4:
        return String("int4")
    if oid == OID_INT8:
        return String("int8")
    if oid == OID_FLOAT4:
        return String("float4")
    if oid == OID_FLOAT8:
        return String("float8")
    if oid == OID_NUMERIC:
        return String("numeric")
    if oid == OID_TEXT:
        return String("text")
    if oid == OID_VARCHAR:
        return String("varchar")
    if oid == OID_CHAR or oid == OID_NAME:
        return String("char")
    if oid == OID_DATE:
        return String("date")
    if oid == OID_TIME:
        return String("time")
    if oid == OID_TIMESTAMP:
        return String("timestamp")
    if oid == OID_TIMESTAMPTZ:
        return String("timestamptz")
    if oid == OID_INTERVAL:
        return String("interval")
    if oid == OID_UUID:
        return String("uuid")
    if oid == OID_JSON:
        return String("json")
    if oid == OID_JSONB:
        return String("jsonb")
    if oid == OID_BYTEA:
        return String("bytea")
    if oid == OID_XML:
        return String("xml")
    if oid == OID_OID:
        return String("oid")
    return String("oid:") + String(oid)


def is_numeric_oid(oid: Int32) -> Bool:
    return (
        oid == OID_INT2
        or oid == OID_INT4
        or oid == OID_INT8
        or oid == OID_FLOAT4
        or oid == OID_FLOAT8
        or oid == OID_NUMERIC
        or oid == OID_OID
    )


struct Column(ImplicitlyCopyable, Movable):
    var name: String
    var table_oid: Int32
    var column_index: Int16
    var type_oid: Int32
    var type_size: Int16
    var type_modifier: Int32
    var format_code: Int16

    def __init__(out self):
        self.name = String("")
        self.table_oid = 0
        self.column_index = 0
        self.type_oid = 0
        self.type_size = 0
        self.type_modifier = -1
        self.format_code = 0

    def type_name(self) -> String:
        return type_name(self.type_oid)


struct Row(Movable):
    """One result row. Values are text-format bytes; -1 length means NULL."""

    var values: List[String]
    var nulls: List[Bool]

    def __init__(out self):
        self.values = List[String]()
        self.nulls = List[Bool]()

    def size(self) -> Int:
        return len(self.values)

    def is_null(self, index: Int) -> Bool:
        if index < 0 or index >= len(self.nulls):
            return True
        return self.nulls[index]

    def text(self, index: Int) raises -> String:
        if index < 0 or index >= len(self.values):
            raise Error("column index " + String(index) + " out of range")
        return self.values[index]

    def int(self, index: Int) raises -> Int:
        if self.is_null(index):
            raise Error("column " + String(index) + " is NULL")
        return Int(self.text(index))

    def float(self, index: Int) raises -> Float64:
        if self.is_null(index):
            raise Error("column " + String(index) + " is NULL")
        return Float64(self.text(index))

    def bool(self, index: Int) raises -> Bool:
        """Postgres sends 't' / 'f' in text format."""
        if self.is_null(index):
            raise Error("column " + String(index) + " is NULL")
        var raw = self.text(index)
        return raw == "t" or raw == "true" or raw == "1"

    def int_or(self, index: Int, fallback: Int) -> Int:
        try:
            return self.int(index)
        except:
            return fallback

    def float_or(self, index: Int, fallback: Float64) -> Float64:
        try:
            return self.float(index)
        except:
            return fallback

    def text_or(self, index: Int, fallback: StringSlice) -> String:
        try:
            if self.is_null(index):
                return String(fallback)
            return self.text(index)
        except:
            return String(fallback)


struct QueryResult(Movable):
    """Rows plus the metadata a caller needs to interpret them."""

    var columns: List[Column]
    var rows: List[Row]
    var command_tag: String
    var rows_affected: Int
    var notices: List[String]

    def __init__(out self):
        self.columns = List[Column]()
        self.rows = List[Row]()
        self.command_tag = String("")
        self.rows_affected = 0
        self.notices = List[String]()

    def row_count(self) -> Int:
        return len(self.rows)

    def column_count(self) -> Int:
        return len(self.columns)

    def column_index(self, name: StringSlice) -> Int:
        for i in range(len(self.columns)):
            if self.columns[i].name == name:
                return i
        return -1

    def column_names(self) -> List[String]:
        var out = List[String]()
        for i in range(len(self.columns)):
            out.append(self.columns[i].name)
        return out^

    def get(self, row: Int, column: StringSlice) raises -> String:
        var index = self.column_index(column)
        if index < 0:
            raise Error("no column named '" + String(column) + "'")
        if row < 0 or row >= len(self.rows):
            raise Error("row index " + String(row) + " out of range")
        return self.rows[row].text(index)

    def scalar(self) raises -> String:
        """The single value of a single-row, single-column result."""
        if len(self.rows) == 0:
            raise Error("query returned no rows")
        if len(self.columns) == 0:
            raise Error("query returned no columns")
        return self.rows[0].text(0)


def parse_command_tag(tag: StringSlice) -> Int:
    """Pull the row count out of tags like 'INSERT 0 3' or 'UPDATE 12'."""
    var parts = String(tag).split(" ")
    if len(parts) == 0:
        return 0
    try:
        return Int(parts[len(parts) - 1])
    except:
        return 0
