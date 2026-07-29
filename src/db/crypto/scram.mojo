"""SCRAM-SHA-256 client (RFC 5802, RFC 7677).

This is the default authentication method on modern PostgreSQL, so a driver
without it can only talk to trust/md5 servers.

Channel binding is not implemented: it requires TLS, and this package speaks
plaintext today. We therefore advertise `n` (client does not support channel
binding) rather than `y`, which is the honest signal and what the server
expects from a non-TLS client.

The server's final signature *is* verified. Skipping that check is a real
weakness - it is what proves the server knew the stored key rather than just
accepting anything - and it costs one HMAC.
"""

from std.ffi import external_call

from db.crypto.base64 import decode, encode
from db.crypto.sha256 import (
    constant_time_equal,
    hmac_sha256,
    pbkdf2_sha256,
    sha256,
)

comptime GS2_HEADER = "n,,"
comptime GS2_HEADER_B64 = "biws"  # base64("n,,"), fixed since we never bind
comptime NONCE_BYTES: Int = 18
comptime MECHANISM = "SCRAM-SHA-256"


def random_nonce() raises -> String:
    """A client nonce from the kernel CSPRNG.

    A predictable nonce lets an observer replay a captured exchange, so this
    must not fall back to a clock.
    """
    var buffer = List[UInt8](length=NONCE_BYTES, fill=0)
    var got = external_call["getrandom", Int](buffer.unsafe_ptr(), NONCE_BYTES, Int(0))
    if got != NONCE_BYTES:
        raise Error("getrandom() failed; refusing to use a weak nonce")
    return encode(Span(buffer))


def _field(message: StringSlice, key: UInt8) raises -> String:
    """Extract `k=value` from a comma-separated SCRAM message."""
    var parts = String(message).split(",")
    for i in range(len(parts)):
        var part = parts[i]
        var bytes = part.as_bytes()
        if len(bytes) >= 2 and bytes[0] == key and bytes[1] == 61:  # '='
            return String(part[byte=2:])
    raise Error("SCRAM message missing field '" + chr(Int(key)) + "'")


def _bytes(text: StringSlice) -> List[UInt8]:
    var out = List[UInt8]()
    var b = text.as_bytes()
    for i in range(len(b)):
        out.append(b[i])
    return out^


struct ScramClient(Movable):
    """Drives the three-message SCRAM exchange."""

    var username: String
    var password: String
    var client_nonce: String
    var client_first_bare: String
    var auth_message: String
    var server_signature: List[UInt8]
    var finished: Bool

    def __init__(out self, username: StringSlice, password: StringSlice) raises:
        self.username = String(username)
        self.password = String(password)
        self.client_nonce = random_nonce()
        self.client_first_bare = String("")
        self.auth_message = String("")
        self.server_signature = List[UInt8]()
        self.finished = False

    def client_first(mut self) -> String:
        """`n,,n=<user>,r=<nonce>`.

        The username is sent empty because PostgreSQL takes it from the
        startup packet; RFC 5802 allows `n=` to be ignored this way.
        """
        self.client_first_bare = String("n=,r=") + self.client_nonce
        return String(GS2_HEADER) + self.client_first_bare

    def client_final(mut self, server_first: StringSlice) raises -> String:
        """Consume the server-first message and produce client-final."""
        var combined_nonce = _field(server_first, 114)  # 'r'
        var salt_b64 = _field(server_first, 115)  # 's'
        var iterations_text = _field(server_first, 105)  # 'i'

        # The server nonce must extend ours, or this is not our exchange.
        if not combined_nonce.startswith(self.client_nonce):
            raise Error("SCRAM server nonce does not extend the client nonce")

        var iterations = Int(iterations_text)
        if iterations < 1:
            raise Error("SCRAM iteration count is not positive")
        if iterations > 1000000:
            # A hostile server could otherwise pin the client in PBKDF2.
            raise Error("SCRAM iteration count is implausibly large")

        var salt = decode(salt_b64)
        var password_bytes = _bytes(self.password)

        var salted = pbkdf2_sha256(Span(password_bytes), Span(salt), iterations)
        var client_key = hmac_sha256(Span(salted), Span(_bytes("Client Key")))
        var stored_key = sha256(Span(client_key))

        var without_proof = String("c=") + GS2_HEADER_B64 + ",r=" + combined_nonce
        self.auth_message = (
            self.client_first_bare + "," + String(server_first) + "," + without_proof
        )
        var auth_bytes = _bytes(self.auth_message)

        var client_signature = hmac_sha256(Span(stored_key), Span(auth_bytes))
        var proof = List[UInt8](capacity=len(client_key))
        for i in range(len(client_key)):
            proof.append(client_key[i] ^ client_signature[i])

        var server_key = hmac_sha256(Span(salted), Span(_bytes("Server Key")))
        self.server_signature = hmac_sha256(Span(server_key), Span(auth_bytes))

        return without_proof + ",p=" + encode(Span(proof))

    def verify_server_final(mut self, server_final: StringSlice) raises:
        """Check `v=` against the signature we derived.

        A mismatch means the peer did not hold the stored key - treat it as a
        failed handshake, not a warning.
        """
        var error_field = String(server_final)
        if error_field.startswith("e="):
            raise Error("SCRAM authentication failed: " + String(error_field[byte=2:]))

        var signature_b64 = _field(server_final, 118)  # 'v'
        var received = decode(signature_b64)

        if len(received) != len(self.server_signature):
            raise Error("SCRAM server signature has the wrong length")

        if not constant_time_equal(Span(received), Span(self.server_signature)):
            raise Error("SCRAM server signature mismatch; server is not authentic")

        self.finished = True
