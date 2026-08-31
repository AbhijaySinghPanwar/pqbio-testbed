"""SQLite persistence: devices, sessions, audit (PROJECT_SPEC.md §5.5).

Owner: Abhijay

Reuses `pqbio.binding.nonce.NonceStore` and `pqbio.binding.phash_index.PhashIndex`
as-is for nonce single-use and evidence-reuse state — this module does not
reimplement either; the pipeline just constructs them against a path here.

`SqliteKeyStore` implements the exact method contract
`pqbio.pqc.keystore.KeyStore` already documents as "the contract that backing store
will need to satisfy" — same `enroll`/`get`/`update_counter` shape, `DeviceRecord`
return type, same exceptions, just SQLite-backed instead of an in-memory dict, so
`pqbio.binding.verify.check_b4_counter` works against it unchanged.
"""

from __future__ import annotations

import sqlite3
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from uuid import UUID

from pqbio.pqc.handshake import HandshakeSession, HandshakeState, ProtocolStateError
from pqbio.pqc.keystore import DeviceRecord, DuplicateEnrolmentError, UnknownDeviceError


@contextmanager
def _connect(db_path: str | Path) -> Iterator[sqlite3.Connection]:
    # `with conn:` on a raw sqlite3.Connection commits/rolls back but never closes it
    # -- see pqbio.binding.nonce.NonceStore._connect for why this wrapper (not a bare
    # `with sqlite3.connect(...) as conn:`) is required; on Windows an unclosed handle
    # made tempdir cleanup in tests fail with PermissionError, not just a theoretical
    # leak.
    conn = sqlite3.connect(str(db_path), timeout=5.0, isolation_level=None)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA busy_timeout=5000;")
    try:
        yield conn
    finally:
        conn.close()


class SqliteKeyStore:
    """SQLite-backed device key registry — see module docstring."""

    def __init__(self, db_path: str | Path) -> None:
        self._db_path = str(db_path)
        with _connect(self._db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS devices (
                    device_id TEXT PRIMARY KEY,
                    sig_pk BLOB NOT NULL,
                    sig_mode TEXT NOT NULL,
                    counter INTEGER NOT NULL DEFAULT 0,
                    face_template BLOB
                )
                """)

    def enroll(
        self, device_id: str, sig_pk: bytes, sig_mode: str, face_template: bytes | None = None
    ) -> DeviceRecord:
        with _connect(self._db_path) as conn:
            existing = conn.execute(
                "SELECT 1 FROM devices WHERE device_id = ?", (device_id,)
            ).fetchone()
            if existing is not None:
                raise DuplicateEnrolmentError(f"device already enrolled: {device_id}")
            conn.execute(
                "INSERT INTO devices (device_id, sig_pk, sig_mode, counter, face_template) "
                "VALUES (?, ?, ?, 0, ?)",
                (device_id, sig_pk, sig_mode, face_template),
            )
        return DeviceRecord(device_id=device_id, sig_pk=sig_pk, sig_mode=sig_mode, counter=0)

    def get(self, device_id: str) -> DeviceRecord:
        with _connect(self._db_path) as conn:
            row = conn.execute(
                "SELECT sig_pk, sig_mode, counter FROM devices WHERE device_id = ?", (device_id,)
            ).fetchone()
        if row is None:
            raise UnknownDeviceError(device_id)
        sig_pk, sig_mode, counter = row
        return DeviceRecord(device_id=device_id, sig_pk=sig_pk, sig_mode=sig_mode, counter=counter)

    def update_counter(self, device_id: str, counter: int) -> None:
        with _connect(self._db_path) as conn:
            row = conn.execute(
                "SELECT counter FROM devices WHERE device_id = ?", (device_id,)
            ).fetchone()
            if row is None:
                raise UnknownDeviceError(device_id)
            if counter <= row[0]:
                raise ValueError(f"counter regression for {device_id}: {counter} <= {row[0]}")
            conn.execute("UPDATE devices SET counter = ? WHERE device_id = ?", (counter, device_id))

    def get_face_template(self, device_id: str) -> bytes | None:
        with _connect(self._db_path) as conn:
            row = conn.execute(
                "SELECT face_template FROM devices WHERE device_id = ?", (device_id,)
            ).fetchone()
        if row is None:
            raise UnknownDeviceError(device_id)
        template: bytes | None = row[0]
        return template


class UnknownSessionError(KeyError):
    """Raised when a session_id was never created via SessionStore.create_session."""


class SessionStore:
    """SQLite-backed handshake session state. Reconstructs a `HandshakeSession` from
    the persisted (state, keyed_once) pair on every `transition()` call rather than
    keeping one in memory — a fresh `HandshakeSession()` always starts with
    `_keyed_once=False`, so that flag has to be persisted and restored explicitly, or
    the at-most-once-KEYED guarantee (§5.1) silently breaks across requests.
    """

    def __init__(self, db_path: str | Path) -> None:
        self._db_path = str(db_path)
        with _connect(self._db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS sessions (
                    session_id TEXT PRIMARY KEY,
                    device_id TEXT NOT NULL,
                    state TEXT NOT NULL,
                    keyed_once INTEGER NOT NULL DEFAULT 0,
                    challenge_cbor BLOB NOT NULL,
                    kem_ct BLOB,
                    k_c2s BLOB,
                    k_s2c BLOB,
                    expires_at_ns INTEGER NOT NULL,
                    created_at_ns INTEGER NOT NULL
                )
                """)

    def create_session(
        self, session_id: UUID, device_id: str, challenge_cbor: bytes, expires_at_ns: int
    ) -> None:
        """Issuing a challenge (Module C's `nonce.issue_challenge`) is exactly what
        synchronously takes a session from INIT to CHALLENGED — there's no meaningful
        separate INIT row, so this creates the session already in CHALLENGED.
        """
        with _connect(self._db_path) as conn:
            conn.execute(
                "INSERT INTO sessions "
                "(session_id, device_id, state, keyed_once, challenge_cbor, expires_at_ns, created_at_ns) "
                "VALUES (?, ?, ?, 0, ?, ?, ?)",
                (
                    str(session_id),
                    device_id,
                    HandshakeState.CHALLENGED.value,
                    challenge_cbor,
                    expires_at_ns,
                    time.time_ns(),
                ),
            )

    def _load(self, conn: sqlite3.Connection, session_id: UUID) -> tuple[str, int, bool, str]:
        row = conn.execute(
            "SELECT state, expires_at_ns, keyed_once, device_id FROM sessions WHERE session_id = ?",
            (str(session_id),),
        ).fetchone()
        if row is None:
            raise UnknownSessionError(str(session_id))
        return row[0], row[1], bool(row[2]), row[3]

    def transition(self, session_id: UUID, target: HandshakeState) -> None:
        """Raises `ProtocolStateError` on any illegal transition (§5.1) — and still
        persists the resulting REJECTED state before re-raising, so a rejected
        session can never be transitioned again on a later request either.
        """
        with _connect(self._db_path) as conn:
            state_str, expires_at_ns, keyed_once, _device_id = self._load(conn, session_id)
            session = HandshakeSession(
                session_id=str(session_id),
                expires_at_ns=expires_at_ns,
                state=HandshakeState(state_str),
            )
            session._keyed_once = keyed_once  # noqa: SLF001 -- restoring persisted invariant
            try:
                session.transition(target)
            except ProtocolStateError:
                raise
            finally:
                conn.execute(
                    "UPDATE sessions SET state = ?, keyed_once = ? WHERE session_id = ?",
                    (
                        session.state.value,
                        int(session._keyed_once),
                        str(session_id),
                    ),  # noqa: SLF001
                )

    def current_state(self, session_id: UUID) -> HandshakeState:
        """Read-only; also lazily expires (matching `HandshakeSession.current_state`)
        and persists that expiry so it's visible to every subsequent reader too.
        """
        with _connect(self._db_path) as conn:
            state_str, expires_at_ns, keyed_once, _device_id = self._load(conn, session_id)
            session = HandshakeSession(
                session_id=str(session_id),
                expires_at_ns=expires_at_ns,
                state=HandshakeState(state_str),
            )
            session._keyed_once = keyed_once  # noqa: SLF001
            resolved = session.current_state
            if resolved.value != state_str:
                conn.execute(
                    "UPDATE sessions SET state = ? WHERE session_id = ?",
                    (resolved.value, str(session_id)),
                )
            return resolved

    def get_device_id(self, session_id: UUID) -> str:
        with _connect(self._db_path) as conn:
            _state, _exp, _keyed, device_id = self._load(conn, session_id)
            return device_id

    def get_challenge_cbor(self, session_id: UUID) -> bytes:
        with _connect(self._db_path) as conn:
            row = conn.execute(
                "SELECT challenge_cbor FROM sessions WHERE session_id = ?", (str(session_id),)
            ).fetchone()
        if row is None:
            raise UnknownSessionError(str(session_id))
        return bytes(row[0])

    def set_kem_ct_and_keys(
        self, session_id: UUID, kem_ct: bytes, k_c2s: bytes, k_s2c: bytes
    ) -> None:
        with _connect(self._db_path) as conn:
            conn.execute(
                "UPDATE sessions SET kem_ct = ?, k_c2s = ?, k_s2c = ? WHERE session_id = ?",
                (kem_ct, k_c2s, k_s2c, str(session_id)),
            )

    def get_session_keys(self, session_id: UUID) -> tuple[bytes, bytes]:
        with _connect(self._db_path) as conn:
            row = conn.execute(
                "SELECT k_c2s, k_s2c FROM sessions WHERE session_id = ?", (str(session_id),)
            ).fetchone()
        if row is None or row[0] is None:
            raise UnknownSessionError(str(session_id))
        return bytes(row[0]), bytes(row[1])


class AuditLog:
    """Append-only. Stores scores, reason codes, and frame *hashes* — never raw
    frames, except when `research_retain=True` is set explicitly (server/app.py's
    `--research-retain` flag), matching §5.5 exactly.
    """

    def __init__(self, db_path: str | Path, research_retain: bool = False) -> None:
        self._db_path = str(db_path)
        self._research_retain = research_retain
        with _connect(self._db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    device_id TEXT NOT NULL,
                    recorded_at_ns INTEGER NOT NULL,
                    decision_json TEXT NOT NULL,
                    frame_hashes_json TEXT NOT NULL,
                    raw_frames BLOB
                )
                """)

    def record(
        self,
        *,
        session_id: UUID,
        device_id: str,
        decision_json: str,
        frame_hashes: list[str],
        raw_frames: list[bytes] | None = None,
    ) -> None:
        import json as _json

        retained_frames = None
        if self._research_retain and raw_frames is not None:
            retained_frames = _json.dumps([f.hex() for f in raw_frames]).encode("utf-8")
        with _connect(self._db_path) as conn:
            conn.execute(
                "INSERT INTO audit_log "
                "(session_id, device_id, recorded_at_ns, decision_json, frame_hashes_json, raw_frames) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (
                    str(session_id),
                    device_id,
                    time.time_ns(),
                    decision_json,
                    _json.dumps(frame_hashes),
                    retained_frames,
                ),
            )
