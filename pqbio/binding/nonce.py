"""Challenge issuance and nonce lifecycle (PROJECT_SPEC.md §5.3).

Owner: Abhijay

The nonce is the seed pqbio.capture.challenge derives its illumination colour sequence
from — `expected_illumination_sequence` below wraps that same PRF rather than
reimplementing it, so nonce.py and capture/challenge.py can never silently disagree.

Nonce lifecycle: issued -> consumed, single-use, atomic, SQLite-backed (WAL). Consuming
a nonce is one `UPDATE ... WHERE consumed = 0` statement with a rowcount check — never
read-then-write — so N concurrent callers racing on the same nonce have exactly one
winner, enforced by SQLite's own write serialisation, not a Python-level lock.
"""

from __future__ import annotations

import os
import sqlite3
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from uuid import UUID

from pqbio.capture.challenge import derive_illumination_sequence
from pqbio.config import settings
from pqbio.pqc.sign import Signer
from pqbio.schemas import Challenge, Txn, canonical_cbor_encode, model_signing_payload, sha256


def expected_illumination_sequence(nonce: bytes) -> list[int]:
    """The colour sequence a genuine capture must reproduce, derived from `nonce` via
    the one shared PRF (pqbio.capture.challenge.derive_illumination_sequence) — used by
    pqbio.binding.verify's B6 check. `illumination_steps` comes from config, never
    hardcoded here.
    """
    return derive_illumination_sequence(nonce, settings.binding.illumination_steps)


class NonceStore:
    """SQLite-backed, single-use nonce cache (binding check B3). Each call opens its own
    short-lived connection against the same on-disk file — real concurrent processes/
    threads/workers share correctness through SQLite's file-level locking (WAL mode,
    busy_timeout) rather than a single Python object's internal state, which is the
    only way "atomic under N concurrent callers" is a meaningful claim.

    `db_path` must be a real file path, not `:memory:` — an in-memory SQLite database is
    private to one connection, so concurrent callers opening separate connections would
    each see an empty, independent database. Module E owns choosing the real path.
    """

    def __init__(self, db_path: str | Path) -> None:
        self._db_path = str(db_path)
        with self._connect() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS nonces (
                    nonce BLOB PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    issued_at_ns INTEGER NOT NULL,
                    expires_at_ns INTEGER NOT NULL,
                    consumed INTEGER NOT NULL DEFAULT 0
                )
                """)

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        # isolation_level=None -> autocommit: every statement is its own transaction,
        # which is exactly the "single atomic statement" the consume() contract needs.
        #
        # `with conn:` on a raw sqlite3.Connection only commits/rolls back a
        # transaction on exit -- it does NOT close the connection. Under autocommit
        # there's no transaction for that to matter, but the connection itself was
        # never being closed either way, which Windows' exclusive-lock file semantics
        # (unlike POSIX, which allows unlinking an open file) turns into real
        # PermissionErrors on any cleanup that tries to delete the db file shortly
        # after. This wrapper is what actually closes it.
        conn = sqlite3.connect(self._db_path, timeout=5.0, isolation_level=None)
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA busy_timeout=5000;")
        try:
            yield conn
        finally:
            conn.close()

    def record_issued(
        self, nonce: bytes, session_id: UUID, issued_at_ns: int, expires_at_ns: int
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO nonces (nonce, session_id, issued_at_ns, expires_at_ns, consumed) "
                "VALUES (?, ?, ?, ?, 0)",
                (nonce, str(session_id), issued_at_ns, expires_at_ns),
            )

    def consume(self, nonce: bytes) -> bool:
        """Atomically mark `nonce` consumed. Returns True iff *this* call is the one
        that consumed it — under concurrent callers racing the same nonce, exactly one
        gets True. An unknown nonce (never issued) also returns False: there is no row
        to match, so the UPDATE affects zero rows either way — unknown and
        already-consumed are indistinguishable here by design (both mean "do not
        proceed"), see pqbio.binding.verify's B3 check.
        """
        with self._connect() as conn:
            cur = conn.execute(
                "UPDATE nonces SET consumed = 1 WHERE nonce = ? AND consumed = 0", (nonce,)
            )
            return cur.rowcount == 1


def issue_challenge(
    *,
    session_id: UUID,
    txn: Txn,
    signer: Signer,
    server_sk: bytes,
    nonce_store: NonceStore,
    now_ns: int | None = None,
) -> Challenge:
    """Build, sign, and record a fresh Challenge (§5.3): session_id, a CSPRNG nonce,
    the transaction descriptor and its hash, an expiry `challenge_ttl_s` out, and the
    server's ML-DSA signature over everything else.
    """
    now_ns = now_ns if now_ns is not None else time.time_ns()
    nonce = os.urandom(settings.binding.nonce_bytes)
    txn_payload = canonical_cbor_encode(txn.model_dump(mode="python"))
    txn_hash = sha256(txn_payload)
    expires_at_ns = now_ns + settings.binding.challenge_ttl_s * 1_000_000_000

    challenge = Challenge(
        session_id=session_id,
        nonce=nonce,
        txn=txn,
        txn_hash=txn_hash,
        issued_at=now_ns,
        expires_at=expires_at_ns,
    )
    payload = model_signing_payload(challenge, exclude={"server_sig"})
    server_sig = signer.sign(sha256(payload), server_sk)
    signed_challenge = challenge.model_copy(update={"server_sig": server_sig})

    nonce_store.record_issued(nonce, session_id, now_ns, expires_at_ns)
    return signed_challenge
