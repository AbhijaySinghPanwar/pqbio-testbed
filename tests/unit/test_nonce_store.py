"""Tests for pqbio.binding.nonce (§5.3 DoD: B3 positive/negative + concurrency)."""

from __future__ import annotations

import hashlib
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from uuid import uuid4

from pqbio.binding.nonce import NonceStore, expected_illumination_sequence, issue_challenge
from pqbio.capture.challenge import derive_illumination_sequence
from pqbio.pqc.sign import get_signer
from pqbio.schemas import Txn


def _store(tmp_path: Path) -> NonceStore:
    return NonceStore(tmp_path / "nonces.db")


def test_record_and_consume_happy_path(tmp_path: Path) -> None:
    store = _store(tmp_path)
    nonce = b"n" * 32
    store.record_issued(nonce, uuid4(), issued_at_ns=1, expires_at_ns=2)
    assert store.consume(nonce) is True


def test_consume_twice_second_call_fails(tmp_path: Path) -> None:
    """Positive/negative pair for B3: first consumption succeeds, replay fails."""
    store = _store(tmp_path)
    nonce = b"n" * 32
    store.record_issued(nonce, uuid4(), issued_at_ns=1, expires_at_ns=2)
    assert store.consume(nonce) is True
    assert store.consume(nonce) is False


def test_consume_unknown_nonce_fails(tmp_path: Path) -> None:
    store = _store(tmp_path)
    assert store.consume(b"never-issued-" + b"x" * 19) is False


def test_wal_mode_enabled(tmp_path: Path) -> None:
    import sqlite3

    db_path = tmp_path / "nonces.db"
    NonceStore(db_path)
    conn = sqlite3.connect(str(db_path))
    mode = conn.execute("PRAGMA journal_mode;").fetchone()[0]
    conn.close()
    assert mode.lower() == "wal"


def test_concurrent_consume_exactly_one_winner_threads(tmp_path: Path) -> None:
    """§5.3 DoD: "atomic under 100 concurrent requests with the same nonce — exactly
    one succeeds". Real threads, synchronised with a Barrier so they hit consume() as
    close to simultaneously as possible — not sequential calls dressed up as concurrent.
    """
    store = _store(tmp_path)
    nonce = b"race" + b"x" * 28
    store.record_issued(nonce, uuid4(), issued_at_ns=1, expires_at_ns=10**18)

    n_workers = 100
    barrier = threading.Barrier(n_workers)

    def worker() -> bool:
        barrier.wait()  # line everyone up so consume() calls actually overlap
        return store.consume(nonce)

    with ThreadPoolExecutor(max_workers=n_workers) as pool:
        results = list(pool.map(lambda _: worker(), range(n_workers)))

    assert results.count(True) == 1
    assert results.count(False) == n_workers - 1


def test_concurrent_consume_different_nonces_all_succeed(tmp_path: Path) -> None:
    """Sanity check the concurrency harness itself isn't just serialising everything
    into failure: distinct nonces racing concurrently should all succeed.
    """
    store = _store(tmp_path)
    nonces = [hashlib.sha256(f"distinct-{i}".encode()).digest() for i in range(50)]
    for n in nonces:
        store.record_issued(n, uuid4(), issued_at_ns=1, expires_at_ns=10**18)

    barrier = threading.Barrier(len(nonces))

    def worker(nonce: bytes) -> bool:
        barrier.wait()
        return store.consume(nonce)

    with ThreadPoolExecutor(max_workers=len(nonces)) as pool:
        results = list(pool.map(worker, nonces))

    assert all(results)


def test_issue_challenge_produces_signed_challenge_and_records_nonce(tmp_path: Path) -> None:
    store = _store(tmp_path)
    signer = get_signer("pq")
    server_pk, server_sk = signer.keygen()
    txn = Txn(action="login", relying_party="bank.example")

    challenge = issue_challenge(
        session_id=uuid4(), txn=txn, signer=signer, server_sk=server_sk, nonce_store=store
    )

    assert len(challenge.nonce) == 32
    assert challenge.server_sig != b""
    # the nonce was recorded as issued -> first consumption succeeds
    assert store.consume(challenge.nonce) is True


def test_expected_illumination_sequence_matches_capture_challenge_prf() -> None:
    """nonce.py must not reimplement the PRF — same nonce, same sequence, via the one
    shared implementation.
    """
    nonce = b"n" * 32
    from pqbio.config import settings

    assert expected_illumination_sequence(nonce) == derive_illumination_sequence(
        nonce, settings.binding.illumination_steps
    )


def test_issue_challenge_expiry_uses_configured_ttl(tmp_path: Path) -> None:
    from pqbio.config import settings

    store = _store(tmp_path)
    signer = get_signer("pq")
    server_pk, server_sk = signer.keygen()
    txn = Txn(action="login", relying_party="bank.example")
    now_ns = time.time_ns()

    challenge = issue_challenge(
        session_id=uuid4(),
        txn=txn,
        signer=signer,
        server_sk=server_sk,
        nonce_store=store,
        now_ns=now_ns,
    )
    assert challenge.expires_at == now_ns + settings.binding.challenge_ttl_s * 1_000_000_000
