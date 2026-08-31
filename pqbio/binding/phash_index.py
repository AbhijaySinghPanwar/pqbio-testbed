"""Seen-evidence perceptual-hash index (PROJECT_SPEC.md §5.3).

Owner: Abhijay

This is what actually satisfies "prevent the reuse of previously captured biometric
evidence": binding checks B1-B5 stop resubmission of the same signed *message*, but a
correctly-signed, freshly-nonced session wrapped around a victim's *previously captured
genuine media* sails through B1-B5 untouched. This index is what catches that.

**Only ACCEPTED bundles are ever recorded here — never during verification.** That is
enforced in this module's shape, not just documented: `PhashIndex.check_reuse` is
read-only (no write path reachable from it), and `record_accepted_bundle` is the only
method that writes, meant to be called from the accept path only (Module E, not built
yet). Storing a rejected bundle's hashes would let an attacker poison the index by
submitting a *victim's* genuine media once, under any garbage session — causing the
victim's own later real capture to be refused as "reused". Never call
`record_accepted_bundle` before a decision is ACCEPT.
"""

from __future__ import annotations

import io
import sqlite3
import time
from pathlib import Path

import imagehash
from PIL import Image


def compute_phash(frame_jpeg: bytes) -> str:
    """Perceptual hash of one JPEG-encoded frame, as a hex string (imagehash's own
    representation — round-trips exactly via imagehash.hex_to_hash).
    """
    image = Image.open(io.BytesIO(frame_jpeg))
    return str(imagehash.phash(image))


def _hamming(a_hex: str, b_hex: str) -> int:
    return imagehash.hex_to_hash(a_hex) - imagehash.hex_to_hash(b_hex)


class _BKNode:
    __slots__ = ("hash_hex", "children")

    def __init__(self, hash_hex: str) -> None:
        self.hash_hex = hash_hex
        self.children: dict[int, _BKNode] = {}


class BKTree:
    """In-memory BK-tree over hex-encoded perceptual hashes, for Hamming-distance
    range queries in better-than-linear time. Purely a lookup accelerator: the SQLite
    table is the source of truth, and this tree is always rebuilt from it on startup
    (see PhashIndex) — never the other way around.
    """

    def __init__(self) -> None:
        self._root: _BKNode | None = None

    def add(self, hash_hex: str) -> None:
        if self._root is None:
            self._root = _BKNode(hash_hex)
            return
        node = self._root
        while True:
            d = _hamming(hash_hex, node.hash_hex)
            if d == 0:
                return  # exact duplicate already present
            child = node.children.get(d)
            if child is None:
                node.children[d] = _BKNode(hash_hex)
                return
            node = child

    def find_within(self, hash_hex: str, max_distance: int) -> list[tuple[str, int]]:
        if self._root is None:
            return []
        results: list[tuple[str, int]] = []
        stack = [self._root]
        while stack:
            node = stack.pop()
            d = _hamming(hash_hex, node.hash_hex)
            if d <= max_distance:
                results.append((node.hash_hex, d))
            for edge_d, child in node.children.items():
                if d - max_distance <= edge_d <= d + max_distance:
                    stack.append(child)
        return results


class PhashIndex:
    """SQLite-backed store of accepted-bundle frame hashes, with a BK-tree accelerator
    that is rebuilt from SQLite every time this class is constructed — so a process
    restart never silently loses detection, and the tree can never drift from the
    table (see tests/unit/test_phash_index.py's restart-preserves-detection test).

    `db_path` must be a real file path, not `:memory:` (same reasoning as
    pqbio.binding.nonce.NonceStore).
    """

    def __init__(self, db_path: str | Path) -> None:
        self._db_path = str(db_path)
        with self._connect() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS accepted_frame_hashes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    phash_hex TEXT NOT NULL,
                    recorded_at_ns INTEGER NOT NULL
                )
                """)
        self._tree = self._rebuild_tree_from_sqlite()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, timeout=5.0, isolation_level=None)
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA busy_timeout=5000;")
        return conn

    def _rebuild_tree_from_sqlite(self) -> BKTree:
        tree = BKTree()
        with self._connect() as conn:
            for (phash_hex,) in conn.execute("SELECT phash_hex FROM accepted_frame_hashes"):
                tree.add(phash_hex)
        return tree

    def check_reuse(
        self, frame_jpegs: list[bytes], max_distance: int
    ) -> list[tuple[int, str, int]]:
        """Read-only. For each frame, look up already-accepted hashes within
        `max_distance`. Returns (frame_index, matched_hash_hex, distance) for every
        match — empty means no single-frame match at all. This method never writes to
        the index; see the module docstring for why that matters.

        This is the low-level primitive; `is_burst_reused` below is what
        `pqbio.binding.verify.check_evidence_reuse` actually uses to decide
        `BIND_EVIDENCE_REUSE` (§5.3, §14's N-of-burst amendment) — a single frame
        landing within `max_distance` of something already accepted is common enough
        between two genuinely distinct captures of the same person that it is not, on
        its own, evidence of reuse. See `is_burst_reused`'s docstring for why.
        """
        hits: list[tuple[int, str, int]] = []
        for idx, frame_jpeg in enumerate(frame_jpegs):
            frame_hash = compute_phash(frame_jpeg)
            for matched_hex, distance in self._tree.find_within(frame_hash, max_distance):
                hits.append((idx, matched_hex, distance))
        return hits

    def is_burst_reused(
        self, frame_jpegs: list[bytes], max_distance: int, min_matching_frames: int
    ) -> bool:
        """True iff at least `min_matching_frames` *distinct* frames in `frame_jpegs`
        each have >=1 match within `max_distance` against previously accepted hashes.

        §14 found that per-frame Hamming distance alone can't serve both goals at a
        single threshold: distance 6 already had a ~13% synthetic within-subject false
        positive rate, and raising it to 10 (the floor that still catches aggressive
        JPEG re-encoding) makes single-frame collisions between distinct captures of
        the same person routine, not rare. Requiring N matching frames out of a burst
        was the proposed fix — measured with
        `scripts/measure_phash_burst_calibration.py`, which found the mitigation
        weaker than hoped (burst frames are highly correlated: within one capture,
        nearly all frames share the same coarse pose/lighting, so a false-positive
        collision tends to hit *all* frames of a burst or *none*, not some fraction
        that scales smoothly with N — see PROJECT_SPEC.md §14 for the full numbers).
        `min_matching_frames` is still config-driven (`phash_reuse_min_frames`), not
        hardcoded, so it can be revised as real data becomes available.
        """
        hits = self.check_reuse(frame_jpegs, max_distance)
        matching_frame_indices = {idx for idx, _matched_hex, _distance in hits}
        return len(matching_frame_indices) >= min_matching_frames

    def record_accepted_bundle(self, session_id: str, frame_jpegs: list[bytes]) -> None:
        """Record every frame's hash for an ACCEPTED bundle. Call this only from the
        accept path (after a decision is ACCEPT) — never from verification. See the
        module docstring.
        """
        now_ns = time.time_ns()
        hashes = [compute_phash(f) for f in frame_jpegs]
        with self._connect() as conn:
            conn.executemany(
                "INSERT INTO accepted_frame_hashes (session_id, phash_hex, recorded_at_ns) "
                "VALUES (?, ?, ?)",
                [(session_id, h, now_ns) for h in hashes],
            )
        for h in hashes:
            self._tree.add(h)
