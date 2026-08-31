"""Full binding verification: checks B1-B6 (PROJECT_SPEC.md §5.3, deliverable D3).

Owner: Abhijay

Every check runs against the already-decrypted, already-signature-verified bundle (that
happens upstream, in Module E's pipeline stage 1 — not here). All six checks always run,
regardless of earlier failures: the fusion layer in Module D consumes `binding_flags` as
a 6-bit feature vector, so all six bits must be present even when an early check already
failed. Fail closed — every check function catches its own exceptions and reports a
failure, never lets one propagate as a skip.

Each check is exposed as its own public `check_b*` function (not just bundled inside
`verify_binding`) because Module E's pipeline runs them at different stages for latency
(B1-B5 fail-fast together; B6 groups with other "cheap signal" checks) — `verify_binding`
is a convenience orchestrator for this module's own testing, not the only supported
entry point.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Protocol

import numpy as np

from pqbio.binding.nonce import NonceStore, expected_illumination_sequence
from pqbio.binding.phash_index import PhashIndex
from pqbio.capture.bundler import compute_capture_binding
from pqbio.capture.challenge import PALETTE_BGR
from pqbio.config import settings
from pqbio.pqc.keystore import DeviceRecord
from pqbio.pqc.sign import Signer, constant_time_eq
from pqbio.schemas import Challenge, EvidenceBundle, model_signing_payload, sha256

CHECK_NAMES = ("B1", "B2", "B3", "B4", "B5", "B6")


class KeyStoreLike(Protocol):
    """The one method B4 needs from a device-key store, as a structural type rather
    than the concrete in-memory `pqbio.pqc.keystore.KeyStore` -- its own docstring
    already calls its method signatures "the contract that backing store will need to
    satisfy", i.e. duck typing was always the intent, not inheritance. Both `KeyStore`
    and Module E's SQLite-backed `pqbio.server.store.SqliteKeyStore` satisfy this
    without either needing to import or subclass the other.
    """

    def get(self, device_id: str) -> DeviceRecord: ...


@dataclass(frozen=True)
class CheckResult:
    check: str  # "B1".."B6"
    passed: bool
    reason_code: str  # the table's failure code, or "<check>_OK" when passed


@dataclass(frozen=True)
class BindingVerificationResult:
    checks: tuple[CheckResult, CheckResult, CheckResult, CheckResult, CheckResult, CheckResult]

    def __post_init__(self) -> None:
        names = tuple(c.check for c in self.checks)
        if names != CHECK_NAMES:
            raise ValueError(f"checks must be exactly {CHECK_NAMES} in order, got {names}")

    @property
    def passed(self) -> bool:
        return all(c.passed for c in self.checks)

    @property
    def binding_flags(self) -> tuple[bool, bool, bool, bool, bool, bool]:
        """6-bit feature vector, B1..B6 order — Module D's fusion input (§5.4)."""
        c1, c2, c3, c4, c5, c6 = self.checks
        return (c1.passed, c2.passed, c3.passed, c4.passed, c5.passed, c6.passed)

    @property
    def reason_codes(self) -> list[str]:
        """Every failing check's reason code, in B1..B6 order. Empty iff all six pass."""
        return [c.reason_code for c in self.checks if not c.passed]


def check_b1_challenge_signature(
    challenge: Challenge, signer: Signer, server_pk: bytes
) -> CheckResult:
    """B1: the server's signature on the echoed challenge is valid."""
    try:
        payload = model_signing_payload(challenge, exclude={"server_sig"})
        passed = signer.verify(sha256(payload), challenge.server_sig, server_pk)
    except Exception:
        passed = False
    return CheckResult("B1", passed, "B1_OK" if passed else "BIND_CHALLENGE_FORGED")


def check_b2_expiry(challenge: Challenge, now_ns: int) -> CheckResult:
    """B2: within expiry, allowing ±`clock_skew_s` clock skew (config, default 2s)."""
    try:
        skew_ns = settings.binding.clock_skew_s * 1_000_000_000
        passed = now_ns <= challenge.expires_at + skew_ns
    except Exception:
        passed = False
    return CheckResult("B2", passed, "B2_OK" if passed else "BIND_EXPIRED")


def check_b3_nonce_freshness(nonce: bytes, nonce_store: NonceStore) -> CheckResult:
    """B3: the nonce was issued and not yet consumed; consumption is atomic.

    This check *is* the consumption — `NonceStore.consume` is the one atomic UPDATE
    that makes single-use enforcement correct under concurrency (see nonce.py). An
    unissued and an already-consumed nonce both fail identically here, which is
    correct: neither should ever proceed.
    """
    try:
        passed = nonce_store.consume(nonce)
    except Exception:
        passed = False
    return CheckResult("B3", passed, "B3_OK" if passed else "BIND_NONCE_REPLAY")


def check_b4_counter(device_id: str, counter: int, keystore: KeyStoreLike) -> CheckResult:
    """B4: device counter strictly greater than last seen.

    Read-only — does *not* advance the stored counter. Advancing belongs to the accept
    path only (Module E), mirroring why `PhashIndex.record_accepted_bundle` is kept out
    of the verification path: a check that mutated state on a bundle that later gets
    rejected by some other check would burn the counter for nothing.
    """
    try:
        record = keystore.get(device_id)
        passed = counter > record.counter
    except Exception:
        passed = False
    return CheckResult("B4", passed, "B4_OK" if passed else "BIND_COUNTER_REGRESSION")


def check_b5_capture_binding(bundle: EvidenceBundle) -> CheckResult:
    """B5: `capture_binding` recomputes from nonce, txn_hash, and frame hashes —
    reuses pqbio.capture.bundler.compute_capture_binding, the same function the client
    used to compute it, rather than a second implementation of the formula.
    """
    try:
        recomputed = compute_capture_binding(
            bundle.challenge_echo.nonce, bundle.challenge_echo.txn_hash, bundle.frames
        )
        passed = constant_time_eq(recomputed, bundle.capture_binding)
    except Exception:
        passed = False
    return CheckResult("B5", passed, "B5_OK" if passed else "BIND_DIGEST_MISMATCH")


def _expand_expected_trace(expected_indices: list[int], n_frames: int) -> list[float]:
    """Map the `illumination_steps` colour indices evenly across `n_frames` captured
    frames, in the same flat [R,G,B, R,G,B, ...] convention as
    pqbio.capture.challenge.measure_chromaticity_trace.

    This even split is a documented approximation: precise per-frame/step timing
    alignment would need the client to report exactly when each challenge step was
    displayed relative to each frame's capture_ts_ns, and Module B's live render+capture
    interleaving isn't wired up yet (see PROJECT_SPEC.md §14's Module B webcam
    amendment) — there is nothing more precise to align against yet. Good enough to
    validate that the correlation signal itself works; revisit once render+capture are
    interleaved for real.
    """
    steps = len(expected_indices)
    if steps == 0 or n_frames == 0:
        return []
    trace: list[float] = []
    for frame_idx in range(n_frames):
        step_idx = min(frame_idx * steps // n_frames, steps - 1)
        b, g, r = PALETTE_BGR[expected_indices[step_idx]]
        trace.extend((r / 255.0, g / 255.0, b / 255.0))
    return trace


def _pearson_r(a: list[float], b: list[float]) -> float:
    if len(a) != len(b) or len(a) < 2:
        return 0.0
    arr_a, arr_b = np.asarray(a, dtype=float), np.asarray(b, dtype=float)
    if np.std(arr_a) == 0 or np.std(arr_b) == 0:
        return 0.0  # a constant sequence cannot correlate with anything, including itself
    return float(np.corrcoef(arr_a, arr_b)[0, 1])


def compute_challenge_correlation(bundle: EvidenceBundle) -> float:
    """The raw Pearson r between the bundle's measured challenge signal and the
    expectation derived from its nonce — the number `check_b6_challenge_correlation`
    thresholds, and also D5's "challenge-illumination correlation" injection feature
    (pqbio/detect/injection.py): a pre-recorded/injected stream cannot satisfy a fresh
    challenge either, so this one computation feeds both. Returns 0.0 (never raises) if
    the trace lengths mismatch or either sequence is constant — see `_pearson_r`.
    """
    expected_indices = expected_illumination_sequence(bundle.challenge_echo.nonce)
    expected_trace = _expand_expected_trace(expected_indices, len(bundle.frame_meta))
    measured_trace = bundle.challenge_signal.illumination_trace
    return _pearson_r(measured_trace, expected_trace)


def check_b6_challenge_correlation(bundle: EvidenceBundle) -> CheckResult:
    """B6: the measured challenge signal correlates with the expectation derived from
    the nonce, at or above `illumination_corr_min` (config, default Pearson r >= 0.70).
    """
    try:
        r = compute_challenge_correlation(bundle)
        passed = r >= settings.binding.illumination_corr_min
    except Exception:
        passed = False
    return CheckResult("B6", passed, "B6_OK" if passed else "BIND_CHALLENGE_UNMET")


def check_evidence_reuse(
    bundle: EvidenceBundle,
    phash_index: PhashIndex,
    max_distance: int | None = None,
    min_matching_frames: int | None = None,
) -> CheckResult:
    """Not one of B1-B6 — a separate check via the seen-evidence index
    (phash_index.py), kept structurally separate (own CheckResult, not folded into
    `BindingVerificationResult.binding_flags`'s six slots) because it lives in a
    different pipeline stage in Module E's design (§5.5: stage 5, after B1-B5's
    fail-fast group and B6's "cheap signals" group). Read-only — never writes to the
    index; see phash_index.py's module docstring for why that matters.

    Fires `BIND_EVIDENCE_REUSE` on `PhashIndex.is_burst_reused` — at least
    `min_matching_frames` (config `phash_reuse_min_frames`) of the burst's frames each
    matching within `max_distance` (config `phash_hamming_max`), not any single frame.
    See phash_index.py's `is_burst_reused` docstring and PROJECT_SPEC.md §14 for why
    this replaced a single-frame-match rule.
    """
    try:
        distance = max_distance if max_distance is not None else settings.binding.phash_hamming_max
        min_frames = (
            min_matching_frames
            if min_matching_frames is not None
            else settings.binding.phash_reuse_min_frames
        )
        reused = phash_index.is_burst_reused(bundle.frames, distance, min_frames)
        passed = not reused
    except Exception:
        passed = False
    return CheckResult("REUSE", passed, "REUSE_OK" if passed else "BIND_EVIDENCE_REUSE")


def verify_binding(
    *,
    bundle: EvidenceBundle,
    nonce_store: NonceStore,
    keystore: KeyStoreLike,
    server_signer: Signer,
    server_pk: bytes,
    now_ns: int | None = None,
) -> BindingVerificationResult:
    """Run all six checks (B1..B6) against `bundle` and return every outcome — not just
    the first failure. Convenience orchestrator; Module E's pipeline may instead call
    the individual `check_b*` functions at different stages.
    """
    now_ns = now_ns if now_ns is not None else time.time_ns()
    challenge = bundle.challenge_echo

    checks = (
        check_b1_challenge_signature(challenge, server_signer, server_pk),
        check_b2_expiry(challenge, now_ns),
        check_b3_nonce_freshness(challenge.nonce, nonce_store),
        check_b4_counter(bundle.device_id, bundle.counter, keystore),
        check_b5_capture_binding(bundle),
        check_b6_challenge_correlation(bundle),
    )
    return BindingVerificationResult(checks=checks)
