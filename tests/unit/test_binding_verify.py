"""Positive and negative tests for binding checks B1-B6 and the reuse check
(§5.3 DoD item 1). Every negative test confirms all six flags are still present in
`binding_flags` — not just that the failing check fired — since Module D's fusion
layer needs the full feature vector even on an early failure.
"""

from __future__ import annotations

import time
from pathlib import Path
from uuid import uuid4

import cv2
import numpy as np
import pytest

from pqbio.binding.nonce import NonceStore, issue_challenge
from pqbio.binding.phash_index import PhashIndex
from pqbio.binding.verify import check_evidence_reuse, verify_binding
from pqbio.capture import CapturedFrame
from pqbio.capture.bundler import assemble_bundle, sign_bundle
from pqbio.capture.challenge import estimate_face_box, measure_chromaticity_trace
from pqbio.config import settings
from pqbio.pqc.keystore import KeyStore
from pqbio.pqc.sign import get_signer
from pqbio.schemas import FrameMeta, Txn


def _synthetic_frame(seed: int, size: int = 128) -> np.ndarray:
    rng = np.random.default_rng(seed)
    img = np.full((size, size, 3), 200, dtype=np.uint8)
    skin = (int(rng.integers(150, 220)),) * 3
    cv2.ellipse(img, (size // 2, size // 2), (size // 3, size // 2 - 10), 0, 0, 360, skin, -1)
    return img


class Harness:
    """Everything a valid verify_binding() call needs, built once per test and mutable
    per-field for the negative cases.
    """

    def __init__(self, tmp_path: Path) -> None:
        self.signer = get_signer("pq")
        self.server_pk, self.server_sk = self.signer.keygen()
        self.device_pk, self.device_sk = self.signer.keygen()

        self.nonce_store = NonceStore(tmp_path / "nonces.db")
        self.keystore = KeyStore()
        self.keystore.enroll(
            "device-1", sig_pk=self.device_pk, sig_mode="pq"
        )  # starts at counter=0

        self.now_ns = time.time_ns()
        self.txn = Txn(action="login", relying_party="bank.example")
        self.challenge = issue_challenge(
            session_id=uuid4(),
            txn=self.txn,
            signer=self.signer,
            server_sk=self.server_sk,
            nonce_store=self.nonce_store,
            now_ns=self.now_ns,
        )

    def build_bundle(self, *, counter: int = 1, n_frames: int = 12, satisfy_b6: bool = True):
        from pqbio.capture.challenge import derive_illumination_sequence

        expected = derive_illumination_sequence(
            self.challenge.nonce, settings.binding.illumination_steps
        )
        captured_frames = []
        images = []
        for i in range(n_frames):
            if satisfy_b6:
                from pqbio.capture.challenge import PALETTE_BGR

                step = min(i * len(expected) // n_frames, len(expected) - 1)
                img = np.full((64, 64, 3), PALETTE_BGR[expected[step]], dtype=np.uint8)
            else:
                img = _synthetic_frame(seed=i)
            images.append(img)
            captured_frames.append(
                CapturedFrame(
                    image=img,
                    meta=FrameMeta(
                        capture_ts_ns=self.now_ns + i,
                        exposure=0.01,
                        iso=100,
                        focal=4.2,
                        sequence_idx=i,
                    ),
                )
            )

        face_box = estimate_face_box(images[0])
        trace = measure_chromaticity_trace(images, face_box)

        from pqbio.schemas import ChallengeSignal, DeviceMeta

        bundle = assemble_bundle(
            session_id=self.challenge.session_id,
            device_id="device-1",
            counter=counter,
            challenge_echo=self.challenge,
            captured_frames=captured_frames,
            challenge_signal=ChallengeSignal(illumination_trace=trace),
            device_meta=DeviceMeta(
                os="test",
                camera_device_name="cam",
                camera_driver_id="0",
                resolution=(64, 64),
                codec="raw",
                app_version="0.1.0",
            ),
        )
        return sign_bundle(bundle, self.signer, self.device_sk)

    def verify(self, bundle, **overrides):
        kwargs = dict(
            bundle=bundle,
            nonce_store=self.nonce_store,
            keystore=self.keystore,
            server_signer=self.signer,
            server_pk=self.server_pk,
            now_ns=self.now_ns,
        )
        kwargs.update(overrides)
        return verify_binding(**kwargs)


def test_all_checks_pass_on_a_valid_bundle(tmp_path: Path) -> None:
    h = Harness(tmp_path)
    bundle = h.build_bundle()
    result = h.verify(bundle)

    assert result.passed is True
    assert result.binding_flags == (True, True, True, True, True, True)
    assert result.reason_codes == []


def test_b1_fails_on_forged_challenge_signature(tmp_path: Path) -> None:
    h = Harness(tmp_path)
    bundle = h.build_bundle()
    tampered_challenge = bundle.challenge_echo.model_copy(update={"server_sig": b"\x00" * 3309})
    tampered_bundle = bundle.model_copy(update={"challenge_echo": tampered_challenge})

    result = h.verify(tampered_bundle)
    assert result.binding_flags[0] is False  # B1
    assert "BIND_CHALLENGE_FORGED" in result.reason_codes
    assert len(result.binding_flags) == 6  # all six still present


def test_b2_fails_when_expired(tmp_path: Path) -> None:
    h = Harness(tmp_path)
    bundle = h.build_bundle()
    far_future = (
        h.now_ns
        + (settings.binding.challenge_ttl_s + settings.binding.clock_skew_s + 5) * 1_000_000_000
    )

    result = h.verify(bundle, now_ns=far_future)
    assert result.binding_flags[1] is False  # B2
    assert "BIND_EXPIRED" in result.reason_codes


def test_b2_passes_within_clock_skew_tolerance(tmp_path: Path) -> None:
    h = Harness(tmp_path)
    bundle = h.build_bundle()
    just_after_expiry = bundle.challenge_echo.expires_at + int(
        settings.binding.clock_skew_s * 0.5 * 1_000_000_000
    )

    result = h.verify(bundle, now_ns=just_after_expiry)
    assert result.binding_flags[1] is True  # B2 tolerated within skew


def test_b3_fails_on_nonce_replay(tmp_path: Path) -> None:
    h = Harness(tmp_path)
    bundle = h.build_bundle()

    first = h.verify(bundle)
    assert first.binding_flags[2] is True  # B3 consumed it

    second = h.verify(bundle)  # same nonce, replayed
    assert second.binding_flags[2] is False  # B3
    assert "BIND_NONCE_REPLAY" in second.reason_codes
    assert len(second.binding_flags) == 6


def test_b4_fails_on_counter_regression(tmp_path: Path) -> None:
    h = Harness(tmp_path)
    h.keystore.update_counter("device-1", 10)  # last seen counter is now 10
    bundle = h.build_bundle(counter=5)  # regression: 5 <= 10

    result = h.verify(bundle)
    assert result.binding_flags[3] is False  # B4
    assert "BIND_COUNTER_REGRESSION" in result.reason_codes


def test_b4_passes_on_strictly_increasing_counter(tmp_path: Path) -> None:
    h = Harness(tmp_path)
    h.keystore.update_counter("device-1", 10)
    bundle = h.build_bundle(counter=11)

    result = h.verify(bundle)
    assert result.binding_flags[3] is True  # B4


def test_b5_fails_on_digest_mismatch(tmp_path: Path) -> None:
    h = Harness(tmp_path)
    bundle = h.build_bundle()
    tampered = bundle.model_copy(update={"capture_binding": b"\x00" * 32})

    result = h.verify(tampered)
    assert result.binding_flags[4] is False  # B5
    assert "BIND_DIGEST_MISMATCH" in result.reason_codes


def test_b6_fails_on_unmet_challenge_correlation(tmp_path: Path) -> None:
    h = Harness(tmp_path)
    bundle = h.build_bundle(
        satisfy_b6=False
    )  # unrelated synthetic frames, not the challenge colours

    result = h.verify(bundle)
    assert result.binding_flags[5] is False  # B6
    assert "BIND_CHALLENGE_UNMET" in result.reason_codes


def test_b6_passes_when_trace_matches_expected_sequence(tmp_path: Path) -> None:
    h = Harness(tmp_path)
    bundle = h.build_bundle(satisfy_b6=True)

    result = h.verify(bundle)
    assert result.binding_flags[5] is True  # B6


def test_multiple_failures_all_reported_together(tmp_path: Path) -> None:
    """The point of the module: a structured result carrying every outcome, not just
    the first failure.
    """
    h = Harness(tmp_path)
    bundle = h.build_bundle(counter=0, satisfy_b6=False)  # B4 and B6 both fail
    tampered = bundle.model_copy(update={"capture_binding": b"\x00" * 32})  # B5 too

    result = h.verify(tampered)
    assert result.passed is False
    assert set(result.reason_codes) == {
        "BIND_COUNTER_REGRESSION",
        "BIND_DIGEST_MISMATCH",
        "BIND_CHALLENGE_UNMET",
    }
    assert len(result.binding_flags) == 6
    # B1, B2, B3 should still have passed
    assert result.binding_flags[0] is True
    assert result.binding_flags[1] is True
    assert result.binding_flags[2] is True


def test_binding_verification_result_rejects_wrong_check_order() -> None:
    from pqbio.binding.verify import BindingVerificationResult, CheckResult

    checks = (
        CheckResult("B2", True, "B2_OK"),
        CheckResult("B1", True, "B1_OK"),
        CheckResult("B3", True, "B3_OK"),
        CheckResult("B4", True, "B4_OK"),
        CheckResult("B5", True, "B5_OK"),
        CheckResult("B6", True, "B6_OK"),
    )
    with pytest.raises(ValueError):
        BindingVerificationResult(checks=checks)  # type: ignore[arg-type]


# --------------------------------------------------------------------------------------
# Reuse check (separate from B1-B6, but part of the same DoD requirement)
# --------------------------------------------------------------------------------------


def test_evidence_reuse_check_passes_on_first_submission(tmp_path: Path) -> None:
    h = Harness(tmp_path)
    bundle = h.build_bundle()
    index = PhashIndex(tmp_path / "phash.db")

    result = check_evidence_reuse(bundle, index)
    assert result.passed is True
    assert result.reason_code == "REUSE_OK"


def test_evidence_reuse_check_fails_on_previously_accepted_media(tmp_path: Path) -> None:
    """This is the check that stops resubmission of the same *media* under a fresh,
    correctly-signed session — B1-B5 alone would let this through.
    """
    h = Harness(tmp_path)
    bundle = h.build_bundle()
    index = PhashIndex(tmp_path / "phash.db")
    index.record_accepted_bundle("earlier-session", bundle.frames)

    result = check_evidence_reuse(bundle, index)
    assert result.passed is False
    assert result.reason_code == "BIND_EVIDENCE_REUSE"


# --------------------------------------------------------------------------------------
# Fail-closed: a check that cannot be evaluated is a failure, never a skip (§11).
# These deliberately break each check's internals (not just its verdict) to prove the
# except-and-fail-closed path actually returns a failing CheckResult instead of
# propagating an exception.
# --------------------------------------------------------------------------------------


def test_b1_fails_closed_on_malformed_server_pk(tmp_path: Path) -> None:
    from pqbio.binding.verify import check_b1_challenge_signature

    h = Harness(tmp_path)
    bundle = h.build_bundle()
    result = check_b1_challenge_signature(bundle.challenge_echo, h.signer, b"too-short")
    assert result.passed is False
    assert result.reason_code == "BIND_CHALLENGE_FORGED"


def test_b3_fails_closed_when_nonce_store_unusable() -> None:
    from pqbio.binding.verify import check_b3_nonce_freshness

    class BrokenStore:
        def consume(self, nonce: bytes) -> bool:
            raise RuntimeError("simulated store failure")

    result = check_b3_nonce_freshness(b"n" * 32, BrokenStore())  # type: ignore[arg-type]
    assert result.passed is False
    assert result.reason_code == "BIND_NONCE_REPLAY"


def test_b4_fails_closed_for_unenrolled_device() -> None:
    from pqbio.binding.verify import check_b4_counter

    result = check_b4_counter("never-enrolled-device", 1, KeyStore())
    assert result.passed is False
    assert result.reason_code == "BIND_COUNTER_REGRESSION"


def test_b5_fails_closed_on_missing_frames(tmp_path: Path) -> None:
    from pqbio.binding.verify import check_b5_capture_binding

    h = Harness(tmp_path)
    bundle = h.build_bundle()
    broken = bundle.model_copy(update={"frames": None})  # violates the model's own type

    result = check_b5_capture_binding(broken)
    assert result.passed is False
    assert result.reason_code == "BIND_DIGEST_MISMATCH"


def test_b6_fails_closed_on_broken_challenge_signal(tmp_path: Path) -> None:
    from pqbio.binding.verify import check_b6_challenge_correlation

    h = Harness(tmp_path)
    bundle = h.build_bundle()
    broken = bundle.model_copy(update={"challenge_signal": None})

    result = check_b6_challenge_correlation(broken)
    assert result.passed is False
    assert result.reason_code == "BIND_CHALLENGE_UNMET"


def test_evidence_reuse_fails_closed_when_index_unusable(tmp_path: Path) -> None:
    h = Harness(tmp_path)
    bundle = h.build_bundle()

    class BrokenIndex:
        def check_reuse(self, frame_jpegs: list[bytes], max_distance: int) -> list:
            raise RuntimeError("simulated index failure")

    result = check_evidence_reuse(bundle, BrokenIndex())  # type: ignore[arg-type]
    assert result.passed is False
    assert result.reason_code == "BIND_EVIDENCE_REUSE"
