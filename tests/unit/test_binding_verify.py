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
from pqbio.binding.verify import (
    challenge_trace_spread,
    check_b6_challenge_correlation,
    check_evidence_reuse,
    compute_challenge_correlation,
    verify_binding,
)
from pqbio.capture import CapturedFrame
from pqbio.capture.bundler import assemble_bundle, sign_bundle
from pqbio.capture.challenge import (
    PALETTE_BGR,
    PALETTE_NAMES,
    derive_illumination_sequence,
    estimate_face_box,
    measure_chromaticity_trace,
)
from pqbio.config import settings
from pqbio.pqc.keystore import KeyStore
from pqbio.pqc.sign import get_signer
from pqbio.schemas import ChallengeSignal, FrameMeta, Txn


def _synthetic_frame(seed: int, size: int = 128) -> np.ndarray:
    rng = np.random.default_rng(seed)
    img = np.full((size, size, 3), 200, dtype=np.uint8)
    skin = (int(rng.integers(150, 220)),) * 3
    cv2.ellipse(img, (size // 2, size // 2), (size // 3, size // 2 - 10), 0, 0, 360, skin, -1)
    return img


def _structurally_varied_frame(seed: int, size: int = 128) -> np.ndarray:
    """Unlike `_synthetic_frame` (tone-only) or the illumination-challenge solid
    colour blocks `build_bundle` normally uses, this varies ellipse size/eye spacing
    per seed — needed for phash reuse tests, since phash is coarse/low-frequency and
    barely responds to tone-only or solid-colour variation (every solid-colour frame
    hashes close to every other, and every tone-only frame hashes close to every
    other, which makes both useless as a "genuinely different frame" phash fixture).
    """
    rng = np.random.default_rng(seed)
    img = np.full((size, size, 3), 200, dtype=np.uint8)
    skin = (int(rng.integers(150, 220)),) * 3
    face_w = int(rng.integers(size // 3 - 10, size // 3 + 10))
    face_h = int(rng.integers(size // 2 - 18, size // 2 - 2))
    cv2.ellipse(img, (size // 2, size // 2), (face_w, face_h), 0, 0, 360, skin, -1)
    eye_dx = int(rng.integers(14, 28))
    eye_y = size // 2 - int(rng.integers(6, 16))
    cv2.circle(img, (size // 2 - eye_dx, eye_y), 6, (30, 30, 30), -1)
    cv2.circle(img, (size // 2 + eye_dx, eye_y), 6, (30, 30, 30), -1)
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
        images = []
        for i in range(n_frames):
            step = min(i * len(expected) // n_frames, len(expected) - 1)
            if satisfy_b6:
                from pqbio.capture.challenge import PALETTE_BGR

                img = np.full((64, 64, 3), PALETTE_BGR[expected[step]], dtype=np.uint8)
            else:
                # A capture lit by a DIFFERENT nonce's sequence, not flat grey frames.
                # Flat frames have no chromaticity movement, so since 2026-09-04 they are
                # correctly UNEVALUABLE rather than UNMET -- which made this a fixture for
                # the wrong outcome. A wrong-sequence capture is measurable and genuinely
                # fails the challenge, which is what a B6 negative is supposed to be.
                from pqbio.capture.challenge import PALETTE_BGR

                wrong = [(idx + 1) % len(PALETTE_BGR) for idx in expected]
                img = np.full((64, 64, 3), PALETTE_BGR[wrong[step]], dtype=np.uint8)
            images.append(img)
        return self.build_bundle_from_images(images, counter=counter)

    def build_bundle_from_images(self, images: list, *, counter: int = 1):
        """Build a signed bundle from explicit frame images — used directly by tests
        that need control over frame *content* (e.g. phash reuse tests, where
        `build_bundle`'s solid-colour illumination frames or single-seed-varying
        frames are too structurally uniform to be a meaningful phash fixture).
        """
        captured_frames = [
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
            for i, img in enumerate(images)
        ]

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
                resolution=(images[0].shape[1], images[0].shape[0]),
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


def _lit_scene_frame(palette_idx: int, strength: float = 0.18, size: int = 64) -> np.ndarray:
    """A static scene under a weak coloured cast — what a sensor actually sees.

    `build_bundle`'s solid palette blocks are a degenerate positive: the frame *is* the
    challenge colour, so the measurement recovers it exactly and B6 scores 1.0. A real
    capture is a room with its own strong static colour, onto which the screen adds a
    small amount of light. That is the case the 2026-09-02 live check showed B6 failing
    on for reasons a solid-colour test can never surface, so it is tested here directly.
    """
    base = np.array((70, 95, 140), dtype=np.float32)  # BGR: a warm, red-dominant scene
    cast = np.array(PALETTE_BGR[palette_idx], dtype=np.float32)
    lit = base * (1.0 - strength) + cast * strength
    return np.full((size, size, 3), np.clip(lit, 0, 255).astype(np.uint8))


class TestB6Semantics:
    """B6 under the 2026-09-02 formulation (normalised chromaticity, channel-centred
    correlation). Green runs alone would not tell us much here: the measurement's
    semantics changed, so each of these asserts a specific property of the new
    definition rather than re-checking that the old assertions still hold.
    """

    def test_passes_on_a_realistically_lit_scene_not_just_solid_colour(
        self, tmp_path: Path
    ) -> None:
        """A static scene with only an 18% cast must still clear the threshold."""
        h = Harness(tmp_path)
        expected = derive_illumination_sequence(
            h.challenge.nonce, settings.binding.illumination_steps
        )
        n_frames = 12
        images = [
            _lit_scene_frame(expected[min(i * len(expected) // n_frames, len(expected) - 1)])
            for i in range(n_frames)
        ]
        bundle = h.build_bundle_from_images(images)

        r = compute_challenge_correlation(bundle)
        assert r >= settings.binding.illumination_corr_min, (
            f"a genuinely lit scene scored {r:.3f}; if this drops below the threshold the "
            "measurement or the threshold has regressed, not the test fixture"
        )

    def test_static_scene_colour_does_not_drive_the_score(self, tmp_path: Path) -> None:
        """Two scenes with very different static colours, the same induced modulation,
        must score near-identically.

        This is the channel-centring property. Before it, the score was dominated by
        whatever colour the room happened to be: a red-walled room scored strongly
        negative against a sequence asking for blue, regardless of whether the challenge
        was satisfied.
        """
        h = Harness(tmp_path)
        expected = derive_illumination_sequence(
            h.challenge.nonce, settings.binding.illumination_steps
        )
        n_frames = 12

        def build(base_bgr: tuple[int, int, int]) -> float:
            images = []
            for i in range(n_frames):
                step = min(i * len(expected) // n_frames, len(expected) - 1)
                base = np.array(base_bgr, dtype=np.float32)
                cast = np.array(PALETTE_BGR[expected[step]], dtype=np.float32)
                lit = base * 0.82 + cast * 0.18
                images.append(np.full((64, 64, 3), np.clip(lit, 0, 255).astype(np.uint8)))
            return compute_challenge_correlation(h.build_bundle_from_images(images))

        red_room = build((40, 60, 160))
        blue_room = build((160, 60, 40))
        assert abs(red_room - blue_room) < 0.05
        assert red_room >= settings.binding.illumination_corr_min
        assert blue_room >= settings.binding.illumination_corr_min

    def test_static_scene_with_no_modulation_fails(self, tmp_path: Path) -> None:
        """A strongly coloured but completely unmodulated scene must not pass.

        The mirror of the test above: removing the static offset must not also remove
        B6's ability to reject. A constant trace has no variance, so `_pearson_r`
        returns 0.0 and the check fails closed.
        """
        h = Harness(tmp_path)
        images = [np.full((64, 64, 3), (160, 60, 40), dtype=np.uint8) for _ in range(12)]
        bundle = h.build_bundle_from_images(images)

        assert compute_challenge_correlation(bundle) < settings.binding.illumination_corr_min
        assert check_b6_challenge_correlation(bundle).passed is False

    def test_capture_made_under_a_different_nonce_is_rejected(self, tmp_path: Path) -> None:
        """The attack B6 exists to stop: a real, correctly-lit capture — just made under
        somebody else's challenge. It must fail against *this* nonce's sequence.
        """
        h = Harness(tmp_path)
        real_sequence = derive_illumination_sequence(
            h.challenge.nonce, settings.binding.illumination_steps
        )
        other_sequence = next(
            seq
            for seq in (
                derive_illumination_sequence(bytes([i]) * 32, settings.binding.illumination_steps)
                for i in range(1, 40)
            )
            if seq != real_sequence
        )

        n_frames = 12
        images = [
            _lit_scene_frame(
                other_sequence[min(i * len(other_sequence) // n_frames, len(other_sequence) - 1)]
            )
            for i in range(n_frames)
        ]
        bundle = h.build_bundle_from_images(images)

        result = check_b6_challenge_correlation(bundle)
        assert result.passed is False
        assert result.reason_code == "BIND_CHALLENGE_UNMET"

    def test_luminance_ramp_alone_does_not_pass(self, tmp_path: Path) -> None:
        """A capture whose brightness ramps but whose hue never changes must fail.

        This is exactly what the 2026-09-01 live sensor run produced, and exactly what
        the old formulation could not distinguish from a real challenge response: the
        per-step means rose monotonically while the channel ratios stayed fixed.
        """
        h = Harness(tmp_path)
        images = []
        for i in range(12):
            scale = 0.35 + 0.05 * i  # brightness climbs, hue is constant
            lit = np.array((70, 95, 140), dtype=np.float32) * scale
            images.append(np.full((64, 64, 3), np.clip(lit, 0, 255).astype(np.uint8)))
        bundle = h.build_bundle_from_images(images)

        assert compute_challenge_correlation(bundle) < settings.binding.illumination_corr_min

    def test_expected_trace_is_built_in_chromaticity_space(self) -> None:
        """Both sides of the correlation must live in the same space. White is the
        neutral point in chromaticity; under the old formulation it was (1, 1, 1),
        which is what made the two sides incomparable.
        """
        from pqbio.binding.verify import palette_chromaticity

        white_idx = PALETTE_NAMES.index("white")
        assert palette_chromaticity(white_idx) == pytest.approx((1 / 3, 1 / 3, 1 / 3))
        red_idx = PALETTE_NAMES.index("red")
        assert palette_chromaticity(red_idx) == pytest.approx((1.0, 0.0, 0.0))


class TestB6Evaluability:
    """B6's evaluability precondition (§5.3, §14 2026-09-04).

    "The challenge was not satisfied" and "the challenge could not be measured" are
    different answers. Before this gate existed, a capture the sensor could not measure
    came out as `BIND_CHALLENGE_UNMET` -- an attack code on a genuine user -- because the
    correlation was computed from noise and thresholded as though it meant something.
    """

    def _bundle_from_trace(self, h: Harness, trace: list[float], n_frames: int = 12):
        """A signed bundle carrying an arbitrary illumination trace.

        Built through the real assembly path so the bundle is genuinely well-formed;
        only the trace is substituted, because the trace is what the gate reads.
        """
        images = [_synthetic_frame(seed=i) for i in range(n_frames)]
        bundle = h.build_bundle_from_images(images)
        return bundle.model_copy(
            update={"challenge_signal": ChallengeSignal(illumination_trace=trace)}
        )

    def test_saturated_capture_is_unevaluable_not_unmet(self, tmp_path: Path) -> None:
        """The case this gate was built for.

        A real capture at ~190/255 in a brightly lit room measured a per-channel spread of
        0.00021 (PROJECT_SPEC.md §14, 2026-09-03): the trace did not move, so there was
        nothing to correlate. It must come back UNEVALUABLE, not UNMET.
        """
        h = Harness(tmp_path)
        # Reproduces the measured shape: a static scene chromaticity with sensor-noise
        # jitter far below the configured floor.
        rng = np.random.default_rng(7)
        base = np.array([0.366, 0.332, 0.302])
        frames = base[None, :] + rng.normal(0.0, 0.0002, size=(12, 3))
        frames = frames / frames.sum(axis=1, keepdims=True)
        bundle = self._bundle_from_trace(h, [float(v) for v in frames.ravel()])

        spread = challenge_trace_spread(bundle)
        assert spread < settings.binding.illumination_min_trace_spread

        result = check_b6_challenge_correlation(bundle)
        assert result.passed is False
        assert result.evaluable is False
        assert result.reason_code == "BIND_CHALLENGE_UNEVALUABLE"
        assert result.reason_code != "BIND_CHALLENGE_UNMET"

    def test_a_measurable_capture_that_fails_is_still_unmet(self, tmp_path: Path) -> None:
        """The gate must not swallow real failures.

        A trace that moves plenty but moves the wrong way is a capture the system CAN
        measure and which did not satisfy the challenge -- that is an attack signal and
        must keep its attack code.
        """
        h = Harness(tmp_path)
        rng = np.random.default_rng(11)
        # Large, structured excursions: unambiguously above the evaluability floor.
        frames = np.array([0.33, 0.33, 0.34]) + rng.normal(0.0, 0.05, size=(12, 3))
        frames = np.clip(frames, 1e-6, None)
        frames = frames / frames.sum(axis=1, keepdims=True)
        bundle = self._bundle_from_trace(h, [float(v) for v in frames.ravel()])

        assert challenge_trace_spread(bundle) >= settings.binding.illumination_min_trace_spread
        result = check_b6_challenge_correlation(bundle)
        assert result.evaluable is True
        assert result.passed is False
        assert result.reason_code == "BIND_CHALLENGE_UNMET"

    def test_a_genuine_passing_capture_is_not_gated(self, tmp_path: Path) -> None:
        """The number that must stay zero: the gate never fires on a capture B6 can read.

        On the 97 held captures that passed the correlation, the lowest spread was 0.00226
        against a floor of 0.0015 (`results/b6_evaluability.json`). A regression that
        raised the floor past that would start rejecting genuine users, so a passing
        fixture is asserted to be evaluable here rather than only asserted to pass.
        """
        h = Harness(tmp_path)
        expected = derive_illumination_sequence(
            h.challenge.nonce, settings.binding.illumination_steps
        )
        n_frames = 12
        images = [
            _lit_scene_frame(expected[min(i * len(expected) // n_frames, len(expected) - 1)])
            for i in range(n_frames)
        ]
        bundle = h.build_bundle_from_images(images)

        result = check_b6_challenge_correlation(bundle)
        assert result.evaluable is True
        assert result.passed is True

    def test_the_gate_runs_before_the_correlation(self, tmp_path: Path) -> None:
        """A capture failing the gate must never reach `compute_challenge_correlation`.

        Ordering is the point, not an optimisation: the correlation on an unevaluable
        trace is a ratio of noise to noise, and computing it invites someone to log or
        threshold it later.
        """
        h = Harness(tmp_path)
        flat = [1 / 3, 1 / 3, 1 / 3] * 12  # perfectly static: spread exactly 0
        bundle = self._bundle_from_trace(h, flat)

        called = False

        def _boom(_bundle):  # pragma: no cover - must not run
            nonlocal called
            called = True
            return 1.0

        import pqbio.binding.verify as verify_mod

        original = verify_mod.compute_challenge_correlation
        verify_mod.compute_challenge_correlation = _boom  # type: ignore[assignment]
        try:
            result = verify_mod.check_b6_challenge_correlation(bundle)
        finally:
            verify_mod.compute_challenge_correlation = original  # type: ignore[assignment]

        assert called is False
        assert result.reason_code == "BIND_CHALLENGE_UNEVALUABLE"

    def test_missing_or_malformed_trace_stays_an_attack_code(self, tmp_path: Path) -> None:
        """A bundle with no usable trace is a protocol violation, not a bad room.

        The distinction is a security one and it points the opposite way to intuition: if
        an absent trace routed to UNEVALUABLE, an attacker could omit the field and get an
        endless CHALLENGE retry loop instead of a REJECT. Only a *present but static*
        trace -- a real sensor that genuinely could not see the cast -- is unevaluable.
        """
        h = Harness(tmp_path)
        bundle = h.build_bundle()

        for broken in (
            bundle.model_copy(update={"challenge_signal": None}),
            self._bundle_from_trace(h, []),
            self._bundle_from_trace(h, [0.5, 0.5]),  # not a multiple of 3
        ):
            assert challenge_trace_spread(broken) is None
            result = check_b6_challenge_correlation(broken)
            assert result.passed is False
            assert result.evaluable is True
            assert result.reason_code == "BIND_CHALLENGE_UNMET"

    def test_result_exposes_the_third_state_distinctly(self, tmp_path: Path) -> None:
        """`binding_flags` stays fail-closed; `binding_flags_tristate` carries the truth."""
        h = Harness(tmp_path)
        flat = [1 / 3, 1 / 3, 1 / 3] * 12
        bundle = self._bundle_from_trace(h, flat)
        result = h.verify(bundle)

        assert result.binding_flags[5] is False  # lossy view: reads as a failure
        assert result.binding_flags_tristate[5] is None  # truthful view
        assert result.unevaluable_checks == ["B6"]
        assert result.any_unevaluable is True
        assert "BIND_CHALLENGE_UNEVALUABLE" in result.reason_codes


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
    correctly-signed session — B1-B5 alone would let this through. Uses a full
    30-frame burst (config's capture.n_frames) since exact resubmission means every
    frame matches, comfortably clearing the default `phash_reuse_min_frames` (30).
    """
    h = Harness(tmp_path)
    bundle = h.build_bundle(n_frames=30)
    index = PhashIndex(tmp_path / "phash.db")
    index.record_accepted_bundle("earlier-session", bundle.frames)

    result = check_evidence_reuse(bundle, index)
    assert result.passed is False


def test_evidence_reuse_check_ignores_a_handful_of_frame_matches(tmp_path: Path) -> None:
    """§14's N-of-burst rule: a few frames matching by chance must not trip
    BIND_EVIDENCE_REUSE — only when at least `min_matching_frames` do. Uses
    structurally-varied frames (not the solid-colour illumination blocks
    `build_bundle` defaults to): those are near-flat images that all hash close to
    each other under phash regardless of exact colour, which would make "only 5 of
    30 frames match" untestable — every frame would match every other.
    """
    h = Harness(tmp_path)
    images = [_structurally_varied_frame(seed=i) for i in range(30)]
    bundle = h.build_bundle_from_images(images)
    index = PhashIndex(tmp_path / "phash.db")
    # accept only the first 5 of this bundle's frames under a different session, so at
    # most 5 of the new submission's 30 frames can ever match — short of the default N.
    index.record_accepted_bundle("earlier-session", bundle.frames[:5])

    result = check_evidence_reuse(bundle, index)
    assert result.passed is True
    assert result.reason_code == "REUSE_OK"


def test_evidence_reuse_check_respects_min_matching_frames_override(tmp_path: Path) -> None:
    h = Harness(tmp_path)
    images = [_structurally_varied_frame(seed=i) for i in range(30)]
    bundle = h.build_bundle_from_images(images)
    index = PhashIndex(tmp_path / "phash.db")
    index.record_accepted_bundle("earlier-session", bundle.frames[:5])

    # with a lowered N, those same 5 matching frames are now enough to flag reuse.
    result = check_evidence_reuse(bundle, index, min_matching_frames=5)
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
        def is_burst_reused(
            self, frame_jpegs: list[bytes], max_distance: int, min_matching_frames: int
        ) -> bool:
            raise RuntimeError("simulated index failure")

    result = check_evidence_reuse(bundle, BrokenIndex())  # type: ignore[arg-type]
    assert result.passed is False
    assert result.reason_code == "BIND_EVIDENCE_REUSE"
