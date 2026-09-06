"""No gate may skip a detector that would have fired (§14, 2026-09-05).

The masking rule: an outcome meaning **"cannot evaluate"** may outrank an **absence** of
detection, but never a **positive** detection. Any gate returning early must not skip a
detector that would have fired.

This was found once in B6 (routing UNEVALUABLE to CHALLENGE let a detected tier-1
injection become a polite retry) and the same error was then found in two more places by
audit. Each test here is in the shape of the one that caught the original: **a capture
that trips the gate AND would trip a detector, asserting the detection survives.**
"""

from __future__ import annotations

import pytest

from pqbio.detect.fusion import FusionInput, fuse_cascade, fuse_rule

ALL_PASS = (True, True, True, True, True, True)
B6_DOWN = (True, True, True, True, True, False)


def _input(**overrides: object) -> FusionInput:
    base: dict[str, object] = {
        "match_score": None,
        "pad_score": None,
        "morph_score": None,
        "deepfake_score": None,
        "replay_score": None,
        "injection_score": 0.05,
        "quality_passed": True,
        "binding_flags": ALL_PASS,
        "n_frames": 30,
    }
    base.update(overrides)
    return FusionInput(**base)  # type: ignore[arg-type]


class TestQualityGateDoesNotMaskDetections:
    """`QUALITY_INSUFFICIENT` is a "cannot evaluate" outcome by face.py's own definition
    ("a bad genuine capture must never read as an attack"). It used to short-circuit
    `fuse_cascade` before the binding and injection checks, so a deliberately degraded
    capture that was *also* an injection reported only the quality failure.

    That mattered even though both paths end in REJECT: §8.1's per-attack detection rates
    and the 6-class confusion matrix are computed from these reason codes, so a masked
    attribution silently understates the injection detector.
    """

    def test_injection_attribution_survives_a_quality_failure(self) -> None:
        x = _input(quality_passed=False, injection_score=0.95)
        result = fuse_cascade(x)

        assert result.decision == "REJECT"
        joined = " ".join(result.reasons)
        assert "injection_score" in joined, (
            "a degraded capture that is also an injection must still be attributed to the "
            "injection detector, not filed as a quality failure"
        )

    def test_binding_failure_attribution_survives_a_quality_failure(self) -> None:
        """Same shape for a real binding failure sitting behind a quality failure."""
        x = _input(quality_passed=False, binding_flags=(True, True, False, True, True, True))
        result = fuse_cascade(x)

        assert result.decision == "REJECT"
        assert any("B3" in r for r in result.reasons)

    def test_a_quality_failure_alone_still_rejects(self) -> None:
        """The gate must still do its job when nothing else fires -- the fix is about
        ordering, not about weakening the gate."""
        result = fuse_cascade(_input(quality_passed=False))

        assert result.decision == "REJECT"
        assert any("QUALITY_INSUFFICIENT" in r for r in result.reasons)

    @pytest.mark.parametrize("fuse", [fuse_rule, fuse_cascade], ids=["rule", "cascade"])
    def test_quality_failure_never_becomes_an_accept(self, fuse) -> None:  # type: ignore[no-untyped-def]
        assert fuse(_input(quality_passed=False)).decision != "ACCEPT"


class TestUnevaluableB6DoesNotSkipHeavyModels:
    """Stage 4's `confident_reject` skips stage 6 (the heavy models, `match` this
    session). It was computed as `not b6.passed`, and an unevaluable B6 reports
    `passed=False` -- so a capture whose illumination trace happened to be unmeasurable
    skipped the identity match entirely and came out CHALLENGE with
    `MISSING_SIGNAL_MATCH`.

    An impostor is a positive detection. A "cannot measure" verdict on a *different*
    check must not prevent it being made.
    """

    def test_confident_reject_ignores_an_unevaluable_b6(self) -> None:
        """The predicate itself, at the level the pipeline computes it."""
        from pqbio.binding.verify import CheckResult

        unevaluable = CheckResult("B6", False, "BIND_CHALLENGE_UNEVALUABLE", evaluable=False)
        failed = CheckResult("B6", False, "BIND_CHALLENGE_UNMET")
        passed = CheckResult("B6", True, "B6_OK")

        def confident(b6: CheckResult, injection_fired: bool) -> bool:
            return (b6.evaluable and not b6.passed) or injection_fired

        assert confident(unevaluable, False) is False, (
            "an unevaluable B6 must not short-circuit the heavy models: that outcome "
            "leads to CHALLENGE, so the match score is still load-bearing"
        )
        assert confident(failed, False) is True  # a real B6 failure still short-circuits
        assert confident(passed, False) is False
        assert confident(unevaluable, True) is True  # injection still short-circuits

    def test_pipeline_runs_match_when_b6_is_unevaluable(self) -> None:
        """End-to-end through the real server: the detector actually executes.

        A predicate test can pass while the wiring is wrong, and the original B6 bug was
        exactly a wiring bug, so this asserts on observed execution rather than on the
        expression.
        """
        import tempfile
        from pathlib import Path
        from uuid import uuid4

        from _server_fixtures import ServerTestClient
        from fastapi.testclient import TestClient

        import pqbio.detect.match as match_mod
        from pqbio.capture.bundler import sign_bundle
        from pqbio.schemas import ChallengeSignal
        from pqbio.server.app import create_app

        ran: list[str] = []
        original = match_mod.MatchDetector.score

        def _record(self, evidence):  # type: ignore[no-untyped-def]
            ran.append("match")
            return original(self, evidence)

        match_mod.MatchDetector.score = _record  # type: ignore[assignment]
        try:
            # A fresh data dir: the pHash reuse index persists between tests and the
            # fixtures build byte-identical frames, so on a shared dir stage 5 rejects
            # this bundle as reused and stage 6 never runs -- the test would fail for a
            # reason unrelated to what it asserts.
            with (
                tempfile.TemporaryDirectory() as tmp,
                TestClient(create_app(data_dir=Path(tmp) / "data")) as client,
            ):
                stc = ServerTestClient(client, device_id=f"dev-{uuid4().hex[:8]}")
                stc.enroll()
                session_id, challenge_obj = stc.challenge()
                keys = stc.handshake(session_id)
                bundle = stc.build_live_genuine_bundle(session_id, challenge_obj, n_frames=30)
                # A flat trace: a real sensor that could not see the cast at all.
                flat = [1 / 3, 1 / 3, 1 / 3] * len(bundle.frame_meta)
                tampered = bundle.model_copy(
                    update={
                        "challenge_signal": ChallengeSignal(illumination_trace=flat),
                        "signature": b"",
                        "bundle_digest": b"",
                    }
                )
                resigned = sign_bundle(tampered, stc.device_signer, stc.device_sk)
                decision = stc.verify(session_id, resigned, keys)
        finally:
            match_mod.MatchDetector.score = original  # type: ignore[assignment]

        assert "BIND_CHALLENGE_UNEVALUABLE" in decision.reason_codes
        assert ran == ["match"], "match must run when B6 is merely unevaluable"
        assert "MISSING_SIGNAL_MATCH" not in decision.reason_codes
