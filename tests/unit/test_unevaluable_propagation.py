"""The third outcome must survive the whole way to a decision (§5.3, §5.5, §14 2026-09-04).

An unevaluable binding check is neither a pass nor an attack. It is easy to implement the
distinction in `verify.py` and then lose it one layer up, where a `False` flag reads as
"failed" and a genuine user is filed as an attacker — which also corrupts §8.1's
per-attack detection rates and the 6-class confusion matrix, since those are computed from
exactly these outcomes.

These tests pin the contract at each hand-off: verify -> fusion -> decision.
"""

from __future__ import annotations

import pytest

from pqbio.detect.fusion import FusionInput, fuse_cascade, fuse_rule
from pqbio.server.decision import binding_outcome

ALL_PASS = (True, True, True, True, True, True)
B6_FAILED = (True, True, True, True, True, False)


def _input(**overrides: object) -> FusionInput:
    base = {
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


class TestFusionRoutesUnevaluable:
    @pytest.mark.parametrize("fuse", [fuse_rule, fuse_cascade], ids=["rule", "cascade"])
    def test_unevaluable_b6_yields_challenge_not_reject(self, fuse) -> None:  # type: ignore[no-untyped-def]
        """The core requirement. B6 reads False (the flags vector is fail-closed and
        cannot express three states), but `binding_unevaluable` says why, and neither
        strategy may turn that into a REJECT."""
        x = _input(binding_flags=B6_FAILED, binding_unevaluable=("B6",))
        result = fuse(x)
        assert result.decision == "CHALLENGE"

    @pytest.mark.parametrize("fuse", [fuse_rule, fuse_cascade], ids=["rule", "cascade"])
    def test_unevaluable_b6_is_never_accepted(self, fuse) -> None:  # type: ignore[no-untyped-def]
        """The other half: it must not silently pass either. Evidence nobody could read
        is not evidence of innocence."""
        x = _input(binding_flags=B6_FAILED, binding_unevaluable=("B6",))
        assert fuse(x).decision != "ACCEPT"

    @pytest.mark.parametrize("fuse", [fuse_rule, fuse_cascade], ids=["rule", "cascade"])
    def test_a_genuinely_failed_b6_still_rejects(self, fuse) -> None:  # type: ignore[no-untyped-def]
        """The gate must not become a way to soften every binding failure: with nothing
        marked unevaluable, a failed B6 is still an attack."""
        x = _input(binding_flags=B6_FAILED, binding_unevaluable=())
        assert fuse(x).decision == "REJECT"

    @pytest.mark.parametrize("fuse", [fuse_rule, fuse_cascade], ids=["rule", "cascade"])
    def test_a_detected_injection_still_rejects_despite_an_unevaluable_b6(
        self, fuse
    ) -> None:  # type: ignore[no-untyped-def]
        """The regression that a security test caught: a statically-injected stream has a
        flat illumination trace, so B6 goes unevaluable at exactly the moment the
        injection detector fires. Evidence that was read must win."""
        x = _input(injection_score=0.95, binding_flags=B6_FAILED, binding_unevaluable=("B6",))
        assert fuse(x).decision == "REJECT"

    @pytest.mark.parametrize("fuse", [fuse_rule, fuse_cascade], ids=["rule", "cascade"])
    def test_quality_failure_still_rejects_despite_an_unevaluable_b6(
        self, fuse
    ) -> None:  # type: ignore[no-untyped-def]
        x = _input(quality_passed=False, binding_flags=B6_FAILED, binding_unevaluable=("B6",))
        assert fuse(x).decision == "REJECT"

    @pytest.mark.parametrize("fuse", [fuse_rule, fuse_cascade], ids=["rule", "cascade"])
    def test_other_binding_failures_still_reject_alongside_an_unevaluable_b6(
        self, fuse
    ) -> None:  # type: ignore[no-untyped-def]
        """An unevaluable B6 must not mask a real B3 nonce replay sitting next to it."""
        flags = (True, True, False, True, True, False)
        x = _input(binding_flags=flags, binding_unevaluable=("B6",))
        assert fuse(x).decision == "REJECT"

    def test_unevaluable_is_reported_as_a_missing_signal(self) -> None:
        """Same contract as the missing detector scores: recorded, never defaulted."""
        x = _input(binding_flags=B6_FAILED, binding_unevaluable=("B6",))
        assert "binding_B6" in x.missing_signals
        assert x.has_unevaluable_binding is True

    def test_reasons_distinguish_unevaluable_from_failed(self) -> None:
        x = _input(binding_flags=B6_FAILED, binding_unevaluable=("B6",))
        joined = " ".join(fuse_rule(x).reasons)
        assert "could not be evaluated" in joined
        assert "B6 failed" not in joined

    def test_cascade_features_do_not_encode_unevaluable_as_failed(self) -> None:
        """0.0 is the trained model's signal for *failed*. A check nobody could read must
        not be handed to it wearing that value."""
        from pqbio.detect.fusion import _cascade_features

        unevaluable = _cascade_features(
            _input(binding_flags=B6_FAILED, binding_unevaluable=("B6",))
        )
        failed = _cascade_features(_input(binding_flags=B6_FAILED, binding_unevaluable=()))
        assert unevaluable != failed
        assert unevaluable[-1] == 1.0
        assert failed[-1] == 0.0


class TestDecisionMapping:
    def test_unevaluable_forces_challenge_from_accept(self) -> None:
        """Accepting on evidence that was never read is the error this guards."""
        assert binding_outcome("ACCEPT", ["B6"]) == "CHALLENGE"

    def test_unevaluable_does_not_override_an_evidence_driven_reject(self) -> None:
        """A REJECT reaching here was driven by evidence that WAS read.

        Fusion already routes the unevaluable-only case to CHALLENGE, so anything still
        saying REJECT was indicted by something else. Overriding it would let an attacker
        launder a detected injection into a retry by making B6 unevaluable -- a
        statically-injected stream has a flat illumination trace too. Found by
        tests/security/test_server_adversary_classes.py::test_a6_injection_tier1_...
        """
        assert binding_outcome("REJECT", ["B6"]) == "REJECT"

    def test_nothing_unevaluable_passes_the_decision_through(self) -> None:
        for outcome in ("ACCEPT", "REJECT", "CHALLENGE"):
            assert binding_outcome(outcome, []) == outcome  # type: ignore[arg-type]


class TestVerifyResultCarriesTheThirdState:
    def test_tristate_flags_use_none_for_unevaluable(self) -> None:
        """`None` matches fusion's missing-signal convention: never benign, never an
        attack, never silently defaulted."""
        from pqbio.binding.verify import CheckResult

        checks = tuple(CheckResult(f"B{i}", True, f"B{i}_OK") for i in range(1, 6)) + (
            CheckResult("B6", False, "BIND_CHALLENGE_UNEVALUABLE", evaluable=False),
        )
        from pqbio.binding.verify import BindingVerificationResult

        result = BindingVerificationResult(checks=checks)  # type: ignore[arg-type]

        assert result.binding_flags == (True, True, True, True, True, False)
        assert result.binding_flags_tristate == (True, True, True, True, True, None)
        assert result.unevaluable_checks == ["B6"]
        assert result.any_unevaluable is True

    def test_a_normal_failure_is_not_marked_unevaluable(self) -> None:
        from pqbio.binding.verify import BindingVerificationResult, CheckResult

        checks = tuple(CheckResult(f"B{i}", True, f"B{i}_OK") for i in range(1, 6)) + (
            CheckResult("B6", False, "BIND_CHALLENGE_UNMET"),
        )
        result = BindingVerificationResult(checks=checks)  # type: ignore[arg-type]

        assert result.binding_flags_tristate[5] is False
        assert result.unevaluable_checks == []
        assert result.any_unevaluable is False
