"""Tests for pqbio.detect.fusion (§5.4 D6)."""

from __future__ import annotations

from pathlib import Path

import pytest

from pqbio.detect.fusion import (
    CascadeModel,
    FusionInput,
    decide_policy,
    fuse_cascade,
    fuse_rule,
)

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
MANIFEST = REPO_ROOT / "data" / "manifests" / "injection_corpus_manifest.json"
CASCADE_MODEL_PATH = REPO_ROOT / "models" / "fusion_cascade_lr.json"

ALL_PASS_FLAGS = (True, True, True, True, True, True)


def _clean_input(**overrides: object) -> FusionInput:
    base = dict(
        match_score=None,
        pad_score=None,
        morph_score=None,
        deepfake_score=None,
        replay_score=None,
        injection_score=0.1,
        quality_passed=True,
        binding_flags=ALL_PASS_FLAGS,
        n_frames=30,
    )
    base.update(overrides)
    return FusionInput(**base)  # type: ignore[arg-type]


# --------------------------------------------------------------------------------------
# FusionInput.missing_signals
# --------------------------------------------------------------------------------------


def test_missing_signals_lists_none_scores() -> None:
    x = _clean_input()
    assert x.missing_signals == ["match", "pad", "morph", "deepfake", "replay"]


def test_missing_signals_empty_when_all_present() -> None:
    x = _clean_input(
        match_score=0.1, pad_score=0.1, morph_score=0.1, deepfake_score=0.1, replay_score=0.1
    )
    assert x.missing_signals == []


# --------------------------------------------------------------------------------------
# decide_policy
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "score,expected",
    [
        (0.0, "ACCEPT"),
        (0.29, "ACCEPT"),
        (0.3, "CHALLENGE"),
        (0.69, "CHALLENGE"),
        (0.7, "REJECT"),
        (1.0, "REJECT"),
    ],
)
def test_decide_policy_thresholds(score: float, expected: str) -> None:
    assert decide_policy(score).decision == expected


# --------------------------------------------------------------------------------------
# Rule strategy
# --------------------------------------------------------------------------------------


def test_rule_accepts_clean_input() -> None:
    result = fuse_rule(_clean_input(injection_score=0.1))
    assert result.decision == "ACCEPT"
    assert result.fused_score == 0.0


def test_rule_rejects_on_injection_score_above_threshold() -> None:
    from pqbio.config import settings

    above = settings.detect.thresholds.injection + 0.1
    result = fuse_rule(_clean_input(injection_score=above))
    assert result.decision == "REJECT"
    assert result.fused_score == 1.0
    assert any("injection_score" in r for r in result.reasons)


def test_rule_rejects_on_quality_failure() -> None:
    result = fuse_rule(_clean_input(quality_passed=False))
    assert result.decision == "REJECT"
    assert "QUALITY_INSUFFICIENT" in result.reasons


def test_rule_rejects_on_any_failed_binding_check() -> None:
    flags = (True, True, False, True, True, True)  # B3 failed
    result = fuse_rule(_clean_input(binding_flags=flags))
    assert result.decision == "REJECT"
    assert any("B3" in r for r in result.reasons)


def test_rule_reports_missing_signals() -> None:
    result = fuse_rule(_clean_input())
    assert result.missing_signals == ["match", "pad", "morph", "deepfake", "replay"]


def test_rule_ignores_missing_signals_scores() -> None:
    """A None score must never trigger the rule — only available scores count."""
    result = fuse_rule(_clean_input(injection_score=0.0))
    assert result.decision == "ACCEPT"


# --------------------------------------------------------------------------------------
# Cascade strategy
# --------------------------------------------------------------------------------------


def test_cascade_short_circuits_on_quality_failure_without_model() -> None:
    result = fuse_cascade(_clean_input(quality_passed=False))
    assert result.decision == "REJECT"
    assert result.fused_score == 1.0
    assert "short-circuit" in result.reasons[0]


def test_cascade_short_circuits_on_binding_failure() -> None:
    flags = (True, False, True, True, True, True)  # B2 failed
    result = fuse_cascade(_clean_input(binding_flags=flags))
    assert result.decision == "REJECT"
    assert "B2" in result.reasons[0]


def test_cascade_short_circuits_on_confident_injection_score() -> None:
    from pqbio.config import settings

    above = settings.detect.thresholds.injection + 0.1
    result = fuse_cascade(_clean_input(injection_score=above))
    assert result.decision == "REJECT"
    assert "injection_score" in result.reasons[0]


def test_cascade_falls_back_to_injection_score_alone_without_model() -> None:
    result = fuse_cascade(_clean_input(injection_score=0.1), model=None)
    assert result.fused_score == 0.1
    assert "no trained cascade model" in result.reasons[-1]


def test_cascade_uses_trained_model_when_provided() -> None:
    model = CascadeModel(coefficients=[5.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0], intercept=-2.0)
    low = fuse_cascade(_clean_input(injection_score=0.0), model=model)
    high = fuse_cascade(_clean_input(injection_score=1.0), model=model)
    assert low.fused_score < high.fused_score
    assert "trained cascade" in low.reasons[-1]


def test_cascade_model_json_round_trip() -> None:
    model = CascadeModel(coefficients=[0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8], intercept=-1.5)
    restored = CascadeModel.from_json(model.to_json())
    assert restored.coefficients == model.coefficients
    assert restored.intercept == model.intercept


# --------------------------------------------------------------------------------------
# Real trained model + corpus comparison (if available)
# --------------------------------------------------------------------------------------


@pytest.mark.skipif(not CASCADE_MODEL_PATH.is_file(), reason="cascade model not trained yet")
def test_real_trained_cascade_model_loads_and_scores() -> None:
    import json

    model = CascadeModel.from_json(json.loads(CASCADE_MODEL_PATH.read_text(encoding="utf-8")))
    result = fuse_cascade(_clean_input(injection_score=0.9), model=model)
    assert 0.0 <= result.fused_score <= 1.0


@pytest.mark.skipif(not MANIFEST.is_file(), reason="injection corpus not generated")
def test_compare_strategies_on_corpus_writes_results(tmp_path: Path) -> None:
    from pqbio.detect.fusion import compare_strategies_on_corpus, train_cascade_model

    injection_model = REPO_ROOT / "models" / "injection_gbm.txt"
    cascade_model = None
    if injection_model.is_file():
        cascade_model = train_cascade_model(MANIFEST, injection_model_path=injection_model)
    results_out = tmp_path / "fusion_results.json"
    result = compare_strategies_on_corpus(
        MANIFEST,
        injection_model_path=injection_model if injection_model.is_file() else None,
        cascade_model=cascade_model,
        results_out=results_out,
    )
    assert results_out.is_file()
    assert "rule_accuracy" in result
    assert "cascade_accuracy" in result
    assert result["n_samples"] > 0
    assert "scope_note" in result
