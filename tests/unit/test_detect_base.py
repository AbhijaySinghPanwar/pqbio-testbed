"""Tests for the Detector ABC / DetectorResult contract (§5.4)."""

from __future__ import annotations

import time

from pqbio.detect.base import Detector, DetectorResult


class _FixedDetector(Detector):
    name = "fixed"

    def __init__(self, score: float, threshold: float, sleep_s: float = 0.0) -> None:
        self._score = score
        self._threshold = threshold
        self._sleep_s = sleep_s

    @property
    def threshold(self) -> float:
        return self._threshold

    def _evaluate(self, evidence: object) -> tuple[float, list[str], dict]:  # type: ignore[type-arg]
        if self._sleep_s:
            time.sleep(self._sleep_s)
        return self._score, ["fixed reason"], {"raw": self._score}


def test_score_assembles_full_detector_result() -> None:
    detector = _FixedDetector(score=0.7, threshold=0.5)
    result = detector.score(evidence=object())  # type: ignore[arg-type]

    assert isinstance(result, DetectorResult)
    assert result.name == "fixed"
    assert result.score == 0.7
    assert result.threshold == 0.5
    assert result.decision is True  # 0.7 >= 0.5
    assert result.reasons == ["fixed reason"]
    assert result.features == {"raw": 0.7}
    assert result.latency_ms >= 0.0


def test_decision_false_below_threshold() -> None:
    detector = _FixedDetector(score=0.2, threshold=0.5)
    result = detector.score(evidence=object())  # type: ignore[arg-type]
    assert result.decision is False


def test_decision_true_at_exact_threshold() -> None:
    detector = _FixedDetector(score=0.5, threshold=0.5)
    result = detector.score(evidence=object())  # type: ignore[arg-type]
    assert result.decision is True


def test_latency_measured_by_base_class_not_subclass() -> None:
    """§5.4: "Latency is measured by the base class, not by each detector." A subclass
    that does nothing to measure its own timing still gets an accurate latency_ms.
    """
    slow = _FixedDetector(score=0.1, threshold=0.5, sleep_s=0.05)
    result = slow.score(evidence=object())  # type: ignore[arg-type]
    assert result.latency_ms >= 45.0  # allow scheduler slack below the 50ms sleep


def test_detector_result_features_defaults_to_empty_dict() -> None:
    result = DetectorResult(
        name="x", score=0.0, decision=False, threshold=0.5, latency_ms=0.0, reasons=[]
    )
    assert result.features == {}
