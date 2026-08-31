"""Detector contract (PROJECT_SPEC.md §5.4).

Every detector under `pqbio/detect/` implements `Detector` and produces a
`DetectorResult`. `face.py`'s `PreparedEvidence` (detect -> align -> crops -> quality
score) is computed once per request and passed to every detector, so face detection
never repeats per-detector.

**Latency is measured here, in `Detector.score()`, not by each subclass** — an explicit
instruction for this build, and a deliberate correction of a pattern in an earlier draft
of this spec where each detector timed itself. Self-timed latency is only comparable
across detectors if every detector remembers to time the same span the same way; one
detector that forgets, or times a narrower span than another, silently corrupts the
`stage_latency_ms`/cascade-ordering numbers everything downstream (Module E's pipeline,
Module F's ACER-vs-latency trade-off analysis) depends on. Subclasses implement
`_evaluate()` — pure scoring logic, no timing concerns — and the base class wraps it.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from pqbio.detect.face import PreparedEvidence


@dataclass
class DetectorResult:
    name: str
    score: float  # 0.0 benign ... 1.0 attack
    decision: bool
    threshold: float
    latency_ms: float
    reasons: list[str]
    features: dict[str, Any] = field(default_factory=dict)  # for fusion training


class Detector(ABC):
    """Common contract for every detector. `name` and `threshold` are per-instance
    (typically config-driven, e.g. `settings.detect.thresholds.injection`), not
    hardcoded class constants — see each subclass.
    """

    name: str

    @property
    @abstractmethod
    def threshold(self) -> float: ...

    @abstractmethod
    def _evaluate(self, evidence: PreparedEvidence) -> tuple[float, list[str], dict[str, Any]]:
        """Subclasses implement scoring here: return (score in [0,1], human-readable
        reasons for the audit log, a features dict for fusion training). Do not measure
        latency here — `score()` does that uniformly for every detector.
        """
        ...

    def score(self, evidence: PreparedEvidence) -> DetectorResult:
        """Public entry point. Measures latency around `_evaluate()` and assembles the
        full `DetectorResult` — the one place latency is ever measured.
        """
        start = time.perf_counter()
        raw_score, reasons, features = self._evaluate(evidence)
        latency_ms = (time.perf_counter() - start) * 1000.0
        return DetectorResult(
            name=self.name,
            score=raw_score,
            decision=raw_score >= self.threshold,
            threshold=self.threshold,
            latency_ms=latency_ms,
            reasons=reasons,
            features=features,
        )
