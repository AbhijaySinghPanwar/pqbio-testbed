"""D0 identity match: ArcFace 512-D embedding, L2-normalised, cosine against the
enrolled template (PROJECT_SPEC.md §5.4 D0).

Owner: Krish (this session)

Answers "is this the right person" — a separate question from every other detector's
"is this evidence real". Kept as its own `Detector` so identity and liveness scores
never get conflated in the audit log or fusion input (§5.4 D6 lists `match` and the
liveness detectors as separate slots in the fusion feature vector for exactly this
reason).
"""

from __future__ import annotations

from typing import Any

import numpy as np
import numpy.typing as npt

from pqbio.config import settings
from pqbio.detect.base import Detector
from pqbio.detect.face import QUALITY_INSUFFICIENT, PreparedEvidence, _get_app


class NoEnrolledTemplateError(RuntimeError):
    """Raised when scoring is attempted with no enrolled template configured."""


def _l2_normalize(vec: npt.NDArray[np.float32]) -> npt.NDArray[np.float32]:
    norm = float(np.linalg.norm(vec))
    if norm == 0:
        return vec
    return vec / norm


def compute_embedding(evidence: PreparedEvidence) -> npt.NDArray[np.float32]:
    """ArcFace 512-D embedding for the request's aligned 112x112 crop, L2-normalised.
    Calls the recognition model's own `get_feat` directly on the crop `face.py` already
    aligned, rather than re-running detection+alignment a second time.
    """
    if evidence.crop_112 is None:
        raise ValueError(
            "PreparedEvidence has no crop_112 — face detection did not run or found no face"
        )
    app = _get_app()
    rec_model = app.models["recognition"]
    raw = np.asarray(rec_model.get_feat(evidence.crop_112), dtype=np.float32).reshape(-1)
    return _l2_normalize(raw)


class MatchDetector(Detector):
    """Score = 1 - cosine_similarity against the enrolled template, clamped to [0, 1],
    so it follows every other detector's 0=benign/1=attack convention: a perfect
    identity match scores ~0, a mismatch approaches 1. `decision=True` (score >=
    threshold) means REJECT — cosine similarity fell below `match_cosine_min`.
    """

    name = "match"

    def __init__(self, enrolled_template: npt.NDArray[np.float32] | None) -> None:
        self._enrolled_template = (
            _l2_normalize(np.asarray(enrolled_template, dtype=np.float32))
            if enrolled_template is not None
            else None
        )

    @property
    def threshold(self) -> float:
        # match_cosine_min (config) is the minimum similarity to PASS; this detector's
        # score is (1 - similarity), so the equivalent score threshold is its complement.
        return 1.0 - settings.detect.thresholds.match_cosine_min

    def _evaluate(self, evidence: PreparedEvidence) -> tuple[float, list[str], dict[str, Any]]:
        if not evidence.quality.passed or evidence.crop_112 is None:
            return 1.0, [QUALITY_INSUFFICIENT], {"cosine_similarity": None}
        if self._enrolled_template is None:
            raise NoEnrolledTemplateError(
                "MatchDetector requires an enrolled template to score against"
            )

        embedding = compute_embedding(evidence)
        cosine_similarity = float(np.dot(embedding, self._enrolled_template))
        score = min(1.0, max(0.0, 1.0 - cosine_similarity))
        min_cosine = settings.detect.thresholds.match_cosine_min
        reasons = (
            [f"cosine_similarity {cosine_similarity:.4f} below match_cosine_min {min_cosine}"]
            if cosine_similarity < min_cosine
            else ["identity match within threshold"]
        )
        return score, reasons, {"cosine_similarity": cosine_similarity}
