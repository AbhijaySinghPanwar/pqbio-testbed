"""Tests for pqbio.detect.match (§5.4 D0 identity match): real ArcFace embeddings,
self-match vs. mismatch, and the quality-gate interaction.
"""

from __future__ import annotations

import numpy as np
import pytest
from _face_fixtures import quality_fail_small_face_bundle, quality_pass_bundle

from pqbio.detect.face import prepare_evidence
from pqbio.detect.match import MatchDetector, NoEnrolledTemplateError, compute_embedding


def test_compute_embedding_is_512d_and_l2_normalised() -> None:
    evidence = prepare_evidence(quality_pass_bundle())
    embedding = compute_embedding(evidence)
    assert embedding.shape == (512,)
    assert abs(float(np.linalg.norm(embedding)) - 1.0) < 1e-4


def test_self_match_scores_near_zero() -> None:
    """Matching an embedding against itself must score ~0 (benign) and not decide
    REJECT.
    """
    evidence = prepare_evidence(quality_pass_bundle())
    embedding = compute_embedding(evidence)
    detector = MatchDetector(enrolled_template=embedding)

    result = detector.score(evidence)
    assert result.features["cosine_similarity"] == pytest.approx(1.0, abs=1e-4)
    assert result.score == pytest.approx(0.0, abs=1e-4)
    assert result.decision is False


def test_mismatch_against_unrelated_template_scores_high() -> None:
    evidence = prepare_evidence(quality_pass_bundle())
    unrelated = np.random.default_rng(0).normal(size=512).astype(np.float32)
    detector = MatchDetector(enrolled_template=unrelated)

    result = detector.score(evidence)
    assert result.features["cosine_similarity"] < 0.38  # below match_cosine_min
    assert result.score > 0.5
    assert result.decision is True


def test_quality_insufficient_short_circuits_without_computing_embedding() -> None:
    """A bad genuine capture must read as QUALITY_INSUFFICIENT, never as a mismatch —
    §5.4: quality gate failures are not attack scores.
    """
    evidence = prepare_evidence(quality_fail_small_face_bundle())
    assert evidence.quality.passed is False

    detector = MatchDetector(enrolled_template=np.zeros(512, dtype=np.float32))
    result = detector.score(evidence)
    assert result.reasons == ["QUALITY_INSUFFICIENT"]
    assert result.features["cosine_similarity"] is None


def test_no_enrolled_template_raises_on_score_attempt() -> None:
    evidence = prepare_evidence(quality_pass_bundle())
    detector = MatchDetector(enrolled_template=None)
    with pytest.raises(NoEnrolledTemplateError):
        detector.score(evidence)


def test_threshold_is_complement_of_match_cosine_min() -> None:
    from pqbio.config import settings

    detector = MatchDetector(enrolled_template=np.zeros(512, dtype=np.float32))
    assert detector.threshold == pytest.approx(1.0 - settings.detect.thresholds.match_cosine_min)
