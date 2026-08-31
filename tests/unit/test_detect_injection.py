"""Tests for pqbio.detect.injection (§5.4 D5)."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from pqbio.detect.face import prepared_evidence_bundle_only
from pqbio.detect.injection import FEATURE_NAMES, InjectionDetector, extract_features

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
MANIFEST = REPO_ROOT / "data" / "manifests" / "injection_corpus_manifest.json"
TRAINED_MODEL = REPO_ROOT / "models" / "injection_gbm.txt"


def _requires_corpus() -> None:
    if not MANIFEST.is_file():
        pytest.skip("injection corpus not generated (run scripts/make_injection_corpus.py)")


# --------------------------------------------------------------------------------------
# Feature extraction
# --------------------------------------------------------------------------------------


def test_extract_features_returns_all_feature_names() -> None:
    from _face_fixtures import no_face_bundle

    bundle = no_face_bundle()
    features = extract_features(bundle)
    assert set(features.keys()) == set(FEATURE_NAMES)
    assert all(isinstance(v, float) for v in features.values())


def test_virtual_cam_name_detected_case_insensitively() -> None:
    from _face_fixtures import no_face_bundle

    base = no_face_bundle()
    tampered = base.model_copy(
        update={
            "device_meta": base.device_meta.model_copy(
                update={"camera_device_name": "OBS VIRTUAL CAMERA"}
            )
        }
    )
    features = extract_features(tampered)
    assert features["virtual_cam_name_match"] == 1.0


def test_plausible_real_camera_name_not_flagged() -> None:
    from _face_fixtures import no_face_bundle

    base = no_face_bundle()
    tampered = base.model_copy(
        update={
            "device_meta": base.device_meta.model_copy(
                update={"camera_device_name": "Logitech HD Webcam C920"}
            )
        }
    )
    features = extract_features(tampered)
    assert features["virtual_cam_name_match"] == 0.0


def test_metadata_all_zero_detected() -> None:
    from _face_fixtures import no_face_bundle

    base = no_face_bundle()  # fixture frames carry non-zero exposure/iso (0.01, 100)
    zeroed_meta = [m.model_copy(update={"exposure": 0.0, "iso": 0}) for m in base.frame_meta]
    tampered = base.model_copy(update={"frame_meta": zeroed_meta})

    features = extract_features(tampered)
    assert features["metadata_all_zero"] == 1.0


def test_metadata_not_flagged_when_nonzero() -> None:
    from _face_fixtures import no_face_bundle

    features = extract_features(no_face_bundle())  # exposure=0.01, iso=100 in the fixture
    assert features["metadata_all_zero"] == 0.0


def test_attestation_absent_by_default() -> None:
    from _face_fixtures import no_face_bundle

    features = extract_features(no_face_bundle())
    assert features["attestation_present"] == 0.0


def test_attestation_present_when_token_set() -> None:
    from _face_fixtures import no_face_bundle

    base = no_face_bundle()
    tampered = base.model_copy(
        update={
            "device_meta": base.device_meta.model_copy(update={"attestation_token": b"tee-signed"})
        }
    )
    features = extract_features(tampered)
    assert features["attestation_present"] == 1.0


# --------------------------------------------------------------------------------------
# InjectionDetector
# --------------------------------------------------------------------------------------


def test_detector_fallback_without_trained_model() -> None:
    from _face_fixtures import no_face_bundle

    base = no_face_bundle()
    tampered = base.model_copy(
        update={
            "device_meta": base.device_meta.model_copy(
                update={"camera_device_name": "v4l2loopback"}
            )
        }
    )
    detector = InjectionDetector(model_path=Path("/nonexistent/model.txt"))
    evidence = prepared_evidence_bundle_only(tampered)
    result = detector.score(evidence)
    assert result.score == 1.0  # falls back to virtual_cam_name_match alone
    assert "INJECTION_MODEL_NOT_LOADED" in result.reasons[0]


@pytest.mark.skipif(not TRAINED_MODEL.is_file(), reason="injection GBM not trained yet")
def test_trained_detector_flags_real_tier1_sample() -> None:
    _requires_corpus()
    import json

    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    sample = manifest["samples"][0]
    from pqbio.schemas import EvidenceBundle, canonical_cbor_decode

    tier1_path = REPO_ROOT / sample["tier1_injection"]["bundle_path"]
    genuine_path = REPO_ROOT / sample["genuine"]["bundle_path"]
    tier1_bundle = EvidenceBundle.model_validate(canonical_cbor_decode(tier1_path.read_bytes()))
    genuine_bundle = EvidenceBundle.model_validate(canonical_cbor_decode(genuine_path.read_bytes()))

    detector = InjectionDetector(model_path=TRAINED_MODEL)
    tier1_result = detector.score(prepared_evidence_bundle_only(tier1_bundle))
    genuine_result = detector.score(prepared_evidence_bundle_only(genuine_bundle))

    assert tier1_result.decision is True
    assert genuine_result.decision is False
    assert tier1_result.score > genuine_result.score


# --------------------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------------------


def test_cli_scores_a_single_bundle(tmp_path: Path) -> None:
    _requires_corpus()
    import json

    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    bundle_path = REPO_ROOT / manifest["samples"][0]["tier1_injection"]["bundle_path"]
    out_path = tmp_path / "score.json"

    result = subprocess.run(
        [
            sys.executable,
            "-W",
            "ignore",
            "-m",
            "pqbio.detect.injection",
            "--input",
            str(bundle_path),
            "--out",
            str(out_path),
        ],
        capture_output=True,
        text=True,
        timeout=60,
        cwd=REPO_ROOT,
    )
    assert result.returncode == 0, result.stderr
    assert out_path.is_file()
    payload = json.loads(out_path.read_text(encoding="utf-8"))
    assert payload["name"] == "injection"
    assert set(payload["features"].keys()) == set(FEATURE_NAMES)
