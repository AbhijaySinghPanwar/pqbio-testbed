"""Tests for pqbio.detect.face (§5.4 D0): checksum verification, quality gate, and the
real SCRFD/ArcFace detection pipeline against a real photographed face.
"""

from __future__ import annotations

import pytest
from _face_fixtures import (
    no_face_bundle,
    quality_fail_small_face_bundle,
    quality_pass_bundle,
)

from pqbio.detect.face import (
    CHECKSUMS_PATH,
    ModelIntegrityError,
    prepare_evidence,
    prepared_evidence_bundle_only,
    verify_model_checksums,
)

# --------------------------------------------------------------------------------------
# Checksum verification (fail-closed model integrity)
# --------------------------------------------------------------------------------------


def test_verify_model_checksums_passes_against_real_checksums_file() -> None:
    """The models actually fetched this session must verify cleanly — this is the
    real models/checksums.txt, not a fixture.
    """
    verify_model_checksums()  # must not raise


def test_verify_model_checksums_rejects_tampered_file(tmp_path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    import pqbio.detect.face as face_module

    bad_checksums = tmp_path / "checksums.txt"
    bad_checksums.write_text(
        "0" * 64
        + "  insightface/models/buffalo_l/det_10g.onnx\n"
        + "0" * 64
        + "  insightface/models/buffalo_l/w600k_r50.onnx\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(face_module, "CHECKSUMS_PATH", bad_checksums)
    with pytest.raises(ModelIntegrityError, match="SHA-256 mismatch"):
        verify_model_checksums()


def test_verify_model_checksums_rejects_missing_entry(tmp_path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    import pqbio.detect.face as face_module

    empty_checksums = tmp_path / "checksums.txt"
    empty_checksums.write_text("# nothing recorded\n", encoding="utf-8")
    monkeypatch.setattr(face_module, "CHECKSUMS_PATH", empty_checksums)
    with pytest.raises(ModelIntegrityError, match="no recorded checksum"):
        verify_model_checksums()


def test_real_checksums_file_is_nonempty() -> None:
    assert CHECKSUMS_PATH.is_file()
    text = CHECKSUMS_PATH.read_text(encoding="utf-8")
    assert "det_10g.onnx" in text
    assert "w600k_r50.onnx" in text
    # every non-comment line's digest must actually be a 64-char hex sha256 shape
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        digest = line.split()[0]
        assert len(digest) == 64
        int(digest, 16)  # raises if not valid hex


# --------------------------------------------------------------------------------------
# prepared_evidence_bundle_only — no face model required
# --------------------------------------------------------------------------------------


def test_prepared_evidence_bundle_only_skips_detection() -> None:
    bundle = no_face_bundle()
    evidence = prepared_evidence_bundle_only(bundle)
    assert evidence.bundle is bundle
    assert evidence.face_box is None
    assert evidence.quality.passed is False


# --------------------------------------------------------------------------------------
# Real detection pipeline (SCRFD + ArcFace, real inference, real photo)
# --------------------------------------------------------------------------------------


def test_prepare_evidence_no_face_detected() -> None:
    evidence = prepare_evidence(no_face_bundle())
    assert evidence.face_box is None
    assert evidence.crop_112 is None
    assert evidence.crop_224 is None
    assert evidence.quality.passed is False
    assert "no face detected" in evidence.quality.reasons


def test_prepare_evidence_quality_insufficient_small_face() -> None:
    """A genuine, real SCRFD detection that fails the quality gate on face size —
    confirms QUALITY_INSUFFICIENT is returned for a bad *genuine* capture, not an
    attack score (§5.4).
    """
    evidence = prepare_evidence(quality_fail_small_face_bundle())
    assert evidence.face_box is not None  # a real face WAS detected
    assert evidence.det_score > 0.0
    assert evidence.quality.passed is False
    assert evidence.quality.reasons[0] == "QUALITY_INSUFFICIENT"
    assert any("face_px" in r for r in evidence.quality.reasons)


def test_prepare_evidence_quality_passes_on_good_real_face() -> None:
    evidence = prepare_evidence(quality_pass_bundle())
    assert evidence.face_box is not None
    assert evidence.quality.passed is True
    assert evidence.quality.face_px >= 112
    assert evidence.quality.blur_variance >= 60.0
    assert abs(evidence.quality.yaw_deg) <= 25.0
    assert evidence.crop_112 is not None and evidence.crop_112.shape == (112, 112, 3)
    assert evidence.crop_224 is not None and evidence.crop_224.shape == (224, 224, 3)
    assert evidence.landmarks is not None and evidence.landmarks.shape == (5, 2)


def test_prepare_evidence_picks_sharpest_frame_in_burst() -> None:
    """Build a bundle where one frame is real and sharp and the rest are blank/blurry
    — the representative frame chosen must be the sharp one.
    """
    import numpy as np
    from _face_fixtures import _astronaut_bgr

    sharp = _astronaut_bgr()
    blank = np.full(sharp.shape, 128, dtype=np.uint8)
    from uuid import uuid4

    from pqbio.capture import CapturedFrame
    from pqbio.capture.bundler import assemble_bundle, sign_bundle
    from pqbio.pqc.sign import get_signer
    from pqbio.schemas import Challenge, ChallengeSignal, DeviceMeta, FrameMeta, Txn, sha256

    images = [blank, blank, sharp, blank]
    signer = get_signer("pq")
    _server_pk, server_sk = signer.keygen()
    device_pk, device_sk = signer.keygen()
    frames = [
        CapturedFrame(
            image=img,
            meta=FrameMeta(capture_ts_ns=i, exposure=0.0, iso=0, focal=0.0, sequence_idx=i),
        )
        for i, img in enumerate(images)
    ]
    txn = Txn(action="test", relying_party="test")
    challenge = Challenge(
        session_id=uuid4(),
        nonce=sha256(b"n"),
        txn=txn,
        txn_hash=sha256(b"t"),
        issued_at=0,
        expires_at=10**18,
    )
    bundle = assemble_bundle(
        session_id=challenge.session_id,
        device_id="d",
        counter=1,
        challenge_echo=challenge,
        captured_frames=frames,
        challenge_signal=ChallengeSignal(illumination_trace=[]),
        device_meta=DeviceMeta(
            os="t",
            camera_device_name="t",
            camera_driver_id="0",
            resolution=(sharp.shape[1], sharp.shape[0]),
            codec="raw",
            app_version="0.1",
        ),
    )
    bundle = sign_bundle(bundle, signer, device_sk)

    evidence = prepare_evidence(bundle)
    assert evidence.representative_frame_idx == 2
