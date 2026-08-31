"""Shared test fixtures for Module D face/match/injection tests. Not a test file itself
(leading underscore keeps pytest from collecting it).

Uses `skimage.data.astronaut()` — a well-known, standard computer-vision test image
(public-domain-status NASA photo, bundled with scikit-image specifically for testing —
not a licensed biometric dataset) as the one real, photographed face available in this
environment. Crop coordinates below were found by hand and verified once manually (see
PROJECT_SPEC.md's Module D amendment) to give a real SCRFD detection that either passes
or fails the quality gate for a known reason, so these fixtures exercise real inference,
not a mock.
"""

from __future__ import annotations

from uuid import uuid4

import cv2
import numpy as np

from pqbio.capture import CapturedFrame
from pqbio.capture.bundler import assemble_bundle, sign_bundle
from pqbio.pqc.sign import Signer, get_signer
from pqbio.schemas import (
    Challenge,
    ChallengeSignal,
    DeviceMeta,
    EvidenceBundle,
    FrameMeta,
    Txn,
    sha256,
)


def _astronaut_bgr() -> np.ndarray:
    import skimage.data

    return cv2.cvtColor(skimage.data.astronaut(), cv2.COLOR_RGB2BGR)


def build_bundle(
    image: np.ndarray, n_frames: int = 5, signer: Signer | None = None
) -> EvidenceBundle:
    signer = signer or get_signer("pq")
    _server_pk, server_sk = signer.keygen()
    device_pk, device_sk = signer.keygen()
    frames = [
        CapturedFrame(
            image=image,
            meta=FrameMeta(capture_ts_ns=i, exposure=0.01, iso=100, focal=4.0, sequence_idx=i),
        )
        for i in range(n_frames)
    ]
    txn = Txn(action="test", relying_party="test")
    challenge = Challenge(
        session_id=uuid4(),
        nonce=sha256(b"fixture-nonce"),
        txn=txn,
        txn_hash=sha256(b"fixture-txn"),
        issued_at=0,
        expires_at=10**18,
    )
    bundle = assemble_bundle(
        session_id=challenge.session_id,
        device_id="fixture-device",
        counter=1,
        challenge_echo=challenge,
        captured_frames=frames,
        challenge_signal=ChallengeSignal(illumination_trace=[]),
        device_meta=DeviceMeta(
            os="test",
            camera_device_name="test-cam",
            camera_driver_id="0",
            resolution=(image.shape[1], image.shape[0]),
            codec="raw",
            app_version="0.1.0",
        ),
    )
    return sign_bundle(bundle, signer, device_sk)


def quality_pass_bundle() -> EvidenceBundle:
    """A real face crop that passes the quality gate: sharp (LANCZOS4, mild 1.3x
    upscale) and large enough (face_px > 112). Verified manually to yield
    `quality.passed is True` with this exact crop/scale.
    """
    img = _astronaut_bgr()
    x, y, w, h = 155, 35, 150, 170
    crop = img[y : y + h, x : x + w]
    big = cv2.resize(crop, (int(w * 1.3), int(h * 1.3)), interpolation=cv2.INTER_LANCZOS4)
    return build_bundle(big)


def quality_fail_small_face_bundle() -> EvidenceBundle:
    """The same real photo at native resolution: SCRFD detects a real face, but it's
    smaller than min_face_px — a genuine, verified QUALITY_INSUFFICIENT case, not a
    contrived one.
    """
    return build_bundle(_astronaut_bgr())


def no_face_bundle() -> EvidenceBundle:
    """A synthetic image SCRFD should not detect any face in at all."""
    blank = np.full((128, 128, 3), 128, dtype=np.uint8)
    return build_bundle(blank)
