"""Assemble, hash, and sign the evidence bundle (PROJECT_SPEC.md §5.2).

Owner: Aviral

    capture_binding = SHA256(nonce ‖ txn_hash ‖ SHA256(concat frame hashes))
    bundle_digest    = SHA256(canonical CBOR of every field except bundle_digest/signature)
    signature        = ML-DSA-65(bundle_digest, device_sk)

Frames are JPEG-encoded before hashing/bundling (§5.2: "frames[]: JPEG/PNG bytes").
Changing any single frame or metadata byte changes `bundle_digest` and therefore
invalidates `signature` — see tests/capture/test_bundler.py.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any
from uuid import UUID

import cv2
import numpy.typing as npt

from pqbio.capture import CapturedFrame
from pqbio.pqc.sign import Signer
from pqbio.schemas import (
    Challenge,
    ChallengeSignal,
    DeviceMeta,
    EvidenceBundle,
    model_signing_payload,
    sha256,
)


def encode_frame_jpeg(image: npt.NDArray[Any], quality: int = 90) -> bytes:
    ok, buf = cv2.imencode(".jpg", image, [cv2.IMWRITE_JPEG_QUALITY, quality])
    if not ok:
        raise ValueError("JPEG encoding failed")
    return bytes(buf)


def compute_capture_binding(nonce: bytes, txn_hash: bytes, frame_bytes: Sequence[bytes]) -> bytes:
    """SHA256(nonce ‖ txn_hash ‖ SHA256(concat frame hashes)) — §5.2."""
    concatenated_frame_hashes = b"".join(sha256(f) for f in frame_bytes)
    return sha256(nonce + txn_hash + sha256(concatenated_frame_hashes))


def assemble_bundle(
    *,
    session_id: UUID,
    device_id: str,
    counter: int,
    challenge_echo: Challenge,
    captured_frames: list[CapturedFrame],
    challenge_signal: ChallengeSignal,
    device_meta: DeviceMeta,
) -> EvidenceBundle:
    """Build an unsigned EvidenceBundle (bundle_digest/signature still empty). Both
    CameraSource and ReplaySource feed this same function, so "byte-identical bundle
    structures" (§5.2 DoD) holds by construction, not by coincidence.
    """
    frame_bytes = [encode_frame_jpeg(f.image) for f in captured_frames]
    frame_meta = [f.meta for f in captured_frames]
    capture_binding = compute_capture_binding(
        challenge_echo.nonce, challenge_echo.txn_hash, frame_bytes
    )
    return EvidenceBundle(
        session_id=session_id,
        device_id=device_id,
        counter=counter,
        challenge_echo=challenge_echo,
        frames=frame_bytes,
        frame_meta=frame_meta,
        challenge_signal=challenge_signal,
        device_meta=device_meta,
        capture_binding=capture_binding,
    )


def sign_bundle(bundle: EvidenceBundle, signer: Signer, device_sk: bytes) -> EvidenceBundle:
    """Compute bundle_digest over the canonical CBOR of every other field, sign it, and
    return a copy of `bundle` with both filled in.
    """
    payload = model_signing_payload(bundle, exclude={"bundle_digest", "signature"})
    digest = sha256(payload)
    signature = signer.sign(digest, device_sk)
    return bundle.model_copy(update={"bundle_digest": digest, "signature": signature})


def verify_bundle_signature(bundle: EvidenceBundle, signer: Signer, device_pk: bytes) -> bool:
    """Recompute bundle_digest from `bundle`'s current fields and check it against both
    the stored digest and the signature. Any tampering — a single frame byte, a
    metadata field, the digest itself — fails this.
    """
    payload = model_signing_payload(bundle, exclude={"bundle_digest", "signature"})
    recomputed_digest = sha256(payload)
    if recomputed_digest != bundle.bundle_digest:
        return False
    return signer.verify(bundle.bundle_digest, bundle.signature, device_pk)
