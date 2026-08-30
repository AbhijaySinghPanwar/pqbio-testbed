"""Tests for pqbio.capture.bundler (§5.2 DoD items 2 and 5).

Bundle signing goes through the real Signer (kyber-py/dilithium-py fallback in this
environment), so it carries the ~52ms fallback ML-DSA cost documented in
results/pqc_micro.json and CLAUDE.md — that's expected here and disappears with
liboqs, not something these tests work around.
"""

from __future__ import annotations

from uuid import uuid4

import numpy as np
import pytest

from pqbio.capture import CapturedFrame
from pqbio.capture.bundler import (
    assemble_bundle,
    compute_capture_binding,
    sign_bundle,
    verify_bundle_signature,
)
from pqbio.pqc.sign import get_signer
from pqbio.schemas import (
    Challenge,
    ChallengeSignal,
    DeviceMeta,
    FrameMeta,
    Txn,
    canonical_cbor_decode,
    canonical_cbor_encode,
    model_signing_payload,
    sha256,
)


def _sample_challenge() -> Challenge:
    txn = Txn(action="login", relying_party="bank.example")
    txn_payload = canonical_cbor_encode(txn.model_dump(mode="python"))
    return Challenge(
        session_id=uuid4(),
        nonce=sha256(b"nonce-seed"),
        txn=txn,
        txn_hash=sha256(txn_payload),
        issued_at=1_000,
        expires_at=31_000,
        server_sig=b"server-sig-bytes",
    )


def _sample_captured_frames(n: int = 3) -> list[CapturedFrame]:
    rng = np.random.default_rng(seed=7)
    return [
        CapturedFrame(
            image=rng.integers(0, 256, size=(32, 32, 3), dtype=np.uint8),
            meta=FrameMeta(capture_ts_ns=i, exposure=0.01, iso=100, focal=4.2, sequence_idx=i),
        )
        for i in range(n)
    ]


def _sample_device_meta() -> DeviceMeta:
    return DeviceMeta(
        os="Windows",
        camera_device_name="test-cam",
        camera_driver_id="0",
        resolution=(32, 32),
        codec="raw",
        app_version="0.1.0",
    )


def _build_and_sign(frames: list[CapturedFrame] | None = None):
    challenge = _sample_challenge()
    frames = frames if frames is not None else _sample_captured_frames()
    bundle = assemble_bundle(
        session_id=challenge.session_id,
        device_id="device-1",
        counter=1,
        challenge_echo=challenge,
        captured_frames=frames,
        challenge_signal=ChallengeSignal(illumination_trace=[0.1, 0.2, 0.3]),
        device_meta=_sample_device_meta(),
    )
    signer = get_signer("pq")
    device_pk, device_sk = signer.keygen()
    signed = sign_bundle(bundle, signer, device_sk)
    return signed, signer, device_pk


def test_compute_capture_binding_matches_spec_formula() -> None:
    nonce = sha256(b"nonce")
    txn_hash = sha256(b"txn")
    frame_bytes = [b"frame-0", b"frame-1"]
    expected = sha256(nonce + txn_hash + sha256(b"".join(sha256(f) for f in frame_bytes)))
    assert compute_capture_binding(nonce, txn_hash, frame_bytes) == expected


def test_sign_and_verify_round_trip() -> None:
    signed, signer, device_pk = _build_and_sign()
    assert signed.bundle_digest != b""
    assert signed.signature != b""
    assert verify_bundle_signature(signed, signer, device_pk) is True


def test_canonical_cbor_round_trip_yields_identical_digest() -> None:
    """§5.2 DoD: "re-serialising yields an identical digest"."""
    signed, _signer, _device_pk = _build_and_sign()

    encoded = model_signing_payload(signed)
    decoded_plain = canonical_cbor_decode(encoded)
    re_encoded = canonical_cbor_encode(decoded_plain)
    assert encoded == re_encoded


@pytest.mark.parametrize(
    "tamper",
    [
        "device_id",
        "counter",
        "capture_binding",
        "frame_byte",
        "frame_meta_field",
        "challenge_signal",
        "device_meta_field",
    ],
)
def test_tampering_any_field_invalidates_signature(tamper: str) -> None:
    """§5.2 DoD: "changing any single byte of any field or frame invalidates the
    signature". Covers a representative field from every part of the bundle, not just
    the frame bytes.
    """
    signed, signer, device_pk = _build_and_sign()
    assert verify_bundle_signature(signed, signer, device_pk) is True

    if tamper == "device_id":
        tampered = signed.model_copy(update={"device_id": signed.device_id + "-x"})
    elif tamper == "counter":
        tampered = signed.model_copy(update={"counter": signed.counter + 1})
    elif tamper == "capture_binding":
        flipped = bytearray(signed.capture_binding)
        flipped[0] ^= 0xFF
        tampered = signed.model_copy(update={"capture_binding": bytes(flipped)})
    elif tamper == "frame_byte":
        frames = list(signed.frames)
        flipped = bytearray(frames[0])
        flipped[0] ^= 0xFF
        frames[0] = bytes(flipped)
        tampered = signed.model_copy(update={"frames": frames})
    elif tamper == "frame_meta_field":
        frame_meta = list(signed.frame_meta)
        frame_meta[0] = frame_meta[0].model_copy(update={"iso": frame_meta[0].iso + 1})
        tampered = signed.model_copy(update={"frame_meta": frame_meta})
    elif tamper == "challenge_signal":
        tampered = signed.model_copy(
            update={"challenge_signal": ChallengeSignal(illumination_trace=[0.9])}
        )
    else:  # device_meta_field
        new_meta = signed.device_meta.model_copy(update={"app_version": "9.9.9"})
        tampered = signed.model_copy(update={"device_meta": new_meta})

    assert verify_bundle_signature(tampered, signer, device_pk) is False


def test_wrong_device_key_rejected() -> None:
    signed, signer, _device_pk = _build_and_sign()
    other_pk, _other_sk = signer.keygen()
    assert verify_bundle_signature(signed, signer, other_pk) is False
