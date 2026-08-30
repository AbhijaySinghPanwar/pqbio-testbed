"""Round-trip and determinism tests for the canonical CBOR helpers (§11) and the wire
schemas (§5.2, §5.3, §5.4, §5.5).
"""

from __future__ import annotations

from uuid import uuid4

from pqbio.schemas import (
    Challenge,
    ChallengeSignal,
    Decision,
    DetectorResult,
    DeviceMeta,
    EvidenceBundle,
    FrameMeta,
    Txn,
    canonical_cbor_decode,
    canonical_cbor_encode,
    model_signing_payload,
    sha256,
)


def test_canonical_cbor_round_trip_scalars_and_containers() -> None:
    obj = {
        "a_string": "hello",
        "bytes_field": b"\x00\x01\xfe\xff",
        "an_int": 12345,
        "a_float": 3.5,
        "a_bool": True,
        "nothing": None,
        "nested": {"list": [1, 2, 3], "tuple_becomes_list": (4, 5)},
    }
    encoded = canonical_cbor_encode(obj)
    decoded = canonical_cbor_decode(encoded)
    assert decoded["a_string"] == "hello"
    assert decoded["bytes_field"] == b"\x00\x01\xfe\xff"
    assert decoded["an_int"] == 12345
    assert decoded["a_float"] == 3.5
    assert decoded["a_bool"] is True
    assert decoded["nothing"] is None
    assert decoded["nested"]["list"] == [1, 2, 3]
    assert decoded["nested"]["tuple_becomes_list"] == [4, 5]


def test_canonical_cbor_is_deterministic_regardless_of_key_insertion_order() -> None:
    a = {"z": 1, "a": 2, "m": 3}
    b = {"a": 2, "m": 3, "z": 1}
    assert canonical_cbor_encode(a) == canonical_cbor_encode(b)


def test_canonical_cbor_encode_decode_is_a_true_round_trip() -> None:
    obj = {"session": "abc-123", "score": 0.037, "frames": [b"jpeg-1", b"jpeg-2"]}
    once = canonical_cbor_encode(obj)
    twice = canonical_cbor_encode(canonical_cbor_decode(once))
    assert once == twice


def test_challenge_signing_payload_excludes_server_sig_and_is_deterministic() -> None:
    txn = Txn(action="login", relying_party="bank.example")
    txn_payload = canonical_cbor_encode(txn.model_dump(mode="python"))
    challenge = Challenge(
        session_id=uuid4(),
        nonce=b"n" * 32,
        txn=txn,
        txn_hash=sha256(txn_payload),
        issued_at=1_000,
        expires_at=31_000,
    )
    payload_1 = model_signing_payload(challenge, exclude={"server_sig"})
    payload_2 = model_signing_payload(challenge, exclude={"server_sig"})
    assert payload_1 == payload_2

    signed = challenge.model_copy(update={"server_sig": b"a-signature"})
    payload_after_signing = model_signing_payload(signed, exclude={"server_sig"})
    assert payload_after_signing == payload_1  # server_sig excluded, so signing doesn't change it


def _sample_bundle() -> EvidenceBundle:
    txn = Txn(action="login", relying_party="bank.example")
    challenge = Challenge(
        session_id=uuid4(),
        nonce=b"n" * 32,
        txn=txn,
        txn_hash=sha256(b"txn-payload"),
        issued_at=1_000,
        expires_at=31_000,
        server_sig=b"server-sig-bytes",
    )
    return EvidenceBundle(
        session_id=challenge.session_id,
        device_id="device-1",
        counter=1,
        challenge_echo=challenge,
        frames=[b"frame-0", b"frame-1"],
        frame_meta=[
            FrameMeta(capture_ts_ns=1, exposure=0.01, iso=100, focal=4.2, sequence_idx=0),
            FrameMeta(capture_ts_ns=2, exposure=0.01, iso=100, focal=4.2, sequence_idx=1),
        ],
        challenge_signal=ChallengeSignal(illumination_trace=[0.1, 0.2, 0.3]),
        device_meta=DeviceMeta(
            os="Android 14",
            camera_device_name="front-wide",
            camera_driver_id="camera2:0",
            resolution=(1280, 720),
            codec="h264",
            app_version="0.1.0",
        ),
        capture_binding=sha256(b"nonce-txn-merkle"),
    )


def test_evidence_bundle_signing_payload_excludes_digest_and_signature() -> None:
    bundle = _sample_bundle()
    payload_before = model_signing_payload(bundle, exclude={"bundle_digest", "signature"})

    digest = sha256(payload_before)
    signed = bundle.model_copy(update={"bundle_digest": digest, "signature": b"sig-bytes"})
    payload_after = model_signing_payload(signed, exclude={"bundle_digest", "signature"})

    assert payload_before == payload_after
    assert digest == sha256(payload_after)


def test_evidence_bundle_digest_changes_if_any_frame_byte_changes() -> None:
    bundle = _sample_bundle()
    payload_1 = model_signing_payload(bundle, exclude={"bundle_digest", "signature"})

    tampered = bundle.model_copy(update={"frames": [b"frame-0-TAMPERED", b"frame-1"]})
    payload_2 = model_signing_payload(tampered, exclude={"bundle_digest", "signature"})

    assert sha256(payload_1) != sha256(payload_2)


def test_detector_result_round_trips_through_json() -> None:
    result = DetectorResult(
        name="pad",
        score=0.12,
        decision=False,
        threshold=0.5,
        latency_ms=8.4,
        reasons=["texture_ok"],
        features={"lbp_energy": 0.03},
    )
    restored = DetectorResult.model_validate_json(result.model_dump_json())
    assert restored == result


def test_decision_round_trips_through_json() -> None:
    decision = Decision(
        session_id=uuid4(),
        decision="ACCEPT",
        fused_score=0.037,
        reason_codes=["BIND_OK", "PAD_OK"],
        detector_scores={"pad": 0.02, "deepfake": 0.11},
        stage_latency_ms={"crypto": 1.2, "binding": 0.9},
        policy_version="v1.0",
        model_versions={"pad": "sha256:abc"},
    )
    restored = Decision.model_validate_json(decision.model_dump_json())
    assert restored == decision
