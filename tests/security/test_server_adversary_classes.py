"""One test per adversary class A1-A6 (PROJECT_SPEC.md §1's threat table, §5.5 DoD),
each driving the real enroll -> challenge -> handshake -> verify flow and asserting the
correct reason code comes back.

Owner: Abhijay

**A2/A3/A4 are BLOCKED, not implemented**: `pad.py`, `morph.py`, and `deepfake.py` were
deliberately left absent (not stubbed) in Module D -- see CLAUDE.md's "Current state"
and PROJECT_SPEC.md §14. There is no detector to defeat and, for A3 specifically, no
second real photographed identity in this environment to blend a morph from (the
astronaut test image is the only one available). What these three tests verify instead
is the contract the DoD actually asks for when a detector is missing: the submission
still reaches the pipeline, gets a real decision (never a crash, never a silent ACCEPT
that pretends the missing signal was benign), and the corresponding `MISSING_SIGNAL_*`
code is present. Do not read a pass here as "the attack is caught" -- it isn't, yet.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest
from _server_fixtures import ServerTestClient, _quality_pass_crop, b64d
from fastapi.testclient import TestClient

from pqbio.pqc.aead import decrypt, encrypt
from pqbio.schemas import Decision, canonical_cbor_decode, model_signing_payload
from pqbio.server.app import create_app


@pytest.fixture
def app_client():
    with tempfile.TemporaryDirectory() as tmp:
        app = create_app(data_dir=Path(tmp) / "data")
        with TestClient(app) as client:
            yield client


def _decrypt_decision(stc: ServerTestClient, keys, resp_body: dict) -> Decision:
    resp_nonce = b64d(resp_body["aead_nonce_b64"])
    resp_ct = b64d(resp_body["ciphertext_b64"])
    decision_bytes = decrypt(keys.k_s2c, resp_nonce, resp_ct, aad=b"")
    return Decision.model_validate(canonical_cbor_decode(decision_bytes))


# --------------------------------------------------------------------------------------
# A1 -- Network: read, drop, reorder, replay, modify
# --------------------------------------------------------------------------------------


def test_a1_bitflipped_ciphertext_rejected_with_crypto_reason_code(app_client):
    """ "Modify" half of A1: a tampered evidence ciphertext must fail AEAD decryption,
    not be silently accepted or crash the pipeline.
    """
    stc = ServerTestClient(app_client)
    stc.enroll()
    session_id, challenge_obj = stc.challenge()
    keys = stc.handshake(session_id)
    bundle = stc.build_live_genuine_bundle(session_id, challenge_obj, n_frames=30)
    plaintext = model_signing_payload(bundle)
    aead_nonce, ciphertext = encrypt(keys.k_c2s, plaintext, aad=b"")
    tampered = bytearray(ciphertext)
    tampered[0] ^= 0xFF

    r = stc.verify_raw(session_id, aead_nonce, bytes(tampered))
    assert r.status_code == 200, r.text
    decision = _decrypt_decision(stc, keys, r.json())
    assert decision.decision == "REJECT"
    assert "CRYPTO_AEAD_FAILED" in decision.reason_codes


def test_a1_replayed_verify_request_rejected_by_session_state_machine(app_client):
    """ "Replay" half of A1: resubmitting the exact same, validly-signed request a
    second time must not be reprocessed -- the handshake state machine's at-most-once
    VERIFIED transition is what actually stops this, independent of the evidence
    content (§5.1).
    """
    stc = ServerTestClient(app_client)
    stc.enroll()
    session_id, challenge_obj = stc.challenge()
    keys = stc.handshake(session_id)
    bundle = stc.build_live_genuine_bundle(session_id, challenge_obj, n_frames=30)
    plaintext = model_signing_payload(bundle)
    aead_nonce, ciphertext = encrypt(keys.k_c2s, plaintext, aad=b"")

    r1 = stc.verify_raw(session_id, aead_nonce, ciphertext)
    assert r1.status_code == 200, r1.text

    r2 = stc.verify_raw(session_id, aead_nonce, ciphertext)
    assert r2.status_code == 409, r2.text


# --------------------------------------------------------------------------------------
# A2 -- Presentation (print/mask/screen artefact) -- BLOCKED, no pad.py
# --------------------------------------------------------------------------------------


def test_a2_presentation_attack_reaches_pipeline_as_missing_signal(app_client):
    """BLOCKED: no PAD detector exists. Shapes the submission like a screen/virtual-
    camera presentation (device name "OBS Virtual Camera", the same shape
    `scripts/make_injection_corpus.py`'s tier-1 corpus uses) and asserts it reaches a
    real decision reporting `MISSING_SIGNAL_PAD` -- never silently treated as benign.
    """
    stc = ServerTestClient(app_client)
    stc.enroll()
    session_id, challenge_obj = stc.challenge()
    keys = stc.handshake(session_id)
    image = _quality_pass_crop()
    bundle = stc.build_instant_bundle(
        session_id, challenge_obj, image, n_frames=30, device_name="OBS Virtual Camera"
    )
    decision = stc.verify(session_id, bundle, keys)

    assert decision.decision in ("REJECT", "CHALLENGE")
    assert "MISSING_SIGNAL_PAD" in decision.reason_codes


# --------------------------------------------------------------------------------------
# A3 -- Morph (enrolment image blended from two identities) -- BLOCKED, no morph.py
# --------------------------------------------------------------------------------------


def test_a3_morph_reaches_pipeline_as_missing_signal(app_client):
    """BLOCKED: no morph detector exists, and this environment has only one real
    photographed identity (no second face to blend a morph from -- see module
    docstring). Confirms a normal enrolment + verification still reports
    `MISSING_SIGNAL_MORPH` rather than pretending morph-liveness was checked.
    """
    stc = ServerTestClient(app_client)
    decision = stc.full_genuine_flow(n_frames=30)
    assert "MISSING_SIGNAL_MORPH" in decision.reason_codes


# --------------------------------------------------------------------------------------
# A4 -- Deepfake (face swap / re-enactment video) -- BLOCKED, no deepfake.py
# --------------------------------------------------------------------------------------


def test_a4_deepfake_reaches_pipeline_as_missing_signal(app_client):
    """BLOCKED: no deepfake detector exists and no licensed FF++/Celeb-DF clips are
    available in this environment (§14). Confirms the pipeline still reaches a real
    decision reporting `MISSING_SIGNAL_DEEPFAKE`.
    """
    stc = ServerTestClient(app_client)
    stc.enroll()
    session_id, challenge_obj = stc.challenge()
    keys = stc.handshake(session_id)
    image = _quality_pass_crop()
    bundle = stc.build_instant_bundle(
        session_id, challenge_obj, image, n_frames=30, device_name="synthetic-reenactment"
    )
    decision = stc.verify(session_id, bundle, keys)

    assert decision.decision in ("REJECT", "CHALLENGE")
    assert "MISSING_SIGNAL_DEEPFAKE" in decision.reason_codes


# --------------------------------------------------------------------------------------
# A5 -- Replay (resubmits previously captured genuine evidence)
# --------------------------------------------------------------------------------------


def test_a5a_verbatim_resubmission_rejected_by_session_state_machine(app_client):
    """A5(a): resubmit a bundle verbatim -- same mechanism as A1's replay sub-case
    (the session-level protection doesn't care why the exact same message reappeared).
    """
    stc = ServerTestClient(app_client)
    stc.enroll()
    session_id, challenge_obj = stc.challenge()
    keys = stc.handshake(session_id)
    bundle = stc.build_live_genuine_bundle(session_id, challenge_obj, n_frames=30)
    plaintext = model_signing_payload(bundle)
    aead_nonce, ciphertext = encrypt(keys.k_c2s, plaintext, aad=b"")

    assert stc.verify_raw(session_id, aead_nonce, ciphertext).status_code == 200
    assert stc.verify_raw(session_id, aead_nonce, ciphertext).status_code == 409


def test_a5b_same_media_under_fresh_nonce_and_signature_flagged_as_reused(app_client):
    """A5(b): resubmit the same media under a fresh nonce and re-signature -- the
    scenario B1-B5 (correctly-signed, freshly-nonced messages) cannot catch by
    construction, and exactly what `phash_index`'s accept-path evidence recording
    (this session's pipeline.py fix) plus the N-of-burst reuse rule (§14) exists for.
    """
    stc = ServerTestClient(app_client)
    genuine = stc.full_genuine_flow(n_frames=30)
    assert genuine.decision == "ACCEPT"

    session_id2, challenge_obj2 = stc.challenge()
    keys2 = stc.handshake(session_id2)
    # same underlying face content as the first, accepted session -- only the palette
    # tint differs (driven by the new nonce); phash is coarse/structure-dominated and
    # was found (this session's calibration) to barely respond to that alone
    bundle2 = stc.build_live_genuine_bundle(session_id2, challenge_obj2, n_frames=30, counter=2)
    decision2 = stc.verify(session_id2, bundle2, keys2)

    assert decision2.decision == "REJECT"
    assert "BIND_EVIDENCE_REUSE" in decision2.reason_codes


@pytest.mark.skip(
    reason="A5(c) screen-replay recapture needs a real display+webcam capture loop "
    "(Module B's render_challenge_fullscreen is unverified headless, §14) -- blocked, "
    "not implemented, rather than faked."
)
def test_a5c_screen_replay_recapture() -> None:
    raise NotImplementedError


# --------------------------------------------------------------------------------------
# A6 -- Injection (bypasses the sensor; assume a valid device key)
# --------------------------------------------------------------------------------------


def test_a6_injection_tier1_instant_capture_flagged(app_client):
    """Tier-1 injection: a valid device key submits frames with no real capture pacing
    (zero-jitter, back-to-back timestamps) -- exactly `injection.py`'s timing-jitter
    feature's target, and the one detector in this pipeline that fully exists.
    """
    stc = ServerTestClient(app_client)
    stc.enroll()
    session_id, challenge_obj = stc.challenge()
    keys = stc.handshake(session_id)
    image = _quality_pass_crop()
    bundle = stc.build_instant_bundle(session_id, challenge_obj, image, n_frames=30)
    decision = stc.verify(session_id, bundle, keys)

    assert decision.decision == "REJECT"
    assert decision.detector_scores["injection"] > 0.5
