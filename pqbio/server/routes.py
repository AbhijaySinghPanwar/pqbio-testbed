"""HTTP routes: the five endpoints (PROJECT_SPEC.md §5.5).

Owner: Abhijay

Binary fields are base64 strings in JSON request/response bodies (explicit, not
relying on pydantic's default `bytes` JSON encoding, which assumes UTF-8-decodable
content and raises on arbitrary binary data — verified, not assumed, while building
this). Internal storage (the challenge cached alongside a session) uses the project's
own canonical-CBOR helpers instead, the same ones used for signing.
"""

from __future__ import annotations

import asyncio
import base64
from typing import Any, cast
from uuid import UUID, uuid4

import cv2
import numpy as np
import numpy.typing as npt
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from pqbio.binding.nonce import issue_challenge
from pqbio.detect.match import compute_embedding_from_image
from pqbio.pqc.aead import encrypt
from pqbio.pqc.handshake import HandshakeState, ProtocolStateError
from pqbio.pqc.kdf import derive_session_keys
from pqbio.pqc.keystore import DuplicateEnrolmentError, UnknownDeviceError
from pqbio.schemas import Challenge, Txn, canonical_cbor_decode, model_signing_payload
from pqbio.server.pipeline import PipelineContext, run_verify_pipeline
from pqbio.server.store import UnknownSessionError

router = APIRouter(prefix="/v1")


def _b64d(s: str) -> bytes:
    try:
        return base64.b64decode(s, validate=True)
    except Exception as exc:
        raise HTTPException(status_code=400, detail="malformed base64 field") from exc


def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _store_challenge(challenge: Challenge) -> bytes:
    return model_signing_payload(challenge)


def _load_challenge(data: bytes) -> Challenge:
    return Challenge.model_validate(canonical_cbor_decode(data))


# --------------------------------------------------------------------------------------
# POST /v1/enroll
# --------------------------------------------------------------------------------------


class EnrollRequest(BaseModel):
    device_id: str
    device_sig_pk_b64: str
    sig_mode: str  # "classical" | "pq"
    face_image_b64: str  # one JPEG-encoded enrollment photo


class EnrollResponse(BaseModel):
    device_id: str
    enrolled: bool
    server_kem_pk_b64: str
    server_sig_pk_b64: str


@router.post("/enroll", response_model=EnrollResponse)
async def enroll(req: EnrollRequest, request: Request) -> EnrollResponse:
    state = request.app.state
    image_bytes = _b64d(req.face_image_b64)
    decoded = cv2.imdecode(np.frombuffer(image_bytes, dtype=np.uint8), cv2.IMREAD_COLOR)
    if decoded is None:
        raise HTTPException(status_code=400, detail="face_image_b64 is not a decodable image")
    # cv2.IMREAD_COLOR always decodes to uint8; the cv2 stub's return type is broader
    # (a union covering every dtype imdecode could theoretically produce) than that
    # runtime guarantee, which is what compute_embedding_from_image's uint8-only
    # signature actually needs.
    image: npt.NDArray[np.uint8] = cast("npt.NDArray[np.uint8]", decoded)

    loop = asyncio.get_running_loop()
    embedding = await loop.run_in_executor(state.executor, compute_embedding_from_image, image)
    if embedding is None:
        raise HTTPException(status_code=400, detail="no face detected in enrollment photo")

    try:
        state.keystore.enroll(
            req.device_id,
            _b64d(req.device_sig_pk_b64),
            req.sig_mode,
            face_template=embedding.astype(np.float32).tobytes(),
        )
    except DuplicateEnrolmentError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    return EnrollResponse(
        device_id=req.device_id,
        enrolled=True,
        server_kem_pk_b64=_b64e(state.server_kem_pk),
        server_sig_pk_b64=_b64e(state.server_sig_pk),
    )


# --------------------------------------------------------------------------------------
# POST /v1/session/challenge
# --------------------------------------------------------------------------------------


class ChallengeRequest(BaseModel):
    device_id: str
    txn: dict[str, Any]


class ChallengeResponseModel(BaseModel):
    session_id: str
    nonce_b64: str
    txn: dict[str, Any]
    txn_hash_b64: str
    issued_at: int
    expires_at: int
    server_sig_b64: str


@router.post("/session/challenge", response_model=ChallengeResponseModel)
async def session_challenge(req: ChallengeRequest, request: Request) -> ChallengeResponseModel:
    state = request.app.state
    try:
        state.keystore.get(req.device_id)
    except UnknownDeviceError as exc:
        raise HTTPException(status_code=404, detail="device not enrolled") from exc

    session_id = uuid4()
    txn = Txn.model_validate(req.txn)
    loop = asyncio.get_running_loop()
    challenge: Challenge = await loop.run_in_executor(
        state.executor,
        lambda: issue_challenge(
            session_id=session_id,
            txn=txn,
            signer=state.signer,
            server_sk=state.server_sig_sk,
            nonce_store=state.nonce_store,
        ),
    )
    state.session_store.create_session(
        session_id, req.device_id, _store_challenge(challenge), challenge.expires_at
    )
    return ChallengeResponseModel(
        session_id=str(session_id),
        nonce_b64=_b64e(challenge.nonce),
        txn=challenge.txn.model_dump(mode="python"),
        txn_hash_b64=_b64e(challenge.txn_hash),
        issued_at=challenge.issued_at,
        expires_at=challenge.expires_at,
        server_sig_b64=_b64e(challenge.server_sig),
    )


# --------------------------------------------------------------------------------------
# POST /v1/session/handshake
# --------------------------------------------------------------------------------------


class HandshakeRequest(BaseModel):
    session_id: str
    kem_ct_b64: str


class HandshakeResponse(BaseModel):
    session_id: str
    keyed: bool


@router.post("/session/handshake", response_model=HandshakeResponse)
async def session_handshake(req: HandshakeRequest, request: Request) -> HandshakeResponse:
    state = request.app.state
    try:
        session_id = UUID(req.session_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="malformed session_id") from exc

    try:
        device_id = state.session_store.get_device_id(session_id)
        challenge_bytes = state.session_store.get_challenge_cbor(session_id)
    except UnknownSessionError as exc:
        raise HTTPException(status_code=404, detail="unknown session") from exc

    device_record = state.keystore.get(device_id)
    kem_ct = _b64d(req.kem_ct_b64)

    loop = asyncio.get_running_loop()

    def _decap_and_derive() -> tuple[bytes, bytes]:
        ss = state.kem.decapsulate(kem_ct, state.server_kem_sk)
        keys = derive_session_keys(
            ss=ss,
            session_id=session_id.bytes,
            kem_ct=kem_ct,
            server_sig_pk=state.server_sig_pk,
            device_sig_pk=device_record.sig_pk,
        )
        return keys.k_c2s, keys.k_s2c

    try:
        k_c2s, k_s2c = await loop.run_in_executor(state.executor, _decap_and_derive)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"handshake failed: {exc}") from exc

    try:
        state.session_store.transition(session_id, HandshakeState.KEYED)
    except ProtocolStateError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    state.session_store.set_kem_ct_and_keys(session_id, kem_ct, k_c2s, k_s2c)
    del challenge_bytes  # only needed to confirm the session exists at this point
    return HandshakeResponse(session_id=req.session_id, keyed=True)


# --------------------------------------------------------------------------------------
# POST /v1/verify
# --------------------------------------------------------------------------------------


class VerifyRequest(BaseModel):
    session_id: str
    aead_nonce_b64: str
    ciphertext_b64: str


class VerifyResponse(BaseModel):
    session_id: str
    aead_nonce_b64: str
    ciphertext_b64: str  # AEAD(K_s2c, canonical_cbor(Decision))


@router.post("/verify", response_model=VerifyResponse)
async def verify(req: VerifyRequest, request: Request) -> VerifyResponse:
    state = request.app.state
    try:
        session_id = UUID(req.session_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="malformed session_id") from exc

    try:
        state.session_store.transition(session_id, HandshakeState.VERIFIED)
    except ProtocolStateError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except UnknownSessionError as exc:
        raise HTTPException(status_code=404, detail="unknown session") from exc

    ctx = PipelineContext(
        keystore=state.keystore,
        session_store=state.session_store,
        nonce_store=state.nonce_store,
        phash_index=state.phash_index,
        audit_log=state.audit_log,
        signer=state.signer,
        server_pk=state.server_sig_pk,
        server_sk=state.server_sig_sk,
        injection_detector=state.injection_detector,
        executor=state.executor,
        cascade_model=state.cascade_model,
    )
    decision = await run_verify_pipeline(
        session_id=session_id,
        aead_nonce=_b64d(req.aead_nonce_b64),
        ciphertext=_b64d(req.ciphertext_b64),
        ctx=ctx,
    )

    _k_c2s, k_s2c = state.session_store.get_session_keys(session_id)
    plaintext = model_signing_payload(decision)  # full payload, signature included
    response_nonce, response_ciphertext = encrypt(k_s2c, plaintext, aad=b"")
    return VerifyResponse(
        session_id=req.session_id,
        aead_nonce_b64=_b64e(response_nonce),
        ciphertext_b64=_b64e(response_ciphertext),
    )


# --------------------------------------------------------------------------------------
# GET /v1/health
# --------------------------------------------------------------------------------------


@router.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}
