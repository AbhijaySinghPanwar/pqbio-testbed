"""Wire protocol: the pydantic models exchanged between client and server (PROJECT_SPEC.md §2),
plus the canonical deterministic-CBOR helpers used to hash and sign them (§11).

Rule: anything that is hashed or signed is encoded as canonical CBOR (RFC 8949 §4.2.1
deterministic encoding), never as a JSON string — JSON object key ordering is not
guaranteed stable across implementations and would silently break every signature.
"""

from __future__ import annotations

import hashlib
from collections.abc import Set as AbstractSet
from typing import Any, Literal
from uuid import UUID

import cbor2
from pydantic import BaseModel, ConfigDict, Field

# --------------------------------------------------------------------------------------
# Canonical CBOR helpers (§11)
# --------------------------------------------------------------------------------------


def canonical_cbor_encode(obj: Any) -> bytes:
    """Deterministically encode a plain Python structure (dict/list/bytes/str/int/float/
    bool/None) as canonical CBOR. Map keys are sorted per RFC 8949's canonical rules
    regardless of input ordering, so equal structures always produce identical bytes.
    """
    return cbor2.dumps(obj, canonical=True)


def canonical_cbor_decode(data: bytes) -> Any:
    """Inverse of canonical_cbor_encode. Returns plain Python structures, not models."""
    return cbor2.loads(data)


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _uuid_to_bytes(value: Any) -> Any:
    """Recursively rewrite UUID instances to their raw 16 bytes so cbor2 (which has no
    native UUID support) can encode the structure. Everything else passes through.
    """
    if isinstance(value, UUID):
        return value.bytes
    if isinstance(value, dict):
        return {k: _uuid_to_bytes(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_uuid_to_bytes(v) for v in value]
    return value


def model_signing_payload(model: BaseModel, *, exclude: AbstractSet[str] = frozenset()) -> bytes:
    """Canonical CBOR encoding of a model's fields, excluding the digest/signature fields
    that are computed *over* this payload (so they can't be part of their own input).
    """
    data = model.model_dump(mode="python", exclude=set(exclude))
    return canonical_cbor_encode(_uuid_to_bytes(data))


# --------------------------------------------------------------------------------------
# Challenge (§5.3, §2)
# --------------------------------------------------------------------------------------


class Txn(BaseModel):
    """Opaque transaction descriptor bound into a Challenge (§5.3 calls it "txn
    (descriptor)" without prescribing fields). `action`/`relying_party` are the minimum
    any relying party needs; anything else is relying-party-specific and allowed through.
    """

    model_config = ConfigDict(extra="allow")

    action: str
    relying_party: str
    amount: str | None = None
    payee: str | None = None


class Challenge(BaseModel):
    """Server-issued, server-signed challenge (§5.3). `server_sig` is empty until the
    server signs `model_signing_payload(challenge, exclude={"server_sig"})`.
    """

    session_id: UUID
    nonce: bytes = Field(min_length=32, max_length=32)
    txn: Txn
    txn_hash: bytes = Field(min_length=32, max_length=32)
    issued_at: int  # ns since epoch, server clock
    expires_at: int  # ns since epoch
    server_sig: bytes = b""


# --------------------------------------------------------------------------------------
# EvidenceBundle (§5.2)
# --------------------------------------------------------------------------------------


class FrameMeta(BaseModel):
    capture_ts_ns: int
    exposure: float
    iso: int
    focal: float
    sequence_idx: int


class ChallengeSignal(BaseModel):
    """Measured response to the active challenge: illumination chromaticity trace and/or
    landmark dynamics trace, correlated against the nonce-derived expectation (B6).
    """

    illumination_trace: list[float] = Field(default_factory=list)
    landmark_trace: list[list[float]] = Field(default_factory=list)


class DeviceMeta(BaseModel):
    os: str
    camera_device_name: str
    camera_driver_id: str
    resolution: tuple[int, int]
    codec: str
    app_version: str
    attestation_token: bytes = b""  # simulated in this project (§2, §7)


class EvidenceBundle(BaseModel):
    """Signed, bound evidence bundle assembled by the capture client (§5.2).

    `bundle_digest` and `signature` are computed last, over
    `model_signing_payload(bundle, exclude={"bundle_digest", "signature"})`.
    """

    session_id: UUID
    device_id: str
    counter: int
    challenge_echo: Challenge
    frames: list[bytes]
    frame_meta: list[FrameMeta]
    challenge_signal: ChallengeSignal
    device_meta: DeviceMeta
    capture_binding: bytes = Field(min_length=32, max_length=32)
    bundle_digest: bytes = b""
    signature: bytes = b""


# --------------------------------------------------------------------------------------
# DetectorResult (§5.4)
# --------------------------------------------------------------------------------------


class DetectorResult(BaseModel):
    """Wire/audit-log form of a single detector's output. The `Detector` ABC in
    pqbio/detect/base.py returns this shape.
    """

    name: str
    score: float = Field(ge=0.0, le=1.0)  # 0.0 = benign, 1.0 = attack
    decision: bool  # score >= threshold
    threshold: float
    latency_ms: float
    reasons: list[str] = Field(default_factory=list)
    features: dict[str, Any] = Field(default_factory=dict)  # raw features for fusion training


# --------------------------------------------------------------------------------------
# Decision (§5.5)
# --------------------------------------------------------------------------------------

DecisionOutcome = Literal["ACCEPT", "REJECT", "CHALLENGE"]


class Decision(BaseModel):
    """Server-signed decision receipt returned to the client and retrievable via
    GET /v1/receipt/{id}. `receipt_signature` is empty until the server signs
    `model_signing_payload(decision, exclude={"receipt_signature"})`.
    """

    session_id: UUID
    decision: DecisionOutcome
    fused_score: float
    reason_codes: list[str]
    detector_scores: dict[str, float]
    stage_latency_ms: dict[str, float]
    policy_version: str
    model_versions: dict[str, str]
    receipt_signature: bytes = b""
