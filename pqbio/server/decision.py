"""Decision object construction and signing (PROJECT_SPEC.md §5.5).

Owner: Abhijay

`schemas.Decision` is the wire type (§5.5, matched field-for-field); this module only
builds and signs one. Receipt signing carries the ~52ms fallback ML-DSA cost documented
in `results/pqc_micro.json` / CLAUDE.md — it shows up in `stage_latency_ms["sign_audit"]`
for every request, not optimised around, since that's the whole point of measuring it.
"""

from __future__ import annotations

from pathlib import Path
from uuid import UUID

from pqbio.pqc.kem import KEM_BACKEND
from pqbio.pqc.sign import SIG_BACKEND, Signer
from pqbio.schemas import Decision, DecisionOutcome, model_signing_payload, sha256

MODELS_DIR = Path(__file__).resolve().parent.parent.parent / "models"
CHECKSUMS_PATH = MODELS_DIR / "checksums.txt"


def load_model_versions() -> dict[str, str]:
    """`model_versions` (§5.5) from `models/checksums.txt`, plus the active crypto
    backend names — every persisted result in this project records which PQC backend
    produced it (§14), and a decision receipt is exactly that kind of persisted result.
    """
    versions: dict[str, str] = {
        "KEM_BACKEND": KEM_BACKEND,
        "SIG_BACKEND": SIG_BACKEND,
    }
    if CHECKSUMS_PATH.is_file():
        for line in CHECKSUMS_PATH.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            digest, _, rel_path = line.partition("  ")
            if digest and rel_path:
                versions[rel_path] = f"sha256:{digest}"
    return versions


def build_and_sign_decision(
    *,
    session_id: UUID,
    decision: DecisionOutcome,
    fused_score: float,
    reason_codes: list[str],
    detector_scores: dict[str, float],
    stage_latency_ms: dict[str, float],
    signer: Signer,
    server_sk: bytes,
) -> Decision:
    """Builds the Decision object (§5.5, verbatim shape) and signs
    `model_signing_payload(decision, exclude={"receipt_signature"})` — canonical CBOR,
    never a JSON string (§11) — with the server's ML-DSA-65 key.
    """
    unsigned = Decision(
        session_id=session_id,
        decision=decision,
        fused_score=fused_score,
        reason_codes=reason_codes,
        detector_scores=detector_scores,
        stage_latency_ms=stage_latency_ms,
        model_versions=load_model_versions(),
    )
    payload = model_signing_payload(unsigned, exclude={"receipt_signature"})
    receipt_signature = signer.sign(sha256(payload), server_sk)
    return unsigned.model_copy(update={"receipt_signature": receipt_signature})


def verify_decision_signature(decision: Decision, signer: Signer, server_pk: bytes) -> bool:
    """For clients (and the DoD's own test) to verify a receipt against the published
    server public key.
    """
    payload = model_signing_payload(decision, exclude={"receipt_signature"})
    return signer.verify(sha256(payload), decision.receipt_signature, server_pk)
