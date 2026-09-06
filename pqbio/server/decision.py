"""Decision object construction and signing (PROJECT_SPEC.md §5.5).

Owner: Abhijay

`schemas.Decision` is the wire type (§5.5, matched field-for-field); this module only
builds and signs one. Receipt signing carries the ~52ms fallback ML-DSA cost documented
in `results/pqc_micro.json` / CLAUDE.md — it shows up in `stage_latency_ms["sign_audit"]`
for every request, not optimised around, since that's the whole point of measuring it.
"""

from __future__ import annotations

from collections.abc import Sequence
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


def binding_outcome(
    proposed: DecisionOutcome, unevaluable_checks: Sequence[str]
) -> DecisionOutcome:
    """Force `CHALLENGE` when part of the binding evidence could not be evaluated.

    An unevaluable check means the system could not read the evidence, not that the
    evidence was bad. `REJECT` would record a genuine user as an attacker, which is not
    only wrong for them: §8.1's per-attack detection rates and the 6-class confusion
    matrix are computed from these outcomes, so every misfiled genuine capture corrupts
    the numbers the report is built on. `ACCEPT` would be worse -- it would pass a capture
    on evidence nobody read.

    `CHALLENGE` (retry with a fresh nonce, §5.5) is the honest third answer, and it is the
    outcome the challenge-response design already has for exactly this situation.

    **This guards `ACCEPT` only, and deliberately does not override `REJECT`.** Fusion has
    already routed the unevaluable-only case to `CHALLENGE` before reaching here, so a
    `REJECT` arriving with an unevaluable check attached was driven by *other* evidence
    that was read -- a failed B3, a quality failure, an injection score over threshold. A
    statically-injected stream has a flat illumination trace too, so overriding `REJECT`
    here would let an attacker convert a detected injection into a polite retry by making
    B6 unevaluable, which is exactly backwards.

    An attacker can still reach `CHALLENGE` by submitting a flat trace that nothing else
    indicts, but that is a loop they can never convert into an `ACCEPT`; it costs them
    attempts rather than buying them anything. The reason code stays in the receipt either
    way.
    """
    if unevaluable_checks and proposed == "ACCEPT":
        return "CHALLENGE"
    return proposed


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
