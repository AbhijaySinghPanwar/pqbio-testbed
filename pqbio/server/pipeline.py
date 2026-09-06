"""Pipeline orchestration: the eight stages, cheapest first, short-circuiting early
(PROJECT_SPEC.md §5.5).

Owner: Abhijay

**Deliberate extension beyond the literal stage numbering.** §5.5 names stages 3-6 as
needing to run off the event loop. This implementation offloads every stage (1-8) to a
thread pool, not just those four: this environment's PQC fallback backend (§14 —
liboqs isn't buildable here, so kyber-py/dilithium-py are the live backend) makes even
stage 1's ML-DSA verify and stage 8's ML-DSA sign take tens of milliseconds (see
`results/pqc_micro.json`), exactly the kind of per-request cost that would otherwise
block the event loop under concurrency. The "never blocked" DoD item would not
actually hold on this backend if only stages 3-6 were offloaded — offloading
uniformly is what keeps the guarantee genuinely true regardless of which backend is
active, not a deviation from the spec's intent.

**Missing-signal contract (Module D, fusion.py).** `pad.py`/`morph.py`/`deepfake.py`/
`replay.py` don't exist this session. This pipeline never scores them and never
defaults them to "benign" — they reach `fusion.FusionInput` as `None`, and every
missing one is named as `MISSING_SIGNAL_<NAME>` in the decision's `reason_codes`,
exactly the "reported as missing-signal rather than silently accepted" contract.

**Accept-path evidence recording.** `ctx.phash_index.record_accepted_bundle` is called
once, only when `decision_outcome == "ACCEPT"`, after fusion — never from the
reject/error paths (see `phash_index.py`'s own module docstring for why: recording a
rejected bundle would let an attacker poison the index with a victim's genuine media
under a garbage session).

**Receipt signing cost.** Backend-dependent by roughly three orders of magnitude, and
not optimised away either way: ML-DSA-65 signing measures ~79ms under the pure-Python
kyber-py/dilithium-py fallback versus ~0.11ms under liboqs (`results/pqc_micro.json`,
`results/pqc_micro_fallback.json`), which shows up here as a `sign_audit` stage of
~155ms versus ~5ms respectively. It appears in `stage_latency_ms`, but — for the reason
explained at `_decision_to_audit_json`'s call site below — only in the audit log's copy,
never inside the signed `Decision` itself; a signature cannot cover the duration of
computing itself.

**Short-circuit points**, matching §5.5's "fail fast" / "short-circuit if confident":
stage 1 (crypto) and stage 2 (binding B1-B5) reject immediately on any failure; stage 5
(evidence reuse) rejects immediately on a hit, the same way B1-B5 do (reused evidence is
as unambiguous a signal as a forged binding check); stage 4 skips stage 6 (the "heavy
models" — just `match` this session) when B6 fails or injection already looks
confidently like an attack, since there is no point computing an identity match for
evidence that's already going to be rejected on liveness/provenance grounds.
"""

from __future__ import annotations

import asyncio
import contextlib
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import TypeVar
from uuid import UUID

import numpy as np

from pqbio.binding.nonce import NonceStore
from pqbio.binding.phash_index import PhashIndex
from pqbio.binding.verify import (
    CheckResult,
    check_b1_challenge_signature,
    check_b2_expiry,
    check_b3_nonce_freshness,
    check_b4_counter,
    check_b5_capture_binding,
    check_b6_challenge_correlation,
    check_evidence_reuse,
)
from pqbio.capture.bundler import verify_bundle_signature
from pqbio.config import settings
from pqbio.detect.base import DetectorResult
from pqbio.detect.face import PreparedEvidence, prepare_evidence
from pqbio.detect.fusion import CascadeModel, FusionInput, FusionResult, fuse_cascade, fuse_rule
from pqbio.detect.injection import InjectionDetector
from pqbio.detect.match import MatchDetector
from pqbio.pqc.aead import AEADDecryptionError, decrypt
from pqbio.pqc.sign import Signer
from pqbio.schemas import Decision, EvidenceBundle, canonical_cbor_decode, sha256
from pqbio.server.decision import binding_outcome, build_and_sign_decision
from pqbio.server.store import AuditLog, SessionStore, SqliteKeyStore


@dataclass
class PipelineContext:
    keystore: SqliteKeyStore
    session_store: SessionStore
    nonce_store: NonceStore
    phash_index: PhashIndex
    audit_log: AuditLog
    signer: Signer
    server_pk: bytes
    server_sk: bytes
    injection_detector: InjectionDetector
    executor: ThreadPoolExecutor
    cascade_model: CascadeModel | None = None


TRIGGER_PREFIX = "REJECTED_BY:"
"""Marks which code actually caused a rejection, as distinct from codes merely observed.

A rejected decision now carries *everything determined up to the rejection point*, not
just the code that fired -- so `reason_codes` alone can no longer say which one ended the
request. Each triggering code also appears once more with this prefix. The bare code stays
in the list, so membership tests and metric consumers that look for `BIND_EVIDENCE_REUSE`
keep working unchanged; anything that needs the distinction reads the prefixed entries.
"""


class PipelineRejection(Exception):
    """Raised internally to short-circuit straight to a signed REJECT decision.

    Carries only the *triggering* codes. Everything the pipeline had already determined
    before this point is merged in by the handler -- see `_determined` below. Discarding
    those was a real defect: an injected bundle that also hit the reuse index was filed
    as `BIND_EVIDENCE_REUSE` alone, and the injection detector's positive result -- which
    had already been computed -- never reached §8.1's per-attack rates or the audit log
    (§14, 2026-09-05/06).
    """

    def __init__(self, reason_codes: list[str]) -> None:
        super().__init__(", ".join(reason_codes))
        self.reason_codes = reason_codes


_T = TypeVar("_T")


async def run_verify_pipeline(
    *,
    session_id: UUID,
    aead_nonce: bytes,
    ciphertext: bytes,
    ctx: PipelineContext,
) -> Decision:
    loop = asyncio.get_running_loop()
    stage_latency_ms: dict[str, float] = {}

    async def _run_stage(name: str, fn: Callable[..., _T], *args: object, **kwargs: object) -> _T:
        start = time.perf_counter()
        try:
            return await loop.run_in_executor(ctx.executor, lambda: fn(*args, **kwargs))
        finally:
            stage_latency_ms[name] = (time.perf_counter() - start) * 1000.0

    reason_codes: list[str] = []
    device_id = "unknown"

    # Everything determined so far, accumulated as each stage completes. On the success
    # path these are re-derived below from the same objects; on the rejection path they
    # are all that survives, and before 2026-09-06 none of it did. Cheapest-first
    # ordering is untouched -- nothing extra is computed, results already in hand are
    # simply not thrown away.
    determined_codes: list[str] = []
    determined_scores: dict[str, float] = {}

    try:
        # -------------------------------------------------------------------------
        # Stage 1: AEAD decrypt + ML-DSA verify -> fail fast
        # -------------------------------------------------------------------------
        def _stage1() -> tuple[EvidenceBundle, str, bytes]:
            k_c2s, _k_s2c = ctx.session_store.get_session_keys(session_id)
            try:
                plaintext = decrypt(k_c2s, aead_nonce, ciphertext, aad=b"")
            except AEADDecryptionError as exc:
                raise PipelineRejection(["CRYPTO_AEAD_FAILED"]) from exc
            try:
                candidate_bundle = EvidenceBundle.model_validate(canonical_cbor_decode(plaintext))
            except Exception as exc:
                raise PipelineRejection(["CRYPTO_MALFORMED_BUNDLE"]) from exc
            resolved_device_id = ctx.session_store.get_device_id(session_id)
            record = ctx.keystore.get(resolved_device_id)
            if not verify_bundle_signature(candidate_bundle, ctx.signer, record.sig_pk):
                raise PipelineRejection(["CRYPTO_DEVICE_SIG_INVALID"])
            return candidate_bundle, resolved_device_id, record.sig_pk

        bundle, device_id, _device_pk = await _run_stage("crypto", _stage1)

        # -------------------------------------------------------------------------
        # Stage 2: binding checks B1-B5 -> fail fast
        # -------------------------------------------------------------------------
        def _stage2() -> list[CheckResult]:
            now_ns = time.time_ns()
            return [
                check_b1_challenge_signature(bundle.challenge_echo, ctx.signer, ctx.server_pk),
                check_b2_expiry(bundle.challenge_echo, now_ns),
                check_b3_nonce_freshness(bundle.challenge_echo.nonce, ctx.nonce_store),
                check_b4_counter(bundle.device_id, bundle.counter, ctx.keystore),
                check_b5_capture_binding(bundle),
            ]

        checks_b1_5 = await _run_stage("binding_fail_fast", _stage2)
        determined_codes.extend(c.reason_code for c in checks_b1_5)
        failed_b1_5 = [c.reason_code for c in checks_b1_5 if not c.passed]
        if failed_b1_5:
            raise PipelineRejection(failed_b1_5)

        # -------------------------------------------------------------------------
        # Stage 3: quality gate + face detect/align
        # -------------------------------------------------------------------------
        prepared_evidence: PreparedEvidence = await _run_stage(
            "quality_face", prepare_evidence, bundle
        )
        if not prepared_evidence.quality.passed:
            determined_codes.append("QUALITY_INSUFFICIENT")

        # -------------------------------------------------------------------------
        # Stage 4: cheap signals (injection heuristics, challenge correlation B6)
        # -> short-circuit stage 6 if confident
        # -------------------------------------------------------------------------
        def _stage4() -> tuple[CheckResult, DetectorResult]:
            b6_result = check_b6_challenge_correlation(bundle)
            injection_score_result = ctx.injection_detector.score(prepared_evidence)
            return b6_result, injection_score_result

        b6, injection_result = await _run_stage("cheap_signals", _stage4)
        determined_codes.append(b6.reason_code)
        determined_scores["injection"] = injection_result.score
        if injection_result.decision:
            determined_codes.append("INJECTION_DETECTED")
        # `b6.evaluable and not b6.passed`, NOT plain `not b6.passed`. An unevaluable B6
        # reports passed=False (the two-state view is fail-closed), and treating that as a
        # confident reject skipped stage 6 -- so an impostor submitting a capture whose
        # illumination trace happened to be unmeasurable was never scored by `match`, and
        # came out as CHALLENGE with MISSING_SIGNAL_MATCH. That is a "cannot measure"
        # outcome skipping a detector that could have produced a positive detection, which
        # is the masking rule's exact prohibition (§14, 2026-09-05).
        b6_failed_evaluably = b6.evaluable and not b6.passed
        confident_reject = b6_failed_evaluably or injection_result.decision

        # -------------------------------------------------------------------------
        # Stage 5: evidence-reuse pHash check -> fail fast (as unambiguous as B1-B5)
        # -------------------------------------------------------------------------
        reuse_check = await _run_stage(
            "evidence_reuse", check_evidence_reuse, bundle, ctx.phash_index
        )
        determined_codes.append(reuse_check.reason_code)
        if not reuse_check.passed:
            raise PipelineRejection([reuse_check.reason_code])

        # -------------------------------------------------------------------------
        # Stage 6: heavy models (this session: match only) -- skipped on confident_reject
        # -------------------------------------------------------------------------
        match_score: float | None = None
        if not confident_reject:

            def _stage6() -> float | None:
                template_bytes = ctx.keystore.get_face_template(device_id)
                if template_bytes is None or not prepared_evidence.quality.passed:
                    return None
                enrolled = np.frombuffer(template_bytes, dtype=np.float32)
                detector = MatchDetector(enrolled_template=enrolled)
                return detector.score(prepared_evidence).score

            match_score = await _run_stage("heavy_models", _stage6)
            if match_score is not None:
                determined_scores["match"] = match_score
        else:
            stage_latency_ms["heavy_models"] = 0.0  # skipped by the stage-4 short-circuit

        # -------------------------------------------------------------------------
        # Stage 7: fusion + policy
        # -------------------------------------------------------------------------
        def _stage7() -> tuple[FusionResult, FusionInput]:
            c1, c2, c3, c4, c5 = checks_b1_5
            binding_flags: tuple[bool, bool, bool, bool, bool, bool] = (
                c1.passed,
                c2.passed,
                c3.passed,
                c4.passed,
                c5.passed,
                b6.passed,
            )
            # B6 is the only check that can be unevaluable; B1-B5 are deterministic
            # predicates that are always decidable on a well-formed bundle.
            unevaluable = tuple(c.check for c in (*checks_b1_5, b6) if not c.evaluable)
            fusion_input = FusionInput(
                match_score=match_score,
                pad_score=None,
                morph_score=None,
                deepfake_score=None,
                replay_score=None,
                injection_score=injection_result.score,
                quality_passed=prepared_evidence.quality.passed,
                binding_flags=binding_flags,
                n_frames=len(bundle.frame_meta),
                binding_unevaluable=unevaluable,
            )
            strategy = settings.detect.fusion.strategy
            fusion_result = (
                fuse_rule(fusion_input)
                if strategy == "rule"
                else fuse_cascade(fusion_input, model=ctx.cascade_model)
            )
            return fusion_result, fusion_input

        fusion_result, fusion_input = await _run_stage("fusion", _stage7)

        reason_codes = (
            [c.reason_code for c in checks_b1_5]
            + [b6.reason_code, reuse_check.reason_code]
            + [f"MISSING_SIGNAL_{name.upper()}" for name in fusion_input.missing_signals]
            + fusion_result.reasons
        )
        detector_scores = {"injection": injection_result.score}
        if match_score is not None:
            detector_scores["match"] = match_score

        # An unevaluable binding check can never come out as REJECT: the evidence was
        # not read, so there is nothing to reject on. See decision.binding_outcome.
        decision_outcome = binding_outcome(fusion_result.decision, fusion_input.binding_unevaluable)
        fused_score = fusion_result.fused_score

        # -------------------------------------------------------------------------
        # Record accepted evidence into the reuse index -- accept-path only (Module C's
        # phash_index.py module docstring: recording a rejected bundle would let an
        # attacker poison the index with a victim's genuine media under a garbage
        # session, causing the victim's own later real capture to be refused as
        # "reused"). This is what makes the N-of-burst mitigation (§14) actually take
        # effect in a live server rather than only being reachable in tests.
        # -------------------------------------------------------------------------
        if decision_outcome == "ACCEPT":
            await _run_stage(
                "record_evidence",
                ctx.phash_index.record_accepted_bundle,
                str(session_id),
                bundle.frames,
            )
            # B4 ("device counter strictly greater than last seen") is deliberately
            # read-only in verify.py -- advancing belongs here, the accept path, for the
            # same reason phash recording does: a check that mutated state on a bundle
            # later rejected by some other check would burn the counter for nothing.
            # Known limitation, not fixed here: this read-then-write has a TOCTOU race
            # against a second concurrent accepted request for the same device (B4's
            # check and this advance aren't one atomic statement, unlike nonce.py's
            # single-UPDATE consume) -- SqliteKeyStore.update_counter raises ValueError
            # on a regression rather than corrupting state, so the race fails loud
            # rather than silently, but does not yet resolve to a clean reason code.
            # The ValueError is recorded, not merely swallowed. Suppressing it kept the
            # decision honest (the request really was accepted) but left the failed
            # advance invisible to the audit log -- a determined outcome dropped before
            # reaching the decision object, which is the same defect class as the
            # discarded reason codes above (§14, 2026-09-06).
            try:
                await _run_stage(
                    "advance_counter", ctx.keystore.update_counter, device_id, bundle.counter
                )
            except ValueError:
                reason_codes.append("COUNTER_ADVANCE_RACE")
        else:
            stage_latency_ms["record_evidence"] = 0.0
            stage_latency_ms["advance_counter"] = 0.0

    except PipelineRejection as rejection:
        # Merge, never replace. The triggering codes come first and are additionally
        # marked with TRIGGER_PREFIX, so "what ended this request" stays recoverable now
        # that "what was known about it" is also present. `dict.fromkeys` dedupes while
        # preserving order -- a triggering code is already in `determined_codes` when the
        # stage that raised had recorded it first.
        reason_codes = list(
            dict.fromkeys(
                [*rejection.reason_codes, *determined_codes]
                + [f"{TRIGGER_PREFIX}{code}" for code in rejection.reason_codes]
            )
        )
        detector_scores = determined_scores
        decision_outcome = "REJECT"
        fused_score = 1.0

    decision = await _run_stage(
        "sign_audit",
        build_and_sign_decision,
        session_id=session_id,
        decision=decision_outcome,
        fused_score=fused_score,
        reason_codes=reason_codes,
        detector_scores=detector_scores,
        stage_latency_ms=dict(stage_latency_ms),
        signer=ctx.signer,
        server_sk=ctx.server_sk,
    )

    frame_hashes = []
    with contextlib.suppress(Exception):
        frame_hashes = [sha256(f).hex() for f in bundle.frames]
        # bundle never decoded (stage 1 failed) -- nothing to hash, suppressed above

    # `stage_latency_ms` now includes "sign_audit" (the finally-block in `_run_stage`
    # recorded it once the call above returned) even though the SIGNED `decision` object
    # embeds only the snapshot taken before that entry existed -- a receipt cannot report
    # the duration of its own signing without re-signing itself, which just pushes the
    # same problem out one more level. The audit record is plaintext, not signed, so it
    # has no such constraint; it gets the complete breakdown, sign_audit included, so the
    # receipt-signing cost the DoD asked to be recorded is captured somewhere real.
    await _run_stage(
        "audit_write",
        ctx.audit_log.record,
        session_id=session_id,
        device_id=device_id,
        decision_json=_decision_to_audit_json(decision, dict(stage_latency_ms)),
        frame_hashes=frame_hashes,
    )

    return decision


def _decision_to_audit_json(decision: Decision, stage_latency_ms: dict[str, float]) -> str:
    """`Decision.model_dump_json()` raises on `receipt_signature` (raw bytes aren't
    valid UTF-8) — pydantic's default JSON encoding assumes text-decodable bytes.
    Audit storage isn't a signing operation, so a plain hex-for-bytes JSON rendering
    is enough; no need for canonical CBOR here. `stage_latency_ms` overrides the
    decision's own (necessarily incomplete, see call site) field with the full breakdown.
    """
    import json

    data = decision.model_dump(mode="python")
    data["session_id"] = str(data["session_id"])
    data["receipt_signature"] = data["receipt_signature"].hex()
    data["stage_latency_ms"] = stage_latency_ms
    return json.dumps(data)
