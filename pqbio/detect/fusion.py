"""D6 fusion and policy engine (PROJECT_SPEC.md §5.4).

Owner: Abhijay

**Scope note, not hidden in a docstring corner — read before trusting any number this
module produces.** The full fusion input per spec is
`[match, pad, morph, deepfake, replay, injection, quality, binding_flags, n_frames]`.
This session implements `match.py`, `injection.py`, the six binding checks (Module C),
and the quality gate (`face.py`) — `pad.py`/`morph.py`/`deepfake.py`/`replay.py` are
dataset-blocked and were deliberately not built (see CLAUDE.md). A missing detector
score is represented as `None` ("not run"), never defaulted to `0.0` ("verified
benign") — defaulting an unrun check to benign would silently overstate confidence.
Every `FusionResult` below carries `missing_signals` naming exactly what wasn't
available, and every result JSON this module writes repeats the caveat. Numbers here
characterise how well the *available* signals (injection provenance, binding, quality)
separate the synthetic injection corpus — not system-wide ACER, which needs the missing
four detectors and real datasets (§6) to mean anything.

**Two strategies, per §5.4 D6:**
1. **Rule baseline** — reject if any available detector score exceeds its threshold, or
   quality failed, or any binding check failed. No training needed.
2. **Cascade** — binding/quality/injection first (cheap), short-circuit REJECT on a
   confident hit; a logistic regression over the surviving scores otherwise (the "heavy
   models" stage — pad/morph/deepfake/replay — is a documented no-op this session: there
   is nothing to run on survivors). The logistic regression is fit on the injection
   corpus (the only labelled data available), so it only ever sees
   {injection_score, quality_pass, binding_flags} as features; `match`'s coefficient is
   untrained (no labelled impostor data exists yet) and excluded from the fitted model,
   clearly flagged in the training result.

**Policy layer**, applied identically after either strategy produces a `fused_score`:
`ACCEPT` below `accept_max`, `REJECT` at/above `reject_min`, `CHALLENGE` in between
(§5.4: three outcomes, `CHALLENGE` steps up with a fresh nonce).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

import numpy as np

from pqbio.config import DEFAULT_CONFIG_PATH, settings

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_CASCADE_MODEL_PATH = REPO_ROOT / "models" / "fusion_cascade_lr.json"


def _git_commit() -> str:
    try:
        out = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, stderr=subprocess.DEVNULL
        )
        return out.decode().strip()
    except Exception:
        return "unknown (not a git repository at run time)"


def _config_hash() -> str:
    return hashlib.sha256(DEFAULT_CONFIG_PATH.read_bytes()).hexdigest()


Decision = Literal["ACCEPT", "REJECT", "CHALLENGE"]

# Cascade's logistic-regression stage: features it was (or will be) fit on. match_score
# is deliberately excluded — see module docstring.
CASCADE_FEATURE_NAMES = [
    "injection_score",
    "quality_failed",
    "b1_ok",
    "b2_ok",
    "b3_ok",
    "b4_ok",
    "b5_ok",
    "b6_ok",
]


@dataclass(frozen=True)
class FusionInput:
    match_score: float | None
    pad_score: float | None
    morph_score: float | None
    deepfake_score: float | None
    replay_score: float | None
    injection_score: float | None
    quality_passed: bool
    binding_flags: tuple[bool, bool, bool, bool, bool, bool]  # B1..B6
    n_frames: int
    binding_unevaluable: tuple[str, ...] = ()
    """Binding checks that could not be evaluated, as distinct from evaluated and failed.

    Same contract as the `None` detector scores above: never benign, never an attack. A
    check in here reads `False` in `binding_flags` (that vector is fail-closed and cannot
    express a third state), so fusion must consult this before treating a `False` flag as
    evidence of an attack. B6 is currently the only check that can appear here — see
    `pqbio.binding.verify.check_b6_evaluable`.
    """

    @property
    def missing_signals(self) -> list[str]:
        names = ["match", "pad", "morph", "deepfake", "replay", "injection"]
        values = [
            self.match_score,
            self.pad_score,
            self.morph_score,
            self.deepfake_score,
            self.replay_score,
            self.injection_score,
        ]
        missing = [n for n, v in zip(names, values, strict=True) if v is None]
        # An unevaluable binding check is a missing signal in exactly the sense this
        # property means: something the pipeline could not measure, which must not be
        # scored as either outcome.
        missing.extend(f"binding_{c}" for c in self.binding_unevaluable)
        return missing

    @property
    def has_unevaluable_binding(self) -> bool:
        return bool(self.binding_unevaluable)


@dataclass(frozen=True)
class FusionResult:
    strategy: Literal["rule", "cascade"]
    fused_score: float
    decision: Decision
    reasons: list[str]
    missing_signals: list[str] = field(default_factory=list)


def _thresholds() -> dict[str, float]:
    t = settings.detect.thresholds
    return {
        "match": 1.0 - t.match_cosine_min,
        "pad": t.pad,
        "morph": t.morph,
        "deepfake": t.deepfake,
        "replay": t.replay,
        "injection": t.injection,
    }


def fuse_rule(x: FusionInput) -> FusionResult:
    """Reject if any *available* detector exceeds its threshold, quality failed, or any
    binding check failed. The rule strategy never returns CHALLENGE on its own — the
    policy layer (`decide_policy`) is what can turn a borderline fused_score into one.
    """
    thresholds = _thresholds()
    reasons: list[str] = []
    triggered = False

    scored = {
        "match": x.match_score,
        "pad": x.pad_score,
        "morph": x.morph_score,
        "deepfake": x.deepfake_score,
        "replay": x.replay_score,
        "injection": x.injection_score,
    }
    for name, score in scored.items():
        if score is not None and score >= thresholds[name]:
            reasons.append(f"{name}_score {score:.3f} >= threshold {thresholds[name]:.3f}")
            triggered = True

    if not x.quality_passed:
        reasons.append("QUALITY_INSUFFICIENT")
        triggered = True

    binding_codes = ["B1", "B2", "B3", "B4", "B5", "B6"]
    for code, ok in zip(binding_codes, x.binding_flags, strict=True):
        if code in x.binding_unevaluable:
            # Recorded, never counted as a trigger. Treating "could not measure" as an
            # attack is what sent genuine users out as BIND_CHALLENGE_UNMET (§14).
            reasons.append(f"binding check {code} could not be evaluated")
            continue
        if not ok:
            reasons.append(f"binding check {code} failed")
            triggered = True

    if not reasons:
        reasons.append("no detector, quality, or binding check triggered")

    fused_score = 1.0 if triggered else 0.0
    if triggered:
        decision = decide_policy(fused_score).decision
    elif x.has_unevaluable_binding:
        # Nothing indicted this capture, but part of the evidence could not be read.
        # Neither ACCEPT (unverified) nor REJECT (not an attacker) is honest: ask again.
        decision = "CHALLENGE"
        fused_score = 0.5
    else:
        decision = decide_policy(fused_score).decision
    return FusionResult(
        strategy="rule",
        fused_score=fused_score,
        decision=decision,
        reasons=reasons,
        missing_signals=x.missing_signals,
    )


@dataclass(frozen=True)
class CascadeModel:
    """A fitted logistic regression: `coefficients` aligned to CASCADE_FEATURE_NAMES,
    plus `intercept`. Trained by `train_cascade_model`.
    """

    coefficients: list[float]
    intercept: float

    def predict_proba(self, x: FusionInput) -> float:
        features = _cascade_features(x)
        z = self.intercept + sum(c * f for c, f in zip(self.coefficients, features, strict=True))
        return float(1.0 / (1.0 + np.exp(-z)))

    def to_json(self) -> dict[str, Any]:
        return {
            "coefficients": self.coefficients,
            "intercept": self.intercept,
            "feature_names": CASCADE_FEATURE_NAMES,
        }

    @classmethod
    def from_json(cls, d: dict[str, Any]) -> CascadeModel:
        return cls(coefficients=list(d["coefficients"]), intercept=float(d["intercept"]))


def _cascade_features(x: FusionInput) -> list[float]:
    """Feature vector for the cascade's logistic-regression stage.

    An unevaluable binding check encodes as 1.0 ("as if it passed") rather than 0.0
    because 0.0 is the trained model's signal for *failed*, and a capture that could not
    be measured is not evidence of failure. In practice the model never sees one:
    `fuse_cascade` returns CHALLENGE before scoring when anything is unevaluable. This
    keeps the encoding honest for any caller that reaches the features directly.
    """
    return [
        x.injection_score if x.injection_score is not None else 0.0,
        0.0 if x.quality_passed else 1.0,
        *[
            1.0 if (ok or code in x.binding_unevaluable) else 0.0
            for code, ok in zip(["B1", "B2", "B3", "B4", "B5", "B6"], x.binding_flags, strict=True)
        ],
    ]


def fuse_cascade(x: FusionInput, model: CascadeModel | None = None) -> FusionResult:
    """Cheap checks first: any failed binding check, or quality failure, short-circuits
    a confident REJECT without needing the (nonexistent, this session) heavy models.
    Otherwise, if a trained `CascadeModel` is available, its logistic regression scores
    the survivor; if not, falls back to the injection score alone (or 0.0 if that's
    also missing), clearly flagged in `reasons` — not silently treated as benign.
    """
    reasons: list[str] = []

    if not x.quality_passed:
        return FusionResult(
            "cascade", 1.0, "REJECT", ["QUALITY_INSUFFICIENT (short-circuit)"], x.missing_signals
        )
    for code, ok in zip(["B1", "B2", "B3", "B4", "B5", "B6"], x.binding_flags, strict=True):
        if code in x.binding_unevaluable:
            continue  # cannot short-circuit a REJECT on evidence that was never read
        if not ok:
            return FusionResult(
                "cascade",
                1.0,
                "REJECT",
                [f"binding check {code} failed (short-circuit)"],
                x.missing_signals,
            )
    if x.injection_score is not None and x.injection_score >= _thresholds()["injection"]:
        reasons.append(f"injection_score {x.injection_score:.3f} >= threshold (short-circuit)")
        return FusionResult("cascade", 1.0, "REJECT", reasons, x.missing_signals)

    # Only now. An unevaluable binding check means part of the evidence could not be read
    # -- it must not mask evidence that WAS read: a statically-injected stream also has a
    # flat illumination trace, so ordering this before the injection check would have
    # turned a detected attack into a polite retry (caught by
    # tests/security/test_server_adversary_classes.py::test_a6_...).
    if x.has_unevaluable_binding:
        return FusionResult(
            "cascade",
            0.5,
            "CHALLENGE",
            [
                "binding checks "
                + ", ".join(x.binding_unevaluable)
                + " could not be evaluated and nothing else indicted this capture; "
                "retry with a fresh nonce"
            ],
            x.missing_signals,
        )

    if model is not None:
        fused_score = model.predict_proba(x)
        reasons.append("survived cheap checks; scored by the trained cascade logistic regression")
    else:
        fused_score = x.injection_score if x.injection_score is not None else 0.0
        reasons.append(
            "survived cheap checks; no trained cascade model available, falling back to "
            "the injection score alone"
        )

    decision = decide_policy(fused_score).decision
    return FusionResult("cascade", fused_score, decision, reasons, x.missing_signals)


@dataclass(frozen=True)
class PolicyDecision:
    decision: Decision
    fused_score: float


def decide_policy(
    fused_score: float, accept_max: float = 0.3, reject_min: float = 0.7
) -> PolicyDecision:
    """ACCEPT below accept_max, REJECT at/above reject_min, CHALLENGE in between."""
    if fused_score >= reject_min:
        return PolicyDecision("REJECT", fused_score)
    if fused_score < accept_max:
        return PolicyDecision("ACCEPT", fused_score)
    return PolicyDecision("CHALLENGE", fused_score)


# ----------------------------------------------------------------------------------
# Training / comparison on the injection corpus
# ----------------------------------------------------------------------------------


def train_cascade_model(
    manifest_path: Path, *, injection_model_path: Path | None = None, seed: int = 2026
) -> CascadeModel:
    """Fit the cascade's logistic-regression stage on the injection corpus. Only
    {injection_score, quality_failed=0, binding_flags} are meaningful features here
    (see module docstring) — `sklearn`'s LogisticRegression on a small, low-dimensional
    feature set, exactly what §5.4 D6 calls for at the cascade's final stage.

    Uses `InjectionDetector` (the already-trained GBM, if `injection_model_path` points
    at one) to get each sample's actual injection score — the same score the cascade
    would see at inference time, not a re-derivation from raw features.
    """
    from sklearn.linear_model import LogisticRegression

    from pqbio.detect.face import prepared_evidence_bundle_only
    from pqbio.detect.injection import InjectionDetector, _load_corpus, _read_bundle

    samples = _load_corpus(manifest_path)
    injection_detector = InjectionDetector(model_path=injection_model_path)

    x_rows: list[list[float]] = []
    y: list[int] = []
    for s in samples:
        bundle = _read_bundle(s.bundle_path)
        evidence = prepared_evidence_bundle_only(bundle)
        injection_score = injection_detector.score(evidence).score
        fusion_input = FusionInput(
            match_score=None,
            pad_score=None,
            morph_score=None,
            deepfake_score=None,
            replay_score=None,
            injection_score=injection_score,
            quality_passed=True,  # synthetic corpus frames never run face.py's real gate
            binding_flags=(True, True, True, True, True, True),
            n_frames=len(bundle.frame_meta),
        )
        x_rows.append(_cascade_features(fusion_input))
        y.append(s.label)

    x = np.array(x_rows)
    y_arr = np.array(y)
    clf = LogisticRegression(max_iter=1000, random_state=seed)
    clf.fit(x, y_arr)
    return CascadeModel(coefficients=clf.coef_[0].tolist(), intercept=float(clf.intercept_[0]))


def compare_strategies_on_corpus(
    manifest_path: Path,
    *,
    injection_model_path: Path | None = None,
    cascade_model: CascadeModel | None = None,
    results_out: Path = REPO_ROOT / "results" / "detectors" / "fusion" / "results.json",
) -> dict[str, Any]:
    """Run both strategies over every injection-corpus sample and report accuracy —
    §5.4 DoD: "both fusion strategies implemented and compared", scoped to the one
    labelled dataset available this session.
    """
    from pqbio.detect.face import prepared_evidence_bundle_only
    from pqbio.detect.injection import InjectionDetector, _load_corpus, _read_bundle

    samples = _load_corpus(manifest_path)
    injection_detector = InjectionDetector(model_path=injection_model_path)

    rows: list[dict[str, Any]] = []
    for s in samples:
        bundle = _read_bundle(s.bundle_path)
        evidence = prepared_evidence_bundle_only(bundle)
        injection_result = injection_detector.score(evidence)

        fusion_input = FusionInput(
            match_score=None,
            pad_score=None,
            morph_score=None,
            deepfake_score=None,
            replay_score=None,
            injection_score=injection_result.score,
            quality_passed=True,
            binding_flags=(True, True, True, True, True, True),
            n_frames=len(bundle.frame_meta),
        )
        rule_result = fuse_rule(fusion_input)
        cascade_result = fuse_cascade(fusion_input, model=cascade_model)
        rows.append(
            {
                "bundle_path": str(s.bundle_path.relative_to(REPO_ROOT)),
                "label": "injection_tier1" if s.label == 1 else "bona_fide",
                "rule_decision": rule_result.decision,
                "cascade_decision": cascade_result.decision,
                "rule_fused_score": rule_result.fused_score,
                "cascade_fused_score": cascade_result.fused_score,
            }
        )

    def accuracy(decision_key: str) -> float:
        correct = 0
        for row in rows:
            predicted_attack = row[decision_key] == "REJECT"
            actual_attack = row["label"] == "injection_tier1"
            if predicted_attack == actual_attack:
                correct += 1
        return correct / len(rows) if rows else 0.0

    result = {
        "git_commit": _git_commit(),
        "config_hash_sha256": _config_hash(),
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "scope_note": (
            "Only match/injection/binding/quality signals exist this session — "
            "pad/morph/deepfake/replay are dataset-blocked and not built. Both "
            "strategies are compared on the injection corpus only (provenance "
            "detection), not full system ACER. See pqbio/detect/fusion.py's module "
            "docstring."
        ),
        "n_samples": len(rows),
        "rule_accuracy": accuracy("rule_decision"),
        "cascade_accuracy": accuracy("cascade_decision"),
        "cascade_model_trained": cascade_model is not None,
        "rows": rows,
    }
    results_out.parent.mkdir(parents=True, exist_ok=True)
    results_out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--manifest",
        type=Path,
        default=REPO_ROOT / "data" / "manifests" / "injection_corpus_manifest.json",
    )
    parser.add_argument("--injection-model", type=Path, default=None)
    parser.add_argument("--cascade-model-out", type=Path, default=DEFAULT_CASCADE_MODEL_PATH)
    parser.add_argument(
        "--results-out",
        type=Path,
        default=REPO_ROOT / "results" / "detectors" / "fusion" / "results.json",
    )
    parser.add_argument("--no-train-cascade", action="store_true")
    args = parser.parse_args()

    cascade_model = None
    if not args.no_train_cascade:
        cascade_model = train_cascade_model(
            args.manifest, injection_model_path=args.injection_model
        )
        args.cascade_model_out.parent.mkdir(parents=True, exist_ok=True)
        args.cascade_model_out.write_text(
            json.dumps(cascade_model.to_json(), indent=2) + "\n", encoding="utf-8"
        )
        print(f"wrote {args.cascade_model_out}", file=sys.stderr)

    result = compare_strategies_on_corpus(
        args.manifest,
        injection_model_path=args.injection_model,
        cascade_model=cascade_model,
        results_out=args.results_out,
    )
    print(json.dumps({k: v for k, v in result.items() if k != "rows"}, indent=2), file=sys.stderr)


if __name__ == "__main__":
    main()
