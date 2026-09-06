"""Every accuracy metric in PROJECT_SPEC.md §8.1, as pure functions over score arrays.

Owner: Abhijay

Score convention throughout this module matches `pqbio.detect.base.DetectorResult`:
0.0 = benign, 1.0 = attack, `decision = score >= threshold` means REJECT. "Accept" means
score < threshold.

Built and unit-tested (`tests/unit/test_bench_accuracy.py`, against synthetic score
distributions with an analytically known answer) before any real detector's scores are
run through it -- an explicit instruction for this build: verify the metric
implementations independently of whether the numbers they will eventually report are
good or bad. Three of six detectors (pad/deepfake/replay) don't exist and three of
four datasets are unlicensed (§6/§14) -- most cells these functions could fill are
`pqbio.bench._common.blocked(...)`, not because the functions are unfinished, but
because there is nothing real to hand them yet.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

import numpy as np
from sklearn.metrics import confusion_matrix as _sklearn_confusion_matrix
from sklearn.metrics import roc_auc_score, roc_curve


def apcer(attack_scores: Sequence[float], threshold: float) -> float:
    """Attack Presentation Classification Error Rate: fraction of attack samples
    incorrectly ACCEPTED (score < threshold, i.e. classified as bona fide)."""
    if not attack_scores:
        raise ValueError("apcer() needs at least one attack score")
    arr = np.asarray(attack_scores, dtype=float)
    return float(np.mean(arr < threshold))


def bpcer(genuine_scores: Sequence[float], threshold: float) -> float:
    """Bona fide Presentation Classification Error Rate: fraction of genuine samples
    incorrectly REJECTED (score >= threshold, i.e. classified as an attack)."""
    if not genuine_scores:
        raise ValueError("bpcer() needs at least one genuine score")
    arr = np.asarray(genuine_scores, dtype=float)
    return float(np.mean(arr >= threshold))


def acer(apcer_value: float, bpcer_value: float) -> float:
    return (apcer_value + bpcer_value) / 2.0


def eer(genuine_scores: Sequence[float], attack_scores: Sequence[float]) -> tuple[float, float]:
    """Equal Error Rate: the point where APCER(t) == BPCER(t), found by sweeping every
    achievable threshold and interpolating the crossing. Returns (eer, threshold).

    Genuine is the "positive"/label-1 class here for `roc_curve` purposes, with score
    negated (lower raw score = more genuine-like = "more positive"): fpr(t) then equals
    BPCER(t) (genuine wrongly rejected) and `1 - tpr(t)` equals APCER(t) (attack wrongly
    accepted), so their crossing is exactly EER by definition.
    """
    if not genuine_scores or not attack_scores:
        raise ValueError("eer() needs at least one genuine and one attack score")
    y_true = np.concatenate([np.ones(len(genuine_scores)), np.zeros(len(attack_scores))])
    y_score = -np.concatenate([np.asarray(genuine_scores), np.asarray(attack_scores)])
    fpr, tpr, thresholds = roc_curve(y_true, y_score)
    fnr = 1.0 - tpr
    # fpr rises, fnr falls (both monotone in a proper roc_curve) -- the crossing is
    # where their difference changes sign; interpolate between the two bracketing points.
    diff = fpr - fnr
    idx = int(np.nanargmin(np.abs(diff)))
    if idx == 0 or idx == len(diff) - 1 or diff[idx] == 0:
        eer_value = float((fpr[idx] + fnr[idx]) / 2.0)
        eer_threshold = float(-thresholds[idx])
    else:
        # linear interpolation between the bracketing pair for a smoother estimate
        lo, hi = (idx - 1, idx) if diff[idx - 1] * diff[idx] <= 0 else (idx, idx + 1)
        x0, x1 = diff[lo], diff[hi]
        frac = 0.0 if x1 == x0 else -x0 / (x1 - x0)
        eer_value = float(fpr[lo] + frac * (fpr[hi] - fpr[lo]))
        eer_threshold = float(-(thresholds[lo] + frac * (thresholds[hi] - thresholds[lo])))
    return eer_value, eer_threshold


def auc_roc(genuine_scores: Sequence[float], attack_scores: Sequence[float]) -> float:
    """Area under the ROC curve treating "attack" as the positive class (higher raw
    score = more attack-like, matching this project's score convention directly, no
    negation needed here unlike `eer`)."""
    if not genuine_scores or not attack_scores:
        raise ValueError("auc_roc() needs at least one genuine and one attack score")
    y_true = np.concatenate([np.zeros(len(genuine_scores)), np.ones(len(attack_scores))])
    y_score = np.concatenate([np.asarray(genuine_scores), np.asarray(attack_scores)])
    return float(roc_auc_score(y_true, y_score))


def tdr_at_far(
    genuine_scores: Sequence[float], attack_scores: Sequence[float], far_target: float = 0.01
) -> tuple[float, float]:
    """True Detection Rate at a fixed False Accept Rate: the fraction of GENUINE
    samples correctly accepted, at the threshold where the fraction of ATTACK samples
    incorrectly accepted (FAR, == APCER) equals `far_target`. Returns (tdr, achieved_far)
    -- `achieved_far` may differ slightly from `far_target` since it is interpolated
    from a finite, discrete score sample, not looked up in a continuous distribution.
    """
    if not genuine_scores or not attack_scores:
        raise ValueError("tdr_at_far() needs at least one genuine and one attack score")
    # genuine = positive class, score negated so "higher = more genuine-like" for
    # roc_curve's fpr/tpr convention -- see eer()'s docstring for the same trick.
    y_true = np.concatenate([np.ones(len(genuine_scores)), np.zeros(len(attack_scores))])
    y_score = -np.concatenate([np.asarray(genuine_scores), np.asarray(attack_scores)])
    fpr, tpr, _thresholds = roc_curve(y_true, y_score)
    # fpr here is exactly APCER(t) (attack accepted) by construction -- see eer()'s note.
    tdr_value = float(np.interp(far_target, fpr, tpr))
    return tdr_value, far_target


def mmpmr(contributor_matches: Sequence[Sequence[bool]]) -> float:
    """Mated Morph Presentation Match Rate (morph-only, §8.1). Each element of
    `contributor_matches` is one morph image's per-contributing-identity match/no-match
    outcomes; MMPMR is the fraction of morphs where at least one contributor matched --
    the morph "worked" if it fooled the system into accepting any of the people blended
    into it.
    """
    if not contributor_matches:
        raise ValueError("mmpmr() needs at least one morph's contributor results")
    return float(np.mean([any(row) for row in contributor_matches]))


def per_attack_detection_rate(
    scores_by_attack: Mapping[str, Sequence[float]], threshold: float
) -> dict[str, float]:
    """Fraction of each attack type's samples correctly detected (score >= threshold)
    at the deployed operating point -- one number per attack type in `scores_by_attack`.
    """
    result: dict[str, float] = {}
    for attack_type, scores in scores_by_attack.items():
        if not scores:
            raise ValueError(f"per_attack_detection_rate(): no scores for {attack_type!r}")
        arr = np.asarray(scores, dtype=float)
        result[attack_type] = float(np.mean(arr >= threshold))
    return result


# Reason codes that name an attack type, most specific first. Order IS the precedence:
# a decision carrying several is attributed to the first match here.
#
# The ordering principle is *specificity of attribution*, not severity. A detector that
# examined the media and named an attack type outranks a binding check that inferred one
# from protocol evidence, because the detector's answer is about what the sample IS while
# the binding check's is about what the sample FAILED TO DO.
ATTACK_CODE_PRECEDENCE: tuple[tuple[str, str], ...] = (
    # 1. Detector verdicts. Only injection exists this session; the other four slots are
    #    listed so the order is fixed before those detectors arrive rather than being
    #    decided ad hoc when they do (§6/§14 -- pad, morph, deepfake, replay are
    #    dataset-blocked).
    ("PAD_DETECTED", "presentation"),
    ("MORPH_DETECTED", "morph"),
    ("DEEPFAKE_DETECTED", "deepfake"),
    ("REPLAY_DETECTED", "replay"),
    ("INJECTION_DETECTED", "injection"),
    # 2. Binding-derived attributions. Resubmitted media is a replay by definition, and a
    #    stream that cannot answer a fresh challenge is §5.2's canonical replay signal.
    ("BIND_EVIDENCE_REUSE", "replay"),
    ("BIND_CHALLENGE_UNMET", "replay"),
)

# Codes that are rejections but name no attack class. Forcing these into one of the six
# would invent an attribution the system never made.
NON_ATTRIBUTING_REJECTION_CODES: frozenset[str] = frozenset(
    {
        "CRYPTO_AEAD_FAILED",
        "CRYPTO_MALFORMED_BUNDLE",
        "CRYPTO_DEVICE_SIG_INVALID",
        "BIND_CHALLENGE_FORGED",
        "BIND_EXPIRED",
        "BIND_NONCE_REPLAY",
        "BIND_COUNTER_REGRESSION",
        "BIND_DIGEST_MISMATCH",
        "QUALITY_INSUFFICIENT",
        "BIND_CHALLENGE_UNEVALUABLE",
    }
)


def predicted_attack_class(reason_codes: Sequence[str]) -> str | None:
    """Collapse a decision's reason codes to one 6-class label, or `None`.

    Since 2026-09-06 a rejected decision carries *every* code determined up to the
    rejection point, not only the triggering one (§14) -- which is what §8.1's per-attack
    rates needed, and which makes a single-label matrix ambiguous unless the collapse is
    defined. It is defined by `ATTACK_CODE_PRECEDENCE`, in that order.

    `None` means "rejected, but the system named no attack type": a forged signature, an
    expired challenge, a counter regression, a quality failure. Those are real rejections
    and belong in the report, but they are **not** one of the six classes and are counted
    separately by `classify_decisions` rather than being folded into the nearest-looking
    one. `BIND_CHALLENGE_UNEVALUABLE` is also `None` -- it is not a rejection at all
    (§14, 2026-09-04) and maps to CHALLENGE.

    `TRIGGER_PREFIX`-marked entries are ignored here: which code *ended* the request is a
    different question from which attack the system attributed it to, and the prefixed
    copy would otherwise double-count.
    """
    present = {c for c in reason_codes if not c.startswith("REJECTED_BY:")}
    for code, label in ATTACK_CODE_PRECEDENCE:
        if code in present:
            return label
    return None


def classify_decisions(
    decisions: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Map decisions to 6-class predicted labels, keeping the collapse auditable.

    Returns the per-decision labels alongside a tally of how often the collapse actually
    discarded a competing attribution. That tally is the point: a precedence order applied
    silently is indistinguishable from a bug, and if `multi_attribution_count` is large the
    matrix is hiding most of what the system found.

    Each decision needs `decision` and `reason_codes`.
    """
    labels: list[str | None] = []
    multi: list[dict[str, Any]] = []
    non_attributing = 0

    for d in decisions:
        codes = list(d.get("reason_codes", []))
        outcome = d.get("decision")
        if outcome != "REJECT":
            labels.append("bona_fide")
            continue
        matched = [
            label
            for code, label in ATTACK_CODE_PRECEDENCE
            if code in {c for c in codes if not c.startswith("REJECTED_BY:")}
        ]
        chosen = predicted_attack_class(codes)
        labels.append(chosen)
        if chosen is None:
            non_attributing += 1
        if len(set(matched)) > 1:
            multi.append({"chosen": chosen, "also_matched": sorted(set(matched) - {chosen})})

    return {
        "labels": labels,
        "multi_attribution_count": len(multi),
        "multi_attribution_detail": multi,
        "non_attributing_rejections": non_attributing,
        "precedence": [list(pair) for pair in ATTACK_CODE_PRECEDENCE],
        "note": (
            "Single-label collapse of multi-code decisions, by ATTACK_CODE_PRECEDENCE. "
            "Rejections naming no attack type are labelled None and counted in "
            "non_attributing_rejections -- they are excluded from the 6-class matrix "
            "rather than folded into the nearest class."
        ),
    }


def confusion_matrix_6class(
    true_labels: Sequence[str],
    predicted_labels: Sequence[str],
    classes: Sequence[str] = (
        "bona_fide",
        "presentation",
        "morph",
        "deepfake",
        "replay",
        "injection",
    ),
) -> dict[str, Any]:
    """6-class confusion matrix (bona fide + the 5 attack types), rows = true class,
    columns = predicted class, in `classes` order.
    """
    if len(true_labels) != len(predicted_labels):
        raise ValueError("true_labels and predicted_labels must be the same length")
    if not true_labels:
        raise ValueError("confusion_matrix_6class() needs at least one labelled sample")
    matrix = _sklearn_confusion_matrix(true_labels, predicted_labels, labels=list(classes))
    return {"labels": list(classes), "matrix": matrix.tolist()}


def det_curve_data(
    genuine_scores: Sequence[float], attack_scores: Sequence[float]
) -> dict[str, list[float]]:
    """DET curve data: paired (FAR, FRR) arrays swept across every achievable
    threshold, for `report.py` to plot (F1). FAR == APCER(t), FRR == BPCER(t) -- same
    convention as `eer()`.
    """
    if not genuine_scores or not attack_scores:
        raise ValueError("det_curve_data() needs at least one genuine and one attack score")
    y_true = np.concatenate([np.ones(len(genuine_scores)), np.zeros(len(attack_scores))])
    y_score = -np.concatenate([np.asarray(genuine_scores), np.asarray(attack_scores)])
    fpr, tpr, thresholds = roc_curve(y_true, y_score)
    return {
        "far": fpr.tolist(),  # APCER(t): attack wrongly accepted
        "frr": (1.0 - tpr).tolist(),  # BPCER(t): genuine wrongly rejected
        "thresholds": (-thresholds).tolist(),
    }


def detector_accuracy_report(
    genuine_scores: Sequence[float], attack_scores: Sequence[float], threshold: float
) -> dict[str, Any]:
    """Bundles apcer/bpcer/acer/eer/auc/tdr into the one dict T1/T2's per-detector rows
    need -- the single call site accuracy.json's writer uses per detector per dataset.
    """
    apcer_v = apcer(attack_scores, threshold)
    bpcer_v = bpcer(genuine_scores, threshold)
    eer_v, eer_threshold = eer(genuine_scores, attack_scores)
    tdr_v, far_achieved = tdr_at_far(genuine_scores, attack_scores, far_target=0.01)
    return {
        "n_genuine": len(genuine_scores),
        "n_attack": len(attack_scores),
        "threshold": threshold,
        "apcer": apcer_v,
        "bpcer": bpcer_v,
        "acer": acer(apcer_v, bpcer_v),
        "eer": eer_v,
        "eer_threshold": eer_threshold,
        "auc_roc": auc_roc(genuine_scores, attack_scores),
        "tdr_at_far_1pct": tdr_v,
        "far_achieved": far_achieved,
    }
