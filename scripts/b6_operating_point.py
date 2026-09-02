"""Find B6's operating point: step-count sweep, TPR/FAR tables, AND-chain calibration.

Owner: Abhijay

**The calibration on 2026-09-02 was set the wrong way round.** It drove B6's false-accept
rate to zero and accepted whatever true-positive rate fell out (0.33). That is the correct
reasoning for a check standing alone and the wrong reasoning for one link in an AND chain.
Six ANDed checks *compound* false rejects — a genuine capture must clear all six — and
*suppress* false accepts, since an attacker must clear all six. So each link should be
calibrated strict on TPR and permissive on FAR, which is the inverse of what was done.

Concretely: at TPR 0.33, B6 alone rejects two thirds of genuine verifications and becomes
the dominant term in system BPCER (§8.1). No threshold repairs that at 4 challenge steps,
because B6's correlation has roughly `illumination_steps` effective samples per channel
however many frames are captured (§14, 2026-09-02). The step count is the lever.

This script sweeps the step count against a fixed frame budget, reports TPR and FAR across
a full threshold sweep for each, and derives the threshold from a stated system-BPCER
target rather than from FAR=0.

Negatives are the same three classes the 2026-09-02 calibration used, for comparability:
real no-render controls, wrong-nonce scorings of real traces, and synthetic no-cast traces.

Usage (needs a camera and a display; captures no biometric data, retains no frames):
    python scripts/b6_operating_point.py --repeats 8
    python scripts/b6_operating_point.py --steps 4,8,12,16 --repeats 8
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

import numpy as np

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from live_challenge_check import (  # noqa: E402
    WEIGHTINGS,
    _capture_pass,
    _open_camera,
)

from pqbio.bench._common import run_metadata, write_json  # noqa: E402
from pqbio.binding.verify import (  # noqa: E402
    _channel_centred_pearson,
    _expand_expected_trace,
)
from pqbio.capture.challenge import derive_illumination_sequence  # noqa: E402

SEED = 2026
DEFAULT_NONCE_HEX = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"

# Rendered conditions are positives (the challenge really was displayed); the no-render
# pass is a real negative. `challenge_setpoint` is §14's untested protocol proposal.
CONDITIONS: tuple[tuple[str, str, bool], ...] = (
    ("locked_render", "full", True),
    ("unlocked_render", "none", True),
    ("wb_locked_ae_auto_render", "wb_only", True),
    ("challenge_setpoint_render", "challenge_setpoint", True),
    ("no_render_control", "full", False),
)
POSITIVE_CONDITIONS = tuple(name for name, _, render in CONDITIONS if render)
CONTROL_CONDITION = "no_render_control"

# The six binding checks of §5.3. Only B6 is statistical; see `and_chain_targets`.
N_BINDING_CHECKS = 6
STATISTICAL_CHECKS = 1


def _score(trace: list[float], sequence: list[int]) -> float:
    return _channel_centred_pearson(trace, _expand_expected_trace(sequence, len(trace) // 3))


def _wrong_nonce_sequences(true_sequence: list[int], steps: int, n: int) -> list[list[int]]:
    """Sequences a *different* nonce derives — the replay B6 exists to stop."""
    out: list[list[int]] = []
    rng = np.random.default_rng(SEED)
    while len(out) < n:
        nonce = rng.integers(0, 256, size=32, dtype=np.uint8).tobytes()
        seq = derive_illumination_sequence(nonce, steps)
        if seq != true_sequence:
            out.append(seq)
    return out


def _synthetic_no_cast_traces(n_frames: int, n: int) -> list[list[float]]:
    """Static scene chromaticity plus sensor noise, no induced modulation."""
    rng = np.random.default_rng(SEED + 1)
    traces: list[list[float]] = []
    for _ in range(n):
        base = rng.uniform([0.33, 0.30, 0.15], [0.48, 0.40, 0.32])
        base = base / base.sum()
        frames = base[None, :] + rng.normal(0.0, float(rng.uniform(0.001, 0.005)), (n_frames, 3))
        frames = np.clip(frames, 1e-6, None)
        frames = frames / frames.sum(axis=1, keepdims=True)
        traces.append([float(v) for v in frames.ravel()])
    return traces


def and_chain_targets(system_bpcer_targets: tuple[float, ...]) -> dict[str, Any]:
    """Per-check TPR required for a target *system* BPCER across the AND chain.

    Two readings, and the difference between them matters:

    * **Naive**: all six checks are statistical and independent, so system TPR = t**6 and
      a per-check t of 0.95**(1/6) = 0.9915 is needed for 5% system BPCER.
    * **Actual**: B1-B5 are deterministic. A genuine, unexpired, correctly-signed bundle
      with a fresh nonce, an advancing counter and a recomputing digest passes all five
      with probability 1 — they have no operating point to set. So the entire BPCER
      budget lands on B6, and its required TPR is the system target itself: 0.95 for 5%.

    The actual reading is the *stricter* one and is what this script calibrates against.
    Reporting both is the point: the naive reading is what "six ANDed checks" suggests at
    a glance, and it happens to be close enough (0.9915 vs 0.95) that the distinction
    changes little here — but it would matter a great deal once other statistical checks
    join the chain, so the reasoning is recorded rather than the number alone.
    """
    return {
        "n_checks": N_BINDING_CHECKS,
        "n_statistical_checks": STATISTICAL_CHECKS,
        "deterministic_checks": ["B1", "B2", "B3", "B4", "B5"],
        "statistical_checks": ["B6"],
        "rationale": (
            "B1-B5 are deterministic predicates on a genuine bundle (valid server "
            "signature, within expiry, unconsumed nonce, advancing counter, recomputing "
            "digest) and reject genuine traffic only when something is actually wrong. "
            "They carry no BPCER budget, so B6 absorbs all of it and its required TPR is "
            "the system target itself, not the sixth root of it."
        ),
        "targets": [
            {
                "system_bpcer": t,
                "required_b6_tpr_actual": 1.0 - t,
                "required_per_check_tpr_if_all_six_were_statistical": float((1.0 - t) ** (1 / 6)),
            }
            for t in system_bpcer_targets
        ],
    }


def bpcer_upper_bound(n_positive: int, n_rejected: int, confidence: float = 0.95) -> float:
    """One-sided Clopper-Pearson upper bound on BPCER given `n_rejected` of `n_positive`.

    Needed because "TPR = 1.00" on eight captures is not evidence of a 5% BPCER, and
    quoting it as though it were would be the same category of error as the FAR=0
    calibration this script exists to correct. With 8/8 successes the upper bound is
    1 - 0.05**(1/8) = 0.312: the data is consistent with a true BPCER of 31%.

    Demonstrating BPCER <= 5% at 95% confidence needs ~59 consecutive clean captures
    (0.95**59 = 0.048). That is a consented-session-scale experiment, not a desk one.
    """
    if n_positive == 0:
        return 1.0
    if n_rejected == 0:
        return float(1.0 - (1.0 - confidence) ** (1.0 / n_positive))
    from scipy.stats import beta

    return float(beta.ppf(confidence, n_rejected + 1, n_positive - n_rejected))


def threshold_table(
    positives: list[float], negatives: list[float], grid: np.ndarray
) -> list[dict[str, float]]:
    pos, neg = np.asarray(positives, float), np.asarray(negatives, float)
    return [
        {
            "threshold": float(t),
            "tpr": float((pos >= t).mean()),
            "far": float((neg >= t).mean()),
        }
        for t in grid
    ]


def pick_operating_point(
    table: list[dict[str, float]], required_tpr: float
) -> dict[str, Any] | None:
    """Highest threshold that still meets the TPR floor — i.e. the least permissive
    setting compatible with the BPCER budget. TPR is the binding constraint; the FAR that
    results is reported, not minimised.
    """
    feasible = [row for row in table if row["tpr"] >= required_tpr]
    if not feasible:
        return None
    best = max(feasible, key=lambda r: r["threshold"])
    return {**best, "required_tpr": required_tpr}


def two_sided_operating_point(
    positives: list[float], negatives: list[float], grid: np.ndarray
) -> dict[str, Any]:
    """The threshold with margin on *both* sides, not the extreme one that just meets a
    TPR floor.

    `pick_operating_point` returns the highest threshold still meeting the BPCER budget,
    which by construction sits right on top of the lowest genuine capture — a setting with
    no headroom for a slightly worse day. When the classes separate completely, the
    defensible choice is the midpoint of the gap: it maximises the smaller of the two
    margins. When they overlap there is no such point, and this says so rather than
    inventing one.
    """
    pos, neg = np.asarray(positives, float), np.asarray(negatives, float)
    pos_min, neg_max = float(pos.min()), float(neg.max())
    separable = pos_min > neg_max
    if not separable:
        return {
            "separable": False,
            "positive_min": pos_min,
            "negative_max": neg_max,
            "overlap": neg_max - pos_min,
            "threshold": None,
        }
    midpoint = (pos_min + neg_max) / 2.0
    # Snap to the reporting grid so the shipped config value is a round number that
    # appears verbatim in the tables, rather than a 15-digit float nobody can check.
    candidates = [float(t) for t in grid if neg_max < t < pos_min]
    chosen = min(candidates, key=lambda t: abs(t - midpoint)) if candidates else midpoint
    return {
        "separable": True,
        "positive_min": pos_min,
        "negative_max": neg_max,
        "gap": pos_min - neg_max,
        "midpoint": midpoint,
        "threshold": chosen,
        "tpr": float((pos >= chosen).mean()),
        "far": float((neg >= chosen).mean()),
        "margin_below": chosen - neg_max,
        "margin_above": pos_min - chosen,
    }


def analyse(
    runs: dict[str, list[dict[str, Any]]], steps: int, weighting: str, threshold_grid: np.ndarray
) -> dict[str, Any]:
    """Score one step count under one region weighting.

    Operating points are computed **per capture condition as well as pooled**, and the
    per-condition ones are what matter. A deployment runs one capture protocol; pooling
    four of them into the positive class means calibrating against the average of
    protocols we have already measured and rejected, which drags the achievable TPR down
    to a threshold no sane deployment would use. The pooled numbers are kept only so the
    difference between the two framings stays visible.

    Raw per-run correlations and per-frame traces are persisted, not just summaries: the
    first version of this script kept summaries only, and recomputing anything then needed
    the hardware and the room back.
    """
    per_condition = {
        cond: [run["by_weighting"][weighting]["correlation_b6_even_split"] for run in runs[cond]]
        for cond, _, _ in CONDITIONS
    }
    positives = [v for cond in POSITIVE_CONDITIONS for v in per_condition[cond]]
    real_negatives = per_condition[CONTROL_CONDITION]

    true_sequence = runs[POSITIVE_CONDITIONS[0]][0]["_sequence"]
    wrong_nonce: list[float] = []
    n_frames_seen = 0
    for cond, _, _ in CONDITIONS:
        for run in runs[cond]:
            trace = run["by_weighting"][weighting]["per_frame_trace"]
            n_frames_seen = len(trace) // 3
            for seq in _wrong_nonce_sequences(true_sequence, steps, 8):
                wrong_nonce.append(_score(trace, seq))
    synthetic = [
        _score(t, true_sequence) for t in _synthetic_no_cast_traces(n_frames_seen or 36, 200)
    ]
    all_negatives = real_negatives + wrong_nonce + synthetic

    return {
        "n_positive_pooled": len(positives),
        "n_negative": len(all_negatives),
        "positive_mean": float(np.mean(positives)),
        "positive_std": float(np.std(positives, ddof=1)),
        "negative_mean": float(np.mean(all_negatives)),
        "negative_std": float(np.std(all_negatives, ddof=1)),
        "wrong_nonce_p95": float(np.percentile(wrong_nonce, 95)),
        "wrong_nonce_max": float(np.max(wrong_nonce)),
        "per_condition_mean": {c: float(np.mean(v)) for c, v in per_condition.items()},
        "per_condition_std": {
            c: float(np.std(v, ddof=1)) if len(v) > 1 else None for c, v in per_condition.items()
        },
        "per_condition_values": per_condition,
        "negatives": {
            "real_no_render_control": real_negatives,
            "wrong_nonce_on_real_traces": wrong_nonce,
            "synthetic_no_cast": synthetic,
        },
        "threshold_table_pooled": threshold_table(positives, all_negatives, threshold_grid),
        "threshold_table_by_condition": {
            cond: threshold_table(per_condition[cond], all_negatives, threshold_grid)
            for cond in POSITIVE_CONDITIONS
        },
        "threshold_table_vs_wrong_nonce_only": {
            cond: threshold_table(per_condition[cond], wrong_nonce, threshold_grid)
            for cond in POSITIVE_CONDITIONS
        },
        "per_frame_traces": {
            cond: [run["by_weighting"][weighting]["per_frame_trace"] for run in runs[cond]]
            for cond, _, _ in CONDITIONS
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--camera-index", type=int, default=0)
    parser.add_argument("--steps", default="4,8,12,16")
    parser.add_argument("--step-ms", type=int, default=200, help="§5.2's spec'd step duration")
    parser.add_argument("--repeats", type=int, default=8)
    parser.add_argument("--exposure", type=int, default=-1)
    parser.add_argument("--gain", type=int, default=128)
    parser.add_argument("--windowed", action="store_true")
    parser.add_argument("--nonce-hex", default=DEFAULT_NONCE_HEX)
    parser.add_argument(
        "--out", type=Path, default=REPO_ROOT / "results" / "b6_operating_point.json"
    )
    parser.add_argument(
        "--reanalyse",
        type=Path,
        default=None,
        help="recompute the derived blocks from a previous run's persisted raw values "
        "instead of capturing again. The raw per-run correlations and per-frame traces "
        "are in the JSON precisely so a threshold can be re-derived without the camera, "
        "the room and the lighting back.",
    )
    args = parser.parse_args()

    step_counts = [int(x) for x in args.steps.split(",")]
    nonce = bytes.fromhex(args.nonce_hex)
    threshold_grid = np.round(np.arange(0.0, 1.0, 0.02), 3)

    by_steps: dict[str, Any] = {}

    if args.reanalyse is not None:
        import json as _json

        prior = _json.loads(args.reanalyse.read_text(encoding="utf-8"))
        by_steps = prior["by_steps"]
        args.nonce_hex = prior["nonce_hex"]
        args.repeats = prior["repeats_per_condition"]
        _finish(args, by_steps, threshold_grid)
        return

    cap = _open_camera(args.camera_index)
    try:
        for steps in step_counts:
            sequence = derive_illumination_sequence(nonce, steps)
            runs: dict[str, list[dict[str, Any]]] = {name: [] for name, _, _ in CONDITIONS}
            for rep in range(args.repeats):
                for name, lock, render in CONDITIONS:
                    print(
                        f"steps={steps:<3} repeat {rep + 1}/{args.repeats}  {name}",
                        file=sys.stderr,
                    )
                    run = _capture_pass(cap, sequence, args, lock=lock, render=render)
                    run["_sequence"] = sequence
                    runs[name].append(run)

            by_steps[str(steps)] = {
                "illumination_steps": steps,
                "step_ms": args.step_ms,
                "capture_wall_time_s": steps * args.step_ms / 1000.0,
                "median_frames_captured": float(
                    np.median([r["n_frames"] for rs in runs.values() for r in rs])
                ),
                "by_weighting": {w: analyse(runs, steps, w, threshold_grid) for w in WEIGHTINGS},
            }
    finally:
        cap.release()

    _finish(args, by_steps, threshold_grid)


def _finish(args: argparse.Namespace, by_steps: dict[str, Any], threshold_grid: np.ndarray) -> None:
    targets = and_chain_targets((0.01, 0.05, 0.10))
    required = {t["system_bpcer"]: t["required_b6_tpr_actual"] for t in targets["targets"]}

    operating_points: dict[str, Any] = {}
    for steps_key, block in by_steps.items():
        operating_points[steps_key] = {
            w: {
                "pooled": {
                    str(bpcer): pick_operating_point(
                        block["by_weighting"][w]["threshold_table_pooled"], tpr
                    )
                    for bpcer, tpr in required.items()
                },
                "by_condition": {
                    cond: {
                        str(bpcer): pick_operating_point(
                            block["by_weighting"][w]["threshold_table_by_condition"][cond], tpr
                        )
                        for bpcer, tpr in required.items()
                    }
                    for cond in POSITIVE_CONDITIONS
                },
            }
            for w in WEIGHTINGS
        }

    # Best protocol and step count, chosen on measured two-sided margin.
    two_sided: dict[str, Any] = {}
    for steps_key, block in by_steps.items():
        two_sided[steps_key] = {}
        for w in WEIGHTINGS:
            b = block["by_weighting"][w]
            negatives = (
                b["negatives"]["real_no_render_control"]
                + b["negatives"]["wrong_nonce_on_real_traces"]
                + b["negatives"]["synthetic_no_cast"]
            )
            two_sided[steps_key][w] = {
                cond: two_sided_operating_point(
                    b["per_condition_values"][cond], negatives, threshold_grid
                )
                for cond in POSITIVE_CONDITIONS
            }

    # Rank by two-sided margin, then prefer the CHEAPEST step count whose margin is
    # within measurement noise of the best. Margin alone would pick the largest step count
    # every time; with 8 positives at sigma ~= 0.06 the standard error of a margin estimate
    # is ~0.02, so a 0.01 advantage is not an advantage. Capture wall time is real:
    # illumination_steps * illumination_step_ms, paid by every user on every verification.
    MARGIN_NOISE_TOLERANCE = 0.02

    ranked: list[dict[str, Any]] = []
    for steps_key, by_w in two_sided.items():
        for w, by_cond in by_w.items():
            for cond, op in by_cond.items():
                if not op["separable"]:
                    continue
                ranked.append(
                    {
                        "illumination_steps": int(steps_key),
                        "weighting": w,
                        "capture_condition": cond,
                        "illumination_corr_min": op["threshold"],
                        "min_margin": min(op["margin_below"], op["margin_above"]),
                        "capture_wall_time_s": int(steps_key) * args.step_ms / 1000.0,
                        "operating_point": op,
                    }
                )
    ranked.sort(key=lambda r: -r["min_margin"])

    best: dict[str, Any] | None = None
    if ranked:
        top_margin = ranked[0]["min_margin"]
        within_noise = [r for r in ranked if r["min_margin"] >= top_margin - MARGIN_NOISE_TOLERANCE]
        # Cheapest capture first; break remaining ties on the larger margin.
        within_noise.sort(key=lambda r: (r["capture_wall_time_s"], -r["min_margin"]))
        best = dict(within_noise[0])
        best["selection_rule"] = (
            f"cheapest capture among operating points within {MARGIN_NOISE_TOLERANCE} of the "
            f"best two-sided margin ({top_margin:.3f}); margin standard error with "
            f"{args.repeats} positives is approximately 0.02, so smaller differences are "
            "not resolvable by this data"
        )
        op = best["operating_point"]
        n_pos = args.repeats
        n_rejected = int(round((1.0 - op["tpr"]) * n_pos))
        best["evidence_strength"] = {
            "n_positive_captures": n_pos,
            "n_rejected": n_rejected,
            "measured_tpr": op["tpr"],
            "bpcer_upper_bound_95pct": bpcer_upper_bound(n_pos, n_rejected),
            "captures_needed_for_5pct_bpcer_at_95pct_confidence": 59,
            "caveat": (
                "measured TPR of 1.00 on this many captures does NOT demonstrate the 5% "
                "system BPCER target -- the 95% upper bound on BPCER is far above it. The "
                "threshold is derived to meet the target; the evidence bounds it only "
                "loosely. One room, one sensor, no subject at capture distance."
            ),
        }
        best["runners_up"] = [
            {
                k: r[k]
                for k in ("illumination_steps", "weighting", "capture_condition", "min_margin")
            }
            for r in ranked[:6]
        ]

    result = {
        **run_metadata(seed=SEED),
        "nonce_hex": args.nonce_hex,
        "two_sided_operating_points": two_sided,
        "recommendation": best,
        "repeats_per_condition": args.repeats,
        "conditions": [c[0] for c in CONDITIONS],
        "positive_conditions": list(POSITIVE_CONDITIONS),
        "control_condition": CONTROL_CONDITION,
        "and_chain": targets,
        "by_steps": by_steps,
        "operating_points": operating_points,
        "note": (
            "Calibrated strict on TPR and permissive on FAR, the inverse of the "
            "2026-09-02 derivation. Rationale in `and_chain`: six ANDed checks compound "
            "false rejects and suppress false accepts, and five of the six are "
            "deterministic, so B6 carries the whole system BPCER budget. Captures no "
            "biometric data and retains no frames -- per-frame region colour means only."
        ),
    }
    write_json(args.out, result)

    for steps_key, block in by_steps.items():
        for w in WEIGHTINGS:
            b = block["by_weighting"][w]
            print(f"--- steps={steps_key} {w}  wrong-nonce p95={b['wrong_nonce_p95']:.3f}")
            for cond in POSITIVE_CONDITIONS:
                op = operating_points[steps_key][w]["by_condition"][cond]["0.05"]
                op_txt = (
                    f"thr={op['threshold']:.2f} far={op['far']:.2f}"
                    if op
                    else "NONE (TPR 0.95 unreachable)"
                )
                print(
                    f"      {cond:<28} {b['per_condition_mean'][cond]:+.3f}"
                    f"+/-{b['per_condition_std'][cond]:.3f}  @BPCER5%: {op_txt}"
                )
    if best is not None:
        op = best["operating_point"]
        print(
            f"\nRECOMMENDED: steps={best['illumination_steps']} "
            f"weighting={best['weighting']} protocol={best['capture_condition']}\n"
            f"  illumination_corr_min={best['illumination_corr_min']:.2f}  "
            f"TPR={op['tpr']:.2f} FAR={op['far']:.4f}  "
            f"margins: below {op['margin_below']:+.3f} / above {op['margin_above']:+.3f}"
        )
    else:
        print("\nNO separable operating point at any step count -- reporting that, not tuning.")
    print(f"wrote {args.out}")


if __name__ == "__main__":
    main()
