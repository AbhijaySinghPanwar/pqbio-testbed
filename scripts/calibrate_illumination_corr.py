"""Derive `binding.illumination_corr_min` (B6's threshold) from measured data.

Owner: Abhijay

The 0.70 default was set against the pre-2026-09-02 formulation, in which
`measure_chromaticity_trace` returned absolute per-channel brightness and B6 correlated
it against raw palette RGB. Both sides of that comparison have changed — the trace is now
luminance-normalised chromaticity and the correlation is channel-centred — so the old
number does not carry over. It has to be re-derived or it is meaningless.

This script does not invent data. It consumes:

* **Real positives and a real negative** from `results/live_challenge_check.json` — the
  per-frame traces of every repeat of every capture condition, including the
  `locked_no_render_control` pass, which is a genuine no-cast capture taken on the same
  sensor in the same room seconds apart. That control is the most honest negative
  available: it is what B6 sees when nothing satisfies the challenge.
* **Wrong-nonce negatives** — each measured trace scored against the sequence a
  *different* nonce derives. This is the attack B6 exists to stop: an adversary who
  replays a capture made under some other challenge. It reuses real sensor data, so it
  carries the real noise, unlike anything synthesised.
* **Synthetic no-cast negatives** — traces with a plausible static scene chromaticity
  plus sensor noise and no induced modulation. These probe the null distribution more
  densely than six real control runs can, and are labelled as synthetic in the output.

Usage:
    python scripts/calibrate_illumination_corr.py
    python scripts/calibrate_illumination_corr.py --live results/live_challenge_check.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import numpy as np

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from pqbio.bench._common import run_metadata, write_json  # noqa: E402
from pqbio.binding.verify import (  # noqa: E402
    _channel_centred_pearson,
    _expand_expected_trace,
)
from pqbio.capture.challenge import derive_illumination_sequence  # noqa: E402
from pqbio.config import settings  # noqa: E402

SEED = 2026
RENDERED_CONDITIONS = ("locked_render", "unlocked_render", "wb_locked_ae_auto_render")
CONTROL_CONDITION = "locked_no_render_control"


def _score(trace: list[float], sequence: list[int]) -> float:
    return _channel_centred_pearson(trace, _expand_expected_trace(sequence, len(trace) // 3))


def _wrong_nonce_sequences(true_sequence: list[int], steps: int, n: int) -> list[list[int]]:
    """Sequences a *different* nonce derives. Skips any that collide with the true one —
    with 4 steps over a 4-colour palette there are only 256 possibilities, so collisions
    happen and scoring one as a negative would be mislabelling it.
    """
    out: list[list[int]] = []
    rng = np.random.default_rng(SEED)
    while len(out) < n:
        nonce = rng.integers(0, 256, size=32, dtype=np.uint8).tobytes()
        seq = derive_illumination_sequence(nonce, steps)
        if seq != true_sequence:
            out.append(seq)
    return out


def _synthetic_no_cast_traces(n_frames: int, n: int) -> list[list[float]]:
    """Static scene chromaticity + sensor noise, no induced modulation.

    Scene bias and noise scale are taken from the live capture's own range rather than
    picked: real rooms in that data sat around r=0.35-0.48, and per-frame chromaticity
    jitter was of order 1e-3 to 5e-3.
    """
    rng = np.random.default_rng(SEED + 1)
    traces: list[list[float]] = []
    for _ in range(n):
        base = rng.uniform([0.33, 0.30, 0.15], [0.48, 0.40, 0.32])
        base = base / base.sum()
        noise_scale = float(rng.uniform(0.001, 0.005))
        frames = base[None, :] + rng.normal(0.0, noise_scale, size=(n_frames, 3))
        frames = np.clip(frames, 1e-6, None)
        frames = frames / frames.sum(axis=1, keepdims=True)
        traces.append([float(v) for v in frames.ravel()])
    return traces


def _separation(positives: list[float], negatives: list[float]) -> dict[str, Any]:
    """Threshold-independent separation, plus the best threshold and its margins.

    Reports Cohen's d and AUC because a mean difference alone says nothing when the
    spread is this wide, and the whole question here is whether a threshold *can* be set.
    """
    pos, neg = np.asarray(positives, float), np.asarray(negatives, float)
    pooled = float(np.sqrt((pos.var(ddof=1) + neg.var(ddof=1)) / 2)) if len(pos) > 1 else 0.0
    cohens_d = float((pos.mean() - neg.mean()) / pooled) if pooled > 0 else 0.0
    auc = float((pos[:, None] > neg[None, :]).mean() + 0.5 * (pos[:, None] == neg[None, :]).mean())

    # Sweep every threshold the data can distinguish and keep the one with the best
    # Youden J. Fail-closed matters more than convenience, so FPR is reported alongside.
    candidates = np.unique(np.concatenate([pos, neg]))
    best: dict[str, Any] = {"threshold": None, "youden_j": -2.0}
    for t in candidates:
        tpr = float((pos >= t).mean())
        fpr = float((neg >= t).mean())
        j = tpr - fpr
        if j > best["youden_j"]:
            best = {"threshold": float(t), "youden_j": float(j), "tpr": tpr, "fpr": fpr}

    zero_fpr = [float(t) for t in candidates if (neg >= t).mean() == 0.0]
    return {
        "n_positive": len(pos),
        "n_negative": len(neg),
        "positive_mean": float(pos.mean()),
        "positive_std": float(pos.std(ddof=1)) if len(pos) > 1 else None,
        "positive_min": float(pos.min()),
        "negative_mean": float(neg.mean()),
        "negative_std": float(neg.std(ddof=1)) if len(neg) > 1 else None,
        "negative_max": float(neg.max()),
        "cohens_d": cohens_d,
        "auc": auc,
        "best_youden": best,
        "lowest_zero_fpr_threshold": min(zero_fpr) if zero_fpr else None,
        "separable": bool(pos.min() > neg.max()),
    }


def calibrate(live_path: Path) -> dict[str, Any]:
    live = json.loads(live_path.read_text(encoding="utf-8"))
    # The live file records the step count it actually ran with, which may differ
    # from config: --steps exists precisely to measure how B6 behaves as a function
    # of it. Trusting config here would silently mis-derive every expected trace.
    steps = int(live.get("illumination_steps", settings.binding.illumination_steps))
    true_sequence = derive_illumination_sequence(bytes.fromhex(live["nonce_hex"]), steps)

    out: dict[str, Any] = {
        **run_metadata(seed=SEED),
        "source_live_check": str(live_path.resolve().relative_to(REPO_ROOT)).replace("\\", "/"),
        "source_live_check_generated_at": live["generated_at_utc"],
        "illumination_steps": steps,
        "previous_threshold": 0.70,
        "previous_threshold_note": (
            "set against the pre-2026-09-02 formulation (absolute per-channel brightness "
            "vs raw palette RGB); carries no information about the current one"
        ),
        "by_weighting": {},
    }

    for weighting in ("uniform", "centre"):
        positives: list[float] = []
        per_condition: dict[str, list[float]] = {}
        for cond in RENDERED_CONDITIONS:
            vals = [
                run["by_weighting"][weighting]["correlation_b6_even_split"]
                for run in live["passes"][cond]
            ]
            per_condition[cond] = vals
            positives.extend(vals)

        real_negatives = [
            run["by_weighting"][weighting]["correlation_b6_even_split"]
            for run in live["passes"][CONTROL_CONDITION]
        ]

        wrong_nonce: list[float] = []
        n_frames_seen = 0
        for cond in (*RENDERED_CONDITIONS, CONTROL_CONDITION):
            for run in live["passes"][cond]:
                trace = run["by_weighting"][weighting]["per_frame_trace"]
                n_frames_seen = len(trace) // 3
                for seq in _wrong_nonce_sequences(true_sequence, steps, 8):
                    wrong_nonce.append(_score(trace, seq))

        synthetic = [
            _score(t, true_sequence) for t in _synthetic_no_cast_traces(n_frames_seen or 36, 200)
        ]

        all_negatives = real_negatives + wrong_nonce + synthetic
        out["by_weighting"][weighting] = {
            "positives_by_condition": {
                c: {
                    "n": len(v),
                    "mean": float(np.mean(v)),
                    "std": float(np.std(v, ddof=1)) if len(v) > 1 else None,
                }
                for c, v in per_condition.items()
            },
            "negatives": {
                "real_no_render_control": {
                    "n": len(real_negatives),
                    "mean": float(np.mean(real_negatives)),
                    "max": float(np.max(real_negatives)),
                },
                "wrong_nonce_on_real_traces": {
                    "n": len(wrong_nonce),
                    "mean": float(np.mean(wrong_nonce)),
                    "p95": float(np.percentile(wrong_nonce, 95)),
                    "max": float(np.max(wrong_nonce)),
                },
                "synthetic_no_cast": {
                    "n": len(synthetic),
                    "mean": float(np.mean(synthetic)),
                    "p95": float(np.percentile(synthetic, 95)),
                    "max": float(np.max(synthetic)),
                    "synthetic": True,
                },
            },
            "separation_all_negatives": _separation(positives, all_negatives),
            "separation_vs_wrong_nonce_only": _separation(positives, wrong_nonce),
            "separation_best_condition": _separation(
                per_condition["unlocked_render"], all_negatives
            ),
        }

    def operating_point(weighting: str, threshold: float) -> dict[str, Any]:
        """What a candidate threshold actually costs, on measured data only."""
        block = out["by_weighting"][weighting]
        pos = [
            v
            for cond in RENDERED_CONDITIONS
            for v in [
                run["by_weighting"][weighting]["correlation_b6_even_split"]
                for run in live["passes"][cond]
            ]
        ]
        neg_real = [
            run["by_weighting"][weighting]["correlation_b6_even_split"]
            for run in live["passes"][CONTROL_CONDITION]
        ]
        wn = block["negatives"]["wrong_nonce_on_real_traces"]
        return {
            "threshold": threshold,
            "tpr_all_rendered": float(np.mean([v >= threshold for v in pos])),
            "tpr_best_condition": float(
                np.mean(
                    [
                        run["by_weighting"][weighting]["correlation_b6_even_split"] >= threshold
                        for run in live["passes"]["unlocked_render"]
                    ]
                )
            ),
            "fpr_real_control": float(np.mean([v >= threshold for v in neg_real])),
            "wrong_nonce_p95": wn["p95"],
            "wrong_nonce_max": wn["max"],
            "margin_above_wrong_nonce_max": float(threshold - wn["max"]),
        }

    uniform_d = out["by_weighting"]["uniform"]["separation_all_negatives"]["cohens_d"]
    centre_d = out["by_weighting"]["centre"]["separation_all_negatives"]["cohens_d"]
    chosen = "uniform" if uniform_d >= centre_d else "centre"
    out["weighting_choice"] = {
        "chosen": chosen,
        "uniform_cohens_d": uniform_d,
        "centre_cohens_d": centre_d,
        "basis": (
            "Cohen's d of rendered captures against all negatives, measured on "
            f"{live['repeats']} repeats per condition. Chosen on this number, not on "
            "preference: the 4x4 regional diagnostic that motivated the centre-weighted "
            "variant showed a much larger per-cell swing, but a larger swing in the "
            "signal is not the same as better separation once the periphery's noise is "
            "dropped along with its signal."
        ),
    }

    chosen_block = out["by_weighting"][chosen]
    zero_fpr = chosen_block["separation_all_negatives"]["lowest_zero_fpr_threshold"]
    out["recommendation"] = {
        "weighting": chosen,
        "illumination_corr_min": zero_fpr,
        "basis": (
            "lowest threshold with zero false accepts across every measured negative: "
            f"{chosen_block['negatives']['real_no_render_control']['n']} real no-render "
            f"controls, {chosen_block['negatives']['wrong_nonce_on_real_traces']['n']} "
            "wrong-nonce scorings of real sensor traces, and "
            f"{chosen_block['negatives']['synthetic_no_cast']['n']} synthetic no-cast "
            "traces. Chosen on false-accept rate rather than on Youden J because B6 is "
            "one of six ANDed binding checks: a false reject costs a retry, a false "
            "accept is the security failure the check exists to prevent (CLAUDE.md, "
            "'Fail closed')."
        ),
        "at_zero_fpr": operating_point(chosen, zero_fpr) if zero_fpr is not None else None,
        "at_0_70_legacy": operating_point(chosen, 0.70),
        "interim": True,
        "interim_reason": (
            "Derived from one session, one room, one sensor, with no subject at capture "
            "distance -- the §6 consent blocker that also blocks the replay corpus. The "
            "positive class is 18 captures across 3 lock conditions, not a population. "
            "Re-derive from the consented recording session; this value is a floor "
            "chosen to fail closed, not a characterised operating point."
        ),
        "effective_sample_size_finding": (
            "B6's correlation has roughly `illumination_steps` effective samples per "
            "channel, not one per frame: frames within a step are near-identical, so "
            "capturing more of them narrows nothing. That is why the null distribution "
            "is so wide at the spec'd 4 steps, and it is a property of §5.2's challenge "
            "design rather than of the threshold. Measured directly by re-running the "
            "live check at 16 steps (results/live_challenge_check_16step.json): the "
            "wrong-nonce negative tail falls from p95 0.577 / max 0.673 to p95 0.213 / "
            "max 0.360 under uniform weighting. Raising the step count -- not lowering "
            "the threshold -- is what buys B6 a usable operating point."
        ),
    }
    return out


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--live", type=Path, default=REPO_ROOT / "results" / "live_challenge_check.json"
    )
    parser.add_argument(
        "--out", type=Path, default=REPO_ROOT / "results" / "illumination_corr_calibration.json"
    )
    args = parser.parse_args()

    if not args.live.exists():
        raise SystemExit(
            f"{args.live} not found. Run scripts/live_challenge_check.py first — this "
            "script calibrates against measured sensor data and will not fabricate any."
        )

    result = calibrate(args.live)
    write_json(args.out, result)

    for weighting, block in result["by_weighting"].items():
        sep = block["separation_all_negatives"]
        print(
            f"{weighting:<8} pos={sep['positive_mean']:+.3f}+/-{sep['positive_std']:.3f} "
            f"neg={sep['negative_mean']:+.3f}+/-{sep['negative_std']:.3f} "
            f"d={sep['cohens_d']:.2f} auc={sep['auc']:.3f} "
            f"separable={sep['separable']}"
        )
    rec = result["recommendation"]
    print(f"\nweighting chosen: {rec['weighting']}")
    print(f"recommended illumination_corr_min: {rec['illumination_corr_min']}")
    if rec["at_zero_fpr"]:
        op = rec["at_zero_fpr"]
        print(
            f"  at that threshold: TPR(all rendered)={op['tpr_all_rendered']:.2f} "
            f"TPR(best condition)={op['tpr_best_condition']:.2f} "
            f"margin over worst wrong-nonce negative={op['margin_above_wrong_nonce_max']:+.3f}"
        )
    print(f"  INTERIM: {rec['interim']}")
    print(f"wrote {args.out}")


if __name__ == "__main__":
    main()
