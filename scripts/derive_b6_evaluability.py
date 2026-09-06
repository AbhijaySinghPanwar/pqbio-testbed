"""Derive B6's evaluability precondition from captures already held.

Owner: Abhijay

B6 has an operating envelope and, until now, no way to tell whether it was inside it. The
sweep and the live check disagreed (+0.775 ± 0.035 versus +0.077 ± 0.455 for the same
condition) because they sampled different physics: one room where the display materially
modulated the scene, one where it contributed ~1.5% of scene light. In the second, B6 was
producing a number with nothing behind it and the verifier was thresholding that number as
though it meant something — so a genuine user came out as `BIND_CHALLENGE_UNMET`, an
attack code.

This picks the precondition, from measurement rather than intuition. It re-uses persisted
data only and captures nothing: `results/b6_operating_point.json` (the step-count sweep's
per-frame traces), `results/live_challenge_check.json`, and
`results/b6_operating_window.json` (the only source that also holds clipping fraction and
screen contribution).

Three candidates were named; **one survives**. See `results/b6_evaluability.json` and
PROJECT_SPEC.md §14 (2026-09-04) for the two that were dropped and why.

Usage:
    python scripts/derive_b6_evaluability.py
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

from pqbio.bench._common import blocked, run_metadata, write_json  # noqa: E402
from pqbio.config import settings  # noqa: E402

SEED = 2026
# Floors considered. Coarse on purpose: a floor picked to more precision than the data
# supports is a floor tuned to this sample.
FLOOR_GRID = (0.0005, 0.0010, 0.0012, 0.0015, 0.0018, 0.0020, 0.0022, 0.0025, 0.0030)


def _trace_spread(trace: list[float]) -> float:
    """Mean per-channel standard deviation of a chromaticity trace across frames.

    This is B6's signal amplitude. A trace that does not move cannot correlate with
    anything, and the challenge's whole premise is that it makes the trace move.
    """
    return float(np.asarray(trace, dtype=float).reshape(-1, 3).std(axis=0).mean())


def _collect() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Every held capture, split into rendered (a challenge really was displayed) and
    no-render controls.

    Rendered captures are the population that matters: they are genuine users, and the
    ones among them that fail the correlation are exactly who is being mislabelled today.
    """
    rendered: list[dict[str, Any]] = []
    control: list[dict[str, Any]] = []
    threshold = settings.binding.illumination_corr_min

    sweep = json.loads((REPO_ROOT / "results" / "b6_operating_point.json").read_text("utf-8"))
    for steps, block in sweep["by_steps"].items():
        b = block["by_weighting"]["uniform"]
        for cond, traces in b["per_frame_traces"].items():
            for trace, r in zip(traces, b["per_condition_values"][cond], strict=True):
                row = {
                    "source": f"sweep/steps={steps}/{cond}",
                    "spread": _trace_spread(trace),
                    "correlation": r,
                    "passed_correlation": r >= threshold,
                }
                (control if cond == "no_render_control" else rendered).append(row)

    live = json.loads((REPO_ROOT / "results" / "live_challenge_check.json").read_text("utf-8"))
    for cond, runs in live["passes"].items():
        for run in runs:
            e = run["by_weighting"]["uniform"]
            r = e["correlation_b6_even_split"]
            row = {
                "source": f"live/{cond}",
                "spread": _trace_spread(e["per_frame_trace"]),
                "correlation": r,
                "passed_correlation": r >= threshold,
                "scene_brightness": run["scene_brightness_mean"],
            }
            (control if "no_render" in cond else rendered).append(row)

    window = json.loads((REPO_ROOT / "results" / "b6_operating_window.json").read_text("utf-8"))
    for p in window["points"]:
        rendered.append(
            {
                "source": f"window/{p['label']}",
                "spread": p["chromaticity_spread_mean"],
                "correlation": p["correlation"],
                "passed_correlation": p["correlation"] >= threshold,
                "clipped_pixel_fraction": p["clipped_pixel_fraction"],
                "screen_fraction_of_scene": p.get("screen_fraction_of_scene"),
                "scene_brightness": p["scene_brightness_mean"],
            }
        )
    return rendered, control


def _candidate_separation(rows: list[dict[str, Any]], field: str, direction: str) -> dict[str, Any]:
    """Does `field` separate captures that passed the correlation from those that did not?

    `direction` is 'low_bad' when small values should predict unevaluable (spread), and
    'high_bad' when large ones should (clipping).
    """
    usable = [r[field] for r in rows if r.get(field) is not None and r["passed_correlation"]]
    unusable = [r[field] for r in rows if r.get(field) is not None and not r["passed_correlation"]]
    if not usable or not unusable:
        return {"discriminates": False, "reason": "only one class present in this source"}

    u, x = np.asarray(usable, float), np.asarray(unusable, float)
    if direction == "low_bad":
        gap = float(u.min() - x.max())
        verdict = "gate rejects below a floor"
    else:
        gap = float(x.min() - u.max())
        verdict = "gate rejects above a limit"
    return {
        "n_passed_correlation": len(u),
        "n_failed_correlation": len(x),
        "passed_min": float(u.min()),
        "passed_max": float(u.max()),
        "failed_min": float(x.min()),
        "failed_max": float(x.max()),
        "fully_separable": bool(gap > 0),
        "gap": gap,
        "direction": verdict,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=REPO_ROOT / "results" / "b6_evaluability.json")
    args = parser.parse_args()

    rendered, control = _collect()
    window_rows = [r for r in rendered if r["source"].startswith("window/")]

    passing = np.array([r["spread"] for r in rendered if r["passed_correlation"]])
    failing = np.array([r["spread"] for r in rendered if not r["passed_correlation"]])
    ctrl = np.array([r["spread"] for r in control])

    floor_table = []
    for t in FLOOR_GRID:
        floor_table.append(
            {
                "floor": t,
                # The number that must stay zero: genuine captures B6 could measure, sent
                # round the retry loop for nothing.
                "false_gate_rate_on_passing_captures": float((passing < t).mean()),
                # Captures currently mislabelled as attacks that become "retry" instead.
                "reclassified_rate_on_failing_captures": float((failing < t).mean()),
                "gated_rate_on_no_render_controls": float((ctrl < t).mean()),
                "margin_below_lowest_passing_capture": float(passing.min() - t),
            }
        )

    # Highest floor that gates none of the passing captures AND keeps a margin of at least
    # half the floor beneath the lowest of them. Maximising reclassification alone would
    # push the floor up against the lowest passing capture, which is how a gate ends up
    # firing on the first slightly-worse genuine capture it meets.
    feasible = [
        row
        for row in floor_table
        if row["false_gate_rate_on_passing_captures"] == 0.0
        and row["margin_below_lowest_passing_capture"] >= 0.5 * row["floor"]
    ]
    chosen = max(feasible, key=lambda r: r["reclassified_rate_on_failing_captures"])

    result = {
        **run_metadata(seed=SEED),
        "illumination_corr_min": settings.binding.illumination_corr_min,
        "population": {
            "rendered_captures": len(rendered),
            "rendered_passing_correlation": int(len(passing)),
            "rendered_failing_correlation": int(len(failing)),
            "no_render_controls": len(control),
            "sources": [
                "b6_operating_point.json",
                "live_challenge_check.json",
                "b6_operating_window.json",
            ],
        },
        "candidates": {
            "chromaticity_trace_spread": {
                "shipped": True,
                "separation_on_rendered": _candidate_separation(rendered, "spread", "low_bad"),
                "floor_table": floor_table,
                "chosen": chosen,
                "selection_rule": (
                    "highest floor that gates none of the captures which passed the "
                    "correlation, keeping a margin of at least half the floor beneath the "
                    "lowest of them; among those, the one reclassifying most failing "
                    "captures"
                ),
            },
            "clipped_pixel_fraction": {
                "shipped": False,
                "n_samples": len(window_rows),
                "separation_on_rendered": _candidate_separation(
                    window_rows, "clipped_pixel_fraction", "high_bad"
                ),
                "dropped_because": (
                    "it does not discriminate, and points the wrong way. The only two "
                    "clipped captures held (9.29% and 10.02% clipped, at 196-199/255) both "
                    "PASSED the correlation, at r=+0.785 and +0.753, while every capture "
                    "that failed had zero clipping. An earlier §14 note attributing a flat "
                    "trace to saturation is corrected by this: high brightness and a flat "
                    "trace do co-occur, but clipping fraction is not what distinguishes "
                    "them, and trace spread measures the thing directly anyway"
                ),
            },
            "screen_contribution_fraction": {
                "shipped": False,
                "n_samples": len(window_rows),
                "separation_on_rendered": _candidate_separation(
                    window_rows, "screen_fraction_of_scene", "low_bad"
                ),
                "dropped_because": (
                    "the classes overlap and are inverted: captures that passed the "
                    "correlation ran 0.0122-0.0171 screen fraction, those that failed "
                    "0.0163-0.0183. It also costs an extra white/black probe at capture "
                    "start. Shipping it would be a gate firing at random"
                ),
            },
        },
        "B6_residual_unmet_after_the_evaluability_gate": blocked(
            "The evaluability gate has not solved B6's BPCER contamination, only a third "
            "of it. At the shipped floor the gate reclassifies 33% of failing rendered "
            "captures from BIND_CHALLENGE_UNMET to BIND_CHALLENGE_UNEVALUABLE, while "
            "gating 74% of no-render controls -- so roughly two-thirds of real-capture B6 "
            "failures are still scored as UNMET, i.e. as challenge-not-answered rather "
            "than could-not-measure. Whether that residual is a conservative gate leaving "
            "measurable-but-weak captures on the attack side, or genuinely unmet "
            "challenges that deserve the code they get, is UNRESOLVED: separating the two "
            "needs captures whose ground truth is known independently of the correlation "
            "itself, which is the consented multi-capture session. Until then any BPCER "
            "figure derived from B6 outcomes carries an unquantified genuine-capture "
            "component (PROJECT_SPEC.md §14, 2026-09-04)"
        ),
        "B6_operating_point_characterisation": blocked(
            "B6's threshold (binding.illumination_corr_min = 0.60) and this evaluability "
            "floor both rest on captures from a single session, in one room, on one "
            "sensor, with no human subject at capture distance. Measured TPR was 1.00 on "
            "8 captures, whose one-sided 95% Clopper-Pearson upper bound on BPCER is "
            "0.312 -- consistent with a true BPCER of 31%. Demonstrating the 5% system "
            "BPCER target at 95% confidence needs ~59 consecutive clean captures. "
            "UNBLOCKER: the consented multi-capture session -- multiple subjects at "
            "capture distance across varied ambient lighting, which §6 gates behind "
            "written consent and supervisor approval (the same blocker as the replay "
            "corpus). §5.2's live-webcam DoD item closes on that measurement and not "
            "before; until then these values are the best available estimate, not a "
            "characterised operating point (PROJECT_SPEC.md §14, 2026-09-03/04)"
        ),
        "note": (
            "Derived entirely from persisted captures; this script measures nothing new. "
            "The shipped floor is binding.illumination_min_trace_spread."
        ),
    }
    write_json(args.out, result)

    print(
        f"rendered={len(rendered)} passing={len(passing)} failing={len(failing)} controls={len(control)}"
    )
    print(
        f"\n{'floor':>8} {'false_gate':>11} {'reclassified':>13} {'ctrl_gated':>11} {'margin':>10}"
    )
    for row in floor_table:
        print(
            f"{row['floor']:>8.4f} {row['false_gate_rate_on_passing_captures']:>11.3f} "
            f"{row['reclassified_rate_on_failing_captures']:>13.3f} "
            f"{row['gated_rate_on_no_render_controls']:>11.3f} "
            f"{row['margin_below_lowest_passing_capture']:>+10.5f}"
        )
    print(f"\nCHOSEN floor: {chosen['floor']}")
    print(
        f"  config binding.illumination_min_trace_spread = {settings.binding.illumination_min_trace_spread}"
    )
    for name, block in result["candidates"].items():
        if not block["shipped"]:
            print(f"  DROPPED {name}: {block['dropped_because'][:70]}...")
    print(f"\nwrote {args.out}")


if __name__ == "__main__":
    main()
