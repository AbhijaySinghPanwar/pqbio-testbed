"""Live illumination-challenge check on a real camera + display (PROJECT_SPEC.md §5.2
DoD: "verified against a real webcam", outstanding since Module B was built).

Owner: Aviral / Krish

Everything in Module B except this has been testable headlessly:
`measure_chromaticity_trace` is pure numpy, `ReplaySource` needs no sensor, and
`render_challenge_fullscreen` needs a display nothing in CI has. This script closes the
gap by doing the one thing that needs both at once — render the nonce-derived colour
sequence full-screen while capturing from a real sensor, then check the trace B6 relies
on is actually recoverable from the pixels that come back.

It runs **three passes on the same sensor in the same room**, so every comparison it
reports is controlled rather than argued:

1. `locked_render` — WB/AE locked, challenge rendered. The primary measurement.
2. `unlocked_render` — auto WB/AE, challenge rendered. What locking actually buys.
3. `wb_locked_ae_auto_render` — WB locked, exposure automatic. The two locks have
   opposite effects and lumping them together hid that; this separates them.
4. `locked_no_render_control` — WB/AE locked, nothing displayed, identical timing and
   frame budget. The control, and a genuine *no-cast negative* for calibrating
   `illumination_corr_min` against something the sensor really produced.

Each pass is scored under both region weightings (`uniform` and `centre`), so the choice
between them is made on measured separation rather than preference.

Three things it establishes that a headless test cannot:

1. **Auto white balance and auto exposure must be locked before capture.** The
   challenge works by inducing a deliberate colour cast; a camera left on auto will
   spend the whole sequence correcting exactly the signal being measured. This script
   lets auto settle, reads back where it converged, locks both, and reports the
   brightness stability that results — so "locked" is demonstrated, not asserted.
2. **How much B6's even-split timing approximation costs.** `verify.py`'s
   `_expand_expected_trace` assumes frames divide evenly across challenge steps,
   because Module B never interleaved render and capture and there was nothing more
   precise to align against. Here there is: every frame is tagged with the step that
   was actually on screen when it was grabbed. The script reports the correlation both
   ways — B6's even split, and the exact per-frame alignment — so the cost of the
   approximation is a measured number rather than an open question.
3. **Whether the measurement formulation is right at all.** The 2026-09-01 run of this
   script is what caught §5.2 specifying "mean chromaticity" while the code returned
   absolute per-channel brightness (PROJECT_SPEC.md §14). It now measures true
   luminance-normalised chromaticity; this script is the regression test for that,
   and there is no substitute for a sensor here.

**Captures no biometric data and retains no frames.** It records only aggregate
per-frame colour means (the trace B6 itself uses) and writes them to
`results/live_challenge_check.json`. It does not require, detect, or store a face; the
face box falls back to a centre crop when none is present, which is the documented
behaviour of `estimate_face_box`.

Usage (needs a display and a camera — will fail loudly, not silently, without either):
    python scripts/live_challenge_check.py
    python scripts/live_challenge_check.py --windowed --step-ms 400
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path
from typing import Any

import cv2
import numpy as np

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from pqbio.bench._common import run_metadata, write_json  # noqa: E402
from pqbio.binding.verify import (  # noqa: E402
    _channel_centred_pearson,
    _expand_expected_trace,
    palette_chromaticity,
)
from pqbio.capture.challenge import (  # noqa: E402
    PALETTE_BGR,
    PALETTE_NAMES,
    RegionWeighting,
    derive_illumination_sequence,
    estimate_face_box,
    measure_chromaticity_trace,
)
from pqbio.config import settings  # noqa: E402
from pqbio.detect.face import detect_face_box  # noqa: E402

WINDOW = "pqbio-illumination-challenge"
WEIGHTINGS: tuple[RegionWeighting, ...] = ("uniform", "centre")


class HardwareUnavailableError(RuntimeError):
    """Raised when the camera or the display isn't usable. Never caught internally --
    a missing sensor must stop this check, not downgrade it to a synthetic one."""


def _open_camera(index: int) -> cv2.VideoCapture:
    cap = cv2.VideoCapture(index, cv2.CAP_DSHOW)
    if not cap.isOpened():
        raise HardwareUnavailableError(
            f"no camera at index {index}. This check requires a real sensor; it will not "
            "fall back to synthetic frames."
        )
    ok, frame = cap.read()
    if not ok or frame is None:
        cap.release()
        raise HardwareUnavailableError(f"camera at index {index} opened but returned no frame")
    return cap


def _lock_white_balance_and_exposure(
    cap: cv2.VideoCapture,
    force_exposure: int | None = None,
    force_gain: int | None = None,
) -> dict[str, Any]:
    """Let auto settle, read where it converged, then pin both. Returns what actually
    took effect -- DirectShow reports some properties back unreliably, so the evidence
    that the lock worked is the brightness stability measured afterwards, not the
    property read-back.

    `force_gain` exists because of a measured hardware limit, not for tuning. On this
    sensor, switching `CAP_PROP_AUTO_EXPOSURE` to manual pins a short exposure that no
    value of `CAP_PROP_EXPOSURE` lifts: -1, -2 and 0 all land at 33/255 in this room and
    only darker settings respond at all. Auto reaches 112/255 on the same scene. Gain is
    the one remaining lever (0 -> 128 buys 33 -> 69), so a locked capture that is also
    bright enough to measure needs it. Locking WB and exposure is about stopping the
    sensor from *moving*; choosing the operating point it stops at is a separate
    decision, and on dark hardware it has to be made deliberately.
    """
    for _ in range(15):  # let AE/AWB converge on the real scene
        cap.read()
    auto_samples = []
    for _ in range(10):
        ok, f = cap.read()
        if ok and f is not None:
            auto_samples.append(float(f.mean()))
    auto_brightness = float(np.mean(auto_samples)) if auto_samples else 0.0

    cap.set(cv2.CAP_PROP_AUTO_WB, 0)
    cap.set(cv2.CAP_PROP_AUTO_EXPOSURE, 0.25)  # DSHOW convention: 0.25 = manual
    if force_gain is not None:
        cap.set(cv2.CAP_PROP_GAIN, force_gain)

    # Pick the manual exposure closest to where auto had converged, so locking does not
    # also change the operating point -- the point is to stop it moving, not to darken.
    #
    # `force_exposure` overrides that when ambient is so dark that matching it puts the
    # measurement near the 8-bit floor: at ~23/255 a real chromatic signal can sit under
    # quantisation noise, and a brighter lock is the way to tell "no signal" apart from
    # "signal below the floor". Still locked, still stable -- just at a higher setpoint.
    if force_exposure is not None:
        cap.set(cv2.CAP_PROP_EXPOSURE, force_exposure)
        for _ in range(6):
            cap.read()
        stability = []
        for _ in range(10):
            ok, f = cap.read()
            if ok and f is not None:
                stability.append(float(f.mean()))
        return {
            "auto_brightness_before_lock": auto_brightness,
            "chosen_exposure": force_exposure,
            "exposure_forced": True,
            "brightness_after_lock_mean": float(np.mean(stability)) if stability else None,
            "brightness_after_lock_std": float(np.std(stability)) if stability else None,
            "auto_wb_readback": cap.get(cv2.CAP_PROP_AUTO_WB),
            "wb_temperature_readback": cap.get(cv2.CAP_PROP_WB_TEMPERATURE),
            "gain_requested": force_gain,
            "gain_readback": cap.get(cv2.CAP_PROP_GAIN),
        }

    best: tuple[int | None, float, float] = (None, float("inf"), 0.0)
    for candidate in (-1, -2, -3, -4, -5, -6, -7, -8):
        cap.set(cv2.CAP_PROP_EXPOSURE, candidate)
        for _ in range(4):
            cap.read()
        ok, f = cap.read()
        if not ok or f is None:
            continue
        brightness = float(f.mean())
        delta = abs(brightness - auto_brightness)
        if delta < best[1]:
            best = (candidate, delta, brightness)
    chosen_exposure = best[0]
    if chosen_exposure is not None:
        cap.set(cv2.CAP_PROP_EXPOSURE, chosen_exposure)
        for _ in range(4):
            cap.read()

    stability = []
    for _ in range(10):
        ok, f = cap.read()
        if ok and f is not None:
            stability.append(float(f.mean()))

    return {
        "auto_brightness_before_lock": auto_brightness,
        "chosen_exposure": chosen_exposure,
        "brightness_after_lock_mean": float(np.mean(stability)) if stability else None,
        "brightness_after_lock_std": float(np.std(stability)) if stability else None,
        "auto_wb_readback": cap.get(cv2.CAP_PROP_AUTO_WB),
        "wb_temperature_readback": cap.get(cv2.CAP_PROP_WB_TEMPERATURE),
        "gain_requested": force_gain,
        "gain_readback": cap.get(cv2.CAP_PROP_GAIN),
    }


def _render_and_capture(
    cap: cv2.VideoCapture,
    sequence: list[int],
    step_ms: int,
    fullscreen: bool,
    *,
    render: bool = True,
) -> tuple[list[np.ndarray], list[int]]:
    """Interleaved render + capture: display step i, grab whatever frames land inside
    its window, and tag each with the step that was actually on screen. This is the
    interleaving Module B's CLI never did.

    With `render=False` the timing, frame count and step tagging are identical but
    nothing is displayed. That is the control, and it is not only a sanity check: a
    capture with no induced cast, correlated against the same nonce-derived expectation,
    is a *real* negative sample for threshold calibration -- one measured on the same
    sensor in the same room, which no synthetic negative can be.
    """
    try:
        cv2.namedWindow(WINDOW, cv2.WND_PROP_FULLSCREEN)
        if fullscreen:
            cv2.setWindowProperty(WINDOW, cv2.WND_PROP_FULLSCREEN, cv2.WINDOW_FULLSCREEN)
    except cv2.error as exc:  # no GUI backend / no display
        raise HardwareUnavailableError(
            f"cannot open a display window ({exc}). This check needs a real screen; "
            "it will not simulate one."
        ) from exc

    frames: list[np.ndarray] = []
    frame_steps: list[int] = []
    try:
        for step_idx, colour_idx in enumerate(sequence):
            colour = PALETTE_BGR[colour_idx] if render else (0, 0, 0)
            panel = np.full((1080, 1920, 3), colour, dtype=np.uint8)
            cv2.imshow(WINDOW, panel)
            cv2.waitKey(1)  # let the compositor actually paint it
            time.sleep(0.06)  # settle: panel response + sensor lag before sampling
            step_deadline = time.perf_counter() + (step_ms / 1000.0)
            while time.perf_counter() < step_deadline:
                ok, frame = cap.read()
                if ok and frame is not None:
                    frames.append(frame)
                    frame_steps.append(step_idx)
                cv2.waitKey(1)
    finally:
        cv2.destroyWindow(WINDOW)
        cv2.waitKey(1)
    return frames, frame_steps


def _regional_chromatic_response(
    frames: list[np.ndarray], frame_steps: list[int], sequence: list[int], grid: int = 4
) -> dict[str, Any]:
    """Per-region B:R ratio by challenge step.

    B6 correlates *absolute* per-channel means, which a luminance change moves in all
    three channels at once. A ratio isolates hue from brightness, so this answers a
    question the correlation alone cannot: is the colour cast physically present in the
    scene but being missed by where/how B6 measures, or is it simply not there? A region
    genuinely lit by the screen should show its B:R ratio rise on blue steps.
    """
    if not frames:
        return {}
    h, w = frames[0].shape[:2]
    gh, gw = h // grid, w // grid
    step_frames: dict[int, list[np.ndarray]] = {}
    for frame, step in zip(frames, frame_steps, strict=True):
        step_frames.setdefault(step, []).append(frame)
    step_means = {s: np.mean(fs, axis=0) for s, fs in step_frames.items()}

    regions: dict[str, Any] = {}
    best_spread, best_cell = 0.0, None
    for row in range(grid):
        for col in range(grid):
            ratios = []
            for step in sorted(step_means):
                patch = step_means[step][row * gh : (row + 1) * gh, col * gw : (col + 1) * gw]
                blue, red = float(patch[:, :, 0].mean()), float(patch[:, :, 2].mean())
                ratios.append(blue / max(red, 1e-6))
            spread = max(ratios) - min(ratios)
            regions[f"r{row}c{col}"] = {
                "b_over_r_by_step": ratios,
                "spread": spread,
            }
            if spread > best_spread:
                best_spread, best_cell = spread, f"r{row}c{col}"
    return {
        "grid": grid,
        "step_colours": [PALETTE_NAMES[sequence[s]] for s in sorted(step_means)],
        "regions": regions,
        "max_b_over_r_spread": best_spread,
        "max_spread_cell": best_cell,
        "interpretation": (
            "A region actually lit by the screen shows its B:R ratio rise on blue steps. "
            "Spread <0.02 across all regions means no cast reached the sensor at all; a "
            "large spread in some region means the cast is physically present and the "
            "limitation is where/how B6 measures, not the mechanism."
        ),
    }


def _exact_expected_trace(sequence: list[int], frame_steps: list[int]) -> list[float]:
    """Expected normalised-chromaticity trace using the step that was *actually*
    displayed per frame, rather than B6's even split across frames."""
    trace: list[float] = []
    for step_idx in frame_steps:
        trace.extend(palette_chromaticity(sequence[step_idx]))
    return trace


def _evaluate(
    frames: list[np.ndarray],
    frame_steps: list[int],
    sequence: list[int],
    face_box: tuple[int, int, int, int],
    weighting: RegionWeighting,
    threshold: float,
) -> dict[str, Any]:
    """Score one capture pass under one region weighting. Returns both correlations,
    the per-step mean chromaticity, and the raw per-frame trace.

    The per-frame trace is persisted deliberately: it is exactly the aggregate the
    check consumes (three region means per frame, no pixels), and without it every
    later recalibration would need the hardware and the room back.
    """
    measured = measure_chromaticity_trace(frames, face_box, weighting=weighting)
    # _channel_centred_pearson is exactly the statistic B6 thresholds -- this script
    # must not compute its own variant, or it stops being a check of B6.
    r_even = _channel_centred_pearson(measured, _expand_expected_trace(sequence, len(frames)))
    r_exact = _channel_centred_pearson(measured, _exact_expected_trace(sequence, frame_steps))

    per_step: dict[str, dict[str, float]] = {}
    for step_idx, colour_idx in enumerate(sequence):
        idxs = [i for i, st in enumerate(frame_steps) if st == step_idx]
        if not idxs:
            continue
        chroma = np.array([measured[3 * i : 3 * i + 3] for i in idxs], dtype=float)
        per_step[f"step{step_idx}_{PALETTE_NAMES[colour_idx]}"] = {
            "n_frames": len(idxs),
            "mean_r": float(chroma[:, 0].mean()),
            "mean_g": float(chroma[:, 1].mean()),
            "mean_b": float(chroma[:, 2].mean()),
        }

    return {
        "weighting": weighting,
        "correlation_b6_even_split": r_even,
        "correlation_exact_alignment": r_exact,
        "trace_recovered_b6_rule": bool(r_even >= threshold),
        "per_step_mean_chromaticity": per_step,
        "per_frame_trace": [float(v) for v in measured],
    }


def _capture_pass(
    cap: cv2.VideoCapture,
    sequence: list[int],
    args: argparse.Namespace,
    *,
    lock: str,
    render: bool,
) -> dict[str, Any]:
    """One full pass, capture and evaluate under both region weightings. Every pass
    shares timing and frame budget so they are directly comparable.

    `lock` is a mode rather than a boolean because white balance and exposure turn out to
    matter for opposite reasons, and lumping them together hides that. Auto WB fights the
    cast (bad); auto exposure is what reaches an operating point bright enough to see it
    at all on this sensor (necessary). "wb_only" separates the two.
    """
    if lock in ("full", "wb_only"):
        if lock == "full":
            lock_info = _lock_white_balance_and_exposure(
                cap, force_exposure=args.exposure, force_gain=args.gain
            )
        else:
            cap.set(cv2.CAP_PROP_AUTO_WB, 0)
            cap.set(cv2.CAP_PROP_AUTO_EXPOSURE, 0.75)  # exposure stays automatic
            for _ in range(15):
                cap.read()
            samples = [float(f.mean()) for ok, f in (cap.read() for _ in range(10)) if ok]
            lock_info = {
                "mode": "wb_only",
                "auto_wb_readback": cap.get(cv2.CAP_PROP_AUTO_WB),
                "brightness_before_capture": float(np.mean(samples)) if samples else None,
            }
    else:
        cap.set(cv2.CAP_PROP_AUTO_WB, 1)
        cap.set(cv2.CAP_PROP_AUTO_EXPOSURE, 0.75)  # DSHOW convention: 0.75 = auto
        for _ in range(15):  # let auto reconverge before this pass starts
            cap.read()
        samples = [float(f.mean()) for ok, f in (cap.read() for _ in range(10)) if ok]
        lock_info = {
            "mode": "none",
            "auto_brightness_before_capture": float(np.mean(samples)) if samples else None,
        }
    lock_info.setdefault("mode", lock)

    frames, frame_steps = _render_and_capture(
        cap, sequence, args.step_ms, fullscreen=not args.windowed, render=render
    )
    if len(frames) < 4:
        raise HardwareUnavailableError(
            f"captured only {len(frames)} frames; too few to evaluate a trace"
        )

    detected_box, detected_score = detect_face_box(frames[0])
    face_box = estimate_face_box(frames[0])  # falls back to a centre crop when None
    threshold = settings.binding.illumination_corr_min

    brightness = [float(f.mean()) for f in frames]
    return {
        "lock": lock_info,
        "rendered": render,
        "n_frames": len(frames),
        "resolution": [int(frames[0].shape[1]), int(frames[0].shape[0])],
        "face_box_used": list(face_box),
        "face_detected": detected_box is not None,
        "face_detection_score": float(detected_score),
        "face_box_source": "SCRFD" if detected_box is not None else "centre-crop fallback",
        "scene_brightness_mean": float(np.mean(brightness)),
        "scene_brightness_std": float(np.std(brightness)),
        "scene_brightness_drift": float(brightness[-1] - brightness[0]),
        "by_weighting": {
            w: _evaluate(frames, frame_steps, sequence, face_box, w, threshold) for w in WEIGHTINGS
        },
        "regional_chromatic_response": _regional_chromatic_response(frames, frame_steps, sequence),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--camera-index", type=int, default=0)
    parser.add_argument("--step-ms", type=int, default=400)
    parser.add_argument("--windowed", action="store_true", help="do not go full-screen")
    parser.add_argument(
        "--exposure",
        type=int,
        default=None,
        help="force this manual exposure instead of matching ambient (see "
        "_lock_white_balance_and_exposure: matching a very dark ambient can put the "
        "measurement under the 8-bit noise floor)",
    )
    parser.add_argument(
        "--steps",
        type=int,
        default=None,
        help="override binding.illumination_steps for this run. The correlation's "
        "effective sample size is the number of challenge steps, not the number of "
        "frames -- frames within a step are near-identical -- so this is the knob that "
        "actually controls B6's noise floor. Used to measure that, not to tune it.",
    )
    parser.add_argument(
        "--repeats",
        type=int,
        default=1,
        help="run every pass this many times. A single capture yields a very noisy r: "
        "the challenge has only `illumination_steps` distinct levels (4 by default), so "
        "the correlation has roughly 4 effective samples per channel however many frames "
        "are captured. Repeats are what make the spread measurable instead of assumed.",
    )
    parser.add_argument(
        "--gain",
        type=int,
        default=None,
        help="pin CAP_PROP_GAIN during the locked passes. Needed on sensors where "
        "switching to manual exposure forces an operating point too dark to measure "
        "(see _lock_white_balance_and_exposure).",
    )
    parser.add_argument(
        "--nonce-hex",
        default="a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90",
        help="fixed by default so the derived colour sequence is reproducible",
    )
    parser.add_argument(
        "--out", type=Path, default=REPO_ROOT / "results" / "live_challenge_check.json"
    )
    args = parser.parse_args()

    nonce = bytes.fromhex(args.nonce_hex)
    steps = args.steps or settings.binding.illumination_steps
    sequence = derive_illumination_sequence(nonce, steps)
    threshold = settings.binding.illumination_corr_min
    print(f"challenge sequence: {[PALETTE_NAMES[i] for i in sequence]}", file=sys.stderr)

    conditions = [
        ("locked_render", "full", True),
        ("unlocked_render", "none", True),
        ("wb_locked_ae_auto_render", "wb_only", True),
        ("locked_no_render_control", "full", False),
    ]

    cap = _open_camera(args.camera_index)
    runs: dict[str, list[dict[str, Any]]] = {name: [] for name, _, _ in conditions}
    try:
        for rep in range(args.repeats):
            for name, lock, render in conditions:
                print(
                    f"repeat {rep + 1}/{args.repeats}  {name}",
                    file=sys.stderr,
                )
                runs[name].append(_capture_pass(cap, sequence, args, lock=lock, render=render))
    finally:
        cap.release()

    def spread(name: str, weighting: str) -> dict[str, Any]:
        vals = [r["by_weighting"][weighting]["correlation_b6_even_split"] for r in runs[name]]
        return {
            "n_runs": len(vals),
            "mean": float(np.mean(vals)),
            "std": float(np.std(vals, ddof=1)) if len(vals) > 1 else None,
            "min": float(np.min(vals)),
            "max": float(np.max(vals)),
            "values": [float(v) for v in vals],
        }

    summary = {
        name: {w: spread(name, w) for w in ("uniform", "centre")} for name, _, _ in conditions
    }
    result: dict[str, Any] = {
        **run_metadata(),
        "camera_index": args.camera_index,
        "step_ms": args.step_ms,
        "fullscreen": not args.windowed,
        "nonce_hex": args.nonce_hex,
        "sequence": [PALETTE_NAMES[i] for i in sequence],
        "illumination_steps": steps,
        "illumination_corr_min": threshold,
        "measurement_formulation": "normalised chromaticity r,g,b = C/(R+G+B) per frame",
        "config_weighting": settings.capture.illumination_region_weighting,
        "config_min_channel_sum": settings.capture.illumination_min_channel_sum,
        "repeats": args.repeats,
        "correlation_summary": summary,
        "passes": {name: runs[name] for name, _, _ in conditions},
        "headline": {
            cond: {w: summary[cond][w]["mean"] for w in ("uniform", "centre")} for cond in summary
        },
        "note": (
            "Live check on a real sensor + display, three passes on the same hardware in "
            "the same room: WB/AE locked with the challenge rendered (primary), auto "
            "WB/AE with it rendered (shows what locking buys), and locked with nothing "
            "rendered (control, and a genuine no-cast negative for calibration). "
            "Records aggregate per-frame region colour means only -- no frames retained, "
            "no face required or stored. correlation_exact_alignment uses the step "
            "actually on screen per frame; correlation_b6_even_split reproduces what "
            "pqbio.binding.verify's B6 actually computes, so the difference is the cost "
            "of that documented approximation."
        ),
    }
    write_json(args.out, result)

    print("", file=sys.stderr)
    for cond, by_w in summary.items():
        u, c = by_w["uniform"], by_w["centre"]
        u_std = f"{u['std']:.3f}" if u["std"] is not None else "n/a"
        c_std = f"{c['std']:.3f}" if c["std"] is not None else "n/a"
        print(
            f"  {cond:<26} uniform {u['mean']:+.4f} +/-{u_std}  "
            f"centre {c['mean']:+.4f} +/-{c_std}",
            file=sys.stderr,
        )
    print(f"  threshold={threshold}\nwrote {args.out}", file=sys.stderr)


if __name__ == "__main__":
    main()
