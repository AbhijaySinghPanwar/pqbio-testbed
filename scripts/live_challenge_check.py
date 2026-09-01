"""Live illumination-challenge check on a real camera + display (PROJECT_SPEC.md §5.2
DoD: "verified against a real webcam", outstanding since Module B was built).

Owner: Aviral / Krish

Everything in Module B except this has been testable headlessly:
`measure_chromaticity_trace` is pure numpy, `ReplaySource` needs no sensor, and
`render_challenge_fullscreen` needs a display nothing in CI has. This script closes the
gap by doing the one thing that needs both at once — render the nonce-derived colour
sequence full-screen while capturing from a real sensor, then check the trace B6 relies
on is actually recoverable from the pixels that come back.

Two things it establishes that a headless test cannot:

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
from pqbio.binding.verify import _expand_expected_trace, _pearson_r  # noqa: E402
from pqbio.capture.challenge import (  # noqa: E402
    PALETTE_BGR,
    PALETTE_NAMES,
    derive_illumination_sequence,
    estimate_face_box,
    measure_chromaticity_trace,
)
from pqbio.config import settings  # noqa: E402

WINDOW = "pqbio-illumination-challenge"


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
    cap: cv2.VideoCapture, force_exposure: int | None = None
) -> dict[str, Any]:
    """Let auto settle, read where it converged, then pin both. Returns what actually
    took effect -- DirectShow reports some properties back unreliably, so the evidence
    that the lock worked is the brightness stability measured afterwards, not the
    property read-back.
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
    }


def _render_and_capture(
    cap: cv2.VideoCapture, sequence: list[int], step_ms: int, fullscreen: bool
) -> tuple[list[np.ndarray], list[int]]:
    """Interleaved render + capture: display step i, grab whatever frames land inside
    its window, and tag each with the step that was actually on screen. This is the
    interleaving Module B's CLI never did.
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
            panel = np.full((1080, 1920, 3), PALETTE_BGR[colour_idx], dtype=np.uint8)
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
    """Expected [R,G,B, ...] using the step that was *actually* displayed per frame,
    rather than B6's even split across frames."""
    trace: list[float] = []
    for step_idx in frame_steps:
        b, g, r = PALETTE_BGR[sequence[step_idx]]
        trace.extend((r / 255.0, g / 255.0, b / 255.0))
    return trace


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
        "--nonce-hex",
        default="a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90",
        help="fixed by default so the derived colour sequence is reproducible",
    )
    parser.add_argument(
        "--out", type=Path, default=REPO_ROOT / "results" / "live_challenge_check.json"
    )
    args = parser.parse_args()

    nonce = bytes.fromhex(args.nonce_hex)
    sequence = derive_illumination_sequence(nonce, settings.binding.illumination_steps)
    print(f"challenge sequence: {[PALETTE_NAMES[i] for i in sequence]}", file=sys.stderr)

    cap = _open_camera(args.camera_index)
    try:
        lock_info = _lock_white_balance_and_exposure(cap, force_exposure=args.exposure)
        print(f"WB/exposure lock: {lock_info}", file=sys.stderr)
        frames, frame_steps = _render_and_capture(
            cap, sequence, args.step_ms, fullscreen=not args.windowed
        )
    finally:
        cap.release()

    if len(frames) < 4:
        raise HardwareUnavailableError(
            f"captured only {len(frames)} frames; too few to evaluate a trace"
        )

    from pqbio.detect.face import detect_face_box

    detected_box, detected_score = detect_face_box(frames[0])
    face_box = estimate_face_box(frames[0])  # falls back to a centre crop when None
    measured = measure_chromaticity_trace(frames, face_box)
    expected_even = _expand_expected_trace(sequence, len(frames))
    expected_exact = _exact_expected_trace(sequence, frame_steps)

    r_even = _pearson_r(measured, expected_even)
    r_exact = _pearson_r(measured, expected_exact)
    threshold = settings.binding.illumination_corr_min

    per_step: dict[str, dict[str, float]] = {}
    for step_idx, colour_idx in enumerate(sequence):
        idxs = [i for i, s in enumerate(frame_steps) if s == step_idx]
        if not idxs:
            continue
        rgb = np.array([measured[3 * i : 3 * i + 3] for i in idxs], dtype=float)
        per_step[f"step{step_idx}_{PALETTE_NAMES[colour_idx]}"] = {
            "n_frames": len(idxs),
            "mean_R": float(rgb[:, 0].mean()),
            "mean_G": float(rgb[:, 1].mean()),
            "mean_B": float(rgb[:, 2].mean()),
        }

    result: dict[str, Any] = {
        **run_metadata(),
        "camera_index": args.camera_index,
        "resolution": [int(frames[0].shape[1]), int(frames[0].shape[0])],
        "n_frames": len(frames),
        "step_ms": args.step_ms,
        "fullscreen": not args.windowed,
        "sequence": [PALETTE_NAMES[i] for i in sequence],
        "face_box_used": list(face_box),
        "face_detected": detected_box is not None,
        "face_detection_score": float(detected_score),
        "face_box_source": "SCRFD" if detected_box is not None else "centre-crop fallback",
        "white_balance_exposure_lock": lock_info,
        "illumination_corr_min": threshold,
        "correlation_b6_even_split": r_even,
        "correlation_exact_alignment": r_exact,
        "trace_recovered_b6_rule": bool(r_even >= threshold),
        "per_step_measured_rgb": per_step,
        "regional_chromatic_response": _regional_chromatic_response(frames, frame_steps, sequence),
        "note": (
            "Live check on a real sensor + display. Records aggregate per-frame colour "
            "means only -- no frames retained, no face required or stored. "
            "correlation_exact_alignment uses the step actually on screen per frame; "
            "correlation_b6_even_split reproduces what pqbio.binding.verify's B6 "
            "actually computes, so the difference is the cost of that documented "
            "approximation."
        ),
    }
    write_json(args.out, result)
    print(
        f"\nframes={len(frames)}  r(B6 even split)={r_even:.4f}  "
        f"r(exact alignment)={r_exact:.4f}  threshold={threshold}\n"
        f"trace recovered under B6's rule: {r_even >= threshold}\nwrote {args.out}",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
