"""Which sensor operating points can B6 actually measure a colour cast at?

Owner: Abhijay

Two live sessions produced opposite answers about the capture protocol, and the
contradiction is the finding. On 2026-09-03 at low ambient, auto-exposure was what reached
a bright enough operating point and locking exposure crippled B6. An hour later at higher
ambient, the same auto-exposure setting drove the sensor to ~190/255 and the measured
chromaticity trace went **flat** — per-channel spread 0.00024, against 0.0116 for a locked
capture at 138/255 in the same room minutes apart. Neither "always auto" nor "always
locked" is the rule; both are proxies for the thing that actually matters, which is landing
in a window where the cast is above the noise floor and below saturation.

This measures that window directly, by sweeping exposure under a rendered challenge and
recording, for each operating point:

* mean scene brightness,
* the fraction of clipped pixels (any channel at 255) in the measured region,
* the per-channel spread of the chromaticity trace — B6's actual signal,
* the resulting correlation.

The output is the basis for a protocol that targets an operating point rather than a
lock setting. Captures no biometric data and retains no frames.

Usage:
    python scripts/measure_operating_window.py
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

import cv2
import numpy as np

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from live_challenge_check import (  # noqa: E402
    WINDOW,
    _open_camera,
    _render_and_capture,
)

from pqbio.bench._common import run_metadata, write_json  # noqa: E402
from pqbio.binding.verify import (  # noqa: E402
    _channel_centred_pearson,
    _expand_expected_trace,
)
from pqbio.capture.challenge import (  # noqa: E402
    derive_illumination_sequence,
    estimate_face_box,
    measure_chromaticity_trace,
)
from pqbio.config import settings  # noqa: E402

SEED = 2026
DEFAULT_NONCE_HEX = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"


def _clipped_fraction(frames: list[np.ndarray], face_box: tuple[int, int, int, int]) -> float:
    x, y, w, h = face_box
    clipped, total = 0, 0
    for frame in frames:
        region = frame[y : y + h, x : x + w]
        if region.size == 0:
            continue
        clipped += int((region >= 254).any(axis=2).sum())
        total += region.shape[0] * region.shape[1]
    return clipped / total if total else 0.0


def _screen_contribution(cap: cv2.VideoCapture, args: argparse.Namespace) -> dict[str, float]:
    """How much of the scene's light is coming from the screen, at the current exposure.

    This is the physical quantity B6 actually depends on, and the one no config value
    controls. The induced cast's relative amplitude goes as
    screen_light / (screen_light + ambient_light): in a dark room the screen dominates and
    the challenge is easy to see; with the room lights on it is a small perturbation on a
    large constant, and no threshold or step count recovers it. Measured by rendering full
    white and full black at a fixed exposure and comparing.
    """
    import time

    readings = {}
    try:
        cv2.namedWindow(WINDOW, cv2.WND_PROP_FULLSCREEN)
        if not args.windowed:
            cv2.setWindowProperty(WINDOW, cv2.WND_PROP_FULLSCREEN, cv2.WINDOW_FULLSCREEN)
        for label, colour in (("black", (0, 0, 0)), ("white", (255, 255, 255))):
            cv2.imshow(WINDOW, np.full((1080, 1920, 3), colour, dtype=np.uint8))
            cv2.waitKey(1)
            time.sleep(0.35)
            samples = []
            for _ in range(8):
                ok, f = cap.read()
                if ok and f is not None:
                    samples.append(float(f.mean()))
                cv2.waitKey(1)
            readings[label] = float(np.mean(samples)) if samples else 0.0
    finally:
        cv2.destroyWindow(WINDOW)
        cv2.waitKey(1)

    ambient, lit = readings["black"], readings["white"]
    return {
        "ambient_only_brightness": ambient,
        "screen_lit_brightness": lit,
        "screen_contribution": lit - ambient,
        "screen_fraction_of_scene": (lit - ambient) / lit if lit > 0 else 0.0,
    }


def _evaluate_point(
    cap: cv2.VideoCapture, sequence: list[int], args: argparse.Namespace, label: str
) -> dict[str, Any]:
    frames, frame_steps = _render_and_capture(
        cap, sequence, args.step_ms, fullscreen=not args.windowed, render=True
    )
    face_box = estimate_face_box(frames[0])
    trace = measure_chromaticity_trace(frames, face_box)
    arr = np.asarray(trace, dtype=float).reshape(-1, 3)
    r = _channel_centred_pearson(trace, _expand_expected_trace(sequence, len(frames)))
    return {
        "label": label,
        "n_frames": len(frames),
        "scene_brightness_mean": float(np.mean([f.mean() for f in frames])),
        "clipped_pixel_fraction": _clipped_fraction(frames, face_box),
        "chromaticity_spread_per_channel": [float(v) for v in arr.std(axis=0)],
        "chromaticity_spread_mean": float(arr.std(axis=0).mean()),
        "correlation": r,
        "passes_threshold": bool(r >= settings.binding.illumination_corr_min),
        "_frame_steps_len": len(frame_steps),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--camera-index", type=int, default=0)
    parser.add_argument("--step-ms", type=int, default=settings.binding.illumination_step_ms)
    parser.add_argument("--windowed", action="store_true")
    parser.add_argument("--nonce-hex", default=DEFAULT_NONCE_HEX)
    parser.add_argument("--repeats", type=int, default=2)
    parser.add_argument(
        "--out", type=Path, default=REPO_ROOT / "results" / "b6_operating_window.json"
    )
    args = parser.parse_args()

    sequence = derive_illumination_sequence(
        bytes.fromhex(args.nonce_hex), settings.binding.illumination_steps
    )
    cap = _open_camera(args.camera_index)
    points: list[dict[str, Any]] = []
    try:
        for rep in range(args.repeats):
            # Auto first, so the sweep can be compared against what the camera chooses.
            cap.set(cv2.CAP_PROP_AUTO_WB, 0)
            cap.set(cv2.CAP_PROP_AUTO_EXPOSURE, 0.75)
            for _ in range(20):
                cap.read()
            print(f"repeat {rep + 1}/{args.repeats}: auto exposure", file=sys.stderr)
            pt = _evaluate_point(cap, sequence, args, "auto_exposure")
            pt.update(_screen_contribution(cap, args))
            points.append(pt)

            cap.set(cv2.CAP_PROP_AUTO_EXPOSURE, 0.25)
            for exposure in (-1, -2, -3, -4, -5, -6):
                cap.set(cv2.CAP_PROP_EXPOSURE, exposure)
                for _ in range(8):
                    cap.read()
                print(f"repeat {rep + 1}/{args.repeats}: exposure={exposure}", file=sys.stderr)
                pt = _evaluate_point(cap, sequence, args, f"exposure_{exposure}")
                pt.update(_screen_contribution(cap, args))
                points.append(pt)
    finally:
        cap.release()

    usable = [p for p in points if p["passes_threshold"]]
    result = {
        **run_metadata(seed=SEED),
        "illumination_steps": settings.binding.illumination_steps,
        "step_ms": args.step_ms,
        "illumination_corr_min": settings.binding.illumination_corr_min,
        "points": points,
        "usable_window": {
            "n_points_passing": len(usable),
            "brightness_min": min((p["scene_brightness_mean"] for p in usable), default=None),
            "brightness_max": max((p["scene_brightness_mean"] for p in usable), default=None),
            "max_clipped_fraction_among_passing": max(
                (p["clipped_pixel_fraction"] for p in usable), default=None
            ),
        },
        "note": (
            "Sweeps sensor operating points under a rendered challenge. The protocol "
            "question is not 'lock or auto' but 'which operating point' -- auto reaches a "
            "good one at low ambient and a saturated one at high ambient, and the "
            "chromaticity trace goes flat when it saturates."
        ),
    }
    write_json(args.out, result)

    print(f"\n{'point':>16} {'bright':>8} {'clip%':>8} {'spread':>9} {'r':>8}")
    for p in points:
        print(
            f"{p['label']:>16} {p['scene_brightness_mean']:>8.1f} "
            f"{100 * p['clipped_pixel_fraction']:>8.2f} "
            f"{p['chromaticity_spread_mean']:>9.5f} {p['correlation']:>+8.3f}"
        )
    print(f"\nwrote {args.out}")


if __name__ == "__main__":
    main()
