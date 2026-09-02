"""Illumination challenge: derive, render, and measure (PROJECT_SPEC.md §5.2).

Owner: Aviral / Krish

Rendering and measurement are deliberately separable: `render_challenge_fullscreen`
needs a display, and is exercised for real by `scripts/live_challenge_check.py`.
`measure_chromaticity_trace` is pure numpy over a frame array and is fully testable
without either — that's what ReplaySource and tests/unit/test_capture_challenge.py use.

`ChallengeSignal.illumination_trace` (pqbio/schemas.py) is a flat `list[float]`; this
module's convention is 3 consecutive values per frame — [r0,g0,b0, r1,g1,b1, ...],
**normalised chromaticity**: r = R/(R+G+B), g = G/(R+G+B), b = B/(R+G+B), so the three
values of a frame sum to 1.

That normalisation is the whole point, and it is a correction, not a refinement. Until
2026-09-01 this function returned each channel's *absolute* mean over [0, 1] — which is
brightness-per-channel, not chromaticity. §5.2 said "mean chromaticity" and the code did
not implement it; chromaticity is luminance-normalised by definition. The consequence
was measured on a real sensor: any change in total scene illumination moved all three
channels together and swamped the hue signal the challenge deliberately induces, so B6
read r = -0.47 on a capture where the cast was demonstrably reaching the sensor
(PROJECT_SPEC.md §14, 2026-09-01). Do not "simplify" this back to raw means.

Correlating this trace against the expected sequence (binding check B6, §5.3) is
Module C's job (`pqbio.binding.verify.check_b6_challenge_correlation`), which builds its
expected trace in the *same* normalised space — this module only derives, renders, and
records.
"""

from __future__ import annotations

from typing import Any, Literal

import numpy as np
import numpy.typing as npt

from pqbio.pqc.kdf import hkdf_expand, hkdf_extract

# BGR (OpenCV convention) for on-screen rendering; index order matches PALETTE_NAMES.
PALETTE_BGR: list[tuple[int, int, int]] = [
    (0, 0, 255),  # red
    (0, 255, 0),  # green
    (255, 0, 0),  # blue
    (255, 255, 255),  # white
]
PALETTE_NAMES = ["red", "green", "blue", "white"]

FaceBox = tuple[int, int, int, int]  # (x, y, w, h)


def derive_illumination_sequence(nonce: bytes, steps: int) -> list[int]:
    """PRF(nonce) -> `steps` palette indices in [0, len(PALETTE_BGR)). Deterministic —
    same nonce, same sequence — but unpredictable without the nonce, which is exactly
    what a pre-recorded stream cannot satisfy (§5.2).
    """
    prk = hkdf_extract(salt=b"pqbio/v1/challenge/illumination", ikm=nonce)
    stream = hkdf_expand(prk, b"pqbio/v1/challenge/steps", length=steps)
    return [b % len(PALETTE_BGR) for b in stream]


def render_challenge_fullscreen(sequence: list[int], step_duration_s: float | None = None) -> None:
    """Render the derived colour sequence full-screen, one step at a time.

    Requires a display; not exercised in this headless dev environment. Callers on a
    machine with a display and webcam should interleave this with `CameraSource.capture`
    (render step i while capturing the frames that fall in its ~200ms window) — that
    wiring doesn't exist yet; the CLI (`python -m pqbio.capture`) currently captures
    without a live render, which is enough to produce a validly-signed bundle but not
    enough to exercise the actual liveness signal. Flagged, not hidden.
    """
    import cv2
    import numpy as np

    from pqbio.config import settings

    if step_duration_s is None:
        step_duration_s = settings.binding.illumination_step_ms / 1000.0

    window = "pqbio-illumination-challenge"
    cv2.namedWindow(window, cv2.WND_PROP_FULLSCREEN)
    cv2.setWindowProperty(window, cv2.WND_PROP_FULLSCREEN, cv2.WINDOW_FULLSCREEN)
    try:
        for idx in sequence:
            frame = np.full((1080, 1920, 3), PALETTE_BGR[idx], dtype=np.uint8)
            cv2.imshow(window, frame)
            cv2.waitKey(int(step_duration_s * 1000))
    finally:
        cv2.destroyWindow(window)


NEUTRAL_CHROMATICITY = (1.0 / 3.0, 1.0 / 3.0, 1.0 / 3.0)

RegionWeighting = Literal["uniform", "centre"]


def rgb_to_chromaticity(mean_rgb: npt.NDArray[Any], min_channel_sum: float) -> tuple[float, ...]:
    """(R, G, B) means in 0-255 units -> normalised chromaticity summing to 1.

    The denominator is guarded, not left to produce noise: a near-black region has no
    meaningful hue, and R/(R+G+B) on three small numbers is dominated by sensor noise
    and quantisation rather than by the scene. Below `min_channel_sum` this returns
    neutral (1/3, 1/3, 1/3) — the "no information" value, which is constant across
    frames and therefore contributes nothing to B6's correlation instead of
    contributing garbage. That is the fail-closed direction: a dark capture cannot
    accidentally correlate its way to a pass.
    """
    total = float(mean_rgb.sum())
    if not np.isfinite(total) or total < min_channel_sum:
        return NEUTRAL_CHROMATICITY
    return tuple(float(v) / total for v in mean_rgb)


def _cell_weights(grid: int) -> npt.NDArray[Any]:
    """Weight for each cell of a `grid` x `grid` split of the face box, falling off with
    distance from the box centre.

    Motivated by measurement, not taste: on the 2026-09-01 live check the four central
    cells showed a B:R swing of 0.05-0.10 across challenge steps while the peripheral
    cells sat at 0.001-0.005 (results/live_challenge_check.json). The screen lights what
    is in front of it; the periphery is mostly background metres away, contributing the
    scene's own static colour and diluting the signal. Whether that dilution actually
    matters for B6 is an empirical question — see `scripts/calibrate_illumination_corr.py`,
    which measures both weightings rather than assuming this one wins.
    """
    axis = (np.arange(grid) + 0.5) / grid - 0.5  # cell centres in [-0.5, 0.5]
    dy, dx = np.meshgrid(axis, axis, indexing="ij")
    dist = np.sqrt(dy**2 + dx**2)
    sigma = 0.25
    return np.asarray(np.exp(-(dist**2) / (2 * sigma**2)), dtype=float)


def _frame_chromaticity(
    region: npt.NDArray[Any],
    weighting: RegionWeighting,
    min_channel_sum: float,
    grid: int,
) -> tuple[float, ...]:
    """Normalised chromaticity of one face region under the selected weighting."""
    if region.size == 0:
        return NEUTRAL_CHROMATICITY

    if weighting == "uniform":
        mean_bgr = region.reshape(-1, 3).mean(axis=0)
        return rgb_to_chromaticity(mean_bgr[::-1], min_channel_sum)

    h, w = region.shape[0], region.shape[1]
    if h < grid or w < grid:  # too small to split meaningfully — degrade to uniform
        mean_bgr = region.reshape(-1, 3).mean(axis=0)
        return rgb_to_chromaticity(mean_bgr[::-1], min_channel_sum)

    weights = _cell_weights(grid)
    y_edges = np.linspace(0, h, grid + 1).astype(int)
    x_edges = np.linspace(0, w, grid + 1).astype(int)

    acc = np.zeros(3, dtype=float)
    total_weight = 0.0
    for row in range(grid):
        for col in range(grid):
            cell = region[y_edges[row] : y_edges[row + 1], x_edges[col] : x_edges[col + 1]]
            if cell.size == 0:
                continue
            mean_bgr = cell.reshape(-1, 3).mean(axis=0)
            if float(mean_bgr.sum()) < min_channel_sum:
                continue  # guarded cell: no hue information, so no vote
            chroma = rgb_to_chromaticity(mean_bgr[::-1], min_channel_sum)
            acc += weights[row, col] * np.asarray(chroma, dtype=float)
            total_weight += float(weights[row, col])

    if total_weight == 0.0:  # every cell below the floor
        return NEUTRAL_CHROMATICITY
    return tuple(float(v) for v in acc / total_weight)


def measure_chromaticity_trace(
    frames: list[npt.NDArray[Any]],
    face_box: FaceBox,
    *,
    weighting: RegionWeighting | None = None,
    min_channel_sum: float | None = None,
    grid: int | None = None,
) -> list[float]:
    """Per-frame normalised chromaticity within `face_box`, flattened per the module
    docstring's convention ([r,g,b] per frame, each frame's three values summing to 1).

    Pure numpy, no I/O — headless and display-free, so this is directly unit-testable on
    synthetic frames. Defaults come from `config/default.yaml` (`capture.illumination_*`);
    the keyword arguments exist so the calibration script can sweep variants without
    mutating global config, not as a second source of truth.
    """
    from pqbio.config import settings

    cfg = settings.capture
    weighting = weighting if weighting is not None else cfg.illumination_region_weighting
    min_sum = min_channel_sum if min_channel_sum is not None else cfg.illumination_min_channel_sum
    cells = grid if grid is not None else cfg.illumination_centre_grid

    x, y, w, h = face_box
    trace: list[float] = []
    for frame in frames:
        region = frame[y : y + h, x : x + w]
        trace.extend(_frame_chromaticity(region, weighting, min_sum, cells))
    return trace


def estimate_face_box(frame: npt.NDArray[Any]) -> FaceBox:
    """Real face-box detection via `pqbio.detect.face`'s SCRFD model (§5.4 D0) — this
    replaced a permanent fixed-centre-crop placeholder now that Module D exists (see
    PROJECT_SPEC.md's Module D section). Falls back to a geometric centre crop only
    when SCRFD finds no face at all: a frame that genuinely has none, or this project's
    own synthetic test/corpus clips (stylised ellipse patterns SCRFD was never going to
    recognise as a face — see scripts/make_injection_corpus.py). The fallback exists
    purely for graceful degradation on those synthetic frames, never as the primary
    path against real capture.
    """
    from pqbio.detect.face import detect_face_box

    box, _det_score = detect_face_box(frame)
    if box is not None:
        return box
    return _centre_crop_fallback(frame.shape)


def _centre_crop_fallback(frame_shape: tuple[int, int, int]) -> FaceBox:
    h, w = frame_shape[0], frame_shape[1]
    box_w, box_h = w // 2, h // 2
    x = (w - box_w) // 2
    y = (h - box_h) // 3  # slightly above vertical centre — faces sit above a torso
    return (x, y, box_w, box_h)
