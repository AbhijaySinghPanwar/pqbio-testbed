"""Illumination challenge: derive, render, and measure (PROJECT_SPEC.md §5.2).

Owner: Aviral / Krish

Rendering and measurement are deliberately separable: `render_challenge_fullscreen`
needs a display and is best-effort / unverified in this headless dev environment (no
display or webcam attached here — the §5.2 DoD's live-webcam check is outstanding).
`measure_chromaticity_trace` is pure numpy over a frame array and is fully testable
without either — that's what ReplaySource and tests/capture/test_challenge.py use.

`ChallengeSignal.illumination_trace` (pqbio/schemas.py) is a flat `list[float]`; this
module's convention is 3 consecutive values per frame — [R0,G0,B0, R1,G1,B1, ...],
each channel's mean pixel value normalised to [0, 1] within the face region.
Correlating this trace against the expected sequence (binding check B6, §5.3) is
Module C's job (`pqbio.binding.verify.check_b6_challenge_correlation`) — this module
only derives, renders, and records.
"""

from __future__ import annotations

from typing import Any

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


def render_challenge_fullscreen(sequence: list[int], step_duration_s: float = 0.2) -> None:
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


def measure_chromaticity_trace(frames: list[npt.NDArray[Any]], face_box: FaceBox) -> list[float]:
    """Per-frame mean (R, G, B) pixel value within `face_box`, normalised to [0, 1] and
    flattened per the module docstring's convention. Pure numpy, no I/O — headless and
    display-free, so this is directly unit-testable on synthetic frames.
    """
    x, y, w, h = face_box
    trace: list[float] = []
    for frame in frames:
        region = frame[y : y + h, x : x + w]
        if region.size == 0:
            trace.extend([0.0, 0.0, 0.0])
            continue
        mean_bgr = region.reshape(-1, 3).mean(axis=0)
        mean_rgb = mean_bgr[::-1] / 255.0  # OpenCV frames are BGR; trace is R,G,B
        trace.extend(float(v) for v in mean_rgb)
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
