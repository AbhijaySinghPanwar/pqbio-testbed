"""Tests for the illumination challenge's derive + measure halves (§5.2 DoD item 3).

`render_challenge_fullscreen` needs a real display and is not exercised here; that half
is covered by `scripts/live_challenge_check.py`, which needs a sensor and a screen. This
file covers what is testable headlessly: the PRF-derived sequence, and the chromaticity
measurement path on synthetic frames with a known injected colour sequence.

**These tests were rewritten on 2026-09-02 and the change is not cosmetic.** They
previously asserted that a solid white frame measured (1.0, 1.0, 1.0) — which encoded the
spec defect §14 records, since `measure_chromaticity_trace` was returning absolute
per-channel brightness under the name "chromaticity". Chromaticity is luminance-
normalised by definition, so white is the *neutral* point (1/3, 1/3, 1/3), not a maximum.
Several tests here exist specifically to stop that regressing: luminance invariance, the
neutrality of white, and the near-black denominator guard.
"""

from __future__ import annotations

import numpy as np

from pqbio.capture.challenge import (
    NEUTRAL_CHROMATICITY,
    PALETTE_BGR,
    derive_illumination_sequence,
    estimate_face_box,
    measure_chromaticity_trace,
)


def test_derive_illumination_sequence_is_deterministic_per_nonce() -> None:
    nonce = b"n" * 32
    assert derive_illumination_sequence(nonce, 8) == derive_illumination_sequence(nonce, 8)


def test_derive_illumination_sequence_differs_across_nonces() -> None:
    seq_a = derive_illumination_sequence(b"a" * 32, 16)
    seq_b = derive_illumination_sequence(b"b" * 32, 16)
    assert seq_a != seq_b


def test_derive_illumination_sequence_indices_in_palette_range() -> None:
    seq = derive_illumination_sequence(b"n" * 32, 100)
    assert all(0 <= idx < len(PALETTE_BGR) for idx in seq)


def test_measure_chromaticity_trace_recovers_injected_colour_sequence() -> None:
    """Synthetic frames with a known injected colour per frame — the DoD's explicit
    fallback for "no webcam available here". Each frame is solid-filled with one palette
    colour; the measured trace must recover which one, in order, as *chromaticity*.
    """
    frame_shape = (100, 100, 3)
    injected_sequence = [0, 1, 2, 3, 0, 2]  # red, green, blue, white, red, blue
    frames = [np.full(frame_shape, PALETTE_BGR[idx], dtype=np.uint8) for idx in injected_sequence]

    face_box = estimate_face_box(frames[0])  # solid colour: SCRFD finds nothing, falls back
    trace = measure_chromaticity_trace(frames, face_box)

    assert len(trace) == 3 * len(frames)  # flattened [r,g,b] per frame, see module docstring
    for i, palette_idx in enumerate(injected_sequence):
        r, g, b = trace[3 * i], trace[3 * i + 1], trace[3 * i + 2]
        blue, green, red = PALETTE_BGR[palette_idx]
        total = float(red + green + blue)
        assert abs(r - red / total) < 1e-6
        assert abs(g - green / total) < 1e-6
        assert abs(b - blue / total) < 1e-6
        assert abs((r + g + b) - 1.0) < 1e-9  # chromaticity sums to 1 by construction


def test_white_measures_as_neutral_not_as_maximum() -> None:
    """White induces no hue shift, so its chromaticity is the neutral point.

    This is the assertion the pre-2026-09-02 code failed. It read white as (1, 1, 1) — a
    maximum in every channel — which is what made B6 correlate a luminance ramp instead
    of a colour sequence on real sensor data (PROJECT_SPEC.md §14).
    """
    white = np.full((40, 40, 3), 255, dtype=np.uint8)
    trace = measure_chromaticity_trace([white], (0, 0, 40, 40))
    assert all(abs(v - 1 / 3) < 1e-9 for v in trace)


def test_measure_chromaticity_trace_is_luminance_invariant() -> None:
    """The same hue at two very different brightnesses must measure identically.

    This is the property "chromaticity" names and the old formulation lacked. On a real
    sensor the scene's overall illumination drifts constantly — panel auto-brightness,
    the subject moving — and none of that should move a hue measurement.
    """
    hue_bgr = (60, 90, 150)  # a warm, skin-ish tone
    bright = np.full((40, 40, 3), hue_bgr, dtype=np.uint8)
    dim = (bright.astype(np.float32) * 0.35).astype(np.uint8)

    bright_trace = measure_chromaticity_trace([bright], (0, 0, 40, 40))
    dim_trace = measure_chromaticity_trace([dim], (0, 0, 40, 40))

    assert float(dim.mean()) < 0.5 * float(bright.mean())  # genuinely much darker
    for a, b in zip(bright_trace, dim_trace, strict=True):
        assert abs(a - b) < 0.01


def test_near_black_region_reads_neutral_rather_than_noise() -> None:
    """The guarded denominator: below the floor there is no hue, so the trace reports
    the "no information" value instead of amplifying sensor noise into a fake signal.

    Reporting neutral is the fail-closed direction — a constant contributes nothing to
    B6's correlation, so a dark capture cannot accidentally correlate its way to a pass.
    """
    black = np.zeros((40, 40, 3), dtype=np.uint8)
    almost_black = np.full((40, 40, 3), 2, dtype=np.uint8)

    for frame in (black, almost_black):
        for weighting in ("uniform", "centre"):
            trace = measure_chromaticity_trace([frame], (0, 0, 40, 40), weighting=weighting)
            assert all(np.isfinite(trace))
            assert tuple(trace) == NEUTRAL_CHROMATICITY


def test_centre_weighting_downweights_the_periphery() -> None:
    """The two weightings must actually differ: a colour confined to the border should
    move the uniform measurement more than the centre-weighted one.
    """
    frame = np.full((80, 80, 3), (100, 100, 100), dtype=np.uint8)
    frame[:12, :] = (255, 0, 0)  # blue band along the top edge only
    frame[-12:, :] = (255, 0, 0)

    uniform = measure_chromaticity_trace([frame], (0, 0, 80, 80), weighting="uniform")
    centre = measure_chromaticity_trace([frame], (0, 0, 80, 80), weighting="centre")

    assert uniform[2] > centre[2]  # peripheral blue pulls the uniform b higher


def test_measure_chromaticity_trace_distinguishes_face_box_region() -> None:
    """A colour outside the face box must not leak into the measured trace."""
    frame_shape = (100, 100, 3)
    face_box = (10, 10, 20, 20)  # small box in the corner

    frame = np.zeros(frame_shape, dtype=np.uint8)
    frame[:, :] = (0, 0, 0)  # background: black
    frame[10:30, 10:30] = (0, 0, 255)  # inside the face box: red (BGR)

    trace = measure_chromaticity_trace([frame], face_box)
    r, g, b = trace
    assert abs(r - 1.0) < 1e-6
    assert abs(g - 0.0) < 1e-6
    assert abs(b - 0.0) < 1e-6


def test_estimate_face_box_fallback_stays_within_frame() -> None:
    """No face in a solid-colour frame -> falls back to the geometric centre crop,
    which must stay within bounds.
    """
    frame_shape = (720, 1280, 3)
    frame = np.full(frame_shape, 128, dtype=np.uint8)
    x, y, w, h = estimate_face_box(frame)
    assert 0 <= x < x + w <= frame_shape[1]
    assert 0 <= y < y + h <= frame_shape[0]


def test_estimate_face_box_uses_real_detection_when_a_face_is_present() -> None:
    """A real photographed face must be detected for real (SCRFD box roughly
    (180, 58, 89, 120) for this image — see tests/unit/_face_fixtures.py), not fall
    back to the geometric centre crop (which would be roughly (320, 85, 256, 256)).
    """
    from _face_fixtures import _astronaut_bgr

    frame = _astronaut_bgr()
    x, y, w, h = estimate_face_box(frame)
    assert 150 <= x <= 210
    assert 30 <= y <= 90
    assert 60 <= w <= 120
    assert 90 <= h <= 150
    assert 0 <= x < x + w <= frame.shape[1]
    assert 0 <= y < y + h <= frame.shape[0]
