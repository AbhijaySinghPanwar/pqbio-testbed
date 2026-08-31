"""Tests for the illumination challenge's derive + measure halves (§5.2 DoD item 3).

`render_challenge_fullscreen` needs a real display and is not exercised here — no
display or webcam is attached in this environment. That half of the DoD item is
outstanding; this file covers everything that's testable without one: the PRF-derived
sequence, and the chromaticity measurement path on synthetic frames with a known,
injected colour sequence (exactly the fallback the DoD item names for this situation).
"""

from __future__ import annotations

import numpy as np

from pqbio.capture.challenge import (
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
    fallback for "no webcam available here". Each frame is solid-filled with one
    palette colour; the measured trace must recover which one, in order.
    """
    frame_shape = (100, 100, 3)
    injected_sequence = [0, 1, 2, 3, 0, 2]  # red, green, blue, white, red, blue
    frames = [np.full(frame_shape, PALETTE_BGR[idx], dtype=np.uint8) for idx in injected_sequence]

    face_box = estimate_face_box(frames[0])  # solid colour: SCRFD finds nothing, falls back
    trace = measure_chromaticity_trace(frames, face_box)

    assert len(trace) == 3 * len(frames)  # flattened [R,G,B] per frame, see module docstring
    for i, palette_idx in enumerate(injected_sequence):
        r, g, b = trace[3 * i], trace[3 * i + 1], trace[3 * i + 2]
        expected_b, expected_g, expected_r = (c / 255.0 for c in PALETTE_BGR[palette_idx])
        assert abs(r - expected_r) < 1e-6
        assert abs(g - expected_g) < 1e-6
        assert abs(b - expected_b) < 1e-6


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
