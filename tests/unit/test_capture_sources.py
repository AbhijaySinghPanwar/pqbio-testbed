"""Tests that CameraSource and ReplaySource produce byte-identical bundle structures
(§5.2 DoD item 1).

Neither a real webcam nor a real video file is used here — both `cv2.VideoCapture`
instances are mocked to return the *same* synthetic frame sequence, isolating the
claim under test ("both sources feed pqbio.capture.bundler the same shape") from
camera/codec availability. "Byte-identical" is checked exactly where it's meaningful:
the resulting JPEG-encoded frame bytes (same pixels in, same encoder, so identical
bytes out) and the structural shape of every field. Per-frame sensor telemetry
(exposure/iso/focal) is *not* expected to be byte-identical — ReplaySource reports 0
for those by design (a video file has no exposure/ISO/focus metadata; see
replay_source.py's docstring), which is itself part of the "structurally identical,
content honestly different" contract, not a bug.
"""

from __future__ import annotations

import itertools
from unittest.mock import MagicMock, patch

import cv2
import numpy as np
import pytest

from pqbio.capture.bundler import encode_frame_jpeg
from pqbio.capture.camera import CameraSource
from pqbio.capture.replay_source import ReplaySource
from pqbio.schemas import DeviceMeta, FrameMeta

N_FRAMES = 5
FRAME_SHAPE = (48, 64, 3)


def _synthetic_frames() -> list[np.ndarray]:
    rng = np.random.default_rng(seed=42)
    return [rng.integers(0, 256, size=FRAME_SHAPE, dtype=np.uint8) for _ in range(N_FRAMES)]


def _mock_video_capture(frames: list[np.ndarray]) -> MagicMock:
    mock_cap = MagicMock()
    mock_cap.isOpened.return_value = True
    # Cycle rather than exhaust. A real webcam does not stop returning frames after N
    # reads, and CameraSource legitimately reads more than n_frames: it discards frames
    # while auto-exposure settles before capture starts
    # (`_apply_capture_protocol`). An exhausting iterator made that look like a
    # camera failure.
    reads = itertools.cycle([(True, f) for f in frames])
    mock_cap.read.side_effect = lambda: next(reads)
    mock_cap.get.side_effect = lambda prop: {
        3: FRAME_SHAPE[1],  # CAP_PROP_FRAME_WIDTH
        4: FRAME_SHAPE[0],  # CAP_PROP_FRAME_HEIGHT
    }.get(prop, -1.0)
    return mock_cap


def _exhausting_video_capture(frames: list, n_available: int) -> MagicMock:
    """A camera that stops returning frames partway through — the real failure mode
    `CameraOpenError` exists for."""
    mock_cap = _mock_video_capture(frames)
    reads = iter([(True, f) for f in frames[:n_available]])
    mock_cap.read.side_effect = lambda: next(reads, (False, None))
    return mock_cap


def test_capture_locks_white_balance_and_leaves_exposure_automatic() -> None:
    """The measured capture protocol (§5.2, §14 2026-09-03), asserted rather than assumed.

    Locking exposure too, and locking it at a challenge-lit setpoint, were both measured
    and both scored worse than this — so a regression that "helpfully" locks exposure
    would silently undo a result that cost two sessions of live capture to establish.
    """
    frames = _synthetic_frames()
    mock_cap = _mock_video_capture(frames)

    with patch("cv2.VideoCapture", return_value=mock_cap):
        CameraSource(device_index=0).capture(N_FRAMES, fps=15)

    settings_applied = {call.args[0]: call.args[1] for call in mock_cap.set.call_args_list}
    assert settings_applied[cv2.CAP_PROP_AUTO_WB] == 0, "white balance must be locked"
    assert settings_applied[cv2.CAP_PROP_AUTO_EXPOSURE] == 0.75, (
        "exposure must stay automatic: on the reference sensor manual exposure cannot "
        "reach an operating point where the challenge cast is measurable"
    )
    assert (
        cv2.CAP_PROP_EXPOSURE not in settings_applied
    ), "nothing should pin a manual exposure value"


def test_capture_returns_matching_types_and_frame_count() -> None:
    frames = _synthetic_frames()

    with patch("cv2.VideoCapture", return_value=_mock_video_capture(frames)):
        camera_frames, camera_meta = CameraSource(device_index=0).capture(N_FRAMES, fps=15)
    with patch("cv2.VideoCapture", return_value=_mock_video_capture(frames)):
        replay_frames, replay_meta = ReplaySource("fake-clip.mp4").capture(N_FRAMES, fps=15)

    assert len(camera_frames) == len(replay_frames) == N_FRAMES
    assert isinstance(camera_meta, DeviceMeta)
    assert isinstance(replay_meta, DeviceMeta)
    for cf, rf in zip(camera_frames, replay_frames, strict=True):
        assert isinstance(cf.meta, FrameMeta)
        assert isinstance(rf.meta, FrameMeta)
        assert cf.image.shape == rf.image.shape == FRAME_SHAPE


def test_capture_produces_byte_identical_jpeg_frames_for_identical_pixels() -> None:
    """Same pixels in -> same JPEG bytes out, regardless of which source produced them
    — this is the part of "byte-identical bundle structures" that's literally checkable.
    """
    frames = _synthetic_frames()

    with patch("cv2.VideoCapture", return_value=_mock_video_capture(frames)):
        camera_frames, _ = CameraSource(device_index=0).capture(N_FRAMES, fps=15)
    with patch("cv2.VideoCapture", return_value=_mock_video_capture(frames)):
        replay_frames, _ = ReplaySource("fake-clip.mp4").capture(N_FRAMES, fps=15)

    camera_jpegs = [encode_frame_jpeg(f.image) for f in camera_frames]
    replay_jpegs = [encode_frame_jpeg(f.image) for f in replay_frames]
    assert camera_jpegs == replay_jpegs


def test_camera_error_when_device_stops_returning_frames() -> None:
    """Distinct from "device unavailable": the camera opened, then died mid-capture.
    Needs the exhausting mock now that the normal fake cycles."""
    from pqbio.capture.camera import CameraOpenError

    frames = _synthetic_frames()
    with (
        patch("cv2.VideoCapture", return_value=_exhausting_video_capture(frames, 2)),
        pytest.raises(CameraOpenError),
    ):
        CameraSource(device_index=0).capture(N_FRAMES, fps=15)


def test_camera_open_error_when_device_unavailable() -> None:
    from pqbio.capture.camera import CameraOpenError

    mock_cap = MagicMock()
    mock_cap.isOpened.return_value = False
    with patch("cv2.VideoCapture", return_value=mock_cap), pytest.raises(CameraOpenError):
        CameraSource(device_index=99).capture(N_FRAMES, fps=15)


def test_replay_source_error_when_clip_runs_out_of_frames() -> None:
    from pqbio.capture.replay_source import ReplaySourceError

    frames = _synthetic_frames()
    # The exhausting mock, not the cycling one: a clip that genuinely runs out is the
    # case this error exists for, and a cycling fake camera can never reproduce it.
    with (
        patch("cv2.VideoCapture", return_value=_exhausting_video_capture(frames, 2)),
        pytest.raises(ReplaySourceError),
    ):
        ReplaySource("fake-clip.mp4").capture(N_FRAMES, fps=15)
