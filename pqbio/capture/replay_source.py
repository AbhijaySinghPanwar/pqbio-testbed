"""Dataset-clip-as-camera evidence source (PROJECT_SPEC.md §5.2).

Owner: Aviral

This is how labelled attack data reaches the real pipeline (§5.2, §7) rather than being
tested against detectors in isolation — treat it as first-class, not a test double.
"""

from __future__ import annotations

import platform
import time
from pathlib import Path

import cv2

import pqbio
from pqbio.capture import CapturedFrame, FrameMeta
from pqbio.schemas import DeviceMeta


class ReplaySourceError(RuntimeError):
    """Raised when the clip cannot be opened or runs out of frames before `n_frames`
    is reached. Fail closed: a partial bundle must never be silently accepted.
    """


class ReplaySource:
    """FrameSource backed by a pre-recorded video clip, presented as if it were a live
    camera. Sensor telemetry a video file cannot carry (exposure/iso/focal) is reported
    as 0 rather than fabricated: a real capture always has these values and a replay
    never does, and that gap is itself a signal for D5 injection detection later
    (§5.4), not something to paper over here.
    """

    def __init__(self, clip_path: str | Path) -> None:
        self._clip_path = Path(clip_path)

    def capture(self, n_frames: int, fps: float) -> tuple[list[CapturedFrame], DeviceMeta]:
        cap = cv2.VideoCapture(str(self._clip_path))
        if not cap.isOpened():
            raise ReplaySourceError(f"could not open clip: {self._clip_path}")
        try:
            interval_s = 1.0 / fps
            frames: list[CapturedFrame] = []
            for idx in range(n_frames):
                t0 = time.perf_counter()
                ok, image = cap.read()
                if not ok:
                    raise ReplaySourceError(
                        f"clip {self._clip_path} ran out of frames at index {idx} "
                        f"(requested {n_frames})"
                    )
                frames.append(
                    CapturedFrame(
                        image=image,
                        meta=FrameMeta(
                            capture_ts_ns=time.time_ns(),
                            exposure=0.0,
                            iso=0,
                            focal=0.0,
                            sequence_idx=idx,
                        ),
                    )
                )
                sleep_s = interval_s - (time.perf_counter() - t0)
                if sleep_s > 0:
                    time.sleep(sleep_s)

            device_meta = DeviceMeta(
                os=platform.platform(),
                camera_device_name=f"replay:{self._clip_path.name}",
                camera_driver_id="replay_source",
                resolution=(
                    int(cap.get(cv2.CAP_PROP_FRAME_WIDTH)),
                    int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT)),
                ),
                codec="replay",
                app_version=pqbio.__version__,
            )
            return frames, device_meta
        finally:
            cap.release()
