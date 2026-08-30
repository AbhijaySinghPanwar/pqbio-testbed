"""Live webcam evidence source (PROJECT_SPEC.md §5.2).

Owner: Aviral

Not exercised against a real webcam in the environment this was written in (headless
dev sandbox, no camera attached) — the §5.2 DoD's live-webcam check is outstanding.
See tests/capture/test_challenge.py for the synthetic-frame stand-in used instead.
"""

from __future__ import annotations

import platform
import time

import cv2

import pqbio
from pqbio.capture import CapturedFrame, FrameMeta
from pqbio.schemas import DeviceMeta


class CameraOpenError(RuntimeError):
    """Raised when the requested camera device cannot be opened or stops delivering
    frames mid-capture. Fail closed: a partial bundle must never be silently accepted.
    """


class CameraSource:
    """FrameSource backed by a live webcam via OpenCV's VideoCapture."""

    def __init__(self, device_index: int = 0, resolution: tuple[int, int] = (1280, 720)) -> None:
        self._device_index = device_index
        self._resolution = resolution

    def capture(self, n_frames: int, fps: float) -> tuple[list[CapturedFrame], DeviceMeta]:
        cap = cv2.VideoCapture(self._device_index)
        if not cap.isOpened():
            raise CameraOpenError(f"could not open camera device {self._device_index}")
        try:
            cap.set(cv2.CAP_PROP_FRAME_WIDTH, self._resolution[0])
            cap.set(cv2.CAP_PROP_FRAME_HEIGHT, self._resolution[1])

            interval_s = 1.0 / fps
            frames: list[CapturedFrame] = []
            for idx in range(n_frames):
                t0 = time.perf_counter()
                ok, image = cap.read()
                if not ok:
                    raise CameraOpenError(
                        f"camera device {self._device_index} stopped returning frames "
                        f"at frame {idx} (requested {n_frames})"
                    )
                frames.append(
                    CapturedFrame(
                        image=image,
                        meta=FrameMeta(
                            capture_ts_ns=time.time_ns(),
                            exposure=max(0.0, float(cap.get(cv2.CAP_PROP_EXPOSURE))),
                            iso=max(0, int(cap.get(cv2.CAP_PROP_ISO_SPEED))),
                            focal=max(0.0, float(cap.get(cv2.CAP_PROP_FOCUS))),
                            sequence_idx=idx,
                        ),
                    )
                )
                sleep_s = interval_s - (time.perf_counter() - t0)
                if sleep_s > 0:
                    time.sleep(sleep_s)

            device_meta = DeviceMeta(
                os=platform.platform(),
                camera_device_name=f"cv2.VideoCapture:{self._device_index}",
                camera_driver_id=str(self._device_index),
                resolution=(
                    int(cap.get(cv2.CAP_PROP_FRAME_WIDTH)),
                    int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT)),
                ),
                codec="raw",
                app_version=pqbio.__version__,
            )
            return frames, device_meta
        finally:
            cap.release()
