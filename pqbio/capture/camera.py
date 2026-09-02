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


# Frames discarded while auto-exposure converges on the scene before capture starts.
# Not a magic number in the config sense -- it is a property of the sensor's AE loop, not
# a tunable of the protocol -- but it is named rather than inlined so it is findable.
_AE_SETTLE_FRAMES = 15


class CameraSource:
    """FrameSource backed by a live webcam via OpenCV's VideoCapture.

    Applies the capture protocol B6 depends on before grabbing frames: white balance
    locked, exposure left automatic. See `_apply_capture_protocol` for why that asymmetry
    is the measured answer rather than the intuitive one.
    """

    def __init__(self, device_index: int = 0, resolution: tuple[int, int] = (1280, 720)) -> None:
        self._device_index = device_index
        self._resolution = resolution

    def _apply_capture_protocol(self, cap: cv2.VideoCapture) -> dict[str, float]:
        """Lock white balance; leave exposure automatic. Measured, not assumed.

        The illumination challenge works by inducing a colour cast, and auto white balance
        spends the capture correcting exactly that — so WB is locked. Auto *exposure* is the
        opposite case: it is what reaches an operating point bright enough for the cast to
        register at all. On the sensor this was developed against, switching exposure to
        manual pins a short exposure that no `CAP_PROP_EXPOSURE` value lifts (0, -1 and -2
        all land at 33/255 in a normally-lit room) while auto reaches 112-169/255.

        Both halves are measured across 8 repeats at four step counts
        (`results/b6_operating_point.json`). Locking both scored below locking WB alone at
        every step count, and so did the "lock at a setpoint chosen while the challenge is
        rendering" protocol proposed in §14 on 2026-09-02 — that idea was tested here and
        lost, so it is not implemented. See §14, 2026-09-03.

        Property read-back over DirectShow is unreliable, so the returned values are
        recorded as evidence of what was *requested*, not proof of what took effect.
        """
        cap.set(cv2.CAP_PROP_AUTO_WB, 0)
        cap.set(cv2.CAP_PROP_AUTO_EXPOSURE, 0.75)  # DSHOW convention: 0.75 = auto
        for _ in range(_AE_SETTLE_FRAMES):  # let auto-exposure converge before frame 0
            cap.read()
        return {
            "auto_wb_readback": float(cap.get(cv2.CAP_PROP_AUTO_WB)),
            "auto_exposure_readback": float(cap.get(cv2.CAP_PROP_AUTO_EXPOSURE)),
        }

    def capture(self, n_frames: int, fps: float) -> tuple[list[CapturedFrame], DeviceMeta]:
        cap = cv2.VideoCapture(self._device_index)
        if not cap.isOpened():
            raise CameraOpenError(f"could not open camera device {self._device_index}")
        try:
            cap.set(cv2.CAP_PROP_FRAME_WIDTH, self._resolution[0])
            cap.set(cv2.CAP_PROP_FRAME_HEIGHT, self._resolution[1])
            self._apply_capture_protocol(cap)

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
