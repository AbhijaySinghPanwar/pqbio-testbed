"""Module B: capture client package (PROJECT_SPEC.md §5.2).

Owner: Aviral (Krish assists on challenge rendering).

`CameraSource` and `ReplaySource` both implement `FrameSource` and must return the
same `CapturedFrame`/`DeviceMeta` shapes so `bundler.py` is source-agnostic — that's
what "both sources produce byte-identical bundle structures" (§5.2 DoD) means in
practice: one `assemble_bundle()` call site, fed by either source.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

import numpy as np

from pqbio.schemas import DeviceMeta, FrameMeta

__all__ = ["CapturedFrame", "FrameSource", "DeviceMeta", "FrameMeta"]


@dataclass(frozen=True)
class CapturedFrame:
    """One captured frame: raw BGR image (OpenCV convention, HxWx3 uint8) plus the
    per-frame metadata that goes straight into `EvidenceBundle.frame_meta` (§5.2).
    """

    image: np.ndarray
    meta: FrameMeta


class FrameSource(Protocol):
    def capture(self, n_frames: int, fps: float) -> tuple[list[CapturedFrame], DeviceMeta]: ...
