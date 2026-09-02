"""End-to-end test of `python -m pqbio.capture --source replay ...` (§5.2 DoD item 4).

Uses a small synthetic clip written with cv2.VideoWriter (no webcam needed) and runs
the CLI as a real subprocess, exactly as a user would invoke it.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import cv2
import numpy as np
import pytest

from pqbio.config import settings
from pqbio.schemas import canonical_cbor_decode


@pytest.fixture
def synthetic_clip(tmp_path: Path) -> Path:
    clip_path = tmp_path / "clip.mp4"
    fourcc = cv2.VideoWriter_fourcc(*"mp4v")
    writer = cv2.VideoWriter(str(clip_path), fourcc, 15.0, (64, 48))
    assert writer.isOpened()
    for i in range(60):  # comfortably more than settings.capture.n_frames (30)
        frame = np.full((48, 64, 3), (i % 255, 100, 50), dtype=np.uint8)
        writer.write(frame)
    writer.release()
    return clip_path


def test_cli_replay_source_produces_valid_signed_bundle(
    synthetic_clip: Path, tmp_path: Path
) -> None:
    out_path = tmp_path / "bundle.cbor"
    result = subprocess.run(
        [
            sys.executable,
            "-W",
            "ignore",
            "-m",
            "pqbio.capture",
            "--source",
            "replay",
            "--clip",
            str(synthetic_clip),
            "--out",
            str(out_path),
        ],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, result.stderr
    assert out_path.is_file()

    decoded = canonical_cbor_decode(out_path.read_bytes())
    assert decoded["device_id"] == "cli-demo-device"
    # From config, not a literal: capture.n_frames moved 30 -> 48 when the challenge
    # went to 12 steps (§14, 2026-09-03), and a hardcoded copy here just breaks.
    assert len(decoded["frames"]) == settings.capture.n_frames
    assert len(decoded["bundle_digest"]) == 32
    assert len(decoded["signature"]) > 0
    assert len(decoded["capture_binding"]) == 32
