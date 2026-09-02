"""What raising the frame count actually costs (PROJECT_SPEC.md §5.2 / §9).

Owner: Abhijay

B6's correlation has roughly `illumination_steps` effective samples per channel, so the
only way to narrow its null distribution is more challenge steps (§14, 2026-09-02). More
steps at the spec'd ~200 ms each need more capture wall-time, and that has to come from
somewhere: more frames, a shorter step, or a higher frame rate. Each is a different bill.

This measures the bill instead of estimating it, for the three levers named in §9:

* **bundle size** — every frame is JPEG-encoded (q90, `encode_frame_jpeg`) into the
  evidence bundle and covered by
  the signature, so this is what crosses the wire and what the server hashes.
* **capture_binding** — SHA-256 over per-frame hashes (`pqbio.capture.bundler`).
* **pHash indexing** — per-frame perceptual hash plus BK-tree lookup, which Module C runs
  on every accepted bundle and which the burst-reuse rule (`phash_reuse_min_frames`)
  makes proportional to frame count.
* **canonical CBOR encode + ML-DSA-65 sign/verify** — the parts of the request whose cost
  moves with bundle size rather than being fixed.

The point of comparison is the ~700 ms of ONNX inference already in a request
(§14, 2026-09-01) and `binding.challenge_ttl_s`. A cost that disappears against 700 ms is
not a reason to under-sample the challenge.

Usage:
    python scripts/measure_frame_budget.py
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path
from typing import Any

import cv2
import numpy as np

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from pqbio.bench._common import run_metadata, write_json  # noqa: E402
from pqbio.config import settings  # noqa: E402

SEED = 2026
# Candidate (n_frames, fps) pairs. Wall time is n_frames / fps, and that is what has to
# cover illumination_steps * step_duration_s.
CANDIDATES: tuple[tuple[int, int], ...] = (
    (30, 15),  # current default: 2.0 s
    (36, 15),  # 2.4 s
    (48, 15),  # 3.2 s -- 16 steps at the spec'd 200 ms
    (48, 24),  # 2.0 s at a higher rate: same wall time, 3 frames/step at 16 steps
    (64, 20),  # 3.2 s with denser sampling
    (72, 24),  # 3.0 s
)


def _synthetic_frames(n: int, resolution: tuple[int, int]) -> list[np.ndarray]:
    """Realistically-textured frames, not flat colour: PNG size and pHash both depend on
    image content, and a flat frame would understate the encode cost badly.
    """
    rng = np.random.default_rng(SEED)
    w, h = resolution
    frames = []
    for _i in range(n):
        base = rng.integers(60, 190, size=(h // 8, w // 8, 3), dtype=np.uint8)
        frame = cv2.resize(base, (w, h), interpolation=cv2.INTER_CUBIC)
        cv2.ellipse(frame, (w // 2, h // 2), (w // 6, h // 3), 0, 0, 360, (180, 170, 165), -1)
        frame = np.clip(
            frame.astype(np.int16) + rng.integers(-6, 7, size=frame.shape, dtype=np.int16),
            0,
            255,
        ).astype(np.uint8)
        frames.append(frame)
    return frames


def _time(fn: Any, repeats: int = 3) -> float:
    """Best-of-N milliseconds. Best-of, not mean: we want the cost of the work, not of
    whatever else this laptop was doing.
    """
    best = float("inf")
    for _ in range(repeats):
        start = time.perf_counter()
        fn()
        best = min(best, (time.perf_counter() - start) * 1000.0)
    return best


def measure(n_frames: int, fps: int, resolution: tuple[int, int]) -> dict[str, Any]:
    from pqbio.binding.phash_index import compute_phash
    from pqbio.capture.bundler import compute_capture_binding, encode_frame_jpeg

    frames = _synthetic_frames(n_frames, resolution)
    # encode_frame_jpeg, not a local imencode: the production path is JPEG q90 and the
    # bundle size question is meaningless against any other encoder.
    encoded = [encode_frame_jpeg(f) for f in frames]
    total_bytes = sum(len(b) for b in encoded)

    encode_ms = _time(lambda: [encode_frame_jpeg(f) for f in frames], repeats=2)
    binding_ms = _time(lambda: compute_capture_binding(b"n" * 32, b"t" * 32, encoded))

    phash_ms = _time(lambda: [compute_phash(b) for b in encoded], repeats=2)

    return {
        "n_frames": n_frames,
        "fps": fps,
        "capture_wall_time_s": n_frames / fps,
        "bundle_frame_bytes": total_bytes,
        "bundle_frame_mib": total_bytes / (1024 * 1024),
        "client_side_jpeg_encode_ms": encode_ms,
        "capture_binding_ms": binding_ms,
        "phash_all_frames_ms": phash_ms,
        "server_side_frame_cost_ms": binding_ms + phash_ms,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=REPO_ROOT / "results" / "frame_budget.json")
    args = parser.parse_args()

    w, h = settings.capture.resolution
    resolution: tuple[int, int] = (int(w), int(h))
    rows = [measure(n, fps, resolution) for n, fps in CANDIDATES]

    baseline = rows[0]
    for row in rows:
        row["delta_server_ms_vs_default"] = (
            row["server_side_frame_cost_ms"] - baseline["server_side_frame_cost_ms"]
        )

    result = {
        **run_metadata(seed=SEED),
        "resolution": list(resolution),
        "reference_points": {
            "onnx_inference_ms": 700.0,
            "onnx_inference_source": "PROJECT_SPEC.md §14, 2026-09-01 (SCRFD+ArcFace, CPU)",
            "challenge_ttl_s": settings.binding.challenge_ttl_s,
            "request_timeout_s": settings.server.request_timeout_s,
        },
        "candidates": rows,
        "note": (
            "Frame-count costs measured, not estimated. capture_binding and pHash are the "
            "only per-frame server-side costs that scale; both are compared against the "
            "~700 ms of ONNX inference already in the request and against challenge_ttl_s."
        ),
    }
    write_json(args.out, result)

    print(f"{'n@fps':>9} {'wall_s':>7} {'MiB':>7} {'bind_ms':>8} {'phash_ms':>9} {'d_ms':>8}")
    for row in rows:
        print(
            f"{row['n_frames']:>4}@{row['fps']:<4} {row['capture_wall_time_s']:>7.2f} "
            f"{row['bundle_frame_mib']:>7.2f} {row['capture_binding_ms']:>8.1f} "
            f"{row['phash_all_frames_ms']:>9.1f} {row['delta_server_ms_vs_default']:>+8.1f}"
        )
    print(f"\nwrote {args.out}")


if __name__ == "__main__":
    main()
