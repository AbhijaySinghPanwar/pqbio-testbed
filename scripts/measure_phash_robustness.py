"""Widen the Module C pHash robustness sweep: how far can a resubmitted frame drift
from the accepted original — via JPEG re-encoding, rescaling, or cropping — before its
perceptual hash no longer lands within `phash_hamming_max` (config, default 6)?

`scripts/measure_phash_fpr.py` measures the *other* side of the same threshold (does it
false-positive on genuinely distinct captures of the same subject); this script measures
whether it still has *margin* to catch a deliberately modified resubmission. Both are
needed to see the real tension the spec calls out (§5.3: "loose enough to catch a
re-encode, tight enough not to flag two genuinely different captures").

Sweeps, against one representative synthetic face-like image (several base images to
avoid conclusions resting on one arbitrary structure):
  - JPEG quality 95 -> 20, step 5, re-encoded from the same pixels.
  - Rescale round-trips at 0.5x, 0.7x, 1.3x (down/up back to original size, or up/down
    for 1.3x), each re-encoded at quality 90.
  - A 5% centre crop (2.5% off each side), resized back to the original dimensions.

Writes results/phash_robustness.json. Prints whether the configured threshold still has
margin over the worst case measured.

Usage:
    python scripts/measure_phash_robustness.py
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

import cv2
import numpy as np

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from pqbio.binding.phash_index import _hamming, compute_phash  # noqa: E402
from pqbio.config import DEFAULT_CONFIG_PATH, settings  # noqa: E402

JPEG_QUALITIES = list(range(95, 19, -5))  # 95, 90, ..., 20
RESCALE_FACTORS = [0.5, 0.7, 1.3]
CENTRE_CROP_FRACTION = 0.05  # 5% total, 2.5% off each side


def _face_like_image(seed: int, size: int = 160) -> np.ndarray:
    rng = np.random.default_rng(seed)
    img = np.full((size, size, 3), 205, dtype=np.uint8)
    skin = (int(rng.integers(140, 225)),) * 3
    face_w = int(rng.integers(size // 3 - 8, size // 3 + 8))
    face_h = int(rng.integers(size // 2 - 15, size // 2 + 5))
    cv2.ellipse(img, (size // 2, size // 2), (face_w, face_h), 0, 0, 360, skin, -1)
    eye_dx = int(rng.integers(15, 26))
    eye_y = size // 2 - int(rng.integers(5, 15))
    cv2.circle(img, (size // 2 - eye_dx, eye_y), 6, (30, 30, 30), -1)
    cv2.circle(img, (size // 2 + eye_dx, eye_y), 6, (30, 30, 30), -1)
    mouth_y = size // 2 + int(rng.integers(20, 32))
    cv2.ellipse(img, (size // 2, mouth_y), (16, 7), 0, 0, 180, (60, 30, 30), 2)
    return img


def _encode(image: np.ndarray, quality: int) -> bytes:
    ok, buf = cv2.imencode(".jpg", image, [cv2.IMWRITE_JPEG_QUALITY, quality])
    if not ok:
        raise RuntimeError("JPEG encoding failed")
    return bytes(buf)


def _rescale_round_trip(image: np.ndarray, factor: float) -> np.ndarray:
    h, w = image.shape[:2]
    if factor <= 1.0:
        # down then back up
        small = cv2.resize(image, (int(w * factor), int(h * factor)), interpolation=cv2.INTER_AREA)
        return cv2.resize(small, (w, h), interpolation=cv2.INTER_LINEAR)
    # up then back down
    big = cv2.resize(image, (int(w * factor), int(h * factor)), interpolation=cv2.INTER_LINEAR)
    return cv2.resize(big, (w, h), interpolation=cv2.INTER_AREA)


def _centre_crop_resized_back(image: np.ndarray, crop_fraction: float) -> np.ndarray:
    h, w = image.shape[:2]
    dx, dy = int(w * crop_fraction / 2), int(h * crop_fraction / 2)
    cropped = image[dy : h - dy, dx : w - dx]
    return cv2.resize(cropped, (w, h), interpolation=cv2.INTER_LINEAR)


def _git_commit() -> str:
    try:
        out = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, stderr=subprocess.DEVNULL
        )
        return out.decode().strip()
    except Exception:
        return "unknown (not a git repository at measurement time)"


def main() -> None:
    threshold = settings.binding.phash_hamming_max
    base_seeds = [1, 2, 3, 4, 5]  # several base images, not one arbitrary structure

    cases: list[dict] = []
    for seed in base_seeds:
        original = _face_like_image(seed)
        original_hash = compute_phash(_encode(original, 95))

        for quality in JPEG_QUALITIES:
            candidate_hash = compute_phash(_encode(original, quality))
            cases.append(
                {
                    "base_seed": seed,
                    "transform": "jpeg_requality",
                    "param": quality,
                    "distance": int(_hamming(original_hash, candidate_hash)),
                }
            )

        for factor in RESCALE_FACTORS:
            rescaled = _rescale_round_trip(original, factor)
            candidate_hash = compute_phash(_encode(rescaled, 90))
            cases.append(
                {
                    "base_seed": seed,
                    "transform": "rescale_round_trip",
                    "param": factor,
                    "distance": int(_hamming(original_hash, candidate_hash)),
                }
            )

        cropped = _centre_crop_resized_back(original, CENTRE_CROP_FRACTION)
        candidate_hash = compute_phash(_encode(cropped, 90))
        cases.append(
            {
                "base_seed": seed,
                "transform": "centre_crop",
                "param": CENTRE_CROP_FRACTION,
                "distance": int(_hamming(original_hash, candidate_hash)),
            }
        )

    distances = [c["distance"] for c in cases]
    worst = max(distances)
    n_within_threshold = sum(1 for d in distances if d <= threshold)

    by_transform: dict[str, dict] = {}
    for transform in {c["transform"] for c in cases}:
        d = [c["distance"] for c in cases if c["transform"] == transform]
        by_transform[transform] = {
            "n": len(d),
            "max_distance": max(d),
            "mean_distance": sum(d) / len(d),
            "n_within_threshold": sum(1 for x in d if x <= threshold),
            "all_within_threshold": all(x <= threshold for x in d),
        }

    result = {
        "git_commit": _git_commit(),
        "config_hash_sha256": hashlib.sha256(DEFAULT_CONFIG_PATH.read_bytes()).hexdigest(),
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "method": "synthetic",
        "caveat": (
            "Same synthetic face-like generator as measure_phash_fpr.py; no licensed face "
            "dataset available yet (PROJECT_SPEC.md §6). Measures robustness (does a modified "
            "resubmission still land within the threshold), the complementary question to "
            "measure_phash_fpr.py's false-positive measurement."
        ),
        "configured_threshold": threshold,
        "jpeg_qualities_swept": JPEG_QUALITIES,
        "rescale_factors_swept": RESCALE_FACTORS,
        "centre_crop_fraction": CENTRE_CROP_FRACTION,
        "n_base_images": len(base_seeds),
        "n_cases": len(cases),
        "worst_case_distance": worst,
        "n_within_threshold": n_within_threshold,
        "all_within_threshold": worst <= threshold,
        "margin_at_configured_threshold": threshold - worst,
        "by_transform": by_transform,
        "cases": cases,
    }

    out_path = REPO_ROOT / "results" / "phash_robustness.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print(f"wrote {out_path}", file=sys.stderr)
    print(f"configured threshold={threshold}, worst-case distance={worst}", file=sys.stderr)
    if worst <= threshold:
        print(
            f"threshold {threshold} still has margin: {threshold - worst} over the worst "
            "case measured",
            file=sys.stderr,
        )
    else:
        print(
            f"threshold {threshold} does NOT cover the worst case measured "
            f"(exceeded by {worst - threshold})",
            file=sys.stderr,
        )


if __name__ == "__main__":
    main()
