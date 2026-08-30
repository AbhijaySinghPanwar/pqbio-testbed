"""Measure the seen-evidence pHash index's false-positive rate (PROJECT_SPEC.md §5.3
DoD: "false-positive rate on genuine distinct captures of the same subject is measured
and reported").

**No licensed dataset exists yet** (see PROJECT_SPEC.md §6), so this generates
synthetic "distinct captures of the same simulated subject": a deterministic face-like
base pattern per subject (skin tone, face proportions), with per-capture jitter
(translation, rotation, brightness/contrast, sensor noise, JPEG quality) meant to
approximate — not reproduce — the variation between two real photos of the same
person. **This number must be re-measured on real data once datasets land (§6);
treat it as a plausibility check on the configured threshold, not a validated FPR.**

Writes results/binding_fpr.json: for a range of candidate Hamming-distance thresholds,
the within-subject false-positive rate (distinct captures of the same synthetic subject
wrongly flagged as reused) and the cross-subject separation, so the threshold tension
noted in the spec (loose enough to catch a re-encode, tight enough not to flag two
genuinely different captures) is visible as data, not asserted.

Usage:
    python scripts/measure_phash_fpr.py [--subjects 30] [--captures-per-subject 10]
"""

from __future__ import annotations

import argparse
import hashlib
import itertools
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

CANDIDATE_THRESHOLDS = [2, 4, 6, 8, 10, 12, 16, 20]


def _subject_base_image(subject_seed: int, size: int = 160) -> np.ndarray:
    """Deterministic face-like pattern for one synthetic subject."""
    rng = np.random.default_rng(subject_seed)
    img = np.full((size, size, 3), 205, dtype=np.uint8)
    skin = (int(rng.integers(140, 225)),) * 3
    face_w = int(rng.integers(size // 3 - 8, size // 3 + 8))
    face_h = int(rng.integers(size // 2 - 15, size // 2 + 5))
    cv2.ellipse(img, (size // 2, size // 2), (face_w, face_h), 0, 0, 360, skin, -1)
    eye_dx = int(rng.integers(15, 26))
    eye_y = size // 2 - int(rng.integers(5, 15))
    eye_color = (30, 30, 30)
    cv2.circle(img, (size // 2 - eye_dx, eye_y), 6, eye_color, -1)
    cv2.circle(img, (size // 2 + eye_dx, eye_y), 6, eye_color, -1)
    mouth_y = size // 2 + int(rng.integers(20, 32))
    cv2.ellipse(img, (size // 2, mouth_y), (16, 7), 0, 0, 180, (60, 30, 30), 2)
    return img


def _jittered_capture(
    base: np.ndarray, capture_seed: int, jpeg_quality_range: tuple[int, int]
) -> bytes:
    """One simulated distinct capture of the same subject: small pose/translation
    jitter, brightness/contrast variation, sensor noise, then JPEG-encoded — the kind
    of variation two real photos of the same person, taken moments apart, would have.
    """
    rng = np.random.default_rng(capture_seed)
    h, w = base.shape[:2]

    angle = float(rng.uniform(-6, 6))
    tx, ty = float(rng.uniform(-4, 4)), float(rng.uniform(-4, 4))
    scale = float(rng.uniform(0.96, 1.04))
    matrix = cv2.getRotationMatrix2D((w / 2, h / 2), angle, scale)
    matrix[0, 2] += tx
    matrix[1, 2] += ty
    warped = cv2.warpAffine(base, matrix, (w, h), borderMode=cv2.BORDER_REPLICATE)

    brightness = rng.uniform(-15, 15)
    contrast = rng.uniform(0.9, 1.1)
    adjusted = np.clip(warped.astype(np.float32) * contrast + brightness, 0, 255).astype(np.uint8)

    noise = rng.normal(0, 4, adjusted.shape).astype(np.float32)
    noisy = np.clip(adjusted.astype(np.float32) + noise, 0, 255).astype(np.uint8)

    quality = int(rng.integers(*jpeg_quality_range))
    ok, buf = cv2.imencode(".jpg", noisy, [cv2.IMWRITE_JPEG_QUALITY, quality])
    if not ok:
        raise RuntimeError("JPEG encoding failed")
    return bytes(buf)


def _git_commit() -> str:
    try:
        out = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, stderr=subprocess.DEVNULL
        )
        return out.decode().strip()
    except Exception:
        return "unknown (not a git repository at measurement time)"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--subjects", type=int, default=30)
    parser.add_argument("--captures-per-subject", type=int, default=10)
    parser.add_argument("--seed", type=int, default=1234)
    parser.add_argument("--out", type=Path, default=REPO_ROOT / "results" / "binding_fpr.json")
    args = parser.parse_args()

    rng = np.random.default_rng(args.seed)
    subject_seeds = rng.integers(0, 2**31 - 1, size=args.subjects)

    print(
        f"generating {args.subjects} synthetic subjects x {args.captures_per_subject} "
        "distinct captures each...",
        file=sys.stderr,
    )
    hashes_per_subject: list[list[str]] = []
    for subject_seed in subject_seeds:
        base = _subject_base_image(int(subject_seed))
        capture_seeds = rng.integers(0, 2**31 - 1, size=args.captures_per_subject)
        hashes = [compute_phash(_jittered_capture(base, int(cs), (60, 96))) for cs in capture_seeds]
        hashes_per_subject.append(hashes)

    # Within-subject pairs: genuinely different captures of the SAME synthetic subject.
    # A match here at the configured threshold is exactly the false positive §5.3 asks
    # about — a real distinct capture wrongly flagged as reused evidence.
    within_subject_distances: list[int] = []
    for hashes in hashes_per_subject:
        for h_a, h_b in itertools.combinations(hashes, 2):
            within_subject_distances.append(_hamming(h_a, h_b))

    # Cross-subject pairs (one hash per subject, all pairs of subjects) — context for
    # the separation margin, not itself part of the FPR definition.
    first_hash_per_subject = [hashes[0] for hashes in hashes_per_subject]
    cross_subject_distances: list[int] = [
        _hamming(h_a, h_b) for h_a, h_b in itertools.combinations(first_hash_per_subject, 2)
    ]

    within_arr = np.array(within_subject_distances)
    cross_arr = np.array(cross_subject_distances)

    per_threshold = {}
    for t in CANDIDATE_THRESHOLDS:
        per_threshold[str(t)] = {
            "within_subject_fpr": float(np.mean(within_arr <= t)),
            "cross_subject_flag_rate": float(np.mean(cross_arr <= t)),
        }

    configured_threshold = settings.binding.phash_hamming_max
    result = {
        "git_commit": _git_commit(),
        "config_hash_sha256": hashlib.sha256(DEFAULT_CONFIG_PATH.read_bytes()).hexdigest(),
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "method": "synthetic",
        "caveat": (
            "No licensed face dataset is available yet (PROJECT_SPEC.md §6). Subjects and "
            "captures are synthetically generated (deterministic face-like base pattern per "
            "subject, jittered per capture: rotation, translation, scale, brightness/"
            "contrast, sensor noise, JPEG quality). This measurement is a plausibility check "
            "on the configured Hamming threshold, not a validated false-positive rate — "
            "re-measure on real data once datasets land."
        ),
        "n_subjects": args.subjects,
        "n_captures_per_subject": args.captures_per_subject,
        "n_within_subject_pairs": len(within_subject_distances),
        "n_cross_subject_pairs": len(cross_subject_distances),
        "within_subject_distance": {
            "mean": float(np.mean(within_arr)),
            "min": int(np.min(within_arr)),
            "max": int(np.max(within_arr)),
            "p50": float(np.percentile(within_arr, 50)),
            "p95": float(np.percentile(within_arr, 95)),
        },
        "cross_subject_distance": {
            "mean": float(np.mean(cross_arr)),
            "min": int(np.min(cross_arr)),
            "p50": float(np.percentile(cross_arr, 50)),
        },
        "configured_threshold": configured_threshold,
        "configured_threshold_within_subject_fpr": float(
            np.mean(within_arr <= configured_threshold)
        ),
        "per_threshold": per_threshold,
    }

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {args.out}", file=sys.stderr)
    print(
        f"configured threshold={configured_threshold}: "
        f"within-subject FPR={result['configured_threshold_within_subject_fpr']:.4f}",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
