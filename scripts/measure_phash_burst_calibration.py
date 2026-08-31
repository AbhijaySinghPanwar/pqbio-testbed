"""Calibrate the N-of-burst evidence-reuse rule (PROJECT_SPEC.md §5.3, §14's
"known mitigation" amendment, now promoted from recorded-but-not-implemented to
implemented).

§14 established that no single per-frame Hamming threshold serves both goals at once:
threshold 6 already had a 12.7% synthetic within-subject false-positive rate, while a
widened robustness sweep showed aggressive JPEG re-encoding (quality <=30) can push the
same-media distance past 6 (false negatives). The fix isn't a better threshold value —
it's changing what "reuse" means: instead of flagging on *any one* frame matching within
distance D, flag only when *at least N* of the submitted burst's frames each match
something in the stored index within D. A genuine reuse (the same media, possibly
re-encoded) trips this on most/all of its frames; a distinct genuine capture of the same
subject colliding on a frame or two by chance should not.

Two phases, run in order (the second depends on the first's output):

**Phase A — find the floor for D.** Re-run the Module C robustness sweep (same
transforms as scripts/measure_phash_robustness.py: JPEG requality 95->20, rescale
round-trips at 0.5x/0.7x/1.3x, a 5% centre crop) and take the worst-case distance across
every case as D's floor — the smallest D that still catches every modified-resubmission
case measured. Going below this floor would reopen the exact robustness gap §14 already
found.

**Phase B — sweep N at that D.** Generate synthetic multi-frame capture *bursts*, not
single images: a per-session jitter (this particular verification attempt's pose/
lighting — same magnitude as measure_phash_fpr.py's single-frame jitter) plus a much
smaller per-frame jitter on top (natural frame-to-frame variation within one ~2s
capture). For many pairs of *distinct sessions of the same synthetic subject*, count how
many of the new burst's frames land within D of *some* frame in the "stored" burst, for
every N from 1 to the burst size. FPR(N) is the fraction of session-pairs where that
count reaches N. Report the curve and pick the smallest N with FPR comfortably below 1%.

Writes results/phash_burst_calibration.json. Does **not** write config/default.yaml
itself — the chosen D and N are reviewed and hand-committed there, with the reasoning
recorded as a dated PROJECT_SPEC.md §14 amendment, same as every other calibration
decision this project has made.

Usage:
    python scripts/measure_phash_burst_calibration.py
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from datetime import UTC, datetime
from itertools import combinations
from pathlib import Path

import cv2
import numpy as np

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(SCRIPTS_DIR))

import measure_phash_robustness as robustness  # noqa: E402

from pqbio.binding.phash_index import _hamming, compute_phash  # noqa: E402
from pqbio.config import DEFAULT_CONFIG_PATH  # noqa: E402

N_BASE_IMAGES_FOR_D = 5  # matches measure_phash_robustness.py's own default
N_SUBJECTS_FOR_N = 30
N_SESSIONS_PER_SUBJECT = 5
BURST_SIZE = 30  # matches config/default.yaml's capture.n_frames


def _git_commit() -> str:
    try:
        out = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, stderr=subprocess.DEVNULL
        )
        return out.decode().strip()
    except Exception:
        return "unknown (not a git repository at run time)"


# --------------------------------------------------------------------------------------
# Phase A: D floor, by re-running the robustness sweep
# --------------------------------------------------------------------------------------


def _find_d_floor() -> tuple[int, dict]:
    base_seeds = [1, 2, 3, 4, 5][:N_BASE_IMAGES_FOR_D]
    cases: list[dict] = []
    for seed in base_seeds:
        original = robustness._face_like_image(seed)
        original_hash = compute_phash(robustness._encode(original, 95))

        for quality in robustness.JPEG_QUALITIES:
            candidate_hash = compute_phash(robustness._encode(original, quality))
            cases.append(
                {
                    "base_seed": seed,
                    "transform": "jpeg_requality",
                    "param": quality,
                    "distance": int(_hamming(original_hash, candidate_hash)),
                }
            )
        for factor in robustness.RESCALE_FACTORS:
            rescaled = robustness._rescale_round_trip(original, factor)
            candidate_hash = compute_phash(robustness._encode(rescaled, 90))
            cases.append(
                {
                    "base_seed": seed,
                    "transform": "rescale_round_trip",
                    "param": factor,
                    "distance": int(_hamming(original_hash, candidate_hash)),
                }
            )
        cropped = robustness._centre_crop_resized_back(original, robustness.CENTRE_CROP_FRACTION)
        candidate_hash = compute_phash(robustness._encode(cropped, 90))
        cases.append(
            {
                "base_seed": seed,
                "transform": "centre_crop",
                "param": robustness.CENTRE_CROP_FRACTION,
                "distance": int(_hamming(original_hash, candidate_hash)),
            }
        )

    d_floor = max(c["distance"] for c in cases)
    return d_floor, {"n_cases": len(cases), "cases": cases}


# --------------------------------------------------------------------------------------
# Phase B: FPR(N) at D = d_floor, over synthetic multi-frame bursts
# --------------------------------------------------------------------------------------


def _subject_base_image(subject_seed: int, size: int = 160) -> np.ndarray:
    rng = np.random.default_rng(subject_seed)
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


def _burst_capture_hashes(base: np.ndarray, session_seed: int, n_frames: int) -> list[str]:
    """One simulated `n_frames`-frame capture burst: a session-level jitter (this
    particular verification attempt — same magnitude as measure_phash_fpr.py's
    single-frame jitter), plus a much smaller per-frame jitter on top (natural
    frame-to-frame variation within one ~2s capture, not a second independent session).
    """
    session_rng = np.random.default_rng(session_seed)
    h, w = base.shape[:2]
    session_angle = float(session_rng.uniform(-6, 6))
    session_tx, session_ty = float(session_rng.uniform(-4, 4)), float(session_rng.uniform(-4, 4))
    session_scale = float(session_rng.uniform(0.96, 1.04))
    session_brightness = float(session_rng.uniform(-15, 15))
    session_contrast = float(session_rng.uniform(0.9, 1.1))

    hashes: list[str] = []
    for i in range(n_frames):
        frame_rng = np.random.default_rng(session_seed * 100_003 + i)
        angle = session_angle + float(frame_rng.uniform(-0.3, 0.3))
        tx = session_tx + float(frame_rng.uniform(-0.3, 0.3))
        ty = session_ty + float(frame_rng.uniform(-0.3, 0.3))
        scale = session_scale + float(frame_rng.uniform(-0.003, 0.003))
        matrix = cv2.getRotationMatrix2D((w / 2, h / 2), angle, scale)
        matrix[0, 2] += tx
        matrix[1, 2] += ty
        warped = cv2.warpAffine(base, matrix, (w, h), borderMode=cv2.BORDER_REPLICATE)

        brightness = session_brightness + float(frame_rng.uniform(-1.5, 1.5))
        contrast = session_contrast + float(frame_rng.uniform(-0.01, 0.01))
        adjusted = np.clip(warped.astype(np.float32) * contrast + brightness, 0, 255).astype(
            np.uint8
        )
        noise = frame_rng.normal(0, 3, adjusted.shape).astype(np.float32)
        noisy = np.clip(adjusted.astype(np.float32) + noise, 0, 255).astype(np.uint8)

        quality = int(frame_rng.integers(85, 101))
        ok, buf = cv2.imencode(".jpg", noisy, [cv2.IMWRITE_JPEG_QUALITY, quality])
        if not ok:
            raise RuntimeError("JPEG encoding failed")
        hashes.append(compute_phash(bytes(buf)))
    return hashes


def _matching_frame_count(
    new_hashes: list[str], stored_hashes: list[str], max_distance: int
) -> int:
    """How many of `new_hashes` have >=1 match within `max_distance` against
    `stored_hashes` — mirrors PhashIndex.check_reuse's per-frame semantics, aggregated.
    """
    count = 0
    for h in new_hashes:
        if any(_hamming(h, stored) <= max_distance for stored in stored_hashes):
            count += 1
    return count


def _sweep_n(d_floor: int) -> dict:
    rng = np.random.default_rng(9999)
    subject_seeds = rng.integers(0, 2**31 - 1, size=N_SUBJECTS_FOR_N)

    # matching_frame_count for every (subject, session-pair)
    match_counts: list[int] = []
    for subject_seed in subject_seeds:
        base = _subject_base_image(int(subject_seed))
        session_seeds = rng.integers(0, 2**31 - 1, size=N_SESSIONS_PER_SUBJECT)
        session_hashes = [_burst_capture_hashes(base, int(s), BURST_SIZE) for s in session_seeds]
        for a, b in combinations(range(N_SESSIONS_PER_SUBJECT), 2):
            match_counts.append(
                _matching_frame_count(session_hashes[a], session_hashes[b], d_floor)
            )

    match_counts_arr = np.array(match_counts)
    n_pairs = len(match_counts)
    fpr_by_n = {str(n): float(np.mean(match_counts_arr >= n)) for n in range(1, BURST_SIZE + 1)}
    return {
        "n_subjects": N_SUBJECTS_FOR_N,
        "n_sessions_per_subject": N_SESSIONS_PER_SUBJECT,
        "n_session_pairs": n_pairs,
        "burst_size": BURST_SIZE,
        "match_count_distribution": {
            "mean": float(np.mean(match_counts_arr)),
            "max": int(np.max(match_counts_arr)),
            "p50": float(np.percentile(match_counts_arr, 50)),
            "p95": float(np.percentile(match_counts_arr, 95)),
        },
        "fpr_by_n": fpr_by_n,
    }


def main() -> None:
    print("phase A: finding D floor via the robustness sweep...", file=sys.stderr)
    d_floor, phase_a_detail = _find_d_floor()
    print(f"  D floor = {d_floor}", file=sys.stderr)

    print(
        f"phase B: sweeping N at D={d_floor} over {N_SUBJECTS_FOR_N} subjects x "
        f"{N_SESSIONS_PER_SUBJECT} sessions x {BURST_SIZE}-frame bursts...",
        file=sys.stderr,
    )
    phase_b = _sweep_n(d_floor)

    # smallest N with FPR comfortably below 1% (strictly less than 1%, and the value
    # stays below 1% for every larger N too, since match counts only get sparser as N
    # rises among the same session-pairs -- monotonically non-increasing FPR(N)).
    chosen_n = None
    for n in range(1, BURST_SIZE + 1):
        if phase_b["fpr_by_n"][str(n)] < 0.01:
            chosen_n = n
            break

    result = {
        "git_commit": _git_commit(),
        "config_hash_sha256": hashlib.sha256(DEFAULT_CONFIG_PATH.read_bytes()).hexdigest(),
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "method": "synthetic",
        "caveat": (
            "No licensed face dataset is available yet (PROJECT_SPEC.md §6). Both phases use "
            "the same synthetic face-like generator as measure_phash_fpr.py / "
            "measure_phash_robustness.py. Phase B's within-subject FPR is a plausibility check "
            "on the chosen N, not a validated false-positive rate -- re-measure on real "
            "multi-session captures once datasets land, and note N may need raising if real "
            "within-subject collisions run higher than these jittered synthetic ones."
        ),
        "phase_a_d_floor": {
            "d_floor": d_floor,
            "reasoning": (
                "Smallest per-frame Hamming distance that still covers every re-encode/"
                "rescale/crop case measured in this run (the same worst-case-distance "
                "definition scripts/measure_phash_robustness.py reports)."
            ),
            **phase_a_detail,
        },
        "phase_b_n_sweep": phase_b,
        "chosen_d": d_floor,
        "chosen_n": chosen_n,
        "chosen_n_reasoning": (
            f"Smallest N in [1, {BURST_SIZE}] where the synthetic within-subject FPR at "
            f"D={d_floor} is strictly below 1%."
            if chosen_n is not None
            else f"No N up to {BURST_SIZE} reached FPR < 1% in this run; see fpr_by_n."
        ),
    }

    out_path = REPO_ROOT / "results" / "phash_burst_calibration.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(result, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    print(f"wrote {out_path}", file=sys.stderr)
    print(f"chosen D={d_floor}, chosen N={chosen_n}", file=sys.stderr)


if __name__ == "__main__":
    main()
