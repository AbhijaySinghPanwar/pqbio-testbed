"""Tests for pqbio.binding.phash_index (§5.3 DoD: reuse check + restart durability)."""

from __future__ import annotations

from pathlib import Path

import cv2
import numpy as np

from pqbio.binding.phash_index import BKTree, PhashIndex, compute_phash
from pqbio.config import settings


def _synthetic_face_like_image(seed: int, size: int = 128) -> np.ndarray:
    """A deterministic, structured (not uniform-noise) synthetic "face-like" pattern:
    perceptual hashing is DCT-based and largely blind to uniform random noise, so a
    flat-noise image would make every test here trivially pass or fail for the wrong
    reason. A face-like ellipse + eyes + mouth gives the low-frequency structure phash
    actually keys on.

    Varies *structure* (ellipse size, eye spacing, mouth position), not just skin
    tone, per seed — an earlier version of this fixture only randomised tone, which
    phash (coarse, low-frequency) barely responds to: every seed pair collided at
    distance <=10, making it useless for a "genuinely distinct subjects" test. Matches
    the generator shape already used in scripts/measure_phash_fpr.py and friends.
    """
    rng = np.random.default_rng(seed)
    img = np.full((size, size, 3), 200, dtype=np.uint8)  # light background
    skin = (int(rng.integers(150, 220)),) * 3
    face_w = int(rng.integers(size // 3 - 10, size // 3 + 10))
    face_h = int(rng.integers(size // 2 - 18, size // 2 - 2))
    cv2.ellipse(img, (size // 2, size // 2), (face_w, face_h), 0, 0, 360, skin, -1)
    eye_dx = int(rng.integers(14, 28))
    eye_y = size // 2 - int(rng.integers(6, 16))
    cv2.circle(img, (size // 2 - eye_dx, eye_y), 6, (30, 30, 30), -1)
    cv2.circle(img, (size // 2 + eye_dx, eye_y), 6, (30, 30, 30), -1)
    mouth_y = size // 2 + int(rng.integers(18, 32))
    cv2.ellipse(img, (size // 2, mouth_y), (18, 8), 0, 0, 180, (60, 30, 30), 2)
    return img


def _encode_jpeg(image: np.ndarray, quality: int = 90) -> bytes:
    ok, buf = cv2.imencode(".jpg", image, [cv2.IMWRITE_JPEG_QUALITY, quality])
    assert ok
    return bytes(buf)


def test_compute_phash_deterministic_for_identical_image() -> None:
    image = _synthetic_face_like_image(seed=1)
    jpeg = _encode_jpeg(image)
    assert compute_phash(jpeg) == compute_phash(jpeg)


def test_bktree_find_within_basic() -> None:
    tree = BKTree()
    tree.add("0000000000000000")
    tree.add("0000000000000001")  # distance 1 from root
    tree.add("ffffffffffffffff")  # distance 64 from root

    hits = tree.find_within("0000000000000000", max_distance=2)
    hit_hashes = {h for h, _d in hits}
    assert "0000000000000000" in hit_hashes
    assert "0000000000000001" in hit_hashes
    assert "ffffffffffffffff" not in hit_hashes


def test_reuse_check_catches_exact_resubmission(tmp_path: Path) -> None:
    index = PhashIndex(tmp_path / "phash.db")
    frame = _encode_jpeg(_synthetic_face_like_image(seed=1))

    index.record_accepted_bundle("session-1", [frame])
    hits = index.check_reuse([frame], max_distance=settings.binding.phash_hamming_max)
    assert len(hits) == 1
    assert hits[0][0] == 0  # frame index


def test_reuse_check_misses_before_acceptance_is_recorded(tmp_path: Path) -> None:
    """A frame never recorded via record_accepted_bundle must not be flagged — proves
    check_reuse doesn't somehow self-poison.
    """
    index = PhashIndex(tmp_path / "phash.db")
    frame = _encode_jpeg(_synthetic_face_like_image(seed=1))
    hits = index.check_reuse([frame], max_distance=settings.binding.phash_hamming_max)
    assert hits == []


def test_reuse_check_catches_reencoded_and_rescaled_resubmission(tmp_path: Path) -> None:
    """§5.3 DoD: catches an exact resubmission AND a re-encoded/rescaled one. Round-trip
    the accepted frame through a lower JPEG quality and a modest rescale, and confirm
    the hash still lands within the configured threshold.
    """
    index = PhashIndex(tmp_path / "phash.db")
    original_image = _synthetic_face_like_image(seed=1)
    original_jpeg = _encode_jpeg(original_image, quality=95)
    index.record_accepted_bundle("session-1", [original_jpeg])

    # Re-encode at a much lower quality.
    reencoded = _encode_jpeg(original_image, quality=35)

    # Rescale down then back up (a modest rescale round-trip), then re-encode.
    h, w = original_image.shape[:2]
    small = cv2.resize(original_image, (int(w * 0.7), int(h * 0.7)), interpolation=cv2.INTER_AREA)
    rescaled = cv2.resize(small, (w, h), interpolation=cv2.INTER_LINEAR)
    rescaled_jpeg = _encode_jpeg(rescaled, quality=90)

    for label, candidate in [("reencoded", reencoded), ("rescaled", rescaled_jpeg)]:
        hits = index.check_reuse([candidate], max_distance=settings.binding.phash_hamming_max)
        assert len(hits) == 1, f"{label} resubmission was not caught"


def test_distinct_synthetic_subjects_do_not_match(tmp_path: Path) -> None:
    """Sanity check in the other direction: genuinely different synthetic subjects must
    not collide within the configured threshold (the real FPR measurement across many
    same-subject distinct captures lives in scripts/measure_phash_fpr.py /
    results/binding_fpr.json — this is a fast smoke check, not that measurement).
    """
    index = PhashIndex(tmp_path / "phash.db")
    frame_a = _encode_jpeg(_synthetic_face_like_image(seed=1))
    frame_b = _encode_jpeg(_synthetic_face_like_image(seed=999))
    index.record_accepted_bundle("session-a", [frame_a])

    hits = index.check_reuse([frame_b], max_distance=settings.binding.phash_hamming_max)
    assert hits == []


def test_burst_of_distinct_subject_is_not_flagged_as_reused(tmp_path: Path) -> None:
    """§14's N-of-burst rule at the configured default: a whole burst from a genuinely
    different subject must not trip BIND_EVIDENCE_REUSE, even at the loosened D=10
    (D was raised specifically to close the robustness gap; N is what's supposed to
    keep the resulting looser single-frame collisions from becoming false accepts).
    """
    index = PhashIndex(tmp_path / "phash.db")
    accepted_burst = [_encode_jpeg(_synthetic_face_like_image(seed=1)) for _ in range(30)]
    index.record_accepted_bundle("session-a", accepted_burst)

    new_burst = [_encode_jpeg(_synthetic_face_like_image(seed=999)) for _ in range(30)]
    reused = index.is_burst_reused(
        new_burst,
        max_distance=settings.binding.phash_hamming_max,
        min_matching_frames=settings.binding.phash_reuse_min_frames,
    )
    assert reused is False


def test_is_burst_reused_true_at_or_above_min_matching_frames(tmp_path: Path) -> None:
    index = PhashIndex(tmp_path / "phash.db")
    base = _synthetic_face_like_image(seed=1)
    accepted = [_encode_jpeg(base) for _ in range(5)]
    index.record_accepted_bundle("session-1", accepted)

    # a 5-frame resubmission of the exact same media, N=5: every frame matches.
    resubmitted = [_encode_jpeg(base) for _ in range(5)]
    assert index.is_burst_reused(resubmitted, max_distance=6, min_matching_frames=5) is True


def test_is_burst_reused_false_below_min_matching_frames(tmp_path: Path) -> None:
    """The core of §14's N-of-burst rule: a handful of matching frames (fewer than N)
    must not flag reuse, even though each of those frames individually matches.
    """
    index = PhashIndex(tmp_path / "phash.db")
    base = _synthetic_face_like_image(seed=1)
    other = _synthetic_face_like_image(seed=999)
    # only 2 of the accepted burst's frames are this exact media; the rest are unrelated.
    accepted = [_encode_jpeg(base), _encode_jpeg(base)] + [_encode_jpeg(other) for _ in range(8)]
    index.record_accepted_bundle("session-1", accepted)

    submitted = [_encode_jpeg(base) for _ in range(2)] + [
        _encode_jpeg(_synthetic_face_like_image(seed=42 + i)) for i in range(8)
    ]
    assert index.is_burst_reused(submitted, max_distance=6, min_matching_frames=5) is False


def test_restart_preserves_burst_level_detection(tmp_path: Path) -> None:
    """The restart property must hold for `is_burst_reused`, the method actually used
    by verify.check_evidence_reuse, not just the lower-level `check_reuse`.
    """
    db_path = tmp_path / "phash.db"
    base = _synthetic_face_like_image(seed=1)
    burst = [_encode_jpeg(base) for _ in range(10)]

    index_before_restart = PhashIndex(db_path)
    index_before_restart.record_accepted_bundle("session-1", burst)
    assert (
        index_before_restart.is_burst_reused(burst, max_distance=6, min_matching_frames=10) is True
    )

    index_after_restart = PhashIndex(db_path)
    assert (
        index_after_restart.is_burst_reused(burst, max_distance=6, min_matching_frames=10) is True
    )


def test_restart_preserves_detection(tmp_path: Path) -> None:
    """§5.3: "the BK-tree must be rebuildable from SQLite on startup and stay
    consistent with it. Test that a restart preserves detection."
    """
    db_path = tmp_path / "phash.db"
    frame = _encode_jpeg(_synthetic_face_like_image(seed=1))

    index_before_restart = PhashIndex(db_path)
    index_before_restart.record_accepted_bundle("session-1", [frame])
    assert index_before_restart.check_reuse([frame], max_distance=6) == [
        (0, compute_phash(frame), 0)
    ]

    # Simulate a process restart: a brand-new PhashIndex object against the same file,
    # with no in-memory state carried over — only the constructor's rebuild-from-SQLite.
    index_after_restart = PhashIndex(db_path)
    hits = index_after_restart.check_reuse([frame], max_distance=6)
    assert len(hits) == 1
    assert hits[0][0] == 0


def test_record_accepted_bundle_not_reachable_from_verify_module() -> None:
    """§5.3: "insertion should not be callable from the verification path, only from
    the accept path" — enforced structurally: pqbio.binding.verify never imports or
    exposes PhashIndex.record_accepted_bundle, only the read-only check_reuse via
    check_evidence_reuse.
    """
    import pqbio.binding.verify as verify_module

    assert not hasattr(verify_module, "record_accepted_bundle")
    assert "record_accepted_bundle" not in dir(verify_module)
