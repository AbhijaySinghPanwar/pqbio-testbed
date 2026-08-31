"""Prepared evidence: face detect -> align -> crops -> quality gate (PROJECT_SPEC.md
§5.4 D0).

Owner: Krish (this session implements the non-dataset-blocked pieces: detection,
alignment, quality gate — not D1/D2/D3/D4, which need licensed datasets).

`PreparedEvidence` is computed once per request and shared by every detector — face
detection is never repeated per-detector. Detectors that don't need face crops at all
(pqbio.detect.injection) can build a minimal `PreparedEvidence` via
`prepared_evidence_bundle_only()` without paying for detection.

Detection runs on one representative frame from the capture burst — the sharpest one
by Laplacian variance, not simply the first or last — so a single motion-blurred frame
in the burst doesn't determine quality for the whole request.

Below the quality gate (blur, pose, face size — §9 `detect.quality`), this returns
`QUALITY_INSUFFICIENT` rather than an attack score: a bad genuine capture (someone
moved, poor lighting) must never read as an attack.

**Model weights and no-network-at-inference (§4).** SCRFD (detection) and ArcFace
`buffalo_l` (recognition) load from `models/insightface/`, fetched once via
`insightface`'s own downloader (see `scripts/fetch_face_models.py` used to populate it
and record checksums). Every load verifies each weight file's SHA-256 against
`models/checksums.txt` first and refuses to proceed on a mismatch or a missing
checksum entry — fail closed, matching §11's crypto convention applied here to model
integrity instead of a cryptographic key.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

import cv2
import numpy as np
import numpy.typing as npt

from pqbio.config import settings
from pqbio.schemas import EvidenceBundle

if TYPE_CHECKING:
    from insightface.app import FaceAnalysis

MODELS_DIR = Path(__file__).resolve().parent.parent.parent / "models"
INSIGHTFACE_ROOT = MODELS_DIR / "insightface"
CHECKSUMS_PATH = MODELS_DIR / "checksums.txt"

QUALITY_INSUFFICIENT = "QUALITY_INSUFFICIENT"

FaceBox = tuple[int, int, int, int]  # (x, y, w, h)


class ModelIntegrityError(RuntimeError):
    """Raised when a model weight file is missing from models/checksums.txt, missing
    from disk, or does not match its recorded SHA-256. Fail closed: never load an
    unverified weight file.
    """


class NoFaceDetectedError(RuntimeError):
    """Raised when SCRFD finds no face in the representative frame."""


@dataclass(frozen=True)
class FaceQuality:
    passed: bool
    blur_variance: float
    yaw_deg: float
    face_px: int
    reasons: list[str]


@dataclass(frozen=True)
class PreparedEvidence:
    bundle: EvidenceBundle
    representative_frame_idx: int
    face_box: FaceBox | None
    landmarks: npt.NDArray[np.float32] | None  # 5x2, insightface's kps order
    det_score: float
    crop_112: npt.NDArray[np.uint8] | None  # ArcFace-aligned, for match.py
    crop_224: npt.NDArray[np.uint8] | None  # larger aligned crop, for future CNN detectors
    quality: FaceQuality


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _load_checksums() -> dict[str, str]:
    if not CHECKSUMS_PATH.is_file():
        return {}
    entries: dict[str, str] = {}
    for line in CHECKSUMS_PATH.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        digest, _, rel_path = line.partition("  ")
        if digest and rel_path:
            entries[rel_path] = digest
    return entries


def verify_model_checksums() -> None:
    """Verify every `*.onnx` file under models/insightface/ against
    models/checksums.txt. Raises ModelIntegrityError on any mismatch, missing file, or
    file with no recorded checksum — never loads a weight file that isn't verified.
    """
    onnx_files = sorted(INSIGHTFACE_ROOT.rglob("*.onnx"))
    if not onnx_files:
        raise ModelIntegrityError(
            f"no .onnx model files found under {INSIGHTFACE_ROOT} — fetch buffalo_l first "
            "(see scripts/fetch_face_models.py)."
        )
    recorded = _load_checksums()
    for path in onnx_files:
        rel_path = path.relative_to(MODELS_DIR).as_posix()
        expected = recorded.get(rel_path)
        if expected is None:
            raise ModelIntegrityError(
                f"{rel_path} has no recorded checksum in {CHECKSUMS_PATH} — fail closed, "
                "refusing to load an unverified model file."
            )
        actual = _sha256_file(path)
        if actual != expected:
            raise ModelIntegrityError(
                f"{rel_path} SHA-256 mismatch: expected {expected}, got {actual} — refusing "
                "to load a model file that doesn't match its recorded checksum."
            )


_APP: FaceAnalysis | None = None


def _get_app() -> FaceAnalysis:
    """Lazy singleton: verify checksums once, then load SCRFD + ArcFace from disk with
    no network access (`allowed_modules` restricted to detection+recognition only —
    buffalo_l also ships gender/age/landmark models this project doesn't use).
    """
    global _APP
    if _APP is not None:
        return _APP
    verify_model_checksums()
    from insightface.app import FaceAnalysis

    app = FaceAnalysis(
        name="buffalo_l",
        root=str(INSIGHTFACE_ROOT),
        allowed_modules=["detection", "recognition"],
        providers=["CPUExecutionProvider"],
    )
    app.prepare(ctx_id=-1, det_size=(640, 640))
    _APP = app
    return app


def _pick_sharpest_frame(bundle: EvidenceBundle) -> tuple[int, npt.NDArray[np.uint8]]:
    """The sharpest frame in the burst by Laplacian variance, not simply frame 0 — a
    single motion-blurred frame shouldn't determine quality for the whole request.
    """
    best_idx, best_var, best_image = 0, -1.0, None
    for idx, frame_jpeg in enumerate(bundle.frames):
        image = cv2.imdecode(np.frombuffer(frame_jpeg, dtype=np.uint8), cv2.IMREAD_COLOR)
        if image is None:
            continue
        gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
        var = float(cv2.Laplacian(gray, cv2.CV_64F).var())
        if var > best_var:
            best_idx, best_var, best_image = idx, var, image
    if best_image is None:
        raise NoFaceDetectedError("no decodable frame in bundle.frames")
    return best_idx, best_image.astype(np.uint8)


def _estimate_yaw_deg(kps: npt.NDArray[np.float32]) -> float:
    """Rough yaw estimate from 5-point landmarks (left eye, right eye, nose, left
    mouth, right mouth): how far the nose sits from the eye-line midpoint, relative to
    inter-ocular distance, mapped through arcsin to a bounded angle.

    This is a documented approximation, not a calibrated pose estimator — a real 3D
    pose solve (insightface's separate landmark_3d68 model, or a PnP solve against a
    3D face model) would need another model download and wasn't judged worth it just
    for a coarse quality-gate threshold. Calibrate or replace once real face data is
    available to check it against (§6).
    """
    left_eye, right_eye, nose = kps[0], kps[1], kps[2]
    inter_ocular = float(np.linalg.norm(right_eye - left_eye))
    if inter_ocular <= 0:
        return 0.0
    face_center_x = (left_eye[0] + right_eye[0]) / 2.0
    dx = float(nose[0] - face_center_x)
    ratio = max(-1.0, min(1.0, dx / (inter_ocular / 2.0)))
    return float(np.degrees(np.arcsin(ratio)))


def _quality_gate(face_box: FaceBox, blur_variance: float, yaw_deg: float) -> FaceQuality:
    q = settings.detect.quality
    _, _, w, h = face_box
    face_px = min(w, h)
    reasons: list[str] = []
    if face_px < q.min_face_px:
        reasons.append(f"face_px {face_px} < min_face_px {q.min_face_px}")
    if blur_variance < q.min_blur_var:
        reasons.append(f"blur_variance {blur_variance:.1f} < min_blur_var {q.min_blur_var}")
    if abs(yaw_deg) > q.max_yaw_deg:
        reasons.append(f"|yaw_deg| {abs(yaw_deg):.1f} > max_yaw_deg {q.max_yaw_deg}")
    passed = not reasons
    if passed:
        reasons = ["quality gate passed"]
    else:
        reasons.insert(0, QUALITY_INSUFFICIENT)
    return FaceQuality(
        passed=passed,
        blur_variance=blur_variance,
        yaw_deg=yaw_deg,
        face_px=face_px,
        reasons=reasons,
    )


def detect_face_box(image: npt.NDArray[np.uint8]) -> tuple[FaceBox | None, float]:
    """Run SCRFD on one raw image and return its highest-confidence face box, or
    (None, 0.0) if no face is found. Independent of any `EvidenceBundle` — used both by
    `prepare_evidence` (below, on the burst's representative frame) and by
    `pqbio.capture.challenge.estimate_face_box`, which needs a face box *while
    assembling* a bundle, before one exists to hand to `prepare_evidence`.
    """
    app = _get_app()
    faces = app.get(image)
    if not faces:
        return None, 0.0
    face = max(faces, key=lambda f: float(f.det_score))
    x1, y1, x2, y2 = face.bbox
    return (int(x1), int(y1), int(x2 - x1), int(y2 - y1)), float(face.det_score)


def prepare_evidence(bundle: EvidenceBundle) -> PreparedEvidence:
    """Full pipeline: pick the sharpest frame, detect + align via SCRFD/ArcFace, build
    112x112 and 224x224 aligned crops, and run the quality gate. If no face is
    detected, returns a `PreparedEvidence` with `face_box=None` and a failing
    `FaceQuality` (QUALITY_INSUFFICIENT) rather than raising — a real request with no
    detectable face is a quality failure the caller should handle, not a crash.
    """
    from insightface.utils import face_align

    frame_idx, image = _pick_sharpest_frame(bundle)
    gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
    blur_variance = float(cv2.Laplacian(gray, cv2.CV_64F).var())

    app = _get_app()
    faces = app.get(image)
    if not faces:
        quality = FaceQuality(
            passed=False,
            blur_variance=blur_variance,
            yaw_deg=0.0,
            face_px=0,
            reasons=[QUALITY_INSUFFICIENT, "no face detected"],
        )
        return PreparedEvidence(
            bundle=bundle,
            representative_frame_idx=frame_idx,
            face_box=None,
            landmarks=None,
            det_score=0.0,
            crop_112=None,
            crop_224=None,
            quality=quality,
        )

    face = max(faces, key=lambda f: float(f.det_score))
    x1, y1, x2, y2 = face.bbox
    face_box: FaceBox = (int(x1), int(y1), int(x2 - x1), int(y2 - y1))
    yaw_deg = _estimate_yaw_deg(face.kps)
    quality = _quality_gate(face_box, blur_variance, yaw_deg)

    crop_112 = face_align.norm_crop(image, face.kps, image_size=112)
    crop_224 = face_align.norm_crop(image, face.kps, image_size=224)

    return PreparedEvidence(
        bundle=bundle,
        representative_frame_idx=frame_idx,
        face_box=face_box,
        landmarks=np.asarray(face.kps, dtype=np.float32),
        det_score=float(face.det_score),
        crop_112=crop_112,
        crop_224=crop_224,
        quality=quality,
    )


def prepared_evidence_bundle_only(bundle: EvidenceBundle) -> PreparedEvidence:
    """Minimal `PreparedEvidence` for detectors that only need `evidence.bundle`
    (pqbio.detect.injection: its six D5 signals are all about capture provenance —
    frame timing, device metadata, compression — not face content). Skips SCRFD/ArcFace
    entirely, so scoring injection features never requires the face models to be
    fetched or loaded.
    """
    return PreparedEvidence(
        bundle=bundle,
        representative_frame_idx=0,
        face_box=None,
        landmarks=None,
        det_score=0.0,
        crop_112=None,
        crop_224=None,
        quality=FaceQuality(
            passed=False,
            blur_variance=0.0,
            yaw_deg=0.0,
            face_px=0,
            reasons=["face detection not run for this PreparedEvidence (bundle-only)"],
        ),
    )
