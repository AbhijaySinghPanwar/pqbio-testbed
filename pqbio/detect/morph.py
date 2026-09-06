"""D2 morphing attack detection: S-MAD and D-MAD (PROJECT_SPEC.md §5.4).

Owner: Krish

A morph is one image that matches two identities well enough for both to pass verification
against it. §5.4 asks for both ISO settings:

* **S-MAD** (single-image) — decide from the suspect image alone. This is the passport-desk
  setting: no trusted reference exists yet.
* **D-MAD** (differential) — decide from the suspect image *and* a trusted live capture.
  This is our threat model, because verification always has a live capture, and it is
  expected to beat S-MAD substantially: the live capture removes the need to model what
  faces look like in general and reduces the question to what this pair's embeddings do.

**Backbone: ArcFace ResNet-50, not EfficientNet-B0, and the reason is the environment not
a preference.** §5.4 suggests "EfficientNet-B0 or similar backbone". `torch` is not
installed here and adding it for one detector was not in scope, so the deep feature is the
`w600k_r50` ArcFace embedding already loaded by `face.py` — a ResNet-50 CNN, running on
CPU via ONNX, with weights already checksum-verified at startup. It is a face-recognition
backbone rather than a texture backbone, which matters: it is strong for D-MAD (embeddings
are exactly what D-MAD compares) and weaker for S-MAD than a texture-pretrained CNN would
be. The S-MAD numbers should be read as a floor, not as what a properly-backboned S-MAD
would achieve.

Texture features are handwritten because they are cheap and interpretable: LBP histograms
(rotation-invariant uniform, `skimage`) and a **BSIF-like** binarised filter-response
histogram. Real BSIF uses filters learned by ICA on natural image patches; this uses fixed
seeded random projections instead, which is the same construction with an untrained filter
bank. Named accordingly rather than called BSIF.

Contract matches `injection.py`: implements `Detector`, latency measured by the base
class, `threshold` from `settings.detect.thresholds.morph`, CPU-only path.

CLI:
    python -m pqbio.detect.morph --input IMAGE --out scores.json
    python -m pqbio.detect.morph --input IMAGE --live LIVE_IMAGE --out scores.json   # D-MAD
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal

import cv2
import numpy as np
import numpy.typing as npt

from pqbio.config import settings
from pqbio.detect.base import Detector

if TYPE_CHECKING:
    from pqbio.detect.face import PreparedEvidence

MODELS_DIR = Path(__file__).resolve().parent.parent.parent / "models"
DEFAULT_SMAD_MODEL_PATH = MODELS_DIR / "morph_smad_gbm.txt"
DEFAULT_DMAD_MODEL_PATH = MODELS_DIR / "morph_dmad_gbm.txt"

SEED = 2026
LBP_POINTS = 8
LBP_RADIUS = 1
BSIF_FILTERS = 8
BSIF_PATCH = 7

Setting = Literal["smad", "dmad"]


# ----------------------------------------------------------------------------------
# Features
# ----------------------------------------------------------------------------------


def _lbp_histogram(gray: npt.NDArray[Any]) -> npt.NDArray[np.float64]:
    from skimage.feature import local_binary_pattern

    codes = local_binary_pattern(  # type: ignore[no-untyped-call]
        gray, LBP_POINTS, LBP_RADIUS, method="uniform"
    )
    n_bins = LBP_POINTS + 2
    hist, _ = np.histogram(codes, bins=n_bins, range=(0, n_bins))
    total = hist.sum()
    return (hist / total).astype(np.float64) if total else np.zeros(n_bins, dtype=np.float64)


def _bsif_like_histogram(gray: npt.NDArray[Any]) -> npt.NDArray[np.float64]:
    """Binarised responses to a fixed random filter bank.

    BSIF's filters are learned by ICA on natural patches; these are seeded random
    projections of the same patch size. The construction — filter, threshold at zero, pack
    the bits into a code, histogram the codes — is BSIF's; only the bank is untrained,
    which is why the name says "like".
    """
    rng = np.random.default_rng(SEED)
    normalised = gray.astype(np.float32) / 255.0
    bits = np.zeros(normalised.shape, dtype=np.int32)
    for i in range(BSIF_FILTERS):
        kernel = rng.normal(0.0, 1.0, size=(BSIF_PATCH, BSIF_PATCH)).astype(np.float32)
        kernel -= kernel.mean()
        response = cv2.filter2D(normalised, -1, kernel, borderType=cv2.BORDER_REFLECT_101)
        bits |= (response > 0).astype(np.int32) << i
    hist, _ = np.histogram(bits, bins=2**BSIF_FILTERS, range=(0, 2**BSIF_FILTERS))
    total = hist.sum()
    return (hist / total).astype(np.float64) if total else hist.astype(np.float64)


def _blend_residual_features(bgr: npt.NDArray[Any]) -> npt.NDArray[np.float64]:
    """Cheap artefacts that averaging two faces tends to leave behind.

    Morphing suppresses high-frequency detail (two misaligned edge sets average into one
    soft edge) and can leave doubled or ghosted structure. These are the classic
    hand-engineered S-MAD cues; they are also exactly the cues the `spliced_jpeg` method
    is built to defeat, which is the point of measuring cross-method generalisation.
    """
    gray = cv2.cvtColor(bgr, cv2.COLOR_BGR2GRAY)
    laplacian = cv2.Laplacian(gray, cv2.CV_64F)
    gx = cv2.Sobel(gray, cv2.CV_64F, 1, 0, ksize=3)
    gy = cv2.Sobel(gray, cv2.CV_64F, 0, 1, ksize=3)
    magnitude = np.sqrt(gx**2 + gy**2)
    spectrum = np.abs(np.fft.fftshift(np.fft.fft2(gray.astype(np.float64))))
    h, w = spectrum.shape
    cy, cx = h // 2, w // 2
    inner = spectrum[cy - h // 8 : cy + h // 8, cx - w // 8 : cx + w // 8].mean()
    outer = spectrum.mean()
    return np.array(
        [
            float(laplacian.var()),
            float(np.abs(laplacian).mean()),
            float(magnitude.mean()),
            float(magnitude.std()),
            float(np.percentile(magnitude, 95)),
            float(inner / outer) if outer else 0.0,
            float(gray.std()),
        ],
        dtype=np.float64,
    )


def _embedding(bgr: npt.NDArray[Any]) -> npt.NDArray[np.float32] | None:
    """L2-normalised ArcFace embedding, or None when no face is found."""
    from pqbio.detect.face import _get_app

    faces = _get_app().get(bgr)
    if not faces:
        return None
    face = max(faces, key=lambda f: float(f.det_score))
    if face.normed_embedding is None:
        return None
    return np.asarray(face.normed_embedding, dtype=np.float32)


def smad_features(bgr: npt.NDArray[Any]) -> npt.NDArray[np.float64]:
    """Single-image feature vector: texture + blend residuals + deep embedding."""
    gray = cv2.cvtColor(bgr, cv2.COLOR_BGR2GRAY)
    parts = [
        _lbp_histogram(gray),
        _bsif_like_histogram(gray),
        _blend_residual_features(bgr),
    ]
    embedding = _embedding(bgr)
    parts.append(
        embedding.astype(np.float64) if embedding is not None else np.zeros(512, dtype=np.float64)
    )
    return np.concatenate(parts)


def dmad_features(
    suspect: npt.NDArray[Any], live: npt.NDArray[Any]
) -> npt.NDArray[np.float64] | None:
    """Differential feature vector: what the two embeddings do relative to each other.

    §5.4 D2 specifies "a classifier over the ArcFace embedding difference between the
    suspect image and a trusted live capture". The signed difference is the specified
    feature; |difference| and the cosine are added because a morph's signature is that it
    sits *between* two identities, which shows up as a moderate cosine to each contributor
    rather than the high cosine a genuine pair produces or the near-zero an impostor does.
    """
    suspect_embedding = _embedding(suspect)
    live_embedding = _embedding(live)
    if suspect_embedding is None or live_embedding is None:
        return None
    difference = (suspect_embedding - live_embedding).astype(np.float64)
    cosine = float(np.dot(suspect_embedding, live_embedding))
    return np.concatenate(
        [
            difference,
            np.abs(difference),
            np.array(
                [cosine, float(np.linalg.norm(difference)), float(difference.std())],
                dtype=np.float64,
            ),
        ]
    )


# ----------------------------------------------------------------------------------
# Detector
# ----------------------------------------------------------------------------------


class MorphDetector(Detector):
    """Morph detector in either ISO setting.

    `setting="dmad"` needs `live_capture`; without one the detector reports a score of
    0.0 with an explicit reason rather than silently degrading to S-MAD, because a D-MAD
    result computed without a reference is not a D-MAD result.
    """

    name = "morph"

    def __init__(
        self,
        setting: Setting = "dmad",
        model_path: Path | None = None,
        live_capture: npt.NDArray[Any] | None = None,
    ) -> None:
        self.setting: Setting = setting
        self._live = live_capture
        default = DEFAULT_DMAD_MODEL_PATH if setting == "dmad" else DEFAULT_SMAD_MODEL_PATH
        path = model_path if model_path is not None else default
        self._model = self._load(path)

    @staticmethod
    def _load(path: Path) -> Any | None:
        if not path.is_file():
            return None
        import lightgbm as lgb

        return lgb.Booster(model_file=str(path))

    @property
    def threshold(self) -> float:
        return float(settings.detect.thresholds.morph)

    def score_image(
        self, bgr: npt.NDArray[Any], live: npt.NDArray[Any] | None = None
    ) -> tuple[float, list[str], dict[str, Any]]:
        """Score a standalone image. Used by the corpus evaluation and the CLI."""
        reasons: list[str] = []
        live_capture = live if live is not None else self._live

        if self.setting == "dmad":
            if live_capture is None:
                return 0.0, ["MORPH_NO_LIVE_CAPTURE (D-MAD needs a trusted reference)"], {}
            features = dmad_features(bgr, live_capture)
            if features is None:
                return 0.0, ["MORPH_NO_FACE (suspect or live capture)"], {}
        else:
            features = smad_features(bgr)

        if self._model is None:
            return 0.0, [f"MORPH_MODEL_MISSING ({self.setting}) -- not scored"], {}

        probability = float(self._model.predict(features.reshape(1, -1))[0])
        reasons.append(f"{self.setting}_morph_probability {probability:.3f}")
        return probability, reasons, {f"{self.setting}_probability": probability}

    def _evaluate(self, evidence: PreparedEvidence) -> tuple[float, list[str], dict[str, Any]]:
        from pqbio.detect.face import QUALITY_INSUFFICIENT

        if evidence.crop_224 is None and evidence.crop_112 is None:
            return 0.0, [QUALITY_INSUFFICIENT], {}
        crop = evidence.crop_224 if evidence.crop_224 is not None else evidence.crop_112
        assert crop is not None
        return self.score_image(crop)


# ----------------------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Score an image for morphing (§5.4 D2).")
    parser.add_argument("--input", type=Path, required=True, help="suspect image")
    parser.add_argument("--live", type=Path, default=None, help="trusted live capture (D-MAD)")
    parser.add_argument("--setting", choices=("smad", "dmad"), default=None)
    parser.add_argument("--model", type=Path, default=None)
    parser.add_argument("--out", type=Path, default=None)
    args = parser.parse_args(argv)

    suspect = cv2.imread(str(args.input))
    if suspect is None:
        print(f"could not read {args.input}", file=sys.stderr)
        return 2
    live = cv2.imread(str(args.live)) if args.live is not None else None
    setting: Setting = args.setting or ("dmad" if live is not None else "smad")

    detector = MorphDetector(setting=setting, model_path=args.model, live_capture=live)
    score, reasons, features = detector.score_image(suspect, live)
    payload = {
        "input": str(args.input),
        "setting": setting,
        "score": score,
        "threshold": detector.threshold,
        "decision": bool(score >= detector.threshold),
        "reasons": reasons,
        "features": features,
    }
    text = json.dumps(payload, indent=2)
    if args.out is not None:
        args.out.write_text(text + "\n", encoding="utf-8")
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
