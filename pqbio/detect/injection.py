"""D5 injection detection (PROJECT_SPEC.md §5.4).

Owner: Abhijay

Injection pixels can be a perfect genuine recording, so this attacks provenance, not
appearance. Six signals, each reduced to scalar features by `extract_features` (a pure
function of the bundle, shared by training and inference so they can never drift
apart), combined by a gradient-boosted tree model (LightGBM — the feature vector is
low-dimensional and heterogeneous; trees beat a network here, per spec).

Trained and evaluated on the corpus from `scripts/make_injection_corpus.py` — see
`train_and_evaluate` below and `results/detectors/injection/`.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import subprocess
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import cv2
import numpy as np
from PIL import Image
from scipy import stats

from pqbio.binding.verify import compute_challenge_correlation
from pqbio.config import DEFAULT_CONFIG_PATH, settings
from pqbio.detect.base import Detector, DetectorResult
from pqbio.detect.face import PreparedEvidence, prepared_evidence_bundle_only
from pqbio.schemas import EvidenceBundle, canonical_cbor_decode

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
MODELS_DIR = REPO_ROOT / "models"
DEFAULT_MODEL_PATH = MODELS_DIR / "injection_gbm.txt"


def _git_commit() -> str:
    try:
        out = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, stderr=subprocess.DEVNULL
        )
        return out.decode().strip()
    except Exception:
        return "unknown (not a git repository at run time)"


def _config_hash() -> str:
    return hashlib.sha256(DEFAULT_CONFIG_PATH.read_bytes()).hexdigest()


# Substring match against DeviceMeta.camera_device_name (case-insensitive) — signal 1.
VIRTUAL_CAM_NAME_SUBSTRINGS = [
    "obs virtual camera",
    "v4l2loopback",
    "manycam",
    "snap camera",
    "virtual camera",
    "virtualcam",
    "droidcam",
    "iriun",
]

FEATURE_NAMES = [
    "virtual_cam_name_match",
    "timing_mean_dt_ns",
    "timing_std_dt_ns",
    "timing_skew_dt",
    "timing_kurtosis_dt",
    "compression_quant_roughness",
    "compression_ela_score",
    "metadata_all_zero",
    "metadata_variance",
    "metadata_brightness_corr",
    "challenge_correlation",
    "attestation_present",
]


def _compression_features(frame_jpeg: bytes) -> tuple[float, float]:
    """(quantisation-table roughness, error-level-analysis score) for one JPEG frame —
    signal 3, "compression provenance".

    Quant roughness: std/mean of the luma quantisation table PIL reports for the file
    as decoded. A fresh single encode from a camera ISP tends toward a smooth, standard
    libjpeg table for its quality setting; a table assembled by repeated re-encoding is
    more irregular. Heuristic, not a calibrated forensic detector.

    ELA (error level analysis): recompress the *decoded* pixels at a fixed reference
    quality and measure the mean absolute difference from the original decode. An image
    that was already JPEG-compressed sits nearer a local minimum of the encoder's
    rate-distortion curve, so its ELA response is characteristically lower than a frame
    encoded for the first time from raw sensor data — evidence the frame was extracted
    from a pre-existing file rather than freshly captured.
    """
    image = Image.open(io.BytesIO(frame_jpeg))
    quant_tables = getattr(image, "quantization", None) or {}
    if quant_tables:
        luma_table = np.array(next(iter(quant_tables.values())), dtype=np.float64)
        mean = float(np.mean(luma_table))
        roughness = float(np.std(luma_table) / mean) if mean > 0 else 0.0
    else:
        roughness = 0.0

    decoded = cv2.imdecode(np.frombuffer(frame_jpeg, dtype=np.uint8), cv2.IMREAD_COLOR)
    if decoded is None:
        return roughness, 0.0
    ok, recompressed_buf = cv2.imencode(".jpg", decoded, [cv2.IMWRITE_JPEG_QUALITY, 90])
    if not ok:
        return roughness, 0.0
    recompressed = cv2.imdecode(recompressed_buf, cv2.IMREAD_COLOR)
    if recompressed is None:
        return roughness, 0.0
    ela = float(np.mean(np.abs(decoded.astype(np.float32) - recompressed.astype(np.float32))))
    return roughness, ela


def _brightness_exposure_correlation(bundle: EvidenceBundle) -> float:
    """Pearson r between reported exposure and each frame's actual mean brightness —
    part of signal 4, "sensor metadata plausibility". Honestly-reported exposure should
    vary in step with observed brightness; constant or bogus telemetry will not.
    """
    if len(bundle.frames) < 3:
        return 0.0
    exposures = [m.exposure for m in bundle.frame_meta]
    brightness: list[float] = []
    for frame_jpeg in bundle.frames:
        decoded = cv2.imdecode(np.frombuffer(frame_jpeg, dtype=np.uint8), cv2.IMREAD_COLOR)
        brightness.append(float(np.mean(decoded)) if decoded is not None else 0.0)
    arr_e, arr_b = np.array(exposures, dtype=np.float64), np.array(brightness, dtype=np.float64)
    if np.std(arr_e) == 0 or np.std(arr_b) == 0:
        return 0.0
    return float(np.corrcoef(arr_e, arr_b)[0, 1])


def extract_features(bundle: EvidenceBundle) -> dict[str, float]:
    """The six D5 signals (§5.4), reduced to scalar features. Pure function of the
    bundle — used identically for training and inference.
    """
    features: dict[str, float] = {}

    # 1. Virtual camera enumeration
    name = (bundle.device_meta.camera_device_name or "").lower()
    features["virtual_cam_name_match"] = (
        1.0 if any(s in name for s in VIRTUAL_CAM_NAME_SUBSTRINGS) else 0.0
    )

    # 2. Frame timing jitter: mean, sigma, skew, kurtosis of inter-frame delta-t
    ts = np.array([m.capture_ts_ns for m in bundle.frame_meta], dtype=np.float64)
    if len(ts) >= 3:
        dt = np.diff(ts)
        features["timing_mean_dt_ns"] = float(np.mean(dt))
        features["timing_std_dt_ns"] = float(np.std(dt))
        features["timing_skew_dt"] = float(stats.skew(dt)) if np.std(dt) > 0 else 0.0
        features["timing_kurtosis_dt"] = float(stats.kurtosis(dt)) if np.std(dt) > 0 else 0.0
    else:
        features.update(
            timing_mean_dt_ns=0.0, timing_std_dt_ns=0.0, timing_skew_dt=0.0, timing_kurtosis_dt=0.0
        )

    # 3. Compression provenance (representative first frame — cheap, one frame is enough
    #    to see whether the source was already compressed)
    quant_roughness, ela = _compression_features(bundle.frames[0]) if bundle.frames else (0.0, 0.0)
    features["compression_quant_roughness"] = quant_roughness
    features["compression_ela_score"] = ela

    # 4. Sensor metadata plausibility
    exposures = np.array([m.exposure for m in bundle.frame_meta], dtype=np.float64)
    isos = np.array([m.iso for m in bundle.frame_meta], dtype=np.float64)
    features["metadata_all_zero"] = 1.0 if (np.all(exposures == 0) and np.all(isos == 0)) else 0.0
    features["metadata_variance"] = float(np.var(exposures) + np.var(isos))
    features["metadata_brightness_corr"] = _brightness_exposure_correlation(bundle)

    # 5. Challenge-illumination correlation — reused from Module C, not reimplemented
    try:
        features["challenge_correlation"] = compute_challenge_correlation(bundle)
    except Exception:
        features["challenge_correlation"] = 0.0

    # 6. Attestation token (simulated). No attestation infrastructure exists in this
    # project (§2.1: "hardware attestation ... simulated only"), and nothing currently
    # populates DeviceMeta.attestation_token, so this feature is always 0.0 today — kept
    # as a real feature slot (not deleted) so a future attestation implementation (TEE-
    # signed capture, Play Integrity, DeviceCheck — the production path §2.1 asks to be
    # documented) only needs to start populating the field, not add a new feature.
    features["attestation_present"] = 1.0 if len(bundle.device_meta.attestation_token) > 0 else 0.0

    return features


def _explain(features: dict[str, float]) -> list[str]:
    """Human-readable reasons for the audit log — descriptive flags on the raw signals,
    not an explanation of the GBM's internal decision.
    """
    reasons = []
    if features["virtual_cam_name_match"] >= 1.0:
        reasons.append("device name matches a known virtual-camera driver")
    if features["timing_std_dt_ns"] < 1_000_000:  # < 1ms jitter: near-instant/metronomic
        reasons.append("frame-to-frame timing is suspiciously uniform (file-read artefact)")
    if features["challenge_correlation"] < settings.binding.illumination_corr_min:
        reasons.append("challenge-illumination correlation below threshold")
    if features["metadata_all_zero"] >= 1.0:
        reasons.append("sensor metadata (exposure/ISO) is all-zero across every frame")
    if features["attestation_present"] < 1.0:
        reasons.append("no attestation token present (simulated in this project)")
    if not reasons:
        reasons.append("no individual signal flagged; score driven by combined feature pattern")
    return reasons


class InjectionDetector(Detector):
    """D5. Scores `evidence.bundle` — ignores face crops entirely, so
    `prepared_evidence_bundle_only()` is enough; no face model needed to run this
    detector.
    """

    name = "injection"

    def __init__(self, model_path: Path | None = None) -> None:
        self._model_path = model_path or DEFAULT_MODEL_PATH
        self._booster: Any = None
        if self._model_path.is_file():
            import lightgbm as lgb

            self._booster = lgb.Booster(model_file=str(self._model_path))

    @property
    def threshold(self) -> float:
        return settings.detect.thresholds.injection

    def _evaluate(self, evidence: PreparedEvidence) -> tuple[float, list[str], dict[str, Any]]:
        features = extract_features(evidence.bundle)
        if self._booster is None:
            # No trained model available: fall back to the single cheapest, strongest
            # signal rather than either silently scoring 0 (fails open) or 1 (useless).
            score = features["virtual_cam_name_match"]
            reasons = [
                "INJECTION_MODEL_NOT_LOADED: no trained model at "
                f"{self._model_path}, falling back to virtual-cam-name-only heuristic"
            ]
        else:
            x = np.array([[features[name] for name in FEATURE_NAMES]])
            score = float(self._booster.predict(x)[0])
            reasons = _explain(features)
        return score, reasons, features


# ----------------------------------------------------------------------------------
# Training / evaluation on the injection corpus (scripts/make_injection_corpus.py)
# ----------------------------------------------------------------------------------


@dataclass(frozen=True)
class _CorpusSample:
    bundle_path: Path
    label: int  # 1 = injection, 0 = bona fide
    device_id: str  # subject-disjoint split key


def _load_corpus(manifest_path: Path) -> list[_CorpusSample]:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    samples: list[_CorpusSample] = []
    for entry in manifest["samples"]:
        device_id = entry["device_id"]
        samples.append(_CorpusSample(REPO_ROOT / entry["genuine"]["bundle_path"], 0, device_id))
        samples.append(
            _CorpusSample(REPO_ROOT / entry["tier1_injection"]["bundle_path"], 1, device_id)
        )
    return samples


def _read_bundle(path: Path) -> EvidenceBundle:
    return EvidenceBundle.model_validate(canonical_cbor_decode(path.read_bytes()))


def train_and_evaluate(
    manifest_path: Path,
    *,
    model_out: Path = DEFAULT_MODEL_PATH,
    results_out: Path = REPO_ROOT / "results" / "detectors" / "injection" / "results.json",
    test_fraction: float = 0.3,
    seed: int = 2026,
) -> dict[str, Any]:
    """Train the GBM on the corpus and evaluate on a held-out, subject-disjoint split
    (split by device_id/pair — the genuine and tier-1 sample sharing a device never
    end up on opposite sides of the split, and no device_id appears in both).
    """
    import lightgbm as lgb
    from sklearn.metrics import accuracy_score, confusion_matrix, roc_auc_score

    samples = _load_corpus(manifest_path)
    device_ids = sorted({s.device_id for s in samples})
    rng = np.random.default_rng(seed)
    shuffled = device_ids.copy()
    rng.shuffle(shuffled)
    n_test_devices = max(1, int(len(shuffled) * test_fraction))
    test_devices = set(shuffled[:n_test_devices])

    train_samples = [s for s in samples if s.device_id not in test_devices]
    test_samples = [s for s in samples if s.device_id in test_devices]
    assert {
        s.device_id for s in train_samples
    } & test_devices == set(), "subject-disjoint split violated"

    def featurize(sample_list: list[_CorpusSample]) -> tuple[np.ndarray, np.ndarray]:
        rows, labels = [], []
        for s in sample_list:
            bundle = _read_bundle(s.bundle_path)
            f = extract_features(bundle)
            rows.append([f[name] for name in FEATURE_NAMES])
            labels.append(s.label)
        return np.array(rows), np.array(labels)

    x_train, y_train = featurize(train_samples)
    x_test, y_test = featurize(test_samples)

    train_set = lgb.Dataset(x_train, label=y_train, feature_name=FEATURE_NAMES)
    params = {
        "objective": "binary",
        "metric": "auc",
        "verbosity": -1,
        "seed": seed,
        "num_leaves": 7,  # small: 12 features, small corpus — avoid overfitting a tiny tree
        "min_data_in_leaf": 2,
    }
    booster = lgb.train(params, train_set, num_boost_round=50)

    model_out.parent.mkdir(parents=True, exist_ok=True)
    booster.save_model(str(model_out))

    train_pred = np.asarray(booster.predict(x_train))
    test_pred = np.asarray(booster.predict(x_test)) if len(x_test) else np.array([])

    threshold = settings.detect.thresholds.injection
    result: dict[str, Any] = {
        "git_commit": _git_commit(),
        "config_hash_sha256": _config_hash(),
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "method": "synthetic corpus (scripts/make_injection_corpus.py)",
        "caveat": (
            "Trained and evaluated on the self-generated synthetic injection corpus "
            "(no licensed dataset exists for injection attacks — §6). Numbers here "
            "describe how well the six D5 signals separate this synthetic tier-1 "
            "construction from its genuine counterpart, not real-world detection rates."
        ),
        "feature_names": FEATURE_NAMES,
        "threshold": threshold,
        "n_train": len(train_samples),
        "n_test": len(test_samples),
        "n_train_devices": len(device_ids) - n_test_devices,
        "n_test_devices": n_test_devices,
        "subject_disjoint": True,
        "train_accuracy": float(accuracy_score(y_train, train_pred >= threshold)),
        "train_auc": float(roc_auc_score(y_train, train_pred)) if len(set(y_train)) > 1 else None,
    }
    if len(x_test):
        test_decisions = test_pred >= threshold
        result["test_accuracy"] = float(accuracy_score(y_test, test_decisions))
        result["test_auc"] = (
            float(roc_auc_score(y_test, test_pred)) if len(set(y_test)) > 1 else None
        )
        cm = confusion_matrix(y_test, test_decisions, labels=[0, 1])
        result["test_confusion_matrix"] = {
            "labels": ["bona_fide", "injection_tier1"],
            "matrix": cm.tolist(),
        }
        result["test_detection_rate_tier1"] = (
            float(np.mean(test_decisions[y_test == 1])) if np.any(y_test == 1) else None
        )
        result["test_false_positive_rate_bona_fide"] = (
            float(np.mean(test_decisions[y_test == 0])) if np.any(y_test == 0) else None
        )
    else:
        result["test_accuracy"] = None

    results_out.parent.mkdir(parents=True, exist_ok=True)
    results_out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


# ----------------------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, help="score a single .cbor EvidenceBundle")
    parser.add_argument("--out", type=Path, help="where to write the score JSON (with --input)")
    parser.add_argument(
        "--train",
        type=Path,
        metavar="MANIFEST",
        help="train + evaluate on an injection corpus manifest",
    )
    parser.add_argument("--model-out", type=Path, default=DEFAULT_MODEL_PATH)
    parser.add_argument(
        "--results-out",
        type=Path,
        default=REPO_ROOT / "results" / "detectors" / "injection" / "results.json",
    )
    args = parser.parse_args()

    if args.train is not None:
        result = train_and_evaluate(
            args.train, model_out=args.model_out, results_out=args.results_out
        )
        print(
            json.dumps({k: v for k, v in result.items() if k != "caveat"}, indent=2),
            file=sys.stderr,
        )
        return

    if args.input is None or args.out is None:
        parser.error("either --input/--out (score one bundle) or --train MANIFEST is required")

    bundle = _read_bundle(args.input)
    evidence = prepared_evidence_bundle_only(bundle)
    detector = InjectionDetector()
    result_obj: DetectorResult = detector.score(evidence)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(
        json.dumps(
            {
                "name": result_obj.name,
                "score": result_obj.score,
                "decision": result_obj.decision,
                "threshold": result_obj.threshold,
                "latency_ms": result_obj.latency_ms,
                "reasons": result_obj.reasons,
                "features": result_obj.features,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    print(f"wrote {args.out}", file=sys.stderr)


if __name__ == "__main__":
    main()
