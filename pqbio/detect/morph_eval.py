"""Train and evaluate D2's morph detectors, including MMPMR (PROJECT_SPEC.md §5.4, §8.1).

Owner: Krish

Lives beside `morph.py` rather than in `scripts/` because `run_full_eval.py` calls it the
same way it calls `injection.train_and_evaluate` — the accuracy stage needs one entry point
that returns the §8.1 cells, not a subprocess.

Three things are measured here, and only the first is about the detector:

1. **Detection** — APCER/BPCER/ACER/EER/AUC for S-MAD and D-MAD, on subject-disjoint
   splits, plus the **cross-method generalisation** gap: train on one morph method, test on
   the other. That gap is the honest number (§12). A detector trained and tested on the
   same generator is measuring whether it can recognise that generator.

2. **MMPMR** — the Mated Morph Presentation Match Rate. This is not a detector metric at
   all: it asks whether the *attack works*, i.e. whether a morph matches **both**
   contributing identities against the enrolled template well enough to verify. It is
   computed through `match.py`'s threshold (`detect.thresholds.match_cosine_min`), because
   that is the decision an attacker has to beat. A corpus with a low MMPMR contains morphs
   that would not have fooled the matcher anyway, so its detection numbers describe an
   attack nobody needed to detect — which is why this is reported *first* when reading the
   results.

3. **Contributor-wise match rates**, so a low MMPMR can be diagnosed: a morph can match one
   contributor strongly and the other not at all, which is a failed morph rather than a
   detected one.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import cv2
import numpy as np

from pqbio.bench import accuracy as acc
from pqbio.bench._common import blocked
from pqbio.config import settings
from pqbio.detect.morph import (
    DEFAULT_DMAD_MODEL_PATH,
    DEFAULT_SMAD_MODEL_PATH,
    _embedding,
    dmad_features,
    smad_features,
)

# Only used if a manifest predates the `methods` key; the manifest is authoritative.
METHODS_FALLBACK = ("landmark_alpha", "spliced_jpeg")

SEED = 2026


def _load_manifest(path: Path) -> dict[str, Any]:
    return dict(json.loads(path.read_text(encoding="utf-8")))


def _read(corpus_dir: Path, rel: str) -> np.ndarray:
    image = cv2.imread(str(corpus_dir / rel))
    if image is None:
        raise FileNotFoundError(
            f"{corpus_dir / rel} missing -- regenerate with scripts/make_morph_corpus.py "
            "(the corpus is never committed, see data/LICENCES.md)"
        )
    return np.asarray(image, dtype=np.uint8)


# ----------------------------------------------------------------------------------
# Feature extraction over the corpus
# ----------------------------------------------------------------------------------


def extract_features(manifest: dict[str, Any], corpus_dir: Path) -> dict[str, Any]:
    """One pass over the corpus, caching everything both settings and MMPMR need.

    Deliberately one pass: SCRFD + ArcFace on every image is the expensive part, and
    S-MAD, D-MAD and MMPMR all want the same embeddings.
    """
    bona_fide_by_identity: dict[str, str] = {
        s["contributors"][0]: s["path"] for s in manifest["samples"] if s["label"] == "bona_fide"
    }
    # A third image per identity, used ONLY as D-MAD's trusted live capture. Keeping it
    # out of the sample pool is what stops the reference leaking into the evaluation: a
    # bona fide sample compared against itself is trivially genuine, and comparing it
    # against the same image the morph was built from would flatter D-MAD instead of
    # testing it.
    live_by_identity: dict[str, str] = {
        s["contributors"][0]: s["path"]
        for s in manifest["samples"]
        if s["label"] == "live_reference"
    }

    rows: list[dict[str, Any]] = []
    for sample in manifest["samples"]:
        if sample["label"] == "live_reference":
            continue  # a reference, not a sample to be classified
        image = _read(corpus_dir, sample["path"])
        embedding = _embedding(image)
        row: dict[str, Any] = {
            "path": sample["path"],
            "label": sample["label"],
            "method": sample["method"],
            "split": sample["split"],
            "contributors": sample["contributors"],
            "smad": smad_features(image),
            "embedding": embedding,
            "face_found": embedding is not None,
        }

        # D-MAD's trusted live capture: for a morph, a genuine capture of the FIRST
        # contributor -- the person presenting the document at the desk. For a bona fide
        # sample, that identity's own live capture, which is the genuine-pair case D-MAD
        # must not flag. Both come from the held-out live_reference image.
        reference_identity = sample["contributors"][0]
        reference_path = live_by_identity.get(reference_identity)
        if reference_path is not None and reference_path != sample["path"]:
            row["dmad"] = dmad_features(image, _read(corpus_dir, reference_path))
        else:
            row["dmad"] = None
        rows.append(row)

    return {
        "rows": rows,
        "bona_fide_by_identity": bona_fide_by_identity,
        "live_by_identity": live_by_identity,
    }


# ----------------------------------------------------------------------------------
# Detection
# ----------------------------------------------------------------------------------


def _fit_and_score(
    train: list[tuple[np.ndarray, int]], test: list[tuple[np.ndarray, int]]
) -> tuple[list[float], list[int], Any]:
    import lightgbm as lgb

    x_train = np.vstack([f for f, _ in train])
    y_train = np.array([y for _, y in train])
    booster = lgb.train(
        {
            "objective": "binary",
            "verbosity": -1,
            "seed": SEED,
            "deterministic": True,
            "num_leaves": 7,
            "min_data_in_leaf": 3,
            "learning_rate": 0.1,
            "feature_fraction": 0.7,
        },
        lgb.Dataset(x_train, label=y_train),
        num_boost_round=120,
    )
    x_test = np.vstack([f for f, _ in test])
    scores = [float(v) for v in booster.predict(x_test)]
    return scores, [y for _, y in test], booster


def _metrics(scores: list[float], labels: list[int], threshold: float) -> dict[str, Any]:
    """APCER/BPCER/ACER at the deployed threshold, plus threshold-free EER and AUC."""
    attack = [s for s, y in zip(scores, labels, strict=True) if y == 1]
    genuine = [s for s, y in zip(scores, labels, strict=True) if y == 0]
    if not attack or not genuine:
        return blocked("split had zero samples for one class")
    report = acc.detector_accuracy_report(genuine, attack, threshold)
    return dict(report)


def evaluate_detection(features: dict[str, Any], setting: str, threshold: float) -> dict[str, Any]:
    """Within-corpus evaluation on the subject-disjoint train/test partition."""
    key = setting
    usable = [r for r in features["rows"] if r.get(key) is not None]
    train = [(r[key], 1 if r["label"] == "morph" else 0) for r in usable if r["split"] == "train"]
    test = [(r[key], 1 if r["label"] == "morph" else 0) for r in usable if r["split"] == "test"]
    if not train or not test:
        return blocked(f"{setting}: train or test split empty after feature extraction")

    scores, labels, booster = _fit_and_score(train, test)
    result = _metrics(scores, labels, threshold)
    result["n_train"] = len(train)
    result["n_test"] = len(test)
    result["n_dropped_no_features"] = sum(1 for r in features["rows"] if r.get(key) is None)
    result["_booster"] = booster
    return result


def evaluate_cross_method(
    features: dict[str, Any], setting: str, threshold: float, methods: list[str]
) -> dict[str, Any]:
    """Train on one morph method, test on the other. The §12 number.

    Bona fide samples appear on both sides -- they belong to no method -- but the
    subject-disjoint split is still respected: training uses train-split identities only,
    testing uses test-split identities only. So this measures method generalisation on top
    of subject generalisation, not instead of it.
    """
    out: dict[str, Any] = {}
    for train_method in methods:
        for test_method in methods:
            if train_method == test_method:
                continue
            usable = [r for r in features["rows"] if r.get(setting) is not None]
            train = [
                (r[setting], 1 if r["label"] == "morph" else 0)
                for r in usable
                if r["split"] == "train" and (r["method"] in (None, train_method))
            ]
            test = [
                (r[setting], 1 if r["label"] == "morph" else 0)
                for r in usable
                if r["split"] == "test" and (r["method"] in (None, test_method))
            ]
            label = f"train_{train_method}__test_{test_method}"
            if not train or not test:
                out[label] = blocked("empty split for this method pairing")
                continue
            scores, labels, _ = _fit_and_score(train, test)
            out[label] = _metrics(scores, labels, threshold)
    return out


# ----------------------------------------------------------------------------------
# MMPMR
# ----------------------------------------------------------------------------------


def evaluate_mmpmr(features: dict[str, Any], corpus_dir: Path) -> dict[str, Any]:
    """MMPMR: does the morph verify as **every** contributing identity?

    Per Scherhag et al., a morph presentation succeeds only if the *minimum* similarity
    across its contributors clears the verification threshold -- one contributor passing is
    not an attack, it is just a photograph of that person. `match_cosine_min` is the
    threshold `match.py` deploys, so this is the real decision boundary, not a
    detector-specific one.
    """
    cosine_min = float(settings.detect.thresholds.match_cosine_min)
    reference: dict[str, np.ndarray] = {}
    for identity, rel in features["bona_fide_by_identity"].items():
        embedding = _embedding(_read(corpus_dir, rel))
        if embedding is not None:
            reference[identity] = embedding

    per_method: dict[str, list[dict[str, Any]]] = {}
    for row in features["rows"]:
        if row["label"] != "morph" or row["embedding"] is None:
            continue
        sims = [
            float(np.dot(row["embedding"], reference[c]))
            for c in row["contributors"]
            if c in reference
        ]
        if len(sims) != len(row["contributors"]):
            continue
        per_method.setdefault(row["method"], []).append(
            {
                "path": row["path"],
                "contributor_similarities": sims,
                "min_similarity": min(sims),
                "verifies_all_contributors": bool(min(sims) >= cosine_min),
                "verifies_any_contributor": bool(max(sims) >= cosine_min),
            }
        )

    summary: dict[str, Any] = {
        "definition": (
            "MMPMR = fraction of morphs whose MINIMUM similarity across contributing "
            "identities clears detect.thresholds.match_cosine_min -- i.e. the morph "
            "verifies as every contributor, which is the attack's success condition"
        ),
        "match_cosine_min": cosine_min,
        "by_method": {},
    }
    all_rows: list[dict[str, Any]] = []
    for method, rows in per_method.items():
        all_rows.extend(rows)
        summary["by_method"][method] = {
            "n_morphs": len(rows),
            "mmpmr": float(np.mean([r["verifies_all_contributors"] for r in rows])),
            "any_contributor_match_rate": float(
                np.mean([r["verifies_any_contributor"] for r in rows])
            ),
            "min_similarity_mean": float(np.mean([r["min_similarity"] for r in rows])),
            "min_similarity_max": float(np.max([r["min_similarity"] for r in rows])),
        }
    if all_rows:
        summary["overall"] = {
            "n_morphs": len(all_rows),
            "mmpmr": float(np.mean([r["verifies_all_contributors"] for r in all_rows])),
            "any_contributor_match_rate": float(
                np.mean([r["verifies_any_contributor"] for r in all_rows])
            ),
        }
    return summary


# ----------------------------------------------------------------------------------
# Entry point used by scripts/run_full_eval.py
# ----------------------------------------------------------------------------------


def train_and_evaluate(
    manifest_path: Path,
    corpus_dir: Path | None = None,
    *,
    smad_model_out: Path | None = None,
    dmad_model_out: Path | None = None,
) -> dict[str, Any]:
    manifest = _load_manifest(manifest_path)
    corpus = (
        corpus_dir
        if corpus_dir is not None
        else manifest_path.parent.parent / "processed" / "morph_corpus"
    )
    methods = list(manifest.get("methods", METHODS_FALLBACK))
    threshold = float(settings.detect.thresholds.morph)

    features = extract_features(manifest, corpus)

    result: dict[str, Any] = {
        "seed": SEED,
        "corpus_manifest": str(manifest_path.name),
        "corpus_counts": manifest.get("counts"),
        "methods": methods,
        "threshold": threshold,
        "mmpmr": evaluate_mmpmr(features, corpus),
    }

    for setting, model_out in (
        ("smad", smad_model_out or DEFAULT_SMAD_MODEL_PATH),
        ("dmad", dmad_model_out or DEFAULT_DMAD_MODEL_PATH),
    ):
        detection = evaluate_detection(features, setting, threshold)
        booster = detection.pop("_booster", None)
        if booster is not None and model_out is not None:
            model_out.parent.mkdir(parents=True, exist_ok=True)
            booster.save_model(str(model_out))
            detection["model_path"] = str(model_out.name)
        result[setting] = detection
        result[f"{setting}_cross_method"] = evaluate_cross_method(
            features, setting, threshold, methods
        )

    smad_acer = result["smad"].get("acer")
    dmad_acer = result["dmad"].get("acer")
    if isinstance(smad_acer, (int, float)) and isinstance(dmad_acer, (int, float)):
        result["dmad_vs_smad"] = {
            "smad_acer": smad_acer,
            "dmad_acer": dmad_acer,
            "acer_reduction": smad_acer - dmad_acer,
            "note": (
                "§5.4 predicts D-MAD substantially outperforms S-MAD because a trusted "
                "live capture is available at verification time; this is that prediction "
                "measured on this corpus"
            ),
        }
    return result
