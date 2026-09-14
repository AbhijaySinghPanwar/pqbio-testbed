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
import sys
from pathlib import Path
from typing import Any

import cv2
import numpy as np

from pqbio.bench import accuracy as acc
from pqbio.bench._common import blocked
from pqbio.config import settings
from pqbio.detect.injection import _record_model_checksum
from pqbio.detect.morph import (
    DEFAULT_DMAD_MODEL_PATH,
    DEFAULT_SMAD_MODEL_PATH,
    _embedding,
    dmad_features_from_embeddings,
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

    # Every image is embedded exactly once. SCRFD + ArcFace dominates the run, and the
    # previous version paid it up to three times per sample (S-MAD features, D-MAD suspect,
    # D-MAD reference) plus again per identity for MMPMR -- tolerable at 800 samples, the
    # long pole at the full pool.
    embedding_by_path: dict[str, np.ndarray | None] = {}

    def embed(rel: str, image: np.ndarray | None = None) -> np.ndarray | None:
        if rel not in embedding_by_path:
            embedding_by_path[rel] = _embedding(
                image if image is not None else _read(corpus_dir, rel)
            )
        return embedding_by_path[rel]

    rows: list[dict[str, Any]] = []
    for index, sample in enumerate(manifest["samples"]):
        if sample["label"] == "live_reference":
            continue  # a reference, not a sample to be classified
        if index % 500 == 0:
            print(f"  features: {index}/{len(manifest['samples'])}", file=sys.stderr)
        image = _read(corpus_dir, sample["path"])
        embedding = embed(sample["path"], image)
        row: dict[str, Any] = {
            "path": sample["path"],
            "label": sample["label"],
            "method": sample["method"],
            "split": sample["split"],
            "contributors": sample["contributors"],
            "pair_cosine": sample.get("pair_cosine"),
            "smad": smad_features(image, embedding=embedding),
            "embedding": embedding,
            "face_found": embedding is not None,
        }

        # D-MAD's trusted live capture: for a morph, a genuine capture of the FIRST
        # contributor -- the person presenting the document at the desk. For a bona fide
        # sample, that identity's own live capture, which is the genuine-pair case D-MAD
        # must not flag. Identities without a third LFW image have no live reference, and
        # their rows are excluded from D-MAD (counted in n_dropped_no_features).
        reference_path = live_by_identity.get(sample["contributors"][0])
        if reference_path is not None and reference_path != sample["path"]:
            row["dmad"] = dmad_features_from_embeddings(embedding, embed(reference_path))
        else:
            row["dmad"] = None
        rows.append(row)

    return {
        "rows": rows,
        "bona_fide_by_identity": bona_fide_by_identity,
        "live_by_identity": live_by_identity,
        "embedding_by_path": embedding_by_path,
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
    test_rows = [r for r in usable if r["split"] == "test"]
    result["_test_scores"] = [
        {"path": r["path"], "label": r["label"], "method": r["method"], "score": sc}
        for r, sc in zip(test_rows, scores, strict=True)
    ]
    return result


def _clopper_pearson(k: int, n: int, confidence: float = 0.95) -> tuple[float, float]:
    """Exact two-sided binomial interval for k successes in n trials."""
    from scipy.stats import beta

    alpha = 1.0 - confidence
    lower = 0.0 if k == 0 else float(beta.ppf(alpha / 2, k, n - k + 1))
    upper = 1.0 if k == n else float(beta.ppf(1 - alpha / 2, k + 1, n - k))
    return lower, upper


def evaluate_verifying_subset(
    detection: dict[str, Any], verifies_by_path: dict[str, bool], threshold: float
) -> dict[str, Any]:
    """Detection restricted to morphs that actually verify as both contributors.

    MMPMR says most of the corpus is failed attacks, so the all-morphs ACER largely scores
    the detection of morphs that would never have worked. This re-scores the *same* model
    on the *same* test split with the attack class narrowed to verifying morphs -- the
    genuine class is unchanged. It is the real number, and it is only reported when the
    attack class is large enough to carry one: below
    `detect.morph.min_verifying_attacks_reported`, the cell is BLOCKED with the count.

    The model is still trained on all train-split morphs. Retraining on verifying morphs
    alone would answer a different question (and on a much smaller training set); this one
    asks how the deployed detector does on the attacks that matter.
    """
    if "_test_scores" not in detection:
        return blocked("no detection scores to re-slice")
    floor = int(settings.detect.morph.min_verifying_attacks_reported)
    rows = detection["_test_scores"]
    genuine = [r["score"] for r in rows if r["label"] == "bona_fide"]
    morphs = [r for r in rows if r["label"] == "morph"]
    verifying = [r for r in morphs if verifies_by_path.get(r["path"]) is True]
    unknown = sum(1 for r in morphs if r["path"] not in verifies_by_path)

    counts = {
        "n_test_morphs": len(morphs),
        "n_test_morphs_verifying": len(verifying),
        "n_test_morphs_verification_unknown": unknown,
        "n_test_bona_fide": len(genuine),
        "verifying_by_method": {
            m: sum(1 for r in verifying if r["method"] == m)
            for m in sorted({r["method"] for r in morphs})
        },
        "min_verifying_attacks_reported": floor,
    }
    if len(verifying) < floor:
        return blocked(
            f"only {len(verifying)} of {len(morphs)} test-split morphs verify as both "
            f"contributors, below the {floor}-attack floor "
            "(detect.morph.min_verifying_attacks_reported); a figure on that few would "
            "carry a confidence interval wider than the effects being reported",
            **counts,
        )

    report = acc.detector_accuracy_report(genuine, [r["score"] for r in verifying], threshold)
    missed = sum(1 for r in verifying if r["score"] < threshold)
    lower, upper = _clopper_pearson(missed, len(verifying))
    return {**dict(report), **counts, "apcer_ci95": [lower, upper]}


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


def all_rows_for_lookup(per_method: dict[str, list[dict[str, Any]]]) -> list[dict[str, Any]]:
    return [row for rows in per_method.values() for row in rows]


MMPMR_BANDS = 5


def _mmpmr_by_pair_cosine(per_method: dict[str, list[dict[str, Any]]]) -> dict[str, Any]:
    """MMPMR per quintile of contributing-pair ArcFace cosine, per method.

    Separates two explanations for a low MMPMR that the headline rate cannot tell apart.
    If the *pool* is the limit, MMPMR climbs steeply with pair similarity and the closest
    look-alikes verify at a high rate. If the *method* is the limit, MMPMR stays low even
    in the most similar band. Quintile edges come from the data rather than chosen cut
    points, and the top decile is reported on its own because the pool question is really
    about the closest pairs available. Costs nothing: every embedding is already computed.
    """
    rows = [r for rs in per_method.values() for r in rs if r.get("pair_cosine") is not None]
    if not rows:
        return blocked("no morph rows carry a pair cosine")
    cosines = np.array([r["pair_cosine"] for r in rows], dtype=float)
    edges = [float(np.quantile(cosines, q)) for q in np.linspace(0.0, 1.0, MMPMR_BANDS + 1)]
    top_cut = float(np.quantile(cosines, 0.9))

    def band_of(value: float) -> int:
        for band in range(MMPMR_BANDS):
            if value <= edges[band + 1]:
                return band
        return MMPMR_BANDS - 1

    out: dict[str, Any] = {"band_edges": edges, "top_decile_pair_cosine_min": top_cut}
    for method, method_rows in per_method.items():
        usable = [r for r in method_rows if r.get("pair_cosine") is not None]
        bands = []
        for band in range(MMPMR_BANDS):
            members = [r for r in usable if band_of(r["pair_cosine"]) == band]
            n_verifying = int(sum(r["verifies_all_contributors"] for r in members))
            bands.append(
                {
                    "pair_cosine_range": [edges[band], edges[band + 1]],
                    "n_morphs": len(members),
                    "n_verifying": n_verifying,
                    "mmpmr": float(n_verifying / len(members)) if members else None,
                }
            )
        top = [r for r in usable if r["pair_cosine"] >= top_cut]
        out[method] = {
            "bands": bands,
            "top_decile": {
                "n_morphs": len(top),
                "n_verifying": int(sum(r["verifies_all_contributors"] for r in top)),
                "mmpmr": (
                    float(np.mean([r["verifies_all_contributors"] for r in top])) if top else None
                ),
            },
        }
    return out


def evaluate_mmpmr(features: dict[str, Any], corpus_dir: Path) -> dict[str, Any]:
    """MMPMR: does the morph verify as **every** contributing identity?

    Per Scherhag et al., a morph presentation succeeds only if the *minimum* similarity
    across its contributors clears the verification threshold -- one contributor passing is
    not an attack, it is just a photograph of that person. `match_cosine_min` is the
    threshold `match.py` deploys, so this is the real decision boundary, not a
    detector-specific one.
    """
    cosine_min = float(settings.detect.thresholds.match_cosine_min)
    cache = features.get("embedding_by_path", {})
    reference: dict[str, np.ndarray] = {}
    for identity, rel in features["bona_fide_by_identity"].items():
        embedding = cache[rel] if rel in cache else _embedding(_read(corpus_dir, rel))
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
                "pair_cosine": row.get("pair_cosine"),
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
            "n_verifying": int(sum(r["verifies_all_contributors"] for r in rows)),
            "mmpmr": float(np.mean([r["verifies_all_contributors"] for r in rows])),
            "any_contributor_match_rate": float(
                np.mean([r["verifies_any_contributor"] for r in rows])
            ),
            "min_similarity_mean": float(np.mean([r["min_similarity"] for r in rows])),
            "min_similarity_max": float(np.max([r["min_similarity"] for r in rows])),
        }
    summary["_verifies_by_path"] = {
        r["path"]: r["verifies_all_contributors"] for r in all_rows_for_lookup(per_method)
    }
    if all_rows:
        by_split: dict[str, list[bool]] = {}
        split_of_path = {row["path"]: row["split"] for row in features["rows"]}
        for r in all_rows:
            by_split.setdefault(split_of_path.get(r["path"], "?"), []).append(
                r["verifies_all_contributors"]
            )
        summary["verifying_count_by_split"] = {k: int(sum(v)) for k, v in by_split.items()}
        summary["by_pair_cosine_quintile"] = _mmpmr_by_pair_cosine(per_method)
        summary["overall"] = {
            "n_morphs": len(all_rows),
            "n_verifying": int(sum(r["verifies_all_contributors"] for r in all_rows)),
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
    }
    mmpmr = evaluate_mmpmr(features, corpus)
    verifies_by_path = mmpmr.pop("_verifies_by_path")
    result["mmpmr"] = mmpmr

    for setting, model_out in (
        ("smad", smad_model_out or DEFAULT_SMAD_MODEL_PATH),
        ("dmad", dmad_model_out or DEFAULT_DMAD_MODEL_PATH),
    ):
        detection = evaluate_detection(features, setting, threshold)
        booster = detection.pop("_booster", None)
        if booster is not None and model_out is not None:
            model_out.parent.mkdir(parents=True, exist_ok=True)
            booster.save_model(str(model_out))
            # Record the new SHA-256 immediately. The server verifies every
            # checksums.txt entry at startup and refuses to run on a mismatch, so a
            # retrain that writes the model without updating the checksum leaves the
            # server unable to start -- which is exactly what happened on the first
            # `make bench` after morph landed: the accuracy stage retrained, the latency
            # stage could not boot the app. `injection.py` has always done this; morph
            # has to as well.
            _record_model_checksum(model_out)
            detection["model_path"] = str(model_out.name)
        # Two views of the same model on the same test split: every morph, and only the
        # morphs that verify as both contributors. The second is the real number.
        result[f"{setting}_verifying_morphs_only"] = evaluate_verifying_subset(
            detection, verifies_by_path, threshold
        )
        detection.pop("_test_scores", None)
        detection["attack_class"] = "all test-split morphs, verifying or not"
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
