"""One-command driver for the full Module F evaluation suite (PROJECT_SPEC.md §5.6):
`make bench` runs this. Trains/evaluates the injection detector, computes every §8.1
accuracy metric (real where data exists, BLOCKED elsewhere), measures latency, sweeps
concurrency to 64, samples resources, runs the C0-C3 overhead ablation, refreshes the
crypto micro-benchmark, and renders results/report.md + results/BLOCKERS.md.

No manual steps: every number lands in `results/*.json` first, and every table/figure
in the report is rendered from that JSON, never hand-assembled (§0, §5.6 DoD).

Owner: Abhijay
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from pqbio.bench._common import (  # noqa: E402
    RESULTS_DIR,
    blocked,
    is_blocked,
    print_progress,
    run_metadata,
    write_json,
)

MANIFEST_PATH = REPO_ROOT / "data" / "manifests" / "injection_corpus_manifest.json"
MORPH_MANIFEST_PATH = REPO_ROOT / "data" / "manifests" / "morph_corpus_manifest.json"
MORPH_CORPUS_DIR = REPO_ROOT / "data" / "processed" / "morph_corpus"
SEED = 2026


# ----------------------------------------------------------------------------------
# Stage 1: accuracy (§8.1) -- real numbers for injection, BLOCKED everywhere else
# ----------------------------------------------------------------------------------


def run_accuracy_stage() -> dict[str, Any]:
    from pqbio.bench import accuracy as acc
    from pqbio.detect.fusion import (
        DEFAULT_CASCADE_MODEL_PATH,
        compare_strategies_on_corpus,
        train_cascade_model,
    )
    from pqbio.detect.injection import DEFAULT_MODEL_PATH, train_and_evaluate

    def no_detector(name: str, module: str) -> dict[str, Any]:
        if module == "replay":
            # More precise than "dataset-blocked": as of 2026-09-01 the hardware blocker
            # is gone (camera + display verified working, WB/exposure lock demonstrated
            # -- results/live_challenge_check.json), so what actually blocks the
            # self-recorded route named in §5.4 D4 is human subjects, not equipment.
            return blocked(
                "no replay detector implemented -- pqbio/detect/replay.py is deliberately "
                "absent, not stubbed. Replay-Attack/MSU-MFSD are unlicensed (§6), and the "
                "self-recorded alternative is blocked on human subjects rather than "
                "hardware: §6 requires written consent and supervisor approval to record "
                "anyone, and a subject-disjoint split needs at least two consenting "
                "subjects. The capture rig itself is verified working (camera, display, "
                "WB/exposure lock -- PROJECT_SPEC.md §14, 2026-09-01)"
            )
        return blocked(
            f"no {name} detector implemented -- pqbio/detect/{module}.py is deliberately "
            "absent, not stubbed (dataset-blocked, see CLAUDE.md 'Current state' / "
            "PROJECT_SPEC.md §14)"
        )

    only_one_dataset = blocked(
        "only one dataset exists in this environment (the self-generated injection "
        "corpus) -- cross-dataset evaluation needs a second, independent dataset (§6)"
    )

    injection_result = train_and_evaluate(MANIFEST_PATH, model_out=DEFAULT_MODEL_PATH, seed=SEED)
    scores = injection_result.get("test_scores")
    threshold = injection_result["threshold"]

    if scores and scores["bona_fide"] and scores["injection_tier1"]:
        genuine_scores, attack_scores = scores["bona_fide"], scores["injection_tier1"]
        injection_report: dict[str, Any] = acc.detector_accuracy_report(
            genuine_scores, attack_scores, threshold
        )
        det_curve: dict[str, Any] = acc.det_curve_data(genuine_scores, attack_scores)
        per_attack: dict[str, Any] = acc.per_attack_detection_rate(
            {"injection_tier1": attack_scores}, threshold
        )
    else:
        empty_reason = "injection corpus test split had zero samples for one class"
        injection_report = blocked(empty_reason)
        det_curve = blocked(empty_reason)
        per_attack = {"injection_tier1": blocked(empty_reason)}

    cascade_model = train_cascade_model(
        MANIFEST_PATH, injection_model_path=DEFAULT_MODEL_PATH, seed=SEED
    )
    DEFAULT_CASCADE_MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    DEFAULT_CASCADE_MODEL_PATH.write_text(
        json.dumps(cascade_model.to_json(), indent=2) + "\n", encoding="utf-8"
    )
    fusion_comparison = compare_strategies_on_corpus(
        MANIFEST_PATH, injection_model_path=DEFAULT_MODEL_PATH, cascade_model=cascade_model
    )

    true_labels = [
        "bona_fide" if row["label"] == "bona_fide" else "injection"
        for row in fusion_comparison["rows"]
    ]
    predicted_labels = [
        "injection" if row["cascade_decision"] == "REJECT" else "bona_fide"
        for row in fusion_comparison["rows"]
    ]
    confusion = acc.confusion_matrix_6class(true_labels, predicted_labels)

    # --- morph (D2) -----------------------------------------------------------------
    # The corpus is never committed (LFW-derived, see data/LICENCES.md), so a checkout
    # without it must BLOCK rather than crash or silently skip the detector.
    morph_result: dict[str, Any]
    if MORPH_MANIFEST_PATH.is_file() and MORPH_CORPUS_DIR.is_dir():
        from pqbio.detect.morph_eval import train_and_evaluate as morph_train_and_evaluate

        morph_result = morph_train_and_evaluate(MORPH_MANIFEST_PATH, MORPH_CORPUS_DIR)
        write_json(RESULTS_DIR / "detectors" / "morph" / "results.json", morph_result)
    else:
        morph_result = blocked(
            "morph corpus not present -- regenerate with scripts/make_morph_corpus.py. "
            "It is LFW-derived and deliberately not committed (data/LICENCES.md); the "
            "manifest is, so this is a one-command rebuild, not a missing dependency"
        )

    def morph_cell(setting: str) -> dict[str, Any]:
        """One T1 row: headline metrics only.

        The cross-method sub-table deliberately does NOT go in here. A T1 cell is one row
        of a rendered table, and nesting a dict-of-dicts inside it dumps raw Python into
        the report. It gets its own top-level block instead, which is also where a reader
        looking for the §12 generalisation number would go looking.
        """
        if is_blocked(morph_result):
            return morph_result
        cell = {k: v for k, v in morph_result.get(setting, {}).items() if not isinstance(v, dict)}
        cell["setting"] = setting
        return cell

    def morph_detection_rate(setting: str) -> Any:
        """T4's per-attack rate for one morph cell: 1 - APCER, or the cell's BLOCKED marker
        (which carries the verifying-morph count when that is why it is blocked)."""
        cell = morph_cell(setting)
        if is_blocked(cell):
            return cell
        apcer = cell.get("apcer")
        if not isinstance(apcer, (int, float)):
            return blocked(f"morph {setting}: no APCER to derive a detection rate from")
        return 1.0 - float(apcer)

    detector_names = ["pad", "deepfake", "replay"]
    return {
        **run_metadata(seed=SEED),
        "T1_per_detector_accuracy_intra_dataset": {
            "injection": injection_report,
            # All morphs, then only the morphs that verify as both contributors. MMPMR says
            # most of the corpus is failed attacks, so the second pair is the real number;
            # its n_attack column is the verifying count, and below the configured floor
            # the cell BLOCKS with that count instead of reporting a figure.
            "morph_smad (all morphs)": morph_cell("smad"),
            "morph_smad (verifying morphs only)": morph_cell("smad_verifying_morphs_only"),
            "morph_dmad (all morphs)": morph_cell("dmad"),
            "morph_dmad (verifying morphs only)": morph_cell("dmad_verifying_morphs_only"),
            **{name: no_detector(name, name) for name in detector_names},
            "match": blocked(
                "no labelled genuine/impostor pair dataset exists to compute match FAR/FRR (§6)"
            ),
        },
        "T2_per_detector_accuracy_cross_dataset": {
            **{name: only_one_dataset for name in [*detector_names, "injection", "match"]},
            # Morph's own blocker: the shared one names the injection corpus, which was
            # simply wrong for these two rows in every report since morph landed.
            **{
                name: blocked(
                    "only one morph corpus exists (self-generated from LFW, "
                    "scripts/make_morph_corpus.py) -- cross-dataset evaluation needs an "
                    "independent morph dataset such as FRLL-Morphs or SMDD, neither "
                    "licensed (§6, data/LICENCES.md). Cross-METHOD generalisation within "
                    "the one corpus is the available proxy: T4c"
                )
                for name in ("morph_smad", "morph_dmad")
            },
        },
        "T3_fusion_strategy_comparison": {
            "rule_accuracy": fusion_comparison["rule_accuracy"],
            "cascade_accuracy": fusion_comparison["cascade_accuracy"],
            "n_samples": fusion_comparison["n_samples"],
            "scope_note": fusion_comparison["scope_note"],
        },
        "T4_per_attack_detection_rate": {
            **per_attack,
            "presentation": no_detector("presentation", "pad"),
            # One number per row: detection rate = 1 - APCER at the deployed threshold.
            # These were whole metric dicts until 2026-09-14, which report.py rendered as
            # raw Python in the committed report.md.
            "morph_smad (all morphs)": morph_detection_rate("smad"),
            "morph_smad (verifying morphs only)": morph_detection_rate(
                "smad_verifying_morphs_only"
            ),
            "morph_dmad (all morphs)": morph_detection_rate("dmad"),
            "morph_dmad (verifying morphs only)": morph_detection_rate(
                "dmad_verifying_morphs_only"
            ),
            "deepfake": no_detector("deepfake", "deepfake"),
            "replay": no_detector("replay", "replay"),
        },
        "confusion_matrix_6class": {
            **confusion,
            # Reconciliation for the matrix total (§8.1). Both are genuinely zero here,
            # and the reason matters: on this corpus the predicted label comes from each
            # sample's cascade DECISION, not from its reason codes, so no sample can carry
            # two attack attributions and none can be a rejection that names no attack
            # class. The single-label collapse has nothing to do on this data. It will,
            # once evaluation runs over real server decisions -- which is why the fields
            # are emitted rather than omitted, so the report renders the reconciliation in
            # both cases instead of only after the numbers first go non-zero.
            "non_attributing_rejections": 0,
            "multi_attribution_count": 0,
            "label_source": (
                "cascade decision per sample, not reason codes -- see the caveat below"
            ),
            "caveat": (
                "Only bona_fide and injection have real labelled samples in this "
                "environment; presentation/morph/deepfake/replay rows and columns are "
                "structurally zero, not measured-and-found-zero (§14)."
            ),
        },
        "morph_cross_method_generalisation": (
            morph_result
            if is_blocked(morph_result)
            else {
                setting: morph_result.get(f"{setting}_cross_method") for setting in ("smad", "dmad")
            }
        ),
        "det_curve": {"injection": det_curve},
        "mmpmr": (
            morph_result
            if is_blocked(morph_result)
            else morph_result.get(
                "mmpmr",
                blocked("morph evaluation produced no MMPMR block"),
            )
        ),
        "caveat": (
            "Every non-BLOCKED number here is measured on the self-generated synthetic "
            "injection corpus (scripts/make_injection_corpus.py) -- it describes how well "
            "the six D5 signals separate that synthetic construction from its genuine "
            "counterpart, not real-world detection rates against a real attacker (§14)."
        ),
    }


# ----------------------------------------------------------------------------------
# Stage 2: performance (§8.2) -- latency, throughput, resources
# ----------------------------------------------------------------------------------


def run_performance_stages(*, quick: bool) -> dict[str, Path]:
    from pqbio.bench import loadgen, resources
    from pqbio.bench.latency import measure_latency

    n_requests = 10 if quick else 40
    n_frames = 4 if quick else 8
    concurrency_levels = (1, 2, 4) if quick else (1, 2, 4, 8, 16, 32, 64)

    print_progress("=== latency ===")
    latency_result = measure_latency(n_requests=n_requests, n_frames=n_frames)
    latency_path = RESULTS_DIR / "latency.json"
    write_json(latency_path, latency_result)
    print_progress(f"wrote {latency_path}")

    print_progress("=== loadgen (concurrency sweep) ===")
    loadgen_result = loadgen.sweep_concurrency(
        concurrency_levels=concurrency_levels, requests_per_worker=1, n_frames=n_frames
    )
    loadgen_path = RESULTS_DIR / "loadgen.json"
    write_json(loadgen_path, loadgen_result)
    print_progress(f"wrote {loadgen_path}")
    print_progress(f"knee: {loadgen_result['knee']}")
    print_progress(f"degradation finding: {loadgen_result['degradation_finding']['finding']}")

    print_progress("=== resources (sampled during a latency run) ===")
    resources_result = resources.sample_during(
        lambda: measure_latency(n_requests=n_requests, n_frames=n_frames)
    )
    resources_path = RESULTS_DIR / "resources.json"
    write_json(resources_path, resources_result)
    print_progress(f"wrote {resources_path}")

    return {"latency": latency_path, "loadgen": loadgen_path, "resources": resources_path}


# ----------------------------------------------------------------------------------
# Stage 3: overhead ablation (§8.3)
# ----------------------------------------------------------------------------------


def run_overhead_stage(*, quick: bool) -> Path:
    from pqbio.bench.overhead import run_overhead_ablation

    print_progress("=== overhead ablation (C0-C3) ===")
    n_iterations = 10 if quick else 50
    result = run_overhead_ablation(n_iterations=n_iterations)
    path = RESULTS_DIR / "overhead_ablation.json"
    write_json(path, result)
    print_progress(f"wrote {path}")
    return path


# ----------------------------------------------------------------------------------
# Stage 4: crypto micro-benchmark (already Module A's own script; invoked here so
# `make bench` is one command and the file is refreshed against the current commit)
# ----------------------------------------------------------------------------------


def run_pqc_micro_stage(*, quick: bool) -> Path:
    print_progress("=== pqc micro-benchmark ===")
    import importlib

    bench_pqc = importlib.import_module("bench_pqc")
    iterations = 100 if quick else 1000
    result: dict[str, Any] = {
        "git_commit": bench_pqc._git_commit(),
        "config_hash_sha256": bench_pqc._config_hash(),
        "hardware": bench_pqc._hardware_description(),
        "iterations_per_operation": iterations,
        "generated_at_utc": run_metadata()["generated_at_utc"],
        "kem": {},
        "signer": {},
    }
    for mode in bench_pqc.MODES:
        result["kem"][mode] = bench_pqc.bench_kem(mode, iterations)
    for mode in bench_pqc.MODES:
        result["signer"][mode] = bench_pqc.bench_signer(mode, iterations)

    path = RESULTS_DIR / "pqc_micro.json"
    write_json(path, result)
    print_progress(f"wrote {path}")
    return path


# ----------------------------------------------------------------------------------
# Orchestration
# ----------------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--quick",
        action="store_true",
        help="smaller request counts / concurrency levels, for fast local iteration -- "
        "not the full sweep §8.2 asks for. Every stage still runs, nothing is skipped.",
    )
    parser.add_argument(
        "--skip-report", action="store_true", help="skip rendering results/report.md at the end"
    )
    args = parser.parse_args()

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    sys.path.insert(0, str(REPO_ROOT / "scripts"))  # for `import bench_pqc` above

    print_progress("=== accuracy ===")
    accuracy_result = run_accuracy_stage()
    accuracy_path = RESULTS_DIR / "accuracy.json"
    write_json(accuracy_path, accuracy_result)
    print_progress(f"wrote {accuracy_path}")

    run_performance_stages(quick=args.quick)
    run_overhead_stage(quick=args.quick)
    run_pqc_micro_stage(quick=args.quick)

    if not args.skip_report:
        from pqbio.bench.report import generate_report

        print_progress("=== report ===")
        report_path = generate_report()
        print_progress(f"wrote {report_path}")

        from pqbio.bench.report import write_blockers_document

        blockers_path = write_blockers_document()
        print_progress(f"wrote {blockers_path}")

    print_progress("=== done ===")


if __name__ == "__main__":
    main()
