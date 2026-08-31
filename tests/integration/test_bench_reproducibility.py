"""Module F DoD: "Same seed reproduces accuracy metrics exactly; timing within a
stated variance" (PROJECT_SPEC.md §5.6) -- tested directly, not asserted.
"""

from __future__ import annotations

import statistics
import tempfile
from pathlib import Path

from pqbio.bench.accuracy import detector_accuracy_report
from pqbio.bench.latency import measure_latency
from pqbio.detect.injection import DEFAULT_MODEL_PATH, train_and_evaluate

MANIFEST = (
    Path(__file__).resolve().parent.parent.parent
    / "data"
    / "manifests"
    / "injection_corpus_manifest.json"
)

# The accuracy pipeline itself is deterministic given a fixed seed (LightGBM's own
# "seed" param, plus a fixed train/test device split); the stated timing variance
# below is generous on purpose -- wall-clock latency in a shared/virtualised
# environment is never bit-reproducible the way accuracy numbers are, and the test
# exists to bound that noise, not eliminate it.
STATED_TIMING_VARIANCE_RATIO = 3.0


def test_same_seed_reproduces_injection_accuracy_exactly():
    with tempfile.TemporaryDirectory() as tmp:
        r1 = train_and_evaluate(
            MANIFEST, model_out=DEFAULT_MODEL_PATH, results_out=Path(tmp) / "r1.json", seed=2026
        )
        r2 = train_and_evaluate(
            MANIFEST, model_out=DEFAULT_MODEL_PATH, results_out=Path(tmp) / "r2.json", seed=2026
        )

    assert r1["test_accuracy"] == r2["test_accuracy"]
    assert r1["test_auc"] == r2["test_auc"]
    assert r1["test_scores"] == r2["test_scores"]
    assert r1["n_train_devices"] == r2["n_train_devices"]
    assert r1["n_test_devices"] == r2["n_test_devices"]


def test_same_seed_reproduces_downstream_metrics_exactly():
    """The reproducibility guarantee has to survive accuracy.py's own metric
    functions too, not just the detector's raw scores -- EER/AUC/TDR involve
    floating-point sweeps and interpolation, which is exactly where non-determinism
    would sneak in if it were going to.
    """
    with tempfile.TemporaryDirectory() as tmp:
        r1 = train_and_evaluate(
            MANIFEST, model_out=DEFAULT_MODEL_PATH, results_out=Path(tmp) / "r1.json", seed=2026
        )
        r2 = train_and_evaluate(
            MANIFEST, model_out=DEFAULT_MODEL_PATH, results_out=Path(tmp) / "r2.json", seed=2026
        )

    scores1, scores2 = r1["test_scores"], r2["test_scores"]
    threshold = r1["threshold"]
    report1 = detector_accuracy_report(scores1["bona_fide"], scores1["injection_tier1"], threshold)
    report2 = detector_accuracy_report(scores2["bona_fide"], scores2["injection_tier1"], threshold)
    assert report1 == report2


def test_latency_timing_stays_within_stated_variance():
    """Two independent small latency runs' mean end-to-end latency should stay within
    STATED_TIMING_VARIANCE_RATIO of each other -- the explicit, measured bound on
    timing noise the DoD asks for, rather than an unstated assumption of stability.
    """
    result1 = measure_latency(n_requests=5, n_frames=4)
    result2 = measure_latency(n_requests=5, n_frames=4)

    mean1 = result1["end_to_end_client_observed"]["mean_ms"]
    mean2 = result2["end_to_end_client_observed"]["mean_ms"]
    ratio = max(mean1, mean2) / min(mean1, mean2)
    assert ratio <= STATED_TIMING_VARIANCE_RATIO, (
        f"latency mean varied {ratio:.2f}x between two runs ({mean1:.1f}ms vs "
        f"{mean2:.1f}ms), outside the stated {STATED_TIMING_VARIANCE_RATIO}x bound"
    )


def test_latency_stats_computation_itself_is_deterministic():
    """The pure statistics computation (not the live timing) must be bit-exact -- no
    hidden randomness in percentile/mean arithmetic.
    """
    from pqbio.bench._common import latency_stats

    samples = [12.3, 45.6, 7.8, 90.1, 23.4, 56.7, 8.9, 34.5]
    stats1 = latency_stats(samples)
    stats2 = latency_stats(list(samples))  # fresh list, same values
    assert stats1 == stats2
    assert statistics.mean(samples) == stats1["mean_ms"]
