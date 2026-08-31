"""Integration test for pqbio/bench/loadgen.py: a small-scale sweep (not the full
{1,2,4,8,16,32,64} — that runs for real via `make bench`/scripts/run_full_eval.py, and
is too slow for a unit-test-speed suite) that exercises the real concurrency-sweep
machinery end to end and checks its outputs are well-formed.
"""

from __future__ import annotations

from pqbio.bench.loadgen import _degradation_finding, _find_knee, sweep_concurrency


def test_small_sweep_produces_well_formed_results():
    result = sweep_concurrency(concurrency_levels=(1, 2), requests_per_worker=1, n_frames=4)
    levels = result["concurrency_levels"]
    assert len(levels) == 2
    assert levels[0]["concurrency"] == 1
    assert levels[1]["concurrency"] == 2
    for level in levels:
        assert level["requested"] == level["concurrency"]
        assert level["setup_failed_before_verify"] == 0
        assert level["expired_before_verify"] == 0
        assert level["throughput_per_s"] > 0.0
        assert level["latency"]["n"] == level["concurrency"]
    assert "knee" in result
    assert "degradation_finding" in result
    assert "finding" in result["degradation_finding"]


class TestFindKnee:
    def test_hand_computed_knee(self):
        # throughput doubles 1->2 (100% gain) then barely moves 2->4 (5% gain, below
        # the 10% default threshold) -- the knee is at concurrency=2.
        levels = [
            {"concurrency": 1, "throughput_per_s": 1.0},
            {"concurrency": 2, "throughput_per_s": 2.0},
            {"concurrency": 4, "throughput_per_s": 2.1},
        ]
        knee = _find_knee(levels)
        assert knee["concurrency"] == 2

    def test_no_knee_when_throughput_keeps_climbing(self):
        levels = [
            {"concurrency": 1, "throughput_per_s": 1.0},
            {"concurrency": 2, "throughput_per_s": 2.0},
            {"concurrency": 4, "throughput_per_s": 4.0},
        ]
        knee = _find_knee(levels)
        assert knee["concurrency"] is None


class TestDegradationFinding:
    def test_flags_linear_degradation(self):
        levels = [
            {"concurrency": 1, "latency": {"p99_ms": 100.0}},
            {"concurrency": 64, "latency": {"p99_ms": 6400.0}},  # exactly proportional
        ]
        finding = _degradation_finding(levels)
        assert finding["linear_degradation_detected"] is True
        assert finding["p99_growth_ratio"] == 64.0
        assert finding["concurrency_growth_ratio"] == 64.0

    def test_does_not_flag_flat_latency(self):
        levels = [
            {"concurrency": 1, "latency": {"p99_ms": 100.0}},
            {"concurrency": 64, "latency": {"p99_ms": 150.0}},  # far below proportional
        ]
        finding = _degradation_finding(levels)
        assert finding["linear_degradation_detected"] is False
