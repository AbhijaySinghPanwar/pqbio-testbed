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
    """The verdict is computed over the *unsaturated* region only (lowest level up to
    peak throughput). Past saturation, p99 rising in proportion to offered concurrency
    is ordinary queueing, not a blocked event loop -- so every fixture here has to
    carry `throughput_per_s`, and where the peak sits decides which levels are read.
    """

    def test_flags_linear_degradation_below_saturation(self):
        # throughput still climbing at the top level -> the whole sweep is unsaturated,
        # so p99 growing exactly in proportion is a real red flag
        levels = [
            {"concurrency": 1, "throughput_per_s": 1.0, "latency": {"p99_ms": 100.0}},
            {"concurrency": 64, "throughput_per_s": 64.0, "latency": {"p99_ms": 6400.0}},
        ]
        finding = _degradation_finding(levels)
        assert finding["linear_degradation_detected"] is True
        assert finding["unsaturated_p99_growth_ratio"] == 64.0
        assert finding["unsaturated_concurrency_growth_ratio"] == 64.0

    def test_does_not_flag_flat_latency(self):
        levels = [
            {"concurrency": 1, "throughput_per_s": 1.0, "latency": {"p99_ms": 100.0}},
            {"concurrency": 64, "throughput_per_s": 64.0, "latency": {"p99_ms": 150.0}},
        ]
        finding = _degradation_finding(levels)
        assert finding["linear_degradation_detected"] is False

    def test_post_saturation_growth_is_excluded_from_the_verdict(self):
        """The case that used to produce a false alarm: throughput peaks early, then
        latency climbs steeply past the peak purely from queueing. The verdict must be
        read from the sub-peak region only, and the post-peak rise must be named as
        queueing rather than counted as evidence of blocking.
        """
        levels = [
            {"concurrency": 1, "throughput_per_s": 2.0, "latency": {"p99_ms": 500.0}},
            {"concurrency": 8, "throughput_per_s": 3.6, "latency": {"p99_ms": 900.0}},
            {"concurrency": 64, "throughput_per_s": 3.1, "latency": {"p99_ms": 20000.0}},
        ]
        finding = _degradation_finding(levels)
        assert finding["peak_throughput_concurrency"] == 8
        # 1->8: p99 1.8x against 8x concurrency -> well below proportional
        assert finding["linear_degradation_detected"] is False
        # the 40x post-peak rise is described, but did not drive the verdict
        assert finding["p99_growth_ratio_full_sweep"] == 40.0
        assert "queueing against a saturated worker pool" in finding["finding"]

    def test_finding_states_it_cannot_answer_the_event_loop_question_alone(self):
        """A latency curve cannot separate a blocked event loop from CPU/worker
        saturation, so the finding must say so and point at the direct test.
        """
        levels = [
            {"concurrency": 1, "throughput_per_s": 2.0, "latency": {"p99_ms": 500.0}},
            {"concurrency": 8, "throughput_per_s": 3.6, "latency": {"p99_ms": 900.0}},
        ]
        finding = _degradation_finding(levels)["finding"]
        assert "cannot separate a blocked event loop" in finding
        assert "test_event_loop_stays_responsive_while_verify_is_in_flight" in finding
