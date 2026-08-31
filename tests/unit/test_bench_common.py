"""Unit tests for pqbio/bench/_common.py's pure helpers: percentile/latency_stats and
the BLOCKED-cell convention.
"""

from __future__ import annotations

import pytest

from pqbio.bench._common import blocked, is_blocked, latency_stats, percentile


class TestPercentile:
    def test_median_of_odd_length_is_middle_value(self):
        assert percentile([1, 2, 3, 4, 5], 50) == 3

    def test_p0_is_minimum(self):
        assert percentile([5, 1, 3, 2, 4], 0) == 1

    def test_p100_is_maximum(self):
        assert percentile([5, 1, 3, 2, 4], 100) == 5

    def test_single_value(self):
        assert percentile([42.0], 50) == 42.0
        assert percentile([42.0], 99) == 42.0

    def test_empty_raises(self):
        with pytest.raises(ValueError):
            percentile([], 50)


class TestLatencyStats:
    def test_hand_computed_stats(self):
        samples = [10.0, 20.0, 30.0, 40.0, 50.0]
        stats = latency_stats(samples)
        assert stats["n"] == 5
        assert stats["mean_ms"] == pytest.approx(30.0)
        assert stats["min_ms"] == 10.0
        assert stats["max_ms"] == 50.0
        assert stats["p50_ms"] == pytest.approx(30.0)

    def test_empty_raises(self):
        with pytest.raises(ValueError):
            latency_stats([])

    def test_p99_never_exceeds_max(self):
        samples = [1.0, 2.0, 3.0, 100.0]
        stats = latency_stats(samples)
        assert stats["p99_ms"] <= stats["max_ms"]


class TestBlockedConvention:
    def test_blocked_cell_shape(self):
        cell = blocked("no dataset available")
        assert cell["blocked"] is True
        assert cell["blocker"] == "no dataset available"

    def test_blocked_cell_carries_extra_fields(self):
        cell = blocked("no dataset available", config="C1")
        assert cell["config"] == "C1"

    def test_is_blocked_true_for_blocked_cell(self):
        assert is_blocked(blocked("reason")) is True

    def test_is_blocked_false_for_real_data(self):
        assert is_blocked({"apcer": 0.0, "bpcer": 0.0}) is False
        assert is_blocked(0.5) is False
        assert is_blocked(None) is False
        assert is_blocked([1, 2, 3]) is False

    def test_is_blocked_false_when_blocked_key_is_falsy(self):
        # a real result that happens to have an unrelated "blocked" key set to False
        # must not be misread as a blocked cell
        assert is_blocked({"blocked": False, "value": 1.0}) is False
