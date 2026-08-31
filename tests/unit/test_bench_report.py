"""Unit tests for pqbio/bench/report.py's rendering functions against hand-crafted
synthetic results, not a real evaluation run -- verifying the BLOCKED-cell convention
renders correctly is what matters here, independent of whether real numbers exist yet.
"""

from __future__ import annotations

from pqbio.bench._common import blocked
from pqbio.bench.report import (
    _collect_blocked,
    render_t1,
    render_t3,
    render_t4,
    render_t6,
    render_t7,
)


class TestRenderT1:
    def test_blocked_cell_renders_as_explicit_row_not_blank(self):
        accuracy = {
            "T1_per_detector_accuracy_intra_dataset": {
                "pad": blocked("no pad.py detector implemented"),
                "injection": {
                    "apcer": 0.0,
                    "bpcer": 0.0,
                    "acer": 0.0,
                    "eer": 0.0,
                    "auc_roc": 1.0,
                    "tdr_at_far_1pct": 1.0,
                    "n_genuine": 7,
                    "n_attack": 7,
                },
            }
        }
        md = render_t1(accuracy)
        assert "BLOCKED — no pad.py detector implemented" in md
        assert "injection" in md
        assert "1.0000" in md  # auc_roc rendered as a real number

    def test_missing_accuracy_json_renders_blocked_not_a_crash(self):
        md = render_t1(None)
        assert "BLOCKED" in md


class TestRenderT3:
    def test_real_fusion_comparison_renders(self):
        accuracy = {
            "T3_fusion_strategy_comparison": {
                "rule_accuracy": 0.9,
                "cascade_accuracy": 1.0,
                "n_samples": 50,
                "scope_note": "synthetic corpus only",
            }
        }
        md = render_t3(accuracy)
        assert "0.9000" in md
        assert "1.0000" in md
        assert "synthetic corpus only" in md

    def test_blocked_fusion_comparison_renders_blocker(self):
        accuracy = {"T3_fusion_strategy_comparison": blocked("no corpus available")}
        md = render_t3(accuracy)
        assert "BLOCKED — no corpus available" in md


class TestRenderT4:
    def test_mixed_real_and_blocked_rows(self):
        accuracy = {
            "T4_per_attack_detection_rate": {
                "injection_tier1": 1.0,
                "morph": blocked("no morph detector"),
            }
        }
        md = render_t4(accuracy)
        assert "1.0000" in md
        assert "BLOCKED — no morph detector" in md


class TestRenderT6:
    def test_c0_real_c1_c2_c3_blocked(self):
        overhead = {
            "C0": {
                "crypto": "none",
                "ai": "none",
                "isolates": "framework/transport floor",
                "latency": {"mean_ms": 1.5},
            },
            "C1": blocked("fallback backend active", config="C1"),
            "C2": blocked("fallback backend active", config="C2"),
            "C3": blocked("fallback backend active", config="C3"),
            "pq_overhead_ms": blocked("requires C1 and C2"),
            "ai_overhead_ms": blocked("requires C2 and C3"),
            "ai_to_pq_overhead_ratio": blocked("requires both overheads"),
        }
        md = render_t6(overhead)
        assert "1.5000" in md
        assert md.count("BLOCKED") >= 6  # 3 config rows + 3 derived quantities

    def test_missing_file_renders_blocked(self):
        md = render_t6(None)
        assert "BLOCKED" in md


class TestRenderT7:
    def test_throughput_table_and_findings_render(self):
        loadgen = {
            "concurrency_levels": [
                {
                    "concurrency": 1,
                    "throughput_per_s": 0.5,
                    "latency": {"p50_ms": 100.0, "p95_ms": 110.0, "p99_ms": 120.0},
                },
                {
                    "concurrency": 2,
                    "throughput_per_s": 0.9,
                    "latency": {"p50_ms": 105.0, "p95_ms": 115.0, "p99_ms": 125.0},
                },
            ],
            "knee": {"concurrency": None, "reason": "kept climbing"},
            "degradation_finding": {"finding": "well below proportional growth"},
        }
        md = render_t7(loadgen)
        assert "0.500" in md
        assert "well below proportional growth" in md


class TestCollectBlocked:
    def test_finds_nested_blocked_entries(self):
        data = {
            "top": blocked("top reason"),
            "nested": {"a": {"b": blocked("nested reason")}},
            "list": [1, 2, blocked("list reason")],
            "real": {"value": 1.0},
        }
        sink: list[dict[str, str]] = []
        _collect_blocked(data, "", "test.json", sink)
        blockers = {entry["blocker"] for entry in sink}
        assert blockers == {"top reason", "nested reason", "list reason"}
        paths = {entry["path"] for entry in sink}
        assert "top" in paths
        assert "nested.a.b" in paths
        assert "list[2]" in paths

    def test_no_false_positives_on_real_data(self):
        data = {"real": {"apcer": 0.0, "bpcer": 0.0}, "n": 5}
        sink: list[dict[str, str]] = []
        _collect_blocked(data, "", "test.json", sink)
        assert sink == []
