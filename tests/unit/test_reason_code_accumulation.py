"""A rejection must carry everything determined, and the metrics must collapse it sanely.

Before 2026-09-06, `PipelineRejection` replaced the reason-code list with the triggering
code alone, so an injected bundle that also hit the reuse index was filed as
`BIND_EVIDENCE_REUSE` and the injection detector's positive result -- already computed --
never reached §8.1's per-attack rates or the audit log. The decision was `REJECT` either
way, so this was never a security hole; it was a measurement hole, and §8.1's numbers are
the deliverable.

Fixing it makes decisions multi-code, which makes the single-label 6-class matrix
ambiguous unless the collapse is defined. These tests pin both halves: what survives a
rejection, and how the survivors collapse to one label.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from uuid import uuid4

import pytest
from _server_fixtures import ServerTestClient, _quality_pass_crop
from fastapi.testclient import TestClient

from pqbio.bench.accuracy import (
    ATTACK_CODE_PRECEDENCE,
    classify_decisions,
    confusion_matrix_6class,
    predicted_attack_class,
)
from pqbio.server.app import create_app
from pqbio.server.pipeline import TRIGGER_PREFIX


class TestPrecedenceCollapse:
    """Known-count synthetic samples. Every expected number here is derived by hand from
    the precedence table, not read back from the implementation.
    """

    def test_single_attack_code_maps_to_its_class(self) -> None:
        assert predicted_attack_class(["INJECTION_DETECTED"]) == "injection"
        assert predicted_attack_class(["BIND_EVIDENCE_REUSE"]) == "replay"
        assert predicted_attack_class(["BIND_CHALLENGE_UNMET"]) == "replay"

    def test_detector_verdict_outranks_a_binding_inference(self) -> None:
        """The ordering principle: a detector that examined the media and named an attack
        outranks a binding check that inferred one from protocol evidence."""
        codes = ["BIND_EVIDENCE_REUSE", "INJECTION_DETECTED", "B1_OK"]
        assert predicted_attack_class(codes) == "injection"

    def test_order_within_the_list_does_not_matter(self) -> None:
        """Precedence comes from the table, never from the order codes happen to appear
        in -- which varies with which stage rejected."""
        a = ["INJECTION_DETECTED", "BIND_EVIDENCE_REUSE"]
        assert predicted_attack_class(a) == predicted_attack_class(list(reversed(a)))

    def test_non_attributing_rejections_are_none_not_a_nearest_class(self) -> None:
        """A forged signature or a counter regression is a real rejection that names no
        attack type. Folding it into the nearest-looking class would invent an
        attribution the system never made."""
        for code in (
            "CRYPTO_DEVICE_SIG_INVALID",
            "BIND_COUNTER_REGRESSION",
            "BIND_NONCE_REPLAY",
            "QUALITY_INSUFFICIENT",
            "BIND_CHALLENGE_UNEVALUABLE",
        ):
            assert predicted_attack_class([code, "B1_OK", "B2_OK"]) is None

    def test_trigger_markers_are_ignored_by_the_collapse(self) -> None:
        """Which code ENDED the request is a different question from which attack was
        attributed; the prefixed copy must not double-count."""
        codes = ["BIND_EVIDENCE_REUSE", f"{TRIGGER_PREFIX}BIND_EVIDENCE_REUSE"]
        assert predicted_attack_class(codes) == "replay"
        result = classify_decisions([{"decision": "REJECT", "reason_codes": codes}])
        assert result["multi_attribution_count"] == 0

    def test_known_counts_over_a_mixed_batch(self) -> None:
        """Ten decisions, counted by hand:

        3 accepts                                    -> bona_fide x3
        2 injection-only                             -> injection x2
        2 injection + reuse (multi)                  -> injection x2, multi x2
        1 reuse-only                                 -> replay x1
        2 counter regression (names no attack)       -> None x2
        """
        decisions = (
            [{"decision": "ACCEPT", "reason_codes": ["B1_OK", "B6_OK"]}] * 3
            + [{"decision": "REJECT", "reason_codes": ["INJECTION_DETECTED"]}] * 2
            + [
                {
                    "decision": "REJECT",
                    "reason_codes": ["BIND_EVIDENCE_REUSE", "INJECTION_DETECTED"],
                }
            ]
            * 2
            + [{"decision": "REJECT", "reason_codes": ["BIND_EVIDENCE_REUSE"]}]
            + [{"decision": "REJECT", "reason_codes": ["BIND_COUNTER_REGRESSION"]}] * 2
        )
        result = classify_decisions(decisions)
        labels = result["labels"]

        assert len(labels) == 10
        assert labels.count("bona_fide") == 3
        assert labels.count("injection") == 4
        assert labels.count("replay") == 1
        assert labels.count(None) == 2
        assert result["non_attributing_rejections"] == 2
        assert result["multi_attribution_count"] == 2
        assert result["multi_attribution_detail"][0] == {
            "chosen": "injection",
            "also_matched": ["replay"],
        }

    def test_the_collapse_feeds_the_matrix_without_none_labels(self) -> None:
        """`None` labels are excluded from the 6-class matrix, not coerced. This is the
        contract the matrix's interpretability rests on (§8.1)."""
        decisions = [
            {"decision": "REJECT", "reason_codes": ["INJECTION_DETECTED"]},
            {"decision": "REJECT", "reason_codes": ["BIND_COUNTER_REGRESSION"]},
            {"decision": "ACCEPT", "reason_codes": ["B1_OK"]},
        ]
        true_labels = ["injection", "injection", "bona_fide"]
        predicted = classify_decisions(decisions)["labels"]

        pairs = [(t, p) for t, p in zip(true_labels, predicted, strict=True) if p is not None]
        assert len(pairs) == 2  # the counter-regression sample is dropped, not miscounted

        matrix = confusion_matrix_6class([t for t, _ in pairs], [p for _, p in pairs])
        assert matrix["labels"][0] == "bona_fide"
        total = sum(sum(row) for row in matrix["matrix"])
        assert total == 2

    def test_precedence_table_covers_every_class_exactly_once_per_code(self) -> None:
        codes = [c for c, _ in ATTACK_CODE_PRECEDENCE]
        assert len(codes) == len(set(codes)), "a code cannot appear twice in the precedence"
        classes = {label for _, label in ATTACK_CODE_PRECEDENCE}
        assert classes == {"presentation", "morph", "deepfake", "replay", "injection"}


class TestRejectionCarriesWhatWasDetermined:
    """End to end on the real server. The reuse case is the one from §14's caveat."""

    @pytest.fixture
    def client(self):  # type: ignore[no-untyped-def]
        """A fresh data dir per test.

        The pHash reuse index persists, and the fixtures build byte-identical frames every
        time, so a shared dir means the very first genuine bundle is already "reused" --
        the seed step of the reuse test would fail for reasons that have nothing to do
        with what it is testing.
        """
        with (
            tempfile.TemporaryDirectory() as tmp,
            TestClient(create_app(data_dir=Path(tmp) / "data")) as c,
        ):
            yield c

    def test_reuse_rejection_keeps_the_binding_and_injection_results(self, client) -> None:  # type: ignore[no-untyped-def]
        stc = ServerTestClient(client, device_id=f"dev-{uuid4().hex[:8]}")
        stc.enroll()

        session_id, challenge_obj = stc.challenge()
        keys = stc.handshake(session_id)
        good = stc.build_live_genuine_bundle(session_id, challenge_obj, n_frames=30)
        assert stc.verify(session_id, good, keys).decision == "ACCEPT"

        # Same media, fresh session: stage 5 rejects, after stage 4 already ran.
        sid2, ch2 = stc.challenge()
        keys2 = stc.handshake(sid2)
        reused = stc.build_live_genuine_bundle(sid2, ch2, n_frames=30, counter=2)
        decision = stc.verify(sid2, reused, keys2)

        assert decision.decision == "REJECT"
        assert "BIND_EVIDENCE_REUSE" in decision.reason_codes
        # The results that used to be discarded:
        for code in ("B1_OK", "B2_OK", "B3_OK", "B4_OK", "B5_OK", "B6_OK"):
            assert code in decision.reason_codes, f"{code} was determined and must survive"
        assert "injection" in decision.detector_scores

    def test_the_trigger_is_identifiable_among_the_accumulated_codes(self, client) -> None:  # type: ignore[no-untyped-def]
        stc = ServerTestClient(client, device_id=f"dev-{uuid4().hex[:8]}")
        stc.enroll()
        session_id, challenge_obj = stc.challenge()
        keys = stc.handshake(session_id)
        bundle = stc.build_instant_bundle(
            session_id, challenge_obj, _quality_pass_crop(), n_frames=30, counter=0
        )
        decision = stc.verify(session_id, bundle, keys)

        triggers = [c for c in decision.reason_codes if c.startswith(TRIGGER_PREFIX)]
        assert triggers == [f"{TRIGGER_PREFIX}BIND_COUNTER_REGRESSION"]
        # The bare code is still present, so membership checks keep working.
        assert "BIND_COUNTER_REGRESSION" in decision.reason_codes
        # Passing checks determined before the trigger survive too.
        assert "B1_OK" in decision.reason_codes

    def test_audit_log_persists_the_full_code_list(self, client) -> None:  # type: ignore[no-untyped-def]
        """§5.5: the audit log records why a verification was rejected. "Why" is now the
        whole list, and the store must not truncate it."""
        stc = ServerTestClient(client, device_id=f"dev-{uuid4().hex[:8]}")
        stc.enroll()
        session_id, challenge_obj = stc.challenge()
        keys = stc.handshake(session_id)
        bundle = stc.build_instant_bundle(
            session_id, challenge_obj, _quality_pass_crop(), n_frames=30, counter=0
        )
        decision = stc.verify(session_id, bundle, keys)

        from pqbio.server.store import _connect

        audit = client.app.state.audit_log
        with _connect(audit._db_path) as conn:
            row = conn.execute(
                "SELECT decision_json FROM audit_log WHERE session_id = ?",
                (str(session_id),),
            ).fetchone()
        assert row is not None
        stored = json.loads(row[0])
        assert stored["reason_codes"] == decision.reason_codes
        assert len(stored["reason_codes"]) > 1, "the whole list, not just the trigger"
