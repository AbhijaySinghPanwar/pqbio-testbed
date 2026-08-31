"""Unit tests for pqbio/bench/accuracy.py against synthetic score distributions where
the correct answer is known analytically (PROJECT_SPEC.md §5.6 DoD) -- these metrics
must be verified before any real detector's scores are run through them, since four of
six detectors don't exist yet and most real invocations will be BLOCKED.
"""

from __future__ import annotations

import pytest

from pqbio.bench.accuracy import (
    acer,
    apcer,
    auc_roc,
    bpcer,
    confusion_matrix_6class,
    det_curve_data,
    detector_accuracy_report,
    eer,
    mmpmr,
    per_attack_detection_rate,
    tdr_at_far,
)


class TestApcerBpcerAcer:
    def test_perfect_separation_gives_zero_error(self):
        genuine = [0.1, 0.2, 0.3]
        attack = [0.7, 0.8, 0.9]
        assert apcer(attack, threshold=0.5) == 0.0
        assert bpcer(genuine, threshold=0.5) == 0.0
        assert acer(0.0, 0.0) == 0.0

    def test_hand_computed_partial_overlap(self):
        # attack scores below 0.5 (wrongly accepted): 0.3, 0.4 -> 2 of 4
        attack = [0.3, 0.4, 0.8, 0.9]
        # genuine scores >= 0.5 (wrongly rejected): 0.6, 0.7 -> 2 of 4
        genuine = [0.1, 0.2, 0.6, 0.7]
        assert apcer(attack, threshold=0.5) == pytest.approx(0.5)
        assert bpcer(genuine, threshold=0.5) == pytest.approx(0.5)
        assert acer(0.5, 0.5) == pytest.approx(0.5)

    def test_all_attacks_accepted_gives_apcer_one(self):
        assert apcer([0.0, 0.1, 0.2], threshold=0.5) == 1.0

    def test_all_genuine_rejected_gives_bpcer_one(self):
        assert bpcer([0.9, 0.8, 0.7], threshold=0.5) == 1.0

    def test_empty_input_raises(self):
        with pytest.raises(ValueError):
            apcer([], threshold=0.5)
        with pytest.raises(ValueError):
            bpcer([], threshold=0.5)


class TestEer:
    def test_perfect_separation_gives_zero_eer(self):
        genuine = [0.0, 0.1, 0.2]
        attack = [0.8, 0.9, 1.0]
        eer_value, _threshold = eer(genuine, attack)
        assert eer_value == pytest.approx(0.0, abs=1e-9)

    def test_identical_distributions_give_near_half_eer(self):
        # genuine and attack scores are drawn from the same values -> indistinguishable,
        # so the crossing point of APCER(t) and BPCER(t) sits near 0.5.
        genuine = [0.5] * 20
        attack = [0.5] * 20
        eer_value, _threshold = eer(genuine, attack)
        assert eer_value == pytest.approx(0.5, abs=1e-6)

    def test_symmetric_overlap_hand_computed(self):
        # genuine uniform on [0, 1), attack uniform on [0.4, 1.4) -- by construction the
        # two CDFs cross at score 0.7, where both APCER and BPCER equal 0.3 (30% of each
        # 10-point evenly spaced range falls on the "wrong" side of 0.7).
        genuine = [0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9]
        attack = [0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0, 1.1, 1.2, 1.3]
        eer_value, threshold = eer(genuine, attack)
        assert eer_value == pytest.approx(0.3, abs=0.05)
        assert threshold == pytest.approx(0.7, abs=0.15)


class TestAucRoc:
    def test_perfect_separation_gives_auc_one(self):
        genuine = [0.0, 0.1, 0.2]
        attack = [0.8, 0.9, 1.0]
        assert auc_roc(genuine, attack) == pytest.approx(1.0)

    def test_reversed_separation_gives_auc_zero(self):
        # attack scores are all LOWER than genuine -- the detector is anti-correlated
        # with the truth, which is the worst possible AUC.
        genuine = [0.8, 0.9, 1.0]
        attack = [0.0, 0.1, 0.2]
        assert auc_roc(genuine, attack) == pytest.approx(0.0)

    def test_identical_distributions_give_auc_half(self):
        genuine = [0.5] * 20
        attack = [0.5] * 20
        assert auc_roc(genuine, attack) == pytest.approx(0.5)


class TestTdrAtFar:
    def test_perfect_separation_gives_tdr_one(self):
        genuine = [0.0, 0.1, 0.2]
        attack = [0.8, 0.9, 1.0]
        tdr_value, far_target = tdr_at_far(genuine, attack, far_target=0.01)
        assert tdr_value == pytest.approx(1.0)
        assert far_target == 0.01

    def test_hand_constructed_exact_operating_point(self):
        # 90 genuine at 0.0 (should be accepted), 10 genuine at 1.0 (attack-like).
        # 99 attack at 1.0 (should be rejected), 1 attack at 0.0 (genuine-like).
        # At threshold=0.5: APCER = 1/100 = 0.01 (exactly the far_target), and the
        # genuine acceptance rate there (TDR) is exactly 90/100 = 0.90 by construction.
        genuine = [0.0] * 90 + [1.0] * 10
        attack = [1.0] * 99 + [0.0] * 1
        tdr_value, _far = tdr_at_far(genuine, attack, far_target=0.01)
        assert tdr_value == pytest.approx(0.90, abs=1e-6)


class TestMmpmr:
    def test_hand_computed_fraction(self):
        # morph 1: contributor A matches -> counts. morph 2: neither matches -> doesn't.
        # morph 3: both match -> counts. 2 of 3 morphs succeed at impersonating someone.
        contributor_matches = [[True, False], [False, False], [True, True]]
        assert mmpmr(contributor_matches) == pytest.approx(2 / 3)

    def test_no_morph_ever_matches_gives_zero(self):
        assert mmpmr([[False, False], [False]]) == 0.0

    def test_every_morph_matches_gives_one(self):
        assert mmpmr([[True], [False, True]]) == 1.0

    def test_empty_input_raises(self):
        with pytest.raises(ValueError):
            mmpmr([])


class TestPerAttackDetectionRate:
    def test_hand_computed_rates(self):
        scores_by_attack = {"pad": [0.9, 0.9], "morph": [0.1, 0.9], "deepfake": [0.1, 0.1]}
        rates = per_attack_detection_rate(scores_by_attack, threshold=0.5)
        assert rates == {
            "pad": pytest.approx(1.0),
            "morph": pytest.approx(0.5),
            "deepfake": pytest.approx(0.0),
        }

    def test_empty_scores_for_one_attack_raises(self):
        with pytest.raises(ValueError):
            per_attack_detection_rate({"pad": []}, threshold=0.5)


class TestConfusionMatrix6Class:
    def test_hand_computed_small_matrix(self):
        true_labels = ["bona_fide", "presentation", "bona_fide", "morph"]
        pred_labels = ["bona_fide", "bona_fide", "presentation", "morph"]
        result = confusion_matrix_6class(true_labels, pred_labels)
        labels = result["labels"]
        matrix = result["matrix"]
        assert labels == [
            "bona_fide",
            "presentation",
            "morph",
            "deepfake",
            "replay",
            "injection",
        ]
        bf_idx, pres_idx, morph_idx = (
            labels.index("bona_fide"),
            labels.index("presentation"),
            labels.index("morph"),
        )
        # 2 true bona_fide: one predicted bona_fide, one predicted presentation
        assert matrix[bf_idx][bf_idx] == 1
        assert matrix[bf_idx][pres_idx] == 1
        # 1 true presentation, predicted bona_fide
        assert matrix[pres_idx][bf_idx] == 1
        # 1 true morph, predicted morph
        assert matrix[morph_idx][morph_idx] == 1
        assert sum(sum(row) for row in matrix) == 4

    def test_empty_input_raises(self):
        with pytest.raises(ValueError):
            confusion_matrix_6class([], [])

    def test_mismatched_lengths_raise(self):
        with pytest.raises(ValueError):
            confusion_matrix_6class(["bona_fide"], ["bona_fide", "morph"])


class TestDetCurveData:
    def test_far_and_frr_are_monotonic_opposite(self):
        genuine = [0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9]
        attack = [0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0, 1.1, 1.2, 1.3]
        curve = det_curve_data(genuine, attack)
        far, frr = curve["far"], curve["frr"]
        assert len(far) == len(frr) == len(curve["thresholds"])
        # far is non-decreasing, frr is non-increasing, as the threshold sweeps up
        assert all(far[i] <= far[i + 1] + 1e-12 for i in range(len(far) - 1))
        assert all(frr[i] >= frr[i + 1] - 1e-12 for i in range(len(frr) - 1))

    def test_perfect_separation_touches_zero_zero(self):
        genuine = [0.0, 0.1, 0.2]
        attack = [0.8, 0.9, 1.0]
        curve = det_curve_data(genuine, attack)
        # at the strictest threshold, both far and frr should reach exactly 0 somewhere
        assert min(curve["far"]) == pytest.approx(0.0)
        assert min(curve["frr"]) == pytest.approx(0.0)


class TestDetectorAccuracyReport:
    def test_bundles_all_metrics_consistently(self):
        genuine = [0.1, 0.2, 0.6, 0.7]
        attack = [0.3, 0.4, 0.8, 0.9]
        report = detector_accuracy_report(genuine, attack, threshold=0.5)
        assert report["apcer"] == pytest.approx(apcer(attack, 0.5))
        assert report["bpcer"] == pytest.approx(bpcer(genuine, 0.5))
        assert report["acer"] == pytest.approx(acer(report["apcer"], report["bpcer"]))
        assert report["n_genuine"] == 4
        assert report["n_attack"] == 4
        assert 0.0 <= report["auc_roc"] <= 1.0
        assert 0.0 <= report["eer"] <= 1.0
