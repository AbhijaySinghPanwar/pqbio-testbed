# BLOCKERS

Every metric this evaluation could not produce, where it would have appeared, and what would need to change to unblock it. Generated from the `blocked` markers in `results/*.json` -- not maintained by hand.

_Generated 2026-09-14T16:37:51.187571+00:00_


---

**18 blocked entries.**

- **`accuracy.json` → `T1_per_detector_accuracy_intra_dataset.deepfake`**
  no deepfake detector implemented -- pqbio/detect/deepfake.py is deliberately absent, not stubbed (dataset-blocked, see CLAUDE.md 'Current state' / PROJECT_SPEC.md §14)

- **`accuracy.json` → `T1_per_detector_accuracy_intra_dataset.match`**
  no labelled genuine/impostor pair dataset exists to compute match FAR/FRR (§6)

- **`accuracy.json` → `T1_per_detector_accuracy_intra_dataset.pad`**
  no pad detector implemented -- pqbio/detect/pad.py is deliberately absent, not stubbed (dataset-blocked, see CLAUDE.md 'Current state' / PROJECT_SPEC.md §14)

- **`accuracy.json` → `T1_per_detector_accuracy_intra_dataset.replay`**
  no replay detector implemented -- pqbio/detect/replay.py is deliberately absent, not stubbed. Replay-Attack/MSU-MFSD are unlicensed (§6), and the self-recorded alternative is blocked on human subjects rather than hardware: §6 requires written consent and supervisor approval to record anyone, and a subject-disjoint split needs at least two consenting subjects. The capture rig itself is verified working (camera, display, WB/exposure lock -- PROJECT_SPEC.md §14, 2026-09-01)

- **`accuracy.json` → `T2_per_detector_accuracy_cross_dataset.deepfake`**
  only one dataset exists in this environment (the self-generated injection corpus) -- cross-dataset evaluation needs a second, independent dataset (§6)

- **`accuracy.json` → `T2_per_detector_accuracy_cross_dataset.injection`**
  only one dataset exists in this environment (the self-generated injection corpus) -- cross-dataset evaluation needs a second, independent dataset (§6)

- **`accuracy.json` → `T2_per_detector_accuracy_cross_dataset.match`**
  only one dataset exists in this environment (the self-generated injection corpus) -- cross-dataset evaluation needs a second, independent dataset (§6)

- **`accuracy.json` → `T2_per_detector_accuracy_cross_dataset.morph_dmad`**
  only one morph corpus exists (self-generated from LFW, scripts/make_morph_corpus.py) -- cross-dataset evaluation needs an independent morph dataset such as FRLL-Morphs or SMDD, neither licensed (§6, data/LICENCES.md). Cross-METHOD generalisation within the one corpus is the available proxy: T4c

- **`accuracy.json` → `T2_per_detector_accuracy_cross_dataset.morph_smad`**
  only one morph corpus exists (self-generated from LFW, scripts/make_morph_corpus.py) -- cross-dataset evaluation needs an independent morph dataset such as FRLL-Morphs or SMDD, neither licensed (§6, data/LICENCES.md). Cross-METHOD generalisation within the one corpus is the available proxy: T4c

- **`accuracy.json` → `T2_per_detector_accuracy_cross_dataset.pad`**
  only one dataset exists in this environment (the self-generated injection corpus) -- cross-dataset evaluation needs a second, independent dataset (§6)

- **`accuracy.json` → `T2_per_detector_accuracy_cross_dataset.replay`**
  only one dataset exists in this environment (the self-generated injection corpus) -- cross-dataset evaluation needs a second, independent dataset (§6)

- **`accuracy.json` → `T4_per_attack_detection_rate.deepfake`**
  no deepfake detector implemented -- pqbio/detect/deepfake.py is deliberately absent, not stubbed (dataset-blocked, see CLAUDE.md 'Current state' / PROJECT_SPEC.md §14)

- **`accuracy.json` → `T4_per_attack_detection_rate.presentation`**
  no presentation detector implemented -- pqbio/detect/pad.py is deliberately absent, not stubbed (dataset-blocked, see CLAUDE.md 'Current state' / PROJECT_SPEC.md §14)

- **`accuracy.json` → `T4_per_attack_detection_rate.replay`**
  no replay detector implemented -- pqbio/detect/replay.py is deliberately absent, not stubbed. Replay-Attack/MSU-MFSD are unlicensed (§6), and the self-recorded alternative is blocked on human subjects rather than hardware: §6 requires written consent and supervisor approval to record anyone, and a subject-disjoint split needs at least two consenting subjects. The capture rig itself is verified working (camera, display, WB/exposure lock -- PROJECT_SPEC.md §14, 2026-09-01)

- **`b6_evaluability.json` → `B6_operating_point_characterisation`**
  B6's threshold (binding.illumination_corr_min = 0.60) and this evaluability floor both rest on captures from a single session, in one room, on one sensor, with no human subject at capture distance. Measured TPR was 1.00 on 8 captures, whose one-sided 95% Clopper-Pearson upper bound on BPCER is 0.312 -- consistent with a true BPCER of 31%. Demonstrating the 5% system BPCER target at 95% confidence needs ~59 consecutive clean captures. UNBLOCKER: the consented multi-capture session -- multiple subjects at capture distance across varied ambient lighting, which §6 gates behind written consent and supervisor approval (the same blocker as the replay corpus). §5.2's live-webcam DoD item closes on that measurement and not before; until then these values are the best available estimate, not a characterised operating point (PROJECT_SPEC.md §14, 2026-09-03/04)

- **`b6_evaluability.json` → `B6_residual_unmet_after_the_evaluability_gate`**
  The evaluability gate has not solved B6's BPCER contamination, only a third of it. At the shipped floor the gate reclassifies 33% of failing rendered captures from BIND_CHALLENGE_UNMET to BIND_CHALLENGE_UNEVALUABLE, while gating 74% of no-render controls -- so roughly two-thirds of real-capture B6 failures are still scored as UNMET, i.e. as challenge-not-answered rather than could-not-measure. Whether that residual is a conservative gate leaving measurable-but-weak captures on the attack side, or genuinely unmet challenges that deserve the code they get, is UNRESOLVED: separating the two needs captures whose ground truth is known independently of the correlation itself, which is the consented multi-capture session. Until then any BPCER figure derived from B6 outcomes carries an unquantified genuine-capture component (PROJECT_SPEC.md §14, 2026-09-04)

- **`overhead_ablation.json` → `ai_to_pq_overhead_ratio`**
  the PQ overhead is not resolvable from run noise: C2-C1 = 0.10 ms with a 95% interval of [-0.70, 0.90] ms, which spans zero, so a point ratio would be dividing by noise (the three committed runs gave 798x, 2327x and -191x). The defensible statement is the lower bound in ai_to_pq_overhead_ratio_lower_bound

- **`resources.json` → `gpu`**
  no GPU / NVML unavailable in this environment: NVML Shared Library Not Found


---

## Backend provenance of each result file

Crypto figures produced on the `kyber-py`/`dilithium-py` fallback are **superseded** by any liboqs-backed file below — the fallback is a reference implementation for correctness, never a performance measurement of ML-KEM-768/ML-DSA-65. `pqc_micro_fallback.json`, if present, is retained deliberately as the labelled comparison arm.

| Result file | KEM backend | SIG backend | Generated |
|---|---|---|---|
| `accuracy.json` | liboqs | liboqs | 2026-09-14T16:31:21 |
| `b6_evaluability.json` | kyber-py-fallback | dilithium-py-fallback | 2026-09-06T07:05:24 |
| `b6_operating_point.json` | kyber-py-fallback | dilithium-py-fallback | 2026-09-01T13:42:59 |
| `b6_operating_window.json` | kyber-py-fallback | dilithium-py-fallback | 2026-09-01T13:59:21 |
| `backend_cross_check.json` | liboqs | liboqs | 2026-08-31T18:48:56 |
| `binding_fpr.json` | — | — | 2026-08-30T17:04:48 |
| `frame_budget.json` | kyber-py-fallback | dilithium-py-fallback | 2026-09-01T12:54:29 |
| `illumination_corr_calibration.json` | kyber-py-fallback | dilithium-py-fallback | 2026-09-01T12:21:30 |
| `illumination_corr_calibration_16step.json` | kyber-py-fallback | dilithium-py-fallback | 2026-09-01T12:20:27 |
| `latency.json` | liboqs | liboqs | 2026-09-14T16:32:45 |
| `live_challenge_check.json` | kyber-py-fallback | dilithium-py-fallback | 2026-09-01T13:53:34 |
| `live_challenge_check_16step.json` | kyber-py-fallback | dilithium-py-fallback | 2026-09-01T12:19:58 |
| `loadgen.json` | liboqs | liboqs | 2026-09-14T16:34:33 |
| `loadgen_fallback_controlled.json` | kyber-py-fallback | dilithium-py-fallback | 2026-08-31T19:21:14 |
| `overhead_ablation.json` | liboqs | liboqs | 2026-09-14T16:37:48 |
| `phash_burst_calibration.json` | — | — | 2026-08-31T09:33:14 |
| `phash_robustness.json` | — | — | 2026-08-31T06:42:36 |
| `pqc_micro.json` | liboqs | liboqs | 2026-09-14T16:37:48 |
| `pqc_micro_fallback.json` | kyber-py-fallback | dilithium-py-fallback | 2026-08-31T13:27:07 |
| `resources.json` | liboqs | liboqs | 2026-09-14T16:35:58 |


---

## What unblocks each category

- **pad/morph/deepfake/replay detectors** — implement `pqbio/detect/{pad,morph,deepfake,replay}.py` once their datasets are licensed (§6); currently deliberately absent, not stubbed.
- **Cross-dataset accuracy (T2)** — needs a second, independent labelled dataset per attack type; only the self-generated injection corpus exists today.
- **MMPMR** — needs the morph detector above, plus a morph dataset (FRLL-Morphs/SMDD).
- **match FAR/FRR** — needs a labelled genuine/impostor pair dataset; none exists (§6).
- **C1/C2/C3 overhead ablation** — UNBLOCKED 2026-09-01. Needs liboqs, which now builds in `docker/Dockerfile.server`; run it there via `make docker-bench`. On a host without a C toolchain the fallback is still selected and `pqbio/bench/overhead.py`'s `guard_against_fallback_backend` will (correctly) re-block C1/C2/C3, so check the backend provenance table above before reading T6.
- **GPU utilisation/VRAM** — needs a machine with an NVIDIA GPU and NVML available; this environment has neither.
- **T8 real ACER-based recommendation** — depends on the detector and dataset gaps above; today's T8 is latency/crypto-cost-only.
