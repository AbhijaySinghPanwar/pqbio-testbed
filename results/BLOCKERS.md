# BLOCKERS

Every metric this evaluation could not produce, where it would have appeared, and what would need to change to unblock it. Generated from the `blocked` markers in `results/*.json` -- not maintained by hand.

_Generated 2026-09-01T12:49:26.670198+00:00_


---

**17 blocked entries.**

- **`accuracy.json` → `T1_per_detector_accuracy_intra_dataset.deepfake`**
  no deepfake detector implemented -- pqbio/detect/deepfake.py is deliberately absent, not stubbed (dataset-blocked, see CLAUDE.md 'Current state' / PROJECT_SPEC.md §14)

- **`accuracy.json` → `T1_per_detector_accuracy_intra_dataset.match`**
  no labelled genuine/impostor pair dataset exists to compute match FAR/FRR (§6)

- **`accuracy.json` → `T1_per_detector_accuracy_intra_dataset.morph`**
  no morph detector implemented -- pqbio/detect/morph.py is deliberately absent, not stubbed (dataset-blocked, see CLAUDE.md 'Current state' / PROJECT_SPEC.md §14)

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

- **`accuracy.json` → `T2_per_detector_accuracy_cross_dataset.morph`**
  only one dataset exists in this environment (the self-generated injection corpus) -- cross-dataset evaluation needs a second, independent dataset (§6)

- **`accuracy.json` → `T2_per_detector_accuracy_cross_dataset.pad`**
  only one dataset exists in this environment (the self-generated injection corpus) -- cross-dataset evaluation needs a second, independent dataset (§6)

- **`accuracy.json` → `T2_per_detector_accuracy_cross_dataset.replay`**
  only one dataset exists in this environment (the self-generated injection corpus) -- cross-dataset evaluation needs a second, independent dataset (§6)

- **`accuracy.json` → `T4_per_attack_detection_rate.deepfake`**
  no deepfake detector implemented -- pqbio/detect/deepfake.py is deliberately absent, not stubbed (dataset-blocked, see CLAUDE.md 'Current state' / PROJECT_SPEC.md §14)

- **`accuracy.json` → `T4_per_attack_detection_rate.morph`**
  no morph detector implemented -- pqbio/detect/morph.py is deliberately absent, not stubbed (dataset-blocked, see CLAUDE.md 'Current state' / PROJECT_SPEC.md §14)

- **`accuracy.json` → `T4_per_attack_detection_rate.presentation`**
  no presentation detector implemented -- pqbio/detect/pad.py is deliberately absent, not stubbed (dataset-blocked, see CLAUDE.md 'Current state' / PROJECT_SPEC.md §14)

- **`accuracy.json` → `T4_per_attack_detection_rate.replay`**
  no replay detector implemented -- pqbio/detect/replay.py is deliberately absent, not stubbed. Replay-Attack/MSU-MFSD are unlicensed (§6), and the self-recorded alternative is blocked on human subjects rather than hardware: §6 requires written consent and supervisor approval to record anyone, and a subject-disjoint split needs at least two consenting subjects. The capture rig itself is verified working (camera, display, WB/exposure lock -- PROJECT_SPEC.md §14, 2026-09-01)

- **`accuracy.json` → `mmpmr`**
  MMPMR is morph-only (§8.1); no morph detector and no morph dataset exist (§6/§14)

- **`resources.json` → `gpu`**
  no GPU / NVML unavailable in this environment: NVML Shared Library Not Found


---

## Backend provenance of each result file

Crypto figures produced on the `kyber-py`/`dilithium-py` fallback are **superseded** by any liboqs-backed file below — the fallback is a reference implementation for correctness, never a performance measurement of ML-KEM-768/ML-DSA-65. `pqc_micro_fallback.json`, if present, is retained deliberately as the labelled comparison arm.

| Result file | KEM backend | SIG backend | Generated |
|---|---|---|---|
| `accuracy.json` | liboqs | liboqs | 2026-09-01T12:49:24 |
| `backend_cross_check.json` | liboqs | liboqs | 2026-08-31T18:48:56 |
| `binding_fpr.json` | — | — | 2026-08-30T17:04:48 |
| `illumination_corr_calibration.json` | kyber-py-fallback | dilithium-py-fallback | 2026-09-01T12:21:30 |
| `illumination_corr_calibration_16step.json` | kyber-py-fallback | dilithium-py-fallback | 2026-09-01T12:20:27 |
| `latency.json` | liboqs | liboqs | 2026-08-31T18:53:44 |
| `live_challenge_check.json` | kyber-py-fallback | dilithium-py-fallback | 2026-09-01T12:14:30 |
| `live_challenge_check_16step.json` | kyber-py-fallback | dilithium-py-fallback | 2026-09-01T12:19:58 |
| `loadgen.json` | liboqs | liboqs | 2026-08-31T19:19:04 |
| `loadgen_fallback_controlled.json` | kyber-py-fallback | dilithium-py-fallback | 2026-08-31T19:21:14 |
| `overhead_ablation.json` | liboqs | liboqs | 2026-08-31T18:59:03 |
| `phash_burst_calibration.json` | — | — | 2026-08-31T09:33:14 |
| `phash_robustness.json` | — | — | 2026-08-31T06:42:36 |
| `pqc_micro.json` | liboqs | liboqs | 2026-08-31T18:59:03 |
| `pqc_micro_fallback.json` | kyber-py-fallback | dilithium-py-fallback | 2026-08-31T13:27:07 |
| `resources.json` | liboqs | liboqs | 2026-08-31T18:57:18 |


---

## What unblocks each category

- **pad/morph/deepfake/replay detectors** — implement `pqbio/detect/{pad,morph,deepfake,replay}.py` once their datasets are licensed (§6); currently deliberately absent, not stubbed.
- **Cross-dataset accuracy (T2)** — needs a second, independent labelled dataset per attack type; only the self-generated injection corpus exists today.
- **MMPMR** — needs the morph detector above, plus a morph dataset (FRLL-Morphs/SMDD).
- **match FAR/FRR** — needs a labelled genuine/impostor pair dataset; none exists (§6).
- **C1/C2/C3 overhead ablation** — UNBLOCKED 2026-09-01. Needs liboqs, which now builds in `docker/Dockerfile.server`; run it there via `make docker-bench`. On a host without a C toolchain the fallback is still selected and `pqbio/bench/overhead.py`'s `guard_against_fallback_backend` will (correctly) re-block C1/C2/C3, so check the backend provenance table above before reading T6.
- **GPU utilisation/VRAM** — needs a machine with an NVIDIA GPU and NVML available; this environment has neither.
- **T8 real ACER-based recommendation** — depends on the detector and dataset gaps above; today's T8 is latency/crypto-cost-only.
