# BLOCKERS

Every metric this evaluation could not produce, where it would have appeared, and what would need to change to unblock it. Generated from the `blocked` markers in `results/*.json` -- not maintained by hand.

_Generated 2026-08-31T13:29:16.134746+00:00_


---

**23 blocked entries.**

- **`accuracy.json` → `T1_per_detector_accuracy_intra_dataset.deepfake`**
  no deepfake detector implemented -- pqbio/detect/deepfake.py is deliberately absent, not stubbed (dataset-blocked, see CLAUDE.md 'Current state' / PROJECT_SPEC.md §14)

- **`accuracy.json` → `T1_per_detector_accuracy_intra_dataset.match`**
  no labelled genuine/impostor pair dataset exists to compute match FAR/FRR (§6)

- **`accuracy.json` → `T1_per_detector_accuracy_intra_dataset.morph`**
  no morph detector implemented -- pqbio/detect/morph.py is deliberately absent, not stubbed (dataset-blocked, see CLAUDE.md 'Current state' / PROJECT_SPEC.md §14)

- **`accuracy.json` → `T1_per_detector_accuracy_intra_dataset.pad`**
  no pad detector implemented -- pqbio/detect/pad.py is deliberately absent, not stubbed (dataset-blocked, see CLAUDE.md 'Current state' / PROJECT_SPEC.md §14)

- **`accuracy.json` → `T1_per_detector_accuracy_intra_dataset.replay`**
  no replay detector implemented -- pqbio/detect/replay.py is deliberately absent, not stubbed (dataset-blocked, see CLAUDE.md 'Current state' / PROJECT_SPEC.md §14)

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
  no replay detector implemented -- pqbio/detect/replay.py is deliberately absent, not stubbed (dataset-blocked, see CLAUDE.md 'Current state' / PROJECT_SPEC.md §14)

- **`accuracy.json` → `mmpmr`**
  MMPMR is morph-only (§8.1); no morph detector and no morph dataset exist (§6/§14)

- **`overhead_ablation.json` → `C1`**
  Refusing to run the overhead ablation (C1/C2/C3): KEM_BACKEND='kyber-py-fallback', SIG_BACKEND='dilithium-py-fallback' — a pure-Python fallback is active for at least one primitive. The C2-C1 'marginal PQ cost' figure would be dominated by rejection-sampling overhead specific to that fallback, not by ML-KEM-768/ML-DSA-65 themselves (liboqs is expected to be roughly two orders of magnitude faster for ML-DSA signing — see results/pqc_micro.json). Install a C toolchain (CMake, Ninja, a C compiler) and run `pip install -e ".[pqc-liboqs]"` so both backends report 'liboqs', then re-run.

- **`overhead_ablation.json` → `C2`**
  Refusing to run the overhead ablation (C1/C2/C3): KEM_BACKEND='kyber-py-fallback', SIG_BACKEND='dilithium-py-fallback' — a pure-Python fallback is active for at least one primitive. The C2-C1 'marginal PQ cost' figure would be dominated by rejection-sampling overhead specific to that fallback, not by ML-KEM-768/ML-DSA-65 themselves (liboqs is expected to be roughly two orders of magnitude faster for ML-DSA signing — see results/pqc_micro.json). Install a C toolchain (CMake, Ninja, a C compiler) and run `pip install -e ".[pqc-liboqs]"` so both backends report 'liboqs', then re-run.

- **`overhead_ablation.json` → `C3`**
  Refusing to run the overhead ablation (C1/C2/C3): KEM_BACKEND='kyber-py-fallback', SIG_BACKEND='dilithium-py-fallback' — a pure-Python fallback is active for at least one primitive. The C2-C1 'marginal PQ cost' figure would be dominated by rejection-sampling overhead specific to that fallback, not by ML-KEM-768/ML-DSA-65 themselves (liboqs is expected to be roughly two orders of magnitude faster for ML-DSA signing — see results/pqc_micro.json). Install a C toolchain (CMake, Ninja, a C compiler) and run `pip install -e ".[pqc-liboqs]"` so both backends report 'liboqs', then re-run.

- **`overhead_ablation.json` → `ai_overhead_ms`**
  requires C2 and C3, both blocked by the fallback backend

- **`overhead_ablation.json` → `ai_to_pq_overhead_ratio`**
  requires pq_overhead_ms and ai_overhead_ms, both blocked

- **`overhead_ablation.json` → `pq_overhead_ms`**
  requires C1 and C2, both blocked by the fallback backend

- **`resources.json` → `gpu`**
  no GPU / NVML unavailable in this environment: NVML Shared Library Not Found


---

## What unblocks each category

- **pad/morph/deepfake/replay detectors** — implement `pqbio/detect/{pad,morph,deepfake,replay}.py` once their datasets are licensed (§6); currently deliberately absent, not stubbed.
- **Cross-dataset accuracy (T2)** — needs a second, independent labelled dataset per attack type; only the self-generated injection corpus exists today.
- **MMPMR** — needs the morph detector above, plus a morph dataset (FRLL-Morphs/SMDD).
- **match FAR/FRR** — needs a labelled genuine/impostor pair dataset; none exists (§6).
- **C1/C2/C3 overhead ablation** — needs liboqs installed (a C toolchain: CMake, Ninja, a C compiler; then `pip install -e ".[pqc-liboqs]"`) so KEM_BACKEND/SIG_BACKEND both report 'liboqs' instead of the pure-Python fallback — see `pqbio/bench/overhead.py`'s `guard_against_fallback_backend`.
- **GPU utilisation/VRAM** — needs a machine with an NVIDIA GPU and NVML available; this environment has neither.
- **T8 real ACER-based recommendation** — depends on the detector and dataset gaps above; today's T8 is latency/crypto-cost-only.
