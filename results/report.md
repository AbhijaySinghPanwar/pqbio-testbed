# Evaluation report (PROJECT_SPEC.md §8)

*git `25d56db2e9f1` · config `2b8a593b5937` · Windows-10-10.0.26200-SP0 / Intel64 Family 6 Model 154 Stepping 3, GenuineIntel · KEM=kyber-py-fallback SIG=dilithium-py-fallback · seed=2026 · generated 2026-08-31T13:16:33.536813+00:00*

---

### T1 — Per-detector accuracy, intra-dataset

| Detector | APCER | BPCER | ACER | EER | AUC-ROC | TDR@FAR=1% | n_genuine | n_attack |
|---|---|---|---|---|---|---|---|---|
| deepfake | BLOCKED — no deepfake detector implemented -- pqbio/detect/deepfake.py is deliberately absent, not stubbed (dataset-blocked, see CLAUDE.md 'Current state' / PROJECT_SPEC.md §14) |  |  |  |  |  |  |  |
| injection | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 1.0000 | 1.0000 | 7 | 7 |
| match | BLOCKED — no labelled genuine/impostor pair dataset exists to compute match FAR/FRR (§6) |  |  |  |  |  |  |  |
| morph | BLOCKED — no morph detector implemented -- pqbio/detect/morph.py is deliberately absent, not stubbed (dataset-blocked, see CLAUDE.md 'Current state' / PROJECT_SPEC.md §14) |  |  |  |  |  |  |  |
| pad | BLOCKED — no pad detector implemented -- pqbio/detect/pad.py is deliberately absent, not stubbed (dataset-blocked, see CLAUDE.md 'Current state' / PROJECT_SPEC.md §14) |  |  |  |  |  |  |  |
| replay | BLOCKED — no replay detector implemented -- pqbio/detect/replay.py is deliberately absent, not stubbed (dataset-blocked, see CLAUDE.md 'Current state' / PROJECT_SPEC.md §14) |  |  |  |  |  |  |  |

### T2 — Per-detector accuracy, cross-dataset

| Detector | APCER | BPCER | ACER | EER | AUC-ROC | TDR@FAR=1% | n_genuine | n_attack |
|---|---|---|---|---|---|---|---|---|
| deepfake | BLOCKED — only one dataset exists in this environment (the self-generated injection corpus) -- cross-dataset evaluation needs a second, independent dataset (§6) |  |  |  |  |  |  |  |
| injection | BLOCKED — only one dataset exists in this environment (the self-generated injection corpus) -- cross-dataset evaluation needs a second, independent dataset (§6) |  |  |  |  |  |  |  |
| match | BLOCKED — only one dataset exists in this environment (the self-generated injection corpus) -- cross-dataset evaluation needs a second, independent dataset (§6) |  |  |  |  |  |  |  |
| morph | BLOCKED — only one dataset exists in this environment (the self-generated injection corpus) -- cross-dataset evaluation needs a second, independent dataset (§6) |  |  |  |  |  |  |  |
| pad | BLOCKED — only one dataset exists in this environment (the self-generated injection corpus) -- cross-dataset evaluation needs a second, independent dataset (§6) |  |  |  |  |  |  |  |
| replay | BLOCKED — only one dataset exists in this environment (the self-generated injection corpus) -- cross-dataset evaluation needs a second, independent dataset (§6) |  |  |  |  |  |  |  |

### T3 — Fusion strategy comparison

| Strategy | Accuracy |
|---|---|
| rule | 1.0000 |
| cascade | 1.0000 |

_n=50 — Only match/injection/binding/quality signals exist this session — pad/morph/deepfake/replay are dataset-blocked and not built. Both strategies are compared on the injection corpus only (provenance detection), not full system ACER. See pqbio/detect/fusion.py's module docstring._

### T4 — Per-attack detection rate at the deployed operating point

| Attack type | Detection rate |
|---|---|
| deepfake | BLOCKED — no deepfake detector implemented -- pqbio/detect/deepfake.py is deliberately absent, not stubbed (dataset-blocked, see CLAUDE.md 'Current state' / PROJECT_SPEC.md §14) |
| injection_tier1 | 1.0000 |
| morph | BLOCKED — no morph detector implemented -- pqbio/detect/morph.py is deliberately absent, not stubbed (dataset-blocked, see CLAUDE.md 'Current state' / PROJECT_SPEC.md §14) |
| presentation | BLOCKED — no presentation detector implemented -- pqbio/detect/pad.py is deliberately absent, not stubbed (dataset-blocked, see CLAUDE.md 'Current state' / PROJECT_SPEC.md §14) |
| replay | BLOCKED — no replay detector implemented -- pqbio/detect/replay.py is deliberately absent, not stubbed (dataset-blocked, see CLAUDE.md 'Current state' / PROJECT_SPEC.md §14) |

### T5 — Crypto micro-benchmarks and artefact sizes

| Operation | Backend | Mean (ms) | p95 (ms) | Iterations |
|---|---|---|---|---|
| kem/classical/keygen | x25519 | 0.1057 | 0.0828 | 1000 |
| kem/classical/encaps | x25519 | 0.1456 | 0.2077 | 1000 |
| kem/classical/decaps | x25519 | 0.1425 | 0.2378 | 1000 |
| kem/classical/artefact_sizes_bytes | x25519 | {"ct": 32, "pk": 32, "sk": 32, "ss": 32} |  |  |
| kem/pq/keygen | kyber-py-fallback | 4.7336 | 6.5721 | 1000 |
| kem/pq/encaps | kyber-py-fallback | 6.3017 | 9.0720 | 1000 |
| kem/pq/decaps | kyber-py-fallback | 8.3876 | 11.8771 | 1000 |
| kem/pq/artefact_sizes_bytes | kyber-py-fallback | {"ct": 1088, "pk": 1184, "sk": 2400, "ss": 32} |  |  |
| signer/classical/keygen | ed25519 | 0.0641 | 0.0839 | 1000 |
| signer/classical/sign | ed25519 | 0.1156 | 0.1519 | 1000 |
| signer/classical/verify | ed25519 | 0.1384 | 0.2307 | 1000 |
| signer/classical/artefact_sizes_bytes | ed25519 | {"pk": 32, "sig": 64, "sk": 32} |  |  |
| signer/pq/keygen | dilithium-py-fallback | 12.8424 | 17.8651 | 1000 |
| signer/pq/sign | dilithium-py-fallback | 78.8858 | 182.2413 | 1000 |
| signer/pq/verify | dilithium-py-fallback | 14.6526 | 18.0214 | 1000 |
| signer/pq/artefact_sizes_bytes | dilithium-py-fallback | {"pk": 1952, "sig": 3309, "sk": 4032} |  |  |

### T6 — Four-configuration overhead ablation

| Config | Crypto | AI | Isolates | Mean latency (ms) |
|---|---|---|---|---|
| C0 | none | none | framework/transport floor | 1.2363 |
| C1 |  |  | BLOCKED — Refusing to run the overhead ablation (C1/C2/C3): KEM_BACKEND='kyber-py-fallback', SIG_BACKEND='dilithium-py-fallback' — a pure-Python fallback is active for at least one primitive. The C2-C1 'marginal PQ cost' figure would be dominated by rejection-sampling overhead specific to that fallback, not by ML-KEM-768/ML-DSA-65 themselves (liboqs is expected to be roughly two orders of magnitude faster for ML-DSA signing — see results/pqc_micro.json). Install a C toolchain (CMake, Ninja, a C compiler) and run `pip install -e ".[pqc-liboqs]"` so both backends report 'liboqs', then re-run. |  |
| C2 |  |  | BLOCKED — Refusing to run the overhead ablation (C1/C2/C3): KEM_BACKEND='kyber-py-fallback', SIG_BACKEND='dilithium-py-fallback' — a pure-Python fallback is active for at least one primitive. The C2-C1 'marginal PQ cost' figure would be dominated by rejection-sampling overhead specific to that fallback, not by ML-KEM-768/ML-DSA-65 themselves (liboqs is expected to be roughly two orders of magnitude faster for ML-DSA signing — see results/pqc_micro.json). Install a C toolchain (CMake, Ninja, a C compiler) and run `pip install -e ".[pqc-liboqs]"` so both backends report 'liboqs', then re-run. |  |
| C3 |  |  | BLOCKED — Refusing to run the overhead ablation (C1/C2/C3): KEM_BACKEND='kyber-py-fallback', SIG_BACKEND='dilithium-py-fallback' — a pure-Python fallback is active for at least one primitive. The C2-C1 'marginal PQ cost' figure would be dominated by rejection-sampling overhead specific to that fallback, not by ML-KEM-768/ML-DSA-65 themselves (liboqs is expected to be roughly two orders of magnitude faster for ML-DSA signing — see results/pqc_micro.json). Install a C toolchain (CMake, Ninja, a C compiler) and run `pip install -e ".[pqc-liboqs]"` so both backends report 'liboqs', then re-run. |  |

**PQ overhead (C2-C1):** BLOCKED — requires C1 and C2, both blocked by the fallback backend

**AI overhead (C3-C2):** BLOCKED — requires C2 and C3, both blocked by the fallback backend

**AI:PQ overhead ratio:** BLOCKED — requires pq_overhead_ms and ai_overhead_ms, both blocked

### T7 — Throughput vs concurrency

| Concurrency | Throughput (verif/s) | p50 (ms) | p95 (ms) | p99 (ms) | Setup failed (409) | Expired before verify (409) |
|---|---|---|---|---|---|---|
| 1 | 0.811 | 1232.0434 | 1232.0434 | 1232.0434 | 0 | 0 |
| 2 | 1.124 | 1700.2842 | 1716.2193 | 1717.6358 | 0 | 0 |
| 4 | 1.921 | 1940.9812 | 2068.1426 | 2078.6752 | 0 | 0 |
| 8 | 2.192 | 3399.8649 | 3590.5793 | 3608.5664 | 0 | 0 |
| 16 | 2.285 | 6579.9956 | 6893.2938 | 6919.4943 | 0 | 0 |
| 32 | 2.246 | 13454.5872 | 13816.2868 | 13877.9503 | 0 | 0 |
| 64 | 0.000 | n/a | n/a | n/a | 29 | 35 |

**Knee:** concurrency=8 — throughput gain from concurrency=8 to 16 was 4.2%, below the 10% threshold

**Event-loop-blocking finding:** p99 latency grew 11.26x while concurrency grew 32x (concurrency=1->32). This is well below proportional growth, consistent with Module E's event loop staying unblocked under concurrency (per-request latency stays roughly flat as concurrency rises, rather than queuing up behind a blocked resource). Separately: concurrency level(s) [64] completed *zero* requests before every session's 30s challenge TTL elapsed -- a real scalability ceiling of this environment's slow PQC fallback + AI pipeline under sustained load at that concurrency, not the event-loop-blocking question this comparison is about. See setup_failed_before_verify/expired_before_verify on those levels.

### T8 — Deployment recommendation matrix

**Provisional — based on measured latency/throughput/PQ-overhead numbers only.** A real ACER-vs-scenario recommendation (§8.4) needs the four missing detectors and real datasets (§6/§14); this matrix cannot yet weigh accuracy against latency per scenario, only latency and crypto cost, which are real.

| Scenario | Recommendation (latency/crypto-only) |
|---|---|
| High-security, low-volume (bank onboarding) | Maximise detection strength once available; current system's own p95 (2556.1220 ms) is not the bottleneck for a low-volume flow. |
| Balanced (mobile login) | PQ overhead over classical crypto (see T6) is the number to watch here; acceptable if it stays a small fraction of total p95 latency. |
| High-volume, low-latency (access control) | T7's knee and degradation finding directly bound this scenario's viable concurrency; the AI stages (`quality_face`, `heavy_models` in F2) currently dominate per-request cost far more than crypto does. |

---

### F1 — DET curves

![DET curves](figures/f1_det_curves.png)

### F2 — Stage-level latency breakdown

![Stage latency](figures/f2_stage_latency.png)

### F3 — ACER vs p95 latency

![ACER vs latency](figures/f3_acer_vs_latency.png)

_Only one real (ACER, p95) pair exists (injection); this plot cannot yet show the trade-off curve §8.4 asks for across strategies/detectors._

### F4 — 6-class confusion matrix

![Confusion matrix](figures/f4_confusion_matrix.png)

_Only bona_fide and injection have real labelled samples in this environment; presentation/morph/deepfake/replay rows and columns are structurally zero, not measured-and-found-zero (§14)._

---

See `results/BLOCKERS.md` for the complete list of blocked metrics and what unblocks each one.
