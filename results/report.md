# Evaluation report (PROJECT_SPEC.md §8)

*git `37067875fb42` · config `c96eb01258bf` · Linux-6.6.87.2-microsoft-standard-WSL2-x86_64-with-glibc2.41 / x86_64 · KEM=liboqs SIG=liboqs · seed=2026 · generated 2026-09-02T13:41:46.384348+00:00*

---

### T1 — Per-detector accuracy, intra-dataset

| Detector | APCER | BPCER | ACER | EER | AUC-ROC | TDR@FAR=1% | n_genuine | n_attack |
|---|---|---|---|---|---|---|---|---|
| deepfake | BLOCKED — no deepfake detector implemented -- pqbio/detect/deepfake.py is deliberately absent, not stubbed (dataset-blocked, see CLAUDE.md 'Current state' / PROJECT_SPEC.md §14) |  |  |  |  |  |  |  |
| injection | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 1.0000 | 1.0000 | 6 | 6 |
| match | BLOCKED — no labelled genuine/impostor pair dataset exists to compute match FAR/FRR (§6) |  |  |  |  |  |  |  |
| morph | BLOCKED — no morph detector implemented -- pqbio/detect/morph.py is deliberately absent, not stubbed (dataset-blocked, see CLAUDE.md 'Current state' / PROJECT_SPEC.md §14) |  |  |  |  |  |  |  |
| pad | BLOCKED — no pad detector implemented -- pqbio/detect/pad.py is deliberately absent, not stubbed (dataset-blocked, see CLAUDE.md 'Current state' / PROJECT_SPEC.md §14) |  |  |  |  |  |  |  |
| replay | BLOCKED — no replay detector implemented -- pqbio/detect/replay.py is deliberately absent, not stubbed. Replay-Attack/MSU-MFSD are unlicensed (§6), and the self-recorded alternative is blocked on human subjects rather than hardware: §6 requires written consent and supervisor approval to record anyone, and a subject-disjoint split needs at least two consenting subjects. The capture rig itself is verified working (camera, display, WB/exposure lock -- PROJECT_SPEC.md §14, 2026-09-01) |  |  |  |  |  |  |  |

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

_n=40 — Only match/injection/binding/quality signals exist this session — pad/morph/deepfake/replay are dataset-blocked and not built. Both strategies are compared on the injection corpus only (provenance detection), not full system ACER. See pqbio/detect/fusion.py's module docstring._

### T4 — Per-attack detection rate at the deployed operating point

| Attack type | Detection rate |
|---|---|
| deepfake | BLOCKED — no deepfake detector implemented -- pqbio/detect/deepfake.py is deliberately absent, not stubbed (dataset-blocked, see CLAUDE.md 'Current state' / PROJECT_SPEC.md §14) |
| injection_tier1 | 1.0000 |
| morph | BLOCKED — no morph detector implemented -- pqbio/detect/morph.py is deliberately absent, not stubbed (dataset-blocked, see CLAUDE.md 'Current state' / PROJECT_SPEC.md §14) |
| presentation | BLOCKED — no presentation detector implemented -- pqbio/detect/pad.py is deliberately absent, not stubbed (dataset-blocked, see CLAUDE.md 'Current state' / PROJECT_SPEC.md §14) |
| replay | BLOCKED — no replay detector implemented -- pqbio/detect/replay.py is deliberately absent, not stubbed. Replay-Attack/MSU-MFSD are unlicensed (§6), and the self-recorded alternative is blocked on human subjects rather than hardware: §6 requires written consent and supervisor approval to record anyone, and a subject-disjoint split needs at least two consenting subjects. The capture rig itself is verified working (camera, display, WB/exposure lock -- PROJECT_SPEC.md §14, 2026-09-01) |

### T5 — Crypto micro-benchmarks and artefact sizes

| Operation | Backend | Mean (ms) | p95 (ms) | Iterations |
|---|---|---|---|---|
| kem/classical/keygen | x25519 | 0.0453 | 0.0597 | 1000 |
| kem/classical/encaps | x25519 | 0.0744 | 0.0952 | 1000 |
| kem/classical/decaps | x25519 | 0.0700 | 0.1251 | 1000 |
| kem/classical/artefact_sizes_bytes | x25519 | {"ct": 32, "pk": 32, "sk": 32, "ss": 32} |  |  |
| kem/pq/keygen | liboqs | 0.0235 | 0.0498 | 1000 |
| kem/pq/encaps | liboqs | 0.0226 | 0.0368 | 1000 |
| kem/pq/decaps | liboqs | 0.0257 | 0.0330 | 1000 |
| kem/pq/artefact_sizes_bytes | liboqs | {"ct": 1088, "pk": 1184, "sk": 2400, "ss": 32} |  |  |
| signer/classical/keygen | ed25519 | 0.0385 | 0.0476 | 1000 |
| signer/classical/sign | ed25519 | 0.0654 | 0.0894 | 1000 |
| signer/classical/verify | ed25519 | 0.1065 | 0.1312 | 1000 |
| signer/classical/artefact_sizes_bytes | ed25519 | {"pk": 32, "sig": 64, "sk": 32} |  |  |
| signer/pq/keygen | liboqs | 0.0471 | 0.0586 | 1000 |
| signer/pq/sign | liboqs | 0.1185 | 0.2653 | 1000 |
| signer/pq/verify | liboqs | 0.0430 | 0.0550 | 1000 |
| signer/pq/artefact_sizes_bytes | liboqs | {"pk": 1952, "sig": 3309, "sk": 4032} |  |  |

### T6 — Four-configuration overhead ablation

| Config | Crypto | AI | Isolates | Mean latency (ms) |
|---|---|---|---|---|
| C0 | none | none | framework/transport floor | 1.6753 |
| C1 | X25519 + Ed25519 | none | conventional crypto cost | 10.8389 |
| C2 | ML-KEM-768 + ML-DSA-65 | none | marginal PQ cost | 11.7205 |
| C3 | ML-KEM-768 + ML-DSA-65 | full | total system cost | 715.5132 |

**PQ overhead (C2-C1):** 0.8816 ms (8.1%)

**AI overhead (C3-C2):** 703.7927 ms (6004.8%)

**AI:PQ overhead ratio:** 798.32

_The AI:PQ ratio is **provisional and a lower bound on the AI side**: C3 runs only one of the six spec'd detectors (injection). pad/morph/deepfake/replay are absent (§6/§14), so the AI term is missing four of its five attack-detection components. Adding them can only increase C3, pushing the ratio further in the same direction — nothing about them could shrink it. The PQ term (C2−C1) is not provisional; both configs are complete._

### T7 — Throughput vs concurrency

| Concurrency | Throughput (verif/s) | p50 (ms) | p95 (ms) | p99 (ms) | Setup failed (409) | Expired before verify (409) |
|---|---|---|---|---|---|---|
| 1 | 1.680 | 592.6707 | 592.6707 | 592.6707 | 0 | 0 |
| 2 | 2.060 | 837.6061 | 944.5535 | 954.0599 | 0 | 0 |
| 4 | 2.629 | 1404.9759 | 1500.1209 | 1506.5613 | 0 | 0 |
| 8 | 2.794 | 2691.0657 | 2819.1287 | 2841.0602 | 0 | 0 |
| 16 | 3.409 | 4509.4922 | 4616.4253 | 4660.8828 | 0 | 0 |
| 32 | 3.250 | 9460.6459 | 9740.1780 | 9789.4414 | 0 | 0 |
| 64 | 3.252 | 19148.8691 | 19549.0358 | 19562.7294 | 0 | 0 |

**Knee:** concurrency=4 — throughput gain from concurrency=4 to 8 was 6.3%, below the 10% threshold

**Event-loop-blocking finding:** Below saturation, p99 grew 7.86x while concurrency grew 16x (concurrency=1->16, peak throughput 3.41/s). That is well below proportional growth, i.e. per-request latency stays roughly flat while there is spare capacity.  Past the peak, p99 rises to 19563ms at concurrency=64 (from 593ms at 1) while throughput stays flat — expected queueing against a saturated worker pool (`server.workers` in config), not a separate defect. NOTE: latency growth alone cannot separate a blocked event loop from ordinary worker-pool/CPU saturation on a CPU-bound workload, so do not read the ratio above as a verdict on its own. The direct discriminator is tests/integration/test_server_happy_path.py::test_event_loop_stays_responsive_while_verify_is_in_flight, which polls GET /v1/health while concurrent /v1/verify calls are in flight and requires it to stay responsive — a blocked loop would stall those health checks behind the CPU-bound work, whatever the latency curve looks like.

### T8 — Deployment recommendation matrix

**Provisional — based on measured latency/throughput/PQ-overhead numbers only.** A real ACER-vs-scenario recommendation (§8.4) needs the four missing detectors and real datasets (§6/§14); this matrix cannot yet weigh accuracy against latency per scenario, only latency and crypto cost, which are real.

| Scenario | Recommendation (latency/crypto-only) |
|---|---|
| High-security, low-volume (bank onboarding) | Maximise detection strength once available; the system's own p95 (921.3634 ms) is not the binding constraint at low volume. Crypto choice is not the trade-off axis here at all. |
| Balanced (mobile login) | PQ is affordable on these numbers: the measured PQ overhead is 0.88 ms per session (T6), 0.10% of end-to-end p95. The cost that matters for this scenario is inference, not crypto. |
| High-volume, low-latency (access control) | T7's knee bounds this scenario. Throughput saturates against `server.workers` running per-request ONNX inference, so scale that (or move inference to a GPU) — dropping PQ for classical crypto would buy back only 0.88 ms per session and is not the lever. |

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
