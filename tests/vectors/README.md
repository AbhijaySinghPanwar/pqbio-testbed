# PQC known-answer test vectors

Real NIST ACVP test vectors for ML-KEM-768 (FIPS 203) and ML-DSA-65 (FIPS 204),
vendored here so `tests/unit/test_pqc_kat.py` verifies the active backend against an
independent, authoritative source instead of pinning the backend's own output (the
original "self-KAT" this replaced proved stability, not correctness — a bug in
kyber-py/dilithium-py would have locked in and reported green).

## Source

[usnistgov/ACVP-Server](https://github.com/usnistgov/ACVP-Server), branch `master`,
under `gen-val/json-files/`. Each algorithm's directory ships an
`internalProjection.json` — inputs and expected outputs combined in one file (as
opposed to `prompt.json` + `expectedResults.json`, which are split and would need
joining by `tcId`). Fetched 2026-08-30.

| Vendored file | Extracted from | Test group used |
|---|---|---|
| `ML-KEM-768-keyGen.json` | `ML-KEM-keyGen-FIPS203/internalProjection.json` | `tgId=2` (`parameterSet=ML-KEM-768`), all 25 AFT cases |
| `ML-KEM-768-encapDecap.json` | `ML-KEM-encapDecap-FIPS203/internalProjection.json` | `tgId=2` encapsulation (25 AFT cases) + `tgId=5` decapsulation (10 VAL cases), both `parameterSet=ML-KEM-768` |
| `ML-DSA-65-keyGen.json` | `ML-DSA-keyGen-FIPS204/internalProjection.json` | `tgId=2` (`parameterSet=ML-DSA-65`), all 25 AFT cases |
| `ML-DSA-65-sigGen.json` | `ML-DSA-sigGen-FIPS204/internalProjection.json` | `tgId=3` (`parameterSet=ML-DSA-65`, `deterministic=true`, `signatureInterface=external`, `preHash=pure`), all 15 AFT cases |

Only the `ML-KEM-768` / `ML-DSA-65` test groups were kept (the upstream files also
cover ML-KEM-512/1024 and ML-DSA-44/87, which this project doesn't implement), and only
the plain deterministic/external/pure ML-DSA sigGen variant was kept (the upstream file
also has prehash, internal-interface, and non-deterministic/hedged variants — this
project's KAT-support code only implements the plain deterministic path; see
`pqbio/pqc/sign.py`'s `ml_dsa_65_sign_deterministic`). Nothing about the *content* of a
kept test case was modified — each vendored `tests[]` entry is byte-for-byte the
original JSON object from `internalProjection.json`.

## Integrity

SHA-256 of the **original, unmodified** upstream file (recompute against a fresh
download to confirm nothing has changed upstream or in transit):

```
d7a62a2c3476957f56dd8d24f9004ea6776ccfe995ffe71a65bb9506dc9c7b1b  ML-KEM-keyGen-FIPS203/internalProjection.json
a556952ce869bb89c3a3196a701dad89647c193a34c86eafb61a9d710d5b810f  ML-KEM-encapDecap-FIPS203/internalProjection.json
e67ee6540d40e11506c3c4e3b1f79fc1cefcd49820db99fc61f87cc8ba463baf  ML-DSA-keyGen-FIPS204/internalProjection.json
72dcaf5f69853ca267ccd16af9cb40949786aca0fcfbf05d1ebeba132b93af22  ML-DSA-sigGen-FIPS204/internalProjection.json
```

SHA-256 of the **vendored, trimmed** files actually committed to this repo (each file
also records its own `sourceSha256` field matching the corresponding line above, so the
provenance survives even if this README and the file diverge):

```
fc4b6e75d8cd46c5e262732ca05b861b421366aab37d300fc7996f3833af3268  ML-KEM-768-keyGen.json
dda3b4b71a15fc55524756825e65aab63d8cbf500784ccd2616a14b93761e005  ML-KEM-768-encapDecap.json
569e9ba15ceb2835a49194e463a317536b3a557b93a4a72b748d0085ee94e7d0  ML-DSA-65-keyGen.json
235d1212afbf896cd8dca89df50e52e7235534fe06851d4e281cf5c34318f536  ML-DSA-65-sigGen.json
```

## Reproducing / refreshing

```bash
BASE=https://raw.githubusercontent.com/usnistgov/ACVP-Server/master/gen-val/json-files
curl -sS -o ML-KEM-keyGen-internalProjection.json      "$BASE/ML-KEM-keyGen-FIPS203/internalProjection.json"
curl -sS -o ML-KEM-encapDecap-internalProjection.json  "$BASE/ML-KEM-encapDecap-FIPS203/internalProjection.json"
curl -sS -o ML-DSA-keyGen-internalProjection.json       "$BASE/ML-DSA-keyGen-FIPS204/internalProjection.json"
curl -sS -o ML-DSA-sigGen-internalProjection.json       "$BASE/ML-DSA-sigGen-FIPS204/internalProjection.json"
```

then re-run the extraction that produced the table above (filter each file's
`testGroups` to the `tgId`s listed in the table, keep those groups' `tests[]` verbatim).

## Known pitfalls this test file works around

- **ACVP keyGen supplies the raw `(d, z)` seed pair**, not a PRNG seed for the public
  `keygen()` entry point. You must call the library's *internal* deterministic keygen
  (`ML_KEM_768.key_derive(d ‖ z)` in kyber-py, `ML_DSA_65.key_derive(seed)` in
  dilithium-py) — calling the public `keygen()` will produce a different, random
  keypair and the vectors will never match.
- **ML-DSA sigGen vectors here are deterministic (non-hedged) mode.** `sign()` must be
  called with `deterministic=True` (and the vector's `context` bytes) or the signature
  will differ from the vector on every run, even though both are valid signatures.
- **ACVP encapsulation vectors supply explicit randomness `m`**, not a PRNG seed —
  you need the *internal* encapsulation entry point (`_encaps_internal(ek, m)` in
  kyber-py), not the public `encaps(ek)`, for the same reason as keyGen above.
