"""Cross-check the two PQC backends against each other on deterministic inputs
(PROJECT_SPEC.md §14's liboqs amendment).

Owner: Abhijay

This is the check that retroactively validates every result this project produced while
the pure-Python `kyber-py`/`dilithium-py` fallback was the only available backend. The
ACVP KATs (tests/unit/test_pqc_kat.py) already prove each backend agrees with *NIST*
independently; this proves the two backends agree with *each other*, byte for byte, on
the same seeds — and, separately, that artefacts produced by one are accepted by the
other (interop, which identical outputs imply but which exercises the verify/decaps
code paths directly rather than by inference).

Only one backend can be active per process (`pqbio.pqc.kem` picks it at import time by
whether `import oqs` succeeds), so this runs in three steps:

    # inside the liboqs image
    python scripts/cross_check_backends.py --emit /tmp/liboqs.json
    # same image, oqs import blocked -> pure-Python fallback
    python scripts/cross_check_backends.py --emit /tmp/fallback.json --force-fallback
    python scripts/cross_check_backends.py --compare /tmp/liboqs.json /tmp/fallback.json

`--compare` exits non-zero on the first mismatch and prints exactly which operation,
which test-case index, and which field disagreed. `--verify-artefacts` additionally
checks the *other* backend's signatures/ciphertexts against the currently active one.

Inputs are the vendored NIST ACVP vectors (real published data, not self-generated)
plus a set of fixed synthetic seeds for coverage beyond them.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

VECTORS_DIR = REPO_ROOT / "tests" / "vectors"

# Synthetic seeds covering input space the vendored ACVP vectors don't reach. Fixed
# constants, not random: the whole point is that both backends see identical bytes.
_SYNTHETIC_SEEDS = [bytes([i]) * 32 for i in (0x00, 0x01, 0x7F, 0x80, 0xFE, 0xFF)]


class _OqsBlocker:
    """Makes `import oqs` fail, so `pqbio.pqc.*` selects the pure-Python fallback even
    inside an image where liboqs is installed and working.
    """

    def find_spec(self, fullname: str, path: Any = None, target: Any = None) -> None:
        if fullname == "oqs" or fullname.startswith("oqs."):
            raise ImportError("oqs import blocked by cross_check_backends --force-fallback")
        return None


def _load_vectors(name: str) -> dict[str, Any]:
    data: dict[str, Any] = json.loads((VECTORS_DIR / name).read_text(encoding="utf-8"))
    return data


def _h(hex_str: str) -> bytes:
    return bytes.fromhex(hex_str)


def emit() -> dict[str, Any]:
    """Run every deterministic operation both backends implement, and record the exact
    output bytes. Nothing here may use randomness: every value must be a pure function
    of the inputs, or the comparison is meaningless.
    """
    from pqbio.pqc.kem import (
        KEM_BACKEND,
        MLKEM768,
        ml_kem_768_encapsulate_with_randomness,
        ml_kem_768_keygen_from_seed,
    )
    from pqbio.pqc.sign import (
        MLDSA65,
        SIG_BACKEND,
        ml_dsa_65_keygen_from_seed,
        ml_dsa_65_sign_deterministic,
        ml_dsa_65_verify_with_context,
    )

    out: dict[str, Any] = {
        "KEM_BACKEND": KEM_BACKEND,
        "SIG_BACKEND": SIG_BACKEND,
        "ml_kem_keygen": [],
        "ml_kem_encaps": [],
        "ml_kem_decaps": [],
        "ml_dsa_keygen": [],
        "ml_dsa_sign": [],
        "ml_dsa_verify": [],
    }

    # ---- ML-KEM-768 keygen from (d, z): ACVP vectors + synthetic seeds -------------
    kem_keygen_cases: list[tuple[bytes, bytes]] = [
        (_h(c["d"]), _h(c["z"])) for c in _load_vectors("ML-KEM-768-keyGen.json")["tests"]
    ]
    kem_keygen_cases += [(s, s[::-1]) for s in _SYNTHETIC_SEEDS]
    for d, z in kem_keygen_cases:
        ek, dk = ml_kem_768_keygen_from_seed(d, z)
        out["ml_kem_keygen"].append({"d": d.hex(), "z": z.hex(), "ek": ek.hex(), "dk": dk.hex()})

    # ---- ML-KEM-768 encapsulation with explicit randomness m ----------------------
    encap_decap = _load_vectors("ML-KEM-768-encapDecap.json")
    for c in encap_decap["encapsulation"]["tests"]:
        ek_b, m_b = _h(c["ek"]), _h(c["m"])
        ct, ss = ml_kem_768_encapsulate_with_randomness(ek_b, m_b)
        out["ml_kem_encaps"].append({"m": m_b.hex(), "ct": ct.hex(), "ss": ss.hex()})

    # ---- ML-KEM-768 decapsulation (already deterministic given (dk, c)) -----------
    kem = MLKEM768()
    for c in encap_decap["decapsulation"]["tests"]:
        ss = kem.decapsulate(_h(c["c"]), _h(c["dk"]))
        out["ml_kem_decaps"].append({"ss": ss.hex()})

    # ---- ML-DSA-65 keygen from seed: ACVP vectors + synthetic seeds ---------------
    dsa_seeds = [_h(c["seed"]) for c in _load_vectors("ML-DSA-65-keyGen.json")["tests"]]
    dsa_seeds += _SYNTHETIC_SEEDS
    for seed in dsa_seeds:
        pk, sk = ml_dsa_65_keygen_from_seed(seed)
        out["ml_dsa_keygen"].append({"seed": seed.hex(), "pk": pk.hex(), "sk": sk.hex()})

    # ---- ML-DSA-65 deterministic signing, and verification ------------------------
    siggen = _load_vectors("ML-DSA-65-sigGen.json")
    for c in siggen["tests"]:
        sk_b, msg_b, ctx_b = _h(c["sk"]), _h(c["message"]), _h(c["context"])
        sig = ml_dsa_65_sign_deterministic(sk_b, msg_b, ctx=ctx_b)
        out["ml_dsa_sign"].append({"sig": sig.hex()})
        ok = ml_dsa_65_verify_with_context(_h(c["pk"]), msg_b, _h(c["signature"]), ctx=ctx_b)
        out["ml_dsa_verify"].append({"accepts_acvp_signature": ok})

    # A frozen-interface signature over a fixed keypair, for the interop check: the
    # other backend must accept this without ever having seen this process's state.
    frozen_seed = _SYNTHETIC_SEEDS[1]
    pk, sk = ml_dsa_65_keygen_from_seed(frozen_seed)
    frozen_sig = ml_dsa_65_sign_deterministic(sk, b"cross-backend interop probe", ctx=b"")
    out["interop_artefacts"] = {
        "dsa_pk": pk.hex(),
        "dsa_msg": b"cross-backend interop probe".hex(),
        "dsa_sig": frozen_sig.hex(),
    }
    ek, dk = ml_kem_768_keygen_from_seed(frozen_seed, frozen_seed[::-1])
    ct, ss = ml_kem_768_encapsulate_with_randomness(ek, _SYNTHETIC_SEEDS[2])
    out["interop_artefacts"].update({"kem_dk": dk.hex(), "kem_ct": ct.hex(), "kem_ss": ss.hex()})

    frozen_verify = MLDSA65().verify(b"cross-backend interop probe", frozen_sig, pk)
    out["interop_artefacts"]["self_verify"] = frozen_verify
    return out


def compare(path_a: Path, path_b: Path, out: Path | None = None) -> int:
    a = json.loads(path_a.read_text(encoding="utf-8"))
    b = json.loads(path_b.read_text(encoding="utf-8"))

    print(f"A: KEM={a['KEM_BACKEND']} SIG={a['SIG_BACKEND']}  ({path_a})")
    print(f"B: KEM={b['KEM_BACKEND']} SIG={b['SIG_BACKEND']}  ({path_b})")
    if (a["KEM_BACKEND"], a["SIG_BACKEND"]) == (b["KEM_BACKEND"], b["SIG_BACKEND"]):
        print(
            "REFUSING: both files were produced by the same backend pair — this would "
            "compare a backend against itself and pass vacuously.",
            file=sys.stderr,
        )
        return 2

    mismatches: list[str] = []
    total_fields = 0
    per_section: dict[str, int] = {}
    for section in (
        "ml_kem_keygen",
        "ml_kem_encaps",
        "ml_kem_decaps",
        "ml_dsa_keygen",
        "ml_dsa_sign",
        "ml_dsa_verify",
    ):
        rows_a, rows_b = a[section], b[section]
        if len(rows_a) != len(rows_b):
            mismatches.append(f"{section}: case count {len(rows_a)} != {len(rows_b)}")
            continue
        for i, (ra, rb) in enumerate(zip(rows_a, rows_b, strict=True)):
            for field in ra:
                total_fields += 1
                if ra[field] != rb.get(field):
                    mismatches.append(
                        f"{section}[{i}].{field}: A={ra[field]!r} B={rb.get(field)!r}"
                    )
        per_section[section] = len(rows_a)
        print(f"  {section}: {len(rows_a)} cases compared")

    for field, va in a["interop_artefacts"].items():
        total_fields += 1
        vb = b["interop_artefacts"].get(field)
        if va != vb:
            mismatches.append(f"interop_artefacts.{field}: A={va!r} B={vb!r}")
    per_section["interop_artefacts"] = len(a["interop_artefacts"])
    print(f"  interop_artefacts: {len(a['interop_artefacts'])} fields compared")

    if out is not None:
        from pqbio.bench._common import run_metadata, write_json

        write_json(
            out,
            {
                **run_metadata(),
                "backend_a": {"KEM": a["KEM_BACKEND"], "SIG": a["SIG_BACKEND"]},
                "backend_b": {"KEM": b["KEM_BACKEND"], "SIG": b["SIG_BACKEND"]},
                "cases_compared": per_section,
                "total_fields_compared": total_fields,
                "mismatches": mismatches,
                "agree": not mismatches,
                "note": (
                    "Deterministic cross-check of the two PQC backends against each "
                    "other on identical seeds (NIST ACVP vectors + fixed synthetic "
                    "seeds), plus two-directional interop. Generated by "
                    "scripts/cross_check_backends.py; see PROJECT_SPEC.md §14's liboqs "
                    "amendment."
                ),
            },
        )
        print(f"wrote {out}", file=sys.stderr)

    if mismatches:
        print(f"\nBACKENDS DISAGREE — {len(mismatches)} mismatch(es):", file=sys.stderr)
        for m in mismatches[:20]:
            print(f"  {m}", file=sys.stderr)
        if len(mismatches) > 20:
            print(f"  ... and {len(mismatches) - 20} more", file=sys.stderr)
        return 1

    print(f"\nBACKENDS AGREE: {total_fields} fields identical, byte for byte.")
    return 0


def verify_artefacts(path_other: Path) -> int:
    """Verify the *other* backend's signature and decapsulate its ciphertext using the
    backend active in this process — interop, not just identical determinism.
    """
    from pqbio.pqc.kem import KEM_BACKEND, MLKEM768
    from pqbio.pqc.sign import MLDSA65, SIG_BACKEND

    other = json.loads(path_other.read_text(encoding="utf-8"))
    art = other["interop_artefacts"]
    print(f"verifying artefacts from KEM={other['KEM_BACKEND']} SIG={other['SIG_BACKEND']}")
    print(f"           using backends KEM={KEM_BACKEND} SIG={SIG_BACKEND}")

    sig_ok = MLDSA65().verify(_h(art["dsa_msg"]), _h(art["dsa_sig"]), _h(art["dsa_pk"]))
    ss = MLKEM768().decapsulate(_h(art["kem_ct"]), _h(art["kem_dk"]))
    ss_ok = ss.hex() == art["kem_ss"]

    print(f"  ML-DSA-65 signature from other backend verifies: {sig_ok}")
    print(f"  ML-KEM-768 decapsulation agrees on shared secret: {ss_ok}")
    if sig_ok and ss_ok:
        print("\nINTEROP OK.")
        return 0
    print("\nINTEROP FAILED.", file=sys.stderr)
    return 1


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--emit", type=Path, help="write this backend's deterministic outputs")
    parser.add_argument(
        "--force-fallback",
        action="store_true",
        help="block `import oqs` so the pure-Python fallback is selected",
    )
    parser.add_argument("--compare", type=Path, nargs=2, metavar=("A", "B"))
    parser.add_argument("--verify-artefacts", type=Path, metavar="OTHER")
    parser.add_argument("--out", type=Path, help="with --compare: write a summary JSON here")
    args = parser.parse_args()

    if args.force_fallback:
        sys.meta_path.insert(0, _OqsBlocker())

    if args.compare:
        sys.exit(compare(args.compare[0], args.compare[1], out=args.out))
    if args.verify_artefacts:
        sys.exit(verify_artefacts(args.verify_artefacts))
    if args.emit:
        result = emit()
        args.emit.parent.mkdir(parents=True, exist_ok=True)
        args.emit.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(
            f"wrote {args.emit} (KEM={result['KEM_BACKEND']} SIG={result['SIG_BACKEND']})",
            file=sys.stderr,
        )
        return
    parser.error("one of --emit, --compare, or --verify-artefacts is required")


if __name__ == "__main__":
    main()
