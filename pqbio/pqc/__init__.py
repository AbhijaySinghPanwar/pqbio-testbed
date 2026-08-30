"""Module A: post-quantum cryptographic layer (PROJECT_SPEC.md §5.1).

Owner: Aviral. Provides the PQ-secure channel and signing primitives; everything else
in the system treats this package as a black box behind the KEM/Signer interfaces.
"""

from pqbio.pqc.kem import KEM, MLKEM768, X25519KEM, KemMode, get_kem
from pqbio.pqc.sign import MLDSA65, Ed25519Signer, SigMode, Signer, get_signer

__all__ = [
    "KEM",
    "KemMode",
    "MLKEM768",
    "X25519KEM",
    "get_kem",
    "Signer",
    "SigMode",
    "Ed25519Signer",
    "MLDSA65",
    "get_signer",
]
