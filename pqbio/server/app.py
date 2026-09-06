"""FastAPI app: startup, model-integrity gate, dependency wiring (PROJECT_SPEC.md §5.5).

Owner: Abhijay

`create_app()` is a factory (not a single module-level `app`) so tests can each get an
isolated data directory and a fresh in-process server — SQLite-backed state must not
leak between tests. `python -m pqbio.server.app` still exposes a module-level `app` for
`uvicorn pqbio.server.app:app`.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI

from pqbio.binding.nonce import NonceStore
from pqbio.binding.phash_index import PhashIndex
from pqbio.config import settings
from pqbio.detect.face import CHECKSUMS_PATH, MODELS_DIR, _load_checksums, _sha256_file
from pqbio.detect.fusion import DEFAULT_CASCADE_MODEL_PATH, CascadeModel
from pqbio.detect.injection import DEFAULT_MODEL_PATH as INJECTION_MODEL_PATH
from pqbio.detect.injection import InjectionDetector
from pqbio.detect.morph import MorphDetector
from pqbio.pqc.kem import get_kem
from pqbio.pqc.sign import get_signer
from pqbio.server.store import AuditLog, SessionStore, SqliteKeyStore

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_DATA_DIR = REPO_ROOT / "data" / "server_state"


class ModelIntegrityStartupError(RuntimeError):
    """Raised — and never caught — when any model listed in `models/checksums.txt` is
    missing or mismatched. The server must refuse to start rather than silently run
    with an unverified or absent detector (§5.5 DoD).
    """


def verify_all_model_checksums() -> None:
    """Verifies *every* entry in `models/checksums.txt` — both the face models
    (SCRFD/ArcFace) and the injection GBM — not just the face ones `pqbio.detect.face`
    checks for its own purposes. A model directory with nothing recorded at all is
    treated the same as a mismatch: fail closed, don't start unverified.
    """
    entries = _load_checksums()
    if not entries:
        raise ModelIntegrityStartupError(
            f"{CHECKSUMS_PATH} has no recorded checksums — refusing to start with no "
            "verified models. Run scripts/fetch_face_models.py and train the injection "
            "detector first."
        )
    for rel_path, expected in entries.items():
        path = MODELS_DIR / rel_path
        if not path.is_file():
            raise ModelIntegrityStartupError(
                f"model file missing: {path} (checksums.txt lists {rel_path})"
            )
        actual = _sha256_file(path)
        if actual != expected:
            raise ModelIntegrityStartupError(
                f"model file {path} SHA-256 mismatch: checksums.txt says {expected}, "
                f"disk has {actual}"
            )


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    verify_all_model_checksums()  # raises -> ASGI server fails to start; never caught here

    data_dir: Path = app.state.data_dir
    data_dir.mkdir(parents=True, exist_ok=True)

    app.state.keystore = SqliteKeyStore(data_dir / "devices.db")
    app.state.session_store = SessionStore(data_dir / "sessions.db")
    app.state.nonce_store = NonceStore(data_dir / "nonces.db")
    app.state.phash_index = PhashIndex(data_dir / "phash.db")
    app.state.audit_log = AuditLog(data_dir / "audit.db", research_retain=app.state.research_retain)

    app.state.signer = get_signer(settings.crypto.mode)
    app.state.server_sig_pk, app.state.server_sig_sk = app.state.signer.keygen()
    app.state.kem = get_kem(settings.crypto.mode)
    app.state.server_kem_pk, app.state.server_kem_sk = app.state.kem.keygen()

    app.state.injection_detector = InjectionDetector(
        model_path=INJECTION_MODEL_PATH if INJECTION_MODEL_PATH.is_file() else None
    )
    # S-MAD: see pipeline.py stage 6 for why the differential setting cannot be used at
    # /v1/verify. Falls back to an unscored 0.0 with an explicit reason when the model
    # file is absent, exactly as the injection detector does.
    app.state.morph_detector = MorphDetector(setting="smad")

    app.state.cascade_model = None
    if DEFAULT_CASCADE_MODEL_PATH.is_file():
        app.state.cascade_model = CascadeModel.from_json(
            json.loads(DEFAULT_CASCADE_MODEL_PATH.read_text(encoding="utf-8"))
        )

    app.state.executor = ThreadPoolExecutor(
        max_workers=settings.server.workers, thread_name_prefix="pqbio-pipeline"
    )

    try:
        yield
    finally:
        app.state.executor.shutdown(wait=True)


def create_app(*, data_dir: Path | None = None, research_retain: bool = False) -> FastAPI:
    fastapi_app = FastAPI(
        title="pq-bio-auth verification server",
        lifespan=_lifespan,
    )
    fastapi_app.state.data_dir = data_dir if data_dir is not None else DEFAULT_DATA_DIR
    fastapi_app.state.research_retain = research_retain

    from pqbio.server.routes import router

    fastapi_app.include_router(router)
    return fastapi_app


app = create_app()
