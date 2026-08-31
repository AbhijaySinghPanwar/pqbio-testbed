"""One-time fetch of the SCRFD + ArcFace `buffalo_l` model pack (PROJECT_SPEC.md §4:
"No network calls at inference time. Models load from models/ with verified SHA-256.").

Run this once, with network access. It downloads (via insightface's own model zoo
downloader) into `models/insightface/`, then computes and records the SHA-256 of every
`*.onnx` file into `models/checksums.txt`. `pqbio/detect/face.py` verifies against those
checksums on every load and never touches the network itself.

Restricted to the `detection` and `recognition` modules only (SCRFD + ArcFace) — the
buffalo_l pack also ships gender/age/landmark models this project doesn't use; skipping
them via `allowed_modules` means they're never downloaded or loaded.

Usage:
    python scripts/fetch_face_models.py
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from pqbio.detect.face import (  # noqa: E402
    CHECKSUMS_PATH,
    INSIGHTFACE_ROOT,
    MODELS_DIR,
    _load_checksums,
    _sha256_file,
)


def main() -> None:
    print(
        f"fetching buffalo_l (detection + recognition only) into {INSIGHTFACE_ROOT}...",
        file=sys.stderr,
    )
    from insightface.app import FaceAnalysis

    app = FaceAnalysis(
        name="buffalo_l",
        root=str(INSIGHTFACE_ROOT),
        allowed_modules=["detection", "recognition"],
        providers=["CPUExecutionProvider"],
    )
    app.prepare(ctx_id=-1, det_size=(640, 640))
    print("model pack loaded OK; computing checksums...", file=sys.stderr)

    onnx_files = sorted(INSIGHTFACE_ROOT.rglob("*.onnx"))
    if not onnx_files:
        print(f"no .onnx files found under {INSIGHTFACE_ROOT} — fetch failed", file=sys.stderr)
        sys.exit(1)

    existing = _load_checksums()
    lines = [
        "# Model weight checksums",
        "#",
        "# Format: <sha256>  <relative-path-under-models/>",
        "#",
        "# Populated by scripts/fetch_face_models.py (face models) and",
        "# scripts/make_injection_corpus.py's training path (injection_gbm.txt, gitignored",
        "# — the model binary isn't committed, only its provenance would be if it were).",
        "# Model binaries themselves (models/*.onnx, models/*.pt) are gitignored; this file",
        "# is tracked so weight provenance survives even though the weights do not.",
        "",
    ]
    for path in onnx_files:
        rel_path = path.relative_to(MODELS_DIR).as_posix()
        digest = _sha256_file(path)
        existing[rel_path] = digest
        print(f"  {digest}  {rel_path}", file=sys.stderr)

    for rel_path in sorted(existing):
        lines.append(f"{existing[rel_path]}  {rel_path}")

    CHECKSUMS_PATH.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"wrote {CHECKSUMS_PATH} ({len(onnx_files)} entries)", file=sys.stderr)


if __name__ == "__main__":
    main()
