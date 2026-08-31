"""Root pytest conftest: makes tests/unit's shared fixture modules (_face_fixtures,
_server_fixtures) importable from tests/integration and tests/security too.

Pytest's default "prepend" import mode only puts a test file's own directory on
sys.path when collecting it; tests/unit's own files rely on that already (bare
`from _face_fixtures import ...`), but a file under tests/integration or
tests/security needs tests/unit added explicitly to reach those same modules.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "unit"))
