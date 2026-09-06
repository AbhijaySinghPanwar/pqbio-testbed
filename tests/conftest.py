"""Root pytest conftest: shared import path, and a data dir no test can escape.

Makes tests/unit's shared fixture modules (_face_fixtures, _server_fixtures) importable
from tests/integration and tests/security too. Pytest's default "prepend" import mode only
puts a test file's own directory on sys.path when collecting it; tests/unit's own files
rely on that already (bare `from _face_fixtures import ...`), but a file under
tests/integration or tests/security needs tests/unit added explicitly.

It also redirects the server's default data dir for the whole session -- see
`_isolated_server_data_dir`.
"""

from __future__ import annotations

import sys
import tempfile
from collections.abc import Iterator
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent / "unit"))


@pytest.fixture(scope="session", autouse=True)
def _isolated_server_data_dir() -> Iterator[Path]:
    """Point `create_app()`'s default data dir at a throwaway directory, suite-wide.

    Structural rather than per-test on purpose. Tests that passed an explicit `data_dir`
    were already safe; the hazard was every test that did not, because they all shared
    `data/server_state/` -- the real one, in the working tree. Two failures came out of
    that: a masking test where the persisted pHash index made stage 5 reject the bundle as
    reused so the detector under test never ran, and a p99 concurrency test that degraded
    as the committed BK-tree grew across sessions. Both looked like code regressions.

    Autouse and session-scoped so no test can opt out by forgetting, and so the default
    location is unreachable rather than merely unused. Individual tests needing a *fresh*
    dir (one that no earlier test has written to) should still pass their own.
    """
    import pqbio.server.app as app_module

    with tempfile.TemporaryDirectory(prefix="pqbio-test-state-") as tmp:
        data_dir = Path(tmp) / "server_state"
        monkeypatch = pytest.MonkeyPatch()
        monkeypatch.setattr(app_module, "DEFAULT_DATA_DIR", data_dir)
        try:
            yield data_dir
        finally:
            monkeypatch.undo()


@pytest.fixture
def fresh_server_data_dir(tmp_path: Path) -> Path:
    """A data dir no earlier test has written to.

    Distinct from `_isolated_server_data_dir`, and the difference is not pedantry. That
    fixture makes the *default location* unreachable, which stops the working tree
    accumulating runtime state. It does not make the suite-wide dir *empty*: within one
    session, tests still share it, and the shared thing that bites is the pHash reuse
    index -- `build_live_genuine_bundle` emits byte-identical frames for every caller, so
    the first test to ACCEPT one makes every later test's identical bundle a reuse hit.

    Tests whose subject is reached only *past* the reuse check need this one. Verified the
    hard way: removing it from `test_pipeline_runs_match_when_b6_is_unevaluable` passed in
    isolation and failed in the full suite, because stage 5 rejected the bundle before the
    detector under test could run.
    """
    return tmp_path / "server_state"
