.PHONY: setup lint typecheck test bench report demo \
        docker-build docker-test docker-bench docker-cross-check

PYTHON ?= python3.11
VENV := .venv
VENV_PY := $(VENV)/bin/python

# --- Docker (the §4 reference environment: the only place liboqs is the live PQC
# backend, so every liboqs number in results/ has to be produced through these) -------
DOCKER_IMAGE ?= pqbio-liboqs
# There is no .git inside the image (it is assembled from explicit COPY steps), so the
# commit is passed in rather than discovered — see pqbio.bench._common.git_commit.
GIT_SHA := $(shell git rev-parse HEAD 2>/dev/null || echo unknown)

# Source read-only: the image installs pqbio editable, so mounting over /app/pqbio
# picks up host edits without an image rebuild. results/ writable so output lands on
# the host. models/ and data/ read-only here — a *test* run must never mutate a
# verified model (that this is enforced rather than assumed is what caught the
# reproducibility test's retrain-as-a-side-effect bug, §14).
DOCKER_MOUNTS_RO = \
	-v "$(CURDIR)/pqbio:/app/pqbio:ro" \
	-v "$(CURDIR)/scripts:/app/scripts:ro" \
	-v "$(CURDIR)/tests:/app/tests:ro" \
	-v "$(CURDIR)/config:/app/config:ro" \
	-v "$(CURDIR)/models:/app/models:ro" \
	-v "$(CURDIR)/data:/app/data:ro" \
	-v "$(CURDIR)/results:/app/results"

# `make bench` legitimately retrains the injection detector as part of a full
# evaluation, so the benchmark variant needs models/ writable. The server image itself
# never does — docker-compose.yml keeps models/ read-only for the running service.
DOCKER_MOUNTS_RW = \
	-v "$(CURDIR)/pqbio:/app/pqbio:ro" \
	-v "$(CURDIR)/scripts:/app/scripts:ro" \
	-v "$(CURDIR)/tests:/app/tests:ro" \
	-v "$(CURDIR)/config:/app/config:ro" \
	-v "$(CURDIR)/models:/app/models" \
	-v "$(CURDIR)/data:/app/data" \
	-v "$(CURDIR)/results:/app/results"

DOCKER_RUN_RO = docker run --rm -e PQBIO_GIT_COMMIT=$(GIT_SHA) $(DOCKER_MOUNTS_RO) $(DOCKER_IMAGE)
DOCKER_RUN_RW = docker run --rm -e PQBIO_GIT_COMMIT=$(GIT_SHA) $(DOCKER_MOUNTS_RW) $(DOCKER_IMAGE)

setup:
	$(PYTHON) -m venv $(VENV)
	$(VENV_PY) -m pip install --upgrade pip
	$(VENV_PY) -m pip install -e ".[dev]"
	@echo "setup complete. Activate with: source $(VENV)/bin/activate"
	@echo "GPU/vision stack (ml extras) and liboqs (pqc-liboqs extra) are opt-in:"
	@echo "  $(VENV_PY) -m pip install -e \".[ml]\""
	@echo "  $(VENV_PY) -m pip install -e \".[pqc-liboqs]\"   # requires cmake, ninja, a C compiler"

lint:
	$(VENV_PY) -m ruff check pqbio scripts tests
	$(VENV_PY) -m black --check pqbio scripts tests

typecheck:
	$(VENV_PY) -m mypy pqbio

test:
	$(VENV_PY) -m pytest -q

bench:
	$(VENV_PY) scripts/run_full_eval.py

report:
	$(VENV_PY) -m pqbio.bench.report

demo:
	@echo "make demo: not implemented yet (requires Module B-E — see PROJECT_SPEC.md §13)." >&2
	@exit 1

docker-build:
	docker build -f docker/Dockerfile.server -t $(DOCKER_IMAGE) .

docker-test:
	$(DOCKER_RUN_RO) python -m pytest -q

docker-bench:
	$(DOCKER_RUN_RW) python scripts/run_full_eval.py

# Proves the two PQC backends produce byte-identical output from identical seeds, and
# that each accepts the other's artefacts (§14). Both backends run inside this one
# image: the second pass blocks `import oqs` to force the pure-Python fallback.
docker-cross-check:
	$(DOCKER_RUN_RO) bash -c '\
		python scripts/cross_check_backends.py --emit /tmp/liboqs.json && \
		python scripts/cross_check_backends.py --emit /tmp/fallback.json --force-fallback && \
		python scripts/cross_check_backends.py --compare /tmp/liboqs.json /tmp/fallback.json \
			--out results/backend_cross_check.json && \
		python scripts/cross_check_backends.py --verify-artefacts /tmp/fallback.json && \
		python scripts/cross_check_backends.py --verify-artefacts /tmp/liboqs.json --force-fallback'
