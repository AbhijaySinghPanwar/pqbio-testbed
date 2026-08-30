.PHONY: setup lint typecheck test bench report demo

PYTHON ?= python3.11
VENV := .venv
VENV_PY := $(VENV)/bin/python

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
	@echo "make bench: not implemented yet (Module F — see PROJECT_SPEC.md §5.6)." >&2
	@echo "For the Module A PQC micro-benchmark, run: $(VENV_PY) scripts/bench_pqc.py" >&2
	@exit 1

report:
	@echo "make report: not implemented yet (Module F — see PROJECT_SPEC.md §5.6)." >&2
	@exit 1

demo:
	@echo "make demo: not implemented yet (requires Module B-E — see PROJECT_SPEC.md §13)." >&2
	@exit 1
