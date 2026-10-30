# Castlevania loader-only phase. No donor game build/profile fallback.
PY ?= python3
.PHONY: all check loader-probe probe host runtime rewrite prepare
all: check
check:
	$(PY) -m unittest discover -s tests -v
loader-probe:
	$(PY) scripts/build_loader_probe.py --tables "$(TABLES)"
probe:
	$(PY) scripts/run_loader_probe.py --modules "$(MODULES)"
host runtime rewrite prepare:
	@printf '%s\n' 'Unavailable in this loader-only implementation. A later diagnostic host must validate its data view; unsupported operations must stop.'
	@exit 2
