# Tessera gallery server — build, test and hardening gates.
#
# There is no compiled server binary: the daemon is Python. The one native
# artefact is libhydrogen, built here as a shared object and loaded by
# src/tessera/hydro.py through ctypes. It is pinned to a commit because the
# 3DS client is pinned to the same one; a signature scheme that differs
# between the two ends is a silent, total outage.

HYDRO_REPO   := https://github.com/jedisct1/libhydrogen.git
HYDRO_COMMIT := 617036a353cd4f6478ab6c3f98c36dd31e23ce8e
DEPS         := .deps
HYDRO        := $(DEPS)/libhydrogen
BUILD        := build
HYDRO_SO     := $(BUILD)/libhydrogen.so

PYTHON  ?= python3
PYTEST  ?= $(PYTHON) -m pytest

# Same hardening flags Blocksmith links its gateway with, applied to the only
# native object in this tree.
HYDRO_CFLAGS  := -std=c11 -O2 -g -fPIC -I$(HYDRO)
HYDRO_LDFLAGS := -shared -Wl,-z,relro,-z,now -Wl,-z,noexecstack -Wl,--as-needed

.PHONY: all deps build test install-check hardening-check clean

all: build

deps: $(HYDRO)/hydrogen.h

$(HYDRO)/hydrogen.h:
	@mkdir -p $(DEPS)
	@echo "fetching libhydrogen at $(HYDRO_COMMIT)"
	git clone -q $(HYDRO_REPO) $(HYDRO)
	git -C $(HYDRO) -c safe.directory='*' checkout -q $(HYDRO_COMMIT)
	@test "$$(git -C $(HYDRO) -c safe.directory='*' rev-parse HEAD)" = "$(HYDRO_COMMIT)" \
	    || (echo "libhydrogen is NOT at the pinned commit"; exit 1)
	@echo "libhydrogen pinned at $(HYDRO_COMMIT)"

build: $(HYDRO_SO)

$(HYDRO_SO): $(HYDRO)/hydrogen.h $(HYDRO)/hydrogen.c
	@mkdir -p $(BUILD)
	$(CC) $(HYDRO_CFLAGS) $(HYDRO)/hydrogen.c -o $@ $(HYDRO_LDFLAGS)

test: build
	TESSERA_HYDRO_LIBRARY=$(abspath $(HYDRO_SO)) $(PYTEST)

# The install gate. container-provision.sh and ts-update both refuse to
# install if this exits non-zero.
install-check: build
	@echo "== libhydrogen pin =="
	@test "$$(git -C $(HYDRO) -c safe.directory='*' rev-parse HEAD)" = "$(HYDRO_COMMIT)" \
	    && echo "  pinned commit ok" || (echo "  WRONG libhydrogen commit"; exit 1)
	@echo "== native artefact hardening =="
	@readelf -d $(HYDRO_SO) | grep -qE 'BIND_NOW'       && echo "  RELRO/BIND_NOW ok" || (echo "  MISSING bind-now"; exit 1)
	@readelf -h $(HYDRO_SO) | grep -qE 'DYN'            && echo "  shared/PIC ok"     || (echo "  not a shared object"; exit 1)
	@readelf -lW $(HYDRO_SO) | grep -q 'GNU_STACK.*RW ' && echo "  NX stack ok"       || (echo "  stack may be executable"; exit 1)
	@echo "== no image decoding anywhere in the daemon =="
	@$(PYTHON) tests/scan_no_image_decode.py src/tessera

# Static assertion that the shipped unit still carries every hardening
# setting. install/hardening-check.sh is also run against the LIVE installed
# unit by container-provision.sh and ts-update, which is the check that
# actually matters in production; this target is the dev-machine-runnable form.
hardening-check:
	@install/hardening-check.sh systemd/tessera.service
	@install/hardening-check.sh systemd/playit.service --profile playit

clean:
	rm -rf $(BUILD) .pytest_cache
	find . -name '__pycache__' -type d -prune -exec rm -rf {} +
