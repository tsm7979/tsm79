# TSMv2 — eBPF/XDP program build
#
# Requires: clang >= 12 with BPF target support, kernel headers, libbpf-dev
#
# Usage:
#   make            — build ingress.o and egress.o
#   make clean      — remove build artifacts
#   make install    — copy .o files to ../ebpf-loader/bpf/ for embedding

CLANG   ?= clang
LLC     ?= llc
ARCH    := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

# Kernel headers search paths
KERNEL_HEADERS ?= /usr/include/$(shell uname -m)-linux-gnu
LIBBPF_HEADERS ?= /usr/include

CFLAGS := \
    -target bpf \
    -O2 \
    -Wall \
    -Wno-unused-value \
    -Wno-pointer-sign \
    -Wno-compare-distinct-pointer-types \
    -fno-stack-protector \
    -D__TARGET_ARCH_$(ARCH) \
    -I$(KERNEL_HEADERS) \
    -I$(LIBBPF_HEADERS) \
    -Isrc

BPF_LOADER_BPF_DIR := ../ebpf-loader/bpf

SRCS := src/ingress.c src/egress.c
OBJS := $(SRCS:src/%.c=build/%.o)

.PHONY: all clean install dirs

all: dirs $(OBJS)
	@echo "[ebpf] Build complete: $(OBJS)"

dirs:
	@mkdir -p build

build/%.o: src/%.c src/maps.h
	@echo "[clang] $< → $@"
	$(CLANG) $(CFLAGS) -c $< -o $@

install: all
	@mkdir -p $(BPF_LOADER_BPF_DIR)
	@cp build/ingress.o $(BPF_LOADER_BPF_DIR)/ingress.o
	@cp build/egress.o  $(BPF_LOADER_BPF_DIR)/egress.o
	@echo "[ebpf] Installed to $(BPF_LOADER_BPF_DIR)"

clean:
	@rm -rf build/
	@echo "[ebpf] Cleaned"

# ── Verification targets ──────────────────────────────────────────────────────

# Verify the compiled objects with llvm-objdump
verify: all
	@for obj in $(OBJS); do \
		echo "=== $$obj ==="; \
		llvm-objdump -d $$obj | head -40; \
	done

# Check that the maps section exists (required for loader)
check-maps: all
	@for obj in $(OBJS); do \
		if llvm-readelf -S $$obj | grep -q '\.maps'; then \
			echo "[OK] $$obj has .maps section"; \
		else \
			echo "[FAIL] $$obj missing .maps section"; exit 1; \
		fi; \
	done

# bpftool skeleton (optional — for CO-RE builds)
skeleton: all
	@for obj in $(OBJS); do \
		base=$$(basename $$obj .o); \
		bpftool gen skeleton $$obj > build/$${base}.skel.h; \
		echo "[skel] build/$${base}.skel.h generated"; \
	done
