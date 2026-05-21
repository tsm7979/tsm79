# TSM eBPF Loader — C userspace build
#
# Requires: libbpf-dev libelf-dev zlib1g-dev clang llvm linux-headers
# On Debian/Ubuntu: apt install libbpf-dev libelf-dev zlib1g-dev clang llvm

CC      ?= gcc
CFLAGS  := -O2 -Wall -Wextra -Wpedantic -std=c11 -D_GNU_SOURCE
LDFLAGS := -lbpf -lelf -lz

# BPF kernel programs (compiled with clang)
CLANG   ?= clang
BPF_SRC := ../ebpf/src
BPF_OBJ := tsm_xdp.o

SRCS := tsm_loader.c
OBJS := $(SRCS:.c=.o)
BIN  := tsm_loader

.PHONY: all clean bpf

all: bpf $(BIN)

$(BIN): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
	@echo "Built $@"

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

# Compile the BPF kernel programs (ingress + egress + tproxy)
bpf: $(BPF_OBJ)

$(BPF_OBJ): $(BPF_SRC)/ingress.c $(BPF_SRC)/maps.h
	$(CLANG) -O2 -g -target bpf \
		-Wall \
		-I/usr/include/$(shell uname -m)-linux-gnu \
		-I$(BPF_SRC) \
		-c $(BPF_SRC)/ingress.c \
		-o $@
	@echo "Compiled BPF object: $@"

clean:
	rm -f $(BIN) $(OBJS) $(BPF_OBJ)

# Install to /usr/local/sbin
install: $(BIN)
	install -m 0755 -o root -g root $(BIN) /usr/local/sbin/
	install -m 0644 ../ebpf/src/ai_cidrs.txt /etc/tsm/ 2>/dev/null || true
	@echo "Installed $(BIN) to /usr/local/sbin/"

# Run with defaults (requires root)
run: $(BIN)
	sudo ./$(BIN) --iface $(TSM_IFACE) --obj $(BPF_OBJ) --cidrs /etc/tsm/ai_cidrs.txt
