CC := clang
CFLAGS := -O2 -g -target bpf -I/usr/include -I/usr/src/linux-headers-$(shell uname -r)/include -D__BPF_TRACING__
SRC := ./kernel_ebpf/xdp_tcp.c
OBJ := ./objs/xdp_tcp.o
VMLINUX_H := ./objs/vmlinux.h


all: build_ebpf build_go

build_ebpf: $(VMLINUX_H) $(OBJ)

$(VMLINUX_H):
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX_H)

$(OBJ): $(SRC) $(VMLINUX_H)
	$(CC) $(CFLAGS) -c $< -o $@ || (echo "Error building eBPF program"; exit 1)  # Stop on error

build_go:
	go run ./main.go || (echo "Error running Go program"; exit 1)  # Stop on error

clean:
	rm -f $(OBJ)

docker:
	docker build -t xdp-go .


NUM_PROCS ?= 2
TEST_TIMEOUT ?= 2m
test: build_ebpf
	go run -mod=mod github.com/onsi/ginkgo/v2/ginkgo -r --procs=$(NUM_PROCS) --compilers=$(NUM_PROCS) \
		--randomize-all --randomize-suites \
		--cover --coverprofile=coverage.txt --covermode=atomic \
		--race --trace \
		--tags debug \
		--timeout=$(TEST_TIMEOUT)

.PHONY: all build_ebpf build_go clean

