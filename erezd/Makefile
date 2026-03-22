SYSTEM  := $(shell uname -s)

src/bpf/vmlinux.h:
ifneq ($(SYSTEM), Linux)
	@echo "Must be on Linux"
	@exit 1
endif

	bpftool btf dump file /sys/kernel/btf/vmlinux format c > src/bpf/vmlinux.h
	  
