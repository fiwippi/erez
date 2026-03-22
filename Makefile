SYSTEM  := $(shell uname -s)

.PHONY: build
build: check-linux
	cargo build

.PHONY: check-linux
check-linux:
ifneq ($(SYSTEM), Linux)
	@echo "Must be on Linux"
	@exit 1
endif

.PHONY: clean
clean:
	rm -rf ./target

example/%: check-linux build
	sudo -E $(shell which cargo) run -p erez_test --example $*
	
.PHONY: install-deps
install-deps: check-linux
	@# Rust dependencies
	rustup toolchain install nightly --component rust-src
	rustup component add rust-analyzer
	
	@# BPF dependencies
	sudo apt install \
	    bpftool \
	    clang-19 \
	    clangd-19 \
	    libclang-19-dev \
	    libelf \
	    libpolly-19-dev \
	    llvm-19-dev \
	    zlib1g
	sudo update-alternatives --install /usr/bin/clang clang /usr/bin/clang-19 1 \
	    --slave /usr/bin/clang++ clang++ /usr/bin/clang++-19 \
	    --slave /usr/bin/clang-cpp clang-cpp /usr/bin/clang-cpp-19 \
	    --slave /usr/bin/clangd clangd /usr/bin/clangd-19

	@# We need BIRD for running the lab
	sudo apt install bird2 -y
	sudo systemctl stop bird # We run it manually in network namespaces, we don't want it running by default

.PHONY: lint
lint:
	cargo clippy --workspace
	cargo fmt --all -- --check

.PHONY: test
test: check-linux
	@# We need to manually resolve cargo's location
	@# because it doesn't exist in sudo's path
	sudo -E $(shell which cargo) nextest run -p erez_test

.PHONY: test-verbose
test-verbose: check-linux
	sudo -E $(shell which cargo) nextest run --no-capture -p erez_test

