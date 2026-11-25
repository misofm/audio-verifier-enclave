# The pins compiled into the image: testnet into out/, mainnet (the crate's `mainnet` feature)
# into out/mainnet/, so neither build overwrites the other's PCRs.
NETWORK ?= testnet
ifeq ($(NETWORK),testnet)
OUT_DIR ?= out
else ifeq ($(NETWORK),mainnet)
OUT_DIR ?= out/mainnet
else
$(error NETWORK must be testnet or mainnet, not $(NETWORK))
endif
ENCLAVE_CID ?= 16
ENCLAVE_CPUS ?= 4
ENCLAVE_MEMORY ?= 6144M
EIF_INPUTS := Cargo.toml Cargo.lock rust-toolchain.toml Containerfile.eif .dockerignore $(shell find crates scripts -type f -not -path '*/target/*')

.DEFAULT_GOAL := eif

.PHONY: eif
eif: $(OUT_DIR)/nitro.eif

$(OUT_DIR):
	mkdir -p $(OUT_DIR)

$(OUT_DIR)/nitro.eif: $(EIF_INPUTS) | $(OUT_DIR)
	rm -rf vendor
	cargo vendor --locked vendor > vendor.toml
	mv vendor.toml vendor/config.toml
	# Vendored files keep crates.io's fixed 2006 mtime, and BuildKit's context transfer reuses
	# a cached file of the same path, size and mtime: a crate's new version could arrive with
	# an old version's files. The image never sees these mtimes.
	find vendor -exec touch {} +
	docker build \
		--pull \
		--progress=plain \
		--platform linux/amd64 \
		--provenance=false \
		--build-arg NETWORK=$(NETWORK) \
		--output type=local,rewrite-timestamp=true,dest=$(OUT_DIR) \
		-f Containerfile.eif \
		.

.PHONY: run-eif
run-eif: $(OUT_DIR)/nitro.eif
	sudo nitro-cli run-enclave \
		--cpu-count $(ENCLAVE_CPUS) \
		--memory $(ENCLAVE_MEMORY) \
		--enclave-cid $(ENCLAVE_CID) \
		--eif-path $(OUT_DIR)/nitro.eif

.PHONY: run-eif-debug
run-eif-debug: $(OUT_DIR)/nitro.eif
	@echo 'WARNING: debug mode reports all-zero PCRs; this enclave cannot be attested or registered on chain.' >&2
	sudo nitro-cli run-enclave \
		--cpu-count $(ENCLAVE_CPUS) \
		--memory $(ENCLAVE_MEMORY) \
		--enclave-cid $(ENCLAVE_CID) \
		--eif-path $(OUT_DIR)/nitro.eif \
		--debug-mode \
		--attach-console
