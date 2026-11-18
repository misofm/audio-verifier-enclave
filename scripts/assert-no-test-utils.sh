#!/bin/sh
# Fails if the enclave binary's build enables nautilus/test-utils, whose development identity
# has a public signing key. Run by Containerfile.eif before the build.
set -eu

tree=$(cargo tree --locked -p audio-verifier-enclave --target x86_64-unknown-linux-musl \
	-e normal,features -i nautilus --prefix none "$@")
if printf '%s\n' "$tree" | grep -q '^nautilus feature "test-utils"'; then
	echo "error: audio-verifier-enclave enables nautilus/test-utils" >&2
	exit 1
fi
echo "ok: audio-verifier-enclave does not enable nautilus/test-utils"
