#!/bin/bash
# Sets up an Amazon Linux 2023 Nitro parent instance to run the audio verifier enclave.
# Run as root from a checkout of this repository: host/setup.sh <path-to-nitro.eif> [vCPUs] [MiB]
set -euo pipefail

eif=${1:?usage: host/setup.sh <nitro.eif> [vCPUs] [MiB]}
cpus=${2:-4}
memory_mib=${3:-6144}
argonaut_commit=02a067cf273a0d26554bd7936d4a1caf5699d8e4
here=$(cd "$(dirname "$0")" && pwd)

dnf install -y -q aws-nitro-enclaves-cli golang git gcc

mkdir -p /etc/miso /opt/miso /opt/src
printf 'ENCLAVE_CPUS=%s\nENCLAVE_MEMORY_MIB=%s\n' "$cpus" "$memory_mib" > /etc/miso/audio-verifier.env
printf -- '---\nmemory_mib: %s\ncpu_count: %s\n' "$memory_mib" "$cpus" > /etc/nitro_enclaves/allocator.yaml
install -m 0644 "$eif" /opt/miso/audio-verifier.eif

rm -rf /opt/src/argonaut
git clone -q https://github.com/miraicloud/argonaut.git /opt/src/argonaut
git -C /opt/src/argonaut checkout -q "$argonaut_commit"
(cd /opt/src/argonaut && HOME=/root GOTOOLCHAIN=auto CGO_ENABLED=0 go build -ldflags='-s -w' -o /usr/local/bin/argonaut .)

export HOME=/root PATH="/root/.cargo/bin:$PATH"
if ! command -v rustup >/dev/null; then
	curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
		| sh -s -- -y -q --profile minimal --default-toolchain none --no-modify-path
fi
(cd "$here/gateway" && rustup toolchain install && cargo build -q --locked --release)
install -m 0755 "$here/gateway/target/release/audio-verifier-host" /usr/local/bin/

install -m 0644 "$here/audio-verifier-enclave.service" "$here/argonaut.service" \
	"$here/audio-verifier-host.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now nitro-enclaves-allocator.service
systemctl enable audio-verifier-enclave.service argonaut.service audio-verifier-host.service
echo "Installed. Start with: systemctl start audio-verifier-enclave argonaut audio-verifier-host"
echo "Every start makes a new enclave key: register it on chain before using its signatures."
