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
# The allocator reserves room for every enclave on this host: one /etc/miso/<name>.env each.
total_cpus=$(sed -n 's/^ENCLAVE_CPUS=//p' /etc/miso/*.env | awk '{ s += $1 } END { print s }')
total_mib=$(sed -n 's/^ENCLAVE_MEMORY_MIB=//p' /etc/miso/*.env | awk '{ s += $1 } END { print s }')
printf -- '---\nmemory_mib: %s\ncpu_count: %s\n' "$total_mib" "$total_cpus" > /etc/nitro_enclaves/allocator.yaml
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

install -m 0755 "$here/miso-enclave-register.py" /usr/local/bin/miso-enclave-register
install -m 0644 "$here/audio-verifier-enclave.service" "$here/argonaut.service" \
	"$here/audio-verifier-host.service" "$here/miso-enclave-register@.service" /etc/systemd/system/
if [ ! -f /etc/miso/audio-verifier.register.env ]; then
	cat > /etc/miso/audio-verifier.register.env <<-ENV
	GATEWAY=http://127.0.0.1:4000
	POLICY=0xeb9fdb274f4edbda86b322cbb876a4f92aa6b9e58964d6d5953ff0cead49160e
	APP=0x79cb3c048707800ea6219cf5f86ef22993837ccb912bba81035abc337e5454c0::audio_verifier::AUDIO_VERIFIER
	ENCLAVE_PACKAGE=0x964846cf1950fc395f7fef6771b2e08f8b00f6871c1560e7dd0ddf1c75c6abb0
	OPS_KEY=/etc/miso/ops.key
	ENV
fi
if [ ! -f /etc/miso/ops.key ]; then
	(umask 077 && python3 -c 'import os; print(os.urandom(32).hex())' > /etc/miso/ops.key)
fi
systemctl daemon-reload
systemctl enable --now nitro-enclaves-allocator.service
systemctl enable audio-verifier-enclave.service argonaut.service audio-verifier-host.service \
	miso-enclave-register@audio-verifier.service
echo "Installed. Start with: systemctl start audio-verifier-enclave argonaut audio-verifier-host"
echo "Every start makes a new enclave key; miso-enclave-register@audio-verifier registers it with the"
echo "operations key /etc/miso/ops.key, whose address needs testnet SUI:"
echo "  miso-enclave-register --address"
