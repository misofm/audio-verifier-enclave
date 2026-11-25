#!/bin/bash
# Sets up an Amazon Linux 2023 Nitro parent instance to run the audio verifier enclave.
# Run as root from a checkout of this repository: host/setup.sh <path-to-nitro.eif> [vCPUs] [MiB]
# NETWORK (testnet, the default, or mainnet) must be the network the image was built for
# (`make eif NETWORK=...`). WALRUS_PUBLISHER is the publisher /measure stores ciphertexts with:
# testnet's public one by default, required on mainnet, which has no public publisher.
# OPS_KMS_KEY, optional, is the ARN of an AWS KMS secp256k1 key that signs registrations in place
# of a generated /etc/miso/ops.key.
set -euo pipefail

eif=${1:?usage: [NETWORK=mainnet WALRUS_PUBLISHER=<url>] host/setup.sh <nitro.eif> [vCPUs] [MiB]}
cpus=${2:-4}
memory_mib=${3:-6144}
network=${NETWORK:-testnet}
argonaut_commit=02a067cf273a0d26554bd7936d4a1caf5699d8e4
here=$(cd "$(dirname "$0")" && pwd)

case "$network" in
testnet)
	policy=0xeb9fdb274f4edbda86b322cbb876a4f92aa6b9e58964d6d5953ff0cead49160e
	app=0x79cb3c048707800ea6219cf5f86ef22993837ccb912bba81035abc337e5454c0::audio_verifier::AUDIO_VERIFIER
	enclave_package=0x964846cf1950fc395f7fef6771b2e08f8b00f6871c1560e7dd0ddf1c75c6abb0
	graphql=https://graphql.testnet.sui.io/graphql
	publisher=${WALRUS_PUBLISHER:-https://publisher.walrus-testnet.walrus.space}
	;;
mainnet)
	policy=0x7d5d2a995a4b243c408c3cf09f8f037211161494c3636f668696c844031fda1e
	app=0x11f24c8cd2aa5dd42580c6799922a6197b2ef6a93cff2f64b6bb8f86ffdc47e4::audio_verifier::AUDIO_VERIFIER
	enclave_package=0x7914545ac251592310fd47fb3a70cdc2b30c233ca0e38b15b5494f30bb0df0ce
	graphql=https://graphql.mainnet.sui.io/graphql
	publisher=${WALRUS_PUBLISHER:?WALRUS_PUBLISHER is required on mainnet: the URL of your Walrus publisher}
	;;
*)
	echo "NETWORK must be testnet or mainnet, not $network" >&2
	exit 1
	;;
esac
case "$publisher" in
http://* | https://*) ;;
*)
	echo "WALRUS_PUBLISHER must be an http(s) URL, not $publisher" >&2
	exit 1
	;;
esac
case "$publisher" in
*[[:space:]]*)
	echo "WALRUS_PUBLISHER must not contain whitespace" >&2
	exit 1
	;;
esac
register_env=/etc/miso/audio-verifier.register.env
# A register file written before NETWORK existed is testnet's.
if [ -f "$register_env" ]; then
	registered=$(sed -n 's/^NETWORK=//p' "$register_env")
	if [ "${registered:-testnet}" != "$network" ]; then
		echo "$register_env is for ${registered:-testnet}, not $network; remove it to switch" >&2
		exit 1
	fi
fi

dnf install -y -q aws-nitro-enclaves-cli golang git gcc

mkdir -p /etc/miso /opt/miso /opt/src
printf 'ENCLAVE_CPUS=%s\nENCLAVE_MEMORY_MIB=%s\n' "$cpus" "$memory_mib" > /etc/miso/audio-verifier.env
printf 'WALRUS_PUBLISHER=%s\n' "$publisher" > /etc/miso/audio-verifier.host.env
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
# The operations key that signs registrations: an AWS KMS secp256k1 key by ARN (OPS_KMS_KEY,
# signed with the instance's role; the key never leaves KMS), else an Ed25519 seed in a file.
if [ -n "${OPS_KMS_KEY:-}" ]; then
	case "$OPS_KMS_KEY" in
	arn:aws:kms:*:*:key/*) ops_line="OPS_KMS_KEY=$OPS_KMS_KEY" ;;
	*)
		echo "OPS_KMS_KEY must be a KMS key ARN (arn:aws:kms:<region>:<account>:key/<id>)" >&2
		exit 1
		;;
	esac
else
	ops_line=OPS_KEY=/etc/miso/ops.key
fi
if [ ! -f "$register_env" ]; then
	cat > "$register_env" <<-ENV
	NETWORK=$network
	GATEWAY=http://127.0.0.1:4000
	POLICY=$policy
	APP=$app
	ENCLAVE_PACKAGE=$enclave_package
	GRAPHQL=$graphql
	$ops_line
	ENV
elif ! grep -q '^GRAPHQL=' "$register_env"; then
	echo "GRAPHQL=$graphql" >> "$register_env"
fi
if [ -z "${OPS_KMS_KEY:-}" ] && [ ! -f /etc/miso/ops.key ]; then
	(umask 077 && python3 -c 'import os; print(os.urandom(32).hex())' > /etc/miso/ops.key)
fi
systemctl daemon-reload
systemctl enable --now nitro-enclaves-allocator.service
systemctl enable audio-verifier-enclave.service argonaut.service audio-verifier-host.service \
	miso-enclave-register@audio-verifier.service
echo "Installed. Start with: systemctl start audio-verifier-enclave argonaut audio-verifier-host"
echo "Every start makes a new enclave key; miso-enclave-register@audio-verifier registers it with the"
echo "operations key (OPS_KMS_KEY or /etc/miso/ops.key), whose address needs $network SUI:"
echo "  miso-enclave-register --address"
