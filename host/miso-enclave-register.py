#!/usr/bin/env python3
"""Registers a running enclave's key on its Sui EnclavePolicy.

Fetches the enclave's public key and a fresh Nitro attestation through its host gateway, then
submits `0x2::nitro_attestation::load_nitro_attestation` and `enclave::register<App>` in one
transaction signed by the operations key, through Sui GraphQL. A key already registered at the
policy's current version is success; one registered at an older version is removed
(`remove_stale`) and registered again in the same transaction.

Needs Python 3.9+ and `cryptography`. The operations key file holds the 32-byte Ed25519 seed as
hex, readable only by root; the script prints the operations address, never the key.

    miso-enclave-register.py --env /etc/miso/<enclave>.register.env
    miso-enclave-register.py --ops-key /etc/miso/ops.key --address   # print the ops address
"""

import argparse
import base64
import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.request

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

GRAPHQL = "https://graphql.testnet.sui.io/graphql"
CLOCK = "0x" + "0" * 63 + "6"
GAS_BUDGET = 100_000_000
ALREADY_REGISTERED = 9


class Fatal(Exception):
    """A failure that retrying would repeat, such as a failed transaction."""


def uleb(n):
    out = bytearray()
    while True:
        byte = n & 0x7F
        n >>= 7
        if n:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def addr(hex_id):
    raw = hex_id[2:] if hex_id.startswith("0x") else hex_id
    return bytes.fromhex(raw.rjust(64, "0"))


def vec(data):
    return uleb(len(data)) + data


def string(s):
    return vec(s.encode())


def u64(n):
    return n.to_bytes(8, "little")


def type_tag(tag):
    """BCS TypeTag of a struct type `0xADDR::module::Name` (no type parameters)."""
    address, module, name = tag.split("::")
    return bytes([7]) + addr(address) + string(module) + string(name) + uleb(0)


def shared(object_id, initial_version, mutable):
    return bytes([1, 1]) + addr(object_id) + u64(initial_version) + bytes([1 if mutable else 0])


def move_call(package, module, function, type_args, args):
    out = bytes([0]) + addr(package) + string(module) + string(function)
    out += uleb(len(type_args)) + b"".join(type_tag(t) for t in type_args)
    out += uleb(len(args)) + b"".join(args)
    return out


def arg_input(i):
    return bytes([1]) + i.to_bytes(2, "little")


def arg_result(i):
    return bytes([2]) + i.to_bytes(2, "little")


def graphql(query, variables=None):
    body = json.dumps({"query": query, "variables": variables or {}}).encode()
    request = urllib.request.Request(
        GRAPHQL, data=body, headers={"content-type": "application/json"}
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        answer = json.load(response)
    if answer.get("errors"):
        raise RuntimeError(f"GraphQL: {answer['errors']}")
    return answer["data"]


def http_json(url, payload=None):
    data = None if payload is None else json.dumps(payload).encode()
    request = urllib.request.Request(url, data=data, headers={"content-type": "application/json"})
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)


def load_key(path):
    with open(path) as f:
        seed = bytes.fromhex(f.read().strip())
    key = Ed25519PrivateKey.from_private_bytes(seed)
    pk = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    address = "0x" + hashlib.blake2b(bytes([0]) + pk, digest_size=32).hexdigest()
    return key, pk, address


def policy_state(policy, enclave_package, pk):
    name = base64.b64encode(vec(pk)).decode()
    data = graphql(
        """query($id: SuiAddress!, $type: String!, $bcs: Base64!) {
          object(address: $id) {
            owner { ... on Shared { initialSharedVersion } }
            asMoveObject { contents { json }
              dynamicField(name: { type: $type, bcs: $bcs }) { value { ... on MoveValue { json } } } }
          }
        }""",
        {"id": policy, "type": f"{enclave_package}::enclave::EnclaveKey", "bcs": name},
    )["object"]
    version = int(data["asMoveObject"]["contents"]["json"]["version"])
    field = data["asMoveObject"]["dynamicField"]
    registered = None if field is None else int(field["value"]["json"])
    return int(data["owner"]["initialSharedVersion"]), version, registered


def gas_and_expiration(owner, price):
    """Pays from a SUI coin of at least the budget if the owner has one, else from the
    owner's address balance, which needs a `ValidDuring` expiration in the current epoch."""
    data = graphql(
        """query($owner: SuiAddress!) {
          chainIdentifier
          epoch { epochId }
          address(address: $owner) {
            objects(filter: { type: "0x2::coin::Coin<0x2::sui::SUI>" }, first: 50) {
              nodes { address version digest contents { json } }
            }
          }
        }""",
        {"owner": owner},
    )
    nodes = ((data["address"] or {}).get("objects") or {}).get("nodes", [])
    nodes = [n for n in nodes if int(n["contents"]["json"]["balance"]) >= GAS_BUDGET]
    owner_bytes = addr(owner)
    if nodes:
        best = max(nodes, key=lambda n: int(n["contents"]["json"]["balance"]))
        coin = addr(best["address"]) + u64(int(best["version"])) + vec(b58decode(best["digest"]))
        return uleb(1) + coin + owner_bytes + u64(price) + u64(GAS_BUDGET), bytes([0])
    epoch = int(data["epoch"]["epochId"])
    expiration = bytes([2]) + bytes([1]) + u64(epoch) + bytes([1]) + u64(epoch)
    expiration += bytes([0, 0]) + vec(b58decode(data["chainIdentifier"]))
    expiration += int.from_bytes(os.urandom(4), "little").to_bytes(4, "little")
    return uleb(0) + owner_bytes + u64(price) + u64(GAS_BUDGET), expiration


B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58decode(s):
    n = 0
    for c in s:
        n = n * 58 + B58.index(c)
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    pad = len(s) - len(s.lstrip("1"))
    return b"\x00" * pad + raw


def register(args):
    key, ops_pk, ops_address = load_key(args.ops_key)
    health = http_json(f"{args.gateway}/health")
    pk = bytes.fromhex(health["pk"])
    isv, version, registered = policy_state(args.policy, args.enclave_package, pk)
    if registered == version:
        print(f"[register] {health['pk']} already registered at version {version}")
        return
    attestation = bytes.fromhex(
        http_json(f"{args.gateway}/attest", {"nonce": os.urandom(32).hex()})["attestation"]
    )
    inputs = [
        bytes([0]) + vec(vec(attestation)),
        shared(CLOCK, 1, False),
        shared(args.policy, isv, True),
    ]
    commands = []
    if registered is not None:
        inputs.append(bytes([0]) + vec(vec(pk)))
        commands.append(
            move_call(args.enclave_package, "enclave", "remove_stale", [args.app],
                      [arg_input(2), arg_input(3)])
        )
    load = len(commands)
    commands.append(
        move_call("0x2", "nitro_attestation", "load_nitro_attestation", [],
                  [arg_input(0), arg_input(1)])
    )
    commands.append(
        move_call(args.enclave_package, "enclave", "register", [args.app],
                  [arg_input(2), arg_result(load)])
    )
    price = int(graphql("{ epoch { referenceGasPrice } }")["epoch"]["referenceGasPrice"])
    kind = bytes([0]) + uleb(len(inputs)) + b"".join(inputs)
    kind += uleb(len(commands)) + b"".join(commands)
    gas, expiration = gas_and_expiration(ops_address, price)
    tx = bytes([0]) + kind + addr(ops_address) + gas + expiration
    digest = hashlib.blake2b(bytes([0, 0, 0]) + tx, digest_size=32).digest()
    signature = bytes([0]) + key.sign(digest) + ops_pk
    result = graphql(
        """mutation($tx: Base64!, $sig: [Base64!]!) {
          executeTransaction(transactionDataBcs: $tx, signatures: $sig) {
            effects { digest status executionError { abortCode message } }
          }
        }""",
        {"tx": base64.b64encode(tx).decode(), "sig": [base64.b64encode(signature).decode()]},
    )["executeTransaction"]
    effects = result.get("effects") or {}
    if effects.get("status") == "SUCCESS":
        print(f"[register] {health['pk']} registered at version {version}: {effects['digest']}")
        return
    error = effects.get("executionError") or {}
    if str(error.get("abortCode")) == str(ALREADY_REGISTERED):
        print(f"[register] {health['pk']} was registered concurrently")
        return
    raise Fatal(f"registration failed: {result}")


def read_env(path):
    values = {}
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                name, _, value = line.partition("=")
                values[name.strip()] = value.strip()
    return values


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--env", help="file of GATEWAY, POLICY, APP, ENCLAVE_PACKAGE, OPS_KEY")
    parser.add_argument("--ops-key", default="/etc/miso/ops.key")
    parser.add_argument("--gateway")
    parser.add_argument("--policy")
    parser.add_argument("--app", help="the policy's App type, 0xADDR::module::NAME")
    parser.add_argument("--enclave-package")
    parser.add_argument("--address", action="store_true", help="print the ops address and exit")
    parser.add_argument("--wait-secs", type=int, default=600)
    args = parser.parse_args()
    if args.env:
        env = read_env(args.env)
        args.gateway = args.gateway or env.get("GATEWAY")
        args.policy = args.policy or env.get("POLICY")
        args.app = args.app or env.get("APP")
        args.enclave_package = args.enclave_package or env.get("ENCLAVE_PACKAGE")
        args.ops_key = env.get("OPS_KEY", args.ops_key)
    if args.address:
        print(load_key(args.ops_key)[2])
        return
    if not all([args.gateway, args.policy, args.app, args.enclave_package]):
        parser.error("GATEWAY, POLICY, APP and ENCLAVE_PACKAGE are required")
    deadline = time.monotonic() + args.wait_secs
    while True:
        try:
            register(args)
            return
        except (urllib.error.URLError, ConnectionError, TimeoutError, RuntimeError) as error:
            if time.monotonic() > deadline:
                print(f"[register] giving up: {error}", file=sys.stderr)
                sys.exit(1)
            print(f"[register] retrying: {error}", file=sys.stderr)
            time.sleep(10)
        except Fatal as error:
            print(f"[register] {error}", file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    main()
