"""Decrypts the enclave's ciphertexts with Google's Tink for Python, as AES256_GCM_HKDF_1MB keys
built from the raw DEK. Usage: python3 interop/tink_check.py <out-dir> <flac>"""

import io
import json
import pathlib
import sys

from tink import cleartext_keyset_handle, streaming_aead
from tink.proto import aes_gcm_hkdf_streaming_pb2, tink_pb2

out, flac = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
streaming_aead.register()
template = streaming_aead.streaming_aead_key_templates.AES256_GCM_HKDF_1MB
template_format = aes_gcm_hkdf_streaming_pb2.AesGcmHkdfStreamingKeyFormat.FromString(template.value)


def primitive(dek: bytes):
    key = aes_gcm_hkdf_streaming_pb2.AesGcmHkdfStreamingKey(
        version=0, params=template_format.params, key_value=dek
    )
    keyset = tink_pb2.Keyset(
        primary_key_id=1,
        key=[
            tink_pb2.Keyset.Key(
                key_data=tink_pb2.KeyData(
                    type_url=template.type_url,
                    value=key.SerializeToString(),
                    key_material_type=tink_pb2.KeyData.SYMMETRIC,
                ),
                status=tink_pb2.ENABLED,
                key_id=1,
                output_prefix_type=tink_pb2.RAW,
            )
        ],
    )
    handle = cleartext_keyset_handle.from_keyset(keyset)
    return handle.primitive(streaming_aead.StreamingAead)


def decrypt(dek: bytes, ciphertext: bytes) -> bytes:
    with primitive(dek).new_decrypting_stream(io.BytesIO(ciphertext), b"") as stream:
        return stream.read()


params = template_format.params
assert params.ciphertext_segment_size == 1 << 20 and params.derived_key_size == 32
kat = json.loads((out / "kat.json").read_text())
plain = decrypt(bytes.fromhex(kat["dek"]), (out / "kat.bin").read_bytes())
assert plain == bytes((i * 31 + 7) % 251 for i in range(kat["plaintext_len"]))
print("Tink: decrypted the known answer")
dek = bytes.fromhex((out / "test_dek.hex").read_text())
assert decrypt(dek, (out / "test_ciphertext.bin").read_bytes()) == flac.read_bytes()
print("Tink: decrypted the /measure ciphertext to the file")
