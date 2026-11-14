"""Create one NEW private Ed25519 test token from exact original fixture inputs.

No key is generated or exported from a token. This script is test support and
must run in a fresh process before the software module is first initialized.
"""
from __future__ import annotations
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import subprocess
import sys

MODULE_SHA = "8453e1bde7dac7a24ed1bab11786fa8641a0ff2b4093c5f027ceaf368a7a438d"
UTILITY_SHA = "dbe84fb38af1cbcaf58fcea71b0d00753b0eb8480b517a1a4dd98f9ee95dfdb3"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def identity(path):
    path = Path(path).resolve()
    data = path.read_bytes()
    return dict(path=str(path), length=len(data), sha256=digest(data))


def main():
    assert __debug__ and sys.flags.optimize == 0
    if len(sys.argv) != 2:
        raise SystemExit("Usage: provision_signing.py ABSOLUTE_NEW_PROVIDER_DIRECTORY")
    root = Path(sys.argv[1])
    assert root.is_absolute() and not root.exists(), "Never reuse a token directory"
    root.mkdir(mode=0o700, parents=True)
    tokens = root / "tokens"
    tokens.mkdir(mode=0o700)
    conf = root / "softhsm2.conf"
    conf.write_text(f"directories.tokendir = {tokens}\nobjectstore.backend = file\nlog.level = ERROR\nslots.removable = false\n")
    module = Path(os.environ.get("SIGIS_PKCS11_SIGNING_MODULE", "/tmp/sigis-p-softhsm-8453e1bde7da/libsofthsm2.so")).resolve()
    utility = Path(os.environ.get("SIGIS_PKCS11_SIGNING_UTILITY", "/tmp/sigis-p-softhsm-8453e1bde7da/softhsm2-util")).resolve()
    overlay = Path(os.environ["SIGIS_PKCS11_ORACLE_OVERLAY"]).resolve()
    before = dict(module=identity(module), utility=identity(utility))
    assert before["module"]["sha256"] == MODULE_SHA
    assert before["utility"]["sha256"] == UTILITY_SHA
    command = [str(utility), "--module", str(module), "--init-token", "--free", "--label", "tested25519", "--pin", "1234", "--so-pin", "5678"]
    result = subprocess.run(command, env=dict(os.environ, SOFTHSM2_CONF=str(conf)), capture_output=True, check=False)
    (root / "utility.stdout.bin").write_bytes(result.stdout)
    (root / "utility.stderr.bin").write_bytes(result.stderr)
    assert result.returncode == 0, "Real isolated token initialization failed"
    # Child-only environment, before the first import/initialization of a module.
    os.environ["SOFTHSM2_CONF"] = str(conf)
    import pkcs11
    from pkcs11 import Attribute, KeyType, Mechanism, ObjectClass
    from pkcs11.util.x509 import decode_x509_certificate
    from asn1crypto import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    assert Path(pkcs11.__file__).resolve().is_relative_to(overlay)
    assert importlib.metadata.version("python-pkcs11") == "0.9.5"
    fixture = Path(__file__).resolve().parent
    manifest = json.loads((fixture / "inputs.json").read_text())
    certs = {}
    for item in manifest["certificates"]:
        data = (fixture / item["file"]).read_bytes()
        assert digest(data) == item["sha256"]
        certs[item["label"]] = (data, x509.Certificate.load(data, strict=True))
    key_input = fixture / manifest["private_key_input"]["file"]
    key_bytes = key_input.read_bytes()
    assert digest(key_bytes) == manifest["private_key_input"]["sha256"]
    key = serialization.load_pem_private_key(key_bytes, password=None)
    assert isinstance(key, Ed25519PrivateKey), "Only the original Ed25519 key is assigned"
    public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    assert public == certs["signer1"][1].public_key["public_key"].native, "Original key and signer certificate must match"
    seed = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    library = pkcs11.lib(str(module))
    token = library.get_token(token_label="tested25519")
    mechanisms = token.slot.get_mechanisms()
    assert Mechanism.EDDSA in mechanisms, "Actual original fixture requires EDDSA"
    certificate_rows = []
    with token.open(rw=True, user_pin="1234") as session:
        for item in manifest["certificates"]:
            raw, parsed = certs[item["label"]]
            attrs = decode_x509_certificate(raw)
            attrs.update({Attribute.TOKEN: True, Attribute.LABEL: item["label"], Attribute.ID: item["label"].encode("ascii")})
            obj = session.create_object(attrs)
            assert obj[Attribute.VALUE] == raw and obj[Attribute.TOKEN]
            certificate_rows.append(dict(label=item["label"], input=identity(fixture / item["file"]), readback_sha256=digest(obj[Attribute.VALUE]), subject=parsed.subject.human_friendly))
        # Same mature PKCS11 attributes used by the accepted native test fixture.
        # VALUE is the input PKCS8 seed; it is never read from the created object.
        key_attributes = {Attribute.CLASS: ObjectClass.PRIVATE_KEY, Attribute.KEY_TYPE: KeyType.EC_EDWARDS,
                          Attribute.TOKEN: True, Attribute.PRIVATE: True, Attribute.SENSITIVE: True,
                          Attribute.EXTRACTABLE: False, Attribute.SIGN: True, Attribute.LABEL: "signer1",
                          Attribute.ID: b"signer1", Attribute.EC_PARAMS: bytes.fromhex("06032b6570"), Attribute.VALUE: seed}
        created = session.create_object(key_attributes)
        assert created[Attribute.CLASS] == ObjectClass.PRIVATE_KEY
        assert created[Attribute.KEY_TYPE] == KeyType.EC_EDWARDS and created[Attribute.SIGN]
        assert created[Attribute.TOKEN] and created[Attribute.PRIVATE]
        assert not created[Attribute.EXTRACTABLE] and created[Attribute.SENSITIVE]
        inventory = list(session.get_objects())
        classes = [obj[Attribute.CLASS] for obj in inventory]
        assert len(inventory) == 4 and classes.count(ObjectClass.CERTIFICATE) == 3 and classes.count(ObjectClass.PRIVATE_KEY) == 1
        for item in manifest["certificates"]:
            found = list(session.get_objects({Attribute.CLASS: ObjectClass.CERTIFICATE, Attribute.LABEL: item["label"]}))
            assert len(found) == 1
            raw = found[0][Attribute.VALUE]
            x509.Certificate.load(raw, strict=True)
            assert digest(raw) == item["sha256"] and found[0][Attribute.TOKEN]
        private = list(session.get_objects({Attribute.CLASS: ObjectClass.PRIVATE_KEY, Attribute.SIGN: True, Attribute.LABEL: "signer1"}))
        assert len(private) == 1
    assert before == dict(module=identity(module), utility=identity(utility))
    maps = Path("/proc/self/maps").read_text()
    (root / "loaded-maps.txt").write_text(maps)
    mapped = []
    for name in sorted({line.split(maxsplit=5)[-1] for line in maps.splitlines() if len(line.split(maxsplit=5)) == 6 and line.split(maxsplit=5)[-1].startswith("/")}):
        p = Path(name)
        if p.exists() and ".so" in p.name:
            mapped.append(identity(p))
    record = dict(kind="Original Ed25519 key/certificate import into a NEW isolated real SoftHSM token", host=platform.node(),
                  interpreter=identity(sys.executable), python=sys.version, assertions_enabled=__debug__, overlay=str(overlay),
                  binding=identity(pkcs11.__file__), module_utility_before_after=before, configuration=identity(conf), token_label="tested25519",
                  # Known public fixture PINs are deliberately not included in diagnostic text.
                  utility_command=command, utility_exit_code=result.returncode,
                  utility_stdout=identity(root / "utility.stdout.bin"), utility_stderr=identity(root / "utility.stderr.bin"),
                  certificates=certificate_rows, original_private_key_input=identity(key_input), signer_public_key_sha256=digest(public),
                  private_key_object=dict(label="signer1", object_class="PRIVATE_KEY", key_type="EC_EDWARDS", token=True, private=True, sign=True, sensitive=True, extractable=False),
                  private_value_readback=False, replacement_key_generation_calls=0, signing_calls=0, inventory_count=4,
                  actual_EDDSA_available=True, actual_advertised_mechanisms=sorted(int(m) for m in mechanisms), loaded_dso_files=mapped)
    (root / "receipt.json").write_text(json.dumps(record, indent=2) + "\n")
    print(json.dumps(dict(receipt=str(root / "receipt.json"), sha256=identity(root / "receipt.json")["sha256"], object_count=4)))


if __name__ == "__main__":
    main()
