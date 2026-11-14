"""Provision only the two genuine certificate objects in a NEW SoftHSM store.

This is test support, not a provider replacement or signing path. Run in a fresh
child process with the isolated python-pkcs11 overlay selected before import.
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


def identity(path: Path) -> dict:
    path = path.resolve()
    data = path.read_bytes()
    return {"path": str(path), "length": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("Usage: provision_certificates.py ABSOLUTE_NEW_PROVIDER_DIRECTORY")
    root = Path(sys.argv[1])
    assert root.is_absolute() and not root.exists(), "Never reuse a provider/token directory"
    root.mkdir(mode=0o700, parents=True)
    tokens = root / "tokens"
    tokens.mkdir(mode=0o700)
    conf = root / "softhsm2.conf"
    conf.write_text(f"directories.tokendir = {tokens}\nobjectstore.backend = file\nlog.level = ERROR\nslots.removable = false\n")
    module = Path(os.environ.get("SIGIS_PKCS11_PREFLIGHT_MODULE", "/tmp/sigis-p-softhsm-8453e1bde7da/libsofthsm2.so")).resolve()
    utility = Path(os.environ.get("SIGIS_PKCS11_PREFLIGHT_UTILITY", "/tmp/sigis-p-softhsm-8453e1bde7da/softhsm2-util")).resolve()
    overlay = Path(os.environ["SIGIS_PKCS11_ORACLE_OVERLAY"]).resolve()
    before = {"module": identity(module), "utility": identity(utility)}
    assert before["module"]["sha256"] == "8453e1bde7dac7a24ed1bab11786fa8641a0ff2b4093c5f027ceaf368a7a438d"
    assert before["utility"]["sha256"] == "dbe84fb38af1cbcaf58fcea71b0d00753b0eb8480b517a1a4dd98f9ee95dfdb3"
    command = [str(utility), "--module", str(module), "--init-token", "--free", "--label", "testrsa", "--pin", "1234", "--so-pin", "5678"]
    env = dict(os.environ, SOFTHSM2_CONF=str(conf))
    result = subprocess.run(command, env=env, capture_output=True, check=False)
    (root / "utility.stdout").write_bytes(result.stdout)
    (root / "utility.stderr").write_bytes(result.stderr)
    assert result.returncode == 0, "Certificate-only token initialization failed"
    # This child has never loaded a provider. Scope its setting before import and
    # first C_Initialize; no parent or unrelated process environment is mutated.
    os.environ["SOFTHSM2_CONF"] = str(conf)
    import pkcs11
    from pkcs11 import Attribute, ObjectClass
    from pkcs11.util.x509 import decode_x509_certificate
    from asn1crypto import x509
    assert Path(pkcs11.__file__).resolve().is_relative_to(overlay)
    assert importlib.metadata.version("python-pkcs11") == "0.9.5"
    assert __debug__ and sys.flags.optimize == 0
    library = pkcs11.lib(str(module))
    token = library.get_token(token_label="testrsa")
    rows = []
    fixture_root = Path(__file__).resolve().parent
    manifest = json.loads((fixture_root / "certificates.json").read_text())
    with token.open(rw=True, user_pin="1234") as session:
        for cert in manifest["certificates"]:
            raw = (fixture_root / cert["der"]).read_bytes()
            assert hashlib.sha256(raw).hexdigest() == cert["der_sha256"]
            parsed = x509.Certificate.load(raw, strict=True)
            attrs = decode_x509_certificate(raw)
            attrs.update({Attribute.TOKEN: True, Attribute.LABEL: cert["label"], Attribute.ID: cert["label"].encode("ascii")})
            created = session.create_object(attrs)
            assert created[Attribute.VALUE] == raw
            rows.append({"label": cert["label"], "source": identity(fixture_root / cert["der"]), "subject": parsed.subject.human_friendly, "created_value_sha256": hashlib.sha256(created[Attribute.VALUE]).hexdigest()})
        found = list(session.get_objects())
        assert len(found) == 2 and all(obj[Attribute.CLASS] == ObjectClass.CERTIFICATE for obj in found), "Only certificate objects may exist"
        for row in rows:
            matches = list(session.get_objects({Attribute.CLASS: ObjectClass.CERTIFICATE, Attribute.LABEL: row["label"]}))
            assert len(matches) == 1
            raw = matches[0][Attribute.VALUE]
            x509.Certificate.load(raw, strict=True)
            assert hashlib.sha256(raw).hexdigest() == row["source"]["sha256"]
            row["retrieved_value_sha256"] = hashlib.sha256(raw).hexdigest()
            row["token_attribute"] = bool(matches[0][Attribute.TOKEN])
            assert row["token_attribute"]
    assert before == {"module": identity(module), "utility": identity(utility)}
    maps = Path("/proc/self/maps").read_text()
    (root / "loaded-maps.txt").write_text(maps)
    loaded = []
    for name in sorted({line.split(maxsplit=5)[-1] for line in maps.splitlines() if len(line.split(maxsplit=5)) == 6 and line.split(maxsplit=5)[-1].startswith("/")}):
        p = Path(name)
        if p.exists() and (".so" in p.name or p == module):
            loaded.append(identity(p))
    record = {"kind": "real certificate-only SoftHSM fixture provisioning", "hostname": platform.node(), "interpreter": identity(Path(sys.executable)), "python": sys.version, "assertions_enabled": __debug__, "overlay": str(overlay), "binding": identity(Path(pkcs11.__file__)), "module_utility_before_after": before, "command": command, "utility_exit_code": result.returncode, "utility_stdout": identity(root / "utility.stdout"), "utility_stderr": identity(root / "utility.stderr"), "environment": {"SOFTHSM2_CONF": str(conf)}, "configuration": identity(conf), "certificates": rows, "object_count": 2, "private_key_objects_created": 0, "key_generation_calls": 0, "signing_calls": 0, "loaded_dso_files": loaded}
    (root / "receipt.json").write_text(json.dumps(record, indent=2) + "\n")
    print(json.dumps({"receipt": str(root / "receipt.json"), "sha256": identity(root / "receipt.json")["sha256"], "certificate_objects": 2}))


if __name__ == "__main__":
    main()
