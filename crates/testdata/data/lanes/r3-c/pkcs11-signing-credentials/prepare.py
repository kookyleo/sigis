"""Provision a new RSA AlwaysAuthenticate fixture; never reuse an old store.

This software-provider supplemental is not a SafeNet hardware original port.
The only private material imported is the pinned original signer1 RSA key.
"""
from __future__ import annotations

import importlib.metadata
import os
from pathlib import Path
import subprocess
import sys


def main():
    assert __debug__
    assert len(sys.argv) == 2
    root = Path(sys.argv[1])
    assert root.is_absolute() and not root.exists(), "Never reuse a token store"
    tokens = root / "provider" / "tokens"
    tokens.mkdir(parents=True, mode=0o700)
    conf = root / "provider" / "softhsm2.conf"
    conf.write_text(f"directories.tokendir = {tokens}\nobjectstore.backend = file\nlog.level = ERROR\nslots.removable = false\n")
    module = os.environ.get("SIGIS_PKCS11_SIGNING_MODULE", "/tmp/sigis-p-softhsm-8453e1bde7da/libsofthsm2.so")
    utility = os.environ.get("SIGIS_PKCS11_SIGNING_UTILITY", "/tmp/sigis-p-softhsm-8453e1bde7da/softhsm2-util")
    for name in ("PYHANKO_PKCS11_PIN", "PYHANKO_PKCS11_SIGNING_PIN", "PKCS11_CONFIG"):
        os.environ.pop(name, None)
    os.environ["SOFTHSM2_CONF"] = str(conf)
    result = subprocess.run([utility, "--module", module, "--init-token", "--free",
                             "--label", "testrsa", "--pin", "1234", "--so-pin", "5678"],
                            stdin=subprocess.DEVNULL, capture_output=True)
    assert result.returncode == 0, "Cannot initialize private software token"

    import pkcs11
    from pkcs11 import Attribute, Mechanism, ObjectClass
    from pkcs11.util.rsa import decode_rsa_private_key
    from pkcs11.util.x509 import decode_x509_certificate
    from certomancer.registry import CertLabel, KeyLabel
    from cryptography.hazmat.primitives import serialization
    from pyhanko_testing_commons.test_data import samples

    assert importlib.metadata.version("python-pkcs11") == "0.9.5"
    arch = samples.TESTING_CA
    key = serialization.load_der_private_key(
        arch.key_set.get_private_key(KeyLabel("signer1")).dump(), password=None)
    certs = {label: arch.get_cert(CertLabel(label)) for label in ("root", "interm", "signer1")}
    assert key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo) == certs["signer1"].public_key.dump()
    cert_dir = root / "rsa"
    cert_dir.mkdir()
    token = pkcs11.lib(module).get_token(token_label="testrsa")
    assert Mechanism.SHA256_RSA_PKCS in token.slot.get_mechanisms()
    with token.open(rw=True, user_pin="1234") as session:
        for label, cert in certs.items():
            raw = cert.dump()
            (cert_dir / f"{label}.der").write_bytes(raw)
            attrs = decode_x509_certificate(raw)
            attrs.update({Attribute.TOKEN: True, Attribute.LABEL: label, Attribute.ID: label.encode()})
            obj = session.create_object(attrs)
            assert obj[Attribute.TOKEN] and obj[Attribute.VALUE] == raw
        attrs = decode_rsa_private_key(key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
        attrs.update({Attribute.TOKEN: True, Attribute.PRIVATE: True, Attribute.SENSITIVE: True,
                      Attribute.EXTRACTABLE: False, Attribute.SIGN: True,
                      Attribute.ALWAYS_AUTHENTICATE: True,
                      Attribute.LABEL: "signer1", Attribute.ID: b"signer1"})
        obj = session.create_object(attrs)
        assert obj[Attribute.CLASS] == ObjectClass.PRIVATE_KEY
        assert obj[Attribute.TOKEN] and obj[Attribute.SIGN] and obj[Attribute.ALWAYS_AUTHENTICATE]
        assert obj[Attribute.SENSITIVE] and not obj[Attribute.EXTRACTABLE]
        assert len(list(session.get_objects({Attribute.CLASS: ObjectClass.PRIVATE_KEY, Attribute.LABEL: "signer1"}))) == 1
        for label, cert in certs.items():
            objects = list(session.get_objects({Attribute.CLASS: ObjectClass.CERTIFICATE, Attribute.LABEL: label}))
            assert len(objects) == 1 and objects[0][Attribute.VALUE] == cert.dump()
    print("Private RSA software fixture: original signer1, TOKEN and ALWAYS_AUTHENTICATE true; nonextractable key")
    print("Original root/interm/signer1 certificates read back; SHA256_RSA_PKCS available")
    print("Software user/context-specific PINs coincide; no SafeNet hardware equivalence claimed")


if __name__ == "__main__":
    main()
