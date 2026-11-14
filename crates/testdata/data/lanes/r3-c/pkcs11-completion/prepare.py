"""Prepare a new private SoftHSM store from the pinned original fixture keys.

Usage: pinned-python prepare.py ABSOLUTE_NEW_DIRECTORY
No provider is loaded until this explicit program is run. The parent must let
this process exit before initializing a provider in a native test process.
"""
from __future__ import annotations

import importlib.metadata
import os
from pathlib import Path
import subprocess
import sys


def main():
    assert __debug__
    if len(sys.argv) != 2:
        raise SystemExit("Usage: prepare.py ABSOLUTE_NEW_DIRECTORY")
    root = Path(sys.argv[1])
    assert root.is_absolute() and not root.exists(), "Never reuse an old token store"
    provider = root / "provider"
    tokens = provider / "tokens"
    tokens.mkdir(parents=True, mode=0o700)
    conf = provider / "softhsm2.conf"
    conf.write_text(f"directories.tokendir = {tokens}\nobjectstore.backend = file\nlog.level = ERROR\nslots.removable = false\n")
    module = os.environ.get("SIGIS_PKCS11_SIGNING_MODULE", "/tmp/sigis-p-softhsm-8453e1bde7da/libsofthsm2.so")
    utility = os.environ.get("SIGIS_PKCS11_SIGNING_UTILITY", "/tmp/sigis-p-softhsm-8453e1bde7da/softhsm2-util")
    for name in ["PYHANKO_PKCS11_PIN", "PYHANKO_PKCS11_SIGNING_PIN", "PKCS11_CONFIG"]:
        os.environ.pop(name, None)
    os.environ["SOFTHSM2_CONF"] = str(conf)
    for algo in ["rsa", "ecdsa", "ed25519", "ed448", "mldsa"]:
        result = subprocess.run([utility, "--module", module, "--init-token", "--free",
                                 "--label", f"test{algo}", "--pin", "1234", "--so-pin", "5678"],
                                stdin=subprocess.DEVNULL, capture_output=True)
        assert result.returncode == 0, f"Cannot initialize private test{algo} token: {result.stderr.decode()}"

    import pkcs11
    from pkcs11 import Attribute, KeyType, Mechanism, ObjectClass
    from pkcs11.util.ec import decode_ec_private_key
    from pkcs11.util.rsa import decode_rsa_private_key
    from pkcs11.util.x509 import decode_x509_certificate
    from certomancer.registry import CertLabel, KeyLabel
    from cryptography.hazmat.primitives import serialization
    from pyhanko_testing_commons.test_data import samples

    assert importlib.metadata.version("python-pkcs11") == "0.9.5"
    architectures = {"rsa": samples.TESTING_CA, "ecdsa": samples.TESTING_CA_ECDSA,
                     "ed25519": samples.TESTING_CA_ED25519, "ed448": samples.TESTING_CA_ED448}
    library = pkcs11.lib(module)
    lines = []
    for algo, arch in architectures.items():
        dest = root / algo
        dest.mkdir()
        token = library.get_token(token_label=f"test{algo}")
        mechanisms = token.slot.get_mechanisms()
        required = {"rsa": Mechanism.SHA256_RSA_PKCS, "ecdsa": Mechanism.ECDSA_SHA256,
                    "ed25519": Mechanism.EDDSA, "ed448": Mechanism.EDDSA}[algo]
        lines.append(f"{algo} required={required} available={required in mechanisms}")
        key_info = arch.key_set.get_private_key(KeyLabel("signer1"))
        key = serialization.load_der_private_key(key_info.dump(), password=None)
        certs = {label: arch.get_cert(CertLabel(label)) for label in ["root", "interm", "signer1"]}
        public = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        assert public == certs["signer1"].public_key.dump(), "Original signer key/certificate mismatch"
        with token.open(rw=True, user_pin="1234") as session:
            for label, cert in certs.items():
                raw = cert.dump()
                (dest / f"{label}.der").write_bytes(raw)
                attrs = decode_x509_certificate(raw)
                attrs.update({Attribute.TOKEN: True, Attribute.LABEL: label, Attribute.ID: label.encode()})
                obj = session.create_object(attrs)
                assert obj[Attribute.VALUE] == raw and obj[Attribute.TOKEN]
            if algo == "rsa":
                attrs = decode_rsa_private_key(key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
            elif algo == "ecdsa":
                attrs = decode_ec_private_key(key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
            else:
                attrs = {Attribute.CLASS: ObjectClass.PRIVATE_KEY, Attribute.KEY_TYPE: KeyType.EC_EDWARDS,
                         Attribute.EC_PARAMS: bytes.fromhex("06032b6570" if algo == "ed25519" else "06032b6571"),
                         Attribute.VALUE: key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())}
            attrs.update({Attribute.TOKEN: True, Attribute.PRIVATE: True, Attribute.SENSITIVE: True,
                          Attribute.EXTRACTABLE: False, Attribute.SIGN: True, Attribute.LABEL: "signer1", Attribute.ID: b"signer1"})
            private = session.create_object(attrs)
            assert private[Attribute.CLASS] == ObjectClass.PRIVATE_KEY and private[Attribute.SIGN]
            assert private[Attribute.SENSITIVE] and not private[Attribute.EXTRACTABLE]
            for label, cert in certs.items():
                objects = list(session.get_objects({Attribute.CLASS: ObjectClass.CERTIFICATE, Attribute.LABEL: label}))
                assert len(objects) == 1 and objects[0][Attribute.VALUE] == cert.dump()
            assert len(list(session.get_objects({Attribute.CLASS: ObjectClass.PRIVATE_KEY, Attribute.LABEL: "signer1"}))) == 1
        print(f"Imported original {algo} signer1 and root/interm/signer1 token certificates")
    mldsa = library.get_token(token_label="testmldsa")
    supported = Mechanism.ML_DSA in mldsa.slot.get_mechanisms()
    assert not supported, "Fixture must be extended with the original ML-DSA key if the provider gains support"
    lines.append("mldsa required=ML_DSA available=False; upstream fixture performs real login then skips missing mechanism")
    (root / "available.txt").write_text("\n".join(lines) + "\n")
    print("\n".join(lines))
    print(f"Provider configuration: {conf}")


if __name__ == "__main__":
    main()
