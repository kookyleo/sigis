"""Export pinned pyHanko test PKI material for CLI signing assertion ports."""
from pathlib import Path
from asn1crypto import pem
from certomancer.registry import CertLabel, KeyLabel
from cryptography.hazmat.primitives import serialization
from pyhanko_testing_commons.test_data.samples import TESTING_CA, TESTING_CA_ECDSA, TESTING_CA_ED25519, TESTING_CA_ED448
base = Path(__file__).parent
for name, arch in [("rsa", TESTING_CA), ("ecdsa", TESTING_CA_ECDSA), ("ed25519", TESTING_CA_ED25519), ("ed448", TESTING_CA_ED448)]:
    p = base / name
    p.mkdir(exist_ok=True)
    for label, filename in [("root", "root.pem"), ("interm", "interm.pem"), ("signer1", "cert.pem")]:
        (p / filename).write_bytes(pem.armor("CERTIFICATE", arch.get_cert(CertLabel(label)).dump()))
    key = serialization.load_der_private_key(arch.key_set.get_private_key(KeyLabel("signer1")).dump(), None)
    for filename, encryption in [("key.pem", serialization.NoEncryption()), ("encrypted-key.pem", serialization.BestAvailableEncryption(b"secret"))]:
        (p / filename).write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, encryption))
    (p / "signer.p12").write_bytes(arch.package_pkcs12(CertLabel("signer1"), password=b"secret"))
    (p / "plain.p12").write_bytes(arch.package_pkcs12(CertLabel("signer1")))
from pyhanko_testing_commons.test_data.samples import MINIMAL_SLIGHTLY_BROKEN,MINIMAL_HYBRID,MINIMAL_ONE_FIELD,MINIMAL_AES256,MINIMAL_PUBKEY_AES256
for name,data in [('mildly-broken.pdf',MINIMAL_SLIGHTLY_BROKEN),('hybrid.pdf',MINIMAL_HYBRID),('one-field.pdf',MINIMAL_ONE_FIELD),('password-encrypted.pdf',MINIMAL_AES256),('pubkey-encrypted.pdf',MINIMAL_PUBKEY_AES256)]:
    (base/name).write_bytes(data)
