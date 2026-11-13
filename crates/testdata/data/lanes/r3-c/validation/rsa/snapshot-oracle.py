"""Fresh supplied-CRL controls for the exact signed snapshot PDF; no networking."""
from pathlib import Path
from datetime import datetime
from io import BytesIO
from unittest.mock import patch
import hashlib,importlib.metadata,json,socket,sys
from asn1crypto import x509
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.validation import validate_pdf_signature
from pyhanko_certvalidator import ValidationContext

root=Path(sys.argv[1]).resolve()
metadata=json.loads((root/'snapshot-provenance.json').read_text())
network=[]
def deny_network(*args,**kwargs):
    network.append(repr(args[1:]))
    raise AssertionError('Network is forbidden for supplied snapshot evidence')
def snapshot(name):
    path=root/name;data=path.read_bytes()
    return data,{'path':str(path),'length':len(data),'sha256':hashlib.sha256(data).hexdigest()}
inputs={name:snapshot(name) for name in ['regular.pdf','root.der','crl-root.der','crl-interm.der','snapshot-revoked-leaf.crl.der']}
for name,(data,receipt) in inputs.items():
    assert receipt['sha256']==metadata['files'][name]['sha256']
    assert receipt['length']==metadata['files'][name]['length']
results=[]
with patch.object(socket.socket,'connect',deny_network),patch.object(socket.socket,'connect_ex',deny_network):
    for label,leaf_crl,expected in [('good','crl-interm.der',True),('revoked','snapshot-revoked-leaf.crl.der',False)]:
        context=ValidationContext(
            trust_roots=[x509.Certificate.load(inputs['root.der'][0])],
            moment=datetime.fromisoformat(metadata['moment']),
            crls=[inputs[leaf_crl][0],inputs['crl-root.der'][0]],
            allow_fetching=False,revocation_mode='require',
        )
        reader=PdfFileReader(BytesIO(inputs['regular.pdf'][0]))
        signatures=reader.embedded_regular_signatures
        assert len(signatures)==1
        status=validate_pdf_signature(signatures[0],signer_validation_context=context)
        assert status.intact and status.valid,status.pretty_print_details()
        assert status.bottom_line is expected,status.pretty_print_details()
        assert status.trusted is expected,status.pretty_print_details()
        results.append({'label':label,'intact':status.intact,'valid':status.valid,'trusted':status.trusted,'bottom_line':status.bottom_line,'revoked':status.revoked,'summary':status.summary(),'leaf_crl':leaf_crl})
assert not network,network
print(json.dumps({
    'scope':'Fresh public Python PDF validation with exact supplied signed CRLs; no CLI or native credit.',
    'python':sys.executable,'pyhanko_version':importlib.metadata.version('pyHanko'),
    'certvalidator_version':importlib.metadata.version('pyhanko-certvalidator'),
    'validation_module':sys.modules['pyhanko.sign.validation'].__file__,
    'certvalidator_module':sys.modules['pyhanko_certvalidator'].__file__,
    'script':str(Path(__file__).resolve()),'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    'moment':metadata['moment'],'inputs':{name:row for name,(_,row) in inputs.items()},
    'results':results,'network_calls':network,
}))
