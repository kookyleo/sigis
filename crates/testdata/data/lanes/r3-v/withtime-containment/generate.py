"""Generate genuine signed PDF WithTime containment controls; ephemeral keys only."""
import asyncio,base64,hashlib,json,sys
from pathlib import Path
from datetime import datetime,timezone
from importlib import metadata
from cryptography import x509 as cx
from cryptography.x509.oid import NameOID,ExtendedKeyUsageOID,ObjectIdentifier
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import rsa,padding
from asn1crypto import x509,keys,crl,cms
from pyhanko.sign import signers,timestamps
from pyhanko_certvalidator.registry import SimpleCertificateStore
from freezegun import freeze_time

OUT=Path(__file__).parent; UTC=timezone.utc
DT=lambda s:datetime.fromisoformat(s.replace('Z','+00:00'))
SIGNED=DT('2020-08-01T00:00:00Z'); CURRENT=DT('2025-03-01T22:00:00Z')
def key():return rsa.generate_private_key(public_exponent=65537,key_size=2048)
def name(s):return cx.Name([cx.NameAttribute(NameOID.COMMON_NAME,s)])
def der(c):return c.public_bytes(serialization.Encoding.DER)
def ac(c):return x509.Certificate.load(der(c))
def ak(k):return keys.PrivateKeyInfo.load(k.private_bytes(serialization.Encoding.DER,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
def ku(ca=False,nr=False):return cx.KeyUsage(digital_signature=not ca,content_commitment=nr,key_encipherment=False,data_encipherment=False,key_agreement=False,key_cert_sign=ca,crl_sign=ca,encipher_only=None,decipher_only=None)
def cert(subject,k,issuer,ik,serial,ca=False,pathlen=None,leaf=False,nr=False,extra=(),wrongkey=None):
 b=cx.CertificateBuilder().subject_name(subject).issuer_name(issuer.subject if issuer else subject).public_key(k.public_key()).serial_number(serial).not_valid_before(DT('2020-01-01T00:00:00Z') if leaf else DT('2000-01-01T00:00:00Z')).not_valid_after(DT('2022-01-01T00:00:00Z') if leaf else DT('2035-01-01T00:00:00Z')).add_extension(cx.BasicConstraints(ca,pathlen),True).add_extension(ku(ca,nr),True).add_extension(cx.SubjectKeyIdentifier.from_public_key(k.public_key()),False).add_extension(cx.AuthorityKeyIdentifier.from_issuer_public_key((ik or k).public_key()),False)
 for e,critical in extra:b=b.add_extension(e,critical)
 return b.sign(wrongkey or ik or k,hashes.SHA256())
def write(name,b):
 (OUT/name).write_bytes(b);return dict(file=name,length=len(b),sha256=hashlib.sha256(b).hexdigest())
def crl_for(issuer,k,serial=None):
 b=cx.CertificateRevocationListBuilder().issuer_name(issuer.subject).last_update(DT('2021-01-01T00:00:00Z')).next_update(DT('2030-01-01T00:00:00Z')).add_extension(cx.AuthorityKeyIdentifier.from_issuer_public_key(k.public_key()),False).add_extension(cx.CRLNumber(1),False)
 if serial is not None:b=b.add_revoked_certificate(cx.RevokedCertificateBuilder().serial_number(serial).revocation_date(DT('2021-01-01T00:00:00Z')).add_extension(cx.CRLReason(cx.ReasonFlags.key_compromise),False).build())
 return b.sign(k,hashes.SHA256()).public_bytes(serialization.Encoding.DER)

from io import BytesIO
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign.fields import SigSeedSubFilter
class WrongImprintTimeStamper(timestamps.DummyTimeStamper):
 async def async_timestamp(self,message_digest,md_algorithm):
  altered=bytes([message_digest[0]^1])+message_digest[1:]
  return await super().async_timestamp(altered,md_algorithm)
async def main():
 assert __debug__ and metadata.version('pyhanko')=='0.38.1' and metadata.version('pyhanko-certvalidator')=='0.33.0'
 repo=next(p for p in OUT.parents if (p/'tools/cargo-locked.sh').exists())
 minimal=repo/'crates/testdata/data/pyhanko/pdf/minimal.pdf'
 raw=minimal.read_bytes()
 rk,ik,sk,lk,tk,wk=[key() for _ in range(6)]
 root=cert(name('WithTime containment root'),rk,None,None,1,True,4)
 base=cert(name('WithTime containment intermediate'),ik,root,rk,2,True,2)
 tsa=cert(name('WithTime containment TSA'),tk,root,rk,3,extra=[(cx.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]),True)])
 wrongtsa=cert(name('WithTime wrong-purpose TSA'),tk,root,rk,4,extra=[(cx.ExtendedKeyUsage([ExtendedKeyUsageOID.CODE_SIGNING]),True)])
 files=[write('root.der',der(root)),write('tsa.der',der(tsa)),write('wrong-purpose-tsa.der',der(wrongtsa))];cases=[]
 for index,label in enumerate(['good','path_length','bad_cert_signature','ds_only','name_constraints','unknown_critical','wrong_tsa_purpose','corrupt_imprint']):
  chain=[base];issuer=base;issuerkey=ik;extra=[]
  if label=='path_length':
   upper=cert(name('Zero path intermediate'),ik,root,rk,11,True,0)
   issuer=cert(name('Forbidden subordinate'),sk,upper,ik,12,True,0);issuerkey=sk;chain=[issuer,upper]
  if label=='name_constraints':
   issuer=cert(name('Constrained intermediate'),ik,root,rk,10,True,1,extra=[(cx.NameConstraints([cx.DNSName('allowed.example')],None),True)]);chain=[issuer];extra=[(cx.SubjectAlternativeName([cx.DNSName('outside.example')]),False)]
  if label=='unknown_critical':extra=[(cx.UnrecognizedExtension(ObjectIdentifier('1.2.3.4.500'),b'\x05\x00'),True)]
  leaf=cert(name('WithTime containment '+label),lk,issuer,issuerkey,100+index,leaf=True,nr=label!='ds_only',extra=extra,wrongkey=wk if label=='bad_cert_signature' else None)
  store=SimpleCertificateStore();store.register_multiple([ac(c) for c in chain]+[ac(root)])
  signer=signers.SimpleSigner(signing_cert=ac(leaf),signing_key=ak(lk),cert_registry=store)
  tsstore=SimpleCertificateStore();tsstore.register(ac(root))
  stampclass=WrongImprintTimeStamper if label=='corrupt_imprint' else timestamps.DummyTimeStamper
  stamp=stampclass(ac(wrongtsa if label=='wrong_tsa_purpose' else tsa),ak(tk),certs_to_embed=tsstore,fixed_dt=SIGNED)
  with freeze_time(SIGNED):
   pdfsigner=signers.PdfSigner(signers.PdfSignatureMetadata(field_name='Signature1',md_algorithm='sha256',subfilter=SigSeedSubFilter.PADES),signer,timestamper=stamp)
   output=await pdfsigner.async_sign_pdf(IncrementalPdfFileWriter(BytesIO(raw)))
  pdfname=label+'.pdf';leafname=label+'.der';chainnames=[]
  files.extend([write(pdfname,output.getvalue()),write(leafname,der(leaf))])
  for j,c in enumerate(chain):
   cn=f'{label}-issuer{j}.der';files.append(write(cn,der(c)));chainnames.append(cn)
  cases.append({'id':label,'file':pdfname,'signer':leafname,'other_certs':chainnames,'signed_at':SIGNED.isoformat(),'key_usage':['non_repudiation'],'revocation':'none','intended_invalid':label!='good','tsa':'wrong-purpose-tsa.der' if label=='wrong_tsa_purpose' else 'tsa.der','timestamp_imprint_expected_valid':label!='corrupt_imprint'})
 manifest={'unique_upstream_credit':0,'generated_by':'generate.py genuine cryptography certificate signatures, pinned PdfSigner and DummyTimeStamper','signed_at':SIGNED.isoformat(),'current_validation_time':'2021-06-01T00:00:00+00:00','expired_validation_time':CURRENT.isoformat(),'root':'root.der','tsa':'tsa.der','field_name':'Signature1','cases':cases,'files':files,'input_origin':{'path':str(minimal),'sha256':hashlib.sha256(raw).hexdigest(),'length':len(raw)},'versions':{n:metadata.version(n) for n in ['pyhanko','pyhanko-certvalidator','cryptography','asn1crypto']},'assertions_enabled':__debug__,'no_private_keys_persisted':True}
 (OUT/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
 print(json.dumps({'cases':len(cases),'files':len(files),'manifest_sha256':hashlib.sha256((OUT/'manifest.json').read_bytes()).hexdigest()}))
asyncio.run(main())
