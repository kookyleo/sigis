"""Real root-signed temporal path-bound counterexamples, tests-first data only.

Only notBefore changes to Nov15. Root signatures are genuinely recomputed;
issuer/subject/SPKI/SKI/serial/purpose/extensions and notAfter stay unchanged.
No CMS/TST/status/provider/POE is constructed by this producer. Parent native
callers must bind these exact certs to actual generated signature/token bytes.
"""
import argparse, asyncio, hashlib, importlib.metadata, inspect, json, sys
from pathlib import Path
from datetime import datetime,timezone
from asn1crypto import x509,ocsp
from cryptography import x509 as cx
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import padding
from freezegun import freeze_time
PINNED=Path('/tmp/pyhanko-oracle/src/v0.38.1')
sys.path[:0]=[str(PINNED/'pkgs/pyhanko'),str(PINNED/'pkgs/pyhanko/src'),str(PINNED/'internal/common-test-utils/src')]
from certomancer.registry import ArchLabel
from pyhanko_testing_commons.test_data.samples import CERTOMANCER
from pyhanko_certvalidator import ValidationContext
from pyhanko_certvalidator.authority import CertTrustAnchor
from pyhanko_certvalidator.path import ValidationPath
from pyhanko_certvalidator.policy_decl import CertRevTrustPolicy,FreshnessReqType,RevocationCheckingPolicy,RevocationCheckingRule
from pyhanko_certvalidator.validate import async_validate_path
import pyhanko_certvalidator.validate as reference_validate
H=lambda b:hashlib.sha256(b).hexdigest()
SIGNED='2020-11-01T00:00:00Z';CURRENT='2020-12-25T00:00:00Z';NEW_NOT_BEFORE='2020-11-15T00:00:00Z'
def rec(path):
 p=Path(path).resolve();b=p.read_bytes();return {'path':str(p),'length':len(b),'sha256':H(b)}
def extension(cert,oid):
 return next(e.dump() for e in cert['tbs_certificate']['extensions'] if e['extn_id'].native==oid)
def main():
 p=argparse.ArgumentParser();p.add_argument('--fixture-root',type=Path,default=Path(__file__).resolve().parent.parent);p.add_argument('--out',type=Path,default=Path(__file__).resolve().parent);p.add_argument('--receipt-dir',type=Path,required=True);a=p.parse_args();assert __debug__ and importlib.metadata.version('pyhanko')=='0.38.1' and importlib.metadata.version('pyhanko-certvalidator')=='0.33.0'
 a.fixture_root=a.fixture_root.resolve();a.out=a.out.resolve();a.out.mkdir(parents=True,exist_ok=True);a.receipt_dir=a.receipt_dir.resolve();a.receipt_dir.mkdir(parents=True,exist_ok=True)
 arch=CERTOMANCER.get_pki_arch(ArchLabel('testing-ca'));root=arch.get_cert('root');root_key=serialization.load_der_private_key(arch.key_set.get_private_key('root').dump(),None);root_public=cx.load_der_x509_certificate(root.dump()).public_key();files=[];crypto=[]
 def write(name,data):
  path=a.out/name;path.parent.mkdir(parents=True,exist_ok=True)
  if path.exists():assert path.read_bytes()==data,('different immutable bytes',path)
  else:path.write_bytes(data)
  files.append({'file':name,'length':len(data),'sha256':H(data)});return data
 for label in ['root','interm','signer2','tsa']:write(f'cert-{label}-original.der',arch.get_cert(label).dump())
 for label in ['interm','tsa']:
  original=arch.get_cert(label);modified=original.copy();modified['tbs_certificate']['validity']['not_before']=x509.Time({'utc_time':'201115000000Z'});tbs=modified['tbs_certificate'].dump(force=True);modified['signature_value']=root_key.sign(tbs,padding.PKCS1v15(),hashes.SHA256());raw=write(f'cert-{label}-not-before-nov15.der',modified.dump(force=True));parsed=x509.Certificate.load(raw)
  root_public.verify(parsed['signature_value'].native,parsed['tbs_certificate'].dump(),padding.PKCS1v15(),hashes.SHA256())
  assert parsed.issuer.dump()==original.issuer.dump() and parsed.subject.dump()==original.subject.dump() and parsed.serial_number==original.serial_number
  assert parsed.public_key.dump()==original.public_key.dump() and extension(parsed,'key_identifier')==extension(original,'key_identifier')
  assert parsed['tbs_certificate']['extensions'].dump()==original['tbs_certificate']['extensions'].dump()
  assert parsed['tbs_certificate']['validity']['not_after'].dump()==original['tbs_certificate']['validity']['not_after'].dump()
  assert parsed['signature_algorithm'].dump()==original['signature_algorithm'].dump() and parsed['tbs_certificate']['signature'].dump()==original['tbs_certificate']['signature'].dump()
  assert parsed['tbs_certificate']['validity']['not_before'].native==datetime(2020,11,15,tzinfo=timezone.utc)
  # Remove only changed validity and outer signature to verify no accidental
  # unrelated field rewrite in the reissued certificate.
  expected=parsed['tbs_certificate'].copy();expected['validity']=original['tbs_certificate']['validity'].copy();assert expected.dump(force=True)==original['tbs_certificate'].dump(force=True)
  crypto.append({'cert':f'cert-{label}-not-before-nov15.der','real_root_signature_valid':True,'original_issuer_subject_spki_ski_serial_extensions_notafter_preserved':True,'only_notbefore_changed_in_tbs':True,'not_before':NEW_NOT_BEFORE})
 for date in ['2020-11-01','2020-12-25']:
  for name in ['crl-root.der','ocsp-signer2.der']:write(f'{date}/{name}',(a.fixture_root/date/name).read_bytes())
 # Existing real leaf signature still verifies with the same intermediate
 # public key, while full CertID remains exactly keyed to that real issuer.
 bob=x509.Certificate.load((a.out/'cert-signer2-original.der').read_bytes());new_inter=x509.Certificate.load((a.out/'cert-interm-not-before-nov15.der').read_bytes());issuer_public=cx.load_der_x509_certificate(new_inter.dump()).public_key();issuer_public.verify(bob['signature_value'].native,bob['tbs_certificate'].dump(),padding.PKCS1v15(),hashes.SHA256())
 for date in ['2020-11-01','2020-12-25']:
  single=ocsp.OCSPResponse.load((a.out/date/'ocsp-signer2.der').read_bytes())['response_bytes']['response'].parsed['tbs_response_data']['responses'][0];cid=single['cert_id'];assert cid['issuer_name_hash'].native==new_inter.subject.sha1 and cid['issuer_key_hash'].native==new_inter.public_key.sha1 and cid['serial_number'].native==bob.serial_number
 manifest={'scope':'Only genuine root-signed certificate time-bound data + fresh public path diagnostics; no CMS/TST/native','signed_time':SIGNED,'current_validation_time':CURRENT,'modified_not_before':NEW_NOT_BEFORE,'files':files,'crypto_controls':crypto,'actual_bob_signature_still_valid_under_same_modified_intermediate_key':True,'both_ocsp_full_certids_still_bind_real_same_issuer_and_bob':True,'architecture':'testing-ca','actual_certificate_signing_key_label':'root','private_keys_written':False,'versions':{n:importlib.metadata.version(n) for n in ['pyhanko','pyhanko-certvalidator','cryptography','asn1crypto','certomancer']},'assertions_enabled':__debug__,'provider_exclusions':[],'limits':['No new TST or CMS is generated here','No signed TL/service boundary is supplied; unsupported service eligibility must remain closed','No context retiming or ordinary policy alteration is proposed']}
 (a.out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
 async def run_case(role,variant,at):
  root=x509.Certificate.load((a.out/'cert-root-original.der').read_bytes());leaf=x509.Certificate.load((a.out/('cert-signer2-original.der' if role=='main' else f'cert-tsa-{variant}.der')).read_bytes());inter=x509.Certificate.load((a.out/f'cert-interm-{variant}.der').read_bytes()) if role=='main' else None
  date=at[:10];policy=CertRevTrustPolicy(RevocationCheckingPolicy(RevocationCheckingRule.CRL_OR_OCSP_REQUIRED if role=='main' else RevocationCheckingRule.CRL_REQUIRED,RevocationCheckingRule.CRL_REQUIRED),freshness_req_type=FreshnessReqType.MAX_DIFF_REVOCATION_VALIDATION)
  ctx=ValidationContext(trust_roots=[root],other_certs=[] if inter is None else [inter],crls=[(a.out/date/'crl-root.der').read_bytes()],ocsps=[] if role=='tsa' else [(a.out/date/'ocsp-signer2.der').read_bytes()],allow_fetching=False,revinfo_policy=policy)
  path=ValidationPath(trust_anchor=CertTrustAnchor(root),interm=[] if inter is None else [inter],leaf=leaf);row={'role':role,'variant':variant,'validation_time':at,'observed_current_time':datetime.now(timezone.utc).isoformat(),'point_in_time_validation':ctx.timing_params.point_in_time_validation,'target_sha256':H(leaf.dump()),'intermediate_sha256':None if inter is None else H(inter.dump()),'evidence_date':date,'input_crls':[rec(a.out/date/'crl-root.der')],'input_ocsps':[] if role=='tsa' else [rec(a.out/date/'ocsp-signer2.der')]}
  try:await async_validate_path(ctx,path);row.update(accepted=True,exception=None)
  except Exception as e:row.update(accepted=False,exception={'class':type(e).__name__,'message':str(e)})
  if variant=='not-before-nov15' and at==SIGNED:assert not row['accepted'] and row['exception']['class']=='NotYetValidError',row
  elif role=='main' and at==CURRENT:assert not row['accepted'] and row['exception']['class']=='RevokedError',row
  else:assert row['accepted'],row
  return row
 results=[]
 for at in [SIGNED,CURRENT]:
  for role in ['main','tsa']:
   for variant in ['original','not-before-nov15']:
    with freeze_time(at):row=asyncio.run(run_case(role,variant,at))
    results.append(row);(a.receipt_dir/'reference-progress.json').write_text(json.dumps(results,indent=2)+'\n')
 receipt={'scope':'Fresh same-byte ordinary public pinned path comparison only; not new temporal resolution/native evidence','interpreter':rec(sys.executable),'python':sys.version,'generator':rec(__file__),'manifest':rec(a.out/'manifest.json'),'module_sources':[rec(inspect.getfile(m)) for m in [reference_validate,x509,cx]],'versions':manifest['versions'],'assertions_enabled':__debug__,'crypto_controls':crypto,'reference_calls':len(results),'cases':results,'network_calls':0,'native_calls':0,'cargo_calls':0,'provider_exclusions':[]}
 (a.receipt_dir/'generation-and-reference.json').write_text(json.dumps(receipt,indent=2)+'\n');print(json.dumps({'files':len(files),'reference_calls':len(results),'cases':results,'manifest':rec(a.out/'manifest.json')}))
if __name__=='__main__':main()
