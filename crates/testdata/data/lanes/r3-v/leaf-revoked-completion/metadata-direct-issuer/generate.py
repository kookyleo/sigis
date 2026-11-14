"""Genuine actual issuer GOOD OCSP and raw signature-bitflip control.

No copied-signature proxy/fake issuer certificate is used. The original actual
Good full CertID/status remains intact; the real intermediate signs its own
response and embeds its exact actual certificate under ResponderID.byName.
"""
import argparse, asyncio, hashlib, importlib.metadata, inspect, json, sys
from pathlib import Path
from datetime import datetime,timezone
from asn1crypto import ocsp,x509
from cryptography import x509 as cx
from cryptography.exceptions import InvalidSignature
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
import pyhanko_certvalidator.revinfo.validate_ocsp as reference_ocsp
H=lambda b:hashlib.sha256(b).hexdigest()
NOW='2020-12-25T00:00:00Z'
def rec(path):
 p=Path(path).resolve();b=p.read_bytes();return {'path':str(p),'length':len(b),'sha256':H(b)}
def main():
 p=argparse.ArgumentParser();p.add_argument('--fixture-root',type=Path,default=Path(__file__).resolve().parent.parent);p.add_argument('--out',type=Path,default=Path(__file__).resolve().parent);p.add_argument('--receipt-dir',type=Path,required=True);a=p.parse_args()
 assert __debug__ and importlib.metadata.version('pyhanko')=='0.38.1' and importlib.metadata.version('pyhanko-certvalidator')=='0.33.0'
 a.fixture_root=a.fixture_root.resolve();a.out=a.out.resolve();a.out.mkdir(parents=True,exist_ok=True);a.receipt_dir=a.receipt_dir.resolve();a.receipt_dir.mkdir(parents=True,exist_ok=True)
 arch=CERTOMANCER.get_pki_arch(ArchLabel('testing-ca'));issuer=arch.get_cert('interm');leaf=arch.get_cert('signer1');key=serialization.load_der_private_key(arch.key_set.get_private_key('interm').dump(),None);public=cx.load_der_x509_certificate(issuer.dump()).public_key();files=[]
 def write(name,b):
  p=a.out/name
  if p.exists():assert p.read_bytes()==b,('different immutable postimage',p)
  else:p.write_bytes(b)
  files.append({'file':name,'length':len(b),'sha256':H(b)});return b
 for label in ['root','interm','signer1']:write(f'cert-{label}.der',arch.get_cert(label).dump())
 original_path=a.fixture_root/'2020-12-25/ocsp-signer1.der';source=ocsp.OCSPResponse.load(original_path.read_bytes());basic=source['response_bytes']['response'].parsed.copy();original_id=basic['tbs_response_data']['responses'][0]['cert_id'].dump();single=basic['tbs_response_data']['responses'][0]
 assert single['cert_status'].name=='good' and single['cert_id']['issuer_name_hash'].native==issuer.subject.sha1 and single['cert_id']['issuer_key_hash'].native==issuer.public_key.sha1 and single['cert_id']['serial_number'].native==leaf.serial_number
 basic['tbs_response_data']['responder_id']=ocsp.ResponderId({'by_name':issuer.subject})
 basic['certs']=[issuer]
 tbs=basic['tbs_response_data'].dump(force=True);basic['signature']=key.sign(tbs,padding.PKCS1v15(),hashes.SHA256());direct=source.copy();direct['response_bytes']['response']=basic;direct_raw=write('actual-direct-issuer-good.ocsp.der',direct.dump(force=True));parsed=ocsp.OCSPResponse.load(direct_raw)['response_bytes']['response'].parsed
 assert parsed['certs'][0].dump()==issuer.dump()
 assert parsed['tbs_response_data']['responder_id'].name=='by_name' and parsed['tbs_response_data']['responder_id'].chosen.untag().dump()==issuer.subject.dump()
 assert parsed['tbs_response_data']['responses'][0]['cert_id'].dump()==original_id
 public.verify(parsed['signature'].native,parsed['tbs_response_data'].dump(),padding.PKCS1v15(),hashes.SHA256())
 bad=direct.copy();bb=bad['response_bytes']['response'].parsed.copy();sig=bytearray(bb['signature'].native);sig[0]^=1;bb['signature']=bytes(sig);bad['response_bytes']['response']=bb;bad_raw=write('actual-direct-issuer-bad-raw-signature.ocsp.der',bad.dump(force=True));bp=ocsp.OCSPResponse.load(bad_raw)['response_bytes']['response'].parsed
 assert bp['tbs_response_data'].dump()==parsed['tbs_response_data'].dump() and bp['certs'][0].dump()==issuer.dump()
 try:public.verify(bp['signature'].native,bp['tbs_response_data'].dump(),padding.PKCS1v15(),hashes.SHA256())
 except InvalidSignature:pass
 else:raise AssertionError('actual direct issuer raw signature bitflip must refuse')
 root_path=a.fixture_root/'2020-12-25/crl-root.der';write('root-good.crl.der',root_path.read_bytes())
 controls={'actual_embedded_issuer_der_exact':True,'responder_by_name_matches_actual_issuer':True,'original_full_certid_and_good_status_preserved':True,'actual_issuer_key_signature_valid':True,'bad_raw_signature_invalid':True,'bad_raw_signature_same_tbs_and_certificate':True}
 manifest={'scope':'Actual direct issuer authority positive/negative; tests-first, no native','current_time':NOW,'files':files,'crypto_controls':controls,'source_inputs':[rec(original_path),rec(root_path)],'versions':{n:importlib.metadata.version(n) for n in ['pyhanko','pyhanko-certvalidator','cryptography','asn1crypto','certomancer']},'assertions_enabled':__debug__,'private_keys_written':False,'provider_exclusions':[]}
 (a.out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
 async def oracle():
  root=x509.Certificate.load((a.out/'cert-root.der').read_bytes());interm=x509.Certificate.load((a.out/'cert-interm.der').read_bytes());target=x509.Certificate.load((a.out/'cert-signer1.der').read_bytes());result=[]
  for file,expected in [('actual-direct-issuer-good.ocsp.der',True),('actual-direct-issuer-bad-raw-signature.ocsp.der',False)]:
   policy=CertRevTrustPolicy(RevocationCheckingPolicy(RevocationCheckingRule.OCSP_REQUIRED,RevocationCheckingRule.CRL_REQUIRED),freshness_req_type=FreshnessReqType.MAX_DIFF_REVOCATION_VALIDATION)
   ctx=ValidationContext(trust_roots=[root],other_certs=[interm],crls=[(a.out/'root-good.crl.der').read_bytes()],ocsps=[(a.out/file).read_bytes()],allow_fetching=False,revinfo_policy=policy);path=ValidationPath(trust_anchor=CertTrustAnchor(root),interm=[interm],leaf=target)
   row={'input':rec(a.out/file),'observed_current_time':datetime.now(timezone.utc).isoformat(),'validation_time':NOW,'point_in_time_validation':ctx.timing_params.point_in_time_validation}
   try:await async_validate_path(ctx,path);row.update(accepted=True,exception=None)
   except Exception as e:row.update(accepted=False,exception={'class':type(e).__name__,'message':str(e)})
   result.append(row);(a.receipt_dir/'reference-progress.json').write_text(json.dumps(result,indent=2)+'\n');assert row['accepted']==expected,row
  return result
 with freeze_time(NOW):results=asyncio.run(oracle())
 receipt={'scope':'Fresh SAME direct-issuer bytes public pinned path; no native/Cargo','interpreter':rec(sys.executable),'python':sys.version,'generator':rec(__file__),'manifest':rec(a.out/'manifest.json'),'modules':[rec(inspect.getfile(m)) for m in [reference_ocsp,ocsp,cx]],'versions':manifest['versions'],'assertions_enabled':__debug__,'crypto_controls':controls,'reference_calls':len(results),'cases':results,'native_calls':0,'cargo_calls':0,'network_calls':0,'provider_exclusions':[]}
 (a.receipt_dir/'generation-and-reference.json').write_text(json.dumps(receipt,indent=2)+'\n');print(json.dumps({'files':len(files),'reference_calls':len(results),'cases':results,'manifest':rec(a.out/'manifest.json')}))
if __name__=='__main__':main()
