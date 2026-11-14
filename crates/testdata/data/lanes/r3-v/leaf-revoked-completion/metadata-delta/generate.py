"""Authentic complete base+selected-delta dependency, not a lone delta marker.

The base predates Bob's real Dec1 revocation, covers all reasons and requires
its named delta. The actual intermediate key signs both. The delta carries
the real KeyCompromise event and is selected by matching issuer/AKI/IDP,
baseCRLNumber100 and CRLNumber101. All native verdicts remain unexecuted here.
"""
import argparse, asyncio, hashlib, importlib.metadata, inspect, json, sys
from pathlib import Path
from datetime import datetime, timezone
from asn1crypto import crl, x509
from cryptography import x509 as cx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
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
import pyhanko_certvalidator.revinfo.validate_crl as reference_crl
H=lambda b:hashlib.sha256(b).hexdigest()
NOW='2020-12-25T00:00:00Z'
def rec(p):
 p=Path(p).resolve();b=p.read_bytes();return {'path':str(p),'length':len(b),'sha256':H(b)}
def main():
 p=argparse.ArgumentParser();p.add_argument('--fixture-root',type=Path,default=Path(__file__).resolve().parent.parent);p.add_argument('--out',type=Path,default=Path(__file__).resolve().parent);p.add_argument('--receipt-dir',type=Path,required=True);a=p.parse_args()
 assert __debug__ and importlib.metadata.version('pyhanko')=='0.38.1' and importlib.metadata.version('pyhanko-certvalidator')=='0.33.0'
 a.out=a.out.resolve();a.out.mkdir(parents=True,exist_ok=True);a.receipt_dir=a.receipt_dir.resolve();a.receipt_dir.mkdir(parents=True,exist_ok=True)
 arch=CERTOMANCER.get_pki_arch(ArchLabel('testing-ca'));key=serialization.load_der_private_key(arch.key_set.get_private_key('interm').dump(),None);issuer=arch.get_cert('interm');public=cx.load_der_x509_certificate(issuer.dump()).public_key()
 original_path=a.fixture_root/'2020-12-25/crl-interm.der';original=crl.CertificateList.load(original_path.read_bytes());files=[]
 def write(name,b):
  p=a.out/name
  if p.exists():assert p.read_bytes()==b,('different immutable fixture',p)
  else:p.write_bytes(b)
  files.append({'file':name,'length':len(b),'sha256':H(b)})
 def sign(value):
  tbs=value['tbs_cert_list'].dump(force=True);value['signature']=key.sign(tbs,padding.PKCS1v15(),hashes.SHA256());raw=value.dump(force=True);p=crl.CertificateList.load(raw);public.verify(p['signature'].native,p['tbs_cert_list'].dump(),padding.PKCS1v15(),hashes.SHA256());return raw
 for name in ['root','interm','signer1','signer2']:write(f'cert-{name}.der',arch.get_cert(name).dump())
 write('root-good.crl.der',(a.fixture_root/'2020-12-25/crl-root.der').read_bytes())
 base=original.copy();t=base['tbs_cert_list'];t['this_update']={'utc_time':'201120000000Z'};t['next_update']={'utc_time':'210110000000Z'};t['revoked_certificates']=None
 for ext in t['crl_extensions']:
  if ext['extn_id'].native=='crl_number':ext['extn_value']=100
 t['crl_extensions'].append(crl.TBSCertListExtension({'extn_id':'freshest_crl','critical':False,'extn_value':x509.CRLDistributionPoints([x509.DistributionPoint({'distribution_point':x509.DistributionPointName({'full_name':x509.GeneralNames([x509.GeneralName({'uniform_resource_identifier':'http://pyhanko.tests/testing-ca/crls/interm/selected.delta.crl'})])})})])}))
 base_raw=sign(base);write('base-number100-before-revocation.crl.der',base_raw)
 delta=original.copy();dt=delta['tbs_cert_list'];dt['this_update']={'utc_time':'201225000000Z'};dt['next_update']={'utc_time':'201226000000Z'}
 for ext in dt['crl_extensions']:
  if ext['extn_id'].native=='crl_number':ext['extn_value']=101
 dt['crl_extensions'].append(crl.TBSCertListExtension({'extn_id':'delta_crl_indicator','critical':True,'extn_value':100}))
 delta_raw=sign(delta);write('selected-delta-number101-key-compromise.crl.der',delta_raw)
 bp=crl.CertificateList.load(base_raw);dp=crl.CertificateList.load(delta_raw)
 def ext(value,oid):return next(e['extn_value'].parsed for e in value['tbs_cert_list']['crl_extensions'] if e['extn_id'].native==oid)
 assert bp['tbs_cert_list']['issuer'].dump()==dp['tbs_cert_list']['issuer'].dump()==issuer.subject.dump()
 assert ext(bp,'authority_key_identifier').dump()==ext(dp,'authority_key_identifier').dump()
 assert ext(bp,'issuing_distribution_point').dump()==ext(dp,'issuing_distribution_point').dump()
 assert ext(bp,'crl_number').native==ext(dp,'delta_crl_indicator').native==100
 assert ext(dp,'crl_number').native==101
 assert bp['tbs_cert_list']['revoked_certificates'].native is None
 entry=dp['tbs_cert_list']['revoked_certificates'][0];assert entry['user_certificate'].native==arch.get_cert('signer2').serial_number and entry['revocation_date'].native==datetime(2020,12,1,tzinfo=timezone.utc)
 assert entry['crl_entry_extensions'][0]['extn_id'].native=='crl_reason' and entry['crl_entry_extensions'][0]['extn_value'].native=='key_compromise'
 bad=delta.copy();sig=bytearray(bad['signature'].native);sig[0]^=1;bad['signature']=bytes(sig);bad_raw=bad.dump(force=True);write('selected-delta-bad-raw-signature.crl.der',bad_raw)
 badp=crl.CertificateList.load(bad_raw);assert badp['tbs_cert_list'].dump()==dp['tbs_cert_list'].dump()
 try:public.verify(badp['signature'].native,badp['tbs_cert_list'].dump(),padding.PKCS1v15(),hashes.SHA256())
 except InvalidSignature:pass
 else:raise AssertionError('bad selected delta signature control failed')
 controls={'base_signature_valid':True,'delta_signature_valid':True,'bad_delta_signature_invalid':True,'bad_delta_same_tbs':True,'matching_issuer_aki_idp':True,'matching_base_number100_delta_number101':True,'base_contains_no_target_revocation':True,'delta_contains_actual_signer2_dec1_key_compromise':True}
 manifest={'scope':'Real base+selected signed delta dependency; tests-first, no native','current_time':NOW,'files':files,'crypto_and_selection_controls':controls,'source_inputs':[rec(original_path),rec(a.fixture_root/'2020-12-25/crl-root.der')],'versions':{n:importlib.metadata.version(n) for n in ['pyhanko','pyhanko-certvalidator','cryptography','asn1crypto','certomancer']},'assertions_enabled':__debug__,'private_keys_written':False,'provider_exclusions':[]}
 (a.out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
 async def oracle():
  root=x509.Certificate.load((a.out/'cert-root.der').read_bytes());interm=x509.Certificate.load((a.out/'cert-interm.der').read_bytes());result=[]
  cases=[('missing-selected-delta','signer2',None,False),('selected-delta-real-revocation','signer2','selected-delta-number101-key-compromise.crl.der',False),('genuinely-good-signer1-selected-delta','signer1','selected-delta-number101-key-compromise.crl.der',True),('bad-selected-delta-signature','signer2','selected-delta-bad-raw-signature.crl.der',False)]
  for name,label,delta_name,expected in cases:
   target=x509.Certificate.load((a.out/f'cert-{label}.der').read_bytes());policy=CertRevTrustPolicy(RevocationCheckingPolicy(RevocationCheckingRule.CRL_REQUIRED,RevocationCheckingRule.CRL_REQUIRED),freshness_req_type=FreshnessReqType.MAX_DIFF_REVOCATION_VALIDATION)
   materials=[(a.out/'root-good.crl.der').read_bytes(),base_raw]+([] if delta_name is None else [(a.out/delta_name).read_bytes()])
   ctx=ValidationContext(trust_roots=[root],other_certs=[interm],crls=materials,ocsps=[],allow_fetching=False,revinfo_policy=policy)
   path=ValidationPath(trust_anchor=CertTrustAnchor(root),interm=[interm],leaf=target);row={'case':name,'target':rec(a.out/f'cert-{label}.der'),'input_crls':[rec(a.out/n) for n in ['root-good.crl.der','base-number100-before-revocation.crl.der']+([] if delta_name is None else [delta_name])],'validation_time':NOW,'observed_current_time':datetime.now(timezone.utc).isoformat(),'point_in_time_validation':ctx.timing_params.point_in_time_validation}
   try:await async_validate_path(ctx,path);row.update(accepted=True,exception=None)
   except Exception as e:row.update(accepted=False,exception={'class':type(e).__name__,'message':str(e)})
   result.append(row);(a.receipt_dir/'reference-progress.json').write_text(json.dumps(result,indent=2)+'\n');assert row['accepted']==expected,row
  return result
 with freeze_time(NOW):results=asyncio.run(oracle())
 receipt={'scope':'Fresh same-byte supplied base+delta public pinned path validation; no native/Cargo','interpreter':rec(sys.executable),'python':sys.version,'generator':rec(__file__),'manifest':rec(a.out/'manifest.json'),'modules':[rec(inspect.getfile(m)) for m in [reference_crl,crl,cx]],'versions':manifest['versions'],'assertions_enabled':__debug__,'crypto_and_selection_controls':controls,'reference_calls':len(results),'cases':results,'network_calls':0,'native_calls':0,'cargo_calls':0,'provider_exclusions':[]}
 (a.receipt_dir/'generation-and-reference.json').write_text(json.dumps(receipt,indent=2)+'\n');print(json.dumps({'files':len(files),'reference_calls':len(results),'cases':results,'manifest':rec(a.out/'manifest.json')}))
if __name__=='__main__':main()
