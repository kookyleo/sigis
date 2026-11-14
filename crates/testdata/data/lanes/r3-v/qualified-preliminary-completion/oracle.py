"""Fresh pinned diagnostics on newly genuinely signed adversarial CMS bytes."""
import argparse,asyncio,dataclasses,hashlib,inspect,json,sys,traceback
from pathlib import Path
from datetime import datetime,timezone
from importlib import metadata
from asn1crypto import cms,x509,crl,tsp
from cryptography import x509 as cx
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from freezegun import freeze_time
from pyhanko.sign.validation import ades,generic_cms
from pyhanko.sign.validation.settings import KeyUsageConstraints
from pyhanko.sign.validation.status import StandardCMSSignatureStatus,TimestampSignatureStatus
from pyhanko.sign.validation.policy_decl import SignatureValidationSpec,LocalKnowledge,RevocationInfoGatheringSpec,RevinfoOnlineFetchingRule,CertificateFetchingRule,bootstrap_validation_data_handlers
from pyhanko_certvalidator.context import CertValidationPolicySpec
from pyhanko_certvalidator.policy_decl import CertRevTrustPolicy,NO_REVOCATION,REQUIRE_REVINFO,PKIXValidationParams
from pyhanko_certvalidator.registry import SimpleTrustManager
from pyhanko_certvalidator.revinfo.archival import CRLContainer
from pyhanko_certvalidator.ltv.types import ValidationTimingInfo

BASE=Path(__file__).parent
DT=lambda s:datetime.fromisoformat(s.replace('Z','+00:00'))
def rec(path):
 p=Path(path).resolve();b=p.read_bytes();return {'path':str(p),'length':len(b),'sha256':hashlib.sha256(b).hexdigest()}
def value(v):
 if v is None or isinstance(v,(str,bool,int)):return v
 if isinstance(v,datetime):return v.isoformat()
 if hasattr(v,'name'):return v.name
 return str(v)
def api(s):
 if s is None:return None
 p=getattr(s,'validation_path',None)
 return {'intact':s.intact,'valid':s.valid,'trusted':s.trusted,'bottom_line':getattr(s,'bottom_line',None),'trust_problem_indic':value(getattr(s,'trust_problem_indic',None)),'error_time_horizon':value(getattr(s,'error_time_horizon',None)),'validation_time':value(getattr(s,'validation_time',None)),'path':None if p is None else [hashlib.sha256(c.dump()).hexdigest() for c in p],'timestamp_validity':api(s.timestamp_validity) if getattr(s,'timestamp_validity',None) else None}
def result(s):return {'ades_subindic':s.ades_subindic.name,'api':api(s.api_status),'best_signature_time':value(getattr(s,'best_signature_time',None)),'failure_msg':s.failure_msg}
async def main(out):
 assert __debug__ and metadata.version('pyhanko')=='0.38.1' and metadata.version('pyhanko-certvalidator')=='0.33.0'
 manifest=json.loads((BASE/'manifest.json').read_text());root=x509.Certificate.load((BASE/manifest['root']).read_bytes());raw=(BASE/manifest['content']).read_bytes();digest=hashlib.sha256(raw).digest();rows=[];tsa_controls=[];crypto_controls=[]
 for f in manifest['files']:
  assert rec(BASE/f['file'])['sha256']==f['sha256'] and rec(BASE/f['file'])['length']==f['length']
 for c in manifest['cases']:
  sd=cms.ContentInfo.load((BASE/c['cms']).read_bytes())['content'];leaf=x509.Certificate.load((BASE/c['signer']).read_bytes());signed=DT(c['signed_at']);current=DT(c['validation_time'])
  params=PKIXValidationParams(user_initial_policy_set=frozenset([c['required_policy']]),initial_explicit_policy=True) if c['required_policy'] else None
  policy=CertValidationPolicySpec(trust_manager=SimpleTrustManager.build(trust_roots=[root]),revinfo_policy=CertRevTrustPolicy(REQUIRE_REVINFO if c['revocation']=='require' else NO_REVOCATION),pkix_validation_params=params)
  knowledge=LocalKnowledge(known_certs=[x509.Certificate.load((BASE/p).read_bytes()) for p in c['other_certs']],known_crls=[CRLContainer(crl.CertificateList.load((BASE/p).read_bytes())) for p in c.get('crls',[])])
  spec=SignatureValidationSpec(cert_validation_policy=policy,key_usage_settings=KeyUsageConstraints(key_usage={'non_repudiation'}),local_knowledge=knowledge,revinfo_gathering_policy=RevocationInfoGatheringSpec(online_fetching_rule=RevinfoOnlineFetchingRule.LOCAL_ONLY,certificate_fetching_rule=CertificateFetchingRule.NEVER_FETCH))
  si=sd['signer_infos'][0]
  ts=next(generic_cms.extract_tst_data_iter(si,signed=False))
  l=cx.load_der_x509_certificate((BASE/c['signer']).read_bytes());t=cx.load_der_x509_certificate((BASE/'tsa.der').read_bytes())
  l.public_key().verify(si['signature'].native,si['signed_attrs'].untag().dump(),padding.PKCS1v15(),hashes.SHA256())
  tsi=ts['signer_infos'][0]
  t.public_key().verify(tsi['signature'].native,tsi['signed_attrs'].untag().dump(),padding.PKCS1v15(),hashes.SHA256())
  info=ts['encap_content_info']['content'].parsed
  assert info['message_imprint']['hashed_message'].native==hashlib.sha256(si['signature'].native).digest()
  crypto_controls.append(dict(case=c['id'],main_signature_valid=True,timestamp_signature_valid=True,imprint_binding=True,timestamp_gen_time=info['gen_time'].native.isoformat()))
  tt=ValidationTimingInfo(current,current,point_in_time_validation=True)
  hh=bootstrap_validation_data_handlers(spec,timing_info=tt);tc=policy.build_validation_context(timing_info=tt,handlers=hh)
  tv=TimestampSignatureStatus(**(await generic_cms.validate_tst_signed_data(ts,tc,lambda alg:hashlib.new(alg,si['signature'].native).digest())))
  assert tv.intact and tv.valid and tv.trusted,(c['id'],api(tv))
  assert tv.timestamp==signed
  tsa_controls.append(dict(case=c['id'],validation_time=current.isoformat(),actual_approved_best=tv.timestamp.isoformat(),status=api(tv)))
  for label,at,best in [('current',current,current),('current_with_authenticated_best',current,tv.timestamp),('explicit_historical_control',signed,signed)]:
   timing=ValidationTimingInfo(at,best,point_in_time_validation=True)
   row={'case':c['id'],'timing_profile':label,'validation_time':at.isoformat(),'best_signature_time':best.isoformat(),'input':rec(BASE/c['cms']),'signer':rec(BASE/c['signer']),'same_policy_identity_across_timing_variants':True,'policy_required':c['required_policy'],'revocation':c['revocation'],'apis':{}}
   try:
    handlers=bootstrap_validation_data_handlers(spec,timing_info=timing);ctx=policy.build_validation_context(timing_info=timing,handlers=handlers)
    status=await generic_cms.cms_basic_validation(sd,raw_digest=digest,validation_context=ctx,pkix_validation_params=params,key_usage_settings=spec.key_usage_settings)
    row['apis']['cms']=api(StandardCMSSignatureStatus(**status))
   except Exception as e:row['apis']['cms']={'exception':type(e).__name__,'message':str(e),'traceback':traceback.format_exc()}
   try:
    status=await ades.ades_with_time_validation(sd,spec,timing_info=timing,raw_digest=digest)
    row['apis']['with_time']=result(status)
   except Exception as e:row['apis']['with_time']={'exception':type(e).__name__,'message':str(e),'traceback':traceback.format_exc()}
   assert 'exception' not in row['apis']['cms'] and 'exception' not in row['apis']['with_time'],row
   assert row['apis']['cms']['intact'] and row['apis']['cms']['valid'],row
   expected_good = c['id']=='good' and label=='explicit_historical_control'
   if expected_good: assert row['apis']['cms']['trusted'] and row['apis']['with_time']['api']['trusted'],row
   if c['id'] in ['name_constraints','unknown_critical','ds_only'] and label!='explicit_historical_control':
    assert not row['apis']['cms']['trusted'] and row['apis']['with_time']['ades_subindic']=='OK' and row['apis']['with_time']['api']['trusted'],row
   if c['id'] in ['name_constraints','unknown_critical','ds_only'] and label=='explicit_historical_control':
    assert not row['apis']['cms']['trusted'] and not row['apis']['with_time']['api']['trusted'],row
   if c['id'] in ['path_length','bad_cert_signature']:assert not row['apis']['cms']['trusted'] and not row['apis']['with_time']['api']['trusted'],row
   if c['id'].startswith('revoked') and label!='explicit_historical_control':
    assert row['apis']['cms']['trust_problem_indic']=='REVOKED_NO_POE' and row['apis']['with_time']['api']['trusted'],row
   rows.append(row)
 modules=[inspect.getfile(ades),inspect.getfile(generic_cms),inspect.getfile(CertValidationPolicySpec),inspect.getfile(KeyUsageConstraints)]
 output={'scope':'Fresh diagnostic only. No production fix or new original function credit. True historical controls do not assert material POE.','assertions_enabled':__debug__,'interpreter':rec(sys.executable),'executable':sys.executable,'versions':{n:metadata.version(n) for n in ['pyhanko','pyhanko-certvalidator','cryptography']},'module_receipts':[rec(p) for p in modules],'producer':rec(BASE/'generate.py'),'runner':rec(__file__),'manifest':rec(BASE/'manifest.json'),'network_requests':0,'provider_exclusions':[],'api_calls':len(rows)*2+len(tsa_controls),'main_api_calls':len(rows)*2,'separate_fixed_tsa_calls':len(tsa_controls),'crypto_controls':crypto_controls,'tsa_controls':tsa_controls,'cases':rows}
 Path(out).write_text(json.dumps(output,indent=2)+'\n');print(json.dumps({'rows':len(rows),'api_calls':len(rows)*2+len(tsa_controls),'exceptions':sum('exception' in a for r in rows for a in r['apis'].values()),'output':rec(out)}))
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--output',required=True);a=p.parse_args()
 with freeze_time('2025-03-01T22:00:00Z'):asyncio.run(main(a.output))
