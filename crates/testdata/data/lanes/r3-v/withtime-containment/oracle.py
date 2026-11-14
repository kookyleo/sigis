"""Fresh same-PDF exact AdES and ordinary PDF controls for WithTime hardening."""
import argparse,asyncio,hashlib,inspect,json,sys,traceback
from pathlib import Path
from io import BytesIO
from datetime import datetime
from importlib import metadata
from asn1crypto import x509
from cryptography import x509 as cx
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from freezegun import freeze_time
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.validation import ades,generic_cms,pdf_embedded
from pyhanko.sign.validation.settings import KeyUsageConstraints
from pyhanko.sign.validation.policy_decl import SignatureValidationSpec,LocalKnowledge,RevocationInfoGatheringSpec,RevinfoOnlineFetchingRule,CertificateFetchingRule,bootstrap_validation_data_handlers
from pyhanko_certvalidator.context import CertValidationPolicySpec
from pyhanko_certvalidator.policy_decl import CertRevTrustPolicy,NO_REVOCATION
from pyhanko_certvalidator.registry import SimpleTrustManager
from pyhanko_certvalidator.ltv.types import ValidationTimingInfo
BASE=Path(__file__).parent
DT=lambda s:datetime.fromisoformat(s.replace('Z','+00:00'))
def rec(p):
 p=Path(p).resolve();b=p.read_bytes();return {'path':str(p),'sha256':hashlib.sha256(b).hexdigest(),'length':len(b)}
def val(v):
 if v is None or isinstance(v,(str,int,bool)):return v
 if isinstance(v,datetime):return v.isoformat()
 if hasattr(v,'name'):return v.name
 return str(v)
def api(s):
 if s is None:return None
 p=getattr(s,'validation_path',None)
 return {'intact':s.intact,'valid':s.valid,'trusted':s.trusted,'bottom_line':getattr(s,'bottom_line',None),'subindic':val(getattr(s,'trust_problem_indic',None)),'horizon':val(getattr(s,'error_time_horizon',None)),'validation_time':val(getattr(s,'validation_time',None)),'path':None if p is None else [hashlib.sha256(c.dump()).hexdigest() for c in p],'timestamp':api(getattr(s,'timestamp_validity',None)),'coverage':val(getattr(s,'coverage',None)),'docmdp_ok':getattr(s,'docmdp_ok',None),'seed_value_constraint_error':val(getattr(s,'seed_value_constraint_error',None))}
async def main(output):
 assert __debug__ and metadata.version('pyhanko')=='0.38.1' and metadata.version('pyhanko-certvalidator')=='0.33.0'
 m=json.loads((BASE/'manifest.json').read_text());root=x509.Certificate.load((BASE/m['root']).read_bytes());rows=[];crypto=[]
 for r in m['files']:
  f=rec(BASE/r['file']);assert f['sha256']==r['sha256'] and f['length']==r['length']
 for row in m['cases']:
  data=(BASE/row['file']).read_bytes();reader=PdfFileReader(BytesIO(data));sig=reader.embedded_signatures[0];sd=sig.signed_data;si=sd['signer_infos'][0]
  leaf=cx.load_der_x509_certificate((BASE/row['signer']).read_bytes());leaf.public_key().verify(si['signature'].native,si['signed_attrs'].untag().dump(),padding.PKCS1v15(),hashes.SHA256())
  md=next(a['values'][0].native for a in si['signed_attrs'] if a['type'].native=='message_digest');digest=sig.compute_digest();assert md==digest
  token=next(generic_cms.extract_tst_data_iter(si,signed=False));tsi=token['signer_infos'][0];tsa=cx.load_der_x509_certificate((BASE/row['tsa']).read_bytes());tsa.public_key().verify(tsi['signature'].native,tsi['signed_attrs'].untag().dump(),padding.PKCS1v15(),hashes.SHA256())
  info=token['encap_content_info']['content'].parsed;imprint=info['message_imprint']['hashed_message'].native==hashlib.sha256(si['signature'].native).digest();assert imprint==row['timestamp_imprint_expected_valid'];assert info['gen_time'].native==DT(m['signed_at'])
  crypto.append({'case':row['id'],'main_signature':True,'pdf_digest_binding':True,'timestamp_signature':True,'imprint_binding':imprint,'token_time':info['gen_time'].native.isoformat(),'pdf':rec(BASE/row['file'])})
  for profile,at in [('current_validity',DT(m['current_validation_time'])),('expired',DT(m['expired_validation_time']))]:
   for clock in ['current','current_best']:
    best=DT(m['signed_at']) if clock=='current_best' else at
    timing=ValidationTimingInfo(at,best,point_in_time_validation=True)
    policy=CertValidationPolicySpec(trust_manager=SimpleTrustManager.build(trust_roots=[root]),revinfo_policy=CertRevTrustPolicy(NO_REVOCATION))
    spec=SignatureValidationSpec(cert_validation_policy=policy,key_usage_settings=KeyUsageConstraints(key_usage={'non_repudiation'}),local_knowledge=LocalKnowledge(known_certs=[x509.Certificate.load((BASE/p).read_bytes()) for p in row['other_certs']]),revinfo_gathering_policy=RevocationInfoGatheringSpec(online_fetching_rule=RevinfoOnlineFetchingRule.LOCAL_ONLY,certificate_fetching_rule=CertificateFetchingRule.NEVER_FETCH))
    r={'case':row['id'],'profile':profile,'clock':clock,'validation_time':at.isoformat(),'best_signature_time':best.isoformat(),'best_clock_eligibility':'counterfactual clone; not independent TSA/material POE','pdf':rec(BASE/row['file']),'apis':{}}
    try:
     result=await ades.ades_with_time_validation(sd,spec,timing_info=timing,raw_digest=digest)
     r['apis']['ades_with_time']={'ades_subindic':result.ades_subindic.name,'api':api(result.api_status),'best':val(result.best_signature_time),'not_before':val(result.signature_not_before_time),'failure':result.failure_msg}
    except Exception as e:r['apis']['ades_with_time']={'exception':type(e).__name__,'message':str(e),'traceback':traceback.format_exc()}
    try:
     handlers=bootstrap_validation_data_handlers(spec,timing_info=timing);ctx=policy.build_validation_context(timing_info=timing,handlers=handlers)
     status=await pdf_embedded.async_validate_pdf_signature(sig,signer_validation_context=ctx,ts_validation_context=ctx,key_usage_settings=spec.key_usage_settings)
     r['apis']['ordinary_pdf']=api(status)
    except Exception as e:r['apis']['ordinary_pdf']={'exception':type(e).__name__,'message':str(e),'traceback':traceback.format_exc()}
    assert not any('exception' in v for v in r['apis'].values()),r
    if row['id']=='good' and profile=='current_validity':assert r['apis']['ades_with_time']['ades_subindic']=='OK' and r['apis']['ordinary_pdf']['bottom_line'],r
    if row['id'] in ['path_length','bad_cert_signature','wrong_tsa_purpose','corrupt_imprint']:assert r['apis']['ades_with_time']['ades_subindic']!='OK',r
    rows.append(r)
 modules=[inspect.getfile(ades),inspect.getfile(generic_cms),inspect.getfile(pdf_embedded),inspect.getfile(CertValidationPolicySpec),inspect.getfile(KeyUsageConstraints)]
 result={'scope':'Fresh same actual PDF bytes; exact AdES MAIN NR predicate separate from ordinary normalized PDF API; no network/provider exclusions; no new original credit','assertions_enabled':__debug__,'interpreter':rec(sys.executable),'versions':{p:metadata.version(p) for p in ['pyhanko','pyhanko-certvalidator','cryptography','asn1crypto']},'modules':[rec(p) for p in modules],'producer':rec(BASE/'generate.py'),'runner':rec(__file__),'manifest':rec(BASE/'manifest.json'),'files':[rec(BASE/r['file']) for r in m['files']],'crypto_controls':crypto,'rows':rows,'api_calls':len(rows)*2,'network_requests':0,'provider_exclusions':[]}
 Path(output).write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({'rows':len(rows),'api_calls':len(rows)*2,'output':rec(output)}))
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--output',required=True);args=p.parse_args()
 with freeze_time('2025-03-01T22:00:00Z'):asyncio.run(main(args.output))
