#!/usr/bin/env python3
"""Synthetic semantic tests, not a signed or executed pilot bundle."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
spec = importlib.util.spec_from_file_location('cold', Path(__file__).with_name('verify-cold-bundle.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
ref = 'ghcr.io/membrane-hq/the-membrane/membrane-gate@sha256:' + 'a'*64
image = 'sha256:'+'b'*64
runtime = [{'Id':'c'*64,'Image':image,'Config':{'Image':ref},'RestartCount':0,
 'State':{'Running':True,'Pid':123,'StartedAt':'2026-10-29T00:00:00Z'},
 'NetworkSettings':{'Ports':{'8787/tcp':[{'HostIp':'127.0.0.1','HostPort':'8787'}]}}}]
iac = {'scope_id':'pilot-scope','caller_pubkey':'d'*64,'signature':'excluded'}
iac_hash=hashlib.sha256(json.dumps({k:v for k,v in iac.items() if k!='signature'},sort_keys=True,separators=(',',':')).encode()).hexdigest()
files = {'source-publish.json':{'repository':'membrane-hq/the-membrane','commit':'e'*40,'run_id':'123','run_attempt':'1','run_url':'https://github.com/membrane-hq/the-membrane/actions/runs/123','ref':ref},
 'runtime-before.json':runtime,'runtime.json':copy.deepcopy(runtime),'iac.json':iac,
 'cold-observations.json':{'pre_pull_absent':True,'endpoint_absent_before':True,'endpoint_absent_after_stop':True},
 'evidence.jsonl':{'event_type':'blocked_action','scope_id':'pilot-scope','policy_hash':iac_hash,'reason':'caller revoked'}}
manifest={'files':[{'path':x} for x in [*files,'registry.yaml','signed-events.jsonl']],
 'run':{'repository':'membrane-hq/the-membrane','commit':'e'*40,'model_input':'real','install_tested':True},
 'inputs':{'gate_image':ref,'gate_image_id':image},'roles':{'caller_pubkey':'d'*64},
 'results':{'authorized_call_status':200,'replay_status':403,'post_revocation_status':403}}
files['run-manifest.json']=manifest

def run(data, fail=False):
 with tempfile.TemporaryDirectory() as t:
  for name, body in data.items():Path(t,name).write_text(json.dumps(body)+'\n')
  try:module.verify(Path(t))
  except (AssertionError, KeyError):
   if fail:return
   raise
  assert not fail, 'bad bundle accepted'
run(files)
mutations=[('runtime.json',lambda x:x[0]['State'].__setitem__('StartedAt','changed')),
 ('runtime.json',lambda x:x[0].__setitem__('RestartCount',1)),
 ('runtime.json',lambda x:x[0].__setitem__('Image','wrong')),
 ('source-publish.json',lambda x:x.__setitem__('commit','wrong')),
 ('source-publish.json',lambda x:x.__setitem__('ref','wrong')),
 ('cold-observations.json',lambda x:x.__setitem__('pre_pull_absent',False)),
 ('cold-observations.json',lambda x:x.__setitem__('endpoint_absent_after_stop',False)),
 ('evidence.jsonl',lambda x:x.__setitem__('policy_hash','wrong')),
 ('evidence.jsonl',lambda x:x.__setitem__('reason','replay')),
 ('iac.json',lambda x:x.__setitem__('caller_pubkey','f'*64)),
 ('run-manifest.json',lambda x:x['run'].__setitem__('model_input','stub')),
 ('run-manifest.json',lambda x:x['results'].__setitem__('authorized_call_status',400))]
for name,mutate in mutations:
 data=copy.deepcopy(files);mutate(data[name]);run(data,True)
print('13 cold-bundle semantic fixture checks passed (not signed execution evidence)')
