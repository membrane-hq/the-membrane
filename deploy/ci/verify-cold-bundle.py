#!/usr/bin/env python3
"""Cold-install semantics. Run AFTER run-manifest verify authenticates files.
This checks signed observations, not GitHub execution or host integrity.
"""
import json
import sys
from pathlib import Path


def verify(bundle):
    def read(name):
        return json.loads((bundle / name).read_text())
    manifest = read('run-manifest.json')
    bound = {x['path'] for x in manifest['files']}
    assert {'source-publish.json', 'runtime-before.json', 'runtime.json',
            'cold-observations.json', 'registry.yaml', 'iac.json', 'signed-events.jsonl', 'evidence.jsonl'} <= bound
    run = manifest['run']
    assert run['model_input'] == 'real' and run['install_tested'] is True
    observations = read('cold-observations.json')
    assert observations['pre_pull_absent'] is True
    assert observations['endpoint_absent_before'] is True
    assert observations['endpoint_absent_after_stop'] is True
    source = read('source-publish.json')
    assert source['repository'] == run['repository'] and source['commit'] == run['commit']
    assert str(source['run_id']).isdigit() and str(source['run_attempt']).isdigit()
    assert source['run_url'] == ('https://github.com/' + run['repository'] +
                                 '/actions/runs/' + str(source['run_id']))
    assert source['ref'] == manifest['inputs']['gate_image']
    before, after = read('runtime-before.json'), read('runtime.json')
    assert len(before) == len(after) == 1
    a, b = before[0], after[0]
    assert a['Id'] == b['Id']
    assert a['State']['StartedAt'] == b['State']['StartedAt']
    for runtime in (a, b):
        assert runtime['RestartCount'] == 0 and runtime['State']['Running'] is True
        assert runtime['State']['Pid'] > 0
        assert runtime['Image'] == manifest['inputs']['gate_image_id']
        assert runtime['Config']['Image'] == source['ref']
        assert runtime['NetworkSettings']['Ports']['8787/tcp'] == [
            {'HostIp': '127.0.0.1', 'HostPort': '8787'}]
    result = manifest['results']
    assert result['authorized_call_status'] == 200
    assert result['replay_status'] == result['post_revocation_status'] == 403
    # Blocked receipts currently identify the operator publisher, not caller.
    # Bind via the IAC hash instead: it commits to caller_pubkey and scope.
    import hashlib
    iac = read('iac.json')
    caller = iac['caller_pubkey']
    assert isinstance(caller, str) and len(caller) == 64
    assert caller == manifest['roles']['caller_pubkey']
    iac.pop('signature', None)
    # Rust canonical serializer uses sorted object keys and compact JSON.
    iac_hash = hashlib.sha256(json.dumps(iac, sort_keys=True,
        separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()
    rows = [json.loads(x) for x in (bundle / 'evidence.jsonl').read_text().splitlines() if x]
    assert any(row['event_type'] == 'blocked_action'
               and row.get('scope_id') == iac['scope_id']
               and row.get('policy_hash') == iac_hash
               and 'revoked' in row.get('reason', '') for row in rows)


if __name__ == '__main__':
    verify(Path(sys.argv[1]))
    print('cold bundle semantic checks passed (signed observations, not execution attestation)')
