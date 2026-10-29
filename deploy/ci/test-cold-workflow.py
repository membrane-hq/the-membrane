#!/usr/bin/env python3
"""Structural and shell syntax checks only, not workflow execution."""
from pathlib import Path
import re
import subprocess

root = Path(__file__).resolve().parents[2]
original = (root / '.github/workflows/integration.yml').read_text()
cold = (root / '.github/workflows/cold-install.yml').read_text()

def steps(text):
    return {part.splitlines()[0]: part for part in
            re.split(r'(?=^      - )', text, flags=re.M)[1:]}

s = steps(cold)
assert '  packages: read\n' in cold
assert cold.count('verify-pulled-gate.sh') == 2
assert cold.index('docker pull ghcr.io/ggml-org/llama.cpp:server') < cold.index('docker logout ghcr.io') < cold.index('up -d --no-build --pull never')
assert cold.index('Refuse an existing service') < cold.index('Start the pilot stack')
assert cold.index('Verify runtime binding after assertions') < cold.index('Write, sign, and verify the run manifest')
assert 'docker stop \"$CID\"' in cold
assert 'endpoint survived stopping the tested gate' in cold
assert '  actions: read\n' in cold
for forbidden in ('docker build ', 'docker push ', 'TESTED_GATE_IMAGE=',
                  'inputs.publish', 'inputs.install_tested', 'packages: write'):
    assert forbidden not in cold, forbidden
assert cold.index('      - uses: docker/login-action@v3') < cold.index(
    '      - name: Resolve and cold-pull') < cold.index('      - name: Start the pilot stack')
assert 'resolve-tested-image.sh "$GITHUB_REPOSITORY" "$GITHUB_SHA" --provenance-json' in cold
assert 'pull-tested-image.sh "$GITHUB_REPOSITORY" "$REF"' in cold
assert '$GITHUB_WORKSPACE/.github/workflows/cold-install.yml' in cold
assert 'install_tested:true' not in cold  # actual jq boolean, not a quoted string
assert '--argjson install_tested "true"' in cold
# Keep the critical HTTP/receipt checks explicit, not just copied names.
for marker in ('[ "$first" = 200 ]', '[ "$second" = 403 ]',
               '[ "$code" = 403 ]', 'test("revoked")',
               'verify-cold-bundle.py', '--no-build --pull never'):
    assert marker in cold, marker
# Parse every run block as Bash after substituting expression placeholders.
for match in re.finditer(r'^        run: \|\n((?:^          .*\n|^\n)+)', cold, re.M):
    script = ''.join(line[10:] if line.startswith('          ') else line
                     for line in match.group(1).splitlines(keepends=True))
    script = re.sub(r'\$\{\{.*?\}\}', 'placeholder', script)
    subprocess.run(['bash', '-n'], input=script, text=True, check=True)
print('Cold workflow: read-only registry, login ordering, exact-commit selection, '
      'unchanged acceptance assertions, manifest workflow binding and Bash syntax passed')
