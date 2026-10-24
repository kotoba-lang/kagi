#!/usr/bin/env python3
"""Agent/bot signer isolation diagnostics; native artifacts do all cryptography.
New private fixtures are written beneath --output; never publish that directory.
"""
import argparse
import hashlib
import json
import os
import platform
import subprocess
from pathlib import Path

p = argparse.ArgumentParser()
p.add_argument('--artifact', required=True, type=Path)
p.add_argument('--output', required=True, type=Path)
a = p.parse_args()
assert platform.system() == 'Linux'
out = a.output.resolve()
out.mkdir(mode=0o700, parents=True, exist_ok=False)
roots = [out / 'agent', out / 'bot']
for root in roots:
    root.mkdir(mode=0o700)
env = dict(os.environ, KEXE_ALLOW='7,23,35,37,38,39', KEXE_CAP_RESOURCES_35=str(out))
cases = []

def run(*args, expected=0):
    r = subprocess.run([str(a.artifact.resolve()), *map(str, args)], env=env,
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == expected, (args[0], r.returncode, r.stderr)
    assert (not r.stdout) if expected else (not r.stderr)
    return r.stdout

def passed(name):
    cases.append({'case': name, 'passed': True})

identities = [json.loads(run('init-local', root, 'agent', 'cell:' + root.name,
                            'hata:local', 'cell-writes', '60000')) for root in roots]
assert identities[0]['author'] != identities[1]['author']
assert identities[0]['genesis'] != identities[1]['genesis']
passed('agent and bot have separate native entropy identities and keysets')
body = out / 'body'
body.write_text('local cell operation digest fixture\n')
run('permit-local', roots[0], body, 'node-declaration', expected=2)
passed('cell-writes delegate cannot authorize a node declaration')
request = out / 'request'
request.write_text(run('permit-local', roots[1], body, 'cell-action'))
before = (roots[0] / 'journal').read_bytes()
run('sign-local', roots[0], request, body, expected=2)
assert (roots[0] / 'journal').read_bytes() == before
passed('foreign bot permit has no effect on agent journal')
request.write_text(run('permit-local', roots[0], body, 'cell-action'))
signature = json.loads(run('sign-local', roots[0], request, body))
assert signature['author'] == identities[0]['author'] and signature['sequence'] == 1
passed('agent signs its delegated cell-action after durable append')
assert json.loads(run('status-local', roots[1]))['sequence'] == 0
passed('agent signing leaves bot identity and sequence untouched')
request.write_text(run('permit-local', roots[0], body, 'state-commit'))
assert json.loads(run('sign-local', roots[0], request, body))['sequence'] == 2
passed('bounded cell-writes policy also permits state-commit')
restored = json.loads(run('status-local', roots[0]))
assert restored['sequence'] == 2 and restored['author'] == identities[0]['author']
assert not restored['cellConnected'] and not restored['productionQualified']
passed('restoration preserves agent history without claiming Cell execution')
report = {'schema': 'kagi.native.agent-host.gate.v1', 'host': platform.machine(),
          'artifactSha256': hashlib.sha256(a.artifact.read_bytes()).hexdigest(),
          'passed': True, 'count': len(cases), 'cases': cases,
          'hataCellExecution': False, 'productionQualified': False,
          'orchestration': 'Python diagnostics; native ELF creates keys and signs/verifies/commits'}
(out / 'receipt.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report, indent=2))
