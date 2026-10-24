#!/usr/bin/env python3
"""Linux lifecycle diagnostics; all keys/signatures are created by the native host.

Python orchestrates independent processes and checks their public results only.
The output contains new private fixtures: keep it out of Git/release archives.
"""
import argparse
import concurrent.futures
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
private = out / 'private'
private.mkdir(mode=0o700)
public = out / 'public'
public.mkdir()
artifact = a.artifact.resolve()
env = dict(os.environ, KEXE_ALLOW='7,23,35,37,38,39',
           KEXE_CAP_RESOURCES_35=str(out))
cases = []

def run(*args, expected=0):
    r = subprocess.run([str(artifact), *map(str, args)], env=env,
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == expected, (args[0], r.returncode, r.stderr)
    if expected:
        assert not r.stdout and 'kagi' in r.stderr, (args[0], r)
    else:
        assert not r.stderr, (args[0], r.stderr)
    return r.stdout

def passed(name):
    cases.append({'case': name, 'passed': True})

info = json.loads(run('init-local', private, 'node', 'node:gate',
                      'tsukasa:local', 'node-statements', '60000'))
assert info['mode'] == 'local-software' and not info['independentCustody']
assert all((f.stat().st_mode & 0o7777) == 0o600 for f in private.iterdir())
passed('native entropy initialization and owner-only files')
original_config = (private / 'config').read_bytes()
run('init-local', private, 'node', 'node:gate', 'tsukasa:local',
    'node-statements', '60000', expected=2)
assert (private / 'config').read_bytes() == original_config
passed('exclusive initialization preserves existing identity')
status = json.loads(run('status-local', private))
assert status['sequence'] == 0 and not status['productionQualified']
assert status['author'] == info['author']
passed('separate process verifies genesis and empty journal')
body = public / 'body'
body.write_text('native local signing gate\n')
request = public / 'request'
run('permit-local', private, body, 'cell-action', expected=2)
passed('node delegate cannot mint a cell-action permit')
request.write_text(run('permit-local', private, body, 'node-declaration'))
journal = private / 'journal'
before = journal.read_bytes()
bad = public / 'bad-request'
bad.write_text('日本語 ' + request.read_text())
run('sign-local', private, bad, body, expected=2)
assert journal.read_bytes() == before
passed('Unicode request refuses without a boundary trap or journal effect')
parts = request.read_text().split()
parts[-1] = ('0' if parts[-1][0] != '0' else '1') + parts[-1][1:]
bad.write_text(' '.join(parts) + '\n')
run('sign-local', private, bad, body, expected=2)
assert journal.read_bytes() == before
passed('changed delegate signature has no journal effect')
other = public / 'other-body'
other.write_text('different bytes\n')
run('sign-local', private, request, other, expected=2)
assert journal.read_bytes() == before
passed('body digest mismatch has no journal effect')
signed = json.loads(run('sign-local', private, request, body))
assert signed['sequence'] == 1 and len(signed['signature']) == 128
assert journal.read_bytes() != before
passed('signature released after durable journal append')
after = journal.read_bytes()
run('sign-local', private, request, body, expected=2)
assert journal.read_bytes() == after
passed('replayed request preserves committed journal')
restored = json.loads(run('status-local', private))
assert restored['sequence'] == 1 and restored['author'] == info['author']
passed('new process restores verified sequence and identity')
audit = run('audit-local', private)
assert signed['signature'] in audit and len(audit.splitlines()) == 2
passed('public verified audit resolves a lost signature reply')
request.write_text(run('permit-local', private, body, 'node-heartbeat'))
with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
    results = list(pool.map(lambda _: subprocess.run(
        [str(artifact), 'sign-local', str(private), str(request), str(body)],
        env=env, capture_output=True, text=True, timeout=60), range(3)))
assert sum(r.returncode == 0 for r in results) == 1
assert all(r.returncode in (0, 2) for r in results)
assert all(not r.stdout for r in results if r.returncode != 0)
assert json.loads(run('status-local', private))['sequence'] == 2
passed('three competing signers release exactly one signature')
request.write_text(run('permit-local', private, body, 'node-heartbeat'))
seed = private / 'author.seed'
seed.chmod(0o644)
run('sign-local', private, request, body, expected=2)
seed.chmod(0o600)
assert json.loads(run('status-local', private))['sequence'] == 2
passed('public-mode author seed refuses signing')
journal.chmod(0o644)
run('status-local', private, expected=2)
journal.chmod(0o600)
passed('public-mode journal refuses startup')
complete = journal.read_bytes()
journal.write_bytes(complete[:-1])
run('status-local', private, expected=2)
journal.write_bytes(complete)
passed('truncated journal refuses rather than resetting sequence')
run('watch-local', private, public, '1')
watched = json.loads((public / 'signer-status.json').read_text())
assert watched['sequence'] == 2 and not watched['productionQualified']
passed('bounded watcher atomically publishes verified public status')
report = {'schema': 'kagi.native.local-host.gate.v1', 'host': platform.machine(),
          'artifactSha256': hashlib.sha256(artifact.read_bytes()).hexdigest(),
          'cases': cases, 'count': len(cases), 'passed': True,
          'independentCustody': False, 'productionQualified': False,
          'orchestration': 'Python diagnostics; entropy, signatures, proof validation and durable journal execute in Amu native ELF'}
(out / 'receipt.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report, indent=2))
