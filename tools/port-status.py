#!/usr/bin/env python3
"""Count accepted unique upstream functions without changing the launch baseline."""
import json
from collections import Counter, defaultdict
from pathlib import Path

root = Path(__file__).resolve().parents[1]
folder = root / 'docs/lanes/round3'
manifest = json.loads((folder / 'ownership.json').read_text())
ledger = json.loads((folder / 'acceptance.json').read_text())
functions = {entry['id']: entry for entry in manifest['functions']}
assert len(functions) == len(manifest['functions']), 'Duplicate baseline ID'
overrides = {entry['id']: entry for entry in ledger['overrides']}
assert len(overrides) == len(ledger['overrides']), 'Duplicate accepted ID'
assert overrides.keys() <= functions.keys(), 'Unknown accepted function ID'
crates, lanes, overall = defaultdict(Counter), defaultdict(Counter), Counter()
for function_id, entry in functions.items():
    status = overrides.get(function_id, {}).get('status', entry['baseline_status'])
    assert status in {'passed', 'skipped', 'pending'}, (function_id, status)
    for counts in (crates[entry['crate']], lanes[entry['lane']], overall):
        counts['total'] += 1
        counts[status] += 1

def complete(counts):
    return {key: counts[key] for key in ('total', 'passed', 'skipped', 'pending')}

assert overall['total'] == sum(overall[s] for s in ('passed', 'skipped', 'pending'))
print(json.dumps({
    'accepted_source_commit': ledger['accepted_source_commit'],
    'crates': {key: complete(value) for key, value in sorted(crates.items())},
    'lanes': {key: complete(value) for key, value in sorted(lanes.items())},
    'overall': complete(overall),
}, indent=2))
