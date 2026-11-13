"""Observational registration trace around unchanged public oracle helper.

Uses sys.setprofile only; no monkeypatch, subclass, argument/order mutation,
network backend, cache preload or validation override is installed.
"""
import argparse
from hashlib import sha256
import json
from pathlib import Path
import runpy
import sys

ap = argparse.ArgumentParser(add_help=False)
ap.add_argument('--events', required=True)
args, forwarded = ap.parse_known_args()
helper = Path(__file__).with_name('oracle.py')
events = []
pending = {}
stores = {}


def info(cert):
    return {'sha256': sha256(cert.dump()).hexdigest(),
            'issuer_der_sha256': sha256(cert.issuer.dump()).hexdigest(),
            'subject_der_sha256': sha256(cert.subject.dump()).hexdigest(),
            'serial': str(cert.serial_number),
            'issuer_serial': cert.issuer_serial.hex(),
            'subject': cert.subject.human_friendly,
            'issuer': cert.issuer.human_friendly,
            'public_key_sha256': sha256(cert.public_key.dump()).hexdigest()}


def profile(frame, event, arg):
    if frame.f_code.co_name != 'register' or not frame.f_code.co_filename.endswith('/pyhanko_certvalidator/registry.py'):
        return
    obj = frame.f_locals.get('self')
    cert = frame.f_locals.get('cert')
    if obj is None or cert is None or not hasattr(obj, 'certs'):
        return
    if event == 'call':
        # Keep the original store alive for the small trace to prevent id reuse.
        key = id(obj)
        if key not in stores:
            stores[key] = (f'store-{len(stores) + 1}', obj)
        calls = []
        historical = None
        f = frame.f_back
        for _ in range(18):
            if f is None:
                break
            if f.f_code.co_filename == str(helper) and f.f_code.co_name == 'run':
                historical = f.f_locals.get('historical')
            calls.append({'function': f.f_code.co_name, 'file': f.f_code.co_filename,
                          'line': f.f_lineno})
            f = f.f_back
        # asyncio may resume a coroutine without its outer async Python frame.
        # The full call stack and trace sequence remain the primary stage record.
        retained = obj.certs.get(cert.issuer_serial)
        pending[id(frame)] = {'event': len(events), 'store': stores[key][0],
            'store_type': type(obj).__name__, 'historical_visible_on_stack': historical,
            'certificate': info(cert), 'retained_before': None if retained is None else info(retained),
            'caller_stack': calls}
    elif event == 'return':
        row = pending.pop(id(frame), None)
        if row is not None:
            retained = obj.certs.get(cert.issuer_serial)
            row.update({'accepted_actual_return': arg,
                        'retained_after': None if retained is None else info(retained)})
            events.append(row)


original = sys.getprofile()
try:
    sys.argv = [str(helper), *forwarded]
    sys.setprofile(profile)
    runpy.run_path(str(helper), run_name='__main__')
finally:
    sys.setprofile(original)
    Path(args.events).write_text(json.dumps({'helper_sha256': sha256(helper.read_bytes()).hexdigest(),
        'profiler_sha256': sha256(Path(__file__).read_bytes()).hexdigest(),
        'mechanism': 'sys.setprofile observing original registry function calls and actual returns',
        'events': events, 'pending_frames': len(pending),
        'no_registry_or_validation_replacement': True}, indent=2) + '\n')
