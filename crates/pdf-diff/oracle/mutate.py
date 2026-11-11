"""
Differential mutation corpus for the difference analysis.

Takes the recorded input files of lane C (``pdf/``), appends one random
incremental update to each with pyHanko's ``IncrementalPdfFileWriter``
(seeded, so the corpus is reproducible from the same inputs), and records
pyHanko's ``DEFAULT_DIFF_POLICY`` verdict on the new revision against the
previous one, in strict mode.

Mutations mix changes the policy allows (field values, appearances, new
signature fields, /Info, DSS additions, orphans, identical rewrites) with
changes it must reject (page content, catalog keys, annotations, deletions,
clobbered objects).

Output (in LANE_C_DIR): ``mutations/<id>.bin`` (the appended bytes; the
file is ``pdf/<base>.pdf`` followed by them), ``mutations.json`` (per
mutation: base, description, pyHanko's cross-reference model of the result
and its verdicts: plain, with DocMDP P=2, and with all fields locked).

Usage: python mutate.py LANE_C_DIR [SEED] [PER_FILE]
"""

import json
import os
import random
import sys
import traceback
from io import BytesIO

os.environ.setdefault('HANKO_CAPTURE_OUT', '/tmp/hanko-mutate-unused')
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from capture_plugin import _eof_end, _meta, _section_data, enc  # noqa: E402
from pyhanko.pdf_utils import generic  # noqa: E402
from pyhanko.pdf_utils.generic import pdf_name, pdf_string  # noqa: E402
from pyhanko.pdf_utils.incremental_writer import (  # noqa: E402
    IncrementalPdfFileWriter,
)
from pyhanko.pdf_utils.reader import PdfFileReader  # noqa: E402
from pyhanko.sign import fields  # noqa: E402
from pyhanko.sign.diff_analysis import (  # noqa: E402
    DEFAULT_DIFF_POLICY,
    SuspiciousModification,
)


def model_of(data: bytes):
    reader = PdfFileReader(BytesIO(data))
    revisions = []
    for ix, section in enumerate(reader.xrefs._xref_sections):
        hyb = section.xref_data.hybrid
        revisions.append(
            {
                'meta': _meta(section.meta_info),
                'data': _section_data(section.xref_data),
                'hybrid': (
                    {'meta': _meta(hyb.meta_info), 'data': _section_data(hyb.xref_data)}
                    if hyb is not None
                    else None
                ),
                'trailer': enc(reader.trailer.flatten(ix)),
                'eof_end': _eof_end(data, section.meta_info.end_location),
            }
        )
    return {'encrypted': False, 'revisions': revisions}


def verdict(data: bytes, base: int, field_mdp=None, doc_mdp=None):
    try:
        reader = PdfFileReader(BytesIO(data))
        result = DEFAULT_DIFF_POLICY.review_file(
            reader, base, field_mdp_spec=field_mdp, doc_mdp=doc_mdp
        )
    except Exception as e:  # noqa: BLE001
        return {'error': type(e).__name__, 'message': str(e)[:300]}
    if isinstance(result, SuspiciousModification):
        return {'suspicious': str(result)[:300]}
    return {
        'level': result.modification_level.value,
        'changed_form_fields': sorted(result.changed_form_fields),
    }


def random_value(rng, w):
    choice = rng.randrange(8)
    if choice == 0:
        return generic.NumberObject(rng.randrange(-5, 1000))
    if choice == 1:
        return pdf_name('/M%d' % rng.randrange(100))
    if choice == 2:
        return generic.NullObject()
    if choice == 3:
        return generic.BooleanObject(rng.random() < 0.5)
    if choice == 4:
        return pdf_string('mut%d' % rng.randrange(100))
    if choice == 5:
        return w.add_object(generic.DictionaryObject({pdf_name('/Mut'): generic.NumberObject(1)}))
    if choice == 6:
        return generic.ArrayObject([generic.NumberObject(rng.randrange(10))])
    return generic.FloatObject('%d.5' % rng.randrange(10))


def reachable_refs(reader, w):
    resolver = reader.get_historical_resolver(reader.xrefs.total_revisions - 1)
    resolver._load_reverse_xref_cache()
    return [
        generic.Reference(r.idnum, r.generation, pdf=w)
        for r in sorted(
            resolver._indirect_object_access_cache,
            key=lambda r: (r.idnum, r.generation),
        )
    ]


def form_fields(w):
    try:
        return list(w.root['/AcroForm']['/Fields'])
    except (KeyError, TypeError):
        return []


def mutate(rng, w, reader):
    """Apply one random mutation, return its description."""
    refs = reachable_refs(reader, w)
    kind = rng.choice(
        [
            'set_key', 'del_key', 'set_key', 'array_elem', 'identical',
            'orphan', 'info', 'field_value', 'field_value', 'field_ap',
            'new_sig_field', 'new_visible_sig_field', 'root_key', 'dss_add',
            'annot_add', 'stream_data', 'metadata', 'field_flags',
        ]
    )
    if kind in ('set_key', 'del_key', 'array_elem', 'identical', 'stream_data'):
        candidates = []
        for ref in refs:
            obj = w.get_object(ref)
            if kind == 'array_elem' and isinstance(obj, generic.ArrayObject) and len(obj):
                candidates.append(ref)
            elif kind == 'stream_data' and isinstance(obj, generic.StreamObject):
                candidates.append(ref)
            elif kind in ('set_key', 'del_key') and isinstance(obj, generic.DictionaryObject) and len(obj):
                candidates.append(ref)
            elif kind == 'identical':
                candidates.append(ref)
        if not candidates:
            return None
        ref = rng.choice(candidates)
        obj = w.get_object(ref)
        if kind == 'identical':
            w.mark_update(ref)
            return f'identical rewrite of {ref.idnum}'
        if kind == 'stream_data':
            obj._data = obj.data + b' '
            obj._encoded_data = None
            w.mark_update(ref)
            return f'stream data of {ref.idnum}'
        if kind == 'array_elem':
            ix = rng.randrange(len(obj))
            obj[ix] = random_value(rng, w)
            w.mark_update(ref)
            return f'array {ref.idnum}[{ix}]'
        key = rng.choice(sorted(obj.keys()))
        if kind == 'del_key':
            del obj[key]
            w.mark_update(ref)
            return f'delete {key} of {ref.idnum}'
        obj[key] = random_value(rng, w)
        w.mark_update(ref)
        return f'set {key} of {ref.idnum}'
    if kind == 'orphan':
        w.add_object(pdf_string('orphan'))
        return 'orphan'
    if kind == 'info':
        w.set_info(generic.DictionaryObject({pdf_name('/Title'): pdf_string('t%d' % rng.randrange(9))}))
        return 'info'
    if kind in ('field_value', 'field_ap', 'field_flags'):
        flds = form_fields(w)
        if not flds:
            return None
        ref = rng.choice(flds)
        fld = ref.get_object()
        if kind == 'field_value':
            fld['/V'] = pdf_string('v%d' % rng.randrange(9))
        elif kind == 'field_flags':
            fld['/Ff'] = generic.NumberObject(rng.randrange(4))
        else:
            stm = generic.StreamObject(
                {pdf_name('/BBox'): generic.ArrayObject(map(generic.NumberObject, (0, 0, 10, 10)))},
                stream_data=b'q Q',
            )
            fld['/AP'] = generic.DictionaryObject({pdf_name('/N'): w.add_object(stm)})
        w.update_container(fld)
        return f'{kind} of field {fld.get("/T")}'
    if kind in ('new_sig_field', 'new_visible_sig_field'):
        box = (10, 10, 60, 40) if kind == 'new_visible_sig_field' else None
        fields.append_signature_field(
            w, fields.SigFieldSpec('MutSig%d' % rng.randrange(1000), box=box)
        )
        return kind
    if kind == 'root_key':
        w.root['/Mut%d' % rng.randrange(9)] = random_value(rng, w)
        w.update_root()
        return 'root key'
    if kind == 'dss_add':
        try:
            dss = w.root['/DSS']
            certs = dss['/Certs']
        except KeyError:
            return None
        certs.append(w.add_object(generic.StreamObject(stream_data=b'\x30\x00')))
        w.update_container(certs)
        return 'dss cert'
    if kind == 'annot_add':
        page = w.root['/Pages']['/Kids'][0].get_object()
        annot = w.add_object(
            generic.DictionaryObject(
                {
                    pdf_name('/Type'): pdf_name('/Annot'),
                    pdf_name('/Subtype'): pdf_name('/Text'),
                    pdf_name('/Rect'): generic.ArrayObject(map(generic.NumberObject, (0, 0, 5, 5))),
                }
            )
        )
        annots = page.get('/Annots')
        if annots is None:
            page['/Annots'] = generic.ArrayObject([annot])
        else:
            annots.append(annot)
        w.update_container(page)
        return 'annotation'
    if kind == 'metadata':
        xmp = (
            b'<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF '
            b'xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"/></x:xmpmeta>'
        )
        w.root['/Metadata'] = w.add_object(
            generic.StreamObject({pdf_name('/Type'): pdf_name('/Metadata')}, stream_data=xmp)
        )
        w.update_root()
        return 'metadata'
    return None


def main():
    lane = sys.argv[1]
    seed = int(sys.argv[2]) if len(sys.argv) > 2 else 1
    per_file = int(sys.argv[3]) if len(sys.argv) > 3 else 3
    rng = random.Random(seed)
    out_dir = os.path.join(lane, 'mutations')
    os.makedirs(out_dir, exist_ok=True)
    for f in os.listdir(out_dir):
        os.remove(os.path.join(out_dir, f))
    bases = []
    for name in sorted(os.listdir(os.path.join(lane, 'pdf'))):
        sha = name[:-4]
        with open(os.path.join(lane, 'model', sha + '.json')) as fh:
            model = json.load(fh)
        size = os.path.getsize(os.path.join(lane, 'pdf', name))
        if not model['encrypted'] and len(model['revisions']) >= 2 and size < 60000:
            bases.append(sha)
    records = {}
    for sha in bases:
        with open(os.path.join(lane, 'pdf', sha + '.pdf'), 'rb') as fh:
            base_bytes = fh.read()
        for k in range(per_file):
            try:
                reader = PdfFileReader(BytesIO(base_bytes))
                w = IncrementalPdfFileWriter(BytesIO(base_bytes))
                desc = mutate(rng, w, reader)
                if desc is None:
                    continue
                out = BytesIO()
                w.write(out)
                data = out.getvalue()
            except Exception:  # noqa: BLE001
                # mutations that pyHanko's writer refuses are not interesting
                traceback.print_exc(file=sys.stderr)
                continue
            assert data.startswith(base_bytes)
            mid = f'{sha}-{k}'
            with open(os.path.join(out_dir, mid + '.bin'), 'wb') as fh:
                fh.write(data[len(base_bytes):])
            n = len(model_of(base_bytes)['revisions'])
            records[mid] = {
                'base': sha,
                'mutation': desc,
                'base_revision': n - 1,
                'model': model_of(data),
                'verdict': verdict(data, n - 1),
                # as after a certification signature (DocMDP P=2)
                'verdict_certify': verdict(data, n - 1, doc_mdp=fields.MDPPerm.FILL_FORMS),
                # with a FieldMDP lock on all fields
                'verdict_locked': verdict(
                    data, n - 1, field_mdp=fields.FieldMDPSpec(fields.FieldMDPAction.ALL)
                ),
            }
    with open(os.path.join(lane, 'mutations.json'), 'w') as fh:
        json.dump({'seed': seed, 'per_file': per_file, 'cases': records}, fh, sort_keys=True)
    print(f'{len(records)} mutations from {len(bases)} files', file=sys.stderr)


if __name__ == '__main__':
    main()
