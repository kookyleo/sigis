"""
pytest plugin that records pyHanko's difference analysis while pyHanko's own
test suite (``pkgs/pyhanko/tests/test_diff_analysis.py`` at tag v0.38.1)
runs. Used to generate the lane C fixtures in
``crates/testdata/data/lanes/c/``; see ``capture.sh``.

Recorded per pytest test id, in call order:

- every ``StandardDiffPolicy.review_file`` call: input PDF (by SHA-256),
  reader strictness, base revision, FieldMDP spec, DocMDP level, the policy
  configuration and pyHanko's verdict (DiffResult, SuspiciousModification, or
  the exception it raised);
- every ``HistoricalResolver._load_reverse_xref_cache`` result (the paths
  through which each reference is reached).

Per input PDF it writes the file and pyHanko's cross-reference model (one
entry per revision: section data, metadata and the flattened trailer), so the
Rust tests can replay the analysis without Python.
"""

import hashlib
import json
import os
from decimal import Decimal

import pytest
from pyhanko.pdf_utils import generic
from pyhanko.pdf_utils.reader import HistoricalResolver, PdfFileReader
from pyhanko.pdf_utils.xref import ObjStreamRef
from pyhanko.sign import diff_analysis as da
from pyhanko.sign.diff_analysis import policies, rules_api
from pyhanko.sign.diff_analysis.form_rules_api import FormUpdatingRule
from pyhanko.sign.diff_analysis.rules import (
    file_structure_rules as fsr,
    form_field_rules as ffr,
    metadata_rules as mr,
)
from pyhanko.sign.fields import FieldMDPAction

OUT = os.environ['HANKO_CAPTURE_OUT']
PDF_DIR = os.path.join(OUT, 'pdf')
MODEL_DIR = os.path.join(OUT, 'model')
os.makedirs(PDF_DIR, exist_ok=True)
os.makedirs(MODEL_DIR, exist_ok=True)

CASES: dict = {}
_current = {'id': None}
_seen_pdfs: set = set()
_seen_usages: set = set()


def _events():
    tid = _current['id']
    if tid is None:
        return None
    return CASES.setdefault(tid, {'events': [], 'outcome': None})['events']


def _reader_bytes(reader: PdfFileReader) -> bytes:
    stream = reader.stream
    pos = stream.tell()
    stream.seek(0)
    data = stream.read()
    stream.seek(pos)
    return bytes(data)


def enc(obj):
    """JSON encoding of a (direct) PDF object."""
    if isinstance(obj, generic.IndirectObject):
        return {'ref': [obj.idnum, obj.generation]}
    if isinstance(obj, generic.Reference):
        return {'ref': [obj.idnum, obj.generation]}
    if isinstance(obj, generic.NullObject) or obj is None:
        return None
    if isinstance(obj, generic.BooleanObject):
        return {'bool': bool(obj)}
    if isinstance(obj, bool):
        return {'bool': obj}
    if isinstance(obj, generic.NameObject):
        return {'name': str(obj)}
    if isinstance(obj, (generic.FloatObject, Decimal, float)):
        return {'real': str(obj)}
    if isinstance(obj, int):
        return {'int': int(obj)}
    if isinstance(obj, (generic.TextStringObject, generic.ByteStringObject)):
        return {'str': obj.original_bytes.hex()}
    if isinstance(obj, generic.StreamObject):
        return {'stream': {str(k): enc(v) for k, v in obj.items()}}
    if isinstance(obj, generic.DictionaryObject):
        return {'dict': {str(k): enc(v) for k, v in obj.items()}}
    if isinstance(obj, generic.ArrayObject):
        return {'arr': [enc(x) for x in obj]}
    return {'unknown': repr(obj)}


def _section_data(data):
    return {
        'freed': {str(k): v for k, v in data.freed.items()},
        'standard': {str(k): list(v) for k, v in data.standard_xrefs.items()},
        'objstm': {
            str(k): [v.obj_stream_id, v.ix_in_stream]
            for k, v in data.xrefs_in_objstm.items()
        },
        'explicit': sorted(list(x) for x in data.explicit_refs_in_revision),
        'obj_streams_used': sorted(data.obj_streams_used),
    }


def _meta(meta):
    return {
        'type': meta.xref_section_type.name,
        'size': meta.size,
        'declared_startxref': meta.declared_startxref,
        'start_location': meta.start_location,
        'end_location': meta.end_location,
        'stream_ref': (
            [meta.stream_ref.idnum, meta.stream_ref.generation]
            if meta.stream_ref is not None
            else None
        ),
    }


def _eof_end(data: bytes, start: int) -> int:
    ix = data.find(b'%%EOF', start)
    if ix < 0:
        return len(data)
    ix += 5
    while ix < len(data) and data[ix : ix + 1] in (b'\r', b'\n'):
        ix += 1
    return ix


def record_pdf(reader: PdfFileReader) -> str:
    data = _reader_bytes(reader)
    sha = hashlib.sha256(data).hexdigest()[:24]
    if sha in _seen_pdfs:
        return sha
    _seen_pdfs.add(sha)
    with open(os.path.join(PDF_DIR, sha + '.pdf'), 'wb') as f:
        f.write(data)
    revisions = []
    sections = reader.xrefs._xref_sections
    for ix, section in enumerate(sections):
        hyb = section.xref_data.hybrid
        revisions.append(
            {
                'meta': _meta(section.meta_info),
                'data': _section_data(section.xref_data),
                'hybrid': (
                    {
                        'meta': _meta(hyb.meta_info),
                        'data': _section_data(hyb.xref_data),
                    }
                    if hyb is not None
                    else None
                ),
                'trailer': enc(reader.trailer.flatten(ix)),
                'eof_end': _eof_end(data, section.meta_info.end_location),
            }
        )
    model = {
        'encrypted': bool(reader.encrypted),
        'revisions': revisions,
    }
    with open(os.path.join(MODEL_DIR, sha + '.json'), 'w') as f:
        json.dump(model, f, sort_keys=True)
    return sha


def _path(p):
    return [x if isinstance(x, int) else str(x) for x in p.path]


def _context(ctx):
    if ctx is None:
        return None
    if isinstance(ctx, rules_api.RelativeContext):
        anchor = ctx.anchor
        a = (
            None
            if isinstance(anchor, generic.TrailerReference)
            else [anchor.idnum, anchor.generation]
        )
        return {'relative': {'anchor': a, 'path': _path(ctx.relative_path)}}
    return {'absolute': _path(ctx.path)}


def _base_field_rule(rule):
    return {
        'allow_in_place_appearance_stream_changes': rule.allow_in_place_appearance_stream_changes,
        'always_modifiable': sorted(rule.always_modifiable),
        'value_update_keys': sorted(rule.value_update_keys),
    }


def describe_field_rule(rule):
    if isinstance(rule, ffr.SigFieldCreationRule):
        return {
            'kind': 'sig_field_creation',
            'approve_widget_bindings': rule.approve_widget_bindings,
            'allow_new_visible_after_certify': rule.allow_new_visible_after_certify,
        }
    if isinstance(rule, ffr.SigFieldModificationRule):
        return {'kind': 'sig_field_modification', **_base_field_rule(rule)}
    if isinstance(rule, ffr.GenericFieldModificationRule):
        return {'kind': 'generic_field_modification', **_base_field_rule(rule)}
    return {'kind': 'unknown', 'class': type(rule).__name__}


def describe_rule(rule, old, new_revisions):
    if isinstance(rule, fsr.CatalogModificationRule):
        return {'kind': 'catalog', 'ignored_keys': sorted(rule.ignored_keys)}
    if isinstance(rule, rules_api._WrappingQualifiedWhitelistRule):
        inner = rule.rule
        d = {'kind': 'qualified', 'level': rule.level.value}
        if isinstance(inner, mr.DocInfoRule):
            d['rule'] = {'kind': 'doc_info'}
        elif isinstance(inner, fsr.XrefStreamRule):
            d['rule'] = {'kind': 'xref_stream'}
        elif isinstance(inner, fsr.ObjectStreamRule):
            d['rule'] = {'kind': 'object_stream'}
        elif isinstance(inner, ffr.DSSCompareRule):
            d['rule'] = {'kind': 'dss'}
        elif isinstance(inner, mr.MetadataUpdateRule):
            d['rule'] = {
                'kind': 'metadata',
                'check_xml_syntax': inner.check_xml_syntax,
                'always_refuse_stream_override': inner.always_refuse_stream_override,
            }
        else:
            d['rule'] = {'kind': 'unknown', 'class': type(inner).__name__}
        return d
    # ad-hoc test rules: record their output per reviewed revision
    outputs = {}
    for new in new_revisions:
        outputs[str(new.revision)] = [
            {
                'level': level.value,
                'ref': [u.updated_ref.idnum, u.updated_ref.generation],
                'context': _context(u.context_checked),
            }
            for level, u in rule.apply_qualified(old, new)
        ]
    return {'kind': 'fixed', 'class': type(rule).__name__, 'outputs': outputs}


def describe_policy(policy, reader, base_revision):
    if not isinstance(policy, policies.StandardDiffPolicy):
        return {'kind': 'unknown', 'class': type(policy).__name__}
    old = reader.get_historical_resolver(base_revision)
    news = [
        reader.get_historical_resolver(r)
        for r in range(base_revision + 1, reader.xrefs.total_revisions)
    ]
    form = None
    if policy.form_rule is not None:
        fr: FormUpdatingRule = policy.form_rule
        form = {
            'field_rules': [describe_field_rule(r) for r in fr.field_rules],
            'ignored_acroform_keys': sorted(fr.ignored_acroform_keys),
        }
    return {
        'kind': 'standard',
        'is_default': policy is da.DEFAULT_DIFF_POLICY,
        'is_no_changes': policy is da.NO_CHANGES_DIFF_POLICY,
        'global_rules': [describe_rule(r, old, news) for r in policy.global_rules],
        'form_rule': form,
        'reject_object_freeing': policy.reject_object_freeing,
        'ignore_orphaned_objects': policy.ignore_orphaned_objects,
        'ignore_identical_objects': policy.ignore_identical_objects,
    }


def describe_fieldmdp(spec):
    if spec is None:
        return None
    action = {
        FieldMDPAction.ALL: 'all',
        FieldMDPAction.INCLUDE: 'include',
        FieldMDPAction.EXCLUDE: 'exclude',
    }[spec.action]
    return {'action': action, 'fields': list(spec.fields or [])}


_orig_review_file = policies.StandardDiffPolicy.review_file


def _review_file(self, reader, base_revision, field_mdp_spec=None, doc_mdp=None):
    events = _events()
    if events is None or not isinstance(base_revision, int):
        return _orig_review_file(
            self, reader, base_revision, field_mdp_spec, doc_mdp
        )
    sha = record_pdf(reader)
    event = {
        'type': 'review',
        'pdf': sha,
        'strict': reader.strict,
        'base_revision': base_revision,
        'field_mdp': describe_fieldmdp(field_mdp_spec),
        'doc_mdp': doc_mdp.value if doc_mdp is not None else None,
    }
    try:
        event['policy'] = describe_policy(self, reader, base_revision)
    except Exception as e:  # noqa: BLE001
        event['policy'] = {'kind': 'error', 'error': repr(e)}
    events.append(event)
    try:
        result = _orig_review_file(
            self, reader, base_revision, field_mdp_spec, doc_mdp
        )
    except Exception as e:
        event['result'] = {
            'error': type(e).__name__,
            'mro': [c.__name__ for c in type(e).__mro__],
            'message': str(e),
        }
        raise
    if isinstance(result, da.SuspiciousModification):
        event['result'] = {'suspicious': str(result)}
    else:
        event['result'] = {
            'level': result.modification_level.value,
            'changed_form_fields': sorted(result.changed_form_fields),
        }
    return result


policies.StandardDiffPolicy.review_file = _review_file

_orig_load_cache = HistoricalResolver._load_reverse_xref_cache


def _load_reverse_xref_cache(self):
    already = self._indirect_object_access_cache is not None
    try:
        _orig_load_cache(self)
    except Exception as e:
        events = _events()
        if events is not None and not already:
            sha = record_pdf(self.reader)
            events.append(
                {
                    'type': 'usages',
                    'pdf': sha,
                    'strict': self.reader.strict,
                    'revision': self.revision,
                    'error': type(e).__name__,
                    'message': str(e),
                }
            )
        raise
    events = _events()
    if events is None or already:
        return
    sha = record_pdf(self.reader)
    key = (sha, self.revision, _current['id'])
    if key in _seen_usages:
        return
    _seen_usages.add(key)
    cache = self._indirect_object_access_cache or {}
    events.append(
        {
            'type': 'usages',
            'pdf': sha,
            'strict': self.reader.strict,
            'revision': self.revision,
            'paths': {
                f'{ref.idnum} {ref.generation}': sorted(
                    _path(p) for p in paths
                )
                for ref, paths in cache.items()
            },
        }
    )


HistoricalResolver._load_reverse_xref_cache = _load_reverse_xref_cache


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_call(item):
    _current['id'] = item.nodeid.split('::', 1)[1]
    CASES.setdefault(_current['id'], {'events': [], 'outcome': None})
    yield
    _current['id'] = None


def pytest_runtest_logreport(report):
    tid = report.nodeid.split('::', 1)[1]
    case = CASES.setdefault(tid, {'events': [], 'outcome': None})
    if report.when == 'call' or (report.when == 'setup' and report.outcome != 'passed'):
        case['outcome'] = report.outcome


def pytest_sessionfinish(session, exitstatus):
    with open(os.path.join(OUT, 'cases.json'), 'w') as f:
        json.dump(CASES, f, indent=1, sort_keys=True)
