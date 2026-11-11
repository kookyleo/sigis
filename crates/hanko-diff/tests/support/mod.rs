// Test harness derived from pyHanko `pdf_utils/xref.py` (`XRefSectionData.try_resolve`,
// `XRefCache` queries) and `pdf_utils/reader.py` (`HistoricalResolver.get_object`)
// (MIT, see LICENSE-pyHanko).

//! Replays pyHanko's difference analysis records
//! (`crates/hanko-testdata/data/lanes/c/`, produced by `oracle/capture.sh`).
//!
//! [`OracleSource`] is a [`RevisionSource`] built from pyHanko's own
//! cross-reference model of each input file, so these tests exercise the
//! rules independently of `hanko-pdf`. Object values come from `lopdf`,
//! loading the file truncated after the revision that wrote the object.

#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::{Arc, OnceLock};

use hanko_core::errors::{HankoError, Result};
use hanko_diff::rules::{
    BaseFieldModificationRule, CatalogModificationRule, DocInfoRule, DssCompareRule,
    GenericFieldModificationRule, MetadataUpdateRule, ObjectStreamRule, QualifiedWhitelistRule,
    SigFieldCreationRule, SigFieldModificationRule, WhitelistRule, XrefStreamRule,
};
use hanko_diff::{
    Anchor, ConfigurableDiffPolicy, Context, DiffOutcome, DiffResultT, FieldMdpAction,
    FieldMdpRule, FormUpdatingRule, MdpPerm, ModificationLevel, PathNode, RawPdfPath,
    ReferenceUpdate, Revision, RevisionSource, XrefSectionInfo,
};
use lopdf::{Dictionary, Document, Object, ObjectId, StringFormat};
use serde_json::Value;

/// Directory of the lane C fixtures.
pub fn lane_dir() -> PathBuf {
    hanko_testdata::path(&["lanes", "c"])
}

/// The recorded cases (`cases.json`).
pub fn cases() -> &'static Value {
    static CASES: OnceLock<Value> = OnceLock::new();
    CASES.get_or_init(|| {
        let p = lane_dir().join("cases.json");
        let data = std::fs::read(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()));
        serde_json::from_slice(&data).unwrap()
    })
}

#[derive(Clone, Copy, Debug)]
enum Loc {
    Offset,
    InStream,
}

#[derive(Debug, Default)]
struct SecData {
    freed: HashMap<u32, i64>,
    standard: HashMap<u32, (i64, u64)>,
    objstm: HashMap<u32, (u32, u32)>,
    explicit: Vec<(u32, i64)>,
    obj_streams_used: BTreeSet<u32>,
}

#[derive(Debug)]
struct Section {
    size: u32,
    stream_ref: Option<ObjectId>,
    data: SecData,
    hybrid: Option<(Option<ObjectId>, SecData)>,
    trailer: Dictionary,
    eof_end: usize,
    startxref: usize,
}

fn as_u32(v: &Value) -> u32 {
    u32::try_from(v.as_u64().unwrap()).unwrap()
}

fn ref_of(v: &Value) -> Option<ObjectId> {
    let a = v.as_array()?;
    Some((as_u32(&a[0]), u16::try_from(a[1].as_u64().unwrap()).unwrap()))
}

fn parse_data(v: &Value) -> SecData {
    let mut d = SecData::default();
    for (k, g) in v["freed"].as_object().unwrap() {
        d.freed.insert(k.parse().unwrap(), g.as_i64().unwrap());
    }
    for (k, x) in v["standard"].as_object().unwrap() {
        let a = x.as_array().unwrap();
        d.standard.insert(k.parse().unwrap(), (a[0].as_i64().unwrap(), a[1].as_u64().unwrap()));
    }
    for (k, x) in v["objstm"].as_object().unwrap() {
        let a = x.as_array().unwrap();
        d.objstm.insert(k.parse().unwrap(), (as_u32(&a[0]), as_u32(&a[1])));
    }
    for x in v["explicit"].as_array().unwrap() {
        let a = x.as_array().unwrap();
        d.explicit.push((as_u32(&a[0]), a[1].as_i64().unwrap()));
    }
    for x in v["obj_streams_used"].as_array().unwrap() {
        d.obj_streams_used.insert(as_u32(x));
    }
    d
}

/// Decode the JSON encoding of `capture_plugin.enc`.
pub fn dec(v: &Value) -> Object {
    if v.is_null() {
        return Object::Null;
    }
    let (k, x) = v.as_object().unwrap().iter().next().unwrap();
    match k.as_str() {
        "ref" => Object::Reference(ref_of(x).unwrap()),
        "bool" => Object::Boolean(x.as_bool().unwrap()),
        "name" => Object::Name(x.as_str().unwrap().as_bytes()[1..].to_vec()),
        "real" => Object::Real(x.as_str().unwrap().parse().unwrap()),
        "int" => Object::Integer(x.as_i64().unwrap()),
        "str" => Object::String(hex(x.as_str().unwrap()), StringFormat::Literal),
        "dict" | "stream" => Object::Dictionary(dec_dict(x)),
        "arr" => Object::Array(x.as_array().unwrap().iter().map(dec).collect()),
        other => panic!("cannot decode {other}: {x}"),
    }
}

fn dec_dict(v: &Value) -> Dictionary {
    let mut d = Dictionary::new();
    for (k, x) in v.as_object().unwrap() {
        d.set(k.as_bytes()[1..].to_vec(), dec(x));
    }
    d
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

/// A recorded input file with pyHanko's cross-reference model.
pub struct OracleFile {
    pub sha: String,
    bytes: Vec<u8>,
    encrypted: bool,
    sections: Vec<Section>,
    docs: RefCell<HashMap<usize, Rc<Document>>>,
}

impl OracleFile {
    pub fn load(sha: &str) -> Rc<OracleFile> {
        thread_local! {
            static FILES: RefCell<HashMap<String, Rc<OracleFile>>> = RefCell::new(HashMap::new());
        }
        if let Some(f) = FILES.with(|m| m.borrow().get(sha).cloned()) {
            return f;
        }
        let dir = lane_dir();
        let bytes = std::fs::read(dir.join("pdf").join(format!("{sha}.pdf"))).unwrap();
        let model: Value =
            serde_json::from_slice(&std::fs::read(dir.join("model").join(format!("{sha}.json"))).unwrap())
                .unwrap();
        let sections = model["revisions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| Section {
                size: as_u32(&r["meta"]["size"]),
                stream_ref: ref_of(&r["meta"]["stream_ref"]),
                data: parse_data(&r["data"]),
                hybrid: if r["hybrid"].is_null() {
                    None
                } else {
                    Some((ref_of(&r["hybrid"]["meta"]["stream_ref"]), parse_data(&r["hybrid"]["data"])))
                },
                trailer: match dec(&r["trailer"]) {
                    Object::Dictionary(d) => d,
                    other => panic!("trailer {other:?}"),
                },
                eof_end: usize::try_from(r["eof_end"].as_u64().unwrap()).unwrap(),
                startxref: usize::try_from(r["meta"]["declared_startxref"].as_u64().unwrap()).unwrap(),
            })
            .collect();
        let f = Rc::new(OracleFile {
            sha: sha.to_string(),
            bytes,
            encrypted: model["encrypted"].as_bool().unwrap(),
            sections,
            docs: RefCell::new(HashMap::new()),
        });
        FILES.with(|m| m.borrow_mut().insert(sha.to_string(), f.clone()));
        f
    }

    /// The document as of revision `rev`, parsed by lopdf: the file up to
    /// the end of the revisions so far, with a `startxref` that points at
    /// revision `rev`'s section (linearized files write their first-page
    /// section near the start of the file).
    fn doc(&self, rev: usize) -> Rc<Document> {
        if let Some(d) = self.docs.borrow().get(&rev) {
            return d.clone();
        }
        let end = self.sections[..=rev].iter().map(|s| s.eof_end).max().unwrap().min(self.bytes.len());
        let mut buf = self.bytes[..end].to_vec();
        buf.extend(format!("\nstartxref\n{}\n%%EOF\n", self.sections[rev].startxref).bytes());
        let doc = if self.encrypted {
            Document::load_mem_with_options(&buf, lopdf::LoadOptions::with_password("secret"))
        } else {
            Document::load_mem(&buf)
        }
        .unwrap_or_else(|e| panic!("lopdf cannot load {} revision {rev}: {e}", self.sha));
        let doc = Rc::new(doc);
        self.docs.borrow_mut().insert(rev, doc.clone());
        doc
    }

    /// `XRefSectionData.try_resolve`: `Err` = KeyError, `Ok(None)` = freed.
    fn try_resolve(data: &SecData, hybrid: Option<&SecData>, id: ObjectId) -> std::result::Result<Option<Loc>, ()> {
        if id.1 == 0 && data.objstm.contains_key(&id.0) {
            return Ok(Some(Loc::InStream));
        }
        if let Some((g, _)) = data.standard.get(&id.0) {
            return if *g == i64::from(id.1) { Ok(Some(Loc::Offset)) } else { Err(()) };
        }
        if let Some(next) = data.freed.get(&id.0) {
            if i64::from(id.1) == next - 1 {
                return Ok(None);
            }
        }
        match hybrid {
            Some(h) => Self::try_resolve(h, None, id),
            None => Err(()),
        }
    }

    fn resolve_in(&self, ix: usize, id: ObjectId) -> std::result::Result<Option<Loc>, ()> {
        let s = &self.sections[ix];
        Self::try_resolve(&s.data, s.hybrid.as_ref().map(|h| &h.1), id)
    }

    /// `get_historical_ref`, with the index of the resolving section.
    fn historical(&self, id: ObjectId, rev: usize) -> Option<(usize, Option<Loc>)> {
        for ix in (0..=rev).rev() {
            if let Ok(x) = self.resolve_in(ix, id) {
                return Some((ix, x));
            }
        }
        None
    }

    fn last_change_ix(&self, id: ObjectId) -> Option<usize> {
        let mut last = None;
        for (ix, s) in self.sections.iter().enumerate() {
            let mut cands: Vec<(u32, i64)> = s.data.explicit.clone();
            if let Some((_, h)) = &s.hybrid {
                cands.extend(h.explicit.iter().copied());
            }
            if cands.iter().any(|(n, g)| *n == id.0 && *g == i64::from(id.1)) && self.resolve_in(ix, id).is_ok() {
                last = Some(ix);
            }
        }
        last
    }
}

/// [`RevisionSource`] over an [`OracleFile`].
pub struct OracleSource {
    pub file: Rc<OracleFile>,
    pub strict: bool,
}

fn explicit_id((n, g): (u32, i64)) -> ObjectId {
    // pyHanko records "dead" free entries as generation -1
    (n, u16::try_from(g).unwrap_or(u16::MAX))
}

impl RevisionSource for OracleSource {
    fn revision_count(&self) -> Result<usize> {
        Ok(self.file.sections.len())
    }

    fn section(&self, revision: usize) -> Result<XrefSectionInfo> {
        let s = &self.file.sections[revision];
        let mut explicit: BTreeSet<ObjectId> = s.data.explicit.iter().copied().map(explicit_id).collect();
        if let Some((_, h)) = &s.hybrid {
            explicit.extend(h.explicit.iter().copied().map(explicit_id));
        }
        Ok(XrefSectionInfo {
            size: s.size,
            stream_ref: s.stream_ref,
            hybrid_stream_ref: s.hybrid.as_ref().and_then(|h| h.0),
            explicit_refs: explicit,
            freed: s
                .data
                .freed
                .iter()
                .filter(|(_, g)| **g > 0)
                .map(|(n, g)| (*n, u16::try_from(g - 1).unwrap()))
                .collect(),
            object_streams_used: s.data.obj_streams_used.clone(),
        })
    }

    fn object(&self, id: ObjectId, revision: usize) -> Result<Option<Object>> {
        let f = &self.file;
        let marker = match f.last_change_ix(id) {
            Some(last) if last <= revision => f.historical(id, f.sections.len() - 1),
            _ => f.historical(id, revision),
        };
        let Some((ix, Some(_loc))) = marker else { return Ok(None) };
        let doc = f.doc(ix);
        match doc.objects.get(&id) {
            Some(o) => Ok(Some(o.clone())),
            // lopdf drops the encryption dictionary after decrypting; the
            // rules only walk through it (it holds no references)
            None if f.encrypted
                && f.sections[revision].trailer.get(b"Encrypt").ok() == Some(&Object::Reference(id)) =>
            {
                Ok(Some(Object::Dictionary(Dictionary::new())))
            }
            None => Err(HankoError::Malformed(format!(
                "lopdf has no object {} {} in revision {ix} of {}",
                id.0, id.1, f.sha
            ))),
        }
    }

    fn trailer(&self, revision: usize) -> Result<Dictionary> {
        Ok(self.file.sections[revision].trailer.clone())
    }

    fn last_change(&self, id: ObjectId) -> Result<Option<usize>> {
        Ok(self.file.last_change_ix(id))
    }

    fn introducing_revision(&self, id: ObjectId) -> Result<Option<usize>> {
        for ix in 0..self.file.sections.len() {
            if let Ok(Some(_)) = self.file.resolve_in(ix, id) {
                return Ok(Some(ix));
            }
        }
        Ok(None)
    }

    fn resolves_in(&self, id: ObjectId, revision: usize) -> Result<bool> {
        Ok(matches!(self.file.historical(id, revision), Some((_, Some(_)))))
    }

    fn strict(&self) -> bool {
        self.strict
    }
}

fn level(v: &Value) -> ModificationLevel {
    match v.as_u64().unwrap() {
        0 => ModificationLevel::None,
        1 => ModificationLevel::LtaUpdates,
        2 => ModificationLevel::FormFilling,
        3 => ModificationLevel::Annotations,
        _ => ModificationLevel::Other,
    }
}

fn keys(v: &Value) -> Vec<Vec<u8>> {
    v.as_array().unwrap().iter().map(|k| k.as_str().unwrap().as_bytes()[1..].to_vec()).collect()
}

fn path_of(v: &Value) -> RawPdfPath {
    RawPdfPath(
        v.as_array()
            .unwrap()
            .iter()
            .map(|n| match n {
                Value::String(s) => PathNode::from(s.as_str()),
                Value::Number(i) => PathNode::Index(usize::try_from(i.as_u64().unwrap()).unwrap()),
                other => panic!("path node {other}"),
            })
            .collect(),
    )
}

/// A test rule replaying recorded outputs (pyHanko tests define ad-hoc
/// rules).
#[derive(Debug)]
struct FixedRule {
    outputs: BTreeMap<usize, Vec<(ModificationLevel, ReferenceUpdate)>>,
}

impl QualifiedWhitelistRule for FixedRule {
    fn apply_qualified(
        &self,
        _old: &Revision<'_>,
        new: &Revision<'_>,
    ) -> DiffResultT<Vec<(ModificationLevel, ReferenceUpdate)>> {
        Ok(self.outputs.get(&new.revision()).cloned().unwrap_or_default())
    }
}

fn base_rule(v: &Value) -> BaseFieldModificationRule {
    BaseFieldModificationRule {
        allow_in_place_appearance_stream_changes: v["allow_in_place_appearance_stream_changes"]
            .as_bool()
            .unwrap(),
        always_modifiable: keys(&v["always_modifiable"]),
        value_update_keys: keys(&v["value_update_keys"]),
    }
}

/// Build the policy described by a recorded review.
pub fn build_policy(v: &Value) -> ConfigurableDiffPolicy {
    assert_eq!(v["kind"], "standard", "policy {v}");
    let mut rules: Vec<Arc<dyn QualifiedWhitelistRule>> = Vec::new();
    for r in v["global_rules"].as_array().unwrap() {
        match r["kind"].as_str().unwrap() {
            "catalog" => rules.push(Arc::new(CatalogModificationRule { ignored_keys: keys(&r["ignored_keys"]) })),
            "qualified" => {
                let l = level(&r["level"]);
                let inner = &r["rule"];
                match inner["kind"].as_str().unwrap() {
                    "doc_info" => rules.push(Arc::new(DocInfoRule.as_qualified(l))),
                    "xref_stream" => rules.push(Arc::new(XrefStreamRule.as_qualified(l))),
                    "object_stream" => rules.push(Arc::new(ObjectStreamRule.as_qualified(l))),
                    "dss" => rules.push(Arc::new(DssCompareRule.as_qualified(l))),
                    "metadata" => rules.push(Arc::new(
                        MetadataUpdateRule {
                            check_xml_syntax: inner["check_xml_syntax"].as_bool().unwrap(),
                            always_refuse_stream_override: inner["always_refuse_stream_override"]
                                .as_bool()
                                .unwrap(),
                        }
                        .as_qualified(l),
                    )),
                    other => panic!("unknown rule {other}"),
                }
            }
            "fixed" => {
                let mut outputs = BTreeMap::new();
                for (rev, ups) in r["outputs"].as_object().unwrap() {
                    let list = ups
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|u| {
                            let ctx = &u["context"];
                            let context = if ctx.is_null() {
                                None
                            } else if let Some(p) = ctx.get("absolute") {
                                Some(Context::Absolute(path_of(p)))
                            } else {
                                let rel = &ctx["relative"];
                                let anchor = match ref_of(&rel["anchor"]) {
                                    Some(r) => Anchor::Ref(r),
                                    None => Anchor::Trailer,
                                };
                                Some(Context::Relative { anchor, path: path_of(&rel["path"]) })
                            };
                            (
                                level(&u["level"]),
                                ReferenceUpdate { updated_ref: ref_of(&u["ref"]).unwrap(), context_checked: context },
                            )
                        })
                        .collect();
                    outputs.insert(rev.parse().unwrap(), list);
                }
                rules.push(Arc::new(FixedRule { outputs }));
            }
            other => panic!("unknown rule kind {other}"),
        }
    }
    let form_rule = if v["form_rule"].is_null() {
        None
    } else {
        let fr = &v["form_rule"];
        let field_rules: Vec<Arc<dyn FieldMdpRule>> = fr["field_rules"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| -> Arc<dyn FieldMdpRule> {
                match r["kind"].as_str().unwrap() {
                    "sig_field_creation" => Arc::new(SigFieldCreationRule {
                        approve_widget_bindings: r["approve_widget_bindings"].as_bool().unwrap(),
                        allow_new_visible_after_certify: r["allow_new_visible_after_certify"]
                            .as_bool()
                            .unwrap(),
                    }),
                    "sig_field_modification" => Arc::new(SigFieldModificationRule { base: base_rule(r) }),
                    "generic_field_modification" => {
                        Arc::new(GenericFieldModificationRule { base: base_rule(r) })
                    }
                    other => panic!("unknown field rule {other}"),
                }
            })
            .collect();
        Some(FormUpdatingRule { field_rules, ignored_acroform_keys: keys(&fr["ignored_acroform_keys"]) })
    };
    ConfigurableDiffPolicy {
        global_rules: rules,
        form_rule,
        reject_object_freeing: v["reject_object_freeing"].as_bool().unwrap(),
        ignore_orphaned_objects: v["ignore_orphaned_objects"].as_bool().unwrap(),
        ignore_identical_objects: v["ignore_identical_objects"].as_bool().unwrap(),
    }
}

fn field_mdp(v: &Value) -> Option<FieldMdpAction> {
    if v.is_null() {
        return None;
    }
    let fields: Vec<String> =
        v["fields"].as_array().unwrap().iter().map(|f| f.as_str().unwrap().to_string()).collect();
    Some(match v["action"].as_str().unwrap() {
        "all" => FieldMdpAction::All,
        "include" => FieldMdpAction::Include(fields),
        _ => FieldMdpAction::Exclude(fields),
    })
}

fn doc_mdp(v: &Value) -> Option<MdpPerm> {
    match v.as_u64() {
        None => None,
        Some(1) => Some(MdpPerm::NoChanges),
        Some(2) => Some(MdpPerm::FillForms),
        Some(_) => Some(MdpPerm::Annotate),
    }
}

/// The outcome of one replayed review.
#[derive(Debug)]
pub struct Replay {
    pub test_id: String,
    pub index: usize,
    pub expected: Value,
    pub actual: Result<DiffOutcome>,
}

impl Replay {
    /// pyHanko rejected (suspicious or error).
    pub fn pyhanko_rejects(&self) -> bool {
        self.expected.get("level").is_none()
    }

    /// The port rejected.
    pub fn port_rejects(&self) -> bool {
        !matches!(self.actual, Ok(DiffOutcome::Reviewed(_)))
    }

    /// Same verdict class and, for accepted reviews, same level and fields.
    pub fn agrees(&self) -> bool {
        let e = &self.expected;
        match &self.actual {
            Ok(DiffOutcome::Reviewed(r)) => {
                e.get("level").is_some_and(|l| level(l) == r.modification_level)
                    && e["changed_form_fields"]
                        .as_array()
                        .is_some_and(|f| {
                            let exp: BTreeSet<String> =
                                f.iter().map(|x| x.as_str().unwrap().to_string()).collect();
                            exp == r.changed_form_fields
                        })
            }
            Ok(DiffOutcome::Suspicious(_)) => e.get("suspicious").is_some(),
            Err(_) => e.get("error").is_some(),
        }
    }

    pub fn message(&self) -> String {
        match &self.actual {
            Ok(DiffOutcome::Suspicious(m)) => m.clone(),
            Err(e) => e.to_string(),
            Ok(DiffOutcome::Reviewed(r)) => format!("{r:?}"),
        }
    }
}

/// Node ids recorded for the pyHanko test function `name` (including all
/// parametrisations).
pub fn node_ids(name: &str) -> Vec<String> {
    cases()
        .as_object()
        .unwrap()
        .keys()
        .filter(|k| *k == name || k.starts_with(&format!("{name}[")))
        .cloned()
        .collect()
}

/// Replay all reviews recorded for one node id.
pub fn replay_node(test_id: &str) -> Vec<Replay> {
    let case = &cases()[test_id];
    let mut out = Vec::new();
    for (index, ev) in case["events"].as_array().unwrap().iter().enumerate() {
        if ev["type"] != "review" {
            continue;
        }
        let file = OracleFile::load(ev["pdf"].as_str().unwrap());
        let src = OracleSource { file, strict: ev["strict"].as_bool().unwrap() };
        let policy = build_policy(&ev["policy"]);
        let base = usize::try_from(ev["base_revision"].as_u64().unwrap()).unwrap();
        let fm = field_mdp(&ev["field_mdp"]);
        let actual = policy.review_source(&src, base, fm.as_ref(), doc_mdp(&ev["doc_mdp"]));
        out.push(Replay { test_id: test_id.to_string(), index, expected: ev["result"].clone(), actual });
    }
    out
}

/// Compare the reverse cross-reference cache with pyHanko's for every
/// recorded `_load_reverse_xref_cache` call of a node id. Returns the
/// mismatches.
pub fn check_usages(test_id: &str) -> Vec<String> {
    let case = &cases()[test_id];
    let mut bad = Vec::new();
    for ev in case["events"].as_array().unwrap() {
        if ev["type"] != "usages" {
            continue;
        }
        let file = OracleFile::load(ev["pdf"].as_str().unwrap());
        let src = OracleSource { file, strict: ev["strict"].as_bool().unwrap() };
        let rev = usize::try_from(ev["revision"].as_u64().unwrap()).unwrap();
        let revision = Revision::new(&src, rev);
        let ours = revision.as_ref().map_err(|e| e.to_string()).and_then(|r| {
            r.usages().cloned().map_err(|e| e.to_string())
        });
        match (ev.get("paths"), ours) {
            (Some(paths), Ok(ours)) => {
                let mut theirs: BTreeMap<ObjectId, BTreeSet<RawPdfPath>> = BTreeMap::new();
                for (k, ps) in paths.as_object().unwrap() {
                    let mut it = k.split(' ');
                    let id = (it.next().unwrap().parse().unwrap(), it.next().unwrap().parse().unwrap());
                    theirs.insert(id, ps.as_array().unwrap().iter().map(path_of).collect());
                }
                let ours: BTreeMap<ObjectId, BTreeSet<RawPdfPath>> =
                    ours.into_iter().map(|(k, v)| (k, v.into_iter().collect())).collect();
                // Known divergence: in encrypted files pyHanko's nested direct
                // containers are decryption proxies, which its path walk does
                // not enter. The port walks them, so its paths must be a
                // superset of pyHanko's (more paths to clear = stricter).
                if src.file.encrypted {
                    let covered = theirs.iter().all(|(k, ps)| ours.get(k).is_some_and(|o| o.is_superset(ps)));
                    assert!(ours != theirs, "{test_id} rev {rev}: encrypted-file divergence no longer occurs");
                    if !covered {
                        bad.push(format!("{test_id} rev {rev}: encrypted file, paths not a superset of pyHanko's"));
                    }
                    continue;
                }
                if ours != theirs {
                    let diff: Vec<String> = theirs
                        .keys()
                        .chain(ours.keys())
                        .collect::<BTreeSet<_>>()
                        .into_iter()
                        .filter(|k| ours.get(k) != theirs.get(k))
                        .take(5)
                        .map(|k| format!("{k:?}: ours {:?} theirs {:?}", ours.get(k), theirs.get(k)))
                        .collect();
                    bad.push(format!("{test_id} rev {rev}: {}", diff.join("; ")));
                }
            }
            (None, Err(_)) => {}
            (Some(_), Err(e)) => bad.push(format!("{test_id} rev {rev}: we fail ({e}), pyHanko succeeds")),
            (None, Ok(_)) => bad.push(format!(
                "{test_id} rev {rev}: pyHanko fails ({}), we succeed",
                ev["message"]
            )),
        }
    }
    bad
}

/// A case whose verdict is known to differ from pyHanko, with the reason.
/// The port must still reject whenever pyHanko rejects.
pub struct Divergence {
    pub node: &'static str,
    pub index: usize,
    pub reason: &'static str,
}

/// Replay every node of `name`; panics on unlisted divergences, on listed
/// divergences that now agree, and on any fail-open divergence. Returns the
/// replays for extra assertions.
pub fn check_function(name: &str, known: &[Divergence]) -> Vec<Replay> {
    let nodes = node_ids(name);
    assert!(!nodes.is_empty(), "no recorded cases for {name}");
    let mut all = Vec::new();
    let mut problems = Vec::new();
    for node in &nodes {
        let outcome = &cases()[node]["outcome"];
        assert_eq!(outcome, "passed", "{node} did not pass in pyHanko");
        for r in replay_node(node) {
            let listed = known.iter().any(|d| d.node == node && d.index == r.index);
            if r.pyhanko_rejects() && !r.port_rejects() {
                problems.push(format!(
                    "FAIL-OPEN {node}#{}: pyHanko {} but port accepts: {}",
                    r.index,
                    r.expected,
                    r.message()
                ));
            } else if !r.agrees() && !listed {
                problems.push(format!(
                    "{node}#{}: pyHanko {} vs port {}",
                    r.index,
                    r.expected,
                    r.message()
                ));
            } else if r.agrees() && listed {
                problems.push(format!("{node}#{}: listed divergence now agrees", r.index));
            }
            all.push(r);
        }
        problems.extend(check_usages(node));
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
    all
}

/// A single-revision [`RevisionSource`] over a lopdf document (for tests on
/// documents built in memory).
pub struct LopdfSource {
    pub doc: Document,
}

impl LopdfSource {
    pub fn minimal() -> LopdfSource {
        let bytes = std::fs::read(hanko_testdata::pyhanko(&["pdf", "minimal.pdf"])).unwrap();
        LopdfSource { doc: Document::load_mem(&bytes).unwrap() }
    }
}

impl RevisionSource for LopdfSource {
    fn revision_count(&self) -> Result<usize> {
        Ok(1)
    }
    fn section(&self, _revision: usize) -> Result<XrefSectionInfo> {
        Ok(XrefSectionInfo {
            size: self.doc.max_id + 1,
            explicit_refs: self.doc.objects.keys().copied().collect(),
            ..Default::default()
        })
    }
    fn object(&self, id: ObjectId, _revision: usize) -> Result<Option<Object>> {
        Ok(self.doc.objects.get(&id).cloned())
    }
    fn trailer(&self, _revision: usize) -> Result<Dictionary> {
        Ok(self.doc.trailer.clone())
    }
    fn last_change(&self, id: ObjectId) -> Result<Option<usize>> {
        Ok(self.doc.objects.contains_key(&id).then_some(0))
    }
    fn introducing_revision(&self, id: ObjectId) -> Result<Option<usize>> {
        self.last_change(id)
    }
    fn resolves_in(&self, id: ObjectId, _revision: usize) -> Result<bool> {
        Ok(self.doc.objects.contains_key(&id))
    }
}

/// Our reverse cross-reference caches for the recorded `usages` events of a
/// node id.
pub fn our_usages(test_id: &str) -> Vec<BTreeMap<ObjectId, BTreeSet<RawPdfPath>>> {
    let case = &cases()[test_id];
    let mut out = Vec::new();
    for ev in case["events"].as_array().unwrap() {
        if ev["type"] != "usages" {
            continue;
        }
        let file = OracleFile::load(ev["pdf"].as_str().unwrap());
        let src = OracleSource { file, strict: ev["strict"].as_bool().unwrap() };
        let rev = Revision::new(&src, usize::try_from(ev["revision"].as_u64().unwrap()).unwrap()).unwrap();
        out.push(rev.usages().unwrap().iter().map(|(k, v)| (*k, v.iter().cloned().collect())).collect());
    }
    out
}

/// Replay of the last recorded review of a node id, with its source.
pub fn last_review_source(test_id: &str) -> (OracleSource, usize) {
    let case = &cases()[test_id];
    let ev = case["events"]
        .as_array()
        .unwrap()
        .iter()
        .rev()
        .find(|e| e["type"] == "review")
        .unwrap();
    let file = OracleFile::load(ev["pdf"].as_str().unwrap());
    (
        OracleSource { file, strict: ev["strict"].as_bool().unwrap() },
        usize::try_from(ev["base_revision"].as_u64().unwrap()).unwrap(),
    )
}
