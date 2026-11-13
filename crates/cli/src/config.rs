//! CLI configuration derived from pyHanko 0.38.1 (MIT).
use serde::de::DeserializeOwned;
use serde_json::{Map, Value};
use sigis_pades_sign::{
    stamp::{QrStampStyle, StampStyle, TextStampStyle},
    SimpleSigner,
};
use sigis_pki_core::cert::Cert;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};

pub type ConfigResult<T> = Result<T, String>;
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LogLevel {
    Number(i64),
    Name(String),
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogConfig {
    pub level: LogLevel,
    pub output: String,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyUsagePolicy {
    pub key_usage: Option<BTreeSet<String>>,
    pub key_usage_forbidden: Option<BTreeSet<String>>,
    pub extd_key_usage: Option<BTreeSet<String>>,
    pub match_all_key_usages: bool,
    pub explicit_extd_key_usage_required: bool,
}
impl Default for KeyUsagePolicy {
    fn default() -> Self {
        Self {
            key_usage: None,
            key_usage_forbidden: None,
            extd_key_usage: None,
            match_all_key_usages: false,
            explicit_extd_key_usage_required: true,
        }
    }
}
#[derive(Clone, Debug)]
pub struct ValidationSettings {
    pub raw: Value,
    pub trust_roots: Vec<Cert>,
    pub other_certs: Vec<Cert>,
    pub trust_replace: bool,
    pub time_tolerance: i64,
    pub retroactive_revinfo: bool,
    pub key_usage: KeyUsagePolicy,
    pub warnings: Vec<String>,
}
#[derive(Clone, Debug)]
pub struct Identity {
    pub plugin: String,
    pub parameters: BTreeMap<String, Value>,
}
#[derive(Clone, Debug)]
pub struct CliConfig {
    pub raw_config: Value,
    pub validation_contexts: BTreeMap<String, Value>,
    pub stamp_styles: BTreeMap<String, Value>,
    pub default_validation_context: String,
    pub default_stamp_style: String,
    pub time_tolerance: Option<i64>,
    pub retroactive_revinfo: bool,
    pub cache_dir: Option<String>,
    pub identities: BTreeMap<String, Identity>,
    pub log_config: Vec<(Option<String>, LogConfig)>,
    pub plugin_endpoints: Vec<String>,
}

fn dict<'a>(v: &'a Value, name: &str) -> ConfigResult<&'a Map<String, Value>> {
    v.as_object()
        .ok_or_else(|| format!("{name} requires a dictionary to initialise."))
}
fn get<'a>(m: &'a Map<String, Value>, k: &str) -> Option<&'a Value> {
    m.get(k).or_else(|| m.get(&k.replace('-', "_")))
}
fn reject_alias_conflicts(m: &Map<String, Value>, keys: &[&str]) -> ConfigResult<()> {
    let mut seen = BTreeMap::new();
    for (key, value) in m {
        let normalised = key.replace('_', "-");
        if !keys.contains(&normalised.as_str()) {
            continue;
        }
        if let Some((previous, previous_value)) = seen.insert(normalised, (key, value)) {
            if previous_value != value {
                return Err(format!(
                    "Conflicting configuration aliases '{previous}' and '{key}'."
                ));
            }
        }
    }
    Ok(())
}
pub(crate) fn reject_unsupported_outer_aliases(m: &Map<String, Value>, keys: &[&str]) -> ConfigResult<()> {
    reject_alias_conflicts(m, keys)?;
    for (key, value) in m {
        let normalised = key.replace('_', "-");
        if key != &normalised
            && keys.contains(&normalised.as_str())
            && m.get(&normalised) != Some(value)
        {
            return Err(format!(
                "Unsupported configuration alias '{key}'; use '{normalised}'."
            ));
        }
    }
    Ok(())
}
fn string(m: &Map<String, Value>, k: &str) -> ConfigResult<Option<String>> {
    match get(m, k) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.clone())),
        _ => Err(format!("'{k}' must be a string")),
    }
}
fn required(m: &Map<String, Value>, k: &str) -> ConfigResult<String> {
    string(m, k)?.ok_or_else(|| format!("Missing required key '{k}'"))
}
fn truth(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(v) => *v,
        Value::Number(n) => n.as_f64() != Some(0.0),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(m) => !m.is_empty(),
    }
}
fn bool_setting(m: &Map<String, Value>, k: &str, default: bool) -> bool {
    get(m, k).map(truth).unwrap_or(default)
}
fn tolerance(m: &Map<String, Value>) -> ConfigResult<Option<i64>> {
    match get(m, "time-tolerance") {
        None | Some(Value::Null) => Ok(None),
        Some(v) => v
            .as_i64()
            .map(Some)
            .ok_or_else(|| "time-tolerance parameter must be specified in seconds".into()),
    }
}
fn strings(v: &Value, k: &str) -> ConfigResult<Vec<String>> {
    match v {
        Value::String(s) => Ok(vec![s.clone()]),
        Value::Array(a) => a
            .iter()
            .map(|v| {
                v.as_str()
                    .map(str::to_string)
                    .ok_or_else(|| format!("{k} requires strings"))
            })
            .collect(),
        _ => Err(format!("{k} requires a string or list of strings")),
    }
}
fn certs(m: &Map<String, Value>, k: &str) -> ConfigResult<Vec<Cert>> {
    let Some(v) = get(m, k) else {
        return Ok(vec![]);
    };
    let mut out = Vec::new();
    for p in strings(v, k)? {
        let bytes =
            std::fs::read(&p).map_err(|e| format!("Failed to read certificate {p}: {e}"))?;
        out.extend(
            sigis_pades_sign::keys::load_certs_from_pemder_data(&bytes)
                .map_err(|e| e.to_string())?,
        );
    }
    Ok(out)
}
fn named<'a>(raw: &'a Value, section: &str, name: &str) -> ConfigResult<&'a Map<String, Value>> {
    let r = dict(raw, "CLIConfig")?;
    get(r, section)
        .and_then(|v| v.get(name))
        .ok_or_else(|| format!("There is no {section} configuration named '{name}'."))
        .and_then(|v| dict(v, section))
}
fn log_level(v: Option<&Value>, default: Option<i64>) -> ConfigResult<LogLevel> {
    match v {
        Some(Value::String(s)) => Ok(LogLevel::Name(s.clone())),
        Some(Value::Number(n)) => n
            .as_i64()
            .map(LogLevel::Number)
            .ok_or_else(|| "Log levels must be int or str".into()),
        None => default
            .map(LogLevel::Number)
            .ok_or_else(|| "Logging config does not define a log level.".into()),
        _ => Err("Log levels must be int or str".into()),
    }
}
fn log_output(v: Option<&Value>) -> ConfigResult<String> {
    match v {
        None => Ok("stderr".into()),
        Some(Value::String(s)) => Ok(if s.eq_ignore_ascii_case("stdout") {
            "stdout".into()
        } else if s.eq_ignore_ascii_case("stderr") {
            "stderr".into()
        } else {
            s.clone()
        }),
        _ => Err("Log output must be specified as a string.".into()),
    }
}
fn logging(raw: &Map<String, Value>) -> ConfigResult<Vec<(Option<String>, LogConfig)>> {
    let empty = Map::new();
    let m = match get(raw, "logging") {
        None => &empty,
        Some(v) => dict(v, "logging config")?,
    };
    let root = LogConfig {
        level: log_level(get(m, "root-level"), Some(20))?,
        output: log_output(get(m, "root-output"))?,
    };
    let mut out = vec![
        (None, root.clone()),
        (
            Some("signxml.processor".into()),
            LogConfig {
                level: LogLevel::Number(30),
                output: root.output.clone(),
            },
        ),
        (
            Some("fontTools.subset".into()),
            LogConfig {
                level: LogLevel::Number(30),
                output: root.output,
            },
        ),
    ];
    if let Some(v) = get(m, "by-module") {
        for (name, v) in dict(v, "logging.by-module")? {
            let m = dict(v, "module logging")?;
            let l = LogConfig {
                level: log_level(get(m, "level"), None)?,
                output: log_output(get(m, "output"))?,
            };
            if let Some(x) = out
                .iter_mut()
                .find(|x| x.0.as_deref() == Some(name.as_str()))
            {
                x.1 = l;
            } else {
                out.push((Some(name.clone()), l));
            }
        }
    }
    Ok(out)
}

fn validate_yaml_numeric_scalar(value: &str, plain: bool, tag: Option<&str>) -> ConfigResult<()> {
    let explicit = matches!(
        tag,
        Some("tag:yaml.org,2002:int" | "tag:yaml.org,2002:float")
    );
    if !explicit && (!plain || tag.is_some()) {
        return Ok(());
    }
    if !explicit && !value.starts_with(|c: char| c.is_ascii_digit() || matches!(c, '+' | '-' | '.'))
    {
        return Ok(());
    }
    // The older schema can resolve these as octal/sexagesimal numbers or
    // timestamps while the tree loader keeps strings. Reject that type loss
    // instead of letting a string select a context or change boolean truth.
    static LEGACY_OR_TIMESTAMP: std::sync::LazyLock<Result<regex::Regex, regex::Error>> =
        std::sync::LazyLock::new(|| {
            regex::Regex::new(
                r"\A(?:[+-]?(?:0[0-9_]+|[0-9][0-9_]*(?::[0-9_]+)+(?:\.[0-9_]*)?)|[0-9]{4}-[0-9]{1,2}-[0-9]{1,2}(?:[Tt \t].*)?)\z",
            )
        });
    if !explicit
        && LEGACY_OR_TIMESTAMP
            .as_ref()
            .map_err(|e| format!("YAML scalar schema error: {e}"))?
            .is_match(value)
    {
        return Err(format!(
            "Unsupported implicit YAML scalar encoding '{value}'; quote literal strings."
        ));
    }
    // Let the mature loader classify the scalar. This common numeric subset
    // excludes implicit octal/exponent forms that PyYAML sees as truthy strings.
    let classified: serde_yaml::Value = match serde_yaml::from_str(value) {
        Ok(value) => value,
        Err(_) if !explicit => return Ok(()),
        Err(_) => return Err("Unsupported explicit YAML numeric encoding.".into()),
    };
    if let serde_yaml::Value::Number(number) = &classified {
        if number.as_f64().is_some_and(|number| !number.is_finite()) {
            return Err("Unsupported nonfinite YAML number.".into());
        }
    } else if !explicit {
        return Ok(());
    }
    static COMMON_NUMBER: std::sync::LazyLock<Result<regex::Regex, regex::Error>> =
        std::sync::LazyLock::new(|| {
            regex::Regex::new(
                r"\A[+-]?(?:0|[1-9][0-9_]*|0x[0-9a-fA-F_]+|0b[01_]+|(?:[0-9][0-9_]*\.[0-9_]*|\.[0-9_]+)(?:[eE][+-][0-9]+)?)\z",
            )
        });
    let common = COMMON_NUMBER
        .as_ref()
        .map_err(|e| format!("YAML numeric schema error: {e}"))?;
    if !common.is_match(value) {
        return Err(format!(
            "Unsupported ambiguous YAML numeric encoding '{value}'."
        ));
    }
    Ok(())
}

fn reject_nonfinite_yaml_numbers(document: &serde_yaml::Value) -> ConfigResult<()> {
    let mut nodes = vec![document];
    while let Some(node) = nodes.pop() {
        match node {
            serde_yaml::Value::Number(number)
                if number.as_f64().is_some_and(|v| !v.is_finite()) =>
            {
                return Err("Unsupported nonfinite YAML number before JSON conversion.".into());
            }
            serde_yaml::Value::Mapping(mapping) => {
                nodes.extend(mapping.keys());
                nodes.extend(mapping.values());
            }
            serde_yaml::Value::Sequence(sequence) => nodes.extend(sequence),
            serde_yaml::Value::Tagged(tagged) => nodes.push(&tagged.value),
            _ => {}
        }
    }
    Ok(())
}

fn reject_nonstring_yaml_mapping_keys(document: &serde_yaml::Value) -> ConfigResult<()> {
    let mut nodes = vec![document];
    while let Some(node) = nodes.pop() {
        match node {
            serde_yaml::Value::Mapping(mapping) => {
                if mapping
                    .keys()
                    .any(|key| !matches!(key, serde_yaml::Value::String(_)))
                {
                    return Err("YAML mapping keys must be strings.".into());
                }
                nodes.extend(mapping.values());
            }
            serde_yaml::Value::Sequence(sequence) => nodes.extend(sequence),
            serde_yaml::Value::Tagged(tagged) => nodes.push(&tagged.value),
            _ => {}
        }
    }
    Ok(())
}

/// Apply the pinned PyYAML boolean schema without guessing YAML token boundaries.
/// The event parser supplies tags/styles; the independent scanner supplies exact
/// scalar coordinates and detects repeated anchor names. serde_yaml remains the
/// tree, alias, duplicate-key and merge implementation.
fn yaml_frontend(source: &str) -> ConfigResult<String> {
    use yaml_rust2::parser::{Event, Parser};
    use yaml_rust2::scanner::{Scanner, TScalarStyle, Token, TokenType};

    const MAX_INPUT: usize = 4 * 1024 * 1024;
    const MAX_EVENTS: usize = 100_000;
    const MAX_EXPANDED: usize = 16 * 1024 * 1024;
    const MAX_DEPTH: usize = 128;
    if source.len() > MAX_INPUT {
        return Err("Configuration exceeds the YAML input size limit.".into());
    }
    let mut scalars = BTreeMap::new();
    let mut anchor_names = BTreeSet::new();
    let mut scanner = Scanner::new(source.chars());
    let mut tokens = 0usize;
    let mut pending_tag = None;
    while let Some(Token(mark, token)) = scanner.next_token().map_err(|e| e.to_string())? {
        tokens += 1;
        if tokens > MAX_EVENTS {
            return Err("Configuration exceeds the YAML token limit.".into());
        }
        match token {
            TokenType::DocumentStart | TokenType::DocumentEnd => {
                anchor_names.clear();
                pending_tag = None;
            }
            TokenType::Tag(handle, suffix) => pending_tag = Some((mark, handle, suffix)),
            TokenType::Anchor(name) => {
                if !anchor_names.insert(name.clone()) {
                    return Err(format!("Duplicate YAML anchor '{name}'."));
                }
            }
            TokenType::Scalar(style, value) => {
                if scalars
                    .insert(
                        (mark.line(), mark.col()),
                        (style, value, pending_tag.take()),
                    )
                    .is_some()
                {
                    return Err("Ambiguous YAML scalar location.".into());
                }
            }
            _ => pending_tag = None,
        }
    }

    // Marker.index() mixes character and byte offsets after block scalars in
    // this parser version. Map its line/character-column coordinates instead.
    let mut positions = vec![Vec::new()];
    let mut chars = source.char_indices().peekable();
    while let Some((offset, character)) = chars.next() {
        if character == '\r' {
            if chars.peek().is_some_and(|(_, c)| *c == '\n') {
                chars.next();
            }
            positions.push(Vec::new());
        } else if character == '\n' {
            positions.push(Vec::new());
        } else if let Some(line) = positions.last_mut() {
            line.push(offset);
        }
    }

    struct Frame {
        anchor: usize,
        cost: usize,
        mapping: bool,
        next_key: bool,
    }
    fn complete(
        frames: &mut [Frame],
        anchors: &mut BTreeMap<usize, (usize, bool)>,
        anchor: usize,
        cost: usize,
        merge_literal: bool,
    ) -> ConfigResult<()> {
        if cost > MAX_EXPANDED {
            return Err("Configuration exceeds the expanded YAML size limit.".into());
        }
        if anchor != 0 {
            anchors.insert(anchor, (cost, merge_literal));
        }
        if let Some(parent) = frames.last_mut() {
            parent.cost = parent
                .cost
                .checked_add(cost)
                .filter(|cost| *cost <= MAX_EXPANDED)
                .ok_or("Configuration exceeds the expanded YAML size limit.")?;
            if parent.mapping {
                parent.next_key = !parent.next_key;
            }
        }
        Ok(())
    }
    fn tag_name(tag: Option<&yaml_rust2::parser::Tag>) -> Option<String> {
        tag.map(|tag| format!("{}{}", tag.handle, tag.suffix))
            .filter(|name| name != "!")
    }
    fn implicit_bool(value: &str) -> Option<bool> {
        match value {
            "yes" | "Yes" | "YES" | "true" | "True" | "TRUE" | "on" | "On" | "ON" => Some(true),
            "no" | "No" | "NO" | "false" | "False" | "FALSE" | "off" | "Off" | "OFF" => Some(false),
            _ => None,
        }
    }
    let mut parser = Parser::new_from_str(source);
    let mut frames: Vec<Frame> = vec![];
    let mut anchors = BTreeMap::new();
    let mut replacements = vec![];
    let mut documents = 0usize;
    let mut events = 0usize;
    loop {
        let (event, mark) = parser.next_token().map_err(|e| e.to_string())?;
        events += 1;
        if events > MAX_EVENTS {
            return Err("Configuration exceeds the YAML event limit.".into());
        }
        let is_key = frames
            .last()
            .is_some_and(|frame| frame.mapping && frame.next_key);
        let mapping_event = matches!(&event, Event::MappingStart(..));
        match event {
            Event::DocumentStart => {
                documents += 1;
                if documents > 1 {
                    return Err("Multiple YAML configuration documents are unsupported.".into());
                }
            }
            Event::MappingStart(anchor, tag) | Event::SequenceStart(anchor, tag) => {
                let mapping = mapping_event;
                let expected = if mapping {
                    "tag:yaml.org,2002:map"
                } else {
                    "tag:yaml.org,2002:seq"
                };
                if tag_name(tag.as_ref()).is_some_and(|name| name != expected) {
                    return Err("Unsupported or incompatible explicit YAML collection tag.".into());
                }
                if frames.len() >= MAX_DEPTH {
                    return Err("Configuration exceeds the YAML nesting limit.".into());
                }
                frames.push(Frame {
                    anchor,
                    cost: 1,
                    mapping,
                    next_key: true,
                });
            }
            Event::MappingEnd | Event::SequenceEnd => {
                let frame = frames
                    .pop()
                    .ok_or("Unbalanced YAML configuration events.")?;
                complete(&mut frames, &mut anchors, frame.anchor, frame.cost, false)?;
            }
            Event::Alias(anchor) => {
                let (cost, merge_literal) = *anchors
                    .get(&anchor)
                    .ok_or("Recursive or unresolved YAML configuration alias.")?;
                if is_key && merge_literal {
                    return Err("Unsupported alias-encoded YAML merge key.".into());
                }
                complete(&mut frames, &mut anchors, 0, cost, merge_literal)?;
            }
            Event::Scalar(value, style, anchor, tag) => {
                let nonspecific_tag = tag
                    .as_ref()
                    .is_some_and(|tag| tag.handle.is_empty() && tag.suffix == "!");
                let tag = tag_name(tag.as_ref());
                if !is_key
                    && tag.is_none()
                    && style == TScalarStyle::Plain
                    && matches!(value.as_str(), "<<" | "=")
                {
                    return Err(format!("Unsupported implicit YAML value token '{value}'."));
                }
                if let Some(name) = &tag {
                    if !matches!(
                        name.as_str(),
                        "tag:yaml.org,2002:str"
                            | "tag:yaml.org,2002:bool"
                            | "tag:yaml.org,2002:int"
                            | "tag:yaml.org,2002:float"
                            | "tag:yaml.org,2002:null"
                    ) {
                        return Err(format!("Unsupported explicit YAML tag '{name}'."));
                    }
                }
                if is_key && value == "<<" && (style != TScalarStyle::Plain || tag.is_some()) {
                    return Err("Unsupported string-encoded YAML merge key.".into());
                }
                if !value.is_empty() {
                    let actual = scalars
                        .get(&(mark.line(), mark.col()))
                        .ok_or("Missing YAML scalar token at event location.")?;
                    if actual.0 != style || actual.1 != value {
                        return Err("YAML scalar event and token disagree.".into());
                    }
                }
                if nonspecific_tag {
                    let (tag_mark, handle, suffix) = scalars
                        .get(&(mark.line(), mark.col()))
                        .and_then(|scalar| scalar.2.as_ref())
                        .ok_or("Unsupported nonspecific YAML tag location.")?;
                    if !handle.is_empty() || suffix != "!" {
                        return Err("YAML tag event and scanner token disagree.".into());
                    }
                    let start = tag_mark
                        .line()
                        .checked_sub(1)
                        .and_then(|line| positions.get(line))
                        .and_then(|line| line.get(tag_mark.col()))
                        .copied()
                        .ok_or("Unsupported nonspecific YAML tag location.")?;
                    let end = start + 1;
                    if source.get(start..end) != Some("!")
                        || !source
                            .get(end..)
                            .and_then(|tail| tail.chars().next())
                            .is_some_and(char::is_whitespace)
                    {
                        return Err("Unsupported nonspecific YAML tag encoding.".into());
                    }
                    // serde_yaml otherwise treats ! false as a string. Remove
                    // only the exact scanner-confirmed nonspecific tag token.
                    replacements.push((start, end, ""));
                }
                validate_yaml_numeric_scalar(&value, style == TScalarStyle::Plain, tag.as_deref())?;
                let boolean = match tag.as_deref() {
                    Some("tag:yaml.org,2002:bool") => {
                        let boolean = match value.to_ascii_lowercase().as_str() {
                            "true" | "yes" | "on" => true,
                            "false" | "no" | "off" => false,
                            _ => return Err("Invalid explicit YAML boolean value.".into()),
                        };
                        if style != TScalarStyle::Plain
                            && !matches!(value.as_str(), "true" | "false")
                        {
                            return Err(
                                "Unsupported nonplain explicit YAML boolean encoding.".into()
                            );
                        }
                        (style == TScalarStyle::Plain).then_some(boolean)
                    }
                    None if style == TScalarStyle::Plain => implicit_bool(&value),
                    _ => None,
                };
                if let Some(boolean) = boolean {
                    let start = mark
                        .line()
                        .checked_sub(1)
                        .and_then(|line| positions.get(line))
                        .and_then(|line| line.get(mark.col()))
                        .copied()
                        .ok_or("Unsupported YAML boolean scalar location.")?;
                    let end = start
                        .checked_add(value.len())
                        .ok_or("Invalid YAML boolean range.")?;
                    if source.get(start..end) != Some(value.as_str()) || !value.is_ascii() {
                        return Err("Unsupported YAML boolean scalar encoding.".into());
                    }
                    replacements.push((start, end, if boolean { "true" } else { "false" }));
                }
                complete(
                    &mut frames,
                    &mut anchors,
                    anchor,
                    value.len() + 1,
                    value == "<<",
                )?;
            }
            Event::StreamEnd => break,
            _ => {}
        }
    }
    if !frames.is_empty() {
        return Err("Unclosed YAML configuration collection.".into());
    }
    replacements.sort_unstable_by_key(|replacement| replacement.0);
    for pair in replacements.windows(2) {
        if pair[0].1 > pair[1].0 {
            return Err("Overlapping YAML boolean scalar ranges.".into());
        }
    }
    let mut normalised = source.to_owned();
    for (start, end, replacement) in replacements.into_iter().rev() {
        normalised.replace_range(start..end, replacement);
    }
    Ok(normalised)
}

impl CliConfig {
    pub fn parse(yaml: &str) -> ConfigResult<Self> {
        let yaml =
            yaml_frontend(yaml).map_err(|e| format!("Failed to parse configuration: {e}"))?;
        let mut document: serde_yaml::Value = serde_yaml::from_str(&yaml)
            .map_err(|e| format!("Failed to parse configuration: {e}"))?;
        reject_nonfinite_yaml_numbers(&document)?;
        document
            .apply_merge()
            .map_err(|e| format!("Failed to apply YAML configuration merge: {e}"))?;
        if let Some(modules) = document
            .get("logging")
            .and_then(|v| v.get("by-module").or_else(|| v.get("by_module")))
            .and_then(serde_yaml::Value::as_mapping)
        {
            if modules
                .keys()
                .any(|key| !matches!(key, serde_yaml::Value::String(_)))
            {
                return Err("Logger names must be strings.".into());
            }
        }
        reject_nonstring_yaml_mapping_keys(&document)?;
        let raw: Value = serde_json::to_value(document)
            .map_err(|e| format!("Failed to parse configuration: {e}"))?;
        let raw = if raw.is_null() {
            Value::Object(Map::new())
        } else {
            raw
        };
        let m = dict(&raw, "CLIConfig")?;
        reject_unsupported_outer_aliases(
            m,
            &[
                "validation-contexts",
                "default-validation-context",
                "time-tolerance",
                "retroactive-revinfo",
            ],
        )?;
        let mut validation_contexts =
            BTreeMap::from([("default".into(), Value::Object(Map::new()))]);
        if let Some(v) = get(m, "validation-contexts") {
            for (k, v) in dict(v, "validation-contexts")? {
                if let Some(context) = v.as_object() {
                    reject_unsupported_outer_aliases(
                        context,
                        &[
                            "trust",
                            "trust-replace",
                            "other-certs",
                            "time-tolerance",
                            "retroactive-revinfo",
                            "signer-key-usage-policy",
                            "signer-key-usage",
                            "signer-extd-key-usage",
                            "eutl-force-redownload",
                            "eutl-lotl-url",
                            "lotl-tlso-certs",
                            "eutl-territories",
                            "revocation-policy",
                        ],
                    )?;
                }
                validation_contexts.insert(k.clone(), v.clone());
            }
        }
        let mut stamp_styles = BTreeMap::from([(
            "default".into(),
            serde_json::json!({"stamp-text":"Digitally signed by %(signer)s.\nTimestamp: %(ts)s.","background":"__stamp__"}),
        )]);
        if let Some(v) = get(m, "stamp-styles") {
            for (k, v) in dict(v, "stamp-styles")? {
                stamp_styles.insert(k.clone(), v.clone());
            }
        }
        let mut identities = BTreeMap::new();
        if let Some(v) = get(m, "identities") {
            for (k, v) in dict(v, "identities")? {
                let id = dict(v, "Identity")?;
                let mut parameters = BTreeMap::new();
                if let Some(p) = get(id, "parameters") {
                    for (k, v) in dict(p, "Identity.parameters")? {
                        parameters.insert(k.replace('-', "_"), v.clone());
                    }
                }
                identities.insert(
                    k.clone(),
                    Identity {
                        plugin: required(id, "plugin")?,
                        parameters,
                    },
                );
            }
        }
        let c = Self {
            validation_contexts,
            stamp_styles,
            default_validation_context: string(m, "default-validation-context")?
                .unwrap_or_else(|| "default".into()),
            default_stamp_style: string(m, "default-stamp-style")?
                .unwrap_or_else(|| "default".into()),
            time_tolerance: tolerance(m)?,
            retroactive_revinfo: bool_setting(m, "retroactive-revinfo", false),
            cache_dir: string(m, "cache-dir")?,
            identities,
            log_config: logging(m)?,
            plugin_endpoints: get(m, "plugins")
                .map(|v| strings(v, "plugins"))
                .transpose()?
                .unwrap_or_default(),
            raw_config: raw,
        };
        Ok(c)
    }
    pub fn logger(&self, name: Option<&str>) -> Option<&LogConfig> {
        self.log_config
            .iter()
            .find(|x| x.0.as_deref() == name)
            .map(|x| &x.1)
    }
    pub fn root_output(&self) -> &str {
        self.log_config
            .first()
            .map(|x| x.1.output.as_str())
            .unwrap_or("stderr")
    }
    pub fn cache_dir(&self) -> PathBuf {
        self.cache_dir
            .as_ref()
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                std::env::var_os("XDG_CACHE_HOME")
                    .map(PathBuf::from)
                    .unwrap_or_else(|| {
                        std::env::var_os("HOME")
                            .map(PathBuf::from)
                            .unwrap_or_else(std::env::temp_dir)
                            .join(".cache")
                    })
                    .join("pyhanko")
            })
    }
    pub fn validation_settings_raw(&self, name: Option<&str>) -> ConfigResult<&Value> {
        let n = name.unwrap_or(&self.default_validation_context);
        self.validation_contexts
            .get(n)
            .ok_or_else(|| format!("There is no validation context named '{n}'."))
    }
    pub fn key_usages(&self, name: Option<&str>) -> ConfigResult<KeyUsagePolicy> {
        let m = dict(self.validation_settings_raw(name)?, "ValidationContext")?;
        reject_unsupported_outer_aliases(
            m,
            &[
                "signer-key-usage-policy",
                "signer-key-usage",
                "signer-extd-key-usage",
            ],
        )?;
        let raw_policy = get(m, "signer-key-usage-policy")
            .map(|v| dict(v, "KeyUsageConstraints").cloned())
            .transpose()?
            .unwrap_or_default();
        let allowed = [
            "key-usage",
            "key-usage-forbidden",
            "extd-key-usage",
            "match-all-key-usages",
            "explicit-extd-key-usage-required",
        ];
        reject_alias_conflicts(&raw_policy, &allowed)?;
        for (old, new) in [
            ("signer-key-usage", "key-usage"),
            ("signer-extd-key-usage", "extd-key-usage"),
        ] {
            if !raw_policy.contains_key(new) {
                if let Some(legacy) = m.get(old) {
                    if raw_policy
                        .iter()
                        .any(|(key, value)| key.replace('_', "-") == new && value != legacy)
                    {
                        return Err(format!(
                            "Conflicting aliases between underscored nested policy and legacy '{old}' setting."
                        ));
                    }
                }
            }
        }
        let mut p = Map::new();
        for (key, value) in raw_policy {
            let key = key.replace('_', "-");
            if !allowed.contains(&key.as_str()) {
                return Err(format!(
                    "Unexpected key in configuration for KeyUsageConstraints: {key}."
                ));
            }
            p.insert(key, value);
        }
        for (old, new) in [
            ("signer-key-usage", "key-usage"),
            ("signer-extd-key-usage", "extd-key-usage"),
        ] {
            if !p.contains_key(new) {
                if let Some(v) = get(m, old) {
                    p.insert(new.into(), v.clone());
                }
            }
        }
        let usage = |key: &str, extended: bool| -> ConfigResult<Option<BTreeSet<String>>> {
            get(&p, key)
                .map(|v| {
                    strings(v, key).and_then(|ss| {
                        ss.into_iter()
                            .map(|s| normalise_usage(&s, extended))
                            .collect()
                    })
                })
                .transpose()
        };
        Ok(KeyUsagePolicy {
            key_usage: usage("key-usage", false)?,
            key_usage_forbidden: usage("key-usage-forbidden", false)?,
            extd_key_usage: usage("extd-key-usage", true)?,
            match_all_key_usages: bool_setting(&p, "match-all-key-usages", false),
            explicit_extd_key_usage_required: bool_setting(
                &p,
                "explicit-extd-key-usage-required",
                true,
            ),
        })
    }
    pub fn validation_settings(&self, name: Option<&str>) -> ConfigResult<ValidationSettings> {
        let raw = self.validation_settings_raw(name)?.clone();
        let m = dict(&raw, "ValidationContext")?;
        let trust_roots = certs(m, "trust")?;
        let trust_replace = bool_setting(m, "trust-replace", false);
        let warnings = if trust_replace {
            vec![]
        } else if trust_roots.is_empty() {
            vec![
                "No trust roots were configured; falling back to the operating system trust store."
                    .into(),
            ]
        } else {
            vec![
                "Configured trust roots are being combined with the operating system trust store."
                    .into(),
            ]
        };
        Ok(ValidationSettings {
            other_certs: certs(m, "other-certs")?,
            time_tolerance: tolerance(m)?.or(self.time_tolerance).unwrap_or(30),
            retroactive_revinfo: bool_setting(m, "retroactive-revinfo", self.retroactive_revinfo),
            key_usage: self.key_usages(name)?,
            raw,
            trust_roots,
            trust_replace,
            warnings,
        })
    }
    pub fn stamp_style(&self, name: Option<&str>) -> ConfigResult<StampStyle> {
        let n = name.unwrap_or(&self.default_stamp_style);
        let v = self
            .stamp_styles
            .get(n)
            .ok_or_else(|| format!("There is no stamp style named '{n}'."))?;
        let mut m = dict(v, "StampStyle")?.clone();
        let kind = string(&m, "type")?.unwrap_or_else(|| "text".into());
        m.remove("type");
        let v = Value::Object(m);
        match kind.as_str() {
            "text" => TextStampStyle::from_config(&v)
                .map(StampStyle::Text)
                .map_err(|e| e.to_string()),
            "qr" => QrStampStyle::from_config(&v)
                .map(StampStyle::Qr)
                .map_err(|e| e.to_string()),
            _ => Err(format!("Unknown stamp style type '{kind}'")),
        }
    }
    pub fn pkcs11_setup(&self, name: &str) -> ConfigResult<Pkcs11Setup> {
        Pkcs11Setup::parse(named(&self.raw_config, "pkcs11-setups", name)?)
    }
    pub fn pemder_setup(&self, name: &str) -> ConfigResult<KeyFileSetup> {
        KeyFileSetup::parse(named(&self.raw_config, "pemder-setups", name)?, false)
    }
    pub fn pkcs12_setup(&self, name: &str) -> ConfigResult<KeyFileSetup> {
        KeyFileSetup::parse(named(&self.raw_config, "pkcs12-setups", name)?, true)
    }
}

fn normalise_usage(s: &str, ext: bool) -> ConfigResult<String> {
    let key_names = [
        "digital_signature",
        "non_repudiation",
        "key_encipherment",
        "data_encipherment",
        "key_agreement",
        "key_cert_sign",
        "crl_sign",
        "encipher_only",
        "decipher_only",
    ];
    let eku = [
        ("1.3.6.1.5.5.7.3.1", "server_auth"),
        ("1.3.6.1.5.5.7.3.2", "client_auth"),
        ("1.3.6.1.5.5.7.3.3", "code_signing"),
        ("1.3.6.1.5.5.7.3.4", "email_protection"),
        ("1.3.6.1.5.5.7.3.8", "time_stamping"),
        ("1.3.6.1.5.5.7.3.9", "ocsp_signing"),
        ("2.5.29.37.0", "any_extended_key_usage"),
        ("2.16.840.1.101.3.6.7", "piv_content_signing"),
    ];
    if !ext {
        return if key_names.contains(&s) {
            Ok(s.into())
        } else {
            Err(format!("Unknown key usage '{s}'"))
        };
    }
    for (oid, name) in eku {
        if s == oid || s == name {
            return Ok(name.into());
        }
    }
    let arcs = s
        .split('.')
        .map(str::parse::<u64>)
        .collect::<Result<Vec<_>, _>>();
    if let Ok(a) = arcs {
        if a.len() >= 2 && a[0] <= 2 && (a[0] == 2 || a[1] < 40) {
            return Ok(s.into());
        }
    }
    Err(format!("Unknown extended key usage '{s}'"))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PinEntry {
    Prompt,
    Skip,
    Defer,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SigningPinEntry {
    Skip,
    Prompt,
    Reauthenticate,
}
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TokenCriteria {
    pub label: Option<String>,
    pub serial: Option<Vec<u8>>,
}
#[derive(Clone, Debug)]
pub struct Pkcs11Setup {
    pub module_path: String,
    pub token_criteria: Option<TokenCriteria>,
    pub slot_no: Option<u64>,
    pub cert_label: Option<String>,
    pub cert_id: Option<Vec<u8>>,
    pub key_label: Option<String>,
    pub key_id: Option<Vec<u8>>,
    pub signing_certificate: Option<Cert>,
    pub other_certs: Vec<Cert>,
    pub only_resident_certs: bool,
    pub prompt_pin: PinEntry,
    pub signing_pin_mode: SigningPinEntry,
    pub user_pin: Option<String>,
    pub signing_pin: Option<String>,
    pub warnings: Vec<String>,
    pub raw: Value,
}
fn unhex(s: &str) -> ConfigResult<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return Err("Failed to parse value as a hex string".into());
    }
    s.as_bytes()
        .chunks(2)
        .map(|c| {
            std::str::from_utf8(c)
                .ok()
                .and_then(|s| u8::from_str_radix(s, 16).ok())
                .ok_or_else(|| "Failed to parse value as a hex string".into())
        })
        .collect()
}
fn token_id(m: &Map<String, Value>, k: &str) -> ConfigResult<Option<Vec<u8>>> {
    match get(m, k) {
        None => Ok(None),
        Some(Value::String(s)) => unhex(s).map(Some),
        Some(Value::Number(n)) => n
            .as_u64()
            .and_then(|n| u8::try_from(n).ok())
            .map(|n| Some(vec![n]))
            .ok_or_else(|| format!("Invalid {k}")),
        _ => Err(format!("Invalid {k}")),
    }
}
impl Pkcs11Setup {
    fn parse(m: &Map<String, Value>) -> ConfigResult<Self> {
        let mut warnings = vec![];
        let mut token_criteria = get(m, "token-criteria")
            .map(|v| {
                let t = dict(v, "TokenCriteria")?;
                Ok::<_, String>(TokenCriteria {
                    label: string(t, "label")?,
                    serial: string(t, "serial")?.map(|s| unhex(&s)).transpose()?,
                })
            })
            .transpose()?;
        if let Some(label) = string(m, "token-label")? {
            warnings.push("'token_label' is deprecated, use 'token_criteria.label' instead".into());
            let t = token_criteria.get_or_insert_with(TokenCriteria::default);
            if t.label.is_none() {
                t.label = Some(label);
            }
        }
        let (mut key_label, mut key_id) = (string(m, "key-label")?, token_id(m, "key-id")?);
        let (mut cert_label, mut cert_id) = (string(m, "cert-label")?, token_id(m, "cert-id")?);
        let signing_certificate = if let Some(p) = string(m, "signing-certificate")? {
            let b =
                std::fs::read(&p).map_err(|e| format!("Failed to read certificate {p}: {e}"))?;
            Some(Cert::from_pem_or_der(&b).map_err(|e| e.to_string())?)
        } else {
            None
        };
        if key_label.is_none() && key_id.is_none() {
            if cert_label.is_none() && cert_id.is_none() {
                return Err("Either 'key_id', 'key_label', 'cert_label' or 'cert_id',must be provided in PKCS#11 setup".into());
            }
            key_label = cert_label.clone();
            key_id = cert_id.clone();
        }
        if cert_label.is_none() && cert_id.is_none() && signing_certificate.is_none() {
            cert_label = key_label.clone();
            cert_id = key_id.clone();
        }
        let prompt_pin = match get(m, "prompt-pin") {
            None => PinEntry::Prompt,
            Some(Value::String(s)) => match s.to_ascii_lowercase().as_str() {
                "prompt" => PinEntry::Prompt,
                "skip" => PinEntry::Skip,
                "defer" => PinEntry::Defer,
                _ => return Err(format!("Invalid PIN entry mode '{s}'")),
            },
            Some(v) => {
                if truth(v) {
                    PinEntry::Prompt
                } else {
                    PinEntry::Skip
                }
            }
        };
        let signing_pin_mode = match string(m, "signing-pin-mode")?.as_deref().unwrap_or("skip") {
            "skip" => SigningPinEntry::Skip,
            "prompt" => SigningPinEntry::Prompt,
            "reauthenticate" => SigningPinEntry::Reauthenticate,
            s => return Err(format!("Invalid signing PIN entry mode '{s}'")),
        };
        Ok(Self {
            module_path: required(m, "module-path")?,
            token_criteria,
            slot_no: get(m, "slot-no")
                .map(|v| {
                    v.as_u64()
                        .ok_or_else(|| "slot-no must be a nonnegative integer".to_string())
                })
                .transpose()?,
            cert_label,
            cert_id,
            key_label,
            key_id,
            signing_certificate,
            other_certs: certs(m, "other-certs")?,
            only_resident_certs: bool_setting(m, "only-resident-certs", false),
            prompt_pin,
            signing_pin_mode,
            user_pin: string(m, "user-pin")?,
            signing_pin: string(m, "signing-pin")?,
            warnings,
            raw: Value::Object(m.clone()),
        })
    }
}

#[derive(Clone, Debug)]
pub struct KeyFileSetup {
    pub key_file: Option<String>,
    pub cert_file: Option<String>,
    pub pfx_file: Option<String>,
    pub passphrase: Option<Vec<u8>>,
    pub other_certs: Vec<Cert>,
    pub prefer_pss: bool,
}
impl KeyFileSetup {
    fn parse(m: &Map<String, Value>, p12: bool) -> ConfigResult<Self> {
        Ok(Self {
            key_file: if p12 {
                None
            } else {
                Some(required(m, "key-file")?)
            },
            cert_file: if p12 {
                None
            } else {
                Some(required(m, "cert-file")?)
            },
            pfx_file: if p12 {
                Some(required(m, "pfx-file")?)
            } else {
                None
            },
            passphrase: string(
                m,
                if p12 {
                    "pfx-passphrase"
                } else {
                    "key-passphrase"
                },
            )?
            .map(String::into_bytes),
            other_certs: certs(m, "other-certs")?,
            prefer_pss: bool_setting(m, "prefer-pss", false),
        })
    }
    pub fn load_signer(&self, provided_passphrase: Option<&[u8]>) -> ConfigResult<SimpleSigner> {
        let pw = provided_passphrase.or(self.passphrase.as_deref());
        let read = |p: &str| std::fs::read(p).map_err(|e| format!("Failed to read {p}: {e}"));
        let signer = if let Some(p) = &self.pfx_file {
            SimpleSigner::from_pkcs12_with_certs(&read(p)?, pw, self.other_certs.clone())
        } else {
            let key = self
                .key_file
                .as_deref()
                .ok_or_else(|| "Missing key file".to_string())?;
            let cert = self
                .cert_file
                .as_deref()
                .ok_or_else(|| "Missing certificate file".to_string())?;
            SimpleSigner::load(&read(key)?, &read(cert)?, pw, self.other_certs.clone())
        };
        signer
            .map(|s| s.with_prefer_pss(self.prefer_pss))
            .map_err(|e| format!("Could not load signing key: {e}"))
    }
}

/// Load a default or explicitly selected configuration file.
pub fn read_config_file(path: &Path, explicit: bool) -> ConfigResult<Option<CliConfig>> {
    match std::fs::read_to_string(path) {
        Ok(s) => CliConfig::parse(&s).map(Some),
        Err(e) if !explicit && e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(if explicit {
            format!("Failed to read configuration: {e}")
        } else {
            format!("Failed to read {}: {e}", path.display())
        }),
    }
}

/// Recursively decode a typed configuration, accepting hyphenated field keys.
pub fn configurable<T: DeserializeOwned>(value: Value) -> ConfigResult<T> {
    fn normalise(v: Value) -> Value {
        match v {
            Value::Object(m) => Value::Object(
                m.into_iter()
                    .map(|(k, v)| (k.replace('-', "_"), normalise(v)))
                    .collect(),
            ),
            Value::Array(a) => Value::Array(a.into_iter().map(normalise).collect()),
            v => v,
        }
    }
    serde_json::from_value(normalise(value)).map_err(|e| {
        let text = e.to_string();
        if text.contains("missing field") {
            format!("Error while processing configurable field: Missing required key: {text}")
        } else {
            format!("Error while processing configurable field: {text}")
        }
    })
}
