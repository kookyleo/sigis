// Derived from pyhanko-certvalidator name_trees.py (MIT, see LICENSE-pyHanko).
//! Normalized DNS, host, email and URI constraints used by path validation.

fn normalize_host(host: &str) -> String {
    let host = if host.len() > 1 { host.strip_suffix('.').unwrap_or(host) } else { host };
    host.to_ascii_lowercase()
}

pub(super) fn dns_tree_contains(base: &str, other: &str) -> bool {
    let base = normalize_host(base);
    let other = normalize_host(other);
    let mut other_labels = other.rsplit('.');
    base.rsplit('.').all(|label| other_labels.next() == Some(label))
}

pub(super) fn host_tree_contains(base: &str, other: &str) -> Result<bool, &'static str> {
    let base = normalize_host(base);
    let other = normalize_host(other);
    if base.is_empty() {
        return Err("A constraint with an empty host name is undefined.");
    }
    Ok(if base.starts_with('.') {
        other.len() > base.len() && other.ends_with(&base)
    } else {
        other == base
    })
}

pub(super) fn email_tree_contains(base: &str, other: &str) -> Result<bool, &'static str> {
    let (base_local, base_host) = base.rsplit_once('@').unwrap_or(("", base));
    let (other_local, other_host) = other.rsplit_once('@').unwrap_or(("", other));
    if !base_local.is_empty() {
        Ok(base_local == other_local && normalize_host(base_host) == normalize_host(other_host))
    } else {
        host_tree_contains(base_host, other_host)
    }
}

pub(super) fn uri_tree_contains(base: &str, other: &str) -> Result<bool, &'static str> {
    const INVALID_URI: &str = "URI constraints require URIs with a host specified as a FQDN";
    let (scheme, rest) = other.split_once("://").ok_or(INVALID_URI)?;
    if scheme.is_empty() || !scheme.as_bytes()[0].is_ascii_alphabetic()
        || !scheme.bytes().all(|b| b.is_ascii_alphanumeric() || b"+-.".contains(&b)) {
        return Err(INVALID_URI);
    }
    let authority = rest.split(['/', '?', '#']).next().ok_or(INVALID_URI)?;
    let authority = authority.rsplit('@').next().ok_or(INVALID_URI)?;
    let host = authority.split(':').next().ok_or(INVALID_URI)?;
    if host.is_empty() || host.starts_with('[') || host.parse::<std::net::Ipv4Addr>().is_ok()
        || host.chars().any(|c| c.is_whitespace() || matches!(c, '[' | ']')) {
        return Err(INVALID_URI);
    }
    host_tree_contains(base, host)
}
