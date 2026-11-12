// Exact assertion and parameter port of pyhanko-certvalidator 0.33.0
// tests/test_name_trees.py (MIT, see LICENSE-pyHanko).
use super::name_constraints::*;

fn cases(name: &str) -> Vec<serde_json::Value> {
    let raw = sigis_testdata::read(&["lanes", "r3-s", "pki-certvalidator", "name-tree-cases.json"]);
    let all: serde_json::Value = serde_json::from_slice(&raw).expect("case inventory");
    all[name].as_array().expect("function cases").clone()
}

#[test]
fn test_dns_tree_contains() {
    for c in cases("test_dns_tree_contains") {
        assert_eq!(
            dns_tree_contains(c[0].as_str().unwrap(), c[1].as_str().unwrap()),
            c[2].as_bool().unwrap(),
            "{c}"
        );
    }
}

#[test]
fn test_host_tree_contains() {
    for c in cases("test_host_tree_contains") {
        assert_eq!(
            host_tree_contains(c[0].as_str().unwrap(), c[1].as_str().unwrap()).unwrap(),
            c[2].as_bool().unwrap(),
            "{c}"
        );
    }
}

#[test]
fn test_host_tree_contains_rejects_empty_base() {
    let error = host_tree_contains("", "example.com").unwrap_err();
    assert!(error.contains("with an empty"), "{error}");
}

#[test]
fn test_email_tree_contains() {
    for c in cases("test_email_tree_contains") {
        assert_eq!(
            email_tree_contains(c[0].as_str().unwrap(), c[1].as_str().unwrap()).unwrap(),
            c[2].as_bool().unwrap(),
            "{c}"
        );
    }
}

#[test]
fn test_uri_tree_contains() {
    for c in cases("test_uri_tree_contains") {
        assert_eq!(
            uri_tree_contains(c[0].as_str().unwrap(), c[1].as_str().unwrap()).unwrap(),
            c[2].as_bool().unwrap(),
            "{c}"
        );
    }
}

#[test]
fn test_uri_tree_contains_requires_fqdn() {
    for c in cases("test_uri_tree_contains_requires_fqdn") {
        let error = uri_tree_contains("example.com", c[0].as_str().unwrap()).unwrap_err();
        assert!(error.contains("require URIs"), "{error}");
    }
}
