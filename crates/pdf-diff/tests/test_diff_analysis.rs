// Port of pyHanko `pkgs/pyhanko/tests/test_diff_analysis.py` (tag v0.38.1)
// (MIT, see LICENSE-pyHanko).
//
// Each pyHanko test function maps to one Rust test of the same name. pyHanko
// builds its inputs with its own signer and writer; `oracle/capture.sh`
// recorded every difference analysis those tests ran (input file, revision,
// FieldMDP / DocMDP, policy, pyHanko's verdict) into
// `crates/testdata/data/lanes/c/`. The tests replay each recorded
// review with this crate and require the same verdict: the same
// modification level and changed fields when pyHanko accepts, a rejection
// whenever pyHanko rejects. They also compare the reverse cross-reference
// cache with pyHanko's for every recorded call.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use support::{check_function, Divergence, Replay};

/// Cases whose verdict differs from pyHanko (none so far). Every entry
/// must still reject where pyHanko rejects.
const KNOWN_DIVERGENCES: &[Divergence] = &[];

fn check(name: &str) -> Vec<Replay> {
    let known: Vec<Divergence> = KNOWN_DIVERGENCES
        .iter()
        .filter(|d| d.node == name || d.node.starts_with(&format!("{name}[")))
        .map(|d| Divergence {
            node: d.node,
            index: d.index,
            reason: d.reason,
        })
        .collect();
    check_function(name, &known)
}

/// At least one rejected review mentions `needle` (pyHanko asserts on the
/// message).
fn assert_message(replays: &[Replay], needle: &str) {
    assert!(
        replays
            .iter()
            .any(|r| r.port_rejects() && r.message().contains(needle)),
        "no rejection mentions {needle:?}: {:?}",
        replays.iter().map(Replay::message).collect::<Vec<_>>()
    );
}

#[test]
fn test_no_changes_policy() {
    check("test_no_changes_policy");
}

#[test]
fn test_double_sig_add_field() {
    check("test_double_sig_add_field");
}

#[test]
fn test_double_sig_different_pages() {
    check("test_double_sig_different_pages");
}

#[test]
fn test_double_sig_create_deep_field_post_sign() {
    check("test_double_sig_create_deep_field_post_sign");
}

#[test]
fn test_double_sig_fill_deep_field_post_sign() {
    check("test_double_sig_fill_deep_field_post_sign");
}

#[test]
fn test_no_field_type() {
    check("test_no_field_type");
}

#[test]
fn test_double_sig_adobe_reader() {
    check("test_double_sig_adobe_reader");
}

#[test]
fn test_double_sig_adobe_reader_second_created() {
    check("test_double_sig_adobe_reader_second_created");
}

#[test]
fn test_bogus_metadata_manipulation() {
    check("test_bogus_metadata_manipulation");
}

#[test]
fn test_dangerous_xml_metadata_manipulation() {
    check("test_dangerous_xml_metadata_manipulation");
}

#[test]
fn test_double_sig_add_field_annots_indirect() {
    check("test_double_sig_add_field_annots_indirect");
}

#[test]
fn test_double_sig_add_visible_field_approval() {
    check("test_double_sig_add_visible_field_approval");
}

#[test]
fn test_double_sig_add_visible_field_certify() {
    let replays = check("test_double_sig_add_visible_field_certify");
    assert_message(&replays, "only allowed after an approval signature");
}

#[test]
fn test_form_field_ft_tamper() {
    check("test_form_field_ft_tamper");
}

#[test]
fn test_form_field_kids_tamper() {
    check("test_form_field_kids_tamper");
}

#[test]
fn test_pages_kids_tamper() {
    check("test_pages_kids_tamper");
}

#[test]
fn test_form_field_postsign_fill() {
    check("test_form_field_postsign_fill");
}

#[test]
fn test_form_field_postsign_modify() {
    check("test_form_field_postsign_modify");
}

#[test]
fn test_form_field_postsign_modify_undefined_ap_ref() {
    check("test_form_field_postsign_modify_undefined_ap_ref");
}

#[test]
fn test_form_field_in_group_postsign_fill() {
    check("test_form_field_in_group_postsign_fill");
}

#[test]
fn test_form_field_in_group_postsign_fill_other_field() {
    check("test_form_field_in_group_postsign_fill_other_field");
}

#[test]
fn test_form_field_in_group_postsign_modify() {
    check("test_form_field_in_group_postsign_modify");
}

#[test]
fn test_form_field_in_group_locked_postsign_modify_failure() {
    check("test_form_field_in_group_locked_postsign_modify_failure");
}

#[test]
fn test_form_field_in_group_locked_postsign_modify_success() {
    check("test_form_field_in_group_locked_postsign_modify_success");
}

#[test]
fn test_form_field_postsign_fill_pades_lt() {
    check("test_form_field_postsign_fill_pades_lt");
}

#[test]
fn test_fieldmdp_all_pades_lta() {
    check("test_fieldmdp_all_pades_lta");
}

#[test]
fn test_inline_ap_pades_lta() {
    check("test_inline_ap_pades_lta");
}

#[test]
fn test_button_appearance_streams_pades_lta() {
    check("test_button_appearance_streams_pades_lta");
}

#[test]
fn test_form_field_postsign_modify_pades_lt() {
    check("test_form_field_postsign_modify_pades_lt");
}

#[test]
fn test_pades_double_sign() {
    check("test_pades_double_sign");
}

#[test]
fn test_pades_double_sign_delete_dss() {
    check("test_pades_double_sign_delete_dss");
}

#[test]
fn test_pades_double_sign_delete_vri() {
    check("test_pades_double_sign_delete_vri");
}

#[test]
fn test_pades_double_sign_delete_entry_in_vri() {
    check("test_pades_double_sign_delete_entry_in_vri");
}

#[test]
fn test_pades_vri_allow_ts_addition() {
    check("test_pades_vri_allow_ts_addition");
}

#[test]
fn test_pades_dss_object_clobber() {
    check("test_pades_dss_object_clobber");
}

#[test]
fn test_pades_dss_object_typing_tamper() {
    check("test_pades_dss_object_typing_tamper");
}

#[test]
fn test_form_field_structure_modification() {
    check("test_form_field_structure_modification");
}

#[test]
fn test_delete_signature() {
    check("test_delete_signature");
}

#[test]
fn test_rogue_backreferences() {
    check("test_rogue_backreferences");
}

#[test]
fn test_sign_reject_freed() {
    check("test_sign_reject_freed");
}

#[test]
fn test_not_all_paths_cleared() {
    check("test_not_all_paths_cleared");
}

#[test]
fn test_double_signature_certify_first() {
    check("test_double_signature_certify_first");
}

#[test]
fn test_orphan() {
    check("test_orphan");
}

#[test]
fn test_form_field_ap_null() {
    let replays = check("test_form_field_ap_null");
    assert_message(&replays, "AP entry should point to a dictionary");
}

#[test]
fn test_signed_file_diff_proxied_objs() {
    check("test_signed_file_diff_proxied_objs");
}

#[test]
fn test_pades_sign_twice_indirect_arrs() {
    check("test_pades_sign_twice_indirect_arrs");
}

#[test]
fn test_pades_sign_update_dss() {
    check("test_pades_sign_update_dss");
}

#[test]
fn test_double_sign_with_separate_annot() {
    check("test_double_sign_with_separate_annot");
}

#[test]
fn test_validate_separate_annot_with_indir_kids() {
    check("test_validate_separate_annot_with_indir_kids");
}

#[test]
fn test_sign_and_update_with_orphaned_obj() {
    check("test_sign_and_update_with_orphaned_obj");
}

#[test]
fn test_sign_and_update_with_orphaned_obj_and_other_upd() {
    check("test_sign_and_update_with_orphaned_obj_and_other_upd");
}

#[test]
fn test_indir_ref_in_sigref_dict() {
    check("test_indir_ref_in_sigref_dict");
}

#[test]
fn test_skip_diff_scenario_1() {
    check("test_skip_diff_scenario_1");
}

#[test]
fn test_skip_diff_scenario_2() {
    check("test_skip_diff_scenario_2");
}

#[test]
fn test_diff_analysis_circular_structure_tree() {
    let replays = check("test_diff_analysis_circular_structure_tree");
    assert_message(
        &replays,
        "Circular reference in structure tree in mapping stage",
    );
}

#[test]
fn test_delete_sig_annot() {
    check("test_delete_sig_annot");
}

#[test]
fn test_double_sig_delete_old_sig_annot() {
    check("test_double_sig_delete_old_sig_annot");
}

#[test]
fn test_double_sig_different_pages_delete_old_annot() {
    check("test_double_sig_different_pages_delete_old_annot");
}

#[test]
fn test_sign_with_hybrid() {
    check("test_sign_with_hybrid");
}

#[test]
fn test_sign_with_hybrid_sneaky_edit() {
    check("test_sign_with_hybrid_sneaky_edit");
}

#[test]
fn test_diff_analysis_add_extensions_dict() {
    check("test_diff_analysis_add_extensions_dict");
}

#[test]
fn test_diff_analysis_update_indirect_extensions_not_all_paths() {
    let replays = check("test_diff_analysis_update_indirect_extensions_not_all_paths");
    assert_message(&replays, "DontOverrideMe");
}

#[test]
fn test_diff_analysis_modify_type_entry() {
    let replays = check("test_diff_analysis_modify_type_entry");
    assert_message(&replays, "/Type of form field altered");
}

#[test]
fn test_diff_analysis_remove_type_entry() {
    let replays = check("test_diff_analysis_remove_type_entry");
    assert_message(&replays, "/Type of form field deleted");
}

#[test]
fn test_diff_analysis_add_invalid_type_entry() {
    let replays = check("test_diff_analysis_add_invalid_type_entry");
    assert_message(
        &replays,
        "/Type of form field set to something other than /Annot",
    );
}

#[test]
fn test_diff_analysis_add_valid_type_entry() {
    check("test_diff_analysis_add_valid_type_entry");
}

#[test]
fn test_appearance_update_edge_cases() {
    check("test_appearance_update_edge_cases");
}

#[test]
fn test_disallow_appearance_stream_override_if_clobbers() {
    let replays = check("test_disallow_appearance_stream_override_if_clobbers");
    assert_message(&replays, ".FooBar");
}

#[test]
fn test_allow_identical_object_replacement() {
    check("test_allow_identical_object_replacement");
}

#[test]
fn test_stream_and_dict_not_considered_identical() {
    let replays = check("test_stream_and_dict_not_considered_identical");
    assert_message(&replays, ".Root.Foo");
}

#[test]
fn test_allow_identical_object_replacement_nonsensical_obj_nonstrict() {
    check("test_allow_identical_object_replacement_nonsensical_obj_nonstrict");
}

#[test]
fn test_sign_twice_with_undefined_refs_nonstrict() {
    check("test_sign_twice_with_undefined_refs_nonstrict");
}

#[test]
fn test_sign_twice_with_undefined_refs_strict() {
    let replays = check("test_sign_twice_with_undefined_refs_strict");
    assert_message(&replays, "not found");
}

#[test]
fn test_signature_without_type_is_form_filling() {
    check("test_signature_without_type_is_form_filling");
}

#[test]
fn test_fieldmdp_include_does_not_lock_field_with_shared_name_prefix() {
    check("test_fieldmdp_include_does_not_lock_field_with_shared_name_prefix");
}

#[test]
fn test_maliciously_recycled_sig_add_visible_field_approval() {
    let replays = check("test_maliciously_recycled_sig_add_visible_field_approval");
    assert_message(&replays, "references an existing object");
}

#[test]
fn test_recycled_phantom_sig_add_visible_field_approval() {
    let replays = check("test_recycled_phantom_sig_add_visible_field_approval");
    assert_message(&replays, "references an existing object");
}

// ---- tests ported by hand -------------------------------------------------

use std::collections::BTreeSet;

use lopdf::{Dictionary, Object};
use sigis_pdf_diff::{Anchor, Context, PathNode, RawPdfPath, Revision};
use support::{check_usages, node_ids, our_usages, LopdfSource};

fn contents_path() -> RawPdfPath {
    RawPdfPath::of([
        PathNode::from("/Root"),
        "/Pages".into(),
        "/Kids".into(),
        0usize.into(),
        "/Contents".into(),
    ])
}

/// The usages recorded for `name` agree with pyHanko, the first page's
/// content stream is reached through the page tree only, and the cache
/// stays small.
fn check_page_tree_paths(name: &str) {
    for node in node_ids(name) {
        let bad = check_usages(&node);
        assert!(bad.is_empty(), "{}", bad.join("\n"));
        let caches = our_usages(&node);
        assert!(!caches.is_empty());
        for cache in caches {
            let want: BTreeSet<RawPdfPath> = [contents_path()].into_iter().collect();
            assert!(
                cache.values().any(|p| *p == want),
                "no content stream with canonical path only"
            );
            assert!(cache.values().map(BTreeSet::len).sum::<usize>() < 1000);
        }
    }
}

#[test]
fn test_cross_linked_pages_do_not_blow_up_paths() {
    let replays = check("test_cross_linked_pages_do_not_blow_up_paths");
    assert!(!replays.is_empty());
    for cache in our_usages("test_cross_linked_pages_do_not_blow_up_paths") {
        assert!(cache.values().map(BTreeSet::len).sum::<usize>() < 1000);
    }
}

#[test]
fn test_page_tree_not_reentered_via_foreign_kids() {
    check_page_tree_paths("test_page_tree_not_reentered_via_foreign_kids");
}

#[test]
fn test_page_tree_root_not_reentered_from_outside() {
    check_page_tree_paths("test_page_tree_root_not_reentered_from_outside");
}

#[test]
fn test_page_tree_direct_root_node() {
    check_page_tree_paths("test_page_tree_direct_root_node");
}

#[test]
fn test_form_field_manipulate_names() {
    let replays = check("test_form_field_manipulate_names");
    for node in node_ids("test_form_field_manipulate_names") {
        // node ids look like `test_form_field_manipulate_names[new_name0-must be strings]`
        let err = node.rsplit_once('-').unwrap().1.trim_end_matches(']');
        let mine: Vec<&Replay> = replays.iter().filter(|r| r.test_id == node).collect();
        assert!(
            mine.iter()
                .any(|r| r.port_rejects() && r.message().contains(err)),
            "{node}: {:?}",
            mine.iter().map(|r| r.message()).collect::<Vec<_>>()
        );
    }
}

#[test]
fn test_diff_analysis_circular_page_tree() {
    let replays = check("test_diff_analysis_circular_page_tree");
    assert_message(&replays, "Circular reference in page tree in mapping stage");
    // the annotation walker has its own cycle check (defence in depth)
    let (src, _) = support::last_review_source("test_diff_analysis_circular_page_tree");
    let old = Revision::new(&src, 1).unwrap();
    let new = Revision::new(&src, 2).unwrap();
    let err = sigis_pdf_diff::rules::walk_page_tree_annots_unchecked(&old, &new).unwrap_err();
    assert!(
        err.to_string()
            .contains("Circular reference in page tree during annotation"),
        "{err}"
    );
}

#[test]
fn test_check_eq_deref() {
    assert_eq!(Anchor::Trailer, Anchor::Trailer);
    assert_eq!(Anchor::Ref((1, 0)), Anchor::Ref((1, 0)));
    assert_ne!(Anchor::Trailer, Anchor::Ref((1, 0)));
    assert_ne!(Anchor::Ref((1, 0)), Anchor::Trailer);
    assert_ne!(Anchor::Ref((1, 0)), Anchor::Ref((1, 1)));
}

#[test]
fn test_check_relative_context_set() {
    let src = LopdfSource::minimal();
    let rev = Revision::new(&src, 0).unwrap();
    let root_rel = Context::relative(Anchor::Trailer, RawPdfPath::of(["/Root"]));
    let info_rel = Context::relative(Anchor::Trailer, RawPdfPath::of(["/Info"]));
    assert_eq!(
        [root_rel.clone(), info_rel]
            .into_iter()
            .collect::<BTreeSet<_>>()
            .len(),
        2
    );

    let p = |nodes: &[PathNode]| RawPdfPath(nodes.to_vec());
    let a = root_rel
        .descend(&rev, &p(&["/Pages".into()]))
        .unwrap()
        .descend(&rev, &p(&["/Kids".into()]))
        .unwrap()
        .descend(&rev, &p(&[0usize.into()]))
        .unwrap();
    let b = root_rel
        .descend(&rev, &p(&["/Pages".into(), "/Kids".into(), 0usize.into()]))
        .unwrap();
    let root = rev.root().unwrap();
    let Ok(Object::Reference(pages)) = root.as_dict().unwrap().get(b"Pages") else {
        panic!()
    };
    let (anchor, path) = rev
        .relative_to(Anchor::Ref(*pages), &p(&["/Kids".into(), 0usize.into()]))
        .unwrap();
    let c = Context::relative(anchor, path);
    let (anchor, path) = rev
        .relative_to(Anchor::Ref(*pages), &p(&["/Kids".into()]))
        .unwrap();
    let d = Context::relative(anchor, path)
        .descend(&rev, &p(&[0usize.into()]))
        .unwrap();
    let all: BTreeSet<Context> = [a, b, c, d].into_iter().collect();
    assert_eq!(all.len(), 1, "{all:?}");
}

#[test]
fn test_cant_descend_into_non_container() {
    let mut src = LopdfSource::minimal();
    let foo = src.doc.add_object(Object::Name(b"Bar".to_vec()));
    let root_id = src
        .doc
        .trailer
        .get(b"Root")
        .unwrap()
        .as_reference()
        .unwrap();
    src.doc
        .get_dictionary_mut(root_id)
        .unwrap()
        .set("Foo", Object::Reference(foo));
    let rev = Revision::new(&src, 0).unwrap();
    let ctx = Context::relative(Anchor::Ref(foo), RawPdfPath::new());
    let err = ctx.descend(&rev, &RawPdfPath::of(["/Blah"])).unwrap_err();
    assert!(err.to_string().contains("Anchor"), "{err}");
}

#[test]
fn test_is_field_visible() {
    use sigis_pdf_diff::rules::{is_annot_visible, is_field_visible};
    let src = LopdfSource::minimal();
    let rev = Revision::new(&src, 0).unwrap();
    let rect = |r: [i64; 4]| {
        let mut d = Dictionary::new();
        d.set(
            "Rect",
            Object::Array(r.iter().map(|x| Object::Integer(*x)).collect()),
        );
        Object::Dictionary(d)
    };
    let with_kids = |kids: Vec<Object>| {
        let mut d = Dictionary::new();
        d.set("Kids", Object::Array(kids));
        Object::Dictionary(d)
    };
    let empty = Object::Dictionary(Dictionary::new());
    assert!(!is_annot_visible(&rev, &empty).unwrap());
    assert!(!is_field_visible(&rev, &empty).unwrap());
    let mut d = Dictionary::new();
    d.set("Rect", 1);
    assert!(!is_annot_visible(&rev, &Object::Dictionary(d)).unwrap());
    let mut d = Dictionary::new();
    d.set("Rect", Object::Null);
    assert!(!is_annot_visible(&rev, &Object::Dictionary(d)).unwrap());
    assert!(is_field_visible(&rev, &with_kids(vec![rect([1, 2, 3, 4])])).unwrap());
    assert!(is_field_visible(
        &rev,
        &with_kids(vec![rect([0, 0, 0, 0]), rect([1, 2, 3, 4])])
    )
    .unwrap());
    assert!(!is_field_visible(&rev, &with_kids(vec![rect([0, 0, 0, 0])])).unwrap());
}

// ---- skipped: no difference analysis runs in these tests (see PORTING.md) --

#[test]
#[ignore = "skipped: signature coverage is decided by pdf_embedded (lane E) before any difference analysis"]
fn test_anomalous_coverage() {}

#[test]
#[ignore = "skipped: signature coverage is decided by pdf_embedded (lane E) before any difference analysis"]
fn test_tamper_sig_obj() {}

#[test]
#[ignore = "skipped: signing a new deep field, single signed revision, no difference analysis (lane D)"]
fn test_create_deep_sig_field() {}

#[test]
#[ignore = "skipped: signing a new deep field, single signed revision, no difference analysis (lane D)"]
fn test_create_multi_deep_sig_field() {}

#[test]
#[ignore = "skipped: the signer refuses a non-signature field, no difference analysis (lane D)"]
fn test_deep_non_sig_field() {}

#[test]
#[ignore = "skipped: separate widget annotation at signing time, single signed revision (lane D)"]
fn test_simple_sign_with_separate_annot() {}

/// pyHanko's reader rejects xref sections that list an object twice. That
/// is a `sigis-pdf` (lane B) check; this test runs once `PdfFile::parse`
/// implements it.
#[test]
fn test_duplicate_xref_table_entry_rejected() {
    let base = std::fs::read(sigis_testdata::pyhanko(&["pdf", "minimal.pdf"])).unwrap();
    let doc = lopdf::Document::load_mem(&base).unwrap();
    let page = doc.page_iter().next().unwrap();
    let contents = doc
        .get_dictionary(page)
        .unwrap()
        .get(b"Contents")
        .unwrap()
        .as_reference()
        .unwrap();
    let original = doc
        .get_object(contents)
        .unwrap()
        .as_stream()
        .unwrap()
        .content
        .clone();
    let prev = {
        let tail = &base[base.len().saturating_sub(64)..];
        let s = String::from_utf8_lossy(tail);
        let n: String = s
            .rsplit("startxref")
            .next()
            .unwrap()
            .trim()
            .lines()
            .next()
            .unwrap()
            .to_string();
        n.parse::<usize>().unwrap()
    };
    let size = doc.trailer.get(b"Size").unwrap().as_i64().unwrap();
    let root = doc.trailer.get(b"Root").unwrap().as_reference().unwrap();
    for changed_first in [true, false] {
        let mut data = base.clone();
        let mut offsets = Vec::new();
        for content in [
            b"BT /F1 24 Tf 50 700 Td (Hi!) Tj ET".to_vec(),
            original.clone(),
        ] {
            offsets.push(data.len());
            data.extend(
                format!(
                    "{} {} obj\n<< /Length {} >>\nstream\n",
                    contents.0,
                    contents.1,
                    content.len()
                )
                .bytes(),
            );
            data.extend(&content);
            data.extend(b"\nendstream\nendobj\n");
        }
        if !changed_first {
            offsets.reverse();
        }
        let xref_start = data.len();
        data.extend(b"xref\n0 1\n0000000000 65535 f \n");
        for o in &offsets {
            data.extend(format!("{} 1\n{o:010} {:05} n \n", contents.0, contents.1).bytes());
        }
        data.extend(
            format!(
                "trailer\n<< /Size {size} /Root {} 0 R /Prev {prev} >>\n",
                root.0
            )
            .bytes(),
        );
        data.extend(format!("startxref\n{xref_start}\n%%EOF\n").bytes());
        assert!(
            sigis_pdf::PdfFile::parse(&data).is_err(),
            "duplicate xref entry accepted"
        );
    }
}
