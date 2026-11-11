//! Minimal CFF (Compact Font Format) helpers: reading the `ROS` of a
//! CID-keyed font and post-processing subsets.
//!
//! The subsets produced by the `subsetter` crate number their glyphs
//! consecutively and use the glyph index as CID. pyHanko keeps the original
//! CIDs (CID-keyed fonts) or glyph ids (name-keyed fonts) in content
//! streams, so the subset's charset is rewritten to map each new glyph to
//! its original CID.

use std::ops::Range;

use hanko_core::errors::{HankoError, Result};

fn malformed(msg: &str) -> HankoError {
    HankoError::Malformed(format!("CFF: {msg}"))
}

fn u16_at(d: &[u8], at: usize) -> Option<usize> {
    Some(usize::from(u16::from_be_bytes([*d.get(at)?, *d.get(at + 1)?])))
}

fn offset_at(d: &[u8], at: usize, size: usize) -> Option<usize> {
    let mut v = 0usize;
    for i in 0..size {
        v = (v << 8) | usize::from(*d.get(at + i)?);
    }
    Some(v)
}

/// Parse an INDEX at `at`; returns the item ranges and the end offset.
fn parse_index(d: &[u8], at: usize) -> Option<(Vec<Range<usize>>, usize)> {
    let count = u16_at(d, at)?;
    if count == 0 {
        return Some((Vec::new(), at + 2));
    }
    let off_size = usize::from(*d.get(at + 2)?);
    if !(1..=4).contains(&off_size) {
        return None;
    }
    let offsets_at = at + 3;
    let data_start = offsets_at + (count + 1) * off_size - 1;
    let mut items = Vec::with_capacity(count);
    for i in 0..count {
        let a = offset_at(d, offsets_at + i * off_size, off_size)?;
        let b = offset_at(d, offsets_at + (i + 1) * off_size, off_size)?;
        if b < a || data_start + b > d.len() {
            return None;
        }
        items.push(data_start + a..data_start + b);
    }
    let last = offset_at(d, offsets_at + count * off_size, off_size)?;
    Some((items, data_start + last))
}

/// A DICT operand: its value and its byte range.
#[derive(Clone, Debug)]
struct Operand {
    value: f64,
    range: Range<usize>,
}

/// Parse a DICT in `range`: `(operator, operands)` pairs; two-byte
/// operators are `1200 + b1`.
fn parse_dict(d: &[u8], range: Range<usize>) -> Option<Vec<(u16, Vec<Operand>)>> {
    let mut out = Vec::new();
    let mut operands = Vec::new();
    let mut i = range.start;
    while i < range.end {
        let b0 = *d.get(i)?;
        match b0 {
            0..=11 | 13..=21 => {
                out.push((u16::from(b0), std::mem::take(&mut operands)));
                i += 1;
            }
            12 => {
                let b1 = *d.get(i + 1)?;
                out.push((1200 + u16::from(b1), std::mem::take(&mut operands)));
                i += 2;
            }
            28 => {
                let v = i16::from_be_bytes([*d.get(i + 1)?, *d.get(i + 2)?]);
                operands.push(Operand { value: f64::from(v), range: i..i + 3 });
                i += 3;
            }
            29 => {
                let v = i32::from_be_bytes([*d.get(i + 1)?, *d.get(i + 2)?, *d.get(i + 3)?, *d.get(i + 4)?]);
                operands.push(Operand { value: f64::from(v), range: i..i + 5 });
                i += 5;
            }
            30 => {
                let start = i;
                i += 1;
                let mut text = String::new();
                'nibbles: loop {
                    let b = *d.get(i)?;
                    i += 1;
                    for n in [b >> 4, b & 0x0f] {
                        match n {
                            0..=9 => text.push(char::from(b'0' + n)),
                            0xa => text.push('.'),
                            0xb => text.push('E'),
                            0xc => text.push_str("E-"),
                            0xe => text.push('-'),
                            0xf => break 'nibbles,
                            _ => {}
                        }
                    }
                }
                let value = text.parse().unwrap_or(0.0);
                operands.push(Operand { value, range: start..i });
            }
            32..=246 => {
                operands.push(Operand { value: f64::from(i32::from(b0) - 139), range: i..i + 1 });
                i += 1;
            }
            247..=250 => {
                let b1 = i32::from(*d.get(i + 1)?);
                operands.push(Operand {
                    value: f64::from((i32::from(b0) - 247) * 256 + b1 + 108),
                    range: i..i + 2,
                });
                i += 2;
            }
            251..=254 => {
                let b1 = i32::from(*d.get(i + 1)?);
                operands.push(Operand {
                    value: f64::from(-(i32::from(b0) - 251) * 256 - b1 - 108),
                    range: i..i + 2,
                });
                i += 2;
            }
            _ => return None,
        }
    }
    Some(out)
}

struct TopLevel {
    /// Start of the Top DICT INDEX.
    top_index_start: usize,
    /// End of the Top DICT INDEX.
    top_index_end: usize,
    top_dict: Range<usize>,
    strings: Vec<Range<usize>>,
}

fn top_level(cff: &[u8]) -> Option<TopLevel> {
    let hdr_size = usize::from(*cff.get(2)?);
    let (_, after_names) = parse_index(cff, hdr_size)?;
    let (top_dicts, after_top) = parse_index(cff, after_names)?;
    let (strings, _) = parse_index(cff, after_top)?;
    Some(TopLevel {
        top_index_start: after_names,
        top_index_end: after_top,
        top_dict: top_dicts.first()?.clone(),
        strings,
    })
}

fn push_op(out: &mut Vec<u8>, op: u16) {
    if op >= 1200 {
        out.push(12);
        out.push(u8::try_from(op - 1200).unwrap_or(0));
    } else {
        out.push(u8::try_from(op).unwrap_or(0));
    }
}

/// Shortest DICT integer encoding.
fn push_int(out: &mut Vec<u8>, v: i64) {
    match v {
        -107..=107 => out.push(u8::try_from(v + 139).unwrap_or(139)),
        108..=1131 => {
            let w = v - 108;
            out.push(u8::try_from(w / 256 + 247).unwrap_or(247));
            out.push(u8::try_from(w % 256).unwrap_or(0));
        }
        -1131..=-108 => {
            let w = -v - 108;
            out.push(u8::try_from(w / 256 + 251).unwrap_or(251));
            out.push(u8::try_from(w % 256).unwrap_or(0));
        }
        -32768..=32767 => {
            out.push(28);
            out.extend_from_slice(&i16::try_from(v).unwrap_or(0).to_be_bytes());
        }
        _ => push_int5(out, v),
    }
}

fn push_int5(out: &mut Vec<u8>, v: i64) {
    out.push(29);
    out.extend_from_slice(&i32::try_from(v).unwrap_or(0).to_be_bytes());
}

/// An INDEX with the given items.
fn build_index(items: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&u16::try_from(items.len()).unwrap_or(0).to_be_bytes());
    if items.is_empty() {
        return out;
    }
    let total: usize = items.iter().map(Vec::len).sum::<usize>() + 1;
    let off_size: usize = if total < 0x100 {
        1
    } else if total < 0x1_0000 {
        2
    } else if total < 0x100_0000 {
        3
    } else {
        4
    };
    out.push(u8::try_from(off_size).unwrap_or(4));
    let mut off = 1usize;
    let write_off = |out: &mut Vec<u8>, v: usize| {
        let b = (v as u32).to_be_bytes();
        out.extend_from_slice(&b[4 - off_size..]);
    };
    write_off(&mut out, off);
    for it in items {
        off += it.len();
        write_off(&mut out, off);
    }
    for it in items {
        out.extend_from_slice(it);
    }
    out
}

const FONT_BBOX_OP: u16 = 5;
const CHARSTRINGS_OP: u16 = 17;
const PRIVATE_OP: u16 = 18;
const FONT_MATRIX_OP: u16 = 1207;
const FD_ARRAY_OP: u16 = 1236;
const FD_SELECT_OP: u16 = 1237;

/// Order of Top DICT operators in fontTools' output (`topDictOperators`).
const TOP_ORDER: &[u16] = &[
    1230, 1206, 0, 1, 1200, 2, 3, 4, 1201, 1202, 1203, 1204, 1205, 1206, 1207, 13, 5, 1208, 14, 1221,
    1222, 1223, 1231, 1232, 1233, 1234, 15, 1235, 16, 18, 1237, 1236, 17,
];

fn top_rank(op: u16) -> usize {
    TOP_ORDER.iter().position(|o| *o == op).unwrap_or(TOP_ORDER.len())
}

fn is_default_matrix(ops: &[Operand]) -> bool {
    ops.len() == 6
        && ops
            .iter()
            .zip([0.001, 0.0, 0.0, 0.001, 0.0, 0.0])
            .all(|(o, v)| (o.value - v).abs() < 1e-9)
}

fn is_identity_matrix(ops: &[Operand]) -> bool {
    ops.len() == 6
        && ops
            .iter()
            .zip([1.0, 0.0, 0.0, 1.0, 0.0, 0.0])
            .all(|(o, v)| (o.value - v).abs() < 1e-9)
}

/// Length of an FDSelect at `at` for `n_glyphs` glyphs.
fn fd_select_len(d: &[u8], at: usize, n_glyphs: usize) -> Option<usize> {
    match *d.get(at)? {
        0 => Some(1 + n_glyphs),
        3 => Some(1 + 2 + u16_at(d, at + 1)? * 3 + 2),
        _ => None,
    }
}

/// Rebuild a CID-keyed CFF subset of the `subsetter` crate in the layout
/// fontTools writes (which pyHanko embeds), so that it renders the same:
///
/// * glyph `i` (for `i >= 1`) gets CID `cids[i]` (new format 0 charset);
/// * with `bbox`, the Top DICT's `FontBBox` is replaced (fontTools
///   recomputes it for subsets);
/// * the default Top DICT `FontMatrix` and identity Font DICT matrices are
///   dropped (fontTools writes neither);
/// * structures are laid out in fontTools' order (charset, FDSelect,
///   CharStrings, FDArray, Private DICTs) with the shortest operand
///   encodings.
///
/// Fonts whose Private DICTs have local subroutines are rejected.
pub fn rebuild_subset(cff: &[u8], cids: &[u16], bbox: Option<[i64; 4]>) -> Result<Vec<u8>> {
    let err = |m: &str| malformed(m);
    let tl = top_level(cff).ok_or_else(|| err("could not parse the top-level structures"))?;
    let hdr_size = usize::from(*cff.get(2).ok_or_else(|| err("short header"))?);
    let mut top = parse_dict(cff, tl.top_dict.clone()).ok_or_else(|| err("could not parse the Top DICT"))?;
    let raw = |r: &Range<usize>| cff.get(r.clone()).unwrap_or(&[]).to_vec();
    let off_of = |dict: &[(u16, Vec<Operand>)], op: u16| -> Option<usize> {
        dict.iter().find(|(o, _)| *o == op).and_then(|(_, v)| v.first()).map(|o| o.value as usize)
    };
    let cs_at = off_of(&top, CHARSTRINGS_OP).ok_or_else(|| err("no CharStrings"))?;
    let (cs_items, cs_end) = parse_index(cff, cs_at).ok_or_else(|| err("bad CharStrings"))?;
    let n_glyphs = cs_items.len();
    let charstrings = cff[cs_at..cs_end].to_vec();
    let fds_at = off_of(&top, FD_ARRAY_OP).ok_or_else(|| err("not a CID-keyed font"))?;
    let sel_at = off_of(&top, FD_SELECT_OP).ok_or_else(|| err("no FDSelect"))?;
    let sel_len = fd_select_len(cff, sel_at, n_glyphs).ok_or_else(|| err("bad FDSelect"))?;
    let fd_select = cff.get(sel_at..sel_at + sel_len).ok_or_else(|| err("bad FDSelect"))?.to_vec();
    let (fd_items, _) = parse_index(cff, fds_at).ok_or_else(|| err("bad FDArray"))?;
    // Font DICTs (without Private) and their Private DICTs
    let mut fds: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    for r in fd_items {
        let d = parse_dict(cff, r).ok_or_else(|| err("bad Font DICT"))?;
        let mut body = Vec::new();
        let mut private = Vec::new();
        for (op, operands) in d {
            match op {
                FONT_MATRIX_OP if is_identity_matrix(&operands) => {}
                PRIVATE_OP if operands.len() == 2 => {
                    let (size, at) = (operands[0].value as usize, operands[1].value as usize);
                    let pr = cff.get(at..at + size).ok_or_else(|| err("bad Private DICT"))?;
                    let pd = parse_dict(cff, at..at + size).ok_or_else(|| err("bad Private DICT"))?;
                    if pd.iter().any(|(o, _)| *o == 19) {
                        return Err(err("local subroutines are not supported"));
                    }
                    private = pr.to_vec();
                }
                _ => {
                    for o in &operands {
                        body.extend(raw(&o.range));
                    }
                    push_op(&mut body, op);
                }
            }
        }
        fds.push((body, private));
    }
    let mut charset = vec![0u8];
    for cid in cids.iter().skip(1) {
        charset.extend_from_slice(&cid.to_be_bytes());
    }
    top.retain(|(op, ops)| !(*op == FONT_MATRIX_OP && is_default_matrix(ops)));
    if let Some(b) = bbox {
        top.retain(|(op, _)| *op != FONT_BBOX_OP);
        top.push((FONT_BBOX_OP, Vec::new()));
        let _ = b;
    }
    top.sort_by_key(|(op, _)| top_rank(*op));
    let head = &cff[..hdr_size];
    let names = cff[hdr_size..tl.top_index_start].to_vec();
    let strings_and_gsubrs = cff[tl.top_index_end..].to_vec();
    // strings and global subrs end where the old data began: find the end
    // of the Global Subr INDEX
    let (_, after_strings) = parse_index(cff, tl.top_index_end).ok_or_else(|| err("bad String INDEX"))?;
    let (_, after_gsubrs) = parse_index(cff, after_strings).ok_or_else(|| err("bad GSubr INDEX"))?;
    let strings_and_gsubrs = strings_and_gsubrs[..after_gsubrs - tl.top_index_end].to_vec();
    // iterate until the offsets are stable
    let mut offsets = [0i64; 4]; // charset, FDSelect, CharStrings, FDArray
    let mut private_offsets = vec![0i64; fds.len()];
    for _ in 0..16 {
        let mut top_bytes = Vec::new();
        for (op, operands) in &top {
            match *op {
                FONT_BBOX_OP if bbox.is_some() => {
                    for v in bbox.unwrap_or_default() {
                        push_int(&mut top_bytes, v);
                    }
                }
                CHARSET_OP => push_int(&mut top_bytes, offsets[0]),
                FD_SELECT_OP => push_int(&mut top_bytes, offsets[1]),
                CHARSTRINGS_OP => push_int(&mut top_bytes, offsets[2]),
                FD_ARRAY_OP => push_int(&mut top_bytes, offsets[3]),
                _ => {
                    for o in operands {
                        top_bytes.extend(raw(&o.range));
                    }
                }
            }
            push_op(&mut top_bytes, *op);
        }
        let top_index = build_index(&[top_bytes]);
        let fd_dicts: Vec<Vec<u8>> = fds
            .iter()
            .zip(&private_offsets)
            .map(|((body, private), off)| {
                let mut d = body.clone();
                push_int(&mut d, private.len() as i64);
                push_int(&mut d, *off);
                push_op(&mut d, PRIVATE_OP);
                d
            })
            .collect();
        let fd_index = build_index(&fd_dicts);
        let mut pos = (head.len() + names.len() + top_index.len() + strings_and_gsubrs.len()) as i64;
        let new_offsets = {
            let charset_at = pos;
            pos += charset.len() as i64;
            let sel = pos;
            pos += fd_select.len() as i64;
            let cs = pos;
            pos += charstrings.len() as i64;
            let fda = pos;
            pos += fd_index.len() as i64;
            [charset_at, sel, cs, fda]
        };
        let mut new_private = Vec::new();
        for (_, private) in &fds {
            new_private.push(pos);
            pos += private.len() as i64;
        }
        if new_offsets == offsets && new_private == private_offsets {
            let mut out = head.to_vec();
            if out.len() >= 4 {
                out[3] = if pos < 0x100 { 1 } else if pos < 0x1_0000 { 2 } else if pos < 0x100_0000 { 3 } else { 4 };
            }
            out.extend(names);
            out.extend(top_index);
            out.extend(strings_and_gsubrs);
            out.extend(charset);
            out.extend(fd_select);
            out.extend(charstrings);
            out.extend(fd_index);
            for (_, private) in &fds {
                out.extend_from_slice(private);
            }
            return Ok(out);
        }
        offsets = new_offsets;
        private_offsets = new_private;
    }
    Err(err("could not lay out the font"))
}

const ROS_OP: u16 = 1230;
const CHARSET_OP: u16 = 15;
/// Number of standard strings in CFF.
const N_STD_STRINGS: usize = 391;

/// The `(Registry, Ordering, Supplement)` of a CID-keyed CFF font, or
/// `None` for a name-keyed font.
pub fn read_ros(cff: &[u8]) -> Option<(String, String, i64)> {
    let tl = top_level(cff)?;
    let dict = parse_dict(cff, tl.top_dict.clone())?;
    let (_, ops) = dict.into_iter().find(|(op, _)| *op == ROS_OP)?;
    if ops.len() != 3 {
        return None;
    }
    let string = |sid: f64| -> Option<String> {
        let sid = sid as usize;
        let r = tl.strings.get(sid.checked_sub(N_STD_STRINGS)?)?;
        Some(String::from_utf8_lossy(cff.get(r.clone())?).into_owned())
    };
    Some((string(ops[0].value)?, string(ops[1].value)?, ops[2].value as i64))
}
