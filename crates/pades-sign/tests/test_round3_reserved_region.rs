//! Error-preserving reserved-region writes for borrowed caller buffers.
//! Native helper coverage only; no upstream-function credit.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use sigis_pades_sign::pdf::writer::{fill_contents, PlaceholderOffsets};

#[test]
fn invalid_reserved_regions_reject_without_panicking_or_changing_bytes() {
    for (start, end) in [(4, 1), (0, 1), (0, 99), (usize::MAX, usize::MAX)] {
        let mut output = b"<0000>".to_vec();
        let before = output.clone();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            fill_contents(
                &mut output,
                &PlaceholderOffsets {
                    contents_start: start,
                    contents_end: end,
                    byte_range_at: 0,
                },
                &[0xab],
            )
        }));
        assert!(result.is_ok(), "region {start}..{end} must return an error");
        assert!(result.unwrap().is_err(), "region {start}..{end}");
        assert_eq!(output, before);
    }
}

#[test]
fn oversized_cms_preserves_buffer_and_success_updates_only_reserved_hex() {
    let offsets = PlaceholderOffsets {
        contents_start: 0,
        contents_end: 6,
        byte_range_at: 0,
    };
    let mut output = b"<0000>suffix".to_vec();
    let before = output.clone();
    let error = fill_contents(&mut output, &offsets, &[0xab; 3]).unwrap_err();
    assert!(error
        .to_string()
        .contains("Final ByteRange payload larger than expected"));
    assert_eq!(output, before);
    fill_contents(&mut output, &offsets, &[0xab]).unwrap();
    assert_eq!(output, b"<AB00>suffix");
}
