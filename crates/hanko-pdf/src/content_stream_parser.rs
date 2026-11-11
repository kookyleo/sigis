// Derived from pyHanko `pdf_utils/content_stream_parser.py`
// (MIT, see LICENSE-pyHanko).

//! Graphics operator parser for content streams
//! (`pyhanko.pdf_utils.content_stream_parser`).

use lopdf::{Object, ObjectId};

use crate::error::{PdfError, PdfResult};
use crate::generic::{read_item, ContentOpReading, Item, ParseContext};
use crate::misc::{skip_over_comments, skip_over_whitespace, Cursor};
use crate::rw_common::{PdfHandler, PdfHandlerExt};

/// A graphics operator with its operands (`GraphicsOperator`).
#[derive(Clone, Debug, PartialEq)]
pub struct GraphicsOperator {
    /// The operator.
    pub op: String,
    /// The operands.
    pub args: Vec<Object>,
    /// Where the operands start: (stream, offset).
    pub start: (ObjectId, usize),
    /// Where the operator ends: (stream, offset).
    pub end: (ObjectId, usize),
}

/// Parse a content stream given as decoded parts, each with the reference of
/// its stream object (`parse_content_stream`). Operands may span parts.
pub fn parse_content_stream(parts: &[(ObjectId, Vec<u8>)]) -> PdfResult<Vec<GraphicsOperator>> {
    let mut out = Vec::new();
    let mut start: Option<(ObjectId, usize)> = None;
    let mut args: Vec<Object> = Vec::new();
    let ctx = ParseContext::default();
    for (current_ref, data) in parts {
        let mut stream = Cursor::new(data);
        let total = data.len();
        skip_over_whitespace(&mut stream, false, false)?;
        skip_over_comments(&mut stream, false)?;
        loop {
            let pos = stream.tell();
            if pos >= total {
                break;
            }
            let item = read_item(&mut stream, &ctx, ContentOpReading::GraphicOps)?;
            if start.is_none() {
                args = Vec::new();
                start = Some((*current_ref, pos));
            }
            match item {
                Item::Operator(op) => {
                    if op == "BI" {
                        return Err(PdfError::read(
                            "Content streams with inline images are not supported",
                        ));
                    }
                    let end = (*current_ref, pos + op.len());
                    out.push(GraphicsOperator {
                        op,
                        args: std::mem::take(&mut args),
                        start: start.take().unwrap_or((*current_ref, pos)),
                        end,
                    });
                }
                Item::Object(o) => args.push(o),
            }
            skip_over_whitespace(&mut stream, false, false)?;
            skip_over_comments(&mut stream, false)?;
        }
    }
    Ok(out)
}

/// Parse the content streams `refs` of a document.
pub fn parse_content_streams_of(handler: &dyn PdfHandler, refs: &[ObjectId]) -> PdfResult<Vec<GraphicsOperator>> {
    let mut parts = Vec::with_capacity(refs.len());
    for r in refs {
        match handler.get_object(*r)? {
            Object::Stream(s) => parts.push((*r, handler.stream_data(&s)?)),
            _ => return Err(PdfError::read("Content stream must be a stream")),
        }
    }
    parse_content_stream(&parts)
}
