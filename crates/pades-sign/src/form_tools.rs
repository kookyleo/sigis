// Derived from pyHanko `pdf_utils/form_tools.py` (MIT, see LICENSE-pyHanko).

//! Filling text fields with static appearances (`pyhanko.pdf_utils.form_tools`).

use lopdf::{Dictionary, Object, ObjectId};
use sigis_pki_core::errors::{HankoError, Result};

use crate::content::{ContentWriter, PdfContent, PdfResources};
use crate::layout::{AxisAlignment, BoxConstraints, InnerScaling, SimpleBoxLayoutRule};
use crate::pdf::fields::{annot_width_height, enumerate_fields_in, single_field_annot};
use crate::pdf::util::text_string;
use crate::text::{TextBox, TextBoxStyle};

/// Prefix of the messages of form filling errors (`FormFillingError`).
pub const FORM_FILLING_ERROR_PREFIX: &str = "form filling error: ";

/// A form filling error (`FormFillingError`), reported as [`HankoError::FormFilling`].
pub fn form_filling_error(msg: impl AsRef<str>) -> HankoError {
    HankoError::FormFilling(msg.as_ref().to_owned())
}

/// `true` if `e` is a form filling error.
pub fn is_form_filling_error(e: &HankoError) -> bool {
    matches!(e, HankoError::FormFilling(_))
}

/// Layout of static text in fields (`DEFAULT_TEXT_FIELD_LAYOUT_RULE`).
pub const DEFAULT_TEXT_FIELD_LAYOUT_RULE: SimpleBoxLayoutRule = SimpleBoxLayoutRule {
    x_align: AxisAlignment::AlignMin,
    y_align: AxisAlignment::AlignMin,
    margins: crate::layout::Margins {
        left: 0.0,
        right: 0.0,
        top: 0.0,
        bottom: 0.0,
    },
    inner_content_scaling: InnerScaling::NoScaling,
};

/// Set `content` as the appearance of the annotation `annot`
/// (`AppearanceContent.apply_appearance`): registers the content as a form
/// XObject, sets `/AP` and removes `/AS`.
pub fn apply_appearance(
    content: &mut dyn PdfContent,
    w: &mut ContentWriter<'_>,
    annot: ObjectId,
) -> Result<ObjectId> {
    let xobj = content.as_form_xobject(w)?;
    let xobj_ref = w.add(Object::Stream(xobj));
    let ap = crate::content::AnnotAppearances {
        normal: xobj_ref,
        rollover: None,
        down: None,
    };
    let d = w.update().get_dict_mut(annot)?;
    d.set("AP", Object::Dictionary(ap.as_pdf_object()));
    d.remove(b"AS");
    Ok(xobj_ref)
}

/// The content of a statically filled text field (`TextFieldContent`).
#[derive(Debug)]
pub struct TextFieldContent {
    text_content: String,
    text_box: TextBox,
    resources: PdfResources,
}

impl TextFieldContent {
    /// Content for `text` in a box of the given size.
    pub fn new(
        w: &mut ContentWriter<'_>,
        text: &str,
        style: &TextBoxStyle,
        bbox: BoxConstraints,
    ) -> Result<Self> {
        let mut style = style.clone();
        style.box_layout_rule = Some(
            style
                .box_layout_rule
                .unwrap_or(DEFAULT_TEXT_FIELD_LAYOUT_RULE),
        );
        let text_box = TextBox::new(style, w, Some(bbox))?;
        Ok(Self {
            text_content: text.to_owned(),
            text_box,
            resources: PdfResources::default(),
        })
    }
}

impl PdfContent for TextFieldContent {
    fn render(&mut self, w: &mut ContentWriter<'_>) -> Result<Vec<u8>> {
        let text = self.text_content.clone();
        self.text_box.set_content(w, &text)?;
        self.text_box.render_into(w, &mut self.resources)
    }
    fn resources(&self) -> &PdfResources {
        &self.resources
    }
    fn resources_mut(&mut self) -> &mut PdfResources {
        &mut self.resources
    }
    fn bbox(&self) -> &BoxConstraints {
        self.text_box.bbox()
    }
    fn bbox_mut(&mut self) -> &mut BoxConstraints {
        self.text_box.bbox_mut()
    }
}

/// Python truthiness of a PDF value (`bool(field_value)`).
fn truthy(o: &Object) -> bool {
    match o {
        Object::Null => false,
        Object::Boolean(b) => *b,
        Object::Integer(i) => *i != 0,
        Object::Real(r) => *r != 0.0,
        Object::String(s, _) => !s.is_empty(),
        Object::Name(n) => !n.is_empty(),
        Object::Array(a) => !a.is_empty(),
        Object::Dictionary(d) => !d.is_empty(),
        _ => true,
    }
}

/// Find an empty field of type `field_type` named `field_name`
/// (`find_existing_empty_field`).
pub fn find_existing_empty_field(
    w: &ContentWriter<'_>,
    field_name: &str,
    field_type: &[u8],
) -> Result<ObjectId> {
    let update = w.update_ref();
    let root = update.root()?;
    let form = match update.dict_get(root, b"AcroForm")? {
        Some(Object::Dictionary(d)) => d.clone(),
        _ => return Err(form_filling_error("No AcroForm present")),
    };
    let fields = match update.dict_get(&form, b"Fields")? {
        Some(Object::Array(a)) => a.clone(),
        _ => return Err(form_filling_error("No AcroForm present")),
    };
    let found = enumerate_fields_in(update, &fields, None, Some(field_name), field_type)?;
    found
        .into_iter()
        .find(|f| !f.value.as_ref().is_some_and(truthy))
        .map(|f| f.id)
        .ok_or_else(|| {
            form_filling_error(format!("No empty text field with name {field_name} found."))
        })
}

/// Fill an existing text field with static content, to be treated as
/// read-only (`populate_static_text_field`).
pub fn populate_static_text_field(
    w: &mut ContentWriter<'_>,
    field_name: &str,
    style: &TextBoxStyle,
    content: &str,
) -> Result<()> {
    let field_id = find_existing_empty_field(w, field_name, b"Tx")?;
    let annot = single_field_annot(w.update_ref(), field_id)?;
    let annot_dict: Dictionary = w.update_ref().get_dict(annot)?.clone();
    let (width, height) = annot_width_height(w.update_ref(), &annot_dict);
    let mut content_obj =
        TextFieldContent::new(w, content, style, BoxConstraints::fixed(width, height))?;
    apply_appearance(&mut content_obj, w, annot)?;
    let field = w.update().get_dict_mut(field_id)?;
    field.set("V", text_string(content));
    let flags = field
        .get(b"Ff")
        .ok()
        .and_then(|o| o.as_i64().ok())
        .unwrap_or(0);
    field.set("Ff", Object::Integer(flags | 1));
    field.remove(b"DA");
    Ok(())
}
