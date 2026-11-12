// Derived from pyHanko `pdf_utils/content.py` and the content-related parts
// of `pdf_utils/writer.py` (`init_xobject_dictionary`, `add_stream_to_page`,
// `merge_resources`, `import_object`, `import_page_as_xobject`) and
// `pdf_utils/rw_common.py` (`find_page_for_modification`) (MIT, see
// LICENSE-pyHanko).

//! Content streams, resources and the writer context used to render
//! appearances (`pyhanko.pdf_utils.content`).

pub mod import;
pub mod ops;

use std::collections::BTreeMap;
use std::path::PathBuf;

use lopdf::{Dictionary, Object, ObjectId, Stream};
use sigis_pki_core::errors::{HankoError, Result};

use crate::barcodes::BarcodeBox;
use crate::font::{FontEngine, FontHandle, FontRegistry};
use crate::images::PdfImage;
use crate::layout::BoxConstraints;
use crate::pdf::writer::PdfUpdate;

fn malformed(msg: impl Into<String>) -> HankoError {
    HankoError::Malformed(msg.into())
}

/// Keys of a resource dictionary (`ResourceType`, ISO 32000-1 Table 34).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ResourceType {
    /// `/ExtGState`.
    ExtGState,
    /// `/ColorSpace`.
    ColorSpace,
    /// `/Pattern`.
    Pattern,
    /// `/Shading`.
    Shading,
    /// `/XObject`.
    XObject,
    /// `/Font`.
    Font,
    /// `/Properties`.
    Properties,
}

impl ResourceType {
    /// All resource types, in pyHanko's order.
    pub const ALL: [ResourceType; 7] = [
        Self::ExtGState,
        Self::ColorSpace,
        Self::Pattern,
        Self::Shading,
        Self::XObject,
        Self::Font,
        Self::Properties,
    ];

    /// The dictionary key.
    pub fn key(self) -> &'static str {
        match self {
            Self::ExtGState => "ExtGState",
            Self::ColorSpace => "ColorSpace",
            Self::Pattern => "Pattern",
            Self::Shading => "Shading",
            Self::XObject => "XObject",
            Self::Font => "Font",
            Self::Properties => "Properties",
        }
    }
}

/// A resource dictionary under construction (`PdfResources`).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct PdfResources {
    entries: BTreeMap<ResourceType, Dictionary>,
}

impl PdfResources {
    /// An empty resource dictionary.
    pub fn new() -> Self {
        Self::default()
    }

    /// The entries of one category.
    pub fn get(&self, category: ResourceType) -> Option<&Dictionary> {
        self.entries.get(&category)
    }

    /// Set a resource (`PdfContent.set_resource`).
    pub fn set(&mut self, category: ResourceType, name: &str, value: Object) {
        self.entries
            .entry(category)
            .or_default()
            .set(name.as_bytes().to_vec(), value);
    }

    /// `true` if `name` is defined in `category`.
    pub fn contains(&self, category: ResourceType, name: &str) -> bool {
        self.entries
            .get(&category)
            .is_some_and(|d| d.has(name.as_bytes()))
    }

    /// The resource dictionary (`as_pdf_object`); empty categories are
    /// omitted.
    pub fn as_pdf_object(&self) -> Dictionary {
        let mut d = Dictionary::new();
        for t in ResourceType::ALL {
            if let Some(v) = self.entries.get(&t) {
                if !v.is_empty() {
                    d.set(t.key(), Object::Dictionary(v.clone()));
                }
            }
        }
        d
    }

    /// Merge `other` into `self` (`__iadd__`); a name defined in both is a
    /// `ResourceManagementError`.
    pub fn merge(&mut self, other: &PdfResources) -> Result<()> {
        for (t, d) in &other.entries {
            let mine = self.entries.entry(*t).or_default();
            for (k, v) in d.iter() {
                if mine.has(k) {
                    return Err(malformed(format!(
                        "Resource with name /{} occurs in both dictionaries.",
                        String::from_utf8_lossy(k)
                    )));
                }
                mine.set(k.clone(), v.clone());
            }
        }
        Ok(())
    }
}

/// The writer an appearance is rendered into: an incremental update plus the
/// font engines whose subsets are embedded before writing
/// (`BasePdfFileWriter`'s font resource management).
///
/// Call [`ContentWriter::prepare_write`] before writing the update
/// (pyHanko does this in `_prep_dom_for_writing`).
#[derive(Debug)]
pub struct ContentWriter<'a> {
    update: &'a mut PdfUpdate,
    fonts: FontRegistry,
}

impl<'a> ContentWriter<'a> {
    /// A writer context over `update`.
    pub fn new(update: &'a mut PdfUpdate) -> Self {
        Self {
            update,
            fonts: FontRegistry::default(),
        }
    }

    /// The underlying update.
    pub fn update(&mut self) -> &mut PdfUpdate {
        self.update
    }

    /// The underlying update (read-only).
    pub fn update_ref(&self) -> &PdfUpdate {
        self.update
    }

    /// The update uses an xref stream (`stream_xrefs`).
    pub fn stream_xrefs(&self) -> bool {
        self.update.uses_xref_stream()
    }

    /// The font registry.
    pub fn fonts(&mut self) -> &mut FontRegistry {
        &mut self.fonts
    }

    /// A registered font engine.
    pub fn font(&mut self, h: FontHandle) -> Result<&mut (dyn FontEngine + 'static)> {
        self.fonts.engine_mut(h)
    }

    /// The resource value of a font engine (`as_resource`).
    pub fn font_resource(&mut self, h: FontHandle) -> Result<Object> {
        let engine = self.fonts.engine_mut(h)?;
        engine.as_resource(self.update)
    }

    /// Register a font engine.
    pub fn register_font(&mut self, engine: Box<dyn FontEngine>) -> FontHandle {
        self.fonts.register(engine)
    }

    /// Embed the font subsets (`prepare_write` of every font engine).
    pub fn prepare_write(&mut self) -> Result<()> {
        self.fonts.prepare_write(self.update)
    }

    /// Embed the font subsets and serialize the update.
    pub fn write(&mut self) -> Result<Vec<u8>> {
        self.prepare_write()?;
        Ok(self.update.write()?.0)
    }

    /// Add a new object.
    pub fn add(&mut self, obj: Object) -> ObjectId {
        self.update.add(obj)
    }
}

/// A form XObject (`init_xobject_dictionary`). The `/BBox` is
/// `[0 h w 0]`, as in pyHanko.
pub fn init_xobject_dictionary(
    command_stream: Vec<u8>,
    box_width: f64,
    box_height: f64,
    resources: Option<Dictionary>,
) -> Stream {
    let mut d = Dictionary::new();
    d.set(
        "BBox",
        Object::Array(vec![
            Object::Real(0.0),
            Object::Real(box_height as f32),
            Object::Real(box_width as f32),
            Object::Real(0.0),
        ]),
    );
    d.set(
        "Resources",
        Object::Dictionary(resources.unwrap_or_default()),
    );
    d.set("Type", Object::Name(b"XObject".to_vec()));
    d.set("Subtype", Object::Name(b"Form".to_vec()));
    Stream::new(d, command_stream)
}

/// A compressed stream (`StreamObject.compress()`); the stream is left
/// uncompressed if compression fails.
pub fn compressed(mut s: Stream) -> Stream {
    let _ = s.compress();
    s
}

/// Part of a content stream (`PdfContent`).
pub trait PdfContent {
    /// Compile the content to graphics operators (`render`).
    fn render(&mut self, w: &mut ContentWriter<'_>) -> Result<Vec<u8>>;

    /// The resources the content uses.
    fn resources(&self) -> &PdfResources;

    /// The resources, mutably.
    fn resources_mut(&mut self) -> &mut PdfResources;

    /// The bounding box.
    fn bbox(&self) -> &BoxConstraints;

    /// The bounding box, mutably.
    fn bbox_mut(&mut self) -> &mut BoxConstraints;

    /// Set a resource (`set_resource`).
    fn set_resource(&mut self, category: ResourceType, name: &str, value: Object) {
        self.resources_mut().set(category, name, value);
    }

    /// Import resources (`import_resources`); conflicts are errors.
    fn import_resources(&mut self, resources: &PdfResources) -> Result<()> {
        self.resources_mut().merge(resources)
    }

    /// Render to a form XObject (`as_form_xobject`). The XObject is not
    /// registered with the writer.
    fn as_form_xobject(&mut self, w: &mut ContentWriter<'_>) -> Result<Stream> {
        let cmd = self.render(w)?;
        let b = self.bbox();
        Ok(init_xobject_dictionary(
            cmd,
            b.width()?,
            b.height()?,
            Some(self.resources().as_pdf_object()),
        ))
    }

    /// Add the content as a content stream of page `page_ix`
    /// (`add_to_page`); returns the page.
    fn add_to_page(
        &mut self,
        w: &mut ContentWriter<'_>,
        page_ix: i64,
        prepend: bool,
    ) -> Result<ObjectId> {
        let data = self.render(w)?;
        let stream_id = w.add(Object::Stream(Stream::new(Dictionary::new(), data)));
        let res = self.resources().as_pdf_object();
        add_stream_to_page(w.update(), page_ix, stream_id, Some(res), prepend)
    }
}

/// Raw content stream data (`RawContent`).
#[derive(Clone, Debug, PartialEq)]
pub struct RawContent {
    /// The operators.
    pub data: Vec<u8>,
    resources: PdfResources,
    bbox: BoxConstraints,
}

impl RawContent {
    /// Raw content with the given box and resources.
    pub fn new(
        data: impl Into<Vec<u8>>,
        resources: Option<PdfResources>,
        bbox: Option<BoxConstraints>,
    ) -> Self {
        Self {
            data: data.into(),
            resources: resources.unwrap_or_default(),
            bbox: bbox.unwrap_or_default(),
        }
    }
}

impl PdfContent for RawContent {
    fn render(&mut self, _w: &mut ContentWriter<'_>) -> Result<Vec<u8>> {
        Ok(self.data.clone())
    }
    fn resources(&self) -> &PdfResources {
        &self.resources
    }
    fn resources_mut(&mut self) -> &mut PdfResources {
        &mut self.resources
    }
    fn bbox(&self) -> &BoxConstraints {
        &self.bbox
    }
    fn bbox_mut(&mut self) -> &mut BoxConstraints {
        &mut self.bbox
    }
}

/// A page of another PDF file, imported lazily as a form XObject
/// (`ImportedPdfPage`).
#[derive(Clone, Debug, PartialEq)]
pub struct ImportedPdfPage {
    /// The file to import from.
    pub file_name: PathBuf,
    /// The page index.
    pub page_ix: usize,
    resources: PdfResources,
    bbox: BoxConstraints,
}

impl ImportedPdfPage {
    /// Import page `page_ix` of `file_name`.
    pub fn new(file_name: impl Into<PathBuf>, page_ix: usize) -> Self {
        Self {
            file_name: file_name.into(),
            page_ix,
            resources: PdfResources::default(),
            bbox: BoxConstraints::default(),
        }
    }
}

impl PdfContent for ImportedPdfPage {
    fn render(&mut self, w: &mut ContentWriter<'_>) -> Result<Vec<u8>> {
        let data = std::fs::read(&self.file_name)?;
        let source = sigis_pdf::PdfFile::parse(&data)?;
        let xobj =
            import::import_page_as_xobject_from_reader(w.update(), &source, self.page_ix, true)?;
        let resource_name = format!("Import{}", ops::uuid4(false));
        self.resources.set(
            ResourceType::XObject,
            &resource_name,
            Object::Reference(xobj),
        );
        let bbox = match w.update_ref().get(xobj)? {
            Object::Stream(s) => s.dict.get(b"BBox").ok().cloned(),
            _ => None,
        };
        let nums: Vec<f64> = match bbox {
            Some(Object::Array(a)) => a.iter().filter_map(crate::pdf::util::as_number).collect(),
            _ => Vec::new(),
        };
        if nums.len() != 4 {
            return Err(malformed("imported page has no valid /BBox"));
        }
        self.bbox = BoxConstraints::new(
            Some((nums[0] - nums[2]).abs()),
            Some((nums[1] - nums[3]).abs()),
            None,
        )?;
        Ok(format!("/{resource_name} Do").into_bytes())
    }
    fn resources(&self) -> &PdfResources {
        &self.resources
    }
    fn resources_mut(&mut self) -> &mut PdfResources {
        &mut self.resources
    }
    fn bbox(&self) -> &BoxConstraints {
        &self.bbox
    }
    fn bbox_mut(&mut self) -> &mut BoxConstraints {
        &mut self.bbox
    }
}

/// Content that can be used as a stamp background or QR centerpiece.
#[derive(Clone, Debug)]
pub enum Content {
    /// Raw operators.
    Raw(RawContent),
    /// A page imported from another PDF.
    ImportedPage(ImportedPdfPage),
    /// A bitmap image.
    Image(PdfImage),
    /// A barcode.
    Barcode(BarcodeBox),
}

impl Content {
    fn inner(&self) -> &dyn PdfContent {
        match self {
            Self::Raw(c) => c,
            Self::ImportedPage(c) => c,
            Self::Image(c) => c,
            Self::Barcode(c) => c,
        }
    }

    fn inner_mut(&mut self) -> &mut dyn PdfContent {
        match self {
            Self::Raw(c) => c,
            Self::ImportedPage(c) => c,
            Self::Image(c) => c,
            Self::Barcode(c) => c,
        }
    }
}

impl PdfContent for Content {
    fn render(&mut self, w: &mut ContentWriter<'_>) -> Result<Vec<u8>> {
        self.inner_mut().render(w)
    }
    fn resources(&self) -> &PdfResources {
        self.inner().resources()
    }
    fn resources_mut(&mut self) -> &mut PdfResources {
        self.inner_mut().resources_mut()
    }
    fn bbox(&self) -> &BoxConstraints {
        self.inner().bbox()
    }
    fn bbox_mut(&mut self) -> &mut BoxConstraints {
        self.inner_mut().bbox_mut()
    }
}

/// An appearance dictionary with only a normal appearance, or also
/// rollover and down appearances (`AnnotAppearances`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AnnotAppearances {
    /// `/N`.
    pub normal: ObjectId,
    /// `/R`.
    pub rollover: Option<ObjectId>,
    /// `/D`.
    pub down: Option<ObjectId>,
}

impl AnnotAppearances {
    /// The `/AP` dictionary.
    pub fn as_pdf_object(&self) -> Dictionary {
        let mut d = Dictionary::new();
        d.set("N", Object::Reference(self.normal));
        if let Some(r) = self.rollover {
            d.set("R", Object::Reference(r));
        }
        if let Some(r) = self.down {
            d.set("D", Object::Reference(r));
        }
        d
    }
}

/// Where a page's resources live (`find_page_for_modification`).
#[derive(Clone, Debug, PartialEq)]
pub enum PageResources {
    /// An indirect resource dictionary.
    Indirect(ObjectId),
    /// A direct (possibly inherited) resource dictionary.
    Direct(Dictionary),
}

/// The page `page_ix` (negative counts from the end) and its possibly
/// inherited resources (`find_page_for_modification`).
pub fn find_page_for_modification(
    update: &PdfUpdate,
    page_ix: i64,
) -> Result<(ObjectId, PageResources)> {
    let page = update.page(page_ix)?;
    // walk up the tree for inherited /Resources
    let mut chain = vec![page];
    let mut cur = page;
    for _ in 0..64 {
        match update.get_dict(cur)?.get(b"Parent") {
            Ok(Object::Reference(p)) => {
                if chain.contains(p) {
                    return Err(malformed("Circular reference in page tree"));
                }
                chain.push(*p);
                cur = *p;
            }
            _ => break,
        }
    }
    for node in &chain {
        if let Ok(r) = update.get_dict(*node)?.get(b"Resources") {
            return Ok((
                page,
                match r {
                    Object::Reference(id) => PageResources::Indirect(*id),
                    Object::Dictionary(d) => PageResources::Direct(d.clone()),
                    _ => PageResources::Direct(Dictionary::new()),
                },
            ));
        }
    }
    Ok((page, PageResources::Direct(Dictionary::new())))
}

/// Add an indirect stream to the contents of page `page_ix`, merging
/// `resources` into the page's resources (`add_stream_to_page`). Returns
/// the page.
pub fn add_stream_to_page(
    update: &mut PdfUpdate,
    page_ix: i64,
    stream_ref: ObjectId,
    resources: Option<Dictionary>,
    prepend: bool,
) -> Result<ObjectId> {
    let (page_id, res) = find_page_for_modification(update, page_ix)?;
    let contents = update.get_dict(page_id)?.get(b"Contents").ok().cloned();
    match contents {
        Some(Object::Reference(cid)) => match update.get(cid)?.clone() {
            Object::Array(_) => {
                if let Object::Array(a) = update.get_mut(cid)? {
                    if prepend {
                        a.insert(0, Object::Reference(stream_ref));
                    } else {
                        a.push(Object::Reference(stream_ref));
                    }
                }
            }
            Object::Stream(_) => {
                let arr = if prepend {
                    vec![Object::Reference(stream_ref), Object::Reference(cid)]
                } else {
                    vec![Object::Reference(cid), Object::Reference(stream_ref)]
                };
                let arr_id = update.add(Object::Array(arr));
                update
                    .get_dict_mut(page_id)?
                    .set("Contents", Object::Reference(arr_id));
            }
            _ => return Err(malformed("Unexpected type for page /Contents")),
        },
        Some(Object::Array(mut a)) => {
            if prepend {
                a.insert(0, Object::Reference(stream_ref));
            } else {
                a.push(Object::Reference(stream_ref));
            }
            let arr_id = update.add(Object::Array(a));
            update
                .get_dict_mut(page_id)?
                .set("Contents", Object::Reference(arr_id));
        }
        _ => return Err(malformed("Unexpected type for page /Contents")),
    }
    let Some(resources) = resources else {
        return Ok(page_id);
    };
    match res {
        PageResources::Indirect(rid) => {
            let mut orig = update.get_dict(rid)?.clone();
            if merge_resources(update, &mut orig, &resources)? {
                match update.get_mut(rid)? {
                    Object::Dictionary(d) => *d = orig,
                    Object::Stream(s) => s.dict = orig,
                    _ => return Err(malformed("resource dictionary expected")),
                }
            }
        }
        PageResources::Direct(d) => {
            let mut orig = d;
            merge_resources(update, &mut orig, &resources)?;
            let rid = update.add(Object::Dictionary(orig));
            update
                .get_dict_mut(page_id)?
                .set("Resources", Object::Reference(rid));
        }
    }
    Ok(page_id)
}

/// Merge `new_dict` into the resource dictionary `orig` (`merge_resources`).
/// Indirect sub-dictionaries are updated in place (and marked as updated);
/// returns `true` if `orig` itself changed.
pub fn merge_resources(
    update: &mut PdfUpdate,
    orig: &mut Dictionary,
    new_dict: &Dictionary,
) -> Result<bool> {
    let mut update_needed = false;
    for (key, value) in new_dict.iter() {
        let orig_value = match orig.get(key) {
            Err(_) => {
                update_needed = true;
                orig.set(key.clone(), value.clone());
                continue;
            }
            Ok(v) => v.clone(),
        };
        let value = update.resolve(value)?.clone();
        match orig_value {
            Object::Reference(id) => {
                let target = update.get_mut(id)?;
                merge_resource_value(key, target, &value)?;
            }
            mut direct => {
                update_needed = true;
                merge_resource_value(key, &mut direct, &value)?;
                orig.set(key.clone(), direct);
            }
        }
    }
    Ok(update_needed)
}

fn merge_resource_value(key: &[u8], target: &mut Object, value: &Object) -> Result<()> {
    match target {
        Object::Array(a) if key == b"ProcSet" => {
            if let Object::Array(new) = value {
                for x in new {
                    if matches!(x, Object::Name(_)) && !a.contains(x) {
                        a.push(x.clone());
                    }
                }
            }
        }
        Object::Dictionary(d) => {
            if let Object::Dictionary(new) = value {
                for (k, v) in new.iter() {
                    if d.has(k) {
                        return Err(malformed(format!(
                            "Naming conflict in resource of type /{}: key /{} occurs in both.",
                            String::from_utf8_lossy(key),
                            String::from_utf8_lossy(k)
                        )));
                    }
                    d.set(k.clone(), v.clone());
                }
            }
        }
        _ => {}
    }
    Ok(())
}
