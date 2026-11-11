// Derived from pyHanko `sign/diff_analysis/rules_api.py` (`Context`,
// `RelativeContext`, `AbsoluteContext`, `ApprovalType`, `ReferenceUpdate`) and
// `form_rules_api.py` (`FormUpdate`) (MIT, see LICENSE-pyHanko).

//! Contexts in which an updated reference was checked, and the update
//! records that rules emit.

use lopdf::ObjectId;

use crate::error::DiffResultT;
use crate::history::{Anchor, Revision};
use crate::path::RawPdfPath;

/// Where an updated reference was checked (`Context`).
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Context {
    /// A path relative to a container object (`RelativeContext`). The anchor
    /// refers to the older revision.
    Relative {
        /// Container object (`anchor`).
        anchor: Anchor,
        /// Path from the container (`relative_path`).
        path: RawPdfPath,
    },
    /// An absolute path from the trailer (`AbsoluteContext`).
    Absolute(RawPdfPath),
}

impl Context {
    /// `Context.from_absolute`.
    pub fn absolute(path: RawPdfPath) -> Self {
        Context::Absolute(path)
    }

    /// A relative context.
    pub fn relative(anchor: Anchor, path: RawPdfPath) -> Self {
        Context::Relative { anchor, path }
    }

    /// `relative_view` of an absolute context, resolved in `rev`; a relative
    /// context is returned as is.
    pub fn relative_view(&self, rev: &Revision<'_>) -> DiffResultT<Context> {
        match self {
            Context::Absolute(p) => {
                let (anchor, path) = rev.relative_view(p)?;
                Ok(Context::Relative { anchor, path })
            }
            rel => Ok(rel.clone()),
        }
    }

    /// `descend`: the context `path` below this one.
    pub fn descend(&self, rev: &Revision<'_>, path: &RawPdfPath) -> DiffResultT<Context> {
        match self {
            Context::Absolute(p) => Ok(Context::Absolute(p.join(path))),
            Context::Relative { anchor, path: rel } => {
                let (anchor, path) = rev.descend_relative(*anchor, rel, path)?;
                Ok(Context::Relative { anchor, path })
            }
        }
    }
}

impl std::fmt::Display for Context {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Context::Absolute(p) => write!(f, "{p}"),
            Context::Relative {
                anchor: Anchor::Trailer,
                path,
            } => write!(f, "trailer{path}"),
            Context::Relative {
                anchor: Anchor::Ref(id),
                path,
            } => {
                write!(f, "{} {} R{path}", id.0, id.1)
            }
        }
    }
}

/// How an update approves the usages of an overwritten reference
/// (`ApprovalType`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ApprovalType {
    /// No context: all usages are approved.
    BlanketApprove,
    /// Approves all usages with the same relative view.
    ApproveRelativeContext,
    /// Approves one absolute path.
    ApprovePath,
}

/// A reference cleared by a rule (`ReferenceUpdate`).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ReferenceUpdate {
    /// The reference that was (potentially) updated.
    pub updated_ref: ObjectId,
    /// Where the update was checked.
    pub context_checked: Option<Context>,
}

impl ReferenceUpdate {
    /// An update without context (blanket approval).
    pub fn new(updated_ref: ObjectId) -> Self {
        Self {
            updated_ref,
            context_checked: None,
        }
    }

    /// An update checked in `context`.
    pub fn with_context(updated_ref: ObjectId, context: Context) -> Self {
        Self {
            updated_ref,
            context_checked: Some(context),
        }
    }

    /// `approval_type`.
    pub fn approval_type(&self) -> ApprovalType {
        match self.context_checked {
            None => ApprovalType::BlanketApprove,
            Some(Context::Relative { .. }) => ApprovalType::ApproveRelativeContext,
            Some(Context::Absolute(_)) => ApprovalType::ApprovePath,
        }
    }
}

/// A form-related update (`FormUpdate`).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FormUpdate {
    /// The reference and its context.
    pub update: ReferenceUpdate,
    /// Fully qualified name of the field concerned, if unambiguous.
    pub field_name: Option<String>,
    /// Whether the update is valid even if the field is locked.
    pub valid_when_locked: bool,
    /// Whether the update is valid under a certification (DocMDP) signature.
    pub valid_when_certifying: bool,
}

impl FormUpdate {
    /// A form update with pyHanko's defaults (`valid_when_locked = False`,
    /// `valid_when_certifying = True`).
    pub fn new(update: ReferenceUpdate, field_name: Option<String>) -> Self {
        Self {
            update,
            field_name,
            valid_when_locked: false,
            valid_when_certifying: true,
        }
    }

    /// Set `valid_when_locked`.
    pub fn locked_ok(mut self, valid_when_locked: bool) -> Self {
        self.valid_when_locked = valid_when_locked;
        self
    }

    /// Set `valid_when_certifying`.
    pub fn certifying_ok(mut self, valid_when_certifying: bool) -> Self {
        self.valid_when_certifying = valid_when_certifying;
        self
    }
}
