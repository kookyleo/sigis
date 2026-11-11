// Derived from pyHanko `pdf_utils/reader.py` (`RawPdfPath`) (MIT, see
// LICENSE-pyHanko).

//! Raw paths through the object graph (`RawPdfPath`).

use std::fmt;

/// One step of a path: a dictionary key (without the leading slash) or an
/// array index.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PathNode {
    /// Dictionary key, e.g. `b"Root"` for `/Root`.
    Key(Vec<u8>),
    /// Array index.
    Index(usize),
}

impl From<&str> for PathNode {
    /// Accepts keys with or without the leading slash.
    fn from(s: &str) -> Self {
        PathNode::Key(s.strip_prefix('/').unwrap_or(s).as_bytes().to_vec())
    }
}

impl From<usize> for PathNode {
    fn from(i: usize) -> Self {
        PathNode::Index(i)
    }
}

/// A path from an object (usually the trailer) to a descendant
/// (`RawPdfPath`).
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RawPdfPath(pub Vec<PathNode>);

impl RawPdfPath {
    /// The empty path.
    pub fn new() -> Self {
        Self(Vec::new())
    }

    /// Build a path from nodes.
    pub fn of<I, N>(nodes: I) -> Self
    where
        I: IntoIterator<Item = N>,
        N: Into<PathNode>,
    {
        Self(nodes.into_iter().map(Into::into).collect())
    }

    /// Number of nodes.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the path is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// This path followed by `node`.
    pub fn child(&self, node: impl Into<PathNode>) -> Self {
        let mut v = self.0.clone();
        v.push(node.into());
        Self(v)
    }

    /// This path followed by `other`.
    pub fn join(&self, other: &RawPdfPath) -> Self {
        let mut v = self.0.clone();
        v.extend(other.0.iter().cloned());
        Self(v)
    }

    /// Whether node `ix` is the key `key` (given without slash).
    pub(crate) fn key_at(&self, ix: usize, key: &[u8]) -> bool {
        matches!(self.0.get(ix), Some(PathNode::Key(k)) if k == key)
    }

    /// Whether the path contains the key `key` (without slash).
    pub(crate) fn contains_key(&self, key: &[u8]) -> bool {
        self.0.iter().any(|n| matches!(n, PathNode::Key(k) if k == key))
    }
}

impl fmt::Display for RawPdfPath {
    /// pyHanko's rendering: `.Root.Pages.Kids[0]`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for n in &self.0 {
            match n {
                PathNode::Key(k) => write!(f, ".{}", String::from_utf8_lossy(k))?,
                PathNode::Index(i) => write!(f, "[{i}]")?,
            }
        }
        Ok(())
    }
}

/// `RawPdfPath('/Root', '/AcroForm')` style constructor.
#[macro_export]
#[doc(hidden)]
macro_rules! raw_path {
    ($($n:expr),* $(,)?) => {
        $crate::RawPdfPath(vec![$($crate::PathNode::from($n)),*])
    };
}

#[cfg(test)]
mod tests {
    #[test]
    fn display_matches_pyhanko() {
        let p = raw_path!("/Root", "/Pages", "/Kids", 0usize, "/Contents");
        assert_eq!(p.to_string(), ".Root.Pages.Kids[0].Contents");
    }
}
