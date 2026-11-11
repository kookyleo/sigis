# const-oid: second arcs above 39 under first arc 2

Status: patch prepared locally, **not yet submitted upstream** (submitting
needs a GitHub account action). Used through `[patch.crates-io]` in the root
`Cargo.toml` until a release contains a fix. Base: const-oid 0.10.3
(RustCrypto/formats `3c35e972cd4b`); upstream `master` has the same limit.

## Issue text

> **const-oid rejects OIDs whose first arc is 2 and second arc is above 39**
>
> X.660 / X.690 §8.19.4 only bound the second arc for the first arcs 0 and 1.
> Under the first arc 2 the second arc is unbounded: the first subidentifier is
> `80 + second`, base-128 encoded like any other subidentifier, so it may span
> several bytes. Example: `2.999.31337.0` encodes as `88 37 81 F4 69 00`.
>
> const-oid 0.10.x stores the first two arcs in one byte (`RootArcs(u8)`,
> `ARC_MAX_SECOND = 39`). As a result `ObjectIdentifier::new("2.999")` fails
> with `ArcInvalid`, and decoding any DER that contains such an OID fails,
> e.g. a certificate with the certificate policy `2.999.31337.0` (used by the
> Certomancer test PKI of pyHanko) cannot be parsed by `x509-cert`.
>
> Proposed fix (below): decode the first subidentifier as a base-128 integer
> (`v < 40` → `0.v`, `v < 80` → `1.(v-40)`, else `2.(v-80)`), and in the
> encoder reject second arcs above 39 only under the first arcs 0 and 1. No
> change to the in-memory representation (BER bytes) or the public API.

## Patch

```diff
diff --git a/const-oid/src/arcs.rs b/const-oid/src/arcs.rs
index 68294ec..d48a9e4 100644
--- a/const-oid/src/arcs.rs
+++ b/const-oid/src/arcs.rs
@@ -21,9 +21,39 @@ pub type Arc = u32;
 /// Maximum value of the first arc in an OID.
 pub(crate) const ARC_MAX_FIRST: Arc = 2;
 
-/// Maximum value of the second arc in an OID.
+/// Maximum value of the second arc in an OID whose first arc is 0 or 1.
+///
+/// Under the first arc 2 the second arc is unbounded (X.690 §8.19.4): the
+/// first subidentifier is `80 + second`, base-128 encoded like any other.
 pub(crate) const ARC_MAX_SECOND: Arc = 39;
 
+/// Decode the first subidentifier of an OID (which combines the first two
+/// arcs) and return `(first_arc, second_arc, encoded_length)`.
+fn root_arcs(bytes: &[u8]) -> Result<(Arc, Arc, usize)> {
+    let mut value: Arc = 0;
+    let mut len = 0usize;
+    loop {
+        let byte = *bytes.get(len).ok_or(if len == 0 { Error::Empty } else { Error::Base128 })?;
+        len = checked_add!(len, 1);
+        value = value
+            .checked_mul(0x80)
+            .and_then(|v| v.checked_add((byte & 0b0111_1111) as Arc))
+            .ok_or(Error::ArcTooBig)?;
+        if byte & 0b1000_0000 == 0 {
+            break;
+        }
+    }
+    let first = match value {
+        0..=39 => 0,
+        40..=79 => 1,
+        _ => 2,
+    };
+    // `first * (ARC_MAX_SECOND + 1) <= value` by construction.
+    #[allow(clippy::arithmetic_side_effects)]
+    let second = value - first * (ARC_MAX_SECOND + 1);
+    Ok((first, second, len))
+}
+
 /// [`Iterator`] over [`Arc`] values (a.k.a. nodes) in an [`ObjectIdentifier`].
 ///
 /// This iterates over all arcs in an OID, including the root.
@@ -52,15 +82,15 @@ impl<'a> Arcs<'a> {
         match self.cursor {
             // Indicates we're on the root arc
             None => {
-                let root_byte = *self.bytes.first().ok_or(Error::Empty)?;
-                let root = RootArcs::try_from(root_byte)?;
+                let (first, _, _) = root_arcs(self.bytes)?;
                 self.cursor = Some(0);
-                Ok(Some(root.first_arc()))
+                Ok(Some(first))
             }
+            // `Some(0)` means the second arc is next; body offsets are >= 1.
             Some(0) => {
-                let root = RootArcs::try_from(self.bytes[0])?;
-                self.cursor = Some(1);
-                Ok(Some(root.second_arc()))
+                let (_, second, len) = root_arcs(self.bytes)?;
+                self.cursor = Some(len);
+                Ok(Some(second))
             }
             Some(offset) => {
                 let mut result: Arc = 0;
@@ -111,62 +141,3 @@ impl Iterator for Arcs<'_> {
         self.try_next().expect("OID malformed")
     }
 }
-
-/// Byte containing the first and second arcs of an OID.
-///
-/// This is represented this way in order to reduce the overall size of the
-/// [`ObjectIdentifier`] struct.
-#[derive(Copy, Clone, Debug, Eq, PartialEq)]
-struct RootArcs(u8);
-
-impl RootArcs {
-    /// Create [`RootArcs`] from the first and second arc values represented
-    /// as `Arc` integers.
-    pub(crate) const fn new(first_arc: Arc, second_arc: Arc) -> Result<Self> {
-        if first_arc > ARC_MAX_FIRST {
-            return Err(Error::ArcInvalid { arc: first_arc });
-        }
-
-        if second_arc > ARC_MAX_SECOND {
-            return Err(Error::ArcInvalid { arc: second_arc });
-        }
-
-        // The checks above ensure this operation will not overflow
-        #[allow(clippy::arithmetic_side_effects)]
-        let byte = (first_arc * (ARC_MAX_SECOND + 1)) as u8 + second_arc as u8;
-
-        Ok(Self(byte))
-    }
-
-    /// Get the value of the first arc
-    #[allow(clippy::arithmetic_side_effects)]
-    pub(crate) const fn first_arc(self) -> Arc {
-        self.0 as Arc / (ARC_MAX_SECOND + 1)
-    }
-
-    /// Get the value of the second arc
-    #[allow(clippy::arithmetic_side_effects)]
-    pub(crate) const fn second_arc(self) -> Arc {
-        self.0 as Arc % (ARC_MAX_SECOND + 1)
-    }
-}
-
-impl TryFrom<u8> for RootArcs {
-    type Error = Error;
-
-    // Ensured not to overflow by constructor invariants
-    #[allow(clippy::arithmetic_side_effects)]
-    fn try_from(octet: u8) -> Result<Self> {
-        let first = octet as Arc / (ARC_MAX_SECOND + 1);
-        let second = octet as Arc % (ARC_MAX_SECOND + 1);
-        let result = Self::new(first, second)?;
-        debug_assert_eq!(octet, result.0);
-        Ok(result)
-    }
-}
-
-impl From<RootArcs> for u8 {
-    fn from(root_arcs: RootArcs) -> u8 {
-        root_arcs.0
-    }
-}
diff --git a/const-oid/src/encoder.rs b/const-oid/src/encoder.rs
index 77c40cc..045f34b 100644
--- a/const-oid/src/encoder.rs
+++ b/const-oid/src/encoder.rs
@@ -62,17 +62,18 @@ impl<const MAX_SIZE: usize> Encoder<MAX_SIZE> {
                 Ok(self)
             }
             State::FirstArc(first_arc) => {
-                if arc > ARC_MAX_SECOND {
+                // Only the first arcs 0 and 1 bound the second arc
+                // (X.690 §8.19.4); under 2 it is encoded as `80 + arc`.
+                if first_arc < ARC_MAX_FIRST && arc > ARC_MAX_SECOND {
                     return Err(Error::ArcInvalid { arc });
                 }
+                let root = match checked_mul!(checked_add!(ARC_MAX_SECOND, 1), first_arc).checked_add(arc) {
+                    Some(root) => root,
+                    None => return Err(Error::ArcTooBig),
+                };
 
                 self.state = State::Body;
-                self.bytes[0] = checked_add!(
-                    checked_mul!(checked_add!(ARC_MAX_SECOND, 1), first_arc),
-                    arc
-                ) as u8;
-                self.cursor = 1;
-                Ok(self)
+                self.encode_base128(root)
             }
             State::Body => self.encode_base128(arc),
         }
@@ -156,6 +157,16 @@ mod tests {
         assert_eq!(super::base128_byte(example_arc, 4, 5).unwrap(), 0b10001);
     }
 
+    #[test]
+    fn encode_large_second_arc_under_joint_iso_itu_t() {
+        // 2.999 -> first subidentifier 1079 = 0x88 0x37
+        let encoder = Encoder::<4>::new().arc(2).unwrap().arc(999).unwrap().arc(3).unwrap();
+        assert_eq!(&encoder.bytes[..encoder.cursor], &hex!("883703"));
+        assert!(Encoder::<4>::new().arc(1).unwrap().arc(40).is_err());
+        assert!(Encoder::<4>::new().arc(0).unwrap().arc(40).is_err());
+        assert!(Encoder::<4>::new().arc(2).unwrap().arc(u32::MAX).is_err());
+    }
+
     #[test]
     fn encode() {
         let encoder = Encoder::<7>::new();
diff --git a/const-oid/tests/oid.rs b/const-oid/tests/oid.rs
index 5e60053..d3afb16 100644
--- a/const-oid/tests/oid.rs
+++ b/const-oid/tests/oid.rs
@@ -316,3 +316,31 @@ fn starts_with() {
     assert!(!child.starts_with(oid("2.2.3")));
     assert!(!child.starts_with(oid("1.2.3.4.5.6")));
 }
+
+/// X.690 §8.19.4: under the first arc 2, the second arc may exceed 39 and the
+/// first subidentifier (80 + second) takes several bytes.
+#[test]
+fn second_arc_above_39_under_arc_2() {
+    let oid = ObjectIdentifier::new("2.999.31337.0").unwrap();
+    assert_eq!(oid.as_bytes(), &hex!("8837 81F469 00")[..]);
+    assert_eq!(oid.to_string(), "2.999.31337.0");
+    assert_eq!(oid.arcs().collect::<Vec<_>>(), [2, 999, 31337, 0]);
+    assert_eq!(oid.len(), 4);
+    assert_eq!(oid.parent().unwrap().to_string(), "2.999.31337");
+    assert_eq!(ObjectIdentifier::from_bytes(oid.as_bytes()).unwrap(), oid);
+
+    // 2.40 is the smallest value that needs no special case but used to fail.
+    let oid = ObjectIdentifier::new("2.40").unwrap();
+    assert_eq!(oid.as_bytes(), &[0x78]);
+    assert_eq!(ObjectIdentifier::from_bytes(&[0x78]).unwrap().to_string(), "2.40");
+
+    // First subidentifier >= 128 decodes as 2.(v - 80).
+    assert_eq!(ObjectIdentifier::from_bytes(&hex!("8100")).unwrap().to_string(), "2.48");
+
+    // The bounds for the first arcs 0 and 1 still apply.
+    assert!(ObjectIdentifier::new("1.40").is_err());
+    assert!(ObjectIdentifier::new("0.40").is_err());
+    assert!(ObjectIdentifier::new("3.1").is_err());
+    // A truncated multi-byte root is rejected.
+    assert!(ObjectIdentifier::from_bytes(&[0x88]).is_err());
+}
```
