# Accepted explicit policy composition

Source f91dccd passed all six workspace gates: 1375 discovered,
1367 passed, 8 ignored, zero failed, 111 suite reports. The
lead first reproduced six actual failures with two positive controls using
the existing public API: a materialized empty policy intersection validated
successfully, and a zero-issued path returned wildcard instead of its finite
policy. The repaired12-test suite passes, including high-level validation,
clone/mutation/replacement, composition algebra and caller/anchor controls.
Related library/policy tests also pass. These are supplemental regressions,
not new immutable upstream functions; overall stays1431/1086/32/313.

PkixValidationParams retains its legacy Vec input (empty means wildcard) and
adds user_initial_policy_constraint: Option<BTreeSet<ObjectIdentifier>> as
an additional conjunction. None/anyPolicy means wildcard; Some(empty) permits
no policies. effective_user_initial_policy_set() returns the combined meaning.
replace_user_initial_policy_set(&mut self, Option<BTreeSet<ObjectIdentifier>>)
deliberately replaces both inputs. Legacy field mutation alone cannot erase
a computed merged restriction. Public merge/anchor composition preserve empty
sets; zero-issued paths still apply final policy wrap-up with anchor context.
Certval policy denial remains denial, including when native replay succeeds.

Existing Default/struct-update callers remain compatible. Adding a public
field can break external exhaustive struct literals; this source compatibility
limit is explicit. No dependency, layer exception or build setting changed.

The lead freshly executed10 pinned Python public validations over the same
three NIST certificate files with SHA256 receipts. Python's asymmetric empty
set plus anyPolicy helper can restore P1: the native fix intentionally retains
empty constraints instead. In the mandatory case native rejects more strictly;
in the optional case it returns no qualified policy. Other finite/default and
zero-issued controls retain their assertions. Do not label all10 calls exact
agreements or infer universal fail-closed parity. Evidence and independent
source review are under round3-launch/policy-merge-api/.

Reproduce with the normal scheduler wrapper:

```sh
tools/cargo-locked.sh test -p sigis-pki-certvalidator --test policy_merge_constraints
tools/cargo-locked.sh test -p sigis-pki-certvalidator --lib --test policy_proc
```

The original red-state log and fixed-source targeted logs are retained; the
complete gate records its exact source hash. Oracle scripts are local-only
and version-check pyHanko0.38.1/certvalidator0.33.0. No fixture replay is called
a fresh Python execution, and no runtime/provider skip was added.
