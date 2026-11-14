# Boolean language adaptation

`boolean_dunders::test_bool_dunders` ports the nine statements in pyHanko
0.38.1 `test_internal_utils.py::test_bool_dunders` using existing public APIs.
The three inputs contain exactly `true`, `false` and `()`.

| Original statements | Native assertions |
| --- | --- |
| B1: true differs from false | Compare actual parsed Boolean Objects. |
| B2/B3: either Boolean differs from empty str | Compare with the actual parsed empty PDF String. |
| B4/B5: true/false truthiness | Project through `Object::as_bool`. |
| B6/B7: Object equals its scalar bool | Reconstruct `Object::from` the actual bool projection. |
| B8/B9: repr equals str equals the expected spelling | Compare actual Object Debug with scalar bool Display and then check `true`/`false`. Both chained comparisons are retained. |

This is an explicit language adaptation: native Object has no Display;
Python object str maps to scalar bool Display, and diagnostics are lowercase.
The empty scalar str maps to a parsed PDF String. No wrapper, capitalization,
Item Debug or Hash assertion substitutes for these operations.

Run the native test with:

```sh
tools/cargo-locked.sh test -p sigis-pdf --test boolean_dunders
```

Run the unchanged original directly with the pinned interpreter:

```sh
/tmp/pyhanko-oracle/venv/bin/python -B -m pytest -q -p no:cacheprovider \
  /tmp/pyhanko-oracle/src/v0.38.1/pkgs/pyhanko/tests/test_internal_utils.py::test_bool_dunders
```
