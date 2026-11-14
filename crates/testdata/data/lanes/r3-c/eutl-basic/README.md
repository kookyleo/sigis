# Original ordinary EUTL CLI fixtures

prepare.py runs the unchanged14pyHanko0.38.1 ordinary EUTL CLI functions and
retains each exact pre-command isolated input/config/signed-list cache plus
the fixture PKI's genuine CRLs. cases.txt records the full parameter order.
The Rust top-level tests replay the complete fixtures with the original2020
logical runtime and password prompter; no product clock override or synthetic
trust verdict is introduced. Cache JSON is application input, not a provenance
report. All signatures and list authentication remain real production operations.
Invalid cache/territory cases retain positive contrasts. Forced download uses
the explicit offline transport and must actually fail after cache reset.
