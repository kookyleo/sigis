#!/usr/bin/env python3
"""Print the workspace crate graph as mermaid (docs/crates.md).

Usage: cargo metadata --no-deps --format-version 1 | python3 tools/crate-graph.py
"""
import json, sys
m = json.load(sys.stdin)
L = json.load(open("tools/layers.json"))["layers"]
ws = {p["name"] for p in m["packages"]}
names = {0: "L0 PKI", 1: "L1 Formats", 2: "L2 AdES", 3: "L3 Containers",
         4: "L4 Facades", 5: "L5 Service API", 6: "L6 Application"}
def ident(n): return n.replace("-", "_")
def short(n): return "sigis (service)" if n == "sigis" else n.replace("sigis-", "")
out = ["```mermaid", "flowchart BT"]
for lv in sorted(set(L.values())):
    out.append(f'  subgraph layer{lv}["{names[lv]}"]')
    for n in sorted(k for k, v in L.items() if v == lv):
        out.append(f'    {ident(n)}["{short(n)}"]')
    out.append("  end")
edges = set()
for p in m["packages"]:
    for d in p["dependencies"]:
        if d["name"] in ws and d.get("kind") is None and d["name"] != "sigis-testdata":
            edges.add((p["name"], d["name"]))
for a, b in sorted(edges):
    out.append(f"  {ident(a)} --> {ident(b)}")
out.append("```")
print("\n".join(out))
print(len(edges), "edges", file=sys.stderr)
