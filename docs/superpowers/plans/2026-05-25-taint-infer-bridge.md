# Taint→Infer Bridge Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire taint_analysis.json (182 LLM-analyzed parameter-mapping records) into the infer stage so multi-hop source→sink paths are found and their parameter-flow evidence is included in vulnerability reports.

**Architecture:** Add a `TaintEdge` parser (`core/taint_parser.py`) that converts LLM result strings into structured objects; extend `simple_path_finder.py` with `find_taint_aware_paths()` that BFS-traverses the taint graph for multi-hop paths; update `vulinfer.py` to embed taint-chain evidence in reports; wire the new function into `run_stage_infer()` in `liva.py`. The original `find_source_sink_paths()` runs as fallback so no existing behavior regresses.

**Tech Stack:** Python 3.8+, `ast.literal_eval`, `collections.deque`, pytest

---

## File Map

| Action | File | Responsibility |
|--------|------|----------------|
| **Create** | `core/taint_parser.py` | Parse `taint_analysis.json` result strings → `List[TaintEdge]` |
| **Create** | `tests/test_taint_parser.py` | Unit tests for taint_parser |
| **Create** | `tests/test_taint_path_finder.py` | Unit tests for find_taint_aware_paths |
| **Modify** | `core/simple_path_finder.py:1,62+` | Add `find_taint_aware_paths()` after existing function |
| **Modify** | `core/vulinfer.py:108-153` | Extend `build_reports()` to render taint chain + multi-func code |
| **Modify** | `liva.py:12,380-390` | Swap import + call to use `find_taint_aware_paths` |

---

## Background: The Data Being Parsed

`taint_analysis.json` result strings come in four variants (all produced by the fine-tuned LLM):

```
# variant A – single callee, with Chinese prefix
参数映射关系结构为 {"sub_A": ("strcpy", {"1": "dest", "2": "a1"}, "line:12", "strcpy(dest, a1);")}

# variant B – list of callees, with prefix
参数映射关系结构为 {"sub_B": [("system", {"1": "buf"}, "line:5", "system(buf);"), ...]}

# variant C – full-width colon
参数映射关系结构为：{"sub_C": ("doSystemCmd", {"1": [1, 2]}, "line:7", "doSystemCmd(s);")}

# variant D – no prefix at all (LLM omitted intro)
{"sub_D": ("system", {"1": "v"}, "line:3", "system(v);")}
```

6 of 182 records are malformed (LLM produced invalid Python) – these must be skipped with a
warning, not raised.

The `param_map` value semantics:
- `{"2": "a1"}` → callee's param-2 receives the parent function's local variable `a1`
- `{"1": [1]}` → callee's param-1 receives the parent function's 1st input parameter (by index)

---

## Task 1: TaintEdge Parser

**Files:**
- Create: `core/taint_parser.py`
- Create: `tests/test_taint_parser.py`

- [ ] **Step 1.1: Write the failing tests**

```python
# tests/test_taint_parser.py
import json
import pytest
from pathlib import Path
from core.taint_parser import TaintEdge, parse_taint_analysis


def _make_file(tmp_path: Path, results: list) -> Path:
    p = tmp_path / "taint_analysis.json"
    p.write_text(json.dumps({"meta": {}, "results": results}), encoding="utf-8")
    return p


def test_parse_single_tuple_with_prefix(tmp_path):
    """Variant A: single callee tuple with Chinese 'is' prefix."""
    f = _make_file(tmp_path, [{
        "index": 1,
        "result": '参数映射关系结构为 {"sub_A": ("strcpy", {"1": "dest", "2": "a1"}, "line:12", "strcpy(dest, a1);")}'
    }])
    edges = parse_taint_analysis(f)
    assert len(edges) == 1
    e = edges[0]
    assert e.caller == "sub_A"
    assert e.callee == "strcpy"
    assert e.param_map == {"1": "dest", "2": "a1"}
    assert e.line_info == "line:12"
    assert e.call_expr == "strcpy(dest, a1);"


def test_parse_list_format_no_prefix(tmp_path):
    """Variant D + B: list of tuples without prefix."""
    f = _make_file(tmp_path, [{
        "index": 2,
        "result": '{"sub_B": [("system", {"1": "buf"}, "line:5", "system(buf);"), ("popen", {"1": "cmd"}, "line:8", "popen(cmd);")]}'
    }])
    edges = parse_taint_analysis(f)
    assert len(edges) == 2
    assert edges[0].callee == "system"
    assert edges[1].callee == "popen"
    assert edges[0].caller == "sub_B"


def test_parse_full_width_colon_prefix(tmp_path):
    """Variant C: Chinese full-width colon (：) in prefix."""
    f = _make_file(tmp_path, [{
        "index": 3,
        "result": '参数映射关系结构为：{"sub_C": ("doSystemCmd", {"1": [1, 2]}, "line:7", "doSystemCmd(s);")}'
    }])
    edges = parse_taint_analysis(f)
    assert len(edges) == 1
    assert edges[0].caller == "sub_C"
    assert edges[0].param_map == {"1": [1, 2]}


def test_parse_skips_malformed_without_raising(tmp_path):
    """6 known-bad records must be skipped; valid records still parsed."""
    bad = '{"FUN_X": {"callee": {"1": "v"}, "line:1", "call();"}}'   # invalid Python dict
    f = _make_file(tmp_path, [
        {"index": 1, "result": bad},
        {"index": 2, "result": '{"sub_D": ("system", {"1": "v"}, "line:3", "system(v);")}'},
    ])
    edges = parse_taint_analysis(f)
    assert len(edges) == 1
    assert edges[0].caller == "sub_D"


def test_parse_empty_results(tmp_path):
    """Empty results list returns empty list, no error."""
    p = tmp_path / "taint_analysis.json"
    p.write_text(json.dumps({"meta": {}, "results": []}), encoding="utf-8")
    assert parse_taint_analysis(p) == []


def test_parse_record_missing_result_field(tmp_path):
    """Records with no 'result' key (e.g. error records) are silently skipped."""
    f = _make_file(tmp_path, [{"index": 1, "entry": "some text", "error": "timeout"}])
    assert parse_taint_analysis(f) == []


def test_parse_index_tracked_for_warning(tmp_path, caplog):
    """Malformed record triggers a logged warning containing its index."""
    import logging
    bad = '{"FUN_X": "not_a_tuple"}'
    f = _make_file(tmp_path, [{"index": 99, "result": bad}])
    with caplog.at_level(logging.WARNING, logger="core.taint_parser"):
        parse_taint_analysis(f)
    # Warning must mention the index so engineers can locate the bad record
    assert "99" in caplog.text or "skipped" in caplog.text.lower()
```

- [ ] **Step 1.2: Run tests – confirm all fail**

```bash
cd /Users/yangshuangning/VscodeProjects/LIVA-main
python -m pytest tests/test_taint_parser.py -v 2>&1 | head -30
```

Expected: `ModuleNotFoundError: No module named 'core.taint_parser'`

- [ ] **Step 1.3: Create `core/taint_parser.py`**

```python
# core/taint_parser.py
"""
Parse taint_analysis.json result strings into TaintEdge objects.

taint_analysis.json is written by run_stage_taint() (liva.py).
Each 'result' field contains LLM output in Python-literal syntax:

  Variant A (single callee, Chinese prefix):
    参数映射关系结构为 {"CALLER": ("CALLEE", {param_map}, "line:N", "expr;")}

  Variant B (multi callee, Chinese prefix):
    参数映射关系结构为 {"CALLER": [("CALLEE1", ...), ("CALLEE2", ...)]}

  Variant C (full-width colon):
    参数映射关系结构为：{"CALLER": ...}

  Variant D (no prefix, LLM omitted intro):
    {"CALLER": ("CALLEE", ...)}

6 of 182 production records are malformed (invalid Python). These are
skipped with logging.WARNING rather than raising, so the infer stage
can still use the remaining 175+ records.
"""

import ast
import json
import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List

logger = logging.getLogger(__name__)

# Matches both ASCII colon and Chinese full-width colon (：U+FF1A)
_PREFIX_RE = re.compile(r"参数映射关系结构为\s*[:：]\s*([\s\S]+)", re.S)


@dataclass
class TaintEdge:
    caller: str       # parent function name
    callee: str       # function being called (may be a sink or intermediate)
    param_map: Dict[str, Any]  # {callee_param_index: expr_or_parent_param_indices}
    line_info: str    # e.g. "line:12"
    call_expr: str    # e.g. "strcpy(dest, a1);"


def _normalize_to_tuple_list(v: Any) -> List[tuple]:
    """Coerce single tuple or list-of-tuples into a consistent list of tuples."""
    if isinstance(v, tuple):
        return [v]
    if isinstance(v, list):
        return [item for item in v if isinstance(item, tuple)]
    return []


def _edges_from_parsed(parsed: Any) -> List[TaintEdge]:
    """Extract TaintEdge list from a parsed Python literal (must be a dict)."""
    if not isinstance(parsed, dict):
        return []
    edges: List[TaintEdge] = []
    for caller, v in parsed.items():
        for item in _normalize_to_tuple_list(v):
            if len(item) < 1 or not isinstance(item[0], str):
                continue
            callee: str = item[0]
            param_map: Dict[str, Any] = (
                item[1] if len(item) > 1 and isinstance(item[1], dict) else {}
            )
            line_info: str = str(item[2]) if len(item) > 2 else ""
            call_expr: str = str(item[3]) if len(item) > 3 else ""
            edges.append(
                TaintEdge(
                    caller=caller,
                    callee=callee,
                    param_map=param_map,
                    line_info=line_info,
                    call_expr=call_expr,
                )
            )
    return edges


def parse_taint_analysis(path: Path) -> List[TaintEdge]:
    """Return all TaintEdge objects parsed from taint_analysis.json.

    Malformed records are skipped with a WARNING log; valid records are
    always returned even when some records fail to parse.
    """
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    edges: List[TaintEdge] = []
    skipped = 0
    records = data.get("results", [])

    for record in records:
        raw_result: str = record.get("result") or ""
        if not raw_result:
            continue

        # Strip Chinese prefix (variants A, B, C); variant D has no prefix
        m = _PREFIX_RE.search(raw_result)
        raw = m.group(1).strip() if m else raw_result.strip()

        try:
            parsed = ast.literal_eval(raw)
            edges.extend(_edges_from_parsed(parsed))
        except Exception as e:
            skipped += 1
            logger.warning(
                "taint_parser: skipping index=%s (%s: %s)",
                record.get("index", "?"),
                type(e).__name__,
                e,
            )

    if skipped:
        logger.warning(
            "taint_parser: skipped %d/%d malformed records in %s",
            skipped,
            len(records),
            path,
        )
    logger.info(
        "taint_parser: extracted %d TaintEdge objects from %s", len(edges), path
    )
    return edges
```

- [ ] **Step 1.4: Run tests – confirm all pass**

```bash
python -m pytest tests/test_taint_parser.py -v
```

Expected output:
```
tests/test_taint_parser.py::test_parse_single_tuple_with_prefix PASSED
tests/test_taint_parser.py::test_parse_list_format_no_prefix PASSED
tests/test_taint_parser.py::test_parse_full_width_colon_prefix PASSED
tests/test_taint_parser.py::test_parse_skips_malformed_without_raising PASSED
tests/test_taint_parser.py::test_parse_empty_results PASSED
tests/test_taint_parser.py::test_parse_record_missing_result_field PASSED
tests/test_taint_parser.py::test_parse_index_tracked_for_warning PASSED
7 passed
```

- [ ] **Step 1.5: Smoke-test against real production data**

```bash
python -c "
from pathlib import Path
from core.taint_parser import parse_taint_analysis
p = Path('result/CH22_19_52/httpd_4717ef/taint_analysis.json')
edges = parse_taint_analysis(p)
print(f'Parsed {len(edges)} edges from 182 records')
callee_counts = {}
for e in edges:
    callee_counts[e.callee] = callee_counts.get(e.callee, 0) + 1
for k,v in sorted(callee_counts.items(), key=lambda x: -x[1])[:10]:
    print(f'  {k}: {v}')
"
```

Expected: `Parsed N edges from 182 records` (N ≥ 175) with no uncaught exception.

- [ ] **Step 1.6: Commit**

```bash
git add core/taint_parser.py tests/test_taint_parser.py
git commit -m "feat: add taint_parser to parse taint_analysis.json result strings into TaintEdge objects"
```

---

## Task 2: Taint-Aware Path Finder

**Files:**
- Modify: `core/simple_path_finder.py` (add function after line 61)
- Create: `tests/test_taint_path_finder.py`

- [ ] **Step 2.1: Write the failing tests**

```python
# tests/test_taint_path_finder.py
import json
import pytest
from pathlib import Path


def _pc(tmp_path: Path, items: list) -> Path:
    """Write parent_child_calls JSON fixture."""
    p = tmp_path / "parent_child.json"
    p.write_text(json.dumps({"data": items}), encoding="utf-8")
    return p


def _ta(tmp_path: Path, results: list) -> Path:
    """Write taint_analysis JSON fixture."""
    p = tmp_path / "taint_analysis.json"
    p.write_text(json.dumps({"meta": {}, "results": results}), encoding="utf-8")
    return p


def test_direct_path_found_via_taint(tmp_path):
    """Function calling BOTH source and sink → found with taint_chain of length 1."""
    pc = _pc(tmp_path, [{
        "parent_name": "handler",
        "child_names": ["websGetVar", "system"],
        "decompiled_c": "void handler() { v = websGetVar(); system(v); }"
    }])
    ta = _ta(tmp_path, [{
        "index": 1,
        "result": '{"handler": ("system", {"1": "v"}, "line:3", "system(v);")}'
    }])
    from core.simple_path_finder import find_taint_aware_paths
    paths = find_taint_aware_paths(
        parent_child_path=pc,
        source_funcs=["websGetVar"],
        sink_funcs=["system"],
        taint_analysis_path=ta,
    )
    assert len(paths) >= 1
    assert any(p["src"]["func_name"] == "handler" and p["dst"]["func_name"] == "system"
               for p in paths)


def test_multihop_taint_path_found(tmp_path):
    """handler→websGetVar + doSystemCmd; doSystemCmd→system → 2-hop path found."""
    pc = _pc(tmp_path, [
        {
            "parent_name": "handler",
            "child_names": ["websGetVar", "doSystemCmd"],
            "decompiled_c": "void handler() { v = websGetVar(); doSystemCmd(v); }"
        },
        {
            "parent_name": "doSystemCmd",
            "child_names": ["system"],
            "decompiled_c": "void doSystemCmd(char *s) { system(s); }"
        },
    ])
    ta = _ta(tmp_path, [
        {
            "index": 1,
            "result": '{"handler": ("doSystemCmd", {"1": "v"}, "line:3", "doSystemCmd(v);")}'
        },
        {
            "index": 2,
            "result": '{"doSystemCmd": ("system", {"1": [1]}, "line:2", "system(s);")}'
        },
    ])
    from core.simple_path_finder import find_taint_aware_paths
    paths = find_taint_aware_paths(
        parent_child_path=pc,
        source_funcs=["websGetVar"],
        sink_funcs=["system"],
        taint_analysis_path=ta,
    )
    multihop = [
        p for p in paths
        if p["src"]["func_name"] == "handler"
        and p["dst"]["func_name"] == "system"
        and len(p.get("taint_chain", [])) >= 2
    ]
    assert len(multihop) >= 1, (
        f"Expected handler→doSystemCmd→system path. Got: "
        f"{[(p['src']['func_name'], p['dst']['func_name'], len(p.get('taint_chain',[]))) for p in paths]}"
    )


def test_no_path_when_no_source_called(tmp_path):
    """Function only calls sink, never a source → no paths returned."""
    pc = _pc(tmp_path, [{
        "parent_name": "handler",
        "child_names": ["system"],
        "decompiled_c": 'void handler() { system("ls"); }'
    }])
    ta = _ta(tmp_path, [{
        "index": 1,
        "result": '{"handler": ("system", {"1": "\\"ls\\""}, "line:2", "system(\\"ls\\");")}'
    }])
    from core.simple_path_finder import find_taint_aware_paths
    paths = find_taint_aware_paths(
        parent_child_path=pc,
        source_funcs=["websGetVar"],
        sink_funcs=["system"],
        taint_analysis_path=ta,
    )
    assert paths == []


def test_no_duplicate_paths(tmp_path):
    """Same (entry_func, src_func, sink_func) triple not returned twice."""
    pc = _pc(tmp_path, [{
        "parent_name": "f",
        "child_names": ["websGetVar", "system"],
        "decompiled_c": "void f() { v = websGetVar(); system(v); }"
    }])
    ta = _ta(tmp_path, [{
        "index": 1,
        "result": '{"f": ("system", {"1": "v"}, "line:3", "system(v);")}'
    }])
    from core.simple_path_finder import find_taint_aware_paths
    paths = find_taint_aware_paths(
        parent_child_path=pc,
        source_funcs=["websGetVar"],
        sink_funcs=["system"],
        taint_analysis_path=ta,
    )
    f_to_system = [
        p for p in paths
        if p["src"]["func_name"] == "f" and p["dst"]["func_name"] == "system"
    ]
    assert len(f_to_system) == 1, f"Expected exactly 1 path, got {len(f_to_system)}"


def test_fallback_when_no_taint_file(tmp_path):
    """When taint_analysis_path=None, falls back to direct co-occurrence search."""
    pc = _pc(tmp_path, [{
        "parent_name": "g",
        "child_names": ["websGetVar", "system"],
        "decompiled_c": ""
    }])
    from core.simple_path_finder import find_taint_aware_paths
    paths = find_taint_aware_paths(
        parent_child_path=pc,
        source_funcs=["websGetVar"],
        sink_funcs=["system"],
        taint_analysis_path=None,
    )
    assert len(paths) == 1
    assert paths[0]["src"]["func_name"] == "g"
    assert paths[0]["dst"]["func_name"] == "system"


def test_path_has_required_fields(tmp_path):
    """Each path dict has the fields VulInfer.build_reports() expects."""
    pc = _pc(tmp_path, [{
        "parent_name": "h",
        "child_names": ["websGetVar", "system"],
        "decompiled_c": "void h() { v = websGetVar(); system(v); }"
    }])
    ta = _ta(tmp_path, [{
        "index": 1,
        "result": '{"h": ("system", {"1": "v"}, "line:2", "system(v);")}'
    }])
    from core.simple_path_finder import find_taint_aware_paths
    paths = find_taint_aware_paths(
        parent_child_path=pc,
        source_funcs=["websGetVar"],
        sink_funcs=["system"],
        taint_analysis_path=ta,
    )
    assert paths
    p = paths[0]
    assert "src" in p and "dst" in p and "rels" in p
    assert "param_func" in p["src"] and "func_name" in p["src"]
    assert "func_name" in p["dst"]
    assert "taint_chain" in p
    assert "path_type" in p


def test_max_hops_limits_bfs_depth(tmp_path):
    """BFS stops at max_hops; 3-hop chain not found when max_hops=2."""
    # A → source + calls B; B → calls C; C → sink
    # With max_hops=2 we find A→B→sink but NOT A→B→C→sink (3 hops)
    pc = _pc(tmp_path, [
        {"parent_name": "A", "child_names": ["websGetVar", "B"], "decompiled_c": "void A(){websGetVar();B();}"},
        {"parent_name": "B", "child_names": ["C"], "decompiled_c": "void B(){C();}"},
        {"parent_name": "C", "child_names": ["system"], "decompiled_c": "void C(){system(s);}"},
    ])
    ta = _ta(tmp_path, [
        {"index": 1, "result": '{"A": ("B", {"1": "v"}, "line:2", "B(v);")}'},
        {"index": 2, "result": '{"B": ("C", {"1": [1]}, "line:2", "C(v);")}'},
        {"index": 3, "result": '{"C": ("system", {"1": [1]}, "line:2", "system(s);")}'},
    ])
    from core.simple_path_finder import find_taint_aware_paths
    paths_limited = find_taint_aware_paths(
        parent_child_path=pc,
        source_funcs=["websGetVar"],
        sink_funcs=["system"],
        taint_analysis_path=ta,
        max_hops=2,
    )
    paths_full = find_taint_aware_paths(
        parent_child_path=pc,
        source_funcs=["websGetVar"],
        sink_funcs=["system"],
        taint_analysis_path=ta,
        max_hops=5,
    )
    three_hop = [p for p in paths_full if len(p.get("taint_chain", [])) == 3]
    assert len(three_hop) >= 1, "max_hops=5 should find 3-hop path"
    three_hop_limited = [p for p in paths_limited if len(p.get("taint_chain", [])) == 3]
    assert len(three_hop_limited) == 0, "max_hops=2 must not find 3-hop path"
```

- [ ] **Step 2.2: Run tests – confirm all fail**

```bash
python -m pytest tests/test_taint_path_finder.py -v 2>&1 | head -20
```

Expected: `ImportError` or `TypeError: find_taint_aware_paths() got unexpected keyword argument 'taint_analysis_path'`

- [ ] **Step 2.3: Add `find_taint_aware_paths()` to `core/simple_path_finder.py`**

Add these imports at the top of the file (replace the existing import line):

```python
# core/simple_path_finder.py  – top of file (replace line 1)
import json
import logging
from collections import defaultdict, deque
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
```

Append the following function **after the existing `find_source_sink_paths` function** (after line 61):

```python
def find_taint_aware_paths(
    parent_child_path: Union[str, Path],
    source_funcs: List[str],
    sink_funcs: List[str],
    taint_analysis_path: Optional[Union[str, Path]] = None,
    max_hops: int = 5,
) -> List[Dict[str, Any]]:
    """Find source→sink paths using taint propagation graph + direct call graph.

    Algorithm
    ---------
    1. Parse taint_analysis.json into a taint graph: caller → [TaintEdge].
    2. From parent_child_calls, identify source-entry functions (any function
       whose child_names or decompiled_c contains a source function name).
    3. BFS from each source-entry function through taint graph edges:
       - If edge.callee is in sink_funcs  → path found; record full chain.
       - If edge.callee has outgoing taint edges → extend BFS (up to max_hops).
    4. Also run find_source_sink_paths() as a fallback for paths not found via
       taint graph (e.g. when taint_analysis.json is absent).

    Returns
    -------
    List of path dicts compatible with VulInfer.build_reports():
    {
        "src": {"param_func": source_func, "func_name": entry_func},
        "dst": {"func_name": sink_func},
        "rels": [],
        "taint_chain": [
            {"caller": str, "callee": str, "param_map": dict,
             "line_info": str, "call_expr": str},
            ...
        ],
        "path_type": "direct" | "taint_1hop" | "taint_2hop" | ...
    }
    """
    from core.taint_parser import parse_taint_analysis

    parent_child_path = Path(parent_child_path)
    if not parent_child_path.exists():
        logger.warning("parent_child_calls file not found: %s", parent_child_path)
        return []

    root = json.loads(parent_child_path.read_text(encoding="utf-8"))
    items: List[Dict[str, Any]] = root.get("data", [])

    source_set = set(source_funcs)
    sink_set = set(sink_funcs)

    # ---------- Build taint graph ----------
    taint_graph: Dict[str, list] = defaultdict(list)
    if taint_analysis_path is not None:
        tp = Path(taint_analysis_path)
        if tp.exists():
            for edge in parse_taint_analysis(tp):
                taint_graph[edge.caller].append(edge)
        else:
            logger.warning(
                "taint_analysis_path not found: %s — using direct search only", tp
            )

    # ---------- Find source-entry functions ----------
    # Maps entry_func_name → set of source functions it calls
    source_entries: Dict[str, set] = {}
    for item in items:
        parent: str = item.get("parent_name", "")
        child_set = set(item.get("child_names", []))
        decompiled: str = item.get("decompiled_c") or ""
        sources_in_code = {s for s in source_set if s in decompiled}
        found_sources = (child_set & source_set) | sources_in_code
        if found_sources:
            source_entries[parent] = found_sources

    # ---------- BFS ----------
    # seen_path_keys prevents duplicates: (entry_func, src_func, sink_func)
    seen_path_keys: set = set()
    paths: List[Dict[str, Any]] = []

    for entry_func, found_sources in source_entries.items():
        for src_func in sorted(found_sources):
            # BFS queue: (current_func, chain_so_far, visited_set)
            queue: deque = deque()
            queue.append((entry_func, [], {entry_func}))

            while queue:
                current, chain, visited = queue.popleft()
                if len(chain) >= max_hops:
                    continue

                for edge in taint_graph.get(current, []):
                    step = {
                        "caller": edge.caller,
                        "callee": edge.callee,
                        "param_map": edge.param_map,
                        "line_info": edge.line_info,
                        "call_expr": edge.call_expr,
                    }
                    new_chain = chain + [step]

                    if edge.callee in sink_set:
                        key = (entry_func, src_func, edge.callee)
                        if key not in seen_path_keys:
                            seen_path_keys.add(key)
                            hop_count = len(new_chain)
                            paths.append({
                                "src": {"param_func": src_func, "func_name": entry_func},
                                "dst": {"func_name": edge.callee},
                                "rels": [],
                                "taint_chain": new_chain,
                                "path_type": (
                                    f"taint_{hop_count}hop" if hop_count > 1 else "direct"
                                ),
                            })
                    elif edge.callee not in visited and taint_graph.get(edge.callee):
                        queue.append((edge.callee, new_chain, visited | {edge.callee}))

    # ---------- Fallback: direct co-occurrence ----------
    for p in find_source_sink_paths(parent_child_path, source_funcs, sink_funcs):
        entry = p["src"]["func_name"]
        src = p["src"]["param_func"]
        sink = p["dst"]["func_name"]
        key = (entry, src, sink)
        if key not in seen_path_keys:
            seen_path_keys.add(key)
            p["taint_chain"] = []
            p["path_type"] = "direct"
            paths.append(p)

    taint_count = sum(1 for p in paths if "taint" in p.get("path_type", ""))
    direct_count = sum(1 for p in paths if p.get("path_type") == "direct")
    logger.info(
        "TaintAwarePathFinder: %d paths total (%d taint-derived, %d direct)",
        len(paths),
        taint_count,
        direct_count,
    )
    return paths
```

- [ ] **Step 2.4: Run tests – confirm all pass**

```bash
python -m pytest tests/test_taint_path_finder.py -v
```

Expected:
```
tests/test_taint_path_finder.py::test_direct_path_found_via_taint PASSED
tests/test_taint_path_finder.py::test_multihop_taint_path_found PASSED
tests/test_taint_path_finder.py::test_no_path_when_no_source_called PASSED
tests/test_taint_path_finder.py::test_no_duplicate_paths PASSED
tests/test_taint_path_finder.py::test_fallback_when_no_taint_file PASSED
tests/test_taint_path_finder.py::test_path_has_required_fields PASSED
tests/test_taint_path_finder.py::test_max_hops_limits_bfs_depth PASSED
7 passed
```

- [ ] **Step 2.5: Verify existing simple_path_finder tests still pass**

```bash
python -m pytest tests/test_simple_path_finder.py -v
```

Expected: all 5 existing tests PASSED (zero regressions)

- [ ] **Step 2.6: Smoke-test against real data**

```bash
python -c "
from pathlib import Path
from core.simple_path_finder import find_taint_aware_paths

base = Path('result/CH22_19_52/httpd_4717ef')
paths = find_taint_aware_paths(
    parent_child_path=base / 'parent_child_calls_ida_decompile.json',
    source_funcs=['websGetVar', 'GetValue', 'nvram_get', 'sub_28B84'],
    sink_funcs=['system', 'popen', 'sprintf', 'strcpy', 'strcat', 'doSystemCmd'],
    taint_analysis_path=base / 'taint_analysis.json',
)
direct = [p for p in paths if p['path_type'] == 'direct']
taint  = [p for p in paths if 'taint' in p['path_type']]
print(f'Total: {len(paths)}  direct: {len(direct)}  taint-derived: {len(taint)}')
for p in taint[:5]:
    chain = ' -> '.join([p[\"src\"][\"func_name\"]] + [s[\"callee\"] for s in p[\"taint_chain\"]])
    print(f'  [{p[\"path_type\"]}] {chain}')
"
```

Expected: `taint-derived` count > 0 (was 0 before this change).

- [ ] **Step 2.7: Commit**

```bash
git add core/simple_path_finder.py tests/test_taint_path_finder.py
git commit -m "feat: add find_taint_aware_paths() — BFS through taint graph for multi-hop source→sink paths"
```

---

## Task 3: Enrich VulInfer Reports with Taint Chain

**Files:**
- Modify: `core/vulinfer.py:85-153` (the `build_reports` method)

This task makes the vulnerability reports sent to GPT include:
1. The **full call chain** (e.g. `handler->doSystemCmd->system()`) for multi-hop paths
2. A **taint_evidence** section showing param flow at each hop
3. **Decompiled code for all intermediate functions**, not just the entry function

- [ ] **Step 3.1: Read the current `build_reports` implementation**

Open `core/vulinfer.py` and locate `build_reports` (currently lines 85–153).
The current inner loop block is:

```python
        decompiled_code = self._get_decompiled_code(src_func_name)
        call_chain = f"{src_func_name}->{dst_func_name}()"

        block_lines = [
            f"source_function: {src_param_func}()",
            f"sink_function: {dst_func_name}()",
            f"call_chain: {call_chain}",
            "code:",
            decompiled_code,
            "",  # 分隔空行
        ]
        block = "\n".join(block_lines)
        reports.append(block)
```

- [ ] **Step 3.2: Replace the inner-loop block in `build_reports`**

Find the block shown above (lines 133–145 approximately) and replace it with:

```python
        taint_chain = path.get("taint_chain", [])

        if taint_chain:
            # Full call chain: entry_func -> intermediate... -> sink()
            chain_funcs = [taint_chain[0]["caller"]] + [s["callee"] for s in taint_chain]
            call_chain = "->".join(chain_funcs[:-1]) + f"->{chain_funcs[-1]}()"

            # Collect decompiled code for every non-sink function in the chain
            code_parts: List[str] = []
            seen_code_funcs: set = set()
            for func in chain_funcs[:-1]:  # exclude the sink itself
                if func not in seen_code_funcs:
                    seen_code_funcs.add(func)
                    code_parts.append(
                        f"// --- {func} ---\n{self._get_decompiled_code(func)}"
                    )
            decompiled_code = "\n\n".join(code_parts)

            # Taint evidence: one line per hop
            evidence_lines = [
                f"  [{i + 1}] {s['caller']} calls {s['callee']}"
                f"(params={list(s['param_map'].keys())}) at {s['line_info']}: {s['call_expr']}"
                for i, s in enumerate(taint_chain)
            ]
            evidence_block = "taint_evidence:\n" + "\n".join(evidence_lines)
        else:
            call_chain = f"{src_func_name}->{dst_func_name}()"
            decompiled_code = self._get_decompiled_code(src_func_name)
            evidence_block = ""

        block_parts = [
            f"source_function: {src_param_func}()",
            f"sink_function: {dst_func_name}()",
            f"call_chain: {call_chain}",
        ]
        if evidence_block:
            block_parts.append(evidence_block)
        block_parts += ["code:", decompiled_code, ""]

        block = "\n".join(block_parts)
        reports.append(block)
```

Also add `List` to the existing import at the top of vulinfer.py if not already present:
```python
from typing import List, Dict, Any, Optional
```

- [ ] **Step 3.3: Run all existing tests to confirm no regression**

```bash
python -m pytest tests/ -v --tb=short 2>&1 | tail -20
```

Expected: all previously passing tests still PASSED; no new failures.

- [ ] **Step 3.4: Smoke-test report content**

```bash
python -c "
from pathlib import Path
from core.simple_path_finder import find_taint_aware_paths
from core.vulinfer import VulInfer

base = Path('result/CH22_19_52/httpd_4717ef')
paths = find_taint_aware_paths(
    parent_child_path=base / 'parent_child_calls_ida_decompile.json',
    source_funcs=['websGetVar', 'GetValue', 'nvram_get', 'sub_28B84'],
    sink_funcs=['system', 'popen', 'sprintf', 'strcpy', 'strcat', 'doSystemCmd'],
    taint_analysis_path=base / 'taint_analysis.json',
)
infer = VulInfer(
    ida_json_path=base / 'parent_child_calls_ida_decompile.json',
    output_path=base / 'cmd_injection_candidates.txt',
)
reports = infer.build_reports(paths=paths, source_func_name='')
taint_reports = [r for r in reports if 'taint_evidence' in r]
print(f'Total reports: {len(reports)},  with taint_evidence: {len(taint_reports)}')
if taint_reports:
    print()
    print('=== Sample taint report (first 40 lines) ===')
    print('\n'.join(taint_reports[0].split('\n')[:40]))
"
```

Expected: `with taint_evidence: N` where N > 0; the sample report should contain a `taint_evidence:` section with numbered hop lines.

- [ ] **Step 3.5: Commit**

```bash
git add core/vulinfer.py
git commit -m "feat: vulinfer.build_reports — include taint_evidence section and multi-func code for multi-hop paths"
```

---

## Task 4: Wire `run_stage_infer()` to Use Taint-Aware Path Finder

**Files:**
- Modify: `liva.py:12` (import line)
- Modify: `liva.py:380-390` (the `find_source_sink_paths` call inside `run_stage_infer`)

This is the key wiring step. Currently `run_stage_infer` never reads `taint_analysis.json`.

- [ ] **Step 4.1: Update the import at `liva.py` line 12**

Current line 12:
```python
from core.simple_path_finder import find_source_sink_paths
```

Replace with:
```python
from core.simple_path_finder import find_source_sink_paths, find_taint_aware_paths
```

(Keep `find_source_sink_paths` in the import — it is still used internally by `find_taint_aware_paths` as its fallback.)

- [ ] **Step 4.2: Update `run_stage_infer()` to call `find_taint_aware_paths`**

Locate `run_stage_infer` (currently lines 363–394). Find this block:

```python
    paths = find_source_sink_paths(
        parent_child_path=parent_child_file,
        source_funcs=source_funcs,
        sink_funcs=sink_funcs,
    )
    print(f"Found {len(paths)} source→sink paths")
```

Replace it with:

```python
    taint_analysis_file = base_dir / "taint_analysis.json"
    paths = find_taint_aware_paths(
        parent_child_path=parent_child_file,
        source_funcs=source_funcs,
        sink_funcs=sink_funcs,
        taint_analysis_path=taint_analysis_file if taint_analysis_file.exists() else None,
    )
    taint_count = sum(1 for p in paths if "taint" in p.get("path_type", ""))
    direct_count = sum(1 for p in paths if p.get("path_type") == "direct")
    print(
        f"Found {len(paths)} source→sink paths "
        f"({direct_count} direct, {taint_count} taint-derived)"
    )
```

- [ ] **Step 4.3: Run all tests**

```bash
python -m pytest tests/ -v --tb=short
```

Expected: all tests pass.

- [ ] **Step 4.4: Integration smoke-test — run the full infer stage in dry-run mode**

```bash
python -c "
import sys
sys.argv = ['liva.py', 'dummy', 'dummy', 'CH22_19_52']
from config import config
config.LivaConfig.set_device_info('CH22_19_52')

# Simulate only what run_stage_infer needs — don't actually call GPT
from pathlib import Path
from core.simple_path_finder import find_taint_aware_paths

base = Path('result/CH22_19_52/httpd_4717ef')
taint_file = base / 'taint_analysis.json'
pc_file    = base / 'parent_child_calls_ida_decompile.json'

source_funcs = ['websGetVar', 'GetValue', 'nvram_get', 'sub_28B84', 'cgiFormString']
sink_funcs   = ['system', 'exec', 'popen', 'doSystemCmd', 'buffer_overflow',
                'memcpy', 'strcpy', 'sprintf', 'sscanf', 'strcat']

paths = find_taint_aware_paths(
    parent_child_path=pc_file,
    source_funcs=source_funcs,
    sink_funcs=sink_funcs,
    taint_analysis_path=taint_file if taint_file.exists() else None,
)
direct = [p for p in paths if p['path_type'] == 'direct']
taint  = [p for p in paths if 'taint' in p['path_type']]
print(f'RESULT: {len(paths)} paths  ({len(direct)} direct, {len(taint)} taint-derived)')
print()
print('Taint-derived paths:')
for p in taint:
    chain = ' -> '.join(
        [p['src']['func_name']] + [s['callee'] for s in p['taint_chain']]
    )
    print(f'  [{p[\"path_type\"]}] {chain}')
"
```

Expected: `taint-derived` count > 0. Before this change the count was 0 and these paths were silently skipped.

- [ ] **Step 4.5: Commit**

```bash
git add liva.py
git commit -m "fix: wire taint_analysis.json into run_stage_infer via find_taint_aware_paths — 182 LLM-analyzed parameter mappings are now used for multi-hop path finding"
```

---

## Self-Review Checklist

### Spec Coverage

| Requirement | Task |
|---|---|
| Parse taint_analysis.json result strings | Task 1 |
| Handle 6 malformed records gracefully (skip+warn, no raise) | Task 1 step 1.3 |
| Handle all 4 result string variants (A/B/C/D) | Task 1 tests |
| Build taint graph: caller → [TaintEdge] | Task 2 step 2.3 |
| BFS multi-hop path finding via taint graph | Task 2 step 2.3 |
| Deduplicate paths (same triple not returned twice) | Task 2 test + step 2.3 |
| Respect max_hops to prevent infinite loops | Task 2 test + step 2.3 |
| Fallback to direct co-occurrence when no taint file | Task 2 test + step 2.3 |
| Enrich reports with full call chain + taint evidence | Task 3 |
| Include decompiled code for all intermediate functions | Task 3 step 3.2 |
| Wire everything into run_stage_infer() | Task 4 |
| Backward compatible (existing 26 direct paths unaffected) | Task 2 step 2.5 |

### Placeholder Scan

No TBDs, TODOs, or placeholder phrases found. All code blocks are complete and runnable.

### Type Consistency

- `TaintEdge` defined in `core/taint_parser.py`, imported into `core/simple_path_finder.py` via `from core.taint_parser import parse_taint_analysis`
- `find_taint_aware_paths` returns `List[Dict[str, Any]]` — same type as `find_source_sink_paths` — so `VulInfer.build_reports(paths=..., source_func_name="")` signature is unchanged
- `taint_chain` is a new optional key in the path dict; `build_reports` reads it with `path.get("taint_chain", [])` so existing paths (no `taint_chain` key) degrade gracefully to the old behavior
- `path_type` field uses values `"direct"`, `"taint_1hop"`, `"taint_2hop"`, ... consistently across step 2.3, tests, and step 4.4 smoke-test
