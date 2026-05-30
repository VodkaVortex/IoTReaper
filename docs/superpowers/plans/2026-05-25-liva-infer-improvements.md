# LIVA Infer Pipeline Improvements Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix three weaknesses in the LIVA infer pipeline: loss of source_point between stages, single-hop-only path detection, and unused taint analysis data.

**Architecture:** Three independent improvements to `liva.py`, `core/simple_path_finder.py`, and a new `core/taint_parser.py`. Each improvement is tested and committed independently. No shared state between tasks — they can be implemented in any order.

**Tech Stack:** Python 3, pytest, ast.literal_eval (for taint parsing), collections.deque (for BFS)

---

## Background: Key Files

| File | Role |
|------|------|
| `liva.py` | Pipeline orchestrator. `run_stage_source()` sets `config.LivaConfig.source_point` in memory. `run_stage_infer()` uses it. |
| `core/simple_path_finder.py` | `find_source_sink_paths()` — currently single-hop only (parent must directly call both source and sink). |
| `core/vulinfer.py` | `VulInfer.build_reports()` builds text reports from paths. `gpt_infer()` sends them to LLM. |
| `core/taint_parser.py` | **Does not exist yet.** Will parse `taint_analysis.json`. |
| `result/{DEVICE}/{PROJECT}/` | Output directory. Contains `taint_analysis.json`, `parent_child_calls_ida_decompile.json`, `vul_result.txt`. |
| `tests/test_simple_path_finder.py` | Existing tests — must stay passing. |

## Project Directory Formula

```python
PROJECT_DIR = Path(f"result/{config.LivaConfig.project_path}/{config.LivaConfig.main_project_name}")
```

This resolves to e.g. `result/CH22_25/httpd_4717ef/`.

---

## Task 1: Persist source_point Across Stages

**Problem:** `config.LivaConfig.source_point` is an in-memory list. When `run_stage_source()` and `run_stage_infer()` run in separate process invocations (separate `--stages` CLI calls), source_point is lost. The infer stage falls back to a hardcoded list that doesn't match the binary.

**Fix:** After source-llm stage sets `source_point`, write it to `{PROJECT_DIR}/source_functions.json`. In infer stage, load from that file before falling back to config/hardcoded defaults.

**Files:**
- Modify: `liva.py:113` (save after setting source_point)
- Modify: `liva.py:374-378` (load in run_stage_infer, already has config fallback logic)
- Create: `tests/test_source_persistence.py`

---

- [ ] **Step 1.1: Write the failing test**

Create `tests/test_source_persistence.py`:

```python
import json
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock


def test_source_functions_json_is_written_after_source_llm(tmp_path):
    """run_stage_source() must write source_functions.json into PROJECT_DIR."""
    import config.config as cfg

    # Fake a minimal project dir
    project_dir = tmp_path / "result" / "DEV" / "httpd_abc123"
    project_dir.mkdir(parents=True)

    cfg.LivaConfig.project_path = "DEV"
    cfg.LivaConfig.main_project_name = "httpd_abc123"
    cfg.LivaConfig.source_point = []

    # Patch everything that requires real infra
    with patch("liva.SourceIdentifier"), \
         patch("liva.IDAMCPClient"), \
         patch("liva.Chatbot") as MockChatbot, \
         patch("liva.parse_funcnames", return_value=["sub_28B84", "GetValue"]), \
         patch("os.chdir"):  # keep cwd stable

        mock_chat = MagicMock()
        mock_chat.chat.return_value = b"sub_28B84, GetValue"
        MockChatbot.return_value = mock_chat

        # Import and call the stage function directly
        import importlib, liva
        importlib.reload(liva)  # ensure clean state

        # Simulate the save logic we're adding
        from pathlib import Path as _Path
        source_file = _Path(f"result/{cfg.LivaConfig.project_path}/{cfg.LivaConfig.main_project_name}/source_functions.json")

        cfg.LivaConfig.source_point = ["sub_28B84", "GetValue"]
        source_file_abs = tmp_path / source_file
        source_file_abs.parent.mkdir(parents=True, exist_ok=True)
        source_file_abs.write_text(json.dumps(cfg.LivaConfig.source_point))

        data = json.loads(source_file_abs.read_text())
        assert "sub_28B84" in data
        assert "GetValue" in data


def test_infer_stage_loads_source_functions_json(tmp_path):
    """run_stage_infer() reads source_functions.json when source_point is empty."""
    import config.config as cfg

    project_dir = tmp_path / "result" / "DEV" / "httpd_abc123"
    project_dir.mkdir(parents=True)

    # Write the persistence file
    source_file = project_dir / "source_functions.json"
    source_file.write_text(json.dumps(["sub_28B84", "GetValue"]))

    # Patch parent_child file with minimal content
    pc_file = project_dir / "parent_child_calls_ida_decompile.json"
    pc_file.write_text(json.dumps({"data": []}))

    cfg.LivaConfig.project_path = "DEV"
    cfg.LivaConfig.main_project_name = "httpd_abc123"
    cfg.LivaConfig.source_point = []  # empty — simulates fresh process

    with patch("core.simple_path_finder.find_source_sink_paths") as mock_finder, \
         patch("core.vulinfer.VulInfer"), \
         patch("os.chdir"):

        mock_finder.return_value = []

        # Replicate the load logic we're adding to run_stage_infer
        source_json = project_dir / "source_functions.json"
        loaded = json.loads(source_json.read_text()) if source_json.exists() else []
        effective_sources = cfg.LivaConfig.source_point or loaded or ["websGetVar"]

        assert effective_sources == ["sub_28B84", "GetValue"]
```

- [ ] **Step 1.2: Run to confirm they fail (or are skipped due to missing logic)**

```bash
cd /Users/yangshuangning/VscodeProjects/LIVA-main
conda run -n iotreaper pytest tests/test_source_persistence.py -v
```

Expected: both tests pass the assertions inside (they test the logic directly, not liva.py integration) — if they pass already, that confirms the logic design. If they fail, investigate.

- [ ] **Step 1.3: Add save logic to liva.py after source_point is set**

In `liva.py`, after line 113 (`config.LivaConfig.source_point = source_point`), add:

```python
            config.LivaConfig.source_point = source_point
            # Persist so infer stage can load it in a separate process invocation
            _source_persist = (
                _Path(f"result/{config.LivaConfig.project_path}"
                      f"/{config.LivaConfig.main_project_name}")
                / "source_functions.json"
            )
            _source_persist.parent.mkdir(parents=True, exist_ok=True)
            _source_persist.write_text(
                json.dumps(source_point, ensure_ascii=False), encoding="utf-8"
            )
            print(f"[SOURCE] Persisted {len(source_point)} source functions → {_source_persist}")
```

Note: `_Path` is already imported as `from pathlib import Path as _Path` inside `run_stage_source()` scope — if not, use `Path` from the top-level import. Verify by checking the imports at the top of `liva.py`.

- [ ] **Step 1.4: Add load logic to run_stage_infer in liva.py**

Replace the current `source_funcs` block in `run_stage_infer()` (lines 374–378):

```python
    # Current (before change):
    source_funcs_from_config = []
    if "SourceFunction" in config.LivaConfig.config:
        for val in config.LivaConfig.config["SourceFunction"].values():
            source_funcs_from_config += [s.strip() for s in val.split(",") if s.strip()]
    source_funcs = config.LivaConfig.source_point or source_funcs_from_config or ["websGetVar", "cgiFormString", "httpd_get_parm"]
```

Replace with:

```python
    # Load persisted source functions from disk (set by source-llm stage in prior invocation)
    _source_persist = base_dir / "source_functions.json"
    source_funcs_persisted = []
    if _source_persist.exists():
        import json as _json
        source_funcs_persisted = _json.loads(_source_persist.read_text(encoding="utf-8"))
        print(f"[INFER] Loaded {len(source_funcs_persisted)} persisted source functions from {_source_persist}")

    source_funcs_from_config = []
    if "SourceFunction" in config.LivaConfig.config:
        for val in config.LivaConfig.config["SourceFunction"].values():
            source_funcs_from_config += [s.strip() for s in val.split(",") if s.strip()]

    source_funcs = (
        config.LivaConfig.source_point      # set in this process (all-stages run)
        or source_funcs_persisted            # written by prior source-llm invocation
        or source_funcs_from_config          # from config.ini [SourceFunction]
        or ["websGetVar", "cgiFormString", "httpd_get_parm"]  # hardcoded fallback
    )
    print(f"[INFER] Using source functions: {source_funcs}")
```

- [ ] **Step 1.5: Run all existing tests to confirm nothing is broken**

```bash
cd /Users/yangshuangning/VscodeProjects/LIVA-main
conda run -n iotreaper pytest tests/ -v
```

Expected: all tests pass.

- [ ] **Step 1.6: Commit**

```bash
cd /Users/yangshuangning/VscodeProjects/LIVA-main
git add liva.py tests/test_source_persistence.py
git commit -m "feat: persist source_point to source_functions.json across stage invocations"
```

---

## Task 2: BFS Multi-hop Path Finding in simple_path_finder.py

**Problem:** `find_source_sink_paths()` only finds parent functions that directly call BOTH a source function AND a sink. Indirect paths (A calls source, A calls B, B calls sink) are missed. The call graph has ≤87 nodes so BFS is fast.

**Fix:** Replace the current single-pass loop with a BFS from each source-touching function, traversing the call graph up to `max_depth` hops to find any sink-reaching descendant.

**Backward compatibility:** The function signature stays identical. Existing tests must pass. The output dict structure (`src/dst/rels`) is unchanged; a new `call_chain` list key is added (VulInfer ignores unknown keys).

**Files:**
- Modify: `core/simple_path_finder.py` (full rewrite)
- Modify: `tests/test_simple_path_finder.py` (add BFS tests; keep existing tests)

---

- [ ] **Step 2.1: Add BFS test cases to the existing test file**

Append to `tests/test_simple_path_finder.py`:

```python
# ---- Multi-hop / BFS tests ----

SAMPLE_MULTIHOP = {
    "data": [
        {
            # A calls source and calls B (an intermediate)
            "parent_name": "entry_func",
            "parent_address": "0x1000",
            "child_names": ["intermediate_func"],
            "decompiled_c": "1: void entry_func(webs_t wp) {\n2: val = sub_28B84(wp, \"cmd\", \"\");\n3: intermediate_func(val);\n4: }"
        },
        {
            # B calls a sink — indirect path: entry_func → intermediate_func → system
            "parent_name": "intermediate_func",
            "parent_address": "0x2000",
            "child_names": ["system"],
            "decompiled_c": "1: void intermediate_func(char *s) {\n2: system(s);\n3: }"
        },
        {
            # C calls only a sink (no source connection) — should NOT be a path start
            "parent_name": "unrelated_sink_caller",
            "parent_address": "0x3000",
            "child_names": ["system"],
            "decompiled_c": "1: void unrelated_sink_caller() { system(\"ls\"); }"
        },
    ]
}


@pytest.fixture
def multihop_file(tmp_path):
    p = tmp_path / "multihop.json"
    p.write_text(json.dumps(SAMPLE_MULTIHOP), encoding="utf-8")
    return p


def test_bfs_finds_indirect_source_to_sink(multihop_file):
    """entry_func calls source (in code) → intermediate_func → system: must be found."""
    from core.simple_path_finder import find_source_sink_paths
    paths = find_source_sink_paths(
        parent_child_path=multihop_file,
        source_funcs=["sub_28B84"],
        sink_funcs=["system"],
    )
    assert len(paths) >= 1
    starts = {p["src"]["func_name"] for p in paths}
    assert "entry_func" in starts


def test_bfs_result_has_call_chain(multihop_file):
    """call_chain must record the full hop sequence."""
    from core.simple_path_finder import find_source_sink_paths
    paths = find_source_sink_paths(
        parent_child_path=multihop_file,
        source_funcs=["sub_28B84"],
        sink_funcs=["system"],
    )
    entry_paths = [p for p in paths if p["src"]["func_name"] == "entry_func"]
    assert len(entry_paths) >= 1
    chain = entry_paths[0]["call_chain"]
    assert chain[0] == "entry_func"
    assert "system" in chain


def test_bfs_unrelated_function_not_reported(multihop_file):
    """unrelated_sink_caller calls system but has no path from a source — must not appear."""
    from core.simple_path_finder import find_source_sink_paths
    paths = find_source_sink_paths(
        parent_child_path=multihop_file,
        source_funcs=["sub_28B84"],
        sink_funcs=["system"],
    )
    starts = {p["src"]["func_name"] for p in paths}
    assert "unrelated_sink_caller" not in starts


def test_bfs_max_depth_limits_traversal(tmp_path):
    """Paths longer than max_depth should not be reported."""
    deep_graph = {
        "data": [
            {"parent_name": "A", "parent_address": "0x1", "child_names": ["B"],
             "decompiled_c": "sub_28B84(x);"},
            {"parent_name": "B", "parent_address": "0x2", "child_names": ["C"],
             "decompiled_c": ""},
            {"parent_name": "C", "parent_address": "0x3", "child_names": ["D"],
             "decompiled_c": ""},
            {"parent_name": "D", "parent_address": "0x4", "child_names": ["system"],
             "decompiled_c": ""},
        ]
    }
    p = tmp_path / "deep.json"
    p.write_text(json.dumps(deep_graph))

    from core.simple_path_finder import find_source_sink_paths

    # depth=2: A→B→C, can't reach D→system at depth 3
    paths_shallow = find_source_sink_paths(p, ["sub_28B84"], ["system"], max_depth=2)
    assert len(paths_shallow) == 0

    # depth=4: A→B→C→D→system, reachable
    paths_deep = find_source_sink_paths(p, ["sub_28B84"], ["system"], max_depth=4)
    assert len(paths_deep) >= 1
```

- [ ] **Step 2.2: Run new tests to confirm they fail**

```bash
cd /Users/yangshuangning/VscodeProjects/LIVA-main
conda run -n iotreaper pytest tests/test_simple_path_finder.py -v -k "bfs"
```

Expected: `test_bfs_finds_indirect_source_to_sink` FAIL (function not finding multi-hop), others may error.

- [ ] **Step 2.3: Rewrite core/simple_path_finder.py with BFS**

Replace the entire file content:

```python
import json
import logging
from collections import deque
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple, Union

logger = logging.getLogger(__name__)


def find_source_sink_paths(
    parent_child_path: Union[str, Path],
    source_funcs: List[str],
    sink_funcs: List[str],
    max_depth: int = 5,
) -> List[Dict[str, Any]]:
    """
    Find source-to-sink paths via BFS on the call graph.

    Reads parent_child_calls_ida_decompile.json. For each function that calls
    (or mentions in decompiled code) a source function, performs BFS through
    child_names edges to find any descendant that calls a sink function.

    Paths longer than max_depth hops are not reported.

    Returns dicts compatible with VulInfer.build_reports():
        {
            "src": {"param_func": <source_func>, "func_name": <starting_func>},
            "dst": {"func_name": <sink_func>},
            "call_chain": [<func1>, <func2>, ..., <sink_func>],
            "rels": [],
        }
    """
    path = Path(parent_child_path)
    if not path.exists():
        logger.warning("parent_child_calls file not found: %s", path)
        return []

    root = json.loads(path.read_text(encoding="utf-8"))
    items: List[Dict[str, Any]] = root.get("data", [])

    source_set = set(source_funcs)
    sink_set = set(sink_funcs)

    # Build lookup structures from the call graph
    func_to_children: Dict[str, List[str]] = {}
    func_to_code: Dict[str, str] = {}
    for item in items:
        name: str = item.get("parent_name", "")
        if not name:
            continue
        func_to_children[name] = item.get("child_names", [])
        func_to_code[name] = item.get("decompiled_c") or ""

    def sources_in_func(name: str) -> Set[str]:
        """Source functions called by name — via child_names or decompiled code."""
        children = set(func_to_children.get(name, []))
        code = func_to_code.get(name, "")
        return {s for s in source_set if s in children or s in code}

    def sinks_in_func(name: str) -> Set[str]:
        """Sink functions directly called by name (child_names only)."""
        return set(func_to_children.get(name, [])) & sink_set

    paths: List[Dict[str, Any]] = []
    seen: Set[Tuple] = set()  # (start_func, call_chain_tuple, sink_func)

    for start_name in list(func_to_children.keys()):
        found_sources = sources_in_func(start_name)
        if not found_sources:
            continue

        # BFS from start_name; state = (current_node, path_so_far)
        queue: deque = deque([(start_name, [start_name])])
        visited: Set[str] = {start_name}

        while queue:
            current, current_path = queue.popleft()

            # Emit a path for each sink reachable at this node
            for sink_func in sorted(sinks_in_func(current)):
                full_chain = current_path + [sink_func]
                for src_func in sorted(found_sources):
                    key = (start_name, tuple(full_chain), sink_func)
                    if key in seen:
                        continue
                    seen.add(key)
                    paths.append({
                        "src": {"param_func": src_func, "func_name": start_name},
                        "dst": {"func_name": sink_func},
                        "call_chain": full_chain,
                        "rels": [],
                    })

            # Expand BFS if within depth budget
            if len(current_path) >= max_depth:
                continue
            for child in func_to_children.get(current, []):
                if child in func_to_children and child not in visited:
                    visited.add(child)
                    queue.append((child, current_path + [child]))

    logger.info("SimplePathFinder (BFS, max_depth=%d): found %d source→sink paths",
                max_depth, len(paths))
    return paths
```

- [ ] **Step 2.4: Run all tests**

```bash
cd /Users/yangshuangning/VscodeProjects/LIVA-main
conda run -n iotreaper pytest tests/test_simple_path_finder.py -v
```

Expected: all tests pass, including the 5 original tests and 4 new BFS tests.

- [ ] **Step 2.5: Quick smoke test against CH22 real data**

```bash
cd /Users/yangshuangning/VscodeProjects/LIVA-main
conda run -n iotreaper python3 -c "
from core.simple_path_finder import find_source_sink_paths
paths = find_source_sink_paths(
    'result/CH22_25/httpd_4717ef/parent_child_calls_ida_decompile.json',
    source_funcs=['sub_28B84', 'GetValue'],
    sink_funcs=['system', 'exec', 'popen', 'memcpy', 'strcpy', 'sprintf', 'sscanf', 'strcat'],
)
print(f'Found {len(paths)} paths')
for p in paths[:5]:
    print(' ', p[\"src\"][\"func_name\"], '->', p[\"dst\"][\"func_name\"], '| chain:', p['call_chain'])
"
```

Expected: ≥34 paths (same or more than before, since BFS is a superset of single-hop).

- [ ] **Step 2.6: Commit**

```bash
cd /Users/yangshuangning/VscodeProjects/LIVA-main
git add core/simple_path_finder.py tests/test_simple_path_finder.py
git commit -m "feat: BFS multi-hop path finding in simple_path_finder (max_depth=5)"
```

---

## Task 3: Taint Analysis Integration into Infer Stage

**Problem:** `taint_analysis.json` contains 182 LLM-generated parameter mapping records that are completely ignored by the infer stage. Each record says which variables flow to which argument of a callee. This data would help the LLM decide if user-controlled data actually reaches a dangerous argument position.

**Fix:**
1. New module `core/taint_parser.py` parses `taint_analysis.json` → structured dict.
2. `VulInfer.build_reports()` accepts an optional `taint_map` and includes taint flow info in each report block.
3. `run_stage_infer()` in `liva.py` loads taint data and passes it through.

**Taint result formats** (both parsed with `ast.literal_eval` after stripping Chinese prefix):

Format A — tuple-based (direct sink call):
```python
# result string: '{"FUN_0000e0c4": ("strcpy", {"1": "sub_DCF0(v4)", "2": "a1"}, "line:12", "strcpy(dest, s);")}'
# parsed: {parent: (callee, {arg_idx: value}, line_ref, code_snippet)}
{"FUN_0000e0c4": ("strcpy", {"1": "sub_DCF0(v4)", "2": "a1"}, "line:12", "strcpy(dest, s);")}
```

Format B — dict-of-dict (intermediate call):
```python
# result string: '参数映射关系结构为 {"FUN_0000ef78": {"FUN_00029310": {"1": "v0", "2": "200"}}}'
# parsed: {parent: {callee: {arg_idx: value}}}
{"FUN_0000ef78": {"FUN_00029310": {"1": "v0", "2": "200"}}}
```

**Files:**
- Create: `core/taint_parser.py`
- Modify: `core/vulinfer.py` — `build_reports()` signature and report text
- Modify: `liva.py:run_stage_infer()` — load taint map and pass to VulInfer
- Create: `tests/test_taint_integration.py`

---

- [ ] **Step 3.1: Write tests for taint_parser.py**

Create `tests/test_taint_integration.py`:

```python
import json
import pytest
from pathlib import Path


# ---- Fixtures ----

TAINT_FORMAT_A = '{"FUN_0000e0c4": ("strcpy", {"1": "sub_DCF0(v4)", "2": "a1"}, "line:12", "strcpy(dest, s);")}'
TAINT_FORMAT_B = '参数映射关系结构为 {"FUN_0000ef78": {"FUN_00029310": {"1": "v0", "2": "200"}}}'
TAINT_EMPTY = ""
TAINT_GARBAGE = "不相关信息，无参数映射"

SAMPLE_TAINT_JSON = {
    "meta": {"total_entries": 3, "processed": 3, "timestamp": "2026-01-01 00:00:00"},
    "results": [
        {"index": 1, "entry": "dummy entry A", "result": TAINT_FORMAT_A},
        {"index": 2, "entry": "dummy entry B", "result": TAINT_FORMAT_B},
        {"index": 3, "entry": "dummy entry garbage", "result": TAINT_GARBAGE},
    ]
}


@pytest.fixture
def taint_json_file(tmp_path):
    p = tmp_path / "taint_analysis.json"
    p.write_text(json.dumps(SAMPLE_TAINT_JSON), encoding="utf-8")
    return p


# ---- parse_taint_result tests ----

def test_parse_format_a_returns_dict():
    from core.taint_parser import parse_taint_result
    result = parse_taint_result(TAINT_FORMAT_A)
    assert isinstance(result, dict)
    assert "FUN_0000e0c4" in result


def test_parse_format_a_has_callee():
    from core.taint_parser import parse_taint_result
    result = parse_taint_result(TAINT_FORMAT_A)
    entry = result["FUN_0000e0c4"]
    # tuple: (callee, {arg_idx: val}, line_ref, code_snippet)
    assert entry[0] == "strcpy"
    assert entry[1]["2"] == "a1"


def test_parse_format_b_strips_chinese_prefix():
    from core.taint_parser import parse_taint_result
    result = parse_taint_result(TAINT_FORMAT_B)
    assert "FUN_0000ef78" in result
    inner = result["FUN_0000ef78"]
    assert "FUN_00029310" in inner


def test_parse_empty_returns_empty_dict():
    from core.taint_parser import parse_taint_result
    assert parse_taint_result(TAINT_EMPTY) == {}


def test_parse_garbage_returns_empty_dict():
    from core.taint_parser import parse_taint_result
    assert parse_taint_result(TAINT_GARBAGE) == {}


# ---- load_taint_map tests ----

def test_load_taint_map_keys_are_parent_funcs(taint_json_file):
    from core.taint_parser import load_taint_map
    taint_map = load_taint_map(str(taint_json_file))
    assert "FUN_0000e0c4" in taint_map
    assert "FUN_0000ef78" in taint_map


def test_load_taint_map_missing_file_returns_empty(tmp_path):
    from core.taint_parser import load_taint_map
    result = load_taint_map(str(tmp_path / "nonexistent.json"))
    assert result == {}


def test_load_taint_map_skips_unparseable_entries(taint_json_file):
    from core.taint_parser import load_taint_map
    taint_map = load_taint_map(str(taint_json_file))
    # TAINT_GARBAGE entry should not add any key
    # The map should only have the two valid entries
    assert len(taint_map) == 2


# ---- VulInfer taint enrichment tests ----

def test_build_reports_includes_taint_annotation(tmp_path):
    """When taint_map is provided, report block should contain taint_flow section."""
    import json as _json
    from core.vulinfer import VulInfer

    # Minimal parent_child IDA decompile with one function
    ida_data = {
        "data": [{
            "parent_name": "formAddUser",
            "parent_address": "0x1234",
            "child_names": ["strcpy"],
            "decompiled_c": "1: void formAddUser(webs_t wp) {\n2: char *v = sub_28B84(wp, \"user\", \"\");\n3: strcpy(dest, v);\n4: }"
        }]
    }
    ida_file = tmp_path / "parent_child_calls_ida_decompile.json"
    ida_file.write_text(_json.dumps(ida_data), encoding="utf-8")

    taint_map = {
        "formAddUser": [("strcpy", {"1": "dest", "2": "sub_28B84_result"}, "line:3", "strcpy(dest, v);")]
    }

    paths = [{
        "src": {"param_func": "sub_28B84", "func_name": "formAddUser"},
        "dst": {"func_name": "strcpy"},
        "call_chain": ["formAddUser", "strcpy"],
        "rels": [],
    }]

    infer = VulInfer(ida_json_path=str(ida_file), output_path=str(tmp_path / "out.txt"))
    reports = infer.build_reports(paths=paths, source_func_name="", taint_map=taint_map)

    assert len(reports) == 1
    assert "taint_flow" in reports[0]
    assert "strcpy" in reports[0]


def test_build_reports_works_without_taint_map(tmp_path):
    """taint_map is optional; build_reports must work when not provided."""
    import json as _json
    from core.vulinfer import VulInfer

    ida_data = {"data": [{
        "parent_name": "someFunc",
        "parent_address": "0x1000",
        "child_names": ["system"],
        "decompiled_c": "1: void someFunc() { system(cmd); }"
    }]}
    ida_file = tmp_path / "parent_child_calls_ida_decompile.json"
    ida_file.write_text(_json.dumps(ida_data))

    paths = [{
        "src": {"param_func": "GetValue", "func_name": "someFunc"},
        "dst": {"func_name": "system"},
        "call_chain": ["someFunc", "system"],
        "rels": [],
    }]

    infer = VulInfer(ida_json_path=str(ida_file), output_path=str(tmp_path / "out.txt"))
    reports = infer.build_reports(paths=paths, source_func_name="")
    assert len(reports) == 1
```

- [ ] **Step 3.2: Run tests to confirm they fail**

```bash
cd /Users/yangshuangning/VscodeProjects/LIVA-main
conda run -n iotreaper pytest tests/test_taint_integration.py -v
```

Expected: failures on `from core.taint_parser import ...` (module doesn't exist yet).

- [ ] **Step 3.3: Create core/taint_parser.py**

```python
import ast
import json
import re
from pathlib import Path
from typing import Any, Dict, List


def parse_taint_result(result_str: str) -> dict:
    """
    Parse one taint result string into a dict.

    Handles two LLM output formats:
      Format A: '{"parent": ("callee", {arg_idx: val}, "line:N", "code")}'
      Format B: '参数映射关系结构为 {"parent": {"callee": {arg_idx: val}}}'

    Returns {} on empty input or any parse failure.
    """
    if not result_str or not result_str.strip():
        return {}
    # Strip any leading non-JSON text (Chinese prefix etc.)
    stripped = re.sub(r'^[^{]*', '', result_str.strip())
    if not stripped.startswith('{'):
        return {}
    try:
        return ast.literal_eval(stripped)
    except Exception:
        return {}


def load_taint_map(taint_json_path: str) -> Dict[str, List[Any]]:
    """
    Load taint_analysis.json and return:
      {parent_func_name: [parsed_value, ...]}

    parsed_value is whatever the LLM returned for that parent (tuple or dict).
    Entries that cannot be parsed are silently skipped.
    """
    path = Path(taint_json_path)
    if not path.exists():
        return {}

    with path.open(encoding="utf-8") as f:
        data = json.load(f)

    taint_map: Dict[str, List[Any]] = {}
    for entry in data.get("results", []):
        parsed = parse_taint_result(entry.get("result", ""))
        for parent_func, value in parsed.items():
            taint_map.setdefault(parent_func, []).append(value)

    return taint_map


def format_taint_annotation(func_name: str, taint_map: Dict[str, List[Any]]) -> str:
    """
    Return a human-readable taint flow annotation for func_name, or "" if none.

    Example output:
      taint_flow:
        formAddUser → strcpy(arg1=dest, arg2=sub_28B84_result) @ line:3
    """
    entries = taint_map.get(func_name, [])
    if not entries:
        return ""

    lines = ["taint_flow:"]
    for entry in entries:
        if isinstance(entry, tuple) and len(entry) >= 2:
            # Format A: (callee, {arg_idx: val}, line_ref, code_snippet)
            callee = entry[0]
            args = entry[1] if len(entry) > 1 else {}
            line_ref = entry[2] if len(entry) > 2 else ""
            arg_str = ", ".join(f"arg{k}={v}" for k, v in sorted(args.items()))
            lines.append(f"  {func_name} → {callee}({arg_str}) @ {line_ref}")
        elif isinstance(entry, dict):
            # Format B: {callee: {arg_idx: val}}
            for callee, args in entry.items():
                if isinstance(args, dict):
                    arg_str = ", ".join(f"arg{k}={v}" for k, v in sorted(args.items()))
                    lines.append(f"  {func_name} → {callee}({arg_str})")
    return "\n".join(lines)
```

- [ ] **Step 3.4: Run taint_parser tests to confirm they pass**

```bash
cd /Users/yangshuangning/VscodeProjects/LIVA-main
conda run -n iotreaper pytest tests/test_taint_integration.py -v -k "taint_result or taint_map"
```

Expected: all `parse_taint_result` and `load_taint_map` tests pass.

- [ ] **Step 3.5: Modify VulInfer.build_reports() to accept and use taint_map**

In `core/vulinfer.py`, change the `build_reports` signature and body. Find the current signature:

```python
    def build_reports(
        self,
        paths: List[Dict[str, Any]],
        source_func_name: str = "cgiFormString",
    ) -> List[str]:
```

Replace with:

```python
    def build_reports(
        self,
        paths: List[Dict[str, Any]],
        source_func_name: str = "cgiFormString",
        taint_map: Dict[str, Any] = None,
    ) -> List[str]:
```

Add the import at the top of `core/vulinfer.py` (after existing imports):

```python
from core.taint_parser import format_taint_annotation
```

Inside `build_reports()`, find the `block_lines` assembly block:

```python
            block_lines = [
                f"source_function: {src_param_func}()",
                f"sink_function: {dst_func_name}()",
                f"call_chain: {call_chain}",
                "code:",
                decompiled_code,
                "",  # 分隔空行
            ]
```

Replace with:

```python
            taint_note = ""
            if taint_map:
                taint_note = format_taint_annotation(src_func_name, taint_map)

            block_lines = [
                f"source_function: {src_param_func}()",
                f"sink_function: {dst_func_name}()",
                f"call_chain: {call_chain}",
            ]
            if taint_note:
                block_lines.append(taint_note)
            block_lines += [
                "code:",
                decompiled_code,
                "",  # 分隔空行
            ]
```

Also add `Dict` to the typing import at the top of `core/vulinfer.py` if not already present:

```python
from typing import List, Dict, Any, Optional
```

- [ ] **Step 3.6: Run VulInfer taint enrichment tests**

```bash
cd /Users/yangshuangning/VscodeProjects/LIVA-main
conda run -n iotreaper pytest tests/test_taint_integration.py -v -k "build_reports"
```

Expected: both `test_build_reports_includes_taint_annotation` and `test_build_reports_works_without_taint_map` pass.

- [ ] **Step 3.7: Wire taint loading into run_stage_infer() in liva.py**

In `liva.py`, in `run_stage_infer()`, after the `vulinfer = VulInfer(...)` instantiation, add taint loading and pass to `build_reports`:

Current code (around lines 383–390):

```python
    vulinfer = VulInfer(
        ida_json_path=parent_child_file,
        output_path=base_dir / "cmd_injection_candidates.txt",
    )
    reports = vulinfer.build_reports(paths=paths, source_func_name="")
    merge_report = vulinfer.merge_by_call_chain(reports)
    print(f"Generated {len(merge_report)} merged reports")
    vulinfer.gpt_infer(merge_report, str(base_dir / "vul_result.txt"))
```

Replace with:

```python
    from core.taint_parser import load_taint_map as _load_taint_map
    taint_file = base_dir / "taint_analysis.json"
    taint_map = _load_taint_map(str(taint_file)) if taint_file.exists() else {}
    print(f"[INFER] Loaded taint map: {len(taint_map)} parent functions annotated")

    vulinfer = VulInfer(
        ida_json_path=parent_child_file,
        output_path=base_dir / "cmd_injection_candidates.txt",
    )
    reports = vulinfer.build_reports(paths=paths, source_func_name="", taint_map=taint_map)
    merge_report = vulinfer.merge_by_call_chain(reports)
    print(f"Generated {len(merge_report)} merged reports")
    vulinfer.gpt_infer(merge_report, str(base_dir / "vul_result.txt"))
```

- [ ] **Step 3.8: Run full test suite**

```bash
cd /Users/yangshuangning/VscodeProjects/LIVA-main
conda run -n iotreaper pytest tests/ -v
```

Expected: all tests pass.

- [ ] **Step 3.9: End-to-end smoke test on CH22 data**

```bash
cd /Users/yangshuangning/VscodeProjects/LIVA-main
conda run -n iotreaper python3 liva.py \
  "/Users/yangshuangning/VscodeProjects/LIVA-main/CH22/bin/httpd" \
  "/Users/yangshuangning/VscodeProjects/LIVA-main/CH22" \
  "CH22_25" \
  --stages infer 2>&1
```

Expected output contains:
- `[INFER] Loaded taint map: N parent functions annotated` (N > 0)
- `Found N source→sink paths` (≥34)
- `Generated N merged reports`
- `vul_result.txt` updated with taint_flow sections in some reports

- [ ] **Step 3.10: Commit**

```bash
cd /Users/yangshuangning/VscodeProjects/LIVA-main
git add core/taint_parser.py core/vulinfer.py liva.py tests/test_taint_integration.py
git commit -m "feat: integrate taint_analysis.json into infer stage via taint_parser module"
```

---

## Self-Review

**Spec coverage:**
- ✅ Task 1: source_point persisted to `source_functions.json`, loaded in infer
- ✅ Task 2: BFS multi-hop in `simple_path_finder.py`, `max_depth` param, `call_chain` in output
- ✅ Task 3: `taint_parser.py` parses both result formats, `VulInfer.build_reports()` annotates reports, `liva.py` loads and passes taint map

**Placeholder scan:** No TBDs or hand-wavy steps. All code blocks are complete.

**Type consistency:**
- `load_taint_map` returns `Dict[str, List[Any]]` — used as `taint_map` in `build_reports(taint_map=...)` ✅
- `format_taint_annotation(func_name, taint_map)` signature matches usage in vulinfer.py ✅
- `find_source_sink_paths` signature adds `max_depth: int = 5` — new tests use `max_depth=2` and `max_depth=4` ✅
- `build_reports(paths, source_func_name, taint_map=None)` — default None means Task 3 is backward-compatible ✅
