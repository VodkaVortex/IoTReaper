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
    assert any(
        p["src"]["func_name"] == "handler"
        and p["dst"]["func_name"] == "system"
        and len(p.get("taint_chain", [])) >= 1
        for p in paths
    ), "Expected path with populated taint_chain"


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
        and len(p.get("taint_chain", [])) == 2
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
