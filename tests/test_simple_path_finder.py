import json
import pytest
from pathlib import Path


SAMPLE_PARENT_CHILD = {
    "data": [
        {
            "parent_name": "handle_request",
            "parent_address": "0x1000",
            "child_names": ["websGetVar", "system", "printf"],
            "decompiled_c": "1: void handle_request() {\n2: v = websGetVar(...);\n3: system(v);\n4: }"
        },
        {
            "parent_name": "safe_func",
            "parent_address": "0x2000",
            "child_names": ["printf", "strlen"],
            "decompiled_c": "1: void safe_func() {}"
        },
        {
            "parent_name": "multi_sink",
            "parent_address": "0x3000",
            "child_names": ["httpd_get_parm", "popen", "system"],
            "decompiled_c": "1: void multi_sink() {}"
        }
    ]
}


@pytest.fixture
def parent_child_file(tmp_path):
    p = tmp_path / "parent_child_calls_ida_decompile.json"
    p.write_text(json.dumps(SAMPLE_PARENT_CHILD), encoding="utf-8")
    return p


def test_finds_direct_source_to_sink_path(parent_child_file):
    from core.simple_path_finder import find_source_sink_paths
    paths = find_source_sink_paths(
        parent_child_path=parent_child_file,
        source_funcs=["websGetVar"],
        sink_funcs=["system", "popen"],
    )
    assert len(paths) >= 1
    src_funcs = {p["src"]["func_name"] for p in paths}
    assert "handle_request" in src_funcs


def test_skips_functions_without_source(parent_child_file):
    from core.simple_path_finder import find_source_sink_paths
    paths = find_source_sink_paths(
        parent_child_path=parent_child_file,
        source_funcs=["websGetVar"],
        sink_funcs=["system"],
    )
    src_funcs = {p["src"]["func_name"] for p in paths}
    assert "safe_func" not in src_funcs


def test_multiple_sinks_from_same_parent(parent_child_file):
    from core.simple_path_finder import find_source_sink_paths
    paths = find_source_sink_paths(
        parent_child_path=parent_child_file,
        source_funcs=["httpd_get_parm"],
        sink_funcs=["popen", "system"],
    )
    sink_names = {p["dst"]["func_name"] for p in paths}
    assert "popen" in sink_names
    assert "system" in sink_names


def test_path_has_expected_structure(parent_child_file):
    from core.simple_path_finder import find_source_sink_paths
    paths = find_source_sink_paths(
        parent_child_path=parent_child_file,
        source_funcs=["websGetVar"],
        sink_funcs=["system"],
    )
    assert len(paths) >= 1
    p = paths[0]
    assert "src" in p and "dst" in p and "rels" in p
    assert "param_func" in p["src"]
    assert "func_name" in p["src"]
    assert "func_name" in p["dst"]


def test_missing_file_returns_empty_list(tmp_path):
    from core.simple_path_finder import find_source_sink_paths
    paths = find_source_sink_paths(
        parent_child_path=tmp_path / "nonexistent.json",
        source_funcs=["websGetVar"],
        sink_funcs=["system"],
    )
    assert paths == []
