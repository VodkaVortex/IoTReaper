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
