"""
Tests for run_stage_danger() source/sink list construction.

These tests focus on the data written to SQLite (captured via mock),
not on the Ghidra/IDA analysis that follows.
"""
import ast
import configparser
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_ini_config():
    """Return a ConfigParser matching the project's config.ini structure."""
    cfg = configparser.ConfigParser()
    cfg.read_dict({
        "VulFunction": {
            "buffer_overflow": "memcpy, strcpy, sprintf, sscanf, strcat",
            "command_injection": "system, exec, popen, doSystemCmd",
            "param": '{"system": "1", "popen": "1"}',
        },
        "SourceFunction": {
            "http_param": "sub_28B84, GetValue",
        },
        "IDAMCP": {
            "ida_mcp_path": "/fake/ida-mcp",
            "ida_dir": "/fake/ida",
        },
    })
    return cfg


def _run_danger_with_mocks(source_point: list, sink_point: list) -> dict:
    """
    Call run_stage_danger() with mocked external dependencies.
    Returns dict {tag: data_string} as captured from upsert_ProjectInfo_data calls.

    Patches:
    - config.LivaConfig attributes (source_point, sink_point, config)
    - upsert_ProjectInfo_data  →  captures tag/data pairs
    - builtins.input           →  returns "" (skip interactive prompt)
    - liva.DangerFuncAnalyzer  →  no-op mock (avoids real IDA/Ghidra)
    """
    from config import config as liva_config
    import liva

    # Stash originals so tests don't bleed into each other
    orig_source = liva_config.LivaConfig.source_point
    orig_sink   = liva_config.LivaConfig.sink_point
    orig_cfg    = liva_config.LivaConfig.config

    liva_config.LivaConfig.source_point = list(source_point)
    liva_config.LivaConfig.sink_point   = list(sink_point)
    liva_config.LivaConfig.config       = _make_ini_config()

    captured = {}

    def fake_upsert(tag, data):
        captured[tag] = data

    mock_danger_inst = MagicMock()
    mock_danger_inst.run_dangerfunc_batch_analysis.return_value = None
    mock_danger_inst.run_dangercompile_IDA.return_value = None

    try:
        with patch("liva.upsert_ProjectInfo_data", side_effect=fake_upsert), \
             patch("builtins.input", return_value=""), \
             patch("liva.DangerFuncAnalyzer", return_value=mock_danger_inst):
            liva.run_stage_danger()
    finally:
        liva_config.LivaConfig.source_point = orig_source
        liva_config.LivaConfig.sink_point   = orig_sink
        liva_config.LivaConfig.config       = orig_cfg

    return captured


# ---------------------------------------------------------------------------
# Bug 1: sink 列表
# ---------------------------------------------------------------------------

def test_sink_includes_sprintf_when_llm_found_sinks():
    """Bug 1: sprintf must survive even when LLM identified other sinks."""
    captured = _run_danger_with_mocks(
        source_point=["GetValue"],
        sink_point=["doSystemCmd"],   # non-empty → LLM found something
    )
    sink_list = ast.literal_eval(captured["sink"])
    assert "sprintf" in sink_list, (
        f"sprintf should be preserved from config.ini [VulFunction] but got: {sink_list}"
    )


def test_sink_includes_all_config_ini_sinks_when_llm_found_sinks():
    """Bug 1: every function in config.ini [VulFunction] must appear in sink list."""
    captured = _run_danger_with_mocks(
        source_point=["GetValue"],
        sink_point=["doSystemCmd"],
    )
    sink_list = ast.literal_eval(captured["sink"])
    expected = {"memcpy", "strcpy", "sprintf", "sscanf", "strcat",
                "system", "exec", "popen", "doSystemCmd"}
    missing = expected - set(sink_list)
    assert not missing, f"Missing sinks: {missing}; got: {sink_list}"


def test_sink_fallback_unchanged_when_llm_found_nothing():
    """Bug 1: when sink_point is empty the fallback string is still used (no regression)."""
    captured = _run_danger_with_mocks(
        source_point=[],
        sink_point=[],   # LLM found nothing → fallback branch
    )
    sink_list = ast.literal_eval(captured["sink"])
    assert "sprintf" in sink_list
    assert "strcpy" in sink_list
