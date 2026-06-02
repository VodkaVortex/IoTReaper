# Fix Source/Sink Missing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 修复 `run_stage_danger()` 中两处逻辑缺陷，确保 `sprintf` 等 buffer overflow sink 和 `sub_28B84` 等 config 级 source 函数始终进入 SQLite，使 `DangerFlowAnalyzer.java` 能正确识别 `frmL7ImForm` 类漏洞函数。

**Architecture:** 仅改动 `liva.py` 的 `run_stage_danger()` 函数。Bug 1：当 LLM 识别出 sink 时，在写入 SQLite 之前，从 `config.ini [VulFunction]` 读出所有 sink 函数名并追加缺失项。Bug 2：在写入 SQLite 的 source 字段之前，合并 `config.ini [SourceFunction]` 的所有函数名（与 `run_stage_infer()` 已有逻辑保持一致）。

**Tech Stack:** Python 3, pytest, unittest.mock, configparser（标准库）

---

## 文件变更清单

| 操作 | 文件 | 说明 |
|------|------|------|
| 新建 | `tests/test_run_stage_danger.py` | 两个 bug 的单元测试 |
| 修改 | `liva.py:260-273` | Bug 1 + Bug 2 修复，共约 12 行逻辑 |

---

## Task 1：为 Bug 1 写失败测试（sink 列表缺少 sprintf）

**Files:**
- Create: `tests/test_run_stage_danger.py`

- [ ] **Step 1：创建测试文件，写辅助函数和 Bug 1 测试**

`tests/test_run_stage_danger.py` 完整内容：

```python
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


def _run_danger_with_mocks(source_point, sink_point):
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
    # fallback is a raw string literal, not a list
    assert "sprintf" in captured["sink"]
    assert "strcpy" in captured["sink"]
```

- [ ] **Step 2：运行测试，确认 Bug 1 两条测试失败**

```bash
cd /Users/yangshuangning/VscodeProjects/LIVA-main
pytest tests/test_run_stage_danger.py::test_sink_includes_sprintf_when_llm_found_sinks \
       tests/test_run_stage_danger.py::test_sink_includes_all_config_ini_sinks_when_llm_found_sinks \
       -v
```

预期：**FAILED** — `AssertionError: sprintf should be preserved from config.ini`  
（当前代码只追加 `system` 和 `strcpy`，`sprintf` 不在结果里）

- [ ] **Step 3：fallback 测试应已通过（验证辅助函数本身没问题）**

```bash
pytest tests/test_run_stage_danger.py::test_sink_fallback_unchanged_when_llm_found_nothing -v
```

预期：**PASSED**

---

## Task 2：实现 Bug 1 修复并验证

**Files:**
- Modify: `liva.py:268-273`

- [ ] **Step 1：修改 `liva.py` Bug 1 片段**

将 `run_stage_danger()` 中的：

```python
        sink_data = "['system','strcat','sprintf','popen','strcpy']"
        if len(config.LivaConfig.sink_point) != 0:
            config.LivaConfig.sink_point.append("system")
            config.LivaConfig.sink_point.append("strcpy")
            sink_data = str(config.LivaConfig.sink_point)
        upsert_ProjectInfo_data(tag="sink", data=sink_data)
```

替换为：

```python
        sink_data = "['system','strcat','sprintf','popen','strcpy']"
        if len(config.LivaConfig.sink_point) != 0:
            vul_funcs = config.LivaConfig.config.get("VulFunction", {})
            for val in vul_funcs.values():
                try:
                    json.loads(val)   # skip "param" key which is a JSON object
                    continue
                except Exception:
                    pass
                for s in val.split(","):
                    s = s.strip()
                    if s and s not in config.LivaConfig.sink_point:
                        config.LivaConfig.sink_point.append(s)
            sink_data = str(config.LivaConfig.sink_point)
        upsert_ProjectInfo_data(tag="sink", data=sink_data)
```

注：`json` 已在 `liva.py` 第 19 行 import，无需新增 import。

- [ ] **Step 2：运行 Bug 1 的三条测试，全部应通过**

```bash
pytest tests/test_run_stage_danger.py::test_sink_includes_sprintf_when_llm_found_sinks \
       tests/test_run_stage_danger.py::test_sink_includes_all_config_ini_sinks_when_llm_found_sinks \
       tests/test_run_stage_danger.py::test_sink_fallback_unchanged_when_llm_found_nothing \
       -v
```

预期：3 条全部 **PASSED**

- [ ] **Step 3：提交**

```bash
git add liva.py tests/test_run_stage_danger.py
git commit -m "fix: always merge config.ini VulFunction sinks into sink list in danger stage

When LLM identified sinks override the default, buffer overflow sinks
(sprintf, strcat, popen, sscanf, memcpy) were being silently dropped.
Now all functions in config.ini [VulFunction] are appended before
writing to SQLite, making config.ini the single source of truth."
```

---

## Task 3：为 Bug 2 写失败测试（source 列表缺少 sub_28B84）

**Files:**
- Modify: `tests/test_run_stage_danger.py`（追加测试函数）

- [ ] **Step 1：在 `tests/test_run_stage_danger.py` 末尾追加 Bug 2 测试**

```python
# ---------------------------------------------------------------------------
# Bug 2: source 列表
# ---------------------------------------------------------------------------

def test_source_includes_sub28B84_from_config_ini():
    """Bug 2: sub_28B84 from config.ini [SourceFunction] must reach SQLite source field."""
    captured = _run_danger_with_mocks(
        source_point=["GetValue"],   # LLM found GetValue only
        sink_point=[],
    )
    source_list = ast.literal_eval(captured["source"])
    assert "sub_28B84" in source_list, (
        f"sub_28B84 from config.ini [SourceFunction] should be merged in, got: {source_list}"
    )


def test_source_includes_config_ini_even_when_source_point_empty():
    """Bug 2: config.ini [SourceFunction] merged even when LLM source stage was skipped."""
    captured = _run_danger_with_mocks(
        source_point=[],   # source stage skipped / LLM found nothing
        sink_point=[],
    )
    source_list = ast.literal_eval(captured["source"])
    assert "sub_28B84" in source_list
    assert "GetValue" in source_list


def test_source_no_duplicates():
    """Bug 2: GetValue appears in both source_point and config.ini; must not be duplicated."""
    captured = _run_danger_with_mocks(
        source_point=["GetValue"],
        sink_point=[],
    )
    source_list = ast.literal_eval(captured["source"])
    assert source_list.count("GetValue") == 1, (
        f"GetValue duplicated: {source_list}"
    )
```

- [ ] **Step 2：运行 Bug 2 测试，确认失败**

```bash
pytest tests/test_run_stage_danger.py::test_source_includes_sub28B84_from_config_ini \
       tests/test_run_stage_danger.py::test_source_includes_config_ini_even_when_source_point_empty \
       tests/test_run_stage_danger.py::test_source_no_duplicates \
       -v
```

预期：前两条 **FAILED**（`sub_28B84` 不在列表里），第三条 **PASSED**（去重在加之前就不需要）  

注：`test_source_no_duplicates` 在修复前也会通过（因为此时根本没有 sub_28B84），修复后仍然通过，用来防止将来引入重复。

---

## Task 4：实现 Bug 2 修复并验证

**Files:**
- Modify: `liva.py:260-264`

- [ ] **Step 1：修改 `liva.py` Bug 2 片段**

将 `run_stage_danger()` 中的：

```python
        if config.LivaConfig.source_point != []:
            parsed_sources = config.LivaConfig.source_point
        # Save sources
        print("SourcePoint: ",parsed_sources)
        upsert_ProjectInfo_data(tag="source", data=str(parsed_sources))
```

替换为：

```python
        if config.LivaConfig.source_point != []:
            parsed_sources = config.LivaConfig.source_point
        # Merge config.ini [SourceFunction] — consistent with run_stage_infer()
        if "SourceFunction" in config.LivaConfig.config:
            for val in config.LivaConfig.config["SourceFunction"].values():
                for s in val.split(","):
                    s = s.strip()
                    if s and s not in parsed_sources:
                        parsed_sources.append(s)
        # Save sources
        print("SourcePoint: ", parsed_sources)
        upsert_ProjectInfo_data(tag="source", data=str(parsed_sources))
```

- [ ] **Step 2：运行全部 Bug 2 测试**

```bash
pytest tests/test_run_stage_danger.py::test_source_includes_sub28B84_from_config_ini \
       tests/test_run_stage_danger.py::test_source_includes_config_ini_even_when_source_point_empty \
       tests/test_run_stage_danger.py::test_source_no_duplicates \
       -v
```

预期：3 条全部 **PASSED**

- [ ] **Step 3：运行全部测试，确认无回归**

```bash
pytest tests/test_run_stage_danger.py -v
```

预期：6 条全部 **PASSED**

- [ ] **Step 4：运行现有测试套件，确认无回归**

```bash
pytest tests/ -v
```

预期：所有已有测试继续通过

- [ ] **Step 5：提交**

```bash
git add liva.py tests/test_run_stage_danger.py
git commit -m "fix: merge config.ini SourceFunction into danger stage source list

sub_28B84 and other functions declared in config.ini [SourceFunction]
were not reaching DangerFlowAnalyzer because run_stage_danger only
wrote LLM-identified sources to SQLite. Now merges config.ini sources
before writing, consistent with how run_stage_infer() already behaves."
```

---

## 验收检查（人工，可选）

在真实固件上重跑 danger 阶段后验证：

```bash
sqlite3 result/CH22_30v2/ghidra_analyze_res.db \
  "SELECT tag, data FROM project_info WHERE tag IN ('source','sink');"
```

预期：
- `source` 字段包含 `sub_28B84`
- `sink` 字段包含 `sprintf`
