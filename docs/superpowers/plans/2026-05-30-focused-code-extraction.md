# Focused Code Extraction Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `_extract_focused_snippet()` to `VulInfer` so that long decompiled functions are clipped to a focused window around the sink call before being sent to the LLM, preventing context overload that causes false-negative vulnerability verdicts.

**Architecture:** One new private method in `VulInfer` clips code to: first 8 declaration lines + ±10 lines around each sink call + ±3 lines around each source call. Two call sites in `build_reports()` apply it per-function when `source_funcs` is provided. One call-site update in `liva.py` passes `source_funcs` through.

**Tech Stack:** Python 3.10+, pytest, standard library only.

---

## Background

`FUN_0006b32c` (115 lines) and `FUN_0006358c` (82 lines) contain the **identical** vulnerability pattern:

```c
GetValue("usb.samba.userlist", s);
doSystemCmd("echo '%s' > /tmp/userListFile", s);
```

`FUN_0006358c` gets **Yes**. `FUN_0006b32c` gets **No**.

The difference: `FUN_0006b32c` has 8 additional `GetValue` calls after line 35, all reusing variable `s`. The LLM sees `s` overwritten repeatedly and loses confidence that the `s` in `doSystemCmd` is user-controlled.

The fix: clip the function so the LLM only sees the first 8 declaration lines, the sink call ±10 lines, and any source calls ±3 lines. The 8 noisy `GetValue` calls (lines 37–72) collapse to a single `// [... N lines omitted ...]` marker.

---

## File Map

| File | Action | Responsibility |
|---|---|---|
| `core/vulinfer.py` | Modify | Add `_extract_focused_snippet()`; update `build_reports()` signature and two code-assignment sites |
| `liva.py` | Modify | Pass `source_funcs` to `build_reports()` at line 403 |
| `tests/test_vulinfer_snippet.py` | Create | Unit tests for `_extract_focused_snippet()` |

---

## Task 1: Add `_extract_focused_snippet` to VulInfer

**Files:**
- Modify: `core/vulinfer.py` — insert new method after `_get_decompiled_code` (currently ends at line 83)
- Create: `tests/test_vulinfer_snippet.py`

---

- [ ] **Step 1: Create the test file with all failing tests**

Create `tests/test_vulinfer_snippet.py`:

```python
from pathlib import Path
import re
import pytest
from core.vulinfer import VulInfer


@pytest.fixture
def vi():
    return VulInfer(ida_json_path=Path("/nonexistent"))


def _noise(n, prefix="generic"):
    return [f"  {prefix}_call_{i}();" for i in range(n)]


def test_short_code_returned_unchanged(vi):
    code = "\n".join(_noise(30))
    assert vi._extract_focused_snippet(code, "doSystemCmd", ["GetValue"]) == code


def test_sink_not_found_returns_full_code(vi):
    code = "\n".join(_noise(80))
    assert vi._extract_focused_snippet(code, "doSystemCmd", ["GetValue"]) == code


def test_first_8_lines_always_kept(vi):
    declarations = [f"  int v{i}; // [sp+{i*4}h]" for i in range(8)]
    code = "\n".join(declarations + _noise(60) + ['  doSystemCmd("cmd");'])
    result = vi._extract_focused_snippet(code, "doSystemCmd", ["GetValue"])
    for decl in declarations:
        assert decl in result.splitlines()


def test_sink_line_always_kept(vi):
    code = "\n".join(_noise(8) + _noise(40) + ['  doSystemCmd("echo", s);'] + _noise(60))
    result = vi._extract_focused_snippet(code, "doSystemCmd", ["GetValue"])
    assert 'doSystemCmd("echo", s)' in result


def test_source_call_near_sink_included(vi):
    lines = _noise(8) + _noise(30)
    lines += ['  GetValue("usb.samba.userlist", s);']  # index 38
    lines += ['  doSystemCmd("echo \'%s\'", s);']       # index 39
    lines += _noise(40)
    result = vi._extract_focused_snippet("\n".join(lines), "doSystemCmd", ["GetValue"])
    assert 'GetValue("usb.samba.userlist", s)' in result
    assert "doSystemCmd" in result


def test_source_calls_far_from_sink_collapsed(vi):
    """Reproduces FUN_0006b32c: key GetValue+doSystemCmd at lines 34-35,
    then 8 more GetValue calls far after the sink that should be omitted."""
    lines = _noise(8)           # declarations
    lines += _noise(26)         # noise
    lines += ['  GetValue("usb.samba.userlist", s);']  # index 34 — relevant
    lines += ['  doSystemCmd("echo \'%s\'", s);']       # index 35 — sink
    for key in ["ftp.enable", "lan.ip", "lan.port", "lan.en",
                "wans.flag", "wans.mode", "wans.policy", "wan.type"]:
        lines += _noise(2)
        lines += [f'  GetValue("{key}", s);']
    lines += ["  return 0;"]
    code = "\n".join(lines)

    result = vi._extract_focused_snippet(code, "doSystemCmd", ["GetValue"])

    assert 'GetValue("usb.samba.userlist", s)' in result   # near-sink source kept
    assert "// [..." in result                              # omission marker present
    assert len(result.splitlines()) < len(lines)            # actually shorter


def test_omission_marker_shows_line_count(vi):
    lines = _noise(8) + _noise(50) + ['  doSystemCmd("cmd");'] + _noise(5)
    result = vi._extract_focused_snippet("\n".join(lines), "doSystemCmd", ["GetValue"])
    markers = re.findall(r'// \[... (\d+) lines omitted \.\.\.\]', result)
    assert markers, "expected at least one omission marker"
    assert int(markers[0]) > 0


def test_multiple_sink_occurrences_all_included(vi):
    lines = _noise(8) + _noise(30)
    lines += ['  doSystemCmd("cmd1");']   # first sink
    lines += _noise(30)
    lines += ['  doSystemCmd("cmd2");']   # second sink
    lines += _noise(10)
    result = vi._extract_focused_snippet("\n".join(lines), "doSystemCmd", ["GetValue"])
    assert 'doSystemCmd("cmd1")' in result
    assert 'doSystemCmd("cmd2")' in result
```

- [ ] **Step 2: Run tests to confirm they all fail with AttributeError**

```bash
cd /Users/yangshuangning/VscodeProjects/LIVA-main
python -m pytest tests/test_vulinfer_snippet.py -v 2>&1 | head -20
```

Expected: `AttributeError: 'VulInfer' object has no attribute '_extract_focused_snippet'`

- [ ] **Step 3: Insert `_extract_focused_snippet` into `core/vulinfer.py`**

Insert immediately after `_get_decompiled_code` (after line 83), before `build_reports`:

```python
    def _extract_focused_snippet(
        self,
        code: str,
        sink_func: str,
        source_funcs: List[str],
        context_lines: int = 10,
    ) -> str:
        """Clip a long decompiled function to lines relevant for vulnerability judgment.

        Returns code unchanged when ≤ 50 lines or sink_func not found in code.
        Otherwise keeps: first 8 lines (declarations) + ±context_lines around each
        sink call + ±3 lines around each source function call.
        Gaps are replaced with '// [... N lines omitted ...]' markers.
        """
        lines = code.splitlines()
        if len(lines) <= 50:
            return code

        sink_indices = [i for i, ln in enumerate(lines) if sink_func in ln]
        if not sink_indices:
            return code

        important: set = set()

        for i in range(min(8, len(lines))):
            important.add(i)

        for si in sink_indices:
            for j in range(max(0, si - context_lines), min(len(lines), si + context_lines + 1)):
                important.add(j)

        for i, ln in enumerate(lines):
            if any(src in ln for src in source_funcs):
                for j in range(max(0, i - 3), min(len(lines), i + 4)):
                    important.add(j)

        result: List[str] = []
        prev = -1
        for idx in sorted(important):
            if prev != -1 and idx > prev + 1:
                result.append(f"  // [... {idx - prev - 1} lines omitted ...]")
            result.append(lines[idx])
            prev = idx

        return "\n".join(result)
```

- [ ] **Step 4: Run tests to confirm they all pass**

```bash
cd /Users/yangshuangning/VscodeProjects/LIVA-main
python -m pytest tests/test_vulinfer_snippet.py -v
```

Expected: `8 passed`

- [ ] **Step 5: Confirm existing tests still pass**

```bash
python -m pytest tests/ -q --tb=short
```

Expected: `34 passed` (26 existing + 8 new)

- [ ] **Step 6: Commit**

```bash
cd /Users/yangshuangning/VscodeProjects/LIVA-main
git add tests/test_vulinfer_snippet.py core/vulinfer.py
git commit -m "feat: add _extract_focused_snippet to VulInfer"
```

---

## Task 2: Wire extraction into `build_reports` and `liva.py`

**Files:**
- Modify: `core/vulinfer.py:85-89` (signature) and two code-assignment sites inside `build_reports`
- Modify: `liva.py:403`
- Test: `tests/test_vulinfer_snippet.py` (add one integration test)

---

- [ ] **Step 1: Add a failing integration test to `tests/test_vulinfer_snippet.py`**

Append to the end of `tests/test_vulinfer_snippet.py`:

```python
def test_build_reports_with_source_funcs_clips_long_code(tmp_path):
    """build_reports(source_funcs=...) must clip long functions via _extract_focused_snippet."""
    declarations = [f"  int v{i}; // [sp+{i*4}h]" for i in range(8)]
    noise_before = _noise(30)
    relevant = [
        '  GetValue("usb.samba.userlist", s);',
        '  doSystemCmd("echo \'%s\' > /tmp/userListFile", s);',
    ]
    noise_after_with_getvalue = []
    for key in ["ftp.enable", "lan.ip", "lan.port", "lan.en",
                "wans.flag", "wans.mode", "wans.policy", "wan.type"]:
        noise_after_with_getvalue += _noise(2)
        noise_after_with_getvalue += [f'  GetValue("{key}", s);']
    tail = ["  return 0;"]
    func_body = "\n".join(declarations + noise_before + relevant
                          + noise_after_with_getvalue + tail)

    # func_body is > 50 lines with the key pattern buried and noisy GetValues after
    assert len(func_body.splitlines()) > 50

    ida_json = tmp_path / "ida.json"
    import json as _json
    ida_json.write_text(_json.dumps({
        "data": [{
            "parent_name": "FUN_test",
            "child_names": ["GetValue", "doSystemCmd"],
            "decompiled_c": func_body,
        }]
    }), encoding="utf-8")

    vulinfer = VulInfer(ida_json_path=ida_json, output_path=tmp_path / "out.txt")
    paths = [{
        "src": {"param_func": "GetValue", "func_name": "FUN_test"},
        "dst": {"func_name": "doSystemCmd"},
        "rels": [],
        "taint_chain": [],
        "path_type": "direct",
    }]

    reports = vulinfer.build_reports(
        paths=paths,
        source_func_name="",
        source_funcs=["GetValue"],
    )

    assert reports, "expected at least one report"
    report_code_section = reports[0].split("code:\n", 1)[-1]
    assert 'GetValue("usb.samba.userlist", s)' in report_code_section
    assert "doSystemCmd" in report_code_section
    assert "// [..." in report_code_section
    assert len(report_code_section.splitlines()) < len(func_body.splitlines())
```

- [ ] **Step 2: Run to confirm it fails**

```bash
cd /Users/yangshuangning/VscodeProjects/LIVA-main
python -m pytest tests/test_vulinfer_snippet.py::test_build_reports_with_source_funcs_clips_long_code -v
```

Expected: `TypeError: build_reports() got an unexpected keyword argument 'source_funcs'`

- [ ] **Step 3: Update `build_reports` signature in `core/vulinfer.py`**

Change lines 85–89 from:

```python
    def build_reports(
        self,
        paths: List[Dict[str, Any]],
        source_func_name: str = "cgiFormString",
    ) -> List[str]:
```

to:

```python
    def build_reports(
        self,
        paths: List[Dict[str, Any]],
        source_func_name: str = "cgiFormString",
        source_funcs: Optional[List[str]] = None,
    ) -> List[str]:
```

- [ ] **Step 4: Apply extraction in the taint-chain branch**

In `build_reports`, change lines 149–152 (inside the `if taint_steps:` branch) from:

```python
                        code_parts.append(
                            f"// --- {func} ---\n{self._get_decompiled_code(func)}"
                        )
```

to:

```python
                        raw = self._get_decompiled_code(func)
                        if source_funcs:
                            raw = self._extract_focused_snippet(
                                raw, dst_func_name, source_funcs
                            )
                        code_parts.append(f"// --- {func} ---\n{raw}")
```

- [ ] **Step 5: Apply extraction in the direct-path branch**

In `build_reports`, change line 162 (inside the `else:` branch) from:

```python
                decompiled_code = self._get_decompiled_code(src_func_name)
```

to:

```python
                raw = self._get_decompiled_code(src_func_name)
                if source_funcs:
                    raw = self._extract_focused_snippet(
                        raw, dst_func_name, source_funcs
                    )
                decompiled_code = raw
```

- [ ] **Step 6: Update the call site in `liva.py`**

Change line 403 from:

```python
    reports = vulinfer.build_reports(paths=paths, source_func_name="")
```

to:

```python
    reports = vulinfer.build_reports(paths=paths, source_func_name="", source_funcs=source_funcs)
```

(`source_funcs` is already defined at line 383 of `run_stage_infer` as `merged_sources or ["websGetVar", "cgiFormString", "httpd_get_parm"]`.)

- [ ] **Step 7: Run all tests**

```bash
cd /Users/yangshuangning/VscodeProjects/LIVA-main
python -m pytest tests/ -q --tb=short
```

Expected: `35 passed`

- [ ] **Step 8: Commit**

```bash
cd /Users/yangshuangning/VscodeProjects/LIVA-main
git add core/vulinfer.py liva.py tests/test_vulinfer_snippet.py
git commit -m "feat: wire focused code extraction into build_reports to reduce LLM context overload"
```

---

## Task 3: Smoke-test on CH22_30v1

**Files:** None modified — measurement only.

- [ ] **Step 1: Back up baseline**

```bash
cd /Users/yangshuangning/VscodeProjects/LIVA-main
cp result/CH22_30v1/httpd_4717ef/vul_result.txt \
   result/CH22_30v1/httpd_4717ef/vul_result_before_extraction.txt
```

- [ ] **Step 2: Re-run infer stage**

```bash
python liva.py CH22/httpd_4717ef CH22 CH22_30v1 --stages infer
```

Expected console output includes: `Generated 54 merged reports` (same count — extraction only changes what LLM sees, not path count).

- [ ] **Step 3: Count new Yes verdicts**

```bash
grep -c "Response: b'Yes" result/CH22_30v1/httpd_4717ef/vul_result.txt
```

Baseline: **2**. Target: **≥ 3**, minimum must include `FUN_0006b32c->doSystemCmd()` since its pattern is now unambiguous after extraction.

- [ ] **Step 4: Verify FUN_0006b32c specifically**

```bash
grep -A3 "call_chain: FUN_0006b32c->doSystemCmd" \
    result/CH22_30v1/httpd_4717ef/vul_result.txt
```

Expected: `Response: b'Yes\r\n\r\n'`

---

## Self-Review

**Spec coverage:**
- [x] `_extract_focused_snippet` method: Task 1
- [x] Short functions pass through unchanged: `test_short_code_returned_unchanged`
- [x] Sink-not-found passthrough: `test_sink_not_found_returns_full_code`
- [x] FUN_0006b32c scenario (far source calls collapsed): `test_source_calls_far_from_sink_collapsed`
- [x] Wire into `build_reports` both branches: Task 2 Steps 4–5
- [x] Wire `source_funcs` through `liva.py`: Task 2 Step 6
- [x] Integration test: `test_build_reports_with_source_funcs_clips_long_code`
- [x] Measure improvement: Task 3

**Placeholder scan:** All code blocks are complete. No TBD/TODO.

**Type consistency:** `_extract_focused_snippet(self, code: str, sink_func: str, source_funcs: List[str], context_lines: int = 10) -> str` — signature is identical in Task 1 Step 3 (definition) and Task 2 Steps 4–5 (call sites).
