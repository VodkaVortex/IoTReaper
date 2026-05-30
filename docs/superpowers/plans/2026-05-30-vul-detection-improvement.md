# Vulnerability Detection Rate Improvement Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Increase LLM Yes-verdict rate from 2/54 (3.7%) by fixing the two root causes: an overly conservative LLM prompt and context overload from long decompiled functions.

**Architecture:** Two-layer fix. Layer 1 (config, no code): rewrite `vul_session.json` with a precise system prompt and 3 few-shot examples covering common IoT patterns. Layer 2 (code): add `_extract_focused_snippet()` to `VulInfer` that clips long functions to a window around the sink call, then wire it into `build_reports` and `liva.py`.

**Tech Stack:** Python 3.10+, pytest, JSON.

---

## Root Cause Evidence

From analysing `result/CH22_30v1/httpd_4717ef/`:

| Root Cause | Evidence |
|---|---|
| Prompt too conservative | `FUN_0006b32c` (115 lines) has identical `GetValue→doSystemCmd("echo '%s'", s)` pattern as `FUN_0006358c` (82 lines), which got Yes. Same vulnerability, different verdict. |
| Context overload | `FUN_0006b32c` is 690 chars longer. The pattern is buried in a 115-line function with many unrelated `GetValue` calls and operations. LLM loses track. |
| No few-shot examples | `vul_session.json` has placeholder `"Okay"` responses, no real IoT examples to calibrate judgment. |

---

## File Map

| File | Action | Responsibility |
|---|---|---|
| `core/llm/vul_session.json` | Modify | LLM system prompt + few-shot calibration |
| `core/vulinfer.py` | Modify | Add `_extract_focused_snippet()`, update `build_reports()` signature |
| `liva.py` | Modify | Pass `source_funcs` to `build_reports()` |
| `tests/test_vulinfer_snippet.py` | Create | Unit tests for the new extraction method |

---

## Task 1: Rewrite vul_session.json

**Files:**
- Modify: `core/llm/vul_session.json`

The current system prompt requires BOTH "buffer size check" AND "data reaches sink" — two conditions LLM can't verify in complex code, so it defaults to No. The fix is a directive prompt plus 3 concrete few-shot examples.

- [ ] **Step 1: Replace the contents of `core/llm/vul_session.json`**

```json
[
  {
    "role": "system",
    "content": "You are an IoT firmware vulnerability analyst. You receive decompiled C code with source_function (user input entry point), sink_function (dangerous function), call_chain, optional taint_evidence, and code.\n\nJudge YES if ANY of these patterns are visible in the code:\n- A variable filled by GetValue/nvram_get/cgiFormString/websGetVar/httpd_get_parm or any listed source_function is passed to doSystemCmd/system/popen as a format argument (e.g. doSystemCmd(\"echo '%s'\", s) where s came from GetValue).\n- A variable filled by a source function is copied into a fixed-size stack buffer via strcpy/strcat/sprintf with no size limit applied before the copy.\n\nJudge NO only when:\n- Every sink argument is a string literal with no user-controlled component, OR\n- A size-limiting function (strncpy, snprintf, strncat) is called with a concrete bound before data reaches the sink.\n\nWhen the data flow path is visible but the code is long: focus on the lines containing the source call and the sink call. If the same variable appears in both, judge YES."
  },
  {
    "role": "user",
    "content": "source_function: GetValue()\nsink_function: doSystemCmd()\ncall_chain: FUN_example1->doSystemCmd()\ncode:\n// --- FUN_example1 ---\nint sub_example1()\n{\n  char s[128];\n  GetValue(\"usb.samba.userlist\", s);\n  doSystemCmd(\"echo '%s' > /tmp/userListFile\", s);\n  return 0;\n}\nHelp me determine whether there is a command injection or buffer overflow issue. Just output Yes or No."
  },
  {
    "role": "assistant",
    "content": "Yes"
  },
  {
    "role": "user",
    "content": "source_function: GetValue()\nsink_function: strcpy()\ncall_chain: FUN_example2->strcpy()\ncode:\n// --- FUN_example2 ---\nint __fastcall sub_example2(const char *a1)\n{\n  char dest[64];\n  strcpy(dest, a1);\n  return 0;\n}\nHelp me determine whether there is a command injection or buffer overflow issue. Just output Yes or No."
  },
  {
    "role": "assistant",
    "content": "Yes"
  },
  {
    "role": "user",
    "content": "source_function: GetValue()\nsink_function: doSystemCmd()\ncall_chain: FUN_example3->doSystemCmd()\ncode:\n// --- FUN_example3 ---\nint sub_example3()\n{\n  doSystemCmd(\"killall -9 dhcps\");\n  return 0;\n}\nHelp me determine whether there is a command injection or buffer overflow issue. Just output Yes or No."
  },
  {
    "role": "assistant",
    "content": "No"
  },
  {
    "role": "user",
    "content": "Please answer strictly Yes or No. Do not output any explanation."
  },
  {
    "role": "assistant",
    "content": "Understood. Please provide the next case."
  }
]
```

- [ ] **Step 2: Verify the JSON is valid**

```bash
python3 -c "import json; data=json.load(open('core/llm/vul_session.json')); print(f'Valid JSON, {len(data)} messages')"
```

Expected output: `Valid JSON, 8 messages`

---

## Task 2: Add `_extract_focused_snippet` to VulInfer

**Files:**
- Modify: `core/vulinfer.py` (insert after `_get_decompiled_code` at line 84)
- Create: `tests/test_vulinfer_snippet.py`

This method clips long functions down to: variable declarations (first 8 lines) + ±3 lines around each source call + ±10 lines around the sink call. Functions ≤ 50 lines are returned unchanged.

- [ ] **Step 1: Write the failing tests first**

Create `tests/test_vulinfer_snippet.py`:

```python
from pathlib import Path
import pytest
from core.vulinfer import VulInfer


@pytest.fixture
def vi():
    return VulInfer(ida_json_path=Path("/nonexistent"))


def test_short_code_returned_unchanged(vi):
    code = "\n".join([f"  line_{i}();" for i in range(30)])
    result = vi._extract_focused_snippet(code, "doSystemCmd", ["GetValue"])
    assert result == code


def test_extracts_source_and_sink_lines(vi):
    lines = [f"  int v{i}; // [sp+{i*4}h]" for i in range(15)]
    lines += [f"  unrelated_{i}();" for i in range(40)]
    lines += ['  GetValue("usb.samba.userlist", s);']
    lines += [f"  unrelated_{i}();" for i in range(25)]
    lines += ['  doSystemCmd("echo \'%s\' > /tmp/userListFile", s);']
    lines += ["  return 0;"]
    code = "\n".join(lines)

    result = vi._extract_focused_snippet(code, "doSystemCmd", ["GetValue"])

    assert 'GetValue("usb.samba.userlist", s)' in result
    assert "doSystemCmd" in result
    assert "// [..." in result
    assert len(result.splitlines()) < len(lines)


def test_omission_marker_between_distant_sections(vi):
    lines = [f"  int v{i};" for i in range(8)]
    lines += ['  GetValue("key", buf);']
    lines += [f"  noise_{i}();" for i in range(40)]
    lines += ['  doSystemCmd("echo %s", buf);']
    lines += ["  return 0;"]
    code = "\n".join(lines)

    result = vi._extract_focused_snippet(code, "doSystemCmd", ["GetValue"])
    assert "// [..." in result
    assert result.index("GetValue") < result.index("doSystemCmd")


def test_multiple_source_funcs_detected(vi):
    lines = [f"  int v{i};" for i in range(8)]
    lines += ['  nvram_get("key1", buf);']
    lines += [f"  noise_{i}();" for i in range(40)]
    lines += ['  strcpy(dest, buf);']
    lines += ["  return 0;"]
    code = "\n".join(lines)

    result = vi._extract_focused_snippet(code, "strcpy", ["GetValue", "nvram_get"])
    assert 'nvram_get("key1", buf)' in result
    assert "strcpy(dest, buf)" in result


def test_no_sink_in_code_returns_full_code(vi):
    lines = [f"  call_{i}();" for i in range(60)]
    code = "\n".join(lines)
    result = vi._extract_focused_snippet(code, "doSystemCmd", ["GetValue"])
    assert result == code
```

- [ ] **Step 2: Run tests to confirm they all fail**

```bash
cd /Users/yangshuangning/VscodeProjects/LIVA-main
python -m pytest tests/test_vulinfer_snippet.py -v 2>&1 | head -30
```

Expected: `AttributeError: 'VulInfer' object has no attribute '_extract_focused_snippet'`

- [ ] **Step 3: Add `_extract_focused_snippet` to `core/vulinfer.py`**

Insert this method immediately after `_get_decompiled_code` (currently ending at line 83), before `build_reports`:

```python
    def _extract_focused_snippet(
        self,
        code: str,
        sink_func: str,
        source_funcs: List[str],
        context_lines: int = 10,
    ) -> str:
        """Return a focused excerpt of code around source and sink calls.

        For functions longer than 50 lines, keeps:
          - First 8 lines (variable declarations)
          - ±3 lines around each source function call
          - ±context_lines lines around each sink function call
        Inserts '// [... N lines omitted ...]' markers for gaps.
        Returns the full code unchanged when ≤ 50 lines or sink not found.
        """
        lines = code.splitlines()
        if len(lines) <= 50:
            return code

        important: set = set()

        # Always keep variable declarations at the top
        for i in range(min(8, len(lines))):
            important.add(i)

        # Window around sink calls
        for i, line in enumerate(lines):
            if sink_func in line:
                for j in range(max(0, i - context_lines), min(len(lines), i + context_lines + 1)):
                    important.add(j)

        # If sink never appears, return full code so LLM still gets context
        sink_present = any(sink_func in line for line in lines)
        if not sink_present:
            return code

        # Narrow window around source function calls
        for i, line in enumerate(lines):
            if any(src in line for src in source_funcs):
                for j in range(max(0, i - 3), min(len(lines), i + 4)):
                    important.add(j)

        sorted_indices = sorted(important)
        result: List[str] = []
        prev = -1
        for idx in sorted_indices:
            if prev != -1 and idx > prev + 1:
                omitted = idx - prev - 1
                result.append(f"  // [... {omitted} lines omitted ...]")
            result.append(lines[idx])
            prev = idx

        return "\n".join(result)
```

- [ ] **Step 4: Run tests to confirm they pass**

```bash
python -m pytest tests/test_vulinfer_snippet.py -v
```

Expected: `5 passed`

- [ ] **Step 5: Commit**

```bash
git add tests/test_vulinfer_snippet.py core/vulinfer.py
git commit -m "feat: add _extract_focused_snippet to reduce LLM context overload"
```

---

## Task 3: Wire focused extraction into `build_reports` and `liva.py`

**Files:**
- Modify: `core/vulinfer.py:85-183` (`build_reports` signature and body)
- Modify: `liva.py:403` (call site)

- [ ] **Step 1: Write the failing test for the new `build_reports` signature**

Add to `tests/test_vulinfer_snippet.py`:

```python
def test_build_reports_applies_extraction_to_long_function(tmp_path, vi):
    # Build a fake IDA JSON with a 100-line function containing GetValue + doSystemCmd
    declarations = [f"  int v{i};" for i in range(15)]
    noise = [f"  noise_{i}();" for i in range(50)]
    source_line = ['  GetValue("usb.key", s);']
    more_noise = [f"  noise2_{i}();" for i in range(20)]
    sink_line = ['  doSystemCmd("echo \'%s\'", s);']
    tail = ["  return 0;"]
    func_body = "\n".join(declarations + noise + source_line + more_noise + sink_line + tail)

    ida_json = tmp_path / "ida.json"
    ida_json.write_text(
        '{"data": [{"parent_name": "test_func", "child_names": ["GetValue", "doSystemCmd"], "decompiled_c": '
        + f'"{func_body.replace(chr(10), "\\n").replace(chr(34), chr(39))}"'
        + "}]}",
        encoding="utf-8",
    )

    vulinfer = VulInfer(ida_json_path=ida_json, output_path=tmp_path / "out.txt")
    paths = [{
        "src": {"param_func": "GetValue", "func_name": "test_func"},
        "dst": {"func_name": "doSystemCmd"},
        "rels": [],
        "taint_chain": [],
        "path_type": "direct",
    }]
    reports = vulinfer.build_reports(paths=paths, source_func_name="", source_funcs=["GetValue"])
    assert reports, "Expected at least one report"
    # The generated code block must contain both GetValue and doSystemCmd
    assert "GetValue" in reports[0]
    assert "doSystemCmd" in reports[0]
    # And must be shorter than the original (extraction was applied)
    assert len(reports[0].splitlines()) < len(func_body.splitlines()) + 10
```

- [ ] **Step 2: Run test to confirm it fails**

```bash
python -m pytest tests/test_vulinfer_snippet.py::test_build_reports_applies_extraction_to_long_function -v
```

Expected: `TypeError: build_reports() got an unexpected keyword argument 'source_funcs'`

- [ ] **Step 3: Update `build_reports` in `core/vulinfer.py`**

Change the signature at line 85 from:
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

Then in the `if taint_steps:` branch, change lines 149-152:
```python
                        code_parts.append(
                            f"// --- {func} ---\n{self._get_decompiled_code(func)}"
                        )
```
to:
```python
                        raw = self._get_decompiled_code(func)
                        if source_funcs:
                            raw = self._extract_focused_snippet(raw, dst_func_name, source_funcs)
                        code_parts.append(f"// --- {func} ---\n{raw}")
```

And in the `else:` branch, change line 162:
```python
                decompiled_code = self._get_decompiled_code(src_func_name)
```
to:
```python
                raw = self._get_decompiled_code(src_func_name)
                if source_funcs:
                    raw = self._extract_focused_snippet(raw, dst_func_name, source_funcs)
                decompiled_code = raw
```

- [ ] **Step 4: Update the call site in `liva.py`**

Change line 403 from:
```python
    reports = vulinfer.build_reports(paths=paths, source_func_name="")
```
to:
```python
    reports = vulinfer.build_reports(paths=paths, source_func_name="", source_funcs=source_funcs)
```

(`source_funcs` is already defined at line 383 in `run_stage_infer`.)

- [ ] **Step 5: Run all tests**

```bash
python -m pytest tests/test_vulinfer_snippet.py -v
```

Expected: `6 passed`

- [ ] **Step 6: Commit**

```bash
git add core/vulinfer.py liva.py tests/test_vulinfer_snippet.py
git commit -m "feat: wire focused code extraction into build_reports to reduce LLM context overload"
```

---

## Task 4: Re-run infer stage and measure improvement

**Files:** None modified — this is a measurement step.

- [ ] **Step 1: Back up the baseline result**

```bash
cp result/CH22_30v1/httpd_4717ef/vul_result.txt result/CH22_30v1/httpd_4717ef/vul_result_baseline.txt
```

- [ ] **Step 2: Re-run the infer stage**

```bash
python liva.py CH22/httpd_4717ef CH22 CH22_30v1 --stages infer
```

Expected: prints `Found N source→sink paths` and `Generated 54 merged reports` (same count as before — we only changed what the LLM sees, not path finding).

- [ ] **Step 3: Count new Yes verdicts**

```bash
grep -c "Response: b'Yes" result/CH22_30v1/httpd_4717ef/vul_result.txt
```

Baseline was **2**. Target: **≥ 5** (at minimum: `FUN_0006b32c->doSystemCmd`, `frmL7ProtForm->doSystemCmd`, `formaddUserName->strcpy`, `fromIpsecitem->doSystemCmd`, `FUN_00065b14->doSystemCmd` — all have visible GetValue→sink paths in their code).

- [ ] **Step 4: Diff the results to inspect changes**

```bash
diff result/CH22_30v1/httpd_4717ef/vul_result_baseline.txt result/CH22_30v1/httpd_4717ef/vul_result.txt
```

For every new Yes, verify manually that the code in `cmd_injection_candidates.txt` does show a real data flow path (GetValue variable used in sink).

- [ ] **Step 5: If Yes count < 5, inspect one missed case and adjust**

```bash
# Find the first No that should be Yes
grep -B 10 "Response: b'No" result/CH22_30v1/httpd_4717ef/vul_result.txt | head -60
```

If `FUN_0006b32c->doSystemCmd()` is still No, the extraction window is too narrow — increase `context_lines` from 10 to 15 in the `_extract_focused_snippet` call inside `build_reports`.

---

## Self-Review Checklist

**Spec coverage:**
- [x] vul_session.json system prompt: Task 1
- [x] Few-shot examples calibrating IoT patterns: Task 1
- [x] Focused code extraction for long functions: Task 2
- [x] Wire extraction into pipeline: Task 3
- [x] Measure improvement: Task 4

**No placeholders:** All code blocks are complete and runnable.

**Type consistency:** `_extract_focused_snippet(self, code: str, sink_func: str, source_funcs: List[str], ...) -> str` is consistent across Task 2 definition and Task 3 call sites.
