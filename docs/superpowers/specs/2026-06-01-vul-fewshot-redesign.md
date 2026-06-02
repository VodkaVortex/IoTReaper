# Few-Shot Redesign for Vulnerability Inference Prompt

**Date:** 2026-06-01  
**File:** `core/llm/vul_session.json`  
**Status:** Approved

## Background

The vulnerability inference stage sends each taint path to an LLM with a few-shot prompt. The current 4 examples cover only `strcpy` and `doSystemCmd`; `sprintf` accounts for 37% of CH22_31 cases (100/268) with zero few-shot coverage.

**CH22_31 sink distribution:**

| Sink | Count | Yes% |
|------|-------|------|
| sprintf | 100 | 33% |
| memcpy | 58 | 41% |
| strcpy | 44 | 52% |
| doSystemCmd | 33 | 36% |
| strcat | 23 | 91% |

The fourth example (`FUN_literal_demo → strcpy → No`) taught the same rule as example 3 (`FUN_safe_demo → doSystemCmd → No`): "literal/constant data flowing to a sink is not a vulnerability." This redundancy leaves `sprintf` completely unguided.

## Change

**Replace example 4** (`literal_demo`) with a new `sprintf → Yes` example using `websGetVar()` as source.

## Design Decisions

| Decision | Choice | Reason |
|----------|--------|--------|
| Code style | Synthetic pseudocode | Consistent with existing examples |
| Source for sprintf | `websGetVar()` | Distinct from GetValue; represents HTTP-layer attack surface; generalizes across firmware |
| Chain depth | Single-hop | Consistent with existing examples |
| Buffer declaration | Include (char s[32]) | Makes overflow boundary explicit without adding noise |

## Four Final Examples

### Example 1 — doSystemCmd YES (unchanged)

```
source_function: GetValue()
sink_function: doSystemCmd()
call_chain: FUN_ci_demo->doSystemCmd()
taint_evidence:
  [1] FUN_ci_demo calls doSystemCmd(params=['1', '2']) at line:6: doSystemCmd("echo '%s' > /tmp/userListFile", s);
code:
// --- FUN_ci_demo ---
int sub_ci_demo()
{
  char s[128];
  GetValue("usb.samba.userlist", s);
  doSystemCmd("echo '%s' > /tmp/userListFile", s);
}
```

**Answer: Yes** — User-controlled string flows into shell command via `%s`. Command injection.

---

### Example 2 — strcpy YES (unchanged)

```
source_function: GetValue()
sink_function: strcpy()
call_chain: FUN_bo_demo->strcpy()
taint_evidence:
  [1] FUN_bo_demo calls strcpy(params=['2']) at line:5: strcpy(dest, a1);
code:
// --- FUN_bo_demo ---
int __fastcall sub_bo_demo(const char *a1)
{
  char dest[64];
  strcpy(dest, a1);
}
```

**Answer: Yes** — User-controlled `a1` copied into 64-byte fixed buffer with no length check. Buffer overflow.

---

### Example 3 — sprintf YES (new, replaces literal_demo)

```
source_function: websGetVar()
sink_function: sprintf()
call_chain: FUN_sprintf_demo->sprintf()
taint_evidence:
  [1] FUN_sprintf_demo calls sprintf(params=['2']) at line:4: sprintf(s, "vpn.ser.%s", v8);
code:
// --- FUN_sprintf_demo ---
int sub_sprintf_demo(int webs)
{
  char s[32];
  const char *v8 = websGetVar(webs, "service", "");
  sprintf(s, "vpn.ser.%s", v8);
}
```

**Answer: Yes** — `v8` comes from HTTP request param. `%s` writes user string into 32-byte fixed buffer with no length check. Buffer overflow.

**Why websGetVar:** This source is universal across GoAhead-based firmware (Tenda, D-Link, TP-Link, Netgear). `GetValue` is NVRAM-specific; `websGetVar` represents the direct HTTP attack surface and generalizes the few-shot beyond CH22.

---

### Example 4 — doSystemCmd NO (unchanged, was example 3)

```
source_function: GetValue()
sink_function: doSystemCmd()
call_chain: FUN_safe_demo->doSystemCmd()
taint_evidence:
  [1] FUN_safe_demo calls doSystemCmd(params=['1']) at line:8: doSystemCmd("killall -9 dhcps");
code:
// --- FUN_safe_demo ---
int sub_safe_demo()
{
  char s[32];
  GetValue("wan.enable", s);
  if (atoi(s) == 1)
    doSystemCmd("killall -9 dhcps");
}
```

**Answer: No** — `doSystemCmd` argument is a hardcoded literal. User input (from `GetValue`) only controls branching, not the sink argument. No vulnerability.

## Coverage After Change

| Sink | Source | Result | Rule taught |
|------|--------|--------|-------------|
| doSystemCmd | GetValue | Yes | User `%s` → shell injection |
| strcpy | GetValue | Yes | User string → fixed buffer BO |
| sprintf | websGetVar | Yes | User `%s` arg → fixed buffer BO |
| doSystemCmd | GetValue | No | Literal-only sink arg → safe |

## Implementation

Edit `core/llm/vul_session.json`: replace the two messages for `FUN_literal_demo` (user + assistant) with the new `FUN_sprintf_demo` pair. All other messages remain unchanged.
