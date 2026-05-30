# core/taint_parser.py
"""
Parse taint_analysis.json result strings into TaintEdge objects.

taint_analysis.json is written by run_stage_taint() (liva.py).
Each 'result' field contains LLM output in Python-literal syntax:

  Variant A (single callee, Chinese prefix, space but no colon):
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
# The colon is optional (?) so variant A ("为 {" with space but no colon) also matches.
_PREFIX_RE = re.compile(r"参数映射关系结构为\s*[:：]?\s*([\s\S]+)", re.S)


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
        result = [item for item in v if isinstance(item, tuple)]
        dropped = len(v) - len(result)
        if dropped:
            logger.debug("_normalize_to_tuple_list: dropped %d non-tuple item(s)", dropped)
        return result
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
        except Exception as e:
            skipped += 1
            logger.warning(
                "taint_parser: skipping index=%s (%s: %s)",
                record.get("index", "?"),
                type(e).__name__,
                e,
            )
            continue
        record_edges = _edges_from_parsed(parsed)
        if not record_edges:
            # Parsed successfully but yielded no edges (e.g. value is a string, not tuple)
            skipped += 1
            logger.warning(
                "taint_parser: skipping index=%s (no edges extracted from parsed value)",
                record.get("index", "?"),
            )
        else:
            edges.extend(record_edges)

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
