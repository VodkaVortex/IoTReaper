import json
import logging
from collections import defaultdict, deque
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

logger = logging.getLogger(__name__)


def find_source_sink_paths(
    parent_child_path: Union[str, Path],
    source_funcs: List[str],
    sink_funcs: List[str],
) -> List[Dict[str, Any]]:
    """
    Find source-to-sink paths without Neo4j.

    Reads parent_child_calls_ida_decompile.json. For each parent function
    that directly calls BOTH a source function AND a sink function,
    emits a path dict compatible with VulInfer.build_reports().

    Returns:
        [{"src": {"param_func": src_func, "func_name": parent}, "dst": {"func_name": sink}, "rels": []}, ...]
    """
    path = Path(parent_child_path)
    if not path.exists():
        logger.warning("parent_child_calls file not found: %s", path)
        return []

    root = json.loads(path.read_text(encoding="utf-8"))
    items: List[Dict[str, Any]] = root.get("data", [])

    source_set = set(source_funcs)
    sink_set = set(sink_funcs)
    paths: List[Dict[str, Any]] = []

    for item in items:
        parent_name: str = item.get("parent_name", "")
        child_names: List[str] = item.get("child_names", [])
        child_set = set(child_names)

        # Also scan decompiled_c text for source function calls that Ghidra
        # may have omitted from child_names (e.g. functions not on sink-reachable paths)
        decompiled_c: str = item.get("decompiled_c") or ""
        sources_in_code = {s for s in source_set if s in decompiled_c}

        found_sources = (child_set & source_set) | sources_in_code
        found_sinks = child_set & sink_set

        if not found_sources or not found_sinks:
            continue

        for src_func in sorted(found_sources):
            for sink_func in sorted(found_sinks):
                paths.append({
                    "src": {"param_func": src_func, "func_name": parent_name},
                    "dst": {"func_name": sink_func},
                    "rels": [],
                })

    logger.info("SimplePathFinder: found %d source→sink paths", len(paths))
    return paths


def find_taint_aware_paths(
    parent_child_path: Union[str, Path],
    source_funcs: List[str],
    sink_funcs: List[str],
    taint_analysis_path: Optional[Union[str, Path]] = None,
    max_hops: int = 5,
) -> List[Dict[str, Any]]:
    """Find source→sink paths using taint propagation graph + direct call graph.

    Algorithm
    ---------
    1. Parse taint_analysis.json into a taint graph: caller → [TaintEdge].
    2. From parent_child_calls, identify source-entry functions (any function
       whose child_names or decompiled_c contains a source function name).
    3. BFS from each source-entry function through taint graph edges:
       - If edge.callee is in sink_funcs  → path found; record full chain.
       - If edge.callee has outgoing taint edges → extend BFS (up to max_hops).
    4. Also run find_source_sink_paths() as a fallback for paths not found via
       taint graph (e.g. when taint_analysis.json is absent).

    Returns
    -------
    List of path dicts compatible with VulInfer.build_reports():
    {
        "src": {"param_func": source_func, "func_name": entry_func},
        "dst": {"func_name": sink_func},
        "rels": [],
        "taint_chain": [
            {"caller": str, "callee": str, "param_map": dict,
             "line_info": str, "call_expr": str},
            ...
        ],
        "path_type": "direct" | "taint_1hop" | "taint_2hop" | ...
    }
    """
    from core.taint_parser import parse_taint_analysis

    parent_child_path = Path(parent_child_path)
    if not parent_child_path.exists():
        logger.warning("parent_child_calls file not found: %s", parent_child_path)
        return []

    root = json.loads(parent_child_path.read_text(encoding="utf-8"))
    items: List[Dict[str, Any]] = root.get("data", [])

    source_set = set(source_funcs)
    sink_set = set(sink_funcs)

    # ---------- Build taint graph ----------
    taint_graph: Dict[str, list] = defaultdict(list)
    if taint_analysis_path is not None:
        tp = Path(taint_analysis_path)
        if tp.exists():
            for edge in parse_taint_analysis(tp):
                taint_graph[edge.caller].append(edge)
        else:
            logger.warning(
                "taint_analysis_path not found: %s — using direct search only", tp
            )

    # ---------- Find source-entry functions ----------
    # Maps entry_func_name → set of source functions it calls
    source_entries: Dict[str, set] = {}
    for item in items:
        parent: str = item.get("parent_name", "")
        child_set = set(item.get("child_names", []))
        decompiled: str = item.get("decompiled_c") or ""
        sources_in_code = {s for s in source_set if s in decompiled}
        found_sources = (child_set & source_set) | sources_in_code
        if found_sources:
            source_entries[parent] = found_sources

    # ---------- BFS ----------
    # seen_path_keys prevents duplicates: (entry_func, src_func, sink_func)
    seen_path_keys: set = set()
    paths: List[Dict[str, Any]] = []

    for entry_func, found_sources in source_entries.items():
        for src_func in sorted(found_sources):
            # BFS queue: (current_func, chain_so_far, visited_set)
            # visited_set is per-path to prevent cycles within one path; seen_path_keys
            # deduplicates (entry_func, src_func, sink_func) triples across all paths.
            queue: deque = deque()
            queue.append((entry_func, [], {entry_func}))

            while queue:
                current, chain, visited = queue.popleft()
                if len(chain) >= max_hops:
                    continue

                for edge in taint_graph.get(current, []):
                    step = {
                        "caller": edge.caller,
                        "callee": edge.callee,
                        "param_map": edge.param_map,
                        "line_info": edge.line_info,
                        "call_expr": edge.call_expr,
                    }
                    new_chain = chain + [step]

                    if edge.callee in sink_set:
                        key = (entry_func, src_func, edge.callee)
                        if key not in seen_path_keys:
                            seen_path_keys.add(key)
                            hop_count = len(new_chain)
                            paths.append({
                                "src": {"param_func": src_func, "func_name": entry_func},
                                "dst": {"func_name": edge.callee},
                                "rels": [],
                                "taint_chain": new_chain,
                                "path_type": f"taint_{hop_count}hop",
                            })
                    elif edge.callee not in visited and taint_graph.get(edge.callee):
                        queue.append((edge.callee, new_chain, visited | {edge.callee}))

    # ---------- Fallback: direct co-occurrence ----------
    for p in find_source_sink_paths(parent_child_path, source_funcs, sink_funcs):
        entry = p["src"]["func_name"]
        src = p["src"]["param_func"]
        sink = p["dst"]["func_name"]
        key = (entry, src, sink)
        if key not in seen_path_keys:
            seen_path_keys.add(key)
            p["taint_chain"] = []
            p["path_type"] = "direct"
            paths.append(p)

    taint_count = sum(1 for p in paths if "taint" in p.get("path_type", ""))
    direct_count = sum(1 for p in paths if p.get("path_type") == "direct")
    logger.info(
        "TaintAwarePathFinder: %d paths total (%d taint-derived, %d direct)",
        len(paths),
        taint_count,
        direct_count,
    )
    return paths
