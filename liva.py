import argparse
import logging
from core.danger_func_analyzer import DangerFuncAnalyzer
from core.elf_parser import ELFParser
from config import config
from core.idanet.IDAMCPClient import IDAMCPClient
from core.llm.llm_request import Chatbot
from core.sink_identifier import SinkIdentifier
from core.source_identifier import SourceIdentifier
from core.taint_analyzer import TaintAnalyzer
from core.vulinfer import VulInfer
from core.simple_path_finder import find_source_sink_paths, find_taint_aware_paths
from utils.utils import parse_funcnames, run_with_timer, timeit_context, upsert_ProjectInfo_data
from openai import OpenAI
import ast
import re
from typing import List
from pathlib import Path
import json
import time

# Regex to validate hex addresses like 0x41ac8
HEX_ADDR_RE = re.compile(r"^0x[0-9a-fA-F]+$")

# ---------- Stage wrappers ----------
def run_stage_elf(binary: str, search_dir: str, device: str):
    """Stage: ELF parsing and dependency analysis"""
    config.LivaConfig.set_device_info(device)
    try:
        analyzer = ELFParser(binary, search_dir)
        libraries = analyzer.get_needed_libraries()

        if libraries:
            analyzer.logger.info("Required dynamic libraries:")
            for lib in libraries:
                analyzer.logger.info(f"  {lib}")

            found_libraries = analyzer.find_libraries()

            analyzer.logger.info("\nFound library paths:")
            for lib, path in found_libraries.items():
                if path:
                    analyzer.logger.info(f"  {lib}: {path}")
                else:
                    analyzer.logger.warning(f"  {lib}: Not found")

            analyzer.save_results()
            analyzer.generate_symbols_json()
            analyzer.check_dangerous_functions_in_libraries()
            analyzer.search_common_functions()
        else:
            analyzer.logger.info("No dynamic libraries found.")
    except Exception:
        logging.getLogger().exception("[ELF] Stage failed")
        raise

def run_stage_source():
    """Stage: Source identifier batch"""
    try:
        source_identifier = SourceIdentifier()
        source_identifier.run_sourceidentifier_batch_analysis()
        source_identifier.load()
        # targets = ["nvram_get", "nvram_set", "nvram_commit"]
        res = source_identifier.parse_call_report_file()
        sorted_items = sorted(res.items(), key=lambda x: x[1], reverse=True)
        top_quarter_count = max(1, len(sorted_items) // 2)
        top_funcs = [name for name, count in sorted_items[:top_quarter_count]]

        # targets = [i for i in res]
        grouped = source_identifier.find_by_lib_grouped(top_funcs, exact=True)

        source_identifier.pretty_print(grouped)

        idamcp_config = config.LivaConfig.config["IDAMCP"]
        client = IDAMCPClient(
            ida_mcp_path=idamcp_config["ida_mcp_path"],
            ida_dir=idamcp_config.get("ida_dir", ""),
        )
        funcs_by_lib = grouped
        file_mapping = {}
        for binary in grouped:
            file_mapping[binary] = f"result/{config.LivaConfig.project_path}/{config.LivaConfig.main_project_name}/iot_file/{binary}"
        batch_resp = client.send_multiple_libs(
            file_mapping=file_mapping,
            funcs_by_lib=funcs_by_lib,
        )
        print("Batch response:")
        print(json.dumps(batch_resp, indent=2, ensure_ascii=False))
        llm_source_send = ""
        for i in batch_resp:
            if "error" in batch_resp[i]:
                print(f"[SOURCE] Skipping {i}: {batch_resp[i]['error']}")
                continue
            for j in batch_resp[i]['resp']:
                # 获取当前函数的代码
                current_code = batch_resp[i]['resp'][j]["code"]
                
                # 检查是否有 "inlined_from"，并且是一个列表
                if 'inlined_from' in batch_resp[i]['resp'][j]:
                    # 如果有多个被调用的函数，遍历并获取每个函数的代码
                    inlined_codes = [callee["code"] for callee in batch_resp[i]['resp'][j]["inlined_from"]]
                    # 将当前函数代码与被调用函数的代码合并
                    llm_source_send += current_code + "\n" + "\n".join(inlined_codes) + "\n-------------------------------"
                else:
                    # 如果没有 "inlined_from" 字段，直接使用当前函数的代码
                    llm_source_send += current_code + "\n-------------------------------"

        chatbot = Chatbot(config_file="config/config.ini", chat_type="source")
        response = chatbot.chat(llm_source_send)
        if isinstance(response, bytes):
            # print(response.decode("utf-8", errors="ignore"))
            source_point = parse_funcnames(response.decode("utf-8", errors="ignore"))
            config.LivaConfig.source_point = source_point
        else:
            print(response)
    except Exception:
        logging.getLogger().exception("[SOURCE] Stage failed")
        raise

def run_stage_sink():
    sink = []
    """Stage: Sink identifier batch & decompile"""
    try:
        identifier = SinkIdentifier()
        results = identifier.run_sink_batch_analysis()
        print(results)
        parsed_results = identifier.load_results_from_sqlite()
        funcs_by_lib, file_mapping, chains_by_lib  = identifier.build_funcs_files_and_chains_from_parsed_results(
            parsed_results,
            base_dir=f"result/{config.LivaConfig.project_path}/{config.LivaConfig.main_project_name}/iot_file/",
            verbose=True,
        )

        idamcp_config = config.LivaConfig.config["IDAMCP"]
        client = IDAMCPClient(
            ida_mcp_path=idamcp_config["ida_mcp_path"],
            ida_dir=idamcp_config.get("ida_dir", ""),
        )
        batch_resp = client.send_multiple_libs(
            file_mapping=file_mapping,
            funcs_by_lib=funcs_by_lib,
        )
        added_chains = set()     # 用来记录已经分析过的 chain

        for item in chains_by_lib:
            if len(chains_by_lib[item]) != 0:
                if "error" in batch_resp.get(item, {}):
                    print(f"[SINK] Skipping {item}: {batch_resp[item]['error']}")
                    continue
                for func_list in chains_by_lib[item]:
                    chain = ""
                    code = ""
                    first_func = func_list[0]
                    for func in func_list:
                        chain += "->" + func 
                        code += "--------------------------\n" + batch_resp[item]['resp'][func]["code"]
                                # -------------------------
                    # 新增：检查 chain 是否重复
                    # -------------------------
                    if chain in added_chains:
                        print("跳过重复 chain:", chain)
                        continue

                    # 记录新的 chain，避免下次重复分析
                    added_chains.add(chain)
            # -------------------------

                    send_llm = "Call chains: " + chain + "\n" + "Code: \n" + code
                    chatbot = Chatbot(config_file="config/config.ini", chat_type="sink")
                    response = chatbot.chat(send_llm)
                    print(chain,response)
                    
                    if b"Yes" in response:
                        sink.append(first_func)
        # identifier.run_decompile_batch_analysis()
        # chatbot = Chatbot(config_file="config/config.ini", chat_type="sink")
        # response = chatbot.chat(llm_source_send)
        for lib_name, res in parsed_results:
            identifier.logger.info(f"{lib_name}: {len(res)} items loaded.")
        
        # print(sink)
        config.LivaConfig.sink_point = sink
    except Exception:
        logging.getLogger().exception("[SINK] Stage failed")
        raise
        

def _parse_source_input(user_text: str) -> List[str]:
    """
    Parse user input into a list of strings in the format ['name|0xADDR', ...].

    Supported formats:
      1) JSON/Python list: ["getenv|0x1234", "webget|0x41ac8"]
      2) Comma separated: getenv|0x1234, webget|0x41ac8
      3) Whitespace separated: getenv|0x1234  webget|0x41ac8

    Validation:
      - Each item must contain '|'
      - The right part must be a valid hex address
    """
    text = user_text.strip()
    items: List[str] = []

    if not text:
        return items

    # Try parsing as Python/JSON literal
    try:
        maybe_list = ast.literal_eval(text)
        if isinstance(maybe_list, (list, tuple)):
            items = [str(x).strip() for x in maybe_list]
        else:
            raise ValueError("Not a list")
    except Exception:
        # Fallback: split by comma or whitespace
        if "," in text:
            items = [p.strip() for p in text.split(",") if p.strip()]
        else:
            items = [p.strip() for p in text.split() if p.strip()]

    # Normalize and validate
    normalized: List[str] = []
    for it in items:
        if "|" not in it:
            raise ValueError(f"Invalid item: {it} (missing '|')")
        name, addr = it.split("|", 1)
        name = name.strip()
        addr = addr.strip().lower()
        if not name:
            raise ValueError(f"Invalid item: {it} (empty function name)")
        if not HEX_ADDR_RE.match(addr):
            raise ValueError(f"Invalid address: {addr} (must be like 0x41ac8)")
        normalized.append(f"{name}|{addr}")
    return normalized

def run_stage_danger():
    """Stage: Dangerous function analyze & decompile"""
    try:
        # === Ask user for source functions ===
        print(
            "Enter source array, e.g.:\n"
            '  ["getenv|0x0000a3c8", "webget|0x41ac8"]  OR  getenv|0x0000a3c8, webget|0x41ac8\n'
            "Press Enter to use default."
        )
        user_input = ""
        if config.LivaConfig.source_point == []:
            user_input = input("source => ").strip()

        parsed_sources = []
        if user_input:
            try:
                parsed_sources = _parse_source_input(user_input)
            except ValueError as e:
                print(f"[Parse error] {e}")
                print("Using default sources instead.")
                parsed_sources = ['websGetVar']
        else:
            parsed_sources = ['getenv|0x0040ccf0', 'webget|0x41ac8']

        if config.LivaConfig.source_point != []:
            parsed_sources = config.LivaConfig.source_point
        # Merge config.ini [SourceFunction] — consistent with run_stage_infer()
        if config.LivaConfig.config.has_section("SourceFunction"):
            for val in config.LivaConfig.config["SourceFunction"].values():
                for s in val.split(","):
                    s = s.strip()
                    if s and s not in parsed_sources:
                        parsed_sources.append(s)
        # Save sources
        print("SourcePoint: ", parsed_sources)
        upsert_ProjectInfo_data(tag="source", data=str(parsed_sources))

        # Sink remains static (can also be interactive if needed)
        # upsert_ProjectInfo_data(tag="sink", data="['system','popen','sprintf']")
        sink_data = "['system','strcat','sprintf','popen','strcpy']"
        if len(config.LivaConfig.sink_point) != 0:
            cfg = config.LivaConfig.config
            if cfg.has_section("VulFunction"):
                vul_funcs = dict(cfg["VulFunction"])
            else:
                vul_funcs = {}
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

        # Run analysis
        idamcp_config = config.LivaConfig.config["IDAMCP"]
        danger_func = DangerFuncAnalyzer(
            ida_mcp_path=idamcp_config["ida_mcp_path"],
            ida_dir=idamcp_config.get("ida_dir", ""),
        )
        danger_func.logger.info("begin")
        danger_func.run_dangerfunc_batch_analysis()
        # Choose ghidra
        # danger_func.run_dangerdecompile_batch_analysis_ghidra()
        # Choose IDA
        out_file = danger_func.run_dangercompile_IDA()

    except Exception:
        logging.getLogger().exception("[DANGER] Stage failed")
        raise


def run_stage_taint():
    """Stage: Taint analysis via GPT"""
    # Preprocess data before GPT analysis
    TaintAnalyzer.gpt_preprocess()
    entries, combined, entry_vars = TaintAnalyzer.load_preprocess_entries()

    total_entries = len(entries)
    print(f"Total entries to process: {total_entries}")

    try:
        # Initialize OpenAI client and analyzer
        liva_config = config.LivaConfig.config["Fine-tuning"]
        client = OpenAI(api_key=liva_config["api_key"], base_url=liva_config["base_url"])
        analyzer = TaintAnalyzer(
            client=client,
            model=liva_config["model"],
            temperature=float(liva_config["temperature"]),
            max_tokens=int(liva_config["max_tokens"]),
            timeout=int(liva_config["timeout"]),
            retries=int(liva_config["retries"])
        )

        results = []  # Store all analysis results

        with timeit_context("Total taint analysis"):
            for idx, entry in enumerate(entries, start=1):
                try:
                    with timeit_context(f"[{idx}/{total_entries}] Entry analysis"):
                        # Call GPT to analyze each entry
                        result = analyzer.ask_gpt(entry)
                        results.append({
                            "index": idx,    # Entry index
                            "entry": entry,  # Original request text
                            "result": result # GPT analysis output
                        })
                        print(f"[{idx}/{total_entries}] Analysis completed")
                except Exception as e:
                    # Log failure but continue with next entry
                    logging.getLogger().exception(f"[TAINT] Failed to analyze entry idx={idx}")
                    results.append({
                        "index": idx,
                        "entry": entry,
                        "error": str(e)  # Save error message for debugging
                    })

        print(f"All analyses completed: {len(results)}/{total_entries} processed")

        # ---------------- Save to file ----------------
        base_dir = Path(f"result/{config.LivaConfig.project_path}/{config.LivaConfig.main_project_name}")
        base_dir.mkdir(parents=True, exist_ok=True)

        save_path = base_dir / "taint_analysis.json"
        with save_path.open("w", encoding="utf-8") as f:
            json.dump({
                "meta": {
                    "total_entries": total_entries,
                    "processed": len(results),
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
                },
                "results": results
            }, f, indent=2, ensure_ascii=False)

        print(f"Results saved to: {save_path}")
        

    except Exception:
        # Log and re-raise if stage setup or execution fails
        logging.getLogger().exception("[TAINT] Stage failed")
        raise

def run_stage_infer():
    """Stage: Vulnerability inference using SimplePathFinder (no Neo4j)"""
    from pathlib import Path as _Path
    base_dir = _Path(f"result/{config.LivaConfig.project_path}/{config.LivaConfig.main_project_name}")
    parent_child_file = base_dir / "parent_child_calls_ida_decompile.json"

    vul_funcs = config.LivaConfig.config["VulFunction"]
    sink_funcs = (
        [s.strip() for s in vul_funcs["command_injection"].split(",") if s.strip()]
        + [s.strip() for s in vul_funcs["buffer_overflow"].split(",") if s.strip()]
    )
    source_funcs_from_config = []
    if "SourceFunction" in config.LivaConfig.config:
        for val in config.LivaConfig.config["SourceFunction"].values():
            source_funcs_from_config += [s.strip() for s in val.split(",") if s.strip()]
    # Merge LLM-identified sources + config.ini [SourceFunction]; never discard either.
    # The old `or` short-circuit silently dropped config sources when source_point was non-empty.
    merged_sources = list(dict.fromkeys(
        (config.LivaConfig.source_point or []) + source_funcs_from_config
    ))
    source_funcs = merged_sources or ["websGetVar", "cgiFormString", "httpd_get_parm"]

    taint_analysis_file = base_dir / "taint_analysis.json"
    paths = find_taint_aware_paths(
        parent_child_path=parent_child_file,
        source_funcs=source_funcs,
        sink_funcs=sink_funcs,
        taint_analysis_path=taint_analysis_file if taint_analysis_file.exists() else None,
    )
    taint_count = sum(1 for p in paths if "taint" in p.get("path_type", ""))
    direct_count = sum(1 for p in paths if p.get("path_type") == "direct")
    print(
        f"Found {len(paths)} source→sink paths "
        f"({direct_count} direct, {taint_count} taint-derived)"
    )

    vulinfer = VulInfer(
        ida_json_path=parent_child_file,
        output_path=base_dir / "cmd_injection_candidates.txt",
    )
    reports = vulinfer.build_reports(paths=paths, source_func_name="")
    merge_report = vulinfer.merge_by_call_chain(reports)
    print(f"Generated {len(merge_report)} merged reports")
    vulinfer.gpt_infer(merge_report, str(base_dir / "vul_result.txt"))

# ---------- Main with stage selection ----------
if __name__ == "__main__":
    # 定义依赖顺序
    RUN_ORDER = ["elf", "source", "sink", "danger", "taint", "infer"]

    # 自定义解析函数，支持逗号和空格
    def parse_stages(stage_list):
        result = []
        for s in stage_list:
            result.extend(s.split(','))
        return [st.strip() for st in result if st.strip()]

    parser = argparse.ArgumentParser(
        description="Extract dynamic dependencies from an ELF file and run selected analysis stages."
    )
    parser.add_argument("binary", help="Path to the ELF binary file")
    parser.add_argument("search_dir", help="Directory to search for library files")
    parser.add_argument("device", help="Device Name")

    parser.add_argument(
        "--stages",
        nargs="+",
        default=["all"],
        help="Stages to run (can select multiple, space- or comma-separated). Default: all."
    )

    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the stages that would run and exit."
    )

    args = parser.parse_args()

    # 解析并校验阶段
    args.stages = parse_stages(args.stages)
    VALID = set(RUN_ORDER + ["all"])
    unknown = [s for s in args.stages if s not in VALID]
    if unknown:
        parser.error(f"Unknown stage(s): {', '.join(unknown)}. Valid choices are: {', '.join(VALID)}")

    # 确定执行顺序
    if "all" in args.stages:
        stages_to_run = RUN_ORDER[:]
    else:
        selected = set(args.stages)
        stages_to_run = [s for s in RUN_ORDER if s in selected]

    print("[Plan] Stages to run (in order):", " -> ".join(stages_to_run))
    if args.dry_run:
        exit(0)

    # 初始化全局 config（无论跳过哪些阶段都需要）
    config.LivaConfig.set_device_info(args.device)
    config.LivaConfig.set_binary_path(args.binary, None)
    config.LivaConfig.init_db()

    # 执行
    try:
        for stage in stages_to_run:
            if stage == "elf":
                run_with_timer("elf", run_stage_elf, args.binary, args.search_dir, args.device)

            elif stage == "source":
                run_with_timer("source", run_stage_source)

            elif stage == "sink":
                run_with_timer("sink", run_stage_sink)

            elif stage == "danger":
                run_with_timer("danger", run_stage_danger)

            elif stage == "taint":
                run_with_timer("taint", run_stage_taint)

            elif stage == "infer":
                run_with_timer("infer", run_stage_infer)

        print("\n✅ All selected stages finished.")
    except Exception as e:
        print(f"\n❌ Pipeline stopped due to failure in stage '{stage}': {e}")
        exit(1)
