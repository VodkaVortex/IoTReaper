# sink_identifier.py

import json
import base64

from core.ghidra_analyzer import UnifiedGhidraRunner
from utils.utils import timeit_context
from config import config
from utils.logger_config import LoggerConfig

from sqlalchemy import create_engine, Column, String, Integer
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
# from __future__ import annotations
from typing import List, Dict, Any, Tuple
import os
# SQLAlchemy base class and model
Base = declarative_base()



class SinkIdentifier:
    def __init__(self):
        self.job_config_path = f"result/{config.IoTReaperConfig.project_path}/{config.IoTReaperConfig.main_project_name}/elf_parse/common_functions.json"
        self.runner = UnifiedGhidraRunner()
        self.logger = LoggerConfig.configure_logger('SinkIdentifier')
        self.libs_unsafe_func_res = None

    def build_sink_jobs(self):
        """
        Read job config and build a list of Ghidra analysis jobs.
        Only add jobs for libraries that are not already in the database.
        Each job is a tuple: (binary_path, script_args, main_binary).
        """
        with open(self.job_config_path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        # Query the database for existing library names
        try:
            session = config.IoTReaperConfig.get_db_session(Base)
            existing_lib_names = {
                row.lib_file_name for row in session.query(config.LibUnsafeResJson.lib_file_name).all()
            }
            session.close()
        except Exception as e:
            self.logger.error("sqlite error")
            existing_lib_names = {}

        jobs = []
        for lib_name, info in data.items():

            if lib_name in existing_lib_names:
                self.logger.info(f"Skipping {lib_name}: already exists in database.")
                continue

            # Encode symbol data as base64 string
            base64_data = base64.b64encode(json.dumps(info).encode('utf-8')).decode('utf-8')
            lib_path = f"result/{config.IoTReaperConfig.project_path}/{config.IoTReaperConfig.main_project_name}/iot_file/{lib_name}" # real lib file
            script_args = [
                "scripts/lib_unsafe_func.py",
                lib_name,
                base64_data,
                config.IoTReaperConfig.db_path
            ]
            main_binary = f"result/{config.IoTReaperConfig.project_path}/{config.IoTReaperConfig.main_project_name}/iot_file/{config.IoTReaperConfig.main_file_name}"

            jobs.append((lib_path, script_args, main_binary))

        return jobs

    def run_sink_batch_analysis(self):
        """
        Run batch analysis jobs using Ghidra.
        """
        results = None
        jobs = self.build_sink_jobs()
        if len(jobs) != 0:
            with timeit_context("batch_ghidra_analysis"):
                results = self.runner.analyze(jobs)
        return results
    
    def load_results_from_sqlite(self):
        """
        Load analysis results from a SQLite database using SQLAlchemy.
        :param db_path: path to the SQLite database
        :return: list of tuples (lib_file_name, parsed_result_json)
        """

        session = config.IoTReaperConfig.get_db_session(Base)

        results = []
        try:
            rows = session.query(config.LibUnsafeResJson).all()
            for row in rows:
                try:
                    parsed_result = json.loads(row.result_json)
                    self.logger.info(f"[{row.lib_file_name}] Loaded successfully with {len(parsed_result)} items.")
                    results.append((row.lib_file_name, parsed_result))
                except json.JSONDecodeError as e:
                    self.logger.warning(f"[{row.lib_file_name}] Failed to parse JSON: {e}")
        finally:
            session.close()

        self.libs_unsafe_func_res = results
        return results
    
    def extract_func_call_chain(self):
        """
        提取每个库的函数调用链，返回一个字典，键是库名，值是对应的函数调用链。
        :return: {'libcommon.so': ['init_core_dump|00007a54', 'doSystemCmd|00002f78', 'system|00002f78']}
        """
        extracted_info = {}

        # 确保 libs_unsafe_func_res 不为空
        if not self.libs_unsafe_func_res:
            return extracted_info
        
        for lib_name, func_info_list in self.libs_unsafe_func_res:
            # 使用集合避免重复
            call_chain_set = set()

            for func_info in func_info_list:
                origin = func_info['origin']
                origin_address = func_info['origin_address']
                
                # 添加 origin 和 origin_address
                call_chain_set.add(f"{origin}|{origin_address}")
                
                for step in func_info['steps']:
                    # 获取每个步骤的最后一个元素并提取函数名和地址
                    func_name, func_address = step[-1]
                    call_chain_set.add(f"{func_name}|{func_address}")
            
            # 将库名和对应的调用链保存到字典中，并将集合转换为列表
            extracted_info[lib_name] = list(call_chain_set)

        return extracted_info

    def build_decompile_jobs(self):
        extracted_info = self.extract_func_call_chain()
        jobs = []
        for lib_name, info in extracted_info.items():
            if info == []:
                continue
            # Encode symbol data as base64 string
            base64_data = base64.b64encode(json.dumps(info).encode('utf-8')).decode('utf-8')
            lib_path = f"result/{config.IoTReaperConfig.project_path}/{config.IoTReaperConfig.main_project_name}/iot_file/{lib_name}"
            script_args = [
                "scripts/LibDecompileFunc.java",
                lib_name,
                base64_data,
                config.IoTReaperConfig.db_path
            ]
            main_binary = f"result/{config.IoTReaperConfig.project_path}/{config.IoTReaperConfig.main_project_name}/iot_file/{config.IoTReaperConfig.main_file_name}"

            jobs.append((lib_path, script_args, main_binary))

        return jobs

    def run_decompile_batch_analysis(self):        
        """
        Run decompile batch analysis jobs using Ghidra.
        """
        results = None
        jobs = self.build_decompile_jobs()
        if len(jobs) != 0:
            with timeit_context("batch_ghidra_analysis"):
                results = self.runner.analyze(jobs)
        return results
                
    def build_funcs_files_and_chains_from_parsed_results(self,
        parsed_results: List[Tuple[str, List[Dict[str, Any]]]],
        base_dir: str | None = None,
        verbose: bool = True,
    ) -> Tuple[
        Dict[str, List[str]],            # funcs_by_lib
        Dict[str, str],                  # file_mapping
        Dict[str, List[List[str]]],      # chains_by_lib
    ]:
        """
        从 parsed_results 结构中一次性生成：

        1) funcs_by_lib:
            { "libwto.so": ["wto_resetTime", "init_xml_daemon", "system", ...], ... }

        2) file_mapping:
            { "libwto.so": "/base_dir/libwto.so", ... }

        3) chains_by_lib:
            { "libwto.so": [
                ["wto_resetTime", "init_xml_daemon", "init_xml_daemon", "system"],
                ["wto_getNamebysessionid", "init_xml_daemon", "system"],
                ...
            ],
            ...
            }

        其中每条 chain 是一个函数名数组 [call1, call2, ..., sink]，
        根据 trace["steps"] 按顺序构造。

        参数:
            parsed_results:
                形如:
                [
                    ("libwto.so", [trace1, trace2, ...]),
                    ("libmmf.so", [trace3, ...]),
                    ...
                ]

            base_dir:
                固件解包目录，比如:
                "/home/satc/iotreaper/result/Dlink-DI8300/jhttpd_9a185c/iot_file"
                最终路径为 os.path.join(base_dir, libname)

                如果为 None，则 file_mapping[libname] = libname（占位）

            verbose:
                是否打印调试信息。
        """
        funcs_by_lib: Dict[str, List[str]] = {}
        file_mapping: Dict[str, str] = {}
        chains_by_lib: Dict[str, List[List[str]]] = {}

        for idx, item in enumerate(parsed_results):
            # item 应该是 (libname, traces)
            if not isinstance(item, (list, tuple)) or len(item) != 2:
                if verbose:
                    print(f"⚠ parsed_results[{idx}] 不是 (libname, traces) 形式，已跳过: {item!r}")
                continue

            libname, traces = item
            if not isinstance(libname, str):
                if verbose:
                    print(f"⚠ parsed_results[{idx}] 的 libname 不是字符串，已跳过")
                continue
            if not isinstance(traces, list):
                if verbose:
                    print(f"⚠ parsed_results[{idx}] 的 traces 不是 list，已跳过")
                continue

            func_set = set()
            chains: List[List[str]] = []

            for t in traces:
                if not isinstance(t, dict):
                    if verbose:
                        print(f"⚠ lib={libname} 的某个 trace 不是 dict，已跳过: {t!r}")
                    continue

                steps = t.get("steps", [])
                origin = t.get("origin")

                # 如果没有 steps，就单独把 origin 记一下
                if not isinstance(steps, list) or not steps:
                    if isinstance(origin, str):
                        func_set.add(origin)
                    continue

                chain: List[str] = []

                # 从 steps 顺序构造 [call1, call2, ..., sink]
                for i, step in enumerate(steps):
                    # 期望: [ [caller_name, caller_addr], callsite_addr, [callee_name, callee_addr] ]
                    if not isinstance(step, list) or len(step) != 3:
                        continue

                    caller_info, _callsite, callee_info = step

                    # 解析 caller
                    caller_name = None
                    if isinstance(caller_info, list) and caller_info and isinstance(caller_info[0], str):
                        caller_name = caller_info[0]

                    # 解析 callee
                    callee_name = None
                    if isinstance(callee_info, list) and callee_info and isinstance(callee_info[0], str):
                        callee_name = callee_info[0]

                    # 第一个 step 时，把 caller 放进 chain 头部
                    if i == 0 and caller_name:
                        chain.append(caller_name)
                        func_set.add(caller_name)

                    # 每一步都把 callee 接到链上
                    if callee_name:
                        chain.append(callee_name)
                        func_set.add(callee_name)

                if chain:
                    chains.append(chain)

            # 写入 funcs_by_lib
            if func_set:
                funcs_by_lib[libname] = sorted(func_set)
            elif verbose:
                print(f"ℹ lib={libname} 在 traces 中未提取到函数")

            # 写入 chains_by_lib
            chains_by_lib[libname] = chains

            # 生成 file_mapping
            if base_dir is not None:
                file_mapping[libname] = os.path.join(base_dir, libname)
            else:
                file_mapping[libname] = libname

        if verbose:
            print("✨ funcs_by_lib:")
            for lib, flist in funcs_by_lib.items():
                print(f"  - {lib}: {flist}")

            print("✨ file_mapping:")
            for lib, path in file_mapping.items():
                print(f"  - {lib}: {path}")

            print("✨ chains_by_lib:")
            for lib, chains in chains_by_lib.items():
                print(f"  - {lib}:")
                for i, chain in enumerate(chains):
                    print(f"      trace#{i}: {chain}")

        return funcs_by_lib, file_mapping, chains_by_lib

if __name__ == "__main__":
    identifier = SinkIdentifier()

    # Run Ghidra analysis
    results = identifier.run_sink_batch_analysis()
    print("Analysis complete.")

    # Load results from SQLite database
    parsed_results = identifier.load_results_from_sqlite()
    for lib_name, res in parsed_results:
        print(f"{lib_name}: {len(res)} items loaded.")

