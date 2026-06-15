<div align="center">

# IoTReaper

**LLM-guided static vulnerability mining for IoT firmware**

![Python](https://img.shields.io/badge/python-3.11-blue?logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/platform-Linux-lightgrey?logo=linux)
![Arch](https://img.shields.io/badge/arch-MIPS%20%7C%20ARM%20%7C%20x86-orange)
![License](https://img.shields.io/badge/license-MIT-green)

</div>

---

IoTReaper is a static analysis pipeline that mines command-injection and buffer-overflow vulnerabilities in IoT firmware binaries. It combines **Ghidra / IDA Pro** decompilation with a team of **LLM agents** that guide taint propagation, identify source/sink functions, and rank exploitable paths — reducing manual analyst effort on large, stripped, heterogeneous firmware.

## Quick Start

```bash
# 1. Clone and set up environment
git clone https://github.com/VodkaVortex/IoTReaper.git && cd IoTReaper
conda env create -f environment.yml
conda activate IoTReaper

# 2. Copy and fill in your config
cp config/config.ini.example config/config.ini
# Edit config/config.ini — add your API key, IDA path, device name

# 3. Extract firmware (requires binwalk)
binwalk -e firmware.bin

# 4. Run the full pipeline
python3 iotreaper.py \
  /path/to/firmware.extracted/httpd \
  /path/to/firmware.extracted/ \
  Dlink-DI8300 \
  --stages all
```

Results land in `result/<device>/`.

---

## What It Does

- **Finds** command-injection and buffer-overflow sinks reachable from HTTP/NVRAM user-input sources
- **Supports** MIPS, ARM, and x86 ELF binaries — including stripped, multi-library firmware
- **Outputs** ranked vulnerability reports with decompiled call chains, taint traces, and LLM reasoning

---

## Pipeline

IoTReaper runs as a six-stage pipeline. Stages can be run individually or composed:

| Stage | Flag | What happens |
|-------|------|-------------|
| ELF Parse | `elf` | Discover dynamic libraries, resolve symbols, flag dangerous imports |
| Source ID | `source` | LLM identifies user-input entry points (`websGetVar`, `nvram_get`, …) via IDA decompilation |
| Sink ID | `sink` | LLM scores call chains ending at dangerous functions (`system`, `popen`, `sprintf`, …) |
| Danger Decompile | `danger` | IDA MCP decompiles all dangerous-function callers into structured JSON |
| Taint Analysis | `taint` | Fine-tuned LLM traces data flow from sources through decompiled code to sinks |
| Infer | `infer` | Path finder ranks source→sink chains; LLM generates final vulnerability report |

```
Firmware ELF
     │
     ▼
 [elf] ──────► library graph + symbol table
     │
     ▼
 [source] ───► source function list  (LLM + IDA MCP)
     │
     ▼
 [sink] ─────► sink call chains      (LLM + IDA MCP)
     │
     ▼
 [danger] ───► decompiled callers    (IDA MCP)
     │
     ▼
 [taint] ────► taint trace JSON      (fine-tuned LLM)
     │
     ▼
 [infer] ────► vul_result.txt        (path finder + LLM)
```

---

## Requirements

| Dependency | Version | Purpose |
|------------|---------|---------|
| Python | 3.11 | Runtime |
| Java (OpenJDK) | 11+ | Ghidra headless analysis |
| [Ghidra](https://ghidra-sre.org/) | 10.x | Binary analysis & call graph extraction |
| [IDA Pro](https://hex-rays.com/ida-pro/) | 8.x / 9.x | High-quality decompilation via MCP |
| [ida-mcp](https://github.com/mrexodia/ida-mcp) | latest | IDA ↔ IoTReaper bridge |
| [LLaMA-Factory](https://github.com/hiyouga/LLaMA-Factory) | latest | Serve fine-tuned taint model (optional) |
| DeepSeek / OpenAI-compatible API | — | LLM reasoning (source/sink/infer stages) |

> **IDA Pro is required** for the `source`, `sink`, `danger`, and `taint` stages. Ghidra alone covers the `elf` stage.

---

## Installation

### 1. Python environment

```bash
conda env create -f environment.yml
conda activate IoTReaper
```

### 2. Java (for Ghidra)

```bash
# Ubuntu / Debian
sudo apt-get install openjdk-11-jdk

# Arch
sudo pacman -S jdk11-openjdk
```

### 3. Ghidra

Download from [ghidra-sre.org](https://ghidra-sre.org/) and place it at `./ghidra/` inside the repo root (or update the `HEADLESS_GHIDRA` path in `config/config.py`).

```
IoTReaper/
└── ghidra/
    └── support/
        └── analyzeHeadless   ← must exist here
```

### 4. IDA Pro + ida-mcp

Install [ida-mcp](https://github.com/mrexodia/ida-mcp) and point `config.ini` to it (see Configuration below).

### 5. Fine-tuned taint model (optional)

If you have a fine-tuned Qwen3-based model, serve it with LLaMA-Factory:

```bash
export CUDA_VISIBLE_DEVICES=0 API_PORT=8000

llamafactory-cli api \
  --model_name_or_path /path/to/your/fine-tuned-model \
  --template qwen3 \
  --infer_backend huggingface
```

Then set `base_url = http://localhost:8000/v1` in the `[Fine-tuning]` section of `config.ini`. Without a fine-tuned model, point `[Fine-tuning]` at any DeepSeek / OpenAI-compatible endpoint.

---

## Configuration

```bash
cp config/config.ini.example config/config.ini
```

Edit `config/config.ini` — the fields you must fill in:

```ini
[Info]
device = Dlink-DI8300          # namespaces all results under result/Dlink-DI8300/

[LLM]
api_key = YOUR_API_KEY_HERE    # DeepSeek, OpenAI, or any compatible endpoint
base_url = https://api.deepseek.com/v1
model = deepseek-chat

[Fine-tuning]
api_key = YOUR_API_KEY_HERE    # can be same key; or local vLLM endpoint
base_url = https://api.deepseek.com/v1
model = deepseek-chat

[IDAMCP]
ida_mcp_path = /path/to/ida-mcp
ida_dir = /path/to/IDA Pro
```

> **`config.ini` is in `.gitignore` and will never be committed.** Only `config.ini.example` (with placeholder values) is tracked by git.

### Supported LLM backends

IoTReaper uses an OpenAI-compatible API interface. Any of the following work out of the box:

| Provider | `base_url` |
|----------|-----------|
| DeepSeek | `https://api.deepseek.com/v1` |
| OpenAI | `https://api.openai.com/v1` |
| Local vLLM / LLaMA-Factory | `http://localhost:8000/v1` |

---

## Usage

```
python3 iotreaper.py <binary> <search_dir> <device> [--stages STAGE[,STAGE...]] [--dry-run]
```

| Argument | Description |
|----------|-------------|
| `binary` | Path to the main ELF binary (e.g. `httpd`, `lighttpd`) |
| `search_dir` | Directory to search for shared libraries |
| `device` | Device identifier — used to namespace results |
| `--stages` | Comma or space separated stage list. Default: `all` |
| `--dry-run` | Print which stages would run, then exit |

### Examples

```bash
# Run all stages
python3 iotreaper.py /fw/jhttpd /fw/ Dlink-DI8300 --stages all

# Run only ELF parsing and source identification
python3 iotreaper.py /fw/jhttpd /fw/ Dlink-DI8300 --stages elf,source

# Preview what would run without executing
python3 iotreaper.py /fw/jhttpd /fw/ Dlink-DI8300 --dry-run
```

---

## Output

All results are written to `result/<device>/<binary_name>/`:

```
result/Dlink-DI8300/
├── ghidra_analyze_res.db          # SQLite — call graph, sink chains, decompiled code
├── parent_child_calls_ida_decompile.json   # IDA decompilation output
├── taint_analysis.json            # per-entry taint trace results from LLM
└── vul_result.txt                 # final ranked vulnerability report
```

The final report (`vul_result.txt`) includes:

- Source → sink call chains
- Taint propagation reasoning
- Vulnerability type classification (command injection / buffer overflow)
- Decompiled code snippets for manual review

---

## Comparison

<details>
<summary>How IoTReaper compares to related tools</summary>

| Feature | IoTReaper | SaTC | SATC | FirmSec |
|---------|-----------|------|------|---------|
| LLM-guided taint | ✅ | ❌ | ❌ | ❌ |
| Source/sink auto-identification | ✅ LLM | ⚠️ keyword | ⚠️ keyword | ⚠️ keyword |
| MIPS / ARM support | ✅ | ✅ | ✅ | ✅ |
| IDA Pro decompilation | ✅ | ❌ | ❌ | ❌ |
| Fine-tunable taint model | ✅ | ❌ | ❌ | ❌ |
| No source code required | ✅ | ✅ | ✅ | ✅ |

</details>

---

## Citation

If you use IoTReaper in your research, please cite:

```bibtex
@misc{iotreaper2025,
  title   = {IoTReaper: LLM-Guided Static Vulnerability Mining for IoT Firmware},
  author  = {Your Name},
  year    = {2025},
  url     = {https://github.com/yourname/IoTReaper}
}
```

---

## License

MIT License. See [LICENSE](LICENSE) for details.
