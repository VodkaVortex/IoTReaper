Liva is an LLM multi-agent–assisted static analysis system for IoT firmware, designed to enhance traditional program analysis with reasoning, coordination, and adaptive exploration capabilities provided by large language models.
Rather than replacing classical static analysis, Liva augments it with a team of specialized LLM agents that collaborate with the analysis engine to guide taint propagation, prioritize security-relevant paths, interpret complex program semantics, and reduce analyst intervention when analyzing large-scale, heterogeneous firmware binaries.
# Install 

```angular2html
conda create -n Liva python=3.11
conda activate Liva
apt-get install openjdk-11-jdk 
conda env create -f environment.yml
```

# Firmware Preparation
```
binwalk -e firmware.bin
```

# Run Fine-tuning LLM

```
export CUDA_VISIBLE_DEVICES=1 API_PORT=8000

llamafactory-cli api \
--model_name_or_path /date/home/LLaMA-Factory/models/Qwen3-32B-Liva-3000 \
--template qwen3 \
--infer_backend huggingface  > output.log
```


# Run Liva

```
python3 liva.py /home/test/Downloads/Liva/1main/2_Dlink_DI_8300-16.07.26A1.zip.extracted/jhttpd /home/test/Downloads/Liva/1main/2_Dlink_DI_8300-16.07.26A1.zip.extracted/ Dlink-DI8300 --stage elf,source,sinkl,danger,taint,neo4j,infer
```

