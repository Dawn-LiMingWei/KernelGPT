# Crash Analysis 使用指南

本目录实现了基于 LLM 的 Linux 内核崩溃自动分析流水线，包含四个阶段：

- 阶段 A：崩溃日志结构化提取（`extractor.py`）
- 阶段 B：源码上下文检索（`context_retriever.py`）
- 阶段 C：LLM 诊断（`diagnoser.py`）
- 阶段 D：报告与统计生成（`reporter.py`）

并提供一键编排入口：`main.py`。

## 1. 目录结构

```text
crash-analysis/
├── config.py
├── extractor.py
├── context_retriever.py
├── diagnoser.py
├── reporter.py
├── main.py
├── prompt_templates/
│   ├── crash_diagnosis.txt
│   ├── crash_type_guide.txt
│   └── report_format.txt
└── crash-samples/
    ├── crashes/          # 原始崩溃样本
    ├── extracted/        # 阶段A缓存
    ├── enriched/         # 阶段B缓存
    ├── diagnosis/        # 阶段C结果 + 阶段D报告
    └── eval_stats.json   # 阶段D统计（或输出目录中的同名文件）
```

## 2. 环境准备

建议使用仓库根目录虚拟环境：

```bash
python3 --version
```

如果要调用真实 LLM，请确保以下依赖和配置可用：

- Python 包：`openai`、`loguru`（`llm_utils.py` 依赖）
- LLM 配置（可放在 `spec-gen/.env`）：

```bash
KGPT_LLM_API_KEY=your_key
KGPT_LLM_MODEL=deepseek-chat
KGPT_LLM_BASE_URL=https://api.deepseek.com
KGPT_LLM_MAX_TOKENS=4096
KGPT_LLM_USE_JSON_RESPONSE_FORMAT=true
```

## 3. 快速开始

### 3.1 一键跑完整流水线（A→B→C→D）

```bash
python3 crash-analysis/main.py --all
```

### 3.2 不调用 LLM 的本地演练（dry-run）

```bash
python3 crash-analysis/main.py --all --dry-run
```

### 3.3 指定单个 crash 调试

```bash
python3 crash-analysis/main.py --all --crash-id 08418c2d59c5109f794fa6f9f35ab91781549ae1 --dry-run --force
```

## 4. 分阶段运行

### 阶段 A：提取

```bash
python3 crash-analysis/main.py --extract-only
```

等价底层命令：

```bash
python3 crash-analysis/extractor.py \
  --input crash-analysis/crash-samples/crashes \
  --output crash-analysis/crash-samples/extracted \
  --manifest crash-analysis/crash-samples/extracted_manifest.json
```

### 阶段 B：上下文检索

```bash
python3 crash-analysis/main.py --retrieve-only
```

等价底层命令：

```bash
python3 crash-analysis/context_retriever.py \
  --input crash-analysis/crash-samples/extracted \
  --output crash-analysis/crash-samples/enriched \
  --stats crash-analysis/crash-samples/enriched_stats.json
```

### 阶段 C：LLM 诊断

```bash
python3 crash-analysis/main.py --diagnose-only
```

等价底层命令（真实 LLM）：

```bash
python3 crash-analysis/diagnoser.py \
  --input crash-analysis/crash-samples/enriched \
  --output crash-analysis/crash-samples/diagnosis
```

等价底层命令（dry-run）：

```bash
python3 crash-analysis/diagnoser.py \
  --input crash-analysis/crash-samples/enriched \
  --output crash-analysis/crash-samples/diagnosis \
  --dry-run
```

### 阶段 D：报告与统计

```bash
python3 crash-analysis/main.py --report-only
```

等价底层命令：

```bash
python3 crash-analysis/reporter.py \
  --diagnosis-dir crash-analysis/crash-samples/diagnosis \
  --enriched-dir crash-analysis/crash-samples/enriched \
  --output crash-analysis/crash-samples/diagnosis \
  --stats crash-analysis/crash-samples/diagnosis/eval_stats.json
```

## 5. 常用参数

`main.py` 支持：

- `--all`：执行 A/B/C/D 全流程
- `--extract-only` / `--retrieve-only` / `--diagnose-only` / `--report-only`
- `--dry-run`：阶段 C 不调用远程 LLM，生成占位诊断
- `--force`：忽略缓存，强制重新计算
- `--crash-id <hash>`：仅处理指定样本
- `--input`：原始 crash 目录（默认 `crash-samples/crashes`）
- `--extracted-dir` / `--enriched-dir` / `--diagnosis-dir`：阶段缓存目录
- `--output`：阶段 D 报告输出目录
- `--linux-root`：Linux 源码目录（阶段 B fallback 使用）
- `--analyzer-root`：`spec-gen/analyzer` 目录

## 6. 输出说明

- 阶段 A：`crash-samples/extracted/{id}_extracted.json`
- 阶段 B：`crash-samples/enriched/{id}_enriched.json`
- 阶段 C：`crash-samples/diagnosis/{id}_diagnosis.json`
- 阶段 D：`{output}/{id}_report.md`、`{output}/eval_stats.json`

其中 `eval_stats.json` 包含：

- 总样本数
- crash 类型分布
- root cause 类型分布
- 置信度分布
- `fix_suggestion` 覆盖率
- `trigger_path` 覆盖率

## 7. 故障排查

### 7.1 `llm_utils.query_llm is unavailable`

通常是解释器环境缺少依赖。优先使用仓库 `.venv`：

```bash
python3 crash-analysis/diagnoser.py --input ... --output ...
```

### 7.2 阶段 B 检索不到 `find_utils`

`context_retriever.py` 内置了 JSON 直读回退逻辑，即使 `find_utils` 导入失败也可运行。

### 7.3 诊断 JSON 解析失败

阶段 C 会尝试：

1. 直接 `json.loads(raw)`
2. 提取 ```json``` 代码块再解析
3. 按重试次数重新请求

若仍失败，建议先用 `--dry-run` 验证流程链路，再检查 LLM 输出约束和 `.env` 配置。
