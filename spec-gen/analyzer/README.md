## Kernel Analyze Script

This scripts requires LLVM and Clang libraries to be installed. The script is used to analyze the kernel code to collect the information about the file operation handler, functions, types, and usage information.

```bash
make all # This will generate the kernel analyze script `analyze` and `usage`
```

More specifically, we need the following Clang libraries:

```makefile
CLANG_LIBS := -lclangTooling -lclangFrontend -lclangDriver -lclangSerialization \
             -lclangParse -lclangSema -lclangAnalysis -lclangAST -lclangBasic \
             -lclangEdit -lclangLex -lclangASTMatchers \
						 -lclangRewrite
```

For more information, please refer to the [Makefile](Makefile).


### Prerequisites

```bash
sudo apt-get install clang-14 libclang-dev-14
```

### Concurrency configuration

The `analyze` and `usage` binaries read `spec-gen/analyzer/.env` if it exists.

```bash
cp .env.example .env
```

Supported keys:

- `ANALYZER_MAX_THREADS`: shared upper bound for both tools.
- `ANALYZER_LIMIT_BY_CPU`: when `true`, the final thread count is capped by the CPU core count.
- `ANALYZER_BATCH_SIZE`: number of translation units processed per batch before cleanup.
- `ANALYZER_DEDUP_CACHE_MAX_ENTRIES`: upper bound of in-memory dedup entries before auto reset.
- `ANALYZE_MAX_THREADS` / `ANALYZE_LIMIT_BY_CPU`: override only `analyze`.
- `USAGE_MAX_THREADS` / `USAGE_LIMIT_BY_CPU`: override only `usage`.
- `ANALYZE_BATCH_SIZE` / `USAGE_BATCH_SIZE`: per-tool batch size override.
- `ANALYZE_DEDUP_CACHE_MAX_ENTRIES` / `USAGE_DEDUP_CACHE_MAX_ENTRIES`: per-tool dedup cache limit override.

Example:

```dotenv
ANALYZER_MAX_THREADS=4
ANALYZER_LIMIT_BY_CPU=true
USAGE_MAX_THREADS=2
USAGE_BATCH_SIZE=64
USAGE_DEDUP_CACHE_MAX_ENTRIES=100000
```
