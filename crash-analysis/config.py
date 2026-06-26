from pathlib import Path


PROJ_ROOT = Path(__file__).resolve().parent.parent
CRASH_ANALYSIS_ROOT = Path(__file__).resolve().parent

DEFAULT_SAMPLES_ROOT = CRASH_ANALYSIS_ROOT / "crash-samples"
DEFAULT_CRASHES_DIR = DEFAULT_SAMPLES_ROOT / "crashes"
DEFAULT_EXTRACTED_DIR = DEFAULT_SAMPLES_ROOT / "extracted"
DEFAULT_ENRICHED_DIR = DEFAULT_SAMPLES_ROOT / "enriched"
DEFAULT_DIAGNOSIS_DIR = DEFAULT_SAMPLES_ROOT / "diagnosis"

DEFAULT_PROMPT_DIR = CRASH_ANALYSIS_ROOT / "prompt_templates"

DEFAULT_LINUX_ROOT = PROJ_ROOT / "linux"
DEFAULT_ANALYZER_ROOT = PROJ_ROOT / "spec-gen" / "analyzer"
