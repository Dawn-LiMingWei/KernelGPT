import argparse
import json
import os
import re
import sys
from dataclasses import asdict, dataclass, is_dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from config import (
    DEFAULT_DIAGNOSIS_DIR,
    DEFAULT_ENRICHED_DIR,
    DEFAULT_PROMPT_DIR,
)
from context_retriever import (
    EnrichedCrash,
    SourceContext,
    StructContext,
    structured_crash_from_json,
)
from loguru import logger

PROJ_ROOT = Path(__file__).resolve().parent.parent
SPEC_GEN_ROOT = PROJ_ROOT / "spec-gen"
if str(SPEC_GEN_ROOT) not in sys.path:
    sys.path.insert(0, str(SPEC_GEN_ROOT))

try:
    from llm_utils import query_llm  # noqa: E402
except Exception:
    query_llm = None


@dataclass
class DiagnosisResult:
    crash_id: str
    crash_type: str
    root_cause: dict
    crash_location: dict
    trigger_path: list[dict]
    evidence: dict
    fix_suggestion: dict
    model_used: str
    prompt_tokens: int
    raw_llm_response: str
    raw_prompt: str
    timestamp: str


def diagnosis_result_from_json(data: dict) -> DiagnosisResult:
    return DiagnosisResult(
        crash_id=data.get("crash_id", ""),
        crash_type=data.get("crash_type", ""),
        root_cause=data.get("root_cause", {}),
        crash_location=data.get("crash_location", {}),
        trigger_path=data.get("trigger_path", []),
        evidence=data.get("evidence", {}),
        fix_suggestion=data.get("fix_suggestion", {}),
        model_used=data.get("model_used", "unknown-model"),
        prompt_tokens=int(data.get("prompt_tokens", 0) or 0),
        raw_llm_response=data.get("raw_llm_response", ""),
        raw_prompt=data.get("raw_prompt", ""),
        timestamp=data.get("timestamp", ""),
    )


def _from_dict_source_context(data: dict) -> SourceContext:
    return SourceContext(
        function_name=data.get("function_name", ""),
        file_path=data.get("file_path", ""),
        start_line=int(data.get("start_line", 0) or 0),
        end_line=int(data.get("end_line", 0) or 0),
        code=data.get("code", ""),
        signature=data.get("signature", ""),
    )


def _from_dict_struct_context(data: dict) -> StructContext:
    return StructContext(
        name=data.get("name", ""),
        definition=data.get("definition", ""),
    )


def enriched_crash_from_json(data: dict) -> EnrichedCrash:
    crash = structured_crash_from_json(data.get("crash", {}))
    crash_source = data.get("crash_source")
    fallback_source = data.get("fallback_source")
    return EnrichedCrash(
        crash=crash,
        crash_source=(
            _from_dict_source_context(crash_source)
            if isinstance(crash_source, dict)
            else None
        ),
        call_chain_sources=[
            _from_dict_source_context(x)
            for x in data.get("call_chain_sources", [])
        ],
        related_structs=[
            _from_dict_struct_context(x)
            for x in data.get("related_structs", [])
        ],
        fallback_source=(
            _from_dict_source_context(fallback_source)
            if isinstance(fallback_source, dict)
            else None
        ),
        retrieval_log=data.get("retrieval_log", []),
    )


def _dataclass_to_dict(obj):
    if is_dataclass(obj):
        return {k: _dataclass_to_dict(v) for k, v in asdict(obj).items()}
    if isinstance(obj, list):
        return [_dataclass_to_dict(x) for x in obj]
    if isinstance(obj, dict):
        return {k: _dataclass_to_dict(v) for k, v in obj.items()}
    return obj


def to_json(result: DiagnosisResult) -> dict:
    return _dataclass_to_dict(result)


class CrashDiagnoser:
    def __init__(self, config: dict = None):
        self.config = config or {}
        prompt_dir = Path(self.config.get("prompt_dir", DEFAULT_PROMPT_DIR))
        self.prompt_main = (prompt_dir / "crash_diagnosis.txt").read_text(
            errors="replace"
        )
        self.prompt_format = (prompt_dir / "report_format.txt").read_text(
            errors="replace"
        )
        system_msg_path = prompt_dir / "system_message.txt"
        if system_msg_path.exists():
            self.system_message = system_msg_path.read_text(errors="replace").strip()
        else:
            self.system_message = None
        self.max_retries = int(self.config.get("max_retries", 2))

    def diagnose(
        self, enriched: EnrichedCrash, dry_run: bool = False
    ) -> DiagnosisResult:
        prompt = self._build_prompt(enriched)
        prompt_tokens = max(1, len(prompt) // 4)
        raw = ""

        if dry_run:
            parsed = self._build_mock_result(enriched)
            raw = json.dumps(parsed, ensure_ascii=False)
        else:
            if query_llm is None:
                raise RuntimeError(
                    "llm_utils.query_llm is unavailable in current environment"
                )

            parsed = None
            for _ in range(self.max_retries + 1):
                raw = query_llm(prompt, system_message_override=self.system_message) or ""
                parsed_candidate = self._parse_response(raw)
                parsed_candidate = self._validate_diagnosis(parsed_candidate)
                if parsed_candidate is not None:
                    parsed = parsed_candidate
                    break
            if parsed is None:
                parsed = self._build_mock_result(enriched)

        return DiagnosisResult(
            crash_id=enriched.crash.crash_id,
            crash_type=enriched.crash.crash_type,
            root_cause=parsed.get("root_cause", {}),
            crash_location=parsed.get("crash_location", {}),
            trigger_path=parsed.get("trigger_path", []),
            evidence=parsed.get("evidence", {}),
            fix_suggestion=parsed.get("fix_suggestion", {}),
            model_used=os.environ.get("KGPT_LLM_MODEL", "unknown-model"),
            prompt_tokens=prompt_tokens,
            raw_llm_response=raw,
            raw_prompt=prompt,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )

    def _build_prompt(self, enriched: EnrichedCrash) -> str:
        crash = enriched.crash
        source = enriched.crash_source or enriched.fallback_source
        return (
            self.prompt_format
            + "\n\n"
            + self.prompt_main.format(
                title=crash.title,
                crash_type=crash.crash_type,
                report_summary=crash.report_raw,
                crash_source_code=(source.code if source else "N/A"),
                call_chain_code=self._format_call_chain(
                    enriched.call_chain_sources
                ),
                struct_definitions=self._format_structs(
                    enriched.related_structs
                ),
            )
        )

    def _format_call_chain(self, sources: list[SourceContext]) -> str:
        if not sources:
            return "N/A"
        parts = []
        for src in sources[:5]:
            block = (
                f"### {src.function_name}\n"
                f"file: {src.file_path}:{src.start_line}\n"
                f"signature: {src.signature}\n"
                f"```c\n{src.code}\n```"
            )
            parts.append(block)
        return "\n\n".join(parts)

    def _format_structs(self, structs: list[StructContext]) -> str:
        if not structs:
            return "N/A"
        parts = []
        for st in structs[:5]:
            parts.append(f"### struct {st.name}\n```c\n{st.definition}\n```")
        return "\n\n".join(parts)

    def _parse_response(self, raw: str) -> Optional[dict]:
        if not raw:
            return None
        text = raw.strip()
        try:
            return json.loads(text)
        except Exception:
            pass

        logger.warning(
            "LLM response was not valid JSON directly, "
            "attempting markdown code block fallback"
        )
        m = re.search(r"```json\s*(\{.*?\})\s*```", text, flags=re.DOTALL)
        if not m:
            m = re.search(r"```\s*(\{.*?\})\s*```", text, flags=re.DOTALL)
        if m:
            try:
                return json.loads(m.group(1))
            except Exception:
                logger.warning(
                    "Fallback code block extraction also failed to parse JSON"
                )
                return None
        return None

    def _validate_diagnosis(self, result: Optional[dict]) -> Optional[dict]:
        if not isinstance(result, dict):
            return None
        for key in ["root_cause", "crash_location", "trigger_path"]:
            if key not in result:
                return None

        result.setdefault("evidence", {})
        result.setdefault("fix_suggestion", {})
        if not isinstance(result.get("trigger_path"), list):
            return None
        return result

    @staticmethod
    def _build_mock_result(enriched: EnrichedCrash) -> dict:
        crash = enriched.crash
        return {
            "root_cause": {
                "type": crash.crash_type or "unknown",
                "confidence": "低",
                "summary": f"{crash.title}",
                "detail": "Dry-run mode generated placeholder diagnosis without remote LLM.",
            },
            "crash_location": {
                "function": crash.crash_function,
                "file": crash.crash_file,
                "line": crash.crash_line,
                "code_snippet": "N/A",
            },
            "trigger_path": [
                {
                    "step": i + 1,
                    "function": frame.function,
                    "description": "from call trace",
                }
                for i, frame in enumerate(crash.main_call_trace[:5])
            ],
            "evidence": {
                "registers": "captured",
                "memory": "unknown",
                "code_analysis": "pending LLM analysis",
            },
            "fix_suggestion": {
                "approach": "add guards and validate object lifecycle",
                "code_hint": "add NULL/UAF checks around crash path",
                "difficulty": "中等",
            },
        }

    def batch_diagnose(
        self,
        enriched_list: list[EnrichedCrash],
        dry_run: bool = False,
    ) -> list[DiagnosisResult]:
        out = []
        for item in enriched_list:
            out.append(self.diagnose(item, dry_run=dry_run))
        return out


def _load_enriched_list(input_dir: Path, limit: int = 0) -> list[EnrichedCrash]:
    items = []
    for path in sorted(input_dir.glob("*_enriched.json")):
        data = json.loads(path.read_text())
        items.append(enriched_crash_from_json(data))
        if limit > 0 and len(items) >= limit:
            break
    return items


def _save_results(results: list[DiagnosisResult], output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    for res in results:
        path = output_dir / f"{res.crash_id}_diagnosis.json"
        path.write_text(json.dumps(to_json(res), indent=2, ensure_ascii=False))


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Diagnose enriched crashes with LLM"
    )
    parser.add_argument("--input", type=str, default=str(DEFAULT_ENRICHED_DIR))
    parser.add_argument(
        "--output", type=str, default=str(DEFAULT_DIAGNOSIS_DIR)
    )
    parser.add_argument(
        "--prompt-dir", type=str, default=str(DEFAULT_PROMPT_DIR)
    )
    parser.add_argument("--dry-run", action="store_true", default=False)
    parser.add_argument("--limit", type=int, default=0)
    args = parser.parse_args()

    enriched_list = _load_enriched_list(
        Path(args.input).resolve(), limit=args.limit
    )
    diagnoser = CrashDiagnoser(config={"prompt_dir": args.prompt_dir})
    results = diagnoser.batch_diagnose(enriched_list, dry_run=args.dry_run)
    _save_results(results, Path(args.output).resolve())

    print(
        f"Diagnosed {len(results)} crashes into {Path(args.output).resolve()} "
        f"(dry_run={args.dry_run})"
    )


if __name__ == "__main__":
    main()
