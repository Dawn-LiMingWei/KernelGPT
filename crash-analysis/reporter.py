import argparse
import json
from collections import Counter
from pathlib import Path

from context_retriever import EnrichedCrash
from diagnoser import DiagnosisResult, diagnosis_result_from_json, enriched_crash_from_json


def generate_markdown_report(result: DiagnosisResult, enriched: EnrichedCrash) -> str:
    crash = enriched.crash
    root = result.root_cause or {}
    loc = result.crash_location or {}
    trigger = result.trigger_path or []
    evidence = result.evidence or {}
    fix = result.fix_suggestion or {}

    trigger_md = "\n".join(
        f"{item.get('step', i + 1)}. `{item.get('function', '')}` - {item.get('description', '')}"
        for i, item in enumerate(trigger)
    )
    if not trigger_md:
        trigger_md = "(empty)"

    return (
        f"# Crash Diagnosis Report: {result.crash_id}\n\n"
        f"- Title: {crash.title}\n"
        f"- Source: {crash.source}\n"
        f"- Crash Type: {result.crash_type}\n"
        f"- Model: {result.model_used}\n"
        f"- Timestamp: {result.timestamp}\n\n"
        "## Root Cause\n"
        f"- Type: {root.get('type', '')}\n"
        f"- Confidence: {root.get('confidence', '')}\n"
        f"- Summary: {root.get('summary', '')}\n"
        f"- Detail: {root.get('detail', '')}\n\n"
        "## Crash Location\n"
        f"- Function: `{loc.get('function', '')}`\n"
        f"- File: `{loc.get('file', '')}`\n"
        f"- Line: {loc.get('line', 0)}\n"
        f"- Code:\n\n````text\n{loc.get('code_snippet', '')}\n````\n\n"
        "## Trigger Path\n"
        f"{trigger_md}\n\n"
        "## Evidence\n"
        f"- Registers: {evidence.get('registers', '')}\n"
        f"- Memory: {evidence.get('memory', '')}\n"
        f"- Code Analysis: {evidence.get('code_analysis', '')}\n\n"
        "## Fix Suggestion\n"
        f"- Approach: {fix.get('approach', '')}\n"
        f"- Code Hint: {fix.get('code_hint', '')}\n"
        f"- Difficulty: {fix.get('difficulty', '')}\n"
    )


def save_report(crash_id: str, report_md: str, output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / f"{crash_id}_report.md"
    path.write_text(report_md)
    return path


def compute_stats(results: list[DiagnosisResult]) -> dict:
    total = len(results)
    type_counter = Counter(r.crash_type for r in results)
    cause_counter = Counter((r.root_cause or {}).get("type", "") for r in results)
    conf_counter = Counter((r.root_cause or {}).get("confidence", "") for r in results)
    with_fix = sum(1 for r in results if (r.fix_suggestion or {}).get("approach"))
    with_trigger = sum(1 for r in results if (r.trigger_path or []))

    return {
        "total": total,
        "crash_type_distribution": dict(type_counter),
        "root_cause_distribution": dict(cause_counter),
        "confidence_distribution": dict(conf_counter),
        "fix_suggestion_coverage": (with_fix / total if total else 0.0),
        "trigger_path_coverage": (with_trigger / total if total else 0.0),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate markdown reports from diagnosis")
    parser.add_argument("--diagnosis-dir", type=str, required=True)
    parser.add_argument("--enriched-dir", type=str, required=True)
    parser.add_argument("--output", type=str, required=True)
    parser.add_argument("--stats", type=str, default="")
    args = parser.parse_args()

    diagnosis_dir = Path(args.diagnosis_dir).resolve()
    enriched_dir = Path(args.enriched_dir).resolve()
    out_dir = Path(args.output).resolve()

    results: list[DiagnosisResult] = []
    by_id: dict[str, EnrichedCrash] = {}

    for ep in sorted(enriched_dir.glob("*_enriched.json")):
        data = json.loads(ep.read_text())
        item = enriched_crash_from_json(data)
        by_id[item.crash.crash_id] = item

    for dp in sorted(diagnosis_dir.glob("*_diagnosis.json")):
        data = json.loads(dp.read_text())
        res = diagnosis_result_from_json(data)
        results.append(res)
        enriched = by_id.get(res.crash_id)
        if enriched is None:
            continue
        report_md = generate_markdown_report(res, enriched)
        save_report(res.crash_id, report_md, out_dir)

    stats = compute_stats(results)
    if args.stats:
        stats_path = Path(args.stats).resolve()
        stats_path.parent.mkdir(parents=True, exist_ok=True)
        stats_path.write_text(json.dumps(stats, indent=2, ensure_ascii=False))

    print(f"Generated {len(results)} report entries in {out_dir}")


if __name__ == "__main__":
    main()
