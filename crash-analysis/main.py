import argparse
import json
from pathlib import Path

from config import (
    DEFAULT_ANALYZER_ROOT,
    DEFAULT_CRASHES_DIR,
    DEFAULT_DIAGNOSIS_DIR,
    DEFAULT_ENRICHED_DIR,
    DEFAULT_EXTRACTED_DIR,
    DEFAULT_LINUX_ROOT,
)
from context_retriever import ContextRetriever, enriched_crash_from_json, structured_crash_from_json, to_json as enriched_to_json
from diagnoser import CrashDiagnoser, diagnosis_result_from_json, to_json as diagnosis_to_json
from extractor import extract_crash, to_json as extracted_to_json
from reporter import compute_stats, generate_markdown_report, save_report


def _load_json_if_exists(path: Path):
    if not path.exists() or not path.is_file():
        return None
    return json.loads(path.read_text())


def _save_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False))


def _iter_crash_dirs(crashes_dir: Path, crash_id: str = "") -> list[Path]:
    if crash_id:
        only = crashes_dir / crash_id
        if only.exists() and only.is_dir():
            return [only]
        return []
    return [p for p in sorted(crashes_dir.iterdir()) if p.is_dir()]


def main() -> None:
    parser = argparse.ArgumentParser(description="Crash analysis A/B/C/D pipeline")
    parser.add_argument("--all", action="store_true", default=False)
    parser.add_argument("--extract-only", action="store_true", default=False)
    parser.add_argument("--retrieve-only", action="store_true", default=False)
    parser.add_argument("--diagnose-only", action="store_true", default=False)
    parser.add_argument("--report-only", action="store_true", default=False)
    parser.add_argument("--dry-run", action="store_true", default=False)
    parser.add_argument("--force", action="store_true", default=False)
    parser.add_argument("--crash-id", type=str, default="")
    parser.add_argument("--input", type=str, default=str(DEFAULT_CRASHES_DIR))
    parser.add_argument("--extracted-dir", type=str, default=str(DEFAULT_EXTRACTED_DIR))
    parser.add_argument("--enriched-dir", type=str, default=str(DEFAULT_ENRICHED_DIR))
    parser.add_argument("--diagnosis-dir", type=str, default=str(DEFAULT_DIAGNOSIS_DIR))
    parser.add_argument("--output", type=str, default=str(DEFAULT_DIAGNOSIS_DIR))
    parser.add_argument("--linux-root", type=str, default=str(DEFAULT_LINUX_ROOT))
    parser.add_argument("--analyzer-root", type=str, default=str(DEFAULT_ANALYZER_ROOT))
    args = parser.parse_args()

    crashes_dir = Path(args.input).resolve()
    extracted_dir = Path(args.extracted_dir).resolve()
    enriched_dir = Path(args.enriched_dir).resolve()
    diagnosis_dir = Path(args.diagnosis_dir).resolve()
    report_dir = Path(args.output).resolve()

    if args.all:
        args.extract_only = False
        args.retrieve_only = False
        args.diagnose_only = False
        args.report_only = False

    crash_dirs = _iter_crash_dirs(crashes_dir, args.crash_id)
    crash_ids = [p.name for p in crash_dirs]

    extracted = []
    if not args.diagnose_only and not args.report_only:
        for crash_dir in crash_dirs:
            cache_path = extracted_dir / f"{crash_dir.name}_extracted.json"
            cache = _load_json_if_exists(cache_path)
            if cache is not None and not args.force:
                extracted.append(structured_crash_from_json(cache))
            else:
                obj = extract_crash(crash_dir)
                _save_json(cache_path, extracted_to_json(obj))
                extracted.append(obj)
    else:
        for cid in crash_ids:
            cache_path = extracted_dir / f"{cid}_extracted.json"
            cache = _load_json_if_exists(cache_path)
            if cache is not None:
                extracted.append(structured_crash_from_json(cache))

    if args.extract_only:
        print(f"Stage A done: {len(extracted)} extracted")
        return

    retriever = ContextRetriever(Path(args.linux_root), Path(args.analyzer_root))
    enriched = []
    if not args.diagnose_only and not args.report_only:
        for item in extracted:
            cache_path = enriched_dir / f"{item.crash_id}_enriched.json"
            cache = _load_json_if_exists(cache_path)
            if cache is not None and not args.force:
                enriched.append(enriched_crash_from_json(cache))
            else:
                obj = retriever.enrich(item)
                _save_json(cache_path, enriched_to_json(obj))
                enriched.append(obj)
    else:
        for cid in crash_ids:
            cache_path = enriched_dir / f"{cid}_enriched.json"
            cache = _load_json_if_exists(cache_path)
            if cache is not None:
                enriched.append(enriched_crash_from_json(cache))

    if args.retrieve_only:
        print(f"Stage B done: {len(enriched)} enriched")
        return

    diagnoser = CrashDiagnoser()
    results = []
    if not args.report_only:
        for item in enriched:
            cid = item.crash.crash_id
            cache_path = diagnosis_dir / f"{cid}_diagnosis.json"
            cache = _load_json_if_exists(cache_path)
            if cache is not None and not args.force:
                results.append(diagnosis_result_from_json(cache))
            else:
                obj = diagnoser.diagnose(item, dry_run=args.dry_run)
                _save_json(cache_path, diagnosis_to_json(obj))
                results.append(obj)
    else:
        for cid in crash_ids:
            cache_path = diagnosis_dir / f"{cid}_diagnosis.json"
            cache = _load_json_if_exists(cache_path)
            if cache is not None:
                results.append(diagnosis_result_from_json(cache))

    if args.diagnose_only:
        print(f"Stage C done: {len(results)} diagnosed")
        return

    enriched_map = {x.crash.crash_id: x for x in enriched}
    generated = 0
    for res in results:
        item = enriched_map.get(res.crash_id)
        if item is None:
            continue
        report = generate_markdown_report(res, item)
        save_report(res.crash_id, report, report_dir)
        generated += 1

    stats = compute_stats(results)
    _save_json(report_dir / "eval_stats.json", stats)
    print(
        f"Pipeline done: A={len(extracted)} B={len(enriched)} "
        f"C={len(results)} D={generated}"
    )


if __name__ == "__main__":
    main()
