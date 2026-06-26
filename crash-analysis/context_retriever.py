import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass, is_dataclass
from pathlib import Path
from typing import Optional

from config import (
    DEFAULT_ANALYZER_ROOT,
    DEFAULT_ENRICHED_DIR,
    DEFAULT_EXTRACTED_DIR,
    DEFAULT_LINUX_ROOT,
)
from extractor import CallFrame, StructuredCrash


PROJ_ROOT = Path(__file__).resolve().parent.parent
SPEC_GEN_ROOT = PROJ_ROOT / "spec-gen"
if str(SPEC_GEN_ROOT) not in sys.path:
    sys.path.insert(0, str(SPEC_GEN_ROOT))

try:
    from find_utils import find_function as _find_function_utils  # noqa: E402
    from find_utils import find_type as _find_type_utils  # noqa: E402
except Exception:
    _find_function_utils = None
    _find_type_utils = None


@dataclass
class SourceContext:
    function_name: str
    file_path: str
    start_line: int
    end_line: int
    code: str
    signature: str


@dataclass
class StructContext:
    name: str
    definition: str


@dataclass
class EnrichedCrash:
    crash: StructuredCrash
    crash_source: Optional[SourceContext]
    call_chain_sources: list[SourceContext]
    related_structs: list[StructContext]
    fallback_source: Optional[SourceContext]
    retrieval_log: list[str]


def _from_dict_call_frame(data: dict) -> CallFrame:
    return CallFrame(
        function=data.get("function", ""),
        file_path=data.get("file_path", ""),
        line=int(data.get("line", 0) or 0),
        offset=data.get("offset", ""),
        is_inline=bool(data.get("is_inline", False)),
        raw_text=data.get("raw_text", ""),
    )


def structured_crash_from_json(data: dict) -> StructuredCrash:
    main_trace = [_from_dict_call_frame(x) for x in data.get("main_call_trace", [])]
    secondary = []
    for trace in data.get("secondary_traces", []):
        secondary.append([_from_dict_call_frame(x) for x in trace])

    return StructuredCrash(
        crash_id=data.get("crash_id", ""),
        source=data.get("source", ""),
        title=data.get("title", ""),
        crash_type=data.get("crash_type", "unknown"),
        crash_subtype=data.get("crash_subtype", ""),
        main_call_trace=main_trace,
        secondary_traces=secondary,
        crash_function=data.get("crash_function", ""),
        crash_file=data.get("crash_file", ""),
        crash_line=int(data.get("crash_line", 0) or 0),
        registers=data.get("registers", {}),
        kasan_access_addr=data.get("kasan_access_addr", ""),
        kasan_access_size=data.get("kasan_access_size", ""),
        kasan_access_type=data.get("kasan_access_type", ""),
        kasan_object_info=data.get("kasan_object_info", ""),
        report_raw=data.get("report_raw", ""),
        log_raw=data.get("log_raw", ""),
        machine_info=data.get("machine_info", ""),
    )


def enriched_crash_from_json(data: dict) -> EnrichedCrash:
    crash = structured_crash_from_json(data.get("crash", {}))

    crash_source = data.get("crash_source")
    fallback_source = data.get("fallback_source")

    def _src(obj: Optional[dict]) -> Optional[SourceContext]:
        if not isinstance(obj, dict):
            return None
        return SourceContext(
            function_name=obj.get("function_name", ""),
            file_path=obj.get("file_path", ""),
            start_line=int(obj.get("start_line", 0) or 0),
            end_line=int(obj.get("end_line", 0) or 0),
            code=obj.get("code", ""),
            signature=obj.get("signature", ""),
        )

    call_chain_sources = [
        _src(x) for x in data.get("call_chain_sources", []) if isinstance(x, dict)
    ]

    related_structs = [
        StructContext(name=x.get("name", ""), definition=x.get("definition", ""))
        for x in data.get("related_structs", [])
        if isinstance(x, dict)
    ]

    return EnrichedCrash(
        crash=crash,
        crash_source=_src(crash_source),
        call_chain_sources=[x for x in call_chain_sources if x is not None],
        related_structs=related_structs,
        fallback_source=_src(fallback_source),
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


def to_json(enriched: EnrichedCrash) -> dict:
    return _dataclass_to_dict(enriched)


class ContextRetriever:
    def __init__(self, linux_root: Path, analyzer_root: Path):
        self.linux_root = linux_root.resolve()
        self.analyzer_root = analyzer_root.resolve()
        self._func_data: Optional[dict] = None
        self._struct_data: Optional[dict] = None
        self._enum_data: Optional[dict] = None

    def enrich(self, crash: StructuredCrash) -> EnrichedCrash:
        retrieval_log: list[str] = []

        crash_source = self._lookup_function(crash.crash_function, crash.crash_file)
        fallback_source = None
        if crash_source is not None:
            retrieval_log.append(
                f"crash_function hit in processed_func: {crash.crash_function}"
            )
        else:
            retrieval_log.append(
                f"crash_function miss in processed_func: {crash.crash_function}"
            )
            if crash.crash_function and crash.crash_file:
                fallback_source = self._read_from_linux_source(
                    crash.crash_file, crash.crash_function
                )
                if fallback_source is not None:
                    retrieval_log.append(
                        f"crash_function hit in linux fallback: {crash.crash_function}"
                    )
                else:
                    retrieval_log.append(
                        f"crash_function miss in linux fallback: {crash.crash_function}"
                    )

        call_chain_sources: list[SourceContext] = []
        seen = set()

        candidates = []
        if crash.crash_function:
            candidates.append((crash.crash_function, crash.crash_file))
        for frame in crash.main_call_trace:
            candidates.append((frame.function, frame.file_path))

        for func_name, file_hint in candidates:
            if not func_name or func_name in seen:
                continue
            seen.add(func_name)

            hit = self._lookup_function(func_name, file_hint)
            if hit is None and file_hint:
                hit = self._read_from_linux_source(file_hint, func_name)

            if hit is not None:
                call_chain_sources.append(hit)
                retrieval_log.append(f"call_chain hit: {func_name}")
            else:
                retrieval_log.append(f"call_chain miss: {func_name}")

            if len(call_chain_sources) >= 5:
                break

        related_structs: list[StructContext] = []
        struct_seen = set()
        for src in call_chain_sources[:3]:
            names = self._extract_struct_names(src.code)
            if not names:
                continue
            struct_hits = self._lookup_structs(names, src.file_path)
            for st in struct_hits:
                if st.name in struct_seen:
                    continue
                struct_seen.add(st.name)
                related_structs.append(st)
                if len(related_structs) >= 5:
                    break
            if len(related_structs) >= 5:
                break

        for st in related_structs:
            retrieval_log.append(f"struct hit: {st.name}")

        return EnrichedCrash(
            crash=crash,
            crash_source=crash_source,
            call_chain_sources=call_chain_sources,
            related_structs=related_structs,
            fallback_source=fallback_source,
            retrieval_log=retrieval_log,
        )

    def _lookup_function(self, func_name: str, file_hint: str) -> Optional[SourceContext]:
        if not func_name:
            return None
        hint = file_hint or str(self.linux_root)
        result = self._find_function(func_name, hint)
        if not result:
            return None

        header = result.get("header", "")
        code = result.get("source", "")
        file_path, start_line = self._split_header(header)
        line_count = len(code.splitlines()) if code else 0
        end_line = start_line + max(0, line_count - 1)
        signature = self._extract_signature(code)

        return SourceContext(
            function_name=func_name,
            file_path=file_path,
            start_line=start_line,
            end_line=end_line,
            code=self._format_code_snippet(code),
            signature=signature,
        )

    def _read_from_linux_source(self, file_path: str, func_name: str) -> Optional[SourceContext]:
        if not file_path or not func_name:
            return None

        rel = Path(file_path)
        source_path = rel if rel.is_absolute() else self.linux_root / rel
        if not source_path.exists() or not source_path.is_file():
            return None

        try:
            lines = source_path.read_text(errors="replace").splitlines()
        except Exception:
            return None

        def_re = re.compile(
            rf"^\s*(?:[a-zA-Z_][\w\s\*]+\s+)+{re.escape(func_name)}\s*\(",
        )
        for i, line in enumerate(lines):
            if not def_re.search(line):
                continue

            start = i
            while start > 0 and lines[start].strip().endswith(")") and "{" not in lines[start]:
                start -= 1

            brace = 0
            opened = False
            body: list[str] = []
            for j in range(start, min(len(lines), start + 400)):
                cur = lines[j]
                body.append(cur)
                brace += cur.count("{")
                if cur.count("{") > 0:
                    opened = True
                brace -= cur.count("}")
                if opened and brace <= 0:
                    end = j
                    code = "\n".join(body)
                    return SourceContext(
                        function_name=func_name,
                        file_path=str(source_path),
                        start_line=start + 1,
                        end_line=end + 1,
                        code=self._format_code_snippet(code),
                        signature=self._extract_signature(code),
                    )

        return None

    def _extract_struct_names(self, code: str) -> list[str]:
        names = re.findall(r"\bstruct\s+([A-Za-z_][A-Za-z0-9_]*)", code)
        uniq = []
        seen = set()
        for name in names:
            if name in seen:
                continue
            seen.add(name)
            uniq.append(name)
            if len(uniq) >= 20:
                break
        return uniq

    def _lookup_structs(self, struct_names: list[str], file_hint: str) -> list[StructContext]:
        out: list[StructContext] = []
        hint = file_hint or str(self.linux_root)
        for name in struct_names:
            result = self._find_type(name, hint)
            if not result:
                continue
            out.append(
                StructContext(
                    name=name,
                    definition=self._format_code_snippet(result.get("source", "")),
                )
            )
            if len(out) >= 5:
                break
        return out

    def _format_code_snippet(self, code: str, max_lines: int = 80) -> str:
        lines = code.splitlines()
        if len(lines) <= max_lines:
            return code
        return "\n".join(lines[:max_lines])

    @staticmethod
    def _extract_signature(code: str) -> str:
        for line in code.splitlines():
            text = line.strip()
            if not text:
                continue
            if text.startswith("{"):
                continue
            return text
        return ""

    @staticmethod
    def _split_header(header: str) -> tuple[str, int]:
        m = re.match(r"^(.*):(\d+)\s*$", header)
        if not m:
            return header, 0
        return m.group(1), int(m.group(2))

    def _find_function(self, name: str, path_hint: str) -> Optional[dict]:
        if _find_function_utils is not None:
            try:
                return _find_function_utils(name, path_hint)
            except Exception:
                pass

        if self._func_data is None:
            self._func_data = self._load_json(self.analyzer_root / "processed_func.json")
        return self._find_name(name, path_hint, self._func_data)

    def _find_type(self, name: str, path_hint: str) -> Optional[dict]:
        if _find_type_utils is not None:
            try:
                return _find_type_utils(name, path_hint)
            except Exception:
                pass

        if self._struct_data is None:
            self._struct_data = self._load_json(self.analyzer_root / "processed_struct.json")
        info = self._find_name(name, path_hint, self._struct_data)
        if info is not None:
            info["type"] = "struct/union"
            return info

        if self._enum_data is None:
            self._enum_data = self._load_json(self.analyzer_root / "processed_enum.json")
        info = self._find_name(name, path_hint, self._enum_data)
        if info is not None:
            info["type"] = "enum"
            return info
        return None

    @staticmethod
    def _load_json(path: Path) -> dict:
        if not path.exists() or not path.is_file():
            return {}
        try:
            return json.loads(path.read_text())
        except Exception:
            return {}

    @staticmethod
    def _path_similarity(path1: str, path2: str) -> float:
        c1 = set(Path(path1).as_posix().split("/"))
        c2 = set(Path(path2).as_posix().split("/"))
        union = c1 | c2
        if not union:
            return 0.0
        return len(c1 & c2) / len(union)

    def _find_name(self, name: str, path_hint: str, data_dict: dict) -> Optional[dict]:
        if name not in data_dict:
            return None
        candidates = data_dict[name]
        if not isinstance(candidates, dict) or not candidates:
            return None
        best_header = max(
            candidates.keys(),
            key=lambda p: self._path_similarity(path_hint or str(self.linux_root), p),
        )
        return {"header": best_header, "source": candidates[best_header]}


def batch_enrich(
    extracted_dir: Path,
    output_dir: Path,
    retriever: ContextRetriever,
) -> list[EnrichedCrash]:
    output_dir.mkdir(parents=True, exist_ok=True)
    results: list[EnrichedCrash] = []
    for path in sorted(extracted_dir.glob("*_extracted.json")):
        data = json.loads(path.read_text())
        crash = structured_crash_from_json(data)
        enriched = retriever.enrich(crash)
        out_path = output_dir / f"{crash.crash_id}_enriched.json"
        out_path.write_text(json.dumps(to_json(enriched), indent=2, ensure_ascii=False))
        results.append(enriched)
    return results


def _coverage_stats(enriched_list: list[EnrichedCrash]) -> dict:
    total = len(enriched_list)
    crash_hit = 0
    call_chain_total = 0
    call_chain_hit = 0
    for item in enriched_list:
        if item.crash_source is not None or item.fallback_source is not None:
            crash_hit += 1
        expected = min(5, len(item.crash.main_call_trace) + (1 if item.crash.crash_function else 0))
        call_chain_total += expected
        call_chain_hit += len(item.call_chain_sources)

    return {
        "total": total,
        "crash_source_hit": crash_hit,
        "crash_source_coverage": (crash_hit / total if total else 0.0),
        "call_chain_hit": call_chain_hit,
        "call_chain_expected": call_chain_total,
        "call_chain_coverage": (call_chain_hit / call_chain_total if call_chain_total else 0.0),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Retrieve static context for extracted crashes")
    parser.add_argument("--input", type=str, default=str(DEFAULT_EXTRACTED_DIR))
    parser.add_argument("--output", type=str, default=str(DEFAULT_ENRICHED_DIR))
    parser.add_argument("--linux-root", type=str, default=str(DEFAULT_LINUX_ROOT))
    parser.add_argument("--analyzer-root", type=str, default=str(DEFAULT_ANALYZER_ROOT))
    parser.add_argument("--stats", type=str, default="")
    args = parser.parse_args()

    retriever = ContextRetriever(
        linux_root=Path(args.linux_root),
        analyzer_root=Path(args.analyzer_root),
    )

    enriched = batch_enrich(
        extracted_dir=Path(args.input).resolve(),
        output_dir=Path(args.output).resolve(),
        retriever=retriever,
    )

    stats = _coverage_stats(enriched)
    if args.stats:
        stats_path = Path(args.stats).resolve()
        stats_path.parent.mkdir(parents=True, exist_ok=True)
        stats_path.write_text(json.dumps(stats, indent=2, ensure_ascii=False))

    print(
        "Enriched "
        f"{len(enriched)} crashes; "
        f"crash_source_coverage={stats['crash_source_coverage']:.2%}, "
        f"call_chain_coverage={stats['call_chain_coverage']:.2%}"
    )


if __name__ == "__main__":
    main()
