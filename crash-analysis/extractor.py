import argparse
import json
import re
from dataclasses import asdict, dataclass, is_dataclass
from pathlib import Path
from typing import Optional

from config import DEFAULT_CRASHES_DIR, DEFAULT_EXTRACTED_DIR

try:
    from fetch_crashes import CRASH_TYPE_KEYWORDS
except Exception:
    CRASH_TYPE_KEYWORDS = {}


CALL_TRACE_RE = re.compile(
    r"^\s*(\?)?\s*"
    r"(\S+?)"
    r"(?:\+0x([0-9a-f]+)/0x([0-9a-f]+))?"
    r"(?:\s+(\S+\.(?:c|cc|h)):([0-9]+))?"
    r"(?:\s+\[inline\])?"
    r"\s*$",
    re.IGNORECASE,
)

KASAN_SUBTYPE_RE = re.compile(r"KASAN:\s+\S+\s+(Read|Write|Free)\b", re.IGNORECASE)
REGISTER_RE = re.compile(r"\b([A-Z][A-Z0-9]{1,7}):\s*([0-9a-fA-Fx]+)\b")
RIP_FUNC_RE = re.compile(
    r"\bRIP:\s+\S+:([^+\s]+)(?:\+0x[0-9a-f]+/[0-9a-f]+)?\b", re.IGNORECASE
)
KASAN_ACCESS_RE = re.compile(
    r"\b(Read|Write|Free)\s+of\s+size\s+(\d+)\s+at\s+addr\s+([0-9a-fx]+)",
    re.IGNORECASE,
)
TITLE_FUNC_RE = re.compile(
    r"\bin\s+([a-zA-Z_][a-zA-Z0-9_\.]+)\s*(?:$|[\s\(])",
    re.IGNORECASE,
)


@dataclass
class CallFrame:
    function: str
    file_path: str
    line: int
    offset: str
    is_inline: bool
    raw_text: str


@dataclass
class StructuredCrash:
    crash_id: str
    source: str
    title: str
    crash_type: str
    crash_subtype: str
    main_call_trace: list[CallFrame]
    secondary_traces: list[list[CallFrame]]
    crash_function: str
    crash_file: str
    crash_line: int
    registers: dict[str, str]
    kasan_access_addr: str
    kasan_access_size: str
    kasan_access_type: str
    kasan_object_info: str
    report_raw: str
    log_raw: str
    machine_info: str


def _strip_log_prefix(line: str) -> str:
    text = line
    while True:
        m = re.match(r"^\s*\[[^\]]+\]\s*(.*)$", text)
        if not m:
            break
        text = m.group(1)
    return text


def _read_text_if_exists(path: Path) -> str:
    if not path.exists() or not path.is_file():
        return ""
    return path.read_text(errors="replace")


def _detect_source(machine_info: str) -> str:
    text = machine_info.lower()
    if "source: syzbot" in text:
        return "syzbot"
    if "source: syzkaller-testdata" in text:
        return "syzkaller-testdata"
    return "local"


def classify_crash_type(title: str) -> tuple[str, str]:
    crash_type = "unknown"
    for keyword, ctype in CRASH_TYPE_KEYWORDS.items():
        if keyword in title:
            crash_type = ctype
            break

    subtype = ""
    m = KASAN_SUBTYPE_RE.search(title)
    if m:
        subtype = m.group(1)
    return crash_type, subtype


def parse_call_trace_line(line: str) -> Optional[CallFrame]:
    raw_line = _strip_log_prefix(line).strip()
    if not raw_line:
        return None
    if raw_line in {"<TASK>", "</TASK>", "Call Trace:"}:
        return None
    if raw_line.startswith("---["):
        return None

    is_inline = "[inline]" in raw_line
    normalized = raw_line.replace("[inline]", "").strip()
    m = CALL_TRACE_RE.match(normalized)
    if not m:
        return None

    function = m.group(2)
    if function in {"RIP:", "Code:", "Modules", "Kernel", "entry_SYSCALL_64_after_hwframe"}:
        return None
    if not re.match(r"^[A-Za-z0-9_.$]+$", function):
        return None

    off_a = m.group(3)
    off_b = m.group(4)
    offset = f"+0x{off_a}/0x{off_b}" if off_a and off_b else ""
    file_path = m.group(5) or ""
    line_no = int(m.group(6)) if m.group(6) else 0

    return CallFrame(
        function=function,
        file_path=file_path,
        line=line_no,
        offset=offset,
        is_inline=is_inline,
        raw_text=raw_line,
    )


def extract_call_traces(report_text: str) -> tuple[list[CallFrame], list[list[CallFrame]]]:
    traces: list[list[CallFrame]] = []
    current: list[CallFrame] = []
    in_trace = False

    for line in report_text.splitlines():
        stripped = _strip_log_prefix(line).strip()

        if re.match(r"^={10,}$", stripped):
            if current:
                traces.append(current)
                current = []
            in_trace = False
            continue

        if (
            stripped.startswith("Call Trace:")
            or stripped.lower().startswith("read to")
            or stripped.lower().startswith("write to")
            or stripped.lower().startswith("freed by")
            or stripped.lower().startswith("allocated by")
        ):
            if current:
                traces.append(current)
                current = []
            in_trace = True
            continue

        if not in_trace:
            continue

        if (
            stripped.startswith("</TASK>")
            or stripped.startswith("---[")
            or stripped.startswith("Modules linked in")
        ):
            if current:
                traces.append(current)
                current = []
            in_trace = False
            continue

        frame = parse_call_trace_line(line)
        if frame:
            current.append(frame)

    if current:
        traces.append(current)

    traces = [t for t in traces if t]
    if not traces:
        return [], []
    return traces[0], traces[1:]


def extract_registers(report_text: str) -> dict[str, str]:
    regs: dict[str, str] = {}
    for line in report_text.splitlines():
        stripped = _strip_log_prefix(line)
        for reg, value in REGISTER_RE.findall(stripped):
            if reg in {"Code"}:
                continue
            regs[reg] = value
    return regs


def extract_kasan_details(report_text: str) -> dict:
    details = {
        "kasan_access_addr": "",
        "kasan_access_size": "",
        "kasan_access_type": "",
        "kasan_object_info": "",
    }

    lines = report_text.splitlines()
    for line in lines:
        stripped = _strip_log_prefix(line)
        m = KASAN_ACCESS_RE.search(stripped)
        if m:
            details["kasan_access_type"] = m.group(1)
            details["kasan_access_size"] = m.group(2)
            details["kasan_access_addr"] = m.group(3)
            break

    obj_lines: list[str] = []
    capture = False
    for line in lines:
        stripped = _strip_log_prefix(line).strip()
        low = stripped.lower()
        if (
            "allocated by task" in low
            or "freed by task" in low
            or "the buggy address belongs to" in low
            or "the buggy address is located" in low
        ):
            capture = True

        if capture:
            obj_lines.append(stripped)
            if len(obj_lines) >= 30:
                break
            if not stripped:
                capture = False

    details["kasan_object_info"] = "\n".join(x for x in obj_lines if x).strip()
    return details


def _is_valid_kernel_func(name: str) -> bool:
    if not name:
        return False
    if name.startswith("0x") or name.startswith("[<"):
        return False
    return bool(re.match(r"^[A-Za-z_]", name))


_INFRA_FUNCS = frozenset({
    "__dump_stack", "dump_stack", "dump_stack_lvl",
    "print_address_description", "print_report", "kasan_report",
    "check_noncircular", "check_prev_add", "check_prevs_add",
    "validate_chain", "__lock_acquire", "lock_acquire",
})


def _find_crash_func_from_trace(
    main_trace: list[CallFrame],
) -> tuple[str, str, int]:
    for frame in main_trace:
        if frame.function in _INFRA_FUNCS:
            continue
        if not _is_valid_kernel_func(frame.function):
            continue
        return frame.function, frame.file_path, frame.line
    if main_trace:
        f = main_trace[0]
        return f.function, f.file_path, f.line
    return "", "", 0


def parse_report(report_text: str, title: str = "") -> dict:
    main_trace, secondary_traces = extract_call_traces(report_text)
    regs = extract_registers(report_text)
    kasan = extract_kasan_details(report_text)

    crash_function = ""
    crash_file = ""
    crash_line = 0

    for line in report_text.splitlines():
        stripped = _strip_log_prefix(line)
        m = RIP_FUNC_RE.search(stripped)
        if m:
            crash_function = m.group(1)
            break

    if not _is_valid_kernel_func(crash_function):
        crash_function = ""
        m = TITLE_FUNC_RE.search(title)
        if m:
            crash_function = m.group(1)

    if main_trace and not crash_function:
        crash_function, crash_file, crash_line = _find_crash_func_from_trace(
            main_trace
        )

    if main_trace and not crash_file:
        crash_file = main_trace[0].file_path
        crash_line = main_trace[0].line

    return {
        "main_call_trace": main_trace,
        "secondary_traces": secondary_traces,
        "registers": regs,
        "crash_function": crash_function,
        "crash_file": crash_file,
        "crash_line": crash_line,
        **kasan,
    }


def extract_crash(crash_dir: Path) -> StructuredCrash:
    if not crash_dir.exists() or not crash_dir.is_dir():
        raise FileNotFoundError(f"Invalid crash dir: {crash_dir}")

    title = _read_text_if_exists(crash_dir / "description").strip()
    report_raw = _read_text_if_exists(crash_dir / "report0")
    log_raw = _read_text_if_exists(crash_dir / "log0")
    machine_info = _read_text_if_exists(crash_dir / "machineInfo0")

    crash_type, crash_subtype = classify_crash_type(title)
    parsed = parse_report(report_raw, title=title)

    return StructuredCrash(
        crash_id=crash_dir.name,
        source=_detect_source(machine_info),
        title=title,
        crash_type=crash_type,
        crash_subtype=crash_subtype,
        main_call_trace=parsed["main_call_trace"],
        secondary_traces=parsed["secondary_traces"],
        crash_function=parsed["crash_function"],
        crash_file=parsed["crash_file"],
        crash_line=parsed["crash_line"],
        registers=parsed["registers"],
        kasan_access_addr=parsed["kasan_access_addr"],
        kasan_access_size=parsed["kasan_access_size"],
        kasan_access_type=parsed["kasan_access_type"],
        kasan_object_info=parsed["kasan_object_info"],
        report_raw=report_raw,
        log_raw=log_raw,
        machine_info=machine_info,
    )


def batch_extract(crashes_dir: Path) -> list[StructuredCrash]:
    if not crashes_dir.exists():
        return []

    items: list[StructuredCrash] = []
    for crash_dir in sorted(crashes_dir.iterdir()):
        if not crash_dir.is_dir():
            continue
        if not (crash_dir / "description").exists():
            continue
        items.append(extract_crash(crash_dir))
    return items


def _dataclass_to_dict(obj):
    if is_dataclass(obj):
        return {k: _dataclass_to_dict(v) for k, v in asdict(obj).items()}
    if isinstance(obj, list):
        return [_dataclass_to_dict(x) for x in obj]
    if isinstance(obj, dict):
        return {k: _dataclass_to_dict(v) for k, v in obj.items()}
    return obj


def to_json(crash: StructuredCrash) -> dict:
    return _dataclass_to_dict(crash)


def _write_batch_json(crashes: list[StructuredCrash], output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    for crash in crashes:
        path = output_dir / f"{crash.crash_id}_extracted.json"
        path.write_text(json.dumps(to_json(crash), indent=2, ensure_ascii=False))


def _build_manifest(crashes: list[StructuredCrash]) -> list[dict]:
    return [
        {
            "id": c.crash_id,
            "source": c.source,
            "title": c.title,
            "crash_type": c.crash_type,
            "crash_subtype": c.crash_subtype,
            "crash_function": c.crash_function,
            "crash_file": c.crash_file,
            "crash_line": c.crash_line,
            "call_trace_len": len(c.main_call_trace),
            "secondary_trace_count": len(c.secondary_traces),
        }
        for c in crashes
    ]


def main() -> None:
    parser = argparse.ArgumentParser(description="Extract structured crash data")
    parser.add_argument(    
        "--input",
        type=str,
        default=str(DEFAULT_CRASHES_DIR),
        help="Input crashes directory",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=str(DEFAULT_EXTRACTED_DIR),
        help="Output extracted JSON directory",
    )
    parser.add_argument(
        "--manifest",
        type=str,
        default="",
        help="Optional manifest output path",
    )
    args = parser.parse_args()

    crashes = batch_extract(Path(args.input).resolve())
    _write_batch_json(crashes, Path(args.output).resolve())

    if args.manifest:
        manifest_path = Path(args.manifest).resolve()
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        manifest_path.write_text(
            json.dumps(_build_manifest(crashes), indent=2, ensure_ascii=False)
        )

    print(f"Extracted {len(crashes)} crashes into {Path(args.output).resolve()}")


if __name__ == "__main__":
    main()
