"""
从多个来源获取 Linux 内核崩溃样本，统一转换为与 KernelGPT 本地 syzkaller 产出一致的目录结构。

数据来源（按优先级）：
  0. 本地 workdir 已有崩溃（--include-local）
  1. syzbot 公开网站 (https://syzbot.org) 爬取真实崩溃报告
  2. syzkaller 仓库内置的 693 个 Linux report 测试样本

输出目录结构（与 syzkaller workdir/crashes/{hash}/ 一致）：
  output_dir/
    crashes/
      {title_hash}/
        description    崩溃单行描述
        report0        内核崩溃报告（call trace 等）
        log0           完整内核日志
        machineInfo0   机器信息
"""

import hashlib
import html
import json
import os
import re
import shutil
import ssl
import sys
import time
import urllib.request
import urllib.parse
import urllib.error
from pathlib import Path
from typing import Optional

PROJ_ROOT = Path(__file__).parent.parent.resolve()
SYZKALLER_TESTDATA = (
    PROJ_ROOT / "syzkaller" / "pkg" / "report" / "testdata" / "linux" / "report"
)

SYZBOT_BASE = "https://syzbot.org"

CRASH_TYPE_KEYWORDS = {
    "KASAN: use-after-free": "use-after-free",
    "KASAN: slab-use-after-free": "use-after-free",
    "KASAN: slab-out-of-bounds": "slab-out-of-bounds",
    "KASAN: stack-out-of-bounds": "stack-out-of-bounds",
    "KASAN: invalid-free": "invalid-free",
    "KASAN: null-ptr-deref": "null-ptr-deref-kasan",
    "KASAN: global-out-of-bounds": "global-out-of-bounds",
    "BUG: unable to handle kernel NULL pointer": "null-ptr-deref",
    "BUG: unable to handle kernel paging request": "bad-access",
    "general protection fault": "gpf",
    "kernel BUG": "kernel-bug",
    "kernel panic": "kernel-panic",
    "WARNING: possible circular locking dependency": "deadlock",
    "WARNING: possible recursive locking": "deadlock",
    "possible deadlock": "deadlock",
    "WARNING:": "warning",
    "WARNING in": "warning",
    "BUG: bad unlock balance": "lock-bug",
    "BUG: scheduling while atomic": "atomic-bug",
    "INFO: task hung": "task-hung",
    "INFO: rcu detected stall": "rcu-stall",
    "BUG: soft lockup": "soft-lockup",
    "BUG: stack guard page": "stack-overflow",
    "BUG: Dentry still in use": "dentry-bug",
    "divide error": "divide-error",
    "invalid opcode": "invalid-opcode",
    "INFO: trying to register non-static key": "lock-registered",
    "BUG: bad usercopy": "bad-usercopy",
    "WARNING: locking bug": "lock-bug",
    "WARNING: refcount bug": "refcount-bug",
    "WARNING: ODEBUG bug": "odebug-bug",
    "KFENCE: invalid free": "kfence-invalid-free",
    "KFENCE: out-of-bounds": "kfence-oob",
    "KMSAN: uninit-value": "uninit-value",
    "KCSAN: data-race": "data-race",
}


def classify_crash(title: str) -> str:
    for keyword, ctype in CRASH_TYPE_KEYWORDS.items():
        if keyword in title:
            return ctype
    return "unknown"


def stable_hash(title: str) -> str:
    return hashlib.sha1(title.encode()).hexdigest()


def _urlopen(url: str, timeout: int = 30) -> Optional[bytes]:
    ssl_ctx = ssl.create_default_context()
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "KernelGPT-CrashFetcher/1.0"})
        with urllib.request.urlopen(req, timeout=timeout, context=ssl_ctx) as resp:
            return resp.read()
    except Exception as e:
        print(f"    [WARN] 请求失败: {url[:80]}... -> {e}")
        return None


def _fetch_text(url: str) -> Optional[str]:
    data = _urlopen(url)
    if data is None:
        return None
    return data.decode("utf-8", errors="replace")


# ---------------------------------------------------------------------------
#  解析 syzkaller 内置测试数据
# ---------------------------------------------------------------------------

def parse_syzkaller_report(filepath: Path):
    meta = {}
    lines = filepath.read_text(errors="replace").splitlines()

    body_start = 0
    for i, line in enumerate(lines):
        if line.startswith("TITLE:"):
            meta["title"] = line[len("TITLE:"):].strip()
        elif line.startswith("ALT:"):
            meta["alt"] = line[len("ALT:"):].strip()
        elif line.startswith("TYPE:"):
            meta["type"] = line[len("TYPE:"):].strip()
        elif line.startswith("CORRUPTED:"):
            meta["corrupted"] = line[len("CORRUPTED:"):].strip() == "Y"
        elif line.strip() == "" and "title" in meta:
            body_start = i + 1
            break

    if "title" not in meta:
        meta["title"] = lines[0].strip() if lines else "unknown"

    kernel_log = "\n".join(lines[body_start:])
    return meta, kernel_log


# ---------------------------------------------------------------------------
#  写入 crash 目录（统一格式）
# ---------------------------------------------------------------------------

def build_crash_dir(output_dir: Path, title: str, report_body: str,
                    log_body: str, machine_info: str, tag: str = ""):
    crash_id = stable_hash(title + tag)
    crash_dir = output_dir / "crashes" / crash_id
    crash_dir.mkdir(parents=True, exist_ok=True)

    (crash_dir / "description").write_text(title + "\n")
    if report_body:
        (crash_dir / "report0").write_text(report_body)
    if log_body:
        (crash_dir / "log0").write_text(log_body)
    if machine_info:
        (crash_dir / "machineInfo0").write_text(machine_info)

    return crash_dir


# ---------------------------------------------------------------------------
#  来源 1: syzbot 网页爬取
# ---------------------------------------------------------------------------

def _parse_bug_list(page_html: str) -> list[dict]:
    """从 syzbot bug 列表页 HTML 中解析出 bug 条目。

    列表页中的每个 bug 链接格式：
      <a href="/bug?extid=XXXX">TITLE</a>
    """
    bugs = []
    pattern = re.compile(
        r'<a\s+href="/bug\?extid=([^"]+?)"[^>]*>([^<]+)</a>'
    )
    seen = set()
    for m in pattern.finditer(page_html):
        extid = m.group(1).strip()
        title = html.unescape(m.group(2).strip())
        if extid in seen:
            continue
        seen.add(extid)
        bugs.append({"extid": extid, "title": title})
    return bugs


def _parse_bug_detail(page_html: str) -> dict:
    """从 bug 详情页 HTML 中提取：
    1. 样本崩溃报告（页面中内嵌的 "Sample crash report" 文本）
    2. CrashReport / CrashLog / MachineInfo / SyzRepro 的下载链接
    """
    result = {
        "sample_report": "",
        "report_url": "",
        "log_url": "",
        "machine_info_url": "",
        "syz_repro_url": "",
        "c_repro_url": "",
    }

    text_link_pattern = re.compile(
        r'href="(/text\?tag=(\w+)(?:&amp;|&)x=([^"&]+))"'
    )
    for m in text_link_pattern.finditer(page_html):
        tag_name = m.group(2)
        raw_path = m.group(1).replace("&amp;", "&")
        full_url = SYZBOT_BASE + raw_path
        if tag_name == "CrashReport" and not result["report_url"]:
            result["report_url"] = full_url
        elif tag_name == "CrashLog" and not result["log_url"]:
            result["log_url"] = full_url
        elif tag_name == "MachineInfo" and not result["machine_info_url"]:
            result["machine_info_url"] = full_url
        elif tag_name == "ReproSyz" and not result["syz_repro_url"]:
            result["syz_repro_url"] = full_url
        elif tag_name == "ReproC" and not result["c_repro_url"]:
            result["c_repro_url"] = full_url

    sample_match = re.search(
        r'<b>Sample crash report:</b>\s*<br\s*/?>\s*<div[^>]*>\s*<pre[^>]*>(.*?)</pre>',
        page_html, re.DOTALL,
    )
    if sample_match:
        raw = sample_match.group(1)
        raw = re.sub(r'<a[^>]*>([^<]*)</a>', r'\1', raw)
        result["sample_report"] = html.unescape(raw).strip()

    return result


def fetch_from_syzbot(output_dir: Path, target_count: int = 20):
    """从 syzbot.org 爬取真实崩溃样本。"""
    print(f"\n{'='*60}")
    print(f"[来源 1] 从 syzbot.org 爬取真实崩溃样本")
    print(f"  网站: {SYZBOT_BASE}")
    print(f"  目标数量: {target_count}")
    print(f"{'='*60}")

    # 第一步：获取 open bug 列表页
    print("[步骤 1] 获取 bug 列表...")
    list_html = _fetch_text(f"{SYZBOT_BASE}/upstream")
    if list_html is None:
        print("[INFO] syzbot.org 不可达，跳过此来源")
        return 0

    bugs = _parse_bug_list(list_html)
    print(f"  解析到 {len(bugs)} 个 bug 链接")

    # 同时获取 fixed 列表以增加多样性
    fixed_html = _fetch_text(f"{SYZBOT_BASE}/upstream/fixed")
    fixed_bugs = []
    if fixed_html:
        fixed_bugs = _parse_bug_list(fixed_html)
        print(f"  解析到 {len(fixed_bugs)} 个 fixed bug 链接")

    # 按崩溃类型筛选以保证多样性
    all_bugs = bugs + fixed_bugs
    by_type: dict[str, list[dict]] = {}
    for bug in all_bugs:
        ctype = classify_crash(bug["title"])
        by_type.setdefault(ctype, []).append(bug)

    # 每种类型最多取 N 个
    per_type = max(1, target_count // max(len(by_type), 1))
    selected = []
    for ctype in sorted(by_type.keys()):
        selected.extend(by_type[ctype][:per_type])
        if len(selected) >= target_count:
            break
    selected = selected[:target_count]

    print(f"\n[步骤 2] 逐一爬取 bug 详情页...")
    print(f"  已选 {len(selected)} 个 bug，按类型多样化筛选")

    count = 0
    crash_types = {}
    for i, bug in enumerate(selected):
        extid = bug["extid"]
        title = bug["title"]
        ctype = classify_crash(title)
        print(f"  [{i+1}/{len(selected)}] {title[:60]}...")

        # 获取 bug 详情页
        detail_html = _fetch_text(f"{SYZBOT_BASE}/bug?extid={extid}")
        if detail_html is None:
            print(f"    跳过（详情页获取失败）")
            time.sleep(0.5)
            continue

        detail = _parse_bug_detail(detail_html)

        # 优先下载 /text?tag=CrashReport，其次用页面内嵌的 sample report
        report_body = ""
        if detail["report_url"]:
            report_body = _fetch_text(detail["report_url"]) or ""
        if not report_body and detail["sample_report"]:
            report_body = detail["sample_report"]
        if not report_body:
            report_body = f"[syzbot crash: {title}]\n(报告获取失败)\n"

        # 下载 crash log
        log_body = ""
        if detail["log_url"]:
            log_body = _fetch_text(detail["log_url"]) or ""

        # 下载 machine info
        machine_info = ""
        if detail["machine_info_url"]:
            machine_info = _fetch_text(detail["machine_info_url"]) or ""

        # 补充元信息到 machineInfo
        if not machine_info:
            machine_info = f"Source: syzbot\n"
        machine_info += f"Bug extid: {extid}\n"
        machine_info += f"Crash type: {ctype}\n"
        machine_info += f"URL: {SYZBOT_BASE}/bug?extid={extid}\n"

        # 保存 syz repro（如果存在）
        crash_dir = build_crash_dir(
            output_dir, title, report_body, log_body, machine_info,
            tag=f"syzbot-{extid}",
        )
        if detail["syz_repro_url"]:
            syz_repro = _fetch_text(detail["syz_repro_url"])
            if syz_repro:
                (crash_dir / "repro.syZ").write_text(syz_repro)

        if detail["c_repro_url"]:
            c_repro = _fetch_text(detail["c_repro_url"])
            if c_repro:
                (crash_dir / "repro.c").write_text(c_repro)

        crash_types[ctype] = crash_types.get(ctype, 0) + 1
        count += 1

        time.sleep(0.5)

    print(f"\n[完成] 从 syzbot 爬取 {count} 个样本")
    if crash_types:
        print(f"  崩溃类型分布:")
        for ct, cnt in sorted(crash_types.items(), key=lambda x: -x[1]):
            print(f"    {ct}: {cnt}")

    return count


# ---------------------------------------------------------------------------
#  来源 2: syzkaller 内置测试数据
# ---------------------------------------------------------------------------

def select_diverse_samples(testdata_dir: Path, target_count: int = 50):
    if not testdata_dir.exists():
        print(f"[ERROR] 测试数据目录不存在: {testdata_dir}")
        return []

    all_files = sorted(
        [f for f in testdata_dir.iterdir() if f.is_file()],
        key=lambda f: f.stat().st_size,
        reverse=True,
    )

    by_type: dict[str, list[tuple[Path, dict, str]]] = {}
    skipped = 0
    for fpath in all_files:
        meta, body = parse_syzkaller_report(fpath)
        title = meta.get("title", "")
        if not title or len(body.strip()) < 20:
            skipped += 1
            continue
        ctype = classify_crash(title)
        by_type.setdefault(ctype, []).append((fpath, meta, body))

    if skipped:
        print(f"  跳过 {skipped} 个内容过短的样本")

    per_type = max(3, target_count // max(len(by_type), 1))
    selected = []
    selected_paths = set()

    for ctype in sorted(by_type.keys()):
        for item in by_type[ctype][:per_type]:
            if len(selected) >= target_count:
                break
            selected.append(item)
            selected_paths.add(item[0])
        if len(selected) >= target_count:
            break

    return selected


def fetch_from_testdata(output_dir: Path, target_count: int = 50):
    print(f"\n{'='*60}")
    print(f"[来源 2] 从 syzkaller 内置测试数据提取样本")
    print(f"  数据目录: {SYZKALLER_TESTDATA}")
    print(f"  目标数量: {target_count}")
    print(f"{'='*60}")

    samples = select_diverse_samples(SYZKALLER_TESTDATA, target_count)
    if not samples:
        print("[ERROR] 未找到可用样本")
        return 0

    count = 0
    crash_types = {}
    for fpath, meta, body in samples:
        title = meta["title"]
        ctype = classify_crash(title)
        crash_types[ctype] = crash_types.get(ctype, 0) + 1

        machine_info = f"Source: syzkaller-testdata-{fpath.name}\n"
        machine_info += f"Crash type: {ctype}\n"
        if meta.get("type"):
            machine_info += f"Report type: {meta['type']}\n"

        build_crash_dir(
            output_dir, title, body, body, machine_info,
            tag=f"syzkaller-testdata-{fpath.name}",
        )
        count += 1

    print(f"\n[完成] 共提取 {count} 个样本")
    print(f"  崩溃类型分布:")
    for ct, cnt in sorted(crash_types.items(), key=lambda x: -x[1]):
        print(f"    {ct}: {cnt}")

    return count


# ---------------------------------------------------------------------------
#  来源 0: 本地 workdir
# ---------------------------------------------------------------------------

def fetch_from_local_workdirs(output_dir: Path):
    eval_dir = PROJ_ROOT / "spec-eval" / "debug"
    if not eval_dir.exists():
        print("[INFO] 本地 spec-eval/debug/ 不存在，跳过")
        return 0

    print(f"\n{'='*60}")
    print(f"[来源 0] 从本地 workdir 复制已有崩溃样本")
    print(f"  搜索目录: {eval_dir}")
    print(f"{'='*60}")

    crash_dirs = list(eval_dir.rglob("crashes"))
    count = 0
    for cdir in crash_dirs:
        for sub in cdir.iterdir():
            if not sub.is_dir():
                continue
            desc_file = sub / "description"
            if not desc_file.exists():
                continue
            desc = desc_file.read_text().strip()
            if "suppressed" in desc.lower():
                continue
            if "syz-executor" in desc and "version" in desc:
                continue

            dst = output_dir / "crashes" / sub.name
            if dst.exists():
                continue
            shutil.copytree(sub, dst)
            count += 1

    print(f"[完成] 从本地复制 {count} 个有效崩溃样本")
    return count


# ---------------------------------------------------------------------------
#  Manifest
# ---------------------------------------------------------------------------

def write_manifest(output_dir: Path):
    crashes_dir = output_dir / "crashes"
    if not crashes_dir.exists():
        return

    manifest = []
    for crash_dir in sorted(crashes_dir.iterdir()):
        if not crash_dir.is_dir():
            continue
        entry = {
            "id": crash_dir.name,
            "path": str(crash_dir.relative_to(output_dir)),
        }
        desc_file = crash_dir / "description"
        if desc_file.exists():
            entry["description"] = desc_file.read_text().strip()

        report_file = crash_dir / "report0"
        if report_file.exists():
            report_text = report_file.read_text(errors="replace")
            entry["report_lines"] = len(report_text.splitlines())
            entry["crash_type"] = classify_crash(entry.get("description", ""))

        files = sorted(f.name for f in crash_dir.iterdir() if f.is_file())
        entry["files"] = files
        manifest.append(entry)

    manifest_path = output_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False))
    print(f"\n[INFO] 清单已写入: {manifest_path}")
    print(f"[INFO] 共 {len(manifest)} 条崩溃记录")


# ---------------------------------------------------------------------------
#  Main
# ---------------------------------------------------------------------------

def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="获取 Linux 内核崩溃样本，统一输出为 syzkaller crashes 目录格式"
    )
    parser.add_argument(
        "-o", "--output",
        type=str,
        default=str(PROJ_ROOT / "crash-analysis" / "crash-samples"),
        help="输出目录 (默认: crash-analysis/crash-samples/)",
    )
    parser.add_argument(
        "-n", "--count",
        type=int,
        default=50,
        help="从测试数据中提取的样本数量 (默认: 50)",
    )
    parser.add_argument(
        "--syzbot",
        action="store_true",
        default=False,
        help="从 syzbot.org 爬取真实崩溃报告",
    )
    parser.add_argument(
        "--syzbot-count",
        type=int,
        default=20,
        help="从 syzbot 下载的数量 (默认: 20)",
    )
    parser.add_argument(
        "--include-local",
        action="store_true",
        default=False,
        help="同时复制本地 workdir 中已有的崩溃样本",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        default=False,
        help="启用所有来源（syzbot + 本地 + 测试数据）",
    )

    args = parser.parse_args()
    output_dir = Path(args.output).resolve()

    if args.all:
        args.syzbot = True
        args.include_local = True

    print(f"KernelGPT 崩溃样本获取工具")
    print(f"项目根目录: {PROJ_ROOT}")
    print(f"输出目录:   {output_dir}")

    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "crashes").mkdir(exist_ok=True)

    total = 0

    if args.include_local:
        total += fetch_from_local_workdirs(output_dir)

    if args.syzbot:
        total += fetch_from_syzbot(output_dir, args.syzbot_count)

    total += fetch_from_testdata(output_dir, args.count)

    write_manifest(output_dir)

    print(f"\n{'='*60}")
    print(f"全部完成！共获取 {total} 个崩溃样本")
    print(f"输出目录: {output_dir}")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
