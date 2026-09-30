import json
import os
import shutil
import subprocess
from pathlib import Path

from .models import Hit


class NucleiError(Exception):
    pass


def find_nuclei(explicit: str | None = None) -> str:
    candidate = explicit or os.environ.get("NUCLEI_BIN") or shutil.which("nuclei")
    if not candidate:
        raise NucleiError(
            "no encontre nuclei. Instalalo, agregalo al PATH o pasalo con --nuclei / NUCLEI_BIN"
        )
    return candidate


def resolve_match_path(raw: str, target: Path) -> Path:
    path = Path(raw)
    if path.is_absolute() and path.exists():
        return path
    for base in (target, target.parent, Path.cwd()):
        joined = base / raw
        if joined.exists():
            return joined
    return path


def parse_jsonl(text: str, target: Path) -> list[Hit]:
    hits = []
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue
        template_id = data.get("template-id")
        where = data.get("matched-at") or data.get("host")
        if not template_id or not where:
            continue
        hits.append(
            Hit(
                template_id=template_id,
                file=resolve_match_path(where, target),
                extracted=[str(x) for x in data.get("extracted-results") or []],
            )
        )
    return hits


class NucleiRunner:
    def __init__(self, binary: str | None = None, timeout: int = 900):
        self.binary = binary
        self.timeout = timeout

    def command(self, template_dirs: list[Path], target: Path) -> list[str]:
        cmd = [find_nuclei(self.binary)]
        for folder in template_dirs:
            cmd += ["-t", str(folder)]
        cmd += ["-target", str(target), "-file", "-jsonl", "-omit-template", "-silent", "-duc", "-nc"]
        return cmd

    def run(self, template_dirs: list[Path], target: Path) -> list[Hit]:
        if not template_dirs:
            return []
        try:
            proc = subprocess.run(
                self.command(template_dirs, target),
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=self.timeout,
            )
        except subprocess.TimeoutExpired:
            raise NucleiError(f"nuclei excedio el timeout de {self.timeout}s")
        if proc.returncode != 0:
            raise NucleiError(f"nuclei termino con codigo {proc.returncode}:\n{proc.stderr.strip()}")
        return parse_jsonl(proc.stdout, target)
