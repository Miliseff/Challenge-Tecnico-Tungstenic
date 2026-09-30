import os
import shutil
import subprocess
from pathlib import Path

from .paths import native


class DecompileError(Exception):
    pass


def is_apk(path: Path) -> bool:
    return path.is_file() and path.suffix.lower() == ".apk"


def find_jadx(explicit: str | None = None) -> str:
    candidate = explicit or os.environ.get("JADX_BIN") or shutil.which("jadx")
    if not candidate:
        raise DecompileError(
            "no encontre jadx. Instalalo, agregalo al PATH o pasalo con --jadx / JADX_BIN"
        )
    return candidate


def decompile(apk: Path, workdir: Path, jadx: str | None = None, force: bool = False) -> Path:
    out = workdir / apk.stem
    if out.exists() and any(out.iterdir()) and not force:
        return out
    binary = find_jadx(jadx)
    if out.exists():
        shutil.rmtree(native(out))
    out.mkdir(parents=True)
    proc = subprocess.run(
        [binary, "-d", str(out), str(apk)],
        capture_output=True,
        text=True,
        errors="replace",
    )
    if not (out / "sources").is_dir():
        tail = "\n".join((proc.stdout + proc.stderr).strip().splitlines()[-15:])
        raise DecompileError(f"jadx no genero codigo fuente (codigo {proc.returncode}):\n{tail}")
    return out
