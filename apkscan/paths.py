import os
from pathlib import Path

LONG_PREFIX = "\\\\?\\"


def native(path: Path) -> str:
    text = str(Path(path).resolve())
    if os.name == "nt" and not text.startswith(LONG_PREFIX):
        return LONG_PREFIX + text
    return text


def plain(text: str) -> Path:
    return Path(text[len(LONG_PREFIX):] if text.startswith(LONG_PREFIX) else text)


def walk_files(root: Path):
    for folder, _, files in os.walk(native(root)):
        for name in files:
            yield plain(folder) / name
