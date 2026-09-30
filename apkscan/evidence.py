from pathlib import Path

from .models import Evidence, Hit, TemplateInfo

CONTEXT_LINES = 2


class SourceCache:
    def __init__(self):
        self._texts: dict[Path, str | None] = {}

    def text(self, path: Path) -> str | None:
        if path not in self._texts:
            try:
                raw = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                raw = None
            self._texts[path] = raw.replace("\r\n", "\n") if raw is not None else None
        return self._texts[path]


def display_path(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def context_lines(lines: list[str], start: int, end: int) -> list[tuple[int, str]]:
    first = max(1, start - CONTEXT_LINES)
    last = min(len(lines), end + CONTEXT_LINES)
    return [(n, lines[n - 1]) for n in range(first, last + 1)]


def locate(root: Path, hit: Hit, template: TemplateInfo, cache: SourceCache) -> list[Evidence]:
    rel = display_path(hit.file, root)
    text = cache.text(hit.file)
    needles = [n.replace("\r\n", "\n") for n in hit.extracted if n.strip()]

    def build(line, end, match, ctx):
        return Evidence(
            file=rel,
            line=line,
            end_line=end,
            match=match,
            template_id=template.id,
            template_name=template.name,
            role=template.role,
            context=ctx,
        )

    if text is None:
        return [build(None, None, n, []) for n in needles] or [build(None, None, "", [])]

    lines = text.split("\n")
    found = []
    for needle in needles:
        pos = text.find(needle)
        while pos != -1:
            line = text.count("\n", 0, pos) + 1
            end = line + needle.count("\n")
            found.append(build(line, end, needle.strip(), context_lines(lines, line, end)))
            pos = text.find(needle, pos + len(needle))
    return found or [build(None, None, "", [])]
