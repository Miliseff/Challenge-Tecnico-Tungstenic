import re
from pathlib import Path

import yaml

from apkscan.models import Hit


def block_matches(block: dict, text: str) -> bool:
    results = []
    for matcher in block.get("matchers", []):
        results.append(any(re.search(rx, text) for rx in matcher.get("regex", [])))
    if not results:
        return False
    if block.get("matchers-condition", "or") == "and":
        return all(results)
    return any(results)


class SimulatedNuclei:
    def run(self, template_dirs, target: Path):
        hits = []
        for folder in template_dirs:
            for path in sorted(folder.glob("*.y*ml")):
                data = yaml.safe_load(path.read_text(encoding="utf-8"))
                for block in data.get("file", []):
                    suffixes = {"." + e for e in block["extensions"]}
                    for source in sorted(target.rglob("*")):
                        if not source.is_file() or source.suffix not in suffixes:
                            continue
                        text = source.read_text(encoding="utf-8")
                        if not block_matches(block, text):
                            continue
                        extracted = []
                        for extractor in block.get("extractors", []):
                            for rx in extractor["regex"]:
                                extracted += [m.group(0) for m in re.finditer(rx, text)]
                        hits.append(Hit(data["id"], source, list(dict.fromkeys(extracted))))
        return hits
