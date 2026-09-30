import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

ANDROID_NAME = "{http://schemas.android.com/apk/res/android}name"


@dataclass
class ManifestInfo:
    path: Path
    package: str
    activities: list[str] = field(default_factory=list)


def find_manifest(root: Path) -> Path | None:
    candidates = sorted(root.rglob("AndroidManifest.xml"), key=lambda p: len(p.parts))
    return candidates[0] if candidates else None


def read_manifest(root: Path) -> ManifestInfo | None:
    path = find_manifest(root)
    if path is None:
        return None
    try:
        tree = ET.parse(path)
    except ET.ParseError:
        return None
    app = tree.getroot()
    package = app.get("package", "")
    names = []
    for node in app.iter("activity"):
        name = node.get(ANDROID_NAME)
        if not name:
            continue
        if name.startswith(".") and package:
            name = package + name
        names.append(name)
    return ManifestInfo(path=path, package=package, activities=names)
