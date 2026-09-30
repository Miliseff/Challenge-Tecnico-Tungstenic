from pathlib import Path

import yaml

from .models import ModuleSpec, TemplateInfo

BUILTIN_DIR = Path(__file__).parent / "modules"
REQUIRED_FIELDS = ("id", "title", "maswe", "severity", "mode", "description", "impact", "mitigation")
MODES = ("presence", "absence")
ROLE_PREFIX = "role-"


class RegistryError(Exception):
    pass


def role_from_tags(tags) -> str:
    if isinstance(tags, str):
        tags = [t.strip() for t in tags.split(",")]
    for tag in tags or []:
        if tag.startswith(ROLE_PREFIX):
            return tag[len(ROLE_PREFIX):]
    return "indicator"


def load_template(path: Path) -> TemplateInfo:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or "id" not in data:
        raise RegistryError(f"template invalido: {path}")
    info = data.get("info") or {}
    patterns, extensions = [], []
    for block in data.get("file") or []:
        for ext in block.get("extensions") or []:
            if ext not in extensions:
                extensions.append(ext)
        for matcher in block.get("matchers") or []:
            if matcher.get("type") == "regex":
                patterns.extend(matcher.get("regex") or [])
    return TemplateInfo(
        id=data["id"],
        name=info.get("name", data["id"]),
        role=role_from_tags(info.get("tags")),
        patterns=patterns,
        extensions=extensions,
        path=path,
    )


def load_module(folder: Path) -> ModuleSpec | None:
    manifest = folder / "module.yaml"
    if not manifest.is_file():
        return None
    data = yaml.safe_load(manifest.read_text(encoding="utf-8")) or {}
    if data.get("enabled", True) is False:
        return None
    missing = [f for f in REQUIRED_FIELDS if not data.get(f)]
    if missing:
        raise RegistryError(f"{manifest}: faltan campos {', '.join(missing)}")
    if data["mode"] not in MODES:
        raise RegistryError(f"{manifest}: mode debe ser uno de {', '.join(MODES)}")
    spec = ModuleSpec(
        id=data["id"],
        title=data["title"],
        maswe=data["maswe"],
        masvs=data.get("masvs", ""),
        severity=data["severity"],
        mode=data["mode"],
        description=data["description"].strip(),
        impact=data["impact"].strip(),
        mitigation=data["mitigation"].strip(),
        validation=(data.get("validation") or "").strip(),
        references=data.get("references") or [],
        path=folder,
    )
    if not spec.templates_dir.is_dir():
        raise RegistryError(f"{folder}: no tiene carpeta templates/")
    spec.templates = [load_template(p) for p in sorted(spec.templates_dir.glob("*.y*ml"))]
    if not spec.templates:
        raise RegistryError(f"{folder}: templates/ esta vacia")
    if spec.mode == "absence" and not spec.templates_with_role("protection"):
        raise RegistryError(f"{folder}: un modulo de ausencia necesita al menos un template role-protection")
    return spec


def discover(extra_dirs: list[Path] | None = None) -> list[ModuleSpec]:
    roots = [BUILTIN_DIR] + list(extra_dirs or [])
    modules: dict[str, ModuleSpec] = {}
    template_ids: dict[str, str] = {}
    for root in roots:
        if not root.is_dir():
            raise RegistryError(f"no existe el directorio de modulos: {root}")
        for folder in sorted(p for p in root.iterdir() if p.is_dir()):
            spec = load_module(folder)
            if spec is None:
                continue
            if spec.id in modules:
                raise RegistryError(f"modulo duplicado: {spec.id}")
            for tpl in spec.templates:
                if tpl.id in template_ids:
                    raise RegistryError(f"template duplicado: {tpl.id} ({spec.id} y {template_ids[tpl.id]})")
                template_ids[tpl.id] = spec.id
            modules[spec.id] = spec
    return sorted(modules.values(), key=lambda m: m.id)


def normalize_id(value: str) -> str:
    value = value.strip().upper()
    if value.isdigit():
        return f"MASTG-TEST-{value.zfill(4)}"
    return value


def select(modules: list[ModuleSpec], only: list[str] | None, skip: list[str] | None) -> list[ModuleSpec]:
    known = {m.id for m in modules}
    only_ids = {normalize_id(v) for v in only or []}
    skip_ids = {normalize_id(v) for v in skip or []}
    unknown = (only_ids | skip_ids) - known
    if unknown:
        raise RegistryError(f"modulos desconocidos: {', '.join(sorted(unknown))}")
    chosen = [m for m in modules if not only_ids or m.id in only_ids]
    return [m for m in chosen if m.id not in skip_ids]
