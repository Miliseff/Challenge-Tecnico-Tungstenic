from datetime import datetime
from pathlib import Path

from .evidence import SourceCache, display_path, locate
from .manifest import read_manifest
from .models import AbsenceProof, Evidence, ModuleResult, ModuleSpec, Report, Status
from .paths import walk_files


def count_sources(root: Path, extensions: set[str]) -> int:
    wanted = {"." + e.lstrip(".").lower() for e in extensions}
    return sum(1 for p in walk_files(root) if p.suffix.lower() in wanted)


def sort_key(ev: Evidence):
    return (ev.file, ev.line or 0, ev.template_id)


def build_absence_proof(module: ModuleSpec, root: Path) -> AbsenceProof:
    protection = module.templates_with_role("protection")
    patterns = [p for t in protection for p in t.patterns]
    extensions = {e for t in protection for e in t.extensions}
    manifest = read_manifest(root)
    return AbsenceProof(
        patterns=patterns,
        files_scanned=count_sources(root, extensions),
        components=manifest.activities if manifest else [],
        manifest=display_path(manifest.path, root) if manifest else None,
    )


def evaluate(module: ModuleSpec, evidences: list[Evidence], root: Path) -> ModuleResult:
    if module.mode == "presence":
        if evidences:
            return ModuleResult(module, Status.VULNERABLE, evidences)
        return ModuleResult(module, Status.PASSED, [])

    protection = [e for e in evidences if e.role == "protection"]
    weakening = [e for e in evidences if e.role == "weakening"]
    if not protection:
        return ModuleResult(
            module,
            Status.VULNERABLE,
            weakening,
            absence=build_absence_proof(module, root),
            notes=["no se encontro ninguna referencia a la proteccion esperada"],
        )
    notes = ["la proteccion existe, pero hay que confirmar que cubre todas las pantallas con datos sensibles"]
    if weakening:
        notes.append("hay codigo que quita la proteccion")
        return ModuleResult(module, Status.REVIEW, protection + weakening, notes=notes)
    return ModuleResult(module, Status.PASSED, protection, notes=notes)


def scan(target: Path, modules: list[ModuleSpec], runner) -> Report:
    started = datetime.now().isoformat(timespec="seconds")
    index = {t.id: (m, t) for m in modules for t in m.templates}
    hits = runner.run([m.templates_dir for m in modules], target)

    cache = SourceCache()
    collected: dict[str, dict[tuple, Evidence]] = {m.id: {} for m in modules}
    for hit in hits:
        owner = index.get(hit.template_id)
        if owner is None:
            continue
        module, template = owner
        for ev in locate(target, hit, template, cache):
            collected[module.id][(ev.file, ev.line, ev.template_id, ev.match)] = ev

    results = []
    for module in modules:
        ordered = sorted(collected[module.id].values(), key=sort_key)
        results.append(evaluate(module, ordered, target))
    return Report(target=str(target), source_root=str(target), started_at=started, results=results)
