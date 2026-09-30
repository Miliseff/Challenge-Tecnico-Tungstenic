from ..models import AbsenceProof, Evidence, ModuleResult, Report, Status

SEVERITY_LABEL = {
    "critical": "Critica",
    "high": "Alta",
    "medium": "Media",
    "low": "Baja",
    "info": "Informativa",
}

ROLE_LABEL = {
    "indicator": "uso inseguro",
    "protection": "proteccion aplicada",
    "weakening": "proteccion removida",
}


DYNAMIC_LABEL = {
    "protected": "protegida",
    "unprotected": "SIN proteccion",
    "skipped": "omitida",
}


def status_label(result: ModuleResult) -> str:
    if result.status is Status.VULNERABLE:
        return "VULNERABLE"
    if result.status is Status.REVIEW:
        return "REVISAR"
    if result.module.mode == "absence":
        return "PROTEGIDO"
    return "SIN HALLAZGOS"


def severity_label(result: ModuleResult) -> str:
    return SEVERITY_LABEL.get(result.module.severity, result.module.severity)


def evidence_location(ev: Evidence) -> str:
    if ev.line is None:
        return ev.file
    if ev.end_line and ev.end_line != ev.line:
        return f"{ev.file}:{ev.line}-{ev.end_line}"
    return f"{ev.file}:{ev.line}"


def in_match(ev: Evidence, number: int) -> bool:
    if ev.line is None:
        return False
    return ev.line <= number <= (ev.end_line or ev.line)


def counts(report: Report) -> dict[Status, int]:
    totals = {s: 0 for s in Status}
    for r in report.results:
        totals[r.status] += 1
    return totals


def absence_summary(proof: AbsenceProof) -> list[str]:
    lines = [
        f"Archivos de codigo analizados: {proof.files_scanned}",
        "Coincidencias con la API de proteccion: 0",
    ]
    if proof.manifest:
        lines.append(f"Activities declaradas en {proof.manifest}: {len(proof.components)}")
    else:
        lines.append("No se encontro AndroidManifest.xml en el directorio analizado")
    return lines
