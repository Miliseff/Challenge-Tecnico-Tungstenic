from ..models import ModuleResult, Report, Status
from .screen_capture import ScreenCaptureProbe

PROBES = {probe.module_id: probe for probe in (ScreenCaptureProbe(),)}


def supported_ids(report: Report) -> list[str]:
    return [r.module.id for r in report.results if r.module.id in PROBES]


def apply(result: ModuleResult, observations) -> None:
    result.dynamic = observations
    verdicts = {o.verdict for o in observations}
    if "unprotected" in verdicts and result.status is Status.PASSED:
        result.status = Status.REVIEW
        result.notes.append("la prueba dinamica encontro pantallas sin proteccion aunque el codigo referencia la API")
    if "protected" in verdicts and "unprotected" not in verdicts and result.status is Status.VULNERABLE:
        result.status = Status.REVIEW
        result.notes.append("la prueba dinamica observo proteccion en runtime que el analisis estatico no vio")


def run(report: Report, adb, package: str, activities: list[str], settle: float) -> None:
    for result in report.results:
        probe = PROBES.get(result.module.id)
        if probe is not None:
            apply(result, probe.run(adb, package, activities, settle))
