import re
import time

from ..models import DynamicObservation
from . import png
from .adb import Adb, AdbError

FLAG_SECURE = 0x2000
START_ERRORS = ("Error", "Exception", "Permission Denial", "does not exist")


def parse_focus(dump: str) -> str | None:
    match = re.search(r"mCurrentFocus=Window\{([^}]*)\}", dump)
    return match.group(1) if match else None


def flags_include_secure(text: str) -> bool:
    text = text.strip()
    if re.search(r"\bSECURE\b", text):
        return True
    match = re.match(r"#?([0-9a-fA-F]+)\b", text)
    if match:
        return bool(int(match.group(1), 16) & FLAG_SECURE)
    return False


def window_has_secure(dump: str, focus: str) -> bool | None:
    lines = dump.splitlines()
    for i, line in enumerate(lines):
        if focus in line and "Window #" in line:
            for follow in lines[i + 1 : i + 40]:
                match = re.search(r"\bfl=(.*?)(?=\s+\w+=|\}|$)", follow)
                if match:
                    return flags_include_secure(match.group(1))
            return None
    return None


def start_failed(output: str) -> bool:
    return any(token in output for token in START_ERRORS)


class ScreenCaptureProbe:
    module_id = "MASTG-TEST-0291"

    def observe(self, adb: Adb, package: str, name: str, settle: float, sleep) -> DynamicObservation:
        component = f"{package}/{name}"
        try:
            output = adb.start_activity(component)
        except AdbError as exc:
            return DynamicObservation(name, "skipped", str(exc))
        if start_failed(output):
            first = next((l.strip() for l in output.splitlines() if start_failed(l)), "no se pudo iniciar")
            return DynamicObservation(name, "skipped", first)
        sleep(settle)
        dump = adb.window_dump()
        focus = parse_focus(dump)
        if focus is None or name not in focus:
            return DynamicObservation(name, "skipped", f"otra ventana tiene el foco: {focus}")
        secure = window_has_secure(dump, focus)
        blank = png.is_black(adb.screencap())
        if secure is None:
            return DynamicObservation(name, "skipped", "no se pudieron leer las flags de la ventana")
        shot = {True: "captura en negro", False: "captura con contenido", None: "captura ilegible"}[blank]
        if secure:
            return DynamicObservation(name, "protected", f"la ventana tiene FLAG_SECURE; {shot}")
        return DynamicObservation(name, "unprotected", f"la ventana no tiene FLAG_SECURE; {shot}")

    def run(self, adb: Adb, package: str, activities: list[str], settle: float = 2.0, sleep=time.sleep):
        observations = []
        for name in activities:
            observations.append(self.observe(adb, package, name, settle, sleep))
        try:
            adb.force_stop(package)
        except AdbError:
            pass
        return observations
