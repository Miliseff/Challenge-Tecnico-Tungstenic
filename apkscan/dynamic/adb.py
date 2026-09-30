import os
import shutil
import subprocess
from pathlib import Path


class AdbError(Exception):
    pass


def find_adb(explicit: str | None = None) -> str:
    candidate = explicit or os.environ.get("ADB_BIN") or shutil.which("adb")
    if not candidate:
        sdk = os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT")
        if sdk:
            for name in ("adb.exe", "adb"):
                path = Path(sdk) / "platform-tools" / name
                if path.exists():
                    candidate = str(path)
                    break
    if not candidate:
        raise AdbError("no encontre adb. Instala platform-tools, agregalo al PATH o usa --adb / ADB_BIN")
    return candidate


class Adb:
    def __init__(self, binary: str | None = None, serial: str | None = None, runner=None):
        self._run = runner or subprocess.run
        self.binary = (binary or "adb") if runner else find_adb(binary)
        self.serial = serial

    def command(self, *args: str) -> list[str]:
        base = [self.binary]
        if self.serial:
            base += ["-s", self.serial]
        return base + list(args)

    def raw(self, *args: str, timeout: int = 90) -> bytes:
        try:
            proc = self._run(self.command(*args), capture_output=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            raise AdbError(f"adb {' '.join(args)} excedio {timeout}s")
        if proc.returncode != 0:
            err = proc.stderr.decode("utf-8", "replace").strip() if proc.stderr else ""
            raise AdbError(f"adb {' '.join(args)} fallo ({proc.returncode}): {err}")
        return proc.stdout

    def text(self, *args: str, timeout: int = 90) -> str:
        return self.raw(*args, timeout=timeout).decode("utf-8", "replace")

    def devices(self) -> list[str]:
        lines = self.text("devices").splitlines()[1:]
        return [l.split()[0] for l in lines if l.strip().endswith("device")]

    def install(self, apk: Path) -> None:
        self.raw("install", "-r", str(apk), timeout=300)

    def start_activity(self, component: str) -> str:
        return self.text("shell", "am", "start", "-W", "-n", component)

    def window_dump(self) -> str:
        return self.text("shell", "dumpsys", "window")

    def screencap(self) -> bytes:
        return self.raw("exec-out", "screencap", "-p")

    def force_stop(self, package: str) -> None:
        self.raw("shell", "am", "force-stop", package)
