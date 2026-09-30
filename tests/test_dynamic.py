import json
import random
import struct
import unittest
import zlib
from types import SimpleNamespace

from apkscan import dynamic
from apkscan.dynamic import png
from apkscan.dynamic.adb import Adb, AdbError
from apkscan.dynamic.screen_capture import (
    ScreenCaptureProbe,
    flags_include_secure,
    parse_focus,
    window_has_secure,
)
from apkscan.engine import scan
from apkscan.models import DynamicObservation, Status
from apkscan.registry import discover, select
from apkscan.reporters import console, jsonout, markdown

from .nuclei_sim import SimulatedNuclei
from .test_scan import FIXTURES

FOCUS = "1a2b3c u0 com.example.vault/com.example.vault.LoginActivity"


def make_dump(flags: str, focus: str = FOCUS) -> str:
    return (
        f"  mCurrentFocus=Window{{{focus}}}\n"
        f"  Window #3 Window{{{focus}}}:\n"
        "    mDisplayId=0 stackId=1 mSession=Session{x}\n"
        f"    mAttrs=WM.LayoutParams{{(0,0)(fillxfill) sim={{adjust=resize}} ty=BASE_APPLICATION fl={flags} pfl=0x10 fmt=TRANSLUCENT}}\n"
        "  Window #4 Window{ffff u0 StatusBar}:\n"
        "    mAttrs=WM.LayoutParams{ty=STATUS_BAR fl=NOT_FOCUSABLE}\n"
    )


def encode_png(pixels, width, height, bpp, filter_kind):
    raw = bytearray()
    prev = bytearray(width * bpp)
    for y in range(height):
        row = bytearray(pixels[y * width * bpp : (y + 1) * width * bpp])
        out = bytearray()
        for i, value in enumerate(row):
            left = row[i - bpp] if i >= bpp else 0
            up = prev[i]
            upleft = prev[i - bpp] if i >= bpp else 0
            if filter_kind == 0:
                predicted = 0
            elif filter_kind == 1:
                predicted = left
            elif filter_kind == 2:
                predicted = up
            elif filter_kind == 3:
                predicted = (left + up) >> 1
            else:
                predicted = png.paeth(left, up, upleft)
            out.append((value - predicted) & 255)
        raw += bytes([filter_kind]) + out
        prev = row

    def chunk(kind, body):
        crc = zlib.crc32(kind + body) & 0xFFFFFFFF
        return struct.pack(">I", len(body)) + kind + body + struct.pack(">I", crc)

    color = 2 if bpp == 3 else 6
    header = struct.pack(">IIBBBBB", width, height, 8, color, 0, 0, 0)
    return png.SIGNATURE + chunk(b"IHDR", header) + chunk(b"IDAT", zlib.compress(bytes(raw))) + chunk(b"IEND", b"")


class PngDecoding(unittest.TestCase):
    def test_all_filters_roundtrip(self):
        rng = random.Random(7)
        width, height, bpp = 9, 6, 4
        pixels = bytes(rng.randrange(256) for _ in range(width * height * bpp))
        for kind in range(5):
            data = encode_png(pixels, width, height, bpp, kind)
            decoded = b"".join(bytes(row) for row, _ in png.rows(data))
            self.assertEqual(decoded, pixels, f"filtro {kind}")

    def test_black_image(self):
        pixels = bytes([0, 0, 0, 255] * 20 * 10)
        self.assertTrue(png.is_black(encode_png(pixels, 20, 10, 4, 0)))
        self.assertTrue(png.is_black(encode_png(pixels, 20, 10, 4, 4)))

    def test_image_with_content(self):
        pixels = bytearray([0, 0, 0, 255] * 20 * 10)
        pixels[4 * 57 + 1] = 120
        self.assertFalse(png.is_black(encode_png(bytes(pixels), 20, 10, 4, 1)))

    def test_rgb_image(self):
        self.assertTrue(png.is_black(encode_png(bytes(12 * 3 * 3), 12, 3, 3, 2)))

    def test_garbage_returns_none(self):
        self.assertIsNone(png.is_black(b"no es un png"))
        self.assertIsNone(png.is_black(png.SIGNATURE + b"\x00\x00"))


class WindowParsing(unittest.TestCase):
    def test_focus(self):
        self.assertEqual(parse_focus(make_dump("SECURE")), FOCUS)
        self.assertIsNone(parse_focus("nada"))

    def test_named_flags(self):
        self.assertTrue(flags_include_secure("DIM_BEHIND SECURE"))
        self.assertFalse(flags_include_secure("DIM_BEHIND LAYOUT_IN_SCREEN"))

    def test_hex_flags(self):
        self.assertTrue(flags_include_secure("81812100"))
        self.assertFalse(flags_include_secure("81810100"))
        self.assertTrue(flags_include_secure("#2000"))

    def test_window_flags_are_read_from_the_focused_window_only(self):
        self.assertTrue(window_has_secure(make_dump("DIM_BEHIND SECURE"), FOCUS))
        self.assertFalse(window_has_secure(make_dump("DIM_BEHIND"), FOCUS))
        self.assertIsNone(window_has_secure(make_dump("SECURE"), "otra cosa"))


class FakeDevice:
    def __init__(self, screens):
        self.screens = screens
        self.current = None
        self.calls = []

    def __call__(self, cmd, capture_output=True, timeout=None):
        args = cmd[1:]
        self.calls.append(args)
        if args[:3] == ["shell", "am", "start"]:
            component = args[-1]
            name = component.split("/")[1]
            if name not in self.screens:
                return self.reply("Error type 3\nError: Activity class {} does not exist.")
            self.current = name
            return self.reply("Status: ok\nActivity: " + component)
        if args[:3] == ["shell", "dumpsys", "window"]:
            flags = self.screens[self.current]["flags"]
            return self.reply(make_dump(flags, FOCUS.replace("com.example.vault.LoginActivity", self.current)))
        if args[:2] == ["exec-out", "screencap"]:
            return self.reply(self.screens[self.current]["png"])
        if args[:1] == ["devices"]:
            return self.reply("List of devices attached\nemulator-5554\tdevice\n")
        return self.reply("")

    @staticmethod
    def reply(out, code=0):
        data = out if isinstance(out, bytes) else out.encode()
        return SimpleNamespace(returncode=code, stdout=data, stderr=b"")


BLACK = encode_png(bytes([0, 0, 0, 255] * 8 * 8), 8, 8, 4, 0)
CONTENT = encode_png(bytes([30, 90, 200, 255] * 8 * 8), 8, 8, 4, 0)


class Probe(unittest.TestCase):
    def run_probe(self, screens, names):
        device = FakeDevice(screens)
        adb = Adb(runner=device)
        return ScreenCaptureProbe().run(adb, "com.example.vault", names, 0, lambda _s: None)

    def test_protected_unprotected_and_unstartable(self):
        screens = {
            "com.example.vault.LoginActivity": {"flags": "DIM_BEHIND SECURE", "png": BLACK},
            "com.example.vault.BalanceActivity": {"flags": "DIM_BEHIND", "png": CONTENT},
        }
        names = list(screens) + ["com.example.vault.Missing"]
        obs = {o.target.split(".")[-1]: o for o in self.run_probe(screens, names)}
        self.assertEqual(obs["LoginActivity"].verdict, "protected")
        self.assertIn("negro", obs["LoginActivity"].detail)
        self.assertEqual(obs["BalanceActivity"].verdict, "unprotected")
        self.assertEqual(obs["Missing"].verdict, "skipped")

    def test_adb_failure_becomes_error(self):
        adb = Adb(runner=lambda cmd, capture_output=True, timeout=None: SimpleNamespace(returncode=1, stdout=b"", stderr=b"boom"))
        with self.assertRaises(AdbError):
            adb.devices()

    def test_devices(self):
        self.assertEqual(Adb(runner=FakeDevice({})).devices(), ["emulator-5554"])


class Integration(unittest.TestCase):
    def report(self, fixture):
        return scan(FIXTURES / fixture, select(discover(), ["0291"], None), SimulatedNuclei())

    def observe(self, verdicts):
        return [DynamicObservation(f"a{i}", v, "d") for i, v in enumerate(verdicts)]

    def test_unprotected_screens_downgrade_a_static_pass(self):
        report = self.report("screen_protected")
        self.assertIs(report.results[0].status, Status.PASSED)
        dynamic.apply(report.results[0], self.observe(["protected", "unprotected"]))
        self.assertIs(report.results[0].status, Status.REVIEW)

    def test_runtime_protection_softens_static_absence(self):
        report = self.report("screen_unprotected")
        dynamic.apply(report.results[0], self.observe(["protected", "skipped"]))
        self.assertIs(report.results[0].status, Status.REVIEW)

    def test_static_absence_is_confirmed(self):
        report = self.report("screen_unprotected")
        dynamic.apply(report.results[0], self.observe(["unprotected"]))
        self.assertIs(report.results[0].status, Status.VULNERABLE)

    def test_reporters_include_dynamic_section(self):
        report = self.report("screen_unprotected")
        dynamic.apply(report.results[0], self.observe(["unprotected", "skipped"]))
        self.assertIn("Prueba dinamica (2 activities)", console.render(report))
        self.assertIn("### Prueba dinamica", markdown.render(report))
        self.assertEqual(len(json.loads(jsonout.render(report))["results"][0]["dynamic"]), 2)


if __name__ == "__main__":
    unittest.main()
