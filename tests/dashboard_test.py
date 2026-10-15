#!/usr/bin/env python3
"""Optional real-browser checks. Uses file:// and an offline Chromium context."""
from __future__ import annotations

import argparse
import json
import struct
import subprocess
import tempfile
from pathlib import Path

from playwright.sync_api import expect, sync_playwright


def analyze(executable: Path, source: Path, output: Path) -> Path:
    subprocess.run([str(executable), "analyze", str(source), "--output", str(output)], check=True, capture_output=True)
    return output / "index.html"


def attack_capture(baseline: bytes) -> bytes:
    # Replace the first synthetic packet's DNS question with hostile display text.
    label = b"</script><script>alert(1)</script>"
    question = bytes([len(label)]) + label + b"\x04test\x00\x00\x01\x00\x01"
    dns = bytearray(12)
    struct.pack_into("!HHH", dns, 0, 1, 256, 1)
    frame = bytearray(baseline[40:40 + 42]) + dns + question
    struct.pack_into("!H", frame, 16, len(frame) - 14)
    struct.pack_into("!H", frame, 38, len(frame) - 34)
    return baseline[:24] + struct.pack("<IIII", 1767225600, 0, len(frame), len(frame)) + frame


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--executable", type=Path, required=True)
    parser.add_argument("--screenshots", type=Path, help="Optional screenshot directory")
    parser.add_argument("--large-report", type=Path, help="Optional existing HTML report for a larger-data check")
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[1]
    executable = args.executable.resolve()
    with tempfile.TemporaryDirectory(prefix="tracetrust-browser-") as temporary, sync_playwright() as runtime:
        root = Path(temporary)
        investigation = analyze(executable, repo / "examples/captures/investigation.pcap", root / "investigation")
        empty = analyze(executable, repo / "examples/captures/empty.pcap", root / "empty")
        attack = root / "hostile-string.pcap"
        attack.write_bytes(attack_capture((repo / "examples/captures/baseline.pcap").read_bytes()))
        hostile = analyze(executable, attack, root / "hostile")
        baseline = (repo / "examples/captures/baseline.pcap").read_bytes()
        length = struct.unpack_from("<I", baseline, 32)[0]
        large_capture = root / "many-frames.pcap"
        large_capture.write_bytes(baseline[:24] + baseline[24:40 + length] * 5000)
        many = analyze(executable, large_capture, root / "many")
        browser = runtime.chromium.launch()
        context = browser.new_context(offline=True, viewport={"width": 1440, "height": 1040}, reduced_motion="reduce")
        page = context.new_page()
        errors, requests, dialogs = [], [], []
        page.on("pageerror", lambda error: errors.append(str(error)))
        page.on("request", lambda request: requests.append(request.url) if request.url.startswith(("http:", "https:")) else None)
        page.on("dialog", lambda dialog: (dialogs.append(dialog.message), dialog.dismiss()))
        page.goto(investigation.as_uri())
        expect(page.locator("#metric-packets")).to_have_text("205")
        expect(page.locator("#metric-flows")).to_have_text("52")
        expect(page.locator("#metric-findings")).to_have_text("4")
        expect(page.locator(".finding")).to_have_count(4)
        embedded = page.locator("#report-data").text_content()
        assert json.loads(embedded) == json.loads(investigation.with_name("report.json").read_text())
        if args.screenshots:
            args.screenshots.mkdir(parents=True, exist_ok=True)
            page.screenshot(path=str(args.screenshots / "dashboard-desktop.png"))
            page.locator("#findings").scroll_into_view_if_needed()
            page.locator("#findings").screenshot(path=str(args.screenshots / "findings.png"))
        page.select_option("#finding-priority", "medium")
        expect(page.locator(".finding")).to_have_count(2)
        page.select_option("#finding-rule", "TT-D")
        expect(page.locator(".finding")).to_have_count(0)
        page.select_option("#finding-priority", "")
        expect(page.locator(".finding")).to_have_count(1)
        page.locator(".finding button").click()
        expect(page.locator("#packet-page-label")).to_have_text("1–30 of 30")
        page.locator("#packet-rows button").first.click()
        expect(page.locator("#inspector")).to_be_visible()
        expect(page.locator("#inspector-title")).to_contain_text("Frame 176")
        page.keyboard.press("Escape")
        expect(page.locator("#inspector")).not_to_be_visible()
        page.locator("#timeline g[role=button]").nth(7).click()
        expect(page.locator("#packet-page-label")).to_have_text("1–40 of 140")
        page.locator("#packet-next").click()
        expect(page.locator("#packet-page-label")).to_have_text("41–80 of 140")
        page.locator("#chart-bytes").click()
        expect(page.locator("#chart-bytes")).to_have_attribute("aria-pressed", "true")
        page.locator('#topology circle[aria-label="Filter conversations for 203.0.113.99"]').click()
        expect(page.locator("#flow-count")).to_have_text("1 of 52 conversations")
        page.locator("#flow-rows button").click()
        expect(page.locator("#packet-page-label")).to_have_text("1–40 of 140")
        page.locator("#clear-host").click()
        page.locator("#flow-search").fill("does-not-exist")
        expect(page.locator("#flow-count")).to_have_text("0 of 52 conversations")
        page.locator("#flow-search").fill("")
        page.locator("#reset-evidence").click()
        page.locator("#packet-search").fill("q29.demo.test")
        expect(page.locator("#packet-page-label")).to_have_text("1–1 of 1")
        with page.expect_download() as download:
            page.locator("#download-json").click()
        assert download.value.suggested_filename == "tracetrust-report.json"
        page.set_viewport_size({"width": 390, "height": 844})
        page.goto(investigation.as_uri())
        assert page.evaluate("document.documentElement.scrollWidth <= innerWidth"), "Mobile page overflows horizontally"
        if args.screenshots:
            page.screenshot(path=str(args.screenshots / "dashboard-mobile.png"), full_page=True)
        page.goto(empty.as_uri())
        expect(page.locator("#metric-packets")).to_have_text("0")
        expect(page.locator("#packet-page-label")).to_have_text("0–0 of 0")
        page.goto(hostile.as_uri())
        expect(page.locator("#packet-rows")).to_contain_text("</script><script>alert(1)</script>.test")
        page.goto(many.as_uri())
        expect(page.locator("#metric-packets")).to_have_text("5,000")
        expect(page.locator("#packet-rows tr")).to_have_count(40)
        page.locator("#packet-search").fill("5000")
        expect(page.locator("#packet-page-label")).to_have_text("1–1 of 1")
        if args.large_report:
            page.goto(args.large_report.resolve().as_uri(), timeout=60000)
            expected = json.loads(args.large_report.with_name("report.json").read_text())
            expect(page.locator("#metric-packets")).to_have_text(f'{expected["summary"]["packets"]:,}')
            expect(page.locator("#packet-rows tr")).to_have_count(min(40, expected["summary"]["packets"]))
        assert not errors, errors
        assert not dialogs, dialogs
        assert not requests, requests
        print(f"Dashboard checks passed in Chromium {browser.version}: data, filters, evidence, pagination, export, mobile, empty capture, injection and offline operation.")
        browser.close()


if __name__ == "__main__":
    main()
