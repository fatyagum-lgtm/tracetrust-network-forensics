#!/usr/bin/env python3
"""Black-box checks against committed synthetic fixtures; standard library only."""
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path


def run(executable, *args, code=0):
    result = subprocess.run([str(executable), *map(str, args)], capture_output=True, text=True, timeout=30)
    assert result.returncode == code, (args, result.returncode, result.stdout, result.stderr)
    return result


def main():
    executable, repo = (Path(value).resolve() for value in sys.argv[1:3])
    fixtures = repo / "examples/captures"
    expectations = json.loads((repo / "examples/expectations.json").read_text())
    with tempfile.TemporaryDirectory(prefix="tracetrust-cli-") as directory:
        root = Path(directory)
        for name in ["baseline.pcap", "investigation.pcap"]:
            source, output = fixtures / name, root / name
            digest = hashlib.sha256(source.read_bytes()).hexdigest()
            run(executable, "analyze", source, "--output", output)
            report = json.loads((output / "report.json").read_text())
            expected = expectations[name]
            for key in ["packets", "flows", "findings", "dns_packets"]:
                assert report["summary"][key] == expected[key], (key, report["summary"])
            assert {p["protocol"]: p["packets"] for p in report["protocols"]} == expected["protocol_packets"]
            assert report["capture"]["sha256"] == digest
            assert report["capture"]["filename"] == name
            assert hashlib.sha256(source.read_bytes()).hexdigest() == digest
            assert str(repo) not in (output / "report.json").read_text()
            frames = {p["frame"] for p in report["packets"]}
            flows = {f["id"] for f in report["flows"]}
            assert sum(f["packets"] for f in report["flows"]) == expected["packets"]
            for finding in report["findings"]:
                assert finding["evidence_total"] == expected["rule_packet_counts"][finding["rule"]]
                assert set(finding["frames"]) <= frames
                assert set(finding["flows"]) <= flows
            assert (output / "index.html").is_file()
            run(executable, "analyze", source, "--output", output, code=2)
        run(executable, "analyze", fixtures / "empty.pcap", "--output", root / "empty", "--json-only")
        assert not (root / "empty/index.html").exists()
        run(executable, "analyze", fixtures / "damaged-tail.pcap", "--output", root / "damaged", code=3)
        run(executable, "analyze", fixtures / "unsupported.pcapng", "--output", root / "invalid", code=2)
        assert not (root / "invalid").exists()
        run(executable, "analyze", fixtures / "investigation.pcap", "--output", root / "limited", "--max-packets", "10", code=3)
        run(executable, "analyze", fixtures / "big-endian-nanoseconds.pcap", "--output", root / "nano")
        nano = json.loads((root / "nano/report.json").read_text())
        assert nano["packets"][0]["timestamp_utc"].endswith("000000123Z")
        config = root / "config.json"
        config.write_text('{"scan_ports": 20, "syn_count": 20, "burst_packets": 200, "dns_count": 50}')
        run(executable, "analyze", fixtures / "investigation.pcap", "--output", root / "configured", "--scan-ports", "12", "--config", config)
        configured = json.loads((root / "configured/report.json").read_text())
        assert [f["rule"] for f in configured["findings"]] == ["TT-A"]
        run(executable, "analyze", fixtures / "baseline.pcap", "--output", root / "bad", "--unknown", "1", code=2)
        config.write_text('{"scan_ports": 12} trailing garbage')
        run(executable, "analyze", fixtures / "baseline.pcap", "--output", root / "invalid-config", "--config", config, code=2)
        assert not (root / "invalid-config").exists()
        run(executable, "--version")
        run(executable, "--help")
        run(executable, "analyze", "--help")
    print("Black-box CLI checks passed: expected counts, evidence, hash, UTC, config precedence, errors and exclusive output.")


if __name__ == "__main__":
    main()
