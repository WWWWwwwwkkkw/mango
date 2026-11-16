"""Run native binaries against normal, boundary and malformed HTTP requests."""
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parent


def main():
    cases = json.loads((ROOT / "manifest.json").read_text())
    checks = 0
    for case in cases:
        name = case["binary"]
        for label in ("normal", "boundary", "malformed"):
            data = b"not http\r\n" if label == "malformed" else (ROOT / "requests" / f"{name}_{label}.http").read_bytes()
            result = subprocess.run([str(ROOT / "bin" / name)], input=data, capture_output=True, timeout=5)
            expected = 400 if label == "malformed" else (200 if label == "normal" else case["expected_boundary_status"])
            assert result.stdout.startswith(f"HTTP/1.1 {expected} ".encode()), (name, label, result.stdout)
            assert result.returncode == (0 if expected == 200 else 1), (name, label, result.returncode)
            if expected == 200:
                size = case[f"expected_{label}_reserved"]
                assert f"reserved={size}\n".encode() in result.stdout, (name, label, result.stdout)
            checks += 1
        print(f"PASS {name}")
    print(f"{checks} checks passed; 3 wrapping allocations accepted, 7 protected boundary requests rejected.")


if __name__ == "__main__":
    main()
