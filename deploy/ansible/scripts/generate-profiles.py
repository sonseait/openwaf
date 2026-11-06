#!/usr/bin/env python3
"""Render checked-in Compose fragments; VPS hosts need only Docker Compose."""
import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "backend/runtime"))
import vps_profiles  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    directory = Path(__file__).resolve().parents[1] / "files/profiles"
    directory.mkdir(exist_ok=True)
    capacities = []
    for name in vps_profiles.NAMES:
        sizing = vps_profiles.profile(name)
        capacities.append({"name": name, "cpus": sizing["host_cpus"],
                           "memory_mib": sizing["host_memory_mib"],
                           "minimum_memory_mib": (sizing["host_memory_mib"] * 95 + 99) // 100})
        path = directory / f"{name}.yaml"
        model = vps_profiles.compose(name)
        data = json.dumps(model, indent=2) + "\n"
        if args.check:
            if not path.exists() or path.read_text() != data:
                raise SystemExit(f"Regenerate {path.relative_to(ROOT)}")
        else:
            path.write_text(data)
    path = directory.parent / "profile-capacity.json"
    data = json.dumps(capacities, indent=2) + "\n"
    if args.check:
        if not path.exists() or path.read_text() != data:
            raise SystemExit(f"Regenerate {path.relative_to(ROOT)}")
    else:
        path.write_text(data)
    print("VPS Compose profiles match sizing source.")


if __name__ == "__main__":
    main()
