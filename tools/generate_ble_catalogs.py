#!/usr/bin/env python3
"""Build offline BLE catalogues from a checkout of bluetooth-SIG/public (requires PyYAML)."""

import argparse
import csv
from pathlib import Path

import yaml


def generate(source, key, identifier, destination):
    with source.open(encoding="utf-8") as stream:
        entries = yaml.safe_load(stream)[key]
    with destination.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream, lineterminator="\n")
        writer.writerow(("id", "name"))
        for row in sorted(entries, key=lambda row: row[identifier]):
            name = " ".join(row["name"].split())
            writer.writerow((f"{row[identifier]:04x}", name))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("checkout", type=Path)
    source = parser.parse_args().checkout / "assigned_numbers"
    output = Path(__file__).resolve().parents[1] / "src/main/resources/ble"
    generate(source / "uuids/service_uuids.yaml", "uuids", "uuid", output / "gatt-services.csv")
    generate(source / "uuids/member_uuids.yaml", "uuids", "uuid", output / "member-services.csv")
    generate(source / "company_identifiers/company_identifiers.yaml", "company_identifiers", "value",
             output / "company-identifiers.csv")


if __name__ == "__main__":
    main()
