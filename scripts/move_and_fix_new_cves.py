#!/usr/bin/env python3

import argparse
import csv
import shutil
from pathlib import Path

from add_manual_markup import check_file_or_exit
from sort_data_by_relevance import MISSING_CWES


COMMIT_HASHES_FILE = "data/commit_hashes.csv"
NEW_CVES_FILE = "cves_db_new.csv"
MAIN_CVES_FILE = "cves_db.csv"


def collect_cves(csv_entries):
    present_cves = set()
    for csv_entry in csv_entries:
        present_cves.add(csv_entry["cve"])
    return present_cves


def map_cve_to_one_cwe(csv_entries):
    cve_to_cwe = dict()
    for csv_entry in csv_entries:
        cwe = csv_entry["cwe"].strip("\"").split(",")[0]
        cve_to_cwe[csv_entry["cve"]] = cwe
    return cve_to_cwe


def normalize_cwe(csv_entry, cve_to_cwe):
    if csv_entry["cwe"] in MISSING_CWES:
        csv_entry["cwe"] = cve_to_cwe[csv_entry["cve"]]
    return csv_entry


def main():
    ap = argparse.ArgumentParser()

    ap.add_argument("-l", "--language", required=True,
                    help="language of the markup specified")

    args = ap.parse_args()

    lang = args.language
    root_dir = Path(__file__).resolve().parents[1] / lang

    new_cves_file = root_dir / NEW_CVES_FILE
    main_cves_file = root_dir / MAIN_CVES_FILE
    commit_hashes_file = root_dir / COMMIT_HASHES_FILE

    check_file_or_exit(new_cves_file)
    check_file_or_exit(main_cves_file)
    check_file_or_exit(commit_hashes_file)

    with open(new_cves_file) as csv_raw:
        csv_file = csv.DictReader(csv_raw)
        new_csv_entries = [row for row in csv_file]

    with open(main_cves_file) as csv_raw:
        csv_file = csv.DictReader(csv_raw)
        csv_fieldnames = csv_file.fieldnames
        main_csv_entries = [row for row in csv_file]

    with open(commit_hashes_file) as csv_raw:
        csv_file = csv.DictReader(csv_raw)
        commit_hashes_entries = [row for row in csv_file]

    cve_to_cwe = map_cve_to_one_cwe(commit_hashes_entries)

    already_added = collect_cves(main_csv_entries)

    with open(main_cves_file, "a") as csv_raw:
        writer = csv.DictWriter(csv_raw, csv_fieldnames)
        for new_cve in new_csv_entries:
            if new_cve["cve"] in already_added:
                continue

            writer.writerow(normalize_cwe(new_cve, cve_to_cwe))

    return 0


if __name__ == "__main__":
    exit(main())
