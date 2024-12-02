#!/usr/bin/env python3

import argparse
import csv
import shutil
import os
from pathlib import Path

from add_manual_markup import check_file_or_exit
from sort_data_by_relevance import MISSING_CWES


COMMIT_HASHES_FILE = "data/commit_hashes.csv"
NEW_CVES_FILE = "cves_db_new.csv"
MAIN_CVES_FILE = "cves_db.csv"
MARKUP_DIR = "markup"
PATCHED_DIR = "patched"
VUL_DIR = "vulnerable"


def read_cves(file_path):
    check_file_or_exit(file_path)
    cves = []
    with open(file_path) as file:
        for line in file:
            cve = line.strip()
            if len(cve) > 0:
                cves.append(cve)
    return cves


def delete_and_rewrite_csv(csv_path, cves_to_delete):
    def is_marked(csv_entry):
        return csv_entry["cve"] not in cves_to_delete

    check_file_or_exit(csv_path)
    with open(csv_path, "r") as csv_raw:
        csv_file = csv.DictReader(csv_raw)
        csv_fieldnames = csv_file.fieldnames
        csv_entries = [row for row in csv_file]
    with open(csv_path, "w") as csv_raw:
        csv_file = csv.DictWriter(csv_raw, csv_fieldnames)
        csv_file.writeheader()
        csv_file.writerows(filter(is_marked, csv_entries))


def delete_cve_markups(dir_path, cves_to_delete):
    for file_name in os.listdir(dir_path):
        if file_name.endswith(".csv") and any([cve in file_name for cve in cves_to_delete]):
            os.remove(dir_path / file_name)


def main():
    ap = argparse.ArgumentParser()

    ap.add_argument("-l", "--language", required=True,
                    help="language of the markup specified")

    ap.add_argument("-d", "--data", required=True,
                    help="file containing CVEs to delete")

    args = ap.parse_args()

    lang = args.language
    root_dir = Path(__file__).resolve().parents[1] / lang

    cves_to_delete = read_cves(args.data)
    delete_and_rewrite_csv(root_dir / COMMIT_HASHES_FILE, cves_to_delete)
    delete_and_rewrite_csv(root_dir / NEW_CVES_FILE, cves_to_delete)
    delete_and_rewrite_csv(root_dir / MAIN_CVES_FILE, cves_to_delete)

    delete_cve_markups(root_dir / PATCHED_DIR, cves_to_delete)
    delete_cve_markups(root_dir / VUL_DIR, cves_to_delete)

    return 0


if __name__ == "__main__":
    exit(main())
