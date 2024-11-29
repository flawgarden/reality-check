#!/usr/bin/env python3

import argparse
import csv
import shutil
from pathlib import Path

from collect_cve_benchmark import get_all_infos_row

CVE_FIELD = "cve"
PROJECT_FIELD = "project"
COMMIT_FIELD = "commit_hash"
CWE_FIELD = "cwe"
VUL_VERSION_FIELD = "vul_version_hash"
FIX_VERSION_FIELD = "patch_version_hash"
MARKUP_VUL_FILE_FIELD = "markup_vul_file"
MARKUP_FIX_FILE_FIELD = "markup_fix_file"

REQUIRED_FIELDS = [
    CVE_FIELD,
    PROJECT_FIELD,
    COMMIT_FIELD,
    CWE_FIELD,
    VUL_VERSION_FIELD,
    FIX_VERSION_FIELD,
    MARKUP_VUL_FILE_FIELD,
    MARKUP_FIX_FILE_FIELD,
]

VUL_MARKUP_FILE_ID = 7
FIX_MARKUP_FILE_ID = 11

VUL_DIR = "vulnerable"
FIX_DIR = "patched"

NEW_CVES_FILE = "cves_db_new.csv"


def check_file_or_exit(filepath):
    if not Path(filepath).exists():
        print(f"Could not find the following file/directory: {filepath}; aborting")
        exit(-1)


def main():
    ap = argparse.ArgumentParser()

    ap.add_argument("-d", "--data", required=True,
                    help="path to the file containing manual markup")

    ap.add_argument("-l", "--language", required=True,
                    help="language of the markup specified")

    args = ap.parse_args()
    filepath = args.data

    check_file_or_exit(filepath)

    lang_dir = Path(__file__).resolve().parents[1] / args.language

    check_file_or_exit(lang_dir)

    markup_dir = Path(filepath).resolve().parent

    with open(filepath) as csv_raw:
        csv_file = csv.DictReader(csv_raw)
        csv_fieldnames = csv_file.fieldnames
        csv_entries = [row for row in csv_file]

    for field in REQUIRED_FIELDS:
        if field not in csv_fieldnames:
            print("Field \"" + field + "\" expected, but not present in the given csv! Aborting.")
            return 3

    def fix_markup_path(relative_path):
        return markup_dir / relative_path

    for csv_entry in csv_entries:
        check_file_or_exit(fix_markup_path(csv_entry[MARKUP_VUL_FILE_FIELD]))
        check_file_or_exit(fix_markup_path(csv_entry[MARKUP_FIX_FILE_FIELD]))

    with open(lang_dir / NEW_CVES_FILE, "a", encoding="UTF8") as new_cves:
        writer = csv.writer(new_cves)
        for csv_entry in csv_entries:
            all_infos = get_all_infos_row(
                {csv_entry[CVE_FIELD]: csv_entry[CWE_FIELD]},
                csv_entry[CVE_FIELD],
                csv_entry[PROJECT_FIELD],
                csv_entry[VUL_VERSION_FIELD],
                csv_entry[FIX_VERSION_FIELD]
            )

            writer.writerow(all_infos)

            shutil.copy(Path(fix_markup_path(csv_entry[MARKUP_VUL_FILE_FIELD])),
                        lang_dir / VUL_DIR / all_infos[VUL_MARKUP_FILE_ID])

            shutil.copy(Path(fix_markup_path(csv_entry[MARKUP_FIX_FILE_FIELD])),
                        lang_dir / FIX_DIR / all_infos[FIX_MARKUP_FILE_ID])

    return 0


if __name__ == "__main__":
    exit(main())
