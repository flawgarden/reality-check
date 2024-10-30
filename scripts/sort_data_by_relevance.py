#!/usr/bin/env python3
import csv
import sys
import os

COMMIT_FIELD = "commit_hash"
CWE_FIELD = "cwe"
USED_FIELDS = [COMMIT_FIELD, CWE_FIELD]
MISSING_CWES = ["NVD-CWE-noinfo", "NVD-CWE-Other"]


def count_cwe_per_hash(csv_entries):
    hash_counts = dict()
    for row in csv_entries:
        hash_counts[row[COMMIT_FIELD]] = set()
    for row in csv_entries:
        row_cwe = row[CWE_FIELD]
        if row_cwe in MISSING_CWES:
            continue
        hash_counts[row[COMMIT_FIELD]].add(row_cwe)
    return hash_counts


def main():
    if len(sys.argv) != 2:
        print("Incorrect amount of arguments! Expected: path to a csv file.")
        return 1

    filepath = sys.argv[1]

    if not os.path.exists(filepath):
        print("Could not find the given file: " + filepath + "!")
        return 2

    with open(filepath) as csv_raw:
        csv_file = csv.DictReader(csv_raw)
        csv_fieldnames = csv_file.fieldnames
        csv_entries = [row for row in csv_file]

    for field in USED_FIELDS:
        if field not in csv_fieldnames:
            print("Field \"" + field + "\" expected, but not present in the given csv! Aborting.")
            return 3

    hash_counts = count_cwe_per_hash(csv_entries)

    def entry_key(e):
        if e[CWE_FIELD] in MISSING_CWES:
            return -1
        return len(hash_counts[e[COMMIT_FIELD]])

    csv_entries.sort(key=entry_key, reverse=True)
    
    with open(filepath, "w") as csv_raw:
        writer = csv.DictWriter(csv_raw, csv_fieldnames)
        writer.writeheader()
        for row in csv_entries:
            writer.writerow(row)


if __name__ == "__main__":
    exitcode = main()
    exit(exitcode)
