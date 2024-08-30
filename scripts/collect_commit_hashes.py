#!/usr/bin/env python3

import argparse
import csv
import os
import sqlite3 as lite
from pathlib import Path
from sqlite3 import Error

import git
import pandas as pd


def create_connection(db_file):
    """
    create a connection to sqlite3 database
    """
    conn = None
    try:
        conn = lite.connect(db_file, timeout=10)  # connection via sqlite3
    except Error as e:
        print(e)
    return conn


def collect_commit_hashes(db_path, result_path, language):
    conn = create_connection(db_path)
    query = f"""
SELECT fx.cve_id, fx.hash, fx.repo_url, cc.cwe_id
FROM fixes fx, repository r, cwe_classification cc
WHERE fx.repo_url=r.repo_url
AND fx.cve_id=cc.cve_id
AND r.repo_language='{language}';
"""
    java_single_line_fixes = pd.read_sql_query(query, conn)

    with open(
        result_path / "commit_hashes.csv", "w", encoding="UTF8"
    ) as csvfile_versions:
        all_writer = csv.writer(csvfile_versions)

        all_writer.writerow(
            [
                "cve",
                "project",
                "commit_hash",
                "cwe",
                "vul_version_hash",
                "patch_version_hash",
            ]
        )

        for index, row in java_single_line_fixes.iterrows():
            repo_url = row["repo_url"]
            commit_hash = row["hash"]
            cve_id = row["cve_id"]
            cwe_id = row["cwe_id"]
            vul_release_hash = None
            patch_release_hash = None

            all_writer.writerow(
                [
                    cve_id,
                    repo_url,
                    commit_hash,
                    cwe_id,
                    vul_release_hash,
                    patch_release_hash,
                ]
            )

def fix_language(language):
    if language == "java":
        return "Java"
    if language == "csharp":
        return "C#"
    if language == "python":
        return "Python"
    if language == "go":
        return "Go"
    return None


def main():
    ap = argparse.ArgumentParser()

    # Add the arguments to the parser
    ap.add_argument("-db", "--database", required=True,
                    help="path to CVEfixes.db")
    ap.add_argument("-l", "--language", required=True,
                    help="language of cve database")
    args = ap.parse_args()

    parent = Path(__file__).resolve().parents[1]
    parent = parent / args.language
    result_path = parent / "data"
    db_path = args.database

    Path(result_path).mkdir(parents=True, exist_ok=True)

    collect_commit_hashes(db_path, result_path, fix_language(args.language))


if __name__ == "__main__":
    main()
