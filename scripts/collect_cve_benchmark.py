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


def try_get_tag_from_commit(repo_url, hash_commit):
    tag_map = {}
    g = git.cmd.Git()
    tags = g.ls_remote("--tags", repo_url).split("\n")
    for tag in tags:
        if tag != "":
            parsed_tag = tag.split()
            tag_map[parsed_tag[0]] = parsed_tag[1]
    return tag_map.get(hash_commit, "").replace("^{}", "")


def get_version_id_from_tag(tag):
    return tag.split("/")[2]


def get_version(project, tag):
    version_id = get_version_id_from_tag(tag)
    return project + "-" + version_id


def get_url(repo_url, tag):
    version_id = get_version_id_from_tag(tag)
    return repo_url + "/releases/tag/" + version_id


def get_zip_url(repo_url, tag):
    return repo_url + "/archive/" + tag + ".zip"


def get_markup_file(project, cve, version):
    return project + "_" + cve + "_" + version + ".csv"


def cve_to_cwe(db_path):
    cwe_map = {}
    conn = create_connection(db_path)
    query = """
SELECT cc.cve_id, cc.cwe_id
FROM cwe_classification cc
"""
    cve_to_cwe_lines = pd.read_sql_query(query, conn)
    for index, line in cve_to_cwe_lines.iterrows():
        cwe_map[line["cve_id"]] = line["cwe_id"]
    return cwe_map


def cve_to_markup(db_path, language):
    cve_map = {}
    conn = create_connection(db_path)
    query = f"""
SELECT f.cve_id, fc.old_path, fc.new_path, mc.name, mc.start_line, mc.end_line, mc.before_change
FROM fixes f, file_change fc, method_change mc
WHERE f.hash=fc.hash
AND fc.file_change_id=mc.file_change_id
AND fc.programming_language='{language}'
"""
    markup_infos = pd.read_sql_query(query, conn)
    for _, line in markup_infos.iterrows():
        cve = line["cve_id"]
        vul_markup, patch_markup = cve_map.get(cve, ([], []))
        if line["before_change"] == "True":
            vul_markup.append(
                (
                    line["old_path"],
                    line["start_line"],
                    line["end_line"],
                    line["name"].replace("::", "_"),
                )
            )
        else:
            patch_markup.append(
                (
                    line["new_path"],
                    line["start_line"],
                    line["end_line"],
                    line["name"].replace("::", "_"),
                )
            )
        cve_map[cve] = (vul_markup, patch_markup)
    return cve_map


def get_tags(
    repo_url,
    vul_version_hash,
    patch_version_hash,
):
    vul_tag = try_get_tag_from_commit(repo_url, vul_version_hash)
    patch_tag = try_get_tag_from_commit(repo_url, patch_version_hash)
    return vul_tag, patch_tag


def get_all_infos_row(
    cve_to_cwe_map,
    cve,
    repo_url,
    vul_version_hash,
    patch_version_hash,
):
    if vul_version_hash == "" or patch_version_hash == "":
        return []
    project = Path(repo_url).name
    full_name = (Path(repo_url).parents[0] / project).as_posix()
    cwe = cve_to_cwe_map[cve]
    vul_tag, patch_tag = get_tags(
        repo_url, vul_version_hash, patch_version_hash)
    vul_version = ""
    vul_url = ""
    vul_zip = ""
    patch_version = ""
    patch_url = ""
    patch_zip = ""
    if vul_tag == "":
        vul_tag = f"{vul_version_hash}"
        vul_version = project + "-" + vul_tag
        vul_url = repo_url + "/tree/" + vul_tag
        vul_zip = repo_url + "/archive/" + vul_tag + ".zip"
    else:
        vul_version = get_version(project, vul_tag)
        vul_url = get_url(repo_url, vul_tag)
        vul_zip = get_zip_url(repo_url, vul_tag)
    if patch_tag == "":
        patch_tag = f"{patch_version_hash}"
        patch_version = project + "-" + patch_tag
        patch_url = repo_url + "/tree/" + patch_tag
        patch_zip = repo_url + "/archive/" + patch_tag + ".zip"
    else:
        patch_version = get_version(project, patch_tag)
        patch_url = get_url(repo_url, patch_tag)
        patch_zip = get_zip_url(repo_url, patch_tag)

    vul_markup_file = get_markup_file(project, cve, vul_version)
    patch_markup_file = get_markup_file(project, cve, patch_version)
    return [
        project,
        cve,
        cwe,
        full_name,
        vul_version,
        vul_url,
        vul_zip,
        vul_markup_file,
        patch_version,
        patch_url,
        patch_zip,
        patch_markup_file,
    ]


def collect_all_infos(db_path, result_path, vul_patch_hashes):
    cve_to_cwe_map = cve_to_cwe(db_path)
    with open(vul_patch_hashes, "r", encoding="UTF8") as csvfile:
        reader = csv.DictReader(csvfile)
        with open(
            result_path / "cves_db_new.csv", "w", encoding="UTF8"
        ) as csvfile_all:
            all_writer = csv.writer(csvfile_all)

            all_writer.writerow(
                [
                    "project",
                    "cve",
                    "cwe",
                    "full_name",
                    "vul_version",
                    "vul_url",
                    "vul_zip",
                    "vul_markup_file",
                    "patch_version",
                    "patch_url",
                    "patch_zip",
                    "patch_markup_file",
                ]
            )

            for row in reader:
                all_infos_row = get_all_infos_row(
                    cve_to_cwe_map,
                    row["cve"],
                    row["project"],
                    row["vul_version_hash"],
                    row["patch_version_hash"],
                )
                if len(all_infos_row) != 0:
                    all_writer.writerow(all_infos_row)


def collect_markup_files(db_path, result_path, language):
    cve_to_markup_map = cve_to_markup(db_path, language)
    with open(result_path / "cves_db_new.csv", "r", encoding="UTF8") as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            cve = row["cve"]
            vul_markup_file = row["vul_markup_file"]
            patch_markup_file = row["patch_markup_file"]
            if not cve in cve_to_markup_map:
                print(cve)
            else:
                vul_markup, patch_markup = cve_to_markup_map[cve]
                with open(
                    result_path / "vulnerable" / vul_markup_file,
                    "w",
                    encoding="UTF8",
                ) as vul_csvfile:
                    writer = csv.writer(vul_csvfile)
                    writer.writerow(["Vul_Path"])
                    for path, start_line, end_line, name in vul_markup:
                        writer.writerow(
                            [path + ":[" + start_line + "," + end_line + "]:" + name]
                        )
                with open(
                    result_path / "patched" / patch_markup_file,
                    "w",
                    encoding="UTF8",
                ) as patch_csvfile:
                    writer = csv.writer(patch_csvfile)
                    writer.writerow(["Fix_Path"])
                    for path, start_line, end_line, name in patch_markup:
                        writer.writerow(
                            [path + ":[" + start_line + "," + end_line + "]:" + name]
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
    ap.add_argument(
        "-vh",
        "--version-hashes",
        required=True,
        help="path to a table with vulnerable and patch version hashes",
    )
    ap.add_argument("-l", "--language", required=True,
                    help="language of cve database")
    args = ap.parse_args()

    parent = Path(__file__).resolve().parents[1]
    parent = parent /  args.language
    data_path = parent
    data_vulnerable_path = data_path / "vulnerable"
    data_patched_path = data_path / "patched"
    db_path = args.database
    vul_patch_hashes = args.version_hashes

    Path(data_path).mkdir(parents=True, exist_ok=True)
    Path(data_vulnerable_path).mkdir(parents=True, exist_ok=True)
    Path(data_patched_path).mkdir(parents=True, exist_ok=True)

    collect_all_infos(db_path, data_path, vul_patch_hashes)
    collect_markup_files(db_path, data_path, fix_language(args.language))


if __name__ == "__main__":
    main()
