#!/usr/bin/env python3

import argparse
import csv
import json
import os
from pathlib import Path


def parse_cvs(csv_path_str, path_key):
    result = []
    with open(csv_path_str, "r") as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            path = row[path_key]
            parts = path.split(":")
            file_path = parts[0]
            region = parts[1].strip("[]").split(",")
            start_line = region[0]
            end_line = region[1]
            name = parts[2]
            kind = "function"
            location = {
                "filePath": file_path,
                "startLine": int(start_line),
                "endLine": int(end_line),
                "kind": kind,
                "name": name,
            }
            result.append(location)
    return result


def convert(
    parent_path_str,
    version_path_str,
    version_to_cves,
    cve_to_vul_csv,
    cve_to_patch_csv,
    cve_to_vul_version,
    cve_to_patch_version,
    cve_to_cwe,
):
    version_path = Path(version_path_str)
    version_parent_path_str = version_path.resolve(
    ).parents[0].absolute().as_posix()
    version = version_path.relative_to(version_parent_path_str).as_posix()
    sarif_data_out = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "reality-check-benchmark-" + version}}}],
    }
    results = []
    for cve in version_to_cves[version]:
        if cve_to_vul_version[cve] == version:
            vul_csv_path_str = cve_to_vul_csv[cve]
            locations = parse_cvs(
                parent_path_str + "/vulnerable/" + vul_csv_path_str, "Vul_Path"
            )
            result = {}
            result["kind"] = "fail"
            result["message"] = {}
            result["message"]["text"] = str(cve)
            result["ruleId"] = str(cve_to_cwe[cve])
            result["locations"] = []
            for markup_location in locations:
                location = {
                    "physicalLocation": {
                        "artifactLocation": {"uri": markup_location["filePath"]},
                        "region": {
                            "startLine": markup_location["startLine"],
                            "endLine": markup_location["endLine"],
                        },
                    },
                    "logicalLocations": [
                        {
                            "name": markup_location["name"],
                            "kind": markup_location["kind"],
                        }
                    ],
                }
                result["locations"].append(location)
            results.append(result)

        if cve_to_patch_version[cve] == version:
            patch_csv_path_str = cve_to_patch_csv[cve]
            locations = parse_cvs(
                parent_path_str + "/patched/" + patch_csv_path_str,
                "Fix_Path",
            )
            result = {}
            result["kind"] = "pass"
            result["message"] = {}
            result["message"]["text"] = str(cve)
            result["ruleId"] = str(cve_to_cwe[cve])
            result["locations"] = []
            for markup_location in locations:
                location = {
                    "physicalLocation": {
                        "artifactLocation": {"uri": markup_location["filePath"]},
                        "region": {
                            "startLine": markup_location["startLine"],
                            "endLine": markup_location["endLine"],
                        },
                    },
                    "logicalLocations": [
                        {
                            "name": markup_location["name"],
                            "kind": markup_location["kind"],
                        }
                    ],
                }
                result["locations"].append(location)
            results.append(result)
    sarif_data_out["runs"][0]["results"] = results
    os.makedirs(version_path_str, exist_ok=True)
    out_file = open(version_path_str + "/truth.sarif", "w")
    json.dump(sarif_data_out, out_file, indent=2)


def main():
    parent = Path(__file__).resolve().parents[1]

    ap = argparse.ArgumentParser()

    ap.add_argument("-l", "--language", required=True,
                    help="language of cve database")
    args = ap.parse_args()

    parent = parent / args.language
    parent_str = parent.absolute().as_posix()
    print(parent_str)
    version_to_cves = {}
    cve_to_vul_version = {}
    cve_to_patch_version = {}
    cve_to_vul_csv = {}
    cve_to_patch_csv = {}
    cve_to_cwe = {}
    versions = set()
    cves_set = set()
    version_to_project = {}
    with open(parent_str + "/cves_db.csv") as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            vul_version = row["vul_version"]
            patch_version = row["patch_version"]
            cve = row["cve"]
            cves = version_to_cves.get(vul_version, [])
            cves.append(cve)
            version_to_cves[vul_version] = cves
            cves = version_to_cves.get(patch_version, [])
            cves.append(cve)
            version_to_cves[patch_version] = cves
            cve_to_vul_csv[cve] = row["vul_markup_file"]
            cve_to_patch_csv[cve] = row["patch_markup_file"]
            cve_to_cwe[cve] = row["cwe"]
            versions.add(vul_version)
            versions.add(patch_version)
            version_to_project[vul_version] = row["project"]
            version_to_project[patch_version] = row["project"]
            cves_set.add(cve)
            cve_to_vul_version[cve] = vul_version
            cve_to_patch_version[cve] = patch_version
    benchmark_root_path_str = (
        (parent / "benchmark/").resolve().absolute().as_posix()
    )
    markup_root_path_str = (
        (parent / "markup/").resolve().absolute().as_posix()
    )
    proj_dirs = [
        proj_dir
        for proj_dir in os.listdir(benchmark_root_path_str)
        if os.path.isdir(os.path.join(benchmark_root_path_str, proj_dir))
    ]
    for proj_dir in proj_dirs:
        for version_dir in os.listdir(benchmark_root_path_str + "/" + proj_dir):
            version_dir_absolute = (
                markup_root_path_str + "/" + proj_dir + "/" + version_dir
            )
            convert(
                parent_str,
                version_dir_absolute,
                version_to_cves,
                cve_to_vul_csv,
                cve_to_patch_csv,
                cve_to_vul_version,
                cve_to_patch_version,
                cve_to_cwe,
            )


if __name__ == "__main__":
    main()
