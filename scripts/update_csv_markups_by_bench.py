#!/usr/bin/env python3

import argparse
import csv
import json
import os
from pathlib import Path


def get_sarif_results(sarif_path):
    try:
        with open(sarif_path, 'r') as sarif_file:
            data = json.load(sarif_file)

        return data["runs"][0]["results"]

    except Exception:
        print(f'Error while working with {sarif_file}! Aborting...')
        exit(-2)


def convert_location_to_csv(loc):
    file_path = loc["physicalLocation"]["artifactLocation"]["uri"]
    start_line = loc["physicalLocation"]["region"]["startLine"]
    end_line = loc["physicalLocation"]["region"]["endLine"]
    name = loc["logicalLocations"][0]["name"]
    return f"\"{file_path}:[{start_line},{end_line}]:{name}\""


def convert_result_to_csv(result):
    return [convert_location_to_csv(loc) for loc in result["locations"]]


def write_csv_result(csv_path, csv_type, csv_data):
    with open(csv_path, "w") as csv_file:
        csv_file.write(csv_type + "\n")
        csv_file.write("\n".join(csv_data))


def get_result_by_cve_and_kind(version_path_str, sarif_data, cve, kind):
    result_by_cve = next(
        (
            x
            for x in sarif_data
            if x["message"]["text"] == cve and x["kind"] == kind
        ),
        None
    )
    if result_by_cve is None:
        print(f"Could not find result in {version_path_str} for {cve}!")
        exit(1)
    return convert_result_to_csv(result_by_cve)


def convert_sarif_to_csv(
    parent_path_str,
    bench_path_str,
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

    sarif_data = get_sarif_results(bench_path_str + "/truth.sarif")

    for cve in version_to_cves[version]:
        if cve_to_vul_version[cve] == version:
            csv_path = parent_path_str + "/vulnerable/" + cve_to_vul_csv[cve]
            csv_result = get_result_by_cve_and_kind(version_path_str, sarif_data, str(cve), "fail")
            write_csv_result(csv_path, "Vul_Path", csv_result)
        if cve_to_patch_version[cve] == version:
            csv_path = parent_path_str + "/patched/" + cve_to_patch_csv[cve]
            csv_result = get_result_by_cve_and_kind(version_path_str, sarif_data, str(cve), "pass")
            write_csv_result(csv_path, "Fix_Path", csv_result)


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
            convert_sarif_to_csv(
                parent_str,
                benchmark_root_path_str + "/" + proj_dir + "/" + version_dir,
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
