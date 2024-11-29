#!/usr/bin/env python3

import argparse
import csv
import os
import subprocess
from pathlib import Path
from zipfile import ZipFile


def find_actual_root(zipfile):
    for name in zipfile.namelist():
        if name.endswith("/") and name.count("/") == 1:
            return name[:-1]


def download_or_skip(save_path, version, zip_url):
    file = os.path.split(zip_url)[1]
    versioned_repo = save_path + '/' + version
    if os.path.exists(versioned_repo):
        print(versioned_repo)
        print("The file has been downloaded! Skip it")
    else:
        print(versioned_repo)
        filename = save_path + '/' + file
        print(filename)
        command = 'wget -P %s' % save_path + '/ ' + zip_url
        print(command)
        subprocess.run(args=command, shell=True, stdout=subprocess.DEVNULL,
                       stderr=subprocess.STDOUT)
        with ZipFile(filename) as file:
            dir = Path(filename).parent.resolve().absolute().as_posix()
            print(dir)
            file.extractall(dir)
            root = save_path + '/' + find_actual_root(file)
            if file != versioned_repo:
                print(f"Renaming '{root}' to '{versioned_repo}' to conform with database!")
                os.rename(root, versioned_repo)
        os.remove(filename)


def main():
    parent = Path(__file__).resolve().parents[1].as_posix()
    ap = argparse.ArgumentParser()

    ap.add_argument("-db", "--database", required=True,
                    help="path to cve database")
    ap.add_argument("-l", "--language", required=True,
                    help="language of cve database")
    args = ap.parse_args()

    parent = parent + '/' + args.language
    with open(parent + '/' + args.database) as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            save_path = parent + '/benchmark/' + row['project']
            vul_zip_url = row['vul_zip']
            patch_zip_url = row['patch_zip']
            vul_version = row['vul_version']
            patch_version = row['patch_version']
            download_or_skip(save_path, vul_version, vul_zip_url)
            download_or_skip(save_path, patch_version, patch_zip_url)


if __name__ == "__main__":
    main()
