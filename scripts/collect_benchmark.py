#!/usr/bin/env python3

import csv
import os
import subprocess
from pathlib import Path
from zipfile import ZipFile


def download_or_skip(save_path, version, zip_url):
    file = os.path.split(zip_url)[1]
    if os.path.exists(save_path + '/' + version):
        print(save_path + '/' + version)
        print("The file has been download! Skip it")
    else:
        print(save_path + '/' + version)
        filename = save_path + '/' + file
        print(filename)
        command = 'wget -P %s' % save_path + '/ ' + zip_url
        print(command)
        subprocess.run(args=command, shell=True)
        with ZipFile(filename) as file:
            dir = Path(filename).parent.resolve().absolute().as_posix()
            print(dir)
            file.extractall(dir)
        os.remove(filename)


def main():
    parent = Path(__file__).resolve().parents[1].as_posix()
    with open(parent + '/cves_db.csv') as csvfile:
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
