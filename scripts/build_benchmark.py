#!/usr/bin/env python3

import os
import subprocess
import sys
from pathlib import Path


def build(scrips_path, project_path):
    command = './autobuild.sh %s' % project_path
    return subprocess.run(args=command, shell=True, cwd=scrips_path).returncode


def main():
    parent = Path(__file__).resolve().parents[1].as_posix()
    scripts = parent + '/scripts'
    benchmark = parent + '/benchmark'
    error_exit = False
    for project in os.listdir(benchmark):
        project_path = os.path.join(benchmark, project)
        if not os.path.isdir(project_path):
            continue
        for version in os.listdir(project_path):
            version_path = os.path.join(project_path, version)
            return_code = build(scripts, version_path)
            if not return_code == 0:
                print(return_code)
                print("Build failed for " + os.path.join(project, version))
            error_exit |= not return_code == 0
    if error_exit:
        sys.exit("Build failed for some projects.")


if __name__ == "__main__":
    main()
