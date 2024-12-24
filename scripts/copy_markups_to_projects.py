#!/usr/bin/env python3

import argparse
import shutil
from pathlib import Path


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-l", "--language", required=True,
                    help="language of cve database")
    args = ap.parse_args()

    root = Path(__file__).resolve().parents[1] / args.language

    markup_dir = root / "markup"
    bench_dir = root / "benchmark"

    for markup_file in Path(markup_dir).rglob("*.sarif"):
        relative_path = markup_file.relative_to(markup_dir)
        shutil.copy(markup_file, bench_dir / relative_path)


if __name__ == "__main__":
    main()
