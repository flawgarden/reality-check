#!/bin/bash

requireCommand() {
  if ! command -v "$1" &> /dev/null
  then
    echo "$1 is required. Please install it and then try again."
    exit 1
  fi
}

requireCommand git
requireCommand python3

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
BASE_DIR="$(cd $SCRIPT_DIR/../data && pwd)"

cd $SCRIPT_DIR/../
./scripts/collect_benchmark.py
./scripts/markup_benchmark.py
