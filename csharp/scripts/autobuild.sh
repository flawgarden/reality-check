#!/usr/bin/env bash

requireCommand() {
  if ! command -v "$1" &> /dev/null
  then
    echo "$1 is required. Please install it and then try again." >> /dev/stderr
    exit 1
  fi
}

entry_point=$1
cd $entry_point
echo "$entry_point" >> /dev/stderr

set -e

requireCommand dotnet
echo "Compile with dotnet" >> /dev/stderr
dotnet build > /dev/null 2>&1
