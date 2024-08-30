#!/usr/bin/env bash

requireCommand() {
  if ! command -v "$1" &> /dev/null
  then
    echo "$1 is required. Please install it and then try again." >> /dev/stderr
    exit 1
  fi
}

entry_point=$1
cd "$entry_point"
echo "$entry_point" >> /dev/stderr

set -e
if [ -f pom.xml ]; then
  requireCommand mvn
  echo "Compile with mvn" >> /dev/stderr
  mvn clean package -f pom.xml -B -V -e \
    -Dfindbugs.skip -Dcheckstyle.skip -Dpmd.skip=true -Dspotbugs.skip \
    -Denforcer.skip -Dmaven.javadoc.skip -DskipTests -Dmaven.test.skip.exec \
    -Dlicense.skip=true -Drat.skip=true -Dspotless.check.skip=true > /dev/null 2>&1
fi
