#!/usr/bin/env sh
set -eu

jar="target/example-security-key-rotator.jar"
if [ ! -f "$jar" ]; then
    printf '%s\n' 'Build the application first with: mvn clean package' >&2
    exit 1
fi
exec java -jar "$jar"
