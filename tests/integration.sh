#!/bin/bash
# Runs the real stack: checks the container requirements and scans test files.
set -euo pipefail

cd "$(dirname "$0")/.."
project=antivirus-integration
compose() { docker compose -p "$project" "$@"; }

work=$(mktemp -d)
cleanup() {
    compose logs --tail 20 >"$work/logs" 2>&1 || true
    [ "${passed:-no}" = yes ] || cat "$work/logs"
    compose down -v --remove-orphans >/dev/null 2>&1 || true
    rm -rf "$work"
}
trap cleanup EXIT

compose up -d --build --wait

for name in clamd service; do
    container=$(compose ps -q "$name")

    read_only=$(docker inspect "$container" --format '{{.HostConfig.ReadonlyRootfs}}')
    [ "$read_only" = true ] || { echo "FAIL $name: root filesystem is writable"; exit 1; }

    uid=$(docker exec "$container" id -u)
    [ "$uid" != 0 ] || { echo "FAIL $name: runs as root"; exit 1; }

    if docker exec "$container" sh -c 'touch /usr/antivirus-write-test' 2>/dev/null; then
        echo "FAIL $name: could write to the root filesystem"
        exit 1
    fi
    echo "OK $name: uid=$uid, read-only root filesystem"
done

expect() {
    local file=$1 verdict=$2 output
    output=$(python3 demo_client.py "$file")
    echo "$output" | grep -q "\"verdict\": \"$verdict\"" || {
        echo "FAIL $(basename "$file"): expected $verdict"
        echo "$output"
        exit 1
    }
    echo "OK $(basename "$file"): $verdict"
}

# The test file is assembled here so this repository doesn't contain a file that
# antivirus tools flag.
printf '%s%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-' \
    'ANTIVIRUS-TEST-FILE!$H+H*' >"$work/eicar.txt"
echo 'just,a,clean,file' >"$work/clean.csv"
head -c "${LARGE_FILE_BYTES:-52428800}" /dev/urandom >"$work/large.bin"

expect "$work/eicar.txt" infected
expect "$work/clean.csv" clean
expect "$work/large.bin" clean

passed=yes
echo "Integration tests passed"
