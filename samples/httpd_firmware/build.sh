#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
cc="${CC:-gcc}"
mkdir -p bin
for source in src/*_httpd.c; do
    name="$(basename "$source" .c)"
    "$cc" -std=c11 -O0 -g -fno-inline -fno-omit-frame-pointer -fno-stack-protector -fno-pie -no-pie \
        -Wall -Wextra -Werror "$source" -o "bin/$name"
    echo "Built bin/$name"
done
