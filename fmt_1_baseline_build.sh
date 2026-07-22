#!/bin/bash
set -e
gcc -m64 -O0 -fno-stack-protector -no-pie -z execstack -z norelro \
    -w -o vuln vuln.c
echo "Built ./vuln"
echo
checksec --file=./vuln 2>/dev/null || echo "(checksec not installed - that's fine)"
