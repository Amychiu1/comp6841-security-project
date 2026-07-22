#!/bin/bash
# Step 2: turn ON the stack canary, but leave everything else off
# (still no PIE, still executable stack, still no RELRO). This isolates
# the effect of the canary specifically, so you can see exactly what it
# does and does not protect against.
set -e
gcc -m64 -O0 -fstack-protector-all -no-pie -z execstack -z norelro \
    -w -o vuln vuln.c
echo "Built ./vuln (canary enabled, everything else still off)"
echo
checksec --file=./vuln 2>/dev/null || echo "(checksec not installed - that's fine)"
