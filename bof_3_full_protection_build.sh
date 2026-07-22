#!/bin/bash
# Step 3: this is just "gcc with no special flags" - i.e. what you get
# by default on a modern Linux distribution. All four protections are
# on at once:
#   - Stack canary   (default on)
#   - PIE            (default on -> works with ASLR to randomise
#                      where the binary is loaded in memory every run)
#   - NX             (default on -> stack/heap memory is not executable)
#   - RELRO          (default on -> GOT is read-only after startup)
set -e
gcc -m64 -O0 -w -o vuln vuln.c
echo "Built ./vuln (all default protections - canary, PIE, NX, RELRO)"
echo
checksec --file=./vuln 2>/dev/null || echo "(checksec not installed - that's fine)"
