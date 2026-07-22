#!/bin/bash
# Step 2: compile with glibc's _FORTIFY_SOURCE=2, which adds RUNTIME
# checks to certain "risky" libc functions - including printf-family
# functions. One specific check it adds: if the format string lives in
# WRITABLE memory (like our stack buffer) and contains %n, glibc's
# fortified printf will detect this and abort the program instead of
# performing the write. This does NOT require -Wformat-security - it's
# an actual runtime defence, not just a compile-time warning.
#
# _FORTIFY_SOURCE requires at least -O1 to have any effect.
set -e
gcc -m64 -O2 -D_FORTIFY_SOURCE=2 -fno-stack-protector -no-pie \
    -w -o vuln vuln.c
echo "Built ./vuln (compiled with -D_FORTIFY_SOURCE=2 -O2)"
echo
checksec --file=./vuln 2>/dev/null || echo "(checksec not installed - that's fine)"
