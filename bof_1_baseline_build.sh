#!/bin/bash
# Compile with ALL modern protections deliberately turned OFF, so the
# baseline is as simple as possible to exploit:
#   -fno-stack-protector : no stack canary
#   -no-pie               : binary loads at a fixed, predictable address
#   -z execstack          : stack is executable (not needed for ret2win,
#                            but keeps the door open for later experiments)
#   -z norelro            : no read-only relocations
set -e
gcc -m64 -O0 -fno-stack-protector -no-pie -z execstack -z norelro \
    -w -o vuln vuln.c
echo "Built ./vuln"
echo
echo "Checking protections (if 'checksec' is installed):"
checksec --file=./vuln 2>/dev/null || echo "(checksec not installed - that's fine, just proceed)"
