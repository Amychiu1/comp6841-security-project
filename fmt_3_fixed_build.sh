#!/bin/bash
set -e
gcc -m64 -O0 -w -o vuln vuln.c
echo "Built ./vuln (source fix: printf(\"%s\", buf) instead of printf(buf))"
