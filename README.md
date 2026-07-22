# COMP6841 Security Engineering Project — En-Mei Chiu (z5727209)

Supplementary code and reports for my Security Engineering project.
The final PDF report references the folders below as evidence for each stage of testing.

## Structure

```
web/                              Web component (SQLi + XSS), 3 layers
  baseline/                       No protection
  weak_protection/                Naive keyword/tag blacklist
  fixed_protection/                Parameterised query + auto-escaping

binary/
  buffer_overflow/                Ret2win challenge, 3 layers
    1_baseline/                   No protection
    2_canary/                     Stack canary only
    3_full_protection/            Canary + PIE/ASLR + NX + RELRO
  format_string/                  Arbitrary read/write challenge, 3 layers
    1_baseline/                   No protection
    2_fortify_partial/            glibc _FORTIFY_SOURCE=2
    3_fixed/                      Source-level fix (printf("%s", buf))

reports/                          Draft Word reports for each component
```

Each numbered/named subfolder contains:
- The source code (`.c` / `.py`) and build script used at that layer

## Course

COMP6441/COMP6841 Security Engineering, UNSW, 2026 T2.
