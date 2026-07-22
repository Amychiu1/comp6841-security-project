# COMP6841 Security Engineering Project — En-Mei Chiu (z5727209)

Supplementary code and reports for my Security Engineering project.
The final PDF report references the files below as evidence for each stage of testing.
Full terminal/browser screenshots for every step are included directly in the report itself
(Report-z5727209.pdf) rather than duplicated here.

## Web component (SQLi + XSS), 3 layers

| File | Layer |
|---|---|
| `web_baseline_app.py` | No protection |
| `web_weak_protection_app.py` | Naive keyword/tag blacklist |
| `web_fixed_app.py` | Parameterised query + auto-escaping |

## Binary component — Buffer Overflow (ret2win), 3 layers

| Files | Layer |
|---|---|
| `bof_1_baseline_vuln.c`, `bof_1_baseline_build.sh` | No protection |
| `bof_2_canary_vuln.c`, `bof_2_canary_build.sh` | Stack canary only |
| `bof_3_full_protection_vuln.c`, `bof_3_full_protection_build.sh`, `bof_3_full_protection_check_aslr.py` | Canary + PIE/ASLR + NX + RELRO |

## Binary component — Format String (arbitrary read/write), 3 layers

| Files | Layer |
|---|---|
| `fmt_1_baseline_vuln.c`, `fmt_1_baseline_build.sh` | No protection |
| `fmt_2_fortify_partial_vuln.c`, `fmt_2_fortify_partial_build.sh` | glibc `_FORTIFY_SOURCE=2` |
| `fmt_3_fixed_vuln.c`, `fmt_3_fixed_build.sh` | Source-level fix (`printf("%s", buf)`) |

## Reports

- `Phase1_Web_Report.docx` / `Phase1_Binary_Report.docx` — earlier draft component reports
- `Report-z5727209.pdf` — final combined submitted report (authoritative version)

## Course

COMP6441/COMP6841 Security Engineering, UNSW, 2026 T2.
