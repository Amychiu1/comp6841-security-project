/*
 * Phase 1 - Binary Group - Step 1: Baseline Buffer Overflow
 * =============================================================
 * This program reads a name into a fixed-size stack buffer using an
 * unbounded read (gets-style). There is NO bounds checking at all.
 *
 * There is also a function, win(), that is never called by normal
 * program flow. Your goal is to overflow the buffer far enough to
 * overwrite the saved return address on the stack, so that when
 * greet() returns, execution jumps into win() instead of back to main().
 *
 * This is a classic "ret2win" challenge - a good first binary
 * exploitation exercise because you don't need to inject shellcode,
 * you just need to redirect control flow to code that already exists
 * in the binary.
 *
 * Compiled deliberately WITHOUT any modern protections - see build.sh
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>

void win() {
    printf("\n[+] win() reached! Here is your flag:\n");
    printf("    FLAG{ret2win_baseline_no_protections}\n\n");
}

void greet() {
    char name[64];
    printf("What's your name? ");
    fflush(stdout);

    // VULNERABLE: no bounds checking whatsoever. read() with a size far
    // larger than the buffer means we can write well past the end of
    // `name` and into the saved return address on the stack.
    read(0, name, 512);

    printf("Hello, %s!\n", name);
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("=== Baseline Buffer Overflow Challenge ===\n");
    greet();
    printf("Goodbye!\n");
    return 0;
}
