/*
 * Phase 1 - Binary Group - Format String - Step 1: Baseline
 * =============================================================
 * The program reads a line of input and passes it DIRECTLY to printf()
 * as the format string itself, instead of using it as data:
 *
 *     printf(buf);              // VULNERABLE
 *     instead of
 *     printf("%s", buf);        // safe - buf is just data here
 *
 * This means anything that looks like a format specifier (%x, %p, %n,
 * %s ...) inside YOUR input gets interpreted by printf as an instruction,
 * not printed as literal text.
 *
 * Two things become possible:
 *   1. READ: %x / %p let you read values off the stack that were never
 *      meant to be exposed (this is how you can leak addresses/canaries
 *      in a more advanced binary).
 *   2. WRITE: %n writes the number of characters printed SO FAR into an
 *      address you control - this is a full arbitrary-write primitive.
 *
 * Your goal: flip the global variable `secret_unlocked` from 0 to
 * non-zero using ONLY the format string bug (no buffer overflow is
 * needed or possible here - the buffer is read safely with a bounded
 * read()).
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>

int secret_unlocked = 0;   // global variable - lives at a fixed, known
                            // address because this binary is compiled
                            // without PIE (see build.sh)

void print_flag() {
    printf("[+] secret_unlocked is now %d - here is your flag:\n", secret_unlocked);
    printf("    FLAG{format_string_arbitrary_write}\n");
}

int main() {
    char buf[256];
    setvbuf(stdout, NULL, _IONBF, 0);

    printf("=== Baseline Format String Challenge ===\n");
    printf("secret_unlocked is currently %d, stored at %p\n", secret_unlocked, (void*)&secret_unlocked);
    printf("Enter some text: ");

    memset(buf, 0, sizeof(buf));
    read(0, buf, sizeof(buf) - 1);

    printf(buf);   // <-- THE VULNERABILITY: user input used AS the format string

    printf("\n");
    if (secret_unlocked) {
        print_flag();
    } else {
        printf("secret_unlocked is still %d - try again.\n", secret_unlocked);
    }
    return 0;
}
