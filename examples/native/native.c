// Tiny AArch64 shared library used by gonidbg's example + integration test.
// No libc dependency except an explicit strlen import (to exercise the dynamic
// linker resolving an import against bundled bionic libc and executing it).
//
// Build (committed prebuilt is native.so; rebuild with):
//   zig cc -target aarch64-linux-gnu -shared -fPIC -nostdlib \
//          -fno-builtin -fno-stack-protector -O2 -o native.so native.c

int add(int a, int b) { return a + b; }

long fib(long n) {
    long a = 0, b = 1;
    while (n-- > 0) { long t = a + b; a = b; b = t; }
    return a;
}

// writes a+b through a guest pointer — exercises memory writes from guest code
void sum_into(int *out, int a, int b) { *out = a + b; }

// imports strlen from libc — exercises cross-module linking + bionic execution
unsigned long strlen(const char *s);
int slen(const char *s) { return (int)strlen(s); }
