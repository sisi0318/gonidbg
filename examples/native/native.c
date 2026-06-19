// Tiny AArch64 shared library used by gonidbg's example + integration test.
// No libc dependency except the explicit imports below (strlen / uname /
// readlink), which exercise the dynamic linker resolving against bundled bionic
// and bionic in turn issuing syscalls gonidbg services.
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

// --- syscall exercises (call real bionic, which issues the syscall) ----------

struct utsname {
    char sysname[65], nodename[65], release[65], version[65], machine[65], domainname[65];
};
int uname(struct utsname *u);
long readlink(const char *path, char *buf, unsigned long bufsiz);

// uname() -> SYS_uname; returns strlen(machine), i.e. len("aarch64") == 7
int uname_machine_len(void) {
    struct utsname u;
    if (uname(&u) != 0) return -1;
    return (int)strlen(u.machine);
}

// readlink("/proc/self/exe") -> SYS_readlinkat; returns the link length
int readlink_exe_len(void) {
    char buf[128];
    long n = readlink("/proc/self/exe", buf, sizeof(buf));
    return (int)n;
}

// --- JNI exercise -----------------------------------------------------------
// env is a JNIEnv*; *(void***)env is the JNINativeInterface function table.
// Call slots by index (no jni.h needed) to exercise gonidbg's JNI dispatch:
// GetVersion, NewStringUTF/GetStringUTFLength, FindClass, NewObjectArray /
// Set/GetObjectArrayElement / GetArrayLength, ThrowNew / ExceptionCheck / Clear.
// Returns 1+5+3+1+1+1 == 12 when all behave.
int jni_probe(void *env) {
    void **t = *(void ***)env;
    int   ver = ((int  (*)(void *))t[4])(env);                                    // GetVersion -> 0x10006
    void *s   = ((void *(*)(void *, const char *))t[167])(env, "hello");          // NewStringUTF
    int   ul  = ((int  (*)(void *, void *))t[168])(env, s);                       // GetStringUTFLength -> 5
    void *cls = ((void *(*)(void *, const char *))t[6])(env, "java/lang/String"); // FindClass
    void *arr = ((void *(*)(void *, int, void *, void *))t[172])(env, 3, cls, 0); // NewObjectArray(3)
    ((void (*)(void *, void *, int, void *))t[174])(env, arr, 1, s);              // arr[1] = s
    void *got = ((void *(*)(void *, void *, int))t[173])(env, arr, 1);            // arr[1]
    int   al  = ((int  (*)(void *, void *))t[171])(env, arr);                     // GetArrayLength -> 3
    int   same = (got == s) ? 1 : 0;
    ((int (*)(void *, void *, const char *))t[14])(env, cls, "boom");             // ThrowNew
    int   pend = ((unsigned char (*)(void *))t[228])(env) ? 1 : 0;                // ExceptionCheck -> 1
    ((void (*)(void *))t[17])(env);                                               // ExceptionClear
    int   clr  = ((unsigned char (*)(void *))t[228])(env) ? 0 : 1;                // -> 1
    return (ver == 0x10006) + ul + al + same + pend + clr;
}
