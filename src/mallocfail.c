/*
https://stackoverflow.com/questions/1711170/unit-testing-for-failed-malloc

I saw a cool solution to this problem which was presented to me by S.
Paavolainen. The idea is to override the standard malloc(), which you can do
just in the linker, by a custom allocator which

 1. reads the current execution stack of the thread calling malloc()
 2. checks if the stack exists in a database that is stored on hard disk
    1. if the stack does not exist, adds the stack to the database and returns NULL
    2. if the stack did exist already, allocates memory normally and returns

Then you just run your unit test many times---this system automatically
enumerates through different control paths to malloc() failure and is much more
efficient and reliable than e.g. random testing.

*/

#define _GNU_SOURCE

#define uthash_malloc libc_malloc

#include <dlfcn.h>
#include <execinfo.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sha3.h"
#include "uthash.h"

#define UNW_LOCAL_ONLY
#include <libunwind.h>
#include <unistd.h>

#define HASH_BITS      256
#define HASH_BYTES     ((HASH_BITS) / 8)
#define HASH_HEX_BYTES ((HASH_BITS) / 4)

extern int force_libc;
extern void *(*libc_malloc)(size_t);
extern void *(*libc_calloc)(size_t, size_t);
extern void *(*libc_realloc)(void *, size_t);

struct traces_s {
    UT_hash_handle hh;
    char hash[HASH_HEX_BYTES + 1];
};

static struct traces_s *traces = NULL;
static char strbuf[1024];
static char *hashfile = NULL;
static char hashfile_default[] = "mallocfail_hashes";
static int debug = -1;
static int fail_count = 0;
static int max_fail_count = -1;

static void hex_encode(const unsigned char *in, unsigned int in_len, char *encoded)
{
    int i;
    for (i = 0; i < in_len; i++) {
        sprintf(&encoded[i * 2], "%02x", in[i]);
    }
}

static int append_stack_context(const char *filename, const char *hash_str)
{
    FILE *fptr;

    struct traces_s *t = (struct traces_s *)libc_malloc(sizeof(struct traces_s));
    memcpy(t->hash, hash_str, HASH_HEX_BYTES);
    t->hash[HASH_HEX_BYTES] = '\0';
    HASH_ADD_STR(traces, hash, t);

    fptr = fopen(filename, "at");
    if (!fptr) {
        return 1;
    }
    fprintf(fptr, "%s\n", hash_str);

    fclose(fptr);
    return 0;
}

static void load_traces(const char *filename)
{
    FILE *fptr;
    char buf[1024];

    fptr = fopen(filename, "rt");
    if (!fptr) {
        return;
    }

    while (!feof(fptr)) {
        if (fgets(buf, 1024, fptr)) {
            if (buf[strlen(buf) - 1] == '\n') {
                buf[strlen(buf) - 1] = '\0';

                struct traces_s *t = (struct traces_s *)libc_malloc(sizeof(struct traces_s));
                memcpy(t->hash, buf, HASH_HEX_BYTES);
                t->hash[HASH_HEX_BYTES] = '\0';
                HASH_ADD_STR(traces, hash, t);
            }
        }
    }
    fclose(fptr);
}

static int stack_context_exists(const char *filename, const char *hash_str)
{
    struct traces_s *found_trace;
    int rc;

    force_libc = 1;
    if (traces == NULL) {
        load_traces(filename);
    }

    HASH_FIND_STR(traces, hash_str, found_trace);
    if (found_trace) {
        rc = 1;
    } else {
        append_stack_context(filename, hash_str);
        rc = 0;
    }

    force_libc = 0;
    return rc;
}

static int (*libc_on_exit)(void);

static bool create_backtrace_hash(char *hash_str)
{
    const unsigned char *hash;
    sha3_context hash_context;

    force_libc = 1;

    sha3_Init256(&hash_context);

    if (!libc_on_exit) {
        libc_on_exit = dlsym(RTLD_DEFAULT, "on_exit");
    }

#if DEBUG
    fprintf(stderr, "------- Start trace -------\n");
#endif
    unw_cursor_t cursor;
    unw_context_t uc;

    unw_getcontext(&uc);
    unw_init_local(&cursor, &uc);
    while (unw_step(&cursor) > 0) {
        unw_word_t ip, sp, off = 0;
        unw_get_reg(&cursor, UNW_REG_IP, &ip);
        unw_get_reg(&cursor, UNW_REG_SP, &sp);

        unw_proc_info_t pi;
        unw_get_proc_info(&cursor, &pi);

        char symbol[256] = "<unknown>";
        if (unw_get_proc_name(&cursor, symbol, sizeof(symbol), &off) != 0) {
            Dl_info info = {0};
            dladdr((void *)ip, &info);
            void *stable_addr = (void *)((char *)ip - (char *)info.dli_fbase);

            snprintf(symbol, sizeof(symbol), "%p", stable_addr);
        }

        if (memcmp(symbol, "_dl_", 4) == 0) {
            return false;
        }

        if ((uintptr_t)libc_on_exit <= pi.end_ip && (uintptr_t)libc_on_exit >= pi.start_ip) {
            return false;
        }

#if DEBUG
        fprintf(stderr, "%s@%lx-%lx %lx %p\n", symbol, pi.start_ip, pi.end_ip, (long)off,
            (void *)libc_on_exit);
#endif
        int len = snprintf(strbuf, 1024, "%s+%lx\n", symbol, (long)off);
        sha3_Update(&hash_context, strbuf, len);
    }

    hash = sha3_Finalize(&hash_context);
    hex_encode(hash, HASH_BYTES, hash_str);
#if DEBUG
    fprintf(stderr, "------- End trace -------\n");
#endif

    force_libc = 0;

    return true;
}

static void print_backtrace(void)
{
    force_libc = 1;
    fprintf(stderr, "------- Start trace -------\n");

    unw_cursor_t cursor;
    unw_context_t uc;

    unw_getcontext(&uc);
    unw_init_local(&cursor, &uc);
    while (unw_step(&cursor) > 0) {
        unw_word_t ip, sp, off;
        unw_get_reg(&cursor, UNW_REG_IP, &ip);
        unw_get_reg(&cursor, UNW_REG_SP, &sp);

        char symbol[256] = "<unknown>";
        unw_get_proc_name(&cursor, symbol, sizeof(symbol), &off);

        fprintf(stderr, "%s %lx\n", symbol, (long)off);
    }

    fprintf(stderr, "------- End trace -------\n");
    force_libc = 0;
}

int should_malloc_fail(void)
{
    char hash_str[1024];
    int exists;

    if (max_fail_count == -1) {
        char *env = getenv("MALLOCFAIL_FAIL_COUNT");
        if (env) {
            max_fail_count = atoi(env);
            if (max_fail_count < 0) {
                max_fail_count = 0;
            }
        } else {
            max_fail_count = 0;
        }
    }

    if (max_fail_count > 0 && fail_count >= max_fail_count) {
        return 0;
    }

    force_libc = 1;
    if (!hashfile) {
        hashfile = getenv("MALLOCFAIL_FILE");
        if (!hashfile) {
            hashfile = hashfile_default;
        }
    }

    if (debug == -1) {
        if (getenv("MALLOCFAIL_DEBUG")) {
            debug = 1;
        } else {
            debug = 0;
        }
    }
    force_libc = 0;

    if (!create_backtrace_hash(hash_str)) {
        return 0;
    }

    exists = stack_context_exists(hashfile, hash_str);
    if (!exists && debug) {
        print_backtrace();
    }
    if (exists) {
        return 0;
    } else {
        fail_count++;
        return 1;
    }
}
