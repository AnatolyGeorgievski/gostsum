/*! gostsum — контрольные суммы файлов (GOST / SHA / SHA3).

Copyright (c) 2011-2026 Anatoly Georgievski
SPDX-License-Identifier: MIT

Изначально под Windows (MinGW/MSYS2); Linux и FreeBSD — тот же make.

*/
#include <stdlib.h>
#if defined(_MSC_VER) || defined(__MINGW32__) || defined(__MINGW64__)
#include <malloc.h>
#endif
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <locale.h>
#include <sys/stat.h>
#include "r3_args.h"
#include "hmac.h"

#ifndef FALSE
#define FALSE 0
#endif

struct {
    char* alg;
    char* passwd;
    char* output_file;
    int check;
    int list;
    int verbose;
} cli = {
.alg="gost",
.passwd=NULL,
.output_file=NULL,
.list = FALSE,
.check = FALSE,
.verbose = FALSE,
};

static GOptionEntry entries[] =
{
  { "alg",      'a', 0, G_OPTION_ARG_STRING,    &cli.alg,   "hash algorithm", "md5|sha|sha256|sha512|sha3-256|sha3-512|gost94|gost|gost512" },
  { "check",    'c', 0, G_OPTION_ARG_NONE,      &cli.check,   "Read checksums from FILE and verify", NULL },
  { "list",     'l', 0, G_OPTION_ARG_NONE,      &cli.list,    "List digest algorithms", NULL },
  { "verbose",  'v', 0, G_OPTION_ARG_NONE,      &cli.verbose, "Be verbose", NULL },
  { NULL }
};

static int hash_file(const MDigest* md, FILE* f, uint8_t* hash)
{
    /* STRIBOG/vector init пишет v8di — нужен выровненный контекст. */
    size_t need = (md->ctx_size + 63u) & ~63u;
    uint8_t* ctx;
    uint8_t buf[8192];
    size_t n;
#if defined(_MSC_VER) || defined(__MINGW32__) || defined(__MINGW64__)
    ctx = _aligned_malloc(need, 64);
#else
    ctx = aligned_alloc(64, need);
#endif
    if (ctx == NULL) return 0;
    md->init(ctx);
    while ((n = fread(buf, 1, sizeof buf, f)) > 0)
        md->update(ctx, buf, (unsigned)n);
    if (ferror(f)) {
#if defined(_MSC_VER) || defined(__MINGW32__) || defined(__MINGW64__)
        _aligned_free(ctx);
#else
        free(ctx);
#endif
        return 0;
    }
    md->final(ctx, hash, md->hash_len);
#if defined(_MSC_VER) || defined(__MINGW32__) || defined(__MINGW64__)
    _aligned_free(ctx);
#else
    free(ctx);
#endif
    return 1;
}

static void print_hash_line(const uint8_t* hash, unsigned hlen, const char* name)
{
    unsigned i;
    for (i = 0; i < hlen; i++)
        printf("%02X", hash[i]);
    printf(" *%s\n", name);
}

static int hex_nibble(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Строка вида: HEX *name  или  HEX  name (как md5sum). */
static int parse_check_line(char* line, char** hex_out, char** name_out)
{
    char* p = line;
    char* hex;
    while (*p == ' ' || *p == '\t') p++;
    if (*p == '#' || *p == '\0' || *p == '\n' || *p == '\r') return 0;
    hex = p;
    while (isxdigit((unsigned char)*p)) p++;
    if (p == hex) return -1;
    *p++ = '\0';
    while (*p == ' ' || *p == '\t') p++;
    if (*p == '*' || *p == ' ') p++;
    while (*p == ' ' || *p == '\t') p++;
    if (*p == '\0' || *p == '\n' || *p == '\r') return -1;
    {
        char* end = p + strlen(p);
        while (end > p && (end[-1] == '\n' || end[-1] == '\r')) *--end = '\0';
    }
    /* длина hex должна быть чётной */
    if ((strlen(hex) & 1) != 0) return -1;
    for (char* h = hex; *h; h++) {
        if (hex_nibble((unsigned char)*h) < 0) return -1;
    }
    *hex_out = hex;
    *name_out = p;
    return 1;
}

static int hex_eq_hash(const char* hex, const uint8_t* hash, unsigned hlen)
{
    unsigned i;
    if (strlen(hex) != hlen * 2) return 0;
    for (i = 0; i < hlen; i++) {
        int a = hex_nibble((unsigned char)hex[i * 2]);
        int b = hex_nibble((unsigned char)hex[i * 2 + 1]);
        if (a < 0 || b < 0) return 0;
        if ((uint8_t)((a << 4) | b) != hash[i]) return 0;
    }
    return 1;
}

static int select_alg(const char* name)
{
    if (strcmp(name, "gost") == 0 || strcmp(name, "gost256") == 0) return MD_STRIBOG_256;
    if (strcmp(name, "gost512") == 0) return MD_STRIBOG_512;
    if (strcmp(name, "gost94") == 0) return MD_GOSTR341194;
    if (strcmp(name, "sha") == 0) return MD_SHA1;
    if (strcmp(name, "sha256") == 0) return MD_SHA256;
    if (strcmp(name, "sha3-224") == 0) return MD_SHA3_224;
    if (strcmp(name, "sha3-256") == 0) return MD_SHA3_256;
    if (strcmp(name, "sha3-384") == 0) return MD_SHA3_384;
    if (strcmp(name, "sha3-512") == 0) return MD_SHA3_512;
    if (strcmp(name, "sha224") == 0) return MD_SHA224;
    if (strcmp(name, "sha384") == 0) return MD_SHA384;
    if (strcmp(name, "sha512-224") == 0) return MD_SHA512_224;
    if (strcmp(name, "sha512-256") == 0) return MD_SHA512_256;
    if (strcmp(name, "sha512-384") == 0) return MD_SHA512_384;
    if (strcmp(name, "sha512") == 0) return MD_SHA512;
    if (strcmp(name, "md5") == 0) return MD_MD5;
    return MD_NONE;
}

static int process_one(const MDigest* md, const char* filename)
{
    uint8_t hash[128];
    FILE* f;
    int from_stdin = (strcmp(filename, "-") == 0);

    if (from_stdin)
        f = stdin;
    else {
        f = fopen(filename, "rb");
        if (f == NULL) {
            fprintf(stderr, "gostsum: %s: cannot open\n", filename);
            return 1;
        }
    }
    if (!hash_file(md, f, hash)) {
        fprintf(stderr, "gostsum: %s: read error\n", filename);
        if (!from_stdin) fclose(f);
        return 1;
    }
    if (!from_stdin) fclose(f);
    print_hash_line(hash, md->hash_len, from_stdin ? "-" : filename);
    return 0;
}

static int check_list(const MDigest* md, const char* listname)
{
    FILE* list;
    char line[4096];
    int failed = 0, ok = 0, bad_fmt = 0;
    int from_stdin = (strcmp(listname, "-") == 0);

    list = from_stdin ? stdin : fopen(listname, "r");
    if (list == NULL) {
        fprintf(stderr, "gostsum: %s: cannot open\n", listname);
        return 1;
    }
    while (fgets(line, sizeof line, list)) {
        char* hex = NULL;
        char* name = NULL;
        int pr = parse_check_line(line, &hex, &name);
        FILE* f;
        uint8_t hash[128];
        if (pr == 0) continue;
        if (pr < 0) {
            bad_fmt++;
            continue;
        }
        f = (strcmp(name, "-") == 0) ? stdin : fopen(name, "rb");
        if (f == NULL) {
            printf("%s: FAILED open or read\n", name);
            failed++;
            continue;
        }
        if (!hash_file(md, f, hash)) {
            if (f != stdin) fclose(f);
            printf("%s: FAILED open or read\n", name);
            failed++;
            continue;
        }
        if (f != stdin) fclose(f);
        if (hex_eq_hash(hex, hash, md->hash_len)) {
            if (cli.verbose) printf("%s: OK\n", name);
            ok++;
        } else {
            printf("%s: FAILED\n", name);
            failed++;
        }
    }
    if (!from_stdin) fclose(list);
    if (bad_fmt)
        fprintf(stderr, "gostsum: WARNING: %d line(s) improperly formatted\n", bad_fmt);
    if (cli.verbose || failed)
        fprintf(stderr, "gostsum: %d computed checksum%s, %d OK, %d FAILED\n",
                ok + failed, (ok + failed) == 1 ? "" : "s", ok, failed);
    return failed ? 1 : 0;
}

const char* description=
"Метод вычисления контрольных сумм gost94 описан в ГОСТ Р 34.11-94.\n"
"Метод gost и gost512 (STRIBOG-256/512) описан в ГОСТ Р 34.11-2012.\n"
"Метод sha1 описан в FIPS-180-2\n"
"Метод sha2 описан в FIPS-180-3 / FIPS-180-4\n"
"Метод sha3 описан в FIPS-202, NIST SP 800-185\n"
"Без файлов или с именем «-» читаю stdin. -c — проверка списка сумм."
;

int main(int argc, char *argv[])
{
    setlocale(LC_ALL, "");
    setlocale(LC_NUMERIC, "C");
    GOptionContext *context = g_option_context_new ("[FILE]...\nPrint or check GOST / SHA checksums");
    g_option_context_add_main_entries (context, entries, NULL);
    g_option_context_set_summary(context, description);
    if (!g_option_context_parse (context, &argc, &argv, NULL))
        exit (1);

    extern void digest_list_print(void);
    if (cli.list) {
        digest_list_print();
        return 0;
    }

    {
        int hash_alg_id = select_alg(cli.alg);
        const MDigest* md = digest_select(hash_alg_id);
        int status = 0;
        int i;

        if (md == NULL) {
            printf("MD: algorithm '%s' not found\n", cli.alg);
            exit (1);
        }

        if (cli.check) {
            if (argc <= 1)
                status = check_list(md, "-");
            else {
                for (i = 1; i < argc; i++)
                    status |= check_list(md, argv[i]);
            }
            return status;
        }

        if (argc <= 1)
            return process_one(md, "-");

        for (i = 1; i < argc; i++)
            status |= process_one(md, argv[i]);
        return status;
    }
}
