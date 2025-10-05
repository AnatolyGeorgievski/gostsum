/*! gostsum
    Вычисление хеш функций от файлов
	
Copyright (C) Anatoly Georgievskii.
License GPLv3+: GNU GPL version 3 or later <https://gnu.org/licenses/gpl.html>.
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.


*/
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
//#include <glib.h>
#include <locale.h>
#include <libgen.h>
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
//  { "passwd",   'p', 0, G_OPTION_ARG_STRING,    &cli.passwd,   "password", "***" },
//  { "output",   'o', 0, G_OPTION_ARG_FILENAME,  &cli.output_file,   "output file name", "*.*" },
  { "check",    'c', 0, G_OPTION_ARG_NONE,      &cli.check,   "Read from FILE and check", NULL },
  { "list",     'l', 0, G_OPTION_ARG_NONE,      &cli.list,    "List digest algorithms", NULL },
  { "verbose",  'v', 0, G_OPTION_ARG_NONE,      &cli.verbose, "Be verbose", NULL },
  { NULL }
};
static int r2_get_contents(char* filename, char** contents, size_t *length, void* error)
{
    struct stat     statbuf;
    int res = stat(filename, &statbuf);
    if (res==0) {
        char* data = malloc(statbuf.st_size);
        FILE * f = fopen(filename, "rb");
        if (f!=NULL) {
            *length = fread(data,1,statbuf.st_size, f);
            *contents = data;
            fclose(f);
        }
    }
    return res==0;
}
#if 0
void r2_hash(const char* filename, unsigned int alg_id)
{
    char* contents=NULL;// файл прошивки
    gsize length = 0; // размер файла прошивки
    if (r2_get_contents(filename, &contents, &length, NULL)){
        const MDigest* md = digest_select(alg_id);
        if (md==NULL) {
            printf("MD: algorithm not found\n");
            g_free(contents); contents=NULL;
            return;
        }
        uint8_t hash[md->hash_len];
        digest(md, hash, md->hash_len, (uint8_t*)contents, length);
        int i;
        for (i=0;i<md->hash_len;i++){
            printf("%02x", hash[i]);
        }
        char* base = basename((char*)filename);
        printf(" %s\n", base);
        free(contents); contents=NULL;
    }
}
#endif // 0

/*!
Метод вычисления контрольных сумм описан в FIPS-180-2. Входными данными при
проверке должны быть полученные ранее выходные данные этой программы.
По умолчанию печатает строку с контрольной суммой, пробел, знак, показывающий
режим ввода («*» для двоичных, пробел для текстовых или если двоичность не
важна) и имя каждого ФАЙЛА.

*/
const char* description=
"Метод вычисления контрольных сумм gost94 описан в ГОСТ Р 34.11-94.\n"
"Метод gost и gost512 (STRIBOG-256/512) описан в ГОСТ Р 34.11-2012.\n"
"Метод sha1 описан в FIPS-180-2\n"
"Метод sha2 описан в FIPS-180-3, August 2015\n"
"Метод sha3 описан в FIPS-180-4, FIPS-202, NIST SP 800-185"
;
int main(int argc, char *argv[])
{
    setlocale(LC_ALL, "");
    setlocale(LC_NUMERIC, "C");
//  GError *error = NULL;
    GOptionContext *context = g_option_context_new ("[FILE]\nPrint or check GOST 34.11-2012/SHA256 (256-bit) checksums");
    g_option_context_add_main_entries (context, entries, NULL/*GETTEXT_PACKAGE*/);
//    g_option_context_set_description(context, description);
    g_option_context_set_summary(context, description);
    if (!g_option_context_parse (context, &argc, &argv, NULL/*&error*/))
    {
      //printf ("option parsing failed: %s\n", error->message);
      exit (1);
    }
    int hash_alg_id=MD_NONE;
    if (strcmp(cli.alg, "gost")==0){
        hash_alg_id=MD_STRIBOG_256;
    } else
    if (strcmp(cli.alg, "gost256")==0){
        hash_alg_id=MD_STRIBOG_256;
    } else
    if (strcmp(cli.alg, "gost512")==0){
        hash_alg_id=MD_STRIBOG_512;
    } else
    if (strcmp(cli.alg, "gost94")==0){
        //hash_alg_id=MD_GOSTR341194_CP;
        hash_alg_id=MD_GOSTR341194;// набор параметров тестовый
    } else
    if (strcmp(cli.alg, "sha")==0){
        hash_alg_id=MD_SHA1;
    } else
    if (strcmp(cli.alg, "sha256")==0){
        hash_alg_id=MD_SHA3_256;
    } else
    if (strcmp(cli.alg, "sha3-256")==0){
        hash_alg_id=MD_SHA3_256;
    } else
    if (strcmp(cli.alg, "sha3-512")==0){
        hash_alg_id=MD_SHA3_512;
    } else
    if (strcmp(cli.alg, "sha224")==0){
        hash_alg_id=MD_SHA224;
    } else
    if (strcmp(cli.alg, "sha384")==0){
        hash_alg_id=MD_SHA384;
    } else
    if (strcmp(cli.alg, "sha512")==0){
        hash_alg_id=MD_SHA512;
    } else
    if (strcmp(cli.alg, "md5")==0){
        hash_alg_id=MD_MD5;
    }
	extern void digest_list_print();
	if (cli.list){ 
		digest_list_print();
		return 0;
	}

    const MDigest* md = digest_select(hash_alg_id);
    if (md==NULL) {
        printf("MD: algorithm '%s' not found\n", cli.alg);
        exit (1);
    }
    uint8_t hash[md->hash_len];
//    digest(md, hash, md->hash_len, (uint8_t*)contents, length);
    char* contents=NULL;// файл прошивки
    size_t length = 0; // размер файла прошивки

    int i;
    for (i=1; i<argc; i++) {
        char* filename = argv[i];
        if (r2_get_contents(filename, &contents, &length, NULL)) {
extern void sha3_256(const uint8_t *data, size_t len, uint8_t *tag);
/*			sha3_256((uint8_t*)contents, length, hash);
            for (i=0;i<md->hash_len;i++){
                printf("%02X", hash[i]);
            }
			printf("\n"); */
            digest(md, hash, md->hash_len, (uint8_t*)contents, length);
            int i;
            for (i=0;i<md->hash_len;i++){
                printf("%02X", hash[i]);
            }
            //char* base = basename(filename);
            printf(" %c%s\n", '*', filename);
            //g_free(base);
            free(contents); contents=NULL; length=0;
        } else {// сообщить об ошибке
            printf("file not found '%s'\n", filename);
        }
    }
    return 0;
}
