/*! \brief The Keyed-Hash Message Authentication Code (HMAC)

    Генерация секретных хешей HMAC_SHA256

    \see [FIPS PUB 198-1] The Keyed-Hash Message Authentication Code (HMAC), July 2008
    http://csrc.nist.gov/publications/fips/fips198-1/FIPS-198-1_final.pdf
тестирование
    http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/HMAC_SHA1.pdf
    http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/HMAC_SHA256.pdf

    \see [RFC 4231] HMAC-SHA Identifiers and Test Vectors, December 2005
    \see [RFC 4868] Using HMAC-SHA-256, HMAC-SHA-384, and HMAC-SHA-512 with IPsec, May 2007
    \see [RFC 5869] Extract-and-Expand HKDF, May 2010
    \see [RFC 6234] SHAs, HMAC-SHAs, and HKDF, May 2011
    \see [RFC 6986] GOST R 34.11-2012: Hash Function, August 2013
    \see [RFC 7836] Cryptographic Algorithms for GOST, March 2016
    \see [TC26PBKDF2] http://www.tc26.ru/methods/containers_v2/Addition_to_PKCS5_v2_1.pdf

 */
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#if defined(__linux__) || defined(__FreeBSD__)
#include <netinet/in.h>
#else
#if defined(__BYTE_ORDER__) && (__BYTE_ORDER__==__ORDER_LITTLE_ENDIAN__)
#define htonl(x) __builtin_bswap32(x)
#define ntohl(x) __builtin_bswap32(x)
#else
#define htonl(x) (x)
#define ntohl(x) (x)
#endif // __BYTE_ORDER__
#endif
#include "hmac.h"
typedef struct _GSList GSList;
struct _GSList {
    void* data;
    GSList* next;
};

//typedef uint32_t v4si __attribute__((__vector_size__(16)));
typedef uint64_t v2di __attribute__((__vector_size__(16)));

typedef struct _HmacCtx HmacCtx;
struct _HmacCtx
{
    const MDigest * md;
    void* ctx;// контекст hash функции
    v2di* K;// __attribute__((__aligned__(16)));
};
#define IPAD 0x3636363636363636ULL
#define OPAD 0x5C5C5C5C5C5C5C5CULL
const v2di ipad = {IPAD, IPAD};
const v2di opad = {OPAD, OPAD};
static void hmac_init(HmacCtx* ctx, const void* key, unsigned int klen)
{
    const MDigest* md = ctx->md;
    const unsigned int block_len= md->block_len;// 128, 64, 32 байта
    const unsigned int hash_len = md->hash_len;
    unsigned int i;
    if (klen > block_len)
    {
        for (i=hash_len/sizeof(v2di); i<block_len/sizeof(v2di); i++) ctx->K[i] = (v2di){0};
        md->init   (ctx->ctx);
        md->update (ctx->ctx, key,  klen);
        md->final  (ctx->ctx, ctx->K, hash_len);
    }
    else if (klen < block_len)
    {
        __builtin_memcpy(ctx->K, key, klen);
        __builtin_memset(((uint8_t*)ctx->K) + klen, 0, block_len-klen);
    }
    else
    {
        __builtin_memcpy(ctx->K, key, block_len);
    }
    for (i=0; i< block_len/sizeof(v2di); i++) ctx->K[i] ^= (opad);
}
// 1. длина ключа равна длине блока
static void hmac_init2(HmacCtx* ctx)
{
    const MDigest* md = ctx->md;
    const unsigned int block_len= md->block_len;
    unsigned int i;
    for (i=0; i< block_len/sizeof(v2di); i++) ctx->K[i] ^= (opad^ipad);
    md->init   (ctx->ctx);
    md->update (ctx->ctx, (void*)ctx->K,  block_len);
}

static inline
void hmac_update(HmacCtx* ctx, const uint8_t * msg, unsigned int mlen)
{
    ctx->md->update (ctx->ctx, msg, mlen);
}
static void hmac_final(HmacCtx* ctx, uint8_t * tag, unsigned int tlen)
{
    const MDigest* md = ctx->md;
    const unsigned int block_len=md->block_len;//512 бит// 64 байта
    const unsigned int hash_len =md->hash_len;//512 бит// 64 байта
    uint64_t H[(hash_len+7)>>3];

    md->final  (ctx->ctx, H, hash_len);
    unsigned int i;
    for (i=0; i< block_len/sizeof(v2di); i++) ctx->K[i] ^= (opad^ipad);
    md->init   (ctx->ctx);
    md->update (ctx->ctx, (void*)ctx->K,  block_len);

    md->update (ctx->ctx, (void*)H,  hash_len);
    md->final  (ctx->ctx, tag, tlen);
}
#ifndef BN_ALIGN
#define BN_ALIGN_BYTES 32
#define BN_ALIGN __attribute__((aligned(BN_ALIGN_BYTES)))
#endif
/*! \brief message digest
 */
void digest(const MDigest* md, uint8_t * tag, unsigned int tlen, const uint8_t * msg, unsigned int mlen)
{
    uint8_t ct[md->ctx_size] BN_ALIGN;
    void* ctx = ct;//__builtin_alloca(md->ctx_size);//_aligned_malloc(md->ctx_size, 16);//
    md->init   (ctx);
    md->update (ctx, msg, mlen);
    md->final  (ctx, tag, tlen);
//    _aligned_free(ctx);
}
int digest_verify(const MDigest* md, const uint8_t * tag, unsigned int tlen, const uint8_t * msg, unsigned int mlen)
{
    uint8_t hash[tlen];
	uint8_t ct[md->ctx_size] BN_ALIGN;
    void* ctx = ct;//__builtin_alloca(md->ctx_size);
    md->init   (ctx);
    md->update (ctx, msg, mlen);
    md->final  (ctx, hash, tlen);
    return __builtin_memcmp(hash,tag,tlen)==0;
}

/*! \brief Salted secure hash algorithm
формат представления паролей в LDAP
    "{SSHA}"+Base64.encode(SHA1('secret'+'salt')+'salt')
    */
void ssha(const MDigest* md, uint8_t * tag, unsigned int tlen, const uint8_t * msg, unsigned int mlen, const uint8_t * salt, unsigned int slen)
{
	uint8_t buf[md->ctx_size] BN_ALIGN;
    void* ctx = buf;//__builtin_alloca(md->ctx_size);
    md->init   (ctx);
    md->update (ctx, msg,  mlen);
    md->update (ctx, salt, slen);
    md->final  (ctx, tag,  tlen);

}
/*! PBKDF1
    \see PKCS #5 v2.0: Password-Based Cryptography Standard
 */
/*
void pbkdf1(const MDigest* md, void* dk, unsigned int dklen, const uint8_t *passwd, unsigned int plen,
                     const uint8_t *salt, unsigned int slen, unsigned int c)
{
   uint8_t tag[md->hash_len];
   uint8_t buf[md->ctx_size] BN_ALIGN;
   void* ctx = buf;//__builtin_alloca(md->ctx_size);//uint64_t ctx[(md->ctx_size+7)>>3];
   md->init   (ctx);
   md->update (ctx, passwd,  plen);
   md->update (ctx, salt, slen);
   md->final  (ctx, tag,  md->hash_len);
   int i;
   for (i=1;i<c;i++){
       md->init   (ctx);
       md->update (ctx, tag,  md->hash_len);
       md->final  (ctx, tag,  md->hash_len);
   }
   if (dklen>md->hash_len) dklen = md->hash_len;
   __builtin_memcpy(dk, tag, dklen);
}
*/
void hmac(const MDigest* md, uint8_t * tag, unsigned int tlen, const uint8_t * msg, unsigned int mlen, const uint8_t * key, unsigned int klen)
{
    HmacCtx ct;
    v2di K[md->block_len/sizeof(v2di)];
	uint8_t buf[md->ctx_size] BN_ALIGN;
    void* ctx = buf;//__builtin_alloca(md->ctx_size);//uint64_t ctx[(md->ctx_size+7)>>3];
    ct.md = md;
    ct.K = K;
    ct.ctx = ctx;
    hmac_init  (&ct, key, klen);
    hmac_init2 (&ct);
    hmac_update(&ct, msg, mlen);

    hmac_final (&ct, tag, tlen);
}

//void prf_tls_hmac(const MDigest* md, const uint8_t * secret, const uint8_t *label, const uint8_t *seed)
/*! \brief Алгоритм диверсификации KDF_GOSTR3411_2012_256
Р 50.1.113-256 4.4 Алгоритм KDF_GOSTR3411_2012_256 на основе хэш-функции 𝐠с длиной выхода,
равной 256 битам, определенной в ГОСТ Р 34.11–2012 (раздел 8), задает функцию
диверсификации для порождения ключевого материала длиной 256 бит, использующую
алгоритм HMAC_GOSTR3411_2012_256, описанный в 4.1.1. Результатом работы
данного алгоритма является значение функции KDF_256, аргументами которой являются
байтовые строки 'K_in' 'label' и 'seed'

*/
void kdf_256(void* kek, const uint8_t *key, unsigned int klen, /*const uint8_t *label, unsigned int llen,*/ const uint8_t *seed, unsigned int slen)
{
    const MDigest* md = digest_select(MD_STRIBOG_256);
    unsigned int msg_len = 8+slen;
    uint8_t msg[msg_len];
    if (1) {
    msg[0] = 0x01;
    __builtin_memcpy(&msg[1], "\x26\xbd\xb8\x78", 4);
    msg[5] = 0x00;
    }
    __builtin_memcpy(&msg[6], seed, slen);
    msg[6+slen] = 0x01;
    msg[7+slen] = 0x00;
    printf("kdf_256 message:");
    int i;
    for (i=0;i<msg_len; i++) {
        if ((i & 0xF)==0) printf("\n%04X:", i);
        printf(" %02x", msg[i]);
    }
    printf("\n");
    hmac(md, kek, 32, msg, msg_len, key, klen);
}
#if 0
/*! Р 50.1.113-2016 Экспорт и импорт ключей на параметрах szOID_Gost28147_89_TC26_Z_ParamSet */
void kek_self_test ()
{
    uint8_t Ke [32];
    uint8_t key[32];
    uint8_t kek[32];
    int i;
    for (i=0;i<32; i++) Ke [i]=i;
    for (i=0;i<32; i++) key[i]=i+0x20;
    const MDigest* md = digest_select(MD_STRIBOG_256);
    uint8_t msg[] = "\x01\x26\xbd\xb8\x78\x00\xaf\x21\x43\x41\x45\x65\x63\x78\x01\x00";
    uint8_t tag[32];
    hmac(md, tag, 32, msg, 16, Ke, 32);
    printf("hmac_test:");
    for (i=0;i<32; i++) {
        if ((i & 0xF)==0) printf("\n%04X:", i);
        printf(" %02x", tag[i]);
    }
    printf("\n");
    uint8_t seed[] = "\xaf\x21\x43\x41\x45\x65\x63\x78";
    kdf_256 (kek, Ke, 32, seed, 8);
    printf("kdf_256_test:");
    for (i=0;i<32; i++) {
        if ((i & 0xF)==0) printf("\n%04X:", i);
        printf(" %02x", kek[i]);
    }
//    for (i=0;i<32; i++) printf("%02x ", kek[i]);
    printf("\n");

    uint8_t kdf[] = "a1 aa 5f 7d e4 02 d7 b3 d3 23 f2 99 1c 8d 45 34"
    "01 31 37 01 0a 83 75 4f d0 af 6d 7c d4 92 2e d9";
    extern uint64_t magma_cmac(uint32_t *K, uint64_t iv, uint8_t* data, size_t len);
    extern void magma_ekb (uint32_t* K, const uint8_t *key, int klen, int ekb);
    extern uint64_t magma_encrypt(uint32_t *K, uint64_t v);
    extern uint64_t magma_decrypt(uint32_t *K, uint64_t v);
    uint32_t K[32];
    magma_ekb(K, kek, 32, 0);
    uint64_t v[4];
    //v = *(uint64_t*)key;
    __builtin_memcpy(v, key, 8);
    v[0] = magma_encrypt(K, v[0]);
    printf("kdf_256_test: CEK_ENC %016llX\n", v[0]);
    v[0] = magma_decrypt(K, v[0]);
    printf("kdf_256_test: CEK_ENC %016llX\n", v[0]);

/*
CEK_MAC
    be 33 f0 52
CEK_ENC
    d1 55 47 f8 ee 85 12 1b c8 7d 4b 10 27 d2 60 27
    ec c0 71 bb a6 e7 2f 3f ec 6f 62 0f 56 83 4c 5a
*/
}
#endif
/*! \brief

*/
/* Р 50.1.113-2016
4.2.1 Псевдослучайные функции протокола TLS
4.2.1.1 PRF_TLS_GOSTR3411_2012_256

*/

/*! \brief Password-based key derivation function PKCS#5
 */
void pbkdf2_hmac(const MDigest* md, void* dk, unsigned int dklen, const uint8_t *passwd, unsigned int plen,
                 const uint8_t *salt, unsigned int slen, unsigned int c)
{
    HmacCtx ct;
    const unsigned int block_len=md->block_len;
    v2di K[block_len/sizeof(v2di)];
	uint8_t buf[md->ctx_size] BN_ALIGN;
    void* ctx = buf;//__builtin_alloca(md->ctx_size);//uint64_t ctx[(md->ctx_size+7)>>3];
    ct.md = md;
    ct.K = K;
    ct.ctx = ctx;

    hmac_init (&ct, passwd, plen);

    const unsigned int hash_len = md->hash_len;
    const unsigned int xlen = (md->hash_len+(sizeof(v2di)-1))/sizeof(v2di);
    v2di H[xlen] __attribute__((__aligned__(16)));
    v2di U[xlen] __attribute__((__aligned__(16)));
    uint32_t S;
    int i,j, offset=0;
    uint32_t count=1;
    while (dklen>0)
    {
        S = ntohl(count);
        hmac_init2 (&ct);
        hmac_update(&ct, salt, slen);
        hmac_update(&ct, (void*)&S, 4);
        hmac_final (&ct, (void*)U, hash_len);

        for (i=0; i<xlen; i++) H[i] = U[i];
        for (j=1; j<c; j++)
        {
            hmac_init2 (&ct);
            hmac_update(&ct, (void*)U, hash_len);
            hmac_final (&ct, (void*)U, hash_len);
            for (i=0; i<xlen; i++) H[i] ^= U[i];
        }
        int len =(dklen>hash_len)? hash_len:dklen;
        __builtin_memcpy((uint8_t*)dk + offset, H, len);
        dklen -= len;
        offset+= len;
        //for (i=0; i<hash_len/4; i++) printf("%08X ",H[i]); printf("\n");
        count ++;
    }
}

//extern const MDigest __start__MDigest[];
//extern const MDigest __stop__MDigest[];
static GSList* digest_list = NULL;
void digest_register(const MDigest* md)
{
    GSList* list = malloc(sizeof(GSList));
    list->data = (void*)md;
    list->next = digest_list;
    digest_list= list;
//    digest_list = g_slist_append(digest_list, (void*)md);
}
static void __attribute__((destructor)) digest_fini()
{
    GSList* list = digest_list;
    digest_list=NULL;
    while (list){
        GSList* next = list->next;
        free(list);
        list = next;
    }
}
/*! \brief выбор хеш-функции по идентификатору
 */
const MDigest* digest_select(int id)
{
    GSList* list = digest_list;
    while(list){
        const MDigest* md = list->data;
        if (md->id == id) return md;
        list = list->next;
    }
#if 0
    const MDigest *md = SEGMENT_START(MDigest);
    const MDigest *md_top = SEGMENT_STOP(MDigest);
//    int i=0;
    while (md < md_top)
    {
        if (md->id == id) return md;
//        printf("%d %s\n",i, md->name);
        md++; //i++;
    }
#endif
    return NULL;
}
void digest_list_print(){
    GSList* list = digest_list;
	
    while(list){
        const MDigest* md = list->data;
        printf("`%s`\n",md->name);
        list = list->next;
    }
}
#ifdef TEST_HMAC
/*!
	$ /c/MinGW64/bin/gcc -march=corei7 -O3 -s stribog.c sha.c sha512.c hmac.c gosthash.c -o hmac.exe -m64
	$ /c/MinGW64/bin/gcc -march=corei7 -O3 -s stribog.c sha.c sha512.c hmac.c gosthash.c md5.c -o hmac.exe -m32 -DTEST_HMAC
	$./hmac.exe
 */
int main()
{

//    const MDigest *md = SEGMENT_START(MDigest);
//    const MDigest *md_top = SEGMENT_STOP(MDigest);
    int i=0;
    GSList* list = digest_list;
    while (list)
    {
        const MDigest* md = list->data;
        printf("%d %s\n",i, md->name);
        list = list->next;
        i++;
    }
    {
        //printf("HMAC_STRIBOG\n");
        struct
        {
            int id;
            char* msg;
            char* hash;
        } hmac_tests[] =
        {
            { // RFC 6986            GOST R 34.11-2012: Hash Function         August 2013
                MD_STRIBOG_512,
                "012345678901234567890123456789012345678901234567890123456789012",
                "\x1b\x54\xd0\x1a\x4a\xf5\xb9\xd5\xcc\x3d\x86\xd6\x8d\x28\x54\x62"
                "\xb1\x9a\xbc\x24\x75\x22\x2f\x35\xc0\x85\x12\x2b\xe4\xba\x1f\xfa"
                "\x00\xad\x30\xf8\x76\x7b\x3a\x82\x38\x4c\x65\x74\xf0\x24\xc3\x11"
                "\xe2\xa4\x81\x33\x2b\x08\xef\x7f\x41\x79\x78\x91\xc1\x64\x6f\x48"

//                "\x48\x6f\x64\xc1\x91\x78\x79\x41\x7f\xef\x08\x2b\x33\x81\xa4\xe2"
//                "\x11\xc3\x24\xf0\x74\x65\x4c\x38\x82\x3a\x7b\x76\xf8\x30\xad\x00"
//                "\xfa\x1f\xba\xe4\x2b\x12\x85\xc0\x35\x2f\x22\x75\x24\xbc\x9a\xb1"
//                "\x62\x54\x28\x8d\xd6\x86\x3d\xcc\xd5\xb9\xf5\x4a\x1a\xd0\x54\x1b"
            },
            { // RFC 6986            GOST R 34.11-2012: Hash Function         August 2013
                MD_STRIBOG_256,
                "012345678901234567890123456789012345678901234567890123456789012",
                "\x9d\x15\x1e\xef\xd8\x59\x0b\x89\xda\xa6\xba\x6c\xb7\x4a\xf9\x27"
                "\x5d\xd0\x51\x02\x6b\xb1\x49\xa4\x52\xfd\x84\xe5\xe5\x7b\x55\x00"
//                "\x00\x55\x7b\xe5\xe5\x84\xfd\x52\xa4\x49\xb1\x6b\x02\x51\xd0\x5d"
//                "\x27\xf9\x4a\xb7\x6c\xba\xa6\xda\x89\x0b\x59\xd8\xef\x1e\x15\x9d"
            },
            {// RFC 6986            GOST R 34.11-2012: Hash Function         August 2013
            //  10.2.1.  For Hash Function with 512-Bit Hash Code
                MD_STRIBOG_512,
                "\xd1\xe5\x20\xe2\xe5\xf2\xf0\xe8\x2c\x20\xd1\xf2\xf0\xe8\xe1\xee"
                "\xe6\xe8\x20\xe2\xed\xf3\xf6\xe8\x2c\x20\xe2\xe5\xfe\xf2\xfa\x20"
                "\xf1\x20\xec\xee\xf0\xff\x20\xf1\xf2\xf0\xe5\xeb\xe0\xec\xe8\x20"
                "\xed\xe0\x20\xf5\xf0\xe0\xe1\xf0\xfb\xff\x20\xef\xeb\xfa\xea\xfb"
                "\x20\xc8\xe3\xee\xf0\xe5\xe2\xfb",

                "\x1e\x88\xe6\x22\x26\xbf\xca\x6f\x99\x94\xf1\xf2\xd5\x15\x69\xe0"
                "\xda\xf8\x47\x5a\x3b\x0f\xe6\x1a\x53\x00\xee\xe4\x6d\x96\x13\x76"
                "\x03\x5f\xe8\x35\x49\xad\xa2\xb8\x62\x0f\xcd\x7c\x49\x6c\xe5\xb3"
                "\x3f\x0c\xb9\xdd\xdc\x2b\x64\x60\x14\x3b\x03\xda\xba\xc9\xfb\x28"
//                "\x28\xfb\xc9\xba\xda\x03\x3b\x14\x60\x64\x2b\xdc\xdd\xb9\x0c\x3f"
//                "\xb3\xe5\x6c\x49\x7c\xcd\x0f\x62\xb8\xa2\xad\x49\x35\xe8\x5f\x03"
//                "\x76\x13\x96\x6d\xe4\xee\x00\x53\x1a\xe6\x0f\x3b\x5a\x47\xf8\xda"
//                "\xe0\x69\x15\xd5\xf2\xf1\x94\x99\x6f\xca\xbf\x26\x22\xe6\x88\x1e"
            },
            {// RFC 6986            GOST R 34.11-2012: Hash Function         August 2013
            //  10.2.2.  For Hash Function with 256-Bit Hash Code
                MD_STRIBOG_256,
                "\xd1\xe5\x20\xe2\xe5\xf2\xf0\xe8\x2c\x20\xd1\xf2\xf0\xe8\xe1\xee"
                "\xe6\xe8\x20\xe2\xed\xf3\xf6\xe8\x2c\x20\xe2\xe5\xfe\xf2\xfa\x20"
                "\xf1\x20\xec\xee\xf0\xff\x20\xf1\xf2\xf0\xe5\xeb\xe0\xec\xe8\x20"
                "\xed\xe0\x20\xf5\xf0\xe0\xe1\xf0\xfb\xff\x20\xef\xeb\xfa\xea\xfb"
                "\x20\xc8\xe3\xee\xf0\xe5\xe2\xfb",
                "\x9d\xd2\xfe\x4e\x90\x40\x9e\x5d\xa8\x7f\x53\x97\x6d\x74\x05\xb0"
                "\xc0\xca\xc6\x28\xfc\x66\x9a\x74\x1d\x50\x06\x3c\x55\x7e\x8f\x50"
//                "\x50\x8f\x7e\x55\x3c\x06\x50\x1d\x74\x9a\x66\xfc\x28\xc6\xca\xc0"
//                "\xb0\x05\x74\x6d\x97\x53\x7f\xa8\x5d\x9e\x40\x90\x4e\xfe\xd2\x9d"
            },
//ГОСТ Р 34.11-94 с параметрами Test
            {
                MD_GOSTR341194,
                "",
                "\xce\x85\xb9\x9c\xc4\x67\x52\xff\xfe\xe3\x5c\xab\x9a\x7b\x02\x78\xab\xb4\xc2\xd2\x05\x5c\xff\x68\x5a\xf4\x91\x2c\x49\x49\x0f\x8d"
            },
            {
                MD_GOSTR341194,
                "a",
                "\xd4\x2c\x53\x9e\x36\x7c\x66\xe9\xc8\x8a\x80\x1f\x66\x49\x34\x9c\x21\x87\x1b\x43\x44\xc6\xa5\x73\xf8\x49\xfd\xce\x62\xf3\x14\xdd"
            },
            {
                MD_GOSTR341194,
                "abc",
                "\xf3\x13\x43\x48\xc4\x4f\xb1\xb2\xa2\x77\x72\x9e\x22\x85\xeb\xb5\xcb\x5e\x0f\x29\xc9\x75\xbc\x75\x3b\x70\x49\x7c\x06\xa4\xd5\x1d"
            },
            {
                MD_GOSTR341194,
                "message digest",
                "\xad\x44\x34\xec\xb1\x8f\x2c\x99\xb6\x0c\xbe\x59\xec\x3d\x24\x69\x58\x2b\x65\x27\x3f\x48\xde\x72\xdb\x2f\xde\x16\xa4\x88\x9a\x4d"
            },
            {
                MD_GOSTR341194,
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                "\x95\xc1\xaf\x62\x7c\x35\x64\x96\xd8\x02\x74\x33\x0b\x2c\xff\x6a\x10\xc6\x7b\x5f\x59\x70\x87\x20\x2f\x94\xd0\x6d\x23\x38\xcf\x8e"
            },
            {
                MD_GOSTR341194,
                "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
                "\xcc\x17\x8d\xca\xd4\xdf\x61\x9d\xca\xa0\x0a\xac\x79\xca\x35\x5c\x00\x14\x4e\x4a\xda\x27\x93\xd7\xbd\x9b\x35\x18\xea\xd3\xcc\xd3"
            },
            {
                MD_GOSTR341194,
                "This is message, length=32 bytes",
                "\xb1\xc4\x66\xd3\x75\x19\xb8\x2e\x83\x19\x81\x9f\xf3\x25\x95\xe0\x47\xa2\x8c\xb6\xf8\x3e\xff\x1c\x69\x16\xa8\x15\xa6\x37\xff\xfa"
            },
            {
                MD_GOSTR341194,
                "Suppose the original message has length = 50 bytes",
                "\x47\x1a\xba\x57\xa6\x0a\x77\x0d\x3a\x76\x13\x06\x35\xc1\xfb\xea\x4e\xf1\x4d\xe5\x1f\x78\xb4\xae\x57\xdd\x89\x3b\x62\xf5\x52\x08"
            },
//ГОСТ Р 34.11-94 с параметрами CryptoPro
            {
                MD_GOSTR341194_CP,
                "",
                "\x98\x1e\x5f\x3c\xa3\x0c\x84\x14\x87\x83\x0f\x84\xfb\x43\x3e\x13\xac\x11\x01\x56\x9b\x9c\x13\x58\x4a\xc4\x83\x23\x4c\xd6\x56\xc0"
            },
            {
                MD_GOSTR341194_CP,
                "a",
                "\xe7\x4c\x52\xdd\x28\x21\x83\xbf\x37\xaf\x00\x79\xc9\xf7\x80\x55\x71\x5a\x10\x3f\x17\xe3\x13\x3c\xef\xf1\xaa\xcf\x2f\x40\x30\x11"
            },
            {
                MD_GOSTR341194_CP,
                "abc",
                "\xb2\x85\x05\x6d\xbf\x18\xd7\x39\x2d\x76\x77\x36\x95\x24\xdd\x14\x74\x74\x59\xed\x81\x43\x99\x7e\x16\x3b\x29\x86\xf9\x2f\xd4\x2c"
            },
            {
                MD_GOSTR341194_CP,
                "message digest",
                "\xbc\x60\x41\xdd\x2a\xa4\x01\xeb\xfa\x6e\x98\x86\x73\x41\x74\xfe\xbd\xb4\x72\x9a\xa9\x72\xd6\x0f\x54\x9a\xc3\x9b\x29\x72\x1b\xa0"
            },
            {
                MD_GOSTR341194_CP,
                "The quick brown fox jumps over the lazy dog",
                "\x90\x04\x29\x4a\x36\x1a\x50\x8c\x58\x6f\xe5\x3d\x1f\x1b\x02\x74\x67\x65\xe7\x1b\x76\x54\x72\x78\x6e\x47\x70\xd5\x65\x83\x0a\x76"
            },
            {
                MD_GOSTR341194_CP,
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                "\x73\xb7\x0a\x39\x49\x7d\xe5\x3a\x6e\x08\xc6\x7b\x6d\x4d\xb8\x53\x54\x0f\x03\xe9\x38\x92\x99\xd9\xb0\x15\x6e\xf7\xe8\x5d\x0f\x61"
            },
            {
                MD_GOSTR341194_CP,
                "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
                "\x6b\xc7\xb3\x89\x89\xb2\x8c\xf9\x3a\xe8\x84\x2b\xf9\xd7\x52\x90\x59\x10\xa7\x52\x8a\x61\xe5\xbc\xe0\x78\x2d\xe4\x3e\x61\x0c\x90"
            },
            {
                MD_GOSTR341194_CP,
                "This is message, length=32 bytes",
                "\x2c\xef\xc2\xf7\xb7\xbd\xc5\x14\xe1\x8e\xa5\x7f\xa7\x4f\xf3\x57\xe7\xfa\x17\xd6\x52\xc7\x5f\x69\xcb\x1b\xe7\x89\x3e\xde\x48\xeb"
            },
            {
                MD_GOSTR341194_CP,
                "Suppose the original message has length = 50 bytes",
                "\xc3\x73\x0c\x5c\xbc\xca\xcf\x91\x5a\xc2\x92\x67\x6f\x21\xe8\xbd\x4e\xf7\x53\x31\xd9\x40\x5e\x5f\x1a\x61\xdc\x31\x30\xa6\x50\x11"
            },
            {
                MD_SHA1,
                "",
                "\xda\x39\xa3\xee\x5e\x6b\x4b\x0d\x32\x55\xbf\xef\x95\x60\x18\x90\xaf\xd8\x07\x09"
            },
            {
                MD_SHA224,
                "",
                "\xd1\x4a\x02\x8c\x2a\x3a\x2b\xc9\x47\x61\x02\xbb\x28\x82\x34\xc4\x15\xa2\xb0\x1f\x82\x8e\xa6\x2a\xc5\xb3\xe4\x2f"
            },
            {
                MD_SHA256,
                "",
                "\xe3\xb0\xc4\x42\x98\xfc\x1c\x14\x9a\xfb\xf4\xc8\x99\x6f\xb9\x24\x27\xae\x41\xe4\x64\x9b\x93\x4c\xa4\x95\x99\x1b\x78\x52\xb8\x55"
            },
            {
                MD_SHA384,
                "",
                "\x38\xb0\x60\xa7\x51\xac\x96\x38\x4c\xd9\x32\x7e\xb1\xb1\xe3\x6a\x21\xfd\xb7\x11\x14\xbe\x07\x43"
                "\x4c\x0c\xc7\xbf\x63\xf6\xe1\xda\x27\x4e\xde\xbf\xe7\x6f\x65\xfb\xd5\x1a\xd2\xf1\x48\x98\xb9\x5b"
            },
            {
                MD_SHA512,
                "",
                "\xcf\x83\xe1\x35\x7e\xef\xb8\xbd\xf1\x54\x28\x50\xd6\x6d\x80\x07\xd6\x20\xe4\x05\x0b\x57\x15\xdc\x83\xf4\xa9\x21\xd3\x6c\xe9\xce"
                "\x47\xd0\xd1\x3c\x5d\x85\xf2\xb0\xff\x83\x18\xd2\x87\x7e\xec\x2f\x63\xb9\x31\xbd\x47\x41\x7a\x81\xa5\x38\x32\x7a\xf9\x27\xda\x3e"
            },
// MD5 test suite:
            {
                MD_MD5,
                "",
                "\xd4\x1d\x8c\xd9\x8f\x00\xb2\x04\xe9\x80\x09\x98\xec\xf8\x42\x7e"
            },
            {
                MD_MD5,
                "a",
                "\x0c\xc1\x75\xb9\xc0\xf1\xb6\xa8\x31\xc3\x99\xe2\x69\x77\x26\x61"
            },
            {
                MD_MD5,
                "abc",
                "\x90\x01\x50\x98\x3c\xd2\x4f\xb0\xd6\x96\x3f\x7d\x28\xe1\x7f\x72"
            },
            {
                MD_MD5,
                "message digest",
                "\xf9\x6b\x69\x7d\x7c\xb7\x93\x8d\x52\x5a\x2f\x31\xaa\xf1\x61\xd0"
            },
            {
                MD_MD5,
                "abcdefghijklmnopqrstuvwxyz",
                "\xc3\xfc\xd3\xd7\x61\x92\xe4\x00\x7d\xfb\x49\x6c\xca\x67\xe1\x3b"
            },
            {
                MD_MD5,
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                "\xd1\x74\xab\x98\xd2\x77\xd9\xf5\xa5\x61\x1c\x2c\x9f\x41\x9d\x9f"
            },
            {
                MD_MD5,
                "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
                "\x57\xed\xf4\xa2\x2b\xe3\xc9\x55\xac\x49\xda\x2e\x21\x07\xb6\x7a"
            },
            {0 }

        };
        printf("DIGEST:\n");
        uint8_t hash[64];// __attribute__((__aligned__(16)));
        int i;
        for (i=0; i<80 && hmac_tests[i].msg; i++)
        {
            const MDigest *md = digest_select(hmac_tests[i].id);// MD_STRIBOG_256_digest;
			if (md==NULL) continue;
            digest(md, hash, md->hash_len, (uint8_t*)hmac_tests[i].msg, strlen(hmac_tests[i].msg));
//    for(i=0; i<8;i++) printf(" %016" PRIX64, ctx.H[i]); printf("\n");
            if (memcmp(hash, hmac_tests[i].hash, md->hash_len)==0) printf("%d %s OK\n", i, md->name);
            else {
                printf("%d %s Fail\n", i, md->name);
                printf("HASH:\n");
                int n;
                for (n=0; n<md->hash_len; n++){
                    printf("\\x%02x", hash[n]);
                    if ((n&0xF)==0xF)printf("\n");
                }

            }
        }
    }
    if(1){// HMAC
        char k0[] =
            "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F"
            "\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2A\x2B\x2C\x2D\x2E\x2F\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3A\x3B\x3C\x3D\x3E\x3F"
            "\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4A\x4B\x4C\x4D\x4E\x4F\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5A\x5B\x5C\x5D\x5E\x5F"
            "\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6A\x6B\x6C\x6D\x6E\x6F\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7A\x7B\x7C\x7D\x7E\x7F"
            "\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8A\x8B\x8C\x8D\x8E\x8F\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9A\x9B\x9C\x9D\x9E\x9F"
            "\xA0\xA1\xA2\xA3\xA4\xA5\xA6\xA7\xA8\xA9\xAA\xAB\xAC\xAD\xAE\xAF\xB0\xB1\xB2\xB3\xB4\xB5\xB6\xB7\xB8\xB9\xBA\xBB\xBC\xBD\xBE\xBF"
            "\xC0\xC1\xC2\xC3\xC4\xC5\xC6\xC7";
        struct
        {
            int id;
            char* key;
            int klen;
            char* msg;
            int mlen;
            char* hash;
            int hash_len;
        } hmac_tests []=
        {
/*
            {
                MD_STRIBOG_256,
                "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"
                "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"
                , 20,
                "Hi There", 8,
//"\xf0\x34\x22\xdf\xa3\x7a\x50\x7c\xa1\x26\xce\x01\xb8\xeb\xa6\xb7"
//"\xfd\xda\x8f\x8a\x60\xdd\x8f\x27\x03\xe3\xa3\x72\x12\x0b\x82\x94", 32
                "\x8b\x92\x53\x05\x5e\x75\x25\xe5\xf8\x35\x3b\x26\xfd\xe9\x58\x62"
                "\xf4\x61\xd3\x32\x86\xce\x01\xf6\xd1\x15\xd2\x69\x8e\x5e\x3d\xf0",	32
            },
            {
                MD_STRIBOG_256,
                "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa", 20,
                "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
                "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
                "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
                "\xdd\xdd", 50,
                "\xb6\x2f\x46\xd8\x98\x7f\x46\x41\xbc\x85\xbd\xd7\xf9\x12\xae\x35"
                "\xce\x6e\x3e\x8f\xe7\x31\xed\x2d\x7e\x99\x66\x9e\xb5\x20\x60\x77",	32
            },
            */
            { // пример из http://www.tc26.ru/methods/recommendation/%D0%A2%D0%9A26%D0%90%D0%9B%D0%93.pdf HMAC_GOSTR3411_2012_256
                MD_STRIBOG_256,
                //Ключ K:
				k0, 32,
//				"00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f"
//"10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f"

//              "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
//              "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
//"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
//"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
//              , 32,
//"\x1F\x1E\x1D\x1C\x1B\x1A\x19\x18\x17\x16\x15\x14\x13\x12\x11\x10"
//"\x0F\x0E\x0D\x0C\x0B\x0A\x09\x08\x07\x06\x05\x04\x03\x02\x01\x00"
//, 64,
                //Данные T:
                "\x01\x26\xbd\xb8\x78\x00\xaf\x21\x43\x41\x45\x65\x63\x78\x01\x00", 16,
//				"\x00\x01\x78\x63\x65\x45\x41\x43\x21\xAF\x00\x78\xB8\xBD\x26\x01", 16,
                //Значение HMAC256(K,T):
                "\xa1\xaa\x5f\x7d\xe4\x02\xd7\xb3\xd3\x23\xf2\x99\x1c\x8d\x45\x34"
                "\x01\x31\x37\x01\x0a\x83\x75\x4f\xd0\xaf\x6d\x7c\xd4\x92\x2e\xd9",32
            },
/*
            {
                MD_STRIBOG_512,
                "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"
                "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b", 20,
                "Hi There", 8,
\x86\xb6\xa0\x6b\xfa\x9f\x19\x74\xaf\xf6\xcc\xd7\xfa\x3f\x83\x5f
\x0b\xd8\x50\x39\x5d\x60\x84\xef\xc4\x7b\x9d\xda\x86\x1a\x2c\xdf
\x0d\xca\xf9\x59\x16\x07\x33\xd5\x26\x9f\x65\x67\x96\x6d\xd7\xa9
\xf9\x32\xa7\x7c\xd6\xf0\x80\x01\x2c\xd4\x76\xf1\xc2\xcc\x31\xbb
                "\x16\x15\x61\x0a\x29\xef\x16\x27\xb2\xb3\x5c\x90\x0d\x24\xe8\x42"
                "\x9a\xe5\x1a\x25\x8a\xdb\xaa\x06\x98\xc3\x1c\x80\xe1\x2e\x61\x0b"
                "\xfc\xca\xcf\x24\x80\xfc\x1a\xf7\xc3\x8a\x29\x5c\xb1\x7e\x4b\xc5"
                "\x65\x4f\x58\xe5\x48\xa8\xc8\x5f\xc7\x6e\x1e\xb0\x84\x76\x0b\x48",	64
            },
            {
                MD_STRIBOG_512,
                "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa", 20,
                "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
                "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
                "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
                "\xdd\xdd", 50,
                "\x15\xfd\x61\x73\x3a\x87\x8f\x8e\x9e\xa8\x55\x30\x8c\x27\x74\x72"
                "\x85\xa7\x25\xa8\x2d\x53\xd1\x51\x16\xf6\x92\x61\xd1\xf7\x91\x54"
                "\xcc\xe8\xb7\xf5\xae\x95\xb2\x2d\x0e\xdd\xe5\xfd\xa0\xc1\xa1\x0d"
                "\xc9\x48\x6d\xf5\xdb\x8d\x44\x17\x9b\xa6\xc5\x5b\x88\x4e\xa2\xa6", 64
            },
			*/
            {
                MD_STRIBOG_512,
//                "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
//                "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f", 32,
                k0, 32,
                "\x01\x26\xbd\xb8\x78\x00\xaf\x21\x43\x41\x45\x65\x63\x78\x01\x00", 16,

                "\xa5\x9b\xab\x22\xec\xae\x19\xc6\x5f\xbd\xe6\xe5\xf4\xe9\xf5\xd8"
                "\x54\x9d\x31\xf0\x37\xf9\xdf\x9b\x90\x55\x00\xe1\x71\x92\x3a\x77"
                "\x3d\x5f\x15\x30\xf2\xed\x7e\x96\x4c\xb2\xee\xdc\x29\xe9\xad\x2f"
                "\x3a\xfe\x93\xb2\x81\x4f\x79\xf5\x00\x0f\xfc\x03\x66\xc2\x51\xe6", 64
            },
            {
                MD_GOSTR341194,
                "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"
                "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b", 20,
                "Hi There", 8,
                "\xc0\xb4\x65\xe5\x58\xe8\xcb\xd3\x97\xfe\x5b\xb1\x8d\x22\x89\xab"
                "\x6a\x31\x9b\x87\x1f\xa8\xa7\x46\xbf\x33\x4f\x69\xa7\xfd\x64\xbd",	32
            },
            {
                MD_GOSTR341194,
                "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa", 20,
                "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
                "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
                "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
                "\xdd\xdd", 50,
                "\x97\x12\x2C\x50\x7C\x98\x1F\x12\x75\xEE\xC2\xD3\xA8\x1E\x8A\x33"
                "\xD7\x18\x61\x25\x0E\xEE\xDF\x25\x40\xEF\xC8\x64\x6E\xEE\xE1\x6E", 32
            },
            {
                MD_MD5,
                "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b", 16,
                "Hi There", 8,
                "\x92\x94\x72\x7a\x36\x38\xbb\x1c\x13\xf4\x8e\xf8\x15\x8b\xfc\x9d", 16
            },
            {
                MD_MD5,
                "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa", 16,
                "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
                "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
                "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
                "\xdd\xdd", 50,
                "\x56\xbe\x34\x52\x1d\x14\x4c\x88\xdb\xb8\xc7\x33\xf0\xe8\xb3\xf6", 16
            },


            {
                MD_SHA512,	k0, 128,
                "Sample message for keylen=blocklen", 34,
                "\xFC\x25\xE2\x40\x65\x8C\xA7\x85\xB7\xA8\x11\xA8\xD3\xF7\xB4\xCA\x48\xCF\xA2\x6A\x8A\x36\x6B\xF2\xCD\x1F\x83\x6B\x05\xFC\xB0\x24"
                "\xBD\x36\x85\x30\x81\x81\x1D\x6C\xEA\x42\x16\xEB\xAD\x79\xDA\x1C\xFC\xB9\x5E\xA4\x58\x6B\x8A\x0C\xE3\x56\x59\x6A\x55\xFB\x13\x47", 64
            },
            {
                MD_SHA512,	k0, 64,
                "Sample message for keylen<blocklen", 34,
                "\xFD\x44\xC1\x8B\xDA\x0B\xB0\xA6\xCE\x0E\x82\xB0\x31\xBF\x28\x18\xF6\x53\x9B\xD5\x6E\xC0\x0B\xDC\x10\xA8\xA2\xD7\x30\xB3\x63\x4D"
                "\xE2\x54\x5D\x63\x9B\x0F\x2C\xF7\x10\xD0\x69\x2C\x72\xA1\x89\x6F\x1F\x21\x1C\x2B\x92\x2D\x1A\x96\xC3\x92\xE0\x7E\x7E\xA9\xFE\xDC", 64
            },
            {
                MD_SHA512,	k0, 200,
                "Sample message for keylen=blocklen", 34,
                "\xD9\x3E\xC8\xD2\xDE\x1A\xD2\xA9\x95\x7C\xB9\xB8\x3F\x14\xE7\x6A\xD6\xB5\xE0\xCC\xE2\x85\x07\x9A\x12\x7D\x3B\x14\xBC\xCB\x7A\xA7"
                "\x28\x6D\x4A\xC0\xD4\xCE\x64\x21\x5F\x2B\xC9\xE6\x87\x0B\x33\xD9\x74\x38\xBE\x4A\xAA\x20\xCD\xA5\xC5\xA9\x12\xB4\x8B\x8E\x27\xF3", 64
            },
            {
                MD_SHA512,	k0, 49,
                "Sample message for keylen<blocklen, with truncated tag", 54,
                "\x00\xF3\xE9\xA7\x7B\xB0\xF0\x6D\xE1\x5F\x16\x06\x03\xE4\x2B\x50\x28\x75\x88\x08\x59\x66\x64\xC0\x3E\x1A\xB8\xFB\x2B\x07\x67\x78", 32
            },
            {
                MD_SHA384,	k0, 128,
                "Sample message for keylen=blocklen", 34,
                "\x63\xC5\xDA\xA5\xE6\x51\x84\x7C\xA8\x97\xC9\x58\x14\xAB\x83\x0B\xED\xED\xC7\xD2\x5E\x83\xEE\xF9"
                "\x19\x5C\xD4\x58\x57\xA3\x7F\x44\x89\x47\x85\x8F\x5A\xF5\x0C\xC2\xB1\xB7\x30\xDD\xF2\x96\x71\xA9", 48
            },
            {
                MD_SHA384,	k0, 48,
                "Sample message for keylen<blocklen", 34,
                "\x6E\xB2\x42\xBD\xBB\x58\x2C\xA1\x7B\xEB\xFA\x48\x1B\x1E\x23\x21\x14\x64\xD2\xB7\xF8\xC2\x0B\x9F"
                "\xF2\x20\x16\x37\xB9\x36\x46\xAF\x5A\xE9\xAC\x31\x6E\x98\xDB\x45\xD9\xCA\xE7\x73\x67\x5E\xEE\xD0", 48
            },
            {
                MD_SHA384,	k0, 200,
                "Sample message for keylen=blocklen", 34,
                "\x5B\x66\x44\x36\xDF\x69\xB0\xCA\x22\x55\x12\x31\xA3\xF0\xA3\xD5\xB4\xF9\x79\x91\x71\x3C\xFA\x84"
                "\xBF\xF4\xD0\x79\x2E\xFF\x96\xC2\x7D\xCC\xBB\xB6\xF7\x9B\x65\xD5\x48\xB4\x0E\x85\x64\xCE\xF5\x94", 48
            },
            {
                MD_SHA384,	k0, 49,
                "Sample message for keylen<blocklen, with truncated tag", 54,
                "\xC4\x81\x30\xD3\xDF\x70\x3D\xD7\xCD\xAA\x56\x80\x0D\xFB\xD2\xBA\x24\x58\x32\x0E\x6E\x1F\x98\xFE", 24
            },
            {
                MD_SHA1,	k0, 64,
                "Sample message for keylen=blocklen", 34,
                "\x5F\xD5\x96\xEE\x78\xD5\x55\x3C\x8F\xF4\xE7\x2D\x26\x6D\xFD\x19\x23\x66\xDA\x29", 20
            },
            {
                MD_SHA1,	k0, 20,
                "Sample message for keylen<blocklen", 34,
                "\x4C\x99\xFF\x0C\xB1\xB3\x1B\xD3\x3F\x84\x31\xDB\xAF\x4D\x17\xFC\xD3\x56\xA8\x07", 20
            },
            {
                MD_SHA1,	k0, 100,
                "Sample message for keylen=blocklen", 34,
                "\x2D\x51\xB2\xF7\x75\x0E\x41\x05\x84\x66\x2E\x38\xF1\x33\x43\x5F\x4C\x4F\xD4\x2A", 20
            },
            {
                MD_SHA1,	k0, 49,
                "Sample message for keylen<blocklen, with truncated tag", 54,
                "\xFE\x35\x29\x56\x5C\xD8\xE2\x8C\x5F\xA7\x9E\xAC", 12
            },

            {
                MD_SHA224,	k0, 64,
                "Sample message for keylen=blocklen", 34,
                "\xC7\x40\x5E\x3A\xE0\x58\xE8\xCD\x30\xB0\x8B\x41\x40\x24\x85\x81\xED\x17\x4C\xB3\x4E\x12\x24\xBC\xC1\xEF\xC8\x1B", 28
            },
            {
                MD_SHA224,	k0, 28,
                "Sample message for keylen<blocklen", 34,
                "\xE3\xD2\x49\xA8\xCF\xB6\x7E\xF8\xB7\xA1\x69\xE9\xA0\xA5\x99\x71\x4A\x2C\xEC\xBA\x65\x99\x9A\x51\xBE\xB8\xFB\xBE", 28
            },
            {
                MD_SHA224,	k0, 100,
                "Sample message for keylen=blocklen", 34,
                "\x91\xC5\x25\x09\xE5\xAF\x85\x31\x60\x1A\xE6\x23\x00\x99\xD9\x0B\xEF\x88\xAA\xEF\xB9\x61\xF4\x08\x0A\xBC\x01\x4D", 28
            },
            {
                MD_SHA224,	k0, 49,
                "Sample message for keylen<blocklen, with truncated tag", 54,
                "\xD5\x22\xF1\xDF\x59\x6C\xA4\xB4\xB1\xC2\x3D\x27\xBD\xE0\x67\xD6", 16
            },

            {
                MD_SHA256,	k0, 64,
                "Sample message for keylen=blocklen", 34,
                "\x8B\xB9\xA1\xDB\x98\x06\xF2\x0D\xF7\xF7\x7B\x82\x13\x8C\x79\x14\xD1\x74\xD5\x9E\x13\xDC\x4D\x01\x69\xC9\x05\x7B\x13\x3E\x1D\x62", 32
            },
            {
                MD_SHA256,	k0, 32,
                "Sample message for keylen<blocklen", 34,
                "\xA2\x8C\xF4\x31\x30\xEE\x69\x6A\x98\xF1\x4A\x37\x67\x8B\x56\xBC\xFC\xBD\xD9\xE5\xCF\x69\x71\x7F\xEC\xF5\x48\x0F\x0E\xBD\xF7\x90", 32
            },
            {
                MD_SHA256,	k0, 100,
                "Sample message for keylen=blocklen", 34,
                "\xBD\xCC\xB6\xC7\x2D\xDE\xAD\xB5\x00\xAE\x76\x83\x86\xCB\x38\xCC\x41\xC6\x3D\xBB\x08\x78\xDD\xB9\xC7\xA3\x8A\x43\x1B\x78\x37\x8D", 32
            },
            {
                MD_SHA256,	k0, 49,
                "Sample message for keylen<blocklen, with truncated tag", 54,
                "\x27\xA8\xB1\x57\x83\x9E\xFE\xAC\x98\xDF\x07\x0B\x33\x1D\x59\x36", 16
            },
            {0},
        };
        printf("HMAC:\n");
        uint8_t hash[64];
        int i;
        for (i=0; i<80 && hmac_tests[i].msg; i++)
        {
            const MDigest *md = digest_select(hmac_tests[i].id);// MD_STRIBOG_256_digest;
			if (md==NULL) continue;
            hmac(md, hash, md->hash_len, (uint8_t*)hmac_tests[i].msg, hmac_tests[i].mlen, (uint8_t*)hmac_tests[i].key, hmac_tests[i].klen);
//    for(i=0; i<8;i++) printf(" %016" PRIX64, ctx.H[i]); printf("\n");
            if (memcmp(hash, hmac_tests[i].hash, hmac_tests[i].hash_len)==0) printf("%d HMAC %s OK\n", i, md->name);
            else {
                printf("%d HMAC %s Fail\n", i, md->name);
                int n;
                for (n=0; n<hmac_tests[i].klen; n++){
                    printf(" %02X", hmac_tests[i].key[hmac_tests[i].klen - n-1]);
                    if ((n&0xF)==0xF)printf("\n");
                }
                printf("Text:\n");
                for (n=0; n<hmac_tests[i].mlen; n++){
                    printf(" %02X", (uint8_t)hmac_tests[i].msg[hmac_tests[i].mlen - n-1]);
                    if ((n&0xF)==0xF)printf("\n");
                }
                printf("HASH:\n");
                for (n=0; n<hmac_tests[i].hash_len; n++){
                    printf("\\x%02x", hash[n]);
                    if ((n&0xF)==0xF)printf("\n");
                }
            }
        }
    }
    if(1){// PBKDF2-HMAC
        struct
        {
            int id;
            char* pass;
            int plen;
            char* salt;
            int slen;
            int c;
            int dklen;
            char* dk;

        } pbkdf2_tests[] =
        {
            {
                MD_GOSTR341194_CP,
                "password", 8,
                "salt", 4,
                1,
                32,
                "\x73\x14\xe7\xc0\x4f\xb2\xe6\x62\xc5\x43\x67\x42\x53\xf6\x8b\xd0"
                "\xb7\x34\x45\xd0\x7f\x24\x1b\xed\x87\x28\x82\xda\x21\x66\x2d\x58"
            },
            {
                MD_GOSTR341194_CP,
                "password", 8,
                "salt", 4,
                2,
                32,
                "\x99\x0d\xfa\x2b\xd9\x65\x63\x9b\xa4\x8b\x07\xb7\x92\x77\x5d\xf7"
                "\x9f\x2d\xb3\x4f\xef\x25\xf2\x74\x37\x88\x72\xfe\xd7\xed\x1b\xb3"
            },
            {
                MD_GOSTR341194_CP,
                "password", 8,
                "salt", 4,
                4096,
                32,
                "\x1f\x18\x29\xa9\x4b\xdf\xf5\xbe\x10\xd0\xae\xb3\x6a\xf4\x98\xe7"
                "\xa9\x74\x67\xf3\xb3\x11\x16\xa5\xa7\xc1\xaf\xff\x9d\xea\xda\xfe"
            },
/*            {// -- takes toooo long
            MD_GOSTR341194_CP,
            "password", 8,
            "salt", 4,
            16777216,
            32,
            "\xa5\x7a\xe5\xa6\x08\x83\x96\xd1\x20\x85\x0c\x5c\x09\xde\x0a\x52"
            "\x51\x00\x93\x8a\x59\xb1\xb5\xc3\xf7\x81\x09\x10\xd0\x5f\xcd\x97"
            },*/
            {
                MD_GOSTR341194_CP,
                "passwordPASSWORDpassword", 24,
                "saltSALTsaltSALTsaltSALTsaltSALTsalt", 36,
                4096,
                40,
                "\x78\x83\x58\xc6\x9c\xb2\xdb\xe2\x51\xa7\xbb\x17\xd5\xf4\x24\x1f"
                "\x26\x5a\x79\x2a\x35\xbe\xcd\xe8\xd5\x6f\x32\x6b\x49\xc8\x50\x47"
                "\xb7\x63\x8a\xcb\x47\x64\xb1\xfd"
            },
            {
                MD_GOSTR341194_CP,
                "pass\0word", 9,
                "sa\0lt", 5,
                4096,
                20,
                "\x43\xe0\x6c\x55\x90\xb0\x8c\x02\x25\x24\x23\x73\x12\x7e\xdf\x9c"
                "\x8e\x9c\x32\x91"
            },

            {
                MD_STRIBOG_512,
                "password", 8,
                "salt", 4,
                1,
                64,
                "\x64\x77\x0a\xf7\xf7\x48\xc3\xb1\xc9\xac\x83\x1d\xbc\xfd\x85\xc2"
                "\x61\x11\xb3\x0a\x8a\x65\x7d\xdc\x30\x56\xb8\x0c\xa7\x3e\x04\x0d"
                "\x28\x54\xfd\x36\x81\x1f\x6d\x82\x5c\xc4\xab\x66\xec\x0a\x68\xa4"
                "\x90\xa9\xe5\xcf\x51\x56\xb3\xa2\xb7\xee\xcd\xdb\xf9\xa1\x6b\x47"

//                "\xbc\xd1\x9a\x1c\x42\x3a\x63\xe7\x2e\x47\xef\x0f\x56\x56\x6c\x72"
//                "\x67\x45\xd9\x6a\xc1\xa1\xc1\x27\xb2\xed\xad\xb4\x5f\xb4\x5b\x30"
//                "\x7a\xca\x15\x99\x9e\x91\xf6\x40\xf4\x81\x8f\x68\xaf\x71\x6e\x30"
//                "\xfd\x54\x3c\x52\x02\x6b\xbb\x29\x5d\x10\x0e\xb4\x71\x33\x9f\x46"
            },
            {
                MD_STRIBOG_512,
                "password", 8,
                "salt", 4,
                2,
                64,
				"\x5a\x58\x5b\xaf\xdf\xbb\x6e\x88\x30\xd6\xd6\x8a\xa3\xb4\x3a\xc0"
				"\x0d\x2e\x4a\xeb\xce\x01\xc9\xb3\x1c\x2c\xae\xd5\x6f\x02\x36\xd4"
				"\xd3\x4b\x2b\x8f\xbd\x2c\x4e\x89\xd5\x4d\x46\xf5\x0e\x47\xd4\x5b"
				"\xba\xc3\x01\x57\x17\x43\x11\x9e\x8d\x3c\x42\xba\x66\xd3\x48\xde"
//                "\x08\x8f\xec\x3b\x0f\x1f\xfa\xf0\x61\x5e\xb2\x67\xde\x92\x90\x7f"
//                "\xd4\xe0\xbb\x89\xd2\xf5\xef\x9d\x41\x11\xa8\x0e\x3c\xbf\x23\x1a"
//                "\xf0\x7b\xa3\xce\x96\x06\x53\x95\xf8\xf1\xa7\x50\x5f\x97\x81\xf9"
//                "\x7e\x99\xa2\x6b\x83\x14\x90\x7d\xbf\x35\x10\xbc\x3c\xa2\x00\x0c"
            },
            {
                MD_STRIBOG_512,
                "password", 8,
                "salt", 4,
                4096,
                64,
				"\xe5\x2d\xeb\x9a\x2d\x2a\xaf\xf4\xe2\xac\x9d\x47\xa4\x1f\x34\xc2"
				"\x03\x76\x59\x1c\x67\x80\x7f\x04\x77\xe3\x25\x49\xdc\x34\x1b\xc7"
				"\x86\x7c\x09\x84\x1b\x6d\x58\xe2\x9d\x03\x47\xc9\x96\x30\x1d\x55"
				"\xdf\x0d\x34\xe4\x7c\xf6\x8f\x4e\x3c\x2c\xda\xf1\xd9\xab\x86\xc3"
//                "\x59\x6f\x63\x97\x1e\xae\x97\x0a\x4e\xac\x9c\x18\xbf\xf4\x2e\xc5"
//                "\x2b\x93\x6c\x1c\xca\xc6\xd1\x7c\xaa\x30\x8a\xfe\x12\xd4\xff\x31"
//                "\x94\x31\x80\xce\x02\xe4\x29\x56\x52\x4e\x99\x13\x92\xc4\xbd\xde"
//                "\xb7\x07\x7e\xdc\x1d\x2a\xbf\x52\xea\xf7\x2b\x9e\x32\xa8\xc6\x05"
            },
            /*     {// -- takes toooo long
            MD_STRIBOG_512,
            "password", 8,
            "salt", 4,
            16777216,
            64,
"\x49\xe4\x84\x3b\xba\x76\xe3\x00\xaf\xe2\x4c\x4d\x23\xdc\x73\x92"
"\xde\xf1\x2f\x2c\x0e\x24\x41\x72\x36\x7c\xd7\x0a\x89\x82\xac\x36"
"\x1a\xdb\x60\x1c\x7e\x2a\x31\x4e\x8c\xb7\xb1\xe9\xdf\x84\x0e\x36"
"\xab\x56\x15\xbe\x5d\x74\x2b\x6c\xf2\x03\xfb\x55\xfd\xc4\x80\x71"
//            "\xeb\xf5\x12\xe4\xfe\x87\x51\x55\x21\x3d\x38\x81\x73\x8e\x10\x80"
//            "\x11\x6e\xfc\x12\xe0\x7e\xc6\x5c\xb7\x07\x20\x9d\x5e\xe8\x90\xd2"
//            "\x5b\xd4\xd9\x86\xca\xd5\xe1\x52\xaf\x23\x30\xf7\xfc\x29\x40\xeb"
//            "\x41\xf9\xbe\x0b\x1b\xae\xad\xfd\x43\x6e\xfb\x8c\x77\xd1\xc9\x13"
            },*/
            {
                MD_STRIBOG_512,
                "passwordPASSWORDpassword", 24,
                "saltSALTsaltSALTsaltSALTsaltSALTsalt", 36,
                4096,
                100,
				"\xb2\xd8\xf1\x24\x5f\xc4\xd2\x92\x74\x80\x20\x57\xe4\xb5\x4e\x0a"
				"\x07\x53\xaa\x22\xfc\x53\x76\x0b\x30\x1c\xf0\x08\x67\x9e\x58\xfe"
				"\x4b\xee\x9a\xdd\xca\xe9\x9b\xa2\xb0\xb2\x0f\x43\x1a\x9c\x5e\x50"
				"\xf3\x95\xc8\x93\x87\xd0\x94\x5a\xed\xec\xa6\xeb\x40\x15\xdf\xc2"
				"\xbd\x24\x21\xee\x9b\xb7\x11\x83\xba\x88\x2c\xee\xbf\xef\x25\x9f"
				"\x33\xf9\xe2\x7d\xc6\x17\x8c\xb8\x9d\xc3\x74\x28\xcf\x9c\xc5\x2a"
				"\x2b\xaa\x2d\x3a"
//                "\xe4\x57\xee\x61\x26\xf0\x7c\x09\xbe\x00\x4b\xa5\x12\xad\xc9\x0c"
//                "\x61\x1c\x2b\x3f\xa1\x11\x41\xc2\x11\x96\xda\xe5\xa4\x8a\x50\xd8"
//                "\x3c\xcf\x16\x32\x33\xf0\x14\xfb\x6a\xde\x71\x69\x5b\xf3\x71\x59"
//                "\xe9\x06\x24\x43\xb7\x5d\xac\x91\x1f\xa7\xa1\x81\xd2\x4c\x4e\xd2"
//                "\xa9\x10\x49\x9d\x72\xab\xa9\x32\x84\xc7\x8d\xbc\x1a\xcb\xa2\x78"
//                "\x9b\xd8\xef\x50\xb5\x05\x2f\x33\xec\x6e\x24\x91\xf4\xf7\x4e\xda"
//                "\x05\x72\x38\x64"
            },
            {
                MD_STRIBOG_512,
                "pass\0word", 9,
                "sa\0lt", 5,
                4096,
                64,
				"\x50\xdf\x06\x28\x85\xb6\x98\x01\xa3\xc1\x02\x48\xeb\x0a\x27\xab"
				"\x6e\x52\x2f\xfe\xb2\x0c\x99\x1c\x66\x0f\x00\x14\x75\xd7\x3a\x4e"
				"\x16\x7f\x78\x2c\x18\xe9\x7e\x92\x97\x6d\x9c\x1d\x97\x08\x31\xea"
				"\x78\xcc\xb8\x79\xf6\x70\x68\xcd\xac\x19\x10\x74\x08\x44\xe8\x30"
//                "\xee\xd9\x2e\x8d\x76\xe1\x8d\x6a\x63\x2f\x2d\xa6\x5c\x9b\x28\x59"
//                "\xaf\x55\x5c\x33\x35\xea\x30\x09\x59\x89\xde\xa1\x4d\x9d\x09\x31"
//                "\x14\x66\x8e\x32\x9d\xeb\x03\x4c\xc1\x56\x5c\x3d\x73\x1d\xe0\xb5"
//                "\xca\x11\xac\xbd\xf8\x5a\xb9\xea\xab\x15\x29\x5d\xf0\x5b\x98\x05"
            },

            {
                MD_SHA1,
                "password", 8,
                "salt", 4,
                1,
                20,
                "\x0c\x60\xc8\x0f\x96\x1f\x0e\x71\xf3\xa9\xb5\x24\xaf\x60\x12\x06\x2f\xe0\x37\xa6"
            },
            {
                MD_SHA1,
                "password", 8,
                "salt", 4,
                2,
                20,
                "\xea\x6c\x01\x4d\xc7\x2d\x6f\x8c\xcd\x1e\xd9\x2a\xce\x1d\x41\xf0\xd8\xde\x89\x57"
            },
            {
                MD_SHA1,
                "password", 8,
                "salt", 4,
                4096,
                20,
                "\x4b\x00\x79\x01\xb7\x65\x48\x9a\xbe\xad\x49\xd9\x26\xf7\x21\xd0\x65\xa4\x29\xc1"
            },
            /*{// -- takes toooo long
            MD_SHA1,
            "password", 8,
            "salt", 4,
            16777216,
            20,
            "\xee\xfe\x3d\x61\xcd\x4d\xa4\xe4\xe9\x94\x5b\x3d\x6b\xa2\x15\x8c\x26\x34\xe9\x84"
            },*/
            {
                MD_SHA1,
                "passwordPASSWORDpassword", 24,
                "saltSALTsaltSALTsaltSALTsaltSALTsalt", 36,
                4096,
                25,
                "\x3d\x2e\xec\x4f\xe4\x1c\x84\x9b\x80\xc8\xd8\x36\x62\xc0\xe4\x4a\x8b\x29\x1a\x96\x4c\xf2\xf0\x70\x38"
            },
            {
                MD_SHA1,
                "pass\0word", 9,
                "sa\0lt", 5,
                4096,
                16,
                "\x56\xfa\x6a\xa7\x55\x48\x09\x9d\xcc\x37\xd7\xf0\x34\x25\xe0\xc3"
            },

            {
                MD_SHA256,
                "password", 8,
                "salt", 4,
                1,
                32,
                "\x12\x0f\xb6\xcf\xfc\xf8\xb3\x2c\x43\xe7\x22\x52\x56\xc4\xf8\x37"
                "\xa8\x65\x48\xc9\x2c\xcc\x35\x48\x08\x05\x98\x7c\xb7\x0b\xe1\x7b"
            },
            {
                MD_SHA256,
                "password", 8,
                "salt", 4,
                2,
                32,
                "\xae\x4d\x0c\x95\xaf\x6b\x46\xd3\x2d\x0a\xdf\xf9\x28\xf0\x6d\xd0"
                "\x2a\x30\x3f\x8e\xf3\xc2\x51\xdf\xd6\xe2\xd8\x5a\x95\x47\x4c\x43"
            },
            {
                MD_SHA256,
                "password", 8,
                "salt", 4,
                4096,
                32,
                "\xc5\xe4\x78\xd5\x92\x88\xc8\x41\xaa\x53\x0d\xb6\x84\x5c\x4c\x8d"
                "\x96\x28\x93\xa0\x01\xce\x4e\x11\xa4\x96\x38\x73\xaa\x98\x13\x4a"
            },
            /*{// -- takes toooo long
            MD_SHA256,
            "password", 8,
            "salt", 4,
            16777216,
            32,
            "\xcf\x81\xc6\x6f\xe8\xcf\xc0\x4d\x1f\x31\xec\xb6\x5d\xab\x40\x89"
               "\xf7\xf1\x79\xe8\x9b\x3b\x0b\xcb\x17\xad\x10\xe3\xac\x6e\xba\x46"
            },*/
            {
                MD_SHA256,
                "passwordPASSWORDpassword", 24,
                "saltSALTsaltSALTsaltSALTsaltSALTsalt", 36,
                4096,
                40,
                "\x34\x8c\x89\xdb\xcb\xd3\x2b\x2f\x32\xd8\x14\xb8\x11\x6e\x84\xcf"
                "\x2b\x17\x34\x7e\xbc\x18\x00\x18\x1c\x4e\x2a\x1f\xb8\xdd\x53\xe1"
                "\xc6\x35\x51\x8c\x7d\xac\x47\xe9"
            },
            {
                MD_SHA256,
                "pass\0word", 9,
                "sa\0lt", 5,
                4096,
                16,
                "\x89\xb6\x9d\x05\x16\xf8\x29\x89\x3c\x69\x62\x26\x65\x0a\x86\x87"
            },
            {0},
        };
        printf("PBKDF2-HMAC:\n");

        uint8_t dk[128];
        int i;
        for (i=0; i<80 && pbkdf2_tests[i].id; i++)
        {
            //if (pbkdf2_tests[i].c> 4096) continue;
            const MDigest *md = digest_select(pbkdf2_tests[i].id);// MD_STRIBOG_256_digest;
			if (md==NULL) continue;
            pbkdf2_hmac(md, dk, pbkdf2_tests[i].dklen, (uint8_t*)pbkdf2_tests[i].pass, pbkdf2_tests[i].plen, (uint8_t*)pbkdf2_tests[i].salt, pbkdf2_tests[i].slen, pbkdf2_tests[i].c);
            if (__builtin_memcmp(dk, pbkdf2_tests[i].dk,pbkdf2_tests[i].dklen)==0) printf("%d PBKDF2-HMAC %s OK\n", i, md->name);
            else
            {
                int i;
                for (i=0; i<32; i++) printf("%02X ",dk[i]);
                printf("\n");
                printf("%d Fail\n", i);
            }
        }
        /*    const MDigest *md = digest_select(MD_SHA1);
            pbkdf2_hmac(md, dk, 16, (uint8_t*)"password", 8, (uint8_t*)"\xAC\x7C\x90\x3C\x16\x6A\x58\xB5", 8, 2048);
            printf("PBKDF2-HMAC-SHA1 ():\n");
            for (i=0; i<16; i++) printf("%02X ",dk[i]); printf("\n");*/
    }
    return 0;

}
#endif // TEST_HMAC
