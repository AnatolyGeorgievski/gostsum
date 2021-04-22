/*!
    [FIPS PUB 180-4] Secure Hash Standard (SHS)
    \see http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf
    \see [RFC 6234] SHAs, HMAC-SHAs, and HKDF, May 2011

    SHA-384, SHA-512, SHA-512/224 and SHA-512/256
 */

#include <inttypes.h>
#include <string.h>
#include <stdio.h>
#include <sys/param.h> // GCC
#if (BYTE_ORDER==LITTLE_ENDIAN)
# define ENDIANNESS 0x7    // для little-endian = 0x7, для big-endian = 0x0
#else
# define ENDIANNESS 0x0    // для little-endian, для big-endian = 0x0UL
#endif

#include "hmac.h"

    typedef uint64_t v8di __attribute__((__vector_size__(64)));
    typedef uint64_t v2di __attribute__((__vector_size__(16)));

static
void ntohll_vec(uint64_t * v, int len)
{

//        len = (len+1)>>1;
    int i;
    for (i=0;i<len; i++){
        v[i] = __builtin_bswap64(v[i]);
    }
}
static inline
uint64_t N2HLL(const uint8_t * b)
{
    uint64_t q;
    __builtin_memcpy(&q,b,8);
#if (BYTE_ORDER==LITTLE_ENDIAN)
    return __builtin_bswap64(q);
#else
    return q;
#endif
/*
    return
		(uint64_t)((b[7^ENDIANNESS]<<24) | (b[6^ENDIANNESS]<<16) | (b[5^ENDIANNESS]<< 8) | (b[4^ENDIANNESS]<< 0))<<32 |
		           (b[3^ENDIANNESS]<<24) | (b[2^ENDIANNESS]<<16) | (b[1^ENDIANNESS]<< 8) | (b[0^ENDIANNESS]<< 0) ;*/
}
static inline uint8_t HLL2N(uint64_t * v, int i)
{
    return ((uint8_t*)v)[i^ENDIANNESS];
}

static const uint64_t K512[] = {
0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL,
};
static const uint64_t H0_384[8] = {
0xcbbb9d5dc1059ed8ULL, 0x629a292a367cd507ULL, 0x9159015a3070dd17ULL, 0x152fecd8f70e5939ULL,
0x67332667ffc00b31ULL, 0x8eb44a8768581511ULL, 0xdb0c2e0d64f98fa7ULL, 0x47b5481dbefa4fa4ULL,
};
static const uint64_t H0_512[8] = {
0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL, 0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL, 0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL,
};
static const uint64_t H0_512_224[8] = {
0x8C3D37C819544DA2ULL, 0x73E1996689DCD4D6ULL, 0x1DFAB7AE32FF9C82ULL, 0x679DD514582F9FCFULL,
0x0F6D2B697BD44DA8ULL, 0x77E36F7304C48942ULL, 0x3F9D85A86A1D36C8ULL, 0x1112E6AD91D692A1ULL,
};
static const uint64_t H0_512_256[8] = {
0x22312194FC2BF72CULL, 0x9F555FA3C84C64C2ULL, 0x2393B86B6F53B151ULL, 0x963877195940EABDULL,
0x96283EE2A88EFFE3ULL, 0xBE5E1E2553863992ULL, 0x2B0199FC2C85B8AAULL, 0x0EB72DDC81C52CA2ULL,
};

static inline uint64_t SHR(uint64_t v, int i)
{
    return v>>i;
}

static inline uint64_t ROTR(uint64_t v, int i)
{
    return (v<<(64-i)) | (v>>(i));
}
static inline uint64_t Ch(uint64_t x, uint64_t y, uint64_t z)
{
    return (x&y) ^ (~x&z);
}
static inline uint64_t Maj(uint64_t x, uint64_t y, uint64_t z)
{
    return (x&y) ^ (x&z) ^ (y&z);
}
static inline uint64_t sigma0(uint64_t x)
{
    return ROTR(x, 1) ^ ROTR(x, 8) ^ SHR(x,7);
}
static inline uint64_t sigma1(uint64_t x)
{
    return ROTR(x,19) ^ ROTR(x,61) ^ SHR(x,6);
}
static inline uint64_t Sum0(uint64_t x)
{
    return ROTR(x,28) ^ ROTR(x,34) ^ ROTR(x,39);
}
static inline uint64_t Sum1(uint64_t x)
{
    return ROTR(x,14) ^ ROTR(x,18) ^ ROTR(x,41);
}


/*! SHA-512 hash computation
TODO вместо копирования можно ходить по таблице на каждом шаге сдвигаять вверх
хотя восемь переменных лезут в регистры и через 8 кругов возвращаются на место
второй вариант оптимизации: описать циклическую функцию и сделать цикл с восмью
функциями внутри
    H -- hash [8]
    M -- message block 1024 bit
 */
/*! в этом варианте 45 инструкций в цикле из них 8 копирование регистров, третий вариант может быть на 1/4 быстрее */

#if 0
void SHA512_0(uint64_t * H, uint64_t * M)
{
    uint64_t W[80];
    int t; // Prepare the message schedule
    for (t=0; t<16; t++) W[t] = M[t];
    for (   ; t<80; t++) W[t] = sigma1(W[t-2]) + W[t-7] + sigma0(W[t-15]) + W[t-16];
    uint64_t a = H[0],b = H[1],c = H[2],d = H[3],e = H[4],f = H[5],g = H[6],h = H[7];
//    v8di x = (v8di){H[0],H[1],H[2],H[3],H[4],H[5],H[6],H[7]};
    for (t=0; t<80; t++)
    {
        uint64_t T = h + Sum1(e) + Ch(e,f,g) + K512[t] + W[t];
        d += T;
        T += Sum0(a) + Maj(a,b,c);
        h=g,g=f,f=e,e=d,d=c,c=b, b=a, a=T;
//        printf ("%2d:\t%016"PRIX64" %016"PRIX64" %016"PRIX64" %016"PRIX64"\n"
//                "    \t%016"PRIX64" %016"PRIX64" %016"PRIX64" %016"PRIX64"\n",t, a,b,c,d,e,f,g,h);
    }
    H[0]+=a, H[1]+=b, H[2]+=c, H[3]+=d, H[4]+=e, H[5]+=f, H[6]+=g, H[7]+=h;
}
#endif
/*! 36 команд на раунд - самый быстрый вариант */
#define ROUND(a,b,c,d,e,f,g,h,t) ({\
        uint64_t T = h + Sum1(e) + Ch(e,f,g) + K512[t] + W[t];  \
        d += T; \
        T += Sum0(a) + Maj(a,b,c); \
        h  = T; })
static __attribute__((noinline))
void SHA512(uint64_t * H, uint64_t * M)
{
    uint64_t W[80] __attribute__((__aligned__(16)));
    int t; // Prepare the message schedule
    for (t=0; t<16; t++) W[t] = M[t];
    for (   ; t<80; t++) W[t] = sigma1(W[t-2]) + W[t-7] + sigma0(W[t-15]) + W[t-16];
    uint64_t a = H[0],b = H[1],c = H[2],d = H[3],e = H[4],f = H[5],g = H[6],h = H[7];
    for (t=0; t<80; t+=8)
    {
        ROUND(a,b,c,d,e,f,g,h,t+0);
        ROUND(h,a,b,c,d,e,f,g,t+1);
        ROUND(g,h,a,b,c,d,e,f,t+2);
        ROUND(f,g,h,a,b,c,d,e,t+3);
        ROUND(e,f,g,h,a,b,c,d,t+4);
        ROUND(d,e,f,g,h,a,b,c,t+5);
        ROUND(c,d,e,f,g,h,a,b,t+6);
        ROUND(b,c,d,e,f,g,h,a,t+7);
    }
    H[0]+=a,H[1]+=b,H[2]+=c,H[3]+=d,H[4]+=e,H[5]+=f,H[6]+=g,H[7]+=h;
//    H[0]+=(v2di){a, b}, H[1]+=(v2di){c, d}, H[2]+=(v2di){e, f}, H[3]+=(v2di){g, h};
//    *H += (v8di){a,b,c,d, e,f,g,h};
}
#if 0
/*! интересный вариант но не эффективный потому что требует больше кода в цикле 120 инструкций против 45 в предыдущем варианте */
void SHA512_v(uint64_t * H, uint64_t * M)
{
    uint64_t buf[80+8] __attribute__((aligned(16)));
    uint64_t *W = buf;
    int t; // Prepare the message schedule
    for (t=0; t< 8; t++) W[t] = H[7-t];
    W+=8;
    for (t=0; t<16; t++) W[t] = M[t];
    for (   ; t<80; t++) W[t] = sigma1(W[t-2]) + W[t-7] + sigma0(W[t-15]) + W[t-16];
// a=W[-0] b=W[-1] c=W[-2] d=W[-3] e=W[-4] f=W[-5] g -6 h -7
    W-=8;
    for (t=0; t<80; t++)
    {
        W[t+8] += W[t] + Sum1(W[t+3]) + Ch(W[t+3],W[t+2],W[t+1]) + K512[t];
        W[t+4] += W[t+8];
        W[t+8] += Sum0(W[t+7]) + Maj(W[t+7],W[t+6],W[t+5]);
    }
    W+=80;
    for (t=0; t< 8; t++) H[t] += W[7-t];
}
#endif
typedef struct _HashCtx HashCtx;
struct _HashCtx {
    uint64_t H[8];
    uint64_t buffer[16];
    uint64_t length;
//    const uint64_t *H0;
    unsigned int hlen; // длина хеша
};
/*
void SHA512_init(HashCtx *ctx, const uint64_t *H0)
{
    int i; for (i=0; i < 8; i++) ctx->H[i] = H0[i];
    ctx->length = 0;
}
*/
static void SHA512_init_512(HashCtx *ctx)
{
    int i; for (i=0; i < 8; i++) ctx->H[i] = H0_512[i];
    ctx->length = 0; ctx->hlen = 64;
}
static void SHA512_init_256(HashCtx *ctx)
{
    int i; for (i=0; i < 8; i++) ctx->H[i] = H0_512_256[i];
    ctx->length = 0; ctx->hlen = 64;
}
static void SHA512_init_224(HashCtx *ctx)
{
    int i; for (i=0; i < 8; i++) ctx->H[i] = H0_512_224[i];
    ctx->length = 0; ctx->hlen = 64;
}
static void SHA512_init_384(HashCtx *ctx)
{
    int i; for (i=0; i < 8; i++) ctx->H[i] = H0_384[i];
    ctx->length = 0; ctx->hlen = 64;
}


#define BLK_SIZE 128
/*!
    len -- длина в байтах < 64
 */
static void SHA512_update(HashCtx *ctx, const uint8_t* msg, unsigned int mlen)
{
    unsigned int offset = ctx->length & (BLK_SIZE-1);
    //uint8_t * buffer = (void*)ctx->buffer;
    ctx->length += mlen;
    while (mlen>0){
        unsigned int len = (mlen>BLK_SIZE-offset)?BLK_SIZE-offset: mlen;
        __builtin_memcpy((uint8_t*)ctx->buffer + offset, msg, len);
        msg+=len; mlen-=len; offset+=len;
        if (offset==BLK_SIZE){
            if (ENDIANNESS) ntohll_vec(ctx->buffer, BLK_SIZE/8);
            SHA512(ctx->H, ctx->buffer);
            offset = 0;
        }
    }
}
/*!
    Правило завершения буфера: добавить 1'b1 в конец потока, забить нулями
    len+1+k=896 mod 1024
    в конец блока записывается длина потока в битах, поле 64 бита
    в нотации network msb
    len - должна быть меньше 1024b (128 байта)*/
static void SHA512_final(HashCtx *ctx, void *tag, int tlen)
{
    uint8_t *buffer = (void*)ctx->buffer;
    int offset = ctx->length&(BLK_SIZE-1);
    buffer[offset] = 0x80;// LE?
    if (offset >= (BLK_SIZE-16))
    {// переход на следующий блок
        __builtin_memset((uint8_t*)ctx->buffer+offset+1, 0, (BLK_SIZE-1) - offset);
        if (ENDIANNESS) ntohll_vec(ctx->buffer, ((offset+8)>>3));
        SHA512(ctx->H, ctx->buffer);
        __builtin_memset(ctx->buffer, 0, (BLK_SIZE-16));
    } else {
        __builtin_memset((uint8_t*)ctx->buffer+offset+1, 0, (BLK_SIZE-17) - offset);
        if (ENDIANNESS) ntohll_vec(ctx->buffer, ((offset+8)>>3));
    }
    ctx->buffer[15] = (ctx->length<< 3);
    ctx->buffer[14] = (ctx->length>>61);
    SHA512(ctx->H, ctx->buffer);
    int i;
    for (i=0; i<tlen; i++) {
        ((uint8_t*)tag)[i] = HLL2N(ctx->H, i);
    }

}
/*
static void digest2(uint64_t *H, uint8_t *tag, int tlen)
{
    int i;
    for (i=0; i<tlen; i++) {
        tag[i] = HLL2N(H, i);
    }
}*/
/*
void sha512(uint8_t *hash, uint8_t *msg, int length)
{
    HashCtx ct;
    HashCtx *ctx = &ct;
    SHA512_init(ctx, H0_512);
    SHA512_update(ctx, msg, length);
    SHA512_final(ctx, hash, 64);
}
void sha384(uint8_t *hash, uint8_t *msg, int length)
{
    HashCtx ct;
    HashCtx *ctx = &ct;
    SHA512_init(ctx, H0_384);
    SHA512_update(ctx, msg, length);
    SHA512_final(ctx, hash, 48);
}
*/
#if 0
typedef struct _HashParams HashParams;
struct _HashParams {
    const char* name;
    const uint64_t *k;
    const int length;
};
static const HashParams hash_params[] = {
    {"SHA-384", H0_384, 48},
    {"SHA-512", H0_512, 64},
    {"SHA-512/224", H0_512_224, 28},
    {"SHA-512/256", H0_512_256, 32},
    {NULL, NULL, 0},
};
#endif
MESSAGE_DIGEST(MD_SHA512){
    .id=MD_SHA512,
    .name = "SHA-512",
    .block_len = 128,
    .hash_len = 64,
    .ctx_size = sizeof(HashCtx),
    .init   = (void*)SHA512_init_512,
    .update = (void*)SHA512_update,
    .final  = (void*)SHA512_final,
};
MESSAGE_DIGEST(MD_SHA384){
    .id=MD_SHA384,
    .name = "SHA-384",
    .block_len = 128,
    .hash_len = 48,
    .ctx_size = sizeof(HashCtx),
    .init   = (void*)SHA512_init_384,
    .update = (void*)SHA512_update,
    .final  = (void*)SHA512_final,
};
MESSAGE_DIGEST(MD_SHA512_256){
    .id=MD_SHA512_256,
    .name = "SHA-512/256",
    .block_len = 128,
    .hash_len = 64,
    .ctx_size = sizeof(HashCtx),
    .init   = (void*)SHA512_init_256,
    .update = (void*)SHA512_update,
    .final  = (void*)SHA512_final,
};
MESSAGE_DIGEST(MD_SHA512_224){
    .id=MD_SHA512_224,
    .name = "SHA-512/224",
    .block_len = 128,
    .hash_len = 28,
    .ctx_size = sizeof(HashCtx),
    .init   = (void*)SHA512_init_224,
    .update = (void*)SHA512_update,
    .final  = (void*)SHA512_final,
};
/*
void sha3(uint8_t *hash, int id, uint8_t *msg, int length)
{
    HashCtx ct;
    HashCtx *ctx = &ct;
    SHA512_init(ctx, hash_params[id].k);//H0_384);
    SHA512_update(ctx, msg, length);
    SHA512_final(ctx, hash, hash_params[id].length);
}*/
#if 0
#define IPAD 0x3636363636363636ULL
#define OPAD 0x5C5C5C5C5C5C5C5CULL
/*!
    \see [RFC 4231] Identifiers and Test Vectors for HMAC-SHA-224, HMAC-SHA-256, HMAC-SHA-384, and HMAC-SHA-512
 */
void HMAC_SHA512(HashCtx* ctx, void * msg, int mlen, uint8_t * key, int klen)
{
    const int block_len=128;//512 бит// 64 байта
    const int hash_len =ctx->hlen;
    uint64_t K[block_len/8], H[hash_len/8];// ={0};
    int i;
    if (klen > block_len)
    {
        SHA512_init   (ctx, ctx->H0);
        SHA512_update (ctx, (void*)key,  klen);
        SHA512_final  (ctx, K, hash_len);
//        for (i=0; i< hash_len/8; i++) K[i] = htonll(ctx->H[i]);
        for (i= hash_len/8; i< block_len/8; i++) K[i] = 0;
    } else
    if (klen < block_len)
    {
        memcpy(K, key, klen);
        memset(((uint8_t*)K) + klen, 0, block_len-klen);
    } else {
        memcpy(K, key, block_len);
    }
//    printf("K =");
//    for (i=0; i<block_len/8; i++) printf(" %016"PRIX64,K[i]); printf("\n");
// 1. длина ключа равна длине блока
    for (i=0; i< block_len/8; i++) K[i] = K[i] ^ IPAD;
    SHA512_init   (ctx, ctx->H0);
    SHA512_update (ctx, (void*)K,  block_len);
    SHA512_update (ctx, msg, mlen);
    SHA512_final  (ctx, H, hash_len);

//    for (i=0; i< hash_len/8; i++) H[i] = htonll(ctx->H[i]);
    for (i=0; i< block_len/8; i++) K[i] = K[i] ^ (OPAD^IPAD);

    SHA512_init   (ctx, ctx->H0);
    SHA512_update (ctx, (void*)K,  block_len);
    SHA512_update (ctx, (void*)H,  hash_len);
    SHA512_final  (ctx, NULL, 0);
// нужен дайджест на выходе определенной длины, MSB();
}
#endif
#ifdef TEST_SHA512

/*! тестирование алгоритма SHA1, SHA2
*/
int  main()
{
    int i;
    uint64_t W[16] = {[0] = 0x6162638000000000ULL, [15] = 0x00000018ULL};
    HashCtx ct;
    HashCtx *ctx = &ct;
    SHA512_init(ctx, H0_512); SHA512(ctx->H, W);
    for (i=0; i<8; i++) printf("%016"PRIX64" ",ctx->H[i]); printf("\n");
    SHA512_init(ctx, H0_512); SHA512_update(ctx, "abc", 3); SHA512_final(ctx, NULL, 0);
    for (i=0; i<8; i++) printf("%016"PRIX64" ",ctx->H[i]); printf("\n");

    SHA512_init(ctx, H0_384); SHA512_update(ctx, "abc", 3); SHA512_final(ctx, NULL, 0);
    for (i=0; i<6; i++) printf("%016"PRIX64" ",ctx->H[i]); printf("\n");

    SHA512_init(ctx, H0_512_224); SHA512_update(ctx, "abc", 3); SHA512_final(ctx, NULL, 0);
    for (i=0; i<4; i++) printf("%016"PRIX64" ",ctx->H[i]); printf("\n");

    SHA512_init(ctx, H0_512_256); SHA512_update(ctx, "abc", 3); SHA512_final(ctx, NULL, 0);
    for (i=0; i<4; i++) printf("%016"PRIX64" ",ctx->H[i]); printf("\n");

    char msg[] = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    SHA512_init(ctx, H0_512); SHA512_update(ctx, msg, strlen(msg)); SHA512_final(ctx, NULL, 0);
    for (i=0; i<8; i++) printf("%016"PRIX64" ",ctx->H[i]); printf("\n");

    SHA512_init(ctx, H0_384); SHA512_update(ctx, msg, strlen(msg)); SHA512_final(ctx, NULL, 0);
    for (i=0; i<6; i++) printf("%016"PRIX64" ",ctx->H[i]); printf("\n");

    SHA512_init(ctx, H0_512_256); SHA512_update(ctx, msg, strlen(msg)); SHA512_final(ctx, NULL, 0);
    for (i=0; i<4; i++) printf("%016"PRIX64" ",ctx->H[i]); printf("\n");

    char  m0[] = "Sample message for keylen=blocklen";
    char  m1[] = "Sample message for keylen<blocklen";
    char  m3[] = "Sample message for keylen<blocklen, with truncated tag";
    uint64_t k0[] = {
        0x0001020304050607, 0x08090A0B0C0D0E0F, 0x1011121314151617, 0x18191A1B1C1D1E1F,
        0x2021222324252627, 0x28292A2B2C2D2E2F, 0x3031323334353637, 0x38393A3B3C3D3E3F,
        0x4041424344454647, 0x48494A4B4C4D4E4F, 0x5051525354555657, 0x58595A5B5C5D5E5F,
        0x6061626364656667, 0x68696A6B6C6D6E6F, 0x7071727374757677, 0x78797A7B7C7D7E7F,
        0x8081828384858687, 0x88898A8B8C8D8E8F, 0x9091929394959697, 0x98999A9B9C9D9E9F,
        0xA0A1A2A3A4A5A6A7, 0xA8A9AAABACADAEAF, 0xB0B1B2B3B4B5B6B7, 0xB8B9BABBBCBDBEBF,
        0xC0C1C2C3C4C5C6C7
    };
    for (i=0; i<25; i++) k0[i]=ntohll(k0[i]);
{
    printf("HMAC SHA384\n");
    ctx->H0 = H0_384; ctx->hlen = 48;
    uint64_t h0[] = {
        0x63C5DAA5E651847C, 0xA897C95814AB830B, 0xEDEDC7D25E83EEF9,
        0x195CD45857A37F44, 0x8947858F5AF50CC2, 0xB1B730DDF29671A9};
    HMAC_SHA512(ctx, m0, strlen(m0), (void*)k0, 128);
    if (memcmp(ctx->H,h0,ctx->hlen)==0) printf("OK\n");
    HMAC_SHA512(ctx, m1, strlen(m1), (void*)k0, 48);
    uint64_t h1[] = {
        0x6EB242BDBB582CA1, 0x7BEBFA481B1E2321, 0x1464D2B7F8C20B9F,
        0xF2201637B93646AF, 0x5AE9AC316E98DB45, 0xD9CAE773675EEED0};
    if (memcmp(ctx->H,h1,ctx->hlen)==0) printf("OK\n");
    HMAC_SHA512(ctx, m0, strlen(m0), (void*)k0, 200);
    uint64_t h2[] = {
        0x5B664436DF69B0CA, 0x22551231A3F0A3D5, 0xB4F97991713CFA84,
        0xBFF4D0792EFF96C2, 0x7DCCBBB6F79B65D5, 0x48B40E8564CEF594};
    if (memcmp(ctx->H,h2,ctx->hlen)==0) printf("OK\n");
    HMAC_SHA512(ctx, m3, strlen(m3), (void*)k0, 49);
    uint64_t h3[] = {
        0xC48130D3DF703DD7, 0xCDAA56800DFBD2BA, 0x2458320E6E1F98FE,};
    if (memcmp(ctx->H,h3,24)==0) printf("OK\n");
}
{
    printf("HMAC SHA512\n");
    ctx->H0 = H0_512; ctx->hlen = 64;
    uint64_t h0[] = {
        0xFC25E240658CA785, 0xB7A811A8D3F7B4CA, 0x48CFA26A8A366BF2, 0xCD1F836B05FCB024,
        0xBD36853081811D6C, 0xEA4216EBAD79DA1C, 0xFCB95EA4586B8A0C, 0xE356596A55FB1347};
    HMAC_SHA512(ctx, m0, strlen(m0), (void*)k0, 128);
//    for (i=0; i<8; i++) printf(" %016"PRIX64,ctx->H[i]); printf("\n");
    if (memcmp(ctx->H,h0,64)==0) printf("OK\n");
    HMAC_SHA512(ctx, m1, strlen(m1), (void*)k0, 8*8);
    uint64_t h1[] = {
        0xFD44C18BDA0BB0A6, 0xCE0E82B031BF2818, 0xF6539BD56EC00BDC, 0x10A8A2D730B3634D,
        0xE2545D639B0F2CF7, 0x10D0692C72A1896F, 0x1F211C2B922D1A96, 0xC392E07E7EA9FEDC};
    if (memcmp(ctx->H,h1,64)==0) printf("OK\n");
    HMAC_SHA512(ctx, m0, strlen(m0), (void*)k0, 25*8);
    uint64_t h2[] = {
        0xD93EC8D2DE1AD2A9, 0x957CB9B83F14E76A, 0xD6B5E0CCE285079A, 0x127D3B14BCCB7AA7,
        0x286D4AC0D4CE6421, 0x5F2BC9E6870B33D9, 0x7438BE4AAA20CDA5, 0xC5A912B48B8E27F3};
    if (memcmp(ctx->H,h2,64)==0) printf("OK\n");
    HMAC_SHA512(ctx, m3, strlen(m3), (void*)k0, 49);
    uint64_t h3[] = {
        0x00F3E9A77BB0F06D, 0xE15F160603E42B50, 0x28758808596664C0, 0x3E1AB8FB2B076778,};
    if (memcmp(ctx->H,h3,32)==0) printf("OK\n");
}
    printf("done\n");
	return 0;
}
#endif
