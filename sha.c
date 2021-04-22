/*! \brief Secure Hash Standard (SHS)

    SHA-256 может использоваться для хешироавния сообщений короче 2^64 bit

    [FIPS PUB 180-3] Secure Hash Standard (SHS)
        http://csrc.nist.gov/publications/fips/fips180-3/fips180-3_final.pdf
    [FIPS PUB 198] The Keyed-Hash Message Authentication Code (HMAC)
        http://csrc.nist.gov/publications/fips/fips198/fips-198a.pdf

тестовые вектора
    \see
    http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/SHA1.pdf
    http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/SHA224.pdf
    http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/SHA256.pdf
    http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/HMAC_SHA1.pdf
    http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/HMAC_SHA256.pdf

    [RFC 2202] Test Cases for HMAC-MD5 and HMAC-SHA-1
    [RFC 3174] US Secure Hash Algorithm 1 (SHA1)
    [RFC 3874] A 224-bit One-way Hash Function: SHA-224
    [RFC 4634] US Secure Hash Algorithms (SHA and HMAC-SHA)

Протестировано SHA-1, SHA-224, SHA-256, HMAC-SHA-256

    [RFC 2104] HMAC: Keyed-Hashing for Message Authentication
        http://tools.ietf.org/html/rfc2104

    [MD5]   Rivest, R., "The MD5 Message-Digest Algorithm", RFC 1321, April 1992.

    http://csrc.nist.gov/publications/nistpubs/800-107/NIST-SP-800-107.pdf
Тезис
    хочется оптимизировать операцию представления network->host byte order таким образом чтобы
    компилятор выкидывал полностью бессмысленные перестановки
    и оптимизировал на процессорах с поддержкой перестановки байт.
    [v] Также оптимизировать операцию ROTR
 */
#include <inttypes.h>
#include <string.h>
#include <stdio.h>
//#include "net.h"
#include "hmac.h"
#include <sys/param.h> // GCC

#ifndef BYTE_ORDER
#define BYTE_ORDER __BYTE_ORDER__
#define BIG_ENDIAN __ORDER_BIG_ENDIAN__
#define LITTLE_ENDIAN __ORDER_LITTLE_ENDIAN__
#endif // __ORDER_BIG_ENDIAN__

#if (BYTE_ORDER==LITTLE_ENDIAN)
# define ENDIANNESS 0x3    // для little-endian, для big-endian = 0x0UL
#else
# define ENDIANNESS 0x0    // для little-endian, для big-endian = 0x0UL
#endif

/*! векторная операция */
static void ntohl_vec(uint32_t * v, int len)
{
/*    int i;
    for (i=0;i<len;i++)
    {
        v[i] = __builtin_bswap32(v[i]);
    }*/
    do {*v = __builtin_bswap32(*v), v++;} while(--len);
}


//#include <stdlib.h>
static const uint32_t K256[] = {
0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};
static const uint32_t H0_160[8] = {
0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0,
};
static const uint32_t H0_224[8] = {
0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4,
};
static const uint32_t H0_256[8] = {
0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
};

/*static inline uint32_t ROTL(uint32_t v, int i)
{
    return (v<<i) | (v>>(32-i)); // ARM: rors	r0, r0, r1
}
static inline uint32_t ROTR(uint32_t v, int i)
{
    return (v<<(32-i)) | (v>>(i)); // ARM: rors	r0, r0, r1
}*/
static inline uint32_t ROTR(uint32_t v, int i)
{
    return (v<<(32-i)) | (v>>i);
}
static inline uint32_t Ch(uint32_t x, uint32_t y, uint32_t z)
{
    return (x&y) ^ (~x&z);
}
static inline uint32_t Maj(uint32_t x, uint32_t y, uint32_t z)
{
    return (x&y) ^ (x&z) ^ (y&z);
}
static inline uint32_t Parity(uint32_t x, uint32_t y, uint32_t z)
{
    return (x ^ y ^ z);
}

/*! SHA-1 (160bit) hash computation
    H -- hash [5]
    M -- message block 512 bit
 */
void SHA1_0(uint32_t * H, uint32_t * M)//, int N)
{
    uint32_t W[80];
    int t; // Prepare the message schedule
    for (t=0; t<16; t++) W[t] = M[t];
    for (   ; t<80; t++) W[t] = ROTR(W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16], 31);
    uint32_t a = H[0], b = H[1], c = H[2], d = H[3], e = H[4];
    for (t=0; t<20; t++)
    {
        uint32_t T = ROTR(a, 27) + Ch(b,c,d) + e + 0x5a827999 + W[t];
        e = d; d = c; c = ROTR(b,2); b=a,  a = T;
//            printf ("%2d: %08X %08X %08X %08X %08X\n", t,a,b,c,d,e);
    }
    for (   ; t<40; t++)
    {
        uint32_t T = ROTR(a, 27) + Parity(b,c,d) + e + 0x6ed9eba1 + W[t];
        e = d; d = c; c = ROTR(b,2); b=a, a = T;
    }
    for (   ; t<60; t++)
    {
        uint32_t T = ROTR(a, 27) + Maj(b,c,d) + e + 0x8f1bbcdc + W[t];
        e = d; d = c; c = ROTR(b,2); b=a, a = T;
    }
    for (   ; t<80; t++)
    {
        uint32_t T = ROTR(a, 27) + Parity(b,c,d) + e + 0xca62c1d6 + W[t];
        e = d; d = c; c = ROTR(b,2); b=a, a = T;
    }
    H[0] += a, H[1] += b, H[2] += c, H[3] += d, H[4] += e;
}
#define R1(a,b,c,d,e,t) ({\
        e+= ROTR(a, 27) + Ch(b,c,d) + 0x5a827999 + W[t]; \
        b = ROTR(b,2); })
#define R2(a,b,c,d,e,t) ({\
        e+= ROTR(a, 27) + Parity(b,c,d) + 0x6ed9eba1 + W[t]; \
        b = ROTR(b,2); })
#define R3(a,b,c,d,e,t) ({\
        e+= ROTR(a, 27) + Maj(b,c,d) + 0x8f1bbcdc + W[t];   \
        b = ROTR(b,2); })
#define R4(a,b,c,d,e,t) ({\
        e+= ROTR(a, 27) + Parity(b,c,d) + 0xca62c1d6 + W[t];   \
        b = ROTR(b,2); })
/*! в этом варианте 10 команд на раунд против 14 в цикле в предыдущем варианте */
void SHA1(uint32_t * H, uint32_t * M)//, int N)
{
    uint32_t W[80];
    int t; // Prepare the message schedule
    for (t=0; t<16; t++) W[t] = M[t];
    for (   ; t<80; t++) W[t] = ROTR(W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16], 31);
    uint32_t a = H[0], b = H[1], c = H[2], d = H[3], e = H[4];
    for (t=0; t<20; t+=5)
    {
        R1(a,b,c,d,e,t+0);
        R1(e,a,b,c,d,t+1);
        R1(d,e,a,b,c,t+2);
        R1(c,d,e,a,b,t+3);
        R1(b,c,d,e,a,t+4);
    }
    for (   ; t<40; t+=5)
    {
        R2(a,b,c,d,e,t+0);
        R2(e,a,b,c,d,t+1);
        R2(d,e,a,b,c,t+2);
        R2(c,d,e,a,b,t+3);
        R2(b,c,d,e,a,t+4);
    }
    for (   ; t<60; t+=5)
    {
        R3(a,b,c,d,e,t+0);
        R3(e,a,b,c,d,t+1);
        R3(d,e,a,b,c,t+2);
        R3(c,d,e,a,b,t+3);
        R3(b,c,d,e,a,t+4);
    }
    for (   ; t<80; t+=5)
    {
        R4(a,b,c,d,e,t+0);
        R4(e,a,b,c,d,t+1);
        R4(d,e,a,b,c,t+2);
        R4(c,d,e,a,b,t+3);
        R4(b,c,d,e,a,t+4);
    }
    H[0] += a, H[1] += b, H[2] += c, H[3] += d, H[4] += e;
}


static inline uint32_t sigma0(uint32_t x)
{
    return ROTR(x, 7) ^ ROTR(x,18) ^ (x>> 3);
}
static inline uint32_t sigma1(uint32_t x)
{
    return ROTR(x,17) ^ ROTR(x,19) ^ (x>>10);
}
static inline uint32_t Sum0(uint32_t x)
{
    return ROTR(x,2) ^ ROTR(x,13) ^ ROTR(x,22);
}
static inline uint32_t Sum1(uint32_t x)
{
    return ROTR(x,6) ^ ROTR(x,11) ^ ROTR(x,25);
}

#if 0
/*! SHA-256 hash computation
    H -- hash [8]
    M -- message block 512 bit
 */
void SHA256_0(uint32_t * H, uint32_t * M)
{
    uint32_t W[64];
    int t; // Prepare the message schedule
    for (t=0; t<16; t++) W[t] = M[t];
    for (   ; t<64; t++) W[t] = sigma1(W[t-2]) + W[t-7] + sigma0(W[t-15]) + W[t-16];
    uint32_t a = H[0],b = H[1],c = H[2],d = H[3],e = H[4],f = H[5],g = H[6],h = H[7];
    for (t=0; t<64; t++)
    {
        uint32_t T = h + Sum1(e) + Ch(e,f,g) + K256[t] + W[t];
        h=g,g=f,f=e,e=d + T,d = c;
        T += Sum0(a) + Maj(a,b,c);
        c = b, b = a, a = T;
        //printf ("%2d: %08X %08X %08X %08X %08X %08X %08X %08X\n",t, a,b,c,d,e,f,g,h);
    }
    H[0]+=a, H[1]+=b, H[2]+=c, H[3]+=d, H[4]+=e, H[5]+=f, H[6]+=g, H[7]+=h;
}
#endif
#define ROUND(a,b,c,d,e,f,g,h,t) ({\
        uint32_t T = h + Sum1(e) + Ch(e,f,g) + K256[t] + W[t];  \
        d += T; \
        T += Sum0(a) + Maj(a,b,c); \
        h  = T; })
static void SHA256(uint32_t * H, uint32_t * M)
{
    uint32_t W[64];
    int t; // Prepare the message schedule
    for (t=0; t<16; t++) W[t] = M[t];
    for (   ; t<64; t++) {
        W[t] = sigma1(W[t-2]) + W[t-7] + sigma0(W[t-15]) + W[t-16];
    }
    uint32_t a = H[0],b = H[1],c = H[2],d = H[3],e = H[4],f = H[5],g = H[6],h = H[7];
    for (t=0; t<64; t+=8)
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
    H[0]+=a, H[1]+=b, H[2]+=c, H[3]+=d, H[4]+=e, H[5]+=f, H[6]+=g, H[7]+=h;
}


typedef struct _HashCtx HashCtx;
struct _HashCtx {
    uint32_t H[8];
    uint32_t buffer[16];
    uint32_t length;    // длина данных
    const uint32_t *H0;
    unsigned int hlen; // длина хеша
    void (* hash)(uint32_t * H, uint32_t *buffer);
};
/*!
надо предварительно назначить функцию hash и H0
 */
void SHA_init(HashCtx *ctx)
{
    int i; for (i=0; i<8; i++) ctx->H[i] = ctx->H0[i];
    ctx->length = 0;
//    ctx->hash = SHA1;
}

static void SHA160_init(HashCtx *ctx)
{
    int i; for (i=0; i < 5; i++) ctx->H[i] = H0_160[i];
    ctx->length = 0;
    ctx->hash = SHA1;
}
static void SHA256_init(HashCtx *ctx)
{
    int i; for (i=0; i < 8; i++) ctx->H[i] = H0_256[i];
    ctx->length = 0;
    ctx->hash = SHA256;
}
static void SHA224_init(HashCtx *ctx)
{
    int i; for (i=0; i < 8; i++) ctx->H[i] = H0_224[i];
    ctx->length = 0;
    ctx->hash = SHA256;
}

#define BLK_SIZE 64
/*
    len -- длина в байтах < 64
 */
void SHA_update(HashCtx *ctx, const uint8_t * msg, int mlen)
{
    unsigned int offset = ctx->length & (BLK_SIZE-1);
    ctx->length += mlen;
    while (mlen>0){
        unsigned int len = (mlen>BLK_SIZE-offset)?BLK_SIZE-offset: mlen;
        __builtin_memcpy((uint8_t*)ctx->buffer + offset, msg, len);
        msg+=len; mlen-=len; offset+=len;
        if (offset==BLK_SIZE){
            if (BYTE_ORDER==LITTLE_ENDIAN) ntohl_vec(ctx->buffer, BLK_SIZE/4);
            ctx->hash(ctx->H, ctx->buffer);
            offset = 0;
        }
    }
}

/*!
    Правило завершения буфера добавить 1'b1 в конец потока, забить нулями
    len+1+k=448 mod 512
    в конец блока записывается длина потока в битах, поле 64 бита
    в нотации network msb
    len - должна быть меньше 512b (64 байта)*/
void SHA_final(HashCtx *ctx, void *tag, unsigned int tlen)
{
    uint8_t *buffer = (void*)ctx->buffer;
    int offset = ctx->length&63;
    buffer[offset] = 0x80;
    if (offset >= 56)
    {// переход на следующий блок
        memset(&buffer[offset+1], 0, 63 - offset);
        if (BYTE_ORDER==LITTLE_ENDIAN) ntohl_vec(ctx->buffer, ((offset+4)>>2));
        ctx->hash(ctx->H, ctx->buffer);
        memset(&buffer[0], 0, 56);
    } else {
        memset(&buffer[offset+1], 0, 55 - offset);
        if (BYTE_ORDER==LITTLE_ENDIAN) ntohl_vec(ctx->buffer, ((offset+4)>>2));
    }
    ctx->buffer[15] = (ctx->length<< 3);
    ctx->buffer[14] = (ctx->length>>29);
    ctx->hash(ctx->H, ctx->buffer);
    if (BYTE_ORDER==LITTLE_ENDIAN) ntohl_vec(ctx->H, /*ctx->hlen>>2*/16);
    if(tlen) __builtin_memcpy(tag, ctx->H, tlen);

}
/*
static void digest2(uint32_t *H, uint8_t *tag, int tlen)
{
    uint8_t ch;
    int i;
    for (i=0; i<tlen; i++) {
        ch = HL2N(H, i);
        tag[i] = ch;//((uint8_t* )H)[i];//ch;
    }
}*/

void sha1sum(uint8_t *tag, uint8_t *msg, int length)
{
//1ed80c7749551a9d4c0eb55a3dc63d63273ad4bb
    HashCtx ct;
    HashCtx *ctx = &ct;
    SHA160_init(ctx);
    SHA_update(ctx, msg, length);
    SHA_final(ctx, tag, 20);
}

typedef struct _HashParams HashParams;
struct _HashParams {
    const char* name;
    void (*init)(HashCtx *ctx);
    const int length;
};
static const HashParams hash_params[] = {
    {"SHA-1",   SHA160_init, 20},
    {"SHA-224", SHA224_init, 28},
    {"SHA-256", SHA256_init, 32},
    {NULL, NULL, 0},
};
void sha2(uint8_t *hash, int id, uint8_t *msg, int length)
{
    HashCtx ct;
    HashCtx *ctx = &ct;
    hash_params[id].init(ctx);
    SHA_update(ctx, msg, length);
    SHA_final(ctx, hash, hash_params[id].length);
}

void ssha160(uint8_t *tag, uint8_t *msg, int mlen, uint8_t *salt, int slen)
{
    HashCtx ct;
    HashCtx *ctx = &ct;
    SHA160_init(ctx);
    SHA_update(ctx,  msg, mlen);
    SHA_update(ctx, salt, slen);
    SHA_final(ctx, tag, 20);
}

void ssha256(uint8_t *tag, uint8_t *msg, int mlen, uint8_t *salt, int slen)
{
    HashCtx ct;
    HashCtx *ctx = &ct;
    SHA256_init(ctx);
    SHA_update(ctx,  msg, mlen);
    SHA_update(ctx, salt, slen);
    SHA_final (ctx, tag, 32);
}

/*
void MD5_init(HashCtx *ctx)
{
    int i; for (i=0; i < 4; i++) ctx->H[i] = H0_128[i];
    ctx->length = 0;
    ctx->hash = MD5;
}
*/

/*! \brief The Keyed-Hash Message Authentication Code (HMAC)

    Генерация секретных хешей HMAC_SHA256

    \see
    http://csrc.nist.gov/publications/fips/fips198-1/FIPS-198-1_final.pdf
тестирование
    http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/HMAC_SHA1.pdf
    http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/HMAC_SHA256.pdf
 */

#define IPAD 0x3636363636363636ULL
#define OPAD 0x5C5C5C5C5C5C5C5CULL
void HMAC_SHA256_B(HashCtx* ctx, const uint8_t * msg, unsigned int mlen, uint64_t * Key)
{
//    HashCtx ct;
//    HashCtx* ctx =  &ct;
    const unsigned int block_len=64;//512 бит// 64 байта
    const unsigned int hash_len =ctx->hlen;//512 бит// 64 байта
    uint64_t K[block_len/8], H[(hash_len+7)/8];
    unsigned int i;

// 1. длина ключа равна длине блока
    for (i=0; i< block_len/8; i++) K[i] = Key[i] ^ (IPAD);
    SHA_init   (ctx);
    SHA_update (ctx, (void*)K,  block_len);
    SHA_update (ctx, msg, mlen);
    SHA_final  (ctx, H, hash_len);
    for (i=0; i< block_len/8; i++) K[i] = Key[i] ^ (OPAD);

    SHA_init   (ctx);
    SHA_update (ctx, (void*)K,  block_len);
    SHA_update (ctx, (void*)H,  hash_len);
    SHA_final  (ctx, NULL, 0);
}

void HMAC_SHA256_key(HashCtx* ctx, uint64_t *K, const void* key, unsigned int klen)
{
    const unsigned int block_len=64;//512 бит// 64 байта
    const unsigned int hash_len = ctx->hlen;
    unsigned int i;
    if (klen > block_len)
    {
        for (i=hash_len/8; i<block_len/8; i++) K[i] = 0;
        SHA_init   (ctx);
        SHA_update (ctx, key,  klen);
        SHA_final  (ctx, K, hash_len);
    } else
    if (klen < block_len)
    {
        __builtin_memcpy(K, key, klen);
        memset(((uint8_t*)K) + klen, 0, block_len-klen);
    } else {
        __builtin_memcpy(K, key, block_len);
    }
}
void HMAC_SHA256(HashCtx* ctx, const uint8_t * msg, unsigned int mlen, const uint8_t * key, unsigned int klen)
{
//    HashCtx ct;
//    HashCtx* ctx =  &ct;
    const unsigned int block_len=64;//512 бит// 64 байта
//    const unsigned int hash_len =ctx->hlen;//512 бит// 64 байта
    uint64_t K[block_len/8];// ={0};
    HMAC_SHA256_key(ctx, K, key, klen);
    HMAC_SHA256_B(ctx, msg, mlen, K);
}
/*! \brief Password-based key derivation function PKCS#5
 */
void PBKDF2_HMAC_SHA256(HashCtx* ctx, void* dk, unsigned int dklen, const uint8_t *passwd, unsigned int plen,
                      const uint8_t *salt, unsigned int slen, unsigned int c)
{
//    HashCtx ct;
//    HashCtx* ctx = &ct;
//    ctx->H0 = H0_160; ctx->hash = SHA1; ctx->hlen = hash_len;
    const unsigned int block_len=64;
    uint64_t K[block_len/8];
    HMAC_SHA256_key(ctx, K, passwd, plen);

    const unsigned int hash_len = ctx->hlen;
    //unsigned int n = (dklen+ctx->hlen-1)/hash_len;
    uint8_t S[slen+4];
    __builtin_memcpy(S, salt, slen);
    uint32_t H[hash_len/4], U[hash_len/4];
    int i,j, offset=0, count=1;
    while (dklen>0)
    {
        S[slen] = 0, S[slen+1] = 0, S[slen+2] = count>>8, S[slen+3] = count & 0xFF;
        HMAC_SHA256_B(ctx,S, slen+4, K);//passwd, plen);
        for (i=0; i<hash_len/4; i++) H[i] = U[i] = ctx->H[i];//htonl(ctx->H[i]);
        for (j=1; j<c; j++){
            HMAC_SHA256_B(ctx,(void*)U, hash_len, K);//passwd, plen);
            for (i=0; i<hash_len/4; i++) H[i] ^= U[i] = ctx->H[i];//htonl(ctx->H[i]);
        }
        int len =(dklen>hash_len)? hash_len:dklen;
        __builtin_memcpy((uint8_t*)dk + offset, H, len);
        dklen -= len;
        offset+= len;
        //for (i=0; i<hash_len/4; i++) printf("%08X ",H[i]); printf("\n");
        count++;
    }
}
void pbkdf2_hmac_sha1(void* dk, unsigned int dklen, const uint8_t *passwd, unsigned int plen, const uint8_t *salt, unsigned int slen, unsigned int c)
{
    HashCtx ctx;
    ctx.H0 = H0_160; ctx.hash = SHA1; ctx.hlen = 20;
    PBKDF2_HMAC_SHA256(&ctx, dk, dklen, passwd, plen, salt, slen, c);
}

MESSAGE_DIGEST(MD_SHA1) {
    .id = MD_SHA1,
    .name = "SHA-1",
    .block_len = 64,
    .hash_len = 20,
    .ctx_size = sizeof(HashCtx),
    .init   = (void*)SHA160_init,
    .update = (void*)SHA_update,
    .final  = (void*)SHA_final,
};
MESSAGE_DIGEST(MD_SHA224) {
    .id = MD_SHA224,
    .name = "SHA-224",
    .block_len = 64,
    .hash_len = 28,
    .ctx_size = sizeof(HashCtx),
    .init   = (void*)SHA224_init,
    .update = (void*)SHA_update,
    .final  = (void*)SHA_final,
};
MESSAGE_DIGEST(MD_SHA256) {
    .id = MD_SHA256,
    .name = "SHA-256",
    .block_len = 64,
    .hash_len = 32,
    .ctx_size = sizeof(HashCtx),
    .init   = (void*)SHA256_init,
    .update = (void*)SHA_update,
    .final  = (void*)SHA_final,
};


#ifdef TEST_SHA
/*! \brief Функция заполняет поле контроля целостности заданной длины в сетевом формате
    \param H -- результат функции хеширования
    \param tag -- ссылка на буфер заданной длины
    \param tlen -- размер Тега в байтах
 */

void digest(uint32_t *H, uint8_t *tag, int tlen)
{
    uint8_t c, ch;
    int i;
    for (i=0; i<tlen; i++) {
        ch = HL2N(H, i);
        c = (ch>>4) & 0xF;
        tag[2*i  ] = (c)>9? (c)+'a'-10:(c)+'0';
        c = (ch   ) & 0xF;
        tag[2*i+1] = (c)>9? (c)+'a'-10:(c)+'0';
    }
}

/*! тестирование алгоритма SHA1, SHA2
*/
int  main()
{
    int i;
    uint32_t W[16] = {[0] = 0x61626380, [15] = 0x00000018};
    HashCtx ct;
    HashCtx *ctx = &ct;
    SHA256_init(ctx); SHA256(ctx->H, W);
    for (i=0; i<8; i++) printf("%08X ",ctx->H[i]); printf("\n");
    SHA256_init(ctx); SHA_update(ctx, "abc", 3); SHA_final(ctx,NULL, 0);
    for (i=0; i<8; i++) printf("%08X ",ctx->H[i]); printf("\n");


    uint32_t W1[16] = {
    0x61626364, 0x62636465, 0x63646566, 0x64656667, 0x65666768, 0x66676869, 0x6768696A, 0x68696A6B,
    0x696A6B6C, 0x6A6B6C6D, 0x6B6C6D6E, 0x6C6D6E6F, 0x6D6E6F70, 0x6E6F7071, 0x80000000, 0x00000000};
    uint32_t W2[16] = {[15] = 0x000001C0};
    uint8_t * msg2 = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    uint8_t * msg21 = "abcdbcdecdefdefgefghfghigh";
    uint8_t * msg22 = "ijhijkijkljklmklmnlmnomnopnopq";
// тестирование алгоритма SHA-256
    SHA256_init(ctx); SHA256(ctx->H, W1); SHA256(ctx->H, W2);
    for (i=0; i<8; i++) printf("%08X ",ctx->H[i]); printf("\n");
    SHA256_init(ctx); SHA_update(ctx, msg2, strlen(msg2)); SHA_final(ctx,NULL, 0);
    for (i=0; i<8; i++) printf("%08X ",ctx->H[i]); printf("\n");
printf("SHA-256:\n");
    SHA256_init(ctx); SHA_update(ctx, msg21, strlen(msg21)); SHA_update(ctx, msg21, strlen(msg22)); SHA_final(ctx,NULL, 0);
    for (i=0; i<8; i++) printf("%08X ",ctx->H[i]); printf("\n");

// тестирование алгоритма SHA-224
    SHA224_init(ctx); SHA_update(ctx, "abc", 3); SHA_final(ctx,NULL, 0);
    for (i=0; i<7; i++) printf("%08X ",ctx->H[i]); printf("\n");
    SHA224_init(ctx); SHA_update(ctx, msg2, strlen(msg2)); SHA_final(ctx,NULL, 0);
    for (i=0; i<7; i++) printf("%08X ",ctx->H[i]); printf("\n");
// тестирование алгоритма SHA-1
    SHA160_init(ctx); SHA_update(ctx, "abc", 3); SHA_final(ctx,NULL, 0);
    for (i=0; i<5; i++) printf("%08X ",ctx->H[i]); printf("\n");
    SHA160_init(ctx); SHA_update(ctx, msg2, strlen(msg2)); SHA_final(ctx,NULL, 0);
    for (i=0; i<5; i++) printf("%08X ",ctx->H[i]); printf("\n");
/*
    MD5_init(ctx); SHA_update(ctx, "abc", 3); SHA_final(ctx);
    for (i=0; i<4; i++) printf("%08X ",ctx->H[i]); printf("\n");
*/
{// SHA-160
    uint8_t msg[] = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    SHA160_init(ctx); SHA_update(ctx, msg, strlen(msg)); SHA_final(ctx,NULL, 0);
    printf ("SHA1 Message Digest is\n");
    for (i=0; i<5; i++) printf("%08X ",ctx->H[i]); printf("\n");
    uint8_t tag[64];
    digest(ctx->H, tag, 20);
//Message Digest is 84983E44 1C3BD26E BAAE4AA1 F95129E5 E54670F1
    for (i=0; i<20; i++) {
        printf("%02X",tag[i]);
        if ((i&3) == 3) printf(" ");
    }
    printf("\n");

}
{
    printf("HMAC-SHA1\n");
    ctx->H0 = H0_160; ctx->hash = SHA1; ctx->hlen = 20;
    uint8_t msg[] = "Sample message for keylen=blocklen";
    uint32_t key[] = {
        0x00010203, 0x04050607, 0x08090A0B, 0x0C0D0E0F,
        0x10111213, 0x14151617, 0x18191A1B, 0x1C1D1E1F,
        0x20212223, 0x24252627, 0x28292A2B, 0x2C2D2E2F,
        0x30313233, 0x34353637, 0x38393A3B, 0x3C3D3E3F,
        0x40414243, 0x44454647, 0x48494A4B, 0x4C4D4E4F,
        0x50515253, 0x54555657, 0x58595A5B, 0x5C5D5E5F,
        0x60616263
    };
    for (i=0; i<25; i++) key[i] = ntohl(key[i]);
    HMAC_SHA256(ctx, msg, strlen(msg), (void*)key, 64);
    for (i=0; i<5; i++) printf("%08X ",ctx->H[i]); printf("\n");
    uint32_t h0[] = {
        0x5FD596EE, 0x78D5553C, 0x8FF4E72D, 0x266DFD19, 0x2366DA29
    };
    if (memcmp(ctx->H,h0,5*4)==0) printf("OK\n");
    uint8_t msg1[] = "Sample message for keylen<blocklen";
    HMAC_SHA256(ctx, msg1, strlen(msg1), (void*)key, 20);
    for (i=0; i<5; i++) printf("%08X ",ctx->H[i]); printf("\n");
    uint32_t h1[] = {
        0x4C99FF0C, 0xB1B31BD3, 0x3F8431DB, 0xAF4D17FC, 0xD356A807 };
    if (memcmp(ctx->H,h1,5*4)==0) printf("OK\n");
    HMAC_SHA256(ctx, msg, strlen(msg), (void*)key, 100);
    for (i=0; i<5; i++) printf("%08X ",ctx->H[i]); printf("\n");
    uint32_t h2[] = {
        0x2D51B2F7, 0x750E4105, 0x84662E38, 0xF133435F, 0x4C4FD42A };
    if (memcmp(ctx->H,h2,5*4)==0) printf("OK\n");
    uint8_t msg2[] = "Sample message for keylen<blocklen, with truncated tag";
    HMAC_SHA256(ctx, msg2, strlen(msg2), (void*)key, 49);
    for (i=0; i<5; i++) printf("%08X ",ctx->H[i]); printf("\n");
    uint32_t h3[] = { 0xFE352956, 0x5CD8E28C, 0x5FA79EAC };
    if (memcmp(ctx->H,h3,3*4)==0) printf("OK\n");
}
{
    printf("HMAC-SHA-224\n");
    ctx->H0 = H0_224; ctx->hash = SHA256; ctx->hlen = 28;
    uint8_t msg[] = "Sample message for keylen=blocklen";
    uint32_t key[] = {
        0x00010203, 0x04050607, 0x08090A0B, 0x0C0D0E0F,
        0x10111213, 0x14151617, 0x18191A1B, 0x1C1D1E1F,
        0x20212223, 0x24252627, 0x28292A2B, 0x2C2D2E2F,
        0x30313233, 0x34353637, 0x38393A3B, 0x3C3D3E3F,
        0x40414243, 0x44454647, 0x48494A4B, 0x4C4D4E4F,
        0x50515253, 0x54555657, 0x58595A5B, 0x5C5D5E5F,
        0x60616263
    };
    for (i=0; i<25; i++) key[i] = ntohl(key[i]);
    HMAC_SHA256(ctx, msg, strlen(msg), (void*)key, 64);
    for (i=0; i<7; i++) printf("%08X ",ctx->H[i]); printf("\n");
    uint32_t h0[] = {
        0xC7405E3A, 0xE058E8CD, 0x30B08B41, 0x40248581, 0xED174CB3, 0x4E1224BC, 0xC1EFC81B
    };
    if (memcmp(ctx->H,h0,ctx->hlen)==0) printf("OK\n");
    uint8_t msg1[] = "Sample message for keylen<blocklen";
    HMAC_SHA256(ctx, msg1, strlen(msg1), (void*)key, 28);
    for (i=0; i<7; i++) printf("%08X ",ctx->H[i]); printf("\n");
    uint32_t h1[] = {
        0xE3D249A8, 0xCFB67EF8, 0xB7A169E9, 0xA0A59971, 0x4A2CECBA, 0x65999A51, 0xBEB8FBBE};
    if (memcmp(ctx->H,h1,ctx->hlen)==0) printf("OK\n");
    HMAC_SHA256(ctx, msg, strlen(msg), (void*)key, 100);
    for (i=0; i<7; i++) printf("%08X ",ctx->H[i]); printf("\n");
    uint32_t h2[] = {
        0x91C52509, 0xE5AF8531, 0x601AE623, 0x0099D90B, 0xEF88AAEF, 0xB961F408, 0x0ABC014D};
    if (memcmp(ctx->H,h2,ctx->hlen)==0) printf("OK\n");
    uint8_t msg2[] = "Sample message for keylen<blocklen, with truncated tag";
    HMAC_SHA256(ctx, msg2, strlen(msg2), (void*)key, 49);
    for (i=0; i<7; i++) printf("%08X ",ctx->H[i]); printf("\n");
    uint32_t h3[] = {
        0xD522F1DF, 0x596CA4B4, 0xB1C23D27, 0xBDE067D6};
    if (memcmp(ctx->H,h3,4*4)==0) printf("OK\n");

}
{
    printf("HMAC-SHA-256\n");
    ctx->H0 = H0_256; ctx->hash = SHA256; ctx->hlen = 32;
    uint8_t msg[] = "Sample message for keylen=blocklen";
    uint32_t key[] = {
        0x00010203, 0x04050607, 0x08090A0B, 0x0C0D0E0F,
        0x10111213, 0x14151617, 0x18191A1B, 0x1C1D1E1F,
        0x20212223, 0x24252627, 0x28292A2B, 0x2C2D2E2F,
        0x30313233, 0x34353637, 0x38393A3B, 0x3C3D3E3F,
        0x40414243, 0x44454647, 0x48494A4B, 0x4C4D4E4F,
        0x50515253, 0x54555657, 0x58595A5B, 0x5C5D5E5F,
        0x60616263
    };
    for (i=0; i<25; i++) key[i] = ntohl(key[i]);
    HMAC_SHA256(ctx, msg, strlen(msg), (void*)key, 64);
    for (i=0; i<8; i++) printf("%08X ",ctx->H[i]); printf("\n");
    uint32_t h0[] = {
        0x8BB9A1DB, 0x9806F20D, 0xF7F77B82, 0x138C7914, 0xD174D59E, 0x13DC4D01, 0x69C9057B, 0x133E1D62
    };
    if (memcmp(ctx->H,h0,8*4)==0) printf("OK\n");
    uint8_t msg1[] = "Sample message for keylen<blocklen";
    HMAC_SHA256(ctx, msg1, strlen(msg1), (void*)key, 32);
    for (i=0; i<8; i++) printf("%08X ",ctx->H[i]); printf("\n");
    uint32_t h1[] = {
        0xA28CF431, 0x30EE696A, 0x98F14A37, 0x678B56BC, 0xFCBDD9E5, 0xCF69717F, 0xECF5480F, 0x0EBDF790};
    if (memcmp(ctx->H,h1,8*4)==0) printf("OK\n");
    HMAC_SHA256(ctx, msg, strlen(msg), (void*)key, 100);
    for (i=0; i<8; i++) printf("%08X ",ctx->H[i]); printf("\n");
    uint32_t h2[] = {
        0xBDCCB6C7, 0x2DDEADB5, 0x00AE7683, 0x86CB38CC, 0x41C63DBB, 0x0878DDB9, 0xC7A38A43, 0x1B78378D };
    if (memcmp(ctx->H,h2,8*4)==0) printf("OK\n");
    uint8_t msg2[] = "Sample message for keylen<blocklen, with truncated tag";
    HMAC_SHA256(ctx, msg2, strlen(msg2), (void*)key, 49);
    for (i=0; i<8; i++) printf("%08X ",ctx->H[i]); printf("\n");
    uint32_t h3[] = {
        0x27A8B157, 0x839EFEAC, 0x98DF070B, 0x331D5936};
    if (memcmp(ctx->H,h3,4*4)==0) printf("OK\n");
    printf("RFC 4231\n");
    uint8_t k0[] = "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"
                    "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b";
    uint8_t m0[] = "Hi There";
    HMAC_SHA256(ctx, m0, 8, k0, 20);
    for (i=0; i<8; i++) printf("%08X ",ctx->H[i]); printf("\n");
    uint32_t h4[] = {0xb0344c61, 0xd8db3853, 0x5ca8afce, 0xaf0bf12b,
                0x881dc200, 0xc9833da7, 0x26e9376c, 0x2e32cff7};
    if (memcmp(ctx->H,h4,32)==0) printf("OK\n");
    uint8_t k1[] =  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                    "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa";//, 20,
    uint8_t m1[] =  "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
                    "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
                    "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
                    "\xdd\xdd";//, 50,
    HMAC_SHA256(ctx, m1, 50, k1, 20);
    for (i=0; i<8; i++) printf("%08X ",ctx->H[i]); printf("\n");
	uint32_t h5[] = {0x773ea91e, 0x36800e46, 0x854db8eb, 0xd09181a7,
		0x2959098b, 0x3ef8c122, 0xd9635514, 0xced565fe};
    if (memcmp(ctx->H,h5,32)==0) printf("OK\n");
/*
    uint8_t tag[64];
    digest(ctx->H, tag, 32);
    for (i=0; i<32; i++) {
        printf("%02X",tag[i]);
        if ((i&3) == 3) printf(" ");
    }
    printf("\n");*/
}
{
    printf("PBKDF2_HMAC_SHA1\n");
    ctx->H0 = H0_160; ctx->hash = SHA1; ctx->hlen = 20;
    uint32_t dk[8];
    PBKDF2_HMAC_SHA256(ctx, dk, 20, "password", 8, "salt", 4, 1);
    uint32_t h0[] = {0x0c60c80f, 0x961f0e71, 0xf3a9b524, 0xaf601206, 0x2fe037a6};
    for (i=0; i<5; i++) h0[i] = htonl(h0[i]);
    if(memcmp(dk,h0, 20)==0) printf("OK\n");
    PBKDF2_HMAC_SHA256(ctx, dk, 20, "password", 8, "salt", 4, 2);
    uint32_t h1[] = {0xea6c014d, 0xc72d6f8c, 0xcd1ed92a, 0xce1d41f0, 0xd8de8957};
    for (i=0; i<5; i++) h1[i] = htonl(h1[i]);
    if(memcmp(dk,h1, 20)==0) printf("OK\n");
    PBKDF2_HMAC_SHA256(ctx, dk, 20, "password", 8, "salt", 4, 4096);
    uint32_t h2[] = {0x4b007901, 0xb765489a, 0xbead49d9, 0x26f721d0, 0x65a429c1};
    for (i=0; i<5; i++) h2[i] = htonl(h2[i]);
    if(memcmp(dk,h2, 20)==0) printf("OK\n");
    //PBKDF2_HMAC_SHA256(ctx, dk, 20, "password", 8, "salt", 4, 16777216);
    uint32_t h3[] = {0xeefe3d61, 0xcd4da4e4, 0xe9945b3d, 0x6ba2158c, 0x2634e984};
    for (i=0; i<5; i++) h3[i] = htonl(h3[i]);
    if(memcmp(dk,h3, 20)==0) printf("OK\n");
    PBKDF2_HMAC_SHA256(ctx, dk, 25, "passwordPASSWORDpassword", 24, "saltSALTsaltSALTsaltSALTsaltSALTsalt", 36, 4096);
    uint8_t h4[32] = {
            0x3d, 0x2e, 0xec, 0x4f, 0xe4, 0x1c, 0x84, 0x9b,
            0x80, 0xc8, 0xd8, 0x36, 0x62, 0xc0, 0xe4, 0x4a,
            0x8b, 0x29, 0x1a, 0x96, 0x4c, 0xf2, 0xf0, 0x70,
            0x38};
    if(memcmp(dk,h4, 25)==0) printf("OK\n");
    uint8_t h5[16] = {0x56, 0xfa, 0x6a, 0xa7, 0x55, 0x48, 0x09, 0x9d, 0xcc, 0x37, 0xd7, 0xf0, 0x34, 0x25, 0xe0, 0xc3};
    PBKDF2_HMAC_SHA256(ctx, dk, 16, "pass\0word", 9, "sa\0lt", 5, 4096);
    if(memcmp(dk,h5, 16)==0) printf("OK\n");
//    printf("KBKDF PRF=HMAC_SHA1\n");
}
{
    printf("PBKDF2_HMAC_SHA256\n");
    ctx->H0 = H0_256; ctx->hash = SHA256; ctx->hlen = 32;
    uint32_t dk[10];
    PBKDF2_HMAC_SHA256(ctx, dk, 32, "password", 8, "salt", 4, 1);
    uint8_t h0[32] = {0x12, 0x0f, 0xb6, 0xcf, 0xfc, 0xf8, 0xb3, 0x2c,
       0x43, 0xe7, 0x22, 0x52, 0x56, 0xc4, 0xf8, 0x37,
       0xa8, 0x65, 0x48, 0xc9, 0x2c, 0xcc, 0x35, 0x48,
       0x08, 0x05, 0x98, 0x7c, 0xb7, 0x0b, 0xe1, 0x7b};
    if(memcmp(dk,h0, 32)==0) printf("OK\n");
	PBKDF2_HMAC_SHA256(ctx, dk, 32, "password", 8, "salt", 4, 2);
	uint8_t h1[32] = {0xae, 0x4d, 0x0c, 0x95, 0xaf, 0x6b, 0x46, 0xd3,
       0x2d, 0x0a, 0xdf, 0xf9, 0x28, 0xf0, 0x6d, 0xd0,
       0x2a, 0x30, 0x3f, 0x8e, 0xf3, 0xc2, 0x51, 0xdf,
       0xd6, 0xe2, 0xd8, 0x5a, 0x95, 0x47, 0x4c, 0x43};
	if(memcmp(dk,h1, 32)==0) printf("OK\n");
	PBKDF2_HMAC_SHA256(ctx, dk, 32, "password", 8, "salt", 4, 4096);
	uint8_t h2[32] = {0xc5, 0xe4, 0x78, 0xd5, 0x92, 0x88, 0xc8, 0x41,
       0xaa, 0x53, 0x0d, 0xb6, 0x84, 0x5c, 0x4c, 0x8d,
       0x96, 0x28, 0x93, 0xa0, 0x01, 0xce, 0x4e, 0x11,
       0xa4, 0x96, 0x38, 0x73, 0xaa, 0x98, 0x13, 0x4a};
	if(memcmp(dk,h2, 32)==0) printf("OK\n");
	//PBKDF2_HMAC_SHA256(ctx, dk, 32, "password", 8, "salt", 4, 16777216);
	uint8_t h3[32] = {0xcf, 0x81, 0xc6, 0x6f, 0xe8, 0xcf, 0xc0, 0x4d,
       0x1f, 0x31, 0xec, 0xb6, 0x5d, 0xab, 0x40, 0x89,
       0xf7, 0xf1, 0x79, 0xe8, 0x9b, 0x3b, 0x0b, 0xcb,
       0x17, 0xad, 0x10, 0xe3, 0xac, 0x6e, 0xba, 0x46};
	if(memcmp(dk,h3, 32)==0) printf("OK\n");
	PBKDF2_HMAC_SHA256(ctx, dk, 40, "passwordPASSWORDpassword", 24, "saltSALTsaltSALTsaltSALTsaltSALTsalt", 36, 4096);
	uint8_t h4[40] = {0x34, 0x8c, 0x89, 0xdb, 0xcb, 0xd3, 0x2b, 0x2f,
       0x32, 0xd8, 0x14, 0xb8, 0x11, 0x6e, 0x84, 0xcf,
       0x2b, 0x17, 0x34, 0x7e, 0xbc, 0x18, 0x00, 0x18,
       0x1c, 0x4e, 0x2a, 0x1f, 0xb8, 0xdd, 0x53, 0xe1,
       0xc6, 0x35, 0x51, 0x8c, 0x7d, 0xac, 0x47, 0xe9};
	if(memcmp(dk,h4, 40)==0) printf("OK\n");
	PBKDF2_HMAC_SHA256(ctx, dk, 16, "pass\0word", 9, "sa\0lt", 5, 4096);
	uint8_t h5[16] = {0x89, 0xb6, 0x9d, 0x05, 0x16, 0xf8, 0x29, 0x89,
       0x3c, 0x69, 0x62, 0x26, 0x65, 0x0a, 0x86, 0x87};
	if(memcmp(dk,h5, 16)==0) printf("OK\n");
}
    return 0;
}
#endif
