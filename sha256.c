#include <stdint.h>
#include "hmac.h"
#include <stdio.h>
//#include <string.h>

typedef struct _HashCtx HashCtx;
struct _HashCtx {
    uint32_t H[8];
    uint32_t buffer[16];
    uint32_t length;    // длина данных
};
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
static inline uint32_t ROTR(uint32_t v, int i)
{
    return (v<<(32-i)) ^ (v>>i);
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
#define ROUND(a,b,c,d,e,f,g,h,i) ({\
		W[i] = M[i]; \
        h += Sum1(e) + Ch(e,f,g) + K256[i] + W[i];  \
        d += h; \
        h += Sum0(a) + Maj(a,b,c); \
		})
#define ROUND2(a,b,c,d,e,f,g,h,i) ({\
		W[i&15] += sigma1(W[(i-2)&15]) + W[(i-7)&15] + sigma0(W[(i-15)&15]);\
        h += Sum1(e) + Ch(e,f,g) + K256[t+i] + W[i&15];  \
        d += h; \
        h += Sum0(a) + Maj(a,b,c); \
		})
static
void SHA256(uint32_t * H, uint32_t * M)
{// всего задействованы 16+8 переменных
    uint32_t W[16];
    // Prepare the message schedule
    register uint32_t a = H[0],b = H[1],c = H[2],d = H[3],e = H[4],f = H[5],g = H[6],h = H[7];
    {
        ROUND(a,b,c,d,e,f,g,h,0);
        ROUND(h,a,b,c,d,e,f,g,1);
        ROUND(g,h,a,b,c,d,e,f,2);
        ROUND(f,g,h,a,b,c,d,e,3);
        ROUND(e,f,g,h,a,b,c,d,4);
        ROUND(d,e,f,g,h,a,b,c,5);
        ROUND(c,d,e,f,g,h,a,b,6);
        ROUND(b,c,d,e,f,g,h,a,7);
        ROUND(a,b,c,d,e,f,g,h,8);
        ROUND(h,a,b,c,d,e,f,g,9);
        ROUND(g,h,a,b,c,d,e,f,10);
        ROUND(f,g,h,a,b,c,d,e,11);
        ROUND(e,f,g,h,a,b,c,d,12);
        ROUND(d,e,f,g,h,a,b,c,13);
        ROUND(c,d,e,f,g,h,a,b,14);
        ROUND(b,c,d,e,f,g,h,a,15);
	}
    for (int t=16; t<64; t+=16)
    {
        ROUND2(a,b,c,d,e,f,g,h,0);
        ROUND2(h,a,b,c,d,e,f,g,1);
        ROUND2(g,h,a,b,c,d,e,f,2);
        ROUND2(f,g,h,a,b,c,d,e,3);
        ROUND2(e,f,g,h,a,b,c,d,4);
        ROUND2(d,e,f,g,h,a,b,c,5);
        ROUND2(c,d,e,f,g,h,a,b,6);
        ROUND2(b,c,d,e,f,g,h,a,7);
        ROUND2(a,b,c,d,e,f,g,h,8);
        ROUND2(h,a,b,c,d,e,f,g,9);
        ROUND2(g,h,a,b,c,d,e,f,10);
        ROUND2(f,g,h,a,b,c,d,e,11);
        ROUND2(e,f,g,h,a,b,c,d,12);
        ROUND2(d,e,f,g,h,a,b,c,13);
        ROUND2(c,d,e,f,g,h,a,b,14);
        ROUND2(b,c,d,e,f,g,h,a,15);
    }
    H[0]+=a, H[1]+=b, H[2]+=c, H[3]+=d, H[4]+=e, H[5]+=f, H[6]+=g, H[7]+=h;
}

/*! векторная операция */
static void ntohl_vec(uint32_t * v, int len)
{
/*    int i;
    for (i=0;i<len;i++)
    {
        v[i] = __builtin_bswap32(v[i]);
    }*/
#if (__BYTE_ORDER__==__ORDER_LITTLE_ENDIAN__)
    do {*v = __builtin_bswap32(*v), v++;} while(--len);
#endif
}
static uint32_t htole32(uint32_t  v)
{
#if (__BYTE_ORDER__==__ORDER_BIG_ENDIAN__)
    return __builtin_bswap32(v);
#else
	return (v);
#endif
}
static void sha256_init(HashCtx *ctx)
{
	static const uint32_t H0_256[8] = {
	0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
	};
	__builtin_memcpy(ctx->H, H0_256, 32);
    ctx->length = 0;
}
#define BLK_SIZE 64
/*
    len -- длина в байтах < 64
 */
static void sha256_update(HashCtx *ctx, const uint8_t * msg, int mlen)
{
    unsigned int offset = ctx->length & (BLK_SIZE-1);
    ctx->length += mlen;
    while (mlen>0){
        unsigned int len = (mlen>BLK_SIZE-offset)?BLK_SIZE-offset: mlen;
        __builtin_memcpy((uint8_t*)ctx->buffer + offset, msg, len);
        msg+=len; mlen-=len; offset+=len;
        if (offset==BLK_SIZE){
            //if (__BYTE_ORDER__==__ORDER_LITTLE_ENDIAN__) 
			ntohl_vec(ctx->buffer, BLK_SIZE/4);
            SHA256(ctx->H, ctx->buffer);
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
static void sha256_final(HashCtx *ctx, void *tag, unsigned int tlen)
{
    uint8_t *buffer = (uint8_t*)ctx->buffer;
    int offset = ctx->length&63;
    buffer[offset] = 0x80;
    if (offset >= 56)
    {// переход на следующий блок
        __builtin_memset(&buffer[offset+1], 0, 63 - offset);
        //if (__BYTE_ORDER__==__ORDER_LITTLE_ENDIAN__) 
		ntohl_vec(ctx->buffer, 64/4);
        SHA256(ctx->H, ctx->buffer);
        __builtin_memset(&buffer[0], 0, 64);
    } else {
        __builtin_memset(&buffer[offset+1], 0, 55 - offset);
        //if (__BYTE_ORDER__==__ORDER_LITTLE_ENDIAN__) 
		ntohl_vec(ctx->buffer, ((offset+4)>>2));
    }
//	*(uint64_t*)(ctx->buffer+56) = htonll(ctx->length<<3);
    ctx->buffer[15] = htole32(ctx->length<< 3);
    ctx->buffer[14] = htole32(ctx->length>>29);
    SHA256(ctx->H, ctx->buffer);
    //if (__BYTE_ORDER__==__ORDER_LITTLE_ENDIAN__) 
	ntohl_vec(ctx->H, /*ctx->hlen>>2*/32/4);
    __builtin_memcpy(tag, ctx->H, 32);

}
MESSAGE_DIGEST(MD_SHA256) {
    .id = MD_SHA256,
    .name = "SHA-256",
    .block_len = 64,
    .hash_len = 32,
    .ctx_size = sizeof(HashCtx),
    .init   = (void*)sha256_init,
    .update = (void*)sha256_update,
    .final  = (void*)sha256_final,
};
#if defined(TEST_SHA256)
#include <stdio.h>
int main(){
	char* msg  =    "";
	char* hash =    "\xe3\xb0\xc4\x42\x98\xfc\x1c\x14\x9a\xfb\xf4\xc8\x99\x6f\xb9\x24\x27\xae\x41\xe4\x64\x9b\x93\x4c\xa4\x95\x99\x1b\x78\x52\xb8\x55";
	char tag[32];
	sha256(tag, (uint8_t*)msg, 0);
    if (__builtin_memcmp(tag, hash,32)==0) {
		for (int i=0; i<32;i++)
			printf("% 02X",(uint8_t)tag[i]);
		printf("\n");
		printf("OK\n");
	} else {
		printf("Fail\n");
	}
	sha256d(tag, (uint8_t*)msg, 0);
	for (int i=0; i<32;i++)
		printf("% 02X",(uint8_t)tag[i]);
	printf("\n");
	return 0;
}
#endif