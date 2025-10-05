/*
$ clang --target=aarch64 -march=armv8-a+crypto -O3 -S -o sha_arm.s  sha256_arm.c
$ llvm-mca --march=aarch64 --mcpu=neoverse-v2 -timeline sha_arm.s | less
*/

#include <stdint.h>
#include "hmac.h"

#if defined(__ARM_NEON)
# include <arm_neon.h>
#endif
/* GCC and LLVM Clang, but not Apple Clang */
#if defined(__ARM_ACLE) || defined(__ARM_FEATURE_CRYPTO)
# include <arm_acle.h>
#endif
static const uint32_t K[] =
{
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
    0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
    0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
    0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
    0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
    0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
    0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
    0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
    0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
};
/* Process multiple blocks. The caller is responsible for setting the initial */
/*  state, and the caller is responsible for padding the final block.        */
static 
void SHA256(uint32_t *state, const uint32_t *data)
{
    uint32x4_t STATE0, STATE1, ABEF_SAVE, CDGH_SAVE;
    uint32x4_t MSG0, MSG1, MSG2, MSG3;
__asm volatile("# LLVM-MCA-BEGIN SHA256_arm");
    /* Load state */
    STATE0 = vld1q_u32(&state[0]);
    STATE1 = vld1q_u32(&state[4]);

        /* Save state */
        ABEF_SAVE = STATE0;
        CDGH_SAVE = STATE1;

        /* Load message */
        MSG0 = vld1q_u32((const uint32_t *)(data + 0));
        MSG1 = vld1q_u32((const uint32_t *)(data + 4));
        MSG2 = vld1q_u32((const uint32_t *)(data + 8));
        MSG3 = vld1q_u32((const uint32_t *)(data +12));

        /* Reverse for little endian */
	{ int t=0;
        //MSG0 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(MSG0)));
        //MSG1 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(MSG1)));
        //MSG2 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(MSG2)));
        //MSG3 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(MSG3)));
		{	uint32x4_t TMP;
			uint32x4_t WK = vaddq_u32(MSG0, vld1q_u32(&K[t+0]));
			TMP = vsha256h2q_u32(STATE1, STATE0, WK);
			STATE0 = vsha256hq_u32(STATE0, STATE1, WK);
			STATE1 = TMP;
		}
		{	uint32x4_t TMP;
			uint32x4_t WK = vaddq_u32(MSG1, vld1q_u32(&K[t+4]));
			TMP = vsha256h2q_u32(STATE1, STATE0, WK);
			STATE0 = vsha256hq_u32(STATE0, STATE1, WK);
			STATE1 = TMP;
		}
		{	uint32x4_t TMP;
			uint32x4_t WK = vaddq_u32(MSG2, vld1q_u32(&K[t+8]));
			TMP = vsha256h2q_u32(STATE1, STATE0, WK);
			STATE0 = vsha256hq_u32(STATE0, STATE1, WK);
			STATE1 = TMP;
		}
		{	uint32x4_t TMP;
			uint32x4_t WK = vaddq_u32(MSG3, vld1q_u32(&K[t+12]));
			TMP = vsha256h2q_u32(STATE1, STATE0, WK);
			STATE0 = vsha256hq_u32(STATE0, STATE1, WK);
			STATE1 = TMP;
		}
	}
        /* Rounds 4-7 */
	for (int t = 16;t<64; t+=16){
        MSG0 = vsha256su0q_u32(MSG0, MSG1);
        MSG0 = vsha256su1q_u32(MSG0, MSG2, MSG3);
		{	uint32x4_t TMP;
			uint32x4_t WK = vaddq_u32(MSG0, vld1q_u32(&K[t+0]));
			TMP = vsha256h2q_u32(STATE1, STATE0, WK);
			STATE0 = vsha256hq_u32(STATE0, STATE1, WK);
			STATE1 = TMP;
		}
        MSG1 = vsha256su0q_u32(MSG1, MSG2);
        MSG1 = vsha256su1q_u32(MSG1, MSG3, MSG0);
		{	uint32x4_t TMP;
			uint32x4_t WK = vaddq_u32(MSG1, vld1q_u32(&K[t+4]));
			TMP = vsha256h2q_u32(STATE1, STATE0, WK);
			STATE0 = vsha256hq_u32(STATE0, STATE1, WK);
			STATE1 = TMP;
		}
        MSG2 = vsha256su0q_u32(MSG2, MSG3);
        MSG2 = vsha256su1q_u32(MSG2, MSG0, MSG1);
		{	uint32x4_t TMP;
			uint32x4_t WK = vaddq_u32(MSG2, vld1q_u32(&K[t+8]));
			TMP = vsha256h2q_u32(STATE1, STATE0, WK);
			STATE0 = vsha256hq_u32(STATE0, STATE1, WK);
			STATE1 = TMP;
		}
        MSG3 = vsha256su0q_u32(MSG3, MSG0);
        MSG3 = vsha256su1q_u32(MSG3, MSG1, MSG2);
		{	uint32x4_t TMP;
			uint32x4_t WK = vaddq_u32(MSG3, vld1q_u32(&K[t+12]));
			TMP = vsha256h2q_u32(STATE1, STATE0, WK);
			STATE0 = vsha256hq_u32(STATE0, STATE1, WK);
			STATE1 = TMP;
		}
	}
	STATE0 += ABEF_SAVE;
	STATE1 += CDGH_SAVE;
    /* Save state */
    vst1q_u32(&state[0], STATE0);
    vst1q_u32(&state[4], STATE1);
__asm volatile("# LLVM-MCA-END SHA256_arm");
}
#if 1
typedef struct _HashCtx HashCtx;
struct _HashCtx {
    uint32_t H[8];
    uint32_t buffer[16];
    uint32_t length;    // длина данных
};
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
static void htole32_32(uint32_t * v)
{
#if (__BYTE_ORDER__==__ORDER_BIG_ENDIAN__)
    for (int i=0; i<8;i++) {
		v[i] = __builtin_bswap32(v[i]);
	}
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
static uint32_t htobe32(uint32_t  v)
{
#if (__BYTE_ORDER__==__ORDER_BIG_ENDIAN__)
    return (v);
#else
	return __builtin_bswap32(v);
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
static void sha256_32_final(HashCtx *ctx, uint8_t *tag)
{
    //if (__BYTE_ORDER__==__ORDER_LITTLE_ENDIAN__) 
	ntohl_vec(ctx->buffer, 32/4);
    int offset = ctx->length&63;
	ctx->buffer[offset>>2] = htobe32(0x80);
    ctx->buffer[15] = htole32(ctx->length<< 3);
    ctx->buffer[14] = htole32(ctx->length>>29);
    SHA256(ctx->H, ctx->buffer);
    //if (__BYTE_ORDER__==__ORDER_LITTLE_ENDIAN__) 
	ntohl_vec(ctx->H, 32/4);
    __builtin_memcpy(tag, ctx->H, 32);

}
static void sha256(uint8_t *hash, const uint8_t *data, unsigned int len)
{
	HashCtx ctx;
	sha256_init  (&ctx);
	sha256_update(&ctx, data, len);
	sha256_final (&ctx, hash, 32);
}
static void sha256_32(uint8_t *digest, uint8_t *message)
{
	const uint32_t H0[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
	HashCtx ctx;
	__builtin_memcpy(ctx.H, H0, 32);
	__builtin_memcpy((uint8_t*)ctx.buffer, message, 32);
	__builtin_memset((uint8_t*)ctx.buffer+32, 0, 32);
	ctx.length = 32;
	sha256_32_final (&ctx, digest);
}

void sha256d(uint8_t *hash, const uint8_t *data, unsigned int len)
{
	sha256(hash, data, len);
	sha256_32(hash, hash);

//	sha256(hash, hash,  32);
}
#define BE32(x) (((x&0xFF)<<24)|((x&0xFF000000)>>24)|((x&0xFF00)<<8)|((x&0xFF0000)>>8))
void sha256_midstate(uint8_t *digest, uint8_t *message)
{
	uint32_t H[8] = {
		(0x6a09e667), (0xbb67ae85), (0x3c6ef372), (0xa54ff53a), 
		(0x510e527f), (0x9b05688c), (0x1f83d9ab), (0x5be0cd19)};
	uint32_t buffer[BLK_SIZE/4];
	__builtin_memcpy((uint8_t*)buffer, message, 64);
	ntohl_vec(buffer, BLK_SIZE/4);
	SHA256(H, buffer);
	htole32_32(H);
	__builtin_memcpy(digest, H, 32);
//	for(int i=0; i < 8; i++, digest+=4)
//		*(uint32_t*)digest = htole32(H[i]);
}

void sha256_calc(uint8_t *digest, uint8_t *message)
{
	uint32_t H[8];
	uint32_t buffer[64/4];
//	HashCtx ctx;
	for(int i=0; i < 8; i++)
		H[i] = htole32(*(uint32_t*)(digest+i*4));
	__builtin_memcpy((uint8_t*)buffer, message+64, 16);
	__builtin_memset((uint8_t*)buffer+16, 0, 64-16);

	ntohl_vec(buffer, 16/4);
	buffer[ 4] = htobe32(0x80);
    buffer[15] = htole32(80<< 3);

    SHA256(H, buffer);

	__builtin_memcpy((uint8_t*)buffer, H, 32);
	__builtin_memset((uint8_t*)buffer+32, 0, 32);
	const uint32_t H0[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
	__builtin_memcpy(H, H0, 32);

	buffer[ 8] = htobe32(0x80);
    buffer[15] = htole32(32<< 3);

    SHA256(H, buffer);

	ntohl_vec(H, 32/4);
    __builtin_memcpy(digest, H, 32);
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
#endif