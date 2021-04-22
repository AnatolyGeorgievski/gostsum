/*!
    MD5 Message-Digest Algorithm            April 1992
не работает!
    \see http://tools.ietf.org/html/rfc1321

MD5 test suite:
MD5 ("") = d41d8cd98f00b204e9800998ecf8427e
MD5 ("a") = 0cc175b9c0f1b6a831c399e269772661
MD5 ("abc") = 900150983cd24fb0d6963f7d28e17f72
MD5 ("message digest") = f96b697d7cb7938d525a2f31aaf161d0
MD5 ("abcdefghijklmnopqrstuvwxyz") = c3fcd3d76192e4007dfb496cca67e13b
MD5 ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789") =
d174ab98d277d9f5a5611c2c9f419d9f
MD5 ("123456789012345678901234567890123456789012345678901234567890123456
78901234567890") = 57edf4a22be3c955ac49da2e2107b67a

 */

#include <stdint.h>
#include "hmac.h"

typedef uint32_t v4si __attribute__((__vector_size__(16)));

#include <sys/param.h> // GCC
#ifndef BYTE_ORDER
#define BYTE_ORDER __BYTE_ORDER__
#define BIG_ENDIAN __ORDER_BIG_ENDIAN__
#define LITTLE_ENDIAN __ORDER_LITTLE_ENDIAN__
#endif // __ORDER_BIG_ENDIAN__
#if (BYTE_ORDER==BIG_ENDIAN)
# define ENDIANNESS 0x3    // для little-endian, для big-endian = 0x0UL
#else
# define ENDIANNESS 0x0    // для little-endian, для big-endian = 0x0UL
#endif
/*! векторная операция */
static void ntohl_vec(uint32_t * v, int len)
{
    do {*v = __builtin_bswap32(*v), v++;} while(--len);
}
/*! инициализация Hash для MD5 */
static const v4si H0_128 = { 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476};
/*! MD5 hash computation
    M -- message block 512b
*/


    static const v4si k[] = {// эта таблица получается как floor(2^32*abs(sin(i+1)));
    {0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee},
    {0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501},
    {0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be},
    {0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821},
    {0xe9b6c7aa-0xd76aa478, 0xf61e2562-0xe8c7b756, 0xfcefa3f8-0x242070db, 0xf4d50d87-0xc1bdceee},// - (v4si){0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee}),
    {0xe7d3fbc8-0xf57c0faf, 0xd62f105d-0x4787c62a, 0xc040b340-0xa8304613, 0x676f02d9-0xfd469501},// - (v4si){0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501}
    {0x455a14ed-0x698098d8, 0x21e1cde6-0x8b44f7af, 0x02441453-0xffff5bb1, 0x265e5a51-0x895cd7be},// - (v4si){0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be}
    {0x8d2a4c8a-0x6b901122, 0xa9e3e905-0xfd987193, 0xc33707d6-0xa679438e, 0xd8a1e681-0x49b40821},// - (v4si){0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821}

    {0xeaa127fa-0xe9b6c7aa, 0xa4beea44-0xf61e2562, 0xc4ac5665-0xfcefa3f8, 0xd4ef3085-0xf4d50d87},// - (v4si){0xe9b6c7aa, 0xf61e2562, 0xfcefa3f8, 0xf4d50d87}
    {0x4bdecfa9-0xe7d3fbc8, 0xfffa3942-0xd62f105d, 0x04881d05-0xc040b340, 0xf6bb4b60-0x676f02d9},// - (v4si){0xe7d3fbc8, 0xd62f105d, 0xc040b340, 0x676f02d9}
    {0x8771f681-0x455a14ed, 0xd9d4d039-0x21e1cde6, 0xbebfbc70-0x02441453, 0x6d9d6122-0x265e5a51},// - (v4si){0x455a14ed, 0x21e1cde6, 0x02441453, 0x265e5a51}
    {0xe6db99e5-0x8d2a4c8a, 0x289b7ec6-0xa9e3e905, 0xfde5380c-0xc33707d6, 0x1fa27cf8-0xd8a1e681},// - (v4si){0x8d2a4c8a, 0xa9e3e905, 0xc33707d6, 0xd8a1e681}

    {0xf4292244-0xeaa127fa, 0x85845dd1-0xa4beea44, 0x2ad7d2bb-0xc4ac5665, 0x8f0ccc92-0xd4ef3085},// - (v4si){0xeaa127fa, 0xa4beea44, 0xc4ac5665, 0xd4ef3085}
    {0xf7537e82-0x4bdecfa9, 0xfc93a039-0xfffa3942, 0xa3014314-0x04881d05, 0x432aff97-0xf6bb4b60},// - (v4si){0x4bdecfa9, 0xfffa3942, 0x04881d05, 0xf6bb4b60}
    {0x6fa87e4f-0x8771f681, 0xeb86d391-0xd9d4d039, 0xffeff47d-0xbebfbc70, 0xbd3af235-0x6d9d6122},// - (v4si){0x8771f681, 0xd9d4d039, 0xbebfbc70, 0x6d9d6122};
    {0x655b59c3-0xe6db99e5, 0x4e0811a1-0x289b7ec6, 0xab9423a7-0xfde5380c, 0xfe2ce6e0-0x1fa27cf8},// - (v4si){0xe6db99e5, 0x289b7ec6, 0xfde5380c, 0x1fa27cf8}
    };

#if 0
static void MD5_0(v4si * H, uint32_t * w)
{
    static const uint32_t k[] = {// эта таблица получается как floor(2^32*abs(sin(i+1)));
    {0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee},
    {0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501},
    {0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be},
    {0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821},
    {0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa},
    {0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8},
    {0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed},
    {0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a},
    {0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c},
    {0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70},
    {0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05},
    {0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665},
    {0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039},
    {0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1},
    {0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1},
    {0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391},
    };

    static const uint8_t rot[] = {
    7, 12, 17, 22,
    5,  9, 14, 20,
    4, 11, 16, 23,
    6, 10, 15, 21,
    };

    uint32_t a = (*H)[0], b= (*H)[1], c=(*H)[2], d=(*H)[3];
    int t;
    for (t=0; t< 16; t++)
    {
        uint32_t f = ROTL((a + ((b&c)|(~b&d)) + k[t] + w[t]), rot[t&0x3]);
        a=d, d=c, c=b, b += f;// ROTL((a + ((b&c)|(~b&d)) + k[t] + w[t]), rot[t&0x3]);
    }
    for (   ; t< 32; t++)
    {
        uint32_t f = ROTL((a + ((d&b)|(~d&c)) + k[t] + w[(5*t+1)&0xF]), rot[4+(t&0x3)]);
        a=d, d=c, c=b, b += f;//ROTL((a + ((d&b)|(~d&c)) + k[t] + w[(5*t+1)&0xF]), rot[4+(t&0x3)]);
    }
    for (   ; t< 48; t++)
    {
        uint32_t f = ROTL((a + (b ^ c ^ d)    + k[t] + w[(3*t+5)&0xF]), rot[8+(t&0x3)]);
        a=d, d=c, c=b, b += f;//ROTL((a + (b ^ c ^ d)    + k[t] + w[(3*t+5)&0xF]), rot[8+(t&0x3)]);
    }
    for (   ; t< 64; t++)
    {
        uint32_t f = ROTL((a + (c ^ (b |~d))  + k[t] + w[(7*t)&0xF]), rot[12+(t&0x3)]);
        a=d, d=c, c=b, b += f;// = ROTL((a + (c ^ (b |~d))  + k[t] + w[(7*t)&0xF]), rot[12+(t&0x3)]);
    }
    *H+=(v4si){a, b, c, d};
}
#endif

#define F1(x, y, z) ((z) ^ ((x) & ((y) ^ (z))))
#define F2(x, y, z) ((y) ^ ((z) & ((x) ^ (y))))
#define F3(x, y, z) ((x) ^  (y) ^  (z))
#define F4(x, y, z) ((y) ^ ((x) | ~(z)))

#define ROUND(f, w, x, y, z, data, s) \
( w += f(x, y, z) + data,  w = w<<s | w>>(32-s),  w += x )
static void MD5(v4si * H, v4si * data)
{
    v4si h = *H;
    v4si x0,x1,x2,x3;
    x0 = data[0] + k[0];
    x1 = data[1] + k[1];
    x2 = data[2] + k[2];
    x3 = data[3] + k[3];

    uint32_t a = h[0], b= h[1], c=h[2], d=h[3];
  ROUND(F1, a, b, c, d, x0[0],  7);//data[ 0] + 0xd76aa478,  7);
  ROUND(F1, d, a, b, c, x0[1], 12);//data[ 1] + 0xe8c7b756, 12);
  ROUND(F1, c, d, a, b, x0[2], 17);//data[ 2] + 0x242070db, 17);
  ROUND(F1, b, c, d, a, x0[3], 22);//data[ 3] + 0xc1bdceee, 22);
  ROUND(F1, a, b, c, d, x1[0],  7);//data[ 4] + 0xf57c0faf,  7);
  ROUND(F1, d, a, b, c, x1[1], 12);//data[ 5] + 0x4787c62a, 12);
  ROUND(F1, c, d, a, b, x1[2], 17);//data[ 6] + 0xa8304613, 17);
  ROUND(F1, b, c, d, a, x1[3], 22);//data[ 7] + 0xfd469501, 22);
  ROUND(F1, a, b, c, d, x2[0],  7);//data[ 8] + 0x698098d8,  7);
  ROUND(F1, d, a, b, c, x2[1], 12);//data[ 9] + 0x8b44f7af, 12);
  ROUND(F1, c, d, a, b, x2[2], 17);//data[10] + 0xffff5bb1, 17);
  ROUND(F1, b, c, d, a, x2[3], 22);//data[11] + 0x895cd7be, 22);
  ROUND(F1, a, b, c, d, x3[0],  7);//data[12] + 0x6b901122,  7);
  ROUND(F1, d, a, b, c, x3[1], 12);//data[13] + 0xfd987193, 12);
  ROUND(F1, c, d, a, b, x3[2], 17);//data[14] + 0xa679438e, 17);
  ROUND(F1, b, c, d, a, x3[3], 22);//data[15] + 0x49b40821, 22);
    x0 += k[4];
    x1 += k[5];
    x2 += k[6];
    x3 += k[7];
  ROUND(F2, a, b, c, d, x0[1],  5);//data[ 1] + 0xf61e2562,  5);//
  ROUND(F2, d, a, b, c, x1[2],  9);//data[ 6] + 0xc040b340,  9);//
  ROUND(F2, c, d, a, b, x2[3], 14);//data[11] + 0x265e5a51, 14);//
  ROUND(F2, b, c, d, a, x0[0], 20);//data[ 0] + 0xe9b6c7aa, 20);//
  ROUND(F2, a, b, c, d, x1[1],  5);//data[ 5] + 0xd62f105d,  5);//
  ROUND(F2, d, a, b, c, x2[2],  9);//data[10] + 0x02441453,  9);//
  ROUND(F2, c, d, a, b, x3[3], 14);//data[15] + 0xd8a1e681, 14);//
  ROUND(F2, b, c, d, a, x1[0], 20);//data[ 4] + 0xe7d3fbc8, 20);//
  ROUND(F2, a, b, c, d, x2[1],  5);//data[ 9] + 0x21e1cde6,  5);
  ROUND(F2, d, a, b, c, x3[2],  9);//data[14] + 0xc33707d6,  9);
  ROUND(F2, c, d, a, b, x0[3], 14);//data[ 3] + 0xf4d50d87, 14);
  ROUND(F2, b, c, d, a, x2[0], 20);//data[ 8] + 0x455a14ed, 20);
  ROUND(F2, a, b, c, d, x3[1],  5);//data[13] + 0xa9e3e905,  5);
  ROUND(F2, d, a, b, c, x0[2],  9);//data[ 2] + 0xfcefa3f8,  9);
  ROUND(F2, c, d, a, b, x1[3], 14);//data[ 7] + 0x676f02d9, 14);
  ROUND(F2, b, c, d, a, x3[0], 20);//data[12] + 0x8d2a4c8a, 20);
    x0 += k[8];
    x1 += k[9];
    x2 += k[10];
    x3 += k[11];
  ROUND(F3, a, b, c, d, x1[1],  4);//data[ 5] + 0xfffa3942,  4);
  ROUND(F3, d, a, b, c, x2[0], 11);//data[ 8] + 0x8771f681, 11);
  ROUND(F3, c, d, a, b, x2[3], 16);//data[11] + 0x6d9d6122, 16);
  ROUND(F3, b, c, d, a, x3[2], 23);//data[14] + 0xfde5380c, 23);
  ROUND(F3, a, b, c, d, x0[1],  4);//data[ 1] + 0xa4beea44,  4);
  ROUND(F3, d, a, b, c, x1[0], 11);//data[ 4] + 0x4bdecfa9, 11);
  ROUND(F3, c, d, a, b, x1[3], 16);//data[ 7] + 0xf6bb4b60, 16);
  ROUND(F3, b, c, d, a, x2[2], 23);//data[10] + 0xbebfbc70, 23);
  ROUND(F3, a, b, c, d, x3[1],  4);//data[13] + 0x289b7ec6,  4);
  ROUND(F3, d, a, b, c, x0[0], 11);//data[ 0] + 0xeaa127fa, 11);
  ROUND(F3, c, d, a, b, x0[3], 16);//data[ 3] + 0xd4ef3085, 16);
  ROUND(F3, b, c, d, a, x1[2], 23);//data[ 6] + 0x04881d05, 23);
  ROUND(F3, a, b, c, d, x2[1],  4);//data[ 9] + 0xd9d4d039,  4);
  ROUND(F3, d, a, b, c, x3[0], 11);//data[12] + 0xe6db99e5, 11);
  ROUND(F3, c, d, a, b, x3[3], 16);//data[15] + 0x1fa27cf8, 16);
  ROUND(F3, b, c, d, a, x0[2], 23);//data[ 2] + 0xc4ac5665, 23);
    x0 += k[12];
    x1 += k[13];
    x2 += k[14];
    x3 += k[15];
  ROUND(F4, a, b, c, d, x0[0],  6);//data[ 0] + 0xf4292244,  6);
  ROUND(F4, d, a, b, c, x1[3], 10);//data[ 7] + 0x432aff97, 10);
  ROUND(F4, c, d, a, b, x3[2], 15);//data[14] + 0xab9423a7, 15);
  ROUND(F4, b, c, d, a, x1[1], 21);//data[ 5] + 0xfc93a039, 21);
  ROUND(F4, a, b, c, d, x3[0],  6);//data[12] + 0x655b59c3,  6);
  ROUND(F4, d, a, b, c, x0[3], 10);//data[ 3] + 0x8f0ccc92, 10);
  ROUND(F4, c, d, a, b, x2[2], 15);//data[10] + 0xffeff47d, 15);
  ROUND(F4, b, c, d, a, x0[1], 21);//data[ 1] + 0x85845dd1, 21);
  ROUND(F4, a, b, c, d, x2[0],  6);//data[ 8] + 0x6fa87e4f,  6);
  ROUND(F4, d, a, b, c, x3[3], 10);//data[15] + 0xfe2ce6e0, 10);
  ROUND(F4, c, d, a, b, x1[2], 15);//data[ 6] + 0xa3014314, 15);
  ROUND(F4, b, c, d, a, x3[1], 21);//data[13] + 0x4e0811a1, 21);
  ROUND(F4, a, b, c, d, x1[0],  6);//data[ 4] + 0xf7537e82,  6);
  ROUND(F4, d, a, b, c, x2[3], 10);//data[11] + 0xbd3af235, 10);
  ROUND(F4, c, d, a, b, x0[2], 15);//data[ 2] + 0x2ad7d2bb, 15);
  ROUND(F4, b, c, d, a, x2[1], 21);//data[ 9] + 0xeb86d391, 21);
    *H = h + (v4si){a, b, c, d};
}
typedef struct _MD5Ctx MD5Ctx;
struct _MD5Ctx {
    uint64_t length;
    v4si H;
    v4si buffer[4];
};

static void md5_init(MD5Ctx * ctx)
{
    //int i;
    //for (i=0;i<4;i++)
        ctx->H = H0_128;
    ctx->length = 0;
}
#define BLK_SIZE 64
static void md5_updt(MD5Ctx * ctx, const uint8_t * msg, unsigned int mlen)
{
    unsigned int offset = ctx->length & (BLK_SIZE-1);
    ctx->length += mlen;
    while (mlen>0){
        unsigned int len = (mlen>BLK_SIZE-offset)?BLK_SIZE-offset: mlen;
        __builtin_memcpy((uint8_t*)ctx->buffer + offset, msg, len);
        msg+=len; mlen-=len; offset+=len;
        if (offset==BLK_SIZE){
            if (BYTE_ORDER==BIG_ENDIAN) ntohl_vec((uint32_t*)ctx->buffer, BLK_SIZE/4);
            MD5(&ctx->H, ctx->buffer);
            offset = 0;
        }
    }
}
static void md5_fini(MD5Ctx * ctx, uint8_t * tag, unsigned int tlen)
{
    uint8_t *buffer = (void*)ctx->buffer;
    int offset = ctx->length&63;
    buffer[offset] = 0x80;
    if (offset >= 56)
    {// переход на следующий блок
        __builtin_memset(&buffer[offset+1], 0, 63 - offset);
        if (BYTE_ORDER==BIG_ENDIAN) ntohl_vec((uint32_t*)ctx->buffer, ((offset+4)>>2));
        MD5(&ctx->H, ctx->buffer);
        __builtin_memset(&buffer[0], 0, 56);
    } else {
        __builtin_memset(&buffer[offset+1], 0, 55 - offset);
        if (BYTE_ORDER==BIG_ENDIAN) ntohl_vec((uint32_t*)ctx->buffer, ((offset+4)>>2));
    }
    ctx->buffer[3][2] = (ctx->length<< 3);
    ctx->buffer[3][3] = (ctx->length>>29);
    MD5(&ctx->H, ctx->buffer);
    if (BYTE_ORDER==BIG_ENDIAN) ntohl_vec((uint32_t*)&ctx->H, 16);
    if(tlen) __builtin_memcpy(tag, &ctx->H, tlen);

}

MESSAGE_DIGEST(MD_MD5) {
    .id = MD_MD5,
    .name = "MD-5",
    .block_len = 64,
    .hash_len = 16,
    .ctx_size = sizeof(MD5Ctx),
    .init   = (void*)md5_init,
    .update = (void*)md5_updt,
    .final  = (void*)md5_fini,
};


