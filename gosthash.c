/*!
    \file gosthash.c
    Copyright (c) 2011-2014 Anatoly Georgievski
    Implementation of GOST R 34.11-94 hash function
    HMAC GOST R
    PBKDF2 HMAC GOSTR

 \see [RFC 5830] GOST 28147-89: Encryption, Decryption, and Message Authentication Code (MAC) Algorithms
 \see [RFC 5831] GOST R 34.11-94, March 2010
 \see [RFC 4357] Additional Cryptographic Algorithms for Use with GOST 28147-89,
        GOST R 34.10-94, GOST R 34.10-2001, and GOST R 34.11-94 Algorithms, 2006
OID: 1.2.643.2.2.35.1 id-GostR3410-2001-CryptoPro-A-ParamSet
OID: 1.2.643.2.2.30.1 id-GostR3411-94-CryptoProParamSet


    This file is distributed under GPL
/usr/gcc/4.3/bin/gcc -DDEBUG_GOST -o gost src/gosthash.c src/base64.c
$ gcc -Os -s -DDEBUG_GOST -o gosthash.exe gosthash.c base64.c
echo -n "8JaanTcVv6ndF8Xp/N011Lp46e68LjaUT9FhnEyQGs8=" | base64 -id | od -A n -X

 */
#include <malloc.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
//#include <glib.h>
#include "hmac.h"
#if defined(__sun__) || defined(__linux__)
#define _aligned_malloc(size, align) memalign(align, size)
#define _aligned_free(ptr) free(ptr)
#endif // __sun__ __linux__

typedef char v16qi __attribute__((__vector_size__(16)));
//typedef uint8_t v4qi __attribute__((__vector_size__(4)));
typedef uint32_t v4si __attribute__((__vector_size__(16)));
typedef uint16_t v8hi __attribute__((__vector_size__(16)));
/* Internal representation of GOST substitution blocks */
typedef struct _GostSubstBlock gost_subst_block;
struct _GostSubstBlock {
	v16qi k8;
	v16qi k7;
	v16qi k6;
	v16qi k5;
	v16qi k4;
	v16qi k3;
	v16qi k2;
	v16qi k1;
};

typedef struct _GostCtx gost_ctx;
struct _GostCtx {
//		uint32_t k[8];
		/* Constant s-boxes -- set up in gost_init(). */
		v16qi k87[16],k65[16],k43[16],k21[16];
//		uint32_t k87[256],k65[256],k43[256],k21[256];
};


uint8_t* base64_enc(char *dst, char *src, int length);
//typedef uint8_t  v4qi __attribute__((vector_size(4)));
typedef long long int v2di __attribute__((__vector_size__(16)));
typedef uint32_t v4si __attribute__((__vector_size__(16)));
typedef int32_t v4Si __attribute__((__vector_size__(16)));
//typedef long long int v2d_i __attribute__((__vector_size__(16)));
typedef uint64_t v4di __attribute__((__vector_size__(32)));
typedef uint8_t v4qi __attribute__((__vector_size__(4)));
typedef char v16qi __attribute__ ((__vector_size__(16)));
//typedef char v32qi __attribute__ ((__vector_size__(32)));

//typedef unsigned long long  v2di __attribute__((mode(V2DI)));

union _v256 {
    v2di q[2];
    uint64_t d[4];
    uint32_t s[8];
    uint16_t h[16];
};

typedef union _v256 v256;

/*
typedef struct _GostHashCtx gost_hash_ctx;
struct _GostHashCtx {
	int len;
	gost_ctx *cipher_ctx;
	int left;
	uint8_t H[32];
	uint8_t S[32];
	uint8_t remainder[32];
};*/
/* Substitution blocks from test examples for GOST R 34.11-94 */
const gost_subst_block GostR3411_94_TestParamSet = {
	{0X1,0XF,0XD,0X0,0X5,0X7,0XA,0X4,0X9,0X2,0X3,0XE,0X6,0XB,0X8,0XC},
	{0XD,0XB,0X4,0X1,0X3,0XF,0X5,0X9,0X0,0XA,0XE,0X7,0X6,0X8,0X2,0XC},
	{0X4,0XB,0XA,0X0,0X7,0X2,0X1,0XD,0X3,0X6,0X8,0X5,0X9,0XC,0XF,0XE},
	{0X6,0XC,0X7,0X1,0X5,0XF,0XD,0X8,0X4,0XA,0X9,0XE,0X0,0X3,0XB,0X2},
	{0X7,0XD,0XA,0X1,0X0,0X8,0X9,0XF,0XE,0X4,0X6,0XC,0XB,0X2,0X5,0X3},
	{0X5,0X8,0X1,0XD,0XA,0X3,0X4,0X2,0XE,0XF,0XC,0X7,0X6,0X0,0X9,0XB},
	{0XE,0XB,0X4,0XC,0X6,0XD,0XF,0XA,0X2,0X3,0X8,0X1,0X0,0X7,0X5,0X9},
	{0X4,0XA,0X9,0X2,0XD,0X8,0X0,0XE,0X6,0XB,0X1,0XC,0X7,0XF,0X5,0X3}
};
/* Substitution blocks for hash function 1.2.643.2.9.1.6.1  */
const gost_subst_block GostR3411_94_CryptoProParamSet= {
	{0x1,0x3,0xA,0x9,0x5,0xB,0x4,0xF,0x8,0x6,0x7,0xE,0xD,0x0,0x2,0xC},
	{0xD,0xE,0x4,0x1,0x7,0x0,0x5,0xA,0x3,0xC,0x8,0xF,0x6,0x2,0x9,0xB},
	{0x7,0x6,0x2,0x4,0xD,0x9,0xF,0x0,0xA,0x1,0x5,0xB,0x8,0xE,0xC,0x3},
	{0x7,0x6,0x4,0xB,0x9,0xC,0x2,0xA,0x1,0x8,0x0,0xE,0xF,0xD,0x3,0x5},
	{0x4,0xA,0x7,0xC,0x0,0xF,0x2,0x8,0xE,0x1,0x6,0x5,0xD,0xB,0x9,0x3},
	{0x7,0xF,0xC,0xE,0x9,0x4,0x1,0x0,0x3,0xB,0x5,0x2,0x6,0xA,0x8,0xD},
	{0x5,0xF,0x4,0x0,0x2,0xD,0xB,0x9,0x1,0x7,0x6,0x3,0xC,0xE,0xA,0x8},
	{0xA,0x4,0x5,0x6,0x8,0x1,0x3,0x7,0xD,0xC,0xE,0x0,0x9,0x2,0xB,0xF}
};

typedef struct _HashParams HashParams;
struct _HashParams {
    const char* name;
    const gost_subst_block* paramset;
    gost_ctx* ctx;
};

static HashParams hash_params[] = {
    {"GOST R 34.11-94 Test ParamSet", &GostR3411_94_TestParamSet, NULL},
    {"GOST R 34.11-94 Crypto-Pro ParamSet", &GostR3411_94_CryptoProParamSet, NULL},
//    {NULL, NULL, 0},
};

static inline void CLR(v256 *x)
{
	//register v2di z = (v2di){0,0};
    x->q[0] =(v2di){0}; //^= x->q[0];
    x->q[1] =(v2di){0}; //^= x->q[1];
}
static inline void MOV(v256 *x, const v256 *a)
{
    x->q[0] = a->q[0];
    x->q[1] = a->q[1];
}
static inline void XOR(v256 *x, const v256 *a)
{
    x->q[0] ^= a->q[0];
    x->q[1] ^= a->q[1];
}
#if defined(__arm__)
extern void UADD(v256 *a, v256 *b);

#elif defined(__x86_64__)//0
static inline
void UADD(v256 *a, v256 *b)
{
    uint64_t ac;
    __asm volatile (
    "   movq   (%1), %0   \n" // ac = a[i]
    "   addq   (%2), %0   \n" // ac = a + b[i]
    "   movq   %0, (%1)   \n" // r[i]=ac

    "   movq   8(%1), %0   \n" // ac = a[i]
    "   adcq   8(%2), %0   \n" // ac = a + b[i]
    "   movq   %0, 8(%1)   \n" // r[i]=ac

    "   movq   16(%1), %0   \n" // ac = a[i]
    "   adcq   16(%2), %0   \n" // ac = a + b[i]
    "   movq   %0, 16(%1)   \n" // r[i]=ac

    "   movq   24(%1), %0   \n" // ac = a[i]
    "   adcq   24(%2), %0   \n" // ac = a + b[i]
    "   movq   %0, 24(%1)   \n" // r[i]=ac

    :"=&r"(ac)
	:"r"(a), "r"(b)
    :"cc","memory"
    );
}
#elif defined(__i386__)
static
void UADD(v256 *a, v256 *b)
{
    uint32_t ac;
    __asm volatile (
    "   movl   (%1), %0   \n" // ac = a[i]
    "   addl   (%2), %0   \n" // ac = a + b[i]
    "   movl   %0, (%1)   \n" // r[i]=ac
    "   movl   4(%1), %0   \n" // ac = a[i]
    "   adcl   4(%2), %0   \n" // ac = a + b[i]
    "   movl   %0, 4(%1)   \n" // r[i]=ac

    "   movl   8(%1), %0   \n" // ac = a[i]
    "   adcl   8(%2), %0   \n" // ac = a + b[i]
    "   movl   %0, 8(%1)   \n" // r[i]=ac
    "   movl   12(%1), %0   \n" // ac = a[i]
    "   adcl   12(%2), %0   \n" // ac = a + b[i]
    "   movl   %0, 12(%1)   \n" // r[i]=ac

    "   movl   16(%1), %0   \n" // ac = a[i]
    "   adcl   16(%2), %0   \n" // ac = a + b[i]
    "   movl   %0, 16(%1)   \n" // r[i]=ac
    "   movl   20(%1), %0   \n" // ac = a[i]
    "   adcl   20(%2), %0   \n" // ac = a + b[i]
    "   movl   %0, 20(%1)   \n" // r[i]=ac

    "   movl   24(%1), %0   \n" // ac = a[i]
    "   adcl   24(%2), %0   \n" // ac = a + b[i]
    "   movl   %0, 24(%1)   \n" // r[i]=ac
    "   movl   28(%1), %0   \n" // ac = a[i]
    "   adcl   28(%2), %0   \n" // ac = a + b[i]
    "   movl   %0, 28(%1)   \n" // r[i]=ac

    :"=&r"(ac)
	:"r"(a), "r"(b)
    :"cc","memory"
    );
}

/*
#define ADD(a,b)    ({ register uint32_t ac;\
    asm ("addl   %1, %0   \n" :"=&r"(ac):"g"(b),"0"(a) :"cc" );\
    ac;})
#define ADC(a,b)    ({ register uint32_t ac;\
    asm ("adcl   %1, %0   \n" :"=&r"(ac):"g"(b),"0"(a) :"cc" );\
    ac;})

static void UADD(v256 *a, v256 *b)
{
    a->s[0] = ADD(a->s[0],b->s[0]);
    a->s[1] = ADC(a->s[1],b->s[1]);
    a->s[2] = ADC(a->s[2],b->s[2]);
    a->s[3] = ADC(a->s[3],b->s[3]);
    a->s[4] = ADC(a->s[4],b->s[4]);
    a->s[5] = ADC(a->s[5],b->s[5]);
    a->s[6] = ADC(a->s[6],b->s[6]);
    a->s[7] = ADC(a->s[7],b->s[7]);
}
*/
#elif 0
void UADD(v256 *r, v256 *a)
{
    uint64_t c;
    c =(uint64_t)r->s[0]+a->s[0];
    r->s[0]=c;
    c>>=32;
    c+=(uint64_t)r->s[1]+a->s[1];
    r->s[1]=c;
    c>>=32;
    c+=(uint64_t)r->s[2]+a->s[2];
    r->s[2]=c;
    c>>=32;
    c+=(uint64_t)r->s[3]+a->s[3];
    r->s[3]=c;
    c>>=32;
    c+=(uint64_t)r->s[4]+a->s[4];
    r->s[4]=c;
    c>>=32;
    c+=(uint64_t)r->s[5]+a->s[5];
    r->s[5]=c;
    c>>=32;
    c+=(uint64_t)r->s[6]+a->s[6];
    r->s[6]=c;
    c>>=32;
    c+=(uint64_t)r->s[7]+a->s[7];
    r->s[7]=c;
}
#else
//static inline
void UADD(v256 *r, const v256 *a)
{
    int i;
    uint64_t cy = 0;
    for (i=0; i<8; i++)
    {   register uint64_t t = (uint64_t)r->s[i] + a->s[i] + cy;
        r->s[i] = t;
        cy = t >> 32;
    }
//    return cy;
}
#endif
static
void A(v256 *x)
{
#ifdef __clang__
    v2di v0 = __builtin_shufflevector(x->q[0],x->q[1], 1,2);
    v2di v1 = __builtin_shufflevector(x->q[1],x->q[0], 1,2);
#else
    v2di v0 = __builtin_shuffle(x->q[0],x->q[1], (v2di){1,2});
    v2di v1 = __builtin_shuffle(x->q[1],x->q[0], (v2di){1,2});
#endif // __clang__
    v1[1]^=v0[0];
    x->q[0] = v0;
    x->q[1] = v1;

}
static
void AA(v256 *x)
{
    v2di z  = x->q[0];
    x->q[0] = x->q[1];
#ifdef __clang__
    x->q[1] = z ^  __builtin_shufflevector(z,x->q[1], 1,2);//(v2di){z[1],x->q[0][0]};
#else
    x->q[1] = z ^  __builtin_shuffle(z,x->q[1], (v2di){1,2});//(v2di){z[1],x->q[0][0]};
#endif // __clang__
}
#if 0 // это тест который делает тоже самое переставляет байты
void __attribute__((constructor)) test2()
{
    v256 x, y, z = {.q={
        [0] = {0x0807060504030201ULL, 0x1817161514131211ULL},
        [1] = {0x2827262524232221ULL, 0x3837363534333231ULL}}};
    y.q[0] = __builtin_ia32_punpcklbw128(z.q[0],z.q[1]);
    y.q[1] = __builtin_ia32_punpckhbw128(z.q[0],z.q[1]);
    x.q[0] = __builtin_ia32_punpcklbw128(y.q[0],y.q[1]);
    x.q[1] = __builtin_ia32_punpckhbw128(y.q[0],y.q[1]);
    int i;
    for (i=0; i<32; i++)
        printf (" %02X", x.b[i]);
    _Exit(0);
}
#endif
static void XP(const v256 *x, const v256 *c, v256 *a)
{
    register v256 z;
    z.q[0] = x->q[0] ^ c->q[0];
    z.q[1] = x->q[1] ^ c->q[1];
#ifdef __clang__
    a->q[0] = (v2di)__builtin_shufflevector((v16qi)z.q[0],(v16qi)z.q[1], 0, 8,16,24, 1, 9,17,25, 2,10,18,26, 3,11,19,27);
    a->q[1] = (v2di)__builtin_shufflevector((v16qi)z.q[0],(v16qi)z.q[1], 4,12,20,28, 5,13,21,29, 6,14,22,30, 7,15,23,31);
#else
    a->q[0] = (v2di)__builtin_shuffle((v16qi)z.q[0],(v16qi)z.q[1], (v16qi){ 0, 8,16,24, 1, 9,17,25, 2,10,18,26, 3,11,19,27});
    a->q[1] = (v2di)__builtin_shuffle((v16qi)z.q[0],(v16qi)z.q[1], (v16qi){ 4,12,20,28, 5,13,21,29, 6,14,22,30, 7,15,23,31});
#endif // __clang__
}
#if 0
void    print_K(uint64_t * K, char* idx)
{
    printf("%s = ", idx);
    int i;
    for (i=0; i<4; i++){
        if ((i&0x1)==0x0) printf("\t");
        printf(" %08X %08X", (uint32_t)(K[3-i]>>32), (uint32_t)K[3-i]);
        if ((i&0x1)==0x1) printf("\n");
    }
}
#endif

/* Part of GOST 28147 algorithm moved into separate function */

static inline
uint32_t f(gost_ctx *c, uint32_t  x)
{
    const uint8_t* k87 = (uint8_t*)c->k87;
    const uint8_t* k65 = (uint8_t*)c->k65;
    const uint8_t* k43 = (uint8_t*)c->k43;
    const uint8_t* k21 = (uint8_t*)c->k21;
    uint32_t h = x>>16;
    x = k87[h>>8 & 0xFF]<<24 | k65[h & 0xFF]<<16 | k43[x>>8 & 0xFF]<<8 | k21[x & 0xFF];
    return x<<11 | x>>(32-11);
}
/*
static inline uint32_t f_(gost_ctx *cc, uint32_t x)
{
    const gost_subst_block *c = &GostR3411_94_CryptoProParamSet;
	x = c->k8[x>>28 & 0xF]<<28 | c->k7[x>>24 & 0xF]<<24 |
        c->k6[x>>20 & 0xF]<<20 | c->k5[x>>16 & 0xF]<<16 |
        c->k4[x>>12 & 0xF]<<12 | c->k3[x>>8  & 0xF]<<8  |
        c->k2[x>>4  & 0xF]<<4  | c->k1[x     & 0xF]     ;
	return x<<11 | x>>(32-11);

}*/

/* Low-level encryption routine - encrypts one 64 bit block*/
static v4si Enc(gost_ctx *c, const v256 * k, v4si in)
{
	const v4si s0 = (v4si)k->q[0];
	const v4si s1 = (v4si)k->q[1];
//	register uint32_t n1,n2;
//	n1 = in[0], n2 = in[1];//>>32; /* As named in the GOST */
	/* Instead of swapping halves, swap names each round */
	in[1] ^= f(c,in[0]+s0[0]); in[0] ^= f(c,in[1]+s0[1]);
	in[1] ^= f(c,in[0]+s0[2]); in[0] ^= f(c,in[1]+s0[3]);
	in[1] ^= f(c,in[0]+s1[0]); in[0] ^= f(c,in[1]+s1[1]);
	in[1] ^= f(c,in[0]+s1[2]); in[0] ^= f(c,in[1]+s1[3]);

	in[1] ^= f(c,in[0]+s0[0]); in[0] ^= f(c,in[1]+s0[1]);
	in[1] ^= f(c,in[0]+s0[2]); in[0] ^= f(c,in[1]+s0[3]);
	in[1] ^= f(c,in[0]+s1[0]); in[0] ^= f(c,in[1]+s1[1]);
	in[1] ^= f(c,in[0]+s1[2]); in[0] ^= f(c,in[1]+s1[3]);

	in[1] ^= f(c,in[0]+s0[0]); in[0] ^= f(c,in[1]+s0[1]);
	in[1] ^= f(c,in[0]+s0[2]); in[0] ^= f(c,in[1]+s0[3]);
	in[1] ^= f(c,in[0]+s1[0]); in[0] ^= f(c,in[1]+s1[1]);
	in[1] ^= f(c,in[0]+s1[2]); in[0] ^= f(c,in[1]+s1[3]);

	in[1] ^= f(c,in[0]+s1[3]); in[0] ^= f(c,in[1]+s1[2]);
	in[1] ^= f(c,in[0]+s1[1]); in[0] ^= f(c,in[1]+s1[0]);
	in[1] ^= f(c,in[0]+s0[3]); in[0] ^= f(c,in[1]+s0[2]);
	in[1] ^= f(c,in[0]+s0[1]); in[0] ^= f(c,in[1]+s0[0]);
    return (v4si){in[2],in[3],in[1],in[0]};
//    return ((uint64_t)n1)<<32 | n2;
}

static inline uint16_t do_phi1(v256 *x)
{// не использует sse
    return x->h[0] ^ x->h[1] ^ x->h[2] ^ x->h[3] ^ x->h[12] ^ x->h[15];
//    return x->d[0] ^ x->d[0]>>16 ^ x->d[0]>>32 ^ x->d[0]>>48 ^ x->d[3] ^ x->d[3]>>48;
}
/*
void do_phi4(uint64_t *x)
{
    uint16_t* e = (void*)x;
    e[0] ^= e[1] ^ e[2] ^ e[3] ^ e[12] ^ e[15];
    e[1] ^= e[2] ^ e[3] ^ e[4] ^ e[13] ^ e[0];
    e[2] ^= e[3] ^ e[4] ^ e[5] ^ e[14] ^ e[1];
    e[3] ^= e[4] ^ e[5] ^ e[6] ^ e[15] ^ e[2];
} */
static
void R12(v256 * x)
{
    v8hi h0 = (v8hi)x->q[0];
    v8hi h1 = (v8hi)x->q[1];
    v8hi hz = (v8hi){0};
    v8hi v0,v1;
#ifdef __clang__
    v0 = __builtin_shufflevector(h0,hz,8,8,8,8,0,0,0,0);
    v0^= __builtin_shufflevector(h0,hz,8,8,8,8,2,8,2,2);
    v0^= __builtin_shufflevector(h0,hz,8,8,8,8,3,4,3,4);
    v0^= __builtin_shufflevector(h0,hz,8,8,8,8,1,8,5,6);
    v0^= __builtin_shufflevector(hz,h1,12,0,0,0,12,12,12,12);
    v0^= __builtin_shufflevector(hz,h1,0,13,0,0, 0,13,13,13);
    v0^= __builtin_shufflevector(hz,h1,0,0,14,0, 0, 0,14,14);
    v0^= __builtin_shufflevector(hz,h1,0,0,0,15,15,15,15, 0);
    x->q[0] = (v2di)v0;

    v1 = __builtin_shufflevector(h0,h0,1,0,1,0,0,1,2,0);
    v1^= __builtin_shufflevector(h0,h0,3,1,2,1,3,4,5,1);
    v1^= __builtin_shufflevector(h0,hz,5,3,4,5,6,7,8,2);
    v1^= __builtin_shufflevector(h0,h1, 7,4,5,6,7, 8,8,6);
    v1^= __builtin_shufflevector(h0,h1,13,6,7,8,9,10,9,9);
    v1^= __builtin_shufflevector(hz,h1,0, 8,9,10,11,12,11,10);
    v1^= __builtin_shufflevector(hz,h1,0,12,0,12,12,13,13, 0);
    v1^= __builtin_shufflevector(hz,h1,14,14,13,14,13,14,14,14);
    v1^= __builtin_shufflevector(hz,h1,15, 0,15,15, 0, 0,15, 0);
    x->q[1] = (v2di)v1;
#else
    v0 = __builtin_shuffle(h0,hz,(v8hi){8,8,8,8,0,0,0,0});
//    v0 = __builtin_shuffle(h0,hz,(v8hi){-1,-1,-1,-1,0,0,0,0});
    v0^= __builtin_shuffle(h0,hz,(v8hi){8,8,8,8,2,8,2,2});
//    v0^= __builtin_shuffle(h0,hz,(v8hi){-1,-1,-1,-1,2,-1,2,2});
    v0^= __builtin_shuffle(h0,hz,(v8hi){8,8,8,8,3,4,3,4});
    v0^= __builtin_shuffle(h0,hz,(v8hi){8,8,8,8,1,8,5,6});
    v0^= __builtin_shuffle(hz,h1,(v8hi){12,0,0,0,12,12,12,12});
    v0^= __builtin_shuffle(hz,h1,(v8hi){0,13,0,0, 0,13,13,13});
    v0^= __builtin_shuffle(hz,h1,(v8hi){0,0,14,0, 0, 0,14,14});
    v0^= __builtin_shuffle(hz,h1,(v8hi){0,0,0,15,15,15,15, 0});
    x->q[0] = (v2di)v0;

    v1 = __builtin_shuffle(h0,(v8hi){1,0,1,0,0,1,2,0});
    v1^= __builtin_shuffle(h0,(v8hi){3,1,2,1,3,4,5,1});
    v1^= __builtin_shuffle(h0,hz,(v8hi){5,3,4,5,6,7,8,2});
    v1^= __builtin_shuffle(h0,h1,(v8hi){7,4,5,6,7,8,8,6});
    v1^= __builtin_shuffle(h0,h1,(v8hi){13,6,7,8,9,10,9,9});
    v1^= __builtin_shuffle(hz,h1,(v8hi){ 0,8,9,10,11,12,11,10});
    v1^= __builtin_shuffle(hz,h1,(v8hi){0,12,0,12,12,13,13, 0});
    v1^= __builtin_shuffle(hz,h1,(v8hi){14,14,13,14,13,14,14,14});
    v1^= __builtin_shuffle(hz,h1,(v8hi){15, 0,15,15, 0, 0,15, 0});
    x->q[1] = (v2di)v1;
#endif
//	register v256 y = *x;
/*
    x->d[0] = y.d[3];

    x->h[ 4] = y.h[ 0] ^ y.h[ 1] ^ y.h[ 2] ^ y.h[ 3] ^ y.h[12] ^           y.h[15];
    x->h[ 5] = y.h[ 0] ^ y.h[ 4] ^                     y.h[12] ^ y.h[13] ^ y.h[15];
    x->h[ 6] = y.h[ 0] ^ y.h[ 2] ^ y.h[ 3] ^ y.h[ 5] ^ y.h[12] ^ y.h[13] ^ y.h[14] ^ y.h[15];
    x->h[ 7] = y.h[ 0] ^ y.h[ 2] ^ y.h[ 4] ^ y.h[ 6] ^ y.h[12] ^ y.h[13] ^ y.h[14];
    x->h[ 8] = y.h[ 1] ^ y.h[ 3] ^ y.h[ 5] ^ y.h[ 7] ^ y.h[13] ^                     y.h[14] ^ y.h[15];
    x->h[ 9] = y.h[ 0] ^ y.h[ 1] ^ y.h[ 3] ^ y.h[ 4] ^ y.h[ 6] ^ y.h[ 8] ^ y.h[12] ^ y.h[14];
    x->h[10] = y.h[ 1] ^ y.h[ 2] ^ y.h[ 4] ^ y.h[ 5] ^ y.h[ 7] ^ y.h[ 9] ^           y.h[13] ^ y.h[15];
    x->h[11] = y.h[ 0] ^ y.h[ 1] ^ y.h[ 5] ^ y.h[ 6] ^ y.h[ 8] ^ y.h[10] ^ y.h[12] ^ y.h[14] ^ y.h[15];
    x->h[12] = y.h[ 0] ^ y.h[ 3] ^ y.h[ 6] ^ y.h[ 7] ^ y.h[ 9] ^ y.h[11] ^ y.h[12] ^ y.h[13];
    x->h[13] = y.h[ 1] ^ y.h[ 4] ^ y.h[ 7] ^ y.h[ 8] ^ y.h[10] ^ y.h[12] ^ y.h[13] ^ y.h[14];
    x->h[14] = y.h[ 2] ^ y.h[ 5] ^           y.h[ 8] ^ y.h[ 9] ^ y.h[11] ^ y.h[13] ^ y.h[14] ^ y.h[15];
    x->h[15] = y.h[ 0] ^ y.h[ 1] ^ y.h[ 2] ^ y.h[ 6] ^ y.h[ 9] ^ y.h[10] ^           y.h[14];
*/
}
#if 0
static void do_phi12(v256 *x)
{

    x->h[0] ^= x->h[1] ^ x->h[2] ^ x->h[3] ^ x->h[12]^ x->h[15];
    x->h[1] ^= x->h[2] ^ x->h[3] ^ x->h[4] ^ x->h[13]^ x->h[0];
    x->h[2] ^= x->h[3] ^ x->h[4] ^ x->h[5] ^ x->h[14]^ x->h[1];
    x->h[3] ^= x->h[4] ^ x->h[5] ^ x->h[6] ^ x->h[15]^ x->h[2];

    x->h[4] ^= x->h[5] ^ x->h[6] ^ x->h[7] ^ x->h[0] ^ x->h[3];
    x->h[5] ^= x->h[6] ^ x->h[7] ^ x->h[8] ^ x->h[1] ^ x->h[4];
    x->h[6] ^= x->h[7] ^ x->h[8] ^ x->h[9] ^ x->h[2] ^ x->h[5];
    x->h[7] ^= x->h[8] ^ x->h[9] ^ x->h[10]^ x->h[3] ^ x->h[6];

    x->h[8] ^= x->h[9] ^ x->h[10]^ x->h[11]^ x->h[4] ^ x->h[7];
    x->h[9] ^= x->h[10]^ x->h[11]^ x->h[12]^ x->h[5] ^ x->h[8];
    x->h[10]^= x->h[11]^ x->h[12]^ x->h[13]^ x->h[6] ^ x->h[9];
    x->h[11]^= x->h[12]^ x->h[13]^ x->h[14]^ x->h[7] ^ x->h[10];
}
#endif
#if 0
static void do_phi16(v256 *x)
{
//    uint16_t* e = (void*)x;

    x->h[0] ^= x->h[1] ^ x->h[2] ^ x->h[3] ^ x->h[12]^ x->h[15];
    x->h[1] ^= x->h[2] ^ x->h[3] ^ x->h[4] ^ x->h[13]^ x->h[0];
    x->h[2] ^= x->h[3] ^ x->h[4] ^ x->h[5] ^ x->h[14]^ x->h[1];
    x->h[3] ^= x->h[4] ^ x->h[5] ^ x->h[6] ^ x->h[15]^ x->h[2];

    x->h[4] ^= x->h[5] ^ x->h[6] ^ x->h[7] ^ x->h[0] ^ x->h[3];
    x->h[5] ^= x->h[6] ^ x->h[7] ^ x->h[8] ^ x->h[1] ^ x->h[4];
    x->h[6] ^= x->h[7] ^ x->h[8] ^ x->h[9] ^ x->h[2] ^ x->h[5];
    x->h[7] ^= x->h[8] ^ x->h[9] ^ x->h[10]^ x->h[3] ^ x->h[6];

    x->h[8] ^= x->h[9] ^ x->h[10]^ x->h[11]^ x->h[4] ^ x->h[7];
    x->h[9] ^= x->h[10]^ x->h[11]^ x->h[12]^ x->h[5] ^ x->h[8];
    x->h[10]^= x->h[11]^ x->h[12]^ x->h[13]^ x->h[6] ^ x->h[9];
    x->h[11]^= x->h[12]^ x->h[13]^ x->h[14]^ x->h[7] ^ x->h[10];

    x->h[12]^= x->h[13]^ x->h[14]^ x->h[15]^ x->h[8] ^ x->h[11];
    x->h[13]^= x->h[14]^ x->h[15]^ x->h[0] ^ x->h[9] ^ x->h[12];
    x->h[14]^= x->h[15]^ x->h[0] ^ x->h[1] ^ x->h[10]^ x->h[13];
    x->h[15]^= x->h[0] ^ x->h[1] ^ x->h[2] ^ x->h[11]^ x->h[14];
}
#endif
static
void R61(v256 *x, v256 *y)
{
    v8hi h0 = (v8hi)x->q[0];
    v8hi h1 = (v8hi)x->q[1];
    v8hi hz = (v8hi){0};
    v8hi v0,v1;
#ifdef __clang__
    v0 = __builtin_shufflevector(h0,h0,1,0,1,0,0,0,1,0);
    v0^= __builtin_shufflevector(h0,h0,3,1,2,1,3,2,3,1);
    v0^= __builtin_shufflevector(h0,h0,7,3,4,5,6,3,4,3);
    v0^= __builtin_shufflevector(h0,hz,8,4,5,6,7,4,5,4);
    v0^= __builtin_shufflevector(h0,h1,10,8,9,10,11,7,8,5);
    v0^= __builtin_shufflevector(h0,h1,11,11,12,12,12,8,9,6);
    v0^= __builtin_shufflevector(hz,h1,13,14,15,13,13,13,14,9);
    v0^= __builtin_shufflevector(hz,h1,14,0,0,15,14,14,15,10);
    v0^= __builtin_shufflevector(hz,h1,15,0,0,0,15,0,0,12);
    y->q[0] = (v2di)v0;
    v1 = __builtin_shufflevector(h0,h0, 1, 2, 3,0,0,1,0,1);
    v1^= __builtin_shufflevector(h0,h0, 2, 3, 4,1,4,5,1,2);
    v1^= __builtin_shufflevector(h0,h0, 4, 5, 6,2,5,6,3,4);
    v1^= __builtin_shufflevector(h0,h0, 5, 6, 7,3,6,7,6,7);
    v1^= __builtin_shufflevector(h0,h1, 6, 7, 8,4,8,9,7,8);
    v1^= __builtin_shufflevector(h0,h1, 7, 8, 9,5,9,10,8,9);
    v1^= __builtin_shufflevector(h0,h1,10,11,12,7,10,11,10,11);
    v1^= __builtin_shufflevector(hz,h1,11,12,13,8,11,12,11,12);
    v1^= __builtin_shufflevector(hz,h1,13,14,15,9,12,13,13,14);
    v1^= __builtin_shufflevector(hz,h1, 0, 0,0,10,13,14,14,15);
    v1^= __builtin_shufflevector(hz,h1, 0, 0,0,12,14,15, 0, 0);
    v1^= __builtin_shufflevector(hz,h1, 0, 0,0,13, 0, 0, 0, 0);
    v1^= __builtin_shufflevector(hz,h1, 0, 0,0,14, 0, 0, 0, 0);
    v1^= __builtin_shufflevector(hz,h1, 0, 0,0,15, 0, 0, 0, 0);
    y->q[1] = (v2di)v1;
#else
    v0 = __builtin_shuffle(h0,   (v8hi){1,0,1,0,0,0,1,0});
    v0^= __builtin_shuffle(h0,   (v8hi){3,1,2,1,3,2,3,1});
    v0^= __builtin_shuffle(h0,   (v8hi){7,3,4,5,6,3,4,3});
    v0^= __builtin_shuffle(h0,hz,(v8hi){8,4,5,6,7,4,5,4});
    v0^= __builtin_shuffle(h0,h1,(v8hi){10,8,9,10,11,7,8,5});
    v0^= __builtin_shuffle(h0,h1,(v8hi){11,11,12,12,12,8,9,6});
    v0^= __builtin_shuffle(hz,h1,(v8hi){13,14,15,13,13,13,14,9});
    v0^= __builtin_shuffle(hz,h1,(v8hi){14,0,0,15,14,14,15,10});
    v0^= __builtin_shuffle(hz,h1,(v8hi){15,0,0,0,15,0,0,12});
    y->q[0] = (v2di)v0;
    v1 = __builtin_shuffle(h0,   (v8hi){ 1, 2, 3,0,0,1,0,1});
    v1^= __builtin_shuffle(h0,   (v8hi){ 2, 3, 4,1,4,5,1,2});
    v1^= __builtin_shuffle(h0,   (v8hi){ 4, 5, 6,2,5,6,3,4});
    v1^= __builtin_shuffle(h0,   (v8hi){ 5, 6, 7,3,6,7,6,7});
    v1^= __builtin_shuffle(h0,h1,(v8hi){ 6, 7, 8,4,8,9,7,8});
    v1^= __builtin_shuffle(h0,h1,(v8hi){ 7, 8, 9,5,9,10,8,9});
    v1^= __builtin_shuffle(h0,h1,(v8hi){10,11,12,7,10,11,10,11});
    v1^= __builtin_shuffle(hz,h1,(v8hi){11,12,13,8,11,12,11,12});
    v1^= __builtin_shuffle(hz,h1,(v8hi){13,14,15,9,12,13,13,14});
    v1^= __builtin_shuffle(hz,h1,(v8hi){ 0, 0,0,10,13,14,14,15});
    v1^= __builtin_shuffle(hz,h1,(v8hi){ 0, 0,0,12,14,15, 0, 0});
    v1^= __builtin_shuffle(hz,h1,(v8hi){ 0, 0,0,13, 0, 0, 0, 0});
    v1^= __builtin_shuffle(hz,h1,(v8hi){ 0, 0,0,14, 0, 0, 0, 0});
    v1^= __builtin_shuffle(hz,h1,(v8hi){ 0, 0,0,15, 0, 0, 0, 0});
    y->q[1] = (v2di)v1;
#endif
/*
    y->h[ 0] = x->h[ 1] ^ x->h[ 3] ^ x->h[ 7] ^            x->h[10] ^ x->h[11] ^ x->h[13] ^ x->h[14] ^ x->h[15];
    y->h[ 1] = x->h[ 0] ^ x->h[ 1] ^ x->h[ 3] ^ x->h[ 4] ^ x->h[ 8] ^ x->h[11] ^ x->h[14];
    y->h[ 2] = x->h[ 1] ^ x->h[ 2] ^ x->h[ 4] ^ x->h[ 5] ^ x->h[ 9] ^ x->h[12] ^ x->h[15];
    y->h[ 3] = x->h[ 0] ^ x->h[ 1] ^ x->h[ 5] ^ x->h[ 6] ^ x->h[10] ^ x->h[12] ^ x->h[13] ^ x->h[15];
    y->h[ 4] = x->h[ 0] ^ x->h[ 3] ^ x->h[ 6] ^ x->h[ 7] ^ x->h[11] ^ x->h[12] ^ x->h[13] ^ x->h[14] ^ x->h[15];
    y->h[ 5] = x->h[ 0] ^ x->h[ 2] ^ x->h[ 3] ^ x->h[ 4] ^ x->h[ 7] ^ x->h[ 8] ^ x->h[13] ^ x->h[14];
    y->h[ 6] = x->h[ 1] ^ x->h[ 3] ^ x->h[ 4] ^ x->h[ 5] ^ x->h[ 8] ^ x->h[ 9] ^ x->h[14] ^ x->h[15];
    y->h[ 7] = x->h[ 0] ^ x->h[ 1] ^ x->h[ 3] ^ x->h[ 4] ^ x->h[ 5] ^ x->h[ 6] ^ x->h[ 9] ^ x->h[10] ^ x->h[12];

    y->h[ 8] = x->h[ 1] ^ x->h[ 2] ^ x->h[ 4] ^ x->h[ 5] ^ x->h[ 6] ^ x->h[ 7] ^ x->h[10] ^ x->h[11] ^ x->h[13];
    y->h[ 9] = x->h[ 2] ^ x->h[ 3] ^ x->h[ 5] ^ x->h[ 6] ^ x->h[ 7] ^ x->h[ 8] ^ x->h[11] ^ x->h[12] ^ x->h[14];
    y->h[10] = x->h[ 3] ^ x->h[ 4] ^ x->h[ 6] ^ x->h[ 7] ^ x->h[ 8] ^ x->h[ 9] ^ x->h[12] ^ x->h[13] ^ x->h[15];
    y->h[11] = x->h[ 0] ^ x->h[ 1] ^ x->h[ 2] ^ x->h[ 3] ^ x->h[ 4] ^ x->h[ 5] ^ x->h[ 7] ^ x->h[ 8] ^ x->h[ 9] ^ x->h[10] ^ x->h[12] ^ x->h[13] ^ x->h[14] ^ x->h[15];
    y->h[12] = x->h[ 0] ^ x->h[ 4] ^ x->h[ 5] ^ x->h[ 6] ^ x->h[ 8] ^ x->h[ 9] ^ x->h[10] ^ x->h[11] ^ x->h[12] ^ x->h[13] ^ x->h[14];
    y->h[13] = x->h[ 1] ^ x->h[ 5] ^ x->h[ 6] ^ x->h[ 7] ^ x->h[ 9] ^ x->h[10] ^ x->h[11] ^ x->h[12] ^ x->h[13] ^ x->h[14] ^ x->h[15];
    y->h[14] = x->h[ 0] ^ x->h[ 1] ^ x->h[ 3] ^ x->h[ 6] ^ x->h[ 7] ^ x->h[ 8] ^ x->h[10] ^ x->h[11] ^ x->h[13] ^ x->h[14];
    y->h[15] = x->h[ 1] ^ x->h[ 2] ^ x->h[ 4] ^ x->h[ 7] ^ x->h[ 8] ^ x->h[ 9] ^ x->h[11] ^ x->h[12] ^ x->h[14] ^ x->h[15];
*/
}
static
void R(v256 *x)
{
//    const uint16_t z =do_phi1(x);
//    register v8hi q = (v8hi){z,0};
    v8hi h0 = (v8hi)x->q[0];
    v8hi h1 = (v8hi)x->q[1];
    v8hi hz = (v8hi){0};
    v8hi v0,v1;

//    v8hi z = (v8hi){0};
#ifdef __clang__
    v0 = __builtin_shufflevector(h0,h1,1,2,3,4,5,6,7,8);
    v1 = __builtin_shufflevector(h1,h0,1,2,3,4,5,6,7,8);
    v1^= __builtin_shufflevector(hz,v0,1,2,3,4,5,6,7,8);
    v1^= __builtin_shufflevector(h0,h0,0,0,0,0,0,0,0,2);
    v1^= __builtin_shufflevector(h0,h0,0,0,0,0,0,0,0,3);
    v1^= __builtin_shufflevector(h1,h1,0,0,0,0,0,0,0,4);
    v1^= __builtin_shufflevector(h1,h1,0,0,0,0,0,0,0,7);
#else
    v0 = __builtin_shuffle(h0, h1,(v8hi){1,2,3,4,5,6,7,8});
    v1 = __builtin_shuffle(h1, h0,(v8hi){1,2,3,4,5,6,7,8});
    v1^= __builtin_shuffle(hz, v0,(v8hi){1,2,3,4,5,6,7,8});
    v1^= __builtin_shuffle(h0,    (v8hi){0,0,0,0,0,0,0,2});
    v1^= __builtin_shuffle(h0,    (v8hi){0,0,0,0,0,0,0,3});
    v1^= __builtin_shuffle(h1,    (v8hi){0,0,0,0,0,0,0,4});
    v1^= __builtin_shuffle(h1,    (v8hi){0,0,0,0,0,0,0,7});
#endif
    x->q[0]=(v2di)v0;
    x->q[1]=(v2di)v1;
//    x->q[1] = x->h[0] ^ x->h[1] ^ x->h[2] ^ x->h[3] ^ x->h[12] ^ x->h[15];
}
#if 0
static inline void R4(v256 *x)
{
    do_phi4(x);
    v2di y  = (v2di){x->d[1], x->d[2]};
    x->q[1] = (v2di){x->d[3], x->d[0]};
    x->q[0] = y;
/*    const uint64_t z = x[0];
    x[0] = x[1];
    x[1] = x[2];
    x[2] = x[3];
    x[3] = z   ;*/
}
#endif
#if 0
static inline void R12_(v256 *x)
{
    do_phi12(x);
    v2di y  = (v2di){x->d[3], x->d[0]};
    x->q[1] = (v2di){x->d[1], x->d[2]};
    x->q[0] = y;

/*    const uint64_t z = x[3];
    x[3] = x[2];
    x[2] = x[1];
    x[1] = x[0];
    x[0] = z;*/
}
#endif
#if 0
static void R60(v256 *x)
{
    do_phi16(x);
    do_phi16(x);
    do_phi16(x);
    do_phi12(x);

//	do_phi60(x);
#if 0// defined (__AVX__)
    x->v = (v4di){x->d[3], x->d[0], x->d[1], x->d[2]};
#elif defined (__SSE2__)
    v2di y  = (v2di){x->d[3], x->d[0]};
    x->q[1] = (v2di){x->d[1], x->d[2]};
    x->q[0] = y;
#else
	const uint64_t z = x->d[3];
    x->d[3] = x->d[2];
    x->d[2] = x->d[1];
    x->d[1] = x->d[0];
    x->d[0] = z;
#endif
}
#endif

static const v256 C1 = {.q = {
    [0] = {0x000000FFFF00FFFFULL, 0xFF00FF00FF00FF00ULL},
    [1] = {0x00FF00FF00FF00FFULL, 0xFF0000FF00FFFF00ULL}}};
static void gost_step(gost_ctx *c, v256* H, v256* M)
{
    v256 V,U,K,S;
    v4si s0,s1;
    MOV(&U,H); MOV(&V, M);
                   XP(&U,&V,&K);
    s0 = (v4si) H->q[0];
    s0 = Enc(c,&K,s0);
    A(&U); AA(&V); XP(&U,&V,&K);
#ifdef __clang__
    s0 = __builtin_shufflevector((v4si) H->q[0], s0, 2,3,6,7);
#else
    s0 = __builtin_shuffle((v4si) H->q[0], s0, (v4si){2,3,6,7});
#endif
    S.q[0] = (v2di) Enc(c,&K,s0);

    XOR(&U, &C1);
    A(&U); AA(&V); XP(&U,&V,&K);
    s1 = (v4si) H->q[1];
    s1 = Enc(c,&K,s1);
    A(&U); AA(&V); XP(&U,&V,&K);
#ifdef __clang__
    s1 = __builtin_shufflevector((v4si) H->q[1], s1, 2,3,6,7);
#else
    s1 = __builtin_shuffle((v4si) H->q[1], s1, (v4si){2,3,6,7});
#endif
    S.q[1] = (v2di)Enc(c,&K,s1);

    R12(&S);
	XOR(&S, M);
	R(&S);
	XOR(&S, H);
    R61(&S, H);
//    R(&S);
//	MOV(H,&S);
}
#if 0
static int* stack=NULL;
static void __attribute__((constructor)) init_stack(){
    int addr;
    stack = &addr;
}
static void check_stack(){
    int addr;
    printf("Stack size: %d\n",&addr-stack);
}
#endif

/* Initalize context. Provides default value for subst_block */
static void gost_init(gost_ctx *c, const gost_subst_block *b)
{
//    check_stack();
    if(!b) {
        b=&GostR3411_94_TestParamSet;
    }
    int i;
    v16qi k7 = b->k7;
    v16qi k5 = b->k5;
    v16qi k3 = b->k3;
    v16qi k1 = b->k1;
    for (i = 0; i < 16; i++) {
#if 1//def __clang__
		uint8_t q;
		q = b->k8[i]<<4;
		c->k87[i] = (v16qi){q,q,q,q, q,q,q,q, q,q,q,q, q,q,q,q} ^ k7;
		q = b->k6[i]<<4;
        c->k65[i] = (v16qi){q,q,q,q, q,q,q,q, q,q,q,q, q,q,q,q} ^ k5;
		q = b->k4[i]<<4;
        c->k43[i] = (v16qi){q,q,q,q, q,q,q,q, q,q,q,q, q,q,q,q} ^ k3;
		q = b->k2[i]<<4;
        c->k21[i] = (v16qi){q,q,q,q, q,q,q,q, q,q,q,q, q,q,q,q} ^ k1;
#else
		v16qi k= {0};
		k[0] = b->k8[i]<<4;
        k = __builtin_shuffle(k, (v16qi){0});
        //__builtin_memset(&k, b->k8[i]<<4 ,16);
        c->k87[i] = k ^ k7;
        k[0] = b->k6[i]<<4;
        k = __builtin_shuffle(k, (v16qi){0});
        //__builtin_memset(&k, b->k6[i]<<4 ,16);
        c->k65[i] = k ^ k5;
        k[0] = b->k4[i]<<4;
        k = __builtin_shuffle(k, (v16qi){0});
        //__builtin_memset(&k, b->k4[i]<<4 ,16);
        c->k43[i] = k ^ k3;
        k[0] = b->k2[i]<<4;
        k = __builtin_shuffle(k, (v16qi){0});
        //__builtin_memset(&k, b->k2[i]<<4 ,16);
        c->k21[i] = k ^ k1;
#endif
    }
/*
    uint32_t x;
    for (i = 0; i < 256; i++) {
        x = (b->k8[i>>4] <<4  | b->k7 [i &15])<<24;
	    c->k87[i] = x<<11 | x>>(32-11);
        x = (b->k6[i>>4] <<4  | b->k5 [i &15])<<16;
	    c->k65[i] = x<<11 | x>>(32-11);
        x = (b->k4[i>>4] <<4  | b->k3 [i &15])<<8;
	    c->k43[i] = x<<11 | x>>(32-11);
        x =  b->k2[i>>4] <<4  | b->k1 [i &15];
	    c->k21[i] = x<<11 | x>>(32-11);
	}
	    */
}
typedef struct _Gost94Ctx Gost94Ctx;
struct _Gost94Ctx {
    v256 H,M,S;
    unsigned int size; // длина данных в битах
    unsigned int offset; // длина хеша
    unsigned int hlen; // длина хеша
    gost_ctx * ctx;
};

static void gost94_init_CP(Gost94Ctx *ctx)
{
    if (1){//hash_params[1].ctx== NULL) {
        gost_ctx* gct = _aligned_malloc(sizeof(gost_ctx),16);
        gost_init(gct, hash_params[1].paramset);
        hash_params[1].ctx = gct;
    }
    ctx->ctx = hash_params[1].ctx; ctx->hlen=32;
    CLR(&ctx->H);CLR(&ctx->S);
    ctx->size=0, ctx->offset=0;
}
#if 0
static void __attribute__((constructor)) gost94_init_(){
    if (hash_params[1].ctx== NULL) {
        gost_ctx* gct = _aligned_malloc(sizeof(gost_ctx),16);
//        printf("%s: Init paramset\n", __FUNCTION__);
        gost_init(gct, hash_params[1].paramset);
//        printf("%s: Init paramset done\n", __FUNCTION__);
        hash_params[1].ctx = gct;
    }
}
#endif // 0

static void gost94_init_T(Gost94Ctx *ctx)
{
    if (hash_params[0].ctx== NULL) {
        gost_ctx* gct = _aligned_malloc(sizeof(gost_ctx),16);
        gost_init(gct, hash_params[0].paramset);
        hash_params[0].ctx = gct;
    }
    ctx->ctx = hash_params[0].ctx; ctx->hlen=32;
    CLR(&ctx->H);CLR(&ctx->S);
    ctx->size=0, ctx->offset=0;
}

static void gost94_update(Gost94Ctx *ctx, const uint8_t* msg, unsigned int mlen)
{
    while (mlen>0)
    {
        unsigned int len = (mlen>32-ctx->offset)?32-ctx->offset:mlen;
        memcpy((uint8_t*)&ctx->M + ctx->offset, msg, len);
        ctx->offset+=len;
        msg+=len;
        mlen-=len;
        if (ctx->offset == 32)
        {
            gost_step(ctx->ctx, &ctx->H, &ctx->M);
            UADD(&ctx->S, &ctx->M);
            ctx->size += 256;
            ctx->offset=0;
        }
    }
}
static void gost94_final (Gost94Ctx *ctx, uint8_t * tag, unsigned int tlen)
{
    if (ctx->offset>0){
        __builtin_memset((uint8_t*)&ctx->M + ctx->offset, 0, 32-ctx->offset);
        gost_step(ctx->ctx, &ctx->H, &ctx->M);
        UADD(&ctx->S, &ctx->M);
        ctx->size += ctx->offset<<3;
        ctx->offset=0;
    }
    ctx->M.q[0] = (v2di){ctx->size,0};
    ctx->M.q[1] = (v2di){0};
    gost_step(ctx->ctx, &ctx->H,&ctx->M);
    gost_step(ctx->ctx, &ctx->H,&ctx->S);
    if (tag && tlen) __builtin_memcpy(tag, &ctx->H.d[0], tlen);
}

MESSAGE_DIGEST(MD_GOSTR341194_CP){
    .id = MD_GOSTR341194_CP,
    .name = "GOST R 34.11-94 CryptoPro",
    .block_len = 32,
    .hash_len = 32,
    .ctx_size = sizeof(Gost94Ctx),
    .init   = (void*)gost94_init_CP,
    .update = (void*)gost94_update,
    .final  = (void*)gost94_final,
};
MESSAGE_DIGEST(MD_GOSTR341194){
    .id = MD_GOSTR341194,
    .name = "GOST R 34.11-94 Test",
    .block_len = 32,
    .hash_len = 32,
    .ctx_size = sizeof(Gost94Ctx),
    .init   = (void*)gost94_init_T,
    .update = (void*)gost94_update,
    .final  = (void*)gost94_final,
};


#ifdef DEBUG_GOST

#include "stdio.h"
///
static uint8_t num(uint8_t ch) {
    return ch>='A'?ch-'A'+10: ch-'0';
}
#if 0
extern uint8_t* base64_enc(uint8_t *dst, uint8_t *src, int length);
void gost_base64(gost_ctx* ctx, char* message, int length)
{
    int len;
    uint8_t hash[32];
    gost_digest(ctx, message, length, hash);
    char b64[48];
    base64_enc(b64, hash, 32);
    printf("Digest: %s\n", b64);
}
#endif
static void GOST(const MDigest *md, char* message)
{
    int len;
    char hash[32];
    len = strlen(message);

//    printf("length = %d\n", len);
//    gost_digest2(ctx, (uint8_t*)message, len, (uint8_t*)hash);
	digest(md, (uint8_t*)&hash[0], md->hash_len, (uint8_t*)message, len);
    char ch;//
    if (len>=128)  {
        ch = message[128];
        message[128]= '\0';
    }
    printf("GOST(\"%s\") = \n",message);
    if (len>=128) message[128] = ch;
    int i;
    for (i=0; i<32; i++){
        printf("%02X", (uint8_t)hash[i]);
    }
    printf("\n");
    char b64[48];
    base64_enc(b64, hash, 32);
    printf("Digest: %s\n", b64);
}
int main (int argc, char *argv[])
{
//    gost_ctx cipher_ctx;
//    gost_init(&cipher_ctx, NULL);//&GostR3411_94_CryptoProParamSet);

    if (argc > 1 ) {
        char* filename = argv[1];
        FILE* fp = fopen(filename, "r");
        char* buf = malloc(2000000+4);
        int len = fread(buf, 1, 2000000, fp);
//        char* s = &buf[len-1];
//        while (s[0]=='\r' || s[0]=='\n' || s[0]==' ') { s--, len--; }
        buf[len]='\0';
//        gost_init(&cipher_ctx, NULL);
//        GOST(&cipher_ctx, buf);
		const MDigest *md = digest_select(MD_GOSTR341194_CP);
//        gost_init(&cipher_ctx, &GostR3411_94_CryptoProParamSet);
		GOST(md, buf);
		fclose(fp);
		free(buf);
        return 0;
    }

    int len, i;
    uint8_t * m;
//    uint8_t msg[]="73657479622032333D6874676E656C202C6567617373656D2073692073696854";

/*
    len = strlen(msg) >>1;
    m=malloc(len);
    for (i=0; i<len; i++){
        m[i] = num(msg[2*i])<<4 | num(msg[2*i+1]);
    }
    gost_digest(&cipher_ctx, m, len, NULL);
    free(m);

    uint8_t msg1[] =
            "7365747962203035203D206874676E656C207361682065676"
            "17373656D206C616E696769726F206568742065736F70707553";
    len = strlen(msg1) >>1;
    m=malloc(len);
    for (i=0; i<len; i++){
        m[i] = num(msg1[2*i])<<4 | num(msg1[2*i+1]);
    }
    gost_digest(&cipher_ctx, m, len, NULL);
    free(m);
 */
	const MDigest *md = digest_select(MD_GOSTR341194);
    GOST(md, "This is message, length=32 bytes");
    GOST(md, "The quick brown fox jumps over the lazy dog");
    GOST(md, "The quick brown fox jumps over the lazy cog");
    GOST(md, "Suppose the original message has length = 50 bytes");
    GOST(md, "");
    GOST(md, "a");
    GOST(md, "abc");
    GOST(md, "message digest");
    GOST(md, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");
    GOST(md, "12345678901234567890123456789012345678901234567890123456789012345678901234567890");
    char *m1 = malloc(1000002);
    memset(m1, 'U', 128); m1[128]='\0';
    GOST(md, m1);
    memset(m1, 'a', 1000000);m1[1000000]='\0';
    GOST(md, m1);

    printf("\nCryptoPro:\n");
	md = digest_select(MD_GOSTR341194_CP);
//    gost_init(md, &GostR3411_94_CryptoProParamSet);
    GOST(md, "");
    GOST(md, "a");
    GOST(md, "abc");
    GOST(md, "message digest");
    GOST(md, "The quick brown fox jumps over the lazy dog");
    memset(m1, 'U', 128); m1[128]='\0';
    GOST(md, m1);
    memset(m1, 'a', 1000000);m1[1000000]='\0';
    GOST(md, m1);

/*
ГОСТ Р 34.11-94 с «тестовыми» параметрами
GOST("") = ce85b99cc46752fffee35cab9a7b0278abb4c2d2055cff685af4912c49490f8d
GOST("a") = d42c539e367c66e9c88a801f6649349c21871b4344c6a573f849fdce62f314dd
GOST("abc") = f3134348c44fb1b2a277729e2285ebb5cb5e0f29c975bc753b70497c06a4d51d
GOST("message digest") = ad4434ecb18f2c99b60cbe59ec3d2469582b65273f48de72db2fde16a4889a4d
GOST("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789") = 95c1af627c356496d80274330b2cff6a10c67b5f597087202f94d06d2338cf8e
GOST("12345678901234567890123456789012345678901234567890123456789012345678901234567890") = cc178dcad4df619dcaa00aac79ca355c00144e4ada2793d7bd9b3518ead3ccd3
GOST("This is message, length=32 bytes") = b1c466d37519b82e8319819ff32595e047a28cb6f83eff1c6916a815a637fffa
GOST("Suppose the original message has length = 50 bytes") = 471aba57a60a770d3a76130635c1fbea4ef14de51f78b4ae57dd893b62f55208
GOST(128 of "U") = 53a3a3ed25180cef0c1d85a074273e551c25660a87062a52d926a9e8fe5733a4
GOST(1000000 of "a") = 5c00ccc2734cdd3332d3d4749576e3c1a7dbaf0e7ea74e9fa602413c90a129fa
GOST("The quick brown fox jumps over the lazy dog") = 77b7fa410c9ac58a25f49bca7d0468c9296529315eaca76bd1a10f376d1f4294
GOST("The quick brown fox jumps over the lazy cog") = a3ebc4daaab78b0be131dab5737a7f67e602670d543521319150d2e14eeec445

ГОСТ Р 34.11-94 с параметрами CryptoPro
GOST("") = 981e5f3ca30c841487830f84fb433e13ac1101569b9c13584ac483234cd656c0
GOST("a") = e74c52dd282183bf37af0079c9f78055715a103f17e3133ceff1aacf2f403011
GOST("abc") = b285056dbf18d7392d7677369524dd14747459ed8143997e163b2986f92fd42c
GOST("message digest") = bc6041dd2aa401ebfa6e9886734174febdb4729aa972d60f549ac39b29721ba0
GOST("The quick brown fox jumps over the lazy dog") = 9004294a361a508c586fe53d1f1b02746765e71b765472786e4770d565830a76
GOST("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789") = 73b70a39497de53a6e08c67b6d4db853540f03e9389299d9b0156ef7e85d0f61
GOST("12345678901234567890123456789012345678901234567890123456789012345678901234567890") = 6bc7b38989b28cf93ae8842bf9d752905910a7528a61e5bce0782de43e610c90
GOST("This is message, length=32 bytes") = 2cefc2f7b7bdc514e18ea57fa74ff357e7fa17d652c75f69cb1be7893ede48eb
GOST("Suppose the original message has length = 50 bytes") = c3730c5cbccacf915ac292676f21e8bd4ef75331d9405e5f1a61dc3130a65011
GOST(128 of "U") = 1c4ac7614691bbf427fa2316216be8f10d92edfd37cd1027514c1008f649c4e8
GOST(1000000 of "a") = 8693287aa62f9478f7cb312ec0866b6c4e4a0f11160441e8f4ffcd2715dd554f
*/
#if 0
    int sh[16], j;
    uint16_t mask = 0x900F;
    for (i=0; i< 16;i++){
        sh[i]= (1<<i);
    }
	int cc = 1;
    int count = cc;
	i=0;
    do {
		int s15 = 0;
        for (j=0; j< 16;j++){
            if (mask& (1<<j)) s15 ^= sh[j];
        }
		sh[i] = s15;
		mask = (mask<<1) | (mask>>15);
		i=(i+1)&0xF;
    } while (--count);
    for (i=0; i< 16;i++){

//        printf("// s[%2d]=%04X\n", i, sh[i]);
		printf("    y.h[%2d] =",(i-cc)&0xF);
		for (j=0;j<16;j++){
			if (sh[i] & (1<<j)) printf(" ^ x->h[%2d]", j);

		}
		printf(";\n");
    }
	 printf("mask=%04X\n", mask);
#endif
#if 0
    uint8_t msg2[]= "A9993E364706816ABA3E25717850C26C9CD0D89D";
    len = strlen((char*)msg2) >>1;
    m=malloc(len);
    for (i=0; i<len; i++){
        m[i] = num(msg2[2*i])<<4 | num(msg2[2*i+1]);
    }
    char * dst = malloc(len*2);
    base64_enc(dst, (char*)m, len);
    printf("<Digest>%s</Digest>\n", dst);
	free(m);
	free(dst);
	free(m1);
#endif
#if 0
{
    Gost94Ctx ctx;
    if (hash_params[0].ctx== NULL) {
        hash_params[0].ctx = _aligned_malloc(sizeof(gost_ctx));
        gost_init(hash_params[0].ctx, hash_params[0].paramset);
    }
    ctx.ctx =  hash_params[0].ctx; ctx.hlen=32;

    uint8_t k0[] = "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"
                    "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b";//, 20,
    uint8_t m0[] = "Hi There";//, 8,
    HMAC_GOSTR3411_94(&ctx, m0, 8, k0, 20);
    for (i=0; i<8; i++) printf("%08X ",ctx.H.s[i]); printf("\n");
    uint8_t h0[] = "\xc0\xb4\x65\xe5\x58\xe8\xcb\xd3\x97\xfe\x5b\xb1\x8d\x22\x89\xab"
		"\x6a\x31\x9b\x87\x1f\xa8\xa7\x46\xbf\x33\x4f\x69\xa7\xfd\x64\xbd";//,	32,
    if (memcmp(ctx.H.s, h0, 32)==0) printf("OK\n");
	uint8_t k1[] = "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa";//, 20,
	uint8_t m1[] = "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
		"\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
		"\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
		"\xdd\xdd";//, 50,
	uint8_t h1[] = "\x97\x12\x2C\x50\x7C\x98\x1F\x12\x75\xEE\xC2\xD3\xA8\x1E\x8A\x33"
		"\xD7\x18\x61\x25\x0E\xEE\xDF\x25\x40\xEF\xC8\x64\x6E\xEE\xE1\x6E";// 32,
    HMAC_GOSTR3411_94(&ctx, m1, 50, k1, 20);
    for (i=0; i<8; i++) printf("%08X ",ctx.H.s[i]); printf("\n");
    if (memcmp(ctx.H.s, h1, 32)==0) printf("OK\n");
}
{   printf("PBKDF2_HMAC_GOSTR3411_94\n");
    uint32_t dk[10];
    Gost94Ctx ctx;
    if (hash_params[1].ctx== NULL) {
        hash_params[1].ctx = _aligned_malloc(sizeof(gost_ctx), 16);
        gost_init(hash_params[1].ctx, hash_params[1].paramset);
    }
    ctx.ctx =  hash_params[1].ctx; ctx.hlen=32;
    uint8_t h0[] =  "\x73\x14\xe7\xc0\x4f\xb2\xe6\x62\xc5\x43\x67\x42\x53\xf6\x8b\xd0"
                    "\xb7\x34\x45\xd0\x7f\x24\x1b\xed\x87\x28\x82\xda\x21\x66\x2d\x58";
    PBKDF2_HMAC_GOSTR3411_94(&ctx, dk, 32,"password",8,"salt",4,1);
    for (i=0; i<8; i++) printf("%02X ",dk[i]); printf("\n");
    if(memcmp(dk,h0, 32)==0) printf("OK\n");
    uint8_t h1[] =  "\x99\x0d\xfa\x2b\xd9\x65\x63\x9b\xa4\x8b\x07\xb7\x92\x77\x5d\xf7"
                    "\x9f\x2d\xb3\x4f\xef\x25\xf2\x74\x37\x88\x72\xfe\xd7\xed\x1b\xb3";
    PBKDF2_HMAC_GOSTR3411_94(&ctx, dk, 32,"password",8,"salt",4,2);
    for (i=0; i<8; i++) printf("%02X ",dk[i]); printf("\n");
    if(memcmp(dk,h1, 32)==0) printf("OK\n");
    uint8_t h2[] =  "\x1f\x18\x29\xa9\x4b\xdf\xf5\xbe\x10\xd0\xae\xb3\x6a\xf4\x98\xe7"
                    "\xa9\x74\x67\xf3\xb3\x11\x16\xa5\xa7\xc1\xaf\xff\x9d\xea\xda\xfe";
    PBKDF2_HMAC_GOSTR3411_94(&ctx, dk, 32,"password",8,"salt",4,4096);
    for (i=0; i<8; i++) printf("%02X ",dk[i]); printf("\n");
    if(memcmp(dk,h2, 32)==0) printf("OK\n");
    uint8_t h3[] =  "\xa5\x7a\xe5\xa6\x08\x83\x96\xd1\x20\x85\x0c\x5c\x09\xde\x0a\x52"
                    "\x51\x00\x93\x8a\x59\xb1\xb5\xc3\xf7\x81\x09\x10\xd0\x5f\xcd\x97";
    // долго считает
    //PBKDF2_HMAC_GOST3411_94(&ctx, dk, 32,"password",8,"salt",4,16777216);
    for (i=0; i<8; i++) printf("%02X ",dk[i]); printf("\n");
    if(memcmp(dk,h3, 32)==0) printf("OK\n");
    uint8_t h4[] =  "\x78\x83\x58\xc6\x9c\xb2\xdb\xe2\x51\xa7\xbb\x17\xd5\xf4\x24\x1f"
                    "\x26\x5a\x79\x2a\x35\xbe\xcd\xe8\xd5\x6f\x32\x6b\x49\xc8\x50\x47"
                    "\xb7\x63\x8a\xcb\x47\x64\xb1\xfd";
    PBKDF2_HMAC_GOSTR3411_94(&ctx, dk, 40,"passwordPASSWORDpassword",24,"saltSALTsaltSALTsaltSALTsaltSALTsalt",36,4096);
    for (i=0; i<10; i++) printf("%02X ",dk[i]); printf("\n");
    if(memcmp(dk,h4, 40)==0) printf("OK\n");
    uint8_t h5[] =  "\x43\xe0\x6c\x55\x90\xb0\x8c\x02\x25\x24\x23\x73\x12\x7e\xdf\x9c"
                    "\x8e\x9c\x32\x91";
    PBKDF2_HMAC_GOSTR3411_94(&ctx, dk, 20,"pass\0word",9,"sa\0lt",5,4096);
    for (i=0; i<5; i++) printf("%02X ",dk[i]); printf("\n");
    if(memcmp(dk,h5, 20)==0) printf("OK\n");

}
#endif
    return 0;
}
#endif

