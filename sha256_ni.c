/* Раелизация алгоритмов SHA256 на базе инструкций Intel SHA-NI

$ gcc -march=native -DTEST_SHA256 -O3 -S -o sha.s sha256_ni.c
$ clang -march=native -DTEST_SHA256 -o sha.s sha256_ni.c


Предопределенные константы:
echo | gcc -march=native -dM -E - | grep SHA
 */

#include <stdint.h>
#include <stdio.h>
#include "hmac.h"

#include <intrin.h>
static uint32_t htobe32(uint32_t  v)
{
#if (__BYTE_ORDER__==__ORDER_BIG_ENDIAN__)
    return (v);
#else
	return __builtin_bswap32(v);
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
#define BLK_SIZE 64
static const uint32_t H0_256[8] = {
#if 0
0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 
0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
#else
// {{H[5],H[4],H[1],H[0]},{H[7],H[6],H[3],H[2]}};
// переставил порядок слов
	0x9b05688c,0x510e527f,0xbb67ae85,0x6a09e667,  
	0x5be0cd19,0x1f83d9ab,0xa54ff53a,0x3c6ef372,
#endif
};
typedef uint32_t uint32x4_t __attribute__((__vector_size__(16)));
typedef uint8_t  uint8x16_t __attribute__((__vector_size__(16)));
//#define PSRLDQ(a,k) (uint32x4_t)_mm_srli_si128((__m128i)a,k)
#define HIGH(a) 	  (uint32x4_t)__builtin_shufflevector (a,a,2,3,0,1)
//#define PALIGNR(a,b,k) (uint32x4_t)_mm_alignr_epi8 ((__m128i)a,(__m128i)b,k)
#define PALIGNR(a,b,k) (uint32x4_t)__builtin_shufflevector(b,a,1,2,3,4)
//#define L2B(X) (uint32x4_t)_mm_shuffle_epi8((__m128i)X,_mm_set_epi32(0x0c0d0e0f,0x08090a0b,0x04050607,0x00010203))
#define L2B(X) 		  (uint32x4_t)__builtin_shufflevector ((uint8x16_t)X,(uint8x16_t)X, 3,2,1,0, 7,6,5,4, 11,10,9,8, 15,14,13,12)
#define CVLO1B(a,b,k) (uint32x4_t)__builtin_shufflevector((uint32x4_t)a,(uint32x4_t)b,5,4,1,0)
#define CVLOB1(a,b,k) (uint32x4_t)__builtin_shufflevector((uint32x4_t)a,(uint32x4_t)b,1,0,5,4)

#define CVHI1B(a,b,k) (uint32x4_t)__builtin_shufflevector((uint32x4_t)a,(uint32x4_t)b,7,6,3,2)
#define CVHIB1(a,b,k) (uint32x4_t)__builtin_shufflevector((uint32x4_t)a,(uint32x4_t)b,3,2,7,6)

#if defined(__SHA__)// {{H[5],H[4],H[1],H[0]},{H[7],H[6],H[3],H[2]}};
//#define CVLO(a,b,k) (uint32x4_t)_mm_shuffle_epi32(_mm_unpacklo_epi64((__m128i)a,(__m128i)b),k)
//#define CVHI(a,b,k) (uint32x4_t)_mm_shuffle_epi32(_mm_unpackhi_epi64((__m128i)a,(__m128i)b),k)

/* Synopsis
__m128i _mm_sha256msg1_epu32 (__m128i a, __m128i b)
#include <immintrin.h>
Instruction: sha256msg1 xmm, xmm
CPUID Flags: SHA

W4 := b[31:0]
W3 := a[127:96]
W2 := a[95:64]
W1 := a[63:32]
W0 := a[31:0]
dst[127:96]:= W3 + sigma0(W4)
dst[95:64] := W2 + sigma0(W3)
dst[63:32] := W1 + sigma0(W2)
dst[31: 0] := W0 + sigma0(W1)
*/
#define ROTR(v, i) 	(((v)<<(32-i)) ^ ((v)>>(i)))
#define sigma0(x) 	(ROTR((x), 7) ^ ROTR((x),18) ^ ((x)>> 3))
#define sigma1(x) 	(ROTR((x),17) ^ ROTR((x),19) ^ ((x)>>10))
#define SHA256MSG11(a,b) (a + sigma0(__builtin_shufflevector(a,b,1,2,3,4)))
#define SHA256MSG1(a,b) (uint32x4_t)_mm_sha256msg1_epu32((__m128i)a,(__m128i)b)
/* Synopsis
__m128i _mm_sha256msg2_epu32 (__m128i a, __m128i b)
#include <immintrin.h>
Instruction: sha256msg2 xmm, xmm
CPUID Flags: SHA

W14 := b[95:64]
W15 := b[127:96]
W16 := a[31:0] + sigma1(W14)
W17 := a[63:32] + sigma1(W15)
W18 := a[95:64] + sigma1(W16)
W19 := a[127:96] + sigma1(W17)
dst[127:96] := W19
dst[95:64] := W18
dst[63:32] := W17
dst[31:0] := W16
*/
#define SHA256MSG21(a,b) ({ uint32x4_t T;\
	T[0] = (a)[0] + sigma1(b[2]); \
	T[1] = (a)[1] + sigma1(b[3]); \
	T[2] = (a)[2] + sigma1(T[0]); \
	T[3] = (a)[3] + sigma1(T[1]); \
	T; \
	})
#define SHA256MSG2(a,b) (uint32x4_t)_mm_sha256msg2_epu32((__m128i)a,(__m128i)b)

/* Synopsis __m128i _mm_sha256rnds2_epu32 (__m128i a, __m128i b, __m128i k)
#include <immintrin.h>
Instruction: sha256rnds2 xmm, xmm
CPUID Flags: SHA

A[0] := b[127:96]
B[0] := b[95:64]
C[0] := a[127:96]
D[0] := a[95:64]
E[0] := b[63:32]
F[0] := b[31:0]
G[0] := a[63:32]
H[0] := a[31:0]
W_K[0] := k[31:0]
W_K[1] := k[63:32]
FOR i := 0 to 1
	A[i+1] := Ch(E[i], F[i], G[i]) + sum1(E[i]) + W_K[i] + H[i] + Maj(A[i], B[i], C[i]) + sum0(A[i])
	B[i+1] := A[i]
	C[i+1] := B[i]
	D[i+1] := C[i]
	E[i+1] := Ch(E[i], F[i], G[i]) + sum1(E[i]) + W_K[i] + H[i] + D[i]
	F[i+1] := E[i]
	G[i+1] := F[i]
	H[i+1] := G[i]
ENDFOR
dst[127:96]:= A[2]
dst[95:64] := B[2]
dst[63:32] := E[2]
dst[31: 0] := F[2]
*/
#define SHA256RNDS2(a,b,k) (uint32x4_t)_mm_sha256rnds2_epu32((__m128i)a,(__m128i)b,(__m128i)(k))
#define SHA256MSG(W,i) ({\
			uint32x4_t X = SHA256MSG1(W[i&3], W[(i-3)&3])\
			  + PALIGNR(W[(i-1)&3],W[(i-2)&3],4);\
			SHA256MSG2(X, W[(i-1)&3]); \
			});
static const uint32x4_t K[] = {
	{0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5}, 
	{0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5},
	{0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3}, 
	{0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174},
	{0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc}, 
	{0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da},
	{0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7}, 
	{0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967},
	{0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13}, 
	{0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85},
	{0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3}, 
	{0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070},
	{0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5}, 
	{0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3},
	{0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208}, 
	{0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2},
};

//A = [a,b,e,f] and C = [c,d,g,h]
// uint32_t * H, uint32_t * M
static inline
void /*sha256_ni_update*/SHA256(uint32_t* H, uint32_t* msg)
{
//	__asm volatile("# LLVM-MCA-BEGIN SHA256_NI");
//	{{H[5],H[4],H[1],H[0]},{H[7],H[6],H[3],H[2]}};
	uint32x4_t W[4];
	uint32x4_t A,C;
	A = *((uint32x4_t*)H+0);
	C = *((uint32x4_t*)H+1);
	int i;
#pragma GCC unroll 16
	for(i=0;i<4;i++){
		W[i] = L2B(*((uint32x4_t*)msg+i));

		uint32x4_t X = W[i]+K[i];
		C = SHA256RNDS2 (C,A,X);
		A = SHA256RNDS2 (A,C,HIGH(X));
	}
#pragma GCC unroll 16
	for(i=4;i<16;i+=4){
		for (int j=0;j<4;j++) {
			W[j] = SHA256MSG(W,j);
		}
		for (int j=0;j<4;j++) {
			uint32x4_t X = W[j]+K[i+j];
			C = SHA256RNDS2 (C,A,X);
			A = SHA256RNDS2 (A,C,HIGH(X));
		}
	}
	*((uint32x4_t*)H+0) += A;
	*((uint32x4_t*)H+1) += C;
//	__asm volatile("# LLVM-MCA-END SHA256_NI");
}

void /*sha256_ni_update*/SHA256_(uint32x4_t *H, uint32_t *M)
{
	__asm volatile("# LLVM-MCA-BEGIN SHA256v_NI");
//	{{H[5],H[4],H[1],H[0]},{H[7],H[6],H[3],H[2]}};
	uint32x4_t W[4];
	W[0] = *((uint32x4_t*)M+0);
	W[1] = *((uint32x4_t*)M+1);
	W[2] = *((uint32x4_t*)M+2);
	W[3] = *((uint32x4_t*)M+3);
	const int N = 8;
	uint32x4_t A[N],C[N];
	for (int k=0; k<N; k++){
		A[k] = *((uint32x4_t*)H+0+2*k);
		C[k] = *((uint32x4_t*)H+1+2*k);
	}
#pragma GCC unroll 16
	for(int i=0;i<4;i++){
		register uint32x4_t X = W[i]+K[i];
		register uint32x4_t Y = HIGH(X);
		for (int k=0; k<N; k++){
			C[k] = SHA256RNDS2 (C[k],A[k],X);
			A[k] = SHA256RNDS2 (A[k],C[k],Y);
		}
	}
#pragma GCC unroll 64
	for(int i=4;i<16;i+=4){
		for (int j=0;j<4;j++) {
			W[j] = SHA256MSG(W,j);
		}
		for (int j=0;j<4;j++) {
			register uint32x4_t X = W[j]+K[i+j];
			register uint32x4_t Y = HIGH(X);
			for (int k=0; k<N; k++){
				C[k] = SHA256RNDS2 (C[k],A[k],X);
				A[k] = SHA256RNDS2 (A[k],C[k],Y);
			}
		}
	}
	for (int k=0; k<N; k++){
		*((uint32x4_t*)H+0+2*k) += A[k];
		*((uint32x4_t*)H+1+2*k) += C[k];
	}
	__asm volatile("# LLVM-MCA-END SHA256v_NI");
}
void /*sha256_ni_update*/SHA256_z(uint32x4_t *H, uint32x4_t *W)
{
	__asm volatile("# LLVM-MCA-BEGIN SHA256v2_NI");
	const int N = 8;
	uint32x4_t A[N],C[N];
	for (int k=0; k<N; k++){
		A[k] = *((uint32x4_t*)H+0 + k*2);
		C[k] = *((uint32x4_t*)H+1 + k*2);
	}
#pragma GCC unroll 4
	for(int i=0;i<4;i++){
		uint32x4_t X = W[i];
		uint32x4_t Y = HIGH(X);
		for (int k=0; k<N; k++){
			C[k] = SHA256RNDS2 (C[k],A[k],X);
			A[k] = SHA256RNDS2 (A[k],C[k],Y);
		}
	}
#pragma GCC unroll 16
	for(int i=4;i<16;i+=4){
		for (int j=0;j<4;j++) {
			uint32x4_t X = W[j+i];
			uint32x4_t Y = HIGH(X);
			for (int k=0; k<N; k++){
				C[k] = SHA256RNDS2 (C[k],A[k],X);
				A[k] = SHA256RNDS2 (A[k],C[k],Y);
			}
		}
	}
	for (int k=0; k<N; k++){
		*((uint32x4_t*)H+0 + k*2) += A[k];
		*((uint32x4_t*)H+1 + k*2) += C[k];
	}
	__asm volatile("# LLVM-MCA-END SHA256v2_NI");
}
void /*sha256_ni_update*/SHA256x2(uint32_t* H, uint32_t* msg)
{
	__asm volatile("# LLVM-MCA-BEGIN SHA256x2_NI");
//	uint32x4_t S[2] = {{H[5],H[4],H[1],H[0]},{H[7],H[6],H[3],H[2]}};
	uint32x4_t W[4];
	uint32x4_t W1[4];
	uint32x4_t W2[4];
	uint32x4_t W3[4];
	uint32x4_t A,C;
	uint32x4_t A1,C1;
	uint32x4_t A2,C2;
	uint32x4_t A3,C3;
	uint32x4_t X,Y;
	uint32x4_t X1,Y1;
	uint32x4_t X2,Y2;
	uint32x4_t X3,Y3;
	A = *((uint32x4_t*)H+0);
	C = *((uint32x4_t*)H+1);
	A1= *((uint32x4_t*)H+2);
	C1= *((uint32x4_t*)H+3);
	A2= *((uint32x4_t*)H+4);
	C2= *((uint32x4_t*)H+5);
	A3= *((uint32x4_t*)H+6);
	C3= *((uint32x4_t*)H+7);
	int i;
#pragma GCC unroll 4
	for(i=0;i<4;i++,msg+=16/4){
		W[i] = L2B(*(uint32x4_t*)(msg));
		X = W[i]+K[i];
		Y = HIGH(X);
		C = SHA256RNDS2 (C,A,X);
		A = SHA256RNDS2 (A,C,Y);

		W1[i] = L2B(*((uint32x4_t*)msg +4));
		X1 = W1[i]+K[i];
		Y1 = HIGH(X1);
		C1 = SHA256RNDS2 (C1,A1,X1);
		A1 = SHA256RNDS2 (A1,C1,Y1);

		W2[i] = L2B(*((uint32x4_t*)msg +8));
		X2 = W2[i]+K[i];
		Y2 = HIGH(X2);
		C2 = SHA256RNDS2 (C2,A2,X2);
		A2 = SHA256RNDS2 (A2,C2,Y2);

		W3[i] = L2B(*((uint32x4_t*)msg +12));
		X3 = W3[i]+K[i];
		Y3 = HIGH(X3);
		C3 = SHA256RNDS2 (C3,A3,X3);
		A3 = SHA256RNDS2 (A3,C3,Y3);
	}
#pragma GCC unroll 16
	for(i=4;i<16;i++){
		X = SHA256MSG1(W[i&3], W[(i-3)&3])
		  + PALIGNR(W[(i-1)&3],W[(i-2)&3],4);
		W[i&3] = SHA256MSG2(X, W[(i-1)&3]);

		X1 = SHA256MSG1(W1[i&3], W1[(i-3)&3])
		   + PALIGNR(W1[(i-1)&3],W1[(i-2)&3],4);
		W1[i&3] = SHA256MSG2(X1, W1[(i-1)&3]);

		X = W[i&3]+K[i];
		Y = HIGH(X);
		C = SHA256RNDS2 (C,A,X);
		A = SHA256RNDS2 (A,C,Y);

		X1 = W1[i&3]+K[i];
		Y1 = HIGH(X1);
		C1 = SHA256RNDS2 (C1,A1,X1);
		A1 = SHA256RNDS2 (A1,C1,Y1);

		X2 = SHA256MSG2(W2[i&3], W2[(i-3)&3])
		   + PALIGNR(W2[(i-1)&3],W2[(i-2)&3],4);
		W2[i&3] = SHA256MSG2(X2, W2[(i-1)&3]);

		X3 = SHA256MSG2(W3[i&3], W3[(i-3)&3]);
		X3+= PALIGNR(W3[(i-1)&3],W3[(i-2)&3],4);
		W3[i&3] = SHA256MSG2(X3, W3[(i-1)&3]);


		X2 = W2[i&3]+K[i];
		Y2 = HIGH(X2);
		C2 = SHA256RNDS2 (C2,A2,X2);
		A2 = SHA256RNDS2 (A2,C2,Y2);

		X3 = W3[i&3]+K[i];
		Y3 = HIGH(X3);
		C3 = SHA256RNDS2 (C3,A3,X3);
		A3 = SHA256RNDS2 (A3,C3,Y3);

	}
	*((uint32x4_t*)H+0) += A;
	*((uint32x4_t*)H+1) += C;
	*((uint32x4_t*)H+2) += A1;
	*((uint32x4_t*)H+3) += C1;
	*((uint32x4_t*)H+4) += A2;
	*((uint32x4_t*)H+5) += C2;
	*((uint32x4_t*)H+6) += A3;
	*((uint32x4_t*)H+7) += C3;
	__asm volatile("# LLVM-MCA-END SHA256x2_NI");
}
#else
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
		W[i] = htobe32(M[i]); \
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
    register uint32_t a = H[3],b = H[2],c = H[7],d = H[6],e = H[1],f = H[0],g = H[5],h = H[4];
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
    H[3]+=a, H[2]+=b, H[7]+=c, H[6]+=d, H[1]+=e, H[0]+=f, H[5]+=g, H[4]+=h;
}
	
#endif // __SHA__

void sha256_midstate(uint8_t *tag, uint8_t *message)
{
	uint32_t H[8];
	uint32_t buffer[BLK_SIZE/4];
	__builtin_memcpy(H, H0_256, 32);
	__builtin_memcpy((uint8_t*)buffer, message, 64);
	SHA256(H, buffer);

	uint32x4_t A = *((uint32x4_t*)H+0);
	uint32x4_t C = *((uint32x4_t*)H+1);

	*((uint32x4_t*)tag+0) = (CVHIB1(A, C, 0b10110001));// каждые два бита imm определяют положение при перестановке
	*((uint32x4_t*)tag+1) = (CVLOB1(A, C, 0b10110001));// {{H[5],H[4],H[1],H[0]},{H[7],H[6],H[3],H[2]}};

//	htole32_32(H);
//	__builtin_memcpy(digest, H, 32);
//	for(int i=0; i < 8; i++, digest+=4)
//		*(uint32_t*)digest = htole32(H[i]);
}
typedef struct _HashCtx HashCtx;
struct _HashCtx {
    uint32_t H[8];
    uint32_t buffer[16];
    uint32_t length;    // длина данных
};
static void sha256_init(HashCtx *ctx)
{
	__builtin_memcpy(ctx->H, H0_256, 32);
    ctx->length = 0;
}

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
			//ntohl_vec(ctx->buffer, BLK_SIZE/4);
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
		//ntohl_vec(ctx->buffer, 64/4);
        SHA256(ctx->H, ctx->buffer);
        __builtin_memset(&buffer[0], 0, 64);
    } else {
        __builtin_memset(&buffer[offset+1], 0, 55 - offset);
        //if (__BYTE_ORDER__==__ORDER_LITTLE_ENDIAN__) 
		//ntohl_vec(ctx->buffer, ((offset+4)>>2));
    }
//	*(uint64_t*)(ctx->buffer+56) = htonll(ctx->length<<3);
    ctx->buffer[15] = htobe32(ctx->length<< 3);
    ctx->buffer[14] = htobe32(ctx->length>>29);
    SHA256(ctx->H, ctx->buffer);
    //if (__BYTE_ORDER__==__ORDER_LITTLE_ENDIAN__) 
	uint32x4_t A = *((uint32x4_t*)ctx->H+0);
	uint32x4_t C = *((uint32x4_t*)ctx->H+1);

	*((uint32x4_t*)tag+0) = L2B(CVHIB1(A, C, 0b10110001));// каждые два бита imm определяют положение при перестановке
	*((uint32x4_t*)tag+1) = L2B(CVLOB1(A, C, 0b10110001));// {{H[5],H[4],H[1],H[0]},{H[7],H[6],H[3],H[2]}};
	
//	ntohl_vec(ctx->H, /*ctx->hlen>>2*/32/4);
//    __builtin_memcpy(tag, ctx->H, 32);

}
static void sha256(uint8_t *hash, const uint8_t *data, unsigned int len)
{
	HashCtx ctx;
	sha256_init  (&ctx);
	sha256_update(&ctx, data, len);
	sha256_final (&ctx, hash, 32);
}
static void sha256_32_final(HashCtx *ctx, uint8_t *tag)
{
    //if (__BYTE_ORDER__==__ORDER_LITTLE_ENDIAN__) 
	//ntohl_vec(ctx->buffer, 32/4);
    int offset = ctx->length&63;
	ctx->buffer[offset>>2] = htole32(0x80);
    ctx->buffer[15] = htobe32(ctx->length<< 3);
    ctx->buffer[14] = htobe32(ctx->length>>29);
    SHA256(ctx->H, ctx->buffer);
    //if (__BYTE_ORDER__==__ORDER_LITTLE_ENDIAN__) 
	uint32x4_t A = *((uint32x4_t*)ctx->H+0);
	uint32x4_t C = *((uint32x4_t*)ctx->H+1);

	*((uint32x4_t*)tag+0) = L2B(CVHIB1(A, C, 0b10110001));// каждые два бита imm определяют положение при перестановке
	*((uint32x4_t*)tag+1) = L2B(CVLOB1(A, C, 0b10110001));// {{H[5],H[4],H[1],H[0]},{H[7],H[6],H[3],H[2]}};

}
static void sha256_32(uint8_t *digest, uint8_t *message)
{
	HashCtx ctx;
	__builtin_memcpy(ctx.H, H0_256, 32);
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
void sha256_calc(uint8_t *digest, uint8_t *message)
{
	uint32x4_t H[2];
	uint32_t buffer[64/4];
//	HashCtx ctx;
	uint32x4_t X = *((uint32x4_t*)digest+0);
	uint32x4_t Y = *((uint32x4_t*)digest+1);
	*((uint32x4_t*)H+0) = CVLO1B(X, Y, 0b00011011);// каждые два бита imm определяют положение при перестановке
	*((uint32x4_t*)H+1) = CVHI1B(X, Y, 0b00011011);// {{H[5],H[4],H[1],H[0]},{H[7],H[6],H[3],H[2]}};

	__builtin_memcpy((uint8_t*)buffer, message+64, 16);
	__builtin_memset((uint8_t*)buffer+16, 0, 64-16);

	buffer[ 4] = htole32(0x80);
    buffer[15] = htobe32(80<< 3);

    SHA256((uint32_t*)H, buffer);
	uint32x4_t A = *((uint32x4_t*)H+0);
	uint32x4_t C = *((uint32x4_t*)H+1);
	
	*((uint32x4_t*)buffer+0) = L2B(CVHIB1(A, C, 0b10110001));// каждые два бита imm определяют положение при перестановке
	*((uint32x4_t*)buffer+1) = L2B(CVLOB1(A, C, 0b10110001));// {{H[5],H[4],H[1],H[0]},{H[7],H[6],H[3],H[2]}};
	__builtin_memset((uint8_t*)buffer+32, 0, 32);

	__builtin_memcpy(H, H0_256, 32);

	buffer[ 8] = htole32(0x80);
    buffer[15] = htobe32(32<< 3);

    SHA256((uint32_t*)H, buffer);
	A = *((uint32x4_t*)H+0);
	C = *((uint32x4_t*)H+1);

	*((uint32x4_t*)digest+0) = L2B(CVHIB1(A, C, 0b10110001));// каждые два бита imm определяют положение при перестановке
	*((uint32x4_t*)digest+1) = L2B(CVLOB1(A, C, 0b10110001));// {{H[5],H[4],H[1],H[0]},{H[7],H[6],H[3],H[2]}};
//	ntohl_vec(H, 32/4);
//    __builtin_memcpy(digest, H, 32);
}

MESSAGE_DIGEST(MD_SHA256) {
    .id = MD_SHA256,
    .name = "SHA-256 NI",
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
    if (__builtin_memcmp(tag, hash,32)==0) 
		printf("OK\n");
	else {
		for (int i=0; i<32;i++)
			printf("% 02X",(uint8_t)tag[i]);
		printf("\n");
		printf("Fail\n");
	}
	sha256d(tag, (uint8_t*)msg, 0);
	for (int i=0; i<32;i++)
		printf("% 02X",(uint8_t)tag[i]);
	printf("\n");
	return 0;
}
#endif
