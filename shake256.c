/*! shake-256, SHA3-256, SHA3-512

2025, Анатолий М. Георгиевский 

Эффективная реализация функций SHA3 и SHAKE с использованием инструкций AVX512 и векторных регистров 512 бит. 
+ Все операции выполняются по строкам 5*64 бит, на регистрах 512 бит. 
+ Перестановки π() реализованы за счет транспонирования матрицы 5x5 и перестановок слов в строке.
+ Логические операции χ() и ρ() ориентированы на использование тернарной логики и циклического сдвига.
+ реализация алгоритма KECCAK-p[1600, 24] выполнена с использованием векторного расширения языка C для переносимости.

\see NIST.FIPS.202
SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions
(https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf)

\see NIST Special Publication 800-185
SHA-3 Derived Functions: cSHAKE, KMAC, TupleHash and ParallelHash
(https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf)

Тестирование:
gcc -DTEST_SHA3 -march=native -O3 -o test shake256.c

\see (https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values)

* https://csrc.nist.gov/csrc/media/projects/cryptographic-standards-and-guidelines/documents/examples/sha3-224_1600.pdf
* https://csrc.nist.gov/csrc/media/projects/cryptographic-standards-and-guidelines/documents/examples/sha3-256_1600.pdf
* https://csrc.nist.gov/csrc/media/projects/cryptographic-standards-and-guidelines/documents/examples/sha3-384_1600.pdf
* https://csrc.nist.gov/csrc/media/projects/cryptographic-standards-and-guidelines/documents/examples/sha3-512_1600.pdf
* https://csrc.nist.gov/csrc/media/projects/cryptographic-standards-and-guidelines/documents/examples/sha3-512_msg0.pdf
* https://csrc.nist.gov/csrc/media/projects/cryptographic-standards-and-guidelines/documents/examples/sha3-384_msg0.pdf
* https://csrc.nist.gov/csrc/media/projects/cryptographic-standards-and-guidelines/documents/examples/sha3-256_msg0.pdf
* https://csrc.nist.gov/csrc/media/projects/cryptographic-standards-and-guidelines/documents/examples/sha3-224_msg0.pdf
* https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHAKE256_Msg0.pdf
* https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHAKE128_Msg0.pdf

* https://csrc.nist.gov/csrc/media/projects/cryptographic-standards-and-guidelines/documents/examples/sha3-384_msg30.pdf
* https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/cSHAKE_samples.pdf

Определение функции KECCAK-p[b, nr] для b = 1600 и nr = 24
Функция определяется для различной разрядности w, w=1,2,4,8,16,32,64, от одного бита до 64 бит. 
Но в стандарте используется вариант w=64, b=1600 с числом циклов 24.

Алгоритм построен как сеть (губка, SPONGE) с контекстным состоянием 200 байт (1600бит), состоящим из 25 64-битных слов.
Алгоритм использует перестановки (permutation) и битовые логические операции.

Губка впитывает данные методом `absorb` - побитовое исключающее или, и применяет 24 _слоя_ преобразования `f`.
Губка рассматривается как отдельный алгоритм, который может впитывать данные и выполнять последующую генерацию 
(squeeze) за счет циклического обновления контекста.

Функции заданы параметрически.
KECCAK[c] = SPONGE[KECCAK-p[1600, 24], pad10*1, 1600–c].
SPONGE[f, pad,r] 
    The sponge function in which the underlying function is `f`, the padding 
    rule is `pad`, and the rate is `r` bits.
* Для кодирования битовой строки используется `pad10*1`

Функции SHA3 предназначены для кодирования байтовых строк. Имеют длину контекста 1600 бит, 
но при кодировании используются часть контекста `r`, которая зависит от длины `с`, r+c=b=1600.

После функции указан длина блока записи `r` в байтах:
SHA3-224(M) = KECCAK[448] (M || 01, 224); -- 144
SHA3-256(M) = KECCAK[512] (M || 01, 256); -- 136
SHA3-384(M) = KECCAK[768] (M || 01, 384); -- 104
SHA3-512(M) = KECCAK[1024](M || 01, 512). --  72

Функция SHAKE XOF (eXtendable Output Function) предназначена для генерации детерминированных 
псевдослучайных байтовых последовательностей произвольной длины `d`.
SHAKE128(M, d) = KECCAK[256] (M || 1111, d), -- 168
SHAKE256(M, d) = KECCAK[512] (M || 1111, d). -- 136

При кодировании байтовой строки дополнительные биты выглядят как 
 * 0x06 || 0.. || 0x08 для функций SHA3  - младшие биты 01, к ним добавляется 1 в функции `pad10*1`,
 * 0x1F || 0.. || 0x08 для функций SHAKE - младшие биты 1111, к ним добавляется 1.
Функция `pad10*1` добавляет в конец состояния старший бит 0x80.
 */ 
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <x86intrin.h>

typedef uint64_t uint64x5_t __attribute__((__vector_size__(64)));// 512
typedef uint32_t uint32x5_t __attribute__((__vector_size__(32)));// 256
#define U64_C(c) c##uLL
static const uint64_t RC[24 + 1] = {// KECCAK-p[1600, 24] 
  U64_C(0x0000000000000001), U64_C(0x0000000000008082),
  U64_C(0x800000000000808A), U64_C(0x8000000080008000),
  U64_C(0x000000000000808B), U64_C(0x0000000080000001),
  U64_C(0x8000000080008081), U64_C(0x8000000000008009),
  U64_C(0x000000000000008A), U64_C(0x0000000000000088),
  U64_C(0x0000000080008009), U64_C(0x000000008000000A),
  U64_C(0x000000008000808B), U64_C(0x800000000000008B),
  U64_C(0x8000000000008089), U64_C(0x8000000000008003),
  U64_C(0x8000000000008002), U64_C(0x8000000000000080),
  U64_C(0x000000000000800A), U64_C(0x800000008000000A),
  U64_C(0x8000000080008081), U64_C(0x8000000000008080),
  U64_C(0x0000000080000001), U64_C(0x8000000080008008),
};
static const uint32_t RC_32[24] = {// KECCAK-p[800, 24] 
0x00000001uL, 0x00008082uL, 0x0000808auL, 0x80008000uL,
0x0000808buL, 0x80000001uL, 0x80008081uL, 0x00008009uL,
0x0000008auL, 0x00000088uL, 0x80008009uL, 0x8000000auL,
0x8000808buL, 0x0000008buL, 0x00008089uL, 0x00008003uL,
0x00008002uL, 0x00000080uL, 0x0000800auL, 0x8000000auL,
0x80008081uL, 0x00008080uL, 0x80000001uL, 0x80008008uL
};
/* The KECCAK-p[1600, 24] permutation, nr=24, 

The generalization of the KECCAK-f[b] permutations that is defined in NIST
Standard by converting the number of rounds nr to an input parameter
The set of values for the width b of the permutations is 
{25, 50, 100, 200, 400, 800, 1600}.

5x5 w=64 b=1600
5x5 w=32 b= 800

Пермутация \rho:
for (t=0; t<24; t++){
    s = (–(t+1)(t+2)/2) % 5;
    A_y[x] := ROTL(A_y[x]^D[x], s);
    {x, y} = {y, (2x+3y) % 5};
}

Rnd(A, ir) = ι(χ(π(ρ(θ(A)))), ir).
 */
static inline
uint64x5_t chi(uint64x5_t a){
    uint64x5_t a1 = __builtin_shufflevector(a, a, 1, 2, 3, 4, 0, 5,6,7);
    uint64x5_t a2 = __builtin_shufflevector(a, a, 2, 3, 4, 0, 1, 5,6,7);
    return (~a1 & a2)^a;
}
static inline
uint64x5_t theta(uint64x5_t a){
    uint64x5_t a0 = __builtin_shufflevector(a, a, 4, 0, 1, 2, 3, 5,6,7);
    uint64x5_t a1 = __builtin_shufflevector(a, a, 1, 2, 3, 4, 0, 5,6,7);
    return a0 ^ ((a1<<1)|(a1>>63));// ROTL(63)
}
/* pi: сдвиг и транспонирование матрицы 5x5
0, 3, 1, 4, 2,
1, 4, 2, 0, 3,
2, 0, 3, 1, 4,
3, 1, 4, 2, 0,
4, 2, 0, 3, 1,
*/
//static inline
void pi_transpose(uint64x5_t *r, uint64x5_t r0, uint64x5_t r1,uint64x5_t r2,uint64x5_t r3,uint64x5_t r4){
    r0 = __builtin_shufflevector(r0, r0, 0, 3, 1, 4, 2, 5,6,7);// старшие 3 бита по маске 0x1F, не используются
    r1 = __builtin_shufflevector(r1, r1, 1, 4, 2, 0, 3, 5,6,7);
    r2 = __builtin_shufflevector(r2, r2, 2, 0, 3, 1, 4, 5,6,7);
    r3 = __builtin_shufflevector(r3, r3, 3, 1, 4, 2, 0, 5,6,7);
    r4 = __builtin_shufflevector(r4, r4, 4, 2, 0, 3, 1, 5,6,7);// -- заменил индексы
    register uint64x5_t t0, t1, t2, t3;
    t0 = __builtin_shufflevector(r0, r1, 0, 8, 2, 10, 4, 12, 6, 14);// unpacklo
    t1 = __builtin_shufflevector(r0, r1, 1, 9, 3, 11, 5, 13, 7, 15);// unpackhi
    t2 = __builtin_shufflevector(r2, r3, 0, 8, 2, 10, 4, 12, 6, 14);
    t3 = __builtin_shufflevector(r2, r3, 1, 9, 3, 11, 5, 13, 7, 15);

    r0 = __builtin_shufflevector(t0, t2, 0, 1, 8,  9, 4, 5, 12, 13);
    r1 = __builtin_shufflevector(t1, t3, 0, 1, 8,  9, 4, 5, 12, 13);
    r2 = __builtin_shufflevector(t0, t2, 2, 3,10, 11, 6, 7, 14, 15);
    r3 = __builtin_shufflevector(t1, t3, 2, 3,10, 11, 6, 7, 14, 15);
// эти сдвиги соответствуют транспонированию матрицы
    r[0] = __builtin_shufflevector(r0, r4, 0, 1, 2, 3, 8,  9,  10, 11);
    r[1] = __builtin_shufflevector(r1, r4, 0, 1, 2, 3, 9,  10, 11, 12);
    r[2] = __builtin_shufflevector(r2, r4, 0, 1, 2, 3, 10, 11, 12, 13);
    r[3] = __builtin_shufflevector(r3, r4, 0, 1, 2, 3, 11, 12, 13, 14);
    r[4] = __builtin_shufflevector(r0, r4, 4, 5, 6, 7, 12, 13, 14, 15);
}
static inline
uint64x5_t rho(uint64x5_t a, uint64x5_t s){
#ifdef __AVX512F__
    return (uint64x5_t)_mm512_rolv_epi64((__m512i)a, (__m512i)s);
#else
    return (a<<s)|(a>>(64-s));
#endif
}
static void print_state(char* title, uint64x5_t a0, uint64x5_t a1, uint64x5_t a2, uint64x5_t a3, uint64x5_t a4)
{
    printf("%s\n", title);
    int n = 0;
    uint8_t* s = (uint8_t*)&a0;
    for (int i=0; i<5*8; i++) {
        printf("%02x ", s[i]);
        if(n++ %16 == 15) printf("\n");
    }
    s = (uint8_t*)&a1;
    for (int i=0; i<5*8; i++) {
        printf("%02x ", s[i]);
        if(n++ %16 == 15) printf("\n");
    }
    s = (uint8_t*)&a2;
    for (int i=0; i<5*8; i++) {
        printf("%02x ", s[i]);
        if(n++ %16 == 15) printf("\n");
    }
    s = (uint8_t*)&a3;
    for (int i=0; i<5*8; i++) {
        printf("%02x ", s[i]);
        if(n++ %16 == 15) printf("\n");
    }
    s = (uint8_t*)&a4;
    for (int i=0; i<5*8; i++) {
        printf("%02x ", s[i]);
        if(n++ %16 == 15) printf("\n");
    }
    printf("\n");
}
#define ROTL(x,n) (((x) << (n)) | ((x) >> (64-(n))))
#define ROTR(x,n) (((x) << (64-(n))) | ((x) >> (n)))
static void KeccakF1600(uint64_t * s, int nr)
{
    register uint64x5_t A0, A1, A2, A3, A4;
#ifdef __AVX512F__
    __mmask8 mask = 0x1F;
    A0 = (uint64x5_t)_mm512_maskz_load_epi64(mask, s);
    A1 = (uint64x5_t)_mm512_maskz_load_epi64(mask, s+5);
    A2 = (uint64x5_t)_mm512_maskz_load_epi64(mask, s+10);
    A3 = (uint64x5_t)_mm512_maskz_load_epi64(mask, s+15);
    A4 = (uint64x5_t)_mm512_maskz_load_epi64(mask, s+20);
#else
    for (int i=0;i<5;i++) {
        A0[i] = s[i];
        A1[i] = s[i+5];
        A2[i] = s[i+10];
        A3[i] = s[i+15];
        A4[i] = s[i+20];
    }
#endif
    const uint64x5_t rh[5] = {// сдвиговые константы для rho
        { 0,  1, 62, 28, 27},
        {36, 44,  6, 55, 20},
        { 3, 10, 43, 25, 39},
        {41, 45, 15, 21,  8},
        {18,  2, 61, 56, 14}};

    for (int ir=0; ir<nr; ir++) {
#if 0// если не поддерживаются векторные типы. Эта реализация использует 64 битные типы.
        uint64x5_t B0,B1,B2,B3,B4, C, D;
        C[0] = A0[0] ^ A1[0] ^ A2[0] ^ A3[0] ^ A4[0];
        C[1] = A0[1] ^ A1[1] ^ A2[1] ^ A3[1] ^ A4[1];
        C[2] = A0[2] ^ A1[2] ^ A2[2] ^ A3[2] ^ A4[2];
        C[3] = A0[3] ^ A1[3] ^ A2[3] ^ A3[3] ^ A4[3];
        C[4] = A0[4] ^ A1[4] ^ A2[4] ^ A3[4] ^ A4[4];

        D[0] = C[4] ^ ROTL(C[1], 1);
        D[1] = C[0] ^ ROTL(C[2], 1);
        D[2] = C[1] ^ ROTL(C[3], 1);
        D[3] = C[2] ^ ROTL(C[4], 1);
        D[4] = C[3] ^ ROTL(C[0], 1);

        B0[1] = ROTR(A0[1]^D[1], 63);
        B2[0] = ROTR(A2[0]^D[0], 61);
        B1[2] = ROTR(A1[2]^D[2], 58);
        B2[1] = ROTR(A2[1]^D[1], 54);
        B3[2] = ROTR(A3[2]^D[2], 49);
        B3[3] = ROTR(A3[3]^D[3], 43);
        B0[3] = ROTR(A0[3]^D[3], 36);
        B1[0] = ROTR(A1[0]^D[0], 28);
        B3[1] = ROTR(A3[1]^D[1], 19);
        B1[3] = ROTR(A1[3]^D[3], 9);
        B4[1] = ROTR(A4[1]^D[1], 62);
        B4[4] = ROTR(A4[4]^D[4], 50);
        B0[4] = ROTR(A0[4]^D[4], 37);
        B3[0] = ROTR(A3[0]^D[0], 23);
        B4[3] = ROTR(A4[3]^D[3], 8);
        B3[4] = ROTR(A3[4]^D[4], 56);
        B2[3] = ROTR(A2[3]^D[3], 39);
        B2[2] = ROTR(A2[2]^D[2], 21);
        B0[2] = ROTR(A0[2]^D[2], 2);
        B4[0] = ROTR(A4[0]^D[0], 46);
        B2[4] = ROTR(A2[4]^D[4], 25);
        B4[2] = ROTR(A4[2]^D[2], 3);
        B1[4] = ROTR(A1[4]^D[4], 44);
        B1[1] = ROTR(A1[1]^D[1], 20);
        B0[0] = (A0[0]^D[0]);
        if(0)print_state("After rho", B0, B1, B2, B3, B4);
        A0[0] = B0[0];
        A0[1] = B1[1];
        A0[2] = B2[2];
        A0[3] = B3[3];
        A0[4] = B4[4];
        A1[0] = B0[3];
        A1[1] = B1[4];
        A1[2] = B2[0];
        A1[3] = B3[1];
        A1[4] = B4[2];
        A2[0] = B0[1];
        A2[1] = B1[2];
        A2[2] = B2[3];
        A2[3] = B3[4];
        A2[4] = B4[0];
        A3[0] = B0[4];
        A3[1] = B1[0];
        A3[2] = B2[1];
        A3[3] = B3[2];
        A3[4] = B4[3];
        A4[0] = B0[2];
        A4[1] = B1[3];
        A4[2] = B2[4];
        A4[3] = B3[0];
        A4[4] = B4[1];
        if(0)print_state("After pi", A0, A1, A2, A3, A4);
// chi
        C[0] = (~A0[1] & A0[2]);
        C[1] = (~A0[2] & A0[3]);
        C[2] = (~A0[3] & A0[4]);
        C[3] = (~A0[4] & A0[0]);
        C[4] = (~A0[0] & A0[1]);
        A0[0] ^= C[0];
        A0[1] ^= C[1];
        A0[2] ^= C[2];
        A0[3] ^= C[3];
        A0[4] ^= C[4];

        C[0] = (~A1[1] & A1[2]);
        C[1] = (~A1[2] & A1[3]);
        C[2] = (~A1[3] & A1[4]);
        C[3] = (~A1[4] & A1[0]);
        C[4] = (~A1[0] & A1[1]);
        A1[0] ^= C[0];
        A1[1] ^= C[1];
        A1[2] ^= C[2];
        A1[3] ^= C[3];
        A1[4] ^= C[4];

        C[0] = (~A2[1] & A2[2]);
        C[1] = (~A2[2] & A2[3]);
        C[2] = (~A2[3] & A2[4]);
        C[3] = (~A2[4] & A2[0]);
        C[4] = (~A2[0] & A2[1]);
        A2[0] ^= C[0];
        A2[1] ^= C[1];
        A2[2] ^= C[2];
        A2[3] ^= C[3];
        A2[4] ^= C[4];

        C[0] = (~A3[1] & A3[2]);
        C[1] = (~A3[2] & A3[3]);
        C[2] = (~A3[3] & A3[4]);
        C[3] = (~A3[4] & A3[0]);
        C[4] = (~A3[0] & A3[1]);
        A3[0] ^= C[0];
        A3[1] ^= C[1];
        A3[2] ^= C[2];
        A3[3] ^= C[3];
        A3[4] ^= C[4];

        C[0] = (~A4[1] & A4[2]);
        C[1] = (~A4[2] & A4[3]);
        C[2] = (~A4[3] & A4[4]);
        C[3] = (~A4[4] & A4[0]);
        C[4] = (~A4[0] & A4[1]);
        A4[0] ^= C[0];
        A4[1] ^= C[1];
        A4[2] ^= C[2];
        A4[3] ^= C[3];
        A4[4] ^= C[4];

#else
        uint64x5_t D = theta(A0 ^ A1 ^ A2 ^ A3 ^ A4);
        if(0)print_state("After theta", A0^D, A1^D, A2^D, A3^D, A4^D);
// rho
        uint64x5_t r[5];
        A0 = rho(A0^D, rh[0]);
        A1 = rho(A1^D, rh[1]);
        A2 = rho(A2^D, rh[2]);
        A3 = rho(A3^D, rh[3]);
        A4 = rho(A4^D, rh[4]);
        if(0)print_state("After rho", A0, A1, A2, A3, A4);
// pi (permutation) вращение по кругу, сводится к пермутации строк и транспонированию 5x5
        pi_transpose(r, A0, A1, A2, A3, A4);
        if(0)print_state("After pi", r[0], r[1], r[2], r[3], r[4]);
// chi
        A0 = chi(r[0]);
        A1 = chi(r[1]);
        A2 = chi(r[2]);
        A3 = chi(r[3]);
        A4 = chi(r[4]);
#endif
        if(0)print_state("After chi", A0, A1, A2, A3, A4);
// iota
        A0[0] = A0[0] ^ RC[ir];
    }
    if(0) print_state("After Permutation", A0, A1, A2, A3, A4);
#ifdef __AVX512F__
    _mm512_mask_store_epi64(s   , mask, (__m512i)A0);
    _mm512_mask_store_epi64(s+5 , mask, (__m512i)A1);
    _mm512_mask_store_epi64(s+10, mask, (__m512i)A2);
    _mm512_mask_store_epi64(s+15, mask, (__m512i)A3);
    _mm512_mask_store_epi64(s+20, mask, (__m512i)A4);
#else
    for (int i=0;i<5;i++) {
        s[i   ] = A0[i];
        s[i+ 5] = A1[i];
        s[i+10] = A2[i];
        s[i+15] = A3[i];
        s[i+20] = A4[i];
    }
#endif
}
#undef ROTL
#undef ROTR
#define ROTL(x,n) (((x) << (n)) | ((x) >> (32-(n))))
#define ROTR(x,n) (((x) << (32-(n))) | ((x) >> (n)))
void KeccakF800(uint32_t * s, int nr)
{
    register uint32x5_t A0, A1, A2, A3, A4;
    for (int i=0;i<5;i++) {
        A0[i] = s[i];
        A1[i] = s[i+5];
        A2[i] = s[i+10];
        A3[i] = s[i+15];
        A4[i] = s[i+20];
    }
    for (int ir=0; ir<nr; ir++) {
        uint32x5_t B0,B1,B2,B3,B4, C, D;
        C[0] = A0[0] ^ A1[0] ^ A2[0] ^ A3[0] ^ A4[0];
        C[1] = A0[1] ^ A1[1] ^ A2[1] ^ A3[1] ^ A4[1];
        C[2] = A0[2] ^ A1[2] ^ A2[2] ^ A3[2] ^ A4[2];
        C[3] = A0[3] ^ A1[3] ^ A2[3] ^ A3[3] ^ A4[3];
        C[4] = A0[4] ^ A1[4] ^ A2[4] ^ A3[4] ^ A4[4];

        D[0] = C[4] ^ ROTL(C[1], 1);
        D[1] = C[0] ^ ROTL(C[2], 1);
        D[2] = C[1] ^ ROTL(C[3], 1);
        D[3] = C[2] ^ ROTL(C[4], 1);
        D[4] = C[3] ^ ROTL(C[0], 1);
// rho:
        B0[1] = ROTR(A0[1]^D[1], 31);
        B2[0] = ROTR(A2[0]^D[0], 29);
        B1[2] = ROTR(A1[2]^D[2], 26);
        B2[1] = ROTR(A2[1]^D[1], 22);
        B3[2] = ROTR(A3[2]^D[2], 17);
        B3[3] = ROTR(A3[3]^D[3], 11);
        B0[3] = ROTR(A0[3]^D[3], 4);
        B1[0] = ROTR(A1[0]^D[0], 28);
        B3[1] = ROTR(A3[1]^D[1], 19);
        B1[3] = ROTR(A1[3]^D[3], 9);
        B4[1] = ROTR(A4[1]^D[1], 30);
        B4[4] = ROTR(A4[4]^D[4], 18);
        B0[4] = ROTR(A0[4]^D[4], 5);
        B3[0] = ROTR(A3[0]^D[0], 23);
        B4[3] = ROTR(A4[3]^D[3], 8);
        B3[4] = ROTR(A3[4]^D[4], 24);
        B2[3] = ROTR(A2[3]^D[3], 7);
        B2[2] = ROTR(A2[2]^D[2], 21);
        B0[2] = ROTR(A0[2]^D[2], 2);
        B4[0] = ROTR(A4[0]^D[0], 14);
        B2[4] = ROTR(A2[4]^D[4], 25);
        B4[2] = ROTR(A4[2]^D[2], 3);
        B1[4] = ROTR(A1[4]^D[4], 12);
        B1[1] = ROTR(A1[1]^D[1], 20);
        B0[0] =     (A0[0]^D[0]);
// pi:
        A0[0] = B0[0];
        A0[1] = B1[1];
        A0[2] = B2[2];
        A0[3] = B3[3];
        A0[4] = B4[4];
        A1[0] = B0[3];
        A1[1] = B1[4];
        A1[2] = B2[0];
        A1[3] = B3[1];
        A1[4] = B4[2];
        A2[0] = B0[1];
        A2[1] = B1[2];
        A2[2] = B2[3];
        A2[3] = B3[4];
        A2[4] = B4[0];
        A3[0] = B0[4];
        A3[1] = B1[0];
        A3[2] = B2[1];
        A3[3] = B3[2];
        A3[4] = B4[3];
        A4[0] = B0[2];
        A4[1] = B1[3];
        A4[2] = B2[4];
        A4[3] = B3[0];
        A4[4] = B4[1];
// chi
        C[0] = (~A0[1] & A0[2]);
        C[1] = (~A0[2] & A0[3]);
        C[2] = (~A0[3] & A0[4]);
        C[3] = (~A0[4] & A0[0]);
        C[4] = (~A0[0] & A0[1]);
        A0[0] ^= C[0];
        A0[1] ^= C[1];
        A0[2] ^= C[2];
        A0[3] ^= C[3];
        A0[4] ^= C[4];

        C[0] = (~A1[1] & A1[2]);
        C[1] = (~A1[2] & A1[3]);
        C[2] = (~A1[3] & A1[4]);
        C[3] = (~A1[4] & A1[0]);
        C[4] = (~A1[0] & A1[1]);
        A1[0] ^= C[0];
        A1[1] ^= C[1];
        A1[2] ^= C[2];
        A1[3] ^= C[3];
        A1[4] ^= C[4];

        C[0] = (~A2[1] & A2[2]);
        C[1] = (~A2[2] & A2[3]);
        C[2] = (~A2[3] & A2[4]);
        C[3] = (~A2[4] & A2[0]);
        C[4] = (~A2[0] & A2[1]);
        A2[0] ^= C[0];
        A2[1] ^= C[1];
        A2[2] ^= C[2];
        A2[3] ^= C[3];
        A2[4] ^= C[4];

        C[0] = (~A3[1] & A3[2]);
        C[1] = (~A3[2] & A3[3]);
        C[2] = (~A3[3] & A3[4]);
        C[3] = (~A3[4] & A3[0]);
        C[4] = (~A3[0] & A3[1]);
        A3[0] ^= C[0];
        A3[1] ^= C[1];
        A3[2] ^= C[2];
        A3[3] ^= C[3];
        A3[4] ^= C[4];

        C[0] = (~A4[1] & A4[2]);
        C[1] = (~A4[2] & A4[3]);
        C[2] = (~A4[3] & A4[4]);
        C[3] = (~A4[4] & A4[0]);
        C[4] = (~A4[0] & A4[1]);
        A4[0] ^= C[0];
        A4[1] ^= C[1];
        A4[2] ^= C[2];
        A4[3] ^= C[3];
        A4[4] ^= C[4];
// iota
        A0[0] = A0[0] ^ RC_32[ir];
    }
    for (int i=0;i<5;i++) {
        s[i   ] = A0[i];
        s[i+ 5] = A1[i];
        s[i+10] = A2[i];
        s[i+15] = A3[i];
        s[i+20] = A4[i];
    }
}

typedef uint64_t uint64x8_t __attribute__((__vector_size__(64)));// 512

/*! Заполнение буфера данными завершается меткой `0x04` для cSHAKE128. Последний байт 
всегда `0x80`.

SPONGE[f, pad, r](N, d):
Steps:
1. Let P=N || pad(r, len(N)).
2. Let n=len(P)/r.
3. Let c=b-r.
4. Let P0, … , Pn-1 be the unique sequence of strings of length r such that P = P0 || … || Pn1.
5. Let S=0^b.
6. For i from 0 to n-1, let S=f(S ⊕ (Pi|| 0^c)).
7. Let Z be the empty string.
8. Let Z=Z || Trunc_r(S).
9. If d≤|Z|, then return Trunc_d (Z); else continue.
10. Let S=f(S), and continue with Step 8.

Размер буфера всегда 200 байт, b=1600 бит. 

*/
static inline void _pad(uint8_t *buf, uint8_t CS, int r, size_t len){
    buf[len] ^= CS;// 0x06 для HASH, 0x04 для cSHAKE128, 0x1F для XOF
    buf[r-1] ^= 0x80;
}
/*! \brief метод для впитывания байтовой строки в губку буфера состояния. 
    \param S - буфер состояния
    \param data - входные данные
    \param len - длина входных данных в байтах
 */
static void absorb(uint64x8_t *S, const uint8_t *data, unsigned int len){
    uint64x8_t v;
    int i;
    for (i=0; i<len/sizeof(uint64x8_t); i++){
        __builtin_memcpy(&v, data, sizeof(uint64x8_t));
        S[i] ^= v;
        data+=sizeof(uint64x8_t);
    }
    len = len%sizeof(uint64x8_t);
    if (len){
        v ^= v;
        __builtin_memcpy(&v, data, len);
        S[i] ^= v;
    }
}
/*! \brief SPONGE - губка для кодирования (absorb) байтовой строки и генерации (squeeze). 

    Метод KECCAK[c] использует функцию KECCAK-p[1600, 24] для кодирования и генерации. 
    \param data - входные данные
    \param len - длина входных данных в байтах
    \param tag - выходные данные
    \param d  - длина выходных данных
    \param CS - метка для кодирования байтовой строки 0x06 - для SHA3, 0x1F - для SHAKE, 00 - cSHAKE
    \param r - размер блока в байтах (b-c)/8
 */
static void _sponge(const uint8_t *data, size_t len, uint8_t *tag, int d, uint8_t CS, unsigned int r){
    //const unsigned int r = 168;
    __attribute__((aligned(64)))
    uint64x8_t S[256/(8*8)]={0};
    for (int i=0; i<len/r; i++, data+=r){// число целых блоков
        absorb(S, data, r);
        KeccakF1600((uint64_t*)S, 24);
    }
    if (len%r){
        absorb(S, data, len%r);
    }
    _pad((uint8_t*)S, CS, r, len%r);
    KeccakF1600((uint64_t*)S, 24);
    // отжим губки
    while (d>r) {
        __builtin_memcpy(tag, S, r);
        d -= r; tag += r;
        KeccakF1600((uint64_t*)S, 24);
    }
    __builtin_memcpy(tag, S, d);
	//__builtin_bzero (S, 200);
}
static void _absorb (uint64x8_t *S, unsigned int r, const uint8_t* data, unsigned int len, uint8_t CS){
    for (int i=0; i<len/r; i++, data+=r){// число целых блоков
        absorb(S, data, r);
        KeccakF1600((uint64_t*)S, 24);
    }
    if (len%r){
        absorb(S, data, len%r);
    }
    _pad((uint8_t*)S, CS, r, len%r);
    KeccakF1600((uint64_t*)S, 24);
}
static void _squeeze(uint64x8_t *S, unsigned int r, uint8_t* tag, unsigned int d){
    while (d>r) {
        __builtin_memcpy(tag, S, r);
        d -= r; tag += r;
        KeccakF1600((uint64_t*)S, 24);
    }
    __builtin_memcpy(tag, S, d);
}

typedef struct _XOF_ctx XOF_ctx_t;
struct _XOF_ctx {
    uint64x8_t S[256/64];
    unsigned int len; // длина сообщения в буфере
    unsigned int tlen;
};
XOF_ctx_t* XOF_init(XOF_ctx_t* ctx) {
    __builtin_bzero(ctx->S, 1600/64);
    ctx->len = 0;
    ctx->tlen = 0;
    return ctx;
}
void XOF_absorb(XOF_ctx_t* ctx, uint8_t* data, size_t len) {
    _absorb(ctx->S, 168, data, len, 0x1F);
}
uint8_t* XOF_squeeze(XOF_ctx_t* ctx, uint8_t* data, size_t len) {
    const unsigned int r = 168;
    if (ctx->tlen>= r) {
        ctx->tlen-= r; 
        KeccakF1600((uint64_t*)ctx->S, 24);
    }
    __builtin_memcpy(data, (uint8_t*)(ctx->S)+ctx->tlen, len);
    ctx->tlen += len;
    return data;
}

/*! \brief SHAKE-256 eXtendable Output Function 
    \param data - входные данные
    \param len - длина входных данных в байтах
    \param tag - выходные данные
    \param d - длина выходных данных в байтах
 */
void shake256(const uint8_t *data, size_t len, uint8_t *tag, int d){
    _sponge(data, len, tag, d, 0x1F, 136);
}
/*! \brief SHAKE-128 eXtendable Output Function 
    \param data - входные данные
    \param len - длина входных данных в байтах
    \param tag - выходные данные
    \param d - длина выходных данных в байтах
 */
void shake128(const uint8_t *data, size_t len, uint8_t *tag, int d){
    _sponge(data, len, tag, d, 0x1F, 168);
}
/*! \brief SHA3-224 Hash Function 
    \param data - входные данные
    \param len - длина входных данных в байтах
    \param tag - выходные данные 224 бит
 */
void sha3_224(const uint8_t *data, size_t len, uint8_t *tag){
    _sponge(data, len, tag, 224/8, 0x06, 144);
}
/*! \brief SHA3-256 Hash Function 
    \param data - входные данные
    \param len - длина входных данных в байтах
    \param tag - выходные данные 256 бит
 */
void sha3_256(const uint8_t *data, size_t len, uint8_t *tag){
    _sponge(data, len, tag, 256/8, 0x06, 136);
}
/*! \brief SHA3-512 Hash Function 
    \param data - входные данные
    \param len - длина входных данных в байтах
    \param tag - выходные данные 512 бит
 */
void sha3_512(const uint8_t *data, size_t len, uint8_t *tag){
    _sponge(data, len, tag, 512/8, 0x06, 72);
}
/*! \brief SHA3-384 Hash Function 
    \param data - входные данные
    \param len - длина входных данных в байтах
    \param tag - выходные данные 384 бит
 */
void sha3_384(const uint8_t *data, size_t len, uint8_t *tag){
    _sponge(data, len, tag, 384/8, 0x06, 104);
}
/*! \brief Кодирование числа в бинарный формат
    \param s - указатель на буфер записи
    \param len - число, не превышает 255
 */
static uint8_t * encode_left(uint8_t *s, unsigned int len){
    *s++ = 0x01;// число байт в кодировании числа
    *s++ = len & 0xff;
    return s;
}
/*! \brief Кодирование строк кастомизации в бинарный формат
    \param s - указатель на буфер записи
    \param cstr - строка кастомизации
    \param len - длина строки, не превышает 255 байт
    \return - указатель на следующий байт
 */
static uint8_t * encode_string(uint8_t *s, const char* cstr, unsigned int len){
    s = encode_left(s, len);// число байт в строке
    __builtin_memcpy(s, cstr, len);
    s += len;
    return s;
}
/*! \brief Кастомизированная SHAKE-256 
    \param data - входные данные
    \param len - длина входных данных в байтах
    \param tag - выходные данные XOF
    \param d - длина выходных данных в байтах
    \param name имя функции
    \param cstr customization string , длина name и cstr не превышает 132 байта
 */
void cshake256(uint8_t *data, size_t len, uint8_t *tag, int d, const char* name, const char* cstr){
	if ((name==NULL || name[0]=='\0') && (cstr==NULL || cstr[0]=='\0')) {
		shake256(data, len, tag, d);
	} else {
		const unsigned int r = 136;
	    __attribute__((aligned(64)))
		uint64x8_t S[256/(8*8)]={0};
        uint8_t* s = (uint8_t*)S;
        // кодирование шапки byte_encode(,136)
        s = encode_left(s, r);// число байт в шапке
        if (name)
            s = encode_string(s, name, strlen(name));
        if (cstr)
            s = encode_string(s, cstr, strlen(cstr));
        KeccakF1600((uint64_t*)S, 24);
	    _absorb (S, r, data, len, 0x00);
		_squeeze(S, r, tag, d);
	}
}

#if !defined(TEST_SHA3)
#include "hmac.h"
typedef struct _HashCtx HashCtx;
struct _HashCtx{
    uint64x8_t S[256/64];
    unsigned int len; // длина сообщения в буфере
};
static void sha3_init(HashCtx* ctx) {
    __builtin_bzero(ctx->S, 256);
    ctx->len = 0;
}
static void sha3_512_init(HashCtx* ctx) {
    __builtin_bzero(ctx->S, 256);
    ctx->len = 0;
}
static void absorb_bytes(uint64x8_t *S, unsigned int offs, const uint8_t *data, unsigned int len){
    uint64x8_t v;
    const unsigned int sz = sizeof(uint64x8_t);
    if (offs%sz) {
        v ^= v;
        unsigned l = sz - offs%sz;
        if (l>len) l = len;
        __builtin_memcpy(&v + offs%sz, data, l);
        S[offs/sz] ^= v;
        data += l;
        offs += l;
        len  -= l;
    }
    absorb(S + offs/sz, data, len);
}
static void sha3_224_update(HashCtx* ctx, const uint8_t* msg, unsigned int mlen) {
    const unsigned int r = 144;
    if (ctx->len){// дописать байты
    }
    for(int i=0; i<mlen/r; i++, msg+=r){
        absorb(ctx->S, msg, r);
        KeccakF1600((uint64_t*)ctx->S, 24);
    }
    if (mlen%r){
        absorb(ctx->S, msg, mlen%r);
        ctx->len += mlen%r;
    }
}
static void sha3_256_update(HashCtx* ctx, const uint8_t* msg, unsigned int mlen) {
    const unsigned int r = 136;
    if (ctx->len){// дописать байты
    }
    for(int i=0; i<mlen/r; i++, msg+=r){
        absorb(ctx->S, msg, r);
        KeccakF1600((uint64_t*)ctx->S, 24);
    }
    if (mlen%r){
        absorb(ctx->S, msg, mlen%r);
        ctx->len += mlen%r;
    }
}
static void sha3_384_update(HashCtx* ctx, const uint8_t* msg, unsigned int mlen) {
    const unsigned int r = 104;
    if (ctx->len){// дописать байты
    }
    for(int i=0; i<mlen/r; i++, msg+=r){
        absorb(ctx->S, msg, r);
        KeccakF1600((uint64_t*)ctx->S, 24);
    }
    if (mlen%r){
        absorb(ctx->S, msg, mlen%r);
        ctx->len += mlen%r;
    }
}
static void sha3_512_update(HashCtx* ctx, const uint8_t* msg, unsigned int mlen) {
    const unsigned int r = 72;
    if (ctx->len){// дописать байты
        if (mlen+ctx->len < r){
            absorb_bytes(ctx->S, ctx->len, msg, mlen);
            ctx->len += mlen;
            return;
        } else {
            unsigned int len = r -ctx->len;
            absorb_bytes(ctx->S, ctx->len, msg, len);
            KeccakF1600((uint64_t*)ctx->S, 24);
            ctx->len = 0; 
            msg += len; mlen -= len;
            if (mlen==0) return;
        }
    }
    for(int i=0; i<mlen/r; i++, msg+=r){
        absorb(ctx->S, msg, r);
        KeccakF1600((uint64_t*)ctx->S, 24);
    }
    if (mlen%r){
        absorb(ctx->S, msg, mlen%r);
        ctx->len += mlen%r;
    }
}

static void sha3_224_final(HashCtx* ctx, uint8_t* tag, unsigned int tlen) {
    _pad((uint8_t*)ctx->S, 0x06, 144, ctx->len);
    KeccakF1600((uint64_t*)ctx->S, 24);
    __builtin_memcpy(tag, ctx->S, tlen);
}
static void sha3_256_final(HashCtx* ctx, uint8_t* tag, unsigned int tlen) {
    _pad((uint8_t*)ctx->S, 0x06, 136, ctx->len);
    KeccakF1600((uint64_t*)ctx->S, 24);
    __builtin_memcpy(tag, ctx->S, tlen);
}
static void sha3_384_final(HashCtx* ctx, uint8_t* tag, unsigned int tlen) {
    _pad((uint8_t*)ctx->S, 0x06, 104, ctx->len);
    KeccakF1600((uint64_t*)ctx->S, 24);
    __builtin_memcpy(tag, ctx->S, tlen);
}
static void sha3_512_final(HashCtx* ctx, uint8_t* tag, unsigned int tlen) {
    _pad((uint8_t*)ctx->S, 0x06, 72, ctx->len);
    KeccakF1600((uint64_t*)ctx->S, 24);
    __builtin_memcpy(tag, ctx->S, tlen);
}

MESSAGE_DIGEST(MD_SHA3_224) {
    .id = MD_SHA3_224,
    .name = "SHA3-224",
    .block_len = 144,//64,
    .hash_len = 224/8,
    .ctx_size = sizeof(HashCtx),
    .init   = (void*)sha3_init,
    .update = (void*)sha3_224_update,
    .final  = (void*)sha3_224_final,
};
MESSAGE_DIGEST(MD_SHA3_256) {
    .id = MD_SHA3_256,
    .name = "SHA3-256",
    .block_len = 136,//64,
    .hash_len = 32,
    .ctx_size = sizeof(HashCtx),
    .init   = (void*)sha3_init,
    .update = (void*)sha3_256_update,
    .final  = (void*)sha3_256_final,
};
MESSAGE_DIGEST(MD_SHA3_384) {
    .id = MD_SHA3_384,
    .name = "SHA3-384",
    .block_len = 104,
    .hash_len = 384/8,
    .ctx_size = sizeof(HashCtx),
    .init   = (void*)sha3_init,
    .update = (void*)sha3_384_update,
    .final  = (void*)sha3_384_final,
};
MESSAGE_DIGEST(MD_SHA3_512) {
    .id = MD_SHA3_512,
    .name = "SHA3-512",
    .block_len = 72,//64,
    .hash_len = 64,
    .ctx_size = sizeof(HashCtx),
    .init   = (void*)sha3_512_init,
    .update = (void*)sha3_512_update,
    .final  = (void*)sha3_512_final,
};
#endif
#ifdef TEST_SHA3 
static uint64_t rc(int t){
    if ((t%255)==0) return 1;
    uint8_t r = 0x01;
    for (int i=0; i<t%255; i++){
        r = (r<<1)|(r>>7);
        if (r&1) r ^= 0x70;
    }
    return r&1;
}
#include <stdio.h>
static void print_hash(const char* title, uint8_t* tag, int len);

/* Синтез алгоритма KECCAK-p[1600, 24]
 C[x] = A[x, 0] ⊕ A[x, 1] ⊕ A[x, 2] ⊕ A[x, 3] ⊕ A[x, 4], x = 0…4;
 D[x] = C[x — 1] ⊕ (С[x + 1] >>> 1), x = 0…4;
 A[x, y] = A[x, y] ⊕ D[x],           x = 0…4, y = 0…4;
 // cдвиг и транспонирование 5x5:
 B[y, 2x + 3y] = A[x, y] >>> r[x, y], x = 0…4, y = 0…4;
 A[x, y] = B[x, y] ⊕ (~B[x + 1, y] & B[x + 2, y]), x = 0…4, y = 0…4, 

*/
int main(int argc, char** argv)
{// Генерация алгоритма KECCAK-p[1600, Nr = 24] = Keccak-f[5*5*w]
    const int Nr=24;
    const int ell=5;
    const int w = 1u<<ell;// разрядность 2^{\ell}
    // генерация RC констант для номера раунда ir = 0..23, w = 64
    if (1) for (int ir=0; ir<Nr; ir++){
        uint64_t RC = 0;
        for (int i=0; i<=ell; i++){// w = 64 = (1<<6) \ell=6
            //printf("%d:RC[%d] = %02x\n", ir, (1<<i)-1, rc(i+7*ir));
            RC |= rc(i+7*ir)<<((1<<i)-1);
        }
        if (ell==6)
            printf("RC[%d] = 0x%016llxuLL\n", ir, RC);
        else
            printf("RC[%d] = 0x%08llxuL\n", ir, RC);
    }

    int x=1, y=0, s;
    printf("// theta:\n");
    for (int x=0; x<5; x++)
        printf("\tC[%d] = A0[%d] ^ A1[%d] ^ A2[%d] ^ A3[%d] ^ A4[%d];\n", x, x, x, x, x, x);
    printf("\n");
    for (int x=0; x<5; x++)
        printf("\tD[%d] = C[%d] ^ ROTR(C[%x], 1);\n", x, (x-1+5)%5, (x+1)%5);
    printf("// rho:\n");
    for (int t=0; t<24; t++){
        s = -(t+1)*(t+2)/2;
        s = s % w;
        if (s<0) s+=w;
        printf("\tB%d[%d] = ROTR(A%d[%d]^D[%d], %d);\n", y, x, y, x, x, s);
        s = y;
        y = (2*x+3*y) % 5;
        x = s;
    }
    y =0, x=0, s=0;
    printf("\tB%d[%d] = ROTR(A%d[%d]^D[%d], %d);\n", y, x, y, x, x, s);
    printf("// pi:\n");
// A′[x, y, z]=A[(x + 3y) mod 5, x, z].
    for (int x=0; x<5; x++){
        for (int y=0; y<5; y++){
            //printf("\tA%d[%d] = r[%d][%d];\n", y, x, x, (3*y+x)%5);
            printf("%d, ", (3*y+x)%5);
        }
        printf("\n");
    }
    for (int y=0; y<5; y++)
    for (int x=0; x<5; x++)
            printf("\tA%d[%d] = B%d[%d];\n", y, x, x, (3*y+x)%5);

// A′[x, y,z] = A[x, y,z] ⊕ ((A[(x+1) mod 5, y, z] ⊕ 1) ⋅ A[(x+2) mod 5, y, z]).
    printf("// xi:\n");
    for (int y=0; y<5; y++){
        for (int x=0; x<5; x++){
            printf("\tA%d[%d] = A%d[%d] ^ (~A%d[%d] & A%d[%d]);\n", y, x, y, x, y, (x+1)%5, y, (x+2)%5);
        }
    }

    uint64_t S[25] = {// SHA3-512("",0)
        0x0000000000000006, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 
        0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 
        0x8000000000000000, 
    };
    KeccakF1600((uint64_t*)S, 24);
    unsigned tlen = 512;
    uint8_t tag[512];
    shake256((uint8_t*)"", 0, tag, tlen); 
    print_hash("SHAKE256 XOF(512)", tag, tlen);
    // valid tag
    // 46 B9 DD ... 3E EB 24
    // 1F D1 66 ... E2 7F 2A
    printf("\n");
    shake128((uint8_t*)"", 0, tag, tlen); 
    print_hash("SHAKE128 XOF(512)", tag, tlen);
    // valid 
    // 7F 9C 2B ... 05 85 3E
    // DD A2 52 ... 29 0B 6F
    sha3_224((uint8_t*)"", 0, tag); 
    print_hash("SHA3-224 Hash(0)", tag, 224/8);
/* Hash val is */
	uint8_t test_sha3_224_0[] = {
    0x6B, 0x4E, 0x03, 0x42, 0x36, 0x67, 0xDB, 0xB7, 0x3B, 0x6E, 0x15, 0x45, 0x4F, 0x0E, 0xB1, 0xAB,
	0xD4, 0x59, 0x7F, 0x9A, 0x1B, 0x07, 0x8E, 0x3F, 0x5B, 0x5A, 0x6B, 0xC7};
	if (__builtin_memcmp(test_sha3_224_0, tag, 224/8)==0) printf("..ok\n");
    sha3_256((uint8_t*)"", 0, tag); 
    print_hash("SHA3-256 Hash(0)", tag, 256/8);
/* Hash val is */
	uint8_t test_sha3_256_0[] = {
    0xA7, 0xFF, 0xC6, 0xF8, 0xBF, 0x1E, 0xD7, 0x66, 0x51, 0xC1, 0x47, 0x56, 0xA0, 0x61, 0xD6, 0x62,
	0xF5, 0x80, 0xFF, 0x4D, 0xE4, 0x3B, 0x49, 0xFA, 0x82, 0xD8, 0x0A, 0x4B, 0x80, 0xF8, 0x43, 0x4A};
	if (__builtin_memcmp(test_sha3_256_0, tag, 256/8)==0) printf("..ok\n");
    sha3_384((uint8_t*)"", 0, tag); 
    print_hash("SHA3-384 Hash(0)", tag, 384/8);
/* Hash val is */
	uint8_t test_sha3_384_0[] = {
    0x0C, 0x63, 0xA7, 0x5B, 0x84, 0x5E, 0x4F, 0x7D, 0x01, 0x10, 0x7D, 0x85, 0x2E, 0x4C, 0x24, 0x85,
    0xC5, 0x1A, 0x50, 0xAA, 0xAA, 0x94, 0xFC, 0x61, 0x99, 0x5E, 0x71, 0xBB, 0xEE, 0x98, 0x3A, 0x2A,
    0xC3, 0x71, 0x38, 0x31, 0x26, 0x4A, 0xDB, 0x47, 0xFB, 0x6B, 0xD1, 0xE0, 0x58, 0xD5, 0xF0, 0x04};
	if (__builtin_memcmp(test_sha3_384_0, tag, 384/8)==0) printf("..ok\n");
    sha3_512((uint8_t*)"", 0, tag); 
    print_hash("SHA3-512 Hash(0)", tag, 512/8);
/* Hash val is */
	uint8_t test_sha3_512_0[] = {
	0xA6, 0x9F, 0x73, 0xCC, 0xA2, 0x3A, 0x9A, 0xC5, 0xC8, 0xB5, 0x67, 0xDC, 0x18, 0x5A, 0x75, 0x6E,
    0x97, 0xC9, 0x82, 0x16, 0x4F, 0xE2, 0x58, 0x59, 0xE0, 0xD1, 0xDC, 0xC1, 0x47, 0x5C, 0x80, 0xA6,
    0x15, 0xB2, 0x12, 0x3A, 0xF1, 0xF5, 0xF9, 0x4C, 0x11, 0xE3, 0xE9, 0x40, 0x2C, 0x3A, 0xC5, 0x58,
    0xF5, 0x00, 0x19, 0x9D, 0x95, 0xB6, 0xD3, 0xE3, 0x01, 0x75, 0x85, 0x86, 0x28, 0x1D, 0xCD, 0x26};
	if (__builtin_memcmp(test_sha3_512_0, tag, 512/8)==0) printf("..ok\n");
    uint8_t dataA3[1600/8] = { [0 ... 199]= 0xA3};
    sha3_224(dataA3, 1600/8, tag); 
    print_hash("SHA3-224 Hash(1600/8)", tag, 224/8);
/* Hash val is */
	uint8_t test_sha3_224_1600[] = {
    0x93, 0x76, 0x81, 0x6A, 0xBA, 0x50, 0x3F, 0x72, 0xF9, 0x6C, 0xE7, 0xEB, 0x65, 0xAC, 0x09, 0x5D,
    0xEE, 0xE3, 0xBE, 0x4B, 0xF9, 0xBB, 0xC2, 0xA1, 0xCB, 0x7E, 0x11, 0xE0};
	if (__builtin_memcmp(test_sha3_224_1600, tag, 224/8)==0) printf("..ok\n");
    sha3_256(dataA3, 1600/8, tag); 
    print_hash("SHA3-256 Hash(1600/8)", tag, 256/8);
/* Hash val is */
	uint8_t test_sha3_256_1600[] = {
    0x79, 0xF3, 0x8A, 0xDE, 0xC5, 0xC2, 0x03, 0x07, 0xA9, 0x8E, 0xF7, 0x6E, 0x83, 0x24, 0xAF, 0xBF,
    0xD4, 0x6C, 0xFD, 0x81, 0xB2, 0x2E, 0x39, 0x73, 0xC6, 0x5F, 0xA1, 0xBD, 0x9D, 0xE3, 0x17, 0x87};
	if (__builtin_memcmp(test_sha3_256_1600, tag, 256/8)==0) printf("..ok\n");
    sha3_384(dataA3, 1600/8, tag); 
    print_hash("SHA3-384 Hash(1600/8)", tag, 384/8);
/* Hash val is  */
	uint8_t test_sha3_384_1600[] = {
    0x18, 0x81, 0xDE, 0x2C, 0xA7, 0xE4, 0x1E, 0xF9, 0x5D, 0xC4, 0x73, 0x2B, 0x8F, 0x5F, 0x00, 0x2B,
    0x18, 0x9C, 0xC1, 0xE4, 0x2B, 0x74, 0x16, 0x8E, 0xD1, 0x73, 0x26, 0x49, 0xCE, 0x1D, 0xBC, 0xDD,
	0x76, 0x19, 0x7A, 0x31, 0xFD, 0x55, 0xEE, 0x98, 0x9F, 0x2D, 0x70, 0x50, 0xDD, 0x47, 0x3E, 0x8F};
	if (__builtin_memcmp(test_sha3_384_1600, tag, 384/8)==0) printf("..ok\n");
    sha3_512(dataA3, 1600/8, tag); 
    print_hash("SHA3-512 Hash(1600/8)", tag, 512/8);
/* Hash val is  */
	uint8_t test_sha3_512_1600[] = {
    0xE7, 0x6D, 0xFA, 0xD2, 0x20, 0x84, 0xA8, 0xB1, 0x46, 0x7F, 0xCF, 0x2F, 0xFA, 0x58, 0x36, 0x1B,
    0xEC, 0x76, 0x28, 0xED, 0xF5, 0xF3, 0xFD, 0xC0, 0xE4, 0x80, 0x5D, 0xC4, 0x8C, 0xAE, 0xEC, 0xA8,
    0x1B, 0x7C, 0x13, 0xC3, 0x0A, 0xDF, 0x52, 0xA3, 0x65, 0x95, 0x84, 0x73, 0x9A, 0x2D, 0xF4, 0x6B,
    0xE5, 0x89, 0xC5, 0x1C, 0xA1, 0xA4, 0xA8, 0x41, 0x6D, 0xF6, 0x54, 0x5A, 0x1C, 0xE8, 0xBA, 0x00};
	if (__builtin_memcmp(test_sha3_512_1600, tag, 512/8)==0) printf("..ok\n");
    return 0;
}
static void print_hash(const char* title, uint8_t* tag, int len){
    printf("%s:\n", title);
    int i;
    for (i=0; i<len; i++) {
        printf("%02X ", tag[i]);
        if (i%16==15) printf("\n");
    }
    if (i%16) printf("\n");
}
#endif
