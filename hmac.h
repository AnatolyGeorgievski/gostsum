#ifndef HMAC_H
#define HMAC_H
#include <inttypes.h>
typedef struct _MDCtx MDigest;
struct _MDCtx {
    int id;
    const char* name;
    const unsigned int block_len;// размер блока для функции HMAC
    const unsigned int hash_len;// длина хеша
    const unsigned int ctx_size;// длина хеша
    void (*init  )(void* ctx);
    void (*update)(void* ctx, const void* msg, unsigned int mlen);
    void (*final )(void* ctx,       void* tag, unsigned int tlen);
};

enum {
    MD_NONE=0,
    MD_MD5,
    MD_SHA1,
    MD_SHA224,
    MD_SHA256,
    MD_SHA384,
    MD_SHA512,
    MD_SHA512_224,
    MD_SHA512_256,
    MD_GOSTR341194_CP,
    MD_GOSTR341194,
    MD_STRIBOG_256,// GOST R 34.11-2012
    MD_STRIBOG_512,// GOST R 34.11-2012(512)
    MD_BLAKE2S,
    MD_BLAKE2B,
};

#define MESSAGE_DIGEST(id) \
    static const MDigest id##_digest;\
    static void __attribute__((constructor)) id##_reg(){ digest_register(&id##_digest); }\
    static const MDigest id##_digest =

void digest_register(const MDigest* );
const MDigest* digest_select(int id);
void digest(const MDigest* md, uint8_t * tag, unsigned int tlen, const uint8_t * msg, unsigned int mlen);
int  digest_verify(const MDigest* md, const uint8_t * tag, unsigned int tlen, const uint8_t * msg, unsigned int mlen);
void hmac       (const MDigest* md, uint8_t * tag, unsigned int tlen, const uint8_t * msg, unsigned int mlen, const uint8_t * key, unsigned int klen);
void pbkdf2_hmac(const MDigest* md, void* dk, unsigned int dklen, const uint8_t *passwd, unsigned int plen,
                      const uint8_t *salt, unsigned int slen, unsigned int c);
void pbkdf1(const MDigest* md, uint8_t *dk, int dklen, int id, const uint8_t* passwd, unsigned int plen,
                      const uint8_t* salt, unsigned int slen, unsigned int c);
/*
void pbkdf1     (const MDigest* md, void* dk, unsigned int dklen, const uint8_t *passwd, unsigned int plen,
                      const uint8_t *salt, unsigned int slen, unsigned int c);
*/
void ssha(const MDigest* md, uint8_t * tag, unsigned int tlen, const uint8_t * msg, unsigned int mlen, const uint8_t * salt, unsigned int slen);
#endif // HMAC_H
