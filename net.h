#ifndef NET_H
#define NET_H

#include <stdint.h>
/* Сетевой порядок октетов (big-endian) ↔ host.
   Единое место Security: ntoh* / hton* / ntohll / htonll.
   В R3-lib/r3_runtime.h — те же операции как _ntoh* / _hton* (стиль runtime).
 */

#if defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
static inline uint64_t ntohll(uint64_t a){ return __builtin_bswap64(a); }
static inline uint64_t htonll(uint64_t a){ return __builtin_bswap64(a); }
static inline uint32_t ntohl (uint32_t a){ return __builtin_bswap32(a); }
static inline uint32_t htonl (uint32_t a){ return __builtin_bswap32(a); }
static inline uint16_t ntohs (uint16_t a){ return __builtin_bswap16(a); }
static inline uint16_t htons (uint16_t a){ return __builtin_bswap16(a); }
#else
static inline uint64_t ntohll(uint64_t a){ return (a); }
static inline uint64_t htonll(uint64_t a){ return (a); }
static inline uint32_t ntohl (uint32_t a){ return (a); }
static inline uint32_t htonl (uint32_t a){ return (a); }
static inline uint16_t ntohs (uint16_t a){ return (a); }
static inline uint16_t htons (uint16_t a){ return (a); }
#endif
#endif /* NET_H */
