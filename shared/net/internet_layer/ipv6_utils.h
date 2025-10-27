#pragma once
#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    IPV6_MCAST_SOLICITED_NODE = 0,
    IPV6_MCAST_ALL_NODES= 1,
    IPV6_MCAST_ALL_ROUTERS = 2
} ipv6_mcast_kind_t;

bool ipv6_is_unspecified(const uint8_t ip[16]);
bool ipv6_is_loopback(const uint8_t ip[16]);
bool ipv6_is_multicast(const uint8_t ip[16]);
bool ipv6_is_ula(const uint8_t ip[16]);
bool ipv6_is_linklocal(const uint8_t ip[16]);
int ipv6_cmp(const uint8_t a[16], const uint8_t b[16]);
void ipv6_cpy(uint8_t dst[16], const uint8_t src[16]);
int ipv6_common_prefix_len(const uint8_t a[16], const uint8_t b[16]);
void ipv6_make_multicast(uint8_t scope, ipv6_mcast_kind_t kind, const uint8_t unicast[16], uint8_t out[16]);
void ipv6_to_string(const uint8_t ip[16], char* buf, int buflen);
bool ipv6_parse(const char* s, uint8_t out[16]);
void ipv6_multicast_mac(const uint8_t ip[16], uint8_t mac[6]);

#ifdef __cplusplus
}
#endif
