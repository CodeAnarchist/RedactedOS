#include "interface_manager.h"
#include "std/memory.h"
#include "net/link_layer/arp.h"
#include "net/internet_layer/ipv4_route.h"
#include "networking/port_manager.h"
#include "process/scheduler.h"
#include "memory/page_allocator.h"
#include "net/internet_layer/ipv4_utils.h"
#include "net/internet_layer/ipv6_utils.h"

static void* g_kmem_page = NULL;

static l2_interface_t g_l2[MAX_L2_INTERFACES];
static uint8_t g_l2_used[MAX_L2_INTERFACES];
static uint8_t g_l2_count = 0;

typedef struct {
    l3_ipv4_interface_t node;
    bool used;
    uint8_t slot_in_l2;
} v4_slot_t;
typedef struct {
    l3_ipv6_interface_t node;
    bool used;
    uint8_t slot_in_l2;
} v6_slot_t;

#define V4_POOL_SIZE (MAX_L2_INTERFACES * MAX_IPV4_PER_INTERFACE)
#define V6_POOL_SIZE (MAX_L2_INTERFACES * MAX_IPV6_PER_INTERFACE)

static v4_slot_t g_v4[V4_POOL_SIZE];
static v6_slot_t g_v6[V6_POOL_SIZE];

static inline int l2_slot_from_ifindex(uint8_t ifindex){
    if (!ifindex) return -1;
    int s = (int)ifindex - 1;
    if (s<0 || s>=(int)MAX_L2_INTERFACES) return -1;
    if (!g_l2_used[s]) return -1;
    return s;
}
static inline uint8_t make_l3_id(uint8_t ifindex, uint8_t local_slot){ return (uint8_t)((ifindex<<4) | (local_slot & 0x0F)); }
static inline uint8_t l3_ifindex_from_id(uint8_t l3_id){ return (uint8_t)((l3_id >> 4) & 0x0F); }
static inline uint8_t l3_local_slot_from_id(uint8_t l3_id){ return (uint8_t)(l3_id & 0x0F); }

static bool v4_has_dhcp_on_l2(uint8_t ifindex){
    for (int i = 0; i < V4_POOL_SIZE; i++){
        if (!g_v4[i].used) continue;
        l3_ipv4_interface_t *x = &g_v4[i].node;
        if (!x->l2) continue;
        if (x->l2->ifindex != ifindex) continue;
        if (x->mode == IPV4_CFG_DHCP) return true;
    }
    return false;
}

uint8_t l2_interface_create(const char *name, void *driver_ctx, uint16_t base_metric){
    int slot = -1;
    for (int i=0;i<(int)MAX_L2_INTERFACES;i++) if (!g_l2_used[i]) {
        slot=i;
        break;
    }
    if (slot < 0) return 0;

    l2_interface_t* itf = &g_l2[slot];
    memset(itf, 0, sizeof(*itf));
    itf->ifindex = (uint8_t)(slot + 1);

    int i = 0;
    if (name) {
        while (name[i] && i < 15) {
            itf->name[i] = name[i];
            i++;
        }
    }
    itf->name[i] = 0;

    itf->driver_context = driver_ctx;
    itf->base_metric = base_metric;
    itf->arp_table = arp_table_create();
    itf->nd_table = NULL;

    g_l2_used[slot] = 1;
    g_l2_count += 1;
    return itf->ifindex;
}

bool l2_interface_destroy(uint8_t ifindex){
    int slot = l2_slot_from_ifindex(ifindex);
    if (slot < 0) return false;
    l2_interface_t* itf = &g_l2[slot];
    if (itf->ipv4_count || itf->ipv6_count) return false;

    if (itf->arp_table) { arp_table_destroy((arp_table_t*)itf->arp_table); itf->arp_table = NULL; }

    memset(&g_l2[slot], 0, sizeof(l2_interface_t));
    g_l2_used[slot] = 0;
    if (g_l2_count) g_l2_count -= 1;
    return true;
}

l2_interface_t* l2_interface_find_by_index(uint8_t ifindex) {
    int slot = l2_slot_from_ifindex(ifindex);
    if (slot < 0) return 0;
    return &g_l2[slot];
}

uint8_t l2_interface_count(void) { return g_l2_count; }

l2_interface_t* l2_interface_at(uint8_t idx) {
    uint8_t seen = 0;
    for (int i=0;i<(int)MAX_L2_INTERFACES;i++){
        if (!g_l2_used[i]) continue;
        if (seen == idx) return &g_l2[i];
        seen++;
    }
    return 0;
}

bool l2_interface_set_up(uint8_t ifindex, bool up) {
    l2_interface_t* itf = l2_interface_find_by_index(ifindex);
    if (!itf) return false;
    itf->is_up = up;
    return true;
}

static int find_ipv4_group_index(l2_interface_t* itf, uint32_t group) {
    for (int i = 0; i < (int)itf->ipv4_mcast_count; ++i) if (itf->ipv4_mcast[i] == group) return i;
    return -1;
}

bool l2_ipv4_mcast_join(uint8_t ifindex, uint32_t group) {
    l2_interface_t* itf = l2_interface_find_by_index(ifindex);
    if (!itf) return false;
    if (!ipv4_is_multicast(group)) return false;
    if (find_ipv4_group_index(itf, group) >= 0) return true;
    if (itf->ipv4_mcast_count >= MAX_IPV4_MCAST_PER_INTERFACE) return false;
    itf->ipv4_mcast[itf->ipv4_mcast_count++] = group;
    return true;
}

bool l2_ipv4_mcast_leave(uint8_t ifindex, uint32_t group) {
    l2_interface_t* itf = l2_interface_find_by_index(ifindex);
    if (!itf) return false;
    int idx = find_ipv4_group_index(itf, group);
    if (idx < 0) return true;
    for (int i = idx + 1; i < (int)itf->ipv4_mcast_count; ++i) itf->ipv4_mcast[i-1] = itf->ipv4_mcast[i];
    if (itf->ipv4_mcast_count) itf->ipv4_mcast_count -= 1;
    return true;
}

static int find_ipv6_group_index(l2_interface_t* itf, const uint8_t group[16]) {
    for (int i = 0; i < (int)itf->ipv6_mcast_count; ++i) if (ipv6_cmp(itf->ipv6_mcast[i], group) == 0) return i;
    return -1;
}
bool l2_ipv6_mcast_join(uint8_t ifindex, const uint8_t group[16]) {
    l2_interface_t* itf = l2_interface_find_by_index(ifindex);
    if (!itf || !group) return false;
    if (!ipv6_is_multicast(group)) return false;
    if (find_ipv6_group_index(itf, group) >= 0) return true;
    if (itf->ipv6_mcast_count >= MAX_IPV6_MCAST_PER_INTERFACE) return false;
    ipv6_cpy(itf->ipv6_mcast[itf->ipv6_mcast_count], group);
    itf->ipv6_mcast_count += 1;
    return true;
}
bool l2_ipv6_mcast_leave(uint8_t ifindex, const uint8_t group[16]) {
    l2_interface_t* itf = l2_interface_find_by_index(ifindex);
    if (!itf || !group) return false;
    int idx = find_ipv6_group_index(itf, group);
    if (idx < 0) return true;
    for (int i = idx + 1; i < (int)itf->ipv6_mcast_count; ++i) ipv6_cpy(itf->ipv6_mcast[i-1], itf->ipv6_mcast[i]);
    if (itf->ipv6_mcast_count) itf->ipv6_mcast_count -= 1;
    return true;
}

static bool v4_ip_exists_anywhere(uint32_t ip){
    for (int i=0;i<V4_POOL_SIZE;i++){ if (g_v4[i].used && g_v4[i].node.ip == ip) return true; }
    return false;
}

static bool v4_overlap_intra_l2(uint8_t ifindex, uint32_t ip, uint32_t mask){
    if (!ipv4_mask_is_contiguous(mask)) return true;
    for (int i=0;i<V4_POOL_SIZE;i++){
        if (!g_v4[i].used) continue;
        l3_ipv4_interface_t *x = &g_v4[i].node;
        if (!x->l2 || x->l2->ifindex != ifindex) continue;
        if (x->mode == IPV4_CFG_DISABLED) continue;
        uint32_t m = (x->mask==0)?mask:((mask==0)?x->mask:((x->mask < mask)?x->mask:mask));
        if (ipv4_net(ip, m) == ipv4_net(x->ip, m)) return true;
    }
    return false;
}

static bool v6_ip_exists_anywhere(const uint8_t ip[16]){
    if (ipv6_is_unspecified(ip)) return false;
    for (int i=0;i<V6_POOL_SIZE;i++) {
        if (g_v6[i].used && ipv6_cmp(g_v6[i].node.ip, ip)==0) return true;
    }
    return false;
}

static bool v6_overlap_intra_l2(uint8_t ifindex, const uint8_t ip[16], uint8_t prefix_len){
    if (ipv6_is_unspecified(ip)) return false;
    for (int i=0;i<V6_POOL_SIZE;i++){
        if (!g_v6[i].used) continue;
        l3_ipv6_interface_t *x = &g_v6[i].node;
        if (!x->l2 || x->l2->ifindex != ifindex) continue;
        if (x->cfg == IPV6_CFG_DISABLE) continue;
        if (ipv6_is_unspecified(x->ip)) continue;
        uint8_t minp = (x->prefix_len < prefix_len) ? x->prefix_len : prefix_len;
        int eq = 1;
        int fb = minp/8, rb = minp%8;
        for (int b=0;b<fb;b++){ if (ip[b]!=x->ip[b]) {eq=0;break;} }
        if (eq && rb){
            uint8_t m=(uint8_t)(0xFF<<(8-rb));
            if ( (ip[fb]&m) != (x->ip[fb]&m) ) eq=0;
        }
        if (eq) return true;
    }
    return false;
}

uint8_t l3_ipv4_add_to_interface(uint8_t ifindex, uint32_t ip, uint32_t mask, uint32_t gw, ipv4_cfg_t mode, net_runtime_opts_t *runtime_opts){
    l2_interface_t *l2 = l2_interface_find_by_index(ifindex);
    if (!l2) return 0;
    if (mode == IPV4_CFG_DHCP) {
        if (v4_has_dhcp_on_l2(ifindex)) {
            return 0;
        }
    }
    if (mode == IPV4_CFG_STATIC){
        if (ipv4_is_unspecified(ip)) return 0;
        if (!ipv4_mask_is_contiguous(mask)) return 0;
        if (ipv4_is_loopback(ip) && !(l2->name[0]=='l' && l2->name[1]=='o')) return 0;
        if (ipv4_is_multicast(ip)) return 0;
        if (ipv4_is_reserved_special(ip)) return 0;
        if (ipv4_is_network_address(ip, mask)) return 0;
        if (ipv4_is_broadcast_address(ip, mask)) return 0;
        if (v4_ip_exists_anywhere(ip)) return 0;
        if (v4_overlap_intra_l2(ifindex, ip, mask)) return 0;
    }
    if (l2->ipv4_count >= MAX_IPV4_PER_INTERFACE) return 0;

    int loc = -1;
    for (int s=0; s<MAX_IPV4_PER_INTERFACE; s++) if (l2->l3_v4[s] == NULL) {
        loc = s;
        break;
    }
    int g = -1;
    for (int i=0;i<V4_POOL_SIZE;i++) if (!g_v4[i].used) {
        g = i;
        break;
    }
    if (loc < 0 || g < 0) return 0;

    g_v4[g].used = true;
    g_v4[g].slot_in_l2 = (uint8_t)loc;

    l3_ipv4_interface_t *n = &g_v4[g].node;
    memset(n, 0, sizeof(*n));
    n->l2 = l2;
    n->mode = mode;
    n->ip = (mode==IPV4_CFG_STATIC) ? ip : 0;
    n->mask = (mode==IPV4_CFG_STATIC) ? mask : 0;
    n->gw = (mode==IPV4_CFG_STATIC) ? gw : 0;
    n->broadcast = (mode==IPV4_CFG_STATIC) ? ipv4_broadcast_calc(ip, mask) : 0;

    memset(&n->runtime_opts_v4, 0, sizeof(n->runtime_opts_v4));
    if (runtime_opts) n->runtime_opts_v4 = *runtime_opts;

    n->routing_table = ipv4_rt_create();
    if (!n->routing_table) {
        g_v4[g].used = false;
        memset(&g_v4[g], 0, sizeof(g_v4[g]));
        return 0;
    }
    ipv4_rt_ensure_basics((ipv4_rt_table_t*)n->routing_table, n->ip, n->mask, n->gw, l2->base_metric);

    n->is_localhost = (l2->name[0]=='l' && l2->name[1]=='o');
    n->l3_id = make_l3_id(l2->ifindex, (uint8_t)loc);
    l2->l3_v4[loc] = n;
    l2->ipv4_count++;

    if (!g_kmem_page) g_kmem_page = palloc(PAGE_SIZE, MEM_PRIV_KERNEL, MEM_RW | MEM_NORM, false);
    n->port_manager = (port_manager_t*)kalloc(g_kmem_page, sizeof(port_manager_t), ALIGN_16B, MEM_PRIV_KERNEL);
    if (!n->port_manager) {
        l2->l3_v4[loc] = NULL;
        if (l2->ipv4_count) l2->ipv4_count--;
        ipv4_rt_destroy((ipv4_rt_table_t*)n->routing_table);
        n->routing_table = NULL;
        g_v4[g].used = false;
        memset(&g_v4[g], 0, sizeof(g_v4[g]));
        return 0;
    }
    port_manager_init(n->port_manager);

    return n->l3_id;
}

bool l3_ipv4_update(uint8_t l3_id, uint32_t ip, uint32_t mask, uint32_t gw, ipv4_cfg_t mode, net_runtime_opts_t *runtime_opts){
    l3_ipv4_interface_t *n = l3_ipv4_find_by_id(l3_id);
    if (!n) return false;
    l2_interface_t *l2 = n->l2;
    if (!l2) return false;
    if (mode == IPV4_CFG_DHCP && n->mode != IPV4_CFG_DHCP) {
        if (v4_has_dhcp_on_l2(l2->ifindex)) return false;
    }
    if (mode == IPV4_CFG_STATIC){
        if (ipv4_is_unspecified(ip)) return false;
        if (!ipv4_mask_is_contiguous(mask)) return false;
        if (ipv4_is_loopback(ip) && !(l2->name[0]=='l' && l2->name[1]=='o')) return false;
        if (ipv4_is_multicast(ip)) return false;
        if (ipv4_is_reserved_special(ip)) return false;
        if (ipv4_is_network_address(ip, mask)) return false;
        if (ipv4_is_broadcast_address(ip, mask)) return false;
        if (ip != n->ip && v4_ip_exists_anywhere(ip)) return false;
        for (int i = 0; i < V4_POOL_SIZE; i++){
            if (!g_v4[i].used) continue;
            l3_ipv4_interface_t *x = &g_v4[i].node;
            if (x==n) continue;
            if (!x->l2 || x->l2->ifindex != l2->ifindex) continue;
            if (x->mode == IPV4_CFG_DISABLED) continue;
            uint32_t m = (x->mask < mask) ? x->mask : mask;
            if (ipv4_net(ip, m) == ipv4_net(x->ip, m)) return false;
        }
    }

    n->mode = mode;

    if (runtime_opts) n->runtime_opts_v4 = *runtime_opts;

    if (mode == IPV4_CFG_STATIC || mode == IPV4_CFG_DHCP) {
        n->ip = ip;
        n->mask = mask;
        n->gw = gw;
        n->broadcast = ipv4_broadcast_calc(ip, mask);
    } else {
        n->ip = 0;
        n->mask = 0;
        n->gw = 0;
        n->broadcast = 0;
    }

    if (!n->routing_table) n->routing_table = ipv4_rt_create();
    ipv4_rt_sync_basics((ipv4_rt_table_t*)n->routing_table, n->ip, n->mask, n->gw, l2->base_metric);
    return true;
}

bool l3_ipv4_remove_from_interface(uint8_t l3_id){
    l3_ipv4_interface_t *n = l3_ipv4_find_by_id(l3_id);
    if (!n) return false;
    l2_interface_t *l2 = n->l2;
    if (!l2) return false;
    if (l2->ipv4_count <= 1) return false;

    int g = -1;
    for (int i=0;i<V4_POOL_SIZE;i++){
        if (g_v4[i].used && &g_v4[i].node == n){ g = i; break; }
    }
    if (g < 0) return false;

    if (n->port_manager) {
        kfree(n->port_manager, sizeof(port_manager_t));
        n->port_manager = NULL;
    }

    uint8_t slot = l3_local_slot_from_id(l3_id);
    if (slot < MAX_IPV4_PER_INTERFACE && l2->l3_v4[slot] == n){
        l2->l3_v4[slot] = NULL;
        if (l2->ipv4_count) l2->ipv4_count--;
    }

    if (n->routing_table) {
        ipv4_rt_destroy((ipv4_rt_table_t*)n->routing_table);
        n->routing_table = 0;
    }

    g_v4[g].used = false;
    memset(&g_v4[g], 0, sizeof(g_v4[g]));
    return true;
}

l3_ipv4_interface_t* l3_ipv4_find_by_id(uint8_t l3_id){
    uint8_t ifx = l3_ifindex_from_id(l3_id);
    uint8_t loc = l3_local_slot_from_id(l3_id);
    l2_interface_t *l2 = l2_interface_find_by_index(ifx);
    if (!l2) return NULL;
    if (loc >= MAX_IPV4_PER_INTERFACE) return NULL;
    return l2->l3_v4[loc];
}
l3_ipv4_interface_t* l3_ipv4_find_by_ip(uint32_t ip){
    for (int i=0;i<V4_POOL_SIZE;i++){ if (g_v4[i].used && g_v4[i].node.ip == ip) return &g_v4[i].node; }
    return NULL;
}

uint8_t l3_ipv6_add_to_interface(uint8_t ifindex, const uint8_t ip[16], uint8_t prefix_len, const uint8_t gw[16], ipv6_cfg_t cfg, uint8_t kind){
    l2_interface_t *l2 = l2_interface_find_by_index(ifindex);
    if (!l2) return 0;
    if (prefix_len > 128) return 0;

    int placeholder_ll = 0;
    if (ip[0]==0xFE && ip[1]==0x80) {
        placeholder_ll = 1;
        for(int i_ = 2; i_ < 16; i_++) {
            if (ip[i_] != 0) {
                placeholder_ll=0; break;
            }
        }
    }
    int placeholder_gua = 0;
    if (ip[0]==0x20 && ip[1]==0x00) {
        placeholder_gua = 1;
        for(int i_=2;i_<16;i_++) {
            if (ip[i_]!=0) {
                placeholder_gua=0;
                break;
            }
        } 
    }        

    if (kind & IPV6_ADDRK_LINK_LOCAL){
        if (!(cfg & (IPV6_CFG_SLAAC | IPV6_CFG_DHCPV6))){
            if (!ipv6_is_linklocal(ip)) return 0;
        }
        if (!ipv6_is_unspecified(ip) && !placeholder_ll && v6_ip_exists_anywhere(ip)) return 0;
        for (int i=0;i<V6_POOL_SIZE;i++){
            if (!g_v6[i].used) continue;
            if (!g_v6[i].node.l2 || g_v6[i].node.l2->ifindex != ifindex) continue;
            if (ipv6_is_linklocal(g_v6[i].node.ip) && g_v6[i].node.cfg != IPV6_CFG_DISABLE) return 0;
        }
    } else if (kind & IPV6_ADDRK_GLOBAL){
        int is_loop = ipv6_is_loopback(ip);

        if (!(cfg & (IPV6_CFG_SLAAC | IPV6_CFG_DHCPV6))){
            if (ipv6_is_unspecified(ip)) return 0;
        }
        if (!ipv6_is_unspecified(ip)){
            if (ipv6_is_multicast(ip)) return 0;
            if (is_loop && !(l2->name[0]=='l' && l2->name[1]=='o')) return 0;
            if (!is_loop){
                if (ipv6_is_ula(ip)) return 0;
                if (!placeholder_gua){
                    if (v6_ip_exists_anywhere(ip)) return 0;
                    if (v6_overlap_intra_l2(ifindex, ip, prefix_len)) return 0;
                }
            }
        }
        if (!is_loop){
            bool has_lla=false;
            for (int i=0;i<V6_POOL_SIZE;i++){
                if (!g_v6[i].used) continue;
                l3_ipv6_interface_t *x=&g_v6[i].node;
                if (!x->l2 || x->l2->ifindex != ifindex) continue;
                if (ipv6_is_linklocal(x->ip) && x->cfg != IPV6_CFG_DISABLE){ has_lla=true; break; }
            }
            if (!has_lla) return 0;
        }
    } else {
        return 0;
    }

    if (l2->ipv6_count >= MAX_IPV6_PER_INTERFACE) return 0;

    int loc = -1;
    for (int s=0; s<MAX_IPV6_PER_INTERFACE; s++) if (l2->l3_v6[s] == NULL) {
        loc = s;
        break;
    }

    int g = -1;
    for (int i=0;i<V6_POOL_SIZE;i++) if (!g_v6[i].used) {
        g = i;
        break;
    }
    if (loc < 0 || g < 0) return 0;

    g_v6[g].used = true;
    g_v6[g].slot_in_l2 = (uint8_t)loc;

    l3_ipv6_interface_t *n = &g_v6[g].node;
    memset(n, 0, sizeof(*n));
    n->l2 = l2;
    n->cfg = cfg;
    n->kind = kind;
    ipv6_cpy(n->ip, ip);
    n->prefix_len = prefix_len;
    ipv6_cpy(n->gateway, gw);
    n->is_localhost = (l2->name[0]=='l' && l2->name[1]=='o');
    n->l3_id = make_l3_id(l2->ifindex, (uint8_t)loc);
    l2->l3_v6[loc] = n;
    l2->ipv6_count++;

    if (!g_kmem_page) g_kmem_page = palloc(PAGE_SIZE, MEM_PRIV_KERNEL, MEM_RW | MEM_NORM, false);
    n->port_manager = (port_manager_t*)kalloc(g_kmem_page, sizeof(port_manager_t), ALIGN_16B, MEM_PRIV_KERNEL);
    if (!n->port_manager){
        l2->l3_v6[loc] = NULL;
        if (l2->ipv6_count) l2->ipv6_count--;
        g_v6[g].used = false;
        memset(&g_v6[g], 0, sizeof(g_v6[g]));
        return 0;
    }
    port_manager_init(n->port_manager);

    return n->l3_id;
}

bool l3_ipv6_update(uint8_t l3_id, const uint8_t ip[16], uint8_t prefix_len, const uint8_t gw[16], ipv6_cfg_t cfg, uint8_t kind){
    l3_ipv6_interface_t *n = l3_ipv6_find_by_id(l3_id);
    if (!n) return false;
    l2_interface_t *l2 = n->l2;
    if (!l2) return false;
    if (prefix_len > 128) return false;

    if ((n->kind & IPV6_ADDRK_LINK_LOCAL) && cfg == IPV6_CFG_DISABLE){
        for (int i=0;i<V6_POOL_SIZE;i++){
            if (!g_v6[i].used) continue;
            l3_ipv6_interface_t *x = &g_v6[i].node;
            if (!x->l2 || x->l2->ifindex != l2->ifindex) continue;
            if ((x->kind & IPV6_ADDRK_GLOBAL) && x->cfg != IPV6_CFG_DISABLE) return false;
        }
    }

    if (kind & IPV6_ADDRK_LINK_LOCAL){
        if (!(cfg & (IPV6_CFG_SLAAC | IPV6_CFG_DHCPV6))){
            if (!ipv6_is_linklocal(ip)) return false;
        }
        if (!ipv6_is_unspecified(ip) && ipv6_cmp(ip, n->ip)!=0 && v6_ip_exists_anywhere(ip)) return false;
        for (int i=0;i<V6_POOL_SIZE;i++){
            if (!g_v6[i].used) continue;
            l3_ipv6_interface_t *x=&g_v6[i].node;
            if (x==n) continue;
            if (!x->l2 || x->l2->ifindex != l2->ifindex) continue;
            if (ipv6_is_linklocal(x->ip) && x->cfg != IPV6_CFG_DISABLE) return false;
        }
    } else if (kind & IPV6_ADDRK_GLOBAL){
        if (!(cfg & (IPV6_CFG_SLAAC | IPV6_CFG_DHCPV6))){
            if (ipv6_is_unspecified(ip)) return false;
        }
        if (!ipv6_is_unspecified(ip)){
            if (ipv6_is_multicast(ip) || ipv6_is_loopback(ip) || ipv6_is_ula(ip)) return false;
            if (ipv6_cmp(ip,n->ip)!=0 && v6_ip_exists_anywhere(ip)) return false;
            if (v6_overlap_intra_l2(l2->ifindex, ip, prefix_len)){
                for (int i=0;i<V6_POOL_SIZE;i++){
                    if (!g_v6[i].used) continue;
                    l3_ipv6_interface_t *x=&g_v6[i].node;
                    if (x==n) continue;
                    if (!x->l2 || x->l2->ifindex != l2->ifindex) continue;
                    if (ipv6_is_unspecified(x->ip)) continue;
                    uint8_t minp = (x->prefix_len < prefix_len) ? x->prefix_len : prefix_len;
                    int eq = 1;
                    int fb=minp/8, rb=minp%8;
                    for (int b=0;b<fb;b++){ if (ip[b]!=x->ip[b]) {eq=0;break;} }
                    if (eq && rb){
                        uint8_t m=(uint8_t)(0xFF<<(8-rb));
                        if ( (ip[fb]&m) != (x->ip[fb]&m) ) eq=0;
                    }
                    if (eq) return false;
                }
            }
        }
    } else {
        return false;
    }

    n->cfg = cfg;
    n->kind = kind;
    ipv6_cpy(n->ip, ip);
    n->prefix_len = prefix_len;
    ipv6_cpy(n->gateway, gw);
    return true;
}

bool l3_ipv6_remove_from_interface(uint8_t l3_id){
    l3_ipv6_interface_t *n = l3_ipv6_find_by_id(l3_id);
    if (!n) return false;
    l2_interface_t *l2 = n->l2;
    if (!l2) return false;
    if ((n->kind & IPV6_ADDRK_LINK_LOCAL)){
        for (int i=0;i<V6_POOL_SIZE;i++){
            if (!g_v6[i].used) continue;
            l3_ipv6_interface_t *x=&g_v6[i].node;
            if (!x->l2 || x->l2->ifindex != l2->ifindex) continue;
            if ((x->kind & IPV6_ADDRK_GLOBAL) && x->cfg != IPV6_CFG_DISABLE) return false;
        }
    }
    if (l2->ipv6_count <= 1) return false;

    int g = -1;
    for (int i=0;i<V6_POOL_SIZE;i++){
        if (g_v6[i].used && &g_v6[i].node == n){ g = i; break; }
    }
    if (g < 0) return false;

    if (n->port_manager) {
        kfree(n->port_manager, sizeof(port_manager_t));
        n->port_manager = NULL;
    }

    uint8_t slot = l3_local_slot_from_id(l3_id);
    if (slot < MAX_IPV6_PER_INTERFACE && l2->l3_v6[slot] == n){
        l2->l3_v6[slot] = NULL;
        if (l2->ipv6_count) l2->ipv6_count--;
    }

    g_v6[g].used = false;
    memset(&g_v6[g], 0, sizeof(g_v6[g]));
    return true;
}

bool l3_ipv6_set_enabled(uint8_t l3_id, bool enable){
    l3_ipv6_interface_t *n = l3_ipv6_find_by_id(l3_id);
    if (!n) return false;
    if (enable){
        if (n->cfg == IPV6_CFG_DISABLE) n->cfg = IPV6_CFG_STATIC;
        return true;
    } else {
        if ((n->kind & IPV6_ADDRK_LINK_LOCAL)){
            l2_interface_t *l2 = n->l2;
            for (int i=0;i<V6_POOL_SIZE;i++){
                if (!g_v6[i].used) continue;
                l3_ipv6_interface_t *x = &g_v6[i].node;
                if (!x->l2 || x->l2->ifindex != l2->ifindex) continue;
                if ((x->kind & IPV6_ADDRK_GLOBAL) && x->cfg != IPV6_CFG_DISABLE) return false;
            }
        }
        n->cfg = IPV6_CFG_DISABLE;
        return true;
    }
}

l3_ipv6_interface_t* l3_ipv6_find_by_id(uint8_t l3_id){
    uint8_t ifx = l3_ifindex_from_id(l3_id);
    uint8_t loc = l3_local_slot_from_id(l3_id);
    l2_interface_t *l2 = l2_interface_find_by_index(ifx);
    if (!l2) return NULL;
    if (loc >= MAX_IPV6_PER_INTERFACE) return NULL;
    return l2->l3_v6[loc];
}
l3_ipv6_interface_t* l3_ipv6_find_by_ip(const uint8_t ip[16]){
    for (int i=0;i<V6_POOL_SIZE;i++){
        if (g_v6[i].used && ipv6_cmp(g_v6[i].node.ip, ip)==0) return &g_v6[i].node;
    }
    return NULL;
}

void l3_init_localhost_ipv4(void){
    l2_interface_t *lo = NULL;
    for (int i=0;i<(int)MAX_L2_INTERFACES;i++){
        if (!g_l2_used[i]) continue;
        if (g_l2[i].name[0]=='l' && g_l2[i].name[1]=='o' && g_l2[i].name[2]=='0' && g_l2[i].name[3]==0) { lo = &g_l2[i]; break; }
    }
    if (!lo) return;
    for (int i=0;i<V4_POOL_SIZE;i++){
        if (!g_v4[i].used) continue;
        if (!g_v4[i].node.l2 || g_v4[i].node.l2 != lo) continue;
        if (ipv4_is_loopback(g_v4[i].node.ip)) return;
    }
    (void)l3_ipv4_add_to_interface(lo->ifindex, 0x7F000001u, 0xFF000000u, 0, IPV4_CFG_STATIC, NULL);
}

void l3_init_localhost_ipv6(void){
    l2_interface_t *lo = NULL;
    for (int i=0;i<(int)MAX_L2_INTERFACES;i++){
        if (!g_l2_used[i]) continue;
        if (g_l2[i].name[0]=='l' && g_l2[i].name[1]=='o' && g_l2[i].name[2]=='0' && g_l2[i].name[3]==0) { lo = &g_l2[i]; break; }
    }
    if (!lo) return;
    uint8_t loop6[16]={0}; loop6[15]=1;
    for (int i=0;i<V6_POOL_SIZE;i++){
        if (!g_v6[i].used) continue;
        if (!g_v6[i].node.l2 || g_v6[i].node.l2 != lo) continue;
        if (ipv6_is_loopback(g_v6[i].node.ip)) return;
    }
    uint8_t zero16[16]={0};
    (void)l3_ipv6_add_to_interface(lo->ifindex, loop6, 128, zero16, IPV6_CFG_STATIC, IPV6_ADDRK_GLOBAL);
}

void ifmgr_autoconfig_l2(uint8_t ifindex){
    l2_interface_t *l2 = l2_interface_find_by_index(ifindex);
    if (!l2) return;

    if (l2->name[0]=='l' && l2->name[1]=='o' && l2->name[2]=='0' && l2->name[3]==0){
        return;
    }

    if (l2->ipv4_count == 0){
        (void)l3_ipv4_add_to_interface(ifindex, 0, 0, 0, IPV4_CFG_DHCP, NULL);
    }

    bool has_lla=false;
    for (int i=0;i<V6_POOL_SIZE;i++){
        if (!g_v6[i].used) continue;
        l3_ipv6_interface_t *x=&g_v6[i].node;
        if (!x->l2 || x->l2->ifindex != ifindex) continue;
        if (ipv6_is_linklocal(x->ip) && x->cfg != IPV6_CFG_DISABLE){ has_lla=true; break; }
    }
    if (!has_lla){
        uint8_t fe80_0[16]={0}; fe80_0[0]=0xFE; fe80_0[1]=0x80;
        uint8_t zero16[16]={0};
        (void)l3_ipv6_add_to_interface(ifindex, fe80_0, 64, zero16, IPV6_CFG_SLAAC, IPV6_ADDRK_LINK_LOCAL);
    }

    bool has_gua=false;
    for (int i=0;i<V6_POOL_SIZE;i++){
        if (!g_v6[i].used) continue;
        l3_ipv6_interface_t *x=&g_v6[i].node;
        if (!x->l2 || x->l2->ifindex != ifindex) continue;
        if (!ipv6_is_linklocal(x->ip) && x->cfg != IPV6_CFG_DISABLE){ has_gua=true; break; }
    }
    if (!has_gua){
        uint8_t g2000_0[16]={0}; g2000_0[0]=0x20; g2000_0[1]=0x00;
        uint8_t zero16[16]={0};
        (void)l3_ipv6_add_to_interface(ifindex, g2000_0, 64, zero16, IPV6_CFG_SLAAC, IPV6_ADDRK_GLOBAL);
    }

    //TODO: add autoconfig settings/policy
}

void ifmgr_autoconfig_all_l2(void){
    for (int i=0;i<(int)MAX_L2_INTERFACES;i++){
        if (!g_l2_used[i]) continue;
        ifmgr_autoconfig_l2(g_l2[i].ifindex);
    }
}

ip_resolution_result_t resolve_ipv4_to_interface(uint32_t dst_ip){
    ip_resolution_result_t r; r.found=false; r.ipv4=NULL; r.ipv6=NULL; r.l2=NULL;
    int best_plen = -1;
    for (int i=0;i<V4_POOL_SIZE;i++){
        if (!g_v4[i].used) continue;
        l3_ipv4_interface_t *x = &g_v4[i].node;
        if (!x->l2) continue;
        if (x->mode == IPV4_CFG_DISABLED) continue;
        uint32_t m = x->mask;
        if (m==0){
            if (x->ip == dst_ip && best_plen < 32){ best_plen = 32; r.found=true; r.ipv4=x; r.l2=x->l2; }
            continue;
        }
        if (ipv4_net(dst_ip, m) == ipv4_net(x->ip, m)){
            int plen=0; uint32_t tmp=m;
            while (tmp){ plen += (tmp & 1u); tmp >>= 1; }
            if (plen > best_plen){ best_plen = plen; r.found=true; r.ipv4=x; r.l2=x->l2; }
        }
    }
    return r;
}

ip_resolution_result_t resolve_ipv6_to_interface(const uint8_t dst_ip[16]){
    ip_resolution_result_t r; r.found=false; r.ipv4=NULL; r.ipv6=NULL; r.l2=NULL;
    int best = -1;
    for (int i=0;i<V6_POOL_SIZE;i++){
        if (!g_v6[i].used) continue;
        l3_ipv6_interface_t *x = &g_v6[i].node;
        if (!x->l2) continue;
        if (x->cfg == IPV6_CFG_DISABLE) continue;
        if (ipv6_is_unspecified(x->ip)) continue;
        int match = ipv6_common_prefix_len(dst_ip, x->ip);
        if (match >= x->prefix_len && match > best){ best = match; r.found=true; r.ipv6=x; r.l2=x->l2; }
    }
    return r;
}

bool check_ipv4_overlap(uint32_t new_ip, uint32_t mask, uint8_t ifindex){ return v4_overlap_intra_l2(ifindex, new_ip, mask); }
bool check_ipv6_overlap(const uint8_t new_ip[16], uint8_t prefix_len, uint8_t ifindex){ return v6_overlap_intra_l2(ifindex, new_ip, prefix_len); }