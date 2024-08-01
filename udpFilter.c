#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define SECTION(NAME) __attribute__((section(NAME), used))

#define mpps 100
#define mbytes 500000 
#define mtime 1000000000 

struct bpf_map_def SECTION("maps") udp_packet_count_map = {

    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(__u64),
    .value_size = sizeof(__u64),
    .max_entries = 10240,

};

struct bpf_map_def SECTION("maps") udp_byte_count_map = {

    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(__u64),
    .value_size = sizeof(__u64),
    .max_entries = 10240,

};

struct bpf_map_def SECTION("maps") udp_last_update_map = {

    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(__u64),
    .value_size = sizeof(__u64),
    .max_entries = 10240,

};

SECTION("udpFilter")
int xdp_filter_udp_floods(struct xdp_md *ctx) {

    void *data_end = (void *)(long)ctx->data_end;

    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if (data + sizeof(*eth) > data_end) {
        return XDP_PASS;
    }

    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return XDP_PASS;
    }

    struct iphdr *ip = data + sizeof(*eth);

    if (data + sizeof(*eth) + sizeof(*ip) > data_end) {
        return XDP_PASS;
    }

    if (ip->protocol != IPPROTO_UDP) {

        return XDP_PASS;
    }

    struct udphdr *udp = data + sizeof(*eth) + sizeof(*ip);

    if (data + sizeof(*eth) + sizeof(*ip) + sizeof(*udp) > data_end) {
        return XDP_PASS;
    }

    __u64 key = ((__u64)ip->saddr << 32) | udp->source; 
    __u64 current_time = bpf_ktime_get_ns();

    __u64 *packet_count = NULL, *byte_count = NULL, *last_update_time = NULL;

    packet_count = bpf_map_lookup_elem(&udp_packet_count_map, &key);
    byte_count = bpf_map_lookup_elem(&udp_byte_count_map, &key);
    last_update_time = bpf_map_lookup_elem(&udp_last_update_map, &key);

    __u64 packet_count_val = 0;
    __u64 byte_count_val = 0;
    __u64 last_update_val = current_time;

    if (packet_count) {
        packet_count_val = *packet_count;
    }
    if (byte_count) {
        byte_count_val = *byte_count;
    }
    if (last_update_time) {
        last_update_val = *last_update_time;
    }

    __u64 time_diff = current_time - last_update_val;
    if (time_diff > mtime) {
        packet_count_val = 0;
        byte_count_val = 0;
        last_update_val = current_time;

    }

    if (packet_count_val >= mpps || byte_count_val + bpf_ntohs(udp->len) >= mbytes) {

        return XDP_DROP;
    }

    packet_count_val++;
    byte_count_val += bpf_ntohs(udp->len);

    bpf_map_update_elem(&udp_packet_count_map, &key, &packet_count_val, BPF_ANY);
    bpf_map_update_elem(&udp_byte_count_map, &key, &byte_count_val, BPF_ANY);
    bpf_map_update_elem(&udp_last_update_map, &key, &last_update_val, BPF_ANY);

    return XDP_PASS;
}

char _license[] SECTION("license") = "GPL";
