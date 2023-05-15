#include <uapi/linux/bpf.h>
//#include "libbpf/src/bpf_helpers.h"
//#include "libbpf/src/bpf_endian.h"
#include <linux/if_ether.h>
#include <linux/ip.h>
//#include <arpa/inet.h>
#include <bcc/proto.h>



struct ipv4_lpm_key {
    __u32 prefixlen;
    __u32 data;
};

/*
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct ipv4_lpm_key);
    __type(fwd_int, __u32);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, 255);
} ipv4_lpm_map SEC("maps");
*/

// BCC TRIE

struct key_t {
    __u16 pfxLen;
    __u8 ip[8];
} BPF_PACKET_HEADER;

struct value_t {
  __u8 valid;
} BPF_PACKET_HEADER;

BPF_LPM_TRIE(my_trie, struct ipv4_lpm_key);//, struct value_t, 1024);
//BPF_HASH(start);






// Parse incoming packet //

struct hdr_cursor {
    void *pos;
};

    // Parse ethernet header //

static __always_inline int parse_ethernet_hdr(struct hdr_cursor *nh, void *data_end, struct ethhdr **ethhdr)
{
    struct ethhdr *eth = nh->pos;
    int hdrsize = sizeof(*eth);

    if (eth + 1 > data_end){
        return 1;
    } 
        

    nh->pos += hdrsize;
    *ethhdr = eth;

    return eth->h_proto;
}

static __always_inline int parse_ipv4_hdr(struct hdr_cursor *nh, void *data_end, struct iphdr **ipv4hdr)
{
    struct iphdr *ipv4 = nh->pos;
    int hdrsize = sizeof(*ipv4);

    if(ipv4 + 1 > data_end){
        return 1;
    }

    nh->pos += hdrsize;
    *ipv4hdr = ipv4;
    
    return ipv4->daddr;

}

//SEC("xdp_std_trie")
int xdp_std_trie_router(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth;
    struct iphdr *ipv4;

    struct hdr_cursor nh;
    int nh_type;

    nh.pos = data;

    /* Packet Processing: First parse the ethernet header. We have no use for this data. 
     * next parse the ipv4 header. We want the dst address from this header. Take the dst address 
     * and perform a lookup in the LPM table. Foward out the interface that is returned using XDP_REDIRECT
     */

    nh_type = parse_ethernet_hdr(&nh, data_end, &eth);
    /*
    if(nh_type != bpf_htons(ETH_P_IP)){
        return XDP_DROP;
    }
    */
    int ip;
    ip = parse_ipv4_hdr(&nh, data_end, &ipv4);


    //const char source[4];
    
    //in4_pton(source, 16, &ip, '\0', NULL);
    //snprintf(source, 16, "%pI4", &ip);
    
    bpf_trace_printk("dst ip: %d", ip);
    



    return XDP_PASS;
}


//SEC("xdp")
int xdp_prog_simple(struct xdp_md *context)
{
  enum xdp_action rc = XDP_PASS;
  __u64 nh_off;
  void *data_end = (void *)(long)context->data_end;
  void *data = (void *)(long)context->data;
  
  return XDP_PASS;
}
