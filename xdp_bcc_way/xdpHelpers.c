#include <uapi/linux/bpf.h>
//#include "libbpf/src/bpf_helpers.h"
//#include "libbpf/src/bpf_endian.h"
#include <linux/if_ether.h>
#include <linux/ip.h>
//#include <arpa/inet.h>
#include <bcc/proto.h>
#include <linux/if.h>
//#include <linux/net/if.h>



#define MAX_ELEMENTS 100

// BCC map

struct key_t {
    __u32 idx;
};

struct value_t {
  __u32 ecode;
};

BPF_ARRAY(error_map, struct key_t, MAX_ELEMENTS);


// Parse incoming packet //

struct hdr_cursor {
    void *pos;
};



// Parse ethernet header //

static __always_inline __u16 parse_ethernet_hdr(struct hdr_cursor *nh, void *data_end, struct ethhdr **ethhdr)
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

static __always_inline __u32 parse_ipv4_hdr(struct hdr_cursor *nh, void *data_end, struct iphdr **ipv4hdr)
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


int xdp_helper(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth;
    struct iphdr *ipv4;

    struct hdr_cursor nh;
    __u16 nh_type;
    __u16 h_proto;
    __u32 dst_ip;

    nh.pos = data;
    struct bpf_fib_lookup fib_params;
    long ret_c;
    __u32 flags = 0;

    memset(&fib_params, 0, sizeof(fib_params));

    h_proto = parse_ethernet_hdr(&nh, data_end, &eth);
    if(1 == h_proto){
        return XDP_PASS;
    }
    dst_ip = parse_ipv4_hdr(&nh, data_end, &ipv4);
    if(1 == dst_ip){
        return XDP_PASS;
    }
    

    //Populate fib_params
    fib_params.family = AF_INET;
    fib_params.tos= ipv4->tos;
    fib_params.l4_protocol = ipv4->protocol;
    fib_params.sport = 0;
    fib_params.dport = 0;
    fib_params.tot_len = ntohs(ipv4->tot_len);
    fib_params.ipv4_src = ipv4->saddr;
    fib_params.ipv4_dst = ipv4->daddr;
    fib_params.ifindex = ctx->ingress_ifindex;

    ret_c = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), flags);

    struct key_t key;
    struct value_t val;

    key.idx = 1;
    val.ecode = ret_c;
    error_map.update(&key, &val);

    // if(5 == ret_c){
    //    return XDP_PASS;
    // }

    bpf_redirect(&fib_params.ifindex, NULL);

    return XDP_PASS;



}



