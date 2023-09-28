#include <uapi/linux/bpf.h>
//#include "libbpf/src/bpf_helpers.h"
//#include "libbpf/src/bpf_endian.h"
#include <linux/if_ether.h>
#include <linux/ip.h>
//#include <arpa/inet.h>
#include <bcc/proto.h>



struct ipv4_lpm_value {
    __u32 prefixlen;
    __u32 iface;
};

struct testKeyS {
    __u64 ip;
};


// BCC TRIE

struct key_t {
    __u32 pfxLen;
    __u8 ip[4];
} BPF_PACKET_HEADER;

struct value_t {
  __u64 valid;
} BPF_PACKET_HEADER;

BPF_LPM_TRIE(my_trie, struct key_t, struct value_t);







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


    
    
    //in4_pton(source, 16, &ip, '\0', NULL);
    
    
    bpf_trace_printk("dst ip: %d", ip);
    



    return XDP_PASS;
}


int xdp_prog_simple(struct xdp_md *context) //struct xdp_md *context
{
//    enum xdp_action rc = XDP_PASS;
//    __u64 nh_off, res = 0;
//    void *data_end = (void *)(long)context->data_end;
//    void *data = (void *)(long)context->data;
  /*
  struct key_t test_key;
  struct value_t test_val;
  struct value_t *val;

  test_val.valid = 1;
  test_key.pfxLen = 24;
  test_key.ip[0] = 255;
  test_key.ip[1] = 255;
  test_key.ip[2] = 255;
  test_key.ip[3] = 255;

  my_trie.insert(&test_key, &test_val);


  val= my_trie.lookup(&test_key);
  
  if(val){
    res = val->valid;
    
  }

  */

    
  
  return XDP_PASS;
}


