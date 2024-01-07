#include <uapi/linux/bpf.h>
//#include "libbpf/src/bpf_helpers.h"
//#include "libbpf/src/bpf_endian.h"
#include <linux/if_ether.h>
#include <linux/ip.h>
//#include <arpa/inet.h>
#include <bcc/proto.h>
#include <linux/if.h>
//#include <linux/net/if.h>



#define MAX_ELEMENTS 1000000

// BCC TRIE

struct key_t {
    __u32 pfxLen;
    __u8 ip[4];
} BPF_PACKET_HEADER;

struct value_t {
  __u32 valid;
} BPF_PACKET_HEADER;

BPF_LPM_TRIE(my_trie, struct key_t, struct value_t, MAX_ELEMENTS);


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

    //Used to mirror packets for testing
    u8 src_temp[6];
    memcpy(src_temp, eth->h_source, 6);

    memcpy(eth->h_source, eth->h_dest, 6);
    memcpy(eth->h_dest, src_temp, 6);
    

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


int xdp_redir(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth;
    struct iphdr *ipv4;

    struct hdr_cursor nh;
    __u16 nh_type;

    nh.pos = data;

    struct value_t *val;

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
    __u32 ip;
    ip = parse_ipv4_hdr(&nh, data_end, &ipv4);

    struct key_t key;
    __u32 pfx = 24;
    

    memcpy(&(key.ip), &ip, 4);
    memcpy(&(key.pfxLen), &pfx, 4);
    //populate_key(&ip, &key, 32);
    
    
    val = my_trie.lookup(&key);
    
    //Use this to 'count' packets with matching ip
    /*
    if(val){
        struct value_t temp_value;
        temp_value.valid = (val->valid) + 1;
        my_trie.insert(&key, &temp_value);
    }
    */
    
    


    // Get ifindex and redirect
    
    //u32 if_idx = 2;
    if(val){
        bpf_redirect((val->valid), NULL);
    }    

    return XDP_REDIRECT;

}



