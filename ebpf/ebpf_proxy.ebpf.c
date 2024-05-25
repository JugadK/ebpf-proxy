#include <bpf/bpf_endian.h>
#include <arpa/inet.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <linux/pkt_cls.h>

#define PROXY_IP 0x039067E8;

char _license[] SEC("license") = "GPL";

struct ipv4_lpm_key {
        __u32 prefixlen;
        __u32 data;
};

struct {
  __uint(type, BPF_MAP_TYPE_LPM_TRIE);
  __type(key, struct ipv4_lpm_key);
  __type(value, __u32);
  __uint(max_entries, 0xFFF);
  __uint(map_flags, BPF_F_NO_PREALLOC);
} src2destipv4 SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LPM_TRIE);
  __type(key, struct ipv4_lpm_key);
  __type(value, __u32);
  __uint(max_entries, 0xFFF);
  __uint(map_flags, BPF_F_NO_PREALLOC);
} dest2srcipv4 SEC(".maps");


SEC("tc")
int tc_ingress(struct __sk_buff *ctx) {

  void *data = (void *)(__u64)ctx->data;

  void *data_end = (void *)(__u64)ctx->data_end;

  struct ethhdr *eth = data;

  if (data+sizeof(struct ethhdr) > data_end)
    return TC_ACT_OK; 
  
	if (eth->h_proto == bpf_htons(ETH_P_IP)) {
    
		struct iphdr *iph = (data + sizeof(struct ethhdr));

		if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
			return TC_ACT_OK; 

    if(iph->protocol == IPPROTO_TCP && data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) <= data_end) {
      
      struct tcphdr *tcph = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
      
      if(tcph->dest == 7878) {
        bpf_printk("ebpf_proxy API packet");
        return TC_ACT_OK;
      } else if(tcph->source == 7878) {
        return TC_ACT_OK;
      } else if(tcph->dest == 22){
        return TC_ACT_OK;
      } else if(tcph->source == 22) {
        return TC_ACT_OK;
      }
    }

		__u32 saddr = bpf_ntohl(iph->saddr);
		__u32 daddr = bpf_ntohl(iph->daddr);
		
		bpf_printk("Source: %x Dest: %x", saddr, daddr);

		__u32 *ret;
		__u32 *destret;

    struct ipv4_lpm_key ipv4_key = {
            .prefixlen = 0x20, // Full IP Address
            .data = saddr,
    };

		ret = bpf_map_lookup_elem(&src2destipv4, &ipv4_key);

		if (ret) {
			bpf_printk("PROXY HIT %x src2dest", *ret);

      __u32 proxy_ip = PROXY_IP;
      __u32 interface = 0x2;

      iph->saddr = bpf_htons(proxy_ip);
      iph->daddr = bpf_htons(*ret);


      return bpf_redirect(interface, 0x0);
	  } 

    destret = bpf_map_lookup_elem(&dest2srcipv4, &ipv4_key);

    if(destret) {
      	bpf_printk("PROXY HIT dest2src %x", *destret);

      __u32 proxy_ip = PROXY_IP;
      __u32 interface = 0x2;

      iph->saddr = bpf_htons(proxy_ip);
      iph->daddr = bpf_htons(*destret);

      return bpf_redirect(interface, 0x0);
    }
	}

  return TC_ACT_OK;
}

