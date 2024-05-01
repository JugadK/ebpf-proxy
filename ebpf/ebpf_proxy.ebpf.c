#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/in.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>

char _license[] SEC("license") = "GPL";

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, __u32);
  __type(value, __u32);
  __uint(max_entries, 4);
} ipv4addr SEC(".maps");


SEC("xdp")
int xdp_pass_prog(struct xdp_md *ctx) {

  void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
  int size = data_end - data;

  struct ethhdr *eth = data;
  struct iphdr *iph = data + sizeof(*eth);

  __u32 key = 0x1;
  __u32 *ret;

  ret = bpf_map_lookup_elem(&ipv4addr, &key);

  if(ret) {
    bpf_printk("%x", *ret);
  } else {
    bpf_printk("Look up failed for key %x", key);
  }

  __u32 value = 0x4;

  //__u32 rv = bpf_map_update_elem(&ipv4addr, &key, &value, BPF_ANY);



  return XDP_PASS;
}
