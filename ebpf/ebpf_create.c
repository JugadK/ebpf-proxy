#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <bpf/libbpf_legacy.h>
#include <stdio.h>
#include <unistd.h>
#include <linux/if_link.h>     // Definitions for network interfaces
#include <linux/if_xdp.h>      // Definitions specific to XDP
#include <net/if.h>            // Interface name to index resolution
#include <unistd.h>            // Common POSIX functions like close()
#include <stdio.h>             // Standard I/O functions
#include <stdlib.h>            // Standard library functions, like exit()
#include <arpa/inet.h>         // Functions for internet operations
#include <string.h>            // String handling functions

/*int create_pinned_ebpf_map() {

  int fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, "bpf_map", sizeof(__u32),
                          sizeof(__u32), 4, NULL);

  if (fd < 0) {
    perror("Map creation failed");
    return 1;
  }

  __u32 status = bpf_obj_pin(fd, "/sys/fs/bpf/ipv4addr");
  if (status < 0) {
    perror("Failed to pin map");
    close(fd);
    return 1;
  }

  return 0;
}*/


const char* interface = "wlan0";

int main() {
  struct bpf_program *prog;
  struct bpf_object *obj;
  int prog_fd;
  
  // Load the BPF object from file
  obj = bpf_object__open_file("ebpf_proxy.ebpf.o", NULL);
  if (libbpf_get_error(obj)) {
    fprintf(stderr, "Failed to open BPF object\n");
    return 1;
  }

  // Load BPF program
  if (bpf_object__load(obj)) {
    fprintf(stderr, "Failed to load BPF program\n");
    return 1;
  }

  printf("eBPF object loaded\n");

  prog = bpf_object__find_program_by_name(obj, "xdp_pass_prog");
  
  if(prog < 0) {
    perror("Error in finding xdp program");
    return 1;
  }

  prog_fd = bpf_program__fd(prog);
  if(prog_fd < 0) {
    perror("Error in finding file descriptor for program");
    return 1;
  }

  struct bpf_map *map;
  map = bpf_object__find_map_by_name(obj, "ipv4addr");

  int fd = bpf_map__fd(map);

  if(fd < 0) {
    perror("Failed too fetch file descriptor for map");
  }


  // Update the map element

  __u32 value = 0x20;
  __u32 key = 0x1;
  if (bpf_map_update_elem(fd, &key, &value, BPF_ANY) != 0) {
    printf("%i", fd);
    perror("Map update failed");
    return 1;
  } else {
    printf("Updated map\n");
  }

  __u32 err;

  err = bpf_xdp_attach(if_nametoindex(interface), prog_fd, XDP_FLAGS_UPDATE_IF_NOEXIST, NULL);

  if(err) {
    perror("Error attaching too xdp");
  }


  // When done, clean up
  bpf_object__close(obj);

  return 0;
}


