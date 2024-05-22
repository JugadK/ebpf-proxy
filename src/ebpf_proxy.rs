use crate::constants;
use rebpf::interface::get_interface;
use rebpf::libbpf;
use rebpf::map_layout::ReadPointer;
use std::os::raw;
use std::path::Path;

pub struct ebpf_proxy_context {
    bpf_object: libbpf::BpfObject,
    bpf_map: libbpf::BpfMap,
    bpf_map_fd: libbpf::BpfMapFd<ipv4_lpm_key, u32, rebpf::map_layout::ScalarLayout>,
    bpf_dest2src: libbpf::BpfMap,
    bpf_dest2src_fd: libbpf::BpfMapFd<ipv4_lpm_key, u32, rebpf::map_layout::ScalarLayout>,
    bpf_prog: libbpf::BpfProgram,
}

struct ValuePointer {
    value: *const u32,
}

#[repr(C)]
struct ipv4_lpm_key {
    prefixlen: u32,
    data: u32,
}

unsafe impl ReadPointer<u32, rebpf::map_layout::ScalarLayout> for ValuePointer {
    fn get_ptr(self) -> *const raw::c_void {
        return self.value as *const u32 as *const raw::c_void;
    }
}

impl ebpf_proxy_context {
    pub fn new() -> Result<Self, String> {
        let (bpf_object, bpf_obj_fd) = libbpf::bpf_prog_load(
            Path::new(constants::EBPF_OBJ_PATH),
            libbpf::BpfProgType::XDP,
        )
        .map_err(|e| format!("Failed to load bpf object: {:?}", e))?;

        let bpf_prog =
            libbpf::bpf_object__find_program_by_title(&bpf_object, constants::EBPF_PROXY_PROG_NAME)
                .map_err(|e| format!("Failed to find program by title: {:?}", e))?;

        let bpf_map: libbpf::BpfMap =
            libbpf::bpf_object__find_map_by_name(&bpf_object, constants::EBPF_PROXY_MAP_NAME)
                .map_err(|e| format!("Failed to find a map by name"))?;

        let bpf_map_fd: libbpf::BpfMapFd<ipv4_lpm_key, u32, rebpf::map_layout::ScalarLayout> =
            libbpf::bpf_object__find_map_fd_by_name(&bpf_object, constants::EBPF_PROXY_MAP_NAME)
                .map_err(|e| format!("Failed to find map by name: {:?}", e))?;
        
        let bpf_dest2src: libbpf::BpfMap =
            libbpf::bpf_object__find_map_by_name(&bpf_object, constants::EBPF_PROXY_DEST2SRC)
                .map_err(|e| format!("Failed to find a map by name"))?;

        let bpf_dest2src_fd : libbpf::BpfMapFd<ipv4_lpm_key, u32, rebpf::map_layout::ScalarLayout> =
            libbpf::bpf_object__find_map_fd_by_name(&bpf_object, constants::EBPF_PROXY_DEST2SRC)
                .map_err(|e| format!("Failed to find map by name: {:?}", e))?;

        let bpf_prog_fd = libbpf::bpf_program__fd(&bpf_prog)
            .map_err(|e| format!("Failed to get program file descriptor: {:?}", e))?;

        let interface = get_interface(constants::INTERFACE_NAME)
            .map_err(|_| "Failed to get network interface".to_string())?;

        libbpf::bpf_set_link_xdp_fd(
            &interface,
            Some(&bpf_prog_fd),
            rebpf::libbpf::XdpFlags::UPDATE_IF_NOEXIST,
        )
        .map_err(|_| "Failed to set XDP link".to_string())?;

        println!("Successfully loaded and linked eBPF components");
        Ok(Self {
            bpf_object,
            bpf_map,
            bpf_map_fd,
            bpf_dest2src,
            bpf_dest2src_fd,
            bpf_prog,
        })
    }

    pub fn add_ipv4_pair(self: &Self, origin_address: u32, destination_address: u32) {
        let key: ipv4_lpm_key = ipv4_lpm_key { prefixlen: 0x20, data: origin_address};
        let value: u32 = destination_address;

        let ptr = ValuePointer { value: &value };

        let ret = libbpf::bpf_map_update_elem(
            &self.bpf_map_fd,
            &key,
            ptr,
            libbpf::BpfUpdateElemFlags::ANY,
        );

        println!("{:?}", ret);
    }
}
