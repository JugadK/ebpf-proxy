use std::sync::OnceLock;
use std::env::var;

pub fn get_interface() -> &'static str {
    static INTERFACE: OnceLock<String> = OnceLock::new();

    println!("{}", var("INTERFACE").unwrap());

    INTERFACE.get_or_init(|| {
        var("INTERFACE").unwrap()
    })
}

pub const EBPF_OBJ_PATH: &str = "ebpf/ebpf_proxy.ebpf.o";
pub const EBPF_PROXY_PROG_NAME: &str = "tc";
pub const EBPF_PROXY_MAP_NAME: &str = "src2destipv4";
pub const EBPF_PROXY_DEST2SRC: &str = "dest2srcipv4";


