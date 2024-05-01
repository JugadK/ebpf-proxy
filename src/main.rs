use rebpf::interface::get_interface;
use rebpf::libbpf;
use signal_hook::{consts::signal::*, iterator::Signals};
use std::io::Read;
use std::net::TcpListener;
use std::path::Path;
use std::process;
use std::thread;

mod constants;
mod ebpf_proxy;

fn setup_ctrlc_signal() {
    let mut signals = Signals::new(&[SIGINT]).unwrap();

    thread::spawn(move || {
        for sig in signals.forever() {
            println!("Received signal {:?}", sig);

            rebpf::libbpf::bpf_set_link_xdp_fd(
                &(get_interface(constants::INTERFACE_NAME).unwrap()),
                None,
                rebpf::libbpf::XdpFlags::UPDATE_IF_NOEXIST,
            )
            .unwrap();

            println!("Killed XDP link");

            signal_hook::low_level::emulate_default_handler(SIGINT)
                .expect("Failed to reset default signal handler");

            process::exit(0);
        }
    });
}

fn main() {
    setup_ctrlc_signal();

    match ebpf_proxy::ebpf_proxy_context::new() {
        Ok(ebpf_proxy_context) => {

            let origin_ip : u32 = 0x00000001;
            let destination_ip : u32 = 0x00000002;

            ebpf_proxy_context.add_ipv4_pair(origin_ip, destination_ip);

            let listener = TcpListener::bind("127.0.0.1:7878").unwrap();

            println!("Server listening on port 7878");

            for stream in listener.incoming() {
                let mut stream = stream.unwrap();

                println!("Connection established!");

                // Read data from the stream
                let mut buffer = [0; 1024];
                stream.read(&mut buffer).unwrap();
            }
        }
        Err(e) => {
            eprintln!("Failed to create eBPF context: {}", e);
        }
    }
}
