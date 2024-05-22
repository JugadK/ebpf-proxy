use rebpf::interface::get_interface;
use rebpf::libbpf;
use signal_hook::{consts::signal::*, iterator::Signals};
use std::io::Read;
use std::net::Ipv4Addr;
use std::net::TcpListener;
use std::path::Path;
use std::process;
use std::string;
use std::thread;

mod constants;
mod ebpf_proxy;

fn setup_ctrlc_signal() {
    let mut signals = Signals::new(&[SIGINT]).unwrap();

    thread::spawn(move || {
        for sig in signals.forever() {
            println!("Received signal {:?}", sig);

            rebpf::libbpf::bpf_set_link_xdp_fd(
                &(get_interface(constants::get_interface()).unwrap()),
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

fn handle_ebpf_proxy_req(
    ebpf_proxy_context: &ebpf_proxy::ebpf_proxy_context,
    request_type: &str,
    origin_ip: &str,
    destination_ip: &str,
) {
    if request_type == "ADD" {
        match (ipv4_to_hex(origin_ip), ipv4_to_hex(destination_ip)) {
            (Ok(origin_ip_hex), Ok(dest_ip_hex)) => {
                ebpf_proxy_context.add_ipv4_pair(origin_ip_hex, dest_ip_hex);
                println!("Added new ip pair Source:{}, Destination:{}",origin_ip, destination_ip);
                println!("Added new ip hex Source:{:X}, Destination:{:X}",origin_ip_hex, dest_ip_hex);
            }
            (Err(e), _) | (_, Err(e)) => {
                eprintln!("Error converting IP address: {}", e);
            }
        }
    }
}

fn ipv4_to_hex(ip: &str) -> Result<u32, String> {
    match ip.parse::<Ipv4Addr>() {
        Ok(ipv4) => {
            // Convert each octet to hex and format the result
            let octets = ipv4.octets();
            Ok(u32::from_be_bytes(octets))
        }
        Err(_) => Err(String::from("Invalid IPv4 address")),
    }
}

fn main() {
    setup_ctrlc_signal();

    match ebpf_proxy::ebpf_proxy_context::new() {
        Ok(ebpf_proxy_context) => {

            // let key : u32 = 0xc0a80105;
            // let val : u32 = 0x2;
            //
            // println!("{:X}", key);
            //
            // ebpf_proxy_context.add_ipv4_pair(key, val);
            
            let listener = TcpListener::bind("127.0.0.1:7878").unwrap();

            println!("Server listening on port 7878");

            for stream in listener.incoming() {
                let mut stream = stream.unwrap();

                let mut buffer = [0; 1024];
                stream.read(&mut buffer).unwrap();

                let req: &str = match std::str::from_utf8(&buffer) {
                    Ok(r) => r,
                    Err(e) => panic!("Invalid UTF-8 sequence: {}", e),
                };

                let parts: Vec<&str> = req.split_whitespace().collect();

                if parts.len() == 4 {
                    let req_type = parts[0];
                    let origin_ip = parts[1];
                    let dest_ip = parts[2];

                    handle_ebpf_proxy_req(&ebpf_proxy_context, req_type, origin_ip, dest_ip)

                } else {
                    println!("ERROR: Invalid request was sent {:?}", parts)
                }
            }
        }
        Err(e) => {
            eprintln!("Failed to create eBPF context: {}", e);
        }
    }
}
