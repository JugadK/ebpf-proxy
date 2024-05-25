use crate::constants;
// use rebpf::interface::get_interface;
// use rebpf::libbpf;
// use rebpf::map_layout::ReadPointer;
use signal_hook::{consts::signal::*, iterator::Signals};
use std::ffi::CString;
use std::os::raw;
use std::path::Path;
use std::process;
use std::process::Command;
use std::thread;

const TC_H_MAJ_MASK: u32 = 0xFFFF; // Adjust according to the actual value in your C code
const TC_H_MIN_MASK: u32 = 0x0; // Adjust according to the actual value in your C code

macro_rules! tc_h_make {
    ($maj:expr, $min:expr) => {
        (($maj & TC_H_MAJ_MASK) | ($min & TC_H_MIN_MASK))
    };
}

pub struct ebpf_proxy_context {
    bpf_prog_fd: i32,
    src2dest_map_fd: i32,
    dest2src_map_fd: i32,
}

#[repr(C)]
struct ipv4_lpm_key {
    prefixlen: u32,
    data: u32,
}

fn start_signal_handling(mut tc_hook: libbpf_sys::bpf_tc_hook) -> Result<(), String> {
    let mut signals =
        Signals::new(&[SIGINT]).map_err(|e| format!("Failed to create signal handler: {}", e))?;

    thread::spawn(move || {
        for sig in signals.forever() {
            println!("Received signal {:?}", sig);

            // for detaching we need fd and id to be uninitialized
            let mut tc_opts_detach = libbpf_sys::bpf_tc_opts {
                prog_fd: 0,
                flags: 0x0,
                prog_id: 0,
                handle: 0xFFFF0000,
                priority: 0x1,
                sz: std::mem::size_of::<libbpf_sys::bpf_tc_opts>() as u64,
                ..Default::default()
            };

            unsafe {
                if libbpf_sys::bpf_tc_detach(&mut tc_hook, &mut tc_opts_detach) != 0 {
                    println!("Failed to detach hook. Use tc qdisc del manually.");
                } else {
                    println!("Detached hook");
                }

                if libbpf_sys::bpf_tc_hook_destroy(&mut tc_hook) != 0 {
                    println!("Failed to destroy hook. Please do it manually.");
                } else {
                    println!("Destroyed hook");
                }
            }
            let output = Command::new("sh")
                .arg("./disable_tc.sh")
                .output()
                .expect("Failed to execute script");

            if !output.status.success() {
                panic!("Script execution failed with: {:?}", output);
            }

            signal_hook::low_level::emulate_default_handler(SIGINT)
                .expect("Failed to reset default signal handler");

            process::exit(0);
        }
    });

    Ok(())
}

impl ebpf_proxy_context {
    pub fn new() -> Result<ebpf_proxy_context, String> {
        let prog_path = CString::new("ebpf/ebpf_proxy.ebpf.o").expect("CString::new failed");
        let prog_path_ptr = prog_path.as_ptr();

        let prog_name = CString::new("tc_ingress").expect("CString::new failed");
        let prog_name_ptr = prog_name.as_ptr();

        let src2dest_map_name =
            CString::new(constants::EBPF_PROXY_MAP_NAME).expect("CString::new failed");
        let src2dest_map_name_ptr = src2dest_map_name.as_ptr();

        let dest2src_map_name =
            CString::new(constants::EBPF_PROXY_DEST2SRC).expect("CString::new failed");
        let dest2src_map_name_ptr = dest2src_map_name.as_ptr();

        unsafe {
            let mut prog_info = libbpf_sys::bpf_prog_info::default();
            let mut prog_info_ptr: *mut libbpf_sys::bpf_prog_info = &mut prog_info;
            let mut prog_info_len = std::mem::size_of::<libbpf_sys::bpf_prog_info>() as u32;

            let bpf_object = libbpf_sys::bpf_object__open_file(prog_path_ptr, std::ptr::null_mut());

            if bpf_object == std::ptr::null_mut() {
                return Err(format!(
                    "Was not able too open bpf object file {:?}",
                    bpf_object
                ));
            }

            let bpf_obj_load = libbpf_sys::bpf_object__load(bpf_object);

            if bpf_obj_load != 0 {
                return Err(format!("Was not able too load bpf object {}", bpf_obj_load));
            }

            let prog = libbpf_sys::bpf_object__find_program_by_name(bpf_object, prog_name_ptr);

            if prog == std::ptr::null_mut() {
                return Err(format!("Could not find program by name"));
            }

            let fd = libbpf_sys::bpf_program__fd(prog);

            if fd < 0 {
                return Err(format!("Error finding file descriptor"));
            }

            let get_info_err = libbpf_sys::bpf_obj_get_info_by_fd(
                fd,
                prog_info_ptr as *mut std::os::raw::c_void,
                &mut prog_info_len,
            );

            if get_info_err != 0 {
                return Err(format!("Error fetching prog info"));
            }

            let mut tc_opts = libbpf_sys::bpf_tc_opts::default();

            println!("{}, {}", fd, prog_info.id);

            // prog id for initial opts must be 0
            tc_opts.prog_fd = fd;
            tc_opts.flags = 0x0;
            tc_opts.prog_id = 0;
            tc_opts.handle = 0xFFFF0000;
            tc_opts.priority = 0x1;
            tc_opts.sz = std::mem::size_of::<libbpf_sys::bpf_tc_opts>() as u64;

            let mut tc_hook: libbpf_sys::bpf_tc_hook = libbpf_sys::bpf_tc_hook::default();
            tc_hook.parent = 0;
            tc_hook.attach_point = libbpf_sys::BPF_TC_INGRESS;
            tc_hook.ifindex = 4;
            tc_hook.sz = std::mem::size_of::<libbpf_sys::bpf_tc_hook>() as u64;
            let hook_create_err = libbpf_sys::bpf_tc_hook_create(&mut tc_hook);

            if hook_create_err != 0 {
                return Err(format!("Hook failed to be made! {:?}", hook_create_err));
            }

            let attach = libbpf_sys::bpf_tc_attach(&mut tc_hook, &mut tc_opts);

            if attach != 0 {
                //libbpf_sys::bpf_tc_hook_destroy(&mut tc_hook);
                return Err(format!("Unable too attach tc program {:?}", attach));
            }

            let src2dest_map_fd =
                libbpf_sys::bpf_object__find_map_fd_by_name(bpf_object, src2dest_map_name_ptr);

            if src2dest_map_fd < 0 {
                return Err(format!("Unable too get src2dest map"));
            }

            let dest2src_map_fd =
                libbpf_sys::bpf_object__find_map_fd_by_name(bpf_object, dest2src_map_name_ptr);

            if dest2src_map_fd < 0 {
                return Err(format!("Unable too get dest2src map"));
            }
            
            let _ = start_signal_handling(tc_hook);

            println!("Successfully loaded and linked eBPF components");
            Ok(Self {
                bpf_prog_fd: fd,
                src2dest_map_fd,
                dest2src_map_fd,
            })
        }
    }

    pub fn add_ipv4_pair(self: &Self, origin_address: u32, destination_address: u32) {
        // proxy works two ways, first scope handles our original source too the destination, second
        // scope handes from our destination back to our source
        //
        use std::ffi::c_void;

        {
            let key: ipv4_lpm_key = ipv4_lpm_key {
                prefixlen: 0x20,
                data: origin_address,
            };
            let key_ptr: *const ipv4_lpm_key = &key as *const ipv4_lpm_key;

            let value: u32 = destination_address;
            let value_ptr = &value as *const u32;

            unsafe {
                let ret = libbpf_sys::bpf_map_update_elem(
                    self.src2dest_map_fd,
                    key_ptr as *const c_void,
                    value_ptr as *const c_void,
                    libbpf_sys::BPF_ANY.into(),
                );

                println!("{:?}", ret);
            }
        }

        {
            let key: ipv4_lpm_key = ipv4_lpm_key {
                prefixlen: 0x20,
                data: destination_address,
            };
            let key_ptr = &key as *const ipv4_lpm_key;

            let value_ptr = origin_address as *const u32;

            unsafe {
                let ret = libbpf_sys::bpf_map_update_elem(
                    self.dest2src_map_fd,
                    key_ptr as *const c_void,
                    value_ptr as *const c_void,
                    libbpf_sys::BPF_ANY.into(),
                );
                println!("{:?}", ret);
            }
        }
    }
}

