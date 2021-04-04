
use std::fs::File;
use std::io::prelude::*;
use std::mem;
use std::env;

mod peform;


fn main() {
    // Read file
    let args: Vec<String> = env::args().collect();
    if args.len() > 1 {
        println!("{}",args[1]);
        
        let mut file = match File::open(&args[1]) {
            Err(why) => panic!("couldn't open {}", why),
            Ok(file) => file,
        };
        
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer).unwrap();

        // DOS Header1
        if buffer.len() > 0x3d {
            let mzmagic = format!("{}{}", buffer[0] as char, buffer[1] as char);
            let off = buffer[0x3c] as u32
                + ((buffer[0x3d] as u32) << 8)
                + ((buffer[0x3e] as u32) << 16)
                + ((buffer[0x3f] as u32) << 24);
            let pemagic = format!(
                "{}{}",
                buffer[off as usize] as char,
                buffer[off as usize + 1] as char
            );

            if mzmagic == "MZ" && pemagic == "PE" {
                let doshead = peform::load_dos_header(&buffer);
                println!("{:#x?}", doshead);
                let oh_off = doshead.e_lfanew;

                let filehead = peform::load_file_header(&buffer, oh_off);
                println!("\n{:#x?}", filehead);
                let oh_off = oh_off as usize + mem::size_of::<peform::ImageFileHeader>();

                if filehead.machine == 0x8664 {
                    let opthead = peform::load_pe64_header(&buffer, oh_off as u32);
                    println!("\n{:#x?}", opthead);
                } else if filehead.machine == 0x014c {
                    let opthead = peform::load_pe32_header(&buffer, oh_off as u32);
                    println!("\n{:#x?}", opthead);
                } else {
                    println!("\nMachie type not implemented: {:x}", filehead.machine);
                }

            } else {
                println!("Not a PE file");
            }
        }
    } else {
        println!("Usage: yama [path to PE file]");
    }
}
