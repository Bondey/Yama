use std::fs::File;
use std::io::prelude::*;
use std::env;

mod peform;


fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() > 1 {
        println!("{}",args[1]);
        
        let mut file = match File::open(&args[1]) {
            Err(why) => panic!("couldn't open {}", why),
            Ok(file) => file,
        };
        
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer).unwrap();
        
        let pefile = peform::PeFile::load_from_buffer(&buffer);

        println!("\n{:#x?}", pefile.dos_header);
        println!("\n{:#x?}", pefile.file_header);
        unsafe {
            println!("\n{:#x?}", pefile.optional_header.optional_header32);
            println!("\n{:#x?}", pefile.optional_header.optional_header64);
        }
    }
}
