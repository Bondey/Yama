use std::fs::File;
use std::io::prelude::*;
use std::path::Path;

// DOCS https://github.com/corkami/pics/blob/master/binary/pe101/pe101-64.pdf
struct PEHeader {
    e_lfanew: u8, // PE header Offset
    machine: u16, // Machine Type                   TODO: Enum with types
    numofsec: u16, // Number of sections
    sizeoptionalheader: u16,
    characteristics: u16
}

impl Default for PEHeader {
    fn default () -> PEHeader {
        PEHeader{e_lfanew: 0, machine: 0, numofsec:0, sizeoptionalheader:0, characteristics:0}
    }
}

impl std::fmt::Display for PEHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "e_lfanew: {:x}\nmachine: {:04x}\nnumofsec: {}\nsizeoptionalheader: {:x}\ncharacteristics: {:04x}", self.e_lfanew, self.machine,self.numofsec,self.sizeoptionalheader,self.characteristics)
    }
}

fn main() {
    // Read file
    let path = Path::new("/home/marc/Descargas/345e5f0189f57c4531702f2107598df70dd0b4753457b11d5255073b85979994");
    let mut file = match File::open(&path) {
        Err(why) => panic!("couldn't open {}", why),
        Ok(file) => file,
    };
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).unwrap();

    // DOS Header1
    if buffer.len()>0x3d {
    let mzmagic = format!("{}{}", buffer[0] as char,buffer[1] as char);
    let off = buffer[0x3c];
    let pemagic = format!("{}{}", buffer[off as usize] as char, buffer[off as usize+1] as char);
    
        if mzmagic== "MZ" && pemagic=="PE" {
            let mut pehead = PEHeader::default(); 
            pehead.e_lfanew = buffer[0x3c];
            pehead.machine = (buffer[pehead.e_lfanew as usize+4] as u16) + ( (buffer[pehead.e_lfanew as usize+5] as u16) << 8);
            pehead.numofsec = (buffer[pehead.e_lfanew as usize+6] as u16) + ( (buffer[pehead.e_lfanew as usize+7] as u16) << 8);
            pehead.sizeoptionalheader = (buffer[pehead.e_lfanew as usize+20] as u16) + ( (buffer[pehead.e_lfanew as usize+21] as u16) << 8);
            pehead.characteristics = (buffer[pehead.e_lfanew as usize+22] as u16) + ( (buffer[pehead.e_lfanew as usize+23] as u16) << 8);
            println!("PE Header:\n{}",pehead);
        } else {
            println!("Not a PE file");
        }
    }    
}