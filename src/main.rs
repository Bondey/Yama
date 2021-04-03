use std::fs::File;
use std::io::prelude::*;
use std::path::Path;

#[derive(Debug)]
struct ImageDosHeader {
    e_lfanew: u32, // PE header Offset
    machine: u16,  // Machine Type                   TODO: Enum with types
    numofsec: u16, // Number of sections
    sizeoptionalheader: u16,
    characteristics: u16,
}

impl Default for ImageDosHeader {
    fn default() -> ImageDosHeader {
        ImageDosHeader {
            e_lfanew: 0,
            machine: 0,
            numofsec: 0,
            sizeoptionalheader: 0,
            characteristics: 0,
        }
    }
}

#[derive(Debug)]
struct ImageOptionalHeader64 {
    magic: u16,
    major_linker_version: u8,
    minor_linker_version: u8,
    size_of_code: u32,
    size_of_initialized_data: u32,
    size_of_uninitialized_data: u32,
    address_of_entry_point: u32,
    base_of_code: u32,
    image_base: u64,
    section_alignment: u32,
    file_alignment: u32,
    major_operating_system_version: u16,
    minor_operating_system_version: u16,
    major_image_version: u16,
    minor_image_version: u16,
    major_subsystem_version: u16,
    minor_subsystem_version: u16,
    win32_version_value: u32,
    size_of_image: u32,
    size_of_headers: u32,
    check_sum: u32,
    subsystem: u16,
    dll_characteristics: u16,
    size_of_stack_reserve: u64,
    size_of_stack_commit: u64,
    size_of_heap_reserve: u64,
    size_of_heap_commit: u64,
    loader_flags: u32,
    number_of_rva_and_sizes: u32,
}

fn load_pe64_header(buffer: std::vec::Vec<u8>, oh_off: u32) -> ImageOptionalHeader64 {
    let opthead = ImageOptionalHeader64 {
        magic: (buffer[oh_off as usize] as u16) + ((buffer[oh_off as usize + 1] as u16) << 8),
        major_linker_version: buffer[oh_off as usize + 2],
        minor_linker_version: buffer[oh_off as usize + 3],
        size_of_code: (buffer[oh_off as usize + 4] as u32)
            + ((buffer[oh_off as usize + 5] as u32) << 8)
            + ((buffer[oh_off as usize + 6] as u32) << 16)
            + ((buffer[oh_off as usize + 7] as u32) << 24),
        size_of_initialized_data: (buffer[oh_off as usize + 8] as u32)
            + ((buffer[oh_off as usize + 9] as u32) << 8)
            + ((buffer[oh_off as usize + 10] as u32) << 16)
            + ((buffer[oh_off as usize + 11] as u32) << 24),
        size_of_uninitialized_data: (buffer[oh_off as usize + 12] as u32)
            + ((buffer[oh_off as usize + 13] as u32) << 8)
            + ((buffer[oh_off as usize + 14] as u32) << 16)
            + ((buffer[oh_off as usize + 15] as u32) << 24),
        address_of_entry_point: (buffer[oh_off as usize + 16] as u32)
            + ((buffer[oh_off as usize + 17] as u32) << 8)
            + ((buffer[oh_off as usize + 18] as u32) << 16)
            + ((buffer[oh_off as usize + 19] as u32) << 24),
        base_of_code: (buffer[oh_off as usize + 20] as u32)
            + ((buffer[oh_off as usize + 21] as u32) << 8)
            + ((buffer[oh_off as usize + 22] as u32) << 16)
            + ((buffer[oh_off as usize + 23] as u32) << 24),
        image_base: (buffer[oh_off as usize + 24] as u64)
            + ((buffer[oh_off as usize + 25] as u64) << 8)
            + ((buffer[oh_off as usize + 26] as u64) << 16)
            + ((buffer[oh_off as usize + 27] as u64) << 24)
            + ((buffer[oh_off as usize + 28] as u64) << 32)
            + ((buffer[oh_off as usize + 29] as u64) << 40)
            + ((buffer[oh_off as usize + 30] as u64) << 48)
            + ((buffer[oh_off as usize + 31] as u64) << 56),
        section_alignment: (buffer[oh_off as usize + 32] as u32)
            + ((buffer[oh_off as usize + 33] as u32) << 8)
            + ((buffer[oh_off as usize + 34] as u32) << 16)
            + ((buffer[oh_off as usize + 35] as u32) << 24),
        file_alignment: (buffer[oh_off as usize + 36] as u32)
            + ((buffer[oh_off as usize + 37] as u32) << 8)
            + ((buffer[oh_off as usize + 38] as u32) << 16)
            + ((buffer[oh_off as usize + 39] as u32) << 24),
        major_operating_system_version: (buffer[oh_off as usize + 40] as u16)
            + ((buffer[oh_off as usize + 41] as u16) << 8),
        minor_operating_system_version: (buffer[oh_off as usize + 42] as u16)
            + ((buffer[oh_off as usize + 43] as u16) << 8),
        major_image_version: (buffer[oh_off as usize + 44] as u16)
            + ((buffer[oh_off as usize + 45] as u16) << 8),
        minor_image_version: (buffer[oh_off as usize + 46] as u16)
            + ((buffer[oh_off as usize + 47] as u16) << 8),
        major_subsystem_version: (buffer[oh_off as usize + 48] as u16)
            + ((buffer[oh_off as usize + 49] as u16) << 8),
        minor_subsystem_version: (buffer[oh_off as usize + 50] as u16)
            + ((buffer[oh_off as usize + 51] as u16) << 8),
        win32_version_value: (buffer[oh_off as usize + 52] as u32)
            + ((buffer[oh_off as usize + 53] as u32) << 8)
            + ((buffer[oh_off as usize + 54] as u32) << 16)
            + ((buffer[oh_off as usize + 55] as u32) << 24),
        size_of_image: (buffer[oh_off as usize + 56] as u32)
            + ((buffer[oh_off as usize + 57] as u32) << 8)
            + ((buffer[oh_off as usize + 58] as u32) << 16)
            + ((buffer[oh_off as usize + 59] as u32) << 24),
        size_of_headers: (buffer[oh_off as usize + 60] as u32)
            + ((buffer[oh_off as usize + 61] as u32) << 8)
            + ((buffer[oh_off as usize + 62] as u32) << 16)
            + ((buffer[oh_off as usize + 63] as u32) << 24),
        check_sum: (buffer[oh_off as usize + 64] as u32)
            + ((buffer[oh_off as usize + 65] as u32) << 8)
            + ((buffer[oh_off as usize + 66] as u32) << 16)
            + ((buffer[oh_off as usize + 67] as u32) << 24),
        subsystem: (buffer[oh_off as usize + 68] as u16)
            + ((buffer[oh_off as usize + 69] as u16) << 8),
        dll_characteristics: (buffer[oh_off as usize + 70] as u16)
            + ((buffer[oh_off as usize + 71] as u16) << 8),
        size_of_stack_reserve: (buffer[oh_off as usize + 72] as u64)
            + ((buffer[oh_off as usize + 73] as u64) << 8)
            + ((buffer[oh_off as usize + 74] as u64) << 16)
            + ((buffer[oh_off as usize + 75] as u64) << 24)
            + ((buffer[oh_off as usize + 76] as u64) << 32)
            + ((buffer[oh_off as usize + 77] as u64) << 40)
            + ((buffer[oh_off as usize + 78] as u64) << 48)
            + ((buffer[oh_off as usize + 79] as u64) << 56),
        size_of_stack_commit: (buffer[oh_off as usize + 80] as u64)
            + ((buffer[oh_off as usize + 81] as u64) << 8)
            + ((buffer[oh_off as usize + 82] as u64) << 16)
            + ((buffer[oh_off as usize + 83] as u64) << 24)
            + ((buffer[oh_off as usize + 84] as u64) << 32)
            + ((buffer[oh_off as usize + 85] as u64) << 40)
            + ((buffer[oh_off as usize + 86] as u64) << 48)
            + ((buffer[oh_off as usize + 87] as u64) << 56),
        size_of_heap_reserve: (buffer[oh_off as usize + 88] as u64)
            + ((buffer[oh_off as usize + 89] as u64) << 8)
            + ((buffer[oh_off as usize + 90] as u64) << 16)
            + ((buffer[oh_off as usize + 91] as u64) << 24)
            + ((buffer[oh_off as usize + 92] as u64) << 32)
            + ((buffer[oh_off as usize + 93] as u64) << 40)
            + ((buffer[oh_off as usize + 94] as u64) << 48)
            + ((buffer[oh_off as usize + 95] as u64) << 56),
        size_of_heap_commit: (buffer[oh_off as usize + 96] as u64)
            + ((buffer[oh_off as usize + 97] as u64) << 8)
            + ((buffer[oh_off as usize + 98] as u64) << 16)
            + ((buffer[oh_off as usize + 99] as u64) << 24)
            + ((buffer[oh_off as usize + 100] as u64) << 32)
            + ((buffer[oh_off as usize + 101] as u64) << 40)
            + ((buffer[oh_off as usize + 102] as u64) << 48)
            + ((buffer[oh_off as usize + 103] as u64) << 56),
        loader_flags: (buffer[oh_off as usize + 104] as u32)
            + ((buffer[oh_off as usize + 105] as u32) << 8)
            + ((buffer[oh_off as usize + 106] as u32) << 16)
            + ((buffer[oh_off as usize + 107] as u32) << 24),
        number_of_rva_and_sizes: (buffer[oh_off as usize + 108] as u32)
            + ((buffer[oh_off as usize + 109] as u32) << 8)
            + ((buffer[oh_off as usize + 110] as u32) << 16)
            + ((buffer[oh_off as usize + 111] as u32) << 24),
    };
    return opthead;
}

fn main() {
    // Read file
    let path = Path::new(
        "/home/marc/Descargas/345e5f0189f57c4531702f2107598df70dd0b4753457b11d5255073b85979994",
    );
    let mut file = match File::open(&path) {
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
            let mut pehead = ImageDosHeader::default();
            pehead.e_lfanew = off;
            // Get PE Header data
            pehead.machine =
                (buffer[off as usize + 4] as u16) + ((buffer[off as usize + 5] as u16) << 8);
            pehead.numofsec =
                (buffer[off as usize + 6] as u16) + ((buffer[off as usize + 7] as u16) << 8);
            pehead.sizeoptionalheader =
                (buffer[off as usize + 20] as u16) + ((buffer[off as usize + 21] as u16) << 8);
            pehead.characteristics =
                (buffer[off as usize + 22] as u16) + ((buffer[off as usize + 23] as u16) << 8);
            println!("{:#x?}", pehead);
            let oh_off = off + 24;
            let opthead = load_pe64_header(buffer, oh_off);
            println!("\n{:#x?}", opthead);
            
        } else {
            println!("Not a PE file");
        }
    }
}
