//https://docs.rs/pelite/0.8.0/pelite/image/struct.IMAGE_NT_HEADERS64.html

pub use self::peform::ImageDosHeader;
pub use self::peform::ImageFileHeader;
pub use self::peform::ImageOptionalHeader64;
pub use self::peform::ImageOptionalHeader32;

pub use self::peform::load_dos_header;
pub use self::peform::load_file_header;
pub use self::peform::load_pe64_header;
pub use self::peform::load_pe32_header;

mod peform {

#[derive(Debug)]
pub struct ImageDosHeader {
    pub e_magic: u16,
    pub e_cblp: u16,
    pub e_cp: u16,
    pub e_crlc: u16,
    pub e_cparhdr: u16,
    pub e_minalloc: u16,
    pub e_maxalloc: u16,
    pub e_ss: u16,
    pub e_sp: u16,
    pub e_csum: u16,
    pub e_ip: u16,
    pub e_cs: u16,
    pub e_lfarlc: u16,
    pub e_ovno: u16,
    pub e_res: [u16; 4],
    pub e_oemid: u16,
    pub e_oeminfo: u16,
    pub e_res2: [u16; 10],
    pub e_lfanew: u32
}

pub fn load_dos_header(buffer: &std::vec::Vec<u8>) -> ImageDosHeader {
    let doshead = ImageDosHeader {
        e_magic: (buffer[0] as u16) + ((buffer[1] as u16) << 8),
        e_cblp: (buffer[2] as u16) + ((buffer[3] as u16) << 8),
        e_cp: (buffer[4] as u16) + ((buffer[5] as u16) << 8),
        e_crlc: (buffer[6] as u16) + ((buffer[7] as u16) << 8),
        e_cparhdr: (buffer[8] as u16) + ((buffer[9] as u16) << 8),
        e_minalloc: (buffer[10] as u16) + ((buffer[11] as u16) << 8),
        e_maxalloc: (buffer[12] as u16) + ((buffer[13] as u16) << 8),
        e_ss: (buffer[14] as u16) + ((buffer[15] as u16) << 8),
        e_sp: (buffer[16] as u16) + ((buffer[17] as u16) << 8),
        e_csum: (buffer[18] as u16) + ((buffer[19] as u16) << 8),
        e_ip: (buffer[20] as u16) + ((buffer[21] as u16) << 8),
        e_cs: (buffer[22] as u16) + ((buffer[23] as u16) << 8),
        e_lfarlc: (buffer[24] as u16) + ((buffer[25] as u16) << 8),
        e_ovno: (buffer[26] as u16) + ((buffer[27] as u16) << 8),
        e_res: [
            (buffer[28] as u16) + ((buffer[29] as u16) << 8),
            (buffer[30] as u16) + ((buffer[31] as u16) << 8),
            (buffer[32] as u16) + ((buffer[33] as u16) << 8),
            (buffer[34] as u16) + ((buffer[35] as u16) << 8)
            ],
        e_oemid: (buffer[36] as u16) + ((buffer[37] as u16) << 8),
        e_oeminfo: (buffer[38] as u16) + ((buffer[39] as u16) << 8),
        e_res2: [
            (buffer[40] as u16) + ((buffer[41] as u16) << 8),
            (buffer[42] as u16) + ((buffer[43] as u16) << 8),
            (buffer[44] as u16) + ((buffer[45] as u16) << 8),
            (buffer[46] as u16) + ((buffer[47] as u16) << 8),
            (buffer[48] as u16) + ((buffer[49] as u16) << 8),
            (buffer[50] as u16) + ((buffer[51] as u16) << 8),
            (buffer[52] as u16) + ((buffer[53] as u16) << 8),
            (buffer[54] as u16) + ((buffer[55] as u16) << 8),
            (buffer[56] as u16) + ((buffer[57] as u16) << 8),
            (buffer[58] as u16) + ((buffer[59] as u16) << 8)
        ],
        e_lfanew: (buffer[60] as u32) + ((buffer[61] as u32) << 8) + ((buffer[62] as u32) << 16) + ((buffer[63] as u32) << 24)
    };
    return doshead;
}

#[derive(Debug)]
pub struct ImageFileHeader {
    pub magic: u32,
    pub machine: u16,
    pub number_of_sections: u16,
    pub time_date_stamp: u32,
    pub pointer_to_symbol_table: u32,
    pub number_of_symbols: u32,
    pub size_of_optional_header: u16,
    pub characteristics: u16
}

pub fn load_file_header(buffer: &std::vec::Vec<u8>, oh_off: u32) -> ImageFileHeader {
    let filehead = ImageFileHeader {
        magic: (buffer[oh_off as usize] as u32)
        + ((buffer[oh_off as usize + 1] as u32) << 8)
        + ((buffer[oh_off as usize + 2] as u32) << 16)
        + ((buffer[oh_off as usize + 3] as u32) << 24),
        machine: (buffer[oh_off as usize +4] as u16) + ((buffer[oh_off as usize + 5] as u16) << 8),
        number_of_sections: (buffer[oh_off as usize+6] as u16) + ((buffer[oh_off as usize + 7] as u16) << 8),
        time_date_stamp: (buffer[oh_off as usize + 8] as u32)
        + ((buffer[oh_off as usize + 9] as u32) << 8)
        + ((buffer[oh_off as usize + 10] as u32) << 16)
        + ((buffer[oh_off as usize + 11] as u32) << 24),
        pointer_to_symbol_table: (buffer[oh_off as usize + 12] as u32)
        + ((buffer[oh_off as usize + 13] as u32) << 8)
        + ((buffer[oh_off as usize + 14] as u32) << 16)
        + ((buffer[oh_off as usize + 15] as u32) << 24),
        number_of_symbols: (buffer[oh_off as usize + 16] as u32)
        + ((buffer[oh_off as usize + 17] as u32) << 8)
        + ((buffer[oh_off as usize + 18] as u32) << 16)
        + ((buffer[oh_off as usize + 19] as u32) << 24),
        size_of_optional_header: (buffer[oh_off as usize+20] as u16) + ((buffer[oh_off as usize + 21] as u16) << 8),
        characteristics: (buffer[oh_off as usize+22] as u16) + ((buffer[oh_off as usize + 23] as u16) << 8)
    };
    return filehead;
}

#[derive(Debug)]
pub struct ImageOptionalHeader64 {
    pub magic: u16,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: u32,
    pub base_of_code: u32,
    pub image_base: u64,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub major_operating_system_version: u16,
    pub minor_operating_system_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub win32_version_value: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub check_sum: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub size_of_stack_reserve: u64,
    pub size_of_stack_commit: u64,
    pub size_of_heap_reserve: u64,
    pub size_of_heap_commit: u64,
    pub loader_flags: u32,
    pub number_of_rva_and_sizes: u32,
}


pub fn load_pe64_header(buffer: &std::vec::Vec<u8>, oh_off: u32) -> ImageOptionalHeader64 {
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

#[derive(Debug)]
pub struct ImageOptionalHeader32 {
    pub magic: u16,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: u32,
    pub base_of_code: u32,
    pub image_base: u32,
    pub data_base: u32,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub major_operating_system_version: u16,
    pub minor_operating_system_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub win32_version_value: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub check_sum: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub size_of_stack_reserve: u32,
    pub size_of_stack_commit: u32,
    pub size_of_heap_reserve: u32,
    pub size_of_heap_commit: u32,
    pub loader_flags: u32,
    pub number_of_rva_and_sizes: u32,
}


pub fn load_pe32_header(buffer: &std::vec::Vec<u8>, oh_off: u32) -> ImageOptionalHeader32 {
    let opthead = ImageOptionalHeader32 {
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
        image_base: (buffer[oh_off as usize + 24] as u32)
            + ((buffer[oh_off as usize + 25] as u32) << 8)
            + ((buffer[oh_off as usize + 26] as u32) << 16)
            + ((buffer[oh_off as usize + 27] as u32) << 24),
        data_base: (buffer[oh_off as usize + 28] as u32)
            + ((buffer[oh_off as usize + 29] as u32) << 8)
            + ((buffer[oh_off as usize + 30] as u32) << 16)
            + ((buffer[oh_off as usize + 31] as u32) << 24),
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
        size_of_stack_reserve: (buffer[oh_off as usize + 72] as u32)
            + ((buffer[oh_off as usize + 73] as u32) << 8)
            + ((buffer[oh_off as usize + 74] as u32) << 16)
            + ((buffer[oh_off as usize + 75] as u32) << 24),
        size_of_stack_commit: (buffer[oh_off as usize + 76] as u32)
            + ((buffer[oh_off as usize + 77] as u32) << 8)
            + ((buffer[oh_off as usize + 78] as u32) << 16)
            + ((buffer[oh_off as usize + 79] as u32) << 24),
        size_of_heap_reserve: (buffer[oh_off as usize + 80] as u32)
            + ((buffer[oh_off as usize + 81] as u32) << 8)
            + ((buffer[oh_off as usize + 82] as u32) << 16)
            + ((buffer[oh_off as usize + 83] as u32) << 24),
        size_of_heap_commit: (buffer[oh_off as usize + 84] as u32)
            + ((buffer[oh_off as usize + 85] as u32) << 8)
            + ((buffer[oh_off as usize + 86] as u32) << 16)
            + ((buffer[oh_off as usize + 87] as u32) << 24),
        loader_flags: (buffer[oh_off as usize + 88] as u32)
            + ((buffer[oh_off as usize + 89] as u32) << 8)
            + ((buffer[oh_off as usize + 90] as u32) << 16)
            + ((buffer[oh_off as usize + 91] as u32) << 24),
        number_of_rva_and_sizes: (buffer[oh_off as usize + 92] as u32)
            + ((buffer[oh_off as usize + 93] as u32) << 8)
            + ((buffer[oh_off as usize + 94] as u32) << 16)
            + ((buffer[oh_off as usize + 95] as u32) << 24),
    };
    return opthead;
}


}
