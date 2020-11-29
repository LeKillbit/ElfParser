use std::fs::File;
use std::io::SeekFrom;
use std::io::prelude::*;

mod types;
use types::*;

mod helpers;

/// Represents an ELF executable
pub struct ELF {
    // Header for the file
    pub header : Elf64Ehdr,
    // Program header table
    pub pht    : Vec<Elf64Phdr>,
    // Section header table
    pub sht    : Vec<Elf64Shdr>,
}

/// Default ELF Header for creating a struct 
impl Default for ELF {
    fn default() -> Self { 
        ELF {
            header : Elf64Ehdr::default(),
            pht    : Vec::new(),
            sht    : Vec::new(),
        } 
    }
}

impl ELF {

    // Loads an ELF file from a filename
    pub fn load(path_to_file : &str) -> Option<ELF> {
        let mut elf = ELF::default();

        let mut file = File::open(path_to_file).expect("File not found");
    
        // Parse Header 
        elf.header = Elf64Ehdr::from_io(&mut file).expect("Header parsing error");

        // Parse Program Header Table
        let mut proght : Vec<Elf64Phdr> = 
            Vec::with_capacity(elf.header.e_phnum as usize);

        // Set reader cursor to the position of the section header table
        // in the file
        file.seek(SeekFrom::Start(elf.header.e_phoff))
            .expect("Cannot set cursor to pht offset");

        // Push all pht entries in the pht
        for _ in 0..elf.header.e_phnum {
            let phtentry = Elf64Phdr::from_io(&mut file).unwrap();
            proght.push(phtentry);
        }

        // Parse Section Header Table
        let mut secht : Vec<Elf64Shdr> = 
            Vec::with_capacity(elf.header.e_shnum as usize);

        // Set reader cursor to the position of the section header table
        // in the file
        file.seek(SeekFrom::Start(elf.header.e_shoff))
            .expect("Cannot set cursor to sht offset");

        // Push all sht entries in the sht
        for _ in 0..elf.header.e_shnum {
            let shtentry = Elf64Shdr::from_io(&mut file).unwrap();
            secht.push(shtentry);
        }

        Some(elf)
    }
}
