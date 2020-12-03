use std::fs::File;
use std::io::SeekFrom;
use std::io::prelude::*;
use std::path::Path;
use std::fmt;
use colored::*;

mod types;
use types::*;

mod helpers;


/// Represents the different mitigations on RELRO
#[derive(Debug)]
enum RelRo {
    NoRelRo,
    PartialRelRo,
    FullRelRo,
}

impl fmt::Display for RelRo {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl Default for RelRo {
    fn default() -> Self {
        RelRo::NoRelRo
    }
}

/// Describes the security options enabled for an `ELF`
#[derive(Default, Debug)]
pub struct SecurityOptions {
    canary : bool,
    nx     : bool,
    relro  : RelRo,
    pie    : bool,
}

impl fmt::Display for SecurityOptions {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let canary_colored = match self.canary {
            true => self.canary.to_string().green(),
            false => self.canary.to_string().red(),
        };
        let nx_colored = match self.nx {
            true => self.nx.to_string().green(),
            false => self.nx.to_string().red(),
        };
        let relro_colored = match self.relro {
            RelRo::NoRelRo => self.relro.to_string().red(),
            RelRo::PartialRelRo => self.relro.to_string().yellow(),
            RelRo::FullRelRo => self.relro.to_string().green(),
        };
        let pie_colored = match self.pie {
            true => self.pie.to_string().green(),
            false => self.pie.to_string().red(),
        };
        write!(f, "Canary\t\t: {}\nNX\t\t: {}\nRELRO\t\t: {}\nPIE\t\t: {}", 
               canary_colored,
               nx_colored,
               relro_colored,
               pie_colored)
    }
}

impl SecurityOptions {
    /// Return enabled Security options from an `ELF`
    pub fn get_options_64(elf : &ELF64, io : &mut std::fs::File) 
        -> Option<SecurityOptions> {

        let mut secop = SecurityOptions::default();
        
        // Get reference to the section header strtab
        let shstrtab_section = elf.sht.get(elf.header.e_shstrndx as usize)?;
        io.seek(SeekFrom::Start(shstrtab_section.sh_offset)).ok()?;
        let mut buf = vec![0; shstrtab_section.sh_size as usize];
        io.read_exact(&mut buf).ok()?;
        let shstrtab = String::from_utf8(buf).expect("Could not read .shstrtab");
        
        let index_strtab = shstrtab.find(".strtab").expect("Could not find .strtab");

        // Check if canary is present

        // Get reference to the symbol table
        let mut iter = elf.sht.iter();
        let symtab = iter.find(|&x| x.sh_name == index_strtab as u32)
            .expect("Could not find STRTAB .strtab section");

        io.seek(SeekFrom::Start(symtab.sh_offset)).ok()?;
        
        // Read strtab
        let mut buf = vec![0; symtab.sh_size as usize];
        io.read_exact(&mut buf).expect("Error reading string table");
        
        // Check if strtab contains __stack_chk_fail
        let symbols = String::from_utf8(buf).expect("Could not read .symtab");
        if symbols.contains("__stack_chk_fail") {
            secop.canary = true;
        }

        // Check if NX is present 
        
        // Get reference to gnu_stack 
        let mut iter = elf.pht.iter();
        let gnu_stack = iter.find(|&x| x.p_type == PType::PtGnuStack)
            .expect("Could not find gnu_stack segment");

        secop.nx = !gnu_stack.has_x();


        // Check RELRO level

        // Get reference to GNU RELRO
        let mut iter = elf.pht.iter();
        let gnu_relro = iter.find(|&x| x.p_type == PType::PtGnuRelro);

        if gnu_relro.is_some() {
            if !shstrtab.contains(".got.plt") { secop.relro = RelRo::FullRelRo; }
            else { secop.relro = RelRo::PartialRelRo; }
        } else { secop.relro = RelRo::NoRelRo; }
        
        // Check if PIE is present
        // If the binary is a shared object (of type EtDyn), PIE
        // If the binary is of type EtExec, no PIE

        secop.pie = match elf.header.e_type {
            EType::EtDyn => true,
            EType::EtExec => false,
            _ => unimplemented!(),
        };

        Some(secop)
    }

    /// Return enabled Security options from an `ELF`
    pub fn get_options_32(elf : &ELF32, io : &mut std::fs::File) 
        -> Option<SecurityOptions> {

        let mut secop = SecurityOptions::default();
        
        // Get reference to the section header strtab
        let shstrtab_section = elf.sht.get(elf.header.e_shstrndx as usize)?;
        io.seek(SeekFrom::Start(shstrtab_section.sh_offset as u64)).ok()?;
        let mut buf = vec![0; shstrtab_section.sh_size as usize];
        io.read_exact(&mut buf).ok()?;
        let shstrtab = String::from_utf8(buf).expect("Could not read .shstrtab");
        
        let index_strtab = shstrtab.find(".strtab").expect("Could not find .strtab");

        // Check if canary is present

        // Get reference to the symbol table
        let mut iter = elf.sht.iter();
        let symtab = iter.find(|&x| x.sh_name == index_strtab as u32)
            .expect("Could not find STRTAB .strtab section");

        io.seek(SeekFrom::Start(symtab.sh_offset as u64)).ok()?;
        
        // Read strtab
        let mut buf = vec![0; symtab.sh_size as usize];
        io.read_exact(&mut buf).expect("Error reading string table");
        
        // Check if strtab contains __stack_chk_fail
        let symbols = String::from_utf8(buf).expect("Could not read .symtab");
        if symbols.contains("__stack_chk_fail") {
            secop.canary = true;
        }

        // Check if NX is present 
        
        // Get reference to gnu_stack 
        let mut iter = elf.pht.iter();
        let gnu_stack = iter.find(|&x| x.p_type == PType::PtGnuStack)
            .expect("Could not find gnu_stack segment");

        secop.nx = !gnu_stack.has_x();


        // Check RELRO level

        // Get reference to GNU RELRO
        let mut iter = elf.pht.iter();
        let gnu_relro = iter.find(|&x| x.p_type == PType::PtGnuRelro);

        if gnu_relro.is_some() {
            if !shstrtab.contains(".got.plt") { secop.relro = RelRo::FullRelRo; }
            else { secop.relro = RelRo::PartialRelRo; }
        } else { secop.relro = RelRo::NoRelRo; }
        
        // Check if PIE is present
        // If the binary is a shared object (of type EtDyn), PIE
        // If the binary is of type EtExec, no PIE

        secop.pie = match elf.header.e_type {
            EType::EtDyn => true,
            EType::EtExec => false,
            _ => unimplemented!(),
        };

        Some(secop)
    }
}

/*
/// Represents an ELF executable
pub struct ELF {
    // Header for the file
    pub header   : Elf64Ehdr,
    // Program header table
    pub pht      : Vec<Elf64Phdr>,
    // Section header table
    pub sht      : Vec<Elf64Shdr>,
    // Security options enabled for the ELF
    pub mitigations : SecurityOptions,
}

/// Impl default method to initialize an `ELF` object
impl Default for ELF {
    fn default() -> Self { 
        ELF {
            header      : Elf64Ehdr::default(),
            pht         : Vec::new(),
            sht         : Vec::new(),
            mitigations : SecurityOptions::default(),
        } 
    }
}
*/

/// Macro that setups the functions and structs for 64 and 32 bits
/// architectures
macro_rules! setup_arch {
    ($name:ident, $header_type:ty, $ph_type:ty, $sh_type:ty) => {
        
        /// Represents an ELF executable
        pub struct $name {
            // Header for the file
            pub header   : $header_type,
            // Program header table
            pub pht      : Vec<$ph_type>,
            // Section header table
            pub sht      : Vec<$sh_type>,
            // Security options enabled for the ELF
            pub mitigations : SecurityOptions,
        }

        /// Impl default method to initialize an `ELF` object
        impl Default for $name {
            fn default() -> Self { 
                $name {
                    header      : <$header_type>::default(),
                    pht         : Vec::new(),
                    sht         : Vec::new(),
                    mitigations : SecurityOptions::default(),
                } 
            }
        }

        impl $name {
            /// Loads an `ELF` file from a `Path`
            pub fn load<P : AsRef<Path>>(path_to_file : P) -> Option<$name> {
                let mut elf = $name::default();

                let mut file = File::open(path_to_file).expect("File not found");
            
                // Parse Header 

                elf.header = <$header_type>::from_io(&mut file)
                    .expect("Header parsing error");

                // ======================== Parse Program Header Table
                let mut proght : Vec<$ph_type> = 
                    Vec::with_capacity(elf.header.e_phnum as usize);

                // Set reader cursor to the position of the section header table
                // in the file
                file.seek(SeekFrom::Start(elf.header.e_phoff as u64))
                    .expect("Cannot set cursor to pht offset");

                // Push all pht entries in the pht
                for _ in 0..elf.header.e_phnum {
                    let phtentry = <$ph_type>::from_io(&mut file).unwrap();
                    proght.push(phtentry);
                }

                // ========================  Parse Section Header Table
                let mut secht : Vec<$sh_type> = 
                    Vec::with_capacity(elf.header.e_shnum as usize);

                // Set reader cursor to the position of the section header table
                // in the file
                file.seek(SeekFrom::Start(elf.header.e_shoff as u64))
                    .expect("Cannot set cursor to sht offset");

                // Push all sht entries in the sht
                for _ in 0..elf.header.e_shnum {
                    let shtentry = <$sh_type>::from_io(&mut file).unwrap();
                    secht.push(shtentry);
                }

                elf.pht = proght;
                elf.sht = secht;

                //elf.mitigations = SecurityOptions::get_options(&elf, &mut file)
                //    .expect("Error detecting mitigations");

                Some(elf)
            }
        }
    }
}

setup_arch!(ELF64, Elf64Ehdr, Elf64Phdr, Elf64Shdr);
setup_arch!(ELF32, Elf32Ehdr, Elf32Phdr, Elf32Shdr);
/*
pub fn load_elf<P: AsRef<Path>, T: ELF>(path_to_file : P) -> Option<T> {
    let mut file = File::open(path_to_file).expect("File not found");
    let mut buf = [0; 5];
    match buf[4] {
        1u8 => return Some(ELF64::load(path_to_file).unwrap()),
        2u8 => return Some(ELF32::load(path_to_file).unwrap()),
        _ => unimplemented!(),
    }
}
*/
/*
impl ELF {
    /// Loads an `ELF` file from a `Path`
    pub fn load<P : AsRef<Path>>(path_to_file : P) -> Option<ELF> {
        let mut elf = ELF::default();

        let mut file = File::open(path_to_file).expect("File not found");
    
        // Parse Header 

        elf.header = Elf64Ehdr::from_io(&mut file).expect("Header parsing error");

        // ======================== Parse Program Header Table
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

        // ========================  Parse Section Header Table
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

        elf.pht = proght;
        elf.sht = secht;

        elf.mitigations = SecurityOptions::get_options(&elf, &mut file)
            .expect("Error retrieving mitigations");

        Some(elf)
    }
}
*/
