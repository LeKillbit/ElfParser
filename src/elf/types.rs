use enum_primitive_derive::Primitive;
use num_traits::FromPrimitive;
use std::convert::TryInto;
use std::fmt;

use crate::elf::helpers::{read_u8, read_u16, read_u32, read_u64};

/// Indicate the OS and Application Binary Interface
#[repr(u8)]
#[derive(Debug, PartialEq, Clone, Primitive)]
pub enum EiOsabi{
    ElfOsabiNONE       = 0,  
    ElfOsabiHPUX       = 1, 
    ElfOsabiNETBSD     = 2,
    ElfOsabiLINUX      = 3,   
    ElfOsabiAIX        = 7,  
    ElfOsabiIRIX       = 8,  
    ElfOsabiFREEBSD    = 9, 
    ElfOsabiTRU64      = 10,  
    ElfOsabiMODESTO    = 11,
    ElfOsabiOPENBSD    = 12,
    ElfOsabiOPENVMS    = 13,
    ElfOsabiNSK        = 14,  
    ElfOsabiARMAEABI   = 64,
    ElfOsabiARM        = 97,
    ElfOsabiSTANDALONE = 255,
}

/// Indicate version of ELF file
#[repr(u8)]
#[derive(Debug, PartialEq, Clone, Primitive)]
pub enum EiVersion {
    // Invalid version
    EvNone    = 0, 
    // Actual version
    EvCurrent = 1,
}

/// Indicate endiannes of ELF file
#[repr(u8)]
#[derive(Debug, PartialEq, Clone, Primitive)]
pub enum EiData {
    ElfDataNone = 0,
    ElfData2Lsb = 1,
    ElfData2Msb = 2,
}

/// Indicate the ELF architecture (x32 or x64)
#[repr(u8)]
#[derive(Debug, PartialEq, Clone, Primitive)]
pub enum EiClass {
    ElfClassNone = 0u8,
    ElfClass32   = 1u8,
    ElfClass64   = 2u8,
}
impl fmt::Display for EiClass {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// Byte array that explains how to interpret the rest of the file 
#[derive(Debug)]
pub struct EIdentStruct {
    pub magic :       [u8; 4],
    pub class :       EiClass,
    pub endianness :  EiData,
    pub version :     EiVersion,
    pub osabi :       EiOsabi,
    pub abi_version : u8,
}

/// Default method to create a new pub struct
impl Default for EIdentStruct {
    fn default() -> Self {
        EIdentStruct{
            magic       : [0x7f, 0x45, 0x4c, 0x46],
            class       : EiClass::ElfClassNone,
            endianness  : EiData::ElfDataNone,
            version     : EiVersion::EvNone,
            osabi       : EiOsabi::ElfOsabiNONE,
            abi_version : 0,
        }
    }
}

/// Indicate type of object file
#[repr(u16)]
#[derive(Debug, PartialEq, Clone, Primitive)]
pub enum EType {
    EtNone = 0,
    EtRel  = 1,
    EtExec = 2,
    EtDyn  = 3,
    EtCore = 4,
}

impl fmt::Display for EType {
    fn fmt(&self, f : &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// Indicate the required architecture for the file
#[repr(u16)]
#[derive(Debug, PartialEq, Clone, Primitive)]
pub enum EMachine {
    EmNone        = 0,
    EmM32         = 1,
    EmSparc       = 2,
    Em386         = 3,
    Em68K         = 4,
    Em88K         = 5,
    Em860         = 7,
    EmMips        = 8,
    EmPAriscV     = 15,
    EmSparc32Plus = 18, 
    EmPPC         = 20,
    EmPPC64       = 21,
    EmS390        = 22,
    EmARM         = 40,
    EmSH          = 42,
    EmSPARCv9     = 43,
    EmIA64        = 50,
    Emx86_64      = 62,
    EmVax         = 75, 
    EmRISCV       = 243,
}

impl fmt::Display for EMachine {
    fn fmt(&self, f : &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}


/// Header version 
#[repr(u32)]
#[derive(Debug, PartialEq, Clone, Primitive)]
pub enum EVersion {
    EvNone    = 0u32,
    EvCurrent = 1u32,
    EvNum     = 2u32,
}

/// Elf header
#[derive(Debug)]
pub struct Elf64Ehdr {
    pub e_ident :      EIdentStruct,  // location of Segments/Sections Tables
    pub e_type :       EType,    // shared object, executable...
    pub e_machine :    EMachine, // arch for the executable
    pub e_version :    EVersion,
    pub e_entry :      u64,  // entry point of the program
    pub e_phoff :      u64,  // program header table's offset 
    pub e_shoff :      u64,  // section header table's offset
    pub e_flags :      u32,  // processor specific flags
    pub e_ehsize :     u16,  // Header size
    pub e_phentsize :  u16,  // Size of one entry in the program header table
    pub e_phnum :      u16,  // Number of entries in the program header table
    pub e_shentsize :  u16,  // Size of a section header
    pub e_shnum :      u16,  // Number of entries in the section header table
    pub e_shstrndx :   u16,  // Section header table index of the entry 
                             // associated with the section name string table
}

impl Default for Elf64Ehdr {
    fn default() -> Self {
        Elf64Ehdr {
            e_ident     : EIdentStruct::default(),
            e_type      : EType::EtNone, 
            e_machine   : EMachine::EmNone,
            e_version   : EVersion::EvNone,
            e_entry     : 0,
            e_phoff     : 0,
            e_shoff     : 0,
            e_flags     : 0,  
            e_ehsize    : 0, 
            e_phentsize : 0,
            e_phnum     : 0,
            e_shentsize : 0, 
            e_shnum     : 0, 
            e_shstrndx  : 0, 
        }
    }
}

impl Elf64Ehdr {
    /// Parse ELF Header 
    pub fn from_io(mut io : &mut dyn std::io::Read) -> Option<Elf64Ehdr> {
        
        let mut header = Elf64Ehdr::default();

        let mut buf = [0; 16];
        io.read_exact(&mut buf).expect("Cannot read io");

        // Read the e_ident field in Elf64Ehdr
        header.e_ident.magic = buf[0..4].try_into().unwrap();
        assert!(header.e_ident.magic == [0x7f, 0x45, 0x4c, 0x46]);
        header.e_ident.class = match EiClass::from_u8(buf[4]){
            Some(v) => v,
            None => panic!("e_indent class invalid"),
        };
        header.e_ident.endianness = match EiData::from_u8(buf[5]) {
            Some(v) => v,
            None => panic!("e_indent endianness invalid\n"),
        };
        header.e_ident.version = match EiVersion::from_u8(buf[6]) {
            Some(v) => v, 
            None => panic!("e_indent version invalid\n"),
        };
        header.e_ident.osabi = match EiOsabi::from_u8(buf[7]) {
            Some(v) => v, 
            None => panic!("e_indent OS ABI invalid\n"),
        };
        header.e_ident.abi_version = buf[8];
        
        // Read the other fields
        header.e_type = match EType::from_u16(read_u16(&mut io)?) {
            Some(v) => v,
            None => panic!("e_type invalid\n"),
        };

        header.e_machine = match EMachine::from_u16(read_u16(&mut io)?) {
            Some(v) => v,
            None => panic!("e_machine invalid\n"),
        };

        header.e_version = match EVersion::from_u32(read_u32(&mut io)?) {
            Some(v) => v,
            None => panic!("e_version invalid\n"),
        };

        header.e_entry     = read_u64(&mut io)?;
        header.e_phoff     = read_u64(&mut io)?;
        header.e_shoff     = read_u64(&mut io)?;
        header.e_flags     = read_u32(&mut io)?;
        header.e_ehsize    = read_u16(&mut io)?;
        header.e_phentsize = read_u16(&mut io)?;
        header.e_phnum     = read_u16(&mut io)?;
        header.e_shentsize = read_u16(&mut io)?;
        header.e_shnum     = read_u16(&mut io)?;
        header.e_shstrndx  = read_u16(&mut io)?;
        
        Some(header)
    }
}

/// Indicates what kind of segment the Program Header describes
#[repr(u32)]
#[derive(Debug, PartialEq, Clone, Primitive)]
pub enum PType{
    PtNull       = 0,
    PtLoad       = 1,
    PtDynamic    = 2,
    PtInterp     = 3,
    PtNote       = 4,
    PtShlib      = 5,
    PtPhdr       = 6,
    PtTls        = 7,
    PtLoos       = 0x60000000,
    PtHios       = 0x6fffffff,
    PtLoproc     = 0x70000000,
    PtHiproc     = 0x7fffffff,
    PtGnuEhFrame = 0x6474e550,
    PtGnuStack   = 0x6474e551,
    PtGnuRelro   = 0x6474e552,
}

impl fmt::Display for PType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl Default for PType {
    fn default() -> Self {
        PType::PtNull
    }
}

/// Program header
/// Array of pub structures describing a segment or other information the 
/// system needs to prepare the program for execution
#[derive(Default, Debug)]
pub struct Elf64Phdr {
    pub p_type   : PType, // u32, describes the type of the segment
    pub p_flags  : u32,   // R | W | X  
    pub p_offset : u64,   // Offset of the segment
    pub p_vaddr  : u64,   // Virtual address of the first byte of the segment
    pub p_paddr  : u64,   // Physical address of the first byte of the segment
    pub p_filesz : u64,   // Size of the segment in the file
    pub p_memsz  : u64,   // Size of the segment in memory
    pub p_align  : u64,   // Value to which segments are aligned in memory
}

impl Elf64Phdr {
    /// Parse an entry in the program header table
    pub fn from_io(mut io : &mut dyn std::io::Read) 
        -> Option<Elf64Phdr> 
    {
        let mut phdr = Elf64Phdr::default();   
        let val = read_u32(&mut io)?;
        phdr.p_type = match PType::from_u32(val) {
            Some(v) => v,
            None => panic!("PType in PHT parsing incorrect"),
        };

        phdr.p_flags  = read_u32(&mut io)?;
        phdr.p_offset = read_u64(&mut io)?;
        phdr.p_vaddr  = read_u64(&mut io)?;
        phdr.p_paddr  = read_u64(&mut io)?;
        phdr.p_filesz = read_u64(&mut io)?;
        phdr.p_memsz  = read_u64(&mut io)?;
        phdr.p_align  = read_u64(&mut io)?;

        Some(phdr)
    }
    
    /// Check if there is a Read permission on this segment
    pub fn has_r(&self) -> bool {
        (self.p_flags >> 2) & 1 == 1
    }

    /// Check if there is a Write permission on this segment
    pub fn has_w(&self) -> bool {
        (self.p_flags >> 1) & 1 == 1
    }

    /// Check if there is an Exec permission on this segment
    pub fn has_x(&self) -> bool {
        (self.p_flags >> 0) & 1 == 1
    }
}


/// Categorize section content
#[repr(u32)]
#[derive(Debug, PartialEq, Clone, Primitive)]
pub enum SHType {
    ShtNULL         = 0,
    ShtPROGBITS     = 1,
    ShtSYMTAB       = 2,
    ShtSTRTAB       = 3,
    ShtRELA         = 4,
    ShtHASH         = 5,
    ShtDYNAMIC      = 6,
    ShtNOTE         = 7,
    ShtNOBITS       = 8,
    ShtREL          = 9,
    ShtSHLIB        = 10,
    ShtDYNSYM       = 11,
    ShtINITARRAY    = 14,
    ShtFINIARRAY    = 15,
    ShtPREINITARRAY = 16,
    ShtGROUP        = 17,
    ShtSYMTABSHNDX  = 18,
    ShtNUM          = 19,
    ShtLOOS         = 0x60000000,
    ShtGNUAttr      = 0x6ffffff5,
    ShtGnuHash      = 0x6ffffff6,
    ShtGnuLiblist   = 0x6ffffff7,
    ShtChecksum     = 0x6ffffff8,
    ShtLosunw       = 0x6ffffffa,
    ShtSunwComdat   = 0x6ffffffb,
    ShtSunwSyminfo  = 0x6ffffffc,
    ShtGnuVerdef    = 0x6ffffffd,
    ShtGnuVerneed   = 0x6ffffffe,
    ShtGnuVersym    = 0x6fffffff,
    ShtLOPROC       = 0x70000000,
    ShtHIPROC       = 0x7fffffff,
    ShtLOUSER       = 0x80000000u32,
    ShtHIUSER       = 0xffffffffu32,
}

impl fmt::Display for SHType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl Default for SHType {
    fn default() -> Self {
        SHType::ShtNULL
    }
}

/// Flags that describes misc attributes for a section
#[repr(u64)]
#[derive(Primitive)]
pub enum SHFlags {
    ShfNull          = 0,
    ShfWrite         = 1,
    ShfAlloc         = 2,
    ShfExecInstr     = 4,
    ShfI             = 66,
    ShfRelaLivepatch = 0x00100000,
    ShfRoAfterInit   = 0x00200000,
    ShfMaskProc      = 0xf0000000u64,
}

impl Default for SHFlags {
    fn default() -> Self {
        SHFlags::ShfWrite
    }
}

/// Describe a section of the ELF file
#[derive(Debug, Default, Clone)]
pub struct Elf64Shdr {
    pub sh_name      : u32,     // Index into section header string table, 
                                // gives name location
    pub sh_type      : SHType,  // u32, Categorizes section content
    pub sh_flags     : u64,     // u64, describes misc attributes
    pub sh_addr      : u64,     // Address of section's first byte
    pub sh_offset    : u64,     // Section first byte's offset 
                                //from the beginning of the file
    pub sh_size      : u64,     // Section size
    pub sh_link      : u32,     // Section header table index link
    pub sh_info      : u32,     // Holds extra info
    pub sh_addralign : u64,     // Alignment for the section
    pub sh_entsize   : u64,     // Size of an entry in the section table if it has one
}

impl Elf64Shdr {
    /// Parse an entry in the Section Header Table
    pub fn from_io(mut io: &mut dyn std::io::Read) 
        -> Option<Elf64Shdr> 
    {
        let mut shdr = Elf64Shdr::default();
        
        shdr.sh_name = read_u32(&mut io)?;
        let val = read_u32(&mut io)?;
        shdr.sh_type = match SHType::from_u32(val) {
            Some(v) => v,
            None => panic!("shentry type invalid"),
        };
        shdr.sh_flags     = read_u64(&mut io)?;
        shdr.sh_addr      = read_u64(&mut io)?;
        shdr.sh_offset    = read_u64(&mut io)?;
        shdr.sh_size      = read_u64(&mut io)?;
        shdr.sh_link      = read_u32(&mut io)?;
        shdr.sh_info      = read_u32(&mut io)?;
        shdr.sh_addralign = read_u64(&mut io)?;
        shdr.sh_entsize   = read_u64(&mut io)?;
        
        Some(shdr)
    }
}

/// An entry in the symbol table
#[derive(Default, Debug)]
pub struct Elf64Sym {
    st_name  : u32,     // index into file's symbol string table
    st_info  : u8,      // symbol's type
    st_other : u8,      // symbol's visibility
    st_shndx : u16,     // section header table index
    st_value : u64,     // value of symbol
    st_size  : u64,     // size of symbol
}

impl Elf64Sym {
    /// Parse an entry in the symbol table
    pub fn from_io(mut io : &mut dyn std::io::Read) -> Option<Elf64Sym> {
        let mut entry = Elf64Sym::default();
        
        entry.st_name  = read_u32(&mut io)?;
        entry.st_info  = read_u8(&mut io)?;
        entry.st_other = read_u8(&mut io)?;
        entry.st_shndx = read_u16(&mut io)?;
        entry.st_value = read_u64(&mut io)?;
        entry.st_size  = read_u64(&mut io)?;

        Some(entry)

    }
}

/// Elf32 Header
#[derive(Debug)]
pub struct Elf32Ehdr {
    pub e_ident :      EIdentStruct,  // location of Segments/Sections Tables
    pub e_type :       EType,    // shared object, executable...
    pub e_machine :    EMachine, // arch for the executable
    pub e_version :    EVersion,
    pub e_entry :      u32,  // entry point of the program
    pub e_phoff :      u32,  // program header table's offset 
    pub e_shoff :      u32,  // section header table's offset
    pub e_flags :      u32,  // processor specific flags
    pub e_ehsize :     u16,  // Header size
    pub e_phentsize :  u16,  // Size of one entry in the program header table
    pub e_phnum :      u16,  // Number of entries in the program header table
    pub e_shentsize :  u16,  // Size of a section header
    pub e_shnum :      u16,  // Number of entries in the section header table
    pub e_shstrndx :   u16,  // Section header table index of the entry 
}

impl Default for Elf32Ehdr {
    fn default() -> Self {
        Elf32Ehdr {
            e_ident     : EIdentStruct::default(),
            e_type      : EType::EtNone, 
            e_machine   : EMachine::EmNone,
            e_version   : EVersion::EvNone,
            e_entry     : 0,
            e_phoff     : 0,
            e_shoff     : 0,
            e_flags     : 0,  
            e_ehsize    : 0, 
            e_phentsize : 0,
            e_phnum     : 0,
            e_shentsize : 0, 
            e_shnum     : 0, 
            e_shstrndx  : 0, 
        }
    }
}

impl Elf32Ehdr {
    /// Parse ELF32 Header 
    pub fn from_io(mut io : &mut dyn std::io::Read) -> Option<Elf32Ehdr> {
        
        let mut header = Elf32Ehdr::default();

        let mut buf = [0; 16];
        io.read_exact(&mut buf).expect("Cannot read io");

        // Read the e_ident field in Elf32Ehdr
        header.e_ident.magic = buf[0..4].try_into().unwrap();
        assert!(header.e_ident.magic == [0x7f, 0x45, 0x4c, 0x46]);
        header.e_ident.class = match EiClass::from_u8(buf[4]){
            Some(v) => v,
            None => panic!("e_indent class invalid"),
        };
        header.e_ident.endianness = match EiData::from_u8(buf[5]) {
            Some(v) => v,
            None => panic!("e_indent endianness invalid\n"),
        };
        header.e_ident.version = match EiVersion::from_u8(buf[6]) {
            Some(v) => v, 
            None => panic!("e_indent version invalid\n"),
        };
        header.e_ident.osabi = match EiOsabi::from_u8(buf[7]) {
            Some(v) => v, 
            None => panic!("e_indent OS ABI invalid\n"),
        };
        header.e_ident.abi_version = buf[8];
        
        // Read the other fields
        header.e_type = match EType::from_u16(read_u16(&mut io)?) {
            Some(v) => v,
            None => panic!("e_type invalid\n"),
        };

        header.e_machine = match EMachine::from_u16(read_u16(&mut io)?) {
            Some(v) => v,
            None => panic!("e_machine invalid\n"),
        };

        header.e_version = match EVersion::from_u32(read_u32(&mut io)?) {
            Some(v) => v,
            None => panic!("e_version invalid\n"),
        };

        header.e_entry     = read_u32(&mut io)?;
        header.e_phoff     = read_u32(&mut io)?;
        header.e_shoff     = read_u32(&mut io)?;
        header.e_flags     = read_u32(&mut io)?;
        header.e_ehsize    = read_u16(&mut io)?;
        header.e_phentsize = read_u16(&mut io)?;
        header.e_phnum     = read_u16(&mut io)?;
        header.e_shentsize = read_u16(&mut io)?;
        header.e_shnum     = read_u16(&mut io)?;
        header.e_shstrndx  = read_u16(&mut io)?;
        
        Some(header)
    }
}

/// Program header 32 bits
/// Array of pub structures describing a segment or other information the 
/// system needs to prepare the program for execution
#[derive(Default, Debug)]
pub struct Elf32Phdr {
    pub p_type   : PType, // u32, describes the type of the segment
    pub p_offset : u32,   // Offset of the segment
    pub p_vaddr  : u32,   // Virtual address of the first byte of the segment
    pub p_paddr  : u32,   // Physical address of the first byte of the segment
    pub p_filesz : u32,   // Size of the segment in the file
    pub p_memsz  : u32,   // Size of the segment in memory
    pub p_flags  : u32,   // R | W | X  
    pub p_align  : u32,   // Value to which segments are aligned in memory
}

impl Elf32Phdr {
    /// Parse an entry in the program header table
    pub fn from_io(mut io : &mut dyn std::io::Read) 
        -> Option<Elf32Phdr> 
    {
        let mut phdr = Elf32Phdr::default();   
        let val = read_u32(&mut io)?;
        phdr.p_type = match PType::from_u32(val) {
            Some(v) => v,
            None => panic!("PType in PHT parsing incorrect"),
        };

        phdr.p_offset = read_u32(&mut io)?;
        phdr.p_vaddr  = read_u32(&mut io)?;
        phdr.p_paddr  = read_u32(&mut io)?;
        phdr.p_filesz = read_u32(&mut io)?;
        phdr.p_memsz  = read_u32(&mut io)?;
        phdr.p_flags  = read_u32(&mut io)?;
        phdr.p_align  = read_u32(&mut io)?;

        Some(phdr)
    }
    
    /// Check if there is a Read permission on this segment
    pub fn has_r(&self) -> bool {
        (self.p_flags >> 2) & 1 == 1
    }

    /// Check if there is a Write permission on this segment
    pub fn has_w(&self) -> bool {
        (self.p_flags >> 1) & 1 == 1
    }

    /// Check if there is an Exec permission on this segment
    pub fn has_x(&self) -> bool {
        (self.p_flags >> 0) & 1 == 1
    }
}

/// Describe a section of the ELF file
#[derive(Debug, Default, Clone)]
pub struct Elf32Shdr {
    pub sh_name      : u32,     // Index into section header string table, 
                                // gives name location
    pub sh_type      : SHType,  // u32, Categorizes section content
    pub sh_flags     : u32,     // u32, describes misc attributes
    pub sh_addr      : u32,     // Address of section's first byte
    pub sh_offset    : u32,     // Section first byte's offset 
                                //from the beginning of the file
    pub sh_size      : u32,     // Section size
    pub sh_link      : u32,     // Section header table index link
    pub sh_info      : u32,     // Holds extra info
    pub sh_addralign : u32,     // Alignment for the section
    pub sh_entsize   : u32,     // Size of an entry in the section table if it has one
}

impl Elf32Shdr {
    /// Parse an entry in the Section Header Table
    pub fn from_io(mut io: &mut dyn std::io::Read) 
        -> Option<Elf32Shdr> 
    {
        let mut shdr = Elf32Shdr::default();
        
        shdr.sh_name = read_u32(&mut io)?;
        let val = read_u32(&mut io)?;
        shdr.sh_type = match SHType::from_u32(val) {
            Some(v) => v,
            None => panic!("shentry type invalid"),
        };
        shdr.sh_flags     = read_u32(&mut io)?;
        shdr.sh_addr      = read_u32(&mut io)?;
        shdr.sh_offset    = read_u32(&mut io)?;
        shdr.sh_size      = read_u32(&mut io)?;
        shdr.sh_link      = read_u32(&mut io)?;
        shdr.sh_info      = read_u32(&mut io)?;
        shdr.sh_addralign = read_u32(&mut io)?;
        shdr.sh_entsize   = read_u32(&mut io)?;
        
        Some(shdr)
    }
}

