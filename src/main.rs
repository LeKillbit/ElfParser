extern crate num_traits;
extern crate enum_primitive_derive;

mod elf;
use elf::ELF;

fn main() {
    let elf : ELF = ELF::load("/home/killbit/programming/test_binary/test")
        .expect("Error in reading elf file");
    println!("Entry point : 0x{:08x}", elf.header.e_entry);
    println!("Number of entries in the program header table : {}", elf.header.e_phnum);
    println!("Number of entries in the section header table : {}", elf.header.e_shnum);
}
