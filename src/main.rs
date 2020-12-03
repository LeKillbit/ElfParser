extern crate num_traits;
extern crate enum_primitive_derive;
extern crate colored;

use std::env;
use std::process;
use std::fs::File;
use std::io::Read;

mod elf;
use elf::*;

fn usage() {
    println!("./elf_parser <filename>");
}

fn main() {
    let args : Vec<String> = env::args().collect();
    if args.len() < 2 {
        usage();
        process::exit(1);
    }
    let filename = &args[1];
    
    let mut file = File::open(filename).expect("File not found");
    let mut buf = [0; 5];
    file.read_exact(&mut buf);
    if buf[4] == 2u8 {
        let mut elf_file = ELF64::load(filename).unwrap();
        elf_file.mitigations = SecurityOptions::get_options_64(&elf_file, &mut file)
            .unwrap();
        println!("Entry point\t: 0x{:08x}", elf_file.header.e_entry);
        println!("Machine\t\t: {}", elf_file.header.e_machine);
        println!("Class\t\t: {}", elf_file.header.e_ident.class);
        println!("{}", elf_file.mitigations);
    } else {
        let mut elf_file = ELF32::load(filename).unwrap();
        elf_file.mitigations = SecurityOptions::get_options_32(&elf_file, &mut file)
            .unwrap();
        println!("Entry point\t: 0x{:08x}", elf_file.header.e_entry);
        println!("Machine\t\t: {}", elf_file.header.e_machine);
        println!("Class\t\t: {}", elf_file.header.e_ident.class);
        println!("{}", elf_file.mitigations);
    }
    
}
