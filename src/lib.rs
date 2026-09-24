#![allow(dead_code)]
#![allow(non_camel_case_types)]
#![allow(unused_imports)]
#![allow(unused_variables)]

#[path = "main.rs"]
pub mod main;

pub mod input;

pub use input::{parse_public_tables_file, parse_public_tables_text, TextInputError};
