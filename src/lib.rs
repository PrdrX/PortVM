#![allow(dead_code)]
#![allow(non_camel_case_types)]
#![allow(unused_imports)]
#![allow(unused_variables)]

#[path = "main.rs"]
pub mod main;

pub mod input;

pub use input::{parse_public_tables_file, parse_public_tables_text, TextInputError};

pub const MIN_CIRCUIT_K: u32 = 17;

pub fn validate_circuit_k(k: u32) -> Result<(), String> {
    if k < MIN_CIRCUIT_K {
        return Err(format!(
            "unsupported k: {k}; this circuit requires k >= {MIN_CIRCUIT_K} because its fixed tables and fixed-column assignments do not fit smaller domains"
        ));
    }
    Ok(())
}
