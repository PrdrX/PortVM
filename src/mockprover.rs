use portvm::input::parse_public_tables_file;
use portvm::main::{generate_witness_from_tables, GeneratedWitness};
use std::env;
use std::path::PathBuf;
use std::process::ExitCode;

fn usage(program: &str) -> String {
    format!(
        "Usage:\n  {program} --k <k> --input <tables.txt>\n  {program} --k <k> --witness <witness.bin>\n"
    )
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(RunError::Help(text)) => {
            print!("{text}");
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("{err}");
            ExitCode::FAILURE
        }
    }
}

enum RunError {
    Help(String),
    Message(String),
}

impl std::fmt::Display for RunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Help(text) | Self::Message(text) => f.write_str(text),
        }
    }
}

fn run() -> Result<(), RunError> {
    let mut args = env::args().skip(1);
    let mut k = None;
    let mut input_path = None;
    let mut witness_path = None;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--k" => {
                let value = args
                    .next()
                    .ok_or_else(|| RunError::Message("--k requires a value".to_string()))?;
                k = Some(
                    value
                        .parse::<u32>()
                        .map_err(|_| RunError::Message(format!("invalid k value: {value}")))?,
                );
            }
            "--input" => {
                let value = args
                    .next()
                    .ok_or_else(|| RunError::Message("--input requires a path".to_string()))?;
                input_path = Some(PathBuf::from(value));
            }
            "--witness" => {
                let value = args
                    .next()
                    .ok_or_else(|| RunError::Message("--witness requires a path".to_string()))?;
                witness_path = Some(PathBuf::from(value));
            }
            "--help" | "-h" => {
                let program = env::args()
                    .next()
                    .unwrap_or_else(|| "mockprover".to_string());
                return Err(RunError::Help(usage(&program)));
            }
            other => {
                return Err(RunError::Message(format!("unknown argument: {other}")));
            }
        }
    }

    let program = env::args()
        .next()
        .unwrap_or_else(|| "mockprover".to_string());
    let k = k.ok_or_else(|| RunError::Help(usage(&program)))?;

    let generated_witness = match (input_path, witness_path) {
        (Some(_), Some(_)) => {
            return Err(RunError::Message(
                "choose exactly one of --input or --witness".to_string(),
            ))
        }
        (None, None) => return Err(RunError::Help(usage(&program))),
        (Some(input_path), None) => {
            let tables = parse_public_tables_file(&input_path)
                .map_err(|err| RunError::Message(format!("input parsing failed: {err}")))?;
            generate_witness_from_tables(tables)
                .map_err(|err| RunError::Message(format!("witness generation failed: {err}")))?
                .generated_witness
        }
        (None, Some(witness_path)) => GeneratedWitness::read_from_file(&witness_path)
            .map_err(|err| RunError::Message(format!("witness read failed: {err}")))?,
    };

    generated_witness
        .mock_verify(k)
        .map_err(|err| RunError::Message(format!("MockProver rejected the witness: {err}")))?;

    println!(
        "MockProver accepted the witness (k={}, cpu={}, alu={}, copy={}, rw={})",
        k,
        generated_witness.logical_cpu_rows,
        generated_witness.logical_alu_rows,
        generated_witness.logical_copy_rows,
        generated_witness.logical_rw_rows
    );

    Ok(())
}
