use portvm::input::parse_public_tables_file;
use portvm::main::generate_witness_from_tables;
use std::env;
use std::path::PathBuf;
use std::process::ExitCode;

fn usage(program: &str) -> String {
    format!("Usage:\n  {program} --input <tables.txt> --out <witness.bin>\n")
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
    let mut input_path = None;
    let mut out_path = None;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--input" => {
                let value = args
                    .next()
                    .ok_or_else(|| RunError::Message("--input requires a path".to_string()))?;
                input_path = Some(PathBuf::from(value));
            }
            "--out" => {
                let value = args
                    .next()
                    .ok_or_else(|| RunError::Message("--out requires a path".to_string()))?;
                out_path = Some(PathBuf::from(value));
            }
            "--help" | "-h" => {
                let program = env::args()
                    .next()
                    .unwrap_or_else(|| "witness_gen".to_string());
                return Err(RunError::Help(usage(&program)));
            }
            other => {
                return Err(RunError::Message(format!("unknown argument: {other}")));
            }
        }
    }

    let program = env::args()
        .next()
        .unwrap_or_else(|| "witness_gen".to_string());
    let input_path = input_path.ok_or_else(|| RunError::Help(usage(&program)))?;
    let out_path = out_path.ok_or_else(|| RunError::Help(usage(&program)))?;

    let tables = parse_public_tables_file(&input_path)
        .map_err(|err| RunError::Message(format!("input parsing failed: {err}")))?;
    let bundle = generate_witness_from_tables(tables)
        .map_err(|err| RunError::Message(format!("witness generation failed: {err}")))?;
    bundle
        .generated_witness
        .write_to_file(&out_path)
        .map_err(|err| RunError::Message(format!("witness write failed: {err}")))?;

    println!(
        "Witness written to {} (cpu={}, alu={}, copy={}, rw={}, public_columns={})",
        out_path.display(),
        bundle.generated_witness.logical_cpu_rows,
        bundle.generated_witness.logical_alu_rows,
        bundle.generated_witness.logical_copy_rows,
        bundle.generated_witness.logical_rw_rows,
        bundle.generated_witness.public_inputs().len()
    );

    Ok(())
}
