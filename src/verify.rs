use portvm::main::verify_proof_from_files;
use std::env;
use std::path::PathBuf;
use std::process::ExitCode;

fn usage(program: &str) -> String {
    format!(
        "Usage:\n  {program} --k <k> --params <params.bin> --vk <vk.bin> --proof <proof.bin> --instances <instances.bin>\n"
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
    let mut params_path = None;
    let mut vk_path = None;
    let mut proof_path = None;
    let mut instances_path = None;

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
            "--params" => {
                let value = args
                    .next()
                    .ok_or_else(|| RunError::Message("--params requires a path".to_string()))?;
                params_path = Some(PathBuf::from(value));
            }
            "--vk" => {
                let value = args
                    .next()
                    .ok_or_else(|| RunError::Message("--vk requires a path".to_string()))?;
                vk_path = Some(PathBuf::from(value));
            }
            "--proof" => {
                let value = args
                    .next()
                    .ok_or_else(|| RunError::Message("--proof requires a path".to_string()))?;
                proof_path = Some(PathBuf::from(value));
            }
            "--instances" => {
                let value = args
                    .next()
                    .ok_or_else(|| RunError::Message("--instances requires a path".to_string()))?;
                instances_path = Some(PathBuf::from(value));
            }
            "--help" | "-h" => {
                let program = env::args().next().unwrap_or_else(|| "verify".to_string());
                return Err(RunError::Help(usage(&program)));
            }
            other => return Err(RunError::Message(format!("unknown argument: {other}"))),
        }
    }

    let program = env::args().next().unwrap_or_else(|| "verify".to_string());
    let k = k.ok_or_else(|| RunError::Help(usage(&program)))?;
    let params_path = params_path.ok_or_else(|| RunError::Help(usage(&program)))?;
    let vk_path = vk_path.ok_or_else(|| RunError::Help(usage(&program)))?;
    let proof_path = proof_path.ok_or_else(|| RunError::Help(usage(&program)))?;
    let instances_path = instances_path.ok_or_else(|| RunError::Help(usage(&program)))?;

    let summary = verify_proof_from_files(k, &params_path, &vk_path, &proof_path, &instances_path)
        .map_err(|err| RunError::Message(format!("proof verification failed: {err}")))?;

    println!(
        "Proof verified (k={}, proof={} bytes, instances={} bytes)",
        summary.k, summary.proof_bytes, summary.instances_bytes
    );
    Ok(())
}
