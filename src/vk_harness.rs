use portvm::main::{generate_vk_from_params_file, generate_vk_with_local_setup};
use portvm::validate_circuit_k;
use std::env;
use std::path::PathBuf;
use std::process::ExitCode;

fn usage(program: &str) -> String {
    format!(
        "Usage:\n  {program} --k <k> --params <params.bin> --out <vk.bin>\n  {program} --k <k> --unsafe-local-setup --params-out <params.bin> --out <vk.bin>\n"
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

    let mut k: Option<u32> = None;
    let mut params_path: Option<PathBuf> = None;
    let mut params_out_path: Option<PathBuf> = None;
    let mut out_path: Option<PathBuf> = None;
    let mut unsafe_local_setup = false;

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
            "--params-out" => {
                let value = args
                    .next()
                    .ok_or_else(|| RunError::Message("--params-out requires a path".to_string()))?;
                params_out_path = Some(PathBuf::from(value));
            }
            "--out" => {
                let value = args
                    .next()
                    .ok_or_else(|| RunError::Message("--out requires a path".to_string()))?;
                out_path = Some(PathBuf::from(value));
            }
            "--unsafe-local-setup" => {
                unsafe_local_setup = true;
            }
            "--help" | "-h" => {
                let program = env::args()
                    .next()
                    .unwrap_or_else(|| "vk_harness".to_string());
                return Err(RunError::Help(usage(&program)));
            }
            other => {
                return Err(RunError::Message(format!("unknown argument: {other}")));
            }
        }
    }

    let program = env::args()
        .next()
        .unwrap_or_else(|| "vk_harness".to_string());
    let k = k.ok_or_else(|| RunError::Message(usage(&program)))?;
    validate_circuit_k(k).map_err(RunError::Message)?;
    let out_path = out_path.ok_or_else(|| RunError::Message(usage(&program)))?;

    if unsafe_local_setup == params_path.is_some() {
        return Err(RunError::Message(
            "choose exactly one of --params <file> or --unsafe-local-setup".to_string(),
        ));
    }

    if !unsafe_local_setup && params_out_path.is_some() {
        return Err(RunError::Message(
            "--params-out is only valid with --unsafe-local-setup".to_string(),
        ));
    }

    let summary = if unsafe_local_setup {
        let params_out_path = params_out_path.ok_or_else(|| {
            RunError::Message("--unsafe-local-setup requires --params-out <params.bin>".to_string())
        })?;
        generate_vk_with_local_setup(k, &out_path, &params_out_path)
            .map_err(|err| RunError::Message(format!("vk generation failed: {err}")))?
    } else {
        let params_path = params_path.ok_or_else(|| RunError::Message(usage(&program)))?;
        generate_vk_from_params_file(k, &params_path, &out_path)
            .map_err(|err| RunError::Message(format!("vk generation failed: {err}")))?
    };

    println!(
        "VK written to {} (k={}, {} bytes)",
        out_path.display(),
        summary.k,
        summary.vk_bytes
    );

    Ok(())
}
