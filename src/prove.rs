use portvm::input::parse_public_tables_file;
use portvm::main::{generate_witness_from_tables, GeneratedWitness, ProofGenerationSummary};
use std::env;
use std::path::PathBuf;
use std::process::ExitCode;

fn usage(program: &str) -> String {
    format!(
        "Usage:\n  {program} --k <k> --params <params.bin> --pk <pk.bin> --input <tables.txt> --witness-out <witness.bin> --proof-out <proof.bin> --instances-out <instances.bin> [--mock-precheck]\n  {program} --k <k> --params <params.bin> --pk <pk.bin> --witness <witness.bin> --proof-out <proof.bin> --instances-out <instances.bin> [--mock-precheck]\n  {program} --k <k> --input <tables.txt> --witness-out <witness.bin> --params-out <params.bin> --vk-out <vk.bin> --pk-out <pk.bin> --proof-out <proof.bin> --instances-out <instances.bin> [--mock-precheck]\n  {program} --k <k> --witness <witness.bin> --params-out <params.bin> --vk-out <vk.bin> --pk-out <pk.bin> --proof-out <proof.bin> --instances-out <instances.bin> [--mock-precheck]\n"
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

#[derive(Default)]
struct Args {
    k: Option<u32>,
    input_path: Option<PathBuf>,
    witness_path: Option<PathBuf>,
    witness_out_path: Option<PathBuf>,
    params_path: Option<PathBuf>,
    pk_path: Option<PathBuf>,
    params_out_path: Option<PathBuf>,
    vk_out_path: Option<PathBuf>,
    pk_out_path: Option<PathBuf>,
    proof_out_path: Option<PathBuf>,
    instances_out_path: Option<PathBuf>,
    mock_precheck: bool,
}

enum KeyMode {
    Existing {
        params_path: PathBuf,
        pk_path: PathBuf,
    },
    LocalSetup {
        params_out_path: PathBuf,
        vk_out_path: PathBuf,
        pk_out_path: PathBuf,
    },
}

fn run() -> Result<(), RunError> {
    let args = parse_args()?;
    let program = env::args().next().unwrap_or_else(|| "prove".to_string());
    let k = args.k.ok_or_else(|| RunError::Help(usage(&program)))?;
    let proof_out_path = args
        .proof_out_path
        .clone()
        .ok_or_else(|| RunError::Help(usage(&program)))?;
    let instances_out_path = args
        .instances_out_path
        .clone()
        .ok_or_else(|| RunError::Help(usage(&program)))?;

    let key_mode = resolve_key_mode(&args, &program)?;
    let witness = load_or_generate_witness(&args)?;

    let summary = match key_mode {
        KeyMode::Existing {
            params_path,
            pk_path,
        } => witness.prove_with_existing_key_files(
            k,
            &params_path,
            &pk_path,
            &proof_out_path,
            &instances_out_path,
            args.mock_precheck,
        ),
        KeyMode::LocalSetup {
            params_out_path,
            vk_out_path,
            pk_out_path,
        } => witness.prove_with_local_setup(
            k,
            &params_out_path,
            &vk_out_path,
            &pk_out_path,
            &proof_out_path,
            &instances_out_path,
            args.mock_precheck,
        ),
    }
    .map_err(|err| RunError::Message(format!("proof generation failed: {err}")))?;

    print_summary(&proof_out_path, &instances_out_path, summary);
    Ok(())
}

fn parse_args() -> Result<Args, RunError> {
    let mut args = Args::default();
    let mut iter = env::args().skip(1);

    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--k" => {
                let value = next_value(&mut iter, "--k")?;
                args.k = Some(
                    value
                        .parse::<u32>()
                        .map_err(|_| RunError::Message(format!("invalid k value: {value}")))?,
                );
            }
            "--input" => args.input_path = Some(PathBuf::from(next_value(&mut iter, "--input")?)),
            "--witness" => {
                args.witness_path = Some(PathBuf::from(next_value(&mut iter, "--witness")?))
            }
            "--witness-out" => {
                args.witness_out_path = Some(PathBuf::from(next_value(&mut iter, "--witness-out")?))
            }
            "--params" => {
                args.params_path = Some(PathBuf::from(next_value(&mut iter, "--params")?))
            }
            "--pk" => args.pk_path = Some(PathBuf::from(next_value(&mut iter, "--pk")?)),
            "--params-out" => {
                args.params_out_path = Some(PathBuf::from(next_value(&mut iter, "--params-out")?))
            }
            "--vk-out" => {
                args.vk_out_path = Some(PathBuf::from(next_value(&mut iter, "--vk-out")?))
            }
            "--pk-out" => {
                args.pk_out_path = Some(PathBuf::from(next_value(&mut iter, "--pk-out")?))
            }
            "--proof-out" => {
                args.proof_out_path = Some(PathBuf::from(next_value(&mut iter, "--proof-out")?))
            }
            "--instances-out" => {
                args.instances_out_path =
                    Some(PathBuf::from(next_value(&mut iter, "--instances-out")?))
            }
            "--mock-precheck" => args.mock_precheck = true,
            "--help" | "-h" => {
                let program = env::args().next().unwrap_or_else(|| "prove".to_string());
                return Err(RunError::Help(usage(&program)));
            }
            other => return Err(RunError::Message(format!("unknown argument: {other}"))),
        }
    }

    Ok(args)
}

fn next_value(
    iter: &mut impl Iterator<Item = String>,
    flag: &'static str,
) -> Result<String, RunError> {
    iter.next()
        .ok_or_else(|| RunError::Message(format!("{flag} requires a value")))
}

fn resolve_key_mode(args: &Args, program: &str) -> Result<KeyMode, RunError> {
    match (&args.params_path, &args.pk_path) {
        (Some(params_path), Some(pk_path)) => {
            if args.params_out_path.is_some() || args.vk_out_path.is_some() || args.pk_out_path.is_some()
            {
                return Err(RunError::Message(
                    "do not combine --params/--pk with --params-out/--vk-out/--pk-out"
                        .to_string(),
                ));
            }
            Ok(KeyMode::Existing {
                params_path: params_path.clone(),
                pk_path: pk_path.clone(),
            })
        }
        (None, None) => {
            let params_out_path = args
                .params_out_path
                .clone()
                .ok_or_else(|| RunError::Help(usage(program)))?;
            let vk_out_path = args
                .vk_out_path
                .clone()
                .ok_or_else(|| RunError::Help(usage(program)))?;
            let pk_out_path = args
                .pk_out_path
                .clone()
                .ok_or_else(|| RunError::Help(usage(program)))?;
            Ok(KeyMode::LocalSetup {
                params_out_path,
                vk_out_path,
                pk_out_path,
            })
        }
        _ => Err(RunError::Message(
            "provide both --params and --pk, or provide neither and use --params-out --vk-out --pk-out"
                .to_string(),
        )),
    }
}

fn load_or_generate_witness(args: &Args) -> Result<GeneratedWitness, RunError> {
    match (&args.input_path, &args.witness_path) {
        (Some(_), Some(_)) => Err(RunError::Message(
            "choose exactly one of --input or --witness".to_string(),
        )),
        (None, None) => Err(RunError::Message(
            "choose exactly one of --input or --witness".to_string(),
        )),
        (Some(input_path), None) => {
            let witness_out_path = args.witness_out_path.as_ref().ok_or_else(|| {
                RunError::Message("--input requires --witness-out <witness.bin>".to_string())
            })?;
            let tables = parse_public_tables_file(input_path)
                .map_err(|err| RunError::Message(format!("input parsing failed: {err}")))?;
            let bundle = generate_witness_from_tables(tables)
                .map_err(|err| RunError::Message(format!("witness generation failed: {err}")))?;
            bundle
                .generated_witness
                .write_to_file(witness_out_path)
                .map_err(|err| RunError::Message(format!("witness write failed: {err}")))?;
            Ok(bundle.generated_witness)
        }
        (None, Some(witness_path)) => {
            if args.witness_out_path.is_some() {
                return Err(RunError::Message(
                    "--witness-out is only valid when using --input".to_string(),
                ));
            }
            GeneratedWitness::read_from_file(witness_path)
                .map_err(|err| RunError::Message(format!("witness read failed: {err}")))
        }
    }
}

fn print_summary(
    proof_out_path: &PathBuf,
    instances_out_path: &PathBuf,
    summary: ProofGenerationSummary,
) {
    println!(
        "Proof written to {} (k={}, {} bytes)",
        proof_out_path.display(),
        summary.k,
        summary.proof_bytes
    );
    println!(
        "Public instances written to {} ({} bytes)",
        instances_out_path.display(),
        summary.instances_bytes
    );
    if let Some(bytes) = summary.params_bytes {
        println!("Local unsafe params generated ({} bytes)", bytes);
    }
    if let Some(bytes) = summary.vk_bytes {
        println!("VK generated ({} bytes)", bytes);
    }
    if let Some(bytes) = summary.pk_bytes {
        println!("PK generated ({} bytes)", bytes);
    }
    if summary.mock_prechecked {
        println!("MockProver precheck passed before proving");
    }
}
