use super::*;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::Path;

const CPU_ASSIGN_ROWS: usize = 10_000;
const CPU_GUARD_ROWS: usize = 1;
const ALU_ASSIGN_ROWS: usize = 49_984;
const ALU_RESERVED_TAIL_ROWS: usize = 32;
const ALU_LOGICAL_MAX_ROWS: usize = ALU_ASSIGN_ROWS - ALU_RESERVED_TAIL_ROWS;
const COPY_ASSIGN_ROWS: usize = 50_000;
const COPY_TAIL_GUARD_ROWS: usize = 2;
const PUBLIC_OUTPUT_ROWS: usize = 50_000;

#[derive(Debug, Clone)]
pub struct LogicalByteTableRow {
    pub logical_call_id: u64,
    pub pc: u64,
    pub limb1: u64,
    pub limb2: u64,
    pub limb3: u64,
    pub limb4: u64,
    pub iscode: bool,
}

#[derive(Debug, Clone)]
pub struct LogicalTxRow {
    pub active: bool,
    pub txid: u64,
    pub tag: u64,
    pub index: u64,
    pub value_low: u128,
    pub value_high: u128,
}

#[derive(Debug, Clone)]
pub struct CompactLogicalTxRow {
    pub tag: u64,
    /// Decimal or 0x-prefixed hexadecimal unsigned value, up to 256 bits.
    pub value: String,
}

#[derive(Debug, Clone)]
pub struct LogicalCpuStep {
    pub logical_call_id: u64,
    pub spawned_logical_call_id: Option<u64>,
    pub pc: u64,
    pub opcode: u64,
    pub rlc_a: [u64; 4],
    pub rlc_b: [u64; 4],
    pub rlc_c: [u64; 4],
    pub rlc_d: [u64; 4],
    pub rlc_e: [u64; 4],
    pub rlc_f: [u64; 4],
    pub rlc_g: [u64; 4],
    pub rlc_h: [u64; 4],
    pub rlc_i: [u64; 4],
    pub rlc_j: [u64; 4],
    pub memaddr: u64,
    pub inv: Fp,
    pub mmax: u64,
    pub ismaxchanged: bool,
    pub sp: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArithmeticOpKind {
    Add,
    Sub,
    Mul,
    Div,
    Lt,
    Eq,
    And,
    Or,
    Xor,
    Not,
}

#[derive(Debug, Clone)]
pub struct LogicalArithmeticRow {
    pub barlt: u64,
    pub carry: Fp,
    pub rem: u64,
    pub limb_a: u64,
    pub limb_b: u64,
    pub limb_c: u64,
    pub pac_a: [u64; 4],
    pub pac_b: [u64; 4],
    pub pac_c: [u64; 4],
    pub pac_carry: [u64; 4],
    pub pac_rem: [u64; 4],
    pub pac_diff: [u64; 4],
    pub rlc_a: [u64; 4],
    pub rlc_b: [u64; 4],
    pub rlc_c: [u64; 4],
    pub noname: u64,
}

#[derive(Debug, Clone)]
pub struct LogicalArithmeticChunk {
    pub op: ArithmeticOpKind,
    pub rows: [LogicalArithmeticRow; 4],
}

#[derive(Debug, Clone)]
pub struct LogicalMemoryEvent {
    pub source_step: usize,
    pub bytes_in_local_row_order: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct LogicalCopyRow {
    pub switch: bool,
    pub isfirst: bool,
    pub islast: bool,
    pub rwc: u64,
    pub address_write: u64,
    pub address_read: u64,
    pub address_end: u64,
    pub iswrite: bool,
    pub ismem: bool,
    pub istx: bool,
    pub logical_call_id_read: u64,
    pub logical_call_id_write: u64,
    pub bytesleft: u64,
    pub value: u64,
    pub ispad: bool,
    pub inv: Fp,
    pub limb_1: u64,
    pub limb_2: u64,
}

#[derive(Debug, Clone)]
pub struct LogicalRwRow {
    pub tag: u64,
    pub logical_call_id: u64,
    pub address: u64,
    pub field_tag: u64,
    pub storage_key: u64,
    pub rw_counter: u64,
    pub iswrite: bool,
    pub value: [u64; 4],
}

#[derive(Debug, Clone, Default)]
pub struct LogicalWitnessInput {
    pub bytecode_rows: Vec<LogicalByteTableRow>,
    pub tx_rows: Vec<LogicalTxRow>,
    pub cpu_steps: Vec<LogicalCpuStep>,
    pub arithmetic_chunks: Vec<LogicalArithmeticChunk>,
    pub memory_events: Vec<LogicalMemoryEvent>,
    pub copy_rows: Vec<LogicalCopyRow>,
    pub rw_rows: Vec<LogicalRwRow>,
}

#[derive(Debug, Clone)]
pub struct GeneratedWitness {
    circuit: EVM_Circuit<Fp>,
    public_inputs: Vec<Vec<Fp>>,
    call_id_map: Vec<(u64, u64)>,
    pub logical_cpu_rows: usize,
    pub logical_alu_rows: usize,
    pub logical_copy_rows: usize,
    pub logical_rw_rows: usize,
}

const WITNESS_MAGIC: &[u8; 8] = b"PORTWIT1";
const WITNESS_FORMAT_VERSION: u32 = 1;
const PUBLIC_INSTANCES_MAGIC: &[u8; 8] = b"PORTINS1";
const PUBLIC_INSTANCES_FORMAT_VERSION: u32 = 1;
pub const PUBLIC_INPUT_COLUMN_COUNT: usize = 23;

#[derive(Debug)]
pub enum WitnessFileError {
    Io(io::Error),
    InvalidMagic,
    UnsupportedVersion(u32),
    InvalidField,
    InvalidLength {
        section: &'static str,
        length: u64,
        maximum: usize,
    },
    InvalidStructure(String),
}

impl std::fmt::Display for WitnessFileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(err) => write!(f, "witness file I/O failed: {err}"),
            Self::InvalidMagic => f.write_str("invalid witness file magic"),
            Self::UnsupportedVersion(version) => {
                write!(f, "unsupported witness file version: {version}")
            }
            Self::InvalidField => f.write_str("witness file contains an invalid field element"),
            Self::InvalidLength {
                section,
                length,
                maximum,
            } => write!(
                f,
                "witness file section {section} is too long: {length} rows, maximum {maximum}"
            ),
            Self::InvalidStructure(message) => {
                write!(f, "invalid witness file structure: {message}")
            }
        }
    }
}

impl std::error::Error for WitnessFileError {}

impl From<io::Error> for WitnessFileError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

struct WitnessWriter<W> {
    writer: W,
}

impl<W: Write> WitnessWriter<W> {
    fn new(writer: W) -> Self {
        Self { writer }
    }

    fn bytes(&mut self, value: &[u8]) -> io::Result<()> {
        self.writer.write_all(value)
    }

    fn u32(&mut self, value: u32) -> io::Result<()> {
        self.bytes(&value.to_le_bytes())
    }

    fn u64(&mut self, value: u64) -> io::Result<()> {
        self.bytes(&value.to_le_bytes())
    }

    fn field(&mut self, value: Fp) -> io::Result<()> {
        self.bytes(value.to_repr().as_ref())
    }

    fn fields(&mut self, values: &[Fp]) -> io::Result<()> {
        for value in values {
            self.field(*value)?;
        }
        Ok(())
    }

    fn u64_array<const N: usize>(&mut self, values: &[u64; N]) -> io::Result<()> {
        for value in values {
            self.u64(*value)?;
        }
        Ok(())
    }

    fn field_array<const N: usize>(&mut self, values: &[Fp; N]) -> io::Result<()> {
        for value in values {
            self.field(*value)?;
        }
        Ok(())
    }
}

struct WitnessReader<R> {
    reader: R,
}

impl<R: Read> WitnessReader<R> {
    fn new(reader: R) -> Self {
        Self { reader }
    }

    fn bytes<const N: usize>(&mut self) -> io::Result<[u8; N]> {
        let mut value = [0u8; N];
        self.reader.read_exact(&mut value)?;
        Ok(value)
    }

    fn u32(&mut self) -> io::Result<u32> {
        Ok(u32::from_le_bytes(self.bytes()?))
    }

    fn u64(&mut self) -> io::Result<u64> {
        Ok(u64::from_le_bytes(self.bytes()?))
    }

    fn field(&mut self) -> Result<Fp, WitnessFileError> {
        let bytes = self.bytes::<32>()?;
        let mut repr = <Fp as PrimeField>::Repr::default();
        repr.as_mut().copy_from_slice(&bytes);
        Option::<Fp>::from(Fp::from_repr(repr)).ok_or(WitnessFileError::InvalidField)
    }

    fn fields<const N: usize>(&mut self) -> Result<[Fp; N], WitnessFileError> {
        let mut values = [Fp::ZERO; N];
        for value in &mut values {
            *value = self.field()?;
        }
        Ok(values)
    }

    fn u64_array<const N: usize>(&mut self) -> Result<[u64; N], WitnessFileError> {
        let mut values = [0u64; N];
        for value in &mut values {
            *value = self.u64()?;
        }
        Ok(values)
    }
}

impl GeneratedWitness {
    pub fn public_inputs(&self) -> &[Vec<Fp>] {
        &self.public_inputs
    }

    pub fn write_public_instances_to_file(
        &self,
        path: impl AsRef<Path>,
    ) -> Result<(), WitnessFileError> {
        write_public_instances_to_file(&self.public_inputs, path)
    }

    pub fn call_id_map(&self) -> &[(u64, u64)] {
        &self.call_id_map
    }

    pub fn write_to_file(&self, path: impl AsRef<Path>) -> Result<(), WitnessFileError> {
        let file = File::create(path)?;
        let mut writer = WitnessWriter::new(io::BufWriter::new(file));

        writer.bytes(WITNESS_MAGIC)?;
        writer.u32(WITNESS_FORMAT_VERSION)?;
        writer.u64(self.call_id_map.len() as u64)?;
        for (logical, actual) in &self.call_id_map {
            writer.u64(*logical)?;
            writer.u64(*actual)?;
        }
        writer.u64(self.logical_cpu_rows as u64)?;
        writer.u64(self.logical_alu_rows as u64)?;
        writer.u64(self.logical_copy_rows as u64)?;
        writer.u64(self.logical_rw_rows as u64)?;

        write_cpu_rows(&mut writer, &self.circuit.cpu)?;
        write_rwtrace_rows(&mut writer, &self.circuit.rwtrace)?;
        write_rwstate_rows(&mut writer, &self.circuit.rwstate)?;
        write_alu_rows(&mut writer, &self.circuit.alu)?;
        write_copy_rows(&mut writer, &self.circuit.copytool)?;
        write_bytetable_rows(&mut writer, &self.circuit.bytetable)?;
        write_tx_rows(&mut writer, &self.circuit.txtrace)?;
        write_output_rows(&mut writer, &self.circuit.output)?;

        writer.u64(self.public_inputs.len() as u64)?;
        for column in &self.public_inputs {
            writer.u64(column.len() as u64)?;
            writer.fields(column)?;
        }

        writer.writer.flush()?;
        Ok(())
    }

    pub fn read_from_file(path: impl AsRef<Path>) -> Result<Self, WitnessFileError> {
        let file = File::open(path)?;
        let mut reader = WitnessReader::new(io::BufReader::new(file));

        if reader.bytes::<8>()? != *WITNESS_MAGIC {
            return Err(WitnessFileError::InvalidMagic);
        }
        let version = reader.u32()?;
        if version != WITNESS_FORMAT_VERSION {
            return Err(WitnessFileError::UnsupportedVersion(version));
        }

        let call_id_map = read_pairs(&mut reader, "call_id_map", 100_000)?;
        let logical_cpu_rows = checked_usize(reader.u64()?, "logical_cpu_rows", 10_000)?;
        let logical_alu_rows = checked_usize(reader.u64()?, "logical_alu_rows", 49_984)?;
        let logical_copy_rows = checked_usize(reader.u64()?, "logical_copy_rows", 50_000)?;
        let logical_rw_rows = checked_usize(reader.u64()?, "logical_rw_rows", 50_000)?;

        let circuit = EVM_Circuit::<Fp> {
            cpu: read_cpu_rows(&mut reader)?,
            rwtrace: read_rwtrace_rows(&mut reader)?,
            rwstate: read_rwstate_rows(&mut reader)?,
            alu: read_alu_rows(&mut reader)?,
            copytool: read_copy_rows(&mut reader)?,
            bytetable: read_bytetable_rows(&mut reader)?,
            txtrace: read_tx_rows(&mut reader)?,
            output: read_output_rows(&mut reader)?,
            rom: vec![],
            and: vec![],
            or: vec![],
            xor: vec![],
            not: vec![],
        };

        let public_inputs = read_public_inputs(&mut reader)?;

        Ok(Self {
            circuit,
            public_inputs,
            call_id_map,
            logical_cpu_rows,
            logical_alu_rows,
            logical_copy_rows,
            logical_rw_rows,
        })
    }

    pub fn mock_verify(&self, k: u32) -> Result<(), WitnessGenerationError> {
        let prover = MockProver::run(k, &self.circuit, self.public_inputs.clone())
            .map_err(|err| WitnessGenerationError::MockProverRun(err.to_string()))?;
        prover
            .verify()
            .map_err(|err| WitnessGenerationError::ConstraintViolation(format!("{err:?}")))
    }

    pub fn prove_with_existing_key_files(
        &self,
        k: u32,
        params_path: impl AsRef<Path>,
        pk_path: impl AsRef<Path>,
        proof_out_path: impl AsRef<Path>,
        instances_out_path: impl AsRef<Path>,
        mock_precheck: bool,
    ) -> Result<ProofGenerationSummary, Box<dyn std::error::Error>> {
        prove_generated_witness_with_existing_key_files(
            self,
            k,
            params_path.as_ref(),
            pk_path.as_ref(),
            proof_out_path.as_ref(),
            instances_out_path.as_ref(),
            mock_precheck,
        )
    }

    pub fn prove_with_local_setup(
        &self,
        k: u32,
        params_out_path: impl AsRef<Path>,
        vk_out_path: impl AsRef<Path>,
        pk_out_path: impl AsRef<Path>,
        proof_out_path: impl AsRef<Path>,
        instances_out_path: impl AsRef<Path>,
        mock_precheck: bool,
    ) -> Result<ProofGenerationSummary, Box<dyn std::error::Error>> {
        prove_generated_witness_with_local_setup(
            self,
            k,
            params_out_path.as_ref(),
            vk_out_path.as_ref(),
            pk_out_path.as_ref(),
            proof_out_path.as_ref(),
            instances_out_path.as_ref(),
            mock_precheck,
        )
    }

    #[cfg(test)]
    pub(crate) fn debug_rwtrace_rows(&self, start: usize, count: usize) -> Vec<String> {
        self.circuit
            .rwtrace
            .iter()
            .enumerate()
            .skip(start)
            .take(count)
            .map(|(idx, row)| {
                format!(
                    "#{idx}: tag={} call_id={} addr={} field={} storage={} rwc={} iswrite={} value={:?} isend={}",
                    field_to_u64(row.tag),
                    field_to_u64(row.call_id),
                    field_to_u64(row.address),
                    field_to_u64(row.field_tag),
                    field_to_u64(row.storage_key),
                    field_to_u64(row.rw_counter),
                    field_to_u64(row.iswrite),
                    row.value,
                    field_to_u64(row.isend),
                )
            })
            .collect()
    }

    #[cfg(test)]
    pub(crate) fn debug_rwstate_rows(&self, start: usize, count: usize) -> Vec<String> {
        self.circuit
            .rwstate
            .iter()
            .enumerate()
            .skip(start)
            .take(count)
            .map(|(idx, row)| {
                format!(
                    "#{idx}: isfirst={} tag={} call_id={} addr={} field={} storage={} rwc={} tagchg={} callchg={} addrchg={} fieldchg={} storagechg={} rwcchg={} iswrite={} value={:?} isend={}",
                    field_to_u64(row.isfirst),
                    field_to_u64(row.tag),
                    field_to_u64(row.call_id),
                    field_to_u64(row.address),
                    field_to_u64(row.field_tag),
                    field_to_u64(row.storage_key),
                    field_to_u64(row.rw_counter),
                    field_to_u64(row.tag_changed),
                    field_to_u64(row.call_id_changed),
                    field_to_u64(row.address_changed),
                    field_to_u64(row.field_tag_changed),
                    field_to_u64(row.storage_key_changed),
                    field_to_u64(row.rw_counter_changed),
                    field_to_u64(row.iswrite),
                    row.value,
                    field_to_u64(row.isend),
                )
            })
            .collect()
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ProofGenerationSummary {
    pub k: u32,
    pub proof_bytes: usize,
    pub instances_bytes: usize,
    pub params_bytes: Option<usize>,
    pub vk_bytes: Option<usize>,
    pub pk_bytes: Option<usize>,
    pub mock_prechecked: bool,
}

pub fn prove_generated_witness_with_existing_key_files(
    witness: &GeneratedWitness,
    k: u32,
    params_path: &Path,
    pk_path: &Path,
    proof_out_path: &Path,
    instances_out_path: &Path,
    mock_precheck: bool,
) -> Result<ProofGenerationSummary, Box<dyn std::error::Error>> {
    if mock_precheck {
        witness.mock_verify(k)?;
    }

    let mut params_reader = io::BufReader::new(File::open(params_path)?);
    let params = ParamsKZG::<Bn256>::read_custom(&mut params_reader, SerdeFormat::RawBytes)?;
    if params.k() != k {
        return Err(format!(
            "params k mismatch: expected {k}, file contains {}",
            params.k()
        )
        .into());
    }

    let mut pk_reader = io::BufReader::new(File::open(pk_path)?);
    let pk =
        ProvingKey::<G1Affine>::read::<_, EVM_Circuit<Fp>>(&mut pk_reader, SerdeFormat::RawBytes)?;
    let pk_k = pk.get_vk().get_domain().k();
    if pk_k != k {
        return Err(format!("pk k mismatch: expected {k}, file contains {pk_k}").into());
    }

    let proof_bytes = write_proof_from_witness(&params, &pk, witness, proof_out_path)?;
    witness.write_public_instances_to_file(instances_out_path)?;
    let instances_bytes = std::fs::metadata(instances_out_path)?.len() as usize;

    Ok(ProofGenerationSummary {
        k,
        proof_bytes,
        instances_bytes,
        params_bytes: None,
        vk_bytes: None,
        pk_bytes: None,
        mock_prechecked: mock_precheck,
    })
}

pub fn prove_generated_witness_with_local_setup(
    witness: &GeneratedWitness,
    k: u32,
    params_out_path: &Path,
    vk_out_path: &Path,
    pk_out_path: &Path,
    proof_out_path: &Path,
    instances_out_path: &Path,
    mock_precheck: bool,
) -> Result<ProofGenerationSummary, Box<dyn std::error::Error>> {
    if mock_precheck {
        witness.mock_verify(k)?;
    }

    let params = ParamsKZG::<Bn256>::setup(k, OsRng);
    let mut params_writer = io::BufWriter::new(File::create(params_out_path)?);
    params.write_custom(&mut params_writer, SerdeFormat::RawBytes)?;
    params_writer.flush()?;
    let params_bytes = std::fs::metadata(params_out_path)?.len() as usize;

    let keygen_circuit = vk_circuit();
    let vk = keygen_vk(&params, &keygen_circuit)?;
    let mut vk_writer = io::BufWriter::new(File::create(vk_out_path)?);
    vk.write(&mut vk_writer, SerdeFormat::RawBytes)?;
    vk_writer.flush()?;
    let vk_bytes = std::fs::metadata(vk_out_path)?.len() as usize;

    let pk = keygen_pk(&params, vk, &keygen_circuit)?;
    let mut pk_writer = io::BufWriter::new(File::create(pk_out_path)?);
    pk.write(&mut pk_writer, SerdeFormat::RawBytes)?;
    pk_writer.flush()?;
    let pk_bytes = std::fs::metadata(pk_out_path)?.len() as usize;

    let proof_bytes = write_proof_from_witness(&params, &pk, witness, proof_out_path)?;
    witness.write_public_instances_to_file(instances_out_path)?;
    let instances_bytes = std::fs::metadata(instances_out_path)?.len() as usize;

    Ok(ProofGenerationSummary {
        k,
        proof_bytes,
        instances_bytes,
        params_bytes: Some(params_bytes),
        vk_bytes: Some(vk_bytes),
        pk_bytes: Some(pk_bytes),
        mock_prechecked: mock_precheck,
    })
}

fn write_proof_from_witness(
    params: &ParamsKZG<Bn256>,
    pk: &ProvingKey<G1Affine>,
    witness: &GeneratedWitness,
    proof_out_path: &Path,
) -> Result<usize, Box<dyn std::error::Error>> {
    if witness.public_inputs.len() != PUBLIC_INPUT_COLUMN_COUNT {
        return Err(format!(
            "public input column count mismatch: expected {PUBLIC_INPUT_COLUMN_COUNT}, got {}",
            witness.public_inputs.len()
        )
        .into());
    }

    let instance_columns = witness
        .public_inputs
        .iter()
        .map(Vec::as_slice)
        .collect::<Vec<&[Fp]>>();
    let instances: &[&[Fp]] = instance_columns.as_slice();
    let circuits = [witness.circuit.clone()];

    let mut transcript =
        Blake2bWrite::<Vec<u8>, G1Affine, Challenge255<G1Affine>>::init(Vec::new());
    create_proof::<
        KZGCommitmentScheme<Bn256>,
        ProverSHPLONK<'_, Bn256>,
        Challenge255<G1Affine>,
        _,
        Blake2bWrite<Vec<u8>, G1Affine, Challenge255<G1Affine>>,
        EVM_Circuit<Fp>,
    >(params, pk, &circuits, &[instances], OsRng, &mut transcript)?;

    let proof = transcript.finalize();
    std::fs::write(proof_out_path, proof)?;
    Ok(std::fs::metadata(proof_out_path)?.len() as usize)
}

pub fn write_public_instances_to_file(
    public_inputs: &[Vec<Fp>],
    path: impl AsRef<Path>,
) -> Result<(), WitnessFileError> {
    let file = File::create(path)?;
    let mut writer = WitnessWriter::new(io::BufWriter::new(file));

    writer.bytes(PUBLIC_INSTANCES_MAGIC)?;
    writer.u32(PUBLIC_INSTANCES_FORMAT_VERSION)?;
    writer.u64(public_inputs.len() as u64)?;
    for column in public_inputs {
        writer.u64(column.len() as u64)?;
        writer.fields(column)?;
    }

    writer.writer.flush()?;
    Ok(())
}

pub fn read_public_instances_from_file(
    path: impl AsRef<Path>,
) -> Result<Vec<Vec<Fp>>, WitnessFileError> {
    let file = File::open(path)?;
    let mut reader = WitnessReader::new(io::BufReader::new(file));

    if reader.bytes::<8>()? != *PUBLIC_INSTANCES_MAGIC {
        return Err(WitnessFileError::InvalidMagic);
    }
    let version = reader.u32()?;
    if version != PUBLIC_INSTANCES_FORMAT_VERSION {
        return Err(WitnessFileError::UnsupportedVersion(version));
    }

    read_public_inputs(&mut reader)
}

fn write_row_count<W: Write>(
    writer: &mut WitnessWriter<W>,
    section: &'static str,
    length: usize,
    maximum: usize,
) -> Result<(), WitnessFileError> {
    if length > maximum {
        return Err(WitnessFileError::InvalidLength {
            section,
            length: length as u64,
            maximum,
        });
    }
    writer.u64(length as u64)?;
    Ok(())
}

fn read_row_count<R: Read>(
    reader: &mut WitnessReader<R>,
    section: &'static str,
    maximum: usize,
) -> Result<usize, WitnessFileError> {
    checked_usize(reader.u64()?, section, maximum)
}

fn checked_usize(
    length: u64,
    section: &'static str,
    maximum: usize,
) -> Result<usize, WitnessFileError> {
    let length_usize = usize::try_from(length).map_err(|_| WitnessFileError::InvalidLength {
        section,
        length,
        maximum,
    })?;
    if length_usize > maximum {
        return Err(WitnessFileError::InvalidLength {
            section,
            length,
            maximum,
        });
    }
    Ok(length_usize)
}

fn read_pairs<R: Read>(
    reader: &mut WitnessReader<R>,
    section: &'static str,
    maximum: usize,
) -> Result<Vec<(u64, u64)>, WitnessFileError> {
    let length = read_row_count(reader, section, maximum)?;
    let mut pairs = Vec::with_capacity(length);
    for _ in 0..length {
        pairs.push((reader.u64()?, reader.u64()?));
    }
    Ok(pairs)
}

fn write_cpu_rows<W: Write>(
    writer: &mut WitnessWriter<W>,
    rows: &[CPU_values<Fp>],
) -> Result<(), WitnessFileError> {
    write_row_count(writer, "cpu", rows.len(), CPU_ASSIGN_ROWS + CPU_GUARD_ROWS)?;
    for row in rows {
        writer.fields(&[row.call_id, row.clk, row.rw_counter, row.pc, row.opcode])?;
        for value in [
            &row.rlc_a, &row.rlc_b, &row.rlc_c, &row.rlc_d, &row.rlc_e, &row.rlc_f, &row.rlc_g,
            &row.rlc_h, &row.rlc_i, &row.rlc_j,
        ] {
            writer.u64_array(value)?;
        }
        writer.fields(&[
            row.memaddr,
            row.inv,
            row.mmax,
            row.ismaxchanged,
            row.isbegintx,
            row.isendtx,
            row.iscall,
            row.isreturn,
            row.returndatacopy,
            row.calldatacopy,
            row.isadd,
            row.issub,
            row.ismul,
            row.isdiv,
            row.islt,
            row.iseq,
            row.isand,
            row.isor,
            row.isxor,
            row.isnot,
            row.isjump,
            row.isjumpdest,
            row.isjumpcon,
            row.ismload,
            row.ismstore,
            row.ismstore8,
            row.isread,
            row.iswrite,
            row.ishalt,
            row.rlc_addr_a,
            row.rlc_addr_b,
            row.sp,
        ])?;
    }
    Ok(())
}

fn read_cpu_rows<R: Read>(
    reader: &mut WitnessReader<R>,
) -> Result<Vec<CPU_values<Fp>>, WitnessFileError> {
    let length = read_row_count(reader, "cpu", CPU_ASSIGN_ROWS + CPU_GUARD_ROWS)?;
    let mut rows = Vec::with_capacity(length);
    for _ in 0..length {
        let head = reader.fields::<5>()?;
        let rlc_a = reader.u64_array()?;
        let rlc_b = reader.u64_array()?;
        let rlc_c = reader.u64_array()?;
        let rlc_d = reader.u64_array()?;
        let rlc_e = reader.u64_array()?;
        let rlc_f = reader.u64_array()?;
        let rlc_g = reader.u64_array()?;
        let rlc_h = reader.u64_array()?;
        let rlc_i = reader.u64_array()?;
        let rlc_j = reader.u64_array()?;
        let tail = reader.fields::<32>()?;
        rows.push(CPU_values {
            call_id: head[0],
            clk: head[1],
            rw_counter: head[2],
            pc: head[3],
            opcode: head[4],
            rlc_a,
            rlc_b,
            rlc_c,
            rlc_d,
            rlc_e,
            rlc_f,
            rlc_g,
            rlc_h,
            rlc_i,
            rlc_j,
            memaddr: tail[0],
            inv: tail[1],
            mmax: tail[2],
            ismaxchanged: tail[3],
            isbegintx: tail[4],
            isendtx: tail[5],
            iscall: tail[6],
            isreturn: tail[7],
            returndatacopy: tail[8],
            calldatacopy: tail[9],
            isadd: tail[10],
            issub: tail[11],
            ismul: tail[12],
            isdiv: tail[13],
            islt: tail[14],
            iseq: tail[15],
            isand: tail[16],
            isor: tail[17],
            isxor: tail[18],
            isnot: tail[19],
            isjump: tail[20],
            isjumpdest: tail[21],
            isjumpcon: tail[22],
            ismload: tail[23],
            ismstore: tail[24],
            ismstore8: tail[25],
            isread: tail[26],
            iswrite: tail[27],
            ishalt: tail[28],
            rlc_addr_a: tail[29],
            rlc_addr_b: tail[30],
            sp: tail[31],
        });
    }
    Ok(rows)
}

fn write_rwtrace_rows<W: Write>(
    writer: &mut WitnessWriter<W>,
    rows: &[RWTrace_values<Fp>],
) -> Result<(), WitnessFileError> {
    write_row_count(writer, "rwtrace", rows.len(), COPY_ASSIGN_ROWS)?;
    for row in rows {
        writer.fields(&[
            row.tag,
            row.call_id,
            row.address,
            row.field_tag,
            row.storage_key,
            row.rw_counter,
            row.iswrite,
        ])?;
        writer.u64_array(&row.value)?;
        writer.field(row.isend)?;
    }
    Ok(())
}

fn read_rwtrace_rows<R: Read>(
    reader: &mut WitnessReader<R>,
) -> Result<Vec<RWTrace_values<Fp>>, WitnessFileError> {
    let length = read_row_count(reader, "rwtrace", COPY_ASSIGN_ROWS)?;
    let mut rows = Vec::with_capacity(length);
    for _ in 0..length {
        let fields = reader.fields::<7>()?;
        rows.push(RWTrace_values {
            tag: fields[0],
            call_id: fields[1],
            address: fields[2],
            field_tag: fields[3],
            storage_key: fields[4],
            rw_counter: fields[5],
            iswrite: fields[6],
            value: reader.u64_array()?,
            isend: reader.field()?,
        });
    }
    Ok(rows)
}

fn write_rwstate_rows<W: Write>(
    writer: &mut WitnessWriter<W>,
    rows: &[RWState_values<Fp>],
) -> Result<(), WitnessFileError> {
    write_row_count(writer, "rwstate", rows.len(), COPY_ASSIGN_ROWS)?;
    for row in rows {
        writer.fields(&[
            row.isfirst,
            row.tag,
            row.call_id,
            row.isroot,
            row.address,
            row.field_tag,
            row.storage_key,
            row.rw_counter,
            row.tag_changed,
            row.call_id_changed,
            row.address_changed,
            row.field_tag_changed,
            row.storage_key_changed,
            row.rw_counter_changed,
            row.iswrite,
        ])?;
        writer.u64_array(&row.value)?;
        writer.fields(&[
            row.isend,
            row.z,
            row.limb_1,
            row.limb_2,
            row.limb_3,
            row.limb_4,
            row.limb_5,
            row.limb_6,
            row.limb_7,
            row.limb_8,
            row.limb_9,
            row.limb_10,
        ])?;
    }
    Ok(())
}

fn read_rwstate_rows<R: Read>(
    reader: &mut WitnessReader<R>,
) -> Result<Vec<RWState_values<Fp>>, WitnessFileError> {
    let length = read_row_count(reader, "rwstate", COPY_ASSIGN_ROWS)?;
    let mut rows = Vec::with_capacity(length);
    for _ in 0..length {
        let head = reader.fields::<15>()?;
        let value = reader.u64_array()?;
        let tail = reader.fields::<12>()?;
        rows.push(RWState_values {
            isfirst: head[0],
            tag: head[1],
            call_id: head[2],
            isroot: head[3],
            address: head[4],
            field_tag: head[5],
            storage_key: head[6],
            rw_counter: head[7],
            tag_changed: head[8],
            call_id_changed: head[9],
            address_changed: head[10],
            field_tag_changed: head[11],
            storage_key_changed: head[12],
            rw_counter_changed: head[13],
            iswrite: head[14],
            value,
            isend: tail[0],
            z: tail[1],
            limb_1: tail[2],
            limb_2: tail[3],
            limb_3: tail[4],
            limb_4: tail[5],
            limb_5: tail[6],
            limb_6: tail[7],
            limb_7: tail[8],
            limb_8: tail[9],
            limb_9: tail[10],
            limb_10: tail[11],
        });
    }
    Ok(rows)
}

fn write_alu_rows<W: Write>(
    writer: &mut WitnessWriter<W>,
    rows: &[ALU_values<Fp>],
) -> Result<(), WitnessFileError> {
    write_row_count(writer, "alu", rows.len(), ALU_ASSIGN_ROWS)?;
    for row in rows {
        writer.fields(&[
            row.isfirst,
            row.islast,
            row.byte32,
            row.isfirst32,
            row.islast32,
            row.limbnumber,
            row.isadd,
            row.ismul,
            row.isdiv,
            row.islt,
            row.iseq,
            row.isand,
            row.isor,
            row.isxor,
            row.isnot,
            row.barlt,
            row.carry,
            row.rem,
            row.limb_a,
            row.limb_b,
            row.limb_c,
        ])?;
        for value in [
            &row.pac_a,
            &row.pac_b,
            &row.pac_c,
            &row.pac_carry,
            &row.pac_rem,
            &row.pac_diff,
        ] {
            writer.field_array(value)?;
        }
        writer.u64_array(&row.rlc_a)?;
        writer.u64_array(&row.rlc_b)?;
        writer.u64_array(&row.rlc_c)?;
        writer.field(row.noname)?;
    }
    Ok(())
}

fn read_alu_rows<R: Read>(
    reader: &mut WitnessReader<R>,
) -> Result<Vec<ALU_values<Fp>>, WitnessFileError> {
    let length = read_row_count(reader, "alu", ALU_ASSIGN_ROWS)?;
    let mut rows = Vec::with_capacity(length);
    for _ in 0..length {
        let head = reader.fields::<21>()?;
        let pac_a = reader.fields()?;
        let pac_b = reader.fields()?;
        let pac_c = reader.fields()?;
        let pac_carry = reader.fields()?;
        let pac_rem = reader.fields()?;
        let pac_diff = reader.fields()?;
        rows.push(ALU_values {
            isfirst: head[0],
            islast: head[1],
            byte32: head[2],
            isfirst32: head[3],
            islast32: head[4],
            limbnumber: head[5],
            isadd: head[6],
            ismul: head[7],
            isdiv: head[8],
            islt: head[9],
            iseq: head[10],
            isand: head[11],
            isor: head[12],
            isxor: head[13],
            isnot: head[14],
            barlt: head[15],
            carry: head[16],
            rem: head[17],
            limb_a: head[18],
            limb_b: head[19],
            limb_c: head[20],
            pac_a,
            pac_b,
            pac_c,
            pac_carry,
            pac_rem,
            pac_diff,
            rlc_a: reader.u64_array()?,
            rlc_b: reader.u64_array()?,
            rlc_c: reader.u64_array()?,
            noname: reader.field()?,
        });
    }
    Ok(rows)
}

fn write_copy_rows<W: Write>(
    writer: &mut WitnessWriter<W>,
    rows: &[CopyTool_values<Fp>],
) -> Result<(), WitnessFileError> {
    write_row_count(
        writer,
        "copytool",
        rows.len(),
        COPY_ASSIGN_ROWS + COPY_TAIL_GUARD_ROWS,
    )?;
    for row in rows {
        writer.fields(&[
            row.q,
            row.switch,
            row.isfirst_fixed,
            row.isfirst,
            row.islast,
            row.rwc,
            row.address_write,
            row.address_read,
            row.address_end,
            row.iswrite,
            row.ismem,
            row.istx,
            row.callid_read,
            row.callid_write,
            row.bytesleft,
            row.value,
            row.ispad,
            row.inv,
            row.limb_1,
            row.limb_2,
        ])?;
    }
    Ok(())
}

fn read_copy_rows<R: Read>(
    reader: &mut WitnessReader<R>,
) -> Result<Vec<CopyTool_values<Fp>>, WitnessFileError> {
    let length = read_row_count(reader, "copytool", COPY_ASSIGN_ROWS + COPY_TAIL_GUARD_ROWS)?;
    let mut rows = Vec::with_capacity(length);
    for _ in 0..length {
        let fields = reader.fields::<20>()?;
        rows.push(CopyTool_values {
            q: fields[0],
            switch: fields[1],
            isfirst_fixed: fields[2],
            isfirst: fields[3],
            islast: fields[4],
            rwc: fields[5],
            address_write: fields[6],
            address_read: fields[7],
            address_end: fields[8],
            iswrite: fields[9],
            ismem: fields[10],
            istx: fields[11],
            callid_read: fields[12],
            callid_write: fields[13],
            bytesleft: fields[14],
            value: fields[15],
            ispad: fields[16],
            inv: fields[17],
            limb_1: fields[18],
            limb_2: fields[19],
        });
    }
    Ok(rows)
}

fn write_bytetable_rows<W: Write>(
    writer: &mut WitnessWriter<W>,
    rows: &[Byte_table_values<Fp>],
) -> Result<(), WitnessFileError> {
    write_row_count(writer, "bytetable", rows.len(), MAX_BYTECODE_ROWS)?;
    for row in rows {
        writer.fields(&[
            row.call_id,
            row.pc,
            row.limb1,
            row.limb2,
            row.limb3,
            row.limb4,
            row.iscode,
        ])?;
    }
    Ok(())
}

fn read_bytetable_rows<R: Read>(
    reader: &mut WitnessReader<R>,
) -> Result<Vec<Byte_table_values<Fp>>, WitnessFileError> {
    let length = read_row_count(reader, "bytetable", MAX_BYTECODE_ROWS)?;
    let mut rows = Vec::with_capacity(length);
    for _ in 0..length {
        let fields = reader.fields::<7>()?;
        rows.push(Byte_table_values {
            call_id: fields[0],
            pc: fields[1],
            limb1: fields[2],
            limb2: fields[3],
            limb3: fields[4],
            limb4: fields[5],
            iscode: fields[6],
        });
    }
    Ok(rows)
}

fn write_tx_rows<W: Write>(
    writer: &mut WitnessWriter<W>,
    rows: &[TXTrace_values<Fp>],
) -> Result<(), WitnessFileError> {
    write_row_count(writer, "txtrace", rows.len(), MAX_TX_ROWS)?;
    for row in rows {
        writer.fields(&[
            row.q,
            row.txid,
            row.tag,
            row.index,
            row.value_low,
            row.value_high,
        ])?;
    }
    Ok(())
}

fn read_tx_rows<R: Read>(
    reader: &mut WitnessReader<R>,
) -> Result<Vec<TXTrace_values<Fp>>, WitnessFileError> {
    let length = read_row_count(reader, "txtrace", MAX_TX_ROWS)?;
    let mut rows = Vec::with_capacity(length);
    for _ in 0..length {
        let fields = reader.fields::<6>()?;
        rows.push(TXTrace_values {
            q: fields[0],
            txid: fields[1],
            tag: fields[2],
            index: fields[3],
            value_low: fields[4],
            value_high: fields[5],
        });
    }
    Ok(rows)
}

fn write_output_rows<W: Write>(
    writer: &mut WitnessWriter<W>,
    rows: &[PublicOutput_values<Fp>],
) -> Result<(), WitnessFileError> {
    write_row_count(writer, "public_output", rows.len(), PUBLIC_OUTPUT_ROWS)?;
    for row in rows {
        writer.fields(&[
            row.active,
            row.tag,
            row.address,
            row.iswrite,
            row.rw_counter,
        ])?;
        writer.u64_array(&row.value)?;
    }
    Ok(())
}

fn read_output_rows<R: Read>(
    reader: &mut WitnessReader<R>,
) -> Result<Vec<PublicOutput_values<Fp>>, WitnessFileError> {
    let length = read_row_count(reader, "public_output", PUBLIC_OUTPUT_ROWS)?;
    let mut rows = Vec::with_capacity(length);
    for _ in 0..length {
        let fields = reader.fields::<5>()?;
        rows.push(PublicOutput_values {
            active: fields[0],
            tag: fields[1],
            address: fields[2],
            iswrite: fields[3],
            value: reader.u64_array()?,
            rw_counter: fields[4],
        });
    }
    Ok(rows)
}

fn read_public_inputs<R: Read>(
    reader: &mut WitnessReader<R>,
) -> Result<Vec<Vec<Fp>>, WitnessFileError> {
    let columns = checked_usize(
        reader.u64()?,
        "public_input_columns",
        PUBLIC_INPUT_COLUMN_COUNT,
    )?;
    if columns != PUBLIC_INPUT_COLUMN_COUNT {
        return Err(WitnessFileError::InvalidStructure(format!(
            "expected {PUBLIC_INPUT_COLUMN_COUNT} public input columns, found {columns}"
        )));
    }

    let mut public_inputs = Vec::with_capacity(columns);
    for column_index in 0..columns {
        let maximum = match column_index {
            0..=7 => MAX_BYTECODE_ROWS,
            8..=13 => MAX_TX_ROWS,
            14..=22 => PUBLIC_OUTPUT_ROWS,
            _ => unreachable!(),
        };
        let length = read_row_count(reader, "public_input_column", maximum)?;
        let mut column = Vec::with_capacity(length);
        for _ in 0..length {
            column.push(reader.field()?);
        }
        public_inputs.push(column);
    }
    Ok(public_inputs)
}

#[derive(Debug, Clone)]
pub enum WitnessGenerationError {
    EmptyCpuTrace,
    CpuTraceMustEndWithHalt,
    CpuTraceMustEndWithEndTxBeforeHalt,
    UnknownLogicalCallId(u64),
    DuplicateLogicalCallId(u64),
    MissingSpawnedLogicalCallId(usize),
    ArithmeticChunkCountMismatch {
        expected: usize,
        actual: usize,
    },
    MemoryEventOpcodeMismatch {
        source_step: usize,
        opcode: u64,
    },
    MemoryEventSourceOutOfRange(usize),
    CpuTraceTooLong(usize),
    AluTraceTooLong(usize),
    CopyTraceTooLong(usize),
    ByteTableTooLong(usize),
    TxTableTooLong(usize),
    NarrowValueRequired(&'static str),
    UnsupportedOpcode(u64),
    EndTxRwCounterMismatch {
        endtx_rw_counter: u64,
        terminal_rw_counter: u64,
    },
    MockProverRun(String),
    ConstraintViolation(String),
}

impl std::fmt::Display for WitnessGenerationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyCpuTrace => f.write_str("cpu_steps must not be empty"),
            Self::CpuTraceMustEndWithHalt => f.write_str(
                "cpu_steps must end with a halt row so the generator can pad the fixed CPU region",
            ),
            Self::CpuTraceMustEndWithEndTxBeforeHalt => f.write_str(
                "cpu_steps must end with an end-tx row immediately before the halt row",
            ),
            Self::UnknownLogicalCallId(id) => write!(f, "unknown logical call id: {id}"),
            Self::DuplicateLogicalCallId(id) => {
                write!(f, "duplicate logical call id mapping attempt: {id}")
            }
            Self::MissingSpawnedLogicalCallId(step) => {
                write!(f, "call step {step} is missing spawned_logical_call_id")
            }
            Self::ArithmeticChunkCountMismatch { expected, actual } => {
                write!(
                    f,
                    "arithmetic chunk count mismatch: expected {expected}, got {actual}"
                )
            }
            Self::MemoryEventOpcodeMismatch {
                source_step,
                opcode,
            } => {
                write!(f, "memory event at cpu step {source_step} does not point to a memory opcode: 0x{opcode:x}")
            }
            Self::MemoryEventSourceOutOfRange(step) => {
                write!(f, "memory event source_step {step} is out of range")
            }
            Self::CpuTraceTooLong(len) => write!(f, "cpu trace too long for fixed region: {len}"),
            Self::AluTraceTooLong(len) => write!(f, "alu trace too long for fixed region: {len}"),
            Self::CopyTraceTooLong(len) => write!(f, "copy trace too long for fixed region: {len}"),
            Self::ByteTableTooLong(len) => write!(f, "byte table too long: {len}"),
            Self::TxTableTooLong(len) => write!(f, "tx table too long: {len}"),
            Self::NarrowValueRequired(name) => write!(f, "{name} must fit in a single u64 limb"),
            Self::UnsupportedOpcode(op) => write!(f, "unsupported opcode: 0x{op:x}"),
            Self::EndTxRwCounterMismatch {
                endtx_rw_counter,
                terminal_rw_counter,
            } => write!(
                f,
                "END_TX rw_counter {endtx_rw_counter} does not match RWTrace terminal rw_counter {terminal_rw_counter}"
            ),
            Self::MockProverRun(msg) => write!(f, "mock prover failed to run: {msg}"),
            Self::ConstraintViolation(msg) => write!(f, "constraints violated: {msg}"),
        }
    }
}

impl std::error::Error for WitnessGenerationError {}

pub fn generate_witness(
    input: LogicalWitnessInput,
) -> Result<GeneratedWitness, WitnessGenerationError> {
    if input.cpu_steps.is_empty() {
        return Err(WitnessGenerationError::EmptyCpuTrace);
    }

    let (call_id_map, cpu_rows) = build_cpu_rows(&input.cpu_steps)?;
    let call_id_lookup = call_id_map.iter().copied().collect::<BTreeMap<_, _>>();

    let mut bytetable = build_bytetable_rows(&input.bytecode_rows, &call_id_lookup)?;
    append_halt_padding_byte_rows(&mut bytetable, &cpu_rows)?;
    let txtrace = build_tx_rows(&input.tx_rows)?;
    let alu = build_alu_rows(&input, &cpu_rows, &call_id_lookup)?;
    let copytool = build_copy_rows(&input.copy_rows, &call_id_lookup)?;
    let mut rwtrace = build_rw_rows(
        &input.rw_rows,
        &input.memory_events,
        &cpu_rows,
        &call_id_lookup,
    )?;
    rwtrace.extend(copy_rows_to_rwtrace(&input.copy_rows, &call_id_lookup)?);
    rwtrace.sort_by_key(|row| {
        (
            field_to_u64(row.rw_counter),
            field_to_u64(row.tag),
            field_to_u64(row.call_id),
            field_to_u64(row.address),
            field_to_u64(row.field_tag),
            field_to_u64(row.storage_key),
            field_to_u64(row.iswrite),
        )
    });
    fill_missing_rw_counters(&mut rwtrace);
    validate_endtx_terminal_rw_counter(&cpu_rows, input.cpu_steps.len(), &rwtrace)?;
    let rwstate = build_rwstate_rows(&rwtrace);

    let output = build_public_output_rows(&rwstate);
    let public_inputs = build_public_inputs(&bytetable, &txtrace, &output);

    let circuit = EVM_Circuit::<Fp> {
        cpu: cpu_rows.clone(),
        rwtrace: rwtrace.clone(),
        rwstate: rwstate.clone(),
        alu: alu.clone(),
        copytool: copytool.clone(),
        bytetable: bytetable.clone(),
        txtrace: txtrace.clone(),
        output,
        rom: vec![],
        and: vec![],
        or: vec![],
        xor: vec![],
        not: vec![],
    };

    Ok(GeneratedWitness {
        circuit,
        public_inputs,
        call_id_map,
        logical_cpu_rows: input.cpu_steps.len(),
        logical_alu_rows: logical_alu_len(&input),
        logical_copy_rows: input.copy_rows.len(),
        logical_rw_rows: rwtrace.len(),
    })
}

pub fn mock_prove_generated(
    k: u32,
    input: LogicalWitnessInput,
) -> Result<(), WitnessGenerationError> {
    generate_witness(input)?.mock_verify(k)
}

fn build_cpu_rows(
    steps: &[LogicalCpuStep],
) -> Result<(Vec<(u64, u64)>, Vec<CPU_values<Fp>>), WitnessGenerationError> {
    let mut map = BTreeMap::new();
    map.insert(steps[0].logical_call_id, 1u64);

    let mut rw_counter = 0u64;
    let mut rows = Vec::with_capacity(CPU_ASSIGN_ROWS + CPU_GUARD_ROWS);

    for (clk, step) in steps.iter().enumerate() {
        let actual_call_id =
            *map.get(&step.logical_call_id)
                .ok_or(WitnessGenerationError::UnknownLogicalCallId(
                    step.logical_call_id,
                ))?;

        let flags = decode_opcode(step.opcode)?;
        let row = CPU_values {
            call_id: fp(actual_call_id),
            clk: fp(clk as u64),
            rw_counter: fp(rw_counter),
            pc: fp(step.pc),
            opcode: fp(step.opcode),
            rlc_a: step.rlc_a,
            rlc_b: step.rlc_b,
            rlc_c: step.rlc_c,
            rlc_d: step.rlc_d,
            rlc_e: step.rlc_e,
            rlc_f: step.rlc_f,
            rlc_g: step.rlc_g,
            rlc_h: step.rlc_h,
            rlc_i: step.rlc_i,
            rlc_j: step.rlc_j,
            memaddr: fp(step.memaddr),
            inv: step.inv,
            mmax: fp(step.mmax),
            ismaxchanged: fp_bool(step.ismaxchanged),
            isbegintx: fp_bool(flags.isbegintx),
            isendtx: fp_bool(flags.isendtx),
            iscall: fp_bool(flags.iscall),
            isreturn: fp_bool(flags.isreturn),
            returndatacopy: fp_bool(flags.returndatacopy),
            calldatacopy: fp_bool(flags.calldatacopy),
            isadd: fp_bool(flags.isadd),
            issub: fp_bool(flags.issub),
            ismul: fp_bool(flags.ismul),
            isdiv: fp_bool(flags.isdiv),
            islt: fp_bool(flags.islt),
            iseq: fp_bool(flags.iseq),
            isand: fp_bool(flags.isand),
            isor: fp_bool(flags.isor),
            isxor: fp_bool(flags.isxor),
            isnot: fp_bool(flags.isnot),
            isjump: fp_bool(flags.isjump),
            isjumpdest: fp_bool(flags.isjumpdest),
            isjumpcon: fp_bool(flags.isjumpcon),
            ismload: fp_bool(flags.ismload),
            ismstore: fp_bool(flags.ismstore),
            ismstore8: fp_bool(flags.ismstore8),
            isread: fp_bool(flags.isread),
            iswrite: fp_bool(flags.iswrite),
            ishalt: fp_bool(flags.ishalt),
            rlc_addr_a: if flags.isreturn {
                fp_inverse_u64(selected_return_len(step)?)
            } else {
                compute_addr_a(step.sp, &flags)
            },
            rlc_addr_b: fp_sub_u64(step.sp, 2),
            sp: fp(step.sp),
        };
        rows.push(row);

        if flags.iscall {
            let spawned = step
                .spawned_logical_call_id
                .ok_or(WitnessGenerationError::MissingSpawnedLogicalCallId(clk))?;
            if map.contains_key(&spawned) {
                return Err(WitnessGenerationError::DuplicateLogicalCallId(spawned));
            }
            map.insert(spawned, rw_counter);
        }

        rw_counter = rw_counter.saturating_add(rwc_delta(step, &flags)?);
    }

    if rows.last().map(|row| row.opcode) != Some(fp(OP_HALT)) {
        return Err(WitnessGenerationError::CpuTraceMustEndWithHalt);
    }
    if rows.len() < 2 || rows[rows.len() - 2].isendtx != Fp::ONE {
        return Err(WitnessGenerationError::CpuTraceMustEndWithEndTxBeforeHalt);
    }
    if let Some(last_row) = rows.last_mut() {
        last_row.call_id = Fp::ZERO;
    }
    if rows.len() > CPU_ASSIGN_ROWS {
        return Err(WitnessGenerationError::CpuTraceTooLong(rows.len()));
    }

    let last = rows
        .last()
        .cloned()
        .ok_or(WitnessGenerationError::EmptyCpuTrace)?;
    while rows.len() < CPU_ASSIGN_ROWS + CPU_GUARD_ROWS {
        let mut filler = last.clone();
        filler.clk = fp(rows.len() as u64);
        rows.push(filler);
    }

    Ok((map.into_iter().collect(), rows))
}

fn build_bytetable_rows(
    rows: &[LogicalByteTableRow],
    call_id_lookup: &BTreeMap<u64, u64>,
) -> Result<Vec<Byte_table_values<Fp>>, WitnessGenerationError> {
    if rows.len() > MAX_BYTECODE_ROWS {
        return Err(WitnessGenerationError::ByteTableTooLong(rows.len()));
    }

    rows.iter()
        .map(|row| {
            Ok(Byte_table_values {
                call_id: fp(resolve_call_id(call_id_lookup, row.logical_call_id)?),
                pc: fp(row.pc),
                limb1: fp(row.limb1),
                limb2: fp(row.limb2),
                limb3: fp(row.limb3),
                limb4: fp(row.limb4),
                iscode: fp_bool(row.iscode),
            })
        })
        .collect()
}

fn build_tx_rows(rows: &[LogicalTxRow]) -> Result<Vec<TXTrace_values<Fp>>, WitnessGenerationError> {
    if rows.len() > MAX_TX_ROWS {
        return Err(WitnessGenerationError::TxTableTooLong(rows.len()));
    }

    Ok(rows
        .iter()
        .map(|row| TXTrace_values {
            q: fp_bool(row.active),
            txid: fp(row.txid),
            tag: fp(row.tag),
            index: fp(row.index),
            value_low: fp_u128(row.value_low),
            value_high: fp_u128(row.value_high),
        })
        .collect())
}

fn append_halt_padding_byte_rows(
    bytetable: &mut Vec<Byte_table_values<Fp>>,
    cpu_rows: &[CPU_values<Fp>],
) -> Result<(), WitnessGenerationError> {
    for row in cpu_rows
        .iter()
        .filter(|row| row.ishalt == Fp::ONE && row.call_id == Fp::ZERO)
    {
        let already_present = bytetable.iter().any(|byte_row| {
            byte_row.call_id == Fp::ZERO
                && byte_row.pc == row.pc
                && byte_row.limb1 == row.opcode
                && byte_row.limb2 == Fp::ZERO
                && byte_row.limb3 == Fp::ZERO
                && byte_row.limb4 == Fp::ZERO
                && byte_row.iscode == Fp::ONE
        });
        if !already_present {
            if bytetable.len() >= MAX_BYTECODE_ROWS {
                return Err(WitnessGenerationError::ByteTableTooLong(
                    bytetable.len() + 1,
                ));
            }
            bytetable.push(Byte_table_values {
                call_id: Fp::ZERO,
                pc: row.pc,
                limb1: row.opcode,
                limb2: Fp::ZERO,
                limb3: Fp::ZERO,
                limb4: Fp::ZERO,
                iscode: Fp::ONE,
            });
        }
    }

    Ok(())
}

fn build_alu_rows(
    input: &LogicalWitnessInput,
    cpu_rows: &[CPU_values<Fp>],
    _call_id_lookup: &BTreeMap<u64, u64>,
) -> Result<Vec<ALU_values<Fp>>, WitnessGenerationError> {
    let expected_arith = input
        .cpu_steps
        .iter()
        .filter(|step| {
            decode_opcode(step.opcode)
                .map(|f| f.is_arithmetic())
                .unwrap_or(false)
        })
        .count();
    if expected_arith != input.arithmetic_chunks.len() {
        return Err(WitnessGenerationError::ArithmeticChunkCountMismatch {
            expected: expected_arith,
            actual: input.arithmetic_chunks.len(),
        });
    }

    let mut rows = Vec::new();
    for chunk in &input.arithmetic_chunks {
        for (local_row, row) in chunk.rows.iter().enumerate() {
            rows.push(ALU_values {
                isfirst: fp_bool(local_row == 0),
                islast: fp_bool(local_row == 3),
                byte32: Fp::ZERO,
                isfirst32: Fp::ZERO,
                islast32: Fp::ZERO,
                limbnumber: fp(local_row as u64),
                isadd: fp_bool(
                    chunk.op == ArithmeticOpKind::Add || chunk.op == ArithmeticOpKind::Sub,
                ),
                ismul: fp_bool(chunk.op == ArithmeticOpKind::Mul),
                isdiv: fp_bool(chunk.op == ArithmeticOpKind::Div),
                islt: fp_bool(chunk.op == ArithmeticOpKind::Lt),
                iseq: fp_bool(chunk.op == ArithmeticOpKind::Eq),
                isand: fp_bool(chunk.op == ArithmeticOpKind::And),
                isor: fp_bool(chunk.op == ArithmeticOpKind::Or),
                isxor: fp_bool(chunk.op == ArithmeticOpKind::Xor),
                isnot: fp_bool(chunk.op == ArithmeticOpKind::Not),
                barlt: fp(row.barlt),
                carry: row.carry,
                rem: fp(row.rem),
                limb_a: fp(row.limb_a),
                limb_b: fp(row.limb_b),
                limb_c: fp(row.limb_c),
                pac_a: row.pac_a.map(fp),
                pac_b: row.pac_b.map(fp),
                pac_c: row.pac_c.map(fp),
                pac_carry: row.pac_carry.map(fp),
                pac_rem: row.pac_rem.map(fp),
                pac_diff: row.pac_diff.map(fp),
                rlc_a: row.rlc_a,
                rlc_b: row.rlc_b,
                rlc_c: row.rlc_c,
                noname: fp(row.noname),
            });
        }

        if matches!(chunk.op, ArithmeticOpKind::Div | ArithmeticOpKind::Eq) {
            rows.extend(zero_add_chunk());
        }
    }

    let has_memory_events = !input.memory_events.is_empty();
    if has_memory_events {
        while rows.len() % 32 != 0 {
            rows.extend(zero_add_chunk());
        }
    }

    for event in &input.memory_events {
        let step = input.cpu_steps.get(event.source_step).ok_or(
            WitnessGenerationError::MemoryEventSourceOutOfRange(event.source_step),
        )?;
        let flags = decode_opcode(step.opcode)?;
        if !(flags.ismload || flags.ismstore || flags.ismstore8) {
            return Err(WitnessGenerationError::MemoryEventOpcodeMismatch {
                source_step: event.source_step,
                opcode: step.opcode,
            });
        }
        let cpu_row = &cpu_rows[event.source_step];
        let base_address = narrow_word_to_u64(step.rlc_a, "memory address")?;
        let start_rwc = field_to_u64(cpu_row.rw_counter) + if flags.ismload { 1 } else { 2 };
        let call_id = field_to_u64(cpu_row.call_id);
        let packed_word = pack_alu_memory_rlc(event.bytes_in_local_row_order);

        for local_row in 0..32 {
            let byte = if flags.ismstore8 {
                event.bytes_in_local_row_order[0] as u64
            } else {
                event.bytes_in_local_row_order[local_row] as u64
            };
            let address = if flags.ismstore8 {
                base_address
            } else {
                base_address + local_row as u64
            };
            let rwc = if flags.ismstore8 {
                start_rwc
            } else {
                start_rwc + local_row as u64
            };

            rows.push(ALU_values {
                isfirst: fp_bool(local_row % 4 == 0),
                islast: fp_bool(local_row % 4 == 3),
                byte32: Fp::ONE,
                isfirst32: fp_bool(local_row == 0),
                islast32: fp_bool(local_row == 31),
                limbnumber: fp(local_row as u64),
                isadd: Fp::ZERO,
                ismul: Fp::ZERO,
                isdiv: Fp::ZERO,
                islt: Fp::ZERO,
                iseq: Fp::ZERO,
                isand: Fp::ZERO,
                isor: Fp::ZERO,
                isxor: Fp::ZERO,
                isnot: Fp::ZERO,
                barlt: Fp::ZERO,
                carry: fp(address),
                rem: fp(call_id),
                limb_a: Fp::ZERO,
                limb_b: Fp::ZERO,
                limb_c: Fp::ZERO,
                pac_a: [Fp::ZERO; 4],
                pac_b: [Fp::ZERO; 4],
                pac_c: [Fp::ZERO; 4],
                pac_carry: [
                    fp_bool(flags.ismstore8),
                    fp(rwc),
                    fp_bool(flags.ismload),
                    fp_bool(flags.ismstore),
                ],
                pac_rem: [Fp::ZERO; 4],
                pac_diff: [Fp::ZERO; 4],
                rlc_a: if local_row == 0 {
                    if flags.ismstore8 {
                        [byte, 0, 0, 0]
                    } else {
                        packed_word
                    }
                } else {
                    [0u64; 4]
                },
                rlc_b: [0u64; 4],
                rlc_c: [0u64; 4],
                noname: fp(byte),
            });
        }
    }

    pad_alu_rows(rows, has_memory_events)
}

fn build_copy_rows(
    rows: &[LogicalCopyRow],
    call_id_lookup: &BTreeMap<u64, u64>,
) -> Result<Vec<CopyTool_values<Fp>>, WitnessGenerationError> {
    if rows.len() > COPY_ASSIGN_ROWS {
        return Err(WitnessGenerationError::CopyTraceTooLong(rows.len()));
    }

    let mut out = Vec::with_capacity(COPY_ASSIGN_ROWS + COPY_TAIL_GUARD_ROWS);
    for row in rows {
        out.push(CopyTool_values {
            q: Fp::ONE,
            switch: fp_bool(row.switch),
            isfirst_fixed: Fp::ZERO,
            isfirst: fp_bool(row.isfirst),
            islast: fp_bool(row.islast),
            rwc: fp(row.rwc),
            address_write: fp(row.address_write),
            address_read: fp(row.address_read),
            address_end: fp(row.address_end),
            iswrite: fp_bool(row.iswrite),
            ismem: fp_bool(row.ismem),
            istx: fp_bool(row.istx),
            callid_read: fp(resolve_call_id(call_id_lookup, row.logical_call_id_read)?),
            callid_write: fp(resolve_call_id(call_id_lookup, row.logical_call_id_write)?),
            bytesleft: fp(row.bytesleft),
            value: fp(row.value),
            ispad: fp_bool(row.ispad),
            inv: row.inv,
            limb_1: fp(row.limb_1),
            limb_2: fp(row.limb_2),
        });
    }

    while out.len() < COPY_ASSIGN_ROWS + COPY_TAIL_GUARD_ROWS {
        let isfirst = out.is_empty();
        out.push(CopyTool_values {
            q: Fp::ONE,
            switch: Fp::ZERO,
            isfirst_fixed: Fp::ZERO,
            isfirst: fp_bool(isfirst),
            islast: Fp::ZERO,
            rwc: Fp::ZERO,
            address_write: Fp::ZERO,
            address_read: Fp::ZERO,
            address_end: Fp::ZERO,
            iswrite: Fp::ZERO,
            ismem: Fp::ZERO,
            istx: Fp::ZERO,
            callid_read: Fp::ZERO,
            callid_write: Fp::ZERO,
            bytesleft: Fp::ZERO,
            value: Fp::ZERO,
            ispad: Fp::ZERO,
            inv: Fp::ZERO,
            limb_1: Fp::ZERO,
            limb_2: Fp::ZERO,
        });
    }

    Ok(out)
}

fn build_rw_rows(
    base_rows: &[LogicalRwRow],
    memory_events: &[LogicalMemoryEvent],
    cpu_rows: &[CPU_values<Fp>],
    call_id_lookup: &BTreeMap<u64, u64>,
) -> Result<Vec<RWTrace_values<Fp>>, WitnessGenerationError> {
    let mut rows = Vec::new();

    for row in base_rows {
        rows.push(RWTrace_values {
            tag: fp(row.tag),
            call_id: fp(resolve_call_id(call_id_lookup, row.logical_call_id)?),
            address: fp(row.address),
            field_tag: fp(row.field_tag),
            storage_key: fp(row.storage_key),
            rw_counter: fp(row.rw_counter),
            iswrite: fp_bool(row.iswrite),
            value: row.value,
            isend: Fp::ZERO,
        });
    }

    for event in memory_events {
        let cpu_row = cpu_rows.get(event.source_step).ok_or(
            WitnessGenerationError::MemoryEventSourceOutOfRange(event.source_step),
        )?;
        let step_call_id = field_to_u64(cpu_row.call_id);
        let step_rwc = field_to_u64(cpu_row.rw_counter);
        let opcode = field_to_u64(cpu_row.opcode);
        let flags = decode_opcode(opcode)?;
        let address = narrow_word_to_u64(cpu_row.rlc_a, "memory address")?;
        let start_rwc = step_rwc + if flags.ismload { 1 } else { 2 };

        if flags.ismstore8 {
            rows.push(RWTrace_values {
                tag: Fp::ONE,
                call_id: fp(step_call_id),
                address: fp(address),
                field_tag: Fp::ZERO,
                storage_key: Fp::ZERO,
                rw_counter: fp(start_rwc),
                iswrite: Fp::ONE,
                value: [event.bytes_in_local_row_order[0] as u64, 0, 0, 0],
                isend: Fp::ZERO,
            });
        } else {
            for (offset, byte) in event.bytes_in_local_row_order.iter().enumerate() {
                rows.push(RWTrace_values {
                    tag: Fp::ONE,
                    call_id: fp(step_call_id),
                    address: fp(address + offset as u64),
                    field_tag: Fp::ZERO,
                    storage_key: Fp::ZERO,
                    rw_counter: fp(start_rwc + offset as u64),
                    iswrite: fp_bool(flags.ismstore),
                    value: [*byte as u64, 0, 0, 0],
                    isend: Fp::ZERO,
                });
            }
        }
    }

    Ok(rows)
}

fn copy_rows_to_rwtrace(
    rows: &[LogicalCopyRow],
    call_id_lookup: &BTreeMap<u64, u64>,
) -> Result<Vec<RWTrace_values<Fp>>, WitnessGenerationError> {
    let mut out = Vec::new();
    for row in rows.iter().filter(|row| row.switch) {
        if row.ismem {
            let call_id = if row.iswrite {
                resolve_call_id(call_id_lookup, row.logical_call_id_write)?
            } else {
                resolve_call_id(call_id_lookup, row.logical_call_id_read)?
            };
            let address = if row.iswrite {
                row.address_write
            } else {
                row.address_read
            };
            out.push(RWTrace_values {
                tag: Fp::ONE,
                call_id: fp(call_id),
                address: fp(address),
                field_tag: Fp::ZERO,
                storage_key: Fp::ZERO,
                rw_counter: fp(row.rwc),
                iswrite: fp_bool(row.iswrite),
                value: [row.value, 0, 0, 0],
                isend: Fp::ZERO,
            });
        } else if row.istx && row.iswrite {
            out.push(RWTrace_values {
                tag: Fp::ONE,
                call_id: fp(resolve_call_id(call_id_lookup, row.logical_call_id_write)?),
                address: fp(row.address_write),
                field_tag: Fp::ZERO,
                storage_key: Fp::ZERO,
                rw_counter: fp(row.rwc),
                iswrite: Fp::ONE,
                value: [row.value, 0, 0, 0],
                isend: Fp::ZERO,
            });
        }
    }
    Ok(out)
}

fn fill_missing_rw_counters(rows: &mut Vec<RWTrace_values<Fp>>) {
    let Some(first) = rows.first() else {
        return;
    };

    let mut filled = Vec::with_capacity(rows.len());
    let mut expected = field_to_u64(first.rw_counter);
    if expected > 0 {
        expected = 0;
    }

    for row in rows.iter() {
        let current = field_to_u64(row.rw_counter);
        while expected < current {
            filled.push(dummy_rw_counter_row(expected));
            expected += 1;
        }
        filled.push(row.clone());
        expected = current.saturating_add(1);
    }

    *rows = filled;
}

fn validate_endtx_terminal_rw_counter(
    cpu_rows: &[CPU_values<Fp>],
    logical_cpu_rows: usize,
    rwtrace: &[RWTrace_values<Fp>],
) -> Result<(), WitnessGenerationError> {
    let logical_rows = cpu_rows
        .get(..logical_cpu_rows)
        .ok_or(WitnessGenerationError::CpuTraceTooLong(logical_cpu_rows))?;

    let endtx_row = logical_rows
        .iter()
        .find(|row| row.isendtx == Fp::ONE)
        .ok_or(WitnessGenerationError::CpuTraceMustEndWithEndTxBeforeHalt)?;

    let terminal_rw_counter = rwtrace
        .last()
        .map(|row| field_to_u64(row.rw_counter).saturating_add(1))
        .unwrap_or(0);
    let endtx_rw_counter = field_to_u64(endtx_row.rw_counter);

    if endtx_rw_counter != terminal_rw_counter {
        return Err(WitnessGenerationError::EndTxRwCounterMismatch {
            endtx_rw_counter,
            terminal_rw_counter,
        });
    }

    Ok(())
}

fn dummy_rw_counter_row(rw_counter: u64) -> RWTrace_values<Fp> {
    RWTrace_values {
        tag: Fp::ZERO,
        call_id: fp(2),
        address: Fp::ZERO,
        field_tag: Fp::ZERO,
        storage_key: Fp::ZERO,
        rw_counter: fp(rw_counter),
        iswrite: Fp::ONE,
        value: [0; 4],
        isend: Fp::ZERO,
    }
}

fn build_rwstate_rows(trace: &[RWTrace_values<Fp>]) -> Vec<RWState_values<Fp>> {
    let mut rows = trace.to_vec();
    rows.sort_by_key(|row| {
        (
            field_to_u64(row.tag),
            field_to_u64(row.call_id),
            field_to_u64(row.address),
            field_to_u64(row.field_tag),
            field_to_u64(row.storage_key),
            field_to_u64(row.rw_counter),
        )
    });
    if let Some(last) = rows.last().cloned() {
        rows.push(RWTrace_values {
            tag: last.tag,
            call_id: last.call_id,
            address: last.address,
            field_tag: last.field_tag,
            storage_key: last.storage_key,
            rw_counter: last.rw_counter + Fp::ONE,
            iswrite: Fp::ZERO,
            value: [0; 4],
            isend: Fp::ONE,
        });
    }

    let mut out = Vec::with_capacity(rows.len());
    for (i, row) in rows.iter().enumerate() {
        let next = rows.get(i + 1);
        let (
            tag_changed,
            call_id_changed,
            address_changed,
            field_tag_changed,
            storage_key_changed,
            rw_counter_changed,
            limbs,
        ) = if let Some(next_row) = next {
            derive_rwstate_transition(row, next_row)
        } else {
            (false, false, false, false, false, false, [0u16; 10])
        };

        out.push(RWState_values {
            isfirst: fp_bool(i == 0),
            tag: row.tag,
            call_id: row.call_id,
            isroot: fp_bool(is_root_public_rwstate_row(row)),
            address: row.address,
            field_tag: row.field_tag,
            storage_key: row.storage_key,
            rw_counter: row.rw_counter,
            tag_changed: fp_bool(tag_changed),
            call_id_changed: fp_bool(call_id_changed),
            address_changed: fp_bool(address_changed),
            field_tag_changed: fp_bool(field_tag_changed),
            storage_key_changed: fp_bool(storage_key_changed),
            rw_counter_changed: fp_bool(rw_counter_changed),
            iswrite: row.iswrite,
            value: row.value,
            isend: row.isend,
            z: Fp::ZERO,
            limb_1: fp(limbs[0] as u64),
            limb_2: fp(limbs[1] as u64),
            limb_3: fp(limbs[2] as u64),
            limb_4: fp(limbs[3] as u64),
            limb_5: fp(limbs[4] as u64),
            limb_6: fp(limbs[5] as u64),
            limb_7: fp(limbs[6] as u64),
            limb_8: fp(limbs[7] as u64),
            limb_9: fp(limbs[8] as u64),
            limb_10: fp(limbs[9] as u64),
        });
    }

    out
}

fn is_root_public_rwstate_row(row: &RWTrace_values<Fp>) -> bool {
    matches!(field_to_u64(row.tag), 1 | 2)
        && field_to_u64(row.call_id) == 1
        && row.isend == Fp::ZERO
}

fn derive_rwstate_transition(
    cur: &RWTrace_values<Fp>,
    next: &RWTrace_values<Fp>,
) -> (bool, bool, bool, bool, bool, bool, [u16; 10]) {
    let cur_key = [
        field_to_u64(cur.tag),
        field_to_u64(cur.call_id),
        field_to_u64(cur.address),
        field_to_u64(cur.field_tag),
        field_to_u64(cur.storage_key),
        field_to_u64(cur.rw_counter),
    ];
    let next_key = [
        field_to_u64(next.tag),
        field_to_u64(next.call_id),
        field_to_u64(next.address),
        field_to_u64(next.field_tag),
        field_to_u64(next.storage_key),
        field_to_u64(next.rw_counter),
    ];

    for idx in 0..6 {
        if next_key[idx] != cur_key[idx] {
            let delta_minus_one = next_key[idx] - cur_key[idx] - 1;
            let limbs = to_u16_limbs(delta_minus_one);
            return match idx {
                0 => (true, false, false, false, false, false, limbs),
                1 => (false, true, false, false, false, false, limbs),
                2 => (false, false, true, false, false, false, limbs),
                3 => (false, false, false, true, false, false, limbs),
                4 => (false, false, false, false, true, false, limbs),
                5 => (false, false, false, false, false, true, limbs),
                _ => unreachable!(),
            };
        }
    }

    (false, false, false, false, false, false, [0u16; 10])
}

fn build_public_output_rows(rwstate: &[RWState_values<Fp>]) -> Vec<PublicOutput_values<Fp>> {
    rwstate
        .iter()
        .filter(|row| row.isroot == Fp::ONE)
        .map(|row| PublicOutput_values {
            active: Fp::ONE,
            tag: row.tag,
            address: row.address,
            iswrite: row.iswrite,
            value: row.value,
            rw_counter: row.rw_counter,
        })
        .collect()
}

fn build_public_inputs(
    bytetable: &[Byte_table_values<Fp>],
    txtrace: &[TXTrace_values<Fp>],
    output: &[PublicOutput_values<Fp>],
) -> Vec<Vec<Fp>> {
    let mut byte_active = vec![Fp::ZERO; MAX_BYTECODE_ROWS];
    let mut byte_call_id = vec![Fp::ZERO; MAX_BYTECODE_ROWS];
    let mut byte_pc = vec![Fp::ZERO; MAX_BYTECODE_ROWS];
    let mut byte_limb1 = vec![Fp::ZERO; MAX_BYTECODE_ROWS];
    let mut byte_limb2 = vec![Fp::ZERO; MAX_BYTECODE_ROWS];
    let mut byte_limb3 = vec![Fp::ZERO; MAX_BYTECODE_ROWS];
    let mut byte_limb4 = vec![Fp::ZERO; MAX_BYTECODE_ROWS];
    let mut byte_iscode = vec![Fp::ZERO; MAX_BYTECODE_ROWS];

    for (idx, row) in bytetable.iter().enumerate() {
        byte_active[idx] = Fp::ONE;
        byte_call_id[idx] = row.call_id;
        byte_pc[idx] = row.pc;
        byte_limb1[idx] = row.limb1;
        byte_limb2[idx] = row.limb2;
        byte_limb3[idx] = row.limb3;
        byte_limb4[idx] = row.limb4;
        byte_iscode[idx] = row.iscode;
    }

    let mut tx_active = vec![Fp::ZERO; MAX_TX_ROWS];
    let mut txid = vec![Fp::ZERO; MAX_TX_ROWS];
    let mut tag = vec![Fp::ZERO; MAX_TX_ROWS];
    let mut index = vec![Fp::ZERO; MAX_TX_ROWS];
    let mut value_low = vec![Fp::ZERO; MAX_TX_ROWS];
    let mut value_high = vec![Fp::ZERO; MAX_TX_ROWS];

    for (idx, row) in txtrace.iter().enumerate() {
        tx_active[idx] = row.q;
        txid[idx] = row.txid;
        tag[idx] = row.tag;
        index[idx] = row.index;
        value_low[idx] = row.value_low;
        value_high[idx] = row.value_high;
    }

    let mut output_active = vec![Fp::ZERO; PUBLIC_OUTPUT_ROWS];
    let mut output_tag = vec![Fp::ZERO; PUBLIC_OUTPUT_ROWS];
    let mut output_address = vec![Fp::ZERO; PUBLIC_OUTPUT_ROWS];
    let mut output_iswrite = vec![Fp::ZERO; PUBLIC_OUTPUT_ROWS];
    let mut output_value_0 = vec![Fp::ZERO; PUBLIC_OUTPUT_ROWS];
    let mut output_value_1 = vec![Fp::ZERO; PUBLIC_OUTPUT_ROWS];
    let mut output_value_2 = vec![Fp::ZERO; PUBLIC_OUTPUT_ROWS];
    let mut output_value_3 = vec![Fp::ZERO; PUBLIC_OUTPUT_ROWS];
    let mut output_rw_counter = vec![Fp::ZERO; PUBLIC_OUTPUT_ROWS];

    for (idx, row) in output.iter().enumerate() {
        output_active[idx] = row.active;
        output_tag[idx] = row.tag;
        output_address[idx] = row.address;
        output_iswrite[idx] = row.iswrite;
        output_value_0[idx] = fp(row.value[0]);
        output_value_1[idx] = fp(row.value[1]);
        output_value_2[idx] = fp(row.value[2]);
        output_value_3[idx] = fp(row.value[3]);
        output_rw_counter[idx] = row.rw_counter;
    }

    vec![
        byte_active,
        byte_call_id,
        byte_pc,
        byte_limb1,
        byte_limb2,
        byte_limb3,
        byte_limb4,
        byte_iscode,
        tx_active,
        txid,
        tag,
        index,
        value_low,
        value_high,
        output_active,
        output_tag,
        output_address,
        output_iswrite,
        output_value_0,
        output_value_1,
        output_value_2,
        output_value_3,
        output_rw_counter,
    ]
}

fn logical_alu_len(input: &LogicalWitnessInput) -> usize {
    input.arithmetic_chunks.len() * 4 + input.memory_events.len() * 32
}

fn resolve_call_id(
    call_id_lookup: &BTreeMap<u64, u64>,
    logical_call_id: u64,
) -> Result<u64, WitnessGenerationError> {
    call_id_lookup.get(&logical_call_id).copied().ok_or(
        WitnessGenerationError::UnknownLogicalCallId(logical_call_id),
    )
}

fn decode_opcode(opcode: u64) -> Result<OpcodeFlags, WitnessGenerationError> {
    decode_circuit_opcode(opcode).ok_or(WitnessGenerationError::UnsupportedOpcode(opcode))
}

fn compute_addr_a(sp: u64, flags: &OpcodeFlags) -> Fp {
    if flags.iswrite {
        fp(sp)
    } else {
        fp_sub_u64(sp, 1)
    }
}

fn selected_return_len(step: &LogicalCpuStep) -> Result<u64, WitnessGenerationError> {
    let requested = narrow_word_to_u64(step.rlc_g, "rlc_g return length")?;
    let actual = narrow_word_to_u64(step.rlc_i, "rlc_i return length")?;
    let selector = narrow_word_to_u64(step.rlc_j, "rlc_j selector")?;
    Ok(if selector == 1 { requested } else { actual })
}

fn fp_inverse_u64(value: u64) -> Fp {
    fp(value).invert().unwrap_or(Fp::ZERO)
}

fn fp_sub_u64(value: u64, sub: u64) -> Fp {
    fp(value) - fp(sub)
}

fn rwc_delta(step: &LogicalCpuStep, flags: &OpcodeFlags) -> Result<u64, WitnessGenerationError> {
    let delta = if flags.isbegintx {
        12
    } else if flags.iscall {
        24
    } else if flags.returndatacopy {
        let len_c = narrow_word_to_u64(step.rlc_c, "rlc_c length")?;
        5 + 2 * len_c
    } else if flags.calldatacopy {
        let len_c = narrow_word_to_u64(step.rlc_c, "rlc_c length")?;
        let isroot = narrow_word_to_u64(step.rlc_g, "rlc_g isroot")?;
        7 + len_c * (2 - isroot)
    } else if flags.isreturn {
        14 + 2 * selected_return_len(step)?
    } else if flags.ismstore || flags.ismload {
        34
    } else if flags.isadd
        || flags.issub
        || flags.ismul
        || flags.isdiv
        || flags.islt
        || flags.iseq
        || flags.isand
        || flags.isor
        || flags.isxor
        || flags.ismstore8
    {
        3
    } else if flags.isjumpcon || flags.isnot {
        2
    } else if flags.isread || flags.isjump || flags.iswrite {
        1
    } else {
        0
    };
    Ok(delta)
}

fn zero_add_chunk() -> [ALU_values<Fp>; 4] {
    core::array::from_fn(|idx| ALU_values {
        isfirst: fp_bool(idx == 0),
        islast: fp_bool(idx == 3),
        byte32: Fp::ZERO,
        isfirst32: fp_bool(idx == 0),
        islast32: Fp::ZERO,
        limbnumber: fp(idx as u64),
        isadd: Fp::ONE,
        ismul: Fp::ZERO,
        isdiv: Fp::ZERO,
        islt: Fp::ZERO,
        iseq: Fp::ZERO,
        isand: Fp::ZERO,
        isor: Fp::ZERO,
        isxor: Fp::ZERO,
        isnot: Fp::ZERO,
        barlt: Fp::ZERO,
        carry: Fp::ZERO,
        rem: Fp::ZERO,
        limb_a: Fp::ZERO,
        limb_b: Fp::ZERO,
        limb_c: Fp::ZERO,
        pac_a: [Fp::ZERO; 4],
        pac_b: [Fp::ZERO; 4],
        pac_c: [Fp::ZERO; 4],
        pac_carry: [Fp::ZERO; 4],
        pac_rem: [Fp::ZERO; 4],
        pac_diff: [Fp::ZERO; 4],
        rlc_a: [0u64; 4],
        rlc_b: [0u64; 4],
        rlc_c: [0u64; 4],
        noname: Fp::ZERO,
    })
}

fn dummy_mstore8_memory_chunk() -> [ALU_values<Fp>; 32] {
    core::array::from_fn(|idx| ALU_values {
        isfirst: fp_bool(idx % 4 == 0),
        islast: fp_bool(idx % 4 == 3),
        byte32: Fp::ONE,
        isfirst32: fp_bool(idx == 0),
        islast32: fp_bool(idx == 31),
        limbnumber: fp(idx as u64),
        isadd: Fp::ZERO,
        ismul: Fp::ZERO,
        isdiv: Fp::ZERO,
        islt: Fp::ZERO,
        iseq: Fp::ZERO,
        isand: Fp::ZERO,
        isor: Fp::ZERO,
        isxor: Fp::ZERO,
        isnot: Fp::ZERO,
        barlt: Fp::ZERO,
        carry: Fp::ZERO,
        rem: Fp::ZERO,
        limb_a: Fp::ZERO,
        limb_b: Fp::ZERO,
        limb_c: Fp::ZERO,
        pac_a: [Fp::ZERO; 4],
        pac_b: [Fp::ZERO; 4],
        pac_c: [Fp::ZERO; 4],
        pac_carry: [Fp::ONE, Fp::ZERO, Fp::ZERO, Fp::ZERO],
        pac_rem: [Fp::ZERO; 4],
        pac_diff: [Fp::ZERO; 4],
        rlc_a: [0u64; 4],
        rlc_b: [0u64; 4],
        rlc_c: [0u64; 4],
        noname: Fp::ZERO,
    })
}

fn pad_alu_rows(
    mut rows: Vec<ALU_values<Fp>>,
    memory_suffix: bool,
) -> Result<Vec<ALU_values<Fp>>, WitnessGenerationError> {
    if rows.len() > ALU_LOGICAL_MAX_ROWS {
        return Err(WitnessGenerationError::AluTraceTooLong(rows.len()));
    }

    if memory_suffix {
        let padding_chunk = if rows.len() >= 32 {
            rows[rows.len() - 32..].to_vec()
        } else {
            dummy_mstore8_memory_chunk().to_vec()
        };
        while rows.len() < ALU_ASSIGN_ROWS {
            rows.extend(padding_chunk.iter().cloned());
        }
    } else {
        while rows.len() < ALU_ASSIGN_ROWS {
            rows.extend(zero_add_chunk());
        }
    }

    rows.truncate(ALU_ASSIGN_ROWS);
    Ok(rows)
}

fn pack_alu_memory_rlc(bytes: [u8; 32]) -> [u64; 4] {
    [
        pack_rev_u64(&bytes[24..32]),
        pack_rev_u64(&bytes[16..24]),
        pack_rev_u64(&bytes[8..16]),
        pack_rev_u64(&bytes[0..8]),
    ]
}

fn pack_le_u64(slice: &[u8]) -> u64 {
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(slice);
    u64::from_le_bytes(bytes)
}

fn pack_rev_u64(slice: &[u8]) -> u64 {
    let mut bytes = [0u8; 8];
    for (idx, byte) in slice.iter().rev().enumerate() {
        bytes[idx] = *byte;
    }
    u64::from_le_bytes(bytes)
}

fn narrow_word_to_u64(word: [u64; 4], name: &'static str) -> Result<u64, WitnessGenerationError> {
    if word[1] != 0 || word[2] != 0 || word[3] != 0 {
        return Err(WitnessGenerationError::NarrowValueRequired(name));
    }
    Ok(word[0])
}

fn field_to_u64(value: Fp) -> u64 {
    let repr = value.to_repr();
    let bytes = repr.as_ref();
    let mut low = [0u8; 8];
    low.copy_from_slice(&bytes[..8]);
    u64::from_le_bytes(low)
}

fn to_u16_limbs(mut value: u64) -> [u16; 10] {
    let mut limbs = [0u16; 10];
    for limb in &mut limbs {
        *limb = (value & 0xffff) as u16;
        value >>= 16;
    }
    limbs
}

fn fp(value: u64) -> Fp {
    Fp::from(value)
}

fn fp_u128(value: u128) -> Fp {
    Fp::from_u128(value)
}

fn fp_bool(value: bool) -> Fp {
    if value {
        Fp::ONE
    } else {
        Fp::ZERO
    }
}

type OpcodeFlags = CircuitOpcodeFlags;
