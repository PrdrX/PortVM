use super::*;
use std::collections::BTreeMap;

const TX_TAG_CALLER_ADDRESS: u64 = 4;
const TX_TAG_CALLEE_ADDRESS: u64 = 5;
const TX_TAG_VALUE: u64 = 7;
const TX_TAG_CALLDATA_LENGTH: u64 = 8;
const TX_TAG_CALLDATA_BYTE: u64 = 1;

const CC_TAG_CALLER_ID: u64 = 2;
const CC_TAG_DEPTH: u64 = 4;
const CC_TAG_CALLER_ADDRESS: u64 = 5;
const CC_TAG_CALLEE_ADDRESS: u64 = 6;
const CC_TAG_CALLDATA_OFFSET: u64 = 7;
const CC_TAG_CALLDATA_LENGTH: u64 = 8;
const CC_TAG_RETURNDATA_OFFSET: u64 = 9;
const CC_TAG_RETURNDATA_LENGTH: u64 = 10;
const CC_TAG_VALUE: u64 = 11;
const CC_TAG_ISSUCCESS: u64 = 12;
const CC_TAG_ISPERSISTENCE: u64 = 13;
const CC_TAG_ISROOT: u64 = 15;
const CC_TAG_LAST_CALLEE_ID: u64 = 18;
const CC_TAG_LAST_CALLEE_RETURNDATA_OFFSET: u64 = 19;
const CC_TAG_LAST_CALLEE_RETURNDATA_LENGTH: u64 = 20;
const CC_TAG_PC: u64 = 21;
const CC_TAG_SP: u64 = 22;
const CC_TAG_MMAX: u64 = 24;

#[derive(Debug, Clone, Default)]
pub struct ExecutionHints {
    pub call_hints: Vec<CallHint>,
    pub call_targets: Vec<CallTargetHint>,
}

#[derive(Debug, Clone)]
pub struct CallHint {
    pub caller_logical_call_id: u64,
    pub caller_pc: u64,
    pub child_image_id: Option<u64>,
    pub child_issuccess: Option<bool>,
}

#[derive(Debug, Clone)]
pub struct CallTargetHint {
    pub callee_address: [u64; 4],
    pub child_image_id: u64,
    pub child_issuccess: Option<bool>,
}

#[derive(Debug, Clone)]
pub struct ExecutionDeploymentRow {
    pub callee_address: [u64; 4],
    pub image_id: u64,
}

#[derive(Debug, Clone)]
pub struct ExecutionBytecodeRow {
    pub image_id: u64,
    pub pc: u64,
    pub limb1: u64,
    pub limb2: u64,
    pub limb3: u64,
    pub limb4: u64,
    pub iscode: bool,
}

#[derive(Debug, Clone)]
pub struct CompactLogicalByteTableRow {
    pub logical_call_id: u64,
    /// Decimal or 0x-prefixed hexadecimal unsigned value, up to 256 bits.
    pub value: String,
}

#[derive(Debug, Clone)]
pub struct CompactExecutionBytecodeRow {
    pub image_id: u64,
    /// Decimal or 0x-prefixed hexadecimal unsigned value, up to 256 bits.
    pub value: String,
}

#[derive(Debug, Clone)]
pub struct ExecutionPublicTables {
    pub root_image_id: u64,
    pub bytecode_rows: Vec<LogicalByteTableRow>,
    pub compact_bytecode_rows: Vec<CompactLogicalByteTableRow>,
    pub bytecode_image_rows: Vec<ExecutionBytecodeRow>,
    pub compact_bytecode_image_rows: Vec<CompactExecutionBytecodeRow>,
    pub deployment_rows: Vec<ExecutionDeploymentRow>,
    pub tx_rows: Vec<LogicalTxRow>,
    pub compact_tx_rows: Vec<CompactLogicalTxRow>,
}

impl Default for ExecutionPublicTables {
    fn default() -> Self {
        Self {
            root_image_id: 0,
            bytecode_rows: Vec::new(),
            compact_bytecode_rows: Vec::new(),
            bytecode_image_rows: Vec::new(),
            compact_bytecode_image_rows: Vec::new(),
            deployment_rows: Vec::new(),
            tx_rows: Vec::new(),
            compact_tx_rows: Vec::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ExecutionInput {
    pub root_logical_call_id: u64,
    pub root_image_id: u64,
    pub bytecode_rows: Vec<LogicalByteTableRow>,
    pub compact_bytecode_rows: Vec<CompactLogicalByteTableRow>,
    pub bytecode_image_rows: Vec<ExecutionBytecodeRow>,
    pub compact_bytecode_image_rows: Vec<CompactExecutionBytecodeRow>,
    pub deployment_rows: Vec<ExecutionDeploymentRow>,
    pub tx_rows: Vec<LogicalTxRow>,
    pub compact_tx_rows: Vec<CompactLogicalTxRow>,
    pub hints: ExecutionHints,
    pub max_steps: Option<usize>,
}

impl Default for ExecutionInput {
    fn default() -> Self {
        Self {
            root_logical_call_id: 0,
            root_image_id: 0,
            bytecode_rows: Vec::new(),
            compact_bytecode_rows: Vec::new(),
            bytecode_image_rows: Vec::new(),
            compact_bytecode_image_rows: Vec::new(),
            deployment_rows: Vec::new(),
            tx_rows: Vec::new(),
            compact_tx_rows: Vec::new(),
            hints: ExecutionHints::default(),
            max_steps: None,
        }
    }
}

impl ExecutionInput {
    pub fn from_public_tables(tables: ExecutionPublicTables) -> Self {
        Self {
            root_logical_call_id: 0,
            root_image_id: tables.root_image_id,
            bytecode_rows: tables.bytecode_rows,
            compact_bytecode_rows: tables.compact_bytecode_rows,
            bytecode_image_rows: tables.bytecode_image_rows,
            compact_bytecode_image_rows: tables.compact_bytecode_image_rows,
            deployment_rows: tables.deployment_rows,
            tx_rows: tables.tx_rows,
            compact_tx_rows: tables.compact_tx_rows,
            hints: ExecutionHints::default(),
            max_steps: None,
        }
    }

    pub fn with_root_logical_call_id(mut self, root_logical_call_id: u64) -> Self {
        self.root_logical_call_id = root_logical_call_id;
        self
    }

    pub fn with_hints(mut self, hints: ExecutionHints) -> Self {
        self.hints = hints;
        self
    }

    pub fn with_max_steps(mut self, max_steps: usize) -> Self {
        self.max_steps = (max_steps != 0).then_some(max_steps);
        self
    }
}

#[derive(Debug, Clone)]
pub struct ExecutionTrace {
    pub bytecode_rows: Vec<LogicalByteTableRow>,
    pub tx_rows: Vec<LogicalTxRow>,
    pub cpu_steps: Vec<LogicalCpuStep>,
    pub arithmetic_ops: Vec<ExecutionArithmeticOp>,
    pub memory_events: Vec<LogicalMemoryEvent>,
    pub copy_plans: Vec<ExecutionCopyPlan>,
    pub events: Vec<ExecutionEvent>,
    pub final_frames: Vec<ExecutionFrameState>,
}

#[derive(Debug, Clone)]
pub struct GeneratedExecutionWitness {
    pub execution_trace: ExecutionTrace,
    pub logical_witness_input: LogicalWitnessInput,
    pub generated_witness: GeneratedWitness,
}

impl ExecutionTrace {
    pub fn into_partial_witness_input(self) -> LogicalWitnessInput {
        LogicalWitnessInput {
            bytecode_rows: self.bytecode_rows,
            tx_rows: self.tx_rows,
            cpu_steps: self.cpu_steps,
            arithmetic_chunks: Vec::new(),
            memory_events: self.memory_events,
            copy_rows: Vec::new(),
            rw_rows: Vec::new(),
        }
    }

    pub fn into_lowered_witness_input(self) -> Result<LogicalWitnessInput, ExecutionError> {
        let Self {
            bytecode_rows,
            tx_rows,
            cpu_steps,
            arithmetic_ops,
            memory_events,
            copy_plans,
            events: _,
            final_frames: _,
        } = self;

        let logical_to_actual = logical_to_actual_call_ids(&cpu_steps)?;
        let lowered_cpu_steps =
            rewrite_cpu_steps_for_actual_call_ids(&cpu_steps, &logical_to_actual)?;
        let arithmetic_chunks = lower_arithmetic_chunks(&arithmetic_ops)?;
        let rw_counter_bases = cpu_rwc_bases(&lowered_cpu_steps)?;
        let rw_rows = lower_rw_rows(
            &cpu_steps,
            &lowered_cpu_steps,
            &rw_counter_bases,
            &logical_to_actual,
        )?;
        let copy_rows = lower_copy_rows(&copy_plans, &rw_counter_bases)?;

        Ok(LogicalWitnessInput {
            bytecode_rows,
            tx_rows,
            cpu_steps: lowered_cpu_steps,
            arithmetic_chunks,
            memory_events,
            copy_rows,
            rw_rows,
        })
    }
}

#[derive(Debug, Clone)]
pub struct ExecutionArithmeticOp {
    pub source_step: usize,
    pub op: ArithmeticOpKind,
    pub lhs: [u64; 4],
    pub rhs: [u64; 4],
    pub result: [u64; 4],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CopyPlanKind {
    Return,
    ReturnDataCopy,
    CallDataCopy,
}

#[derive(Debug, Clone)]
pub struct ExecutionCopyPlan {
    pub source_step: usize,
    pub kind: CopyPlanKind,
    pub src_call_id: Option<u64>,
    pub dst_call_id: u64,
    pub src_offset: u64,
    pub src_end: u64,
    pub dst_offset: u64,
    pub length: u64,
    pub bytes: Vec<u8>,
    pub use_tx_source: bool,
}

#[derive(Debug, Clone)]
pub enum ExecutionEvent {
    BytecodeRead {
        logical_call_id: u64,
        pc: u64,
        opcode: u8,
    },
    ImmediateRead {
        logical_call_id: u64,
        pc: u64,
        value: [u64; 4],
    },
    StackRead {
        logical_call_id: u64,
        address: u64,
        value: [u64; 4],
    },
    StackWrite {
        logical_call_id: u64,
        address: u64,
        value: [u64; 4],
    },
    MemoryRead {
        logical_call_id: u64,
        address: u64,
        value: u8,
    },
    MemoryWrite {
        logical_call_id: u64,
        address: u64,
        value: u8,
    },
    CallContextRead {
        logical_call_id: u64,
        field_tag: u64,
        value: [u64; 4],
    },
    CallContextWrite {
        logical_call_id: u64,
        field_tag: u64,
        value: [u64; 4],
    },
    TxRead {
        txid: u64,
        tag: u64,
        index: u64,
        value_low: u128,
        value_high: u128,
    },
    StateRead {
        logical_call_id: u64,
        key: [u64; 4],
    },
    Call {
        caller_logical_call_id: u64,
        child_logical_call_id: u64,
    },
    Return {
        child_logical_call_id: u64,
        parent_logical_call_id: u64,
    },
}

#[derive(Debug, Clone)]
pub struct ExecutionFrameState {
    pub logical_call_id: u64,
    pub image_id: u64,
    pub parent_logical_call_id: Option<u64>,
    pub live_pc: u64,
    pub live_sp: u64,
    pub live_mmax: u64,
    pub stack: Vec<(u64, [u64; 4])>,
    pub memory: Vec<(u64, u8)>,
    pub call_context: Vec<(u64, [u64; 4])>,
}

#[derive(Debug, Clone)]
pub enum ExecutionError {
    EmptyBytecode,
    BytecodeInputConflict,
    UnknownRootCallId(u64),
    UnknownBytecodeCallId(u64),
    UnknownCallIdMapping(u64),
    InvalidRootLogicalCallId(u64),
    NonContiguousLogicalCallIds {
        expected: u64,
        found: u64,
    },
    DuplicateBytecodeCell {
        logical_call_id: u64,
        pc: u64,
        iscode: bool,
    },
    DuplicateCallHint {
        logical_call_id: u64,
        pc: u64,
    },
    DuplicateCallTarget([u64; 4]),
    DuplicateDeploymentAddress([u64; 4]),
    DuplicateLogicalCallId(u64),
    ArithmeticOverflow(&'static str),
    ArithmeticMismatch(&'static str),
    MissingOpcode {
        logical_call_id: u64,
        pc: u64,
    },
    MissingImmediate {
        logical_call_id: u64,
        pc: u64,
    },
    NonByteOpcode {
        logical_call_id: u64,
        pc: u64,
        value: u64,
    },
    NonByteValue(&'static str),
    TxMetadataMissing(&'static str),
    TxCalldataLengthMismatch {
        declared: u64,
        actual: usize,
    },
    StackUnderflow {
        logical_call_id: u64,
        pc: u64,
        sp: u64,
        needed: u64,
    },
    MissingSpawnedLogicalCallId(usize),
    CallHintMissing {
        logical_call_id: u64,
        pc: u64,
    },
    CallTargetMissing {
        logical_call_id: u64,
        pc: u64,
        callee_address: [u64; 4],
    },
    RootReturn,
    StepLimitExceeded(usize),
    ParentFrameMissing(u64),
    NarrowValueRequired(&'static str),
    InvalidCompactValue(String),
    CompactValueTooLarge,
    CompactBytecodeRowsOutOfOrder {
        previous_id: u64,
        found_id: u64,
    },
    UnsupportedOpcode(u64),
}

impl std::fmt::Display for ExecutionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyBytecode => f.write_str("bytecode_rows must contain at least one code row"),
            Self::BytecodeInputConflict => {
                f.write_str("provide either logical bytecode rows or image bytecode rows, not both")
            }
            Self::UnknownRootCallId(id) => {
                write!(f, "root logical call id {id} has no bytecode rows")
            }
            Self::UnknownBytecodeCallId(id) => {
                write!(f, "logical call id {id} has no bytecode rows")
            }
            Self::UnknownCallIdMapping(id) => {
                write!(f, "missing logical->actual call-id mapping for {id}")
            }
            Self::InvalidRootLogicalCallId(id) => {
                write!(
                    f,
                    "order-based logical bytecode input requires root logical call id 0, got {id}"
                )
            }
            Self::NonContiguousLogicalCallIds { expected, found } => {
                write!(f, "logical call ids must be contiguous from 0: expected {expected}, found {found}")
            }
            Self::DuplicateBytecodeCell {
                logical_call_id,
                pc,
                iscode,
            } => {
                write!(f, "duplicate bytecode cell for call_id={logical_call_id}, pc={pc}, iscode={iscode}")
            }
            Self::DuplicateCallHint {
                logical_call_id,
                pc,
            } => {
                write!(
                    f,
                    "duplicate call hint for call_id={logical_call_id}, pc={pc}"
                )
            }
            Self::DuplicateCallTarget(address) => {
                write!(
                    f,
                    "duplicate call target for callee_address={:#x?}",
                    address
                )
            }
            Self::DuplicateDeploymentAddress(address) => {
                write!(
                    f,
                    "duplicate deployment row for callee_address={:#x?}",
                    address
                )
            }
            Self::DuplicateLogicalCallId(id) => {
                write!(f, "duplicate logical call id mapping attempt: {id}")
            }
            Self::ArithmeticOverflow(name) => write!(
                f,
                "arithmetic intermediate does not fit the current ALU model: {name}"
            ),
            Self::ArithmeticMismatch(name) => write!(
                f,
                "execution arithmetic result does not satisfy expected ALU relation: {name}"
            ),
            Self::MissingOpcode {
                logical_call_id,
                pc,
            } => {
                write!(
                    f,
                    "missing opcode row for call_id={logical_call_id}, pc={pc}"
                )
            }
            Self::MissingImmediate {
                logical_call_id,
                pc,
            } => {
                write!(
                    f,
                    "missing immediate row for call_id={logical_call_id}, pc={pc}"
                )
            }
            Self::NonByteOpcode {
                logical_call_id,
                pc,
                value,
            } => {
                write!(
                    f,
                    "opcode row for call_id={logical_call_id}, pc={pc} is not a byte: {value}"
                )
            }
            Self::NonByteValue(name) => write!(f, "{name} must fit in one byte"),
            Self::TxMetadataMissing(name) => write!(f, "tx metadata missing: {name}"),
            Self::TxCalldataLengthMismatch { declared, actual } => {
                write!(
                    f,
                    "tx calldata length mismatch: declared {declared}, actual {actual}"
                )
            }
            Self::StackUnderflow {
                logical_call_id,
                pc,
                sp,
                needed,
            } => write!(
                f,
                "stack underflow at call_id={logical_call_id}, pc={pc}, sp={sp}, needed {needed}"
            ),
            Self::MissingSpawnedLogicalCallId(step) => {
                write!(f, "call step {step} is missing spawned_logical_call_id")
            }
            Self::CallHintMissing {
                logical_call_id,
                pc,
            } => {
                write!(
                    f,
                    "missing call hint for call_id={logical_call_id}, pc={pc}"
                )
            }
            Self::CallTargetMissing {
                logical_call_id,
                pc,
                callee_address,
            } => {
                write!(
                    f,
                    "missing call target for call_id={logical_call_id}, pc={pc}, callee_address={:#x?}",
                    callee_address
                )
            }
            Self::RootReturn => f.write_str("root frame cannot execute return"),
            Self::StepLimitExceeded(limit) => write!(f, "execution exceeded max_steps={limit}"),
            Self::ParentFrameMissing(id) => {
                write!(f, "parent frame {id} is missing from the active call stack")
            }
            Self::NarrowValueRequired(name) => write!(f, "{name} must fit in a single u64 limb"),
            Self::InvalidCompactValue(value) => {
                write!(f, "invalid compact bytecode value: {value}")
            }
            Self::CompactValueTooLarge => {
                f.write_str("compact bytecode value must fit in 256 bits")
            }
            Self::CompactBytecodeRowsOutOfOrder {
                previous_id,
                found_id,
            } => write!(
                f,
                "compact bytecode rows must be grouped by nondecreasing id: previous {previous_id}, found {found_id}"
            ),
            Self::UnsupportedOpcode(opcode) => {
                write!(f, "unsupported opcode in execution core: 0x{opcode:x}")
            }
        }
    }
}

impl std::error::Error for ExecutionError {}

#[derive(Debug, Clone)]
pub enum ExecutionPipelineError {
    Execution(ExecutionError),
    WitnessGeneration(WitnessGenerationError),
}

impl std::fmt::Display for ExecutionPipelineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Execution(err) => write!(f, "execution failed: {err}"),
            Self::WitnessGeneration(err) => write!(f, "witness generation failed: {err}"),
        }
    }
}

impl std::error::Error for ExecutionPipelineError {}

impl From<ExecutionError> for ExecutionPipelineError {
    fn from(value: ExecutionError) -> Self {
        Self::Execution(value)
    }
}

impl From<WitnessGenerationError> for ExecutionPipelineError {
    fn from(value: WitnessGenerationError) -> Self {
        Self::WitnessGeneration(value)
    }
}

pub fn execute_from_public_inputs(input: ExecutionInput) -> Result<ExecutionTrace, ExecutionError> {
    ExecutionEngine::new(input)?.run()
}

pub fn execute_from_tables(
    tables: ExecutionPublicTables,
) -> Result<ExecutionTrace, ExecutionPipelineError> {
    execute_from_public_inputs(ExecutionInput::from_public_tables(tables))
        .map_err(ExecutionPipelineError::Execution)
}

pub fn execute_from_tables_with_hints(
    tables: ExecutionPublicTables,
    hints: ExecutionHints,
    max_steps: usize,
) -> Result<ExecutionTrace, ExecutionPipelineError> {
    execute_from_public_inputs(
        ExecutionInput::from_public_tables(tables)
            .with_hints(hints)
            .with_max_steps(max_steps),
    )
    .map_err(ExecutionPipelineError::Execution)
}

pub fn lower_witness_from_public_inputs(
    input: ExecutionInput,
) -> Result<(ExecutionTrace, LogicalWitnessInput), ExecutionPipelineError> {
    let trace = execute_from_public_inputs(input)?;
    let logical_witness_input = trace.clone().into_lowered_witness_input()?;
    Ok((trace, logical_witness_input))
}

pub fn lower_witness_from_tables(
    tables: ExecutionPublicTables,
) -> Result<(ExecutionTrace, LogicalWitnessInput), ExecutionPipelineError> {
    lower_witness_from_public_inputs(ExecutionInput::from_public_tables(tables))
}

pub fn lower_witness_from_tables_with_hints(
    tables: ExecutionPublicTables,
    hints: ExecutionHints,
    max_steps: usize,
) -> Result<(ExecutionTrace, LogicalWitnessInput), ExecutionPipelineError> {
    lower_witness_from_public_inputs(
        ExecutionInput::from_public_tables(tables)
            .with_hints(hints)
            .with_max_steps(max_steps),
    )
}

pub fn generate_witness_from_public_inputs(
    input: ExecutionInput,
) -> Result<GeneratedExecutionWitness, ExecutionPipelineError> {
    let (execution_trace, logical_witness_input) = lower_witness_from_public_inputs(input)?;
    let generated_witness = generate_witness(logical_witness_input.clone())?;
    Ok(GeneratedExecutionWitness {
        execution_trace,
        logical_witness_input,
        generated_witness,
    })
}

pub fn generate_witness_from_tables(
    tables: ExecutionPublicTables,
) -> Result<GeneratedExecutionWitness, ExecutionPipelineError> {
    generate_witness_from_public_inputs(ExecutionInput::from_public_tables(tables))
}

pub fn generate_witness_from_tables_with_hints(
    tables: ExecutionPublicTables,
    hints: ExecutionHints,
    max_steps: usize,
) -> Result<GeneratedExecutionWitness, ExecutionPipelineError> {
    generate_witness_from_public_inputs(
        ExecutionInput::from_public_tables(tables)
            .with_hints(hints)
            .with_max_steps(max_steps),
    )
}

pub fn mock_prove_from_public_inputs(
    k: u32,
    input: ExecutionInput,
) -> Result<GeneratedExecutionWitness, ExecutionPipelineError> {
    let bundle = generate_witness_from_public_inputs(input)?;
    bundle
        .generated_witness
        .mock_verify(k)
        .map_err(ExecutionPipelineError::WitnessGeneration)?;
    Ok(bundle)
}

pub fn mock_prove_from_tables(
    k: u32,
    tables: ExecutionPublicTables,
) -> Result<GeneratedExecutionWitness, ExecutionPipelineError> {
    mock_prove_from_public_inputs(k, ExecutionInput::from_public_tables(tables))
}

pub fn mock_prove_from_tables_with_hints(
    k: u32,
    tables: ExecutionPublicTables,
    hints: ExecutionHints,
    max_steps: usize,
) -> Result<GeneratedExecutionWitness, ExecutionPipelineError> {
    mock_prove_from_public_inputs(
        k,
        ExecutionInput::from_public_tables(tables)
            .with_hints(hints)
            .with_max_steps(max_steps),
    )
}

fn expand_compact_logical_rows(
    rows: Vec<CompactLogicalByteTableRow>,
) -> Result<Vec<LogicalByteTableRow>, ExecutionError> {
    let mut out = Vec::with_capacity(rows.len());
    let mut current_id = None;
    let mut current_pc = 0u64;
    let mut previous_was_write = false;

    for row in rows {
        match current_id {
            None => {
                current_id = Some(row.logical_call_id);
                previous_was_write = false;
            }
            Some(id) if row.logical_call_id == id => {}
            Some(id) if row.logical_call_id > id => {
                current_id = Some(row.logical_call_id);
                current_pc = 0;
                previous_was_write = false;
            }
            Some(id) => {
                return Err(ExecutionError::CompactBytecodeRowsOutOfOrder {
                    previous_id: id,
                    found_id: row.logical_call_id,
                });
            }
        }

        let limbs = parse_compact_word(&row.value)?;
        let iscode = !previous_was_write;
        out.push(LogicalByteTableRow {
            logical_call_id: row.logical_call_id,
            pc: current_pc,
            limb1: limbs[0],
            limb2: limbs[1],
            limb3: limbs[2],
            limb4: limbs[3],
            iscode,
        });
        previous_was_write = iscode && limbs == [OP_WRITE, 0, 0, 0];
        current_pc = current_pc.saturating_add(1);
    }

    Ok(out)
}

fn expand_compact_image_rows(
    rows: Vec<CompactExecutionBytecodeRow>,
) -> Result<Vec<ExecutionBytecodeRow>, ExecutionError> {
    let mut out = Vec::with_capacity(rows.len());
    let mut current_id = None;
    let mut current_pc = 0u64;
    let mut previous_was_write = false;

    for row in rows {
        match current_id {
            None => {
                current_id = Some(row.image_id);
                previous_was_write = false;
            }
            Some(id) if row.image_id == id => {}
            Some(id) if row.image_id > id => {
                current_id = Some(row.image_id);
                current_pc = 0;
                previous_was_write = false;
            }
            Some(id) => {
                return Err(ExecutionError::CompactBytecodeRowsOutOfOrder {
                    previous_id: id,
                    found_id: row.image_id,
                });
            }
        }

        let limbs = parse_compact_word(&row.value)?;
        let iscode = !previous_was_write;
        out.push(ExecutionBytecodeRow {
            image_id: row.image_id,
            pc: current_pc,
            limb1: limbs[0],
            limb2: limbs[1],
            limb3: limbs[2],
            limb4: limbs[3],
            iscode,
        });
        previous_was_write = iscode && limbs == [OP_WRITE, 0, 0, 0];
        current_pc = current_pc.saturating_add(1);
    }

    Ok(out)
}

fn expand_compact_tx_rows(
    rows: Vec<CompactLogicalTxRow>,
) -> Result<Vec<LogicalTxRow>, ExecutionError> {
    let mut calldata_index = 0u64;
    let mut out = Vec::with_capacity(rows.len());

    for row in rows {
        let limbs = parse_compact_word(&row.value)?;
        let value_low = u128::from(limbs[0]) | (u128::from(limbs[1]) << 64);
        let value_high = u128::from(limbs[2]) | (u128::from(limbs[3]) << 64);
        let index = if row.tag == TX_TAG_CALLDATA_BYTE {
            let index = calldata_index;
            calldata_index = calldata_index.saturating_add(1);
            index
        } else {
            0
        };

        out.push(LogicalTxRow {
            active: true,
            txid: 1,
            tag: row.tag,
            index,
            value_low,
            value_high,
        });
    }

    Ok(out)
}

fn parse_compact_word(raw: &str) -> Result<[u64; 4], ExecutionError> {
    let value = raw.trim();
    if value.is_empty() {
        return Err(ExecutionError::InvalidCompactValue(raw.to_string()));
    }

    if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        return parse_compact_hex(hex, raw);
    }

    parse_compact_decimal(value, raw)
}

fn parse_compact_hex(hex: &str, raw: &str) -> Result<[u64; 4], ExecutionError> {
    let digits = hex.replace('_', "");
    if digits.is_empty()
        || digits.len() > 64
        || !digits.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(if digits.len() > 64 {
            ExecutionError::CompactValueTooLarge
        } else {
            ExecutionError::InvalidCompactValue(raw.to_string())
        });
    }

    let mut limbs = [0u64; 4];
    for (chunk_index, chunk) in digits.as_bytes().rchunks(16).enumerate() {
        let chunk = std::str::from_utf8(chunk)
            .map_err(|_| ExecutionError::InvalidCompactValue(raw.to_string()))?;
        limbs[chunk_index] = u64::from_str_radix(chunk, 16)
            .map_err(|_| ExecutionError::InvalidCompactValue(raw.to_string()))?;
    }
    Ok(limbs)
}

fn parse_compact_decimal(decimal: &str, raw: &str) -> Result<[u64; 4], ExecutionError> {
    let digits = decimal.replace('_', "");
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(ExecutionError::InvalidCompactValue(raw.to_string()));
    }

    let mut limbs = [0u64; 4];
    for digit in digits.bytes() {
        let digit = u128::from(digit - b'0');
        let mut carry = digit;
        for limb in &mut limbs {
            let value = u128::from(*limb) * 10 + carry;
            *limb = value as u64;
            carry = value >> 64;
        }
        if carry != 0 {
            return Err(ExecutionError::CompactValueTooLarge);
        }
    }
    Ok(limbs)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
struct Word([u64; 4]);

impl Word {
    const fn zero() -> Self {
        Self([0, 0, 0, 0])
    }

    const fn one() -> Self {
        Self([1, 0, 0, 0])
    }

    const fn from_u64(value: u64) -> Self {
        Self([value, 0, 0, 0])
    }

    const fn from_u128_halves(low: u128, high: u128) -> Self {
        Self([
            low as u64,
            (low >> 64) as u64,
            high as u64,
            (high >> 64) as u64,
        ])
    }

    const fn from_bool(value: bool) -> Self {
        if value {
            Self::one()
        } else {
            Self::zero()
        }
    }

    const fn limbs(self) -> [u64; 4] {
        self.0
    }

    const fn low_u128(self) -> u128 {
        (self.0[0] as u128) | ((self.0[1] as u128) << 64)
    }

    const fn high_u128(self) -> u128 {
        (self.0[2] as u128) | ((self.0[3] as u128) << 64)
    }

    fn low_u64(self) -> Result<u64, ExecutionError> {
        if self.0[1] != 0 || self.0[2] != 0 || self.0[3] != 0 {
            return Err(ExecutionError::NarrowValueRequired("word"));
        }
        Ok(self.0[0])
    }

    const fn is_zero(self) -> bool {
        self.0[0] == 0 && self.0[1] == 0 && self.0[2] == 0 && self.0[3] == 0
    }

    fn add_mod(self, rhs: Self) -> Self {
        let mut out = [0u64; 4];
        let mut carry = 0u128;
        for (idx, slot) in out.iter_mut().enumerate() {
            let acc = self.0[idx] as u128 + rhs.0[idx] as u128 + carry;
            *slot = acc as u64;
            carry = acc >> 64;
        }
        Self(out)
    }

    fn sub_mod(self, rhs: Self) -> Self {
        let mut out = [0u64; 4];
        let mut borrow = 0u128;
        for (idx, slot) in out.iter_mut().enumerate() {
            let lhs = self.0[idx] as u128;
            let rhs = rhs.0[idx] as u128 + borrow;
            if lhs >= rhs {
                *slot = (lhs - rhs) as u64;
                borrow = 0;
            } else {
                *slot = ((1u128 << 64) + lhs - rhs) as u64;
                borrow = 1;
            }
        }
        Self(out)
    }

    fn bitand(self, rhs: Self) -> Self {
        Self([
            self.0[0] & rhs.0[0],
            self.0[1] & rhs.0[1],
            self.0[2] & rhs.0[2],
            self.0[3] & rhs.0[3],
        ])
    }

    fn bitor(self, rhs: Self) -> Self {
        Self([
            self.0[0] | rhs.0[0],
            self.0[1] | rhs.0[1],
            self.0[2] | rhs.0[2],
            self.0[3] | rhs.0[3],
        ])
    }

    fn bitxor(self, rhs: Self) -> Self {
        Self([
            self.0[0] ^ rhs.0[0],
            self.0[1] ^ rhs.0[1],
            self.0[2] ^ rhs.0[2],
            self.0[3] ^ rhs.0[3],
        ])
    }

    fn bitnot(self) -> Self {
        Self([!self.0[0], !self.0[1], !self.0[2], !self.0[3]])
    }

    fn lt(self, rhs: Self) -> bool {
        for idx in (0..4).rev() {
            if self.0[idx] != rhs.0[idx] {
                return self.0[idx] < rhs.0[idx];
            }
        }
        false
    }

    fn shl1(self) -> Self {
        let mut out = [0u64; 4];
        let mut carry = 0u64;
        for (idx, slot) in out.iter_mut().enumerate() {
            *slot = (self.0[idx] << 1) | carry;
            carry = self.0[idx] >> 63;
        }
        Self(out)
    }

    fn shl1_with_bit(self, bit: bool) -> Self {
        let mut shifted = self.shl1();
        shifted.0[0] |= u64::from(bit);
        shifted
    }

    fn shr1(self) -> Self {
        let mut out = [0u64; 4];
        let mut carry = 0u64;
        for idx in (0..4).rev() {
            out[idx] = (self.0[idx] >> 1) | (carry << 63);
            carry = self.0[idx] & 1;
        }
        Self(out)
    }

    fn bit(self, bit_index: usize) -> bool {
        let limb = bit_index / 64;
        let bit = bit_index % 64;
        ((self.0[limb] >> bit) & 1) == 1
    }

    fn set_bit(&mut self, bit_index: usize) {
        let limb = bit_index / 64;
        let bit = bit_index % 64;
        self.0[limb] |= 1u64 << bit;
    }

    fn mul_mod(self, rhs: Self) -> Self {
        let mut acc = Self::zero();
        let mut left = self;
        let mut right = rhs;
        while !right.is_zero() {
            if right.bit(0) {
                acc = acc.add_mod(left);
            }
            left = left.shl1();
            right = right.shr1();
        }
        acc
    }

    fn div_mod(self, rhs: Self) -> Self {
        if rhs.is_zero() {
            return Self::zero();
        }

        let mut quotient = Self::zero();
        let mut remainder = Self::zero();
        for bit_index in (0..256).rev() {
            remainder = remainder.shl1_with_bit(self.bit(bit_index));
            if !remainder.lt(rhs) {
                remainder = remainder.sub_mod(rhs);
                quotient.set_bit(bit_index);
            }
        }
        quotient
    }

    fn from_memory_bytes(bytes: [u8; 32]) -> Self {
        Self([
            pack_rev_u64(&bytes[24..32]),
            pack_rev_u64(&bytes[16..24]),
            pack_rev_u64(&bytes[8..16]),
            pack_rev_u64(&bytes[0..8]),
        ])
    }

    fn to_memory_bytes(self) -> [u8; 32] {
        let mut out = [0u8; 32];
        write_rev_u64(&mut out[24..32], self.0[0]);
        write_rev_u64(&mut out[16..24], self.0[1]);
        write_rev_u64(&mut out[8..16], self.0[2]);
        write_rev_u64(&mut out[0..8], self.0[3]);
        out
    }
}

#[derive(Debug, Clone)]
struct BytecodeProgram {
    images: BTreeMap<u64, ProgramImage>,
}

#[derive(Debug, Clone, Default)]
struct ProgramImage {
    image_id: u64,
    code: BTreeMap<u64, u8>,
    immediates: BTreeMap<u64, Word>,
}

#[derive(Debug, Clone)]
struct TxPublicData {
    txid: u64,
    caller_address: Word,
    callee_address: Word,
    value: Word,
    calldata: Vec<u8>,
}

#[derive(Debug, Clone)]
struct ExecutionFrame {
    logical_call_id: u64,
    image_id: u64,
    parent_logical_call_id: Option<u64>,
    live_pc: u64,
    live_sp: u64,
    live_mmax: u64,
    stack: BTreeMap<u64, Word>,
    memory: BTreeMap<u64, u8>,
    context: CallContextState,
}

#[derive(Debug, Clone)]
struct CallContextState {
    caller_id: u64,
    depth: u64,
    caller_address: Word,
    callee_address: Word,
    calldata_offset: u64,
    calldata_length: u64,
    returndata_offset: u64,
    returndata_length: u64,
    value: Word,
    issuccess: bool,
    ispersistence: bool,
    isroot: bool,
    last_callee_id: u64,
    last_callee_returndata_offset: u64,
    last_callee_returndata_length: u64,
    parent_resume_pc: u64,
    parent_resume_sp: u64,
    parent_resume_mmax: u64,
}

struct ExecutionEngine {
    input_byte_rows: Vec<LogicalByteTableRow>,
    input_tx_rows: Vec<LogicalTxRow>,
    program: BytecodeProgram,
    tx: TxPublicData,
    call_hints: BTreeMap<(u64, u64), CallHint>,
    deployments: BTreeMap<Word, u64>,
    call_targets: BTreeMap<Word, CallTargetHint>,
    frames: Vec<ExecutionFrame>,
    cpu_steps: Vec<LogicalCpuStep>,
    arithmetic_ops: Vec<ExecutionArithmeticOp>,
    memory_events: Vec<LogicalMemoryEvent>,
    copy_plans: Vec<ExecutionCopyPlan>,
    events: Vec<ExecutionEvent>,
    rw_counter: u64,
    executed_images: BTreeMap<u64, u64>,
    next_logical_call_id: u64,
    order_based_call_routing: bool,
    halted: bool,
    max_steps: Option<usize>,
}

#[derive(Debug, Clone, Copy)]
struct ResolvedCallTarget {
    child_image_id: u64,
    child_issuccess: bool,
}

impl ExecutionEngine {
    fn new(input: ExecutionInput) -> Result<Self, ExecutionError> {
        if (!input.bytecode_rows.is_empty() || !input.compact_bytecode_rows.is_empty())
            && (!input.bytecode_image_rows.is_empty()
                || !input.compact_bytecode_image_rows.is_empty())
        {
            return Err(ExecutionError::BytecodeInputConflict);
        }

        let compact_bytecode_rows = expand_compact_logical_rows(input.compact_bytecode_rows)?;
        let compact_bytecode_image_rows =
            expand_compact_image_rows(input.compact_bytecode_image_rows)?;
        let compact_tx_rows = expand_compact_tx_rows(input.compact_tx_rows)?;
        let mut bytecode_rows = input.bytecode_rows;
        bytecode_rows.extend(compact_bytecode_rows);
        let mut bytecode_image_rows = input.bytecode_image_rows;
        bytecode_image_rows.extend(compact_bytecode_image_rows);
        let mut tx_rows = input.tx_rows;
        tx_rows.extend(compact_tx_rows);

        let order_based_call_routing = bytecode_image_rows.is_empty();
        if order_based_call_routing && input.root_logical_call_id != 0 {
            return Err(ExecutionError::InvalidRootLogicalCallId(
                input.root_logical_call_id,
            ));
        }

        let program = if order_based_call_routing {
            BytecodeProgram::from_legacy_rows(&bytecode_rows)?
        } else {
            BytecodeProgram::from_image_rows(&bytecode_image_rows)?
        };
        let root_logical_call_id = if order_based_call_routing {
            0
        } else {
            input.root_logical_call_id
        };
        let root_image_id = if order_based_call_routing {
            0
        } else {
            input.root_image_id
        };
        if !program.images.contains_key(&root_image_id) {
            return Err(ExecutionError::UnknownRootCallId(root_image_id));
        }

        let tx = TxPublicData::from_rows(&tx_rows)?;
        let call_hints = index_call_hints(input.hints.call_hints)?;
        let deployments = index_deployments(&program, input.deployment_rows)?;
        let call_targets = index_call_targets(input.hints.call_targets)?;
        let root_frame = ExecutionFrame {
            logical_call_id: root_logical_call_id,
            image_id: root_image_id,
            parent_logical_call_id: None,
            live_pc: 0,
            live_sp: 0,
            live_mmax: 0,
            stack: BTreeMap::new(),
            memory: BTreeMap::new(),
            context: CallContextState {
                caller_id: 0,
                depth: 1,
                caller_address: tx.caller_address,
                callee_address: tx.callee_address,
                calldata_offset: 0,
                calldata_length: tx.calldata.len() as u64,
                returndata_offset: 0,
                returndata_length: 0,
                value: tx.value,
                issuccess: true,
                ispersistence: true,
                isroot: true,
                last_callee_id: 0,
                last_callee_returndata_offset: 0,
                last_callee_returndata_length: 0,
                parent_resume_pc: 0,
                parent_resume_sp: 0,
                parent_resume_mmax: 0,
            },
        };

        Ok(Self {
            input_byte_rows: if bytecode_image_rows.is_empty() {
                bytecode_rows
            } else {
                Vec::new()
            },
            input_tx_rows: tx_rows,
            program,
            tx,
            call_hints,
            deployments,
            call_targets,
            frames: vec![root_frame],
            cpu_steps: Vec::new(),
            arithmetic_ops: Vec::new(),
            memory_events: Vec::new(),
            copy_plans: Vec::new(),
            events: Vec::new(),
            rw_counter: 0,
            executed_images: BTreeMap::from([(root_logical_call_id, root_image_id)]),
            next_logical_call_id: root_logical_call_id.saturating_add(1),
            order_based_call_routing,
            halted: false,
            max_steps: input.max_steps.filter(|limit| *limit > 0),
        })
    }

    fn run(mut self) -> Result<ExecutionTrace, ExecutionError> {
        while !self.halted {
            if let Some(limit) = self.max_steps {
                if self.cpu_steps.len() >= limit {
                    return Err(ExecutionError::StepLimitExceeded(limit));
                }
            }
            self.step()?;
        }

        Ok(ExecutionTrace {
            bytecode_rows: if self.input_byte_rows.is_empty() {
                self.program.expand_for_calls(&self.executed_images)
            } else {
                self.input_byte_rows
            },
            tx_rows: self.input_tx_rows,
            cpu_steps: self.cpu_steps,
            arithmetic_ops: self.arithmetic_ops,
            memory_events: self.memory_events,
            copy_plans: self.copy_plans,
            events: self.events,
            final_frames: self
                .frames
                .into_iter()
                .map(|frame| ExecutionFrameState {
                    logical_call_id: frame.logical_call_id,
                    image_id: frame.image_id,
                    parent_logical_call_id: frame.parent_logical_call_id,
                    live_pc: frame.live_pc,
                    live_sp: frame.live_sp,
                    live_mmax: frame.live_mmax,
                    stack: frame
                        .stack
                        .into_iter()
                        .map(|(addr, word)| (addr, word.limbs()))
                        .collect(),
                    memory: frame.memory.into_iter().collect(),
                    call_context: frame.context.as_rows(),
                })
                .collect(),
        })
    }

    fn step(&mut self) -> Result<(), ExecutionError> {
        let frame_index = self.frames.len() - 1;
        let logical_call_id = self.frames[frame_index].logical_call_id;
        let image_id = self.frames[frame_index].image_id;
        let pc = self.frames[frame_index].live_pc;
        let opcode = self.program.opcode(image_id, pc)?;
        self.events.push(ExecutionEvent::BytecodeRead {
            logical_call_id,
            pc,
            opcode,
        });

        match opcode as u64 {
            OP_BEGIN_TX => self.step_begintx(frame_index, opcode),
            OP_END_TX => self.step_endtx(frame_index, opcode),
            OP_HALT => self.step_halt(frame_index, opcode),
            0x01 => self.step_binary_arithmetic(frame_index, opcode, ArithmeticOpKind::Add),
            0x03 => self.step_binary_arithmetic(frame_index, opcode, ArithmeticOpKind::Sub),
            0x02 => self.step_binary_arithmetic(frame_index, opcode, ArithmeticOpKind::Mul),
            0x04 => self.step_binary_arithmetic(frame_index, opcode, ArithmeticOpKind::Div),
            0x10 => self.step_binary_arithmetic(frame_index, opcode, ArithmeticOpKind::Lt),
            0x14 => self.step_binary_arithmetic(frame_index, opcode, ArithmeticOpKind::Eq),
            0x16 => self.step_binary_arithmetic(frame_index, opcode, ArithmeticOpKind::And),
            0x17 => self.step_binary_arithmetic(frame_index, opcode, ArithmeticOpKind::Or),
            0x18 => self.step_binary_arithmetic(frame_index, opcode, ArithmeticOpKind::Xor),
            0x19 => self.step_not(frame_index, opcode),
            0x56 => self.step_jump(frame_index, opcode),
            0x57 => self.step_jumpcon(frame_index, opcode),
            0x5b => self.step_jumpdest(frame_index, opcode),
            0x51 => self.step_mload(frame_index, opcode),
            0x52 => self.step_mstore(frame_index, opcode),
            0x53 => self.step_mstore8(frame_index, opcode),
            0x37 => self.step_calldatacopy(frame_index, opcode),
            0x3e => self.step_returndatacopy(frame_index, opcode),
            0xf1 => self.step_call(frame_index, opcode),
            0xf3 => self.step_return(frame_index, opcode),
            OP_WRITE => self.step_write(frame_index, opcode),
            OP_READ => self.step_read(frame_index, opcode),
            other => Err(ExecutionError::UnsupportedOpcode(other)),
        }
    }

    fn step_begintx(&mut self, frame_index: usize, opcode: u8) -> Result<(), ExecutionError> {
        let logical_call_id = self.frames[frame_index].logical_call_id;
        let live_pc = self.frames[frame_index].live_pc;
        let live_sp = self.frames[frame_index].live_sp;
        let live_mmax = self.frames[frame_index].live_mmax;
        let caller_address = self.frames[frame_index].context.caller_address;
        let callee_address = self.frames[frame_index].context.callee_address;
        let context = self.frames[frame_index].context.clone();
        let cpu_step = LogicalCpuStep {
            logical_call_id,
            spawned_logical_call_id: None,
            pc: live_pc,
            opcode: opcode as u64,
            rlc_a: [0; 4],
            rlc_b: [0; 4],
            rlc_c: [0; 4],
            rlc_d: [0; 4],
            rlc_e: caller_address.limbs(),
            rlc_f: callee_address.limbs(),
            rlc_g: Word::from_u64(self.tx.calldata.len() as u64).limbs(),
            rlc_h: self.tx.value.limbs(),
            rlc_i: Word::one().limbs(),
            rlc_j: [0; 4],
            memaddr: 0,
            inv: Fp::ZERO,
            mmax: live_mmax,
            ismaxchanged: false,
            sp: live_sp,
        };
        self.events.push(ExecutionEvent::TxRead {
            txid: self.tx.txid,
            tag: TX_TAG_CALLER_ADDRESS,
            index: 0,
            value_low: self.tx.caller_address.low_u128(),
            value_high: self.tx.caller_address.high_u128(),
        });
        self.events.push(ExecutionEvent::TxRead {
            txid: self.tx.txid,
            tag: TX_TAG_CALLEE_ADDRESS,
            index: 0,
            value_low: self.tx.callee_address.low_u128(),
            value_high: self.tx.callee_address.high_u128(),
        });
        self.events.push(ExecutionEvent::TxRead {
            txid: self.tx.txid,
            tag: TX_TAG_CALLDATA_LENGTH,
            index: 0,
            value_low: self.tx.calldata.len() as u128,
            value_high: 0,
        });
        self.events.push(ExecutionEvent::TxRead {
            txid: self.tx.txid,
            tag: TX_TAG_VALUE,
            index: 0,
            value_low: self.tx.value.low_u128(),
            value_high: self.tx.value.high_u128(),
        });
        self.write_context_events(logical_call_id, &context, true);
        self.push_cpu_step(cpu_step)?;
        self.frames[frame_index].live_pc += 1;
        Ok(())
    }

    fn step_endtx(&mut self, frame_index: usize, opcode: u8) -> Result<(), ExecutionError> {
        let frame = &self.frames[frame_index];
        let cpu_step = self.base_cpu_step(frame, opcode as u64);
        self.push_cpu_step(cpu_step)?;
        self.frames[frame_index].live_pc += 1;
        Ok(())
    }

    fn step_halt(&mut self, frame_index: usize, opcode: u8) -> Result<(), ExecutionError> {
        let mut cpu_step = self.base_cpu_step(&self.frames[frame_index], opcode as u64);
        if self.frames[frame_index].parent_logical_call_id.is_none()
            && self.frames[frame_index].live_pc > 0
        {
            cpu_step.logical_call_id = 0;
        }
        self.push_cpu_step(cpu_step)?;
        self.halted = true;
        Ok(())
    }

    fn step_binary_arithmetic(
        &mut self,
        frame_index: usize,
        opcode: u8,
        op: ArithmeticOpKind,
    ) -> Result<(), ExecutionError> {
        let (a, addr_a, b, addr_b) = self.read_top2(frame_index)?;
        let result = match op {
            ArithmeticOpKind::Add => a.add_mod(b),
            ArithmeticOpKind::Sub => a.sub_mod(b),
            ArithmeticOpKind::Mul => a.mul_mod(b),
            ArithmeticOpKind::Div => a.div_mod(b),
            ArithmeticOpKind::Lt => Word::from_bool(a.lt(b)),
            ArithmeticOpKind::Eq => Word::from_bool(a == b),
            ArithmeticOpKind::And => a.bitand(b),
            ArithmeticOpKind::Or => a.bitor(b),
            ArithmeticOpKind::Xor => a.bitxor(b),
            ArithmeticOpKind::Not => unreachable!(),
        };
        self.write_stack(frame_index, addr_b, result);
        self.frames[frame_index].stack.remove(&addr_a);
        self.frames[frame_index].live_sp -= 1;
        self.frames[frame_index].live_pc += 1;

        let mut cpu_step = self.base_cpu_step(&self.frames[frame_index], opcode as u64);
        cpu_step.pc -= 1;
        cpu_step.sp += 1;
        cpu_step.rlc_a = a.limbs();
        cpu_step.rlc_b = b.limbs();
        cpu_step.rlc_c = result.limbs();
        self.arithmetic_ops.push(ExecutionArithmeticOp {
            source_step: self.cpu_steps.len(),
            op,
            lhs: a.limbs(),
            rhs: b.limbs(),
            result: result.limbs(),
        });
        self.push_cpu_step(cpu_step)?;
        Ok(())
    }

    fn step_not(&mut self, frame_index: usize, opcode: u8) -> Result<(), ExecutionError> {
        let (value, addr) = self.read_top1(frame_index)?;
        let result = value.bitnot();
        self.write_stack(frame_index, addr, result);
        self.frames[frame_index].live_pc += 1;

        let mut cpu_step = self.base_cpu_step(&self.frames[frame_index], opcode as u64);
        cpu_step.pc -= 1;
        cpu_step.rlc_a = value.limbs();
        cpu_step.rlc_c = result.limbs();
        self.arithmetic_ops.push(ExecutionArithmeticOp {
            source_step: self.cpu_steps.len(),
            op: ArithmeticOpKind::Not,
            lhs: value.limbs(),
            rhs: [0; 4],
            result: result.limbs(),
        });
        self.push_cpu_step(cpu_step)?;
        Ok(())
    }

    fn step_jump(&mut self, frame_index: usize, opcode: u8) -> Result<(), ExecutionError> {
        let pc = self.frames[frame_index].live_pc;
        let (dest, addr) = self.read_top1(frame_index)?;
        let dest_pc = dest.low_u64()?;
        self.frames[frame_index].stack.remove(&addr);
        self.frames[frame_index].live_sp -= 1;
        self.frames[frame_index].live_pc = dest_pc;

        let mut cpu_step = self.base_cpu_step(&self.frames[frame_index], opcode as u64);
        cpu_step.pc = pc;
        cpu_step.sp += 1;
        cpu_step.rlc_a = dest.limbs();
        self.push_cpu_step(cpu_step)?;
        Ok(())
    }

    fn step_jumpcon(&mut self, frame_index: usize, opcode: u8) -> Result<(), ExecutionError> {
        let pc = self.frames[frame_index].live_pc;
        let (dest, addr_a, cond, addr_b) = self.read_top2(frame_index)?;
        let taken = !cond.is_zero();
        let dest_pc = dest.low_u64()?;
        self.frames[frame_index].stack.remove(&addr_a);
        self.frames[frame_index].stack.remove(&addr_b);
        self.frames[frame_index].live_sp -= 2;
        self.frames[frame_index].live_pc = if taken {
            dest_pc
        } else {
            self.frames[frame_index].live_pc + 1
        };

        let mut cpu_step = self.base_cpu_step(&self.frames[frame_index], opcode as u64);
        cpu_step.pc = pc;
        cpu_step.sp += 2;
        cpu_step.rlc_a = dest.limbs();
        cpu_step.rlc_b = cond.limbs();
        cpu_step.rlc_c = Word::from_bool(taken).limbs();
        cpu_step.inv = if taken {
            field_inverse_u64(cond.low_u64()?)
        } else {
            Fp::ZERO
        };
        self.push_cpu_step(cpu_step)?;
        Ok(())
    }

    fn step_jumpdest(&mut self, frame_index: usize, opcode: u8) -> Result<(), ExecutionError> {
        let cpu_step = self.base_cpu_step(&self.frames[frame_index], opcode as u64);
        self.push_cpu_step(cpu_step)?;
        self.frames[frame_index].live_pc += 1;
        Ok(())
    }

    fn step_mload(&mut self, frame_index: usize, opcode: u8) -> Result<(), ExecutionError> {
        let (address_word, stack_addr) = self.read_top1(frame_index)?;
        let address = address_word.low_u64()?;
        let bytes = self.read_memory_chunk(frame_index, address);
        let loaded = Word::from_memory_bytes(bytes);
        self.write_stack(frame_index, stack_addr, loaded);
        let prior_mmax = self.frames[frame_index].live_mmax;
        let (next_mmax, ismaxchanged) = grow_mmax(prior_mmax, address + 32);
        self.frames[frame_index].live_mmax = next_mmax;
        self.frames[frame_index].live_pc += 1;

        let mut cpu_step = self.base_cpu_step(&self.frames[frame_index], opcode as u64);
        cpu_step.pc -= 1;
        cpu_step.rlc_a = address_word.limbs();
        cpu_step.rlc_c = loaded.limbs();
        cpu_step.memaddr = address;
        cpu_step.mmax = prior_mmax;
        cpu_step.ismaxchanged = ismaxchanged;
        let source_step = self.cpu_steps.len();
        self.memory_events.push(LogicalMemoryEvent {
            source_step,
            bytes_in_local_row_order: bytes,
        });
        self.push_cpu_step(cpu_step)?;
        Ok(())
    }

    fn step_mstore(&mut self, frame_index: usize, opcode: u8) -> Result<(), ExecutionError> {
        let (address_word, addr_a, value, addr_b) = self.read_top2(frame_index)?;
        let address = address_word.low_u64()?;
        let bytes = value.to_memory_bytes();
        for (offset, byte) in bytes.iter().enumerate() {
            self.write_memory_byte(frame_index, address + offset as u64, *byte);
        }
        self.frames[frame_index].stack.remove(&addr_a);
        self.frames[frame_index].stack.remove(&addr_b);
        self.frames[frame_index].live_sp -= 2;
        let prior_mmax = self.frames[frame_index].live_mmax;
        let (next_mmax, ismaxchanged) = grow_mmax(prior_mmax, address + 32);
        self.frames[frame_index].live_mmax = next_mmax;
        self.frames[frame_index].live_pc += 1;

        let mut cpu_step = self.base_cpu_step(&self.frames[frame_index], opcode as u64);
        cpu_step.pc -= 1;
        cpu_step.sp += 2;
        cpu_step.rlc_a = address_word.limbs();
        cpu_step.rlc_b = value.limbs();
        cpu_step.memaddr = address;
        cpu_step.mmax = prior_mmax;
        cpu_step.ismaxchanged = ismaxchanged;
        let source_step = self.cpu_steps.len();
        self.memory_events.push(LogicalMemoryEvent {
            source_step,
            bytes_in_local_row_order: bytes,
        });
        self.push_cpu_step(cpu_step)?;
        Ok(())
    }

    fn step_mstore8(&mut self, frame_index: usize, opcode: u8) -> Result<(), ExecutionError> {
        let (address_word, addr_a, value, addr_b) = self.read_top2(frame_index)?;
        let address = address_word.low_u64()?;
        let byte = (value.0[0] & 0xff) as u8;
        self.write_memory_byte(frame_index, address, byte);
        self.frames[frame_index].stack.remove(&addr_a);
        self.frames[frame_index].stack.remove(&addr_b);
        self.frames[frame_index].live_sp -= 2;
        let prior_mmax = self.frames[frame_index].live_mmax;
        let (next_mmax, ismaxchanged) = grow_mmax(prior_mmax, address + 1);
        self.frames[frame_index].live_mmax = next_mmax;
        self.frames[frame_index].live_pc += 1;

        let mut bytes = [byte; 32];
        bytes[0] = byte;

        let mut cpu_step = self.base_cpu_step(&self.frames[frame_index], opcode as u64);
        cpu_step.pc -= 1;
        cpu_step.sp += 2;
        cpu_step.rlc_a = address_word.limbs();
        cpu_step.rlc_b = value.limbs();
        cpu_step.memaddr = address;
        cpu_step.mmax = prior_mmax;
        cpu_step.ismaxchanged = ismaxchanged;
        let source_step = self.cpu_steps.len();
        self.memory_events.push(LogicalMemoryEvent {
            source_step,
            bytes_in_local_row_order: bytes,
        });
        self.push_cpu_step(cpu_step)?;
        Ok(())
    }

    fn step_calldatacopy(&mut self, frame_index: usize, opcode: u8) -> Result<(), ExecutionError> {
        let (dst_word, dst_addr, src_word, src_addr, len_word, len_addr) =
            self.read_top3(frame_index)?;
        let dst = dst_word.low_u64()?;
        let src = src_word.low_u64()?;
        let len = len_word.low_u64()?;
        let (
            source_bytes,
            source_call_id,
            source_offset,
            use_tx_source,
            logical_call_id,
            root_bit,
            tx_len,
        ) = {
            let frame = &self.frames[frame_index];
            if frame.context.isroot {
                (
                    read_vec_range(&self.tx.calldata, src, len),
                    None,
                    0,
                    true,
                    frame.logical_call_id,
                    Word::one(),
                    Word::from_u64(self.tx.calldata.len() as u64),
                )
            } else {
                let caller = self.find_frame(frame.context.caller_id)?;
                (
                    caller.read_memory_range(frame.context.calldata_offset + src, len),
                    Some(caller.logical_call_id),
                    frame.context.calldata_offset,
                    false,
                    frame.logical_call_id,
                    Word::zero(),
                    Word::from_u64(self.tx.calldata.len() as u64),
                )
            }
        };
        let prior_mmax = self.frames[frame_index].live_mmax;
        self.apply_memory_copy(frame_index, dst, &source_bytes);
        let (next_mmax, ismaxchanged) = grow_mmax(prior_mmax, dst + len);
        self.frames[frame_index].live_mmax = next_mmax;
        self.frames[frame_index].stack.remove(&dst_addr);
        self.frames[frame_index].stack.remove(&src_addr);
        self.frames[frame_index].stack.remove(&len_addr);
        self.frames[frame_index].live_sp -= 3;
        self.frames[frame_index].live_pc += 1;

        let frame = &self.frames[frame_index];
        let mut cpu_step = self.base_cpu_step(frame, opcode as u64);
        cpu_step.pc -= 1;
        cpu_step.sp += 3;
        cpu_step.rlc_a = dst_word.limbs();
        cpu_step.rlc_b = src_word.limbs();
        cpu_step.rlc_c = len_word.limbs();
        cpu_step.rlc_d = Word::from_u64(frame.context.caller_id).limbs();
        cpu_step.rlc_e = Word::from_u64(frame.context.calldata_offset).limbs();
        cpu_step.rlc_f = Word::from_u64(frame.context.calldata_length).limbs();
        cpu_step.rlc_g = root_bit.limbs();
        cpu_step.rlc_h = tx_len.limbs();
        cpu_step.rlc_i = Word::one().limbs();
        cpu_step.mmax = prior_mmax;
        cpu_step.ismaxchanged = ismaxchanged;
        let source_step = self.cpu_steps.len();
        self.copy_plans.push(ExecutionCopyPlan {
            source_step,
            kind: CopyPlanKind::CallDataCopy,
            src_call_id: source_call_id,
            dst_call_id: logical_call_id,
            src_offset: src + source_offset,
            src_end: if use_tx_source {
                self.tx.calldata.len() as u64
            } else {
                source_offset + frame.context.calldata_length
            },
            dst_offset: dst,
            length: len,
            bytes: source_bytes,
            use_tx_source,
        });
        self.push_cpu_step(cpu_step)?;
        Ok(())
    }

    fn step_returndatacopy(
        &mut self,
        frame_index: usize,
        opcode: u8,
    ) -> Result<(), ExecutionError> {
        let (dst_word, dst_addr, src_word, src_addr, len_word, len_addr) =
            self.read_top3(frame_index)?;
        let dst = dst_word.low_u64()?;
        let src = src_word.low_u64()?;
        let len = len_word.low_u64()?;
        let (base_offset, max_len, logical_call_id, source_bytes) = {
            let frame = &self.frames[frame_index];
            (
                frame.context.last_callee_returndata_offset,
                frame.context.last_callee_returndata_length,
                frame.logical_call_id,
                frame.read_memory_range(frame.context.last_callee_returndata_offset + src, len),
            )
        };
        let prior_mmax = self.frames[frame_index].live_mmax;
        self.apply_memory_copy(frame_index, dst, &source_bytes);
        let (next_mmax, ismaxchanged) = grow_mmax(prior_mmax, dst + len);
        self.frames[frame_index].live_mmax = next_mmax;
        self.frames[frame_index].stack.remove(&dst_addr);
        self.frames[frame_index].stack.remove(&src_addr);
        self.frames[frame_index].stack.remove(&len_addr);
        self.frames[frame_index].live_sp -= 3;
        self.frames[frame_index].live_pc += 1;

        let frame = &self.frames[frame_index];
        let mut cpu_step = self.base_cpu_step(frame, opcode as u64);
        cpu_step.pc -= 1;
        cpu_step.sp += 3;
        cpu_step.rlc_a = dst_word.limbs();
        cpu_step.rlc_b = src_word.limbs();
        cpu_step.rlc_c = len_word.limbs();
        cpu_step.rlc_d = Word::from_u64(base_offset).limbs();
        cpu_step.rlc_e = Word::from_u64(max_len).limbs();
        cpu_step.rlc_i = Word::one().limbs();
        cpu_step.mmax = prior_mmax;
        cpu_step.ismaxchanged = ismaxchanged;
        let source_step = self.cpu_steps.len();
        self.copy_plans.push(ExecutionCopyPlan {
            source_step,
            kind: CopyPlanKind::ReturnDataCopy,
            src_call_id: Some(logical_call_id),
            dst_call_id: logical_call_id,
            src_offset: base_offset + src,
            src_end: base_offset + max_len,
            dst_offset: dst,
            length: len,
            bytes: source_bytes,
            use_tx_source: false,
        });
        self.push_cpu_step(cpu_step)?;
        Ok(())
    }

    fn step_call(&mut self, frame_index: usize, opcode: u8) -> Result<(), ExecutionError> {
        let caller_id = self.frames[frame_index].logical_call_id;
        let caller_pc = self.frames[frame_index].live_pc;
        let (
            calldata_offset,
            returndata_offset,
            returndata_length,
            callee_address,
            calldata_length,
            value,
        ) = self.read_call_operands(frame_index)?;
        let site_hint = self.call_hints.get(&(caller_id, caller_pc)).cloned();
        let child_logical_call_id = self.allocate_logical_call_id();
        let resolved_target = if self.order_based_call_routing {
            ResolvedCallTarget {
                child_image_id: child_logical_call_id,
                child_issuccess: site_hint
                    .as_ref()
                    .and_then(|hint| hint.child_issuccess)
                    .unwrap_or(true),
            }
        } else {
            match site_hint.as_ref() {
                Some(hint) => ResolvedCallTarget {
                    child_image_id: hint.child_image_id.unwrap_or(
                        self.resolve_call_target(caller_id, caller_pc, callee_address)?
                            .child_image_id,
                    ),
                    child_issuccess: hint.child_issuccess.unwrap_or(true),
                },
                None => self.resolve_call_target(caller_id, caller_pc, callee_address)?,
            }
        };
        if !self
            .program
            .images
            .contains_key(&resolved_target.child_image_id)
        {
            return Err(ExecutionError::UnknownBytecodeCallId(
                resolved_target.child_image_id,
            ));
        }

        let child_depth = self.frames[frame_index].context.depth + 1;
        let child_success = resolved_target.child_issuccess;
        let parent_ispersistence = self.frames[frame_index].context.ispersistence;
        let caller_address = self.frames[frame_index].context.caller_address;
        let child_context = CallContextState {
            caller_id,
            depth: child_depth,
            caller_address,
            callee_address,
            calldata_offset,
            calldata_length,
            returndata_offset,
            returndata_length,
            value,
            issuccess: child_success,
            ispersistence: parent_ispersistence && child_success,
            isroot: false,
            last_callee_id: 0,
            last_callee_returndata_offset: 0,
            last_callee_returndata_length: 0,
            parent_resume_pc: self.frames[frame_index].live_pc,
            parent_resume_sp: self.frames[frame_index].live_sp,
            parent_resume_mmax: self.frames[frame_index].live_mmax,
        };

        self.events.push(ExecutionEvent::Call {
            caller_logical_call_id: caller_id,
            child_logical_call_id,
        });
        self.events.push(ExecutionEvent::CallContextRead {
            logical_call_id: caller_id,
            field_tag: CC_TAG_DEPTH,
            value: Word::from_u64(child_depth - 1).limbs(),
        });
        self.events.push(ExecutionEvent::CallContextRead {
            logical_call_id: caller_id,
            field_tag: CC_TAG_CALLER_ADDRESS,
            value: caller_address.limbs(),
        });
        self.events.push(ExecutionEvent::CallContextRead {
            logical_call_id: caller_id,
            field_tag: CC_TAG_ISPERSISTENCE,
            value: Word::from_bool(parent_ispersistence).limbs(),
        });
        self.write_context_events(child_logical_call_id, &child_context, false);

        let cpu_step = LogicalCpuStep {
            logical_call_id: caller_id,
            spawned_logical_call_id: Some(child_logical_call_id),
            pc: caller_pc,
            opcode: opcode as u64,
            rlc_a: Word::from_u64(child_depth).limbs(),
            rlc_b: Word::from_u64(calldata_offset).limbs(),
            rlc_c: Word::from_u64(returndata_offset).limbs(),
            rlc_d: Word::from_u64(returndata_length).limbs(),
            rlc_e: caller_address.limbs(),
            rlc_f: callee_address.limbs(),
            rlc_g: Word::from_u64(calldata_length).limbs(),
            rlc_h: value.limbs(),
            rlc_i: Word::from_bool(parent_ispersistence).limbs(),
            rlc_j: Word::from_bool(child_success).limbs(),
            memaddr: 0,
            inv: Fp::ZERO,
            mmax: self.frames[frame_index].live_mmax,
            ismaxchanged: false,
            sp: self.frames[frame_index].live_sp,
        };
        self.push_cpu_step(cpu_step)?;
        self.frames.push(ExecutionFrame {
            logical_call_id: child_logical_call_id,
            image_id: resolved_target.child_image_id,
            parent_logical_call_id: Some(caller_id),
            live_pc: 0,
            live_sp: 0,
            live_mmax: 0,
            stack: BTreeMap::new(),
            memory: BTreeMap::new(),
            context: child_context,
        });
        self.executed_images
            .insert(child_logical_call_id, resolved_target.child_image_id);
        Ok(())
    }

    fn step_return(&mut self, frame_index: usize, opcode: u8) -> Result<(), ExecutionError> {
        if self.frames[frame_index].parent_logical_call_id.is_none() {
            return Err(ExecutionError::RootReturn);
        }

        let child = self.frames[frame_index].clone();
        let parent_id = child.context.caller_id;
        let parent_index = self.find_frame_index(parent_id)?;
        let (source_offset_word, source_offset_addr, actual_len_word, actual_len_addr) =
            self.read_top2(frame_index)?;
        let source_offset = source_offset_word.low_u64()?;
        let actual_len = actual_len_word.low_u64()?;
        let requested_len = child.context.returndata_length;
        let copied_len = requested_len.min(actual_len);
        let copied_len_selector = requested_len <= actual_len;
        let source_bytes = child.read_memory_range(source_offset, copied_len);

        let parent_pc = child.context.parent_resume_pc;
        let parent_sp = child.context.parent_resume_sp;
        let parent_mmax = child.context.parent_resume_mmax;
        let child_isroot = child.context.isroot;

        self.events.push(ExecutionEvent::CallContextRead {
            logical_call_id: child.logical_call_id,
            field_tag: CC_TAG_CALLER_ID,
            value: Word::from_u64(parent_id).limbs(),
        });
        self.events.push(ExecutionEvent::CallContextRead {
            logical_call_id: child.logical_call_id,
            field_tag: CC_TAG_ISROOT,
            value: Word::from_bool(child_isroot).limbs(),
        });
        self.events.push(ExecutionEvent::CallContextRead {
            logical_call_id: child.logical_call_id,
            field_tag: CC_TAG_PC,
            value: Word::from_u64(parent_pc).limbs(),
        });
        self.events.push(ExecutionEvent::CallContextRead {
            logical_call_id: child.logical_call_id,
            field_tag: CC_TAG_SP,
            value: Word::from_u64(parent_sp).limbs(),
        });
        self.events.push(ExecutionEvent::CallContextRead {
            logical_call_id: child.logical_call_id,
            field_tag: CC_TAG_MMAX,
            value: Word::from_u64(parent_mmax).limbs(),
        });
        self.events.push(ExecutionEvent::CallContextRead {
            logical_call_id: child.logical_call_id,
            field_tag: CC_TAG_RETURNDATA_OFFSET,
            value: Word::from_u64(child.context.returndata_offset).limbs(),
        });
        self.events.push(ExecutionEvent::CallContextRead {
            logical_call_id: child.logical_call_id,
            field_tag: CC_TAG_RETURNDATA_LENGTH,
            value: Word::from_u64(child.context.returndata_length).limbs(),
        });
        self.events.push(ExecutionEvent::StackRead {
            logical_call_id: child.logical_call_id,
            address: source_offset_addr,
            value: source_offset_word.limbs(),
        });
        self.events.push(ExecutionEvent::StackRead {
            logical_call_id: child.logical_call_id,
            address: actual_len_addr,
            value: actual_len_word.limbs(),
        });

        {
            let parent = &mut self.frames[parent_index];
            parent.context.last_callee_id = child.logical_call_id;
            parent.context.last_callee_returndata_offset = child.context.returndata_offset;
            parent.context.last_callee_returndata_length = copied_len;
            parent.live_pc = parent_pc + 1;
            parent.live_sp = parent_sp - 5;
            parent.live_mmax = parent_mmax;
            if !child_isroot {
                for (offset, byte) in source_bytes.iter().enumerate() {
                    self.events.push(ExecutionEvent::MemoryWrite {
                        logical_call_id: parent.logical_call_id,
                        address: child.context.returndata_offset + offset as u64,
                        value: *byte,
                    });
                    parent
                        .memory
                        .insert(child.context.returndata_offset + offset as u64, *byte);
                }
                let (next_mmax, _) = grow_mmax(
                    parent.live_mmax,
                    child.context.returndata_offset + copied_len,
                );
                parent.live_mmax = next_mmax;
            }
            let success_addr = parent_sp - 6;
            self.events.push(ExecutionEvent::StackWrite {
                logical_call_id: parent.logical_call_id,
                address: success_addr,
                value: Word::one().limbs(),
            });
            parent.stack.insert(success_addr, Word::one());
        }

        self.events.push(ExecutionEvent::CallContextWrite {
            logical_call_id: parent_id,
            field_tag: CC_TAG_LAST_CALLEE_ID,
            value: Word::from_u64(child.logical_call_id).limbs(),
        });
        self.events.push(ExecutionEvent::CallContextWrite {
            logical_call_id: parent_id,
            field_tag: CC_TAG_LAST_CALLEE_RETURNDATA_OFFSET,
            value: Word::from_u64(child.context.returndata_offset).limbs(),
        });
        self.events.push(ExecutionEvent::CallContextWrite {
            logical_call_id: parent_id,
            field_tag: CC_TAG_LAST_CALLEE_RETURNDATA_LENGTH,
            value: Word::from_u64(copied_len).limbs(),
        });
        self.events.push(ExecutionEvent::Return {
            child_logical_call_id: child.logical_call_id,
            parent_logical_call_id: parent_id,
        });

        let cpu_step = LogicalCpuStep {
            logical_call_id: child.logical_call_id,
            spawned_logical_call_id: None,
            pc: child.live_pc,
            opcode: opcode as u64,
            rlc_a: Word::from_u64(parent_id).limbs(),
            rlc_b: Word::from_bool(child_isroot).limbs(),
            rlc_c: Word::from_u64(parent_pc).limbs(),
            rlc_d: Word::from_u64(parent_sp).limbs(),
            rlc_e: Word::from_u64(parent_mmax).limbs(),
            rlc_f: Word::from_u64(child.context.returndata_offset).limbs(),
            rlc_g: Word::from_u64(requested_len).limbs(),
            rlc_h: source_offset_word.limbs(),
            rlc_i: actual_len_word.limbs(),
            rlc_j: Word::from_bool(copied_len_selector).limbs(),
            memaddr: child.context.returndata_offset,
            inv: Fp::from(requested_len.abs_diff(actual_len)),
            mmax: child.live_mmax,
            ismaxchanged: !child_isroot
                && child.context.returndata_offset + copied_len > parent_mmax,
            sp: child.live_sp,
        };
        let source_step = self.cpu_steps.len();
        if !child_isroot {
            self.copy_plans.push(ExecutionCopyPlan {
                source_step,
                kind: CopyPlanKind::Return,
                src_call_id: Some(child.logical_call_id),
                dst_call_id: parent_id,
                src_offset: source_offset,
                src_end: source_offset + copied_len,
                dst_offset: child.context.returndata_offset,
                length: copied_len,
                bytes: source_bytes,
                use_tx_source: false,
            });
        }
        self.push_cpu_step(cpu_step)?;
        self.frames.remove(frame_index);
        Ok(())
    }

    fn step_write(&mut self, frame_index: usize, opcode: u8) -> Result<(), ExecutionError> {
        let logical_call_id = self.frames[frame_index].logical_call_id;
        let image_id = self.frames[frame_index].image_id;
        let pc = self.frames[frame_index].live_pc;
        let immediate = self.program.immediate(image_id, pc + 1)?;
        self.events.push(ExecutionEvent::ImmediateRead {
            logical_call_id,
            pc: pc + 1,
            value: immediate.limbs(),
        });
        let write_addr = self.frames[frame_index].live_sp;
        self.write_stack(frame_index, write_addr, immediate);
        self.frames[frame_index].live_sp += 1;
        self.frames[frame_index].live_pc += 2;

        let cpu_step = LogicalCpuStep {
            logical_call_id,
            spawned_logical_call_id: None,
            pc,
            opcode: opcode as u64,
            rlc_a: [0; 4],
            rlc_b: [0; 4],
            rlc_c: immediate.limbs(),
            rlc_d: [0; 4],
            rlc_e: [0; 4],
            rlc_f: [0; 4],
            rlc_g: [0; 4],
            rlc_h: [0; 4],
            rlc_i: [0; 4],
            rlc_j: [0; 4],
            memaddr: 0,
            inv: Fp::ZERO,
            mmax: self.frames[frame_index].live_mmax,
            ismaxchanged: false,
            sp: write_addr,
        };
        self.push_cpu_step(cpu_step)?;
        Ok(())
    }

    fn step_read(&mut self, frame_index: usize, opcode: u8) -> Result<(), ExecutionError> {
        let (key, addr) = self.read_top1(frame_index)?;
        let logical_call_id = self.frames[frame_index].logical_call_id;
        let pc = self.frames[frame_index].live_pc;
        self.events.push(ExecutionEvent::StateRead {
            logical_call_id,
            key: key.limbs(),
        });
        self.frames[frame_index].stack.remove(&addr);
        self.frames[frame_index].live_sp -= 1;
        self.frames[frame_index].live_pc += 1;

        let mut cpu_step = self.base_cpu_step(&self.frames[frame_index], opcode as u64);
        cpu_step.pc = pc;
        cpu_step.sp += 1;
        cpu_step.rlc_a = key.limbs();
        self.push_cpu_step(cpu_step)?;
        Ok(())
    }

    fn base_cpu_step(&self, frame: &ExecutionFrame, opcode: u64) -> LogicalCpuStep {
        LogicalCpuStep {
            logical_call_id: frame.logical_call_id,
            spawned_logical_call_id: None,
            pc: frame.live_pc,
            opcode,
            rlc_a: [0; 4],
            rlc_b: [0; 4],
            rlc_c: [0; 4],
            rlc_d: [0; 4],
            rlc_e: [0; 4],
            rlc_f: [0; 4],
            rlc_g: [0; 4],
            rlc_h: [0; 4],
            rlc_i: [0; 4],
            rlc_j: [0; 4],
            memaddr: 0,
            inv: Fp::ZERO,
            mmax: frame.live_mmax,
            ismaxchanged: false,
            sp: frame.live_sp,
        }
    }

    fn push_cpu_step(&mut self, step: LogicalCpuStep) -> Result<(), ExecutionError> {
        let flags = decode_opcode_execution(step.opcode)?;
        let delta = rwc_delta_execution(&step, &flags)?;
        self.cpu_steps.push(step);
        self.rw_counter = self.rw_counter.saturating_add(delta);
        Ok(())
    }

    fn read_top1(&mut self, frame_index: usize) -> Result<(Word, u64), ExecutionError> {
        ensure_stack(
            self.frames[frame_index].live_sp,
            1,
            self.frames[frame_index].logical_call_id,
            self.frames[frame_index].live_pc,
        )?;
        let addr = self.frames[frame_index].live_sp - 1;
        let value = *self.frames[frame_index]
            .stack
            .get(&addr)
            .unwrap_or(&Word::zero());
        self.events.push(ExecutionEvent::StackRead {
            logical_call_id: self.frames[frame_index].logical_call_id,
            address: addr,
            value: value.limbs(),
        });
        Ok((value, addr))
    }

    fn read_top2(&mut self, frame_index: usize) -> Result<(Word, u64, Word, u64), ExecutionError> {
        ensure_stack(
            self.frames[frame_index].live_sp,
            2,
            self.frames[frame_index].logical_call_id,
            self.frames[frame_index].live_pc,
        )?;
        let addr_a = self.frames[frame_index].live_sp - 1;
        let addr_b = self.frames[frame_index].live_sp - 2;
        let a = *self.frames[frame_index]
            .stack
            .get(&addr_a)
            .unwrap_or(&Word::zero());
        let b = *self.frames[frame_index]
            .stack
            .get(&addr_b)
            .unwrap_or(&Word::zero());
        self.events.push(ExecutionEvent::StackRead {
            logical_call_id: self.frames[frame_index].logical_call_id,
            address: addr_a,
            value: a.limbs(),
        });
        self.events.push(ExecutionEvent::StackRead {
            logical_call_id: self.frames[frame_index].logical_call_id,
            address: addr_b,
            value: b.limbs(),
        });
        Ok((a, addr_a, b, addr_b))
    }

    fn read_top3(
        &mut self,
        frame_index: usize,
    ) -> Result<(Word, u64, Word, u64, Word, u64), ExecutionError> {
        ensure_stack(
            self.frames[frame_index].live_sp,
            3,
            self.frames[frame_index].logical_call_id,
            self.frames[frame_index].live_pc,
        )?;
        let addr_a = self.frames[frame_index].live_sp - 1;
        let addr_b = self.frames[frame_index].live_sp - 2;
        let addr_c = self.frames[frame_index].live_sp - 3;
        let a = *self.frames[frame_index]
            .stack
            .get(&addr_a)
            .unwrap_or(&Word::zero());
        let b = *self.frames[frame_index]
            .stack
            .get(&addr_b)
            .unwrap_or(&Word::zero());
        let c = *self.frames[frame_index]
            .stack
            .get(&addr_c)
            .unwrap_or(&Word::zero());
        for (addr, value) in [(addr_a, a), (addr_b, b), (addr_c, c)] {
            self.events.push(ExecutionEvent::StackRead {
                logical_call_id: self.frames[frame_index].logical_call_id,
                address: addr,
                value: value.limbs(),
            });
        }
        Ok((a, addr_a, b, addr_b, c, addr_c))
    }

    fn read_call_operands(
        &mut self,
        frame_index: usize,
    ) -> Result<(u64, u64, u64, Word, u64, Word), ExecutionError> {
        ensure_stack(
            self.frames[frame_index].live_sp,
            6,
            self.frames[frame_index].logical_call_id,
            self.frames[frame_index].live_pc,
        )?;

        let sp = self.frames[frame_index].live_sp;
        let logical_call_id = self.frames[frame_index].logical_call_id;
        let addr_calldata_offset = sp - 1;
        let addr_returndata_offset = sp - 2;
        let addr_returndata_length = sp - 3;
        let addr_callee_address = sp - 4;
        let addr_calldata_length = sp - 5;
        let addr_value = sp - 6;

        let calldata_offset = *self.frames[frame_index]
            .stack
            .get(&addr_calldata_offset)
            .unwrap_or(&Word::zero());
        let returndata_offset = *self.frames[frame_index]
            .stack
            .get(&addr_returndata_offset)
            .unwrap_or(&Word::zero());
        let returndata_length = *self.frames[frame_index]
            .stack
            .get(&addr_returndata_length)
            .unwrap_or(&Word::zero());
        let callee_address = *self.frames[frame_index]
            .stack
            .get(&addr_callee_address)
            .unwrap_or(&Word::zero());
        let calldata_length = *self.frames[frame_index]
            .stack
            .get(&addr_calldata_length)
            .unwrap_or(&Word::zero());
        let value = *self.frames[frame_index]
            .stack
            .get(&addr_value)
            .unwrap_or(&Word::zero());

        for (address, value) in [
            (addr_calldata_offset, calldata_offset),
            (addr_returndata_offset, returndata_offset),
            (addr_returndata_length, returndata_length),
            (addr_callee_address, callee_address),
            (addr_calldata_length, calldata_length),
            (addr_value, value),
        ] {
            self.events.push(ExecutionEvent::StackRead {
                logical_call_id,
                address,
                value: value.limbs(),
            });
        }

        Ok((
            calldata_offset.low_u64()?,
            returndata_offset.low_u64()?,
            returndata_length.low_u64()?,
            callee_address,
            calldata_length.low_u64()?,
            value,
        ))
    }

    fn resolve_call_target(
        &self,
        logical_call_id: u64,
        pc: u64,
        callee_address: Word,
    ) -> Result<ResolvedCallTarget, ExecutionError> {
        if let Some(&child_image_id) = self.deployments.get(&callee_address) {
            return Ok(ResolvedCallTarget {
                child_image_id,
                child_issuccess: true,
            });
        }

        let hint =
            self.call_targets
                .get(&callee_address)
                .ok_or(ExecutionError::CallTargetMissing {
                    logical_call_id,
                    pc,
                    callee_address: callee_address.limbs(),
                })?;

        Ok(ResolvedCallTarget {
            child_image_id: hint.child_image_id,
            child_issuccess: hint.child_issuccess.unwrap_or(true),
        })
    }

    fn allocate_logical_call_id(&mut self) -> u64 {
        let next = self.next_logical_call_id;
        self.next_logical_call_id = self.next_logical_call_id.saturating_add(1);
        next
    }

    fn write_stack(&mut self, frame_index: usize, address: u64, value: Word) {
        self.events.push(ExecutionEvent::StackWrite {
            logical_call_id: self.frames[frame_index].logical_call_id,
            address,
            value: value.limbs(),
        });
        self.frames[frame_index].stack.insert(address, value);
    }

    fn write_memory_byte(&mut self, frame_index: usize, address: u64, value: u8) {
        self.events.push(ExecutionEvent::MemoryWrite {
            logical_call_id: self.frames[frame_index].logical_call_id,
            address,
            value,
        });
        self.frames[frame_index].memory.insert(address, value);
    }

    fn read_memory_chunk(&mut self, frame_index: usize, base: u64) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        for (offset, byte) in bytes.iter_mut().enumerate() {
            let address = base + offset as u64;
            *byte = *self.frames[frame_index].memory.get(&address).unwrap_or(&0);
            self.events.push(ExecutionEvent::MemoryRead {
                logical_call_id: self.frames[frame_index].logical_call_id,
                address,
                value: *byte,
            });
        }
        bytes
    }

    fn apply_memory_copy(&mut self, frame_index: usize, dst: u64, bytes: &[u8]) {
        for (offset, byte) in bytes.iter().enumerate() {
            self.write_memory_byte(frame_index, dst + offset as u64, *byte);
        }
    }

    fn write_context_events(
        &mut self,
        logical_call_id: u64,
        context: &CallContextState,
        root: bool,
    ) {
        let rows = if root {
            context.root_context_rows()
        } else {
            context.child_context_rows()
        };
        for (field_tag, value) in rows {
            self.events.push(ExecutionEvent::CallContextWrite {
                logical_call_id,
                field_tag,
                value,
            });
        }
    }

    fn find_frame(&self, logical_call_id: u64) -> Result<&ExecutionFrame, ExecutionError> {
        self.frames
            .iter()
            .find(|frame| frame.logical_call_id == logical_call_id)
            .ok_or(ExecutionError::ParentFrameMissing(logical_call_id))
    }

    fn find_frame_index(&self, logical_call_id: u64) -> Result<usize, ExecutionError> {
        self.frames
            .iter()
            .position(|frame| frame.logical_call_id == logical_call_id)
            .ok_or(ExecutionError::ParentFrameMissing(logical_call_id))
    }
}

impl ExecutionFrame {
    fn read_memory_range(&self, base: u64, len: u64) -> Vec<u8> {
        (0..len)
            .map(|offset| *self.memory.get(&(base + offset)).unwrap_or(&0))
            .collect()
    }
}

impl CallContextState {
    fn root_context_rows(&self) -> Vec<(u64, [u64; 4])> {
        vec![
            (CC_TAG_CALLER_ID, Word::from_u64(0).limbs()),
            (CC_TAG_DEPTH, Word::from_u64(self.depth).limbs()),
            (CC_TAG_CALLDATA_OFFSET, Word::from_u64(0).limbs()),
            (CC_TAG_RETURNDATA_OFFSET, Word::from_u64(0).limbs()),
            (CC_TAG_RETURNDATA_LENGTH, Word::from_u64(0).limbs()),
            (CC_TAG_CALLER_ADDRESS, self.caller_address.limbs()),
            (CC_TAG_CALLEE_ADDRESS, self.callee_address.limbs()),
            (
                CC_TAG_CALLDATA_LENGTH,
                Word::from_u64(self.calldata_length).limbs(),
            ),
            (CC_TAG_VALUE, self.value.limbs()),
            (CC_TAG_ISROOT, Word::one().limbs()),
            (CC_TAG_ISSUCCESS, Word::one().limbs()),
            (
                CC_TAG_ISPERSISTENCE,
                Word::from_bool(self.ispersistence).limbs(),
            ),
        ]
    }

    fn child_context_rows(&self) -> Vec<(u64, [u64; 4])> {
        vec![
            (CC_TAG_CALLER_ID, Word::from_u64(self.caller_id).limbs()),
            (CC_TAG_DEPTH, Word::from_u64(self.depth).limbs()),
            (
                CC_TAG_CALLDATA_OFFSET,
                Word::from_u64(self.calldata_offset).limbs(),
            ),
            (
                CC_TAG_RETURNDATA_OFFSET,
                Word::from_u64(self.returndata_offset).limbs(),
            ),
            (
                CC_TAG_RETURNDATA_LENGTH,
                Word::from_u64(self.returndata_length).limbs(),
            ),
            (CC_TAG_CALLER_ADDRESS, self.caller_address.limbs()),
            (CC_TAG_CALLEE_ADDRESS, self.callee_address.limbs()),
            (
                CC_TAG_CALLDATA_LENGTH,
                Word::from_u64(self.calldata_length).limbs(),
            ),
            (CC_TAG_VALUE, self.value.limbs()),
            (CC_TAG_ISROOT, Word::zero().limbs()),
            (CC_TAG_PC, Word::from_u64(self.parent_resume_pc).limbs()),
            (CC_TAG_SP, Word::from_u64(self.parent_resume_sp).limbs()),
            (CC_TAG_MMAX, Word::from_u64(self.parent_resume_mmax).limbs()),
            (CC_TAG_ISSUCCESS, Word::from_bool(self.issuccess).limbs()),
            (
                CC_TAG_ISPERSISTENCE,
                Word::from_bool(self.ispersistence).limbs(),
            ),
        ]
    }

    fn as_rows(&self) -> Vec<(u64, [u64; 4])> {
        let mut rows = self.child_context_rows();
        if self.isroot {
            rows = self.root_context_rows();
        }
        rows.extend([
            (
                CC_TAG_LAST_CALLEE_ID,
                Word::from_u64(self.last_callee_id).limbs(),
            ),
            (
                CC_TAG_LAST_CALLEE_RETURNDATA_OFFSET,
                Word::from_u64(self.last_callee_returndata_offset).limbs(),
            ),
            (
                CC_TAG_LAST_CALLEE_RETURNDATA_LENGTH,
                Word::from_u64(self.last_callee_returndata_length).limbs(),
            ),
        ]);
        rows
    }
}

impl BytecodeProgram {
    fn from_legacy_rows(rows: &[LogicalByteTableRow]) -> Result<Self, ExecutionError> {
        if rows.is_empty() {
            return Err(ExecutionError::EmptyBytecode);
        }

        let mut images = BTreeMap::<u64, ProgramImage>::new();
        for row in rows {
            let image = images
                .entry(row.logical_call_id)
                .or_insert_with(|| ProgramImage {
                    image_id: row.logical_call_id,
                    ..ProgramImage::default()
                });
            if row.iscode {
                let opcode =
                    u8::try_from(row.limb1).map_err(|_| ExecutionError::NonByteOpcode {
                        logical_call_id: row.logical_call_id,
                        pc: row.pc,
                        value: row.limb1,
                    })?;
                if image.code.insert(row.pc, opcode).is_some() {
                    return Err(ExecutionError::DuplicateBytecodeCell {
                        logical_call_id: row.logical_call_id,
                        pc: row.pc,
                        iscode: true,
                    });
                }
            } else {
                if image
                    .immediates
                    .insert(row.pc, Word([row.limb1, row.limb2, row.limb3, row.limb4]))
                    .is_some()
                {
                    return Err(ExecutionError::DuplicateBytecodeCell {
                        logical_call_id: row.logical_call_id,
                        pc: row.pc,
                        iscode: false,
                    });
                }
            }
        }

        validate_contiguous_logical_call_ids(images.keys().copied())?;
        Ok(Self { images })
    }

    fn from_image_rows(rows: &[ExecutionBytecodeRow]) -> Result<Self, ExecutionError> {
        if rows.is_empty() {
            return Err(ExecutionError::EmptyBytecode);
        }

        let mut images = BTreeMap::<u64, ProgramImage>::new();
        for row in rows {
            let image = images.entry(row.image_id).or_insert_with(|| ProgramImage {
                image_id: row.image_id,
                ..ProgramImage::default()
            });
            if row.iscode {
                let opcode =
                    u8::try_from(row.limb1).map_err(|_| ExecutionError::NonByteOpcode {
                        logical_call_id: row.image_id,
                        pc: row.pc,
                        value: row.limb1,
                    })?;
                if image.code.insert(row.pc, opcode).is_some() {
                    return Err(ExecutionError::DuplicateBytecodeCell {
                        logical_call_id: row.image_id,
                        pc: row.pc,
                        iscode: true,
                    });
                }
            } else if image
                .immediates
                .insert(row.pc, Word([row.limb1, row.limb2, row.limb3, row.limb4]))
                .is_some()
            {
                return Err(ExecutionError::DuplicateBytecodeCell {
                    logical_call_id: row.image_id,
                    pc: row.pc,
                    iscode: false,
                });
            }
        }

        Ok(Self { images })
    }

    fn opcode(&self, image_id: u64, pc: u64) -> Result<u8, ExecutionError> {
        self.images
            .get(&image_id)
            .ok_or(ExecutionError::UnknownBytecodeCallId(image_id))?
            .code
            .get(&pc)
            .copied()
            .ok_or(ExecutionError::MissingOpcode {
                logical_call_id: image_id,
                pc,
            })
    }

    fn immediate(&self, image_id: u64, pc: u64) -> Result<Word, ExecutionError> {
        self.images
            .get(&image_id)
            .ok_or(ExecutionError::UnknownBytecodeCallId(image_id))?
            .immediates
            .get(&pc)
            .copied()
            .ok_or(ExecutionError::MissingImmediate {
                logical_call_id: image_id,
                pc,
            })
    }

    fn expand_for_calls(&self, executed_images: &BTreeMap<u64, u64>) -> Vec<LogicalByteTableRow> {
        let mut out = Vec::new();
        for (logical_call_id, image_id) in executed_images {
            if let Some(image) = self.images.get(image_id) {
                for (&pc, &opcode) in &image.code {
                    out.push(LogicalByteTableRow {
                        logical_call_id: *logical_call_id,
                        pc,
                        limb1: opcode as u64,
                        limb2: 0,
                        limb3: 0,
                        limb4: 0,
                        iscode: true,
                    });
                }
                for (&pc, word) in &image.immediates {
                    out.push(LogicalByteTableRow {
                        logical_call_id: *logical_call_id,
                        pc,
                        limb1: word.0[0],
                        limb2: word.0[1],
                        limb3: word.0[2],
                        limb4: word.0[3],
                        iscode: false,
                    });
                }
            }
        }
        out.sort_by_key(|row| (row.logical_call_id, row.pc, !row.iscode));
        out
    }
}

impl TxPublicData {
    fn from_rows(rows: &[LogicalTxRow]) -> Result<Self, ExecutionError> {
        let mut first_txid = None;
        let mut caller_address = None;
        let mut callee_address = None;
        let mut value = None;
        let mut declared_calldata_len = None;
        let mut calldata = BTreeMap::<u64, u8>::new();

        for row in rows.iter().filter(|row| row.active) {
            first_txid.get_or_insert(row.txid);
            match row.tag {
                TX_TAG_CALLER_ADDRESS => {
                    caller_address = Some(Word::from_u128_halves(row.value_low, row.value_high));
                }
                TX_TAG_CALLEE_ADDRESS => {
                    callee_address = Some(Word::from_u128_halves(row.value_low, row.value_high));
                }
                TX_TAG_VALUE => {
                    value = Some(Word::from_u128_halves(row.value_low, row.value_high));
                }
                TX_TAG_CALLDATA_LENGTH => {
                    if row.value_high != 0 || row.value_low > u128::from(u64::MAX) {
                        return Err(ExecutionError::NarrowValueRequired("tx calldata length"));
                    }
                    declared_calldata_len = Some(row.value_low as u64);
                }
                TX_TAG_CALLDATA_BYTE => {
                    if row.value_high != 0 {
                        return Err(ExecutionError::NonByteValue("tx calldata byte"));
                    }
                    let byte = u8::try_from(row.value_low)
                        .map_err(|_| ExecutionError::NonByteValue("tx calldata byte"))?;
                    calldata.insert(row.index, byte);
                }
                _ => {}
            }
        }

        let txid = first_txid.ok_or(ExecutionError::TxMetadataMissing("active tx row"))?;
        let caller_address =
            caller_address.ok_or(ExecutionError::TxMetadataMissing("caller address"))?;
        let callee_address =
            callee_address.ok_or(ExecutionError::TxMetadataMissing("callee address"))?;
        let value = value.ok_or(ExecutionError::TxMetadataMissing("value"))?;
        let declared =
            declared_calldata_len.ok_or(ExecutionError::TxMetadataMissing("calldata length"))?;
        let calldata_vec = (0..declared)
            .map(|idx| calldata.get(&idx).copied().unwrap_or(0))
            .collect::<Vec<_>>();
        if declared as usize != calldata_vec.len() {
            return Err(ExecutionError::TxCalldataLengthMismatch {
                declared,
                actual: calldata_vec.len(),
            });
        }

        Ok(Self {
            txid,
            caller_address,
            callee_address,
            value,
            calldata: calldata_vec,
        })
    }
}

fn index_call_hints(
    hints: Vec<CallHint>,
) -> Result<BTreeMap<(u64, u64), CallHint>, ExecutionError> {
    let mut out = BTreeMap::new();
    for hint in hints {
        let key = (hint.caller_logical_call_id, hint.caller_pc);
        if out.insert(key, hint).is_some() {
            return Err(ExecutionError::DuplicateCallHint {
                logical_call_id: key.0,
                pc: key.1,
            });
        }
    }
    Ok(out)
}

fn index_call_targets(
    hints: Vec<CallTargetHint>,
) -> Result<BTreeMap<Word, CallTargetHint>, ExecutionError> {
    let mut out = BTreeMap::new();
    for hint in hints {
        let key = Word(hint.callee_address);
        if out.insert(key, hint).is_some() {
            return Err(ExecutionError::DuplicateCallTarget(key.limbs()));
        }
    }
    Ok(out)
}

fn index_deployments(
    program: &BytecodeProgram,
    rows: Vec<ExecutionDeploymentRow>,
) -> Result<BTreeMap<Word, u64>, ExecutionError> {
    let mut out = BTreeMap::new();
    for &image_id in program.images.keys() {
        out.insert(Word::from_u64(image_id), image_id);
    }

    for row in rows {
        let key = Word(row.callee_address);
        if let Some(previous_image_id) = out.insert(key, row.image_id) {
            if previous_image_id == row.image_id {
                continue;
            }
            return Err(ExecutionError::DuplicateDeploymentAddress(key.limbs()));
        }
    }
    Ok(out)
}

fn validate_contiguous_logical_call_ids(
    ids: impl IntoIterator<Item = u64>,
) -> Result<(), ExecutionError> {
    for (expected, found) in ids.into_iter().enumerate() {
        let expected = expected as u64;
        if found != expected {
            return Err(ExecutionError::NonContiguousLogicalCallIds { expected, found });
        }
    }
    Ok(())
}

fn ensure_stack(sp: u64, needed: u64, logical_call_id: u64, pc: u64) -> Result<(), ExecutionError> {
    if sp < needed {
        return Err(ExecutionError::StackUnderflow {
            logical_call_id,
            pc,
            sp,
            needed,
        });
    }
    Ok(())
}

fn read_vec_range(data: &[u8], start: u64, len: u64) -> Vec<u8> {
    (0..len)
        .map(|offset| data.get((start + offset) as usize).copied().unwrap_or(0))
        .collect()
}

fn grow_mmax(current: u64, required_end: u64) -> (u64, bool) {
    if required_end > current {
        (required_end, true)
    } else {
        (current, false)
    }
}

fn decode_opcode_execution(opcode: u64) -> Result<ExecutionOpcodeFlags, ExecutionError> {
    decode_circuit_opcode(opcode).ok_or(ExecutionError::UnsupportedOpcode(opcode))
}

fn cpu_rwc_bases(steps: &[LogicalCpuStep]) -> Result<Vec<u64>, ExecutionError> {
    let mut rw_counter = 0u64;
    let mut bases = Vec::with_capacity(steps.len());

    for step in steps {
        bases.push(rw_counter);
        let flags = decode_opcode_execution(step.opcode)?;
        rw_counter = rw_counter.saturating_add(rwc_delta_execution(step, &flags)?);
    }

    Ok(bases)
}

fn logical_to_actual_call_ids(
    steps: &[LogicalCpuStep],
) -> Result<BTreeMap<u64, u64>, ExecutionError> {
    let root_logical_call_id = steps
        .first()
        .ok_or(ExecutionError::EmptyBytecode)?
        .logical_call_id;
    let mut map = BTreeMap::new();
    map.insert(root_logical_call_id, 1u64);

    let mut rw_counter = 0u64;
    for (step_index, step) in steps.iter().enumerate() {
        let flags = decode_opcode_execution(step.opcode)?;
        if flags.iscall {
            let spawned = step
                .spawned_logical_call_id
                .ok_or(ExecutionError::MissingSpawnedLogicalCallId(step_index))?;
            if map.insert(spawned, rw_counter).is_some() {
                return Err(ExecutionError::DuplicateLogicalCallId(spawned));
            }
        }
        rw_counter = rw_counter.saturating_add(rwc_delta_execution(step, &flags)?);
    }

    Ok(map)
}

fn rewrite_cpu_steps_for_actual_call_ids(
    steps: &[LogicalCpuStep],
    logical_to_actual: &BTreeMap<u64, u64>,
) -> Result<Vec<LogicalCpuStep>, ExecutionError> {
    let mut out = Vec::with_capacity(steps.len());

    for step in steps {
        let mut rewritten = step.clone();
        let flags = decode_opcode_execution(step.opcode)?;

        if flags.isreturn {
            rewritten.rlc_a = word_from_u64(resolve_actual_call_id(
                logical_to_actual,
                word_to_u64(step.rlc_a, "return parent logical call_id")?,
            )?);
        }

        if flags.calldatacopy && word_to_u64(step.rlc_g, "calldatacopy source selector")? == 0 {
            rewritten.rlc_d = word_from_u64(resolve_actual_call_id(
                logical_to_actual,
                word_to_u64(step.rlc_d, "calldatacopy caller logical call_id")?,
            )?);
        }

        out.push(rewritten);
    }

    Ok(out)
}

fn lower_arithmetic_chunks(
    ops: &[ExecutionArithmeticOp],
) -> Result<Vec<LogicalArithmeticChunk>, ExecutionError> {
    let mut chunks = Vec::with_capacity(ops.len());
    let mut deferred_eq = Vec::new();
    let mut deferred_div = Vec::new();

    for op in ops {
        let chunk = lower_arithmetic_chunk(op)?;
        match op.op {
            ArithmeticOpKind::Eq => deferred_eq.push(chunk),
            ArithmeticOpKind::Div => deferred_div.push(chunk),
            _ => chunks.push(chunk),
        }
    }

    chunks.extend(deferred_eq);
    chunks.extend(deferred_div);
    Ok(chunks)
}

fn lower_arithmetic_chunk(
    op: &ExecutionArithmeticOp,
) -> Result<LogicalArithmeticChunk, ExecutionError> {
    match op.op {
        ArithmeticOpKind::Add => {
            lower_add_like_chunk(ArithmeticOpKind::Add, op.lhs, op.rhs, op.result, "add")
        }
        ArithmeticOpKind::Sub => {
            lower_add_like_chunk(ArithmeticOpKind::Sub, op.result, op.rhs, op.lhs, "sub")
        }
        ArithmeticOpKind::Mul => lower_mul_chunk(op),
        ArithmeticOpKind::Div => lower_div_chunk(op),
        ArithmeticOpKind::Lt => lower_lt_chunk(op),
        ArithmeticOpKind::Eq => lower_eq_chunk(op),
        ArithmeticOpKind::And
        | ArithmeticOpKind::Or
        | ArithmeticOpKind::Xor
        | ArithmeticOpKind::Not => lower_bitwise_chunk(op),
    }
}

fn lower_add_like_chunk(
    op_kind: ArithmeticOpKind,
    alu_a: [u64; 4],
    alu_b: [u64; 4],
    alu_c: [u64; 4],
    mismatch_name: &'static str,
) -> Result<LogicalArithmeticChunk, ExecutionError> {
    let mut rows = empty_arithmetic_rows();
    let mut carry_in = 0u128;

    for limb_idx in 0..4 {
        let sum = alu_a[limb_idx] as u128 + alu_b[limb_idx] as u128 + carry_in;
        if alu_c[limb_idx] != sum as u64 {
            return Err(ExecutionError::ArithmeticMismatch(mismatch_name));
        }
        let carry_out = (sum >> 64) as u64;
        carry_in = carry_out as u128;

        rows[limb_idx] = base_arithmetic_row(alu_a, alu_b, alu_c, limb_idx);
        rows[limb_idx].carry = Fp::from(carry_out);
        rows[limb_idx].pac_a = u64_to_u16_quads(alu_a[limb_idx]);
        rows[limb_idx].pac_b = u64_to_u16_quads(alu_b[limb_idx]);
        rows[limb_idx].pac_c = u64_to_u16_quads(alu_c[limb_idx]);
        rows[limb_idx].pac_carry = u64_to_u16_quads(carry_out);
    }

    Ok(LogicalArithmeticChunk { op: op_kind, rows })
}

fn lower_mul_chunk(op: &ExecutionArithmeticOp) -> Result<LogicalArithmeticChunk, ExecutionError> {
    let alu_a = op.lhs;
    let alu_b = op.rhs;
    let alu_c = op.result;
    let mut rows = empty_arithmetic_rows();
    let mut carry_in = 0u64;

    for limb_idx in 0..4 {
        let mut acc = Acc192::default();
        acc.add_u64(carry_in)?;
        match limb_idx {
            0 => {
                acc.add_u128((alu_a[0] as u128) * (alu_b[0] as u128))?;
            }
            1 => {
                acc.add_u128((alu_a[1] as u128) * (alu_b[0] as u128))?;
                acc.add_u128((alu_a[0] as u128) * (alu_b[1] as u128))?;
            }
            2 => {
                acc.add_u128((alu_a[2] as u128) * (alu_b[0] as u128))?;
                acc.add_u128((alu_a[0] as u128) * (alu_b[2] as u128))?;
                acc.add_u128((alu_a[1] as u128) * (alu_b[1] as u128))?;
            }
            3 => {
                acc.add_u128((alu_a[3] as u128) * (alu_b[0] as u128))?;
                acc.add_u128((alu_a[0] as u128) * (alu_b[3] as u128))?;
                acc.add_u128((alu_a[2] as u128) * (alu_b[1] as u128))?;
                acc.add_u128((alu_a[1] as u128) * (alu_b[2] as u128))?;
            }
            _ => unreachable!(),
        }

        if acc.low_u64() != alu_c[limb_idx] {
            return Err(ExecutionError::ArithmeticMismatch("mul"));
        }
        let carry_out = acc.carry_u64()?;
        carry_in = carry_out;

        rows[limb_idx] = base_arithmetic_row(alu_a, alu_b, alu_c, limb_idx);
        rows[limb_idx].carry = Fp::from(carry_out);
        rows[limb_idx].pac_a = u64_to_u16_quads(alu_a[limb_idx]);
        rows[limb_idx].pac_b = u64_to_u16_quads(alu_b[limb_idx]);
        rows[limb_idx].pac_c = u64_to_u16_quads(alu_c[limb_idx]);
        rows[limb_idx].pac_carry = u64_to_u16_quads(carry_out);
    }

    // EVM multiplication is modulo 2^256.  The four rows above constrain the
    // low four limbs and their carries; any remaining high half is deliberately
    // discarded rather than treated as a witness-generation error.

    Ok(LogicalArithmeticChunk {
        op: ArithmeticOpKind::Mul,
        rows,
    })
}

fn lower_div_chunk(op: &ExecutionArithmeticOp) -> Result<LogicalArithmeticChunk, ExecutionError> {
    let quotient = op.result;
    let divisor = op.rhs;
    let dividend = op.lhs;
    let product = mul_word_256(quotient, divisor);
    if product.high != [0; 4] {
        return Err(ExecutionError::ArithmeticOverflow(
            "div quotient*divisor high half",
        ));
    }
    let remainder = Word(dividend).sub_mod(Word(product.low)).limbs();
    if !Word(remainder).lt(Word(divisor)) && remainder != [0; 4] {
        return Err(ExecutionError::ArithmeticMismatch("div remainder range"));
    }

    let mut rows = empty_arithmetic_rows();
    let mut carry_in = 0u64;
    let (diff_limbs, borrow_ins, final_borrow) = strict_diff_trace(divisor, remainder);
    if final_borrow != 0 {
        return Err(ExecutionError::ArithmeticMismatch(
            "div remainder < divisor",
        ));
    }

    for limb_idx in 0..4 {
        let mut acc = Acc192::default();
        acc.add_u64(carry_in)?;
        acc.add_u64(remainder[limb_idx])?;
        match limb_idx {
            0 => {
                acc.add_u128((quotient[0] as u128) * (divisor[0] as u128))?;
            }
            1 => {
                acc.add_u128((quotient[1] as u128) * (divisor[0] as u128))?;
                acc.add_u128((quotient[0] as u128) * (divisor[1] as u128))?;
            }
            2 => {
                acc.add_u128((quotient[2] as u128) * (divisor[0] as u128))?;
                acc.add_u128((quotient[0] as u128) * (divisor[2] as u128))?;
                acc.add_u128((quotient[1] as u128) * (divisor[1] as u128))?;
            }
            3 => {
                acc.add_u128((quotient[3] as u128) * (divisor[0] as u128))?;
                acc.add_u128((quotient[0] as u128) * (divisor[3] as u128))?;
                acc.add_u128((quotient[2] as u128) * (divisor[1] as u128))?;
                acc.add_u128((quotient[1] as u128) * (divisor[2] as u128))?;
            }
            _ => unreachable!(),
        }

        if acc.low_u64() != dividend[limb_idx] {
            return Err(ExecutionError::ArithmeticMismatch("div"));
        }
        let carry_out = acc.carry_u64()?;
        carry_in = carry_out;

        rows[limb_idx] = base_arithmetic_row(quotient, divisor, dividend, limb_idx);
        rows[limb_idx].barlt = borrow_ins[limb_idx] as u64;
        rows[limb_idx].carry = Fp::from(carry_out);
        rows[limb_idx].rem = remainder[limb_idx];
        rows[limb_idx].pac_a = u64_to_u16_quads(quotient[limb_idx]);
        rows[limb_idx].pac_b = u64_to_u16_quads(divisor[limb_idx]);
        rows[limb_idx].pac_c = u64_to_u16_quads(dividend[limb_idx]);
        rows[limb_idx].pac_carry = u64_to_u16_quads(carry_out);
        rows[limb_idx].pac_rem = u64_to_u16_quads(remainder[limb_idx]);
        rows[limb_idx].pac_diff = u64_to_u16_quads(diff_limbs[limb_idx]);
    }

    let mut high_tail = Acc192::default();
    high_tail.add_u64(carry_in)?;
    for (ai, bi) in [(3usize, 1usize), (1, 3), (3, 2), (2, 3), (3, 3), (2, 2)] {
        high_tail.add_u128((quotient[ai] as u128) * (divisor[bi] as u128))?;
    }
    if !high_tail.is_zero() {
        return Err(ExecutionError::ArithmeticOverflow(
            "div quotient*divisor high half",
        ));
    }

    Ok(LogicalArithmeticChunk {
        op: ArithmeticOpKind::Div,
        rows,
    })
}

fn lower_lt_chunk(op: &ExecutionArithmeticOp) -> Result<LogicalArithmeticChunk, ExecutionError> {
    let alu_a = op.lhs;
    let alu_b = op.rhs;
    let result = op.result;
    let result_bit = result[0];
    let (diff_limbs, borrow_ins, final_borrow) = strict_diff_trace(alu_b, alu_a);
    let expected = u64::from(final_borrow == 0);
    if result != word_from_u64(expected) || result_bit != expected {
        return Err(ExecutionError::ArithmeticMismatch("lt"));
    }

    let mut rows = empty_arithmetic_rows();
    for limb_idx in 0..4 {
        rows[limb_idx] = base_arithmetic_row(alu_a, alu_b, word_from_u64(result_bit), limb_idx);
        rows[limb_idx].barlt = borrow_ins[limb_idx] as u64;
        rows[limb_idx].limb_c = diff_limbs[limb_idx];
        rows[limb_idx].pac_a = u64_to_u16_quads(alu_a[limb_idx]);
        rows[limb_idx].pac_b = u64_to_u16_quads(alu_b[limb_idx]);
        rows[limb_idx].pac_c = u64_to_u16_quads(diff_limbs[limb_idx]);
        rows[limb_idx].rlc_c = word_from_u64(result_bit);
    }

    Ok(LogicalArithmeticChunk {
        op: ArithmeticOpKind::Lt,
        rows,
    })
}

fn lower_eq_chunk(op: &ExecutionArithmeticOp) -> Result<LogicalArithmeticChunk, ExecutionError> {
    let expected = if op.lhs == op.rhs { 1 } else { 0 };
    if op.result != word_from_u64(expected) {
        return Err(ExecutionError::ArithmeticMismatch("eq"));
    }

    let mut rows = empty_arithmetic_rows();
    let limb_eq = core::array::from_fn::<_, 4, _>(|idx| u64::from(op.lhs[idx] == op.rhs[idx]));
    for limb_idx in 0..4 {
        rows[limb_idx] = base_arithmetic_row(op.lhs, op.rhs, [0; 4], limb_idx);
        rows[limb_idx].limb_c = limb_eq[limb_idx];
        rows[limb_idx].carry = if limb_eq[limb_idx] == 1 {
            Fp::ZERO
        } else {
            (Fp::from(op.lhs[limb_idx]) - Fp::from(op.rhs[limb_idx]))
                .invert()
                .unwrap_or(Fp::ZERO)
        };
        rows[limb_idx].pac_a = u64_to_u16_quads(op.lhs[limb_idx]);
        rows[limb_idx].pac_b = u64_to_u16_quads(op.rhs[limb_idx]);
        rows[limb_idx].pac_carry = [
            1,
            u64::from(limb_idx == 0),
            if limb_idx < 3 {
                limb_eq[limb_idx] * limb_eq[limb_idx + 1]
            } else {
                0
            },
            0,
        ];
        rows[limb_idx].rlc_c = if limb_idx == 0 {
            word_from_u64(expected)
        } else {
            [0; 4]
        };
    }

    Ok(LogicalArithmeticChunk {
        op: ArithmeticOpKind::Eq,
        rows,
    })
}

fn lower_bitwise_chunk(
    op: &ExecutionArithmeticOp,
) -> Result<LogicalArithmeticChunk, ExecutionError> {
    let (alu_a, alu_b, alu_c) = match op.op {
        ArithmeticOpKind::And => (op.lhs, op.rhs, op.result),
        ArithmeticOpKind::Or => (op.lhs, op.rhs, op.result),
        ArithmeticOpKind::Xor => (op.lhs, op.rhs, op.result),
        ArithmeticOpKind::Not => (op.lhs, [0; 4], op.result),
        _ => unreachable!(),
    };

    let mut rows = empty_arithmetic_rows();
    for limb_idx in 0..4 {
        let expected = match op.op {
            ArithmeticOpKind::And => alu_a[limb_idx] & alu_b[limb_idx],
            ArithmeticOpKind::Or => alu_a[limb_idx] | alu_b[limb_idx],
            ArithmeticOpKind::Xor => alu_a[limb_idx] ^ alu_b[limb_idx],
            ArithmeticOpKind::Not => !alu_a[limb_idx],
            _ => unreachable!(),
        };
        if expected != alu_c[limb_idx] {
            return Err(ExecutionError::ArithmeticMismatch("bitwise"));
        }

        let a_bytes = alu_a[limb_idx].to_le_bytes();
        let b_bytes = alu_b[limb_idx].to_le_bytes();
        let c_bytes = alu_c[limb_idx].to_le_bytes();

        rows[limb_idx] = base_arithmetic_row(alu_a, alu_b, alu_c, limb_idx);
        rows[limb_idx].barlt = c_bytes[4] as u64;
        rows[limb_idx].carry = Fp::from(c_bytes[5] as u64);
        rows[limb_idx].rem = c_bytes[6] as u64;
        rows[limb_idx].pac_a = a_bytes[..4]
            .iter()
            .map(|byte| *byte as u64)
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        rows[limb_idx].pac_b = a_bytes[4..]
            .iter()
            .map(|byte| *byte as u64)
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        rows[limb_idx].pac_c = b_bytes[..4]
            .iter()
            .map(|byte| *byte as u64)
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        rows[limb_idx].pac_carry = b_bytes[4..]
            .iter()
            .map(|byte| *byte as u64)
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        rows[limb_idx].pac_rem = c_bytes[..4]
            .iter()
            .map(|byte| *byte as u64)
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        rows[limb_idx].noname = c_bytes[7] as u64;
    }

    Ok(LogicalArithmeticChunk { op: op.op, rows })
}

fn lower_rw_rows(
    original_steps: &[LogicalCpuStep],
    lowered_steps: &[LogicalCpuStep],
    rwc_bases: &[u64],
    logical_to_actual: &BTreeMap<u64, u64>,
) -> Result<Vec<LogicalRwRow>, ExecutionError> {
    let mut rows = Vec::new();

    for (((step_index, original), lowered), base_rwc) in original_steps
        .iter()
        .enumerate()
        .zip(lowered_steps.iter())
        .zip(rwc_bases.iter().copied())
    {
        let flags = decode_opcode_execution(original.opcode)?;
        let logical_call_id = original.logical_call_id;
        let addr_a = compute_addr_a_execution(original.sp, &flags);
        let addr_b = original.sp.saturating_sub(2);

        if flags.isbegintx {
            rows.push(ctx_rw(
                logical_call_id,
                CC_TAG_CALLER_ID,
                base_rwc,
                true,
                word_from_u64(0),
            ));
            rows.push(ctx_rw(
                logical_call_id,
                CC_TAG_DEPTH,
                base_rwc + 1,
                true,
                word_from_u64(1),
            ));
            rows.push(ctx_rw(
                logical_call_id,
                CC_TAG_CALLDATA_OFFSET,
                base_rwc + 2,
                true,
                word_from_u64(0),
            ));
            rows.push(ctx_rw(
                logical_call_id,
                CC_TAG_RETURNDATA_OFFSET,
                base_rwc + 3,
                true,
                word_from_u64(0),
            ));
            rows.push(ctx_rw(
                logical_call_id,
                CC_TAG_RETURNDATA_LENGTH,
                base_rwc + 4,
                true,
                word_from_u64(0),
            ));
            rows.push(ctx_rw(
                logical_call_id,
                CC_TAG_CALLER_ADDRESS,
                base_rwc + 5,
                true,
                lowered.rlc_e,
            ));
            rows.push(ctx_rw(
                logical_call_id,
                CC_TAG_CALLEE_ADDRESS,
                base_rwc + 6,
                true,
                lowered.rlc_f,
            ));
            rows.push(ctx_rw(
                logical_call_id,
                CC_TAG_CALLDATA_LENGTH,
                base_rwc + 7,
                true,
                lowered.rlc_g,
            ));
            rows.push(ctx_rw(
                logical_call_id,
                CC_TAG_VALUE,
                base_rwc + 8,
                true,
                lowered.rlc_h,
            ));
            rows.push(ctx_rw(
                logical_call_id,
                CC_TAG_ISROOT,
                base_rwc + 9,
                true,
                word_from_u64(1),
            ));
            rows.push(ctx_rw(
                logical_call_id,
                CC_TAG_ISSUCCESS,
                base_rwc + 10,
                true,
                lowered.rlc_i,
            ));
            rows.push(ctx_rw(
                logical_call_id,
                CC_TAG_ISPERSISTENCE,
                base_rwc + 11,
                true,
                lowered.rlc_i,
            ));
            continue;
        }

        if flags.iscall {
            let child_logical_call_id = original
                .spawned_logical_call_id
                .ok_or(ExecutionError::MissingSpawnedLogicalCallId(step_index))?;
            let child_ispersistence = word_from_u64(
                word_to_u64(lowered.rlc_i, "call parent ispersistence")?
                    * word_to_u64(lowered.rlc_j, "call child issuccess")?,
            );
            let actual_current_call_id =
                word_from_u64(resolve_actual_call_id(logical_to_actual, logical_call_id)?);

            rows.push(ctx_rw(
                child_logical_call_id,
                CC_TAG_CALLER_ID,
                base_rwc,
                true,
                actual_current_call_id,
            ));
            rows.push(ctx_rw(
                logical_call_id,
                CC_TAG_DEPTH,
                base_rwc + 1,
                false,
                word_from_u64(word_to_u64(lowered.rlc_a, "call child depth")?.saturating_sub(1)),
            ));
            rows.push(ctx_rw(
                child_logical_call_id,
                CC_TAG_DEPTH,
                base_rwc + 2,
                true,
                lowered.rlc_a,
            ));
            rows.push(stack_rw(
                logical_call_id,
                original.sp.saturating_sub(1),
                base_rwc + 3,
                false,
                lowered.rlc_b,
            ));
            rows.push(ctx_rw(
                child_logical_call_id,
                CC_TAG_CALLDATA_OFFSET,
                base_rwc + 4,
                true,
                lowered.rlc_b,
            ));
            rows.push(stack_rw(
                logical_call_id,
                original.sp.saturating_sub(2),
                base_rwc + 5,
                false,
                lowered.rlc_c,
            ));
            rows.push(ctx_rw(
                child_logical_call_id,
                CC_TAG_RETURNDATA_OFFSET,
                base_rwc + 6,
                true,
                lowered.rlc_c,
            ));
            rows.push(stack_rw(
                logical_call_id,
                original.sp.saturating_sub(3),
                base_rwc + 7,
                false,
                lowered.rlc_d,
            ));
            rows.push(ctx_rw(
                child_logical_call_id,
                CC_TAG_RETURNDATA_LENGTH,
                base_rwc + 8,
                true,
                lowered.rlc_d,
            ));
            rows.push(ctx_rw(
                logical_call_id,
                CC_TAG_CALLER_ADDRESS,
                base_rwc + 9,
                false,
                lowered.rlc_e,
            ));
            rows.push(ctx_rw(
                child_logical_call_id,
                CC_TAG_CALLER_ADDRESS,
                base_rwc + 10,
                true,
                lowered.rlc_e,
            ));
            rows.push(stack_rw(
                logical_call_id,
                original.sp.saturating_sub(4),
                base_rwc + 11,
                false,
                lowered.rlc_f,
            ));
            rows.push(ctx_rw(
                child_logical_call_id,
                CC_TAG_CALLEE_ADDRESS,
                base_rwc + 12,
                true,
                lowered.rlc_f,
            ));
            rows.push(stack_rw(
                logical_call_id,
                original.sp.saturating_sub(5),
                base_rwc + 13,
                false,
                lowered.rlc_g,
            ));
            rows.push(ctx_rw(
                child_logical_call_id,
                CC_TAG_CALLDATA_LENGTH,
                base_rwc + 14,
                true,
                lowered.rlc_g,
            ));
            rows.push(stack_rw(
                logical_call_id,
                original.sp.saturating_sub(6),
                base_rwc + 15,
                false,
                lowered.rlc_h,
            ));
            rows.push(ctx_rw(
                child_logical_call_id,
                CC_TAG_VALUE,
                base_rwc + 16,
                true,
                lowered.rlc_h,
            ));
            rows.push(ctx_rw(
                child_logical_call_id,
                CC_TAG_ISROOT,
                base_rwc + 17,
                true,
                word_from_u64(0),
            ));
            rows.push(ctx_rw(
                logical_call_id,
                CC_TAG_PC,
                base_rwc + 18,
                true,
                word_from_u64(original.pc),
            ));
            rows.push(ctx_rw(
                logical_call_id,
                CC_TAG_SP,
                base_rwc + 19,
                true,
                word_from_u64(original.sp),
            ));
            rows.push(ctx_rw(
                logical_call_id,
                CC_TAG_MMAX,
                base_rwc + 20,
                true,
                word_from_u64(original.mmax),
            ));
            rows.push(ctx_rw(
                logical_call_id,
                CC_TAG_ISPERSISTENCE,
                base_rwc + 21,
                false,
                lowered.rlc_i,
            ));
            rows.push(ctx_rw(
                child_logical_call_id,
                CC_TAG_ISSUCCESS,
                base_rwc + 22,
                true,
                lowered.rlc_j,
            ));
            rows.push(ctx_rw(
                child_logical_call_id,
                CC_TAG_ISPERSISTENCE,
                base_rwc + 23,
                true,
                child_ispersistence,
            ));
            continue;
        }

        if flags.isreturn {
            let parent_logical_call_id =
                word_to_u64(original.rlc_a, "return parent logical call_id")?;
            let current_actual_call_id =
                word_from_u64(resolve_actual_call_id(logical_to_actual, logical_call_id)?);
            let copied_len = choose_return_copy_len(lowered)?;

            rows.push(ctx_rw(
                logical_call_id,
                CC_TAG_CALLER_ID,
                base_rwc,
                false,
                lowered.rlc_a,
            ));
            rows.push(ctx_rw(
                logical_call_id,
                CC_TAG_ISROOT,
                base_rwc + 1,
                false,
                lowered.rlc_b,
            ));
            rows.push(ctx_rw(
                parent_logical_call_id,
                CC_TAG_PC,
                base_rwc + 2,
                false,
                lowered.rlc_c,
            ));
            rows.push(ctx_rw(
                parent_logical_call_id,
                CC_TAG_SP,
                base_rwc + 3,
                false,
                lowered.rlc_d,
            ));
            rows.push(ctx_rw(
                parent_logical_call_id,
                CC_TAG_MMAX,
                base_rwc + 4,
                false,
                lowered.rlc_e,
            ));
            rows.push(ctx_rw(
                parent_logical_call_id,
                CC_TAG_LAST_CALLEE_ID,
                base_rwc + 5,
                true,
                current_actual_call_id,
            ));
            rows.push(ctx_rw(
                logical_call_id,
                CC_TAG_RETURNDATA_OFFSET,
                base_rwc + 6,
                false,
                lowered.rlc_f,
            ));
            rows.push(ctx_rw(
                logical_call_id,
                CC_TAG_RETURNDATA_LENGTH,
                base_rwc + 7,
                false,
                lowered.rlc_g,
            ));
            rows.push(ctx_rw(
                parent_logical_call_id,
                CC_TAG_LAST_CALLEE_RETURNDATA_OFFSET,
                base_rwc + 8,
                true,
                lowered.rlc_f,
            ));
            rows.push(ctx_rw(
                parent_logical_call_id,
                CC_TAG_LAST_CALLEE_RETURNDATA_LENGTH,
                base_rwc + 9,
                true,
                word_from_u64(copied_len),
            ));
            rows.push(stack_rw(
                parent_logical_call_id,
                word_to_u64(lowered.rlc_d, "return parent sp")?.saturating_sub(6),
                base_rwc + 10,
                true,
                word_from_u64(1),
            ));
            rows.push(ctx_rw(
                logical_call_id,
                CC_TAG_ISSUCCESS,
                base_rwc + 11,
                false,
                word_from_u64(1),
            ));
            rows.push(stack_rw(
                logical_call_id,
                original.sp.saturating_sub(1),
                base_rwc + 12,
                false,
                lowered.rlc_h,
            ));
            rows.push(stack_rw(
                logical_call_id,
                original.sp.saturating_sub(2),
                base_rwc + 13,
                false,
                lowered.rlc_i,
            ));
            continue;
        }

        if flags.returndatacopy {
            rows.push(stack_rw(
                logical_call_id,
                original.sp.saturating_sub(1),
                base_rwc,
                false,
                lowered.rlc_a,
            ));
            rows.push(stack_rw(
                logical_call_id,
                original.sp.saturating_sub(2),
                base_rwc + 1,
                false,
                lowered.rlc_b,
            ));
            rows.push(stack_rw(
                logical_call_id,
                original.sp.saturating_sub(3),
                base_rwc + 2,
                false,
                lowered.rlc_c,
            ));
            rows.push(ctx_rw(
                logical_call_id,
                CC_TAG_LAST_CALLEE_RETURNDATA_OFFSET,
                base_rwc + 3,
                false,
                lowered.rlc_d,
            ));
            rows.push(ctx_rw(
                logical_call_id,
                CC_TAG_LAST_CALLEE_RETURNDATA_LENGTH,
                base_rwc + 4,
                false,
                lowered.rlc_e,
            ));
            continue;
        }

        if flags.calldatacopy {
            rows.push(stack_rw(
                logical_call_id,
                original.sp.saturating_sub(1),
                base_rwc,
                false,
                lowered.rlc_a,
            ));
            rows.push(stack_rw(
                logical_call_id,
                original.sp.saturating_sub(2),
                base_rwc + 1,
                false,
                lowered.rlc_b,
            ));
            rows.push(stack_rw(
                logical_call_id,
                original.sp.saturating_sub(3),
                base_rwc + 2,
                false,
                lowered.rlc_c,
            ));
            rows.push(ctx_rw(
                logical_call_id,
                CC_TAG_CALLER_ID,
                base_rwc + 3,
                false,
                lowered.rlc_d,
            ));
            rows.push(ctx_rw(
                logical_call_id,
                CC_TAG_CALLDATA_OFFSET,
                base_rwc + 4,
                false,
                lowered.rlc_e,
            ));
            rows.push(ctx_rw(
                logical_call_id,
                CC_TAG_CALLDATA_LENGTH,
                base_rwc + 5,
                false,
                lowered.rlc_f,
            ));
            rows.push(ctx_rw(
                logical_call_id,
                CC_TAG_ISROOT,
                base_rwc + 6,
                false,
                lowered.rlc_g,
            ));
            continue;
        }

        if flags.isadd
            || flags.issub
            || flags.ismul
            || flags.isdiv
            || flags.islt
            || flags.iseq
            || flags.isand
            || flags.isor
            || flags.isxor
            || flags.ismstore
            || flags.ismstore8
            || flags.isjumpcon
        {
            rows.push(stack_rw(
                logical_call_id,
                addr_a,
                base_rwc,
                false,
                lowered.rlc_a,
            ));
            rows.push(stack_rw(
                logical_call_id,
                addr_b,
                base_rwc + 1,
                false,
                lowered.rlc_b,
            ));
        } else if flags.isjump || flags.isnot || flags.ismload || flags.isread {
            rows.push(stack_rw(
                logical_call_id,
                addr_a,
                base_rwc,
                false,
                lowered.rlc_a,
            ));
        }

        if flags.isadd
            || flags.issub
            || flags.ismul
            || flags.isdiv
            || flags.islt
            || flags.iseq
            || flags.isand
            || flags.isor
            || flags.isxor
        {
            rows.push(stack_rw(
                logical_call_id,
                addr_b,
                base_rwc + 2,
                true,
                lowered.rlc_c,
            ));
        } else if flags.isnot {
            rows.push(stack_rw(
                logical_call_id,
                original.sp.saturating_sub(1),
                base_rwc + 1,
                true,
                lowered.rlc_c,
            ));
        } else if flags.ismload {
            rows.push(stack_rw(
                logical_call_id,
                original.sp.saturating_sub(1),
                base_rwc + 33,
                true,
                lowered.rlc_c,
            ));
        } else if flags.iswrite {
            rows.push(stack_rw(
                logical_call_id,
                original.sp,
                base_rwc,
                true,
                lowered.rlc_c,
            ));
        }
    }

    Ok(rows)
}

fn lower_copy_rows(
    plans: &[ExecutionCopyPlan],
    rwc_bases: &[u64],
) -> Result<Vec<LogicalCopyRow>, ExecutionError> {
    let mut rows = Vec::new();

    for plan in plans {
        let start_rwc = match plan.kind {
            CopyPlanKind::Return => rwc_bases[plan.source_step] + 14,
            CopyPlanKind::ReturnDataCopy => rwc_bases[plan.source_step] + 5,
            CopyPlanKind::CallDataCopy => rwc_bases[plan.source_step] + 7,
        };
        let read_call_id = plan.src_call_id.unwrap_or(plan.dst_call_id);

        for (index, byte) in plan.bytes.iter().copied().enumerate() {
            let index = index as u64;
            let bytesleft = plan.length.saturating_sub(index);
            let address_read = plan.src_offset + index;
            let address_write = plan.dst_offset + index;
            let rwc_read = if plan.use_tx_source {
                start_rwc + index
            } else {
                start_rwc + 2 * index
            };
            let rwc_write = if plan.use_tx_source {
                rwc_read
            } else {
                rwc_read + 1
            };
            let ispad = address_read >= plan.src_end;
            let (limb_1, limb_2) = copy_distance_limbs(plan.src_end, address_read, ispad);

            rows.push(LogicalCopyRow {
                switch: true,
                isfirst: index == 0,
                islast: false,
                rwc: rwc_read,
                address_write,
                address_read,
                address_end: plan.src_end,
                iswrite: false,
                ismem: !plan.use_tx_source,
                istx: plan.use_tx_source,
                logical_call_id_read: read_call_id,
                logical_call_id_write: plan.dst_call_id,
                bytesleft,
                value: if ispad { 0 } else { byte as u64 },
                ispad,
                inv: Fp::ZERO,
                limb_1,
                limb_2,
            });

            rows.push(LogicalCopyRow {
                switch: true,
                isfirst: false,
                islast: index + 1 == plan.length,
                rwc: rwc_write,
                address_write,
                address_read,
                address_end: plan.src_end,
                iswrite: true,
                ismem: !plan.use_tx_source,
                istx: plan.use_tx_source,
                logical_call_id_read: read_call_id,
                logical_call_id_write: plan.dst_call_id,
                bytesleft,
                value: if ispad { 0 } else { byte as u64 },
                ispad: false,
                inv: if index + 1 == plan.length {
                    Fp::ZERO
                } else {
                    field_inverse_u64(bytesleft.saturating_sub(1))
                },
                limb_1: 0,
                limb_2: 0,
            });
        }
    }

    if !rows.is_empty() {
        rows.push(LogicalCopyRow {
            switch: false,
            isfirst: true,
            islast: false,
            rwc: 0,
            address_write: 0,
            address_read: 0,
            address_end: 0,
            iswrite: false,
            ismem: false,
            istx: false,
            logical_call_id_read: 0,
            logical_call_id_write: 0,
            bytesleft: 0,
            value: 0,
            ispad: false,
            inv: Fp::ZERO,
            limb_1: 0,
            limb_2: 0,
        });
    }

    Ok(rows)
}

fn empty_arithmetic_rows() -> [LogicalArithmeticRow; 4] {
    core::array::from_fn(|_| LogicalArithmeticRow {
        barlt: 0,
        carry: Fp::ZERO,
        rem: 0,
        limb_a: 0,
        limb_b: 0,
        limb_c: 0,
        pac_a: [0; 4],
        pac_b: [0; 4],
        pac_c: [0; 4],
        pac_carry: [0; 4],
        pac_rem: [0; 4],
        pac_diff: [0; 4],
        rlc_a: [0; 4],
        rlc_b: [0; 4],
        rlc_c: [0; 4],
        noname: 0,
    })
}

fn base_arithmetic_row(
    word_a: [u64; 4],
    word_b: [u64; 4],
    word_c: [u64; 4],
    limb_idx: usize,
) -> LogicalArithmeticRow {
    let mut row = empty_arithmetic_rows()[0].clone();
    row.limb_a = word_a[limb_idx];
    row.limb_b = word_b[limb_idx];
    row.limb_c = word_c[limb_idx];
    row.rlc_a = suffix_word(word_a, limb_idx);
    row.rlc_b = suffix_word(word_b, limb_idx);
    row.rlc_c = suffix_word(word_c, limb_idx);
    row
}

fn suffix_word(word: [u64; 4], start: usize) -> [u64; 4] {
    let mut out = [0u64; 4];
    for idx in start..4 {
        out[idx - start] = word[idx];
    }
    out
}

fn u64_to_u16_quads(value: u64) -> [u64; 4] {
    [
        value & 0xffff,
        (value >> 16) & 0xffff,
        (value >> 32) & 0xffff,
        (value >> 48) & 0xffff,
    ]
}

fn u64_to_u8_octets(value: u64) -> [u64; 8] {
    value.to_le_bytes().map(u64::from)
}

fn strict_diff_trace(minuend: [u64; 4], subtrahend: [u64; 4]) -> ([u64; 4], [u8; 4], u8) {
    let mut diff = [0u64; 4];
    let mut borrow_ins = [0u8; 4];
    let mut borrow_in = 1u8;

    for limb_idx in 0..4 {
        borrow_ins[limb_idx] = borrow_in;
        let lhs = minuend[limb_idx] as u128;
        let rhs = subtrahend[limb_idx] as u128 + borrow_in as u128;
        if lhs >= rhs {
            diff[limb_idx] = (lhs - rhs) as u64;
            borrow_in = 0;
        } else {
            diff[limb_idx] = ((1u128 << 64) + lhs - rhs) as u64;
            borrow_in = 1;
        }
    }

    (diff, borrow_ins, borrow_in)
}

#[derive(Debug, Clone, Copy, Default)]
struct MulWord256 {
    low: [u64; 4],
    high: [u64; 4],
}

fn mul_word_256(lhs: [u64; 4], rhs: [u64; 4]) -> MulWord256 {
    let mut acc = [0u64; 8];
    for i in 0..4 {
        for j in 0..4 {
            add_u128_into_limbs(&mut acc, i + j, (lhs[i] as u128) * (rhs[j] as u128));
        }
    }

    MulWord256 {
        low: [acc[0], acc[1], acc[2], acc[3]],
        high: [acc[4], acc[5], acc[6], acc[7]],
    }
}

fn add_u128_into_limbs(limbs: &mut [u64], index: usize, value: u128) {
    let low = value as u64;
    let high = (value >> 64) as u64;
    add_u64_into_limbs(limbs, index, low);
    add_u64_into_limbs(limbs, index + 1, high);
}

fn add_u64_into_limbs(limbs: &mut [u64], mut index: usize, mut value: u64) {
    while value != 0 && index < limbs.len() {
        let (sum, overflow) = limbs[index].overflowing_add(value);
        limbs[index] = sum;
        value = u64::from(overflow);
        index += 1;
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct Acc192([u64; 3]);

impl Acc192 {
    fn add_u64(&mut self, value: u64) -> Result<(), ExecutionError> {
        self.add_at(0, value)
    }

    fn add_u128(&mut self, value: u128) -> Result<(), ExecutionError> {
        self.add_at(0, value as u64)?;
        self.add_at(1, (value >> 64) as u64)
    }

    fn add_at(&mut self, idx: usize, value: u64) -> Result<(), ExecutionError> {
        let mut index = idx;
        let mut carry = value;
        while carry != 0 {
            if index >= self.0.len() {
                return Err(ExecutionError::ArithmeticOverflow("accumulator overflow"));
            }
            let (sum, overflow) = self.0[index].overflowing_add(carry);
            self.0[index] = sum;
            carry = u64::from(overflow);
            index += 1;
        }
        Ok(())
    }

    fn low_u64(self) -> u64 {
        self.0[0]
    }

    fn carry_u64(self) -> Result<u64, ExecutionError> {
        if self.0[2] != 0 {
            return Err(ExecutionError::ArithmeticOverflow("carry does not fit u64"));
        }
        Ok(self.0[1])
    }

    fn is_zero(self) -> bool {
        self.0 == [0; 3]
    }
}

fn rwc_delta_execution(
    step: &LogicalCpuStep,
    flags: &ExecutionOpcodeFlags,
) -> Result<u64, ExecutionError> {
    Ok(if flags.isbegintx {
        12
    } else if flags.iscall {
        24
    } else if flags.returndatacopy {
        let len_c = word_to_u64(step.rlc_c, "rlc_c length")?;
        5 + 2 * len_c
    } else if flags.calldatacopy {
        let len_c = word_to_u64(step.rlc_c, "rlc_c length")?;
        let isroot = word_to_u64(step.rlc_g, "rlc_g isroot")?;
        7 + len_c * (2 - isroot)
    } else if flags.isreturn {
        let ret_g = word_to_u64(step.rlc_g, "rlc_g return length")?;
        let ret_i = word_to_u64(step.rlc_i, "rlc_i return length")?;
        let ret_j = word_to_u64(step.rlc_j, "rlc_j selector")?;
        let chosen_return_len = if ret_j == 1 { ret_g } else { ret_i };
        14 + 2 * chosen_return_len
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
    })
}

fn word_to_u64(word: [u64; 4], name: &'static str) -> Result<u64, ExecutionError> {
    if word[1] != 0 || word[2] != 0 || word[3] != 0 {
        return Err(ExecutionError::NarrowValueRequired(name));
    }
    Ok(word[0])
}

fn field_inverse_u64(value: u64) -> Fp {
    Fp::from(value).invert().unwrap_or(Fp::ZERO)
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

fn write_rev_u64(slice: &mut [u8], value: u64) {
    for (idx, byte) in value.to_le_bytes().iter().enumerate() {
        slice[7 - idx] = *byte;
    }
}

fn resolve_actual_call_id(
    logical_to_actual: &BTreeMap<u64, u64>,
    logical_call_id: u64,
) -> Result<u64, ExecutionError> {
    logical_to_actual
        .get(&logical_call_id)
        .copied()
        .ok_or(ExecutionError::UnknownCallIdMapping(logical_call_id))
}

fn word_from_u64(value: u64) -> [u64; 4] {
    [value, 0, 0, 0]
}

fn compute_addr_a_execution(sp: u64, flags: &ExecutionOpcodeFlags) -> u64 {
    if flags.iswrite {
        sp
    } else if flags.isreturn {
        1
    } else {
        sp.saturating_sub(1)
    }
}

fn choose_return_copy_len(step: &LogicalCpuStep) -> Result<u64, ExecutionError> {
    let requested = word_to_u64(step.rlc_g, "return requested length")?;
    let actual = word_to_u64(step.rlc_i, "return actual length")?;
    let selector = word_to_u64(step.rlc_j, "return selector")?;
    Ok(if selector == 1 { requested } else { actual })
}

fn stack_rw(
    logical_call_id: u64,
    address: u64,
    rw_counter: u64,
    iswrite: bool,
    value: [u64; 4],
) -> LogicalRwRow {
    LogicalRwRow {
        tag: 2,
        logical_call_id,
        address,
        field_tag: 0,
        storage_key: 0,
        rw_counter,
        iswrite,
        value,
    }
}

fn ctx_rw(
    logical_call_id: u64,
    field_tag: u64,
    rw_counter: u64,
    iswrite: bool,
    value: [u64; 4],
) -> LogicalRwRow {
    LogicalRwRow {
        tag: 5,
        logical_call_id,
        address: 0,
        field_tag,
        storage_key: 0,
        rw_counter,
        iswrite,
        value,
    }
}

fn copy_distance_limbs(address_end: u64, address_read: u64, ispad: bool) -> (u64, u64) {
    let distance = if ispad {
        address_read.saturating_sub(address_end)
    } else {
        address_end.saturating_sub(address_read).saturating_sub(1)
    };
    (distance & 0xffff, (distance >> 16) & 0xffff)
}

type ExecutionOpcodeFlags = CircuitOpcodeFlags;

#[cfg(test)]
mod tests {
    use super::*;

    const ROOT_IMAGE_ID: u64 = 100;
    const CHILD_IMAGE_ID: u64 = 200;
    const DIRECT_CHILD_IMAGE_ID: u64 = CHILD_CALLEE_ADDRESS[0];
    const CHILD_CALLEE_ADDRESS: [u64; 4] = [0xdead_beef, 0, 0, 0];
    const CUSTOM_CHILD_ADDRESS: [u64; 4] = [0xabcdef, 0, 0, 0];
    const ROOT_CALLER_ADDRESS: [u64; 4] = [0x1111, 0, 0, 0];
    const ROOT_CALLEE_ADDRESS: [u64; 4] = [0x2222, 0, 0, 0];

    #[test]
    fn compact_bytecode_value_expands_to_little_endian_limbs() {
        let rows = expand_compact_logical_rows(vec![
            CompactLogicalByteTableRow {
                logical_call_id: 0,
                value: (OP_WRITE as u8).to_string(),
            },
            CompactLogicalByteTableRow {
                logical_call_id: 0,
                value: "0x0123456789abcdef112233445566778899aabbccddeeff001122334455667788"
                    .to_string(),
            },
        ])
        .expect("compact value should parse");

        assert_eq!(rows[0].pc, 0);
        assert_eq!(rows[1].pc, 1);
        assert!(rows[0].iscode);
        assert!(!rows[1].iscode);
        assert_eq!(
            (rows[1].limb1, rows[1].limb2, rows[1].limb3, rows[1].limb4),
            (
                0x1122_3344_5566_7788,
                0x99aa_bbcc_ddee_ff00,
                0x1122_3344_5566_7788,
                0x0123_4567_89ab_cdef
            )
        );
    }

    #[test]
    fn overflowing_mul_lowers_modulo_2_256() {
        let operation = ExecutionArithmeticOp {
            source_step: 0,
            op: ArithmeticOpKind::Mul,
            lhs: [0, 0, 0, 1u64 << 63],
            rhs: [2, 0, 0, 0],
            result: [0; 4],
        };

        let chunk = lower_mul_chunk(&operation)
            .expect("the high half of an EVM multiplication must be discarded");

        assert_eq!(chunk.op, ArithmeticOpKind::Mul);
        assert!(chunk.rows.iter().all(|row| row.limb_c == 0));
        assert_eq!(chunk.rows[3].carry, Fp::ONE);
    }

    #[test]
    fn compact_tx_values_split_into_128_bit_halves_and_indexes() {
        let rows = expand_compact_tx_rows(vec![
            CompactLogicalTxRow {
                tag: TX_TAG_CALLER_ADDRESS,
                value: "0x100000000000000000000000000000001".to_string(),
            },
            CompactLogicalTxRow {
                tag: TX_TAG_CALLDATA_BYTE,
                value: "0xaa".to_string(),
            },
            CompactLogicalTxRow {
                tag: TX_TAG_CALLDATA_BYTE,
                value: "0xbb".to_string(),
            },
            CompactLogicalTxRow {
                tag: TX_TAG_CALLDATA_LENGTH,
                value: "2".to_string(),
            },
        ])
        .expect("compact TX values should parse");

        assert_eq!(rows[0].active, true);
        assert_eq!(rows[0].txid, 1);
        assert_eq!(rows[0].index, 0);
        assert_eq!(rows[0].value_low, 1);
        assert_eq!(rows[0].value_high, 1);
        assert_eq!((rows[1].tag, rows[1].index), (TX_TAG_CALLDATA_BYTE, 0));
        assert_eq!((rows[2].tag, rows[2].index), (TX_TAG_CALLDATA_BYTE, 1));
        assert_eq!(rows[3].index, 0);
    }

    #[test]
    fn concrete_public_tables_call_return_roundtrip_lowers_witness() {
        let tables = concrete_scenario_tables();

        let bundle = generate_witness_from_tables(tables)
            .expect("concrete scenario should generate witness");

        assert_eq!(bundle.execution_trace.cpu_steps.len(), 16);
        assert_eq!(bundle.generated_witness.call_id_map(), &[(0, 1), (1, 18)],);
        assert_eq!(bundle.logical_witness_input.copy_rows.len(), 3);
        assert_eq!(bundle.logical_witness_input.cpu_steps.len(), 16);

        let final_frames = &bundle.execution_trace.final_frames;
        assert_eq!(final_frames.len(), 1);
        let root = &final_frames[0];
        assert_eq!(root.logical_call_id, 0);
        assert_eq!(root.image_id, ROOT_IMAGE_ID);
        assert_eq!(root.parent_logical_call_id, None);
        assert_eq!(root.live_pc, 15);
        assert_eq!(root.live_sp, 1);
        assert_eq!(root.live_mmax, 1);
        assert_eq!(root.stack[0], (0, [1, 0, 0, 0]));
        assert_eq!(root.stack.len(), 6);
        assert_eq!(root.memory, vec![(0, 42)]);

        let copy_rows = &bundle.logical_witness_input.copy_rows;
        assert_eq!(copy_rows[0].value, 42);
        assert_eq!(copy_rows[0].logical_call_id_read, 1);
        assert_eq!(copy_rows[0].logical_call_id_write, 0);
        assert_eq!(copy_rows[0].address_read, 0);
        assert_eq!(copy_rows[0].address_write, 0);
        assert_eq!(copy_rows[0].address_end, 1);
        assert!(!copy_rows[0].iswrite);
        assert_eq!(copy_rows[1].address_end, 1);
        assert!(copy_rows[1].iswrite);
        assert!(!copy_rows[2].switch);

        let rw_rows = &bundle.logical_witness_input.rw_rows;
        assert!(rw_rows.iter().any(|row| {
            row.tag == 5
                && row.logical_call_id == 0
                && row.field_tag == CC_TAG_PC
                && row.rw_counter == 36
                && row.iswrite
                && row.value == word_from_u64(13)
        }));
        assert!(rw_rows.iter().any(|row| {
            row.tag == 5
                && row.logical_call_id == 0
                && row.field_tag == CC_TAG_SP
                && row.rw_counter == 37
                && row.iswrite
                && row.value == word_from_u64(6)
        }));
        assert!(rw_rows.iter().any(|row| {
            row.tag == 5
                && row.logical_call_id == 0
                && row.field_tag == CC_TAG_MMAX
                && row.rw_counter == 38
                && row.iswrite
                && row.value == word_from_u64(0)
        }));
    }

    #[test]
    fn concrete_public_tables_call_resolves_direct_image_id_without_deployments() {
        let tables = direct_address_scenario_tables();

        let bundle = generate_witness_from_tables(tables)
            .expect("direct image-id call target should resolve without deployments");

        assert_eq!(bundle.execution_trace.cpu_steps.len(), 16);
        assert_eq!(bundle.generated_witness.call_id_map(), &[(0, 1), (1, 18)]);
        let root = &bundle.execution_trace.final_frames[0];
        assert_eq!(root.memory, vec![(0, 42)]);
    }

    #[test]
    fn concrete_public_tables_call_resolves_custom_deployment_address() {
        let tables = custom_deployment_scenario_tables();

        let bundle = generate_witness_from_tables(tables)
            .expect("custom deployment address should resolve through deployment rows");

        assert_eq!(bundle.execution_trace.cpu_steps.len(), 16);
        let root = &bundle.execution_trace.final_frames[0];
        assert_eq!(root.memory, vec![(0, 42)]);
    }

    #[test]
    fn logical_public_tables_route_calls_by_execution_order() {
        let tables = logical_scenario_tables();

        let bundle = generate_witness_from_tables(tables)
            .expect("logical bytecode rows should route by CALL order");

        assert_eq!(bundle.execution_trace.cpu_steps.len(), 16);
        assert_eq!(bundle.generated_witness.call_id_map(), &[(0, 1), (1, 18)]);
        let root = &bundle.execution_trace.final_frames[0];
        assert_eq!(root.logical_call_id, 0);
        assert_eq!(root.image_id, 0);
        assert_eq!(root.memory, vec![(0, 42)]);
    }

    #[test]
    fn logical_public_tables_reject_non_contiguous_call_ids() {
        let mut tables = logical_scenario_tables();
        for row in &mut tables.bytecode_rows {
            if row.logical_call_id == 1 {
                row.logical_call_id = 2;
            }
        }

        let err = generate_witness_from_tables(tables)
            .expect_err("logical call ids must be contiguous from 0");
        match err {
            ExecutionPipelineError::Execution(ExecutionError::NonContiguousLogicalCallIds {
                expected: 1,
                found: 2,
            }) => {}
            other => panic!("unexpected pipeline error: {other}"),
        }
    }

    #[test]
    fn generated_witness_binary_roundtrips() {
        let bundle = generate_witness_from_tables(logical_scenario_tables())
            .expect("logical scenario should generate a witness");
        let path = std::env::temp_dir().join(format!(
            "portvm-witness-roundtrip-{}.bin",
            std::process::id()
        ));

        bundle
            .generated_witness
            .write_to_file(&path)
            .expect("witness should serialize");
        let loaded = GeneratedWitness::read_from_file(&path).expect("witness should deserialize");
        std::fs::remove_file(&path).expect("temporary witness should be removable");

        assert_eq!(
            loaded.public_inputs(),
            bundle.generated_witness.public_inputs()
        );
        assert_eq!(loaded.call_id_map(), bundle.generated_witness.call_id_map());
        assert_eq!(
            loaded.logical_cpu_rows,
            bundle.generated_witness.logical_cpu_rows
        );
        assert_eq!(
            loaded.logical_alu_rows,
            bundle.generated_witness.logical_alu_rows
        );
        assert_eq!(
            loaded.logical_copy_rows,
            bundle.generated_witness.logical_copy_rows
        );
        assert_eq!(
            loaded.logical_rw_rows,
            bundle.generated_witness.logical_rw_rows
        );
    }

    #[test]
    #[ignore = "Known live circuit issues in region padding/ROM assignment/call RW lookups still block MockProver"]
    fn concrete_public_tables_call_return_roundtrip_reproduces_mock_prover_failure() {
        let err = mock_prove_from_tables(17, concrete_scenario_tables())
            .expect_err("scenario currently should fail inside MockProver");
        match err {
            ExecutionPipelineError::WitnessGeneration(
                WitnessGenerationError::ConstraintViolation(message),
            ) => {
                assert!(!message.is_empty());
            }
            other => panic!("unexpected pipeline error: {other}"),
        }
    }

    #[test]
    #[ignore = "debug helper for inspecting live MockProver failures"]
    fn debug_print_concrete_mock_prover_failure() {
        let err = mock_prove_from_tables(17, concrete_scenario_tables())
            .expect_err("scenario currently should fail inside MockProver");
        eprintln!("{err}");
        panic!("debug printed concrete MockProver failure");
    }

    #[test]
    #[ignore = "debug helper for inspecting generated rw rows"]
    fn debug_print_concrete_rw_rows() {
        let bundle = generate_witness_from_tables(concrete_scenario_tables())
            .expect("concrete scenario should generate witness");
        for line in bundle.generated_witness.debug_rwtrace_rows(0, 80) {
            eprintln!("rwtrace {line}");
        }
        for line in bundle.generated_witness.debug_rwstate_rows(20, 40) {
            eprintln!("rwstate {line}");
        }
        panic!("debug printed concrete rw rows");
    }

    fn concrete_scenario_tables() -> ExecutionPublicTables {
        ExecutionPublicTables {
            root_image_id: ROOT_IMAGE_ID,
            bytecode_rows: Vec::new(),
            compact_bytecode_rows: Vec::new(),
            bytecode_image_rows: concrete_scenario_bytecode_rows(),
            compact_bytecode_image_rows: Vec::new(),
            deployment_rows: vec![ExecutionDeploymentRow {
                callee_address: CHILD_CALLEE_ADDRESS,
                image_id: CHILD_IMAGE_ID,
            }],
            tx_rows: concrete_scenario_tx_rows(),
            compact_tx_rows: Vec::new(),
        }
    }

    fn logical_scenario_tables() -> ExecutionPublicTables {
        ExecutionPublicTables {
            root_image_id: 0,
            bytecode_rows: concrete_scenario_logical_bytecode_rows(),
            compact_bytecode_rows: Vec::new(),
            bytecode_image_rows: Vec::new(),
            compact_bytecode_image_rows: Vec::new(),
            deployment_rows: Vec::new(),
            tx_rows: concrete_scenario_tx_rows(),
            compact_tx_rows: Vec::new(),
        }
    }

    fn concrete_scenario_tx_rows() -> Vec<LogicalTxRow> {
        vec![
            tx_row(
                TX_TAG_CALLER_ADDRESS,
                0,
                ROOT_CALLER_ADDRESS[0],
                ROOT_CALLER_ADDRESS[1],
            ),
            tx_row(
                TX_TAG_CALLEE_ADDRESS,
                0,
                ROOT_CALLEE_ADDRESS[0],
                ROOT_CALLEE_ADDRESS[1],
            ),
            tx_row(TX_TAG_VALUE, 0, 0, 0),
            tx_row(TX_TAG_CALLDATA_LENGTH, 0, 0, 0),
        ]
    }

    fn direct_address_scenario_tables() -> ExecutionPublicTables {
        ExecutionPublicTables {
            root_image_id: ROOT_IMAGE_ID,
            bytecode_rows: Vec::new(),
            compact_bytecode_rows: Vec::new(),
            bytecode_image_rows: direct_address_scenario_bytecode_rows(),
            compact_bytecode_image_rows: Vec::new(),
            deployment_rows: vec![],
            tx_rows: concrete_scenario_tx_rows(),
            compact_tx_rows: Vec::new(),
        }
    }

    fn custom_deployment_scenario_tables() -> ExecutionPublicTables {
        ExecutionPublicTables {
            root_image_id: ROOT_IMAGE_ID,
            bytecode_rows: Vec::new(),
            compact_bytecode_rows: Vec::new(),
            bytecode_image_rows: custom_deployment_scenario_bytecode_rows(),
            compact_bytecode_image_rows: Vec::new(),
            deployment_rows: vec![ExecutionDeploymentRow {
                callee_address: CUSTOM_CHILD_ADDRESS,
                image_id: CHILD_IMAGE_ID,
            }],
            tx_rows: concrete_scenario_tx_rows(),
            compact_tx_rows: Vec::new(),
        }
    }

    fn concrete_scenario_bytecode_rows() -> Vec<ExecutionBytecodeRow> {
        vec![
            code_row(ROOT_IMAGE_ID, 0, OP_BEGIN_TX as u8),
            code_row(ROOT_IMAGE_ID, 1, OP_WRITE as u8),
            imm_row(ROOT_IMAGE_ID, 2, 0),
            code_row(ROOT_IMAGE_ID, 3, OP_WRITE as u8),
            imm_row(ROOT_IMAGE_ID, 4, 0),
            code_row(ROOT_IMAGE_ID, 5, OP_WRITE as u8),
            imm_row(ROOT_IMAGE_ID, 6, CHILD_CALLEE_ADDRESS[0]),
            code_row(ROOT_IMAGE_ID, 7, OP_WRITE as u8),
            imm_row(ROOT_IMAGE_ID, 8, 1),
            code_row(ROOT_IMAGE_ID, 9, OP_WRITE as u8),
            imm_row(ROOT_IMAGE_ID, 10, 0),
            code_row(ROOT_IMAGE_ID, 11, OP_WRITE as u8),
            imm_row(ROOT_IMAGE_ID, 12, 0),
            code_row(ROOT_IMAGE_ID, 13, 0xf1),
            code_row(ROOT_IMAGE_ID, 14, OP_END_TX as u8),
            code_row(ROOT_IMAGE_ID, 15, OP_HALT as u8),
            code_row(CHILD_IMAGE_ID, 0, OP_WRITE as u8),
            imm_row(CHILD_IMAGE_ID, 1, 42),
            code_row(CHILD_IMAGE_ID, 2, OP_WRITE as u8),
            imm_row(CHILD_IMAGE_ID, 3, 0),
            code_row(CHILD_IMAGE_ID, 4, 0x53),
            code_row(CHILD_IMAGE_ID, 5, OP_WRITE as u8),
            imm_row(CHILD_IMAGE_ID, 6, 1),
            code_row(CHILD_IMAGE_ID, 7, OP_WRITE as u8),
            imm_row(CHILD_IMAGE_ID, 8, 0),
            code_row(CHILD_IMAGE_ID, 9, 0xf3),
        ]
    }

    fn direct_address_scenario_bytecode_rows() -> Vec<ExecutionBytecodeRow> {
        vec![
            code_row(ROOT_IMAGE_ID, 0, OP_BEGIN_TX as u8),
            code_row(ROOT_IMAGE_ID, 1, OP_WRITE as u8),
            imm_row(ROOT_IMAGE_ID, 2, 0),
            code_row(ROOT_IMAGE_ID, 3, OP_WRITE as u8),
            imm_row(ROOT_IMAGE_ID, 4, 0),
            code_row(ROOT_IMAGE_ID, 5, OP_WRITE as u8),
            imm_row(ROOT_IMAGE_ID, 6, DIRECT_CHILD_IMAGE_ID),
            code_row(ROOT_IMAGE_ID, 7, OP_WRITE as u8),
            imm_row(ROOT_IMAGE_ID, 8, 1),
            code_row(ROOT_IMAGE_ID, 9, OP_WRITE as u8),
            imm_row(ROOT_IMAGE_ID, 10, 0),
            code_row(ROOT_IMAGE_ID, 11, OP_WRITE as u8),
            imm_row(ROOT_IMAGE_ID, 12, 0),
            code_row(ROOT_IMAGE_ID, 13, 0xf1),
            code_row(ROOT_IMAGE_ID, 14, OP_END_TX as u8),
            code_row(ROOT_IMAGE_ID, 15, OP_HALT as u8),
            code_row(DIRECT_CHILD_IMAGE_ID, 0, OP_WRITE as u8),
            imm_row(DIRECT_CHILD_IMAGE_ID, 1, 42),
            code_row(DIRECT_CHILD_IMAGE_ID, 2, OP_WRITE as u8),
            imm_row(DIRECT_CHILD_IMAGE_ID, 3, 0),
            code_row(DIRECT_CHILD_IMAGE_ID, 4, 0x53),
            code_row(DIRECT_CHILD_IMAGE_ID, 5, OP_WRITE as u8),
            imm_row(DIRECT_CHILD_IMAGE_ID, 6, 1),
            code_row(DIRECT_CHILD_IMAGE_ID, 7, OP_WRITE as u8),
            imm_row(DIRECT_CHILD_IMAGE_ID, 8, 0),
            code_row(DIRECT_CHILD_IMAGE_ID, 9, 0xf3),
        ]
    }

    fn custom_deployment_scenario_bytecode_rows() -> Vec<ExecutionBytecodeRow> {
        vec![
            code_row(ROOT_IMAGE_ID, 0, OP_BEGIN_TX as u8),
            code_row(ROOT_IMAGE_ID, 1, OP_WRITE as u8),
            imm_row(ROOT_IMAGE_ID, 2, 0),
            code_row(ROOT_IMAGE_ID, 3, OP_WRITE as u8),
            imm_row(ROOT_IMAGE_ID, 4, 0),
            code_row(ROOT_IMAGE_ID, 5, OP_WRITE as u8),
            imm_row(ROOT_IMAGE_ID, 6, CUSTOM_CHILD_ADDRESS[0]),
            code_row(ROOT_IMAGE_ID, 7, OP_WRITE as u8),
            imm_row(ROOT_IMAGE_ID, 8, 1),
            code_row(ROOT_IMAGE_ID, 9, OP_WRITE as u8),
            imm_row(ROOT_IMAGE_ID, 10, 0),
            code_row(ROOT_IMAGE_ID, 11, OP_WRITE as u8),
            imm_row(ROOT_IMAGE_ID, 12, 0),
            code_row(ROOT_IMAGE_ID, 13, 0xf1),
            code_row(ROOT_IMAGE_ID, 14, OP_END_TX as u8),
            code_row(ROOT_IMAGE_ID, 15, OP_HALT as u8),
            code_row(CHILD_IMAGE_ID, 0, OP_WRITE as u8),
            imm_row(CHILD_IMAGE_ID, 1, 42),
            code_row(CHILD_IMAGE_ID, 2, OP_WRITE as u8),
            imm_row(CHILD_IMAGE_ID, 3, 0),
            code_row(CHILD_IMAGE_ID, 4, 0x53),
            code_row(CHILD_IMAGE_ID, 5, OP_WRITE as u8),
            imm_row(CHILD_IMAGE_ID, 6, 1),
            code_row(CHILD_IMAGE_ID, 7, OP_WRITE as u8),
            imm_row(CHILD_IMAGE_ID, 8, 0),
            code_row(CHILD_IMAGE_ID, 9, 0xf3),
        ]
    }

    fn concrete_scenario_logical_bytecode_rows() -> Vec<LogicalByteTableRow> {
        vec![
            logical_code_row(0, 0, OP_BEGIN_TX as u8),
            logical_code_row(0, 1, OP_WRITE as u8),
            logical_imm_row(0, 2, 0),
            logical_code_row(0, 3, OP_WRITE as u8),
            logical_imm_row(0, 4, 0),
            logical_code_row(0, 5, OP_WRITE as u8),
            logical_imm_row(0, 6, CHILD_CALLEE_ADDRESS[0]),
            logical_code_row(0, 7, OP_WRITE as u8),
            logical_imm_row(0, 8, 1),
            logical_code_row(0, 9, OP_WRITE as u8),
            logical_imm_row(0, 10, 0),
            logical_code_row(0, 11, OP_WRITE as u8),
            logical_imm_row(0, 12, 0),
            logical_code_row(0, 13, 0xf1),
            logical_code_row(0, 14, OP_END_TX as u8),
            logical_code_row(0, 15, OP_HALT as u8),
            logical_code_row(1, 0, OP_WRITE as u8),
            logical_imm_row(1, 1, 42),
            logical_code_row(1, 2, OP_WRITE as u8),
            logical_imm_row(1, 3, 0),
            logical_code_row(1, 4, 0x53),
            logical_code_row(1, 5, OP_WRITE as u8),
            logical_imm_row(1, 6, 1),
            logical_code_row(1, 7, OP_WRITE as u8),
            logical_imm_row(1, 8, 0),
            logical_code_row(1, 9, 0xf3),
        ]
    }

    fn tx_row(tag: u64, index: u64, value_low: u64, value_high: u64) -> LogicalTxRow {
        LogicalTxRow {
            active: true,
            txid: 0,
            tag,
            index,
            value_low: u128::from(value_low),
            value_high: u128::from(value_high),
        }
    }

    fn code_row(image_id: u64, pc: u64, opcode: u8) -> ExecutionBytecodeRow {
        ExecutionBytecodeRow {
            image_id,
            pc,
            limb1: opcode as u64,
            limb2: 0,
            limb3: 0,
            limb4: 0,
            iscode: true,
        }
    }

    fn imm_row(image_id: u64, pc: u64, value: u64) -> ExecutionBytecodeRow {
        ExecutionBytecodeRow {
            image_id,
            pc,
            limb1: value,
            limb2: 0,
            limb3: 0,
            limb4: 0,
            iscode: false,
        }
    }

    fn logical_code_row(logical_call_id: u64, pc: u64, opcode: u8) -> LogicalByteTableRow {
        LogicalByteTableRow {
            logical_call_id,
            pc,
            limb1: opcode as u64,
            limb2: 0,
            limb3: 0,
            limb4: 0,
            iscode: true,
        }
    }

    fn logical_imm_row(logical_call_id: u64, pc: u64, value: u64) -> LogicalByteTableRow {
        LogicalByteTableRow {
            logical_call_id,
            pc,
            limb1: value,
            limb2: 0,
            limb3: 0,
            limb4: 0,
            iscode: false,
        }
    }
}
