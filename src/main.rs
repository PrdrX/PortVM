use ff::PrimeField;
use halo2_proofs::arithmetic::Field;
use halo2_proofs::circuit::Cell;
use halo2_proofs::circuit::Value;
use halo2_proofs::circuit::{AssignedCell, Region};
use halo2_proofs::plonk::Fixed;
use halo2_proofs::plonk::VirtualCells;
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner},
    dev::MockProver,
    halo2curves::bn256::{Bn256, Fr as Fp, G1Affine},
    plonk::{
        create_proof, keygen_pk, keygen_vk, verify_proof, Advice, Challenge, Circuit, Column,
        ConstraintSystem, Error, Expression, FirstPhase, Instance, ProvingKey, SecondPhase,
        Selector, TableColumn, VerifyingKey,
    },
    poly::commitment::Params,
    poly::kzg::commitment::ParamsKZG,
    poly::kzg::{
        commitment::KZGCommitmentScheme,
        multiopen::{ProverSHPLONK, VerifierSHPLONK},
        strategy::SingleStrategy,
    },
    poly::Rotation,
    transcript::{
        Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
    },
    SerdeFormat,
};
use rand::rngs::OsRng;
use std::cell::RefCell;
use std::fs::File;
use std::io::{BufReader, BufWriter, Write};
use std::marker::PhantomData;
use std::path::Path;

#[path = "witness_generation.rs"]
mod witness_generation;
pub use witness_generation::*;

#[path = "execution_core.rs"]
mod execution_core;
pub use execution_core::*;

const MAX_CPU_ROWS: usize = 1024;
const MAX_RW_ROWS: usize = 2048;
const MAX_RW_STATE_ROWS: usize = 2048;
const MAX_ALU_ROWS: usize = 4096;
const MAX_COPY_ROWS: usize = 2048;
const MAX_TX_ROWS: usize = 256;
const MAX_BYTECODE_ROWS: usize = 4096;
const MAX_PUBLIC_OUTPUT_ROWS: usize = 50_000;

const OP_BEGIN_TX: u64 = 0x00;
const OP_END_TX: u64 = 0xfe;
const OP_HALT: u64 = 0xff;
const OP_READ: u64 = 0x54;
const OP_WRITE: u64 = 0x55;

#[derive(Debug, Clone, Copy, Default)]
struct CircuitOpcodeFlags {
    isbegintx: bool,
    isendtx: bool,
    iscall: bool,
    isreturn: bool,
    returndatacopy: bool,
    calldatacopy: bool,
    isadd: bool,
    issub: bool,
    ismul: bool,
    isdiv: bool,
    islt: bool,
    iseq: bool,
    isand: bool,
    isor: bool,
    isxor: bool,
    isnot: bool,
    isjump: bool,
    isjumpdest: bool,
    isjumpcon: bool,
    ismload: bool,
    ismstore: bool,
    ismstore8: bool,
    isread: bool,
    iswrite: bool,
    ishalt: bool,
}

impl CircuitOpcodeFlags {
    fn is_arithmetic(self) -> bool {
        self.isadd
            || self.issub
            || self.ismul
            || self.isdiv
            || self.islt
            || self.iseq
            || self.isand
            || self.isor
            || self.isxor
            || self.isnot
    }
}

fn decode_circuit_opcode(opcode: u64) -> Option<CircuitOpcodeFlags> {
    let mut flags = CircuitOpcodeFlags::default();
    match opcode {
        OP_BEGIN_TX => flags.isbegintx = true,
        OP_END_TX => flags.isendtx = true,
        0xf1 => flags.iscall = true,
        0xf3 => flags.isreturn = true,
        0x3e => flags.returndatacopy = true,
        0x37 => flags.calldatacopy = true,
        0x01 => flags.isadd = true,
        0x03 => flags.issub = true,
        0x02 => flags.ismul = true,
        0x04 => flags.isdiv = true,
        0x10 => flags.islt = true,
        0x14 => flags.iseq = true,
        0x16 => flags.isand = true,
        0x17 => flags.isor = true,
        0x18 => flags.isxor = true,
        0x19 => flags.isnot = true,
        0x56 => flags.isjump = true,
        0x5b => flags.isjumpdest = true,
        0x57 => flags.isjumpcon = true,
        0x51 => flags.ismload = true,
        0x52 => flags.ismstore = true,
        0x53 => flags.ismstore8 = true,
        OP_READ => flags.isread = true,
        OP_WRITE => flags.iswrite = true,
        OP_HALT => flags.ishalt = true,
        _ => return None,
    }
    Some(flags)
}

#[derive(Debug, Clone)]

struct CPU_values<F: PrimeField> {
    pub call_id: F,
    pub clk: F,
    pub rw_counter: F,
    pub pc: F,
    pub opcode: F,
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
    pub memaddr: F,
    pub inv: F,
    pub mmax: F,
    pub ismaxchanged: F,
    pub isbegintx: F,
    pub isendtx: F,
    pub iscall: F,
    pub isreturn: F,
    pub returndatacopy: F,
    pub calldatacopy: F,
    pub isadd: F,
    pub issub: F,
    pub ismul: F,
    pub isdiv: F,
    pub islt: F,
    pub iseq: F,
    pub isand: F,
    pub isor: F,
    pub isxor: F,
    pub isnot: F,
    pub isjump: F,
    pub isjumpdest: F,
    pub isjumpcon: F,
    pub ismload: F,
    pub ismstore: F,
    pub ismstore8: F,
    pub isread: F,
    pub iswrite: F,
    pub ishalt: F,
    pub rlc_addr_a: F,
    pub rlc_addr_b: F,
    pub sp: F,
}

impl<F: PrimeField> CPU_values<F> {
    fn without_values(&self) -> Self {
        Self {
            call_id: F::ZERO,
            clk: F::ZERO,
            rw_counter: F::ZERO,
            pc: F::ZERO,
            opcode: F::ZERO,

            rlc_a: [0u64; 4],
            rlc_b: [0u64; 4],
            rlc_c: [0u64; 4],
            rlc_d: [0u64; 4],
            rlc_e: [0u64; 4],
            rlc_f: [0u64; 4],
            rlc_g: [0u64; 4],
            rlc_h: [0u64; 4],
            rlc_i: [0u64; 4],
            rlc_j: [0u64; 4],

            memaddr: F::ZERO,
            inv: F::ZERO,
            mmax: F::ZERO,
            ismaxchanged: F::ZERO,
            isbegintx: F::ZERO,
            isendtx: F::ZERO,
            iscall: F::ZERO,
            isreturn: F::ZERO,
            returndatacopy: F::ZERO,
            calldatacopy: F::ZERO,
            isadd: F::ZERO,
            issub: F::ZERO,
            ismul: F::ZERO,
            isdiv: F::ZERO,
            islt: F::ZERO,
            iseq: F::ZERO,
            isand: F::ZERO,
            isor: F::ZERO,
            isxor: F::ZERO,
            isnot: F::ZERO,
            isjump: F::ZERO,
            isjumpdest: F::ZERO,
            isjumpcon: F::ZERO,
            ismload: F::ZERO,
            ismstore: F::ZERO,
            ismstore8: F::ZERO,
            isread: F::ZERO,
            iswrite: F::ZERO,
            ishalt: F::ZERO,
            rlc_addr_a: F::ZERO,
            rlc_addr_b: F::ZERO,
            sp: F::ZERO,
        }
    }
}

#[derive(Debug, Clone)]
struct CPUTrace_Chip<F: PrimeField> {
    _ph: PhantomData<F>,
    isfirst: Selector,
    islast: Selector,
    selector: Selector,
    call_id: Column<Advice>,
    clk: Column<Advice>,
    rw_counter: Column<Advice>,
    pc: Column<Advice>,
    opcode: Column<Advice>,
    rlc_a: Column<Advice>,
    rlc_b: Column<Advice>,
    rlc_c: Column<Advice>,
    rlc_d: Column<Advice>,
    rlc_e: Column<Advice>,
    rlc_f: Column<Advice>,
    rlc_g: Column<Advice>,
    rlc_h: Column<Advice>,
    rlc_i: Column<Advice>,
    rlc_j: Column<Advice>,
    memaddr: Column<Advice>,
    inv: Column<Advice>,
    mmax: Column<Advice>,
    ismaxchanged: Column<Advice>,
    isbegintx: Column<Advice>,
    isendtx: Column<Advice>,
    iscall: Column<Advice>,
    isreturn: Column<Advice>,
    returndatacopy: Column<Advice>,
    calldatacopy: Column<Advice>,
    isadd: Column<Advice>,
    issub: Column<Advice>,
    ismul: Column<Advice>,
    isdiv: Column<Advice>,
    islt: Column<Advice>,
    iseq: Column<Advice>,
    isand: Column<Advice>,
    isor: Column<Advice>,
    isxor: Column<Advice>,
    isnot: Column<Advice>,
    isjump: Column<Advice>,
    isjumpdest: Column<Advice>,
    isjumpcon: Column<Advice>,
    ismload: Column<Advice>,
    ismstore: Column<Advice>,
    ismstore8: Column<Advice>,
    isread: Column<Advice>,
    iswrite: Column<Advice>,
    ishalt: Column<Advice>,
    rlc_addr_a: Column<Advice>,
    rlc_addr_b: Column<Advice>,
    sp: Column<Advice>,
}

impl<F: PrimeField> CPUTrace_Chip<F> {
    fn configure(
        meta: &mut ConstraintSystem<F>,
        isfirst: Selector,
        islast: Selector,
        selector: Selector,
        call_id: Column<Advice>,
        clk: Column<Advice>,
        rw_counter: Column<Advice>,
        pc: Column<Advice>,
        opcode: Column<Advice>,
        rlc_a: Column<Advice>,
        rlc_b: Column<Advice>,
        rlc_c: Column<Advice>,
        rlc_d: Column<Advice>,
        rlc_e: Column<Advice>,
        rlc_f: Column<Advice>,
        rlc_g: Column<Advice>,
        rlc_h: Column<Advice>,
        rlc_i: Column<Advice>,
        rlc_j: Column<Advice>,
        memaddr: Column<Advice>,
        inv: Column<Advice>,
        mmax: Column<Advice>,
        ismaxchanged: Column<Advice>,
        isbegintx: Column<Advice>,
        isendtx: Column<Advice>,
        iscall: Column<Advice>,
        isreturn: Column<Advice>,
        returndatacopy: Column<Advice>,
        calldatacopy: Column<Advice>,
        isadd: Column<Advice>,
        issub: Column<Advice>,
        ismul: Column<Advice>,
        isdiv: Column<Advice>,
        islt: Column<Advice>,
        iseq: Column<Advice>,
        isand: Column<Advice>,
        isor: Column<Advice>,
        isxor: Column<Advice>,
        isnot: Column<Advice>,
        isjump: Column<Advice>,
        isjumpdest: Column<Advice>,
        isjumpcon: Column<Advice>,
        ismload: Column<Advice>,
        ismstore: Column<Advice>,
        ismstore8: Column<Advice>,
        isread: Column<Advice>,
        iswrite: Column<Advice>,
        ishalt: Column<Advice>,
        rlc_addr_a: Column<Advice>,
        rlc_addr_b: Column<Advice>,
        sp: Column<Advice>,
    ) -> Self {
        meta.create_gate("cpu_gates", |meta| {
            let isfirst = meta.query_selector(isfirst);
            let islast = meta.query_selector(islast);
            let q = meta.query_selector(selector);
            let callid = meta.query_advice(call_id, Rotation::cur());
            let callid_next = meta.query_advice(call_id, Rotation::next());
            let clk_cur = meta.query_advice(clk, Rotation::cur());
            let clk_next = meta.query_advice(clk, Rotation::next());
            let rw_counter_cur = meta.query_advice(rw_counter, Rotation::cur());
            let rw_counter_next = meta.query_advice(rw_counter, Rotation::next());
            let pc_cur = meta.query_advice(pc, Rotation::cur());
            let pc_next = meta.query_advice(pc, Rotation::next());
            let _opcode = meta.query_advice(opcode, Rotation::cur());
            let rlc_a = meta.query_advice(rlc_a, Rotation::cur());
            let rlc_b = meta.query_advice(rlc_b, Rotation::cur());
            let rlc_c = meta.query_advice(rlc_c, Rotation::cur());
            let rlc_d = meta.query_advice(rlc_d, Rotation::cur());
            let rlc_e = meta.query_advice(rlc_e, Rotation::cur());
            let rlc_f = meta.query_advice(rlc_f, Rotation::cur());
            let rlc_g = meta.query_advice(rlc_g, Rotation::cur());
            let _rlc_h = meta.query_advice(rlc_h, Rotation::cur());
            let rlc_i = meta.query_advice(rlc_i, Rotation::cur());
            let rlc_j = meta.query_advice(rlc_j, Rotation::cur());
            let _addr = meta.query_advice(memaddr, Rotation::cur());
            let inv = meta.query_advice(inv, Rotation::cur());
            let mmax_cur = meta.query_advice(mmax, Rotation::cur());
            let mmax_next = meta.query_advice(mmax, Rotation::next());
            let ismaxchanged = meta.query_advice(ismaxchanged, Rotation::cur());
            let isbegintx = meta.query_advice(isbegintx, Rotation::cur());
            let isendtx = meta.query_advice(isendtx, Rotation::cur());
            let iscall = meta.query_advice(iscall, Rotation::cur());
            let isreturn = meta.query_advice(isreturn, Rotation::cur());
            let returndatacopy = meta.query_advice(returndatacopy, Rotation::cur());
            let calldatacopy = meta.query_advice(calldatacopy, Rotation::cur());
            let isadd = meta.query_advice(isadd, Rotation::cur());
            let issub = meta.query_advice(issub, Rotation::cur());
            let ismul = meta.query_advice(ismul, Rotation::cur());
            let isdiv = meta.query_advice(isdiv, Rotation::cur());
            let islt = meta.query_advice(islt, Rotation::cur());
            let iseq = meta.query_advice(iseq, Rotation::cur());
            let isand = meta.query_advice(isand, Rotation::cur());
            let isor = meta.query_advice(isor, Rotation::cur());
            let isxor = meta.query_advice(isxor, Rotation::cur());
            let isnot = meta.query_advice(isnot, Rotation::cur());
            let isjump = meta.query_advice(isjump, Rotation::cur());
            let isjumpdest_cur = meta.query_advice(isjumpdest, Rotation::cur());
            let isjumpdest_next = meta.query_advice(isjumpdest, Rotation::next());
            let isjumpcon = meta.query_advice(isjumpcon, Rotation::cur());
            let ismload = meta.query_advice(ismload, Rotation::cur());
            let ismstore = meta.query_advice(ismstore, Rotation::cur());
            let ismstore8 = meta.query_advice(ismstore8, Rotation::cur());
            let isread = meta.query_advice(isread, Rotation::cur());
            let iswrite = meta.query_advice(iswrite, Rotation::cur());
            let rlc_addr_a = meta.query_advice(rlc_addr_a, Rotation::cur());
            let rlc_addr_b = meta.query_advice(rlc_addr_b, Rotation::cur());
            let ishalt_cur = meta.query_advice(ishalt, Rotation::cur());
            let ishalt_next = meta.query_advice(ishalt, Rotation::next());
            let sp_cur = meta.query_advice(sp, Rotation::cur());
            let sp_next = meta.query_advice(sp, Rotation::next());

            let zero = Expression::Constant(F::ZERO);
            let one = Expression::Constant(F::ONE);
            let two = Expression::Constant(F::from(2u64));
            let three = Expression::Constant(F::from(3u64));
            let five = Expression::Constant(F::from(5u64));
            let _six = Expression::Constant(F::from(6u64));
            let seven = Expression::Constant(F::from(7u64));
            let twelve = Expression::Constant(F::from(12u64));
            let fourteen = Expression::Constant(F::from(14u64));
            let twenty_four = Expression::Constant(F::from(24u64));
            let thirty_one = Expression::Constant(F::from(31u64));
            let thirty_four = Expression::Constant(F::from(34u64));

            let callcontextop =
                isbegintx.clone() + iscall.clone() + isendtx.clone() + isreturn.clone();

            let opcode_sum = isadd.clone()
                + issub.clone()
                + ismul.clone()
                + isdiv.clone()
                + islt.clone()
                + iseq.clone()
                + isand.clone()
                + isor.clone()
                + isxor.clone();
            let increase_rwc_34 = ismstore.clone() + ismload.clone();

            let increase_rwc_3 = isadd.clone()
                + issub.clone()
                + ismul.clone()
                + isdiv.clone()
                + islt.clone()
                + iseq.clone()
                + isand.clone()
                + isor.clone()
                + isxor.clone()
                + ismstore8.clone();

            let increase_rwc_2 = isjumpcon.clone() + isnot.clone();
            let increase_rwc_1 = isread.clone() + isjump.clone() + iswrite.clone();
            let increase_rwc_0 = ishalt_cur.clone() + isjumpdest_cur.clone();
            let rwc_change = isbegintx.clone() * twelve.clone()
                + iscall.clone() * twenty_four.clone()
                + returndatacopy.clone() * (five.clone() + rlc_c.clone() * two.clone())
                + calldatacopy.clone()
                    * (seven.clone() + rlc_c.clone() * (two.clone() - rlc_g.clone()))
                + isreturn.clone()
                    * (fourteen.clone()
                        + (rlc_j.clone() * rlc_g.clone()
                            + (one.clone() - rlc_j.clone()) * rlc_i.clone())
                            * two.clone())
                + thirty_four.clone() * increase_rwc_34.clone()
                + three.clone() * increase_rwc_3.clone()
                + two.clone() * increase_rwc_2.clone()
                + one.clone() * increase_rwc_1.clone()
                + zero.clone() * increase_rwc_0.clone();
            let mmaxrlca = ismload.clone()
                + ismstore.clone()
                + ismstore8.clone()
                + returndatacopy.clone()
                + calldatacopy.clone();
            let mmax_opcodes = ismload.clone()
                + ismstore.clone()
                + ismstore8.clone()
                + returndatacopy.clone()
                + calldatacopy.clone()
                + isreturn.clone();
            vec![
                // isfirst\begintx
                q.clone() * isfirst.clone() * rw_counter_cur.clone(),
                q.clone() * (isfirst.clone() * sp_cur.clone()),
                q.clone() * (isfirst.clone() * pc_cur.clone()),
                q.clone() * (isfirst.clone() * clk_cur.clone()),
                q.clone() * isfirst.clone() * mmax_cur.clone(),
                q.clone() * isfirst.clone() * (one.clone() - isbegintx.clone()),
                q.clone() * (one.clone() - isfirst.clone()) * isbegintx.clone(),
                q.clone() * isbegintx.clone() * (callid.clone() - one.clone()),
                // iscall
                q.clone() * iscall.clone() * sp_next.clone(), //redundant
                q.clone() * iscall.clone() * pc_next.clone(), //redundant
                // general
                q.clone() * (clk_next.clone() - clk_cur.clone() - one.clone()),
                q.clone() * (rw_counter_next.clone() - rw_counter_cur.clone() - rwc_change.clone()),
                q.clone()
                    * (pc_next.clone()
                        - (one.clone() - isjump.clone() - isjumpcon.clone() - isreturn.clone())
                            * (pc_cur.clone() + one.clone() - ishalt_cur.clone()
                                + iswrite.clone())
                            * (one.clone() - iscall.clone())
                        - isjump.clone() * rlc_a.clone()
                        - isjumpcon.clone()
                            * (rlc_c.clone() * rlc_a.clone()
                                + (one.clone() - rlc_c.clone()) * (pc_cur.clone() + one.clone()))
                        - isreturn.clone() * (rlc_c.clone() + one.clone())),
                q.clone()
                    * (one.clone() - iswrite.clone() - isreturn.clone())
                    * (sp_cur.clone() - rlc_addr_a.clone() - one.clone()),
                q.clone() * (sp_cur.clone() - rlc_addr_b.clone() - two.clone()),
                q.clone() * (iswrite.clone() * (sp_cur.clone() - rlc_addr_a.clone())),
                q.clone()
                    * (sp_next.clone()
                        - (opcode_sum.clone() + isread.clone() + isjump.clone() + iscall.clone())
                            * (sp_cur.clone() - one.clone())
                            * (one.clone() - iscall.clone())
                        - iswrite.clone() * (sp_cur.clone() + one.clone())
                        - (ishalt_cur.clone()
                            + isjumpdest_cur.clone()
                            + ismload.clone()
                            + isnot.clone()
                            + isendtx.clone())
                            * (sp_cur.clone())
                        - ((isjumpcon.clone() + ismstore.clone() + ismstore8.clone())
                            * (sp_cur.clone() - two.clone()))
                        - isreturn.clone() * (rlc_d.clone() - five.clone())
                        - (returndatacopy.clone() + calldatacopy.clone())
                            * (sp_cur.clone() - three.clone())),
                // jumps
                q.clone()
                    * (isjump.clone() + isjumpcon.clone() * rlc_c.clone())
                    * (one.clone() - isjumpdest_next.clone()),
                q.clone() * isjumpcon.clone() * rlc_c.clone() * (one.clone() - rlc_c.clone()),
                q.clone()
                    * isjumpcon.clone()
                    * (rlc_c.clone() * (rlc_b.clone() * inv.clone() - one.clone())
                        + (one.clone() - rlc_c.clone()) * rlc_b.clone()),
                // mmax
                q.clone() * ismaxchanged.clone() * (one.clone() - ismaxchanged.clone()),
                q.clone() * ismaxchanged.clone() * (one.clone() - mmax_opcodes.clone()),
                q.clone()
                    * (mmax_next.clone()
                        - (one.clone() - ismaxchanged.clone())
                            * (one.clone() - iscall.clone() - isreturn.clone())
                            * mmax_cur.clone()
                        - ismaxchanged.clone()
                            * (rlc_a.clone() * mmaxrlca.clone()
                                + rlc_f.clone() * isreturn.clone()
                                + (ismstore.clone() + ismload.clone()) * thirty_one.clone()
                                + (returndatacopy.clone() + calldatacopy.clone())
                                    * (rlc_c.clone() - one.clone())
                                + isreturn.clone()
                                    * (rlc_j.clone() * rlc_g.clone()
                                        + (one.clone() - rlc_j.clone()) * rlc_i.clone()
                                        - one.clone())
                                + one.clone())
                        - (one.clone() - ismaxchanged.clone()) * isreturn.clone() * rlc_e.clone()),
                // callid
                q.clone()
                    * (one.clone() - callcontextop.clone())
                    * (callid_next.clone() - callid.clone()),
                q.clone() * isbegintx.clone() * (callid_next.clone() - callid.clone()),
                q.clone() * iscall.clone() * (callid_next.clone() - rw_counter_cur.clone()),
                q.clone() * isreturn.clone() * (callid_next.clone() - rlc_a.clone()),
                q.clone() * isendtx.clone() * (callid_next.clone()),
                // halt managment
                q.clone() * isendtx.clone() * (one.clone() - ishalt_next.clone()),
                q.clone() * ishalt_cur.clone() * (one.clone() - ishalt_next.clone()),
                
                q.clone() * isreturn.clone() * rlc_j.clone() * (one.clone() - rlc_j.clone()),
                q.clone()
                    * isreturn.clone()
                    * ((rlc_j.clone() * (rlc_i.clone() - rlc_g.clone())
                        + (one.clone() - rlc_j.clone()) * (rlc_g.clone() - rlc_i.clone()))
                        - inv.clone()),
                q.clone() * islast.clone() * (one.clone() - ishalt_cur.clone() - isendtx.clone()),
                q.clone()
                    * (one.clone() - isendtx.clone() - ishalt_cur.clone())
                    * (ishalt_next.clone()), // redundant
                q.clone() * isendtx.clone() * (one.clone() - callid.clone()),
                // Reject zero-length copies and selected return copies with inverse witnesses.
                q.clone()
                    * ((returndatacopy.clone() + calldatacopy.clone())
                        * (rlc_c.clone() * rlc_i.clone() - one.clone())),
                q.clone()
                    * isreturn.clone()
                    * ((rlc_j.clone() * rlc_g.clone()
                        + (one.clone() - rlc_j.clone()) * rlc_i.clone())
                        * rlc_addr_a.clone()
                        - one.clone()),
            ]
        });

        Self {
            _ph: PhantomData,
            isfirst,
            islast,
            selector,
            call_id,
            clk,
            rw_counter,
            pc,
            opcode,
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
            memaddr,
            inv,
            mmax,
            ismaxchanged,
            isbegintx,
            isendtx,
            iscall,
            isreturn,
            returndatacopy,
            calldatacopy,
            isadd,
            issub,
            ismul,
            isdiv,
            islt,
            iseq,
            isand,
            isor,
            isxor,
            isnot,
            isjump,
            isjumpdest,
            isjumpcon,
            ismload,
            ismstore,
            ismstore8,
            isread,
            iswrite,
            ishalt,
            rlc_addr_a,
            rlc_addr_b,
            sp,
        }
    }

    pub fn assign(
        &self,
        layouter: &mut impl Layouter<F>,
        trace: &[CPU_values<F>],
        challenge_r: Value<F>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "Assign CPU Execution Trace",
            |mut region| {
                for offset in 0..10000 {
                    if offset == 0 {
                        self.isfirst.enable(&mut region, offset)?;
                        self.selector.enable(&mut region, offset)?;
                    } else if offset < 9999 {
                        self.selector.enable(&mut region, offset)?;
                    } else {
                        self.selector.enable(&mut region, offset)?;
                        self.islast.enable(&mut region, offset)?;
                    }
                }
                for (offset, state) in trace.iter().enumerate() {
                    region.assign_advice(
                        || format!("call_id at row {}", offset),
                        self.call_id,
                        offset,
                        || Value::known(state.call_id),
                    )?;

                    region.assign_advice(
                        || format!("clk at row {}", offset),
                        self.clk,
                        offset,
                        || Value::known(state.clk),
                    )?;

                    region.assign_advice(
                        || format!("rw_counter at row {}", offset),
                        self.rw_counter,
                        offset,
                        || Value::known(state.rw_counter),
                    )?;

                    region.assign_advice(
                        || format!("pc at row {}", offset),
                        self.pc,
                        offset,
                        || Value::known(state.pc),
                    )?;

                    region.assign_advice(
                        || format!("opcode at row {}", offset),
                        self.opcode,
                        offset,
                        || Value::known(state.opcode),
                    )?;

                    let rlc_val_a = challenge_r.map(|r| {
                        let mut rlc = F::ZERO;
                        let mut r_power = F::ONE;
                        for byte in state.rlc_a.iter() {
                            rlc += F::from(*byte as u64) * r_power;
                            r_power *= r;
                        }
                        rlc
                    });

                    let rlc_val_b = challenge_r.map(|r| {
                        let mut rlc = F::ZERO;
                        let mut r_power = F::ONE;
                        for byte in state.rlc_b.iter() {
                            rlc += F::from(*byte as u64) * r_power;
                            r_power *= r;
                        }
                        rlc
                    });

                    let rlc_val_c = challenge_r.map(|r| {
                        let mut rlc = F::ZERO;
                        let mut r_power = F::ONE;
                        for byte in state.rlc_c.iter() {
                            rlc += F::from(*byte as u64) * r_power;
                            r_power *= r;
                        }
                        rlc
                    });

                    let rlc_val_d = challenge_r.map(|r| {
                        let mut rlc = F::ZERO;
                        let mut r_power = F::ONE;
                        for byte in state.rlc_d.iter() {
                            rlc += F::from(*byte as u64) * r_power;
                            r_power *= r;
                        }
                        rlc
                    });

                    let rlc_val_e = challenge_r.map(|r| {
                        let mut rlc = F::ZERO;
                        let mut r_power = F::ONE;
                        for byte in state.rlc_e.iter() {
                            rlc += F::from(*byte as u64) * r_power;
                            r_power *= r;
                        }
                        rlc
                    });

                    let rlc_val_f = challenge_r.map(|r| {
                        let mut rlc = F::ZERO;
                        let mut r_power = F::ONE;
                        for byte in state.rlc_f.iter() {
                            rlc += F::from(*byte as u64) * r_power;
                            r_power *= r;
                        }
                        rlc
                    });

                    let rlc_val_g = challenge_r.map(|r| {
                        let mut rlc = F::ZERO;
                        let mut r_power = F::ONE;
                        for byte in state.rlc_g.iter() {
                            rlc += F::from(*byte as u64) * r_power;
                            r_power *= r;
                        }
                        rlc
                    });

                    let rlc_val_h = challenge_r.map(|r| {
                        let mut rlc = F::ZERO;
                        let mut r_power = F::ONE;
                        for byte in state.rlc_h.iter() {
                            rlc += F::from(*byte as u64) * r_power;
                            r_power *= r;
                        }
                        rlc
                    });

                    let rlc_val_i =
                        if state.returndatacopy == F::ONE || state.calldatacopy == F::ONE {
                            rlc_val_c.map(|value| value.invert().unwrap_or(F::ZERO))
                        } else {
                            challenge_r.map(|r| {
                                let mut rlc = F::ZERO;
                                let mut r_power = F::ONE;
                                for byte in state.rlc_i.iter() {
                                    rlc += F::from(*byte as u64) * r_power;
                                    r_power *= r;
                                }
                                rlc
                            })
                        };

                    let rlc_val_j = challenge_r.map(|r| {
                        let mut rlc = F::ZERO;
                        let mut r_power = F::ONE;
                        for byte in state.rlc_j.iter() {
                            rlc += F::from(*byte as u64) * r_power;
                            r_power *= r;
                        }
                        rlc
                    });

                    region.assign_advice(
                        || format!("rlc_a at row {}", offset),
                        self.rlc_a,
                        offset,
                        || rlc_val_a,
                    )?;

                    region.assign_advice(
                        || format!("rlc_b at row {}", offset),
                        self.rlc_b,
                        offset,
                        || rlc_val_b,
                    )?;

                    region.assign_advice(
                        || format!("rlc_c at row {}", offset),
                        self.rlc_c,
                        offset,
                        || rlc_val_c,
                    )?;

                    region.assign_advice(
                        || format!("rlc_d at row {}", offset),
                        self.rlc_d,
                        offset,
                        || rlc_val_d,
                    )?;

                    region.assign_advice(
                        || format!("rlc_e at row {}", offset),
                        self.rlc_e,
                        offset,
                        || rlc_val_e,
                    )?;

                    region.assign_advice(
                        || format!("rlc_f at row {}", offset),
                        self.rlc_f,
                        offset,
                        || rlc_val_f,
                    )?;

                    region.assign_advice(
                        || format!("rlc_g at row {}", offset),
                        self.rlc_g,
                        offset,
                        || rlc_val_g,
                    )?;

                    region.assign_advice(
                        || format!("rlc_h at row {}", offset),
                        self.rlc_h,
                        offset,
                        || rlc_val_h,
                    )?;

                    region.assign_advice(
                        || format!("rlc_i at row {}", offset),
                        self.rlc_i,
                        offset,
                        || rlc_val_i,
                    )?;

                    region.assign_advice(
                        || format!("rlc_j at row {}", offset),
                        self.rlc_j,
                        offset,
                        || rlc_val_j,
                    )?;

                    region.assign_advice(
                        || format!("memaddr at row {}", offset),
                        self.memaddr,
                        offset,
                        || Value::known(state.memaddr),
                    )?;

                    region.assign_advice(
                        || format!("inv at row {}", offset),
                        self.inv,
                        offset,
                        || Value::known(state.inv),
                    )?;

                    region.assign_advice(
                        || format!("mmax at row {}", offset),
                        self.mmax,
                        offset,
                        || Value::known(state.mmax),
                    )?;

                    region.assign_advice(
                        || format!("ismaxchanged at row {}", offset),
                        self.ismaxchanged,
                        offset,
                        || Value::known(state.ismaxchanged),
                    )?;

                    region.assign_advice(
                        || format!("isbegintx at row {}", offset),
                        self.isbegintx,
                        offset,
                        || Value::known(state.isbegintx),
                    )?;

                    region.assign_advice(
                        || format!("isendtx at row {}", offset),
                        self.isendtx,
                        offset,
                        || Value::known(state.isendtx),
                    )?;

                    region.assign_advice(
                        || format!("iscall at row {}", offset),
                        self.iscall,
                        offset,
                        || Value::known(state.iscall),
                    )?;

                    region.assign_advice(
                        || format!("isreturn at row {}", offset),
                        self.isreturn,
                        offset,
                        || Value::known(state.isreturn),
                    )?;

                    region.assign_advice(
                        || format!("returndatacopy at row {}", offset),
                        self.returndatacopy,
                        offset,
                        || Value::known(state.returndatacopy),
                    )?;

                    region.assign_advice(
                        || format!("calldatacopy at row {}", offset),
                        self.calldatacopy,
                        offset,
                        || Value::known(state.calldatacopy),
                    )?;

                    region.assign_advice(
                        || format!("isadd at row {}", offset),
                        self.isadd,
                        offset,
                        || Value::known(state.isadd),
                    )?;

                    region.assign_advice(
                        || format!("issub at row {}", offset),
                        self.issub,
                        offset,
                        || Value::known(state.issub),
                    )?;

                    region.assign_advice(
                        || format!("ismul at row {}", offset),
                        self.ismul,
                        offset,
                        || Value::known(state.ismul),
                    )?;

                    region.assign_advice(
                        || format!("isdiv at row {}", offset),
                        self.isdiv,
                        offset,
                        || Value::known(state.isdiv),
                    )?;

                    region.assign_advice(
                        || format!("islt at row {}", offset),
                        self.islt,
                        offset,
                        || Value::known(state.islt),
                    )?;

                    region.assign_advice(
                        || format!("iseq at row {}", offset),
                        self.iseq,
                        offset,
                        || Value::known(state.iseq),
                    )?;

                    region.assign_advice(
                        || format!("isand at row {}", offset),
                        self.isand,
                        offset,
                        || Value::known(state.isand),
                    )?;

                    region.assign_advice(
                        || format!("isor at row {}", offset),
                        self.isor,
                        offset,
                        || Value::known(state.isor),
                    )?;

                    region.assign_advice(
                        || format!("isxor at row {}", offset),
                        self.isxor,
                        offset,
                        || Value::known(state.isxor),
                    )?;

                    region.assign_advice(
                        || format!("isnot at row {}", offset),
                        self.isnot,
                        offset,
                        || Value::known(state.isnot),
                    )?;

                    region.assign_advice(
                        || format!("isjump at row {}", offset),
                        self.isjump,
                        offset,
                        || Value::known(state.isjump),
                    )?;

                    region.assign_advice(
                        || format!("isjumpdest at row {}", offset),
                        self.isjumpdest,
                        offset,
                        || Value::known(state.isjumpdest),
                    )?;

                    region.assign_advice(
                        || format!("isjumpcon at row {}", offset),
                        self.isjumpcon,
                        offset,
                        || Value::known(state.isjumpcon),
                    )?;

                    region.assign_advice(
                        || format!("ismload at row {}", offset),
                        self.ismload,
                        offset,
                        || Value::known(state.ismload),
                    )?;

                    region.assign_advice(
                        || format!("ismstore at row {}", offset),
                        self.ismstore,
                        offset,
                        || Value::known(state.ismstore),
                    )?;

                    region.assign_advice(
                        || format!("ismstore8 at row {}", offset),
                        self.ismstore8,
                        offset,
                        || Value::known(state.ismstore8),
                    )?;

                    region.assign_advice(
                        || format!("isread at row {}", offset),
                        self.isread,
                        offset,
                        || Value::known(state.isread),
                    )?;

                    region.assign_advice(
                        || format!("iswrite at row {}", offset),
                        self.iswrite,
                        offset,
                        || Value::known(state.iswrite),
                    )?;

                    region.assign_advice(
                        || format!("ishalt at row {}", offset),
                        self.ishalt,
                        offset,
                        || Value::known(state.ishalt),
                    )?;

                    region.assign_advice(
                        || format!("rlc_addr_a at row {}", offset),
                        self.rlc_addr_a,
                        offset,
                        || Value::known(state.rlc_addr_a),
                    )?;

                    region.assign_advice(
                        || format!("rlc_addr_b at row {}", offset),
                        self.rlc_addr_b,
                        offset,
                        || Value::known(state.rlc_addr_b),
                    )?;

                    region.assign_advice(
                        || format!("sp at row {}", offset),
                        self.sp,
                        offset,
                        || Value::known(state.sp),
                    )?;
                }

                Ok(())
            },
        )
    }
}

#[derive(Debug, Clone)]
struct ALU_values<F: PrimeField> {
    isfirst: F,
    islast: F,
    byte32: F,
    isfirst32: F,
    islast32: F,
    limbnumber: F,
    isadd: F,
    ismul: F,
    isdiv: F,
    islt: F,
    iseq: F,
    isand: F,
    isor: F,
    isxor: F,
    isnot: F,
    barlt: F,
    carry: F,
    rem: F,
    limb_a: F,
    limb_b: F,
    limb_c: F,
    pac_a: [F; 4],
    pac_b: [F; 4],
    pac_c: [F; 4],
    pac_carry: [F; 4],
    pac_rem: [F; 4],
    pac_diff: [F; 4],
    rlc_a: [u64; 4],
    rlc_b: [u64; 4],
    rlc_c: [u64; 4],
    noname: F,
}

impl<F: PrimeField> ALU_values<F> {
    fn without_values(&self) -> Self {
        Self {
            byte32: F::ZERO,
            isadd: F::ZERO,
            ismul: F::ZERO,
            isdiv: F::ZERO,
            islt: F::ZERO,
            iseq: F::ZERO,
            isand: F::ZERO,
            isor: F::ZERO,
            isxor: F::ZERO,
            isnot: F::ZERO,
            barlt: F::ZERO,
            carry: F::ZERO,
            rem: F::ZERO,
            limb_a: F::ZERO,
            limb_b: F::ZERO,
            limb_c: F::ZERO,

            pac_a: [F::ZERO; 4],
            pac_b: [F::ZERO; 4],
            pac_c: [F::ZERO; 4],
            pac_carry: [F::ZERO; 4],
            pac_rem: [F::ZERO; 4],
            pac_diff: [F::ZERO; 4],

            rlc_a: [0u64; 4],
            rlc_b: [0u64; 4],
            rlc_c: [0u64; 4],
            noname: F::ZERO,
            ..self.clone()
        }
    }
}

#[derive(Debug, Clone)]
struct ALUTrace_Chip<F: PrimeField> {
    _ph: PhantomData<F>,
    q_selector: Selector,
    isfirst: Column<Fixed>,
    islast: Column<Fixed>,
    byte32: Column<Advice>,
    isfirst32: Column<Fixed>,
    islast32: Column<Fixed>,
    limbnumber: Column<Fixed>,
    isadd: Column<Advice>,
    ismul: Column<Advice>,
    isdiv: Column<Advice>,
    islt: Column<Advice>,
    iseq: Column<Advice>,
    isand: Column<Advice>,
    isor: Column<Advice>,
    isxor: Column<Advice>,
    isnot: Column<Advice>,
    barlt: Column<Advice>,
    carry: Column<Advice>,
    rem: Column<Advice>,
    limb_a: Column<Advice>,
    limb_b: Column<Advice>,
    limb_c: Column<Advice>,
    pac_a: [Column<Advice>; 4],
    pac_b: [Column<Advice>; 4],
    pac_c: [Column<Advice>; 4],
    pac_carry: [Column<Advice>; 4],
    pac_rem: [Column<Advice>; 4],
    pac_diff: [Column<Advice>; 4],
    rlc_a: Column<Advice>,
    rlc_b: Column<Advice>,
    rlc_c: Column<Advice>,
    noname: Column<Advice>,
}

impl<F: PrimeField> ALUTrace_Chip<F> {
    fn configure(
        meta: &mut ConstraintSystem<F>,
        q_selector: Selector,
        isfirst: Column<Fixed>,
        islast: Column<Fixed>,
        byte32: Column<Advice>,
        isfirst32: Column<Fixed>,
        islast32: Column<Fixed>,
        limbnumber: Column<Fixed>,
        isadd: Column<Advice>,
        ismul: Column<Advice>,
        isdiv: Column<Advice>,
        islt: Column<Advice>,
        iseq: Column<Advice>,
        isand: Column<Advice>,
        isor: Column<Advice>,
        isxor: Column<Advice>,
        isnot: Column<Advice>,
        barlt: Column<Advice>,
        carry: Column<Advice>,
        rem: Column<Advice>,
        limb_a: Column<Advice>,
        limb_b: Column<Advice>,
        limb_c: Column<Advice>,
        pac_a: [Column<Advice>; 4],
        pac_b: [Column<Advice>; 4],
        pac_c: [Column<Advice>; 4],
        pac_carry: [Column<Advice>; 4],
        pac_rem: [Column<Advice>; 4],
        pac_diff: [Column<Advice>; 4],
        rlc_a: Column<Advice>,
        rlc_b: Column<Advice>,
        rlc_c: Column<Advice>,
        noname: Column<Advice>,
        rc: Challenge,
    ) -> Self {
        meta.create_gate("alu_gates", |meta| {
            let one = Expression::Constant(F::ONE);
            let q = meta.query_selector(q_selector);
            let isfirst = meta.query_fixed(isfirst, Rotation::cur());
            let islast = meta.query_fixed(islast, Rotation::cur());

            let byte32_cur = meta.query_advice(byte32, Rotation::cur());
            let byte32_next = meta.query_advice(byte32, Rotation(1));
            let limb4 = one.clone() - byte32_cur.clone();
            let gatecalc = q.clone() * limb4.clone();
            let gatemem = q.clone() * byte32_cur.clone();
            let isfirst32 = meta.query_fixed(isfirst32, Rotation::cur());
            let islast32_cur = meta.query_fixed(islast32, Rotation::cur());
            let _islast32_next = meta.query_fixed(islast32, Rotation::next());
            let _limbnumber = meta.query_fixed(limbnumber, Rotation::cur());

            let isadd_prev = meta.query_advice(isadd, Rotation::prev());
            let isadd_cur = meta.query_advice(isadd, Rotation::cur());

            let ismul_prev = meta.query_advice(ismul, Rotation::prev());
            let ismul_cur = meta.query_advice(ismul, Rotation::cur());

            let isdiv_prev = meta.query_advice(isdiv, Rotation::prev());
            let isdiv_cur = meta.query_advice(isdiv, Rotation::cur());

            let islt = meta.query_advice(islt, Rotation::cur());
            let iseq = meta.query_advice(iseq, Rotation::cur());
            let isand = meta.query_advice(isand, Rotation::cur());
            let isor = meta.query_advice(isor, Rotation::cur());
            let isxor = meta.query_advice(isxor, Rotation::cur());
            let isnot = meta.query_advice(isnot, Rotation::cur());
            let barlt_cur = meta.query_advice(barlt, Rotation::cur());
            let barlt_next = meta.query_advice(barlt, Rotation::next());

            let carry_cur = meta.query_advice(carry, Rotation::cur());
            let carry_1 = meta.query_advice(carry, Rotation(1));
            let carry_2 = meta.query_advice(carry, Rotation(2));
            let carry_3 = meta.query_advice(carry, Rotation(3));
            let carry_prev = meta.query_advice(carry, Rotation::prev());

            let rem_0_prev = meta.query_advice(rem, Rotation::prev());
            let rem_0 = meta.query_advice(rem, Rotation::cur());
            let rem_1 = meta.query_advice(rem, Rotation(1));
            let rem_2 = meta.query_advice(rem, Rotation(2));
            let rem_3 = meta.query_advice(rem, Rotation(3));

            let limb_a_cur = meta.query_advice(limb_a, Rotation::cur());
            let limb_b_cur = meta.query_advice(limb_b, Rotation::cur());
            let limb_c_cur = meta.query_advice(limb_c, Rotation::cur());
            let limb_a_1 = meta.query_advice(limb_a, Rotation(1));
            let limb_b_1 = meta.query_advice(limb_b, Rotation(1));
            let limb_c_1 = meta.query_advice(limb_c, Rotation(1));
            let limb_a_2 = meta.query_advice(limb_a, Rotation(2));
            let limb_b_2 = meta.query_advice(limb_b, Rotation(2));
            let limb_c_2 = meta.query_advice(limb_c, Rotation(2));
            let limb_a_3 = meta.query_advice(limb_a, Rotation(3));
            let limb_b_3 = meta.query_advice(limb_b, Rotation(3));
            let limb_c_3 = meta.query_advice(limb_c, Rotation(3));

            let pac_a_0 = meta.query_advice(pac_a[0], Rotation::cur());
            let pac_a_1 = meta.query_advice(pac_a[1], Rotation::cur());
            let pac_a_2 = meta.query_advice(pac_a[2], Rotation::cur());
            let pac_a_3 = meta.query_advice(pac_a[3], Rotation::cur());
            let pac_b_0 = meta.query_advice(pac_b[0], Rotation::cur());
            let pac_b_1 = meta.query_advice(pac_b[1], Rotation::cur());
            let pac_b_2 = meta.query_advice(pac_b[2], Rotation::cur());
            let pac_b_3 = meta.query_advice(pac_b[3], Rotation::cur());
            let pac_c_0 = meta.query_advice(pac_c[0], Rotation::cur());
            let pac_c_1 = meta.query_advice(pac_c[1], Rotation::cur());
            let pac_c_2 = meta.query_advice(pac_c[2], Rotation::cur());
            let pac_c_3 = meta.query_advice(pac_c[3], Rotation::cur());
            let pac_carry_0 = meta.query_advice(pac_carry[0], Rotation::cur());
            let _pac_carry_0_next = meta.query_advice(pac_carry[0], Rotation::next());
            let pac_carry_1_prev = meta.query_advice(pac_carry[1], Rotation::prev());
            let pac_carry_1 = meta.query_advice(pac_carry[1], Rotation::cur());
            let pac_carry_1_next = meta.query_advice(pac_carry[1], Rotation::next());
            let pac_carry_2 = meta.query_advice(pac_carry[2], Rotation::cur());
            let pac_carry_2_next = meta.query_advice(pac_carry[2], Rotation::next());
            let pac_carry_3 = meta.query_advice(pac_carry[3], Rotation::cur());
            let pac_carry_3_next = meta.query_advice(pac_carry[3], Rotation::next());
            let pac_rem_0 = meta.query_advice(pac_rem[0], Rotation::cur());
            let pac_rem_1 = meta.query_advice(pac_rem[1], Rotation::cur());
            let pac_rem_2 = meta.query_advice(pac_rem[2], Rotation::cur());
            let pac_rem_3 = meta.query_advice(pac_rem[3], Rotation::cur());
            let pac_diff_0 = meta.query_advice(pac_diff[0], Rotation::cur());
            let pac_diff_1 = meta.query_advice(pac_diff[1], Rotation::cur());
            let pac_diff_2 = meta.query_advice(pac_diff[2], Rotation::cur());
            let pac_diff_3 = meta.query_advice(pac_diff[3], Rotation::cur());

            let rlc_a_cur = meta.query_advice(rlc_a, Rotation::cur());
            let rlc_b_cur = meta.query_advice(rlc_b, Rotation::cur());
            let rlc_c_cur = meta.query_advice(rlc_c, Rotation::cur());
            let rlc_a_next = meta.query_advice(rlc_a, Rotation::next());
            let rlc_b_next = meta.query_advice(rlc_b, Rotation::next());
            let rlc_c_next = meta.query_advice(rlc_c, Rotation::next());
            let rlc_c_last = meta.query_advice(rlc_c, Rotation(3));

            let noname_prev = meta.query_advice(noname, Rotation::prev());
            let noname: [Expression<F>; 32] =
                core::array::from_fn(|i| meta.query_advice(noname, Rotation(i as i32)));
            let r = meta.query_challenge(rc);

            let one = Expression::Constant(F::ONE);
            let _minus_one = Expression::Constant(-F::ONE);
            let two_pow_8 = Expression::Constant(F::from(1u64 << 8));
            let two_pow_16 = Expression::Constant(F::from(1u64 << 16));
            let two_pow_24 = Expression::Constant(F::from(1u64 << 24));
            let two_pow_32 = Expression::Constant(F::from(1u64 << 32));
            let two_pow_40 = Expression::Constant(F::from(1u64 << 40));
            let two_pow_48 = Expression::Constant(F::from(1u64 << 48));
            let two_pow_56 = Expression::Constant(F::from(1u64 << 56));
            let two_pow_64 = Expression::Constant(F::from_u128(1_u128 << 64));

            let _diff_rem_b = limb_b_cur.clone()
                - (pac_rem_0.clone()
                    + pac_rem_1.clone() * two_pow_16.clone()
                    + pac_rem_2.clone() * two_pow_32.clone()
                    + pac_rem_3.clone() * two_pow_48.clone());

            let pac_diff = pac_diff_0.clone()
                + pac_diff_1.clone() * two_pow_16.clone()
                + pac_diff_2.clone() * two_pow_32.clone()
                + pac_diff_3.clone() * two_pow_48.clone();

            let part_0 = noname[31].clone()
                + noname[30].clone() * two_pow_8.clone()
                + noname[29].clone() * two_pow_16.clone()
                + noname[28].clone() * two_pow_24.clone()
                + noname[27].clone() * two_pow_32.clone()
                + noname[26].clone() * two_pow_40.clone()
                + noname[25].clone() * two_pow_48.clone()
                + noname[24].clone() * two_pow_56.clone();

            let part_1 = noname[23].clone()
                + noname[22].clone() * two_pow_8.clone()
                + noname[21].clone() * two_pow_16.clone()
                + noname[20].clone() * two_pow_24.clone()
                + noname[19].clone() * two_pow_32.clone()
                + noname[18].clone() * two_pow_40.clone()
                + noname[17].clone() * two_pow_48.clone()
                + noname[16].clone() * two_pow_56.clone();

            let part_2 = noname[15].clone()
                + noname[14].clone() * two_pow_8.clone()
                + noname[13].clone() * two_pow_16.clone()
                + noname[12].clone() * two_pow_24.clone()
                + noname[11].clone() * two_pow_32.clone()
                + noname[10].clone() * two_pow_40.clone()
                + noname[9].clone() * two_pow_48.clone()
                + noname[8].clone() * two_pow_56.clone();

            let part_3 = noname[7].clone()
                + noname[6].clone() * two_pow_8.clone()
                + noname[5].clone() * two_pow_16.clone()
                + noname[4].clone() * two_pow_24.clone()
                + noname[3].clone() * two_pow_32.clone()
                + noname[2].clone() * two_pow_40.clone()
                + noname[1].clone() * two_pow_48.clone()
                + noname[0].clone() * two_pow_56.clone();

            let r_sq = r.clone() * r.clone();
            let r_cb = r_sq.clone() * r.clone();
            let rlc_mem = part_0 + part_1 * r.clone() + part_2 * r_sq + part_3 * r_cb;

            vec![
                // binary checks, redundant
                (gatecalc.clone() * isadd_cur.clone() * (one.clone() - isadd_cur.clone())),
                (gatecalc.clone() * ismul_cur.clone() * (one.clone() - ismul_cur.clone())),
                (gatecalc.clone() * isdiv_cur.clone() * (one.clone() - isdiv_cur.clone())),
                (gatecalc.clone() * islt.clone() * (one.clone() - islt.clone())),
                (gatecalc.clone() * iseq.clone() * (one.clone() - iseq.clone())),
                (gatecalc.clone() * isand.clone() * (one.clone() - isand.clone())),
                (gatecalc.clone() * isor.clone() * (one.clone() - isor.clone())),
                (gatecalc.clone() * isxor.clone() * (one.clone() - isxor.clone())),
                (gatecalc.clone() * isnot.clone() * (one.clone() - isnot.clone())),
                (gatecalc.clone()
                    * (islt.clone()
                        + iseq.clone()
                        + isadd_cur.clone()
                        + ismul_cur.clone()
                        + isdiv_cur.clone()
                        + isand.clone()
                        + isor.clone()
                        + isxor.clone()
                        + isnot.clone()
                        - one.clone())),
                // isadd, degree 5
                (gatecalc.clone()
                    * isadd_cur.clone()
                    * carry_cur.clone()
                    * (one.clone() - carry_cur.clone())),
                (gatecalc.clone()
                    * isadd_cur.clone()
                    * isfirst.clone()
                    * (limb_a_cur.clone() + limb_b_cur.clone()
                        - limb_c_cur.clone()
                        - carry_cur.clone() * two_pow_64.clone())),
                (gatecalc.clone()
                    * isadd_cur.clone()
                    * (one.clone() - isfirst.clone())
                    * (limb_a_cur.clone() + limb_b_cur.clone() + carry_prev.clone()
                        - limb_c_cur.clone()
                        - carry_cur.clone() * two_pow_64.clone())),
                (gatecalc.clone()
                    * isadd_cur.clone()
                    * (one.clone() - isfirst.clone())
                    * (isadd_cur.clone() - isadd_prev.clone())),
                // ismul, degree 5
                (gatecalc.clone()
                    * ismul_cur.clone()
                    * isfirst.clone()
                    * (limb_a_cur.clone() * limb_b_cur.clone()
                        - limb_c_cur.clone()
                        - carry_cur.clone() * two_pow_64.clone())),
                (gatecalc.clone()
                    * ismul_cur.clone()
                    * isfirst.clone()
                    * (limb_a_1.clone() * limb_b_cur.clone()
                        + limb_b_1.clone() * limb_a_cur.clone()
                        + carry_cur.clone()
                        - limb_c_1.clone()
                        - carry_1.clone() * two_pow_64.clone())),
                (gatecalc.clone()
                    * ismul_cur.clone()
                    * isfirst.clone()
                    * (limb_a_2.clone() * limb_b_cur.clone()
                        + limb_b_2.clone() * limb_a_cur.clone()
                        + limb_a_1.clone() * limb_b_1.clone()
                        + carry_1.clone()
                        - limb_c_2.clone()
                        - carry_2.clone() * two_pow_64.clone())),
                (gatecalc.clone()
                    * ismul_cur.clone()
                    * isfirst.clone()
                    * (limb_a_3.clone() * limb_b_cur.clone()
                        + limb_b_3.clone() * limb_a_cur.clone()
                        + limb_a_2.clone() * limb_b_1.clone()
                        + limb_b_2.clone() * limb_a_1.clone()
                        + carry_2.clone()
                        - limb_c_3.clone()
                        - carry_3.clone() * two_pow_64.clone())),
                (gatecalc.clone()
                    * ismul_cur.clone()
                    * (one.clone() - isfirst.clone())
                    * (ismul_cur.clone() - ismul_prev.clone())),
                // isdiv, degree 5
                (gatecalc.clone()
                    * isdiv_cur.clone()
                    * isfirst.clone()
                    * (limb_a_cur.clone() * limb_b_cur.clone()
                        - limb_c_cur.clone()
                        - carry_cur.clone() * two_pow_64.clone()
                        + rem_0.clone())),
                (gatecalc.clone()
                    * isdiv_cur.clone()
                    * isfirst.clone()
                    * (limb_a_1.clone() * limb_b_cur.clone()
                        + limb_b_1.clone() * limb_a_cur.clone()
                        + carry_cur.clone()
                        - limb_c_1.clone()
                        - carry_1.clone() * two_pow_64.clone()
                        + rem_1.clone())),
                (gatecalc.clone()
                    * isdiv_cur.clone()
                    * isfirst.clone()
                    * (limb_a_2.clone() * limb_b_cur.clone()
                        + limb_b_2.clone() * limb_a_cur.clone()
                        + limb_a_1.clone() * limb_b_1.clone()
                        + carry_1.clone()
                        - limb_c_2.clone()
                        - carry_2.clone() * two_pow_64.clone()
                        + rem_2.clone())),
                (gatecalc.clone()
                    * isdiv_cur.clone()
                    * isfirst.clone()
                    * (limb_a_3.clone() * limb_b_cur.clone()
                        + limb_b_3.clone() * limb_a_cur.clone()
                        + limb_a_2.clone() * limb_b_1.clone()
                        + limb_b_2.clone() * limb_a_1.clone()
                        + carry_2.clone()
                        - limb_c_3.clone()
                        - carry_3.clone() * two_pow_64.clone()
                        + rem_3.clone())),
                (gatecalc.clone()
                    * isdiv_cur.clone()
                    * (carry_3.clone()
                        + limb_b_3.clone() * limb_a_1.clone()
                        + limb_a_3.clone() * limb_b_1.clone()
                        + limb_b_3.clone() * limb_a_2.clone()
                        + limb_a_3.clone() * limb_b_2.clone()
                        + limb_a_3.clone() * limb_b_3.clone()
                        + limb_b_2.clone() * limb_a_2.clone())),
                (gatecalc.clone()
                    * isdiv_cur.clone()
                    * barlt_cur.clone()
                    * (one.clone() - barlt_cur.clone())),
                (gatecalc.clone()
                    * isdiv_cur.clone()
                    * isfirst.clone()
                    * (one.clone() - barlt_cur.clone())),
                (gatecalc.clone()
                    * isdiv_cur.clone()
                    * (one.clone() - islast.clone())
                    * (limb_b_cur.clone() - rem_0.clone() - barlt_cur.clone()
                        + barlt_next.clone() * two_pow_64.clone()
                        - pac_diff.clone())),
                (gatecalc.clone()
                    * isdiv_cur.clone()
                    * islast.clone()
                    * (limb_b_cur.clone() - rem_0.clone() - barlt_cur.clone() - pac_diff.clone())),
                (gatecalc.clone()
                    * isdiv_cur.clone()
                    * (one.clone() - isfirst.clone())
                    * (isdiv_cur.clone() - isdiv_prev.clone())),
                // islt
                (gatecalc.clone()
                    * islt.clone()
                    * barlt_cur.clone()
                    * (one.clone() - barlt_cur.clone())),
                (gatecalc.clone()
                    * islt.clone()
                    * isfirst.clone()
                    * (one.clone() - barlt_cur.clone())),
                (gatecalc.clone()
                    * islt.clone()
                    * (one.clone() - islast.clone())
                    * (limb_b_cur.clone() - limb_a_cur.clone() - barlt_cur.clone()
                        + barlt_next.clone() * two_pow_64.clone()
                        - limb_c_cur.clone())),
                (gatecalc.clone()
                    * islt.clone()
                    * rlc_c_cur.clone()
                    * (one.clone() - rlc_c_cur.clone())),
                (gatecalc.clone()
                    * islt.clone()
                    * islast.clone()
                    * (limb_b_cur.clone() - limb_a_cur.clone() - barlt_cur.clone()
                        + (one.clone() - rlc_c_cur.clone()) * two_pow_64.clone()
                        - limb_c_cur.clone())),
                (gatecalc.clone()
                    * islt.clone()
                    * isfirst.clone()
                    * (rlc_c_cur.clone() - rlc_c_last.clone())),
                // iseq
                (gatecalc.clone()
                    * iseq.clone()
                    * limb_c_cur.clone()
                    * (one.clone() - limb_c_cur.clone())),
                (gatecalc.clone()
                    * iseq.clone()
                    * rlc_c_cur.clone()
                    * (one.clone() - rlc_c_cur.clone())),
                (gatecalc.clone()
                    * iseq.clone()
                    * limb_c_cur.clone()
                    * (limb_a_cur.clone() - limb_b_cur.clone())),
                (q.clone() * iseq.clone() * (gatecalc.clone() - pac_carry_0.clone())), // degree managment
                (q.clone() * iseq.clone() * (iseq.clone() * isfirst.clone() - pac_carry_1.clone())), // degree managment
                (q.clone()
                    * iseq.clone()
                    * (limb_c_cur.clone() * limb_c_1.clone() - pac_carry_2.clone())), // degree managment
                (gatecalc.clone()
                    * pac_carry_0.clone()
                    * iseq.clone()
                    * (one.clone() - limb_c_cur.clone())
                    * ((limb_a_cur.clone() - limb_b_cur.clone())
                    * carry_cur.clone() // mul inverse of limb_a - limb_b
                    - one.clone())),
                (gatecalc.clone()
                    * pac_carry_0.clone()
                    * pac_carry_1.clone()
                    * (pac_carry_2.clone() * limb_c_2.clone() * limb_c_3.clone()
                        - rlc_c_cur.clone())),
                (gatecalc.clone()
                    * (isand.clone() + isor.clone() + isxor.clone() + isnot.clone())
                    * (limb_a_cur.clone()
                        - pac_a_0.clone()
                        - pac_a_1.clone() * two_pow_8.clone()
                        - pac_a_2.clone() * two_pow_16.clone()
                        - pac_a_3.clone() * two_pow_24.clone()
                        - pac_b_0.clone() * two_pow_32.clone()
                        - pac_b_1.clone() * two_pow_40.clone()
                        - pac_b_2.clone() * two_pow_48.clone()
                        - pac_b_3.clone() * two_pow_56.clone())),
                (gatecalc.clone()
                    * (isand.clone() + isor.clone() + isxor.clone() + isnot.clone())
                    * (limb_b_cur.clone()
                        - pac_c_0.clone()
                        - pac_c_1.clone() * two_pow_8.clone()
                        - pac_c_2.clone() * two_pow_16.clone()
                        - pac_c_3.clone() * two_pow_24.clone()
                        - pac_carry_0.clone() * two_pow_32.clone()
                        - pac_carry_1.clone() * two_pow_40.clone()
                        - pac_carry_2.clone() * two_pow_48.clone()
                        - pac_carry_3.clone() * two_pow_56.clone())),
                (gatecalc.clone()
                    * (isand.clone() + isor.clone() + isxor.clone() + isnot.clone())
                    * (limb_c_cur.clone()
                        - pac_rem_0.clone()
                        - pac_rem_1.clone() * two_pow_8.clone()
                        - pac_rem_2.clone() * two_pow_16.clone()
                        - pac_rem_3.clone() * two_pow_24.clone()
                        - barlt_cur.clone() * two_pow_32.clone()
                        - carry_cur.clone() * two_pow_40.clone()
                        - rem_0.clone() * two_pow_48.clone()
                        - noname[0].clone() * two_pow_56.clone())),
                (gatecalc.clone() * islast.clone() * (rlc_a_cur.clone() - limb_a_cur.clone())),
                (gatecalc.clone() * islast.clone() * (rlc_b_cur.clone() - limb_b_cur.clone())),
                (gatecalc.clone()
                    * (isadd_cur.clone()
                        + ismul_cur.clone()
                        + isdiv_cur.clone()
                        + isand.clone()
                        + isor.clone()
                        + isxor.clone()
                        + isnot.clone())
                    * islast.clone()
                    * (rlc_c_cur.clone() - limb_c_cur.clone())),
                (gatecalc.clone()
                    * (one.clone() - islast.clone())
                    * (rlc_a_cur.clone() - rlc_a_next.clone() * r.clone() - limb_a_cur.clone())),
                (gatecalc.clone()
                    * (one.clone() - islast.clone())
                    * (rlc_b_cur.clone() - rlc_b_next.clone() * r.clone() - limb_b_cur.clone())),
                (gatecalc.clone()
                    * (one.clone() - islast.clone())
                    * (isadd_cur.clone()
                        + ismul_cur.clone()
                        + isdiv_cur.clone()
                        + isand.clone()
                        + isor.clone()
                        + isxor.clone()
                        + isnot.clone())
                    * (rlc_c_cur.clone() - rlc_c_next.clone() * r.clone() - limb_c_cur.clone())),
                (gatecalc.clone()
                    * (one.clone()
                        - (isand.clone() + isor.clone() + isxor.clone() + isnot.clone()))
                    * (limb_a_cur.clone()
                        - pac_a_0.clone()
                        - pac_a_1.clone() * two_pow_16.clone()
                        - pac_a_2.clone() * two_pow_32.clone()
                        - pac_a_3.clone() * two_pow_48.clone())),
                (gatecalc.clone()
                    * (one.clone()
                        - (isand.clone() + isor.clone() + isxor.clone() + isnot.clone()))
                    * (limb_b_cur.clone()
                        - pac_b_0.clone()
                        - pac_b_1.clone() * two_pow_16.clone()
                        - pac_b_2.clone() * two_pow_32.clone()
                        - pac_b_3.clone() * two_pow_48.clone())),
                (gatecalc.clone()
                    * (isadd_cur.clone() + ismul_cur.clone() + isdiv_cur.clone() + islt.clone())
                    * (limb_c_cur.clone()
                        - pac_c_0.clone()
                        - pac_c_1.clone() * two_pow_16.clone()
                        - pac_c_2.clone() * two_pow_32.clone()
                        - pac_c_3.clone() * two_pow_48.clone())),
                (gatecalc.clone()
                    * isdiv_cur.clone()
                    * (rem_0.clone()
                        - pac_rem_0.clone()
                        - pac_rem_1.clone() * two_pow_16.clone()
                        - pac_rem_2.clone() * two_pow_32.clone()
                        - pac_rem_3.clone() * two_pow_48.clone())),
                (gatecalc.clone()
                    * (isadd_cur.clone() + ismul_cur.clone() + isdiv_cur.clone())
                    * (carry_cur.clone()
                        - pac_carry_0.clone()
                        - pac_carry_1.clone() * two_pow_16.clone()
                        - pac_carry_2.clone() * two_pow_32.clone()
                        - pac_carry_3.clone() * two_pow_48.clone()
                        - (ismul_cur.clone() + isdiv_cur.clone())
                            * noname[0].clone()
                            * two_pow_64.clone())),
                (q.clone() * byte32_cur.clone() * limb4.clone()),
                (gatemem.clone()
                    * (one.clone() - byte32_next.clone() + byte32_cur.clone()) // ?
                    * (byte32_next.clone() - byte32_cur.clone())),
                // pac_carry_0 = ismstore8
                (gatemem.clone() * pac_carry_0.clone() * (one.clone() - pac_carry_0.clone())),
                (gatemem.clone()
                    * (one.clone() - pac_carry_0.clone())
                    * isfirst32.clone()
                    * (rlc_mem.clone() - rlc_a_cur.clone())),
                // carry = address
                // carry_1 => next row carry
                (gatemem.clone()
                    * (one.clone() - pac_carry_0.clone())
                    * (one.clone() - islast32_cur.clone())
                    * (carry_1.clone() - carry_cur.clone() - one.clone())),
                (gatemem.clone()
                    * isfirst32.clone()
                    * pac_carry_0.clone()
                    * (rlc_a_cur.clone() - noname[0].clone())),
                // pac_carry_1 = rwc
                (gatemem.clone()
                    * (one.clone() - pac_carry_0.clone())
                    * (one.clone() - islast32_cur.clone())
                    * (pac_carry_1_next.clone() - pac_carry_1.clone() - one.clone())),
                (gatemem.clone()
                    * pac_carry_0.clone()
                    * (one.clone() - isfirst32.clone())
                    * (pac_carry_1.clone() - pac_carry_1_prev.clone())),
                // rem = callid
                (gatemem.clone()
                    * (one.clone() - pac_carry_0.clone())
                    * (one.clone() - islast32_cur.clone())
                    * (rem_1.clone() - rem_0.clone())),
                (gatemem.clone()
                    * pac_carry_0.clone()
                    * (one.clone() - isfirst32.clone())
                    * (rem_0.clone() - rem_0_prev.clone())),
                // noname = value
                (gatemem.clone()
                    * pac_carry_0.clone()
                    * (one.clone() - isfirst32.clone())
                    * (noname[0].clone() - noname_prev.clone())),
                (gatemem.clone()
                    * pac_carry_0.clone()
                    * (one.clone() - isfirst32.clone())
                    * (carry_cur.clone() - carry_prev.clone())),
                // pac_carry_2 = ismload
                (gatemem.clone()
                    * pac_carry_0.clone()
                    * (one.clone() - isfirst32.clone())
                    * pac_carry_2.clone()),
                // pac_carry_3 = imstore
                (gatemem.clone()
                    * pac_carry_0.clone()
                    * (one.clone() - isfirst32.clone())
                    * pac_carry_3.clone()),
                (gatemem.clone()
                    * pac_carry_2.clone()
                    * (one.clone() - pac_carry_2_next.clone())
                    * (one.clone() - islast32_cur.clone())),
                (gatemem.clone()
                    * pac_carry_3.clone()
                    * (one.clone() - pac_carry_3_next.clone())
                    * (one.clone() - islast32_cur.clone())),
            ]
        });
        Self {
            _ph: PhantomData,
            q_selector,
            isfirst,
            islast,
            byte32,
            isfirst32,
            islast32,
            limbnumber,
            isadd,
            ismul,
            isdiv,
            islt,
            iseq,
            isand,
            isor,
            isxor,
            isnot,
            barlt,
            carry,
            rem,
            limb_a,
            limb_b,
            limb_c,
            pac_a,
            pac_b,
            pac_c,
            pac_carry,
            pac_rem,
            pac_diff,
            rlc_a,
            rlc_b,
            rlc_c,
            noname,
        }
    }

    pub fn assign(
        &self,
        layouter: &mut impl Layouter<F>,
        trace: &[ALU_values<F>],
        challenge_r: Value<F>,
    ) -> Result<(), Error> {
        const ALU_ACTIVE_ROWS: usize = 49_984;
        const ALU_HEAD_GUARD_ROWS: usize = 1;
        const ALU_TAIL_GUARD_ROWS: usize = 32;
        const ALU_ASSIGNED_ROWS: usize =
            ALU_HEAD_GUARD_ROWS + ALU_ACTIVE_ROWS + ALU_TAIL_GUARD_ROWS;

        let zero_row = trace
            .first()
            .map(ALU_values::without_values)
            .unwrap_or(ALU_values {
                isfirst: F::ZERO,
                islast: F::ZERO,
                byte32: F::ZERO,
                isfirst32: F::ZERO,
                islast32: F::ZERO,
                limbnumber: F::ZERO,
                isadd: F::ZERO,
                ismul: F::ZERO,
                isdiv: F::ZERO,
                islt: F::ZERO,
                iseq: F::ZERO,
                isand: F::ZERO,
                isor: F::ZERO,
                isxor: F::ZERO,
                isnot: F::ZERO,
                barlt: F::ZERO,
                carry: F::ZERO,
                rem: F::ZERO,
                limb_a: F::ZERO,
                limb_b: F::ZERO,
                limb_c: F::ZERO,
                pac_a: [F::ZERO; 4],
                pac_b: [F::ZERO; 4],
                pac_c: [F::ZERO; 4],
                pac_carry: [F::ZERO; 4],
                pac_rem: [F::ZERO; 4],
                pac_diff: [F::ZERO; 4],
                rlc_a: [0u64; 4],
                rlc_b: [0u64; 4],
                rlc_c: [0u64; 4],
                noname: F::ZERO,
            });
        let tail_guard_chunk = if trace
            .last()
            .map(|row| row.byte32 == F::ONE)
            .unwrap_or(false)
            && trace.len() >= 32
        {
            Some(trace[trace.len() - 32..].to_vec())
        } else {
            None
        };

        layouter.assign_region(
            || "alu_trace",
            |mut region| {
                for offset in 0..ALU_ASSIGNED_ROWS {
                    let active_offset = offset.checked_sub(ALU_HEAD_GUARD_ROWS);
                    let is_active_row =
                        matches!(active_offset, Some(inner) if inner < ALU_ACTIVE_ROWS);

                    if is_active_row {
                        self.q_selector.enable(&mut region, offset)?;
                    }

                    let isfirst_value = match active_offset {
                        Some(inner) if inner < ALU_ACTIVE_ROWS && inner % 4 == 0 => F::ONE,
                        _ => F::ZERO,
                    };

                    let islast_value = match active_offset {
                        Some(inner) if inner < ALU_ACTIVE_ROWS && inner % 4 == 3 => F::ONE,
                        _ => F::ZERO,
                    };

                    let isfirst32_value = match active_offset {
                        Some(inner) if inner < ALU_ACTIVE_ROWS && inner % 32 == 0 => F::ONE,
                        _ => F::ZERO,
                    };

                    let islast32_value = match active_offset {
                        Some(inner) if inner < ALU_ACTIVE_ROWS && inner % 32 == 31 => F::ONE,
                        _ => F::ZERO,
                    };

                    let limbnumber_value = match active_offset {
                        Some(inner) if inner < ALU_ACTIVE_ROWS => F::from((inner % 32) as u64),
                        _ => F::ZERO,
                    };

                    region.assign_fixed(
                        || "isfirst32",
                        self.isfirst32,
                        offset,
                        || Value::known(isfirst32_value),
                    )?;

                    region.assign_fixed(
                        || "islast32",
                        self.islast32,
                        offset,
                        || Value::known(islast32_value),
                    )?;

                    region.assign_fixed(
                        || "isfirst",
                        self.isfirst,
                        offset,
                        || Value::known(isfirst_value),
                    )?;

                    region.assign_fixed(
                        || "islast",
                        self.islast,
                        offset,
                        || Value::known(islast_value),
                    )?;

                    region.assign_fixed(
                        || "limbnumber",
                        self.limbnumber,
                        offset,
                        || Value::known(limbnumber_value),
                    )?;
                }
                for offset in 0..ALU_ASSIGNED_ROWS {
                    let row = if offset == 0 {
                        &zero_row
                    } else if offset >= ALU_HEAD_GUARD_ROWS + trace.len() {
                        if let Some(chunk) = tail_guard_chunk.as_ref() {
                            let tail_offset = offset - (ALU_HEAD_GUARD_ROWS + trace.len());
                            &chunk[tail_offset % chunk.len()]
                        } else {
                            &zero_row
                        }
                    } else {
                        &trace[offset - ALU_HEAD_GUARD_ROWS]
                    };

                    region.assign_advice(
                        || "byte32",
                        self.byte32,
                        offset,
                        || Value::known(row.byte32),
                    )?;

                    region.assign_advice(
                        || "isadd",
                        self.isadd,
                        offset,
                        || Value::known(row.isadd),
                    )?;

                    region.assign_advice(
                        || "ismul",
                        self.ismul,
                        offset,
                        || Value::known(row.ismul),
                    )?;

                    region.assign_advice(
                        || "isdiv",
                        self.isdiv,
                        offset,
                        || Value::known(row.isdiv),
                    )?;

                    region.assign_advice(
                        || "islt",
                        self.islt,
                        offset,
                        || Value::known(row.islt),
                    )?;

                    region.assign_advice(
                        || "iseq",
                        self.iseq,
                        offset,
                        || Value::known(row.iseq),
                    )?;

                    region.assign_advice(
                        || "isand",
                        self.isand,
                        offset,
                        || Value::known(row.isand),
                    )?;

                    region.assign_advice(
                        || "isor",
                        self.isor,
                        offset,
                        || Value::known(row.isor),
                    )?;

                    region.assign_advice(
                        || "isxor",
                        self.isxor,
                        offset,
                        || Value::known(row.isxor),
                    )?;

                    region.assign_advice(
                        || "isnot",
                        self.isnot,
                        offset,
                        || Value::known(row.isnot),
                    )?;

                    region.assign_advice(
                        || "barlt",
                        self.barlt,
                        offset,
                        || Value::known(row.barlt),
                    )?;

                    region.assign_advice(
                        || "carry",
                        self.carry,
                        offset,
                        || Value::known(row.carry),
                    )?;

                    region.assign_advice(|| "rem", self.rem, offset, || Value::known(row.rem))?;

                    region.assign_advice(
                        || "limb_a",
                        self.limb_a,
                        offset,
                        || Value::known(row.limb_a),
                    )?;

                    region.assign_advice(
                        || "limb_b",
                        self.limb_b,
                        offset,
                        || Value::known(row.limb_b),
                    )?;

                    region.assign_advice(
                        || "limb_c",
                        self.limb_c,
                        offset,
                        || Value::known(row.limb_c),
                    )?;

                    region.assign_advice(
                        || "noname",
                        self.noname,
                        offset,
                        || Value::known(row.noname),
                    )?;

                    let rlc_val_a = challenge_r.map(|r| {
                        let mut rlc = F::ZERO;
                        let mut r_power = F::ONE;
                        for byte in row.rlc_a.iter() {
                            rlc += F::from(*byte as u64) * r_power;
                            r_power *= r;
                        }
                        rlc
                    });

                    let rlc_val_b = challenge_r.map(|r| {
                        let mut rlc = F::ZERO;
                        let mut r_power = F::ONE;
                        for byte in row.rlc_b.iter() {
                            rlc += F::from(*byte as u64) * r_power;
                            r_power *= r;
                        }
                        rlc
                    });

                    let rlc_val_c = challenge_r.map(|r| {
                        let mut rlc = F::ZERO;
                        let mut r_power = F::ONE;
                        for byte in row.rlc_c.iter() {
                            rlc += F::from(*byte as u64) * r_power;
                            r_power *= r;
                        }
                        rlc
                    });

                    region.assign_advice(|| "rlc_a", self.rlc_a, offset, || rlc_val_a)?;

                    region.assign_advice(|| "rlc_b", self.rlc_b, offset, || rlc_val_b)?;

                    region.assign_advice(|| "rlc_c", self.rlc_c, offset, || rlc_val_c)?;

                    for i in 0..4 {
                        region.assign_advice(
                            || "pac_a",
                            self.pac_a[i],
                            offset,
                            || Value::known(row.pac_a[i]),
                        )?;

                        region.assign_advice(
                            || "pac_b",
                            self.pac_b[i],
                            offset,
                            || Value::known(row.pac_b[i]),
                        )?;

                        region.assign_advice(
                            || "pac_c",
                            self.pac_c[i],
                            offset,
                            || Value::known(row.pac_c[i]),
                        )?;

                        region.assign_advice(
                            || "pac_carry",
                            self.pac_carry[i],
                            offset,
                            || Value::known(row.pac_carry[i]),
                        )?;

                        region.assign_advice(
                            || "pac_rem",
                            self.pac_rem[i],
                            offset,
                            || Value::known(row.pac_rem[i]),
                        )?;
                        region.assign_advice(
                            || "pac_diff",
                            self.pac_diff[i],
                            offset,
                            || Value::known(row.pac_diff[i]),
                        )?;
                    }
                }

                Ok(())
            },
        )
    }
}

#[derive(Debug, Clone)]
struct CopyTool_values<F: PrimeField> {
    pub q: F,
    pub switch: F,
    pub isfirst_fixed: F,
    pub isfirst: F,
    pub islast: F,
    pub rwc: F,
    pub address_write: F,
    pub address_read: F,
    pub address_end: F,
    pub iswrite: F,
    pub ismem: F,
    pub istx: F,
    pub callid_read: F,
    pub callid_write: F,
    pub bytesleft: F,
    pub value: F,
    pub ispad: F,
    pub inv: F,
    pub limb_1: F,
    pub limb_2: F,
}

impl<F: PrimeField> CopyTool_values<F> {
    fn without_values(&self) -> Self {
        Self {
            switch: F::ZERO,
            isfirst: F::ZERO,
            islast: F::ZERO,
            rwc: F::ZERO,
            address_write: F::ZERO,
            address_read: F::ZERO,
            address_end: F::ZERO,
            iswrite: F::ZERO,
            ismem: F::ZERO,
            istx: F::ZERO,
            callid_read: F::ZERO,
            callid_write: F::ZERO,
            bytesleft: F::ZERO,
            value: F::ZERO,
            ispad: F::ZERO,
            inv: F::ZERO,
            limb_1: F::ZERO,
            limb_2: F::ZERO,
            q: self.q,
            isfirst_fixed: self.isfirst_fixed,
        }
    }
}

#[derive(Debug, Clone)]
struct CopyTool_Chip<F: PrimeField> {
    _ph: PhantomData<F>,
    q: Selector,
    switch: Column<Advice>,
    isfirst_fixed: Column<Fixed>,
    isfirst: Column<Advice>,
    islast: Column<Advice>,
    rwc: Column<Advice>,
    address_write: Column<Advice>,
    address_read: Column<Advice>,
    address_end: Column<Advice>,
    iswrite: Column<Advice>,
    ismem: Column<Advice>,
    istx: Column<Advice>,
    callid_read: Column<Advice>,
    callid_write: Column<Advice>,
    bytesleft: Column<Advice>,
    value: Column<Advice>,
    ispad: Column<Advice>,
    inv: Column<Advice>,
    limb_1: Column<Advice>,
    limb_2: Column<Advice>,
}

impl<F: PrimeField> CopyTool_Chip<F> {
    fn configure(
        meta: &mut ConstraintSystem<F>,
        q: Selector,
        switch: Column<Advice>,
        isfirst_fixed: Column<Fixed>,
        isfirst: Column<Advice>,
        islast: Column<Advice>,
        rwc: Column<Advice>,
        address_write: Column<Advice>,
        address_read: Column<Advice>,
        address_end: Column<Advice>,
        iswrite: Column<Advice>,
        ismem: Column<Advice>,
        istx: Column<Advice>,
        callid_read: Column<Advice>,
        callid_write: Column<Advice>,
        bytesleft: Column<Advice>,
        value: Column<Advice>,
        ispad: Column<Advice>,
        inv: Column<Advice>,
        limb_1: Column<Advice>,
        limb_2: Column<Advice>,
    ) -> Self {
        meta.create_gate("CopyTool_gates", |meta| {
            let q = meta.query_selector(q);
            let switch_cur = meta.query_advice(switch, Rotation::cur());
            let switch_next = meta.query_advice(switch, Rotation::next());
            let gate = q.clone() * switch_cur.clone();
            let isfirst_fixed = meta.query_fixed(isfirst_fixed, Rotation::cur());
            let isfirst_cur = meta.query_advice(isfirst, Rotation::cur());
            let isfirst_next = meta.query_advice(isfirst, Rotation::next());
            let islast_cur = meta.query_advice(islast, Rotation::cur());
            let islast_next = meta.query_advice(islast, Rotation::next());
            let rwc_cur = meta.query_advice(rwc, Rotation::cur());
            let rwc_next = meta.query_advice(rwc, Rotation::next());
            let address_write_cur = meta.query_advice(address_write, Rotation::cur());
            let address_write_next = meta.query_advice(address_write, Rotation::next());
            let address_write_2 = meta.query_advice(address_write, Rotation(2));
            let address_read_cur = meta.query_advice(address_read, Rotation::cur());
            let address_read_next = meta.query_advice(address_read, Rotation::next());
            let address_read_2 = meta.query_advice(address_read, Rotation(2));
            let address_end_cur = meta.query_advice(address_end, Rotation::cur());
            let address_end_next = meta.query_advice(address_end, Rotation::next());
            let iswrite_cur = meta.query_advice(iswrite, Rotation::cur());
            let iswrite_next = meta.query_advice(iswrite, Rotation::next());
            let ismem_cur = meta.query_advice(ismem, Rotation::cur());
            let ismem_next = meta.query_advice(ismem, Rotation::next());
            let istx_cur = meta.query_advice(istx, Rotation::cur());
            let istx_next = meta.query_advice(istx, Rotation::next());
            let callid_read_cur = meta.query_advice(callid_read, Rotation::cur());
            let callid_read_next = meta.query_advice(callid_read, Rotation::next());
            let callid_write_cur = meta.query_advice(callid_write, Rotation::cur());
            let callid_write_next = meta.query_advice(callid_write, Rotation::next());
            let bytesleft_cur = meta.query_advice(bytesleft, Rotation::cur());
            let bytesleft_next = meta.query_advice(bytesleft, Rotation::next());
            let value_cur = meta.query_advice(value, Rotation::cur());
            let value_next = meta.query_advice(value, Rotation::next());
            let ispad = meta.query_advice(ispad, Rotation::cur());
            let inv = meta.query_advice(inv, Rotation::cur());
            let limb_1 = meta.query_advice(limb_1, Rotation::cur());
            let limb_2 = meta.query_advice(limb_2, Rotation::cur());

            let one = Expression::Constant(F::ONE);
            let two_pow_16 = Expression::Constant(F::from(1u64 << 16));
            vec![
                (gate.clone() * isfirst_fixed.clone() * (one.clone() - isfirst_cur.clone())),
                (gate.clone() * isfirst_cur.clone() * islast_cur.clone()),
                (gate.clone() * (isfirst_next.clone() - islast_cur.clone())),
                (gate.clone() * (one.clone() - isfirst_cur.clone()) * isfirst_cur.clone()),
                (gate.clone() * (one.clone() - islast_cur.clone()) * islast_cur.clone()),
                (gate.clone() * (one.clone() - ismem_cur.clone()) * ismem_cur.clone()),
                (gate.clone() * (one.clone() - istx_cur.clone()) * istx_cur.clone()),
                (gate.clone() * (one.clone() - iswrite_cur.clone()) * iswrite_cur.clone()),
                (gate.clone() * (one.clone() - ispad.clone()) * ispad.clone()),
                (gate.clone() * (one.clone() - switch_cur.clone()) * switch_cur.clone()),
                (gate.clone()
                    * (one.clone() - islast_cur.clone())
                    * (ismem_next.clone() - ismem_cur.clone())),
                (gate.clone()
                    * (one.clone() - islast_cur.clone())
                    * (istx_next.clone() - istx_cur.clone())),
                (gate.clone()
                    * (one.clone() - islast_cur.clone())
                    * (callid_read_next.clone() - callid_read_cur.clone())),
                (gate.clone()
                    * (one.clone() - islast_cur.clone())
                    * (callid_write_next.clone() - callid_write_cur.clone())),
                (gate.clone()
                    * (one.clone() - islast_cur.clone())
                    * (rwc_next.clone() - rwc_cur.clone() - one.clone()
                        + (one.clone() - iswrite_cur.clone()) * istx_cur.clone())),
                (gate.clone()
                    * iswrite_cur.clone()
                    * (one.clone() - islast_cur.clone())
                    * (address_write_2.clone() - address_write_cur.clone() - one.clone())),
                (gate.clone()
                    * (one.clone() - iswrite_cur.clone())
                    * (one.clone() - islast_next.clone())
                    * (address_read_2.clone() - address_read_cur.clone() - one.clone())),
                (gate.clone() * iswrite_cur.clone() * iswrite_next.clone()),
                (gate.clone()
                    * (one.clone() - iswrite_cur.clone())
                    * (one.clone() - iswrite_next.clone())),
                (gate.clone() * isfirst_cur.clone() * iswrite_cur.clone()),
                (gate.clone()
                    * (one.clone() - iswrite_cur.clone())
                    * (bytesleft_next.clone() - bytesleft_cur.clone())),
                (gate.clone()
                    * iswrite_cur.clone()
                    * (one.clone() - islast_cur.clone())
                    * (bytesleft_next.clone() - bytesleft_cur.clone() + one.clone())), // degree 5
                (gate.clone()
                    * iswrite_cur.clone()
                    * ((bytesleft_cur.clone() - one.clone()) * inv.clone()
                        - (one.clone() - islast_cur.clone()))), // redundant
                (gate.clone()
                    * iswrite_cur.clone()
                    * islast_cur.clone()
                    * (bytesleft_cur.clone() - one.clone())),
                (gate.clone()
                    * (one.clone() - islast_cur.clone())
                    * (address_end_next.clone() - address_end_cur.clone())),
                (gate.clone()
                    * (one.clone() - iswrite_cur.clone())
                    * (one.clone() - ispad.clone())
                    * ((address_end_cur.clone() - address_read_cur.clone())
                        - limb_1.clone()
                        - limb_2.clone() * two_pow_16.clone()
                        - one.clone())),
                (gate.clone()
                    * (one.clone() - iswrite_cur.clone())
                    * ispad.clone()
                    * ((address_read_cur.clone() - address_end_cur.clone())
                        - limb_1.clone()
                        - limb_2.clone() * two_pow_16.clone())),
                (gate.clone() * iswrite_cur.clone() * ispad.clone()),
                (gate.clone()
                    * (one.clone() - iswrite_cur.clone())
                    * (value_next.clone() - value_cur.clone())),
                (gate.clone()
                    * (one.clone() - iswrite_cur.clone())
                    * (address_write_next.clone() - address_write_cur.clone())),
                (gate.clone()
                    * (one.clone() - iswrite_cur.clone())
                    * (address_read_next.clone() - address_read_cur.clone())),
                (q.clone()
                    * (switch_next.clone() - switch_cur.clone())
                    * (one.clone() + switch_next.clone() - switch_cur.clone())),
                (q.clone()
                    * (switch_next.clone() - switch_cur.clone())
                    * (one.clone() - islast_cur.clone())),
                (gate.clone() * ispad.clone() * value_cur.clone()),
                (gate.clone() * (ismem_cur.clone() + istx_cur.clone() - one.clone())),
                //              ((one.clone() - q.clone()) * ispad.clone()),
                //              ((one.clone() - istx_cur.clone()) * ispad.clone()),
                (q.clone() * (one.clone() - switch_cur.clone()) * ispad.clone()),
            ]
        });

        Self {
            _ph: PhantomData,
            q,
            switch,
            isfirst_fixed,
            isfirst,
            islast,
            rwc,
            address_write,
            address_read,
            address_end,
            iswrite,
            ismem,
            istx,
            callid_read,
            callid_write,
            bytesleft,
            value,
            ispad,
            inv,
            limb_1,
            limb_2,
        }
    }
    pub fn assign(
        &self,
        layouter: &mut impl Layouter<F>,
        trace: &[CopyTool_values<F>],
    ) -> Result<(), Error> {
        const COPY_ACTIVE_ROWS: usize = 50_000;
        const COPY_TAIL_GUARD_ROWS: usize = 2;
        const COPY_ASSIGNED_ROWS: usize = COPY_ACTIVE_ROWS + COPY_TAIL_GUARD_ROWS;

        let tail_row = trace.last().cloned().unwrap_or(CopyTool_values {
            q: F::ONE,
            switch: F::ZERO,
            isfirst_fixed: F::ZERO,
            isfirst: F::ZERO,
            islast: F::ZERO,
            rwc: F::ZERO,
            address_write: F::ZERO,
            address_read: F::ZERO,
            address_end: F::ZERO,
            iswrite: F::ZERO,
            ismem: F::ZERO,
            istx: F::ZERO,
            callid_read: F::ZERO,
            callid_write: F::ZERO,
            bytesleft: F::ZERO,
            value: F::ZERO,
            ispad: F::ZERO,
            inv: F::ZERO,
            limb_1: F::ZERO,
            limb_2: F::ZERO,
        });

        layouter.assign_region(
            || "CopyTool trace",
            |mut region| {
                for offset in 0..COPY_ACTIVE_ROWS {
                    self.q.enable(&mut region, offset)?;

                    let isfirst_value = if offset == 0 { F::ONE } else { F::ZERO };

                    region.assign_fixed(
                        || format!("copy isfirst_fixed at row {offset}"),
                        self.isfirst_fixed,
                        offset,
                        || Value::known(isfirst_value),
                    )?;
                }
                for offset in 0..COPY_ASSIGNED_ROWS {
                    let row = trace.get(offset).unwrap_or(&tail_row);

                    region.assign_advice(
                        || format!("copy switch at row {offset}"),
                        self.switch,
                        offset,
                        || Value::known(row.switch),
                    )?;

                    region.assign_advice(
                        || format!("copy isfirst at row {offset}"),
                        self.isfirst,
                        offset,
                        || Value::known(row.isfirst),
                    )?;

                    region.assign_advice(
                        || format!("copy islast at row {offset}"),
                        self.islast,
                        offset,
                        || Value::known(row.islast),
                    )?;

                    region.assign_advice(
                        || format!("copy rwc at row {offset}"),
                        self.rwc,
                        offset,
                        || Value::known(row.rwc),
                    )?;

                    region.assign_advice(
                        || format!("copy address_write at row {offset}"),
                        self.address_write,
                        offset,
                        || Value::known(row.address_write),
                    )?;

                    region.assign_advice(
                        || format!("copy address_read at row {offset}"),
                        self.address_read,
                        offset,
                        || Value::known(row.address_read),
                    )?;

                    region.assign_advice(
                        || format!("copy address_end at row {offset}"),
                        self.address_end,
                        offset,
                        || Value::known(row.address_end),
                    )?;

                    region.assign_advice(
                        || format!("copy iswrite at row {offset}"),
                        self.iswrite,
                        offset,
                        || Value::known(row.iswrite),
                    )?;

                    region.assign_advice(
                        || format!("copy ismem at row {offset}"),
                        self.ismem,
                        offset,
                        || Value::known(row.ismem),
                    )?;

                    region.assign_advice(
                        || format!("copy istx at row {offset}"),
                        self.istx,
                        offset,
                        || Value::known(row.istx),
                    )?;

                    region.assign_advice(
                        || format!("copy callid_read at row {offset}"),
                        self.callid_read,
                        offset,
                        || Value::known(row.callid_read),
                    )?;

                    region.assign_advice(
                        || format!("copy callid_write at row {offset}"),
                        self.callid_write,
                        offset,
                        || Value::known(row.callid_write),
                    )?;

                    region.assign_advice(
                        || format!("copy bytesleft at row {offset}"),
                        self.bytesleft,
                        offset,
                        || Value::known(row.bytesleft),
                    )?;

                    region.assign_advice(
                        || format!("copy value at row {offset}"),
                        self.value,
                        offset,
                        || Value::known(row.value),
                    )?;

                    region.assign_advice(
                        || format!("copy ispad at row {offset}"),
                        self.ispad,
                        offset,
                        || Value::known(row.ispad),
                    )?;

                    region.assign_advice(
                        || format!("copy inv at row {offset}"),
                        self.inv,
                        offset,
                        || Value::known(row.inv),
                    )?;

                    region.assign_advice(
                        || format!("copy limb_1 at row {offset}"),
                        self.limb_1,
                        offset,
                        || Value::known(row.limb_1),
                    )?;

                    region.assign_advice(
                        || format!("copy limb_2 at row {offset}"),
                        self.limb_2,
                        offset,
                        || Value::known(row.limb_2),
                    )?;
                }

                Ok(())
            },
        )
    }
}

#[derive(Debug, Clone)]
struct Range_Table0<F: PrimeField> {
    _ph: PhantomData<F>,
    range0: TableColumn,
}

impl<F: PrimeField> Range_Table0<F> {
    fn configure(range0: TableColumn) -> Self {
        Self {
            _ph: PhantomData,
            range0,
        }
    }

    fn load_range_table(
        &self,
        layouter: &mut impl Layouter<F>,
        max_difference: u64,
    ) -> Result<(), Error> {
        layouter.assign_table(
            || "Populate Static Range Table",
            |mut table| {
                for i in 0..=max_difference {
                    table.assign_cell(
                        || format!("range0 value {}", i),
                        self.range0,
                        i as usize,
                        || Value::known(F::from(i)),
                    )?;
                }
                Ok(())
            },
        )
    }
}

#[derive(Debug, Clone)]
struct Range_Table8<F: PrimeField> {
    _ph: PhantomData<F>,
    range8: TableColumn,
}

impl<F: PrimeField> Range_Table8<F> {
    fn configure(range8: TableColumn) -> Self {
        Self {
            _ph: PhantomData,
            range8,
        }
    }

    fn load_range_table(
        &self,
        layouter: &mut impl Layouter<F>,
        max_difference: u64,
    ) -> Result<(), Error> {
        layouter.assign_table(
            || "Populate Static Range Table",
            |mut table| {
                for i in 0..=max_difference {
                    table.assign_cell(
                        || format!("range8 value {}", i),
                        self.range8,
                        i as usize,
                        || Value::known(F::from(i)),
                    )?;
                }
                Ok(())
            },
        )
    }
}

#[derive(Debug, Clone)]
struct Bitwise_values<F: PrimeField> {
    pac_a: F,
    pac_b: F,
    pac_c: F,
}

#[derive(Debug, Clone)]
struct Range_Table_Bitwise<F: PrimeField> {
    _ph: PhantomData<F>,
    pac_a: TableColumn,
    pac_b: TableColumn,
    pac_c: TableColumn,
}

impl<F: PrimeField> Range_Table_Bitwise<F> {
    fn configure(pac_a: TableColumn, pac_b: TableColumn, pac_c: TableColumn) -> Self {
        Self {
            _ph: PhantomData,
            pac_a,
            pac_b,
            pac_c,
        }
    }

    fn load_bitwise_table(
        &self,
        layouter: &mut impl Layouter<F>,
        op: fn(u8, u8) -> u8,
    ) -> Result<(), Error> {
        layouter.assign_table(
            || "bitwise table",
            |mut table| {
                let mut offset = 0;

                for a in 0u16..256 {
                    for b in 0u16..256 {
                        let a = a as u8;
                        let b = b as u8;
                        let c = op(a, b);

                        table.assign_cell(
                            || "pac_a",
                            self.pac_a,
                            offset,
                            || Value::known(F::from(a as u64)),
                        )?;

                        table.assign_cell(
                            || "pac_b",
                            self.pac_b,
                            offset,
                            || Value::known(F::from(b as u64)),
                        )?;

                        table.assign_cell(
                            || "pac_c",
                            self.pac_c,
                            offset,
                            || Value::known(F::from(c as u64)),
                        )?;

                        offset += 1;
                    }
                }

                Ok(())
            },
        )
    }
    fn load_not_table(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        layouter.assign_table(
            || "not table",
            |mut table| {
                table.assign_cell(|| "dummy pac_a", self.pac_a, 0, || Value::known(F::ZERO))?;
                table.assign_cell(|| "dummy pac_b", self.pac_b, 0, || Value::known(F::ZERO))?;
                table.assign_cell(|| "dummy pac_c", self.pac_c, 0, || Value::known(F::ZERO))?;

                for (offset, a) in (0u16..256).enumerate() {
                    let a = a as u8;
                    let c = !a;
                    let offset = offset + 1;

                    table.assign_cell(
                        || "pac_a",
                        self.pac_a,
                        offset,
                        || Value::known(F::from(a as u64)),
                    )?;

                    table.assign_cell(|| "pac_b", self.pac_b, offset, || Value::known(F::ZERO))?;

                    table.assign_cell(
                        || "pac_c",
                        self.pac_c,
                        offset,
                        || Value::known(F::from(c as u64)),
                    )?;
                }

                Ok(())
            },
        )
    }
}

#[derive(Debug, Clone)]
struct ROM_table_values<F: PrimeField> {
    pub byte: F,
    pub begintx: F,
    pub endtx: F,
    pub iscall: F,
    pub isreturn: F,
    pub returndatacopy: F,
    pub calldatacopy: F,
    pub isadd: F,
    pub issub: F,
    pub ismul: F,
    pub isdiv: F,
    pub islt: F,
    pub iseq: F,
    pub isand: F,
    pub isor: F,
    pub isxor: F,
    pub isnot: F,
    pub isjump: F,
    pub isjumpdest: F,
    pub isjumpcon: F,
    pub ismload: F,
    pub ismstore: F,
    pub ismstore8: F,
    pub isread: F,
    pub iswrite: F,
    pub ishalt: F,
}

#[derive(Debug, Clone)]
struct ROM_Table<F: PrimeField> {
    _ph: PhantomData<F>,
    byte: TableColumn,
    begintx: TableColumn,
    endtx: TableColumn,
    iscall: TableColumn,
    isreturn: TableColumn,
    returndatacopy: TableColumn,
    calldatacopy: TableColumn,
    isadd: TableColumn,
    issub: TableColumn,
    ismul: TableColumn,
    isdiv: TableColumn,
    islt: TableColumn,
    iseq: TableColumn,
    isand: TableColumn,
    isor: TableColumn,
    isxor: TableColumn,
    isnot: TableColumn,
    isjump: TableColumn,
    isjumpdest: TableColumn,
    isjumpcon: TableColumn,
    ismload: TableColumn,
    ismstore: TableColumn,
    ismstore8: TableColumn,
    isread: TableColumn,
    iswrite: TableColumn,
    ishalt: TableColumn,
}

impl<F: PrimeField> ROM_Table<F> {
    fn configure(
        byte: TableColumn,
        begintx: TableColumn,
        endtx: TableColumn,
        iscall: TableColumn,
        isreturn: TableColumn,
        returndatacopy: TableColumn,
        calldatacopy: TableColumn,
        isadd: TableColumn,
        issub: TableColumn,
        ismul: TableColumn,
        isdiv: TableColumn,
        islt: TableColumn,
        iseq: TableColumn,
        isand: TableColumn,
        isor: TableColumn,
        isxor: TableColumn,
        isnot: TableColumn,
        isjump: TableColumn,
        isjumpdest: TableColumn,
        isjumpcon: TableColumn,
        ismload: TableColumn,
        ismstore: TableColumn,
        ismstore8: TableColumn,
        isread: TableColumn,
        iswrite: TableColumn,
        ishalt: TableColumn,
    ) -> Self {
        Self {
            _ph: PhantomData,
            byte,
            begintx,
            endtx,
            iscall,
            isreturn,
            returndatacopy,
            calldatacopy,
            isadd,
            issub,
            ismul,
            isdiv,
            islt,
            iseq,
            isand,
            isor,
            isxor,
            isnot,
            isjump,
            isjumpdest,
            isjumpcon,
            ismload,
            ismstore,
            ismstore8,
            isread,
            iswrite,
            ishalt,
        }
    }

    pub fn load_rom_table(
        &self,
        layouter: &mut impl Layouter<F>,
        _trace: &[ROM_table_values<F>],
    ) -> Result<(), Error> {
        layouter.assign_table(
            || "Load ROM table",
            |mut table| {
                for offset in 0..256 {
                    let byte = F::from(offset as u64);

                    let begintx = if offset as u64 == OP_BEGIN_TX {
                        F::ONE
                    } else {
                        F::ZERO
                    };
                    let endtx = if offset as u64 == OP_END_TX {
                        F::ONE
                    } else {
                        F::ZERO
                    };

                    let iscall = if offset == 0xf1 { F::ONE } else { F::ZERO };
                    let isreturn = if offset == 0xf3 { F::ONE } else { F::ZERO };

                    let returndatacopy = if offset == 0x3e { F::ONE } else { F::ZERO };
                    let calldatacopy = if offset == 0x37 { F::ONE } else { F::ZERO };

                    let isadd = if offset == 0x01 { F::ONE } else { F::ZERO };
                    let issub = if offset == 0x03 { F::ONE } else { F::ZERO };
                    let ismul = if offset == 0x02 { F::ONE } else { F::ZERO };
                    let isdiv = if offset == 0x04 { F::ONE } else { F::ZERO };

                    let islt = if offset == 0x10 { F::ONE } else { F::ZERO };
                    let iseq = if offset == 0x14 { F::ONE } else { F::ZERO };

                    let isand = if offset == 0x16 { F::ONE } else { F::ZERO };
                    let isor = if offset == 0x17 { F::ONE } else { F::ZERO };
                    let isxor = if offset == 0x18 { F::ONE } else { F::ZERO };
                    let isnot = if offset == 0x19 { F::ONE } else { F::ZERO };

                    let isjump = if offset == 0x56 { F::ONE } else { F::ZERO };
                    let isjumpdest = if offset == 0x5b { F::ONE } else { F::ZERO };
                    let isjumpcon = if offset == 0x57 { F::ONE } else { F::ZERO };

                    let ismload = if offset == 0x51 { F::ONE } else { F::ZERO };
                    let ismstore = if offset == 0x52 { F::ONE } else { F::ZERO };
                    let ismstore8 = if offset == 0x53 { F::ONE } else { F::ZERO };

                    let isread = if offset as u64 == OP_READ {
                        F::ONE
                    } else {
                        F::ZERO
                    };
                    let iswrite = if offset as u64 == OP_WRITE {
                        F::ONE
                    } else {
                        F::ZERO
                    };

                    let ishalt = if offset as u64 == OP_HALT {
                        F::ONE
                    } else {
                        F::ZERO
                    };

                    table.assign_cell(|| "byte", self.byte, offset, || Value::known(byte))?;

                    table.assign_cell(
                        || "begintx",
                        self.begintx,
                        offset,
                        || Value::known(begintx),
                    )?;

                    table.assign_cell(|| "endtx", self.endtx, offset, || Value::known(endtx))?;

                    table.assign_cell(|| "iscall", self.iscall, offset, || Value::known(iscall))?;

                    table.assign_cell(
                        || "isreturn",
                        self.isreturn,
                        offset,
                        || Value::known(isreturn),
                    )?;

                    table.assign_cell(
                        || "returndatacopy",
                        self.returndatacopy,
                        offset,
                        || Value::known(returndatacopy),
                    )?;

                    table.assign_cell(
                        || "calldatacopy",
                        self.calldatacopy,
                        offset,
                        || Value::known(calldatacopy),
                    )?;

                    table.assign_cell(|| "isadd", self.isadd, offset, || Value::known(isadd))?;

                    table.assign_cell(|| "issub", self.issub, offset, || Value::known(issub))?;

                    table.assign_cell(|| "ismul", self.ismul, offset, || Value::known(ismul))?;

                    table.assign_cell(|| "isdiv", self.isdiv, offset, || Value::known(isdiv))?;

                    table.assign_cell(|| "islt", self.islt, offset, || Value::known(islt))?;

                    table.assign_cell(|| "iseq", self.iseq, offset, || Value::known(iseq))?;

                    table.assign_cell(|| "isand", self.isand, offset, || Value::known(isand))?;

                    table.assign_cell(|| "isor", self.isor, offset, || Value::known(isor))?;

                    table.assign_cell(|| "isxor", self.isxor, offset, || Value::known(isxor))?;

                    table.assign_cell(|| "isnot", self.isnot, offset, || Value::known(isnot))?;

                    table.assign_cell(|| "isjump", self.isjump, offset, || Value::known(isjump))?;

                    table.assign_cell(
                        || "isjumpdest",
                        self.isjumpdest,
                        offset,
                        || Value::known(isjumpdest),
                    )?;

                    table.assign_cell(
                        || "isjumpcon",
                        self.isjumpcon,
                        offset,
                        || Value::known(isjumpcon),
                    )?;

                    table.assign_cell(
                        || "ismload",
                        self.ismload,
                        offset,
                        || Value::known(ismload),
                    )?;

                    table.assign_cell(
                        || "ismstore",
                        self.ismstore,
                        offset,
                        || Value::known(ismstore),
                    )?;

                    table.assign_cell(
                        || "ismstore8",
                        self.ismstore8,
                        offset,
                        || Value::known(ismstore8),
                    )?;

                    table.assign_cell(|| "isread", self.isread, offset, || Value::known(isread))?;

                    table.assign_cell(
                        || "iswrite",
                        self.iswrite,
                        offset,
                        || Value::known(iswrite),
                    )?;

                    table.assign_cell(|| "ishalt", self.ishalt, offset, || Value::known(ishalt))?;
                }

                macro_rules! assign_dummy_rom_cell {
                    ($name:expr, $column:expr) => {
                        table.assign_cell(|| $name, $column, 256, || Value::known(F::ZERO))?;
                    };
                }

                assign_dummy_rom_cell!("dummy byte", self.byte);
                assign_dummy_rom_cell!("dummy begintx", self.begintx);
                assign_dummy_rom_cell!("dummy endtx", self.endtx);
                assign_dummy_rom_cell!("dummy iscall", self.iscall);
                assign_dummy_rom_cell!("dummy isreturn", self.isreturn);
                assign_dummy_rom_cell!("dummy returndatacopy", self.returndatacopy);
                assign_dummy_rom_cell!("dummy calldatacopy", self.calldatacopy);
                assign_dummy_rom_cell!("dummy isadd", self.isadd);
                assign_dummy_rom_cell!("dummy issub", self.issub);
                assign_dummy_rom_cell!("dummy ismul", self.ismul);
                assign_dummy_rom_cell!("dummy isdiv", self.isdiv);
                assign_dummy_rom_cell!("dummy islt", self.islt);
                assign_dummy_rom_cell!("dummy iseq", self.iseq);
                assign_dummy_rom_cell!("dummy isand", self.isand);
                assign_dummy_rom_cell!("dummy isor", self.isor);
                assign_dummy_rom_cell!("dummy isxor", self.isxor);
                assign_dummy_rom_cell!("dummy isnot", self.isnot);
                assign_dummy_rom_cell!("dummy isjump", self.isjump);
                assign_dummy_rom_cell!("dummy isjumpdest", self.isjumpdest);
                assign_dummy_rom_cell!("dummy isjumpcon", self.isjumpcon);
                assign_dummy_rom_cell!("dummy ismload", self.ismload);
                assign_dummy_rom_cell!("dummy ismstore", self.ismstore);
                assign_dummy_rom_cell!("dummy ismstore8", self.ismstore8);
                assign_dummy_rom_cell!("dummy isread", self.isread);
                assign_dummy_rom_cell!("dummy iswrite", self.iswrite);
                assign_dummy_rom_cell!("dummy ishalt", self.ishalt);

                Ok(())
            },
        )
    }
}

#[derive(Debug, Clone)]
struct Byte_Table<F: PrimeField> {
    _ph: PhantomData<F>,

    q_byte: Selector,
    q_byte_step: Selector,
    q_byte_first: Selector,
    q_byte_last: Selector,

    active: Column<Instance>,
    call_id: Column<Instance>,
    pc: Column<Instance>,
    limb1: Column<Instance>,
    limb2: Column<Instance>,
    limb3: Column<Instance>,
    limb4: Column<Instance>,
    iscode: Column<Instance>,
}

#[derive(Debug, Clone)]
struct Byte_table_values<F: PrimeField> {
    pub call_id: F,
    pub pc: F,
    pub limb1: F,
    pub limb2: F,
    pub limb3: F,
    pub limb4: F,
    pub iscode: F,
}

impl<F: PrimeField> Byte_Table<F> {
    fn configure(
        _meta: &mut ConstraintSystem<F>,
        q_byte: Selector,
        q_byte_step: Selector,
        q_byte_first: Selector,
        q_byte_last: Selector,
        active: Column<Instance>,
        call_id: Column<Instance>,
        pc: Column<Instance>,
        limb1: Column<Instance>,
        limb2: Column<Instance>,
        limb3: Column<Instance>,
        limb4: Column<Instance>,
        iscode: Column<Instance>,
    ) -> Self {
        Self {
            _ph: PhantomData,
            q_byte,
            q_byte_step,
            q_byte_first,
            q_byte_last,
            active,
            call_id,
            pc,
            limb1,
            limb2,
            limb3,
            limb4,
            iscode,
        }
    }

    pub fn assign(
        &self,
        _layouter: &mut impl Layouter<F>,
        _trace: &[Byte_table_values<F>],
    ) -> Result<(), Error> {
        Ok(())
    }
}

#[derive(Debug, Clone)]
struct TXTrace_values<F: PrimeField> {
    pub q: F,
    pub txid: F,
    pub tag: F,
    pub index: F,
    pub value_low: F,
    pub value_high: F,
}

impl<F: PrimeField> TXTrace_values<F> {
    fn without_values(&self) -> Self {
        Self {
            q: self.q,
            txid: F::ZERO,
            tag: F::ZERO,
            index: F::ZERO,
            value_low: F::ZERO,
            value_high: F::ZERO,
        }
    }
}

#[derive(Debug, Clone)]
struct TXTrace_Chip<F: PrimeField> {
    _ph: PhantomData<F>,
    active: Column<Instance>,
    txid: Column<Instance>,
    tag: Column<Instance>,
    index: Column<Instance>,
    value_low: Column<Instance>,
    value_high: Column<Instance>,
}

impl<F: PrimeField> TXTrace_Chip<F> {
    fn configure(
        _meta: &mut ConstraintSystem<F>,
        active: Column<Instance>,
        txid: Column<Instance>,
        tag: Column<Instance>,
        index: Column<Instance>,
        value_low: Column<Instance>,
        value_high: Column<Instance>,
    ) -> Self {
        Self {
            _ph: PhantomData,
            active,
            txid,
            tag,
            index,
            value_low,
            value_high,
        }
    }

    pub fn assign(
        &self,
        _layouter: &mut impl Layouter<F>,
        trace: &[TXTrace_values<F>],
    ) -> Result<(), Error> {
        let _ = (
            self.active,
            self.txid,
            self.tag,
            self.index,
            self.value_low,
            self.value_high,
        );

        if trace.len() > MAX_TX_ROWS {
            return Err(Error::Synthesis);
        }

        Ok(())
    }
}

#[derive(Debug, Clone)]
struct PublicOutput_values<F: PrimeField> {
    pub active: F,
    pub tag: F,
    pub address: F,
    pub iswrite: F,
    pub value: [u64; 4],
    pub rw_counter: F,
}

#[derive(Debug, Clone)]
struct PublicOutput_Chip<F: PrimeField> {
    _ph: PhantomData<F>,
    active: Column<Instance>,
    tag: Column<Instance>,
    address: Column<Instance>,
    iswrite: Column<Instance>,
    value_0: Column<Instance>,
    value_1: Column<Instance>,
    value_2: Column<Instance>,
    value_3: Column<Instance>,
    rw_counter: Column<Instance>,
}

impl<F: PrimeField> PublicOutput_Chip<F> {
    fn configure(
        meta: &mut ConstraintSystem<F>,
        active: Column<Instance>,
        tag: Column<Instance>,
        address: Column<Instance>,
        iswrite: Column<Instance>,
        value_0: Column<Instance>,
        value_1: Column<Instance>,
        value_2: Column<Instance>,
        value_3: Column<Instance>,
        rw_counter: Column<Instance>,
    ) -> Self {
        meta.create_gate("public_output_gates", |meta| {
            let active_cur = meta.query_instance(active, Rotation::cur());
            let tag_cur = meta.query_instance(tag, Rotation::cur());
            let one = Expression::Constant(F::ONE);
            let two = Expression::Constant(F::from(2u64));

            vec![
                active_cur.clone() * (one.clone() - active_cur.clone()),
                active_cur * (tag_cur.clone() - one) * (tag_cur - two),
            ]
        });

        Self {
            _ph: PhantomData,
            active,
            tag,
            address,
            iswrite,
            value_0,
            value_1,
            value_2,
            value_3,
            rw_counter,
        }
    }

    pub fn assign(
        &self,
        _layouter: &mut impl Layouter<F>,
        trace: &[PublicOutput_values<F>],
    ) -> Result<(), Error> {
        let _ = (
            self.active,
            self.tag,
            self.address,
            self.iswrite,
            self.value_0,
            self.value_1,
            self.value_2,
            self.value_3,
            self.rw_counter,
        );

        if trace.len() > MAX_PUBLIC_OUTPUT_ROWS {
            return Err(Error::Synthesis);
        }

        Ok(())
    }
}
////////////////////
fn rlc_from_u64_limbs<F: PrimeField>(limbs: &[u64; 4], challenge: F) -> F {
    let mut result = F::ZERO;
    let mut power = F::ONE;

    for limb in limbs {
        result += F::from(*limb) * power;
        power *= challenge;
    }

    result
}

fn rw_fingerprint<F: PrimeField>(
    tag: F,
    call_id: F,
    address: F,
    field_tag: F,
    storage_key: F,
    rw_counter: F,
    iswrite: F,
    value: F,
    isend: F,
    r: F,
    b: F,
) -> F {
    let r2 = r * r;
    let r3 = r2 * r;
    let r4 = r2 * r2;
    let r5 = r4 * r;
    let r6 = r4 * r2;
    let r7 = r4 * r3;
    let r8 = r4 * r4;

    tag + r * call_id
        + r2 * address
        + r3 * field_tag
        + r4 * storage_key
        + r5 * rw_counter
        + r6 * iswrite
        + r7 * value
        + r8 * isend
        + b
}
#[derive(Debug, Clone)]
struct RWTrace_values<F: PrimeField> {
    pub tag: F,
    pub call_id: F,
    pub address: F,
    pub field_tag: F,
    pub storage_key: F,
    pub rw_counter: F,
    pub iswrite: F,
    pub value: [u64; 4],
    pub isend: F,
}

impl<F: PrimeField> RWTrace_values<F> {
    fn without_values(&self) -> Self {
        Self {
            tag: F::ZERO,
            call_id: F::ZERO,
            address: F::ZERO,
            field_tag: F::ZERO,
            storage_key: F::ZERO,
            rw_counter: F::ZERO,
            iswrite: F::ZERO,
            value: [0u64; 4],
            isend: F::ZERO,
        }
    }

    fn terminal_padding_row() -> Self {
        Self {
            tag: F::ZERO,
            call_id: F::ZERO,
            address: F::ZERO,
            field_tag: F::ZERO,
            storage_key: F::ZERO,
            rw_counter: F::ZERO,
            iswrite: F::ZERO,
            value: [0u64; 4],
            isend: F::ONE,
        }
    }
}

#[derive(Debug, Clone)]
struct RWTrace_Chip<F: PrimeField> {
    _ph: PhantomData<F>,
    selector: Selector,
    isfirst: Column<Fixed>,
    tag: Column<Advice>,
    call_id: Column<Advice>,
    address: Column<Advice>,
    field_tag: Column<Advice>,
    storage_key: Column<Advice>,
    rw_counter: Column<Advice>,
    iswrite: Column<Advice>,
    value: Column<Advice>,
    isend: Column<Advice>,
    z: Column<Advice>,
}

impl<F: PrimeField> RWTrace_Chip<F> {
    fn configure(
        meta: &mut ConstraintSystem<F>,
        selector: Selector,
        isfirst: Column<Fixed>,
        tag: Column<Advice>,
        call_id: Column<Advice>,
        address: Column<Advice>,
        field_tag: Column<Advice>,
        storage_key: Column<Advice>,
        rw_counter: Column<Advice>,
        iswrite: Column<Advice>,
        value: Column<Advice>,
        isend: Column<Advice>,
        z: Column<Advice>,
        rc: Challenge,
        bc: Challenge,
    ) -> Self {
        meta.enable_equality(z);

        meta.create_gate("rw_trace_gates", |meta| {
            let q = meta.query_selector(selector);
            let isfirst = meta.query_fixed(isfirst, Rotation::cur());
            let tag = meta.query_advice(tag, Rotation::cur());
            let call_id = meta.query_advice(call_id, Rotation::cur());
            let address = meta.query_advice(address, Rotation::cur());
            let field_tag = meta.query_advice(field_tag, Rotation::cur());
            let storage_key = meta.query_advice(storage_key, Rotation::cur());
            let rw_counter_cur = meta.query_advice(rw_counter, Rotation::cur());
            let rw_counter_next = meta.query_advice(rw_counter, Rotation::next());
            let iswrite_cur = meta.query_advice(iswrite, Rotation::cur());
            let value = meta.query_advice(value, Rotation::cur());
            let isend_cur = meta.query_advice(isend, Rotation::cur());
            let isend_next = meta.query_advice(isend, Rotation::next());
            let z_cur = meta.query_advice(z, Rotation::cur());
            let z_next = meta.query_advice(z, Rotation::next());
            let r = meta.query_challenge(rc);
            let b = meta.query_challenge(bc);
            let one = Expression::Constant(F::ONE);
            let gate = q.clone() * (one.clone() - isend_cur.clone());
            let r2 = r.clone() * r.clone();
            let r3 = r2.clone() * r.clone();
            let r4 = r2.clone() * r2.clone();
            let r5 = r4.clone() * r.clone();
            let r6 = r4.clone() * r2.clone();
            let r7 = r6.clone() * r.clone();
            let r8 = r4.clone() * r4.clone();
            let fp = tag.clone()
                + r.clone() * call_id.clone()
                + r2.clone() * address.clone()
                + r3.clone() * field_tag.clone()
                + r4.clone() * storage_key.clone()
                + r5.clone() * rw_counter_cur.clone()
                + r6.clone() * iswrite_cur.clone()
                + r7.clone() * value.clone()
                + r8.clone() * isend_cur.clone()
                + b;

            let perm = z_cur.clone() * fp.clone() - z_next.clone();
            vec![
                (q.clone() * isfirst.clone() * (one.clone() - z_cur.clone())),
                (q.clone() * isfirst.clone() * rw_counter_cur.clone()),
                (q.clone() * iswrite_cur.clone() * (one.clone() - iswrite_cur.clone())),
                (q.clone() * isend_cur.clone() * (one.clone() - isend_cur.clone())),
                (q.clone()
                    * (rw_counter_next.clone()
                        - rw_counter_cur.clone()
                        - (one.clone() - isend_cur.clone()))),
                (q.clone() * isend_cur.clone() * (one.clone() - isend_next.clone())),
                (gate.clone() * perm.clone()),
                (q.clone() * isend_cur.clone() * (z_cur.clone() - z_next.clone())),
            ]
        });

        Self {
            _ph: PhantomData,
            selector,
            isfirst,
            tag,
            call_id,
            address,
            field_tag,
            storage_key,
            rw_counter,
            iswrite,
            value,
            isend,
            z,
        }
    }

    pub fn assign(
        &self,
        layouter: &mut impl Layouter<F>,
        trace: &[RWTrace_values<F>],
        challenge_r: Value<F>,
        challenge_b: Value<F>,
    ) -> Result<AssignedCell<F, F>, Error> {
        const RWTRACE_ACTIVE_ROWS: usize = 50_000;
        const RWTRACE_TAIL_GUARD_ROWS: usize = 1;

        let terminal_row = if let Some(last_state) = trace.last() {
            let sentinel_rw_counter = last_state.rw_counter + (F::ONE - last_state.isend);

            RWTrace_values {
                tag: F::ZERO,
                call_id: F::ZERO,
                address: F::ZERO,
                field_tag: F::ZERO,
                storage_key: F::ZERO,
                rw_counter: sentinel_rw_counter,
                iswrite: F::ZERO,
                value: [0u64; 4],
                isend: F::ONE,
            }
        } else {
            RWTrace_values {
                tag: F::ZERO,
                call_id: F::ZERO,
                address: F::ZERO,
                field_tag: F::ZERO,
                storage_key: F::ZERO,
                rw_counter: F::ZERO,
                iswrite: F::ZERO,
                value: [0u64; 4],
                isend: F::ONE,
            }
        };

        let mut trace_with_padding = trace.to_vec();
        if trace_with_padding.len() > RWTRACE_ACTIVE_ROWS {
            return Err(Error::Synthesis);
        }
        while trace_with_padding.len() < RWTRACE_ACTIVE_ROWS {
            trace_with_padding.push(terminal_row.clone());
        }
        for _ in 0..RWTRACE_TAIL_GUARD_ROWS {
            trace_with_padding.push(terminal_row.clone());
        }

        layouter.assign_region(
            || "Assign RW execution trace",
            |mut region| {
                let mut running_z = Value::known(F::ONE);

                let mut sentinel_z_cell: Option<AssignedCell<F, F>> = None;
                for offset in 0..RWTRACE_ACTIVE_ROWS {
                    self.selector.enable(&mut region, offset)?;

                    let isfirst_value = if offset == 0 { F::ONE } else { F::ZERO };

                    region.assign_fixed(
                        || format!("isfirst at row {offset}"),
                        self.isfirst,
                        offset,
                        || Value::known(isfirst_value),
                    )?;
                }

                for (offset, state) in trace_with_padding.iter().enumerate() {
                    region.assign_advice(
                        || format!("tag at row {offset}"),
                        self.tag,
                        offset,
                        || Value::known(state.tag),
                    )?;

                    region.assign_advice(
                        || format!("call_id at row {offset}"),
                        self.call_id,
                        offset,
                        || Value::known(state.call_id),
                    )?;

                    region.assign_advice(
                        || format!("address at row {offset}"),
                        self.address,
                        offset,
                        || Value::known(state.address),
                    )?;

                    region.assign_advice(
                        || format!("field_tag at row {offset}"),
                        self.field_tag,
                        offset,
                        || Value::known(state.field_tag),
                    )?;

                    region.assign_advice(
                        || format!("storage_key at row {offset}"),
                        self.storage_key,
                        offset,
                        || Value::known(state.storage_key),
                    )?;

                    region.assign_advice(
                        || format!("rw_counter at row {offset}"),
                        self.rw_counter,
                        offset,
                        || Value::known(state.rw_counter),
                    )?;

                    region.assign_advice(
                        || format!("iswrite at row {offset}"),
                        self.iswrite,
                        offset,
                        || Value::known(state.iswrite),
                    )?;

                    let value_limbs = state.value;

                    let value_rlc = challenge_r
                        .clone()
                        .map(move |r| rlc_from_u64_limbs::<F>(&value_limbs, r));

                    region.assign_advice(
                        || format!("value at row {offset}"),
                        self.value,
                        offset,
                        || value_rlc.clone(),
                    )?;

                    region.assign_advice(
                        || format!("isend at row {offset}"),
                        self.isend,
                        offset,
                        || Value::known(state.isend),
                    )?;

                    let current_z = running_z.clone();

                    let z_cell = region.assign_advice(
                        || format!("z at row {offset}"),
                        self.z,
                        offset,
                        || current_z.clone(),
                    )?;

                    if offset + 1 == RWTRACE_ACTIVE_ROWS {
                        sentinel_z_cell = Some(z_cell);
                    } else if offset + 1 < RWTRACE_ACTIVE_ROWS && state.isend != F::ONE {
                        let tag = state.tag;
                        let call_id = state.call_id;
                        let address = state.address;
                        let field_tag = state.field_tag;
                        let storage_key = state.storage_key;
                        let rw_counter = state.rw_counter;
                        let iswrite = state.iswrite;
                        let isend = state.isend;
                        let limbs = state.value;

                        let fingerprint =
                            challenge_r
                                .clone()
                                .zip(challenge_b.clone())
                                .map(move |(r, b)| {
                                    let value = rlc_from_u64_limbs::<F>(&limbs, r);

                                    rw_fingerprint(
                                        tag,
                                        call_id,
                                        address,
                                        field_tag,
                                        storage_key,
                                        rw_counter,
                                        iswrite,
                                        value,
                                        isend,
                                        r,
                                        b,
                                    )
                                });

                        running_z = running_z.zip(fingerprint).map(|(z, fp)| z * fp);
                    } else if offset + 1 < RWTRACE_ACTIVE_ROWS {
                        sentinel_z_cell = Some(z_cell);
                    }
                }

                sentinel_z_cell.ok_or(Error::Synthesis)
            },
        )
    }
}

#[derive(Debug, Clone)]
struct RWState_values<F: PrimeField> {
    pub isfirst: F,
    pub tag: F,
    pub call_id: F,
    pub isroot: F,
    pub address: F,
    pub field_tag: F,
    pub storage_key: F,
    pub rw_counter: F,
    pub tag_changed: F,
    pub call_id_changed: F,
    pub address_changed: F,
    pub field_tag_changed: F,
    pub storage_key_changed: F,
    pub rw_counter_changed: F,
    pub iswrite: F,
    pub value: [u64; 4],
    pub isend: F,
    pub z: F,
    pub limb_1: F,
    pub limb_2: F,
    pub limb_3: F,
    pub limb_4: F,
    pub limb_5: F,
    pub limb_6: F,
    pub limb_7: F,
    pub limb_8: F,
    pub limb_9: F,
    pub limb_10: F,
}

impl<F: PrimeField> RWState_values<F> {
    fn without_values(&self) -> Self {
        Self {
            isfirst: self.isfirst,
            tag: F::ZERO,
            call_id: F::from(2u64),
            isroot: F::ZERO,
            address: F::ZERO,
            field_tag: F::ZERO,
            storage_key: F::ZERO,
            rw_counter: F::ZERO,

            tag_changed: F::ZERO,
            call_id_changed: F::ZERO,
            address_changed: F::ZERO,
            field_tag_changed: F::ZERO,
            storage_key_changed: F::ZERO,
            rw_counter_changed: F::ZERO,

            iswrite: F::ZERO,
            value: [0u64; 4],
            isend: F::ZERO,
            z: self.z,

            limb_1: F::ZERO,
            limb_2: F::ZERO,
            limb_3: F::ZERO,
            limb_4: F::ZERO,
            limb_5: F::ZERO,
            limb_6: F::ZERO,
            limb_7: F::ZERO,
            limb_8: F::ZERO,
            limb_9: F::ZERO,
            limb_10: F::ZERO,
        }
    }

    fn terminal_padding_row() -> Self {
        Self {
            isfirst: F::ZERO,
            tag: F::ZERO,
            call_id: F::from(2u64),
            isroot: F::ZERO,
            address: F::ZERO,
            field_tag: F::ZERO,
            storage_key: F::ZERO,
            rw_counter: F::ZERO,
            tag_changed: F::ZERO,
            call_id_changed: F::ZERO,
            address_changed: F::ZERO,
            field_tag_changed: F::ZERO,
            storage_key_changed: F::ZERO,
            rw_counter_changed: F::ZERO,
            iswrite: F::ZERO,
            value: [0u64; 4],
            isend: F::ONE,
            z: F::ZERO,
            limb_1: F::ZERO,
            limb_2: F::ZERO,
            limb_3: F::ZERO,
            limb_4: F::ZERO,
            limb_5: F::ZERO,
            limb_6: F::ZERO,
            limb_7: F::ZERO,
            limb_8: F::ZERO,
            limb_9: F::ZERO,
            limb_10: F::ZERO,
        }
    }
}

#[derive(Debug, Clone)]
struct RWState_Chip<F: PrimeField> {
    _ph: PhantomData<F>,
    selector: Selector,
    isfirst: Column<Fixed>,
    tag: Column<Advice>,
    call_id: Column<Advice>,
    isroot: Column<Advice>,
    address: Column<Advice>,
    field_tag: Column<Advice>,
    storage_key: Column<Advice>,
    rw_counter: Column<Advice>,
    tag_changed: Column<Advice>,
    call_id_changed: Column<Advice>,
    address_changed: Column<Advice>,
    field_tag_changed: Column<Advice>,
    storage_key_changed: Column<Advice>,
    rw_counter_changed: Column<Advice>,
    iswrite: Column<Advice>,
    value: Column<Advice>,
    isend: Column<Advice>,
    z: Column<Advice>,
    limb_1: Column<Advice>,
    limb_2: Column<Advice>,
    limb_3: Column<Advice>,
    limb_4: Column<Advice>,
    limb_5: Column<Advice>,
    limb_6: Column<Advice>,
    limb_7: Column<Advice>,
    limb_8: Column<Advice>,
    limb_9: Column<Advice>,
    limb_10: Column<Advice>,
}

impl<F: PrimeField> RWState_Chip<F> {
    fn configure(
        meta: &mut ConstraintSystem<F>,
        selector: Selector,
        isfirst: Column<Fixed>,
        tag: Column<Advice>,
        call_id: Column<Advice>,
        isroot: Column<Advice>,
        address: Column<Advice>,
        field_tag: Column<Advice>,
        storage_key: Column<Advice>,
        rw_counter: Column<Advice>,
        tag_changed: Column<Advice>,
        call_id_changed: Column<Advice>,
        address_changed: Column<Advice>,
        field_tag_changed: Column<Advice>,
        storage_key_changed: Column<Advice>,
        rw_counter_changed: Column<Advice>,
        iswrite: Column<Advice>,
        value: Column<Advice>,
        isend: Column<Advice>,
        z: Column<Advice>,
        limb_1: Column<Advice>,
        limb_2: Column<Advice>,
        limb_3: Column<Advice>,
        limb_4: Column<Advice>,
        limb_5: Column<Advice>,
        limb_6: Column<Advice>,
        limb_7: Column<Advice>,
        limb_8: Column<Advice>,
        limb_9: Column<Advice>,
        limb_10: Column<Advice>,
        rc: Challenge,
        bc: Challenge,
    ) -> Self {
        meta.enable_equality(z);

        meta.create_gate("rw_state_gates", |meta| {
            let q = meta.query_selector(selector);
            let isfirst = meta.query_fixed(isfirst, Rotation::cur());
            let tag_cur = meta.query_advice(tag, Rotation::cur());
            let call_id_cur = meta.query_advice(call_id, Rotation::cur());
            let isroot_cur = meta.query_advice(isroot, Rotation::cur());
            let address_cur = meta.query_advice(address, Rotation::cur());
            let field_tag_cur = meta.query_advice(field_tag, Rotation::cur());
            let storage_key_cur = meta.query_advice(storage_key, Rotation::cur());
            let rw_counter_cur = meta.query_advice(rw_counter, Rotation::cur());
            let tag_next = meta.query_advice(tag, Rotation::next());
            let call_id_next = meta.query_advice(call_id, Rotation::next());
            let address_next = meta.query_advice(address, Rotation::next());
            let field_tag_next = meta.query_advice(field_tag, Rotation::next());
            let storage_key_next = meta.query_advice(storage_key, Rotation::next());
            let rw_counter_next = meta.query_advice(rw_counter, Rotation::next());
            let tag_changed = meta.query_advice(tag_changed, Rotation::cur());
            let call_id_changed = meta.query_advice(call_id_changed, Rotation::cur());
            let address_changed = meta.query_advice(address_changed, Rotation::cur());
            let field_tag_changed = meta.query_advice(field_tag_changed, Rotation::cur());
            let storage_key_changed = meta.query_advice(storage_key_changed, Rotation::cur());
            let rw_counter_changed_cur = meta.query_advice(rw_counter_changed, Rotation::cur());
            let rw_counter_changed_prev = meta.query_advice(rw_counter_changed, Rotation::prev());
            let value_cur = meta.query_advice(value, Rotation::cur());
            let value_prev = meta.query_advice(value, Rotation::prev());
            let isend_cur = meta.query_advice(isend, Rotation::cur());
            let isend_next = meta.query_advice(isend, Rotation::next());
            let iswrite_cur = meta.query_advice(iswrite, Rotation::cur());
            let one = Expression::Constant(F::ONE);
            let two = Expression::Constant(F::from(2u64));
            let limb_1 = meta.query_advice(limb_1, Rotation::cur());
            let limb_2 = meta.query_advice(limb_2, Rotation::cur());
            let limb_3 = meta.query_advice(limb_3, Rotation::cur());
            let limb_4 = meta.query_advice(limb_4, Rotation::cur());
            let limb_5 = meta.query_advice(limb_5, Rotation::cur());
            let limb_6 = meta.query_advice(limb_6, Rotation::cur());
            let limb_7 = meta.query_advice(limb_7, Rotation::cur());
            let limb_8 = meta.query_advice(limb_8, Rotation::cur());
            let limb_9 = meta.query_advice(limb_9, Rotation::cur());
            let limb_10 = meta.query_advice(limb_10, Rotation::cur());
            let z_cur = meta.query_advice(z, Rotation::cur());
            let z_next = meta.query_advice(z, Rotation::next());
            let r = meta.query_challenge(rc);
            let b = meta.query_challenge(bc);
            let two_pow_16 = Expression::Constant(F::from(1u64 << 16));
            let two_pow_32 = two_pow_16.clone() * two_pow_16.clone();
            let two_pow_48 = two_pow_32.clone() * two_pow_16.clone();
            let two_pow_64 = two_pow_32.clone() * two_pow_32.clone();
            let two_pow_80 = two_pow_64.clone() * two_pow_16.clone();
            let two_pow_96 = two_pow_64.clone() * two_pow_32.clone();
            let two_pow_112 = two_pow_96.clone() * two_pow_16.clone();
            let two_pow_128 = two_pow_64.clone() * two_pow_64.clone();
            let two_pow_144 = two_pow_128.clone() * two_pow_16.clone();
            let r2 = r.clone() * r.clone();
            let r3 = r2.clone() * r.clone();
            let r4 = r2.clone() * r2.clone();
            let r5 = r4.clone() * r.clone();
            let r6 = r4.clone() * r2.clone();
            let r7 = r6.clone() * r.clone();
            let r8 = r4.clone() * r4.clone();

            let packed_value = limb_1.clone()
                + limb_2.clone() * two_pow_16.clone()
                + limb_3.clone() * two_pow_32.clone()
                + limb_4.clone() * two_pow_48.clone()
                + limb_5.clone() * two_pow_64.clone()
                + limb_6.clone() * two_pow_80.clone()
                + limb_7.clone() * two_pow_96.clone()
                + limb_8.clone() * two_pow_112.clone()
                + limb_9.clone() * two_pow_128.clone()
                + limb_10.clone() * two_pow_144.clone();
            let fp = tag_cur.clone()
                + r.clone() * call_id_cur.clone()
                + r2.clone() * address_cur.clone()
                + r3.clone() * field_tag_cur.clone()
                + r4.clone() * storage_key_cur.clone()
                + r5.clone() * rw_counter_cur.clone()
                + r6.clone() * iswrite_cur.clone()
                + r7.clone() * value_cur.clone()
                + r8.clone() * isend_cur.clone()
                + b;
            let gate = q.clone() * (one.clone() - isend_cur.clone());
            let perm = z_cur.clone() * fp.clone() - z_next.clone();

            vec![
                (gate.clone() * tag_changed.clone() * (one.clone() - tag_changed.clone())),
                (gate.clone() * call_id_changed.clone() * (one.clone() - call_id_changed.clone())),
                (gate.clone() * address_changed.clone() * (one.clone() - address_changed.clone())),
                (gate.clone() * isend_cur.clone() * (one.clone() - isend_cur.clone())),
                (gate.clone()
                    * field_tag_changed.clone()
                    * (one.clone() - field_tag_changed.clone())),
                (gate.clone()
                    * storage_key_changed.clone()
                    * (one.clone() - storage_key_changed.clone())),
                (gate.clone()
                    * rw_counter_changed_cur.clone()
                    * (one.clone() - rw_counter_changed_cur.clone())),
                (gate.clone()
                    * (one.clone()
                        - tag_changed.clone()
                        - call_id_changed.clone()
                        - address_changed.clone()
                        - field_tag_changed.clone()
                        - storage_key_changed.clone()
                        - rw_counter_changed_cur.clone())),
                (gate.clone()
                    * (call_id_changed.clone()
                        + address_changed.clone()
                        + field_tag_changed.clone()
                        + storage_key_changed.clone()
                        + rw_counter_changed_cur.clone())
                    * (tag_next.clone() - tag_cur.clone())),
                (gate.clone()
                    * (address_changed.clone()
                        + field_tag_changed.clone()
                        + storage_key_changed.clone()
                        + rw_counter_changed_cur.clone())
                    * (call_id_next.clone() - call_id_cur.clone())),
                (gate.clone()
                    * (field_tag_changed.clone()
                        + storage_key_changed.clone()
                        + rw_counter_changed_cur.clone())
                    * (address_next.clone() - address_cur.clone())),
                (gate.clone()
                    * (storage_key_changed.clone() + rw_counter_changed_cur.clone())
                    * (field_tag_next.clone() - field_tag_cur.clone())),
                (gate.clone()
                    * rw_counter_changed_cur.clone()
                    * (storage_key_next.clone() - storage_key_cur.clone())),
                (gate.clone()
                    * storage_key_changed.clone()
                    * (storage_key_next.clone()
                        - storage_key_cur.clone()
                        - packed_value.clone()
                        - one.clone())),
                (gate.clone()
                    * call_id_changed.clone()
                    * (call_id_next.clone()
                        - call_id_cur.clone()
                        - limb_1.clone()
                        - limb_2.clone() * two_pow_16.clone()
                        - one.clone())),
                (gate.clone()
                    * tag_changed.clone()
                    * (tag_next.clone() - tag_cur.clone() - limb_1.clone() - one.clone())),
                (gate.clone()
                    * field_tag_changed.clone()
                    * (field_tag_next.clone()
                        - field_tag_cur.clone()
                        - limb_1.clone()
                        - one.clone())),
                (gate.clone()
                    * rw_counter_changed_cur.clone()
                    * (rw_counter_next.clone()
                        - rw_counter_cur.clone()
                        - limb_1.clone()
                        - limb_2.clone() * two_pow_16.clone()
                        - one.clone())),
                (gate.clone()
                    * address_changed.clone()
                    * (address_next.clone()
                        - address_cur.clone()
                        - packed_value.clone()
                        - one.clone())),
                (gate.clone() * iswrite_cur.clone() * (one.clone() - iswrite_cur.clone())),
                (gate.clone() * isfirst.clone() * (one.clone() - iswrite_cur.clone())),
                (gate.clone()
                    * (one.clone() - isfirst.clone())
                    * (one.clone() - rw_counter_changed_prev.clone())
                    * (one.clone() - iswrite_cur.clone())),
                (gate.clone()
                    * (one.clone() - iswrite_cur.clone())
                    * (value_cur.clone() - value_prev.clone())),
                (q.clone()
                    * (isend_cur.clone() - isend_next.clone())
                    * (one.clone() - isend_next.clone() + isend_cur.clone())),
                (gate.clone() * perm.clone()),
                (q.clone() * isend_cur.clone() * (z_cur.clone() - z_next.clone())),
                (q.clone() * isfirst.clone() * (one.clone() - z_cur.clone())),
                (q.clone() * isroot_cur.clone() * (one.clone() - isroot_cur.clone())),
                (q.clone() * isroot_cur.clone() * (call_id_cur.clone() - one.clone())),
                (q.clone()
                    * isroot_cur.clone()
                    * (tag_cur.clone() - one.clone())
                    * (tag_cur.clone() - two.clone())),
            ]
        });

        Self {
            _ph: PhantomData,
            selector,
            isfirst,
            tag,
            call_id,
            isroot,
            address,
            field_tag,
            storage_key,
            rw_counter,
            tag_changed,
            call_id_changed,
            address_changed,
            field_tag_changed,
            storage_key_changed,
            rw_counter_changed,
            iswrite,
            value,
            isend,
            z,
            limb_1,
            limb_2,
            limb_3,
            limb_4,
            limb_5,
            limb_6,
            limb_7,
            limb_8,
            limb_9,
            limb_10,
        }
    }

    pub fn assign(
        &self,
        layouter: &mut impl Layouter<F>,
        trace: &[RWState_values<F>],
        challenge_r: Value<F>,
        challenge_b: Value<F>,
    ) -> Result<Cell, Error> {
        const RWSTATE_HEAD_GUARD_ROWS: usize = 1;
        const RWSTATE_ACTIVE_ROWS: usize = 50_000;
        const RWSTATE_TAIL_GUARD_ROWS: usize = 1;

        let terminal_row = if let Some(last_state) = trace.last() {
            RWState_values {
                isfirst: F::ZERO,
                tag: F::ZERO,
                call_id: F::from(2u64),
                isroot: F::ZERO,
                address: F::ZERO,
                field_tag: F::ZERO,
                storage_key: F::ZERO,
                rw_counter: last_state.rw_counter + (F::ONE - last_state.isend),
                tag_changed: F::ZERO,
                call_id_changed: F::ZERO,
                address_changed: F::ZERO,
                field_tag_changed: F::ZERO,
                storage_key_changed: F::ZERO,
                rw_counter_changed: F::ZERO,
                iswrite: F::ZERO,
                value: [0u64; 4],
                isend: F::ONE,
                z: F::ZERO,
                limb_1: F::ZERO,
                limb_2: F::ZERO,
                limb_3: F::ZERO,
                limb_4: F::ZERO,
                limb_5: F::ZERO,
                limb_6: F::ZERO,
                limb_7: F::ZERO,
                limb_8: F::ZERO,
                limb_9: F::ZERO,
                limb_10: F::ZERO,
            }
        } else {
            RWState_values {
                isfirst: F::ZERO,
                tag: F::ZERO,
                call_id: F::from(2u64),
                isroot: F::ZERO,
                address: F::ZERO,
                field_tag: F::ZERO,
                storage_key: F::ZERO,
                rw_counter: F::ZERO,
                tag_changed: F::ZERO,
                call_id_changed: F::ZERO,
                address_changed: F::ZERO,
                field_tag_changed: F::ZERO,
                storage_key_changed: F::ZERO,
                rw_counter_changed: F::ZERO,
                iswrite: F::ZERO,
                value: [0u64; 4],
                isend: F::ONE,
                z: F::ZERO,
                limb_1: F::ZERO,
                limb_2: F::ZERO,
                limb_3: F::ZERO,
                limb_4: F::ZERO,
                limb_5: F::ZERO,
                limb_6: F::ZERO,
                limb_7: F::ZERO,
                limb_8: F::ZERO,
                limb_9: F::ZERO,
                limb_10: F::ZERO,
            }
        };

        let mut trace_with_padding = trace.to_vec();
        if trace_with_padding.len() > RWSTATE_ACTIVE_ROWS {
            return Err(Error::Synthesis);
        }
        while trace_with_padding.len() < RWSTATE_ACTIVE_ROWS {
            trace_with_padding.push(terminal_row.clone());
        }

        let head_guard_row = trace_with_padding
            .first()
            .cloned()
            .map(|mut row| {
                row.isfirst = F::ZERO;
                row
            })
            .unwrap_or_else(RWState_values::terminal_padding_row);

        layouter.assign_region(
            || "Assign Execution Trace",
            |mut region| {
                let mut running_z = Value::known(F::ONE);
                let mut z_last_cell: Option<Cell> = None;
                for offset in 0..RWSTATE_ACTIVE_ROWS {
                    let absolute_offset = offset + RWSTATE_HEAD_GUARD_ROWS;

                    self.selector.enable(&mut region, absolute_offset)?;

                    let isfirst_value = if offset == 0 { F::ONE } else { F::ZERO };

                    region.assign_fixed(
                        || format!("isfirst at row {absolute_offset}"),
                        self.isfirst,
                        absolute_offset,
                        || Value::known(isfirst_value),
                    )?;
                }
                for assigned_offset in
                    0..(RWSTATE_HEAD_GUARD_ROWS + RWSTATE_ACTIVE_ROWS + RWSTATE_TAIL_GUARD_ROWS)
                {
                    let state = if assigned_offset < RWSTATE_HEAD_GUARD_ROWS {
                        &head_guard_row
                    } else if assigned_offset < RWSTATE_HEAD_GUARD_ROWS + RWSTATE_ACTIVE_ROWS {
                        &trace_with_padding[assigned_offset - RWSTATE_HEAD_GUARD_ROWS]
                    } else {
                        &terminal_row
                    };

                    region.assign_advice(
                        || format!("tag at row {}", assigned_offset),
                        self.tag,
                        assigned_offset,
                        || Value::known(state.tag),
                    )?;

                    region.assign_advice(
                        || format!("call_id at row {}", assigned_offset),
                        self.call_id,
                        assigned_offset,
                        || Value::known(state.call_id),
                    )?;

                    region.assign_advice(
                        || format!("isroot at row {}", assigned_offset),
                        self.isroot,
                        assigned_offset,
                        || Value::known(state.isroot),
                    )?;

                    region.assign_advice(
                        || format!("address at row {}", assigned_offset),
                        self.address,
                        assigned_offset,
                        || Value::known(state.address),
                    )?;

                    region.assign_advice(
                        || format!("field_tag at row {}", assigned_offset),
                        self.field_tag,
                        assigned_offset,
                        || Value::known(state.field_tag),
                    )?;

                    region.assign_advice(
                        || format!("storage_key at row {}", assigned_offset),
                        self.storage_key,
                        assigned_offset,
                        || Value::known(state.storage_key),
                    )?;

                    region.assign_advice(
                        || format!("rw_counter at row {}", assigned_offset),
                        self.rw_counter,
                        assigned_offset,
                        || Value::known(state.rw_counter),
                    )?;

                    region.assign_advice(
                        || format!("tag_changed at row {}", assigned_offset),
                        self.tag_changed,
                        assigned_offset,
                        || Value::known(state.tag_changed),
                    )?;

                    region.assign_advice(
                        || format!("call_id_changed at row {}", assigned_offset),
                        self.call_id_changed,
                        assigned_offset,
                        || Value::known(state.call_id_changed),
                    )?;

                    region.assign_advice(
                        || format!("address_changed at row {}", assigned_offset),
                        self.address_changed,
                        assigned_offset,
                        || Value::known(state.address_changed),
                    )?;

                    region.assign_advice(
                        || format!("field_tag_changed at row {}", assigned_offset),
                        self.field_tag_changed,
                        assigned_offset,
                        || Value::known(state.field_tag_changed),
                    )?;

                    region.assign_advice(
                        || format!("storage_key_changed at row {}", assigned_offset),
                        self.storage_key_changed,
                        assigned_offset,
                        || Value::known(state.storage_key_changed),
                    )?;

                    region.assign_advice(
                        || format!("rw_counter_changed at row {}", assigned_offset),
                        self.rw_counter_changed,
                        assigned_offset,
                        || Value::known(state.rw_counter_changed),
                    )?;

                    region.assign_advice(
                        || format!("iswrite at row {}", assigned_offset),
                        self.iswrite,
                        assigned_offset,
                        || Value::known(state.iswrite),
                    )?;

                    let value_limbs = state.value;

                    let value_rlc = challenge_r
                        .clone()
                        .map(move |r| rlc_from_u64_limbs::<F>(&value_limbs, r));

                    region.assign_advice(
                        || format!("RWS value at row {assigned_offset}"),
                        self.value,
                        assigned_offset,
                        || value_rlc,
                    )?;

                    region.assign_advice(
                        || format!("isend at row {}", assigned_offset),
                        self.isend,
                        assigned_offset,
                        || Value::known(state.isend),
                    )?;

                    region.assign_advice(
                        || format!("limb_1 at row {}", assigned_offset),
                        self.limb_1,
                        assigned_offset,
                        || Value::known(state.limb_1),
                    )?;

                    region.assign_advice(
                        || format!("limb_2 at row {}", assigned_offset),
                        self.limb_2,
                        assigned_offset,
                        || Value::known(state.limb_2),
                    )?;

                    region.assign_advice(
                        || format!("limb_3 at row {}", assigned_offset),
                        self.limb_3,
                        assigned_offset,
                        || Value::known(state.limb_3),
                    )?;

                    region.assign_advice(
                        || format!("limb_4 at row {}", assigned_offset),
                        self.limb_4,
                        assigned_offset,
                        || Value::known(state.limb_4),
                    )?;

                    region.assign_advice(
                        || format!("limb_5 at row {}", assigned_offset),
                        self.limb_5,
                        assigned_offset,
                        || Value::known(state.limb_5),
                    )?;

                    region.assign_advice(
                        || format!("limb_6 at row {}", assigned_offset),
                        self.limb_6,
                        assigned_offset,
                        || Value::known(state.limb_6),
                    )?;

                    region.assign_advice(
                        || format!("limb_7 at row {}", assigned_offset),
                        self.limb_7,
                        assigned_offset,
                        || Value::known(state.limb_7),
                    )?;

                    region.assign_advice(
                        || format!("limb_8 at row {}", assigned_offset),
                        self.limb_8,
                        assigned_offset,
                        || Value::known(state.limb_8),
                    )?;

                    region.assign_advice(
                        || format!("limb_9 at row {}", assigned_offset),
                        self.limb_9,
                        assigned_offset,
                        || Value::known(state.limb_9),
                    )?;

                    region.assign_advice(
                        || format!("limb_10 at row {}", assigned_offset),
                        self.limb_10,
                        assigned_offset,
                        || Value::known(state.limb_10),
                    )?;

                    let current_z = running_z.clone();

                    let z_cell = region.assign_advice(
                        || format!("z at row {}", assigned_offset),
                        self.z,
                        assigned_offset,
                        || current_z,
                    )?;

                    let active_row_index = assigned_offset.checked_sub(RWSTATE_HEAD_GUARD_ROWS);

                    if active_row_index == Some(RWSTATE_ACTIVE_ROWS - 1) {
                        z_last_cell = Some(z_cell.cell());
                    } else if matches!(
                        active_row_index,
                        Some(inner) if inner + 1 < RWSTATE_ACTIVE_ROWS
                    ) && state.isend != F::ONE
                    {
                        let tag = state.tag;
                        let call_id = state.call_id;
                        let address = state.address;
                        let field_tag = state.field_tag;
                        let storage_key = state.storage_key;
                        let rw_counter = state.rw_counter;
                        let iswrite = state.iswrite;
                        let isend = state.isend;
                        let limbs = state.value;

                        let fingerprint =
                            challenge_r
                                .clone()
                                .zip(challenge_b.clone())
                                .map(move |(r, b)| {
                                    let value = rlc_from_u64_limbs::<F>(&limbs, r);

                                    rw_fingerprint(
                                        tag,
                                        call_id,
                                        address,
                                        field_tag,
                                        storage_key,
                                        rw_counter,
                                        iswrite,
                                        value,
                                        isend,
                                        r,
                                        b,
                                    )
                                });

                        running_z = running_z.zip(fingerprint).map(|(z, fp)| z * fp);
                    } else if matches!(
                        active_row_index,
                        Some(inner) if inner + 1 < RWSTATE_ACTIVE_ROWS
                    ) {
                        z_last_cell = Some(z_cell.cell());
                    }
                }

                z_last_cell.ok_or(Error::Synthesis)
            },
        )
    }
}

#[derive(Debug, Clone)]
struct EVM_Circuit<F: PrimeField> {
    pub cpu: Vec<CPU_values<F>>,
    pub rwtrace: Vec<RWTrace_values<F>>,
    pub rwstate: Vec<RWState_values<F>>,
    pub alu: Vec<ALU_values<F>>,
    pub copytool: Vec<CopyTool_values<F>>,
    pub bytetable: Vec<Byte_table_values<F>>,
    pub txtrace: Vec<TXTrace_values<F>>,
    pub output: Vec<PublicOutput_values<F>>,
    pub rom: Vec<ROM_table_values<F>>,
    pub and: Vec<Bitwise_values<F>>,
    pub or: Vec<Bitwise_values<F>>,
    pub xor: Vec<Bitwise_values<F>>,
    pub not: Vec<Bitwise_values<F>>,
}

#[derive(Debug, Clone)]
struct EVM_config<F: PrimeField> {
    _ph: PhantomData<F>,
    challenge_r: Challenge,
    challenge_b: Challenge,
    isfirst_cpu: Selector,
    islast_cpu: Selector,
    q_cpu: Selector,
    call_id_cpu: Column<Advice>,
    clk_cpu: Column<Advice>,
    rw_counter_cpu: Column<Advice>,
    pc_cpu: Column<Advice>,
    opcode_cpu: Column<Advice>,
    rlc_a_cpu: Column<Advice>,
    rlc_b_cpu: Column<Advice>,
    rlc_c_cpu: Column<Advice>,
    rlc_d_cpu: Column<Advice>,
    rlc_e_cpu: Column<Advice>,
    rlc_f_cpu: Column<Advice>,
    rlc_g_cpu: Column<Advice>,
    rlc_h_cpu: Column<Advice>,
    rlc_i_cpu: Column<Advice>,
    rlc_j_cpu: Column<Advice>,
    memaddr_cpu: Column<Advice>,
    inv_cpu: Column<Advice>,
    mmax_cpu: Column<Advice>,
    ismaxchanged_cpu: Column<Advice>,
    isbegintx_cpu: Column<Advice>,
    isendtx_cpu: Column<Advice>,
    iscall_cpu: Column<Advice>,
    isreturn_cpu: Column<Advice>,
    returndatacopy_cpu: Column<Advice>,
    calldatacopy_cpu: Column<Advice>,
    isadd_cpu: Column<Advice>,
    issub_cpu: Column<Advice>,
    ismul_cpu: Column<Advice>,
    isdiv_cpu: Column<Advice>,
    islt_cpu: Column<Advice>,
    iseq_cpu: Column<Advice>,
    isand_cpu: Column<Advice>,
    isor_cpu: Column<Advice>,
    isxor_cpu: Column<Advice>,
    isnot_cpu: Column<Advice>,
    isjump_cpu: Column<Advice>,
    isjumpdest_cpu: Column<Advice>,
    isjumpcon_cpu: Column<Advice>,
    ismload_cpu: Column<Advice>,
    ismstore_cpu: Column<Advice>,
    ismstore8_cpu: Column<Advice>,
    isread_cpu: Column<Advice>,
    iswrite_cpu: Column<Advice>,
    ishalt_cpu: Column<Advice>,
    rlc_addr_a_cpu: Column<Advice>,
    rlc_addr_b_cpu: Column<Advice>,
    sp_cpu: Column<Advice>,

    q_rt: Selector,
    isfirst_rt: Column<Fixed>,
    tag_rt: Column<Advice>,
    call_id_rt: Column<Advice>,
    address_rt: Column<Advice>,
    field_tag_rt: Column<Advice>,
    storage_key_rt: Column<Advice>,
    rw_counter_rt: Column<Advice>,
    iswrite_rt: Column<Advice>,
    value_rt: Column<Advice>,
    isend_rt: Column<Advice>,
    z_rt: Column<Advice>,

    q_rs: Selector,
    isfirst_rs: Column<Fixed>,
    tag_rs: Column<Advice>,
    call_id_rs: Column<Advice>,
    isroot_rs: Column<Advice>,
    address_rs: Column<Advice>,
    field_tag_rs: Column<Advice>,
    storage_key_rs: Column<Advice>,
    rw_counter_rs: Column<Advice>,
    tag_changed_rs: Column<Advice>,
    call_id_changed_rs: Column<Advice>,
    address_changed_rs: Column<Advice>,
    field_tag_changed_rs: Column<Advice>,
    storage_key_changed_rs: Column<Advice>,
    rw_counter_changed_rs: Column<Advice>,
    iswrite_rs: Column<Advice>,
    value_rs: Column<Advice>,
    isend_rs: Column<Advice>,
    z_rs: Column<Advice>,
    limb_1_rs: Column<Advice>,
    limb_2_rs: Column<Advice>,
    limb_3_rs: Column<Advice>,
    limb_4_rs: Column<Advice>,
    limb_5_rs: Column<Advice>,
    limb_6_rs: Column<Advice>,
    limb_7_rs: Column<Advice>,
    limb_8_rs: Column<Advice>,
    limb_9_rs: Column<Advice>,
    limb_10_rs: Column<Advice>,

    q_alu: Selector,
    isfirst_alu: Column<Fixed>,
    islast_alu: Column<Fixed>,
    byte32_alu: Column<Advice>,
    isfirst32_alu: Column<Fixed>,
    islast32_alu: Column<Fixed>,
    limbnumber_alu: Column<Fixed>,
    isadd_alu: Column<Advice>,
    ismul_alu: Column<Advice>,
    isdiv_alu: Column<Advice>,
    islt_alu: Column<Advice>,
    iseq_alu: Column<Advice>,
    isand_alu: Column<Advice>,
    isor_alu: Column<Advice>,
    isxor_alu: Column<Advice>,
    isnot_alu: Column<Advice>,
    barlt_alu: Column<Advice>,
    carry_alu: Column<Advice>,
    rem_alu: Column<Advice>,
    limb_a_alu: Column<Advice>,
    limb_b_alu: Column<Advice>,
    limb_c_alu: Column<Advice>,
    pac_a: [Column<Advice>; 4],
    pac_b: [Column<Advice>; 4],
    pac_c: [Column<Advice>; 4],
    pac_carry: [Column<Advice>; 4],
    pac_rem: [Column<Advice>; 4],
    pac_diff: [Column<Advice>; 4],
    rlc_a_alu: Column<Advice>,
    rlc_b_alu: Column<Advice>,
    rlc_c_alu: Column<Advice>,
    noname_alu: Column<Advice>,

    q_cc: Selector,
    switch_cc: Column<Advice>,
    isfirst_fixed_cc: Column<Fixed>,
    isfirst_cc: Column<Advice>,
    islast_cc: Column<Advice>,
    rwc_cc: Column<Advice>,
    address_write_cc: Column<Advice>,
    address_read_cc: Column<Advice>,
    address_end_cc: Column<Advice>,
    iswrite_cc: Column<Advice>,
    ismem_cc: Column<Advice>,
    istx_cc: Column<Advice>,
    callid_read_cc: Column<Advice>,
    callid_write_cc: Column<Advice>,
    bytesleft_cc: Column<Advice>,
    value_cc: Column<Advice>,
    ispad_cc: Column<Advice>,
    inv_cc: Column<Advice>,
    limb_1_cc: Column<Advice>,
    limb_2_cc: Column<Advice>,

    q_byte: Selector,
    q_byte_step: Selector,
    q_byte_first: Selector,
    q_byte_last: Selector,

    byte_active: Column<Instance>,
    call_id_bytetable: Column<Instance>,
    pc_bytetable: Column<Instance>,
    limb1_bytetable: Column<Instance>,
    limb2_bytetable: Column<Instance>,
    limb3_bytetable: Column<Instance>,
    limb4_bytetable: Column<Instance>,
    iscode_bytetable: Column<Instance>,

    active_tx: Column<Instance>,
    txid_tx: Column<Instance>,
    tag_tx: Column<Instance>,
    index_tx: Column<Instance>,
    value_low_tx: Column<Instance>,
    value_high_tx: Column<Instance>,

    active_output: Column<Instance>,
    tag_output: Column<Instance>,
    address_output: Column<Instance>,
    iswrite_output: Column<Instance>,
    value_0_output: Column<Instance>,
    value_1_output: Column<Instance>,
    value_2_output: Column<Instance>,
    value_3_output: Column<Instance>,
    rw_counter_output: Column<Instance>,

    byte_rom: TableColumn,
    begintx_rom: TableColumn,
    endtx_rom: TableColumn,
    iscall_rom: TableColumn,
    isreturn_rom: TableColumn,
    returndatacopy_rom: TableColumn,
    calldatacopy_rom: TableColumn,
    isadd_rom: TableColumn,
    issub_rom: TableColumn,
    ismul_rom: TableColumn,
    isdiv_rom: TableColumn,
    islt_rom: TableColumn,
    iseq_rom: TableColumn,
    isand_rom: TableColumn,
    isor_rom: TableColumn,
    isxor_rom: TableColumn,
    isnot_rom: TableColumn,
    isjump_rom: TableColumn,
    isjumpdest_rom: TableColumn,
    isjumpcon_rom: TableColumn,
    ismload_rom: TableColumn,
    ismstore_rom: TableColumn,
    ismstore8_rom: TableColumn,
    isread_rom: TableColumn,
    iswrite_rom: TableColumn,
    ishalt_rom: TableColumn,

    range0: TableColumn,
    range8: TableColumn,

    pac_a_and: TableColumn,
    pac_b_and: TableColumn,
    pac_c_and: TableColumn,

    pac_a_or: TableColumn,
    pac_b_or: TableColumn,
    pac_c_or: TableColumn,

    pac_a_xor: TableColumn,
    pac_b_xor: TableColumn,
    pac_c_xor: TableColumn,

    pac_a_not: TableColumn,
    pac_b_not: TableColumn,
    pac_c_not: TableColumn,

    cpu_chip: CPUTrace_Chip<F>,
    rwtrace_chip: RWTrace_Chip<F>,
    rwstate_chip: RWState_Chip<F>,
    alu_chip: ALUTrace_Chip<F>,
    copytool_chip: CopyTool_Chip<F>,
    rom_chip: ROM_Table<F>,
    byte_chip: Byte_Table<F>,
    tx_chip: TXTrace_Chip<F>,
    output_chip: PublicOutput_Chip<F>,
    range0_chip: Range_Table0<F>,
    range8_chip: Range_Table8<F>,
    range_and_chip: Range_Table_Bitwise<F>,
    range_or_chip: Range_Table_Bitwise<F>,
    range_xor_chip: Range_Table_Bitwise<F>,
    range_not_chip: Range_Table_Bitwise<F>,
}

impl<F: PrimeField> Default for EVM_Circuit<F> {
    fn default() -> Self {
        Self {
            cpu: vec![],
            rwtrace: vec![],
            rwstate: vec![],
            alu: vec![],
            copytool: vec![],
            bytetable: vec![],
            txtrace: vec![],
            output: vec![],
            rom: vec![],
            and: vec![],
            or: vec![],
            xor: vec![],
            not: vec![],
        }
    }
}

impl<F: PrimeField> EVM_Circuit<F> {
    fn for_vk(&self) -> Self {
        self.without_witnesses()
    }
}

#[derive(Debug, Clone, Copy)]
pub struct VkGenerationSummary {
    pub k: u32,
    pub vk_bytes: usize,
}

#[derive(Debug, Clone, Copy)]
pub struct PkGenerationSummary {
    pub k: u32,
    pub pk_bytes: usize,
}

#[derive(Debug, Clone, Copy)]
pub struct ProofVerificationSummary {
    pub k: u32,
    pub proof_bytes: usize,
    pub instances_bytes: usize,
}

fn vk_circuit() -> EVM_Circuit<Fp> {
    EVM_Circuit::<Fp>::default().for_vk()
}

pub fn generate_vk_with_local_setup(
    k: u32,
    out_path: &Path,
    params_out_path: &Path,
) -> Result<VkGenerationSummary, Box<dyn std::error::Error>> {
    let params = ParamsKZG::<Bn256>::setup(k, OsRng);
    let mut params_writer = BufWriter::new(File::create(params_out_path)?);
    params.write_custom(&mut params_writer, SerdeFormat::RawBytes)?;
    params_writer.flush()?;

    write_vk_from_params(k, params, out_path)
}

pub fn generate_vk_from_params_file(
    k: u32,
    params_path: &Path,
    out_path: &Path,
) -> Result<VkGenerationSummary, Box<dyn std::error::Error>> {
    let mut reader = BufReader::new(File::open(params_path)?);
    let params = ParamsKZG::<Bn256>::read_custom(&mut reader, SerdeFormat::RawBytes)?;
    if params.k() != k {
        return Err(format!(
            "params k mismatch: expected {k}, file contains {}",
            params.k()
        )
        .into());
    }

    write_vk_from_params(k, params, out_path)
}

fn write_vk_from_params(
    k: u32,
    params: ParamsKZG<Bn256>,
    out_path: &Path,
) -> Result<VkGenerationSummary, Box<dyn std::error::Error>> {
    let circuit = vk_circuit();
    let vk = keygen_vk(&params, &circuit)?;

    let mut writer = BufWriter::new(File::create(out_path)?);
    vk.write(&mut writer, SerdeFormat::RawBytes)?;
    writer.flush()?;

    let vk_bytes = std::fs::metadata(out_path)?.len() as usize;

    Ok(VkGenerationSummary { k, vk_bytes })
}

pub fn generate_pk_from_files(
    k: u32,
    params_path: &Path,
    vk_path: &Path,
    out_path: &Path,
) -> Result<PkGenerationSummary, Box<dyn std::error::Error>> {
    let mut params_reader = BufReader::new(File::open(params_path)?);
    let params = ParamsKZG::<Bn256>::read_custom(&mut params_reader, SerdeFormat::RawBytes)?;
    if params.k() != k {
        return Err(format!(
            "params k mismatch: expected {k}, file contains {}",
            params.k()
        )
        .into());
    }

    let mut vk_reader = BufReader::new(File::open(vk_path)?);
    let vk = VerifyingKey::<G1Affine>::read::<_, EVM_Circuit<Fp>>(
        &mut vk_reader,
        SerdeFormat::RawBytes,
    )?;
    let vk_k = vk.get_domain().k();
    if vk_k != k {
        return Err(format!("vk k mismatch: expected {k}, file contains {vk_k}").into());
    }

    let circuit = vk_circuit();
    let pk: ProvingKey<G1Affine> = keygen_pk(&params, vk, &circuit)?;

    let mut writer = BufWriter::new(File::create(out_path)?);
    pk.write(&mut writer, SerdeFormat::RawBytes)?;
    writer.flush()?;

    let pk_bytes = std::fs::metadata(out_path)?.len() as usize;
    Ok(PkGenerationSummary { k, pk_bytes })
}

pub fn verify_proof_from_files(
    k: u32,
    params_path: &Path,
    vk_path: &Path,
    proof_path: &Path,
    instances_path: &Path,
) -> Result<ProofVerificationSummary, Box<dyn std::error::Error>> {
    let mut params_reader = BufReader::new(File::open(params_path)?);
    let params = ParamsKZG::<Bn256>::read_custom(&mut params_reader, SerdeFormat::RawBytes)?;
    if params.k() != k {
        return Err(format!(
            "params k mismatch: expected {k}, file contains {}",
            params.k()
        )
        .into());
    }

    let mut vk_reader = BufReader::new(File::open(vk_path)?);
    let vk = VerifyingKey::<G1Affine>::read::<_, EVM_Circuit<Fp>>(
        &mut vk_reader,
        SerdeFormat::RawBytes,
    )?;
    let vk_k = vk.get_domain().k();
    if vk_k != k {
        return Err(format!("vk k mismatch: expected {k}, file contains {vk_k}").into());
    }

    let public_inputs = read_public_instances_from_file(instances_path)?;
    if public_inputs.len() != PUBLIC_INPUT_COLUMN_COUNT {
        return Err(format!(
            "public input column count mismatch: expected {PUBLIC_INPUT_COLUMN_COUNT}, got {}",
            public_inputs.len()
        )
        .into());
    }

    let proof = std::fs::read(proof_path)?;
    if proof.is_empty() {
        return Err("proof file is empty".into());
    }

    let instance_columns = public_inputs
        .iter()
        .map(Vec::as_slice)
        .collect::<Vec<&[Fp]>>();
    let instances: &[&[Fp]] = instance_columns.as_slice();
    let strategy = SingleStrategy::new(&params);
    let mut transcript = Blake2bRead::<&[u8], G1Affine, Challenge255<G1Affine>>::init(&proof[..]);

    verify_proof::<
        KZGCommitmentScheme<Bn256>,
        VerifierSHPLONK<'_, Bn256>,
        Challenge255<G1Affine>,
        Blake2bRead<&[u8], G1Affine, Challenge255<G1Affine>>,
        SingleStrategy<'_, Bn256>,
    >(&params, &vk, strategy, &[instances], &mut transcript)?;

    Ok(ProofVerificationSummary {
        k,
        proof_bytes: proof.len(),
        instances_bytes: std::fs::metadata(instances_path)?.len() as usize,
    })
}

impl<F: PrimeField> Circuit<F> for EVM_Circuit<F> {
    type Config = EVM_config<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        let mut rwtrace = self
            .rwtrace
            .iter()
            .map(RWTrace_values::without_values)
            .collect::<Vec<_>>();

        if let Some(last) = rwtrace.last_mut() {
            *last = RWTrace_values::terminal_padding_row();
        } else {
            rwtrace.push(RWTrace_values::terminal_padding_row());
        }

        let mut rwstate = self
            .rwstate
            .iter()
            .map(RWState_values::without_values)
            .collect::<Vec<_>>();

        if let Some(last) = rwstate.last_mut() {
            *last = RWState_values::terminal_padding_row();
        } else {
            rwstate.push(RWState_values::terminal_padding_row());
        }

        Self {
            cpu: self.cpu.iter().map(CPU_values::without_values).collect(),
            rwtrace,

            rwstate,

            alu: self.alu.iter().map(ALU_values::without_values).collect(),

            copytool: self
                .copytool
                .iter()
                .map(CopyTool_values::without_values)
                .collect(),

            txtrace: self
                .txtrace
                .iter()
                .map(TXTrace_values::without_values)
                .collect(),

            output: self.output.clone(),
            bytetable: self.bytetable.clone(),
            rom: self.rom.clone(),

            and: self.and.clone(),
            or: self.or.clone(),
            xor: self.xor.clone(),
            not: self.not.clone(),
        }
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let isfirst_cpu = meta.complex_selector();
        let islast_cpu = meta.complex_selector();
        let q_cpu = meta.complex_selector();
        let call_id_cpu = meta.advice_column();
        let clk_cpu = meta.advice_column();
        let rw_counter_cpu = meta.advice_column();
        let pc_cpu = meta.advice_column();
        let opcode_cpu = meta.advice_column();
        let rlc_a_cpu = meta.advice_column_in(SecondPhase);
        let rlc_b_cpu = meta.advice_column_in(SecondPhase);
        let rlc_c_cpu = meta.advice_column_in(SecondPhase);
        let rlc_d_cpu = meta.advice_column_in(SecondPhase);
        let rlc_e_cpu = meta.advice_column_in(SecondPhase);
        let rlc_f_cpu = meta.advice_column_in(SecondPhase);
        let rlc_g_cpu = meta.advice_column_in(SecondPhase);
        let rlc_h_cpu = meta.advice_column_in(SecondPhase);
        let rlc_i_cpu = meta.advice_column_in(SecondPhase);
        let rlc_j_cpu = meta.advice_column_in(SecondPhase);
        let memaddr_cpu = meta.advice_column();
        let inv_cpu = meta.advice_column();
        let mmax_cpu = meta.advice_column();
        let ismaxchanged_cpu = meta.advice_column();
        let isbegintx_cpu = meta.advice_column();
        let isendtx_cpu = meta.advice_column();
        let iscall_cpu = meta.advice_column();
        let isreturn_cpu = meta.advice_column();
        let returndatacopy_cpu = meta.advice_column();
        let calldatacopy_cpu = meta.advice_column();
        let isadd_cpu = meta.advice_column();
        let issub_cpu = meta.advice_column();
        let ismul_cpu = meta.advice_column();
        let isdiv_cpu = meta.advice_column();
        let islt_cpu = meta.advice_column();
        let iseq_cpu = meta.advice_column();
        let isand_cpu = meta.advice_column();
        let isor_cpu = meta.advice_column();
        let isxor_cpu = meta.advice_column();
        let isnot_cpu = meta.advice_column();
        let isjump_cpu = meta.advice_column();
        let isjumpdest_cpu = meta.advice_column();
        let isjumpcon_cpu = meta.advice_column();
        let ismload_cpu = meta.advice_column();
        let ismstore_cpu = meta.advice_column();
        let ismstore8_cpu = meta.advice_column();
        let isread_cpu = meta.advice_column();
        let iswrite_cpu = meta.advice_column();
        let ishalt_cpu = meta.advice_column();
        let rlc_addr_a_cpu = meta.advice_column();
        let rlc_addr_b_cpu = meta.advice_column();
        let sp_cpu = meta.advice_column();

        let q_rt = meta.complex_selector();
        let isfirst_rt = meta.fixed_column();
        let tag_rt = meta.advice_column();
        let call_id_rt = meta.advice_column();
        let address_rt = meta.advice_column();
        let field_tag_rt = meta.advice_column();
        let storage_key_rt = meta.advice_column();
        let rw_counter_rt = meta.advice_column();
        let iswrite_rt = meta.advice_column();
        let value_rt = meta.advice_column_in(SecondPhase);
        let isend_rt = meta.advice_column();
        let z_rt = meta.advice_column_in(SecondPhase);
        meta.enable_equality(z_rt);

        let q_rs = meta.complex_selector();
        let isfirst_rs = meta.fixed_column();
        let tag_rs = meta.advice_column();
        let call_id_rs = meta.advice_column();
        let isroot_rs = meta.advice_column();
        let address_rs = meta.advice_column();
        let field_tag_rs = meta.advice_column();
        let storage_key_rs = meta.advice_column();
        let rw_counter_rs = meta.advice_column();
        let tag_changed_rs = meta.advice_column();
        let call_id_changed_rs = meta.advice_column();
        let address_changed_rs = meta.advice_column();
        let field_tag_changed_rs = meta.advice_column();
        let storage_key_changed_rs = meta.advice_column();
        let rw_counter_changed_rs = meta.advice_column();
        let iswrite_rs = meta.advice_column();
        let value_rs = meta.advice_column_in(SecondPhase);
        let isend_rs = meta.advice_column();
        let z_rs = meta.advice_column_in(SecondPhase);
        let limb_1_rs = meta.advice_column();
        let limb_2_rs = meta.advice_column();
        let limb_3_rs = meta.advice_column();
        let limb_4_rs = meta.advice_column();
        let limb_5_rs = meta.advice_column();
        let limb_6_rs = meta.advice_column();
        let limb_7_rs = meta.advice_column();
        let limb_8_rs = meta.advice_column();
        let limb_9_rs = meta.advice_column();
        let limb_10_rs = meta.advice_column();
        meta.enable_equality(z_rs);

        let q_alu = meta.complex_selector();
        let isfirst_alu = meta.fixed_column();
        let islast_alu = meta.fixed_column();
        let byte32_alu = meta.advice_column();
        let isfirst32_alu = meta.fixed_column();
        let islast32_alu = meta.fixed_column();
        let limbnumber_alu = meta.fixed_column();
        let isadd_alu = meta.advice_column();
        let ismul_alu = meta.advice_column();
        let isdiv_alu = meta.advice_column();
        let islt_alu = meta.advice_column();
        let iseq_alu = meta.advice_column();
        let isand_alu = meta.advice_column();
        let isor_alu = meta.advice_column();
        let isxor_alu = meta.advice_column();
        let isnot_alu = meta.advice_column();
        let barlt_alu = meta.advice_column();
        let carry_alu = meta.advice_column();
        let rem_alu = meta.advice_column();
        let limb_a_alu = meta.advice_column();
        let limb_b_alu = meta.advice_column();
        let limb_c_alu = meta.advice_column();
        let pac_a = std::array::from_fn(|_| meta.advice_column());
        let pac_b = std::array::from_fn(|_| meta.advice_column());
        let pac_c = std::array::from_fn(|_| meta.advice_column());
        let pac_carry = std::array::from_fn(|_| meta.advice_column());
        let pac_rem = std::array::from_fn(|_| meta.advice_column());
        let pac_diff = std::array::from_fn(|_| meta.advice_column());
        let rlc_a_alu = meta.advice_column_in(SecondPhase);
        let rlc_b_alu = meta.advice_column_in(SecondPhase);
        let rlc_c_alu = meta.advice_column_in(SecondPhase);
        let noname_alu = meta.advice_column();

        let q_cc = meta.complex_selector();
        let switch_cc = meta.advice_column();
        let isfirst_fixed_cc = meta.fixed_column();
        let isfirst_cc = meta.advice_column();
        let islast_cc = meta.advice_column();
        let rwc_cc = meta.advice_column();
        let address_write_cc = meta.advice_column();
        let address_read_cc = meta.advice_column();
        let address_end_cc = meta.advice_column();
        let iswrite_cc = meta.advice_column();
        let ismem_cc = meta.advice_column();
        let istx_cc = meta.advice_column();
        let callid_read_cc = meta.advice_column();
        let callid_write_cc = meta.advice_column();
        let bytesleft_cc = meta.advice_column();
        let value_cc = meta.advice_column();
        let ispad_cc = meta.advice_column();
        let inv_cc = meta.advice_column();
        let limb_1_cc = meta.advice_column();
        let limb_2_cc = meta.advice_column();

        let q_byte = meta.complex_selector();
        let q_byte_step = meta.complex_selector();
        let q_byte_first = meta.complex_selector();
        let q_byte_last = meta.complex_selector();

        let byte_active = meta.instance_column();
        let call_id_bytetable = meta.instance_column();
        let pc_bytetable = meta.instance_column();
        let limb1_bytetable = meta.instance_column();
        let limb2_bytetable = meta.instance_column();
        let limb3_bytetable = meta.instance_column();
        let limb4_bytetable = meta.instance_column();
        let iscode_bytetable = meta.instance_column();

        let active_tx = meta.instance_column();
        let txid_tx = meta.instance_column();
        let tag_tx = meta.instance_column();
        let index_tx = meta.instance_column();
        let value_low_tx = meta.instance_column();
        let value_high_tx = meta.instance_column();

        let active_output = meta.instance_column();
        let tag_output = meta.instance_column();
        let address_output = meta.instance_column();
        let iswrite_output = meta.instance_column();
        let value_0_output = meta.instance_column();
        let value_1_output = meta.instance_column();
        let value_2_output = meta.instance_column();
        let value_3_output = meta.instance_column();
        let rw_counter_output = meta.instance_column();

        let byte_rom = meta.lookup_table_column();
        let begintx_rom = meta.lookup_table_column();
        let endtx_rom = meta.lookup_table_column();
        let iscall_rom = meta.lookup_table_column();
        let isreturn_rom = meta.lookup_table_column();
        let returndatacopy_rom = meta.lookup_table_column();
        let calldatacopy_rom = meta.lookup_table_column();
        let isadd_rom = meta.lookup_table_column();
        let issub_rom = meta.lookup_table_column();
        let ismul_rom = meta.lookup_table_column();
        let isdiv_rom = meta.lookup_table_column();
        let islt_rom = meta.lookup_table_column();
        let iseq_rom = meta.lookup_table_column();
        let isand_rom = meta.lookup_table_column();
        let isor_rom = meta.lookup_table_column();
        let isxor_rom = meta.lookup_table_column();
        let isnot_rom = meta.lookup_table_column();
        let isjump_rom = meta.lookup_table_column();
        let isjumpdest_rom = meta.lookup_table_column();
        let isjumpcon_rom = meta.lookup_table_column();
        let ismload_rom = meta.lookup_table_column();
        let ismstore_rom = meta.lookup_table_column();
        let ismstore8_rom = meta.lookup_table_column();
        let isread_rom = meta.lookup_table_column();
        let iswrite_rom = meta.lookup_table_column();
        let ishalt_rom = meta.lookup_table_column();

        let range0 = meta.lookup_table_column();
        let range8 = meta.lookup_table_column();

        let pac_a_and = meta.lookup_table_column();
        let pac_b_and = meta.lookup_table_column();
        let pac_c_and = meta.lookup_table_column();

        let pac_a_or = meta.lookup_table_column();
        let pac_b_or = meta.lookup_table_column();
        let pac_c_or = meta.lookup_table_column();

        let pac_a_xor = meta.lookup_table_column();
        let pac_b_xor = meta.lookup_table_column();
        let pac_c_xor = meta.lookup_table_column();

        let pac_a_not = meta.lookup_table_column();
        let pac_b_not = meta.lookup_table_column();
        let pac_c_not = meta.lookup_table_column();

        let rc = meta.challenge_usable_after(FirstPhase);
        let bc = meta.challenge_usable_after(FirstPhase);

        let cpu_chip = CPUTrace_Chip::configure(
            meta,
            isfirst_cpu,
            islast_cpu,
            q_cpu,
            call_id_cpu,
            clk_cpu,
            rw_counter_cpu,
            pc_cpu,
            opcode_cpu,
            rlc_a_cpu,
            rlc_b_cpu,
            rlc_c_cpu,
            rlc_d_cpu,
            rlc_e_cpu,
            rlc_f_cpu,
            rlc_g_cpu,
            rlc_h_cpu,
            rlc_i_cpu,
            rlc_j_cpu,
            memaddr_cpu,
            inv_cpu,
            mmax_cpu,
            ismaxchanged_cpu,
            isbegintx_cpu,
            isendtx_cpu,
            iscall_cpu,
            isreturn_cpu,
            returndatacopy_cpu,
            calldatacopy_cpu,
            isadd_cpu,
            issub_cpu,
            ismul_cpu,
            isdiv_cpu,
            islt_cpu,
            iseq_cpu,
            isand_cpu,
            isor_cpu,
            isxor_cpu,
            isnot_cpu,
            isjump_cpu,
            isjumpdest_cpu,
            isjumpcon_cpu,
            ismload_cpu,
            ismstore_cpu,
            ismstore8_cpu,
            isread_cpu,
            iswrite_cpu,
            ishalt_cpu,
            rlc_addr_a_cpu,
            rlc_addr_b_cpu,
            sp_cpu,
        );

        let rwtrace_chip = RWTrace_Chip::configure(
            meta,
            q_rt,
            isfirst_rt,
            tag_rt,
            call_id_rt,
            address_rt,
            field_tag_rt,
            storage_key_rt,
            rw_counter_rt,
            iswrite_rt,
            value_rt,
            isend_rt,
            z_rt,
            rc,
            bc,
        );

        let rwstate_chip = RWState_Chip::configure(
            meta,
            q_rs,
            isfirst_rs,
            tag_rs,
            call_id_rs,
            isroot_rs,
            address_rs,
            field_tag_rs,
            storage_key_rs,
            rw_counter_rs,
            tag_changed_rs,
            call_id_changed_rs,
            address_changed_rs,
            field_tag_changed_rs,
            storage_key_changed_rs,
            rw_counter_changed_rs,
            iswrite_rs,
            value_rs,
            isend_rs,
            z_rs,
            limb_1_rs,
            limb_2_rs,
            limb_3_rs,
            limb_4_rs,
            limb_5_rs,
            limb_6_rs,
            limb_7_rs,
            limb_8_rs,
            limb_9_rs,
            limb_10_rs,
            rc,
            bc,
        );
        let alu_chip = ALUTrace_Chip::configure(
            meta,
            q_alu,
            isfirst_alu,
            islast_alu,
            byte32_alu,
            isfirst32_alu,
            islast32_alu,
            limbnumber_alu,
            isadd_alu,
            ismul_alu,
            isdiv_alu,
            islt_alu,
            iseq_alu,
            isand_alu,
            isor_alu,
            isxor_alu,
            isnot_alu,
            barlt_alu,
            carry_alu,
            rem_alu,
            limb_a_alu,
            limb_b_alu,
            limb_c_alu,
            pac_a,
            pac_b,
            pac_c,
            pac_carry,
            pac_rem,
            pac_diff,
            rlc_a_alu,
            rlc_b_alu,
            rlc_c_alu,
            noname_alu,
            rc,
        );

        let copytool_chip = CopyTool_Chip::configure(
            meta,
            q_cc,
            switch_cc,
            isfirst_fixed_cc,
            isfirst_cc,
            islast_cc,
            rwc_cc,
            address_write_cc,
            address_read_cc,
            address_end_cc,
            iswrite_cc,
            ismem_cc,
            istx_cc,
            callid_read_cc,
            callid_write_cc,
            bytesleft_cc,
            value_cc,
            ispad_cc,
            inv_cc,
            limb_1_cc,
            limb_2_cc,
        );

        let rom_chip = ROM_Table::configure(
            byte_rom,
            begintx_rom,
            endtx_rom,
            iscall_rom,
            isreturn_rom,
            returndatacopy_rom,
            calldatacopy_rom,
            isadd_rom,
            issub_rom,
            ismul_rom,
            isdiv_rom,
            islt_rom,
            iseq_rom,
            isand_rom,
            isor_rom,
            isxor_rom,
            isnot_rom,
            isjump_rom,
            isjumpdest_rom,
            isjumpcon_rom,
            ismload_rom,
            ismstore_rom,
            ismstore8_rom,
            isread_rom,
            iswrite_rom,
            ishalt_rom,
        );

        let byte_chip = Byte_Table::configure(
            meta,
            q_byte,
            q_byte_step,
            q_byte_first,
            q_byte_last,
            byte_active,
            call_id_bytetable,
            pc_bytetable,
            limb1_bytetable,
            limb2_bytetable,
            limb3_bytetable,
            limb4_bytetable,
            iscode_bytetable,
        );

        let tx_chip = TXTrace_Chip::configure(
            meta,
            active_tx,
            txid_tx,
            tag_tx,
            index_tx,
            value_low_tx,
            value_high_tx,
        );

        let output_chip = PublicOutput_Chip::configure(
            meta,
            active_output,
            tag_output,
            address_output,
            iswrite_output,
            value_0_output,
            value_1_output,
            value_2_output,
            value_3_output,
            rw_counter_output,
        );

        let range0_chip = Range_Table0::configure(range0);
        let range8_chip = Range_Table8::configure(range8);

        let range_and_chip = Range_Table_Bitwise::configure(pac_a_and, pac_b_and, pac_c_and);

        let range_or_chip = Range_Table_Bitwise::configure(pac_a_or, pac_b_or, pac_c_or);

        let range_xor_chip = Range_Table_Bitwise::configure(pac_a_xor, pac_b_xor, pac_c_xor);

        let range_not_chip = Range_Table_Bitwise::configure(pac_a_not, pac_b_not, pac_c_not);

        let and_lookups = [
            ("AND_1 to table", pac_a[0], pac_c[0], pac_rem[0]),
            ("AND_2 to table", pac_a[1], pac_c[1], pac_rem[1]),
            ("AND_3 to table", pac_a[2], pac_c[2], pac_rem[2]),
            ("AND_4 to table", pac_a[3], pac_c[3], pac_rem[3]),
            ("AND_5 to table", pac_b[0], pac_carry[0], barlt_alu),
            ("AND_6 to table", pac_b[1], pac_carry[1], carry_alu),
            ("AND_7 to table", pac_b[2], pac_carry[2], rem_alu),
            ("AND_8 to table", pac_b[3], pac_carry[3], noname_alu),
        ];

        for (name, col_a, col_b, col_c) in and_lookups {
            meta.lookup(name, |meta| {
                let q = meta.query_selector(q_alu);
                let isand = meta.query_advice(isand_alu, Rotation::cur());
                let a = meta.query_advice(col_a, Rotation::cur());
                let b = meta.query_advice(col_b, Rotation::cur());
                let c = meta.query_advice(col_c, Rotation::cur());

                vec![
                    (q.clone() * isand.clone() * a, pac_a_and.clone()),
                    (q.clone() * isand.clone() * b, pac_b_and.clone()),
                    (q.clone() * isand.clone() * c, pac_c_and.clone()),
                ]
            });
        }

        let or_lookups = [
            ("OR_1 to table", pac_a[0], pac_c[0], pac_rem[0]),
            ("OR_2 to table", pac_a[1], pac_c[1], pac_rem[1]),
            ("OR_3 to table", pac_a[2], pac_c[2], pac_rem[2]),
            ("OR_4 to table", pac_a[3], pac_c[3], pac_rem[3]),
            ("OR_5 to table", pac_b[0], pac_carry[0], barlt_alu),
            ("OR_6 to table", pac_b[1], pac_carry[1], carry_alu),
            ("OR_7 to table", pac_b[2], pac_carry[2], rem_alu),
            ("OR_8 to table", pac_b[3], pac_carry[3], noname_alu),
        ];

        for (name, col_a, col_b, col_c) in or_lookups {
            meta.lookup(name, |meta| {
                let q = meta.query_selector(q_alu);
                let isor = meta.query_advice(isor_alu, Rotation::cur());
                let a = meta.query_advice(col_a, Rotation::cur());
                let b = meta.query_advice(col_b, Rotation::cur());
                let c = meta.query_advice(col_c, Rotation::cur());

                vec![
                    (q.clone() * isor.clone() * a, pac_a_or.clone()),
                    (q.clone() * isor.clone() * b, pac_b_or.clone()),
                    (q.clone() * isor.clone() * c, pac_c_or.clone()),
                ]
            });
        }

        let xor_lookups = [
            ("XOR_1 to table", pac_a[0], pac_c[0], pac_rem[0]),
            ("XOR_2 to table", pac_a[1], pac_c[1], pac_rem[1]),
            ("XOR_3 to table", pac_a[2], pac_c[2], pac_rem[2]),
            ("XOR_4 to table", pac_a[3], pac_c[3], pac_rem[3]),
            ("XOR_5 to table", pac_b[0], pac_carry[0], barlt_alu),
            ("XOR_6 to table", pac_b[1], pac_carry[1], carry_alu),
            ("XOR_7 to table", pac_b[2], pac_carry[2], rem_alu),
            ("XOR_8 to table", pac_b[3], pac_carry[3], noname_alu),
        ];

        for (name, col_a, col_b, col_c) in xor_lookups {
            meta.lookup(name, |meta| {
                let q = meta.query_selector(q_alu);
                let isxor = meta.query_advice(isxor_alu, Rotation::cur());
                let a = meta.query_advice(col_a, Rotation::cur());
                let b = meta.query_advice(col_b, Rotation::cur());
                let c = meta.query_advice(col_c, Rotation::cur());

                vec![
                    (q.clone() * isxor.clone() * a, pac_a_xor.clone()),
                    (q.clone() * isxor.clone() * b, pac_b_xor.clone()),
                    (q.clone() * isxor.clone() * c, pac_c_xor.clone()),
                ]
            });
        }

        let not_lookups = [
            ("NOT_1 to table", pac_a[0], pac_c[0], pac_rem[0]),
            ("NOT_2 to table", pac_a[1], pac_c[1], pac_rem[1]),
            ("NOT_3 to table", pac_a[2], pac_c[2], pac_rem[2]),
            ("NOT_4 to table", pac_a[3], pac_c[3], pac_rem[3]),
            ("NOT_5 to table", pac_b[0], pac_carry[0], barlt_alu),
            ("NOT_6 to table", pac_b[1], pac_carry[1], carry_alu),
            ("NOT_7 to table", pac_b[2], pac_carry[2], rem_alu),
            ("NOT_8 to table", pac_b[3], pac_carry[3], noname_alu),
        ];

        for (name, col_a, col_b, col_c) in not_lookups {
            meta.lookup(name, |meta| {
                let q = meta.query_selector(q_alu);
                let isnot = meta.query_advice(isnot_alu, Rotation::cur());
                let a = meta.query_advice(col_a, Rotation::cur());
                let b = meta.query_advice(col_b, Rotation::cur());
                let c = meta.query_advice(col_c, Rotation::cur());

                vec![
                    (q.clone() * isnot.clone() * a, pac_a_not.clone()),
                    (q.clone() * isnot.clone() * b, pac_b_not.clone()),
                    (q.clone() * isnot.clone() * c, pac_c_not.clone()),
                ]
            });
        }

        meta.lookup("alu to range8", |meta| {
            let q_alu = meta.query_selector(q_alu);
            let byte32 = meta.query_advice(byte32_alu, Rotation::cur());
            let value = meta.query_advice(noname_alu, Rotation::cur());

            vec![(q_alu.clone() * byte32.clone() * value.clone(), range8)]
        });

        meta.lookup("mmax on range0", |meta| {
            let q_cpu = meta.query_selector(q_cpu);
            let mmax_next = meta.query_advice(mmax_cpu, Rotation::next());
            let ismload = meta.query_advice(ismload_cpu, Rotation::cur());
            let ismstore = meta.query_advice(ismstore_cpu, Rotation::cur());
            let ismstore8 = meta.query_advice(ismstore8_cpu, Rotation::cur());
            let returndatacopy = meta.query_advice(returndatacopy_cpu, Rotation::cur());
            let calldatacopy = meta.query_advice(calldatacopy_cpu, Rotation::cur());
            let isreturn = meta.query_advice(isreturn_cpu, Rotation::cur());
            let rlc_c = meta.query_advice(rlc_c_cpu, Rotation::cur());
            let rlc_f = meta.query_advice(rlc_f_cpu, Rotation::cur());
            let rlc_j = meta.query_advice(rlc_j_cpu, Rotation::cur());
            let rlc_g = meta.query_advice(rlc_g_cpu, Rotation::cur());
            let rlc_i = meta.query_advice(rlc_i_cpu, Rotation::cur());
            let rlc_a = meta.query_advice(rlc_a_cpu, Rotation::cur());
            let one = Expression::Constant(F::from(1u64));
            let thirty_one = Expression::Constant(F::from(31u64));

            vec![(
                q_cpu.clone()
                    * (ismload.clone()
                        + ismstore.clone()
                        + ismstore8.clone()
                        + returndatacopy.clone()
                        + calldatacopy.clone()
                        + isreturn.clone())
                    * (mmax_next.clone()
                        - (rlc_a.clone() * (one.clone() - isreturn.clone())
                            + rlc_f.clone() * isreturn.clone()
                            + (ismstore.clone() + ismload.clone()) * thirty_one.clone()
                            + (returndatacopy.clone() + calldatacopy.clone())
                                * (rlc_c.clone() - one.clone())
                            + isreturn.clone()
                                * (rlc_j.clone() * rlc_g.clone()
                                    + (one.clone() - rlc_j.clone()) * rlc_i.clone()
                                    - one.clone())
                            + one.clone())),
                range0,
            )]
        });

        meta.lookup("mmax on range0", |meta| {
            let q_cpu = meta.query_selector(q_cpu);
            let mmax = meta.query_advice(mmax_cpu, Rotation::cur());
            let ismload = meta.query_advice(ismload_cpu, Rotation::cur());
            let ismstore = meta.query_advice(ismstore_cpu, Rotation::cur());
            let ismstore8 = meta.query_advice(ismstore8_cpu, Rotation::cur());
            let returndatacopy = meta.query_advice(returndatacopy_cpu, Rotation::cur());
            let calldatacopy = meta.query_advice(calldatacopy_cpu, Rotation::cur());
            let isreturn = meta.query_advice(isreturn_cpu, Rotation::cur());
            let ismaxchanged = meta.query_advice(ismaxchanged_cpu, Rotation::cur());
            let rlc_c = meta.query_advice(rlc_c_cpu, Rotation::cur());
            let rlc_f = meta.query_advice(rlc_f_cpu, Rotation::cur());
            let rlc_j = meta.query_advice(rlc_j_cpu, Rotation::cur());
            let rlc_g = meta.query_advice(rlc_g_cpu, Rotation::cur());
            let rlc_i = meta.query_advice(rlc_i_cpu, Rotation::cur());
            let rlc_a = meta.query_advice(rlc_a_cpu, Rotation::cur());
            let one = Expression::Constant(F::from(1u64));
            let thirty_one = Expression::Constant(F::from(31u64));

            vec![(
                q_cpu.clone()
                    * ismaxchanged.clone()
                    * ((rlc_a.clone() * (one.clone() - isreturn.clone())
                        + rlc_f.clone() * isreturn.clone()
                        + (ismstore.clone() + ismload.clone()) * thirty_one.clone()
                        + (returndatacopy.clone() + calldatacopy.clone())
                            * (rlc_c.clone() - one.clone())
                        + isreturn.clone()
                            * (rlc_j.clone() * rlc_g.clone()
                                + (one.clone() - rlc_j.clone()) * rlc_i.clone()
                                - one.clone())
                        + one.clone())
                        - mmax.clone()),
                range0,
            )]
        });

        meta.lookup("rwstate non-root call_id on range0", |meta| {
            let q_rs = meta.query_selector(q_rs);
            let isroot = meta.query_advice(isroot_rs, Rotation::cur());
            let tag = meta.query_advice(tag_rs, Rotation::cur());
            let call_id = meta.query_advice(call_id_rs, Rotation::cur());
            let one = Expression::Constant(F::ONE);
            let two = Expression::Constant(F::from(2u64));
            let five = Expression::Constant(F::from(5u64));

            vec![(
                q_rs * (one - isroot) * (call_id - two) * (five - tag),
                range0,
            )]
        });

        meta.lookup_any("rwstate to public output", |cells| {
            let q_rs = cells.query_selector(q_rs);
            let isroot = cells.query_advice(isroot_rs, Rotation::cur());
            let rw_gate = q_rs * isroot;
            let output_gate = cells.query_instance(active_output, Rotation::cur());

            let tag_rs_cur = cells.query_advice(tag_rs, Rotation::cur());
            let address_rs_cur = cells.query_advice(address_rs, Rotation::cur());
            let iswrite_rs_cur = cells.query_advice(iswrite_rs, Rotation::cur());
            let value_rs_cur = cells.query_advice(value_rs, Rotation::cur());
            let rw_counter_rs_cur = cells.query_advice(rw_counter_rs, Rotation::cur());

            let tag_output_cur = cells.query_instance(tag_output, Rotation::cur());
            let address_output_cur = cells.query_instance(address_output, Rotation::cur());
            let iswrite_output_cur = cells.query_instance(iswrite_output, Rotation::cur());
            let value_0_output_cur = cells.query_instance(value_0_output, Rotation::cur());
            let value_1_output_cur = cells.query_instance(value_1_output, Rotation::cur());
            let value_2_output_cur = cells.query_instance(value_2_output, Rotation::cur());
            let value_3_output_cur = cells.query_instance(value_3_output, Rotation::cur());
            let rw_counter_output_cur = cells.query_instance(rw_counter_output, Rotation::cur());
            let r = cells.query_challenge(rc);
            let r2 = r.clone() * r.clone();
            let r3 = r2.clone() * r.clone();
            let output_value = value_0_output_cur
                + value_1_output_cur * r.clone()
                + value_2_output_cur * r2
                + value_3_output_cur * r3;

            vec![
                (
                    rw_gate.clone() * tag_rs_cur,
                    output_gate.clone() * tag_output_cur,
                ),
                (
                    rw_gate.clone() * address_rs_cur,
                    output_gate.clone() * address_output_cur,
                ),
                (
                    rw_gate.clone() * iswrite_rs_cur,
                    output_gate.clone() * iswrite_output_cur,
                ),
                (
                    rw_gate.clone() * value_rs_cur,
                    output_gate.clone() * output_value,
                ),
                (
                    rw_gate * rw_counter_rs_cur,
                    output_gate * rw_counter_output_cur,
                ),
            ]
        });

        meta.lookup_any("public output to rwstate", |cells| {
            let q_rs = cells.query_selector(q_rs);
            let isroot = cells.query_advice(isroot_rs, Rotation::cur());
            let rw_gate = q_rs * isroot;
            let output_gate = cells.query_instance(active_output, Rotation::cur());

            let tag_rs_cur = cells.query_advice(tag_rs, Rotation::cur());
            let address_rs_cur = cells.query_advice(address_rs, Rotation::cur());
            let iswrite_rs_cur = cells.query_advice(iswrite_rs, Rotation::cur());
            let value_rs_cur = cells.query_advice(value_rs, Rotation::cur());
            let rw_counter_rs_cur = cells.query_advice(rw_counter_rs, Rotation::cur());

            let tag_output_cur = cells.query_instance(tag_output, Rotation::cur());
            let address_output_cur = cells.query_instance(address_output, Rotation::cur());
            let iswrite_output_cur = cells.query_instance(iswrite_output, Rotation::cur());
            let value_0_output_cur = cells.query_instance(value_0_output, Rotation::cur());
            let value_1_output_cur = cells.query_instance(value_1_output, Rotation::cur());
            let value_2_output_cur = cells.query_instance(value_2_output, Rotation::cur());
            let value_3_output_cur = cells.query_instance(value_3_output, Rotation::cur());
            let rw_counter_output_cur = cells.query_instance(rw_counter_output, Rotation::cur());
            let r = cells.query_challenge(rc);
            let r2 = r.clone() * r.clone();
            let r3 = r2.clone() * r.clone();
            let output_value = value_0_output_cur
                + value_1_output_cur * r.clone()
                + value_2_output_cur * r2
                + value_3_output_cur * r3;

            vec![
                (
                    output_gate.clone() * tag_output_cur,
                    rw_gate.clone() * tag_rs_cur,
                ),
                (
                    output_gate.clone() * address_output_cur,
                    rw_gate.clone() * address_rs_cur,
                ),
                (
                    output_gate.clone() * iswrite_output_cur,
                    rw_gate.clone() * iswrite_rs_cur,
                ),
                (
                    output_gate.clone() * output_value,
                    rw_gate.clone() * value_rs_cur,
                ),
                (
                    output_gate * rw_counter_output_cur,
                    rw_gate * rw_counter_rs_cur,
                ),
            ]
        });

        let all_pacs = [
            pac_a[0],
            pac_a[1],
            pac_a[2],
            pac_a[3],
            pac_b[0],
            pac_b[1],
            pac_b[2],
            pac_b[3],
            pac_c[0],
            pac_c[1],
            pac_c[2],
            pac_c[3],
            pac_carry[0],
            pac_carry[1],
            pac_carry[2],
            pac_carry[3],
            pac_rem[0],
            pac_rem[1],
            pac_rem[2],
            pac_rem[3],
            pac_diff[0],
            pac_diff[1],
            pac_diff[2],
            pac_diff[3],
            limb_1_cc,
            limb_2_cc,
            limb_1_rs,
            limb_2_rs,
            limb_3_rs,
            limb_4_rs,
            limb_5_rs,
            limb_6_rs,
            limb_7_rs,
            limb_8_rs,
            limb_9_rs,
            limb_10_rs,
        ];

        for (i, pac_col) in all_pacs.iter().enumerate() {
            let lookup_name = format!("pac_chunk_{} to range0", i);

            meta.lookup(Box::leak(lookup_name.into_boxed_str()), |meta| {
                let pac = meta.query_advice(*pac_col, Rotation::cur());

                vec![(pac, range0)]
            });
        }

        meta.lookup("return inv range", |meta| {
            let q = meta.query_selector(q_cpu);
            let isreturn = meta.query_advice(isreturn_cpu, Rotation::cur());
            let inv = meta.query_advice(inv_cpu, Rotation::cur());

            vec![(q * isreturn * inv, range0)]
        });

        meta.lookup("(ismul_alu + isdiv_alu) * noname_alu range", |meta| {
            let q = meta.query_selector(q_alu);
            let ismul_alu = meta.query_advice(ismul_alu, Rotation::cur());
            let isdiv_alu = meta.query_advice(isdiv_alu, Rotation::cur());
            let noname_alu = meta.query_advice(noname_alu, Rotation::cur());

            vec![(q * (ismul_alu + isdiv_alu) * noname_alu, range0)]
        });

        meta.lookup_any("copy circuit to rt, ismem", |cells| {
            let zero = Expression::Constant(F::ZERO);
            let one = Expression::Constant(F::ONE);
            let gate_cc = cells.query_selector(q_cc)
                * cells.query_advice(switch_cc, Rotation::cur())
                * cells.query_advice(ismem_cc, Rotation::cur());
            let rwc_cc = cells.query_advice(rwc_cc, Rotation::cur());
            let address_write_cc = cells.query_advice(address_write_cc, Rotation::cur());
            let address_read_cc = cells.query_advice(address_read_cc, Rotation::cur());
            let iswrite_cc = cells.query_advice(iswrite_cc, Rotation::cur());
            let _ismem_cc = cells.query_advice(ismem_cc, Rotation::cur());
            let callid_read_cc = cells.query_advice(callid_read_cc, Rotation::cur());
            let callid_write_cc = cells.query_advice(callid_write_cc, Rotation::cur());
            let value_cc = cells.query_advice(value_cc, Rotation::cur());
            let ispad_cc = cells.query_advice(ispad_cc, Rotation::cur());
            let isntpad_cc = one.clone() - ispad_cc.clone();
            let gate_rt = cells.query_selector(q_rt)
                * (one.clone() - cells.query_advice(isend_rt, Rotation::cur()));
            let tag_rt = cells.query_advice(tag_rt, Rotation::cur());
            let call_id_rt = cells.query_advice(call_id_rt, Rotation::cur());
            let address_rt = cells.query_advice(address_rt, Rotation::cur());
            let field_tag_rt = cells.query_advice(field_tag_rt, Rotation::cur());
            let storage_key_rt = cells.query_advice(storage_key_rt, Rotation::cur());
            let rwc_rt = cells.query_advice(rw_counter_rt, Rotation::cur());
            let value_rt = cells.query_advice(value_rt, Rotation::cur());
            let iswrite_rt = cells.query_advice(iswrite_rt, Rotation::cur());

            vec![
                (
                    gate_cc.clone() * isntpad_cc.clone() * one.clone(),
                    gate_rt.clone() * tag_rt.clone(),
                ),
                (
                    gate_cc.clone()
                        * (iswrite_cc.clone() * callid_write_cc.clone()
                            + (one.clone() - iswrite_cc.clone() - ispad_cc.clone())
                                * callid_read_cc.clone()),
                    gate_rt.clone() * call_id_rt.clone(),
                ),
                (
                    gate_cc.clone()
                        * (iswrite_cc.clone() * address_write_cc.clone()
                            + (one.clone() - iswrite_cc.clone() - ispad_cc.clone())
                                * address_read_cc.clone()),
                    gate_rt.clone() * address_rt.clone(),
                ),
                (
                    gate_cc.clone() * isntpad_cc.clone() * zero.clone(),
                    gate_rt.clone() * field_tag_rt.clone(),
                ),
                (
                    gate_cc.clone() * isntpad_cc.clone() * zero.clone(),
                    gate_rt.clone() * storage_key_rt.clone(),
                ),
                (
                    gate_cc.clone() * isntpad_cc.clone() * rwc_cc.clone(),
                    gate_rt.clone() * rwc_rt.clone(),
                ),
                (
                    gate_cc.clone() * isntpad_cc.clone() * value_cc.clone(),
                    gate_rt.clone() * value_rt.clone(),
                ),
                (
                    gate_cc.clone() * isntpad_cc.clone() * iswrite_cc.clone(),
                    gate_rt.clone() * iswrite_rt.clone(),
                ),
            ]
        });

        meta.lookup_any("copy circuit to rt, istx, isread", |cells| {
            let zero = Expression::Constant(F::ZERO);
            let one = Expression::Constant(F::ONE);
            let iswrite_cc = cells.query_advice(iswrite_cc, Rotation::cur());
            let switch = cells.query_advice(switch_cc, Rotation::cur());
            let gate_cc = cells.query_selector(q_cc)
                * switch.clone()
                * cells.query_advice(istx_cc, Rotation::cur())
                * (one.clone() - iswrite_cc.clone())
                - cells.query_selector(q_cc)
                    * cells.query_advice(istx_cc, Rotation::cur())
                    * cells.query_advice(ispad_cc, Rotation::cur());
            let _rwc_cc = cells.query_advice(rwc_cc, Rotation::cur());
            let address_read_cc = cells.query_advice(address_read_cc, Rotation::cur());
            let _callid_read_cc = cells.query_advice(callid_read_cc, Rotation::cur());
            let value_cc = cells.query_advice(value_cc, Rotation::cur());

            let gate_tx = cells.query_instance(active_tx, Rotation::cur());
            let tag_tx = cells.query_instance(tag_tx, Rotation::cur());
            let value_low_tx = cells.query_instance(value_low_tx, Rotation::cur());
            let value_high_tx = cells.query_instance(value_high_tx, Rotation::cur());
            let index_tx = cells.query_instance(index_tx, Rotation::cur());

            vec![
                (
                    gate_cc.clone() * one.clone(),
                    gate_tx.clone() * tag_tx.clone(),
                ),
                (
                    gate_cc.clone() * address_read_cc.clone(),
                    gate_tx.clone() * index_tx.clone(),
                ),
                (
                    gate_cc.clone() * value_cc.clone(),
                    gate_tx.clone() * value_low_tx.clone(),
                ),
                (
                    gate_cc.clone() * zero.clone(),
                    gate_tx.clone() * value_high_tx.clone(),
                ),
            ]
        });

        meta.lookup_any("copy circuit to rt, istx, iswrite", |cells| {
            let zero = Expression::Constant(F::ZERO);
            let one = Expression::Constant(F::ONE);
            let iswrite_cc = cells.query_advice(iswrite_cc, Rotation::cur());
            let gate_cc = cells.query_selector(q_cc)
                * cells.query_advice(switch_cc, Rotation::cur())
                * cells.query_advice(istx_cc, Rotation::cur())
                * iswrite_cc.clone();
            let rwc_cc = cells.query_advice(rwc_cc, Rotation::cur());
            let address_write_cc = cells.query_advice(address_write_cc, Rotation::cur());
            let callid_write_cc = cells.query_advice(callid_write_cc, Rotation::cur());
            let value_cc = cells.query_advice(value_cc, Rotation::cur());

            let gate_rt = cells.query_selector(q_rt)
                * (one.clone() - cells.query_advice(isend_rt, Rotation::cur()));
            let tag_rt = cells.query_advice(tag_rt, Rotation::cur());
            let call_id_rt = cells.query_advice(call_id_rt, Rotation::cur());
            let address_rt = cells.query_advice(address_rt, Rotation::cur());
            let field_tag_rt = cells.query_advice(field_tag_rt, Rotation::cur());
            let storage_key_rt = cells.query_advice(storage_key_rt, Rotation::cur());
            let rwc_rt = cells.query_advice(rw_counter_rt, Rotation::cur());
            let value_rt = cells.query_advice(value_rt, Rotation::cur());
            let iswrite_rt = cells.query_advice(iswrite_rt, Rotation::cur());

            vec![
                (
                    gate_cc.clone() * one.clone(),
                    gate_rt.clone() * tag_rt.clone(),
                ),
                (
                    gate_cc.clone() * callid_write_cc.clone(),
                    gate_rt.clone() * call_id_rt.clone(),
                ),
                (
                    gate_cc.clone() * address_write_cc.clone(),
                    gate_rt.clone() * address_rt.clone(),
                ),
                (
                    gate_cc.clone() * zero.clone(),
                    gate_rt.clone() * field_tag_rt.clone(),
                ),
                (
                    gate_cc.clone() * zero.clone(),
                    gate_rt.clone() * storage_key_rt.clone(),
                ),
                (
                    gate_cc.clone() * rwc_cc.clone(),
                    gate_rt.clone() * rwc_rt.clone(),
                ),
                (
                    gate_cc.clone() * value_cc.clone(),
                    gate_rt.clone() * value_rt.clone(),
                ),
                (
                    gate_cc.clone() * one.clone(),
                    gate_rt.clone() * iswrite_rt.clone(),
                ),
            ]
        });

        meta.lookup_any("cpu to alu for memory", |cells| {
            let isfirst32_alu = cells.query_fixed(isfirst32_alu, Rotation::cur());
            let q_cpu = cells.query_selector(q_cpu);
            let q_alu = cells.query_selector(q_alu);
            let call_id_cpu = cells.query_advice(call_id_cpu, Rotation::cur());
            let call_id_alu = cells.query_advice(rem_alu, Rotation::cur());
            let byte32 = cells.query_advice(byte32_alu, Rotation::cur());
            let ismstore_cpu = cells.query_advice(ismstore_cpu, Rotation::cur());
            let ismload_cpu = cells.query_advice(ismload_cpu, Rotation::cur());
            let ismstore8_cpu = cells.query_advice(ismstore8_cpu, Rotation::cur());
            let gate_alu = q_alu.clone() * byte32.clone();
            let gate_cpu = q_cpu.clone()
                * (ismload_cpu.clone() + ismstore_cpu.clone() + ismstore8_cpu.clone());
            let rlc_a_cpu = cells.query_advice(rlc_a_cpu, Rotation::cur());
            let rlc_b_cpu = cells.query_advice(rlc_b_cpu, Rotation::cur());
            let rlc_c_cpu = cells.query_advice(rlc_c_cpu, Rotation::cur());
            let rlc_a_alu = cells.query_advice(rlc_a_alu, Rotation::cur());
            let rwc_cpu = cells.query_advice(rw_counter_cpu, Rotation::cur());
            let ismstore8_alu = cells.query_advice(pac_carry[0], Rotation::cur());
            let rwc_alu = cells.query_advice(pac_carry[1], Rotation::cur());
            let _value_alu = cells.query_advice(noname_alu, Rotation::cur());
            let addr_alu = cells.query_advice(carry_alu, Rotation::cur());
            let ismload_alu = cells.query_advice(pac_carry[2], Rotation::cur());
            let ismstore_alu = cells.query_advice(pac_carry[3], Rotation::cur());
            let _zero = Expression::Constant(F::ZERO);
            let one = Expression::Constant(F::ONE);
            let two = Expression::Constant(F::from(2u64));

            vec![
                (
                    gate_cpu.clone() * one.clone(),
                    gate_alu.clone() * isfirst32_alu.clone(),
                ),
                (
                    gate_cpu.clone()
                        * (rwc_cpu
                            + ismload_cpu.clone()
                            + (ismstore_cpu.clone() + ismstore8_cpu.clone()) * two.clone()),
                    gate_alu.clone() * rwc_alu.clone(),
                ),
                (
                    gate_cpu.clone() * call_id_cpu.clone(),
                    gate_alu.clone() * call_id_alu.clone(),
                ),
                (
                    gate_cpu.clone() * rlc_a_cpu.clone(),
                    gate_alu.clone() * addr_alu.clone(),
                ),
                (
                    gate_cpu.clone()
                        * (ismload_cpu.clone() * rlc_c_cpu.clone()
                            + (ismstore_cpu.clone() + ismstore8_cpu.clone()) * rlc_b_cpu.clone()),
                    gate_alu.clone() * rlc_a_alu.clone(),
                ),
                (
                    gate_cpu.clone() * ismload_cpu.clone(),
                    gate_alu.clone() * ismload_alu.clone(),
                ),
                (
                    gate_cpu.clone() * ismstore_cpu.clone(),
                    gate_alu.clone() * ismstore_alu.clone(),
                ),
                (
                    gate_cpu.clone() * ismstore8_cpu.clone(),
                    gate_alu.clone() * ismstore8_alu.clone(),
                ),
            ]
        });
        /*
                meta.lookup_any("alu to cpu for memory", |cells| {
                    let q_cpu = cells.query_selector(q_cpu);
                    let q_alu = cells.query_selector(q_alu);
                    let call_id_cpu = cells.query_advice(call_id_cpu, Rotation::cur());
                    let call_id_alu = cells.query_advice(rem_alu, Rotation::cur());
                    let byte32 = cells.query_advice(byte32_alu, Rotation::cur());
                    let ismstore_cpu = cells.query_advice(ismstore_cpu, Rotation::cur());
                    let ismload_cpu = cells.query_advice(ismload_cpu, Rotation::cur());
                    let ismstore8_cpu = cells.query_advice(ismstore8_cpu, Rotation::cur());
                    let gate_alu = q_alu.clone() * byte32.clone();
                    let gate_cpu = q_cpu.clone()
                        * (ismload_cpu.clone() + ismstore_cpu.clone() + ismstore8_cpu.clone());
                    let rlc_a_cpu = cells.query_advice(rlc_a_cpu, Rotation::cur());
                    let rlc_b_cpu = cells.query_advice(rlc_b_cpu, Rotation::cur());
                    let rlc_c_cpu = cells.query_advice(rlc_c_cpu, Rotation::cur());
                    let rlc_a_alu = cells.query_advice(rlc_a_alu, Rotation::cur());
                    let rwc_cpu = cells.query_advice(rw_counter_cpu, Rotation::cur());
                    let ismstore8_alu = cells.query_advice(pac_carry[0], Rotation::cur());
                    let rwc_alu = cells.query_advice(pac_carry[1], Rotation::cur());
                    let value_alu = cells.query_advice(noname_alu, Rotation::cur());
                    let addr_alu = cells.query_advice(carry_alu, Rotation::cur());
                    let _ismload_alu = cells.query_advice(pac_carry[2], Rotation::cur());
                    let ismstore_alu = cells.query_advice(pac_carry[3], Rotation::cur());

                    vec![
                        (
                            gate_alu.clone() * rwc_alu.clone(),
                            gate_cpu.clone() * rwc_cpu.clone(),
                        ),
                        (
                            gate_alu.clone() * call_id_alu.clone(),
                            gate_cpu.clone() * call_id_cpu.clone(),
                        ),
                        (
                            gate_alu.clone() * addr_alu.clone(),
                            gate_cpu.clone() * rlc_a_cpu.clone(),
                        ),
                        (
                            gate_alu.clone() * rlc_a_alu.clone(),
                            gate_cpu.clone()
                                * (ismload_cpu.clone() * rlc_c_cpu.clone()
                                    + (ismstore_cpu.clone() + ismstore8_cpu.clone()) * rlc_b_cpu.clone()),
                        ),
                        (
                            gate_alu.clone() * ismload_alu.clone(),
                            gate_cpu.clone() * ismload_cpu.clone(),
                        ),
                        (
                            gate_alu.clone() * ismstore_alu.clone(),
                            gate_cpu.clone() * ismstore_cpu.clone(),
                        ),
                        (
                            gate_alu.clone() * ismstore8_alu.clone(),
                            gate_cpu.clone() * ismstore8_cpu.clone(),
                        ),
                    ]
                });
        */
        meta.lookup_any("alu to memory", |cells| {
            let q_rt = cells.query_selector(q_rt.clone());
            let rwc_rt = cells.query_advice(rw_counter_rt, Rotation::cur());
            let address_rt = cells.query_advice(address_rt, Rotation::cur());
            let value_rt = cells.query_advice(value_rt, Rotation::cur());
            let iswrite_rt = cells.query_advice(iswrite_rt, Rotation::cur());
            let tag_rt = cells.query_advice(tag_rt, Rotation::cur());
            let call_id_rt = cells.query_advice(call_id_rt, Rotation::cur());
            let storage_key_rt = cells.query_advice(storage_key_rt, Rotation::cur());
            let field_tag_rt = cells.query_advice(field_tag_rt, Rotation::cur());
            let isend_rt = cells.query_advice(isend_rt, Rotation::cur());

            let q_alu = cells.query_selector(q_alu);
            let rwc_alu = cells.query_advice(pac_carry[1], Rotation::cur());
            let address_alu = cells.query_advice(carry_alu, Rotation::cur());
            let byte_alu = cells.query_advice(noname_alu, Rotation::cur());
            let ismload_alu = cells.query_advice(pac_carry[2], Rotation::cur());
            let ismstore_alu = cells.query_advice(pac_carry[3], Rotation::cur())
                + cells.query_advice(pac_carry[0], Rotation::cur());
            let byte32_alu = cells.query_advice(byte32_alu, Rotation::cur());
            let call_id_alu = cells.query_advice(rem_alu, Rotation::cur());
            let gate_alu = q_alu.clone() * byte32_alu.clone();
            let one = Expression::Constant(F::ONE);
            let zero = Expression::Constant(F::ZERO);

            vec![
                (
                    gate_alu.clone() * one.clone(),
                    q_rt.clone() * tag_rt.clone(),
                ),
                (
                    gate_alu.clone() * call_id_alu.clone(),
                    q_rt.clone() * call_id_rt.clone(),
                ),
                (
                    gate_alu.clone() * address_alu.clone(),
                    q_rt.clone() * address_rt.clone(),
                ),
                (zero.clone(), q_rt.clone() * field_tag_rt.clone()),
                (zero.clone(), q_rt.clone() * storage_key_rt.clone()),
                (
                    gate_alu.clone() * rwc_alu.clone(),
                    q_rt.clone() * rwc_rt.clone(),
                ),
                (
                    gate_alu.clone() * byte_alu.clone(),
                    q_rt.clone() * value_rt.clone(),
                ),
                (
                    gate_alu.clone() * ismstore_alu.clone(),
                    q_rt.clone() * iswrite_rt.clone(),
                ),
                (zero.clone(), q_rt.clone() * isend_rt.clone()),
            ]
        });

        meta.lookup_any("cpu to stack, read rlc_addr_a", |cells| {
            let q_cpu = cells.query_selector(q_cpu);
            let q_rt = cells.query_selector(q_rt);

            let isadd_cpu = cells.query_advice(isadd_cpu, Rotation::cur());
            let issub_cpu = cells.query_advice(issub_cpu, Rotation::cur());
            let ismul_cpu = cells.query_advice(ismul_cpu, Rotation::cur());
            let isdiv_cpu = cells.query_advice(isdiv_cpu, Rotation::cur());
            let islt_cpu = cells.query_advice(islt_cpu, Rotation::cur());
            let iseq_cpu = cells.query_advice(iseq_cpu, Rotation::cur());
            let isand_cpu = cells.query_advice(isand_cpu, Rotation::cur());
            let isor_cpu = cells.query_advice(isor_cpu, Rotation::cur());
            let isxor_cpu = cells.query_advice(isxor_cpu, Rotation::cur());
            let isnot_cpu = cells.query_advice(isnot_cpu, Rotation::cur());
            let isjump_cpu = cells.query_advice(isjump_cpu, Rotation::cur());
            let isjumpcon_cpu = cells.query_advice(isjumpcon_cpu, Rotation::cur());
            let ismload_cpu = cells.query_advice(ismload_cpu, Rotation::cur());
            let ismstore_cpu = cells.query_advice(ismstore_cpu, Rotation::cur());
            let ismstore8_cpu = cells.query_advice(ismstore8_cpu, Rotation::cur());
            let isread_cpu = cells.query_advice(isread_cpu, Rotation::cur());

            let opcode_sum = isadd_cpu.clone()
                + issub_cpu.clone()
                + ismul_cpu.clone()
                + isdiv_cpu.clone()
                + islt_cpu.clone()
                + iseq_cpu.clone()
                + isand_cpu.clone()
                + isor_cpu.clone()
                + isxor_cpu.clone()
                + isnot_cpu.clone()
                + isjump_cpu.clone()
                + isjumpcon_cpu.clone()
                + ismload_cpu.clone()
                + ismstore_cpu.clone()
                + ismstore8_cpu.clone()
                + isread_cpu.clone();

            let gate = q_cpu.clone() * opcode_sum.clone();
            let call_id_cpu = cells.query_advice(call_id_cpu, Rotation::cur());
            let rlc_a_cpu = cells.query_advice(rlc_a_cpu, Rotation::cur());
            let rw_counter_cpu = cells.query_advice(rw_counter_cpu, Rotation::cur());

            let rlc_addr_a = cells.query_advice(rlc_addr_a_cpu, Rotation::cur());

            let tag_rt = cells.query_advice(tag_rt, Rotation::cur());
            let call_id_rt = cells.query_advice(call_id_rt, Rotation::cur());
            let address_rt = cells.query_advice(address_rt, Rotation::cur());
            let field_tag_rt = cells.query_advice(field_tag_rt, Rotation::cur());
            let storage_key_rt = cells.query_advice(storage_key_rt, Rotation::cur());
            let rw_counter_rt = cells.query_advice(rw_counter_rt, Rotation::cur());
            let value_rt = cells.query_advice(value_rt, Rotation::cur());
            let iswrite_rt = cells.query_advice(iswrite_rt, Rotation::cur());
            let isend_rt = cells.query_advice(isend_rt, Rotation::cur());
            let zero = Expression::Constant(F::ZERO);
            let one = Expression::Constant(F::ONE);
            let two = Expression::Constant(F::from(2u64));

            vec![
                (gate.clone() * two.clone(), q_rt.clone() * tag_rt.clone()),
                (
                    gate.clone() * call_id_cpu.clone(),
                    q_rt.clone() * call_id_rt.clone(),
                ),
                (
                    gate.clone() * rlc_addr_a.clone(),
                    q_rt.clone() * address_rt.clone(),
                ),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * field_tag_rt.clone(),
                ),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * storage_key_rt.clone(),
                ),
                (
                    gate.clone() * rw_counter_cpu.clone(),
                    q_rt.clone() * rw_counter_rt.clone(),
                ),
                (
                    gate.clone() * one.clone(),
                    q_rt.clone() * (one.clone() - iswrite_rt.clone()),
                ),
                (
                    gate.clone() * rlc_a_cpu.clone(),
                    q_rt.clone() * value_rt.clone(),
                ),
                (gate.clone() * zero.clone(), q_rt.clone() * isend_rt.clone()),
            ]
        });

        meta.lookup_any("cpu to memory, read rlc_addr_b", |cells| {
            let isadd_cpu = cells.query_advice(isadd_cpu, Rotation::cur());
            let issub_cpu = cells.query_advice(issub_cpu, Rotation::cur());
            let ismul_cpu = cells.query_advice(ismul_cpu, Rotation::cur());
            let isdiv_cpu = cells.query_advice(isdiv_cpu, Rotation::cur());
            let islt_cpu = cells.query_advice(islt_cpu, Rotation::cur());
            let iseq_cpu = cells.query_advice(iseq_cpu, Rotation::cur());
            let isand_cpu = cells.query_advice(isand_cpu, Rotation::cur());
            let isor_cpu = cells.query_advice(isor_cpu, Rotation::cur());
            let isxor_cpu = cells.query_advice(isxor_cpu, Rotation::cur());
            let isjumpcon_cpu = cells.query_advice(isjumpcon_cpu, Rotation::cur());
            let ismstore_cpu = cells.query_advice(ismstore_cpu, Rotation::cur());
            let ismstore8_cpu = cells.query_advice(ismstore8_cpu, Rotation::cur());

            let opcode_sum = isadd_cpu.clone()
                + issub_cpu.clone()
                + ismul_cpu.clone()
                + isdiv_cpu.clone()
                + islt_cpu.clone()
                + iseq_cpu.clone()
                + isand_cpu.clone()
                + isor_cpu.clone()
                + isxor_cpu.clone()
                + isjumpcon_cpu.clone()
                + ismstore_cpu.clone()
                + ismstore8_cpu.clone();

            let q_cpu = cells.query_selector(q_cpu);
            let gate = q_cpu.clone() * opcode_sum.clone();
            let rlc_b_cpu = cells.query_advice(rlc_b_cpu, Rotation::cur());
            let rlc_addr_b = cells.query_advice(rlc_addr_b_cpu, Rotation::cur());
            let call_id_cpu = cells.query_advice(call_id_cpu, Rotation::cur());
            let rw_counter_cpu = cells.query_advice(rw_counter_cpu, Rotation::cur());

            let q_rt = cells.query_selector(q_rt);
            let tag_rt = cells.query_advice(tag_rt, Rotation::cur());
            let call_id_rt = cells.query_advice(call_id_rt, Rotation::cur());
            let address_rt = cells.query_advice(address_rt, Rotation::cur());
            let field_tag_rt = cells.query_advice(field_tag_rt, Rotation::cur());
            let storage_key_rt = cells.query_advice(storage_key_rt, Rotation::cur());
            let rw_counter_rt = cells.query_advice(rw_counter_rt, Rotation::cur());
            let value_rt = cells.query_advice(value_rt, Rotation::cur());
            let iswrite_rt = cells.query_advice(iswrite_rt, Rotation::cur());
            let isend_rt = cells.query_advice(isend_rt, Rotation::cur());
            let zero = Expression::Constant(F::ZERO);
            let one = Expression::Constant(F::ONE);
            let two = Expression::Constant(F::from(2u64));
            vec![
                (gate.clone() * two.clone(), q_rt.clone() * tag_rt.clone()),
                (
                    gate.clone() * call_id_cpu.clone(),
                    q_rt.clone() * call_id_rt.clone(),
                ),
                (
                    gate.clone() * rlc_addr_b.clone(),
                    q_rt.clone() * address_rt.clone(),
                ),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * field_tag_rt.clone(),
                ),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * storage_key_rt.clone(),
                ),
                (
                    gate.clone() * (rw_counter_cpu.clone() + one.clone()),
                    q_rt.clone() * rw_counter_rt.clone(),
                ),
                (
                    gate.clone() * one.clone(),
                    q_rt.clone() * (one.clone() - iswrite_rt.clone()),
                ),
                (
                    gate.clone() * rlc_b_cpu.clone(),
                    q_rt.clone() * value_rt.clone(),
                ),
                (gate.clone() * zero.clone(), q_rt.clone() * isend_rt.clone()),
            ]
        });

        meta.lookup_any("cpu to memory, write on rlc_addr_c", |cells| {
            let isadd_cpu = cells.query_advice(isadd_cpu, Rotation::cur());
            let issub_cpu = cells.query_advice(issub_cpu, Rotation::cur());
            let ismul_cpu = cells.query_advice(ismul_cpu, Rotation::cur());
            let isdiv_cpu = cells.query_advice(isdiv_cpu, Rotation::cur());
            let islt_cpu = cells.query_advice(islt_cpu, Rotation::cur());
            let iseq_cpu = cells.query_advice(iseq_cpu, Rotation::cur());
            let isand_cpu = cells.query_advice(isand_cpu, Rotation::cur());
            let isor_cpu = cells.query_advice(isor_cpu, Rotation::cur());
            let isxor_cpu = cells.query_advice(isxor_cpu, Rotation::cur());

            let iswrite_cpu = cells.query_advice(iswrite_cpu, Rotation::cur());
            let ismload_cpu = cells.query_advice(ismload_cpu, Rotation::cur());
            let isnot_cpu = cells.query_advice(isnot_cpu, Rotation::cur());

            let opcode2_sum = isadd_cpu.clone()
                + issub_cpu.clone()
                + ismul_cpu.clone()
                + isdiv_cpu.clone()
                + islt_cpu.clone()
                + iseq_cpu.clone()
                + isand_cpu.clone()
                + isor_cpu.clone()
                + isxor_cpu.clone();

            let opcode_sum =
                opcode2_sum.clone() + iswrite_cpu.clone() + ismload_cpu.clone() + isnot_cpu.clone();
            let two = Expression::Constant(F::from(2u64));
            let q_cpu = cells.query_selector(q_cpu);
            let gate = q_cpu.clone() * opcode_sum.clone();
            let rlc_c_cpu = cells.query_advice(rlc_c_cpu, Rotation::cur());
            let sp = cells.query_advice(sp_cpu, Rotation::cur());
            let rlc_addr_c = sp.clone()
                - opcode2_sum.clone() * two.clone()
                - ismload_cpu.clone()
                - isnot_cpu.clone();
            let call_id_cpu = cells.query_advice(call_id_cpu, Rotation::cur());
            let rw_counter_cpu = cells.query_advice(rw_counter_cpu, Rotation::cur());

            let q_rt = cells.query_selector(q_rt);
            let tag_rt = cells.query_advice(tag_rt, Rotation::cur());
            let call_id_rt = cells.query_advice(call_id_rt, Rotation::cur());
            let address_rt = cells.query_advice(address_rt, Rotation::cur());
            let field_tag_rt = cells.query_advice(field_tag_rt, Rotation::cur());
            let storage_key_rt = cells.query_advice(storage_key_rt, Rotation::cur());
            let rw_counter_rt = cells.query_advice(rw_counter_rt, Rotation::cur());
            let value_rt = cells.query_advice(value_rt, Rotation::cur());
            let iswrite_rt = cells.query_advice(iswrite_rt, Rotation::cur());
            let isend_rt = cells.query_advice(isend_rt, Rotation::cur());
            let zero = Expression::Constant(F::ZERO);
            let one = Expression::Constant(F::ONE);
            let thirty_three = Expression::Constant(F::from(33));

            vec![
                (gate.clone() * two.clone(), q_rt.clone() * tag_rt.clone()),
                (
                    gate.clone() * call_id_cpu.clone(),
                    q_rt.clone() * call_id_rt.clone(),
                ),
                (
                    gate.clone() * rlc_addr_c.clone(),
                    q_rt.clone() * address_rt.clone(),
                ),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * field_tag_rt.clone(),
                ),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * storage_key_rt.clone(),
                ),
                (
                    gate.clone()
                        * (rw_counter_cpu.clone()
                            + opcode2_sum.clone() * two.clone()
                            + ismload_cpu.clone() * thirty_three.clone()
                            + isnot_cpu.clone()),
                    q_rt.clone() * rw_counter_rt.clone(),
                ),
                (
                    gate.clone() * one.clone(),
                    q_rt.clone() * (iswrite_rt.clone()),
                ),
                (
                    gate.clone() * rlc_c_cpu.clone(),
                    q_rt.clone() * value_rt.clone(),
                ),
                (gate.clone() * zero.clone(), q_rt.clone() * isend_rt.clone()),
            ]
        });

        meta.lookup_any("cpu to alu, sorted(rlc_a_cpu => rlc_a_alu ..., includes every alu opcode else than sub)", |cells| {
            let one = Expression::Constant(F::ONE);
            let q_alu = cells.query_selector(q_alu);
            let q_cpu = cells.query_selector(q_cpu);
            let byte32_alu = cells.query_advice(byte32_alu, Rotation::cur());
            let gate_alu = q_alu.clone() * (one.clone() - byte32_alu.clone());
            let isfirst_alu = cells.query_fixed(isfirst_alu, Rotation::cur());
            let isadd_cpu = cells.query_advice(isadd_cpu, Rotation::cur());
            let ismul_cpu = cells.query_advice(ismul_cpu, Rotation::cur());
            let isdiv_cpu = cells.query_advice(isdiv_cpu, Rotation::cur());
            let islt_cpu = cells.query_advice(islt_cpu, Rotation::cur());
            let iseq_cpu = cells.query_advice(iseq_cpu, Rotation::cur());
            let isand_cpu = cells.query_advice(isand_cpu, Rotation::cur());
            let isor_cpu = cells.query_advice(isor_cpu, Rotation::cur());
            let isxor_cpu = cells.query_advice(isxor_cpu, Rotation::cur());
            let isnot_cpu = cells.query_advice(isnot_cpu, Rotation::cur());

            let rlc_a_cpu = cells.query_advice(rlc_a_cpu, Rotation::cur());
            let rlc_b_cpu = cells.query_advice(rlc_b_cpu, Rotation::cur());
            let rlc_c_cpu = cells.query_advice(rlc_c_cpu, Rotation::cur());

            let rlc_a_alu = cells.query_advice(rlc_a_alu, Rotation::cur());
            let rlc_b_alu = cells.query_advice(rlc_b_alu, Rotation::cur());
            let rlc_c_alu = cells.query_advice(rlc_c_alu, Rotation::cur());

            let isadd_alu = cells.query_advice(isadd_alu, Rotation::cur());
            let ismul_alu = cells.query_advice(ismul_alu, Rotation::cur());
            let isdiv_alu = cells.query_advice(isdiv_alu, Rotation::cur());
            let islt_alu = cells.query_advice(islt_alu, Rotation::cur());
            let iseq_alu = cells.query_advice(iseq_alu, Rotation::cur());
            let isand_alu = cells.query_advice(isand_alu, Rotation::cur());
            let isor_alu = cells.query_advice(isor_alu, Rotation::cur());
            let isxor_alu = cells.query_advice(isxor_alu, Rotation::cur());
            let isnot_alu = cells.query_advice(isnot_alu, Rotation::cur());
            let gate_cpu = q_cpu.clone()
                * (isadd_cpu.clone()
                    + ismul_cpu.clone()
                    + isdiv_cpu.clone()
                    + islt_cpu.clone()
                    + iseq_cpu.clone()
                    + isand_cpu.clone()
                    + isor_cpu.clone()
                    + isxor_cpu.clone()
                    + isnot_cpu.clone());
            vec![
                (
                    gate_cpu.clone() * one.clone(),
                    gate_alu.clone() * isfirst_alu.clone(),
                ),
                (
                    gate_cpu.clone() * isadd_cpu.clone(),
                    gate_alu.clone() * isadd_alu.clone(),
                ),
                (
                    gate_cpu.clone() * isadd_cpu.clone() * rlc_a_cpu.clone(),
                    gate_alu.clone() * isadd_alu.clone() * rlc_a_alu.clone(),
                ),
                (
                    gate_cpu.clone() * isadd_cpu.clone() * rlc_b_cpu.clone(),
                    gate_alu.clone() * isadd_alu.clone() * rlc_b_alu.clone(),
                ),
                (
                    gate_cpu.clone() * isadd_cpu.clone() * rlc_c_cpu.clone(),
                    gate_alu.clone() * isadd_alu.clone() * rlc_c_alu.clone(),
                ),
                (
                    gate_cpu.clone() * ismul_cpu.clone(),
                    gate_alu.clone() * ismul_alu.clone(),
                ),
                (
                    gate_cpu.clone() * ismul_cpu.clone() * rlc_a_cpu.clone(),
                    gate_alu.clone() * ismul_alu.clone() * rlc_a_alu.clone(),
                ),
                (
                    gate_cpu.clone() * ismul_cpu.clone() * rlc_b_cpu.clone(),
                    gate_alu.clone() * ismul_alu.clone() * rlc_b_alu.clone(),
                ),
                (
                    gate_cpu.clone() * ismul_cpu.clone() * rlc_c_cpu.clone(),
                    gate_alu.clone() * ismul_alu.clone() * rlc_c_alu.clone(),
                ),
                (
                    gate_cpu.clone() * isdiv_cpu.clone(),
                    gate_alu.clone() * isdiv_alu.clone(),
                ),
                (
                    gate_cpu.clone() * isdiv_cpu.clone() * rlc_c_cpu.clone(),
                    gate_alu.clone() * isdiv_alu.clone() * rlc_a_alu.clone(),
                ),
                (
                    gate_cpu.clone() * isdiv_cpu.clone() * rlc_b_cpu.clone(),
                    gate_alu.clone() * isdiv_alu.clone() * rlc_b_alu.clone(),
                ),
                (
                    gate_cpu.clone() * isdiv_cpu.clone() * rlc_a_cpu.clone(),
                    gate_alu.clone() * isdiv_alu.clone() * rlc_c_alu.clone(),
                ),
                (
                    gate_cpu.clone() * islt_cpu.clone(),
                    gate_alu.clone() * islt_alu.clone(),
                ),
                (
                    gate_cpu.clone() * islt_cpu.clone() * rlc_a_cpu.clone(),
                    gate_alu.clone() * islt_alu.clone() * rlc_a_alu.clone(),
                ),
                (
                    gate_cpu.clone() * islt_cpu.clone() * rlc_b_cpu.clone(),
                    gate_alu.clone() * islt_alu.clone() * rlc_b_alu.clone(),
                ),
                (
                    gate_cpu.clone() * islt_cpu.clone() * rlc_c_cpu.clone(),
                    gate_alu.clone() * islt_alu.clone() * rlc_c_alu.clone(),
                ),
                (
                    gate_cpu.clone() * iseq_cpu.clone(),
                    gate_alu.clone() * iseq_alu.clone(),
                ),
                (
                    gate_cpu.clone() * iseq_cpu.clone() * rlc_a_cpu.clone(),
                    gate_alu.clone() * iseq_alu.clone() * rlc_a_alu.clone(),
                ),
                (
                    gate_cpu.clone() * iseq_cpu.clone() * rlc_b_cpu.clone(),
                    gate_alu.clone() * iseq_alu.clone() * rlc_b_alu.clone(),
                ),
                (
                    gate_cpu.clone() * iseq_cpu.clone() * rlc_c_cpu.clone(),
                    gate_alu.clone() * iseq_alu.clone() * rlc_c_alu.clone(),
                ),
                (
                    gate_cpu.clone() * isand_cpu.clone(),
                    gate_alu.clone() * isand_alu.clone(),
                ),
                (
                    gate_cpu.clone() * isand_cpu.clone() * rlc_a_cpu.clone(),
                    gate_alu.clone() * isand_alu.clone() * rlc_a_alu.clone(),
                ),
                (
                    gate_cpu.clone() * isand_cpu.clone() * rlc_b_cpu.clone(),
                    gate_alu.clone() * isand_alu.clone() * rlc_b_alu.clone(),
                ),
                (
                    gate_cpu.clone() * isand_cpu.clone() * rlc_c_cpu.clone(),
                    gate_alu.clone() * isand_alu.clone() * rlc_c_alu.clone(),
                ),
                (
                    gate_cpu.clone() * isor_cpu.clone(),
                    gate_alu.clone() * isor_alu.clone(),
                ),
                (
                    gate_cpu.clone() * isor_cpu.clone() * rlc_a_cpu.clone(),
                    gate_alu.clone() * isor_alu.clone() * rlc_a_alu.clone(),
                ),
                (
                    gate_cpu.clone() * isor_cpu.clone() * rlc_b_cpu.clone(),
                    gate_alu.clone() * isor_alu.clone() * rlc_b_alu.clone(),
                ),
                (
                    gate_cpu.clone() * isor_cpu.clone() * rlc_c_cpu.clone(),
                    gate_alu.clone() * isor_alu.clone() * rlc_c_alu.clone(),
                ),
                (
                    gate_cpu.clone() * isxor_cpu.clone(),
                    gate_alu.clone() * isxor_alu.clone(),
                ),
                (
                    gate_cpu.clone() * isxor_cpu.clone() * rlc_a_cpu.clone(),
                    gate_alu.clone() * isxor_alu.clone() * rlc_a_alu.clone(),
                ),
                (
                    gate_cpu.clone() * isxor_cpu.clone() * rlc_b_cpu.clone(),
                    gate_alu.clone() * isxor_alu.clone() * rlc_b_alu.clone(),
                ),
                (
                    gate_cpu.clone() * isxor_cpu.clone() * rlc_c_cpu.clone(),
                    gate_alu.clone() * isxor_alu.clone() * rlc_c_alu.clone(),
                ),
                (
                    gate_cpu.clone() * isnot_cpu.clone(),
                    gate_alu.clone() * isnot_alu.clone(),
                ),
                (
                    gate_cpu.clone() * isnot_cpu.clone() * rlc_a_cpu.clone(),
                    gate_alu.clone() * isnot_alu.clone() * rlc_a_alu.clone(),
                ),
                (
                    gate_cpu.clone() * isnot_cpu.clone() * rlc_b_cpu.clone(),
                    gate_alu.clone() * isnot_alu.clone() * rlc_b_alu.clone(),
                ),
                (
                    gate_cpu.clone() * isnot_cpu.clone() * rlc_c_cpu.clone(),
                    gate_alu.clone() * isnot_alu.clone() * rlc_c_alu.clone(),
                ),
            ]
        });

        meta.lookup_any("cpu to alu, issub", |cells| {
            let one = Expression::Constant(F::ONE);
            let q_alu = cells.query_selector(q_alu);
            let q_cpu = cells.query_selector(q_cpu);
            let byte32_alu = cells.query_advice(byte32_alu, Rotation::cur());
            let gate_alu = q_alu.clone() * (one.clone() - byte32_alu.clone());
            let isfirst_alu = cells.query_fixed(isfirst_alu, Rotation::cur());
            let issub_cpu = cells.query_advice(issub_cpu, Rotation::cur());

            let rlc_a_cpu = cells.query_advice(rlc_a_cpu, Rotation::cur());
            let rlc_b_cpu = cells.query_advice(rlc_b_cpu, Rotation::cur());
            let rlc_c_cpu = cells.query_advice(rlc_c_cpu, Rotation::cur());

            let rlc_a_alu = cells.query_advice(rlc_a_alu, Rotation::cur());
            let rlc_b_alu = cells.query_advice(rlc_b_alu, Rotation::cur());
            let rlc_c_alu = cells.query_advice(rlc_c_alu, Rotation::cur());

            let isadd_alu = cells.query_advice(isadd_alu, Rotation::cur());
            let gate_cpu = q_cpu.clone() * issub_cpu.clone();
            vec![
                (
                    gate_cpu.clone() * one.clone(),
                    gate_alu.clone() * isfirst_alu.clone(),
                ),
                (
                    gate_cpu.clone() * issub_cpu.clone(),
                    gate_alu.clone() * isadd_alu.clone(),
                ),
                (
                    gate_cpu.clone() * issub_cpu.clone() * rlc_a_cpu.clone(),
                    gate_alu.clone() * isadd_alu.clone() * rlc_c_alu.clone(),
                ),
                (
                    gate_cpu.clone() * issub_cpu.clone() * rlc_b_cpu.clone(),
                    gate_alu.clone() * isadd_alu.clone() * rlc_b_alu.clone(),
                ),
                (
                    gate_cpu.clone() * issub_cpu.clone() * rlc_c_cpu.clone(),
                    gate_alu.clone() * isadd_alu.clone() * rlc_a_alu.clone(),
                ),
            ]
        });

        meta.lookup_any("cpu to byte, iscode = 1", |cells| {
            let q_cpu = cells.query_selector(q_cpu);
            let gate = q_cpu;
            let call_id_cpu = cells.query_advice(call_id_cpu, Rotation::cur());
            let pc_cpu = cells.query_advice(pc_cpu, Rotation::cur());
            let opcode_cpu = cells.query_advice(opcode_cpu, Rotation::cur());
            let byte_active = cells.query_instance(byte_active, Rotation::cur());
            let call_id_byte = cells.query_instance(call_id_bytetable, Rotation::cur());
            let pc_byte = cells.query_instance(pc_bytetable, Rotation::cur());
            let limb1_byte = cells.query_instance(limb1_bytetable, Rotation::cur());
            let iscode_byte = cells.query_instance(iscode_bytetable, Rotation::cur());

            vec![
                (gate.clone(), byte_active.clone()),
                (gate.clone(), byte_active.clone() * iscode_byte),
                (
                    gate.clone() * call_id_cpu,
                    byte_active.clone() * call_id_byte,
                ),
                (gate.clone() * pc_cpu, byte_active.clone() * pc_byte),
                (gate * opcode_cpu, byte_active * limb1_byte),
            ]
        });

        meta.lookup_any("cpu to byte, iscode = 0", |cells| {
            let r = cells.query_challenge(rc);

            let q_cpu = cells.query_selector(q_cpu);

            let iswrite = cells.query_advice(iswrite_cpu, Rotation::cur());

            let gate = q_cpu * iswrite;

            let rlc_cpu = cells.query_advice(rlc_c_cpu, Rotation::cur());

            let pc_cpu = cells.query_advice(pc_cpu, Rotation::cur());
            let call_id_cpu = cells.query_advice(call_id_cpu, Rotation::cur());

            let byte_active = cells.query_instance(byte_active, Rotation::cur());
            let call_id_byte = cells.query_instance(call_id_bytetable, Rotation::cur());

            let pc_byte = cells.query_instance(pc_bytetable, Rotation::cur());

            let limb1_byte = cells.query_instance(limb1_bytetable, Rotation::cur());

            let limb2_byte = cells.query_instance(limb2_bytetable, Rotation::cur());

            let limb3_byte = cells.query_instance(limb3_bytetable, Rotation::cur());

            let limb4_byte = cells.query_instance(limb4_bytetable, Rotation::cur());

            let iscode_byte = cells.query_instance(iscode_bytetable, Rotation::cur());

            let one = Expression::Constant(F::ONE);

            let byte_rlc = limb1_byte
                + limb2_byte * r.clone()
                + limb3_byte * r.clone() * r.clone()
                + limb4_byte * r.clone() * r.clone() * r;

            vec![
                (gate.clone(), byte_active.clone()),
                (
                    gate.clone(),
                    byte_active.clone() * (one.clone() - iscode_byte),
                ),
                (gate.clone() * rlc_cpu, byte_active.clone() * byte_rlc),
                (
                    gate.clone() * call_id_cpu,
                    byte_active.clone() * call_id_byte,
                ),
                (gate.clone() * pc_cpu, byte_active * (pc_byte - one)),
            ]
        });

        meta.lookup_any("byte limb1 to alu", |cells| {
            let one = Expression::Constant(F::ONE);
            let byte_active = cells.query_instance(byte_active, Rotation::cur());
            let gate_alu = cells.query_selector(q_alu) * (one.clone() - cells.query_advice(byte32_alu, Rotation::cur()));
            
            let limb_a_alu = cells.query_advice(limb_a_alu, Rotation::cur());

            let limb1_byte = cells.query_instance(limb1_bytetable, Rotation::cur());

            vec![
                (byte_active.clone(), gate_alu.clone()),
                (byte_active.clone() * limb1_byte.clone(), gate_alu.clone() * limb_a_alu.clone()),
            ]
        });
        meta.lookup_any("byte limb2 to alu", |cells| {
            let one = Expression::Constant(F::ONE);
            let byte_active = cells.query_instance(byte_active, Rotation::cur());
            let gate_alu = cells.query_selector(q_alu) * (one.clone() - cells.query_advice(byte32_alu, Rotation::cur()));
            
            let limb_a_alu = cells.query_advice(limb_a_alu, Rotation::cur());

            let limb2_byte = cells.query_instance(limb2_bytetable, Rotation::cur());

            vec![
                (byte_active.clone(), gate_alu.clone()),
                (byte_active.clone() * limb2_byte.clone(), gate_alu.clone() * limb_a_alu.clone()),
            ]
        });
        meta.lookup_any("byte limb3 to alu", |cells| {
            let one = Expression::Constant(F::ONE);
            let byte_active = cells.query_instance(byte_active, Rotation::cur());
            let gate_alu = cells.query_selector(q_alu) * (one.clone() - cells.query_advice(byte32_alu, Rotation::cur()));
            
            let limb_a_alu = cells.query_advice(limb_a_alu, Rotation::cur());

            let limb3_byte = cells.query_instance(limb3_bytetable, Rotation::cur());

            vec![
                (byte_active.clone(), gate_alu.clone()),
                (byte_active.clone() * limb3_byte.clone(), gate_alu.clone() * limb_a_alu.clone()),
            ]
        });
        meta.lookup_any("byte limb4 to alu", |cells| {
            let one = Expression::Constant(F::ONE);
            let byte_active = cells.query_instance(byte_active, Rotation::cur());
            let gate_alu = cells.query_selector(q_alu) * (one.clone() - cells.query_advice(byte32_alu, Rotation::cur()));
            
            let limb_a_alu = cells.query_advice(limb_a_alu, Rotation::cur());

            let limb4_byte = cells.query_instance(limb4_bytetable, Rotation::cur());

            vec![
                (byte_active.clone(), gate_alu.clone()),
                (byte_active.clone() * limb4_byte.clone(), gate_alu.clone() * limb_a_alu.clone()),
            ]
        });

        meta.lookup("cpu to rom", |cells| {
            let opcode = cells.query_advice(opcode_cpu, Rotation::cur());
            let q_cpu = cells.query_selector(q_cpu);
            let isadd_cpu = cells.query_advice(isadd_cpu, Rotation::cur());
            let issub_cpu = cells.query_advice(issub_cpu, Rotation::cur());
            let ismul_cpu = cells.query_advice(ismul_cpu, Rotation::cur());
            let isdiv_cpu = cells.query_advice(isdiv_cpu, Rotation::cur());
            let islt_cpu = cells.query_advice(islt_cpu, Rotation::cur());
            let iseq_cpu = cells.query_advice(iseq_cpu, Rotation::cur());
            let isand_cpu = cells.query_advice(isand_cpu, Rotation::cur());
            let isor_cpu = cells.query_advice(isor_cpu, Rotation::cur());
            let isxor_cpu = cells.query_advice(isxor_cpu, Rotation::cur());
            let isnot_cpu = cells.query_advice(isnot_cpu, Rotation::cur());
            let isread_cpu = cells.query_advice(isread_cpu, Rotation::cur());
            let iswrite_cpu = cells.query_advice(iswrite_cpu, Rotation::cur());
            let ishalt_cpu = cells.query_advice(ishalt_cpu, Rotation::cur());
            let begintx_cpu = cells.query_advice(isbegintx_cpu, Rotation::cur());
            let endtx_cpu = cells.query_advice(isendtx_cpu, Rotation::cur());
            let iscall_cpu = cells.query_advice(iscall_cpu, Rotation::cur());
            let isreturn_cpu = cells.query_advice(isreturn_cpu, Rotation::cur());
            let returndatacopy_cpu = cells.query_advice(returndatacopy_cpu, Rotation::cur());
            let calldatacopy_cpu = cells.query_advice(calldatacopy_cpu, Rotation::cur());
            let isjump_cpu = cells.query_advice(isjump_cpu, Rotation::cur());
            let isjumpdest_cpu = cells.query_advice(isjumpdest_cpu, Rotation::cur());
            let isjumpcon_cpu = cells.query_advice(isjumpcon_cpu, Rotation::cur());
            let ismload_cpu = cells.query_advice(ismload_cpu, Rotation::cur());
            let ismstore_cpu = cells.query_advice(ismstore_cpu, Rotation::cur());
            let ismstore8_cpu = cells.query_advice(ismstore8_cpu, Rotation::cur());

            vec![
                (q_cpu.clone() * opcode, byte_rom.clone()),
                (q_cpu.clone() * isadd_cpu, isadd_rom),
                (q_cpu.clone() * issub_cpu, issub_rom),
                (q_cpu.clone() * ismul_cpu, ismul_rom),
                (q_cpu.clone() * isdiv_cpu, isdiv_rom),
                (q_cpu.clone() * islt_cpu, islt_rom),
                (q_cpu.clone() * iseq_cpu, iseq_rom),
                (q_cpu.clone() * isand_cpu, isand_rom),
                (q_cpu.clone() * isor_cpu, isor_rom),
                (q_cpu.clone() * isxor_cpu, isxor_rom),
                (q_cpu.clone() * isnot_cpu, isnot_rom),
                (q_cpu.clone() * isread_cpu, isread_rom),
                (q_cpu.clone() * iswrite_cpu, iswrite_rom),
                (q_cpu.clone() * ishalt_cpu, ishalt_rom),
                (q_cpu.clone() * begintx_cpu, begintx_rom),
                (q_cpu.clone() * endtx_cpu, endtx_rom),
                (q_cpu.clone() * iscall_cpu, iscall_rom),
                (q_cpu.clone() * isreturn_cpu, isreturn_rom),
                (q_cpu.clone() * returndatacopy_cpu, returndatacopy_rom),
                (q_cpu.clone() * calldatacopy_cpu, calldatacopy_rom),
                (q_cpu.clone() * isjump_cpu, isjump_rom),
                (q_cpu.clone() * isjumpdest_cpu, isjumpdest_rom),
                (q_cpu.clone() * isjumpcon_cpu, isjumpcon_rom),
                (q_cpu.clone() * ismload_cpu, ismload_rom),
                (q_cpu.clone() * ismstore_cpu, ismstore_rom),
                (q_cpu.clone() * ismstore8_cpu, ismstore8_rom),
            ]
        });
        //////////////////////////////////////////////////
        meta.lookup_any("cpu to rt, w, callerid, iscall", |cells| {
            let gate =
                cells.query_advice(iscall_cpu, Rotation::cur()) * cells.query_selector(q_cpu);
            let q_rt = cells.query_selector(q_rt);
            let caller_id = cells.query_advice(call_id_cpu, Rotation::cur());
            let value = cells.query_advice(value_rt, Rotation::cur());
            let tag_rt = cells.query_advice(tag_rt, Rotation::cur());
            let call_id_rt = cells.query_advice(call_id_rt, Rotation::cur());
            let address_rt = cells.query_advice(address_rt, Rotation::cur());
            let ft_rt = cells.query_advice(field_tag_rt, Rotation::cur());
            let storage_key_rt = cells.query_advice(storage_key_rt, Rotation::cur());
            let rwc_rt = cells.query_advice(rw_counter_rt, Rotation::cur());
            let iswrite_rt = cells.query_advice(iswrite_rt, Rotation::cur());
            let zero = Expression::Constant(F::ZERO);
            let one = Expression::Constant(F::ONE);
            let tag_cpu = Expression::Constant(F::from(5u64));
            let rwc_cpu = cells.query_advice(rw_counter_cpu, Rotation::cur());
            let ft_cpu = Expression::Constant(F::from(2u64));
            let notisend = one.clone() - cells.query_advice(isend_rt, Rotation::cur());
            vec![
                (
                    gate.clone() * caller_id.clone(),
                    q_rt.clone() * value.clone(),
                ),
                (
                    gate.clone() * tag_cpu.clone(),
                    q_rt.clone() * tag_rt.clone(),
                ),
                (
                    gate.clone() * rwc_cpu.clone(),
                    q_rt.clone() * call_id_rt.clone(),
                ),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * address_rt.clone(),
                ),
                (gate.clone() * ft_cpu.clone(), q_rt.clone() * ft_rt.clone()),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * storage_key_rt.clone(),
                ),
                (
                    gate.clone() * rwc_cpu.clone(),
                    q_rt.clone() * rwc_rt.clone(),
                ),
                (
                    gate.clone() * one.clone(),
                    q_rt.clone() * iswrite_rt.clone(),
                ),
                (gate.clone() * one.clone(), q_rt.clone() * notisend),
            ]
        });

        meta.lookup_any("cpu to rt, w, callerid, isbegintx", |cells| {
            let gate =
                cells.query_advice(isbegintx_cpu, Rotation::cur()) * cells.query_selector(q_cpu);
            let q_rt = cells.query_selector(q_rt);
            let _caller_id = cells.query_advice(call_id_cpu, Rotation::cur());
            let value = cells.query_advice(value_rt, Rotation::cur());
            let tag_rt = cells.query_advice(tag_rt, Rotation::cur());
            let call_id_rt = cells.query_advice(call_id_rt, Rotation::cur());
            let address_rt = cells.query_advice(address_rt, Rotation::cur());
            let ft_rt = cells.query_advice(field_tag_rt, Rotation::cur());
            let storage_key_rt = cells.query_advice(storage_key_rt, Rotation::cur());
            let rwc_rt = cells.query_advice(rw_counter_rt, Rotation::cur());
            let iswrite_rt = cells.query_advice(iswrite_rt, Rotation::cur());
            let zero = Expression::Constant(F::ZERO);
            let one = Expression::Constant(F::ONE);
            let tag_cpu = Expression::Constant(F::from(5u64));
            let rwc_cpu = cells.query_advice(rw_counter_cpu, Rotation::cur());
            let ft_cpu = Expression::Constant(F::from(2u64));
            let notisend = one.clone() - cells.query_advice(isend_rt, Rotation::cur());
            vec![
                (gate.clone() * zero.clone(), q_rt.clone() * value.clone()),
                (
                    gate.clone() * tag_cpu.clone(),
                    q_rt.clone() * tag_rt.clone(),
                ),
                (
                    gate.clone() * one.clone(),
                    q_rt.clone() * call_id_rt.clone(),
                ),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * address_rt.clone(),
                ),
                (gate.clone() * ft_cpu.clone(), q_rt.clone() * ft_rt.clone()),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * storage_key_rt.clone(),
                ),
                (
                    gate.clone() * rwc_cpu.clone(),
                    q_rt.clone() * rwc_rt.clone(),
                ),
                (
                    gate.clone() * one.clone(),
                    q_rt.clone() * iswrite_rt.clone(),
                ),
                (gate.clone() * one.clone(), q_rt.clone() * notisend),
            ]
        });

        meta.lookup_any("cpu to rt, r, depth, iscall", |cells| {
            let gate =
                cells.query_advice(iscall_cpu, Rotation::cur()) * cells.query_selector(q_cpu);
            let q_rt = cells.query_selector(q_rt);
            let rlc = cells.query_advice(rlc_a_cpu, Rotation::cur());
            let value = cells.query_advice(value_rt, Rotation::cur());
            let tag_rt = cells.query_advice(tag_rt, Rotation::cur());
            let call_id_rt = cells.query_advice(call_id_rt, Rotation::cur());
            let address_rt = cells.query_advice(address_rt, Rotation::cur());
            let ft_rt = cells.query_advice(field_tag_rt, Rotation::cur());
            let storage_key_rt = cells.query_advice(storage_key_rt, Rotation::cur());
            let rwc_rt = cells.query_advice(rw_counter_rt, Rotation::cur());
            let iswrite_rt = cells.query_advice(iswrite_rt, Rotation::cur());
            let zero = Expression::Constant(F::ZERO);
            let one = Expression::Constant(F::ONE);
            let rwc_adder = Expression::Constant(F::ONE);
            let rwc_cpu = cells.query_advice(rw_counter_cpu, Rotation::cur());
            let tag_cpu = Expression::Constant(F::from(5u64));
            let call_id_cpu = cells.query_advice(call_id_cpu, Rotation::cur());
            let ft_cpu = Expression::Constant(F::from(4u64));
            let notisend = one.clone() - cells.query_advice(isend_rt, Rotation::cur());
            vec![
                (
                    gate.clone() * rlc.clone(),
                    q_rt.clone() * (value.clone() + one.clone()),
                ),
                (
                    gate.clone() * tag_cpu.clone(),
                    q_rt.clone() * tag_rt.clone(),
                ),
                (
                    gate.clone() * call_id_cpu,
                    q_rt.clone() * call_id_rt.clone(),
                ),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * address_rt.clone(),
                ),
                (gate.clone() * ft_cpu.clone(), q_rt.clone() * ft_rt.clone()),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * storage_key_rt.clone(),
                ),
                (
                    gate.clone() * (rwc_cpu.clone() + rwc_adder.clone()),
                    q_rt.clone() * rwc_rt.clone(),
                ),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * iswrite_rt.clone(),
                ),
                (gate.clone() * one.clone(), q_rt.clone() * notisend),
            ]
        });

        meta.lookup_any("cpu to rt, w, depth, iscall", |cells| {
            let gate =
                cells.query_advice(iscall_cpu, Rotation::cur()) * cells.query_selector(q_cpu);
            let q_rt = cells.query_selector(q_rt);
            let rlc = cells.query_advice(rlc_a_cpu, Rotation::cur());
            let value = cells.query_advice(value_rt, Rotation::cur());
            let tag_rt = cells.query_advice(tag_rt, Rotation::cur());
            let call_id_rt = cells.query_advice(call_id_rt, Rotation::cur());
            let address_rt = cells.query_advice(address_rt, Rotation::cur());
            let ft_rt = cells.query_advice(field_tag_rt, Rotation::cur());
            let storage_key_rt = cells.query_advice(storage_key_rt, Rotation::cur());
            let rwc_rt = cells.query_advice(rw_counter_rt, Rotation::cur());
            let iswrite_rt = cells.query_advice(iswrite_rt, Rotation::cur());
            let zero = Expression::Constant(F::ZERO);
            let one = Expression::Constant(F::ONE);
            let rwc_adder = Expression::Constant(F::from(2u64));
            let tag_cpu = Expression::Constant(F::from(5u64));
            let rwc_cpu = cells.query_advice(rw_counter_cpu, Rotation::cur());
            let ft_cpu = Expression::Constant(F::from(4u64));
            let notisend = one.clone() - cells.query_advice(isend_rt, Rotation::cur());
            vec![
                (gate.clone() * rlc.clone(), q_rt.clone() * value.clone()),
                (
                    gate.clone() * tag_cpu.clone(),
                    q_rt.clone() * tag_rt.clone(),
                ),
                (
                    gate.clone() * rwc_cpu.clone(),
                    q_rt.clone() * call_id_rt.clone(),
                ),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * address_rt.clone(),
                ),
                (gate.clone() * ft_cpu.clone(), q_rt.clone() * ft_rt.clone()),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * storage_key_rt.clone(),
                ),
                (
                    gate.clone() * (rwc_cpu.clone() + rwc_adder.clone()),
                    q_rt.clone() * rwc_rt.clone(),
                ),
                (
                    gate.clone() * one.clone(),
                    q_rt.clone() * iswrite_rt.clone(),
                ),
                (gate.clone() * one.clone(), q_rt.clone() * notisend),
            ]
        });

        meta.lookup_any("cpu to rt, w, depth, isbegintx", |cells| {
            let gate =
                cells.query_advice(isbegintx_cpu, Rotation::cur()) * cells.query_selector(q_cpu);
            let q_rt = cells.query_selector(q_rt);
            let caller_id = cells.query_advice(call_id_cpu, Rotation::cur());
            let value = cells.query_advice(value_rt, Rotation::cur());
            let tag_rt = cells.query_advice(tag_rt, Rotation::cur());
            let call_id_rt = cells.query_advice(call_id_rt, Rotation::cur());
            let address_rt = cells.query_advice(address_rt, Rotation::cur());
            let ft_rt = cells.query_advice(field_tag_rt, Rotation::cur());
            let storage_key_rt = cells.query_advice(storage_key_rt, Rotation::cur());
            let rwc_rt = cells.query_advice(rw_counter_rt, Rotation::cur());
            let iswrite_rt = cells.query_advice(iswrite_rt, Rotation::cur());
            let zero = Expression::Constant(F::ZERO);
            let one = Expression::Constant(F::ONE);
            let tag_cpu = Expression::Constant(F::from(5u64));
            let rwc_cpu = cells.query_advice(rw_counter_cpu, Rotation::cur());
            let ft_cpu = Expression::Constant(F::from(4u64));
            let notisend = one.clone() - cells.query_advice(isend_rt, Rotation::cur());
            vec![
                (gate.clone() * one.clone(), q_rt.clone() * value.clone()),
                (
                    gate.clone() * tag_cpu.clone(),
                    q_rt.clone() * tag_rt.clone(),
                ),
                (
                    gate.clone() * one.clone(),
                    q_rt.clone() * call_id_rt.clone(),
                ),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * address_rt.clone(),
                ),
                (gate.clone() * ft_cpu.clone(), q_rt.clone() * ft_rt.clone()),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * storage_key_rt.clone(),
                ),
                (
                    gate.clone() * (rwc_cpu.clone() + one.clone()),
                    q_rt.clone() * rwc_rt.clone(),
                ),
                (
                    gate.clone() * one.clone(),
                    q_rt.clone() * iswrite_rt.clone(),
                ),
                (gate.clone() * one.clone(), q_rt.clone() * notisend),
            ]
        });
        ///////////////////////////////////

        meta.lookup_any("cpu to rt, r, calldataoffset, iscall", |cells| {
            let gate =
                cells.query_advice(iscall_cpu, Rotation::cur()) * cells.query_selector(q_cpu);
            let q_rt = cells.query_selector(q_rt);
            let rlc = cells.query_advice(rlc_b_cpu, Rotation::cur());
            let value = cells.query_advice(value_rt, Rotation::cur());
            let sp = cells.query_advice(sp_cpu, Rotation::cur());
            let tag_rt = cells.query_advice(tag_rt, Rotation::cur());
            let call_id_rt = cells.query_advice(call_id_rt, Rotation::cur());
            let address_rt = cells.query_advice(address_rt, Rotation::cur());
            let ft_rt = cells.query_advice(field_tag_rt, Rotation::cur());
            let storage_key_rt = cells.query_advice(storage_key_rt, Rotation::cur());
            let rwc_rt = cells.query_advice(rw_counter_rt, Rotation::cur());
            let iswrite_rt = cells.query_advice(iswrite_rt, Rotation::cur());
            let zero = Expression::Constant(F::ZERO);
            let one = Expression::Constant(F::ONE);
            let two = Expression::Constant(F::from(2u64));
            let rwc_adder = Expression::Constant(F::from(3u64));
            let rwc_cpu = cells.query_advice(rw_counter_cpu, Rotation::cur());
            let tag_cpu = Expression::Constant(F::from(2u64));
            let call_id_cpu = cells.query_advice(call_id_cpu, Rotation::cur());
            let notisend = one.clone() - cells.query_advice(isend_rt, Rotation::cur());

            vec![
                (gate.clone() * rlc.clone(), q_rt.clone() * value.clone()),
                (
                    gate.clone() * tag_cpu.clone(),
                    q_rt.clone() * tag_rt.clone(),
                ),
                (
                    gate.clone() * call_id_cpu,
                    q_rt.clone() * call_id_rt.clone(),
                ),
                (
                    gate.clone() * (sp.clone() - one.clone()),
                    q_rt.clone() * address_rt.clone(),
                ),
                (gate.clone() * zero.clone(), q_rt.clone() * ft_rt.clone()),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * storage_key_rt.clone(),
                ),
                (
                    gate.clone() * (rwc_cpu.clone() + rwc_adder.clone()),
                    q_rt.clone() * rwc_rt.clone(),
                ),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * iswrite_rt.clone(),
                ),
                (gate.clone() * one.clone(), q_rt.clone() * notisend),
            ]
        });

        meta.lookup_any("cpu to rt, w, calldataoffset, iscall", |cells| {
            let gate =
                cells.query_advice(iscall_cpu, Rotation::cur()) * cells.query_selector(q_cpu);
            let q_rt = cells.query_selector(q_rt);
            let rlc = cells.query_advice(rlc_b_cpu, Rotation::cur());
            let value = cells.query_advice(value_rt, Rotation::cur());
            let tag_rt = cells.query_advice(tag_rt, Rotation::cur());
            let call_id_rt = cells.query_advice(call_id_rt, Rotation::cur());
            let address_rt = cells.query_advice(address_rt, Rotation::cur());
            let ft_rt = cells.query_advice(field_tag_rt, Rotation::cur());
            let storage_key_rt = cells.query_advice(storage_key_rt, Rotation::cur());
            let rwc_rt = cells.query_advice(rw_counter_rt, Rotation::cur());
            let iswrite_rt = cells.query_advice(iswrite_rt, Rotation::cur());
            let zero = Expression::Constant(F::ZERO);
            let one = Expression::Constant(F::ONE);
            let rwc_adder = Expression::Constant(F::from(4u64));
            let tag_cpu = Expression::Constant(F::from(5u64));
            let rwc_cpu = cells.query_advice(rw_counter_cpu, Rotation::cur());
            let ft_cpu = Expression::Constant(F::from(7u64));
            let notisend = one.clone() - cells.query_advice(isend_rt, Rotation::cur());
            vec![
                (gate.clone() * rlc.clone(), q_rt.clone() * value.clone()),
                (
                    gate.clone() * tag_cpu.clone(),
                    q_rt.clone() * tag_rt.clone(),
                ),
                (
                    gate.clone() * rwc_cpu.clone(),
                    q_rt.clone() * call_id_rt.clone(),
                ),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * address_rt.clone(),
                ),
                (gate.clone() * ft_cpu.clone(), q_rt.clone() * ft_rt.clone()),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * storage_key_rt.clone(),
                ),
                (
                    gate.clone() * (rwc_cpu.clone() + rwc_adder.clone()),
                    q_rt.clone() * rwc_rt.clone(),
                ),
                (
                    gate.clone() * one.clone(),
                    q_rt.clone() * iswrite_rt.clone(),
                ),
                (gate.clone() * one.clone(), q_rt.clone() * notisend),
            ]
        });

        meta.lookup_any("cpu to rt, w, calldataoffset, isbegintx", |cells| {
            let gate =
                cells.query_advice(isbegintx_cpu, Rotation::cur()) * cells.query_selector(q_cpu);
            let q_rt = cells.query_selector(q_rt);
            let value = cells.query_advice(value_rt, Rotation::cur());
            let tag_rt = cells.query_advice(tag_rt, Rotation::cur());
            let call_id_rt = cells.query_advice(call_id_rt, Rotation::cur());
            let address_rt = cells.query_advice(address_rt, Rotation::cur());
            let ft_rt = cells.query_advice(field_tag_rt, Rotation::cur());
            let storage_key_rt = cells.query_advice(storage_key_rt, Rotation::cur());
            let rwc_rt = cells.query_advice(rw_counter_rt, Rotation::cur());
            let iswrite_rt = cells.query_advice(iswrite_rt, Rotation::cur());
            let zero = Expression::Constant(F::ZERO);
            let one = Expression::Constant(F::ONE);
            let two = Expression::Constant(F::from(2u64));
            let tag_cpu = Expression::Constant(F::from(5u64));
            let rwc_cpu = cells.query_advice(rw_counter_cpu, Rotation::cur());
            let ft_cpu = Expression::Constant(F::from(7u64));
            let notisend = one.clone() - cells.query_advice(isend_rt, Rotation::cur());
            vec![
                (gate.clone() * zero.clone(), q_rt.clone() * value.clone()),
                (
                    gate.clone() * tag_cpu.clone(),
                    q_rt.clone() * tag_rt.clone(),
                ),
                (
                    gate.clone() * one.clone(),
                    q_rt.clone() * call_id_rt.clone(),
                ),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * address_rt.clone(),
                ),
                (gate.clone() * ft_cpu.clone(), q_rt.clone() * ft_rt.clone()),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * storage_key_rt.clone(),
                ),
                (
                    gate.clone() * (rwc_cpu.clone() + two.clone()),
                    q_rt.clone() * rwc_rt.clone(),
                ),
                (
                    gate.clone() * one.clone(),
                    q_rt.clone() * iswrite_rt.clone(),
                ),
                (gate.clone() * one.clone(), q_rt.clone() * notisend),
            ]
        });
        ///////////////////////////////////////////

        meta.lookup_any("cpu to rt, r, returndataoffset, iscall", |cells| {
            let gate =
                cells.query_advice(iscall_cpu, Rotation::cur()) * cells.query_selector(q_cpu);
            let q_rt = cells.query_selector(q_rt);
            let rlc = cells.query_advice(rlc_c_cpu, Rotation::cur());
            let value = cells.query_advice(value_rt, Rotation::cur());
            let sp = cells.query_advice(sp_cpu, Rotation::cur());
            let tag_rt = cells.query_advice(tag_rt, Rotation::cur());
            let call_id_rt = cells.query_advice(call_id_rt, Rotation::cur());
            let address_rt = cells.query_advice(address_rt, Rotation::cur());
            let ft_rt = cells.query_advice(field_tag_rt, Rotation::cur());
            let storage_key_rt = cells.query_advice(storage_key_rt, Rotation::cur());
            let rwc_rt = cells.query_advice(rw_counter_rt, Rotation::cur());
            let iswrite_rt = cells.query_advice(iswrite_rt, Rotation::cur());
            let zero = Expression::Constant(F::ZERO);
            let one = Expression::Constant(F::ONE);
            let two = Expression::Constant(F::from(2u64));
            let rwc_adder = Expression::Constant(F::from(5u64));
            let rwc_cpu = cells.query_advice(rw_counter_cpu, Rotation::cur());
            let tag_cpu = Expression::Constant(F::from(2u64));
            let call_id_cpu = cells.query_advice(call_id_cpu, Rotation::cur());
            let notisend = one.clone() - cells.query_advice(isend_rt, Rotation::cur());

            vec![
                (
                    gate.clone() * tag_cpu.clone(),
                    q_rt.clone() * tag_rt.clone(),
                ),
                (
                    gate.clone() * call_id_cpu,
                    q_rt.clone() * call_id_rt.clone(),
                ),
                (
                    gate.clone() * (sp.clone() - two.clone()),
                    q_rt.clone() * address_rt.clone(),
                ),
                (gate.clone() * zero.clone(), q_rt.clone() * ft_rt.clone()),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * storage_key_rt.clone(),
                ),
                (
                    gate.clone() * (rwc_cpu.clone() + rwc_adder.clone()),
                    q_rt.clone() * rwc_rt.clone(),
                ),
                (gate.clone() * rlc.clone(), q_rt.clone() * value.clone()),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * iswrite_rt.clone(),
                ),
                (gate.clone() * one.clone(), q_rt.clone() * notisend),
            ]
        });

        meta.lookup_any("cpu to rt, w, returndataoffset, iscall", |cells| {
            let gate =
                cells.query_advice(iscall_cpu, Rotation::cur()) * cells.query_selector(q_cpu);
            let q_rt = cells.query_selector(q_rt);
            let rlc = cells.query_advice(rlc_c_cpu, Rotation::cur());
            let value = cells.query_advice(value_rt, Rotation::cur());
            let tag_rt = cells.query_advice(tag_rt, Rotation::cur());
            let call_id_rt = cells.query_advice(call_id_rt, Rotation::cur());
            let address_rt = cells.query_advice(address_rt, Rotation::cur());
            let ft_rt = cells.query_advice(field_tag_rt, Rotation::cur());
            let storage_key_rt = cells.query_advice(storage_key_rt, Rotation::cur());
            let rwc_rt = cells.query_advice(rw_counter_rt, Rotation::cur());
            let iswrite_rt = cells.query_advice(iswrite_rt, Rotation::cur());
            let zero = Expression::Constant(F::ZERO);
            let one = Expression::Constant(F::ONE);
            let rwc_adder = Expression::Constant(F::from(6u64));
            let tag_cpu = Expression::Constant(F::from(5u64));
            let rwc_cpu = cells.query_advice(rw_counter_cpu, Rotation::cur());
            let ft_cpu = Expression::Constant(F::from(9u64));
            let notisend = one.clone() - cells.query_advice(isend_rt, Rotation::cur());
            vec![
                (gate.clone() * rlc.clone(), q_rt.clone() * value.clone()),
                (
                    gate.clone() * tag_cpu.clone(),
                    q_rt.clone() * tag_rt.clone(),
                ),
                (
                    gate.clone() * rwc_cpu.clone(),
                    q_rt.clone() * call_id_rt.clone(),
                ),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * address_rt.clone(),
                ),
                (gate.clone() * ft_cpu.clone(), q_rt.clone() * ft_rt.clone()),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * storage_key_rt.clone(),
                ),
                (
                    gate.clone() * (rwc_cpu.clone() + rwc_adder.clone()),
                    q_rt.clone() * rwc_rt.clone(),
                ),
                (
                    gate.clone() * one.clone(),
                    q_rt.clone() * iswrite_rt.clone(),
                ),
                (gate.clone() * one.clone(), q_rt.clone() * notisend),
            ]
        });

        meta.lookup_any("cpu to rt, w, returndataoffset, isbegintx", |cells| {
            let gate =
                cells.query_advice(isbegintx_cpu, Rotation::cur()) * cells.query_selector(q_cpu);
            let q_rt = cells.query_selector(q_rt);
            let value = cells.query_advice(value_rt, Rotation::cur());
            let tag_rt = cells.query_advice(tag_rt, Rotation::cur());
            let call_id_rt = cells.query_advice(call_id_rt, Rotation::cur());
            let address_rt = cells.query_advice(address_rt, Rotation::cur());
            let ft_rt = cells.query_advice(field_tag_rt, Rotation::cur());
            let storage_key_rt = cells.query_advice(storage_key_rt, Rotation::cur());
            let rwc_rt = cells.query_advice(rw_counter_rt, Rotation::cur());
            let iswrite_rt = cells.query_advice(iswrite_rt, Rotation::cur());
            let zero = Expression::Constant(F::ZERO);
            let one = Expression::Constant(F::ONE);
            let three = Expression::Constant(F::from(3u64));
            let tag_cpu = Expression::Constant(F::from(5u64));
            let rwc_cpu = cells.query_advice(rw_counter_cpu, Rotation::cur());
            let ft_cpu = Expression::Constant(F::from(9u64));
            let notisend = one.clone() - cells.query_advice(isend_rt, Rotation::cur());
            vec![
                (gate.clone() * zero.clone(), q_rt.clone() * value.clone()),
                (
                    gate.clone() * tag_cpu.clone(),
                    q_rt.clone() * tag_rt.clone(),
                ),
                (
                    gate.clone() * one.clone(),
                    q_rt.clone() * call_id_rt.clone(),
                ),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * address_rt.clone(),
                ),
                (gate.clone() * ft_cpu.clone(), q_rt.clone() * ft_rt.clone()),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * storage_key_rt.clone(),
                ),
                (
                    gate.clone() * (rwc_cpu.clone() + three.clone()),
                    q_rt.clone() * rwc_rt.clone(),
                ),
                (
                    gate.clone() * one.clone(),
                    q_rt.clone() * iswrite_rt.clone(),
                ),
                (gate.clone() * one.clone(), q_rt.clone() * notisend),
            ]
        });
        ////////////////////////////////////////////

        meta.lookup_any("cpu to rt, r, returndatalength, iscall", |cells| {
            let gate =
                cells.query_advice(iscall_cpu, Rotation::cur()) * cells.query_selector(q_cpu);
            let q_rt = cells.query_selector(q_rt);
            let rlc = cells.query_advice(rlc_d_cpu, Rotation::cur());
            let value = cells.query_advice(value_rt, Rotation::cur());
            let sp = cells.query_advice(sp_cpu, Rotation::cur());
            let tag_rt = cells.query_advice(tag_rt, Rotation::cur());
            let call_id_rt = cells.query_advice(call_id_rt, Rotation::cur());
            let address_rt = cells.query_advice(address_rt, Rotation::cur());
            let ft_rt = cells.query_advice(field_tag_rt, Rotation::cur());
            let storage_key_rt = cells.query_advice(storage_key_rt, Rotation::cur());
            let rwc_rt = cells.query_advice(rw_counter_rt, Rotation::cur());
            let iswrite_rt = cells.query_advice(iswrite_rt, Rotation::cur());
            let zero = Expression::Constant(F::ZERO);
            let one = Expression::Constant(F::ONE);
            let two = Expression::Constant(F::from(2u64));
            let three = Expression::Constant(F::from(3u64));
            let rwc_adder = Expression::Constant(F::from(7u64));
            let rwc_cpu = cells.query_advice(rw_counter_cpu, Rotation::cur());
            let tag_cpu = Expression::Constant(F::from(2u64));
            let call_id_cpu = cells.query_advice(call_id_cpu, Rotation::cur());
            let notisend = one.clone() - cells.query_advice(isend_rt, Rotation::cur());

            vec![
                (
                    gate.clone() * tag_cpu.clone(),
                    q_rt.clone() * tag_rt.clone(),
                ),
                (
                    gate.clone() * call_id_cpu,
                    q_rt.clone() * call_id_rt.clone(),
                ),
                (
                    gate.clone() * (sp.clone() - three.clone()),
                    q_rt.clone() * address_rt.clone(),
                ),
                (gate.clone() * zero.clone(), q_rt.clone() * ft_rt.clone()),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * storage_key_rt.clone(),
                ),
                (
                    gate.clone() * (rwc_cpu.clone() + rwc_adder.clone()),
                    q_rt.clone() * rwc_rt.clone(),
                ),
                (gate.clone() * rlc.clone(), q_rt.clone() * value.clone()),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * iswrite_rt.clone(),
                ),
                (gate.clone() * one.clone(), q_rt.clone() * notisend),
            ]
        });

        meta.lookup_any("cpu to rt, w, returndatalength, iscall", |cells| {
            let gate =
                cells.query_advice(iscall_cpu, Rotation::cur()) * cells.query_selector(q_cpu);
            let q_rt = cells.query_selector(q_rt);
            let rlc = cells.query_advice(rlc_d_cpu, Rotation::cur());
            let value = cells.query_advice(value_rt, Rotation::cur());
            let tag_rt = cells.query_advice(tag_rt, Rotation::cur());
            let call_id_rt = cells.query_advice(call_id_rt, Rotation::cur());
            let address_rt = cells.query_advice(address_rt, Rotation::cur());
            let ft_rt = cells.query_advice(field_tag_rt, Rotation::cur());
            let storage_key_rt = cells.query_advice(storage_key_rt, Rotation::cur());
            let rwc_rt = cells.query_advice(rw_counter_rt, Rotation::cur());
            let iswrite_rt = cells.query_advice(iswrite_rt, Rotation::cur());
            let zero = Expression::Constant(F::ZERO);
            let one = Expression::Constant(F::ONE);
            let rwc_adder = Expression::Constant(F::from(8u64));
            let tag_cpu = Expression::Constant(F::from(5u64));
            let rwc_cpu = cells.query_advice(rw_counter_cpu, Rotation::cur());
            let ft_cpu = Expression::Constant(F::from(10u64));
            let notisend = one.clone() - cells.query_advice(isend_rt, Rotation::cur());
            vec![
                (gate.clone() * rlc.clone(), q_rt.clone() * value.clone()),
                (
                    gate.clone() * tag_cpu.clone(),
                    q_rt.clone() * tag_rt.clone(),
                ),
                (
                    gate.clone() * rwc_cpu.clone(),
                    q_rt.clone() * call_id_rt.clone(),
                ),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * address_rt.clone(),
                ),
                (gate.clone() * ft_cpu.clone(), q_rt.clone() * ft_rt.clone()),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * storage_key_rt.clone(),
                ),
                (
                    gate.clone() * (rwc_cpu.clone() + rwc_adder.clone()),
                    q_rt.clone() * rwc_rt.clone(),
                ),
                (
                    gate.clone() * one.clone(),
                    q_rt.clone() * iswrite_rt.clone(),
                ),
                (gate.clone() * one.clone(), q_rt.clone() * notisend),
            ]
        });

        meta.lookup_any("cpu to rt, w, returndatalength, isbegintx", |cells| {
            let gate =
                cells.query_advice(isbegintx_cpu, Rotation::cur()) * cells.query_selector(q_cpu);
            let q_rt = cells.query_selector(q_rt);
            let value = cells.query_advice(value_rt, Rotation::cur());
            let tag_rt = cells.query_advice(tag_rt, Rotation::cur());
            let call_id_rt = cells.query_advice(call_id_rt, Rotation::cur());
            let address_rt = cells.query_advice(address_rt, Rotation::cur());
            let ft_rt = cells.query_advice(field_tag_rt, Rotation::cur());
            let storage_key_rt = cells.query_advice(storage_key_rt, Rotation::cur());
            let rwc_rt = cells.query_advice(rw_counter_rt, Rotation::cur());
            let iswrite_rt = cells.query_advice(iswrite_rt, Rotation::cur());
            let zero = Expression::Constant(F::ZERO);
            let one = Expression::Constant(F::ONE);
            let four = Expression::Constant(F::from(4u64));
            let tag_cpu = Expression::Constant(F::from(5u64));
            let rwc_cpu = cells.query_advice(rw_counter_cpu, Rotation::cur());
            let ft_cpu = Expression::Constant(F::from(10u64));
            let notisend = one.clone() - cells.query_advice(isend_rt, Rotation::cur());
            vec![
                (gate.clone() * zero.clone(), q_rt.clone() * value.clone()),
                (
                    gate.clone() * tag_cpu.clone(),
                    q_rt.clone() * tag_rt.clone(),
                ),
                (
                    gate.clone() * one.clone(),
                    q_rt.clone() * call_id_rt.clone(),
                ),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * address_rt.clone(),
                ),
                (gate.clone() * ft_cpu.clone(), q_rt.clone() * ft_rt.clone()),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * storage_key_rt.clone(),
                ),
                (
                    gate.clone() * (rwc_cpu.clone() + four.clone()),
                    q_rt.clone() * rwc_rt.clone(),
                ),
                (
                    gate.clone() * one.clone(),
                    q_rt.clone() * iswrite_rt.clone(),
                ),
                (gate.clone() * one.clone(), q_rt.clone() * notisend),
            ]
        });
        ///////////////////////////////////////////

        meta.lookup_any("cpu to rt, r, calleraddress, iscall", |cells| {
            let gate =
                cells.query_advice(iscall_cpu, Rotation::cur()) * cells.query_selector(q_cpu);
            let q_rt = cells.query_selector(q_rt);
            let rlc = cells.query_advice(rlc_e_cpu, Rotation::cur());
            let value = cells.query_advice(value_rt, Rotation::cur());
            let tag_rt = cells.query_advice(tag_rt, Rotation::cur());
            let call_id_rt = cells.query_advice(call_id_rt, Rotation::cur());
            let address_rt = cells.query_advice(address_rt, Rotation::cur());
            let ft_rt = cells.query_advice(field_tag_rt, Rotation::cur());
            let storage_key_rt = cells.query_advice(storage_key_rt, Rotation::cur());
            let rwc_rt = cells.query_advice(rw_counter_rt, Rotation::cur());
            let iswrite_rt = cells.query_advice(iswrite_rt, Rotation::cur());
            let zero = Expression::Constant(F::ZERO);
            let one = Expression::Constant(F::ONE);
            let rwc_adder = Expression::Constant(F::from(9u64));
            let rwc_cpu = cells.query_advice(rw_counter_cpu, Rotation::cur());
            let tag_cpu = Expression::Constant(F::from(5u64));
            let ft_cpu = Expression::Constant(F::from(5u64));
            let call_id_cpu = cells.query_advice(call_id_cpu, Rotation::cur());
            let notisend = one.clone() - cells.query_advice(isend_rt, Rotation::cur());

            vec![
                (gate.clone() * rlc.clone(), q_rt.clone() * value.clone()),
                (
                    gate.clone() * tag_cpu.clone(),
                    q_rt.clone() * tag_rt.clone(),
                ),
                (
                    gate.clone() * call_id_cpu,
                    q_rt.clone() * call_id_rt.clone(),
                ),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * address_rt.clone(),
                ),
                (gate.clone() * ft_cpu.clone(), q_rt.clone() * ft_rt.clone()),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * storage_key_rt.clone(),
                ),
                (
                    gate.clone() * (rwc_cpu.clone() + rwc_adder.clone()),
                    q_rt.clone() * rwc_rt.clone(),
                ),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * iswrite_rt.clone(),
                ),
                (gate.clone() * one.clone(), q_rt.clone() * notisend),
            ]
        });

        meta.lookup_any("cpu to rt, w, calleraddress, iscall", |cells| {
            let gate =
                cells.query_advice(iscall_cpu, Rotation::cur()) * cells.query_selector(q_cpu);
            let q_rt = cells.query_selector(q_rt);
            let rlc = cells.query_advice(rlc_e_cpu, Rotation::cur());
            let value = cells.query_advice(value_rt, Rotation::cur());
            let tag_rt = cells.query_advice(tag_rt, Rotation::cur());
            let call_id_rt = cells.query_advice(call_id_rt, Rotation::cur());
            let address_rt = cells.query_advice(address_rt, Rotation::cur());
            let ft_rt = cells.query_advice(field_tag_rt, Rotation::cur());
            let storage_key_rt = cells.query_advice(storage_key_rt, Rotation::cur());
            let rwc_rt = cells.query_advice(rw_counter_rt, Rotation::cur());
            let iswrite_rt = cells.query_advice(iswrite_rt, Rotation::cur());
            let zero = Expression::Constant(F::ZERO);
            let one = Expression::Constant(F::ONE);
            let rwc_adder = Expression::Constant(F::from(10u64));
            let tag_cpu = Expression::Constant(F::from(5u64));
            let rwc_cpu = cells.query_advice(rw_counter_cpu, Rotation::cur());
            let ft_cpu = Expression::Constant(F::from(5u64));
            let notisend = one.clone() - cells.query_advice(isend_rt, Rotation::cur());
            vec![
                (gate.clone() * rlc.clone(), q_rt.clone() * value.clone()),
                (
                    gate.clone() * tag_cpu.clone(),
                    q_rt.clone() * tag_rt.clone(),
                ),
                (
                    gate.clone() * rwc_cpu.clone(),
                    q_rt.clone() * call_id_rt.clone(),
                ),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * address_rt.clone(),
                ),
                (gate.clone() * ft_cpu.clone(), q_rt.clone() * ft_rt.clone()),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * storage_key_rt.clone(),
                ),
                (
                    gate.clone() * (rwc_cpu.clone() + rwc_adder.clone()),
                    q_rt.clone() * rwc_rt.clone(),
                ),
                (
                    gate.clone() * one.clone(),
                    q_rt.clone() * iswrite_rt.clone(),
                ),
                (gate.clone() * one.clone(), q_rt.clone() * notisend),
            ]
        });

        meta.lookup_any("cpu to txtable, r, calleraddress, isbegintx", |cells| {
            let gate =
                cells.query_advice(isbegintx_cpu, Rotation::cur()) * cells.query_selector(q_cpu);
            let active_tx = cells.query_instance(active_tx, Rotation::cur());
            let rlc = cells.query_advice(rlc_e_cpu, Rotation::cur());
            let value_low = cells.query_instance(value_low_tx, Rotation::cur());
            let value_high = cells.query_instance(value_high_tx, Rotation::cur());
            let tag_tx = cells.query_instance(tag_tx, Rotation::cur());
            let index_tx = cells.query_instance(index_tx, Rotation::cur());
            let zero = Expression::Constant(F::ZERO);
            let tag_cpu = Expression::Constant(F::from(4u64));
            let two_pow_128 = Expression::Constant(F::from(2u64).pow_vartime([128]));
            vec![
                (
                    gate.clone() * rlc.clone(),
                    active_tx.clone()
                        * (value_low.clone() + value_high.clone() * two_pow_128.clone()),
                ),
                (
                    gate.clone() * tag_cpu.clone(),
                    active_tx.clone() * tag_tx.clone(),
                ),
                (
                    gate.clone() * zero.clone(),
                    active_tx.clone() * index_tx.clone(),
                ),
            ]
        });

        meta.lookup_any("cpu to rt, w, calleraddress, isbegintx", |cells| {
            let gate =
                cells.query_advice(isbegintx_cpu, Rotation::cur()) * cells.query_selector(q_cpu);
            let q_rt = cells.query_selector(q_rt);
            let rlc = cells.query_advice(rlc_e_cpu, Rotation::cur());
            let value = cells.query_advice(value_rt, Rotation::cur());
            let tag_rt = cells.query_advice(tag_rt, Rotation::cur());
            let call_id_rt = cells.query_advice(call_id_rt, Rotation::cur());
            let address_rt = cells.query_advice(address_rt, Rotation::cur());
            let ft_rt = cells.query_advice(field_tag_rt, Rotation::cur());
            let storage_key_rt = cells.query_advice(storage_key_rt, Rotation::cur());
            let rwc_rt = cells.query_advice(rw_counter_rt, Rotation::cur());
            let iswrite_rt = cells.query_advice(iswrite_rt, Rotation::cur());
            let zero = Expression::Constant(F::ZERO);
            let one = Expression::Constant(F::ONE);
            let rwc_adder = Expression::Constant(F::from(5u64));
            let tag_cpu = Expression::Constant(F::from(5u64));
            let rwc_cpu = cells.query_advice(rw_counter_cpu, Rotation::cur());
            let ft_cpu = Expression::Constant(F::from(5u64));
            let notisend = one.clone() - cells.query_advice(isend_rt, Rotation::cur());
            vec![
                (gate.clone() * rlc.clone(), q_rt.clone() * value.clone()),
                (
                    gate.clone() * tag_cpu.clone(),
                    q_rt.clone() * tag_rt.clone(),
                ),
                (
                    gate.clone() * one.clone(),
                    q_rt.clone() * call_id_rt.clone(),
                ),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * address_rt.clone(),
                ),
                (gate.clone() * ft_cpu.clone(), q_rt.clone() * ft_rt.clone()),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * storage_key_rt.clone(),
                ),
                (
                    gate.clone() * (rwc_cpu.clone() + rwc_adder.clone()),
                    q_rt.clone() * rwc_rt.clone(),
                ),
                (
                    gate.clone() * one.clone(),
                    q_rt.clone() * iswrite_rt.clone(),
                ),
                (gate.clone() * one.clone(), q_rt.clone() * notisend),
            ]
        });
        ///////////////////////////////////
        meta.lookup_any("cpu to rt, r, calleeaddress, iscall", |cells| {
            let gate =
                cells.query_advice(iscall_cpu, Rotation::cur()) * cells.query_selector(q_cpu);
            let q_rt = cells.query_selector(q_rt);
            let rlc = cells.query_advice(rlc_f_cpu, Rotation::cur());
            let value = cells.query_advice(value_rt, Rotation::cur());
            let sp = cells.query_advice(sp_cpu, Rotation::cur());
            let tag_rt = cells.query_advice(tag_rt, Rotation::cur());
            let call_id_rt = cells.query_advice(call_id_rt, Rotation::cur());
            let address_rt = cells.query_advice(address_rt, Rotation::cur());
            let ft_rt = cells.query_advice(field_tag_rt, Rotation::cur());
            let storage_key_rt = cells.query_advice(storage_key_rt, Rotation::cur());
            let rwc_rt = cells.query_advice(rw_counter_rt, Rotation::cur());
            let iswrite_rt = cells.query_advice(iswrite_rt, Rotation::cur());
            let zero = Expression::Constant(F::ZERO);
            let one = Expression::Constant(F::ONE);
            let _two = Expression::Constant(F::from(2u64));
            let four = Expression::Constant(F::from(4u64));
            let rwc_adder = Expression::Constant(F::from(11u64));
            let rwc_cpu = cells.query_advice(rw_counter_cpu, Rotation::cur());
            let tag_cpu = Expression::Constant(F::from(2u64));
            let call_id_cpu = cells.query_advice(call_id_cpu, Rotation::cur());
            let notisend = one.clone() - cells.query_advice(isend_rt, Rotation::cur());

            vec![
                (
                    gate.clone() * tag_cpu.clone(),
                    q_rt.clone() * tag_rt.clone(),
                ),
                (
                    gate.clone() * call_id_cpu,
                    q_rt.clone() * call_id_rt.clone(),
                ),
                (
                    gate.clone() * (sp.clone() - four.clone()),
                    q_rt.clone() * address_rt.clone(),
                ),
                (gate.clone() * zero.clone(), q_rt.clone() * ft_rt.clone()),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * storage_key_rt.clone(),
                ),
                (
                    gate.clone() * (rwc_cpu.clone() + rwc_adder.clone()),
                    q_rt.clone() * rwc_rt.clone(),
                ),
                (gate.clone() * rlc.clone(), q_rt.clone() * value.clone()),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * iswrite_rt.clone(),
                ),
                (gate.clone() * one.clone(), q_rt.clone() * notisend),
            ]
        });

        meta.lookup_any("cpu to rt, w, calleeaddress, iscall", |cells| {
            let gate =
                cells.query_advice(iscall_cpu, Rotation::cur()) * cells.query_selector(q_cpu);
            let q_rt = cells.query_selector(q_rt);
            let rlc = cells.query_advice(rlc_f_cpu, Rotation::cur());
            let value = cells.query_advice(value_rt, Rotation::cur());
            let tag_rt = cells.query_advice(tag_rt, Rotation::cur());
            let call_id_rt = cells.query_advice(call_id_rt, Rotation::cur());
            let address_rt = cells.query_advice(address_rt, Rotation::cur());
            let ft_rt = cells.query_advice(field_tag_rt, Rotation::cur());
            let storage_key_rt = cells.query_advice(storage_key_rt, Rotation::cur());
            let rwc_rt = cells.query_advice(rw_counter_rt, Rotation::cur());
            let iswrite_rt = cells.query_advice(iswrite_rt, Rotation::cur());
            let zero = Expression::Constant(F::ZERO);
            let one = Expression::Constant(F::ONE);
            let rwc_adder = Expression::Constant(F::from(12u64));
            let tag_cpu = Expression::Constant(F::from(5u64));
            let rwc_cpu = cells.query_advice(rw_counter_cpu, Rotation::cur());
            let ft_cpu = Expression::Constant(F::from(6u64));
            let notisend = one.clone() - cells.query_advice(isend_rt, Rotation::cur());
            vec![
                (gate.clone() * rlc.clone(), q_rt.clone() * value.clone()),
                (
                    gate.clone() * tag_cpu.clone(),
                    q_rt.clone() * tag_rt.clone(),
                ),
                (
                    gate.clone() * rwc_cpu.clone(),
                    q_rt.clone() * call_id_rt.clone(),
                ),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * address_rt.clone(),
                ),
                (gate.clone() * ft_cpu.clone(), q_rt.clone() * ft_rt.clone()),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * storage_key_rt.clone(),
                ),
                (
                    gate.clone() * (rwc_cpu.clone() + rwc_adder.clone()),
                    q_rt.clone() * rwc_rt.clone(),
                ),
                (
                    gate.clone() * one.clone(),
                    q_rt.clone() * iswrite_rt.clone(),
                ),
                (gate.clone() * one.clone(), q_rt.clone() * notisend),
            ]
        });

        meta.lookup_any("cpu to txtable, r, calleeaddress, isbegintx", |cells| {
            let gate =
                cells.query_advice(isbegintx_cpu, Rotation::cur()) * cells.query_selector(q_cpu);
            let active_tx = cells.query_instance(active_tx, Rotation::cur());
            let rlc = cells.query_advice(rlc_f_cpu, Rotation::cur());
            let value_low = cells.query_instance(value_low_tx, Rotation::cur());
            let value_high = cells.query_instance(value_high_tx, Rotation::cur());
            let tag_tx = cells.query_instance(tag_tx, Rotation::cur());
            let index_tx = cells.query_instance(index_tx, Rotation::cur());
            let zero = Expression::Constant(F::ZERO);
            let tag_cpu = Expression::Constant(F::from(5u64));
            let two_pow_128 = Expression::Constant(F::from(2u64).pow_vartime([128]));
            vec![
                (
                    gate.clone() * rlc.clone(),
                    active_tx.clone()
                        * (value_low.clone() + value_high.clone() * two_pow_128.clone()),
                ),
                (
                    gate.clone() * tag_cpu.clone(),
                    active_tx.clone() * tag_tx.clone(),
                ),
                (
                    gate.clone() * zero.clone(),
                    active_tx.clone() * index_tx.clone(),
                ),
            ]
        });

        meta.lookup_any("cpu to rt, w, calleeaddress, isbegintx", |cells| {
            let gate =
                cells.query_advice(isbegintx_cpu, Rotation::cur()) * cells.query_selector(q_cpu);
            let q_rt = cells.query_selector(q_rt);
            let rlc = cells.query_advice(rlc_f_cpu, Rotation::cur());
            let value = cells.query_advice(value_rt, Rotation::cur());
            let tag_rt = cells.query_advice(tag_rt, Rotation::cur());
            let call_id_rt = cells.query_advice(call_id_rt, Rotation::cur());
            let address_rt = cells.query_advice(address_rt, Rotation::cur());
            let ft_rt = cells.query_advice(field_tag_rt, Rotation::cur());
            let storage_key_rt = cells.query_advice(storage_key_rt, Rotation::cur());
            let rwc_rt = cells.query_advice(rw_counter_rt, Rotation::cur());
            let iswrite_rt = cells.query_advice(iswrite_rt, Rotation::cur());
            let zero = Expression::Constant(F::ZERO);
            let one = Expression::Constant(F::ONE);
            let rwc_adder = Expression::Constant(F::from(6u64));
            let tag_cpu = Expression::Constant(F::from(5u64));
            let rwc_cpu = cells.query_advice(rw_counter_cpu, Rotation::cur());
            let ft_cpu = Expression::Constant(F::from(6u64));
            let notisend = one.clone() - cells.query_advice(isend_rt, Rotation::cur());
            vec![
                (gate.clone() * rlc.clone(), q_rt.clone() * value.clone()),
                (
                    gate.clone() * tag_cpu.clone(),
                    q_rt.clone() * tag_rt.clone(),
                ),
                (
                    gate.clone() * one.clone(),
                    q_rt.clone() * call_id_rt.clone(),
                ),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * address_rt.clone(),
                ),
                (gate.clone() * ft_cpu.clone(), q_rt.clone() * ft_rt.clone()),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * storage_key_rt.clone(),
                ),
                (
                    gate.clone() * (rwc_cpu.clone() + rwc_adder.clone()),
                    q_rt.clone() * rwc_rt.clone(),
                ),
                (
                    gate.clone() * one.clone(),
                    q_rt.clone() * iswrite_rt.clone(),
                ),
                (gate.clone() * one.clone(), q_rt.clone() * notisend),
            ]
        });

        //////////////////////////////////

        meta.lookup_any("cpu to rt, r, calldatalength, iscall", |cells| {
            let gate =
                cells.query_advice(iscall_cpu, Rotation::cur()) * cells.query_selector(q_cpu);
            let q_rt = cells.query_selector(q_rt);
            let rlc = cells.query_advice(rlc_g_cpu, Rotation::cur());
            let value = cells.query_advice(value_rt, Rotation::cur());
            let sp = cells.query_advice(sp_cpu, Rotation::cur());
            let tag_rt = cells.query_advice(tag_rt, Rotation::cur());
            let call_id_rt = cells.query_advice(call_id_rt, Rotation::cur());
            let address_rt = cells.query_advice(address_rt, Rotation::cur());
            let ft_rt = cells.query_advice(field_tag_rt, Rotation::cur());
            let storage_key_rt = cells.query_advice(storage_key_rt, Rotation::cur());
            let rwc_rt = cells.query_advice(rw_counter_rt, Rotation::cur());
            let iswrite_rt = cells.query_advice(iswrite_rt, Rotation::cur());
            let zero = Expression::Constant(F::ZERO);
            let one = Expression::Constant(F::ONE);
            let _two = Expression::Constant(F::from(2u64));
            let five = Expression::Constant(F::from(5u64));
            let rwc_adder = Expression::Constant(F::from(13u64));
            let rwc_cpu = cells.query_advice(rw_counter_cpu, Rotation::cur());
            let tag_cpu = Expression::Constant(F::from(2u64));
            let call_id_cpu = cells.query_advice(call_id_cpu, Rotation::cur());
            let notisend = one.clone() - cells.query_advice(isend_rt, Rotation::cur());

            vec![
                (
                    gate.clone() * tag_cpu.clone(),
                    q_rt.clone() * tag_rt.clone(),
                ),
                (
                    gate.clone() * call_id_cpu,
                    q_rt.clone() * call_id_rt.clone(),
                ),
                (
                    gate.clone() * (sp.clone() - five.clone()),
                    q_rt.clone() * address_rt.clone(),
                ),
                (gate.clone() * zero.clone(), q_rt.clone() * ft_rt.clone()),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * storage_key_rt.clone(),
                ),
                (
                    gate.clone() * (rwc_cpu.clone() + rwc_adder.clone()),
                    q_rt.clone() * rwc_rt.clone(),
                ),
                (gate.clone() * rlc.clone(), q_rt.clone() * value.clone()),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * iswrite_rt.clone(),
                ),
                (gate.clone() * one.clone(), q_rt.clone() * notisend),
            ]
        });

        meta.lookup_any("cpu to rt, w, calldatalength, iscall", |cells| {
            let gate =
                cells.query_advice(iscall_cpu, Rotation::cur()) * cells.query_selector(q_cpu);
            let q_rt = cells.query_selector(q_rt);
            let rlc = cells.query_advice(rlc_g_cpu, Rotation::cur());
            let value = cells.query_advice(value_rt, Rotation::cur());
            let tag_rt = cells.query_advice(tag_rt, Rotation::cur());
            let call_id_rt = cells.query_advice(call_id_rt, Rotation::cur());
            let address_rt = cells.query_advice(address_rt, Rotation::cur());
            let ft_rt = cells.query_advice(field_tag_rt, Rotation::cur());
            let storage_key_rt = cells.query_advice(storage_key_rt, Rotation::cur());
            let rwc_rt = cells.query_advice(rw_counter_rt, Rotation::cur());
            let iswrite_rt = cells.query_advice(iswrite_rt, Rotation::cur());
            let zero = Expression::Constant(F::ZERO);
            let one = Expression::Constant(F::ONE);
            let rwc_adder = Expression::Constant(F::from(14u64));
            let tag_cpu = Expression::Constant(F::from(5u64));
            let rwc_cpu = cells.query_advice(rw_counter_cpu, Rotation::cur());
            let ft_cpu = Expression::Constant(F::from(8u64));
            let notisend = one.clone() - cells.query_advice(isend_rt, Rotation::cur());
            vec![
                (gate.clone() * rlc.clone(), q_rt.clone() * value.clone()),
                (
                    gate.clone() * tag_cpu.clone(),
                    q_rt.clone() * tag_rt.clone(),
                ),
                (
                    gate.clone() * rwc_cpu.clone(),
                    q_rt.clone() * call_id_rt.clone(),
                ),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * address_rt.clone(),
                ),
                (gate.clone() * ft_cpu.clone(), q_rt.clone() * ft_rt.clone()),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * storage_key_rt.clone(),
                ),
                (
                    gate.clone() * (rwc_cpu.clone() + rwc_adder.clone()),
                    q_rt.clone() * rwc_rt.clone(),
                ),
                (
                    gate.clone() * one.clone(),
                    q_rt.clone() * iswrite_rt.clone(),
                ),
                (gate.clone() * one.clone(), q_rt.clone() * notisend),
            ]
        });

        meta.lookup_any("cpu to txtable, r, calldatalength, isbegintx", |cells| {
            let gate =
                cells.query_advice(isbegintx_cpu, Rotation::cur()) * cells.query_selector(q_cpu);
            let active_tx = cells.query_instance(active_tx, Rotation::cur());
            let rlc = cells.query_advice(rlc_g_cpu, Rotation::cur());
            let value_low = cells.query_instance(value_low_tx, Rotation::cur());
            let value_high = cells.query_instance(value_high_tx, Rotation::cur());
            let tag_tx = cells.query_instance(tag_tx, Rotation::cur());
            let index_tx = cells.query_instance(index_tx, Rotation::cur());
            let zero = Expression::Constant(F::ZERO);
            let tag_cpu = Expression::Constant(F::from(8u64));
            let two_pow_128 = Expression::Constant(F::from(2u64).pow_vartime([128]));
            vec![
                (
                    gate.clone() * rlc.clone(),
                    active_tx.clone()
                        * (value_low.clone() + value_high.clone() * two_pow_128.clone()),
                ),
                (
                    gate.clone() * tag_cpu.clone(),
                    active_tx.clone() * tag_tx.clone(),
                ),
                (
                    gate.clone() * zero.clone(),
                    active_tx.clone() * index_tx.clone(),
                ),
            ]
        });

        meta.lookup_any("cpu to rt, w, calldatalength, isbegintx", |cells| {
            let gate =
                cells.query_advice(isbegintx_cpu, Rotation::cur()) * cells.query_selector(q_cpu);
            let q_rt = cells.query_selector(q_rt);
            let rlc = cells.query_advice(rlc_g_cpu, Rotation::cur());
            let value = cells.query_advice(value_rt, Rotation::cur());
            let tag_rt = cells.query_advice(tag_rt, Rotation::cur());
            let call_id_rt = cells.query_advice(call_id_rt, Rotation::cur());
            let address_rt = cells.query_advice(address_rt, Rotation::cur());
            let ft_rt = cells.query_advice(field_tag_rt, Rotation::cur());
            let storage_key_rt = cells.query_advice(storage_key_rt, Rotation::cur());
            let rwc_rt = cells.query_advice(rw_counter_rt, Rotation::cur());
            let iswrite_rt = cells.query_advice(iswrite_rt, Rotation::cur());
            let zero = Expression::Constant(F::ZERO);
            let one = Expression::Constant(F::ONE);
            let rwc_adder = Expression::Constant(F::from(7u64));
            let tag_cpu = Expression::Constant(F::from(5u64));
            let rwc_cpu = cells.query_advice(rw_counter_cpu, Rotation::cur());
            let ft_cpu = Expression::Constant(F::from(8u64));
            let notisend = one.clone() - cells.query_advice(isend_rt, Rotation::cur());
            vec![
                (gate.clone() * rlc.clone(), q_rt.clone() * value.clone()),
                (
                    gate.clone() * tag_cpu.clone(),
                    q_rt.clone() * tag_rt.clone(),
                ),
                (
                    gate.clone() * one.clone(),
                    q_rt.clone() * call_id_rt.clone(),
                ),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * address_rt.clone(),
                ),
                (gate.clone() * ft_cpu.clone(), q_rt.clone() * ft_rt.clone()),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * storage_key_rt.clone(),
                ),
                (
                    gate.clone() * (rwc_cpu.clone() + rwc_adder.clone()),
                    q_rt.clone() * rwc_rt.clone(),
                ),
                (
                    gate.clone() * one.clone(),
                    q_rt.clone() * iswrite_rt.clone(),
                ),
                (gate.clone() * one.clone(), q_rt.clone() * notisend),
            ]
        });
        ///////////////////////////////

        meta.lookup_any("cpu to rt, r, value, iscall", |cells| {
            let gate =
                cells.query_advice(iscall_cpu, Rotation::cur()) * cells.query_selector(q_cpu);
            let q_rt = cells.query_selector(q_rt);
            let rlc = cells.query_advice(rlc_h_cpu, Rotation::cur());
            let value = cells.query_advice(value_rt, Rotation::cur());
            let sp = cells.query_advice(sp_cpu, Rotation::cur());
            let tag_rt = cells.query_advice(tag_rt, Rotation::cur());
            let call_id_rt = cells.query_advice(call_id_rt, Rotation::cur());
            let address_rt = cells.query_advice(address_rt, Rotation::cur());
            let ft_rt = cells.query_advice(field_tag_rt, Rotation::cur());
            let storage_key_rt = cells.query_advice(storage_key_rt, Rotation::cur());
            let rwc_rt = cells.query_advice(rw_counter_rt, Rotation::cur());
            let iswrite_rt = cells.query_advice(iswrite_rt, Rotation::cur());
            let zero = Expression::Constant(F::ZERO);
            let one = Expression::Constant(F::ONE);
            let _two = Expression::Constant(F::from(2u64));
            let six = Expression::Constant(F::from(6u64));
            let rwc_adder = Expression::Constant(F::from(15u64));
            let rwc_cpu = cells.query_advice(rw_counter_cpu, Rotation::cur());
            let tag_cpu = Expression::Constant(F::from(2u64));
            let call_id_cpu = cells.query_advice(call_id_cpu, Rotation::cur());
            let notisend = one.clone() - cells.query_advice(isend_rt, Rotation::cur());

            vec![
                (
                    gate.clone() * tag_cpu.clone(),
                    q_rt.clone() * tag_rt.clone(),
                ),
                (
                    gate.clone() * call_id_cpu,
                    q_rt.clone() * call_id_rt.clone(),
                ),
                (
                    gate.clone() * (sp.clone() - six.clone()),
                    q_rt.clone() * address_rt.clone(),
                ),
                (gate.clone() * zero.clone(), q_rt.clone() * ft_rt.clone()),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * storage_key_rt.clone(),
                ),
                (
                    gate.clone() * (rwc_cpu.clone() + rwc_adder.clone()),
                    q_rt.clone() * rwc_rt.clone(),
                ),
                (gate.clone() * rlc.clone(), q_rt.clone() * value.clone()),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * iswrite_rt.clone(),
                ),
                (gate.clone() * one.clone(), q_rt.clone() * notisend),
            ]
        });

        meta.lookup_any("cpu to rt, w, value, iscall", |cells| {
            let gate =
                cells.query_advice(iscall_cpu, Rotation::cur()) * cells.query_selector(q_cpu);
            let q_rt = cells.query_selector(q_rt);
            let rlc = cells.query_advice(rlc_h_cpu, Rotation::cur());
            let value = cells.query_advice(value_rt, Rotation::cur());
            let tag_rt = cells.query_advice(tag_rt, Rotation::cur());
            let call_id_rt = cells.query_advice(call_id_rt, Rotation::cur());
            let address_rt = cells.query_advice(address_rt, Rotation::cur());
            let ft_rt = cells.query_advice(field_tag_rt, Rotation::cur());
            let storage_key_rt = cells.query_advice(storage_key_rt, Rotation::cur());
            let rwc_rt = cells.query_advice(rw_counter_rt, Rotation::cur());
            let iswrite_rt = cells.query_advice(iswrite_rt, Rotation::cur());
            let zero = Expression::Constant(F::ZERO);
            let one = Expression::Constant(F::ONE);
            let rwc_adder = Expression::Constant(F::from(16u64));
            let tag_cpu = Expression::Constant(F::from(5u64));
            let rwc_cpu = cells.query_advice(rw_counter_cpu, Rotation::cur());
            let ft_cpu = Expression::Constant(F::from(11u64));
            let notisend = one.clone() - cells.query_advice(isend_rt, Rotation::cur());
            vec![
                (gate.clone() * rlc.clone(), q_rt.clone() * value.clone()),
                (
                    gate.clone() * tag_cpu.clone(),
                    q_rt.clone() * tag_rt.clone(),
                ),
                (
                    gate.clone() * rwc_cpu.clone(),
                    q_rt.clone() * call_id_rt.clone(),
                ),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * address_rt.clone(),
                ),
                (gate.clone() * ft_cpu.clone(), q_rt.clone() * ft_rt.clone()),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * storage_key_rt.clone(),
                ),
                (
                    gate.clone() * (rwc_cpu.clone() + rwc_adder.clone()),
                    q_rt.clone() * rwc_rt.clone(),
                ),
                (
                    gate.clone() * one.clone(),
                    q_rt.clone() * iswrite_rt.clone(),
                ),
                (gate.clone() * one.clone(), q_rt.clone() * notisend),
            ]
        });

        meta.lookup_any("cpu to txtable, r, value, isbegintx", |cells| {
            let gate =
                cells.query_advice(isbegintx_cpu, Rotation::cur()) * cells.query_selector(q_cpu);
            let active_tx = cells.query_instance(active_tx, Rotation::cur());
            let rlc = cells.query_advice(rlc_h_cpu, Rotation::cur());
            let value_low = cells.query_instance(value_low_tx, Rotation::cur());
            let value_high = cells.query_instance(value_high_tx, Rotation::cur());
            let tag_tx = cells.query_instance(tag_tx, Rotation::cur());
            let index_tx = cells.query_instance(index_tx, Rotation::cur());
            let zero = Expression::Constant(F::ZERO);
            let tag_cpu = Expression::Constant(F::from(7u64));
            let two_pow_128 = Expression::Constant(F::from(2u64).pow_vartime([128]));
            vec![
                (
                    gate.clone() * rlc.clone(),
                    active_tx.clone()
                        * (value_low.clone() + value_high.clone() * two_pow_128.clone()),
                ),
                (
                    gate.clone() * tag_cpu.clone(),
                    active_tx.clone() * tag_tx.clone(),
                ),
                (
                    gate.clone() * zero.clone(),
                    active_tx.clone() * index_tx.clone(),
                ),
            ]
        });

        meta.lookup_any("cpu to rt, w, value, isbegintx", |cells| {
            let gate =
                cells.query_advice(isbegintx_cpu, Rotation::cur()) * cells.query_selector(q_cpu);
            let q_rt = cells.query_selector(q_rt);
            let rlc = cells.query_advice(rlc_h_cpu, Rotation::cur());
            let value = cells.query_advice(value_rt, Rotation::cur());
            let tag_rt = cells.query_advice(tag_rt, Rotation::cur());
            let call_id_rt = cells.query_advice(call_id_rt, Rotation::cur());
            let address_rt = cells.query_advice(address_rt, Rotation::cur());
            let ft_rt = cells.query_advice(field_tag_rt, Rotation::cur());
            let storage_key_rt = cells.query_advice(storage_key_rt, Rotation::cur());
            let rwc_rt = cells.query_advice(rw_counter_rt, Rotation::cur());
            let iswrite_rt = cells.query_advice(iswrite_rt, Rotation::cur());
            let zero = Expression::Constant(F::ZERO);
            let one = Expression::Constant(F::ONE);
            let rwc_adder = Expression::Constant(F::from(8u64));
            let tag_cpu = Expression::Constant(F::from(5u64));
            let rwc_cpu = cells.query_advice(rw_counter_cpu, Rotation::cur());
            let ft_cpu = Expression::Constant(F::from(11u64));
            let notisend = one.clone() - cells.query_advice(isend_rt, Rotation::cur());
            vec![
                (gate.clone() * rlc.clone(), q_rt.clone() * value.clone()),
                (
                    gate.clone() * tag_cpu.clone(),
                    q_rt.clone() * tag_rt.clone(),
                ),
                (
                    gate.clone() * one.clone(),
                    q_rt.clone() * call_id_rt.clone(),
                ),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * address_rt.clone(),
                ),
                (gate.clone() * ft_cpu.clone(), q_rt.clone() * ft_rt.clone()),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * storage_key_rt.clone(),
                ),
                (
                    gate.clone() * (rwc_cpu.clone() + rwc_adder.clone()),
                    q_rt.clone() * rwc_rt.clone(),
                ),
                (
                    gate.clone() * one.clone(),
                    q_rt.clone() * iswrite_rt.clone(),
                ),
                (gate.clone() * one.clone(), q_rt.clone() * notisend),
            ]
        });
        ///////////////////////////////////////
        meta.lookup_any("cpu to rt, w, isroot, iscall", |cells| {
            let gate =
                cells.query_advice(iscall_cpu, Rotation::cur()) * cells.query_selector(q_cpu);
            let q_rt = cells.query_selector(q_rt);
            let value = cells.query_advice(value_rt, Rotation::cur());
            let tag_rt = cells.query_advice(tag_rt, Rotation::cur());
            let call_id_rt = cells.query_advice(call_id_rt, Rotation::cur());
            let address_rt = cells.query_advice(address_rt, Rotation::cur());
            let ft_rt = cells.query_advice(field_tag_rt, Rotation::cur());
            let storage_key_rt = cells.query_advice(storage_key_rt, Rotation::cur());
            let rwc_rt = cells.query_advice(rw_counter_rt, Rotation::cur());
            let iswrite_rt = cells.query_advice(iswrite_rt, Rotation::cur());
            let zero = Expression::Constant(F::ZERO);
            let one = Expression::Constant(F::ONE);
            let tag_cpu = Expression::Constant(F::from(5u64));
            let rwc_cpu = cells.query_advice(rw_counter_cpu, Rotation::cur());
            let rwc_adder = Expression::Constant(F::from(17u64));
            let ft_cpu = Expression::Constant(F::from(15u64));
            let notisend = one.clone() - cells.query_advice(isend_rt, Rotation::cur());
            vec![
                (gate.clone() * zero.clone(), q_rt.clone() * value.clone()),
                (
                    gate.clone() * tag_cpu.clone(),
                    q_rt.clone() * tag_rt.clone(),
                ),
                (
                    gate.clone() * rwc_cpu.clone(),
                    q_rt.clone() * call_id_rt.clone(),
                ),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * address_rt.clone(),
                ),
                (gate.clone() * ft_cpu.clone(), q_rt.clone() * ft_rt.clone()),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * storage_key_rt.clone(),
                ),
                (
                    gate.clone() * (rwc_cpu.clone() + rwc_adder.clone()),
                    q_rt.clone() * rwc_rt.clone(),
                ),
                (
                    gate.clone() * one.clone(),
                    q_rt.clone() * iswrite_rt.clone(),
                ),
                (gate.clone() * one.clone(), q_rt.clone() * notisend),
            ]
        });

        meta.lookup_any("cpu to rt, w, isroot, isbegintx", |cells| {
            let gate =
                cells.query_advice(isbegintx_cpu, Rotation::cur()) * cells.query_selector(q_cpu);
            let q_rt = cells.query_selector(q_rt);
            let value = cells.query_advice(value_rt, Rotation::cur());
            let tag_rt = cells.query_advice(tag_rt, Rotation::cur());
            let call_id_rt = cells.query_advice(call_id_rt, Rotation::cur());
            let address_rt = cells.query_advice(address_rt, Rotation::cur());
            let ft_rt = cells.query_advice(field_tag_rt, Rotation::cur());
            let storage_key_rt = cells.query_advice(storage_key_rt, Rotation::cur());
            let rwc_rt = cells.query_advice(rw_counter_rt, Rotation::cur());
            let iswrite_rt = cells.query_advice(iswrite_rt, Rotation::cur());
            let zero = Expression::Constant(F::ZERO);
            let one = Expression::Constant(F::ONE);
            let tag_cpu = Expression::Constant(F::from(5u64));
            let rwc_cpu = cells.query_advice(rw_counter_cpu, Rotation::cur());
            let rwc_adder = Expression::Constant(F::from(9u64));
            let ft_cpu = Expression::Constant(F::from(15u64));
            let notisend = one.clone() - cells.query_advice(isend_rt, Rotation::cur());
            vec![
                (gate.clone() * one.clone(), q_rt.clone() * value.clone()),
                (
                    gate.clone() * tag_cpu.clone(),
                    q_rt.clone() * tag_rt.clone(),
                ),
                (
                    gate.clone() * one.clone(),
                    q_rt.clone() * call_id_rt.clone(),
                ),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * address_rt.clone(),
                ),
                (gate.clone() * ft_cpu.clone(), q_rt.clone() * ft_rt.clone()),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * storage_key_rt.clone(),
                ),
                (
                    gate.clone() * (rwc_cpu.clone() + rwc_adder.clone()),
                    q_rt.clone() * rwc_rt.clone(),
                ),
                (
                    gate.clone() * one.clone(),
                    q_rt.clone() * iswrite_rt.clone(),
                ),
                (gate.clone() * one.clone(), q_rt.clone() * notisend),
            ]
        });
        ///////////////////////////////////////

        meta.lookup_any("cpu to rt, w, issuccess, isbegintx", |cells| {
            let gate =
                cells.query_advice(isbegintx_cpu, Rotation::cur()) * cells.query_selector(q_cpu);
            let q_rt = cells.query_selector(q_rt);
            let value = cells.query_advice(value_rt, Rotation::cur());
            let tag_rt = cells.query_advice(tag_rt, Rotation::cur());
            let call_id_rt = cells.query_advice(call_id_rt, Rotation::cur());
            let address_rt = cells.query_advice(address_rt, Rotation::cur());
            let ft_rt = cells.query_advice(field_tag_rt, Rotation::cur());
            let storage_key_rt = cells.query_advice(storage_key_rt, Rotation::cur());
            let rwc_rt = cells.query_advice(rw_counter_rt, Rotation::cur());
            let iswrite_rt = cells.query_advice(iswrite_rt, Rotation::cur());
            let zero = Expression::Constant(F::ZERO);
            let one = Expression::Constant(F::ONE);
            let tag_cpu = Expression::Constant(F::from(5u64));
            let rwc_cpu = cells.query_advice(rw_counter_cpu, Rotation::cur());
            let value_cpu = cells.query_advice(rlc_i_cpu, Rotation::cur());
            let rwc_adder = Expression::Constant(F::from(10u64));
            let ft_cpu = Expression::Constant(F::from(12u64));
            let notisend = one.clone() - cells.query_advice(isend_rt, Rotation::cur());

            vec![
                (
                    gate.clone() * value_cpu.clone(),
                    q_rt.clone() * value.clone(),
                ),
                (
                    gate.clone() * tag_cpu.clone(),
                    q_rt.clone() * tag_rt.clone(),
                ),
                (
                    gate.clone() * one.clone(),
                    q_rt.clone() * call_id_rt.clone(),
                ),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * address_rt.clone(),
                ),
                (gate.clone() * ft_cpu.clone(), q_rt.clone() * ft_rt.clone()),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * storage_key_rt.clone(),
                ),
                (
                    gate.clone() * (rwc_cpu.clone() + rwc_adder.clone()),
                    q_rt.clone() * rwc_rt.clone(),
                ),
                (
                    gate.clone() * one.clone(),
                    q_rt.clone() * iswrite_rt.clone(),
                ),
                (gate.clone() * one.clone(), q_rt.clone() * notisend),
            ]
        });

        meta.lookup_any("cpu to rt, w, ispersistence, isbegintx", |cells| {
            let gate =
                cells.query_advice(isbegintx_cpu, Rotation::cur()) * cells.query_selector(q_cpu);
            let q_rt = cells.query_selector(q_rt);
            let value = cells.query_advice(value_rt, Rotation::cur());
            let tag_rt = cells.query_advice(tag_rt, Rotation::cur());
            let call_id_rt = cells.query_advice(call_id_rt, Rotation::cur());
            let address_rt = cells.query_advice(address_rt, Rotation::cur());
            let ft_rt = cells.query_advice(field_tag_rt, Rotation::cur());
            let storage_key_rt = cells.query_advice(storage_key_rt, Rotation::cur());
            let rwc_rt = cells.query_advice(rw_counter_rt, Rotation::cur());
            let iswrite_rt = cells.query_advice(iswrite_rt, Rotation::cur());
            let zero = Expression::Constant(F::ZERO);
            let one = Expression::Constant(F::ONE);
            let tag_cpu = Expression::Constant(F::from(5u64));
            let rwc_cpu = cells.query_advice(rw_counter_cpu, Rotation::cur());
            let value_cpu = cells.query_advice(rlc_i_cpu, Rotation::cur());
            let rwc_adder = Expression::Constant(F::from(11u64));
            let ft_cpu = Expression::Constant(F::from(13u64));
            let notisend = one.clone() - cells.query_advice(isend_rt, Rotation::cur());

            vec![
                (
                    gate.clone() * value_cpu.clone(),
                    q_rt.clone() * value.clone(),
                ),
                (
                    gate.clone() * tag_cpu.clone(),
                    q_rt.clone() * tag_rt.clone(),
                ),
                (
                    gate.clone() * one.clone(),
                    q_rt.clone() * call_id_rt.clone(),
                ),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * address_rt.clone(),
                ),
                (gate.clone() * ft_cpu.clone(), q_rt.clone() * ft_rt.clone()),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * storage_key_rt.clone(),
                ),
                (
                    gate.clone() * (rwc_cpu.clone() + rwc_adder.clone()),
                    q_rt.clone() * rwc_rt.clone(),
                ),
                (
                    gate.clone() * one.clone(),
                    q_rt.clone() * iswrite_rt.clone(),
                ),
                (gate.clone() * one.clone(), q_rt.clone() * notisend),
            ]
        });

        meta.lookup_any("cpu to rt, w, pc, iscall", |cells| {
            let gate =
                cells.query_advice(iscall_cpu, Rotation::cur()) * cells.query_selector(q_cpu);
            let q_rt = cells.query_selector(q_rt);
            let value = cells.query_advice(value_rt, Rotation::cur());
            let tag_rt = cells.query_advice(tag_rt, Rotation::cur());
            let call_id_rt = cells.query_advice(call_id_rt, Rotation::cur());
            let address_rt = cells.query_advice(address_rt, Rotation::cur());
            let ft_rt = cells.query_advice(field_tag_rt, Rotation::cur());
            let storage_key_rt = cells.query_advice(storage_key_rt, Rotation::cur());
            let rwc_rt = cells.query_advice(rw_counter_rt, Rotation::cur());
            let iswrite_rt = cells.query_advice(iswrite_rt, Rotation::cur());
            let zero = Expression::Constant(F::ZERO);
            let one = Expression::Constant(F::ONE);
            let tag_cpu = Expression::Constant(F::from(5u64));
            let rwc_cpu = cells.query_advice(rw_counter_cpu, Rotation::cur());
            let call_id_cpu = cells.query_advice(call_id_cpu, Rotation::cur());
            let value_cpu = cells.query_advice(pc_cpu, Rotation::cur());
            let rwc_adder = Expression::Constant(F::from(18u64));
            let ft_cpu = Expression::Constant(F::from(21u64));
            let notisend = one.clone() - cells.query_advice(isend_rt, Rotation::cur());
            vec![
                (
                    gate.clone() * value_cpu.clone(),
                    q_rt.clone() * value.clone(),
                ),
                (
                    gate.clone() * tag_cpu.clone(),
                    q_rt.clone() * tag_rt.clone(),
                ),
                (
                    gate.clone() * call_id_cpu.clone(),
                    q_rt.clone() * call_id_rt.clone(),
                ),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * address_rt.clone(),
                ),
                (gate.clone() * ft_cpu.clone(), q_rt.clone() * ft_rt.clone()),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * storage_key_rt.clone(),
                ),
                (
                    gate.clone() * (rwc_cpu.clone() + rwc_adder.clone()),
                    q_rt.clone() * rwc_rt.clone(),
                ),
                (
                    gate.clone() * one.clone(),
                    q_rt.clone() * iswrite_rt.clone(),
                ),
                (gate.clone() * one.clone(), q_rt.clone() * notisend),
            ]
        });

        /////////////////////////////////////////
        meta.lookup_any("cpu to rt, w, sp, iscall", |cells| {
            let gate =
                cells.query_advice(iscall_cpu, Rotation::cur()) * cells.query_selector(q_cpu);
            let q_rt = cells.query_selector(q_rt);
            let value = cells.query_advice(value_rt, Rotation::cur());
            let tag_rt = cells.query_advice(tag_rt, Rotation::cur());
            let call_id_rt = cells.query_advice(call_id_rt, Rotation::cur());
            let address_rt = cells.query_advice(address_rt, Rotation::cur());
            let ft_rt = cells.query_advice(field_tag_rt, Rotation::cur());
            let storage_key_rt = cells.query_advice(storage_key_rt, Rotation::cur());
            let rwc_rt = cells.query_advice(rw_counter_rt, Rotation::cur());
            let iswrite_rt = cells.query_advice(iswrite_rt, Rotation::cur());
            let zero = Expression::Constant(F::ZERO);
            let one = Expression::Constant(F::ONE);
            let tag_cpu = Expression::Constant(F::from(5u64));
            let rwc_cpu = cells.query_advice(rw_counter_cpu, Rotation::cur());
            let call_id_cpu = cells.query_advice(call_id_cpu, Rotation::cur());
            let value_cpu = cells.query_advice(sp_cpu, Rotation::cur());
            let rwc_adder = Expression::Constant(F::from(19u64));
            let ft_cpu = Expression::Constant(F::from(22u64));
            let notisend = one.clone() - cells.query_advice(isend_rt, Rotation::cur());
            vec![
                (
                    gate.clone() * value_cpu.clone(),
                    q_rt.clone() * value.clone(),
                ),
                (
                    gate.clone() * tag_cpu.clone(),
                    q_rt.clone() * tag_rt.clone(),
                ),
                (
                    gate.clone() * call_id_cpu.clone(),
                    q_rt.clone() * call_id_rt.clone(),
                ),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * address_rt.clone(),
                ),
                (gate.clone() * ft_cpu.clone(), q_rt.clone() * ft_rt.clone()),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * storage_key_rt.clone(),
                ),
                (
                    gate.clone() * (rwc_cpu.clone() + rwc_adder.clone()),
                    q_rt.clone() * rwc_rt.clone(),
                ),
                (
                    gate.clone() * one.clone(),
                    q_rt.clone() * iswrite_rt.clone(),
                ),
                (gate.clone() * one.clone(), q_rt.clone() * notisend),
            ]
        });

        meta.lookup_any("cpu to rt, w, mmax, iscall", |cells| {
            let gate =
                cells.query_advice(iscall_cpu, Rotation::cur()) * cells.query_selector(q_cpu);
            let q_rt = cells.query_selector(q_rt);
            let value = cells.query_advice(value_rt, Rotation::cur());
            let tag_rt = cells.query_advice(tag_rt, Rotation::cur());
            let call_id_rt = cells.query_advice(call_id_rt, Rotation::cur());
            let address_rt = cells.query_advice(address_rt, Rotation::cur());
            let ft_rt = cells.query_advice(field_tag_rt, Rotation::cur());
            let storage_key_rt = cells.query_advice(storage_key_rt, Rotation::cur());
            let rwc_rt = cells.query_advice(rw_counter_rt, Rotation::cur());
            let iswrite_rt = cells.query_advice(iswrite_rt, Rotation::cur());
            let zero = Expression::Constant(F::ZERO);
            let one = Expression::Constant(F::ONE);
            let tag_cpu = Expression::Constant(F::from(5u64));
            let rwc_cpu = cells.query_advice(rw_counter_cpu, Rotation::cur());
            let call_id_cpu = cells.query_advice(call_id_cpu, Rotation::cur());
            let value_cpu = cells.query_advice(mmax_cpu, Rotation::cur());
            let rwc_adder = Expression::Constant(F::from(20u64));
            let ft_cpu = Expression::Constant(F::from(24u64));
            let notisend = one.clone() - cells.query_advice(isend_rt, Rotation::cur());
            vec![
                (
                    gate.clone() * value_cpu.clone(),
                    q_rt.clone() * value.clone(),
                ),
                (
                    gate.clone() * tag_cpu.clone(),
                    q_rt.clone() * tag_rt.clone(),
                ),
                (
                    gate.clone() * call_id_cpu.clone(),
                    q_rt.clone() * call_id_rt.clone(),
                ),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * address_rt.clone(),
                ),
                (gate.clone() * ft_cpu.clone(), q_rt.clone() * ft_rt.clone()),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * storage_key_rt.clone(),
                ),
                (
                    gate.clone() * (rwc_cpu.clone() + rwc_adder.clone()),
                    q_rt.clone() * rwc_rt.clone(),
                ),
                (
                    gate.clone() * one.clone(),
                    q_rt.clone() * iswrite_rt.clone(),
                ),
                (gate.clone() * one.clone(), q_rt.clone() * notisend),
            ]
        });

        meta.lookup_any("cpu to rt, r, ispersistence, iscall", |cells| {
            let gate =
                cells.query_advice(iscall_cpu, Rotation::cur()) * cells.query_selector(q_cpu);
            let q_rt = cells.query_selector(q_rt);
            let value = cells.query_advice(value_rt, Rotation::cur());
            let tag_rt = cells.query_advice(tag_rt, Rotation::cur());
            let call_id_rt = cells.query_advice(call_id_rt, Rotation::cur());
            let address_rt = cells.query_advice(address_rt, Rotation::cur());
            let ft_rt = cells.query_advice(field_tag_rt, Rotation::cur());
            let storage_key_rt = cells.query_advice(storage_key_rt, Rotation::cur());
            let rwc_rt = cells.query_advice(rw_counter_rt, Rotation::cur());
            let iswrite_rt = cells.query_advice(iswrite_rt, Rotation::cur());
            let zero = Expression::Constant(F::ZERO);
            let one = Expression::Constant(F::ONE);
            let tag_cpu = Expression::Constant(F::from(5u64));
            let rwc_cpu = cells.query_advice(rw_counter_cpu, Rotation::cur());
            let callid_cpu = cells.query_advice(call_id_cpu, Rotation::cur());
            let value_cpu = cells.query_advice(rlc_i_cpu, Rotation::cur());
            let rwc_adder = Expression::Constant(F::from(21u64));
            let ft_cpu = Expression::Constant(F::from(13u64));
            let notisend = one.clone() - cells.query_advice(isend_rt, Rotation::cur());

            vec![
                (
                    gate.clone() * value_cpu.clone(),
                    q_rt.clone() * value.clone(),
                ),
                (
                    gate.clone() * tag_cpu.clone(),
                    q_rt.clone() * tag_rt.clone(),
                ),
                (
                    gate.clone() * callid_cpu.clone(),
                    q_rt.clone() * call_id_rt.clone(),
                ),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * address_rt.clone(),
                ),
                (gate.clone() * ft_cpu.clone(), q_rt.clone() * ft_rt.clone()),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * storage_key_rt.clone(),
                ),
                (
                    gate.clone() * (rwc_cpu.clone() + rwc_adder.clone()),
                    q_rt.clone() * rwc_rt.clone(),
                ),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * iswrite_rt.clone(),
                ),
                (gate.clone() * one.clone(), q_rt.clone() * notisend),
            ]
        });

        meta.lookup_any("cpu to rt, w, issuccess, iscall", |cells| {
            let gate =
                cells.query_advice(iscall_cpu, Rotation::cur()) * cells.query_selector(q_cpu);
            let q_rt = cells.query_selector(q_rt);
            let value = cells.query_advice(value_rt, Rotation::cur());
            let tag_rt = cells.query_advice(tag_rt, Rotation::cur());
            let call_id_rt = cells.query_advice(call_id_rt, Rotation::cur());
            let address_rt = cells.query_advice(address_rt, Rotation::cur());
            let ft_rt = cells.query_advice(field_tag_rt, Rotation::cur());
            let storage_key_rt = cells.query_advice(storage_key_rt, Rotation::cur());
            let rwc_rt = cells.query_advice(rw_counter_rt, Rotation::cur());
            let iswrite_rt = cells.query_advice(iswrite_rt, Rotation::cur());
            let zero = Expression::Constant(F::ZERO);
            let one = Expression::Constant(F::ONE);
            let tag_cpu = Expression::Constant(F::from(5u64));
            let rwc_cpu = cells.query_advice(rw_counter_cpu, Rotation::cur());
            let rwc_adder = Expression::Constant(F::from(22u64));
            let value_cpu = cells.query_advice(rlc_j_cpu, Rotation::cur());
            let ft_cpu = Expression::Constant(F::from(12u64));
            let notisend = one.clone() - cells.query_advice(isend_rt, Rotation::cur());

            vec![
                (
                    gate.clone() * value_cpu.clone(),
                    q_rt.clone() * value.clone(),
                ),
                (
                    gate.clone() * tag_cpu.clone(),
                    q_rt.clone() * tag_rt.clone(),
                ),
                (
                    gate.clone() * rwc_cpu.clone(),
                    q_rt.clone() * call_id_rt.clone(),
                ),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * address_rt.clone(),
                ),
                (gate.clone() * ft_cpu.clone(), q_rt.clone() * ft_rt.clone()),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * storage_key_rt.clone(),
                ),
                (
                    gate.clone() * (rwc_cpu.clone() + rwc_adder.clone()),
                    q_rt.clone() * rwc_rt.clone(),
                ),
                (
                    gate.clone() * one.clone(),
                    q_rt.clone() * iswrite_rt.clone(),
                ),
                (gate.clone() * one.clone(), q_rt.clone() * notisend),
            ]
        });

        meta.lookup_any("cpu to rt, w, ispersistence, iscall", |cells| {
            let gate =
                cells.query_advice(iscall_cpu, Rotation::cur()) * cells.query_selector(q_cpu);
            let q_rt = cells.query_selector(q_rt);
            let value = cells.query_advice(value_rt, Rotation::cur());
            let tag_rt = cells.query_advice(tag_rt, Rotation::cur());
            let call_id_rt = cells.query_advice(call_id_rt, Rotation::cur());
            let address_rt = cells.query_advice(address_rt, Rotation::cur());
            let ft_rt = cells.query_advice(field_tag_rt, Rotation::cur());
            let storage_key_rt = cells.query_advice(storage_key_rt, Rotation::cur());
            let rwc_rt = cells.query_advice(rw_counter_rt, Rotation::cur());
            let iswrite_rt = cells.query_advice(iswrite_rt, Rotation::cur());
            let zero = Expression::Constant(F::ZERO);
            let one = Expression::Constant(F::ONE);
            let tag_cpu = Expression::Constant(F::from(5u64));
            let rwc_cpu = cells.query_advice(rw_counter_cpu, Rotation::cur());
            let rwc_adder = Expression::Constant(F::from(23u64));
            let value_cpu = cells.query_advice(rlc_i_cpu, Rotation::cur())
                * cells.query_advice(rlc_j_cpu, Rotation::cur());
            let ft_cpu = Expression::Constant(F::from(13u64));
            let notisend = one.clone() - cells.query_advice(isend_rt, Rotation::cur());

            vec![
                (
                    gate.clone() * value_cpu.clone(),
                    q_rt.clone() * value.clone(),
                ),
                (
                    gate.clone() * tag_cpu.clone(),
                    q_rt.clone() * tag_rt.clone(),
                ),
                (
                    gate.clone() * rwc_cpu.clone(),
                    q_rt.clone() * call_id_rt.clone(),
                ),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * address_rt.clone(),
                ),
                (gate.clone() * ft_cpu.clone(), q_rt.clone() * ft_rt.clone()),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * storage_key_rt.clone(),
                ),
                (
                    gate.clone() * (rwc_cpu.clone() + rwc_adder.clone()),
                    q_rt.clone() * rwc_rt.clone(),
                ),
                (
                    gate.clone() * one.clone(),
                    q_rt.clone() * iswrite_rt.clone(),
                ),
                (gate.clone() * one.clone(), q_rt.clone() * notisend),
            ]
        });

        /////////////////////////////////////

        meta.lookup_any("cpu to rt, r, callerid, isreturn", |cells| {
            let gate =
                cells.query_advice(isreturn_cpu, Rotation::cur()) * cells.query_selector(q_cpu);
            let q_rt = cells.query_selector(q_rt);
            let value = cells.query_advice(value_rt, Rotation::cur());
            let tag_rt = cells.query_advice(tag_rt, Rotation::cur());
            let call_id_rt = cells.query_advice(call_id_rt, Rotation::cur());
            let address_rt = cells.query_advice(address_rt, Rotation::cur());
            let ft_rt = cells.query_advice(field_tag_rt, Rotation::cur());
            let storage_key_rt = cells.query_advice(storage_key_rt, Rotation::cur());
            let rwc_rt = cells.query_advice(rw_counter_rt, Rotation::cur());
            let iswrite_rt = cells.query_advice(iswrite_rt, Rotation::cur());
            let zero = Expression::Constant(F::ZERO);
            let one = Expression::Constant(F::ONE);
            let tag_cpu = Expression::Constant(F::from(5u64));
            let rwc_cpu = cells.query_advice(rw_counter_cpu, Rotation::cur());
            let value_cpu = cells.query_advice(rlc_a_cpu, Rotation::cur());
            let call_id_cpu = cells.query_advice(call_id_cpu, Rotation::cur());
            let rwc_adder = Expression::Constant(F::from(0u64));
            let ft_cpu = Expression::Constant(F::from(2u64));
            let notisend = one.clone() - cells.query_advice(isend_rt, Rotation::cur());
            vec![
                (
                    gate.clone() * value_cpu.clone(),
                    q_rt.clone() * value.clone(),
                ),
                (
                    gate.clone() * tag_cpu.clone(),
                    q_rt.clone() * tag_rt.clone(),
                ),
                (
                    gate.clone() * call_id_cpu.clone(),
                    q_rt.clone() * call_id_rt.clone(),
                ),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * address_rt.clone(),
                ),
                (gate.clone() * ft_cpu.clone(), q_rt.clone() * ft_rt.clone()),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * storage_key_rt.clone(),
                ),
                (
                    gate.clone() * (rwc_cpu.clone() + rwc_adder.clone()),
                    q_rt.clone() * rwc_rt.clone(),
                ),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * iswrite_rt.clone(),
                ),
                (gate.clone() * one.clone(), q_rt.clone() * notisend),
            ]
        });

        meta.lookup_any("cpu to rt, r, isroot, isreturn", |cells| {
            let gate =
                cells.query_advice(isreturn_cpu, Rotation::cur()) * cells.query_selector(q_cpu);
            let q_rt = cells.query_selector(q_rt);
            let value = cells.query_advice(value_rt, Rotation::cur());
            let tag_rt = cells.query_advice(tag_rt, Rotation::cur());
            let call_id_rt = cells.query_advice(call_id_rt, Rotation::cur());
            let address_rt = cells.query_advice(address_rt, Rotation::cur());
            let ft_rt = cells.query_advice(field_tag_rt, Rotation::cur());
            let storage_key_rt = cells.query_advice(storage_key_rt, Rotation::cur());
            let rwc_rt = cells.query_advice(rw_counter_rt, Rotation::cur());
            let iswrite_rt = cells.query_advice(iswrite_rt, Rotation::cur());
            let zero = Expression::Constant(F::ZERO);
            let one = Expression::Constant(F::ONE);
            let tag_cpu = Expression::Constant(F::from(5u64));
            let rwc_cpu = cells.query_advice(rw_counter_cpu, Rotation::cur());
            let value_cpu = cells.query_advice(rlc_b_cpu, Rotation::cur());
            let call_id_cpu = cells.query_advice(call_id_cpu, Rotation::cur());
            let rwc_adder = Expression::Constant(F::from(1u64));
            let ft_cpu = Expression::Constant(F::from(15u64));
            let notisend = one.clone() - cells.query_advice(isend_rt, Rotation::cur());
            vec![
                (
                    gate.clone() * value_cpu.clone(),
                    q_rt.clone() * value.clone(),
                ),
                (
                    gate.clone() * tag_cpu.clone(),
                    q_rt.clone() * tag_rt.clone(),
                ),
                (
                    gate.clone() * call_id_cpu.clone(),
                    q_rt.clone() * call_id_rt.clone(),
                ),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * address_rt.clone(),
                ),
                (gate.clone() * ft_cpu.clone(), q_rt.clone() * ft_rt.clone()),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * storage_key_rt.clone(),
                ),
                (
                    gate.clone() * (rwc_cpu.clone() + rwc_adder.clone()),
                    q_rt.clone() * rwc_rt.clone(),
                ),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * iswrite_rt.clone(),
                ),
                (gate.clone() * one.clone(), q_rt.clone() * notisend),
            ]
        });

        meta.lookup_any("cpu to rt, r, pc, isreturn", |cells| {
            let gate =
                cells.query_advice(isreturn_cpu, Rotation::cur()) * cells.query_selector(q_cpu);
            let q_rt = cells.query_selector(q_rt);
            let value = cells.query_advice(value_rt, Rotation::cur());
            let tag_rt = cells.query_advice(tag_rt, Rotation::cur());
            let call_id_rt = cells.query_advice(call_id_rt, Rotation::cur());
            let address_rt = cells.query_advice(address_rt, Rotation::cur());
            let ft_rt = cells.query_advice(field_tag_rt, Rotation::cur());
            let storage_key_rt = cells.query_advice(storage_key_rt, Rotation::cur());
            let rwc_rt = cells.query_advice(rw_counter_rt, Rotation::cur());
            let iswrite_rt = cells.query_advice(iswrite_rt, Rotation::cur());
            let zero = Expression::Constant(F::ZERO);
            let one = Expression::Constant(F::ONE);
            let tag_cpu = Expression::Constant(F::from(5u64));
            let rwc_cpu = cells.query_advice(rw_counter_cpu, Rotation::cur());
            let value_cpu = cells.query_advice(rlc_c_cpu, Rotation::cur());
            let call_id_cpu = cells.query_advice(rlc_a_cpu, Rotation::cur());
            let rwc_adder = Expression::Constant(F::from(2u64));
            let ft_cpu = Expression::Constant(F::from(21u64));
            let notisend = one.clone() - cells.query_advice(isend_rt, Rotation::cur());
            vec![
                (
                    gate.clone() * value_cpu.clone(),
                    q_rt.clone() * value.clone(),
                ),
                (
                    gate.clone() * tag_cpu.clone(),
                    q_rt.clone() * tag_rt.clone(),
                ),
                (
                    gate.clone() * call_id_cpu.clone(),
                    q_rt.clone() * call_id_rt.clone(),
                ),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * address_rt.clone(),
                ),
                (gate.clone() * ft_cpu.clone(), q_rt.clone() * ft_rt.clone()),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * storage_key_rt.clone(),
                ),
                (
                    gate.clone() * (rwc_cpu.clone() + rwc_adder.clone()),
                    q_rt.clone() * rwc_rt.clone(),
                ),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * iswrite_rt.clone(),
                ),
                (gate.clone() * one.clone(), q_rt.clone() * notisend),
            ]
        });

        meta.lookup_any("cpu to rt, r, sp, isreturn", |cells| {
            let gate =
                cells.query_advice(isreturn_cpu, Rotation::cur()) * cells.query_selector(q_cpu);
            let q_rt = cells.query_selector(q_rt);
            let value = cells.query_advice(value_rt, Rotation::cur());
            let tag_rt = cells.query_advice(tag_rt, Rotation::cur());
            let call_id_rt = cells.query_advice(call_id_rt, Rotation::cur());
            let address_rt = cells.query_advice(address_rt, Rotation::cur());
            let ft_rt = cells.query_advice(field_tag_rt, Rotation::cur());
            let storage_key_rt = cells.query_advice(storage_key_rt, Rotation::cur());
            let rwc_rt = cells.query_advice(rw_counter_rt, Rotation::cur());
            let iswrite_rt = cells.query_advice(iswrite_rt, Rotation::cur());
            let zero = Expression::Constant(F::ZERO);
            let one = Expression::Constant(F::ONE);
            let tag_cpu = Expression::Constant(F::from(5u64));
            let rwc_cpu = cells.query_advice(rw_counter_cpu, Rotation::cur());
            let value_cpu = cells.query_advice(rlc_d_cpu, Rotation::cur());
            let call_id_cpu = cells.query_advice(rlc_a_cpu, Rotation::cur());
            let rwc_adder = Expression::Constant(F::from(3u64));
            let ft_cpu = Expression::Constant(F::from(22u64));
            let notisend = one.clone() - cells.query_advice(isend_rt, Rotation::cur());
            vec![
                (
                    gate.clone() * value_cpu.clone(),
                    q_rt.clone() * value.clone(),
                ),
                (
                    gate.clone() * tag_cpu.clone(),
                    q_rt.clone() * tag_rt.clone(),
                ),
                (
                    gate.clone() * call_id_cpu.clone(),
                    q_rt.clone() * call_id_rt.clone(),
                ),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * address_rt.clone(),
                ),
                (gate.clone() * ft_cpu.clone(), q_rt.clone() * ft_rt.clone()),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * storage_key_rt.clone(),
                ),
                (
                    gate.clone() * (rwc_cpu.clone() + rwc_adder.clone()),
                    q_rt.clone() * rwc_rt.clone(),
                ),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * iswrite_rt.clone(),
                ),
                (gate.clone() * one.clone(), q_rt.clone() * notisend),
            ]
        });

        meta.lookup_any("cpu to rt, r, mmax, isreturn", |cells| {
            let gate =
                cells.query_advice(isreturn_cpu, Rotation::cur()) * cells.query_selector(q_cpu);
            let q_rt = cells.query_selector(q_rt);
            let value = cells.query_advice(value_rt, Rotation::cur());
            let tag_rt = cells.query_advice(tag_rt, Rotation::cur());
            let call_id_rt = cells.query_advice(call_id_rt, Rotation::cur());
            let address_rt = cells.query_advice(address_rt, Rotation::cur());
            let ft_rt = cells.query_advice(field_tag_rt, Rotation::cur());
            let storage_key_rt = cells.query_advice(storage_key_rt, Rotation::cur());
            let rwc_rt = cells.query_advice(rw_counter_rt, Rotation::cur());
            let iswrite_rt = cells.query_advice(iswrite_rt, Rotation::cur());
            let zero = Expression::Constant(F::ZERO);
            let one = Expression::Constant(F::ONE);
            let tag_cpu = Expression::Constant(F::from(5u64));
            let rwc_cpu = cells.query_advice(rw_counter_cpu, Rotation::cur());
            let value_cpu = cells.query_advice(rlc_e_cpu, Rotation::cur());
            let call_id_cpu = cells.query_advice(rlc_a_cpu, Rotation::cur());
            let rwc_adder = Expression::Constant(F::from(4u64));
            let ft_cpu = Expression::Constant(F::from(24u64));
            let notisend = one.clone() - cells.query_advice(isend_rt, Rotation::cur());
            vec![
                (
                    gate.clone() * value_cpu.clone(),
                    q_rt.clone() * value.clone(),
                ),
                (
                    gate.clone() * tag_cpu.clone(),
                    q_rt.clone() * tag_rt.clone(),
                ),
                (
                    gate.clone() * call_id_cpu.clone(),
                    q_rt.clone() * call_id_rt.clone(),
                ),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * address_rt.clone(),
                ),
                (gate.clone() * ft_cpu.clone(), q_rt.clone() * ft_rt.clone()),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * storage_key_rt.clone(),
                ),
                (
                    gate.clone() * (rwc_cpu.clone() + rwc_adder.clone()),
                    q_rt.clone() * rwc_rt.clone(),
                ),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * iswrite_rt.clone(),
                ),
                (gate.clone() * one.clone(), q_rt.clone() * notisend),
            ]
        });

        meta.lookup_any("cpu to rt, w, lastcalleeid, isreturn", |cells| {
            let gate =
                cells.query_advice(isreturn_cpu, Rotation::cur()) * cells.query_selector(q_cpu);
            let q_rt = cells.query_selector(q_rt);
            let value = cells.query_advice(value_rt, Rotation::cur());
            let tag_rt = cells.query_advice(tag_rt, Rotation::cur());
            let call_id_rt = cells.query_advice(call_id_rt, Rotation::cur());
            let address_rt = cells.query_advice(address_rt, Rotation::cur());
            let ft_rt = cells.query_advice(field_tag_rt, Rotation::cur());
            let storage_key_rt = cells.query_advice(storage_key_rt, Rotation::cur());
            let rwc_rt = cells.query_advice(rw_counter_rt, Rotation::cur());
            let iswrite_rt = cells.query_advice(iswrite_rt, Rotation::cur());
            let zero = Expression::Constant(F::ZERO);
            let one = Expression::Constant(F::ONE);
            let tag_cpu = Expression::Constant(F::from(5u64));
            let rwc_cpu = cells.query_advice(rw_counter_cpu, Rotation::cur());
            let value_cpu = cells.query_advice(call_id_cpu, Rotation::cur());
            let call_id_cpu = cells.query_advice(rlc_a_cpu, Rotation::cur());
            let rwc_adder = Expression::Constant(F::from(5u64));
            let ft_cpu = Expression::Constant(F::from(18u64));
            let notisend = one.clone() - cells.query_advice(isend_rt, Rotation::cur());
            vec![
                (
                    gate.clone() * value_cpu.clone(),
                    q_rt.clone() * value.clone(),
                ),
                (
                    gate.clone() * tag_cpu.clone(),
                    q_rt.clone() * tag_rt.clone(),
                ),
                (
                    gate.clone() * call_id_cpu.clone(),
                    q_rt.clone() * call_id_rt.clone(),
                ),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * address_rt.clone(),
                ),
                (gate.clone() * ft_cpu.clone(), q_rt.clone() * ft_rt.clone()),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * storage_key_rt.clone(),
                ),
                (
                    gate.clone() * (rwc_cpu.clone() + rwc_adder.clone()),
                    q_rt.clone() * rwc_rt.clone(),
                ),
                (
                    gate.clone() * one.clone(),
                    q_rt.clone() * iswrite_rt.clone(),
                ),
                (gate.clone() * one.clone(), q_rt.clone() * notisend),
            ]
        });

        meta.lookup_any("cpu to rt, r, returndataoffset, isreturn", |cells| {
            let gate =
                cells.query_advice(isreturn_cpu, Rotation::cur()) * cells.query_selector(q_cpu);
            let q_rt = cells.query_selector(q_rt);
            let value = cells.query_advice(value_rt, Rotation::cur());
            let tag_rt = cells.query_advice(tag_rt, Rotation::cur());
            let call_id_rt = cells.query_advice(call_id_rt, Rotation::cur());
            let address_rt = cells.query_advice(address_rt, Rotation::cur());
            let ft_rt = cells.query_advice(field_tag_rt, Rotation::cur());
            let storage_key_rt = cells.query_advice(storage_key_rt, Rotation::cur());
            let rwc_rt = cells.query_advice(rw_counter_rt, Rotation::cur());
            let iswrite_rt = cells.query_advice(iswrite_rt, Rotation::cur());
            let zero = Expression::Constant(F::ZERO);
            let one = Expression::Constant(F::ONE);
            let tag_cpu = Expression::Constant(F::from(5u64));
            let rwc_cpu = cells.query_advice(rw_counter_cpu, Rotation::cur());
            let value_cpu = cells.query_advice(rlc_f_cpu, Rotation::cur());
            let call_id_cpu = cells.query_advice(call_id_cpu, Rotation::cur());
            let rwc_adder = Expression::Constant(F::from(6u64));
            let ft_cpu = Expression::Constant(F::from(9u64));
            let notisend = one.clone() - cells.query_advice(isend_rt, Rotation::cur());
            vec![
                (
                    gate.clone() * value_cpu.clone(),
                    q_rt.clone() * value.clone(),
                ),
                (
                    gate.clone() * tag_cpu.clone(),
                    q_rt.clone() * tag_rt.clone(),
                ),
                (
                    gate.clone() * call_id_cpu.clone(),
                    q_rt.clone() * call_id_rt.clone(),
                ),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * address_rt.clone(),
                ),
                (gate.clone() * ft_cpu.clone(), q_rt.clone() * ft_rt.clone()),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * storage_key_rt.clone(),
                ),
                (
                    gate.clone() * (rwc_cpu.clone() + rwc_adder.clone()),
                    q_rt.clone() * rwc_rt.clone(),
                ),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * iswrite_rt.clone(),
                ),
                (gate.clone() * one.clone(), q_rt.clone() * notisend),
            ]
        });

        meta.lookup_any("cpu to rt, r, returndatalength, isreturn", |cells| {
            let gate =
                cells.query_advice(isreturn_cpu, Rotation::cur()) * cells.query_selector(q_cpu);
            let q_rt = cells.query_selector(q_rt);
            let value = cells.query_advice(value_rt, Rotation::cur());
            let tag_rt = cells.query_advice(tag_rt, Rotation::cur());
            let call_id_rt = cells.query_advice(call_id_rt, Rotation::cur());
            let address_rt = cells.query_advice(address_rt, Rotation::cur());
            let ft_rt = cells.query_advice(field_tag_rt, Rotation::cur());
            let storage_key_rt = cells.query_advice(storage_key_rt, Rotation::cur());
            let rwc_rt = cells.query_advice(rw_counter_rt, Rotation::cur());
            let iswrite_rt = cells.query_advice(iswrite_rt, Rotation::cur());
            let zero = Expression::Constant(F::ZERO);
            let one = Expression::Constant(F::ONE);
            let tag_cpu = Expression::Constant(F::from(5u64));
            let rwc_cpu = cells.query_advice(rw_counter_cpu, Rotation::cur());
            let value_cpu = cells.query_advice(rlc_g_cpu, Rotation::cur());
            let call_id_cpu = cells.query_advice(call_id_cpu, Rotation::cur());
            let rwc_adder = Expression::Constant(F::from(7u64));
            let ft_cpu = Expression::Constant(F::from(10u64));
            let notisend = one.clone() - cells.query_advice(isend_rt, Rotation::cur());
            vec![
                (
                    gate.clone() * value_cpu.clone(),
                    q_rt.clone() * value.clone(),
                ),
                (
                    gate.clone() * tag_cpu.clone(),
                    q_rt.clone() * tag_rt.clone(),
                ),
                (
                    gate.clone() * call_id_cpu.clone(),
                    q_rt.clone() * call_id_rt.clone(),
                ),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * address_rt.clone(),
                ),
                (gate.clone() * ft_cpu.clone(), q_rt.clone() * ft_rt.clone()),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * storage_key_rt.clone(),
                ),
                (
                    gate.clone() * (rwc_cpu.clone() + rwc_adder.clone()),
                    q_rt.clone() * rwc_rt.clone(),
                ),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * iswrite_rt.clone(),
                ),
                (gate.clone() * one.clone(), q_rt.clone() * notisend),
            ]
        });

        meta.lookup_any(
            "cpu to rt, w, lastcalleereturndataoffset, isreturn",
            |cells| {
                let gate =
                    cells.query_advice(isreturn_cpu, Rotation::cur()) * cells.query_selector(q_cpu);
                let q_rt = cells.query_selector(q_rt);
                let value = cells.query_advice(value_rt, Rotation::cur());
                let tag_rt = cells.query_advice(tag_rt, Rotation::cur());
                let call_id_rt = cells.query_advice(call_id_rt, Rotation::cur());
                let address_rt = cells.query_advice(address_rt, Rotation::cur());
                let ft_rt = cells.query_advice(field_tag_rt, Rotation::cur());
                let storage_key_rt = cells.query_advice(storage_key_rt, Rotation::cur());
                let rwc_rt = cells.query_advice(rw_counter_rt, Rotation::cur());
                let iswrite_rt = cells.query_advice(iswrite_rt, Rotation::cur());
                let zero = Expression::Constant(F::ZERO);
                let one = Expression::Constant(F::ONE);
                let tag_cpu = Expression::Constant(F::from(5u64));
                let rwc_cpu = cells.query_advice(rw_counter_cpu, Rotation::cur());
                let value_cpu = cells.query_advice(rlc_f_cpu, Rotation::cur());
                let call_id_cpu = cells.query_advice(rlc_a_cpu, Rotation::cur());
                let rwc_adder = Expression::Constant(F::from(8u64));
                let ft_cpu = Expression::Constant(F::from(19u64));
                let notisend = one.clone() - cells.query_advice(isend_rt, Rotation::cur());
                vec![
                    (
                        gate.clone() * value_cpu.clone(),
                        q_rt.clone() * value.clone(),
                    ),
                    (
                        gate.clone() * tag_cpu.clone(),
                        q_rt.clone() * tag_rt.clone(),
                    ),
                    (
                        gate.clone() * call_id_cpu.clone(),
                        q_rt.clone() * call_id_rt.clone(),
                    ),
                    (
                        gate.clone() * zero.clone(),
                        q_rt.clone() * address_rt.clone(),
                    ),
                    (gate.clone() * ft_cpu.clone(), q_rt.clone() * ft_rt.clone()),
                    (
                        gate.clone() * zero.clone(),
                        q_rt.clone() * storage_key_rt.clone(),
                    ),
                    (
                        gate.clone() * (rwc_cpu.clone() + rwc_adder.clone()),
                        q_rt.clone() * rwc_rt.clone(),
                    ),
                    (
                        gate.clone() * one.clone(),
                        q_rt.clone() * iswrite_rt.clone(),
                    ),
                    (gate.clone() * one.clone(), q_rt.clone() * notisend),
                ]
            },
        );

        meta.lookup_any(
            "cpu to rt, w, lastcalleereturndatalength, isreturn",
            |cells| {
                let gate =
                    cells.query_advice(isreturn_cpu, Rotation::cur()) * cells.query_selector(q_cpu);
                let q_rt = cells.query_selector(q_rt);
                let value = cells.query_advice(value_rt, Rotation::cur());
                let tag_rt = cells.query_advice(tag_rt, Rotation::cur());
                let call_id_rt = cells.query_advice(call_id_rt, Rotation::cur());
                let address_rt = cells.query_advice(address_rt, Rotation::cur());
                let ft_rt = cells.query_advice(field_tag_rt, Rotation::cur());
                let storage_key_rt = cells.query_advice(storage_key_rt, Rotation::cur());
                let rwc_rt = cells.query_advice(rw_counter_rt, Rotation::cur());
                let iswrite_rt = cells.query_advice(iswrite_rt, Rotation::cur());
                let zero = Expression::Constant(F::ZERO);
                let one = Expression::Constant(F::ONE);
                let tag_cpu = Expression::Constant(F::from(5u64));
                let rwc_cpu = cells.query_advice(rw_counter_cpu, Rotation::cur());
                let rlc_j = cells.query_advice(rlc_j_cpu, Rotation::cur());
                let rlc_i = cells.query_advice(rlc_i_cpu, Rotation::cur());
                let rlc_g = cells.query_advice(rlc_g_cpu, Rotation::cur());
                let value_cpu =
                    rlc_j.clone() * rlc_g.clone() + (one.clone() - rlc_j.clone()) * rlc_i.clone();
                let call_id_cpu = cells.query_advice(rlc_a_cpu, Rotation::cur());
                let rwc_adder = Expression::Constant(F::from(9u64));
                let ft_cpu = Expression::Constant(F::from(20u64));
                let notisend = one.clone() - cells.query_advice(isend_rt, Rotation::cur());
                vec![
                    (
                        gate.clone() * value_cpu.clone(),
                        q_rt.clone() * value.clone(),
                    ),
                    (
                        gate.clone() * tag_cpu.clone(),
                        q_rt.clone() * tag_rt.clone(),
                    ),
                    (
                        gate.clone() * call_id_cpu.clone(),
                        q_rt.clone() * call_id_rt.clone(),
                    ),
                    (
                        gate.clone() * zero.clone(),
                        q_rt.clone() * address_rt.clone(),
                    ),
                    (gate.clone() * ft_cpu.clone(), q_rt.clone() * ft_rt.clone()),
                    (
                        gate.clone() * zero.clone(),
                        q_rt.clone() * storage_key_rt.clone(),
                    ),
                    (
                        gate.clone() * (rwc_cpu.clone() + rwc_adder.clone()),
                        q_rt.clone() * rwc_rt.clone(),
                    ),
                    (
                        gate.clone() * one.clone(),
                        q_rt.clone() * iswrite_rt.clone(),
                    ),
                    (gate.clone() * one.clone(), q_rt.clone() * notisend),
                ]
            },
        );

        meta.lookup_any("cpu to stack, w, issuccess, isreturn", |cells| {
            let gate =
                cells.query_advice(isreturn_cpu, Rotation::cur()) * cells.query_selector(q_cpu);
            let q_rt = cells.query_selector(q_rt);
            let value = cells.query_advice(value_rt, Rotation::cur());
            let tag_rt = cells.query_advice(tag_rt, Rotation::cur());
            let call_id_rt = cells.query_advice(call_id_rt, Rotation::cur());
            let address_rt = cells.query_advice(address_rt, Rotation::cur());
            let ft_rt = cells.query_advice(field_tag_rt, Rotation::cur());
            let storage_key_rt = cells.query_advice(storage_key_rt, Rotation::cur());
            let rwc_rt = cells.query_advice(rw_counter_rt, Rotation::cur());
            let iswrite_rt = cells.query_advice(iswrite_rt, Rotation::cur());
            let zero = Expression::Constant(F::ZERO);
            let one = Expression::Constant(F::ONE);
            let six = Expression::Constant(F::from(6u64));
            let tag_cpu = Expression::Constant(F::from(2u64));
            let rwc_cpu = cells.query_advice(rw_counter_cpu, Rotation::cur());
            let sp_cpu = cells.query_advice(rlc_d_cpu, Rotation::cur());
            let call_id_cpu = cells.query_advice(rlc_a_cpu, Rotation::cur());
            let rwc_adder = Expression::Constant(F::from(10u64));
            let ft_cpu = Expression::Constant(F::from(0u64));
            let notisend = one.clone() - cells.query_advice(isend_rt, Rotation::cur());
            vec![
                (gate.clone() * one.clone(), q_rt.clone() * value.clone()),
                (
                    gate.clone() * tag_cpu.clone(),
                    q_rt.clone() * tag_rt.clone(),
                ),
                (
                    gate.clone() * call_id_cpu.clone(),
                    q_rt.clone() * call_id_rt.clone(),
                ),
                (
                    gate.clone() * (sp_cpu.clone() - six.clone()),
                    q_rt.clone() * address_rt.clone(),
                ),
                (gate.clone() * ft_cpu.clone(), q_rt.clone() * ft_rt.clone()),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * storage_key_rt.clone(),
                ),
                (
                    gate.clone() * (rwc_cpu.clone() + rwc_adder.clone()),
                    q_rt.clone() * rwc_rt.clone(),
                ),
                (
                    gate.clone() * one.clone(),
                    q_rt.clone() * iswrite_rt.clone(),
                ),
                (gate.clone() * one.clone(), q_rt.clone() * notisend),
            ]
        });

        meta.lookup_any("cpu to rt, r, issuccess, isreturn", |cells| {
            let gate =
                cells.query_advice(isreturn_cpu, Rotation::cur()) * cells.query_selector(q_cpu);
            let q_rt = cells.query_selector(q_rt);
            let value = cells.query_advice(value_rt, Rotation::cur());
            let tag_rt = cells.query_advice(tag_rt, Rotation::cur());
            let call_id_rt = cells.query_advice(call_id_rt, Rotation::cur());
            let address_rt = cells.query_advice(address_rt, Rotation::cur());
            let ft_rt = cells.query_advice(field_tag_rt, Rotation::cur());
            let storage_key_rt = cells.query_advice(storage_key_rt, Rotation::cur());
            let rwc_rt = cells.query_advice(rw_counter_rt, Rotation::cur());
            let iswrite_rt = cells.query_advice(iswrite_rt, Rotation::cur());
            let zero = Expression::Constant(F::ZERO);
            let one = Expression::Constant(F::ONE);
            let tag_cpu = Expression::Constant(F::from(5u64));
            let rwc_cpu = cells.query_advice(rw_counter_cpu, Rotation::cur());
            let call_id_cpu = cells.query_advice(call_id_cpu, Rotation::cur());
            let rwc_adder = Expression::Constant(F::from(11u64));
            let ft_cpu = Expression::Constant(F::from(12u64));
            let notisend = one.clone() - cells.query_advice(isend_rt, Rotation::cur());
            vec![
                (gate.clone() * one.clone(), q_rt.clone() * value.clone()),
                (
                    gate.clone() * tag_cpu.clone(),
                    q_rt.clone() * tag_rt.clone(),
                ),
                (
                    gate.clone() * call_id_cpu.clone(),
                    q_rt.clone() * call_id_rt.clone(),
                ),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * address_rt.clone(),
                ),
                (gate.clone() * ft_cpu.clone(), q_rt.clone() * ft_rt.clone()),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * storage_key_rt.clone(),
                ),
                (
                    gate.clone() * (rwc_cpu.clone() + rwc_adder.clone()),
                    q_rt.clone() * rwc_rt.clone(),
                ),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * iswrite_rt.clone(),
                ),
                (gate.clone() * one.clone(), q_rt.clone() * notisend),
            ]
        });

        meta.lookup_any("cpu to rt, r, offset, isreturn", |cells| {
            let gate =
                cells.query_advice(isreturn_cpu, Rotation::cur()) * cells.query_selector(q_cpu);
            let q_rt = cells.query_selector(q_rt);
            let value = cells.query_advice(value_rt, Rotation::cur());
            let tag_rt = cells.query_advice(tag_rt, Rotation::cur());
            let call_id_rt = cells.query_advice(call_id_rt, Rotation::cur());
            let address_rt = cells.query_advice(address_rt, Rotation::cur());
            let ft_rt = cells.query_advice(field_tag_rt, Rotation::cur());
            let storage_key_rt = cells.query_advice(storage_key_rt, Rotation::cur());
            let rwc_rt = cells.query_advice(rw_counter_rt, Rotation::cur());
            let iswrite_rt = cells.query_advice(iswrite_rt, Rotation::cur());
            let zero = Expression::Constant(F::ZERO);
            let one = Expression::Constant(F::ONE);
            let tag_cpu = Expression::Constant(F::from(2u64));
            let rwc_cpu = cells.query_advice(rw_counter_cpu, Rotation::cur());
            let address_cpu = cells.query_advice(sp_cpu, Rotation::cur());
            let value_cpu = cells.query_advice(rlc_h_cpu, Rotation::cur());
            let call_id_cpu = cells.query_advice(call_id_cpu, Rotation::cur());
            let rwc_adder = Expression::Constant(F::from(12u64));
            let ft_cpu = Expression::Constant(F::from(0u64));
            let notisend = one.clone() - cells.query_advice(isend_rt, Rotation::cur());
            vec![
                (
                    gate.clone() * value_cpu.clone(),
                    q_rt.clone() * value.clone(),
                ),
                (
                    gate.clone() * tag_cpu.clone(),
                    q_rt.clone() * tag_rt.clone(),
                ),
                (
                    gate.clone() * call_id_cpu.clone(),
                    q_rt.clone() * call_id_rt.clone(),
                ),
                (
                    gate.clone() * (address_cpu.clone() - one.clone()),
                    q_rt.clone() * address_rt.clone(),
                ),
                (gate.clone() * ft_cpu.clone(), q_rt.clone() * ft_rt.clone()),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * storage_key_rt.clone(),
                ),
                (
                    gate.clone() * (rwc_cpu.clone() + rwc_adder.clone()),
                    q_rt.clone() * rwc_rt.clone(),
                ),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * iswrite_rt.clone(),
                ),
                (gate.clone() * one.clone(), q_rt.clone() * notisend),
            ]
        });

        meta.lookup_any("cpu to rt, r, length, isreturn", |cells| {
            let gate =
                cells.query_advice(isreturn_cpu, Rotation::cur()) * cells.query_selector(q_cpu);
            let q_rt = cells.query_selector(q_rt);
            let value = cells.query_advice(value_rt, Rotation::cur());
            let tag_rt = cells.query_advice(tag_rt, Rotation::cur());
            let call_id_rt = cells.query_advice(call_id_rt, Rotation::cur());
            let address_rt = cells.query_advice(address_rt, Rotation::cur());
            let ft_rt = cells.query_advice(field_tag_rt, Rotation::cur());
            let storage_key_rt = cells.query_advice(storage_key_rt, Rotation::cur());
            let rwc_rt = cells.query_advice(rw_counter_rt, Rotation::cur());
            let iswrite_rt = cells.query_advice(iswrite_rt, Rotation::cur());
            let zero = Expression::Constant(F::ZERO);
            let one = Expression::Constant(F::ONE);
            let two = Expression::Constant(F::from(2u64));
            let tag_cpu = Expression::Constant(F::from(2u64));
            let rwc_cpu = cells.query_advice(rw_counter_cpu, Rotation::cur());
            let address_cpu = cells.query_advice(sp_cpu, Rotation::cur());
            let value_cpu = cells.query_advice(rlc_i_cpu, Rotation::cur());
            let call_id_cpu = cells.query_advice(call_id_cpu, Rotation::cur());
            let rwc_adder = Expression::Constant(F::from(13u64));
            let ft_cpu = Expression::Constant(F::from(0u64));
            let notisend = one.clone() - cells.query_advice(isend_rt, Rotation::cur());
            vec![
                (
                    gate.clone() * value_cpu.clone(),
                    q_rt.clone() * value.clone(),
                ),
                (
                    gate.clone() * tag_cpu.clone(),
                    q_rt.clone() * tag_rt.clone(),
                ),
                (
                    gate.clone() * call_id_cpu.clone(),
                    q_rt.clone() * call_id_rt.clone(),
                ),
                (
                    gate.clone() * (address_cpu.clone() - two.clone()),
                    q_rt.clone() * address_rt.clone(),
                ),
                (gate.clone() * ft_cpu.clone(), q_rt.clone() * ft_rt.clone()),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * storage_key_rt.clone(),
                ),
                (
                    gate.clone() * (rwc_cpu.clone() + rwc_adder.clone()),
                    q_rt.clone() * rwc_rt.clone(),
                ),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * iswrite_rt.clone(),
                ),
                (gate.clone() * one.clone(), q_rt.clone() * notisend),
            ]
        });

        meta.lookup_any("cpu to copy circuit, isreturn", |cells| {
            let zero = Expression::Constant(F::ZERO);
            let one = Expression::Constant(F::ONE);
            let _two = Expression::Constant(F::from(2u64));
            let gate_cpu = cells.query_advice(isreturn_cpu, Rotation::cur())
                * cells.query_selector(q_cpu)
                * (one.clone() - cells.query_advice(rlc_b_cpu, Rotation::cur()));
            let gate_cc =
                cells.query_selector(q_cc) * cells.query_advice(switch_cc, Rotation::cur());
            let isfirst_cc = cells.query_advice(isfirst_cc, Rotation::cur());
            let address_write_cpu = cells.query_advice(rlc_f_cpu, Rotation::cur());
            let address_write_cc = cells.query_advice(address_write_cc, Rotation::cur());
            let address_read_cpu = cells.query_advice(rlc_h_cpu, Rotation::cur());
            let address_read_cc = cells.query_advice(address_read_cc, Rotation::cur());
            let rlc_j = cells.query_advice(rlc_j_cpu, Rotation::cur());
            let rlc_i = cells.query_advice(rlc_i_cpu, Rotation::cur());
            let rlc_g = cells.query_advice(rlc_g_cpu, Rotation::cur());
            let bytesleft_cpu =
                rlc_j.clone() * rlc_g.clone() + (one.clone() - rlc_j.clone()) * rlc_i.clone();
            let address_end_cc = cells.query_advice(address_end_cc, Rotation::cur());
            let ismem_cc = cells.query_advice(ismem_cc, Rotation::cur());
            let istx_cc = cells.query_advice(istx_cc, Rotation::cur());
            let rwc_cc = cells.query_advice(rwc_cc, Rotation::cur());
            let rwc_cpu = cells.query_advice(rw_counter_cpu, Rotation::cur());
            let call_id_cpu = cells.query_advice(call_id_cpu, Rotation::cur());
            let call_id_read_cc = cells.query_advice(callid_read_cc, Rotation::cur());
            let call_id_parent_cpu = cells.query_advice(rlc_a_cpu, Rotation::cur());
            let call_id_write_cc = cells.query_advice(callid_write_cc, Rotation::cur());
            let bytesleft_cc = cells.query_advice(bytesleft_cc, Rotation::cur());
            let rwc_adder = Expression::Constant(F::from(14u64));

            vec![
                (
                    gate_cpu.clone() * one.clone(),
                    gate_cc.clone() * isfirst_cc.clone(),
                ),
                (
                    gate_cpu.clone() * (rwc_cpu.clone() + rwc_adder.clone()),
                    gate_cc.clone() * rwc_cc.clone(),
                ),
                (
                    gate_cpu.clone() * address_write_cpu.clone(),
                    gate_cc.clone() * address_write_cc.clone(),
                ),
                (
                    gate_cpu.clone() * address_read_cpu.clone(),
                    gate_cc.clone() * address_read_cc.clone(),
                ),
                (
                    gate_cpu.clone() * (address_read_cpu.clone() + bytesleft_cpu.clone()),
                    gate_cc.clone() * address_end_cc.clone(),
                ),
                (
                    gate_cpu.clone() * one.clone(),
                    gate_cc.clone() * ismem_cc.clone(),
                ),
                (
                    gate_cpu.clone() * zero.clone(),
                    gate_cc.clone() * istx_cc.clone(),
                ),
                (
                    gate_cpu.clone() * call_id_cpu.clone(),
                    gate_cc.clone() * call_id_read_cc.clone(),
                ),
                (
                    gate_cpu.clone() * call_id_parent_cpu.clone(),
                    gate_cc.clone() * call_id_write_cc.clone(),
                ),
                (
                    gate_cpu.clone() * bytesleft_cpu.clone(),
                    gate_cc.clone() * bytesleft_cc.clone(),
                ),
            ]
        });

        meta.lookup_any(
            "cpu to rw stack, destination offset, returndatacopy",
            |cells| {
                let gate = cells.query_advice(returndatacopy_cpu, Rotation::cur())
                    * cells.query_selector(q_cpu);
                let q_rt = cells.query_selector(q_rt);
                let value = cells.query_advice(value_rt, Rotation::cur());
                let tag_rt = cells.query_advice(tag_rt, Rotation::cur());
                let call_id_rt = cells.query_advice(call_id_rt, Rotation::cur());
                let address_rt = cells.query_advice(address_rt, Rotation::cur());
                let ft_rt = cells.query_advice(field_tag_rt, Rotation::cur());
                let storage_key_rt = cells.query_advice(storage_key_rt, Rotation::cur());
                let rwc_rt = cells.query_advice(rw_counter_rt, Rotation::cur());
                let iswrite_rt = cells.query_advice(iswrite_rt, Rotation::cur());
                let zero = Expression::Constant(F::ZERO);
                let one = Expression::Constant(F::ONE);
                let two = Expression::Constant(F::from(2u64));
                let tag_cpu = Expression::Constant(F::from(2u64));
                let rwc_cpu = cells.query_advice(rw_counter_cpu, Rotation::cur());
                let address_cpu = cells.query_advice(sp_cpu, Rotation::cur());
                let value_cpu = cells.query_advice(rlc_a_cpu, Rotation::cur());
                let call_id_cpu = cells.query_advice(call_id_cpu, Rotation::cur());
                let rwc_adder = Expression::Constant(F::from(0u64));
                let ft_cpu = Expression::Constant(F::from(0u64));
                let notisend = one.clone() - cells.query_advice(isend_rt, Rotation::cur());
                vec![
                    (
                        gate.clone() * value_cpu.clone(),
                        q_rt.clone() * value.clone(),
                    ),
                    (
                        gate.clone() * tag_cpu.clone(),
                        q_rt.clone() * tag_rt.clone(),
                    ),
                    (
                        gate.clone() * call_id_cpu.clone(),
                        q_rt.clone() * call_id_rt.clone(),
                    ),
                    (
                        gate.clone() * (address_cpu.clone() - one.clone()),
                        q_rt.clone() * address_rt.clone(),
                    ),
                    (gate.clone() * ft_cpu.clone(), q_rt.clone() * ft_rt.clone()),
                    (
                        gate.clone() * zero.clone(),
                        q_rt.clone() * storage_key_rt.clone(),
                    ),
                    (
                        gate.clone() * (rwc_cpu.clone() + rwc_adder.clone()),
                        q_rt.clone() * rwc_rt.clone(),
                    ),
                    (
                        gate.clone() * zero.clone(),
                        q_rt.clone() * iswrite_rt.clone(),
                    ),
                    (gate.clone() * one.clone(), q_rt.clone() * notisend),
                ]
            },
        );

        meta.lookup_any("cpu to rw stack, source offset, returndatacopy", |cells| {
            let gate = cells.query_advice(returndatacopy_cpu, Rotation::cur())
                * cells.query_selector(q_cpu);
            let q_rt = cells.query_selector(q_rt);
            let value = cells.query_advice(value_rt, Rotation::cur());
            let tag_rt = cells.query_advice(tag_rt, Rotation::cur());
            let call_id_rt = cells.query_advice(call_id_rt, Rotation::cur());
            let address_rt = cells.query_advice(address_rt, Rotation::cur());
            let ft_rt = cells.query_advice(field_tag_rt, Rotation::cur());
            let storage_key_rt = cells.query_advice(storage_key_rt, Rotation::cur());
            let rwc_rt = cells.query_advice(rw_counter_rt, Rotation::cur());
            let iswrite_rt = cells.query_advice(iswrite_rt, Rotation::cur());
            let zero = Expression::Constant(F::ZERO);
            let one = Expression::Constant(F::ONE);
            let two = Expression::Constant(F::from(2u64));
            let tag_cpu = Expression::Constant(F::from(2u64));
            let rwc_cpu = cells.query_advice(rw_counter_cpu, Rotation::cur());
            let address_cpu = cells.query_advice(sp_cpu, Rotation::cur());
            let value_cpu = cells.query_advice(rlc_b_cpu, Rotation::cur());
            let call_id_cpu = cells.query_advice(call_id_cpu, Rotation::cur());
            let rwc_adder = Expression::Constant(F::from(1u64));
            let ft_cpu = Expression::Constant(F::from(0u64));
            let notisend = one.clone() - cells.query_advice(isend_rt, Rotation::cur());
            vec![
                (
                    gate.clone() * value_cpu.clone(),
                    q_rt.clone() * value.clone(),
                ),
                (
                    gate.clone() * tag_cpu.clone(),
                    q_rt.clone() * tag_rt.clone(),
                ),
                (
                    gate.clone() * call_id_cpu.clone(),
                    q_rt.clone() * call_id_rt.clone(),
                ),
                (
                    gate.clone() * (address_cpu.clone() - two.clone()),
                    q_rt.clone() * address_rt.clone(),
                ),
                (gate.clone() * ft_cpu.clone(), q_rt.clone() * ft_rt.clone()),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * storage_key_rt.clone(),
                ),
                (
                    gate.clone() * (rwc_cpu.clone() + rwc_adder.clone()),
                    q_rt.clone() * rwc_rt.clone(),
                ),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * iswrite_rt.clone(),
                ),
                (gate.clone() * one.clone(), q_rt.clone() * notisend),
            ]
        });

        meta.lookup_any("cpu to rw stack, lenght, returndatacopy", |cells| {
            let gate = cells.query_advice(returndatacopy_cpu, Rotation::cur())
                * cells.query_selector(q_cpu);
            let q_rt = cells.query_selector(q_rt);
            let value = cells.query_advice(value_rt, Rotation::cur());
            let tag_rt = cells.query_advice(tag_rt, Rotation::cur());
            let call_id_rt = cells.query_advice(call_id_rt, Rotation::cur());
            let address_rt = cells.query_advice(address_rt, Rotation::cur());
            let ft_rt = cells.query_advice(field_tag_rt, Rotation::cur());
            let storage_key_rt = cells.query_advice(storage_key_rt, Rotation::cur());
            let rwc_rt = cells.query_advice(rw_counter_rt, Rotation::cur());
            let iswrite_rt = cells.query_advice(iswrite_rt, Rotation::cur());
            let zero = Expression::Constant(F::ZERO);
            let one = Expression::Constant(F::ONE);
            let _two = Expression::Constant(F::from(2u64));
            let three = Expression::Constant(F::from(3u64));
            let tag_cpu = Expression::Constant(F::from(2u64));
            let rwc_cpu = cells.query_advice(rw_counter_cpu, Rotation::cur());
            let address_cpu = cells.query_advice(sp_cpu, Rotation::cur());
            let value_cpu = cells.query_advice(rlc_c_cpu, Rotation::cur());
            let call_id_cpu = cells.query_advice(call_id_cpu, Rotation::cur());
            let rwc_adder = Expression::Constant(F::from(2u64));
            let ft_cpu = Expression::Constant(F::from(0u64));
            let notisend = one.clone() - cells.query_advice(isend_rt, Rotation::cur());
            vec![
                (
                    gate.clone() * value_cpu.clone(),
                    q_rt.clone() * value.clone(),
                ),
                (
                    gate.clone() * tag_cpu.clone(),
                    q_rt.clone() * tag_rt.clone(),
                ),
                (
                    gate.clone() * call_id_cpu.clone(),
                    q_rt.clone() * call_id_rt.clone(),
                ),
                (
                    gate.clone() * (address_cpu.clone() - three.clone()),
                    q_rt.clone() * address_rt.clone(),
                ),
                (gate.clone() * ft_cpu.clone(), q_rt.clone() * ft_rt.clone()),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * storage_key_rt.clone(),
                ),
                (
                    gate.clone() * (rwc_cpu.clone() + rwc_adder.clone()),
                    q_rt.clone() * rwc_rt.clone(),
                ),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * iswrite_rt.clone(),
                ),
                (gate.clone() * one.clone(), q_rt.clone() * notisend),
            ]
        });

        meta.lookup_any(
            "cpu to rt, r, lastcalleereturndataoffset, returndatacopy",
            |cells| {
                let gate = cells.query_advice(returndatacopy_cpu, Rotation::cur())
                    * cells.query_selector(q_cpu);
                let q_rt = cells.query_selector(q_rt);
                let value = cells.query_advice(value_rt, Rotation::cur());
                let tag_rt = cells.query_advice(tag_rt, Rotation::cur());
                let call_id_rt = cells.query_advice(call_id_rt, Rotation::cur());
                let address_rt = cells.query_advice(address_rt, Rotation::cur());
                let ft_rt = cells.query_advice(field_tag_rt, Rotation::cur());
                let storage_key_rt = cells.query_advice(storage_key_rt, Rotation::cur());
                let rwc_rt = cells.query_advice(rw_counter_rt, Rotation::cur());
                let iswrite_rt = cells.query_advice(iswrite_rt, Rotation::cur());
                let zero = Expression::Constant(F::ZERO);
                let one = Expression::Constant(F::ONE);
                let tag_cpu = Expression::Constant(F::from(5u64));
                let rwc_cpu = cells.query_advice(rw_counter_cpu, Rotation::cur());
                let value_cpu = cells.query_advice(rlc_d_cpu, Rotation::cur());
                let call_id_cpu = cells.query_advice(call_id_cpu, Rotation::cur());
                let rwc_adder = Expression::Constant(F::from(3u64));
                let ft_cpu = Expression::Constant(F::from(19u64));
                let notisend = one.clone() - cells.query_advice(isend_rt, Rotation::cur());
                vec![
                    (
                        gate.clone() * value_cpu.clone(),
                        q_rt.clone() * value.clone(),
                    ),
                    (
                        gate.clone() * tag_cpu.clone(),
                        q_rt.clone() * tag_rt.clone(),
                    ),
                    (
                        gate.clone() * call_id_cpu.clone(),
                        q_rt.clone() * call_id_rt.clone(),
                    ),
                    (
                        gate.clone() * zero.clone(),
                        q_rt.clone() * address_rt.clone(),
                    ),
                    (gate.clone() * ft_cpu.clone(), q_rt.clone() * ft_rt.clone()),
                    (
                        gate.clone() * zero.clone(),
                        q_rt.clone() * storage_key_rt.clone(),
                    ),
                    (
                        gate.clone() * (rwc_cpu.clone() + rwc_adder.clone()),
                        q_rt.clone() * rwc_rt.clone(),
                    ),
                    (
                        gate.clone() * zero.clone(),
                        q_rt.clone() * iswrite_rt.clone(),
                    ),
                    (gate.clone() * one.clone(), q_rt.clone() * notisend),
                ]
            },
        );

        meta.lookup_any(
            "cpu to rt, r, lastcalleereturndatalength, returndatacopy",
            |cells| {
                let gate = cells.query_advice(returndatacopy_cpu, Rotation::cur())
                    * cells.query_selector(q_cpu);
                let q_rt = cells.query_selector(q_rt);
                let value = cells.query_advice(value_rt, Rotation::cur());
                let tag_rt = cells.query_advice(tag_rt, Rotation::cur());
                let call_id_rt = cells.query_advice(call_id_rt, Rotation::cur());
                let address_rt = cells.query_advice(address_rt, Rotation::cur());
                let ft_rt = cells.query_advice(field_tag_rt, Rotation::cur());
                let storage_key_rt = cells.query_advice(storage_key_rt, Rotation::cur());
                let rwc_rt = cells.query_advice(rw_counter_rt, Rotation::cur());
                let iswrite_rt = cells.query_advice(iswrite_rt, Rotation::cur());
                let zero = Expression::Constant(F::ZERO);
                let one = Expression::Constant(F::ONE);
                let tag_cpu = Expression::Constant(F::from(5u64));
                let rwc_cpu = cells.query_advice(rw_counter_cpu, Rotation::cur());
                let value_cpu = cells.query_advice(rlc_e_cpu, Rotation::cur());
                let call_id_cpu = cells.query_advice(call_id_cpu, Rotation::cur());
                let rwc_adder = Expression::Constant(F::from(4u64));
                let ft_cpu = Expression::Constant(F::from(20u64));
                let notisend = one.clone() - cells.query_advice(isend_rt, Rotation::cur());
                vec![
                    (
                        gate.clone() * value_cpu.clone(),
                        q_rt.clone() * value.clone(),
                    ),
                    (
                        gate.clone() * tag_cpu.clone(),
                        q_rt.clone() * tag_rt.clone(),
                    ),
                    (
                        gate.clone() * call_id_cpu.clone(),
                        q_rt.clone() * call_id_rt.clone(),
                    ),
                    (
                        gate.clone() * zero.clone(),
                        q_rt.clone() * address_rt.clone(),
                    ),
                    (gate.clone() * ft_cpu.clone(), q_rt.clone() * ft_rt.clone()),
                    (
                        gate.clone() * zero.clone(),
                        q_rt.clone() * storage_key_rt.clone(),
                    ),
                    (
                        gate.clone() * (rwc_cpu.clone() + rwc_adder.clone()),
                        q_rt.clone() * rwc_rt.clone(),
                    ),
                    (
                        gate.clone() * zero.clone(),
                        q_rt.clone() * iswrite_rt.clone(),
                    ),
                    (gate.clone() * one.clone(), q_rt.clone() * notisend),
                ]
            },
        );

        meta.lookup_any("cpu to copy circuit, returndatacopy", |cells| {
            let zero = Expression::Constant(F::ZERO);
            let one = Expression::Constant(F::ONE);
            let two = Expression::Constant(F::from(2u64));
            let gate_cpu = cells.query_advice(returndatacopy_cpu, Rotation::cur())
                * cells.query_selector(q_cpu);
            let gate_cc =
                cells.query_selector(q_cc) * cells.query_advice(switch_cc, Rotation::cur());
            let isfirst_cc = cells.query_advice(isfirst_cc, Rotation::cur());
            let address_write_cpu = cells.query_advice(rlc_a_cpu, Rotation::cur());
            let address_write_cc = cells.query_advice(address_write_cc, Rotation::cur());
            let address_read_cpu = cells.query_advice(rlc_b_cpu, Rotation::cur())
                + cells.query_advice(rlc_d_cpu, Rotation::cur());
            let address_read_cc = cells.query_advice(address_read_cc, Rotation::cur());
            let bytesleft_cpu = cells.query_advice(rlc_c_cpu, Rotation::cur());
            let address_end_cc = cells.query_advice(address_end_cc, Rotation::cur());
            let ismem_cc = cells.query_advice(ismem_cc, Rotation::cur());
            let istx_cc = cells.query_advice(istx_cc, Rotation::cur());
            let rwc_cc = cells.query_advice(rwc_cc, Rotation::cur());
            let rwc_cpu = cells.query_advice(rw_counter_cpu, Rotation::cur());
            let call_id_read_cc = cells.query_advice(callid_read_cc, Rotation::cur());
            let call_id_cpu = cells.query_advice(call_id_cpu, Rotation::cur());
            let call_id_write_cc = cells.query_advice(callid_write_cc, Rotation::cur());
            let bytesleft_cc = cells.query_advice(bytesleft_cc, Rotation::cur());
            let lastcalleereturndatalength_cpu = cells.query_advice(rlc_e_cpu, Rotation::cur());
            let lastcalleereturndataoffset_cpu = cells.query_advice(rlc_d_cpu, Rotation::cur());
            let rwc_adder = Expression::Constant(F::from(5u64));

            vec![
                (
                    gate_cpu.clone() * one.clone(),
                    gate_cc.clone() * isfirst_cc.clone(),
                ),
                (
                    gate_cpu.clone() * (rwc_cpu.clone() + rwc_adder.clone()),
                    gate_cc.clone() * rwc_cc.clone(),
                ),
                (
                    gate_cpu.clone() * address_write_cpu.clone(),
                    gate_cc.clone() * address_write_cc.clone(),
                ),
                (
                    gate_cpu.clone() * address_read_cpu.clone(),
                    gate_cc.clone() * address_read_cc.clone(),
                ),
                (
                    gate_cpu.clone()
                        * (lastcalleereturndataoffset_cpu.clone()
                            + lastcalleereturndatalength_cpu.clone()),
                    gate_cc.clone() * address_end_cc.clone(),
                ),
                (
                    gate_cpu.clone() * one.clone(),
                    gate_cc.clone() * ismem_cc.clone(),
                ),
                (
                    gate_cpu.clone() * zero.clone(),
                    gate_cc.clone() * istx_cc.clone(),
                ),
                (
                    gate_cpu.clone() * call_id_cpu.clone(),
                    gate_cc.clone() * call_id_read_cc.clone(),
                ),
                (
                    gate_cpu.clone() * call_id_cpu.clone(),
                    gate_cc.clone() * call_id_write_cc.clone(),
                ),
                (
                    gate_cpu.clone() * bytesleft_cpu.clone(),
                    gate_cc.clone() * bytesleft_cc.clone(),
                ),
            ]
        });

        ///////////////////////////////////

        meta.lookup_any(
            "cpu to rw stack, destination offset, calldatacopy",
            |cells| {
                let gate = cells.query_advice(calldatacopy_cpu, Rotation::cur())
                    * cells.query_selector(q_cpu);
                let q_rt = cells.query_selector(q_rt);
                let value = cells.query_advice(value_rt, Rotation::cur());
                let tag_rt = cells.query_advice(tag_rt, Rotation::cur());
                let call_id_rt = cells.query_advice(call_id_rt, Rotation::cur());
                let address_rt = cells.query_advice(address_rt, Rotation::cur());
                let ft_rt = cells.query_advice(field_tag_rt, Rotation::cur());
                let storage_key_rt = cells.query_advice(storage_key_rt, Rotation::cur());
                let rwc_rt = cells.query_advice(rw_counter_rt, Rotation::cur());
                let iswrite_rt = cells.query_advice(iswrite_rt, Rotation::cur());
                let zero = Expression::Constant(F::ZERO);
                let one = Expression::Constant(F::ONE);
                let two = Expression::Constant(F::from(2u64));
                let tag_cpu = Expression::Constant(F::from(2u64));
                let rwc_cpu = cells.query_advice(rw_counter_cpu, Rotation::cur());
                let address_cpu = cells.query_advice(sp_cpu, Rotation::cur());
                let value_cpu = cells.query_advice(rlc_a_cpu, Rotation::cur());
                let call_id_cpu = cells.query_advice(call_id_cpu, Rotation::cur());
                let rwc_adder = Expression::Constant(F::from(0u64));
                let ft_cpu = Expression::Constant(F::from(0u64));
                let notisend = one.clone() - cells.query_advice(isend_rt, Rotation::cur());
                vec![
                    (
                        gate.clone() * value_cpu.clone(),
                        q_rt.clone() * value.clone(),
                    ),
                    (
                        gate.clone() * tag_cpu.clone(),
                        q_rt.clone() * tag_rt.clone(),
                    ),
                    (
                        gate.clone() * call_id_cpu.clone(),
                        q_rt.clone() * call_id_rt.clone(),
                    ),
                    (
                        gate.clone() * (address_cpu.clone() - one.clone()),
                        q_rt.clone() * address_rt.clone(),
                    ),
                    (gate.clone() * ft_cpu.clone(), q_rt.clone() * ft_rt.clone()),
                    (
                        gate.clone() * zero.clone(),
                        q_rt.clone() * storage_key_rt.clone(),
                    ),
                    (
                        gate.clone() * (rwc_cpu.clone() + rwc_adder.clone()),
                        q_rt.clone() * rwc_rt.clone(),
                    ),
                    (
                        gate.clone() * zero.clone(),
                        q_rt.clone() * iswrite_rt.clone(),
                    ),
                    (gate.clone() * one.clone(), q_rt.clone() * notisend),
                ]
            },
        );

        meta.lookup_any("cpu to rw stack, source offset, calldatacopy", |cells| {
            let gate =
                cells.query_advice(calldatacopy_cpu, Rotation::cur()) * cells.query_selector(q_cpu);
            let q_rt = cells.query_selector(q_rt);
            let value = cells.query_advice(value_rt, Rotation::cur());
            let tag_rt = cells.query_advice(tag_rt, Rotation::cur());
            let call_id_rt = cells.query_advice(call_id_rt, Rotation::cur());
            let address_rt = cells.query_advice(address_rt, Rotation::cur());
            let ft_rt = cells.query_advice(field_tag_rt, Rotation::cur());
            let storage_key_rt = cells.query_advice(storage_key_rt, Rotation::cur());
            let rwc_rt = cells.query_advice(rw_counter_rt, Rotation::cur());
            let iswrite_rt = cells.query_advice(iswrite_rt, Rotation::cur());
            let zero = Expression::Constant(F::ZERO);
            let one = Expression::Constant(F::ONE);
            let two = Expression::Constant(F::from(2u64));
            let tag_cpu = Expression::Constant(F::from(2u64));
            let rwc_cpu = cells.query_advice(rw_counter_cpu, Rotation::cur());
            let address_cpu = cells.query_advice(sp_cpu, Rotation::cur());
            let value_cpu = cells.query_advice(rlc_b_cpu, Rotation::cur());
            let call_id_cpu = cells.query_advice(call_id_cpu, Rotation::cur());
            let rwc_adder = Expression::Constant(F::from(1u64));
            let ft_cpu = Expression::Constant(F::from(0u64));
            let notisend = one.clone() - cells.query_advice(isend_rt, Rotation::cur());
            vec![
                (
                    gate.clone() * value_cpu.clone(),
                    q_rt.clone() * value.clone(),
                ),
                (
                    gate.clone() * tag_cpu.clone(),
                    q_rt.clone() * tag_rt.clone(),
                ),
                (
                    gate.clone() * call_id_cpu.clone(),
                    q_rt.clone() * call_id_rt.clone(),
                ),
                (
                    gate.clone() * (address_cpu.clone() - two.clone()),
                    q_rt.clone() * address_rt.clone(),
                ),
                (gate.clone() * ft_cpu.clone(), q_rt.clone() * ft_rt.clone()),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * storage_key_rt.clone(),
                ),
                (
                    gate.clone() * (rwc_cpu.clone() + rwc_adder.clone()),
                    q_rt.clone() * rwc_rt.clone(),
                ),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * iswrite_rt.clone(),
                ),
                (gate.clone() * one.clone(), q_rt.clone() * notisend),
            ]
        });

        meta.lookup_any("cpu to rw stack, length, calldatacopy", |cells| {
            let gate =
                cells.query_advice(calldatacopy_cpu, Rotation::cur()) * cells.query_selector(q_cpu);
            let q_rt = cells.query_selector(q_rt);
            let value = cells.query_advice(value_rt, Rotation::cur());
            let tag_rt = cells.query_advice(tag_rt, Rotation::cur());
            let call_id_rt = cells.query_advice(call_id_rt, Rotation::cur());
            let address_rt = cells.query_advice(address_rt, Rotation::cur());
            let ft_rt = cells.query_advice(field_tag_rt, Rotation::cur());
            let storage_key_rt = cells.query_advice(storage_key_rt, Rotation::cur());
            let rwc_rt = cells.query_advice(rw_counter_rt, Rotation::cur());
            let iswrite_rt = cells.query_advice(iswrite_rt, Rotation::cur());
            let zero = Expression::Constant(F::ZERO);
            let one = Expression::Constant(F::ONE);
            let two = Expression::Constant(F::from(2u64));
            let three = Expression::Constant(F::from(3u64));
            let tag_cpu = Expression::Constant(F::from(2u64));
            let rwc_cpu = cells.query_advice(rw_counter_cpu, Rotation::cur());
            let address_cpu = cells.query_advice(sp_cpu, Rotation::cur());
            let value_cpu = cells.query_advice(rlc_c_cpu, Rotation::cur());
            let call_id_cpu = cells.query_advice(call_id_cpu, Rotation::cur());
            let rwc_adder = Expression::Constant(F::from(2u64));
            let ft_cpu = Expression::Constant(F::from(0u64));
            let notisend = one.clone() - cells.query_advice(isend_rt, Rotation::cur());
            vec![
                (
                    gate.clone() * value_cpu.clone(),
                    q_rt.clone() * value.clone(),
                ),
                (
                    gate.clone() * tag_cpu.clone(),
                    q_rt.clone() * tag_rt.clone(),
                ),
                (
                    gate.clone() * call_id_cpu.clone(),
                    q_rt.clone() * call_id_rt.clone(),
                ),
                (
                    gate.clone() * (address_cpu.clone() - three.clone()),
                    q_rt.clone() * address_rt.clone(),
                ),
                (gate.clone() * ft_cpu.clone(), q_rt.clone() * ft_rt.clone()),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * storage_key_rt.clone(),
                ),
                (
                    gate.clone() * (rwc_cpu.clone() + rwc_adder.clone()),
                    q_rt.clone() * rwc_rt.clone(),
                ),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * iswrite_rt.clone(),
                ),
                (gate.clone() * one.clone(), q_rt.clone() * notisend),
            ]
        });

        meta.lookup_any("cpu to rt, r, callerid, calldatacopy", |cells| {
            let gate =
                cells.query_advice(calldatacopy_cpu, Rotation::cur()) * cells.query_selector(q_cpu);
            let q_rt = cells.query_selector(q_rt);
            let value = cells.query_advice(value_rt, Rotation::cur());
            let tag_rt = cells.query_advice(tag_rt, Rotation::cur());
            let call_id_rt = cells.query_advice(call_id_rt, Rotation::cur());
            let address_rt = cells.query_advice(address_rt, Rotation::cur());
            let ft_rt = cells.query_advice(field_tag_rt, Rotation::cur());
            let storage_key_rt = cells.query_advice(storage_key_rt, Rotation::cur());
            let rwc_rt = cells.query_advice(rw_counter_rt, Rotation::cur());
            let iswrite_rt = cells.query_advice(iswrite_rt, Rotation::cur());
            let zero = Expression::Constant(F::ZERO);
            let one = Expression::Constant(F::ONE);
            let tag_cpu = Expression::Constant(F::from(5u64));
            let rwc_cpu = cells.query_advice(rw_counter_cpu, Rotation::cur());
            let value_cpu = cells.query_advice(rlc_d_cpu, Rotation::cur());
            let call_id_cpu = cells.query_advice(call_id_cpu, Rotation::cur());
            let rwc_adder = Expression::Constant(F::from(3u64));
            let ft_cpu = Expression::Constant(F::from(2u64));
            let notisend = one.clone() - cells.query_advice(isend_rt, Rotation::cur());
            vec![
                (
                    gate.clone() * value_cpu.clone(),
                    q_rt.clone() * value.clone(),
                ),
                (
                    gate.clone() * tag_cpu.clone(),
                    q_rt.clone() * tag_rt.clone(),
                ),
                (
                    gate.clone() * call_id_cpu.clone(),
                    q_rt.clone() * call_id_rt.clone(),
                ),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * address_rt.clone(),
                ),
                (gate.clone() * ft_cpu.clone(), q_rt.clone() * ft_rt.clone()),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * storage_key_rt.clone(),
                ),
                (
                    gate.clone() * (rwc_cpu.clone() + rwc_adder.clone()),
                    q_rt.clone() * rwc_rt.clone(),
                ),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * iswrite_rt.clone(),
                ),
                (gate.clone() * one.clone(), q_rt.clone() * notisend),
            ]
        });

        meta.lookup_any("cpu to rt, r, calldataoffset, calldatacopy", |cells| {
            let gate =
                cells.query_advice(calldatacopy_cpu, Rotation::cur()) * cells.query_selector(q_cpu);
            let q_rt = cells.query_selector(q_rt);
            let value = cells.query_advice(value_rt, Rotation::cur());
            let tag_rt = cells.query_advice(tag_rt, Rotation::cur());
            let call_id_rt = cells.query_advice(call_id_rt, Rotation::cur());
            let address_rt = cells.query_advice(address_rt, Rotation::cur());
            let ft_rt = cells.query_advice(field_tag_rt, Rotation::cur());
            let storage_key_rt = cells.query_advice(storage_key_rt, Rotation::cur());
            let rwc_rt = cells.query_advice(rw_counter_rt, Rotation::cur());
            let iswrite_rt = cells.query_advice(iswrite_rt, Rotation::cur());
            let zero = Expression::Constant(F::ZERO);
            let one = Expression::Constant(F::ONE);
            let tag_cpu = Expression::Constant(F::from(5u64));
            let rwc_cpu = cells.query_advice(rw_counter_cpu, Rotation::cur());
            let value_cpu = cells.query_advice(rlc_e_cpu, Rotation::cur());
            let call_id_cpu = cells.query_advice(call_id_cpu, Rotation::cur());
            let rwc_adder = Expression::Constant(F::from(4u64));
            let ft_cpu = Expression::Constant(F::from(7u64));
            let notisend = one.clone() - cells.query_advice(isend_rt, Rotation::cur());
            vec![
                (
                    gate.clone() * value_cpu.clone(),
                    q_rt.clone() * value.clone(),
                ),
                (
                    gate.clone() * tag_cpu.clone(),
                    q_rt.clone() * tag_rt.clone(),
                ),
                (
                    gate.clone() * call_id_cpu.clone(),
                    q_rt.clone() * call_id_rt.clone(),
                ),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * address_rt.clone(),
                ),
                (gate.clone() * ft_cpu.clone(), q_rt.clone() * ft_rt.clone()),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * storage_key_rt.clone(),
                ),
                (
                    gate.clone() * (rwc_cpu.clone() + rwc_adder.clone()),
                    q_rt.clone() * rwc_rt.clone(),
                ),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * iswrite_rt.clone(),
                ),
                (gate.clone() * one.clone(), q_rt.clone() * notisend),
            ]
        });

        meta.lookup_any("cpu to rt, r, calldatalength, calldatacopy", |cells| {
            let gate =
                cells.query_advice(calldatacopy_cpu, Rotation::cur()) * cells.query_selector(q_cpu);
            let q_rt = cells.query_selector(q_rt);
            let value = cells.query_advice(value_rt, Rotation::cur());
            let tag_rt = cells.query_advice(tag_rt, Rotation::cur());
            let call_id_rt = cells.query_advice(call_id_rt, Rotation::cur());
            let address_rt = cells.query_advice(address_rt, Rotation::cur());
            let ft_rt = cells.query_advice(field_tag_rt, Rotation::cur());
            let storage_key_rt = cells.query_advice(storage_key_rt, Rotation::cur());
            let rwc_rt = cells.query_advice(rw_counter_rt, Rotation::cur());
            let iswrite_rt = cells.query_advice(iswrite_rt, Rotation::cur());
            let zero = Expression::Constant(F::ZERO);
            let one = Expression::Constant(F::ONE);
            let tag_cpu = Expression::Constant(F::from(5u64));
            let rwc_cpu = cells.query_advice(rw_counter_cpu, Rotation::cur());
            let value_cpu = cells.query_advice(rlc_f_cpu, Rotation::cur());
            let call_id_cpu = cells.query_advice(call_id_cpu, Rotation::cur());
            let rwc_adder = Expression::Constant(F::from(5u64));
            let ft_cpu = Expression::Constant(F::from(8u64));
            let notisend = one.clone() - cells.query_advice(isend_rt, Rotation::cur());
            vec![
                (
                    gate.clone() * value_cpu.clone(),
                    q_rt.clone() * value.clone(),
                ),
                (
                    gate.clone() * tag_cpu.clone(),
                    q_rt.clone() * tag_rt.clone(),
                ),
                (
                    gate.clone() * call_id_cpu.clone(),
                    q_rt.clone() * call_id_rt.clone(),
                ),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * address_rt.clone(),
                ),
                (gate.clone() * ft_cpu.clone(), q_rt.clone() * ft_rt.clone()),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * storage_key_rt.clone(),
                ),
                (
                    gate.clone() * (rwc_cpu.clone() + rwc_adder.clone()),
                    q_rt.clone() * rwc_rt.clone(),
                ),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * iswrite_rt.clone(),
                ),
                (gate.clone() * one.clone(), q_rt.clone() * notisend),
            ]
        });

        meta.lookup_any("cpu to rt, r, isroot, calldatacopy", |cells| {
            let gate =
                cells.query_advice(calldatacopy_cpu, Rotation::cur()) * cells.query_selector(q_cpu);
            let q_rt = cells.query_selector(q_rt);
            let value = cells.query_advice(value_rt, Rotation::cur());
            let tag_rt = cells.query_advice(tag_rt, Rotation::cur());
            let call_id_rt = cells.query_advice(call_id_rt, Rotation::cur());
            let address_rt = cells.query_advice(address_rt, Rotation::cur());
            let ft_rt = cells.query_advice(field_tag_rt, Rotation::cur());
            let storage_key_rt = cells.query_advice(storage_key_rt, Rotation::cur());
            let rwc_rt = cells.query_advice(rw_counter_rt, Rotation::cur());
            let iswrite_rt = cells.query_advice(iswrite_rt, Rotation::cur());
            let zero = Expression::Constant(F::ZERO);
            let one = Expression::Constant(F::ONE);
            let tag_cpu = Expression::Constant(F::from(5u64));
            let rwc_cpu = cells.query_advice(rw_counter_cpu, Rotation::cur());
            let value_cpu = cells.query_advice(rlc_g_cpu, Rotation::cur());
            let call_id_cpu = cells.query_advice(call_id_cpu, Rotation::cur());
            let rwc_adder = Expression::Constant(F::from(6u64));
            let ft_cpu = Expression::Constant(F::from(15u64));
            let notisend = one.clone() - cells.query_advice(isend_rt, Rotation::cur());
            vec![
                (
                    gate.clone() * value_cpu.clone(),
                    q_rt.clone() * value.clone(),
                ),
                (
                    gate.clone() * tag_cpu.clone(),
                    q_rt.clone() * tag_rt.clone(),
                ),
                (
                    gate.clone() * call_id_cpu.clone(),
                    q_rt.clone() * call_id_rt.clone(),
                ),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * address_rt.clone(),
                ),
                (gate.clone() * ft_cpu.clone(), q_rt.clone() * ft_rt.clone()),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * storage_key_rt.clone(),
                ),
                (
                    gate.clone() * (rwc_cpu.clone() + rwc_adder.clone()),
                    q_rt.clone() * rwc_rt.clone(),
                ),
                (
                    gate.clone() * zero.clone(),
                    q_rt.clone() * iswrite_rt.clone(),
                ),
                (gate.clone() * one.clone(), q_rt.clone() * notisend),
            ]
        });

        meta.lookup_any("cpu to copy circuit, ismem, calldatacopy", |cells| {
            let zero = Expression::Constant(F::ZERO);
            let one = Expression::Constant(F::ONE);
            let two = Expression::Constant(F::from(2u64));
            let gate_cpu = cells.query_advice(calldatacopy_cpu, Rotation::cur())
                * cells.query_selector(q_cpu)
                * (one.clone() - cells.query_advice(rlc_g_cpu, Rotation::cur()));
            let gate_cc =
                cells.query_selector(q_cc) * cells.query_advice(switch_cc, Rotation::cur());
            let isfirst_cc = cells.query_advice(isfirst_cc, Rotation::cur());
            let address_write_cpu = cells.query_advice(rlc_a_cpu, Rotation::cur());
            let address_write_cc = cells.query_advice(address_write_cc, Rotation::cur());
            let address_read_cpu = cells.query_advice(rlc_b_cpu, Rotation::cur())
                + cells.query_advice(rlc_e_cpu, Rotation::cur());
            let address_read_cc = cells.query_advice(address_read_cc, Rotation::cur());
            let address_end_cc = cells.query_advice(address_end_cc, Rotation::cur());
            let ismem_cc = cells.query_advice(ismem_cc, Rotation::cur());
            let istx_cc = cells.query_advice(istx_cc, Rotation::cur());
            let rwc_cc = cells.query_advice(rwc_cc, Rotation::cur());
            let rwc_cpu = cells.query_advice(rw_counter_cpu, Rotation::cur());
            let call_id_cpu = cells.query_advice(call_id_cpu, Rotation::cur());
            let caller_id_cpu = cells.query_advice(rlc_d_cpu, Rotation::cur());
            let call_id_read_cc = cells.query_advice(callid_read_cc, Rotation::cur());
            let call_id_write_cc = cells.query_advice(callid_write_cc, Rotation::cur());
            let bytesleft_cc = cells.query_advice(bytesleft_cc, Rotation::cur());
            let bytesleft_cpu = cells.query_advice(rlc_c_cpu, Rotation::cur());
            let calldataoffset_cpu = cells.query_advice(rlc_e_cpu, Rotation::cur());
            let calldatalength_cpu = cells.query_advice(rlc_f_cpu, Rotation::cur());
            let rwc_adder = Expression::Constant(F::from(7u64));

            vec![
                (
                    gate_cpu.clone() * one.clone(),
                    gate_cc.clone() * isfirst_cc.clone(),
                ),
                (
                    gate_cpu.clone() * (rwc_cpu.clone() + rwc_adder.clone()),
                    gate_cc.clone() * rwc_cc.clone(),
                ),
                (
                    gate_cpu.clone() * address_write_cpu.clone(),
                    gate_cc.clone() * address_write_cc.clone(),
                ),
                (
                    gate_cpu.clone() * address_read_cpu.clone(),
                    gate_cc.clone() * address_read_cc.clone(),
                ),
                (
                    gate_cpu.clone() * (calldataoffset_cpu.clone() + calldatalength_cpu.clone()),
                    gate_cc.clone() * address_end_cc.clone(),
                ),
                (
                    gate_cpu.clone() * one.clone(),
                    gate_cc.clone() * ismem_cc.clone(),
                ),
                (
                    gate_cpu.clone() * zero.clone(),
                    gate_cc.clone() * istx_cc.clone(),
                ),
                (
                    gate_cpu.clone() * caller_id_cpu.clone(),
                    gate_cc.clone() * call_id_read_cc.clone(),
                ),
                (
                    gate_cpu.clone() * call_id_cpu.clone(),
                    gate_cc.clone() * call_id_write_cc.clone(),
                ),
                (
                    gate_cpu.clone() * bytesleft_cpu.clone(),
                    gate_cc.clone() * bytesleft_cc.clone(),
                ),
            ]
        });

        meta.lookup_any("cpu to txtable, r, calldatalenght, calldatacopy", |cells| {
            let gate =
                cells.query_advice(calldatacopy_cpu, Rotation::cur()) * cells.query_selector(q_cpu);
            let active_tx = cells.query_instance(active_tx, Rotation::cur());
            let rlc = cells.query_advice(rlc_h_cpu, Rotation::cur());
            let value_low = cells.query_instance(value_low_tx, Rotation::cur());
            let value_high = cells.query_instance(value_high_tx, Rotation::cur());
            let tag_tx = cells.query_instance(tag_tx, Rotation::cur());
            let index_tx = cells.query_instance(index_tx, Rotation::cur());
            let zero = Expression::Constant(F::ZERO);
            let tag_cpu = Expression::Constant(F::from(8u64));
            let two_pow_128 = Expression::Constant(F::from(2u64).pow_vartime([128]));
            vec![
                (
                    gate.clone() * rlc.clone(),
                    active_tx.clone()
                        * (value_low.clone() + value_high.clone() * two_pow_128.clone()),
                ),
                (
                    gate.clone() * tag_cpu.clone(),
                    active_tx.clone() * tag_tx.clone(),
                ),
                (
                    gate.clone() * zero.clone(),
                    active_tx.clone() * index_tx.clone(),
                ),
            ]
        });

        meta.lookup_any("cpu to copy circuit, istx, calldatacopy", |cells| {
            let zero = Expression::Constant(F::ZERO);
            let one = Expression::Constant(F::ONE);
            let _two = Expression::Constant(F::from(2u64));
            let gate_cpu = cells.query_advice(calldatacopy_cpu, Rotation::cur())
                * cells.query_selector(q_cpu)
                * cells.query_advice(rlc_g_cpu, Rotation::cur());
            let gate_cc =
                cells.query_selector(q_cc) * cells.query_advice(switch_cc, Rotation::cur());
            let isfirst_cc = cells.query_advice(isfirst_cc, Rotation::cur());
            let address_write_cpu = cells.query_advice(rlc_a_cpu, Rotation::cur());
            let address_write_cc = cells.query_advice(address_write_cc, Rotation::cur());
            let address_read_cpu = cells.query_advice(rlc_b_cpu, Rotation::cur());
            let address_read_cc = cells.query_advice(address_read_cc, Rotation::cur());
            let address_end_cc = cells.query_advice(address_end_cc, Rotation::cur());
            let ismem_cc = cells.query_advice(ismem_cc, Rotation::cur());
            let istx_cc = cells.query_advice(istx_cc, Rotation::cur());
            let rwc_cc = cells.query_advice(rwc_cc, Rotation::cur());
            let rwc_cpu = cells.query_advice(rw_counter_cpu, Rotation::cur());
            let call_id_cpu = cells.query_advice(call_id_cpu, Rotation::cur());
            let call_id_read_cc = cells.query_advice(callid_read_cc, Rotation::cur());
            let call_id_write_cc = cells.query_advice(callid_write_cc, Rotation::cur());
            let bytesleft_cc = cells.query_advice(bytesleft_cc, Rotation::cur());
            let bytesleft_cpu = cells.query_advice(rlc_c_cpu, Rotation::cur());
            let calldataoffset_cpu = cells.query_advice(rlc_e_cpu, Rotation::cur());
            let calldatalength_cpu = cells.query_advice(rlc_h_cpu, Rotation::cur());
            let rwc_adder = Expression::Constant(F::from(7u64));

            vec![
                (
                    gate_cpu.clone() * one.clone(),
                    gate_cc.clone() * isfirst_cc.clone(),
                ),
                (
                    gate_cpu.clone() * (rwc_cpu.clone() + rwc_adder.clone()),
                    gate_cc.clone() * rwc_cc.clone(),
                ),
                (
                    gate_cpu.clone() * address_write_cpu.clone(),
                    gate_cc.clone() * address_write_cc.clone(),
                ),
                (
                    gate_cpu.clone() * address_read_cpu.clone(),
                    gate_cc.clone() * address_read_cc.clone(),
                ),
                (
                    gate_cpu.clone() * (calldatalength_cpu.clone()),
                    gate_cc.clone() * address_end_cc.clone(),
                ),
                (
                    gate_cpu.clone() * zero.clone(),
                    gate_cc.clone() * ismem_cc.clone(),
                ),
                (
                    gate_cpu.clone() * one.clone(),
                    gate_cc.clone() * istx_cc.clone(),
                ),
                (
                    gate_cpu.clone() * call_id_cpu.clone(),
                    gate_cc.clone() * call_id_read_cc.clone(),
                ),
                (
                    gate_cpu.clone() * call_id_cpu.clone(),
                    gate_cc.clone() * call_id_write_cc.clone(),
                ),
                (
                    gate_cpu.clone() * bytesleft_cpu.clone(),
                    gate_cc.clone() * bytesleft_cc.clone(),
                ),
            ]
        });
        meta.lookup_any("cpu to rt, isend", |cells| {
            let gate =
                cells.query_advice(isendtx_cpu, Rotation::cur()) * cells.query_selector(q_cpu);
            let q_rt = cells.query_selector(q_rt);
            let rwc_rt = cells.query_advice(rw_counter_rt, Rotation::cur());
            let one = Expression::Constant(F::ONE);
            let rwc_cpu = cells.query_advice(rw_counter_cpu, Rotation::cur());
            let isend = cells.query_advice(isend_rt, Rotation::cur());
            vec![
                (
                    gate.clone() * rwc_cpu.clone(),
                    q_rt.clone() * rwc_rt.clone(),
                ),
                (gate.clone() * one.clone(), q_rt.clone() * isend),
            ]
        });
        EVM_config {
            _ph: PhantomData,
            challenge_r: rc,
            challenge_b: bc,
            isfirst_cpu,
            islast_cpu,
            q_cpu,
            call_id_cpu,
            clk_cpu,
            rw_counter_cpu,
            pc_cpu,
            opcode_cpu,
            rlc_a_cpu,
            rlc_b_cpu,
            rlc_c_cpu,
            rlc_d_cpu,
            rlc_e_cpu,
            rlc_f_cpu,
            rlc_g_cpu,
            rlc_h_cpu,
            rlc_i_cpu,
            rlc_j_cpu,
            memaddr_cpu,
            inv_cpu,
            mmax_cpu,
            ismaxchanged_cpu,
            isbegintx_cpu,
            isendtx_cpu,
            iscall_cpu,
            isreturn_cpu,
            returndatacopy_cpu,
            calldatacopy_cpu,
            isadd_cpu,
            issub_cpu,
            ismul_cpu,
            isdiv_cpu,
            islt_cpu,
            iseq_cpu,
            isand_cpu,
            isor_cpu,
            isxor_cpu,
            isnot_cpu,
            isjump_cpu,
            isjumpdest_cpu,
            isjumpcon_cpu,
            ismload_cpu,
            ismstore_cpu,
            ismstore8_cpu,
            isread_cpu,
            iswrite_cpu,
            ishalt_cpu,
            rlc_addr_a_cpu,
            rlc_addr_b_cpu,
            sp_cpu,

            q_rt,
            isfirst_rt,
            tag_rt,
            call_id_rt,
            address_rt,
            field_tag_rt,
            storage_key_rt,
            rw_counter_rt,
            iswrite_rt,
            value_rt,
            isend_rt,
            z_rt,

            q_rs,
            isfirst_rs,
            tag_rs,
            call_id_rs,
            isroot_rs,
            address_rs,
            field_tag_rs,
            storage_key_rs,
            rw_counter_rs,
            tag_changed_rs,
            call_id_changed_rs,
            address_changed_rs,
            field_tag_changed_rs,
            storage_key_changed_rs,
            rw_counter_changed_rs,
            iswrite_rs,
            value_rs,
            isend_rs,
            z_rs,
            limb_1_rs,
            limb_2_rs,
            limb_3_rs,
            limb_4_rs,
            limb_5_rs,
            limb_6_rs,
            limb_7_rs,
            limb_8_rs,
            limb_9_rs,
            limb_10_rs,

            q_alu,
            isfirst_alu,
            islast_alu,
            byte32_alu,
            isfirst32_alu,
            islast32_alu,
            limbnumber_alu,
            isadd_alu,
            ismul_alu,
            isdiv_alu,
            islt_alu,
            iseq_alu,
            isand_alu,
            isor_alu,
            isxor_alu,
            isnot_alu,
            barlt_alu,
            carry_alu,
            rem_alu,
            limb_a_alu,
            limb_b_alu,
            limb_c_alu,
            pac_a,
            pac_b,
            pac_c,
            pac_carry,
            pac_rem,
            pac_diff,
            rlc_a_alu,
            rlc_b_alu,
            rlc_c_alu,
            noname_alu,

            q_cc,
            switch_cc,
            isfirst_fixed_cc,
            isfirst_cc,
            islast_cc,
            rwc_cc,
            address_write_cc,
            address_read_cc,
            address_end_cc,
            iswrite_cc,
            ismem_cc,
            istx_cc,
            callid_read_cc,
            callid_write_cc,
            bytesleft_cc,
            value_cc,
            ispad_cc,
            inv_cc,
            limb_1_cc,
            limb_2_cc,

            q_byte,
            q_byte_step,
            q_byte_first,
            q_byte_last,
            byte_active,
            call_id_bytetable,

            pc_bytetable,
            limb1_bytetable,
            limb2_bytetable,
            limb3_bytetable,
            limb4_bytetable,
            iscode_bytetable,

            active_tx,
            txid_tx,
            tag_tx,
            index_tx,
            value_low_tx,
            value_high_tx,

            active_output,
            tag_output,
            address_output,
            iswrite_output,
            value_0_output,
            value_1_output,
            value_2_output,
            value_3_output,
            rw_counter_output,

            byte_rom,
            begintx_rom,
            endtx_rom,
            iscall_rom,
            isreturn_rom,
            returndatacopy_rom,
            calldatacopy_rom,
            isadd_rom,
            issub_rom,
            ismul_rom,
            isdiv_rom,
            islt_rom,
            iseq_rom,
            isand_rom,
            isor_rom,
            isxor_rom,
            isnot_rom,
            isjump_rom,
            isjumpdest_rom,
            isjumpcon_rom,
            ismload_rom,
            ismstore_rom,
            ismstore8_rom,
            isread_rom,
            iswrite_rom,
            ishalt_rom,

            range0,
            range8,

            pac_a_and,
            pac_b_and,
            pac_c_and,

            pac_a_or,
            pac_b_or,
            pac_c_or,

            pac_a_xor,
            pac_b_xor,
            pac_c_xor,

            pac_a_not,
            pac_b_not,
            pac_c_not,

            cpu_chip,
            rwtrace_chip,
            rwstate_chip,
            alu_chip,
            copytool_chip,
            rom_chip,
            byte_chip,
            tx_chip,
            output_chip,
            range0_chip,
            range8_chip,
            range_and_chip,
            range_or_chip,
            range_xor_chip,
            range_not_chip,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let challenge_r_value = layouter.get_challenge(config.challenge_r);

        let challenge_b_value = layouter.get_challenge(config.challenge_b);

        config.rom_chip.load_rom_table(&mut layouter, &self.rom)?;

        config.byte_chip.assign(&mut layouter, &self.bytetable)?;

        config
            .range0_chip
            .load_range_table(&mut layouter, 65535 as u64)?;

        config
            .range8_chip
            .load_range_table(&mut layouter, 255 as u64)?;
        config
            .range_and_chip
            .load_bitwise_table(&mut layouter, |a, b| a & b)?;
        config
            .range_or_chip
            .load_bitwise_table(&mut layouter, |a, b| a | b)?;
        config
            .range_xor_chip
            .load_bitwise_table(&mut layouter, |a, b| a ^ b)?;

        config.range_not_chip.load_not_table(&mut layouter)?;

        config.tx_chip.assign(&mut layouter, &self.txtrace)?;

        config.output_chip.assign(&mut layouter, &self.output)?;

        config
            .cpu_chip
            .assign(&mut layouter, &self.cpu, challenge_r_value.clone())?;

        config
            .alu_chip
            .assign(&mut layouter, &self.alu, challenge_r_value.clone())?;

        config.copytool_chip.assign(&mut layouter, &self.copytool)?;

        let z_trace_last = config.rwtrace_chip.assign(
            &mut layouter,
            &self.rwtrace,
            challenge_r_value.clone(),
            challenge_b_value.clone(),
        )?;

        let z_state_last = config.rwstate_chip.assign(
            &mut layouter,
            &self.rwstate,
            challenge_r_value.clone(),
            challenge_b_value.clone(),
        )?;

        layouter.assign_region(
            || "constrain rw z equality",
            |mut region| region.constrain_equal(z_trace_last.cell(), z_state_last),
        )?;

        Ok(())
    }
}
