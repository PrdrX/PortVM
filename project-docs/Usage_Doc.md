# PortVM AI-Agent Operating Guide

This document is meant to be given directly to an AI coding agent that has no prior PortVM context. It explains how to prepare a valid program, generate and check a witness, create keys and proofs, verify a proof, and reason about the project without silently assuming ordinary EVM behavior.

The instructions describe the repository state in which this file is stored. When code and this document disagree, treat the Rust source as authoritative and report the discrepancy before changing either one.

## Contents

- [1. What PortVM is](#1-what-portvm-is)
- [2. Repository map](#2-repository-map)
- [3. First-time setup and build](#3-first-time-setup-and-build)
- [4. Compact input format](#4-compact-input-format)
  - [4.1 Minimal valid input](#41-minimal-valid-input)
  - [4.2 Byte Table derivation](#42-byte-table-derivation)
  - [4.3 Logical call IDs](#43-logical-call-ids)
  - [4.4 TX Table tags](#44-tx-table-tags)
- [5. Program lifecycle and stack model](#5-program-lifecycle-and-stack-model)
- [6. Supported opcodes](#6-supported-opcodes)
  - [6.1 Operand-order examples](#61-operand-order-examples)
  - [6.2 CALL operands and call IDs](#62-call-operands-and-call-ids)
  - [6.3 RETURN operands](#63-return-operands)
  - [6.4 CALLDATACOPY operands and source](#64-calldatacopy-operands-and-source)
  - [6.5 RETURNDATACOPY operands and source](#65-returndatacopy-operands-and-source)
  - [6.6 Complete CALL/RETURN example](#66-complete-callreturn-example)
- [7. What the witness generator derives](#7-what-the-witness-generator-derives)
- [8. Circuit size and capacity](#8-circuit-size-and-capacity)
- [9. Executable reference](#9-executable-reference)
  - [9.1 `witness_gen`](#91-witness_gen-compact-input---complete-witness)
  - [9.2 `mockprover`: compact input](#92-mockprover-validate-compact-input-directly)
  - [9.3 `mockprover`: serialized witness](#93-mockprover-validate-a-serialized-witness)
  - [9.4 `vk_harness`](#94-vk_harness-generate-a-verification-key)
  - [9.5 `pk_harness`](#95-pk_harness-generate-a-proving-key)
  - [9.6–9.9 `prove`](#96-prove-compact-input-with-existing-params-and-pk)
  - [9.10 `verify`](#910-verify-a-real-proof)
- [10. Artifact meanings and compatibility](#10-artifact-meanings-and-compatibility)
- [11. Recommended AI-agent workflows](#11-recommended-ai-agent-workflows)
  - [11.1 Validate a user program](#111-validate-a-user-program)
  - [11.2 Produce a reusable checked witness](#112-produce-a-reusable-checked-witness)
  - [11.3 Produce and verify a real proof](#113-produce-and-verify-a-real-proofonly-if-user-explicitly-asked-you-to-do-that)
  - [11.4 Diagnose a failure](#114-diagnose-a-failure)
- [12. Rust library API for integrations](#12-rust-library-api-for-integrations)
- [13. Known limitations and unsupported behavior](#13-known-limitations-and-unsupported-behavior)
- [14. Security and operating rules for an AI agent](#14-security-and-operating-rules-for-an-ai-agent)
- [15. Final checklist](#15-final-checklist)

## 1. What PortVM is

PortVM is a fixed-shape Halo2 circuit plus an execution core and witness generator. A user supplies two compact public tables:

- a Byte Table containing programs, grouped by logical call ID;
- a TX Table containing root-transaction metadata and calldata.

The execution core interprets those public rows. The witness generator derives the private CPU, ALU, memory/copy, RWTrace, RWState, and call-context rows. It also derives the public instance columns. The same generated witness can then be checked by Halo2's `MockProver` or used by the real KZG prover.

The processing pipeline is:

```text
compact text input
    -> text parser
    -> public Byte/TX rows
    -> execution core
    -> logical execution trace
    -> circuit-row lowering and padding
    -> full witness.bin + public instance columns
    -> MockProver OR real prover
    -> proof.bin + instances.bin
    -> verifier
```

Important: this is a learning VM inspired by zkEVM designs. It is not Ethereum-compatible, production-audited, or safe for real assets.

## 2. Repository map

The important files are:

| Path | Purpose |
|---|---|
| `src/main.rs` | The Halo2 circuit, chips, constraints, lookups, assignments, key generation, and proof verification helpers. Despite its name, this is a library module, not a CLI entry point. |
| `src/execution_core.rs` | Executes compact programs and produces logical CPU, arithmetic, memory, copy, call-context, and RW events. |
| `src/witness_generation.rs` | Lowers execution events into all circuit rows, pads fixed shapes, serializes witnesses/instances, runs MockProver, and creates proofs. |
| `src/input.rs` | Parses the two-section compact text input. |
| `src/lib.rs` | Exposes the modules to the binaries. |
| `src/vk_harness.rs` | CLI for verification-key generation. |
| `src/pk_harness.rs` | CLI for proving-key generation. |
| `src/witness_gen.rs` | CLI for compact input -> complete witness file. |
| `src/mockprover.rs` | CLI for checking compact input or a saved witness. |
| `src/prove.rs` | CLI for generating a real proof, optionally generating keys first. |
| `src/verify.rs` | CLI for verifying a real proof. |
| `testdata/correct_mock_test_input.txt` | Minimal valid root execution. |
| `testdata/call_return_coverage_input.txt` | Valid CALL/child/MSTORE8/RETURN example. |
| `project-docs/` | Design notes and diagrams. These are supporting material; source code remains authoritative. |

`Cargo.toml` has `autobins = false` and explicitly declares six binaries. Adding a Rust file to `src/` does not automatically make it an executable.

## 3. First-time setup and build

Prerequisites:

- a Rust toolchain with Cargo;
- Git/network access for the pinned Halo2 Git dependency;
- enough memory for a `k = 17` circuit.

From the repository root:

```bash
cargo check --all-targets
cargo test --lib
cargo build --release --bins
mkdir -p artifacts
```

The optimized executables are then in `target/release/`:

```text
target/release/vk_harness
target/release/pk_harness
target/release/witness_gen
target/release/mockprover
target/release/prove
target/release/verify
```

During development, a binary can also be compiled and run in one command:

```bash
cargo run --release --bin mockprover -- --k 17 --input testdata/correct_mock_test_input.txt
```

The second `--` separates Cargo's options from the PortVM executable's options.

Use `--help` on any binary when uncertain. Use release builds for the large circuit; debug builds are much slower and larger.

## 4. Compact input format

The compact input is plain UTF-8 text with two named sections:

```text
[Byte_Table]
<logical_call_id> <value>

[TX_Table]
<tag> <value>
```

Parser rules:

- section names are case-sensitive and must be exactly `[Byte_Table]` and `[TX_Table]`;
- each data line has exactly two whitespace-separated fields;
- blank lines are ignored;
- text after `#` is a comment;
- IDs and tags are unsigned `u64` values in decimal or `0x`-prefixed hexadecimal;
- values are unsigned 256-bit values in decimal or `0x`-prefixed hexadecimal;
- underscores in numeric literals are accepted;
- hexadecimal values may contain at most 64 hex digits;
- negative values are invalid;
- the current CLIs need both useful Byte Table rows and the required TX metadata, even though the parser itself accepts either section alone.

The user does **not** supply PCs, active flags, `iscode`, TX IDs, TX indexes, or limbs. They are derived automatically.

### 4.1 Minimal valid input

```text
[Byte_Table]
0 0x00
0 0xfe
0 0xff

[TX_Table]
4 0x1111
5 0x2222
7 0
8 0
```

This is also stored in `testdata/correct_mock_test_input.txt`.

### 4.2 Byte Table derivation

For each logical call ID, the parser assigns PCs starting at zero and incrementing by one for every input row. Input must be grouped in ascending logical-call-ID order.

The only instruction with an immediate data row is custom `WRITE` (`0x55`):

```text
0 0x55       # PC x: WRITE opcode; iscode = 1
0 12345      # PC x+1: 256-bit immediate; iscode = 0
```

Every other input row is treated as an opcode row with `iscode = 1`. Consequently:

- every `WRITE` must be followed immediately by exactly one value row;
- that value row is data, not an executable opcode;
- execution advances by two PCs for `WRITE` and by one PC for ordinary sequential instructions;
- if an intended opcode is placed after `WRITE` without an intervening immediate value, the opcode number itself will be pushed as data.

The compact value is split into four little-endian 64-bit limbs internally:

```text
value = limb0 + limb1*2^64 + limb2*2^128 + limb3*2^192
```

Byte Table rows are public circuit inputs. The witness generator also creates a four-row arithmetic ADD chunk `limb + 0 = limb` for each active Byte Table row so the circuit range-constrains the limbs.

### 4.3 Logical call IDs

Logical call IDs are simple user-facing program/execution identifiers:

- root program: `0`;
- child created by the first executed `CALL`: `1`;
- child created by the second executed `CALL`: `2`;
- and so on, globally in actual CALL execution order, including nested calls.

The set must be contiguous: `0, 1, 2, ...`. Do not skip, reorder, or reuse an ID. Group all rows for ID 0 first, then ID 1, and so on.

In compact-text mode, call routing is order-based. The first executed `CALL` runs Byte Table program 1, the second executed `CALL` runs program 2, etc. The callee address is still part of the CALL witness and constraints, but it does not select the child program in this mode.

If the same code should run in two separate calls, duplicate that code under two logical IDs. The richer Rust API supports reusable image IDs and deployment mappings, but the compact text parser intentionally does not expose those sections.

Logical IDs are not the actual IDs used by the circuit. The witness generator maps them automatically:

- logical root ID 0 -> actual circuit call ID 1;
- each child's actual call ID is derived from the RW counter at its CALL site.

Never manually substitute actual call IDs into the compact text file.

### 4.4 TX Table tags

The compact TX parser sets `active = 1` and `txid = 1` for every supplied row. Values are split into two little-endian 128-bit halves for the public TX columns.

Execution currently consumes these tags:

| Tag | Meaning | Rules |
|---:|---|---|
| `1` | Root calldata byte | One byte per row. Values must fit `0..255`. Repeated tag-1 rows receive indexes `0, 1, 2, ...` in input order. |
| `4` | Root caller address | One 256-bit value. |
| `5` | Root callee/contract address | One 256-bit value. |
| `7` | Root transaction value | One 256-bit value. |
| `8` | Declared root calldata length | Must fit `u64`. |

Other tags can be parsed and made public but are ignored by the current execution core.

Tags 4, 5, 7, and 8 must be present as active rows. Provide exactly one tag-1 row for every byte covered by tag 8 and keep tag-1 rows in byte order. If tag 8 declares length `N`, indexes `0..N-1` must all exist; execution rejects the input before witness generation if fewer than `N` calldata rows are supplied. Use an explicit tag-1 value of zero when a calldata byte should be zero.

Example calldata `[0xaa, 0xbb, 0xcc]`:

```text
[TX_Table]
1 0xaa
1 0xbb
1 0xcc
4 0x1111
5 0x2222
7 0
8 3
```

TX rows need not be sorted by tag for parsing, but deterministic tag order is recommended for reviewability.

## 5. Program lifecycle and stack model

Each call frame has its own stack, memory, program counter, memory maximum, and call context.

- A frame starts with an empty stack and no initialized memory addresses.
- `sp` is the next free stack address.
- The top value is at address `sp - 1`.
- `WRITE` pushes one 256-bit value.
- An unwritten memory address is not readable by the circuit. Every byte read by `MLOAD`, CALL calldata, or RETURN must previously have been written in that call frame by `MSTORE`, `MSTORE8`, or a copy operation.
- Memory words use 32 bytes and are encoded in EVM-style big-endian byte order.
- `mmax` is the greatest accessed end offset: highest accessed byte offset plus one. `mmax = 0` means no memory byte has been accessed.

The root program must begin with `BEGIN_TX` (`0x00`) at PC 0. A normal root success path ends with `END_TX` (`0xfe`) followed by `HALT` (`0xff`). `HALT` stops the whole execution engine. Child frames should end with `RETURN` (`0xf3`), not HALT. Root `RETURN` is rejected.

The current circuit supports successful execution paths only. Input errors such as stack underflow are witness-generation errors, not modeled exceptional-halt traces.

## 6. Supported opcodes

These byte meanings are PortVM's current meanings. In particular `0x00`, `0x54`, `0x55`, `0xfe`, and `0xff` are not standard-EVM semantics.

In the table below, “top A, next B” means `A = stack[sp-1]` and `B = stack[sp-2]` before execution.

| Byte | Name | Minimum stack | Behavior | Stack delta |
|---:|---|---:|---|---:|
| `0x00` | `BEGIN_TX` | 0 | Root initialization; reads TX metadata and writes root call context. Must be root PC 0. | 0 |
| `0xfe` | `END_TX` | 0 | Marks the final successful root CPU operation before HALT. | 0 |
| `0xff` | `HALT` | 0 | Stops execution globally. | 0 |
| `0x55` | `WRITE` | 0 | Reads the next Byte Table row as a 256-bit immediate and pushes it. | +1 |
| `0x54` | `READ` | 1 | Pops a symbolic state key and records a state-read event. The current custom operation does not push a read value. | -1 |
| `0x01` | `ADD` | 2 | Replaces B with `(A + B) mod 2^256`; removes A. | -1 |
| `0x03` | `SUB` | 2 | Replaces B with `(A - B) mod 2^256`; removes A. | -1 |
| `0x02` | `MUL` | 2 | Replaces B with `(A * B) mod 2^256`; removes A. Overflow is intentionally truncated modulo `2^256`. | -1 |
| `0x04` | `DIV` | 2 | Replaces B with unsigned `A / B`; removes A. The current circuit cannot support divisor B = 0. | -1 |
| `0x10` | `LT` | 2 | Replaces B with `1` iff unsigned A < B, else `0`; removes A. | -1 |
| `0x14` | `EQ` | 2 | Replaces B with `1` iff A = B, else `0`; removes A. | -1 |
| `0x16` | `AND` | 2 | Replaces B with bitwise `A & B`; removes A. | -1 |
| `0x17` | `OR` | 2 | Replaces B with bitwise `A \| B `; removes A. | -1 |
| `0x18` | `XOR` | 2 | Replaces B with bitwise `A ^ B`; removes A. | -1 |
| `0x19` | `NOT` | 1 | Replaces top with the 256-bit bitwise complement. | 0 |
| `0x56` | `JUMP` | 1 | Pops a `u64` destination and jumps to it. The destination must resolve to a `JUMPDEST` row for a valid circuit witness. | -1 |
| `0x57` | `JUMPCON` | 2 | Top is destination; next is condition. Pops both. Nonzero condition jumps; zero continues at PC+1. | -2 |
| `0x5b` | `JUMPDEST` | 0 | Valid jump target and no-op. | 0 |
| `0x51` | `MLOAD` | 1 | Top is a `u64` memory address. Reads 32 bytes and replaces the address with the word. All 32 addressed bytes must already have been written in the current call frame. | 0 |
| `0x52` | `MSTORE` | 2 | Top is a `u64` address; next is a 256-bit value. Writes 32 bytes. | -2 |
| `0x53` | `MSTORE8` | 2 | Top is a `u64` address; next is a value. Writes only the low byte of the value. | -2 |
| `0x37` | `CALLDATACOPY` | 3 | Top is destination offset, next is source offset, next is length. Copies root TX calldata or child calldata into current memory. | -3 |
| `0x3e` | `RETURNDATACOPY` | 3 | Top is destination offset, next is source offset, next is length. Copies from the most recent child's returned-data area. | -3 |
| `0xf1` | `CALL` | 6 | Creates the next logical child frame. Operand order is detailed below. On successful RETURN, six operands become one success value. | net -5 after return |
| `0xf3` | `RETURN` | 2 | Child only. Top is source-memory offset; next is actual return length. Returns to the parent and may copy data. | terminates child |

Any other opcode produces `UnsupportedOpcode`.

### 6.1 Operand-order examples

Because `WRITE` pushes onto the top, values are usually written in reverse of the top-first descriptions.

To compute `10 - 2`, SUB requires top A = 10 and next B = 2:

```text
0 0x55
0 2
0 0x55
0 10
0 0x03
```

To store value 42 at memory offset 5, MSTORE8 requires top address = 5 and next value = 42:

```text
0 0x55
0 42
0 0x55
0 5
0 0x53
```

To copy 3 calldata bytes from source offset 2 to memory offset 10, push length, then source, then destination:

```text
0 0x55
0 3
0 0x55
0 2
0 0x55
0 10
0 0x37
```

Zero-length `CALLDATACOPY`, `RETURNDATACOPY`, and `RETURN` paths are not currently supported by the circuit. Use a positive length.

### 6.2 CALL operands and call IDs

CALL uses six operands, not the standard EVM seven-operand form. From bottom to top:

```text
value
calldata_length
callee_address
returndata_length
returndata_offset
calldata_offset       <- top
```

Therefore, use six WRITE instructions in that exact listed order before CALL.

CALL behavior:

1. The next unused logical child ID is allocated.
2. In compact mode, that logical ID selects the child's Byte Table program.
3. Child calldata refers to the parent memory range beginning at `calldata_offset` for `calldata_length` bytes. Every byte in a nonempty range must already have been written in the parent frame.
4. The child's stack and memory start empty.
5. The parent frame is suspended.
6. A successful child RETURN resumes the parent at the instruction after CALL.
7. Up to `min(requested_returndata_length, actual_return_length)` bytes are copied into parent memory at `returndata_offset`.
8. The six CALL operands are replaced by success value `1` in their lowest stack slot.

There is currently no failed-CALL execution path exposed by compact input. The generated path assumes success.

### 6.3 RETURN operands

RETURN requires two values:

```text
actual_return_length   <- next
source_memory_offset   <- top
```

Push actual length first, then source offset. RETURN is only valid in a child frame.
Every byte in the returned source range must already have been written in the child frame. Unwritten child memory cannot be returned as implicit zero bytes.

### 6.4 CALLDATACOPY operands and source

CALLDATACOPY uses three operands. From bottom to top:

```text
length
source_offset
destination_offset       <- top
```

Push the length, then the source offset, then the destination offset before executing `CALLDATACOPY`. All three values must fit `u64`; the length must be positive for a supported circuit path. The opcode consumes all three values.

The source depends on the current frame:

- In the root frame, bytes come from the public TX calldata rows (tag 1), starting at `source_offset` index.
- In a child frame, bytes come from the parent frame's memory range assigned to that child's calldata by CALL. Every source byte must have been written in the parent before CALL.

The copied bytes are written into the current frame's memory beginning at `destination_offset`. Those destination addresses are then initialized and can be read later, subject to the normal memory-read rules. For root calldata, supply one public tag-1 row for every byte covered by tag 8 on compact input; missing rows are rejected during witness generation.

Example: copy 3 bytes from source offset 2 to memory offset 10:

```text
0 0x55
0 3                 # length
0 0x55
0 2                 # source offset
0 0x55
0 10                # destination offset
0 0x37
```

### 6.5 RETURNDATACOPY operands and source

RETURNDATACOPY also uses three operands, from bottom to top:

```text
length
source_offset
destination_offset       <- top
```

Push the length, then the source offset, then the destination offset before executing `RETURNDATACOPY`. All three values must fit `u64`; the length must be positive for a supported circuit path. The opcode consumes all three values.

The source is the return-data range produced by the most recent child CALL in the current frame. `source_offset` is relative to the beginning of that returned range. The requested source range must lie within the available returned data; out-of-bounds RETURNDATACOPY is not modeled as a valid exceptional-halt path and will successfully be padded with 0. The copied bytes are written to current-frame memory beginning at `destination_offset`, where they can be read later.

Example: copy 3 returned bytes from source offset 0 to memory offset 10:

```text
0 0x55
0 3                 # length
0 0x55
0 0                 # source offset within returned data
0 0x55
0 10                # destination offset
0 0x3e
```

### 6.6 Complete CALL/RETURN example

The tested example is `testdata/call_return_coverage_input.txt`. Its root program:

- begins the transaction;
- pushes CALL operands with zero calldata, callee `0xdeadbeef`, and one requested return byte at parent memory offset 0;
- executes CALL;
- ends and halts.

Logical child 1 stores byte 42 at child memory offset 0 and returns one byte from offset 0.

The complete compact input is:

```text
[Byte_Table]
# Root: BEGIN_TX
0 0x00
# CALL operands, pushed bottom-to-top:
# value=0, calldata_length=0, callee=0xdeadbeef,
# returndata_length=1, returndata_offset=0, calldata_offset=0
0 0x55
0 0
0 0x55
0 0
0 0x55
0 0xdeadbeef
0 0x55
0 1
0 0x55
0 0
0 0x55
0 0
0 0xf1
0 0xfe
0 0xff

# Child 1: MSTORE8(value=42, address=0), RETURN(length=1, source=0)
1 0x55
1 42
1 0x55
1 0
1 0x53
1 0x55
1 1
1 0x55
1 0
1 0xf3

[TX_Table]
4 0x1111
5 0x2222
7 0
8 0
```

Run it with:

```bash
target/release/mockprover --k 17 --input testdata/call_return_coverage_input.txt
```

## 7. What the witness generator derives

From compact public input, the generator derives:

- all CPU rows and opcode selectors;
- all ALU arithmetic, comparison, bitwise, and memory chunks;
- Byte Table limb range-check ADD chunks;
- stack, memory, call-context, and symbolic state RW events;
- RWTrace sorted by RW counter;
- RWState sorted by its state key;
- copy rows for calldata, returndata, and RETURN;
- logical-to-actual call-ID mapping;
- fixed-shape padding and boundary/guard rows;
- public Byte Table, TX Table, and root-output instance columns.

The output public table contains all root-call stack and memory RWState rows selected by the circuit, including read/write history. It is not merely a snapshot of final stack and memory.

There are 23 public instance columns:

- 8 Byte Table columns: active, call ID, PC, four value limbs, `iscode`;
- 6 TX columns: active, txid, tag, index, value-low, value-high;
- 9 output columns: active, tag, address, iswrite, four value limbs, RW counter.

## 8. Circuit size and capacity

Use `k = 17` for normal PortVM operations. The circuit domain has `2^17 = 131072` rows. The CLIs reject `k < 17`: the fixed 16-bit/bitwise tables and fixed-column chip assignments do not fit in smaller domains. Values above 17 create a different, larger circuit domain and require matching parameters and keys.

Current important fixed shapes:

| Area | Shape/capacity |
|---|---:|
| CPU active rows | 10,000 plus guard row |
| ALU active rows | 49,984 |
| ALU reserved meaningful tail | final 32 rows are unavailable to logical operations |
| CopyTool active rows | 50,000 plus 2 tail guards |
| RWTrace active rows | 50,000 plus guard |
| RWState active rows | 50,000 plus head/tail guards |
| Public Byte Table | 4,096 circuit rows; at most 4,095 compact user rows because generation reserves one row for a dummy HALT |
| Public TX Table | 256 rows |
| Public output | 50,000 rows |

Capacity is shared and opcode-dependent:

- each arithmetic operation normally consumes a four-row ALU chunk;
- each memory operation consumes a 32-row ALU chunk;
- Byte Table range checking consumes one four-row ADD chunk per active Byte Table row;
- comparisons/division can require helper chunks;
- arithmetic-to-memory alignment and deterministic padding consume additional rows;
- copy operations consume rows proportional to copied length.

Do not estimate capacity solely from constants named `MAX_*` near the beginning of `src/main.rs`; some are stale/default-vector limits while actual chip assignment loops use the fixed shapes listed above. Let witness generation report capacity errors.

## 9. Executable reference

All examples below assume `cargo build --release --bins` has completed and commands run from the repository root.

### 9.1 `witness_gen`: compact input -> complete witness

```bash
target/release/witness_gen \
  --input testdata/correct_mock_test_input.txt \
  --out artifacts/program.witness.bin
```

This parses and executes the compact input and serializes the full circuit witness. It does not run MockProver and does not create a real proof.

### 9.2 `mockprover`: validate compact input directly

```bash
target/release/mockprover \
  --k 17 \
  --input testdata/correct_mock_test_input.txt
```

This generates a full witness in memory, runs Halo2 MockProver, and reports whether all gates, lookups, permutations, and public-instance constraints pass.

### 9.3 `mockprover`: validate a serialized witness

```bash
target/release/mockprover \
  --k 17 \
  --witness artifacts/program.witness.bin
```

Choose exactly one of `--input` and `--witness`.

MockProver acceptance is the primary local correctness precheck, but it is not a cryptographic proof and is not an audit.

### 9.4 `vk_harness`: generate a verification key

Using an existing KZG parameter file:

```bash
target/release/vk_harness \
  --k 17 \
  --params artifacts/params.bin \
  --out artifacts/vk.bin
```

Creating local random KZG parameters and a VK:

```bash
target/release/vk_harness \
  --k 17 \
  --unsafe-local-setup \
  --params-out artifacts/params.bin \
  --out artifacts/vk.bin
```

Choose exactly one setup mode. Local setup is explicitly unsafe for production trust assumptions: SRS generation uses secret randomness inside the process, and no multiparty ceremony establishes that the toxic setup secret was discarded. The serialized parameter file is normally public; it is the setup trust assumption that is unsafe. This mode is appropriate for development, testing, and portfolio demonstrations.

The VK depends on circuit shape and `k`, not on a particular witness.

### 9.5 `pk_harness`: generate a proving key

```bash
target/release/pk_harness \
  --k 17 \
  --params artifacts/params.bin \
  --vk artifacts/vk.bin \
  --out artifacts/pk.bin
```

The params and VK must both have the requested `k`. A PK is larger and more expensive to generate than a VK.

### 9.6 `prove`: compact input with existing params and PK

```bash
target/release/prove \
  --k 17 \
  --params artifacts/params.bin \
  --pk artifacts/pk.bin \
  --input testdata/correct_mock_test_input.txt \
  --witness-out artifacts/program.witness.bin \
  --proof-out artifacts/proof.bin \
  --instances-out artifacts/instances.bin \
  --mock-precheck
```

When `--input` is used, `--witness-out` is required. `--mock-precheck` is optional but strongly recommended before spending resources on proving.

### 9.7 `prove`: saved witness with existing params and PK

```bash
target/release/prove \
  --k 17 \
  --params artifacts/params.bin \
  --pk artifacts/pk.bin \
  --witness artifacts/program.witness.bin \
  --proof-out artifacts/proof.bin \
  --instances-out artifacts/instances.bin \
  --mock-precheck
```

Do not pass `--witness-out` when `--witness` already supplies a serialized witness.

### 9.8 `prove`: compact input and locally generate every key artifact

```bash
target/release/prove \
  --k 17 \
  --input testdata/correct_mock_test_input.txt \
  --witness-out artifacts/program.witness.bin \
  --params-out artifacts/params.bin \
  --vk-out artifacts/vk.bin \
  --pk-out artifacts/pk.bin \
  --proof-out artifacts/proof.bin \
  --instances-out artifacts/instances.bin \
  --mock-precheck
```

This is the wall-to-wall local-development mode. It performs expensive parameter setup, VK generation, PK generation, and proof generation in one run.

### 9.9 `prove`: saved witness and locally generate every key artifact

```bash
target/release/prove \
  --k 17 \
  --witness artifacts/program.witness.bin \
  --params-out artifacts/params.bin \
  --vk-out artifacts/vk.bin \
  --pk-out artifacts/pk.bin \
  --proof-out artifacts/proof.bin \
  --instances-out artifacts/instances.bin \
  --mock-precheck
```

Prover argument rules:

- choose exactly one of `--input` or `--witness`;
- existing-key mode requires both `--params` and `--pk`;
- local-setup mode requires all of `--params-out`, `--vk-out`, and `--pk-out`;
- do not mix existing-key options with local-output key options;
- `--proof-out` and `--instances-out` are always required;
- real proving is resource-intensive; do not launch it casually on a constrained machine.

### 9.10 `verify`: verify a real proof

```bash
target/release/verify \
  --k 17 \
  --params artifacts/params.bin \
  --vk artifacts/vk.bin \
  --proof artifacts/proof.bin \
  --instances artifacts/instances.bin
```

Verification needs the exact matching parameter set, VK, proof, and public instances. It does not need the private witness or PK.

## 10. Artifact meanings and compatibility

| Artifact | Contains | Secret? | Used by |
|---|---|---|---|
| compact input `.txt` | Public Byte/TX input | No | witness generator, MockProver, prover |
| `witness.bin` | Complete private circuit witness, public inputs, logical/actual call map | Treat as private | MockProver, prover |
| `params.bin` | KZG structured reference string for one `k` | Normally public; setup randomness/trust matters | VK/PK generation, prover, verifier |
| `vk.bin` | Verification key for circuit shape and `k` | Public | PK generation, verifier |
| `pk.bin` | Proving key for circuit shape, params, and `k` | Usually prover-side | prover |
| `proof.bin` | Cryptographic proof | Public | verifier |
| `instances.bin` | Serialized public instance columns | Public | verifier |

Serialization markers:

- witness format: magic `PORTWIT1`, version 1;
- public-instance format: magic `PORTINS1`, version 1.

Proof configuration:

- curve/commitment: BN256 KZG;
- multi-opening: SHPLONK;
- transcript: Blake2b with `Challenge255`;
- proof randomness: generated internally with OS randomness.

All artifacts in one proof flow must agree on `k = 17`, circuit shape, serialization format, and parameter set. A circuit-column, gate, lookup, selector, fixed-shape, or instance-layout change invalidates old VKs, PKs, and proofs. A witness-generator change requires regenerating witnesses; if circuit shape is unchanged, keys may remain structurally compatible, but re-run MockProver before reuse.

Do not commit witness files containing sensitive execution data. Do not assume a locally generated SRS has production-grade ceremony security.

## 11. Recommended AI-agent workflows

### 11.1 Validate a user program

1. Read this guide and the supplied compact input.
2. Simulate stack depth and control flow for every reachable opcode.
3. Verify root starts with BEGIN_TX and reaches END_TX then HALT.
4. Verify each WRITE has exactly one following immediate row.
5. Verify logical IDs are contiguous and agree with dynamic CALL order.
6. Verify every CALL has a corresponding child program and every child returns.
7. Verify TX tags 4, 5, 7, and 8 exist and tag-1 bytes match the declared calldata intent.
8. Build if needed.
9. Run `mockprover --k 17 --input ...`.
10. Report the exact command and result. Do not claim validity merely because witness generation succeeded.

### 11.2 Produce a reusable checked witness

```bash
target/release/witness_gen --input INPUT.txt --out WITNESS.bin
target/release/mockprover --k 17 --witness WITNESS.bin
```

Keep both steps. `witness_gen` alone does not prove constraint satisfaction.

### 11.3 Produce and verify a real proof(ONLY IF USER EXPLICITLY ASKED YOU TO DO THAT)

1. Mock-check the compact input or witness first.
2. Prefer pre-generated matching params/VK/PK when available.
3. Run the prover in release mode on appropriately sized hardware.
4. Preserve `proof.bin` and `instances.bin` together.
5. Run `verify` independently using the matching params and VK.
6. Report file sizes and hashes if artifacts cross machine boundaries.

### 11.4 Diagnose a failure

Classify the stage before changing code:

| Error prefix/stage | Likely source |
|---|---|
| `input parsing failed` | Bad section name, wrong field count, invalid number, duplicate section. |
| `witness generation failed` | Unsupported opcode, stack underflow, invalid call IDs/routing, missing TX metadata, bad immediate, capacity, unsupported semantics. |
| `MockProver rejected` | Generated rows do not satisfy a gate, lookup, permutation, or public-instance constraint. |
| params/VK/PK `k mismatch` | Artifacts were generated for another domain size. |
| invalid magic/version | Wrong artifact type, corruption, or unsupported serialization version. |
| proof verification failure | Mismatched params/VK/instances/proof, changed data, or invalid proof. |

When MockProver reports a constraint or lookup failure:

- preserve the exact input and command;
- reduce to the smallest reproducer while keeping required BEGIN/END/HALT and TX rows;
- identify whether execution semantics, lowering, padding, or circuit constraints disagree;
- do not “fix” a witness by weakening the circuit;
- do not alter `src/main.rs` unless the task explicitly authorizes circuit changes;
- re-run existing regression examples after any generator change.

## 12. Rust library API for integrations

The CLI is the stable starting point. Rust callers can use lower-level APIs exposed through `portvm::main` and `portvm::input`:

- `parse_public_tables_text` / `parse_public_tables_file`;
- `execute_from_public_inputs` / `execute_from_tables`;
- `lower_witness_from_public_inputs` / `lower_witness_from_tables`;
- `generate_witness_from_public_inputs` / `generate_witness_from_tables`;
- `mock_prove_from_public_inputs` / `mock_prove_from_tables`;
- `GeneratedWitness::write_to_file` / `read_from_file` / `mock_verify`;
- `GeneratedWitness::prove_with_existing_key_files`;
- `GeneratedWitness::prove_with_local_setup`;
- `generate_vk_with_local_setup` / `generate_vk_from_params_file`;
- `generate_pk_from_files`;
- `verify_proof_from_files`.

`*_with_hints` variants and image/deployment structures support richer program routing from Rust. They are not represented by the compact two-section text format. An agent should not introduce these advanced APIs into a basic CLI workflow unless reusable bytecode images or address-based routing are explicitly requested.

`ExecutionInput::with_max_steps(n)` is an optional interpreter safety limit for Rust callers. The compact CLI path does not set a step limit. A program with an infinite jump loop can therefore run indefinitely until externally interrupted or until another failure occurs. Validate control flow before executing untrusted compact input.

## 13. Known limitations and unsupported behavior

An AI agent must disclose these when they matter:

1. **Success paths only.** There is no complete STOP, REVERT, failed CALL, exceptional halt, or state rollback model.
2. **No gas system.** Out-of-gas and gas-dependent EVM behavior do not exist.
3. **Custom instruction set.** Several byte values deliberately differ from Ethereum.
4. **Partial EVM semantics.** There is no complete account/storage/world-state model, transaction validation, logs, create, selfdestruct, precompiles, or broad opcode set.
5. **DIV by zero is unsupported.** The execution helper can calculate zero, but current circuit lowering cannot produce a valid DIV-by-zero proof.
6. **Zero-length copy/return paths are unsupported.** The current circuit expects positive logical copy lengths for CALLDATACOPY, RETURNDATACOPY, and RETURN.
7. **Exceptional copy bounds are not modeled.** RETURNDATACOPY behavior outside available returned data is not a faithful Ethereum exceptional halt.
8. **Stack faults are generator errors.** Stack underflow is rejected before proving. The EVM 1024-item stack limit is not comprehensively enforced as an exceptional path.
9. **Invalid jumps/opcodes are errors, not proved exceptional traces.**
10. **Address and length narrowing.** Memory/copy offsets and lengths used by execution must fit `u64`.
11. **Unwritten memory is unreadable.** PortVM does not provide EVM-style implicit zero reads from untouched memory. Every source byte consumed by `MLOAD`, CALL calldata, or RETURN must have a prior write in the same call frame.
12. **Compact call routing is order-based.** The text interface does not prove a deployment registry mapping an address to reusable code. Advanced image/deployment routing is off the compact path.
13. **No explicit call-depth limit.** Capacity eventually limits execution, but there is no Ethereum-style depth constraint. Deep recursion can consume CPU/RW rows or fail host execution.
14. **Fixed capacities.** Long execution, large public tables, large copies, or too many ALU/RW rows fail generation or synthesis.
15. **ALU tail reservation.** The final 32 ALU active rows are guard/reserved rows and cannot host a logical operation chunk.
16. **Public output is RW history.** Root memory/stack output exposes selected root RWState rows, not only a canonical final-state snapshot.
17. **No production audit or formal equivalence proof.** Passing tests and MockProver does not establish soundness, completeness, Ethereum equivalence, or security.
18. **Real prover path is expensive and less exercised locally.** The proof and verifier binaries compile, but real proving was intentionally not used as a routine local test because of hardware cost.


## 14. Security and operating rules for an AI agent

- Never claim Ethereum compatibility.
- Never claim a proof was created unless the real `prove` command completed and `verify` accepted it.
- Never call MockProver output a cryptographic proof.
- Never treat `witness.bin` as public by default.
- Never mix artifacts from different circuit commits, `k` values, or parameter sets.
- Never start real proof generation merely to “test” a change unless the user authorizes the resource use.
- Prefer `cargo check`, unit tests, and MockProver before real proving.
- Do not silently modify the circuit to make malformed input pass.
- Preserve a failing compact input as a regression test before fixing generator logic.
- For circuit changes, regenerate VK, PK, proof, and instances.
- For input/witness changes, regenerate the witness, proof, and instances.
- Use `k = 17` unless the source shape is intentionally redesigned and fully revalidated.
- Treat unsafe local setup as development-only unless the trust model is explicitly accepted.

## 15. Final checklist

Before telling a user that their PortVM input is ready:

- [ ] Byte and TX sections parse.
- [ ] Logical IDs are contiguous from zero and grouped.
- [ ] Root PC 0 is BEGIN_TX.
- [ ] Every WRITE has exactly one 256-bit immediate row.
- [ ] Stack preconditions hold along every executed path.
- [ ] Operand ordering is correct, especially SUB, DIV, LT, copies, CALL, and RETURN.
- [ ] Every taken jump reaches JUMPDEST.
- [ ] Every CALL has the next logical child program.
- [ ] Child frames RETURN; root executes END_TX then HALT.
- [ ] Required TX tags exist, and tag 8 does not declare more calldata bytes than the supplied tag-1 rows.
- [ ] Values used as bytes fit 8 bits; offsets/lengths fit `u64`.
- [ ] Every memory byte read by MLOAD, CALL calldata, or RETURN has a prior write in the same call frame.
- [ ] DIV divisor is nonzero and copy/return lengths are positive.
- [ ] Witness generation succeeds within fixed capacities.
- [ ] Full `k = 17` MockProver accepts the witness.
- [ ] If a real proof is requested, matching params/keys are used and independent verification succeeds.

If any item is uncertain, report the uncertainty with the exact source location or failing command instead of inventing a witness value.
