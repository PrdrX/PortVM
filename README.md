> PK and Proof generation executables are carefully developed, but due to hardware limitation they haven't been tested yet. So considering that, and considering the fact that this project doesn't have any real world impact and it aims to be a portfolio, generating a proof has no point other than making sure the circuit is valid, which is also achievable through MockProver, which is much cheaper and has already been tested.
# PortVM

PortVM is a stack based Halo2 ZKVM that implements a custom, EVM like execution model. It accepts compact input program, executes the program, generates the complete circuit witness, and supports MockProver validation, key generation, real proof generation, and proof verification.

## Table of Contents

- [Highlights](#highlights)
- [Execution Flow](#execution-flow)
- [Supported Opcodes](#supported-opcodes)
- [Requirements](#requirements)
- [Quick Start](#quick-start)
- [Compact Public Input](#compact-public-input)
- [Command-Line Tools](#command-line-tools)
- [Common Workflows](#common-workflows)
  - [Generate and MockProve a Reusable Witness](#generate-and-mockprove-a-reusable-witness)
  - [Generate Development Keys](#generate-development-keys)
  - [Generate a Proof with Existing Keys](#generate-a-proof-with-existing-keys)
  - [Verify a Proof](#verify-a-proof)
- [Artifacts and Compatibility](#artifacts-and-compatibility)
- [Documentation](#documentation)
- [Acknowledgements](#acknowledgements)
- [License](#license)

## Highlights

- CPU, ALU, RW, Copy, ByteTable, TxTable and Output chips.
- Stack, memory, call contexts, nested calls, and dynamic copy operations.
- Public ByteTable and TxTable as inputs.
- Automatic generation of CPU, ALU, RWTrace, RWState, CopyTool, and Output witnesses out of ByteTable and TxTable.
- Command line tools for witness generation, MockProver, VK/PK generation, proving, and verification.
- BN256 KZG commitments, SHPLONK multi-opening, and a Blake2b transcript.

## Execution flow

```text
Compact input => Public ByteTable + TxTable input => Parser and execution core => VM witness => Mockprover or Proof Generation
```

The main circuit components are:

| Component | Responsibility |
|---|---|
| ByteTable | Public program bytes, PCs, call IDs, and 256 bit values |
| TxTable | Public root call related information |
| CPU | Opcode initiator and flow manager |
| ALU | Arithmetic constrains and memory handler |
| RWTrace / RWState | Stack, memory, and call context recorder |
| CopyTool | Dynamic copies |
| ROM / StaticTables | Opcode metadata, range checks, and bit wise logical operations |
| Output | Public root call stack and memory RW rows |


## Supported opcodes

PortVM uses a custom implemented opcodes inspired by the EVM.

| Category | Opcodes |
|---|---|
| Stack | `READ` (`POP`), `WRITE` (`PUSH32`) |
| Control flow | `JUMP`, `JUMPCON` (`JUMPI`), `JUMPDEST`, `HALT` |
| Arithmetic and comparison | `ADD`, `SUB`, `MUL`, `DIV`, `LT`, `EQ` |
| Bitwise | `AND`, `OR`, `XOR`, `NOT` |
| Memory | `MSTORE`, `MSTORE8`, `MLOAD` |
| Calls and copying | `CALL`, `RETURN`, `CALLDATACOPY`, `RETURNDATACOPY` |
| Lifecycle | `BEGIN_TX`, `END_TX` |

See the [Supported Opcodes](project-docs/Usage_Doc.md#6-supported-opcodes) to learn about requirements of different opcodes.  
## Requirements

- Rust and Cargo with support for Rust 2021 edition.
- Git.

## Quick start

After cloning the repository, build all executables:

```bash
cargo build --release --bins
```

Run the included minimal program through the witness generator and Halo2 MockProver:

```bash
target/release/mockprover \
  --k 17 \
  --input testdata/correct_mock_test_input.txt
```
The minimum k across the project is 17 since we have some 2^16 - 1 row static tables on the circuit. so just use k = 17.

MockProver checks the existing constraints. It does not create a cryptographic proof.
> To fully understand how to use PortVM, Read [Usage_Doc Operating Guide](project-docs/Usage_Doc.md). You can also give it to your ai agent alongside with [CLI Interface](project-docs/cli_interfaces.txt).
## Compact public input

We need witness to create proofs out of them and to generally work with our PortVM. since manually generating a full witness for this circuit can be challenging, I implemented a witness generator that makes the witness generation process much easier.  
User provides the compacted input, it automatically expands into full ByteTable chip and TxTable chip which are equivalent to public inputs of the VM, and from that point rest of the witnesses are generated using the ByteTable and TxTable. 

The compact input is a UTF-8 text file with two sections:

```text
[Byte_Table]
<logical_call_id> <value>

[TX_Table]
<tag> <value>
```

A minimal valid example is:

```text
[Byte_Table]
0 0x00  # BEGIN_TX
0 0xfe  # END_TX
0 0xff  # HALT

[TX_Table]
4 0x1111
5 0x2222
7 0
8 0
```

Values can be unsigned 256 bit decimal or 0x prefixed hexadecimal integers. The generator derives PCs, active flags, code/data markers, TX IDs, TX indexes, value limbs, actual circuit call IDs, and the rest of the witness eventually.

On compact input, logical call IDs must be contiguous and ordered:

- `0` is the root program.
- `1` is the child created by the first executed `CALL`.
- `2` is the child created by the second executed `CALL`.
- The sequence continues globally in actual CALL execution order.

`WRITE` is the only instruction with an immediate row:

```text
0 0x55   # WRITE opcode
0 12345  # immediate 256 bit value that will be pushed onto the stack
```

For the root transaction, the execution core currently consumes these TX tags:

| Tag | Meaning |
|---:|---|
| `1` | Root calldata byte; repeated rows receive sequential indexes |
| `4` | Root caller address |
| `5` | Root callee or contract address |
| `7` | Root transaction value |
| `8` | Declared root calldata length |

Since PortVM isnt settled on Ethereum, the caller and callee address and tx value dont need to be anything valid and they can be just local values.  
See the [Usage_Doc Operating Guide](project-docs/Usage_Doc.md) for complete input rules, operand ordering, CALL/RETURN behavior, and larger examples.  

## Command-line tools

| Binary | Purpose |
|---|---|
| `witness_gen` | Generate and serialize a complete witness from compact input |
| `mockprover` | Validate compact input or an existing witness out of witness_gen with MockProver |
| `vk_harness` | Generate a verification key from existing or locally generated parameters |
| `pk_harness` | Generate a proving key from matching parameters and a VK |
| `prove` | Generate a real proof from compact input or a serialized witness |
| `verify` | Verify a proof using matching parameters, VK, and public instances |

Every executable provides CLI help:

```bash
target/release/<binary> --help
```

All command variants are documented in [CLI Interfaces](project-docs/cli_interfaces.txt).

## Common workflows

### Generate and mockprove a reusable witness

```bash
mkdir -p artifacts

target/release/witness_gen \
  --input testdata/correct_mock_test_input.txt \
  --out artifacts/witness.bin

target/release/mockprover \
  --k 17 \
  --witness artifacts/witness.bin
```

### Generate development keys

```bash
target/release/vk_harness \
  --k 17 \
  --unsafe-local-setup \
  --params-out artifacts/params.bin \
  --out artifacts/vk.bin

target/release/pk_harness \
  --k 17 \
  --params artifacts/params.bin \
  --vk artifacts/vk.bin \
  --out artifacts/pk.bin
```


### Generate a proof with existing keys

```bash
target/release/prove \
  --k 17 \
  --params artifacts/params.bin \
  --pk artifacts/pk.bin \
  --input testdata/correct_mock_test_input.txt \
  --witness-out artifacts/witness.bin \
  --proof-out artifacts/proof.bin \
  --instances-out artifacts/instances.bin \
  --mock-precheck
```

`--mock-precheck` is optional but recommended before starting expensive proof generation. The prover can also consume an existing `witness.bin`, or generate local params, VK, and PK in the same invocation; see the CLI reference for those forms.

### Verify a proof

```bash
target/release/verify \
  --k 17 \
  --params artifacts/params.bin \
  --vk artifacts/vk.bin \
  --proof artifacts/proof.bin \
  --instances artifacts/instances.bin
```


## Artifacts and compatibility

| Artifact | Visibility | Purpose |
|---|---|---|
| Compact input | Public | ByteTable and TxTable input |
| `witness.bin` | Private | Complete generated circuit witness |
| `params.bin` | Public | KZG parameters |
| `vk.bin` | Public | Verification key |
| `pk.bin` | Prover-side | Proving key for the circuit and parameters |
| `proof.bin` | Public | Cryptographic proof transcript |
| `instances.bin` | Public | The public instance columns bound to the proof |

All artifacts in a proof flow must agree on the circuit shape, `k` and parameter set. Circuit shape or instance layout changes require new keys and proofs. Witness generator changes require regenerated witnesses and renewed MockProver validation.

## Documentation

- [Technical Overview](project-docs/Technical%20Overview.md)  circuit architecture and chip relationships.
- [Usage_Doc Operating Guide](project-docs/Usage_Doc.md)  complete input, opcode, CLI, and operational instructions.
- [CLI Interfaces](project-docs/cli_interfaces.txt)  every supported executable form and argument.

## Acknowledgements

PortVM was developed as a learning project using publicly available material from modern zkEVM and Halo2 projects. Its architecture was particularly informed by Scroll's zkEVM circuits, Polygon zkEVM documentation, and the PSE Halo2 ecosystem.

## License

PortVM is available under the [MIT License](LICENSE).
