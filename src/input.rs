use crate::main::{CompactLogicalByteTableRow, CompactLogicalTxRow, ExecutionPublicTables};
use std::fmt;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TextInputError {
    Io(String),
    MissingSection,
    UnexpectedSection {
        line: usize,
        section: String,
    },
    DuplicateSection {
        line: usize,
        section: String,
    },
    RowOutsideSection {
        line: usize,
    },
    InvalidRow {
        line: usize,
        section: String,
        message: String,
    },
    InvalidInteger {
        line: usize,
        field: &'static str,
        value: String,
    },
    EmptyValue {
        line: usize,
        section: String,
    },
}

impl fmt::Display for TextInputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(message) => write!(f, "could not read input file: {message}"),
            Self::MissingSection => write!(f, "input must contain [Byte_Table] or [TX_Table]"),
            Self::UnexpectedSection { line, section } => {
                write!(f, "line {line}: unknown section [{section}]")
            }
            Self::DuplicateSection { line, section } => {
                write!(f, "line {line}: duplicate section [{section}]")
            }
            Self::RowOutsideSection { line } => {
                write!(f, "line {line}: data row appears before a table section")
            }
            Self::InvalidRow {
                line,
                section,
                message,
            } => write!(f, "line {line} in [{section}]: {message}"),
            Self::InvalidInteger { line, field, value } => {
                write!(f, "line {line}: invalid {field} '{value}'")
            }
            Self::EmptyValue { line, section } => {
                write!(f, "line {line} in [{section}]: value is empty")
            }
        }
    }
}

impl std::error::Error for TextInputError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Section {
    ByteTable,
    TxTable,
}

impl Section {
    fn name(self) -> &'static str {
        match self {
            Self::ByteTable => "Byte_Table",
            Self::TxTable => "TX_Table",
        }
    }
}

/// Parse the compact user input format into the public table representation
/// consumed by the execution core.
///
/// Supported rows:
///
/// ```text
/// [Byte_Table]
/// 0 0x00
/// 0 0x55
/// 0 42
///
/// [TX_Table]
/// 4 0x1111
/// 5 0x2222
/// 1 0xaa
/// ```
///
/// Byte-table PCs, `iscode`, TX indexes, active flags, TX IDs, and 256-bit
/// limb representations are derived by the execution core.
pub fn parse_public_tables_text(text: &str) -> Result<ExecutionPublicTables, TextInputError> {
    let mut section = None;
    let mut saw_section = false;
    let mut saw_byte_table = false;
    let mut saw_tx_table = false;
    let mut tables = ExecutionPublicTables::default();

    for (line_index, raw_line) in text.lines().enumerate() {
        let line_number = line_index + 1;
        let line = raw_line
            .split_once('#')
            .map_or(raw_line, |(body, _)| body)
            .trim();
        if line.is_empty() {
            continue;
        }

        if let Some(section_name) = line
            .strip_prefix('[')
            .and_then(|line| line.strip_suffix(']'))
        {
            let parsed_section = match section_name {
                "Byte_Table" => Section::ByteTable,
                "TX_Table" => Section::TxTable,
                _ => {
                    return Err(TextInputError::UnexpectedSection {
                        line: line_number,
                        section: section_name.to_string(),
                    })
                }
            };

            let already_seen = match parsed_section {
                Section::ByteTable => saw_byte_table,
                Section::TxTable => saw_tx_table,
            };
            if already_seen {
                return Err(TextInputError::DuplicateSection {
                    line: line_number,
                    section: parsed_section.name().to_string(),
                });
            }

            match parsed_section {
                Section::ByteTable => saw_byte_table = true,
                Section::TxTable => saw_tx_table = true,
            }
            section = Some(parsed_section);
            saw_section = true;
            continue;
        }

        let section = section.ok_or(TextInputError::RowOutsideSection { line: line_number })?;
        let mut fields = line.split_whitespace();
        let first = fields.next();
        let value = fields.next();
        let extra = fields.next();

        let (first, value) = match (first, value, extra) {
            (Some(first), Some(value), None) => (first, value),
            _ => {
                return Err(TextInputError::InvalidRow {
                    line: line_number,
                    section: section.name().to_string(),
                    message: "expected exactly two fields: <id-or-tag> <value>".to_string(),
                })
            }
        };

        if value.is_empty() {
            return Err(TextInputError::EmptyValue {
                line: line_number,
                section: section.name().to_string(),
            });
        }

        match section {
            Section::ByteTable => {
                let logical_call_id = parse_u64(first, line_number, "logical call id")?;
                tables
                    .compact_bytecode_rows
                    .push(CompactLogicalByteTableRow {
                        logical_call_id,
                        value: value.to_string(),
                    });
            }
            Section::TxTable => {
                let tag = parse_u64(first, line_number, "TX tag")?;
                tables.compact_tx_rows.push(CompactLogicalTxRow {
                    tag,
                    value: value.to_string(),
                });
            }
        }
    }

    if !saw_section {
        return Err(TextInputError::MissingSection);
    }

    Ok(tables)
}

pub fn parse_public_tables_file(
    path: impl AsRef<Path>,
) -> Result<ExecutionPublicTables, TextInputError> {
    let path = path.as_ref();
    let text = fs::read_to_string(path)
        .map_err(|err| TextInputError::Io(format!("{}: {err}", path.display())))?;
    parse_public_tables_text(&text)
}

fn parse_u64(value: &str, line: usize, field: &'static str) -> Result<u64, TextInputError> {
    let value_without_underscores = value.replace('_', "");
    let parsed = if let Some(hex) = value_without_underscores
        .strip_prefix("0x")
        .or_else(|| value_without_underscores.strip_prefix("0X"))
    {
        u64::from_str_radix(hex, 16)
    } else {
        value_without_underscores.parse::<u64>()
    };

    parsed.map_err(|_| TextInputError::InvalidInteger {
        line,
        field,
        value: value.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_byte_and_tx_sections() {
        let tables = parse_public_tables_text(
            "# compact input\n\n[Byte_Table]\n0 0x00\n0 0x55\n0 42\n1 0xff\n\n[TX_Table]\n4 0x1111\n5 0x2222\n1 0xaa\n1 0xbb\n",
        )
        .expect("input should parse");

        assert_eq!(tables.compact_bytecode_rows.len(), 4);
        assert_eq!(tables.compact_bytecode_rows[2].logical_call_id, 0);
        assert_eq!(tables.compact_bytecode_rows[2].value, "42");
        assert_eq!(tables.compact_tx_rows.len(), 4);
        assert_eq!(tables.compact_tx_rows[2].tag, 1);
        assert_eq!(tables.compact_tx_rows[2].value, "0xaa");
    }

    #[test]
    fn accepts_hex_ids_and_comments() {
        let tables =
            parse_public_tables_text("[Byte_Table]\n0x0 0x01 # opcode\n[TX_Table]\n0x1 2\n")
                .expect("input should parse");

        assert_eq!(tables.compact_bytecode_rows[0].logical_call_id, 0);
        assert_eq!(tables.compact_tx_rows[0].tag, 1);
    }

    #[test]
    fn rejects_unknown_sections_and_malformed_rows() {
        let unknown = parse_public_tables_text("[Other]\n0 1\n");
        assert!(matches!(
            unknown,
            Err(TextInputError::UnexpectedSection { .. })
        ));

        let malformed = parse_public_tables_text("[TX_Table]\n1 2 extra\n");
        assert!(matches!(malformed, Err(TextInputError::InvalidRow { .. })));
    }
}
