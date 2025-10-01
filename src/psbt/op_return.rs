use crate::psbt::{OpReturnPart, OutputKind, PsbtOutput};
use bdk_wallet::bitcoin::TxOut;
use bdk_wallet::bitcoin::opcodes::all::OP_RETURN;
use bdk_wallet::bitcoin::script::Instruction;
use std::str;

/// Parse an OP_RETURN output to retrieve the message.
///
/// It is assumed that the data after the OP_RETURN instruction are still
/// valid data pushes which are then decoded as UTF-8 strings.
pub fn parse(txout: &TxOut) -> PsbtOutput {
    let mut instructions = txout.script_pubkey.instructions();

    // Skip the OP_RETURN instruction itself.
    //
    // PANICS:
    //
    // We assume that output.script_pubkey.is_op_return() is true, so these panics should never
    // trigger.
    let first = instructions
        .next()
        .expect("at least OP_RETURN should be present")
        .expect("OP_RETURN should be encoded correctly");
    debug_assert!(is_op_return(first));

    let mut parts = Vec::new();
    while let Some(inst) = instructions.next() {
        match inst {
            Ok(Instruction::PushBytes(pushbytes)) => {
                let part = parse_part(pushbytes.as_bytes(), OpReturnPart::Binary);
                parts.push(part);
            }
            // Maybe valid script, but we don't really know what to do with the opcode,
            // so just return it as an unknown part from this point on.
            Ok(Instruction::Op(_)) => {
                let part = parse_part(instructions.as_script().as_bytes(), OpReturnPart::Unknown);
                parts.push(part);
                break;
            }
            // Invalid script part, return remaining bytes as unknown.
            Err(_) => {
                let part = parse_part(instructions.as_script().as_bytes(), OpReturnPart::Unknown);
                parts.push(part);
                break;
            }
        }
    }

    PsbtOutput {
        amount: txout.value,
        kind: OutputKind::OpReturn(parts),
    }
}

fn parse_part(bytes: &[u8], or_else: impl FnOnce(Vec<u8>) -> OpReturnPart) -> OpReturnPart {
    match str::from_utf8(bytes) {
        Ok(message) => OpReturnPart::Message(message.to_owned()),
        Err(_) => or_else(bytes.to_owned()),
    }
}

fn is_op_return(instruction: Instruction) -> bool {
    match instruction {
        Instruction::Op(opcode) => opcode == OP_RETURN,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::psbt::{OpReturnPart, OutputKind, PsbtOutput};
    use bdk_wallet::bitcoin::{Amount, Script, script::PushBytes};

    #[test]
    fn message() {
        const MESSAGE: &str = "Hello, World!";

        let value = Amount::from_sat(1000);
        let pushdata: &'_ PushBytes = MESSAGE.as_bytes().try_into().unwrap();
        let script_pubkey = Script::builder()
            .push_opcode(OP_RETURN)
            .push_slice(pushdata)
            .as_script()
            .to_owned();

        let output = parse(&TxOut {
            value,
            script_pubkey,
        });
        assert_eq!(
            output,
            PsbtOutput {
                amount: value,
                kind: OutputKind::OpReturn(vec![OpReturnPart::Message(MESSAGE.to_owned())])
            }
        )
    }
}
