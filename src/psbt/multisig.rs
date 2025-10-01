use bdk_wallet::bitcoin::opcodes::all::{OP_CHECKMULTISIG, OP_PUSHNUM_1, OP_PUSHNUM_16};
use bdk_wallet::bitcoin::script::{Instruction, Instructions};
use bdk_wallet::bitcoin::{PublicKey, Script};
use std::iter::Peekable;
use thiserror::Error;

/// Errors that can happen during the disassembly of the multi-sig script.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    #[error("expected OP_PUSHNUM")]
    ExpectedPushnum,
    #[error("expected a public key")]
    ExpectedPublicKey,
    #[error("expected OP_CHECKMULTISIG")]
    ExpectedCheckMultisig,
    #[error("expected end of script")]
    ExpectedEof,
    #[error("malformed public key")]
    MalformedPublicKey,
    #[error("malformed script")]
    MalformedScript,
    #[error("invalid total public keys length")]
    InvalidTotalPublicKeysLength,
    #[error("unexpected end of script")]
    UnexpectedEof,
}

/// Disassebmle a multi-sig script.
///
/// # Return
///
/// This returns the number of signers required on success.
pub fn disassemble(script: &Script) -> Result<u8, Error> {
    let mut instructions = script.instructions_minimal().peekable();

    let m = parse_pushnum(&mut instructions).ok_or(Error::UnexpectedEof)??;

    let mut public_keys = 0;
    loop {
        match parse_public_key(&mut instructions).ok_or(Error::UnexpectedEof)? {
            Ok(_) => public_keys += 1,
            Err(Error::ExpectedPublicKey) => break,
            Err(e) => return Err(e),
        }
    }

    let n = parse_pushnum(&mut instructions).ok_or(Error::UnexpectedEof)??;
    if usize::from(n) != public_keys {
        return Err(Error::InvalidTotalPublicKeysLength);
    }

    parse_check_multisig(&mut instructions).ok_or(Error::UnexpectedEof)??;

    if instructions.next().is_some() {
        Err(Error::ExpectedEof)
    } else {
        Ok(m)
    }
}

fn parse_pushnum(instructions: &mut Peekable<Instructions>) -> Option<Result<u8, Error>> {
    match instructions.next()? {
        Ok(Instruction::Op(op)) => {
            let opcode = op.to_u8();
            if opcode >= OP_PUSHNUM_1.to_u8() && opcode <= OP_PUSHNUM_16.to_u8() {
                Some(Ok(opcode - OP_PUSHNUM_1.to_u8() + 1))
            } else {
                Some(Err(Error::ExpectedPushnum))
            }
        }
        Ok(_) => Some(Err(Error::ExpectedPushnum)),
        Err(_) => Some(Err(Error::MalformedScript)),
    }
}

fn parse_public_key(instructions: &mut Peekable<Instructions>) -> Option<Result<PublicKey, Error>> {
    match instructions.peek()? {
        Ok(Instruction::PushBytes(push_bytes)) => {
            match PublicKey::from_slice(push_bytes.as_bytes()) {
                Ok(pk) => {
                    instructions.next();
                    Some(Ok(pk))
                }
                Err(_) => Some(Err(Error::MalformedPublicKey)),
            }
        }
        Ok(_) => Some(Err(Error::ExpectedPublicKey)),
        Err(_) => Some(Err(Error::MalformedScript)),
    }
}

fn parse_check_multisig(instructions: &mut Peekable<Instructions>) -> Option<Result<(), Error>> {
    match instructions.next()? {
        Ok(Instruction::Op(op)) if op == OP_CHECKMULTISIG => Some(Ok(())),
        Ok(_) => Some(Err(Error::ExpectedCheckMultisig)),
        Err(_) => Some(Err(Error::MalformedScript)),
    }
}
