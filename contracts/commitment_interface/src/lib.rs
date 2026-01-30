#![no_std]

pub mod error;
pub mod types;

use soroban_sdk::{contract, contractimpl, symbol_short, Address, Env, Symbol};

use crate::error::Error;
use crate::types::CommitmentSpec;

/// =======================
/// Interface Metadata
/// =======================

pub const INTERFACE_VERSION: u32 = 1;

/// =======================
/// Events
/// =======================

pub const COMMITMENT_CREATED: Symbol = symbol_short!("created");
pub const COMMITMENT_REVOKED: Symbol = symbol_short!("revoked");

/// =======================
/// Interface Contract
/// =======================

#[contract]
pub struct CommitmentInterface;

#[contractimpl]
impl CommitmentInterface {
    /// Initialize the commitment system
    pub fn initialize(_env: Env, _admin: Address) -> Result<(), Error> {
        unimplemented!("interface only")
    }

    /// Create a new commitment
    pub fn create_commitment(_env: Env, _spec: CommitmentSpec) -> Result<u64, Error> {
        unimplemented!("interface only")
    }

    /// Fetch an existing commitment
    pub fn get_commitment(_env: Env, _id: u64) -> Result<CommitmentSpec, Error> {
        unimplemented!("interface only")
    }

    /// Revoke a commitment
    pub fn revoke_commitment(_env: Env, _id: u64) -> Result<(), Error> {
        unimplemented!("interface only")
    }
}
