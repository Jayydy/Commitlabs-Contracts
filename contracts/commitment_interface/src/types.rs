use soroban_sdk::{contracttype, Address, BytesN};

#[derive(Clone, Debug, PartialEq)]
#[contracttype]
pub struct CommitmentSpec {
    pub provider: Address,
    pub amount: i128,
    pub unlock_date: u64,
    pub metadata_hash: BytesN<32>,
}
