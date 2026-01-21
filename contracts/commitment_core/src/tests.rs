#![cfg(test)]

use super::*;
use soroban_sdk::{testutils::Address as _, Address, Env, String};

#[test]
fn test_initialize() {
    let e = Env::default();
    let contract_id = e.register_contract(None, CommitmentCoreContract);

    let admin = Address::generate(&e);
    let nft_contract = Address::generate(&e);

    // Test successful initialization
    e.as_contract(&contract_id, || {
        CommitmentCoreContract::initialize(e.clone(), admin.clone(), nft_contract.clone());
    });
}

#[test]
fn test_create_commitment_valid() {
    let e = Env::default();
    let contract_id = e.register_contract(None, CommitmentCoreContract);

    let admin = Address::generate(&e);
    let nft_contract = Address::generate(&e);
    let _owner = Address::generate(&e);
    let _asset_address = Address::generate(&e);

    // Initialize the contract
    e.as_contract(&contract_id, || {
        CommitmentCoreContract::initialize(e.clone(), admin.clone(), nft_contract.clone());
    });

    // Create valid commitment rules
    let rules = CommitmentRules {
        duration_days: 30,
        max_loss_percent: 10,
        commitment_type: String::from_str(&e, "safe"),
        early_exit_penalty: 5,
        min_fee_threshold: 100,
    };

    let _amount = 1000i128;

    // Test commitment creation (this will panic if NFT contract is not properly set up)
    // For now, we'll test that the validation works by testing individual validation functions
    e.as_contract(&contract_id, || {
        CommitmentCoreContract::validate_rules(&e, &rules); // Should not panic
    });
}

#[test]
#[should_panic(expected = "Invalid duration")]
fn test_validate_rules_invalid_duration() {
    let e = Env::default();
    let contract_id = e.register_contract(None, CommitmentCoreContract);

    let rules = CommitmentRules {
        duration_days: 0, // Invalid duration
        max_loss_percent: 10,
        commitment_type: String::from_str(&e, "safe"),
        early_exit_penalty: 5,
        min_fee_threshold: 100,
    };

    // Test invalid duration - should panic
    e.as_contract(&contract_id, || {
        CommitmentCoreContract::validate_rules(&e, &rules);
    });
}

#[test]
#[should_panic(expected = "Invalid max loss percent")]
fn test_validate_rules_invalid_max_loss() {
    let e = Env::default();
    let contract_id = e.register_contract(None, CommitmentCoreContract);

    let rules = CommitmentRules {
        duration_days: 30,
        max_loss_percent: 150, // Invalid max loss (> 100)
        commitment_type: String::from_str(&e, "safe"),
        early_exit_penalty: 5,
        min_fee_threshold: 100,
    };

    // Test invalid max loss percent - should panic
    e.as_contract(&contract_id, || {
        CommitmentCoreContract::validate_rules(&e, &rules);
    });
}

#[test]
#[should_panic(expected = "Invalid commitment type")]
fn test_validate_rules_invalid_type() {
    let e = Env::default();
    let contract_id = e.register_contract(None, CommitmentCoreContract);

    let rules = CommitmentRules {
        duration_days: 30,
        max_loss_percent: 10,
        commitment_type: String::from_str(&e, "invalid_type"), // Invalid type
        early_exit_penalty: 5,
        min_fee_threshold: 100,
    };

    // Test invalid commitment type - should panic
    e.as_contract(&contract_id, || {
        CommitmentCoreContract::validate_rules(&e, &rules);
    });
}

#[test]
fn test_get_owner_commitments() {
    let e = Env::default();
    let contract_id = e.register_contract(None, CommitmentCoreContract);

    let admin = Address::generate(&e);
    let nft_contract = Address::generate(&e);
    let owner = Address::generate(&e);

    e.as_contract(&contract_id, || {
        CommitmentCoreContract::initialize(e.clone(), admin.clone(), nft_contract.clone());
    });

    // Initially empty
    let commitments = e.as_contract(&contract_id, || {
        CommitmentCoreContract::get_owner_commitments(e.clone(), owner.clone())
    });
    assert_eq!(commitments.len(), 0);
}

#[test]
fn test_get_total_commitments() {
    let e = Env::default();
    let contract_id = e.register_contract(None, CommitmentCoreContract);

    let admin = Address::generate(&e);
    let nft_contract = Address::generate(&e);

    e.as_contract(&contract_id, || {
        CommitmentCoreContract::initialize(e.clone(), admin.clone(), nft_contract.clone());
    });

    // Initially zero
    let total = e.as_contract(&contract_id, || {
        CommitmentCoreContract::get_total_commitments(e.clone())
    });
    assert_eq!(total, 0);
}

#[test]
fn test_get_admin() {
    let e = Env::default();
    let contract_id = e.register_contract(None, CommitmentCoreContract);

    let admin = Address::generate(&e);
    let nft_contract = Address::generate(&e);

    e.as_contract(&contract_id, || {
        CommitmentCoreContract::initialize(e.clone(), admin.clone(), nft_contract.clone());
    });

    let retrieved_admin = e.as_contract(&contract_id, || {
        CommitmentCoreContract::get_admin(e.clone())
    });
    assert_eq!(retrieved_admin, admin);
}

#[test]
fn test_get_nft_contract() {
    let e = Env::default();
    let contract_id = e.register_contract(None, CommitmentCoreContract);

    let admin = Address::generate(&e);
    let nft_contract = Address::generate(&e);

    e.as_contract(&contract_id, || {
        CommitmentCoreContract::initialize(e.clone(), admin.clone(), nft_contract.clone());
    });

    let retrieved_nft_contract = e.as_contract(&contract_id, || {
        CommitmentCoreContract::get_nft_contract(e.clone())
    });
    assert_eq!(retrieved_nft_contract, nft_contract);
}
