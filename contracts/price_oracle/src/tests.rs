#![cfg(test)]

use super::*;
use soroban_sdk::testutils::{Address as _, Ledger};

#[test]
fn test_initialize() {
    let e = Env::default();
    let admin = Address::generate(&e);
    let contract_id = e.register_contract(None, PriceOracleContract);
    let client = PriceOracleContractClient::new(&e, &contract_id);

    e.as_contract(&contract_id, || {
        let r = PriceOracleContract::initialize(e.clone(), admin.clone());
        assert_eq!(r, Ok(()));
    });

    assert_eq!(client.get_admin(), admin);
    assert_eq!(client.get_max_staleness(), 3600);
}

#[test]
fn test_initialize_twice_fails() {
    let e = Env::default();
    let admin = Address::generate(&e);
    let contract_id = e.register_contract(None, PriceOracleContract);

    e.as_contract(&contract_id, || {
        PriceOracleContract::initialize(e.clone(), admin.clone()).unwrap();
        let r = PriceOracleContract::initialize(e.clone(), admin.clone());
        assert_eq!(r, Err(OracleError::AlreadyInitialized));
    });
}

#[test]
fn test_add_remove_oracle_admin_only() {
    let e = Env::default();
    e.mock_all_auths();
    let admin = Address::generate(&e);
    let oracle = Address::generate(&e);
    let contract_id = e.register_contract(None, PriceOracleContract);
    let client = PriceOracleContractClient::new(&e, &contract_id);

    e.as_contract(&contract_id, || {
        PriceOracleContract::initialize(e.clone(), admin.clone()).unwrap();
    });

    client.add_oracle(&admin, &oracle);
    assert!(client.is_oracle_whitelisted(&oracle));

    client.remove_oracle(&admin, &oracle);
    assert!(!client.is_oracle_whitelisted(&oracle));
}

#[test]
fn test_set_price_whitelisted() {
    let e = Env::default();
    e.mock_all_auths();
    let admin = Address::generate(&e);
    let oracle = Address::generate(&e);
    let asset = Address::generate(&e);
    let contract_id = e.register_contract(None, PriceOracleContract);
    let client = PriceOracleContractClient::new(&e, &contract_id);

    e.as_contract(&contract_id, || {
        PriceOracleContract::initialize(e.clone(), admin.clone()).unwrap();
        PriceOracleContract::add_oracle(e.clone(), admin.clone(), oracle.clone()).unwrap();
    });

    client.set_price(&oracle, &asset, &1000_00000000, &8);
    let data = client.get_price(&asset);
    assert_eq!(data.price, 1000_00000000);
    assert_eq!(data.decimals, 8);
    assert!(data.updated_at >= 0);
}

#[test]
#[should_panic(expected = "Oracle not whitelisted")]
fn test_set_price_unauthorized_fails() {
    let e = Env::default();
    e.mock_all_auths();
    let admin = Address::generate(&e);
    let unauthorized = Address::generate(&e);
    let asset = Address::generate(&e);
    let contract_id = e.register_contract(None, PriceOracleContract);
    let client = PriceOracleContractClient::new(&e, &contract_id);

    e.as_contract(&contract_id, || {
        PriceOracleContract::initialize(e.clone(), admin.clone()).unwrap();
    });

    client.set_price(&unauthorized, &asset, &1000, &8);
}

#[test]
fn test_get_price_valid_fresh() {
    let e = Env::default();
    e.mock_all_auths();
    let admin = Address::generate(&e);
    let oracle = Address::generate(&e);
    let asset = Address::generate(&e);
    let contract_id = e.register_contract(None, PriceOracleContract);
    let client = PriceOracleContractClient::new(&e, &contract_id);

    e.as_contract(&contract_id, || {
        PriceOracleContract::initialize(e.clone(), admin.clone()).unwrap();
        PriceOracleContract::add_oracle(e.clone(), admin.clone(), oracle.clone()).unwrap();
    });

    client.set_price(&oracle, &asset, &500_0000000, &8);
    let data = client.get_price_valid(&asset, &None);
    assert_eq!(data.price, 500_0000000);
}

#[test]
#[should_panic]
fn test_get_price_valid_not_found() {
    let e = Env::default();
    let admin = Address::generate(&e);
    let asset = Address::generate(&e);
    let contract_id = e.register_contract(None, PriceOracleContract);
    let client = PriceOracleContractClient::new(&e, &contract_id);

    e.as_contract(&contract_id, || {
        PriceOracleContract::initialize(e.clone(), admin.clone()).unwrap();
    });

    let _ = client.get_price_valid(&asset, &None);
}

#[test]
#[should_panic]
fn test_get_price_valid_stale() {
    let e = Env::default();
    e.mock_all_auths();
    let admin = Address::generate(&e);
    let oracle = Address::generate(&e);
    let asset = Address::generate(&e);
    let contract_id = e.register_contract(None, PriceOracleContract);
    let client = PriceOracleContractClient::new(&e, &contract_id);

    e.as_contract(&contract_id, || {
        PriceOracleContract::initialize(e.clone(), admin.clone()).unwrap();
        PriceOracleContract::add_oracle(e.clone(), admin.clone(), oracle.clone()).unwrap();
    });

    client.set_price(&oracle, &asset, &1000, &8);

    // Advance time past max staleness (default 3600)
    e.ledger().with_mut(|li| {
        li.timestamp += 4000;
    });

    let _ = client.get_price_valid(&asset, &None);
}

#[test]
fn test_get_price_valid_override_staleness() {
    let e = Env::default();
    e.mock_all_auths();
    let admin = Address::generate(&e);
    let oracle = Address::generate(&e);
    let asset = Address::generate(&e);
    let contract_id = e.register_contract(None, PriceOracleContract);
    let client = PriceOracleContractClient::new(&e, &contract_id);

    e.as_contract(&contract_id, || {
        PriceOracleContract::initialize(e.clone(), admin.clone()).unwrap();
        PriceOracleContract::add_oracle(e.clone(), admin.clone(), oracle.clone()).unwrap();
    });

    client.set_price(&oracle, &asset, &1000, &8);
    e.ledger().with_mut(|li| {
        li.timestamp += 100;
    });

    // Override: allow 200 seconds staleness, so still valid
    let data = client.get_price_valid(&asset, &Some(200));
    assert_eq!(data.price, 1000);
}

#[test]
fn test_set_max_staleness() {
    let e = Env::default();
    e.mock_all_auths();
    let admin = Address::generate(&e);
    let contract_id = e.register_contract(None, PriceOracleContract);
    let client = PriceOracleContractClient::new(&e, &contract_id);

    e.as_contract(&contract_id, || {
        PriceOracleContract::initialize(e.clone(), admin.clone()).unwrap();
    });

    client.set_max_staleness(&admin, &7200);
    assert_eq!(client.get_max_staleness(), 7200);
}

#[test]
fn test_fallback_get_price_returns_default_when_not_set() {
    let e = Env::default();
    let admin = Address::generate(&e);
    let asset = Address::generate(&e);
    let contract_id = e.register_contract(None, PriceOracleContract);
    let client = PriceOracleContractClient::new(&e, &contract_id);

    e.as_contract(&contract_id, || {
        PriceOracleContract::initialize(e.clone(), admin.clone()).unwrap();
    });

    let data = client.get_price(&asset);
    assert_eq!(data.price, 0);
    assert_eq!(data.updated_at, 0);
    assert_eq!(data.decimals, 0);
}
