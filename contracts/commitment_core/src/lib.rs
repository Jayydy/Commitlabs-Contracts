#![no_std]

use soroban_sdk::{
    contract, contractimpl, contracttype,
    Address, Env, String, Symbol, Vec, symbol_short,
    Val, IntoVal,
};
use soroban_sdk::token::Client as TokenClient;

/* -------------------- STORAGE KEYS -------------------- */

const ADMIN_KEY: Symbol = symbol_short!("ADMIN");
const NFT_KEY: Symbol = symbol_short!("NFT");
const COMMITMENTS_KEY: Symbol = symbol_short!("COMMS");

/* -------------------- DATA TYPES -------------------- */
    contract, contracterror, contractimpl, contracttype, log, token, symbol_short, Address, Env, IntoVal, String,
    Symbol, Vec,
};
use shared_utils::{SafeMath, TimeUtils, Validation, RateLimiter};

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum CommitmentError {
    InvalidDuration = 1,
    InvalidMaxLossPercent = 2,
    InvalidCommitmentType = 3,
    InvalidAmount = 4,
    InsufficientBalance = 5,
    TransferFailed = 6,
    MintingFailed = 7,
    CommitmentNotFound = 8,
    Unauthorized = 9,
    AlreadyInitialized = 10,
    ReentrancyDetected = 11,
}

#[contracttype]
#[derive(Clone)]
pub struct CommitmentCreatedEvent {
    pub commitment_id: String,
    pub owner: Address,
    pub amount: i128,
    pub asset_address: Address,
    pub nft_token_id: u32,
    pub rules: CommitmentRules,
    pub timestamp: u64,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitmentRules {
    pub duration_days: u32,
    pub max_loss_percent: u32,
    pub commitment_type: String,
    pub early_exit_penalty: u32,
    pub min_fee_threshold: i128,
    pub grace_period_days: u32,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Commitment {
    pub commitment_id: String,
    pub owner: Address,
    pub nft_token_id: u32,
    pub rules: CommitmentRules,
    pub amount: i128,
    pub asset_address: Address,
    pub created_at: u64,
    pub expires_at: u64,
    pub current_value: i128,
    pub status: String, // active | settled | violated | early_exit
}

/* -------------------- CONTRACT -------------------- */
#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    Admin,
    NftContract,
    Commitment(String),        // commitment_id -> Commitment
    OwnerCommitments(Address), // owner -> Vec<commitment_id>
    TotalCommitments,          // counter
    ReentrancyGuard,           // reentrancy protection flag
    TotalValueLocked,          // aggregate value locked across active commitments
}

/// Transfer assets from owner to contract
fn transfer_assets(e: &Env, from: &Address, to: &Address, asset_address: &Address, amount: i128) {
    let token_client = token::Client::new(e, asset_address);

    // Check balance first
    let balance = token_client.balance(from);
    if balance < amount {
        log!(e, "Insufficient balance: {} < {}", balance, amount);
        panic!("Insufficient balance");
    }

    // Transfer tokens (fails transaction if unsuccessful)
    token_client.transfer(from, to, &amount);
}

/// Helper function to call NFT contract mint function
fn call_nft_mint(
    e: &Env,
    nft_contract: &Address,
    owner: &Address,
    commitment_id: &String,
    duration_days: u32,
    max_loss_percent: u32,
    commitment_type: &String,
    initial_amount: i128,
    asset_address: &Address,
) -> u32 {
    let mut args = Vec::new(e);
    args.push_back(owner.clone().into_val(e));
    args.push_back(commitment_id.clone().into_val(e));
    args.push_back(duration_days.into_val(e));
    args.push_back(max_loss_percent.into_val(e));
    args.push_back(commitment_type.clone().into_val(e));
    args.push_back(initial_amount.into_val(e));
    args.push_back(asset_address.clone().into_val(e));

    // In Soroban, contract calls return the value directly
    // Failures cause the entire transaction to fail
    e.invoke_contract::<u32>(nft_contract, &Symbol::new(e, "mint"), args)
}

// Storage helpers
fn read_commitment(e: &Env, commitment_id: &String) -> Option<Commitment> {
    e.storage()
        .instance()
        .get::<_, Commitment>(&DataKey::Commitment(commitment_id.clone()))
}

fn set_commitment(e: &Env, commitment: &Commitment) {
    e.storage()
        .instance()
        .set(&DataKey::Commitment(commitment.commitment_id.clone()), commitment);
}

fn has_commitment(e: &Env, commitment_id: &String) -> bool {
    e.storage()
        .instance()
        .has(&DataKey::Commitment(commitment_id.clone()))
}

/// Reentrancy protection helpers
fn require_no_reentrancy(e: &Env) {
    let guard: bool = e.storage()
        .instance()
        .get::<_, bool>(&DataKey::ReentrancyGuard)
        .unwrap_or(false);
    
    if guard {
        panic!("Reentrancy detected");
    }
}

fn set_reentrancy_guard(e: &Env, value: bool) {
    e.storage().instance().set(&DataKey::ReentrancyGuard, &value);
}

/// Require that the caller is the admin stored in this contract.
fn require_admin(e: &Env, caller: &Address) {
    caller.require_auth();
    let admin = e
        .storage()
        .instance()
        .get::<_, Address>(&DataKey::Admin)
        .unwrap_or_else(|| panic!("Contract not initialized"));
    if *caller != admin {
        panic!("Unauthorized: only admin can perform this action");
    }
}

#[contract]
pub struct CommitmentCoreContract;

#[contractimpl]
impl CommitmentCoreContract {

    /* ---------- INITIALIZE ---------- */

    pub fn initialize(e: Env, admin: Address, nft_contract: Address) {
        admin.require_auth();

        e.storage().instance().set(&ADMIN_KEY, &admin);
        e.storage().instance().set(&NFT_KEY, &nft_contract);

        let empty: Vec<Commitment> = Vec::new(&e);
        e.storage().instance().set(&COMMITMENTS_KEY, &empty);
    }

    /* ---------- CREATE COMMITMENT ---------- */

    /// Validate commitment rules
    /// Validate commitment rules using shared utilities
    fn validate_rules(e: &Env, rules: &CommitmentRules) {
        // Duration must be > 0
        Validation::require_valid_duration(rules.duration_days);

        // Max loss percent must be between 0 and 100
        Validation::require_valid_percent(rules.max_loss_percent);

        // Commitment type must be valid
        let valid_types = ["safe", "balanced", "aggressive"];
        Validation::require_valid_commitment_type(e, &rules.commitment_type, &valid_types);
    }

    /// Generate unique commitment ID
    fn generate_commitment_id(e: &Env, _owner: &Address) -> String {
        let _counter = e
            .storage()
            .instance()
            .get::<_, u64>(&DataKey::TotalCommitments)
            .unwrap_or(0);
        // Create a simple unique ID using counter
        // This is a simplified version - in production you might want a more robust ID generation
        String::from_str(e, "commitment_") // We'll extend this with a proper implementation later
    }

    /// Initialize the core commitment contract
    pub fn initialize(e: Env, admin: Address, nft_contract: Address) {
        // Check if already initialized
        if e.storage().instance().has(&DataKey::Admin) {
            panic!("Contract already initialized");
        }

        // Store admin and NFT contract address
        e.storage().instance().set(&DataKey::Admin, &admin);
        e.storage()
            .instance()
            .set(&DataKey::NftContract, &nft_contract);

        // Initialize total commitments counter
        e.storage()
            .instance()
            .set(&DataKey::TotalCommitments, &0u64);

        // Initialize total value locked counter
        e.storage()
            .instance()
            .set(&DataKey::TotalValueLocked, &0i128);
    }

    /// Create a new commitment
    /// 
    /// # Reentrancy Protection
    /// This function uses checks-effects-interactions pattern:
    /// 1. Checks: Validate inputs
    /// 2. Effects: Update state (commitment storage, counters)
    /// 3. Interactions: External calls (token transfer, NFT mint)
    /// Reentrancy guard prevents recursive calls.
    /// 
    /// # Formal Verification
    /// **Preconditions:**
    /// - `amount > 0`
    /// - `rules.duration_days > 0`
    /// - `rules.max_loss_percent <= 100`
    /// - `rules.commitment_type ∈ {"safe", "balanced", "aggressive"}`
    /// - Contract is initialized
    /// - `reentrancy_guard == false`
    /// 
    /// **Postconditions:**
    /// - Returns unique `commitment_id`
    /// - `get_commitment(commitment_id).owner == owner`
    /// - `get_commitment(commitment_id).amount == amount`
    /// - `get_commitment(commitment_id).status == "active"`
    /// - `get_total_commitments() == old(get_total_commitments()) + 1`
    /// - `reentrancy_guard == false`
    /// 
    /// **Invariants Maintained:**
    /// - INV-1: Total commitments consistency
    /// - INV-2: Commitment balance conservation
    /// - INV-3: Owner commitment list consistency
    /// - INV-4: Reentrancy guard invariant
    /// 
    /// **Security Properties:**
    /// - SP-1: Reentrancy protection
    /// - SP-2: Access control
    /// - SP-4: State consistency
    /// - SP-5: Token conservation
    pub fn create_commitment(
        e: Env,
        owner: Address,
        amount: i128,
        asset_address: Address,
        rules: CommitmentRules,
    ) -> String {
        owner.require_auth();

        if amount <= 0 {
            panic!("Invalid amount");
        }

        let now = e.ledger().timestamp();
        let expires_at = now + (rules.duration_days as u64 * 86400);

        let commitment_id =
            String::from_str(&e, "commitment");

        // Transfer asset into contract
        TokenClient::new(&e, &asset_address)
            .transfer(&owner, &e.current_contract_address(), &amount);

        // Mint NFT
        let nft_contract: Address =
            e.storage().instance().get(&NFT_KEY).unwrap();

        let mut mint_args = Vec::<Val>::new(&e);
        mint_args.push_back(owner.clone().into_val(&e));
        mint_args.push_back(commitment_id.clone().into_val(&e));

        let nft_token_id: u32 = e.invoke_contract(
            &nft_contract,
            &symbol_short!("mint"),
            mint_args,
        );

        let mut commitments: Vec<Commitment> =
            e.storage().instance().get(&COMMITMENTS_KEY).unwrap();

        commitments.push_back(Commitment {
            commitment_id: commitment_id.clone(),
            owner: owner.clone(),
            nft_token_id,
            rules,
            amount,
            asset_address,
            created_at: now,
            expires_at,
            current_value: amount,
            status: String::from_str(&e, "active"),
        });

        e.storage().instance().set(&COMMITMENTS_KEY, &commitments);

        e.events().publish(
            (Symbol::new(&e, "CommitmentCreated"),),
            (commitment_id.clone(), owner, amount, now),
        );

        // Reentrancy protection
        require_no_reentrancy(&e);
        set_reentrancy_guard(&e, true);

        // Rate limit: per-owner commitment creation
        let fn_symbol = symbol_short!("create");
        RateLimiter::check(&e, &owner, &fn_symbol);

        // Validate amount > 0 using shared utilities
        Validation::require_positive(amount);

        // Validate rules
        Self::validate_rules(&e, &rules);

        // Generate unique commitment ID
        let commitment_id = Self::generate_commitment_id(&e, &owner);

        // Get NFT contract address
        let nft_contract = e
            .storage()
            .instance()
            .get::<_, Address>(&DataKey::NftContract)
            .unwrap_or_else(|| {
                set_reentrancy_guard(&e, false);
                panic!("Contract not initialized")
            });

        // CHECKS: Validate commitment doesn't already exist
        if has_commitment(&e, &commitment_id) {
            set_reentrancy_guard(&e, false);
            panic!("Commitment already exists");
        }

        // EFFECTS: Update state before external calls
        // Calculate expiration timestamp using shared utilities
        let current_timestamp = TimeUtils::now(&e);
        let expires_at = TimeUtils::calculate_expiration(&e, rules.duration_days);

        // Create commitment data
        let commitment = Commitment {
            commitment_id: commitment_id.clone(),
            owner: owner.clone(),
            nft_token_id: 0, // Will be set after NFT mint
            rules: rules.clone(),
            amount,
            asset_address: asset_address.clone(),
            created_at: current_timestamp,
            expires_at,
            current_value: amount, // Initially same as amount
            status: String::from_str(&e, "active"),
        };

        // Store commitment data (before external calls)
        set_commitment(&e, &commitment);

        // Update owner's commitment list
        let mut owner_commitments = e
            .storage()
            .instance()
            .get::<_, Vec<String>>(&DataKey::OwnerCommitments(owner.clone()))
            .unwrap_or(Vec::new(&e));
        owner_commitments.push_back(commitment_id.clone());
        e.storage().instance().set(
            &DataKey::OwnerCommitments(owner.clone()),
            &owner_commitments,
        );

        // Increment total commitments counter
        let current_total = e
            .storage()
            .instance()
            .get::<_, u64>(&DataKey::TotalCommitments)
            .unwrap_or(0);
        e.storage()
            .instance()
            .set(&DataKey::TotalCommitments, &(current_total + 1));

        // Update total value locked (aggregate)
        let current_tvl = e
            .storage()
            .instance()
            .get::<_, i128>(&DataKey::TotalValueLocked)
            .unwrap_or(0);
        e.storage()
            .instance()
            .set(&DataKey::TotalValueLocked, &(current_tvl + amount));

        // INTERACTIONS: External calls (token transfer, NFT mint)
        // Transfer assets from owner to contract
        let contract_address = e.current_contract_address();
        transfer_assets(&e, &owner, &contract_address, &asset_address, amount);

        // Mint NFT
        let nft_token_id = call_nft_mint(
            &e,
            &nft_contract,
            &owner,
            &commitment_id,
            rules.duration_days,
            rules.max_loss_percent,
            &rules.commitment_type,
            amount,
            &asset_address,
        );

        // Update commitment with NFT token ID
        let mut updated_commitment = commitment;
        updated_commitment.nft_token_id = nft_token_id;
        set_commitment(&e, &updated_commitment);

        // Clear reentrancy guard
        set_reentrancy_guard(&e, false);

        // Emit creation event
        e.events().publish(
            (symbol_short!("Created"), commitment_id.clone(), owner.clone()),
            (amount, rules, nft_token_id, e.ledger().timestamp()),
        );
        commitment_id
    }

    /* ---------- GET COMMITMENT ---------- */

    pub fn get_commitment(e: Env, commitment_id: String) -> Commitment {
        let commitments: Vec<Commitment> =
            e.storage().instance().get(&COMMITMENTS_KEY).unwrap();

        for c in commitments.iter() {
            if c.commitment_id == commitment_id {
                return c;
            }
        }

        panic!("Commitment not found");
    }

    /* ---------- UPDATE VALUE ---------- */

    pub fn update_value(e: Env, commitment_id: String, new_value: i128) {
        let admin: Address =
            e.storage().instance().get(&ADMIN_KEY).unwrap();
        admin.require_auth();

        let mut commitments: Vec<Commitment> =
            e.storage().instance().get(&COMMITMENTS_KEY).unwrap();

        for mut c in commitments.iter() {
            if c.commitment_id == commitment_id {
                if c.status != String::from_str(&e, "active") {
                    panic!("Not active");
                }

                c.current_value = new_value;

                let loss_percent =
                    (c.amount - new_value) * 100 / c.amount;

                if loss_percent > c.rules.max_loss_percent as i128 {
                    c.status = String::from_str(&e, "violated");
                }

                e.events().publish(
                    (Symbol::short("ValueUpdated"),),
                    (commitment_id, new_value),
                );

                e.storage().instance().set(&COMMITMENTS_KEY, &commitments);
                return;
            }
        }

        panic!("Commitment not found");
    }

    /* ---------- CHECK VIOLATIONS ---------- */

    pub fn check_violations(e: Env, commitment_id: String) -> bool {
        let commitment = read_commitment(&e, &commitment_id)
            .unwrap_or_else(|| panic!("Commitment not found"));

        // Check if past grace period (violated)
        let grace_period_end = c.expires_at + (c.rules.grace_period_days as u64 * 86400);
        if now >= grace_period_end {
            return true;
        }

        let loss_percent =
            (c.amount - c.current_value) * 100 / c.amount;

        loss_percent > c.rules.max_loss_percent as i128
    }

    /* ---------- SETTLEMENT ---------- */

    pub fn settle(e: Env, commitment_id: String) {
        let now = e.ledger().timestamp();

        let mut commitments: Vec<Commitment> =
            e.storage().instance().get(&COMMITMENTS_KEY).unwrap();

        let mut found_index = None;
        let mut commitment_to_settle = None;

        // Find the commitment first
        for (i, c) in commitments.iter().enumerate() {
            if c.commitment_id == commitment_id {
                if c.status != String::from_str(&e, "active") {
                    panic!("Already settled");
                }

                // Check if expired or within grace period
                let grace_period_end = c.expires_at + (c.rules.grace_period_days as u64 * 86400);
                if now < c.expires_at && now >= grace_period_end {
                    panic!("Commitment not expired and grace period has passed");
                }

                found_index = Some(i);
                commitment_to_settle = Some(c.clone());
                break;
            }
        }

        // If commitment not found, panic
        let commitment = match commitment_to_settle {
            Some(c) => c,
            None => panic!("Commitment not found"),
        };

        // Transfer settlement amount
        TokenClient::new(&e, &commitment.asset_address)
            .transfer(
                &e.current_contract_address(),
                &commitment.owner,
                &commitment.current_value,
            );

        // Call NFT contract to mark NFT as settled
        let nft_contract = e
            .storage()
            .instance()
            .get::<_, Address>(&DataKey::NftContract)
            .unwrap_or_else(|| {
                set_reentrancy_guard(&e, false);
                panic!("NFT contract not initialized")
            });
        
        let mut args = Vec::new(&e);
        args.push_back(commitment.nft_token_id.into_val(&e));

        e.invoke_contract::<()>(
            &nft_contract,
            &Symbol::short("Mark_settled"),
            args,
        );

        // Emit settlement event
        e.events().publish(
            (Symbol::short("Commitment Settled"),),
            (
                commitment_id.clone(),
                commitment.owner.clone(),
                commitment.current_value,
                now,
            ),
        );

        // Remove the commitment from the active list
        if let Some(index) = found_index {
            commitments.remove(index as u32);
        }

        e.storage().instance().set(&COMMITMENTS_KEY, &commitments);
    }

    /* ---------- EARLY EXIT ---------- */

    pub fn early_exit(e: Env, commitment_id: String, caller: Address) {
        // Reentrancy protection
        require_no_reentrancy(&e);
        set_reentrancy_guard(&e, true);

        let mut commitments: Vec<Commitment> =
            e.storage().instance().get(&COMMITMENTS_KEY).unwrap();

        for mut c in commitments.iter() {
            if c.commitment_id == commitment_id {
                if caller != c.owner {
                    panic!("Unauthorized");
                }

        // Verify commitment is active
        let active_status = String::from_str(&e, "active");
        if commitment.status != active_status {
            set_reentrancy_guard(&e, false);
            panic!("Commitment is not active");
        }

        // EFFECTS: Calculate penalty using shared utilities
        let penalty_amount =
            SafeMath::penalty_amount(commitment.current_value, commitment.rules.early_exit_penalty);
        let returned_amount = SafeMath::sub(commitment.current_value, penalty_amount);

                TokenClient::new(&e, &c.asset_address)
                    .transfer(
                        &e.current_contract_address(),
                        &c.owner,
                        &payout,
                    );

                c.status = String::from_str(&e, "early_exit");

                e.events().publish(
                    (Symbol::short("EarlyExit"),),
                    (commitment_id, payout),
                );

                e.storage().instance().set(&COMMITMENTS_KEY, &commitments);
                return;
            }
        }

        panic!("Commitment not found");
    }

    /* ---------- ALLOCATE ---------- */

    pub fn allocate(
        e: Env,
        commitment_id: String,
        target_pool: Address,
        amount: i128,
    ) {
        let admin: Address =
            e.storage().instance().get(&ADMIN_KEY).unwrap();
        admin.require_auth();

        let commitments: Vec<Commitment> =
            e.storage().instance().get(&COMMITMENTS_KEY).unwrap();

        for c in commitments.iter() {
            if c.commitment_id == commitment_id {
                if c.status != String::from_str(&e, "active") {
                    panic!("Not active");
                }

                TokenClient::new(&e, &c.asset_address)
                    .transfer(
                        &e.current_contract_address(),
                        &target_pool,
                        &amount,
                    );

                e.events().publish(
                    (Symbol::short("Allocated"),),
                    (commitment_id, target_pool, amount),
                );

                return;
            }
        }

        panic!("Commitment not found");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{symbol_short, testutils::{Address as _, Ledger as _}, Address, Env, String, Vec};

    /* -------------------- DUMMY CONTRACTS -------------------- */

    #[contract]
    struct DummyTokenContract;

    #[contractimpl]
    impl DummyTokenContract {
        pub fn transfer(_from: Address, _to: Address, _amount: i128) {
            // record transfer for assertions
        }
    }

    #[contract]
    struct DummyNFTContract;

    #[contractimpl]
    impl DummyNFTContract {
        pub fn mint(_owner: Address, _commitment_id: String) -> u32 {
            1
        }

    pub fn settle(_e: Env, _token_id: u32) {
        // record settled
    }
    }

    /* -------------------- HELPER FUNCTIONS -------------------- */

    fn create_test_commitment(e: &Env, id: &str, owner: Address, expired: bool) -> Commitment {
        let now = e.ledger().timestamp();
        let (created_at, expires_at) = if expired {
            (now - 10000, now - 100)
        } else {
            (now, now + 10000)
        };

        Commitment {
            commitment_id: String::from_str(e, id),
            owner,
            nft_token_id: 1,
            rules: CommitmentRules {
                duration_days: 7,
                max_loss_percent: 20,
                commitment_type: String::from_str(e, "balanced"),
                early_exit_penalty: 5,
                min_fee_threshold: 0,
                grace_period_days: 3,
            },
            amount: 1000,
            asset_address: Address::generate(e),
            created_at,
            expires_at,
            current_value: 1000,
            status: String::from_str(e, "active"),
        }
    }

    fn setup_test_env() -> (Env, Address, Address, Address) {
        let e = Env::default();
        e.ledger().set(soroban_sdk::testutils::LedgerInfo {
            timestamp: 10000000,
            protocol_version: 21,
            sequence_number: 1,
            network_id: [0u8; 32],
            base_reserve: 10,
            min_temp_entry_ttl: 16,
            min_persistent_entry_ttl: 4096,
            max_entry_ttl: 6312000,
        });
        let token_id = e.register_contract(None, DummyTokenContract);
        let nft_id = e.register_contract(None, DummyNFTContract);
        let core_id = e.register_contract(None, CommitmentCoreContract);

        (e, token_id, nft_id, core_id)
    }

    /* -------------------- TESTS -------------------- */

    #[test]
    fn test_initialize() {
        let e = Env::default();
        e.mock_all_auths();
        let admin = Address::generate(&e);
        let nft_contract = Address::generate(&e);
        let contract_id = e.register_contract(None, CommitmentCoreContract);
        let client = CommitmentCoreContractClient::new(&e, &contract_id);
        
        client.initialize(&admin, &nft_contract);
        
        let stored_admin: Address = e.as_contract(&contract_id, || e.storage().instance().get(&symbol_short!("ADMIN")).unwrap());
        let stored_nft: Address = e.as_contract(&contract_id, || e.storage().instance().get(&symbol_short!("NFT")).unwrap());
        
        assert_eq!(stored_admin, admin);
        assert_eq!(stored_nft, nft_contract);
    }

    #[test]
    fn test_settlement_flow_basic() {
        let (e, token_addr, nft_addr, core_addr) = setup_test_env();
        let client = CommitmentCoreContractClient::new(&e, &core_addr);
        e.mock_all_auths();
        
        let owner = Address::generate(&e);
        let admin = Address::generate(&e);
        
        // Initialize contract
        client.initialize(&admin, &nft_addr);
        
        // Create an expired commitment
        let now = e.ledger().timestamp();
        let commitment = Commitment {
            commitment_id: String::from_str(&e, "settle_test_1"),
            owner: owner.clone(),
            nft_token_id: 101,
            rules: CommitmentRules {
                duration_days: 1,
                max_loss_percent: 10,
                commitment_type: String::from_str(&e, "safe"),
                early_exit_penalty: 5,
                min_fee_threshold: 0,
                grace_period_days: 2,
            },
            amount: 5000,
            asset_address: token_addr.clone(),
            created_at: now - 100000,
            expires_at: now - 1000,
            current_value: 5500,
            status: String::from_str(&e, "active"),
        };
        
        let mut commitments: Vec<Commitment> = Vec::new(&e);
        commitments.push_back(commitment.clone());
        e.as_contract(&core_addr, || e.storage().instance().set(&symbol_short!("COMMS"), &commitments));
        
        // Settle the commitment
        client.settle(&String::from_str(&e, "settle_test_1"));
        
        // Verify settlement (status changed to settled)
        let updated_commitments: Vec<Commitment> = e.as_contract(&core_addr, || e.storage().instance().get(&symbol_short!("COMMS")).unwrap());
        assert_eq!(updated_commitments.len(), 1); 
        assert_eq!(updated_commitments.get(0).unwrap().status, String::from_str(&e, "settled"));
    }

    #[test]
    #[should_panic(expected = "Commitment not expired")]
    fn test_settlement_rejects_active_commitment() {
        let (e, _token_addr, nft_addr, core_addr) = setup_test_env();
        let client = CommitmentCoreContractClient::new(&e, &core_addr);
        e.mock_all_auths();
        
        let owner = Address::generate(&e);
        let admin = Address::generate(&e);
        
        // Initialize
        client.initialize(&admin, &nft_addr);
        
        // Create non-expired commitment
        let commitment = create_test_commitment(&e, "not_expired", owner.clone(), false);
        
        let mut commitments: Vec<Commitment> = Vec::new(&e);
        commitments.push_back(commitment);
        e.as_contract(&core_addr, || e.storage().instance().set(&symbol_short!("COMMS"), &commitments));
        
        // Try to settle; should panic
        client.settle(&String::from_str(&e, "not_expired"));
    }

    #[test]
    #[should_panic(expected = "Commitment not found")]
    fn test_settlement_commitment_not_found() {
        let (e, _token_addr, nft_addr, core_addr) = setup_test_env();
        let client = CommitmentCoreContractClient::new(&e, &core_addr);
        e.mock_all_auths();
        
        let admin = Address::generate(&e);
        
        // Initialize
        client.initialize(&admin, &nft_addr);
        
        // Try to settle non-existent commitment
        client.settle(&String::from_str(&e, "nonexistent"));
    }

    #[test]
    #[should_panic(expected = "Already settled")]
    fn test_settlement_already_settled() {
        let (e, _token_addr, nft_addr, core_addr) = setup_test_env();
        let client = CommitmentCoreContractClient::new(&e, &core_addr);
        e.mock_all_auths();
        
        let owner = Address::generate(&e);
        let admin = Address::generate(&e);
        
        // Initialize
        client.initialize(&admin, &nft_addr);
        
        // Create expired commitment already settled
        let _now = e.ledger().timestamp();
        let mut commitment = create_test_commitment(&e, "already_settled", owner.clone(), true);
        commitment.status = String::from_str(&e, "settled");
        
        let mut commitments: Vec<Commitment> = Vec::new(&e);
        commitments.push_back(commitment);
        e.as_contract(&core_addr, || e.storage().instance().set(&symbol_short!("COMMS"), &commitments));
        
        // Try to settle already settled commitment; should panic
        client.settle(&String::from_str(&e, "already_settled"));
    }

    #[test]
    fn test_expiration_check_expired() {
        let (e, _token_addr, nft_addr, core_addr) = setup_test_env();
        let client = CommitmentCoreContractClient::new(&e, &core_addr);
        e.mock_all_auths();
        
        let admin = Address::generate(&e);
        let owner = Address::generate(&e);
        
        // Initialize
        client.initialize(&admin, &nft_addr);
        
        // Create expired commitment
        let commitment = create_test_commitment(&e, "expired_check", owner, true);
        let mut commitments: Vec<Commitment> = Vec::new(&e);
        commitments.push_back(commitment);
        e.as_contract(&core_addr, || e.storage().instance().set(&symbol_short!("COMMS"), &commitments));
        
        // Check violations
        let is_violated = client.check_violations(&String::from_str(&e, "expired_check"));
        // Note: is_violated is true only if past grace period (3 days)
        // expired_check is only 100s past expires_at, so it's NOT violated yet
        assert!(!is_violated);
    }

    #[test]
    fn test_expiration_check_not_expired() {
        let (e, _token_addr, nft_addr, core_addr) = setup_test_env();
        let client = CommitmentCoreContractClient::new(&e, &core_addr);
        e.mock_all_auths();
        
        let admin = Address::generate(&e);
        let owner = Address::generate(&e);
        
        // Initialize
        client.initialize(&admin, &nft_addr);
        
        // Create active (non-expired) commitment
        let commitment = create_test_commitment(&e, "not_expired_check", owner, false);
        let mut commitments: Vec<Commitment> = Vec::new(&e);
        commitments.push_back(commitment);
        e.as_contract(&core_addr, || e.storage().instance().set(&symbol_short!("COMMS"), &commitments));
        
        // Check violations
        let is_violated = client.check_violations(&String::from_str(&e, "not_expired_check"));
        assert!(!is_violated);
    }

    #[test]
    fn test_expiration_check_violated() {
        let (e, _token_addr, nft_addr, core_addr) = setup_test_env();
        let client = CommitmentCoreContractClient::new(&e, &core_addr);
        e.mock_all_auths();
        
        let admin = Address::generate(&e);
        let owner = Address::generate(&e);
        
        // Initialize
        client.initialize(&admin, &nft_addr);
        
        // Create commitment past grace period
        let now = e.ledger().timestamp();
        let commitment = Commitment {
            commitment_id: String::from_str(&e, "violated_check"),
            owner,
            nft_token_id: 1,
            rules: CommitmentRules {
                duration_days: 7,
                max_loss_percent: 20,
                commitment_type: String::from_str(&e, "balanced"),
                early_exit_penalty: 5,
                min_fee_threshold: 0,
                grace_period_days: 1,
            },
            amount: 1000,
            asset_address: Address::generate(&e),
            created_at: now - 1000000,
            expires_at: now - 200000, // past 1 day grace period (86400)
            current_value: 1000,
            status: String::from_str(&e, "active"),
        };
        let mut commitments: Vec<Commitment> = Vec::new(&e);
        commitments.push_back(commitment);
        e.as_contract(&core_addr, || e.storage().instance().set(&symbol_short!("COMMS"), &commitments));
        
        // Check violations
        let is_violated = client.check_violations(&String::from_str(&e, "violated_check"));
        assert!(is_violated);
    }

    #[test]
    fn test_asset_transfer_on_settlement() {
        let (e, token_addr, nft_addr, core_addr) = setup_test_env();
        let client = CommitmentCoreContractClient::new(&e, &core_addr);
        e.mock_all_auths();
        
        let owner = Address::generate(&e);
        let admin = Address::generate(&e);
        let settlement_amount = 7500i128;
        
        // Initialize
        client.initialize(&admin, &nft_addr);
        
        // Create expired commitment
        let now = e.ledger().timestamp();
        let commitment = Commitment {
            commitment_id: String::from_str(&e, "transfer_test"),
            owner: owner.clone(),
            nft_token_id: 102,
            rules: CommitmentRules {
                duration_days: 5,
                max_loss_percent: 15,
                commitment_type: String::from_str(&e, "growth"),
                early_exit_penalty: 10,
                min_fee_threshold: 0,
                grace_period_days: 1,
            },
            amount: 5000,
            asset_address: token_addr.clone(),
            created_at: now - 500000,
            expires_at: now - 10000,
            current_value: settlement_amount,
            status: String::from_str(&e, "active"),
        };
        
        let mut commitments: Vec<Commitment> = Vec::new(&e);
        commitments.push_back(commitment);
        e.as_contract(&core_addr, || e.storage().instance().set(&symbol_short!("COMMS"), &commitments));
        
        // Settle - this will call token transfer
        client.settle(&String::from_str(&e, "transfer_test"));
        
        // Verify the commitment status updated
        let updated_commitments: Vec<Commitment> = e.as_contract(&core_addr, || e.storage().instance().get(&symbol_short!("COMMS")).unwrap());
        assert_eq!(updated_commitments.len(), 1);
        assert_eq!(updated_commitments.get(0).unwrap().status, String::from_str(&e, "settled"));
    }

    #[test]
    fn test_settlement_with_different_values() {
        let (e, token_addr, nft_addr, core_addr) = setup_test_env();
        let client = CommitmentCoreContractClient::new(&e, &core_addr);
        e.mock_all_auths();
        
        let owner = Address::generate(&e);
        let admin = Address::generate(&e);
        
        // Initialize
        client.initialize(&admin, &nft_addr);
        
        let now = e.ledger().timestamp();
        
        // Test case 1: Settlement with gain
        let commitment_gain = Commitment {
            commitment_id: String::from_str(&e, "gain_test"),
            owner: owner.clone(),
            nft_token_id: 201,
            rules: CommitmentRules {
                duration_days: 30,
                max_loss_percent: 5,
                commitment_type: String::from_str(&e, "stable"),
                early_exit_penalty: 2,
                min_fee_threshold: 0,
                grace_period_days: 7,
            },
            amount: 10000,
            asset_address: token_addr.clone(),
            created_at: now - 2592000,
            expires_at: now - 1,
            current_value: 11000,
            status: String::from_str(&e, "active"),
        };
        
        let mut commitments: Vec<Commitment> = Vec::new(&e);
        commitments.push_back(commitment_gain);
        e.as_contract(&core_addr, || e.storage().instance().set(&symbol_short!("COMMS"), &commitments));
        
        client.settle(&String::from_str(&e, "gain_test"));
        
        let updated: Vec<Commitment> = e.as_contract(&core_addr, || e.storage().instance().get(&symbol_short!("COMMS")).unwrap());
        assert_eq!(updated.get(0).unwrap().status, String::from_str(&e, "settled"));
    }

    #[test]
    fn test_cross_contract_nft_settlement() {
        let (e, token_addr, nft_addr, core_addr) = setup_test_env();
        let client = CommitmentCoreContractClient::new(&e, &core_addr);
        e.mock_all_auths();
        
        let owner = Address::generate(&e);
        let admin = Address::generate(&e);
        let nft_token_id = 999u32;
        
        // Initialize
        client.initialize(&admin, &nft_addr);
        
        // Create expired commitment with specific NFT ID
        let now = e.ledger().timestamp();
        let commitment = Commitment {
            commitment_id: String::from_str(&e, "nft_cross_contract"),
            owner: owner.clone(),
            nft_token_id,
            rules: CommitmentRules {
                duration_days: 1,
                max_loss_percent: 10,
                commitment_type: String::from_str(&e, "safe"),
                early_exit_penalty: 5,
                min_fee_threshold: 0,
                grace_period_days: 1,
            },
            amount: 2000,
            asset_address: token_addr.clone(),
            created_at: now - 100000,
            expires_at: now - 1000,
            current_value: 2000,
            status: String::from_str(&e, "active"),
        };
        
        let mut commitments: Vec<Commitment> = Vec::new(&e);
        commitments.push_back(commitment);
        e.as_contract(&core_addr, || e.storage().instance().set(&symbol_short!("COMMS"), &commitments));
        
        // Settle - this will invoke NFT contract
        client.settle(&String::from_str(&e, "nft_cross_contract"));
        
        // Verify settlement completed (status updated)
        let updated_commitments: Vec<Commitment> = e.as_contract(&core_addr, || e.storage().instance().get(&symbol_short!("COMMS")).unwrap());
        assert_eq!(updated_commitments.get(0).unwrap().status, String::from_str(&e, "settled"));
    }

    #[test]
    fn test_settlement_removes_commitment_status() {
        let (e, token_addr, nft_addr, core_addr) = setup_test_env();
        let client = CommitmentCoreContractClient::new(&e, &core_addr);
        e.mock_all_auths();
        
        let owner = Address::generate(&e);
        let admin = Address::generate(&e);
        
        // Initialize
        client.initialize(&admin, &nft_addr);
        
        // Create multiple commitments
        let now = e.ledger().timestamp();
        let commitment1 = Commitment {
            commitment_id: String::from_str(&e, "multi_1"),
            owner: owner.clone(),
            nft_token_id: 301,
            rules: CommitmentRules {
                duration_days: 1,
                max_loss_percent: 10,
                commitment_type: String::from_str(&e, "safe"),
                early_exit_penalty: 5,
                min_fee_threshold: 0,
                grace_period_days: 1,
            },
            amount: 1000,
            asset_address: token_addr.clone(),
            created_at: now - 100000,
            expires_at: now - 1000,
            current_value: 1000,
            status: String::from_str(&e, "active"),
        };
        
        let commitment2 = Commitment {
            commitment_id: String::from_str(&e, "multi_2"),
            owner: owner.clone(),
            nft_token_id: 302,
            rules: CommitmentRules {
                duration_days: 30,
                max_loss_percent: 20,
                commitment_type: String::from_str(&e, "growth"),
                early_exit_penalty: 10,
                min_fee_threshold: 0,
                grace_period_days: 5,
            },
            amount: 2000,
            asset_address: token_addr.clone(),
            created_at: now,
            expires_at: now + 2592000,
            current_value: 2000,
            status: String::from_str(&e, "active"),
        };
        
        let mut commitments: Vec<Commitment> = Vec::new(&e);
        commitments.push_back(commitment1);
        commitments.push_back(commitment2);
        e.as_contract(&core_addr, || e.storage().instance().set(&symbol_short!("COMMS"), &commitments));
        
        // Settle first commitment
        client.settle(&String::from_str(&e, "multi_1"));
        
        // Verify status updated (still in list but not active)
        let updated_commitments: Vec<Commitment> = e.as_contract(&core_addr, || e.storage().instance().get(&symbol_short!("COMMS")).unwrap());
        assert_eq!(updated_commitments.len(), 2); 
        
        for c in updated_commitments.iter() {
            if c.commitment_id == String::from_str(&e, "multi_1") {
                assert_eq!(c.status, String::from_str(&e, "settled"));
            } else {
                assert_eq!(c.status, String::from_str(&e, "active"));
            }
        }
    }
}
mod tests;
mod tests;
