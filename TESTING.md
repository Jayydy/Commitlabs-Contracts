# Testing Documentation

This document describes the comprehensive test suite for CommitLabs Contracts.

## Overview

The test suite covers all three contracts in the CommitLabs protocol:
- **Commitment NFT Contract** - NFT representing liquidity commitments
- **Commitment Core Contract** - Core contract managing commitment lifecycle
- **Attestation Engine Contract** - Contract for verifying and recording commitment health

## Test Structure

### Unit Tests

Each contract has its own unit test file:
- `contracts/commitment_nft/src/tests.rs` - NFT contract tests
- `contracts/commitment_core/src/tests.rs` - Core contract tests
- `contracts/attestation_engine/src/tests.rs` - Attestation engine tests

### Integration Tests

Cross-contract interaction tests are located in:
- `tests/integration_tests.rs` - Integration tests for all contracts

## Running Tests

### Run All Tests

```bash
cargo test
```

### Run Tests for Specific Contract

```bash
# NFT Contract
cd contracts/commitment_nft
cargo test

# Core Contract
cd contracts/commitment_core
cargo test

# Attestation Engine
cd contracts/attestation_engine
cargo test
```

### Run Integration Tests

```bash
cargo test --test integration_tests
```

### Run with Output

```bash
cargo test -- --nocapture
```

## Running Tests

### Run All Tests

```bash
cargo test
```

### Run Tests for Specific Contract

```bash
# NFT Contract
cargo test -p commitment_nft

# Core Contract  
cargo test -p commitment_core

# Attestation Engine
cargo test -p attestation_engine

# Integration Tests
cargo test -p integration_tests
```

### Run with Output

```bash
cargo test -- --nocapture
```

## Test Coverage Reports

### Using cargo-tarpaulin (recommended)

Install tarpaulin:
```bash
cargo install cargo-tarpaulin
```

Generate coverage report:
```bash
cargo tarpaulin --out Html --output-dir coverage
```

View the report:
```bash
open coverage/tarpaulin-report.html
```

### Using cargo-llvm-cov (alternative)

Install llvm-cov:
```bash
cargo install cargo-llvm-cov
```

Generate coverage:
```bash
cargo llvm-cov --html --output-dir coverage
```

## Test Coverage Statistics

### Commitment NFT Contract Tests

#### Basic Functionality
- ✅ Initialize contract
- ✅ Mint NFT with metadata
- ✅ Get metadata by token ID
- ✅ Get owner of NFT
- ✅ Transfer NFT to new owner
- ✅ Check if NFT is active
- ✅ Settle NFT after maturity

#### Edge Cases
- ✅ Mint with zero duration
- ✅ Mint with maximum values
- ✅ Get metadata for nonexistent token
- ✅ Transfer by non-owner (should fail)
- ✅ Settle before expiration (should fail)
- ✅ Transfer after settlement (should fail)

#### Access Control
- ✅ Only admin can mint
- ✅ Only owner can transfer
- ✅ Only admin can settle

#### Event Emission
- ✅ Mint emits event
- ✅ Transfer emits event

### Commitment Core Contract Tests

#### Basic Functionality
- ✅ Initialize contract
- ✅ Create commitment with rules
- ✅ Get commitment details
- ✅ Update commitment value
- ✅ Check for violations
- ✅ Settle commitment at maturity
- ✅ Early exit with penalty
- ✅ Allocate liquidity

#### Validation Tests
- ✅ Reject zero amount commitments
- ✅ Reject negative amounts
- ✅ Reject zero duration
- ✅ Reject max_loss_percent > 100

#### Violation Detection
- ✅ Detect max loss violation
- ✅ Detect expiration violation
- ✅ Mark commitment as violated

#### Edge Cases
- ✅ Create multiple commitments
- ✅ Update value with maximum values
- ✅ Early exit after settlement (should fail)
- ✅ Allocate with invalid amount (should fail)

#### Access Control
- ✅ Only admin can update value (by default)
- ✅ Only owner can early exit
- ✅ Only authorized allocator can allocate
- ✅ Only admin can set authorized allocator

#### Event Emission
- ✅ Create commitment emits event
- ✅ Update value emits event

### Attestation Engine Contract Tests

#### Basic Functionality
- ✅ Initialize contract
- ✅ Record attestation
- ✅ Get all attestations for commitment
- ✅ Get health metrics
- ✅ Verify compliance
- ✅ Record fee generation
- ✅ Record drawdown
- ✅ Calculate compliance score

#### Edge Cases
- ✅ Attest with empty data
- ✅ Record zero drawdown
- ✅ Record maximum drawdown
- ✅ Track multiple commitments
- ✅ Accumulate fees over time

#### Validation Tests
- ✅ Reject zero fee amount
- ✅ Reject negative fee amount

#### Compliance Testing
- ✅ Verify compliant commitments
- ✅ Detect non-compliant commitments
- ✅ Calculate score with violations

#### Event Emission
- ✅ Attest emits event
- ✅ Record fees emits event
- ✅ Record drawdown emits event

### Integration Tests

#### Cross-Contract Flows
- ✅ Create commitment flow (Core + NFT + Attestation)
- ✅ Value update and attestation flow
- ✅ Violation detection flow across contracts
- ✅ Settlement flow with attestations
- ✅ Early exit flow with attestations

## Test Fixtures

Each test file includes a `TestFixture` helper struct that:
- Sets up the test environment
- Creates necessary addresses
- Initializes contracts
- Provides helper methods for creating test data

Example:
```rust
pub struct TestFixture {
    pub env: Env,
    pub admin: Address,
    pub owner: Address,
    // ... other fields
}

impl TestFixture {
    pub fn setup() -> Self {
        // Initialize test environment
    }
}
```

## Best Practices

1. **Isolation**: Each test is independent and doesn't rely on other tests
2. **Clear Naming**: Test names clearly describe what they're testing
3. **Edge Cases**: Tests cover boundary conditions and error cases
4. **Access Control**: All access control scenarios are tested
5. **Event Verification**: Events are verified where applicable
6. **Integration**: Cross-contract interactions are tested

## Test Utilities

### Soroban Test Utilities

The tests use Soroban SDK test utilities:
- `Env::default()` - Creates a test environment
- `Address::generate()` - Generates test addresses
- `set_authorized()` and `require_auth()` - Mock authentication

### Common Test Patterns

#### Testing Initialization
```rust
#[test]
fn test_initialize() {
    let fixture = TestFixture::setup();
    // Test initialization
}
```

#### Testing Error Cases
```rust
#[test]
#[should_panic(expected = "error message")]
fn test_invalid_input() {
    // Test that should panic
}
```

#### Testing Access Control
```rust
#[test]
#[should_panic(expected = "unauthorized")]
fn test_unauthorized_access() {
    // Test unauthorized operation
}
```

## Continuous Integration

Tests should be run in CI/CD pipeline:
1. On every pull request
2. Before merging to main
3. Before deployment

## Coverage Goals

- **Unit Test Coverage**: > 90%
- **Integration Test Coverage**: All critical flows
- **Edge Case Coverage**: All boundary conditions
- **Error Case Coverage**: All error paths

## Debugging Tests

### Print Debug Information
```bash
cargo test -- --nocapture --test-threads=1
```

### Run Single Test
```bash
cargo test test_name
```

### Run Tests Matching Pattern
```bash
cargo test pattern
```

## Future Improvements

- [ ] Add gas/resource usage tests
- [ ] Add fuzzing tests
- [ ] Add property-based tests
- [ ] Generate test coverage reports
- [ ] Add performance benchmarks

## Notes

- Tests use mock authentication - no real blockchain required
- Tests run in isolated environments
- All tests should be deterministic
- Tests may need updates as contracts evolve
