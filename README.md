# CommitLabs Contracts

Stellar Soroban smart contracts for the CommitLabs protocol.

## Overview

This directory contains the core smart contracts for CommitLabs:

- **commitment_nft**: NFT contract representing liquidity commitments
- **commitment_core**: Core contract for creating and managing commitments
- **attestation_engine**: Contract for verifying and recording commitment health

## Prerequisites

- Rust (latest stable version)
- Stellar Soroban CLI tools
- Cargo

## Building

```bash
# Build all contracts
cargo build --target wasm32-unknown-unknown --release

# Build individual contract
cd contracts/commitment_nft
cargo build --target wasm32-unknown-unknown --release
```

## Testing

```bash
# Run all tests
cargo test

# Test specific contract
cd contracts/commitment_nft
cargo test
```

## Deployment

```bash
# Deploy to testnet
soroban contract deploy \
  --wasm target/wasm32-unknown-unknown/release/commitment_nft.wasm \
  --source <your-key> \
  --network testnet

# Deploy to mainnet (when ready)
soroban contract deploy \
  --wasm target/wasm32-unknown-unknown/release/commitment_nft.wasm \
  --source <your-key> \
  --network mainnet
```

## Contract Structure

### Commitment NFT (`commitment_nft`)

Represents a liquidity commitment as an NFT. Each NFT contains:
- Commitment metadata (duration, risk tolerance, type)
- Owner information
- Active status

### Commitment Core (`commitment_core`)

Manages the lifecycle of commitments:
- Creation with rules
- Value tracking
- Settlement at maturity
- Early exit handling

### Attestation Engine (`attestation_engine`)

Continuously verifies commitment health:
- Records attestations
- Tracks health metrics
- Verifies compliance
- Calculates compliance scores

## Development Status

⚠️ **Early Development**: These contracts are basic skeletons with placeholder implementations. Core functionality needs to be implemented.

## Next Steps

- [ ] Implement storage for all contracts
- [ ] Add proper access control
- [ ] Implement commitment rule enforcement
- [ ] Add integration with Stellar asset contracts
- [ ] Implement allocation logic
- [ ] Add comprehensive tests
- [ ] Security audit

## License

MIT

