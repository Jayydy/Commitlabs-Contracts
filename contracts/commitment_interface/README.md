# 📖 Integration Guide: Commitment Interface

This guide provides the technical specifications and integration patterns for the `CommitmentInterface` ABI (v1).

---

## 1. Interface Overview

The `CommitmentInterface` provides a standardized way to manage feedback-driven commitments on the Soroban network.

### Metadata & Constants

* **Interface Version:** `1`
* **Event Symbols:** `created`, `revoked`

### Function Signatures

| Function | Arguments | Return Type | Description |
|:---------|:----------|:------------|:------------|
| `initialize` | `env: Env, admin: Address` | `Result<(), Error>` | Authorizes the contract administrator. |
| `create_commitment` | `env: Env, spec: CommitmentSpec` | `Result<u64, Error>` | Records a new commitment and increments the ID. |
| `get_commitment` | `env: Env, id: u64` | `Result<CommitmentSpec, Error>` | Fetches commitment data from persistent storage. |
| `revoke_commitment` | `env: Env, id: u64` | `Result<(), Error>` | Deactivates or removes an existing commitment. |

### Data Structures (Rust)

```rust
pub struct CommitmentSpec {
    pub provider: Address,      
    pub amount: i128,           
    pub unlock_date: u64,       
    pub metadata_hash: BytesN<32>,
}
```

---

## 2. Frontend Integration (TypeScript)

The TypeScript bindings are located in the root `/bindings` directory.

### Build Workflow

Before use, the definitions must be compiled into JavaScript:

```bash
cd bindings
npm install
npm run build
```

### Usage Example

```typescript
import { Contract, Networks } from '../bindings'; 

const contract = new Contract({
  networkPassphrase: Networks.Testnet, 
  rpcUrl: 'https://soroban-testnet.stellar.org',
});

// Example: Calling get_commitment
async function checkCommitment(id: bigint) {
  try {
    const commitment = await contract.get_commitment({ id });
    console.log('Commitment Details:', commitment);
  } catch (err) {
    console.error("Error fetching commitment:", err);
  }
}
```

---

## 3. Error Reference

Integration errors return a `u32` code mapped to the following definitions:

| Code | Name | Meaning | Recommended Action |
|:-----|:-----|:--------|:-------------------|
| 1 | `NotFound` | Requested ID does not exist in storage. | Verify the ID exists via `get_commitment`. |
| 2 | `Unauthorized` | Caller failed `require_auth()` check. | Ensure transaction is signed by the correct Address. |
| 3 | `AlreadyInitialized` | `initialize` called more than once. | Check contract state before initialization. |

---

## 4. Maintenance & Synchronization

To update the interface when the Rust code changes:

1. **Build WASM:**
   ```bash
   stellar contract build
   ```

2. **Sync Bindings:**
   ```bash
   stellar contract bindings typescript \
     --wasm target/wasm32v1-none/release/commitment_interface.wasm \
     --output-dir bindings \
     --overwrite
   ```

3. **Rebuild Types:**
   ```bash
   cd bindings && npm run build
   ```

---

## Additional Resources

- [Soroban Documentation](https://soroban.stellar.org/docs)
- [Stellar CLI Reference](https://developers.stellar.org/docs/tools/developer-tools)

---
