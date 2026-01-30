#!/usr/bin/env bash
# Import transformed state into a new contract (#64).
# Deploy new WASM and initialize from migrated state.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

TRANSFORMED_FILE="${1:-}"
if [[ -z "$TRANSFORMED_FILE" || ! -f "$TRANSFORMED_FILE" ]]; then
  echo "Usage: $0 <transformed_state.json>"
  echo "  Run export_state.sh -> transform_state.sh -> validate_state.sh first."
  exit 1
fi

if [[ -f "$ROOT_DIR/config/deploy.env" ]]; then
  # shellcheck disable=SC1091
  source "$ROOT_DIR/config/deploy.env"
fi

NETWORK="${NETWORK:-testnet}"
if [[ -z "${STELLAR_ACCOUNT:-}" ]] || [[ -z "${STELLAR_ADMIN_ADDRESS:-}" ]]; then
  echo "STELLAR_ACCOUNT and STELLAR_ADMIN_ADDRESS required (config/deploy.env or env)."
  exit 1
fi

if [[ -z "${STELLAR_RPC_URL:-}" ]]; then
  if [[ "$NETWORK" == "testnet" ]]; then
    STELLAR_RPC_URL="https://soroban-testnet.stellar.org"
  else
    STELLAR_RPC_URL="https://soroban-mainnet.stellar.org"
  fi
fi
if [[ -z "${STELLAR_NETWORK_PASSPHRASE:-}" ]]; then
  if [[ "$NETWORK" == "testnet" ]]; then
    STELLAR_NETWORK_PASSPHRASE="Test SDF Network ; September 2015"
  else
    STELLAR_NETWORK_PASSPHRASE="Public Global Stellar Network ; September 2015"
  fi
fi

echo "Import: deploy new core contract and initialize from $TRANSFORMED_FILE"
"$ROOT_DIR/scripts/build-contracts.sh"

CORE_WASM="$ROOT_DIR/target/wasm32v1-none/release/commitment_core.wasm"
NFT_ID=$(jq -r '.nft_contract // empty' "$TRANSFORMED_FILE")
ADMIN=$(jq -r '.admin // empty' "$TRANSFORMED_FILE")
if [[ -z "$ADMIN" ]]; then
  ADMIN="$STELLAR_ADMIN_ADDRESS"
fi
if [[ -z "$NFT_ID" ]]; then
  echo "nft_contract missing in state; use existing deployment."
  if [[ -f "$ROOT_DIR/deployments/${NETWORK}.json" ]]; then
    NFT_ID=$(jq -r '.contracts.commitment_nft // empty' "$ROOT_DIR/deployments/${NETWORK}.json")
  fi
fi

NEW_CORE_ID=$(soroban contract deploy -q \
  --wasm "$CORE_WASM" \
  --source-account "$STELLAR_ACCOUNT" \
  --rpc-url "$STELLAR_RPC_URL" \
  --network-passphrase "$STELLAR_NETWORK_PASSPHRASE")

echo "Deployed new commitment_core: $NEW_CORE_ID"
soroban contract invoke -q \
  --id "$NEW_CORE_ID" \
  --source-account "$STELLAR_ACCOUNT" \
  --rpc-url "$STELLAR_RPC_URL" \
  --network-passphrase "$STELLAR_NETWORK_PASSPHRASE" \
  initialize --_admin "$ADMIN" --_nft_contract "$NFT_ID"

echo "Import complete. New core contract: $NEW_CORE_ID"
echo "Update deployments/${NETWORK}.json and NFT core_contract to $NEW_CORE_ID as needed."
