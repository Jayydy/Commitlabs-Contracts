#!/usr/bin/env bash
# Export contract state for migration (#64).
# Uses Soroban CLI to invoke getters and persist output to JSON.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

if [[ -f "$ROOT_DIR/config/deploy.env" ]]; then
  # shellcheck disable=SC1091
  source "$ROOT_DIR/config/deploy.env"
fi

NETWORK="${1:-${NETWORK:-testnet}}"
OUTPUT_DIR="${2:-$ROOT_DIR/migration/export}"
CONTRACT_CORE="${CORE_CONTRACT_ID:-}"

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

if [[ -z "$CONTRACT_CORE" && -f "$ROOT_DIR/deployments/${NETWORK}.json" ]]; then
  CONTRACT_CORE=$(jq -r '.contracts.commitment_core // empty' "$ROOT_DIR/deployments/${NETWORK}.json")
fi

mkdir -p "$OUTPUT_DIR"
TIMESTAMP=$(date -u +"%Y%m%dT%H%M%SZ")
OUTPUT_FILE="$OUTPUT_DIR/state_${NETWORK}_${TIMESTAMP}.json"

echo "Exporting state from network=$NETWORK core=$CONTRACT_CORE to $OUTPUT_FILE"

# Export core contract state (getters). Soroban CLI returns raw values.
STATE="{}"
if [[ -n "$CONTRACT_CORE" ]] && command -v jq &>/dev/null; then
  ADMIN=$(soroban contract invoke --send no --rpc-url "$STELLAR_RPC_URL" --network-passphrase "$STELLAR_NETWORK_PASSPHRASE" --id "$CONTRACT_CORE" get_admin 2>/dev/null || echo "")
  NFT=$(soroban contract invoke --send no --rpc-url "$STELLAR_RPC_URL" --network-passphrase "$STELLAR_NETWORK_PASSPHRASE" --id "$CONTRACT_CORE" get_nft_contract 2>/dev/null || echo "")
  TOTAL=$(soroban contract invoke --send no --rpc-url "$STELLAR_RPC_URL" --network-passphrase "$STELLAR_NETWORK_PASSPHRASE" --id "$CONTRACT_CORE" get_total_commitments 2>/dev/null || echo "0")
  TVL=$(soroban contract invoke --send no --rpc-url "$STELLAR_RPC_URL" --network-passphrase "$STELLAR_NETWORK_PASSPHRASE" --id "$CONTRACT_CORE" get_total_value_locked 2>/dev/null || echo "0")
  STATE=$(jq -n \
    --arg network "$NETWORK" \
    --arg core "$CONTRACT_CORE" \
    --arg admin "${ADMIN:-}" \
    --arg nft "${NFT:-}" \
    --arg total_commitments "${TOTAL:-0}" \
    --arg total_value_locked "${TVL:-0}" \
    '{network: $network, contract_core: $core, admin: $admin, nft_contract: $nft, total_commitments: $total_commitments, total_value_locked: $total_value_locked}')
fi

echo "$STATE" > "$OUTPUT_FILE"
echo "Exported to $OUTPUT_FILE"
echo "$OUTPUT_FILE"
