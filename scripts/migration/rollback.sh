#!/usr/bin/env bash
# Rollback helper for migration (#64).
# Restore previous contract id in deployments and point NFT/core back.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
NETWORK="${1:-testnet}"
PREVIOUS_CORE_ID="${2:-}"

if [[ -z "$PREVIOUS_CORE_ID" ]]; then
  echo "Usage: $0 <network> <previous_core_contract_id>"
  echo "  Points deployments and operational config back to previous core contract."
  exit 1
fi

DEPLOYMENTS="$ROOT_DIR/deployments/${NETWORK}.json"
if [[ ! -f "$DEPLOYMENTS" ]]; then
  echo "No deployment file: $DEPLOYMENTS"
  exit 1
fi

echo "Rollback: set commitment_core to $PREVIOUS_CORE_ID for $NETWORK"
if command -v jq &>/dev/null; then
  jq --arg id "$PREVIOUS_CORE_ID" '.contracts.commitment_core = $id' "$DEPLOYMENTS" > "${DEPLOYMENTS}.tmp"
  mv "${DEPLOYMENTS}.tmp" "$DEPLOYMENTS"
  echo "Updated $DEPLOYMENTS"
else
  echo "jq required to edit JSON. Manually set contracts.commitment_core to $PREVIOUS_CORE_ID in $DEPLOYMENTS"
fi
echo "If NFT contract points to core, invoke set_core_contract with $PREVIOUS_CORE_ID."
