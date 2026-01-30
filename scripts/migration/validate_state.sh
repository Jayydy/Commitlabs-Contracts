#!/usr/bin/env bash
# Validate transformed state before import (#64).
set -euo pipefail

INPUT_FILE="${1:-}"

if [[ -z "$INPUT_FILE" || ! -f "$INPUT_FILE" ]]; then
  echo "Usage: $0 <transformed_state.json>"
  exit 1
fi

FAIL=0
if command -v jq &>/dev/null; then
  if ! jq -e '.' "$INPUT_FILE" >/dev/null 2>&1; then
    echo "Invalid JSON: $INPUT_FILE"
    FAIL=1
  fi
  if ! jq -e '.contract_core and .admin' "$INPUT_FILE" >/dev/null 2>&1; then
    echo "Missing required fields: contract_core, admin"
    FAIL=1
  fi
else
  echo "jq not found; skipping validation"
fi

[[ $FAIL -eq 0 ]] && echo "Validation passed: $INPUT_FILE" || exit 1
