#!/usr/bin/env bash
# Transform exported state for migration (#64).
# Applies schema/format changes between contract versions.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
INPUT_FILE="${1:-}"
OUTPUT_DIR="${2:-$ROOT_DIR/migration/transformed}"

if [[ -z "$INPUT_FILE" || ! -f "$INPUT_FILE" ]]; then
  echo "Usage: $0 <exported_state.json> [output_dir]"
  echo "  Exported state from export_state.sh"
  exit 1
fi

mkdir -p "$OUTPUT_DIR"
OUTPUT_FILE="$OUTPUT_DIR/$(basename "$INPUT_FILE" .json)_transformed.json"

# Copy and optionally transform keys/format for new contract version
if command -v jq &>/dev/null; then
  jq '.' "$INPUT_FILE" > "$OUTPUT_FILE"
  echo "Transformed to $OUTPUT_FILE"
else
  cp "$INPUT_FILE" "$OUTPUT_FILE"
  echo "Copied to $OUTPUT_FILE (no jq for transform)"
fi
echo "$OUTPUT_FILE"
