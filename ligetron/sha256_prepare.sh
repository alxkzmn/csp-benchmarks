#!/usr/bin/env bash
set -euo pipefail
: "${INPUT_SIZE:?INPUT_SIZE is required}"
exec "$(dirname "$0")/common_prepare.sh" sha256 hex "$INPUT_SIZE"
