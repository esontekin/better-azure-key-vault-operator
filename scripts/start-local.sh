#!/usr/bin/env bash
set -euo pipefail

# Azure Key Vault Manager — Linux/macOS Local Startup Script
# Never passes AZURE_CLIENT_SECRET via CLI arguments or shell history.
# Supports AZURE_CLIENT_SECRET_FILE (preferred) or masked interactive prompt.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
JAR_PATH="${AKV_JAR_PATH:-${REPO_ROOT}/backend/build/libs/azure-key-vault-operator.jar}"

if [[ ! -f "${JAR_PATH}" ]]; then
  echo "ERROR: Executable JAR not found at '${JAR_PATH}'." >&2
  echo "Build it first with: ./gradlew bootJar" >&2
  exit 1
fi

resolve_java() {
  local candidates=()
  if [[ -n "${JAVA_HOME:-}" && -x "${JAVA_HOME}/bin/java" ]]; then
    candidates+=("${JAVA_HOME}/bin/java")
  fi
  if command -v java >/dev/null 2>&1; then
    candidates+=("$(command -v java)")
  fi

  local bin version_line major
  for bin in "${candidates[@]}"; do
    version_line="$("${bin}" -version 2>&1 | head -n 1 || true)"
    major="$(printf '%s\n' "${version_line}" | sed -nE 's/.*version "([0-9]+).*/\1/p')"
    if [[ -n "${major}" && "${major}" -ge 21 ]]; then
      printf '%s\n' "${bin}"
      return 0
    fi
  done
  return 1
}

if ! JAVA_BIN="$(resolve_java)"; then
  echo "ERROR: Java 21 or newer is required. Set JAVA_HOME to a JDK/JRE 21 installation or add Java 21 to PATH." >&2
  exit 1
fi

if [[ -z "${AZURE_TENANT_ID:-}" ]]; then
  echo "ERROR: AZURE_TENANT_ID is required. Export AZURE_TENANT_ID before running this script." >&2
  exit 1
fi

if [[ -z "${AZURE_CLIENT_ID:-}" ]]; then
  echo "ERROR: AZURE_CLIENT_ID is required. Export AZURE_CLIENT_ID before running this script." >&2
  exit 1
fi

if [[ -n "${AZURE_CLIENT_SECRET:-}" && -n "${AZURE_CLIENT_SECRET_FILE:-}" ]]; then
  echo "ERROR: Both AZURE_CLIENT_SECRET and AZURE_CLIENT_SECRET_FILE are set. Configure exactly one secret source." >&2
  exit 1
fi

PROMPTED_SECRET=0
cleanup() {
  if [[ "${PROMPTED_SECRET}" -eq 1 ]]; then
    unset AZURE_CLIENT_SECRET || true
  fi
}
trap cleanup EXIT INT TERM

if [[ -n "${AZURE_CLIENT_SECRET_FILE:-}" ]]; then
  if [[ ! -f "${AZURE_CLIENT_SECRET_FILE}" || ! -r "${AZURE_CLIENT_SECRET_FILE}" ]]; then
    echo "ERROR: AZURE_CLIENT_SECRET_FILE does not exist or is not readable: '${AZURE_CLIENT_SECRET_FILE}'" >&2
    exit 1
  fi
elif [[ -z "${AZURE_CLIENT_SECRET:-}" ]]; then
  echo "AZURE_CLIENT_SECRET / AZURE_CLIENT_SECRET_FILE is not set." >&2
  printf 'Enter Azure Service Principal Client Secret VALUE (masked): ' >&2
  IFS= read -r -s AZURE_CLIENT_SECRET
  printf '\n' >&2
  if [[ -z "${AZURE_CLIENT_SECRET}" ]]; then
    echo "ERROR: Client secret value cannot be empty." >&2
    exit 1
  fi
  export AZURE_CLIENT_SECRET
  PROMPTED_SECRET=1
fi

export APP_PROFILE="${APP_PROFILE:-local}"
export SERVER_ADDRESS="${SERVER_ADDRESS:-127.0.0.1}"
export SERVER_PORT="${SERVER_PORT:-8765}"
export APP_DELETE_ENABLED="${APP_DELETE_ENABLED:-false}"
export APP_METADATA_TTL="${APP_METADATA_TTL:-5m}"

echo "Starting Azure Key Vault Manager (profile=${APP_PROFILE}, bind=${SERVER_ADDRESS}:${SERVER_PORT})..."
echo "UI URL: http://${SERVER_ADDRESS}:${SERVER_PORT}/"

# Secret is inherited strictly via environment variable or mounted file, NEVER via CLI arguments.
"${JAVA_BIN}" -jar "${JAR_PATH}"
