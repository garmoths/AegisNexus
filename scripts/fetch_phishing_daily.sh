#!/usr/bin/env bash
set -euo pipefail

# AegisNexus phishing feed auto-fetch script
# Intended for Frankfurt production server automation (cron/systemd)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="${PROJECT_DIR:-$(cd "$SCRIPT_DIR/.." && pwd)}"

BASE_URL="${AEGIS_BASE_URL:-http://127.0.0.1:8000}"
FETCH_ENDPOINT="${PHISHING_FETCH_ENDPOINT:-/api/v2/phishing/fetch-all}"
REQUEST_TIMEOUT="${FETCH_TIMEOUT_SECONDS:-300}"
MAX_RETRIES="${FETCH_MAX_RETRIES:-3}"
RETRY_WAIT_SECONDS="${FETCH_RETRY_WAIT_SECONDS:-15}"
LOG_FILE="${FETCH_LOG_FILE:-${PROJECT_DIR}/logs/fetch_phishing.log}"
LOCK_FILE="${FETCH_LOCK_FILE:-/tmp/aegisnexus-phishing-fetch.lock}"
API_KEY="${PHISHING_FETCH_API_KEY:-}"

mkdir -p "$(dirname "$LOG_FILE")"

log() {
  local level="$1"
  local msg="$2"
  printf '%s [%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S %z')" "$level" "$msg" | tee -a "$LOG_FILE"
}

run_fetch() {
  local attempt=1
  local url="${BASE_URL%/}${FETCH_ENDPOINT}"

  while [[ "$attempt" -le "$MAX_RETRIES" ]]; do
    log "INFO" "Phishing fetch baslatildi (attempt=${attempt}/${MAX_RETRIES}) url=${url}"

    local headers=(-H "Content-Type: application/json")
    if [[ -n "$API_KEY" ]]; then
      headers+=(-H "X-API-Key: ${API_KEY}")
    fi

    local response_body
    response_body="$(mktemp)"

    local http_code
    set +e
    http_code=$(curl -sS -X POST \
      --connect-timeout 15 \
      --max-time "$REQUEST_TIMEOUT" \
      "${headers[@]}" \
      -o "$response_body" \
      -w "%{http_code}" \
      "$url")
    local curl_exit=$?
    set -e

    if [[ "$curl_exit" -eq 0 && "$http_code" -ge 200 && "$http_code" -lt 300 ]]; then
      log "INFO" "Phishing fetch basarili (http=${http_code})"
      log "INFO" "Response: $(tr '\n' ' ' < "$response_body" | head -c 1200)"
      rm -f "$response_body"
      return 0
    fi

    log "WARN" "Phishing fetch hatasi (attempt=${attempt}, curl_exit=${curl_exit}, http=${http_code})"
    log "WARN" "Response: $(tr '\n' ' ' < "$response_body" | head -c 1200)"
    rm -f "$response_body"

    if [[ "$attempt" -lt "$MAX_RETRIES" ]]; then
      log "INFO" "${RETRY_WAIT_SECONDS}s sonra yeniden denenecek"
      sleep "$RETRY_WAIT_SECONDS"
    fi

    attempt=$((attempt + 1))
  done

  return 1
}

exec 9>"$LOCK_FILE"
if ! flock -n 9; then
  log "WARN" "Baska bir fetch islemi zaten calisiyor, cikiliyor"
  exit 0
fi

if run_fetch; then
  log "INFO" "Phishing fetch tamamlandi"
  exit 0
fi

log "ERROR" "Phishing fetch tum denemelerde basarisiz oldu"
exit 1
