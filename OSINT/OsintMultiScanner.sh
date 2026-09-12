#!/usr/bin/env bash
#
# multi-scan.sh
# ---------------------------------------------------------------------------
# Orchestrates multiple vulnerability/recon tools against a single target and
# collects their output into one timestamped report folder.
#
# Covers, where a real CLI/API exists:
#   - Nmap                 (open source, local binary)
#   - OWASP ZAP            (open source, run via Docker baseline scan)
#   - OpenVAS/Greenbone     (open source, via gvm-cli if installed)
#   - sqlmap                (open source, optional targeted injection test)
#   - gobuster/ffuf          (open source, content discovery)
#   - Nessus                 (commercial - REST API launch, requires API key)
#   - Rapid7 InsightVM        (commercial - REST API launch, requires API key)
#   - Qualys VMDR              (commercial - REST API launch, requires API creds)
#   - Acunetix                  (commercial - REST API launch, requires API key)
#   - Intruder                   (commercial - REST API launch, requires API key)
#   - StackHawk                   (commercial CLI - `hawk scan`, requires API key)
#   - Burp Suite Enterprise         (commercial - REST API launch, requires API key)
#
# The commercial tools are cloud/GUI-driven products, not simple local
# binaries, so this script talks to their REST APIs where one is available.
# Each commercial section is disabled by default and only runs if you export
# the matching API key/URL environment variable â€” nothing fires silently.
#
# ---------------------------------------------------------------------------
# AUTHORIZATION REQUIREMENT
# Only ever point this at a target you own or have EXPLICIT WRITTEN
# AUTHORIZATION to test (a signed pentest engagement / bug bounty scope).
# Unauthorized scanning of third-party systems is illegal in most
# jurisdictions. The script will refuse to run without an explicit
# confirmation flag (see below).
# ---------------------------------------------------------------------------
#
# USAGE:
#   ./multi-scan.sh -t <target> --i-am-authorized [options]
#
#   -t, --target        Target IP, hostname, or URL (required)
#   --i-am-authorized   Required flag confirming you have permission to scan
#   -o, --outdir        Output directory (default: ./scan-results-<timestamp>)
#   --skip-nmap         Skip the Nmap recon phase
#   --skip-zap          Skip the OWASP ZAP baseline scan
#   --skip-openvas       Skip the OpenVAS scan
#   --skip-content        Skip gobuster/ffuf content discovery
#   --skip-sqlmap          Skip the optional sqlmap crawl-test
#   -h, --help               Show this help text
#
# Commercial tool integrations activate automatically if their env vars are
# set (see the "COMMERCIAL API INTEGRATIONS" section below for the variable
# names each one expects).
# ---------------------------------------------------------------------------

set -uo pipefail

# ---------- Defaults ----------
TARGET=""
AUTHORIZED=0
OUTDIR=""
SKIP_NMAP=0
SKIP_ZAP=0
SKIP_OPENVAS=0
SKIP_CONTENT=0
SKIP_SQLMAP=0

usage() {
  sed -n '2,45p' "$0" | sed 's/^# \{0,1\}//'
  exit 1
}

# ---------- Argument parsing ----------
while [[ $# -gt 0 ]]; do
  case "$1" in
    -t|--target) TARGET="$2"; shift 2 ;;
    --i-am-authorized) AUTHORIZED=1; shift ;;
    -o|--outdir) OUTDIR="$2"; shift 2 ;;
    --skip-nmap) SKIP_NMAP=1; shift ;;
    --skip-zap) SKIP_ZAP=1; shift ;;
    --skip-openvas) SKIP_OPENVAS=1; shift ;;
    --skip-content) SKIP_CONTENT=1; shift ;;
    --skip-sqlmap) SKIP_SQLMAP=1; shift ;;
    -h|--help) usage ;;
    *) echo "Unknown argument: $1"; usage ;;
  esac
done

if [[ -z "$TARGET" ]]; then
  echo "[ERROR] No target specified. Use -t <target>."
  usage
fi

if [[ "$AUTHORIZED" -ne 1 ]]; then
  echo "[ERROR] Refusing to scan without explicit authorization confirmation."
  echo "        Re-run with --i-am-authorized only if you own this target or"
  echo "        hold written permission (signed engagement / bounty scope)."
  exit 1
fi

TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
OUTDIR="${OUTDIR:-./scan-results-${TIMESTAMP}}"
mkdir -p "$OUTDIR"

LOG="$OUTDIR/run.log"
touch "$LOG"

log() {
  echo "[$(date '+%H:%M:%S')] $*" | tee -a "$LOG"
}

have() { command -v "$1" >/dev/null 2>&1; }

log "=== multi-scan.sh started ==="
log "Target:     $TARGET"
log "Output dir: $OUTDIR"
echo "$TARGET" > "$OUTDIR/target.txt"

# =============================================================================
# 1. NMAP â€” network/service discovery
# =============================================================================
if [[ "$SKIP_NMAP" -eq 0 ]]; then
  if have nmap; then
    log "--- Running Nmap service/version scan ---"
    nmap -sV -sC -p- --min-rate 1000 -oA "$OUTDIR/nmap_full" "$TARGET" \
      >> "$LOG" 2>&1

    log "--- Running Nmap NSE vulnerability scripts ---"
    nmap --script vuln -oA "$OUTDIR/nmap_vuln" "$TARGET" \
      >> "$LOG" 2>&1
  else
    log "[SKIP] nmap not installed â€” skipping network recon."
  fi
else
  log "[SKIP] Nmap phase skipped by flag."
fi

# =============================================================================
# 2. Content discovery â€” gobuster / ffuf (web targets only)
# =============================================================================
if [[ "$SKIP_CONTENT" -eq 0 ]]; then
  WORDLIST="/usr/share/wordlists/dirb/common.txt"
  if have gobuster && [[ -f "$WORDLIST" ]]; then
    log "--- Running gobuster content discovery ---"
    gobuster dir -u "$TARGET" -w "$WORDLIST" -q \
      -o "$OUTDIR/gobuster.txt" >> "$LOG" 2>&1
  elif have ffuf && [[ -f "$WORDLIST" ]]; then
    log "--- Running ffuf content discovery ---"
    ffuf -u "${TARGET%/}/FUZZ" -w "$WORDLIST" -o "$OUTDIR/ffuf.json" \
      >> "$LOG" 2>&1
  else
    log "[SKIP] gobuster/ffuf or wordlist not found â€” skipping content discovery."
  fi
else
  log "[SKIP] Content discovery skipped by flag."
fi

# =============================================================================
# 3. OWASP ZAP â€” baseline DAST scan (via Docker)
# =============================================================================
if [[ "$SKIP_ZAP" -eq 0 ]]; then
  if have docker; then
    log "--- Running OWASP ZAP baseline scan ---"
    docker run --rm -v "$(pwd)/$OUTDIR:/zap/wrk/:rw" \
      owasp/zap2docker-stable zap-baseline.py \
      -t "$TARGET" -r zap_report.html \
      >> "$LOG" 2>&1
  else
    log "[SKIP] Docker not installed â€” skipping ZAP baseline scan."
  fi
else
  log "[SKIP] ZAP phase skipped by flag."
fi

# =============================================================================
# 4. OpenVAS / Greenbone â€” via gvm-cli (if configured locally)
# =============================================================================
if [[ "$SKIP_OPENVAS" -eq 0 ]]; then
  if have gvm-cli; then
    log "--- Launching OpenVAS scan via gvm-cli ---"
    # Assumes a GVM socket/user is already configured on this host.
    gvm-cli socket --xml \
      "<create_target><name>multiscan-${TIMESTAMP}</name><hosts>${TARGET}</hosts></create_target>" \
      >> "$OUTDIR/openvas_target.xml" 2>> "$LOG"
    log "Target created in GVM. Launch/monitor the scan task from the"
    log "Greenbone Security Assistant UI or gvm-cli 'create_task' / 'start_task'."
  else
    log "[SKIP] gvm-cli not installed â€” skipping OpenVAS phase."
  fi
else
  log "[SKIP] OpenVAS phase skipped by flag."
fi

# =============================================================================
# 5. sqlmap â€” optional targeted injection test (URL targets with a param)
# =============================================================================
if [[ "$SKIP_SQLMAP" -eq 0 ]]; then
  if have sqlmap && [[ "$TARGET" == http* && "$TARGET" == *"?"* ]]; then
    log "--- Running sqlmap against parameterized URL ---"
    sqlmap -u "$TARGET" --batch --level=2 --risk=1 \
      --output-dir="$OUTDIR/sqlmap" >> "$LOG" 2>&1
  else
    log "[SKIP] sqlmap not installed, or target has no query parameter to test."
  fi
else
  log "[SKIP] sqlmap phase skipped by flag."
fi

# =============================================================================
# 6. COMMERCIAL API INTEGRATIONS
# Each block only runs if its environment variables are set. Nothing here
# fires unless you've explicitly configured credentials for that platform.
# =============================================================================

# --- Tenable Nessus ---
# export NESSUS_URL="https://nessus.example.com:8834"
# export NESSUS_API_KEY="accessKey=XXXX;secretKey=YYYY"
if [[ -n "${NESSUS_URL:-}" && -n "${NESSUS_API_KEY:-}" ]]; then
  log "--- Launching Nessus scan via REST API ---"
  curl -sk -X POST "$NESSUS_URL/scans" \
    -H "X-ApiKeys: $NESSUS_API_KEY" \
    -H "Content-Type: application/json" \
    -d "{\"uuid\":\"${NESSUS_TEMPLATE_UUID:-}\",\"settings\":{\"name\":\"multiscan-${TIMESTAMP}\",\"text_targets\":\"${TARGET}\"}}" \
    -o "$OUTDIR/nessus_launch.json" >> "$LOG" 2>&1
else
  log "[SKIP] NESSUS_URL/NESSUS_API_KEY not set â€” skipping Nessus."
fi

# --- Rapid7 InsightVM ---
# export INSIGHTVM_URL="https://insightvm.example.com:3780"
# export INSIGHTVM_API_KEY="base64(user:pass)"
if [[ -n "${INSIGHTVM_URL:-}" && -n "${INSIGHTVM_API_KEY:-}" ]]; then
  log "--- Launching InsightVM scan via REST API ---"
  curl -sk -X POST "$INSIGHTVM_URL/api/3/sites/${INSIGHTVM_SITE_ID:-1}/scans" \
    -H "Authorization: Basic $INSIGHTVM_API_KEY" \
    -H "Content-Type: application/json" \
    -o "$OUTDIR/insightvm_launch.json" >> "$LOG" 2>&1
else
  log "[SKIP] INSIGHTVM_URL/INSIGHTVM_API_KEY not set â€” skipping InsightVM."
fi

# --- Qualys VMDR ---
# export QUALYS_URL="https://qualysapi.qualys.com"
# export QUALYS_USER="username"
# export QUALYS_PASS="password"
if [[ -n "${QUALYS_URL:-}" && -n "${QUALYS_USER:-}" && -n "${QUALYS_PASS:-}" ]]; then
  log "--- Launching Qualys VMDR scan via REST API ---"
  curl -sk -u "${QUALYS_USER}:${QUALYS_PASS}" \
    -H "X-Requested-With: multi-scan.sh" \
    "$QUALYS_URL/api/2.0/fo/scan/?action=launch&ip=${TARGET}&scan_title=multiscan-${TIMESTAMP}" \
    -o "$OUTDIR/qualys_launch.xml" >> "$LOG" 2>&1
else
  log "[SKIP] QUALYS_URL/QUALYS_USER/QUALYS_PASS not set â€” skipping Qualys."
fi

# --- Acunetix ---
# export ACUNETIX_URL="https://acunetix.example.com:3443"
# export ACUNETIX_API_KEY="XXXX"
if [[ -n "${ACUNETIX_URL:-}" && -n "${ACUNETIX_API_KEY:-}" ]]; then
  log "--- Launching Acunetix scan via REST API ---"
  curl -sk -X POST "$ACUNETIX_URL/api/v1/scans" \
    -H "X-Auth: $ACUNETIX_API_KEY" \
    -H "Content-Type: application/json" \
    -d "{\"target\":{\"address\":\"${TARGET}\"},\"profile_id\":\"11111111-1111-1111-1111-111111111111\"}" \
    -o "$OUTDIR/acunetix_launch.json" >> "$LOG" 2>&1
else
  log "[SKIP] ACUNETIX_URL/ACUNETIX_API_KEY not set â€” skipping Acunetix."
fi

# --- Intruder ---
# export INTRUDER_API_KEY="XXXX"
if [[ -n "${INTRUDER_API_KEY:-}" ]]; then
  log "--- Triggering Intruder scan via REST API ---"
  curl -s -X POST "https://api.intruder.io/v1/targets/scan" \
    -H "Authorization: Bearer $INTRUDER_API_KEY" \
    -H "Content-Type: application/json" \
    -d "{\"targets\":[\"${TARGET}\"]}" \
    -o "$OUTDIR/intruder_launch.json" >> "$LOG" 2>&1
else
  log "[SKIP] INTRUDER_API_KEY not set â€” skipping Intruder."
fi

# --- StackHawk ---
# export HAWK_API_KEY="XXXX"
# Requires a stackhawk.yml config file in the working directory and the
# `hawk` CLI installed.
if [[ -n "${HAWK_API_KEY:-}" ]] && have hawk; then
  log "--- Running StackHawk scan ---"
  hawk scan --api-key "$HAWK_API_KEY" > "$OUTDIR/stackhawk.log" 2>&1
else
  log "[SKIP] HAWK_API_KEY not set or 'hawk' CLI not installed â€” skipping StackHawk."
fi

# --- Burp Suite Enterprise ---
# export BURP_URL="https://burp-enterprise.example.com"
# export BURP_API_KEY="XXXX"
if [[ -n "${BURP_URL:-}" && -n "${BURP_API_KEY:-}" ]]; then
  log "--- Launching Burp Suite Enterprise scan via REST API ---"
  curl -sk -X POST "$BURP_URL/api/v1/scans" \
    -H "Authorization: Bearer $BURP_API_KEY" \
    -H "Content-Type: application/json" \
    -d "{\"urls\":[\"${TARGET}\"]}" \
    -o "$OUTDIR/burp_launch.json" >> "$LOG" 2>&1
else
  log "[SKIP] BURP_URL/BURP_API_KEY not set â€” skipping Burp Enterprise."
fi

# =============================================================================
log "=== multi-scan.sh finished. Results in: $OUTDIR ==="
echo ""
echo "Summary of what ran (see $LOG for full detail):"
grep -E '^\[.*\] (---|\[SKIP\])' "$LOG"
