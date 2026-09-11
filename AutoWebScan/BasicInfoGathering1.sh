#!/usr/bin/env bash
#
# webvuln_scan.sh
# -----------------------------------------------------------------------------
# Automated recon / vulnerability-surface checker for a web application domain.
# Chains together:
#   1. Sublist3r   -> subdomain enumeration
#   2. theHarvester -> OSINT (emails, hosts, ASNs, IPs from public sources)
#   3. nmap        -> live host detection, port/service scan, NSE vuln scripts
#
# This tool performs ACTIVE scanning. Only run it against domains/IPs you
# own or have explicit written authorization to test. Unauthorized scanning
# may be illegal under laws such as the CFAA (US), Computer Misuse Act (UK),
# and equivalents elsewhere.
#
# Requirements (must be installed and on $PATH, or set paths below):
#   - sublist3r      (https://github.com/aboul3la/Sublist3r)
#   - theHarvester   (https://github.com/laramies/theHarvester)
#   - nmap
#   - jq (optional, used for pretty summaries if present)
#
# Usage:
#   ./webvuln_scan.sh -d example.com [-o output_dir] [-p ports] [--fast]
#
# -----------------------------------------------------------------------------
set -uo pipefail

# ---------- Defaults ----------------------------------------------------
DOMAIN=""
OUTDIR=""
PORTS="1-1000"
FAST=0
SUBLIST3R_BIN="${SUBLIST3R_BIN:-sublist3r}"
HARVESTER_BIN="${HARVESTER_BIN:-theHarvester}"
NMAP_BIN="${NMAP_BIN:-nmap}"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"

# ---------- Colors --------------------------------------------------------
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'

log()  { echo -e "${BLUE}[*]${NC} $*"; }
ok()   { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[-]${NC} $*" >&2; }

usage() {
    cat <<EOF
Usage: $0 -d <domain> [options]

Required:
  -d, --domain <domain>     Target domain (e.g. example.com)

Optional:
  -o, --outdir <dir>        Output directory (default: ./scan_<domain>_<timestamp>)
  -p, --ports <range>       Port range for nmap (default: 1-1000). Use "-" for all 65535.
  --fast                    Skip theHarvester (faster, subdomains + nmap only)
  -h, --help                Show this help

Example:
  $0 -d example.com -p 1-65535
EOF
    exit 1
}

# ---------- Parse args ------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        -d|--domain) DOMAIN="$2"; shift 2 ;;
        -o|--outdir) OUTDIR="$2"; shift 2 ;;
        -p|--ports)  PORTS="$2"; shift 2 ;;
        --fast)      FAST=1; shift ;;
        -h|--help)   usage ;;
        *) err "Unknown option: $1"; usage ;;
    esac
done

[[ -z "$DOMAIN" ]] && { err "Domain is required."; usage; }
[[ -z "$OUTDIR" ]] && OUTDIR="./scan_${DOMAIN}_${TIMESTAMP}"

mkdir -p "$OUTDIR"/{subdomains,osint,nmap,report}

# ---------- Authorization gate ---------------------------------------------
cat <<WARNING
${YELLOW}=================================================================
 LEGAL / AUTHORIZATION NOTICE
=================================================================${NC}
You are about to run active reconnaissance and vulnerability
scanning (nmap NSE 'vuln' scripts) against:

    ${DOMAIN}

Only proceed if you OWN this target or have EXPLICIT WRITTEN
AUTHORIZATION to test it (e.g. a signed pentest agreement or a
bug bounty program's in-scope rules).
WARNING

read -r -p "Type 'YES' to confirm you are authorized to scan ${DOMAIN}: " CONFIRM
if [[ "$CONFIRM" != "YES" ]]; then
    err "Authorization not confirmed. Aborting."
    exit 1
fi

# ---------- Dependency checks ------------------------------------------------
check_bin() {
    command -v "$1" >/dev/null 2>&1
}

MISSING=0
for bin in "$NMAP_BIN"; do
    if ! check_bin "$bin"; then
        err "Required tool not found: $bin"
        MISSING=1
    fi
done
if ! check_bin "$SUBLIST3R_BIN" && [[ ! -f "./sublist3r.py" ]]; then
    warn "sublist3r not found on PATH and no local sublist3r.py â€” subdomain step will be skipped."
fi
if [[ $FAST -eq 0 ]] && ! check_bin "$HARVESTER_BIN"; then
    warn "theHarvester not found on PATH â€” OSINT step will be skipped (or use --fast to silence this)."
fi
[[ $MISSING -eq 1 ]] && { err "Install missing required tools and re-run."; exit 1; }

# =============================================================================
# STEP 1: Subdomain enumeration with Sublist3r
# =============================================================================
SUBS_RAW="$OUTDIR/subdomains/sublist3r_raw.txt"
SUBS_CLEAN="$OUTDIR/subdomains/subdomains.txt"

log "Step 1/3: Enumerating subdomains with Sublist3r..."
if check_bin "$SUBLIST3R_BIN"; then
    "$SUBLIST3R_BIN" -d "$DOMAIN" -o "$SUBS_RAW" >/dev/null 2>&1
elif [[ -f "./sublist3r.py" ]]; then
    python3 ./sublist3r.py -d "$DOMAIN" -o "$SUBS_RAW" >/dev/null 2>&1
else
    warn "Skipping Sublist3r (not installed)."
    : > "$SUBS_RAW"
fi

# Normalize: strip blank lines, dedupe, always include the root domain
{ echo "$DOMAIN"; cat "$SUBS_RAW" 2>/dev/null; } \
    | grep -v '^\s*$' \
    | tr -d '\r' \
    | sort -u > "$SUBS_CLEAN"

SUB_COUNT=$(wc -l < "$SUBS_CLEAN" | tr -d ' ')
ok "Found $SUB_COUNT unique host(s) (including root domain). Saved to $SUBS_CLEAN"

# =============================================================================
# STEP 2: OSINT with theHarvester
# =============================================================================
HARVEST_OUT="$OUTDIR/osint/theharvester_${DOMAIN}"

if [[ $FAST -eq 0 ]] && check_bin "$HARVESTER_BIN"; then
    log "Step 2/3: Gathering OSINT with theHarvester..."
    # -b all queries multiple public sources; some require API keys and will
    # simply return nothing if unconfigured, which is fine.
    "$HARVESTER_BIN" -d "$DOMAIN" -b all -f "$HARVEST_OUT" >/dev/null 2>&1
    ok "theHarvester results saved to ${HARVEST_OUT}.{json,xml}"
else
    warn "Step 2/3: Skipping theHarvester (missing or --fast set)."
fi

# =============================================================================
# STEP 3: Live host detection + port/service scan + nmap NSE vuln scripts
# =============================================================================
log "Step 3/3: Resolving hosts and scanning with nmap..."

LIVE_HOSTS="$OUTDIR/nmap/live_hosts.txt"
: > "$LIVE_HOSTS"

while IFS= read -r host; do
    [[ -z "$host" ]] && continue
    if getent hosts "$host" >/dev/null 2>&1 || host "$host" >/dev/null 2>&1; then
        echo "$host" >> "$LIVE_HOSTS"
    fi
done < "$SUBS_CLEAN"

LIVE_COUNT=$(wc -l < "$LIVE_HOSTS" | tr -d ' ')
ok "$LIVE_COUNT host(s) resolved and will be scanned."

if [[ "$LIVE_COUNT" -eq 0 ]]; then
    err "No resolvable hosts found. Exiting."
    exit 1
fi

# Cap concurrent scanning to avoid hammering the target; scan sequentially.
NMAP_SUMMARY="$OUTDIR/nmap/summary.txt"
: > "$NMAP_SUMMARY"

while IFS= read -r host; do
    [[ -z "$host" ]] && continue
    SAFE_NAME=$(echo "$host" | tr -c 'A-Za-z0-9._-' '_')
    OUT_BASE="$OUTDIR/nmap/${SAFE_NAME}"

    log "  Scanning $host (ports: $PORTS)..."
    # -sV: service/version detection
    # -Pn: skip host discovery ping (many web hosts block ICMP)
    # --script vuln: run nmap's built-in vulnerability-screening NSE scripts
    # -T3: polite-ish timing (avoid hammering the target)
    "$NMAP_BIN" -sV -Pn -T3 -p "$PORTS" --script vuln \
        -oN "${OUT_BASE}.nmap" -oX "${OUT_BASE}.xml" "$host" \
        > "${OUT_BASE}.log" 2>&1

    OPEN_PORTS=$(grep -E '^[0-9]+/tcp\s+open' "${OUT_BASE}.nmap" 2>/dev/null)
    VULN_HITS=$(grep -iE 'VULNERABLE|CVE-' "${OUT_BASE}.nmap" 2>/dev/null)

    {
        echo "==== $host ===="
        if [[ -n "$OPEN_PORTS" ]]; then
            echo "Open ports/services:"
            echo "$OPEN_PORTS"
        else
            echo "Open ports/services: none detected in range $PORTS"
        fi
        if [[ -n "$VULN_HITS" ]]; then
            echo ""
            echo "Potential vulnerability indicators:"
            echo "$VULN_HITS"
        fi
        echo ""
    } >> "$NMAP_SUMMARY"

done < "$LIVE_HOSTS"

ok "nmap scanning complete. Per-host results in $OUTDIR/nmap/"

# =============================================================================
# Final report
# =============================================================================
REPORT="$OUTDIR/report/summary_report.txt"

{
    echo "================================================================="
    echo " Web Application Recon / Vulnerability Surface Report"
    echo " Target domain : $DOMAIN"
    echo " Generated     : $(date)"
    echo "================================================================="
    echo ""
    echo "Subdomains enumerated : $SUB_COUNT"
    echo "Live/resolvable hosts : $LIVE_COUNT"
    echo ""
    echo "--- Subdomain list ---"
    cat "$SUBS_CLEAN"
    echo ""
    echo "--- nmap scan summary (open ports + potential vuln indicators) ---"
    cat "$NMAP_SUMMARY"
    if [[ -f "${HARVEST_OUT}.json" ]]; then
        echo ""
        echo "--- theHarvester OSINT ---"
        echo "See: ${HARVEST_OUT}.json / ${HARVEST_OUT}.xml"
    fi
    echo ""
    echo "================================================================="
    echo " NOTE: nmap's 'vuln' NSE scripts flag *potential* issues based on"
    echo " banners/version strings. Every hit needs manual verification â€”"
    echo " this report is a triage starting point, not a confirmed"
    echo " vulnerability list."
    echo "================================================================="
} > "$REPORT"

ok "Full report written to: $REPORT"
echo ""
cat "$REPORT"
