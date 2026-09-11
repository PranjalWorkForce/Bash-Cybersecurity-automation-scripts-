#!/usr/bin/env bash
#
# osint_top10.sh
# -----------------------------------------------------------------------------
# Aggregates passive/OSINT reconnaissance on a target domain from ~10 of the
# most commonly used OSINT sources/tools:
#
#   1.  whois           - domain registration data
#   2.  dig/dnsrecon     - DNS records (A, MX, NS, TXT, SOA)
#   3.  crt.sh            - certificate transparency logs (subdomains)
#   4.  Sublist3r        - subdomain enumeration (multi search-engine)
#   5.  Amass            - subdomain enum + passive sources (if installed)
#   6.  theHarvester     - emails, hosts, employees from search engines
#   7.  Shodan CLI        - exposed services/banners (requires API key)
#   8.  Wayback Machine  - historical URLs (via waybackurls or CDX API)
#   9.  builtwith-style  - basic tech fingerprint via HTTP headers (curl/whatweb)
#   10. GitHub dorking     - leaked info / repos mentioning the domain (via gh or curl)
#
# All sources here are PASSIVE / OSINT (no exploitation), but subdomain and
# service data can still be sensitive. Only run this against domains you own
# or are authorized to research.
#
# Usage:
#   ./osint_top10.sh -d example.com [-o output_dir] [--shodan-key KEY]
#
# -----------------------------------------------------------------------------
set -uo pipefail

DOMAIN=""
OUTDIR=""
SHODAN_KEY="${SHODAN_API_KEY:-}"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"

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
  -o, --outdir <dir>        Output directory (default: ./osint_<domain>_<timestamp>)
  --shodan-key <key>        Shodan API key (or set SHODAN_API_KEY env var)
  -h, --help                Show this help
EOF
    exit 1
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -d|--domain)     DOMAIN="$2"; shift 2 ;;
        -o|--outdir)     OUTDIR="$2"; shift 2 ;;
        --shodan-key)    SHODAN_KEY="$2"; shift 2 ;;
        -h|--help)       usage ;;
        *) err "Unknown option: $1"; usage ;;
    esac
done

[[ -z "$DOMAIN" ]] && { err "Domain is required."; usage; }
[[ -z "$OUTDIR" ]] && OUTDIR="./osint_${DOMAIN}_${TIMESTAMP}"
mkdir -p "$OUTDIR"

cat <<NOTICE
${YELLOW}=================================================================
 OSINT NOTICE
=================================================================${NC}
This gathers information from public/passive sources about:

    ${DOMAIN}

Only proceed on domains you own or are authorized to research.
Some steps (Shodan) reflect scans Shodan already performed, not
scans this script performs itself.
NOTICE
read -r -p "Type 'YES' to continue: " CONFIRM
[[ "$CONFIRM" != "YES" ]] && { err "Not confirmed. Aborting."; exit 1; }

check_bin() { command -v "$1" >/dev/null 2>&1; }

results_file() { echo "$OUTDIR/$1"; }

# =============================================================================
# 1. WHOIS
# =============================================================================
log "[1/10] WHOIS lookup..."
OUT="$(results_file 01_whois.txt)"
if check_bin whois; then
    whois "$DOMAIN" > "$OUT" 2>&1
    ok "Saved -> $OUT"
else
    warn "whois not installed, skipping."
fi

# =============================================================================
# 2. DNS records (dig, fallback to host)
# =============================================================================
log "[2/10] DNS record enumeration..."
OUT="$(results_file 02_dns_records.txt)"
{
    for rtype in A AAAA MX NS TXT SOA CNAME; do
        echo "--- $rtype ---"
        if check_bin dig; then
            dig +short "$DOMAIN" "$rtype"
        elif check_bin host; then
            host -t "$rtype" "$DOMAIN"
        fi
        echo ""
    done
} > "$OUT" 2>&1
ok "Saved -> $OUT"

if check_bin dnsrecon; then
    log "   dnsrecon (zone transfer / bruteforce checks)..."
    dnsrecon -d "$DOMAIN" > "$(results_file 02b_dnsrecon.txt)" 2>&1
    ok "Saved -> $(results_file 02b_dnsrecon.txt)"
fi

# =============================================================================
# 3. crt.sh (Certificate Transparency logs)
# =============================================================================
log "[3/10] Certificate Transparency search (crt.sh)..."
OUT="$(results_file 03_crtsh_subdomains.txt)"
if check_bin curl; then
    curl -s "https://crt.sh/?q=%25.${DOMAIN}&output=json" \
        | grep -o '"name_value":"[^"]*"' \
        | sed 's/"name_value":"//; s/"$//' \
        | tr ',' '\n' \
        | sed 's/^\*\.//' \
        | sort -u > "$OUT"
    COUNT=$(wc -l < "$OUT" | tr -d ' ')
    ok "Found $COUNT unique name(s) -> $OUT"
else
    warn "curl not installed, skipping crt.sh."
fi

# =============================================================================
# 4. Sublist3r
# =============================================================================
log "[4/10] Sublist3r subdomain enumeration..."
OUT="$(results_file 04_sublist3r.txt)"
if check_bin sublist3r; then
    sublist3r -d "$DOMAIN" -o "$OUT" >/dev/null 2>&1
    ok "Saved -> $OUT"
elif [[ -f ./sublist3r.py ]]; then
    python3 ./sublist3r.py -d "$DOMAIN" -o "$OUT" >/dev/null 2>&1
    ok "Saved -> $OUT"
else
    warn "Sublist3r not found, skipping."
fi

# =============================================================================
# 5. Amass (passive mode)
# =============================================================================
log "[5/10] Amass passive enumeration..."
OUT="$(results_file 05_amass.txt)"
if check_bin amass; then
    amass enum -passive -d "$DOMAIN" -o "$OUT" >/dev/null 2>&1
    ok "Saved -> $OUT"
else
    warn "amass not installed, skipping."
fi

# =============================================================================
# 6. theHarvester
# =============================================================================
log "[6/10] theHarvester (emails/hosts from search engines)..."
OUT_BASE="$(results_file 06_theharvester)"
if check_bin theHarvester; then
    theHarvester -d "$DOMAIN" -b all -f "$OUT_BASE" >/dev/null 2>&1
    ok "Saved -> ${OUT_BASE}.json / .xml"
else
    warn "theHarvester not installed, skipping."
fi

# =============================================================================
# 7. Shodan
# =============================================================================
log "[7/10] Shodan lookup..."
OUT="$(results_file 07_shodan.txt)"
if [[ -n "$SHODAN_KEY" ]] && check_bin curl; then
    RESOLVED_IP=$(dig +short "$DOMAIN" A 2>/dev/null | head -n1)
    if [[ -n "$RESOLVED_IP" ]]; then
        curl -s "https://api.shodan.io/shodan/host/${RESOLVED_IP}?key=${SHODAN_KEY}" > "$OUT"
        ok "Saved -> $OUT (IP: $RESOLVED_IP)"
    else
        warn "Could not resolve an IP for Shodan lookup."
    fi
elif check_bin shodan; then
    shodan host "$DOMAIN" > "$OUT" 2>&1
    ok "Saved -> $OUT"
else
    warn "No Shodan API key / CLI configured, skipping (set --shodan-key or SHODAN_API_KEY)."
fi

# =============================================================================
# 8. Wayback Machine (historical URLs)
# =============================================================================
log "[8/10] Wayback Machine historical URLs..."
OUT="$(results_file 08_wayback_urls.txt)"
if check_bin waybackurls; then
    echo "$DOMAIN" | waybackurls > "$OUT" 2>&1
    ok "Saved -> $OUT"
elif check_bin curl; then
    curl -s "http://web.archive.org/cdx/search/cdx?url=*.${DOMAIN}/*&output=text&fl=original&collapse=urlkey" \
        > "$OUT"
    ok "Saved -> $OUT (via CDX API)"
else
    warn "Neither waybackurls nor curl available, skipping."
fi

# =============================================================================
# 9. Tech fingerprint (whatweb, or raw headers via curl)
# =============================================================================
log "[9/10] Technology fingerprinting..."
OUT="$(results_file 09_tech_fingerprint.txt)"
if check_bin whatweb; then
    whatweb "$DOMAIN" > "$OUT" 2>&1
    ok "Saved -> $OUT"
elif check_bin curl; then
    {
        echo "--- HTTP response headers ---"
        curl -sI "https://${DOMAIN}" --max-time 10
        echo ""
        echo "--- robots.txt ---"
        curl -s "https://${DOMAIN}/robots.txt" --max-time 10
    } > "$OUT" 2>&1
    ok "Saved -> $OUT"
else
    warn "No whatweb/curl available, skipping."
fi

# =============================================================================
# 10. GitHub dorking (public repos/code mentioning the domain)
# =============================================================================
log "[10/10] GitHub code/repo search..."
OUT="$(results_file 10_github_mentions.txt)"
if check_bin gh; then
    gh search code "$DOMAIN" --limit 30 > "$OUT" 2>&1
    ok "Saved -> $OUT"
elif check_bin curl; then
    # Unauthenticated GitHub search API is rate-limited (10 req/min) but works
    # for a light check. For heavier use, authenticate with a GitHub token.
    curl -s "https://api.github.com/search/code?q=${DOMAIN}" \
        -H "Accept: application/vnd.github+json" > "$OUT"
    ok "Saved -> $OUT (unauthenticated, rate-limited)"
else
    warn "Neither gh CLI nor curl available, skipping."
fi

# =============================================================================
# Combined summary
# =============================================================================
REPORT="$(results_file 00_SUMMARY.txt)"
{
    echo "================================================================="
    echo " OSINT Top-10 Aggregated Report"
    echo " Target   : $DOMAIN"
    echo " Generated: $(date)"
    echo "================================================================="
    for f in "$OUTDIR"/0*_*.txt "$OUTDIR"/0*_*.json; do
        [[ -f "$f" ]] || continue
        [[ "$f" == "$REPORT" ]] && continue
        echo ""
        echo "----- $(basename "$f") -----"
        head -n 15 "$f"
        LINES=$(wc -l < "$f" | tr -d ' ')
        [[ "$LINES" -gt 15 ]] && echo "... ($LINES total lines, see full file)"
    done
} > "$REPORT" 2>/dev/null

ok "All done. Combined summary: $REPORT"
echo ""
echo "Files written to: $OUTDIR/"
ls -1 "$OUTDIR"
