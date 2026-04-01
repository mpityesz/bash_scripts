#!/usr/bin/env bash

# Unified domain audit script
# - Reads domains from plain list or category list ([full]/[alias]/[simple])
# - Collects DNS records from one or more resolvers
# - Collects registration data (.hu webwhois, fallback to whois CLI)
# - Generates unified TXT, CSV and JSONL outputs

set -u

WHOIS_HU_URL="https://info.domain.hu/webwhois/hu/domain"
DEFAULT_RESOLVERS="1.1.1.1,8.8.8.8"
DEFAULT_RECORD_TYPES="A,NS,MX,TXT,SOA"
DEFAULT_SUBDOMAINS="mail:A,ftp:A,www:A,_dmarc:TXT,mail._domainkey:TXT,fixnet._domainkey:TXT,fixvps._domainkey:TXT"
DNS_TIMEOUT=5
WHOIS_TIMEOUT=15
RATE_LIMIT_SLEEP=1

INPUT_FILE=""
OUTPUT_PREFIX="domain_audit"
RESOLVERS=()
RECORD_TYPES=()
SUBDOMAIN_KEYS=()
declare -A SUBDOMAIN_TYPES
declare -a DOMAINS
declare -a CATEGORIES

CSV_FILE=""
TXT_FILE=""
JSONL_FILE=""

# Show command-line help, expected input file formats, and optional switches.
# Exit handling is done by the caller.
usage() {
    cat <<'EOF'
Usage:
  domain_audit.sh -i <domain_list.txt> [options]

Options:
  -i, --input <file>        Input file with domains (required)
  -o, --output-prefix <p>   Output file prefix (default: domain_audit)
  -r, --resolvers <list>    Comma separated resolvers (default: 1.1.1.1,8.8.8.8)
  -t, --types <list>        Comma separated DNS types (default: A,NS,MX,TXT,SOA)
  -s, --subdomains <list>   Comma separated subdomain:type pairs
                            (default includes mail, ftp, www, _dmarc, *domainkey)
  -h, --help                Show this help

Input formats:
  1) Plain list:
       example.hu
       valami.com

  2) Category list:
       [full]
       example.hu
       [alias]
       alias.hu
       [simple]
       simple.net
EOF
}

# Print an informational message to stdout.
# Params: $1 message text.
log_info() {
    printf '[INFO] %s\n' "$1"
}

# Print a warning message to stderr.
# Params: $1 message text.
log_warn() {
    printf '[WARN] %s\n' "$1" >&2
}

# Print an error message to stderr.
# Params: $1 message text.
log_error() {
    printf '[ERR ] %s\n' "$1" >&2
}

# Trim leading and trailing whitespace from a string.
# Params: $1 input string.
# Returns: trimmed string on stdout.
trim() {
    local s="$1"
    s="${s#${s%%[![:space:]]*}}"
    s="${s%${s##*[![:space:]]}}"
    printf '%s' "$s"
}

# Convert input text to lowercase.
# Params: $1 input string.
# Returns: lowercase string on stdout.
to_lower() {
    printf '%s' "$1" | tr '[:upper:]' '[:lower:]'
}

# Escape a value for safe CSV output and wrap it in quotes.
# Params: $1 raw value.
# Returns: CSV-safe quoted value on stdout.
escape_csv() {
    local v="$1"
    v="${v//\"/\"\"}"
    printf '"%s"' "$v"
}

# Escape a string for safe JSON string literal output.
# Params: $1 raw value.
# Returns: JSON-escaped string (without surrounding quotes) on stdout.
escape_json() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\t'/\\t}"
    printf '%s' "$s"
}

# Join positional arguments with a delimiter.
# Params: $1 delimiter, $2..$N values.
# Returns: joined string on stdout.
join_by() {
    local delim="$1"
    shift
    local out=""
    local first=1
    local item=""
    for item in "$@"; do
        if [[ $first -eq 1 ]]; then
            out="$item"
            first=0
        else
            out+="$delim$item"
        fi
    done
    printf '%s' "$out"
}

# Check whether a command is available in PATH.
# Params: $1 command name.
# Returns: shell status code only (0 if exists, non-zero otherwise).
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Parse and validate command-line arguments, then populate runtime globals.
# Sets INPUT_FILE, OUTPUT_PREFIX, RESOLVERS, RECORD_TYPES, SUBDOMAIN_KEYS/TYPES.
# Exits with code 2 on invalid usage or missing input.
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -i|--input)
                INPUT_FILE="$2"
                shift 2
                ;;
            -o|--output-prefix)
                OUTPUT_PREFIX="$2"
                shift 2
                ;;
            -r|--resolvers)
                IFS=',' read -r -a RESOLVERS <<< "$2"
                shift 2
                ;;
            -t|--types)
                IFS=',' read -r -a RECORD_TYPES <<< "$2"
                shift 2
                ;;
            -s|--subdomains)
                parse_subdomains "$2"
                shift 2
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                log_error "Unknown argument: $1"
                usage
                exit 2
                ;;
        esac
    done

    if [[ -z "$INPUT_FILE" ]]; then
        log_error "Input file is required"
        usage
        exit 2
    fi

    if [[ ! -f "$INPUT_FILE" ]]; then
        log_error "Input file not found: $INPUT_FILE"
        exit 2
    fi

    if [[ ${#RESOLVERS[@]} -eq 0 ]]; then
        IFS=',' read -r -a RESOLVERS <<< "$DEFAULT_RESOLVERS"
    fi

    if [[ ${#RECORD_TYPES[@]} -eq 0 ]]; then
        IFS=',' read -r -a RECORD_TYPES <<< "$DEFAULT_RECORD_TYPES"
    fi

    if [[ ${#SUBDOMAIN_KEYS[@]} -eq 0 ]]; then
        parse_subdomains "$DEFAULT_SUBDOMAINS"
    fi
}

# Parse subdomain:type mappings into SUBDOMAIN_KEYS and SUBDOMAIN_TYPES.
# Params: $1 comma-separated list like "www:A,_dmarc:TXT".
# Invalid entries are skipped with warnings.
parse_subdomains() {
    local pairs="$1"
    local token=""
    local key=""
    local typ=""

    SUBDOMAIN_KEYS=()
    SUBDOMAIN_TYPES=()

    IFS=',' read -r -a _tmp_pairs <<< "$pairs"
    for token in "${_tmp_pairs[@]}"; do
        token=$(trim "$token")
        [[ -z "$token" ]] && continue

        key="${token%%:*}"
        typ="${token##*:}"
        key=$(trim "$key")
        typ=$(trim "$typ")
        typ=$(to_lower "$typ")

        if [[ -z "$key" || -z "$typ" || "$key" == "$typ" ]]; then
            log_warn "Skipping invalid subdomain mapping: $token"
            continue
        fi

        SUBDOMAIN_KEYS+=("$key")
        SUBDOMAIN_TYPES["$key"]="$typ"
    done
}

# Read domains from input file.
# Supports plain format and category markers ([full]/[alias]/[simple]).
# Populates parallel arrays DOMAINS[] and CATEGORIES[].
read_domains() {
    local line=""
    local clean=""
    local category="full"

    DOMAINS=()
    CATEGORIES=()

    while IFS= read -r line || [[ -n "$line" ]]; do
        clean=$(trim "$line")
        [[ -z "$clean" ]] && continue
        [[ "$clean" =~ ^# ]] && continue

        if [[ "$clean" =~ ^\[[A-Za-z0-9_-]+\]$ ]]; then
            category=$(to_lower "${clean:1:${#clean}-2}")
            continue
        fi

        clean=$(to_lower "$clean")
        DOMAINS+=("$clean")
        CATEGORIES+=("$category")
    done < "$INPUT_FILE"
}

# Execute a short DNS query via dig for one domain/type/resolver tuple.
# Params: $1 domain, $2 record type, $3 resolver IP/host (optional).
# Returns: non-empty answer lines on stdout.
dig_short() {
    local domain="$1"
    local typ="$2"
    local resolver="$3"

    if [[ -n "$resolver" ]]; then
        dig +short +timeout="$DNS_TIMEOUT" "$domain" "$typ" "@$resolver" 2>/dev/null | sed '/^$/d'
    else
        dig +short +timeout="$DNS_TIMEOUT" "$domain" "$typ" 2>/dev/null | sed '/^$/d'
    fi
}

# Build a human-readable DNS section for TXT report output.
# Params: $1 domain, $2 resolver.
# Includes configured main record types and configured subdomain checks.
dns_collect_record_block() {
    local domain="$1"
    local resolver="$2"
    local typ=""
    local sub=""
    local stype=""
    local target=""
    local ans=""

    printf 'Resolver: %s\n' "$resolver"
    printf '  Main records:\n'
    for typ in "${RECORD_TYPES[@]}"; do
        ans=$(dig_short "$domain" "$typ" "$resolver" | tr '\n' ';' | sed 's/;*$//')
        printf '    %s: %s\n' "$(to_lower "$typ")" "${ans:-<empty>}"
    done

    printf '  Subdomain records:\n'
    for sub in "${SUBDOMAIN_KEYS[@]}"; do
        stype="${SUBDOMAIN_TYPES[$sub]}"
        target="$sub.$domain"
        ans=$(dig_short "$target" "$stype" "$resolver" | tr '\n' ';' | sed 's/;*$//')
        printf '    %s (%s): %s\n' "$sub" "$stype" "${ans:-<empty>}"
    done
}

# Build a compact DNS snapshot string for CSV/JSON output.
# Params: $1 domain, $2 resolver.
# Returns: semicolon-separated key/value pairs like "A=...;NS=...;".
dns_snapshot_for_csv() {
    local domain="$1"
    local resolver="$2"
    local typ=""
    local row=""
    local ans=""

    row=""
    for typ in "${RECORD_TYPES[@]}"; do
        ans=$(dig_short "$domain" "$typ" "$resolver" | tr '\n' ';' | sed 's/;*$//')
        row+="${typ}=${ans};"
    done
    printf '%s' "$row"
}

# Query the .hu WebWhois endpoint with a two-step cookie-based flow.
# Params: $1 domain.
# Returns: raw HTML response body on stdout.
fetch_whois_hu_html() {
    local domain="$1"
    local cookie_file="/tmp/domain_audit_cookie_$$.txt"
    local response=""

    curl -sS --max-time "$WHOIS_TIMEOUT" -c "$cookie_file" \
        -A "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36" \
        "${WHOIS_HU_URL}/${domain}" >/dev/null 2>&1

    response=$(curl -sS --max-time "$WHOIS_TIMEOUT" -b "$cookie_file" \
        -X POST \
        -A "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -H "Referer: ${WHOIS_HU_URL}/${domain}" \
        --data-raw "" \
        "${WHOIS_HU_URL}/${domain}" 2>/dev/null || true)

    rm -f "$cookie_file"
    printf '%s' "$response"
}

# Parse .hu WebWhois HTML and extract normalized registration fields.
# Params: $1 raw HTML.
# Returns: pipe-separated tuple:
#   status|created|expires|registrar|organization|nameservers
# Status can be: REGISTERED, AVAILABLE, RATE_LIMITED, UNKNOWN.
parse_whois_hu_html() {
    local html="$1"
    local one_line=""
    local created=""
    local expires=""
    local registrar=""
    local org=""
    local nameservers=""
    local status="UNKNOWN"

    one_line=$(printf '%s' "$html" | tr '\n' ' ' | sed 's/[[:space:]]\+/ /g')

    created=$(printf '%s' "$one_line" | grep -oP 'Regisztrálva:</td><td>\s*\K\d{4}-\d{2}-\d{2}' | head -1)
    expires=$(printf '%s' "$one_line" | grep -oP 'Lejárati idő:</td><td>\s*\K\d{4}-\d{2}-\d{2}' | head -1)
    registrar=$(printf '%s' "$one_line" | grep -oP 'Regisztrátor:</td><td>\s*\K[^<]+' | head -1 | sed 's/^\s*//;s/\s*$//')
    org=$(printf '%s' "$one_line" | grep -oP 'Domain-használó:</td><td>\s*\K[^<]+' | head -1 | sed 's/^\s*//;s/\s*$//')
    nameservers=$(printf '%s' "$one_line" | grep -oP 'Névszerverek:</td><td>\s*\K[^<]+' | head -1 | sed 's/^\s*//;s/\s*$//;s/[[:space:]]\+/,/g')

    if printf '%s' "$one_line" | grep -qi 'napi limit\|daily limit\|too many request\|too many quer\|t[uU]l sok lek[eé]rdez'; then
        status="RATE_LIMITED"
    elif printf '%s' "$one_line" | grep -qi 'Regisztrált\|Registered'; then
        status="REGISTERED"
    elif [[ -n "$created" || -n "$expires" || -n "$registrar" || -n "$org" ]]; then
        status="REGISTERED"
    elif printf '%s' "$one_line" | grep -qi 'nem található\|not found\|available\|szabad'; then
        status="AVAILABLE"
    fi

    printf '%s|%s|%s|%s|%s|%s' "$status" "$created" "$expires" "$registrar" "$org" "$nameservers"
}

# Parse generic whois CLI text output into normalized fields.
# Params: $1 raw whois text.
# Returns: pipe-separated tuple:
#   status|created|expires|registrar|organization|nameservers
parse_whois_cli() {
    local raw="$1"
    local status="UNKNOWN"
    local created=""
    local expires=""
    local registrar=""
    local org=""
    local nameservers=""
    local line=""

    if printf '%s' "$raw" | grep -Eqi 'No match for|NOT FOUND|No entries found|Status:\s*free|available'; then
        status="AVAILABLE"
    elif [[ -n "$raw" ]]; then
        status="REGISTERED"
    fi

    created=$(printf '%s' "$raw" | grep -Eim1 'Creation Date:|Registered on:|created:' | sed -E 's/^[^:]+:[[:space:]]*//')
    expires=$(printf '%s' "$raw" | grep -Eim1 'Expiry Date:|Registry Expiry Date:|Expires on:|paid-till:' | sed -E 's/^[^:]+:[[:space:]]*//')
    registrar=$(printf '%s' "$raw" | grep -Eim1 '^Registrar:|Sponsoring Registrar:' | sed -E 's/^[^:]+:[[:space:]]*//')
    org=$(printf '%s' "$raw" | grep -Eim1 '^Registrant Organization:|^org-name:' | sed -E 's/^[^:]+:[[:space:]]*//')

    while IFS= read -r line; do
        line=$(trim "$line")
        [[ -z "$line" ]] && continue
        nameservers+="${line},"
    done < <(printf '%s' "$raw" | grep -Ei '^Name Server:|^nserver:' | sed -E 's/^[^:]+:[[:space:]]*//I')
    nameservers="${nameservers%,}"

    printf '%s|%s|%s|%s|%s|%s' "$status" "$created" "$expires" "$registrar" "$org" "$nameservers"
}

# Collect registration data for a domain using TLD-aware strategy.
# Params: $1 domain.
# .hu uses webwhois HTML parsing, other TLDs use whois CLI when available.
# Returns: normalized pipe-separated tuple.
whois_collect() {
    local domain="$1"
    local tld="${domain##*.}"
    local raw=""

    if [[ "$tld" == "hu" ]]; then
        raw=$(fetch_whois_hu_html "$domain")
        parse_whois_hu_html "$raw"
        return
    fi

    if command_exists whois; then
        raw=$(whois "$domain" 2>/dev/null || true)
        parse_whois_cli "$raw"
    else
        printf '%s|%s|%s|%s|%s|%s' "UNKNOWN" "" "" "" "" ""
    fi
}

# Determine if any configured DNS type has at least one answer.
# Params: $1 domain.
# Returns: "true" or "false" on stdout.
is_dns_present() {
    local domain="$1"
    local resolver=""
    local typ=""
    local ans=""

    for resolver in "${RESOLVERS[@]}"; do
        for typ in "${RECORD_TYPES[@]}"; do
            ans=$(dig_short "$domain" "$typ" "$resolver" | head -1)
            if [[ -n "$ans" ]]; then
                printf 'true'
                return
            fi
        done
    done

    printf 'false'
}

# Infer final domain status from WHOIS state and DNS presence.
# Params: $1 whois_status, $2 dns_present.
# Returns: final status token used in reports.
infer_status() {
    local whois_status="$1"
    local dns_present="$2"

    if [[ "$whois_status" == "REGISTERED" ]]; then
        printf 'REGISTERED'
        return
    fi
    if [[ "$whois_status" == "RATE_LIMITED" && "$dns_present" == "true" ]]; then
        printf 'WHOIS_RATE_LIMITED_DNS_PRESENT'
        return
    fi
    if [[ "$whois_status" == "RATE_LIMITED" && "$dns_present" == "false" ]]; then
        printf 'WHOIS_RATE_LIMITED'
        return
    fi
    if [[ "$whois_status" == "AVAILABLE" && "$dns_present" == "false" ]]; then
        printf 'AVAILABLE'
        return
    fi
    if [[ "$whois_status" == "AVAILABLE" && "$dns_present" == "true" ]]; then
        printf 'POSSIBLY_REGISTERED'
        return
    fi
    if [[ "$whois_status" == "UNKNOWN" && "$dns_present" == "true" ]]; then
        printf 'LIKELY_REGISTERED'
        return
    fi
    printf 'UNKNOWN'
}

# Create and initialize output files (TXT, CSV, JSONL) with headers.
# Uses global output file path variables.
write_headers() {
    printf 'Domain Audit Report - %s\n' "$(date)" > "$TXT_FILE"
    printf '============================================================\n\n' >> "$TXT_FILE"

    printf '"domain","category","final_status","whois_status","dns_present","created","expires","registrar","organization","whois_nameservers","dns_snapshot"\n' > "$CSV_FILE"
    : > "$JSONL_FILE"
}

# Append one domain's normalized and detailed result to all output formats.
# Params:
#   $1 domain, $2 category, $3 final_status, $4 whois_status, $5 dns_present,
#   $6 created, $7 expires, $8 registrar, $9 organization,
#   ${10} whois_nameservers, ${11} dns_snapshot_summary.
write_domain_report() {
    local domain="$1"
    local category="$2"
    local final_status="$3"
    local whois_status="$4"
    local dns_present="$5"
    local created="$6"
    local expires="$7"
    local registrar="$8"
    local org="$9"
    local whois_ns="${10}"
    local dns_summary="${11}"
    local resolver=""

    printf 'Domain: %s\n' "$domain" >> "$TXT_FILE"
    printf 'Category: %s\n' "$category" >> "$TXT_FILE"
    printf 'Final status: %s\n' "$final_status" >> "$TXT_FILE"
    printf 'WHOIS status: %s\n' "$whois_status" >> "$TXT_FILE"
    printf 'DNS present: %s\n' "$dns_present" >> "$TXT_FILE"
    [[ -n "$created" ]] && printf 'Created: %s\n' "$created" >> "$TXT_FILE"
    [[ -n "$expires" ]] && printf 'Expires: %s\n' "$expires" >> "$TXT_FILE"
    [[ -n "$registrar" ]] && printf 'Registrar: %s\n' "$registrar" >> "$TXT_FILE"
    [[ -n "$org" ]] && printf 'Organization: %s\n' "$org" >> "$TXT_FILE"
    [[ -n "$whois_ns" ]] && printf 'WHOIS nameservers: %s\n' "$whois_ns" >> "$TXT_FILE"
    printf '\nDNS details:\n' >> "$TXT_FILE"

    for resolver in "${RESOLVERS[@]}"; do
        dns_collect_record_block "$domain" "$resolver" >> "$TXT_FILE"
    done

    printf '\n------------------------------------------------------------\n\n' >> "$TXT_FILE"

    printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
        "$(escape_csv "$domain")" \
        "$(escape_csv "$category")" \
        "$(escape_csv "$final_status")" \
        "$(escape_csv "$whois_status")" \
        "$(escape_csv "$dns_present")" \
        "$(escape_csv "$created")" \
        "$(escape_csv "$expires")" \
        "$(escape_csv "$registrar")" \
        "$(escape_csv "$org")" \
        "$(escape_csv "$whois_ns")" \
        "$(escape_csv "$dns_summary")" \
        >> "$CSV_FILE"

    printf '{"domain":"%s","category":"%s","final_status":"%s","whois_status":"%s","dns_present":"%s","created":"%s","expires":"%s","registrar":"%s","organization":"%s","whois_nameservers":"%s","dns_snapshot":"%s"}\n' \
        "$(escape_json "$domain")" \
        "$(escape_json "$category")" \
        "$(escape_json "$final_status")" \
        "$(escape_json "$whois_status")" \
        "$(escape_json "$dns_present")" \
        "$(escape_json "$created")" \
        "$(escape_json "$expires")" \
        "$(escape_json "$registrar")" \
        "$(escape_json "$org")" \
        "$(escape_json "$whois_ns")" \
        "$(escape_json "$dns_summary")" \
        >> "$JSONL_FILE"
}

# Run end-to-end audit for every loaded domain and build summary counters.
# Uses global DOMAINS/CATEGORIES and writes to all report outputs.
audit_domains() {
    local i=0
    local total=${#DOMAINS[@]}
    local domain=""
    local category=""
    local whois_data=""
    local whois_status=""
    local created=""
    local expires=""
    local registrar=""
    local org=""
    local whois_ns=""
    local dns_present=""
    local final_status=""
    local dns_parts=()
    local resolver=""
    local snap=""
    local dns_summary=""

    local c_registered=0
    local c_available=0
    local c_likely=0
    local c_unknown=0

    for ((i = 0; i < total; i++)); do
        domain="${DOMAINS[$i]}"
        category="${CATEGORIES[$i]}"

        printf 'Checking (%d/%d): %s ... ' "$((i + 1))" "$total" "$domain"

        whois_data=$(whois_collect "$domain")
        IFS='|' read -r whois_status created expires registrar org whois_ns <<< "$whois_data"

        dns_present=$(is_dns_present "$domain")
        final_status=$(infer_status "$whois_status" "$dns_present")

        dns_parts=()
        for resolver in "${RESOLVERS[@]}"; do
            snap=$(dns_snapshot_for_csv "$domain" "$resolver")
            dns_parts+=("$resolver{$snap}")
        done
        dns_summary=$(join_by '|' "${dns_parts[@]}")

        write_domain_report "$domain" "$category" "$final_status" "$whois_status" "$dns_present" "$created" "$expires" "$registrar" "$org" "$whois_ns" "$dns_summary"

        case "$final_status" in
            REGISTERED) ((c_registered++)) ;;
            AVAILABLE) ((c_available++)) ;;
            POSSIBLY_REGISTERED|LIKELY_REGISTERED) ((c_likely++)) ;;
            *) ((c_unknown++)) ;;
        esac

        printf '%s\n' "$final_status"
        sleep "$RATE_LIMIT_SLEEP"
    done

    printf 'Summary\n' >> "$TXT_FILE"
    printf '============================================================\n' >> "$TXT_FILE"
    printf 'Total domains: %d\n' "$total" >> "$TXT_FILE"
    printf 'REGISTERED: %d\n' "$c_registered" >> "$TXT_FILE"
    printf 'AVAILABLE: %d\n' "$c_available" >> "$TXT_FILE"
    printf 'LIKELY/POSSIBLY REGISTERED: %d\n' "$c_likely" >> "$TXT_FILE"
    printf 'UNKNOWN: %d\n' "$c_unknown" >> "$TXT_FILE"

    printf '\nDone. Outputs:\n'
    printf '  TXT   : %s\n' "$TXT_FILE"
    printf '  CSV   : %s\n' "$CSV_FILE"
    printf '  JSONL : %s\n' "$JSONL_FILE"
}

# Entry point: parse arguments, validate dependencies, load input, and run audit.
main() {
    parse_args "$@"

    if ! command_exists dig; then
        log_error "dig command is required"
        exit 2
    fi
    if ! command_exists curl; then
        log_error "curl command is required"
        exit 2
    fi

    read_domains
    if [[ ${#DOMAINS[@]} -eq 0 ]]; then
        log_error "No domains found in input file"
        exit 2
    fi

    local timestamp
    timestamp=$(date +%Y%m%d_%H%M%S)
    TXT_FILE="${OUTPUT_PREFIX}_${timestamp}.txt"
    CSV_FILE="${OUTPUT_PREFIX}_${timestamp}.csv"
    JSONL_FILE="${OUTPUT_PREFIX}_${timestamp}.jsonl"

    write_headers

    log_info "Loaded ${#DOMAINS[@]} domains from $INPUT_FILE"
    log_info "Resolvers: $(join_by ',' "${RESOLVERS[@]}")"
    log_info "Record types: $(join_by ',' "${RECORD_TYPES[@]}")"

    audit_domains
}

main "$@"
