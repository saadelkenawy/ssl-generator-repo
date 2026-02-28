#!/bin/bash
set -euo pipefail

# --- Configuration & Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# --- Task 2: OpenSSL Version Check ---
check_openssl() {
    if ! command -v openssl &>/dev/null; then
        echo -e "${RED}Error: OpenSSL is not installed or not in PATH.${NC}"
        exit 1
    fi
    local ver
    ver=$(openssl version | awk '{print $2}')
    local major minor
    major=$(echo "$ver" | cut -d. -f1)
    minor=$(echo "$ver" | cut -d. -f2)
    if [[ "$major" -lt 1 ]] || { [[ "$major" -eq 1 ]] && [[ "$minor" -lt 1 ]]; }; then
        echo -e "${RED}Error: OpenSSL >= 1.1.1 required. Found: $ver${NC}"
        exit 1
    fi
    echo -e "${GREEN}OpenSSL $ver detected.${NC}"
}

# --- Validation Functions ---

validate_domain() {
    local domain=$1
    local type=$2
    local allow_wildcard=${3:-false}

    if [[ -z "$domain" ]]; then
        echo -e "${RED}Error: $type cannot be empty${NC}"
        return 1
    fi
    if [[ "$domain" =~ [[:space:]] ]]; then
        echo -e "${RED}Error: $type cannot contain spaces${NC}"
        return 1
    fi
    if [[ "$domain" =~ [\'\"] ]]; then
        echo -e "${RED}Error: $type cannot contain quotes${NC}"
        return 1
    fi
    if [[ "$domain" =~ -$ ]]; then
        echo -e "${RED}Error: $type cannot end with a hyphen${NC}"
        return 1
    fi
    if [[ "$domain" =~ ^\.|\.$ ]]; then
        echo -e "${RED}Error: $type cannot start or end with a dot${NC}"
        return 1
    fi
    if [[ ! "$domain" =~ \. ]]; then
        echo -e "${RED}Error: $type should contain at least one dot (e.g., example.com)${NC}"
        return 1
    fi

    if [[ "$allow_wildcard" == true && "$domain" =~ ^\*\. ]]; then
        local base_domain="${domain#\*.}"
        if [[ ! "$base_domain" =~ ^[a-zA-Z0-9][a-zA-Z0-9\.-]*[a-zA-Z0-9]$ ]]; then
            echo -e "${RED}Error: Invalid domain after wildcard in $type${NC}"
            return 1
        fi
        if [[ "$base_domain" =~ \.\.|-- ]]; then
            echo -e "${RED}Error: $type cannot have consecutive dots or hyphens${NC}"
            return 1
        fi
        return 0
    fi

    if [[ ! "$domain" =~ ^[a-zA-Z0-9][a-zA-Z0-9\.-]*[a-zA-Z0-9]$ ]]; then
        echo -e "${RED}Error: $type contains invalid characters${NC}"
        return 1
    fi
    if [[ "$domain" =~ \.\.|-- ]]; then
        echo -e "${RED}Error: $type cannot have consecutive dots or hyphens${NC}"
        return 1
    fi
    return 0
}

validate_ip() {
    local ip=$1
    if [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        IFS='.' read -r a b c d <<< "$ip"
        if [[ $a -le 255 && $b -le 255 && $c -le 255 && $d -le 255 ]]; then
            if [[ "$ip" == "0.0.0.0" || "$ip" == "127.0.0.1" ]]; then
                echo -e "${YELLOW}Warning: IP $ip is reserved and may not be accepted by all systems${NC}"
                return 2
            fi
            return 0
        fi
    fi
    return 1
}

parse_list() {
    local input=$1
    local type=$2
    local result_var=$3
    eval "$result_var=()"
    if [[ -z "$input" ]]; then
        return 0
    fi
    input=$(echo "$input" | sed "s/[[:space:]\'\"]//g")
    input=$(echo "$input" | sed 's/^,*//; s/,*$//')
    IFS=',' read -ra entries <<< "$input"
    local has_errors=0
    for entry in "${entries[@]}"; do
        if [[ -z "$entry" ]]; then
            continue
        fi
        case "$type" in
            "DNS")
                if validate_domain "$entry" "SAN DNS entry" true; then
                    eval "$result_var+=(\"$entry\")"
                else
                    has_errors=1
                    echo -e "${YELLOW}Skipping invalid DNS entry: $entry${NC}"
                fi
                ;;
            "IP")
                if validate_ip "$entry"; then
                    local valid=$?
                    if [[ $valid -eq 0 ]] || [[ $valid -eq 2 ]]; then
                        eval "$result_var+=(\"$entry\")"
                    fi
                else
                    has_errors=1
                    echo -e "${YELLOW}Skipping invalid IP entry: $entry${NC}"
                fi
                ;;
        esac
    done
    return $has_errors
}

remove_duplicates() {
    local array_name=$1
    local -a temp_array=()
    local -a unique_array=()
    declare -A seen=()
    local len
    eval "len=\${#${array_name}[@]}"
    if [[ $len -gt 0 ]]; then
        eval "temp_array=(\"\${${array_name}[@]}\")"
    fi
    for item in "${temp_array[@]+"${temp_array[@]}"}"; do
        if [[ -z "${seen[$item]+x}" ]]; then
            seen["$item"]=1
            unique_array+=("$item")
        else
            echo -e "${YELLOW}Warning: Duplicate entry '$item' removed${NC}"
        fi
    done
    if [[ ${#unique_array[@]} -gt 0 ]]; then
        eval "$array_name=(\"\${unique_array[@]}\")"
    else
        eval "$array_name=()"
    fi
}

validate_country() {
    local country=$1
    if [[ ! "$country" =~ ^[A-Z]{2}$ ]]; then
        echo -e "${RED}Error: Country must be exactly 2 uppercase letters (e.g., US, EG)${NC}"
        return 1
    fi
    return 0
}

validate_text_field() {
    local value=$1
    local field_name=$2
    if [[ -z "$value" ]]; then
        echo -e "${RED}Error: $field_name cannot be empty${NC}"
        return 1
    fi
    if [[ "$value" =~ [,/\'\"\\] ]]; then
        echo -e "${RED}Error: $field_name cannot contain commas, quotes, slashes, or backslashes${NC}"
        return 1
    fi
    return 0
}

# --- Improved function to extract DN field from certificate ---
extract_dn_field() {
    local cert=$1
    local field=$2
    openssl x509 -in "$cert" -noout -subject -nameopt sep_multiline 2>/dev/null | \
        sed 's/^ *//' | grep "^${field}=" | cut -d= -f2- | head -1 || true
}

# --- Task 5: Chain Verification ---
verify_chain() {
    local domain_clean=$1
    local inter_cert=$2
    local root_cert=$3
    echo -e "\n${GREEN}[*] Verifying certificate chain for ${domain_clean}.crt...${NC}"
    if openssl verify -CAfile "$root_cert" -untrusted "$inter_cert" "${domain_clean}.crt" > /dev/null 2>&1; then
        echo -e "${GREEN}Chain verification: PASSED${NC}"
    else
        echo -e "${RED}Chain verification: FAILED - check your certificate files${NC}"
    fi
}

# --- Task 8: Certificate Info Writer ---
write_cert_info() {
    local domain_clean=$1
    local outfile="${domain_clean}-cert-info.txt"
    echo -e "${GREEN}[*] Writing certificate info to ${outfile}...${NC}"
    {
        echo "=== Certificate Info: ${domain_clean}.crt ==="
        echo "Generated: $(date)"
        echo ""
        openssl x509 -in "${domain_clean}.crt" -text -noout
    } > "$outfile"
    echo -e "${GREEN}Certificate info saved: $outfile${NC}"
}

# --- Task 9: Generation Log Writer ---
write_generation_log() {
    local logfile=$1
    local mode=$2
    local domain=$3
    local dn_base=$4
    local san_dns=$5
    local san_ip=$6
    local operator=$7
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    {
        echo "=================================="
        echo "Timestamp  : $timestamp"
        echo "Mode       : $mode"
        echo "Operator   : $operator"
        echo "DN Base    : $dn_base"
        echo "Domain (CN): $domain"
        echo "SAN DNS    : $san_dns"
        echo "SAN IP     : $san_ip"
        echo "=================================="
        echo ""
    } >> "$logfile"
    echo -e "${GREEN}Generation log updated: $logfile${NC}"
}

# --- Function to generate a server certificate (used in both modes) ---
generate_server_cert() {
    local domain_cn=$1
    local inter_key=$4
    local inter_cert=$5
    local root_cert=$6
    local dn_base=$7
    local user_name=$8

    # Safely copy caller arrays — ${!n} on empty arrays fails under set -u in bash < 5
    local -a san_dns_array=()
    local -a san_ip_array=()
    local _dns_var="${2%%\[*}"
    local _ip_var="${3%%\[*}"
    local _dns_len _ip_len
    eval "_dns_len=\${#${_dns_var}[@]}"
    eval "_ip_len=\${#${_ip_var}[@]}"
    [[ $_dns_len -gt 0 ]] && eval "san_dns_array=(\"\${${2}}\")"
    [[ $_ip_len -gt 0 ]] && eval "san_ip_array=(\"\${${3}}\")"

    local domain_clean
    domain_clean=$(echo "$domain_cn" | sed 's/\./-/g')

    # Build SAN string
    local san_string="DNS:$domain_cn"
    for dns in "${san_dns_array[@]+"${san_dns_array[@]}"}"; do
        san_string+=",DNS:$dns"
    done
    for ip in "${san_ip_array[@]+"${san_ip_array[@]}"}"; do
        san_string+=",IP:$ip"
    done

    echo -e "\n${GREEN}[*] Creating Server Certificate for $domain_cn...${NC}"
    openssl genrsa -out "${domain_clean}.key" 2048

    local server_subj="${dn_base}/CN=$domain_cn"
    MSYS_NO_PATHCONV=1 openssl req -new -key "${domain_clean}.key" -out "${domain_clean}.csr" -subj "$server_subj" \
        -addext "subjectAltName=$san_string"

    # Sign with 3 years validity (1095 days)
    openssl x509 -req -in "${domain_clean}.csr" -CA "$inter_cert" -CAkey "$inter_key" -CAcreateserial \
        -out "${domain_clean}.crt" -days 1095 -sha256 -copy_extensions copy

    # Create fullchain
    cat "${domain_clean}.crt" "$inter_cert" "$root_cert" > "${domain_clean}-fullchain.pem"

    # Task 6: Cleanup temp CSR file
    rm -f "${domain_clean}.csr"

    echo -e "${GREEN}Server certificate generated: ${domain_clean}.crt (valid for 3 years)${NC}"
    echo -e "${GREEN}Full chain: ${domain_clean}-fullchain.pem${NC}"
    # Task 10: Plain-text key storage warning
    echo -e "${YELLOW}Security: '${domain_clean}.key' is stored unencrypted. Restrict access to this directory.${NC}"
}

# --- Main Script ---

# --- Task 7: Help / Usage ---
if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
    echo -e "${BLUE}${BOLD}SSL Certificate Generator - Usage${NC}"
    echo ""
    echo "  Usage: ./ssl-generator.sh [--help|-h]"
    echo ""
    echo "  Mode 1  Full PKI generation (Root CA + Intermediate CA + server cert)"
    echo "  Mode 2  Issue additional server certs using an existing CA"
    echo ""
    echo "  Prerequisites: OpenSSL >= 1.1.1"
    echo ""
    echo "  Output (Mode 1)  certs_<domain>_<YYYYMMDD>/"
    echo "    root_key.pem              Root CA private key   (keep secret)"
    echo "    root_cert.pem             Root CA certificate   (install into trusted store)"
    echo "    inter_key.pem             Intermediate CA private key   (keep secret)"
    echo "    inter_cert.pem            Intermediate CA certificate"
    echo "    fullchain.pem             CA chain (intermediate + root)"
    echo "    <domain>.key              Server private key    (unencrypted)"
    echo "    <domain>.crt              Server certificate"
    echo "    <domain>-fullchain.pem    Full chain (server + intermediate + root)"
    echo "    <domain>-cert-info.txt    Human-readable certificate details"
    echo "    generation.log            Audit log of this generation session"
    echo ""
    echo "  Output (Mode 2)  certs_<domain>_<YYYYMMDD>/"
    echo "    <domain>.key              Server private key    (unencrypted)"
    echo "    <domain>.crt              Server certificate"
    echo "    <domain>-fullchain.pem    Full chain (server + intermediate + root)"
    echo "    <domain>-cert-info.txt    Human-readable certificate details"
    echo "    generation.log            Audit log of this generation session"
    echo ""
    echo "  Examples:"
    echo "    ./ssl-generator.sh          Run interactively"
    echo "    ./ssl-generator.sh --help   Show this help message"
    exit 0
fi

echo -e "${BLUE}${BOLD}===================================================${NC}"
echo -e "${BLUE}${BOLD}   PKI Certificate Generator | By Saad El-Kenawy     ${NC}"
echo -e "${BLUE}${BOLD}===================================================${NC}"
echo ""

# Task 2: Run OpenSSL check before anything else
check_openssl
echo ""

# --- Mode Selection ---
echo "Select operation mode:"
echo "  1) Generate new PKI (Root CA + Intermediate CA + first server certificate)"
echo "  2) Generate additional server certificate using existing CA"
MODE=""
read -p "Enter choice (1 or 2): " MODE || true

if [[ "$MODE" != "1" && "$MODE" != "2" ]]; then
    echo -e "${RED}Invalid choice. Exiting.${NC}"
    exit 1
fi

if [[ "$MODE" == "1" ]]; then
    # --- Mode 1: Full PKI generation ---

    # Collect DN fields
    while true; do
        ORG_NAME=""
        read -p "Enter Organization Name (O) [e.g., MyCompany]: " ORG_NAME || true
        validate_text_field "$ORG_NAME" "Organization Name" && break
    done

    while true; do
        COUNTRY=""
        read -p "Enter Country Code (C) [2 letters, e.g., US]: " COUNTRY || true
        COUNTRY=$(echo "$COUNTRY" | tr '[:lower:]' '[:upper:]')
        validate_country "$COUNTRY" && break
    done

    while true; do
        STATE=""
        read -p "Enter State or Province (ST) [e.g., California]: " STATE || true
        validate_text_field "$STATE" "State/Province" && break
    done

    while true; do
        LOCALITY=""
        read -p "Enter Locality / City (L) [e.g., San Francisco]: " LOCALITY || true
        validate_text_field "$LOCALITY" "Locality/City" && break
    done

    OU=""
    read -p "Enter Organizational Unit (OU) [optional, e.g., IT]: " OU || true
    if [[ -n "$OU" ]]; then
        if ! validate_text_field "$OU" "Organizational Unit"; then
            echo -e "${YELLOW}Warning: Organizational Unit invalid, skipping.${NC}"
            OU=""
        fi
    fi

    while true; do
        USER_NAME=""
        read -p "Enter your Name/Operator (e.g., John Doe): " USER_NAME || true
        if [[ -n "$USER_NAME" && ! "$USER_NAME" =~ [\'\"] ]]; then
            break
        else
            echo -e "${RED}Error: Name cannot be empty or contain quotes${NC}"
        fi
    done

    echo ""

    # Primary Domain with validation (no wildcard)
    while true; do
        DOMAIN_CN=""
        read -p "Enter Primary Domain (CN) (e.g., www.example.com): " DOMAIN_CN || true
        if validate_domain "$DOMAIN_CN" "Primary Domain" false; then
            break
        fi
        echo -e "${YELLOW}Note: Domain should be like 'example.com' or 'server.example.com'${NC}"
    done

    DOMAIN_CLEAN=$(echo "$DOMAIN_CN" | sed 's/\./-/g')

    echo ""

    # SAN DNS list (wildcards allowed)
    echo -e "${BOLD}SAN DNS List Instructions:${NC}"
    echo -e "  - Use commas ONLY to separate entries (e.g., alt1.com,*.example.com)"
    echo -e "  - No spaces, quotes, or special characters"
    echo -e "  - Wildcard entries like *.example.com are allowed"
    echo ""

    declare -a san_dns_array=()
    while true; do
        SAN_DNS_INPUT=""
        read -p "Enter SAN DNS list (comma separated) [Leave empty if none]: " SAN_DNS_INPUT || true
        parse_list "$SAN_DNS_INPUT" "DNS" san_dns_array || true
        remove_duplicates san_dns_array

        # Remove primary domain if present
        for i in "${!san_dns_array[@]}"; do
            if [[ "${san_dns_array[$i]}" == "$DOMAIN_CN" ]]; then
                echo -e "${YELLOW}Warning: Primary domain '$DOMAIN_CN' is already included automatically. Removing.${NC}"
                unset 'san_dns_array[$i]'
            fi
        done
        san_dns_array=("${san_dns_array[@]+"${san_dns_array[@]}"}")

        if [[ ${#san_dns_array[@]} -gt 0 ]]; then
            echo -e "${GREEN}Valid SAN DNS entries: ${san_dns_array[*]}${NC}"
            confirm=""
            read -p "Continue with these entries? (y/n): " confirm || true
            [[ "$confirm" =~ ^[Yy]$ ]] && break
            san_dns_array=()
        else
            [[ -z "$SAN_DNS_INPUT" ]] && echo -e "${GREEN}No SAN DNS entries added.${NC}"
            break
        fi
    done

    echo ""

    # SAN IP list
    echo -e "${BOLD}SAN IP List Instructions:${NC}"
    echo -e "  - Use commas ONLY to separate entries (e.g., 10.0.0.1,10.0.0.2)"
    echo -e "  - No spaces, quotes, or special characters"
    echo -e "  - Each entry must be a valid IPv4 address"
    echo -e "  - Reserved IPs (0.0.0.0, 127.0.0.1) are not recommended${NC}"
    echo ""

    declare -a san_ip_array=()
    while true; do
        SAN_IP_INPUT=""
        read -p "Enter SAN IP list (comma separated) [Leave empty if none]: " SAN_IP_INPUT || true
        parse_list "$SAN_IP_INPUT" "IP" san_ip_array || true
        remove_duplicates san_ip_array

        # Filter reserved IPs
        declare -a filtered_ips=()
        for ip in "${san_ip_array[@]+"${san_ip_array[@]}"}"; do
            if [[ "$ip" == "0.0.0.0" || "$ip" == "127.0.0.1" ]]; then
                echo -e "${YELLOW}Warning: Reserved IP '$ip' removed.${NC}"
            else
                filtered_ips+=("$ip")
            fi
        done
        san_ip_array=("${filtered_ips[@]+"${filtered_ips[@]}"}")

        if [[ ${#san_ip_array[@]} -gt 0 ]]; then
            echo -e "${GREEN}Valid SAN IP entries: ${san_ip_array[*]}${NC}"
            confirm=""
            read -p "Continue with these entries? (y/n): " confirm || true
            [[ "$confirm" =~ ^[Yy]$ ]] && break
            san_ip_array=()
        else
            [[ -z "$SAN_IP_INPUT" ]] && echo -e "${GREEN}No SAN IP entries added.${NC}"
            break
        fi
    done

    echo ""

    # Build SAN string (for display only)
    SAN_STRING="DNS:$DOMAIN_CN"
    for dns in "${san_dns_array[@]+"${san_dns_array[@]}"}"; do
        SAN_STRING+=",DNS:$dns"
    done
    for ip in "${san_ip_array[@]+"${san_ip_array[@]}"}"; do
        SAN_STRING+=",IP:$ip"
    done
    echo -e "${BLUE}SAN string: $SAN_STRING${NC}"

    # Create output directory
    DIR="certs_${DOMAIN_CLEAN}_$(date +%Y%m%d)"
    mkdir -p "$DIR"
    cd "$DIR" || exit

    # Build base DN
    DN_BASE="/C=$COUNTRY/ST=$STATE/L=$LOCALITY/O=$ORG_NAME"
    [[ -n "$OU" ]] && DN_BASE="$DN_BASE/OU=$OU"

    # Generate Root CA
    echo -e "\n${GREEN}[*] Creating Root CA...${NC}"
    openssl genrsa -out root_key.pem 4096
    MSYS_NO_PATHCONV=1 openssl req -x509 -new -nodes -key root_key.pem -sha256 -days 3650 \
        -out root_cert.pem -subj "${DN_BASE}/CN=Server Secure Root CA | By $USER_NAME"
    # Task 10: Plain-text key storage warning
    echo -e "${YELLOW}Security: 'root_key.pem' is stored unencrypted. Restrict access to this directory.${NC}"

    # Task 3 (4096-bit) & Task 4 (5-year validity): Generate Intermediate CA
    echo -e "\n${GREEN}[*] Creating Intermediate CA...${NC}"
    openssl genrsa -out inter_key.pem 4096
    MSYS_NO_PATHCONV=1 openssl req -new -key inter_key.pem -out inter.csr \
        -subj "${DN_BASE}/CN=Intermediate Secure Server CA | By $USER_NAME"
    echo -e "${YELLOW}Security: 'inter_key.pem' is stored unencrypted. Restrict access to this directory.${NC}"

    # Create ext.cnf for intermediate
    cat > ext.cnf << 'EOF'
[ v3_intermediate_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true
keyUsage = critical, digitalSignature, cRLSign, keyCertSign
EOF

    # Task 4: Reduced validity — 1825 days (5 years) instead of 3650
    openssl x509 -req -in inter.csr -CA root_cert.pem -CAkey root_key.pem -CAcreateserial \
        -out inter_cert.pem -days 1825 -sha256 -extfile ext.cnf -extensions v3_intermediate_ca

    # Task 6: Cleanup temp intermediate CSR and config
    rm -f ext.cnf inter.csr

    # Generate first server certificate using the function
    generate_server_cert "$DOMAIN_CN" san_dns_array[@] san_ip_array[@] \
        "inter_key.pem" "inter_cert.pem" "root_cert.pem" "$DN_BASE" "$USER_NAME"

    # Task 5: Verify chain
    verify_chain "$DOMAIN_CLEAN" "inter_cert.pem" "root_cert.pem"

    # Task 8: Write human-readable cert info
    write_cert_info "$DOMAIN_CLEAN"

    # Task 9: Write generation log
    write_generation_log "generation.log" "1 (Full PKI)" "$DOMAIN_CN" "$DN_BASE" \
        "${san_dns_array[*]:-none}" "${san_ip_array[*]:-none}" "$USER_NAME"

    # Create CA chain file
    cat inter_cert.pem root_cert.pem > fullchain.pem

    echo -e "\n${GREEN}PKI generation complete. Files are in: $(pwd)${NC}"

    # Display summary
    echo -e "\n${BLUE}${BOLD}================ SUMMARY =================${NC}"
    echo -e "Distinguished Name: $DN_BASE"
    echo -e "Operator: $USER_NAME"
    echo -e "Primary Domain: $DOMAIN_CN (3-year validity)"
    echo -e "SAN DNS Entries: ${#san_dns_array[@]} -> ${san_dns_array[*]:-}"
    echo -e "SAN IP Entries: ${#san_ip_array[@]} -> ${san_ip_array[*]:-}"
    echo -e "${BLUE}${BOLD}===========================================${NC}"

    cd - >/dev/null

else
    # --- Mode 2: Generate additional server certificate using existing CA ---

    echo -e "\n${BOLD}Mode 2: Generate additional server certificate using existing CA${NC}"
    echo "You will need the directory containing the existing CA files:"
    echo "  - inter_key.pem  (Intermediate CA private key)"
    echo "  - inter_cert.pem (Intermediate CA certificate)"
    echo "  - root_cert.pem  (Root CA certificate)"
    echo ""

    # Enable tab completion for path input
    CA_DIR=""
    read -e -p "Enter the full path to the directory containing CA files: " CA_DIR || true
    if [[ ! -d "$CA_DIR" ]]; then
        echo -e "${RED}Error: Directory does not exist.${NC}"
        exit 1
    fi

    # Check for required files
    if [[ ! -f "$CA_DIR/inter_key.pem" || ! -f "$CA_DIR/inter_cert.pem" || ! -f "$CA_DIR/root_cert.pem" ]]; then
        echo -e "${RED}Error: Missing required CA files in $CA_DIR (need inter_key.pem, inter_cert.pem, root_cert.pem)${NC}"
        exit 1
    fi

    # Extract DN components from the intermediate certificate to reuse
    echo -e "\n${GREEN}Extracting organization details from existing intermediate certificate...${NC}"
    INTER_CERT="$CA_DIR/inter_cert.pem"
    COUNTRY=$(extract_dn_field "$INTER_CERT" "C")
    STATE=$(extract_dn_field "$INTER_CERT" "ST")
    LOCALITY=$(extract_dn_field "$INTER_CERT" "L")
    ORG_NAME=$(extract_dn_field "$INTER_CERT" "O")
    OU=$(extract_dn_field "$INTER_CERT" "OU")

    if [[ -z "$COUNTRY" || -z "$STATE" || -z "$LOCALITY" || -z "$ORG_NAME" ]]; then
        echo -e "${YELLOW}Warning: Could not extract all DN fields from certificate. You may need to re-enter them.${NC}"
        # Fallback to manual input
        while true; do
            ORG_NAME=""
            read -p "Enter Organization Name (O): " ORG_NAME || true
            validate_text_field "$ORG_NAME" "Organization Name" && break
        done
        while true; do
            COUNTRY=""
            read -p "Enter Country Code (C) [2 letters]: " COUNTRY || true
            COUNTRY=$(echo "$COUNTRY" | tr '[:lower:]' '[:upper:]')
            validate_country "$COUNTRY" && break
        done
        while true; do
            STATE=""
            read -p "Enter State or Province (ST): " STATE || true
            validate_text_field "$STATE" "State/Province" && break
        done
        while true; do
            LOCALITY=""
            read -p "Enter Locality / City (L): " LOCALITY || true
            validate_text_field "$LOCALITY" "Locality/City" && break
        done
        OU=""
        read -p "Enter Organizational Unit (OU) [optional]: " OU || true
        if [[ -n "$OU" ]]; then
            validate_text_field "$OU" "Organizational Unit" || OU=""
        fi
    else
        echo -e "Using existing DN:"
        echo -e "  C=$COUNTRY, ST=$STATE, L=$LOCALITY, O=$ORG_NAME${OU:+, OU=$OU}"
    fi

    # Build base DN (will be reused for all certificates in this session)
    DN_BASE="/C=$COUNTRY/ST=$STATE/L=$LOCALITY/O=$ORG_NAME"
    [[ -n "$OU" ]] && DN_BASE="$DN_BASE/OU=$OU"

    # Loop for creating multiple certificates in mode 2
    while true; do
        echo ""
        # New server domain
        while true; do
            DOMAIN_CN=""
            read -p "Enter new server domain (CN) (e.g., sub.example.com): " DOMAIN_CN || true
            if validate_domain "$DOMAIN_CN" "Server Domain" false; then
                break
            fi
        done

        DOMAIN_CLEAN=$(echo "$DOMAIN_CN" | sed 's/\./-/g')

        echo ""

        # SAN DNS list (wildcards allowed)
        echo -e "${BOLD}SAN DNS List Instructions:${NC}"
        echo -e "  - Use commas ONLY to separate entries (e.g., alt1.com,*.example.com)"
        echo ""
        declare -a san_dns_array=()
        while true; do
            SAN_DNS_INPUT=""
            read -p "Enter SAN DNS list (comma separated) [Leave empty if none]: " SAN_DNS_INPUT || true
            parse_list "$SAN_DNS_INPUT" "DNS" san_dns_array || true
            remove_duplicates san_dns_array

            # Remove primary domain if present
            for i in "${!san_dns_array[@]}"; do
                if [[ "${san_dns_array[$i]}" == "$DOMAIN_CN" ]]; then
                    echo -e "${YELLOW}Warning: Primary domain '$DOMAIN_CN' is already included automatically. Removing.${NC}"
                    unset 'san_dns_array[$i]'
                fi
            done
            san_dns_array=("${san_dns_array[@]+"${san_dns_array[@]}"}")

            if [[ ${#san_dns_array[@]} -gt 0 ]]; then
                echo -e "${GREEN}Valid SAN DNS entries: ${san_dns_array[*]}${NC}"
                confirm=""
                read -p "Continue with these entries? (y/n): " confirm || true
                [[ "$confirm" =~ ^[Yy]$ ]] && break
                san_dns_array=()
            else
                [[ -z "$SAN_DNS_INPUT" ]] && echo -e "${GREEN}No SAN DNS entries added.${NC}"
                break
            fi
        done

        echo ""

        # SAN IP list
        echo -e "${BOLD}SAN IP List Instructions:${NC}"
        echo -e "  - Use commas ONLY to separate entries (e.g., 10.0.0.1,10.0.0.2)"
        echo ""
        declare -a san_ip_array=()
        while true; do
            SAN_IP_INPUT=""
            read -p "Enter SAN IP list (comma separated) [Leave empty if none]: " SAN_IP_INPUT || true
            parse_list "$SAN_IP_INPUT" "IP" san_ip_array || true
            remove_duplicates san_ip_array

            declare -a filtered_ips=()
            for ip in "${san_ip_array[@]+"${san_ip_array[@]}"}"; do
                if [[ "$ip" == "0.0.0.0" || "$ip" == "127.0.0.1" ]]; then
                    echo -e "${YELLOW}Warning: Reserved IP '$ip' removed.${NC}"
                else
                    filtered_ips+=("$ip")
                fi
            done
            san_ip_array=("${filtered_ips[@]+"${filtered_ips[@]}"}")

            if [[ ${#san_ip_array[@]} -gt 0 ]]; then
                echo -e "${GREEN}Valid SAN IP entries: ${san_ip_array[*]}${NC}"
                confirm=""
                read -p "Continue with these entries? (y/n): " confirm || true
                [[ "$confirm" =~ ^[Yy]$ ]] && break
                san_ip_array=()
            else
                [[ -z "$SAN_IP_INPUT" ]] && echo -e "${GREEN}No SAN IP entries added.${NC}"
                break
            fi
        done

        # Create output directory for new certificate
        NEW_DIR="certs_${DOMAIN_CLEAN}_$(date +%Y%m%d)"
        mkdir -p "$NEW_DIR"
        cd "$NEW_DIR" || exit

        # Generate the new server certificate
        generate_server_cert "$DOMAIN_CN" san_dns_array[@] san_ip_array[@] \
            "$CA_DIR/inter_key.pem" "$CA_DIR/inter_cert.pem" "$CA_DIR/root_cert.pem" \
            "$DN_BASE" "(using existing CA)"

        # Task 5: Verify chain
        verify_chain "$DOMAIN_CLEAN" "$CA_DIR/inter_cert.pem" "$CA_DIR/root_cert.pem"

        # Task 8: Write human-readable cert info
        write_cert_info "$DOMAIN_CLEAN"

        # Task 9: Write generation log
        write_generation_log "generation.log" "2 (Existing CA)" "$DOMAIN_CN" "$DN_BASE" \
            "${san_dns_array[*]:-none}" "${san_ip_array[*]:-none}" "(using existing CA)"

        echo -e "\n${GREEN}New server certificate generated in: $(pwd)${NC}"

        # Summary for this certificate
        echo -e "\n${BLUE}${BOLD}================ SUMMARY =================${NC}"
        echo -e "Distinguished Name: $DN_BASE"
        echo -e "Server Domain: $DOMAIN_CN (3-year validity)"
        echo -e "SAN DNS Entries: ${#san_dns_array[@]} -> ${san_dns_array[*]:-}"
        echo -e "SAN IP Entries: ${#san_ip_array[@]} -> ${san_ip_array[*]:-}"
        echo -e "${BLUE}${BOLD}===========================================${NC}"

        cd - >/dev/null

        # Ask if user wants to create another certificate
        echo ""
        create_another=""
        read -p "Do you want to create another certificate? (y/n): " create_another || true
        if [[ ! "$create_another" =~ ^[Yy]$ ]]; then
            break
        fi
    done

    echo -e "\n${GREEN}Exiting mode 2. Goodbye!${NC}"
fi
