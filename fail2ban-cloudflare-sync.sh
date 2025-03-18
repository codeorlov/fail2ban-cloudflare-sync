#!/bin/bash

# This script synchronizes blocked IP addresses from Fail2Ban to Cloudflare's IP Access Rules
# It creates/updates IP lists and WAF rules for each configured domain to block malicious IPs
# at the Cloudflare edge network level

# Paths to the required binaries
PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
IPTABLES="/usr/sbin/iptables"
JQ="/usr/bin/jq"
CURL="/usr/bin/curl"

# Cloudflare configuration
# Format: ["domain;parameter"]=value
# Parameters: email, api_key, account_id, zone_id
# Example: ["example.com;email"]="user@domain.com"
declare -A CONFIG=(
    ["test.com.ua;email"]="EMAIL"
    ["test.com.ua;api_key"]="APIKEY"
    ["test.com.ua;account_id"]="ACCOUNTID"
    ["test.com.ua;zone_id"]="ZONEID"
)

LIST_NAME="plesk"
RULE_NAME="Blocked IPs from Plesk"

# Function for logging messages with a timestamp
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1"
}

# Function to retrieve blocked IPs from Fail2Ban chains
get_fail2ban_ips() {
    # Collect unique IPs from Fail2Ban chains
    local ips=()
    while read -r ip; do
        # Validate IP format (xxx.xxx.xxx.xxx)
        if [[ $ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            ips+=("$ip")
        fi
    done < <($IPTABLES -L | grep "Chain f2b-" | awk '{print $2}' | while read -r chain; do
        $IPTABLES -L "$chain" -n | grep REJECT | awk '{print $4}'
    done | sort -u)
    echo "${ips[@]}"
}

# Function to retrieve or create an IP list in Cloudflare
get_or_create_list() {
    local domain=$1
    local response

    # Request the list of existing Cloudflare lists
    response=$($CURL -s -X GET \
        -H "X-Auth-Email: ${CONFIG["$domain;email"]}" \
        -H "X-Auth-Key: ${CONFIG["$domain;api_key"]}" \
        -H "Content-Type: application/json" \
        "https://api.cloudflare.com/client/v4/accounts/${CONFIG["$domain;account_id"]}/rules/lists")

    if [ -z "$response" ]; then
        log "Error: Empty response from Cloudflare API for $domain when requesting lists"
        return 1
    fi

    local success
    success=$(echo "$response" | $JQ -r '.success')
    if [ "$success" != "true" ]; then
        log "Cloudflare API error for $domain: $(echo "$response" | $JQ -r '.errors[]?.message // "Unknown error"')"
        return 1
    fi

    # Check if the list with the given name exists
    local list_id
    list_id=$(echo "$response" | $JQ -r '.result[] | select(.name == "'"$LIST_NAME"'") | .id' 2>/dev/null)

    # Create a new list if it doesn't exist
    if [ -z "$list_id" ]; then
        log "List $LIST_NAME not found for $domain. Creating a new one..."
        response=$($CURL -s -X POST \
            -H "X-Auth-Email: ${CONFIG["$domain;email"]}" \
            -H "X-Auth-Key: ${CONFIG["$domain;api_key"]}" \
            -H "Content-Type: application/json" \
            -d "{\"name\":\"$LIST_NAME\",\"kind\":\"ip\",\"description\":\"Blocked IPs from Plesk\"}" \
            "https://api.cloudflare.com/client/v4/accounts/${CONFIG["$domain;account_id"]}/rules/lists")

        if [ -z "$response" ]; then
            log "Error: Empty response when creating list for $domain"
            return 1
        fi

        success=$(echo "$response" | $JQ -r '.success')
        if [ "$success" != "true" ]; then
            log "Error creating list for $domain: $(echo "$response" | $JQ -r '.errors[]?.message // "Unknown error"')"
            return 1
        fi

        list_id=$(echo "$response" | $JQ -r '.result.id // ""')
        if [ -z "$list_id" ]; then
            log "Failed to retrieve ID of the new list for $domain"
            return 1
        fi
    fi

    echo "$list_id"
}

# Function to update the IP list in Cloudflare
update_list() {
    local domain=$1
    local list_id=$2
    local ips=$3
    local json_data="["

    # Form JSON payload for the update
    for ip in $ips; do
        json_data+="{\"ip\":\"$ip\",\"comment\":\"Blocked by Fail2Ban\"},"
    done
    json_data=${json_data%,}]

    log "Updating IP list for $domain..."
    local response
    response=$($CURL -s -X PUT \
        -H "X-Auth-Email: ${CONFIG["$domain;email"]}" \
        -H "X-Auth-Key: ${CONFIG["$domain;api_key"]}" \
        -H "Content-Type: application/json" \
        -d "$json_data" \
        "https://api.cloudflare.com/client/v4/accounts/${CONFIG["$domain;account_id"]}/rules/lists/$list_id/items")

    if [ -z "$response" ]; then
        log "Error: Empty response when updating list for $domain"
        return 1
    fi

    local success
    success=$(echo "$response" | $JQ -r '.success')
    if [ "$success" != "true" ]; then
        log "Error updating list for $domain: $(echo "$response" | $JQ -r '.errors[]?.message // "Unknown error"')"
        return 1
    fi

    log "IP list successfully updated for $domain."
}

# Function to create a WAF rule in Cloudflare
create_waf_rule() {
    local domain=$1
    local list_name=$2
    local response

    # Check existing WAF rules
    response=$($CURL -s -X GET \
        -H "X-Auth-Email: ${CONFIG["$domain;email"]}" \
        -H "X-Auth-Key: ${CONFIG["$domain;api_key"]}" \
        -H "Content-Type: application/json" \
        "https://api.cloudflare.com/client/v4/zones/${CONFIG["$domain;zone_id"]}/firewall/rules")

    if [ -z "$response" ]; then
        log "Error: Empty response when requesting WAF rules for $domain"
        return 1
    fi

    local success
    success=$(echo "$response" | $JQ -r '.success')
    if [ "$success" != "true" ]; then
        log "Error requesting WAF rules for $domain: $(echo "$response" | $JQ -r '.errors[]?.message // "Unknown error"')"
        return 1
    fi

    # Create a new rule if one with the same description doesn't exist
    if ! echo "$response" | $JQ -e ".result[] | select(.description == \"$RULE_NAME\")" > /dev/null 2>&1; then
        log "Creating WAF rule for $domain..."
        response=$($CURL -s -X POST \
            -H "X-Auth-Email: ${CONFIG["$domain;email"]}" \
            -H "X-Auth-Key: ${CONFIG["$domain;api_key"]}" \
            -H "Content-Type: application/json" \
            -d "[{\"action\":\"block\",\"description\":\"$RULE_NAME\",\"priority\":1,\"filter\":{\"expression\":\"ip.src in \$$list_name\",\"paused\":false,\"description\":\"Filter Fail2Ban IPs\"}}]" \
            "https://api.cloudflare.com/client/v4/zones/${CONFIG["$domain;zone_id"]}/firewall/rules")

        if [ -z "$response" ]; then
            log "Error: Empty response when creating WAF rule for $domain"
            return 1
        fi

        success=$(echo "$response" | $JQ -r '.success')
        if [ "$success" != "true" ]; then
            log "Error creating WAF rule for $domain: $(echo "$response" | $JQ -r '.errors[]?.message // "Unknown error"')"
            return 1
        fi
        log "WAF rule successfully created for $domain."
    else
        log "WAF rule already exists for $domain."
    fi
}

# Main process
log "Retrieving blocked IPs"
IPS=$(get_fail2ban_ips)
IP_COUNT=$(echo "$IPS" | wc -w)
log "Number of IPs found: $IP_COUNT"

# Flag to skip sleep on the first iteration
first_iteration=true

for domain in $(echo "${!CONFIG[@]}" | tr ' ' '\n' | cut -d';' -f1 | sort -u); do
    # Add a 10-second delay between iterations, except for the first one
    if [ "$first_iteration" = false ]; then
        log "Waiting 10 seconds before processing the next domain..."
        sleep 10
    else
        first_iteration=false
    fi

    log "Processing domain: $domain"
    LIST_ID=$(get_or_create_list "$domain")
    if [ -z "$LIST_ID" ]; then
        log "Skipping $domain due to error in retrieving or creating list"
        continue
    fi

    update_list "$domain" "$LIST_ID" "$IPS"
    create_waf_rule "$domain" "$LIST_NAME"
    log "Processing complete for $domain"
done