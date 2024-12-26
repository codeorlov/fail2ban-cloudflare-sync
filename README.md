# Fail2Ban Cloudflare Sync for Plesk

A bash script that automatically synchronizes blocked IP addresses from Fail2Ban to Cloudflare's IP Access Rules, designed for Plesk servers. This helps extend your server's security by blocking malicious IPs at the Cloudflare edge network level.

## Features

- Automatically retrieves blocked IPs from all Fail2Ban chains
- Creates and maintains IP lists in Cloudflare
- Sets up WAF rules to block listed IPs
- Supports multiple domains
- Detailed logging of all operations
- Easy configuration through a simple array
- Optimized for Plesk server environments

## Prerequisites

- Plesk server
- Bash shell
- `iptables`
- `jq` for JSON processing
- `curl` for API requests
- Cloudflare account with API access

## Configuration

1. Set up the configuration array in the script:
```bash
declare -A CONFIG=(
    ["domain.com;email"]="YOUR_CLOUDFLARE_EMAIL"
    ["domain.com;api_key"]="YOUR_API_KEY"
    ["domain.com;account_id"]="YOUR_ACCOUNT_ID"
    ["domain.com;zone_id"]="YOUR_ZONE_ID"
)
```

Replace placeholders with your actual Cloudflare credentials:
- `domain.com`: Your domain name
- `YOUR_CLOUDFLARE_EMAIL`: Email associated with your Cloudflare account
- `YOUR_API_KEY`: Cloudflare API key
- `YOUR_ACCOUNT_ID`: Your Cloudflare account ID
- `YOUR_ZONE_ID`: Zone ID for your domain

## Usage

1. Make the script executable:
```bash
chmod +x cloudflare-fail2ban-sync.sh
```

2. Run the script:
```bash
./cloudflare-fail2ban-sync.sh
```

For automated execution, add it to your Plesk server's crontab:
```bash
# Run every hour
0 * * * * /path/to/cloudflare-fail2ban-sync.sh
```

## How It Works

1. Retrieves blocked IP addresses from all Fail2Ban chains in Plesk
2. Creates or updates an IP list in Cloudflare for each configured domain
3. Creates WAF rules that block requests from listed IPs
4. Logs all operations with timestamps

## License

MIT License

## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

## Security Notes

- Keep your API credentials secure
- Review blocked IPs periodically to prevent false positives
- Consider the impact on legitimate users before deployment
- Ensure proper Fail2Ban configuration in your Plesk server
