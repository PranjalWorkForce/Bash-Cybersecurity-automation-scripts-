# OSINT Top 10 Scanner (`osint_top10.sh`)

An automated reconnaissance bash script that aggregates passive and open-source intelligence (OSINT) data on a target domain using the 10 most commonly used OSINT sources and tools.

---

## 🔍 Included OSINT Sources & Tools

All checks executed by this script are **strictly passive / OSINT** to ensure zero direct exploitation or disruptive interaction with the target infrastructure:

1. **Whois** – Domain registration and ownership data.
2. **Dig / DNSrecon** – DNS record mapping (A, MX, NS, TXT).
3. **Crt.sh** – Certificate Transparency logs for domain history.
4. **Sublist3r** – Multi-source subdomain enumeration.
5. **Amass** – In-depth subdomain enumeration and passive asset mapping.
6. **TheHarvester** – Email addresses, hosts, and employee names lookup.
7. **Shodan CLI** – Exposed internet-facing services and banners *(requires API key)*.
8. **Wayback Machine** – Historical URLs and archived endpoint discovery.
9. **BuiltWith-style** – Basic technology stack fingerprinting.
10. **GitHub Dorking** – Search for leaked configurations, secrets, or repository mentions.

---

## ⚙️ Prerequisites & Dependencies

Make sure you have the required CLI tools installed and available in your system's `PATH` before running the script:
* `whois`
* `dig` / `dnsrecon`
* `sublist3r`
* `amass`
* `theHarvester`
* `shodan` (configured with your API key)
* `curl` / `jq` (for API parsing)

---

## 🚀 Usage

Run the script from your terminal by specifying the target domain and an optional output directory:

```bash
./osint_top10.sh -d example.com [-o output_dir]

Options:
 * -d : Target domain to investigate (Required)
 * -o : Custom directory to save scan results/reports (Optional)
🔑 Environment Variables
For tools requiring authentication (such as Shodan), export your API key as an environment variable before execution:
export SHODAN_API_KEY="your_api_key_here"

⚠️ Legal & Ethical Disclaimer
This script is intended for authorized security research, educational purposes, and defensive reconnaissance only. Only run this script against targets you own or have explicit written permission to research. Service data gathered from public OSINT channels can still be sensitive; handle all findings responsibly.

---

Would you like any specific modifications added to this documentation, such as instructions on how to install missing dependencies?

