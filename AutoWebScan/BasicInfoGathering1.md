Sublist3r enumerates subdomains → subdomains/subdomains.txt
theHarvester pulls OSINT (emails, hosts, ASNs) from public sources → osint/ (skip with --fast)
For each resolvable subdomain, nmap runs -sV -Pn --script vuln (service detection + NSE vulnerability-screening scripts) → per-host results in nmap/
Everything gets rolled into report/summary_report.txt

Safety features built in:

Prompts for explicit YES authorization confirmation before scanning — don't skip or hardcode past this on targets you don't control
Checks required binaries are installed before running
Uses -T3 (polite timing) rather than aggressive scan speeds
Flags nmap's vuln-script hits as things that need manual verification, not confirmed findings — version/banner-based detection has false positives

To run it you'll need sublist3r, theHarvester, and nmap installed and on your $PATH (or set SUBLIST3R_BIN/HARVESTER_BIN/NMAP_BIN env vars to point at them).

One thing worth flagging: nmap's --script vuln category is a real but fairly shallow vulnerability screen — it's good for a first-pass triage pipeline like this, but it won't replace a proper scanner like Nessus/OpenVAS or manual testing for anything you're taking seriously. Let me know if you want me to add things like output-to-JSON for CI integration, Slack/webhook alerting on vuln hits, or a rate-limit/scope-file option to restrict which subdomains actually get scanned. 


example to use this script. 
./webvuln_scan.sh -d example.com [-o output_dir] [-p 1-65535] [--fast]
