
OWASP Top 10 Automated Scanner
An all-in-one Bash automation script designed to streamline security assessments by running vulnerability checks targeting the OWASP Top 10 in a single workflow.

About
This tool consolidates essential security scanning utilities into one unified shell script. Instead of running separate tools manually for reconnaissance, injection flaws, and misconfigurations, this script automates the execution pipeline, saving time and standardizing your security checks

Features
 * All-in-One Execution: Sequences multiple security checks covering the OWASP Top 10 risk categories.
 * Lightweight & Portable: Written purely in Bash, requiring no heavy framework installations.
 * Automated Reporting: Outputs scan results directly to organized log files for quick review.

Prerequisites & Dependencies
Ensure the following tools are installed on your Linux/Unix system and available in your system $PATH before running the script:
 * bash (version 4.x or higher recommended)
 * Common utilities: curl, wget, nmap (adjust based on the specific tools your script calls)
 * Target security tools integrated into your script (e.g., nikto, sqlmap, dirb, etc.)
Installation
 * Clone the repository:
   git clone https://github.com/PranjalWorkForce/Bash-Cybersecurity-automation-scripts-/new/main/OWASP
cd OWASP

 * Make the script executable:
   chmod +x scanner.sh

Usage
Run the script from your terminal by providing the target URL or domain:
./scanner.sh -u https://example.com

Command-Line Options
| Flag | Description | Example |
|---|---|---|
| -u, --url | Target URL to scan | ./scanner.sh -u [http://testphp.vulnweb.com](http://testphp.vulnweb.com) |
| -o, --output | Specify output file for the report | ./scanner.sh -u [http://example.com](http://example.com) -o report.txt |
| -h, --help | Display the help menu | ./scanner.sh --help |
Disclaimer
> Warning: This tool is intended for educational purposes and authorized security testing only. Do not run this script against targets without explicit, written permission from the system owners. The author assumes no liability for any misuse or damage caused by this program.
