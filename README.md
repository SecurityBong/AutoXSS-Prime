# AutoXSS-Prime
⚡ AutoXSS Prime: The ultimate automated XSS vulnerability scanner. Features a dual-engine core (Nuclei DAST + Dalfox), smart URL prioritization, and uncensored payload reporting. Production-ready, environment-agnostic, and designed for bug bounty hunters.

💻 Usage
Simply run the script and enter your target domain.


What happens next?

Recon: Gathers URLs from Wayback Machine and Active Crawling.
Filter: Removes static files (.jpg, .css) and keeps only parameterized URLs.
Live Check: Verifies which URLs are actually alive (200, 403, 500).
Nuclei Scan: Checks for server misconfigs and low-hanging CVEs.
Dalfox Scan: Fuzzes every live parameter for XSS.
Report: Saves all findings in the results/folder.


📂 After running, the tool creates a workspace.

⚠️ Disclaimer
This tool is for educational purposes and authorized testing only.
Do not use this tool on targets you do not have permission to scan.
The creator is not responsible for any misuse or damage caused by this program.


🤝 Credits
This pipeline stands on the shoulders of giants. Special thanks to the creators of:
ProjectDiscovery (Nuclei, Katana)
Hahwul (Dalfox)
Corben Leo (GAU)
Jaeles Project

Made with ❤️ by Rahul A.K.A SecurityBong
