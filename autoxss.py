import subprocess
import os
import sys
import shutil
import time
import venv
import threading
import json
import concurrent.futures
import requests
import warnings
import re # Added for robust parsing

# Disable SSL warnings
warnings.filterwarnings("ignore")

# --- BRANDING ---
TOOL_NAME = "AutoXSS-Prime"
VERSION = "1.0"
CREATOR = "Rahul A.K.A SecurityBong"
DESC = "The ultimate automated XSS vulnerability scanner"

# --- CONFIGURATION ---
HOME = os.path.expanduser("~")
WORKSPACE_DIR = os.path.abspath("AutoXSS_Workspace")
TOOLS_DIR = os.path.join(WORKSPACE_DIR, "tools")
VENV_DIR = os.path.join(TOOLS_DIR, "venv")
RESULTS_DIR = os.path.join(WORKSPACE_DIR, "results")

# REPOS
JAELES_REPO = "https://github.com/jaeles-project/jaeles.git"
JAELES_SIG_REPO = "https://github.com/jaeles-project/jaeles-signatures.git"

# PATHS
JAELES_PATH = os.path.join(TOOLS_DIR, "jaeles")
JAELES_SIG_PATH = os.path.join(TOOLS_DIR, "jaeles-signatures")

# VENV
if sys.platform == "win32":
    VENV_PYTHON = os.path.join(VENV_DIR, "Scripts", "python.exe")
    VENV_PIP = os.path.join(VENV_DIR, "Scripts", "pip.exe")
else:
    VENV_PYTHON = os.path.join(VENV_DIR, "bin", "python3")
    VENV_PIP = os.path.join(VENV_DIR, "bin", "pip")

# LIMITS
MAX_URLS_SCAN = 10000  

# --- UTILS ---

def print_banner():
    print("\033[96m" + "="*70)
    print(f" {TOOL_NAME} | v{VERSION}")
    print(f" Created by: {CREATOR}")
    print(f" {DESC}")
    print("="*70 + "\033[0m")
    sys.stdout.flush()

def log(msg, level="INFO"):
    colors = {
        "INFO": "\033[94m[i]\033[0m",
        "SUCCESS": "\033[92m[+]\033[0m",
        "WARN": "\033[93m[!]\033[0m",
        "ERROR": "\033[91m[-]\033[0m",
        "SETUP": "\033[95m[SETUP]\033[0m",
        "VULN": "\033[91m[VULN]\033[0m",
        "BONUS": "\033[96m[BONUS]\033[0m",
    }
    print(f"{colors.get(level, '[?]')} {msg}")
    sys.stdout.flush()

def resolve_binary_path(tool_name):
    if shutil.which(tool_name): return shutil.which(tool_name)
    possible_paths = [
        os.path.join(HOME, "go", "bin", tool_name),
        os.path.join("/usr", "local", "go", "bin", tool_name),
        os.path.join("/usr", "bin", tool_name),
        os.path.join(TOOLS_DIR, tool_name)
    ]
    for p in possible_paths:
        if os.path.exists(p): return p
    return None

def run_cmd_spinner(cmd, task_name, timeout=3600):
    stop_spinner = threading.Event()
    def spinner():
        chars = "|/-\\"
        i = 0
        while not stop_spinner.is_set():
            sys.stdout.write(f"\r\033[93m[Wait]\033[0m {task_name}... {chars[i]}")
            sys.stdout.flush()
            time.sleep(0.1)
            i = (i + 1) % 4
    t = threading.Thread(target=spinner)
    t.start()
    try:
        subprocess.run(cmd, shell=True, check=True, timeout=timeout, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        stop_spinner.set()
        t.join()
        sys.stdout.write("\r" + " "*80 + "\r")
        return True
    except:
        stop_spinner.set()
        t.join()
        sys.stdout.write("\r" + " "*80 + "\r")
        return False

# --- SORTING LOGIC ---
def prioritize_urls(urls):
    juicy_params = ["id=", "cat=", "artist=", "search=", "query=", "file=", "u=", "page="]
    high_priority = []
    low_priority = []
    
    for url in urls:
        is_juicy = False
        for param in juicy_params:
            if param in url:
                high_priority.append(url)
                is_juicy = True
                break
        if not is_juicy:
            low_priority.append(url)
            
    log(f"Sorting: {len(high_priority)} High Priority / {len(low_priority)} Standard URLs.", "INFO")
    return high_priority + low_priority

# --- LIVE CHECKER ---
def check_alive(urls):
    log(f"Checking {len(urls)} URLs for liveness...", "INFO")
    alive_urls = []
    
    def check(url):
        try:
            r = requests.head(url, timeout=5, verify=False)
            return url
        except: 
            return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(check, u): u for u in urls}
        completed = 0
        total = len(urls)
        for future in concurrent.futures.as_completed(futures):
            completed += 1
            if completed % 100 == 0:
                sys.stdout.write(f"\r    -> Progress: {completed}/{total}")
                sys.stdout.flush()
            if future.result():
                alive_urls.append(future.result())
    
    sys.stdout.write("\r" + " "*60 + "\r") 
    return alive_urls

# --- SETUP ---

def setup():
    print("\n\033[1m--- [ PRE-FLIGHT CHECK ] ---\033[0m")
    
    for d in [WORKSPACE_DIR, TOOLS_DIR, RESULTS_DIR]:
        if not os.path.exists(d): os.makedirs(d)

    # 1. Tools
    tools = {
        "gau": "github.com/lc/gau/v2/cmd/gau@latest",
        "katana": "github.com/projectdiscovery/katana/cmd/katana@latest",
        "dalfox": "github.com/hahwul/dalfox/v2@latest",
        "nuclei": "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    }
    
    for name, path in tools.items():
        if resolve_binary_path(name):
            log(f"Tool '{name}' Found.", "SUCCESS")
        else:
            log(f"Installing '{name}'...", "SETUP")
            run_cmd_spinner(f"go install {path}", f"Installing {name}")

    # 2. Jaeles
    if resolve_binary_path("jaeles"):
         log("Tool 'jaeles' Found.", "SUCCESS")
    else:
         log("Installing Jaeles...", "SETUP")
         run_cmd_spinner(f"go install github.com/jaeles-project/jaeles@latest", "Jaeles Install")

    if not os.path.exists(JAELES_SIG_PATH):
        subprocess.run(f"git clone {JAELES_SIG_REPO} {JAELES_SIG_PATH}", shell=True, stderr=subprocess.DEVNULL)

    log("Updating Nuclei Templates...", "SETUP")
    subprocess.run("nuclei -update-templates", shell=True, stderr=subprocess.DEVNULL)

    print("\033[1m--- [ READY ] ---\033[0m\n")

# --- EXECUTION ---

def run_pipeline(domain):
    log(f"Starting Recon on: {domain}", "INFO")
    
    if domain.startswith("http"):
        domain_clean = domain.split("//")[1].split("/")[0]
        domain_full = domain
    else:
        domain_clean = domain.split("/")[0]
        domain_full = f"http://{domain}"
        
    raw_path = os.path.join(RESULTS_DIR, "raw_urls.txt")
    live_path = os.path.join(RESULTS_DIR, "live_targets.txt")
    
    # 1. RECON
    run_cmd_spinner(f"gau {domain_clean} --threads 10 >> {raw_path} 2>&1", "GAU Recon")
    run_cmd_spinner(f"katana -u {domain_full} -d 2 -silent >> {raw_path}", "Katana Recon")
    
    # 2. SORTING & FILTERING
    found_urls = []
    if os.path.exists(raw_path):
        with open(raw_path, "r", errors="ignore") as f:
            for line in f:
                url = line.strip()
                if "?" in url and "=" in url:
                    found_urls.append(url)
    
    unique_urls = list(set(found_urls))
    sorted_urls = prioritize_urls(unique_urls)
    
    # Live Check
    alive_urls = check_alive(sorted_urls)
    alive_urls = alive_urls[:MAX_URLS_SCAN]
    
    with open(live_path, "w") as f:
        f.write("\n".join(alive_urls))
        
    log(f"Scan Ready: {len(alive_urls)} URLs (Top Priority First).", "SUCCESS")
    
    VULN_COUNT = 0

    # 3. NUCLEI (DUAL MODE)
    nuclei_bin = resolve_binary_path("nuclei")
    if nuclei_bin:
        log("Running Nuclei Mode A (General Misconfig/CVEs)...", "INFO")
        nuclei_out_a = os.path.join(RESULTS_DIR, "nuclei_general.json")
        cmd_a = f"{nuclei_bin} -u {domain_full} -tags cve,misconfig,exposure,vulnerability -severity medium,high,critical -json -o {nuclei_out_a}"
        run_cmd_spinner(cmd_a, "Nuclei General Scan")
        
        log("Running Nuclei Mode B (DAST/XSS/SQLi on URLs)...", "INFO")
        nuclei_out_b = os.path.join(RESULTS_DIR, "nuclei_dast.json")
        cmd_b = f"{nuclei_bin} -l {live_path} -tags dast,xss,sqli,lfi,injection -severity low,medium,high,critical -json -o {nuclei_out_b}"
        run_cmd_spinner(cmd_b, "Nuclei DAST Scan")

        for out_file in [nuclei_out_a, nuclei_out_b]:
            if os.path.exists(out_file):
                try:
                    with open(out_file, "r") as f:
                        for line in f:
                            data = json.loads(line)
                            name = data.get('info', {}).get('name')
                            matched = data.get('matched-at')
                            
                            if "xss" in name.lower():
                                print(f"\n\033[91m[VULN] Nuclei XSS: {name}\033[0m")
                                print(f"       URL: {matched}")
                            else:
                                print(f"\n\033[96m[BONUS] Nuclei: {name}\033[0m")
                                print(f"       URL: {matched}")
                            VULN_COUNT += 1
                except: pass

    # 4. JAELES
    jaeles_exec = resolve_binary_path("jaeles")
    if jaeles_exec and os.path.exists(JAELES_SIG_PATH):
        log("Running Jaeles...", "INFO")
        jaeles_out_dir = os.path.join(RESULTS_DIR, "jaeles_out")
        cmd = f"{jaeles_exec} scan -c 50 -U {live_path} -s {JAELES_SIG_PATH} --no-background -O {jaeles_out_dir} --quiet"
        run_cmd_spinner(cmd, "Jaeles Scan")
        
        if os.path.exists(jaeles_out_dir):
            for root, dirs, files in os.walk(jaeles_out_dir):
                for file in files:
                    if file.endswith(".txt"):
                        with open(os.path.join(root, file), 'r') as f:
                            headline = f.readline().strip()
                            print(f"\n\033[96m[BONUS] Jaeles Finding ({file}):\033[0m")
                            print(f"       {headline}")
                        VULN_COUNT += 1

    # 5. DALFOX (REGEX PARSER)
    dalfox_bin = resolve_binary_path("dalfox")
    if dalfox_bin:
        log(f"Dalfox Scanning {len(alive_urls)} URLs (Uncensored)...", "INFO")
        dalfox_out = os.path.join(RESULTS_DIR, "dalfox.txt")
        cmd = f"{dalfox_bin} file {live_path} --skip-mining-all --format plain > {dalfox_out}"
        run_cmd_spinner(cmd, "Dalfox Scan")
        
        if os.path.exists(dalfox_out):
            with open(dalfox_out, "r") as f:
                for line in f:
                    line = line.strip()
                    if "[POC]" in line:
                        # Improved Regex to capture the full URL starting from http/https
                        match = re.search(r'(https?://\S+)', line)
                        if match:
                            full_url = match.group(1)
                            
                            # Determine Type for Color
                            if "[V]" in line or "inHTML" in line:
                                print(f"\n\033[91m[VULN] Dalfox XSS Confirmed!\033[0m")
                                print(f"       \033[93m{full_url}\033[0m")
                            elif "[R]" in line:
                                print(f"\n\033[93m[WARN] Dalfox Open Redirect / Reflected:\033[0m")
                                print(f"       \033[97m{full_url}\033[0m")
                            
                            VULN_COUNT += 1

    print("\n" + "="*70)
    if VULN_COUNT > 0:
        log(f"Scan Complete. Found {VULN_COUNT} issues.", "SUCCESS")
        log(f"Full reports saved in: {RESULTS_DIR}", "INFO")
    else:
        log("Scan Complete. No direct vulnerabilities found.", "INFO")

if __name__ == "__main__":
    print_banner()
    if len(sys.argv) > 1: target = sys.argv[1]
    else: target = input("\033[94m[?] Target Domain: \033[0m")
    
    def clean_input(u):
        u = u.strip().replace("http://", "").replace("https://", "")
        if "/" in u: u = u.split("/")[0]
        return u

    try:
        setup()
        run_pipeline(clean_input(target))
    except KeyboardInterrupt:
        print("\n[!] Exiting...")
