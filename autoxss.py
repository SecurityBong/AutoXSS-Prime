import subprocess
import os
import sys
import shutil
import time
import threading
import json
import concurrent.futures

# --- BRANDING ---
TOOL_NAME = "AutoXSS Prime"
VERSION = "1.0"
CREATOR = "Rahul A.K.A SecurityBong"
DESC = "Automated Unauthenticated XSS & Vulnerability Scanner."

# --- CONFIGURATION ---
HOME = os.path.expanduser("~")
WORKSPACE_DIR = os.path.abspath("AutoXSS_Workspace")
TOOLS_DIR = os.path.join(WORKSPACE_DIR, "tools")
RESULTS_DIR = os.path.join(WORKSPACE_DIR, "results")

# REPOS & PATHS
JAELES_REPO = "https://github.com/jaeles-project/jaeles.git"
JAELES_SIG_REPO = "https://github.com/jaeles-project/jaeles-signatures.git"
JAELES_PATH = os.path.join(TOOLS_DIR, "jaeles")
JAELES_SIG_PATH = os.path.join(TOOLS_DIR, "jaeles-signatures")

# LIMITS
MAX_URLS_SCAN = 15000  

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
        start_time = time.time()
        while not stop_spinner.is_set():
            elapsed = int(time.time() - start_time)
            sys.stdout.write(f"\r\033[93m[Wait]\033[0m {task_name}... {chars[i]} ({elapsed}s)")
            sys.stdout.flush()
            time.sleep(0.1)
            i = (i + 1) % 4
            
    t = threading.Thread(target=spinner)
    t.start()
    try:
        subprocess.run(cmd, shell=True, check=True, timeout=timeout, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        stop_spinner.set()
        t.join()
        sys.stdout.write("\r" + " "*100 + "\r") 
        return True
    except:
        stop_spinner.set()
        t.join()
        sys.stdout.write("\r" + " "*100 + "\r")
        return False

# --- WORKSPACE WIPER (THE BUG FIX) ---
def clean_workspace():
    """Wipes old results to prevent cross-contamination between targets."""
    if not os.path.exists(RESULTS_DIR):
        return
        
    old_files = ["raw_urls.txt", "live_targets.txt", "dalfox.txt", "nuclei_general.json", "nuclei_dast.json", "temp_to_check.txt", "temp_alive.txt"]
    for file in old_files:
        filepath = os.path.join(RESULTS_DIR, file)
        if os.path.exists(filepath):
            os.remove(filepath)
            
    jaeles_out = os.path.join(RESULTS_DIR, "jaeles_out")
    if os.path.exists(jaeles_out):
        shutil.rmtree(jaeles_out)

# --- LIVE CHECKER (HTTPX INTEGRATION) ---
def check_alive(urls):
    log(f"Checking {len(urls)} URLs for liveness using httpx...", "INFO")
    alive_urls = []
    
    httpx_bin = resolve_binary_path("httpx")
    if not httpx_bin:
        log("httpx not found! Returning raw URLs.", "WARN")
        return urls

    temp_in = os.path.join(RESULTS_DIR, "temp_to_check.txt")
    temp_out = os.path.join(RESULTS_DIR, "temp_alive.txt")
    
    with open(temp_in, "w", encoding="utf-8") as f:
        f.write("\n".join(urls))
        
    cmd = f"{httpx_bin} -l {temp_in} -fc 404 -silent -t 50 -o {temp_out}"
    run_cmd_spinner(cmd, "HTTPX (Validating live endpoints)")
    
    if os.path.exists(temp_out):
        with open(temp_out, "r", encoding="utf-8") as f:
            alive_urls = [line.strip() for line in f if line.strip()]
        os.remove(temp_out)
        
    if os.path.exists(temp_in):
        os.remove(temp_in)
        
    return alive_urls

# --- SETUP PHASE ---

def setup():
    print("\n\033[1m--- [ PRE-FLIGHT CHECK ] ---\033[0m")
    
    for d in [WORKSPACE_DIR, TOOLS_DIR, RESULTS_DIR]:
        if not os.path.exists(d): os.makedirs(d)

    tools = {
        "gau": "github.com/lc/gau/v2/cmd/gau@latest",
        "katana": "github.com/projectdiscovery/katana/cmd/katana@latest",
        "dalfox": "github.com/hahwul/dalfox/v2@latest",
        "nuclei": "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        "httpx": "github.com/projectdiscovery/httpx/cmd/httpx@latest"
    }
    
    for name, path in tools.items():
        if resolve_binary_path(name):
            log(f"Tool '{name}' Found.", "SUCCESS")
        else:
            log(f"Installing '{name}'...", "SETUP")
            run_cmd_spinner(f"go install {path}", f"Installing {name}")

    if resolve_binary_path("jaeles"):
         log("Tool 'jaeles' Found.", "SUCCESS")
    else:
         log("Installing Jaeles...", "SETUP")
         run_cmd_spinner(f"go install github.com/jaeles-project/jaeles@latest", "Installing Jaeles")

    if not os.path.exists(JAELES_SIG_PATH):
        subprocess.run(f"git clone {JAELES_SIG_REPO} {JAELES_SIG_PATH}", shell=True, stderr=subprocess.DEVNULL)

    log("Updating Nuclei Templates...", "SETUP")
    subprocess.run("nuclei -update-templates", shell=True, stderr=subprocess.DEVNULL)

    print("\033[1m--- [ READY ] ---\033[0m\n")

# --- EXECUTION PHASE ---

def run_pipeline(domain):
    # CRITICAL FIX: Wipe old data before doing anything!
    clean_workspace()
    
    log(f"Starting Recon on: {domain}", "INFO")
    
    if domain.startswith("http"):
        domain_clean = domain.split("//")[1].split("/")[0]
        domain_full = domain
    else:
        domain_clean = domain.split("/")[0]
        domain_full = f"http://{domain}"
        
    raw_path = os.path.join(RESULTS_DIR, "raw_urls.txt")
    live_path = os.path.join(RESULTS_DIR, "live_targets.txt")
    
    gau_bin = resolve_binary_path("gau") or "gau"
    katana_bin = resolve_binary_path("katana") or "katana"
    
    # 1. RECON 
    run_cmd_spinner(f"{gau_bin} {domain_clean} --threads 10 >> {raw_path} 2>&1", "GAU (Fetching historical URLs)")
    run_cmd_spinner(f"{katana_bin} -u {domain_full} -d 3 -jc -silent >> {raw_path}", "Katana (Crawling active links)")
    
    # 2. FILTERING 
    found_urls = []
    if os.path.exists(raw_path):
        with open(raw_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                url = line.strip()
                if "?" in url: 
                    found_urls.append(url)
    
    unique_urls = list(set(found_urls))
    log(f"Extracted {len(unique_urls)} total parameterized URLs.", "INFO")
    
    if len(unique_urls) == 0:
        log("No parameterized URLs found! The site may be static or blocking crawlers.", "WARN")
        return

    # 3. LIVE CHECK
    alive_urls = check_alive(unique_urls)
    alive_urls = alive_urls[:MAX_URLS_SCAN]
    
    with open(live_path, "w", encoding="utf-8") as f:
        f.write("\n".join(alive_urls))
        
    log(f"Scan Scope: {len(alive_urls)} Confirmed Live URLs.", "SUCCESS")
    if len(alive_urls) == 0:
        return

    VULN_COUNT = 0

    # 4. NUCLEI 
    nuclei_bin = resolve_binary_path("nuclei")
    if nuclei_bin:
        log("Phase 1: Nuclei Domain-Level & Tech Scan", "INFO")
        nuclei_out_a = os.path.join(RESULTS_DIR, "nuclei_general.json")
        cmd_a = f"{nuclei_bin} -u {domain_full} -tags cve,misconfig,exposure,vulnerability,tech,recon -json -o {nuclei_out_a}"
        run_cmd_spinner(cmd_a, "Nuclei (Fingerprinting tech & hunting CVEs)")
        
        log("Phase 2: Nuclei Parameter-Level Scan", "INFO")
        nuclei_out_b = os.path.join(RESULTS_DIR, "nuclei_dast.json")
        cmd_b = f"{nuclei_bin} -l {live_path} -tags dast,xss,sqli,lfi,injection -json -o {nuclei_out_b}"
        run_cmd_spinner(cmd_b, "Nuclei (Fuzzing parameters for SQLi/LFI/XSS)")

        for out_file in [nuclei_out_a, nuclei_out_b]:
            if os.path.exists(out_file):
                try:
                    with open(out_file, "r", encoding="utf-8") as f:
                        for line in f:
                            data = json.loads(line)
                            name = data.get('info', {}).get('name', 'Unknown')
                            severity = data.get('info', {}).get('severity', 'info').upper()
                            matched = data.get('matched-at', 'Unknown URL')
                            
                            if "xss" in name.lower() or "cross-site" in name.lower():
                                print(f"\n\033[91m[VULN] Nuclei XSS ({severity}): {name}\033[0m")
                                print(f"       URL: {matched}")
                            else:
                                color = "\033[96m" 
                                if severity == "CRITICAL": color = "\033[91m"
                                elif severity == "HIGH": color = "\033[93m"
                                elif severity == "MEDIUM": color = "\033[95m"
                                elif severity == "LOW": color = "\033[94m"

                                print(f"\n{color}[BONUS] Nuclei ({severity}): {name}\033[0m")
                                print(f"       URL: {matched}")
                            VULN_COUNT += 1
                except: pass

    # 5. JAELES
    jaeles_exec = resolve_binary_path("jaeles")
    if jaeles_exec and os.path.exists(JAELES_SIG_PATH):
        log("Phase 3: Jaeles Signature Scan", "INFO")
        jaeles_out_dir = os.path.join(RESULTS_DIR, "jaeles_out")
        cmd = f"{jaeles_exec} scan -c 50 -U {live_path} -s {JAELES_SIG_PATH} --no-background -O {jaeles_out_dir} --quiet"
        run_cmd_spinner(cmd, "Jaeles (Checking known payload signatures)")
        
        if os.path.exists(jaeles_out_dir):
            for root, dirs, files in os.walk(jaeles_out_dir):
                for file in files:
                    if file.endswith(".txt"):
                        with open(os.path.join(root, file), 'r', encoding="utf-8", errors="ignore") as f:
                            headline = f.readline().strip()
                            print(f"\n\033[96m[BONUS] Jaeles Finding ({file}):\033[0m")
                            print(f"       {headline}")
                        VULN_COUNT += 1

    # 6. DALFOX
    dalfox_bin = resolve_binary_path("dalfox")
    if dalfox_bin and len(alive_urls) > 0:
        log("Phase 4: Dalfox Mass XSS Testing", "INFO")
        dalfox_out = os.path.join(RESULTS_DIR, "dalfox.txt")
        cmd = f"{dalfox_bin} file {live_path} --skip-mining-all --format plain > {dalfox_out}"
        run_cmd_spinner(cmd, "Dalfox (Injecting context-aware XSS payloads)")
        
        if os.path.exists(dalfox_out):
            with open(dalfox_out, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if "[POC]" in line:
                        parts = line.split("http", 1)
                        if len(parts) > 1:
                            full_url = "http" + parts[1].strip()
                            
                            if "[V]" in line or "inHTML" in line:
                                print(f"\n\033[91m[VULN] Dalfox XSS Confirmed!\033[0m")
                                print(f"       \033[93m{full_url}\033[0m")
                            elif "[R]" in line:
                                print(f"\n\033[93m[WARN] Dalfox Open Redirect / Reflected:\033[0m")
                                print(f"       \033[97m{full_url}\033[0m")
                            
                            VULN_COUNT += 1

    print("\n" + "="*70)
    if VULN_COUNT > 0:
        log(f"Scan Complete. Found {VULN_COUNT} issues/intel points.", "SUCCESS")
        log(f"Full reports saved in: {RESULTS_DIR}", "INFO")
    else:
        log("Scan Complete. No vulnerabilities found on target surface.", "INFO")

if __name__ == "__main__":
    print_banner()
    
    setup()
    
    if len(sys.argv) > 1: target = sys.argv[1]
    else: target = input("\n\033[94m[?] Target Domain (e.g., example.com): \033[0m")
    
    def clean_input(u):
        u = u.strip().replace("http://", "").replace("https://", "")
        if "/" in u: u = u.split("/")[0]
        return u

    try:
        run_pipeline(clean_input(target))
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user. Exiting...")
