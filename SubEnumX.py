import os
import subprocess
import sys
import time
import re
import json
import subprocess
from datetime import datetime


if len(sys.argv) < 3:
    print("2nd argument not supplied")
    print("2nd argument is the resolver file list path")
    print("Usage : python3 SubEnumX.py domain resolvers_list")
    sys.exit(1)

domain = sys.argv[1]
resolvers_file = sys.argv[2]
dt = datetime.now().strftime('%Y-%m-%d.%H.%M.%S')
recon_dir = os.path.expanduser('~/recon')
result_dir = os.path.join(recon_dir, f'results/{domain}-{dt}')
os.makedirs(result_dir, exist_ok=True)

def start_amass():
    amass_output = os.path.join(result_dir, f'amass_{domain}.txt')
    amass_dir = os.path.join(result_dir, f'{domain}_amass')
    os.makedirs(amass_dir, exist_ok=True)
    cmd = f'amass enum -passive -d {domain} -src -dir {amass_dir} -o {amass_output} -rf {resolvers_file}'
    time.sleep(5)
    return subprocess.Popen(cmd, shell=True)

def start_subfinder():
    subfinder_output = os.path.join(result_dir, f'subfinder_{domain}.txt')
    cmd = f'subfinder -nW -d {domain} -rL {resolvers_file} -o {subfinder_output}'
    time.sleep(5)
    return subprocess.Popen(cmd, shell=True)
def start_assetfinder():
    assetfinder_output = os.path.join(result_dir, f'assetfinder_{domain}.txt')
    cmd = f'assetfinder {domain} > {assetfinder_output}'
    time.sleep(5)
    return subprocess.Popen(cmd, shell=True)

def start_findomain():
    findomain_output = os.path.join(result_dir, f'findomain_{domain}.txt')
    cmd = f'findomain --target {domain} --resolvers {resolvers_file} --threads 40 -u {findomain_output}'
    time.sleep(5)
    return subprocess.Popen(cmd, shell=True)
def find_subdomains():
    amass_process = start_amass()
    subfinder_process = start_subfinder()
    assetfinder_process = start_assetfinder()
    findomain_process = start_findomain()

    return amass_process, subfinder_process, assetfinder_process, findomain_process

def combine_subdomains():
    print("Combining subdomains...")
    amass_output = os.path.join(result_dir, f'amass_{domain}.txt')
    subfinder_output = os.path.join(result_dir, f'subfinder_{domain}.txt')
    assetfinder_output = os.path.join(result_dir, f'assetfinder_{domain}.txt')
    findomain_output = os.path.join(result_dir, f'findomain_{domain}.txt')
    crt_output = os.path.join(result_dir, f'{domain}.crt.txt') 
    subdomains_output = os.path.join(result_dir, f'{domain}.subdomains.txt')

    subdomain_files = [amass_output, subfinder_output, assetfinder_output, findomain_output, crt_output] 
    unique_subdomains = set()

    for file in subdomain_files:
        with open(file, 'r') as f:
            lines = f.readlines()
            for line in lines:
                line = re.sub(r'\[.*?\]', '', line).strip()
                if line:
                    unique_subdomains.add(line)

    with open(subdomains_output, 'w') as f:
        for subdomain in sorted(unique_subdomains):
            f.write(subdomain + '\n')

    print(f"Combined subdomains written to: {subdomains_output}")



def find_ips():
    print("Now finding IPs for subdomains...")
    subdomains_output = os.path.join(result_dir, f'{domain}.subdomains.txt')
    ips_output = os.path.join(result_dir, f'{domain}.ips.txt')
    cmd = f'massdns -r {resolvers_file} -t A -o S -w {ips_output} {subdomains_output}'
    subprocess.run(cmd, shell=True)
    print(f"IPs written to: {ips_output}")

def strip_ansi_escape_codes(text):
    return re.sub(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])', '', text)

def strip_brackets(text):
    return text.replace('[', '').replace(']', '')


def scan_httpx():
    print("Scanning subdomains with httpx...")
    subdomains_output = os.path.join(result_dir, f'{domain}.subdomains.txt')
    httpx_output = os.path.join(result_dir, f'httpx_{domain}.txt')
    cmd = f'httpx -l {subdomains_output} -title -tech-detect -status-code -o {httpx_output}'
    subprocess.run(cmd, shell=True)
    print(f"Httpx results written to: {httpx_output}")

    print("Sorting httpx results...")
    sorted_httpx_output = os.path.join(result_dir, f'sorted_httpx_{domain}.txt')

    with open(httpx_output, 'r') as f:
        lines = f.readlines()

    stripped_lines = [strip_ansi_escape_codes(line) for line in lines]
    stripped_brackets_lines = [strip_brackets(line) for line in stripped_lines]
    sorted_lines = sorted(stripped_brackets_lines, key=lambda line: int(line.split()[1]))

    with open(sorted_httpx_output, 'w') as f:
        for line in sorted_lines:
            url = line.split()[0].replace("https://", "").replace("http://", "") 
            f.write(url + '\n')

    print(f"Sorted httpx results written to: {sorted_httpx_output}")




def scan_crt():
    print("Scanning crt.sh...")
    crt_output = os.path.join(result_dir, f'{domain}.crt.txt')
    crt_url = f"https://crt.sh/?q=%.{domain}&output=json"

    response = subprocess.check_output(["curl", "-s", crt_url])
    data = json.loads(response)

    unique_subdomains = set()

    for entry in data:
        name_value = entry.get("name_value")
        if name_value:
            name_value = name_value.replace("*.", "")
            unique_subdomains.add(name_value)

    with open(crt_output, "w") as f:
        for subdomain in sorted(unique_subdomains):
            f.write(subdomain + "\n")

    print(f"crt.sh results written to: {crt_output}")

def scan_naabu():
    print("Scanning subdomains with naabu...")
    sorted_httpx_output = os.path.join(result_dir, f'sorted_httpx_{domain}.txt')
    naabu_output = os.path.join(result_dir, f'naabu_{domain}.txt')
    cmd = f'naabu -list {sorted_httpx_output} -o {naabu_output}'
    subprocess.run(cmd, shell=True)
    print(f"Naabu results written to: {naabu_output}")

def scan_nuclei():
    print("Scanning subdomains with nuclei...")
    sorted_httpx_output = os.path.join(result_dir, f'sorted_httpx_{domain}.txt')
    nuclei_output = os.path.join(result_dir, f'nuclei_{domain}.txt')
    cmd = f'nuclei -list {sorted_httpx_output} -o {nuclei_output}'
    subprocess.run(cmd, shell=True)
    print(f"Nuclei results written to: {nuclei_output}")

def main():
    try:
        amass_process, subfinder_process, assetfinder_process, findomain_process = find_subdomains()
        amass_process.wait()
        subfinder_process.wait()
        assetfinder_process.wait()
        findomain_process.wait()

        scan_crt()
        combine_subdomains()
        find_ips()
        scan_httpx()
        scan_naabu()
        scan_nuclei()
    except KeyboardInterrupt:
        print("Keyboard interrupt detected. Exiting script...")
        sys.exit(1)

if __name__ == "__main__":
    main()

