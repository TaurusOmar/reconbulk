# SubEnumX
## Automated Subdomain Enumeration and Scanning Tool

![Untitled](https://github.com/TaurusOmar/SubEnumX/blob/main/SubEnumX-4.png?raw=true)

This script automates the process of subdomain enumeration and scanning using several popular open-source tools, combining their results and providing detailed output. The primary purpose of this tool is to simplify and streamline the process of discovering subdomains and their related information for a given domain.

## **Features**

- Uses Amass, Subfinder, Assetfinder, Findomain, crt.sh, MassDNS, Httpx, Naabu, and Nuclei
- Combines subdomain results from all tools into a single file
- Extracts IP addresses for discovered subdomains
- Scans subdomains with Httpx and sorts the results
- Scans subdomains with Naabu to find open ports
- Scans subdomains with Nuclei for potential vulnerabilities
- Organizes results in a structured directory

## **Installation**

1. Clone this repository

```
git clone https://github.com/yourusername/automated-subdomain-enumeration.git

```

2. Install all required tools:
- **[Amass](https://github.com/OWASP/Amass)**
- **[Subfinder](https://github.com/projectdiscovery/subfinder)**
- **[Assetfinder](https://github.com/tomnomnom/assetfinder)**
- **[Findomain](https://github.com/Findomain/Findomain)**
- **[MassDNS](https://github.com/blechschmidt/massdns)**
- **[Httpx](https://github.com/projectdiscovery/httpx)**
- **[Naabu](https://github.com/projectdiscovery/naabu)**
- **[Nuclei](https://github.com/projectdiscovery/nuclei)**

Make sure all these tools are in your system's **`PATH`**.

3. Prepare a list of DNS resolvers. You can find a sample list **[here](https://public-dns.info/nameservers.txt)**.

## **Usage**

```
python3 master_script.py <domain> <resolvers_list>

```

- **`<domain>`**: The target domain to scan
- **`<resolvers_list>`**: The file path to your list of DNS resolvers

The script will create a directory named **`~/recon/results/<domain>-<timestamp>`** containing the output files from each tool.

## **Output**

The output directory will contain the following files:

- amass_{domain}.txt: Output from Amass
- subfinder_{domain}.txt: Output from Subfinder
- assetfinder_{domain}.txt: Output from Assetfinder
- findomain_{domain}.txt: Output from Findomain
- {domain}.crt.txt: Output from crt.sh
- {domain}.subdomains.txt: Combined and unique subdomains from all tools
- {domain}.ips.txt: IP addresses associated with the discovered subdomains
- httpx_{domain}.txt: Results of the Httpx scan
- sorted_httpx_{domain}.txt: Sorted Httpx results
- naabu_{domain}.txt: Results of the Naabu scan
- nuclei_{domain}.txt: Results of the Nuclei scan

## **Disclaimer**

This tool is intended for educational purposes and legal use only. The authors and contributors are not responsible for any misuse, damage, or legal consequences caused by the use of this tool. Please use responsibly.

## **License**

This project is licensed under the MIT License - see the **[LICENSE]** file for details.
