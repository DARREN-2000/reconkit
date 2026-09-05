"""
reconkit.core.arsenal
=====================
Catalog + launcher for the wider ecosystem of *legal* offensive-security tools.

reconkit ships 25 native, dependency-free modules. The arsenal layer turns
reconkit into a single front-end for the best-of-breed industry tools
(nmap, ffuf, nuclei, sqlmap, BloodHound, Metasploit, ...): it knows about them,
detects which are installed, prints install hints, and can launch the ones you
have -- but only against authorized scope.

Ethics / law: every tool here is legal to install and study. Running these
against systems you do not own or are not explicitly authorized IN WRITING to
test can be a crime (e.g. US CFAA, UK CMA 1990, Germany StGB 202a-c / 303a-b).
The launcher refuses to run anything unless authorized=True (CLI: --authorized).
Exploitation / C2 / post-exploitation tooling is catalogued for orientation and
lab use (HTB / GOAD / your own range) and authorized engagements only.
"""

from __future__ import annotations

import shutil
import subprocess

try:
    from .utils import make_result
except Exception:  # allow standalone import / testing

    def make_result(module, summary, findings=None, data=None):
        return {
            "module": module,
            "summary": summary,
            "findings": findings or [],
            "data": data or {},
        }


# Availability buckets
FOSS = "foss"
FREEMIUM = "freemium"
COMMERCIAL = "commercial"
REF = "reference"  # distros, labs, methodology - not a single installable binary

# Kill-chain phases (see the Offensive Security Field Encyclopedia):
#  1 recon   2 scanning/enum   3 vuln-assessment   4 exploitation
#  5 post-exploitation/privesc/AD/C2   6 impact   7 reporting   0 support
CATALOG: list[dict] = []


def _t(name, category, phase, desc, bins, install, license=FOSS, url=""):
    return {
        "name": name,
        "category": category,
        "phase": phase,
        "desc": desc,
        "bins": list(bins),
        "install": install,
        "license": license,
        "url": url,
    }


# ---------------------------------------------------------------- recon / OSINT
CATALOG += [
    _t(
        "amass",
        "recon-osint",
        1,
        "In-depth DNS / asset enumeration and mapping",
        ["amass"],
        "apt install amass | go install github.com/owasp-amass/amass/v4/...@master",
        FOSS,
        "https://github.com/owasp-amass/amass",
    ),
    _t(
        "subfinder",
        "recon-osint",
        1,
        "Fast passive subdomain discovery",
        ["subfinder"],
        "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
        FOSS,
        "https://github.com/projectdiscovery/subfinder",
    ),
    _t(
        "assetfinder",
        "recon-osint",
        1,
        "Find domains and subdomains related to a target",
        ["assetfinder"],
        "go install github.com/tomnomnom/assetfinder@latest",
        FOSS,
        "https://github.com/tomnomnom/assetfinder",
    ),
    _t(
        "findomain",
        "recon-osint",
        1,
        "Fast cross-platform subdomain enumerator",
        ["findomain"],
        "cargo install findomain | download release",
        FOSS,
        "https://github.com/Findomain/Findomain",
    ),
    _t(
        "dnsx",
        "recon-osint",
        1,
        "Fast multipurpose DNS toolkit",
        ["dnsx"],
        "go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
        FOSS,
        "https://github.com/projectdiscovery/dnsx",
    ),
    _t(
        "massdns",
        "recon-osint",
        1,
        "High-performance DNS stub resolver for brute force",
        ["massdns"],
        "git clone github.com/blechschmidt/massdns && make",
        FOSS,
        "https://github.com/blechschmidt/massdns",
    ),
    _t(
        "theharvester",
        "recon-osint",
        1,
        "Emails, subdomains and hosts from public sources",
        ["theHarvester", "theharvester"],
        "apt install theharvester | pipx install theHarvester",
        FOSS,
        "https://github.com/laramies/theHarvester",
    ),
    _t(
        "recon-ng",
        "recon-osint",
        1,
        "Full-featured modular web reconnaissance framework",
        ["recon-ng"],
        "apt install recon-ng | pipx install recon-ng",
        FOSS,
        "https://github.com/lanmaster53/recon-ng",
    ),
    _t(
        "spiderfoot",
        "recon-osint",
        1,
        "Automated OSINT collection and correlation",
        ["spiderfoot", "sf.py"],
        "pipx install spiderfoot",
        FOSS,
        "https://github.com/smicallef/spiderfoot",
    ),
    _t(
        "maltego",
        "recon-osint",
        1,
        "Link-analysis and OSINT graphing (CE is free)",
        ["maltego"],
        "download from maltego.com (Community Edition)",
        FREEMIUM,
        "https://www.maltego.com/",
    ),
    _t(
        "shodan",
        "recon-osint",
        1,
        "Search engine for internet-exposed assets",
        ["shodan"],
        "pipx install shodan (needs API key)",
        FREEMIUM,
        "https://cli.shodan.io/",
    ),
    _t(
        "censys",
        "recon-osint",
        1,
        "Internet asset search / attack-surface data",
        ["censys"],
        "pipx install censys (needs API key)",
        FREEMIUM,
        "https://github.com/censys/censys-python",
    ),
    _t(
        "dnsrecon",
        "recon-osint",
        1,
        "DNS enumeration and zone-transfer testing",
        ["dnsrecon"],
        "apt install dnsrecon | pipx install dnsrecon",
        FOSS,
        "https://github.com/darkoperator/dnsrecon",
    ),
    _t(
        "fierce",
        "recon-osint",
        1,
        "DNS reconnaissance / subdomain scanner",
        ["fierce"],
        "apt install fierce | pipx install fierce",
        FOSS,
        "https://github.com/mschwager/fierce",
    ),
    _t(
        "sublist3r",
        "recon-osint",
        1,
        "Subdomain enumeration via search engines",
        ["sublist3r"],
        "pipx install sublist3r",
        FOSS,
        "https://github.com/aboul3la/Sublist3r",
    ),
    _t(
        "waybackurls",
        "recon-osint",
        1,
        "Fetch known URLs from the Wayback Machine",
        ["waybackurls"],
        "go install github.com/tomnomnom/waybackurls@latest",
        FOSS,
        "https://github.com/tomnomnom/waybackurls",
    ),
    _t(
        "gau",
        "recon-osint",
        1,
        "getallurls: URLs from Wayback / CommonCrawl / OTX",
        ["gau"],
        "go install github.com/lc/gau/v2/cmd/gau@latest",
        FOSS,
        "https://github.com/lc/gau",
    ),
    _t(
        "katana",
        "recon-osint",
        1,
        "Next-gen crawling and spidering framework",
        ["katana"],
        "go install github.com/projectdiscovery/katana/cmd/katana@latest",
        FOSS,
        "https://github.com/projectdiscovery/katana",
    ),
    _t(
        "gitleaks",
        "recon-osint",
        1,
        "Detect hardcoded secrets/keys in git repos",
        ["gitleaks"],
        "apt install gitleaks | brew install gitleaks",
        FOSS,
        "https://github.com/gitleaks/gitleaks",
    ),
    _t(
        "trufflehog",
        "recon-osint",
        1,
        "Find leaked credentials in repos and files",
        ["trufflehog"],
        "pipx install trufflehog | brew install trufflehog",
        FOSS,
        "https://github.com/trufflesecurity/trufflehog",
    ),
    _t(
        "metagoofil",
        "recon-osint",
        1,
        "Extract metadata from public documents",
        ["metagoofil"],
        "apt install metagoofil | pipx install metagoofil",
        FOSS,
        "https://github.com/opsdisk/metagoofil",
    ),
    _t(
        "exiftool",
        "recon-osint",
        1,
        "Read/write file and document metadata",
        ["exiftool"],
        "apt install libimage-exiftool-perl | brew install exiftool",
        FOSS,
        "https://exiftool.org/",
    ),
    _t(
        "sherlock",
        "recon-osint",
        1,
        "Hunt a username across social networks",
        ["sherlock"],
        "pipx install sherlock-project",
        FOSS,
        "https://github.com/sherlock-project/sherlock",
    ),
    _t(
        "holehe",
        "recon-osint",
        1,
        "Check which sites an email is registered on",
        ["holehe"],
        "pipx install holehe",
        FOSS,
        "https://github.com/megadose/holehe",
    ),
]


# --------------------------------------------------------- scanning / enumeration
CATALOG += [
    _t(
        "nmap",
        "scanning-enum",
        2,
        "Port scanning, service/version detection and NSE",
        ["nmap"],
        "apt install nmap | brew install nmap",
        FOSS,
        "https://nmap.org/",
    ),
    _t(
        "masscan",
        "scanning-enum",
        2,
        "Internet-scale asynchronous TCP port scanner",
        ["masscan"],
        "apt install masscan | brew install masscan",
        FOSS,
        "https://github.com/robertdavidgraham/masscan",
    ),
    _t(
        "rustscan",
        "scanning-enum",
        2,
        "Very fast port scanner that feeds into nmap",
        ["rustscan"],
        "cargo install rustscan | docker pull rustscan/rustscan",
        FOSS,
        "https://github.com/RustScan/RustScan",
    ),
    _t(
        "naabu",
        "scanning-enum",
        2,
        "Fast SYN/CONNECT port scanner",
        ["naabu"],
        "go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
        FOSS,
        "https://github.com/projectdiscovery/naabu",
    ),
    _t(
        "zmap",
        "scanning-enum",
        2,
        "Single-packet internet-wide network scanner",
        ["zmap"],
        "apt install zmap",
        FOSS,
        "https://github.com/zmap/zmap",
    ),
    _t(
        "httpx",
        "scanning-enum",
        2,
        "Fast HTTP prober (status/title/tech)",
        ["httpx"],
        "go install github.com/projectdiscovery/httpx/cmd/httpx@latest",
        FOSS,
        "https://github.com/projectdiscovery/httpx",
    ),
    _t(
        "whatweb",
        "scanning-enum",
        2,
        "Web technology fingerprinting",
        ["whatweb"],
        "apt install whatweb",
        FOSS,
        "https://github.com/urbanadventurer/WhatWeb",
    ),
    _t(
        "wafw00f",
        "scanning-enum",
        2,
        "Identify the WAF in front of a web app",
        ["wafw00f"],
        "apt install wafw00f | pipx install wafw00f",
        FOSS,
        "https://github.com/EnableSecurity/wafw00f",
    ),
    _t(
        "enum4linux-ng",
        "scanning-enum",
        2,
        "SMB / NetBIOS enumeration (next-gen)",
        ["enum4linux-ng", "enum4linux"],
        "pipx install enum4linux-ng | apt install enum4linux",
        FOSS,
        "https://github.com/cddmp/enum4linux-ng",
    ),
    _t(
        "smbmap",
        "scanning-enum",
        2,
        "Enumerate SMB shares and permissions",
        ["smbmap"],
        "apt install smbmap | pipx install smbmap",
        FOSS,
        "https://github.com/ShawnDEvans/smbmap",
    ),
    _t(
        "smbclient",
        "scanning-enum",
        2,
        "SMB/CIFS client to list and access shares",
        ["smbclient"],
        "apt install smbclient",
        FOSS,
        "https://www.samba.org/",
    ),
    _t(
        "rpcclient",
        "scanning-enum",
        2,
        "MS-RPC client for Windows/Samba enumeration",
        ["rpcclient"],
        "apt install samba-common-bin",
        FOSS,
        "https://www.samba.org/",
    ),
    _t(
        "snmpwalk",
        "scanning-enum",
        2,
        "Walk SNMP MIB trees on network devices",
        ["snmpwalk"],
        "apt install snmp",
        FOSS,
        "http://www.net-snmp.org/",
    ),
    _t(
        "onesixtyone",
        "scanning-enum",
        2,
        "Fast SNMP community-string scanner",
        ["onesixtyone"],
        "apt install onesixtyone",
        FOSS,
        "https://github.com/trailofbits/onesixtyone",
    ),
    _t(
        "nbtscan",
        "scanning-enum",
        2,
        "Scan networks for NetBIOS name information",
        ["nbtscan"],
        "apt install nbtscan",
        FOSS,
        "https://github.com/resurrecting-open-source-projects/nbtscan",
    ),
    _t(
        "ldapsearch",
        "scanning-enum",
        2,
        "Query LDAP / Active Directory directory data",
        ["ldapsearch"],
        "apt install ldap-utils",
        FOSS,
        "https://www.openldap.org/",
    ),
    _t(
        "ike-scan",
        "scanning-enum",
        2,
        "Discover and fingerprint IKE/IPsec VPNs",
        ["ike-scan"],
        "apt install ike-scan",
        FOSS,
        "https://github.com/royhills/ike-scan",
    ),
]

# --- END PART 1 ---

# ------------------------------------------------------------- web application
CATALOG += [
    _t(
        "burpsuite",
        "web-app",
        3,
        "The de-facto web proxy / scanner (CE is free)",
        ["burpsuite"],
        "download from PortSwigger (Community Edition)",
        FREEMIUM,
        "https://portswigger.net/burp",
    ),
    _t(
        "zaproxy",
        "web-app",
        3,
        "OWASP ZAP: full-featured web app scanner and proxy",
        ["zaproxy", "zap.sh", "owasp-zap"],
        "apt install zaproxy | snap install zaproxy",
        FOSS,
        "https://www.zaproxy.org/",
    ),
    _t(
        "ffuf",
        "web-app",
        3,
        "Fast web fuzzer (dirs, params, vhosts)",
        ["ffuf"],
        "apt install ffuf | go install github.com/ffuf/ffuf/v2@latest",
        FOSS,
        "https://github.com/ffuf/ffuf",
    ),
    _t(
        "gobuster",
        "web-app",
        3,
        "Directory / DNS / vhost brute-forcer",
        ["gobuster"],
        "apt install gobuster | go install github.com/OJ/gobuster/v3@latest",
        FOSS,
        "https://github.com/OJ/gobuster",
    ),
    _t(
        "feroxbuster",
        "web-app",
        3,
        "Fast recursive content discovery",
        ["feroxbuster"],
        "apt install feroxbuster | cargo install feroxbuster",
        FOSS,
        "https://github.com/epi052/feroxbuster",
    ),
    _t(
        "dirsearch",
        "web-app",
        3,
        "Web path brute-forcer",
        ["dirsearch"],
        "pipx install dirsearch | apt install dirsearch",
        FOSS,
        "https://github.com/maurosoria/dirsearch",
    ),
    _t(
        "wfuzz",
        "web-app",
        3,
        "Web application fuzzer",
        ["wfuzz"],
        "apt install wfuzz | pipx install wfuzz",
        FOSS,
        "https://github.com/xmendez/wfuzz",
    ),
    _t(
        "nikto",
        "web-app",
        3,
        "Web server vulnerability scanner",
        ["nikto"],
        "apt install nikto",
        FOSS,
        "https://github.com/sullo/nikto",
    ),
    _t(
        "wpscan",
        "web-app",
        3,
        "WordPress security scanner",
        ["wpscan"],
        "gem install wpscan | apt install wpscan",
        FOSS,
        "https://github.com/wpscanteam/wpscan",
    ),
    _t(
        "joomscan",
        "web-app",
        3,
        "Joomla vulnerability scanner",
        ["joomscan"],
        "apt install joomscan",
        FOSS,
        "https://github.com/OWASP/joomscan",
    ),
    _t(
        "cmseek",
        "web-app",
        3,
        "CMS detection and enumeration",
        ["cmseek"],
        "git clone github.com/Tuhinshubhra/CMSeeK",
        FOSS,
        "https://github.com/Tuhinshubhra/CMSeeK",
    ),
    _t(
        "dalfox",
        "web-app",
        3,
        "Powerful XSS scanning and parameter analysis",
        ["dalfox"],
        "go install github.com/hahwul/dalfox/v2@latest",
        FOSS,
        "https://github.com/hahwul/dalfox",
    ),
    _t(
        "xsstrike",
        "web-app",
        3,
        "Advanced XSS detection suite",
        ["xsstrike", "XSStrike"],
        "git clone github.com/s0md3v/XSStrike",
        FOSS,
        "https://github.com/s0md3v/XSStrike",
    ),
    _t(
        "arjun",
        "web-app",
        3,
        "HTTP parameter discovery",
        ["arjun"],
        "pipx install arjun",
        FOSS,
        "https://github.com/s0md3v/Arjun",
    ),
    _t(
        "paramspider",
        "web-app",
        3,
        "Mine parameters from web archives",
        ["paramspider"],
        "pipx install paramspider",
        FOSS,
        "https://github.com/devanshbatham/ParamSpider",
    ),
    _t(
        "hakrawler",
        "web-app",
        3,
        "Fast web crawler for endpoint discovery",
        ["hakrawler"],
        "go install github.com/hakluke/hakrawler@latest",
        FOSS,
        "https://github.com/hakluke/hakrawler",
    ),
    _t(
        "gowitness",
        "web-app",
        3,
        "Screenshot web pages at scale",
        ["gowitness"],
        "go install github.com/sensepost/gowitness@latest",
        FOSS,
        "https://github.com/sensepost/gowitness",
    ),
    _t(
        "testssl.sh",
        "web-app",
        3,
        "Test TLS/SSL config, ciphers and known flaws",
        ["testssl.sh", "testssl"],
        "git clone github.com/drwetter/testssl.sh",
        FOSS,
        "https://testssl.sh/",
    ),
    _t(
        "sslscan",
        "web-app",
        3,
        "Query SSL/TLS services for ciphers and certs",
        ["sslscan"],
        "apt install sslscan",
        FOSS,
        "https://github.com/rbsec/sslscan",
    ),
    _t(
        "sslyze",
        "web-app",
        3,
        "Fast, deep TLS configuration analyzer",
        ["sslyze"],
        "pipx install sslyze",
        FOSS,
        "https://github.com/nabla-c0d3/sslyze",
    ),
    _t(
        "jwt_tool",
        "web-app",
        3,
        "Test, tamper and crack JSON Web Tokens",
        ["jwt_tool", "jwt_tool.py"],
        "git clone github.com/ticarpi/jwt_tool",
        FOSS,
        "https://github.com/ticarpi/jwt_tool",
    ),
]


# ---------------------------------------------------------- vulnerability scanners
CATALOG += [
    _t(
        "nuclei",
        "vuln-scan",
        3,
        "Template-based vulnerability scanner",
        ["nuclei"],
        "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        FOSS,
        "https://github.com/projectdiscovery/nuclei",
    ),
    _t(
        "openvas",
        "vuln-scan",
        3,
        "Greenbone / OpenVAS full vulnerability scanner",
        ["gvm-cli", "openvas", "gvmd"],
        "apt install openvas | Greenbone GVM setup",
        FOSS,
        "https://www.greenbone.net/",
    ),
    _t(
        "nessus",
        "vuln-scan",
        3,
        "Industry vulnerability scanner (Essentials free)",
        ["nessuscli", "nessusd", "nessus"],
        "download Nessus Essentials from Tenable",
        FREEMIUM,
        "https://www.tenable.com/products/nessus",
    ),
    _t(
        "trivy",
        "vuln-scan",
        3,
        "Vuln/misconfig scanner for images, FS and repos",
        ["trivy"],
        "apt install trivy | brew install trivy",
        FOSS,
        "https://github.com/aquasecurity/trivy",
    ),
    _t(
        "grype",
        "vuln-scan",
        3,
        "Vulnerability scanner for container images and FS",
        ["grype"],
        "brew install grype | curl installer",
        FOSS,
        "https://github.com/anchore/grype",
    ),
]

# --- END PART 2 ---

# --------------------------------------------------------------- password attacks
CATALOG += [
    _t(
        "hydra",
        "password",
        0,
        "Fast online login brute-forcer (many protocols)",
        ["hydra"],
        "apt install hydra | brew install hydra",
        FOSS,
        "https://github.com/vanhauser-thc/thc-hydra",
    ),
    _t(
        "medusa",
        "password",
        0,
        "Parallel network login brute-forcer",
        ["medusa"],
        "apt install medusa",
        FOSS,
        "https://github.com/jmk-foofus/medusa",
    ),
    _t(
        "ncrack",
        "password",
        0,
        "High-speed network authentication cracker",
        ["ncrack"],
        "apt install ncrack",
        FOSS,
        "https://nmap.org/ncrack/",
    ),
    _t(
        "patator",
        "password",
        0,
        "Multi-purpose modular brute-forcer",
        ["patator"],
        "apt install patator | pipx install patator",
        FOSS,
        "https://github.com/lanjelot/patator",
    ),
    _t(
        "john",
        "password",
        0,
        "John the Ripper offline password cracker",
        ["john"],
        "apt install john | brew install john-jumbo",
        FOSS,
        "https://www.openwall.com/john/",
    ),
    _t(
        "hashcat",
        "password",
        0,
        "World's fastest GPU password cracker",
        ["hashcat"],
        "apt install hashcat | brew install hashcat",
        FOSS,
        "https://hashcat.net/hashcat/",
    ),
    _t(
        "cewl",
        "password",
        0,
        "Crawl a site to build a custom wordlist",
        ["cewl"],
        "apt install cewl",
        FOSS,
        "https://github.com/digininja/CeWL",
    ),
    _t(
        "crunch",
        "password",
        0,
        "Generate wordlists from character sets/patterns",
        ["crunch"],
        "apt install crunch",
        FOSS,
        "https://github.com/crunchsec/crunch",
    ),
    _t(
        "hashid",
        "password",
        0,
        "Identify the type of a given hash",
        ["hashid"],
        "pipx install hashid | apt install hashid",
        FOSS,
        "https://github.com/psypanda/hashID",
    ),
    _t(
        "name-that-hash",
        "password",
        0,
        "Modern hash-type identifier",
        ["nth", "name-that-hash"],
        "pipx install name-that-hash",
        FOSS,
        "https://github.com/HashPals/Name-That-Hash",
    ),
]


# ------------------------------------------------------------------- exploitation
CATALOG += [
    _t(
        "metasploit",
        "exploitation",
        4,
        "The exploitation framework (modules, payloads, sessions)",
        ["msfconsole"],
        "apt install metasploit-framework | omnibus installer",
        FOSS,
        "https://www.metasploit.com/",
    ),
    _t(
        "msfvenom",
        "exploitation",
        4,
        "Metasploit payload generator/encoder",
        ["msfvenom"],
        "ships with metasploit-framework",
        FOSS,
        "https://www.metasploit.com/",
    ),
    _t(
        "searchsploit",
        "exploitation",
        4,
        "Offline search of the Exploit-DB archive",
        ["searchsploit"],
        "apt install exploitdb",
        FOSS,
        "https://gitlab.com/exploit-database/exploitdb",
    ),
    _t(
        "sqlmap",
        "exploitation",
        4,
        "Automatic SQL injection detection and exploitation",
        ["sqlmap"],
        "apt install sqlmap | pipx install sqlmap",
        FOSS,
        "https://sqlmap.org/",
    ),
    _t(
        "commix",
        "exploitation",
        4,
        "Automated command-injection exploitation",
        ["commix"],
        "apt install commix | git clone commixproject/commix",
        FOSS,
        "https://github.com/commixproject/commix",
    ),
    _t(
        "pwntools",
        "exploitation",
        4,
        "CTF/exploit-dev framework for Python",
        ["pwn"],
        "pipx install pwntools",
        FOSS,
        "https://github.com/Gallopsled/pwntools",
    ),
    _t(
        "ropgadget",
        "exploitation",
        4,
        "Find ROP gadgets in binaries",
        ["ROPgadget"],
        "pipx install ROPgadget",
        FOSS,
        "https://github.com/JonathanSalwan/ROPgadget",
    ),
    _t(
        "ropper",
        "exploitation",
        4,
        "Display info about binaries and find gadgets",
        ["ropper"],
        "pipx install ropper",
        FOSS,
        "https://github.com/sashs/Ropper",
    ),
    _t(
        "one_gadget",
        "exploitation",
        4,
        "Find one-shot execve gadgets in libc",
        ["one_gadget"],
        "gem install one_gadget",
        FOSS,
        "https://github.com/david942j/one_gadget",
    ),
    _t(
        "checksec",
        "exploitation",
        4,
        "Check binary hardening (RELRO, canary, NX, PIE)",
        ["checksec"],
        "apt install checksec",
        FOSS,
        "https://github.com/slimm609/checksec.sh",
    ),
    _t(
        "routersploit",
        "exploitation",
        4,
        "Exploitation framework for embedded/IoT devices",
        ["rsf.py", "routersploit"],
        "git clone threat9/routersploit",
        FOSS,
        "https://github.com/threat9/routersploit",
    ),
    _t(
        "beef",
        "exploitation",
        4,
        "Browser Exploitation Framework (hook & drive browsers)",
        ["beef-xss", "beef"],
        "apt install beef-xss",
        FOSS,
        "https://github.com/beefproject/beef",
    ),
    _t(
        "setoolkit",
        "exploitation",
        4,
        "Social-Engineer Toolkit (phishing sims, authorized only)",
        ["setoolkit", "se-toolkit"],
        "apt install set | git clone trustedsec/social-engineer-toolkit",
        FOSS,
        "https://github.com/trustedsec/social-engineer-toolkit",
    ),
    _t(
        "evil-winrm",
        "exploitation",
        4,
        "WinRM shell for pentesting Windows hosts",
        ["evil-winrm"],
        "gem install evil-winrm | apt install evil-winrm",
        FOSS,
        "https://github.com/Hackplayers/evil-winrm",
    ),
]

# --- END PART 3 ---

# ------------------------------------------- Active Directory / post-exploitation
CATALOG += [
    _t(
        "bloodhound",
        "ad-postex",
        5,
        "Map AD attack paths with graph analytics",
        ["bloodhound", "BloodHound"],
        "download BloodHound CE | apt install bloodhound",
        FOSS,
        "https://github.com/SpecterOps/BloodHound",
    ),
    _t(
        "sharphound",
        "ad-postex",
        5,
        "BloodHound data collector for AD",
        ["sharphound", "SharpHound.exe"],
        "download from BloodHound release (run on Windows)",
        FOSS,
        "https://github.com/SpecterOps/SharpHound",
    ),
    _t(
        "bloodhound-python",
        "ad-postex",
        5,
        "Python BloodHound ingestor (no Windows needed)",
        ["bloodhound-python"],
        "pipx install bloodhound",
        FOSS,
        "https://github.com/dirkjanm/BloodHound.py",
    ),
    _t(
        "neo4j",
        "ad-postex",
        5,
        "Graph database backing BloodHound",
        ["neo4j", "cypher-shell"],
        "apt install neo4j | download from Neo4j",
        FOSS,
        "https://neo4j.com/",
    ),
    _t(
        "netexec",
        "ad-postex",
        5,
        "Network/AD swiss-army (CrackMapExec successor)",
        ["nxc", "netexec", "crackmapexec", "cme"],
        "pipx install netexec",
        FOSS,
        "https://github.com/Pennyw0rth/NetExec",
    ),
    _t(
        "impacket",
        "ad-postex",
        5,
        "Python classes + scripts for Windows/AD protocols",
        ["impacket-secretsdump", "secretsdump.py", "impacket-GetUserSPNs"],
        "pipx install impacket",
        FOSS,
        "https://github.com/fortra/impacket",
    ),
    _t(
        "rubeus",
        "ad-postex",
        5,
        "Kerberos abuse toolkit (roasting, PtT, S4U)",
        ["rubeus", "Rubeus.exe"],
        "compile from GhostPack (run on Windows)",
        FOSS,
        "https://github.com/GhostPack/Rubeus",
    ),
    _t(
        "certipy",
        "ad-postex",
        5,
        "Enumerate and abuse AD Certificate Services",
        ["certipy", "certipy-ad"],
        "pipx install certipy-ad",
        FOSS,
        "https://github.com/ly4k/Certipy",
    ),
    _t(
        "kerbrute",
        "ad-postex",
        5,
        "Kerberos user enumeration and password spraying",
        ["kerbrute"],
        "go install github.com/ropnop/kerbrute@latest",
        FOSS,
        "https://github.com/ropnop/kerbrute",
    ),
    _t(
        "ldapdomaindump",
        "ad-postex",
        5,
        "Dump AD info over LDAP into readable files",
        ["ldapdomaindump"],
        "pipx install ldapdomaindump",
        FOSS,
        "https://github.com/dirkjanm/ldapdomaindump",
    ),
    _t(
        "adidnsdump",
        "ad-postex",
        5,
        "Dump AD-integrated DNS records via LDAP",
        ["adidnsdump"],
        "pipx install adidnsdump",
        FOSS,
        "https://github.com/dirkjanm/adidnsdump",
    ),
    _t(
        "powerview",
        "ad-postex",
        5,
        "PowerShell AD situational-awareness toolkit",
        ["powerview", "PowerView.ps1"],
        "part of PowerSploit / obfuscated forks",
        FOSS,
        "https://github.com/PowerShellMafia/PowerSploit",
    ),
    _t(
        "mimikatz",
        "ad-postex",
        5,
        "Extract Windows credentials (lab / authorized only)",
        ["mimikatz", "mimikatz.exe"],
        "download from gentilkiwi (run on Windows lab)",
        FOSS,
        "https://github.com/gentilkiwi/mimikatz",
    ),
    _t(
        "lsassy",
        "ad-postex",
        5,
        "Remotely extract LSASS secrets (authorized only)",
        ["lsassy"],
        "pipx install lsassy",
        FOSS,
        "https://github.com/Hackndo/lsassy",
    ),
    _t(
        "responder",
        "ad-postex",
        5,
        "LLMNR/NBT-NS/mDNS poisoner and rogue services",
        ["responder", "Responder.py"],
        "apt install responder | git clone lgandx/Responder",
        FOSS,
        "https://github.com/lgandx/Responder",
    ),
    _t(
        "mitm6",
        "ad-postex",
        5,
        "Abuse IPv6 to take over Windows DNS",
        ["mitm6"],
        "pipx install mitm6",
        FOSS,
        "https://github.com/dirkjanm/mitm6",
    ),
]


# ----------------------------------------- command & control (authorized / lab)
CATALOG += [
    _t(
        "sliver",
        "c2",
        5,
        "Modern cross-platform C2 (red-team / lab only)",
        ["sliver-server", "sliver-client", "sliver"],
        "curl https://sliver.sh/install | bash",
        FOSS,
        "https://github.com/BishopFox/sliver",
    ),
    _t(
        "mythic",
        "c2",
        5,
        "Plugin-based, multi-agent C2 framework (lab only)",
        ["mythic-cli", "mythic"],
        "git clone its-a-feature/Mythic && ./mythic-cli start",
        FOSS,
        "https://github.com/its-a-feature/Mythic",
    ),
    _t(
        "covenant",
        "c2",
        5,
        ".NET collaborative C2 framework (lab only)",
        ["covenant", "Covenant"],
        "git clone cobbr/Covenant (dotnet)",
        FOSS,
        "https://github.com/cobbr/Covenant",
    ),
    _t(
        "empire",
        "c2",
        5,
        "PowerShell/Python post-exploitation C2 (lab only)",
        ["powershell-empire", "empire"],
        "apt install powershell-empire | BC-Security installer",
        FOSS,
        "https://github.com/BC-SECURITY/Empire",
    ),
    _t(
        "poshc2",
        "c2",
        5,
        "Proxy-aware C2 for red teams (lab only)",
        ["posh-c2", "poshc2"],
        "curl posh install | bash",
        FOSS,
        "https://github.com/nettitude/PoshC2",
    ),
    _t(
        "havoc",
        "c2",
        5,
        "Modern malleable C2 framework (lab only)",
        ["havoc"],
        "git clone HavocFramework/Havoc && make",
        FOSS,
        "https://github.com/HavocFramework/Havoc",
    ),
    _t(
        "merlin",
        "c2",
        5,
        "HTTP/2 cross-platform C2 (lab only)",
        ["merlinServer", "merlin"],
        "download from Ne0nd0g/merlin release",
        FOSS,
        "https://github.com/Ne0nd0g/merlin",
    ),
    _t(
        "cobaltstrike",
        "c2",
        5,
        "Commercial adversary-simulation C2 (licensed)",
        ["cobaltstrike", "teamserver"],
        "licensed purchase from Fortra",
        COMMERCIAL,
        "https://www.cobaltstrike.com/",
    ),
]

# --- END PART 4 ---

# ------------------------------------------------------------------------ wireless
CATALOG += [
    _t(
        "aircrack-ng",
        "wireless",
        4,
        "Wi-Fi capture, injection and WPA/WEP cracking suite",
        ["aircrack-ng", "airodump-ng", "aireplay-ng"],
        "apt install aircrack-ng",
        FOSS,
        "https://www.aircrack-ng.org/",
    ),
    _t(
        "kismet",
        "wireless",
        2,
        "Wireless network/device detector and sniffer",
        ["kismet"],
        "apt install kismet",
        FOSS,
        "https://www.kismetwireless.net/",
    ),
    _t(
        "wifite",
        "wireless",
        4,
        "Automated wireless auditing wrapper",
        ["wifite"],
        "apt install wifite",
        FOSS,
        "https://github.com/derv82/wifite2",
    ),
    _t(
        "hcxdumptool",
        "wireless",
        4,
        "Capture WPA PMKID/handshakes from Wi-Fi",
        ["hcxdumptool"],
        "apt install hcxdumptool",
        FOSS,
        "https://github.com/ZerBea/hcxdumptool",
    ),
    _t(
        "hcxtools",
        "wireless",
        4,
        "Convert captures to hashcat-crackable formats",
        ["hcxpcapngtool", "hcxtools"],
        "apt install hcxtools",
        FOSS,
        "https://github.com/ZerBea/hcxtools",
    ),
    _t(
        "reaver",
        "wireless",
        4,
        "Brute-force WPS PINs to recover WPA keys",
        ["reaver"],
        "apt install reaver",
        FOSS,
        "https://github.com/t6x/reaver-wps-fork-t6x",
    ),
    _t(
        "bettercap",
        "wireless",
        5,
        "Swiss-army for Wi-Fi/BLE/Ethernet MITM and recon",
        ["bettercap"],
        "apt install bettercap | go install",
        FOSS,
        "https://www.bettercap.org/",
    ),
]


# --------------------------------------------------------------- network / MITM
CATALOG += [
    _t(
        "wireshark",
        "network-mitm",
        2,
        "Deep packet capture and protocol analysis",
        ["wireshark"],
        "apt install wireshark",
        FOSS,
        "https://www.wireshark.org/",
    ),
    _t(
        "tshark",
        "network-mitm",
        2,
        "Terminal packet analyzer (Wireshark CLI)",
        ["tshark"],
        "apt install tshark",
        FOSS,
        "https://www.wireshark.org/",
    ),
    _t(
        "tcpdump",
        "network-mitm",
        2,
        "Command-line packet capture",
        ["tcpdump"],
        "apt install tcpdump",
        FOSS,
        "https://www.tcpdump.org/",
    ),
    _t(
        "ettercap",
        "network-mitm",
        5,
        "Classic MITM suite (ARP poisoning, sniffing)",
        ["ettercap", "ettercap-text-only"],
        "apt install ettercap-text-only",
        FOSS,
        "https://www.ettercap-project.org/",
    ),
    _t(
        "mitmproxy",
        "network-mitm",
        5,
        "Interactive HTTPS intercepting proxy",
        ["mitmproxy", "mitmdump"],
        "pipx install mitmproxy | apt install mitmproxy",
        FOSS,
        "https://mitmproxy.org/",
    ),
    _t(
        "dsniff",
        "network-mitm",
        5,
        "Sniffing/MITM tools incl. arpspoof",
        ["arpspoof", "dsniff"],
        "apt install dsniff",
        FOSS,
        "https://www.monkey.org/~dugsong/dsniff/",
    ),
    _t(
        "scapy",
        "network-mitm",
        0,
        "Interactive packet crafting and manipulation",
        ["scapy"],
        "pipx install scapy | apt install python3-scapy",
        FOSS,
        "https://scapy.net/",
    ),
]


# ------------------------------------------------------------------------- cloud
CATALOG += [
    _t(
        "scoutsuite",
        "cloud",
        3,
        "Multi-cloud security auditing (AWS/Azure/GCP)",
        ["scout", "scoutsuite"],
        "pipx install scoutsuite",
        FOSS,
        "https://github.com/nccgroup/ScoutSuite",
    ),
    _t(
        "prowler",
        "cloud",
        3,
        "Cloud security assessments and CIS benchmarks",
        ["prowler"],
        "pipx install prowler",
        FOSS,
        "https://github.com/prowler-cloud/prowler",
    ),
    _t(
        "pacu",
        "cloud",
        4,
        "AWS exploitation framework",
        ["pacu"],
        "pipx install pacu",
        FOSS,
        "https://github.com/RhinoSecurityLabs/pacu",
    ),
    _t(
        "cloudfox",
        "cloud",
        3,
        "Find exploitable attack paths in cloud infra",
        ["cloudfox"],
        "brew install cloudfox | download release",
        FOSS,
        "https://github.com/BishopFox/cloudfox",
    ),
    _t(
        "cloudmapper",
        "cloud",
        3,
        "Analyze and visualize AWS environments",
        ["cloudmapper"],
        "git clone duo-labs/cloudmapper",
        FOSS,
        "https://github.com/duo-labs/cloudmapper",
    ),
    _t(
        "cloudsplaining",
        "cloud",
        3,
        "AWS IAM least-privilege assessment",
        ["cloudsplaining"],
        "pipx install cloudsplaining",
        FOSS,
        "https://github.com/salesforce/cloudsplaining",
    ),
    _t(
        "enumerate-iam",
        "cloud",
        3,
        "Brute the permissions of AWS keys",
        ["enumerate-iam"],
        "git clone andresriancho/enumerate-iam",
        FOSS,
        "https://github.com/andresriancho/enumerate-iam",
    ),
    _t(
        "s3scanner",
        "cloud",
        3,
        "Find open/misconfigured S3-style buckets",
        ["s3scanner"],
        "pipx install s3scanner",
        FOSS,
        "https://github.com/sa7mon/S3Scanner",
    ),
    _t(
        "cartography",
        "cloud",
        3,
        "Graph infra/assets and their relationships",
        ["cartography"],
        "pipx install cartography",
        FOSS,
        "https://github.com/lyft/cartography",
    ),
    _t(
        "awscli",
        "cloud",
        0,
        "Official AWS CLI (enumeration once you have keys)",
        ["aws"],
        "pipx install awscli | apt install awscli",
        FOSS,
        "https://aws.amazon.com/cli/",
    ),
]


# ----------------------------------------------------------- containers / kubernetes
CATALOG += [
    _t(
        "kube-hunter",
        "containers-k8s",
        3,
        "Hunt for security weaknesses in Kubernetes",
        ["kube-hunter"],
        "pipx install kube-hunter",
        FOSS,
        "https://github.com/aquasecurity/kube-hunter",
    ),
    _t(
        "kube-bench",
        "containers-k8s",
        3,
        "Check Kubernetes against CIS benchmarks",
        ["kube-bench"],
        "download release | run as job",
        FOSS,
        "https://github.com/aquasecurity/kube-bench",
    ),
    _t(
        "kubeaudit",
        "containers-k8s",
        3,
        "Audit Kubernetes clusters for common risks",
        ["kubeaudit"],
        "brew install kubeaudit | download release",
        FOSS,
        "https://github.com/Shopify/kubeaudit",
    ),
    _t(
        "peirates",
        "containers-k8s",
        4,
        "Kubernetes penetration-testing / escalation",
        ["peirates"],
        "download release from inguardians/peirates",
        FOSS,
        "https://github.com/inguardians/peirates",
    ),
    _t(
        "docker-bench-security",
        "containers-k8s",
        3,
        "Check Docker hosts against CIS benchmarks",
        ["docker-bench-security"],
        "git clone docker/docker-bench-security",
        FOSS,
        "https://github.com/docker/docker-bench-security",
    ),
]

# --- END PART 5 ---

# ------------------------------------------------------------------------ mobile
CATALOG += [
    _t(
        "mobsf",
        "mobile",
        3,
        "Mobile Security Framework: static/dynamic app analysis",
        ["mobsf", "MobSF"],
        "pip install mobsf | docker pull opensecurity/mobile-security-framework-mobsf",
        FOSS,
        "https://github.com/MobSF/Mobile-Security-Framework-MobSF",
    ),
    _t(
        "frida",
        "mobile",
        3,
        "Dynamic instrumentation toolkit (hook apps at runtime)",
        ["frida", "frida-server"],
        "pipx install frida-tools",
        FOSS,
        "https://frida.re/",
    ),
    _t(
        "objection",
        "mobile",
        3,
        "Runtime mobile exploration built on Frida",
        ["objection"],
        "pipx install objection",
        FOSS,
        "https://github.com/sensepost/objection",
    ),
    _t(
        "apktool",
        "mobile",
        3,
        "Reverse-engineer and rebuild Android APKs",
        ["apktool"],
        "apt install apktool",
        FOSS,
        "https://apktool.org/",
    ),
    _t(
        "jadx",
        "mobile",
        3,
        "Decompile Android DEX/APK to Java source",
        ["jadx", "jadx-gui"],
        "apt install jadx | download release",
        FOSS,
        "https://github.com/skylot/jadx",
    ),
    _t(
        "dex2jar",
        "mobile",
        3,
        "Convert Android .dex to .jar for analysis",
        ["d2j-dex2jar", "dex2jar"],
        "apt install dex2jar",
        FOSS,
        "https://github.com/pxb1988/dex2jar",
    ),
]


# ---------------------------------------------- reverse engineering / binary / pwn
CATALOG += [
    _t(
        "ghidra",
        "re-pwn",
        4,
        "NSA software reverse-engineering suite / decompiler",
        ["ghidra", "ghidraRun"],
        "apt install ghidra | download from NSA",
        FOSS,
        "https://ghidra-sre.org/",
    ),
    _t(
        "radare2",
        "re-pwn",
        4,
        "Portable reversing framework and disassembler",
        ["r2", "radare2"],
        "apt install radare2 | git clone radareorg/radare2",
        FOSS,
        "https://rada.re/",
    ),
    _t(
        "rizin",
        "re-pwn",
        4,
        "Reverse-engineering framework (radare2 fork)",
        ["rizin", "rz"],
        "apt install rizin",
        FOSS,
        "https://rizin.re/",
    ),
    _t(
        "cutter",
        "re-pwn",
        4,
        "GUI for Rizin with Ghidra decompiler",
        ["cutter", "Cutter"],
        "download AppImage from rizinorg/cutter",
        FOSS,
        "https://cutter.re/",
    ),
    _t(
        "gdb",
        "re-pwn",
        4,
        "GNU debugger (add pwndbg/GEF/peda)",
        ["gdb"],
        "apt install gdb ; then install pwndbg or GEF",
        FOSS,
        "https://www.sourceware.org/gdb/",
    ),
    _t(
        "ida-free",
        "re-pwn",
        4,
        "Interactive disassembler (Free edition)",
        ["ida64", "ida"],
        "download IDA Free from Hex-Rays",
        FREEMIUM,
        "https://hex-rays.com/ida-free/",
    ),
    _t(
        "binaryninja",
        "re-pwn",
        4,
        "Reverse-engineering platform (commercial)",
        ["binaryninja"],
        "licensed purchase from Vector 35",
        COMMERCIAL,
        "https://binary.ninja/",
    ),
    _t(
        "angr",
        "re-pwn",
        4,
        "Python binary analysis + symbolic execution (library)",
        [],
        "pipx install angr (imported as a library)",
        FOSS,
        "https://angr.io/",
    ),
    _t(
        "objdump",
        "re-pwn",
        4,
        "Disassemble and inspect object files (binutils)",
        ["objdump"],
        "apt install binutils",
        FOSS,
        "https://www.gnu.org/software/binutils/",
    ),
    _t(
        "readelf",
        "re-pwn",
        4,
        "Display info about ELF files (binutils)",
        ["readelf"],
        "apt install binutils",
        FOSS,
        "https://www.gnu.org/software/binutils/",
    ),
    _t(
        "strings",
        "re-pwn",
        4,
        "Extract printable strings from binaries",
        ["strings"],
        "apt install binutils",
        FOSS,
        "https://www.gnu.org/software/binutils/",
    ),
    _t(
        "ltrace",
        "re-pwn",
        4,
        "Trace library calls of a running program",
        ["ltrace"],
        "apt install ltrace",
        FOSS,
        "https://ltrace.org/",
    ),
    _t(
        "strace",
        "re-pwn",
        4,
        "Trace system calls and signals",
        ["strace"],
        "apt install strace",
        FOSS,
        "https://strace.io/",
    ),
    _t(
        "xxd",
        "re-pwn",
        4,
        "Hex dump / reverse hex dump",
        ["xxd"],
        "apt install xxd (vim-common)",
        FOSS,
        "https://linux.die.net/man/1/xxd",
    ),
]


# --------------------------------------------------------------- forensics / DFIR
CATALOG += [
    _t(
        "autopsy",
        "forensics",
        0,
        "GUI digital forensics platform (Sleuth Kit front-end)",
        ["autopsy"],
        "apt install autopsy | download from sleuthkit.org",
        FOSS,
        "https://www.autopsy.com/",
    ),
    _t(
        "sleuthkit",
        "forensics",
        0,
        "Command-line filesystem forensics toolkit",
        ["fls", "mmls", "tsk_recover"],
        "apt install sleuthkit",
        FOSS,
        "https://www.sleuthkit.org/",
    ),
    _t(
        "volatility3",
        "forensics",
        0,
        "Memory forensics framework",
        ["vol", "vol.py", "volatility3"],
        "pipx install volatility3",
        FOSS,
        "https://github.com/volatilityfoundation/volatility3",
    ),
    _t(
        "binwalk",
        "forensics",
        0,
        "Analyze and extract firmware images",
        ["binwalk"],
        "apt install binwalk",
        FOSS,
        "https://github.com/ReFirmLabs/binwalk",
    ),
    _t(
        "foremost",
        "forensics",
        0,
        "Recover files by header/footer carving",
        ["foremost"],
        "apt install foremost",
        FOSS,
        "https://foremost.sourceforge.net/",
    ),
    _t(
        "scalpel",
        "forensics",
        0,
        "Fast file carver from disk images",
        ["scalpel"],
        "apt install scalpel",
        FOSS,
        "https://github.com/sleuthkit/scalpel",
    ),
    _t(
        "bulk_extractor",
        "forensics",
        0,
        "Scan disks for emails, cards, URLs and artifacts",
        ["bulk_extractor"],
        "apt install bulk-extractor",
        FOSS,
        "https://github.com/simsong/bulk_extractor",
    ),
    _t(
        "steghide",
        "forensics",
        0,
        "Hide/extract data in images and audio",
        ["steghide"],
        "apt install steghide",
        FOSS,
        "https://steghide.sourceforge.net/",
    ),
    _t(
        "zsteg",
        "forensics",
        0,
        "Detect hidden data in PNG/BMP files",
        ["zsteg"],
        "gem install zsteg",
        FOSS,
        "https://github.com/zed-0xff/zsteg",
    ),
    _t(
        "stegseek",
        "forensics",
        0,
        "Ultra-fast steghide passphrase cracker",
        ["stegseek"],
        "download release from RickdeJager/stegseek",
        FOSS,
        "https://github.com/RickdeJager/stegseek",
    ),
    _t(
        "testdisk",
        "forensics",
        0,
        "Recover partitions and files (incl. photorec)",
        ["testdisk", "photorec"],
        "apt install testdisk",
        FOSS,
        "https://www.cgsecurity.org/",
    ),
]

# --- END PART 6 ---

# ----------------------------------------------------------------------- fuzzing
CATALOG += [
    _t(
        "aflplusplus",
        "fuzzing",
        4,
        "State-of-the-art coverage-guided fuzzer",
        ["afl-fuzz", "aflplusplus"],
        "apt install afl++ | build from AFLplusplus",
        FOSS,
        "https://github.com/AFLplusplus/AFLplusplus",
    ),
    _t(
        "honggfuzz",
        "fuzzing",
        4,
        "Security-oriented feedback-driven fuzzer",
        ["honggfuzz"],
        "apt install honggfuzz",
        FOSS,
        "https://github.com/google/honggfuzz",
    ),
    _t(
        "boofuzz",
        "fuzzing",
        4,
        "Network protocol fuzzing framework (library)",
        [],
        "pipx install boofuzz (imported as a library)",
        FOSS,
        "https://github.com/jtpereyda/boofuzz",
    ),
    _t(
        "radamsa",
        "fuzzing",
        4,
        "Mutation-based general-purpose fuzzer",
        ["radamsa"],
        "apt install radamsa | build from gitlab",
        FOSS,
        "https://gitlab.com/akihe/radamsa",
    ),
    _t(
        "libfuzzer",
        "fuzzing",
        4,
        "In-process coverage-guided fuzzer (ships with clang)",
        ["clang"],
        "apt install clang (use -fsanitize=fuzzer)",
        FOSS,
        "https://llvm.org/docs/LibFuzzer.html",
    ),
]


# ------------------------------------------------------------- AI / LLM security
CATALOG += [
    _t(
        "garak",
        "ai-llm",
        3,
        "LLM vulnerability scanner (prompt injection, leakage)",
        ["garak"],
        "pipx install garak",
        FOSS,
        "https://github.com/leondz/garak",
    ),
    _t(
        "pyrit",
        "ai-llm",
        3,
        "Microsoft risk-identification toolkit for GenAI",
        ["pyrit"],
        "pipx install pyrit",
        FOSS,
        "https://github.com/Azure/PyRIT",
    ),
    _t(
        "promptfoo",
        "ai-llm",
        3,
        "Test/red-team LLM apps and prompts",
        ["promptfoo"],
        "npm install -g promptfoo",
        FOSS,
        "https://github.com/promptfoo/promptfoo",
    ),
    _t(
        "llm-guard",
        "ai-llm",
        3,
        "Security toolkit for LLM inputs/outputs (library)",
        [],
        "pipx install llm-guard (imported as a library)",
        FOSS,
        "https://github.com/protectai/llm-guard",
    ),
    _t(
        "giskard",
        "ai-llm",
        3,
        "Scan ML/LLM models for vulnerabilities (library)",
        [],
        "pipx install giskard (imported as a library)",
        FOSS,
        "https://github.com/Giskard-AI/giskard",
    ),
    _t(
        "rebuff",
        "ai-llm",
        3,
        "Prompt-injection detector for LLM apps (library)",
        [],
        "pip install rebuff (imported as a library)",
        FOSS,
        "https://github.com/protectai/rebuff",
    ),
]


# ----------------------------------------------------------- reporting / collaboration
CATALOG += [
    _t(
        "faraday",
        "reporting",
        7,
        "Collaborative pentest management and reporting",
        ["faraday-server", "faraday"],
        "pipx install faradaysec | docker",
        FOSS,
        "https://github.com/infobyte/faraday",
    ),
    _t(
        "dradis",
        "reporting",
        7,
        "Reporting and collaboration for security teams",
        ["dradis"],
        "git clone dradis/dradis-ce | docker",
        FOSS,
        "https://dradisframework.com/",
    ),
    _t(
        "ghostwriter",
        "reporting",
        7,
        "Engagement, reporting and project management",
        ["ghostwriter"],
        "git clone GhostManager/Ghostwriter (docker)",
        FOSS,
        "https://github.com/GhostManager/Ghostwriter",
    ),
    _t(
        "sysreptor",
        "reporting",
        7,
        "Customizable pentest reporting platform",
        ["sysreptor"],
        "docker compose from syslifters/sysreptor",
        FREEMIUM,
        "https://docs.sysreptor.com/",
    ),
    _t(
        "serpico",
        "reporting",
        7,
        "SimplE RePort wrIting and CollaboratiOn",
        ["serpico"],
        "git clone SerpicoProject/Serpico",
        FOSS,
        "https://github.com/SerpicoProject/Serpico",
    ),
    _t(
        "cherrytree",
        "reporting",
        7,
        "Hierarchical note-taking for engagements",
        ["cherrytree"],
        "apt install cherrytree",
        FOSS,
        "https://www.giuspen.net/cherrytree/",
    ),
    _t(
        "plextrac",
        "reporting",
        7,
        "Commercial reporting/collaboration platform",
        ["plextrac"],
        "commercial SaaS",
        COMMERCIAL,
        "https://plextrac.com/",
    ),
]


# ----------------------------------------------- distros, labs and practice targets
CATALOG += [
    _t(
        "kali",
        "distros-labs",
        0,
        "Debian-based offensive-security distro (600+ tools)",
        [],
        "reference OS - kali.org/get-kali",
        REF,
        "https://www.kali.org/",
    ),
    _t(
        "parrot",
        "distros-labs",
        0,
        "Security-focused distro (pentest + privacy)",
        [],
        "reference OS - parrotsec.org",
        REF,
        "https://www.parrotsec.org/",
    ),
    _t(
        "blackarch",
        "distros-labs",
        0,
        "Arch-based distro with 2800+ security tools",
        [],
        "reference OS / Arch repo",
        REF,
        "https://www.blackarch.org/",
    ),
    _t(
        "exegol",
        "distros-labs",
        0,
        "Dockerized pro pentest environments (has a CLI)",
        ["exegol"],
        "pipx install exegol",
        FOSS,
        "https://github.com/ThePorgs/Exegol",
    ),
    _t(
        "commando-vm",
        "distros-labs",
        0,
        "Windows-based offensive VM distribution",
        [],
        "reference - Mandiant/commando-vm",
        REF,
        "https://github.com/mandiant/commando-vm",
    ),
    _t(
        "hackthebox",
        "distros-labs",
        0,
        "Online labs, machines and Pro Labs",
        [],
        "platform - hackthebox.com",
        REF,
        "https://www.hackthebox.com/",
    ),
    _t(
        "tryhackme",
        "distros-labs",
        0,
        "Guided rooms and learning paths for beginners",
        [],
        "platform - tryhackme.com",
        REF,
        "https://tryhackme.com/",
    ),
    _t(
        "vulnhub",
        "distros-labs",
        0,
        "Downloadable vulnerable VMs to practice on",
        [],
        "platform - vulnhub.com",
        REF,
        "https://www.vulnhub.com/",
    ),
    _t(
        "goad",
        "distros-labs",
        0,
        "Game of Active Directory - vulnerable AD lab",
        [],
        "git clone Orange-Cyberdefense/GOAD",
        REF,
        "https://github.com/Orange-Cyberdefense/GOAD",
    ),
    _t(
        "dvwa",
        "distros-labs",
        0,
        "Damn Vulnerable Web Application",
        [],
        "git clone digininja/DVWA | docker",
        REF,
        "https://github.com/digininja/DVWA",
    ),
    _t(
        "juice-shop",
        "distros-labs",
        0,
        "OWASP modern vulnerable web app",
        [],
        "docker run bkimminich/juice-shop",
        REF,
        "https://owasp.org/www-project-juice-shop/",
    ),
    _t(
        "webgoat",
        "distros-labs",
        0,
        "OWASP deliberately insecure teaching app",
        [],
        "docker run webgoat/webgoat",
        REF,
        "https://owasp.org/www-project-webgoat/",
    ),
    _t(
        "portswigger-academy",
        "distros-labs",
        0,
        "Free web-security labs from the Burp team",
        [],
        "platform - portswigger.net/web-security",
        REF,
        "https://portswigger.net/web-security",
    ),
    _t(
        "vulhub",
        "distros-labs",
        0,
        "Pre-built vulnerable environments (docker)",
        [],
        "git clone vulhub/vulhub",
        REF,
        "https://vulhub.org/",
    ),
    _t(
        "metasploitable",
        "distros-labs",
        0,
        "Intentionally vulnerable Linux VM",
        [],
        "download Metasploitable 2/3",
        REF,
        "https://sourceforge.net/projects/metasploitable/",
    ),
    _t(
        "hackerone",
        "distros-labs",
        0,
        "Bug-bounty platform (legal real-world targets)",
        [],
        "platform - hackerone.com",
        REF,
        "https://www.hackerone.com/",
    ),
]

# --- END PART 7 ---

# =============================================================================
# Query, detection and launch logic
# =============================================================================


def categories():
    """Categories in catalog (insertion) order."""
    seen = []
    for t in CATALOG:
        if t["category"] not in seen:
            seen.append(t["category"])
    return seen


def by_name(name):
    """Look up a tool by its name, or by one of its binary names."""
    key = (name or "").strip().lower()
    if not key:
        return None
    for t in CATALOG:
        if t["name"].lower() == key:
            return t
    for t in CATALOG:
        if any(b.lower() == key for b in t["bins"]):
            return t
    return None


def filter_tools(category="", phase=0, license=""):
    cat = (category or "").strip().lower()
    lic = (license or "").strip().lower()
    out = []
    for t in CATALOG:
        if cat and t["category"] != cat:
            continue
        if phase and t["phase"] != phase:
            continue
        if lic and t["license"] != lic:
            continue
        out.append(t)
    return out


def summary():
    by_cat, by_phase, by_lic = {}, {}, {}
    for t in CATALOG:
        by_cat[t["category"]] = by_cat.get(t["category"], 0) + 1
        by_phase[t["phase"]] = by_phase.get(t["phase"], 0) + 1
        by_lic[t["license"]] = by_lic.get(t["license"], 0) + 1
    return {
        "total": len(CATALOG),
        "categories": by_cat,
        "phases": by_phase,
        "licenses": by_lic,
    }


def detect(entry):
    """Return the resolved path of the first installed binary, else None."""
    for b in entry.get("bins", []):
        path = shutil.which(b)
        if path:
            return path
    return None


def check(category=""):
    """Detect which catalogued tools are installed on this machine."""
    installed, missing, libs, refs = [], [], [], []
    for t in filter_tools(category=category):
        if not t["bins"]:
            (refs if t["license"] == REF else libs).append(t["name"])
            continue
        path = detect(t)
        if path:
            installed.append((t["name"], path))
        else:
            missing.append(t["name"])
    summ = "%d installed, %d missing, %d libraries, %d references" % (
        len(installed),
        len(missing),
        len(libs),
        len(refs),
    )
    return {
        "installed": installed,
        "missing": missing,
        "libraries": libs,
        "references": refs,
        "summary": summ,
    }


def run_tool(name, toolargs=None, authorized=False, timeout=120):
    """Launch an installed catalogued tool. Refuses without authorized=True."""
    toolargs = list(toolargs or [])
    entry = by_name(name)
    if entry is None:
        return make_result(
            "arsenal.run",
            "unknown tool: " + str(name),
            findings=["try: reconkit arsenal list"],
            data={"ok": False},
        )
    if not authorized:
        return make_result(
            "arsenal.run",
            "refused: authorization required to launch " + entry["name"],
            findings=[
                "pass --authorized to attest you may run this against your target"
            ],
            data={"ok": False, "tool": entry["name"]},
        )
    if not entry["bins"]:
        return make_result(
            "arsenal.run",
            entry["name"] + " is a library/reference, not a runnable CLI",
            findings=[entry["install"]],
            data={"ok": False, "tool": entry["name"]},
        )
    exe = detect(entry)
    if not exe:
        return make_result(
            "arsenal.run",
            entry["name"] + " is not installed",
            findings=["install: " + entry["install"]],
            data={"ok": False, "tool": entry["name"], "installed": False},
        )
    cmd = [exe] + toolargs
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        return make_result(
            "arsenal.run",
            "could not execute " + exe,
            data={"ok": False, "tool": entry["name"]},
        )
    except subprocess.TimeoutExpired:
        return make_result(
            "arsenal.run",
            entry["name"] + " timed out after " + str(timeout) + "s",
            data={"ok": False, "tool": entry["name"], "timeout": timeout},
        )
    out = ((proc.stdout or "") + (proc.stderr or "")).strip()
    tail = out.splitlines()[-40:]
    return make_result(
        "arsenal.run",
        entry["name"] + " exited with code " + str(proc.returncode),
        findings=tail,
        data={
            "ok": proc.returncode == 0,
            "tool": entry["name"],
            "cmd": " ".join(cmd),
            "returncode": proc.returncode,
        },
    )


def format_list(entries):
    lines, cur = [], None
    for t in entries:
        if t["category"] != cur:
            cur = t["category"]
            lines.append("")
            lines.append("== " + cur + " ==")
        lic = "" if t["license"] == FOSS else "  [" + t["license"] + "]"
        lines.append("  P%s  %-22s %s%s" % (t["phase"], t["name"], t["desc"], lic))
    return "\n".join(lines).strip()


def format_check(res):
    lines = []
    lines.append("installed (" + str(len(res["installed"])) + "):")
    for name, path in res["installed"]:
        lines.append("  [+] " + name.ljust(22) + path)
    lines.append("")
    lines.append("missing (" + str(len(res["missing"])) + "):")
    for name in res["missing"]:
        e = by_name(name)
        lines.append(
            "  [-] " + name.ljust(22) + "install: " + (e["install"] if e else "")
        )
    if res["libraries"]:
        lines.append("")
        lines.append("libraries (import, no CLI): " + ", ".join(res["libraries"]))
    if res["references"]:
        lines.append("")
        lines.append(
            "references (distros/labs/platforms): " + ", ".join(res["references"])
        )
    return "\n".join(lines)


# --- END PART 8 ---
